(in-package #:bursyk-server)

;;;; A small SSH command server over cl-pnet-ssh.  It binds a listener,
;;;; authenticates clients with their own keys, and runs each exec request as
;;;; a child process.  Nothing blocks the event loop: both directions of every
;;;; child pipe are watched descriptors.

(defvar *options*
  '(:address nil :port nil :host-key nil :authorized-keys nil
    :accept-env nil :allow nil :subsystem nil
    :no-tcp-forwarding nil :permit-open nil
    :no-remote-forwarding nil :gateway-ports nil
    :config-file nil :option nil :login-grace-time nil
    :verbose 0 :quiet nil)
  "The command line as parsed.

A NIL value means the option was not given, so an sshd_config setting can
supply it; anything named here wins over the file, as sshd's command line
does.")

(defvar *server-config* nil
  "The sshd_config settings in force, or NIL when no config file is used.")

(defvar *log-level* :info
  "How much to report: sshd's LogLevel names, or what -q and -v selected.")

(defparameter +log-levels+
  '((:quiet . 0) (:fatal . 1) (:error . 2) (:info . 3)
    (:verbose . 4) (:debug . 5) (:debug1 . 5) (:debug2 . 6) (:debug3 . 7))
  "LogLevel names from least to most talkative.")

(defun log-number (level)
  (or (cdr (assoc level +log-levels+)) (cdr (assoc :info +log-levels+))))

(defun log-allowed-p (level)
  "Whether a message at LEVEL is wanted at the current *LOG-LEVEL*.

sshd's level is the most talkative message to print, so a message prints
when it is no more talkative than that; QUIET prints nothing at all."
  (let ((threshold (log-number *log-level*)))
    (and (plusp threshold)
         (<= (log-number level) threshold))))

(defun log-at (level control &rest arguments)
  (when (log-allowed-p level)
    (format *error-output* "bursyk-server: ~?~%" control arguments)
    (finish-output *error-output*)))


(defvar *server* nil)
(defvar *signals* '()
  "The signal watchers this process installed, so each can be stopped.")
(defvar *remote-forwards* nil
  "Remote forwarding listeners requested with tcpip-forward, newest first.")
(defvar *remote-tunnels* (make-hash-table :test #'eq)
  "Accepted remote-forwarding connections, keyed by their CL-PNET connection.")

(defparameter *default-subsystems*
  #+win32
  (list (cons "sftp"
              (format nil "~A/System32/OpenSSH/sftp-server.exe"
                      (or (uiop:getenv "WINDIR") "C:\\Windows"))))
  #-win32
  '(("sftp" . "/usr/lib/openssh/sftp-server"))
  "Subsystem names and programs, unless --subsystem replaces them.")

(defparameter +bursyk-server-version+ "0.0.2.11"
  "The program's own version, also sent in the SSH identification string.

Keep this in step with the :VERSION in BURSYK-SERVER.ASD; the library gets
the value through MAKE-SSH-SERVER, so peers see the server's real name and
version rather than a generic library string.")

;;; ---- Command line ----

(defun usage ()
  (format *error-output*
          "usage: bursyk-server [-a ADDRESS] [-p PORT] [-f SSHD_CONFIG]~%~
           ~15@T[-g LOGIN_GRACE_TIME] [-H HOST_KEY]... [-A AUTHORIZED_KEYS]~%~
           ~15@T[-e NAME]... [-c PREFIX]... [-S NAME=PATH]...~%~
           ~15@T[-o KEYWORD=VALUE]... [-v]... [-q]~%~
           ~15@T[--no-tcp-forwarding]~%~
           ~15@T[--allow-tcpip HOST:PORT]... [--no-remote-forwarding]~%~
           ~15@T[--gateway-ports] [-V]~%~
           ~15@T-f none reads no config; the default is ~A~%~
           ~15@T-p defaults to 22, or the Port in the config file~%"
          cl-pnet-ssh:+ssh-server-config-default-file+)
  (finish-output *error-output*))

(defun print-version ()
  (format t "bursyk-server ~A~%" +bursyk-server-version+)
  (finish-output))

(defun fail (format-string &rest arguments)
  (format *error-output* "bursyk-server: ~?~%" format-string arguments)
  (finish-output *error-output*)
  (uiop:quit 2))

(defun option-key (name)
  ;; Short options are case-sensitive: -a is the address, -A the key file.
  (cond ((member name '("-a" "--address") :test #'string=) :address)
        ((member name '("-p" "--port") :test #'string=) :port)
        ((member name '("-H" "--host-key") :test #'string=) :host-key)
        ((member name '("-A" "--authorized-keys") :test #'string=)
         :authorized-keys)
        ((member name '("-e" "--accept-env") :test #'string=) :accept-env)
        ((member name '("-c" "--command") :test #'string=) :allow)
        ((member name '("-S" "--subsystem") :test #'string=) :subsystem)
        ((member name '("--no-tcp-forwarding") :test #'string=)
         :no-tcp-forwarding)
        ((member name '("--no-remote-forwarding") :test #'string=)
         :no-remote-forwarding)
        ((member name '("--gateway-ports") :test #'string=) :gateway-ports)
        ((member name '("--allow-tcpip" "--permit-open") :test #'string=)
         :permit-open)
        ((member name '("-f" "--config") :test #'string=) :config-file)
        ((member name '("-g" "--login-grace-time") :test #'string=)
         :login-grace-time)
        ((member name '("-o" "--option") :test #'string=) :option)
        ((member name '("-v" "--verbose") :test #'string=) :verbose)
        ((member name '("-q" "--quiet") :test #'string=) :quiet)
        (t nil)))

(defun split-host-port (text)
  "HOST and PORT from HOST:PORT, allowing [ ] around an IPv6 HOST."
  (let ((colon (position #\: text :from-end t)))
    (when (and colon (plusp colon) (< (1+ colon) (length text)))
      (let ((host (subseq text 0 colon))
            (port (subseq text (1+ colon))))
        (when (and (>= (length host) 2)
                   (char= (char host 0) #\[)
                   (char= (char host (1- (length host))) #\]))
          (setf host (subseq host 1 (1- (length host)))))
        (values host port)))))

(defun valid-permit-port-p (port)
  "Whether PORT is a number or the * wildcard."
  (and port
       (or (string= port "*")
           (and (plusp (length port))
                (every #'digit-char-p port)
                (<= 1 (parse-integer port) 65535)))))

(defun record-option (key value)
  (case key
    ((:accept-env :allow :subsystem :host-key :option)
     (push value (getf *options* key)))
    (:verbose
     (incf (getf *options* :verbose 0)))
    (:quiet
     (setf (getf *options* :quiet) t))
    (:permit-open
     (multiple-value-bind (host port) (split-host-port value)
       (unless (and host (valid-permit-port-p port))
         (fail "--allow-tcpip needs HOST:PORT, not ~A" value))
       (push value (getf *options* :permit-open))))
    (t (setf (getf *options* key) value))))

(defun parse-arguments (arguments)
  (loop
    (let ((argument (first arguments)))
      (cond
        ((null arguments) (return))
        ((option-key argument)
         (let ((key (option-key argument)))
           (if (member key '(:no-tcp-forwarding :no-remote-forwarding
                             :gateway-ports :quiet :verbose))
               (progn
                 (record-option key t)
                 (setf arguments (cdr arguments)))
               (let ((value (second arguments)))
                 (unless value (fail "~A needs a value" argument))
                 (record-option key value)
                 (setf arguments (cddr arguments))))))
        ((and (> (length argument) 1) (char= (char argument 0) #\-))
         (fail "unknown option ~A" argument))
        (t (fail "unexpected argument ~A" argument))))))

(defun command-line-port ()
  "The -p port as a number, or NIL when -p was not given."
  (let ((value (getf *options* :port)))
    (when value
      (let ((port (handler-case (parse-integer value)
                    (parse-error () nil))))
        (unless (and port (<= 1 port 65535))
          (fail "not a port number: ~A" value))
        port))))

(defun command-line-login-grace-time ()
  "The -g grace period in seconds, or NIL when -g was not given."
  (let ((value (getf *options* :login-grace-time)))
    (when value
      (or (cl-pnet-ssh:ssh-parse-time value)
          (fail "not a time value: ~A" value)))))

(defun command-allowed-p (command)
  "Whether COMMAND starts with one of the --command prefixes."
  (let ((prefixes (reverse (getf *options* :allow))))
    (or (null prefixes)
        (some (lambda (prefix)
                (and (<= (length prefix) (length command))
                     (string= prefix command :end2 (length prefix))))
              prefixes))))

;;; ---- Forwarded connections ----

(defun host-pattern-match-p (pattern host)
  "Whether HOST matches PATTERN, where * stands for any run of characters."
  (let ((pattern-length (length pattern))
        (host-length (length host))
        (p 0)
        (h 0)
        (star nil)
        (resume 0))
    (loop while (< h host-length)
          do (cond
               ((and (< p pattern-length)
                     (char= (char pattern p) #\*))
                (setf star p
                      resume h
                      p (1+ p)))
               ((and (< p pattern-length)
                     (char-equal (char pattern p) (char host h)))
                (incf p)
                (incf h))
               (star
                (incf resume)
                (setf h resume
                      p (1+ star)))
               (t (return nil))))
    (loop while (and (< p pattern-length)
                     (char= (char pattern p) #\*))
          do (incf p))
    (= p pattern-length)))

;;; ---- sshd_config and the values it supplies ----

(defun config-setting (accessor)
  "ACCESSOR applied to *SERVER-CONFIG*, or NIL without a config file."
  (and *server-config* (funcall accessor *server-config*)))

(defun config-file-path ()
  "The sshd_config to read, or NIL for none.

Without -f this is /etc/ssh/sshd_config when it exists; a missing default is
not an error, so the program still runs for an unprivileged user.  An
explicit -f that does not exist is an error, as in sshd."
  (let ((value (getf *options* :config-file)))
    (cond
      ((null value)
       (let ((default cl-pnet-ssh:+ssh-server-config-default-file+))
         (and (probe-file default) default)))
      ((string-equal value "none") nil)
      ((probe-file value) value)
      (t (fail "cannot read the config file ~A" value)))))

(defun load-server-config ()
  "Read the sshd_config, then let -q and -v adjust its LogLevel."
  (let ((path (config-file-path))
        (options (reverse (getf *options* :option))))
    (setf *server-config*
          (cond
            (path (cl-pnet-ssh:ssh-server-config-load path :options options))
            (options (cl-pnet-ssh:ssh-server-config-load nil :options options))
            (t nil)))
    (when (config-setting #'cl-pnet-ssh:ssh-server-config-log-level)
      (setf *log-level*
            (config-setting #'cl-pnet-ssh:ssh-server-config-log-level)))
    (cond
      ((getf *options* :quiet)
       (setf *log-level* :quiet))
      ((plusp (or (getf *options* :verbose) 0))
       (setf *log-level*
             (nth (min (1- (getf *options* :verbose)) 3)
                  '(:verbose :debug :debug2 :debug3)))))
    (when *server-config*
      (dolist (warning (cl-pnet-ssh:ssh-server-config-warnings
                        *server-config*))
        (log-at :info "warning: ~A" warning)))
    ;; Library milestones are only worth printing at VERBOSE and above.
    (setf cl-pnet-ssh:*ssh-log-function*
          (when (log-allowed-p :verbose)
            (lambda (message) (log-at :debug "~A" message))))
    *server-config*))

(defun config-listen-address ()
  (first (config-setting
          #'cl-pnet-ssh:ssh-server-config-listen-addresses)))

(defun server-address ()
  "The address to bind: -a, then ListenAddress, then every IPv4 address."
  (or (getf *options* :address)
      (let ((listen (config-listen-address)))
        (and listen (if (string= (car listen) "*")
                        "0.0.0.0"
                        (car listen))))
      "0.0.0.0"))

(defun server-port ()
  "The port to bind: -p, then ListenAddress's port, then Port, then 22."
  (or (command-line-port)
      (cdr (config-listen-address))
      (first (config-setting #'cl-pnet-ssh:ssh-server-config-ports))
      22))

(defun accept-env-names ()
  "The -e names, or the empty list meaning AcceptEnv's answer."
  (or (and (getf *options* :accept-env)
           (reverse (getf *options* :accept-env)))
      (config-setting #'cl-pnet-ssh:ssh-server-config-accept-env)))

(defun permit-open-rules ()
  (or (and (getf *options* :permit-open)
           (reverse (getf *options* :permit-open)))
      (config-setting #'cl-pnet-ssh:ssh-server-config-permit-open)))

(defun forwarding-disabled-p ()
  (config-setting #'cl-pnet-ssh:ssh-server-config-disable-forwarding))

(defun tcp-forwarding-mode ()
  (config-setting #'cl-pnet-ssh:ssh-server-config-allow-tcp-forwarding))

(defun direct-tcpip-allowed-p ()
  "Whether locally forwarded connections may be opened."
  (and (not (getf *options* :no-tcp-forwarding))
       (not (forwarding-disabled-p))
       (not (member (tcp-forwarding-mode) '(:no :remote)))))

(defun remote-forwarding-allowed-p ()
  "Whether the client may ask this server to listen for it."
  (and (not (getf *options* :no-remote-forwarding))
       (not (forwarding-disabled-p))
       (not (member (tcp-forwarding-mode) '(:no :local)))))

(defun gateway-ports-p ()
  (or (getf *options* :gateway-ports)
      (member (config-setting #'cl-pnet-ssh:ssh-server-config-gateway-ports)
              '(:yes :clientspecified))))

(defun tcpip-allowed-p (host port)
  "Whether a direct-tcpip connection to HOST:PORT may be opened.

As sshd does by default, every destination is allowed.  Each --allow-tcpip
or PermitOpen narrows that set, PermitOpen none refuses them all, and either
one of --no-tcp-forwarding and AllowTcpForwarding no refuses everything."
  (and (direct-tcpip-allowed-p)
       (let ((rules (permit-open-rules)))
         (cond
           ((null rules) t)
           ((member "none" rules :test #'string-equal) nil)
           ((member "any" rules :test #'string-equal) t)
           (t
            (some (lambda (rule)
                    (multiple-value-bind (rule-host rule-port)
                        (split-host-port rule)
                      (and rule-host
                           rule-port
                           (host-pattern-match-p rule-host host)
                           (or (string= rule-port "*")
                               (string= rule-port
                                        (princ-to-string port))))))
                  rules))))))

;;; ---- Remote forwarding (tcpip-forward) ----
;;;
;;; The client asks the server to listen on an address and port; when a
;;; connection arrives the server opens a forwarded-tcpip channel back to the
;;; client, which dials the target on its side.  The listener belongs to this
;;; program, not the library, because the policy of which addresses may be
;;; exposed is an sshd decision.

(defstruct (remote-forward (:constructor %make-remote-forward))
  session
  requested-address
  bind-address
  bind-port
  listener)

(defun loopback-bind-address-p (address)
  (member address '("" "localhost" "127.0.0.1" "::1") :test #'string-equal))

(defun remote-bind-address (requested)
  "The address to bind for a tcpip-forward request, or NIL to refuse.

Empty means loopback, as in sshd.  Any other non-loopback address is refused
unless GatewayPorts allowed it: binding a LAN-wide port is a policy change a
client should not make by itself."
  (cond
    ((or (null requested) (zerop (length requested)))
     "127.0.0.1")
    ((string= requested "*")
     (if (gateway-ports-p) "0.0.0.0" "127.0.0.1"))
    ((loopback-bind-address-p requested) "127.0.0.1")
    ((gateway-ports-p) requested)
    (t nil)))

(defun remote-forward-for (session bind-address bind-port)
  "The REMOTE-FORWARD SESSION opened for BIND-ADDRESS:BIND-PORT, if any."
  (find-if (lambda (forward)
             (and (eq (remote-forward-session forward) session)
                  (= (remote-forward-bind-port forward) bind-port)
                  (string-equal (remote-forward-bind-address forward)
                                bind-address)))
           *remote-forwards*))

(defun remote-forward-close (forward)
  (when (remote-forward-listener forward)
    (ignore-errors
      (cl-pnet:close-listener (remote-forward-listener forward)))
    (setf (remote-forward-listener forward) nil)))

(defun close-remote-forwards (&optional session)
  "Close remote forward listeners, for SESSION or for every session."
  (let ((kept '()))
    (dolist (forward *remote-forwards*)
      (if (or (null session) (eq (remote-forward-session forward) session))
          (remote-forward-close forward)
          (push forward kept)))
    (setf *remote-forwards* (nreverse kept))))

(defun remote-tunnel-data (connection data)
  "Move bytes between an accepted remote-forwarding connection and its channel.

DATA NIL means the local peer will send nothing more; tell the channel so the
client can half-close its target, and the reply can still come back."
  (let ((channel (gethash connection *remote-tunnels*)))
    (when channel
      (if data
          (handler-case
              (cl-pnet-ssh:ssh-server-channel-write channel data)
            (error (condition)
              (declare (ignore condition))
              (remote-tunnel-close connection)))
          (ignore-errors
            (cl-pnet-ssh:ssh-server-channel-eof channel))))))

(defun remote-tunnel-close (connection)
  "Close a remote-forwarding connection and the channel paired with it."
  (let ((channel (gethash connection *remote-tunnels*)))
    (remhash connection *remote-tunnels*)
    (when channel
      (remhash channel *remote-tunnels*)
      (ignore-errors (cl-pnet-ssh:ssh-server-channel-close channel)))
    (ignore-errors (cl-pnet:close-connection connection))))

(defun remote-tunnel-half-close (connection)
  "Tell the accepted connection that the client will send nothing more."
  (let ((fd (cl-pnet:connection-fileno connection)))
    (when fd
      (ignore-errors (cl-pnet-sockets:c-shutdown fd 1)))))

(defun remote-forward-accept (forward connection)
  "Open the forwarded-tcpip channel for a connection that reached FORWARD."
  (let* ((peer (cl-pnet:connection-peer-address connection))
         (origin (or (getf peer :address) "0.0.0.0"))
         (origin-port (or (getf peer :port) 0))
         (channel
           (cl-pnet-ssh:ssh-server-open-forwarded-tcpip
            (remote-forward-session forward)
            (remote-forward-requested-address forward)
            (remote-forward-bind-port forward)
            origin origin-port
            :on-data (lambda (channel data kind)
                       (declare (ignore kind))
                       (let ((connection (gethash channel *remote-tunnels*)))
                         (when connection
                           (cl-pnet:send-data
                            connection data
                            :on-error
                            (lambda (status)
                              (declare (ignore status))
                              (remote-tunnel-close connection))))))
            :on-eof (lambda (channel)
                      (let ((connection (gethash channel *remote-tunnels*)))
                        (when connection
                          (remote-tunnel-half-close connection))))
            :on-close (lambda (channel)
                        (remote-tunnel-close-by-channel channel))
            :on-error (lambda (channel condition)
                        (declare (ignore condition))
                        (remote-tunnel-close-by-channel channel)))))
    (setf (gethash connection *remote-tunnels*) channel)
    (setf (gethash channel *remote-tunnels*) connection)
    channel))

(defun remote-tunnel-close-by-channel (channel)
  (let ((connection (gethash channel *remote-tunnels*)))
    (when connection
      (remhash connection *remote-tunnels*)
      (ignore-errors (cl-pnet:close-connection connection)))
    (remhash channel *remote-tunnels*)))

(defun start-remote-forward (session bind-address bind-port)
  "Listener for a client's tcpip-forward request; returns the bound port."
  (unless (remote-forwarding-allowed-p)
    (log-at :error "remote forwarding refused by policy")
    (return-from start-remote-forward nil))
  (let ((address (remote-bind-address bind-address)))
    (unless address
      (log-at :error
              "refusing a remote forward bound to ~A; set GatewayPorts to allow it"
              bind-address)
      (return-from start-remote-forward nil))
    (let* ((forward (%make-remote-forward
                     :session session
                     :requested-address (or bind-address "")
                     :bind-address address
                     :bind-port bind-port))
           (listener
             (handler-case
                 (cl-pnet:make-tcp-listener
                  address bind-port
                  :read-cb #'remote-tunnel-data
                  :on-accept (lambda (connection)
                               (remote-forward-accept forward connection))
                  :on-error (lambda (status)
                              (declare (ignore status))
                              (remote-forward-close forward)))
               (error () nil))))
      (unless listener
        (log-at :error "remote forward could not listen on ~A:~D"
                address bind-port)
        (return-from start-remote-forward nil))
      (setf (remote-forward-bind-port forward)
            (or (cl-pnet:listener-port listener) bind-port)
            (remote-forward-listener forward) listener)
      (push forward *remote-forwards*)
      ;; The session may end before the client cancels; when it does, the
      ;; listener must not outlive it.
      (remote-forward-bind-port forward))))

(defun cancel-remote-forward (session bind-address bind-port)
  (let ((forward (remote-forward-for session bind-address bind-port)))
    (if forward
        (progn
          (remote-forward-close forward)
          (setf *remote-forwards* (delete forward *remote-forwards*))
          t)
        ;; The client may name the requested address while we stored the
        ;; resolved loopback address.
        (let ((any (find-if (lambda (candidate)
                              (and (eq (remote-forward-session candidate)
                                       session)
                                   (= (remote-forward-bind-port candidate)
                                      bind-port)))
                            *remote-forwards*)))
          (if any
              (progn
                (remote-forward-close any)
                (setf *remote-forwards* (delete any *remote-forwards*))
                t)
              nil)))))

(defun split-subsystem (text)
  "NAME=PATH from one --subsystem argument, as (NAME . PATH)."
  (let ((equals (position #\= text)))
    (unless (and equals (plusp equals) (< (1+ equals) (length text)))
      (fail "not NAME=PATH: ~A" text))
    (cons (subseq text 0 equals) (subseq text (1+ equals)))))

(defun configured-subsystems ()
  "Subsystem (NAME . PROGRAM) pairs from -S, else from the sshd_config."
  (or (and (getf *options* :subsystem)
           (mapcar #'split-subsystem
                   (reverse (getf *options* :subsystem))))
      (config-setting #'cl-pnet-ssh:ssh-server-config-subsystems)))

(defun subsystem-path (name)
  "The program for subsystem NAME, or NIL when nothing serves it."
  (let ((configured (assoc name (configured-subsystems) :test #'string=)))
    (cond
      (configured (cdr configured))
      (t (let ((default (assoc name *default-subsystems* :test #'string=)))
           (and default
                (probe-file (cdr default))
                (cdr default)))))))

;;; ---- Child process bridge ----

#-win32
(progn
  (defstruct bridge
  channel
  pid
  (stdin-fd nil)
  (stdout-fd nil)
  (stderr-fd nil)
  (status-fd nil)
  (master-fd nil)
  (pty nil)
  stdin-watcher
  stdout-watcher
  stderr-watcher
  status-watcher
  master-watcher
  (pending (make-array 0 :element-type '(unsigned-byte 8)
                         :adjustable t :fill-pointer 0))
  (status-data (make-array 0 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))
  (input-open t)
  (input-eof nil)
  (stdout-eof nil)
  (stderr-eof nil)
  (status-known nil)
  (exit-status 0)
  (finished nil))

(defun channel-usable-p (channel)
  (not (eq (cl-pnet-ssh:ssh-server-channel-state channel) :closed)))

(defun bridge-input-fd (bridge)
  "Where client input goes: the pty master, or the child's stdin pipe."
  (or (bridge-stdin-fd bridge) (bridge-master-fd bridge)))

(defun bridge-output-fd (bridge)
  "Where child output comes from: the pty master, or the stdout pipe."
  (or (bridge-stdout-fd bridge) (bridge-master-fd bridge)))

(defun bridge-drop-pending (bridge count)
  (let ((pending (bridge-pending bridge)))
    (replace pending pending :start1 0 :start2 count)
    (decf (fill-pointer pending) count)))

(defun bridge-unwatch-all (bridge)
  (when (bridge-stdin-watcher bridge)
    (cl-pnet:fd-unwatch (bridge-stdin-watcher bridge))
    (setf (bridge-stdin-watcher bridge) nil))
  (when (bridge-stdout-watcher bridge)
    (cl-pnet:fd-unwatch (bridge-stdout-watcher bridge))
    (setf (bridge-stdout-watcher bridge) nil))
  (when (bridge-stderr-watcher bridge)
    (cl-pnet:fd-unwatch (bridge-stderr-watcher bridge))
    (setf (bridge-stderr-watcher bridge) nil))
  (when (bridge-status-watcher bridge)
    (cl-pnet:fd-unwatch (bridge-status-watcher bridge))
    (setf (bridge-status-watcher bridge) nil))
  (when (bridge-master-watcher bridge)
    (cl-pnet:fd-unwatch (bridge-master-watcher bridge))
    (setf (bridge-master-watcher bridge) nil)))

(defun bridge-close-fds (bridge)
  "Release the descriptors the bridge owns, once each."
  (when (bridge-stdin-fd bridge)
    (c-close (bridge-stdin-fd bridge))
    (setf (bridge-stdin-fd bridge) nil))
  (when (bridge-stdout-fd bridge)
    (c-close (bridge-stdout-fd bridge))
    (setf (bridge-stdout-fd bridge) nil))
  (when (bridge-stderr-fd bridge)
    (c-close (bridge-stderr-fd bridge))
    (setf (bridge-stderr-fd bridge) nil))
  (when (bridge-status-fd bridge)
    (c-close (bridge-status-fd bridge))
    (setf (bridge-status-fd bridge) nil))
  (when (bridge-master-fd bridge)
    (c-close (bridge-master-fd bridge))
    (setf (bridge-master-fd bridge) nil)))

(defun bridge-cleanup (bridge)
  "Stop every watcher and release the child's pipes, once."
  (unless (bridge-finished bridge)
    (setf (bridge-finished bridge) t)
    (bridge-unwatch-all bridge)
    (bridge-close-fds bridge)))

(defun bridge-abort (bridge)
  "End the child because its channel went away."
  (unless (bridge-finished bridge)
    (unless (bridge-status-known bridge)
      (if (bridge-pty bridge)
          (kill-child-group (bridge-pid bridge))
          (kill-child (bridge-pid bridge))))
    (bridge-cleanup bridge)))

(defun bridge-finish (bridge)
  "Report the child's status on the channel, then release everything."
  (collect-child (bridge-pid bridge))
  (let ((channel (bridge-channel bridge)))
    (unless (eq (cl-pnet-ssh:ssh-server-channel-state channel) :closed)
      (cl-pnet-ssh:ssh-server-channel-exit
       channel (bridge-exit-status bridge))
      (cl-pnet-ssh:ssh-server-channel-close channel))
    (bridge-cleanup bridge)))

(defun bridge-maybe-finish (bridge)
  "Finish once the status arrived and both output pipes hit EOF."
  (when (and (not (bridge-finished bridge))
             (bridge-status-known bridge)
             (bridge-stdout-eof bridge)
             (bridge-stderr-eof bridge))
    (bridge-finish bridge)))

(defun bridge-status (bridge)
  "The status the wrapper shell reported, or the exec-failure code."
  (let ((text (map 'string #'code-char (bridge-status-data bridge))))
    (handler-case (parse-integer text)
      (parse-error () 127))))

(defun bridge-read-status (bridge)
  "Collect the exit status the wrapper shell wrote on its pipe."
  (multiple-value-bind (octets count error)
      (cl-pnet-sockets:read-octets (bridge-status-fd bridge) 32)
    (declare (ignore error))
    (cond
      ((plusp count)
       (let ((data (bridge-status-data bridge)))
         (loop for index from 0 below count
               do (vector-push-extend (aref octets index) data))))
      ((zerop count)
       (when (bridge-status-watcher bridge)
         (cl-pnet:fd-unwatch (bridge-status-watcher bridge))
         (setf (bridge-status-watcher bridge) nil))
       (setf (bridge-status-known bridge) t
             (bridge-exit-status bridge) (bridge-status bridge))
       (bridge-maybe-finish bridge))
      (t nil))))

(defun bridge-output (bridge fd stderr-p)
  "Move whatever the child wrote on FD to the channel.

A positive count is output; zero is end of file.  Reading a pty master after
every slave descriptor has closed reports EIO rather than zero, so a read
error that is not EAGAIN ends the stream too instead of leaving the watcher
to spin on it."
  (unless (channel-usable-p (bridge-channel bridge))
    (return-from bridge-output (bridge-abort bridge)))
  (multiple-value-bind (octets count error)
      (cl-pnet-sockets:read-octets fd (* 64 1024))
    (cond
      ((plusp count)
       (let ((channel (bridge-channel bridge)))
         (if stderr-p
             (cl-pnet-ssh:ssh-server-channel-write-stderr channel octets)
             (cl-pnet-ssh:ssh-server-channel-write channel octets))))
      ((or (zerop count) (not (eql error 11)))
       (if stderr-p
           (setf (bridge-stderr-eof bridge) t)
           (setf (bridge-stdout-eof bridge) t))
       (if stderr-p
           (when (bridge-stderr-watcher bridge)
             (cl-pnet:fd-unwatch (bridge-stderr-watcher bridge))
             (setf (bridge-stderr-watcher bridge) nil))
           (when (bridge-stdout-watcher bridge)
             (cl-pnet:fd-unwatch (bridge-stdout-watcher bridge))
             (setf (bridge-stdout-watcher bridge) nil)))
       (when (and (bridge-pty bridge) (not stderr-p))
         ;; The master is also the input descriptor, and its watcher may be
         ;; the combined read/write one.  Unwatch both so no callback keeps
         ;; firing on a terminal that reported end of file.
         (when (bridge-master-watcher bridge)
           (cl-pnet:fd-unwatch (bridge-master-watcher bridge))
           (setf (bridge-master-watcher bridge) nil))
         (when (bridge-stdin-watcher bridge)
           (cl-pnet:fd-unwatch (bridge-stdin-watcher bridge))
           (setf (bridge-stdin-watcher bridge) nil)))
       (bridge-maybe-finish bridge))
      (t nil))))

(defun bridge-watch-master (bridge)
  "Watch the pty master for output; input writes are folded in on demand."
  (setf (bridge-master-watcher bridge)
        (cl-pnet:fd-watch
         (bridge-master-fd bridge)
         :on-readable
         (lambda (watcher)
           (declare (ignore watcher))
           (bridge-output bridge (bridge-master-fd bridge) nil)))))

(defun bridge-arm-input (bridge)
  (unless (bridge-stdin-watcher bridge)
    (if (bridge-pty bridge)
        (progn
          ;; Every backend keeps one watcher per descriptor, so the write
          ;; interest is folded into the master's read watcher.  It is
          ;; removed again as soon as the queue drains.
          (when (bridge-master-watcher bridge)
            (cl-pnet:fd-unwatch (bridge-master-watcher bridge))
            (setf (bridge-master-watcher bridge) nil))
          (setf (bridge-stdin-watcher bridge)
                (cl-pnet:fd-watch
                 (bridge-master-fd bridge)
                 :on-readable
                 (lambda (watcher)
                   (declare (ignore watcher))
                   (bridge-output bridge (bridge-master-fd bridge) nil))
                 :on-writable
                 (lambda (watcher)
                   (declare (ignore watcher))
                   (bridge-flush-input bridge)))))
        (setf (bridge-stdin-watcher bridge)
              (cl-pnet:fd-watch
               (bridge-input-fd bridge)
               :on-writable
               (lambda (watcher)
                 (declare (ignore watcher))
                 (bridge-flush-input bridge)))))))

(defun bridge-disarm-input (bridge)
  (when (bridge-stdin-watcher bridge)
    (cl-pnet:fd-unwatch (bridge-stdin-watcher bridge))
    (setf (bridge-stdin-watcher bridge) nil)
    (when (and (bridge-pty bridge) (bridge-master-fd bridge)
               (not (bridge-stdout-eof bridge)))
      (bridge-watch-master bridge))))

(defun bridge-close-input (bridge)
  (when (bridge-input-open bridge)
    (setf (bridge-input-open bridge) nil)
    (bridge-disarm-input bridge)
    (cond
      ((bridge-pty bridge)
       ;; A pty has no half-close, so send the terminal EOF character.  The
       ;; master stays open because the child's output still travels on it.
       (ignore-errors
        (cl-pnet-sockets:write-octets (bridge-master-fd bridge) #(4))))
      ((bridge-stdin-fd bridge)
       (c-close (bridge-stdin-fd bridge))
       (setf (bridge-stdin-fd bridge) nil)))))

(defun bridge-flush-input (bridge)
  "Write as much pending stdin as the child accepts without blocking."
  (unless (bridge-input-open bridge)
    (return-from bridge-flush-input nil))
  (let ((pending (bridge-pending bridge))
        (fd (bridge-input-fd bridge))
        (dead nil))
    (loop while (plusp (fill-pointer pending))
          do (multiple-value-bind (count error)
                 (cl-pnet-sockets:write-octets fd pending)
               (cond
                 ((plusp count) (bridge-drop-pending bridge count))
                 ((and (minusp count) (member error '(5 32)))
                  ;; The child closed the terminal or its stdin; re-arming
                  ;; the writer would only spin on the same error.
                  (setf dead t)
                  (return))
                 (t (return)))))
    (cond
      (dead
       (setf (fill-pointer pending) 0)
       (setf (bridge-input-open bridge) nil)
       (bridge-disarm-input bridge))
      ((plusp (fill-pointer pending))
       (bridge-arm-input bridge))
      (t
       (bridge-disarm-input bridge)
       (when (bridge-input-eof bridge)
         (bridge-close-input bridge))))))

(defun bridge-on-data (bridge octets)
  "Queue OCTETS for the child and try to hand them over at once."
  (unless (or (bridge-finished bridge) (not (bridge-input-open bridge)))
    (let ((pending (bridge-pending bridge)))
      (loop for octet across octets
            do (vector-push-extend octet pending)))
    (bridge-flush-input bridge)))

(defun bridge-on-eof (bridge)
  "The client sent EOF: let the child see it once the queue drains."
  (setf (bridge-input-eof bridge) t)
  (bridge-flush-input bridge))

(defun bridge-attach (bridge)
  "Route the channel's callbacks to BRIDGE."
  (let ((channel (bridge-channel bridge)))
    (setf (cl-pnet-ssh:ssh-server-channel-on-data channel)
          (lambda (channel data kind)
            (declare (ignore channel kind))
            (bridge-on-data bridge data)))
    (setf (cl-pnet-ssh:ssh-server-channel-on-eof channel)
          (lambda (channel)
            (declare (ignore channel))
            (bridge-on-eof bridge)))
    (setf (cl-pnet-ssh:ssh-server-channel-on-close channel)
          (lambda (channel)
            (declare (ignore channel))
            (bridge-abort bridge)))))

(defun bridge-watch (bridge)
  "Watch the child's output and status descriptor."
  (if (bridge-pty bridge)
      (bridge-watch-master bridge)
      (progn
        (setf (bridge-stdout-watcher bridge)
              (cl-pnet:fd-watch
               (bridge-stdout-fd bridge)
               :on-readable
               (lambda (watcher)
                 (declare (ignore watcher))
                 (bridge-output bridge (bridge-stdout-fd bridge) nil))))
        (setf (bridge-stderr-watcher bridge)
              (cl-pnet:fd-watch
               (bridge-stderr-fd bridge)
               :on-readable
               (lambda (watcher)
                 (declare (ignore watcher))
                 (bridge-output bridge (bridge-stderr-fd bridge) t))))))
  (setf (bridge-status-watcher bridge)
        (cl-pnet:fd-watch
         (bridge-status-fd bridge)
         :on-readable
         (lambda (watcher)
           (declare (ignore watcher))
           (bridge-read-status bridge))))))

#-win32
(progn
(defun attach-bridge (channel bridge)
  (bridge-attach bridge)
  (bridge-watch bridge)
  bridge)

(defun start-command (channel command)
  "Run COMMAND as a child, on the pty the client asked for if there is one.

The channel's accepted environment requests are added to the child's own
environment, so a SendEnv from the client arrives where the command can see
it.  The library has already applied AcceptEnv."
  (let ((environment (session-environment channel)))
    (if (channel-pty-p channel)
        (multiple-value-bind (pid master status)
            (spawn-pty-shell command (user-shell)
                             :environment environment
                             :rows (channel-rows channel)
                             :columns (channel-columns channel))
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :master-fd master :status-fd status
                        :pty t :stderr-eof t)))
        (multiple-value-bind (pid stdin stdout stderr status)
            (spawn-shell command :environment environment)
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :stdin-fd stdin :stdout-fd stdout
                        :stderr-fd stderr :status-fd status))))))

(defun start-program (channel program arguments)
  "Run PROGRAM with ARGUMENTS on CHANNEL, without shell expansion."
  (let ((environment (session-environment channel)))
    (if (channel-pty-p channel)
        (multiple-value-bind (pid master status)
            (spawn-pty-program program arguments
                               :environment environment
                               :rows (channel-rows channel)
                               :columns (channel-columns channel))
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :master-fd master :status-fd status
                        :pty t :stderr-eof t)))
        (multiple-value-bind (pid stdin stdout stderr status)
            (spawn-program program arguments :environment environment)
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :stdin-fd stdin :stdout-fd stdout
                        :stderr-fd stderr :status-fd status))))))

(defun start-login-shell (channel)
  "Run the login shell, on the pty when one was requested.

A non-pty login shell keeps its stdout and stderr separate, as sshd does for
-T; a pty merges them, as a terminal does."
  (if (channel-pty-p channel)
      (start-command channel nil)
      (start-program channel (user-shell) (list "-l"))))

(defun bridge-resize (bridge columns rows)
  "Resize BRIDGE's pty, if it has one."
  (when (bridge-pty bridge)
    (set-child-window (bridge-master-fd bridge) rows columns)))
)

;;; ---- Server ----

(defun close-reason-text (reason)
  "REASON as the log should show it: keywords without their colon."
  (if (stringp reason)
      reason
      (string-downcase (string reason))))

(defun session-failure (channel control-string &rest arguments)
  "Tell the client why its session could not start, then close it."
  (cl-pnet-ssh:ssh-server-channel-write-stderr
   channel (format nil "~?~%" control-string arguments))
  (cl-pnet-ssh:ssh-server-channel-exit channel 126)
  (cl-pnet-ssh:ssh-server-channel-close channel))

(defun install-channel-handlers (channel)
  "Attach the session policy and remember the bridge for window changes."
  (let ((bridge nil))
    (labels ((remember (new-bridge)
               (setf bridge new-bridge))
           (run-command (command)
             (if (command-allowed-p command)
                 (handler-case (remember (start-command channel command))
                   (error (condition)
                     (session-failure channel "~A" condition)))
                 (session-failure channel "command not allowed: ~A" command)))
           (run-shell ()
             (handler-case (remember (start-login-shell channel))
               (error (condition) (session-failure channel "~A" condition))))
           (run-subsystem (path)
             (handler-case (remember (start-program channel path nil))
               (error (condition) (session-failure channel "~A" condition)))))
      (setf (cl-pnet-ssh:ssh-server-channel-on-exec channel)
            (lambda (channel command)
              (declare (ignore channel))
              (run-command command)))
      (setf (cl-pnet-ssh:ssh-server-channel-on-pty channel)
            (lambda (channel term columns rows width height modes)
              (declare (ignore channel term columns rows width height modes))
              ;; Every pty is accepted; the application's policy is which
              ;; terminal metadata it keeps, and the library keeps it all.
              t))
      (setf (cl-pnet-ssh:ssh-server-channel-on-shell channel)
            (lambda (channel)
              (declare (ignore channel))
              ;; Returning a thunk lets the library send the success reply
              ;; before the shell can write its first prompt.
              (lambda () (run-shell))))
      (setf (cl-pnet-ssh:ssh-server-channel-on-subsystem channel)
            (lambda (channel name)
              (declare (ignore channel))
              (let ((path (subsystem-path name)))
                (and path (lambda () (run-subsystem path))))))
      (setf (cl-pnet-ssh:ssh-server-channel-on-window-change channel)
            (lambda (channel columns rows)
              (declare (ignore channel))
              (when bridge
                (bridge-resize bridge columns rows)))))))

(defun home-file (name)
  (merge-pathnames name (user-homedir-pathname)))

;;; ---- authorized_keys ----
;;;
;;; AUTHORIZED-KEYS (-A) names one file for every user.  Without it, sshd's
;;; AuthorizedKeysFile is used, and its %h/%u/%U tokens are expanded for the
;;; user who is trying to log in.

#-win32
(defun passwd-fields (user)
  "The colon-separated fields for USER in /etc/passwd, or NIL."
  (when (and user (plusp (length user)))
    (with-open-file (stream "/etc/passwd" :direction :input
                            :if-does-not-exist nil)
      (when stream
        (loop for line = (read-line stream nil nil)
              while line
              for fields = (uiop:split-string line :separator ":")
              when (and (>= (length fields) 7)
                        (string= (first fields) user))
                do (return fields))))))

#-win32
(defun user-home-and-uid (user)
  "HOME and UID for USER from /etc/passwd, or NIL when it names no one.

sshd asks the C library, which also sees NSS users; this server reads the
local file, so a directory-service account falls back to the global key file
at authentication time."
  (let ((fields (passwd-fields user)))
    (when fields
      (values (nth 5 fields) (nth 2 fields)))))

#+win32
(defun user-home-and-uid (user)
  (declare (ignore user))
  nil)

#-win32
(defun user-primary-gid (user)
  "USER's primary group id from /etc/passwd, or NIL."
  (let ((fields (passwd-fields user)))
    (and fields (nth 3 fields))))

#-win32
(defun user-groups (user)
  "Group names USER belongs to, primary group included.

sshd asks the C library for the full list, NSS included; this reads
/etc/group, as the account lookup already reads /etc/passwd.  An unknown
user simply has no groups, so an AllowGroups rule then denies the login."
  (let ((primary (user-primary-gid user))
        (names '()))
    (with-open-file (stream "/etc/group" :direction :input
                            :if-does-not-exist nil)
      (when stream
        (loop for line = (read-line stream nil nil)
              while line
              for fields = (uiop:split-string line :separator ":")
              when (and (>= (length fields) 4)
                        (or (and primary (string= (nth 2 fields) primary))
                            (member user
                                    (uiop:split-string (nth 3 fields)
                                                       :separator ",")
                                    :test #'string=)))
                do (pushnew (first fields) names :test #'string=))))
    names))

#+win32
(defun user-groups (user)
  (declare (ignore user))
  nil)

(defun expand-authorized-keys-path (pattern user home uid)
  "PATTERN with sshd's %h, %u, %U and %% expanded, anchored at HOME.

A relative result is relative to the user's home, as
expand_authorized_keys() makes it."
  (let ((value
          (with-output-to-string (out)
            (loop with length = (length pattern)
                  for index from 0 below length
                  for character = (char pattern index)
                  do (if (and (char= character #\%)
                              (< (1+ index) length))
                         (case (char pattern (1+ index))
                           (#\h (write-string home out) (incf index))
                           (#\u (write-string user out) (incf index))
                           (#\U (write-string uid out) (incf index))
                           (#\% (write-char #\% out) (incf index))
                           (t (write-char character out)))
                         (write-char character out))))))
    (if (and (plusp (length value)) (char= (char value 0) #\/))
        value
        (concatenate 'string home "/" value))))

(defparameter +default-host-key-candidates+
  '("/etc/ssh/ssh_host_ed25519_key"
    "/etc/ssh/ssh_host_ecdsa_key"
    "/etc/ssh/ssh_host_rsa_key")
  "sshd's host keys when a config file names none, strongest first.")

(defun host-key-files ()
  "The -H keys in command-line order, then the config's, then the default.

A server may present several key types; a client picks the strongest one
they share, so an RSA-only client still connects to an ed25519-first host.
A config file takes on sshd's defaults: /etc/ssh/ssh_host_* .  With no
config file at all, the account's own ~/.ssh/id_ed25519 keeps an
unprivileged run simple."
  (or (reverse (getf *options* :host-key))
      (config-setting #'cl-pnet-ssh:ssh-server-config-host-key-files)
      (if *server-config*
          (let ((found (remove-if-not #'probe-file +default-host-key-candidates+)))
            (unless found
              (fail "the config ~A names no HostKey and no /etc/ssh/ssh_host_* key exists"
                    (cl-pnet-ssh:ssh-server-config-path *server-config*)))
            found)
          (list (home-file ".ssh/id_ed25519")))))

(defun authorized-keys-p (user key-blob)
  "Whether KEY-BLOB may log in as USER, and the environment it carries.

-A names one file for every user.  Otherwise AuthorizedKeysFile decides,
with its %h/%u/%U tokens expanded for USER; when the user has no local
passwd entry, the single key file of the account running the server is used,
so an unprivileged or Windows setup keeps working.  The second value is the
environment= options of the line that matched, which
PermitUserEnvironment decides whether to apply."
  (let ((global (getf *options* :authorized-keys)))
    (if global
        (cl-pnet-ssh:ssh-authorized-key-blob-match global key-blob)
        (multiple-value-bind (home uid) (user-home-and-uid user)
          (if (null home)
              (cl-pnet-ssh:ssh-authorized-key-blob-match
               (home-file ".ssh/authorized_keys") key-blob)
              (let ((patterns
                      (or (config-setting
                           #'cl-pnet-ssh:ssh-server-config-authorized-keys-files)
                          cl-pnet-ssh:+ssh-server-config-default-authorized-keys-files+)))
                (dolist (pattern patterns (values nil nil))
                  (unless (string-equal pattern "none")
                    (multiple-value-bind (matched key-env)
                        (cl-pnet-ssh:ssh-authorized-key-blob-match
                         (expand-authorized-keys-path
                          pattern user home uid)
                         key-blob)
                      (when matched
                        (return-from authorized-keys-p
                          (values t key-env))))))))))))

;;; ---- Account policy ----
;;;
;;; AllowUsers, DenyUsers, AllowGroups, DenyGroups and PermitRootLogin are
;;; decided when a user name first appears, before any authentication
;;; method runs, which is when sshd decides them too.

(defun session-remote-ip (session)
  "SESSION's peer address as text, or NIL when the backend did not report it."
  (getf (cl-pnet-ssh:ssh-session-remote-address session) :address))

(defun root-login-allowed-p (user)
  "Whether PermitRootLogin admits USER, when USER is uid 0.

Only publickey exists in this build, so forced-commands-only has no forced
command to allow and refuses root outright."
  (multiple-value-bind (home uid) (user-home-and-uid user)
    (declare (ignore home))
    (or (null uid)
        (not (string= uid "0"))
        (cl-pnet-ssh:ssh-root-login-allowed-p
         (config-setting
          #'cl-pnet-ssh:ssh-server-config-permit-root-login)
         "publickey"))))

(defun user-allowed-p (session user)
  "Whether sshd's account policy admits USER from SESSION's peer."
  (and (root-login-allowed-p user)
       (or (null *server-config*)
           (cl-pnet-ssh:ssh-server-user-allowed-p
            *server-config* user (or (session-remote-ip session) "")
            (user-groups user)))))

;;; ---- Banner ----

(defun read-banner-file (path)
  "The text of sshd's Banner file at PATH, or NIL when there is none.

sshd reads the file for every connection and ignores one it cannot read,
one that is empty, and one larger than a megabyte, so a bad banner never
stops a login.  A function is passed to the server rather than the text so
that editing the file takes effect without a restart."
  (handler-case
      (when (probe-file path)
        (with-open-file (in path :direction :input :if-does-not-exist nil)
          (when in
            (let ((length (file-length in)))
              (when (and (integerp length)
                         (plusp length)
                         (<= length (* 1024 1024)))
                (let ((text (make-string length)))
                  (read-sequence text in)
                  text))))))
    (error () nil)))

;;; ---- Pid file ----

#-win32
(cffi:defcfun ("getpid" c-getpid) :int)

#+win32
(cffi:defcfun ("GetCurrentProcessId" c-getpid) :unsigned-long)

(defvar *pid-file* nil
  "The PidFile this process wrote, or NIL when it wrote none.")

(defun write-pid-file ()
  "Record the process id in the configured PidFile, if there is one.

sshd's default /run/sshd.pid needs root, and an unprivileged run should not
guess, so only an explicit PidFile is written."
  (let ((path (config-setting #'cl-pnet-ssh:ssh-server-config-pid-file)))
    (when (and path (not (string-equal path "none")))
      (handler-case
          (progn
            (with-open-file (out path :direction :output
                                      :if-exists :supersede
                                      :if-does-not-exist :create)
              (format out "~D~%" (c-getpid)))
            (setf *pid-file* path))
        (error (condition)
          (log-at :error "cannot write PidFile ~A: ~A" path condition))))))

(defun remove-pid-file ()
  (when *pid-file*
    (ignore-errors (delete-file *pid-file*))
    (setf *pid-file* nil)))

(defun start-server ()
  (load-server-config)
  (let ((host-keys (host-key-files)))
    (dolist (host-key host-keys)
      (unless (probe-file host-key)
        (fail "host key not found: ~A" host-key)))
    (let ((global (getf *options* :authorized-keys)))
      (when (and global (not (probe-file global)))
        (log-at :info "warning: ~A not found" global)))
    (setf *server*
          (cl-pnet-ssh:make-ssh-server
           (server-address)
           (server-port)
           :host-key host-keys
           :authorize #'authorized-keys-p
           :authorize-user #'user-allowed-p
           :permit-user-environment
           (config-setting
            #'cl-pnet-ssh:ssh-server-config-permit-user-environment)
           :set-env (config-setting #'cl-pnet-ssh:ssh-server-config-set-env)
           :banner
           (let ((banner
                   (config-setting #'cl-pnet-ssh:ssh-server-config-banner)))
             (cond
               ((null banner) nil)
               ((eq banner :none) nil)
               (t (lambda () (read-banner-file banner)))))
           :max-auth-tries
           (config-setting #'cl-pnet-ssh:ssh-server-config-max-auth-tries)
           :max-sessions
           (config-setting #'cl-pnet-ssh:ssh-server-config-max-sessions)
           :login-grace-time
           (or (command-line-login-grace-time)
               (config-setting
                #'cl-pnet-ssh:ssh-server-config-login-grace-time))
           :client-alive-interval
           (config-setting
            #'cl-pnet-ssh:ssh-server-config-client-alive-interval)
           :client-alive-count-max
           (config-setting
            #'cl-pnet-ssh:ssh-server-config-client-alive-count-max)
           :server-version (format nil "bursyk-server_~A"
                                   +bursyk-server-version+)
           :version-addendum
           (let ((addendum
                   (config-setting
                    #'cl-pnet-ssh:ssh-server-config-version-addendum)))
             (if (eq addendum :none) nil addendum))
           :accept-env (accept-env-names)
           :on-channel #'install-channel-handlers
           :on-session (lambda (session)
                         (log-at :info "accepted ~A from ~A"
                                 (cl-pnet-ssh:ssh-session-user session)
                                 (cl-pnet-ssh:ssh-session-remote-address
                                  session)))
           :on-direct-tcpip
           (lambda (session host port origin origin-port)
             (declare (ignore session origin origin-port))
             (let ((allowed (tcpip-allowed-p host port)))
               (log-at :verbose "direct-tcpip to ~A:~D: ~:[refused~;allowed~]"
                       host port allowed)
               allowed))
           ;; The libssh backend has no forwarded-tcpip channels yet, so it
           ;; must not be handed these hooks: its MAKE-SSH-SERVER does not
           ;; take them, and libssh refuses a client's tcpip-forward request
           ;; itself instead of the request being accepted and then dropped.
           #-ssh-backend-ffi
           :on-tcpip-forward
           #-ssh-backend-ffi
           (lambda (session bind-address bind-port)
             (start-remote-forward session bind-address bind-port))
           #-ssh-backend-ffi
           :on-cancel-tcpip-forward
           #-ssh-backend-ffi
           (lambda (session bind-address bind-port)
             (cancel-remote-forward session bind-address bind-port))
           :on-close (lambda (session reason)
                       (log-at :info "closed session for ~A: ~A"
                               (cl-pnet-ssh:ssh-session-user session)
                               (close-reason-text reason))
                       (close-remote-forwards session))
           :on-error (lambda (session condition)
                       (when session
                         (close-remote-forwards session))
                       (log-at :error "~A" condition))))
    (log-at :info "listening on ~A:~D"
            (cl-pnet-ssh:ssh-server-address *server*)
            (cl-pnet-ssh:ssh-server-port *server*))
    ;; Say it once at startup rather than let a client's -R fail with no
    ;; explanation from this side: the libssh backend refuses forwarded-tcpip.
    #+ssh-backend-ffi
    (log-at :error
            "the libssh backend does not support remote forwarding; ~
             a client's -R or RemoteForward will be refused")
    (write-pid-file)
    *server*))

(defun close-server ()
  (when *server*
    (close-remote-forwards)
    (cl-pnet-ssh:ssh-server-close *server*)
    (setf *server* nil))
  (remove-pid-file))

(defun shutdown ()
  (close-server)
  (cl-pnet:event-loop-stop))

(defun main ()
  "Entry point for the BURSYK-SERVER program."
  (handler-case
      (let ((arguments (uiop:command-line-arguments)))
        (when (member (first arguments) '("-h" "--help") :test #'string=)
          (usage)
          (uiop:quit 0))
        (when (member (first arguments) '("-V" "--version") :test #'string=)
          (print-version)
          (uiop:quit 0))
        (parse-arguments arguments)
        (start-server)
        ;; Ctrl-C and SIGTERM are conveniences, not requirements: a backend
        ;; that cannot watch signals on this platform must not stop the server
        ;; listening.  SIGTERM is what a service manager sends, and it must
        ;; remove the PidFile just as Ctrl-C does.
        (dolist (signum '(2 15))
          (handler-case
              (push (cl-pnet:signal-start signum (lambda () (shutdown)))
                    *signals*)
            (error (condition)
              (format *error-output*
                      "bursyk-server: no handler for signal ~D: ~A~%"
                      signum condition))))
        (cl-pnet:event-loop-run)
        (dolist (signal *signals*)
          (cl-pnet:signal-stop signal))
        (setf *signals* '())
        (close-server))
    (error (condition)
      (format *error-output* "bursyk-server: ~A~%" condition)
      (finish-output *error-output*)
      (uiop:quit 1))))
