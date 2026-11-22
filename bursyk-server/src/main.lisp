(in-package #:bursyk-server)

#+sbcl (require :sb-posix)

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
    :address-family nil :verbose 0 :quiet nil)
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
(defvar *streamlocal-forwards* nil
  "Unix-socket listeners requested with streamlocal-forward, newest first.")
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

(defparameter +bursyk-server-version+ "0.0.2.85"
  "The program's own version, also sent in the SSH identification string.

Keep this in step with the :VERSION in BURSYK-SERVER.ASD; the library gets
the value through MAKE-SSH-SERVER, so peers see the server's real name and
version rather than a generic library string.")

;;; ---- Command line ----

(defun usage ()
  (format *error-output*
          "usage: bursyk-server [-4|-6] [-a ADDRESS] [-p PORT]~%~
           ~15@T[-f SSHD_CONFIG] [-g LOGIN_GRACE_TIME]~%~
           ~15@T[-H HOST_KEY]... [-A AUTHORIZED_KEYS]~%~
           ~15@T[--host-certificate CERT_FILE]...~%~
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
        ((member name '("--host-certificate") :test #'string=)
         :host-certificate)
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
        ((string= name "-4") :address-family-4)
        ((string= name "-6") :address-family-6)
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
    ((:accept-env :allow :subsystem :host-key :host-certificate :option)
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
                             :gateway-ports :quiet :verbose
                             :address-family-4 :address-family-6))
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

(defun session-config-setting (session accessor)
  "ACCESSOR applied to SESSION's Match-resolved config, or NIL.

The library falls back to the server's base config when no Match block
applies, so this answers the global value for an ordinary connection.  A NIL
SESSION means there is no connection yet and the startup config is meant."
  (let ((config (if session
                    (cl-pnet-ssh:ssh-session-effective-config session)
                    *server-config*)))
    (and config (funcall accessor config))))

(defun session-config (session)
  (if session
      (cl-pnet-ssh:ssh-session-effective-config session)
      *server-config*))

(defun session-log-level (session)
  "SESSION's Match-resolved LogLevel, or the program's global level."
  (or (session-config-setting
       session #'cl-pnet-ssh:ssh-server-config-log-level)
      *log-level*))

(defun log-at-session (session level control &rest arguments)
  "LOG-AT with SESSION's LogLevel, for connection-scoped messages."
  (let ((*log-level* (session-log-level session)))
    (when (log-allowed-p level)
      (format *error-output* "bursyk-server: ~?~%" control arguments)
      (finish-output *error-output*))))

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

(defun numeric-ipv4-address-p (text)
  "Whether TEXT is a dotted quad rather than a name to resolve."
  (and (plusp (length text))
       (= 3 (count #\. text))
       (every (lambda (character)
                (or (digit-char-p character) (char= character #\.)))
              text)))

(defun server-address-family ()
  "The family to bind: -4 or -6, then AddressFamily, then any."
  (cond
    ((getf *options* :address-family-4) "inet")
    ((getf *options* :address-family-6) "inet6")
    ((getf *options* :address-family) (getf *options* :address-family))
    (t (or (config-setting #'cl-pnet-ssh:ssh-server-config-address-family)
           "any"))))

(defun wildcard-address (family)
  "The wildcard address FAMILY listens on."
  (if (string-equal family "inet6") "::" "0.0.0.0"))

(defun address-matches-family-p (address family)
  "Whether an explicit ADDRESS may be used with FAMILY.

Only numeric literals are classified; anything else is left for the
listener, so a name is never rejected merely because it is not a literal."
  (cond
    ((string-equal family "any") t)
    ((cl-pnet-sockets:ipv6-address-p address)
     (string-equal family "inet6"))
    ((numeric-ipv4-address-p address)
     (string-equal family "inet"))
    (t t)))

(defun server-address ()
  "The address to bind: -a, then ListenAddress, then the family's wildcard."
  (let* ((family (server-address-family))
         (address
           (or (getf *options* :address)
               (let ((listen (config-listen-address)))
                 (and listen
                      (not (string= (car listen) "*"))
                      (car listen)))
               (wildcard-address family))))
    (unless (address-matches-family-p address family)
      ;; sshd resolves the address with the configured family; a literal in
      ;; the other one cannot be bound, so say so instead of binding it and
      ;; pretending AddressFamily was honoured.
      (error "ListenAddress ~A does not match AddressFamily ~A"
             address family))
    address))

(defun server-port ()
  "The port to bind: -p, then ListenAddress's port, then Port, then 22."
  (or (command-line-port)
      (cdr (config-listen-address))
      (first (config-setting #'cl-pnet-ssh:ssh-server-config-ports))
      22))

(defun accept-env-names ()
  "The -e names, or NIL meaning the sshd_config's AcceptEnv applies.

Only the command line is returned: a global AcceptEnv already reaches every
session through the resolved config, where a Match block may replace it,
while -e is an explicit command-line answer and must win over the file."
  (and (getf *options* :accept-env)
       (reverse (getf *options* :accept-env))))

(defun permit-open-rules (session)
  (or (and (getf *options* :permit-open)
           (reverse (getf *options* :permit-open)))
      (session-config-setting
       session #'cl-pnet-ssh:ssh-server-config-permit-open)))

(defun forwarding-disabled-p (session)
  (session-config-setting
   session #'cl-pnet-ssh:ssh-server-config-disable-forwarding))

(defun tcp-forwarding-mode (session)
  (session-config-setting
   session #'cl-pnet-ssh:ssh-server-config-allow-tcp-forwarding))

(defun direct-tcpip-allowed-p (session)
  "Whether locally forwarded connections may be opened."
  (and (not (getf *options* :no-tcp-forwarding))
       (not (forwarding-disabled-p session))
       (not (member (tcp-forwarding-mode session) '(:no :remote)))))

(defun remote-forwarding-allowed-p (session)
  "Whether the client may ask this server to listen for it."
  (and (not (getf *options* :no-remote-forwarding))
       (not (forwarding-disabled-p session))
       (not (member (tcp-forwarding-mode session) '(:no :local)))))

(defun gateway-ports-p (session)
  (or (getf *options* :gateway-ports)
      (member (session-config-setting
               session #'cl-pnet-ssh:ssh-server-config-gateway-ports)
              '(:yes :clientspecified))))

(defun tcpip-allowed-p (session host port)
  "Whether a direct-tcpip connection to HOST:PORT may be opened.

As sshd does by default, every destination is allowed.  Each --allow-tcpip
or PermitOpen narrows that set, PermitOpen none refuses them all, and either
one of --no-tcp-forwarding and AllowTcpForwarding no refuses everything."
  (and (direct-tcpip-allowed-p session)
       (let ((rules (permit-open-rules session)))
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

(defstruct (streamlocal-forward (:constructor %make-streamlocal-forward))
  session
  path
  fd
  watcher)

(defstruct (remote-forward (:constructor %make-remote-forward))
  session
  requested-address
  bind-address
  bind-port
  listener)

(defun loopback-bind-address-p (address)
  (member address '("" "localhost" "127.0.0.1" "::1") :test #'string-equal))

(defun remote-bind-address (session requested)
  "The address to bind for a tcpip-forward request, or NIL to refuse.

Empty means loopback, as in sshd.  Any other non-loopback address is refused
unless GatewayPorts allowed it: binding a LAN-wide port is a policy change a
client should not make by itself."
  (cond
    ((or (null requested) (zerop (length requested)))
     "127.0.0.1")
    ((string= requested "*")
     (if (gateway-ports-p session) "0.0.0.0" "127.0.0.1"))
    ((loopback-bind-address-p requested) "127.0.0.1")
    ((gateway-ports-p session) requested)
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
    (setf *remote-forwards* (nreverse kept)))
  (close-streamlocal-forwards session))

#-win32
(progn
(defun streamlocal-forwarding-mode (session)
  "SESSION's AllowStreamLocalForwarding value, defaulting to no."
  (or (session-config-setting
       session #'cl-pnet-ssh:ssh-server-config-allow-streamlocal-forwarding)
      :no))

(defun streamlocal-forward-close (forward)
  "Stop a streamlocal listener and remove its socket file."
  (when (streamlocal-forward-watcher forward)
    (cl-pnet:fd-unwatch (streamlocal-forward-watcher forward))
    (setf (streamlocal-forward-watcher forward) nil))
  (when (streamlocal-forward-fd forward)
    (ignore-errors (c-close (streamlocal-forward-fd forward)))
    (setf (streamlocal-forward-fd forward) nil))
  (ignore-errors (delete-file (streamlocal-forward-path forward))))

(defun close-streamlocal-forwards (&optional session)
  "Close streamlocal listeners, for SESSION or for every session."
  (let ((kept '()))
    (dolist (forward *streamlocal-forwards*)
      (if (or (null session) (eq (streamlocal-forward-session forward) session))
          (streamlocal-forward-close forward)
          (push forward kept)))
    (setf *streamlocal-forwards* (nreverse kept))))

(defun start-streamlocal-remote-forward (session path)
  "Listen on PATH for a client's streamlocal-forward request."
  (unless (and (not (getf *options* :no-remote-forwarding))
               (member (streamlocal-forwarding-mode session)
                       '(:yes :remote)))
    (log-at-session session :error
                    "streamlocal forwarding refused by policy")
    (return-from start-streamlocal-remote-forward nil))
  (let* ((unlink (session-config-setting
                  session
                  #'cl-pnet-ssh:ssh-server-config-streamlocal-bind-unlink))
         (mask (or (session-config-setting
                    session
                    #'cl-pnet-ssh:ssh-server-config-streamlocal-bind-mask)
                   #o177))
         (old-mask (c-umask mask))
         (fd (handler-case
                 (progn
                   (when unlink (ignore-errors (delete-file path)))
                   (cl-pnet-sockets:listen-unix path))
               (error () nil))))
    (c-umask old-mask)
    (unless fd
      (log-at-session session :error
                      "streamlocal forward could not listen on ~A" path)
      (return-from start-streamlocal-remote-forward nil))
    (let* ((forward (%make-streamlocal-forward
                     :session session :path path :fd fd))
           (watcher
             (cl-pnet:fd-watch
              fd :on-readable
              (lambda (watcher)
                (declare (ignore watcher))
                (streamlocal-forward-accept forward)))))
      (setf (streamlocal-forward-watcher forward) watcher)
      (push forward *streamlocal-forwards*)
      t)))

(defun streamlocal-forward-accept (forward)
  "Open a forwarded-streamlocal channel for each accepted connection."
  (let ((fd (streamlocal-forward-fd forward)))
    (loop for client = (cl-pnet-sockets:accept-socket fd)
          while client
          do (cl-pnet-sockets:set-nonblocking client)
             (let ((bridge nil))
               (handler-case
                   (let ((channel
                           (cl-pnet-ssh:ssh-server-open-forwarded-streamlocal
                            (streamlocal-forward-session forward)
                            (streamlocal-forward-path forward)
                            :on-data
                            (lambda (channel data kind)
                              (declare (ignore channel kind))
                              (when bridge
                                (streamlocal-bridge-on-data bridge data)))
                            :on-eof
                            (lambda (channel)
                              (declare (ignore channel))
                              (when bridge
                                (streamlocal-bridge-on-eof bridge)))
                            :on-close
                            (lambda (channel)
                              (declare (ignore channel))
                              (when bridge
                                (streamlocal-bridge-close bridge)))
                            :on-error
                            (lambda (channel condition)
                              (declare (ignore channel condition))
                              (when bridge
                                (streamlocal-bridge-close bridge))))))
                     (setf bridge
                           (%make-streamlocal-bridge
                            :channel channel :fd client))
                     (streamlocal-bridge-connected bridge))
                 (error (condition)
                   (declare (ignore condition))
                   (ignore-errors (c-close client))))))))

(defun cancel-streamlocal-remote-forward (session path)
  "Stop a streamlocal listener the client cancelled."
  (let ((forward
          (find-if (lambda (candidate)
                     (and (eq (streamlocal-forward-session candidate) session)
                          (string= (streamlocal-forward-path candidate) path)))
                   *streamlocal-forwards*)))
    (if forward
        (progn
          (streamlocal-forward-close forward)
          (setf *streamlocal-forwards*
                (delete forward *streamlocal-forwards*))
          t)
        nil)))

;;; ---- Agent forwarding ----
;;;
;;; sshd creates a Unix listener for a session that asks for agent
;;; forwarding, puts its path in SSH_AUTH_SOCK, and relays each accepted
;;; connection to the client.  AgentSocketPath names where that listener
;;; lives; "user:" keeps it under a directory the user owns, "shared:" makes
;;; a temporary directory below a shared one.  The library applies the
;;; AllowAgentForwarding, DisableForwarding and no-agent-forwarding policy and
;;; does the relaying; this code only chooses and creates the socket.

#-win32
(defun agent-random-suffix (length)
  "LENGTH characters from the class ssh uses for temporary socket names."
  (let ((alphabet
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        (text (make-string length)))
    (dotimes (index length text)
      (setf (char text index) (char alphabet (random (length alphabet)))))))

#-win32
(cffi:defcfun ("mkdir" c-mkdir) :int
  (path :string) (mode :unsigned-int))

#-win32
(cffi:defcfun ("rmdir" c-rmdir) :int
  (path :string))

#-win32
(defun ensure-private-directory (path)
  "Create PATH, and any missing parents, with sshd's 0700 mode."
  (let ((directory (uiop:ensure-directory-pathname path)))
    (unless (uiop:directory-exists-p directory)
      (let ((old-mask (c-umask #o077)))
        (unwind-protect
             (ignore-errors (ensure-directories-exist directory))
          (c-umask old-mask))))
    (uiop:directory-exists-p directory)))

#-win32
(defun agent-percent-expand (text user home uid)
  "Expand AgentSocketPath's %u, %U and %h tokens; NIL on an unknown one."
  (let ((output (make-string-output-stream)))
    (loop with index = 0
          while (< index (length text))
          do (let ((character (char text index)))
               (cond
                 ((and (char= character #\%)
                       (< (1+ index) (length text)))
                  (let ((token (char text (1+ index))))
                    (case token
                      ((#\u) (write-string user output))
                      ((#\U) (write-string (or uid "") output))
                      ((#\h) (write-string home output))
                      ((#\%) (write-char #\% output))
                      (t (return-from agent-percent-expand nil)))
                    (incf index 2)))
                 (t
                  (write-char character output)
                  (incf index)))))
    (get-output-stream-string output)))

#-win32
(defun expand-agent-directory (directory user home uid)
  "DIRECTORY with sshd's tokens and ~ expansion, absolute, or NIL."
  (let ((text (agent-percent-expand directory user home uid)))
    (when text
      (cond
        ((string= text "")
         nil)
        ((and (> (length text) 1)
              (string= (subseq text 0 2) "~/"))
         (namestring (merge-pathnames (subseq text 2)
                                      (uiop:ensure-directory-pathname home))))
        ((string= text "~")
         (namestring (uiop:ensure-directory-pathname home)))
        ((char= (char text 0) #\~)
         ;; ~otheruser needs another passwd lookup and sshd's path helpers;
         ;; refusing is safer than guessing whose directory was meant.
         nil)
        ((char= (char text 0) #\/)
         text)
        (t
         (format nil "~A/~A"
                 (string-right-trim "/" home) text))))))

#-win32
(defun agent-socket-directory (pathspec session)
  "The directory PATHSPEC names for SESSION, and whether it is shared."
  (multiple-value-bind (home uid)
      (user-home-and-uid (cl-pnet-ssh:ssh-session-user session))
    (when home
      (cond
        ((and (> (length pathspec) 7)
              (string-equal (subseq pathspec 0 7) "shared:"))
         (values (expand-agent-directory
                  (subseq pathspec 7)
                  (cl-pnet-ssh:ssh-session-user session) home uid)
                 t))
        ((and (> (length pathspec) 5)
              (string-equal (subseq pathspec 0 5) "user:"))
         (values (expand-agent-directory
                  (subseq pathspec 5)
                  (cl-pnet-ssh:ssh-session-user session) home uid)
                 nil))
        (t nil)))))

#-win32
(defun start-agent-forward (session)
  "Create the Unix listener SESSION's forwarded agent will accept on.

Returns (VALUES FD PATH CLEANUP) for the library, or NIL when
AgentSocketPath is none or the socket cannot be created."
  (let* ((pathspec
           (or (session-config-setting
                session
                #'cl-pnet-ssh:ssh-server-config-agent-socket-path)
               "user:~/.ssh/agent")))
    (when (string-equal pathspec "none")
      (return-from start-agent-forward nil))
    (multiple-value-bind (directory shared)
        (agent-socket-directory pathspec session)
      (unless directory
        (log-at-session session :error
                        "cannot expand AgentSocketPath ~A" pathspec)
        (return-from start-agent-forward nil))
      (flet ((open-listener (socket-path)
               (handler-case
                   (cl-pnet-sockets:listen-unix socket-path :mask #o177)
                 (error (condition)
                   (declare (ignore condition))
                   (log-at-session session :error
                                   "cannot listen on agent socket ~A"
                                   socket-path)
                   nil))))
        (if shared
            ;; A shared parent needs a private directory per session, which
            ;; is what sshd's mkdtemp step creates and removes.
            (let* ((temporary
                     (format nil "~A/ssh-~A"
                             (string-right-trim "/" directory)
                             (agent-random-suffix 12)))
                   (socket-path (format nil "~A/agent.~D"
                                        temporary (c-getpid))))
              (unless (ensure-private-directory temporary)
                (log-at-session session :error
                                "cannot create agent socket directory ~A"
                                temporary)
                (return-from start-agent-forward nil))
              (let ((fd (open-listener socket-path)))
                (unless fd
                  (ignore-errors (c-rmdir temporary))
                  (return-from start-agent-forward nil))
                (log-at-session session :verbose
                                "agent forwarding listening on ~A" socket-path)
                (values fd socket-path
                        (lambda ()
                          (ignore-errors (delete-file socket-path))
                          (ignore-errors (c-rmdir temporary))))))
            (let* ((socket-path
                     (format nil "~A/s.~A.~D.~A"
                             (string-right-trim "/" directory)
                             (agent-random-suffix 10)
                             (c-getpid)
                             (agent-random-suffix 10)))
                   (fd (progn
                         (unless (ensure-private-directory directory)
                           (log-at-session session :error
                                           "cannot create agent socket directory ~A"
                                           directory)
                           (return-from start-agent-forward nil))
                         (open-listener socket-path))))
              (unless fd
                (return-from start-agent-forward nil))
              (log-at-session session :verbose
                              "agent forwarding listening on ~A" socket-path)
              (values fd socket-path
                      (lambda () (ignore-errors (delete-file socket-path))))))))))
)

#+win32
(defun close-streamlocal-forwards (&optional session)
  (declare (ignore session))
  nil)

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
  (unless (remote-forwarding-allowed-p session)
    (log-at-session session :error "remote forwarding refused by policy")
    (return-from start-remote-forward nil))
  (let ((address (remote-bind-address session bind-address)))
    (unless address
      (log-at-session session :error
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
        (log-at-session session :error
                        "remote forward could not listen on ~A:~D"
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

(defun configured-subsystems (&optional session)
  "Subsystem (NAME . PROGRAM) pairs from -S, else from the sshd_config.

SESSION selects the Match-resolved Subsystem list for a connection; NIL
means the startup config."
  (or (and (getf *options* :subsystem)
           (mapcar #'split-subsystem
                   (reverse (getf *options* :subsystem))))
      (if session
          (session-config-setting
           session #'cl-pnet-ssh:ssh-server-config-subsystems)
          (config-setting #'cl-pnet-ssh:ssh-server-config-subsystems))))

(defun subsystem-path (name &optional session)
  "The program for subsystem NAME, or NIL when nothing serves it."
  (let ((configured (assoc name (configured-subsystems session)
                           :test #'string=)))
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

(defun start-command (channel command &key extra-environment chroot)
  "Run COMMAND as a child, on the pty the client asked for if there is one.

The channel's accepted environment requests are added to the child's own
environment, so a SendEnv from the client arrives where the command can see
it.  The library has already applied AcceptEnv.  EXTRA-ENVIRONMENT is added
last, for values the server itself sets such as SSH_ORIGINAL_COMMAND.
CHROOT, when given, is entered before the command runs."
  (let ((environment (session-environment channel)))
    (dolist (pair extra-environment)
      (setf environment
            (environment-put environment (car pair) (cdr pair))))
    (if (channel-pty-p channel)
        (multiple-value-bind (pid master status)
            (spawn-pty-shell command (user-shell)
                             :environment environment
                             :rows (channel-rows channel)
                             :columns (channel-columns channel)
                             :chroot chroot)
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :master-fd master :status-fd status
                        :pty t :stderr-eof t)))
        (multiple-value-bind (pid stdin stdout stderr status)
            (spawn-shell command :environment environment :chroot chroot)
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :stdin-fd stdin :stdout-fd stdout
                        :stderr-fd stderr :status-fd status))))))

(defun start-program (channel program arguments &key chroot)
  "Run PROGRAM with ARGUMENTS on CHANNEL, without shell expansion."
  (let ((environment (session-environment channel)))
    (if (channel-pty-p channel)
        (multiple-value-bind (pid master status)
            (spawn-pty-program program arguments
                               :environment environment
                               :rows (channel-rows channel)
                               :columns (channel-columns channel)
                               :chroot chroot)
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :master-fd master :status-fd status
                        :pty t :stderr-eof t)))
        (multiple-value-bind (pid stdin stdout stderr status)
            (spawn-program program arguments :environment environment
                                               :chroot chroot)
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :stdin-fd stdin :stdout-fd stdout
                        :stderr-fd stderr :status-fd status))))))

(defun start-login-shell (channel &key chroot)
  "Run the login shell, on the pty when one was requested.

A non-pty login shell keeps its stdout and stderr separate, as sshd does for
-T; a pty merges them, as a terminal does."
  (if (channel-pty-p channel)
      (start-command channel nil :chroot chroot)
      (start-program channel (user-shell) (list "-l") :chroot chroot)))

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

;;; ---- stream-local forwarding ----
;;;
;;; A direct-streamlocal channel names a Unix-domain socket on this host.
;;; The library approves the path; this program owns the socket, so it can
;;; bridge it without teaching the library about file descriptors.

#-win32
(progn
(defstruct (streamlocal-bridge (:constructor %make-streamlocal-bridge))
  channel
  fd
  read-watcher
  write-watcher
  (pending (make-array 0 :element-type '(unsigned-byte 8)
                         :adjustable t :fill-pointer 0))
  (offset 0)
  (input-closed nil)
  (output-closed nil)
  (shutdown-done nil)
  (closed nil))

(defun streamlocal-bridge-close (bridge)
  "Close BRIDGE's socket and watchers once."
  (unless (streamlocal-bridge-closed bridge)
    (setf (streamlocal-bridge-closed bridge) t)
    (when (streamlocal-bridge-read-watcher bridge)
      (cl-pnet:fd-unwatch (streamlocal-bridge-read-watcher bridge))
      (setf (streamlocal-bridge-read-watcher bridge) nil))
    (when (streamlocal-bridge-write-watcher bridge)
      (cl-pnet:fd-unwatch (streamlocal-bridge-write-watcher bridge))
      (setf (streamlocal-bridge-write-watcher bridge) nil))
    (let ((fd (streamlocal-bridge-fd bridge)))
      (when (and fd (not (minusp fd)))
        (ignore-errors (c-close fd))
        (setf (streamlocal-bridge-fd bridge) nil)))))

(defun streamlocal-bridge-fail (bridge condition)
  "Report CONDITION and close BRIDGE and its channel."
  (log-at-session
   (cl-pnet-ssh:ssh-server-channel-session (streamlocal-bridge-channel bridge))
   :error "direct-streamlocal: ~A" condition)
  (streamlocal-bridge-close bridge)
  (ignore-errors
    (cl-pnet-ssh:ssh-server-channel-close
     (streamlocal-bridge-channel bridge))))

(defun streamlocal-bridge-shutdown-input (bridge)
  "Shut the socket's write side once the client's queued data has drained."
  (when (and (streamlocal-bridge-input-closed bridge)
             (not (streamlocal-bridge-shutdown-done bridge))
             (zerop (fill-pointer (streamlocal-bridge-pending bridge))))
    (setf (streamlocal-bridge-shutdown-done bridge) t)
    (let ((fd (streamlocal-bridge-fd bridge)))
      (when (and fd (not (minusp fd)))
        (ignore-errors (cl-pnet-sockets:c-shutdown fd 1))))))

(defun streamlocal-bridge-flush (bridge)
  "Send BRIDGE's queued client data to the Unix socket."
  (unless (or (streamlocal-bridge-closed bridge)
              (streamlocal-bridge-input-closed bridge))
    (let* ((fd (streamlocal-bridge-fd bridge))
           (pending (streamlocal-bridge-pending bridge))
           (offset (streamlocal-bridge-offset bridge))
           (failed nil))
      (loop while (< offset (fill-pointer pending))
            do (multiple-value-bind (count error)
                   (cl-pnet-sockets:write-octets
                    fd pending :start offset)
                 (cond
                   ((plusp count) (incf offset count))
                   ((member error '(4 11)) (return))
                   (t
                    (setf failed error)
                    (return)))))
      (setf (streamlocal-bridge-offset bridge) offset)
      (cond
        (failed
         (streamlocal-bridge-fail
          bridge
          (make-condition 'cl-pnet-ssh:ssh-connection-error
                          :detail (format nil "Unix socket write failed (~A)"
                                          failed))))
        ((>= offset (fill-pointer pending))
         (setf (fill-pointer pending) 0
               (streamlocal-bridge-offset bridge) 0)
         (when (streamlocal-bridge-write-watcher bridge)
           (cl-pnet:fd-unwatch (streamlocal-bridge-write-watcher bridge))
           (setf (streamlocal-bridge-write-watcher bridge) nil))
         (streamlocal-bridge-shutdown-input bridge))
        (t
         (unless (streamlocal-bridge-write-watcher bridge)
           (setf (streamlocal-bridge-write-watcher bridge)
                 (cl-pnet:fd-watch
                  fd :on-writable
                  (lambda (watcher)
                    (declare (ignore watcher))
                    (setf (streamlocal-bridge-write-watcher bridge) nil)
                    (streamlocal-bridge-flush bridge))))))))))

(defun streamlocal-bridge-on-data (bridge data)
  "Queue client DATA for the Unix socket."
  (unless (or (streamlocal-bridge-closed bridge)
              (streamlocal-bridge-input-closed bridge))
    (let ((pending (streamlocal-bridge-pending bridge)))
      (loop for octet across data
            do (vector-push-extend octet pending)))
    (streamlocal-bridge-flush bridge)))

(defun streamlocal-bridge-on-eof (bridge)
  "The client sent EOF: drain what it queued, then shut the socket's writer."
  (unless (streamlocal-bridge-closed bridge)
    (setf (streamlocal-bridge-input-closed bridge) t)
    (streamlocal-bridge-shutdown-input bridge)
    (when (streamlocal-bridge-output-closed bridge)
      (ignore-errors
        (cl-pnet-ssh:ssh-server-channel-close
         (streamlocal-bridge-channel bridge))))))

(defun streamlocal-bridge-on-readable (bridge)
  "Read the Unix socket and send what it yields to the client."
  (unless (streamlocal-bridge-closed bridge)
    (multiple-value-bind (data count error)
        (cl-pnet-sockets:read-octets (streamlocal-bridge-fd bridge) 4096)
      (cond
        ((plusp count)
         (ignore-errors
           (cl-pnet-ssh:ssh-server-channel-write
            (streamlocal-bridge-channel bridge) data)))
        ((or (zerop count) (member error '(5 104 111)))
         ;; EOF, EIO on a closed peer, ECONNRESET or ECONNREFUSED.
         (setf (streamlocal-bridge-output-closed bridge) t)
         (when (streamlocal-bridge-read-watcher bridge)
           (cl-pnet:fd-unwatch (streamlocal-bridge-read-watcher bridge))
           (setf (streamlocal-bridge-read-watcher bridge) nil))
         (ignore-errors
           (cl-pnet-ssh:ssh-server-channel-eof
            (streamlocal-bridge-channel bridge)))
         (when (streamlocal-bridge-input-closed bridge)
           (ignore-errors
             (cl-pnet-ssh:ssh-server-channel-close
              (streamlocal-bridge-channel bridge)))))
        (t
         (streamlocal-bridge-fail
          bridge
          (make-condition 'cl-pnet-ssh:ssh-connection-error
                          :detail (format nil "Unix socket read failed (~A)"
                                          error))))))))

(defun streamlocal-bridge-connected (bridge)
  "BRIDGE's socket is connected: watch it and send anything already queued."
  (setf (streamlocal-bridge-read-watcher bridge)
        (cl-pnet:fd-watch
         (streamlocal-bridge-fd bridge)
         :on-readable
         (lambda (watcher)
           (declare (ignore watcher))
           (streamlocal-bridge-on-readable bridge))))
  (streamlocal-bridge-flush bridge))

(defun start-streamlocal-bridge (channel)
  "Bridge CHANNEL to the Unix socket its open named."
  (let ((path (cl-pnet-ssh:ssh-server-channel-streamlocal-path channel)))
    (multiple-value-bind (fd state)
        (cl-pnet-sockets:connect-unix path)
      (if (null fd)
          (progn
            (log-at-session
             (cl-pnet-ssh:ssh-server-channel-session channel)
             :error "direct-streamlocal ~A: ~A"
             path (cl-pnet-sockets:c-strerror state))
            (ignore-errors (cl-pnet-ssh:ssh-server-channel-close channel)))
          (let ((bridge (%make-streamlocal-bridge :channel channel :fd fd)))
            (setf (cl-pnet-ssh:ssh-server-channel-on-data channel)
                  (lambda (channel data kind)
                    (declare (ignore channel kind))
                    (streamlocal-bridge-on-data bridge data))
                  (cl-pnet-ssh:ssh-server-channel-on-eof channel)
                  (lambda (channel)
                    (declare (ignore channel))
                    (streamlocal-bridge-on-eof bridge))
                  (cl-pnet-ssh:ssh-server-channel-on-close channel)
                  (lambda (channel)
                    (declare (ignore channel))
                    (streamlocal-bridge-close bridge)))
            (if (eq state :connected)
                (streamlocal-bridge-connected bridge)
                (setf (streamlocal-bridge-write-watcher bridge)
                      (cl-pnet:fd-watch
                       fd :on-writable
                       (lambda (watcher)
                         (declare (ignore watcher))
                         (setf (streamlocal-bridge-write-watcher bridge) nil)
                         (multiple-value-bind (errno answered)
                             (cl-pnet-sockets:socket-error fd)
                           (if (and answered (zerop errno))
                               (streamlocal-bridge-connected bridge)
                               (streamlocal-bridge-fail
                                bridge
                                (make-condition
                                 'cl-pnet-ssh:ssh-connection-error
                                 :detail
                                 (format nil "Unix socket connect failed (~A)"
                                         errno)))))))))))))))

(defun install-channel-handlers (channel)
  "Attach the session policy and remember the bridge for window changes.

A forced command replaces the client's exec, shell or subsystem command, as
sshd's ForceCommand and the authorized_keys command= option do; ForceCommand
wins when both are present.  It runs through the same bridge as any other
command, with SSH_ORIGINAL_COMMAND in its environment holding what the client
asked for, when it asked for anything."
  #-win32
  (when (string= (cl-pnet-ssh:ssh-server-channel-type channel)
                 "direct-streamlocal@openssh.com")
    (start-streamlocal-bridge channel)
    (return-from install-channel-handlers nil))
  (let* ((session (cl-pnet-ssh:ssh-server-channel-session channel))
         (authorization (cl-pnet-ssh:ssh-session-authorization session))
         (forced-command
           (or (session-config-setting
                session #'cl-pnet-ssh:ssh-server-config-force-command)
               (and authorization
                    (cl-pnet-ssh:ssh-authorization-options-force-command
                     authorization))))
         (chroot
           (handler-case (session-chroot-directory session)
             (error (condition)
               (session-failure channel "~A" condition)
               (return-from install-channel-handlers nil))))
         (bridge nil))
    (labels ((remember (new-bridge)
               (setf bridge new-bridge))
           (run-command (command)
             (if (command-allowed-p command)
                 (handler-case
                     (remember (start-command channel command :chroot chroot))
                   (error (condition)
                     (session-failure channel "~A" condition)))
                 (session-failure channel "command not allowed: ~A" command)))
           (run-forced (original-command)
             (handler-case
                 (remember
                  (start-command
                   channel forced-command
                   :chroot chroot
                   :extra-environment
                   (and original-command
                        (list (cons "SSH_ORIGINAL_COMMAND" original-command)))))
               (error (condition) (session-failure channel "~A" condition))))
           (run-shell ()
             (handler-case
                 (remember (start-login-shell channel :chroot chroot))
               (error (condition) (session-failure channel "~A" condition))))
           (run-subsystem (path)
             (handler-case
                 (remember (start-program channel path nil :chroot chroot))
               (error (condition) (session-failure channel "~A" condition)))))
      (setf (cl-pnet-ssh:ssh-server-channel-on-exec channel)
            (lambda (channel command)
              (declare (ignore channel))
              (if forced-command
                  (run-forced command)
                  (run-command command))))
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
              (lambda () (if forced-command
                             (run-forced nil)
                             (run-shell)))))
      (setf (cl-pnet-ssh:ssh-server-channel-on-subsystem channel)
            (lambda (channel name)
              (declare (ignore channel))
              ;; sshd still refuses an unknown subsystem before the forced
              ;; command is considered, so look the name up first.
              (let ((path (subsystem-path name session)))
                (and path
                     (if forced-command
                         (lambda () (run-forced path))
                         (lambda () (run-subsystem path)))))))
      (setf (cl-pnet-ssh:ssh-server-channel-on-window-change channel)
            (lambda (channel columns rows)
              (declare (ignore channel))
              (when bridge
                (bridge-resize bridge columns rows)))))))

(defun home-file (name)
  (merge-pathnames name (user-homedir-pathname)))

(defun x11-authority-file (session)
  "The Xauthority file sshd records a forwarded display's cookie in.

The file follows the account's home, as sshd runs xauth as that user; the
server process's own XAUTHORITY would be the wrong one when it serves more
than one account."
  (multiple-value-bind (home uid)
      (user-home-and-uid (cl-pnet-ssh:ssh-session-user session))
    (declare (ignore uid))
    (and home
         (namestring (merge-pathnames ".Xauthority"
                                      (uiop:ensure-directory-pathname home))))))

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

#-win32
(cffi:defcfun ("getuid" c-getuid) :unsigned-int)

#-win32
(defun current-user-name ()
  "The name of the account running this process, or NIL.

AuthorizedPrincipalsCommandUser selects which account the command runs as;
without privilege separation this server can only use its own."
  (let ((uid (format nil "~D" (c-getuid))))
    (with-open-file (stream "/etc/passwd" :direction :input
                            :if-does-not-exist nil)
      (when stream
        (loop for line = (read-line stream nil nil)
              while line
              for fields = (uiop:split-string line :separator ":")
              when (and (>= (length fields) 3)
                        (string= (nth 2 fields) uid))
                do (return (first fields)))))))

#+win32
(defun current-user-name ()
  (uiop:getenv "USERNAME"))

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

(defun expand-session-path (pattern user home uid)
  "PATTERN with sshd's %h, %u, %U and %% expanded for USER.

A leading ~ is the user's home, as tilde_expand_filename does.  Unlike an
AuthorizedKeysFile pattern, a relative result is left relative so chroot
can refuse it."
  (let ((pattern (if (and (plusp (length pattern))
                          (char= (char pattern 0) #\~)
                          (or (= (length pattern) 1)
                              (char= (char pattern 1) #\/)))
                     (concatenate 'string (or home "") (subseq pattern 1))
                     pattern)))
    (with-output-to-string (out)
      (loop with length = (length pattern)
            for index from 0 below length
            for character = (char pattern index)
            do (if (and (char= character #\%)
                        (< (1+ index) length))
                   (case (char pattern (1+ index))
                     (#\h (write-string (or home "") out) (incf index))
                     (#\u (write-string user out) (incf index))
                     (#\U (write-string (or uid "") out) (incf index))
                     (#\% (write-char #\% out) (incf index))
                     (t (write-char character out)))
                   (write-char character out))))))

(defun safely-chroot-path-p (path)
  "Whether every component of PATH is a root-owned, unwritable directory.

This is sshd's safely_chroot check.  Only SBCL can inspect the ownership
and mode here, so another implementation refuses the chroot rather than
skipping the check."
  (and (plusp (length path))
       (char= (char path 0) #\/)
       #+sbcl
       (let ((prefixes '()))
         (loop for index from 1 below (length path)
               when (char= (char path index) #\/)
                 do (push (subseq path 0 index) prefixes))
         (push path prefixes)
         (every (lambda (prefix)
                  (handler-case
                      (let ((stat (sb-posix:stat prefix)))
                        (and (sb-posix:s-isdir (sb-posix:stat-mode stat))
                             (zerop (sb-posix:stat-uid stat))
                             (zerop (logand (sb-posix:stat-mode stat) #o022))))
                    (error () nil)))
                (nreverse prefixes)))
       #-sbcl
       nil))

(defun session-chroot-directory (session)
  "SESSION's expanded ChrootDirectory, or NIL when none is configured.

The path is expanded for the session's user and checked before any child
starts, so a bad directory refuses the session instead of failing after the
client's command has been accepted."
  (let ((value (session-config-setting
                session #'cl-pnet-ssh:ssh-server-config-chroot-directory)))
    (unless (or (null value) (eq value :none))
      (multiple-value-bind (home uid)
          (user-home-and-uid (cl-pnet-ssh:ssh-session-user session))
        (let ((path (expand-session-path
                     value (cl-pnet-ssh:ssh-session-user session)
                     home uid)))
          (unless (and (plusp (length path))
                       (char= (char path 0) #\/))
            (error "ChrootDirectory ~A is not an absolute path" path))
          (unless (safely-chroot-path-p path)
            (error "ChrootDirectory ~A is not a root-owned, unwritable directory"
                   path))
          path)))))

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

(defun host-key-agent ()
  "The HostKeyAgent socket, or NIL."
  (config-setting #'cl-pnet-ssh:ssh-server-config-host-key-agent))

(defun host-certificate-files ()
  "The --host-certificate files, then the config's HostCertificate files."
  (append (reverse (getf *options* :host-certificate))
          (config-setting
           #'cl-pnet-ssh:ssh-server-config-host-certificate-files)))

(defun root-uid-p (user)
  "Whether USER is uid 0, the only account PermitRootLogin governs."
  (let ((uid (nth-value 1 (user-home-and-uid user))))
    (and uid (string= uid "0"))))

;;; ---- Hostbased authentication ----
;;;
;;; The library verifies the client host's signature; this program decides
;;; whether the host and the client user are trusted, using sshd's rhosts
;;; and known_hosts rules.

(defvar *hostbased-system-rhosts*
  '("/etc/hosts.equiv" "/etc/ssh/shosts.equiv")
  "The system-wide rhosts files, in sshd's order.")

(defvar *hostbased-system-known-hosts*
  '("/etc/ssh/ssh_known_hosts" "/etc/ssh/ssh_known_hosts2")
  "The system-wide known_hosts files used by hostbased authentication.")

(defun rhosts-line-decision (line host ip client-user server-user)
  "Whether LINE allows or denies CLIENT-USER from HOST/IP.

Returns :ALLOW, :DENY or NIL.  A leading + or - negates or wildcards an
entry; netgroups (@) and empty wildcards are ignored, as sshd does."
  (let* ((trimmed (string-trim '(#\Space #\Tab #\Return) line))
         (hash (position #\# trimmed))
         (text (string-trim '(#\Space #\Tab)
                            (if hash (subseq trimmed 0 hash) trimmed))))
    (when (plusp (length text))
      (let ((fields (remove "" (uiop:split-string
                                text :separator '(#\Space #\Tab))
                            :test #'string=)))
        (when (<= 1 (length fields) 2)
          (let ((host-field (first fields))
                (user-field (or (second fields) server-user))
                (negated nil))
            (when (and (plusp (length host-field))
                       (member (char host-field 0) '(#\- #\+)))
              (setf negated (char= (char host-field 0) #\-))
              (setf host-field (subseq host-field 1)))
            (when (and (plusp (length user-field))
                       (member (char user-field 0) '(#\- #\+)))
              (setf negated (or negated
                                (char= (char user-field 0) #\-)))
              (setf user-field (subseq user-field 1)))
            (when (and (plusp (length host-field))
                       (plusp (length user-field))
                       (not (char= (char host-field 0) #\@))
                       (not (char= (char user-field 0) #\@))
                       (or (string-equal host-field host)
                           (string= host-field ip))
                       (string= user-field client-user))
              (if negated :deny :allow))))))))

(defun rhosts-file-decision (path host ip client-user server-user)
  "The first decision in PATH, or NIL when no line matches."
  (handler-case
      (when (probe-file path)
        (dolist (line (uiop:read-file-lines path))
          (let ((decision
                  (rhosts-line-decision
                   line host ip client-user server-user)))
            (when decision (return decision)))))
    (error () nil)))

(defun strict-rhosts-file-p (path user-uid)
  "Whether PATH is a regular file owned by root or USER-UID and not writable
by group or others."
  #+sbcl
  (handler-case
      (let* ((stat (sb-posix:stat path))
             (mode (sb-posix:stat-mode stat))
             (uid (sb-posix:stat-uid stat)))
        (and (sb-posix:s-isreg mode)
             (or (zerop uid)
                 (and user-uid
                      (string= (princ-to-string uid) user-uid)))
             (zerop (logand mode #o022))))
    (error () nil))
  #-sbcl
  (declare (ignore path user-uid))
  #-sbcl
  nil)

(defun strict-home-directory-p (home user-uid)
  "Whether HOME is a directory owned by root or USER-UID and not writable
by group or others."
  #+sbcl
  (handler-case
      (let* ((stat (sb-posix:stat home))
             (mode (sb-posix:stat-mode stat))
             (uid (sb-posix:stat-uid stat)))
        (and (sb-posix:s-isdir mode)
             (or (zerop uid)
                 (and user-uid
                      (string= (princ-to-string uid) user-uid)))
             (zerop (logand mode #o022))))
    (error () nil))
  #-sbcl
  (declare (ignore home user-uid))
  #-sbcl
  nil)

(defun hostbased-rhosts-allowed-p (session user client-user host ip)
  "Whether sshd's rhosts files admit CLIENT-USER at HOST/IP for USER."
  (multiple-value-bind (home uid) (user-home-and-uid user)
    (when home
      (let* ((ignore (or (session-config-setting
                          session
                          #'cl-pnet-ssh:ssh-server-config-ignore-rhosts)
                         :yes))
             (strict (let ((value (session-config-setting
                                   session
                                   #'cl-pnet-ssh:ssh-server-config-strict-modes)))
                       (not (eq value :no))))
             (server-user user)
             (directory (uiop:ensure-directory-pathname home))
             (system-files
               (unless (root-uid-p user)
                 *hostbased-system-rhosts*))
             (user-files
               (unless (eq ignore :yes)
                 (if (eq ignore :shosts-only)
                     (list (merge-pathnames ".shosts" directory))
                     (list (merge-pathnames ".shosts" directory)
                           (merge-pathnames ".rhosts" directory))))))
        (and (or (not strict) (strict-home-directory-p home uid))
             (or (some (lambda (path)
                         (eq :allow (rhosts-file-decision
                                     path host ip client-user server-user)))
                       system-files)
                 (and user-files
                      (some (lambda (path)
                              (and (or (not strict)
                                       (strict-rhosts-file-p path uid))
                                   (eq :allow
                                       (rhosts-file-decision
                                        path host ip
                                        client-user server-user))))
                            user-files))))))))

(defun hostbased-known-host-p (session lookup key-blob)
  "Whether KEY-BLOB is a known host key for LOOKUP."
  (when (cl-pnet-ssh:ssh-certificate-blob-p key-blob)
    ;; Host certificates would need their CA and principal checked here.
    (return-from hostbased-known-host-p nil))
  (let* ((user-file
           (unless (session-config-setting
                    session
                    #'cl-pnet-ssh:ssh-server-config-ignore-user-known-hosts)
             (multiple-value-bind (home uid)
                 (user-home-and-uid (cl-pnet-ssh:ssh-session-user session))
               (declare (ignore uid))
               (and home
                    (merge-pathnames ".ssh/known_hosts"
                                     (uiop:ensure-directory-pathname home))))))
         (files (append *hostbased-system-known-hosts*
                        (when user-file
                          (list user-file)))))
    (some (lambda (path)
            (eq :match
                (cl-pnet-ssh:ssh-known-host-status path lookup key-blob)))
          files)))

(defun hostbased-key-allowed-p (session user client-user client-host key-blob)
  "Whether the client host and its rhosts/known_hosts entry admit USER.

Without UseDNS the server resolves the peer to its IP, so unless
HostbasedUsesNameFromPacketOnly is set, the IP is what known_hosts and the
rhosts files are matched against."
  (let* ((packet-only
           (eq (session-config-setting
                session
                #'cl-pnet-ssh:ssh-server-config-hostbased-uses-name-from-packet-only)
               :yes))
         (peer (session-remote-ip session))
         (claimed (string-right-trim "." client-host))
         (lookup (if packet-only claimed (or peer "")))
         (host (if packet-only claimed (or peer "")))
         (ip (or peer "")))
    (and (not (zerop (length lookup)))
         (hostbased-rhosts-allowed-p
          session user client-user host ip)
         (hostbased-known-host-p session lookup key-blob))))

;;; ---- Certificate authentication ----
;;;
;;; A certificate adds a CA signature and a principal list to an ordinary
;;; key.  The CA is trusted through TrustedUserCAKeys or a cert-authority
;;; line in authorized_keys, and the login name must be one of the
;;; certificate's principals or appear in AuthorizedPrincipalsFile or the
;;; output of AuthorizedPrincipalsCommand.  Those files are per user, so this
;;; program expands and reads them; the library parses and verifies.

(defun config-directive-value (value)
  "VALUE with sshd's \"none\" read as NIL."
  (and value
       (not (eq value :none))
       (not (and (stringp value) (string-equal value "none")))
       value))

(defun certificate-config-value (session accessor)
  "ACCESSOR's per-connection value, or NIL when it is \"none\" or absent."
  (config-directive-value (session-config-setting session accessor)))

(defun split-command-arguments (text)
  "TEXT split into arguments the way OpenSSH's argv_split does.

Single and double quotes group words and a backslash quotes the next
character.  An unmatched quote is an error rather than a silently different
command."
  (let ((arguments '())
        (current (make-string-output-stream))
        (started nil)
        (quote nil)
        (escape nil))
    (loop for character across text
          do (cond
               (escape
                (write-char character current)
                (setf escape nil started t))
               ((char= character #\\)
                (setf escape t started t))
               (quote
                (if (char= character quote)
                    (setf quote nil)
                    (write-char character current)))
               ((or (char= character #\") (char= character #\'))
                (setf quote character started t))
               ((member character '(#\Space #\Tab #\Return #\Newline))
                (when started
                  (push (get-output-stream-string current) arguments)
                  (setf started nil)))
               (t
                (write-char character current)
                (setf started t))))
    (when quote
      (error "unmatched ~C in command ~S" quote text))
    (when escape
      (write-char #\\ current)
      (setf started t))
    (when started
      (push (get-output-stream-string current) arguments))
    (nreverse arguments)))

(defun expand-command-tokens (text substitutions)
  "TEXT with %X tokens replaced from SUBSTITUTIONS, an alist of characters.

An unknown token is left as it is, as OpenSSH's percent_expand does for a
string that names no substitution."
  (with-output-to-string (out)
    (loop with length = (length text)
          for index from 0 below length
          for character = (char text index)
          do (let ((pair (and (char= character #\%)
                              (< (1+ index) length)
                              (assoc (char text (1+ index)) substitutions))))
               (if pair
                   (progn
                     (write-string (cdr pair) out)
                     (incf index))
                   (write-char character out))))))

(defun authorized-principals-command-lines
    (command command-user user home uid key-blob certificate)
  "The lines AuthorizedPrincipalsCommand prints for CERTIFICATE, or NIL.

The command is run as COMMAND-USER, which this build can only do when that
is the account running the server: there is no privilege separation to
switch users.  sshd requires the user whenever the command is set, and a
command that cannot run authorizes nothing."
  (let ((arguments
          (handler-case (split-command-arguments command)
            (error (condition)
              (log-at :error
                      "AuthorizedPrincipalsCommand is not a valid command: ~A"
                      condition)
              (return-from authorized-principals-command-lines nil)))))
    (unless (plusp (length arguments))
      (log-at :error "AuthorizedPrincipalsCommand names no program")
      (return-from authorized-principals-command-lines nil))
    (unless command-user
      (log-at :error
              "No user for AuthorizedPrincipalsCommand specified, skipping")
      (return-from authorized-principals-command-lines nil))
    (unless (string= (expand-command-tokens command-user
                                            (list (cons #\u user)))
                     (current-user-name))
      (log-at :error
              "AuthorizedPrincipalsCommandUser ~A is not supported: this server cannot switch users"
              command-user)
      (return-from authorized-principals-command-lines nil))
    (let* ((ca (cl-pnet-ssh:ssh-certificate-signature-key certificate))
           (substitutions
             (list
              (cons #\% "%")
              (cons #\U (or uid ""))
              (cons #\u user)
              (cons #\h (or home ""))
              (cons #\t (cl-pnet-ssh:ssh-certificate-key-type certificate))
              (cons #\T (nth-value 0 (cl-pnet-ssh:ssh-public-key-parts ca)))
              (cons #\f (cl-pnet-ssh:ssh-key-fingerprint key-blob))
              (cons #\F (cl-pnet-ssh:ssh-key-fingerprint ca))
              (cons #\k (cl-pnet-ssh:ssh-octets-base64 key-blob))
              (cons #\K (cl-pnet-ssh:ssh-octets-base64 ca))
              (cons #\i (cl-pnet-ssh:ssh-certificate-key-id certificate))
              (cons #\s (format nil "~D"
                                (cl-pnet-ssh:ssh-certificate-serial
                                 certificate))))))
      (handler-case
          (multiple-value-bind (output error-output status)
              (uiop:run-program
               (cons (first arguments)
                     (mapcar (lambda (argument)
                               (expand-command-tokens argument substitutions))
                             (rest arguments)))
               :output :string
               :error-output :string
               :ignore-error-status t)
            (declare (ignore error-output))
            (if (zerop status)
                (uiop:split-string output :separator '(#\Newline))
                (progn
                  (log-at :error
                          "AuthorizedPrincipalsCommand exited with status ~D"
                          status)
                  nil)))
        (error (condition)
          (log-at :error "AuthorizedPrincipalsCommand failed: ~A" condition)
          nil)))))

(defun authorized-keys-command-lines
    (command command-user user home uid key-blob)
  "The authorized_keys lines AuthorizedKeysCommand prints for KEY-BLOB, or NIL.

The command is run as COMMAND-USER, which this build can only do when that
is the account running the server: there is no privilege separation to switch
users.  A command that cannot run, or that exits nonzero, authorizes nothing,
as sshd's user_key_command_allowed2 does."
  (let ((arguments
          (handler-case (split-command-arguments command)
            (error (condition)
              (log-at :error
                      "AuthorizedKeysCommand is not a valid command: ~A"
                      condition)
              (return-from authorized-keys-command-lines nil)))))
    (unless (plusp (length arguments))
      (log-at :error "AuthorizedKeysCommand names no program")
      (return-from authorized-keys-command-lines nil))
    (unless command-user
      (log-at :error
              "No user for AuthorizedKeysCommand specified, skipping")
      (return-from authorized-keys-command-lines nil))
    (unless (string= (expand-command-tokens command-user
                                            (list (cons #\u user)))
                     (current-user-name))
      (log-at :error
              "AuthorizedKeysCommandUser ~A is not supported: this server cannot switch users"
              command-user)
      (return-from authorized-keys-command-lines nil))
    (let* ((substitutions
             (list
              (cons #\% "%")
              ;; %C needs the local endpoint, which the server does not
              ;; record, so it is left as written rather than guessed.
              (cons #\U (or uid ""))
              (cons #\u user)
              (cons #\h (or home ""))
              (cons #\t (nth-value 0 (cl-pnet-ssh:ssh-public-key-parts
                                      key-blob)))
              ;; sshd's %f is the plain key's fingerprint even when a
              ;; certificate is offered, while %k is the whole blob.
              (cons #\f (cl-pnet-ssh:ssh-key-fingerprint
                         (cl-pnet-ssh:ssh-key-plain-blob key-blob)))
              (cons #\k (cl-pnet-ssh:ssh-octets-base64 key-blob))
              ;; No routing domains are implemented, so %D is empty, as it
              ;; is for an sshd without routing domain support.
              (cons #\D "")))
           (program (first arguments))
           ;; sshd passes the target user name when the command names no
           ;; argument of its own.
           (program-arguments
             (if (rest arguments)
                 (mapcar (lambda (argument)
                           (expand-command-tokens argument substitutions))
                         (rest arguments))
                 (list user))))
      (handler-case
          (multiple-value-bind (output error-output status)
              (uiop:run-program (cons program program-arguments)
                                :output :string
                                :error-output :string
                                :ignore-error-status t)
            (declare (ignore error-output))
            (if (zerop status)
                (uiop:split-string output :separator '(#\Newline))
                (progn
                  (log-at :error
                          "AuthorizedKeysCommand exited with status ~D"
                          status)
                  nil)))
        (error (condition)
          (log-at :error "AuthorizedKeysCommand failed: ~A" condition)
          nil)))))

(defun read-text-file (path)
  "PATH's text, or an empty string when it cannot be read.

An unreadable AuthorizedPrincipalsFile authorizes nobody, as sshd's
match_principals_file finds no principals; treating it as empty is what keeps
a configured file from silently falling back to the user name."
  (handler-case
      (if (probe-file path)
          (uiop:read-file-string path)
          "")
    (error () "")))

(defun certificate-principals-source (session user home uid key-blob
                                      certificate)
  "The principals source for CERTIFICATE, or NIL to match USER directly.

AuthorizedPrincipalsFile's lines come first, then the command's, so a file
that yields a principal wins and a command is consulted when it does not.
NIL means neither is configured; a configured source that matches nothing
denies the login rather than falling back to the user name."
  (let ((file (certificate-config-value
               session
               #'cl-pnet-ssh:ssh-server-config-authorized-principals-file))
        (command (certificate-config-value
                  session
                  #'cl-pnet-ssh:ssh-server-config-authorized-principals-command))
        (command-user
          (certificate-config-value
           session
           #'cl-pnet-ssh:ssh-server-config-authorized-principals-command-user)))
    (cond
      ((or file command)
       (append
        (when file
          (uiop:split-string
           (if home
               (read-text-file (expand-authorized-keys-path file user home uid))
               "")
           :separator '(#\Newline)))
        (when command
          (authorized-principals-command-lines
           command command-user user home uid key-blob certificate))))
      (t nil))))

(defun approved-authorized-key (session user key-env authorization)
  "The authorized-keys-p answer for a key that matched USER's file.

PermitRootLogin forced-commands-only admits root only when the key that
authenticated carries command=, which sshd checks once the key options are
known.  Any other mode was already enforced before authentication."
  (if (and (root-uid-p user)
           (eq (session-config-setting
                session
                #'cl-pnet-ssh:ssh-server-config-permit-root-login)
               :forced-commands-only)
           (not (and authorization
                     (cl-pnet-ssh:ssh-authorization-options-force-command
                      authorization))))
      (values nil nil nil)
      (values t key-env authorization)))

(defun authorized-keys-p (user key-blob &optional address session)
  "Whether KEY-BLOB may log in as USER, and the environment it carries.

-A names one file for every user.  Otherwise AuthorizedKeysFile decides,
with its %h/%u/%U tokens expanded for USER; when the user has no local
passwd entry, the single key file of the account running the server is used,
so an unprivileged or Windows setup keeps working.  The second value is the
environment= options of the line that matched, which PermitUserEnvironment
decides whether to apply; the third is the rest of the line's options,
including from=, which ADDRESS is needed to check.  SESSION supplies the
Match-resolved AuthorizedKeysFile and PermitRootLogin when it is present.

A certificate is first checked against cert-authority lines in the same
files, then against TrustedUserCAKeys with AuthorizedPrincipalsFile or
AuthorizedPrincipalsCommand deciding the principal.  Only when neither
authorizes the key does AuthorizedKeysCommand run, and its output is read
as the same authorized_keys format."
  (labels ((approve (matched key-env authorization)
             (if matched
                 (approved-authorized-key session user key-env authorization)
                 (values nil nil nil)))
           (try-key-source (source certificate)
             (if certificate
                 (multiple-value-bind (matched key-env authorization)
                     (cl-pnet-ssh:ssh-certificate-authorized-key-match
                      source certificate user
                      :address address
                      :ca-signature-algorithms
                      (session-config-setting
                       session
                       #'cl-pnet-ssh:ssh-server-config-ca-signature-algorithms))
                   (when matched
                     (return-from authorized-keys-p
                       (approve matched key-env authorization))))
                 (multiple-value-bind (matched key-env authorization)
                     (cl-pnet-ssh:ssh-authorized-key-blob-match
                      source key-blob :address address)
                   (when matched
                     (return-from authorized-keys-p
                       (approve matched key-env authorization))))))
           (try-trusted-ca (certificate)
             (let ((ca-file
                     (certificate-config-value
                      session
                      #'cl-pnet-ssh:ssh-server-config-trusted-user-ca-keys)))
               (when ca-file
                 (multiple-value-bind (home uid) (user-home-and-uid user)
                   (multiple-value-bind (matched key-env authorization)
                       (cl-pnet-ssh:ssh-certificate-user-authorized-p
                        user key-blob
                        :address address
                        :ca-keys ca-file
                        :principals-source
                        (certificate-principals-source
                         session user home uid key-blob certificate)
                        :ca-signature-algorithms
                        (session-config-setting
                         session
                         #'cl-pnet-ssh:ssh-server-config-ca-signature-algorithms))
                     (when matched
                       (return-from authorized-keys-p
                         (approve matched key-env authorization)))))))))
    (let* ((certificate-type (cl-pnet-ssh:ssh-certificate-blob-p key-blob))
           (certificate
             (and certificate-type
                  (cl-pnet-ssh:ssh-certificate-parse key-blob))))
      ;; A blob that claims to be a certificate but does not parse is never
      ;; treated as the plain key it might wrap.
      (when (and certificate-type (null certificate))
        (return-from authorized-keys-p (values nil nil nil)))
      (let ((global (getf *options* :authorized-keys)))
        (if global
            (try-key-source global certificate)
            (multiple-value-bind (home uid) (user-home-and-uid user)
              (if (null home)
                  (try-key-source (home-file ".ssh/authorized_keys") certificate)
                  (let ((patterns
                          (or (session-config-setting
                               session
                               #'cl-pnet-ssh:ssh-server-config-authorized-keys-files)
                              cl-pnet-ssh:+ssh-server-config-default-authorized-keys-files+)))
                    (dolist (pattern patterns)
                      (unless (string-equal pattern "none")
                        (try-key-source
                         (expand-authorized-keys-path pattern user home uid)
                         certificate))))))))
      (when certificate
        (try-trusted-ca certificate))
      ;; sshd tries AuthorizedKeysCommand after both the files and the
      ;; trusted CAs, so a key found in either is not looked for there.
      (let ((command
              (certificate-config-value
               session
               #'cl-pnet-ssh:ssh-server-config-authorized-keys-command))
            (command-user
              (certificate-config-value
               session
               #'cl-pnet-ssh:ssh-server-config-authorized-keys-command-user)))
        (when command
          (multiple-value-bind (home uid) (user-home-and-uid user)
            (let ((lines (authorized-keys-command-lines
                          command command-user user home uid key-blob)))
              (when lines
                (try-key-source lines certificate)))))))
    (values nil nil nil)))

;;; ---- Account policy ----
;;;
;;; AllowUsers, DenyUsers, AllowGroups, DenyGroups and PermitRootLogin are
;;; decided when a user name first appears, before any authentication
;;; method runs, which is when sshd decides them too.

(defun session-remote-ip (session)
  "SESSION's peer address as text, or NIL when the backend did not report it."
  (getf (cl-pnet-ssh:ssh-session-remote-address session) :address))

(defun root-login-allowed-p (session user)
  "Whether PermitRootLogin admits USER at the start of authentication.

A non-root user always passes.  Root under forced-commands-only also passes
here, because sshd decides that mode once the authenticating key is known:
only a key carrying command= may log root in, which APPROVED-AUTHORIZED-KEY
checks after the key matches."
  (multiple-value-bind (home uid) (user-home-and-uid user)
    (declare (ignore home))
    (or (null uid)
        (not (string= uid "0"))
        (let ((mode (session-config-setting
                     session
                     #'cl-pnet-ssh:ssh-server-config-permit-root-login)))
          (or (eq mode :forced-commands-only)
              (cl-pnet-ssh:ssh-root-login-allowed-p mode "publickey"))))))

(defun user-allowed-p (session user)
  "Whether sshd's account policy admits USER from SESSION's peer."
  (and (root-login-allowed-p session user)
       (or (null (session-config session))
           (cl-pnet-ssh:ssh-server-user-allowed-p
            (session-config session) user
            (or (session-remote-ip session) "")
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

(defun check-certificate-config ()
  "Refuse certificate settings this server cannot honour.\n\nTrustedUserCAKeys must name a readable file, and AuthorizedPrincipalsCommand\nruns as AuthorizedPrincipalsCommandUser; without privilege separation only\nthe account running the server can be used, so a literal different name is a\nclear startup error rather than a login that quietly fails later.  A %u\ncommand user is checked per connection."
  (let ((config *server-config*))
    (when config
      (let ((ca (config-directive-value
                 (cl-pnet-ssh:ssh-server-config-trusted-user-ca-keys config))))
        (when (and ca (not (probe-file ca)))
          (fail "TrustedUserCAKeys file not found: ~A" ca)))
      (let ((command
              (config-directive-value
               (cl-pnet-ssh:ssh-server-config-authorized-principals-command
                config)))
            (user
              (config-directive-value
               (cl-pnet-ssh:ssh-server-config-authorized-principals-command-user
                config))))
        (when command
          (handler-case
              (split-command-arguments command)
            (error (condition)
              (fail "AuthorizedPrincipalsCommand is invalid: ~A" condition)))
          (unless user
            (fail "AuthorizedPrincipalsCommand needs AuthorizedPrincipalsCommandUser"))
          (when (and (not (find #\% user))
                     (not (string= user (current-user-name))))
            (fail "AuthorizedPrincipalsCommandUser ~A is not supported: this server cannot switch users"
                  user)))))))

(defun start-server ()
  (load-server-config)
  (check-certificate-config)
  (let ((host-keys (host-key-files)))
    (let ((agent (host-key-agent)))
      (dolist (host-key host-keys)
        (unless (or (probe-file host-key)
                    (and agent
                         (or (probe-file (concatenate
                                          'string (namestring host-key) ".pub"))
                             (probe-file host-key))))
          (fail "host key not found: ~A" host-key))))
    ;; sshd logs a HostCertificate it cannot load and serves the plain key,
    ;; so a bad certificate never stops the listener.
    (dolist (host-certificate (host-certificate-files))
      (unless (probe-file host-certificate)
        (log-at :info "warning: host certificate ~A not found"
                host-certificate)))
    (let ((global (getf *options* :authorized-keys)))
      (when (and global (not (probe-file global)))
        (log-at :info "warning: ~A not found" global)))
    (setf *server*
          (cl-pnet-ssh:make-ssh-server
           (server-address)
           (server-port)
           :host-key host-keys
           :host-key-agent (host-key-agent)
           :host-certificate (host-certificate-files)
           :authorize #'authorized-keys-p
           :authorize-user #'user-allowed-p
           :hostbased-key-allowed #'hostbased-key-allowed-p
           :sshd-config *server-config*
           :user-groups #'user-groups
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
           :max-startups
           (list (or (config-setting
                      #'cl-pnet-ssh:ssh-server-config-max-startups-begin)
                     10)
                 (or (config-setting
                      #'cl-pnet-ssh:ssh-server-config-max-startups-rate)
                     30)
                 (or (config-setting
                      #'cl-pnet-ssh:ssh-server-config-max-startups-full)
                     100))
           :per-source-max-startups
           (config-setting
            #'cl-pnet-ssh:ssh-server-config-per-source-max-startups)
           :per-source-net-block-size
           (list (or (config-setting
                      #'cl-pnet-ssh:ssh-server-config-per-source-net-block-size-ipv4)
                     32)
                 (or (config-setting
                      #'cl-pnet-ssh:ssh-server-config-per-source-net-block-size-ipv6)
                     128))
           :unused-connection-timeout
           (or (config-setting
                #'cl-pnet-ssh:ssh-server-config-unused-connection-timeout)
               0)
           :channel-timeouts
           (config-setting
            #'cl-pnet-ssh:ssh-server-config-channel-timeouts)
           :tcp-keep-alive
           (not (eq (config-setting
                     #'cl-pnet-ssh:ssh-server-config-tcp-keep-alive)
                    :no))
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
                         (log-at-session
                          session :info "accepted ~A from ~A"
                          (cl-pnet-ssh:ssh-session-user session)
                          (cl-pnet-ssh:ssh-session-remote-address
                           session))
                         ;; sshd writes this once authentication succeeds,
                         ;; before any channel can run.
                         (write-auth-info-file session))
           :on-direct-tcpip
           (lambda (session host port origin origin-port)
             (declare (ignore origin origin-port))
             (let ((allowed (tcpip-allowed-p session host port)))
               (log-at-session
                session :verbose "direct-tcpip to ~A:~D: ~:[refused~;allowed~]"
                host port allowed)
               allowed))
           :on-direct-streamlocal
           #-win32
           (lambda (session path)
             ;; The library has already applied AllowStreamLocalForwarding,
             ;; the key's permit-port-forwarding option and DisableForwarding.
             (log-at-session session :verbose
                             "direct-streamlocal to ~A: allowed" path)
             t)
           #+win32
           (lambda (session path)
             (declare (ignore session path))
             nil)
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
           #-(or win32 ssh-backend-ffi)
           :on-streamlocal-forward
           #-(or win32 ssh-backend-ffi)
           (lambda (session path)
             (start-streamlocal-remote-forward session path))
           #-(or win32 ssh-backend-ffi)
           :on-cancel-streamlocal-forward
           #-(or win32 ssh-backend-ffi)
           (lambda (session path)
             (cancel-streamlocal-remote-forward session path))
           ;; Agent forwarding: the library applies AllowAgentForwarding,
           ;; DisableForwarding and the key's no-agent-forwarding, then asks
           ;; this hook for the Unix socket the session's SSH_AUTH_SOCK names.
           #-ssh-backend-ffi
           :on-agent-forward
           #-ssh-backend-ffi
           #-win32
           (lambda (session) (start-agent-forward session))
           #-ssh-backend-ffi
           #+win32
           (lambda (session)
             (declare (ignore session))
             nil)
           ;; X11 forwarding: the library binds the display listener and asks
           ;; where to record the account's fake cookie.
           #-ssh-backend-ffi
           :x11-authority-file
           #-ssh-backend-ffi
           #-win32
           #'x11-authority-file
           #-ssh-backend-ffi
           #+win32
           (lambda (session)
             (declare (ignore session))
             nil)
           :on-close (lambda (session reason)
                       (log-at-session
                        session :info "closed session for ~A: ~A"
                        (cl-pnet-ssh:ssh-session-user session)
                        (close-reason-text reason))
                       (delete-auth-info-file session)
                       (close-remote-forwards session))
           :on-error (lambda (session condition)
                       (when session
                         (delete-auth-info-file session)
                         (close-remote-forwards session))
                       (if session
                           (log-at-session session :error "~A" condition)
                           (log-at :error "~A" condition)))))
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
