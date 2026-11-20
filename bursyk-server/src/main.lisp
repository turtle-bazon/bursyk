(in-package #:bursyk-server)

;;;; A small SSH command server over cl-pnet-ssh.  It binds a listener,
;;;; authenticates clients with their own keys, and runs each exec request as
;;;; a child process.  Nothing blocks the event loop: both directions of every
;;;; child pipe are watched descriptors.

(defvar *options*
  '(:address "0.0.0.0" :port "2222" :host-key nil :authorized-keys nil
    :accept-env nil :allow nil :subsystem nil
    :no-tcp-forwarding nil :permit-open nil
    :no-remote-forwarding nil :gateway-ports nil)
  "The command line as parsed.")

(defvar *server* nil)
(defvar *signal* nil)
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

(defparameter +bursyk-server-version+ "0.0.2.3"
  "The program's own version, also sent in the SSH identification string.

Keep this in step with the :VERSION in BURSYK-SERVER.ASD; the library gets
the value through MAKE-SSH-SERVER, so peers see the server's real name and
version rather than a generic library string.")

;;; ---- Command line ----

(defun usage ()
  (format *error-output*
          "usage: bursyk-server [-a ADDRESS] [-p PORT] -H HOST_KEY~%~
           ~15@T[-A AUTHORIZED_KEYS] [-e NAME]... [-c PREFIX]...~%~
           ~15@T[-S NAME=PATH]... [--no-tcp-forwarding]~%~
           ~15@T[--allow-tcpip HOST:PORT]... [--no-remote-forwarding]~%~
           ~15@T[--gateway-ports] [-V]~%")
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
        ((string= name "--no-tcp-forwarding") :no-tcp-forwarding)
        ((string= name "--no-remote-forwarding") :no-remote-forwarding)
        ((string= name "--gateway-ports") :gateway-ports)
        ((member name '("--allow-tcpip" "--permit-open") :test #'string=)
         :permit-open)
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
    ((:accept-env :allow :subsystem)
     (push value (getf *options* key)))
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
                             :gateway-ports))
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

(defun port-option ()
  "The port number the command line asked for."
  (handler-case (parse-integer (getf *options* :port))
    (parse-error ()
      (fail "not a port number: ~A" (getf *options* :port)))))

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

(defun tcpip-allowed-p (host port)
  "Whether a direct-tcpip connection to HOST:PORT may be opened.

As sshd does by default, every destination is allowed.  Each --allow-tcpip
narrows that set, and --no-tcp-forwarding refuses them all."
  (and (not (getf *options* :no-tcp-forwarding))
       (let ((rules (reverse (getf *options* :permit-open))))
         (or (null rules)
             (some (lambda (rule)
                     (multiple-value-bind (rule-host rule-port)
                         (split-host-port rule)
                       (and rule-host
                            rule-port
                            (host-pattern-match-p rule-host host)
                            (or (string= rule-port "*")
                                (string= rule-port
                                         (princ-to-string port))))))
                   rules)))))

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
unless --gateway-ports was given: binding a LAN-wide port is a policy change
a client should not make by itself."
  (cond
    ((or (null requested) (zerop (length requested)))
     "127.0.0.1")
    ((string= requested "*")
     (if (getf *options* :gateway-ports) "0.0.0.0" "127.0.0.1"))
    ((loopback-bind-address-p requested) "127.0.0.1")
    ((getf *options* :gateway-ports) requested)
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
  (when (getf *options* :no-remote-forwarding)
    (format *error-output*
            "bursyk-server: remote forwarding refused by --no-remote-forwarding~%")
    (return-from start-remote-forward nil))
  (let ((address (remote-bind-address bind-address)))
    (unless address
      (format *error-output*
              "bursyk-server: refusing a remote forward bound to ~A; use --gateway-ports~%"
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
        (format *error-output*
                "bursyk-server: remote forward could not listen on ~A:~D~%"
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

(defun subsystem-path (name)
  "The program for subsystem NAME, or NIL when nothing serves it."
  (let ((configured
          (assoc name
                 (mapcar #'split-subsystem
                         (reverse (getf *options* :subsystem)))
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

(defun start-server ()
  (let* ((host-key (or (getf *options* :host-key)
                       (home-file ".ssh/id_ed25519")))
         (authorized (or (getf *options* :authorized-keys)
                         (home-file ".ssh/authorized_keys"))))
    (unless (probe-file host-key)
      (fail "host key not found: ~A" host-key))
    (unless (probe-file authorized)
      (format *error-output* "bursyk-server: warning: ~A not found~%"
              authorized))
    (setf *server*
          (cl-pnet-ssh:make-ssh-server
           (getf *options* :address)
           (port-option)
           :host-key host-key
           :authorized-keys authorized
           :server-version (format nil "bursyk-server_~A"
                                   +bursyk-server-version+)
           :accept-env (reverse (getf *options* :accept-env))
           :on-channel #'install-channel-handlers
           :on-direct-tcpip
           (lambda (session host port origin origin-port)
             (declare (ignore session origin origin-port))
             (tcpip-allowed-p host port))
           :on-tcpip-forward
           (lambda (session bind-address bind-port)
             (start-remote-forward session bind-address bind-port))
           :on-cancel-tcpip-forward
           (lambda (session bind-address bind-port)
             (cancel-remote-forward session bind-address bind-port))
           :on-close (lambda (session reason)
                       (declare (ignore reason))
                       (close-remote-forwards session))
           :on-error (lambda (session condition)
                       (when session
                         (close-remote-forwards session))
                       (format *error-output* "bursyk-server: ~A~%" condition)
                       (finish-output *error-output*))))
    (format t "bursyk-server: listening on ~A:~D~%"
            (cl-pnet-ssh:ssh-server-address *server*)
            (cl-pnet-ssh:ssh-server-port *server*))
    (finish-output)
    *server*))

(defun close-server ()
  (when *server*
    (close-remote-forwards)
    (cl-pnet-ssh:ssh-server-close *server*)
    (setf *server* nil)))

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
        ;; Ctrl-C is a convenience, not a requirement: a backend that cannot
        ;; watch signals on this platform must not stop the server listening.
        (setf *signal*
              (handler-case (cl-pnet:signal-start 2 (lambda () (shutdown)))
                (error (condition)
                  (format *error-output*
                          "bursyk-server: no interrupt handler: ~A~%"
                          condition)
                  nil)))
        (cl-pnet:event-loop-run)
        (when *signal*
          (cl-pnet:signal-stop *signal*)
          (setf *signal* nil))
        (close-server))
    (error (condition)
      (format *error-output* "bursyk-server: ~A~%" condition)
      (finish-output *error-output*)
      (uiop:quit 1))))
