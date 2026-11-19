(in-package #:bursyk-server)

;;;; A small SSH command server over cl-pnet-ssh.  It binds a listener,
;;;; authenticates clients with their own keys, and runs each exec request as
;;;; a child process.  Nothing blocks the event loop: both directions of every
;;;; child pipe are watched descriptors.

(defvar *options*
  '(:address "0.0.0.0" :port "2222" :host-key nil :authorized-keys nil
    :accept-env nil :allow nil)
  "The command line as parsed.")

(defvar *server* nil)
(defvar *signal* nil)

;;; ---- Command line ----

(defun usage ()
  (format *error-output*
          "usage: bursyk-server [-a ADDRESS] [-p PORT] -H HOST_KEY~%~
           ~15@T[-A AUTHORIZED_KEYS] [-e NAME]... [-c PREFIX]...~%")
  (finish-output *error-output*))

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
        (t nil)))

(defun record-option (key value)
  (case key
    ((:accept-env :allow) (push value (getf *options* key)))
    (t (setf (getf *options* key) value))))

(defun parse-arguments (arguments)
  (loop
    (let ((argument (first arguments)))
      (cond
        ((null arguments) (return))
        ((option-key argument)
         (let ((value (second arguments)))
           (unless value (fail "~A needs a value" argument))
           (record-option (option-key argument) value)
           (setf arguments (cddr arguments))))
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

;;; ---- Child process bridge ----

(defstruct bridge
  channel
  pid
  (stdin-fd nil)
  (stdout-fd nil)
  (stderr-fd nil)
  (status-fd nil)
  stdin-watcher
  stdout-watcher
  stderr-watcher
  status-watcher
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
    (setf (bridge-status-watcher bridge) nil)))

(defun bridge-close-fds (bridge)
  "Release the four pipe descriptors, once each."
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
    (setf (bridge-status-fd bridge) nil)))

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
      (kill-child (bridge-pid bridge)))
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
  "Move whatever the child wrote on FD to the channel."
  (unless (channel-usable-p (bridge-channel bridge))
    (return-from bridge-output (bridge-abort bridge)))
  (multiple-value-bind (octets count error)
      (cl-pnet-sockets:read-octets fd (* 64 1024))
    (declare (ignore error))
    (cond
      ((plusp count)
       (let ((channel (bridge-channel bridge)))
         (if stderr-p
             (cl-pnet-ssh:ssh-server-channel-write-stderr channel octets)
             (cl-pnet-ssh:ssh-server-channel-write channel octets))))
      ((zerop count)
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
       (bridge-maybe-finish bridge))
      (t nil))))

(defun bridge-arm-input (bridge)
  (unless (bridge-stdin-watcher bridge)
    (setf (bridge-stdin-watcher bridge)
          (cl-pnet:fd-watch
           (bridge-stdin-fd bridge)
           :on-writable
           (lambda (watcher)
             (declare (ignore watcher))
             (bridge-flush-input bridge))))))

(defun bridge-disarm-input (bridge)
  (when (bridge-stdin-watcher bridge)
    (cl-pnet:fd-unwatch (bridge-stdin-watcher bridge))
    (setf (bridge-stdin-watcher bridge) nil)))

(defun bridge-close-input (bridge)
  (when (bridge-input-open bridge)
    (setf (bridge-input-open bridge) nil)
    (bridge-disarm-input bridge)
    (when (bridge-stdin-fd bridge)
      (c-close (bridge-stdin-fd bridge))
      (setf (bridge-stdin-fd bridge) nil))))

(defun bridge-flush-input (bridge)
  "Write as much pending stdin as the child accepts without blocking."
  (unless (bridge-input-open bridge)
    (return-from bridge-flush-input nil))
  (let ((pending (bridge-pending bridge)))
    (loop while (plusp (fill-pointer pending))
          do (multiple-value-bind (count error)
                 (cl-pnet-sockets:write-octets
                  (bridge-stdin-fd bridge) pending)
               (declare (ignore error))
               (if (plusp count)
                   (bridge-drop-pending bridge count)
                   (return))))
    (if (plusp (fill-pointer pending))
        (bridge-arm-input bridge)
        (progn
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
  "Watch the child's three reporting pipes."
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
           (bridge-output bridge (bridge-stderr-fd bridge) t))))
  (setf (bridge-status-watcher bridge)
        (cl-pnet:fd-watch
         (bridge-status-fd bridge)
         :on-readable
         (lambda (watcher)
           (declare (ignore watcher))
           (bridge-read-status bridge)))))

(defun start-command (channel command)
  "Run COMMAND as a child and pipe it to CHANNEL."
  (multiple-value-bind (pid stdin stdout stderr status) (spawn-shell command)
    (let ((bridge (make-bridge :channel channel :pid pid
                               :stdin-fd stdin :stdout-fd stdout
                               :stderr-fd stderr :status-fd status)))
      (bridge-attach bridge)
      (bridge-watch bridge)
      bridge)))

;;; ---- Server ----

(defun exec-request (channel command)
  (if (command-allowed-p command)
      (handler-case (start-command channel command)
        (error (condition)
          (cl-pnet-ssh:ssh-server-channel-write-stderr
           channel (format nil "~A~%" condition))
          (cl-pnet-ssh:ssh-server-channel-exit channel 126)
          (cl-pnet-ssh:ssh-server-channel-close channel)))
      (progn
        (cl-pnet-ssh:ssh-server-channel-write-stderr
         channel (format nil "command not allowed: ~A~%" command))
        (cl-pnet-ssh:ssh-server-channel-exit channel 126)
        (cl-pnet-ssh:ssh-server-channel-close channel))))

(defun install-channel-handlers (channel)
  (setf (cl-pnet-ssh:ssh-server-channel-on-exec channel) #'exec-request))

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
           :accept-env (reverse (getf *options* :accept-env))
           :on-channel #'install-channel-handlers
           :on-error (lambda (session condition)
                       (declare (ignore session))
                       (format *error-output* "bursyk-server: ~A~%" condition)
                       (finish-output *error-output*))))
    (format t "bursyk-server: listening on ~A:~D~%"
            (cl-pnet-ssh:ssh-server-address *server*)
            (cl-pnet-ssh:ssh-server-port *server*))
    (finish-output)
    *server*))

(defun close-server ()
  (when *server*
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
        (parse-arguments arguments)
        (start-server)
        (setf *signal* (cl-pnet:signal-start 2 (lambda () (shutdown))))
        (cl-pnet:event-loop-run)
        (when *signal*
          (cl-pnet:signal-stop *signal*)
          (setf *signal* nil))
        (close-server))
    (error (condition)
      (format *error-output* "bursyk-server: ~A~%" condition)
      (finish-output *error-output*)
      (uiop:quit 1))))
