(defpackage #:burs
  (:use #:cl)
  (:export #:main))

(in-package #:burs)

;;;; A small SSH client command line over cl-pnet-ssh.  It runs one command
;;;; on the remote host and streams its output and stdin, without blocking the
;;;; event loop: stdin is watched with CL-PNET:FD-WATCH, never read in a loop.

(defvar *status* nil
  "The exit status the remote command reported, or NIL before it does.")
(defvar *channel* nil)
(defvar *client* nil
  "The connected client, kept so FINISH can shut it down before quitting.")
(defvar *stdin-watcher* nil)
(defvar *finishing* nil
  "True once FINISH is tearing down, so nested close callbacks do not quit early.")

(defvar *options*
  '(:port nil :user nil :identity nil :config nil :known-hosts nil
    :policy nil :agent nil :options nil :jump nil :proxy-command nil)
  "The command line as parsed, before ~/.ssh/config is applied.")

(defun usage ()
  (format *error-output*
          "usage: burs [-p PORT] [-l USER] [-i KEY] [-J JUMP] [-o OPTION]...~%~
           ~7@T[-F CONFIG] user@host [command [args...]]~%")
  (finish-output *error-output*))

(defun fail (format-string &rest arguments)
  (format *error-output* "burs: ~?~%" format-string arguments)
  (finish-output *error-output*)
  (uiop:quit 2))

;;; ---- Command line ----

(defun split-destination (destination)
  "DESTINATION as (VALUES HOST USER), splitting USER@HOST at the first @."
  (let ((at (position #\@ destination)))
    (if at
        (values (subseq destination (1+ at)) (subseq destination 0 at))
        (values destination nil))))

(defun option-key (name)
  "The option NAME selects, or NIL.

Short options are case-sensitive, as in SSH itself: -p is the port, -F the
config file, and a -P or -f this client does not have is an error."
  (let ((long (and (> (length name) 2)
                   (string= "--" name :end1 2 :end2 2)
                   (string-downcase name))))
    (cond ((string= name "-p") :port)
          ((string= name "-l") :user)
          ((string= name "-i") :identity)
          ((string= name "-J") :jump)
          ((string= name "-F") :config)
          ((string= name "-o") :options)
          ((string= name "-a") :agent)
          ((equal long "--port") :port)
          ((equal long "--user") :user)
          ((equal long "--identity") :identity)
          ((equal long "--jump") :jump)
          ((equal long "--config") :config)
          ((equal long "--option") :options)
          ((equal long "--agent") :agent)
          (t nil))))

(defun record-option (key value)
  (case key
    (:identity (push value (getf *options* :identity)))
    (:options (push value (getf *options* :options)))
    (t (setf (getf *options* key) value))))

(defun parse-arguments (arguments)
  "Fill *OPTIONS* from ARGUMENTS; return (VALUES DESTINATION COMMAND)."
  (let ((destination nil)
        (command nil))
    (loop
      (let ((argument (first arguments)))
        (cond
          ((null arguments)
           (return))
          ((string= argument "--")
           (setf arguments (rest arguments)
                 destination (first arguments)
                 command (rest arguments))
           (return))
          ((option-key argument)
           (let ((value (second arguments)))
             (unless value (fail "~A needs a value" argument))
             (record-option (option-key argument) value)
             (setf arguments (cddr arguments))))
          ((and (> (length argument) 1) (char= (char argument 0) #\-))
           (fail "unknown option ~A" argument))
          (t
           (setf destination argument
                 command (rest arguments))
           (return)))))
    (values destination command)))

;;; ---- ~/.ssh/config and -o ----

(defun match-exec (command on-result on-error)
  "Answer a Match exec condition.

The config is resolved before the event loop starts, so running the shell
test here costs the process nothing that was concurrent anyway.  The library
itself never blocks: this matcher is what a caller supplies."
  (handler-case
      (funcall on-result
               (eql 0
                    (nth-value 2
                               (uiop:run-program (list "/bin/sh" "-c" command)
                                                 :ignore-error-status t
                                                 :output nil
                                                 :error-output nil))))
    (error (condition) (funcall on-error condition))))

(defun command-line-option (name value)
  "Apply one -o NAME=VALUE to the parsed options."
  (cond
    ((string-equal name "Port") (setf (getf *options* :port) value))
    ((string-equal name "User") (setf (getf *options* :user) value))
    ((string-equal name "IdentityFile")
     (push value (getf *options* :identity)))
    ((string-equal name "UserKnownHostsFile")
     (setf (getf *options* :known-hosts) value))
    ((string-equal name "IdentityAgent") (setf (getf *options* :agent) value))
    ((string-equal name "StrictHostKeyChecking")
     (setf (getf *options* :policy)
           (cond ((member (string-downcase value) '("no" "off") :test #'string=)
                  :insecure)
                 ((string-equal value "accept-new") :accept-new)
                 (t :strict))))
    ((string-equal name "ProxyJump") (setf (getf *options* :jump) value))
    ((string-equal name "ProxyCommand")
     (setf (getf *options* :proxy-command) value))
    ;; Everything else is accepted and ignored, as SSH itself tolerates
    ;; keywords a newer client wrote.
    (t nil)))

(defun command-line-option-list ()
  "The -o options in the order they were written."
  (reverse (getf *options* :options)))

(defun apply-command-line-options ()
  (dolist (option (command-line-option-list))
    (let ((equals (position #\= option)))
      (when equals
        (command-line-option (subseq option 0 equals)
                             (subseq option (1+ equals)))))))

;;; ---- Session ----

(defun write-octets (stream octets)
  (write-string (cl-pnet-ssh:ssh-octets-string octets) stream)
  (finish-output stream))

(defun stop-stdin ()
  (when *stdin-watcher*
    (cl-pnet:fd-unwatch *stdin-watcher*)
    (setf *stdin-watcher* nil)))

(defun stdin-readable (channel)
  "Move whatever stdin has to CHANNEL; end the input at real EOF.

stdin is a pipe or a terminal, so it is read with READ-OCTETS: RECV would
answer ENOTSOCK.  A count of -1 means nothing is ready yet, not EOF."
  (multiple-value-bind (octets count error)
      (cl-pnet-sockets:read-octets 0 65536)
    (declare (ignore error))
    (cond
      ((plusp count) (cl-pnet-ssh:ssh-channel-write channel octets))
      ((zerop count)
       (stop-stdin)
       (cl-pnet-ssh:ssh-channel-eof channel))
      (t nil))))

(defun start-stdin (channel)
  (setf *stdin-watcher*
        (cl-pnet:fd-watch
         0
         :on-readable
         (lambda (watcher)
           (declare (ignore watcher))
           (handler-case (stdin-readable channel)
             (error () (stop-stdin)))))))

(defun finish (status)
  ;; Closing the client below reports its open channels closed, whose
  ;; callbacks call FINISH again; only the outermost call may quit, or the
  ;; connection (and a ProxyCommand helper) would be left half torn down.
  (unless *finishing*
    (setf *finishing* t)
    (stop-stdin)
    ;; Close the client before leaving: a ProxyCommand's helper is a child
    ;; process, and quitting without closing would leave it running.
    (when *client*
      (let ((client *client*))
        (setf *client* nil)
        (ignore-errors (cl-pnet-ssh:ssh-client-close client))))
    (finish-output *standard-output*)
    (finish-output *error-output*)
    (uiop:quit (or status 255))))

(defun session-error (channel condition)
  (declare (ignore channel))
  (format *error-output* "burs: ~A~%" condition)
  (finish 255))

(defun start-session (client command)
  (setf *channel*
        (cl-pnet-ssh:ssh-open-session
         client
         :on-data (lambda (channel data kind)
                    (declare (ignore channel))
                    (write-octets (ecase kind (:stdout *standard-output*)
                                         (:stderr *error-output*))
                                  data))
         :on-exit (lambda (channel status)
                    (declare (ignore channel))
                    (setf *status* status))
         :on-close (lambda (channel status)
                     (declare (ignore channel status))
                     (finish *status*))
         :on-error #'session-error))
  (dolist (name (cl-pnet-ssh:ssh-client-send-env client))
    (let ((value (uiop:getenv name)))
      (when value
        (cl-pnet-ssh:ssh-channel-env *channel* name value))))
  (cl-pnet-ssh:ssh-channel-exec *channel* command)
  (start-stdin *channel*))

;;; ---- Entry point ----

(defun remote-shell ()
  (or (uiop:getenv "SHELL") "/bin/sh"))

(defun join-command (arguments)
  (if arguments
      (format nil "~{~A~^ ~}" arguments)
      (remote-shell)))

;;; ---- The target client ----

(defun client-port ()
  "The -p or -o Port value as a number, when the command line gave one."
  (let ((value (getf *options* :port)))
    (when value
      (multiple-value-bind (port end) (parse-integer value :junk-allowed t)
        (if (and port (= end (length value)))
            port
            (fail "invalid port ~A" value))))))

(defun start-client (host command)
  "Run COMMAND on HOST, letting the library follow ~/.ssh/config for it."
  (cl-pnet-ssh:make-ssh-client-from-config
   host
   :config (getf *options* :config)
   :user (getf *options* :user)
   :port (client-port)
   :private-key (reverse (getf *options* :identity))
   :agent (getf *options* :agent)
   :known-hosts (getf *options* :known-hosts)
   :host-key-policy (getf *options* :policy)
   :proxy-jump (getf *options* :jump)
   :proxy-command (getf *options* :proxy-command)
   ;; Every -o keyword reaches the same resolver the file uses, so facts the
   ;; command line has no dedicated flag for (HostName, ConnectTimeout,
   ;; ServerAliveInterval, ...) work too.
   :options (command-line-option-list)
   :exec-matcher #'match-exec
   :on-client (lambda (client) (setf *client* client))
   :on-config-error (lambda (condition) (fail "~A" condition))
   :on-open (lambda (client) (start-session client command))
   :on-error (lambda (client condition)
               (declare (ignore client))
               (format *error-output* "burs: ~A~%" condition)
               (finish 255))
   :on-close (lambda (client reason)
               (declare (ignore client reason))
               (finish *status*))))

(defun main ()
  "Entry point for the BURS program."
  (handler-case
      (let ((arguments (uiop:command-line-arguments)))
        (when (member (first arguments) '("-h" "--help") :test #'string=)
          (usage)
          (uiop:quit 0))
        (multiple-value-bind (destination command)
            (parse-arguments arguments)
          (unless destination
            (usage)
            (uiop:quit 2))
          (apply-command-line-options)
          (multiple-value-bind (host user) (split-destination destination)
            (when user (setf (getf *options* :user) user))
            (start-client host (join-command command))
            (cl-pnet:event-loop-run)
            (finish *status*))))
    #+sbcl
    (sb-sys:interactive-interrupt ()
      ;; Ctrl-C is not an error: leave the terminal on a fresh line and exit
      ;; with the status a shell reports for SIGINT, instead of dropping into
      ;; SBCL's debugger.
      (format *error-output* "~&")
      (finish-output *error-output*)
      (finish 130))
    (error (condition)
      (when (uiop:getenv "BURS_DEBUG")
        (sb-debug:print-backtrace :count 40 :stream *error-output*))
      (format *error-output* "burs: ~A~%" condition)
      (uiop:quit 1))))
