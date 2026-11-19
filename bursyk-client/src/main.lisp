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
(defvar *stdin-watcher* nil)

(defvar *options*
  '(:port nil :user nil :identity nil :config nil :known-hosts nil
    :policy nil :agent nil :options nil)
  "The command line as parsed, before ~/.ssh/config is applied.")

(defun usage ()
  (format *error-output*
          "usage: burs [-p PORT] [-l USER] [-i KEY] [-o OPTION]... [-F CONFIG]~%~
           ~10@Tuser@host [command [args...]]~%")
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
  (let ((name (string-downcase name)))
    (cond ((member name '("-p" "--port") :test #'string=) :port)
          ((member name '("-l" "--user") :test #'string=) :user)
          ((member name '("-i" "--identity") :test #'string=) :identity)
          ((member name '("-f" "--config") :test #'string=) :config)
          ((member name '("-o" "--option") :test #'string=) :options)
          ((member name '("-a" "--agent") :test #'string=) :agent)
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

(defun config-options (host)
  "The ssh_config options that apply to HOST, or NIL."
  (let ((path (or (getf *options* :config)
                  (merge-pathnames ".ssh/config" (user-homedir-pathname))))
        (result nil))
    (let ((config (cl-pnet-ssh:ssh-config-load path)))
      (when config
        (cl-pnet-ssh:ssh-config-resolve
         config host
         :on-options (lambda (options) (setf result options))
         :on-error (lambda (condition)
                     (format *error-output* "burs: config: ~A~%" condition)))))
    result))

(defun config-policy (config)
  "The host-key policy CONFIG asks for, as the client understands it."
  (let ((value (and config
                    (cl-pnet-ssh:ssh-config-options-strict-host-key-checking
                     config))))
    (cond ((null value) :strict)
          ((member value '("no" "off") :test #'string=) :insecure)
          ((string= value "accept-new") :accept-new)
          (t :strict))))

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
    ;; Everything else is accepted and ignored, as SSH itself tolerates
    ;; keywords a newer client wrote.
    (t nil)))

(defun apply-command-line-options ()
  (dolist (option (nreverse (getf *options* :options)))
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
  (stop-stdin)
  (finish-output *standard-output*)
  (finish-output *error-output*)
  (uiop:quit (or status 255)))

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
  (cl-pnet-ssh:ssh-channel-exec *channel* command)
  (start-stdin *channel*))

;;; ---- Entry point ----

(defun remote-shell ()
  (or (uiop:getenv "SHELL") "/bin/sh"))

(defun join-command (arguments)
  (if arguments
      (format nil "~{~A~^ ~}" arguments)
      (remote-shell)))

(defun start-client (host command)
  (let* ((config (config-options host))
         (user (or (getf *options* :user)
                   (and config (cl-pnet-ssh:ssh-config-options-user config))
                   (cl-pnet-ssh:ssh-default-user)))
         (port (or (and (getf *options* :port)
                        (parse-integer (getf *options* :port)))
                   (and config (cl-pnet-ssh:ssh-config-options-port config))
                   22))
         (hostname (or (and config
                            (cl-pnet-ssh:ssh-config-options-hostname config))
                       host))
         (identity (or (getf *options* :identity)
                       (and config
                            (cl-pnet-ssh:ssh-config-options-identity-files
                             config))))
         (known-hosts (or (getf *options* :known-hosts)
                          (first (and config
                                      (cl-pnet-ssh:ssh-config-options-known-hosts
                                       config)))))
         (policy (or (getf *options* :policy) (config-policy config))))
    (cl-pnet-ssh:make-ssh-client
     host
     :connect-host hostname
     :port port
     :user user
     :private-key identity
     :agent (getf *options* :agent)
     :known-hosts known-hosts
     :host-key-policy policy
     :on-open (lambda (client) (start-session client command))
     :on-error (lambda (client condition)
                 (declare (ignore client))
                 (format *error-output* "burs: ~A~%" condition)
                 (finish 255))
     :on-close (lambda (client reason)
                 (declare (ignore client reason))
                 (finish *status*)))))

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
    (error (condition)
      (when (uiop:getenv "BURS_DEBUG")
        (sb-debug:print-backtrace :count 40 :stream *error-output*))
      (format *error-output* "burs: ~A~%" condition)
      (uiop:quit 1))))
