;;;; Live SSH client test: needs a reachable sshd and a usable key.
;;;;
;;;; The target is optional, so everything is configured through environment
;;;; variables rather than hard-coded paths:
;;;;
;;;;   SSH_TEST_HOST         default 127.0.0.1
;;;;   SSH_TEST_PORT         default 22
;;;;   SSH_TEST_USER         default $USER
;;;;   SSH_TEST_KEY          path to an ssh-ed25519 key
;;;;   SSH_TEST_PASSPHRASE   passphrase for an encrypted SSH_TEST_KEY
;;;;   SSH_TEST_AGENT        agent socket to use instead of SSH_TEST_KEY
;;;;   SSH_TEST_KNOWN_HOSTS  default a fresh file under /tmp
;;;;   SSH_TEST_COMMAND      default "printf hello; printf oops >&2; exit 7"
;;;;   SSH_TEST_STATUS       expected exit status, default 7
;;;;   SSH_TEST_STDOUT       expected stdout, default "hello"
;;;;   SSH_TEST_STDERR       expected stderr, default "oops"

(load (merge-pathnames "../../cl-pnet/tests/pnet-backend.lisp"
                       (make-pathname :name nil :type nil :defaults *load-truename*)))
(require :asdf)
(asdf:load-system :cl-pnet-ssh)

(defvar *stdout* (make-string-output-stream))
(defvar *stderr* (make-string-output-stream))
(defvar *status* :no-exit-status)

(defun env (name default)
  (or (uiop:getenv name) default))

(defun live-error (control &rest arguments)
  (format t "~&SSH LIVE TEST FAILED: ~?~%" control arguments)
  (sb-ext:exit :abort t :code 1))

(defun note-data (channel data kind)
  (declare (ignore channel))
  (write-string (cl-pnet-ssh::ssh-octets-string data)
                (ecase kind (:stdout *stdout*) (:stderr *stderr*))))

(defun finish ()
  (let ((stdout (get-output-stream-string *stdout*))
        (stderr (get-output-stream-string *stderr*)))
    (unless (equal stdout (env "SSH_TEST_STDOUT" "hello"))
      (live-error "stdout was ~S" stdout))
    (unless (equal stderr (env "SSH_TEST_STDERR" "oops"))
      (live-error "stderr was ~S" stderr))
    (unless (equal (princ-to-string *status*) (env "SSH_TEST_STATUS" "7"))
      (live-error "exit status was ~S" *status*))
    (format t "~&SSH LIVE TEST PASSED~%")
    (sb-ext:exit :code 0)))

(defun start (client command)
  (let ((channel (cl-pnet-ssh:ssh-open-session
                  client
                  :on-data #'note-data
                  :on-exit (lambda (channel status)
                             (declare (ignore channel))
                             (setf *status* status)
                             (finish))
                  :on-error (lambda (channel condition)
                              (declare (ignore channel))
                              (live-error "channel error: ~A" condition)))))
    (cl-pnet-ssh:ssh-channel-exec channel command)))

(defun main ()
  (let* ((key (env "SSH_TEST_KEY" nil))
         (agent (let ((value (env "SSH_TEST_AGENT" nil)))
                  (if (and value (string-equal value "t")) t value)))
         (known-hosts (env "SSH_TEST_KNOWN_HOSTS"
                           (format nil "/tmp/cl-pnet-ssh-live-~D.known_hosts"
                                   (get-universal-time)))))
    (unless (or key agent)
      (live-error "SSH_TEST_KEY or SSH_TEST_AGENT is not set"))
    (cl-pnet-ssh:make-ssh-client
     (env "SSH_TEST_HOST" "127.0.0.1")
     :port (parse-integer (env "SSH_TEST_PORT" "22"))
     :user (env "SSH_TEST_USER" (uiop:getenv "USER"))
     :private-key key
     :agent agent
     :passphrase (env "SSH_TEST_PASSPHRASE" nil)
     :known-hosts known-hosts
     :host-key-policy :accept-new
     :on-open (lambda (client)
                (start client (env "SSH_TEST_COMMAND"
                                   "printf hello; printf oops >&2; exit 7")))
     :on-error (lambda (client condition)
                 (declare (ignore client))
                 (live-error "client error: ~A" condition))
     :on-close (lambda (client reason)
                 (declare (ignore client reason))
                 (when (eq *status* :no-exit-status)
                   (live-error "connection closed without an exit status"))))
    (cl-pnet:event-loop-run)
    (if (eq *status* :no-exit-status)
        (live-error "event loop ended without an exit status")
        (finish))))

(main)
