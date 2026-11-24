(in-package #:cl-pnet-ssh)

;;;; A single optional reporter for protocol milestones.  It belongs to no
;;;; role: a client command line binds it for -v, and a server can bind it
;;;; when its config asks for VERBOSE or DEBUG.  Nothing in the protocol
;;;; depends on it, and a reporter that signals is ignored so logging can
;;;; never take a connection down.

(defvar *ssh-log-function* nil
  "A function of one string, called at connection milestones, or NIL.")

(defvar *ssh-log-enabled* t
  "Whether SSH-LOG may report; a server binds this per connection so a
Match LogLevel can suppress protocol detail without changing the reporter.")

(defun ssh-log (format-string &rest arguments)
  "Report a protocol milestone through *SSH-LOG-FUNCTION*, if one is bound."
  (when (and *ssh-log-enabled* *ssh-log-function*)
    (ignore-errors
      (funcall *ssh-log-function* (apply #'format nil format-string arguments)))))

(defvar *ssh-warning-function* nil
  "A function of one string for warnings shown at ssh's default log level.

SSH-LOG's reporter is only bound when a command line asks for -v or a log
file, but OpenSSH prints warnings such as WarnWeakCrypto's notice without
being asked.  A command line binds this reporter for those, and SSH-WARN
falls back to SSH-LOG when a library user only bound the logger.")

(defun ssh-warn (format-string &rest arguments)
  "Report a warning through *SSH-WARNING-FUNCTION*, else through SSH-LOG."
  (let ((message (apply #'format nil format-string arguments)))
    (cond
      (*ssh-warning-function*
       (ignore-errors (funcall *ssh-warning-function* message)))
      (t (ssh-log "~A" message)))))
