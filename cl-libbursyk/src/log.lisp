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
