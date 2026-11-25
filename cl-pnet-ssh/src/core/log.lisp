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

(defun ssh-log-escape (text)
  "TEXT as OpenSSH's log.c writes a message to stderr.

logit() passes every message through strnvis(3) with VIS_SAFE|VIS_OCTAL, so
a backslash is doubled and a control or high byte becomes a three-digit octal
escape, while space, tab, newline, carriage return, backspace and bell pass
through unchanged.  The encoding works on bytes; a character above #xFF is
written as its UTF-8 bytes, so the result is always ASCII."
  (let ((out (make-string-output-stream)))
    (flet ((put-byte (value)
             ;; strnvis's VIS_SAFE with VIS_OCTAL: a backslash gets a
             ;; second backslash, safe characters are copied, and the rest
             ;; is a three-digit octal escape of the byte.
             (cond
               ((= value 92) (write-string "\\\\" out))
               ((member value '(32 9 10 13 8 7))
                (write-char (code-char value) out))
               ((and (> value 32) (< value 127))
                (write-char (code-char value) out))
               (t (format out "\\~3,'0o" value)))))
      (loop for character across text
            for code = (char-code character)
            do (cond
                 ((< code #x80) (put-byte code))
                 ((< code #x800)
                  (put-byte (logior #xc0 (ash code -6)))
                  (put-byte (logior #x80 (logand code #x3f))))
                 ((< code #x10000)
                  (put-byte (logior #xe0 (ash code -12)))
                  (put-byte (logior #x80 (logand (ash code -6) #x3f)))
                  (put-byte (logior #x80 (logand code #x3f))))
                 (t
                  (put-byte (logior #xf0 (ash code -18)))
                  (put-byte (logior #x80 (logand (ash code -12) #x3f)))
                  (put-byte (logior #x80 (logand (ash code -6) #x3f)))
                  (put-byte (logior #x80 (logand code #x3f)))))))
    (get-output-stream-string out)))

(defun ssh-log (format-string &rest arguments)
  "Report a protocol milestone through *SSH-LOG-FUNCTION*, if one is bound.

The message is encoded once, here, because log.c encodes every line it
writes; a reporter only has to put the text on a stream."
  (when (and *ssh-log-enabled* *ssh-log-function*)
    (ignore-errors
      (funcall *ssh-log-function*
               (ssh-log-escape (apply #'format nil format-string arguments))))))

(defvar *ssh-warning-function* nil
  "A function of one string for warnings shown at ssh's default log level.

SSH-LOG's reporter is only bound when a command line asks for -v or a log
file, but OpenSSH prints warnings such as WarnWeakCrypto's notice without
being asked.  A command line binds this reporter for those, and SSH-WARN
falls back to SSH-LOG when a library user only bound the logger.")

(defun ssh-warn (format-string &rest arguments)
  "Report a warning through *SSH-WARNING-FUNCTION*, else through SSH-LOG."
  (let ((message (ssh-log-escape (apply #'format nil format-string arguments))))
    (cond
      (*ssh-warning-function*
       (ignore-errors (funcall *ssh-warning-function* message)))
      ((and *ssh-log-enabled* *ssh-log-function*)
       ;; MESSAGE is already encoded, so it goes straight to the reporter
       ;; rather than back through SSH-LOG.
       (ignore-errors (funcall *ssh-log-function* message))))))

(defvar *ssh-forced-warning-function* nil
  "A function of one string for notices ssh prints before it logs anything.

ssh applies every -o option while it is still reading its own arguments and
calls log_init only afterwards.  A readconf message about a command-line
option therefore reaches stderr before -q, -E or -v can have any effect on
it.  Command-line config notices use this reporter; file notices do not.")

(defun ssh-warn-always (format-string &rest arguments)
  "Report a warning through *SSH-FORCED-WARNING-FUNCTION*, else SSH-WARN."
  (let ((message (ssh-log-escape (apply #'format nil format-string arguments))))
    (cond
      (*ssh-forced-warning-function*
       (ignore-errors (funcall *ssh-forced-warning-function* message)))
      (*ssh-warning-function*
       (ignore-errors (funcall *ssh-warning-function* message)))
      ((and *ssh-log-enabled* *ssh-log-function*)
       (ignore-errors (funcall *ssh-log-function* message))))))
