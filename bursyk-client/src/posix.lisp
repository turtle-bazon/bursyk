(in-package #:burs)

;;;; POSIX terminal and stdin support.
;;;;
;;;; STTY is the terminal interface: it saves and restores the settings and
;;;; reports the size.  CL-PNET:FD-WATCH reports when stdin is readable, so the
;;;; event loop moves input without ever blocking on a read.

(declaim (ftype (function (t) *) finish)
         (ftype (function (t) *) send-window-change))

(defun stdin-terminal-p ()
  #+sbcl (plusp (sb-unix:unix-isatty 0))
  #-sbcl nil)

(cffi:defcfun ("open" c-open) :int (path :string) (flags :int) (mode :int))
(cffi:defcfun ("dup2" c-dup2) :int (old :int) (new :int))
(cffi:defcfun ("close" c-close) :int (fd :int))

;;; A child is waited for with SB-EXT:PROCESS-WAIT, which serves events, and
;;; SBCL aborts the whole process when a deferrable signal is blocked at that
;;; point.  The puma backend keeps signals blocked so its signalfd sees them,
;;; so a STTY, LocalCommand or control-master child would kill the client.
;;; Unblock SBCL's deferrable set for the child and put the exact mask back
;;; afterwards; a signal delivered during the wait is handled as usual.
#+sbcl
(cffi:defcfun ("pthread_sigmask" c-pthread-sigmask) :int
  (how :int) (set :pointer) (oldset :pointer))

#+sbcl
(defun call-with-deferrable-signals-unblocked (function)
  "Call FUNCTION with SBCL's deferrable signals unblocked, then restore."
  ;; SIG_BLOCK with a null set only reads the thread's mask; SIG_SETMASK
  ;; restores it exactly, so signals the caller had blocked stay blocked.
  (cffi:with-foreign-object (saved :uint8 128)
    (c-pthread-sigmask 0 (cffi:null-pointer) saved)
    (unwind-protect
         (progn
           (sb-unix::unblock-deferrable-signals)
           (funcall function))
      (c-pthread-sigmask 2 saved (cffi:null-pointer)))))

#-sbcl
(defun call-with-deferrable-signals-unblocked (function)
  (funcall function))

(defun background-ready ()
  "Tell the waiting parent that authentication succeeded, then detach stdio."
  (write-line "BURS-AUTH-OK" *standard-output*)
  (finish-output *standard-output*)
  (let ((null (c-open "/dev/null" 2 0)))
    (when (>= null 0)
      (c-dup2 null 0)
      (c-dup2 null 1)
      (c-dup2 null 2)
      (when (> null 2)
        (c-close null))))
  (setf *background-child* nil))

(defun restore-terminal ()
  "Put the terminal back the way TERMINAL-ENTER-RAW found it."
  (when *terminal-saved*
    (let ((saved *terminal-saved*))
      (setf *terminal-saved* nil)
      (ignore-errors
       (call-with-deferrable-signals-unblocked
        (lambda ()
          (uiop:run-program (list "stty" saved)
                            :input :interactive
                            :output nil
                            :error-output nil)))))))

(defun run-stty (&rest arguments)
  "Run stty with ARGUMENTS on our terminal; its output, or NIL.

STTY -G and STTY SIZE talk to stdin, so the child inherits fd 0.  A caller
must already know that stdin is a terminal."
  (handler-case
      (string-trim '(#\Newline #\Return)
                   (call-with-deferrable-signals-unblocked
                    (lambda ()
                      (uiop:run-program (cons "stty" arguments)
                                        :input :interactive
                                        :output :string
                                        :error-output nil))))
    (error () nil)))

(defun terminal-size ()
  "The terminal's (VALUES ROWS COLUMNS), or (VALUES NIL NIL)."
  (let ((text (run-stty "size")))
    (when text
      (let ((space (position #\Space text)))
        (when space
          (let ((rows (parse-integer text :end space :junk-allowed t))
                (columns (parse-integer text :start (1+ space)
                                       :junk-allowed t)))
            (when (and rows columns)
              (values rows columns))))))))

(defun read-prompt-line (prompt &key (echo t))
  "Write PROMPT to stderr and read one line from stdin.

When ECHO is false and stdin is a terminal, the typed characters are not
echoed.  NIL is returned at end of input, so a non-interactive caller can
treat a closed stdin as a cancelled prompt rather than an empty answer."
  (format *error-output* "~A" prompt)
  (finish-output *error-output*)
  (let ((saved (and (not echo) (stdin-terminal-p) (run-stty "-g"))))
    (unwind-protect
         (progn
           (when saved (run-stty "-echo"))
           (read-line *standard-input* nil nil))
      (when saved
        (run-stty saved))
      (when (not echo)
        (format *error-output* "~%")
        (finish-output *error-output*)))))

(defun read-keyboard-interactive-answers (name instruction prompts)
  "Ask each of PROMPTS, a list of (TEXT ECHO-P), and return the answers.

NAME and INSTRUCTION are shown first when the server supplied them, as ssh
does.  NIL means the input ended before every prompt was answered."
  (when (and name (plusp (length name)))
    (format *error-output* "~A~%" name))
  (when (and instruction (plusp (length instruction)))
    (format *error-output* "~A~%" instruction))
  (finish-output *error-output*)
  (let ((answers '()))
    (dolist (prompt prompts (nreverse answers))
      (let ((answer (read-prompt-line (first prompt)
                                      :echo (second prompt))))
        (unless answer
          (return nil))
        (push answer answers)))))

(defun terminal-enter-raw ()
  "Save the terminal settings and stop local line editing and signals.

With a PTY, the remote side echoes and edits.  Leaving the local terminal in
raw mode is also what makes Ctrl-C a byte for the remote shell, as in ssh."
  (when (and (stdin-terminal-p)
             (not (getf *options* :stdin-null)))
    (setf *terminal-saved* (run-stty "-g"))
    (when *terminal-saved*
      (run-stty "raw" "-echo"))))

(defun stop-winch ()
  (when *winch*
    (ignore-errors (cl-pnet:signal-stop *winch*))
    (setf *winch* nil)))

(defun start-winch (channel)
  "Forward terminal resizes to CHANNEL while the session is open."
  (when (stdin-terminal-p)
    (setf *winch*
          (ignore-errors
           (cl-pnet:signal-start
            #+sbcl sb-unix:sigwinch
            #-sbcl 28
            (lambda ()
              (handler-case (send-window-change channel)
                (error () nil))))))))

(defun write-octets (stream octets)
  "Write channel output to STREAM, leaving as SIGPIPE would if it is closed.

A shell pipeline such as \"burs host cat | head\" closes our stdout once it
has enough.  SBCL ignores SIGPIPE, so the write raises instead; treating that
as failure and exiting 128+13 keeps the usual pipeline behavior."
  (handler-case
      (progn
        (write-string (cl-pnet-ssh:ssh-octets-string octets) stream)
        (finish-output stream))
    (error () (finish 141))))

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
      ((plusp count)
       (feed-keystrokes
        channel (if *escape-char* (escape-filter octets) octets)))
      ((zerop count)
       (stop-stdin)
       (finish-keystrokes channel)
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
