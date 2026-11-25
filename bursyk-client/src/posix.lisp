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

(defun run-tty-stty (&rest arguments)
  "Run stty with ARGUMENTS on the controlling terminal; its output, or NIL.

Unlike RUN-STTY this does not depend on stdin being the terminal, so it also
works while stdin carries a file to the remote side.  A child whose stdin is
opened separately lands in its own process group, and a terminal setting
change from a background group is stopped with SIGTTOU, so the redirection
belongs to a shell that stays in our group."
  (handler-case
      (string-trim
       '(#\Newline #\Return)
       (call-with-deferrable-signals-unblocked
        (lambda ()
          (uiop:run-program
           (list "sh" "-c"
                 (format nil "stty ~{~A~^ ~} < /dev/tty" arguments))
           :input :interactive :output :string :error-output nil))))
    (error () nil)))

(defun read-tty-line (prompt)
  "Write PROMPT on the controlling terminal and read one line, or NIL.

ssh asks for a key passphrase with read_passphrase, which opens /dev/tty
rather than trusting stdin: a redirected stdin is still a prompt, and no
terminal at all means no prompt.  Echo is off while the answer is typed, and
a carriage return first puts the prompt over any type-ahead, as OpenSSH does."
  (let ((fd (c-open "/dev/tty" 2 0)))
    (when (>= fd 0)
      (let ((stream
              (sb-sys:make-fd-stream fd :input t :output t
                                        :buffering :line :auto-close t)))
        (unwind-protect
             (let ((saved (run-tty-stty "-g")))
               (unwind-protect
                    (progn
                      (write-char #\Return stream)
                      (finish-output stream)
                      (when saved (run-tty-stty "-echo"))
                      (format stream "~A" prompt)
                      (finish-output stream)
                      (read-line stream nil nil))
                 (when saved (run-tty-stty saved))
                 (format stream "~%")
                 (finish-output stream)))
          (close stream))))))

(defun read-prompt-line (prompt &key (echo t))
  "Write PROMPT to stderr and read one line from stdin.

When ECHO is false and stdin is a terminal, the typed characters are not
echoed; the terminal stops echoing before the prompt is written, so an
answer that arrives with the prompt is not shown either.  NIL is returned at
end of input, so a non-interactive caller can treat a closed stdin as a
cancelled prompt rather than an empty answer."
  (let ((saved (and (not echo) (stdin-terminal-p) (run-stty "-g"))))
    (unwind-protect
         (progn
           (when saved (run-stty "-echo"))
           (format *error-output* "~A" prompt)
           (finish-output *error-output*)
           (read-line *standard-input* nil nil))
      (when saved
        (run-stty saved))
      (when (not echo)
        (format *error-output* "~%")
        (finish-output *error-output*)))))

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

;;; ---- raw standard streams ----
;;;
;;; A key comment is arbitrary bytes, but the standard character streams
;;; encode what is written to them.  These helpers reach the process's own
;;; descriptors when the standard streams are still the process's streams,
;;; and report NIL when a caller has rebound them (as tests do) so the
;;; caller can fall back to the character stream.

(defun resolve-stream-synonym (stream)
  "STREAM with any SYNONYM-STREAM wrappers followed."
  (loop while (typep stream 'synonym-stream)
        do (setf stream (symbol-value (synonym-stream-symbol stream)))
        finally (return stream)))

#+sbcl
(defun process-stream-descriptor (stream)
  "STREAM's descriptor when it is one of the process's own standard streams."
  (let ((stream (resolve-stream-synonym stream)))
    (when (and (typep stream 'sb-sys:fd-stream)
               (member stream
                       (mapcar #'resolve-stream-synonym
                               (list sb-sys:*stdin* sb-sys:*stdout*
                                     sb-sys:*stderr*))
                       :test #'eq))
      (sb-sys:fd-stream-fd stream))))
#-sbcl
(defun process-stream-descriptor (stream)
  (declare (ignore stream))
  nil)

(defun standard-output-descriptor ()
  (process-stream-descriptor *standard-output*))

(defun standard-input-descriptor ()
  (process-stream-descriptor *standard-input*))

(cffi:defcfun ("write" c-write) :ssize
  (descriptor :int) (buffer :pointer) (count :size))

(defun write-standard-output-octets (octets)
  "Write OCTETS to the process's stdout unchanged, or return NIL.

NIL means standard output is not the process's own stream, so the caller
must write through *STANDARD-OUTPUT* instead.  Otherwise the descriptor is
written directly, which keeps a key comment's arbitrary bytes intact; the
Lisp stream is flushed first so earlier output stays in order."
  (let ((descriptor (standard-output-descriptor)))
    (when descriptor
      (finish-output *standard-output*)
      (cffi:with-pointer-to-vector-data (pointer octets)
        (let ((length (length octets))
              (offset 0))
          (loop while (< offset length)
                do (let ((written
                           (c-write descriptor
                                    (cffi:inc-pointer pointer offset)
                                    (- length offset))))
                     (unless (plusp written)
                       (return-from write-standard-output-octets nil))
                     (incf offset written)))
          t)))))

#+sbcl
(defun standard-input-binary-stream ()
  "A binary stream over the process's standard input when it is one.

When *STANDARD-INPUT* has been rebound, that stream is returned instead so
a caller keeps control of the input.  Reading bytes directly keeps a
comment that is not valid UTF-8 from being replaced by the character
decoder before the parser sees it."
  (let ((descriptor (standard-input-descriptor)))
    (if descriptor
        (sb-sys:make-fd-stream descriptor
                               :input t
                               :element-type '(unsigned-byte 8)
                               :buffering :full
                               :auto-close nil
                               :name "standard input")
        *standard-input*)))
#-sbcl
(defun standard-input-binary-stream ()
  *standard-input*)

(defun stop-stdin ()
  (setf *stdin-stopped* t)
  (when *stdin-watcher*
    (cl-pnet:fd-unwatch *stdin-watcher*)
    (setf *stdin-watcher* nil)))

(defun stdin-thread (channel)
  "Read an unwatchable stdin until EOF, handing every chunk to the loop.

A regular file and /dev/null have no poll method, so the kernel refuses to
register them; their reads complete at once and CALL-ON-LOOP keeps the
chunks in the order they were read."
  (loop
    (when *stdin-stopped* (return))
    (multiple-value-bind (octets count error)
        (cl-pnet-sockets:read-octets 0 65536)
      (declare (ignore error))
      (cond
        ((plusp count)
         (cl-pnet:call-on-loop
          (lambda ()
            (unless *stdin-stopped*
              (feed-keystrokes
               channel (if *escape-char* (escape-filter octets) octets))))))
        ((zerop count)
         (cl-pnet:call-on-loop
          (lambda ()
            (unless *stdin-stopped*
              (finish-keystrokes channel)
              (handler-case (cl-pnet-ssh:ssh-channel-eof channel)
                (error () nil)))))
         (return))
        (t nil)))))

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
  "Feed CHANNEL from stdin, by a watch or, when that is impossible, a thread.

A terminal, pipe or socket can be watched; a regular file or /dev/null
cannot, and ssh treats those as ordinary input, so they are read on their own
thread rather than reported as a broken descriptor."
  (setf *stdin-stopped* nil)
  (handler-case
      (setf *stdin-watcher*
            (cl-pnet:fd-watch
             0
             :on-readable
             (lambda (watcher)
               (declare (ignore watcher))
               (handler-case (stdin-readable channel)
                 (error () (stop-stdin))))))
    (error ()
      (setf *stdin-watcher* nil
            *stdin-thread*
            (bt:make-thread (lambda () (stdin-thread channel))
                            :name "burs stdin")))))
