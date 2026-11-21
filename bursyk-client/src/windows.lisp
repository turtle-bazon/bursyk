(in-package #:burs)

;;;; Windows terminal and stdin support.
;;;;
;;;; A Windows console has no stty, and libuv's FD-WATCH is socket-only, so
;;;; the terminal is driven with GetConsoleMode/SetConsoleMode and stdin is
;;;; moved by a blocking thread that hands every read to CL-PNET:CALL-ON-LOOP.
;;;; The console code pages are switched to UTF-8 for the session so the bytes
;;;; the remote pty sends, and the bytes the user types, cross unchanged.

(cffi:define-foreign-library burs-client-kernel32
  (:windows "kernel32.dll"))
(cffi:use-foreign-library burs-client-kernel32)

(cffi:defcfun ("GetStdHandle" c-get-std-handle) :pointer
  (which :unsigned-long))
(cffi:defcfun ("GetConsoleMode" c-get-console-mode) :int
  (handle :pointer) (mode :pointer))
(cffi:defcfun ("SetConsoleMode" c-set-console-mode) :int
  (handle :pointer) (mode :unsigned-long))
(cffi:defcfun ("GetConsoleScreenBufferInfo" c-get-console-screen-buffer-info) :int
  (handle :pointer) (info :pointer))
(cffi:defcfun ("GetConsoleCP" c-get-console-cp) :unsigned-long)
(cffi:defcfun ("GetConsoleOutputCP" c-get-console-output-cp) :unsigned-long)
(cffi:defcfun ("SetConsoleCP" c-set-console-cp) :int
  (code-page :unsigned-long))
(cffi:defcfun ("SetConsoleOutputCP" c-set-console-output-cp) :int
  (code-page :unsigned-long))
(cffi:defcfun ("ReadFile" c-read-file) :int
  (handle :pointer) (buffer :pointer) (length :unsigned-long)
  (read :pointer) (overlapped :pointer))
(cffi:defcfun ("WriteFile" c-write-file) :int
  (handle :pointer) (buffer :pointer) (length :unsigned-long)
  (written :pointer) (overlapped :pointer))

(cffi:defcstruct coord
  (x :short)
  (y :short))

(cffi:defcstruct small-rect
  (left :short)
  (top :short)
  (right :short)
  (bottom :short))

(cffi:defcstruct console-screen-buffer-info
  (size (:struct coord))
  (cursor-position (:struct coord))
  (attributes :unsigned-short)
  (window (:struct small-rect))
  (maximum-window-size (:struct coord)))

;;; The pseudo-handle values GetStdHandle takes.
(defconstant +std-input-handle+ #xFFFFFFF6)
(defconstant +std-output-handle+ #xFFFFFFF5)
(defconstant +std-error-handle+ #xFFFFFFF4)

;;; Console input modes.
(defconstant +enable-processed-input+ #x0001)
(defconstant +enable-line-input+ #x0002)
(defconstant +enable-echo-input+ #x0004)
(defconstant +enable-mouse-input+ #x0010)
(defconstant +enable-quick-edit-mode+ #x0040)
(defconstant +enable-extended-flags+ #x0080)
(defconstant +enable-virtual-terminal-input+ #x0200)

;;; Console output modes.
(defconstant +enable-virtual-terminal-processing+ #x0004)

(defconstant +utf-8-code-page+ 65001)

(defvar *console-input-mode* nil
  "The input mode TERMINAL-ENTER-RAW replaced, or NIL.")
(defvar *console-output-mode* nil
  "The output mode TERMINAL-ENTER-RAW replaced, or NIL.")
(defvar *console-code-pages* nil
  "The (INPUT OUTPUT) console code pages to restore, or NIL.")

(declaim (ftype (function (t) *) finish)
         (ftype (function (t) *) send-window-change))

(defun console-mode (handle)
  "HANDLE's console mode, or NIL when it is not a console."
  (cffi:with-foreign-object (mode :unsigned-long)
    (when (plusp (c-get-console-mode handle mode))
      (cffi:mem-ref mode :unsigned-long))))

(defun stdin-terminal-p ()
  (not (null (console-mode (c-get-std-handle +std-input-handle+)))))

(defun terminal-size ()
  "The console window's (VALUES ROWS COLUMNS), or (VALUES NIL NIL)."
  (let ((handle (c-get-std-handle +std-output-handle+)))
    (cffi:with-foreign-object (info '(:struct console-screen-buffer-info))
      (if (zerop (c-get-console-screen-buffer-info handle info))
          (values nil nil)
          (let ((window (cffi:foreign-slot-pointer
                         info '(:struct console-screen-buffer-info) 'window)))
            (let ((left (cffi:foreign-slot-value
                         window '(:struct small-rect) 'left))
                  (top (cffi:foreign-slot-value
                        window '(:struct small-rect) 'top))
                  (right (cffi:foreign-slot-value
                          window '(:struct small-rect) 'right))
                  (bottom (cffi:foreign-slot-value
                           window '(:struct small-rect) 'bottom)))
              (values (1+ (- bottom top))
                      (1+ (- right left)))))))))

(defun restore-terminal ()
  "Put the console modes and code pages back the way they were."
  (when *console-code-pages*
    (destructuring-bind (input output) *console-code-pages*
      (setf *console-code-pages* nil)
      (ignore-errors (c-set-console-cp input))
      (ignore-errors (c-set-console-output-cp output))))
  (when *console-input-mode*
    (let ((mode *console-input-mode*))
      (setf *console-input-mode* nil)
      (ignore-errors
       (c-set-console-mode (c-get-std-handle +std-input-handle+) mode))))
  (when *console-output-mode*
    (let ((mode *console-output-mode*))
      (setf *console-output-mode* nil)
      (ignore-errors
       (c-set-console-mode (c-get-std-handle +std-output-handle+) mode)))))

(defun ensure-console-codepage ()
  "Switch the console to UTF-8 once, remembering the codes to restore.

A Windows console renders the bytes WRITE-HANDLE passes it in the active
output code page, so every session that writes there needs UTF-8, not only a
pty with virtual terminal processing."
  (unless *console-code-pages*
    (setf *console-code-pages*
          (list (c-get-console-cp) (c-get-console-output-cp)))
    (ignore-errors (c-set-console-cp +utf-8-code-page+))
    (ignore-errors (c-set-console-output-cp +utf-8-code-page+)))
  *console-code-pages*)

(defun terminal-enter-raw ()
  "Stop local line editing, echo and Ctrl-C handling; turn on VT sequences.

The remote pty owns echo and line editing, and Ctrl-C has to arrive there as
a byte.  VT input makes the arrow and function keys arrive as the escape
sequences a terminal would send, and VT output renders the remote's escapes."
  (when (and (stdin-terminal-p)
             (not (getf *options* :stdin-null)))
    (let ((input (c-get-std-handle +std-input-handle+))
          (output (c-get-std-handle +std-output-handle+)))
      (let ((mode (console-mode input)))
        (when mode
          (setf *console-input-mode* mode)
          (let ((raw (logand mode
                             (lognot (logior +enable-processed-input+
                                             +enable-line-input+
                                             +enable-echo-input+
                                             +enable-mouse-input+
                                             +enable-quick-edit-mode+)))))
            (setf raw (logior raw +enable-extended-flags+))
            ;; Virtual terminal input needs Windows 10 too; a console that
            ;; refuses it keeps the raw flags and still passes every key.
            (unless (plusp
                     (c-set-console-mode
                      input (logior raw +enable-virtual-terminal-input+)))
              (ignore-errors (c-set-console-mode input raw))))))
      (let ((mode (console-mode output)))
        (when mode
          (setf *console-output-mode* mode)
          (ignore-errors
           (c-set-console-mode
            output (logior mode +enable-virtual-terminal-processing+)))))
      (ensure-console-codepage))))
(defun stop-winch ()
  (when *winch*
    (ignore-errors (cl-pnet:timer-stop *winch*))
    (setf *winch* nil)))

(defun start-winch (channel)
  "Forward console resizes to CHANNEL, polling because Windows has no SIGWINCH."
  (when (stdin-terminal-p)
    (let ((last (multiple-value-list (terminal-size))))
      (setf *winch*
            (ignore-errors
             (cl-pnet:timer-start
              0.25 0.25
              (lambda ()
                (let ((now (multiple-value-list (terminal-size))))
                  (unless (equal now last)
                    (setf last now)
                    (handler-case (send-window-change channel)
                      (error () nil)))))))))))

(defun standard-handle (stream)
  (cond ((eq stream *error-output*)
         (c-get-std-handle +std-error-handle+))
        ((eq stream *standard-output*)
         (c-get-std-handle +std-output-handle+))))

(defun write-handle (handle octets)
  "Write every octet of OCTETS to HANDLE; NIL when the handle is broken."
  (cffi:with-foreign-object (buffer :unsigned-char (max 1 (length octets)))
    (loop for index below (length octets)
          do (setf (cffi:mem-aref buffer :unsigned-char index)
                   (aref octets index)))
    (cffi:with-foreign-object (written :unsigned-long)
      (loop with offset = 0
            while (< offset (length octets))
            do (let ((count (min 65536 (- (length octets) offset))))
                 (unless (plusp (c-write-file
                                 handle (cffi:inc-pointer buffer offset)
                                 count written (cffi:null-pointer)))
                   (return-from write-handle nil))
                 (let ((wrote (cffi:mem-ref written :unsigned-long)))
                   (when (zerop wrote)
                     (return-from write-handle nil))
                   (incf offset wrote))))))
  t)

(defun write-octets (stream octets)
  "Write channel output to STREAM's handle, leaving as SIGPIPE would if closed.

The handle write keeps the bytes unchanged: the console is in UTF-8 and
virtual terminal mode during a pty session, and a redirected stdout is a file
or pipe that wants the raw stream."
  (handler-case
      (let ((handle (standard-handle stream)))
        (if handle
            (progn
              ;; A console wants UTF-8 bytes in its active code page; a file
              ;; or pipe wants them unchanged.
              (when (console-mode handle) (ensure-console-codepage))
              (finish-output stream)
              (unless (write-handle handle octets)
                (finish 141)))
            (progn
              (write-string (cl-pnet-ssh:ssh-octets-string octets) stream)
              (finish-output stream))))
    (error () (finish 141))))

(defun stop-stdin ()
  "Stop posting input.  The blocked ReadFile is left to the process exit."
  (setf *stdin-stopped* t))

(defun stdin-octets (buffer count)
  (let ((octets (make-array count :element-type '(unsigned-byte 8))))
    (loop for index below count
          do (setf (aref octets index)
                   (cffi:mem-aref buffer :unsigned-char index)))
    octets))

(defun stdin-thread (channel)
  "Read stdin until EOF, handing every chunk to the event loop.

ReadFile blocks, which is why this cannot run on the loop.  CALL-ON-LOOP
keeps the chunks in the order they were read, so the remote pty sees the same
bytes the user typed."
  (let ((handle (c-get-std-handle +std-input-handle+)))
    (cffi:with-foreign-object (buffer :unsigned-char 65536)
      (cffi:with-foreign-object (read :unsigned-long)
        (loop
          (when *stdin-stopped* (return))
          (unless (plusp (c-read-file handle buffer 65536 read
                                      (cffi:null-pointer)))
            (unless *stdin-stopped*
              (cl-pnet:call-on-loop
               (lambda ()
                 (unless *stdin-stopped*
                   (handler-case (cl-pnet-ssh:ssh-channel-eof channel)
                     (error () nil))))))
            (return))
          (let ((count (cffi:mem-ref read :unsigned-long)))
            (when (zerop count)
              (unless *stdin-stopped*
                (cl-pnet:call-on-loop
                 (lambda ()
                   (unless *stdin-stopped*
                     (handler-case (cl-pnet-ssh:ssh-channel-eof channel)
                       (error () nil))))))
              (return))
            (let ((octets (stdin-octets buffer count)))
              (unless *stdin-stopped*
                (cl-pnet:call-on-loop
                 (lambda ()
                   (unless *stdin-stopped*
                     (handler-case
                         (cl-pnet-ssh:ssh-channel-write channel octets)
                       (error () nil)))))))))))))

(defun start-stdin (channel)
  (setf *stdin-stopped* nil)
  (setf *stdin-thread*
        (bt:make-thread (lambda () (stdin-thread channel))
                        :name "burs stdin")))



;;; The parent waits for this marker on stdout before it exits.
(defun background-ready ()
  (write-line "BURS-AUTH-OK" *standard-output*)
  (finish-output *standard-output*)
  (setf *background-child* nil))
