(in-package #:bursyk-server)

;;;; Windows children: CreateProcess with inherited pipes, and ConPTY for a
;;;; pty.  There is no fork, so the child is a separate process from the
;;;; start, and its exit status comes from GetExitCodeProcess rather than a
;;;; status pipe.  A job object ties the shell's whole process tree to the
;;;; channel, standing in for the POSIX process group.

(cffi:define-foreign-library bursyk-kernel32
  (:windows "kernel32.dll"))
(cffi:use-foreign-library bursyk-kernel32)

(cffi:defcfun ("CreatePipe" c-create-pipe) :int
  (read-pipe :pointer) (write-pipe :pointer)
  (attributes :pointer) (size :unsigned-long))
(cffi:defcfun ("SetHandleInformation" c-set-handle-information) :int
  (handle :pointer) (mask :unsigned-long) (flags :unsigned-long))
(cffi:defcfun ("CloseHandle" c-close-handle) :int (handle :pointer))
(cffi:defcfun ("CreateProcessW" c-create-process-w) :int
  (application-name :pointer) (command-line :pointer)
  (process-attributes :pointer) (thread-attributes :pointer)
  (inherit-handles :int) (creation-flags :unsigned-long)
  (environment :pointer) (current-directory :pointer)
  (startup-info :pointer) (process-information :pointer))
(cffi:defcfun ("WaitForSingleObject" c-wait-for-single-object) :unsigned-long
  (handle :pointer) (milliseconds :unsigned-long))
(cffi:defcfun ("GetExitCodeProcess" c-get-exit-code-process) :int
  (process :pointer) (exit-code :pointer))
(cffi:defcfun ("TerminateProcess" c-terminate-process) :int
  (process :pointer) (exit-code :unsigned-long))
(cffi:defcfun ("CreateJobObjectW" c-create-job-object-w) :pointer
  (attributes :pointer) (name :pointer))
(cffi:defcfun ("SetInformationJobObject" c-set-information-job-object) :int
  (job :pointer) (class :int) (information :pointer) (length :unsigned-long))
(cffi:defcfun ("AssignProcessToJobObject" c-assign-process-to-job-object) :int
  (job :pointer) (process :pointer))
(cffi:defcfun ("TerminateJobObject" c-terminate-job-object) :int
  (job :pointer) (exit-code :unsigned-long))
(cffi:defcfun ("GetEnvironmentStringsW" c-get-environment-strings-w) :pointer)
(cffi:defcfun ("FreeEnvironmentStringsW" c-free-environment-strings-w) :int
  (block :pointer))
(cffi:defcfun ("GetLastError" c-get-last-error) :unsigned-long)
(cffi:defcfun ("ReadFile" c-read-file) :int
  (handle :pointer) (buffer :pointer) (length :unsigned-long)
  (read :pointer) (overlapped :pointer))
(cffi:defcfun ("WriteFile" c-write-file) :int
  (handle :pointer) (buffer :pointer) (length :unsigned-long)
  (written :pointer) (overlapped :pointer))

;;; ConPTY is present from Windows 10 1809; the entry points are resolved
;;; when first called, so an older system gets a clear error instead of a
;;; server that cannot start at all.
(cffi:defcfun ("CreatePseudoConsole" c-create-pseudo-console) :int
  (size :unsigned-long) (input :pointer) (output :pointer)
  (flags :unsigned-long) (pseudo-console :pointer))
(cffi:defcfun ("ClosePseudoConsole" c-close-pseudo-console) :void
  (pseudo-console :pointer))
(cffi:defcfun ("ResizePseudoConsole" c-resize-pseudo-console) :int
  (pseudo-console :pointer) (size :unsigned-long))
(cffi:defcfun ("InitializeProcThreadAttributeList" c-init-attribute-list) :int
  (list :pointer) (count :unsigned-long) (flags :unsigned-long)
  (size :pointer))
(cffi:defcfun ("UpdateProcThreadAttribute" c-update-attribute) :int
  (list :pointer) (flags :unsigned-long) (attribute :unsigned-long-long)
  (value :pointer) (size :unsigned-long-long)
  (previous :pointer) (return-size :pointer))
(cffi:defcfun ("DeleteProcThreadAttributeList" c-delete-attribute-list) :void
  (list :pointer))

(cffi:defcstruct startup-info-w
  (cb :unsigned-long)
  (reserved :pointer)
  (desktop :pointer)
  (title :pointer)
  (x :unsigned-long)
  (y :unsigned-long)
  (x-size :unsigned-long)
  (y-size :unsigned-long)
  (x-count-chars :unsigned-long)
  (y-count-chars :unsigned-long)
  (fill-attribute :unsigned-long)
  (flags :unsigned-long)
  (show-window :unsigned-short)
  (reserved2-size :unsigned-short)
  (reserved2 :pointer)
  (std-input :pointer)
  (std-output :pointer)
  (std-error :pointer))

(cffi:defcstruct startup-info-ex-w
  (startup (:struct startup-info-w))
  (attribute-list :pointer))

(cffi:defcstruct process-information
  (process :pointer)
  (thread :pointer)
  (process-id :unsigned-long)
  (thread-id :unsigned-long))

(defconstant +startf-use-std-handles+ #x100)
(defconstant +extended-startupinfo-present+ #x00080000)
(defconstant +create-unicode-environment+ #x00000400)
(defconstant +handle-flag-inherit+ #x1)
(defconstant +infinite+ #xFFFFFFFF)
(defconstant +job-object-extended-limit-information+ 9)
(defconstant +job-object-limit-kill-on-job-close+ #x2000)
(defconstant +proc-thread-attribute-pseudoconsole+ #x00020016)

(defparameter +windows-shell-fallback+
  "C:\\Windows\\System32\\cmd.exe")

(defvar *children* (make-hash-table :test #'eql)
  "PID -> (PROCESS JOB HPCON), the handles a Windows child owns.")

(defun windows-shell ()
  (or (uiop:getenv "COMSPEC") +windows-shell-fallback+))

(defun windows-error (operation)
  (error "~A failed: Windows error ~D" operation (c-get-last-error)))

(defun zero-memory (pointer size)
  (loop for index below size
        do (setf (cffi:mem-aref pointer :unsigned-char index) 0)))

;;; ---- command lines ----

(defun quote-windows-argument (argument)
  "Quote ARGUMENT for CommandLineToArgvW, the parser CreateProcess uses.

Backslashes are literal except before a quote, where an odd count escapes
the quote and an even count ends the run; the closing quote doubles every
trailing backslash."
  (let ((needs-quotes
          (or (zerop (length argument))
              (find-if (lambda (character)
                         (member character '(#\Space #\Tab #\Newline #\")))
                       argument))))
    (if (not needs-quotes)
        argument
        (with-output-to-string (out)
          (write-char #\" out)
          (let ((backslashes 0))
            (flet ((flush-backslashes (count)
                     (dotimes (index count) (write-char #\\ out))))
              (loop for character across argument
                    do (cond
                         ((char= character #\\)
                          (incf backslashes))
                         ((char= character #\")
                          (flush-backslashes (1+ (* 2 backslashes)))
                          (write-char #\" out)
                          (setf backslashes 0))
                         (t
                          (flush-backslashes backslashes)
                          (setf backslashes 0)
                          (write-char character out))))
              (flush-backslashes (* 2 backslashes))))
          (write-char #\" out)))))

(defun windows-command-line (arguments)
  (format nil "~{~A~^ ~}" (mapcar #'quote-windows-argument arguments)))

(defun shell-command-line (command)
  "cmd.exe's spelling of a remote command, as sshd on Windows runs it.

The command is the tail of the line on purpose: cmd parses it itself, so
quoting it as one CreateProcess argument would change its meaning."
  (format nil "~A /d /c ~A" (quote-windows-argument (windows-shell)) command))

;;; ---- environment ----

(defun environment-strings ()
  "The parent environment as a list of NAME=VALUE strings."
  (let ((block (c-get-environment-strings-w)))
    (when (cffi:null-pointer-p block)
      (windows-error "GetEnvironmentStringsW"))
    (unwind-protect
         (loop with offset = 0
               for (string next) =
               (multiple-value-list
                (cffi:foreign-string-to-lisp
                 block :offset offset :encoding :utf-16le))
               while (plusp (length string))
               collect string
               ;; FOREIGN-STRING-TO-LISP counts the bytes before the NUL,
               ;; so skip the two-byte UTF-16 terminator as well.
               do (incf offset (+ next 2)))
      (c-free-environment-strings-w block))))

(defun environment-name (string)
  (let ((equals (position #\= string)))
    (if (and equals (plusp equals))
        (subseq string 0 equals)
        nil)))

(defun merge-environment (extra)
  "The parent environment with EXTRA replacing same-named entries.

Names compare case-insensitively, as Windows does, so a SendEnv PATH does
not leave two PATH entries for the child to choose between."
  (let ((extra-names (mapcar (lambda (pair) (car pair)) extra)))
    (append
     (loop for string in (environment-strings)
           for name = (environment-name string)
           unless (and name
                       (member name extra-names :test #'string-equal))
             collect string)
     (mapcar (lambda (pair) (format nil "~A=~A" (car pair) (cdr pair)))
             extra))))

(defun environment-string-lessp (left right)
  "Order two NAME=VALUE strings the way CreateProcessW requires.

The names compare case-insensitively in Unicode order, and the value only
breaks a tie, which a merged environment never has."
  (let ((length (min (length left) (length right))))
    (loop for index below length
          for a = (char-downcase (char left index))
          for b = (char-downcase (char right index))
          do (cond ((char< a b) (return t))
                   ((char> a b) (return nil)))
          finally (return (< (length left) (length right))))))

(defun make-environment-block (extra)
  "A NUL-separated, double-NUL-terminated UTF-16 environment block.

The entries are sorted as CreateProcessW requires, and each string is encoded
with Babel's UTF-16LE so a name or value outside the BMP keeps its surrogate
pair."
  (let* ((strings (sort (merge-environment extra) #'environment-string-lessp))
         (parts (mapcar (lambda (string)
                          (multiple-value-list
                           (cffi:foreign-string-alloc string :encoding :utf-16le)))
                        strings))
         ;; Every part includes its own two-byte NUL; one more UTF-16 NUL
         ;; makes the block's final double NUL.
         (size (+ 2 (loop for part in parts sum (second part))))
         (block (cffi:foreign-alloc :uint8 :count size)))
    (unwind-protect
         (loop with offset = 0
               for (pointer length) in parts
               do (loop for index below length
                        do (setf (cffi:mem-aref block :uint8 (+ offset index))
                                 (cffi:mem-aref pointer :uint8 index)))
                  (incf offset length)
               finally (setf (cffi:mem-aref block :uint8 offset) 0
                             (cffi:mem-aref block :uint8 (1+ offset)) 0))
      (mapc (lambda (part) (cffi:foreign-free (first part))) parts))
    block))

;;; ---- pipes and processes ----

(cffi:defcstruct security-attributes
  (length :unsigned-long)
  (descriptor :pointer)
  (inherit :int))

(defun make-inheritable-pipe ()
  "A pipe whose ends both may be inherited, as (VALUES READ WRITE)."
  (cffi:with-foreign-object (attributes '(:struct security-attributes))
    (setf (cffi:foreign-slot-value
           attributes '(:struct security-attributes) 'length)
          (cffi:foreign-type-size '(:struct security-attributes))
          (cffi:foreign-slot-value
           attributes '(:struct security-attributes) 'descriptor)
          (cffi:null-pointer)
          (cffi:foreign-slot-value
           attributes '(:struct security-attributes) 'inherit)
          1)
    (cffi:with-foreign-object (read-pipe :pointer)
      (cffi:with-foreign-object (write-pipe :pointer)
        (unless (plusp (c-create-pipe read-pipe write-pipe attributes 0))
          (windows-error "CreatePipe"))
        (values (cffi:mem-ref read-pipe :pointer)
                (cffi:mem-ref write-pipe :pointer))))))

(defun make-private-pipe ()
  "A pipe for ConPTY, whose ends are not inherited by the child."
  (cffi:with-foreign-object (read-pipe :pointer)
    (cffi:with-foreign-object (write-pipe :pointer)
      (unless (plusp (c-create-pipe read-pipe write-pipe
                                    (cffi:null-pointer) 0))
        (windows-error "CreatePipe"))
      (values (cffi:mem-ref read-pipe :pointer)
              (cffi:mem-ref write-pipe :pointer)))))

(defun make-private (handle)
  "Keep HANDLE out of later children's inherited set."
  (unless (plusp (c-set-handle-information handle +handle-flag-inherit+ 0))
    (windows-error "SetHandleInformation"))
  handle)

(defun close-child-fd (handle)
  "Release one Windows handle, ignoring an already invalid one."
  (when (and handle (not (cffi:null-pointer-p handle)))
    (ignore-errors (c-close-handle handle)))
  nil)

(defun make-job ()
  "A job that kills its whole process tree when the last handle closes."
  (let ((job (c-create-job-object-w (cffi:null-pointer) (cffi:null-pointer))))
    (when (cffi:null-pointer-p job)
      (return-from make-job nil))
    ;; JOBOBJECT_EXTENDED_LIMIT_INFORMATION; only LimitFlags is set, so a
    ;; large zeroed buffer is simpler and less brittle than mirroring every
    ;; field of the structure.
    (cffi:with-foreign-object (information :char 256)
      (zero-memory information 256)
      (setf (cffi:mem-ref information :unsigned-long 16)
            +job-object-limit-kill-on-job-close+)
      (unless (plusp (c-set-information-job-object
                      job +job-object-extended-limit-information+
                      information 256))
        (c-close-handle job)
        (return-from make-job nil)))
    job))

(defun make-attribute-list (pseudo-console)
  "A PROC_THREAD_ATTRIBUTE_LIST holding PSEUDO-CONSOLE."
  (cffi:with-foreign-object (size :size)
    (c-init-attribute-list (cffi:null-pointer) 1 0 size)
    (let ((list (cffi:foreign-alloc :char :count (cffi:mem-ref size :size))))
      (unless (plusp (c-init-attribute-list list 1 0 size))
        (cffi:foreign-free list)
        (windows-error "InitializeProcThreadAttributeList"))
      (unless (plusp (c-update-attribute
                      list 0 +proc-thread-attribute-pseudoconsole+
                      pseudo-console (cffi:foreign-type-size :pointer)
                      (cffi:null-pointer) (cffi:null-pointer)))
        (c-delete-attribute-list list)
        (cffi:foreign-free list)
        (windows-error "UpdateProcThreadAttribute"))
      list)))

(defun start-process (command-line environment std-input std-output std-error
                      &key console)
  "Create one child; return (VALUES PROCESS-ID PROCESS JOB).

CONSOLE, when given, attaches the child to that pseudoconsole instead of the
three standard handles."
  (let* ((arguments (cffi:foreign-string-alloc command-line
                                               :encoding :utf-16le))
         (block (make-environment-block environment))
         (job (make-job))
         (pid nil)
         (process nil))
    (unwind-protect
         (cffi:with-foreign-object (information '(:struct process-information))
           (zero-memory information
                        (cffi:foreign-type-size '(:struct process-information)))
           (if console
               (cffi:with-foreign-object (info-ex '(:struct startup-info-ex-w))
                 (zero-memory info-ex
                              (cffi:foreign-type-size
                               '(:struct startup-info-ex-w)))
                 (let ((attribute-list (make-attribute-list console))
                       (startup (cffi:foreign-slot-pointer
                                 info-ex '(:struct startup-info-ex-w)
                                 'startup)))
                   (unwind-protect
                        (progn
                          (setf (cffi:foreign-slot-value
                                 info-ex '(:struct startup-info-ex-w)
                                 'attribute-list)
                                attribute-list
                                (cffi:foreign-slot-value
                                 startup '(:struct startup-info-w) 'cb)
                                (cffi:foreign-type-size
                                 '(:struct startup-info-ex-w)))
                          (unless (plusp
                                   (c-create-process-w
                                    (cffi:null-pointer) arguments
                                    (cffi:null-pointer) (cffi:null-pointer)
                                    0
                                    (logior +extended-startupinfo-present+
                                            +create-unicode-environment+)
                                    block (cffi:null-pointer)
                                    info-ex information))
                            (windows-error "CreateProcessW")))
                     (c-delete-attribute-list attribute-list)
                     (cffi:foreign-free attribute-list))))
               (cffi:with-foreign-object (startup '(:struct startup-info-w))
                 (zero-memory startup
                              (cffi:foreign-type-size '(:struct startup-info-w)))
                 (setf (cffi:foreign-slot-value
                        startup '(:struct startup-info-w) 'cb)
                       (cffi:foreign-type-size '(:struct startup-info-w))
                       (cffi:foreign-slot-value
                        startup '(:struct startup-info-w) 'flags)
                       +startf-use-std-handles+
                       (cffi:foreign-slot-value
                        startup '(:struct startup-info-w) 'std-input)
                       std-input
                       (cffi:foreign-slot-value
                        startup '(:struct startup-info-w) 'std-output)
                       std-output
                       (cffi:foreign-slot-value
                        startup '(:struct startup-info-w) 'std-error)
                       std-error)
                 (unless (plusp
                          (c-create-process-w
                           (cffi:null-pointer) arguments
                           (cffi:null-pointer) (cffi:null-pointer)
                           1
                           +create-unicode-environment+
                           block (cffi:null-pointer)
                           startup information))
                   (windows-error "CreateProcessW"))))
           (setf process (cffi:foreign-slot-value
                          information '(:struct process-information) 'process)
                 pid (cffi:foreign-slot-value
                      information '(:struct process-information) 'process-id))
           (c-close-handle
            (cffi:foreign-slot-value information
                                     '(:struct process-information) 'thread))
           (when job
             (unless (plusp (c-assign-process-to-job-object job process))
               (c-close-handle job)
               (setf job nil))))
      (unless process
        (close-child-fd job))
      (cffi:foreign-free arguments)
      (cffi:foreign-free block))
    (setf (gethash pid *children*) (list process job console))
    (values pid process job)))

(defun spawn-with-pipes (command-line environment)
  "Run COMMAND-LINE with pipes on its three standard streams.

Returns (VALUES PID STDIN STDOUT STDERR): STDIN is the handle we write,
STDOUT and STDERR the handles we read."
  (multiple-value-bind (child-in child-in-write) (make-inheritable-pipe)
    (multiple-value-bind (child-out child-out-write) (make-inheritable-pipe)
      (multiple-value-bind (child-err child-err-write) (make-inheritable-pipe)
        (unwind-protect
             (handler-case
                 (progn
                   ;; Clear the parent's ends before the fork-equivalent, or
                   ;; the child inherits the very handles whose close signals
                   ;; EOF.
                   (make-private child-in-write)
                   (make-private child-out)
                   (make-private child-err)
                   (multiple-value-bind (pid)
                       (start-process command-line environment
                                      child-in child-out-write child-err-write)
                     (values pid child-in-write child-out child-err)))
               (error (condition)
                 (close-child-fd child-in-write)
                 (close-child-fd child-out)
                 (close-child-fd child-err)
                 (error condition)))
          (c-close-handle child-in)
          (c-close-handle child-out-write)
          (c-close-handle child-err-write))))))

(defun spawn-shell (command &key environment chroot)
  "Run COMMAND through cmd.exe; return (VALUES PID STDIN STDOUT STDERR).

CHROOT is accepted for the shared application path and ignored: Windows has
no chroot, and safely-chroot-path-p refuses one before this point."
  (declare (ignore chroot))
  (spawn-with-pipes (shell-command-line command) environment))

(defun spawn-program (program arguments &key environment chroot)
  "Run PROGRAM with ARGUMENTS, no shell interpretation."
  (declare (ignore chroot))
  (spawn-with-pipes
   (windows-command-line (cons program arguments))
   environment))

;;; ---- pseudo-terminals ----

(defun pty-size (rows columns)
  "Pack a COORD (X then Y) for CreatePseudoConsole's by-value argument.

COORD is two shorts, which the x64 ABI passes as one 32-bit register, so
the packed value is what the foreign call already expects."
  (logior (logand (max 1 columns) #xFFFF)
          (ash (logand (max 1 rows) #xFFFF) 16)))

(defun make-pseudo-console (rows columns)
  "Return (VALUES HPCON INPUT-WRITE OUTPUT-READ)."
  (multiple-value-bind (input-read input-write) (make-private-pipe)
    (multiple-value-bind (output-read output-write) (make-private-pipe)
      (cffi:with-foreign-object (console :pointer)
        (let ((result
                (handler-case
                    (c-create-pseudo-console (pty-size rows columns)
                                             input-read output-write 0 console)
                  (error ()
                    (c-close-handle input-read)
                    (c-close-handle input-write)
                    (c-close-handle output-read)
                    (c-close-handle output-write)
                    (error "a pty needs Windows 10 1809 or newer")))))
          (if (minusp result)
              (progn
                (c-close-handle input-read)
                (c-close-handle input-write)
                (c-close-handle output-read)
                (c-close-handle output-write)
                (error "CreatePseudoConsole failed: Windows error ~D"
                       (c-get-last-error)))
              (progn
                ;; ConPTY duplicated its ends; ours must go so a broken
                ;; channel is detected when the session closes.
                (c-close-handle input-read)
                (c-close-handle output-write)
                (values (cffi:mem-ref console :pointer)
                        input-write
                        output-read))))))))

(defun spawn-pty (command-line environment rows columns)
  "Run COMMAND-LINE on a ConPTY; return (VALUES PID INPUT-WRITE OUTPUT-READ HPCON)."
  (multiple-value-bind (console input-write output-read)
      (make-pseudo-console rows columns)
    (handler-case
        (let ((pid (start-process command-line environment
                                  (cffi:null-pointer) (cffi:null-pointer)
                                  (cffi:null-pointer)
                                  :console console)))
          (values pid input-write output-read console))
      (error (condition)
        (c-close-pseudo-console console)
        (close-child-fd input-write)
        (close-child-fd output-read)
        (error condition)))))

(defun spawn-pty-shell (command shell &key environment rows columns chroot)
  "Run COMMAND (or the login shell) on a ConPTY."
  (declare (ignore chroot))
  (let ((shell (or shell (windows-shell))))
    (spawn-pty (if (and command (plusp (length command)))
                   (shell-command-line command)
                   (quote-windows-argument shell))
               environment (or rows 24) (or columns 80))))

(defun spawn-pty-program (program arguments &key environment rows columns chroot)
  (declare (ignore chroot))
  (spawn-pty (windows-command-line (cons program arguments))
             environment (or rows 24) (or columns 80)))

(defun set-child-window (console rows columns)
  "Resize the pseudoconsole, which sends the equivalent of SIGWINCH."
  (when console
    (ignore-errors (c-resize-pseudo-console console
                                            (pty-size rows columns)))))

;;; ---- lifetime ----

(defun child-handles (pid)
  (gethash pid *children*))

(defun collect-child (pid)
  "Wait for PID and release its process, job and console handles."
  (let ((handles (gethash pid *children*)))
    (when handles
      (destructuring-bind (process job console) handles
        (when process
          (c-wait-for-single-object process +infinite+))
        (close-child-fd console)
        (close-child-fd job)
        (close-child-fd process))
      (remhash pid *children*)))
  (values))

(defun kill-child (pid)
  "Terminate PID and its job, then release the handles."
  (let ((handles (gethash pid *children*)))
    (when handles
      (destructuring-bind (process job console) handles
        (declare (ignore console))
        (when job (ignore-errors (c-terminate-job-object job 1)))
        (when process (ignore-errors (c-terminate-process process 1))))))
  (values))

(defun kill-child-group (pid)
  "Terminate PID and every process in its job."
  (kill-child pid))
