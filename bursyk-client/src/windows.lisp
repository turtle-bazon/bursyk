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

(defun client-user-id ()
  "The uid ssh's %i percent expansion prints.

Win32-OpenSSH answers its getuid() compat call with 1, so a Windows client
expands %i to the same value."
  1)

(defun call-with-deferrable-signals-unblocked (function)
  "Call FUNCTION; Windows has no signal mask to work around."
  (funcall function))

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

(defun read-prompt-line (prompt &key (echo t))
  "Write PROMPT to stderr and read one line from stdin.

When ECHO is false and stdin is a console, the console's echo bit is cleared
for the read and restored afterwards; it is cleared before the prompt is
written, so an answer arriving with the prompt is not shown either.  NIL is
returned at end of input, so a non-interactive caller can treat a closed
stdin as a cancelled prompt rather than an empty answer."
  (let ((handle (and (not echo)
                     (stdin-terminal-p)
                     (c-get-std-handle +std-input-handle+)))
        (saved nil))
    (unwind-protect
         (progn
           (when handle
             (let ((mode (console-mode handle)))
               (when mode
                 (setf saved mode)
                 (ignore-errors
                  (c-set-console-mode
                   handle (logand mode (lognot +enable-echo-input+)))))))
           (format *error-output* "~A" prompt)
           (finish-output *error-output*)
           (read-line *standard-input* nil nil))
      (when saved
        (ignore-errors (c-set-console-mode handle saved)))
      (when (not echo)
        (format *error-output* "~%")
        (finish-output *error-output*)))))

(defun read-tty-line (prompt)
  "Write PROMPT on the console and read one line, or NIL without a console.

A key passphrase is asked for on the console rather than through stdin, so a
redirected stdin does not consume the answer and a non-interactive run never
prompts."
  (when (stdin-terminal-p)
    (read-prompt-line prompt :echo nil)))

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

(defun resolve-stream-synonym (stream)
  "STREAM with any SYNONYM-STREAM wrappers followed."
  (loop while (typep stream 'synonym-stream)
        do (setf stream (symbol-value (synonym-stream-symbol stream)))
        finally (return stream)))

#+sbcl
(defun standard-output-is-ours-p ()
  "Whether *STANDARD-OUTPUT* is still the process's own standard output."
  (eq (resolve-stream-synonym *standard-output*)
      (resolve-stream-synonym sb-sys:*stdout*)))
#-sbcl
(defun standard-output-is-ours-p ()
  nil)

(defun write-standard-output-octets (octets)
  "Write OCTETS to the process's standard output handle, or return NIL.

NIL means standard output was captured by the caller, which then has to use
the character stream.  The handle write keeps a key comment's bytes intact."
  (handler-case
      (when (standard-output-is-ours-p)
        (let ((handle (c-get-std-handle +std-output-handle+)))
          (when (console-mode handle) (ensure-console-codepage))
          (finish-output *standard-output*)
          (write-handle handle octets)))
    (error () nil)))

(defun standard-input-binary-stream ()
  "Windows keeps the character stream; the caller parses it as text."
  *standard-input*)

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
                   (finish-keystrokes channel)
                   (handler-case (cl-pnet-ssh:ssh-channel-eof channel)
                     (error () nil))))))
            (return))
          (let ((count (cffi:mem-ref read :unsigned-long)))
            (when (zerop count)
              (unless *stdin-stopped*
                (cl-pnet:call-on-loop
                 (lambda ()
                   (unless *stdin-stopped*
                     (finish-keystrokes channel)
                     (handler-case (cl-pnet-ssh:ssh-channel-eof channel)
                       (error () nil))))))
              (return))
            (let ((octets (stdin-octets buffer count)))
              (unless *stdin-stopped*
                (cl-pnet:call-on-loop
                 (lambda ()
                   (unless *stdin-stopped*
                     (handler-case
                         (feed-keystrokes channel octets)
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

;;;; ---- private-key ACL checks ----
;;;;
;;;; ssh-keygen on Windows cannot look at POSIX mode bits, so it asks the
;;;; security subsystem instead.  The rules come from
;;;; check_secure_file_permission() in Win32-OpenSSH's sshfileperm.c: the
;;;; owner must be the current user, Administrators, SYSTEM or
;;;; TrustedInstaller, and no other trustee may appear in an allowing ACE at
;;;; all, even with read-only access.  A SID history entry that resolves to
;;;; the current user is the exception.
;;;;
;;;; Getting this wrong in either direction is visible to users: a key that
;;;; ssh-keygen accepts must not be refused here, and one ssh-keygen refuses
;;;; (a file copied from a shared folder, say) must not be used.

(cffi:define-foreign-library burs-client-advapi32
  (:windows "advapi32.dll"))
(cffi:use-foreign-library burs-client-advapi32)

(cffi:defcfun ("GetCurrentProcess" c-get-current-process) :pointer)
(cffi:defcfun ("OpenProcessToken" c-open-process-token) :int
  (process :pointer) (access :unsigned-long) (token :pointer))
(cffi:defcfun ("GetTokenInformation" c-get-token-information) :int
  (token :pointer) (class :int) (information :pointer)
  (length :unsigned-long) (returned :pointer))
(cffi:defcfun ("CloseHandle" c-close-handle) :int (handle :pointer))
(cffi:defcfun ("GetNamedSecurityInfoW" c-get-named-security-info) :unsigned-long
  (object :pointer) (object-type :int) (information :unsigned-long)
  (owner :pointer) (group :pointer) (dacl :pointer) (sacl :pointer)
  (descriptor :pointer))
(cffi:defcfun ("GetAce" c-get-ace) :int
  (acl :pointer) (index :unsigned-long) (ace :pointer))
(cffi:defcfun ("IsValidSid" c-is-valid-sid) :int (sid :pointer))
(cffi:defcfun ("IsValidAcl" c-is-valid-acl) :int (acl :pointer))
(cffi:defcfun ("IsWellKnownSid" c-is-well-known-sid) :int
  (sid :pointer) (type :int))
(cffi:defcfun ("EqualSid" c-equal-sid) :int (a :pointer) (b :pointer))
(cffi:defcfun ("LocalFree" c-local-free) :pointer (memory :pointer))
(cffi:defcfun ("ConvertStringSidToSidW" c-convert-string-sid-to-sid) :int
  (string :pointer) (sid :pointer))
(cffi:defcfun ("ConvertSidToStringSidW" c-convert-sid-to-string-sid) :int
  (sid :pointer) (string :pointer))
(cffi:defcfun ("ConvertStringSecurityDescriptorToSecurityDescriptorW"
               c-convert-string-security-descriptor) :int
  (string :pointer) (revision :unsigned-long) (descriptor :pointer)
  (size :pointer))
(cffi:defcfun ("SetFileSecurityW" c-set-file-security) :int
  (file :pointer) (security-information :unsigned-long) (descriptor :pointer))
(cffi:defcfun ("GetComputerNameW" c-get-computer-name) :int
  (buffer :pointer) (size :pointer))
(cffi:defcfun ("LookupAccountSidW" c-lookup-account-sid) :int
  (system :pointer) (sid :pointer) (name :pointer) (name-length :pointer)
  (domain :pointer) (domain-length :pointer) (use :pointer))

(defconstant +windows-se-file-object+ 1)
(defconstant +windows-owner-security-information+ #x1)
(defconstant +windows-dacl-security-information+ #x4)
(defconstant +windows-token-query+ #x8)
(defconstant +windows-token-user+ 1)
(defconstant +windows-access-allowed-ace-type+ 0)
(defconstant +windows-win-local-system-sid+ 22)
(defconstant +windows-win-builtin-administrators-sid+ 26)
(defparameter *windows-trusted-installer-sid*
  "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")

(defun windows-utf16-units (string)
  "STRING as UTF-16 code units, without a terminator."
  (let ((units (make-array (length string) :element-type '(unsigned-byte 16)
                                           :adjustable t :fill-pointer 0)))
    (loop for character across string
          for code = (char-code character)
          do (if (> code #xFFFF)
                 (let ((value (- code #x10000)))
                   (vector-push-extend (+ #xD800 (ldb (byte 10 10) value)) units)
                   (vector-push-extend (+ #xDC00 (ldb (byte 10 0) value)) units))
                 (vector-push-extend code units)))
    units))

(defun windows-utf16-pointer (string)
  "VALUES POINTER LENGTH for a null-terminated UTF-16 copy of STRING."
  (let* ((units (windows-utf16-units string))
         (length (1+ (length units)))
         (pointer (cffi:foreign-alloc :unsigned-short :count length)))
    (loop for index below (length units)
          do (setf (cffi:mem-aref pointer :unsigned-short index)
                   (aref units index)))
    (setf (cffi:mem-aref pointer :unsigned-short (length units)) 0)
    (values pointer length)))

(defun windows-utf16-string (pointer length)
  "The Lisp string in the first LENGTH UTF-16 units at POINTER."
  (let ((string (make-array length :element-type 'character
                                   :adjustable t :fill-pointer 0)))
    (loop for index below length
          do (vector-push-extend
              (code-char (cffi:mem-aref pointer :unsigned-short index))
              string))
    (coerce string 'string)))

(defun windows-utf16-c-string (pointer)
  "The null-terminated UTF-16 string at POINTER as a Lisp string."
  (let ((length 0))
    (loop while (plusp (cffi:mem-aref pointer :unsigned-short length))
          do (incf length))
    (windows-utf16-string pointer length)))

(defun windows-current-user-sid (buffer)
  "The SID of the process user, stored in BUFFER, or NIL."
  (cffi:with-foreign-objects ((token :pointer)
                              (returned :unsigned-long))
    (when (plusp (c-open-process-token (c-get-current-process)
                                       +windows-token-query+ token))
      (unwind-protect
           (when (plusp (c-get-token-information
                         (cffi:mem-ref token :pointer) +windows-token-user+
                         buffer 256 returned))
             ;; The token buffer starts with TOKEN_USER, whose first field
             ;; is a pointer to the SID.
             (cffi:mem-ref buffer :pointer))
        (c-close-handle (cffi:mem-ref token :pointer))))))

(defun windows-current-user-sid-string ()
  "The current user's SID as the S-1-... text SDDL wants, or NIL."
  (let ((buffer (cffi:foreign-alloc :unsigned-char :count 256)))
    (unwind-protect
         (let ((sid (windows-current-user-sid buffer)))
           (when sid
             (cffi:with-foreign-object (string :pointer)
               (when (plusp (c-convert-sid-to-string-sid sid string))
                 (unwind-protect
                      (windows-utf16-c-string
                       (cffi:mem-ref string :pointer))
                   (c-local-free (cffi:mem-ref string :pointer)))))))
      (cffi:foreign-free buffer))))

(defun windows-secure-private-file (path)
  "Give PATH the protected DACL Win32-OpenSSH gives a new private key.

Its createFile_flags_setup() builds the SDDL
  O:<user>D:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;<user>)
so a fresh key grants full control only to Administrators, SYSTEM and its
owner, and inherits nothing from the directory.  SBCL's OPEN cannot pass a
security descriptor, so apply the equivalent DACL once the file is written.
Best effort: if the ACL cannot be set, the inherited one stays, and the
permission check that runs before every load judges it on its own."
  (let ((sid (windows-current-user-sid-string)))
    (when sid
      (multiple-value-bind (sddl sddl-length)
          (windows-utf16-pointer
           (format nil "D:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;~A)" sid))
        (declare (ignore sddl-length))
        (multiple-value-bind (path-pointer path-length)
            (windows-utf16-pointer (uiop:native-namestring path))
          (declare (ignore path-length))
          (cffi:with-foreign-object (descriptor :pointer)
            (unwind-protect
                 (when (plusp
                        (c-convert-string-security-descriptor
                         sddl 1 descriptor (cffi:null-pointer)))
                   (unwind-protect
                        (c-set-file-security
                         path-pointer +windows-dacl-security-information+
                         (cffi:mem-ref descriptor :pointer))
                     (c-local-free (cffi:mem-ref descriptor :pointer))))
              (cffi:foreign-free path-pointer)
              (cffi:foreign-free sddl))))))))

(defun windows-trusted-installer-sid ()
  "The TrustedInstaller SID, which the caller frees with LocalFree."
  (multiple-value-bind (string length)
      (windows-utf16-pointer *windows-trusted-installer-sid*)
    (declare (ignore length))
    (unwind-protect
         (cffi:with-foreign-object (sid :pointer)
           (when (plusp (c-convert-string-sid-to-sid string sid))
             (cffi:mem-ref sid :pointer)))
      (cffi:foreign-free string))))

(defun windows-sid-account (sid)
  "VALUES NAME DOMAIN TYPE for SID, or NIL when it has no account."
  (cffi:with-foreign-objects ((name :unsigned-short 257)
                              (domain :unsigned-short 257)
                              (name-length :unsigned-long)
                              (domain-length :unsigned-long)
                              (use :int))
    (setf (cffi:mem-ref name-length :unsigned-long) 256
          (cffi:mem-ref domain-length :unsigned-long) 256)
    (when (plusp (c-lookup-account-sid (cffi:null-pointer) sid
                                       name name-length
                                       domain domain-length use))
      (values (windows-utf16-string
               name (cffi:mem-ref name-length :unsigned-long))
              (windows-utf16-string
               domain (cffi:mem-ref domain-length :unsigned-long))
              (cffi:mem-ref use :int)))))

(defun windows-computer-name ()
  "This machine's NetBIOS name, as GetComputerNameW reports it."
  (cffi:with-foreign-objects ((buffer :unsigned-short 32768)
                              (size :unsigned-long))
    (setf (cffi:mem-ref size :unsigned-long) 32767)
    (when (plusp (c-get-computer-name buffer size))
      (windows-utf16-string buffer (cffi:mem-ref size :unsigned-long)))))

(defun windows-current-user-name ()
  "The current account as Win32 getpwuid() spells it, or NIL.

A local account is just its name; a domain account is DOMAIN\\name, and
Win32-OpenSSH lowercases both before using the result as the default
comment's user part."
  (let ((buffer (cffi:foreign-alloc :unsigned-char :count 256)))
    (unwind-protect
         (let ((sid (windows-current-user-sid buffer)))
           (when sid
             (multiple-value-bind (name domain type)
                 (windows-sid-account sid)
               (declare (ignore type))
               (when name
                 (let ((computer (windows-computer-name)))
                   (string-downcase
                    (if (and domain computer (not (string-equal domain computer)))
                        (format nil "~A\\~A" domain name)
                        name)))))))
      (cffi:foreign-free buffer))))

(defun windows-acl-denies-private-access-p (owner-sid acl)
  "Whether OWNER-SID and ACL let anyone but the trusted accounts in."
  (let ((user-buffer (cffi:foreign-alloc :unsigned-char :count 256))
        (trusted-installer nil))
    (unwind-protect
         (let ((user-sid (windows-current-user-sid user-buffer)))
           (setf trusted-installer (windows-trusted-installer-sid))
           (block check
             (when (null user-sid)
               (return-from check t))
             (unless (or (plusp (c-is-well-known-sid
                                 owner-sid
                                 +windows-win-builtin-administrators-sid+))
                         (plusp (c-is-well-known-sid
                                 owner-sid +windows-win-local-system-sid+))
                         (plusp (c-equal-sid owner-sid user-sid))
                         (and trusted-installer
                              (plusp (c-equal-sid
                                      owner-sid trusted-installer))))
               (return-from check t))
             (multiple-value-bind (user-name user-domain user-type)
                 (windows-sid-account user-sid)
               (cffi:with-foreign-object (ace :pointer)
                 (dotimes (index
                           (cffi:mem-ref (cffi:inc-pointer acl 4)
                                         :unsigned-short))
                   (unless (plusp (c-get-ace acl index ace))
                     (return-from check t))
                   (let* ((entry (cffi:mem-ref ace :pointer))
                          (ace-type (cffi:mem-ref entry :unsigned-char))
                          ;; The trustee SID follows the ACE header: type,
                          ;; flags, size and mask.
                          (trustee (cffi:inc-pointer entry 8)))
                     (when (= ace-type +windows-access-allowed-ace-type+)
                       (unless
                           (or (plusp (c-is-well-known-sid
                                       trustee
                                       +windows-win-builtin-administrators-sid+))
                               (plusp (c-is-well-known-sid
                                       trustee +windows-win-local-system-sid+))
                               (plusp (c-equal-sid trustee user-sid))
                               (and trusted-installer
                                    (plusp (c-equal-sid
                                            trustee trusted-installer))))
                         ;; A SID history entry may name the same user
                         ;; under another SID, so compare resolved names.
                         (multiple-value-bind (name domain type)
                             (windows-sid-account trustee)
                           (unless (and user-name name
                                        (string-equal name user-name)
                                        (string-equal domain user-domain)
                                        (eql type user-type))
                             (return-from check t))))))))
               nil)))
      (when trusted-installer
        (c-local-free trusted-installer))
      (cffi:foreign-free user-buffer))))

(defun windows-acl-too-open-p (path)
  "Whether PATH's DACL breaks Win32-OpenSSH's private-file rules."
  (multiple-value-bind (path-pointer length)
      (windows-utf16-pointer (uiop:native-namestring path))
    (declare (ignore length))
    (unwind-protect
         (cffi:with-foreign-objects ((owner :pointer)
                                     (dacl :pointer)
                                     (descriptor :pointer))
           (setf (cffi:mem-ref owner :pointer) (cffi:null-pointer)
                 (cffi:mem-ref dacl :pointer) (cffi:null-pointer)
                 (cffi:mem-ref descriptor :pointer) (cffi:null-pointer))
           (if (plusp (c-get-named-security-info
                       path-pointer +windows-se-file-object+
                       (logior +windows-owner-security-information+
                               +windows-dacl-security-information+)
                       owner (cffi:null-pointer) dacl (cffi:null-pointer)
                       descriptor))
               ;; check_secure_file_permission() fails closed when it
               ;; cannot read the descriptor.
               t
               (unwind-protect
                    (let ((owner-sid (cffi:mem-ref owner :pointer))
                          (acl (cffi:mem-ref dacl :pointer)))
                      (or (zerop (c-is-valid-sid owner-sid))
                          (zerop (c-is-valid-acl acl))
                          (windows-acl-denies-private-access-p
                           owner-sid acl)))
                 (c-local-free (cffi:mem-ref descriptor :pointer)))))
      (cffi:foreign-free path-pointer))))

(defun windows-private-key-permissions-too-open-p (path)
  "Print ssh-keygen's warning and return T when PATH's ACL is too open."
  (when (handler-case (windows-acl-too-open-p path)
          (error () t))
    (format *error-output*
            "~A~%~A~%~A~%Permissions for '~A' are too open.~%~A~%~A~%"
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
            "@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @"
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
            (uiop:native-namestring path)
            "It is required that your private key files are NOT accessible by others."
            "This private key will be ignored.")
    t))
