;;;; Windows account home directories.
;;;;
;;;; ssh's tilde_expand() calls getpwnam(), and Win32-OpenSSH answers that
;;;; from the registry: the account name is resolved to a SID, and
;;;; HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
;;;; ProfileList\<SID>\ProfileImagePath gives its profile directory, with
;;;; environment variables expanded.  A profile that cannot be read falls
;;;; back to the Windows directory, exactly as get_passwd() does.
;;;;
;;;; This component is built on Windows only.  The rest of the client keeps
;;;; using Lisp namestrings for paths, so the answer is normalised to that
;;;; spelling before it is returned.

(in-package #:cl-pnet-ssh)

(cffi:define-foreign-library cl-pnet-ssh-advapi32
  (:windows "advapi32.dll"))
(cffi:use-foreign-library cl-pnet-ssh-advapi32)

(cffi:define-foreign-library cl-pnet-ssh-kernel32
  (:windows "kernel32.dll"))
(cffi:use-foreign-library cl-pnet-ssh-kernel32)

(cffi:defcfun ("LookupAccountNameW" c-lookup-account-name) :int
  (system :pointer) (account :pointer)
  (sid :pointer) (sid-size :pointer)
  (domain :pointer) (domain-size :pointer) (use :pointer))

(cffi:defcfun ("ConvertSidToStringSidW" c-convert-sid-to-string) :int
  (sid :pointer) (string :pointer))

(cffi:defcfun ("RegOpenKeyExW" c-reg-open-key) :long
  (root :pointer) (subkey :pointer) (options :unsigned-long)
  (desired :unsigned-long) (result :pointer))

(cffi:defcfun ("RegQueryValueExW" c-reg-query-value) :long
  (key :pointer) (name :pointer) (reserved :pointer) (type :pointer)
  (data :pointer) (size :pointer))

(cffi:defcfun ("RegCloseKey" c-reg-close-key) :long (key :pointer))

(cffi:defcfun ("ExpandEnvironmentStringsW" c-expand-environment-strings)
    :unsigned-long
  (source :pointer) (target :pointer) (size :unsigned-long))

(cffi:defcfun ("GetWindowsDirectoryW" c-get-windows-directory)
    :unsigned-long
  (buffer :pointer) (size :unsigned-long))

(cffi:defcfun ("LocalFree" c-local-free) :pointer (memory :pointer))

(defconstant +hk-local-machine+ #x80000002)
(defconstant +key-read+ #x20019)
(defconstant +key-wow64-64key+ #x0100)
(defconstant +security-max-sid-size+ 68)
(defparameter +profile-list-path+
  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\")
(defparameter +profile-image-path+ "ProfileImagePath")

;;; ---- UTF-16 helpers ----

(defun windows-utf16-pointer (string)
  "A null-terminated UTF-16 copy of STRING, which the caller frees."
  (let* ((length (1+ (length string)))
         (pointer (cffi:foreign-alloc :unsigned-short :count length)))
    (loop for index below (length string)
          for code = (char-code (char string index))
          do (setf (cffi:mem-aref pointer :unsigned-short index)
                   (if (> code #xFFFF)
                       ;; Registry names are BMP in practice; substituting
                       ;; the replacement character is better than writing an
                       ;; out-of-range unit.
                       #xFFFD
                       code)))
    (setf (cffi:mem-aref pointer :unsigned-short (length string)) 0)
    pointer))

(defun windows-utf16-string (pointer length)
  "The first LENGTH UTF-16 units at POINTER as a Lisp string."
  (let ((string (make-array length :element-type 'character
                                   :adjustable t :fill-pointer 0)))
    (loop for index below length
          for code = (cffi:mem-aref pointer :unsigned-short index)
          until (zerop code)
          do (vector-push-extend (code-char code) string))
    (coerce string 'string)))

(defun windows-utf16-c-string (pointer)
  "The null-terminated UTF-16 string at POINTER as a Lisp string."
  (let ((length 0))
    (loop while (plusp (cffi:mem-aref pointer :unsigned-short length))
          do (incf length))
    (windows-utf16-string pointer length)))

;;; ---- Registry ----

(defun windows-profile-image-path (sid-text)
  "ProfileImagePath for SID-TEXT, or NIL when the key or value is absent."
  (multiple-value-bind (subkey subkey-length)
      (windows-utf16-pointer (concatenate 'string +profile-list-path+ sid-text))
    (declare (ignore subkey-length))
    (unwind-protect
         (cffi:with-foreign-object (key :pointer)
           (when (zerop (c-reg-open-key (cffi:make-pointer +hk-local-machine+)
                                        subkey 0
                                        (logior +key-read+ +key-wow64-64key+)
                                        key))
             (unwind-protect
                  (windows-profile-value (cffi:mem-ref key :pointer))
               (c-reg-close-key (cffi:mem-ref key :pointer)))))
      (cffi:foreign-free subkey))))

(defun windows-profile-value (key)
  "KEY's ProfileImagePath string, or NIL."
  (let ((buffer (cffi:foreign-alloc :unsigned-short :count 32768)))
    (unwind-protect
         (multiple-value-bind (name name-length)
             (windows-utf16-pointer +profile-image-path+)
           (declare (ignore name-length))
           (unwind-protect
                (cffi:with-foreign-objects ((type :unsigned-long)
                                            (size :unsigned-long))
                  (setf (cffi:mem-ref size :unsigned-long) (* 32768 2))
                  (when (zerop (c-reg-query-value key name (cffi:null-pointer)
                                                  type buffer size))
                    (windows-utf16-c-string buffer)))
             (cffi:foreign-free name)))
      (cffi:foreign-free buffer))))

(defun windows-expand-environment (text)
  "TEXT with %NAME% references expanded by the system, or TEXT."
  (multiple-value-bind (source source-length)
      (windows-utf16-pointer text)
    (declare (ignore source-length))
    (unwind-protect
         (let ((needed (c-expand-environment-strings
                        source (cffi:null-pointer) 0)))
           (if (zerop needed)
               text
               (let ((target (cffi:foreign-alloc :unsigned-short :count needed)))
                 (unwind-protect
                      (if (plusp (c-expand-environment-strings
                                  source target needed))
                          (windows-utf16-c-string target)
                          text)
                   (cffi:foreign-free target)))))
      (cffi:foreign-free source))))

(defun windows-directory ()
  "The Windows directory, used when a profile cannot be read."
  (let ((size (c-get-windows-directory (cffi:null-pointer) 0)))
    (when (plusp size)
      (let ((buffer (cffi:foreign-alloc :unsigned-short :count size)))
        (unwind-protect
             (when (plusp (c-get-windows-directory buffer size))
               (windows-utf16-c-string buffer))
          (cffi:foreign-free buffer))))))

;;; ---- The account lookup ----

(defun ssh-windows-user-home (user)
  "USER's profile directory as a namestring, or NIL when it is no account.

USER may be a local name, DOMAIN\\name or name@domain; LookupAccountName
accepts each form, and Win32-OpenSSH converts a slash-separated domain to
the backslash form first."
  (multiple-value-bind (name name-length)
      (windows-utf16-pointer (substitute #\\ #\/ user))
    (declare (ignore name-length))
    (unwind-protect
         (cffi:with-foreign-objects ((sid :unsigned-char
                                          +security-max-sid-size+)
                                     (sid-size :unsigned-long)
                                     (domain :unsigned-short 256)
                                     (domain-size :unsigned-long)
                                     (use :int))
           (setf (cffi:mem-ref sid-size :unsigned-long)
                 +security-max-sid-size+
                 (cffi:mem-ref domain-size :unsigned-long) 256)
           (when (plusp (c-lookup-account-name
                         (cffi:null-pointer) name
                         sid sid-size domain domain-size use))
             (cffi:with-foreign-object (string :pointer)
               (when (plusp (c-convert-sid-to-string sid string))
                 (unwind-protect
                      (let* ((sid-text
                               (windows-utf16-c-string
                                (cffi:mem-ref string :pointer)))
                             (home
                               (or (windows-profile-image-path sid-text)
                                   (windows-directory)))
                             (expanded
                               (and home (windows-expand-environment home))))
                        (when expanded
                          (namestring (pathname expanded))))
                   (c-local-free (cffi:mem-ref string :pointer)))))))
      (cffi:foreign-free name))))
