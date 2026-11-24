(in-package #:burs)

;;;; BURS KEYGEN -- key generation and key-file maintenance, the part of
;;;; ssh-keygen this client needs.
;;;;
;;;; The on-disk format lives in CL-PNET-SSH (SSH-GENERATE-PRIVATE-KEY,
;;;; SSH-WRITE-PRIVATE-KEY); this file is the command line: option parsing,
;;;; prompts, default file names, permissions and the messages ssh-keygen
;;;; prints.  Everything here is plain Common Lisp and UIOP, so the same
;;;; command runs on Linux, FreeBSD and Windows.

(defparameter +keygen-usage+
  "usage: burs keygen [-q] [-a rounds] [-b bits] [-C comment] [-f file]
                   [-N passphrase] [-t type] [-Z cipher]
       burs keygen -p [-a rounds] [-f file] [-N new] [-P old] [-Z cipher]
       burs keygen -y [-f file] [-P passphrase]
       burs keygen -l [-v] [-E hash] [-f file]
       burs keygen -B [-v] [-f file]
       burs keygen -c [-a rounds] [-C comment] [-f file] [-P passphrase]
       burs keygen -F hostname [-f known_hosts_file]"
  "The usage text, laid out like ssh-keygen's own synopsis.")

(defparameter +keygen-value-options+
  '(#\t #\b #\f #\N #\C #\P #\E #\Z #\a #\F)
  "The short options that take a value.")

(defparameter +keygen-flag-options+
  '(#\q #\y #\l #\p #\c #\B #\h #\v)
  "The short options that are switches.  ssh-keygen's -h means
host-certificate signing and is ignored outside -s, so it is accepted here
and does nothing; it is not help.  -v only adds the randomart picture to
fingerprint output.")

(defparameter +keygen-unsupported-options+
  '(#\A #\D #\H #\K #\Q #\R #\r #\s #\u #\V #\Y #\k #\e #\i
    #\m #\n #\w #\j #\I #\O #\S #\z)
  "ssh-keygen switches that belong to features this command does not have.")

(defparameter +keygen-ciphers+
  '("none" "3des-cbc"
    "aes128-ctr" "aes192-ctr" "aes256-ctr"
    "aes128-cbc" "aes192-cbc" "aes256-cbc"
    "aes128-gcm@openssh.com" "aes256-gcm@openssh.com"
    "chacha20-poly1305@openssh.com")
  "The ciphers an OpenSSH private key can use here.")

(defparameter +keygen-maximum-comment-length+ 2048
  "ssh-keygen's KEY_COMMENT_MAX less the terminating NUL.

ssh-keygen copies the comment into a NI_MAXHOST + 1024 byte buffer, so a
longer -C or typed comment is silently shortened.")

(defun keygen-clamp-comment (comment)
  (if (> (length comment) +keygen-maximum-comment-length+)
      (subseq comment 0 +keygen-maximum-comment-length+)
      comment))

(defun keygen-fail (format-string &rest arguments)
  (error (apply #'format nil format-string arguments)))

(define-condition keygen-usage-error (error)
  ((message :initarg :message :reader keygen-usage-error-message))
  (:report (lambda (condition stream)
             (write-string (keygen-usage-error-message condition) stream))))

(defun keygen-usage-fail (format-string &rest arguments)
  "Signal an error that ends like ssh-keygen's getopt: message and usage."
  (error 'keygen-usage-error
         :message (apply #'format nil format-string arguments)))

(defun keygen-print-usage ()
  (format *error-output* "~A~%" +keygen-usage+)
  (finish-output *error-output*))

(defun keygen-parse-bits (value)
  "VALUE as ssh-keygen reads -b, with its wording for a bad value.

ssh-keygen takes any unsigned 32-bit number here; the per-type limits are
checked later, so -b is meaningless for ed25519 and is not rejected."
  (let ((bits (handler-case (parse-integer value)
                (error ()
                  (keygen-fail "Bits has bad value ~A (invalid)" value)))))
    (when (< bits 1)
      (keygen-fail "Bits has bad value ~A (too small)" value))
    (when (> bits (1- (expt 2 32)))
      (keygen-fail "Bits has bad value ~A (too large)" value))
    bits))

(defun keygen-parse-rounds (value)
  "VALUE as ssh-keygen reads -a, with its wording for a bad value."
  (let ((rounds (handler-case (parse-integer value)
                  (error ()
                    (keygen-fail "Invalid number: ~A (invalid)" value)))))
    (when (< rounds 1)
      (keygen-fail "Invalid number: ~A (too small)" value))
    (when (> rounds (1- (expt 2 31)))
      (keygen-fail "Invalid number: ~A (too large)" value))
    rounds))

(defun keygen-set-value (options option value)
  (ecase option
    (#\t (setf (getf options :type) value))
    (#\b (setf (getf options :bits) (keygen-parse-bits value)))
    (#\f (setf (getf options :file) value))
    (#\N (setf (getf options :new-passphrase) value))
    (#\C (setf (getf options :comment) value))
    (#\P (setf (getf options :old-passphrase) value))
    (#\E (setf (getf options :hash)
               (cond
                 ((string-equal value "md5") :md5)
                 ((string-equal value "sha1") :sha1)
                 ((string-equal value "sha256") :sha256)
                 ((string-equal value "sha384") :sha384)
                 ((string-equal value "sha512") :sha512)
                 (t (keygen-fail "Invalid hash algorithm \"~A\"" value)))))
    (#\Z (unless (member value +keygen-ciphers+ :test #'string=)
            (keygen-fail "Invalid OpenSSH-format cipher '~A'" value))
          (setf (getf options :cipher) value))
    (#\a (setf (getf options :rounds) (keygen-parse-rounds value)))
    (#\F (setf (getf options :find-host) value))))

(defun keygen-parse-arguments (arguments)
  "The option plist for ARGUMENTS.

Short options may be clustered (-qy) and a value may be attached (-b3072)
or the next argument, as ssh-keygen's getopt does.  Anything left over is
ssh-keygen's \"Too many arguments.\" error; ssh-keygen's getopt permutes
non-option arguments, so one before an option does not stop the parse."
  (let ((options (list :type nil :bits nil :file nil :new-passphrase nil
                       :comment nil :old-passphrase nil :hash :sha256
                       :cipher nil :rounds nil :quiet nil :print-public nil
                       :fingerprint nil :change-passphrase nil
                       :change-comment nil :bubblebabble nil
                       :find-host nil :verbose nil))
        (remaining (copy-list arguments))
        (extras nil))
    (loop while remaining
          for argument = (pop remaining)
          do (cond
               ((string= argument "--")
                (setf extras (nconc extras remaining)
                      remaining nil))
               ((and (> (length argument) 1)
                     (char= (char argument 0) #\-))
                (loop with index = 1
                      while (< index (length argument))
                      for option = (char argument index)
                      do (cond
                           ((member option +keygen-value-options+)
                            (let ((value
                                    (if (< (1+ index) (length argument))
                                        (subseq argument (1+ index))
                                        (or (pop remaining)
                                            (keygen-usage-fail
                                             "option requires an argument -- ~C"
                                             option)))))
                              (keygen-set-value options option value))
                            (setf index (length argument)))
                           ((member option +keygen-flag-options+)
                            (ecase option
                              (#\q (setf (getf options :quiet) t))
                              (#\y (setf (getf options :print-public) t))
                              (#\l (setf (getf options :fingerprint) t))
                              (#\p (setf (getf options :change-passphrase) t))
                              (#\c (setf (getf options :change-comment) t))
                              (#\B (setf (getf options :bubblebabble) t))
                              (#\h nil)
                              (#\v (setf (getf options :verbose) t)))
                            (incf index))
                           ((member option +keygen-unsupported-options+)
                            (keygen-fail "-~A is not supported by burs keygen"
                                         option))
                           (t
                            (keygen-usage-fail "unknown option -- ~C"
                                               option)))))
               (t
                (push argument extras))))
    (when extras
      (keygen-usage-fail "Too many arguments."))
    options))

;;; ---- paths and names ----

(defun keygen-default-name (type)
  "The file ssh-keygen uses below ~/.ssh for TYPE."
  (let ((name (cl-pnet-ssh:ssh-normalize-key-type type)))
    (cond
      ((string= name "ssh-rsa") "id_rsa")
      ((string= name "ssh-ed25519") "id_ed25519")
      ((string= name "ssh-mldsa44-ed25519") "id_mldsa44_ed25519")
      (t "id_ecdsa"))))

(defun keygen-pathname (name)
  (uiop:parse-native-namestring name))

(defun keygen-empty-path-p (path)
  "Whether PATH names nothing, as -f \"\" does.

SBCL turns the empty string into the current directory, but open(\"\") fails
with ENOENT, so ssh-keygen reports an empty name as missing.  Every lookup
of a user-supplied path goes through KEYGEN-PROBE-FILE to get that wrong
answer right."
  (zerop (length (uiop:native-namestring path))))

(defun keygen-probe-file (path)
  "The truename of PATH, or NIL when it does not exist.

Unlike PROBE-FILE this does not turn the empty string into a directory."
  (unless (keygen-empty-path-p path)
    (probe-file path)))

(defun keygen-path (options &key (default-type "ed25519"))
  "The private key file the options select.

An explicit -f wins; otherwise ~/.ssh/ gets the type's usual name, with
ed25519 as the fallback for the operations ssh-keygen applies to an
existing key.  Whether a missing -f is asked for is up to the caller."
  (if (getf options :file)
      (keygen-pathname (getf options :file))
      (merge-pathnames (format nil ".ssh/~A"
                               (keygen-default-name
                                (or (getf options :type) default-type)))
                       (user-homedir-pathname))))

(defun keygen-ask-path (options &key (default-type "ed25519")
                                   (prompt "Enter file in which the key is"))
  "The key file for OPTIONS, asking like ssh-keygen when -f is absent.

The default path is printed in parentheses; an empty answer takes it and
end of input cancels the operation (NIL).  ssh-keygen writes this prompt to
standard output, so keep it out of the passphrase chatter on stderr."
  (if (getf options :file)
      (keygen-path options)
      (let* ((path (keygen-path options :default-type default-type))
             (native (uiop:native-namestring path)))
        (format t "~A (~A): " prompt native)
        (finish-output)
        (let ((line (read-prompt-line "")))
          (cond
            ((null line) nil)
            ((plusp (length line)) (keygen-pathname line))
            (t path))))))

(defun keygen-public-path (path)
  (keygen-pathname (concatenate 'string (uiop:native-namestring path) ".pub")))

(defun keygen-default-comment ()
  (format nil "~A@~A"
          (or (uiop:getenv "USER") (uiop:getenv "USERNAME") "user")
          (or (machine-instance) "localhost")))

(defun keygen-set-permissions (path mode)
  ;; Windows has no POSIX mode bits; the file is private by directory ACL.
  #+(and sbcl (not win32))
  (ignore-errors (sb-posix:chmod (uiop:native-namestring path) mode))
  #-(and sbcl (not win32))
  (declare (ignore path mode))
  (values))

;;; ---- prompts ----

(defun keygen-read-passphrase (prompt)
  "Read one passphrase, or \"\" at end of input.

ssh-keygen reads the answer from standard input even when it is a pipe, so
a script can answer the prompt; an empty answer asks for no encryption.
Typing is hidden only on a terminal, and only there does the read add the
newline the terminal is not echoing."
  (or (read-prompt-line prompt :echo (not (stdin-terminal-p))) ""))

(defun keygen-new-passphrase (options)
  ;; -p reads the new passphrase twice and gives up when they differ, with
  ;; ssh-keygen's own wording and status 1.
  (let ((given (getf options :new-passphrase)))
    (if (stringp given)
        given
        (let ((first (keygen-read-passphrase
                      "Enter new passphrase (empty for no passphrase): "))
              (second (keygen-read-passphrase
                       "Enter same passphrase again: ")))
          (unless (string= first second)
            (format t "Pass phrases do not match.  Try again.~%")
            (return-from keygen-new-passphrase nil))
          first))))

(defun keygen-generation-passphrase (options path)
  ;; Generation asks again until the two answers agree, and 10.6 names the
  ;; file it is about to write in the prompt.
  (let ((given (getf options :new-passphrase)))
    (if (stringp given)
        given
        (let ((prompt (format nil "Enter passphrase for \"~A\" (empty for no passphrase): "
                              (uiop:native-namestring path))))
          (loop
            (let ((first (keygen-read-passphrase prompt))
                  (second (keygen-read-passphrase
                           "Enter same passphrase again: ")))
              (if (string= first second)
                  (return first)
                  (format t "Passphrases do not match.  Try again.~%"))))))))

;;; ---- reading existing keys ----

(defun keygen-first-line (path)
  (unless (keygen-empty-path-p path)
    (with-open-file (stream path :direction :input
                                 :if-does-not-exist nil)
      (and stream (read-line stream nil nil)))))

(defun keygen-private-file-p (path)
  "Whether PATH's first line announces a private key.

ssh-keygen's -l only treats a file as private when its first line holds
\"PRIVATE KEY\", so an EC PARAMETERS block in front of an EC key makes -l
look for public keys instead, exactly as it does there."
  (let ((line (keygen-first-line path)))
    (and line
         (let ((trimmed (string-left-trim '(#\Space #\Tab) line)))
           (and (> (length trimmed) (length "-----BEGIN"))
                (string= "-----BEGIN" trimmed
                         :end2 (length "-----BEGIN"))
                (not (null (search "PRIVATE KEY" trimmed))))))))

(defun keygen-require-file (path)
  "Signal ssh-keygen's message when PATH does not exist."
  (unless (keygen-probe-file path)
    (keygen-fail "~A: No such file or directory"
                 (uiop:native-namestring path)))
  path)

(defun keygen-directory-p (path)
  (let ((truename (keygen-probe-file path)))
    (and truename (uiop:directory-pathname-p truename))))

(defun keygen-file-readable-p (path)
  "Whether PATH can be opened for reading, in the POSIX sense."
  #+(and sbcl (not win32))
  (ignore-errors
    (sb-posix:access (uiop:native-namestring path) sb-posix:r-ok))
  #-(and sbcl (not win32))
  t)

(defun keygen-load-failure-detail (path)
  "The ssh-keygen detail for a file that cannot be read as a key, or NIL.

The mode check in KEYGEN-PRIVATE-PERMISSIONS-TOO-OPEN-P runs first, exactly
as sshkey_perm_ok does, so a directory that the check catches is reported
as bad permissions; this only covers the paths that get past it."
  (cond
    ((keygen-directory-p path) "Is a directory")
    ((and (probe-file path) (not (keygen-file-readable-p path)))
     "Permission denied")
    (t nil)))

(defun keygen-file-error-detail (condition)
  "The strerror part of a CL FILE-ERROR, without its explanatory prefix."
  (let* ((text (format nil "~A" condition))
         (colon (search ": " text :from-end t)))
    (if colon (subseq text (+ colon 2)) text)))

(defun keygen-private-permissions-too-open-p (path)
  "Print ssh-keygen's warning and return T when PATH is too permissive.

OpenSSH checks the mode only for files the current user owns, and only on
systems with POSIX mode bits.  Windows has ACLs instead: Win32-OpenSSH
refuses a key whose DACL admits anyone but its owner, Administrators,
SYSTEM or TrustedInstaller, even read-only."
  #+win32
  (windows-private-key-permissions-too-open-p path)
  #+(and sbcl (not win32))
  (let ((stat (ignore-errors
               (sb-posix:stat (uiop:native-namestring path)))))
    (when (and stat
               (= (sb-posix:stat-uid stat) (sb-posix:getuid))
               (plusp (logand (sb-posix:stat-mode stat) #o077)))
      (format *error-output*
              "~A~%~A~%~A~%Permissions 0~3,'0O for '~A' are too open.~%~A~%~A~%"
              "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
              "@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @"
              "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
              (logand (sb-posix:stat-mode stat) #o777)
              (uiop:native-namestring path)
              "It is required that your private key files are NOT accessible by others."
              "This private key will be ignored.")
      t))
  #-(or win32 (and sbcl (not win32)))
  nil)

(defun keygen-load-key (path &key passphrase (prompt "Enter passphrase: ")
                                  (failure :cannot))
  "VALUES KEY PASSPHRASE-USED for the private key at PATH.

ssh-keygen first tries the empty passphrase, then the one -P or -N gives,
then reads PROMPT from standard input, even when that is a pipe.  FAILURE
picks its wording for the final error: :CANNOT for -c, :FAILED for -p and
:LOAD for -y.  PASSPHRASE-USED is the non-empty string the key was opened
with, or NIL when it was in the clear, so a rewrite can preserve it."
  (keygen-require-file path)
  (labels ((fail-with (detail)
             (let ((native (uiop:native-namestring path)))
               (keygen-fail
                "~A"
                (ecase failure
                  (:cannot
                   (format nil "Cannot load private key \"~A\": ~A"
                           native detail))
                  (:failed
                   (format nil "Failed to load key ~A: ~A" native detail))
                  (:load
                   (format nil "Load key \"~A\": ~A" native detail)))))))
    (when (keygen-private-permissions-too-open-p path)
      (fail-with "bad permissions"))
    (let ((unreadable (keygen-load-failure-detail path)))
      (when unreadable
        (fail-with unreadable)))
    (labels ((attempt (candidate)
               (handler-case
                   (values (cl-pnet-ssh:ssh-load-private-key
                            path :passphrase candidate)
                           (and (stringp candidate) (plusp (length candidate))
                                candidate))
                 (cl-pnet-ssh:ssh-authentication-error (condition)
                   ;; The wrong passphrase sends us back to the prompt; a
                   ;; structural problem is fatal, as in ssh-keygen.
                   (let ((detail (cl-pnet-ssh:ssh-error-detail condition)))
                     (if (or (search "incorrect passphrase supplied" detail)
                             (search "passphrase is required" detail))
                         (values nil detail)
                         (fail-with detail))))
                 (cl-pnet-ssh:ssh-protocol-error ()
                   (fail-with "invalid format"))
                 (file-error (condition)
                   (fail-with (keygen-file-error-detail condition)))
                 (error ()
                   (fail-with "invalid format"))))
             (report (detail)
               (fail-with detail)))
      (multiple-value-bind (key used) (attempt "")
        (if key
            (values key used)
            ;; An explicit -P or -N is used as given, even when it is the
            ;; empty string; only a missing one asks on standard input.
            (let ((candidate (if (stringp passphrase)
                                 passphrase
                                 (keygen-read-passphrase prompt))))
              (multiple-value-bind (key detail) (attempt candidate)
                (if key
                    (values key
                            (and (plusp (length candidate)) candidate))
                    (report detail)))))))))

(defun keygen-public-line-comment (line)
  (let* ((trimmed (string-trim '(#\Space #\Tab #\Return #\Newline) line))
         (first (position-if (lambda (character)
                               (member character '(#\Space #\Tab)))
                             trimmed))
         (second (and first
                      (position-if (lambda (character)
                                     (member character '(#\Space #\Tab)))
                                   trimmed :start (1+ first)))))
    (if second
        (string-trim '(#\Space #\Tab #\Return #\Newline)
                     (subseq trimmed (1+ second)))
        "")))

(defun keygen-line-key (line)
  "VALUES BLOB COMMENT for the key on one LINE, or NIL.

LINE may be a plain public key, an authorized_keys line that starts with
options, or a known_hosts line that starts with host patterns.  COMMENT is
the text after the base64 key, as in ssh-keygen; when there is none the
prefix ssh-keygen would have kept is used instead, and a bare key with no
comment returns NIL so the caller can print \"no comment\"."
  (let ((trimmed (string-trim '(#\Space #\Tab #\Return #\Newline) line)))
    (when (and (plusp (length trimmed))
               (not (member (char trimmed 0) '(#\# #\@))))
      (let ((fields (cl-pnet-ssh::ssh-authorized-key-line-fields trimmed)))
        (loop for rest on fields
              for index from 0
              for type = (first rest)
              for encoded = (second rest)
              while encoded
              do (let ((blob (handler-case
                                 (cl-pnet-ssh:ssh-base64-octets encoded)
                               (error () nil))))
                   (when blob
                     (multiple-value-bind (blob-type data)
                         (handler-case
                             (cl-pnet-ssh:ssh-public-key-parts blob)
                           (error () (values nil nil)))
                       (declare (ignore data))
                       (when (and blob-type (string= blob-type type))
                         (let* ((tail (cddr rest))
                                (tail-string
                                  (and tail (format nil "~{~A~^ ~}" tail))))
                           (return-from keygen-line-key
                             (values blob
                                     (cond
                                       ((and tail-string
                                             (plusp (length tail-string))
                                             (not (char= (char tail-string 0)
                                                         #\#)))
                                        tail-string)
                                       ((plusp index) (first fields))
                                       (t nil))))))))))))))

(defun keygen-public-file-keys (path)
  "A list of (BLOB COMMENT) for each key line in the file at PATH."
  (keygen-require-file path)
  (when (keygen-directory-p path)
    (keygen-fail "~A is not a public key file."
                 (uiop:native-namestring path)))
  (with-open-file (stream path :direction :input
                               :if-does-not-exist nil
                               :external-format :utf-8)
    (loop for line = (read-line stream nil nil)
          while line
          for key = (multiple-value-list (keygen-line-key line))
          when (first key) collect key)))

;;; ---- overwrite handling ----

(defun keygen-confirm-overwrite (path)
  "Ask before replacing PATH, as ssh-keygen does once.

Returns :YES or :NO.  The question goes to standard output and is asked
even when standard input is not a terminal; ssh-keygen treats both end of
input and any non-yes answer as a refusal and exits 1, so :NO covers both.
Only the private path matters: a stray .pub alone is simply rewritten."
  (let ((existing (keygen-probe-file path)))
    (if (not existing)
        :yes
        (progn
          (format t "~A already exists.~%Overwrite (y/n)? "
                  ;; ssh-keygen prints the name it was given, not the
                  ;; resolved path, so a relative -f stays relative.
                  (uiop:native-namestring path))
          (finish-output)
          (let* ((answer (read-prompt-line ""))
                 (trimmed (and answer
                               (string-trim
                                '(#\Space #\Tab #\Return #\Newline)
                                answer))))
            (if (and trimmed
                     (plusp (length trimmed))
                     (char-equal (char trimmed 0) #\y))
                :yes
                :no))))))

(defun keygen-prepare-directory (path quiet)
  "Create ~/.ssh when PATH belongs there, as ssh-keygen does.

Returns true when PATH's directory exists or was created.  ssh-keygen
creates no other missing directory, so saving elsewhere fails; the
\"Created directory\" notice is left out under -q."
  (let ((directory (uiop:ensure-directory-pathname
                    (uiop:pathname-directory-pathname path)))
        (ssh-directory
          (uiop:ensure-directory-pathname
           (merge-pathnames ".ssh/" (user-homedir-pathname)))))
    (cond
      ;; An empty -f names no file at all, so its directory is not the
      ;; current one; ssh-keygen fails at open() with ENOENT.
      ((keygen-empty-path-p path) nil)
      ((probe-file directory) t)
      ((uiop:pathname-equal directory ssh-directory)
       (ensure-directories-exist ssh-directory)
       ;; ssh refuses a group/world-accessible ~/.ssh, so match its mode.
       (keygen-set-permissions ssh-directory #o700)
       (unless quiet
         (format *error-output* "Created directory '~A'.~%"
                 (string-right-trim
                  (list #\/ #\\)
                  (uiop:native-namestring ssh-directory))))
       t)
      (t nil))))

;;; ---- operations ----

(defun keygen-check-type-and-bits (type bits)
  "Validate generation input and return TYPE's wire name.

The checks happen before the overwrite question, as ssh-keygen's do."
  (let ((name (cl-pnet-ssh:ssh-normalize-key-type type)))
    (when bits
      (cond
        ((string= name "ssh-rsa")
         (when (< bits cl-pnet-ssh:+ssh-keygen-minimum-rsa-bits+)
           (keygen-fail "Invalid RSA key length: minimum is ~D bits"
                        cl-pnet-ssh:+ssh-keygen-minimum-rsa-bits+))
         (when (> bits cl-pnet-ssh:+ssh-keygen-maximum-rsa-bits+)
           (keygen-fail "Invalid RSA key length: maximum is ~D bits"
                        cl-pnet-ssh:+ssh-keygen-maximum-rsa-bits+)))
        ((and (> (length name) (length "ecdsa-sha2-"))
              (string= "ecdsa-sha2-" name
                       :end2 (length "ecdsa-sha2-")))
         (unless (member bits '(256 384 521))
           (keygen-fail
            "Invalid ECDSA key length: valid lengths are 256, 384 or 521 bits")))))
    name))

(defun keygen-generate (options)
  (let* ((type (or (getf options :type)
                   ;; ssh-keygen's default stays ed25519 even when -b is
                   ;; given without -t; -b is then simply ignored.
                   "ed25519"))
         (bits (getf options :bits))
         (bits (getf options :bits))
         (comment (keygen-clamp-comment
                   (or (getf options :comment) (keygen-default-comment))))
         (quiet (getf options :quiet))
         (path nil))
    (keygen-check-type-and-bits type bits)
    (unless quiet
      ;; ssh-keygen echoes the -t spelling it was given.
      (format t "Generating public/private ~A key pair.~%" type))
    (setf path
          (or (keygen-ask-path options :default-type type
                               :prompt "Enter file in which to save the key")
              (return-from keygen-generate 1)))
    (let ((public (keygen-public-path path)))
    (unless (eq (keygen-confirm-overwrite path) :yes)
      (return-from keygen-generate 1))
    (unless (keygen-prepare-directory path quiet)
      ;; ssh-keygen only creates ~/.ssh; any other missing directory is
      ;; reported when the key cannot be saved.
      (format *error-output*
              "burs keygen: Saving key \"~A\" failed: No such file or directory~%"
              (uiop:native-namestring path))
      (return-from keygen-generate 1))
    (when (keygen-directory-p path)
      (format *error-output*
              "burs keygen: Saving key \"~A\" failed: Is a directory~%"
              (uiop:native-namestring path))
      (return-from keygen-generate 1))
    (let ((passphrase (keygen-generation-passphrase options path)))
      (let ((key (cl-pnet-ssh:ssh-generate-private-key
                  type :num-bits bits :comment comment)))
        (cl-pnet-ssh:ssh-write-private-key
         key path
         :passphrase passphrase
         :cipher (or (getf options :cipher)
                     cl-pnet-ssh:+ssh-keygen-default-cipher+)
         :rounds (or (getf options :rounds)
                             cl-pnet-ssh:+ssh-keygen-default-rounds+))
        (cl-pnet-ssh:ssh-write-public-key key public :comment comment)
        (keygen-set-permissions path #o600)
        (keygen-set-permissions public #o644)
        (unless quiet
          (format t "Your identification has been saved in ~A~%"
                  (uiop:native-namestring path))
          (format t "Your public key has been saved in ~A~%"
                  (uiop:native-namestring public))
          (let* ((blob (cl-pnet-ssh:ssh-public-key-blob-of key))
                 (fingerprint (cl-pnet-ssh:ssh-key-fingerprint blob)))
            (format t "The key fingerprint is:~%")
            (format t "~A ~A~%" fingerprint comment)
            (format t "The key's randomart image is:~%~A~%"
                    (cl-pnet-ssh:ssh-key-randomart blob))))))
      nil)))

(defun keygen-print-public (options)
  (let ((path (or (keygen-ask-path options)
                  (return-from keygen-print-public 1))))
    (let ((key (keygen-load-key path
                                :passphrase (getf options :old-passphrase)
                                :prompt
                                (format nil "Enter passphrase for \"~A\": "
                                        (uiop:native-namestring path))
                                :failure :load)))
      (format t "~A" (cl-pnet-ssh:ssh-public-key-line key))))
  nil)

(defun keygen-fingerprint-string (blob options)
  (if (getf options :bubblebabble)
      (cl-pnet-ssh:ssh-key-bubblebabble blob)
      (cl-pnet-ssh:ssh-key-fingerprint blob (or (getf options :hash) :sha256))))

(defun keygen-print-fingerprint (blob comment options)
  ;; ssh-keygen prints "no comment" when the file had no comment field at
  ;; all, but an empty comment from a private key prints as two spaces.
  (format t "~D ~A ~A (~A)~%"
          (cl-pnet-ssh:ssh-key-bits blob)
          (keygen-fingerprint-string blob options)
          (if comment comment "no comment")
          (cl-pnet-ssh:ssh-key-type-name blob))
  (when (getf options :verbose)
    (format t "~A~%"
            (cl-pnet-ssh:ssh-key-randomart
             blob (or (getf options :hash) :sha256)))))

(defun keygen-fingerprint-private-header (path options)
  "Fingerprint the private key at PATH without its .pub, as ssh-keygen -l does.

OpenSSH's fingerprint_private asks sshkey_load_public first: for an
openssh-key-v1 file that yields the cleartext public half, but never the
comment, so it tries the private half next, which supplies the comment and
also emits the too-open warning.  A PEM file gives sshkey_load_public
nothing, so only an unencrypted one can be read by the private attempt; any
failure there, whether from a passphrase, a bad mode or an unsupported
type, ends as \"is not a key file.\""
  (let ((native (uiop:native-namestring path)))
    (if (cl-pnet-ssh:ssh-private-key-file-openssh-p path)
        (let ((blob (cl-pnet-ssh:ssh-private-key-public-blob path))
              (comment nil))
          (unless (keygen-private-permissions-too-open-p path)
            (handler-case
                (let ((key (cl-pnet-ssh:ssh-load-private-key path)))
                  (setf comment
                        (or (cl-pnet-ssh:ssh-private-key-comment key) "")))
              (error () nil)))
          (keygen-print-fingerprint blob comment options))
        (progn
          (when (keygen-private-permissions-too-open-p path)
            (keygen-fail "~A is not a key file." native))
          (handler-case
              (let ((key (cl-pnet-ssh:ssh-load-private-key path)))
                (keygen-print-fingerprint
                 (cl-pnet-ssh:ssh-public-key-blob-of key) nil options))
            (error ()
              (keygen-fail "~A is not a key file." native)))))))

(defun keygen-fingerprint-private (path options)
  "Print fingerprints for the private key at PATH, as ssh-keygen -l does.

ssh-keygen reads PATH.pub when it exists and otherwise the unencrypted
public header of the private file, so -l never asks for a passphrase.  Only
a cleartext key contributes the comment carried in its private section."
  (let ((public (keygen-public-path path)))
    (if (probe-file public)
        (let ((keys (keygen-public-file-keys public)))
          (if keys
              (let ((comment (second (first keys))))
                (keygen-print-fingerprint
                 (first (first keys))
                 ;; ssh-keygen substitutes the .pub file name when the
                 ;; first line there has no comment of its own.
                 (if (plusp (length comment))
                     comment
                     (uiop:native-namestring public))
                 options))
              (keygen-fingerprint-private-header path options)))
        (keygen-fingerprint-private-header path options))))

(defun keygen-fingerprint (options)
  (let* ((path (or (keygen-ask-path options)
                   (return-from keygen-fingerprint 1)))
         (native (uiop:native-namestring path)))
    (keygen-require-file path)
    (cond
      ((keygen-directory-p path)
       (keygen-fail "~A is not a public key file." native))
      ((not (keygen-file-readable-p path))
       ;; do_fingerprint opens the file before it looks at it.
       (keygen-fail "~A: Permission denied" native))
      ((keygen-private-file-p path)
       (keygen-fingerprint-private path options))
      (t
       ;; One file can hold many keys: authorized_keys with options and
       ;; known_hosts with host patterns both list one key per line.
       (let ((keys (keygen-public-file-keys path)))
         (unless keys
           (keygen-fail "~A is not a public key file." native))
         (dolist (entry keys)
           (keygen-print-fingerprint (first entry) (second entry) options)))))
    nil))

(defun keygen-known-host-line-comment (line)
  "The comment after the base64 key on known_hosts LINE, or NIL.

The line is already trimmed, so what follows the key type and key is the
comment, with any inner spacing kept as OpenSSH keeps it."
  (let ((index 0)
        (length (length line)))
    (labels ((space-p (character)
               (member character '(#\Space #\Tab)))
             (skip-space ()
               (loop while (and (< index length)
                                (space-p (char line index)))
                     do (incf index)))
             (skip-field ()
               (loop while (and (< index length)
                                (not (space-p (char line index))))
                     do (incf index))))
      (skip-space)
      ;; A @cert-authority or @revoked marker comes before the hosts.
      (when (and (< index length) (char= (char line index) #\@))
        (skip-field)
        (skip-space))
      (skip-field)                     ; hosts
      (skip-space)
      (skip-field)                     ; key type
      (skip-space)
      (skip-field)                     ; base64 key
      (skip-space)
      (when (< index length)
        (subseq line index)))))

(defun keygen-find-host (options)
  "Print the known_hosts entries for -F HOST, as ssh-keygen -F does.

With -l the entry prints HOST TYPE FINGERPRINT [COMMENT] instead of the
whole line, and -B selects the Bubble Babble form of that fingerprint.
The \"# Host ... found\" line is left out under -q."
  (let* ((path (if (getf options :file)
                   (keygen-pathname (getf options :file))
                   (merge-pathnames ".ssh/known_hosts"
                                    (user-homedir-pathname))))
         (native (uiop:native-namestring path))
         (host (getf options :find-host))
         (found nil))
    (unless (keygen-probe-file path)
      (keygen-fail "Cannot stat ~A: No such file or directory" native))
    (dolist (entry (cl-pnet-ssh:ssh-load-known-hosts path))
      (when (cl-pnet-ssh::ssh-known-host-entry-matches-p entry host)
        (setf found t)
        (unless (getf options :quiet)
          (format t "# Host ~A found: line ~D ~A~%"
                  host
                  (cl-pnet-ssh::ssh-known-host-entry-line-number entry)
                  (let ((marker
                          (cl-pnet-ssh::ssh-known-host-entry-marker entry)))
                    (cond
                      ((equal marker "@cert-authority") "CA")
                      ((equal marker "@revoked") "REVOKED")
                      (t "")))))
        (if (getf options :fingerprint)
            (let* ((line (cl-pnet-ssh::ssh-known-host-entry-line entry))
                   (blob (cl-pnet-ssh::ssh-known-host-entry-key-blob entry))
                   (comment (keygen-known-host-line-comment line)))
              (format t "~A ~A ~A~@[ ~A~]~%"
                      host
                      (cl-pnet-ssh:ssh-key-type-name blob)
                      (keygen-fingerprint-string blob options)
                      (and comment (plusp (length comment)) comment))
              (when (getf options :verbose)
                (format t "~A~%"
                        (cl-pnet-ssh:ssh-key-randomart
                         blob (or (getf options :hash) :sha256)))))
            (format t "~A~%" (cl-pnet-ssh::ssh-known-host-entry-line entry)))))
    (if found 0 1)))

(defun keygen-change-passphrase (options)
  (let ((path (or (keygen-ask-path options)
                  (return-from keygen-change-passphrase 1))))
    (multiple-value-bind (key passphrase-used)
        (keygen-load-key path :passphrase (getf options :old-passphrase)
                              :prompt "Enter old passphrase: "
                              :failure :failed)
      (declare (ignore passphrase-used))
      ;; ssh-keygen prints this line even under -q, but only when the format
      ;; carried a comment; a PEM key has none.  The format is read only
      ;; after the key loaded, so a missing or unreadable file keeps
      ;; ssh-keygen's own error instead of a raw stream error.
      (when (cl-pnet-ssh:ssh-private-key-file-openssh-p path)
        (format t "Key has comment '~A'~%"
                (or (cl-pnet-ssh:ssh-private-key-comment key) "")))
      (let ((new (keygen-new-passphrase options)))
        (unless new
          (return-from keygen-change-passphrase 1))
        (cl-pnet-ssh:ssh-write-private-key
         key path
         :passphrase new
         :cipher (or (getf options :cipher)
                     cl-pnet-ssh:+ssh-keygen-default-cipher+)
         :rounds (or (getf options :rounds)
                             cl-pnet-ssh:+ssh-keygen-default-rounds+))
        (keygen-set-permissions path #o600)
        (format t "Your identification has been saved with the new passphrase.~%")))
    nil))

(defun keygen-change-comment (options)
  (let ((path (or (keygen-ask-path options)
                  (return-from keygen-change-comment 1))))
    ;; Like ssh-keygen, -N can name the passphrase that opens the key when
    ;; -P is absent (the first attempt is always with an empty passphrase).
    (multiple-value-bind (key passphrase-used)
        (keygen-load-key
         path
         :passphrase (or (getf options :old-passphrase)
                         (getf options :new-passphrase))
         :failure :cannot)
      ;; Only a key that loaded can be inspected for its format; reading the
      ;; file first would hide a missing or unreadable path behind a stream
      ;; error instead of ssh-keygen's message.
      (let* ((public (keygen-public-path path))
             (openssh (cl-pnet-ssh:ssh-private-key-file-openssh-p path))
             (old (or (cl-pnet-ssh:ssh-private-key-comment key) ""))
             (given (getf options :comment))
             (comment
               (keygen-clamp-comment
                (progn
                  (if openssh
                      (format t "Old comment: ~A~%" old)
                      (format t "No existing comment~%"))
                  (if (stringp given)
                      given
                      (progn
                        (format t "New comment: ")
                        (finish-output)
                        (let ((line (read-prompt-line "")))
                          (unless line
                            ;; End of input cancels the change, as it does in
                            ;; ssh-keygen, and leaves both files untouched.
                            (return-from keygen-change-comment 1))
                          line))))))
             ;; A -P given for an unencrypted key names no protection to
             ;; preserve; rewriting with it would silently encrypt the key.
             (passphrase
               (and (cl-pnet-ssh:ssh-private-key-file-encrypted-p path)
                    passphrase-used)))
        (when (and openssh (string= comment old))
          ;; ssh-keygen leaves both files alone and says so.  A PEM key has
          ;; no old comment to compare against, so it is always rewritten.
          (format t "No change to comment~%")
          (return-from keygen-change-comment 0))
        (setf (cl-pnet-ssh:ssh-private-key-comment key) comment)
        (cl-pnet-ssh:ssh-write-private-key
         key path
         :passphrase passphrase
         :cipher (or (getf options :cipher)
                     cl-pnet-ssh:+ssh-keygen-default-cipher+)
         :rounds (or (getf options :rounds)
                             cl-pnet-ssh:+ssh-keygen-default-rounds+))
        ;; ssh-keygen rewrites the .pub alongside the private file, even
        ;; when it was missing, and says so even under -q.
        (cl-pnet-ssh:ssh-write-public-key key public :comment comment)
        (keygen-set-permissions path #o600)
        (keygen-set-permissions public #o644)
        (if (plusp (length comment))
            (format t "Comment '~A' applied~%" comment)
            (format t "Comment removed~%"))))
    nil))

(defun keygen-run (arguments)
  (let ((options (keygen-parse-arguments arguments)))
    (cond
      ((getf options :find-host)
       (keygen-find-host options))
      ((or (getf options :fingerprint) (getf options :bubblebabble))
       (keygen-fingerprint options))
      ((and (getf options :change-passphrase)
            (getf options :change-comment))
       (format *error-output* "Can only have one of -p and -c.~%")
       (keygen-print-usage)
       1)
      ((getf options :change-passphrase)
       (keygen-change-passphrase options))
      ((getf options :change-comment)
       (keygen-change-comment options))
      ((getf options :print-public)
       (keygen-print-public options))
      (t
       (keygen-generate options)))))

(defun keygen-main (arguments)
  "Run `burs keygen ARGUMENTS` and return an exit status."
  (handler-case
      (or (keygen-run arguments) 0)
    (keygen-usage-error (condition)
      (format *error-output* "burs keygen: ~A~%"
              (keygen-usage-error-message condition))
      (keygen-print-usage)
      1)
    (cl-pnet-ssh:ssh-keygen-error (condition)
      (format *error-output* "burs keygen: ~A~%"
              (cl-pnet-ssh:ssh-error-detail condition))
      (finish-output *error-output*)
      255)
    (error (condition)
      (format *error-output* "burs keygen: ~A~%" condition)
      (finish-output *error-output*)
      255)))
