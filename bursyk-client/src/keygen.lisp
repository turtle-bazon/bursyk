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
  "usage: burs keygen [-q] [-t type] [-b bits] [-f file] [-N passphrase]
                   [-C comment] [-Z cipher] [-a rounds]
       burs keygen -y [-f file] [-P passphrase]
       burs keygen -l [-E md5|sha256] [-f file]
       burs keygen -p [-f file] [-P old] [-N new] [-a rounds]
       burs keygen -c [-f file] [-P passphrase] [-C comment]"
  "The usage text, laid out like ssh-keygen's own synopsis.")

(defparameter +keygen-value-options+
  '(#\t #\b #\f #\N #\C #\P #\E #\Z #\a)
  "The short options that take a value.")

(defparameter +keygen-flag-options+
  '(#\q #\y #\l #\p #\c)
  "The short options that are switches.  ssh-keygen has no -h for help; its
-h is host-certificate signing, which this command does not do.")

(defparameter +keygen-unsupported-options+
  '(#\A #\B #\D #\F #\H #\K #\Q #\R #\r #\s #\u #\V #\Y #\h #\k #\e #\i
    #\m #\n #\w #\j #\I #\O #\S #\z)
  "ssh-keygen switches that belong to features this command does not have.")

(defun keygen-fail (format-string &rest arguments)
  (error (apply #'format nil format-string arguments)))

(defun keygen-print-usage ()
  (format *error-output* "~A~%" +keygen-usage+)
  (finish-output *error-output*))

(defun keygen-parse-integer (option value)
  (handler-case
      (parse-integer value)
    (error ()
      (keygen-fail "~A needs an integer, not ~S" option value))))

(defun keygen-set-value (options option value)
  (ecase option
    (#\t (setf (getf options :type) (string-downcase value)))
    (#\b (setf (getf options :bits) (keygen-parse-integer "-b" value)))
    (#\f (setf (getf options :file) value))
    (#\N (setf (getf options :new-passphrase) value))
    (#\C (setf (getf options :comment) value))
    (#\P (setf (getf options :old-passphrase) value))
    (#\E (setf (getf options :hash)
               (cond
                 ((string-equal value "md5") :md5)
                 ((string-equal value "sha256") :sha256)
                 (t (keygen-fail "-E must be md5 or sha256, not ~S" value)))))
    (#\Z (setf (getf options :cipher) (string-downcase value)))
    (#\a (setf (getf options :rounds)
               (keygen-parse-integer "-a" value)))))

(defun keygen-parse-arguments (arguments)
  "The option plist for ARGUMENTS.

Short options may be clustered (-qy) and a value may be attached (-b3072)
or the next argument, as ssh-keygen's getopt does."
  (let ((options (list :type nil :bits nil :file nil :new-passphrase nil
                       :comment nil :old-passphrase nil :hash :sha256
                       :cipher nil :rounds nil :quiet nil :print-public nil
                       :fingerprint nil :change-passphrase nil
                       :change-comment nil :help nil))
        (remaining (copy-list arguments)))
    (loop while remaining
          for argument = (pop remaining)
          do (cond
               ((string= argument "--")
                (when remaining
                  (keygen-fail "unexpected argument ~S" (first remaining)))
                (return))
               ((string= argument "--help")
                (setf (getf options :help) t))
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
                                            (keygen-fail
                                             "option -~A requires a value"
                                             option)))))
                              (keygen-set-value options option value))
                            (setf index (length argument)))
                           ((member option +keygen-flag-options+)
                            (ecase option
                              (#\q (setf (getf options :quiet) t))
                              (#\y (setf (getf options :print-public) t))
                              (#\l (setf (getf options :fingerprint) t))
                              (#\p (setf (getf options :change-passphrase) t))
                              (#\c (setf (getf options :change-comment) t)))
                            (incf index))
                           ((member option +keygen-unsupported-options+)
                            (keygen-fail "-~A is not supported by burs keygen"
                                         option))
                           (t
                            (keygen-fail "unknown option -~A" option)))))
               (t
                (keygen-fail "unexpected argument ~S" argument))))
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

(defun keygen-short-type (type)
  "The name ssh-keygen prints when it announces a new TYPE."
  (let ((name (cl-pnet-ssh:ssh-normalize-key-type type)))
    (cond
      ((string= name "ssh-rsa") "rsa")
      ((string= name "ssh-ed25519") "ed25519")
      ((string= name "ssh-mldsa44-ed25519") "mldsa44-ed25519")
      (t "ecdsa"))))

(defun keygen-pathname (name)
  (uiop:parse-native-namestring name))

(defun keygen-path (options &key (default-type "rsa"))
  "The private key file the options select.

An explicit -f wins; otherwise ~/.ssh/ gets the type's usual name, with RSA
as the fallback for the operations ssh-keygen applies to an existing key."
  (if (getf options :file)
      (keygen-pathname (getf options :file))
      (merge-pathnames (format nil ".ssh/~A"
                               (keygen-default-name
                                (or (getf options :type) default-type)))
                       (user-homedir-pathname))))

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
  "Read one passphrase, or \"\" when stdin is not a terminal.

An empty answer is meaningful here: it asks for no encryption, exactly as
ssh-keygen's empty passphrase does."
  (if (stdin-terminal-p)
      (or (read-prompt-line prompt :echo nil) "")
      ""))

(defun keygen-new-passphrase (options)
  (let ((given (getf options :new-passphrase)))
    (if (stringp given)
        given
        (let ((first (keygen-read-passphrase
                      "Enter new passphrase (empty for no passphrase): ")))
          (unless (stdin-terminal-p)
            (return-from keygen-new-passphrase first))
          (let ((second (keygen-read-passphrase
                         "Enter same passphrase again: ")))
            (unless (string= first second)
              (keygen-fail "passphrases do not match"))
            first)))))

(defun keygen-generation-passphrase (options)
  (let ((given (getf options :new-passphrase)))
    (if (stringp given)
        given
        (if (not (stdin-terminal-p))
            ""
            (let ((first (keygen-read-passphrase
                          "Enter passphrase (empty for no passphrase): ")))
              (let ((second (keygen-read-passphrase
                             "Enter same passphrase again: ")))
                (unless (string= first second)
                  (keygen-fail "passphrases do not match"))
                first))))))

;;; ---- reading existing keys ----

(defun keygen-first-line (path)
  (with-open-file (stream path :direction :input
                               :if-does-not-exist nil)
    (and stream (read-line stream nil nil))))

(defun keygen-private-file-p (path)
  (let ((line (keygen-first-line path)))
    (and line
         (let ((trimmed (string-left-trim '(#\Space #\Tab) line)))
           (and (> (length trimmed) (length "-----BEGIN"))
                (string= "-----BEGIN" trimmed
                         :end2 (length "-----BEGIN")))))))

(defun keygen-prompt-passphrase (path)
  (format *error-output* "Enter passphrase for key '~A': "
          (uiop:native-namestring path))
  (finish-output *error-output*)
  (keygen-read-passphrase ""))

(defun keygen-load-key (path &key passphrase)
  "VALUES KEY PASSPHRASE-USED for the private key at PATH.

A missing passphrase for an encrypted key is prompted for once; a wrong one
is an error, so a typo cannot silently rewrite the key.  PASSPHRASE-USED is
the non-empty string the key was decrypted with, or NIL when it was in the
clear, so a rewrite can preserve the protection."
  (handler-case
      (values (cl-pnet-ssh:ssh-load-private-key path :passphrase passphrase)
              (and (stringp passphrase) (plusp (length passphrase))
                   passphrase))
    (cl-pnet-ssh:ssh-authentication-error (condition)
      (let ((message (cl-pnet-ssh:ssh-error-detail condition)))
        (when (and (stringp passphrase) (plusp (length passphrase)))
          (keygen-fail "~A" message))
        (unless (stdin-terminal-p)
          (keygen-fail "~A" message))
        (let ((entered (keygen-prompt-passphrase path)))
          (values (cl-pnet-ssh:ssh-load-private-key path
                                                    :passphrase entered)
                  (and (plusp (length entered)) entered)))))))

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

(defun keygen-file-blob-and-comment (path &key passphrase)
  "VALUES BLOB COMMENT for the key file at PATH, private or public."
  (if (keygen-private-file-p path)
      (let ((key (keygen-load-key path :passphrase passphrase)))
        (values (cl-pnet-ssh:ssh-public-key-blob-of key)
                (or (cl-pnet-ssh:ssh-private-key-comment key) "")))
      (let ((line (keygen-first-line path)))
        (unless line
          (keygen-fail "~A is not a key file" (uiop:native-namestring path)))
        (let ((blob (cl-pnet-ssh:ssh-authorized-key-line-blob line)))
          (unless blob
            (keygen-fail "~A is not a key file" (uiop:native-namestring path)))
          (values blob (keygen-public-line-comment line))))))

;;; ---- overwrite handling ----

(defun keygen-confirm-overwrite (path &optional public)
  "Ask before replacing PATH or its PUBLIC half, as ssh-keygen does once."
  (let ((existing (or (probe-file path)
                      (and public (probe-file public)))))
    (when existing
      (if (not (stdin-terminal-p))
          (keygen-fail "~A already exists" (uiop:native-namestring existing))
          (let ((answer
                  (read-prompt-line
                   (format nil "~A already exists. Overwrite (y/n)? "
                           (uiop:native-namestring existing)))))
            (unless (and answer
                         (plusp (length answer))
                         (char-equal (char (string-trim
                                            '(#\Space #\Tab #\Return #\Newline)
                                            answer)
                                           0)
                                     #\y))
              (keygen-fail "not overwriting ~A"
                           (uiop:native-namestring existing))))))))

(defun keygen-prepare-directory (path)
  (let ((directory (uiop:pathname-directory-pathname path)))
    (unless (probe-file directory)
      (ensure-directories-exist path)
      ;; ssh refuses a group/world-accessible ~/.ssh, so match its mode.
      (keygen-set-permissions directory #o700))))

;;; ---- operations ----

(defun keygen-generate (options)
  (let* ((type (or (getf options :type) "ed25519"))
         (path (keygen-path options :default-type type))
         (public (keygen-public-path path))
         (comment (or (getf options :comment) (keygen-default-comment)))
         (quiet (getf options :quiet))
         (passphrase (keygen-generation-passphrase options)))
    (keygen-confirm-overwrite path public)
    (keygen-prepare-directory path)
    (unless quiet
      (format t "Generating public/private ~A key pair.~%"
              (keygen-short-type type)))
    (let ((key (cl-pnet-ssh:ssh-generate-private-key
                type :num-bits (getf options :bits) :comment comment)))
      (cl-pnet-ssh:ssh-write-private-key
       key path
       :passphrase passphrase
       :cipher (or (getf options :cipher)
                   cl-pnet-ssh:+ssh-keygen-default-cipher+)
       :rounds (or (getf options :rounds) 16))
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
                  (cl-pnet-ssh:ssh-key-randomart blob)))))
    (values)))

(defun keygen-print-public (options)
  (let ((path (keygen-path options)))
    (let ((key (keygen-load-key path
                                :passphrase (getf options :old-passphrase))))
      (format t "~A" (cl-pnet-ssh:ssh-public-key-line key)))))

(defun keygen-fingerprint (options)
  (let* ((path (keygen-path options))
         (hash (or (getf options :hash) :sha256)))
    (multiple-value-bind (blob comment)
        (keygen-file-blob-and-comment
         path :passphrase (getf options :old-passphrase))
      ;; ssh-keygen prints "no comment" rather than two spaces when the
      ;; file has no comment.
      (format t "~D ~A ~A (~A)~%"
              (cl-pnet-ssh:ssh-key-bits blob)
              (cl-pnet-ssh:ssh-key-fingerprint blob hash)
              (if (plusp (length comment)) comment "no comment")
              (cl-pnet-ssh:ssh-key-type-name blob)))))

(defun keygen-change-passphrase (options)
  (let* ((path (keygen-path options))
         (quiet (getf options :quiet)))
    (multiple-value-bind (key passphrase-used)
        (keygen-load-key path :passphrase (getf options :old-passphrase))
      (declare (ignore passphrase-used))
      (let ((new (keygen-new-passphrase options)))
        (cl-pnet-ssh:ssh-write-private-key
         key path
         :passphrase new
         :cipher (or (getf options :cipher)
                     cl-pnet-ssh:+ssh-keygen-default-cipher+)
         :rounds (or (getf options :rounds) 16))
        (keygen-set-permissions path #o600)
        (unless quiet
          (format t "Your identification has been saved with the new passphrase.~%"))))
    (values)))

(defun keygen-change-comment (options)
  (let* ((path (keygen-path options))
         (public (keygen-public-path path)))
    (multiple-value-bind (key passphrase-used)
        (keygen-load-key path :passphrase (getf options :old-passphrase))
      (let ((comment
              (or (getf options :comment)
                  (if (stdin-terminal-p)
                      (or (read-prompt-line "Enter new comment: ") "")
                      (keygen-fail "no comment given; use -C"))))
            ;; A -P given for an unencrypted key names no protection to
            ;; preserve; rewriting with it would silently encrypt the key.
            (passphrase
              (and (cl-pnet-ssh:ssh-private-key-file-encrypted-p path)
                   passphrase-used))
            (old (cl-pnet-ssh:ssh-private-key-comment key)))
        (setf (cl-pnet-ssh:ssh-private-key-comment key) comment)
        (cl-pnet-ssh:ssh-write-private-key
         key path
         :passphrase passphrase
         :cipher (or (getf options :cipher)
                     cl-pnet-ssh:+ssh-keygen-default-cipher+)
         :rounds (or (getf options :rounds) 16))
        ;; ssh-keygen rewrites the .pub alongside the private file, even
        ;; when it was missing, and says so even under -q.
        (cl-pnet-ssh:ssh-write-public-key key public :comment comment)
        (keygen-set-permissions path #o600)
        (keygen-set-permissions public #o644)
        (format t "Old comment: ~A~%" old)
        (if (plusp (length comment))
            (format t "Comment '~A' applied~%" comment)
            (format t "Comment removed~%"))))
    (values)))

(defun keygen-run (arguments)
  (let ((options (keygen-parse-arguments arguments)))
    (when (getf options :help)
      (keygen-print-usage)
      (return-from keygen-run 0))
    (cond
      ((getf options :change-passphrase)
       (keygen-change-passphrase options))
      ((getf options :change-comment)
       (keygen-change-comment options))
      ((getf options :print-public)
       (keygen-print-public options))
      ((getf options :fingerprint)
       (keygen-fingerprint options))
      (t
       (keygen-generate options)))
    0))

(defun keygen-main (arguments)
  "Run `burs keygen ARGUMENTS` and return an exit status."
  (handler-case
      (keygen-run arguments)
    (cl-pnet-ssh:ssh-keygen-error (condition)
      (format *error-output* "burs keygen: ~A~%"
              (cl-pnet-ssh:ssh-error-detail condition))
      (finish-output *error-output*)
      1)
    (error (condition)
      (format *error-output* "burs keygen: ~A~%" condition)
      (finish-output *error-output*)
      1)))
