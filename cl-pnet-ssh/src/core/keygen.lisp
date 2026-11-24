(in-package #:cl-pnet-ssh)

;;;; Key generation and OpenSSH key files.
;;;;
;;;; BURS KEYGEN builds on these functions.  A key made here is written in
;;;; OpenSSH's own formats, so ssh-keygen and sshd accept it, and a file made
;;;; by OpenSSH can be read back by SSH-LOAD-PRIVATE-KEY.  Everything is
;;;; plain Common Lisp over IRONCLAD-UNSAFE, so the same code runs on Linux,
;;;; FreeBSD and Windows.

(defparameter +ssh-keygen-default-rsa-bits+ 3072
  "The RSA size ssh-keygen generates when -b is not given.")

(defparameter +ssh-keygen-minimum-rsa-bits+ 1024
  "The smallest RSA modulus this generator will build.")

(defparameter +ssh-keygen-maximum-rsa-bits+ 16384
  "The largest RSA modulus this generator will build.")

(defparameter +ssh-keygen-default-cipher+ "aes256-ctr"
  "The cipher ssh-keygen uses for a passphrase-protected key.")

(defparameter +ssh-keygen-default-rounds+ 16
  "The bcrypt KDF rounds ssh-keygen uses by default.")

(defparameter +ssh-keygen-private-block-size+ 8
  "OpenSSH pads an unencrypted private section to this many octets.")

(defparameter +ssh-keygen-armor-width+ 70
  "The base64 line width ssh-keygen uses inside the private key armor.")

(defparameter +ssh-keygen-ecdsa-curves+
  '(("ecdsa-sha2-nistp256" :curve :secp256r1 :bits 256)
    ("ecdsa-sha2-nistp384" :curve :secp384r1 :bits 384)
    ("ecdsa-sha2-nistp521" :curve :secp521r1 :bits 521))
  "The ECDSA key types, Ironclad's curve, and the key size -l reports.")

(defun ssh-keygen-fail (format-string &rest arguments)
  (error 'ssh-keygen-error
         :detail (apply #'format nil format-string arguments)))

(defun ssh-normalize-key-type (type)
  "TYPE as one of the SSH type names KEYGEN understands.

Accepts both ssh-keygen's short spelling (ed25519, rsa) and the wire name
(ssh-ed25519, ssh-rsa).  ECDSA accepts the short name, a curve suffix, or
the full wire name."
  (let ((name (string-downcase (string type))))
    (cond
      ((string= name "ed25519") "ssh-ed25519")
      ((string= name "ssh-ed25519") "ssh-ed25519")
      ((string= name "rsa") "ssh-rsa")
      ((string= name "ssh-rsa") "ssh-rsa")
      ((string= name "mldsa44-ed25519") "ssh-mldsa44-ed25519")
      ((string= name "ssh-mldsa44-ed25519") "ssh-mldsa44-ed25519")
      ((string= name "ecdsa") "ecdsa-sha2-nistp256")
      ((member name '("ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384"
                      "ecdsa-sha2-nistp521")
               :test #'string=)
       name)
      ((member name '("nistp256" "nistp384" "nistp521") :test #'string=)
       (concatenate 'string "ecdsa-sha2-" name))
      (t
       (ssh-keygen-fail "unknown key type ~A" type)))))

(defun ssh-key-type-ecdsa-p (type)
  (and (> (length type) (length "ecdsa-sha2-"))
       (string= "ecdsa-sha2-" type :end2 (length "ecdsa-sha2-"))))

(defun ssh-key-type-ecdsa-curve (type)
  "The curve entry of an ECDSA key TYPE, or signal."
  (or (cdr (assoc type +ssh-keygen-ecdsa-curves+ :test #'string=))
      (ssh-keygen-fail "unsupported ECDSA key type ~A" type)))

(defun ssh-modular-inverse (value modulus)
  "VALUE's inverse modulo MODULUS, by the extended Euclidean algorithm."
  (let ((t0 1) (t1 0) (r0 (mod value modulus)) (r1 modulus))
    (loop while (plusp r1)
          do (let ((quotient (floor r0 r1)))
               (psetf r0 r1 r1 (- r0 (* quotient r1))
                      t0 t1 t1 (- t0 (* quotient t1)))))
    (unless (= r0 1)
      (ssh-keygen-fail "~A has no inverse modulo ~A" value modulus))
    (mod t0 modulus)))

(defun ssh-key-bits (key-blob)
  "The size ssh-keygen -l reports for KEY-BLOB."
  (multiple-value-bind (type data)
      (ssh-public-key-parts (ssh-key-plain-blob key-blob))
    (declare (ignore data))
    (cond
      ((string= type "ssh-rsa")
       (ssh-rsa-public-key-bits key-blob))
      ((string= type "ssh-ed25519") 256)
      ;; OpenSSH sizes the composite by its classical half.
      ((string= type "ssh-mldsa44-ed25519") 256)
      ((ssh-key-type-ecdsa-p type)
       (getf (ssh-key-type-ecdsa-curve type) :bits))
      (t 0))))

;;; ---- generating ----

(defun ssh-generate-rsa-private-key (num-bits comment)
  (let* ((bits (or num-bits +ssh-keygen-default-rsa-bits+))
         (bits (if (integerp bits) bits
                   (ssh-keygen-fail "Bits has bad value ~A (invalid)" num-bits))))
    (when (< bits +ssh-keygen-minimum-rsa-bits+)
      (ssh-keygen-fail "Invalid RSA key length: minimum is ~D bits"
                       +ssh-keygen-minimum-rsa-bits+))
    (when (> bits +ssh-keygen-maximum-rsa-bits+)
      (ssh-keygen-fail "Invalid RSA key length: maximum is ~D bits"
                       +ssh-keygen-maximum-rsa-bits+))
    (multiple-value-bind (private public)
        (ironclad-unsafe:generate-key-pair :rsa :num-bits bits)
      (let* ((e (getf (ironclad-unsafe:destructure-public-key public) :e))
             (n (getf (ironclad-unsafe:destructure-public-key public) :n))
             (d (getf (ironclad-unsafe:destructure-private-key private) :d))
             (p (getf (ironclad-unsafe:destructure-private-key private) :p))
             (q (getf (ironclad-unsafe:destructure-private-key private) :q))
             (iqmp (ssh-modular-inverse q p))
             (public-writer (ssh-writer))
             (private-writer (ssh-writer)))
        (ssh-write-mpint public-writer e)
        (ssh-write-mpint public-writer n)
        (ssh-write-mpint private-writer d)
        (ssh-write-mpint private-writer iqmp)
        (ssh-write-mpint private-writer p)
        (ssh-write-mpint private-writer q)
        (%make-ssh-private-key
         :type "ssh-rsa"
         :public (ssh-writer-output public-writer)
         :private (ssh-writer-output private-writer)
         :comment (or comment ""))))))

(defun ssh-generate-ecdsa-private-key (type num-bits comment)
  ;; ssh-keygen lets -b choose the curve even when -t names another one, so
  ;; `-t ecdsa-sha2-nistp256 -b 384' makes a 384-bit key.
  (let* ((name
           (if num-bits
               (cond
                 ((= num-bits 256) "ecdsa-sha2-nistp256")
                 ((= num-bits 384) "ecdsa-sha2-nistp384")
                 ((= num-bits 521) "ecdsa-sha2-nistp521")
                 (t (ssh-keygen-fail
                     "Invalid ECDSA key length: valid lengths are 256, 384 or 521 bits")))
               type))
         (curve (ssh-key-type-ecdsa-curve name)))
    (multiple-value-bind (private public)
        (ironclad-unsafe:generate-key-pair (getf curve :curve))
      (let ((x (getf (ironclad-unsafe:destructure-private-key private) :x))
            (point (getf (ironclad-unsafe:destructure-public-key public) :y))
            (writer (ssh-writer)))
        (ssh-write-mpint writer (ssh-mpint-integer x))
        (%make-ssh-private-key
         :type name
         :public point
         :private (ssh-writer-output writer)
         :comment (or comment ""))))))

(defun ssh-generate-ed25519-private-key (comment)
  (multiple-value-bind (private public)
      (ironclad-unsafe:generate-key-pair :ed25519)
    (let ((seed (getf (ironclad-unsafe:destructure-private-key private) :x))
          (public-bytes
            (getf (ironclad-unsafe:destructure-public-key public) :y)))
      ;; OpenSSH stores the seed and the public key, in that order.
      (%make-ssh-private-key
       :type "ssh-ed25519"
       :public (ssh-copy-octets public-bytes)
       :private (ssh-concat seed public-bytes)
       :comment (or comment "")))))

(defun ssh-generate-mldsa44-ed25519-private-key (comment)
  (let* ((mldsa-seed (ironclad-unsafe:random-data 32))
         (ed-seed (ironclad-unsafe:random-data 32)))
    (multiple-value-bind (mldsa-public secret)
        (ironclad-unsafe::ml-dsa-keygen-from-coins
         (ssh-copy-octets mldsa-seed)
         (ironclad-unsafe::ml-dsa-params-for-kind :ml-dsa-44))
      (declare (ignore secret))
      (let ((public (ssh-concat
                     mldsa-public
                     (ironclad-unsafe:ed25519-public-key
                      (ssh-copy-octets ed-seed))))
            (private (ssh-concat mldsa-seed ed-seed)))
        (%make-ssh-private-key
         :type "ssh-mldsa44-ed25519"
         :public public
         :private private
         :comment (or comment ""))))))

(defun ssh-generate-private-key (type &key num-bits comment)
  "A fresh SSH private KEY of TYPE.

TYPE is ssh-keygen's short spelling or the wire name; NUM-BITS chooses the
RSA size or the ECDSA curve.  The key can be written with
SSH-WRITE-PRIVATE-KEY and is otherwise identical to one read from a file."
  (let ((name (ssh-normalize-key-type type)))
    (cond
      ((string= name "ssh-ed25519")
       ;; ssh-keygen accepts -b for ed25519 and ignores it.
       (ssh-generate-ed25519-private-key comment))
      ((string= name "ssh-rsa")
       (ssh-generate-rsa-private-key num-bits comment))
      ((string= name "ssh-mldsa44-ed25519")
       (ssh-generate-mldsa44-ed25519-private-key comment))
      ((ssh-key-type-ecdsa-p name)
       (ssh-generate-ecdsa-private-key name num-bits comment))
      (t
       (ssh-keygen-fail "cannot generate a ~A key" type)))))

;;; ---- writing ----

(defun ssh-private-key-section (key &key encrypted)
  "The private section of KEY's openssh-key-v1 file, padded but not encrypted."
  (let* ((type (ssh-private-key-type key))
         (writer (ssh-writer))
         (check (ironclad-unsafe:strong-random #x100000000)))
    (ssh-write-u32 writer check)
    (ssh-write-u32 writer check)
    (ssh-write-text writer type)
    (cond
      ((string= type "ssh-ed25519")
       (let ((material (ssh-private-key-private key)))
         (unless (and (= (length material) 64)
                      (= (length (ssh-private-key-public key)) 32))
           (ssh-keygen-fail "the ed25519 key material is malformed"))
         ;; The private string is seed || public, and the public string
         ;; repeats the second half.
         (ssh-write-string writer (subseq material 32 64))
         (ssh-write-string writer material)))
      ((string= type "ssh-rsa")
       (multiple-value-bind (e n)
           (ssh-rsa-public-parameters (ssh-private-key-public key))
         (let ((reader (ssh-make-reader (ssh-private-key-private key))))
           ;; PROTOCOL.key writes n and e again, then the private half.
           (ssh-write-mpint writer n)
           (ssh-write-mpint writer e)
           (ssh-write-mpint writer (ssh-read-mpint reader)) ; d
           (ssh-write-mpint writer (ssh-read-mpint reader)) ; iqmp
           (ssh-write-mpint writer (ssh-read-mpint reader)) ; p
           (ssh-write-mpint writer (ssh-read-mpint reader))))) ; q
      ((string= type "ssh-mldsa44-ed25519")
       (ssh-write-string writer (ssh-private-key-public key))
       (ssh-write-string writer (ssh-private-key-private key)))
      ((ssh-key-type-ecdsa-p type)
       (let ((curve (subseq type (length "ecdsa-sha2-")))
             (reader (ssh-make-reader (ssh-private-key-private key))))
         (ssh-write-text writer curve)
         (ssh-write-string writer (ssh-private-key-public key))
         (ssh-write-mpint writer (ssh-read-mpint reader))))
      (t
       (ssh-keygen-fail "cannot write a ~A key" type)))
    (ssh-write-text writer (or (ssh-private-key-comment key) ""))
    (let* ((block (if encrypted 16 +ssh-keygen-private-block-size+))
           (length (length (ssh-writer-octets writer)))
           (padding (mod (- block length) block)))
      (dotimes (index padding)
        (ssh-write-u8 writer (1+ index))))
    (ssh-writer-output writer)))

(defun ssh-encrypt-private-section (section passphrase cipher-name rounds)
  "VALUES CIPHER-NAME KDF-NAME KDF-OPTIONS PAYLOAD for SECTION."
  (let* ((spec (ssh-openssh-key-cipher cipher-name))
         (key-length (second spec))
         (salt (ironclad-unsafe:random-data 16))
         (material
           (ironclad-unsafe:derive-key
            (make-instance 'ironclad-unsafe:bcrypt-pbkdf)
            (ssh-string-octets passphrase)
            salt rounds (+ key-length 16)))
         (cipher (ironclad-unsafe:make-cipher
                  :aes
                  :mode (third spec)
                  :key (subseq material 0 key-length)
                  :initialization-vector (subseq material key-length)))
         (options (ssh-writer)))
    (ssh-write-string options salt)
    (ssh-write-u32 options rounds)
    (values cipher-name
            "bcrypt"
            (ssh-writer-output options)
            (ironclad-unsafe:encrypt-message cipher section))))

(defun ssh-private-key-file-octets (key &key passphrase
                                         (cipher +ssh-keygen-default-cipher+)
                                         (rounds +ssh-keygen-default-rounds+))
  "KEY as the octets of an armored openssh-key-v1 file.

A non-empty PASSPHRASE encrypts the private half with CIPHER after ROUNDS of
bcrypt; an empty or missing one writes it in the clear, as ssh-keygen does."
  (let* ((encrypted (and (stringp passphrase) (plusp (length passphrase))))
         (section (ssh-private-key-section key :encrypted encrypted))
         (payload section)
         (cipher-name "none")
         (kdf-name "none")
         (kdf-options (make-array 0 :element-type '(unsigned-byte 8))))
    (when encrypted
      (multiple-value-setq (cipher-name kdf-name kdf-options payload)
        (ssh-encrypt-private-section section passphrase cipher rounds)))
    (let* ((writer (ssh-writer))
           (magic (map 'vector #'char-code +openssh-key-magic+)))
      (ssh-write-octets writer magic)
      (ssh-write-u8 writer 0)
      (ssh-write-text writer cipher-name)
      (ssh-write-text writer kdf-name)
      (ssh-write-string writer kdf-options)
      (ssh-write-u32 writer 1)
      (ssh-write-string writer (ssh-public-key-blob-of key))
      (ssh-write-string writer payload)
      (let* ((base64 (ssh-octets-base64 (ssh-writer-output writer)))
             (text (with-output-to-string (out)
                     (write-line "-----BEGIN OPENSSH PRIVATE KEY-----" out)
                     (loop for start from 0 below (length base64)
                           by +ssh-keygen-armor-width+
                           do (write-string
                               base64 out
                               :start start
                               :end (min (length base64)
                                         (+ start +ssh-keygen-armor-width+)))
                              (terpri out))
                     (write-line "-----END OPENSSH PRIVATE KEY-----" out))))
        (map 'vector #'char-code text)))))

(defun ssh-public-key-line (key &key comment)
  "The one-line public key for KEY, as ssh-keygen writes the .pub file."
  (let* ((blob (ssh-public-key-blob-of key))
         (type (nth-value 0 (ssh-public-key-parts blob)))
         (comment (or comment (ssh-private-key-comment key) "")))
    (format nil "~A ~A~@[ ~A~]~%"
            type
            (ssh-octets-base64 blob)
            (and (plusp (length comment)) comment))))

(defun ssh-write-octets-file (octets path)
  "Write OCTETS to PATH, replacing it.

Octets rather than characters keep the file byte-for-byte identical on
Windows, where a character stream would otherwise translate newlines."
  (with-open-file (stream path :direction :output
                               :if-exists :supersede
                               :if-does-not-exist :create
                               :element-type '(unsigned-byte 8))
    (write-sequence octets stream))
  path)

(defun ssh-secure-file-permissions (path mode)
  "Best-effort MODE on PATH.

OpenSSH refuses a private key that other users can read, so the file this
library writes must be 0600 before ssh-keygen or ssh looks at it.  Windows
has no POSIX mode bits; there the containing directory's ACL is what
protects the file."
  #+(and sbcl (not win32))
  (ignore-errors (sb-posix:chmod (uiop:native-namestring path) mode))
  #-(and sbcl (not win32))
  (declare (ignore path mode))
  (values))

(defun ssh-write-private-key (key path &key passphrase
                                          (cipher +ssh-keygen-default-cipher+)
                                          (rounds +ssh-keygen-default-rounds+))
  "Write KEY to PATH as an armored openssh-key-v1 file and return PATH."
  (ssh-write-octets-file
   (ssh-private-key-file-octets key
                                :passphrase passphrase
                                :cipher cipher
                                :rounds rounds)
   path)
  (ssh-secure-file-permissions path #o600)
  path)

(defun ssh-write-public-key (key path &key comment)
  "Write KEY's public line to PATH and return PATH."
  (ssh-write-octets-file
   (map 'vector #'char-code (ssh-public-key-line key :comment comment))
   path)
  (ssh-secure-file-permissions path #o644)
  path)
