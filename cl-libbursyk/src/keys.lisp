(in-package #:cl-pnet-ssh)

;;;; SSH key material: public key blobs, fingerprints, OpenSSH private keys.
;;;;
;;;; Only the ssh-ed25519 key type is implemented. It is what OpenSSH
;;;; generates by default today, what fold's users have, and the type this
;;;; client advertises as its host key algorithm.

(defstruct (ssh-private-key (:constructor %make-ssh-private-key))
  (type nil :type (or null string))
  (public nil :type (or null ssh-octets))
  (private nil :type (or null ssh-octets))
  (comment "" :type string))

(defun ssh-read-octets-file (path)
  "PATH as octets, or signal."
  (with-open-file (stream path :direction :input
                               :element-type '(unsigned-byte 8)
                               :if-does-not-exist :error)
    (let ((out (make-array (file-length stream)
                           :element-type '(unsigned-byte 8))))
      (read-sequence out stream)
      out)))

(defun ssh-octets-base64 (octets)
  (cl-base64:usb8-array-to-base64-string octets))

(defun ssh-base64-octets (string)
  (cl-base64:base64-string-to-usb8-array string))

(defun ssh-key-fingerprint (key-blob)
  "OpenSSH's SHA256 fingerprint of KEY-BLOB: SHA256:base64, unpadded."
  (let* ((digest (ssh-hash :sha256 key-blob))
         (text (ssh-octets-base64 digest)))
    (concatenate 'string "SHA256:"
                 (string-right-trim '(#\=) text))))

(defun ssh-public-key-parts (key-blob)
  "KEY-BLOB as (VALUES TYPE DATA), where DATA is the type-specific octets."
  (let* ((reader (ssh-make-reader key-blob))
         (type (ssh-read-text reader)))
    (values type (ssh-read-string reader))))

(defun ssh-make-public-key-blob (type data)
  "A public key blob from TYPE and its type-specific DATA."
  (let ((writer (ssh-writer)))
    (ssh-write-text writer type)
    (ssh-write-string writer data)
    (ssh-writer-output writer)))

(defun ssh-ed25519-key-bytes (key-blob)
  "The 32-octet public key inside an ssh-ed25519 KEY-BLOB."
  (multiple-value-bind (type data) (ssh-public-key-parts key-blob)
    (unless (string= type "ssh-ed25519")
      (error 'ssh-protocol-error
             :detail (format nil "expected ssh-ed25519, got ~A" type)))
    (unless (= (length data) 32)
      (error 'ssh-protocol-error
             :detail "an ssh-ed25519 public key is 32 octets"))
    data))

(defun ssh-ed25519-sign (private-key message)
  "A 64-octet Ed25519 signature of MESSAGE by PRIVATE-KEY."
  (unless (string= (ssh-private-key-type private-key) "ssh-ed25519")
    (error 'ssh-protocol-error :detail "only ssh-ed25519 keys sign here"))
  (let* ((material (ssh-private-key-private private-key))
         (seed (subseq material 0 32))
         (public (subseq material 32 64))
         (key (ironclad-unsafe:make-private-key :ed25519
                                                :x (ssh-copy-octets seed)
                                                :y (ssh-copy-octets public))))
    (ironclad-unsafe:sign-message key (ssh-copy-octets message))))

(defun ssh-ed25519-signature-blob (private-key message)
  "The SSH signature blob (algorithm name and signature) of MESSAGE."
  (let ((writer (ssh-writer)))
    (ssh-write-text writer "ssh-ed25519")
    (ssh-write-string writer (ssh-ed25519-sign private-key message))
    (ssh-writer-output writer)))

;;; ---- OpenSSH private key files ----

(defparameter +openssh-key-magic+ "openssh-key-v1")

(defparameter +openssh-key-ciphers+
  '(("aes128-ctr" 16 :ctr)
    ("aes192-ctr" 24 :ctr)
    ("aes256-ctr" 32 :ctr)
    ("aes128-cbc" 16 :cbc)
    ("aes192-cbc" 24 :cbc)
    ("aes256-cbc" 32 :cbc))
  "Encrypted openssh-key-v1 ciphers: name, key octets, Ironclad mode.")

(defun ssh-find-octets (needle haystack &optional (start 0))
  (search needle haystack :start2 start :test #'=))

(defun ssh-private-key-body (file-octets)
  "The decoded openssh-key-v1 body inside an armored key FILE-OCTETS."
  (let* ((begin (ssh-find-octets
                 (map 'vector #'char-code
                      "-----BEGIN OPENSSH PRIVATE KEY-----")
                 file-octets))
         (end (ssh-find-octets
               (map 'vector #'char-code
                    "-----END OPENSSH PRIVATE KEY-----")
               file-octets)))
    (unless (and begin end (< begin end))
      (error 'ssh-protocol-error
             :detail "not an armored OpenSSH private key"))
    (let* ((start (+ begin (length "-----BEGIN OPENSSH PRIVATE KEY-----")))
           (text (map 'string #'code-char
                      (subseq file-octets start end))))
      (ssh-base64-octets text))))

(defun ssh-check-key-magic (body)
  "Signal unless BODY starts with the openssh-key-v1 magic."
  (let ((magic (map 'vector #'char-code +openssh-key-magic+)))
    (unless (ssh-octets= magic (subseq body 0 (length magic)))
      (error 'ssh-protocol-error
             :detail "unsupported private key format (expected openssh-key-v1)"))
    t))

(defun ssh-parse-private-section (section type &key encrypted)
  "The key material in an openssh-key-v1 private SECTION.

On a bad check value the key is either corrupt or was decrypted with the
wrong passphrase; ENCRYPTED selects which of the two to report."
  (let* ((reader (ssh-make-reader section))
         (check-one (ssh-read-u32 reader))
         (check-two (ssh-read-u32 reader)))
    (unless (= check-one check-two)
      (if encrypted
          (error 'ssh-authentication-error
                 :detail "the passphrase for the private key is wrong")
          (error 'ssh-protocol-error :detail "private key check values differ")))
    (let ((key-type (ssh-read-text reader))
          (public (ssh-read-string reader))
          (private (ssh-read-string reader))
          (comment (ssh-read-text reader)))
      (unless (string= key-type type)
        (error 'ssh-protocol-error
               :detail (format nil "private key is ~A, header said ~A"
                               key-type type)))
      (%make-ssh-private-key :type key-type :public public
                             :private private :comment comment))))

(defun ssh-openssh-key-cipher (name)
  "The cipher spec for NAME, or signal."
  (or (assoc name +openssh-key-ciphers+ :test #'string=)
      (error 'ssh-authentication-error
             :detail (format nil "unsupported encrypted key cipher ~A" name))))

(defun ssh-openssh-kdf-options (octets)
  "SALT and ROUNDS from an OpenSSH bcrypt KDF options string."
  (let ((reader (ssh-make-reader octets)))
    (values (ssh-read-string reader)
            (ssh-read-u32 reader))))

(defun ssh-decrypt-private-section (passphrase cipher-name kdf-name
                                    kdf-options section)
  "Decrypt SECTION, the private half of an encrypted openssh-key-v1 key."
  (unless passphrase
    (error 'ssh-authentication-error
           :detail "the private key is encrypted; a passphrase is required"))
  (unless (string= kdf-name "bcrypt")
    (error 'ssh-authentication-error
           :detail (format nil "unsupported private key KDF ~A" kdf-name)))
  (let* ((spec (ssh-openssh-key-cipher cipher-name))
         (key-length (second spec))
         (material
           (multiple-value-bind (salt rounds)
               (ssh-openssh-kdf-options kdf-options)
             (let ((derived
                     (ironclad-unsafe:derive-key
                      (make-instance 'ironclad-unsafe:bcrypt-pbkdf)
                      (ssh-string-octets passphrase)
                      salt rounds (+ key-length 16))))
               derived)))
         (cipher (ironclad-unsafe:make-cipher
                  :aes
                  :mode (third spec)
                  :key (subseq material 0 key-length)
                  :initialization-vector (subseq material key-length))))
    (ironclad-unsafe:decrypt-message cipher section)))

(defun ssh-parse-openssh-private-key (body &key passphrase)
  "Parse an openssh-key-v1 BODY, decrypting it with PASSPHRASE if needed."
  (let* ((header (+ (length +openssh-key-magic+) 1))
         (reader (ssh-make-reader body header))
         (cipher (ssh-read-text reader))
         (kdf (ssh-read-text reader))
         (kdf-options (ssh-read-string reader))
         (count (ssh-read-u32 reader))
         (public-blob (ssh-read-string reader))
         (raw-section (ssh-read-string reader))
         (encrypted (not (string= cipher "none")))
         (section
           (if encrypted
               (ssh-decrypt-private-section passphrase cipher kdf
                                            kdf-options raw-section)
               (progn
                 (unless (string= kdf "none")
                   (error 'ssh-protocol-error
                          :detail "unsupported private key KDF"))
                 raw-section))))
    (unless (= count 1)
      (error 'ssh-protocol-error :detail "a key file with several keys is unsupported"))
    (multiple-value-bind (type data) (ssh-public-key-parts public-blob)
      (declare (ignore data))
      (ssh-parse-private-section section type :encrypted encrypted))))

(defun ssh-load-private-key (path &key passphrase)
  "Load an OpenSSH ssh-ed25519 PRIVATE-KEY from PATH.

PASSPHRASE decrypts a passphrase-protected file; an unencrypted file ignores
it.  Only ed25519 keys are supported, and the file must hold one key."
  (let* ((body (ssh-private-key-body (ssh-read-octets-file path)))
         (magic (ssh-check-key-magic body)))
    (declare (ignore magic))
    (ssh-parse-openssh-private-key body :passphrase passphrase)))

(defun ssh-public-key-blob-of (private-key)
  "The public key blob of PRIVATE-KEY."
  (ssh-make-public-key-blob (ssh-private-key-type private-key)
                            (ssh-private-key-public private-key)))
