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

(defun ssh-parse-private-section (section type)
  "The key material in an unencrypted openssh-key-v1 private SECTION."
  (let* ((reader (ssh-make-reader section))
         (check-one (ssh-read-u32 reader))
         (check-two (ssh-read-u32 reader))
         (key-type (ssh-read-text reader))
         (public (ssh-read-string reader))
         (private (ssh-read-string reader))
         (comment (ssh-read-text reader)))
    (unless (= check-one check-two)
      (error 'ssh-protocol-error :detail "private key check values differ"))
    (unless (string= key-type type)
      (error 'ssh-protocol-error
             :detail (format nil "private key is ~A, header said ~A"
                             key-type type)))
    (%make-ssh-private-key :type key-type :public public
                           :private private :comment comment)))

(defun ssh-parse-openssh-private-key (body)
  "Parse an unencrypted openssh-key-v1 BODY."
  (let* ((header (+ (length +openssh-key-magic+) 1))
         (reader (ssh-make-reader body header))
         (cipher (ssh-read-text reader))
         (kdf (ssh-read-text reader))
         (kdf-options (ssh-read-string reader))
         (count (ssh-read-u32 reader))
         (public-blob (ssh-read-string reader))
         (section (ssh-read-string reader)))
    (declare (ignore kdf-options))
    (unless (string= cipher "none")
      (error 'ssh-protocol-error
             :detail "encrypted private keys are not supported"))
    (unless (string= kdf "none")
      (error 'ssh-protocol-error :detail "unsupported private key KDF"))
    (unless (= count 1)
      (error 'ssh-protocol-error :detail "a key file with several keys is unsupported"))
    (multiple-value-bind (type data) (ssh-public-key-parts public-blob)
      (declare (ignore data))
      (ssh-parse-private-section section type))))

(defun ssh-load-private-key (path)
  "Load an unencrypted OpenSSH ssh-ed25519 PRIVATE-KEY from PATH."
  (let* ((body (ssh-private-key-body (ssh-read-octets-file path)))
         (magic (ssh-check-key-magic body)))
    (declare (ignore magic))
    (ssh-parse-openssh-private-key body)))

(defun ssh-public-key-blob-of (private-key)
  "The public key blob of PRIVATE-KEY."
  (ssh-make-public-key-blob (ssh-private-key-type private-key)
                            (ssh-private-key-public private-key)))
