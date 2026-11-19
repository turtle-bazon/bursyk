(in-package #:cl-pnet-ssh)

;;;; SSH key material: public key blobs, fingerprints, OpenSSH private keys.
;;;;
;;;; ssh-ed25519, RSA (ssh-rsa / rsa-sha2-256 / rsa-sha2-512) and the three
;;;; ECDSA curves are understood.  RSA matters because many existing accounts
;;;; have only ~/.ssh/id_rsa and some servers offer no ed25519 host key; ECDSA
;;;; matters because it is the other common host key type.

(defstruct (ssh-private-key (:constructor %make-ssh-private-key))
  (type nil :type (or null string))
  (public nil :type (or null ssh-octets))
  (private nil :type (or null ssh-octets))
  (comment "" :type string)
  ;; Where the key came from, when it came from a file.  The libssh backend
  ;; hands paths to libssh, so a parsed key is useful to it only with one.
  (path nil))

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
  "KEY-BLOB as (VALUES TYPE DATA), where DATA is the type-specific octets.

On the wire a public key is the type name followed by fields that differ by
type: ed25519 has one string, while ssh-rsa has two bare mpints and ECDSA has
a curve name and a point.  DATA is the decoded ed25519 key and, for the
others, the exact field octets after the type, so RSA and ECDSA verification
reads them as the protocol lays them out."
  (let* ((reader (ssh-make-reader key-blob))
         (type (ssh-read-text reader)))
    (values type
            (if (string= type "ssh-ed25519")
                (ssh-read-string reader)
                (ssh-read-octets reader (ssh-reader-remaining reader))))))

(defun ssh-make-public-key-blob (type data)
  "A public key blob from TYPE and its type-specific DATA.

DATA is the decoded ed25519 key; for RSA it is the e and n mpints and for
ECDSA the curve name and point strings, already encoded as the wire has
them.  Only ed25519 needs the extra string wrapper."
  (let ((writer (ssh-writer)))
    (ssh-write-text writer type)
    (if (string= type "ssh-ed25519")
        (ssh-write-string writer data)
        (ssh-write-octets writer data))
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

;;; ---- Integers, RSA signatures ----

(defun ssh-integer-octets (integer length)
  "INTEGER as exactly LENGTH big-endian octets, or signal when it overflows."
  (let ((out (make-array length :element-type '(unsigned-byte 8)
                                :initial-element 0))
        (value integer))
    (when (minusp value)
      (error 'ssh-protocol-error :detail "a negative integer has no encoding"))
    (loop for i downfrom (1- length) to 0
          while (plusp value)
          do (setf (aref out i) (ldb (byte 8 0) value)
                   value (ash value -8)))
    (when (plusp value)
      (error 'ssh-protocol-error
             :detail "an integer does not fit the requested width"))
    out))

(defparameter +ssh-rsa-digest-info+
  '((:sha256 . #(48 49 48 13 6 9 96 134 72 1 101 3 4 2 1 5 0 4 32))
    (:sha512 . #(48 81 48 13 6 9 96 134 72 1 101 3 4 2 3 5 0 4 64))
    (:sha1 . #(48 33 48 9 6 5 43 14 3 2 26 5 0 4 20)))
  "RFC 8017's DigestInfo prefix for the RSA signature digests used by SSH.")

(defun ssh-rsa-digest-keyword (algorithm)
  "The Ironclad digest keyword for an SSH RSA signature ALGORITHM."
  (cond
    ((string= algorithm "rsa-sha2-256") :sha256)
    ((string= algorithm "rsa-sha2-512") :sha512)
    ((string= algorithm "ssh-rsa") :sha1)
    (t nil)))

(defun ssh-rsa-signature-algorithm (digest)
  "The SSH signature algorithm name for DIGEST."
  (ecase digest
    (:sha256 "rsa-sha2-256")
    (:sha512 "rsa-sha2-512")
    (:sha1 "ssh-rsa")))

(defun ssh-rsa-emsa-pkcs1-v1-5 (digest message-octets modulus-octets)
  "EMSA-PKCS1-v1_5 encoding of the DIGEST of MESSAGE-OCTETS."
  (let* ((prefix (cdr (assoc digest +ssh-rsa-digest-info+)))
         (hash (ssh-hash digest message-octets))
         (t-length (+ (length prefix) (length hash)))
         (padding (- modulus-octets t-length 3)))
    (when (minusp padding)
      (error 'ssh-protocol-error
             :detail "the RSA key is too short for this digest"))
    (ssh-concat (make-array 2 :element-type '(unsigned-byte 8)
                              :initial-contents '(0 1))
                (make-array padding :element-type '(unsigned-byte 8)
                                    :initial-element #xFF)
                (make-array 1 :element-type '(unsigned-byte 8)
                              :initial-element 0)
                prefix hash)))

(defun ssh-rsa-public-parameters (key-data)
  "The (VALUES E N) inside an ssh-rsa public KEY-DATA."
  (let ((reader (ssh-make-reader key-data)))
    (values (ssh-read-mpint reader)
            (ssh-read-mpint reader))))

(defun ssh-rsa-private-parameters (private-key)
  "The (VALUES E N D IQMP P Q) of an OpenSSH RSA PRIVATE-KEY."
  (multiple-value-bind (e n) (ssh-rsa-public-parameters
                              (ssh-private-key-public private-key))
    (let ((reader (ssh-make-reader (ssh-private-key-private private-key))))
      ;; OpenSSH's order is d, iqmp, p, q.  IQMP is q^-1 mod p, which
      ;; Ironclad recomputes; it is returned so the caller can ignore it.
      (values e n
              (ssh-read-mpint reader)
              (ssh-read-mpint reader)
              (ssh-read-mpint reader)
              (ssh-read-mpint reader)))))

(defun ssh-rsa-sign (private-key message digest)
  "A PKCS#1 v1.5 RSA signature of MESSAGE under PRIVATE-KEY."
  (multiple-value-bind (e n d iqmp p q)
      (ssh-rsa-private-parameters private-key)
    (declare (ignore iqmp))
    (let* ((encoded (ssh-rsa-emsa-pkcs1-v1-5
                     digest message (ceiling (integer-length n) 8)))
           (key (ironclad-unsafe:make-private-key
                 :rsa :n n :e e :d d :p p :q q)))
      (ironclad-unsafe:sign-message key encoded))))

(defun ssh-rsa-signature-blob (private-key message digest)
  "The SSH RSA signature blob for MESSAGE under PRIVATE-KEY.

The signature is a string of exactly the modulus length, as OpenSSH emits
it; encoding it as an mpint would add a leading zero whenever the top bit is
set and some servers reject that non-canonical length."
  (let ((writer (ssh-writer))
        (signature (ssh-rsa-sign private-key message digest)))
    (ssh-write-text writer (ssh-rsa-signature-algorithm digest))
    (ssh-write-string writer signature)
    (ssh-writer-output writer)))

(defun ssh-rsa-verify (key-data signature digest message)
  "Whether SIGNATURE over MESSAGE verifies under an ssh-rsa KEY-DATA."
  (multiple-value-bind (e n) (ssh-rsa-public-parameters key-data)
    (let* ((modulus-octets (ceiling (integer-length n) 8))
           (encoded (ssh-rsa-emsa-pkcs1-v1-5
                     digest message modulus-octets))
           (raw (ssh-integer-octets
                 (ssh-mpint-integer signature) modulus-octets))
           (key (ironclad-unsafe:make-public-key :rsa :e e :n n)))
      (handler-case
          (ironclad-unsafe:verify-signature key encoded raw)
        (error () nil)))))

;;; ---- ECDSA signatures ----

(defun ssh-ecdsa-signature-elements (signature)
  "The (VALUES R S) octets inside an SSH ECDSA SIGNATURE.

RFC 5656 puts the two integers on the wire as two strings, not as the DER
encoding OpenSSL uses internally: string r then string s.  A leading zero
keeps an integer positive and is harmless to the conversion."
  (let ((reader (ssh-make-reader signature)))
    (let ((r (ssh-read-string reader))
          (s (ssh-read-string reader)))
      (unless (zerop (ssh-reader-remaining reader))
        (error 'ssh-protocol-error :detail "malformed ECDSA signature"))
      (values r s))))

(defparameter +ssh-ecdsa-curves+
  '(("nistp256" :curve :secp256r1 :size 32 :digest :sha256)
    ("nistp384" :curve :secp384r1 :size 48 :digest :sha384)
    ("nistp521" :curve :secp521r1 :size 66 :digest :sha512))
  "The ECDSA curves SSH names, with Ironclad's keyword, width and digest.")

(defun ssh-ecdsa-verify (key-data signature message)
  "Whether SIGNATURE over MESSAGE verifies under ECDSA KEY-DATA.

KEY-DATA holds the curve name and an uncompressed point; the curve selects
the Ironclad key and the hash.  SSH's ECDSA signature hashes MESSAGE (the
exchange hash or the userauth blob) again with the curve's digest, exactly
as OpenSSH's ssh_ecdsa_verify does.  The wire signature holds r and s as two
strings, while Ironclad wants a fixed-width r||s, so both are padded here."
  (multiple-value-bind (curve-name point)
      (let ((reader (ssh-make-reader key-data)))
        (values (ssh-read-text reader) (ssh-read-string reader)))
    (let ((curve (cdr (assoc curve-name +ssh-ecdsa-curves+ :test #'string=))))
      (unless curve
        (error 'ssh-protocol-error
               :detail (format nil "unsupported ECDSA curve ~A" curve-name)))
      (let ((size (getf curve :size)))
        (unless (and (= (length point) (1+ (* 2 size)))
                     (= (aref point 0) 4))
          (error 'ssh-protocol-error
                 :detail (format nil "expected an uncompressed ~A point"
                                 curve-name)))
        (multiple-value-bind (r s) (ssh-ecdsa-signature-elements signature)
          (let ((raw (ssh-concat
                      (ssh-integer-octets (ssh-mpint-integer r) size)
                      (ssh-integer-octets (ssh-mpint-integer s) size)))
                (digest (ssh-hash (getf curve :digest) message))
                (key (ironclad-unsafe:make-public-key
                      (getf curve :curve) :y point)))
            (handler-case
                (ironclad-unsafe:verify-signature key digest raw)
              (error () nil))))))))

;;; ---- Signing with a loaded key ----

(defun ssh-ecdsa-signature-blob (key message)
  "A signature blob of MESSAGE under an ECDSA private KEY.

The key file stores the scalar D and the public point; Ironclad signs the
curve digest of MESSAGE and returns r||s at the curve width, which goes out
as two mpints, the layout RFC 5656 names."
  (let* ((type (ssh-private-key-type key))
         (curve-name (subseq type (length "ecdsa-sha2-")))
         (curve (cdr (assoc curve-name +ssh-ecdsa-curves+ :test #'string=))))
    (unless curve
      (error 'ssh-authentication-error
             :detail (format nil "unsupported ECDSA curve ~A" curve-name)))
    (let ((private-half (ssh-private-key-private key))
          (public-point (ssh-private-key-public key)))
      (unless (and private-half public-point)
        (error 'ssh-authentication-error
               :detail "the ECDSA key has no private half to sign with"))
      (let* ((size (getf curve :size))
             (d (ssh-read-mpint (ssh-make-reader private-half)))
             (private (ironclad-unsafe:make-private-key
                       (getf curve :curve)
                       :x (ssh-integer-octets d size)
                       :y public-point))
             (raw (ironclad-unsafe:sign-message
                   private (ssh-hash (getf curve :digest) message)))
             (middle (/ (length raw) 2))
             (inner (ssh-writer))
             (outer (ssh-writer)))
        (ssh-write-mpint inner (ssh-mpint-integer (subseq raw 0 middle)))
        (ssh-write-mpint inner (ssh-mpint-integer (subseq raw middle)))
        (ssh-write-text outer type)
        (ssh-write-string outer (ssh-writer-output inner))
        (ssh-writer-output outer)))))

(defun ssh-private-key-signature-blob (key message)
  "A signature blob of MESSAGE under a loaded private KEY, or signal."
  (let ((type (ssh-private-key-type key)))
    (cond
      ((string= type "ssh-ed25519")
       (ssh-ed25519-signature-blob key message))
      ((and (> (length type) (length "ecdsa-sha2-"))
            (string= "ecdsa-sha2-" type
                     :end2 (length "ecdsa-sha2-")))
       (ssh-ecdsa-signature-blob key message))
      ((string= type "ssh-rsa")
       ;; rsa-sha2-256 is supported by every OpenSSH since 7.2, which is the
       ;; same floor that already requires rsa-sha2 for host keys.  Old
       ;; servers that only know ssh-rsa are rare and can still use the
       ;; agent or an explicit legacy path later.
       (ssh-rsa-signature-blob key message :sha256))
      (t
       (error 'ssh-authentication-error
              :detail (format nil "unsupported private key type ~A" type))))))

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
    (let ((key-type (ssh-read-text reader)))
      (unless (string= key-type type)
        (error 'ssh-protocol-error
               :detail (format nil "private key is ~A, header said ~A"
                               key-type type)))
      ;; The private section is laid out per key type: ed25519 holds two
      ;; octet strings, RSA holds the six mpints n, e, d, iqmp, p, q, and
      ;; ECDSA holds the public point then the private scalar.
      (cond
        ((string= key-type "ssh-ed25519")
         (let ((public (ssh-read-string reader))
               (private (ssh-read-string reader))
               (comment (ssh-read-text reader)))
           (%make-ssh-private-key :type key-type :public public
                                  :private private :comment comment)))
        ((string= key-type "ssh-rsa")
         (let ((n (ssh-read-mpint reader))
               (e (ssh-read-mpint reader))
               (d (ssh-read-mpint reader))
               (iqmp (ssh-read-mpint reader))
               (p (ssh-read-mpint reader))
               (q (ssh-read-mpint reader))
               (comment (ssh-read-text reader))
               (public-writer (ssh-writer))
               (private-writer (ssh-writer)))
           ;; The stored halves keep the layouts the rest of this file
           ;; reads: a public blob holds e then n, a private section holds
           ;; d, iqmp, p, q, exactly as OpenSSH writes them.
           (ssh-write-mpint public-writer e)
           (ssh-write-mpint public-writer n)
           (ssh-write-mpint private-writer d)
           (ssh-write-mpint private-writer iqmp)
           (ssh-write-mpint private-writer p)
           (ssh-write-mpint private-writer q)
           (%make-ssh-private-key
            :type key-type
            :public (ssh-writer-output public-writer)
            :private (ssh-writer-output private-writer)
            :comment comment)))
        ((and (> (length key-type) (length "ecdsa-sha2-"))
              (string= "ecdsa-sha2-" key-type
                       :end2 (length "ecdsa-sha2-")))
         ;; OpenSSH writes the curve name, the public point, then the
         ;; private scalar.  The curve in the section must match the one
         ;; the key type names.
         (let* ((curve (ssh-read-text reader))
                (expected (subseq key-type (length "ecdsa-sha2-")))
                (public (ssh-read-string reader))
                (d (ssh-read-mpint reader))
                (comment (ssh-read-text reader))
                (private-writer (ssh-writer)))
           (unless (string= curve expected)
             (error 'ssh-protocol-error
                    :detail (format nil "ECDSA key names ~A but holds ~A"
                                    expected curve)))
           (ssh-write-mpint private-writer d)
           (%make-ssh-private-key
            :type key-type :public public
            :private (ssh-writer-output private-writer)
            :comment comment)))
        (t
         (error 'ssh-protocol-error
                :detail (format nil "unsupported private key type ~A"
                                key-type)))))))

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
  "Load an OpenSSH PRIVATE-KEY from PATH.

PASSPHRASE decrypts a passphrase-protected file; an unencrypted file ignores
it.  ssh-ed25519, ssh-rsa and the ECDSA curves all sign here.  The file must
hold one key."
  (let* ((body (ssh-private-key-body (ssh-read-octets-file path)))
         (magic (ssh-check-key-magic body)))
    (declare (ignore magic))
    (let ((key (ssh-parse-openssh-private-key body :passphrase passphrase)))
      (setf (ssh-private-key-path key) path)
      key)))

(defun ssh-public-key-blob-of (private-key)
  "The public key blob of PRIVATE-KEY."
  (let ((type (ssh-private-key-type private-key)))
    (ssh-make-public-key-blob
     type
     (if (and (> (length type) (length "ecdsa-sha2-"))
              (string= "ecdsa-sha2-" type
                       :end2 (length "ecdsa-sha2-")))
         ;; An ECDSA public key is its curve name and point, both strings;
         ;; the private key stores only the point.
         (let ((writer (ssh-writer)))
           (ssh-write-text writer (subseq type (length "ecdsa-sha2-")))
           (ssh-write-string writer (ssh-private-key-public private-key))
           (ssh-writer-output writer))
         (ssh-private-key-public private-key)))))
