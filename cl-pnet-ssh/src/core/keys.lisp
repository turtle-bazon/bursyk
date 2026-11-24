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

(defstruct (ssh-agent-host-key (:constructor %make-ssh-agent-host-key))
  "A host key whose private half lives in an ssh-agent."
  (blob nil :type (or null ssh-octets))
  (type nil :type (or null string))
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

(defun ssh-key-fingerprint (key-blob &optional (hash :sha256))
  "OpenSSH's fingerprint of KEY-BLOB.

HASH is :SHA256 for the modern SHA256:base64 form, or :MD5 for the legacy
MD5:aa:bb:... form.  A certificate is fingerprinted through its plain key,
as OpenSSH's sshkey_fingerprint does with force_plain."
  (let ((digest (ssh-hash hash (ssh-key-plain-blob key-blob))))
    (ecase hash
      (:sha256
       (concatenate 'string "SHA256:"
                    (string-right-trim
                     '(#\=) (ssh-octets-base64 digest))))
      (:md5
       ;; ssh-keygen prints the hexadecimal groups in lower case; FORMAT's
       ;; ~X directive is upper case on some implementations even with a
       ;; lower-case directive, so normalise here.
       (concatenate
        'string "MD5:"
        (string-downcase
         (format nil "~{~2,'0x~^:~}" (coerce digest 'list))))))))

(defparameter +bubblebabble-vowels+ "aeiouy"
  "The vowels in OpenSSH's Bubble Babble alphabet.")

(defparameter +bubblebabble-consonants+ "bcdfghklmnprstvzx"
  "The consonants in OpenSSH's Bubble Babble alphabet.")

(defun ssh-key-bubblebabble (key-blob)
  "OpenSSH's Bubble Babble SHA1 fingerprint of KEY-BLOB.

This is the `xigak-nyryk-humil-bosek-sonax' form ssh-keygen -B prints.
The seed carried between octet pairs is the checksum that makes a typo
show up as a word that does not decode back to the digest."
  (let* ((digest (ssh-hash :sha1 (ssh-key-plain-blob key-blob)))
         (length (length digest))
         (rounds (1+ (floor length 2)))
         (output (make-string-output-stream))
         (seed 1))
    (write-char #\x output)
    (dotimes (index rounds)
      (if (or (< (1+ index) rounds) (oddp length))
          (let* ((byte (aref digest (* 2 index)))
                 (first (mod (+ (ldb (byte 2 6) byte) seed) 6))
                 (middle (ldb (byte 4 2) byte))
                 (last (mod (+ (ldb (byte 2 0) byte) (floor seed 6)) 6)))
            (write-char (char +bubblebabble-vowels+ first) output)
            (write-char (char +bubblebabble-consonants+ middle) output)
            (write-char (char +bubblebabble-vowels+ last) output)
            (when (< (1+ index) rounds)
              (let ((next (aref digest (1+ (* 2 index)))))
                (write-char (char +bubblebabble-consonants+
                                  (ldb (byte 4 4) next))
                            output)
                (write-char #\- output)
                (write-char (char +bubblebabble-consonants+
                                  (ldb (byte 4 0) next))
                            output)
                (setf seed (mod (+ (* seed 5) (* byte 7) next) 36)))))
          (progn
            (write-char (char +bubblebabble-vowels+ (mod seed 6)) output)
            (write-char (char +bubblebabble-consonants+ 16) output)
            (write-char (char +bubblebabble-vowels+ (floor seed 6)) output))))
    (write-char #\x output)
    (get-output-stream-string output)))

(defun ssh-key-randomart-title (key-blob)
  "The [TYPE SIZE] title OpenSSH puts over a randomart field."
  (multiple-value-bind (type data)
      (ssh-public-key-parts (ssh-key-plain-blob key-blob))
    (declare (ignore data))
    (let ((name (cond
                  ((string= type "ssh-ed25519") "ED25519")
                  ((string= type "ssh-mldsa44-ed25519") "MLDSA44-ED25519")
                  ((string= type "ssh-rsa") "RSA")
                  ((member type '("ecdsa-sha2-nistp256"
                                  "ecdsa-sha2-nistp384"
                                  "ecdsa-sha2-nistp521")
                           :test #'string=)
                   "ECDSA")
                  (t (string-upcase type))))
          (size (cond
                  ((string= type "ssh-ed25519") 256)
                  ((string= type "ssh-mldsa44-ed25519") 512)
                  ((string= type "ssh-rsa")
                   (ssh-rsa-public-key-bits key-blob))
                  ((string= type "ecdsa-sha2-nistp256") 256)
                  ((string= type "ecdsa-sha2-nistp384") 384)
                  ((string= type "ecdsa-sha2-nistp521") 521)
                  (t 0))))
      (when (and (ssh-certificate-blob-p key-blob)
                 (not (search "-CERT" name)))
        (setf name (concatenate 'string name "-CERT")))
      (format nil "[~A~@[ ~D~]]" name size))))

(defun ssh-key-randomart (key-blob &optional (hash :sha256))
  "OpenSSH's randomart picture of KEY-BLOB's HASH digest."
  (let* ((digest (ssh-hash hash key-blob))
         (width 17)
         (height 9)
         (field (make-array (list width height) :initial-element 0))
         (augmentation " .o+=*BOX@%&#/^SE")
         (len (1- (length augmentation)))
         (x (floor width 2))
         (y (floor height 2)))
    (loop for octet across digest
          do (let ((input octet))
               (dotimes (bit 4)
                 (declare (ignore bit))
                 (incf x (if (logbitp 0 input) 1 -1))
                 (incf y (if (logbitp 1 input) 1 -1))
                 (setf x (max 0 (min (1- width) x))
                       y (max 0 (min (1- height) y)))
                 (when (< (aref field x y) (- len 2))
                   (incf (aref field x y)))
                 (setf input (ash input -2)))))
    (setf (aref field (floor width 2) (floor height 2)) (1- len)
          (aref field x y) len)
    (let ((title (ssh-key-randomart-title key-blob))
          (hash-title (format nil "[~A]"
                              (string-upcase (symbol-name hash)))))
      (flet ((border (label)
               (let* ((label (if (>= (length label) width)
                                 ;; OpenSSH's title buffer holds WIDTH - 1
                                 ;; characters plus the terminating NUL, so a
                                 ;; long type name loses its last character.
                                 (subseq label 0 (1- width))
                                 label))
                      (left (floor (- width (length label)) 2)))
                 (concatenate 'string
                              "+"
                              (make-string left :initial-element #\-)
                              label
                              (make-string (- width (length label) left)
                                           :initial-element #\-)
                              "+"))))
        (with-output-to-string (out)
          (write-line (border title) out)
          (dotimes (row height)
            (write-char #\| out)
            (dotimes (column width)
              (write-char (char augmentation
                                (min (aref field column row) len))
                          out))
            (write-line "|" out))
          (write-string (border hash-title) out))))))

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
            (if (member type '("ssh-ed25519" "ssh-mldsa44-ed25519")
                        :test #'string=)
                (ssh-read-string reader)
                (ssh-read-octets reader (ssh-reader-remaining reader))))))

(defun ssh-rsa-public-key-bits (key-blob)
  "The modulus bit length of an ssh-rsa KEY-BLOB, or NIL for another type."
  (handler-case
      (multiple-value-bind (type data)
          (ssh-public-key-parts (ssh-key-plain-blob key-blob))
        (when (string= type "ssh-rsa")
          (let ((reader (ssh-make-reader data)))
            ;; The wire order is e, then n.
            (ssh-read-mpint reader)
            (integer-length (ssh-read-mpint reader)))))
    (error () nil)))

(defun ssh-key-rsa-size-allowed-p (key-blob minimum)
  "Whether KEY-BLOB satisfies sshd's RSA minimum and the configured MINIMUM.

Only RSA keys have a size floor: sshd rejects any RSA modulus below its
SSH_RSA_MINIMUM_MODULUS_SIZE (1024) even when RequiredRSASize is lower, and
rejects one below MINIMUM when that directive set a stricter size.  A NIL or
non-positive MINIMUM leaves only the built-in floor.  Every other key type
passes, as sshkey_check_rsa_length does."
  (let ((bits (ssh-rsa-public-key-bits key-blob)))
    (or (null bits)
        (and (>= bits +ssh-rsa-minimum-modulus-size+)
             (or (not (integerp minimum))
                 (<= minimum 0)
                 (>= bits minimum))))))

(defun ssh-make-public-key-blob (type data)
  "A public key blob from TYPE and its type-specific DATA.

DATA is the decoded ed25519 or composite ML-DSA key; for RSA it is the e and
n mpints and for ECDSA the curve name and point strings, already encoded as
the wire has them.  Ed25519 and ssh-mldsa44-ed25519 need the extra string
wrapper."
  (let ((writer (ssh-writer)))
    (ssh-write-text writer type)
    (if (member type '("ssh-ed25519" "ssh-mldsa44-ed25519") :test #'string=)
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

;;; ---- Composite ML-DSA-44 + Ed25519 signatures ----
;;;;
;;;; OpenSSH's ssh-mldsa44-ed25519 follows
;;;; draft-miller-sshm-mldsa44-ed25519: the public key is
;;;; mldsaPK || ed25519PK, the private key is mldsaSeed || ed25519Seed, and
;;;; a signature is mldsaSig || edSig.  Both halves sign
;;;; m' = PREFIX || LABEL || 0 || SHA-512(message); the ML-DSA half uses
;;;; LABEL as its FIPS 204 context.  OpenSSH's sshkey integration calls the
;;;; composite primitive with a zero context length, so m' carries a zero
;;;; octet where the general composite scheme would carry the label.

(defparameter +ssh-mldsa44-public-key-bytes+ 1312
  "The ML-DSA-44 public key length inside the composite key.")

(defparameter +ssh-mldsa44-ed25519-public-key-bytes+ 1344
  "The composite public key length: ML-DSA-44 then Ed25519.")

(defparameter +ssh-mldsa44-ed25519-private-key-bytes+ 64
  "The composite private key length: ML-DSA seed then Ed25519 seed.")

(defparameter +ssh-mldsa44-signature-bytes+ 2420
  "The ML-DSA-44 signature length inside the composite signature.")

(defparameter +ssh-mldsa44-ed25519-signature-bytes+ 2484
  "The composite signature length: ML-DSA-44 then Ed25519.")

(defparameter +ssh-mldsa44-ed25519-prefix+
  "CompositeAlgorithmSignatures2025"
  "The domain-separation prefix of the composite signature scheme.")

(defparameter +ssh-mldsa44-ed25519-label+
  "COMPSIG-MLDSA44-Ed25519-SHA512"
  "The composite label, also used as ML-DSA's FIPS 204 context.")

(defun ssh-mldsa44-ed25519-mprime (message)
  "The composite message representative m' over MESSAGE.

OpenSSH calls the composite primitive with a zero context length, so m' is
PREFIX || LABEL || #x00 || SHA-512(MESSAGE).  The ML-DSA half still signs m'
under the LABEL context."
  (ssh-concat (ssh-string-octets +ssh-mldsa44-ed25519-prefix+)
              (ssh-string-octets +ssh-mldsa44-ed25519-label+)
              (make-array 1 :element-type '(unsigned-byte 8)
                            :initial-element 0)
              (ssh-hash :sha512 message)))

(defun ssh-mldsa44-ed25519-expand-private (material)
  "VALUES ML-DSA-PRIVATE ED25519-PRIVATE from a composite seed MATERIAL.

OpenSSH stores the two 32-octet seeds, not the expanded ML-DSA secret key.
Ironclad-unsafe has no public seeded constructor, so the deterministic
keygen is called directly; the result is exactly OpenSSH's expanded key."
  (unless (= (length material) +ssh-mldsa44-ed25519-private-key-bytes+)
    (error 'ssh-protocol-error
           :detail "an ssh-mldsa44-ed25519 private key is 64 octets"))
  (multiple-value-bind (public secret)
      (ironclad-unsafe::ml-dsa-keygen-from-coins
       (ssh-copy-octets (subseq material 0 32))
       (ironclad-unsafe::ml-dsa-params-for-kind :ml-dsa-44))
    (declare (ignore public))
    (values (ironclad-unsafe:make-private-key
             :ml-dsa-44 :bytes (ssh-copy-octets secret))
            (ironclad-unsafe:make-private-key
             :ed25519 :x (ssh-copy-octets (subseq material 32 64))))))

(defun ssh-mldsa44-ed25519-sign (private-key message)
  "A composite signature of MESSAGE by PRIVATE-KEY."
  (unless (string= (ssh-private-key-type private-key)
                   "ssh-mldsa44-ed25519")
    (error 'ssh-protocol-error
           :detail "only ssh-mldsa44-ed25519 keys sign here"))
  (multiple-value-bind (mldsa ed25519)
      (ssh-mldsa44-ed25519-expand-private
       (ssh-private-key-private private-key))
    (let ((mprime (ssh-mldsa44-ed25519-mprime message)))
      (ssh-concat
       (ironclad-unsafe:sign-message
        mldsa mprime :ctx (ssh-string-octets +ssh-mldsa44-ed25519-label+))
       (ironclad-unsafe:sign-message ed25519 mprime)))))

(defun ssh-mldsa44-ed25519-signature-blob (private-key message)
  "The SSH signature blob (algorithm name and signature) of MESSAGE."
  (let ((writer (ssh-writer)))
    (ssh-write-text writer "ssh-mldsa44-ed25519")
    (ssh-write-string writer
                      (ssh-mldsa44-ed25519-sign private-key message))
    (ssh-writer-output writer)))

(defun ssh-mldsa44-ed25519-verify (key-data signature message)
  "Whether SIGNATURE over MESSAGE verifies under composite KEY-DATA.

Both halves must verify: ML-DSA-44 under the LABEL context and Ed25519
plainly, exactly as OpenSSH's crypto_sign_mldsa44_ed25519_verify requires."
  (unless (= (length key-data) +ssh-mldsa44-ed25519-public-key-bytes+)
    (error 'ssh-protocol-error
           :detail "an ssh-mldsa44-ed25519 public key is 1344 octets"))
  (unless (= (length signature) +ssh-mldsa44-ed25519-signature-bytes+)
    (error 'ssh-protocol-error
           :detail "an ssh-mldsa44-ed25519 signature is 2484 octets"))
  (let* ((mprime (ssh-mldsa44-ed25519-mprime message))
         (mldsa-key
           (ironclad-unsafe:make-public-key
            :ml-dsa-44
            :bytes (subseq key-data 0 +ssh-mldsa44-public-key-bytes+)))
         (ed25519-key
           (ironclad-unsafe:make-public-key
            :ed25519 :y (subseq key-data +ssh-mldsa44-public-key-bytes+)))
         (mldsa-signature
           (subseq signature 0 +ssh-mldsa44-signature-bytes+))
         (ed25519-signature
           (subseq signature +ssh-mldsa44-signature-bytes+)))
    (and (ironclad-unsafe:verify-signature
          mldsa-key mprime mldsa-signature
          :ctx (ssh-string-octets +ssh-mldsa44-ed25519-label+))
         (ironclad-unsafe:verify-signature
          ed25519-key mprime ed25519-signature))))

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

(defun ssh-private-key-signature-blob (key message &key algorithm)
  "A signature blob of MESSAGE under a loaded private KEY, or signal.

ALGORITHM names the signature algorithm the request asked for; an RSA key
uses it to pick SHA-256 or SHA-512.  Without it RSA signs as rsa-sha2-256,
the form every OpenSSH since 7.2 understands."
  (let ((type (ssh-private-key-type key)))
    (cond
      ((string= type "ssh-ed25519")
       (ssh-ed25519-signature-blob key message))
      ((string= type "ssh-mldsa44-ed25519")
       (ssh-mldsa44-ed25519-signature-blob key message))
      ((and (> (length type) (length "ecdsa-sha2-"))
            (string= "ecdsa-sha2-" type
                     :end2 (length "ecdsa-sha2-")))
       (ssh-ecdsa-signature-blob key message))
      ((string= type "ssh-rsa")
       (ssh-rsa-signature-blob
        key message
        (or (and algorithm (ssh-rsa-digest-keyword algorithm)) :sha256)))
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
        ((string= key-type "ssh-mldsa44-ed25519")
         ;; OpenSSH writes the composite public key (ML-DSA then Ed25519)
         ;; followed by the two 32-octet seeds.  The rest of this file keeps
         ;; the public half as the raw 1344 octets and the private half as
         ;; the 64-octet seed pair.
         (let ((public (ssh-read-string reader))
               (private (ssh-read-string reader))
               (comment (ssh-read-text reader)))
           (unless (= (length public)
                      +ssh-mldsa44-ed25519-public-key-bytes+)
             (error 'ssh-protocol-error
                    :detail "an ssh-mldsa44-ed25519 public key is 1344 octets"))
           (unless (= (length private)
                      +ssh-mldsa44-ed25519-private-key-bytes+)
             (error 'ssh-protocol-error
                    :detail "an ssh-mldsa44-ed25519 private key is 64 octets"))
           (%make-ssh-private-key :type key-type :public public
                                  :private private :comment comment)))
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

(defun ssh-private-key-file-encrypted-p (path)
  "Whether the private key file at PATH is passphrase-protected.

The header names the cipher, so this answers without a passphrase and
without decrypting anything."
  (let* ((body (ssh-private-key-body (ssh-read-octets-file path))))
    (ssh-check-key-magic body)
    (let ((reader (ssh-make-reader body)))
      ;; Step over the magic and its trailing NUL to the cipher string.
      (dotimes (index (1+ (length +openssh-key-magic+)))
        (declare (ignore index))
        (ssh-read-u8 reader))
      (not (string= (ssh-read-text reader) "none")))))

(defun ssh-private-key-public-blob (path)
  "The public key blob in the openssh-key-v1 header at PATH.

The header sits outside the encrypted section, so a protected key can be
identified without its passphrase, as ssh-keygen -l does."
  (let* ((body (ssh-private-key-body (ssh-read-octets-file path)))
         (magic (ssh-check-key-magic body)))
    (declare (ignore magic))
    (let ((reader (ssh-make-reader
                   body (+ (length +openssh-key-magic+) 1))))
      (ssh-read-text reader)                 ; cipher
      (ssh-read-text reader)                 ; kdf
      (ssh-read-string reader)               ; kdf options
      (let ((count (ssh-read-u32 reader)))
        (unless (= count 1)
          (error 'ssh-protocol-error
                 :detail "a key file with several keys is unsupported"))
        (ssh-read-string reader)))))

(defun ssh-public-key-blob-of (key)
  "The public key blob of private KEY, or an agent-backed host key."
  (if (ssh-agent-host-key-p key)
      (ssh-agent-host-key-blob key)
      (let ((type (ssh-private-key-type key)))
        (ssh-make-public-key-blob
         type
         (if (and (> (length type) (length "ecdsa-sha2-"))
                  (string= "ecdsa-sha2-" type
                           :end2 (length "ecdsa-sha2-")))
             ;; An ECDSA public key is its curve name and point, both strings;
             ;; the private key stores only the point.
             (let ((writer (ssh-writer)))
               (ssh-write-text writer (subseq type (length "ecdsa-sha2-")))
               (ssh-write-string writer (ssh-private-key-public key))
               (ssh-writer-output writer))
             (ssh-private-key-public key))))))

;;;; ---- OpenSSH certificates ----
;;;;
;;;; A certificate is a normal public key blob whose type name gains
;;;; "-cert-v01@openssh.com", followed by the plain key fields and the
;;;; certificate body that a CA signed.  OpenSSH puts a nonce before the key
;;;; fields, so the plain key is rebuilt here for signature verification.
;;;; The certificate's own signature is over the whole blob except the final
;;;; signature string; parsing deliberately does not check it, so a caller
;;;; that trusts a certificate must also call SSH-CERTIFICATE-SIGNATURE-VALID-P.

(defparameter +ssh-certificate-suffix+ "-cert-v01@openssh.com")

(defparameter +ssh-mldsa-certificate-suffix+ "-cert"
  "The shorter certificate suffix OpenSSH uses for ssh-mldsa44-ed25519-cert.")

(defparameter +ssh-unix-epoch+ 2208988800
  "The universal time of 1970-01-01, which certificate times count from.")

(defun ssh-unix-time (&optional (universal (get-universal-time)))
  "UNIVERSAL, or now, as seconds since the Unix epoch."
  (- universal +ssh-unix-epoch+))

(defparameter +ssh-certificate-plain-types+
  '("ssh-ed25519" "ssh-rsa" "ssh-mldsa44-ed25519"
    "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521")
  "The plain key types OpenSSH can certify and this build understands.")

(defparameter +ssh-short-certificate-plain-types+
  '("ssh-mldsa44-ed25519")
  "The plain key types whose certificate name uses the short -cert suffix.")

(defun ssh-certificate-plain-type (name)
  "The plain key type of certificate type NAME, or NIL.

Most certificates use the -cert-v01@openssh.com suffix, but the composite
ML-DSA key uses a plain -cert, so the long suffix must not also accept it."
  (flet ((strip (suffix plain-types)
           (let ((start (- (length name) (length suffix))))
             (when (and (not (minusp start))
                        (string= suffix name :start2 start))
               (let ((plain (subseq name 0 start)))
                 (when (member plain plain-types :test #'string=)
                   plain))))))
    (or (let ((plain (strip +ssh-certificate-suffix+
                            +ssh-certificate-plain-types+)))
          (and plain
               (not (member plain +ssh-short-certificate-plain-types+
                            :test #'string=))
               plain))
        (strip +ssh-mldsa-certificate-suffix+
               +ssh-short-certificate-plain-types+))))

(defun ssh-certificate-type-name-p (name)
  "Whether NAME is a certificate key type this build understands."
  (not (null (ssh-certificate-plain-type name))))

(defun ssh-certificate-name (plain-type)
  "The certificate type name for PLAIN-TYPE."
  (if (member plain-type +ssh-short-certificate-plain-types+
              :test #'string=)
      (concatenate 'string plain-type +ssh-mldsa-certificate-suffix+)
      (concatenate 'string plain-type +ssh-certificate-suffix+)))

(defun ssh-mldsa44-ed25519-algorithm-p (name)
  "Whether NAME is the composite ML-DSA-44 + Ed25519 key or its certificate."
  (or (string= name "ssh-mldsa44-ed25519")
      (string= name "ssh-mldsa44-ed25519-cert")))

(defun ssh-certificate-type (key-blob)
  "The certificate type name in KEY-BLOB, or NIL when it is not a cert."
  (handler-case
      (let ((name (ssh-read-text (ssh-make-reader key-blob))))
        (and (ssh-certificate-type-name-p name) name))
    (error () nil)))

(defun ssh-certificate-blob-p (key-blob)
  "Whether KEY-BLOB is an OpenSSH certificate this build understands."
  (not (null (ssh-certificate-type key-blob))))

(defstruct (ssh-certificate (:constructor %make-ssh-certificate))
  (key-type nil :type (or null string))
  (plain-key-type nil :type (or null string))
  (plain-blob nil :type (or null ssh-octets))
  (serial 0 :type integer)
  ;; 1 is a user certificate and 2 a host certificate (PROTOCOL.certkeys).
  (cert-type 0 :type integer)
  (key-id "" :type string)
  (principals '())
  (valid-after 0 :type integer)
  (valid-before 0 :type integer)
  ;; (NAME . VALUE) pairs in wire order.  VALUE is a string for the options
  ;; that carry one and the empty string for the flags.
  (critical '())
  (extensions '())
  (reserved "")
  (signature-key nil :type (or null ssh-octets))
  (signature nil :type (or null ssh-octets))
  (signature-algorithm nil :type (or null string))
  (signed-data nil :type (or null ssh-octets)))

(defun ssh-certificate-option-list (reader)
  "The (NAME . VALUE) option pairs in READER.

Each option is a name string and a data string.  A key/value option's data
is itself a length-prefixed string holding the value (ssh-keygen writes it
that way), while a flag option's data is empty."
  (let ((options '()))
    (loop while (plusp (ssh-reader-remaining reader))
          do (let* ((name (ssh-read-text reader))
                    (data (ssh-read-string reader))
                    (value
                      (if (zerop (length data))
                          ""
                          (let ((inner (ssh-make-reader data)))
                            (prog1 (ssh-read-text inner)
                              (unless (zerop (ssh-reader-remaining inner))
                                (error 'ssh-protocol-error
                                       :detail
                                       "trailing certificate option data")))))))
               (push (cons name value) options)))
    (nreverse options)))

(defun ssh-certificate-key-field-count (plain-type)
  "How many length-prefixed fields PLAIN-TYPE's public key has."
  (cond
    ((string= plain-type "ssh-ed25519") 1)
    ((string= plain-type "ssh-mldsa44-ed25519") 1)
    ((string= plain-type "ssh-rsa") 2)
    ((member plain-type
             '("ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384"
               "ecdsa-sha2-nistp521")
             :test #'string=)
     2)
    (t nil)))

(defun ssh-certificate-parse (key-blob)
  "KEY-BLOB as an SSH-CERTIFICATE, or NIL when it is not a readable cert.

The certificate's signature is not checked here; see
SSH-CERTIFICATE-SIGNATURE-VALID-P."
  (when (ssh-certificate-blob-p key-blob)
    (handler-case
        (let* ((reader (ssh-make-reader key-blob))
               (type (ssh-read-text reader))
               (plain-type (ssh-certificate-plain-type type))
               (field-count (ssh-certificate-key-field-count plain-type))
               (key-writer (ssh-writer)))
          ;; The nonce precedes the plain key fields.
          (ssh-read-string reader)
          (ssh-write-text key-writer plain-type)
          (dotimes (index field-count)
            (declare (ignore index))
            (ssh-write-string key-writer (ssh-read-string reader)))
          (let ((plain-key-blob (ssh-writer-output key-writer))
                (serial (ssh-read-u64 reader))
                (cert-type (ssh-read-u32 reader))
                (key-id (ssh-read-text reader))
                (principal-reader
                  (ssh-make-reader (ssh-read-string reader)))
                (valid-after (ssh-read-u64 reader))
                (valid-before (ssh-read-u64 reader))
                (critical (ssh-certificate-option-list
                           (ssh-make-reader (ssh-read-string reader))))
                (extensions (ssh-certificate-option-list
                             (ssh-make-reader (ssh-read-string reader))))
                (reserved (ssh-read-text reader))
                (signature-key (ssh-read-string reader))
                (signature-start (ssh-reader-position reader))
                (signature (ssh-read-string reader)))
            (unless (zerop (ssh-reader-remaining reader))
              (error 'ssh-protocol-error
                     :detail "trailing data after a certificate"))
            (let ((principals '()))
              (when (plusp (ssh-reader-remaining principal-reader))
                (loop while (plusp (ssh-reader-remaining principal-reader))
                      do (push (ssh-read-text principal-reader) principals)))
              (%make-ssh-certificate
               :key-type type
               :plain-key-type plain-type
               :plain-blob plain-key-blob
               :serial serial
               :cert-type cert-type
               :key-id key-id
               :principals (nreverse principals)
               :valid-after valid-after
               :valid-before valid-before
               :critical critical
               :extensions extensions
               :reserved reserved
               :signature-key signature-key
               :signature signature
               :signature-algorithm
               (nth-value 0 (ssh-parse-signature-blob signature))
               :signed-data (subseq key-blob 0 signature-start)))))
      (error () nil))))

(defun ssh-certificate-plain-key-blob (key-blob)
  "The plain public key blob inside certificate KEY-BLOB, or NIL."
  (let ((certificate (ssh-certificate-parse key-blob)))
    (and certificate (ssh-certificate-plain-blob certificate))))

(defun ssh-key-plain-blob (key-blob)
  "KEY-BLOB with a certificate's certified key substituted for the cert.

A plain key is returned unchanged.  A malformed certificate is returned as
it is, so every caller fails closed instead of trusting the wrapper."
  (if (ssh-certificate-blob-p key-blob)
      (or (ssh-certificate-plain-key-blob key-blob) key-blob)
      key-blob))

(defun ssh-key-type-name (key-blob)
  "OpenSSH's short name for KEY-BLOB's type, as ssh -Z prints it.

A certificate adds \"-CERT\" to the plain key's short name, so an Ed25519
certificate is ED25519-CERT and an RSA one is RSA-CERT."
  (multiple-value-bind (plain data)
      (ssh-public-key-parts (ssh-key-plain-blob key-blob))
    (declare (ignore data))
    (let ((name
            (cond
              ((string= plain "ssh-ed25519") "ED25519")
              ((string= plain "ssh-mldsa44-ed25519") "MLDSA44-ED25519")
              ((string= plain "ssh-rsa") "RSA")
              ((member plain '("ecdsa-sha2-nistp256"
                               "ecdsa-sha2-nistp384"
                               "ecdsa-sha2-nistp521")
                       :test #'string=)
               "ECDSA")
              ((string= plain "sk-ssh-ed25519@openssh.com") "ED25519-SK")
              ((string= plain "sk-ecdsa-sha2-nistp256@openssh.com")
               "ECDSA-SK")
              (t (string-upcase plain)))))
      (if (ssh-certificate-blob-p key-blob)
          (concatenate 'string name "-CERT")
          name))))

(defun ssh-certificate-signature-valid-p (certificate)
  "Whether CERTIFICATE's body carries a valid CA signature.

The CA key itself may not be a certificate, which is OpenSSH's rule for a
valid certificate authority."
  (and (ssh-certificate-p certificate)
       (let ((ca (ssh-certificate-signature-key certificate)))
         (and ca
              (not (ssh-certificate-blob-p ca))
              (ssh-public-key-signature-valid-p
               ca (ssh-certificate-signature certificate)
               (ssh-certificate-signed-data certificate))))))
