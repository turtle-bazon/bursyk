(in-package #:cl-pnet-ssh)

;;;; SSH's cryptographic primitives on top of ironclad-unsafe.
;;;;
;;;; SSH needs three things ironclad does not expose directly: ChaCha20 with
;;;; an 8-byte nonce and a caller-chosen block counter (the OpenSSH
;;;; chacha20-poly1305 construction), X25519 as raw octets, and Ed25519
;;;; verification of a host signature. Everything else is a thin wrapper.

(defun ssh-random-octets (count)
  "COUNT random octets from the system entropy source."
  (ironclad-unsafe:random-data count))

(defun ssh-hash (algorithm &rest sequences)
  "Digest ALGORITHM over the concatenation of SEQUENCES, as octets."
  (ironclad-unsafe:digest-sequence algorithm (apply #'ssh-concat sequences)))

(defun ssh-hmac (key data &optional (digest :sha256))
  "HMAC-DIGEST of DATA under KEY."
  (let ((hmac (ironclad-unsafe:make-hmac key digest)))
    (ironclad-unsafe:update-hmac hmac data)
    (ironclad-unsafe:hmac-digest hmac)))

(defun ssh-hmac-length (digest)
  "The tag length of the named HMAC DIGEST."
  (ecase digest
    (:sha1 20)
    (:sha256 32)
    (:sha512 64)))

(defun ssh-poly1305 (key data)
  "The Poly1305 one-time tag of DATA under KEY (32 octets)."
  (let ((mac (ironclad-unsafe:make-poly1305 key)))
    (ironclad-unsafe:update-poly1305 mac data)
    (ironclad-unsafe:poly1305-digest mac)))

;;; ---- X25519 ----

(defun ssh-curve25519-keypair ()
  "A fresh X25519 keypair as (VALUES PRIVATE PUBLIC), both 32 octets."
  (let* ((secret (ssh-random-octets 32))
         (public (ironclad-unsafe:curve25519-public-key secret)))
    (values secret public)))

(defun ssh-curve25519-shared (private peer-public)
  "The X25519 shared secret of PRIVATE with PEER-PUBLIC, 32 octets."
  (unless (= (length private) 32)
    (error 'ssh-protocol-error :detail "an X25519 private key is 32 octets"))
  (unless (= (length peer-public) 32)
    (error 'ssh-protocol-error :detail "an X25519 public key is 32 octets"))
  (let ((private-key (ironclad-unsafe:make-private-key :curve25519 :x private))
        (public-key (ironclad-unsafe:make-public-key :curve25519 :y peer-public)))
    (ironclad-unsafe:diffie-hellman private-key public-key)))

;;; ---- NIST-curve ECDH (ecdh-sha2-nistp256/384/521) ----
;;;
;;; RFC 5656: the public key Q is an uncompressed SEC1 point and the shared
;;; secret K is the X coordinate written as an mpint.  ironclad-unsafe already
;;; implements the three curves, so this only lays out the SSH wire form.

(defparameter +ssh-ecdh-curves+
  '(("ecdh-sha2-nistp256" :curve :secp256r1 :size 32 :digest :sha256)
    ("ecdh-sha2-nistp384" :curve :secp384r1 :size 48 :digest :sha384)
    ("ecdh-sha2-nistp521" :curve :secp521r1 :size 66 :digest :sha512))
  "The NIST-curve key exchanges SSH names, with Ironclad's curve, width and
digest.  The digest is both the exchange hash and the key-derivation hash.")

(defun ssh-ecdh-kex-parameters (kex)
  "The (VALUES CURVE SIZE DIGEST) of the NIST-curve key exchange KEX.

Answers NIL when KEX is not one of them."
  (let ((entry (and (stringp kex)
                    (assoc kex +ssh-ecdh-curves+ :test #'string=))))
    (when entry
      (values (getf (cdr entry) :curve)
              (getf (cdr entry) :size)
              (getf (cdr entry) :digest)))))

(defun ssh-ecdh-kex-p (name)
  "Whether NAME is a NIST-curve ECDH key exchange."
  (and (ssh-ecdh-kex-parameters name) t))

(defun ssh-ecdh-keypair-for-curve (curve)
  "A fresh keypair on CURVE as (VALUES PRIVATE-KEY PUBLIC-POINT).

The point is SEC1's uncompressed form, the encoding RFC 5656 puts on the
wire; the private key object is what DIFFIE-HELLMAN takes later."
  (multiple-value-bind (private public)
      (ironclad-unsafe:generate-key-pair curve)
    (values private
            (getf (ironclad-unsafe:destructure-public-key public) :y))))

(defun ssh-ecdh-keypair (kex)
  "A fresh keypair for KEX as (VALUES PRIVATE-KEY PUBLIC-POINT)."
  (let ((curve (nth-value 0 (ssh-ecdh-kex-parameters kex))))
    (unless curve
      (error 'ssh-protocol-error
             :detail (format nil "unsupported ECDH key exchange ~A" kex)))
    (ssh-ecdh-keypair-for-curve curve)))

(defun ssh-ecdh-shared-for-curve (private peer-point curve size)
  "The X coordinate of the ECDH shared point on CURVE, SIZE octets.

Ironclad's DIFFIE-HELLMAN returns the whole SEC1 point; RFC 5656 uses only
its X coordinate, zero-padded to the field width.  MAKE-PUBLIC-KEY checks
that the peer's point is on the curve before it is multiplied."
  (let ((point
          (handler-case
              (ironclad-unsafe:diffie-hellman
               private
               (ironclad-unsafe:make-public-key curve :y peer-point))
            (error (condition)
              (error 'ssh-protocol-error
                     :detail (format nil "invalid ECDH public key: ~A"
                                     condition))))))
    (unless (and (= (length point) (1+ (* 2 size)))
                 (= (aref point 0) 4))
      (error 'ssh-protocol-error :detail "malformed ECDH shared point"))
    (subseq point 1 (1+ size))))

(defun ssh-ecdh-shared (private peer-point kex)
  "The X coordinate of the ECDH shared point for KEX, SIZE octets."
  (multiple-value-bind (curve size)
      (ssh-ecdh-kex-parameters kex)
    (unless curve
      (error 'ssh-protocol-error
             :detail (format nil "unsupported ECDH key exchange ~A" kex)))
    (ssh-ecdh-shared-for-curve private peer-point curve size)))

;;; ---- ML-KEM-768 hybrids ----
;;;
;;; OpenSSH's post-quantum key exchanges concatenate an ML-KEM-768
;;; encapsulation key with a classical public key (X25519 or NIST P-256).
;;; The server answers with the ML-KEM ciphertext followed by its classical
;;; public key.  The two secrets are concatenated and SHA-256 hashed, and that
;;; digest is the shared secret the exchange hash and key derivation both use.
;;; ironclad-unsafe provides the FIPS 203 primitive; this file only lays the
;;; two halves out the way the SSH methods do.

(defconstant +ssh-mlkem768-public-bytes+ 1184)
(defconstant +ssh-mlkem768-ciphertext-bytes+ 1088)

(defparameter +ssh-mlkem768-hybrids+
  '(("mlkem768x25519-sha256" :curve :x25519 :point-bytes 32)
    ("mlkem768nistp256-sha256" :curve :secp256r1 :point-bytes 65))
  "OpenSSH's ML-KEM-768 hybrids, with the classical curve and its wire width.")

(defun ssh-mlkem768-hybrid-parameters (kex)
  "The (VALUES CURVE POINT-BYTES) of the ML-KEM hybrid KEX, or NIL."
  (let ((entry (and (stringp kex)
                    (assoc kex +ssh-mlkem768-hybrids+ :test #'string=))))
    (when entry
      (values (getf (cdr entry) :curve)
              (getf (cdr entry) :point-bytes)))))

(defun ssh-mlkem768-hybrid-p (name)
  "Whether NAME is one of OpenSSH's ML-KEM-768 hybrids."
  (and (ssh-mlkem768-hybrid-parameters name) t))

(defun ssh-mlkem768-hybrid-classical-keypair (curve)
  "A fresh classical half for an ML-KEM hybrid as (VALUES PRIVATE PUBLIC)."
  (if (eq curve :x25519)
      (ssh-curve25519-keypair)
      (ssh-ecdh-keypair-for-curve curve)))

(defun ssh-mlkem768-hybrid-classical-shared (private peer curve point-bytes)
  "The classical shared secret of PRIVATE with PEER."
  (if (eq curve :x25519)
      (ssh-curve25519-shared private peer)
      (ssh-ecdh-shared-for-curve private peer curve (/ (1- point-bytes) 2))))

(defstruct (ssh-mlkem768-hybrid-state
             (:constructor %make-ssh-mlkem768-hybrid-state))
  "A client's ML-KEM and classical private halves plus the blob to send."
  (kex nil)
  (mlkem-private nil)
  (classical-private nil)
  (public nil))

(defun ssh-mlkem768-hybrid-client-keypair (kex)
  "A fresh client keypair for the ML-KEM hybrid KEX.

Returns an SSH-MLKEM768-HYBRID-STATE whose PUBLIC is the encapsulation key
followed by the classical public key."
  (multiple-value-bind (curve)
      (ssh-mlkem768-hybrid-parameters kex)
    (unless curve
      (error 'ssh-protocol-error
             :detail (format nil "unsupported ML-KEM key exchange ~A" kex)))
    (multiple-value-bind (mlkem-private mlkem-public)
        (ironclad-unsafe:generate-key-pair :ml-kem-768)
      (multiple-value-bind (classical-private classical-public)
          (ssh-mlkem768-hybrid-classical-keypair curve)
        (%make-ssh-mlkem768-hybrid-state
         :kex kex
         :mlkem-private mlkem-private
         :classical-private classical-private
         :public (ssh-concat
                  (ironclad-unsafe:ml-kem-key-bytes mlkem-public)
                  classical-public))))))

(defun ssh-mlkem768-hybrid-client-shared (state server-blob)
  "The hybrid shared secret of STATE with the server's SERVER-BLOB."
  (multiple-value-bind (curve point-bytes)
      (ssh-mlkem768-hybrid-parameters (ssh-mlkem768-hybrid-state-kex state))
    (unless (= (length server-blob)
               (+ +ssh-mlkem768-ciphertext-bytes+ point-bytes))
      (error 'ssh-protocol-error
             :detail "malformed ML-KEM hybrid server key exchange"))
    (let ((mlkem-shared
            (ironclad-unsafe:decapsulate-key
             (ssh-mlkem768-hybrid-state-mlkem-private state)
             (subseq server-blob 0 +ssh-mlkem768-ciphertext-bytes+)))
          (classical-shared
            (ssh-mlkem768-hybrid-classical-shared
             (ssh-mlkem768-hybrid-state-classical-private state)
             (subseq server-blob +ssh-mlkem768-ciphertext-bytes+)
             curve point-bytes)))
      ;; OpenSSH hashes the concatenation and uses that digest as the shared
      ;; secret, so the exchange hash and the key derivation see 32 octets
      ;; rather than the concatenation itself.
      (ssh-hash :sha256 (ssh-concat mlkem-shared classical-shared)))))

(defun ssh-mlkem768-hybrid-server-shared (kex client-blob)
  "Answer CLIENT-BLOB with (VALUES SERVER-BLOB SHARED-SECRET)."
  (multiple-value-bind (curve point-bytes)
      (ssh-mlkem768-hybrid-parameters kex)
    (unless curve
      (error 'ssh-protocol-error
             :detail (format nil "unsupported ML-KEM key exchange ~A" kex)))
    (unless (= (length client-blob)
               (+ +ssh-mlkem768-public-bytes+ point-bytes))
      (error 'ssh-protocol-error
             :detail "malformed ML-KEM hybrid client key exchange"))
    (let* ((mlkem-public
             (ironclad-unsafe:make-public-key
              :ml-kem-768
              :bytes (subseq client-blob 0 +ssh-mlkem768-public-bytes+)))
           (classical-peer (subseq client-blob +ssh-mlkem768-public-bytes+)))
      (multiple-value-bind (ciphertext mlkem-shared)
          (ironclad-unsafe:encapsulate-key mlkem-public)
        (multiple-value-bind (classical-private classical-public)
            (ssh-mlkem768-hybrid-classical-keypair curve)
          (values (ssh-concat ciphertext classical-public)
                  (ssh-hash :sha256
                            (ssh-concat
                             mlkem-shared
                             (ssh-mlkem768-hybrid-classical-shared
                              classical-private classical-peer
                              curve point-bytes)))))))))

(defun ssh-ed25519-verify (signature message public-key)
  "Verify SIGNATURE (64 octets) over MESSAGE under PUBLIC-KEY (32 octets)."
  (and (= (length signature) 64)
       (= (length public-key) 32)
       (ironclad-unsafe:verify-signature
        (ironclad-unsafe:make-public-key :ed25519
                                         :y (ssh-copy-octets public-key))
        (ssh-copy-octets message)
        (ssh-copy-octets signature))))

;;; ---- ChaCha20 (original construction: 8-byte nonce, 64-bit counter) ----

(deftype ssh-u32 () '(unsigned-byte 32))

(defun ssh-u32-from-le (octets start)
  "The little-endian uint32 at START."
  (logior (aref octets start)
          (ash (aref octets (+ start 1)) 8)
          (ash (aref octets (+ start 2)) 16)
          (ash (aref octets (+ start 3)) 24)))

(defun ssh-u32-to-le (octets start value)
  "Store VALUE at START, little-endian."
  (setf (aref octets start) (ldb (byte 8 0) value)
        (aref octets (+ start 1)) (ldb (byte 8 8) value)
        (aref octets (+ start 2)) (ldb (byte 8 16) value)
        (aref octets (+ start 3)) (ldb (byte 8 24) value)))

(defun ssh-chacha20-quarter-round (state a b c d)
  "One ChaCha20 quarter round on STATE, in place."
  (declare (type simple-vector state)
           (type ssh-u32 a b c d)
           (optimize (speed 3) (safety 0)))
  (macrolet ((add (x y)
               `(setf (svref state ,x)
                      (logand (+ (svref state ,x) (svref state ,y))
                              #xFFFFFFFF)))
             (rot (x n)
               `(setf (svref state ,x)
                      (logand (logior (ash (svref state ,x) ,n)
                                      (ash (svref state ,x) (- ,n 32)))
                              #xFFFFFFFF)))
             (xors (x y)
               `(setf (svref state ,x)
                      (logxor (svref state ,x) (svref state ,y)))))
    (add a b) (xors d a) (rot d 16)
    (add c d) (xors b c) (rot b 12)
    (add a b) (xors d a) (rot d 8)
    (add c d) (xors b c) (rot b 7))
  state)

(defun ssh-chacha20-block (key nonce counter)
  "One 64-octet ChaCha20 block.

KEY is 32 octets, NONCE 8 octets, COUNTER a non-negative integer.  The
counter is 64 bits wide, as OpenSSH's SSH construction uses it: the length
field is encrypted with counter 0 and the payload with counter 1 onwards."
  (declare (type ssh-octets key nonce)
           (type (unsigned-byte 64) counter))
  (let ((state (make-array 16))
        (initial (make-array 16)))
    (setf (svref state 0) 1634760805
          (svref state 1) 857760878
          (svref state 2) 2036477234
          (svref state 3) 1797285236
          (svref state 12) (ldb (byte 32 0) counter)
          (svref state 13) (ldb (byte 32 32) counter)
          (svref state 14) (ssh-u32-from-le nonce 0)
          (svref state 15) (ssh-u32-from-le nonce 4))
    (dotimes (i 8)
      (setf (svref state (+ 4 i)) (ssh-u32-from-le key (* i 4))))
    (replace initial state)
    (dotimes (i 10)
      (ssh-chacha20-quarter-round state 0 4 8 12)
      (ssh-chacha20-quarter-round state 1 5 9 13)
      (ssh-chacha20-quarter-round state 2 6 10 14)
      (ssh-chacha20-quarter-round state 3 7 11 15)
      (ssh-chacha20-quarter-round state 0 5 10 15)
      (ssh-chacha20-quarter-round state 1 6 11 12)
      (ssh-chacha20-quarter-round state 2 7 8 13)
      (ssh-chacha20-quarter-round state 3 4 9 14))
    (let ((out (make-array 64 :element-type '(unsigned-byte 8))))
      (dotimes (i 16)
        (ssh-u32-to-le out (* i 4)
                       (logand (+ (svref state i) (svref initial i))
                               #xFFFFFFFF)))
      out)))

(defun ssh-chacha20-keystream (key nonce counter length)
  "LENGTH octets of the ChaCha20 keystream starting at block COUNTER."
  (let ((out (make-array length :element-type '(unsigned-byte 8))))
    (iter (for offset from 0 below length by 64)
      (let* ((block (ssh-chacha20-block key nonce
                                        (+ counter (floor offset 64))))
             (take (min 64 (- length offset))))
        (replace out block :start1 offset :end2 take)))
    out))

(defun ssh-chacha20-xor (key nonce counter data)
  "DATA encrypted with the ChaCha20 keystream starting at block COUNTER."
  (let ((stream (ssh-chacha20-keystream key nonce counter (length data)))
        (out (make-array (length data) :element-type '(unsigned-byte 8))))
    (dotimes (i (length data) out)
      (setf (aref out i) (logxor (aref data i) (aref stream i))))))

;;; ---- OpenSSH's chacha20-poly1305@openssh.com packet key ----

(defstruct (ssh-chacha-packet-key (:constructor %make-ssh-chacha-packet-key))
  (length-key nil :type ssh-octets)
  (payload-key nil :type ssh-octets))

(defun ssh-chacha-packet-key (key)
  "Split an SSH chacha20-poly1305 KEY (64 octets) into its two halves.

OpenSSH's construction gives the first half to the payload and the second to
the length; only the length half also supplies the Poly1305 key."
  (unless (= (length key) 64)
    (error 'ssh-protocol-error
           :detail "chacha20-poly1305@openssh.com wants a 64-octet key"))
  (%make-ssh-chacha-packet-key
   :payload-key (subseq key 0 32)
   :length-key (subseq key 32 64)))

(defun ssh-chacha-nonce (sequence)
  "The 8-octet ChaCha nonce for packet SEQUENCE, big-endian."
  (ssh-uint64-octets sequence))

(defun ssh-chacha-length-block (packet-key sequence)
  "The keystream block hiding a packet's length."
  (ssh-chacha20-block (ssh-chacha-packet-key-length-key packet-key)
                      (ssh-chacha-nonce sequence)
                      0))

(defun ssh-chacha-poly-key (packet-key sequence)
  "The 32-octet Poly1305 key for SEQUENCE's packet.

OpenSSH takes it from the payload cipher's counter-0 keystream, before that
same cipher is advanced to counter 1 for the payload itself."
  (subseq (ssh-chacha20-block (ssh-chacha-packet-key-payload-key packet-key)
                              (ssh-chacha-nonce sequence)
                              0)
          0 32))

(defun ssh-chacha-encrypt-length (packet-key sequence length)
  "The encrypted four-octet packet length for SEQUENCE."
  (let* ((block (ssh-chacha-length-block packet-key sequence))
         (out (make-array 4 :element-type '(unsigned-byte 8)))
         (plain (ssh-uint32-octets length)))
    (dotimes (i 4 out)
      (setf (aref out i) (logxor (aref plain i) (aref block i))))))

(defun ssh-chacha-decrypt-length (packet-key sequence octets)
  "The packet length hidden in the first four OCTETS for SEQUENCE."
  (let ((block (ssh-chacha-length-block packet-key sequence)))
    (logior (ash (logxor (aref octets 0) (aref block 0)) 24)
            (ash (logxor (aref octets 1) (aref block 1)) 16)
            (ash (logxor (aref octets 2) (aref block 2)) 8)
            (logxor (aref octets 3) (aref block 3)))))
