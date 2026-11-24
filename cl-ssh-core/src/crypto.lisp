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
  "The tag length of the named MAC DIGEST.

A truncated MAC (hmac-sha1-96, hmac-md5-96) keeps its digest's key but sends
only the first twelve octets, so the tag length and the key length differ.
UMAC names ride along here so callers that only need the tag size do not
have to know which construction produced it."
  (ecase digest
    (:sha1 20)
    (:sha1-96 12)
    (:sha256 32)
    (:sha512 64)
    (:md5 16)
    (:md5-96 12)
    (:umac-64 8)
    (:umac-128 16)))

(defun ssh-hmac-key-length (digest)
  "The key length the named HMAC DIGEST takes.

A truncated MAC still derives the digest's full key; only its tag is
shortened."
  (ecase digest
    ((:sha1 :sha1-96) 20)
    (:sha256 32)
    (:sha512 64)
    ((:md5 :md5-96) 16)))

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

;;; ---- Fixed-group MODP Diffie-Hellman (diffie-hellman-group*) ----
;;;
;;; RFC 4253 section 8: the client sends e = g^x mod p as an mpint, the
;;; server answers with f = g^y mod p, and each side computes K = f^x = e^y
;;; mod p.  The primes are the standard RFC 2409 and RFC 3526 groups.  The
;;; SHA-1 names are implemented for compatibility with old peers but, as in
;;; OpenSSH, never offered by default.

(defparameter +ssh-dh-group1-prime+
  #xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF)

(defparameter +ssh-dh-group14-prime+
  #xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF)

(defparameter +ssh-dh-group16-prime+
  #xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF)

(defparameter +ssh-dh-group18-prime+
  #xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF)

(defparameter +ssh-dh-groups+
  (list (list "diffie-hellman-group1-sha1"
              :prime +ssh-dh-group1-prime+ :bits 1024 :digest :sha1)
        (list "diffie-hellman-group14-sha1"
              :prime +ssh-dh-group14-prime+ :bits 2048 :digest :sha1)
        (list "diffie-hellman-group14-sha256"
              :prime +ssh-dh-group14-prime+ :bits 2048 :digest :sha256)
        (list "diffie-hellman-group16-sha512"
              :prime +ssh-dh-group16-prime+ :bits 4096 :digest :sha512)
        (list "diffie-hellman-group18-sha512"
              :prime +ssh-dh-group18-prime+ :bits 8192 :digest :sha512))
  "Every fixed-group Diffie-Hellman method, with its prime, size and digest.

group1-sha1 and group14-sha1 are legacy compatibility methods: OpenSSH
lists them for -Q kex but keeps them out of the default offer, and so does
this build.")

(defun ssh-dh-group-parameters (kex)
  "The (VALUES PRIME BITS DIGEST) of the fixed-group exchange KEX.

Answers NIL when KEX is not one of them."
  (let ((entry (and (stringp kex)
                    (assoc kex +ssh-dh-groups+ :test #'string=))))
    (when entry
      (values (getf (cdr entry) :prime)
              (getf (cdr entry) :bits)
              (getf (cdr entry) :digest)))))

(defun ssh-dh-kex-p (name)
  "Whether NAME is a fixed-group Diffie-Hellman key exchange."
  (and (ssh-dh-group-parameters name) t))

(defun ssh-dh-random-exponent (bits)
  "A random exponent of BITS bits, with the top bit set.

OpenSSH doubles the negotiated security level for its exponent and never
uses fewer than 256 bits; 512 bits keeps a 2048-bit group comfortably in
that range without making every exchange expensive."
  (let* ((width (min 512 (1- bits)))
         (value (ssh-mpint-integer (ssh-random-octets (ceiling width 8)))))
    (logior value (ash 1 (1- width)))))

(defun ssh-dh-keypair-for-group (prime bits &optional (generator 2))
  "A fresh keypair for PRIME as (VALUES PRIVATE-EXPONENT PUBLIC-ELEMENT).

GENERATOR is the group's generator, which RFC 4419 lets a server choose
freely; the RFC 3526 groups this build carries use 2, but a moduli file may
name 5."
  (loop
    (let* ((exponent (ssh-dh-random-exponent bits))
           (public (ironclad-unsafe:expt-mod generator exponent prime)))
      ;; RFC 4253 requires 1 < e < p-1; the generator can in principle
      ;; land on a small subgroup, so a fresh exponent is the safe answer.
      (when (and (< 1 public) (< public (1- prime)))
        (return (values exponent public))))))

(defun ssh-dh-shared-for-group (private peer-public prime)
  "The shared secret K = PEER-PUBLIC^PRIVATE mod PRIME, as mpint octets."
  (unless (and (integerp peer-public)
               (< 1 peer-public)
               (< peer-public (1- prime)))
    (error 'ssh-protocol-error
           :detail "invalid Diffie-Hellman public key"))
  (ssh-mpint-octets (ironclad-unsafe:expt-mod peer-public private prime)))

(defun ssh-dh-keypair (kex)
  "A fresh fixed-group keypair as (VALUES PRIVATE-EXPONENT PUBLIC-ELEMENT).

PUBLIC-ELEMENT is the integer e = g^x mod p that goes on the wire as an
mpint."
  (multiple-value-bind (prime bits)
      (ssh-dh-group-parameters kex)
    (unless prime
      (error 'ssh-protocol-error
             :detail (format nil "unsupported Diffie-Hellman key exchange ~A"
                             kex)))
    (ssh-dh-keypair-for-group prime bits)))

(defun ssh-dh-shared (private peer-public kex)
  "The shared secret K = PEER-PUBLIC^PRIVATE mod p, as mpint octets."
  (multiple-value-bind (prime)
      (ssh-dh-group-parameters kex)
    (unless prime
      (error 'ssh-protocol-error
             :detail (format nil "unsupported Diffie-Hellman key exchange ~A"
                             kex)))
    (ssh-dh-shared-for-group private peer-public prime)))

;;; ---- Group-exchange Diffie-Hellman (diffie-hellman-group-exchange-sha*) ----
;;;
;;; RFC 4419 lets the client ask for a group size rather than naming a fixed
;;; group.  The server answers with a safe prime and generator from its own
;;; set, and the exchange then runs exactly like a fixed-group one.  This
;;; build offers the RFC 3526 groups it already carries, so no moduli file is
;;; needed.

(defparameter +ssh-gex-min-bits+ 2048)
(defparameter +ssh-gex-preferred-bits+ 4096)
(defparameter +ssh-gex-max-bits+ 8192)

(defparameter +ssh-gex-groups+
  (list (list +ssh-dh-group14-prime+ 2048)
        (list +ssh-dh-group16-prime+ 4096)
        (list +ssh-dh-group18-prime+ 8192))
  "The safe-prime groups offered for RFC 4419 group exchange.")

(defun ssh-gex-kex-parameters (kex)
  "The digest of the group-exchange KEX, or NIL when KEX is not one."
  (cond ((and (stringp kex)
              (string= kex "diffie-hellman-group-exchange-sha256"))
         :sha256)
        ((and (stringp kex)
              (string= kex "diffie-hellman-group-exchange-sha1"))
         :sha1)
        (t nil)))

(defun ssh-gex-kex-p (name)
  "Whether NAME is a group-exchange key exchange."
  (and (stringp name) (ssh-gex-kex-parameters name) t))

(defun ssh-gex-choose-group (min preferred max)
  "The (VALUES PRIME BITS) closest to PREFERRED within MIN..MAX.

The smallest group at least as large as PREFERRED wins, so a client that
asks for a stronger group never gets a weaker one; only when none is large
enough does the largest available group answer.  Answers NIL when no group
fits."
  (let ((above nil)
        (below nil))
    (dolist (entry +ssh-gex-groups+)
      (let ((bits (second entry)))
        (when (and (<= min bits) (<= bits max))
          (cond ((>= bits preferred)
                 (when (or (null above) (< bits (second above)))
                   (setf above entry)))
                (t
                 (when (or (null below) (> bits (second below)))
                   (setf below entry)))))))
    (let ((best (or above below)))
      (values (first best) (second best)))))

(defun ssh-gex-keypair (prime generator)
  "A fresh group-exchange keypair for PRIME and GENERATOR."
  (ssh-dh-keypair-for-group prime (integer-length prime) generator))

(defun ssh-gex-shared (private peer-public prime)
  "The group-exchange shared secret, as mpint octets."
  (ssh-dh-shared-for-group private peer-public prime))

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
