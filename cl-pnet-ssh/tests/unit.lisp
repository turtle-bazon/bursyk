(in-package #:cl-user)

(defpackage #:cl-pnet-ssh-tests
  (:use #:cl #:fiveam #:cl-pnet-ssh))

(in-package #:cl-pnet-ssh-tests)

(def-suite cl-pnet-ssh :description "SSH client unit and live tests")
(in-suite cl-pnet-ssh)

;;; ---- helpers ----

(defun hex-octets (string)
  (let* ((length (/ (length string) 2))
         (out (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length out)
      (setf (aref out i)
            (parse-integer string :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun octets-hex (octets)
  (format nil "~{~2,'0X~}" (coerce octets 'list)))

(defun octets-ascii (string)
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

(defun concatenated (&rest sequences)
  (let ((out (make-array (reduce #'+ sequences :key #'length)
                         :element-type '(unsigned-byte 8)))
        (offset 0))
    (dolist (sequence sequences out)
      (replace out sequence :start1 offset)
      (incf offset (length sequence)))))

;;; ---- wire types ----

(test wire-uint-round-trips
  (is (= #xDEADBEEF (ssh-octets-uint32 (ssh-uint32-octets #xDEADBEEF))))
  (is (= #x0123456789ABCDEF
         (ssh-octets-uint64 (ssh-uint64-octets #x0123456789ABCDEF)))))

(test wire-mpint-encoding
  (is (equalp #() (ssh-mpint-octets 0)))
  (is (equalp (hex-octets "01") (ssh-mpint-octets 1)))
  (is (equalp (hex-octets "00FF") (ssh-mpint-octets 255))
      "a high bit gets a leading zero")
  (is (= 255 (ssh-mpint-integer (hex-octets "00FF")))))

(test wire-reader-and-writer
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer 7)
    (ssh-write-u32 writer 70000)
    (ssh-write-text writer "hello")
    (ssh-write-name-list writer '("a" "b"))
    (let ((reader (ssh-make-reader (ssh-writer-output writer))))
      (is (= 7 (ssh-read-u8 reader)))
      (is (= 70000 (ssh-read-u32 reader)))
      (is (string= "hello" (ssh-read-text reader)))
      (is (equal '("a" "b") (ssh-read-name-list reader)))
      (is (zerop (ssh-reader-remaining reader))))))

(test wire-truncated-message-signals
  (signals ssh-protocol-error
    (ssh-read-u32 (ssh-make-reader (hex-octets "0102")))))

;;; ---- ChaCha20 known answers ----
;;;
;;; With an all-zero key and nonce these blocks are the same for RFC 8439's
;;; 12-octet nonce and SSH's 8-octet one, so they pin the core rounds.

(test chacha20-zero-key-counter-zero
  (is (equalp (hex-octets
               (concatenate
                'string
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"))
              (ssh-chacha20-block (make-array 32 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                                  (make-array 8 :element-type '(unsigned-byte 8)
                                                :initial-element 0)
                                  0))))

(test chacha20-zero-key-counter-one
  (is (equalp (hex-octets
               (concatenate
                'string
                "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
                "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"))
              (ssh-chacha20-block (make-array 32 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                                  (make-array 8 :element-type '(unsigned-byte 8)
                                                :initial-element 0)
                                  1))))

(test chacha20-xor-round-trips
  (let* ((key (ssh-random-octets 32))
         (nonce (ssh-random-octets 8))
         (data (ssh-random-octets 150))
         (sealed (ssh-chacha20-xor key nonce 1 data)))
    (is (equalp data (ssh-chacha20-xor key nonce 1 sealed)))))

;;; ---- Poly1305 and X25519 known answers ----

(test poly1305-rfc8439-vector
  (let ((key (hex-octets "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"))
        (message (octets-ascii "Cryptographic Forum Research Group")))
    (is (equalp (hex-octets "a8061dc1305136c6c22b8baf0c0127a9")
                (ssh-poly1305 key message)))))

(test x25519-rfc7748-vector
  (let* ((alice-private (hex-octets "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
         (bob-private (hex-octets "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
         (alice-public (hex-octets "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
         (bob-public (hex-octets "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
         (shared (hex-octets "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")))
    (is (equalp alice-public
                (ironclad-unsafe:curve25519-public-key alice-private)))
    (is (equalp shared (ssh-curve25519-shared alice-private bob-public)))
    (is (equalp shared (ssh-curve25519-shared bob-private alice-public)))))

;;; ---- Ed25519 signatures ----

(test ed25519-sign-and-verify
  (multiple-value-bind (private public)
      (ironclad-unsafe:generate-key-pair :ed25519)
    (let* ((raw-public (ironclad-unsafe:ed25519-key-y public))
           (message (ssh-random-octets 64))
           (signature (ironclad-unsafe:sign-message private message)))
      (is (ssh-ed25519-verify signature message raw-public))
      (setf (aref message 0) (logxor 1 (aref message 0)))
      (is (not (ssh-ed25519-verify signature message raw-public))))))

;;; ---- Packet framing ----

(test plain-packet-round-trip
  (let* ((send (ssh-make-cipher-state))
         (receive (ssh-make-cipher-state))
         (payload (concatenated (hex-octets "14") (ssh-random-octets 37)))
         (wire (ssh-encode-packet payload send)))
    (multiple-value-bind (decoded consumed) (ssh-decode-packet wire receive)
      (is (equalp payload decoded))
      (is (= (length wire) consumed))
      (is (= 1 (ssh-cipher-state-send-sequence send)))
      (is (= 1 (ssh-cipher-state-receive-sequence receive))))))

(test aead-packet-round-trip
  (let* ((key (ssh-random-octets 64))
         (send (ssh-make-cipher-state))
         (receive (ssh-make-cipher-state))
         (payload (concatenated (hex-octets "5e") (ssh-random-octets 300))))
    (ssh-install-keys send :encrypt key :aead t)
    (ssh-install-keys receive :decrypt key :aead t)
    (let ((wire (ssh-encode-packet payload send)))
      (is (not (equalp payload wire)))
      (multiple-value-bind (decoded consumed) (ssh-decode-packet wire receive)
        (is (equalp payload decoded))
        (is (= (length wire) consumed))))))

(test aead-packet-detects-tampering
  (let* ((key (ssh-random-octets 64))
         (send (ssh-make-cipher-state))
         (receive (ssh-make-cipher-state))
         (wire (progn (ssh-install-keys send :encrypt key :aead t)
                      (ssh-encode-packet (hex-octets "15") send))))
    (ssh-install-keys receive :decrypt key :aead t)
    (setf (aref wire 5) (logxor 1 (aref wire 5)))
    (signals ssh-protocol-error (ssh-decode-packet wire receive))))

(test incomplete-packet-is-not-an-error
  (let* ((state (ssh-make-cipher-state))
         (wire (ssh-encode-packet (hex-octets "15") state)))
    (multiple-value-bind (payload consumed)
        (ssh-decode-packet (subseq wire 0 (1- (length wire)))
                           (ssh-make-cipher-state))
      (is (eq :incomplete payload))
      (is (zerop consumed)))))

(test aead-short-buffer-is-incomplete
  (let ((state (ssh-make-cipher-state)))
    (ssh-install-keys state :decrypt (ssh-random-octets 64) :aead t)
    (dolist (size '(0 3))
      (multiple-value-bind (payload consumed)
          (ssh-decode-packet (make-array size
                                         :element-type '(unsigned-byte 8))
                             state)
        (is (eq :incomplete payload))
        (is (zerop consumed))))))

(test aead-padding-aligns-the-encrypted-length
  (let* ((key (ssh-random-octets 64))
         (send (ssh-make-cipher-state))
         (payload (concatenated (hex-octets "5e") (ssh-random-octets 31))))
    (ssh-install-keys send :encrypt key :aead t)
    (let* ((wire (ssh-encode-packet payload send))
           (length (ssh-chacha-decrypt-length
                    (ssh-cipher-state-encrypt send) 0 wire)))
      ;; The length field is not part of the encrypted stream, so OpenSSH
      ;; aligns the body alone (packet.c: len -= aadlen).
      (is (zerop (mod length +ssh-block-size+)))
      (is (>= length (+ 1 (length payload) 4))))))

(test plain-padding-aligns-the-whole-packet
  (let* ((state (ssh-make-cipher-state))
         (payload (concatenated (hex-octets "14") (ssh-random-octets 30)))
         (wire (ssh-encode-packet payload state))
         (length (ssh-octets-uint32 wire)))
    (is (zerop (mod (+ 4 length) +ssh-block-size+)))
    (is (>= length (+ 1 (length payload) 4)))))

(test install-keys-leaves-the-other-direction-alone
  (let* ((encrypt-key (ssh-random-octets 64))
         (decrypt-key (ssh-random-octets 64))
         (state (ssh-make-cipher-state)))
    (ssh-install-keys state :encrypt encrypt-key :aead t)
    (ssh-install-keys state :decrypt decrypt-key :aead t)
    (let ((encrypt (ssh-cipher-state-encrypt state))
          (decrypt (ssh-cipher-state-decrypt state)))
      (is (equalp (ssh-chacha-packet-key-payload-key encrypt)
                  (subseq encrypt-key 0 32)))
      (is (equalp (ssh-chacha-packet-key-length-key decrypt)
                  (subseq decrypt-key 32 64))))))

(test derive-key-chains-blocks-without-the-session-id
  (let* ((shared (ssh-random-octets 32))
         (exchange-hash (ssh-random-octets 32))
         (session-id (ssh-random-octets 32))
         (k (let ((writer (ssh-writer)))
              (ssh-write-mpint writer (ssh-mpint-integer shared))
              (ssh-writer-output writer)))
         (k1 (ssh-hash :sha256 k exchange-hash (hex-octets "44") session-id))
         (k2 (ssh-hash :sha256 k exchange-hash k1)))
    (is (equalp (ssh-derive-key shared exchange-hash session-id #\D 64)
                (ssh-concat k1 k2)))))

;;; ---- Rekey ----

(defun kexinit-message-types (already-sent)
  "Types of the messages HANDLE-KEXINIT sends when our KEXINIT was ALREADY-SENT."
  (let ((sent '())
        (client (cl-pnet-ssh::%make-ssh-client)))
    (setf (cl-pnet-ssh::ssh-client-kexinit-sent client) already-sent)
    (let ((original (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)))
      (unwind-protect
           (progn
             (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                   (lambda (client payload)
                     (declare (ignore client))
                     (push (aref payload 0) sent)
                     t))
             (cl-pnet-ssh::ssh-client-handle-kexinit
              client (ssh-make-kexinit-payload)))
        (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload) original)))
    (nreverse sent)))

(test rekey-sends-our-kexinit-before-ecdh-init
  ;; A server-initiated exchange has not seen our KEXINIT yet, so both go out;
  ;; the initial exchange already sent ours and only needs the ECDH half.
  (is (equal (kexinit-message-types nil)
             (list cl-pnet-ssh::+ssh-msg-kexinit+
                   cl-pnet-ssh::+ssh-msg-kex-ecdh-init+)))
  (is (equal (kexinit-message-types t)
             (list cl-pnet-ssh::+ssh-msg-kex-ecdh-init+))))

(test plain-hmac-packet-round-trip
  (let* ((mac-key (ssh-random-octets 32))
         (send (ssh-make-cipher-state))
         (receive (ssh-make-cipher-state))
         (payload (hex-octets "16010203")))
    (ssh-install-keys send :encrypt-mac-key mac-key :encrypt-mac :sha256)
    (ssh-install-keys receive :decrypt-mac-key mac-key :decrypt-mac :sha256)
    (let ((wire (ssh-encode-packet payload send)))
      (multiple-value-bind (decoded consumed) (ssh-decode-packet wire receive)
        (is (equalp payload decoded))
        (is (= (length wire) consumed))))))

;;; ---- Private keys ----

(defun ssh-keygen-available-p ()
  (handler-case
      (zerop (nth-value 2 (uiop:run-program '("sh" "-c" "command -v ssh-keygen")
                                            :ignore-error-status t
                                            :output nil :error-output nil)))
    (error () nil)))

(defun ssh-keygen (arguments)
  (uiop:run-program (cons "ssh-keygen" arguments)
                    :output :string :error-output :string))

(defun ssh-test-directory (prefix)
  "A fresh temporary directory name unique to this process and second."
  (merge-pathnames
   (format nil "~A-~D-~D/" prefix (get-universal-time) (random 1000000))
   (uiop:temporary-directory)))

(test openssh-private-key-round-trip
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-test"))
             (path (merge-pathnames "id_ed25519" directory)))
        (ensure-directories-exist path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" "" "-f" (namestring path)))
               (let* ((key (ssh-load-private-key path))
                      (blob (ssh-public-key-blob-of key))
                      (parts (multiple-value-list (ssh-public-key-parts blob))))
                 (is (string= "ssh-ed25519" (first parts)))
                 (is (= 32 (length (second parts))))
                 (is (string= "SHA256:" (subseq (ssh-key-fingerprint blob) 0 7)))
                 (let ((signature (ssh-ed25519-signature-blob key (octets-ascii "data"))))
                   (multiple-value-bind (algorithm bytes)
                       (ssh-parse-signature-blob signature)
                     (is (string= "ssh-ed25519" algorithm))
                     (is (ssh-ed25519-verify bytes (octets-ascii "data")
                                             (second parts)))))))
          (ignore-errors (delete-directory-tree directory :validate t))))))

;;; ---- known_hosts ----

(defun ssh-test-known-host-blob ()
  (ssh-make-public-key-blob "ssh-ed25519" (ssh-random-octets 32)))

(test known-hosts-plain-and-wildcard
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-kh"))
         (file (merge-pathnames "known_hosts" directory))
         (blob (ssh-test-known-host-blob)))
    (ensure-directories-exist file)
    (unwind-protect
         (progn
           (ssh-remember-known-host file "example.org" "ssh-ed25519" blob)
           (is (eq :match (ssh-known-host-status file "example.org" blob)))
           (is (eq :unknown (ssh-known-host-status file "other.org" blob)))
           (ssh-remember-known-host file "*.example.com" "ssh-ed25519" blob)
           (is (eq :match (ssh-known-host-status file "a.example.com" blob)))
           (is (eq :mismatch
                   (ssh-known-host-status file "example.org"
                                          (ssh-test-known-host-blob)))))
      (ignore-errors (delete-directory-tree directory :validate t)))))

(test known-hosts-hashed-entry
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-khh"))
         (file (merge-pathnames "known_hosts" directory))
         (blob (ssh-test-known-host-blob))
         (salt (ssh-random-octets 20))
         (hash (ssh-hmac salt (ssh-string-octets "hashed.example:2222") :sha1)))
    (ensure-directories-exist file)
    (unwind-protect
         (progn
           (with-open-file (stream file :direction :output :if-exists :overwrite
                                        :if-does-not-exist :create)
             (format stream "|1|~A|~A ssh-ed25519 ~A~%"
                     (ssh-octets-base64 salt)
                     (ssh-octets-base64 hash)
                     (ssh-octets-base64 blob)))
           (is (eq :match (ssh-known-host-status file "hashed.example:2222" blob)))
           (is (eq :unknown (ssh-known-host-status file "hashed.example:2223" blob))))
      (ignore-errors (delete-directory-tree directory :validate t)))))
