(in-package #:cl-user)

(defpackage #:cl-pnet-ssh-tests
  (:use #:cl #:fiveam #:iterate #:cl-pnet-ssh))

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
;;; These two tests replace functions inside the pure client transport.  The
;;; libssh backend has a different transport, so they only exist there.

#-ssh-backend-ffi
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

#-ssh-backend-ffi
(test rekey-sends-our-kexinit-before-ecdh-init
  ;; A server-initiated exchange has not seen our KEXINIT yet, so both go out;
  ;; the initial exchange already sent ours and only needs the ECDH half.
  (is (equal (kexinit-message-types nil)
             (list cl-pnet-ssh::+ssh-msg-kexinit+
                   cl-pnet-ssh::+ssh-msg-kex-ecdh-init+)))
  (is (equal (kexinit-message-types t)
             (list cl-pnet-ssh::+ssh-msg-kex-ecdh-init+))))

#+ssh-backend-ffi
(test rekey-sends-our-kexinit-before-ecdh-init
  (skip "the pure client transport is not built"))

#-ssh-backend-ffi
(test strict-kex-survives-a-rekey
  "The strict-KEX marker appears only in the first KEXINIT.
OpenSSH keeps resetting sequence numbers at every NEWKEYS, so dropping the
flag at a rekey would make the two sides count packets differently."
  (flet ((strict-after (initial negotiated)
           (let ((client (cl-pnet-ssh::%make-ssh-client)))
             (setf (cl-pnet-ssh::ssh-client-strict-kex client) initial)
             (let ((original-negotiate
                     (symbol-function 'cl-pnet-ssh::ssh-negotiate))
                   (original-send
                     (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)))
               (unwind-protect
                    (progn
                      (setf (symbol-function 'cl-pnet-ssh::ssh-negotiate)
                            (lambda (offers &rest arguments)
                              (declare (ignore offers arguments))
                              (list :kex "curve25519-sha256"
                                    :host-key "ssh-ed25519"
                                    :cipher-c2s "chacha20-poly1305@openssh.com"
                                    :cipher-s2c "chacha20-poly1305@openssh.com"
                                    :mac-c2s "hmac-sha2-256"
                                    :mac-s2c "hmac-sha2-256"
                                    :compression "none"
                                    :strict negotiated)))
                      (setf (symbol-function
                             'cl-pnet-ssh::ssh-client-send-payload)
                            (lambda (client payload)
                              (declare (ignore client payload))
                              t))
                      (cl-pnet-ssh::ssh-client-handle-kexinit
                       client (ssh-make-kexinit-payload))
                      (cl-pnet-ssh::ssh-client-strict-kex client))
                 (setf (symbol-function 'cl-pnet-ssh::ssh-negotiate)
                       original-negotiate
                       (symbol-function
                        'cl-pnet-ssh::ssh-client-send-payload)
                       original-send))))))
    (is (eq t (strict-after nil t)))
    (is (eq t (strict-after t nil)))
    (is (null (strict-after nil nil)))))

(test disconnect-description-is-a-wire-string
  ;; RFC 4253 section 11.1: reason, then a length-prefixed description and
  ;; language tag.  Sending the description as bare UTF-8 makes the peer read
  ;; its first four bytes as the length and fail with "string is too large".
  (let ((reader (ssh-make-reader
                 (cl-pnet-ssh::ssh-disconnect-payload "client closed"))))
    (is (= cl-pnet-ssh::+ssh-msg-disconnect+ (ssh-read-u8 reader)))
    (is (= cl-pnet-ssh::+ssh-disconnect-by-application+
           (ssh-read-u32 reader)))
    (is (string= "client closed" (ssh-read-text reader)))
    (is (string= "" (ssh-read-text reader)))
    (is (zerop (ssh-reader-remaining reader)))))

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
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test openssh-private-key-passphrase-round-trip
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-enc"))
             (path (merge-pathnames "id_ed25519" directory)))
        (ensure-directories-exist path)
        (unwind-protect
             (progn
               (ssh-keygen
                (list "-q" "-t" "ed25519" "-N" "secret" "-f" (namestring path)))
               (let* ((key (ssh-load-private-key path :passphrase "secret"))
                      (blob (ssh-public-key-blob-of key)))
                 (is (string= "ssh-ed25519"
                              (nth-value 0 (ssh-public-key-parts blob))))
                 (let ((signature (ssh-ed25519-signature-blob
                                   key (octets-ascii "locked"))))
                   (multiple-value-bind (algorithm bytes)
                       (ssh-parse-signature-blob signature)
                     (declare (ignore algorithm))
                     (is (ssh-ed25519-verify
                          bytes (octets-ascii "locked")
                          (nth-value 1 (ssh-public-key-parts blob))))))
                 (signals ssh-authentication-error
                   (ssh-load-private-key path :passphrase "wrong"))
                 (signals ssh-authentication-error
                   (ssh-load-private-key path))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

;;; ---- OpenSSH certificates ----

(defun ssh-test-public-key-blob (path)
  "The public key blob on the first line of PATH's key file."
  (let ((line (with-open-file (stream path :direction :input)
                (read-line stream))))
    (ssh-base64-octets (second (uiop:split-string line :separator " ")))))

(defun ssh-test-certificate-blob (path)
  "The certificate blob in PATH's .pub file."
  (ssh-test-public-key-blob path))

(test user-certificates-parse-verify-and-authorize
  "A CA-signed user certificate carries the right fields, verifies against
its CA, and is admitted only for a principal and address its options allow."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-cert"))
             (ca (merge-pathnames "ca" directory))
             (user (merge-pathnames "user" directory))
             (ca-pub (merge-pathnames "ca.pub" directory)))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ca)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring user)))
               (ssh-keygen
                (list "-q" "-s" (namestring ca) "-I" "test-id"
                      "-n" "alice,bob" "-V" "-1m:+52w"
                      "-O" "clear" "-O" "permit-pty"
                      "-O" "force-command=echo certified"
                      "-O" "source-address=127.0.0.1/32"
                      (namestring (merge-pathnames "user.pub" directory))))
               (let* ((cert-blob
                        (ssh-test-certificate-blob
                         (merge-pathnames "user-cert.pub" directory)))
                      (certificate (ssh-certificate-parse cert-blob))
                      (ca-blob (ssh-test-public-key-blob ca-pub))
                      (plain-blob (ssh-test-public-key-blob
                                   (merge-pathnames "user.pub" directory))))
                 (is (ssh-certificate-blob-p cert-blob))
                 (is (string= "test-id"
                              (ssh-certificate-key-id (ssh-certificate-parse cert-blob))))
                 (is (string= "ssh-ed25519-cert-v01@openssh.com"
                              (ssh-certificate-key-type certificate)))
                 (is (string= "ssh-ed25519"
                              (ssh-certificate-plain-key-type certificate)))
                 (is (= 1 (ssh-certificate-cert-type certificate)))
                 (is (string= "test-id"
                              (ssh-certificate-key-id certificate)))
                 (is (equal '("alice" "bob")
                            (ssh-certificate-principals certificate)))
                 (is (ssh-certificate-signature-valid-p certificate))
                 (is (string= "echo certified"
                              (cdr (assoc "force-command"
                                          (ssh-certificate-critical certificate)
                                          :test #'string=))))
                 (is (string= "127.0.0.1/32"
                              (cdr (assoc "source-address"
                                          (ssh-certificate-critical certificate)
                                          :test #'string=))))
                 ;; The certified key is what a userauth signature uses.
                 (is (equalp plain-blob (ssh-key-plain-blob cert-blob)))
                 (is (equalp plain-blob
                             (ssh-certificate-plain-key-blob cert-blob)))
                 (multiple-value-bind (valid options)
                     (ssh-certificate-check certificate "alice"
                                            :address "127.0.0.1")
                   (is (not (null valid)))
                   (is (ssh-authorization-options-permit-pty-p options))
                   ;; The certificate grants only pty.
                   (is (not (ssh-authorization-options-permit-port-forwarding-p
                             options)))
                   (is (string= "echo certified"
                                (ssh-authorization-options-force-command
                                 options))))
                 ;; source-address and the principal list are enforced.
                 (is (null (ssh-certificate-check certificate "alice"
                                                  :address "10.0.0.1")))
                 (is (null (ssh-certificate-check certificate "carol")))
                 ;; TrustedUserCAKeys alone: the user name must be a
                 ;; principal when no principals file is in use.
                 (multiple-value-bind (matched environments options)
                     (ssh-certificate-user-authorized-p
                      "alice" cert-blob
                      :address "127.0.0.1"
                      :ca-keys (namestring ca-pub))
                   (declare (ignore environments))
                   (is (not (null matched)))
                   (is (string= "echo certified"
                                (ssh-authorization-options-force-command
                                 options))))
                 (is (null (ssh-certificate-user-authorized-p
                            "carol" cert-blob
                            :address "127.0.0.1"
                            :ca-keys (namestring ca-pub))))
                 ;; A CA not in the trusted file authorizes nothing.
                 (is (null (ssh-certificate-user-authorized-p
                            "alice" cert-blob
                            :address "127.0.0.1"
                            :ca-keys (namestring
                                      (merge-pathnames "user.pub" directory)))))
                 ;; An authorized_keys cert-authority line works the same way.
                 (let ((line (format nil "cert-authority,principals=\"alice,bob\" ~A"
                                     (with-open-file (stream ca-pub)
                                       (read-line stream)))))
                   (is (not (null (nth-value 0
                                             (ssh-certificate-authorized-key-match
                                              line certificate "alice"
                                              :address "127.0.0.1")))))
                   ;; A line that names other principals refuses this cert.
                   (let ((other (format nil "cert-authority,principals=\"carol\" ~A"
                                        (with-open-file (stream ca-pub)
                                          (read-line stream)))))
                     (is (null (ssh-certificate-authorized-key-match
                                other certificate "alice"
                                :address "127.0.0.1"))))
                   ;; The CA key itself cannot log in on a cert-authority line.
                   (is (null (ssh-authorized-key-blob-match
                              line ca-blob :address "127.0.0.1"))))
                 ;; An expired certificate is refused.
                 (let ((old (merge-pathnames "old" directory)))
                   (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                     "-f" (namestring old)))
                   (ssh-keygen
                    (list "-q" "-s" (namestring ca) "-I" "old-id"
                          "-n" "alice" "-V" "-2h:-1h"
                          (namestring (merge-pathnames "old.pub" directory))))
                   (is (null (ssh-certificate-check
                              (ssh-certificate-parse
                               (ssh-test-certificate-blob
                                (merge-pathnames "old-cert.pub" directory)))
                              "alice" :address "127.0.0.1"))))
                 ;; A host certificate is not a user certificate.
                 (let ((host (merge-pathnames "host" directory)))
                   (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                     "-f" (namestring host)))
                   (ssh-keygen
                    (list "-q" "-s" (namestring ca) "-h" "-I" "host-id"
                          "-n" "example.org" "-V" "-1m:+52w"
                          (namestring (merge-pathnames "host.pub" directory))))
                   (let ((host-certificate
                           (ssh-certificate-parse
                            (ssh-test-certificate-blob
                             (merge-pathnames "host-cert.pub" directory)))))
                     (is (= 2 (ssh-certificate-cert-type host-certificate)))
                     (is (null (ssh-certificate-check host-certificate
                                                      "example.org")))))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test certificate-option-merge-follows-sshd
  "Permission flags are ANDed, restrictive values are combined, and two
different force-command clauses cannot be merged."
  (let* ((primary (nth-value 0
                             (ssh-authorized-key-options-parse
                              "no-pty,command=\"one\",permitopen=\"db:5432\"")))
         (additional (ssh-certificate-authorization-options-empty)))
    (setf (ssh-authorization-options-permit-pty additional) t
          (ssh-authorization-options-permit-port-forwarding additional) t)
    (let ((merged (ssh-authorization-options-merge primary additional)))
      (is (not (null merged)))
      ;; no-pty withholds pty even though the certificate grants it.
      (is (not (ssh-authorization-options-permit-pty-p merged)))
      ;; The certificate grants port forwarding and the line does not deny it.
      (is (ssh-authorization-options-permit-port-forwarding-p merged))
      (is (string= "one"
                   (ssh-authorization-options-force-command merged)))
      (is (equal '(("db" . 5432))
                 (ssh-authorization-options-permit-open merged))))
    (setf (ssh-authorization-options-force-command additional) "two")
    (is (null (ssh-authorization-options-merge primary additional)))))

(test client-offers-the-certificate-beside-its-private-key
  "ssh -i KEY offers KEY-cert.pub when it is the certificate of KEY, and
refuses to pair a certificate with a different key."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-client-cert"))
             (ca (merge-pathnames "ca" directory))
             (user (merge-pathnames "user" directory)))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ca)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring user)))
               (ssh-keygen
                (list "-q" "-s" (namestring ca) "-I" "client-id"
                      "-n" "turtle" "-V" "-1m:+52w"
                      (namestring (merge-pathnames "user.pub" directory))))
               (let* ((cert-blob
                        (ssh-test-certificate-blob
                         (merge-pathnames "user-cert.pub" directory)))
                      (signer
                        (ssh-private-key-signer
                         (ssh-load-private-key user))))
                 (is (string= "ssh-ed25519-cert-v01@openssh.com"
                              (cl-pnet-ssh::ssh-signer-type signer)))
                 (is (equalp cert-blob
                             (cl-pnet-ssh::ssh-signer-blob signer))))
               ;; A certificate for another key is refused, not silently
               ;; ignored: that would authenticate as someone else.
               (let ((other (merge-pathnames "other" directory)))
                 (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                   "-f" (namestring other)))
                 (ssh-keygen
                  (list "-q" "-s" (namestring ca) "-I" "other-id"
                        "-n" "turtle" "-V" "-1m:+52w"
                        (namestring (merge-pathnames "other.pub" directory))))
                 (ignore-errors
                   (delete-file (merge-pathnames "user-cert.pub" directory)))
                 (rename-file
                  (merge-pathnames "other-cert.pub" directory)
                  (merge-pathnames "user-cert.pub" directory))
                 (let ((mismatch
                         (handler-case
                             (progn (ssh-private-key-signer
                                     (ssh-load-private-key user))
                                    nil)
                           (error () t))))
                   (is (not (null mismatch))))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))


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
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

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
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

;; Both backends accept a list of known-hosts files, as ssh_config's
;; UserKnownHostsFile and GlobalKnownHostsFile produce, and a key found in
;; either one is trusted.
(defun client-known-host-status-for (client blob)
  #+ssh-backend-ffi (cl-pnet-ssh::ssh-plibssh-known-host-status client blob)
  #-ssh-backend-ffi (cl-pnet-ssh::ssh-client-known-host-status client blob))

(defun client-remember-host-key-for (client blob)
  #+ssh-backend-ffi (cl-pnet-ssh::ssh-plibssh-remember-host-key client blob)
  #-ssh-backend-ffi (cl-pnet-ssh::ssh-client-remember-host-key client blob))

(defun client-host-spec-for (client)
  #+ssh-backend-ffi (cl-pnet-ssh::ssh-plibssh-host-spec client)
  #-ssh-backend-ffi (cl-pnet-ssh::ssh-client-host-spec client))

(defun client-accept-unknown-host-key-for (client blob fingerprint)
  #+ssh-backend-ffi
  (cl-pnet-ssh::ssh-plibssh-accept-unknown-host-key client blob fingerprint)
  #-ssh-backend-ffi
  (cl-pnet-ssh::ssh-client-accept-unknown-host-key client blob fingerprint))

(test client-known-hosts-uses-the-host-name-for-an-alias
  "A config alias is checked and recorded under its HostName.

OpenSSH treats \"Host gh / HostName github.com\" as a connection to
github.com for known_hosts: an existing github.com entry must match the
alias, and trust-on-first-use must write github.com, not gh."
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-alias"))
         (file (merge-pathnames "known_hosts" directory))
         (blob (ssh-test-known-host-blob))
         (client (cl-pnet-ssh::%make-ssh-client
                  :host "gh" :connect-host "github.com"
                  :host-key-host "github.com"
                  :port 22
                  :known-hosts (list file))))
    (ensure-directories-exist file)
    (unwind-protect
         (progn
           (is (string= "github.com" (client-host-spec-for client)))
           (ssh-remember-known-host file "github.com" "ssh-ed25519" blob)
           (is (eq :match (client-known-host-status-for client blob))
               "the entry under the HostName was not found")
           ;; Without the override the alias is what gets looked up, so
           ;; nothing is found for the alias.
           (let ((alias-only (cl-pnet-ssh::%make-ssh-client
                              :host "gh" :connect-host "github.com"
                              :port 22 :known-hosts (list file))))
             (is (eq :unknown (client-known-host-status-for alias-only blob)))
             ;; Trust-on-first-use records the HostName too.
             (let ((trusted (ssh-test-known-host-blob)))
               (client-remember-host-key-for client trusted)
               (is (eq :match (ssh-known-host-status file "github.com"
                                                     trusted)))
               (is (eq :unknown (ssh-known-host-status file "gh" trusted))))
             ;; An entry under the alias does not satisfy the override
             ;; client, which looks under the HostName; the alias-only
             ;; client does see it.
             (let ((fresh (ssh-test-known-host-blob)))
               (ssh-remember-known-host file "gh" "ssh-ed25519" fresh)
               (is (eq :mismatch (client-known-host-status-for client fresh))
                   "the alias entry was consulted instead of the HostName's")
               (is (eq :match (client-known-host-status-for alias-only fresh))))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test client-rejected-host-key-signals
  "A policy callback that declines an unknown key must refuse the connection.

Returning false is the answer \"no\" to the host-key prompt; silently
connecting without recording the key would be the opposite of what the
caller asked for."
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-reject"))
         (file (merge-pathnames "known_hosts" directory))
         (blob (ssh-test-known-host-blob))
         (fingerprint (ssh-key-fingerprint blob))
         (client (cl-pnet-ssh::%make-ssh-client
                  :host "example.org" :port 22
                  :known-hosts (list file)
                  :host-key-policy (lambda (client fingerprint key)
                                     (declare (ignore client fingerprint key))
                                     nil))))
    (ensure-directories-exist file)
    (unwind-protect
         (progn
           (signals ssh-host-key-error
             (client-accept-unknown-host-key-for client blob fingerprint))
           (is (eq :unknown (client-known-host-status-for client blob))
               "a rejected key was recorded anyway"))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test client-accepted-host-key-is-recorded
  "A policy callback that accepts an unknown key records it and does not
signal, so the override still works."
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-accept"))
         (file (merge-pathnames "known_hosts" directory))
         (blob (ssh-test-known-host-blob))
         (client (cl-pnet-ssh::%make-ssh-client
                  :host "example.org" :port 22
                  :known-hosts (list file)
                  :host-key-policy (lambda (client fingerprint key)
                                     (declare (ignore client fingerprint key))
                                     t))))
    (ensure-directories-exist file)
    (unwind-protect
         (progn
           (client-accept-unknown-host-key-for client blob
                                               (ssh-key-fingerprint blob))
           (is (eq :match (client-known-host-status-for client blob))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test client-known-hosts-checks-every-file
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-khm"))
         (first-file (merge-pathnames "user_known_hosts" directory))
         (second-file (merge-pathnames "global_known_hosts" directory))
         (blob (ssh-test-known-host-blob))
         (other (ssh-test-known-host-blob))
         (client (cl-pnet-ssh::%make-ssh-client
                  :host "example.org" :port 22
                  :known-hosts (list first-file second-file))))
    (ensure-directories-exist first-file)
    (unwind-protect
         (progn
           (ssh-remember-known-host first-file "example.org"
                                    "ssh-ed25519" blob)
           (ssh-remember-known-host second-file "example.org"
                                    "ssh-ed25519" other)
           (is (eq :match (client-known-host-status-for client blob)))
           (is (eq :match (client-known-host-status-for client other)))
           (is (eq :mismatch
                   (client-known-host-status-for client
                                                 (ssh-test-known-host-blob))))
           ;; Trust-on-first-use writes the first file, the user's own.
           (let ((fresh (ssh-test-known-host-blob)))
             (client-remember-host-key-for client fresh)
             (is (eq :match (ssh-known-host-status first-file
                                                   "example.org" fresh)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

;;; ---- Channel requests ----
;;; Capturing SSH-CHANNEL-SEND only makes sense for the pure transport.

#-ssh-backend-ffi
(defun captured-channel-messages (channel thunk)
  "Payloads THUNK sends on CHANNEL, in order."
  (let ((sent '()))
    (let ((original (symbol-function 'cl-pnet-ssh::ssh-channel-send)))
      (unwind-protect
           (progn
             (setf (symbol-function 'cl-pnet-ssh::ssh-channel-send)
                   (lambda (channel payload)
                     (declare (ignore channel))
                     (push payload sent)
                     t))
             (funcall thunk))
        (setf (symbol-function 'cl-pnet-ssh::ssh-channel-send) original)))
    (nreverse sent)))

(defun channel-request-parts (payload)
  "TYPE, REMOTE-ID, REQUEST, WANT-REPLY and the remaining text fields."
  (let ((reader (ssh-make-reader payload)))
    (values (ssh-read-u8 reader)
            (ssh-read-u32 reader)
            (ssh-read-text reader)
            (ssh-read-boolean reader)
            (iter (while (plusp (ssh-reader-remaining reader)))
              (collect (ssh-read-text reader))))))

#-ssh-backend-ffi
(test channel-env-precedes-a-queued-exec
  (let ((channel (cl-pnet-ssh::%make-ssh-channel
                  :client (cl-pnet-ssh::%make-ssh-client)
                  :remote-id 7 :state :opening)))
    (ssh-channel-env channel "GIT_PROTOCOL" "version=2")
    (ssh-channel-exec channel "git-upload-pack 'repo'")
    (let* ((confirmation (concatenated
                          (ssh-uint32-octets 7)
                          (ssh-uint32-octets 1048576)
                          (ssh-uint32-octets 32768)))
           (messages
             (captured-channel-messages
              channel
              (lambda ()
                (cl-pnet-ssh::ssh-channel-handle-open-confirmation
                 channel (ssh-make-reader confirmation))))))
      (is (= 2 (length messages)))
      (multiple-value-bind (type remote request reply fields)
          (channel-request-parts (first messages))
        (is (= type cl-pnet-ssh::+ssh-msg-channel-request+))
        (is (= remote 7))
        (is (string= request "env"))
        (is (not reply))
        (is (equal fields '("GIT_PROTOCOL" "version=2"))))
      (multiple-value-bind (type remote request reply fields)
          (channel-request-parts (second messages))
        (is (= type cl-pnet-ssh::+ssh-msg-channel-request+))
        (is (= remote 7))
        (is (string= request "exec"))
        (is (eq t reply))
        (is (equal fields '("git-upload-pack 'repo'")))))))

#+ssh-backend-ffi
(test channel-env-precedes-a-queued-exec
  (skip "the pure client transport is not built"))

;;; ---- ssh-agent ----

(defun agent-identities-response (entries)
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer cl-pnet-ssh::+ssh-agent-identities-answer+)
    (ssh-write-u32 writer (length entries))
    (dolist (entry entries)
      (ssh-write-string writer (car entry))
      (ssh-write-text writer (cdr entry)))
    (ssh-writer-output writer)))

(test agent-identities-parse
  (let* ((blob (ssh-make-public-key-blob "ssh-ed25519" (ssh-random-octets 32)))
         (entries (cl-pnet-ssh::ssh-agent-parse-identities
                   (agent-identities-response (list (cons blob "laptop"))))))
    (is (= 1 (length entries)))
    (is (equalp blob (caar entries)))
    (is (string= "laptop" (cdar entries)))))

(test agent-sign-parse
  (let ((signature (ssh-make-public-key-blob "ssh-ed25519" (ssh-random-octets 64)))
        (writer (ssh-writer)))
    (ssh-write-u8 writer cl-pnet-ssh::+ssh-agent-sign-response+)
    (ssh-write-string writer signature)
    (is (equalp signature
                (cl-pnet-ssh::ssh-agent-parse-sign (ssh-writer-output writer)))))
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer cl-pnet-ssh::+ssh-agent-failure+)
    (signals ssh-authentication-error
      (cl-pnet-ssh::ssh-agent-parse-sign (ssh-writer-output writer)))))

;;; A fake agent on a Unix socket, driven by the same non-blocking loop as
;;; the client.  It serves exactly one request, then closes.

(defstruct (fake-agent (:constructor %make-fake-agent))
  listener
  listener-watcher
  connection
  connection-watcher
  (incoming (make-array 0 :element-type '(unsigned-byte 8)
                          :adjustable t :fill-pointer 0))
  responder)

(defun fake-agent-close (agent)
  (when (fake-agent-connection-watcher agent)
    (cl-pnet:fd-unwatch (fake-agent-connection-watcher agent))
    (setf (fake-agent-connection-watcher agent) nil))
  (when (fake-agent-connection agent)
    (cl-pnet-sockets:close-open-fd (fake-agent-connection agent))
    (setf (fake-agent-connection agent) nil))
  (when (fake-agent-listener-watcher agent)
    (cl-pnet:fd-unwatch (fake-agent-listener-watcher agent))
    (setf (fake-agent-listener-watcher agent) nil))
  (when (fake-agent-listener agent)
    (cl-pnet-sockets:close-open-fd (fake-agent-listener agent))
    (setf (fake-agent-listener agent) nil)))

(defun fake-agent-send (agent octets)
  (cl-pnet-sockets:send-octets (fake-agent-connection agent) octets))

(defun fake-agent-respond (agent)
  (let* ((incoming (fake-agent-incoming agent))
         (length (ssh-octets-uint32 incoming))
         (payload (subseq incoming 4 (+ 4 length)))
         (response (funcall (fake-agent-responder agent) payload)))
    (fake-agent-send
     agent (ssh-concat (ssh-uint32-octets (length response)) response))
    (fake-agent-close agent)))

(defun fake-agent-read (agent)
  (multiple-value-bind (octets count)
      (cl-pnet-sockets:receive-octets (fake-agent-connection agent) 4096)
    (when (plusp count)
      (loop for octet across octets
            do (vector-push-extend octet (fake-agent-incoming agent)))
      (let ((incoming (fake-agent-incoming agent)))
        (when (and (>= (fill-pointer incoming) 4)
                   (>= (fill-pointer incoming)
                       (+ 4 (ssh-octets-uint32 incoming))))
          (fake-agent-respond agent))))))

(defun fake-agent-accept (agent)
  (when (fake-agent-listener-watcher agent)
    (cl-pnet:fd-unwatch (fake-agent-listener-watcher agent))
    (setf (fake-agent-listener-watcher agent) nil))
  (let ((connection (cl-pnet-sockets:accept-socket
                     (fake-agent-listener agent))))
    (cl-pnet-sockets:close-open-fd (fake-agent-listener agent))
    (setf (fake-agent-listener agent) nil)
    (when connection
      (setf (fake-agent-connection agent) connection)
      (setf (fake-agent-connection-watcher agent)
            (cl-pnet:fd-watch
             connection :on-readable
             (lambda (watcher)
               (declare (ignore watcher))
               (fake-agent-read agent)))))))

(defun fake-agent-open (path respond)
  (ignore-errors (delete-file path))
  (let ((listener (cl-pnet-sockets:listen-unix path :backlog 4))
        (agent nil))
    (setf agent (%make-fake-agent :listener listener :responder respond))
    (setf (fake-agent-listener-watcher agent)
          (cl-pnet:fd-watch
           listener :on-readable
           (lambda (watcher)
             (declare (ignore watcher))
             (fake-agent-accept agent))))
    agent))

(defun run-agent-call (path respond start)
  "Run START against a fake agent; return its result when the call ends."
  (let ((agent (fake-agent-open path respond))
        (result nil)
        (done nil)
        (turns 0))
    (unwind-protect
         (progn
           (funcall start
                    (lambda (value)
                      (setf result value done t))
                    (lambda (condition)
                      (setf result condition done t)))
           (loop until (or done (> turns 10000))
                 do (cl-pnet:event-loop-run-once)
                    (incf turns))
           (is (not (null done)) "the agent call did not finish")
           result)
      (fake-agent-close agent))))

(test agent-missing-socket-reports-error
  (let ((condition nil))
    (cl-pnet-ssh:ssh-agent-identities
     :path "/nonexistent/cl-pnet-ssh-agent.sock"
     :on-identities (lambda (entries) (declare (ignore entries)))
     :on-error (lambda (reported) (setf condition reported)))
    (is (typep condition 'ssh-authentication-error))
    (is (search "cannot connect"
                (ssh-error-detail condition)))))

(test agent-identities-over-a-unix-socket
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-agent-i"))
         (path (namestring (merge-pathnames "agent.sock" directory)))
         (blob (ssh-make-public-key-blob "ssh-ed25519" (ssh-random-octets 32)))
         (response (agent-identities-response (list (cons blob "from-agent")))))
    (ensure-directories-exist path)
    (unwind-protect
         (let ((entries
                 (run-agent-call
                  path
                  (lambda (payload)
                    (is (= (aref payload 0)
                           cl-pnet-ssh::+ssh-agentc-request-identities+))
                    response)
                  (lambda (on-result on-error)
                    (ssh-agent-identities :path path
                                          :on-identities on-result
                                          :on-error on-error)))))
           (is (equalp blob (caar entries)))
           (is (string= "from-agent" (cdar entries))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test agent-sign-over-a-unix-socket
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-agent-s"))
         (path (namestring (merge-pathnames "agent.sock" directory)))
         (blob (ssh-make-public-key-blob "ssh-ed25519" (ssh-random-octets 32)))
         (data (octets-ascii "sign this"))
         (signature (ssh-make-public-key-blob "ssh-ed25519"
                                              (ssh-random-octets 64)))
         (response (let ((writer (ssh-writer)))
                     (ssh-write-u8 writer cl-pnet-ssh::+ssh-agent-sign-response+)
                     (ssh-write-string writer signature)
                     (ssh-writer-output writer))))
    (ensure-directories-exist path)
    (unwind-protect
         (let ((received
                 (run-agent-call
                  path
                  (lambda (payload)
                    (let ((reader (ssh-make-reader payload)))
                      (is (= (ssh-read-u8 reader)
                             cl-pnet-ssh::+ssh-agentc-sign-request+))
                      (is (equalp blob (ssh-read-string reader)))
                      (is (equalp data (ssh-read-string reader)))
                      (is (zerop (ssh-read-u32 reader))))
                    response)
                  (lambda (on-result on-error)
                    (ssh-agent-sign blob data :path path
                                    :on-signature on-result
                                    :on-error on-error)))))
           (is (equalp signature received)))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

;;; ---- Server role: a loopback around both halves of this library ----

(defun ssh-test-run-command (channel command)
  "Run COMMAND, then report its output and status on CHANNEL."
  (multiple-value-bind (stdout stderr status)
      (uiop:run-program (list "/bin/sh" "-c" command)
                        :output :string :error-output :string
                        :ignore-error-status t)
    (when (plusp (length stdout))
      (ssh-server-channel-write channel stdout))
    (when (plusp (length stderr))
      (ssh-server-channel-write-stderr channel stderr))
    (ssh-server-channel-exit channel (or status 0))
    (ssh-server-channel-close channel)))

(defun ssh-test-write-authorized-keys (public-key-file authorized-file
                                       &key prefix)
  "Copy the one public key in PUBLIC-KEY-FILE into AUTHORIZED-FILE.

PREFIX, when given, is an authorized_keys options string placed before the
key on the line."
  (with-open-file (output authorized-file :direction :output
                                      :if-exists :supersede
                                      :if-does-not-exist :create)
    (with-open-file (input public-key-file)
      (format output "~@[~A ~]~A~%"
              prefix
              (string-trim '(#\Space #\Return #\Newline) (read-line input))))))

(defun ssh-test-loopback-handle-data (stdout stderr)
  "A channel data callback that splits stdout from stderr."
  (lambda (channel data kind)
    (declare (ignore channel))
    (write-string (ssh-octets-string data)
                  (ecase kind (:stdout stdout) (:stderr stderr)))))

(defun ssh-test-loopback-start (client stdout stderr state)
  "Open one session, run the test command, and record its exit in STATE.

STATE is (STATUS ERROR): a cons cell so the callbacks can update it."
  (let ((channel
          (ssh-open-session
           client
           :on-data (ssh-test-loopback-handle-data stdout stderr)
           :on-exit (lambda (channel value)
                      (declare (ignore channel))
                      (setf (first state) value))
           :on-close (lambda (channel value)
                       (declare (ignore channel value))
                       (ssh-client-close client)
                       (cl-pnet:event-loop-stop))
           :on-error (lambda (channel condition)
                       (declare (ignore channel))
                       (setf (second state) condition)
                       (cl-pnet:event-loop-stop)))))
    (ssh-channel-exec channel "printf hello; printf oops >&2; exit 3")))

(defun ssh-test-loopback-run (server client-key known-hosts stdout stderr
                              &key (host-key-policy :accept-new))
  "Start a client against SERVER and return the command's exit status.

HOST-KEY-POLICY is passed to MAKE-SSH-CLIENT; :STRICT proves a host
certificate was trusted rather than added on first use."
  (let ((state (list :none nil))
        (timeout nil))
    (unwind-protect
         (progn
           (setf timeout
                 (cl-pnet:timer-start
                  10 0
                  (lambda ()
                    (setf (second state) :timed-out)
                    (cl-pnet:event-loop-stop))))
           (make-ssh-client
            "127.0.0.1"
            :port (ssh-server-port server)
            :user "tester"
            :private-key client-key
            :known-hosts known-hosts
            :host-key-policy host-key-policy
            ;; Exercise the timer wiring too: both timers must start with
            ;; numeric repeat values or the backend rejects them.
            :connect-timeout 10
            :server-alive-interval 1
            :on-open (lambda (client)
                       (ssh-test-loopback-start client stdout stderr state))
            :on-error (lambda (client condition)
                        (declare (ignore client))
                        (setf (second state) condition)
                        (cl-pnet:event-loop-stop))
            :on-close (lambda (client reason)
                        (declare (ignore client reason))
                        (cl-pnet:event-loop-stop)))
           ;; A stop requested after an earlier loop had already ended can
           ;; leave a wakeup queued; consume it so it cannot break this run
           ;; before the client has connected.
           (when (fboundp '(setf cl-pnet::ev-stop-requested-p))
             (setf (cl-pnet::ev-stop-requested-p) nil)
             (cl-pnet:event-loop-run-once))
           (cl-pnet:event-loop-run)
           (when (second state)
             (error "loopback: ~A" (second state)))
           (first state))
      (when timeout (cl-pnet:timer-stop timeout)))))

(defun ssh-test-loopback-result (&key (host-key-arguments '("-t" "ed25519")))
  "Run one exec through a server and client in this process.

HOST-KEY-ARGUMENTS choose the server's key type, so the same loopback can
prove an RSA or ECDSA host key is negotiated and its signature verified.
Returns (VALUES STDOUT STDERR STATUS)."
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-loop"))
         (server-key (merge-pathnames "host_key" directory))
         (client-key (merge-pathnames "client_key" directory))
         (authorized (merge-pathnames "authorized_keys" directory))
         (known-hosts (merge-pathnames "known_hosts" directory))
         (stdout (make-string-output-stream))
         (stderr (make-string-output-stream))
         (server nil))
    (ensure-directories-exist server-key)
    (unwind-protect
         (progn
           (ssh-keygen (append (list "-q" "-N" "")
                               host-key-arguments
                               (list "-f" (namestring server-key))))
           (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                             "-f" (namestring client-key)))
           (ssh-test-write-authorized-keys
            (merge-pathnames "client_key.pub" directory) authorized)
           (setf server
                 (make-ssh-server
                  "127.0.0.1" 0
                  :host-key server-key
                  :authorized-keys authorized
                  :on-channel
                  (lambda (channel)
                    (setf (cl-pnet-ssh::ssh-server-channel-on-exec channel)
                          (lambda (channel command)
                            (ssh-test-run-command channel command))))))
           (let ((status (ssh-test-loopback-run
                          server client-key known-hosts stdout stderr)))
             (values (get-output-stream-string stdout)
                     (get-output-stream-string stderr)
                     status)))
      (when server (ssh-server-close server))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

#-ssh-backend-ffi
(defun ssh-test-loopback-pty-shell-result (&key authorized-options)
  "Run one pty and shell session through a loopback server and client.

AUTHORIZED-OPTIONS is placed before the client's key in authorized_keys.
Returns (VALUES STDOUT PTY WINDOW-CHANGE STATUS).  PTY is the (TERM COLUMNS
ROWS) the server recorded from the pty request, WINDOW-CHANGE the (COLUMNS
ROWS) it saw afterwards, and STATUS the command's exit status.  Both backends
share the test, so each must dispatch the same channel requests."
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-loop-pty"))
         (server-key (merge-pathnames "host_key" directory))
         (client-key (merge-pathnames "client_key" directory))
         (authorized (merge-pathnames "authorized_keys" directory))
         (known-hosts (merge-pathnames "known_hosts" directory))
         (stdout (make-string-output-stream))
         (stderr (make-string-output-stream))
         (status :none)
         (error nil)
         (pty nil)
         (window-change nil)
         (server nil)
         (timeout nil)
         ;; A no-pty or restrict line makes the server refuse the pty request;
         ;; the client reports that refusal, and this helper expects it.
         (refuse-pty (and authorized-options
                          (or (search "no-pty" authorized-options)
                              (search "restrict" authorized-options)))))
    (ensure-directories-exist server-key)
    (unwind-protect
         (progn
           (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                             "-f" (namestring server-key)))
           (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                             "-f" (namestring client-key)))
           (ssh-test-write-authorized-keys
            (merge-pathnames "client_key.pub" directory) authorized
            :prefix authorized-options)
           (setf server
                 (make-ssh-server
                  "127.0.0.1" 0
                  :host-key server-key
                  :authorized-keys authorized
                  :on-channel
                  (lambda (channel)
                    (setf (ssh-server-channel-on-pty channel)
                          (lambda (channel term columns rows width height modes)
                            (declare (ignore channel width height modes))
                            (setf pty (list term columns rows))
                            t)
                          (ssh-server-channel-on-window-change channel)
                          (lambda (channel columns rows)
                            (declare (ignore channel))
                            (setf window-change (list columns rows)))
                          (ssh-server-channel-on-shell channel)
                          (lambda (channel)
                            (lambda ()
                              (ssh-test-run-command
                               channel "printf pty-shell; exit 7")))))))
           (setf timeout
                 (cl-pnet:timer-start
                  10 0
                  (lambda ()
                    (setf error :timed-out)
                    (cl-pnet:event-loop-stop))))
           (make-ssh-client
            "127.0.0.1"
            :port (ssh-server-port server)
            :user "tester"
            :private-key client-key
            :known-hosts known-hosts
            :host-key-policy :accept-new
            :on-open
            (lambda (client)
              (cl-pnet-ssh::ssh-open-channel
               client "session"
               :on-data (ssh-test-loopback-handle-data stdout stderr)
               :on-open
               (lambda (channel)
                 (flet ((request (name want-reply fields)
                          (cl-pnet-ssh::ssh-channel-send-message
                           channel cl-pnet-ssh::+ssh-msg-channel-request+
                           :fields
                           (lambda (writer)
                             (cl-pnet-ssh::ssh-write-text writer name)
                             (cl-pnet-ssh::ssh-write-boolean writer want-reply)
                             (funcall fields writer)))))
                   (request
                    "pty-req" t
                    (lambda (writer)
                      (cl-pnet-ssh::ssh-write-text writer "xterm-test")
                      (cl-pnet-ssh::ssh-write-u32 writer 90)
                      (cl-pnet-ssh::ssh-write-u32 writer 24)
                      (cl-pnet-ssh::ssh-write-u32 writer 0)
                      (cl-pnet-ssh::ssh-write-u32 writer 0)
                      (cl-pnet-ssh::ssh-write-string
                       writer
                       (make-array 0 :element-type '(unsigned-byte 8)))))
                   (request
                    "window-change" nil
                    (lambda (writer)
                      (cl-pnet-ssh::ssh-write-u32 writer 100)
                      (cl-pnet-ssh::ssh-write-u32 writer 50)
                      (cl-pnet-ssh::ssh-write-u32 writer 0)
                      (cl-pnet-ssh::ssh-write-u32 writer 0)))
                   (request "shell" t
                            (lambda (writer) (declare (ignore writer))))))
               :on-exit (lambda (channel value)
                          (declare (ignore channel))
                          (setf status value))
               :on-close (lambda (channel value)
                           (declare (ignore channel value))
                           (ssh-client-close client)
                           (cl-pnet:event-loop-stop))
               :on-error (lambda (channel condition)
                           (declare (ignore channel))
                           ;; A refused pty is the expected answer to a no-pty
                           ;; key line, so it must not fail the whole session.
                           (unless (and refuse-pty
                                        (typep condition
                                               'cl-pnet-ssh:ssh-channel-error))
                             (setf error condition)
                             (cl-pnet:event-loop-stop)))))
            :on-error (lambda (client condition)
                        (declare (ignore client))
                        (setf error condition)
                        (cl-pnet:event-loop-stop)))
           (cl-pnet:event-loop-run)
           (when error (error "loopback: ~A" error))
           (values (get-output-stream-string stdout)
                   pty
                   window-change
                   status))
      (when timeout (cl-pnet:timer-stop timeout))
      (when server (ssh-server-close server))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test server-loopback-exec
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (stdout stderr status) (ssh-test-loopback-result)
        (is (equal "hello" stdout))
        (is (equal "oops" stderr))
        (is (eql 3 status)))))

(test server-loopback-exec-rsa-host-key
  ;; An ssh-rsa key serves rsa-sha2-512/256, so the client must negotiate one
  ;; of those and verify an RSA signature over the exchange hash.
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (stdout stderr status)
          (ssh-test-loopback-result
           :host-key-arguments '("-t" "rsa" "-b" "2048"))
        (is (equal "hello" stdout))
        (is (equal "oops" stderr))
        (is (eql 3 status)))))

#-ssh-backend-ffi
(test server-loopback-pty-shell
  ;; A pty request must be answered, its metadata kept, a window change applied,
  ;; and a shell request must start the application's command after the reply.
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (stdout pty window-change status)
          (ssh-test-loopback-pty-shell-result)
        (is (equal "pty-shell" stdout))
        (is (equal '("xterm-test" 90 24) pty))
        (is (equal '(100 50) window-change))
        (is (eql 7 status)))))

#+ssh-backend-ffi
(test server-loopback-pty-shell
  (skip "the pure client transport is not built"))

(test server-loopback-no-pty-key-option
  ;; A no-pty option on the authenticating key refuses the pty request; the
  ;; shell itself still runs, as it does in sshd.
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (stdout pty window-change status)
          (ssh-test-loopback-pty-shell-result :authorized-options "no-pty")
        (is (equal "pty-shell" stdout))
        (is (null pty))
        (is (equal '(100 50) window-change))
        (is (eql 7 status)))))

#+ssh-backend-ffi
(test server-loopback-no-pty-key-option
  (skip "the pure client transport is not built"))

(test server-loopback-exec-ecdsa-host-key
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (stdout stderr status)
          (ssh-test-loopback-result :host-key-arguments '("-t" "ecdsa"))
        (is (equal "hello" stdout))
        (is (equal "oops" stderr))
        (is (eql 3 status)))))

(test server-loopback-host-certificate
  ;; The server presents the certificate, the client checks its CA against
  ;; @cert-authority in known_hosts, and the KEX signature is verified with
  ;; the plain key inside the certificate.
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-hostcert-loop"))
             (ca (merge-pathnames "ca" directory))
             (host-key (merge-pathnames "host_key" directory))
             (client-key (merge-pathnames "client_key" directory))
             (authorized (merge-pathnames "authorized_keys" directory))
             (known-hosts (merge-pathnames "known_hosts" directory))
             (stdout (make-string-output-stream))
             (stderr (make-string-output-stream))
             (server nil))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ca)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring host-key)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring client-key)))
               (ssh-keygen
                (list "-q" "-s" (namestring ca) "-I" "host-id"
                      "-h" "-n" "127.0.0.1" "-V" "-1m:+52w"
                      (namestring (merge-pathnames "host_key.pub" directory))))
               (ssh-test-write-authorized-keys
                (merge-pathnames "client_key.pub" directory) authorized)
               (setf server
                     (make-ssh-server
                      "127.0.0.1" 0
                      :host-key host-key
                      :host-certificate
                      (merge-pathnames "host_key-cert.pub" directory)
                      :authorized-keys authorized
                      :on-channel
                      (lambda (channel)
                        (setf (cl-pnet-ssh::ssh-server-channel-on-exec channel)
                              (lambda (channel command)
                                (ssh-test-run-command channel command))))))
               ;; The host's known_hosts name includes the ephemeral port.
               (with-open-file (out known-hosts :direction :output
                                               :if-exists :supersede
                                               :if-does-not-exist :create)
                 (with-open-file (in (merge-pathnames "ca.pub" directory))
                   (format out "@cert-authority [127.0.0.1]:~D ~A~%"
                           (ssh-server-port server)
                           (string-trim '(#\Space #\Return #\Newline)
                                        (read-line in)))))
               ;; Strict policy: only the certificate's CA can admit the host.
               (let ((status (ssh-test-loopback-run
                              server client-key known-hosts stdout stderr
                              :host-key-policy :strict)))
                 (is (equal "hello" (get-output-stream-string stdout)))
                 (is (equal "oops" (get-output-stream-string stderr)))
                 (is (eql 3 status))))
          (when server (ssh-server-close server))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-loopback-authentication-methods
  "publickey,publickey requires two different keys, and ExposeAuthInfo
records both successful methods."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-authmethods"))
             (host-key (merge-pathnames "host_key" directory))
             (client-key-1 (merge-pathnames "client_key_1" directory))
             (client-key-2 (merge-pathnames "client_key_2" directory))
             (authorized (merge-pathnames "authorized_keys" directory))
             (known-hosts (merge-pathnames "known_hosts" directory))
             (config (ssh-server-config-load
                      nil :options '("AuthenticationMethods publickey,publickey")))
             (captured nil)
             (server nil))
        (ensure-directories-exist host-key)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring host-key)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring client-key-1)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring client-key-2)))
               (with-open-file (out authorized :direction :output
                                               :if-exists :supersede
                                               :if-does-not-exist :create)
                 (dolist (public (list (merge-pathnames "client_key_1.pub"
                                                        directory)
                                       (merge-pathnames "client_key_2.pub"
                                                        directory)))
                   (with-open-file (in public)
                     (format out "~A~%"
                             (string-trim '(#\Space #\Return #\Newline)
                                          (read-line in))))))
               (setf server
                     (make-ssh-server
                      "127.0.0.1" 0
                      :host-key host-key
                      :authorized-keys authorized
                      :sshd-config config
                      :on-session
                      (lambda (session)
                        (setf captured
                              (copy-list
                               (ssh-session-auth-info-lines session))))
                      :on-channel
                      (lambda (channel)
                        (setf (cl-pnet-ssh::ssh-server-channel-on-exec channel)
                              (lambda (channel command)
                                (ssh-test-run-command channel command))))))
               (let ((stdout (make-string-output-stream))
                     (stderr (make-string-output-stream)))
                 (let ((status (ssh-test-loopback-run
                                server
                                (list client-key-1 client-key-2)
                                known-hosts stdout stderr)))
                   (is (equal "hello" (get-output-stream-string stdout)))
                   (is (equal "oops" (get-output-stream-string stderr)))
                   (is (eql 3 status)))
                 (is (= 2 (length captured)))
                 (is (every (lambda (line)
                              (and (stringp line)
                                   (search "publickey ssh-ed25519 " line)))
                            captured)))
               ;; One key cannot complete both methods.
               (let ((stdout (make-string-output-stream))
                     (stderr (make-string-output-stream))
                     (failed
                       (handler-case
                           (progn (ssh-test-loopback-run
                                   server client-key-1 known-hosts
                                   stdout stderr)
                                  nil)
                         (error () t))))
                 (is (not (null failed))))
               ;; The same key twice is refused as already used.
               (let ((stdout (make-string-output-stream))
                     (stderr (make-string-output-stream))
                     (failed
                       (handler-case
                           (progn (ssh-test-loopback-run
                                   server
                                   (list client-key-1 client-key-1)
                                   known-hosts stdout stderr)
                                  nil)
                         (error () t))))
                 (is (not (null failed)))))
          (when server (ssh-server-close server))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test host-certificate-known-hosts-policy
  "A @cert-authority line trusts the certificate; a @revoked line for the
certificate, its plain key or its CA refuses it."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-hostcert-known"))
             (ca (merge-pathnames "ca" directory))
             (host-key (merge-pathnames "host" directory))
             (cert (merge-pathnames "host-cert.pub" directory))
             (known-hosts (merge-pathnames "known_hosts" directory)))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ca)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring host-key)))
               (ssh-keygen
                (list "-q" "-s" (namestring ca) "-I" "host-id"
                      "-h" "-n" "127.0.0.1" "-V" "-1m:+52w"
                      (namestring (merge-pathnames "host.pub" directory))))
               (let* ((blob (cl-pnet-ssh::ssh-public-key-file-blob cert))
                      (ca-line
                        (cl-pnet-ssh::ssh-public-key-file-blob
                         (merge-pathnames "ca.pub" directory)))
                      (host-line
                        (cl-pnet-ssh::ssh-public-key-file-blob
                         (merge-pathnames "host.pub" directory)))
                      (client
                        (cl-pnet-ssh::%make-ssh-client
                         :host "127.0.0.1" :port 22
                         :known-hosts known-hosts
                         :host-key-policy :strict)))
                 (labels ((remember (marker key-line)
                            (with-open-file (out known-hosts
                                                 :direction :output
                                                 :if-exists :supersede
                                                 :if-does-not-exist :create)
                              (format out "~A 127.0.0.1 ~A ~A~%"
                                      marker
                                      (nth-value 0 (cl-pnet-ssh:ssh-public-key-parts
                                                    key-line))
                                      (cl-pnet-ssh:ssh-octets-base64 key-line)))))
                   (remember "@cert-authority" ca-line)
                   (is (cl-pnet-ssh::ssh-client-verify-host-key client blob))
                   (dolist (revoked (list ca-line host-line blob))
                     (remember "@revoked" revoked)
                     (signals cl-pnet-ssh:ssh-host-key-error
                       (cl-pnet-ssh::ssh-client-verify-host-key client blob))))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-host-key-advertisement
  ;; KEXINIT must list exactly the algorithms the loaded keys can sign with,
  ;; in preference order, and no algorithm whose key is missing.
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-hostkeys"))
             (rsa (merge-pathnames "rsa" directory))
             (ecdsa (merge-pathnames "ecdsa" directory))
             (ed25519 (merge-pathnames "ed25519" directory)))
        (ensure-directories-exist rsa)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "2048" "-N" ""
                                 "-f" (namestring rsa)))
               (ssh-keygen (list "-q" "-t" "ecdsa" "-N" ""
                                 "-f" (namestring ecdsa)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ed25519)))
               (let* ((keys (list (ssh-load-private-key ed25519)
                                  (ssh-load-private-key ecdsa)
                                  (ssh-load-private-key rsa)))
                      (advertised
                        (cl-pnet-ssh::ssh-server-host-key-algorithms keys)))
                 (is (equal '("ssh-ed25519"
                              "ecdsa-sha2-nistp256"
                              "rsa-sha2-512"
                              "rsa-sha2-256"
                              "ssh-rsa")
                            advertised))
                 (is (eq (first keys)
                         (cl-pnet-ssh::ssh-server-host-key-for
                          keys "ssh-ed25519")))
                 (is (eq (second keys)
                         (cl-pnet-ssh::ssh-server-host-key-for
                          keys "ecdsa-sha2-nistp256")))
                 (is (eq (third keys)
                         (cl-pnet-ssh::ssh-server-host-key-for
                          keys "rsa-sha2-512")))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-host-certificate-advertisement
  "A paired certificate outranks its plain key, and is what KEX_ECDH_REPLY
carries; without it only the plain algorithm is offered."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-hostcert"))
             (ca (merge-pathnames "ca" directory))
             (host-key (merge-pathnames "host" directory))
             (other-key (merge-pathnames "other" directory))
             (cert (merge-pathnames "host-cert.pub" directory))
             (other-cert (merge-pathnames "other-cert.pub" directory)))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ca)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring host-key)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring other-key)))
               (ssh-keygen
                (list "-q" "-s" (namestring ca) "-I" "host-id"
                      "-h" "-n" "127.0.0.1" "-V" "-1m:+52w"
                      (namestring (merge-pathnames "host.pub" directory))))
               (ssh-keygen
                (list "-q" "-s" (namestring ca) "-I" "other-id"
                      "-h" "-n" "other" "-V" "-1m:+52w"
                      (namestring (merge-pathnames "other.pub" directory))))
               (let* ((key (ssh-load-private-key host-key))
                      (other (ssh-load-private-key other-key))
                      (blob (cl-pnet-ssh::ssh-public-key-file-blob cert))
                      (other-blob
                        (cl-pnet-ssh::ssh-public-key-file-blob other-cert)))
                 (is (equal '("ssh-ed25519-cert-v01@openssh.com"
                              "ssh-ed25519")
                            (cl-pnet-ssh::ssh-server-host-key-algorithms
                             (list key) nil (list blob))))
                 (multiple-value-bind (presented presented-blob)
                     (cl-pnet-ssh::ssh-server-host-key-presentation
                      (list key) (list blob)
                      "ssh-ed25519-cert-v01@openssh.com")
                   (is (eq key presented))
                   (is (cl-pnet-ssh::ssh-octets= blob presented-blob)))
                 ;; Without the certificate the plain key stands alone.
                 (is (equal '("ssh-ed25519")
                            (cl-pnet-ssh::ssh-server-host-key-algorithms
                             (list key))))
                 ;; A certificate for another key is dropped at startup.
                 (is (null (cl-pnet-ssh::ssh-server-pair-host-certificates
                            (list key) (list other-blob))))
                 (is (equal (list blob other-blob)
                            (cl-pnet-ssh::ssh-server-pair-host-certificates
                             (list key other) (list blob other-blob))))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

;;; ---- algorithm choices from sshd_config ----
;;
;;; The pure backend builds KEXINIT from these choices.  The libssh backend
;;; passes the same lists to ssh_bind_options_set, so its own checks are in
;;; CL-PLIBSSH and not exercised here.

#-ssh-backend-ffi
(defun test-server-algorithm-keys (directory)
  "Generate ed25519 and 2048-bit RSA keys under DIRECTORY, as a list."
  (let ((ed25519 (merge-pathnames "ed25519" directory))
        (rsa (merge-pathnames "rsa-2048" directory)))
    (ensure-directories-exist ed25519)
    (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                      "-f" (namestring ed25519)))
    (ssh-keygen (list "-q" "-t" "rsa" "-b" "2048" "-N" ""
                      "-f" (namestring rsa)))
    (list (ssh-load-private-key ed25519)
          (ssh-load-private-key rsa))))

#-ssh-backend-ffi
(test server-kexinit-honours-configured-algorithms
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let ((directory (ssh-test-directory "cl-pnet-ssh-algos")))
        (unwind-protect
             (let* ((keys (test-server-algorithm-keys directory))
                    (config
                      (ssh-server-config-load
                       nil
                       :options
                       '("Ciphers chacha20-poly1305@openssh.com"
                         "MACs hmac-sha2-512"
                         "KexAlgorithms curve25519-sha256@libssh.org"
                         "HostKeyAlgorithms rsa-sha2-512")))
                    (server (cl-pnet-ssh::%make-ssh-server
                             :host-keys keys :sshd-config config))
                    (session (cl-pnet-ssh::%make-ssh-session :server server))
                    (offer
                      (ssh-parse-kexinit-payload
                       (cl-pnet-ssh::ssh-server-make-kexinit-payload
                        session))))
               ;; The chosen method, then the markers a KexAlgorithms value
               ;; must never remove.
               (is (equal '("curve25519-sha256@libssh.org"
                            "kex-strict-s-v00@openssh.com"
                            "ext-info-s")
                          (getf offer :kex)))
               ;; Only rsa-sha2-512 was chosen and the RSA key can sign it.
               (is (equal '("rsa-sha2-512") (getf offer :host-keys)))
               (is (equal '("chacha20-poly1305@openssh.com")
                          (getf offer :ciphers-c2s)))
               (is (equal '("hmac-sha2-512") (getf offer :macs-c2s)))
               ;; Negotiation must pick from the same restricted lists, not
               ;; merely advertise them.
               (let ((negotiated
                       (cl-pnet-ssh::ssh-server-negotiate
                        session
                        '(:kex ("curve25519-sha256"
                                "curve25519-sha256@libssh.org")
                          :host-keys ("ssh-ed25519" "rsa-sha2-512")
                          :ciphers-c2s ("chacha20-poly1305@openssh.com")
                          :ciphers-s2c ("chacha20-poly1305@openssh.com")
                          :macs-c2s ("hmac-sha2-256" "hmac-sha2-512")
                          :macs-s2c ("hmac-sha2-256" "hmac-sha2-512")
                          :compressions-c2s ("none")))))
                 (is (equal "curve25519-sha256@libssh.org"
                            (getf negotiated :kex)))
                 (is (equal "rsa-sha2-512" (getf negotiated :host-key)))
                 (is (equal "hmac-sha2-512"
                            (getf negotiated :mac-c2s)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

#-ssh-backend-ffi
(test server-host-keys-obey-required-rsa-size
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let ((directory (ssh-test-directory "cl-pnet-ssh-rsasize")))
        (unwind-protect
             (let* ((short (merge-pathnames "rsa-1024" directory))
                    (long (merge-pathnames "rsa-2048" directory))
                    (ed25519 (merge-pathnames "ed25519" directory)))
               (ensure-directories-exist short)
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "1024" "-N" ""
                                 "-f" (namestring short)))
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "2048" "-N" ""
                                 "-f" (namestring long)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ed25519)))
               (let* ((short-key (ssh-load-private-key short))
                      (long-key (ssh-load-private-key long))
                      (ed-key (ssh-load-private-key ed25519))
                      (restricted
                        (ssh-server-config-load
                         nil :options '("RequiredRSASize 2048")))
                      (default (ssh-server-config-load nil))
                      (session-for
                        (lambda (config)
                          (let ((server (cl-pnet-ssh::%make-ssh-server
                                         :host-keys (list short-key long-key
                                                          ed-key)
                                         :sshd-config config)))
                            (cl-pnet-ssh::%make-ssh-session
                             :server server)))))
                 ;; 2048 is the minimum, so the 1024-bit key is skipped and
                 ;; the other two are still presentable.
                 (let ((keys (cl-pnet-ssh::ssh-session-host-keys
                              (funcall session-for restricted))))
                   (is (= 2 (length keys)))
                   (is (not (member short-key keys :test #'eq)))
                   (is (member long-key keys :test #'eq))
                   (is (member ed-key keys :test #'eq))
                   ;; Only the remaining keys' algorithms are advertised.
                   (is (equal '("ssh-ed25519" "rsa-sha2-512" "rsa-sha2-256"
                                "ssh-rsa")
                              (cl-pnet-ssh::ssh-server-host-key-algorithms-for
                               (funcall session-for restricted)))))
                 ;; Without the directive sshd still enforces its own 1024-bit
                 ;; floor, which the short key meets.
                 (is (= 3
                        (length (cl-pnet-ssh::ssh-session-host-keys
                                 (funcall session-for default)))))
                 ;; Host keys are filtered once at startup from the global
                 ;; directive; a Match block that lowers RequiredRSASize must
                 ;; not bring a key sshd already skipped back into KEXINIT.
                 (let ((session
                         (cl-pnet-ssh::%make-ssh-session
                          :server (cl-pnet-ssh::%make-ssh-server
                                   :host-keys (list short-key long-key ed-key)
                                   :sshd-config restricted)
                          :config
                          (ssh-server-config-load
                           nil :options '("RequiredRSASize 1024")))))
                   (is (= 2 (length (cl-pnet-ssh::ssh-session-host-keys
                                     session))))
                   (is (not (member short-key
                                    (cl-pnet-ssh::ssh-session-host-keys session)
                                    :test #'eq))))
                 ;; sshd refuses to start rather than listen with no usable
                 ;; host key; the caller's own NIL list is left alone.
                 (signals ssh-connection-error
                   (cl-pnet-ssh::ssh-server-check-host-keys
                    (list short-key) 2048))
                 (is (equal (list short-key)
                            (cl-pnet-ssh::ssh-server-check-host-keys
                             (list short-key) nil)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

#-ssh-backend-ffi
(test server-user-key-policy-follows-config
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let ((directory (ssh-test-directory "cl-pnet-ssh-userkey")))
        (unwind-protect
             (let* ((short (merge-pathnames "rsa-1024" directory))
                    (ed25519 (merge-pathnames "ed25519" directory)))
               (ensure-directories-exist short)
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "1024" "-N" ""
                                 "-f" (namestring short)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ed25519)))
               (let* ((rsa-blob (ssh-public-key-blob-of
                                 (ssh-load-private-key short)))
                      (ed-blob (ssh-public-key-blob-of
                                (ssh-load-private-key ed25519)))
                      (restricted
                        (ssh-server-config-load
                         nil
                         :options
                         '("PubkeyAcceptedAlgorithms rsa-sha2-512"
                           "RequiredRSASize 2048")))
                      (default (ssh-server-config-load nil))
                      (session-for
                        (lambda (config)
                          (let ((server (cl-pnet-ssh::%make-ssh-server
                                         :host-keys nil :sshd-config config)))
                            (cl-pnet-ssh::%make-ssh-session
                             :server server)))))
                 (let ((session (funcall session-for restricted)))
                   ;; The configured list replaces the default, so an
                   ;; ed25519 signature and SHA-1 ssh-rsa are both refused.
                   (is (not (cl-pnet-ssh::ssh-session-user-key-algorithm-p
                             session ed-blob "ssh-ed25519")))
                   (is (cl-pnet-ssh::ssh-session-user-key-algorithm-p
                        session rsa-blob "rsa-sha2-512"))
                   (is (not (cl-pnet-ssh::ssh-session-user-key-algorithm-p
                             session rsa-blob "ssh-rsa")))
                   ;; RequiredRSASize 2048 rejects the 1024-bit key.
                   (is (not (cl-pnet-ssh::ssh-session-user-key-length-p
                             session rsa-blob)))
                   (is (cl-pnet-ssh::ssh-session-user-key-length-p
                        session ed-blob)))
                 ;; Without the directives, the old SHA-1 name stays usable
                 ;; for old clients and the built-in 1024-bit floor passes.
                 (let ((session (funcall session-for default)))
                   (is (cl-pnet-ssh::ssh-session-user-key-algorithm-p
                        session rsa-blob "ssh-rsa"))
                   (is (cl-pnet-ssh::ssh-session-user-key-length-p
                        session rsa-blob)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

#-ssh-backend-ffi
(test server-permit-listen-restricts-remote-forwards
  (let* ((config
           (ssh-server-config-load
            nil
            :options '("PermitListen 8080 localhost:9000")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server
                   :authorization
                   (cl-pnet-ssh::%make-ssh-authorization-options))))
    ;; A bare port is a wildcard host.
    (is (ssh-session-permits-tcpip-forward-p session "" 8080))
    (is (ssh-session-permits-tcpip-forward-p session "example.com" 8080))
    ;; A named host matches case-insensitively and only that host.
    (is (ssh-session-permits-tcpip-forward-p session "localhost" 9000))
    (is (ssh-session-permits-tcpip-forward-p session "LOCALHOST" 9000))
    (is (not (ssh-session-permits-tcpip-forward-p session "" 9000)))
    (is (not (ssh-session-permits-tcpip-forward-p session "example.com" 9000)))
    (is (not (ssh-session-permits-tcpip-forward-p session "localhost" 8081)))
    ;; PermitListen none refuses every listener.
    (let* ((none (ssh-server-config-load
                  nil :options '("PermitListen none")))
           (session (cl-pnet-ssh::%make-ssh-session
                     :server (cl-pnet-ssh::%make-ssh-server :sshd-config none)
                     :authorization
                     (cl-pnet-ssh::%make-ssh-authorization-options))))
      (is (not (ssh-session-permits-tcpip-forward-p session "" 8080))))
    ;; The key's own permitlisten= narrows the administrator's list further.
    (let ((session (cl-pnet-ssh::%make-ssh-session
                    :server server
                    :authorization
                    (cl-pnet-ssh::%make-ssh-authorization-options
                     :permit-listen '(("localhost" . 8080))))))
      (is (ssh-session-permits-tcpip-forward-p session "localhost" 8080))
      (is (not (ssh-session-permits-tcpip-forward-p
                session "example.com" 8080))))))

(test server-channel-timeout-closes-idle-channels
  "ChannelTimeout selects on sshd's extended type, first pattern wins."
  (let* ((config (ssh-server-config-load
                  nil
                  :options '("ChannelTimeout session:command=5 session:*=30")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (closed nil)
         (channel (cl-pnet-ssh::%make-ssh-server-channel
                   :session session
                   :local-id 0
                   :remote-id 0
                   :state :open
                   :on-close (lambda (channel) (setf closed channel)))))
    (unwind-protect
         (progn
           (setf (gethash 0 (cl-pnet-ssh::ssh-session-channels session))
                 channel)
           ;; The clock starts when the channel opens, as in sshd, but
           ;; "session:*" does not match the unlabeled "session" type.
           (cl-pnet-ssh::ssh-server-channel-start-inactivity-timeout channel)
           (is (= 0 (cl-pnet-ssh::ssh-server-channel-inactive-timeout
                     channel)))
           (is (plusp (cl-pnet-ssh::ssh-server-channel-last-used channel)))
           (cl-pnet-ssh::ssh-server-channel-set-x-type
            channel "session:command")
           (is (= 5 (cl-pnet-ssh::ssh-server-channel-inactive-timeout
                     channel)))
           (is (plusp (cl-pnet-ssh::ssh-server-channel-last-used channel)))
           ;; The same list's later pattern handles the other session type.
           (cl-pnet-ssh::ssh-server-channel-set-x-type
            channel "session:shell")
           (is (= 30 (cl-pnet-ssh::ssh-server-channel-inactive-timeout
                      channel)))
           ;; Moving bytes resets the clock.
           (setf (cl-pnet-ssh::ssh-server-channel-last-used channel) 1)
           (cl-pnet-ssh::ssh-server-channel-note-activity channel)
           (is (> (cl-pnet-ssh::ssh-server-channel-last-used channel) 1))
           ;; Pretend 31 seconds passed with no bytes and run the wakeup.
           (setf (cl-pnet-ssh::ssh-server-channel-last-used channel)
                 (- (cl-pnet-ssh::ssh-session-now) 31))
           (cl-pnet-ssh::ssh-session-channel-timeout-tick session)
           (is (eq :closed
                   (cl-pnet-ssh::ssh-server-channel-state channel)))
           (is (eq channel closed)))
      (cl-pnet-ssh::ssh-session-stop-channel-timeout-timer session)))
  ;; A zero interval disables the type, and "none" disables every type.
  (dolist (options '(("ChannelTimeout session:*=0")
                     ("ChannelTimeout none")))
    (let* ((config (ssh-server-config-load nil :options options))
           (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
           (session (cl-pnet-ssh::%make-ssh-session :server server))
           (channel (cl-pnet-ssh::%make-ssh-server-channel
                     :session session :state :open)))
      (unwind-protect
           (progn
             (setf (gethash 0 (cl-pnet-ssh::ssh-session-channels session))
                   channel)
             (cl-pnet-ssh::ssh-server-channel-set-x-type
              channel "session:command")
             (is (= 0 (cl-pnet-ssh::ssh-server-channel-inactive-timeout
                       channel)))
             (setf (cl-pnet-ssh::ssh-server-channel-last-used channel)
                   (- (cl-pnet-ssh::ssh-session-now) 100))
             (cl-pnet-ssh::ssh-session-channel-timeout-tick session)
             (is (eq :open
                     (cl-pnet-ssh::ssh-server-channel-state channel))))
        (cl-pnet-ssh::ssh-session-stop-channel-timeout-timer session)))))

(test server-channel-timeout-base-type-and-relabeling
  "ChannelTimeout picks the base type at open and only re-resolves on labels."
  (let* ((config (ssh-server-config-load
                  nil :options '("ChannelTimeout session=2")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (channel (cl-pnet-ssh::%make-ssh-server-channel
                   :session session :local-id 0 :remote-id 0 :state :open)))
    (unwind-protect
         (progn
           (setf (gethash 0 (cl-pnet-ssh::ssh-session-channels session))
                 channel)
           ;; "session=2" matches the plain type, so the clock is running
           ;; from the moment the channel opened, before any request.
           (cl-pnet-ssh::ssh-server-channel-start-inactivity-timeout channel)
           (is (= 2 (cl-pnet-ssh::ssh-server-channel-inactive-timeout
                     channel)))
           ;; Labeling re-resolves the limit but, as sshd's
           ;; channel_set_xtype does, leaves the activity clock alone.  In
           ;; 10.6 "session" covers every session subtype, so the limit
           ;; survives the label.
           (let ((started (cl-pnet-ssh::ssh-server-channel-last-used channel)))
             (cl-pnet-ssh::ssh-server-channel-set-x-type
              channel "session:command")
             (is (= 2 (cl-pnet-ssh::ssh-server-channel-inactive-timeout
                       channel)))
             (is (= started (cl-pnet-ssh::ssh-server-channel-last-used
                             channel)))))
      (cl-pnet-ssh::ssh-session-stop-channel-timeout-timer session)))
  (let* ((config (ssh-server-config-load
                  nil :options '("ChannelTimeout session:*=5")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (channel (cl-pnet-ssh::%make-ssh-server-channel
                   :session session :local-id 0 :remote-id 0 :state :open)))
    (unwind-protect
         (progn
           (setf (gethash 0 (cl-pnet-ssh::ssh-session-channels session))
                 channel)
           (cl-pnet-ssh::ssh-server-channel-start-inactivity-timeout channel)
           (is (= 0 (cl-pnet-ssh::ssh-server-channel-inactive-timeout
                     channel)))
           ;; The label arrives after the channel has already been idle for
           ;; ten seconds, so the five-second limit is already past.
           (setf (cl-pnet-ssh::ssh-server-channel-last-used channel)
                 (- (cl-pnet-ssh::ssh-session-now) 10))
           (cl-pnet-ssh::ssh-server-channel-set-x-type
            channel "session:command")
           (is (= 5 (cl-pnet-ssh::ssh-server-channel-inactive-timeout
                     channel)))
           (cl-pnet-ssh::ssh-session-channel-timeout-tick session)
           (is (eq :closed
                   (cl-pnet-ssh::ssh-server-channel-state channel))))
      (cl-pnet-ssh::ssh-session-stop-channel-timeout-timer session))))

(test server-channel-global-timeout-closes-all-channels
  "A global ChannelTimeout runs from the newest activity on any open channel
and closes them all together."
  (let* ((config (ssh-server-config-load
                  nil :options '("ChannelTimeout global=5 session:*=30")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (first (cl-pnet-ssh::%make-ssh-server-channel
                 :session session :local-id 0 :remote-id 0 :state :open))
         (second (cl-pnet-ssh::%make-ssh-server-channel
                  :session session :local-id 1 :remote-id 1 :state :open))
         (now (cl-pnet-ssh::ssh-session-now)))
    (unwind-protect
         (progn
           (setf (gethash 0 (cl-pnet-ssh::ssh-session-channels session)) first
                 (gethash 1 (cl-pnet-ssh::ssh-session-channels session)) second)
           (cl-pnet-ssh::ssh-server-channel-set-x-type
            first "session:command")
           (cl-pnet-ssh::ssh-server-channel-set-x-type
            second "session:subsystem:sftp")
           ;; The per-channel limit is 30, but the global one is 5.
           (is (= 30 (cl-pnet-ssh::ssh-server-channel-inactive-timeout first)))
           (setf (cl-pnet-ssh::ssh-server-channel-last-used first) (- now 20)
                 (cl-pnet-ssh::ssh-server-channel-last-used second) (- now 2))
           (cl-pnet-ssh::ssh-session-channel-timeout-tick session)
           (is (eq :open (cl-pnet-ssh::ssh-server-channel-state first)))
           (is (eq :open (cl-pnet-ssh::ssh-server-channel-state second)))
           ;; Once the newest activity is older than five seconds, both go.
           (setf (cl-pnet-ssh::ssh-server-channel-last-used first) (- now 20)
                 (cl-pnet-ssh::ssh-server-channel-last-used second) (- now 10))
           (cl-pnet-ssh::ssh-session-channel-timeout-tick session)
           (is (eq :closed (cl-pnet-ssh::ssh-server-channel-state first)))
           (is (eq :closed (cl-pnet-ssh::ssh-server-channel-state second))))
      (cl-pnet-ssh::ssh-session-stop-channel-timeout-timer session))))

(test server-loopback-exec-multiple-host-keys
  ;; The server advertises several key types and the client picks the one it
  ;; prefers; the KEX must succeed whichever key is chosen.
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-multikey"))
             (rsa (merge-pathnames "rsa" directory))
             (ecdsa (merge-pathnames "ecdsa" directory))
             (ed25519 (merge-pathnames "ed25519" directory))
             (client-key (merge-pathnames "client_key" directory))
             (authorized (merge-pathnames "authorized_keys" directory))
             (known-hosts (merge-pathnames "known_hosts" directory))
             (stdout (make-string-output-stream))
             (stderr (make-string-output-stream))
             (server nil))
        (ensure-directories-exist rsa)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "2048" "-N" ""
                                 "-f" (namestring rsa)))
               (ssh-keygen (list "-q" "-t" "ecdsa" "-N" ""
                                 "-f" (namestring ecdsa)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ed25519)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring client-key)))
               (ssh-test-write-authorized-keys
                (merge-pathnames "client_key.pub" directory) authorized)
               (setf server
                     (make-ssh-server
                      "127.0.0.1" 0
                      :host-key (list rsa ed25519 ecdsa)
                      :authorized-keys authorized
                      :on-channel
                      (lambda (channel)
                        (setf (cl-pnet-ssh::ssh-server-channel-on-exec channel)
                              (lambda (channel command)
                                (ssh-test-run-command channel command))))))
               (let ((status (ssh-test-loopback-run
                              server client-key known-hosts stdout stderr)))
                 (is (equal "hello" (get-output-stream-string stdout)))
                 (is (equal "oops" (get-output-stream-string stderr)))
                 (is (eql 3 status))))
          (when server (ssh-server-close server))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(defun ssh-test-loopback-outcome (policy &key server-version version-addendum
                                         banner authorized-options)
  "Run one client handshake against a loopback server with POLICY.

SERVER-VERSION, when given, is passed to MAKE-SSH-SERVER so a test can see
the greeting the server chose; VERSION-ADDENDUM does the same for the
comment appended after it, and BANNER for the authentication banner.
AUTHORIZED-OPTIONS is placed before the client's key in authorized_keys.
Returns (VALUES OPENED ERROR GREETING BANNER-TEXT KEY-ENV): OPENED is true
once authentication completed, ERROR is the condition the client reported,
GREETING is the server's identification line as the client read it,
BANNER-TEXT is the USERAUTH_BANNER the client stored, and KEY-ENV is the
environment= list the server recorded for the authenticated key."
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-loop-policy"))
         (server-key (merge-pathnames "host_key" directory))
         (client-key (merge-pathnames "client_key" directory))
         (authorized (merge-pathnames "authorized_keys" directory))
         (known-hosts (merge-pathnames "known_hosts" directory))
         (opened nil)
         (error nil)
         (greeting nil)
         (banner-text nil)
         (key-env nil)
         (closed nil)
         (server nil)
         (timeout nil))
    (ensure-directories-exist server-key)
    (unwind-protect
         (progn
           (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                             "-f" (namestring server-key)))
           (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                             "-f" (namestring client-key)))
           (ssh-test-write-authorized-keys
            (merge-pathnames "client_key.pub" directory) authorized
            :prefix authorized-options)
           (setf server (make-ssh-server "127.0.0.1" 0
                                         :host-key server-key
                                         :authorized-keys authorized
                                         :server-version server-version
                                         :version-addendum version-addendum
                                         :banner banner
                                         :on-session
                                         (lambda (session)
                                           (setf key-env
                                                 (ssh-session-key-env
                                                  session)))))
           (setf timeout
                 (cl-pnet:timer-start
                  10 0
                  (lambda ()
                    (setf error :timed-out)
                    (cl-pnet:event-loop-stop))))
           (make-ssh-client
            "127.0.0.1"
            :port (ssh-server-port server)
            :user "tester"
            :private-key client-key
            :known-hosts known-hosts
            :host-key-policy policy
            :on-open (lambda (client)
                       (setf opened t
                             greeting (ssh-client-server-version client)
                             banner-text (ssh-client-banner client))
                       (cl-pnet:event-loop-stop))
            :on-error (lambda (client condition)
                        (declare (ignore client))
                        (setf error condition)
                        (cl-pnet:event-loop-stop))
            :on-close (lambda (client reason)
                        (declare (ignore client reason))
                        (setf closed t)
                        (cl-pnet:event-loop-stop)))
           ;; EVENT-LOOP-STOP is delivered asynchronously, so a run started
           ;; immediately after the previous test's run can consume the stale
           ;; wakeup and return before touching the new connection.  Retrying
           ;; only while nothing at all happened keeps a real timeout a
           ;; timeout; it cannot hide a failure, because no callback ran.
           (loop repeat 3
                 until (or opened error closed)
                 do (cl-pnet:event-loop-run))
           (values opened error greeting banner-text key-env))
      (when timeout (cl-pnet:timer-stop timeout))
      (when server (ssh-server-close server))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test server-loopback-declined-host-key-does-not-connect
  "Answering \"no\" to an unknown host key must end the handshake.

The callback is the prompt; returning false has to refuse the host rather
than connect and quietly skip the known_hosts record."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (opened error)
          (ssh-test-loopback-outcome
           (lambda (client fingerprint key)
             (declare (ignore client fingerprint key))
             nil))
        (is (null opened) "the client authenticated after the key was declined")
        (is (typep error 'ssh-host-key-error)))))

(test server-version-names-the-program-that-embeds-it
  "A library user like bursyk-server must be able to say who it is.

The greeting is what a peer shows in its logs, so leaving it at the
library's default string hides which program is actually serving."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (opened error greeting)
          (ssh-test-loopback-outcome
           (lambda (client fingerprint key)
             (declare (ignore client fingerprint key))
             t)
           :server-version "bursyk-server_0.0.2.6")
        (is (null error))
        (is (not (null opened)))
        (is (equal "SSH-2.0-bursyk-server_0.0.2.6" greeting)))))

(test server-version-addendum-follows-the-version
  "sshd's VersionAddendum is a comment after the version, not a replacement."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (opened error greeting)
          (ssh-test-loopback-outcome
           (lambda (client fingerprint key)
             (declare (ignore client fingerprint key))
             t)
           :server-version "bursyk-server_0.0.2.14"
           :version-addendum "experimental")
        (is (null error))
        (is (not (null opened)))
        (is (equal "SSH-2.0-bursyk-server_0.0.2.14 experimental" greeting)))))

(test version-addendum-none-leaves-the-greeting-alone
  "sshd's \"VersionAddendum none\" appends no comment at all."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (opened error greeting)
          (ssh-test-loopback-outcome
           (lambda (client fingerprint key)
             (declare (ignore client fingerprint key))
             t)
           :server-version "bursyk-server_0.0.2.14"
           :version-addendum :none)
        (is (null error))
        (is (not (null opened)))
        (is (equal "SSH-2.0-bursyk-server_0.0.2.14" greeting)))))

(test server-sends-the-configured-banner
  "sshd's Banner reaches the client before authentication completes."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (opened error greeting banner)
          (ssh-test-loopback-outcome
           (lambda (client fingerprint key)
             (declare (ignore client fingerprint key))
             t)
           :banner "Authorized use only.
Disconnect immediately if you are not an operator.
")
        (is (null error))
        (is (not (null opened)))
        (is (equal "SSH-2.0-cl-pnet-ssh_0.0.1.19" greeting))
        (is (equal "Authorized use only.
Disconnect immediately if you are not an operator.
" banner)))))

(test banner-may-be-a-function-so-the-file-can-change
  "sshd reads its Banner file for each connection; a function keeps that."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let ((calls 0))
        (multiple-value-bind (opened error greeting banner)
            (ssh-test-loopback-outcome
             (lambda (client fingerprint key)
               (declare (ignore client fingerprint key))
               t)
             :banner (lambda ()
                       (incf calls)
                       "from a function
"))
          (declare (ignore greeting))
          (is (null error))
          (is (not (null opened)))
          (is (= 1 calls))
          (is (equal "from a function
" banner))))))

(test no-banner-means-no-userauth-banner-packet
  "A server without Banner leaves the client's banner slot empty."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (opened error greeting banner)
          (ssh-test-loopback-outcome
           (lambda (client fingerprint key)
             (declare (ignore client fingerprint key))
             t))
        (declare (ignore greeting))
        (is (null error))
        (is (not (null opened)))
        (is (null banner)))))

(test version-addendum-is-one-printable-line
  (is (equal "my build" (cl-pnet-ssh::check-version-addendum "my build")))
  (signals error (cl-pnet-ssh::check-version-addendum ""))
  (signals error (cl-pnet-ssh::check-version-addendum "bad
newline")))

(test server-version-is-checked-before-it-reaches-the-wire
  (is (equal "burst_1.2.3"
             (cl-pnet-ssh::check-server-version "burst_1.2.3")))
  (signals error (cl-pnet-ssh::check-server-version "has a space"))
  (signals error (cl-pnet-ssh::check-server-version ""))
  (signals error (cl-pnet-ssh::check-server-version "bad
newline")))

;;; ---- ssh_config client policy ----
;;;
;;; MAKE-SSH-CLIENT-FROM-CONFIG is the library version of what a command
;;; line used to do by hand: turn resolved options into client arguments.
;;; These pin the mapping itself, which is what a caller like fold depends
;;; on rather than reimplementing.

(defun facade-options (initargs)
  "An SSH-CONFIG-OPTIONS carrying INITARGS."
  (apply #'cl-pnet-ssh::%make-ssh-config-options initargs))

(test facade-jump-list-understands-none-and-commas
  (is (null (cl-pnet-ssh::ssh-config-jump-list nil)))
  (is (null (cl-pnet-ssh::ssh-config-jump-list "none")))
  (is (null (cl-pnet-ssh::ssh-config-jump-list " NONE ")))
  (is (null (cl-pnet-ssh::ssh-config-jump-list "")))
  (is (equal '("jump.example")
             (cl-pnet-ssh::ssh-config-jump-list "jump.example")))
  (is (equal '("one" "user@two:2222" "three")
             (cl-pnet-ssh::ssh-config-jump-list "one, user@two:2222,three")))
  ;; An already split list passes through.
  (is (equal '("one" "two") (cl-pnet-ssh::ssh-config-jump-list '("one" "two")))))

(test facade-split-host-port-brackets-ipv6
  (multiple-value-bind (host port) (cl-pnet-ssh::ssh-config-split-host-port "example.org")
    (is (equal "example.org" host))
    (is (null port)))
  (multiple-value-bind (host port)
      (cl-pnet-ssh::ssh-config-split-host-port "example.org:2200")
    (is (equal "example.org" host))
    (is (equal "2200" port)))
  (multiple-value-bind (host port) (cl-pnet-ssh::ssh-config-split-host-port "[::1]:2222")
    (is (equal "::1" host))
    (is (equal "2222" port)))
  (multiple-value-bind (host port) (cl-pnet-ssh::ssh-config-split-host-port "[::1]")
    (is (equal "::1" host))
    (is (null port)))
  (is (= 2222 (cl-pnet-ssh::ssh-config-port-number "2222")))
  (is (null (cl-pnet-ssh::ssh-config-port-number "22x")))
  (is (null (cl-pnet-ssh::ssh-config-port-number "2222-with"))))

(test ssh-config-seconds-parses-bare-and-suffixed-times
  ;; A bare number has no suffix, so the final flush runs after the loop; a
  ;; missing flush there leaves the value at zero without diagnosing it.
  (is (= 5 (cl-pnet-ssh::ssh-config-seconds nil "5")))
  (is (= 30 (cl-pnet-ssh::ssh-config-seconds nil "30s")))
  (is (= 90 (cl-pnet-ssh::ssh-config-seconds nil "1m30s")))
  (is (= 7200 (cl-pnet-ssh::ssh-config-seconds nil "2h")))
  (is (= 604800 (cl-pnet-ssh::ssh-config-seconds nil "1w")))
  (is (eq :none (cl-pnet-ssh::ssh-config-seconds nil "none"))))

(test facade-jump-descriptor-reads-user-and-port
  (let ((hop (cl-pnet-ssh::ssh-config-jump-descriptor "alice@other:2201")))
    (is (equal "other" (getf hop :host)))
    (is (equal "alice" (getf hop :user)))
    (is (= 2201 (getf hop :port))))
  (let ((hop (cl-pnet-ssh::ssh-config-jump-descriptor "plain")))
    (is (equal "plain" (getf hop :host)))
    (is (null (getf hop :user)))
    (is (null (getf hop :port)))))

(test facade-client-policy-reads-strict-host-key-checking
  (is (eq :insecure
          (cl-pnet-ssh::ssh-config-client-policy
           (facade-options '(:strict-host-key-checking "no")))))
  (is (eq :insecure
          (cl-pnet-ssh::ssh-config-client-policy
           (facade-options '(:strict-host-key-checking "off")))))
  (is (eq :accept-new
          (cl-pnet-ssh::ssh-config-client-policy
           (facade-options '(:strict-host-key-checking "accept-new")))))
  (is (eq :strict
          (cl-pnet-ssh::ssh-config-client-policy
           (facade-options '(:strict-host-key-checking "yes")))))
  (is (eq :strict (cl-pnet-ssh::ssh-config-client-policy (facade-options nil)))))

(test facade-client-agent-understands-none-and-the-environment
  (is (eq t (cl-pnet-ssh::ssh-config-client-agent
             (facade-options '(:identity-agent :environment)) nil)))
  (is (null (cl-pnet-ssh::ssh-config-client-agent
             (facade-options '(:identity-agent :none)) nil)))
  ;; An explicit command-line answer wins over the file.
  (is (string= "/tmp/explicit.sock"
               (cl-pnet-ssh::ssh-config-client-agent
                (facade-options '(:identity-agent "/tmp/config.sock"))
                "/tmp/explicit.sock")))
  ;; "none" and SSH_AUTH_SOCK from -o mean what they do in the file.
  (is (null (cl-pnet-ssh::ssh-config-client-agent (facade-options nil) "none")))
  (is (eq t (cl-pnet-ssh::ssh-config-client-agent (facade-options nil) "SSH_AUTH_SOCK")))
  ;; IdentitiesOnly turns the environment's agent off.
  (is (null (cl-pnet-ssh::ssh-config-client-agent
             (facade-options '(:identities-only t)) nil))))

(test facade-client-identities-keep-the-file-order
  (let ((options (facade-options
                  (list :identity-files (list "second" "first")))))
    ;; The parser pushes, so the facade reverses back into file order.
    (is (equal '("first" "second")
               (cl-pnet-ssh::ssh-config-client-identities options nil))))
  (is (equal '("given")
             (cl-pnet-ssh::ssh-config-client-identities (facade-options nil) '("given")))))

(test facade-client-known-hosts-put-the-user-file-first
  (let ((known (cl-pnet-ssh::ssh-config-client-known-hosts
                (facade-options (list :known-hosts (list #p"/u/known")
                                      :global-known-hosts (list #p"/e/known")))
                nil)))
    (is (equal '("/u/known" "/e/known")
               (mapcar #'namestring known))))
  (is (null (cl-pnet-ssh::ssh-config-client-known-hosts (facade-options nil) nil)))
  (is (equal '("/given")
             (mapcar #'namestring
                     (cl-pnet-ssh::ssh-config-client-known-hosts
                      (facade-options nil) '("/given"))))))

(test facade-proxy-jumps-let-the-command-line-win
  (let ((options (facade-options '(:proxy-jump "from-config.example"))))
    (is (equal "from-config.example"
               (getf (first (cl-pnet-ssh::ssh-config-proxy-jumps options nil)) :host)))
    (is (equal "cli.example"
               (getf (first (cl-pnet-ssh::ssh-config-proxy-jumps options "cli.example"))
                     :host)))
    (is (null (cl-pnet-ssh::ssh-config-proxy-jumps options "none")))))

(test facade-carries-a-proxy-command
  ;; A ProxyCommand is a transport, not a policy refusal: it reaches the
  ;; parameters make-ssh-client is built from, and "none" turns it off.
  (is (equal "nc %h %p"
             (cl-pnet-ssh::ssh-config-proxy-command
              (facade-options '(:proxy-command "nc %h %p")) nil)))
  (is (null (cl-pnet-ssh::ssh-config-proxy-command (facade-options nil) nil)))
  (is (null (cl-pnet-ssh::ssh-config-proxy-command
             (facade-options '(:proxy-command "none")) nil)))
  (is (equal "manual %h"
             (cl-pnet-ssh::ssh-config-proxy-command
              (facade-options nil) "manual %h")))
  (is (equal "nc %h %p"
             (getf (cl-pnet-ssh::ssh-config-client-parameters
                    "alias"
                    (facade-options (list :hostname "real.example" :port 2222
                                          :proxy-command "nc %h %p")))
                   :proxy-command)))
  ;; ProxyCommand wins over a ProxyJump: OpenSSH does not chain the two.
  (let ((options (facade-options '(:proxy-command "nc %h %p"
                                   :proxy-jump "jump.example"))))
    (is (equal "nc %h %p"
               (cl-pnet-ssh::ssh-config-proxy-command options nil)))))

(test facade-client-parameters-carry-the-whole-config
  (let* ((options (facade-options
                   (list :hostname "real.example"
                         :user "file-user"
                         :port 2200
                         :identity-files (list "second" "first")
                         :known-hosts (list #p"/u/known")
                         :global-known-hosts (list #p"/e/known")
                         :strict-host-key-checking "accept-new"
                         :identity-agent :none)))
         (parameters
           (cl-pnet-ssh::ssh-config-client-parameters "alias" options)))
    (is (equal "alias" (getf parameters :host)))
    (is (equal "real.example" (getf parameters :connect-host)))
    (is (equal "real.example" (getf parameters :host-key-host))
        "known_hosts must use the HostName, not the alias")
    (is (= 2200 (getf parameters :port)))
    (is (equal "file-user" (getf parameters :user)))
    (is (equal '("first" "second") (getf parameters :private-key)))
    (is (null (getf parameters :agent)))
    (is (equal '("/u/known" "/e/known")
               (mapcar #'namestring (getf parameters :known-hosts))))
    (is (eq :accept-new (getf parameters :host-key-policy))))
  ;; An explicit command-line answer still wins.
  (let ((parameters
          (cl-pnet-ssh::ssh-config-client-parameters
           "alias"
           (facade-options (list :user "file-user" :port 2200))
           :user "cli-user" :port 2222)))
    (is (equal "cli-user" (getf parameters :user)))
    (is (= 2222 (getf parameters :port)))))

(test algorithm-selection-follows-ssh-prefixes
  ;; ssh_config's +, - and ^ prefixes edit this build's list; a name it does
  ;; not offer is an error, never a silently widened offer.
  (is (equal '("chacha20-poly1305@openssh.com")
             (cl-pnet-ssh:ssh-resolve-algorithm-list
              '("chacha20-poly1305@openssh.com")
              cl-pnet-ssh:+ssh-ciphers+ "Ciphers")))
  (is (equal '("hmac-sha2-256" "hmac-sha2-512")
             (cl-pnet-ssh:ssh-resolve-algorithm-list
              '("+hmac-sha2-256") cl-pnet-ssh:+ssh-macs+ "MACs")))
  (is (equal '("hmac-sha2-512")
             (cl-pnet-ssh:ssh-resolve-algorithm-list
              '("-hmac-sha2-256") cl-pnet-ssh:+ssh-macs+ "MACs")))
  (is (equal '("hmac-sha2-512" "hmac-sha2-256")
             (cl-pnet-ssh:ssh-resolve-algorithm-list
              '("^hmac-sha2-512") cl-pnet-ssh:+ssh-macs+ "MACs")))
  ;; ssh_config allows glob patterns in these lists too.
  (is (equal '("hmac-sha2-256" "hmac-sha2-512")
             (cl-pnet-ssh:ssh-resolve-algorithm-list
              '("hmac-sha2-*") cl-pnet-ssh:+ssh-macs+ "MACs")))
  (is (equal '("curve25519-sha256")
             (cl-pnet-ssh:ssh-resolve-algorithm-list
              '("curve25519-sha256")
              cl-pnet-ssh:+ssh-kex-real-algorithms+ "KexAlgorithms")))
  (signals cl-pnet-ssh:ssh-config-error
    (cl-pnet-ssh:ssh-resolve-algorithm-list
     '("aes128-ctr") cl-pnet-ssh:+ssh-ciphers+ "Ciphers"))
  (signals cl-pnet-ssh:ssh-config-error
    (cl-pnet-ssh:ssh-resolve-algorithm-list
     '("-*") cl-pnet-ssh:+ssh-macs+ "MACs")))

(test kex-markers-survive-a-restricted-kex-list
  ;; ext-info and strict KEX are protocol markers, not choices; a KexAlgorithms
  ;; restriction must not turn them off.
  (let ((offers (map 'string #'code-char
                     (cl-pnet-ssh:ssh-make-kexinit-payload
                      :kex '("curve25519-sha256")))))
    (is (not (null (search "ext-info-c" offers))))
    (is (not (null (search "kex-strict-c-v00@openssh.com" offers))))))

(test facade-client-parameters-carry-algorithm-choices
  (let ((parameters
          (cl-pnet-ssh::ssh-config-client-parameters
           "alias"
           (facade-options
            (list :ciphers '("chacha20-poly1305@openssh.com")
                  :macs '("-hmac-sha2-256")
                  :kex-algorithms '("curve25519-sha256")
                  :host-key-algorithms '("ssh-ed25519")
                  :pubkey-accepted-algorithms '("ssh-ed25519"))))))
    (is (equal '("chacha20-poly1305@openssh.com")
               (getf parameters :ciphers)))
    (is (equal '("hmac-sha2-512") (getf parameters :macs)))
    (is (equal '("curve25519-sha256") (getf parameters :kex-algorithms)))
    (is (equal '("ssh-ed25519") (getf parameters :host-key-algorithms)))
    (is (equal '("ssh-ed25519")
               (getf parameters :pubkey-accepted-algorithms))))
  ;; Absent choices leave the client on this build's own lists.
  (let ((parameters
          (cl-pnet-ssh::ssh-config-client-parameters
           "alias" (facade-options nil))))
    (is (null (getf parameters :ciphers)))
    (is (null (getf parameters :macs)))
    (is (null (getf parameters :kex-algorithms)))
    (is (null (getf parameters :host-key-algorithms)))
    (is (null (getf parameters :pubkey-accepted-algorithms)))))

;;; ---- Command-line -o options ----

(test option-line-parses-ssh-syntax
  (let ((line (cl-pnet-ssh::ssh-config-option-line "HostName real.example")))
    (is (string= "hostname" (cl-pnet-ssh::ssh-config-line-keyword line)))
    (is (equal '("real.example") (cl-pnet-ssh::ssh-config-line-args line))))
  (let ((line (cl-pnet-ssh::ssh-config-option-line "Port=2222")))
    (is (string= "port" (cl-pnet-ssh::ssh-config-line-keyword line)))
    (is (equal '("2222") (cl-pnet-ssh::ssh-config-line-args line))))
  ;; A keyword with several arguments keeps them all, as Ciphers needs.
  (let ((line (cl-pnet-ssh::ssh-config-option-line
               "Ciphers=aes128-ctr,aes256-ctr")))
    (is (string= "ciphers" (cl-pnet-ssh::ssh-config-line-keyword line)))
    (is (equal '("aes128-ctr,aes256-ctr") (cl-pnet-ssh::ssh-config-line-args line))))
  ;; The cons form is accepted too, for callers that already split it.
  (let ((line (cl-pnet-ssh::ssh-config-option-line '("ServerAliveInterval" . 30))))
    (is (string= "serveraliveinterval" (cl-pnet-ssh::ssh-config-line-keyword line)))
    (is (equal '("30") (cl-pnet-ssh::ssh-config-line-args line))))
  (let ((line (cl-pnet-ssh::ssh-config-option-line '("Host" ("a" "b")))))
    (is (equal '("a" "b") (cl-pnet-ssh::ssh-config-line-args line))))
  (signals ssh-config-error
    (cl-pnet-ssh::ssh-config-option-line "   ")))

(test proxy-command-keeps-the-whole-shell-command
  ;; OpenSSH hands the rest of the line to the shell as written, so quotes and
  ;; internal spaces must survive -o parsing rather than becoming one token.
  (is (equal "sh -c 'exec nc %h %p'"
             (cl-pnet-ssh::ssh-config-line-raw
              (cl-pnet-ssh::ssh-config-option-line
               "ProxyCommand sh -c 'exec nc %h %p'"))))
  (is (equal "nc %h %p"
             (cl-pnet-ssh::ssh-config-line-raw
              (cl-pnet-ssh::ssh-config-option-line "ProxyCommand=nc %h %p"))))
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "ProxyCommand sh -c 'exec nc %h %p'"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (equal "sh -c 'exec nc %h %p'"
               (cl-pnet-ssh::ssh-config-options-proxy-command options)))))

(test option-lines-win-over-the-config
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line "HostName file.example")
                  (cl-pnet-ssh::ssh-config-option-line "Port 2200"))))
         (combined
           (ssh-config-add-options
            config '("HostName real.example" "Port=2222")))
         (options nil))
    (ssh-config-resolve combined "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (equal "real.example" (ssh-config-options-hostname options)))
    (is (= 2222 (ssh-config-options-port options)))
    ;; Adding no options leaves the parsed config itself untouched.
    (is (eq config (ssh-config-add-options config nil)))))

(test forwarding-lines-are-kept-in-file-order
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "LocalForward 18082 127.0.0.1:22")
                  (cl-pnet-ssh::ssh-config-option-line
                   "LocalForward 127.0.0.1:18083 127.0.0.1:22")
                  (cl-pnet-ssh::ssh-config-option-line "DynamicForward 1080"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (equal '("18082 127.0.0.1:22" "127.0.0.1:18083 127.0.0.1:22")
               ;; The slots are built by pushing, so reading them back in
               ;; file order means reversing once.
               (reverse (ssh-config-options-local-forwards options))))
    (is (equal '("1080")
               (reverse (ssh-config-options-dynamic-forwards options))))
    ;; A command line -o LocalForward is a forwarding line too.
    (let ((combined (ssh-config-add-options
                     config '("LocalForward 18084 127.0.0.1:22")))
          (more nil))
      (ssh-config-resolve combined "alias"
                          :on-options (lambda (value) (setf more value)))
      (is (equal '("18084 127.0.0.1:22" "18082 127.0.0.1:22"
                   "127.0.0.1:18083 127.0.0.1:22")
                 (reverse (ssh-config-options-local-forwards more)))))))

(test hashed-known-hosts-round-trip
  "HashKnownHosts writes a salted hash that still matches the same host."
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-hash-known"))
         (path (merge-pathnames "known_hosts" directory))
         (blob (ssh-random-octets 32)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (ssh-remember-known-host path "example.org" "ssh-ed25519" blob
                                    :hash t)
           (let ((line (with-open-file (in path)
                         (read-line in))))
             (is (not (search "example.org" line)))
             (is (eql 0 (search "|1|" line))))
           (is (eq :match
                   (ssh-known-host-status path "example.org" blob)))
           (is (eq :unknown
                   (ssh-known-host-status path "other.example" blob)))
           ;; Without HASH the name stays readable, as before.
           (ssh-remember-known-host path "plain.example" "ssh-ed25519" blob)
           (is (eq :match
                   (ssh-known-host-status path "plain.example" blob))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test fingerprints-obey-the-hash-choice
  (let ((blob (ssh-random-octets 32)))
    (is (eql 0 (search "SHA256:" (ssh-key-fingerprint blob))))
    (let ((md5 (ssh-key-fingerprint blob :md5)))
      (is (eql 0 (search "MD5:" md5)))
      ;; MD5: plus sixteen two-hex groups and their separators.
      (is (= 16 (count #\: md5))))))

(test fingerprint-hash-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "FingerprintHash md5"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (eq :md5 (ssh-config-options-fingerprint-hash options))))
  (let* ((config (cl-pnet-ssh::%make-ssh-config :directives nil))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-fingerprint-hash options))))
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "FingerprintHash sha1"))))
         (failure nil))
    (ssh-config-resolve config "alias"
                        :on-error (lambda (condition)
                                    (setf failure condition)))
    (is (typep failure 'ssh-config-error))))

(test log-level-and-log-verbose-parse
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "LogLevel DEBUG2")
                  (cl-pnet-ssh::ssh-config-option-line
                   "LogVerbose kex.c:*"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (equal "debug2" (ssh-config-options-log-level options)))
    (is (equal '("kex.c:*") (ssh-config-options-log-verbose options))))
  (let* ((config (cl-pnet-ssh::%make-ssh-config :directives nil))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-log-level options))))
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "LogLevel LOUD"))))
         (failure nil))
    (ssh-config-resolve config "alias"
                        :on-error (lambda (condition)
                                    (setf failure condition)))
    (is (typep failure 'ssh-config-error))))

(test local-command-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "PermitLocalCommand yes")
                  (cl-pnet-ssh::ssh-config-option-line
                   "LocalCommand printf '%h %p'"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (eq t (ssh-config-options-permit-local-command options)))
    (is (equal "printf '%h %p'"
               (ssh-config-options-local-command options))))
  (let* ((config (cl-pnet-ssh::%make-ssh-config :directives nil))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-permit-local-command options)))
    (is (null (ssh-config-options-local-command options)))))

(test remote-command-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "RemoteCommand printf '%h %p %r %n %%'"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (equal "printf '%h %p %r %n %%'"
               (ssh-config-options-remote-command options))))
  (let* ((config (cl-pnet-ssh::%make-ssh-config :directives nil))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-remote-command options)))))

(test permit-remote-open-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "PermitRemoteOpen example.org:80 [::1]:2222 *:*"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (equal '(("example.org" . 80) ("::1" . 2222) ("*" . :any))
               (ssh-config-options-permit-remote-open options))))
  (flet ((value (line)
           (let* ((config
                    (cl-pnet-ssh::%make-ssh-config
                     :directives
                     (list (cl-pnet-ssh::ssh-config-option-line line))))
                  (options nil))
             (ssh-config-resolve config "alias"
                                 :on-options
                                 (lambda (value) (setf options value)))
             (ssh-config-options-permit-remote-open options))))
    (is (eq :any (value "PermitRemoteOpen any")))
    (is (eq :none (value "PermitRemoteOpen none")))
    (is (null (value "Port 22"))))
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "PermitRemoteOpen example.org"))))
         (failure nil))
    (ssh-config-resolve config "alias"
                        :on-error (lambda (condition)
                                    (setf failure condition)))
    (is (typep failure 'ssh-config-error))))

(test clear-all-forwardings-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "ClearAllForwardings yes"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (eq t (ssh-config-options-clear-all-forwardings options))))
  (let* ((config (cl-pnet-ssh::%make-ssh-config :directives nil))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-clear-all-forwardings options)))))

(test host-key-alias-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "HostKeyAlias myalias"))))
         (options nil))
    (ssh-config-resolve config "example.org"
                        :on-options (lambda (value) (setf options value)))
    (is (equal "myalias" (ssh-config-options-host-key-alias options)))
    ;; The alias is what known_hosts and host certificates are checked under.
    (is (equal "myalias"
               (getf (cl-pnet-ssh::ssh-config-client-parameters
                      "example.org" options)
                     :host-key-host)))))

(test connection-attempts-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "ConnectionAttempts 3"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (= 3 (ssh-config-options-connection-attempts options))))
  (let* ((config (cl-pnet-ssh::%make-ssh-config :directives nil))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-connection-attempts options))))
  ;; Zero attempts is not a connection policy.
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "ConnectionAttempts 0"))))
         (failure nil))
    (ssh-config-resolve config "alias"
                        :on-error (lambda (condition)
                                    (setf failure condition)))
    (is (typep failure 'ssh-config-error))))

(test session-type-and-stdin-null-parse
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "SessionType none")
                  (cl-pnet-ssh::ssh-config-option-line
                   "StdinNull yes"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (equal "none" (ssh-config-options-session-type options)))
    (is (eq t (ssh-config-options-stdin-null options))))
  (let* ((config (cl-pnet-ssh::%make-ssh-config :directives nil))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-session-type options)))
    (is (null (ssh-config-options-stdin-null options))))
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "SessionType nonsense"))))
         (failure nil))
    (ssh-config-resolve config "alias"
                        :on-error (lambda (condition)
                                    (setf failure condition)))
    (is (typep failure 'ssh-config-error))))

(test setenv-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "SetEnv FOO=bar BAZ=qux")
                  (cl-pnet-ssh::ssh-config-option-line
                   "SetEnv LATER=ignored"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    ;; ssh keeps the first active SetEnv line.
    (is (equal '("FOO=bar" "BAZ=qux")
               (ssh-config-options-set-env options))))
  ;; A duplicate name within the line keeps the first assignment.
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "SetEnv A=1 A=2 B=3"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (equal '("A=1" "B=3")
               (ssh-config-options-set-env options))))
  ;; An assignment without '=' is a configuration error.
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "SetEnv NOEQUALS"))))
         (failure nil))
    (ssh-config-resolve config "alias"
                        :on-error (lambda (condition)
                                    (setf failure condition)))
    (is (typep failure 'ssh-config-error))))

(test tcp-keepalive-parses
  (flet ((value (line)
           (let* ((config
                    (cl-pnet-ssh::%make-ssh-config
                     :directives
                     (list (cl-pnet-ssh::ssh-config-option-line line))))
                  (options nil))
             (ssh-config-resolve config "alias"
                                 :on-options
                                 (lambda (value) (setf options value)))
             (ssh-config-options-tcp-keep-alive options))))
    (is (eq t (value "TCPKeepAlive yes")))
    (is (null (value "TCPKeepAlive no")))
    ;; KeepAlive is the old spelling of the same keyword.
    (is (null (value "KeepAlive no")))
    (is (eq t (value "Port 22")))))

(test exit-on-forward-failure-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "ExitOnForwardFailure yes"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (eq t (ssh-config-options-exit-on-forward-failure options))))
  (let* ((config (cl-pnet-ssh::%make-ssh-config :directives nil))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-exit-on-forward-failure options)))))

(test hash-known-hosts-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "HashKnownHosts yes"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (eq t (ssh-config-options-hash-known-hosts options))))
  (let* ((config (cl-pnet-ssh::%make-ssh-config :directives nil))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-hash-known-hosts options)))))

(test refuse-connection-stops-resolution
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "RefuseConnection \"maintenance window\""))))
         (failure nil)
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value))
                        :on-error (lambda (condition) (setf failure condition)))
    (is (typep failure 'ssh-config-error))
    (is (search "maintenance window" (princ-to-string failure)))
    (is (null options)))
  ;; A RefuseConnection in a Host block that does not match is inert.
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line "Host other")
                  (cl-pnet-ssh::ssh-config-option-line
                   "RefuseConnection not for you")
                  (cl-pnet-ssh::ssh-config-option-line "Host alias")
                  (cl-pnet-ssh::ssh-config-option-line "Port 2222"))))
         (failure nil)
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value))
                        :on-error (lambda (condition) (setf failure condition)))
    (is (null failure))
    (is (= 2222 (ssh-config-options-port options)))))

(test revoked-host-keys-parse
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "RevokedHostKeys /tmp/one")
                  (cl-pnet-ssh::ssh-config-option-line
                   "RevokedHostKeys /tmp/two"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (equal '("/tmp/one" "/tmp/two")
               (mapcar #'namestring
                       (reverse
                        (ssh-config-options-revoked-host-keys options))))))
  ;; NONE clears the list, as ssh's oRevokedHostKeys does.
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "RevokedHostKeys /tmp/one")
                  (cl-pnet-ssh::ssh-config-option-line
                   "RevokedHostKeys none"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-revoked-host-keys options)))))

(test ca-signature-algorithms-parses
  (flet ((parameters (line)
           (let* ((config
                    (cl-pnet-ssh::%make-ssh-config
                     :directives
                     (list (cl-pnet-ssh::ssh-config-option-line line))))
                  (options nil))
             (ssh-config-resolve config "alias"
                                 :on-options
                                 (lambda (value) (setf options value)))
             (cl-pnet-ssh::ssh-config-client-parameters "alias" options))))
    ;; Unset leaves the build's default, which excludes SHA-1 ssh-rsa.
    (is (null (getf (parameters "Port 22") :ca-signature-algorithms)))
    (is (equal '("ssh-ed25519")
               (getf (parameters "CASignatureAlgorithms ssh-ed25519")
                     :ca-signature-algorithms)))
    ;; ssh-rsa is not in the default but may be opted into, by prefix or
    ;; by naming it alone.
    (is (member "ssh-rsa"
                (getf (parameters "CASignatureAlgorithms +ssh-rsa")
                      :ca-signature-algorithms)
                :test #'string=))
    (is (equal '("ssh-rsa")
               (getf (parameters "CASignatureAlgorithms ssh-rsa")
                     :ca-signature-algorithms)))))

(test required-rsa-size-parses
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "RequiredRSASize 2048"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (= 2048 (ssh-config-options-required-rsa-size options)))
    (is (= 2048 (getf (cl-pnet-ssh::ssh-config-client-parameters
                       "alias" options)
                      :required-rsa-size))))
  ;; Unset means OpenSSH's default floor of 1024.
  (let* ((config (cl-pnet-ssh::%make-ssh-config :directives nil))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (= 1024 (getf (cl-pnet-ssh::ssh-config-client-parameters
                       "alias" options)
                      :required-rsa-size)))))

(test stream-local-bind-options-parse
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "StreamLocalBindMask 0177")
                  (cl-pnet-ssh::ssh-config-option-line
                   "StreamLocalBindUnlink yes"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (= #o177 (ssh-config-options-streamlocal-bind-mask options)))
    (is (eq t (ssh-config-options-streamlocal-bind-unlink options))))
  ;; Unset means the caller supplies OpenSSH's defaults: 0177 and no.
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line "Port 22"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (null (ssh-config-options-streamlocal-bind-mask options)))
    (is (null (ssh-config-options-streamlocal-bind-unlink options)))))

(test user-config-values-come-before-the-system-file
  (let* ((system
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line "Port 22")
                  (cl-pnet-ssh::ssh-config-option-line
                   "HostName system.example"))))
         (user
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line "Port 2200")
                  (cl-pnet-ssh::ssh-config-option-line "User alice"))))
         (options nil))
    (ssh-config-resolve (ssh-config-combine user system) "alias"
                        :on-options (lambda (value) (setf options value)))
    ;; OpenSSH reads the user file first and every keyword keeps its first
    ;; value, so the user's Port wins; the system file still supplies what
    ;; the user file omitted.
    (is (= 2200 (ssh-config-options-port options)))
    (is (equal "system.example" (ssh-config-options-hostname options)))
    (is (equal "alice" (ssh-config-options-user options)))
    ;; An absent file contributes nothing.
    (is (eq user (ssh-config-combine user nil)))))

(test client-source-applies-options-before-the-file
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-opt"))
         (path (merge-pathnames "config" directory)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (with-open-file (stream path :direction :output
                                        :if-exists :supersede)
             (format stream "HostName file.example~%Port 2200~%"))
           (let ((options nil))
             (ssh-config-resolve
              (cl-pnet-ssh::ssh-config-client-source
               path '("HostName cli.example" "Port=2222"))
              "alias"
              :on-options (lambda (value) (setf options value)))
             (is (equal "cli.example" (ssh-config-options-hostname options)))
             (is (= 2222 (ssh-config-options-port options)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test facade-client-parameters-carry-timeouts
  (let ((parameters
          (cl-pnet-ssh::ssh-config-client-parameters
           "alias"
           (facade-options (list :connect-timeout 15
                                 :server-alive-interval 30
                                 :server-alive-count-max 2)))))
    (is (= 15 (getf parameters :connect-timeout)))
    (is (= 30 (getf parameters :server-alive-interval)))
    (is (= 2 (getf parameters :server-alive-count-max))))
  ;; "none" and 0 both mean the feature is off.
  (let ((parameters
          (cl-pnet-ssh::ssh-config-client-parameters
           "alias"
           (facade-options (list :connect-timeout :none
                                 :server-alive-interval 0)))))
    (is (null (getf parameters :connect-timeout)))
    (is (null (getf parameters :server-alive-interval)))))

(test client-record-holds-timing-settings
  (let ((client (cl-pnet-ssh::%make-ssh-client
                 :host "example" :connect-host "example"
                 :host-key-host "example" :port 22 :connect-port 22
                 :user "tester"
                 :connect-timeout 10
                 :server-alive-interval 5
                 :server-alive-count-max 2)))
    (is (= 10 (cl-pnet-ssh::ssh-client-connect-timeout client)))
    (is (= 5 (cl-pnet-ssh::ssh-client-server-alive-interval client)))
    (is (= 2 (cl-pnet-ssh::ssh-client-server-alive-count-max client)))
    (is (null (cl-pnet-ssh::ssh-client-connect-timer client)))
    (is (null (cl-pnet-ssh::ssh-client-alive-timer client)))))

(test proxy-command-none-means-direct
  ;; "ProxyCommand none" is OpenSSH's way of turning a proxy off, so it must
  ;; not try to run a helper called none.
  (is (null (cl-pnet-ssh::ssh-proxy-command-value nil)))
  (is (null (cl-pnet-ssh::ssh-proxy-command-value "none")))
  (is (null (cl-pnet-ssh::ssh-proxy-command-value "  NONE  ")))
  (is (null (cl-pnet-ssh::ssh-proxy-command-value "   ")))
  (is (equal "nc %h %p"
             (cl-pnet-ssh::ssh-proxy-command-value " nc %h %p "))))

#-ssh-backend-ffi
(test proxy-command-expands-ssh-escapes
  (let ((client (cl-pnet-ssh::%make-ssh-client
                 :host "alias" :connect-host "real.example"
                 :port 2222 :connect-port 2222 :user "alice")))
    (is (equal "nc real.example 2222"
               (cl-pnet-ssh::ssh-proxy-expand-command "nc %h %p" client)))
    (is (equal "alias:alice:100%"
               (cl-pnet-ssh::ssh-proxy-expand-command
                "%n:%r:100%%" client)))
    ;; An escape this client does not know stays literal rather than eaten.
    (is (equal "%z and %" (cl-pnet-ssh::ssh-proxy-expand-command
                           "%z and %" client)))))

;;; ---- RSA and ECDSA host/user keys ----

(test openssh-rsa-private-key-round-trip
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-rsa"))
             (path (merge-pathnames "id_rsa" directory)))
        (ensure-directories-exist path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "2048" "-N" ""
                                 "-f" (namestring path)))
               (let* ((key (ssh-load-private-key path))
                      (blob (ssh-public-key-blob-of key))
                      (type (nth-value 0 (ssh-public-key-parts blob)))
                      (message (octets-ascii "rsa signed data"))
                      (signature (cl-pnet-ssh::ssh-private-key-signature-blob key message)))
                 (is (string= "ssh-rsa" type))
                 ;; The request names rsa-sha2-256 while the key stays ssh-rsa.
                 (multiple-value-bind (algorithm bytes)
                     (ssh-parse-signature-blob signature)
                   (declare (ignore bytes))
                   (is (string= "rsa-sha2-256" algorithm)))
                 (is (null (cl-pnet-ssh::ssh-verify-host-signature
                            blob signature message)))
                 (signals ssh-protocol-error
                   (cl-pnet-ssh::ssh-verify-host-signature
                    blob signature (octets-ascii "different data")))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test openssh-ecdsa-private-key-signs
  ;; An ECDSA key file holds the scalar and the point; signing must produce
  ;; the two mpints RFC 5656 wants, and the curve key type must survive.
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (dolist (spec '(("id_ecdsa_256" "256" "ecdsa-sha2-nistp256")
                      ("id_ecdsa_384" "384" "ecdsa-sha2-nistp384")
                      ("id_ecdsa_521" "521" "ecdsa-sha2-nistp521")))
        (destructuring-bind (name bits type) spec
          (let* ((directory (ssh-test-directory "cl-pnet-ssh-ecdsa-sign"))
                 (path (merge-pathnames name directory)))
            (ensure-directories-exist path)
            (unwind-protect
                 (progn
                   (ssh-keygen (list "-q" "-t" "ecdsa" "-b" bits "-N" ""
                                     "-f" (namestring path)))
                   (let* ((key (ssh-load-private-key path))
                          (blob (ssh-public-key-blob-of key))
                          (message (octets-ascii (format nil "ecdsa ~A signed" bits)))
                          (signature
                            (cl-pnet-ssh::ssh-private-key-signature-blob
                             key message)))
                     (is (string= type (nth-value 0 (ssh-public-key-parts blob))))
                     (multiple-value-bind (algorithm bytes)
                         (ssh-parse-signature-blob signature)
                       (declare (ignore bytes))
                       (is (string= type algorithm)))
                     (is (null (cl-pnet-ssh::ssh-verify-host-signature
                                blob signature message)))
                     (signals ssh-protocol-error
                       (cl-pnet-ssh::ssh-verify-host-signature
                        blob signature (octets-ascii "different data")))))
              (ignore-errors (uiop:delete-directory-tree directory :validate t))))))))

(defun ssh-test-public-key-file-blob (private-key-path)
  "The wire blob encoded in the .pub file beside PRIVATE-KEY-PATH."
  (let* ((line (with-open-file (stream (concatenate 'string
                                                    (namestring private-key-path)
                                                    ".pub"))
                 (read-line stream)))
         (fields (uiop:split-string line :separator '(#\Space))))
    (cl-base64:base64-string-to-usb8-array (second fields))))

(test public-key-blobs-match-ssh-keygen
  ;; ssh-keygen's .pub file holds the exact wire blob, so comparing against
  ;; it catches a key blob that round-trips locally but cannot be sent: an
  ;; ssh-rsa blob has two bare mpints, not one length-prefixed string.
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (dolist (spec '(("id_ed25519" "ed25519" nil)
                      ("id_rsa" "rsa" "2048")
                      ("id_ecdsa_256" "ecdsa" "256")
                      ("id_ecdsa_384" "ecdsa" "384")
                      ("id_ecdsa_521" "ecdsa" "521")))
        (destructuring-bind (name type bits) spec
          (let* ((directory (ssh-test-directory "cl-pnet-ssh-pub"))
                 (path (merge-pathnames name directory)))
            (ensure-directories-exist path)
            (unwind-protect
                 (progn
                   (ssh-keygen
                    (append (list "-q" "-t" type)
                            (when bits (list "-b" bits))
                            (list "-N" "" "-f" (namestring path))))
                   (let ((key (ssh-load-private-key path)))
                     (is (equalp (ssh-test-public-key-file-blob path)
                                 (ssh-public-key-blob-of key))
                         "~A uses the wire blob ssh-keygen wrote" name)))
              (ignore-errors (uiop:delete-directory-tree directory :validate t))))))))

(defun ssh-test-ecdsa-signature (raw)
  "RAW r||s as the SSH signature value: string r then string s.

An integer whose top bit is set gets the mpint leading zero, so the test
also covers that the verifier trims it before padding to the curve width."
  (let* ((middle (/ (length raw) 2))
         (writer (ssh-writer)))
    (ssh-write-mpint writer (ssh-mpint-integer (subseq raw 0 middle)))
    (ssh-write-mpint writer (ssh-mpint-integer (subseq raw middle)))
    (ssh-writer-output writer)))

(test ecdsa-host-signatures-verify
  ;; Every curve SSH names, with several signatures each so the leading-zero
  ;; cases are actually exercised rather than left to chance.
  (dolist (spec '(("nistp256" :secp256r1 :sha256 "ecdsa-sha2-nistp256")
                  ("nistp384" :secp384r1 :sha384 "ecdsa-sha2-nistp384")
                  ("nistp521" :secp521r1 :sha512 "ecdsa-sha2-nistp521")))
    (destructuring-bind (curve-name curve digest-name type) spec
      (multiple-value-bind (private public)
          (ironclad-unsafe:generate-key-pair curve)
        (let* ((point (getf (ironclad-unsafe:destructure-public-key public)
                            :y))
               (key-data (let ((writer (ssh-writer)))
                           (ssh-write-text writer curve-name)
                           (ssh-write-string writer point)
                           (ssh-writer-output writer)))
               (blob (ssh-make-public-key-blob type key-data)))
          (dotimes (i 5)
            (let* ((message
                     (ssh-hash :sha256
                               (octets-ascii
                                (format nil "ecdsa-~A-~D" curve-name i))))
                   (digest (ssh-hash digest-name message))
                   (encoded (ssh-test-ecdsa-signature
                             (ironclad-unsafe:sign-message private digest)))
                   (signature (let ((writer (ssh-writer)))
                                (ssh-write-text writer type)
                                (ssh-write-string writer encoded)
                                (ssh-writer-output writer))))
              (is (cl-pnet-ssh::ssh-ecdsa-verify key-data encoded message))
              (is (null (cl-pnet-ssh::ssh-verify-host-signature
                         blob signature message)))
              (is (not (cl-pnet-ssh::ssh-ecdsa-verify
                        key-data encoded
                        (ssh-hash :sha256 (octets-ascii "other"))))))))))))

;;; ---- sshd_config include anchors and AcceptEnv globbing ----

(test ssh-config-include-base-follows-the-config-kind
  ;; A system ssh_config anchors a relative Include at /etc/ssh, while a user
  ;; one anchors it at ~/.ssh, matching OpenSSH.
  (is (equal "/etc/ssh/conf.d/extra.conf"
             (namestring (cl-pnet-ssh::ssh-config-include-path
                          "conf.d/extra.conf" :user-config nil))))
  (is (equal (namestring (merge-pathnames
                          ".ssh/conf.d/extra.conf"
                          (user-homedir-pathname)))
             (namestring (cl-pnet-ssh::ssh-config-include-path
                          "conf.d/extra.conf" :user-config t))))
  (is (equal "/absolute/ssh_config"
             (namestring (cl-pnet-ssh::ssh-config-include-path
                          "/absolute/ssh_config" :user-config nil)))))

(test ssh-match-pattern-uses-only-star-and-question
  (is (cl-pnet-ssh:ssh-match-pattern "LANG" "LANG"))
  (is (not (cl-pnet-ssh:ssh-match-pattern "LANG" "LANGUAGE")))
  (is (cl-pnet-ssh:ssh-match-pattern "LC_*" "LC_ALL"))
  (is (cl-pnet-ssh:ssh-match-pattern "LC_*" "LC_"))
  (is (not (cl-pnet-ssh:ssh-match-pattern "LC_*" "LANG")))
  (is (cl-pnet-ssh:ssh-match-pattern "A?C" "ABC"))
  (is (not (cl-pnet-ssh:ssh-match-pattern "A?C" "AC")))
  ;; Brackets are literal in sshd's matcher, unlike a shell glob.
  (is (not (cl-pnet-ssh:ssh-match-pattern "[AB]" "A")))
  (is (cl-pnet-ssh:ssh-match-pattern "[AB]" "[AB]")))

(test ssh-match-pattern-is-not-case-folding
  (is (not (cl-pnet-ssh:ssh-match-pattern "LANG" "lang")))
  (is (not (cl-pnet-ssh:ssh-match-pattern "LC_*" "lc_all"))))

(defparameter +test-authorized-key-blob+
  "AAAAB3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
  "A well-formed ed25519 public key blob for the authorized_keys tests.")

(test authorized-keys-options-carry-environment
  ;; sshd reads environment="NAME=VALUE" options on the key line and applies
  ;; them under PermitUserEnvironment.  The options precede the key type and
  ;; may hold quoted commas and spaces.
  (let ((line (format nil
                      "environment=\"LANG=en_US.UTF-8\",environment=\"GREETING=hello, world\" ssh-ed25519 ~A comment"
                      +test-authorized-key-blob+)))
    (is (equal '("LANG=en_US.UTF-8" "GREETING=hello, world")
               (cl-pnet-ssh:ssh-authorized-key-line-environments line)))
    ;; The options do not stop the key from being recognised.
    (is (cl-pnet-ssh:ssh-authorized-key-line-blob line)))
  ;; A variable name sshd would refuse makes it skip the whole line.
  (is (null (cl-pnet-ssh:ssh-authorized-key-line-environments
             (format nil "environment=\"BAD-NAME=x\" ssh-ed25519 ~A"
                     +test-authorized-key-blob+))))
  (is (null (cl-pnet-ssh:ssh-authorized-key-line-blob
             (format nil "environment=\"BAD-NAME=x\" ssh-ed25519 ~A"
                     +test-authorized-key-blob+))))
  (is (null (cl-pnet-ssh:ssh-authorized-key-line-environments
             (format nil "ssh-ed25519 ~A" +test-authorized-key-blob+)))))

(test authorized-key-blob-match-returns-the-first-lines-environment
  "The line that authenticates the user supplies its environment= options."
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-key-env"))
         (authorized (merge-pathnames "authorized_keys" directory)))
    (ensure-directories-exist authorized)
    (unwind-protect
         (progn
           (with-open-file (stream authorized :direction :output
                                             :if-exists :supersede
                                             :if-does-not-exist :create)
             (format stream "environment=\"FROM=first\" ssh-ed25519 ~A one~%"
                     +test-authorized-key-blob+)
             (format stream "environment=\"FROM=second\" ssh-ed25519 ~A two~%"
                     +test-authorized-key-blob+))
           (multiple-value-bind (blob options)
               (cl-pnet-ssh:ssh-authorized-key-line-parts
                (format nil "ssh-ed25519 ~A" +test-authorized-key-blob+))
             (declare (ignore options))
             (multiple-value-bind (matched environment)
                 (cl-pnet-ssh:ssh-authorized-key-blob-match authorized blob)
               (is (not (null matched)))
               (is (equal '("FROM=first") environment)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test authorized-keys-options-follow-sshd
  "Key options decide pty, forwarding, command and environment, and an
option the server cannot honour refuses the line rather than being lost."
  (labels ((parse (text)
             (multiple-value-bind (options valid)
                 (cl-pnet-ssh:ssh-authorized-key-options-parse text)
               (values options valid))))
    ;; No options keeps every default.
    (multiple-value-bind (options valid) (parse "")
      (is (not (null valid)))
      (is (cl-pnet-ssh:ssh-authorization-options-permit-pty-p options))
      (is (cl-pnet-ssh:ssh-authorization-options-permit-port-forwarding-p
           options))
      (is (null (cl-pnet-ssh:ssh-authorization-options-force-command options))))
    ;; Negative flags, positive re-enable, and restrict clears everything.
    (multiple-value-bind (options valid) (parse "no-pty,no-port-forwarding")
      (is (not (null valid)))
      (is (not (cl-pnet-ssh:ssh-authorization-options-permit-pty-p options)))
      (is (not (cl-pnet-ssh:ssh-authorization-options-permit-port-forwarding-p
                options))))
    (multiple-value-bind (options valid) (parse "restrict,pty")
      (is (not (null valid)))
      (is (cl-pnet-ssh:ssh-authorization-options-permit-pty-p options))
      (is (not (cl-pnet-ssh:ssh-authorization-options-permit-port-forwarding-p
                options))))
    ;; Unknown options, TUN and the unsupported positive forms make sshd skip
    ;; the whole line.  Certificate options are understood.
    (dolist (text '("no-such-option" "tunnel=\"0\""
                    "touch-required" "verify-required"
                    "user-rc" "pty,,no-pty" "command=\"unterminated"))
      (is (null (nth-value 0 (parse text))) text)
      (is (null (nth-value 1 (parse text))) text))
    (multiple-value-bind (options valid) (parse "cert-authority")
      (is (not (null valid)))
      (is (cl-pnet-ssh:ssh-authorization-options-cert-authority options))
      (is (null (cl-pnet-ssh:ssh-authorization-options-cert-principals
                 options))))
    (multiple-value-bind (options valid)
        (parse "cert-authority,principals=\"alice,bob\"")
      (is (not (null valid)))
      (is (cl-pnet-ssh:ssh-authorization-options-cert-authority options))
      (is (string= "alice,bob"
                   (cl-pnet-ssh:ssh-authorization-options-cert-principals
                    options))))
    ;; sshd refuses a second principals= clause and an unquoted value.
    (dolist (text '("principals=\"a\",principals=\"b\"" "principals=alice"
                    "principals=\"unterminated"))
      (is (null (nth-value 0 (parse text))) text)
      (is (null (nth-value 1 (parse text))) text))
    (multiple-value-bind (options valid)
        (parse "no-touch-required,no-verify-required,no-user-rc")
      (declare (ignore options))
      (is (not (null valid))))
    ;; command= is the forced command; a second one is refused.
    (multiple-value-bind (options valid) (parse "command=\"echo hi\"")
      (is (not (null valid)))
      (is (equal "echo hi"
                 (cl-pnet-ssh:ssh-authorization-options-force-command
                  options))))
    (is (null (nth-value 1 (parse "command=\"a\",command=\"b\""))))
    ;; from= is one address list, and a missing address fails closed.
    (multiple-value-bind (options valid)
        (parse "from=\"10.0.0.0/8,!10.1.2.3\"")
      (is (not (null valid)))
      (is (cl-pnet-ssh:ssh-authorization-options-permit-address-p
           options "10.9.8.7"))
      (is (not (cl-pnet-ssh:ssh-authorization-options-permit-address-p
                options "10.1.2.3")))
      (is (not (cl-pnet-ssh:ssh-authorization-options-permit-address-p
                options "192.168.0.1")))
      (is (not (cl-pnet-ssh:ssh-authorization-options-permit-address-p
                options nil))))
    (is (null (nth-value 1 (parse "from=\"a\",from=\"b\""))))
    ;; permitopen= is exact host and port, with * as the only wildcard.
    (multiple-value-bind (options valid)
        (parse "permitopen=\"host:22\",permitopen=\"[::1]:*\"")
      (is (not (null valid)))
      (is (cl-pnet-ssh:ssh-authorization-options-permit-open-p
           options "host" 22))
      (is (not (cl-pnet-ssh:ssh-authorization-options-permit-open-p
                options "host" 23)))
      (is (cl-pnet-ssh:ssh-authorization-options-permit-open-p
           options "::1" 999))
      (is (not (cl-pnet-ssh:ssh-authorization-options-permit-open-p
                options "other" 22))))
    ;; A bare permitlisten= port means every address, as sshd expands it.
    (multiple-value-bind (options valid)
        (parse "permitlisten=\"127.0.0.1:8080\",permitlisten=\"9000\"")
      (is (not (null valid)))
      (is (cl-pnet-ssh:ssh-authorization-options-permit-listen-p
           options "127.0.0.1" 8080))
      (is (not (cl-pnet-ssh:ssh-authorization-options-permit-listen-p
                options "localhost" 8080)))
      (is (cl-pnet-ssh:ssh-authorization-options-permit-listen-p
           options "0.0.0.0" 9000)))
    ;; expiry-time= is a universal time; the earliest value wins.
    (multiple-value-bind (options valid)
        (parse "expiry-time=\"29990101\"")
      (is (not (null valid)))
      (is (cl-pnet-ssh:ssh-authorization-options-permit-now-p
           options (encode-universal-time 0 0 0 1 1 2026 0))))
    (multiple-value-bind (options valid)
        (parse "expiry-time=\"20000101\"")
      (is (not (null valid)))
      (is (not (cl-pnet-ssh:ssh-authorization-options-permit-now-p
                options (encode-universal-time 0 0 0 1 1 2026 0)))))
    (is (null (nth-value 1 (parse "expiry-time=\"2999\""))))
    ;; The first environment= for a name wins, as sshd's parser does.
    (multiple-value-bind (options valid)
        (parse "environment=\"A=1\",environment=\"A=2\",environment=\"B=3\"")
      (is (not (null valid)))
      (is (equal '("A=1" "B=3")
                 (cl-pnet-ssh:ssh-authorization-options-environments
                  options))))))

(test authorized-key-line-splits-options-like-sshd
  "Option values must be quoted, and a space ends the options as in sshd."
  (let ((key (format nil "ssh-ed25519 ~A" +test-authorized-key-blob+)))
    ;; sshd's opt_dequote requires the opening quote.
    (is (null (cl-pnet-ssh:ssh-authorized-key-line-blob
               (format nil "no-pty,from=10.0.0.1 ~A" key))))
    ;; sshd stops the options at the first unquoted space, so the token it
    ;; would read as a key type here is "hi" and the line is refused.
    (is (null (cl-pnet-ssh:ssh-authorized-key-line-blob
               (format nil "command=echo hi ~A" key))))
    ;; Quoting keeps the space inside the value.
    (multiple-value-bind (blob options parsed)
        (cl-pnet-ssh:ssh-authorized-key-line-parts
         (format nil "command=\"echo hi\" ~A" key))
      (is (not (null blob)))
      (is (equal "command=\"echo hi\"" options))
      (is (equal "echo hi"
                 (cl-pnet-ssh:ssh-authorization-options-force-command
                  parsed))))
    ;; Only \" escapes in sshd's opt_dequote; other backslashes pass through.
    (multiple-value-bind (blob options parsed)
        (cl-pnet-ssh:ssh-authorized-key-line-parts
         (format nil "command=\"printf \\\"hi\\\" \\\\n\" ~A" key))
      (declare (ignore options))
      (is (not (null blob)))
      (is (equal "printf \"hi\" \\\\n"
                 (cl-pnet-ssh:ssh-authorization-options-force-command
                  parsed))))))

(test authorized-key-blob-match-checks-from-and-expiry
  "A matching key is refused when from= or expiry-time= excludes this peer."
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-key-policy"))
         (authorized (merge-pathnames "authorized_keys" directory)))
    (ensure-directories-exist authorized)
    (unwind-protect
         (progn
           (with-open-file (stream authorized :direction :output
                                             :if-exists :supersede
                                             :if-does-not-exist :create)
             (format stream "from=\"127.0.0.1\",no-pty ssh-ed25519 ~A~%"
                     +test-authorized-key-blob+))
           (multiple-value-bind (matched environment options)
               (cl-pnet-ssh:ssh-authorized-key-blob-match
                authorized (cl-pnet-ssh:ssh-authorized-key-line-blob
                            (format nil "ssh-ed25519 ~A"
                                    +test-authorized-key-blob+))
                :address "127.0.0.1")
             (is (not (null matched)))
             (is (null environment))
             (is (not (cl-pnet-ssh:ssh-authorization-options-permit-pty-p
                       options))))
           (is (null (cl-pnet-ssh:ssh-authorized-key-blob-match
                      authorized (cl-pnet-ssh:ssh-authorized-key-line-blob
                                  (format nil "ssh-ed25519 ~A"
                                          +test-authorized-key-blob+))
                      :address "10.0.0.1"))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test server-records-authorized-key-environment
  "A successful publickey login keeps the environment= options it carried."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (opened error greeting banner key-env)
          (ssh-test-loopback-outcome
           (lambda (client fingerprint key)
             (declare (ignore client fingerprint key))
             t)
           :authorized-options
           "environment=\"LANG=en_US.UTF-8\",environment=\"TZ=UTC\"")
        (declare (ignore greeting banner))
        (is (null error))
        (is (not (null opened)))
        (is (equal '("LANG=en_US.UTF-8" "TZ=UTC") key-env)))))

(test session-forwarding-policy-follows-key-options
  "no-port-forwarding, permitopen= and permitlisten= reach the session."
  (let* ((server (cl-pnet-ssh::%make-ssh-server))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (options (lambda (text)
                    (nth-value 0
                               (cl-pnet-ssh:ssh-authorized-key-options-parse
                                text)))))
    ;; An unrestricted key keeps sshd's defaults.
    (is (cl-pnet-ssh:ssh-session-permits-direct-tcpip-p session "host" 22))
    (is (cl-pnet-ssh:ssh-session-permits-tcpip-forward-p session "host" 22))
    ;; no-port-forwarding stops both directions.
    (setf (cl-pnet-ssh:ssh-session-authorization session)
          (funcall options "no-port-forwarding"))
    (is (not (cl-pnet-ssh:ssh-session-permits-direct-tcpip-p session "host" 22)))
    (is (not (cl-pnet-ssh:ssh-session-permits-tcpip-forward-p session "host" 22)))
    ;; permitopen= restricts the local direction only.
    (setf (cl-pnet-ssh:ssh-session-authorization session)
          (funcall options "permitopen=\"host:22\""))
    (is (cl-pnet-ssh:ssh-session-permits-direct-tcpip-p session "host" 22))
    (is (not (cl-pnet-ssh:ssh-session-permits-direct-tcpip-p session "host" 23)))
    (is (not (cl-pnet-ssh:ssh-session-permits-direct-tcpip-p session "other" 22)))
    (is (cl-pnet-ssh:ssh-session-permits-tcpip-forward-p session "0.0.0.0" 9000))
    ;; permitlisten= restricts the remote direction only.
    (setf (cl-pnet-ssh:ssh-session-authorization session)
          (funcall options "permitlisten=\"127.0.0.1:8080\""))
    (is (cl-pnet-ssh:ssh-session-permits-tcpip-forward-p session "127.0.0.1" 8080))
    (is (not (cl-pnet-ssh:ssh-session-permits-tcpip-forward-p session "127.0.0.1" 8081)))
    (is (cl-pnet-ssh:ssh-session-permits-direct-tcpip-p session "host" 22))))

(test ssh-config-carries-the-features-the-caller-must-refuse
  ;; Agent, X11 and compression wishes can come from the file.  The parser
  ;; records them so a client can refuse a feature it lacks instead of
  ;; silently dropping the option.
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line "ForwardAgent yes")
                  (cl-pnet-ssh::ssh-config-option-line "ForwardX11 yes")
                  (cl-pnet-ssh::ssh-config-option-line "ForwardX11Trusted no")
                  (cl-pnet-ssh::ssh-config-option-line "Compression yes"))))
         (options nil))
    (ssh-config-resolve config "alias"
                        :on-options (lambda (value) (setf options value)))
    (is (eq t (cl-pnet-ssh:ssh-config-options-forward-agent options)))
    (is (eq t (cl-pnet-ssh:ssh-config-options-forward-x11 options)))
    (is (null (cl-pnet-ssh:ssh-config-options-forward-x11-trusted options)))
    (is (eq t (cl-pnet-ssh:ssh-config-options-compression options)))))

(test -F-none-disables-the-config-files-but-not-o
  (let ((source (cl-pnet-ssh::ssh-config-client-source "none")))
    (is (null (cl-pnet-ssh::ssh-config-directives source))))
  (let ((options nil))
    (ssh-config-resolve
     (cl-pnet-ssh::ssh-config-client-source "none" '("Port=2200"))
     "alias"
     :on-options (lambda (value) (setf options value)))
    (is (= 2200 (cl-pnet-ssh:ssh-config-options-port options)))))

(test public-key-signature-valid-p-covers-ed25519-rsa-and-ecdsa
  ;; User authentication uses the same verifier as host-key checking, so an
  ;; authorized key of any supported type must verify under the signature
  ;; algorithm its request names.
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (dolist (spec '(("ed25519" nil "ssh-ed25519" "rsa-sha2-256")
                      ("rsa" "2048" "ssh-rsa" "ssh-ed25519")
                      ("ecdsa" "256" "ecdsa-sha2-nistp256"
                       "ecdsa-sha2-nistp384")))
        (destructuring-bind (kind bits type wrong-algorithm) spec
          (let* ((directory (ssh-test-directory "cl-pnet-ssh-userkey"))
                 (path (merge-pathnames (format nil "id_~A" kind) directory)))
            (ensure-directories-exist path)
            (unwind-protect
                 (progn
                   (ssh-keygen
                    (append (list "-q" "-t" kind)
                            (when bits (list "-b" bits))
                            (list "-N" "" "-f" (namestring path))))
                   (let* ((key (ssh-load-private-key path))
                          (blob (ssh-public-key-blob-of key))
                          (message (octets-ascii "userauth data"))
                          (signature
                            (cl-pnet-ssh::ssh-private-key-signature-blob
                             key message))
                          (algorithm
                            (nth-value 0 (ssh-parse-signature-blob signature))))
                     (is (string= type (nth-value 0 (ssh-public-key-parts blob))))
                     (is (cl-pnet-ssh::ssh-public-key-signature-valid-p
                          blob signature message))
                     (is (not (cl-pnet-ssh::ssh-public-key-signature-valid-p
                               blob signature (octets-ascii "other data"))))
                     (is (cl-pnet-ssh::ssh-server-user-key-algorithm-p
                          blob algorithm))
                     (is (not (cl-pnet-ssh::ssh-server-user-key-algorithm-p
                               blob wrong-algorithm)))
                     (when (string= type "ssh-rsa")
                       ;; One RSA key signs under any RFC 8332 name.
                       (is (cl-pnet-ssh::ssh-server-user-key-algorithm-p
                            blob "rsa-sha2-512")))))
              (ignore-errors (uiop:delete-directory-tree directory :validate t))))))))

(test kex-markers-are-never-selected
  ;; ext-info-* and kex-strict-* are negotiation signals.  A peer that lists
  ;; one as a key exchange method must not make the server choose it.
  (is (cl-pnet-ssh::ssh-kex-marker-p "ext-info-c"))
  (is (cl-pnet-ssh::ssh-kex-marker-p "ext-info-s"))
  (is (cl-pnet-ssh::ssh-kex-marker-p "kex-strict-s-v00@openssh.com"))
  (is (not (cl-pnet-ssh::ssh-kex-marker-p "curve25519-sha256")))
  (is (string= "curve25519-sha256"
               (cl-pnet-ssh::ssh-choose-algorithm
                (remove-if #'cl-pnet-ssh::ssh-kex-marker-p
                           (list "kex-strict-s-v00@openssh.com"
                                 "ext-info-s" "curve25519-sha256"))
                (list "ext-info-s" "kex-strict-s-v00@openssh.com"
                      "curve25519-sha256")))))

(test server-advertises-the-user-key-signatures-it-accepts
  ;; EXT_INFO's server-sig-algs is what makes an OpenSSH client willing to
  ;; try an RSA key; the modern names must be there.
  (dolist (algorithm '("ssh-ed25519" "ecdsa-sha2-nistp256"
                       "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521"
                       "rsa-sha2-512" "rsa-sha2-256"))
    (is (member algorithm cl-pnet-ssh::+ssh-server-user-key-algorithms+
                :test #'string=)))
  (is (not (member "ssh-rsa" cl-pnet-ssh::+ssh-server-user-key-algorithms+
                   :test #'string=))))

#-ssh-backend-ffi
(test server-sends-newkeys-and-ext-info-in-one-write
  ;; libssh decides how to sign an RSA key from server-sig-algs before its
  ;; next read of the socket.  An EXT_INFO left in a second segment makes it
  ;; fall back to SHA-1 ssh-rsa and refuse the key without ever asking, so
  ;; the two packets must leave in one write, as OpenSSH's server sends them.
  (let* ((original (symbol-function 'cl-pnet:send-data))
         (writes '())
         (capture
           (lambda (negotiated)
             (setf writes nil)
             (let* ((server (cl-pnet-ssh::%make-ssh-server :host-keys nil))
                    (session (cl-pnet-ssh::%make-ssh-session
                              :server server)))
               (setf (cl-pnet-ssh::ssh-session-connection session) :captured
                     (cl-pnet-ssh::ssh-session-negotiated session)
                     negotiated)
               (cl-pnet-ssh::ssh-server-send-newkeys session)
               (values (length writes) (first writes))))))
    (unwind-protect
         (progn
           (setf (symbol-function 'cl-pnet:send-data)
                 (lambda (connection data &key on-error on-write)
                   (declare (ignore connection on-error on-write))
                   (push (copy-seq data) writes)
                   (length data)))
           (multiple-value-bind (write-count wire)
               (funcall capture '(:ext-info t))
             ;; One write, holding NEWKEYS then EXT_INFO.
             (is (= 1 write-count))
             (let ((state (cl-pnet-ssh::ssh-make-cipher-state)))
               (multiple-value-bind (payload consumed)
                   (ssh-decode-packet wire state)
                 (is (= cl-pnet-ssh::+ssh-msg-newkeys+ (aref payload 0)))
                 (let ((ext (ssh-decode-packet (subseq wire consumed) state)))
                   (is (= cl-pnet-ssh::+ssh-msg-ext-info+ (aref ext 0)))
                   (let ((reader (ssh-make-reader ext)))
                     (ssh-read-u8 reader)
                     (is (= 1 (ssh-read-u32 reader)))
                     (is (string= "server-sig-algs" (ssh-read-text reader)))
                     (is (member "rsa-sha2-512"
                                 (ssh-read-name-list reader)
                                 :test #'string=)))))))
           ;; Without a client that asked for extensions, only NEWKEYS.
           (multiple-value-bind (plain-count plain-wire)
               (funcall capture '(:ext-info nil))
             (is (= 1 plain-count))
             (let ((decoded (ssh-decode-packet
                             plain-wire
                             (cl-pnet-ssh::ssh-make-cipher-state))))
               (is (= cl-pnet-ssh::+ssh-msg-newkeys+ (aref decoded 0))))))
      (setf (symbol-function 'cl-pnet:send-data) original))))

(test local-network-cidr-matching-uses-the-network-bits
  ;; ssh_config's LocalNetwork (and sshd's AllowUsers host patterns) treat
  ;; the prefix as the high-order bits, so a /8 must compare the first octet.
  (is (cl-pnet-ssh::ssh-config-ipv4-cidr-match-p "10.0.0.0/8" "10.4.5.6"))
  (is (not (cl-pnet-ssh::ssh-config-ipv4-cidr-match-p "10.0.0.0/8"
                                                      "11.4.5.6")))
  (is (cl-pnet-ssh::ssh-config-ipv4-cidr-match-p "192.168.0.0/16"
                                                 "192.168.1.1"))
  (is (not (cl-pnet-ssh::ssh-config-ipv4-cidr-match-p "192.168.0.0/16"
                                                      "192.169.1.1")))
  ;; /0 matches everything and /32 matches one address.
  (is (cl-pnet-ssh::ssh-config-ipv4-cidr-match-p "0.0.0.0/0" "203.0.113.9"))
  (is (cl-pnet-ssh::ssh-config-ipv4-cidr-match-p "10.4.5.6/32"
                                                 "10.4.5.6"))
  (is (not (cl-pnet-ssh::ssh-config-ipv4-cidr-match-p "10.4.5.6/32"
                                                      "10.4.5.7"))))

(test ipv6-cidr-matching-for-host-patterns
  ;; sshd's AllowUsers host part accepts IPv6 CIDRs too, and a deny list that
  ;; silently matched nothing would fail open.
  (is (cl-pnet-ssh::ssh-config-ipv6-cidr-match-p "2001:db8::/32"
                                                 "2001:db8:1:2::5"))
  (is (not (cl-pnet-ssh::ssh-config-ipv6-cidr-match-p "2001:db8::/32"
                                                      "2001:db9::1")))
  (is (cl-pnet-ssh::ssh-config-ipv6-cidr-match-p "::1/128" "::1"))
  (is (not (cl-pnet-ssh::ssh-config-ipv6-cidr-match-p "::1/128" "::2")))
  (is (cl-pnet-ssh::ssh-config-ipv6-cidr-match-p "fe80::/10" "fe80::1"))
  (is (cl-pnet-ssh::ssh-config-ipv6-cidr-match-p "fe80::/10" "febf::1"))
  (is (not (cl-pnet-ssh::ssh-config-ipv6-cidr-match-p "fe80::/10" "fec0::1")))
  (is (cl-pnet-ssh::ssh-config-ipv6-cidr-match-p "::ffff:192.168.1.0/120"
                                                 "::ffff:192.168.1.9"))
  (is (not (cl-pnet-ssh::ssh-config-ipv6-cidr-match-p "::ffff:192.168.1.0/120"
                                                      "::ffff:192.168.2.9")))
  ;; Words are hex, so a decimal-looking but invalid group is refused rather
  ;; than read as part of something else.
  (is (null (cl-pnet-ssh::ssh-config-ipv6-words "12345::1")))
  (is (null (cl-pnet-ssh::ssh-config-ipv6-words "1:2:3:4:5:6:7")))
  (is (null (cl-pnet-ssh::ssh-config-ipv6-words "1::2::3")))
  (is (= 8 (length (cl-pnet-ssh::ssh-config-ipv6-words "::")))))

(test authentication-methods-are-filtered-to-what-this-server-can-complete
  ;; Password and the other methods are valid names, but this server cannot
  ;; complete them, so a list that needs one is skipped as sshd skips a list
  ;; naming a disabled method.
  (let ((two (ssh-server-config-load
              nil :options '("AuthenticationMethods publickey,publickey")))
        (mixed (ssh-server-config-load
                nil :options '("AuthenticationMethods publickey,password")))
        (any (ssh-server-config-load
              nil :options '("AuthenticationMethods any"))))
    (is (equal '(("publickey" "publickey"))
               (cl-pnet-ssh::ssh-server-auth-method-lists two)))
    (is (eq :impossible
            (cl-pnet-ssh::ssh-server-auth-method-lists mixed)))
    (is (null (cl-pnet-ssh::ssh-server-auth-method-lists any)))
    (is (null (cl-pnet-ssh::ssh-server-auth-method-lists nil)))))

(test pubkey-ok-budget-delays-max-auth-tries
  "The first max-pk-ok rejected probes are not charged to MaxAuthTries."
  (let* ((config (ssh-server-config-load
                  nil :options '("PubkeyAuthOptions max-pk-ok:2")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server)))
    (is (not (cl-pnet-ssh::ssh-server-publickey-offer-counts-p session)))
    (is (not (cl-pnet-ssh::ssh-server-publickey-offer-counts-p session)))
    (is (cl-pnet-ssh::ssh-server-publickey-offer-counts-p session))
    (is (cl-pnet-ssh::ssh-server-publickey-offer-counts-p session)))
  ;; sshd's default budget is six probes.
  (let* ((server (cl-pnet-ssh::%make-ssh-server))
         (session (cl-pnet-ssh::%make-ssh-session :server server)))
    (dotimes (index 6)
      (declare (ignore index))
      (is (not (cl-pnet-ssh::ssh-server-publickey-offer-counts-p session))))
    (is (cl-pnet-ssh::ssh-server-publickey-offer-counts-p session))))

(test server-loopback-refuse-connection
  "RefuseConnection in a Match block terminates the connection before auth."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-refuse"))
             (host-key (merge-pathnames "host_key" directory))
             (client-key (merge-pathnames "client_key" directory))
             (authorized (merge-pathnames "authorized_keys" directory))
             (known-hosts (merge-pathnames "known_hosts" directory))
             (config-path (merge-pathnames "sshd_config" directory))
             (stdout (make-string-output-stream))
             (stderr (make-string-output-stream))
             (server nil))
        (ensure-directories-exist host-key)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring host-key)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring client-key)))
               (ssh-test-write-authorized-keys
                (merge-pathnames "client_key.pub" directory) authorized)
               (with-open-file (out config-path :direction :output
                                               :if-exists :supersede
                                               :if-does-not-exist :create)
                 (write-string "Match User tester
  RefuseConnection yes" out))
               (setf server
                     (make-ssh-server
                      "127.0.0.1" 0
                      :host-key host-key
                      :authorized-keys authorized
                      :sshd-config (ssh-server-config-load config-path)
                      :on-channel
                      (lambda (channel)
                        (setf (cl-pnet-ssh::ssh-server-channel-on-exec channel)
                              (lambda (channel command)
                                (ssh-test-run-command channel command))))))
               (let ((failed
                       (handler-case
                           (progn (ssh-test-loopback-run
                                   server client-key known-hosts
                                   stdout stderr)
                                  nil)
                         (error () t))))
                 (is (not (null failed)))))
          (when server (ssh-server-close server))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(defun penalty-allowed-p (server address)
  (multiple-value-bind (allowed)
      (cl-pnet-ssh::ssh-server-penalty-check server address)
    (and allowed t)))

(defun penalty-refused-p (server address)
  (not (penalty-allowed-p server address)))

(test per-source-penalties-refuse-penalised-networks
  "Penalties activate above min, accumulate up to max, expire, and honour
the exempt list and PerSourceNetBlockSize."
  ;; Off unless configured.
  (let ((server (cl-pnet-ssh::%make-ssh-server)))
    (cl-pnet-ssh::ssh-server-penalise server "127.0.0.1" :authfail)
    (is (not (null (penalty-allowed-p server "127.0.0.1")))))
  ;; A single penalty above min refuses the network.
  (let* ((config (ssh-server-config-load
                  nil :options '("PerSourcePenalties authfail:10 min:5 max:30")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config)))
    (multiple-value-bind (allowed reason)
        (cl-pnet-ssh::ssh-server-penalty-check server "127.0.0.1")
      (is (not (null allowed)))
      (is (null reason)))
    (cl-pnet-ssh::ssh-server-penalise server "127.0.0.1" :authfail)
    (multiple-value-bind (allowed reason)
        (cl-pnet-ssh::ssh-server-penalty-check server "127.0.0.1")
      (is (not allowed))
      (is (stringp reason))))
  ;; Below min the entry is deferred; a second penalty activates it.
  (let* ((config (ssh-server-config-load
                  nil :options '("PerSourcePenalties authfail:3 min:5 max:30")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config)))
    (cl-pnet-ssh::ssh-server-penalise server "127.0.0.1" :authfail)
    (is (not (null (penalty-allowed-p server "127.0.0.1"))))
    (cl-pnet-ssh::ssh-server-penalise server "127.0.0.1" :authfail)
    (is (not (null (penalty-refused-p server "127.0.0.1")))))
  ;; The exempt list wins.
  (let* ((config (ssh-server-config-load
                  nil :options
                  '("PerSourcePenalties authfail:10 min:5"
                    "PerSourcePenaltyExemptList 127.0.0.1/32")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config)))
    (cl-pnet-ssh::ssh-server-penalise server "127.0.0.1" :authfail)
    (is (not (null (penalty-allowed-p server "127.0.0.1")))))
  ;; PerSourceNetBlockSize groups the penalty.
  (let* ((config (ssh-server-config-load
                  nil :options '("PerSourcePenalties authfail:10 min:5")))
         (server (cl-pnet-ssh::%make-ssh-server
                  :sshd-config config
                  :per-source-net-block-size-ipv4 24
                  :per-source-net-block-size-ipv6 128)))
    (cl-pnet-ssh::ssh-server-penalise server "192.0.2.1" :authfail)
    (is (not (null (penalty-refused-p server "192.0.2.200")))))
  ;; An expired entry is gone.
  (let* ((config (ssh-server-config-load
                  nil :options '("PerSourcePenalties authfail:1 min:0 max:30")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config)))
    (cl-pnet-ssh::ssh-server-penalise server "127.0.0.1" :authfail)
    (is (not (null (penalty-refused-p server "127.0.0.1"))))
    (maphash (lambda (key value)
               (declare (ignore key))
               (setf (first value) 0))
             (cl-pnet-ssh::ssh-server-per-source-penalties server))
    (is (not (null (penalty-allowed-p server "127.0.0.1"))))))

(test per-source-penalties-are-applied-on-session-close
  "A failed or unauthenticated close charges the source; a refusal uses the
RefuseConnection penalty."
  (let* ((config (ssh-server-config-load
                  nil :options '("PerSourcePenalties authfail:10 min:5")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server
                   :remote-address '(:address "192.0.2.1" :port 1234))))
    (setf (cl-pnet-ssh::ssh-session-auth-failures session) 1
          (cl-pnet-ssh::ssh-session-close-reason session) :peer-closed)
    (cl-pnet-ssh::ssh-server-session-penalty session)
    (is (not (null (penalty-refused-p server "192.0.2.1"))) "authfail"))
  (let* ((config (ssh-server-config-load
                  nil :options '("PerSourcePenalties noauth:10 min:5")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server
                   :remote-address '(:address "192.0.2.1" :port 1234))))
    (setf (cl-pnet-ssh::ssh-session-close-reason session) :peer-closed)
    (cl-pnet-ssh::ssh-server-session-penalty session)
    (is (not (null (penalty-refused-p server "192.0.2.1"))) "noauth"))
  (let* ((config (ssh-server-config-load
                  nil :options '("PerSourcePenalties refuseconnection:10 min:5")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server
                   :remote-address '(:address "192.0.2.1" :port 1234))))
    (setf (cl-pnet-ssh::ssh-session-refused-p session) t
          (cl-pnet-ssh::ssh-session-close-reason session) :refused)
    (cl-pnet-ssh::ssh-server-session-penalty session)
    (is (not (null (penalty-refused-p server "192.0.2.1"))) "refused")))

(test direct-streamlocal-forwarding-policy
  "AllowStreamLocalForwarding admits local forwards only for yes/all/local,
and DisableForwarding or no-port-forwarding vetoes them."
  (dolist (case '(("yes" . t) ("all" . t) ("local" . t)
                  ("remote" . nil) ("no" . nil)))
    (let* ((config (ssh-server-config-load
                    nil :options
                    (list (format nil "AllowStreamLocalForwarding ~A"
                                  (car case)))))
           (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
           (session (cl-pnet-ssh::%make-ssh-session :server server)))
      (is (eq (cdr case)
              (not (null (cl-pnet-ssh:ssh-session-permits-direct-streamlocal-p
                          session "/tmp/sock")))))))
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes"
                                 "DisableForwarding yes")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server)))
    (is (null (cl-pnet-ssh:ssh-session-permits-direct-streamlocal-p
               session "/tmp/sock"))))
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server
                   :authorization
                   (nth-value
                    0 (ssh-authorized-key-options-parse
                       "no-port-forwarding")))))
    (is (null (cl-pnet-ssh:ssh-session-permits-direct-streamlocal-p
               session "/tmp/sock")))))

(test server-accepts-a-direct-streamlocal-open
  "A permitted direct-streamlocal open records the socket path."
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes")))
         (server (cl-pnet-ssh::%make-ssh-server
                  :sshd-config config
                  :on-direct-streamlocal
                  (lambda (session path)
                    (declare (ignore session))
                    (string= path "/tmp/sock"))))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-channel-open+)
    (cl-pnet-ssh:ssh-write-text writer "direct-streamlocal@openssh.com")
    (cl-pnet-ssh:ssh-write-u32 writer 7)
    (cl-pnet-ssh:ssh-write-u32 writer 2097152)
    (cl-pnet-ssh:ssh-write-u32 writer 32768)
    (cl-pnet-ssh:ssh-write-text writer "/tmp/sock")
    (cl-pnet-ssh:ssh-write-text writer "")
    (cl-pnet-ssh:ssh-write-u32 writer 0)
    (cl-pnet-ssh::ssh-server-handle-channel-message
     session (cl-pnet-ssh:ssh-writer-output writer))
    (let ((channel (gethash 0 (cl-pnet-ssh::ssh-session-channels session))))
      (is (not (null channel)))
      (is (equal "direct-streamlocal@openssh.com"
                 (cl-pnet-ssh:ssh-server-channel-type channel)))
      (is (equal "/tmp/sock"
                 (cl-pnet-ssh:ssh-server-channel-streamlocal-path channel)))))
  ;; The application hook can refuse a path.
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes")))
         (server (cl-pnet-ssh::%make-ssh-server
                  :sshd-config config
                  :on-direct-streamlocal (lambda (session path)
                                           (declare (ignore session path))
                                           nil)))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-channel-open+)
    (cl-pnet-ssh:ssh-write-text writer "direct-streamlocal@openssh.com")
    (cl-pnet-ssh:ssh-write-u32 writer 7)
    (cl-pnet-ssh:ssh-write-u32 writer 2097152)
    (cl-pnet-ssh:ssh-write-u32 writer 32768)
    (cl-pnet-ssh:ssh-write-text writer "/tmp/sock")
    (cl-pnet-ssh:ssh-write-text writer "")
    (cl-pnet-ssh:ssh-write-u32 writer 0)
    (cl-pnet-ssh::ssh-server-handle-channel-message
     session (cl-pnet-ssh:ssh-writer-output writer))
    (is (null (gethash 0 (cl-pnet-ssh::ssh-session-channels session))))))

(test streamlocal-remote-forwarding-policy
  "Remote stream-local forwarding needs yes/all or remote, and forwarding
must not be disabled by the key or the connection."
  (dolist (case '(("yes" . t) ("all" . t) ("remote" . t)
                  ("local" . nil) ("no" . nil)))
    (let* ((config (ssh-server-config-load
                    nil :options
                    (list (format nil "AllowStreamLocalForwarding ~A"
                                  (car case)))))
           (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
           (session (cl-pnet-ssh::%make-ssh-session :server server)))
      (is (eq (cdr case)
              (not (null (cl-pnet-ssh:ssh-session-permits-streamlocal-forward-p
                          session "/tmp/sock")))))))
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes"
                                 "DisableForwarding yes")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server)))
    (is (null (cl-pnet-ssh:ssh-session-permits-streamlocal-forward-p
               session "/tmp/sock"))))
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server
                   :authorization
                   (nth-value
                    0 (ssh-authorized-key-options-parse
                       "no-port-forwarding")))))
    (is (null (cl-pnet-ssh:ssh-session-permits-streamlocal-forward-p
               session "/tmp/sock")))))

(test server-handles-streamlocal-forward-requests
  "A streamlocal-forward request reaches the application hook; a cancel does
too, and a refused policy never calls it."
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes")))
         (seen '())
         (server (cl-pnet-ssh::%make-ssh-server
                  :sshd-config config
                  :on-streamlocal-forward
                  (lambda (session path)
                    (declare (ignore session))
                    (push (cons :forward path) seen)
                    t)
                  :on-cancel-streamlocal-forward
                  (lambda (session path)
                    (declare (ignore session))
                    (push (cons :cancel path) seen)
                    t)))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-global-request+)
    (cl-pnet-ssh:ssh-write-text writer "streamlocal-forward@openssh.com")
    (cl-pnet-ssh:ssh-write-boolean writer nil)
    (cl-pnet-ssh:ssh-write-text writer "/tmp/sock")
    (cl-pnet-ssh::ssh-server-handle-global-request
     session (cl-pnet-ssh:ssh-writer-output writer))
    (setf writer (cl-pnet-ssh:ssh-writer))
    (cl-pnet-ssh:ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-global-request+)
    (cl-pnet-ssh:ssh-write-text writer "cancel-streamlocal-forward@openssh.com")
    (cl-pnet-ssh:ssh-write-boolean writer nil)
    (cl-pnet-ssh:ssh-write-text writer "/tmp/sock")
    (cl-pnet-ssh::ssh-server-handle-global-request
     session (cl-pnet-ssh:ssh-writer-output writer))
    (is (equal '((:forward . "/tmp/sock") (:cancel . "/tmp/sock"))
               (nreverse seen))))
  ;; The library's policy gate keeps a hook from running when the directive
  ;; does not allow remote stream-local forwarding.
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding no")))
         (called nil)
         (server (cl-pnet-ssh::%make-ssh-server
                  :sshd-config config
                  :on-streamlocal-forward
                  (lambda (session path)
                    (declare (ignore session path))
                    (setf called t)
                    t)))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-global-request+)
    (cl-pnet-ssh:ssh-write-text writer "streamlocal-forward@openssh.com")
    (cl-pnet-ssh:ssh-write-boolean writer nil)
    (cl-pnet-ssh:ssh-write-text writer "/tmp/sock")
    (cl-pnet-ssh::ssh-server-handle-global-request
     session (cl-pnet-ssh:ssh-writer-output writer))
    (is (null called))))

(test server-opens-a-forwarded-streamlocal-channel
  "The forwarded-streamlocal channel carries the listen path and reserved field."
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (channel
           (cl-pnet-ssh:ssh-server-open-forwarded-streamlocal
            session "/tmp/sock")))
    (is (eq :opening (cl-pnet-ssh:ssh-server-channel-state channel)))
    (is (equal "forwarded-streamlocal@openssh.com"
               (cl-pnet-ssh:ssh-server-channel-type channel)))
    (is (equal "/tmp/sock"
               (cl-pnet-ssh:ssh-server-channel-streamlocal-path channel)))))

(test client-opens-a-direct-streamlocal-channel
  "The client's open carries the socket path and the two reserved fields."
  (let* ((client (cl-pnet-ssh::%make-ssh-client))
         (channel (ssh-open-direct-streamlocal client "/tmp/sock"))
         (reader (ssh-make-reader
                  (cl-pnet-ssh::ssh-channel-open-extra channel))))
    (is (equal "direct-streamlocal@openssh.com"
               (cl-pnet-ssh::ssh-channel-type channel)))
    (is (equal "/tmp/sock" (ssh-read-text reader)))
    (is (equal "" (ssh-read-text reader)))
    (is (= 0 (ssh-read-u32 reader)))
    ;; Nothing is sent before the transport is ready.
    (is (eq :connecting (cl-pnet-ssh:ssh-client-phase client)))))

(test client-refuses-a-revoked-host-key
  "RevokedHostKeys refuses a listed host key, and an unreadable list fails
closed rather than being ignored."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-client-revoked"))
             (key-path (merge-pathnames "host_key" directory))
             (revoked (merge-pathnames "revoked_keys" directory))
             (missing (merge-pathnames "missing_keys" directory)))
        (ensure-directories-exist key-path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring key-path)))
               (let* ((private (ssh-load-private-key key-path))
                      (blob (ssh-public-key-blob-of private)))
                 (with-open-file (out revoked :direction :output
                                               :if-exists :supersede
                                               :if-does-not-exist :create)
                   (with-open-file (in
                                    (merge-pathnames "host_key.pub" directory))
                     (write-line (read-line in) out)))
                 (flet ((client (&rest arguments)
                          (apply #'cl-pnet-ssh::%make-ssh-client
                                 :host "example.org"
                                 :known-hosts '()
                                 :host-key-policy :insecure
                                 arguments)))
                   (signals ssh-host-key-error
                     (cl-pnet-ssh::ssh-client-verify-host-key
                      (client :revoked-host-keys (list revoked)) blob))
                   (signals ssh-host-key-error
                     (cl-pnet-ssh::ssh-client-verify-host-key
                      (client :revoked-host-keys (list missing)) blob))
                   (is (null (cl-pnet-ssh::ssh-client-verify-host-key
                              (client :revoked-host-keys '()) blob))))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test client-host-certificate-obeys-ca-signature-algorithms
  "A host certificate is trusted only when its CA signature algorithm is
allowed by CASignatureAlgorithms."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-client-caalg"))
             (ca (merge-pathnames "ca" directory))
             (host-key (merge-pathnames "host_key" directory))
             (known-hosts (merge-pathnames "known_hosts" directory)))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ca)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring host-key)))
               (ssh-keygen
                (list "-q" "-s" (namestring ca) "-I" "host-id" "-h"
                      "-n" "example.org" "-V" "-1m:+52w"
                      (namestring (merge-pathnames "host_key.pub" directory))))
               (with-open-file (out known-hosts :direction :output
                                               :if-exists :supersede
                                               :if-does-not-exist :create)
                 (with-open-file (in (merge-pathnames "ca.pub" directory))
                   (format out "@cert-authority example.org ~A~%"
                           (string-trim '(#\Space #\Return #\Newline)
                                        (read-line in)))))
               (let* ((certificate
                        (ssh-certificate-parse
                         (cl-pnet-ssh::ssh-public-key-file-blob
                          (merge-pathnames "host_key-cert.pub" directory))))
                      (client
                        (cl-pnet-ssh::%make-ssh-client
                         :host "example.org"
                         :host-key-host "example.org"
                         :known-hosts (list known-hosts)
                         :host-key-policy :strict)))
                 (is (cl-pnet-ssh::ssh-client-host-certificate-trusted-p
                      client certificate))
                 ;; The certificate's CA signed it with ed25519.
                 (setf (cl-pnet-ssh::ssh-client-ca-signature-algorithms client)
                       '("rsa-sha2-512"))
                 (is (not (cl-pnet-ssh::ssh-client-host-certificate-trusted-p
                           client certificate)))
                 (setf (cl-pnet-ssh::ssh-client-ca-signature-algorithms client)
                       '("ssh-ed25519"))
                 (is (cl-pnet-ssh::ssh-client-host-certificate-trusted-p
                      client certificate))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test client-keys-obey-required-rsa-size
  "RequiredRSASize rejects small RSA host keys and authentication keys."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let ((directory (ssh-test-directory "cl-pnet-ssh-client-rsasize")))
        (unwind-protect
             (let* ((short (merge-pathnames "rsa-1024" directory))
                    (long (merge-pathnames "rsa-2048" directory))
                    (ed25519 (merge-pathnames "ed25519" directory)))
               (ensure-directories-exist short)
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "1024" "-N" ""
                                 "-f" (namestring short)))
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "2048" "-N" ""
                                 "-f" (namestring long)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ed25519)))
               (let* ((short-key (ssh-load-private-key short))
                      (long-key (ssh-load-private-key long))
                      (ed-key (ssh-load-private-key ed25519))
                      (signers
                        (list (ssh-private-key-signer short-key)
                              (ssh-private-key-signer long-key)
                              (ssh-private-key-signer ed-key))))
                 ;; A 2048-bit floor leaves the large RSA key and ed25519.
                 (let ((kept (cl-pnet-ssh::ssh-filter-signers
                              signers nil :minimum-rsa-size 2048)))
                   (is (= 2 (length kept)))
                   (is (member (second signers) kept :test #'eq))
                   (is (member (third signers) kept :test #'eq)))
                 ;; The default floor, 1024, keeps every key here.
                 (is (= 3
                        (length (cl-pnet-ssh::ssh-filter-signers
                                 signers nil :minimum-rsa-size 1024))))
                 ;; A small RSA host key is refused before any policy runs.
                 (let ((client (cl-pnet-ssh::%make-ssh-client
                                :host "example.org"
                                :known-hosts '()
                                :host-key-policy :insecure
                                :required-rsa-size 2048)))
                   (signals ssh-host-key-error
                     (cl-pnet-ssh::ssh-client-verify-host-key
                      client (ssh-public-key-blob-of short-key)))
                   (is (null (cl-pnet-ssh::ssh-client-verify-host-key
                              client (ssh-public-key-blob-of long-key))))
                   (is (null (cl-pnet-ssh::ssh-client-verify-host-key
                              client (ssh-public-key-blob-of ed-key)))))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test client-accepts-a-forwarded-streamlocal-channel
  "A requested path is accepted and handed to the application's setup hook;
an unrequested one is refused with a CHANNEL_OPEN_FAILURE."
  (flet ((open-message (path)
           (let ((writer (ssh-writer)))
             (ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-channel-open+)
             (ssh-write-text writer "forwarded-streamlocal@openssh.com")
             (ssh-write-u32 writer 7)
             (ssh-write-u32 writer 2097152)
             (ssh-write-u32 writer 32768)
             (ssh-write-text writer path)
             (ssh-write-text writer "")
             (ssh-write-u32 writer 0)
             (ssh-writer-output writer))))
    (let* ((client (cl-pnet-ssh::%make-ssh-client))
           (seen '())
           (setup-channel nil)
           (sent '()))
      (setf (cl-pnet-ssh::ssh-client-on-forwarded-streamlocal client)
            (lambda (client path)
              (declare (ignore client))
              (push path seen)
              (lambda (channel) (setf setup-channel channel))))
      (let ((original (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)))
        (unwind-protect
             (progn
               (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                     (lambda (client payload)
                       (declare (ignore client))
                       (push payload sent)
                       t))
               (cl-pnet-ssh::ssh-client-handle-channel-message
                client (open-message "/tmp/sock")))
          (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                original)))
      (is (equal '("/tmp/sock") seen))
      (is (not (null setup-channel)))
      (is (equal "forwarded-streamlocal@openssh.com"
                 (cl-pnet-ssh::ssh-channel-type setup-channel)))
      (is (eq :open (cl-pnet-ssh::ssh-channel-state setup-channel)))
      ;; The confirmation names the server's sender id.
      (let ((reader (ssh-make-reader (first sent))))
        (is (= cl-pnet-ssh::+ssh-msg-channel-open-confirmation+
               (ssh-read-u8 reader)))
        (is (= 7 (ssh-read-u32 reader)))))
    ;; With no handler the path is refused and no channel is created.
    (let* ((client (cl-pnet-ssh::%make-ssh-client))
           (sent '()))
      (let ((original (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)))
        (unwind-protect
             (progn
               (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                     (lambda (client payload)
                       (declare (ignore client))
                       (push payload sent)
                       t))
               (cl-pnet-ssh::ssh-client-handle-channel-message
                client (open-message "/tmp/other.sock")))
          (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                original)))
      (is (null (cl-pnet-ssh::ssh-client-channel-for client 0)))
      (let ((reader (ssh-make-reader (first sent))))
        (is (= cl-pnet-ssh::+ssh-msg-channel-open-failure+ (ssh-read-u8 reader)))
        (is (= 7 (ssh-read-u32 reader)))))))

(test server-accepts-a-hostbased-request
  "A hostbased request is verified with the client host key and handed to
the application's trust hook."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-hostbased"))
             (key-path (merge-pathnames "host_key" directory)))
        (ensure-directories-exist key-path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring key-path)))
               (let* ((private (ssh-load-private-key key-path))
                      (blob (ssh-public-key-blob-of private))
                      (session-id
                        (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 9))
                      (run
                        (lambda (config allowed)
                          (let* ((server
                                   (cl-pnet-ssh::%make-ssh-server
                                    :sshd-config config
                                    :hostbased-key-allowed
                                    (lambda (session user cuser chost key)
                                      (declare (ignore session user cuser
                                                       chost key))
                                      allowed)))
                                 (session
                                   (cl-pnet-ssh::%make-ssh-session
                                    :server server
                                    :session-id session-id))
                                 (signed
                                   (cl-pnet-ssh::ssh-server-hostbased-signed-data
                                    session "turtle" "ssh-ed25519" blob
                                    "client.example" "turtle"))
                                 (signature
                                   (cl-pnet-ssh::ssh-ed25519-signature-blob
                                    private signed))
                                 (writer (cl-pnet-ssh:ssh-writer)))
                            (cl-pnet-ssh:ssh-write-u8
                             writer cl-pnet-ssh::+ssh-msg-userauth-request+)
                            (cl-pnet-ssh:ssh-write-text writer "turtle")
                            (cl-pnet-ssh:ssh-write-text writer "ssh-connection")
                            (cl-pnet-ssh:ssh-write-text writer "hostbased")
                            (cl-pnet-ssh:ssh-write-text writer "ssh-ed25519")
                            (cl-pnet-ssh:ssh-write-string writer blob)
                            (cl-pnet-ssh:ssh-write-text writer "client.example")
                            (cl-pnet-ssh:ssh-write-text writer "turtle")
                            (cl-pnet-ssh:ssh-write-string writer signature)
                            (cl-pnet-ssh::ssh-server-handle-userauth-request
                             session (cl-pnet-ssh:ssh-writer-output writer))
                            (cl-pnet-ssh::ssh-session-authenticated
                             session)))))
                 (is (funcall
                      run
                      (ssh-server-config-load
                       nil :options '("HostbasedAuthentication yes"))
                      t))
                 (is (not (funcall
                           run
                           (ssh-server-config-load
                            nil :options '("HostbasedAuthentication yes"))
                           nil)))
                 (is (not (funcall
                           run
                           (ssh-server-config-load
                            nil :options '("HostbasedAuthentication no"))
                           t)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-host-key-list-falls-back-to-the-agent
  "A HostKey whose private half is absent becomes an agent-backed key when
HostKeyAgent is configured."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-agent-hostkey"))
             (key-path (merge-pathnames "host_key" directory)))
        (ensure-directories-exist key-path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring key-path)))
               (let* ((private (ssh-load-private-key key-path))
                      (blob (ssh-public-key-blob-of private))
                      (public-path (concatenate 'string
                                                (namestring key-path) ".pub")))
                 (ignore-errors (delete-file key-path))
                 (let ((keys (cl-pnet-ssh::ssh-server-host-key-list
                              (list key-path) "/tmp/agent.sock")))
                   (is (= 1 (length keys)))
                   (is (cl-pnet-ssh::ssh-agent-host-key-p (first keys)))
                   (is (equalp blob
                               (ssh-public-key-blob-of (first keys))))
                   (is (equalp blob
                               (cl-pnet-ssh::ssh-public-key-file-blob
                                public-path))))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-kex-signs-with-an-agent-host-key
  "An agent-backed host key sends the exchange hash to the agent and finishes
the KEX from its signature."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-agent-kex"))
             (key-path (merge-pathnames "host_key" directory))
             (agent-path (namestring (merge-pathnames "agent.sock" directory))))
        (ensure-directories-exist key-path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring key-path)))
               (let* ((private (ssh-load-private-key key-path))
                      (blob (ssh-public-key-blob-of private))
                      (agent
                        (fake-agent-open
                         agent-path
                         (lambda (payload)
                           (let ((reader (ssh-make-reader payload)))
                             (is (= (ssh-read-u8 reader)
                                    cl-pnet-ssh::+ssh-agentc-sign-request+))
                             (is (equalp blob (ssh-read-string reader)))
                             (let* ((data (ssh-read-string reader))
                                    (signature
                                      (cl-pnet-ssh::ssh-ed25519-signature-blob
                                       private data))
                                    (writer (ssh-writer)))
                               (ssh-write-u8
                                writer cl-pnet-ssh::+ssh-agent-sign-response+)
                               (ssh-write-string writer signature)
                               (ssh-writer-output writer))))))
                      (server
                        (cl-pnet-ssh::%make-ssh-server
                         :host-keys
                         (list (cl-pnet-ssh::%make-ssh-agent-host-key
                                :blob blob :type "ssh-ed25519"
                                :path key-path))
                         :host-key-agent agent-path))
                      (session
                        (cl-pnet-ssh::%make-ssh-session
                         :server server
                         :client-version "SSH-2.0-test-client"
                         :server-version "SSH-2.0-test-server"
                         :client-kexinit (make-array 1 :element-type
                                                     '(unsigned-byte 8)
                                                     :initial-element 0)
                         :server-kexinit (make-array 1 :element-type
                                                     '(unsigned-byte 8)
                                                     :initial-element 0)
                         :negotiated
                         (list :kex "curve25519-sha256"
                               :host-key "ssh-ed25519"
                               :cipher-c2s "chacha20-poly1305@openssh.com"
                               :cipher-s2c "chacha20-poly1305@openssh.com"
                               :mac-c2s "hmac-sha2-256"
                               :mac-s2c "hmac-sha2-256"
                               :ext-info nil :strict nil)))
                      (writer (ssh-writer)))
                 (multiple-value-bind (client-private client-public)
                     (ssh-curve25519-keypair)
                   (declare (ignore client-private))
                   (ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-kex-ecdh-init+)
                   (ssh-write-string writer client-public))
                 (cl-pnet-ssh::ssh-server-handle-kex-init
                  session (ssh-writer-output writer))
                 (is (cl-pnet-ssh::ssh-session-kex-signature-pending session))
                 (loop repeat 10000
                       until (cl-pnet-ssh::ssh-session-derived-keys session)
                       do (cl-pnet:event-loop-run-once))
                 (is (not (null (cl-pnet-ssh::ssh-session-derived-keys
                                 session))))
                 (is (not (cl-pnet-ssh::ssh-session-kex-signature-pending
                           session)))
                 (fake-agent-close agent)))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))
