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
                            (lambda (offers)
                              (declare (ignore offers))
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
          (ignore-errors (delete-directory-tree directory :validate t))))))

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
      (ignore-errors (delete-directory-tree directory :validate t)))))

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
      (ignore-errors (delete-directory-tree directory :validate t)))))

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
      (ignore-errors (delete-directory-tree directory :validate t)))))

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
      (ignore-errors (delete-directory-tree directory :validate t)))))

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
      (ignore-errors (delete-directory-tree directory :validate t)))))

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
      (ignore-errors (delete-directory-tree directory :validate t)))))

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

(defun ssh-test-loopback-run (server client-key known-hosts stdout stderr)
  "Start a client against SERVER and return the command's exit status."
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
            :host-key-policy :accept-new
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
      (ignore-errors (delete-directory-tree directory :validate t)))))

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

(test server-loopback-exec-ecdsa-host-key
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (stdout stderr status)
          (ssh-test-loopback-result :host-key-arguments '("-t" "ecdsa"))
        (is (equal "hello" stdout))
        (is (equal "oops" stderr))
        (is (eql 3 status)))))

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
          (ignore-errors (delete-directory-tree directory :validate t))))))

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
          (ignore-errors (delete-directory-tree directory :validate t))))))

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
      (ignore-errors (delete-directory-tree directory :validate t)))))

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
           :server-version "bursyk-server_0.0.2.9"
           :version-addendum "experimental")
        (is (null error))
        (is (not (null opened)))
        (is (equal "SSH-2.0-bursyk-server_0.0.2.9 experimental" greeting)))))

(test version-addendum-none-leaves-the-greeting-alone
  "sshd's \"VersionAddendum none\" appends no comment at all."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (multiple-value-bind (opened error greeting)
          (ssh-test-loopback-outcome
           (lambda (client fingerprint key)
             (declare (ignore client fingerprint key))
             t)
           :server-version "bursyk-server_0.0.2.9"
           :version-addendum :none)
        (is (null error))
        (is (not (null opened)))
        (is (equal "SSH-2.0-bursyk-server_0.0.2.9" greeting)))))

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
        (is (equal "SSH-2.0-cl-pnet-ssh_0.0.1.10" greeting))
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
      (ignore-errors (delete-directory-tree directory :validate t)))))

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
          (ignore-errors (delete-directory-tree directory :validate t))))))

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
              (ignore-errors (delete-directory-tree directory :validate t))))))))

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
              (ignore-errors (delete-directory-tree directory :validate t))))))))

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
      (ignore-errors (delete-directory-tree directory :validate t)))))

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
              (ignore-errors (delete-directory-tree directory :validate t))))))))

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
