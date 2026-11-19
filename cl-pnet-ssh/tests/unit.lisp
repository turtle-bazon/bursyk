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

(defun ssh-test-write-authorized-keys (public-key-file authorized-file)
  "Copy the one public key in PUBLIC-KEY-FILE into AUTHORIZED-FILE."
  (with-open-file (output authorized-file :direction :output
                                      :if-exists :supersede
                                      :if-does-not-exist :create)
    (with-open-file (input public-key-file)
      (write-line (string-trim '(#\Space #\Return #\Newline) (read-line input))
                  output))))

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

(defun ssh-test-loopback-result ()
  "Run one exec through a server and client in this process.
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
           (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                             "-f" (namestring server-key)))
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
