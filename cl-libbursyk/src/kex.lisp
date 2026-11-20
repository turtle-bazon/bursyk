(in-package #:cl-pnet-ssh)

;;;; Key exchange (RFC 4253 section 7, RFC 8731): version negotiation comes
;;;; before this, and after it the session is encrypted.

;;; ---- Message numbers (RFC 4250 section 4.1) ----

(defconstant +ssh-msg-disconnect+ 1)
(defconstant +ssh-msg-ignore+ 2)
(defconstant +ssh-msg-unimplemented+ 3)
(defconstant +ssh-msg-debug+ 4)
(defconstant +ssh-msg-service-request+ 5)
(defconstant +ssh-msg-service-accept+ 6)
(defconstant +ssh-msg-ext-info+ 7)
(defconstant +ssh-msg-kexinit+ 20)
(defconstant +ssh-msg-newkeys+ 21)
(defconstant +ssh-msg-kex-ecdh-init+ 30)
(defconstant +ssh-msg-kex-ecdh-reply+ 31)
(defconstant +ssh-msg-userauth-request+ 50)
(defconstant +ssh-msg-userauth-failure+ 51)
(defconstant +ssh-msg-userauth-success+ 52)
(defconstant +ssh-msg-userauth-banner+ 53)
(defconstant +ssh-msg-userauth-pk-ok+ 60)
(defconstant +ssh-msg-global-request+ 80)
(defconstant +ssh-msg-request-success+ 81)
(defconstant +ssh-msg-request-failure+ 82)
(defconstant +ssh-msg-channel-open+ 90)
(defconstant +ssh-msg-channel-open-confirmation+ 91)
(defconstant +ssh-msg-channel-open-failure+ 92)
(defconstant +ssh-msg-channel-window-adjust+ 93)
(defconstant +ssh-msg-channel-data+ 94)
(defconstant +ssh-msg-channel-extended-data+ 95)
(defconstant +ssh-msg-channel-eof+ 96)
(defconstant +ssh-msg-channel-close+ 97)
(defconstant +ssh-msg-channel-request+ 98)
(defconstant +ssh-msg-channel-success+ 99)
(defconstant +ssh-msg-channel-failure+ 100)

;; Disconnect reason codes (RFC 4250 section 4.2.2).
(defconstant +ssh-disconnect-protocol-error+ 2
  "RFC 4253 reason 2; sshd uses it for a policy disconnect such as
MaxAuthTries, which is why the client shows it as a protocol-error
disconnect rather than a plain application one.")

(defconstant +ssh-disconnect-by-application+ 11)

;;; ---- Identification and disconnection ----

(defparameter +ssh-server-version+ "SSH-2.0-cl-pnet-ssh_0.0.1.10"
  "The default SSH identification string a server sends.

A program identifies itself by passing SERVER-VERSION to MAKE-SSH-SERVER;
the library's own default is only for callers that do not name themselves.")

(defun check-server-version (version)
  "Validate VERSION as the tail of the SSH identification string.

RFC 4253 allows printable US-ASCII and forbids space, so a malformed value
is refused here rather than corrupting the greeting on the wire."
  (unless (and (stringp version)
               (plusp (length version))
               (<= (+ 10 (length version)) 255)
               (every (lambda (character)
                        (let ((code (char-code character)))
                          (and (<= 32 code 126) (/= code 32))))
                      version))
    (error 'ssh-connection-error
           :detail (format nil "invalid server version ~S" version)))
  version)

(defun check-version-addendum (addendum)
  "Validate ADDENDUM, the comment appended after the identification string.

sshd writes it as \"SSH-2.0-name comment\".  A CR or LF would end the
greeting early, so only printable ASCII is accepted here; spaces are fine."
  (unless (and (stringp addendum)
               (plusp (length addendum))
               (every (lambda (character)
                        (let ((code (char-code character)))
                          (and (<= 32 code 126))))
                      addendum))
    (error 'ssh-connection-error
           :detail (format nil "invalid version addendum ~S" addendum)))
  addendum)

(defun ssh-disconnect-payload (&optional (description "client closed")
                                        (reason +ssh-disconnect-by-application+))
  "A DISCONNECT payload: reason code, description and language tag.

Both strings are length-prefixed as RFC 4253 section 11.1 requires;
SSH-STRING-OCTETS only turns text into UTF-8 bytes, so building the message
with SSH-CONCAT around it would hand the peer the text itself as a length."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-disconnect+)
    (ssh-write-u32 writer reason)
    (ssh-write-text writer (princ-to-string description))
    (ssh-write-text writer "")
    (ssh-writer-output writer)))


;;; ---- Algorithm preferences ----

(defparameter +ssh-kex-algorithms+
  '("curve25519-sha256"
    "curve25519-sha256@libssh.org"
    ;; Not algorithms: markers asking the peer to answer EXT_INFO and to
    ;; reset packet sequence numbers at NEWKEYS (OpenSSH's strict KEX).
    "ext-info-c"
    "kex-strict-c-v00@openssh.com"))

(defparameter +ssh-host-key-algorithms+
  '("ssh-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    ;; RSA host keys keep the ssh-rsa key format while rsa-sha2 names the
    ;; signature; SHA-1 ssh-rsa stays last for servers that never learned
    ;; the newer names.
    "rsa-sha2-512"
    "rsa-sha2-256"
    "ssh-rsa")
  "Host key algorithms offered to a server, in preference order.")

(defparameter +ssh-server-host-key-preference+
  '("ssh-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    "rsa-sha2-512"
    "rsa-sha2-256"
    "ssh-rsa")
  "Host key algorithms a server can present, in preference order.

A server advertises only those its loaded keys can actually sign with, so a
client never selects an algorithm that would fail at KEX_ECDH_REPLY.")

(defun ssh-server-host-key-algorithm-p (key algorithm)
  "Whether private KEY can sign with host key ALGORITHM."
  (let ((type (ssh-private-key-type key)))
    (and type
         (cond
           ((string= algorithm "ssh-ed25519")
            (string= type "ssh-ed25519"))
           ((ssh-rsa-digest-keyword algorithm)
            ;; A single ssh-rsa key serves all three signature algorithms.
            (string= type "ssh-rsa"))
           (t
            (string= type algorithm))))))

(defun ssh-server-host-key-algorithms (keys)
  "The host key algorithms KEYS can present, in preference order."
  (remove-if-not
   (lambda (algorithm)
     (some (lambda (key)
             (ssh-server-host-key-algorithm-p key algorithm))
           keys))
   +ssh-server-host-key-preference+))

(defun ssh-server-host-key-for (keys algorithm)
  "The first of KEYS able to sign with host key ALGORITHM, or NIL."
  (find-if (lambda (key)
             (ssh-server-host-key-algorithm-p key algorithm))
           keys))

(defun ssh-server-host-key-signature (key algorithm message)
  "A signature blob of MESSAGE under host KEY for negotiated ALGORITHM.

RSA is the one type whose wire signature name differs from the key type:
rsa-sha2-512 and rsa-sha2-256 select the digest while the key stays ssh-rsa."
  (let ((digest (ssh-rsa-digest-keyword algorithm)))
    (cond
      (digest (ssh-rsa-signature-blob key message digest))
      ((string= algorithm "ssh-ed25519")
       (ssh-ed25519-signature-blob key message))
      (t (ssh-ecdsa-signature-blob key message)))))


(defparameter +ssh-ciphers+ '("chacha20-poly1305@openssh.com"))

;; chacha20-poly1305@openssh.com is an AEAD and ignores the MAC, but RFC 4253
;; still negotiates one of these, and OpenSSH expects a common choice.
(defparameter +ssh-macs+ '("hmac-sha2-256" "hmac-sha2-512"))

(defparameter +ssh-compressions+ '("none"))

(defun ssh-choose-algorithm (ours theirs)
  "The first of OURS that is also in THEIRS, or NIL."
  (iter (for candidate in ours)
    (when (member candidate theirs :test #'string=)
      (leave candidate))))

(defun ssh-make-kexinit-payload ()
  "A fresh SSH_MSG_KEXINIT."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-kexinit+)
    (ssh-write-octets writer (ssh-random-octets 16))
    (iter (for list in (list +ssh-kex-algorithms+
                             +ssh-host-key-algorithms+
                             +ssh-ciphers+ +ssh-ciphers+
                             +ssh-macs+ +ssh-macs+
                             +ssh-compressions+ +ssh-compressions+
                             '() '()))
      (ssh-write-name-list writer list))
    (ssh-write-boolean writer nil)
    (ssh-write-u32 writer 0)
    (ssh-writer-output writer)))

(defun ssh-parse-kexinit-payload (payload)
  "PAYLOAD as a plist of the peer's KEXINIT offers."
  (let ((reader (ssh-make-reader payload)))
    (unless (= (ssh-read-u8 reader) +ssh-msg-kexinit+)
      (error 'ssh-protocol-error :detail "not a KEXINIT"))
    (ssh-read-octets reader 16)
    (list :kex (ssh-read-name-list reader)
          :host-keys (ssh-read-name-list reader)
          :ciphers-c2s (ssh-read-name-list reader)
          :ciphers-s2c (ssh-read-name-list reader)
          :macs-c2s (ssh-read-name-list reader)
          :macs-s2c (ssh-read-name-list reader)
          :compressions-c2s (ssh-read-name-list reader)
          :compressions-s2c (ssh-read-name-list reader)
          :languages-c2s (ssh-read-name-list reader)
          :languages-s2c (ssh-read-name-list reader)
          :first-kex-packet-follows (ssh-read-boolean reader))))

(defun ssh-negotiate (server-kexinit)
  "The mutually acceptable algorithms as a plist, or signal when empty.

:STRICT is true when the peer offered OpenSSH's strict-KEX marker, which
makes both sides reset packet sequence numbers at NEWKEYS."
  (let* ((kex (ssh-choose-algorithm +ssh-kex-algorithms+
                                    (getf server-kexinit :kex)))
         (host-key (ssh-choose-algorithm +ssh-host-key-algorithms+
                                         (getf server-kexinit :host-keys)))
         (cipher-c2s (ssh-choose-algorithm +ssh-ciphers+
                                           (getf server-kexinit :ciphers-c2s)))
         (cipher-s2c (ssh-choose-algorithm +ssh-ciphers+
                                           (getf server-kexinit :ciphers-s2c)))
         (mac-c2s (ssh-choose-algorithm +ssh-macs+
                                        (getf server-kexinit :macs-c2s)))
         (mac-s2c (ssh-choose-algorithm +ssh-macs+
                                        (getf server-kexinit :macs-s2c)))
         (compression (ssh-choose-algorithm +ssh-compressions+
                                            (getf server-kexinit
                                                  :compressions-c2s))))
    (unless (and kex host-key cipher-c2s cipher-s2c mac-c2s mac-s2c compression)
      (error 'ssh-protocol-error
             :detail "no common algorithm (need curve25519, a supported host key and chacha20-poly1305)"))
    (list :kex kex :host-key host-key
          :cipher-c2s cipher-c2s :cipher-s2c cipher-s2c
          :mac-c2s mac-c2s :mac-s2c mac-s2c
          :strict (member "kex-strict-s-v00@openssh.com"
                          (getf server-kexinit :kex) :test #'string=)
          :guess-wrong (and (getf server-kexinit :first-kex-packet-follows)
                            (not (and (string= (first (getf server-kexinit :kex)) kex)
                                      (string= (first (getf server-kexinit :host-keys))
                                               host-key)))))))

;;; ---- Exchange hash and key derivation ----

(defun ssh-exchange-hash (client-version server-version
                          client-kexinit server-kexinit
                          host-key-blob client-public server-public shared)
  "RFC 8731's H, binding both versions, both KEXINITs, the host key, both
ephemeral public keys and the X25519 shared secret."
  (let ((writer (ssh-writer)))
    (ssh-write-text writer client-version)
    (ssh-write-text writer server-version)
    (ssh-write-string writer client-kexinit)
    (ssh-write-string writer server-kexinit)
    (ssh-write-string writer host-key-blob)
    (ssh-write-string writer client-public)
    (ssh-write-string writer server-public)
    (ssh-write-mpint writer (ssh-mpint-integer shared))
    (ssh-hash :sha256 (ssh-writer-output writer))))

(defun ssh-derive-key (shared exchange-hash session-id letter length)
  "One key from RFC 4253 section 7.2, LENGTH octets long.

SHARED is the X25519 secret as octets; it and H are hashed as the spec
writes them, with the secret's mpint encoding carrying its length prefix."
  (let* ((k (let ((writer (ssh-writer)))
              (ssh-write-mpint writer (ssh-mpint-integer shared))
              (ssh-writer-output writer)))
         (material (ssh-hash :sha256 k exchange-hash
                             (make-array 1 :element-type '(unsigned-byte 8)
                                           :initial-element (char-code letter))
                             session-id)))
    ;; Only K1 mixes in the session id; later blocks chain the material so far
    ;; (RFC 4253 section 7.2: Kn = HASH(K || H || K1 || ... || Kn-1)).
    (iter (while (< (length material) length))
      (setf material (ssh-concat
                      material
                      (ssh-hash :sha256 k exchange-hash material))))
    (subseq material 0 length)))

(defun ssh-cipher-key-length (cipher)
  "The key length of CIPHER, or NIL when it is not implemented."
  (cond ((string= cipher "chacha20-poly1305@openssh.com") 64)
        (t nil)))

(defun ssh-cipher-iv-length (cipher)
  "The IV length of CIPHER, or NIL when it is not implemented."
  (cond ((string= cipher "chacha20-poly1305@openssh.com") 0)
        (t nil)))

(defun ssh-mac-name-keyword (mac)
  "The ironclad name for MAC, or NIL when it is not implemented."
  (cond ((string= mac "hmac-sha2-256") :sha256)
        ((string= mac "hmac-sha2-512") :sha512)
        ((string= mac "hmac-sha1") :sha1)
        (t nil)))

(defun ssh-mac-key-length (mac)
  (let ((name (ssh-mac-name-keyword mac)))
    (and name (ssh-hmac-length name))))

(defun ssh-session-keys (negotiated shared exchange-hash session-id &key server)
  "All six derived keys, as a plist keyed by direction and purpose.

SERVER selects the server half: the letters swap, because C/D and E/F name
the client-to-server and server-to-client directions, not the two ends."
  (let ((cipher-c2s (getf negotiated :cipher-c2s))
        (cipher-s2c (getf negotiated :cipher-s2c))
        (mac-c2s (ssh-mac-key-length (getf negotiated :mac-c2s)))
        (mac-s2c (ssh-mac-key-length (getf negotiated :mac-s2c))))
    (unless (and cipher-c2s cipher-s2c mac-c2s mac-s2c)
      (error 'ssh-protocol-error :detail "unsupported session algorithms"))
    (list :encrypt (ssh-derive-key shared exchange-hash session-id
                                   (if server #\D #\C)
                                   (ssh-cipher-key-length
                                    (if server cipher-s2c cipher-c2s)))
          :decrypt (ssh-derive-key shared exchange-hash session-id
                                   (if server #\C #\D)
                                   (ssh-cipher-key-length
                                    (if server cipher-c2s cipher-s2c)))
          :encrypt-mac-key (ssh-derive-key shared exchange-hash session-id
                                           (if server #\F #\E)
                                           (if server mac-s2c mac-c2s))
          :decrypt-mac-key (ssh-derive-key shared exchange-hash session-id
                                           (if server #\E #\F)
                                           (if server mac-c2s mac-s2c))
          :encrypt-mac (ssh-mac-name-keyword (getf negotiated :mac-c2s))
          :decrypt-mac (ssh-mac-name-keyword (getf negotiated :mac-s2c))
          :aead t)))

;;; ---- Host key and signature ----

(defun ssh-parse-signature-blob (blob)
  "BLOB as (VALUES ALGORITHM SIGNATURE-OCTETS)."
  (let ((reader (ssh-make-reader blob)))
    (values (ssh-read-text reader) (ssh-read-string reader))))

(defun ssh-kex-marker-p (name)
  "Whether NAME is a KEXINIT marker rather than a key exchange method.

ext-info-c, ext-info-s and the kex-strict-* names are negotiation signals;
selecting one as the exchange algorithm would abort the connection."
  (or (string= name "ext-info-c")
      (string= name "ext-info-s")
      (let ((prefix "kex-strict-"))
        (and (>= (length name) (length prefix))
             (string= prefix name :end2 (length prefix))))))

(defun ssh-public-key-signature-valid-p (key-blob signature-blob message)
  "Whether SIGNATURE-BLOB over MESSAGE verifies under public KEY-BLOB.

Everything this library can verify is supported here: ssh-ed25519, ssh-rsa
under any of RFC 8332's three signature names, and the three ECDSA curves.
A malformed or mismatched blob is simply not a valid signature."
  (handler-case
      (multiple-value-bind (type key-bytes) (ssh-public-key-parts key-blob)
        (multiple-value-bind (algorithm signature)
            (ssh-parse-signature-blob signature-blob)
          (cond
            ((string= type "ssh-ed25519")
             (and (string= algorithm "ssh-ed25519")
                  (ssh-ed25519-verify signature message key-bytes)))
            ((string= type "ssh-rsa")
             (let ((digest (ssh-rsa-digest-keyword algorithm)))
               (and digest
                    (ssh-rsa-verify key-bytes signature digest message))))
            ((member type '("ecdsa-sha2-nistp256"
                            "ecdsa-sha2-nistp384"
                            "ecdsa-sha2-nistp521")
                     :test #'string=)
             (and (string= algorithm type)
                  (ssh-ecdsa-verify key-bytes signature message)))
            (t nil))))
    (error () nil)))

(defun ssh-verify-host-signature (host-key-blob signature-blob exchange-hash)
  "Signal unless SIGNATURE-BLOB by HOST-KEY-BLOB covers EXCHANGE-HASH.

The key blob names the key type; the signature blob names the algorithm.
An RSA host key keeps the ssh-rsa type while the algorithm says
rsa-sha2-256 or rsa-sha2-512, exactly as RFC 8332 defines."
  (unless (ssh-public-key-signature-valid-p
           host-key-blob signature-blob exchange-hash)
    (error 'ssh-protocol-error
           :detail "host key signature does not verify")))
