(in-package #:cl-pnet-ssh)

;;;; The server's transport state machine: version exchange, KEX, NEWKEYS,
;;;; user authentication, then channel dispatch.  It shares every primitive
;;;; with the client; only the order of messages and the signing side differ.

(defparameter +ssh-server-kex-algorithms+
  '("curve25519-sha256"
    "curve25519-sha256@libssh.org"
    "kex-strict-s-v00@openssh.com")
  "Server KEX offers.  The strict marker tells OpenSSH clients to reset
sequence numbers at NEWKEYS; it is not an algorithm and is never selected.")

(defun ssh-server-make-kexinit-payload ()
  "A fresh server SSH_MSG_KEXINIT."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-kexinit+)
    (ssh-write-octets writer (ssh-random-octets 16))
    (iter (for list in (list +ssh-server-kex-algorithms+
                             +ssh-host-key-algorithms+
                             +ssh-ciphers+ +ssh-ciphers+
                             +ssh-macs+ +ssh-macs+
                             +ssh-compressions+ +ssh-compressions+
                             '() '()))
      (ssh-write-name-list writer list))
    (ssh-write-boolean writer nil)
    (ssh-write-u32 writer 0)
    (ssh-writer-output writer)))

(defun ssh-server-connected (session connection)
  "SESSION's TCP connection is up: greet it and offer our KEXINIT."
  (setf (ssh-session-connection session) connection
        (ssh-session-phase session) :version)
  (ssh-session-send-bytes
   session
   (ssh-string-octets (concatenate 'string
                                   (ssh-session-server-version session)
                                   (string #\Return) (string #\Newline))))
  (let ((kexinit (ssh-server-make-kexinit-payload)))
    (setf (ssh-session-server-kexinit session) kexinit
          (ssh-session-kexinit-sent session) t)
    (ssh-session-send-payload session kexinit)))

(defun ssh-server-read-version-line (session)
  "Consume one line of the version exchange.
Returns :VERSION when the peer line arrived, :BANNER for a pre-version line,
and NIL while the line is still incomplete."
  (let* ((buffer (ssh-session-incoming session))
         (newline (position 10 buffer)))
    (when newline
      (let ((line (string-right-trim
                   '(#\Return)
                   (map 'string #'code-char (subseq buffer 0 newline)))))
        (ssh-session-buffer-consume session (1+ newline))
        (if (and (>= (length line) 4) (string= (subseq line 0 4) "SSH-"))
            (progn
              (setf (ssh-session-client-version session) line
                    (ssh-session-phase session) :kex)
              :version)
            :banner)))))

(defun ssh-server-advance (session)
  "Process every complete message in SESSION's receive buffer."
  (handler-case
      (iter (while (not (ssh-session-closed-p session)))
        (if (eq (ssh-session-phase session) :version)
            (unless (ssh-server-read-version-line session) (leave))
            (multiple-value-bind (payload consumed)
                (ssh-decode-packet (ssh-session-incoming session)
                                   (ssh-session-cipher session))
              (when (eq payload :incomplete) (leave))
              (ssh-session-buffer-consume session consumed)
              (ssh-server-handle-payload session payload))))
    (error (condition) (ssh-session-fail session condition))))

(defun ssh-server-receive (session data)
  "The event loop has DATA for SESSION, or NIL at the end of the connection."
  (unless (ssh-session-closed-p session)
    (if (null data)
        (ssh-session-finish session :peer-closed :close)
        (progn
          (ssh-session-buffer-append session data)
          (ssh-server-advance session)))))

(defun ssh-server-handle-payload (session payload)
  "Dispatch one decrypted protocol message."
  (when (ssh-session-ignore-next-kex-packet session)
    (setf (ssh-session-ignore-next-kex-packet session) nil)
    (when (<= +ssh-msg-kex-ecdh-init+ (aref payload 0)
              +ssh-msg-kex-ecdh-reply+)
      (return-from ssh-server-handle-payload nil)))
  (let ((type (aref payload 0)))
    (cond
      ((= type +ssh-msg-disconnect+)
       (ssh-server-handle-disconnect session payload))
      ((member type '(+ssh-msg-ignore+ +ssh-msg-debug+ +ssh-msg-unimplemented+))
       nil)
      ((= type +ssh-msg-kexinit+)
       (ssh-server-handle-kexinit session payload))
      ((= type +ssh-msg-kex-ecdh-init+)
       (ssh-server-handle-kex-init session payload))
      ((= type +ssh-msg-newkeys+)
       (ssh-server-handle-newkeys session))
      ((= type +ssh-msg-service-request+)
       (ssh-server-handle-service-request session payload))
      ((= type +ssh-msg-userauth-request+)
       (ssh-server-handle-userauth-request session payload))
      ((= type +ssh-msg-global-request+)
       (ssh-server-handle-global-request session payload))
      ((<= +ssh-msg-channel-open+ type +ssh-msg-channel-failure+)
       (ssh-server-handle-channel-message session payload)))))

(defun ssh-server-handle-disconnect (session payload)
  "The peer is going away: report its reason."
  (let* ((reader (ssh-make-reader payload))
         (reason (progn (ssh-read-u8 reader) (ssh-read-u32 reader)))
         (description (ssh-read-text reader)))
    (declare (ignore reason))
    (ssh-session-finish
     session (format nil "disconnected by peer: ~A" description) :close)))

;;; ---- Key exchange ----

(defun ssh-server-negotiate (session client-kexinit)
  "Choose algorithms from CLIENT-KEXINIT for the server role."
  (let* ((kex (ssh-choose-algorithm +ssh-server-kex-algorithms+
                                    (getf client-kexinit :kex)))
         (host-key (ssh-choose-algorithm +ssh-host-key-algorithms+
                                         (getf client-kexinit :host-keys)))
         (cipher-c2s (ssh-choose-algorithm +ssh-ciphers+
                                           (getf client-kexinit :ciphers-c2s)))
         (cipher-s2c (ssh-choose-algorithm +ssh-ciphers+
                                           (getf client-kexinit :ciphers-s2c)))
         (mac-c2s (ssh-choose-algorithm +ssh-macs+
                                        (getf client-kexinit :macs-c2s)))
         (mac-s2c (ssh-choose-algorithm +ssh-macs+
                                        (getf client-kexinit :macs-s2c)))
         (compression (ssh-choose-algorithm +ssh-compressions+
                                            (getf client-kexinit
                                                  :compressions-c2s))))
    (unless (and kex host-key cipher-c2s cipher-s2c mac-c2s mac-s2c compression)
      (error 'ssh-protocol-error
             :detail "no common algorithm for the server"))
    (list :kex kex :host-key host-key
          :cipher-c2s cipher-c2s :cipher-s2c cipher-s2c
          :mac-c2s mac-c2s :mac-s2c mac-s2c
          :strict (member "kex-strict-c-v00@openssh.com"
                          (getf client-kexinit :kex) :test #'string=))))

(defun ssh-server-send-kexinit (session)
  (let ((kexinit (ssh-server-make-kexinit-payload)))
    (setf (ssh-session-server-kexinit session) kexinit
          (ssh-session-kexinit-sent session) t)
    (ssh-session-send-payload session kexinit)))

(defun ssh-server-handle-kexinit (session payload)
  "Remember the client's offer, choose, and wait for its ECDH_INIT.

A client-initiated rekey starts here too.  We need our own KEXINIT in
flight before the reply, and the initial one was sent when the connection
came up."
  (unless (ssh-session-kexinit-sent session)
    (ssh-server-send-kexinit session))
  (when (eq (ssh-session-phase session) :ready)
    (setf (ssh-session-rekey session) t
          (ssh-session-phase session) :kex))
  (let ((offers (ssh-parse-kexinit-payload payload)))
    (setf (ssh-session-client-kexinit session) payload
          (ssh-session-negotiated session) (ssh-server-negotiate session offers)
          (ssh-session-strict-kex session)
          (getf (ssh-session-negotiated session) :strict)
          (ssh-session-ignore-next-kex-packet session)
          (getf (ssh-session-negotiated session) :guess-wrong))))

(defun ssh-server-handle-kex-init (session payload)
  "Answer the client's curve25519 offer: host key, ephemeral key, signature."
  (let* ((reader (ssh-make-reader payload))
         (client-public (progn (ssh-read-u8 reader) (ssh-read-string reader)))
         (private nil)
         (server-public nil)
         (shared nil)
         (hash nil)
         (signature nil))
    (unless (ssh-session-negotiated session)
      (error 'ssh-protocol-error :detail "ECDH_INIT before KEXINIT"))
    (multiple-value-setq (private server-public) (ssh-curve25519-keypair))
    (setf shared (ssh-curve25519-shared private client-public))
    (setf hash (ssh-exchange-hash
                (ssh-session-client-version session)
                (ssh-session-server-version session)
                (ssh-session-client-kexinit session)
                (ssh-session-server-kexinit session)
                (ssh-public-key-blob-of (ssh-server-host-key
                                         (ssh-session-server session)))
                client-public server-public shared)
          signature (ssh-ed25519-signature-blob
                     (ssh-server-host-key (ssh-session-server session)) hash))
    (setf (ssh-session-session-id session)
          (or (ssh-session-session-id session) hash)
          (ssh-session-ephemeral-private session) private
          (ssh-session-ephemeral-public session) server-public
          (ssh-session-host-key-blob session)
          (ssh-public-key-blob-of (ssh-server-host-key
                                   (ssh-session-server session)))
          (ssh-session-derived-keys session)
          (ssh-session-keys (ssh-session-negotiated session) shared hash
                            (ssh-session-session-id session) :server t))
    (ssh-server-send-kex-reply session server-public signature)
    (ssh-server-send-newkeys session)))

(defun ssh-server-send-kex-reply (session server-public signature)
  "Send KEX_ECDH_REPLY: our host key, ephemeral key and signature."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-kex-ecdh-reply+)
    (ssh-write-string writer (ssh-session-host-key-blob session))
    (ssh-write-string writer server-public)
    (ssh-write-string writer signature)
    (ssh-session-send-payload session (ssh-writer-output writer))))

(defun ssh-server-send-newkeys (session)
  "Send NEWKEYS, then switch our sending half to the negotiated keys."
  (let ((keys (ssh-session-derived-keys session))
        (cipher (ssh-session-cipher session)))
    (ssh-session-send-payload
     session (make-array 1 :element-type '(unsigned-byte 8)
                           :initial-element +ssh-msg-newkeys+))
    (when (ssh-session-strict-kex session)
      (ssh-reset-send-sequence cipher))
    (ssh-install-keys cipher
                      :encrypt (getf keys :encrypt)
                      :encrypt-mac-key (getf keys :encrypt-mac-key)
                      :encrypt-mac (getf keys :encrypt-mac)
                      :aead (getf keys :aead))
    (setf (ssh-session-keys-sent session) t
          (ssh-session-kexinit-sent session) nil)
    (ssh-server-maybe-finish-kex session)))

(defun ssh-server-handle-newkeys (session)
  "The client's NEWKEYS arrived: switch our receiving half, then proceed."
  (let ((keys (ssh-session-derived-keys session))
        (cipher (ssh-session-cipher session)))
    (when (ssh-session-strict-kex session)
      (ssh-reset-receive-sequence cipher))
    (ssh-install-keys cipher
                      :decrypt (getf keys :decrypt)
                      :decrypt-mac-key (getf keys :decrypt-mac-key)
                      :decrypt-mac (getf keys :decrypt-mac)
                      :aead (getf keys :aead))
    (setf (ssh-session-keys-received session) t)
    (ssh-server-maybe-finish-kex session)))

(defun ssh-server-maybe-finish-kex (session)
  "Once both NEWKEYS have crossed, move on to authentication or the session."
  (when (and (ssh-session-keys-sent session)
             (ssh-session-keys-received session)
             (eq (ssh-session-phase session) :kex))
    (setf (ssh-session-phase session)
          (if (ssh-session-rekey session) :ready :auth)
          (ssh-session-rekey session) nil
          (ssh-session-keys-sent session) nil
          (ssh-session-keys-received session) nil)))

;;; ---- Service and authentication ----

(defun ssh-server-handle-service-request (session payload)
  "Accept the ssh-userauth service the client asks for."
  (let* ((reader (ssh-make-reader payload))
         (service (progn (ssh-read-u8 reader) (ssh-read-text reader)))
         (writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-service-accept+)
    (ssh-write-text writer service)
    (ssh-session-send-payload session (ssh-writer-output writer))))

(defun ssh-server-send-auth-failure (session)
  "Refuse the current attempt and say publickey is the only method."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-userauth-failure+)
    (ssh-write-name-list writer '("publickey"))
    (ssh-write-boolean writer nil)
    (ssh-session-send-payload session (ssh-writer-output writer))))

(defun ssh-server-send-pk-ok (session algorithm key-blob)
  "Tell the client the unsigned key is acceptable; it may sign next."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-userauth-pk-ok+)
    (ssh-write-text writer algorithm)
    (ssh-write-string writer key-blob)
    (ssh-session-send-payload session (ssh-writer-output writer))))

(defun ssh-server-send-auth-success (session)
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-userauth-success+)
    (ssh-session-send-payload session (ssh-writer-output writer))))

(defun ssh-server-userauth-request-bytes (user algorithm key-blob)
  "The signed part of a publickey request, encoded exactly as received."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-userauth-request+)
    (ssh-write-text writer user)
    (ssh-write-text writer "ssh-connection")
    (ssh-write-text writer "publickey")
    (ssh-write-boolean writer t)
    (ssh-write-text writer algorithm)
    (ssh-write-string writer key-blob)
    (ssh-writer-output writer)))

(defun ssh-server-signed-data (session user algorithm key-blob)
  "The octets a publickey request signs: session id then the request.

The session id is itself a length-prefixed string, so it is written with
SSH-WRITE-STRING; writing its raw octets would shift every later field."
  (let ((writer (ssh-writer)))
    (ssh-write-string writer (ssh-session-session-id session))
    (ssh-write-octets writer
                      (ssh-server-userauth-request-bytes user algorithm key-blob))
    (ssh-writer-output writer)))

(defun ssh-server-verify-signature (session user algorithm key-blob signature)
  "True when SIGNATURE covers this request and SESSION's session id."
  (handler-case
      (multiple-value-bind (type bytes) (ssh-parse-signature-blob signature)
        (and (string= type algorithm)
             (string= algorithm "ssh-ed25519")
             (ssh-ed25519-verify
              bytes
              (ssh-server-signed-data session user algorithm key-blob)
              (ssh-ed25519-key-bytes key-blob))))
    (error () nil)))

(defun ssh-server-authorized-key-p (server user key-blob)
  "Whether KEY-BLOB may log in as USER."
  (let ((authorize (ssh-server-authorize server)))
    (cond
      ((functionp authorize) (funcall authorize user key-blob))
      ((ssh-server-authorized-keys server)
       (ssh-authorized-key-blob-p (ssh-server-authorized-keys server) key-blob))
      (t nil))))

(defun ssh-server-complete-auth (session user key-blob)
  "Accept SESSION's authenticated user, then let the application run."
  (setf (ssh-session-user session) user
        (ssh-session-authorized-key session) key-blob
        (ssh-session-authenticated session) t
        (ssh-session-phase session) :ready)
  (ssh-server-send-auth-success session)
  (when (ssh-server-on-session (ssh-session-server session))
    (funcall (ssh-server-on-session (ssh-session-server session)) session)))

(defun ssh-server-handle-signed-key (session user algorithm key-blob reader)
  (let ((signature (ssh-read-string reader)))
    (if (and (ssh-server-verify-signature session user algorithm key-blob signature)
             (ssh-server-authorized-key-p (ssh-session-server session)
                                          user key-blob))
        (ssh-server-complete-auth session user key-blob)
        (ssh-server-send-auth-failure session))))

(defun ssh-server-handle-publickey (session user algorithm key-blob reader
                                    has-signature)
  "Handle one publickey attempt, signed or merely offered."
  (if (and (string= algorithm "ssh-ed25519")
           (ssh-server-authorized-key-p (ssh-session-server session)
                                        user key-blob))
      (if has-signature
          (ssh-server-handle-signed-key session user algorithm key-blob reader)
          (ssh-server-send-pk-ok session algorithm key-blob))
      (ssh-server-send-auth-failure session)))

(defun ssh-server-handle-userauth-request (session payload)
  "Parse one USER AUTH REQUEST and answer it."
  (let* ((reader (ssh-make-reader payload))
         (type (ssh-read-u8 reader))
         (user (ssh-read-text reader))
         (service (ssh-read-text reader))
         (method (ssh-read-text reader)))
    (declare (ignore type))
    (cond
      ((not (string= service "ssh-connection"))
       (ssh-server-send-auth-failure session))
      ((string= method "publickey")
       (let ((has-signature (ssh-read-boolean reader))
             (algorithm (ssh-read-text reader))
             (key-blob (ssh-read-string reader)))
         (ssh-server-handle-publickey session user algorithm key-blob reader
                                      has-signature)))
      (t (ssh-server-send-auth-failure session)))))

(defun ssh-server-handle-global-request (session payload)
  (let* ((reader (ssh-make-reader payload))
         (name (progn (ssh-read-u8 reader) (ssh-read-text reader)))
         (want-reply (ssh-read-boolean reader)))
    (declare (ignore name))
    (when want-reply
      (let ((writer (ssh-writer)))
        (ssh-write-u8 writer +ssh-msg-request-failure+)
        (ssh-session-send-payload session (ssh-writer-output writer))))))
