(in-package #:cl-pnet-ssh)

;;;; The server's transport state machine: version exchange, KEX, NEWKEYS,
;;;; user authentication, then channel dispatch.  It shares every primitive
;;;; with the client; only the order of messages and the signing side differ.

(defparameter +ssh-server-kex-algorithms+
  '("curve25519-sha256"
    "curve25519-sha256@libssh.org"
    ;; Markers, never selected: strict KEX and RFC 8308 extensions.
    "kex-strict-s-v00@openssh.com"
    "ext-info-s")
  "Server KEX offers.  The markers are negotiation signals, not algorithms.")

(defun ssh-server-make-kexinit-payload (session)
  "A fresh server SSH_MSG_KEXINIT advertising the keys SESSION's server holds."
  (let ((host-keys (ssh-server-host-keys
                    (ssh-session-server session)))
        (writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-kexinit+)
    (ssh-write-octets writer (ssh-random-octets 16))
    (iter (for list in (list +ssh-server-kex-algorithms+
                             (ssh-server-host-key-algorithms host-keys)
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
  (let ((kexinit (ssh-server-make-kexinit-payload session)))
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
          (ssh-session-note-input session)
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
  "Choose algorithms from CLIENT-KEXINIT for the server role.

The host key offer is built from SESSION's loaded keys, so every algorithm
advertised can be signed with."
  (let* ((kex (ssh-choose-algorithm
               (remove-if #'ssh-kex-marker-p +ssh-server-kex-algorithms+)
               (getf client-kexinit :kex)))
         (host-key (ssh-choose-algorithm
                    (ssh-server-host-key-algorithms
                     (ssh-server-host-keys (ssh-session-server session)))
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
          :ext-info (and (member "ext-info-c" (getf client-kexinit :kex)
                                 :test #'string=)
                         t)
          :strict (member "kex-strict-c-v00@openssh.com"
                          (getf client-kexinit :kex) :test #'string=))))

(defun ssh-server-send-kexinit (session)
  (let ((kexinit (ssh-server-make-kexinit-payload session)))
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
          ;; Only the first KEXINIT carries the strict-KEX marker; once the
          ;; connection is strict it stays strict through every rekey.
          (ssh-session-strict-kex session)
          (or (ssh-session-strict-kex session)
              (getf (ssh-session-negotiated session) :strict))
          (ssh-session-ignore-next-kex-packet session)
          (getf (ssh-session-negotiated session) :guess-wrong))))

(defun ssh-server-handle-kex-init (session payload)
  "Answer the client's curve25519 offer: host key, ephemeral key, signature."
  (let* ((reader (ssh-make-reader payload))
         (client-public (progn (ssh-read-u8 reader) (ssh-read-string reader)))
         (algorithm (getf (ssh-session-negotiated session) :host-key))
         (host-key (and algorithm
                        (ssh-server-host-key-for
                         (ssh-server-host-keys (ssh-session-server session))
                         algorithm)))
         (private nil)
         (server-public nil)
         (shared nil)
         (hash nil)
         (signature nil))
    (unless (ssh-session-negotiated session)
      (error 'ssh-protocol-error :detail "ECDH_INIT before KEXINIT"))
    (unless host-key
      (error 'ssh-protocol-error
             :detail (format nil "no key for host key algorithm ~A" algorithm)))
    (multiple-value-setq (private server-public) (ssh-curve25519-keypair))
    (setf shared (ssh-curve25519-shared private client-public))
    (setf hash (ssh-exchange-hash
                (ssh-session-client-version session)
                (ssh-session-server-version session)
                (ssh-session-client-kexinit session)
                (ssh-session-server-kexinit session)
                (ssh-public-key-blob-of host-key)
                client-public server-public shared)
          signature (ssh-server-host-key-signature host-key algorithm hash))
    (setf (ssh-session-session-id session)
          (or (ssh-session-session-id session) hash)
          (ssh-session-ephemeral-private session) private
          (ssh-session-ephemeral-public session) server-public
          (ssh-session-host-key-blob session)
          (ssh-public-key-blob-of host-key)
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

(defun ssh-server-send-ext-info (session)
  "Tell the client which public-key signatures this server accepts.

RFC 8308 sends EXT_INFO right after the first NEWKEYS, when the client
asked for it with ext-info-c.  Without server-sig-algs an OpenSSH client
refuses to try an RSA key (\"no mutual signature algorithm\"), because it
cannot know that rsa-sha2-512 is acceptable."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-ext-info+)
    (ssh-write-u32 writer 1)
    (ssh-write-text writer "server-sig-algs")
    (ssh-write-name-list writer +ssh-server-user-key-algorithms+)
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
    (when (and (getf (ssh-session-negotiated session) :ext-info)
               (not (ssh-session-rekey session)))
      (ssh-server-send-ext-info session))
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

(defun ssh-server-banner-text (server)
  "The Banner text SERVER should send now, or NIL.

The application may pass the text itself or a function returning it; sshd
reads its Banner file for every connection, so a function keeps that
behaviour without this library knowing about files."
  (let ((banner (ssh-server-banner server)))
    (when banner
      (let ((text (if (functionp banner) (funcall banner) banner)))
        (when (and text (plusp (length text)))
          text)))))

(defun ssh-server-send-banner (session)
  "Send the configured Banner before the first authentication reply.

RFC 4252 allows banners at any point during authentication; sshd sends one
when the first USER AUTH REQUEST arrives, which is when the account name is
finally known to the user."
  (let ((text (ssh-server-banner-text (ssh-session-server session))))
    (when text
      (let ((writer (ssh-writer)))
        (ssh-write-u8 writer +ssh-msg-userauth-banner+)
        (ssh-write-text writer text)
        ;; Language tag, unused, as in sshd.
        (ssh-write-text writer "")
        (ssh-session-send-payload session (ssh-writer-output writer))))))

(defun ssh-server-send-auth-failure (session &key (count t))
  "Refuse the current attempt and say publickey is the only method.

COUNT is false for sshd's two exempt cases: the first \"none\" probe and an
unsigned publickey offer that was answered with PK_OK.  Reaching
MaxAuthTries sends DISCONNECT instead of another failure."
  (when count
    (incf (ssh-session-auth-failures session))
    (when (>= (ssh-session-auth-failures session)
              (ssh-server-max-auth-tries (ssh-session-server session)))
      (ssh-session-send-payload-and-close
       session
       (ssh-disconnect-payload "Too many authentication failures"
                               +ssh-disconnect-protocol-error+)
       :auth-failures)
      (return-from ssh-server-send-auth-failure nil)))
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
  "True when SIGNATURE covers this request and SESSION's session id.

The request's ALGORITHM and the signature blob's own name must agree, so an
rsa-sha2-512 request cannot be satisfied by a SHA-1 ssh-rsa signature."
  (and (ssh-server-user-key-algorithm-p key-blob algorithm)
       (handler-case
           (multiple-value-bind (signature-algorithm signature-bytes)
               (ssh-parse-signature-blob signature)
             (declare (ignore signature-bytes))
             (and (string= signature-algorithm algorithm)
                  (ssh-public-key-signature-valid-p
                   key-blob signature
                   (ssh-server-signed-data session user algorithm key-blob))))
         (error () nil))))

(defun ssh-server-complete-auth (session user key-blob &optional key-env)
  "Accept SESSION's authenticated user, then let the application run.

KEY-ENV holds the environment= assignments from the authorized_keys line
that admitted the key; the application applies them under
PermitUserEnvironment."
  (setf (ssh-session-user session) user
        (ssh-session-authorized-key session) key-blob
        (ssh-session-key-env session) key-env
        (ssh-session-authenticated session) t
        (ssh-session-phase session) :ready)
  (setf (ssh-session-login-grace-timer session)
        (ssh-session-cancel-timer (ssh-session-login-grace-timer session)))
  (ssh-server-send-auth-success session)
  (ssh-session-start-client-alive-timer session)
  (when (ssh-server-on-session (ssh-session-server session))
    (funcall (ssh-server-on-session (ssh-session-server session)) session)))

(defun ssh-server-handle-signed-key (session user algorithm key-blob reader
                                    &key (count t))
  (let ((signature (ssh-read-string reader)))
    (if (ssh-server-verify-signature session user algorithm key-blob signature)
        (multiple-value-bind (authorized key-env)
            (ssh-server-authorized-key-p (ssh-session-server session)
                                         user key-blob)
          (if authorized
              (ssh-server-complete-auth session user key-blob key-env)
              (ssh-server-send-auth-failure session :count count)))
        (ssh-server-send-auth-failure session :count count))))

(defun ssh-server-handle-publickey (session user algorithm key-blob reader
                                    has-signature &key (count t))
  "Handle one publickey attempt, signed or merely offered."
  (if (and (ssh-server-user-key-algorithm-p key-blob algorithm)
           (ssh-server-authorized-key-p (ssh-session-server session)
                                        user key-blob))
      (if has-signature
          (ssh-server-handle-signed-key session user algorithm key-blob reader
                                        :count count)
          ;; An accepted offer is sshd's "partial" attempt: it may not count
          ;; against MaxAuthTries because no authentication was tried.
          (ssh-server-send-pk-ok session algorithm key-blob))
      (ssh-server-send-auth-failure session :count count)))

(defun ssh-server-user-permitted-p (session user)
  "Whether the application admits USER on SESSION.

The answer is cached per name: sshd decides this once when the name first
appears, and running a group lookup again on every retry would only repeat
the same answer."
  (let ((hook (ssh-server-authorize-user (ssh-session-server session))))
    (if (null hook)
        t
        (let ((cached (assoc user (ssh-session-allowed-users session)
                             :test #'string=)))
          (if cached
              (cdr cached)
              (let ((allowed (and (funcall hook session user) t)))
                (push (cons user allowed)
                      (ssh-session-allowed-users session))
                allowed))))))

(defun ssh-server-auth-failure-counts-p (attempt method)
  "Whether a failed ATTEMPT using METHOD counts toward MaxAuthTries.

sshd exempts the first \"none\" probe every client sends to learn the
allowed methods; everything after it counts."
  (or (/= 1 attempt)
      (not (string= method "none"))))

(defun ssh-server-handle-userauth-request (session payload)
  "Parse one USER AUTH REQUEST and answer it."
  (let* ((reader (ssh-make-reader payload))
         (type (ssh-read-u8 reader))
         (user (ssh-read-text reader))
         (service (ssh-read-text reader))
         (method (ssh-read-text reader)))
    (declare (ignore type))
    (when (zerop (ssh-session-auth-attempts session))
      (ssh-server-send-banner session))
    (incf (ssh-session-auth-attempts session))
    (let ((count (ssh-server-auth-failure-counts-p
                  (ssh-session-auth-attempts session) method)))
      (cond
        ((not (string= service "ssh-connection"))
         (ssh-server-send-auth-failure session :count count))
        ((not (ssh-server-user-permitted-p session user))
         (ssh-server-send-auth-failure session :count count))
        ((string= method "publickey")
         (let ((has-signature (ssh-read-boolean reader))
               (algorithm (ssh-read-text reader))
               (key-blob (ssh-read-string reader)))
           (ssh-server-handle-publickey session user algorithm key-blob reader
                                        has-signature :count count)))
        (t (ssh-server-send-auth-failure session :count count))))))

(defun ssh-server-send-global-reply (session success-p &optional fields)
  "Answer the last global request.  FIELDS writes its success arguments."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer (if success-p
                             +ssh-msg-request-success+
                             +ssh-msg-request-failure+))
    (when (and success-p fields) (funcall fields writer))
    (ssh-session-send-payload session (ssh-writer-output writer))))

(defun ssh-server-handle-tcpip-forward (session reader want-reply)
  "Offer a remote forwarding request to the application.

The application binds the requested address and port and returns the port
it got, which differs from the request only when the client asked for port
0.  A NIL answer refuses the request."
  (let* ((bind-address (ssh-read-text reader))
         (bind-port (ssh-read-u32 reader))
         (handler (ssh-server-on-tcpip-forward (ssh-session-server session)))
         (bound (and handler
                     (funcall handler session bind-address bind-port))))
    (when want-reply
      (if bound
          (ssh-server-send-global-reply
           session t
           (and (zerop bind-port)
                (lambda (writer) (ssh-write-u32 writer bound))))
          (ssh-server-send-global-reply session nil)))))

(defun ssh-server-handle-cancel-tcpip-forward (session reader want-reply)
  (let* ((bind-address (ssh-read-text reader))
         (bind-port (ssh-read-u32 reader))
         (handler (ssh-server-on-cancel-tcpip-forward
                   (ssh-session-server session)))
         (ok (and handler
                  (funcall handler session bind-address bind-port))))
    (when want-reply
      (ssh-server-send-global-reply session (not (null ok))))))

(defun ssh-server-handle-global-request (session payload)
  (let* ((reader (ssh-make-reader payload))
         (name (progn (ssh-read-u8 reader) (ssh-read-text reader)))
         (want-reply (ssh-read-boolean reader)))
    (cond
      ((string= name "tcpip-forward")
       (ssh-server-handle-tcpip-forward session reader want-reply))
      ((string= name "cancel-tcpip-forward")
       (ssh-server-handle-cancel-tcpip-forward session reader want-reply))
      (t
       (when want-reply
         (ssh-server-send-global-reply session nil))))))

(defun ssh-session-send-keepalive (session)
  "Send OpenSSH's keepalive@openssh.com global request with a reply wanted.

The reply proves the peer is alive; any inbound packet resets the miss
count, so the content of the reply does not matter.  A global request is
used whether or not a channel is open, which keeps the probe out of the
application's channel callbacks."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-global-request+)
    (ssh-write-text writer "keepalive@openssh.com")
    (ssh-write-boolean writer t)
    (ssh-session-send-payload session (ssh-writer-output writer))))
