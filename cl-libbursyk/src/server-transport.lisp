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

(defun ssh-server-kex-offer (session)
  "The KEX list SESSION advertises, with the server markers appended.

KexAlgorithms chooses the methods; the strict-KEX and EXT_INFO markers are
never selectable and ride along with every offer, so an administrator naming
only curve25519 does not turn off either extension."
  (let ((result (copy-list
                 (ssh-session-algorithm-list
                  session #'ssh-server-config-kex-algorithms
                  +ssh-kex-real-algorithms+))))
    (dolist (marker '("kex-strict-s-v00@openssh.com" "ext-info-s")
             result)
      (unless (member marker result :test #'string=)
        (setf result (append result (list marker)))))))

(defun ssh-server-host-key-algorithms-for (session)
  "The host key algorithms SESSION can present, in configured order."
  (ssh-server-host-key-algorithms
   (ssh-session-host-keys session)
   (ssh-session-setting session #'ssh-server-config-host-key-algorithms)
   (ssh-server-host-certificates (ssh-session-server session))))

(defun ssh-server-make-kexinit-payload (session)
  "A fresh server SSH_MSG_KEXINIT advertising SESSION's configured offers."
  (let* ((ciphers (ssh-session-algorithm-list
                   session #'ssh-server-config-ciphers +ssh-ciphers+))
         (macs (ssh-session-algorithm-list
                session #'ssh-server-config-macs +ssh-macs+))
         (writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-kexinit+)
    (ssh-write-octets writer (ssh-random-octets 16))
    (iter (for list in (list (ssh-server-kex-offer session)
                             (ssh-server-host-key-algorithms-for session)
                             ciphers ciphers
                             macs macs
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
               (remove-if #'ssh-kex-marker-p
                          (ssh-server-kex-offer session))
               (getf client-kexinit :kex)))
         (host-key (ssh-choose-algorithm
                    (ssh-server-host-key-algorithms-for session)
                    (getf client-kexinit :host-keys)))
         (ciphers (ssh-session-algorithm-list
                   session #'ssh-server-config-ciphers +ssh-ciphers+))
         (macs (ssh-session-algorithm-list
                session #'ssh-server-config-macs +ssh-macs+))
         (cipher-c2s (ssh-choose-algorithm ciphers
                                           (getf client-kexinit :ciphers-c2s)))
         (cipher-s2c (ssh-choose-algorithm ciphers
                                           (getf client-kexinit :ciphers-s2c)))
         (mac-c2s (ssh-choose-algorithm macs
                                        (getf client-kexinit :macs-c2s)))
         (mac-s2c (ssh-choose-algorithm macs
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
         (host-key nil)
         (host-key-blob nil)
         (private nil)
         (server-public nil)
         (shared nil)
         (hash nil)
         (signature nil))
    (unless (ssh-session-negotiated session)
      (error 'ssh-protocol-error :detail "ECDH_INIT before KEXINIT"))
    (when algorithm
      (multiple-value-setq (host-key host-key-blob)
        (ssh-server-host-key-presentation
         (ssh-session-host-keys session)
         (ssh-server-host-certificates (ssh-session-server session))
         algorithm)))
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
                host-key-blob
                client-public server-public shared)
          signature (ssh-server-host-key-signature host-key algorithm hash))
    (setf (ssh-session-session-id session)
          (or (ssh-session-session-id session) hash)
          (ssh-session-ephemeral-private session) private
          (ssh-session-ephemeral-public session) server-public
          (ssh-session-host-key-blob session) host-key-blob
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

(defun ssh-server-ext-info-payload ()
  "The EXT_INFO payload naming the public-key signatures this server accepts.

RFC 8308 sends EXT_INFO right after the first NEWKEYS, when the client
asked for it with ext-info-c.  Without server-sig-algs an OpenSSH client
refuses to try an RSA key (\"no mutual signature algorithm\"), because it
cannot know that rsa-sha2-512 is acceptable."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-ext-info+)
    (ssh-write-u32 writer 1)
    (ssh-write-text writer "server-sig-algs")
    (ssh-write-name-list writer +ssh-server-user-key-algorithms+)
    (ssh-writer-output writer)))

(defun ssh-server-send-ext-info (session)
  "Send EXT_INFO as a packet of its own."
  (ssh-session-send-payload session (ssh-server-ext-info-payload)))

(defun ssh-server-send-newkeys (session)
  "Send NEWKEYS, then switch our sending half to the negotiated keys.

EXT_INFO goes out in the same write as NEWKEYS, as OpenSSH's server does.
A client only learns that an RSA key may sign with rsa-sha2-512 from
server-sig-algs; libssh decides that before it next reads the socket, so an
announcement left in a second segment makes it fall back to SHA-1 ssh-rsa
and refuse the key without ever asking."
  (let* ((keys (ssh-session-derived-keys session))
         (cipher (ssh-session-cipher session))
         (ext-info (and (getf (ssh-session-negotiated session) :ext-info)
                        (not (ssh-session-rekey session))))
         (newkeys (ssh-encode-packet
                   (make-array 1 :element-type '(unsigned-byte 8)
                                 :initial-element +ssh-msg-newkeys+)
                   cipher)))
    (when (ssh-session-strict-kex session)
      (ssh-reset-send-sequence cipher))
    (ssh-install-keys cipher
                      :encrypt (getf keys :encrypt)
                      :encrypt-mac-key (getf keys :encrypt-mac-key)
                      :encrypt-mac (getf keys :encrypt-mac)
                      :aead (getf keys :aead))
    (setf (ssh-session-keys-sent session) t
          (ssh-session-kexinit-sent session) nil)
    (ssh-session-send-bytes
     session
     (if ext-info
         (ssh-concat newkeys
                     (ssh-encode-packet
                      (ssh-server-ext-info-payload) cipher))
         newkeys))
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
when the first USER AUTH REQUEST arrives, after the account name -- and with
it the Match blocks -- is finally known to the server."
  (let ((text (ssh-session-banner-text session)))
    (when text
      (let ((writer (ssh-writer)))
        (ssh-write-u8 writer +ssh-msg-userauth-banner+)
        (ssh-write-text writer text)
        ;; Language tag, unused, as in sshd.
        (ssh-write-text writer "")
        (ssh-session-send-payload session (ssh-writer-output writer))))))

(defun ssh-server-allowed-auth-methods (session)
  "The methods SESSION may try next, as sshd's authmethods_get reports.

An impossible AuthenticationMethods setting leaves no method, which makes
every attempt fail rather than quietly falling back to publickey."
  (let ((lists (ssh-session-auth-method-lists session)))
    (cond
      ((eq lists :impossible) '())
      ((null lists) +ssh-server-enabled-auth-methods+)
      (t (remove-duplicates (mapcar #'first lists) :test #'string=)))))

(defun ssh-server-auth-key-used-p (session key-blob)
  "Whether KEY-BLOB already completed a method on SESSION."
  (some (lambda (used)
          (ssh-octets= used key-blob))
        (ssh-session-auth-used-keys session)))

(defun ssh-server-record-auth-success (session key-blob)
  "Record KEY-BLOB as a completed method and add its ExposeAuthInfo line."
  (setf (ssh-session-auth-used-keys session)
        (cons key-blob (ssh-session-auth-used-keys session))
        (ssh-session-auth-info-lines session)
        (append (ssh-session-auth-info-lines session)
                (list (ssh-server-auth-info-line key-blob)))))

(defun ssh-server-send-auth-failure (session &key (count t) partial)
  "Refuse the current attempt and name the methods that may continue.

COUNT is false for sshd's exempt cases: the first \"none\" probe, an
unsigned publickey offer answered with PK_OK, and a method that completed
one list of AuthenticationMethods but not all of them.  PARTIAL sets the
RFC 4252 partial-success flag for that last case.  Reaching MaxAuthTries
sends DISCONNECT instead of another failure."
  (when count
    (incf (ssh-session-auth-failures session))
    (when (>= (ssh-session-auth-failures session)
              (or (ssh-session-setting
                   session #'ssh-server-config-max-auth-tries)
                  (ssh-server-max-auth-tries (ssh-session-server session))))
      (ssh-session-send-payload-and-close
       session
       (ssh-disconnect-payload "Too many authentication failures"
                               +ssh-disconnect-protocol-error+)
       :auth-failures)
      (return-from ssh-server-send-auth-failure nil)))
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-userauth-failure+)
    (ssh-write-name-list writer (ssh-server-allowed-auth-methods session))
    (ssh-write-boolean writer (and partial t))
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
  (and (ssh-session-user-key-algorithm-p session key-blob algorithm)
       (ssh-session-user-key-length-p session key-blob)
       (handler-case
           (multiple-value-bind (signature-algorithm signature-bytes)
               (ssh-parse-signature-blob signature)
             (declare (ignore signature-bytes))
             (and (string= signature-algorithm
                           (ssh-certificate-userauth-signature-algorithm
                            algorithm))
                  (ssh-public-key-signature-valid-p
                   key-blob signature
                   (ssh-server-signed-data session user algorithm key-blob))))
         (error () nil))))

(defun ssh-server-auth-method-succeeded
    (session user key-blob key-env authorization)
  "Record one successful publickey and either finish or ask for the next.

Without AuthenticationMethods this is the whole login.  With it, the method
is removed from the front of every remaining list; a list that becomes empty
finishes the login, and otherwise the client is told the method was a
partial success.  Options from all successful keys are merged, and a key
already used for a method is never accepted again."
  (let ((lists (ssh-session-auth-method-lists session)))
    (cond
      ((eq lists :impossible)
       (ssh-server-send-auth-failure session))
      ((null lists)
       (ssh-server-record-auth-success session key-blob)
       (ssh-server-complete-auth session user key-blob key-env authorization))
      ((not (some (lambda (list)
                    (and list (string= (first list) "publickey")))
                  lists))
       ;; No remaining list starts with this method; do not advance.
       (ssh-server-send-auth-failure session))
      (t
       (let* ((empty (ssh-certificate-authorization-options-empty))
              (merged (ssh-authorization-options-merge
                       (or (ssh-session-auth-merged-options session) empty)
                       (or authorization empty))))
         (unless merged
           ;; Inconsistent options, such as two different force-commands.
           (ssh-server-send-auth-failure session)
           (return-from ssh-server-auth-method-succeeded nil))
         (let ((remaining (mapcar #'rest lists)))
           (ssh-server-record-auth-success session key-blob)
           (setf (ssh-session-auth-merged-options session) merged
                 (ssh-session-auth-merged-key-env session)
                 (append (ssh-session-auth-merged-key-env session) key-env))
           (if (some #'null remaining)
               (ssh-server-complete-auth
                session user key-blob
                (ssh-session-auth-merged-key-env session)
                merged)
               (progn
                 (setf (ssh-session-auth-method-lists session) remaining)
                 (ssh-server-send-auth-failure
                  session :count nil :partial t)))))))))

(defun ssh-server-complete-auth (session user key-blob
                                 &optional key-env authorization)
  "Accept SESSION's authenticated user, then let the application run.

KEY-ENV holds the environment= assignments from the authorized_keys line
that admitted the key; the application applies them under
PermitUserEnvironment.  AUTHORIZATION holds that line's remaining options,
which the transport enforces for pty and forwarding requests."
  (setf (ssh-session-user session) user
        (ssh-session-authorized-key session) key-blob
        (ssh-session-key-env session) key-env
        (ssh-session-authorization session) authorization
        (ssh-session-authenticated session) t
        (ssh-session-phase session) :ready)
  (setf (ssh-session-login-grace-timer session)
        (ssh-session-cancel-timer (ssh-session-login-grace-timer session)))
  (ssh-server-send-auth-success session)
  (ssh-session-start-client-alive-timer session)
  (when (ssh-server-on-session (ssh-session-server session))
    (funcall (ssh-server-on-session (ssh-session-server session)) session))
  ;; sshd starts UnusedConnectionTimeout when authentication finishes, before
  ;; the client has had a chance to open a channel.
  (ssh-session-note-channel-change session))

(defun ssh-server-handle-signed-key (session user algorithm key-blob reader
                                    &key (count t))
  (let ((signature (ssh-read-string reader)))
    (if (ssh-server-verify-signature session user algorithm key-blob signature)
        (multiple-value-bind (authorized key-env authorization)
            (ssh-server-authorized-key-p
             (ssh-session-server session) user key-blob
             :address (ssh-session-remote-ip session)
             :session session)
          (if authorized
              (ssh-server-auth-method-succeeded session user key-blob
                                                key-env authorization)
              (ssh-server-send-auth-failure session :count count)))
        (ssh-server-send-auth-failure session :count count))))

(defun ssh-server-max-pubkey-ok (session)
  "SESSION's PubkeyAuthOptions max-pk-ok budget, defaulting to sshd's 6."
  (or (ssh-session-setting session #'ssh-server-config-max-pubkey-ok) 6))

(defun ssh-server-publickey-offer-counts-p (session)
  "Record a rejected unsigned publickey probe and say whether it counts.

The first MAX-PK-OK probes do not count against MaxAuthTries, so a client
can test keys without burning its authentication budget; later ones do."
  (incf (ssh-session-pk-ok-failures session))
  (> (ssh-session-pk-ok-failures session)
     (ssh-server-max-pubkey-ok session)))

(defun ssh-server-publickey-failure (session has-signature count)
  "Refuse a publickey attempt, applying the probe budget only to offers."
  (if has-signature
      (ssh-server-send-auth-failure session :count count)
      (ssh-server-send-auth-failure
       session :count (ssh-server-publickey-offer-counts-p session))))

(defun ssh-server-handle-publickey (session user algorithm key-blob reader
                                    has-signature &key (count t))
  "Handle one publickey attempt, signed or merely offered."
  (cond
    ;; No AuthenticationMethods list can finish here; refuse before doing
    ;; the authorization work, as sshd's authmethod_lookup does.
    ((eq (ssh-session-auth-method-lists session) :impossible)
     (ssh-server-publickey-failure session has-signature count))
    ;; sshd refuses a key that already completed a method, even its probe.
    ((ssh-server-auth-key-used-p session key-blob)
     (ssh-server-publickey-failure session has-signature count))
    ((and (ssh-session-user-key-algorithm-p session key-blob algorithm)
          (ssh-session-user-key-length-p session key-blob)
          (ssh-server-authorized-key-p
           (ssh-session-server session) user key-blob
           :address (ssh-session-remote-ip session)
           :session session))
     (if has-signature
         (ssh-server-handle-signed-key session user algorithm key-blob reader
                                       :count count)
         ;; An accepted offer is sshd's "partial" attempt: it may not count
         ;; against MaxAuthTries because no authentication was tried.
         (ssh-server-send-pk-ok session algorithm key-blob)))
    (t
     (ssh-server-publickey-failure session has-signature count))))

(defun ssh-server-user-permitted-p (session user)
  "Whether the application admits USER on SESSION.

The answer is cached per name: sshd decides this once when the name first
appears, and running a group lookup again on every retry would only repeat
the same answer.  The connection's Match blocks are resolved first, so the
application's answer and everything after it use the per-connection values."
  (ssh-session-resolve-config session user)
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
      ;; sshd resolves the connection's Match blocks when the account name is
      ;; first known, before it sends the Banner that they may choose.
      (ssh-session-resolve-config session user)
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
                     (ssh-session-permits-tcpip-forward-p
                      session bind-address bind-port)
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
