(in-package #:cl-pnet-ssh)

;;;; The server's transport state machine: version exchange, KEX, NEWKEYS,
;;;; user authentication, then channel dispatch.  It shares every primitive
;;;; with the client; only the order of messages and the signing side differ.

(defparameter +ssh-server-kex-algorithms+
  '("mlkem768x25519-sha256"
    "curve25519-sha256"
    "curve25519-sha256@libssh.org"
    "ecdh-sha2-nistp256"
    "ecdh-sha2-nistp384"
    "ecdh-sha2-nistp521"
    ;; Markers, never selected: strict KEX and RFC 8308 extensions.
    "kex-strict-s-v00@openssh.com"
    "ext-info-s")
  "The server's default KEX offers.

The markers are negotiation signals, not algorithms.  mlkem768nistp256 is
implemented but, as in OpenSSH, not offered unless KexAlgorithms names it.")

(defun ssh-server-kex-offer (session)
  "The KEX list SESSION advertises, with the server markers appended.

KexAlgorithms chooses the methods; the strict-KEX and EXT_INFO markers are
never selectable and ride along with every offer, so an administrator naming
only curve25519 does not turn off either extension."
  (let ((result (copy-list
                 (ssh-session-algorithm-list
                  session #'ssh-server-config-kex-algorithms
                  +ssh-kex-default-algorithms+))))
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

(defun ssh-server-compression-offer (session)
  "The compression methods SESSION advertises.

sshd offers \"none,zlib@openssh.com\" by default and only \"none\" when
Compression is off.  The client's order decides, so a server that keeps the
default still lets a -C client turn compression on."
  (if (eq (ssh-session-setting session #'ssh-server-config-compression) :no)
      '("none")
      +ssh-compressions+))

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
                             (ssh-server-compression-offer session)
                             (ssh-server-compression-offer session)
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
              (let ((cipher (ssh-session-cipher session)))
                (when cipher
                  (incf (ssh-session-received-packets session))
                  (incf (ssh-session-received-blocks session)
                        (floor (ssh-packet-counted-length
                                consumed cipher :receive)
                               (ssh-cipher-state-block-size cipher)))))
              (ssh-server-handle-payload session payload)
              (ssh-session-maybe-rekey session))))
    (error (condition) (ssh-session-fail session condition))))

(defun ssh-server-receive (session data)
  "The event loop has DATA for SESSION, or NIL at the end of the connection."
  (unless (ssh-session-closed-p session)
    (let ((*ssh-log-enabled* (ssh-session-log-enabled-p session)))
      (if (null data)
          (ssh-session-finish session :peer-closed :close)
          (progn
            (ssh-session-note-input session)
            (ssh-session-buffer-append session data)
            (ssh-server-advance session))))))

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
      ((= type +ssh-msg-ping+)
       (ssh-server-handle-ping session payload))
      ((= type +ssh-msg-pong+)
       ;; A PONG answers a probe this server did not send; accepting it keeps
       ;; the transport code tolerant of the other side's chaff.
       (ssh-server-read-pong payload))
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
      ((= type +ssh-msg-userauth-info-response+)
       (ssh-server-handle-info-response session payload))
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

(defun ssh-server-handle-ping (session payload)
  "Answer a PING with a PONG carrying the same data.

As in OpenSSH's transport code, a PING is ignored before authentication and
while key exchange is in progress, so it can never answer for KEX traffic."
  (let* ((reader (ssh-make-reader payload))
         (type (ssh-read-u8 reader))
         (data (ssh-read-string reader)))
    (declare (ignore type))
    (when (and (ssh-session-authenticated session)
               (not (eq (ssh-session-phase session) :kex)))
      (ssh-session-send-payload session (ssh-make-pong-payload data)))))

(defun ssh-server-read-pong (payload)
  "Read a peer PONG's echoed data and discard it."
  (let ((reader (ssh-make-reader payload)))
    (ssh-read-u8 reader)
    (ssh-read-string reader)
    nil))

;;; ---- Key exchange ----

(defun ssh-server-negotiate (session client-kexinit)
  "Choose algorithms from CLIENT-KEXINIT for the server role.

The host key offer is built from SESSION's loaded keys, so every algorithm
advertised can be signed with.  Each choice follows RFC 4253: the first
method on the client's list that the server also offers.  Using the server's
own order here would let the two sides disagree when their preferences
differ, which compression exposes immediately."
  (let* ((kex-offer (remove-if #'ssh-kex-marker-p
                               (ssh-server-kex-offer session)))
         (host-key-offer (ssh-server-host-key-algorithms-for session))
         (ciphers (ssh-session-algorithm-list
                   session #'ssh-server-config-ciphers +ssh-ciphers+))
         (macs (ssh-session-algorithm-list
                session #'ssh-server-config-macs +ssh-macs+))
         (compressions (ssh-server-compression-offer session))
         (kex (ssh-choose-algorithm
               (getf client-kexinit :kex) kex-offer))
         (host-key (ssh-choose-algorithm
                    (getf client-kexinit :host-keys) host-key-offer))
         (cipher-c2s (ssh-choose-algorithm
                      (getf client-kexinit :ciphers-c2s) ciphers))
         (cipher-s2c (ssh-choose-algorithm
                      (getf client-kexinit :ciphers-s2c) ciphers))
         (mac-c2s (ssh-choose-algorithm
                   (getf client-kexinit :macs-c2s) macs))
         (mac-s2c (ssh-choose-algorithm
                   (getf client-kexinit :macs-s2c) macs))
         (compression-c2s (ssh-choose-algorithm
                           (getf client-kexinit :compressions-c2s)
                           compressions))
         (compression-s2c (ssh-choose-algorithm
                           (getf client-kexinit :compressions-s2c)
                           compressions)))
    (unless (and kex host-key cipher-c2s cipher-s2c mac-c2s mac-s2c
                 compression-c2s compression-s2c)
      (error 'ssh-protocol-error
             :detail "no common algorithm for the server"))
    (list :kex kex :host-key host-key
          :cipher-c2s cipher-c2s :cipher-s2c cipher-s2c
          :mac-c2s mac-c2s :mac-s2c mac-s2c
          :compression-c2s compression-c2s
          :compression-s2c compression-s2c
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

(defun ssh-server-finish-kex (session signature)
  "Derive keys from SESSION's stored KEX state and send the reply."
  (unless (ssh-session-closed-p session)
    (let* ((kex (getf (ssh-session-negotiated session) :kex))
           (shared (ssh-session-kex-shared session))
           (hash (ssh-session-kex-hash session)))
      (setf (ssh-session-derived-keys session)
            (ssh-session-keys (ssh-session-negotiated session) shared hash
                              (ssh-session-session-id session) :server t
                              :string-shared
                              (ssh-mlkem768-hybrid-p kex)
                              :digest (ssh-kex-digest kex))
            (ssh-session-kex-shared session) nil
            (ssh-session-kex-hash session) nil
            (ssh-session-kex-signature-pending session) nil)
      (ssh-server-send-kex-reply session
                                 (ssh-session-ephemeral-public session)
                                 signature)
      (ssh-server-send-newkeys session))))

(defun ssh-server-handle-kex-init (session payload)
  "Answer the client's key-exchange offer: host key, ephemeral key, signature.

A private host key signs now.  An agent-backed key sends the sign request
and returns; the agent's callback finishes the KEX."
  (let* ((reader (ssh-make-reader payload))
         (client-public (progn (ssh-read-u8 reader) (ssh-read-string reader)))
         (algorithm (getf (ssh-session-negotiated session) :host-key))
         (host-key nil)
         (host-key-blob nil)
         (private nil)
         (server-public nil)
         (shared nil)
         (hash nil))
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
    (let ((kex (getf (ssh-session-negotiated session) :kex)))
      (cond
        ((ssh-mlkem768-hybrid-p kex)
         (multiple-value-setq (server-public shared)
           (ssh-mlkem768-hybrid-server-shared kex client-public)))
        ((ssh-ecdh-kex-p kex)
         (multiple-value-setq (private server-public) (ssh-ecdh-keypair kex))
         (setf shared (ssh-ecdh-shared private client-public kex)))
        (t
         (multiple-value-setq (private server-public)
           (ssh-curve25519-keypair))
         (setf shared (ssh-curve25519-shared private client-public))))
      (setf hash (ssh-exchange-hash
                  (ssh-session-client-version session)
                  (ssh-session-server-version session)
                  (ssh-session-client-kexinit session)
                  (ssh-session-server-kexinit session)
                  host-key-blob
                  client-public server-public shared
                  :string-shared (ssh-mlkem768-hybrid-p kex)
                  :digest (ssh-kex-digest kex))))
    (setf (ssh-session-session-id session)
          (or (ssh-session-session-id session) hash)
          (ssh-session-ephemeral-private session) private
          (ssh-session-ephemeral-public session) server-public
          (ssh-session-host-key-blob session) host-key-blob
          (ssh-session-kex-shared session) shared
          (ssh-session-kex-hash session) hash)
    (if (ssh-agent-host-key-p host-key)
        (progn
          (setf (ssh-session-kex-signature-pending session) t)
          (ssh-agent-sign
           (ssh-public-key-blob-of host-key)
           hash
           :path (ssh-server-host-key-agent (ssh-session-server session))
           :flags (ssh-agent-host-key-signature-flags algorithm)
           :on-signature
           (lambda (signature)
             (when (ssh-session-kex-signature-pending session)
               (ssh-server-finish-kex session signature)))
           :on-error
           (lambda (condition)
             (when (ssh-session-kex-signature-pending session)
               (setf (ssh-session-kex-signature-pending session) nil)
               (ssh-session-fail session condition)))))
        (ssh-server-finish-kex
         session
         (ssh-server-host-key-signature host-key algorithm hash)))))

(defun ssh-server-send-kex-reply (session server-public signature)
  "Send KEX_ECDH_REPLY: our host key, ephemeral key and signature."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-kex-ecdh-reply+)
    (ssh-write-string writer (ssh-session-host-key-blob session))
    (ssh-write-string writer server-public)
    (ssh-write-string writer signature)
    (ssh-session-send-payload session (ssh-writer-output writer))))

(defun ssh-server-ext-info-payload ()
  "The EXT_INFO payload naming the extensions this server supports.

RFC 8308 sends EXT_INFO right after the first NEWKEYS, when the client
asked for it with ext-info-c.  Without server-sig-algs an OpenSSH client
refuses to try an RSA key (\"no mutual signature algorithm\"), because it
cannot know that rsa-sha2-512 is acceptable.  ping@openssh.com version 0
tells a 10.6 client it may send PING as chaff for ObscureKeystrokeTiming;
the server answers those PINGs with PONG.  agent-forward version 0 says the
server understands RFC 9987's agent-req and agent-connect names as well as
OpenSSH's auth-agent@openssh.com."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-ext-info+)
    (ssh-write-u32 writer 3)
    (ssh-write-text writer "server-sig-algs")
    (ssh-write-name-list writer +ssh-server-user-key-algorithms+)
    (ssh-write-text writer "ping@openssh.com")
    (ssh-write-text writer "0")
    (ssh-write-text writer "agent-forward")
    (ssh-write-text writer "0")
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
    ;; NEWKEYS itself went out under the old stream; EXT_INFO below belongs
    ;; to the new one, as it does in OpenSSH.
    (ssh-install-send-compression
     cipher
     (getf (ssh-session-negotiated session) :compression-s2c)
     :after-authentication (ssh-session-after-authentication session))
    (setf (ssh-session-keys-sent session) t
          (ssh-session-kexinit-sent session) nil
          ;; OpenSSH resets its send counters when the new keys are
          ;; installed, so a rekeyed session starts a fresh volume budget.
          (ssh-session-sent-packets session) 0
          (ssh-session-sent-blocks session) 0
          (ssh-session-rekey-time session) (ssh-session-now))
    (ssh-session-send-bytes
     session
     (if ext-info
         (ssh-concat newkeys
                     (ssh-encode-packet
                      (ssh-server-ext-info-payload) cipher))
         newkeys))
    (when (ssh-session-rekey session)
      (ssh-log "rekey complete; resuming queued packets")
      (ssh-session-flush-outgoing session))
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
    (ssh-install-receive-compression
     cipher
     (getf (ssh-session-negotiated session) :compression-c2s)
     :after-authentication (ssh-session-after-authentication session))
    (setf (ssh-session-keys-received session) t
          (ssh-session-received-packets session) 0
          (ssh-session-received-blocks session) 0)
    (ssh-server-maybe-finish-kex session)))

(defun ssh-server-maybe-finish-kex (session)
  "Once both NEWKEYS have crossed, move on to authentication or the session."
  (when (and (ssh-session-keys-sent session)
             (ssh-session-keys-received session)
             (eq (ssh-session-phase session) :kex))
    (let ((rekey (ssh-session-rekey session)))
      (setf (ssh-session-phase session)
            (if rekey :ready :auth)
            (ssh-session-rekey session) nil
            (ssh-session-keys-sent session) nil
            (ssh-session-keys-received session) nil)
      (when rekey
        (ssh-session-schedule-rekey-timer session)))))

;;; ---- Rekeying ----
;;;
;;; The server enforces its own RekeyLimit and may start the exchange, as
;;; sshd's packet layer does.  It holds non-key-exchange packets until its
;;; NEWKEYS has been sent.

(defun ssh-session-kex-message-p (type)
  "Whether packet TYPE may travel during a key exchange, as OpenSSH decides."
  (and (<= +ssh-kex-message-min+ type +ssh-kex-message-max+)
       (not (member type (list +ssh-msg-service-request+
                               +ssh-msg-service-accept+
                               +ssh-msg-ext-info+)))))

(defun ssh-session-rekeying-p (session)
  "Whether SESSION must hold application packets for the keys being installed."
  (and (ssh-session-rekey session)
       (eq (ssh-session-phase session) :kex)
       (not (ssh-session-keys-sent session))))

(defun ssh-session-rekey-limits (session)
  "SESSION's RekeyLimit volume and interval, defaulting both to zero."
  (let ((config (ssh-session-effective-config session)))
    (values (or (and config (ssh-server-config-rekey-limit config)) 0)
            (or (and config (ssh-server-config-rekey-interval config)) 0))))

(defun ssh-session-rekey-hard-max-blocks (block-size)
  "The cipher's absolute block limit from RFC 4344 and OpenSSH's packet.c."
  (if (>= block-size 16)
      (ash 1 (* block-size 2))
      (floor (ash 1 30) block-size)))

(defun ssh-session-rekey-max-blocks (session)
  "SESSION's block budget for the current keys."
  (multiple-value-bind (limit interval)
      (ssh-session-rekey-limits session)
    (declare (ignore interval))
    (let* ((block-size (ssh-cipher-state-block-size (ssh-session-cipher session)))
           (hard (ssh-session-rekey-hard-max-blocks block-size)))
      (if (and (integerp limit) (plusp limit))
          (min hard (floor limit block-size))
          hard))))

(defun ssh-session-rekey-interval (session)
  "SESSION's RekeyLimit time value in seconds, or zero."
  (nth-value 1 (ssh-session-rekey-limits session)))

(defun ssh-session-need-rekey-p (session &optional (outbound-payload-length 0))
  "Whether SESSION must start a rekey before sending an outbound packet."
  (and (eq (ssh-session-phase session) :ready)
       (ssh-session-after-authentication session)
       ;; Our NEWKEYS has gone out but the peer's has not arrived: wait for
       ;; the open exchange before starting another one.
       (not (and (ssh-session-keys-sent session)
                 (not (ssh-session-keys-received session))))
       (not (ssh-session-closed-p session))
       (not (and (zerop (ssh-session-sent-packets session))
                 (zerop (ssh-session-received-packets session))))
       (let ((interval (ssh-session-rekey-interval session))
             (time (ssh-session-rekey-time session)))
         (or (and (integerp interval) (plusp interval) time
                  (<= (+ time interval) (ssh-session-now)))
             (let* ((cipher (ssh-session-cipher session))
                    (block-size (ssh-cipher-state-block-size cipher))
                    (max-blocks (ssh-session-rekey-max-blocks session))
                    (out-blocks (if (plusp outbound-payload-length)
                                    (* block-size
                                       (ceiling (+ 5 outbound-payload-length)
                                                block-size))
                                    0)))
               (or (> (ssh-session-sent-packets session) (ash 1 31))
                   (> (ssh-session-received-packets session) (ash 1 31))
                   (and (plusp max-blocks)
                        (or (> (+ (ssh-session-sent-blocks session) out-blocks)
                               max-blocks)
                            (> (ssh-session-received-blocks session)
                               max-blocks)))))))))

(defun ssh-session-start-rekey (session)
  "Begin a server-initiated key exchange, as OpenSSH's kex_start_rekex."
  (when (and (eq (ssh-session-phase session) :ready)
             (not (ssh-session-closed-p session)))
    (setf (ssh-session-rekey session) t
          (ssh-session-phase session) :kex)
    (ssh-log "rekeying after ~D blocks, ~D received"
             (ssh-session-sent-blocks session)
             (ssh-session-received-blocks session))
    (ssh-server-send-kexinit session)
    t))

(defun ssh-session-flush-outgoing (session)
  "Send the payloads held during a rekey, in their original order."
  (let ((queue (ssh-session-outgoing-queue session)))
    (setf (ssh-session-outgoing-queue session) nil)
    (dolist (payload queue)
      (unless (ssh-session-closed-p session)
        (ssh-session-send-payload session payload)))))

(defun ssh-session-maybe-rekey (session)
  "Start a rekey now when SESSION's volume or time limit has been reached."
  (when (ssh-session-need-rekey-p session)
    (ssh-session-start-rekey session)))

(defun ssh-session-schedule-rekey-timer (session)
  "Arm the timer for RekeyLimit's time value, if it is set."
  (setf (ssh-session-rekey-timer session)
        (ssh-session-cancel-timer (ssh-session-rekey-timer session)))
  (let ((interval (ssh-session-rekey-interval session)))
    (when (and (integerp interval) (plusp interval)
               (eq (ssh-session-phase session) :ready)
               (not (ssh-session-closed-p session)))
      (let* ((now (ssh-session-now))
             (base (or (ssh-session-rekey-time session) now))
             (delay (- (+ base interval) now)))
        (setf (ssh-session-rekey-timer session)
              (cl-pnet:timer-start
               (max 1 delay) 0
               (lambda ()
                 (setf (ssh-session-rekey-timer session) nil)
                 (when (and (not (ssh-session-closed-p session))
                            (eq (ssh-session-phase session) :ready))
                   (when (ssh-session-need-rekey-p session)
                     (ssh-session-start-rekey session))))))))))

(defun ssh-session-start-rekey-timer (session)
  "Start time-based rekeying once authentication has completed."
  (ssh-session-schedule-rekey-timer session))

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

(defun ssh-server-send-banner-text (session text)
  "Send TEXT to SESSION as a USERAUTH_BANNER, or do nothing when empty."
  (when (and text (plusp (length text)))
    (let ((writer (ssh-writer)))
      (ssh-write-u8 writer +ssh-msg-userauth-banner+)
      (ssh-write-text writer text)
      ;; Language tag, unused, as in sshd.
      (ssh-write-text writer "")
      (ssh-session-send-payload session (ssh-writer-output writer)))))

(defun ssh-server-send-banner (session)
  "Send the configured Banner before the first authentication reply.

RFC 4252 allows banners at any point during authentication; sshd sends one
when the first USER AUTH REQUEST arrives, after the account name -- and with
it the Match blocks -- is finally known to the server."
  (ssh-server-send-banner-text session (ssh-session-banner-text session)))

(defun ssh-server-allowed-auth-methods (session)
  "The methods SESSION may try next, as sshd's authmethods_get reports.

An impossible AuthenticationMethods setting leaves no method, which makes
every attempt fail rather than quietly falling back to publickey."
  (let ((lists (ssh-session-auth-method-lists session)))
    (cond
      ((eq lists :impossible) '())
      ((null lists) (ssh-server-enabled-auth-methods session))
      (t (remove-duplicates (mapcar #'first lists) :test #'string=)))))

(defun ssh-server-auth-key-used-p (session key-blob)
  "Whether KEY-BLOB already completed a method on SESSION."
  (some (lambda (used)
          (ssh-octets= used key-blob))
        (ssh-session-auth-used-keys session)))

(defun ssh-server-record-auth-success (session method key-blob)
  "Record METHOD with KEY-BLOB and add its ExposeAuthInfo line.

Password and keyboard-interactive carry no key, so they neither consume a key
nor contribute an auth-info line."
  (when key-blob
    (push key-blob (ssh-session-auth-used-keys session)))
  (let ((line (ssh-server-auth-info-line method key-blob)))
    (when line
      (setf (ssh-session-auth-info-lines session)
            (append (ssh-session-auth-info-lines session) (list line))))))

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
    (session method user key-blob key-env authorization)
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
       (ssh-server-record-auth-success session method key-blob)
       (ssh-server-complete-auth session user key-blob key-env authorization))
      ((not (some (lambda (list)
                    (and list (string= (first list) method)))
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
           (ssh-server-record-auth-success session method key-blob)
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
which the transport enforces for pty and forwarding requests.  An
AUTHORIZE-LOGIN hook runs before the success reply; refusing there closes the
connection the way sshd's PAM account failure does."
  (let ((hook (ssh-server-authorize-login (ssh-session-server session))))
    (when (and hook (not (funcall hook session user)))
      (ssh-session-send-payload-and-close
       session (ssh-disconnect-payload "Access denied") :close)
      (return-from ssh-server-complete-auth nil)))
  ;; sshd sends the login messages a pre-success hook collected -- PAM's
  ;; account-management text -- as a banner before USERAUTH_SUCCESS.
  (let ((messages (ssh-session-login-messages session)))
    (when messages
      (ssh-server-send-banner-text
       session
       (with-output-to-string (stream)
         (dolist (message (nreverse messages))
           (write-string message stream)
           (terpri stream))))))
  (setf (ssh-session-user session) user
        (ssh-session-authorized-key session) key-blob
        (ssh-session-key-env session) key-env
        (ssh-session-authorization session) authorization
        (ssh-session-authenticated session) t
        (ssh-session-phase session) :ready)
  (setf (ssh-session-login-grace-timer session)
        (ssh-session-cancel-timer (ssh-session-login-grace-timer session)))
  (ssh-server-send-auth-success session)
  (setf (ssh-session-after-authentication session) t)
  ;; zlib@openssh.com starts with the next packet in each direction; the
  ;; USERAUTH_SUCCESS just sent was the last uncompressed one.
  (ssh-enable-delayed-compression (ssh-session-cipher session))
  (ssh-session-start-client-alive-timer session)
  (ssh-session-start-rekey-timer session)
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
              (ssh-server-auth-method-succeeded
               session "publickey" user key-blob key-env authorization)
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

(defun ssh-server-hostbased-signed-data
    (session user algorithm key-blob chost cuser)
  "The octets a hostbased request signs: session id then the request."
  (let ((writer (ssh-writer)))
    (ssh-write-string writer (ssh-session-session-id session))
    (ssh-write-u8 writer +ssh-msg-userauth-request+)
    (ssh-write-text writer user)
    (ssh-write-text writer "ssh-connection")
    (ssh-write-text writer "hostbased")
    (ssh-write-text writer algorithm)
    (ssh-write-string writer key-blob)
    (ssh-write-text writer chost)
    (ssh-write-text writer cuser)
    (ssh-writer-output writer)))

(defun ssh-server-hostbased-signature-valid-p
    (session user algorithm key-blob chost cuser signature)
  "Whether SIGNATURE covers SESSION's hostbased request."
  (handler-case
      (multiple-value-bind (signature-algorithm signature-bytes)
          (ssh-parse-signature-blob signature)
        (declare (ignore signature-bytes))
        (and (string= signature-algorithm
                      (ssh-certificate-userauth-signature-algorithm algorithm))
             (ssh-public-key-signature-valid-p
              (ssh-key-plain-blob key-blob) signature
              (ssh-server-hostbased-signed-data
               session user algorithm key-blob chost cuser))))
    (error () nil)))

(defun ssh-server-handle-hostbased (session user reader &key (count t))
  "Handle one hostbased authentication attempt."
  (let* ((algorithm (ssh-read-text reader))
         (key-blob (ssh-read-string reader))
         (chost (ssh-read-text reader))
         (cuser (ssh-read-text reader))
         (signature (ssh-read-string reader))
         (hook (ssh-server-hostbased-key-allowed
                (ssh-session-server session)))
         (algorithms
           (or (ssh-session-setting
                session
                #'ssh-server-config-hostbased-accepted-algorithms)
               +ssh-server-host-key-preference+))
         (enabled
           (eq (ssh-session-setting
                session #'ssh-server-config-hostbased-authentication)
               :yes)))
    (if (and enabled
             (member algorithm algorithms :test #'string=)
             (ssh-session-user-key-length-p session key-blob)
             (not (ssh-server-revoked-key-p
                   (ssh-session-server session) session key-blob))
             hook
             (ssh-server-hostbased-signature-valid-p
              session user algorithm key-blob chost cuser signature)
             (funcall hook session user cuser chost key-blob))
        (ssh-server-auth-method-succeeded
         session "hostbased" user key-blob nil nil)
        (ssh-server-send-auth-failure session :count count))))

(defun ssh-server-handle-password (session user reader &key (count t))
  "Handle one password authentication attempt.

The change-password flag is refused: this server has no password-change
backend, and silently treating it as a login would be worse than a failure."
  (let ((change (ssh-read-boolean reader))
        (password (ssh-read-text reader))
        (hook (ssh-server-authorize-password (ssh-session-server session))))
    (if (and hook
             (not change)
             (funcall hook session user password))
        (ssh-server-auth-method-succeeded
         session "password" user nil nil nil)
        (ssh-server-send-auth-failure session :count count))))

(defun ssh-server-send-info-request (session name instruction prompts)
  "Send one keyboard-interactive INFO_REQUEST.

PROMPTS is a list of (TEXT ECHO-P); each prompt's echo flag travels in the
request so the client's terminal can hide a password."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-userauth-info-request+)
    (ssh-write-text writer (or name ""))
    (ssh-write-text writer (or instruction ""))
    (ssh-write-text writer "")
    (ssh-write-u32 writer (length prompts))
    (dolist (prompt prompts)
      (ssh-write-text writer (first prompt))
      (ssh-write-boolean writer (second prompt)))
    (ssh-session-send-payload session (ssh-writer-output writer))))

(defun ssh-server-keyboard-interactive-step (session responses)
  "Call the keyboard-interactive hook with RESPONSES and act on its answer."
  (let* ((server (ssh-session-server session))
         (hook (ssh-server-authorize-keyboard-interactive server))
         (user (ssh-session-kbd-interactive-user session))
         (request (list :responses responses)))
    (setf (ssh-session-kbd-interactive-pending session) nil)
    (cond
      ((null hook)
       (ssh-server-send-auth-failure session))
      (t
       (let ((result (funcall hook session user request)))
         (cond
           ((eq result :success)
            (ssh-server-auth-method-succeeded
             session "keyboard-interactive" user nil nil nil))
           ((or (null result) (eq result :failure))
            (ssh-server-send-auth-failure session))
           ((eq result t)
            (ssh-server-auth-method-succeeded
             session "keyboard-interactive" user nil nil nil))
           (t
            (let ((prompts (getf result :prompts))
                  (name (getf result :name))
                  (instruction (getf result :instruction)))
              ;; A round may carry text and no prompts, which sshd sends for
              ;; PAM_TEXT_INFO/PAM_ERROR_MSG; the client answers with an empty
              ;; INFO_RESPONSE.  A round with nothing at all would spin.
              (unless (or prompts
                          (and name (plusp (length name)))
                          (and instruction (plusp (length instruction))))
                (error 'ssh-protocol-error
                       :detail "keyboard-interactive hook returned empty round"))
              (setf (ssh-session-kbd-interactive-pending session) t)
              (ssh-server-send-info-request
               session name instruction prompts)))))))))

(defun ssh-server-handle-keyboard-interactive
    (session user reader &key (count t))
  "Start a keyboard-interactive exchange, or refuse it when no hook exists."
  (let ((language (ssh-read-text reader))
        (submethods (ssh-read-text reader))
        (hook (ssh-server-authorize-keyboard-interactive
               (ssh-session-server session))))
    (declare (ignore language submethods))
    (cond
      ((null hook)
       (ssh-server-send-auth-failure session :count count))
      (t
       (setf (ssh-session-kbd-interactive-user session) user
             (ssh-session-kbd-interactive-pending session) t)
       (ssh-server-keyboard-interactive-step session '())))))

(defun ssh-server-handle-info-response (session payload)
  "Feed one keyboard-interactive INFO_RESPONSE back to the hook."
  (unless (ssh-session-kbd-interactive-pending session)
    (error 'ssh-protocol-error
           :detail "USERAUTH_INFO_RESPONSE without an INFO_REQUEST"))
  (let* ((reader (ssh-make-reader payload))
         (type (ssh-read-u8 reader))
         (count (ssh-read-u32 reader))
         (responses '()))
    (declare (ignore type))
    (when (>= count 1024)
      (error 'ssh-protocol-error
             :detail "USERAUTH_INFO_RESPONSE has too many answers"))
    (dotimes (index count)
      (declare (ignore index))
      (push (ssh-read-text reader) responses))
    (ssh-server-keyboard-interactive-step session (nreverse responses))))

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
                (unless allowed
                  (setf (ssh-session-invalid-user-p session) t))
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
    ;; RefuseConnection is checked once the account is known, before any
    ;; method runs, as sshd's monitor does after getpwnamallow.
    (when (eq (ssh-session-setting
               session #'ssh-server-config-refuse-connection)
              :yes)
      (setf (ssh-session-refused-p session) t)
      (ssh-session-send-payload-and-close
       session
       (ssh-disconnect-payload "administratively prohibited"
                               +ssh-disconnect-protocol-error+)
       :refused)
      (return-from ssh-server-handle-userauth-request nil))
    (incf (ssh-session-auth-attempts session))
    ;; A new USER AUTH REQUEST abandons any half-finished kbdint exchange.
    (setf (ssh-session-kbd-interactive-pending session) nil)
    (let ((count (ssh-server-auth-failure-counts-p
                  (ssh-session-auth-attempts session) method)))
      (cond
        ((not (string= service "ssh-connection"))
         (ssh-server-send-auth-failure session :count count))
        ((not (ssh-server-user-permitted-p session user))
         (ssh-server-send-auth-failure session :count count))
        ((and (member method '("password" "keyboard-interactive")
                      :test #'string=)
              (not (member method (ssh-server-allowed-auth-methods session)
                           :test #'string=)))
         (ssh-server-send-auth-failure session :count count))
        ((string= method "publickey")
         (let ((has-signature (ssh-read-boolean reader))
               (algorithm (ssh-read-text reader))
               (key-blob (ssh-read-string reader)))
           (ssh-server-handle-publickey session user algorithm key-blob reader
                                        has-signature :count count)))
        ((string= method "hostbased")
         (ssh-server-handle-hostbased session user reader :count count))
        ((string= method "password")
         (ssh-server-handle-password session user reader :count count))
        ((string= method "keyboard-interactive")
         (ssh-server-handle-keyboard-interactive session user reader
                                                 :count count))
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

(defun ssh-server-handle-streamlocal-forward (session reader want-reply)
  "Offer a streamlocal-forward@openssh.com request to the application."
  (let* ((path (ssh-read-text reader))
         (handler (ssh-server-on-streamlocal-forward
                   (ssh-session-server session)))
         (ok (and handler
                  (ssh-session-permits-streamlocal-forward-p session path)
                  (funcall handler session path))))
    (when want-reply
      (ssh-server-send-global-reply session (not (null ok))))))

(defun ssh-server-handle-cancel-streamlocal-forward (session reader want-reply)
  (let* ((path (ssh-read-text reader))
         (handler (ssh-server-on-cancel-streamlocal-forward
                   (ssh-session-server session)))
         (ok (and handler (funcall handler session path))))
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
      ((string= name "streamlocal-forward@openssh.com")
       (ssh-server-handle-streamlocal-forward session reader want-reply))
      ((string= name "cancel-streamlocal-forward@openssh.com")
       (ssh-server-handle-cancel-streamlocal-forward
        session reader want-reply))
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
