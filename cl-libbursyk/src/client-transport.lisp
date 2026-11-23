(in-package #:cl-pnet-ssh)

;;;; The client's transport state machine: version exchange, KEX, NEWKEYS,
;;;; userauth, then dispatch to channels. Everything runs from cl-pnet
;;;; callbacks, so no function here waits for the peer.

(defun ssh-client-compression-offer (client)
  "The compression methods CLIENT advertises, in its preference order."
  (if (ssh-client-compression client)
      +ssh-compressions-preferred+
      +ssh-compressions+))

(defun ssh-client-connected (client connection)
  "CLIENT's TCP connection is up: greet and offer our KEXINIT."
  (setf (ssh-client-connection client) connection
        (ssh-client-phase client) :version)
  ;; The session type is not known yet; the application may raise this to
  ;; the interactive value once it decides whether to request a pty.
  (ssh-client-set-ip-qos client nil)
  (unless (ssh-client-tcp-keep-alive client)
    (let ((fd (ssh-client-transport-fd client)))
      (when fd
        (cl-pnet-sockets:set-socket-option
         fd cl-pnet-sockets:+sol-socket+
         cl-pnet-sockets:+so-keepalive+ 0))))
  (ssh-client-send-bytes
   client
   (ssh-string-octets (concatenate 'string
                                   (ssh-client-version-string client)
                                   (string #\Return)
                                   (string #\Newline))))
  (let ((kexinit (ssh-make-kexinit-payload
                  :kex (ssh-client-kex-algorithms client)
                  :host-keys (ssh-client-host-key-algorithms client)
                  :ciphers (ssh-client-ciphers client)
                  :macs (ssh-client-macs client)
                  :compressions (ssh-client-compression-offer client))))
    (setf (ssh-client-client-kexinit client) kexinit
          (ssh-client-kexinit-sent client) t)
    (ssh-client-send-payload client kexinit)))

(defun ssh-client-read-version-line (client)
  "Consume one line of the version exchange.

Returns :VERSION when the peer line arrived, :BANNER for a pre-version
line, and NIL while the line is still incomplete."
  (let* ((buffer (ssh-client-incoming client))
         (newline (position 10 buffer)))
    (when newline
      (let ((line (string-right-trim
                   '(#\Return)
                   (map 'string #'code-char (subseq buffer 0 newline)))))
        (ssh-client-buffer-consume client (1+ newline))
        (if (and (>= (length line) 4) (string= (subseq line 0 4) "SSH-"))
            (progn
              (setf (ssh-client-server-version client) line
                    (ssh-client-phase client) :kex)
              (ssh-log "remote version ~A" line)
              :version)
            (progn
              (ssh-log "remote banner ~A" line)
              :banner))))))

(defun ssh-client-advance (client)
  "Process every complete message in CLIENT's receive buffer."
  (handler-case
      (iter (while (not (ssh-client-closed-p client)))
        (if (eq (ssh-client-phase client) :version)
            (unless (ssh-client-read-version-line client) (leave))
            (multiple-value-bind (payload consumed)
                (ssh-decode-packet (ssh-client-incoming client)
                                   (ssh-client-cipher client))
              (when (eq payload :incomplete) (leave))
              (ssh-client-buffer-consume client consumed)
              (let ((cipher (ssh-client-cipher client)))
                (when cipher
                  (incf (ssh-client-received-packets client))
                  (incf (ssh-client-received-blocks client)
                        (floor (ssh-packet-counted-length
                                consumed cipher :receive)
                               (ssh-cipher-state-block-size cipher)))))
              (ssh-client-handle-payload client payload)
              (ssh-client-maybe-rekey client))))
    (error (condition)
      (ssh-client-fail client condition))))

(defun ssh-client-receive (client data)
  "The event loop has DATA for CLIENT, or NIL at the end of the connection."
  (unless (ssh-client-closed-p client)
    (if (null data)
        (ssh-client-finish client :peer-closed :close)
        (progn
          (ssh-client-buffer-append client data)
          (ssh-client-advance client)))))

(defun ssh-client-handle-payload (client payload)
  "Dispatch one decrypted protocol message."
  ;; Any traffic from the peer answers a keepalive, as OpenSSH counts it:
  ;; even an unrelated packet proves the server is still there.
  (setf (ssh-client-alive-misses client) 0)
  (when (ssh-client-ignore-next-kex-packet client)
    (setf (ssh-client-ignore-next-kex-packet client) nil)
    (when (<= +ssh-msg-kex-ecdh-init+ (aref payload 0)
              +ssh-msg-kex-ecdh-reply+)
      (return-from ssh-client-handle-payload nil)))
  (let ((type (aref payload 0)))
    (cond
      ((= type +ssh-msg-disconnect+)
       (ssh-client-handle-disconnect client payload))
      ((= type +ssh-msg-kexinit+)
       (ssh-client-handle-kexinit client payload))
      ((= type +ssh-msg-kex-ecdh-reply+)
       (ssh-client-handle-kex-reply client payload))
      ((= type +ssh-msg-newkeys+)
       (ssh-client-handle-newkeys client))
      ((= type +ssh-msg-ext-info+)
       (ssh-client-handle-ext-info client payload))
      ((= type +ssh-msg-ping+)
       (ssh-client-handle-ping client payload))
      ((= type +ssh-msg-pong+)
       ;; A reply to one of our chaff packets.  Its size proves only that the
       ;; server answered; chaff needs no accounting beyond that.
       (ssh-client-read-pong payload))
      ((= type +ssh-msg-service-accept+)
       (ssh-client-handle-service-accept client payload))
      ((= type +ssh-msg-userauth-banner+)
       (ssh-client-handle-banner client payload))
      ((= type +ssh-msg-userauth-info-request+)
       (ssh-client-handle-info-request client payload))
      ((= type +ssh-msg-userauth-success+)
       (ssh-client-handle-auth-success client))
      ((= type +ssh-msg-userauth-failure+)
       (ssh-client-handle-auth-failure client payload))
      ((= type +ssh-msg-global-request+)
       (ssh-client-handle-global-request client payload))
      ((= type +ssh-msg-request-success+)
       (ssh-client-handle-global-reply client payload t))
      ((= type +ssh-msg-request-failure+)
       (ssh-client-handle-global-reply client payload nil))
      ((<= +ssh-msg-channel-open+ type +ssh-msg-channel-failure+)
       (ssh-client-handle-channel-message client payload)))))

(defun ssh-client-handle-disconnect (client payload)
  "The peer is going away: report its reason."
  (let* ((reader (ssh-make-reader payload))
         (reason (progn (ssh-read-u8 reader) (ssh-read-u32 reader)))
         (description (ssh-read-text reader)))
    (declare (ignore reason))
    (ssh-client-fail
     client
     (make-condition 'ssh-connection-error
                     :detail (format nil "disconnected by peer: ~A" description)))))

(defun ssh-client-handle-ext-info (client payload)
  "Read RFC 8308 extensions and remember the ones this client can use.

Only ping@openssh.com matters here: version 0 lets the client send PING as
chaff while it hides keystroke timing.  A malformed announcement is a protocol
error rather than something to guess past, as OpenSSH treats it."
  (let ((reader (ssh-make-reader payload)))
    (ssh-read-u8 reader)
    (let ((count (ssh-read-u32 reader)))
      (when (>= count 1024)
        (error 'ssh-protocol-error
               :detail "EXT_INFO has too many extensions"))
      (dotimes (index count)
        (declare (ignore index))
        (let ((name (ssh-read-text reader))
              (value (ssh-read-string reader)))
          (cond
            ((string= name "ping@openssh.com")
             ;; Only version 0 is defined; a different value leaves the
             ;; extension unusable, as OpenSSH's version check does.
             (when (and (= (length value) 1) (= (aref value 0) 48))
               (setf (ssh-client-ping-supported client) t)
               (ssh-log "server supports ping@openssh.com")))
            ((string= name "agent-forward")
             ;; Version 0 selects RFC 9987's agent-req and agent-connect.
             (when (and (= (length value) 1) (= (aref value 0) 48))
               (setf (ssh-client-agent-forward-supported client) t)
               (ssh-log "server supports agent-forward")))
            (t
             (ssh-log "server extension ~A ignored" name))))))
    (unless (zerop (ssh-reader-remaining reader))
      (error 'ssh-protocol-error
             :detail "trailing bytes in EXT_INFO"))))

(defun ssh-client-handle-ping (client payload)
  "Answer a peer PING with a PONG once the session is past key exchange.

OpenSSH's transport code refuses to answer before authentication and while
rekeying, when a PING could be mistaken for key-exchange traffic."
  (let* ((reader (ssh-make-reader payload))
         (type (ssh-read-u8 reader))
         (data (ssh-read-string reader)))
    (declare (ignore type))
    (when (and (eq (ssh-client-phase client) :ready)
               (not (ssh-client-kexinit-sent client)))
      (ssh-client-send-payload client (ssh-make-pong-payload data)))))

(defun ssh-client-read-pong (payload)
  "Read a PONG's echoed data; chaff needs no further accounting."
  (let ((reader (ssh-make-reader payload)))
    (ssh-read-u8 reader)
    (ssh-read-string reader)
    (ssh-log "received chaff PONG")
    nil))

(defun ssh-client-send-chaff-packet (client)
  "Put one PING decoy on the wire, as EXT_INFO's ping extension allows."
  (ssh-client-send-payload client (ssh-make-ping-payload)))


;;; ---- Key exchange ----

(defun ssh-client-handle-kexinit (client payload)
  "Remember the peer's offer, choose, and start curve25519.

A server-initiated rekey starts here too. Then we have not sent a KEXINIT for
this exchange yet, and must do so before ECDH_INIT; the initial exchange sent
its KEXINIT when the connection came up."
  (unless (ssh-client-kexinit-sent client)
    (let ((kexinit (ssh-make-kexinit-payload
                    :kex (ssh-client-kex-algorithms client)
                    :host-keys (ssh-client-host-key-algorithms client)
                    :ciphers (ssh-client-ciphers client)
                    :macs (ssh-client-macs client)
                    :compressions (ssh-client-compression-offer client))))
      (setf (ssh-client-client-kexinit client) kexinit
            (ssh-client-kexinit-sent client) t)
      (ssh-client-send-payload client kexinit)))
  ;; A KEXINIT that arrives once channels are running is a rekey; hold
  ;; application packets until our NEWKEYS has crossed.
  (when (eq (ssh-client-phase client) :ready)
    (setf (ssh-client-rekeying client) t
          (ssh-client-keys-sent client) nil
          (ssh-client-keys-received client) nil))
  (let ((offers (ssh-parse-kexinit-payload payload)))
    (setf (ssh-client-server-kexinit client) payload
          (ssh-client-negotiated client)
          (ssh-negotiate offers
                         :kex-algorithms (ssh-client-kex-algorithms client)
                         :host-key-algorithms
                         (ssh-client-host-key-algorithms client)
                         :ciphers (ssh-client-ciphers client)
                         :macs (ssh-client-macs client)
                         :compressions (ssh-client-compression-offer client))
          ;; Strict KEX is negotiated once.  A rekey's KEXINIT leaves the
          ;; marker out, but the connection stays strict, so neither side may
          ;; forget it or the sequence resets at NEWKEYS stop matching.
          (ssh-client-strict-kex client)
          (or (ssh-client-strict-kex client)
              (getf (ssh-client-negotiated client) :strict))
          (ssh-client-ignore-next-kex-packet client)
          (getf (ssh-client-negotiated client) :guess-wrong))
    (let ((negotiated (ssh-client-negotiated client)))
      (ssh-log "key exchange ~A, host key ~A, cipher ~A, mac ~A, compression ~A/~A"
               (getf negotiated :kex)
               (getf negotiated :host-key)
               (getf negotiated :cipher-c2s)
               (getf negotiated :mac-c2s)
               (getf negotiated :compression-c2s)
               (getf negotiated :compression-s2c)))
    (ssh-client-send-kex-init client)))

(defun ssh-client-send-kex-init (client)
  "Start the negotiated key exchange with our ephemeral public key.

mlkem768x25519-sha256 sends the ML-KEM encapsulation key followed by the
X25519 public key; curve25519 sends the bare 32 octets."
  (let ((kex (getf (ssh-client-negotiated client) :kex)))
    (if (ssh-mlkem768x25519-p kex)
        (let ((state (ssh-mlkem768x25519-client-keypair)))
          (setf (ssh-client-ephemeral-private client) state
                (ssh-client-ephemeral-public client)
                (ssh-mlkem768x25519-state-public state))
          (let ((writer (ssh-writer)))
            (ssh-write-u8 writer +ssh-msg-kex-ecdh-init+)
            (ssh-write-string writer (ssh-client-ephemeral-public client))
            (ssh-client-send-payload client (ssh-writer-output writer))))
        (multiple-value-bind (private public) (ssh-curve25519-keypair)
          (setf (ssh-client-ephemeral-private client) private
                (ssh-client-ephemeral-public client) public)
          (let ((writer (ssh-writer)))
            (ssh-write-u8 writer +ssh-msg-kex-ecdh-init+)
            (ssh-write-string writer public)
            (ssh-client-send-payload client (ssh-writer-output writer)))))))

(defun ssh-client-handle-kex-reply (client payload)
  "Check the peer's host key and signature, derive keys, send NEWKEYS."
  (let* ((reader (ssh-make-reader payload))
         (host-key (progn (ssh-read-u8 reader) (ssh-read-string reader)))
         (server-public (ssh-read-string reader))
         (signature (ssh-read-string reader))
         (hybrid (ssh-mlkem768x25519-p
                  (getf (ssh-client-negotiated client) :kex)))
         (shared
           (if hybrid
               (ssh-mlkem768x25519-client-shared
                (ssh-client-ephemeral-private client) server-public)
               (ssh-curve25519-shared
                (ssh-client-ephemeral-private client) server-public)))
         (hash (ssh-exchange-hash
                (ssh-client-version-string client)
                (ssh-client-server-version client)
                (ssh-client-client-kexinit client)
                (ssh-client-server-kexinit client)
                host-key
                (ssh-client-ephemeral-public client)
                server-public
                shared
                :string-shared hybrid)))
    (ssh-verify-host-signature host-key signature hash)
    (ssh-client-verify-host-key client host-key)
    (setf (ssh-client-session-id client)
          (or (ssh-client-session-id client) hash)
          (ssh-client-host-key-blob client) host-key
          (ssh-client-derived-keys client)
          (ssh-session-keys (ssh-client-negotiated client)
                            shared hash (ssh-client-session-id client)
                            :string-shared hybrid))
    (ssh-client-send-newkeys client)))

(defun ssh-client-send-newkeys (client)
  "Send NEWKEYS, then switch our sending half to the negotiated keys."
  (let ((keys (ssh-client-derived-keys client)))
    (ssh-client-send-payload
     client (make-array 1 :element-type '(unsigned-byte 8)
                          :initial-element +ssh-msg-newkeys+))
    (when (ssh-client-strict-kex client)
      (ssh-reset-send-sequence (ssh-client-cipher client)))
    (ssh-install-keys (ssh-client-cipher client)
                      :encrypt (getf keys :encrypt)
                      :encrypt-mac-key (getf keys :encrypt-mac-key)
                      :encrypt-mac (getf keys :encrypt-mac)
                      :aead (getf keys :aead))
    (ssh-install-send-compression
     (ssh-client-cipher client)
     (getf (ssh-client-negotiated client) :compression-c2s)
     :after-authentication (ssh-client-after-authentication client))
    (setf (ssh-client-keys-sent client) t
          ;; OpenSSH resets its send counters when the new keys are
          ;; installed, so a rekeyed session starts a fresh volume budget.
          (ssh-client-sent-packets client) 0
          (ssh-client-sent-blocks client) 0
          (ssh-client-rekey-time client) (ssh-client-now))
    (let ((rekey (eq (ssh-client-phase client) :ready)))
      (setf (ssh-client-rekeying client) nil)
      (when rekey
        (ssh-log "rekey complete; resuming queued packets")
        (ssh-client-flush-outgoing client)
        (ssh-client-schedule-rekey-timer client)))
    (ssh-client-maybe-finish-kex client)))

(defun ssh-client-handle-newkeys (client)
  "The peer's NEWKEYS arrived: switch our receiving half, then proceed."
  (let ((keys (ssh-client-derived-keys client)))
    (when (ssh-client-strict-kex client)
      (ssh-reset-receive-sequence (ssh-client-cipher client)))
    (ssh-install-keys (ssh-client-cipher client)
                      :decrypt (getf keys :decrypt)
                      :decrypt-mac-key (getf keys :decrypt-mac-key)
                      :decrypt-mac (getf keys :decrypt-mac)
                      :aead (getf keys :aead))
    (ssh-install-receive-compression
     (ssh-client-cipher client)
     (getf (ssh-client-negotiated client) :compression-s2c)
     :after-authentication (ssh-client-after-authentication client))
    (setf (ssh-client-keys-received client) t
          (ssh-client-kexinit-sent client) nil
          (ssh-client-received-packets client) 0
          (ssh-client-received-blocks client) 0)
    (ssh-client-maybe-finish-kex client)))


(defun ssh-client-maybe-finish-kex (client)
  "Once both NEWKEYS have crossed, ask for the userauth service."
  (when (and (ssh-client-keys-sent client)
             (ssh-client-keys-received client)
             (eq (ssh-client-phase client) :kex))
    (setf (ssh-client-phase client) :auth
          (ssh-client-keys-sent client) nil
          (ssh-client-keys-received client) nil)
    (ssh-client-check-weak-crypto client)
    ;; ConnectTimeout keeps running through authentication, as it does in
    ;; OpenSSH: a server that completes the key exchange and then stalls
    ;; must not hang the caller forever.
    (ssh-client-send-service-request client)))

;;; ---- Rekeying ----
;;;
;;; OpenSSH rekeys after a cipher-dependent volume, after RekeyLimit bytes
;;; or seconds, or after 2^31 packets.  The client starts the exchange with
;;; KEXINIT and holds non-key-exchange packets until its NEWKEYS is sent.

(defun ssh-client-kex-message-p (type)
  "Whether packet TYPE may travel during a key exchange, as OpenSSH decides.

OpenSSH excludes SERVICE_REQUEST, SERVICE_ACCEPT and EXT_INFO from the
transport range, so those wait for the new keys even though their numbers
lie between DISCONNECT and the last key-exchange message."
  (and (<= +ssh-kex-message-min+ type +ssh-kex-message-max+)
       (not (member type (list +ssh-msg-service-request+
                               +ssh-msg-service-accept+
                               +ssh-msg-ext-info+)))))

(defun ssh-client-rekey-hard-max-blocks (block-size)
  "The cipher's absolute block limit from RFC 4344 and OpenSSH's packet.c."
  (if (>= block-size 16)
      (ash 1 (* block-size 2))
      (floor (ash 1 30) block-size)))

(defun ssh-client-rekey-max-blocks (client)
  "CLIENT's block budget for the current keys."
  (let* ((block-size (ssh-cipher-state-block-size (ssh-client-cipher client)))
         (hard (ssh-client-rekey-hard-max-blocks block-size))
         (limit (ssh-client-rekey-limit client)))
    (if (and (integerp limit) (plusp limit))
        (min hard (floor limit block-size))
        hard)))

(defun ssh-client-need-rekey-p (client &optional (outbound-payload-length 0))
  "Whether CLIENT must start a rekey before sending an outbound packet.

OUTBOUND-PAYLOAD-LENGTH is the payload about to go out, or zero when the
check follows a received packet.  OpenSSH permits one packet in or out
after every rekey, so an otherwise idle connection does not rekey."
  (and (eq (ssh-client-phase client) :ready)
       (ssh-client-after-authentication client)
       (not (ssh-client-rekeying client))
       ;; Our NEWKEYS has gone out but the peer's has not arrived: the
       ;; exchange is still open, so its old receive counters must not start
       ;; another one.  OpenSSH's kex state covers this window.
       (not (and (ssh-client-keys-sent client)
                 (not (ssh-client-keys-received client))))
       (not (ssh-client-closed-p client))
       (not (and (zerop (ssh-client-sent-packets client))
                 (zerop (ssh-client-received-packets client))))
       (let ((interval (ssh-client-rekey-interval client))
             (time (ssh-client-rekey-time client)))
         (or (and (integerp interval) (plusp interval) time
                  (<= (+ time interval) (ssh-client-now)))
             (let* ((cipher (ssh-client-cipher client))
                    (block-size (ssh-cipher-state-block-size cipher))
                    (max-blocks (ssh-client-rekey-max-blocks client))
                    (out-blocks (if (plusp outbound-payload-length)
                                    (* block-size
                                       (ceiling (+ 5 outbound-payload-length)
                                                block-size))
                                    0)))
               (or (> (ssh-client-sent-packets client) (ash 1 31))
                   (> (ssh-client-received-packets client) (ash 1 31))
                   (and (plusp max-blocks)
                        (or (> (+ (ssh-client-sent-blocks client) out-blocks)
                               max-blocks)
                            (> (ssh-client-received-blocks client)
                               max-blocks)))))))))

(defun ssh-client-start-rekey (client)
  "Begin a client-initiated key exchange, as OpenSSH's kex_start_rekex."
  (when (and (eq (ssh-client-phase client) :ready)
             (not (ssh-client-rekeying client))
             (not (ssh-client-closed-p client)))
    (let ((kexinit (ssh-make-kexinit-payload
                    :kex (ssh-client-kex-algorithms client)
                    :host-keys (ssh-client-host-key-algorithms client)
                    :ciphers (ssh-client-ciphers client)
                    :macs (ssh-client-macs client)
                    :compressions (ssh-client-compression-offer client))))
      (setf (ssh-client-rekeying client) t
            (ssh-client-client-kexinit client) kexinit
            (ssh-client-kexinit-sent client) t
            (ssh-client-keys-sent client) nil
            (ssh-client-keys-received client) nil)
      (ssh-log "rekeying after ~D blocks, ~D received"
               (ssh-client-sent-blocks client)
               (ssh-client-received-blocks client))
      (ssh-client-transmit-payload client kexinit))
    t))

(defun ssh-client-flush-outgoing (client)
  "Send the payloads held back during a rekey, in their original order.

A payload that would itself exceed the fresh limit queues again and starts
another exchange, exactly as OpenSSH's queue drain does."
  (let ((queue (ssh-client-outgoing-queue client)))
    (setf (ssh-client-outgoing-queue client) nil)
    (dolist (payload queue)
      (unless (ssh-client-closed-p client)
        (ssh-client-send-payload client payload)))))

(defun ssh-client-maybe-rekey (client)
  "Start a rekey now when the volume or time limit has been reached."
  (when (ssh-client-need-rekey-p client)
    (ssh-client-start-rekey client)))

(defun ssh-client-schedule-rekey-timer (client)
  "Arm the timer for RekeyLimit's time value, if it is set."
  (setf (ssh-client-rekey-timer client)
        (ssh-client-cancel-timer (ssh-client-rekey-timer client)))
  (let ((interval (ssh-client-rekey-interval client)))
    (when (and (integerp interval) (plusp interval)
               (eq (ssh-client-phase client) :ready)
               (not (ssh-client-closed-p client)))
      (let* ((now (ssh-client-now))
             (base (or (ssh-client-rekey-time client) now))
             (delay (- (+ base interval) now)))
        (setf (ssh-client-rekey-timer client)
              (cl-pnet:timer-start
               (max 1 delay) 0
               (lambda ()
                 (setf (ssh-client-rekey-timer client) nil)
                 (when (and (not (ssh-client-closed-p client))
                            (eq (ssh-client-phase client) :ready))
                   (when (ssh-client-need-rekey-p client)
                     (ssh-client-start-rekey client))))))))))

(defun ssh-client-start-rekey-timer (client)
  "Start time-based rekeying once authentication has completed."
  (ssh-client-schedule-rekey-timer client))


;;; ---- User authentication ----

(defun ssh-client-send-service-request (client)
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-service-request+)
    (ssh-write-text writer "ssh-userauth")
    (ssh-client-send-payload client (ssh-writer-output writer))))

(defun ssh-client-handle-service-accept (client payload)
  (let* ((reader (ssh-make-reader payload))
         (service (progn (ssh-read-u8 reader) (ssh-read-text reader))))
    (when (string= service "ssh-userauth")
      (ssh-client-send-auth-request client))))

(defparameter +ssh-auth-attempt-limit+ 6
  "Keys to offer before giving up, matching OpenSSH's default.")

(defun ssh-client-current-signer (client)
  "The signer the next publickey request uses."
  (nth (ssh-client-auth-index client) (ssh-client-signers client)))

(defun ssh-client-auth-request-unsigned (client)
  "The publickey request without its signature."
  (let ((writer (ssh-writer))
        (signer (ssh-client-current-signer client)))
    (unless signer
      (error 'ssh-authentication-error :detail "no key left to offer"))
    (ssh-write-u8 writer +ssh-msg-userauth-request+)
    (ssh-write-text writer (ssh-client-user client))
    (ssh-write-text writer "ssh-connection")
    (ssh-write-text writer "publickey")
    (ssh-write-boolean writer t)
    (ssh-write-text writer (ssh-signer-type signer))
    (ssh-write-string writer (ssh-signer-blob signer))
    (ssh-writer-output writer)))

(defun ssh-client-send-auth-signed (client unsigned signature)
  "Send a publickey request that carries SIGNATURE."
  (let ((writer (ssh-writer)))
    (ssh-write-octets writer unsigned)
    (ssh-write-string writer signature)
    (ssh-client-send-payload client (ssh-writer-output writer))))

(defun ssh-client-send-publickey-request (client)
  "Offer the current key, signing the session id and the request.

The signer may answer at once (a local key) or later (an agent), so the
request goes out from the callback rather than from this function's tail."
  (handler-case
      (let* ((signer (ssh-client-current-signer client))
             (unsigned (ssh-client-auth-request-unsigned client))
             (signature-data (let ((writer (ssh-writer)))
                               (ssh-write-string writer
                                                 (ssh-client-session-id client))
                               (ssh-write-octets writer unsigned)
                               (ssh-writer-output writer))))
        (setf (ssh-client-last-auth-method client) "publickey")
        (funcall (ssh-signer-sign signer)
                 signature-data
                 (lambda (signature)
                   (unless (ssh-client-closed-p client)
                     (ssh-client-send-auth-signed client unsigned signature)))
                 (lambda (condition)
                   (ssh-client-fail client condition))))
    (error (condition)
      (ssh-client-fail client condition))))

(defun ssh-client-local-host-name ()
  "The name this client reports in a hostbased request, with a trailing dot."
  (let ((name (or (uiop:getenv "HOSTNAME") (machine-instance) "localhost")))
    (if (and (plusp (length name))
             (char= (char name (1- (length name))) #\.))
        name
        (concatenate 'string name "."))))

(defun ssh-client-hostbased-request-unsigned (client)
  "The hostbased request without its signature."
  (let ((writer (ssh-writer))
        (key (ssh-client-hostbased-key client)))
    (unless key
      (error 'ssh-authentication-error
             :detail "no host key for hostbased authentication"))
    (ssh-write-u8 writer +ssh-msg-userauth-request+)
    (ssh-write-text writer (ssh-client-user client))
    (ssh-write-text writer "ssh-connection")
    (ssh-write-text writer "hostbased")
    (ssh-write-text writer (ssh-private-key-algorithm key))
    (ssh-write-string writer (ssh-public-key-blob-of key))
    (ssh-write-text writer (ssh-client-local-host-name))
    (ssh-write-text writer (ssh-default-user))
    (ssh-writer-output writer)))

(defun ssh-client-send-hostbased-request (client)
  "Offer the host key, signing the session id and the hostbased request."
  (handler-case
      (let* ((key (ssh-client-hostbased-key client))
             (unsigned (ssh-client-hostbased-request-unsigned client))
             (data (let ((writer (ssh-writer)))
                     (ssh-write-string writer (ssh-client-session-id client))
                     (ssh-write-octets writer unsigned)
                     (ssh-writer-output writer)))
             (signature (ssh-private-key-signature-blob key data)))
        (setf (ssh-client-last-auth-method client) "hostbased")
        (let ((writer (ssh-writer)))
          (ssh-write-octets writer unsigned)
          (ssh-write-string writer signature)
          (ssh-client-send-payload client (ssh-writer-output writer))))
    (error (condition)
      (ssh-client-fail client condition))))

(defparameter +ssh-client-auth-method-order+
  '("hostbased" "publickey" "keyboard-interactive" "password")
  "Methods to try, in OpenSSH's order, when PreferredAuthentications is unset.")

(defun ssh-client-auth-option-on-p (value)
  "Whether an authentication switch VALUE leaves its method on.

The library accepts T and NIL from programs and ssh_config's :YES and :NO
from the configuration layer, so neither spelling can turn :NO into truth."
  (not (or (null value) (eq value :no))))

(defun ssh-client-auth-method-enabled-p (client method)
  "Whether CLIENT may try METHOD.

BatchMode forbids the two interactive methods entirely, so their callbacks
are never called when the user asked not to be asked anything."
  (cond
    ((string= method "hostbased")
     (and (ssh-client-auth-option-on-p
           (ssh-client-hostbased-authentication client))
          (ssh-client-hostbased-key client)))
    ((string= method "publickey")
     (ssh-client-auth-option-on-p (ssh-client-pubkey-authentication client)))
    ((string= method "keyboard-interactive")
     (and (ssh-client-auth-option-on-p
           (ssh-client-kbd-interactive-authentication client))
          (not (ssh-client-batch-mode client))
          (ssh-client-kbd-interactive-callback client)))
    ((string= method "password")
     (and (ssh-client-auth-option-on-p
           (ssh-client-password-authentication client))
          (not (ssh-client-batch-mode client))
          (ssh-client-password-callback client)))
    (t nil)))

(defun ssh-client-auth-method-order (client)
  "The methods CLIENT may try, in the order it should try them."
  (let ((preferred (ssh-client-preferred-authentications client)))
    (remove-if-not (lambda (method)
                     (ssh-client-auth-method-enabled-p client method))
                   (or preferred +ssh-client-auth-method-order+))))

(defun ssh-client-next-auth-method (client)
  "Make the next untried method CLIENT may try current, and return it.

A method the last USERAUTH_FAILURE did not name is skipped when the server
has told us what it accepts, so a PreferredAuthentications list cannot make
the client prompt for a method the server refused."
  (let ((offered (ssh-client-auth-offered-methods client)))
    (loop for method in (ssh-client-auth-method-order client)
          unless (member method (ssh-client-auth-methods-tried client)
                         :test #'string=)
          unless (and offered (not (member method offered :test #'string=)))
          do (setf (ssh-client-auth-method client) method)
             (push method (ssh-client-auth-methods-tried client))
             (return method))))

(defun ssh-client-send-next-auth-method (client)
  "Give up on the current method and start the next one."
  (setf (ssh-client-auth-method client) nil)
  (ssh-client-send-auth-request client))

(defun ssh-client-password-prompt (client)
  "The prompt ssh shows before reading a password."
  (format nil "~A@~A's password: "
          (ssh-client-user client) (ssh-client-host client)))

(defun ssh-client-send-password-request (client)
  "Ask CLIENT's PASSWORD-CALLBACK for a password and offer it."
  (let ((password
          (funcall (ssh-client-password-callback client)
                   client (ssh-client-password-prompt client))))
    (if (null password)
        (ssh-client-send-next-auth-method client)
        (progn
          (incf (ssh-client-password-attempts client))
          (setf (ssh-client-last-auth-method client) "password")
          (let ((writer (ssh-writer)))
            (ssh-write-u8 writer +ssh-msg-userauth-request+)
            (ssh-write-text writer (ssh-client-user client))
            (ssh-write-text writer "ssh-connection")
            (ssh-write-text writer "password")
            ;; FALSE: this client cannot change an expired password.
            (ssh-write-boolean writer nil)
            (ssh-write-text writer password)
            (ssh-client-send-payload client (ssh-writer-output writer)))))))

(defun ssh-client-send-kbd-interactive-request (client)
  "Start a keyboard-interactive exchange with no preferred submethods."
  (setf (ssh-client-last-auth-method client) "keyboard-interactive")
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-userauth-request+)
    (ssh-write-text writer (ssh-client-user client))
    (ssh-write-text writer "ssh-connection")
    (ssh-write-text writer "keyboard-interactive")
    (ssh-write-text writer "")
    (ssh-write-text writer "")
    (ssh-client-send-payload client (ssh-writer-output writer))))

(defun ssh-client-handle-info-request (client payload)
  "Answer a keyboard-interactive INFO_REQUEST through KBD-INTERACTIVE-CALLBACK."
  (unless (string= (or (ssh-client-last-auth-method client) "")
                   "keyboard-interactive")
    (error 'ssh-protocol-error
           :detail "unexpected USERAUTH_INFO_REQUEST"))
  (let* ((reader (ssh-make-reader payload))
         (type (ssh-read-u8 reader))
         (name (ssh-read-text reader))
         (instruction (ssh-read-text reader))
         (language (ssh-read-text reader))
         (count (ssh-read-u32 reader))
         (prompts '()))
    (declare (ignore type language))
    (when (>= count 1024)
      (error 'ssh-protocol-error
             :detail "USERAUTH_INFO_REQUEST has too many prompts"))
    (dotimes (index count)
      (declare (ignore index))
      (push (list (ssh-read-text reader) (ssh-read-boolean reader)) prompts))
    (setf prompts (nreverse prompts))
    (let ((answers
            (funcall (ssh-client-kbd-interactive-callback client)
                     client name instruction prompts)))
      (cond
        ;; A zero-prompt INFO_REQUEST only displays a message; NIL is then an
        ;; empty answer list, not a cancellation.
        ((and (null answers) (plusp count))
         (ssh-client-fail
          client
          (make-condition 'ssh-authentication-error
                          :detail "keyboard-interactive cancelled")))
        ((/= (length (or answers '())) count)
         (error 'ssh-protocol-error
                :detail "keyboard-interactive answer count does not match"))
        (t
         (let ((writer (ssh-writer)))
           (ssh-write-u8 writer +ssh-msg-userauth-info-response+)
           (ssh-write-u32 writer count)
           (dolist (answer answers)
             (ssh-write-text writer answer))
           (ssh-client-send-payload client (ssh-writer-output writer))))))))

(defun ssh-client-send-auth-request (client)
  "Start the next permitted authentication method."
  (let ((method (or (ssh-client-auth-method client)
                    (ssh-client-next-auth-method client))))
    (cond
      ((null method)
       (ssh-client-fail
        client
        (make-condition
         'ssh-authentication-error
         :detail
         (if (ssh-client-auth-offered-methods client)
             (format nil "server accepts ~{~A~^, ~}"
                     (ssh-client-auth-offered-methods client))
             "server refused every authentication method"))))
      ((string= method "hostbased")
       (ssh-client-send-hostbased-request client))
      ((string= method "publickey")
       (if (ssh-client-current-signer client)
           (ssh-client-send-publickey-request client)
           (ssh-client-send-next-auth-method client)))
      ((string= method "keyboard-interactive")
       (ssh-client-send-kbd-interactive-request client))
      ((string= method "password")
       (ssh-client-send-password-request client)))))

(defun ssh-client-handle-banner (client payload)
  "Store a USER AUTH BANNER, which the program shows as it likes.

The second string is a language tag; sshd leaves it empty and this client
has no use for it either."
  (let* ((reader (ssh-make-reader payload))
         (type (ssh-read-u8 reader))
         (text (ssh-read-text reader))
         (language (ssh-read-text reader)))
    (declare (ignore type language))
    (setf (ssh-client-banner client) text)))

(defun ssh-client-handle-auth-success (client)
  "Authenticated: let the queued channel work start."
  (ssh-log "authenticated as ~A" (ssh-client-user client))
  (setf (ssh-client-phase client) :ready
        (ssh-client-after-authentication client) t)
  ;; zlib@openssh.com starts after USERAUTH_SUCCESS, and this packet itself
  ;; was the last uncompressed one in each direction.
  (ssh-enable-delayed-compression (ssh-client-cipher client))
  (ssh-client-cancel-connect-timer client)
  (ssh-client-start-alive-timer client)
  (ssh-client-start-rekey-timer client)
  (let ((actions (nreverse (ssh-client-pending-actions client))))
    (setf (ssh-client-pending-actions client) nil)
    (when (ssh-client-on-open client)
      (funcall (ssh-client-on-open client) client))
    (iter (for action in actions) (funcall action))))

(defun ssh-client-next-signer-p (client)
  "Move to the next signer; NIL when none is left or the limit is reached."
  (let ((next (1+ (ssh-client-auth-index client))))
    (when (and (< next (length (ssh-client-signers client)))
               (< next +ssh-auth-attempt-limit+))
      (setf (ssh-client-auth-index client) next)
      t)))

(defun ssh-client-handle-auth-failure (client payload)
  "Advance after one refused authentication attempt.

The failure names the methods the server will still consider.  A
partial-success flag means one method of an AuthenticationMethods list
finished; the next request must use the method the server now names, which
may even be the same method with a second key."
  (let* ((reader (ssh-make-reader payload))
         (methods (progn (ssh-read-u8 reader) (ssh-read-name-list reader)))
         (partial (ssh-read-boolean reader))
         (method (or (ssh-client-auth-method client) "")))
    (setf (ssh-client-auth-offered-methods client) methods)
    (cond
      ((string= method "hostbased")
       (setf (ssh-client-last-auth-method client) nil)
       (ssh-log "hostbased rejected~:[~;; partial success~]; trying the next method"
                partial)
       (ssh-client-send-next-auth-method client))
      ((string= method "publickey")
       (if (and (or (not partial)
                    (member "publickey" methods :test #'string=))
                (ssh-client-next-signer-p client))
           (progn
             (ssh-log "~:[publickey rejected~;partial success~]; trying the next key"
                      partial)
             (ssh-client-send-auth-request client))
           (progn
             ;; No key left, or the server now wants a different method.
             (setf (ssh-client-auth-index client)
                   (length (ssh-client-signers client)))
             (ssh-log "publickey exhausted~:[~;; partial success~]"
                      partial)
             (ssh-client-send-next-auth-method client))))
      ((string= method "password")
       (if (and (< (ssh-client-password-attempts client)
                   (or (ssh-client-number-of-password-prompts client) 3))
                (or (null methods)
                    (member "password" methods :test #'string=)))
           (progn
             (ssh-log "password rejected~:[~;; partial success~]; asking again"
                      partial)
             (ssh-client-send-auth-request client))
           (ssh-client-send-next-auth-method client)))
      ((string= method "keyboard-interactive")
       (ssh-log "keyboard-interactive rejected~:[~;; partial success~]"
                partial)
       (ssh-client-send-next-auth-method client))
      (t
       (ssh-client-send-next-auth-method client)))))

(defun ssh-client-send-global-request (client name &key fields on-success
                                                     on-failure)
  "Send the global request NAME to CLIENT's peer, expecting an answer.

FIELDS, when given, writes the request's arguments.  ON-SUCCESS receives a
reader over the success reply after its message type, so it can read an
allocated port; ON-FAILURE takes no arguments.  The peer answers requests in
order, which is how the callbacks stay paired with their requests."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-global-request+)
    (ssh-write-text writer name)
    (ssh-write-boolean writer t)
    (when fields (funcall fields writer))
    (setf (ssh-client-pending-global-requests client)
          (append (ssh-client-pending-global-requests client)
                  (list (list :on-success on-success
                              :on-failure on-failure))))
    (ssh-client-send-payload client (ssh-writer-output writer))
    t))

(defun ssh-client-handle-global-reply (client payload success-p)
  (let ((pending (ssh-client-pending-global-requests client)))
    (when pending
      (setf (ssh-client-pending-global-requests client) (cdr pending))
      (let ((entry (car pending))
            (reader (ssh-make-reader payload)))
        (ssh-read-u8 reader)
        (if success-p
            (when (getf entry :on-success)
              (funcall (getf entry :on-success) reader))
            (when (getf entry :on-failure)
              (funcall (getf entry :on-failure))))))))

(defun ssh-client-host-key-known-p (client key-blob)
  "Whether KEY-BLOB itself is already recorded for CLIENT's host."
  (some (lambda (file)
          (eq :match (ssh-known-host-status
                      file (ssh-client-host-spec client) key-blob)))
        (ssh-client-known-hosts-files client)))

(defun ssh-client-host-key-allowed-p (client key-blob)
  "Whether KEY-BLOB's type is permitted by HostKeyAlgorithms."
  (let* ((patterns (or (ssh-client-host-key-algorithms client)
                       +ssh-host-key-algorithms+))
         (type (nth-value 0 (ssh-public-key-parts
                             (ssh-key-plain-blob key-blob)))))
    (flet ((match (name)
             (some (lambda (pattern) (ssh-match-pattern pattern name))
                   patterns)))
      (cond
        ((string= type "ssh-rsa")
         (or (match "rsa-sha2-512") (match "rsa-sha2-256")
             (match "ssh-rsa")))
        (t (match type))))))

(defun ssh-signature-algorithm-name (signature)
  "The algorithm name inside a signature blob, or NIL."
  (handler-case (ssh-read-text (ssh-make-reader signature))
    (error () nil)))

(defun ssh-client-hostkey-proof-data (client key-blob)
  "The octets a hostkeys-prove reply signs for KEY-BLOB."
  (let ((writer (ssh-writer)))
    (ssh-write-text writer "hostkeys-prove-00@openssh.com")
    (ssh-write-string writer (ssh-client-session-id client))
    (ssh-write-string writer key-blob)
    (ssh-writer-output writer)))

(defun ssh-client-add-proven-hostkey (client key-blob)
  "Record a host key the server has proved it owns."
  (multiple-value-bind (type data) (ssh-public-key-parts key-blob)
    (declare (ignore data))
    (handler-case
        (ssh-remember-known-host (ssh-client-known-hosts-file client)
                                 (ssh-client-host-spec client)
                                 type key-blob
                                 :hash (ssh-client-hash-known-hosts client))
      (error (condition)
        (ssh-log "could not record a proved host key: ~A" condition)))))

(defun ssh-client-prove-hostkeys (client keys)
  "Ask the server to prove ownership of KEYS, then record the proofs."
  (ssh-client-send-global-request
   client "hostkeys-prove-00@openssh.com"
   :fields (lambda (writer)
             (dolist (key keys)
               (ssh-write-string writer key)))
   :on-success
   (lambda (reply)
     (dolist (key keys)
       (when (plusp (ssh-reader-remaining reply))
         (let ((signature (ssh-read-string reply)))
           (when (and (not (string= (or (ssh-signature-algorithm-name signature)
                                        "")
                                    "ssh-rsa"))
                      (ssh-public-key-signature-valid-p
                       key signature
                       (ssh-client-hostkey-proof-data client key)))
             (ssh-client-add-proven-hostkey client key))))))
   :on-failure
   (lambda ()
     (ssh-log "server refused to prove its host keys"))))

(defun ssh-client-handle-hostkeys (client reader)
  "Handle the server's hostkeys-00 list and update known_hosts."
  (unless (ssh-client-host-keys-seen client)
    (setf (ssh-client-host-keys-seen client) t)
    (let ((keys '()))
      (loop while (plusp (ssh-reader-remaining reader))
            do (let ((blob (ssh-read-string reader)))
                 (unless (or (ssh-certificate-blob-p blob)
                             (member blob keys :test #'ssh-octets=)
                             (not (ssh-client-host-key-allowed-p client blob)))
                   (push blob keys))))
      (when (eq (ssh-client-update-host-keys client) :yes)
        (let ((new (remove-if (lambda (key)
                                (ssh-client-host-key-known-p client key))
                              keys)))
          (when new
            (ssh-client-prove-hostkeys client new)))))))

(defun ssh-client-handle-global-request (client payload)
  (let* ((reader (ssh-make-reader payload))
         (name (progn (ssh-read-u8 reader) (ssh-read-text reader)))
         (want-reply (ssh-read-boolean reader)))
    (when (string= name "hostkeys-00@openssh.com")
      (ssh-client-handle-hostkeys client reader))
    (when want-reply
      (let ((writer (ssh-writer)))
        (ssh-write-u8 writer (if (string= name "hostkeys-00@openssh.com")
                                 +ssh-msg-request-success+
                                 +ssh-msg-request-failure+))
        (ssh-client-send-payload client (ssh-writer-output writer))))))
