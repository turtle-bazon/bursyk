(in-package #:cl-pnet-ssh)

;;;; Client and channel state. The shared pieces (wire, packets, KEX, keys)
;;;; never look at these; they define the client role only.

(defstruct (ssh-client (:constructor %make-ssh-client))
  host
  connect-host
  ;; The name known_hosts is checked and recorded under when it differs from
  ;; HOST, as with "Host gh / HostName github.com": OpenSSH looks up the
  ;; HostName, not the alias the user typed.  NIL means HOST.
  host-key-host
  (port 22)
  (user nil)
  (connection nil)
  ;; The port actually dialled; PORT stays the logical one known_hosts and
  ;; the server name use, so a tunnel can listen on a loopback port while the
  ;; key is still checked under the host's real port.
  (connect-port 22)
  (phase :connecting)
  (incoming (make-array 4096 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))
  (client-version "SSH-2.0-cl-pnet-ssh_0.0.1.19")
  (server-version nil)
  ;; USERAUTH_BANNER text, if the server sent one.  A program shows it once;
  ;; after that this is just the last banner received.
  (banner nil)
  (session-id nil)
  (cipher (ssh-make-cipher-state))
  (client-kexinit nil)
  (kexinit-sent nil)
  (server-kexinit nil)
  (negotiated nil)
  (ephemeral-private nil)
  (ephemeral-public nil)
  (host-key-blob nil)
  (derived-keys nil)
  (strict-kex nil)
  (ignore-next-kex-packet nil)
  (keys-sent nil)
  (keys-received nil)
  (signers nil)
  (auth-index 0)
  (known-hosts nil)
  (host-key-policy :strict)
  (host-key-callback nil)
  ;; Algorithm offers from ssh_config's Ciphers, MACs, KexAlgorithms and
  ;; HostKeyAlgorithms.  NIL means this build's own list; a list from
  ;; SSH-RESOLVE-ALGORITHM-LIST restricts what KEXINIT offers.
  (kex-algorithms nil)
  (host-key-algorithms nil)
  (ciphers nil)
  (macs nil)
  ;; PubkeyAcceptedAlgorithms: key types that may authenticate.  NIL offers
  ;; every signer; a list of patterns filters them before the first request.
  (pubkey-accepted-algorithms nil)
  ;; CASignatureAlgorithms: signature algorithms a host certificate's CA may
  ;; use.  NIL means this build's default, which excludes SHA-1 ssh-rsa.
  (ca-signature-algorithms nil)
  ;; RevokedHostKeys: files whose host keys and certificates may not be used.
  (revoked-host-keys '())
  ;; HashKnownHosts: write new known_hosts entries as salted hashes.
  (hash-known-hosts nil)
  ;; FingerprintHash: the digest used when showing a key fingerprint.
  (fingerprint-hash :sha256)
  ;; IPQoS: DSCP values for interactive and bulk traffic; :NONE leaves the
  ;; operating system default.
  (ip-qos-interactive #xb8)
  (ip-qos-bulk :none)
  ;; TCPKeepAlive: keep the transport's keepalive probes on, ssh's default.
  (tcp-keep-alive t)
  ;; SetEnv: NAME=VALUE assignments to send on every session.
  (set-env nil)
  ;; RequiredRSASize: the smallest RSA modulus accepted in a host key or an
  ;; authentication key, as ssh's RequiredRSASize directive sets it.
  (required-rsa-size +ssh-rsa-minimum-modulus-size+)
  ;; ProxyCommand: a helper program carrying the stream on its stdin/stdout.
  ;; NIL means dial the address directly.
  proxy-command
  ;; The running helper and its pipes, once SSH-OPEN-PROXY-CONNECTION starts
  ;; it.  NIL on the direct TCP path.
  pipe
  ;; Connection timing, from ConnectTimeout and ServerAlive* in ssh_config.
  ;; A NIL timeout or interval means the feature is off.
  connect-timeout
  server-alive-interval
  (server-alive-count-max 3)
  ;; ConnectionAttempts: how many times a failed TCP connect is retried.
  (connection-attempts 1)
  (connection-attempt 0)
  connect-timer
  retry-timer
  alive-timer
  (alive-misses 0)
  (channels (make-hash-table :test #'eql))
  (next-channel-id 0)
  (pending-actions nil)
  ;; Global requests sent by us, oldest first; the peer answers in order.
  (pending-global-requests nil)
  ;; Server-initiated forwarded-tcpip channels: the application maps the
  ;; remote bind address and port to the local target to dial.
  (on-forwarded-tcpip nil)
  ;; A function of (CLIENT PATH) returning a setup function of CHANNEL for a
  ;; server-initiated forwarded-streamlocal channel, or NIL to refuse.
  (on-forwarded-streamlocal nil)
  (on-open nil)
  (on-error nil)
  (on-close nil)
  ;; The resolved ssh_config this client was built from, when it came from
  ;; MAKE-SSH-CLIENT-FROM-CONFIG.  Channel code reads SendEnv from it.
  (config-options nil)
  (closed nil)
  (close-reason nil)
  (window 2097152)
  (max-packet 32768))

(defstruct (ssh-channel (:constructor %make-ssh-channel))
  client
  local-id
  (remote-id nil)
  (type "session")
  (open-extra (make-array 0 :element-type '(unsigned-byte 8)))
  (state :opening)
  (remote-window 0)
  (remote-max-packet 0)
  (local-window 0)
  (local-max-packet 32768)
  (write-queue (make-array 0 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))
  (write-callbacks nil)
  (pending-exec nil)
  (pending-subsystem nil)
  (pending-env nil)
  (want-eof nil)
  (sent-eof nil)
  (want-close nil)
  (sent-close nil)
  (eof-received nil)
  (exit-status nil)
  (exit-signal nil)
  ;; A forwarded-tcpip channel's local socket, once it is dialled.
  (target nil)
  (target-eof nil)
  (on-data nil)
  (on-open nil)
  (on-eof nil)
  (on-exit nil)
  (on-close nil)
  (on-error nil))

(defun ssh-client-closed-p (client)
  "True once CLIENT has shut down."
  (ssh-client-closed client))

(defun ssh-client-buffer-append (client data)  "Append DATA to CLIENT's receive buffer."
  (let ((buffer (ssh-client-incoming client)))
    (iter (for octet in-vector data)
      (vector-push-extend octet buffer))))

(defun ssh-client-buffer-consume (client count)
  "Drop the first COUNT octets of CLIENT's receive buffer."
  (let ((buffer (ssh-client-incoming client)))
    (when (plusp count)
      (replace buffer buffer :start1 0 :start2 count)
      (decf (fill-pointer buffer) count))
    buffer))

(defun ssh-client-buffer-empty-p (client)
  (zerop (fill-pointer (ssh-client-incoming client))))

(defun ssh-client-close-connection (client)
  ;; CL-PNET:CLOSE-CONNECTION is idempotent, so there is nothing expected to
  ;; ignore here; swallowing every error would only hide a real bug.
  (cond
    ((ssh-client-pipe client) (ssh-proxy-close client))
    ((ssh-client-connection client)
     (cl-pnet:close-connection (ssh-client-connection client)))))

;;; ---- Connect timeout and server-alive keepalives ----

(defun ssh-client-cancel-timer (timer)
  "Stop TIMER when it is set, answering NIL for the caller to store."
  (when timer
    (cl-pnet:timer-stop timer))
  nil)

(defun ssh-client-stop-timers (client)
  "Disarm CLIENT's connect timeout and keepalive timer, once."
  (setf (ssh-client-connect-timer client)
        (ssh-client-cancel-timer (ssh-client-connect-timer client))
        (ssh-client-retry-timer client)
        (ssh-client-cancel-timer (ssh-client-retry-timer client))
        (ssh-client-alive-timer client)
        (ssh-client-cancel-timer (ssh-client-alive-timer client))))

(defun ssh-client-start-connect-timer (client)
  "Fail CLIENT when ConnectTimeout seconds pass before authentication.

OpenSSH's ConnectTimeout covers the TCP connect, the version exchange, the
key exchange and the initial authentication; it stops mattering once the
session is ready for channels."
  (when (and (ssh-client-connect-timeout client)
             (plusp (ssh-client-connect-timeout client))
             (not (ssh-client-connect-timer client)))
    (setf (ssh-client-connect-timer client)
          (cl-pnet:timer-start
           (ssh-client-connect-timeout client) 0
           (lambda ()
             (setf (ssh-client-connect-timer client) nil)
             (unless (ssh-client-closed client)
               (ssh-client-fail
                client
                (make-condition
                 'ssh-connection-error
                 :detail (format nil "connecting to ~A:~D timed out after ~D seconds"
                                 (ssh-client-connect-host client)
                                 (or (ssh-client-connect-port client)
                                     (ssh-client-port client))
                                 (ssh-client-connect-timeout client))))))))))

(defun ssh-client-cancel-connect-timer (client)
  "The handshake is far enough along that ConnectTimeout no longer applies."
  (setf (ssh-client-connect-timer client)
        (ssh-client-cancel-timer (ssh-client-connect-timer client))))

(defun ssh-client-send-keepalive (client)
  "Ask the server to answer, as OpenSSH's ServerAliveInterval does.

OpenSSH names keepalive@openssh.com with want-reply set and treats the
REQUEST_FAILURE it gets back as proof that the peer is alive."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-global-request+)
    (ssh-write-text writer "keepalive@openssh.com")
    (ssh-write-boolean writer t)
    (ssh-client-send-payload client (ssh-writer-output writer))))

(defun ssh-client-start-alive-timer (client)
  "Start the ServerAliveInterval timer once CLIENT can carry channels."
  (when (and (ssh-client-server-alive-interval client)
             (plusp (ssh-client-server-alive-interval client))
             (not (ssh-client-alive-timer client)))
    (setf (ssh-client-alive-timer client)
          (cl-pnet:timer-start
           (ssh-client-server-alive-interval client)
           (ssh-client-server-alive-interval client)
           (lambda ()
             (when (and (not (ssh-client-closed client))
                        (eq (ssh-client-phase client) :ready))
               (incf (ssh-client-alive-misses client))
               (let ((count-max (or (ssh-client-server-alive-count-max
                                     client)
                                    3)))
                 ;; A count of 0 turns the disconnect off but still sends,
                 ;; exactly as OpenSSH reads ServerAliveCountMax.
                 (if (and (plusp count-max)
                          (> (ssh-client-alive-misses client) count-max))
                     (ssh-client-fail
                      client
                      (make-condition
                       'ssh-connection-error
                       :detail (format nil "server ~A stopped responding"
                                       (ssh-client-host client))))
                     (ssh-client-send-keepalive client)))))))))

(defun ssh-client-finish (client reason kind)
  "Close CLIENT once, reporting REASON through the callback KIND selects."
  (unless (ssh-client-closed client)
    (setf (ssh-client-closed client) t
          (ssh-client-phase client) :closed
          (ssh-client-close-reason client) reason)
    (ssh-client-stop-timers client)
    (ssh-client-terminate-channels client reason kind)
    (ssh-client-close-connection client)
    (ecase kind
      (:error (when (ssh-client-on-error client)
                (funcall (ssh-client-on-error client) client reason)))
      (:close (when (ssh-client-on-close client)
                (funcall (ssh-client-on-close client) client reason))))))

(defun ssh-client-fail (client condition)
  "End CLIENT because of CONDITION, telling its error callback once."
  (ssh-client-finish client condition :error))

(defun ssh-client-send-bytes (client octets)
  "Queue OCTETS on CLIENT's connection. NIL once the client is closed."
  (unless (ssh-client-closed client)
    (if (ssh-client-pipe client)
        (ssh-proxy-send client octets)
        (let ((connection (ssh-client-connection client)))
          (when connection
            (handler-case
                (cl-pnet:send-data
                 connection octets
                 :on-error (lambda (status)
                             (ssh-client-fail
                              client
                              (make-condition 'ssh-connection-error
                                              :detail (format nil "send failed (~A)" status)))))
              (error (condition) (ssh-client-fail client condition)))))))
  (not (ssh-client-closed client)))

(defun ssh-client-send-payload (client payload)
  "Frame and send one protocol PAYLOAD."
  (ssh-client-send-bytes client
                         (ssh-encode-packet payload (ssh-client-cipher client))))

(defun ssh-client-send-disconnect (client &optional (description "client closed"))
  "Tell the peer CLIENT is going away, so it can close the session.

A ProxyCommand helper forwards this packet to the server; the server then
closes the transport, which is what lets netcat exit instead of waiting on
a half-closed connection forever."
  (when (and (not (ssh-client-closed client))
             (member (ssh-client-phase client) '(:kex :auth :ready)))
    (handler-case
        (ssh-client-send-payload client (ssh-disconnect-payload description))
      (error () nil))))

(defun ssh-client-run-when-ready (client action)
  "Run ACTION now when CLIENT is ready, otherwise after authentication."
  (if (eq (ssh-client-phase client) :ready)
      (funcall action)
      (push action (ssh-client-pending-actions client))))

(defun ssh-client-channel-for (client local-id)
  (gethash local-id (ssh-client-channels client)))
