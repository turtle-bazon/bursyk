(in-package #:cl-pnet-ssh)

;;;; Client and channel state. The shared pieces (wire, packets, KEX, keys)
;;;; never look at these; they define the client role only.

(defstruct (ssh-client (:constructor %make-ssh-client))
  host
  connect-host
  ;; When this client object was made, for -O conninfo's duration line.
  (connected-at (get-universal-time))
  ;; The name known_hosts is checked and recorded under when it differs from
  ;; HOST, as with "Host gh / HostName github.com": OpenSSH looks up the
  ;; HostName, not the alias the user typed.  NIL means HOST.
  host-key-host
  (port 22)
  (user nil)
  (connection nil)
  ;; The peer OpenSSH's packet layer names in Connection closed/reset
  ;; messages.  It records the address and port at connect time, so the
  ;; strings survive the socket closing; getpeername() would not.
  (peer-ip nil)
  (peer-port nil)
  ;; The port actually dialled; PORT stays the logical one known_hosts and
  ;; the server name use, so a tunnel can listen on a loopback port while the
  ;; key is still checked under the host's real port.
  (connect-port 22)
  (phase :connecting)
  ;; A control-master proxy client rides an existing master connection: its
  ;; packets are plaintext connection-protocol frames on MUX-FD, not an
  ;; encrypted SSH transport of its own.
  (mux-mode nil)
  (mux-fd nil)
  (mux-watcher nil)
  ;; A control master's function of (CLIENT TYPE READER) that may take over a
  ;; server-initiated OPEN (relaying it to a mux proxy client).  NIL leaves
  ;; the ordinary handlers in charge.
  (forwarded-open-relay nil)
  (incoming (make-array 4096 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))
  (client-version "SSH-2.0-cl-pnet-ssh_0.0.1.19")
  ;; VersionAddendum: a comment appended after a space, or NIL for none.
  (version-addendum nil)
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
  ;; RFC 4419 group exchange: the sizes we asked for, and the group the
  ;; server chose, kept until the reply computes the exchange hash.
  (gex-min nil)
  (gex-preferred nil)
  (gex-max nil)
  (gex-prime nil)
  (gex-generator nil)
  (host-key-blob nil)
  (derived-keys nil)
  (strict-kex nil)
  (ignore-next-kex-packet nil)
  (keys-sent nil)
  (keys-received nil)
  ;; RekeyLimit: the configured byte volume (0 selects the cipher's default)
  ;; and interval in seconds (0 disables time-based rekeying).  A rekey's
  ;; KEXINIT was sent but our NEWKEYS has not gone out yet.
  (rekey-limit 0)
  (rekey-interval 0)
  (rekeying nil)
  ;; OpenSSH starts no rekey before authentication completes (packet.c's
  ;; after_authentication), including for very small RekeyLimits.
  (after-authentication nil)
  ;; Packet and block counters since the last NEWKEYS in each direction.
  ;; OpenSSH resets both counters at every NEWKEYS, so the limits apply per
  ;; set of keys, not to the whole connection.
  (sent-packets 0)
  (received-packets 0)
  (sent-blocks 0)
  (received-blocks 0)
  ;; Wire octets in each direction since the last NEWKEYS, for -O conninfo.
  (sent-bytes 0)
  (received-bytes 0)
  ;; Payloads held back while a rekey is in progress, oldest first.  They are
  ;; encoded only after NEWKEYS so they use the new keys.
  (outgoing-queue '())
  (rekey-time nil)
  (rekey-timer nil)
  (signers nil)
  (auth-index 0)
  (known-hosts nil)
  (global-known-hosts nil)
  (host-key-policy :ask)
  (host-key-callback nil)
  ;; BatchMode: never ask the user anything, so an unknown host key fails
  ;; even when a confirmation callback was supplied.
  (batch-mode nil)
  ;; WarnWeakCrypto: OpenSSH 10.6 warns after the initial key exchange when
  ;; it did not use a post-quantum algorithm and KexAlgorithms was left at
  ;; its default.  NIL turns the notice off; NON-PQ-KEX-WARNED keeps it to
  ;; one notice per connection.
  (warn-weak-crypto t)
  (non-pq-kex-warned nil)
  ;; EXT_INFO's ping@openssh.com extension.  When the server advertises
  ;; version 0 the client may use PING packets as chaff while hiding
  ;; keystroke timing.
  (ping-supported nil)
  ;; EXT_INFO's server-sig-algs: the signature algorithm names the server
  ;; verifies for publickey authentication.  An RSA key picks rsa-sha2-512 or
  ;; rsa-sha2-256 from this list, and a name it omits is not offered.
  (server-sig-algs nil)
  ;; EXT_INFO's agent-forward extension.  Version 0 selects RFC 9987's
  ;; agent-req request and agent-connect channel instead of OpenSSH's
  ;; auth-agent-req@openssh.com names.
  (agent-forward-supported nil)
  ;; ForwardAgent: T asks the server to forward its agent connections, and
  ;; FORWARD-AGENT-SOCK-PATH, when set, names the agent socket to use instead
  ;; of SSH_AUTH_SOCK.
  (forward-agent nil)
  (forward-agent-sock-path nil)
  ;; ForwardX11, ForwardX11Trusted and ForwardX11Timeout: ask the server to
  ;; forward X11 connections, whether forwarding may invent data when there
  ;; is no cookie, and how long untrusted forwarding keeps accepting new x11
  ;; channels (0 for no limit, NIL for OpenSSH's 1200-second default; trusted
  ;; forwarding never expires).  XAUTHORITY is read the way every X client
  ;; reads it, so XAUTH-LOCATION only names the xauth program OpenSSH would
  ;; run; this implementation reads the file directly and keeps it for
  ;; parity.
  (forward-x11 nil)
  (forward-x11-trusted nil)
  (forward-x11-timeout nil)
  (xauth-location nil)
  ;; The DISPLAY forwarded and the real and fake cookies, once
  ;; SSH-CLIENT-PREPARE-X11 has run.  The fake data goes to the server in
  ;; x11-req; the real one replaces it on each forwarded connection.
  (x11-display nil)
  (x11-proto nil)
  (x11-saved-data nil)
  (x11-fake-data nil)
  ;; ForwardX11Timeout as a deadline on SSH-CLIENT-NOW, or NIL.
  (x11-refuse-time nil)
  ;; ObscureKeystrokeTiming: milliseconds between quantised keystrokes; 0
  ;; disables it.  The application owns stdin, so it applies this policy.
  (obscure-keystroke-timing +ssh-keystroke-default-interval-ms+)
  ;; Algorithm offers from ssh_config's Ciphers, MACs, KexAlgorithms and
  ;; HostKeyAlgorithms.  NIL means this build's own list; a list from
  ;; SSH-RESOLVE-ALGORITHM-LIST restricts what KEXINIT offers.
  (kex-algorithms nil)
  (host-key-algorithms nil)
  (ciphers nil)
  (macs nil)
  ;; Compression, from -C or Compression yes.  NIL keeps the offer
  ;; "none,zlib@openssh.com", so the server's preference cannot turn it on;
  ;; true offers "zlib@openssh.com,none" as OpenSSH does.
  (compression nil)
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
  ;; KnownHostsCommand: a command whose output is read as known_hosts lines.
  (known-hosts-command nil)
  ;; AddKeysToAgent: :YES adds file-loaded keys to the agent.
  (add-keys-to-agent :no)
  ;; CertificateFile: user certificate files paired with the matching
  ;; private key, in the order the configuration listed them.
  (certificate-files '())
  ;; NoHostAuthenticationForLocalhost: a loopback peer's host key is accepted
  ;; without consulting known_hosts, unless a HostKeyAlias names it.
  (no-host-authentication-for-localhost nil)
  ;; HostKeyAlias: the name known_hosts is checked under when it is an alias
  ;; rather than the host's own name.
  (host-key-alias nil)
  ;; CanonicalizeHostname and the resolver used to try its candidates.
  (canonicalize-hostname :no)
  (canonical-domains '())
  (canonicalize-max-dots 1)
  (canonicalize-fallback-local t)
  (resolver nil)
  ;; HostbasedAuthentication: a readable host key and the method state.
  (hostbased-authentication nil)
  (hostbased-accepted-algorithms nil)
  (hostbased-keys '())
  (hostbased-key nil)
  (last-auth-method nil)
  ;; PasswordAuthentication, KbdInteractiveAuthentication and
  ;; NumberOfPasswordPrompts, with ssh's defaults.  A method a
  ;; PreferredAuthentications list does not name is still offered only if it
  ;; is enabled here.
  (password-authentication t)
  (kbd-interactive-authentication t)
  (number-of-password-prompts nil)
  (preferred-authentications nil)
  (pubkey-authentication t)
  ;; A function of (CLIENT PROMPT) returning a password, or NIL to skip the
  ;; method.  BatchMode suppresses every prompt before this is called.
  (password-callback nil)
  ;; A function of (CLIENT NAME INSTRUCTION PROMPTS), where each prompt is
  ;; (TEXT ECHO-P), returning a list of answer strings or NIL to cancel.
  (kbd-interactive-callback nil)
  ;; The method currently being attempted, the methods already tried, the
  ;; methods the last USERAUTH_FAILURE named, and how many password prompts
  ;; this connection has used.
  (auth-method nil)
  (auth-methods-tried '())
  (auth-offered-methods '())
  (password-attempts 0)
  ;; UpdateHostKeys: whether a proven host key may be added to known_hosts.
  (update-host-keys :yes)
  (host-keys-seen nil)
  ;; FingerprintHash: the digest used when showing a key fingerprint.
  (fingerprint-hash :sha256)
  ;; VisualHostKey: show the randomart picture once connected.
  (visual-host-key nil)
  ;; CheckHostIP: also look up and record the peer's numeric address.
  (check-host-ip nil)
  ;; VerifyHostKeyDNS and the SSHFP records fetched before connecting.
  (verify-host-key-dns :no)
  (host-key-dns-resolver nil)
  (host-key-dns-records nil)
  (host-key-dns-secure nil)
  (host-key-dns-queried nil)
  (host-key-dns-accepted nil)
  (remote-address nil)
  (host-key-ip-checked nil)
  ;; Whether the host key was already trusted before this connection; ssh
  ;; shows randomart only for a key that was not just added.
  (host-key-known nil)
  ;; Set when StrictHostKeyChecking=no continued past a changed host key.
  ;; Password, keyboard-interactive, agent and X11 forwarding are disabled,
  ;; and the caller refuses to start port forwarding.
  (host-key-untrusted nil)
  ;; IPQoS: DSCP values for interactive and bulk traffic; :NONE leaves the
  ;; operating system default.
  (ip-qos-interactive #xb8)
  (ip-qos-bulk #x00)
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
  ;; ProxyUseFdpass: the helper connects the socket itself and hands the
  ;; connected descriptor back over a socketpair instead of carrying bytes.
  proxy-use-fdpass
  ;; BindAddress / BindInterface: where a direct connection comes from.
  ;; The numeric form of BIND-ADDRESS is cached once resolved.
  bind-address
  bind-interface
  bind-address-resolved
  ;; AddressFamily: NIL for any, or :INET / :INET6 to ask the resolver for one
  ;; family and reject an address of the other.  A caller-supplied resolver
  ;; chooses its own family; the result is checked before dialling.
  (address-family nil)
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
  ;; Local channel ids owned by things outside the channel table (a control
  ;; master's listener and one mux-control channel per attached client).
  ;; ssh's channel_new() takes the first free slot of its array, so the
  ;; allocator skips both these ids and the channels map, and a released
  ;; control id becomes available again.
  (reserved-channel-ids nil)
  ;; ChannelTimeout: (PATTERN . SECONDS) pairs from ssh_config; a "global"
  ;; pattern bounds the whole connection, and NIL means no timeout at all.
  (channel-timeouts nil)
  channel-timeout-timer
  ;; The connection-wide activity clock for a "global" ChannelTimeout; a new
  ;; channel resets it, as ssh's channel_register_fds does.
  (channel-last-used nil)
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
  ;; channels.c's c->remote_name, shown by -O channels for forwarded
  ;; connections.  Sessions and mux-control channels get theirs from the
  ;; mux layer.
  (remote-name nil)
  ;; ChannelTimeout support: the extended type a session request gives the
  ;; channel ("session:command", "session:subsystem:git-upload-pack", ...),
  ;; the resolved inactivity limit in seconds, and when it was last used.
  ;; A limit of 0, or no LAST-USED, means the channel does not time out.
  (x-type nil)
  (inactive-timeout 0)
  (last-used nil)
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
  ;; ForwardAgent: the request goes out after the peer confirms the session,
  ;; before the pty, env and exec requests, as ssh orders it.
  (pending-agent-request nil)
  ;; ForwardX11: the x11-req request goes out once the peer confirms the
  ;; session, before env and exec.
  (pending-x11-request nil)
  ;; ssh asks for a reply to x11-req and treats a refusal as a warning, so the
  ;; answer is matched here instead of becoming a channel error.  Replies only
  ;; follow requests that asked for one, in order, and this is the first.
  (x11-reply-pending nil)
  ;; An accepted x11 channel buffers the X11 setup message until the whole
  ;; header is present, so the fake cookie can be replaced exactly once.
  (x11-buffer (make-array 0 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer 0))
  (x11-setup-done nil)
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
  ;; An agent-forwarding channel's raw local socket.
  (target-fd-relay nil)
  (target-fd-eof nil)
  (on-data nil)
  (on-open nil)
  (on-eof nil)
  (on-exit nil)
  (on-close nil)
  (on-error nil)
  ;; A mux-proxy channel: every CHANNEL message from the server is handed to
  ;; this function instead of the usual handlers, and relayed to the proxy
  ;; client with its channel id restored.
  (relay nil)
  ;; The local descriptor -O channels shows for a forwarded connection.
  (display-fd nil))

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
    ((ssh-client-mux-fd client)
     (when (ssh-client-mux-watcher client)
       (ignore-errors
        (cl-pnet:fd-unwatch (ssh-client-mux-watcher client)))
       (setf (ssh-client-mux-watcher client) nil))
     (ignore-errors
       (cl-pnet-sockets:close-open-fd (ssh-client-mux-fd client)))
     (setf (ssh-client-mux-fd client) nil))
    ((ssh-client-pipe client) (ssh-proxy-close client))
    ((ssh-client-connection client)
     (cl-pnet:close-connection (ssh-client-connection client)))))

(defun ssh-client-transport-fd (client)
  "The socket CLIENT reads from, when its transport is a socket.

A ProxyCommand pipe is not one, and neither is an unconnected client, so
both answer NIL.  A bound direct connection (and a descriptor received
with ProxyUseFdpass) is a socket stored without a CL-PNET connection."
  (or (ssh-client-mux-fd client)
      (let ((connection (ssh-client-connection client)))
        (and connection (cl-pnet:connection-fileno connection)))
      (let ((proxy (ssh-client-pipe client)))
        (when (and proxy
                   (not (ssh-proxy-closed proxy))
                   (ssh-proxy-close-fds proxy))
          (ssh-proxy-read-fd proxy)))))

(defmethod ssh-client-connection-endpoints ((client ssh-client))
  "CLIENT's socket endpoints; a ProxyCommand pipe has none."
  (let ((fd (ssh-client-transport-fd client)))
    (when (and fd (integerp fd) (not (minusp fd)))
      (ssh-socket-endpoints fd))))

(defmethod ssh-client-traffic-stats ((client ssh-client))
  "OpenSSH's packet, block and byte counters in each direction."
  (list :received-packets (ssh-client-received-packets client)
        :received-blocks (ssh-client-received-blocks client)
        :received-bytes (ssh-client-received-bytes client)
        :sent-packets (ssh-client-sent-packets client)
        :sent-blocks (ssh-client-sent-blocks client)
        :sent-bytes (ssh-client-sent-bytes client)))

;;; ---- Connect timeout and server-alive keepalives ----

(defun ssh-client-cancel-timer (timer)
  "Stop TIMER when it is set, answering NIL for the caller to store."
  (when timer
    (cl-pnet:timer-stop timer))
  nil)

(defun ssh-client-stop-timers (client)
  "Disarm CLIENT's connection timers, once."
  (setf (ssh-client-connect-timer client)
        (ssh-client-cancel-timer (ssh-client-connect-timer client))
        (ssh-client-retry-timer client)
        (ssh-client-cancel-timer (ssh-client-retry-timer client))
        (ssh-client-alive-timer client)
        (ssh-client-cancel-timer (ssh-client-alive-timer client))
        (ssh-client-channel-timeout-timer client)
        (ssh-client-cancel-timer (ssh-client-channel-timeout-timer client))
        (ssh-client-rekey-timer client)
        (ssh-client-cancel-timer (ssh-client-rekey-timer client))))

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
                 :kind :connect
                 :host (ssh-client-connect-host client)
                 :port (or (ssh-client-connect-port client)
                           (ssh-client-port client))
                 :reason "Connection timed out"
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

;;; ---- Channel inactivity timeouts ----
;;;
;;; OpenSSH's ChannelTimeout closes a channel that has seen no traffic for
;;; its pattern's interval, and a "global" interval closes every channel once
;;; none of them has been used for that long.  One timer for the connection is
;;; enough: activity only moves LAST-USED, so a timer that fires early simply
;;; recomputes and rearms.

(defun ssh-client-now ()
  "Monotonic time in seconds, for the channel timers."
  (/ (get-internal-real-time) internal-time-units-per-second))


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

(defun ssh-client-remote-id (client)
  "CLIENT's peer as ssh's sshpkt_fmt_connection_id names it.

OpenSSH reports the address and port it dialled, recording them when the
connection is set up so they are still available after the socket closes.
A transport whose read side is not a socket - a ProxyCommand pipe - has no
peer address at all, so ssh falls back to the \"UNKNOWN port 65535\" it uses
in exactly that case."
  (multiple-value-bind (local-ip local-port remote-ip remote-port)
      (ssh-client-connection-endpoints client)
    (declare (ignore local-ip local-port))
    (let ((remote-ip (or (ssh-client-peer-ip client) remote-ip))
          (remote-port (or (ssh-client-peer-port client) remote-port)))
      (if (and remote-ip remote-port)
          (format nil "~A port ~D" remote-ip remote-port)
          "UNKNOWN port 65535"))))

(defun ssh-client-data-pending-p (client)
  "True when data from CLIENT's peer is waiting to be read."
  (or (plusp (fill-pointer (ssh-client-incoming client)))
      (let ((fd (ssh-client-transport-fd client)))
        (and fd (integerp fd) (not (minusp fd))
             (ssh-socket-data-pending-p fd)))))

(defun ssh-client-send-failed (client status)
  "Report a failed write of CLIENT's banner or packets.

OpenSSH's packet layer turns a reset into sshpkt_fatal()'s \"Connection
reset by ...\", and a broken pipe into the \"Connection closed by ...\" it
uses for EOF.  The errno is the only evidence left once the write fails, so
that mapping happens here; any other write error keeps its own message, as
does a write error during the session, where ssh reports it differently."
  (let* ((code (abs (or status 0)))
         (reset (member code '(54 104 10054)))
         (closed (member code '(32 10058))))
    (if (or (not (or reset closed))
            (eq (ssh-client-phase client) :ready))
        (ssh-client-fail
         client
         (make-condition 'ssh-connection-error
                         :detail (format nil "send failed (~A)" status)))
        (let ((message (format nil "Connection ~:[closed~;reset~] by ~A"
                               reset
                               (ssh-client-remote-id client))))
          (when (and reset (eq (ssh-client-phase client) :version)
                     (not (ssh-client-data-pending-p client)))
            ;; kex_exchange_identification() reports the failed banner read
            ;; through error_f() before the packet layer's own message.  When
            ;; the peer's banner is already waiting, that read would have
            ;; succeeded, so ssh never prints the line.
            (setf message
                  (format nil "kex_exchange_identification: read: ~
                               Connection reset by peer~%~A"
                          message)))
          (ssh-client-fail
           client
           (make-condition 'ssh-connection-error
                           :kind :closed
                           :reason message
                           :detail message))))))

(defun ssh-client-send-bytes (client octets)
  "Queue OCTETS on CLIENT's connection. NIL once the client is closed."
  (unless (ssh-client-closed client)
    (cond
      ((ssh-client-mux-fd client)
       ;; The control master carries the SSH connection: packets are written
       ;; to its descriptor unchanged, without encryption or framing of our
       ;; own beyond the mux packet header built by TRANSMIT.
       (handler-case
           (progn
             (cl-pnet-sockets:write-octets
              (ssh-client-mux-fd client) octets)
             t)
         (error (condition) (ssh-client-fail client condition) nil)))
      ((ssh-client-pipe client)
       (ssh-proxy-send client octets))
      (t
       (let ((connection (ssh-client-connection client)))
         (when connection
           (handler-case
               (cl-pnet:send-data
                connection octets
                :on-error (lambda (status)
                            (ssh-client-send-failed client status)))
             (error (condition) (ssh-client-fail client condition))))))))
  (not (ssh-client-closed client)))

(defun ssh-client-mux-frame (payload)
  "PAYLOAD as OpenSSH's mux-mode packet: u32 length, padlen 0, type, body.

Only the connection protocol travels in mux mode, and there is no padding or
encryption of its own: the master carries the packets to the server."
  (when (<= 80 (aref payload 0) 127)
    (let ((writer (ssh-writer (+ 5 (length payload)))))
      (ssh-write-u32 writer (+ 1 (length payload)))
      (ssh-write-u8 writer 0)
      (ssh-write-octets writer payload)
      (ssh-writer-output writer))))

(defun ssh-client-transmit-payload (client payload)
  "Frame and send PAYLOAD now, counting it against the rekey limits."
  (if (ssh-client-mux-mode client)
      (let ((octets (ssh-client-mux-frame payload)))
        (when (and octets (ssh-client-send-bytes client octets))
          (incf (ssh-client-sent-packets client))
          (incf (ssh-client-sent-bytes client) (length octets))))
      (let* ((cipher (ssh-client-cipher client))
             (octets (ssh-encode-packet payload cipher))
             (counted (ssh-packet-counted-length (length octets) cipher :send)))
        (when (ssh-client-send-bytes client octets)
          (incf (ssh-client-sent-packets client))
          (incf (ssh-client-sent-bytes client) (length octets))
          (incf (ssh-client-sent-blocks client)
                (floor counted (ssh-cipher-state-block-size cipher)))))))

(defun ssh-client-send-payload (client payload)
  "Frame and send one protocol PAYLOAD, deferring it during a rekey.

OpenSSH queues every non-key-exchange packet while a rekey is under way and
starts a rekey before sending a packet that would exceed RekeyLimit.  The
queue holds payloads, not wire octets, so each is encrypted with the keys in
force when it finally goes out."
  (cond
    ((ssh-client-mux-mode client)
     (ssh-client-transmit-payload client payload))
    ((and (not (ssh-client-kex-message-p (aref payload 0)))
          (ssh-client-rekeying client))
     (setf (ssh-client-outgoing-queue client)
           (nconc (ssh-client-outgoing-queue client) (list payload)))
     nil)
    ((and (not (ssh-client-kex-message-p (aref payload 0)))
          (ssh-client-need-rekey-p client (length payload)))
     (setf (ssh-client-outgoing-queue client)
           (nconc (ssh-client-outgoing-queue client) (list payload)))
     (ssh-client-start-rekey client)
     nil)
    (t
     (ssh-client-transmit-payload client payload))))

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
