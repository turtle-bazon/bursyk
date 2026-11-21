(in-package #:cl-pnet-ssh)

;;;; Server state.  The protocol core (wire, packets, keys, KEX) is shared
;;;; with the client; this file holds only what the server role adds: a
;;;; listener, one record per accepted connection, and the channels it serves.
;;;;
;;;; Everything is driven by cl-pnet callbacks.  No function here waits for
;;;; the peer: a request that needs work (an authorized-keys file, a command)
;;;; hands that work to the caller's callback and returns.

(defstruct (ssh-server (:constructor %make-ssh-server))
  (address "0.0.0.0")
  (version +ssh-server-version+)
  (port 22)
  listener
  (host-keys nil)
  ;; HostCertificate blobs paired with those keys.  A certificate is
  ;; presented instead of its plain key when the client selects a
  ;; certificate algorithm.
  (host-certificates nil)
  authorized-keys
  authorize
  ;; Called once per (SESSION USER) before any authentication method runs;
  ;; the answer is cached for that pair.  NIL means every user is admitted.
  authorize-user
  ;; The sshd_config the connection-scoped Match blocks are resolved from.
  ;; NIL means the program configured the server directly and there is
  ;; nothing to re-read per connection.
  sshd-config
  ;; A function of USER returning the group names used by Match Group, or
  ;; NIL when the program has no group lookup.  sshd asks the C library.
  user-groups
  ;; sshd's Banner: text sent before the first authentication reply, a
  ;; function of no arguments returning it (so the file can change without a
  ;; restart), or NIL for none.
  banner
  ;; PermitUserEnvironment: NIL and :NO permit nothing, :YES lets a user set
  ;; any variable, and a list of patterns is sshd's allowlist.
  (permit-user-environment nil)
  ;; SetEnv assignments from the config, applied after the user's own
  ;; environment so an administrator's value wins.
  (set-env '())
  ;; sshd's defaults: six failed attempts per connection, ten session
  ;; channels.  A program tightens or relaxes them from its config.
  (max-auth-tries 6)
  (max-sessions 10)
  ;; sshd's connection timers, in seconds.  LoginGraceTime bounds the whole
  ;; unauthenticated phase; ClientAliveInterval of zero sends no probes, and
  ;; ClientAliveCountMax of zero never disconnects.
  (login-grace-time +ssh-server-default-login-grace-time+)
  (client-alive-interval +ssh-server-default-client-alive-interval+)
  (client-alive-count-max +ssh-server-default-client-alive-count-max+)
  ;; MaxStartups: BEGIN:RATE:FULL, sshd's 10:30:100 by default.  A
  ;; connection is unauthenticated from accept until its first success.
  (max-startups-begin 10)
  (max-startups-rate 30)
  (max-startups-full 100)
  ;; PerSourceMaxStartups; NIL is sshd's "none", no per-source limit.
  (per-source-max-startups nil)
  ;; PerSourceNetBlockSize; 32:128 treats every address by itself.
  (per-source-net-block-size-ipv4 32)
  (per-source-net-block-size-ipv6 128)
  ;; PerSourcePenalties: (EXPIRY ACTIVE REASON) per masked source network.
  (per-source-penalties (make-hash-table :test #'equal))
  ;; UnusedConnectionTimeout in seconds; 0 is sshd's "none".
  (unused-connection-timeout 0)
  ;; ChannelTimeout: (TYPE-PATTERN . SECONDS) pairs, in the order the winning
  ;; line gave them, or :NONE when the directive disables every timeout.
  ;; A Match block's value replaces this one for that connection.
  (channel-timeouts nil)
  ;; Whether accepted sockets ask the system for TCP keepalives.
  (tcp-keep-alive t)
  (accept-env nil)
  (on-session nil)
  (on-channel nil)
  (on-direct-tcpip nil)
  ;; A function of (SESSION PATH) answering whether a client's
  ;; direct-streamlocal@openssh.com channel may connect to PATH.
  (on-direct-streamlocal nil)
  ;; Remote forwarding: the application owns the listener, because it knows
  ;; which addresses and ports its user is willing to expose.  The first
  ;; returns the bound port (or NIL to refuse); the second returns true once
  ;; the listener is closed.
  (on-tcpip-forward nil)
  (on-cancel-tcpip-forward nil)
  ;; Stream-local remote forwarding, as (SESSION PATH) functions.
  (on-streamlocal-forward nil)
  (on-cancel-streamlocal-forward nil)
  (on-error nil)
  (on-close nil)
  (sessions (make-hash-table :test #'eq))
  (connections (make-hash-table :test #'eq))
  (closed nil))

(defun ssh-server-host-key (server)
  "The first host key SERVER presents.

A server may hold several; this returns the preferred one it can actually
present after RequiredRSASize, for callers that only want to describe it."
  (first (ssh-server-presentable-host-keys server)))

(defstruct (ssh-session (:constructor %make-ssh-session))
  server
  connection
  remote-address
  (phase :version)
  (incoming (make-array 4096 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))
  (client-version nil)
  (server-version +ssh-server-version+)
  (session-id nil)
  (cipher (ssh-make-cipher-state))
  (client-kexinit nil)
  (server-kexinit nil)
  (kexinit-sent nil)
  (negotiated nil)
  (ephemeral-private nil)
  (ephemeral-public nil)
  (host-key-blob nil)
  (derived-keys nil)
  (strict-kex nil)
  (ignore-next-kex-packet nil)
  (rekey nil)
  (keys-sent nil)
  (keys-received nil)
  (authenticated nil)
  (user nil)
  (authorized-key nil)
  ;; AuthenticationMethods progress.  AUTH-METHOD-LISTS is NIL when no
  ;; multi-method requirement applies, a list of remaining method lists, or
  ;; :IMPOSSIBLE when no configured list can be completed here.  The rest
  ;; record what has already succeeded for this connection.
  (auth-method-lists nil)
  (auth-used-keys '())
  (auth-merged-options nil)
  (auth-merged-key-env '())
  ;; ExposeAuthInfo lines, one per successful method, in completion order.
  (auth-info-lines '())
  ;; The environment= options of the authorized_keys line that authenticated
  ;; the user, applied only when PermitUserEnvironment allows them.
  (key-env '())
  ;; The rest of that line's options: no-pty, from=, command=, permitopen=
  ;; and so on.  NIL means the line had no options (every default allowed).
  (authorization nil)
  ;; The sshd_config resolved for this connection's Match blocks, and the
  ;; user it was resolved for, so a retry by the same name reuses it.
  (config nil)
  (config-user nil)
  ;; Userauth bookkeeping: a fresh connection starts at zero, and the first
  ;; "none" probe is exempt from the failure count, as in sshd.
  (auth-attempts 0)
  (auth-failures 0)
  ;; PubkeyAuthOptions max-pk-ok: rejected unsigned publickey probes before
  ;; they start counting against MaxAuthTries.
  (pk-ok-failures 0)
  ;; PerSourcePenalties reasons observed for this connection.
  (invalid-user-p nil)
  (grace-exceeded-p nil)
  (refused-p nil)
  (penalty-applied-p nil)
  (allowed-users '())
  (channels (make-hash-table :test #'eql))
  (next-channel-id 0)
  ;; Connection timers.  LAST-INPUT-TIME is monotonic seconds and is moved
  ;; whenever bytes arrive or a probe is sent, as sshd's last_client_time is.
  login-grace-timer
  client-alive-timer
  ;; Armed while the connection has no channels open, as sshd's
  ;; UnusedConnectionTimeout is; NIL when the setting is off or a channel is up.
  unused-connection-timer
  ;; Armed for the earliest ChannelTimeout deadline across the session's
  ;; open channels; activity moves the deadlines without rearming it.
  channel-timeout-timer
  (client-alive-misses 0)
  (last-input-time 0)
  (closed nil)
  (close-reason nil)
  (window 2097152)
  (max-packet 32768))

(defstruct (ssh-server-channel (:constructor %make-ssh-server-channel))
  session
  local-id
  (remote-id nil)
  (type "session")
  ;; sshd's extended type, which ChannelTimeout selects on: session:shell,
  ;; session:command or session:subsystem:NAME.  NIL means TYPE itself.
  (x-type nil)
  ;; Seconds of inactivity before this channel is closed, 0 for none, and the
  ;; monotonic time of the last byte read or written (0 before it opens).
  (inactive-timeout 0)
  (last-used 0)
  (open-extra (make-array 0 :element-type '(unsigned-byte 8)))
  (state :opening)
  (remote-window 0)
  (remote-max-packet 0)
  (local-window 0)
  (local-max-packet 32768)
  (write-queue (make-array 0 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))
  (write-callbacks nil)
  (pending-env nil)
  (env nil)
  (command nil)
  (subsystem nil)
  ;; The Unix-domain path a direct-streamlocal channel targets.
  (streamlocal-path nil)
  ;; PTY-REQ stores the peer's terminal here, so the application that starts
  ;; the shell or command can size it before the first output.
  (pty-p nil)
  (pty-term nil)
  (pty-columns 0)
  (pty-rows 0)
  (pty-modes nil)
  (want-eof nil)
  (sent-eof nil)
  (want-close nil)
  (sent-close nil)
  (eof-received nil)
  (exit-status nil)
  (target nil)
  (target-eof nil)
  (on-data nil)
  (on-eof nil)
  (on-exec nil)
  (on-pty nil)
  (on-shell nil)
  (on-subsystem nil)
  (on-window-change nil)
  (on-close nil)
  (on-error nil))

(defun ssh-session-closed-p (session)
  (ssh-session-closed session))

(defun ssh-session-buffer-append (session data)
  "Append DATA to SESSION's receive buffer."
  (let ((buffer (ssh-session-incoming session)))
    (iter (for octet in-vector data)
      (vector-push-extend octet buffer))))

(defun ssh-session-buffer-consume (session count)
  "Drop the first COUNT octets of SESSION's receive buffer."
  (let ((buffer (ssh-session-incoming session)))
    (when (plusp count)
      (replace buffer buffer :start1 0 :start2 count)
      (decf (fill-pointer buffer) count))
    buffer))

(defun ssh-session-buffer-empty-p (session)
  (zerop (fill-pointer (ssh-session-incoming session))))

(defun ssh-session-close-connection (session)
  ;; Closing is idempotent; do not swallow unrelated errors here.
  (when (ssh-session-connection session)
    (cl-pnet:close-connection (ssh-session-connection session))))

(defun ssh-session-report (session kind value)
  "Report SESSION's end to the server callback KIND selects."
  (let ((server (ssh-session-server session)))
    (ecase kind
      (:error (when (ssh-server-on-error server)
                (funcall (ssh-server-on-error server) session value)))
      (:close (when (ssh-server-on-close server)
                (funcall (ssh-server-on-close server) session value))))))

(defun ssh-session-terminate-channels (session reason kind)
  "Report SESSION's end to every channel not yet closed."
  (let ((channels (iter (for (id channel) in-hashtable
                              (ssh-session-channels session))
                    (collect (cons id channel)))))
    (iter (for (id . channel) in channels)
      (unless (eq (ssh-server-channel-state channel) :closed)
        (setf (ssh-server-channel-state channel) :closed)
        (remhash id (ssh-session-channels session))
        (ecase kind
          (:error (when (ssh-server-channel-on-error channel)
                    (funcall (ssh-server-channel-on-error channel)
                             channel reason)))
          (:close (when (ssh-server-channel-on-close channel)
                    (funcall (ssh-server-channel-on-close channel) channel))))))))

;;; ---- Connection timers ----
;;;
;;; LoginGraceTime bounds the time before authentication, and ClientAlive*
;;; probe an authenticated peer that has gone quiet.  Both run from the event
;;; loop's own timers so nothing here blocks.

(defun ssh-session-now ()
  "Monotonic time in seconds, for the connection timers."
  (/ (get-internal-real-time) internal-time-units-per-second))

(defun ssh-session-cancel-timer (timer)
  "Stop TIMER when it is set, answering NIL for the caller to store."
  (when timer
    (cl-pnet:timer-stop timer))
  nil)

(defun ssh-session-stop-timers (session)
  "Disarm SESSION's login-grace, client-alive and channel timers, once."
  (setf (ssh-session-login-grace-timer session)
        (ssh-session-cancel-timer (ssh-session-login-grace-timer session))
        (ssh-session-client-alive-timer session)
        (ssh-session-cancel-timer (ssh-session-client-alive-timer session))
        (ssh-session-unused-connection-timer session)
        (ssh-session-cancel-timer
         (ssh-session-unused-connection-timer session))
        (ssh-session-channel-timeout-timer session)
        (ssh-session-cancel-timer
         (ssh-session-channel-timeout-timer session))))

(defun ssh-session-start-login-grace-timer (session)
  "Close SESSION if it has not authenticated in LoginGraceTime seconds.

Zero means no limit, and sshd's default of 120 seconds applies when the
server was built without a value."
  (let ((seconds (ssh-server-login-grace-time (ssh-session-server session))))
    (when (and seconds
               (plusp seconds)
               (not (ssh-session-login-grace-timer session))
               (not (ssh-session-closed-p session)))
      (setf (ssh-session-login-grace-timer session)
            (cl-pnet:timer-start
             seconds 0
             (lambda ()
               (setf (ssh-session-login-grace-timer session) nil)
               (unless (or (ssh-session-closed-p session)
                           (ssh-session-authenticated session))
                 (setf (ssh-session-grace-exceeded-p session) t)
                 ;; sshd leaves no disconnect behind: the alarm exits and the
                 ;; socket simply closes.
                 (ssh-session-finish session
                                     "Timeout before authentication"
                                     :close))))))))

(defun ssh-session-schedule-client-alive (session delay)
  "Arm SESSION's next client-alive probe after DELAY seconds."
  (when (and (not (ssh-session-closed-p session))
             (not (ssh-session-client-alive-timer session)))
    (setf (ssh-session-client-alive-timer session)
          (cl-pnet:timer-start
           (max 0.05 delay) 0
           (lambda ()
             (setf (ssh-session-client-alive-timer session) nil)
             (ssh-session-client-alive-tick session))))))

(defun ssh-session-client-alive-tick (session)
  "Probe SESSION if it has been quiet, and disconnect once it stops answering."
  (unless (ssh-session-closed-p session)
    (let* ((server (ssh-session-server session))
           (interval (or (ssh-session-setting
                          session #'ssh-server-config-client-alive-interval)
                         (ssh-server-client-alive-interval server)))
           (count-max (or (ssh-session-setting
                           session
                           #'ssh-server-config-client-alive-count-max)
                          (ssh-server-client-alive-count-max server))))
      (when (and interval (plusp interval))
        (let ((idle (- (ssh-session-now)
                       (ssh-session-last-input-time session))))
          (if (< idle interval)
              ;; Activity arrived while we waited; give it the rest of the
              ;; interval before deciding the peer is quiet.
              (ssh-session-schedule-client-alive
               session (- interval idle))
              ;; sshd increments before it compares, so with the default of
              ;; three a peer is dropped on the fourth quiet probe.
              (progn
                (incf (ssh-session-client-alive-misses session))
                (if (and (plusp count-max)
                         (> (ssh-session-client-alive-misses session)
                            count-max))
                    (ssh-session-finish
                     session "Timeout, client not responding" :close)
                    (progn
                      (ssh-session-send-keepalive session)
                      (setf (ssh-session-last-input-time session)
                            (ssh-session-now))
                      (ssh-session-schedule-client-alive session
                                                         interval))))))))))

(defun ssh-session-start-client-alive-timer (session)
  "Start probing SESSION once authentication has finished."
  (let ((interval (or (ssh-session-setting
                       session #'ssh-server-config-client-alive-interval)
                      (ssh-server-client-alive-interval
                       (ssh-session-server session)))))
    (when (and interval
               (plusp interval)
               (not (ssh-session-client-alive-timer session))
               (not (ssh-session-closed-p session)))
      (setf (ssh-session-last-input-time session) (ssh-session-now)
            (ssh-session-client-alive-misses session) 0)
      (ssh-session-schedule-client-alive session interval))))

(defun ssh-session-note-input (session)
  "Record that SESSION's peer sent bytes, resetting its keepalive misses."
  (setf (ssh-session-last-input-time session) (ssh-session-now)
        (ssh-session-client-alive-misses session) 0))

(defun ssh-session-finish (session reason kind)
  "Close SESSION once, reporting REASON through the callback KIND selects."
  (unless (ssh-session-closed session)
    (setf (ssh-session-closed session) t
          (ssh-session-phase session) :closed
          (ssh-session-close-reason session) reason)
    (ssh-server-session-penalty session)
    (ssh-session-stop-timers session)
    (ssh-session-terminate-channels session reason kind)
    (ssh-session-close-connection session)
    (let ((server (ssh-session-server session)))
      (when server
        (remhash session (ssh-server-sessions server))
        (when (ssh-session-connection session)
          (remhash (ssh-session-connection session)
                   (ssh-server-connections server)))))
    (ssh-session-report session kind reason)))

(defun ssh-session-fail (session condition)
  "End SESSION because of CONDITION, telling the server once."
  (ssh-session-finish session condition :error))

(defun ssh-session-send-bytes (session octets)
  "Queue OCTETS on SESSION's connection.  NIL once it is closed."
  (unless (ssh-session-closed session)
    (let ((connection (ssh-session-connection session)))
      (when connection
        (handler-case
            (cl-pnet:send-data
             connection octets
             :on-error (lambda (status)
                         (ssh-session-fail
                          session
                          (make-condition 'ssh-connection-error
                                          :detail (format nil "send failed (~A)"
                                                          status)))))
          (error (condition) (ssh-session-fail session condition))))))
  (not (ssh-session-closed session)))

(defun ssh-session-send-payload (session payload)
  "Frame and send one protocol PAYLOAD."
  (ssh-session-send-bytes session
                          (ssh-encode-packet payload (ssh-session-cipher session))))

(defun ssh-session-send-payload-and-close (session payload reason)
  "Send PAYLOAD, then close SESSION with REASON once it is on the wire.

Closing immediately would discard the queued bytes, so the DISCONNECT that
explains a policy refusal would never reach the client."
  (let ((connection (ssh-session-connection session)))
    (if (or (ssh-session-closed session) (null connection))
        (ssh-session-finish session reason :close)
        (handler-case
            (cl-pnet:send-data
             connection
             (ssh-encode-packet payload (ssh-session-cipher session))
             :on-write (lambda (count)
                         (declare (ignore count))
                         (ssh-session-finish session reason :close))
             :on-error (lambda (status)
                         (declare (ignore status))
                         (ssh-session-finish session reason :close)))
          (error ()
            (ssh-session-finish session reason :close))))))

(defun ssh-session-channel-for (session local-id)
  (gethash local-id (ssh-session-channels session)))
