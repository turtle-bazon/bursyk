(in-package #:cl-pnet-ssh)

;;;; Channels (RFC 4254): opening, exec requests, data in both directions,
;;;; flow control, and the session close handshake. A future server reuses
;;;; the message formats; only this client-side bookkeeping is role-specific.

(defun ssh-channel-send (channel payload)
  "Send PAYLOAD, which already names CHANNEL's remote id."
  (ssh-client-send-payload (ssh-channel-client channel) payload))

(defun ssh-channel-send-message (channel type &key fields)
  "A channel message with TYPE, CHANNEL's remote id, and FIELDS as a thunk."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer type)
    (ssh-write-u32 writer (ssh-channel-remote-id channel))
    (when fields (funcall fields writer))
    (ssh-channel-send channel (ssh-writer-output writer))))

(defun ssh-channel-adjust-window (channel amount)
  "Give AMOUNT octets of receive window back to the peer."
  (when (and (plusp amount) (eq (ssh-channel-state channel) :open))
    (incf (ssh-channel-local-window channel) amount)
    (ssh-channel-send-message
     channel +ssh-msg-channel-window-adjust+
     :fields (lambda (writer) (ssh-write-u32 writer amount)))))

;;; ---- Opening ----

(defun ssh-channel-open-payload (channel)
  "The CHANNEL_OPEN message for CHANNEL."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-channel-open+)
    (ssh-write-text writer (ssh-channel-type channel))
    (ssh-write-u32 writer (ssh-channel-local-id channel))
    (ssh-write-u32 writer (ssh-channel-local-window channel))
    (ssh-write-u32 writer (ssh-channel-local-max-packet channel))
    (ssh-write-octets writer (ssh-channel-open-extra channel))
    (ssh-writer-output writer)))

(defun ssh-client-allocate-channel-id (client)
  "Return the lowest local channel id CLIENT may use.

ssh keeps channels in a slot array and channel_new() takes the first free
slot, so a closed channel's number is reused.  Matching that keeps channel
numbers in \"channel N:\" diagnostics identical."
  (let ((channels (ssh-client-channels client))
        (reserved (ssh-client-reserved-channel-ids client)))
    (loop for id from 0
          unless (or (gethash id channels) (member id reserved))
            return id)))

(defun ssh-open-channel (client type &key open-extra on-data on-open on-eof
                                      on-exit on-close on-error
                                      window max-packet)
  "Register a channel of TYPE on CLIENT and ask the peer for it.

The returned channel is usable immediately: requests and writes made before
the open confirmation are queued and flushed once the peer answers.  ON-OPEN
runs once the peer has confirmed the channel, before any of its data.
WINDOW and MAX-PACKET override the client defaults; a mux proxy passes the
values its downstream client advertised."
  (let* ((id (ssh-client-allocate-channel-id client))
         (channel (%make-ssh-channel
                   :client client
                   :local-id id
                   :type type
                   :open-extra (or open-extra
                                   (make-array 0 :element-type '(unsigned-byte 8)))
                   :local-window (or window (ssh-client-window client))
                   :local-max-packet (or max-packet
                                         (ssh-client-max-packet client))
                   :on-data on-data :on-open on-open :on-eof on-eof
                   :on-exit on-exit
                   :on-close on-close :on-error on-error)))
    (setf (ssh-client-channel-last-used client) (ssh-client-now))
    (setf (gethash id (ssh-client-channels client)) channel)
    (ssh-client-run-when-ready
     client (lambda () (ssh-channel-send channel (ssh-channel-open-payload channel))))
    channel))

(defun ssh-client-reserve-channel-ids (client count)
  "Reserve COUNT fresh local channel ids for users outside the channel table.

ssh creates its mux listener and one mux-control channel per attached client
as channels of their own, so they occupy ids even though they carry no SSH
channel.  A control master reserves their ids to keep the numbers in
\"channel N:\" diagnostics identical; reserving an id also keeps later
allocations from reusing it.  Returns the reserved ids so the caller can
release them with SSH-CLIENT-RELEASE-CHANNEL-IDS."
  (let ((ids nil))
    (dotimes (index count)
      (declare (ignore index))
      (let ((id (ssh-client-allocate-channel-id client)))
        (push id (ssh-client-reserved-channel-ids client))
        (push id ids)))
    (nreverse ids)))

(defun ssh-client-release-channel-ids (client ids)
  "Give reserved channel IDS back, as a closed mux-control channel would."
  (setf (ssh-client-reserved-channel-ids client)
        (set-difference (ssh-client-reserved-channel-ids client) ids
                        :test #'=)))

(defun ssh-client-forward-agent-path (client)
  "The Unix socket CLIENT forwards when ForwardAgent is on, or NIL.

ForwardAgent's path form wins over SSH_AUTH_SOCK.  A path that does not
exist is treated as no agent at all, as ssh's check_agent_present disables
forwarding rather than asking the server and failing every channel."
  (let ((path (or (ssh-client-forward-agent-sock-path client)
                  (uiop:getenv "SSH_AUTH_SOCK"))))
    (and path (plusp (length path)) (probe-file path) path)))

(defun ssh-channel-send-agent-request (channel)
  "Ask the peer to forward authentication-agent connections on CHANNEL.

RFC 9987's agent-req is used once the server advertised EXT_INFO's
agent-forward extension; otherwise the OpenSSH auth-agent-req name is the
one every server understands.  Neither wants a reply."
  (let ((request
          (if (ssh-client-agent-forward-supported
               (ssh-channel-client channel))
              "agent-req"
              "auth-agent-req@openssh.com")))
    (ssh-channel-send-message
     channel +ssh-msg-channel-request+
     :fields (lambda (writer)
               (ssh-write-text writer request)
               (ssh-write-boolean writer nil)))))

(defun ssh-open-session (client &key on-data on-eof on-exit on-close on-error)
  "Open a session channel; commands run on it with SSH-CHANNEL-EXEC.

When CLIENT's ForwardAgent is on and an agent socket exists, the agent
forwarding request is queued for the moment the peer confirms the channel."
  (let ((channel
          (ssh-open-channel client "session"
                            :on-data on-data :on-eof on-eof :on-exit on-exit
                            :on-close on-close :on-error on-error)))
    (when (and (ssh-client-forward-agent client)
               (ssh-client-forward-agent-path client))
      (setf (ssh-channel-pending-agent-request channel) t))
    (when (ssh-client-prepare-x11 client)
      (setf (ssh-channel-pending-x11-request channel) t))
    channel))

(defun ssh-open-direct-tcpip (client host port
                              &key (origin-address "0.0.0.0") (origin-port 0)
                                   on-data on-open on-eof on-close on-error)
  "Ask the peer to connect to HOST:PORT and carry the bytes on a channel."
  (let ((writer (ssh-writer)))
    (ssh-write-text writer host)
    (ssh-write-u32 writer port)
    (ssh-write-text writer origin-address)
    (ssh-write-u32 writer origin-port)
    (ssh-open-channel client "direct-tcpip"
                      :open-extra (ssh-writer-output writer)
                      :on-data on-data :on-open on-open :on-eof on-eof
                      :on-close on-close :on-error on-error)))

(defun ssh-open-direct-streamlocal (client path
                                    &key on-data on-open on-eof on-close
                                      on-error)
  "Ask the peer to connect to the Unix socket PATH and carry its bytes."
  (let ((writer (ssh-writer)))
    (ssh-write-text writer path)
    ;; Reserved for future owner/mode information.
    (ssh-write-text writer "")
    (ssh-write-u32 writer 0)
    (ssh-open-channel client "direct-streamlocal@openssh.com"
                      :open-extra (ssh-writer-output writer)
                      :on-data on-data :on-open on-open :on-eof on-eof
                      :on-close on-close :on-error on-error)))

;;; ---- Requests ----

(defun ssh-channel-send-exec (channel command)
  (ssh-channel-send-message
   channel +ssh-msg-channel-request+
   :fields (lambda (writer)
             (ssh-write-text writer "exec")
             (ssh-write-boolean writer t)
             (ssh-write-text writer command)))
  (ssh-channel-set-x-type channel "session:command"))

(defun ssh-channel-send-subsystem (channel subsystem)
  "Ask the peer to run SUBSYSTEM on CHANNEL's session."
  (ssh-channel-send-message
   channel +ssh-msg-channel-request+
   :fields (lambda (writer)
             (ssh-write-text writer "subsystem")
             (ssh-write-boolean writer t)
             (ssh-write-text writer subsystem)))
  (ssh-channel-set-x-type
   channel (concatenate 'string "session:subsystem:" subsystem)))

(defun ssh-channel-send-env (channel name value)
  "Ask the peer to set NAME=VALUE for commands on CHANNEL's session."
  (ssh-channel-send-message
   channel +ssh-msg-channel-request+
   :fields (lambda (writer)
             (ssh-write-text writer "env")
             (ssh-write-boolean writer nil)
             (ssh-write-text writer name)
             (ssh-write-text writer value))))

(defun ssh-channel-env (channel name value)
  "Set NAME=VALUE for commands run later on CHANNEL.

Like SSH-CHANNEL-EXEC this queues while the channel opens, and a queued
exec follows the queued env requests.  The peer applies the value only when
its policy allows the name (sshd: AcceptEnv), so ask for names the remote
side is known to accept."
  (ecase (ssh-channel-state channel)
    (:opening
     (setf (ssh-channel-pending-env channel)
           (append (ssh-channel-pending-env channel)
                   (list (cons name value)))))
    (:open (ssh-channel-send-env channel name value))
    (:closing nil)
    (:closed (error 'ssh-channel-error
                    :channel channel :detail "channel is closed")))
  channel)

(defun ssh-channel-exec (channel command)
  "Run COMMAND on CHANNEL's session, or queue it until the channel opens."
  (ecase (ssh-channel-state channel)
    (:opening (setf (ssh-channel-pending-exec channel) command))
    (:open (ssh-channel-send-exec channel command))
    (:closing nil)
    (:closed (error 'ssh-channel-error
                    :channel channel :detail "channel is closed")))
  channel)

(defun ssh-channel-subsystem (channel subsystem)
  "Run SUBSYSTEM on CHANNEL's session, or queue it until the channel opens."
  (ecase (ssh-channel-state channel)
    (:opening (setf (ssh-channel-pending-subsystem channel) subsystem))
    (:open (ssh-channel-send-subsystem channel subsystem))
    (:closing nil)
    (:closed (error 'ssh-channel-error
                    :channel channel :detail "channel is closed")))
  channel)

;;; ---- Writing and flow control ----

(defun ssh-channel-queue (channel data)
  (let ((queue (ssh-channel-write-queue channel)))
    (iter (for octet in-vector (ssh-ensure-octets data))
      (vector-push-extend octet queue))))

(defun ssh-channel-drop-queue (channel count)
  (let ((queue (ssh-channel-write-queue channel)))
    (replace queue queue :start1 0 :start2 count)
    (decf (fill-pointer queue) count)))

(defun ssh-channel-flush (channel)
  "Send as much queued data as the peer's window and packet size allow."
  (let ((queue (ssh-channel-write-queue channel))
        (sent nil))
    (iter (while (and (eq (ssh-channel-state channel) :open)
                      (plusp (fill-pointer queue))
                      (plusp (ssh-channel-remote-window channel))))
      (let ((count (min (fill-pointer queue)
                        (ssh-channel-remote-window channel)
                        (max 1 (ssh-channel-remote-max-packet channel)))))
        (let ((chunk (subseq queue 0 count)))
          (ssh-channel-send-message
           channel +ssh-msg-channel-data+
           :fields (lambda (writer) (ssh-write-string writer chunk))))
        (decf (ssh-channel-remote-window channel) count)
        (ssh-channel-drop-queue channel count)
        (setf sent t)))
    (when sent
      (ssh-client-channel-note-activity channel))
    (ssh-channel-after-queue channel)))

(defun ssh-channel-after-queue (channel)
  "Run deferred work once nothing is left queued."
  (when (zerop (fill-pointer (ssh-channel-write-queue channel)))
    (let ((callbacks (nreverse (ssh-channel-write-callbacks channel))))
      (setf (ssh-channel-write-callbacks channel) nil)
      (iter (for callback in callbacks) (funcall callback)))
    (when (and (ssh-channel-want-eof channel)
               (not (ssh-channel-sent-eof channel))
               (eq (ssh-channel-state channel) :open))
      (setf (ssh-channel-sent-eof channel) t)
      (ssh-channel-send-message channel +ssh-msg-channel-eof+))
    (when (and (ssh-channel-want-close channel)
               (not (ssh-channel-sent-close channel))
               (member (ssh-channel-state channel) '(:open :closing)))
      (setf (ssh-channel-sent-close channel) t
            (ssh-channel-state channel) :closing)
      (ssh-channel-send-message channel +ssh-msg-channel-close+))))

(defun ssh-channel-write (channel data &key on-done)
  "Queue DATA for the peer's stdin; ON-DONE runs when it has all been sent."
  (when (eq (ssh-channel-state channel) :closed)
    (error 'ssh-channel-error :channel channel :detail "channel is closed"))
  (ssh-channel-queue channel data)
  (when on-done
    (push on-done (ssh-channel-write-callbacks channel)))
  (ssh-channel-flush channel)
  channel)

(defun ssh-channel-eof (channel)
  "Say no more input follows, after everything already queued."
  (setf (ssh-channel-want-eof channel) t)
  (ssh-channel-flush channel)
  channel)

(defun ssh-channel-close (channel)
  "Start the close handshake, after everything already queued."
  (when (member (ssh-channel-state channel) '(:open :opening))
    (setf (ssh-channel-want-close channel) t)
    (ssh-channel-flush channel))
  channel)

;;; ---- Incoming messages ----

(defun ssh-client-send-channel-open-failure (client sender reason)
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-channel-open-failure+)
    (ssh-write-u32 writer sender)
    (ssh-write-u32 writer 1)
    (ssh-write-text writer reason)
    (ssh-write-text writer "")
    (ssh-client-send-payload client (ssh-writer-output writer))))

(defun ssh-client-handle-channel-open (client reader)
  "Answer a server-initiated CHANNEL_OPEN; only forwarded-tcpip is wanted."
  (let ((type (ssh-read-text reader))
        (sender (ssh-read-u32 reader))
        (window (ssh-read-u32 reader))
        (max-packet (ssh-read-u32 reader)))
    (cond
      ((string= type "forwarded-tcpip")
       (ssh-client-accept-forwarded-tcpip client reader sender window
                                          max-packet))
      ((string= type "forwarded-streamlocal@openssh.com")
       (ssh-client-accept-forwarded-streamlocal client reader sender window
                                                max-packet))
      ((string= type "x11")
       (ssh-client-accept-x11-channel client reader sender window
                                      max-packet))
      ((member type '("auth-agent@openssh.com" "agent-connect")
               :test #'string=)
       (ssh-client-accept-agent-channel client type sender window
                                        max-packet))
      (t
       (ssh-client-send-channel-open-failure
        client sender (format nil "unsupported channel type ~A" type))))))

(defun ssh-client-confirm-channel (channel)
  "Confirm a server-initiated CHANNEL, our half of the open handshake."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-channel-open-confirmation+)
    (ssh-write-u32 writer (ssh-channel-remote-id channel))
    (ssh-write-u32 writer (ssh-channel-local-id channel))
    (ssh-write-u32 writer (ssh-channel-local-window channel))
    (ssh-write-u32 writer (ssh-channel-local-max-packet channel))
    (ssh-client-send-payload (ssh-channel-client channel)
                             (ssh-writer-output writer))))

(defun ssh-client-register-incoming-channel (client type sender window
                                            max-packet)
  "Create, confirm and register a server-initiated channel of TYPE."
  (let* ((id (ssh-client-allocate-channel-id client))
         (channel (%make-ssh-channel
                   :client client
                   :local-id id
                   :remote-id sender
                   :type type
                   :state :open
                   :remote-window window
                   :remote-max-packet max-packet
                   :local-window (ssh-client-window client)
                   :local-max-packet (ssh-client-max-packet client))))
    (setf (gethash id (ssh-client-channels client)) channel)
    (ssh-client-confirm-channel channel)
    (ssh-client-channel-start-timeout channel)
    channel))

(defun ssh-client-accept-forwarded-tcpip (client reader sender window
                                          max-packet)
  "Accept a forwarded-tcpip channel and dial the application's local target.

The handler returns (VALUES HOST PORT) to dial, or a function of CHANNEL to
take over the new channel (reverse dynamic SOCKS forwarding), or NIL to
refuse it."
  (let* ((bind-address (ssh-read-text reader))
         (bind-port (ssh-read-u32 reader))
         (origin-address (ssh-read-text reader))
         (origin-port (ssh-read-u32 reader))
         (handler (ssh-client-on-forwarded-tcpip client)))
    (ssh-log "forwarded-tcpip for ~A:~D from ~A:~D"
             bind-address bind-port origin-address origin-port)
    (multiple-value-bind (host port)
        (and handler (funcall handler client bind-address bind-port
                              origin-address origin-port))
      (cond
        ((functionp host)
         (let ((channel
                 (ssh-client-register-incoming-channel
                  client "forwarded-tcpip" sender window max-packet)))
           (funcall host channel)
           channel))
        ((null host)
         (ssh-log "refusing forwarded-tcpip for ~A:~D" bind-address bind-port)
         (ssh-client-send-channel-open-failure
          client sender
          (format nil "forwarded-tcpip for ~A:~D was not requested"
                  bind-address bind-port)))
        (t
         (let ((channel
                 (ssh-client-register-incoming-channel
                  client "forwarded-tcpip" sender window max-packet)))
           (ssh-client-connect-forward-target channel host port)
           channel))))))

(defun ssh-client-accept-forwarded-streamlocal (client reader sender window
                                                max-packet)
  "Accept a forwarded-streamlocal channel and let the application bridge it.

The handler is a function of (CLIENT PATH) returning a setup function of
CHANNEL, or NIL to refuse the request."
  (let* ((path (ssh-read-text reader))
         (reserved (ssh-read-text reader))
         (handler (ssh-client-on-forwarded-streamlocal client))
         (setup (and handler (funcall handler client path))))
    (declare (ignore reserved))
    (if (null setup)
        (progn
          (ssh-log "refusing forwarded-streamlocal for ~A" path)
          (ssh-client-send-channel-open-failure
           client sender
           (format nil "forwarded-streamlocal for ~A was not requested" path)))
        (let* ((id (ssh-client-allocate-channel-id client))
               (channel (%make-ssh-channel
                         :client client
                         :local-id id
                         :remote-id sender
                         :type "forwarded-streamlocal@openssh.com"
                         :state :open
                         :remote-window window
                         :remote-max-packet max-packet
                         :local-window (ssh-client-window client)
                         :local-max-packet (ssh-client-max-packet client))))
          (setf (gethash id (ssh-client-channels client)) channel)
          (ssh-client-confirm-channel channel)
          (ssh-client-channel-start-timeout channel)
          (funcall setup channel)
          channel))))

(defun ssh-client-accept-agent-channel (client type sender window max-packet)
  "Accept a server-initiated agent channel and dial the local agent.

The socket is the one ForwardAgent names, or SSH_AUTH_SOCK.  A server that
opens an agent channel when forwarding was not requested is refused, which
is the check OpenSSH's client_request_agent makes before touching an agent."
  (let ((path (and (ssh-client-forward-agent client)
                   (ssh-client-forward-agent-path client))))
    (if (null path)
        (progn
          (ssh-log "refusing ~A: agent forwarding was not enabled" type)
          (ssh-client-send-channel-open-failure
           client sender
           "agent forwarding was not requested"))
        (multiple-value-bind (fd status)
            (cl-pnet-sockets:connect-unix path)
          (if (null fd)
              (progn
                (ssh-log "cannot connect to the agent at ~A: ~A"
                         path (cl-pnet-sockets:c-strerror status))
                (ssh-client-send-channel-open-failure
                 client sender
                 (format nil "cannot connect to the agent at ~A" path)))
              (let* ((id (ssh-client-allocate-channel-id client))
                     (channel (%make-ssh-channel
                               :client client
                               :local-id id
                               :remote-id sender
                               :type type
                               :state :open
                               :remote-window window
                               :remote-max-packet max-packet
                               :local-window (ssh-client-window client)
                               :local-max-packet (ssh-client-max-packet client)))
                     (relay (%make-ssh-fd-relay
                             :fd fd
                             :phase (if (eq status :connected)
                                        :connected :connecting)
                             :on-data
                             (lambda (relay octets)
                               (declare (ignore relay))
                               (ssh-channel-write channel octets))
                             :on-eof
                             (lambda (relay)
                               (declare (ignore relay))
                               (setf (ssh-channel-target-fd-eof channel) t)
                               (ssh-channel-eof channel)
                               (when (ssh-channel-eof-received channel)
                                 (ssh-channel-close channel)))
                             :on-error
                             (lambda (relay condition)
                               (declare (ignore relay))
                               (ssh-client-forward-fail channel condition)))))
                (setf (gethash id (ssh-client-channels client)) channel
                      (ssh-channel-target-fd-relay channel) relay)
                (ssh-client-confirm-channel channel)
                (ssh-client-channel-start-timeout channel)
                (ssh-fd-relay-start relay)
                channel))))))

(defun ssh-client-connect-forward-target (channel host port &key on-connected)
  "Connect a forwarded CHANNEL to HOST:PORT without blocking.

ON-CONNECTED runs once the local socket exists, so a caller with bytes that
arrived before the request (reverse dynamic SOCKS) can send them."
  (handler-case
      (burzay:resolve-host
       host
       (lambda (address)
         (ssh-client-dial-forward-target channel address port on-connected))
       (lambda (condition)
         (ssh-client-forward-fail channel condition)))
    (error (condition) (ssh-client-forward-fail channel condition))))

(defun ssh-client-dial-forward-target (channel address port
                                       &optional on-connected)
  (ssh-log "forwarded-tcpip dialling ~A:~D" address port)
  (let ((connection
          (cl-pnet:tcp-connect
           address port
           :read-cb (lambda (data)
                      (if data
                          (ssh-channel-write channel data)
                          (ssh-client-channel-target-ended channel)))
           :on-error
           (lambda (status)
             (ssh-client-forward-fail
              channel
              (make-condition 'ssh-channel-error
                              :channel channel
                              :detail (format nil "target connect failed (~A)"
                                              status)))))))
    (if connection
        (progn
          (setf (ssh-channel-target channel) connection)
          (when on-connected (funcall on-connected)))
        (ssh-client-forward-fail
         channel
         (make-condition 'ssh-channel-error
                         :channel channel
                         :detail (format nil "could not connect to ~A:~D"
                                         address port))))))

(defun ssh-client-forward-fail (channel condition)
  (when (ssh-channel-on-error channel)
    (funcall (ssh-channel-on-error channel) channel condition))
  (ssh-channel-close channel))

(defun ssh-client-channel-write-target (channel reader)
  "Move channel data to a forwarded-tcpip CHANNEL's local socket."
  (let ((data (ssh-read-string reader))
        (target (ssh-channel-target channel)))
    (ssh-client-channel-note-activity channel)
    (decf (ssh-channel-local-window channel) (length data))
    (ssh-channel-adjust-window channel (length data))
    (when target
      (cl-pnet:send-data
       target data
       :on-error
       (lambda (status)
         (ssh-client-forward-fail
          channel
          (make-condition 'ssh-channel-error
                          :channel channel
                          :detail (format nil "target send failed (~A)"
                                          status))))))))

(defun ssh-client-channel-half-close-target (channel)
  "Tell a forwarded-tcpip target that the peer will send nothing more."
  (let ((target (ssh-channel-target channel)))
    (when target
      (let ((fd (cl-pnet:connection-fileno target)))
        (when fd
          (ignore-errors (cl-pnet-sockets:c-shutdown fd 1)))))))

(defun ssh-client-channel-target-ended (channel)
  "A forwarded-tcpip CHANNEL's local target closed its output side."
  (setf (ssh-channel-target-eof channel) t)
  (ssh-channel-eof channel)
  (when (ssh-channel-eof-received channel)
    (ssh-channel-close channel)))

(defun ssh-channel-handle-open-confirmation (channel reader)
  (setf (ssh-channel-remote-id channel) (ssh-read-u32 reader)
        (ssh-channel-remote-window channel) (ssh-read-u32 reader)
        (ssh-channel-remote-max-packet channel) (ssh-read-u32 reader)
        (ssh-channel-state channel) :open)
  ;; Start the inactivity clock before the queued session request labels the
  ;; channel, so the label can override the plain type's timeout, as ssh's
  ;; channel_set_xtype does after the request is sent.
  (ssh-client-channel-start-timeout channel)
  (let ((agent (ssh-channel-pending-agent-request channel))
        (x11 (ssh-channel-pending-x11-request channel))
        (env (ssh-channel-pending-env channel))
        (exec (ssh-channel-pending-exec channel))
        (subsystem (ssh-channel-pending-subsystem channel)))
    (setf (ssh-channel-pending-agent-request channel) nil
          (ssh-channel-pending-x11-request channel) nil
          (ssh-channel-pending-env channel) nil
          (ssh-channel-pending-exec channel) nil
          (ssh-channel-pending-subsystem channel) nil)
    (when agent
      (ssh-channel-send-agent-request channel))
    (when x11
      (ssh-channel-send-x11-request channel))
    (iter (for (name . value) in env)
      (ssh-channel-send-env channel name value))
    (when exec
      (ssh-channel-send-exec channel exec))
    (when subsystem
      (ssh-channel-send-subsystem channel subsystem)))
  (ssh-channel-flush channel)
  (when (ssh-channel-on-open channel)
    (funcall (ssh-channel-on-open channel) channel)))

(defun ssh-channel-handle-open-failure (channel reader)
  (let ((reason (ssh-read-u32 reader))
        (description (ssh-read-text reader)))
    (declare (ignore reason))
    ;; Report before FINISH: FINISH runs ON-CLOSE, and a caller that answers a
    ;; failed open (a SOCKS proxy sends a refusal reply) needs its local
    ;; connection still open when its ON-ERROR runs.
    (when (ssh-channel-on-error channel)
      (funcall (ssh-channel-on-error channel) channel
               (make-condition 'ssh-channel-error
                               :channel channel
                               :reason reason
                               :description description
                               :detail (format nil "channel open refused: ~A"
                                               description))))
    (ssh-channel-finish channel)))

(defun ssh-channel-handle-data (channel reader extended)
  (let* ((kind (if extended
                   (if (= (ssh-read-u32 reader) 1) :stderr :other)
                   :stdout))
         (data (ssh-read-string reader)))
    (ssh-client-channel-note-activity channel)
    (decf (ssh-channel-local-window channel) (length data))
    (when (eq kind :other)
      (ssh-channel-adjust-window channel (length data))
      (return-from ssh-channel-handle-data nil))
    (ssh-channel-adjust-window channel (length data))
    (when (ssh-channel-on-data channel)
      (funcall (ssh-channel-on-data channel) channel data kind))))

(defun ssh-channel-handle-request (channel reader)
  (let* ((request (ssh-read-text reader))
         (want-reply (ssh-read-boolean reader))
         (handled
           (cond
             ((string= request "exit-status")
              (setf (ssh-channel-exit-status channel) (ssh-read-u32 reader))
              (when (ssh-channel-on-exit channel)
                (funcall (ssh-channel-on-exit channel) channel
                         (ssh-channel-exit-status channel)))
              t)
             ((string= request "exit-signal")
              (setf (ssh-channel-exit-signal channel) (ssh-read-text reader))
              (ssh-read-boolean reader)
              (ssh-read-text reader)
              (ssh-read-text reader)
              t)
             (t nil))))
    (when want-reply
      (ssh-channel-send-message
       channel (if handled +ssh-msg-channel-success+ +ssh-msg-channel-failure+)))))

(defun ssh-channel-finish (channel)
  "Mark CHANNEL closed once, unregister it, and report its end."
  (unless (eq (ssh-channel-state channel) :closed)
    (setf (ssh-channel-state channel) :closed)
    (when (ssh-channel-target channel)
      (ignore-errors (cl-pnet:close-connection (ssh-channel-target channel)))
      (setf (ssh-channel-target channel) nil))
    (when (ssh-channel-target-fd-relay channel)
      (ssh-fd-relay-close (ssh-channel-target-fd-relay channel))
      (setf (ssh-channel-target-fd-relay channel) nil))
    (remhash (ssh-channel-local-id channel)
             (ssh-client-channels (ssh-channel-client channel)))
    (ssh-client-note-channel-change (ssh-channel-client channel))
    (when (ssh-channel-on-close channel)
      (funcall (ssh-channel-on-close channel) channel
               (ssh-channel-exit-status channel)))))

(defun ssh-channel-handle-close (channel)
  (unless (ssh-channel-sent-close channel)
    (setf (ssh-channel-sent-close channel) t)
    (ssh-channel-send-message channel +ssh-msg-channel-close+))
  (ssh-channel-finish channel))

(defun ssh-client-handle-channel-message (client payload)
  "Dispatch one channel-related message."
  (let* ((reader (ssh-make-reader payload))
         (type (ssh-read-u8 reader)))
    (if (= type +ssh-msg-channel-open+)
        (ssh-client-handle-channel-open client reader)
        (let ((channel (ssh-client-channel-for client (ssh-read-u32 reader))))
          (when channel
            (if (and (ssh-channel-relay channel)
                     (not (eq (ssh-channel-state channel) :opening)))
                ;; A mux-proxy channel is relayed verbatim; the proxy client
                ;; owns its windows, buffers and requests.
                (funcall (ssh-channel-relay channel) channel payload)
                (case type
              (#.+ssh-msg-channel-open-confirmation+
               (ssh-channel-handle-open-confirmation channel reader))
              (#.+ssh-msg-channel-open-failure+
               (ssh-channel-handle-open-failure channel reader))
              (#.+ssh-msg-channel-window-adjust+
               (incf (ssh-channel-remote-window channel) (ssh-read-u32 reader))
               (ssh-channel-flush channel))
              (#.+ssh-msg-channel-data+
               ;; A channel whose local target the library dialled carries
               ;; its bytes straight there; anything else belongs to the
               ;; application, which may bridge it to its own descriptor.
               (cond
                 ((and (ssh-channel-target-fd-relay channel)
                       (string= (ssh-channel-type channel) "x11"))
                  (let ((data (ssh-read-string reader)))
                    (ssh-client-channel-note-activity channel)
                    (decf (ssh-channel-local-window channel) (length data))
                    (ssh-channel-adjust-window channel (length data))
                    (ssh-client-x11-target-data channel data)))
                 ((ssh-channel-target-fd-relay channel)
                  (let ((data (ssh-read-string reader)))
                    (ssh-client-channel-note-activity channel)
                    (decf (ssh-channel-local-window channel) (length data))
                    (ssh-channel-adjust-window channel (length data))
                    (ssh-fd-relay-queue
                     (ssh-channel-target-fd-relay channel) data)))
                 ((ssh-channel-target channel)
                  (ssh-client-channel-write-target channel reader))
                 (t
                  (ssh-channel-handle-data channel reader nil))))
              (#.+ssh-msg-channel-extended-data+
               (ssh-channel-handle-data channel reader t))
              (#.+ssh-msg-channel-eof+
               (setf (ssh-channel-eof-received channel) t)
               (cond
                 ((ssh-channel-target-fd-relay channel)
                  (ssh-fd-relay-shutdown-write
                   (ssh-channel-target-fd-relay channel))
                  (when (ssh-channel-target-fd-eof channel)
                    (ssh-channel-close channel)))
                 ((ssh-channel-target channel)
                  (ssh-client-channel-half-close-target channel)
                  (when (ssh-channel-target-eof channel)
                    (ssh-channel-close channel)))
                 ((ssh-channel-on-eof channel)
                  (funcall (ssh-channel-on-eof channel) channel))))
              (#.+ssh-msg-channel-close+
               (ssh-channel-handle-close channel))
              (#.+ssh-msg-channel-request+
               (ssh-channel-handle-request channel reader))
              (#.+ssh-msg-channel-success+
               ;; The first reply is x11-req's: ssh asks for it, while the
               ;; requests queued around it do not want one.
               (when (ssh-channel-x11-reply-pending channel)
                 (setf (ssh-channel-x11-reply-pending channel) nil)))
              (#.+ssh-msg-channel-failure+
               (if (ssh-channel-x11-reply-pending channel)
                   ;; ssh logs a refused x11-req and keeps the session, so the
                   ;; failure is not the channel error an exec refusal is.
                   (progn
                     (setf (ssh-channel-x11-reply-pending channel) nil)
                     (ssh-warn "X11 forwarding request failed on channel ~D"
                               (ssh-channel-local-id channel)))
                   (when (ssh-channel-on-error channel)
                     (funcall (ssh-channel-on-error channel) channel
                              (make-condition 'ssh-channel-error
                                              :channel channel
                                              :detail "request refused"))))))))))))

;;; ---- Client shutdown ----

(defun ssh-client-terminate-channels (client reason kind)
  "Report CLIENT's end to every channel not yet closed."
  (let ((channels (iter (for (id channel) in-hashtable
                              (ssh-client-channels client))
                    (collect channel))))
    (iter (for channel in channels)
      (unless (eq (ssh-channel-state channel) :closed)
        (setf (ssh-channel-state channel) :closed)
        (remhash (ssh-channel-local-id channel) (ssh-client-channels client))
        (ecase kind
          (:error (when (ssh-channel-on-error channel)
                    (funcall (ssh-channel-on-error channel) channel reason)))
          (:close (when (ssh-channel-on-close channel)
                    (funcall (ssh-channel-on-close channel) channel
                             (ssh-channel-exit-status channel)))))))))
