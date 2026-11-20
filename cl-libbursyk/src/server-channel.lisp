(in-package #:cl-pnet-ssh)

;;;; Server-side channels (RFC 4254).  A session channel runs one command;
;;;; a direct-tcpip channel is a byte pipe to a target the caller approves.
;;;; Flow control and the close handshake mirror the client, on the server's
;;;; half of the same protocol.

(defun ssh-server-channel-send (channel payload)
  "Send PAYLOAD, which already names CHANNEL's remote id."
  (ssh-session-send-payload (ssh-server-channel-session channel) payload))

(defun ssh-server-channel-send-message (channel type &key fields)
  "A channel message with TYPE, CHANNEL's remote id, and FIELDS as a thunk."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer type)
    (ssh-write-u32 writer (ssh-server-channel-remote-id channel))
    (when fields (funcall fields writer))
    (ssh-server-channel-send channel (ssh-writer-output writer))))

(defun ssh-server-channel-adjust-window (channel amount)
  "Give AMOUNT octets of receive window back to the client."
  (when (and (plusp amount) (eq (ssh-server-channel-state channel) :open))
    (incf (ssh-server-channel-local-window channel) amount)
    (ssh-server-channel-send-message
     channel +ssh-msg-channel-window-adjust+
     :fields (lambda (writer) (ssh-write-u32 writer amount)))))

;;; ---- Opening ----

(defun ssh-server-channel-open-confirmation (channel)
  "Tell the client its channel is open, naming our local id."
  (ssh-server-channel-send-message
   channel +ssh-msg-channel-open-confirmation+
   :fields (lambda (writer)
             (ssh-write-u32 writer (ssh-server-channel-local-id channel))
             (ssh-write-u32 writer (ssh-server-channel-local-window channel))
             (ssh-write-u32 writer (ssh-server-channel-local-max-packet channel)))))

(defun ssh-server-channel-open-failure (session sender reason description)
  "Refuse a channel open that names SENDER, the client's local id."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-channel-open-failure+)
    (ssh-write-u32 writer sender)
    (ssh-write-u32 writer reason)
    (ssh-write-text writer description)
    (ssh-write-text writer "")
    (ssh-session-send-payload session (ssh-writer-output writer))))

(defun ssh-server-open-forwarded-tcpip (session bind-address bind-port
                                        origin-address origin-port
                                        &key on-data on-eof on-close on-error)
  "Ask SESSION's client to open a forwarded-tcpip channel.

BIND-ADDRESS:BIND-PORT is the address the client asked the server to listen
on, and ORIGIN-ADDRESS:ORIGIN-PORT names the peer that connected there.  The
channel starts in :OPENING; data queued with SSH-SERVER-CHANNEL-WRITE goes
out once the client confirms."
  (let* ((id (ssh-session-next-channel-id session))
         (window (ssh-session-window session))
         (max-packet (ssh-session-max-packet session))
         (channel (%make-ssh-server-channel
                   :session session
                   :local-id id
                   :type "forwarded-tcpip"
                   :state :opening
                   :local-window window
                   :local-max-packet max-packet
                   :on-data on-data :on-eof on-eof
                   :on-close on-close :on-error on-error)))
    (incf (ssh-session-next-channel-id session))
    (setf (gethash id (ssh-session-channels session)) channel)
    (ssh-session-note-channel-change session)
    (let ((writer (ssh-writer)))
      (ssh-write-u8 writer +ssh-msg-channel-open+)
      (ssh-write-text writer "forwarded-tcpip")
      (ssh-write-u32 writer id)
      (ssh-write-u32 writer window)
      (ssh-write-u32 writer max-packet)
      (ssh-write-text writer bind-address)
      (ssh-write-u32 writer bind-port)
      (ssh-write-text writer origin-address)
      (ssh-write-u32 writer origin-port)
      (ssh-session-send-payload session (ssh-writer-output writer)))
    channel))

(defun ssh-server-channel-handle-open-confirmation (channel reader)
  "The client accepted a forwarded-tcpip CHANNEL we opened."
  (setf (ssh-server-channel-remote-id channel) (ssh-read-u32 reader)
        (ssh-server-channel-remote-window channel) (ssh-read-u32 reader)
        (ssh-server-channel-remote-max-packet channel) (ssh-read-u32 reader)
        (ssh-server-channel-state channel) :open)
  (ssh-server-channel-start-inactivity-timeout channel)
  (ssh-server-channel-flush channel))

(defun ssh-server-channel-handle-open-failure (channel reader)
  "The client refused a forwarded-tcpip CHANNEL we opened."
  (let ((reason (ssh-read-u32 reader))
        (description (ssh-read-text reader)))
    (declare (ignore reason))
    (when (ssh-server-channel-on-error channel)
      (funcall (ssh-server-channel-on-error channel) channel
               (make-condition 'ssh-channel-error
                               :channel channel
                               :detail (format nil "channel open refused: ~A"
                                               description))))
    (ssh-server-channel-finish channel)))

(defun ssh-server-register-channel (session type sender window max-packet
                                     &key open-extra on-data on-eof on-exec
                                       on-close on-error (confirm t))
  "Create a channel for SENDER.

CONFIRM defaults to true: the channel is open at once and the client is told
so.  A caller that still has work to do before the channel can carry data -
Direct-tcpip dials its target first - passes NIL and calls
SSH-SERVER-CHANNEL-CONFIRM-TARGET once the channel is usable; until then the
channel stays in :OPENING and client data is not expected."
  (let* ((id (ssh-session-next-channel-id session))
         (channel (%make-ssh-server-channel
                   :session session
                   :local-id id
                   :remote-id sender
                   :type type
                   :open-extra (or open-extra
                                   (make-array 0 :element-type '(unsigned-byte 8)))
                   :state (if confirm :open :opening)
                   :remote-window window
                   :remote-max-packet max-packet
                   :local-window (ssh-session-window session)
                   :local-max-packet (ssh-session-max-packet session)
                   :on-data on-data :on-eof on-eof :on-exec on-exec
                   :on-close on-close :on-error on-error)))
    (incf (ssh-session-next-channel-id session))
    (setf (gethash id (ssh-session-channels session)) channel)
    (ssh-session-note-channel-change session)
    (when confirm
      (ssh-server-channel-open-confirmation channel)
      (ssh-server-channel-start-inactivity-timeout channel))
    channel))

(defun ssh-server-session-channel-count (session)
  "How many session channels SESSION still has open or opening."
  (iter (for (id channel) in-hashtable (ssh-session-channels session))
    (declare (ignore id))
    (counting (and (string= (ssh-server-channel-type channel) "session")
                   (not (eq (ssh-server-channel-state channel) :closed))))))

(defun ssh-server-open-session-channel (session sender window max-packet)
  "Accept a session channel and make it available to the application.

MaxSessions bounds how many may be live at once; sshd answers further opens
with SSH_OPEN_ADMINISTRATIVELY_PROHIBITED instead of allocating a channel."
  (let ((limit (or (ssh-session-setting
                    session #'ssh-server-config-max-sessions)
                   (ssh-server-max-sessions (ssh-session-server session)))))
    (when (and limit
               (>= (ssh-server-session-channel-count session) limit))
      (ssh-server-channel-open-failure
       session sender 1
       (format nil "administratively prohibited: too many sessions (~D)"
               limit))
      (return-from ssh-server-open-session-channel nil)))
  (let ((channel (ssh-server-register-channel
                  session "session" sender window max-packet))
        (handler (ssh-server-on-channel (ssh-session-server session))))
    (when handler (funcall handler channel))
    channel))

(defun ssh-server-handle-channel-open (session reader)
  "Read a CHANNEL_OPEN and accept or refuse it by type."
  (let* ((type (ssh-read-text reader))
         (sender (ssh-read-u32 reader))
         (window (ssh-read-u32 reader))
         (max-packet (ssh-read-u32 reader)))
    (cond
      ((string= type "session")
       (ssh-server-open-session-channel session sender window max-packet))
      ((string= type "direct-tcpip")
       (ssh-server-handle-direct-tcpip-open session reader sender window
                                            max-packet))
      (t
       (ssh-server-channel-open-failure session sender 3
                                        (format nil "unsupported channel type ~A"
                                                type))))))

(defun ssh-server-handle-direct-tcpip-open (session reader sender window
                                            max-packet)
  "Ask the application about a forwarded connection, then pipe it.

The channel is confirmed only after its target is connected, so a refused
target makes the client's channel open fail - which is what OpenSSH's sshd
reports - instead of opening a channel that can never carry a byte."
  (let* ((host (ssh-read-text reader))
         (port (ssh-read-u32 reader))
         (origin (ssh-read-text reader))
         (origin-port (ssh-read-u32 reader))
         (handler (ssh-server-on-direct-tcpip (ssh-session-server session)))
         (allowed (and (ssh-session-permits-direct-tcpip-p session host port)
                       handler
                       (funcall handler session host port origin origin-port))))
    (if allowed
        (let ((channel (ssh-server-register-channel
                        session "direct-tcpip" sender window max-packet
                        :confirm nil)))
          (ssh-server-connect-target channel host port))
        (ssh-server-channel-open-failure
         session sender 1
         (format nil "direct-tcpip to ~A:~D is not permitted" host port)))))

;;; ---- Requests ----

(defun ssh-server-channel-reply (channel ok want-reply)
  (when want-reply
    (ssh-server-channel-send-message
     channel (if ok +ssh-msg-channel-success+ +ssh-msg-channel-failure+))))

(defun ssh-server-handle-pty-request (channel reader want-reply)
  "Remember the peer's terminal for the shell or command that follows.

The application's ON-PTY predicate decides whether the request succeeds; a
NIL predicate refuses it, as a server that cannot allocate a PTY should."
  (let* ((term (ssh-read-text reader))
         (columns (ssh-read-u32 reader))
         (rows (ssh-read-u32 reader))
         (width (ssh-read-u32 reader))
         (height (ssh-read-u32 reader))
         (modes (ssh-read-string reader))
         (handler (ssh-server-channel-on-pty channel))
         (ok (and (ssh-session-permits-pty-p
                   (ssh-server-channel-session channel))
                  handler
                  (funcall handler channel term columns rows width height
                           modes))))
    (when ok
      (setf (ssh-server-channel-pty-p channel) t
            (ssh-server-channel-pty-term channel) term
            (ssh-server-channel-pty-columns channel) columns
            (ssh-server-channel-pty-rows channel) rows
            (ssh-server-channel-pty-modes channel) modes))
    (ssh-server-channel-reply channel (not (null ok)) want-reply)))

(defun ssh-server-handle-shell-request (channel want-reply)
  "Ask the application for the login shell thunk, then answer and run it.

The thunk runs after the success reply, so output a shell writes cannot
overtake the reply that opened it.  Returning NIL refuses the request."
  (let* ((handler (ssh-server-channel-on-shell channel))
         (start (and handler (funcall handler channel))))
    ;; sshd labels the channel before running the shell, even if starting it
    ;; fails; the label selects ChannelTimeout from here on.
    (ssh-server-channel-set-x-type channel "session:shell")
    (ssh-server-channel-reply channel (not (null start)) want-reply)
    (when start (funcall start))))

(defun ssh-server-handle-subsystem-request (channel reader want-reply)
  "Ask the application to start the named subsystem, then run its thunk.

The same reply-before-output rule as SHELL applies; an unknown subsystem
returns NIL and is refused rather than accepted and abandoned."
  (let* ((name (ssh-read-text reader))
         (handler (ssh-server-channel-on-subsystem channel))
         (start (and handler (funcall handler channel name))))
    (when start
      (setf (ssh-server-channel-subsystem channel) name)
      (ssh-server-channel-set-x-type
       channel (format nil "session:subsystem:~A" name)))
    (ssh-server-channel-reply channel (not (null start)) want-reply)
    (when start (funcall start))))

(defun ssh-server-handle-window-change (channel reader want-reply)
  "Store the peer's new terminal size and tell the application."
  (let ((columns (ssh-read-u32 reader))
        (rows (ssh-read-u32 reader)))
    (ssh-read-u32 reader)
    (ssh-read-u32 reader)
    (setf (ssh-server-channel-pty-columns channel) columns
          (ssh-server-channel-pty-rows channel) rows)
    (when (ssh-server-channel-on-window-change channel)
      (funcall (ssh-server-channel-on-window-change channel)
               channel columns rows))
    ;; RFC 4254 says a window-change never wants a reply, but a peer that
    ;; asks for one still deserves an answer rather than a silent channel.
    (ssh-server-channel-reply channel t want-reply)))

(defun ssh-server-handle-env-request (channel reader want-reply)
  (let* ((name (ssh-read-text reader))
         (value (ssh-read-text reader))
         (session (ssh-server-channel-session channel))
         (ok (ssh-session-env-allowed-p session name value)))
    (when ok
      (push (cons name value) (ssh-server-channel-env channel)))
    (ssh-server-channel-reply channel ok want-reply)))

(defun ssh-server-handle-exec-request (channel reader want-reply)
  (let ((command (ssh-read-text reader))
        (handler (ssh-server-channel-on-exec channel)))
    (setf (ssh-server-channel-command channel) command)
    ;; sshd labels the channel before do_exec, success or not.
    (ssh-server-channel-set-x-type channel "session:command")
    (ssh-server-channel-reply channel (not (null handler)) want-reply)
    (when handler
      (funcall handler channel command))))

(defun ssh-server-handle-channel-request (session channel reader)
  "Dispatch one request addressed to CHANNEL."
  (let ((request (ssh-read-text reader))
        (want-reply (ssh-read-boolean reader)))
    (cond
      ((string= request "env")
       (ssh-server-handle-env-request channel reader want-reply))
      ((string= request "exec")
       (ssh-server-handle-exec-request channel reader want-reply))
      ((string= request "pty-req")
       (ssh-server-handle-pty-request channel reader want-reply))
      ((string= request "shell")
       (ssh-server-handle-shell-request channel want-reply))
      ((string= request "subsystem")
       (ssh-server-handle-subsystem-request channel reader want-reply))
      ((string= request "window-change")
       (ssh-server-handle-window-change channel reader want-reply))
      ((member request '("auth-agent-req@openssh.com" "x11-req")
               :test #'string=)
       (ssh-server-channel-reply channel nil want-reply))
      (t (ssh-server-channel-reply channel nil want-reply)))))

;;; ---- Data, flow control and closing ----

(defun ssh-server-channel-queue (channel data)
  (let ((queue (ssh-server-channel-write-queue channel)))
    (iter (for octet in-vector (ssh-ensure-octets data))
      (vector-push-extend octet queue))))

(defun ssh-server-channel-drop-queue (channel count)
  (let ((queue (ssh-server-channel-write-queue channel)))
    (replace queue queue :start1 0 :start2 count)
    (decf (fill-pointer queue) count)))

(defun ssh-server-channel-flush (channel)
  "Send as much queued data as the client's window and packet size allow."
  (let ((queue (ssh-server-channel-write-queue channel)))
    (iter (while (and (eq (ssh-server-channel-state channel) :open)
                      (plusp (fill-pointer queue))
                      (plusp (ssh-server-channel-remote-window channel))))
      (let ((count (min (fill-pointer queue)
                        (ssh-server-channel-remote-window channel)
                        (max 1 (ssh-server-channel-remote-max-packet channel)))))
        (let ((chunk (subseq queue 0 count)))
          (ssh-server-channel-send-message
           channel +ssh-msg-channel-data+
           :fields (lambda (writer) (ssh-write-string writer chunk))))
        (decf (ssh-server-channel-remote-window channel) count)
        (ssh-server-channel-drop-queue channel count)))
    (ssh-server-channel-after-queue channel)))

(defun ssh-server-channel-after-queue (channel)
  "Run deferred work once nothing is left queued."
  (when (zerop (fill-pointer (ssh-server-channel-write-queue channel)))
    (let ((callbacks (nreverse (ssh-server-channel-write-callbacks channel))))
      (setf (ssh-server-channel-write-callbacks channel) nil)
      (iter (for callback in callbacks) (funcall callback)))
    (when (and (ssh-server-channel-want-eof channel)
               (not (ssh-server-channel-sent-eof channel))
               (eq (ssh-server-channel-state channel) :open))
      (setf (ssh-server-channel-sent-eof channel) t)
      (ssh-server-channel-send-message channel +ssh-msg-channel-eof+))
    (when (and (ssh-server-channel-want-close channel)
               (not (ssh-server-channel-sent-close channel))
               (member (ssh-server-channel-state channel) '(:open :closing)))
      (setf (ssh-server-channel-sent-close channel) t
            (ssh-server-channel-state channel) :closing)
      (ssh-server-channel-send-message channel +ssh-msg-channel-close+))))

(defun ssh-server-channel-write (channel data &key on-done)
  "Queue DATA for the client's channel; ON-DONE runs when all of it is sent."
  (when (eq (ssh-server-channel-state channel) :closed)
    (error 'ssh-channel-error :channel channel :detail "channel is closed"))
  (ssh-server-channel-queue channel data)
  (when on-done
    (push on-done (ssh-server-channel-write-callbacks channel)))
  (ssh-server-channel-note-activity channel)
  (ssh-server-channel-flush channel)
  channel)

(defun ssh-server-channel-write-stderr (channel data &key on-done)
  "Queue DATA as extended channel data, the SSH equivalent of stderr."
  (ssh-server-channel-send-message
   channel +ssh-msg-channel-extended-data+
   :fields (lambda (writer)
             (ssh-write-u32 writer 1)
             (ssh-write-string writer (ssh-ensure-octets data))))
  (ssh-server-channel-note-activity channel)
  (when on-done (funcall on-done))
  channel)

(defun ssh-server-channel-eof (channel)
  "Say no more output follows, after everything already queued."
  (setf (ssh-server-channel-want-eof channel) t)
  (ssh-server-channel-flush channel)
  channel)

(defun ssh-server-channel-close (channel)
  "Start the close handshake, after everything already queued."
  (cond
    ((and (eq (ssh-server-channel-state channel) :opening)
          (null (ssh-server-channel-remote-id channel)))
     ;; A channel we opened has not been confirmed, so the client has no id to
     ;; close; there is nothing to tell it and no reason to keep the record.
     (ssh-server-channel-finish channel))
    ((member (ssh-server-channel-state channel) '(:open :opening))
     (setf (ssh-server-channel-want-close channel) t)
     (ssh-server-channel-flush channel)))
  channel)

(defun ssh-server-channel-exit (channel status)
  "Send an exit status and end the channel's output."
  (setf (ssh-server-channel-exit-status channel) status)
  (ssh-server-channel-send-message
   channel +ssh-msg-channel-request+
   :fields (lambda (writer)
             (ssh-write-text writer "exit-status")
             (ssh-write-boolean writer nil)
             (ssh-write-u32 writer status)))
  (ssh-server-channel-eof channel))

(defun ssh-server-channel-handle-data (channel reader extended)
  (let* ((kind (if extended
                   (if (= (ssh-read-u32 reader) 1) :stderr :other)
                   :stdin))
         (data (ssh-read-string reader)))
    (ssh-server-channel-note-activity channel)
    (decf (ssh-server-channel-local-window channel) (length data))
    (ssh-server-channel-adjust-window channel (length data))
    (cond
      ((string= (ssh-server-channel-type channel) "direct-tcpip")
       (ssh-server-channel-write-target channel data))
      ((and (not (eq kind :other)) (ssh-server-channel-on-data channel))
       (funcall (ssh-server-channel-on-data channel) channel data kind)))))

(defun ssh-server-channel-finish (channel)
  "Mark CHANNEL closed once, unregister it, and report its end."
  (unless (eq (ssh-server-channel-state channel) :closed)
    (setf (ssh-server-channel-state channel) :closed)
    (remhash (ssh-server-channel-local-id channel)
             (ssh-session-channels (ssh-server-channel-session channel)))
    (ssh-session-note-channel-change (ssh-server-channel-session channel))
    (when (ssh-server-channel-target channel)
      ;; The target connection may already have closed; CL-PNET's close is
      ;; idempotent, so call it plainly rather than hiding other errors.
      (cl-pnet:close-connection (ssh-server-channel-target channel))
      (setf (ssh-server-channel-target channel) nil))
    (when (ssh-server-channel-on-close channel)
      (funcall (ssh-server-channel-on-close channel) channel))))

(defun ssh-server-channel-handle-close (channel)
  (unless (ssh-server-channel-sent-close channel)
    (setf (ssh-server-channel-sent-close channel) t)
    (ssh-server-channel-send-message channel +ssh-msg-channel-close+))
  (ssh-server-channel-finish channel))

(defun ssh-server-channel-force-close (channel)
  "End CHANNEL at once, as sshd's channel_force_close does for an idle one.

The client is told with CHANNEL_CLOSE when the channel had a remote id, and
the application's ON-CLOSE runs immediately instead of waiting for the
client's half of the handshake."
  (when (member (ssh-server-channel-state channel) '(:open :closing))
    (unless (ssh-server-channel-sent-close channel)
      (setf (ssh-server-channel-sent-close channel) t)
      (ssh-server-channel-send-message channel +ssh-msg-channel-close+)))
  (ssh-server-channel-finish channel))

(defun ssh-server-channel-half-close-target (channel)
  "Tell a direct-tcpip target that the client will send nothing more.

The channel stays open for the target's remaining output, which is what a
client using -W or -L expects after it closes its own stdin.  1 is SHUT_WR
on POSIX and SD_SEND on Winsock."
  (let ((target (ssh-server-channel-target channel)))
    (when target
      (let ((fd (cl-pnet:connection-fileno target)))
        (when fd
          (ignore-errors (cl-pnet-sockets:c-shutdown fd 1)))))))

(defun ssh-server-channel-target-ended (channel)
  "The target of a direct-tcpip CHANNEL closed its output side.

Send the channel EOF, and close the channel when the client has already
said it will send nothing more; otherwise its remaining input still has a
reader."
  (setf (ssh-server-channel-target-eof channel) t)
  (ssh-server-channel-eof channel)
  (when (ssh-server-channel-eof-received channel)
    (ssh-server-channel-close channel)))

(defun ssh-server-dispatch-channel-message (session type channel reader)
  (case type
    (#.+ssh-msg-channel-open-confirmation+
     (ssh-server-channel-handle-open-confirmation channel reader))
    (#.+ssh-msg-channel-open-failure+
     (ssh-server-channel-handle-open-failure channel reader))
    (#.+ssh-msg-channel-window-adjust+
     (incf (ssh-server-channel-remote-window channel) (ssh-read-u32 reader))
     (ssh-server-channel-flush channel))
    (#.+ssh-msg-channel-data+
     (ssh-server-channel-handle-data channel reader nil))
    (#.+ssh-msg-channel-extended-data+
     (ssh-server-channel-handle-data channel reader t))
    (#.+ssh-msg-channel-eof+
     (setf (ssh-server-channel-eof-received channel) t)
     (when (string= (ssh-server-channel-type channel) "direct-tcpip")
       (ssh-server-channel-half-close-target channel)
       (when (ssh-server-channel-target-eof channel)
         (ssh-server-channel-close channel)))
     (when (ssh-server-channel-on-eof channel)
       (funcall (ssh-server-channel-on-eof channel) channel)))
    (#.+ssh-msg-channel-close+
     (ssh-server-channel-handle-close channel))
    (#.+ssh-msg-channel-request+
     (ssh-server-handle-channel-request session channel reader))
    (#.+ssh-msg-channel-success+ nil)
    (#.+ssh-msg-channel-failure+
     (when (ssh-server-channel-on-error channel)
       (funcall (ssh-server-channel-on-error channel) channel
                (make-condition 'ssh-channel-error
                                :channel channel
                                :detail "client refused a request"))))))

(defun ssh-server-handle-channel-message (session payload)
  "Dispatch one channel-related message."
  (let* ((reader (ssh-make-reader payload))
         (type (ssh-read-u8 reader)))
    (if (= type +ssh-msg-channel-open+)
        (ssh-server-handle-channel-open session reader)
        (let ((channel (ssh-session-channel-for session (ssh-read-u32 reader))))
          (when channel
            (ssh-server-dispatch-channel-message session type channel reader))))))

;;; ---- direct-tcpip target ----

(defun ssh-server-connect-target (channel host port)
  "Connect CHANNEL to HOST:PORT without blocking, then pipe both ways."
  (handler-case
      (burzay:resolve-host
       host
       (lambda (address)
         (ssh-server-dial-target channel address port))
       (lambda (condition)
         (ssh-server-channel-fail channel condition)))
    (error (condition) (ssh-server-channel-fail channel condition))))

(defun ssh-server-channel-confirm-target (channel)
  "Confirm CHANNEL now that its direct-tcpip target accepted the connection."
  (when (eq (ssh-server-channel-state channel) :opening)
    (setf (ssh-server-channel-state channel) :open)
    (ssh-server-channel-open-confirmation channel)
    (ssh-server-channel-start-inactivity-timeout channel)
    (ssh-server-channel-flush channel)))

(defun ssh-server-dial-target (channel address port)
  "Open the target TCP connection for CHANNEL once its name resolved."
  (let ((connection
          (cl-pnet:tcp-connect
           address port
           :on-connect (lambda (connection)
                         (declare (ignore connection))
                         (ssh-server-channel-confirm-target channel))
           :read-cb (lambda (data)
                      (if data
                          (ssh-server-channel-write channel data)
                          (ssh-server-channel-target-ended channel)))
           :on-error (lambda (status)
                       (ssh-server-channel-fail
                        channel
                        (make-condition 'ssh-connection-error
                                        :detail (format nil "target connect failed (~A)"
                                                        status)))))))
    (if connection
        (setf (ssh-server-channel-target channel) connection)
        (ssh-server-channel-fail
         channel
         (make-condition 'ssh-connection-error
                         :detail (format nil "could not connect to ~A:~D"
                                         address port))))))

(defun ssh-server-channel-fail (channel condition)
  "Report CONDITION and end CHANNEL.

A channel that was never confirmed cannot be closed: the client does not know
its local id yet, and CHANNEL_CLOSE would name an id it never opened.  Refuse
the open instead, which is what turns a refused direct-tcpip target into a
SOCKS failure reply rather than an accepted-but-dead tunnel."
  (when (ssh-server-channel-on-error channel)
    (funcall (ssh-server-channel-on-error channel) channel condition))
  (if (and (eq (ssh-server-channel-state channel) :opening)
           (ssh-server-channel-remote-id channel))
      (progn
        (ssh-server-channel-open-failure
         (ssh-server-channel-session channel)
         (ssh-server-channel-remote-id channel)
         2
         (princ-to-string condition))
        (ssh-server-channel-finish channel))
      (ssh-server-channel-close channel)))

(defun ssh-server-channel-write-target (channel data)
  "Send client channel DATA to CHANNEL's direct-tcpip target."
  (let ((target (ssh-server-channel-target channel)))
    (when target
      (cl-pnet:send-data
       target data
       :on-error (lambda (status)
                   (ssh-server-channel-fail
                    channel
                    (make-condition 'ssh-connection-error
                                    :detail (format nil "target send failed (~A)"
                                                    status))))))))
