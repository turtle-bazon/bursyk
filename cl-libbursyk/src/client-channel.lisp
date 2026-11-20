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

(defun ssh-open-channel (client type &key open-extra on-data on-eof on-exit
                                      on-close on-error)
  "Register a channel of TYPE on CLIENT and ask the peer for it.

The returned channel is usable immediately: requests and writes made before
the open confirmation are queued and flushed once the peer answers."
  (let* ((id (ssh-client-next-channel-id client))
         (channel (%make-ssh-channel
                   :client client
                   :local-id id
                   :type type
                   :open-extra (or open-extra
                                   (make-array 0 :element-type '(unsigned-byte 8)))
                   :local-window (ssh-client-window client)
                   :local-max-packet (ssh-client-max-packet client)
                   :on-data on-data :on-eof on-eof :on-exit on-exit
                   :on-close on-close :on-error on-error)))
    (incf (ssh-client-next-channel-id client))
    (setf (gethash id (ssh-client-channels client)) channel)
    (ssh-client-run-when-ready
     client (lambda () (ssh-channel-send channel (ssh-channel-open-payload channel))))
    channel))

(defun ssh-open-session (client &key on-data on-eof on-exit on-close on-error)
  "Open a session channel; commands run on it with SSH-CHANNEL-EXEC."
  (ssh-open-channel client "session"
                    :on-data on-data :on-eof on-eof :on-exit on-exit
                    :on-close on-close :on-error on-error))

(defun ssh-open-direct-tcpip (client host port
                              &key (origin-address "0.0.0.0") (origin-port 0)
                                   on-data on-eof on-close on-error)
  "Ask the peer to connect to HOST:PORT and carry the bytes on a channel."
  (let ((writer (ssh-writer)))
    (ssh-write-text writer host)
    (ssh-write-u32 writer port)
    (ssh-write-text writer origin-address)
    (ssh-write-u32 writer origin-port)
    (ssh-open-channel client "direct-tcpip"
                      :open-extra (ssh-writer-output writer)
                      :on-data on-data :on-eof on-eof
                      :on-close on-close :on-error on-error)))

;;; ---- Requests ----

(defun ssh-channel-send-exec (channel command)
  (ssh-channel-send-message
   channel +ssh-msg-channel-request+
   :fields (lambda (writer)
             (ssh-write-text writer "exec")
             (ssh-write-boolean writer t)
             (ssh-write-text writer command))))

(defun ssh-channel-send-subsystem (channel subsystem)
  "Ask the peer to run SUBSYSTEM on CHANNEL's session."
  (ssh-channel-send-message
   channel +ssh-msg-channel-request+
   :fields (lambda (writer)
             (ssh-write-text writer "subsystem")
             (ssh-write-boolean writer t)
             (ssh-write-text writer subsystem))))

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
  (let ((queue (ssh-channel-write-queue channel)))
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
        (ssh-channel-drop-queue channel count)))
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

(defun ssh-client-refuse-channel-open (client reader)
  "Answer a server-initiated CHANNEL_OPEN with administratively prohibited."
  (let* ((type (ssh-read-text reader))
         (sender (ssh-read-u32 reader))
         (writer (ssh-writer)))
    (declare (ignore type))
    (ssh-write-u8 writer +ssh-msg-channel-open-failure+)
    (ssh-write-u32 writer sender)
    (ssh-write-u32 writer 1)
    (ssh-write-text writer "server-initiated channels are not accepted")
    (ssh-write-text writer "")
    (ssh-client-send-payload client (ssh-writer-output writer))))

(defun ssh-channel-handle-open-confirmation (channel reader)
  (setf (ssh-channel-remote-id channel) (ssh-read-u32 reader)
        (ssh-channel-remote-window channel) (ssh-read-u32 reader)
        (ssh-channel-remote-max-packet channel) (ssh-read-u32 reader)
        (ssh-channel-state channel) :open)
  (let ((env (ssh-channel-pending-env channel))
        (exec (ssh-channel-pending-exec channel))
        (subsystem (ssh-channel-pending-subsystem channel)))
    (setf (ssh-channel-pending-env channel) nil
          (ssh-channel-pending-exec channel) nil
          (ssh-channel-pending-subsystem channel) nil)
    (iter (for (name . value) in env)
      (ssh-channel-send-env channel name value))
    (when exec
      (ssh-channel-send-exec channel exec))
    (when subsystem
      (ssh-channel-send-subsystem channel subsystem)))
  (ssh-channel-flush channel))

(defun ssh-channel-handle-open-failure (channel reader)
  (let ((reason (ssh-read-u32 reader))
        (description (ssh-read-text reader)))
    (declare (ignore reason))
    (ssh-channel-finish channel)
    (when (ssh-channel-on-error channel)
      (funcall (ssh-channel-on-error channel) channel
               (make-condition 'ssh-channel-error
                               :channel channel
                               :detail (format nil "channel open refused: ~A"
                                               description))))))

(defun ssh-channel-handle-data (channel reader extended)
  (let* ((kind (if extended
                   (if (= (ssh-read-u32 reader) 1) :stderr :other)
                   :stdout))
         (data (ssh-read-string reader)))
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
    (remhash (ssh-channel-local-id channel)
             (ssh-client-channels (ssh-channel-client channel)))
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
        (ssh-client-refuse-channel-open client reader)
        (let ((channel (ssh-client-channel-for client (ssh-read-u32 reader))))
          (when channel
            (case type
              (#.+ssh-msg-channel-open-confirmation+
               (ssh-channel-handle-open-confirmation channel reader))
              (#.+ssh-msg-channel-open-failure+
               (ssh-channel-handle-open-failure channel reader))
              (#.+ssh-msg-channel-window-adjust+
               (incf (ssh-channel-remote-window channel) (ssh-read-u32 reader))
               (ssh-channel-flush channel))
              (#.+ssh-msg-channel-data+
               (ssh-channel-handle-data channel reader nil))
              (#.+ssh-msg-channel-extended-data+
               (ssh-channel-handle-data channel reader t))
              (#.+ssh-msg-channel-eof+
               (setf (ssh-channel-eof-received channel) t)
               (when (ssh-channel-on-eof channel)
                 (funcall (ssh-channel-on-eof channel) channel)))
              (#.+ssh-msg-channel-close+
               (ssh-channel-handle-close channel))
              (#.+ssh-msg-channel-request+
               (ssh-channel-handle-request channel reader))
              (#.+ssh-msg-channel-success+ nil)
              (#.+ssh-msg-channel-failure+
               (when (ssh-channel-on-error channel)
                 (funcall (ssh-channel-on-error channel) channel
                          (make-condition 'ssh-channel-error
                                          :channel channel
                                          :detail "request refused"))))))))))

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
