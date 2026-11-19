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

(defun ssh-server-register-channel (session type sender window max-packet
                                     &key open-extra on-data on-eof on-exec
                                       on-close on-error)
  "Create a channel for SENDER and confirm it."
  (let* ((id (ssh-session-next-channel-id session))
         (channel (%make-ssh-server-channel
                   :session session
                   :local-id id
                   :remote-id sender
                   :type type
                   :open-extra (or open-extra
                                   (make-array 0 :element-type '(unsigned-byte 8)))
                   :state :open
                   :remote-window window
                   :remote-max-packet max-packet
                   :local-window (ssh-session-window session)
                   :local-max-packet (ssh-session-max-packet session)
                   :on-data on-data :on-eof on-eof :on-exec on-exec
                   :on-close on-close :on-error on-error)))
    (incf (ssh-session-next-channel-id session))
    (setf (gethash id (ssh-session-channels session)) channel)
    (ssh-server-channel-open-confirmation channel)
    channel))

(defun ssh-server-open-session-channel (session sender window max-packet)
  "Accept a session channel and make it available to the application."
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
  "Ask the application about a forwarded connection, then pipe it."
  (let* ((host (ssh-read-text reader))
         (port (ssh-read-u32 reader))
         (origin (ssh-read-text reader))
         (origin-port (ssh-read-u32 reader))
         (handler (ssh-server-on-direct-tcpip (ssh-session-server session)))
         (allowed (and handler
                       (funcall handler session host port origin origin-port))))
    (if allowed
        (let ((channel (ssh-server-register-channel
                        session "direct-tcpip" sender window max-packet)))
          (ssh-server-connect-target channel host port))
        (ssh-server-channel-open-failure
         session sender 1
         (format nil "direct-tcpip to ~A:~D is not permitted" host port)))))

;;; ---- Requests ----

(defun ssh-server-channel-reply (channel ok want-reply)
  (when want-reply
    (ssh-server-channel-send-message
     channel (if ok +ssh-msg-channel-success+ +ssh-msg-channel-failure+))))

(defun ssh-server-handle-env-request (channel reader want-reply)
  (let* ((name (ssh-read-text reader))
         (value (ssh-read-text reader))
         (ok (ssh-server-env-allowed-p
              (ssh-session-server (ssh-server-channel-session channel))
              name value)))
    (when ok
      (push (cons name value) (ssh-server-channel-env channel)))
    (ssh-server-channel-reply channel ok want-reply)))

(defun ssh-server-handle-exec-request (channel reader want-reply)
  (let ((command (ssh-read-text reader)))
    (setf (ssh-server-channel-command channel) command)
    (ssh-server-channel-reply channel t want-reply)
    (when (ssh-server-channel-on-exec channel)
      (funcall (ssh-server-channel-on-exec channel) channel command))))

(defun ssh-server-handle-channel-request (session channel reader)
  "Dispatch one request addressed to CHANNEL."
  (let ((request (ssh-read-text reader))
        (want-reply (ssh-read-boolean reader)))
    (cond
      ((string= request "env")
       (ssh-server-handle-env-request channel reader want-reply))
      ((string= request "exec")
       (ssh-server-handle-exec-request channel reader want-reply))
      ((string= request "window-change")
       (ssh-read-u32 reader) (ssh-read-u32 reader)
       (ssh-read-u32 reader) (ssh-read-u32 reader))
      ((member request '("pty-req" "shell" "subsystem" "auth-agent-req@openssh.com"
                         "x11-req")
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
  (ssh-server-channel-flush channel)
  channel)

(defun ssh-server-channel-write-stderr (channel data &key on-done)
  "Queue DATA as extended channel data, the SSH equivalent of stderr."
  (ssh-server-channel-send-message
   channel +ssh-msg-channel-extended-data+
   :fields (lambda (writer)
             (ssh-write-u32 writer 1)
             (ssh-write-string writer (ssh-ensure-octets data))))
  (when on-done (funcall on-done))
  channel)

(defun ssh-server-channel-eof (channel)
  "Say no more output follows, after everything already queued."
  (setf (ssh-server-channel-want-eof channel) t)
  (ssh-server-channel-flush channel)
  channel)

(defun ssh-server-channel-close (channel)
  "Start the close handshake, after everything already queued."
  (when (member (ssh-server-channel-state channel) '(:open :opening))
    (setf (ssh-server-channel-want-close channel) t)
    (ssh-server-channel-flush channel))
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

(defun ssh-server-dispatch-channel-message (session type channel reader)
  (case type
    (#.+ssh-msg-channel-window-adjust+
     (incf (ssh-server-channel-remote-window channel) (ssh-read-u32 reader))
     (ssh-server-channel-flush channel))
    (#.+ssh-msg-channel-data+
     (ssh-server-channel-handle-data channel reader nil))
    (#.+ssh-msg-channel-extended-data+
     (ssh-server-channel-handle-data channel reader t))
    (#.+ssh-msg-channel-eof+
     (setf (ssh-server-channel-eof-received channel) t)
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
      (balkort.resolve:resolve-host
       host
       (lambda (address)
         (ssh-server-dial-target channel address port))
       (lambda (condition)
         (ssh-server-channel-fail channel condition)))
    (error (condition) (ssh-server-channel-fail channel condition))))

(defun ssh-server-dial-target (channel address port)
  "Open the target TCP connection for CHANNEL once its name resolved."
  (let ((connection
          (cl-pnet:tcp-connect
           address port
           :read-cb (lambda (connection data)
                      (declare (ignore connection))
                      (if data
                          (ssh-server-channel-write channel data)
                          (ssh-server-channel-eof channel)))
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
  "Report CONDITION and close CHANNEL."
  (when (ssh-server-channel-on-error channel)
    (funcall (ssh-server-channel-on-error channel) channel condition))
  (ssh-server-channel-close channel))

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
