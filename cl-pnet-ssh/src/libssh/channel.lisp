(in-package #:cl-pnet-ssh)

;;;; The libssh channel role.  libssh allows one request in flight per channel,
;;;; so started requests are kept as a queue and retried until the peer
;;;; answers; the same queue makes env-then-exec ordering explicit.  Incoming
;;;; bytes are drained with SSH_CHANNEL_READ_NONBLOCKING, which also drives
;;;; the session's packet processing.

(defconstant +ssh-read-chunk+ 32768)

;;; ---- Construction ----

(defun ssh-plibssh-open-channel (client type &key target-host target-port
                                              (origin-address "0.0.0.0")
                                              origin-port
                                              on-data on-open on-eof on-exit
                                              on-close on-error)
  "Create a client channel of TYPE and start opening it."
  (let* ((id (ssh-client-next-channel-id client))
         (handle (ssh-channel-new (ssh-client-session client)))
         (channel (%make-ssh-channel
                   :client client
                   :handle handle
                   :local-id id
                   :type type
                   :state :queued
                   :target-host target-host
                   :target-port target-port
                   :origin-address origin-address
                   :origin-port (or origin-port 0)
                   :exit-status 0
                   :on-data on-data :on-open on-open :on-eof on-eof
                   :on-exit on-exit
                   :on-close on-close :on-error on-error)))
    (when (ssh-plibssh-null-p handle)
      (error 'ssh-channel-error
             :channel nil
             :detail "could not allocate a libssh channel"))
    (incf (ssh-client-next-channel-id client))
    (setf (gethash id (ssh-client-channels client)) channel)
    (ssh-plibssh-drive-channel channel)
    channel))

(defun ssh-open-channel (client type &key open-extra on-data on-open on-eof
                                      on-exit on-close on-error)
  "Register a channel of TYPE on CLIENT and ask the peer for it.

OPEN-EXTRA carries the type-specific opening arguments, which libssh takes
through dedicated calls; only session, direct-tcpip and direct-streamlocal
are meaningful to it, and the last two are opened by SSH-OPEN-DIRECT-*."
  (declare (ignore open-extra))
  (ssh-plibssh-open-channel client type
                            :on-data on-data :on-open on-open :on-eof on-eof
                            :on-exit on-exit :on-close on-close
                            :on-error on-error))

(defun ssh-plibssh-client-agent-path (client)
  "The local agent socket CLIENT forwards, or NIL.

ForwardAgent's path form wins over SSH_AUTH_SOCK, and a path that is gone
disables forwarding, as ssh's check_agent_present does."
  (let ((path (or (ssh-client-forward-agent-sock-path client)
                  (uiop:getenv "SSH_AUTH_SOCK"))))
    (and path
         (plusp (length path))
         (probe-file path)
         path)))

(defun ssh-plibssh-client-accept-agent-channel (client)
  "Accept a server-initiated agent channel, dialling the local agent.

Returns the libssh channel handle the callback must hand back, or NIL to
refuse the open."
  (let ((path (and (ssh-client-forward-agent client)
                   (ssh-plibssh-client-agent-path client))))
    (unless path
      (ssh-log "refusing an agent channel: forwarding was not enabled")
      (return-from ssh-plibssh-client-accept-agent-channel nil))
    (multiple-value-bind (fd status)
        (cl-pnet-sockets:connect-unix path)
      (unless fd
        (ssh-log "cannot connect to the agent at ~A: ~A"
                 path (cl-pnet-sockets:c-strerror status))
        (return-from ssh-plibssh-client-accept-agent-channel nil))
      (let* ((handle (ssh-channel-new (ssh-client-session client)))
             (id (ssh-client-next-channel-id client))
             (channel (%make-ssh-channel
                       :client client
                       :handle handle
                       :local-id id
                       :type "auth-agent@openssh.com"
                       :state :open
                       :exit-status 0)))
        (when (ssh-plibssh-null-p handle)
          (ignore-errors (cl-pnet-sockets:close-open-fd fd))
          (return-from ssh-plibssh-client-accept-agent-channel nil))
        (let ((relay (%make-ssh-fd-relay
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
                        (ssh-channel-eof channel))
                      :on-error
                      (lambda (relay condition)
                        (declare (ignore relay))
                        (ssh-plibssh-channel-fail channel condition)))))
          (setf (ssh-channel-agent-relay channel) relay
                (ssh-channel-on-data channel)
                (lambda (channel data kind)
                  (declare (ignore channel kind))
                  (ssh-fd-relay-queue relay data))
                (ssh-channel-on-eof channel)
                (lambda (channel)
                  (declare (ignore channel))
                  (ssh-fd-relay-shutdown-write relay))
                (ssh-channel-on-close channel)
                (lambda (channel status)
                  (declare (ignore channel status))
                  (ssh-fd-relay-close relay))
                (ssh-channel-on-error channel)
                (lambda (channel condition)
                  (declare (ignore channel condition))
                  (ssh-fd-relay-close relay)))
          (incf (ssh-client-next-channel-id client))
          (setf (gethash id (ssh-client-channels client)) channel)
          (ssh-fd-relay-start relay)
          handle)))))

(cffi:defcallback ssh-plibssh-agent-open-request-callback
    cl-plibssh:libssh-channel ((session :pointer) (userdata :pointer))
  (declare (ignore userdata))
  (let ((client (ssh-plibssh-session-object session)))
    (or (and client (ssh-plibssh-client-accept-agent-channel client))
        (cffi:null-pointer))))

(defun ssh-plibssh-install-client-callbacks (client)
  "Give CLIENT the common callbacks libssh needs to route agent opens."
  (unless (ssh-client-callbacks client)
    (let* ((type 'ssh-callbacks-struct)
           (struct (cffi:foreign-alloc (list :struct type))))
      (setf (cffi:foreign-slot-value struct (list :struct type) 'cl-plibssh::size)
            (ssh-plibssh-callback-struct-size type))
      (dolist (slot '(cl-plibssh::userdata
                      cl-plibssh::auth-function
                      cl-plibssh::log-function
                      cl-plibssh::connect-status-function
                      cl-plibssh::global-request-function
                      cl-plibssh::channel-open-request-x11-function))
        (setf (cffi:foreign-slot-value struct (list :struct type) slot)
              (cffi:null-pointer)))
      (setf (cffi:foreign-slot-value
             struct (list :struct type)
             'cl-plibssh::channel-open-request-auth-agent-function)
            (cffi:callback ssh-plibssh-agent-open-request-callback))
      (when (minusp (ssh-set-callbacks (ssh-client-session client) struct))
        (cffi:foreign-free struct)
        (error 'ssh-connection-error
               :detail (format nil "libssh rejected the callbacks: ~A"
                               (ssh-plibssh-error
                                (ssh-client-session client)))))
      (setf (ssh-client-callbacks client) struct))))

(defun ssh-open-session (client &key on-data on-open on-eof on-exit
                                  on-close on-error)
  "Open a session channel; commands run on it with SSH-CHANNEL-EXEC.

When ForwardAgent is on and an agent socket exists, the agent-forwarding
request is queued for the moment the peer confirms the channel."
  (ssh-plibssh-install-client-callbacks client)
  (let ((channel
          (ssh-plibssh-open-channel client "session"
                                    :on-data on-data :on-open on-open
                                    :on-eof on-eof
                                    :on-exit on-exit
                                    :on-close on-close :on-error on-error)))
    (when (and (ssh-client-forward-agent client)
               (ssh-plibssh-client-agent-path client))
      (ssh-channel-queue-request channel '(:agent))
      (ssh-plibssh-drive-channel channel))
    channel))

(defun ssh-open-direct-tcpip (client host port
                              &key (origin-address "0.0.0.0") (origin-port 0)
                                   on-data on-eof on-close on-error)
  "Ask the peer to connect to HOST:PORT and carry the bytes on a channel."
  (ssh-plibssh-open-channel client "direct-tcpip"
                            :target-host host :target-port port
                            :origin-address origin-address
                            :origin-port origin-port
                            :on-data on-data :on-eof on-eof
                            :on-close on-close :on-error on-error))

(defun ssh-open-direct-streamlocal (client path
                                    &key on-data on-open on-eof on-close
                                      on-error)
  "Ask the peer to connect to the Unix socket PATH and carry its bytes."
  (ssh-plibssh-open-channel client "direct-streamlocal@openssh.com"
                            :target-host path
                            :on-data on-data :on-open on-open :on-eof on-eof
                            :on-close on-close :on-error on-error))

(defun ssh-client-send-global-request (client name &key fields on-success
                                                     on-failure)
  "Refuse a global request; libssh exposes no asynchronous entry point.

Remote forwarding is the only caller, and SSH-CLIENT-FEATURE-SUPPORTED-P
reports it as unavailable, so this is a guard rather than a path a working
client takes."
  (declare (ignore client fields on-success on-failure))
  (error 'ssh-unsupported-feature
         :feature name
         :detail "global requests are not available in the libssh transport"))

(defun ssh-client-connect-forward-target (channel host port)
  "Refuse a server-initiated forwarded connection.

libssh has no forwarded-tcpip channel-open callback, so the libssh server
cannot ask this client to dial a target either."
  (declare (ignore host port))
  (error 'ssh-unsupported-feature
         :feature "forwarded-tcpip"
         :detail (format nil "the libssh transport cannot bridge a forwarded ~
                              channel (~A)" channel)))

;;; ---- Requests ----

(defun ssh-plibssh-issue-request (channel request)
  "Send one queued REQUEST, returning libssh's code."
  (ecase (first request)
    (:env
     (ssh-channel-request-env (ssh-channel-handle channel)
                              (second request) (third request)))
    (:exec
     (ssh-channel-request-exec (ssh-channel-handle channel)
                               (second request)))
    (:pty
     (ssh-channel-request-pty-size (ssh-channel-handle channel)
                                   (second request) (third request)
                                   (fourth request)))
    (:window-change
     (ssh-channel-change-pty-size (ssh-channel-handle channel)
                                  (second request) (third request)))
    (:shell
     (ssh-channel-request-shell (ssh-channel-handle channel)))
    (:subsystem
     (ssh-channel-request-subsystem (ssh-channel-handle channel)
                                    (second request)))
    (:agent
     (ssh-channel-request-auth-agent (ssh-channel-handle channel)))
    (:x11
     (ssh-channel-request-x11 (ssh-channel-handle channel)
                              (second request) (third request)
                              (fourth request) (fifth request)))))

(defun ssh-plibssh-drive-requests (channel)
  "Send queued requests one at a time, staying on the first until it answers."
  (when (eq (ssh-channel-state channel) :open)
    (loop
      (let ((request (first (ssh-channel-requests channel))))
        (unless request (return))
        (let ((rc (ssh-plibssh-issue-request channel request)))
          (cond
            ((zerop rc) (pop (ssh-channel-requests channel)))
            ((= rc +ssh-again+) (return))
            (t
             (pop (ssh-channel-requests channel))
             (cond
               ;; sshd refuses env names and pty requests under policy (no-pty,
               ;; restrict).  OpenSSH treats those as ordinary outcomes and
               ;; still runs the shell or command, so the rest of the queue
               ;; must go out.
               ((member (first request) '(:env :pty :window-change)) nil)
               (t
                (ssh-plibssh-channel-fail
                 channel
                 (make-condition 'ssh-channel-error
                                 :channel channel
                                 :detail (format nil "request ~A was refused: ~A"
                                                 (first request)
                                                 (ssh-plibssh-error
                                                  (ssh-client-session
                                                   (ssh-channel-client channel))))))
                (return))))))))))

(defun ssh-channel-queue-request (channel request)
  (setf (ssh-channel-requests channel)
        (append (ssh-channel-requests channel) (list request))))

(defun ssh-plibssh-channel-request-descriptor (reader name)
  "Turn a request NAME and its wire arguments into a queue descriptor.

Only the fields libssh's own request calls accept are kept; the rest are
read and dropped so the reader stays aligned."
  (cond
    ((string= name "pty-req")
     (let ((term (ssh-read-text reader))
           (columns (ssh-read-u32 reader))
           (rows (ssh-read-u32 reader)))
       (ssh-read-u32 reader)                ; pixel width
       (ssh-read-u32 reader)                ; pixel height
       (ssh-read-string reader)             ; terminal modes
       (list :pty term columns rows)))
    ((string= name "window-change")
     (let ((columns (ssh-read-u32 reader))
           (rows (ssh-read-u32 reader)))
       (ssh-read-u32 reader)
       (ssh-read-u32 reader)
       (list :window-change columns rows)))
    ((string= name "shell")
     (list :shell))
    ((string= name "subsystem")
     (list :subsystem (ssh-read-text reader)))
    ((string= name "env")
     (list :env (ssh-read-text reader) (ssh-read-text reader)))
    ((string= name "exec")
     (list :exec (ssh-read-text reader)))
    ((or (string= name "auth-agent-req@openssh.com")
         (string= name "agent-req"))
     (list :agent))
    ((string= name "x11-req")
     (let ((single (ssh-read-boolean reader))
           (protocol (ssh-read-text reader))
           (cookie (ssh-read-text reader))
           (screen (ssh-read-u32 reader)))
       (list :x11 (if single 1 0) protocol cookie screen)))
    (t nil)))

(defun ssh-channel-send-message (channel type &key fields)
  "A channel message with TYPE, CHANNEL's remote id, and FIELDS as a thunk.

libssh owns the wire format, so a request is decoded back into the arguments
its own request call takes and queued like SSH-CHANNEL-EXEC."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer type)
    ;; The remote id is libssh's to fill in; a zero is a valid placeholder
    ;; because the payload never reaches the wire in this form.
    (ssh-write-u32 writer 0)
    (when fields (funcall fields writer))
    (let* ((payload (ssh-writer-output writer))
           (reader (ssh-make-reader payload))
           (message-type (ssh-read-u8 reader))
           (remote-id (ssh-read-u32 reader)))
      (declare (ignore remote-id))
      (unless (= message-type +ssh-msg-channel-request+)
        (error 'ssh-channel-error
               :channel channel
               :detail (format nil "the libssh backend cannot send message ~D"
                               message-type)))
      (let* ((name (ssh-read-text reader))
             (want-reply (ssh-read-boolean reader))
             (descriptor (ssh-plibssh-channel-request-descriptor reader name)))
        (declare (ignore want-reply))
        (unless descriptor
          (error 'ssh-channel-error
                 :channel channel
                 :detail (format nil "the libssh backend cannot send request ~A"
                                 name)))
        (ssh-channel-queue-request channel descriptor)
        (ssh-plibssh-drive-channel channel))))
  channel)

(defun ssh-channel-env (channel name value)
  "Set NAME=VALUE for commands run later on CHANNEL."
  (case (ssh-channel-state channel)
    (:closed (error 'ssh-channel-error
                    :channel channel :detail "channel is closed"))
    (:closing nil)
    (t
     (ssh-channel-queue-request channel (list :env name value))
     (ssh-plibssh-drive-channel channel)))
  channel)

(defun ssh-channel-exec (channel command)
  "Run COMMAND on CHANNEL's session, or queue it until the channel opens."
  (case (ssh-channel-state channel)
    (:closed (error 'ssh-channel-error
                    :channel channel :detail "channel is closed"))
    (:closing nil)
    (t
     (ssh-channel-queue-request channel (list :exec command))
     (ssh-plibssh-drive-channel channel)))
  channel)

(defun ssh-channel-subsystem (channel subsystem)
  "Run SUBSYSTEM on CHANNEL's session, or queue it until the channel opens."
  (case (ssh-channel-state channel)
    (:closed (error 'ssh-channel-error
                    :channel channel :detail "channel is closed"))
    (:closing nil)
    (t
     (ssh-channel-queue-request channel (list :subsystem subsystem))
     (ssh-plibssh-drive-channel channel)))
  (unless (eq (ssh-channel-state channel) :closed)
    (ssh-channel-set-x-type
     channel (concatenate 'string "session:subsystem:" subsystem)))
  channel)

;;; ---- Writing ----

(defun ssh-plibssh-run-write-callbacks (channel)
  (let ((callbacks (nreverse (ssh-channel-write-callbacks channel))))
    (setf (ssh-channel-write-callbacks channel) nil)
    (iter (for callback in callbacks) (funcall callback))))

(defun ssh-plibssh-flush-channel (channel)
  "Send queued bytes, then the EOF or close the caller asked for."
  (let ((queue (ssh-channel-write-queue channel)))
    (when (eq (ssh-channel-state channel) :open)
      (loop
        (unless (plusp (fill-pointer queue)) (return))
        (let* ((count (min (fill-pointer queue) +ssh-read-chunk+))
               (written
                 (ssh-plibssh-write-octets
                  (lambda (buffer length)
                    (ssh-plibssh-channel-write (ssh-channel-handle channel)
                                               buffer length))
                  queue 0 count)))
          (cond
            ((plusp written) (ssh-plibssh-buffer-drop queue written))
            ((zerop written) (return))
            (t
             (ssh-plibssh-channel-fail
              channel
              (make-condition 'ssh-channel-error
                              :channel channel
                              :detail (format nil "channel write failed: ~A"
                                              (ssh-plibssh-error
                                               (ssh-client-session
                                                (ssh-channel-client channel))))))
             (return))))))
    (when (and (not (eq (ssh-channel-state channel) :closed))
               (zerop (fill-pointer queue)))
      (ssh-plibssh-run-write-callbacks channel)
      (when (and (ssh-channel-want-eof channel)
                 (not (ssh-channel-sent-eof channel))
                 (eq (ssh-channel-state channel) :open))
        (when (zerop (ssh-channel-send-eof (ssh-channel-handle channel)))
          (setf (ssh-channel-sent-eof channel) t)))
      (when (and (ssh-channel-want-close channel)
                 (not (ssh-channel-sent-close channel))
                 (member (ssh-channel-state channel) '(:open :queued)))
        (unless (minusp (ssh-plibssh-channel-close
                         (ssh-channel-handle channel)))
          (setf (ssh-channel-sent-close channel) t
                (ssh-channel-state channel) :closing))))))

(defun ssh-channel-write (channel data &key on-done)
  "Queue DATA for the peer's stdin; ON-DONE runs when it has all been sent."
  (when (eq (ssh-channel-state channel) :closed)
    (error 'ssh-channel-error :channel channel :detail "channel is closed"))
  (ssh-plibssh-buffer-append (ssh-channel-write-queue channel)
                             (ssh-ensure-octets data))
  (when on-done
    (push on-done (ssh-channel-write-callbacks channel)))
  (ssh-plibssh-flush-channel channel)
  channel)

(defun ssh-channel-eof (channel)
  "Say no more input follows, after everything already queued."
  (setf (ssh-channel-want-eof channel) t)
  (ssh-plibssh-flush-channel channel)
  channel)

(defun ssh-channel-close (channel)
  "Start the close handshake, after everything already queued."
  (when (member (ssh-channel-state channel) '(:queued :open :opening))
    (setf (ssh-channel-want-close channel) t)
    (ssh-plibssh-flush-channel channel))
  channel)

;;; ---- Reading ----

(defun ssh-plibssh-read-stream (channel stderr)
  "Drain one direction of CHANNEL into its data callback."
  (cffi:with-foreign-object (buffer :unsigned-char +ssh-read-chunk+)
    (loop
      (let ((rc (ssh-channel-read-nonblocking
                 (ssh-channel-handle channel) buffer +ssh-read-chunk+
                 (if stderr 1 0))))
        (cond
          ((plusp rc)
           (let ((data (ssh-plibssh-fill-octets buffer rc)))
             (when (ssh-channel-on-data channel)
               (funcall (ssh-channel-on-data channel) channel data
                        (if stderr :stderr :stdout)))))
          ((or (zerop rc) (= rc +ssh-eof+)) (return))
          (t
           ;; A gone server ends the session through its close callback;
           ;; only a read error on a live connection is a channel failure.
           (let* ((client (ssh-channel-client channel))
                  (session (ssh-client-session client)))
             (if (and session (plusp (ssh-is-connected session)))
                 (ssh-plibssh-channel-fail
                  channel
                  (make-condition 'ssh-channel-error
                                  :channel channel
                                  :detail (format nil "channel read failed: ~A"
                                                  (ssh-plibssh-error session))))
                 (ssh-client-finish client :peer-closed :close)))
           (return)))))))

(defun ssh-plibssh-finish-channel (channel)
  "Mark CHANNEL closed once, unregister it, and report its end."
  (unless (ssh-channel-close-reported channel)
    (setf (ssh-channel-close-reported channel) t
          (ssh-channel-state channel) :closed)
    (remhash (ssh-channel-local-id channel)
             (ssh-client-channels (ssh-channel-client channel)))
    (let ((handle (ssh-channel-handle channel)))
      (setf (ssh-channel-handle channel) nil)
      (when handle (ssh-channel-free handle)))
    (when (ssh-channel-on-close channel)
      (funcall (ssh-channel-on-close channel) channel
               (ssh-channel-exit-status channel)))))

(defun ssh-channel-handle-close (channel)
  "Close CHANNEL now, as the pure backend's timeout path does."
  (when (and (eq (ssh-channel-state channel) :open)
             (ssh-channel-handle channel))
    (ssh-plibssh-channel-close (ssh-channel-handle channel)))
  (ssh-plibssh-finish-channel channel))

(defun ssh-plibssh-channel-fail (channel condition)
  "Report CONDITION, then close CHANNEL.

The error callback runs first, as in the pure backend: a program that ends
the session from it must see the diagnostic before any close callback can
exit without one."
  (when (ssh-channel-on-error channel)
    (funcall (ssh-channel-on-error channel) channel condition))
  (ssh-plibssh-finish-channel channel))

(defun ssh-plibssh-channel-report-exit (channel)
  (let ((status (ssh-channel-get-exit-status (ssh-channel-handle channel))))
    (when (and (>= status 0)
               (not (ssh-channel-exit-reported channel)))
      (setf (ssh-channel-exit-status channel) status
            (ssh-channel-exit-reported channel) t)
      (when (ssh-channel-on-exit channel)
        (funcall (ssh-channel-on-exit channel) channel status)))))

(defun ssh-plibssh-channel-report-eof (channel)
  (when (and (plusp (ssh-channel-is-eof (ssh-channel-handle channel)))
             (not (ssh-channel-eof-reported channel)))
    (setf (ssh-channel-eof-reported channel) t
          (ssh-channel-eof-received channel) t)
    (when (ssh-channel-on-eof channel)
      (funcall (ssh-channel-on-eof channel) channel))))

(defun ssh-plibssh-drain-channel (channel)
  "Read everything available and report EOF, exit status and close."
  (unless (ssh-channel-close-reported channel)
    (when (eq (ssh-channel-state channel) :open)
      (ssh-plibssh-read-stream channel nil)
      (ssh-plibssh-read-stream channel t))
    (when (ssh-channel-handle channel)
      (ssh-plibssh-channel-report-exit channel)
      (ssh-plibssh-channel-report-eof channel)
      (when (plusp (ssh-channel-is-closed (ssh-channel-handle channel)))
        (ssh-plibssh-finish-channel channel)))))

;;; ---- Driving ----

(defun ssh-plibssh-open-channel-now (channel)
  "Send CHANNEL's open request; true once libssh reports it open."
  (let* ((client (ssh-channel-client channel))
         (rc (cond
               ((string= (ssh-channel-type channel) "session")
                (ssh-channel-open-session (ssh-channel-handle channel)))
               ((string= (ssh-channel-type channel)
                         "direct-streamlocal@openssh.com")
                (ssh-channel-open-forward-unix
                 (ssh-channel-handle channel)
                 (ssh-channel-target-host channel)
                 (ssh-channel-origin-address channel)
                 (ssh-channel-origin-port channel)))
               (t
                (ssh-channel-open-forward
                 (ssh-channel-handle channel)
                 (ssh-channel-target-host channel)
                 (ssh-channel-target-port channel)
                 (ssh-channel-origin-address channel)
                 (ssh-channel-origin-port channel))))))
    (cond
      ((zerop rc)
       (setf (ssh-channel-state channel) :open)
       (when (ssh-channel-on-open channel)
         (let ((callback (ssh-channel-on-open channel)))
           (setf (ssh-channel-on-open channel) nil)
           (funcall callback channel)))
       t)
      ((= rc +ssh-again+) nil)
      (t
       (ssh-plibssh-channel-fail
        channel
        (make-condition 'ssh-channel-error
                        :channel channel
                        :detail (format nil "channel open failed: ~A"
                                        (ssh-plibssh-error
                                         (ssh-client-session client)))))
       nil))))

(defun ssh-plibssh-drive-channel (channel)
  "Advance CHANNEL's open, requests, writes and reads as far as possible."
  (when (or (ssh-channel-close-reported channel)
            (null (ssh-channel-handle channel))
            (and (eq (ssh-channel-state channel) :queued)
                 (not (eq (ssh-client-phase
                           (ssh-channel-client channel))
                          :ready))))
    (return-from ssh-plibssh-drive-channel nil))
  (case (ssh-channel-state channel)
      (:queued
       (ssh-plibssh-open-channel-now channel)
       (when (eq (ssh-channel-state channel) :open)
         (ssh-plibssh-drive-requests channel)
         (ssh-plibssh-flush-channel channel)
         (ssh-plibssh-drain-channel channel)))
      (:open
       (ssh-plibssh-drive-requests channel)
       (ssh-plibssh-flush-channel channel)
       (ssh-plibssh-drain-channel channel))
      (:closing
       (ssh-plibssh-drain-channel channel))
      (:closed nil)))
