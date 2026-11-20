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
                                              on-data on-eof on-exit
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
                   :on-data on-data :on-eof on-eof :on-exit on-exit
                   :on-close on-close :on-error on-error)))
    (when (ssh-plibssh-null-p handle)
      (error 'ssh-channel-error
             :channel nil
             :detail "could not allocate a libssh channel"))
    (incf (ssh-client-next-channel-id client))
    (setf (gethash id (ssh-client-channels client)) channel)
    (ssh-plibssh-drive-channel channel)
    channel))

(defun ssh-open-session (client &key on-data on-eof on-exit on-close on-error)
  "Open a session channel; commands run on it with SSH-CHANNEL-EXEC."
  (ssh-plibssh-open-channel client "session"
                            :on-data on-data :on-eof on-eof :on-exit on-exit
                            :on-close on-close :on-error on-error))

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

;;; ---- Requests ----

(defun ssh-plibssh-issue-request (channel request)
  "Send one queued REQUEST, returning libssh's code."
  (ecase (first request)
    (:env
     (ssh-channel-request-env (ssh-channel-handle channel)
                              (second request) (third request)))
    (:exec
     (ssh-channel-request-exec (ssh-channel-handle channel)
                               (second request)))))

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
               ;; sshd refuses env names it does not accept.  OpenSSH treats
               ;; that as an ordinary outcome and still runs the command, so
               ;; the rest of the queue must go out.
               ((eq (first request) :env) nil)
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
         (rc (if (string= (ssh-channel-type channel) "session")
                 (ssh-channel-open-session (ssh-channel-handle channel))
                 (ssh-channel-open-forward
                  (ssh-channel-handle channel)
                  (ssh-channel-target-host channel)
                  (ssh-channel-target-port channel)
                  (ssh-channel-origin-address channel)
                  (ssh-channel-origin-port channel)))))
    (cond
      ((zerop rc)
       (setf (ssh-channel-state channel) :open)
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
