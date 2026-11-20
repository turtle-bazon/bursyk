(in-package #:cl-pnet-ssh)

;;;; The libssh server role.  The listening socket, the accepted descriptors
;;;; and all data are owned here; libssh only runs the protocol on a descriptor
;;;; it is handed.  That keeps accept(2) off the blocking DNS/connect path and
;;;; lets the event loop decide when a session may make progress.
;;;;
;;;; Each call that can wait is called from a descriptor watch.  A call that
;;;; would wait returns SSH_AGAIN and the watch comes back when the socket
;;;; moves, exactly as on the client side.

(defun ssh-plibssh-listen (address port)
  "Bind and listen on ADDRESS:PORT, returning a non-blocking descriptor."
  (let ((fd (cl-pnet-sockets:c-socket
             (if (cl-pnet-sockets:ipv6-address-p address)
                 cl-pnet-sockets:+af-inet6+
                 cl-pnet-sockets:+af-inet+)
             cl-pnet-sockets:+sock-stream+
             cl-pnet-sockets:+ipproto-tcp+)))
    (when (minusp fd)
      (error 'ssh-connection-error
             :detail (format nil "could not make a socket (~A)"
                             (cl-pnet-sockets:c-strerror
                              (cl-pnet-sockets:c-errno)))))
    (flet ((fail (detail)
             (cl-pnet-sockets:c-close fd)
             (error 'ssh-connection-error :detail detail)))
      ;; Best effort: a refused REUSEADDR must not stop a listener from
      ;; binding a fresh port, only a restart from reusing a fresh one.
      (cl-pnet-sockets:set-socket-option
       fd cl-pnet-sockets:+sol-socket+ cl-pnet-sockets:+so-reuseaddr+ 1)
      (multiple-value-bind (sockaddr length)
          (cl-pnet-sockets:make-sockaddr address port)
        (unless sockaddr
          (fail (format nil "not an address: ~A" address)))
        (let ((result (cl-pnet-sockets:c-bind fd sockaddr length)))
          (cffi:foreign-free sockaddr)
          (when (minusp result)
            (fail (format nil "could not bind ~A:~D (~A)"
                          address port
                          (cl-pnet-sockets:c-strerror
                           (cl-pnet-sockets:c-errno)))))))
      (when (minusp (cl-pnet-sockets:c-listen fd 128))
        (fail (format nil "could not listen on ~A:~D (~A)"
                      address port
                      (cl-pnet-sockets:c-strerror
                       (cl-pnet-sockets:c-errno)))))
      (cl-pnet-sockets:set-nonblocking fd)
      fd)))

(defun ssh-plibssh-bound-port (fd)
  "The port FD is actually bound to; needed when the caller asked for zero."
  (cffi:with-foreign-objects
      ((address '(:struct cl-pnet-sockets:sockaddr-in6))
       (length :unsigned-int))
    (setf (cffi:mem-ref length :unsigned-int)
          cl-pnet-sockets:+sockaddr-in6-size+)
    (when (>= (cl-pnet-sockets:c-getsockname fd address length) 0)
      (multiple-value-bind (ip port)
          (cl-pnet-sockets:sockaddr-to-string address)
        (declare (ignore ip))
        port))))

(defun ssh-plibssh-peer-address (fd)
  "FD's peer as (:ADDRESS IP :PORT PORT), the shape CL-PNET reports."
  (cffi:with-foreign-objects
      ((address '(:struct cl-pnet-sockets:sockaddr-in6))
       (length :unsigned-int))
    (setf (cffi:mem-ref length :unsigned-int)
          cl-pnet-sockets:+sockaddr-in6-size+)
    (when (>= (cl-pnet-sockets:c-getpeername fd address length) 0)
      (multiple-value-bind (ip port)
          (cl-pnet-sockets:sockaddr-to-string address)
        (when ip (list :address ip :port port))))))

;;; ---- Sessions ----

(defun ssh-plibssh-session-channels (session)
  (iter (for (id channel) in-hashtable (ssh-session-channels session))
    (declare (ignore id))
    (collect channel)))

(defun ssh-plibssh-session-sync-watchers (session)
  "Arm the write watch exactly when libssh has bytes it could not send."
  (let ((watcher (ssh-session-write-watcher session))
        (handle (ssh-session-handle session))
        (fd (ssh-session-fd session)))
    (if (and handle fd (not (ssh-session-closed session))
             (logtest (ssh-get-poll-flags handle) +ssh-write-pending+))
        (unless watcher
          (setf (ssh-session-write-watcher session)
                (cl-pnet:fd-watch
                 fd
                 :on-writable
                 (lambda (watcher)
                   (declare (ignore watcher))
                   (ssh-plibssh-session-pump session)))))
        (when watcher
          (setf (ssh-session-write-watcher session) nil)
          (cl-pnet:fd-unwatch watcher)))))

(defun ssh-plibssh-session-pump (session)
  "Advance SESSION as far as its descriptor allows."
  (when (and (ssh-session-handle session)
             (not (ssh-session-closed session)))
    (handler-case
        (progn
          (case (ssh-session-phase session)
            (:key-exchange (ssh-plibssh-session-drive-key-exchange session))
            (:authenticating (ssh-plibssh-session-drive-messages session))
            (:ready (ssh-plibssh-session-drive-messages session))
            (:closed nil))
          (unless (ssh-session-closed session)
            (ssh-plibssh-session-sync-watchers session)))
      (error (condition)
        (ssh-session-fail session condition)))))

(defun ssh-plibssh-session-drive-key-exchange (session)
  "Run SSH_HANDLE_KEY_EXCHANGE until the handshake completes."
  (let ((rc (ssh-handle-key-exchange (ssh-session-handle session))))
    (cond
      ((zerop rc)
       (setf (ssh-session-phase session) :authenticating
             (ssh-session-client-version session)
             (ssh-get-clientbanner (ssh-session-handle session)))
       (ssh-plibssh-session-drive-messages session))
      ((= rc +ssh-again+) nil)
      (t
       (error 'ssh-connection-error
              :detail (format nil "SSH handshake failed: ~A"
                              (ssh-plibssh-error (ssh-session-handle session))))))))

(defun ssh-plibssh-session-drive-messages (session)
  "Drain every request libssh has, then move any channel's bytes."
  (loop
    (when (ssh-session-closed session) (return))
    (let ((message (ssh-message-get (ssh-session-handle session))))
      (when (ssh-plibssh-null-p message)
        (unless (plusp (ssh-is-connected (ssh-session-handle session)))
          (ssh-session-finish session :peer-closed :close))
        (return))
      (unwind-protect
           (ssh-plibssh-session-handle-message session message)
        (ssh-message-free message))
      ;; A policy refusal decided inside the callback (MaxAuthTries) takes
      ;; effect now, with libssh no longer holding the message.
      (let ((reason (ssh-session-pending-close session)))
        (when reason
          (setf (ssh-session-pending-close session) nil)
          (ssh-session-finish session reason :close)
          (return)))))
  (when (and (not (ssh-session-closed session))
             (eq (ssh-session-phase session) :ready))
    (iter (for channel in (ssh-plibssh-session-channels session))
      (ssh-plibssh-server-channel-drive channel))
    (unless (or (ssh-session-closed session)
                (plusp (ssh-is-connected (ssh-session-handle session))))
      (ssh-session-finish session :peer-closed :close))))

(defun ssh-plibssh-session-handle-message (session message)
  "Dispatch one libssh request."
  (let ((type (ssh-message-type message)))
    (cond
      ((= type +ssh-request-auth+)
       (ssh-plibssh-session-handle-auth session message))
      ((= type +ssh-request-service+)
       (ssh-message-reply-default message))
      ((and (= type +ssh-request-channel-open+)
            (eq (ssh-session-phase session) :ready))
       (ssh-plibssh-session-handle-open session message))
      ((and (= type +ssh-request-channel+)
            (eq (ssh-session-phase session) :ready))
       (ssh-plibssh-session-handle-channel-request session message))
      (t (ssh-message-reply-default message)))))

;;; ---- Authentication ----

;;; ---- Account policy helpers shared with the pure backend's API ----
;;;
;;; The pure backend defines these in CL-LIBBURSKY's server files, which a
;;; :ssh-backend-ffi build does not compile.  The names are part of the public
;;; server API either way, so this backend carries its own copies.

(defun ssh-server-auth-failure-counts-p (attempt method)
  "Whether a failed ATTEMPT using METHOD counts toward MaxAuthTries.

sshd exempts the first \"none\" probe every client sends to learn the
allowed methods; everything after it counts."
  (or (/= 1 attempt)
      (not (string= method "none"))))

(defun ssh-server-session-channel-count (session)
  "How many session channels SESSION still has open or opening."
  (loop for channel being the hash-values of (ssh-session-channels session)
        counting (and (string= (ssh-server-channel-type channel) "session")
                      (not (eq (ssh-server-channel-state channel) :closed)))))

(defun ssh-server-user-permitted-p (session user)
  "Whether the application admits USER on SESSION, cached per name."
  (let ((hook (ssh-server-authorize-user (ssh-session-server session))))
    (if (null hook)
        t
        (let ((cached (assoc user (ssh-session-allowed-users session)
                             :test #'string=)))
          (if cached
              (cdr cached)
              (let ((allowed (and (funcall hook session user) t)))
                (push (cons user allowed)
                      (ssh-session-allowed-users session))
                allowed))))))

(defun ssh-plibssh-auth-failure (message)
  "Refuse a request, advertising the one method this server offers."
  (ssh-message-auth-set-methods message +ssh-auth-method-publickey+)
  (ssh-message-reply-default message))

(defun ssh-plibssh-session-auth-failure (session message &key (count t))
  "Refuse one userauth attempt, counting it toward MaxAuthTries when COUNT.

A limit reached inside a libssh callback cannot close the session there, so
the reason is recorded and the pump finishes it after the callback returns."
  (when count
    (incf (ssh-session-auth-failures session))
    (when (>= (ssh-session-auth-failures session)
              (ssh-server-max-auth-tries (ssh-session-server session)))
      (setf (ssh-session-pending-close session) :auth-failures)))
  (ssh-plibssh-auth-failure message))

(defun ssh-plibssh-session-complete-auth (session message user key-blob)
  "Accept USER for SESSION, then let the application run."
  (declare (ignore key-blob))
  (setf (ssh-session-user session) user
        (ssh-session-authenticated session) t
        (ssh-session-phase session) :ready)
  (ssh-message-auth-reply-success message 0)
  (when (ssh-server-on-session (ssh-session-server session))
    (funcall (ssh-server-on-session (ssh-session-server session)) session)))

(defun ssh-plibssh-session-handle-auth (session message)
  "Answer one USER AUTH REQUEST from MESSAGE."
  (let* ((user (ssh-message-auth-user message))
         (method (ssh-message-subtype message)))
    (setf (ssh-session-user session) user)
    (incf (ssh-session-auth-attempts session))
    (let ((count (ssh-server-auth-failure-counts-p
                  (ssh-session-auth-attempts session)
                  (if (= method +ssh-auth-method-none+) "none" "other"))))
      (cond
        ((not (ssh-server-user-permitted-p session user))
         (ssh-plibssh-session-auth-failure session message :count count))
        ((= method +ssh-auth-method-none+)
         (ssh-plibssh-session-auth-failure session message :count count))
        ((= method +ssh-auth-method-publickey+)
         (ssh-plibssh-session-handle-publickey session message user count))
        (t (ssh-plibssh-session-auth-failure session message :count count))))))

(defun ssh-plibssh-session-handle-publickey (session message user
                                            &optional (count t))
  "Handle a publickey offer (state NONE) or a signed attempt (state VALID).

COUNT is false for an accepted offer, which sshd does not treat as a failed
authentication attempt."
  (let* ((key (ssh-message-auth-pubkey message))
         (state (ssh-message-auth-publickey-state message))
         (blob (and key (ssh-plibssh-public-key-blob key)))
         (authorized
           (and blob
                (ssh-server-authorized-key-p
                 (ssh-session-server session) user blob))))
    (cond
      ((null key) (ssh-plibssh-session-auth-failure session message
                                                    :count count))
      ((and authorized (= state +ssh-publickey-state-none+))
       (ssh-message-auth-reply-pk-ok-simple message))
      ((and authorized (= state +ssh-publickey-state-valid+))
       (ssh-plibssh-session-complete-auth session message user blob))
      (t (ssh-plibssh-session-auth-failure session message :count count)))))

;;; ---- Channel opens ----

(defun ssh-plibssh-session-register-channel (session handle type)
  "Wrap HANDLE in the server's channel record and announce it."
  (let* ((id (ssh-session-next-channel-id session))
         (channel (%make-ssh-server-channel
                   :session session
                   :handle handle
                   :local-id id
                   :type type
                   :state :open
                   :remote-address (ssh-session-remote-address session))))
    (incf (ssh-session-next-channel-id session))
    (setf (gethash id (ssh-session-channels session)) channel)
    channel))

(defun ssh-plibssh-session-handle-open (session message)
  "Accept or refuse one CHANNEL OPEN request."
  (case (ssh-message-subtype message)
    (#.+ssh-channel-session+
     (ssh-plibssh-session-open-session session message))
    (#.+ssh-channel-direct-tcpip+
     (ssh-plibssh-session-open-direct-tcpip session message))
    (t (ssh-message-reply-default message))))

(defun ssh-plibssh-session-open-session (session message)
  "Accept a session channel and offer it to the application.

MaxSessions bounds how many may be live at once, as in sshd: a further open
is refused instead of allocated."
  (let ((limit (ssh-server-max-sessions (ssh-session-server session))))
    (when (and limit
               (>= (ssh-server-session-channel-count session) limit))
      (ssh-message-reply-default message)
      (return-from ssh-plibssh-session-open-session nil)))
  (let ((handle (ssh-message-open-reply-accept message)))
    (when (ssh-plibssh-null-p handle)
      (error 'ssh-channel-error
             :channel nil
             :detail "could not accept a session channel"))
    (let ((channel (ssh-plibssh-session-register-channel
                    session handle "session")))
      (when (ssh-server-on-channel (ssh-session-server session))
        (funcall (ssh-server-on-channel (ssh-session-server session))
                 channel))
      channel)))

(defun ssh-plibssh-session-open-direct-tcpip (session message)
  "Ask the application about a forwarded connection, then accept it."
  (let* ((host (ssh-message-open-destination message))
         (port (ssh-message-open-destination-port message))
         (origin (ssh-message-open-originator message))
         (origin-port (ssh-message-open-originator-port message))
         (handler (ssh-server-on-direct-tcpip (ssh-session-server session)))
         (allowed (and handler
                       (funcall handler session host port origin origin-port))))
    (unless allowed
      (ssh-message-reply-default message)
      (return-from ssh-plibssh-session-open-direct-tcpip nil))
    (let ((handle (ssh-message-open-reply-accept message)))
      (when (ssh-plibssh-null-p handle)
        (error 'ssh-channel-error
               :channel nil
               :detail "could not accept a direct-tcpip channel"))
      (let ((channel (ssh-plibssh-session-register-channel
                      session handle "direct-tcpip")))
        (ssh-plibssh-server-connect-target channel host port)
        channel))))

;;; ---- Channel requests ----

(defun ssh-plibssh-session-channel-for-handle (session handle)
  "The channel record whose libssh handle is HANDLE."
  (loop for channel being the hash-values of (ssh-session-channels session)
        when (cffi:pointer-eq (ssh-server-channel-handle channel) handle)
          return channel))

(defun ssh-plibssh-session-handle-channel-request (session message)
  "Dispatch one CHANNEL REQUEST message."
  (let* ((handle (ssh-message-channel-request-channel message))
         (channel (ssh-plibssh-session-channel-for-handle session handle)))
    (if (null channel)
        (ssh-message-reply-default message)
        (case (ssh-message-subtype message)
          (#.+ssh-channel-request-env+
           (ssh-plibssh-session-handle-env channel message))
          (#.+ssh-channel-request-exec+
           (ssh-plibssh-session-handle-exec channel message))
          (#.+ssh-channel-request-window-change+
           (ssh-message-reply-default message))
          (t (ssh-message-reply-default message))))))

(defun ssh-plibssh-session-handle-env (channel message)
  "Record an accepted environment variable, or refuse it."
  (let* ((name (ssh-message-channel-request-env-name message))
         (value (ssh-message-channel-request-env-value message))
         (server (ssh-session-server (ssh-server-channel-session channel))))
    (if (ssh-server-env-allowed-p server name value)
        (progn
          (push (cons name value) (ssh-server-channel-env channel))
          (ssh-message-channel-request-reply-success message))
        (ssh-message-reply-default message))))

(defun ssh-plibssh-session-handle-exec (channel message)
  "Run the command in MESSAGE through the application's handler."
  (let ((command (ssh-message-channel-request-command message)))
    (setf (ssh-server-channel-command channel) command)
    (ssh-message-channel-request-reply-success message)
    (when (ssh-server-channel-on-exec channel)
      (funcall (ssh-server-channel-on-exec channel) channel command))))

;;; ---- Channel data and flow control ----

(defun ssh-plibssh-server-channel-queue (channel data stderr)
  (ssh-plibssh-buffer-append
   (if stderr (ssh-server-channel-stderr-queue channel)
       (ssh-server-channel-write-queue channel))
   (ssh-ensure-octets data)))

(defun ssh-plibssh-server-flush-queue (channel queue stderr)
  "Send QUEUE as far as libssh's window allows; return the bytes left."
  (loop
    (unless (plusp (fill-pointer queue)) (return 0))
    (let* ((count (min (fill-pointer queue) +ssh-read-chunk+))
           (written
             (ssh-plibssh-write-octets
              (lambda (buffer length)
                (if stderr
                    (ssh-plibssh-channel-write-stderr
                     (ssh-server-channel-handle channel) buffer length)
                    (ssh-plibssh-channel-write
                     (ssh-server-channel-handle channel) buffer length)))
              queue 0 count)))
      (cond
        ((plusp written) (ssh-plibssh-buffer-drop queue written))
        ((zerop written) (return (fill-pointer queue)))
        (t (return (fill-pointer queue)))))))

(defun ssh-plibssh-server-run-callbacks (channel)
  (let ((callbacks (nreverse (ssh-server-channel-write-callbacks channel))))
    (setf (ssh-server-channel-write-callbacks channel) nil)
    (iter (for callback in callbacks) (funcall callback))))

(defun ssh-plibssh-server-after-queue (channel)
  "Send the exit status, EOF and close once the queues are empty."
  (when (and (ssh-server-channel-handle channel)
             (not (ssh-server-channel-close-reported channel)))
    (ssh-plibssh-server-run-callbacks channel)
    (ssh-plibssh-server-send-exit channel)
    (ssh-plibssh-server-send-eof channel)
    (ssh-plibssh-server-send-close channel)))

(defun ssh-plibssh-server-send-exit (channel)
  (let ((status (ssh-server-channel-exit-status channel)))
    (when (and status
               (not (ssh-server-channel-exit-sent channel))
               (ssh-server-channel-handle channel))
      (ssh-channel-request-send-exit-status
       (ssh-server-channel-handle channel) status)
      (setf (ssh-server-channel-exit-sent channel) t))))

(defun ssh-plibssh-server-send-eof (channel)
  (when (and (ssh-server-channel-want-eof channel)
             (not (ssh-server-channel-sent-eof channel))
             (eq (ssh-server-channel-state channel) :open)
             (ssh-server-channel-handle channel))
    (when (zerop (ssh-channel-send-eof (ssh-server-channel-handle channel)))
      (setf (ssh-server-channel-sent-eof channel) t))))

(defun ssh-plibssh-server-send-close (channel)
  (when (and (ssh-server-channel-want-close channel)
             (not (ssh-server-channel-sent-close channel))
             (member (ssh-server-channel-state channel) '(:open :closing))
             (ssh-server-channel-handle channel))
    (when (zerop (ssh-plibssh-channel-close
                  (ssh-server-channel-handle channel)))
      (setf (ssh-server-channel-sent-close channel) t
            (ssh-server-channel-state channel) :closing))))

(defun ssh-plibssh-server-channel-flush (channel)
  "Move both queues, then send whatever end the application asked for."
  (when (eq (ssh-server-channel-state channel) :open)
    (ssh-plibssh-server-flush-queue
     channel (ssh-server-channel-write-queue channel) nil)
    (ssh-plibssh-server-flush-queue
     channel (ssh-server-channel-stderr-queue channel) t))
  (when (and (zerop (fill-pointer
                     (ssh-server-channel-write-queue channel)))
             (zerop (fill-pointer
                     (ssh-server-channel-stderr-queue channel))))
    (ssh-plibssh-server-after-queue channel)))

(defun ssh-plibssh-server-channel-dispatch (channel data stderr)
  "Hand DATA to the target connection or the application."
  (if (string= (ssh-server-channel-type channel) "direct-tcpip")
      (ssh-plibssh-server-channel-write-target channel data)
      (when (ssh-server-channel-on-data channel)
        (funcall (ssh-server-channel-on-data channel) channel data
                 (if stderr :stderr :stdin)))))

(defun ssh-plibssh-server-channel-read (channel stderr)
  "Drain one direction of CHANNEL into its consumer."
  (cffi:with-foreign-object (buffer :unsigned-char +ssh-read-chunk+)
    (loop
      (let ((handle (ssh-server-channel-handle channel)))
        (unless handle (return))
        (let ((rc (ssh-channel-read-nonblocking
                   handle buffer +ssh-read-chunk+ (if stderr 1 0))))
          (cond
            ((plusp rc)
             (ssh-plibssh-server-channel-dispatch
              channel (ssh-plibssh-fill-octets buffer rc) stderr))
            ((or (zerop rc) (= rc +ssh-eof+)) (return))
            (t
             ;; A vanished peer is not a channel error: end the session and
             ;; report the connection closed, as the pure backend does.
             (let* ((session (ssh-server-channel-session channel))
                    (session-handle (ssh-session-handle session)))
               (if (and session-handle
                        (plusp (ssh-is-connected session-handle)))
                   (ssh-plibssh-server-channel-fail
                    channel
                    (make-condition
                     'ssh-channel-error :channel channel
                     :detail (format nil "channel read failed: ~A"
                                     (ssh-plibssh-error session-handle))))
                   (ssh-session-finish session :peer-closed :close)))
             (return))))))))

(defun ssh-plibssh-server-channel-report-eof (channel)
  (let ((handle (ssh-server-channel-handle channel)))
    (when (and handle
               (plusp (ssh-channel-is-eof handle))
               (not (ssh-server-channel-eof-reported channel)))
      (setf (ssh-server-channel-eof-reported channel) t
            (ssh-server-channel-eof-received channel) t)
      (when (ssh-server-channel-on-eof channel)
        (funcall (ssh-server-channel-on-eof channel) channel)))))

(defun ssh-plibssh-server-channel-drive (channel)
  "Read, write and finish CHANNEL as far as its descriptor allows."
  (unless (ssh-server-channel-close-reported channel)
    (case (ssh-server-channel-state channel)
      (:open
       (ssh-plibssh-server-channel-read channel nil)
       (ssh-plibssh-server-channel-read channel t)
       (ssh-plibssh-server-channel-report-eof channel)
       (ssh-plibssh-server-channel-flush channel)
       (ssh-plibssh-server-channel-check-close channel))
      (:closing
       (ssh-plibssh-server-channel-check-close channel))
      (:closed nil))))

(defun ssh-plibssh-server-channel-check-close (channel)
  (let ((handle (ssh-server-channel-handle channel)))
    (when (and handle
               (plusp (ssh-channel-is-closed handle)))
      (ssh-plibssh-server-channel-finish channel))))

;;; ---- Channel termination ----

(defun ssh-plibssh-server-channel-finish (channel)
  "Mark CHANNEL closed once, unregister it, and report its end."
  (unless (ssh-server-channel-close-reported channel)
    (setf (ssh-server-channel-close-reported channel) t
          (ssh-server-channel-state channel) :closed)
    (remhash (ssh-server-channel-local-id channel)
             (ssh-session-channels
              (ssh-server-channel-session channel)))
    (ssh-plibssh-server-channel-close-target channel)
    (let ((handle (ssh-server-channel-handle channel)))
      (setf (ssh-server-channel-handle channel) nil)
      (when handle (ssh-channel-free handle)))
    (when (ssh-server-channel-on-close channel)
      (funcall (ssh-server-channel-on-close channel) channel))))

(defun ssh-plibssh-server-channel-fail (channel condition)
  "Report CONDITION, then close CHANNEL."
  (when (ssh-server-channel-on-error channel)
    (funcall (ssh-server-channel-on-error channel) channel condition))
  (ssh-server-channel-close channel))

(defun ssh-plibssh-server-channel-close-target (channel)
  (let ((target (ssh-server-channel-target channel)))
    (when target
      (setf (ssh-server-channel-target channel) nil)
      (cl-pnet:close-connection target))))

;;; ---- Public channel operations ----

(defun ssh-server-channel-write (channel data &key on-done)
  "Queue DATA for the client; ON-DONE runs when all of it has been sent."
  (when (eq (ssh-server-channel-state channel) :closed)
    (error 'ssh-channel-error :channel channel :detail "channel is closed"))
  (when (ssh-plibssh-channel-usable-p channel)
    (ssh-plibssh-server-channel-queue channel data nil)
    (when on-done
      (push on-done (ssh-server-channel-write-callbacks channel)))
    (ssh-plibssh-server-channel-flush channel))
  channel)

(defun ssh-server-channel-write-stderr (channel data &key on-done)
  "Queue DATA as extended data, the SSH equivalent of stderr."
  (when (eq (ssh-server-channel-state channel) :closed)
    (error 'ssh-channel-error :channel channel :detail "channel is closed"))
  (when (ssh-plibssh-channel-usable-p channel)
    (ssh-plibssh-server-channel-queue channel data t)
    (when on-done
      (push on-done (ssh-server-channel-write-callbacks channel)))
    (ssh-plibssh-server-channel-flush channel))
  channel)

(defun ssh-server-channel-eof (channel)
  "Say no more output follows, after everything already queued."
  (setf (ssh-server-channel-want-eof channel) t)
  (ssh-plibssh-server-channel-flush channel)
  channel)

(defun ssh-server-channel-close (channel)
  "Start the close handshake, after everything already queued."
  (when (member (ssh-server-channel-state channel) '(:open :opening))
    (setf (ssh-server-channel-want-close channel) t)
    (ssh-plibssh-server-channel-flush channel))
  channel)

(defun ssh-server-channel-exit (channel status)
  "Send an exit status and end the channel's output."
  (setf (ssh-server-channel-exit-status channel) status
        (ssh-server-channel-want-eof channel) t)
  (ssh-plibssh-server-channel-flush channel)
  channel)

(defun ssh-plibssh-channel-usable-p (channel)
  "Whether CHANNEL still has a live libssh handle."
  (and (ssh-server-channel-handle channel)
       (not (ssh-server-channel-close-reported channel))))

;;; ---- direct-tcpip target ----

(defun ssh-plibssh-server-channel-write-target (channel data)
  "Send client channel DATA to CHANNEL's forwarded target."
  (let ((target (ssh-server-channel-target channel)))
    (when target
      (cl-pnet:send-data
       target data
       :on-error
       (lambda (status)
         (ssh-plibssh-server-channel-fail
          channel
          (make-condition 'ssh-connection-error
                          :detail (format nil "target send failed (~A)"
                                          status))))))))

(defun ssh-plibssh-server-connect-target (channel host port)
  "Connect CHANNEL to HOST:PORT without blocking, then pipe both ways."
  (handler-case
      (burzay:resolve-host
       host
       (lambda (address)
         (ssh-plibssh-server-dial-target channel address port))
       (lambda (condition)
         (ssh-plibssh-server-channel-fail channel condition)))
    (error (condition) (ssh-plibssh-server-channel-fail channel condition))))

(defun ssh-plibssh-server-dial-target (channel address port)
  "Open the forwarded target for CHANNEL once its name resolved."
  (let ((connection
          (cl-pnet:tcp-connect
           address port
           :read-cb (lambda (connection data)
                      (declare (ignore connection))
                      (if data
                          (ssh-server-channel-write channel data)
                          (ssh-server-channel-eof channel)))
           :on-error
           (lambda (status)
             (ssh-plibssh-server-channel-fail
              channel
              (make-condition 'ssh-connection-error
                              :detail (format nil "target connect failed (~A)"
                                              status)))))))
    (if connection
        (setf (ssh-server-channel-target channel) connection)
        (ssh-plibssh-server-channel-fail
         channel
         (make-condition 'ssh-connection-error
                         :detail (format nil "could not connect to ~A:~D"
                                         address port))))))

;;; ---- Session termination ----

(defun ssh-plibssh-session-terminate-channels (session kind reason)
  "Report the end of every channel still registered on SESSION."
  (let ((channels (iter (for (id channel) in-hashtable
                              (ssh-session-channels session))
                    (collect (cons id channel)))))
    (iter (for (id . channel) in channels)
      (remhash id (ssh-session-channels session))
      (setf (ssh-server-channel-state channel) :closed
            (ssh-server-channel-close-reported channel) t
            (ssh-server-channel-handle channel) nil)
      (ssh-plibssh-server-channel-close-target channel)
      (ecase kind
        (:error
         (when (ssh-server-channel-on-error channel)
           (funcall (ssh-server-channel-on-error channel) channel reason)))
        (:close
         (when (ssh-server-channel-on-close channel)
           (funcall (ssh-server-channel-on-close channel) channel)))))))

(defun ssh-plibssh-session-release (session)
  "Stop watching SESSION's descriptor and let libssh free it."
  (let ((watcher (ssh-session-watcher session))
        (write-watcher (ssh-session-write-watcher session))
        (handle (ssh-session-handle session)))
    (setf (ssh-session-watcher session) nil
          (ssh-session-write-watcher session) nil
          (ssh-session-handle session) nil
          (ssh-session-fd session) nil)
    (when watcher (cl-pnet:fd-unwatch watcher))
    (when write-watcher (cl-pnet:fd-unwatch write-watcher))
    (when handle
      (ssh-disconnect handle)
      (ssh-free handle))))

(defun ssh-session-finish (session reason kind)
  "Close SESSION once, reporting REASON through the callback KIND selects."
  (unless (ssh-session-closed session)
    (setf (ssh-session-closed session) t
          (ssh-session-phase session) :closed
          (ssh-session-close-reason session) reason)
    (let ((server (ssh-session-server session)))
      (when server
        (remhash session (ssh-server-sessions server))))
    (ssh-plibssh-session-terminate-channels session kind reason)
    (ssh-plibssh-session-release session)
    (let ((server (ssh-session-server session)))
      (ecase kind
        (:error
         (when (and server (ssh-server-on-error server))
           (funcall (ssh-server-on-error server) session reason)))
        (:close
         (when (and server (ssh-server-on-close server))
           (funcall (ssh-server-on-close server) session reason)))))))

(defun ssh-session-fail (session condition)
  "End SESSION because of CONDITION, telling the server once."
  (ssh-session-finish session condition :error))

(defun ssh-session-close (session)
  "Close SESSION and every channel it carries."
  (ssh-session-finish session :client-closed :close)
  session)

;;; ---- Accepting connections ----

(defun ssh-plibssh-server-accept (server fd)
  "Wrap a freshly accepted FD in a session and start its handshake."
  (let ((handle (ssh-new)))
    (when (ssh-plibssh-null-p handle)
      (cl-pnet-sockets:c-close fd)
      (error 'ssh-connection-error :detail "could not allocate a libssh session"))
    (let ((session (%make-ssh-session
                    :server server
                    :handle handle
                    :fd fd
                    :remote-address (ssh-plibssh-peer-address fd))))
      (let ((rc (ssh-bind-accept-fd (ssh-server-bind server) handle fd)))
        (unless (zerop rc)
          (let ((detail (ssh-plibssh-error handle)))
            (ssh-free handle)
            (cl-pnet-sockets:c-close fd)
            (error 'ssh-connection-error
                   :detail (format nil "could not attach a session: ~A"
                                   detail)))))
      (setf (gethash session (ssh-server-sessions server)) session)
      (setf (ssh-session-watcher session)
            (cl-pnet:fd-watch
             fd
             :on-readable
             (lambda (watcher)
               (declare (ignore watcher))
               (ssh-plibssh-session-pump session))))
      (ssh-set-blocking handle 0)
      (ssh-plibssh-session-pump session)
      session)))

(defun ssh-plibssh-server-accept-loop (server)
  "Drain every waiting connection on SERVER's listener."
  (loop
    (let ((fd (cl-pnet-sockets:accept-socket
               (ssh-server-listener server))))
      (unless (and fd (not (ssh-server-closed server)))
        (return))
      (cl-pnet-sockets:set-nonblocking fd)
      (handler-case
          (ssh-plibssh-server-accept server fd)
        (error (condition)
          (when (ssh-server-on-error server)
            (funcall (ssh-server-on-error server) nil condition)))))))

;;; ---- Public entry points ----

(defun make-ssh-server (address port
                        &key
                          host-key
                          authorized-keys
                          authorize
                          authorize-user
                          max-auth-tries
                          max-sessions
                          accept-env
                          server-version
                          version-addendum
                          on-session
                          on-channel
                          on-direct-tcpip
                          on-error
                          on-close)
  "Listen on ADDRESS:PORT and serve SSH clients, returning at once.

The libssh backend owns the listener and every accepted descriptor, so no
call in this file waits for a peer.  The arguments are the same as the pure
backend's; HOST-KEY may be an ssh-private-key, a path, or a list of those.
libssh needs a file for each key it presents, so a key parsed from octets
without a path is refused here.  SERVER-VERSION is the part of the greeting
after \"SSH-2.0-\"; libssh adds that prefix itself."
  (let* ((keys (mapcar (lambda (value)
                         (if (typep value 'ssh-private-key)
                             value
                             (ssh-load-private-key value)))
                       (if (listp host-key) host-key (list host-key))))
         (version (if server-version
                      (check-server-version server-version)
                      (subseq +ssh-server-version+
                              (length "SSH-2.0-"))))
         (addendum (and version-addendum
                        (not (eq version-addendum :none))
                        (check-version-addendum version-addendum)))
         (server (%make-ssh-server
                  :address address
                  :port port
                  :host-keys keys
                  :authorized-keys authorized-keys
                  :authorize authorize
                  :authorize-user authorize-user
                  :max-auth-tries (or max-auth-tries 6)
                  :max-sessions (or max-sessions 10)
                  :accept-env accept-env
                  :on-session on-session
                  :on-channel on-channel
                  :on-direct-tcpip on-direct-tcpip
                  :on-error on-error
                  :on-close on-close))
         (bind (ssh-bind-new)))
    (when (ssh-plibssh-null-p bind)
      (error 'ssh-connection-error :detail "could not allocate a libssh bind"))
    (setf (ssh-server-bind server) bind)
    ;; libssh prepends "SSH-2.0-" to the banner, so the option takes only the
    ;; version tail.  A program that names itself must appear that way in a
    ;; peer's log instead of being hidden behind libssh's own string.
    (when (minusp (ssh-plibssh-bind-string-option
                   bind +ssh-bind-options-banner+
                   (if addendum
                       (format nil "~A ~A" version addendum)
                       version)))
      (let ((detail (ssh-plibssh-error bind)))
        (ssh-bind-free bind)
        (error 'ssh-connection-error
               :detail (format nil "libssh rejected the server version: ~A"
                               detail))))
    ;; The library must not read /etc/ssh/sshd_config behind the caller's
    ;; back: this server's host key and policy are the arguments it was given.
    (when (minusp (ssh-plibssh-bind-int-option
                   bind +ssh-bind-options-process-config+ 0))
      (let ((detail (ssh-plibssh-error bind)))
        (ssh-bind-free bind)
        (error 'ssh-connection-error
               :detail (format nil "libssh rejected the config flag: ~A"
                               detail))))
    (unless keys
      (ssh-bind-free bind)
      (error 'ssh-connection-error :detail "no host key given"))
    (dolist (key keys)
      (let ((path (or (ssh-private-key-path key)
                      (progn
                        (ssh-bind-free bind)
                        (error 'ssh-connection-error
                               :detail "the host key has no file path")))))
        (when (minusp (ssh-plibssh-bind-string-option
                       bind +ssh-bind-options-host-key+ path))
          (let ((detail (ssh-plibssh-error bind)))
            (ssh-bind-free bind)
            (error 'ssh-connection-error
                   :detail (format nil "libssh rejected the host key ~A: ~A"
                                   path detail))))))
    (handler-case
        (let ((fd (ssh-plibssh-listen address port)))
          (setf (ssh-server-listener server) fd
                (ssh-server-port server) (or (ssh-plibssh-bound-port fd) port)
                (ssh-server-watcher server)
                (cl-pnet:fd-watch
                 fd
                 :on-readable
                 (lambda (watcher)
                   (declare (ignore watcher))
                   (ssh-plibssh-server-accept-loop server)))))
      (error (condition)
        (setf (ssh-server-bind server) nil)
        (ssh-bind-free bind)
        (error condition)))
    server))

(defun ssh-server-close (server)
  "Stop accepting connections and close every session."
  (unless (ssh-server-closed server)
    (setf (ssh-server-closed server) t)
    (let ((watcher (ssh-server-watcher server))
          (listener (ssh-server-listener server))
          (bind (ssh-server-bind server)))
      (setf (ssh-server-watcher server) nil
            (ssh-server-listener server) nil
            (ssh-server-bind server) nil)
      (when watcher (cl-pnet:fd-unwatch watcher))
      (when listener (cl-pnet-sockets:c-close listener))
      (let ((sessions (iter (for (session value) in-hashtable
                                  (ssh-server-sessions server))
                        (declare (ignore value))
                        (collect session))))
        (iter (for session in sessions)
          (ssh-session-finish session :server-closed :close)))
      (when bind (ssh-bind-free bind))))
  server)
