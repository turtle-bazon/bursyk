(in-package #:cl-pnet-ssh)

;;;; X11 forwarding, the server half.
;;;;
;;;; sshd answers x11-req by binding a display number on loopback (or on
;;;; every address when X11UseLocalhost is no) and writing the client's fake
;;;; cookie into the account's Xauthority.  Remote X clients connect to that
;;;; display, sshd turns each connection into an x11 channel, and the client
;;;; substitutes the real cookie before handing the setup message to its own
;;;; X server.  The fake cookie is all this side ever sees.

(defconstant +ssh-x11-max-displays+ 100
  "How many display numbers sshd tries above X11DisplayOffset.")

(defun ssh-server-open-x11 (session origin-address origin-port
                            &key on-data on-eof on-close on-error)
  "Ask SESSION's client to open an x11 channel for an X11 connection.

ORIGIN-ADDRESS:ORIGIN-PORT name the remote X client that connected to the
display listener.  The channel starts in :OPENING; data queued with
SSH-SERVER-CHANNEL-WRITE goes out once the client confirms."
  (let* ((id (ssh-session-next-channel-id session))
         (window (ssh-session-window session))
         (max-packet (ssh-session-max-packet session))
         (channel (%make-ssh-server-channel
                   :session session
                   :local-id id
                   :type "x11"
                   :state :opening
                   :local-window window
                   :local-max-packet max-packet
                   :on-data on-data
                   :on-eof on-eof
                   :on-close on-close
                   :on-error on-error)))
    (incf (ssh-session-next-channel-id session))
    (setf (gethash id (ssh-session-channels session)) channel)
    (ssh-session-note-channel-change session)
    (let ((writer (ssh-writer)))
      (ssh-write-u8 writer +ssh-msg-channel-open+)
      (ssh-write-text writer "x11")
      (ssh-write-u32 writer id)
      (ssh-write-u32 writer window)
      (ssh-write-u32 writer max-packet)
      (ssh-write-text writer origin-address)
      (ssh-write-u32 writer origin-port)
      (ssh-session-send-payload session (ssh-writer-output writer)))
    channel))

(defun ssh-server-x11-authority-path (session)
  "The Xauthority file SESSION's fake cookie belongs in, or NIL.

The server passed an application function because the file follows the
account's home directory; without one this side forwards but records no
cookie, which is only useful when the X server needs no authentication."
  (let ((server (ssh-session-server session)))
    (when (and server (ssh-server-x11-authority-file server))
      (funcall (ssh-server-x11-authority-file server) session))))

(defun ssh-server-x11-display-host ()
  "The host name an X11UseLocalhost=no DISPLAY names."
  (or (machine-instance) "localhost"))

(defun ssh-server-x11-bind-address (use-localhost)
  (if use-localhost "127.0.0.1" "0.0.0.0"))

(defun ssh-server-x11-tunnel-close (x11 connection)
  "Close one accepted X11 connection and the channel paired with it."
  (let ((channel (gethash connection (ssh-x11-forward-connections x11))))
    (remhash connection (ssh-x11-forward-connections x11))
    (when channel
      (ignore-errors (ssh-server-channel-close channel)))
    (ignore-errors (cl-pnet:close-connection connection))))

(defun ssh-server-x11-half-close (connection)
  "Tell an accepted X11 connection the client will send nothing more."
  (let ((fd (cl-pnet:connection-fileno connection)))
    (when fd
      (ignore-errors (cl-pnet-sockets:c-shutdown fd 1)))))

(defun ssh-server-x11-accept (x11 connection)
  "Open the x11 channel for a connection that reached X11's listener."
  (let* ((peer (cl-pnet:connection-peer-address connection))
         (origin (or (getf peer :address) "0.0.0.0"))
         (origin-port (or (getf peer :port) 0))
         (channel
           (ssh-server-open-x11
            (ssh-x11-forward-session x11) origin origin-port
            :on-data
            (lambda (channel data kind)
              (declare (ignore channel kind))
              (cl-pnet:send-data
               connection data
               :on-error
               (lambda (status)
                 (declare (ignore status))
                 (ssh-server-x11-tunnel-close x11 connection))))
            :on-eof
            (lambda (channel)
              (declare (ignore channel))
              (ssh-server-x11-half-close connection))
            :on-close
            (lambda (channel)
              (declare (ignore channel))
              (ssh-server-x11-tunnel-close x11 connection))
            :on-error
            (lambda (channel condition)
              (declare (ignore channel condition))
              (ssh-server-x11-tunnel-close x11 connection)))))
    (setf (gethash connection (ssh-x11-forward-connections x11)) channel)
    (cl-pnet:on-data
     connection
     (lambda (data)
       (if data
           (handler-case
               (ssh-server-channel-write channel data)
             (error ()
               (ssh-server-x11-tunnel-close x11 connection)))
           (ignore-errors (ssh-server-channel-eof channel)))))
    ;; A single-connection request closes the listener after the first X11
    ;; client, as ssh's -X with sshd's optional single flag does.
    (when (ssh-x11-forward-single x11)
      (when (ssh-x11-forward-listener x11)
        (ignore-errors
         (cl-pnet:close-listener (ssh-x11-forward-listener x11)))
        (setf (ssh-x11-forward-listener x11) nil)))
    channel))

(defun ssh-server-x11-listen (x11 session display-offset use-localhost)
  "Bind the first free display number at or above DISPLAY-OFFSET."
  (let ((address (ssh-server-x11-bind-address use-localhost)))
    (loop for number from display-offset
            below (+ display-offset +ssh-x11-max-displays+)
          for listener =
            (handler-case
                (cl-pnet:make-tcp-listener
                 address (+ +ssh-x11-display-port-base+ number)
                 :on-accept
                 (lambda (connection)
                   (ssh-server-x11-accept x11 connection))
                 :on-error
                 (lambda (status)
                   (declare (ignore status))
                   (ssh-log "X11 display listener ~D failed" number)))
              (error () nil))
          when listener
            do (setf (ssh-x11-forward-display-number x11) number
                     (ssh-x11-forward-listener x11) listener)
               (return number)
          finally (return nil))))

(defun ssh-server-handle-x11-request (session channel reader want-reply)
  "Answer x11-req: bind a display, record the fake cookie, set DISPLAY.

The cookie in the request is the client's fake one; this side never learns
the real cookie and does not need to."
  (let* ((single (ssh-read-boolean reader))
         (proto (ssh-read-text reader))
         (cookie (ssh-x11-hex-cookie (ssh-read-text reader)))
         (screen (ssh-read-u32 reader))
         (permitted (ssh-session-permits-x11-p session))
         (previous (ssh-session-x11-forward session))
         (x11 nil)
         (ok
           (and permitted
                (null previous)
                cookie
                (= (length cookie) +ssh-x11-cookie-length+)
                (string= proto +ssh-x11-protocol+)
                (progn
                  (setf x11 (%make-ssh-x11-forward
                             :session session
                             :screen screen
                             :proto proto
                             :cookie cookie
                             :single single))
                  (let* ((offset
                           (or (ssh-session-setting
                                session
                                #'ssh-server-config-x11-display-offset)
                               10))
                         (use-localhost
                           ;; The slot holds :YES or :NO; unset means sshd's
                           ;; default of yes.
                           (not (eq (ssh-session-setting
                                     session
                                     #'ssh-server-config-x11-use-localhost)
                                    :no))))
                    (setf (ssh-x11-forward-display-host x11)
                          (if use-localhost
                              "localhost"
                              (ssh-server-x11-display-host)))
                    (ssh-server-x11-listen x11 session offset use-localhost))))))
    (when ok
      (setf (ssh-session-x11-forward session) x11)
      (let ((display (%make-ssh-x11-display
                      :host (ssh-x11-forward-display-host x11)
                      :number (ssh-x11-forward-display-number x11)
                      :screen screen)))
        (ssh-server-channel-add-env
         channel "DISPLAY"
         (ssh-x11-display-string display (ssh-x11-forward-display-host x11)))
        (let ((path (ssh-server-x11-authority-path session)))
          (when path
            (handler-case
                (progn
                  (ssh-x11-write-cookie path display proto cookie)
                  (setf (ssh-x11-forward-authority-file x11) path
                        (ssh-x11-forward-cookie-added x11) t))
              (error (condition)
                (ssh-log "could not write the X11 cookie to ~A: ~A"
                         path condition)))))))
    (unless ok
      (when (and (null previous) (null permitted))
        (ssh-log "refusing x11-req: X11 forwarding is not enabled")))
    (ssh-server-channel-reply channel (not (null ok)) want-reply)
    ok))
