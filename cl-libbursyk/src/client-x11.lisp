(in-package #:cl-pnet-ssh)

;;;; X11 forwarding, the client half.
;;;;
;;;; ssh sends one x11-req on the session channel after it opens.  The cookie
;;;; in that request is fake: the real one never leaves the client.  The
;;;; server writes the fake one into its user's Xauthority, remote X clients
;;;; authenticate with it, and each x11 channel's first message has its fake
;;;; cookie replaced by the real one before it reaches the local X server.
;;;;
;;;; The shared cookie and DISPLAY code lives in X11; this file is the SSH
;;;; side: choosing the cookie, sending the request, and relaying a channel to
;;;; the local display.

(defun ssh-client-x11-expired-p (client)
  "Whether ForwardX11Timeout has passed for CLIENT."
  (let ((deadline (ssh-client-x11-refuse-time client)))
    (and deadline (>= (ssh-client-now) deadline))))

(defun ssh-client-x11-authority-cookie (display)
  "The MIT-MAGIC-COOKIE-1 data of DISPLAY from the client's Xauthority, or NIL."
  (multiple-value-bind (name data)
      (ssh-x11-authority-cookie (ssh-x11-authority-path) display)
    (when (and (ssh-x11-octets-equal-text-p name +ssh-x11-protocol+)
               data
               (plusp (length data)))
      data)))

(defun ssh-client-prepare-x11 (client)
  "Choose CLIENT's cookies and DISPLAY; true when x11-req should be sent.

ssh -X and ssh -Y both relay with the user's own cookie.  The difference is
only the fallback: trusted forwarding (ssh -Y) may invent data when there is
no cookie, because the local X server can be trusted to ignore it, while
untrusted forwarding (ssh -X) refuses to start without a real
MIT-MAGIC-COOKIE-1, as ssh does.  OpenSSH's -X would instead ask xauth for a
fresh untrusted cookie through the X Security extension; this client has no
X Security client, so -X gives the forwarded display the same access as the
local session, while ssh's -X would not."
  (when (ssh-client-forward-x11 client)
    (or (ssh-client-x11-saved-data client)
        (let* ((text (uiop:getenv "DISPLAY"))
               (display (and text (ssh-x11-parse-display text))))
          (cond
            ((null display)
             (ssh-warn "DISPLAY ~S is not usable; disabling X11 forwarding"
                       text)
             nil)
            (t
             (let ((real (ssh-client-x11-authority-cookie display)))
               (cond
                 (real
                  (setf (ssh-client-x11-display client) display
                        (ssh-client-x11-proto client) +ssh-x11-protocol+
                        (ssh-client-x11-saved-data client) real
                        (ssh-client-x11-fake-data client)
                        (ssh-x11-generate-cookie (length real)))
                  (ssh-client-x11-start-timeout client)
                  t)
                 ((ssh-client-forward-x11-trusted client)
                  ;; No authority data: make some up.  The local X server
                  ;; ignores it, and the substitution still has to preserve
                  ;; the packet's shape.
                  (let ((data (ssh-x11-generate-cookie)))
                    (setf (ssh-client-x11-display client) display
                          (ssh-client-x11-proto client) +ssh-x11-protocol+
                          (ssh-client-x11-saved-data client) data
                          (ssh-client-x11-fake-data client)
                          (ssh-x11-generate-cookie (length data)))
                    (ssh-warn "no X11 authority data for ~A; forwarding with fake data"
                              text)
                    (ssh-client-x11-start-timeout client)
                    t))
                 (t
                  (ssh-warn "no X11 authority data for ~A; disabling untrusted X11 forwarding"
                            text)
                  nil)))))))))

(defun ssh-client-x11-start-timeout (client)
  "Arm ForwardX11Timeout's deadline on CLIENT, if it applies.

ssh applies the limit to untrusted forwarding only: a trusted connection
(ssh -Y) never expires.  ForwardX11Timeout 0 turns the limit off, while an
unset value, or \"none\", is OpenSSH's 1200-second default."
  (when (and (ssh-client-forward-x11 client)
             (not (ssh-client-forward-x11-trusted client)))
    (let ((timeout (ssh-client-forward-x11-timeout client)))
      (unless (and timeout (zerop timeout))
        (setf (ssh-client-x11-refuse-time client)
              (+ (ssh-client-now) (or timeout 1200)))))))

(defun ssh-channel-send-x11-request (channel)
  "Ask the peer to forward X11 connections on CHANNEL, with the fake cookie."
  (let ((client (ssh-channel-client channel)))
    (setf (ssh-channel-x11-reply-pending channel) t)
    (ssh-channel-send-message
     channel +ssh-msg-channel-request+
     :fields
     (lambda (writer)
       (ssh-write-text writer "x11-req")
       (ssh-write-boolean writer t)
       ;; ssh never asks for a single connection.
       (ssh-write-boolean writer nil)
       (ssh-write-text writer (ssh-client-x11-proto client))
       (ssh-write-text writer
                       (ssh-x11-cookie-hex
                        (ssh-client-x11-fake-data client)))
       (ssh-write-u32 writer
                      (ssh-x11-display-screen
                       (ssh-client-x11-display client)))))))

(defun ssh-client-refuse-x11 (client sender description)
  (ssh-log "refusing x11 channel: ~A" description)
  (ssh-client-send-channel-open-failure client sender description))

(defun ssh-client-accept-x11-channel (client reader sender window max-packet)
  "Accept a server-initiated x11 channel and bridge it to the local display."
  (let ((origin (ssh-read-text reader))
        (origin-port (ssh-read-u32 reader)))
    (cond
      ((not (ssh-client-forward-x11 client))
       (ssh-client-refuse-x11
        client sender "X11 forwarding was not requested"))
      ((ssh-client-x11-expired-p client)
       (ssh-client-refuse-x11
        client sender "ForwardX11Timeout has expired"))
      ((null (ssh-client-x11-display client))
       (ssh-client-refuse-x11
        client sender "X11 forwarding has no usable display"))
      (t
       (ssh-log "x11 channel from ~A:~D" origin origin-port)
       (let ((display (ssh-client-x11-display client)))
         (if (ssh-x11-display-unix-p display)
             (multiple-value-bind (fd status)
                 (cl-pnet-sockets:connect-unix
                  (ssh-x11-display-socket-path display))
               (if fd
                   (ssh-client-x11-connected client sender window max-packet
                                             fd status)
                   (ssh-client-refuse-x11
                    client sender
                    (format nil "cannot connect to the X server at ~A"
                            (ssh-x11-display-socket-path display)))))
             (multiple-value-bind (host port)
                 (ssh-x11-display-host-port display)
               (burzay:resolve-host
                host
                (lambda (address)
                  (multiple-value-bind (fd status)
                      (cl-pnet-sockets:connect-tcp address port)
                    (if fd
                        (ssh-client-x11-connected client sender window
                                                  max-packet fd status)
                        (ssh-client-refuse-x11
                         client sender
                         (format nil "cannot connect to the X server at ~A:~D"
                                 address port)))))
                (lambda (condition)
                  (declare (ignore condition))
                  (ssh-client-refuse-x11
                   client sender
                   (format nil "cannot resolve the X server host ~A" host)))))))))))

(defun ssh-client-x11-connected (client sender window max-packet fd status)
  "Make the confirmed x11 channel for an already connected display FD."
  (let* ((id (ssh-client-allocate-channel-id client))
         (channel (%make-ssh-channel
                   :client client
                   :local-id id
                   :remote-id sender
                   :type "x11"
                   :state :open
                   :remote-window window
                   :remote-max-packet max-packet
                   :local-window (ssh-client-window client)
                   :local-max-packet (ssh-client-max-packet client)))
         (relay (%make-ssh-fd-relay
                 :fd fd
                 :phase (if (eq status :connected) :connected :connecting)
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
    channel))

(defun ssh-client-x11-target-data (channel data)
  "Send DATA toward the local X server, replacing the fake cookie once.

The first setup message may arrive in several CHANNEL_DATA packets, so nothing
is written until the header and cookie are both here."
  (let ((relay (ssh-channel-target-fd-relay channel)))
    (when relay
      (if (ssh-channel-x11-setup-done channel)
          (ssh-fd-relay-queue relay data)
          (let* ((client (ssh-channel-client channel))
                 (buffer (ssh-channel-x11-buffer channel)))
            (loop for octet across data
                  do (vector-push-extend octet buffer))
            (multiple-value-bind (result complete)
                (ssh-x11-substitute-cookie
                 buffer
                 (ssh-client-x11-fake-data client)
                 (ssh-client-x11-saved-data client))
              (when complete
                (setf (ssh-channel-x11-setup-done channel) t)
                ;; RESULT may be BUFFER itself, so clear it only after the
                ;; relay has copied the bytes out.
                (ssh-fd-relay-queue relay result)
                (setf (fill-pointer buffer) 0))))))))
