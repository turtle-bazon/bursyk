(in-package #:cl-pnet-ssh)

;;;; Server state.  The protocol core (wire, packets, keys, KEX) is shared
;;;; with the client; this file holds only what the server role adds: a
;;;; listener, one record per accepted connection, and the channels it serves.
;;;;
;;;; Everything is driven by cl-pnet callbacks.  No function here waits for
;;;; the peer: a request that needs work (an authorized-keys file, a command)
;;;; hands that work to the caller's callback and returns.

(defparameter +ssh-server-version+ "SSH-2.0-cl-pnet-ssh_0.0.1.0"
  "The default SSH identification string a server sends.

A program identifies itself by passing SERVER-VERSION to MAKE-SSH-SERVER;
the library's own default is only for callers that do not name themselves.")

(defstruct (ssh-server (:constructor %make-ssh-server))
  (address "0.0.0.0")
  (version +ssh-server-version+)
  (port 22)
  listener
  host-key
  authorized-keys
  authorize
  (accept-env nil)
  (on-session nil)
  (on-channel nil)
  (on-direct-tcpip nil)
  (on-error nil)
  (on-close nil)
  (sessions (make-hash-table :test #'eq))
  (connections (make-hash-table :test #'eq))
  (closed nil))

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
  (channels (make-hash-table :test #'eql))
  (next-channel-id 0)
  (closed nil)
  (close-reason nil)
  (window 2097152)
  (max-packet 32768))

(defstruct (ssh-server-channel (:constructor %make-ssh-server-channel))
  session
  local-id
  (remote-id nil)
  (type "session")
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

(defun ssh-session-finish (session reason kind)
  "Close SESSION once, reporting REASON through the callback KIND selects."
  (unless (ssh-session-closed session)
    (setf (ssh-session-closed session) t
          (ssh-session-phase session) :closed
          (ssh-session-close-reason session) reason)
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

(defun ssh-session-channel-for (session local-id)
  (gethash local-id (ssh-session-channels session)))
