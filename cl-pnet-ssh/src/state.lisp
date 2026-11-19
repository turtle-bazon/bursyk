(in-package #:cl-pnet-ssh)

;;;; Client and channel state. The shared pieces (wire, packets, KEX, keys)
;;;; never look at these; they define the client role only.

(defstruct (ssh-client (:constructor %make-ssh-client))
  host
  (port 22)
  (user nil)
  (connection nil)
  (phase :connecting)
  (incoming (make-array 4096 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))
  (client-version "SSH-2.0-cl-pnet-ssh_0.0.1.0")
  (server-version nil)
  (session-id nil)
  (cipher (ssh-make-cipher-state))
  (client-kexinit nil)
  (kexinit-sent nil)
  (server-kexinit nil)
  (negotiated nil)
  (ephemeral-private nil)
  (ephemeral-public nil)
  (host-key-blob nil)
  (derived-keys nil)
  (strict-kex nil)
  (ignore-next-kex-packet nil)
  (keys-sent nil)
  (keys-received nil)
  (private-key nil)
  (known-hosts nil)
  (host-key-policy :strict)
  (host-key-callback nil)
  (channels (make-hash-table :test #'eql))
  (next-channel-id 0)
  (pending-actions nil)
  (on-open nil)
  (on-error nil)
  (on-close nil)
  (closed nil)
  (close-reason nil)
  (window 2097152)
  (max-packet 32768))

(defstruct (ssh-channel (:constructor %make-ssh-channel))
  client
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
  (pending-exec nil)
  (want-eof nil)
  (sent-eof nil)
  (want-close nil)
  (sent-close nil)
  (eof-received nil)
  (exit-status nil)
  (exit-signal nil)
  (on-data nil)
  (on-eof nil)
  (on-exit nil)
  (on-close nil)
  (on-error nil))

(defun ssh-client-closed-p (client)
  "True once CLIENT has shut down."
  (ssh-client-closed client))

(defun ssh-client-buffer-append (client data)  "Append DATA to CLIENT's receive buffer."
  (let ((buffer (ssh-client-incoming client)))
    (iter (for octet in-vector data)
      (vector-push-extend octet buffer))))

(defun ssh-client-buffer-consume (client count)
  "Drop the first COUNT octets of CLIENT's receive buffer."
  (let ((buffer (ssh-client-incoming client)))
    (when (plusp count)
      (replace buffer buffer :start1 0 :start2 count)
      (decf (fill-pointer buffer) count))
    buffer))

(defun ssh-client-buffer-empty-p (client)
  (zerop (fill-pointer (ssh-client-incoming client))))

(defun ssh-client-close-connection (client)
  (when (ssh-client-connection client)
    (ignore-errors (cl-pnet:close-connection (ssh-client-connection client)))))

(defun ssh-client-finish (client reason kind)
  "Close CLIENT once, reporting REASON through the callback KIND selects."
  (unless (ssh-client-closed client)
    (setf (ssh-client-closed client) t
          (ssh-client-phase client) :closed
          (ssh-client-close-reason client) reason)
    (ssh-client-terminate-channels client reason kind)
    (ssh-client-close-connection client)
    (ecase kind
      (:error (when (ssh-client-on-error client)
                (funcall (ssh-client-on-error client) client reason)))
      (:close (when (ssh-client-on-close client)
                (funcall (ssh-client-on-close client) client reason))))))

(defun ssh-client-fail (client condition)
  "End CLIENT because of CONDITION, telling its error callback once."
  (ssh-client-finish client condition :error))

(defun ssh-client-send-bytes (client octets)
  "Queue OCTETS on CLIENT's connection. NIL once the client is closed."
  (unless (ssh-client-closed client)
    (let ((connection (ssh-client-connection client)))
      (when connection
        (handler-case
            (cl-pnet:send-data
             connection octets
             :on-error (lambda (status)
                         (ssh-client-fail
                          client
                          (make-condition 'ssh-connection-error
                                          :detail (format nil "send failed (~A)" status)))))
          (error (condition) (ssh-client-fail client condition))))))
  (not (ssh-client-closed client)))

(defun ssh-client-send-payload (client payload)
  "Frame and send one protocol PAYLOAD."
  (ssh-client-send-bytes client
                         (ssh-encode-packet payload (ssh-client-cipher client))))

(defun ssh-client-run-when-ready (client action)
  "Run ACTION now when CLIENT is ready, otherwise after authentication."
  (if (eq (ssh-client-phase client) :ready)
      (funcall action)
      (push action (ssh-client-pending-actions client))))

(defun ssh-client-channel-for (client local-id)
  (gethash local-id (ssh-client-channels client)))
