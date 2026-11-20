(in-package #:cl-pnet-ssh)

;;;; Server state.  The protocol core (wire, packets, keys, KEX) is shared
;;;; with the client; this file holds only what the server role adds: a
;;;; listener, one record per accepted connection, and the channels it serves.
;;;;
;;;; Everything is driven by cl-pnet callbacks.  No function here waits for
;;;; the peer: a request that needs work (an authorized-keys file, a command)
;;;; hands that work to the caller's callback and returns.

(defstruct (ssh-server (:constructor %make-ssh-server))
  (address "0.0.0.0")
  (version +ssh-server-version+)
  (port 22)
  listener
  (host-keys nil)
  authorized-keys
  authorize
  ;; Called once per (SESSION USER) before any authentication method runs;
  ;; the answer is cached for that pair.  NIL means every user is admitted.
  authorize-user
  ;; sshd's Banner: text sent before the first authentication reply, a
  ;; function of no arguments returning it (so the file can change without a
  ;; restart), or NIL for none.
  banner
  ;; PermitUserEnvironment: NIL and :NO permit nothing, :YES lets a user set
  ;; any variable, and a list of patterns is sshd's allowlist.
  (permit-user-environment nil)
  ;; SetEnv assignments from the config, applied after the user's own
  ;; environment so an administrator's value wins.
  (set-env '())
  ;; sshd's defaults: six failed attempts per connection, ten session
  ;; channels.  A program tightens or relaxes them from its config.
  (max-auth-tries 6)
  (max-sessions 10)
  (accept-env nil)
  (on-session nil)
  (on-channel nil)
  (on-direct-tcpip nil)
  ;; Remote forwarding: the application owns the listener, because it knows
  ;; which addresses and ports its user is willing to expose.  The first
  ;; returns the bound port (or NIL to refuse); the second returns true once
  ;; the listener is closed.
  (on-tcpip-forward nil)
  (on-cancel-tcpip-forward nil)
  (on-error nil)
  (on-close nil)
  (sessions (make-hash-table :test #'eq))
  (connections (make-hash-table :test #'eq))
  (closed nil))

(defun ssh-server-host-key (server)
  "The first host key SERVER presents.

A server may hold several; this returns the preferred one, for callers that
only want to describe it."
  (first (ssh-server-host-keys server)))

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
  ;; The environment= options of the authorized_keys line that authenticated
  ;; the user, applied only when PermitUserEnvironment allows them.
  (key-env '())
  ;; Userauth bookkeeping: a fresh connection starts at zero, and the first
  ;; "none" probe is exempt from the failure count, as in sshd.
  (auth-attempts 0)
  (auth-failures 0)
  (allowed-users '())
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
  (target-eof nil)
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

(defun ssh-session-send-payload-and-close (session payload reason)
  "Send PAYLOAD, then close SESSION with REASON once it is on the wire.

Closing immediately would discard the queued bytes, so the DISCONNECT that
explains a policy refusal would never reach the client."
  (let ((connection (ssh-session-connection session)))
    (if (or (ssh-session-closed session) (null connection))
        (ssh-session-finish session reason :close)
        (handler-case
            (cl-pnet:send-data
             connection
             (ssh-encode-packet payload (ssh-session-cipher session))
             :on-write (lambda (count)
                         (declare (ignore count))
                         (ssh-session-finish session reason :close))
             :on-error (lambda (status)
                         (declare (ignore status))
                         (ssh-session-finish session reason :close)))
          (error ()
            (ssh-session-finish session reason :close))))))

(defun ssh-session-channel-for (session local-id)
  (gethash local-id (ssh-session-channels session)))
