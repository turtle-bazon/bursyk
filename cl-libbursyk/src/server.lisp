(in-package #:cl-pnet-ssh)

;;;; The public server entry points.  MAKE-SSH-SERVER binds a listener and
;;;; returns at once; accepted connections, authentication and channels all
;;;; run from cl-pnet callbacks.

(defun ssh-server-dispatch-read (server connection data)
  "The event loop has DATA for CONNECTION; find its session and feed it."
  (let ((session (gethash connection (ssh-server-connections server))))
    (when session
      (ssh-server-receive session data))))

(defun ssh-server-accept-session (server connection)
  "Create SESSION for a freshly accepted CONNECTION and start its greeting."
  (let ((session (%make-ssh-session
                  :server server
                  :connection connection
                  :remote-address (cl-pnet:connection-peer-address connection))))
    (setf (gethash connection (ssh-server-connections server)) session
          (gethash session (ssh-server-sessions server)) session)
    (ssh-server-connected session connection)
    session))

(defun make-ssh-server (address port
                        &key
                          host-key
                          authorized-keys
                          authorize
                          accept-env
                          on-session
                          on-channel
                          on-direct-tcpip
                          on-error
                          on-close)
  "Listen on ADDRESS:PORT and serve SSH clients, returning at once.

HOST-KEY is an ssh-private-key or a path to an OpenSSH key; only
ssh-ed25519 is implemented.  AUTHORIZED-KEYS is an authorized_keys file,
a list of public key blobs, or NIL.  AUTHORIZE, when given, is a function
of (USER KEY-BLOB) and replaces AUTHORIZED-KEYS.

ACCEPT-ENV is T (accept every env request), a list of names, a function of
(NAME VALUE), or NIL (refuse).  ON-SESSION runs once a client has
authenticated.  ON-DIRECT-TCPIP is a function of
(SESSION HOST PORT ORIGIN-ADDRESS ORIGIN-PORT) returning true to allow a
forwarded connection.  ON-ERROR receives (SESSION CONDITION) (SESSION is NIL
for listener errors), ON-CLOSE receives (SESSION REASON)."
  (let* ((key (if (typep host-key 'ssh-private-key)
                  host-key
                  (ssh-load-private-key host-key)))
         (server (%make-ssh-server
                  :address address
                  :port port
                  :host-key key
                  :authorized-keys authorized-keys
                  :authorize authorize
                  :accept-env accept-env
                  :on-session on-session
                  :on-channel on-channel
                  :on-direct-tcpip on-direct-tcpip
                  :on-error on-error
                  :on-close on-close
                  :connections (make-hash-table :test #'eq)))
         (listener (cl-pnet:make-tcp-listener
                    address port
                    :read-cb (lambda (connection data)
                               (ssh-server-dispatch-read server connection data))
                    :on-accept (lambda (connection)
                                 (ssh-server-accept-session server connection))
                    :on-error (lambda (status)
                                (when on-error
                                  (funcall on-error
                                           nil
                                           (make-condition
                                            'ssh-connection-error
                                            :detail (format nil
                                                            "listener error (~A)"
                                                            status))))))))
    (unless listener
      (error 'ssh-connection-error
             :detail (format nil "could not listen on ~A:~D" address port)))
    (setf (ssh-server-listener server) listener
          (ssh-server-port server) (or (cl-pnet:listener-bound-port listener)
                                       port))
    server))

(defun ssh-server-close (server)
  "Stop accepting connections and close every session."
  (unless (ssh-server-closed server)
    (setf (ssh-server-closed server) t)
    (when (ssh-server-listener server)
      (cl-pnet:close-listener (ssh-server-listener server))
      (setf (ssh-server-listener server) nil))
    (let ((sessions (iter (for (session value) in-hashtable
                                (ssh-server-sessions server))
                      (declare (ignore value))
                      (collect session))))
      (iter (for session in sessions)
        (ssh-session-finish session :server-closed :close))))
  server)


