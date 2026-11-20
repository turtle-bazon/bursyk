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
                  :server-version (ssh-server-version server)
                  :remote-address (cl-pnet:connection-peer-address connection))))
    (setf (gethash connection (ssh-server-connections server)) session
          (gethash session (ssh-server-sessions server)) session)
    (ssh-server-connected session connection)
    (ssh-session-start-login-grace-timer session)
    session))

(defun ssh-server-host-key-list (host-key)
  "HOST-KEY as a list of loaded private keys.

HOST-KEY is one key, one path, or a list of those.  Every key must be a type
the server can present; a key it could not sign with would otherwise be
advertised and then fail the first KEX."
  (let ((values (if (listp host-key) host-key (list host-key))))
    (unless values
      (error 'ssh-connection-error :detail "no host key given"))
    (mapcar (lambda (value)
              (let ((key (if (typep value 'ssh-private-key)
                             value
                             (ssh-load-private-key value))))
                (unless (some (lambda (algorithm)
                                (ssh-server-host-key-algorithm-p
                                 key algorithm))
                              +ssh-server-host-key-preference+)
                  (error 'ssh-connection-error
                         :detail (format nil "unsupported host key type ~A"
                                         (ssh-private-key-type key))))
                key))
            values)))

(defun make-ssh-server (address port
                        &key
                          host-key
                          authorized-keys
                          authorize
                          authorize-user
                          banner
                          permit-user-environment
                          set-env
                          max-auth-tries
                          max-sessions
                          login-grace-time
                          client-alive-interval
                          client-alive-count-max
                          accept-env
                          server-version
                          version-addendum
                          on-session
                          on-channel
                          on-direct-tcpip
                          on-tcpip-forward
                          on-cancel-tcpip-forward
                          on-error
                          on-close)
  "Listen on ADDRESS:PORT and serve SSH clients, returning at once.

HOST-KEY is an ssh-private-key, a path to an OpenSSH key, or a list of
those; ssh-ed25519, ECDSA and RSA keys are supported, and the server
advertises every algorithm its keys can sign with.  AUTHORIZED-KEYS is an
authorized_keys file, a list of public key blobs, or NIL.  AUTHORIZE, when
given, is a function of (USER KEY-BLOB) and replaces AUTHORIZED-KEYS.
AUTHORIZE-USER is a function of (SESSION USER) answering whether the
account may try to authenticate at all; it runs before any method and its
answer is cached for that name, which is where AllowUsers, DenyUsers and
PermitRootLogin belong.

BANNER is sshd's Banner text, a function of no arguments returning it (so a
file can change between connections), or NIL for none.

PERMIT-USER-ENVIRONMENT is sshd's PermitUserEnvironment: NIL and :NO permit
nothing, :YES lets a user set any variable, and a list of patterns is an
allowlist.  SET-ENV is the config's SetEnv assignments (\"NAME=VALUE\"), which
override the user's own environment.

MAX-AUTH-TRIES and MAX-SESSIONS keep sshd's defaults of 6 and 10 when NIL.
A MaxSessions of 0 refuses every session channel, as sshd does.

LOGIN-GRACE-TIME is sshd's LoginGraceTime in seconds (default 120); 0 means
no limit.  CLIENT-ALIVE-INTERVAL is ClientAliveInterval (default 0, no
probes) and CLIENT-ALIVE-COUNT-MAX is ClientAliveCountMax (default 3); a
count of 0 probes forever without disconnecting.  A NIL argument keeps the
default, so a config's explicit zero is still honoured.

SERVER-VERSION is the software version in the SSH identification string,
the part after \"SSH-2.0-\"; it defaults to the library's own string.  A
program should pass its real name and version, such as
\"bursyk-server_0.0.2.10\", so peers and logs identify it correctly.
VERSION-ADDENDUM is sshd's VersionAddendum: a comment appended after a
space, or :NONE for none.

ACCEPT-ENV is T (accept every env request), a list of names, a function of
(NAME VALUE), or NIL (refuse).  ON-SESSION runs once a client has
authenticated.  ON-DIRECT-TCPIP is a function of
(SESSION HOST PORT ORIGIN-ADDRESS ORIGIN-PORT) returning true to allow a
forwarded connection.  ON-TCPIP-FORWARD is a function of
(SESSION BIND-ADDRESS BIND-PORT) returning the port actually bound, or NIL to
refuse a remote forwarding request; ON-CANCEL-TCPIP-FORWARD takes the same
arguments and returns true once the listener is gone.  ON-ERROR receives
(SESSION CONDITION) (SESSION is NIL for listener errors), ON-CLOSE receives
(SESSION REASON)."
  (let* ((version (if server-version
                      (format nil "SSH-2.0-~A"
                              (check-server-version server-version))
                      +ssh-server-version+))
         (addendum (and version-addendum
                        (not (eq version-addendum :none))
                        (check-version-addendum version-addendum)))
         (software (if addendum
                       (format nil "~A ~A" version addendum)
                       version))
         (keys (ssh-server-host-key-list host-key))
         (server (%make-ssh-server
                  :address address
                  :port port
                  :version software
                  :host-keys keys
                  :authorized-keys authorized-keys
                  :authorize authorize
                  :authorize-user authorize-user
                  :banner banner
                  :permit-user-environment permit-user-environment
                  :set-env set-env
                  :max-auth-tries (or max-auth-tries 6)
                  :max-sessions (or max-sessions 10)
                  :login-grace-time
                  (or login-grace-time
                      +ssh-server-default-login-grace-time+)
                  :client-alive-interval
                  (or client-alive-interval
                      +ssh-server-default-client-alive-interval+)
                  :client-alive-count-max
                  (or client-alive-count-max
                      +ssh-server-default-client-alive-count-max+)
                  :accept-env accept-env
                  :on-session on-session
                  :on-channel on-channel
                  :on-direct-tcpip on-direct-tcpip
                  :on-tcpip-forward on-tcpip-forward
                  :on-cancel-tcpip-forward on-cancel-tcpip-forward
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


