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
  (let ((peer (cl-pnet:connection-peer-address connection)))
    (multiple-value-bind (allowed reason)
        (ssh-server-penalty-check server (getf peer :address))
      (unless allowed
        (ssh-log "refuse connection from ~A: ~A"
                 (getf peer :address) reason)
        (cl-pnet:close-connection connection)
        (return-from ssh-server-accept-session nil)))
    (unless (ssh-server-connection-allowed-p server peer)
      (ssh-log "drop connection from ~A past MaxStartups or PerSourceMaxStartups"
               (getf peer :address))
      ;; sshd writes a short notice before closing; it is best effort, so a
      ;; failed send simply closes the socket too.
      (unless (cl-pnet:send-data
               connection (format nil "Exceeded MaxStartups~C~C"
                                  #\Return #\Linefeed)
               :on-write (lambda (count)
                           (declare (ignore count))
                           (cl-pnet:close-connection connection))
               :on-error (lambda (status)
                           (declare (ignore status))
                           (cl-pnet:close-connection connection)))
        (cl-pnet:close-connection connection))
      (return-from ssh-server-accept-session nil)))
  (ssh-server-apply-tcp-keepalive
   server (cl-pnet:connection-fileno connection))
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

(defun ssh-server-host-key-list (host-key &optional host-key-agent)
  "HOST-KEY as a list of loaded private or agent-backed keys.

HOST-KEY is one key, one path, or a list of those.  Every key must be a type
the server can present; a key it could not sign with would otherwise be
advertised and then fail the first KEX.  When HOST-KEY-AGENT is given, a
path whose private half cannot be read falls back to its public key and the
agent signs for it."
  (let ((values (if (listp host-key) host-key (list host-key))))
    (unless values
      (error 'ssh-connection-error :detail "no host key given"))
    (mapcar (lambda (value)
              (let ((key
                      (cond
                        ((or (typep value 'ssh-private-key)
                             (typep value 'ssh-agent-host-key))
                         value)
                        (t
                         (handler-case (ssh-load-private-key value)
                           (error (condition)
                             (if (null host-key-agent)
                                 (error condition)
                                 (let ((blob
                                         (or (ssh-public-key-file-blob value)
                                             (ssh-public-key-file-blob
                                              (concatenate
                                               'string
                                               (namestring value) ".pub")))))
                                   (if blob
                                       (%make-ssh-agent-host-key
                                        :blob blob
                                        :type (nth-value
                                               0 (ssh-public-key-parts blob))
                                        :path value)
                                       (error condition))))))))))
                (unless (some (lambda (algorithm)
                                (ssh-server-host-key-algorithm-p
                                 key algorithm))
                              +ssh-server-host-key-preference+)
                  (error 'ssh-connection-error
                         :detail (format nil "unsupported host key type ~A"
                                         (ssh-host-key-type key))))
                key))
            values)))

(defun ssh-server-host-certificate-list (host-certificate)
  "HOST-CERTIFICATE as a list of certificate blobs.

HOST-CERTIFICATE is a certificate blob, a file holding one, or a list of
those.  sshd logs a file it cannot load and carries on with the rest, so a
missing or malformed entry never stops the listener; it is simply not
offered."
  (let ((values (if (listp host-certificate)
                    host-certificate
                    (list host-certificate))))
    (remove nil
            (mapcar (lambda (value)
                      (let ((blob
                              (if (or (stringp value) (pathnamep value))
                                  (ssh-public-key-file-blob value)
                                  value)))
                        (cond
                          ((null blob)
                           (ssh-log "could not load host certificate ~A"
                                    value)
                           nil)
                          ((not (ssh-certificate-blob-p blob))
                           (ssh-log "not a host certificate: ~A" value)
                           nil)
                          (t blob))))
                    values))))


(defun make-ssh-server (address port
                        &key
                          host-key
                          host-certificate
                          host-key-agent
                          authorized-keys
                          authorize
                          authorize-user
                          hostbased-key-allowed
                          authorize-password
                          authorize-keyboard-interactive
                          authorize-login
                          sshd-config
                          user-groups
                          banner
                          permit-user-environment
                          set-env
                          max-auth-tries
                          max-sessions
                          login-grace-time
                          client-alive-interval
                          client-alive-count-max
                          (max-startups '(10 30 100))
                          per-source-max-startups
                          (per-source-net-block-size '(32 128))
                          (unused-connection-timeout 0)
                          channel-timeouts
                          (tcp-keep-alive t)
                          v6only
                          address-family
                          accept-env
                          server-version
                          version-addendum
                          on-session
                          on-channel
                          on-direct-tcpip
                          on-direct-streamlocal
                          on-tcpip-forward
                          on-cancel-tcpip-forward
                          on-streamlocal-forward
                          on-cancel-streamlocal-forward
                          on-agent-forward
                          x11-authority-file
                          on-error
                          on-close)
  "Listen on ADDRESS:PORT and serve SSH clients, returning at once.

HOST-KEY is an ssh-private-key, a path to an OpenSSH key, or a list of
those; ssh-ed25519, ECDSA and RSA keys are supported, and the server
advertises every algorithm its keys can sign with.  HOST-CERTIFICATE is a
host certificate blob, a file holding one, or a list of those; each must
certify one of HOST-KEY's public keys, and a certificate algorithm then
outranks the plain key in KEXINIT.  AUTHORIZED-KEYS is an
authorized_keys file, a list of public key blobs, or NIL.  AUTHORIZE, when
given, is a function of (USER KEY-BLOB ADDRESS) and replaces AUTHORIZED-KEYS;
it should return the same (VALUES MATCHED ENVIRONMENTS OPTIONS) that
SSH-AUTHORIZED-KEY-BLOB-MATCH does, so the caller can enforce from=, no-pty,
command= and the other key options.  ADDRESS is the connection's peer
address.
AUTHORIZE-USER is a function of (SESSION USER) answering whether the
account may try to authenticate at all; it runs before any method and its
answer is cached for that name, which is where AllowUsers, DenyUsers and
PermitRootLogin belong.

AUTHORIZE-PASSWORD is a function of (SESSION USER PASSWORD) answering whether
a password request may finish the login; PasswordAuthentication must also not
be off.  AUTHORIZE-KEYBOARD-INTERACTIVE is a function of (SESSION USER
REQUEST) returning :SUCCESS, :FAILURE, or a plist (:NAME :INSTRUCTION
:PROMPTS) for the next challenge, where each prompt is (TEXT ECHO-P) and
REQUEST's :RESPONSES holds the previous round's answers.  Both are optional;
a method with no hook is never advertised.

SSHD-CONFIG is the parsed sshd_config whose Match blocks are resolved for
each connection once its account name is known; USER-GROUPS is a function of
USER returning group names for Match Group.  Without SSHD-CONFIG a server has
only the settings given here.

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

MAX-STARTUPS is sshd's MaxStartups as (BEGIN RATE FULL), default
(10 30 100): connections above BEGIN are dropped with a rising chance, and
above FULL always.  PER-SOURCE-MAX-STARTUPS caps unauthenticated connections
from one network, with PER-SOURCE-NET-BLOCK-SIZE (IPV4 IPV6, default
(32 128)) saying how much of the address groups peers; NIL means no such
cap, sshd's "none".

UNUSED-CONNECTION-TIMEOUT closes an authenticated connection that has had
no channel open for that many seconds; 0, the default, never closes one.
CHANNEL-TIMEOUTS is sshd's ChannelTimeout list, as (TYPE-PATTERN . SECONDS)
pairs or :NONE: an open channel that moves no bytes for the first matching
type's interval is closed.
TCP-KEEP-ALIVE (default T) controls SO_KEEPALIVE on accepted sockets.
V6ONLY, when true, sets IPV6_V6ONLY on an IPv6 listener, so an AddressFamily
inet6 wildcard does not also accept IPv4-mapped connections.  ADDRESS-FAMILY,
when :INET or :INET6, restricts a named ADDRESS when the listener resolves it,
so `localhost' under inet6 binds ::1 rather than the first answer.

SERVER-VERSION is the software version in the SSH identification string,
the part after \"SSH-2.0-\"; it defaults to the library's own string.  A
program should pass its real name and version, such as
\"bursyk-server_0.0.2.19\", so peers and logs identify it correctly.
VERSION-ADDENDUM is sshd's VersionAddendum: a comment appended after a
space, or :NONE for none.

ACCEPT-ENV is T (accept every env request), a list of names, a function of
(NAME VALUE), or NIL (refuse).  ON-SESSION runs once a client has
authenticated.  ON-DIRECT-TCPIP is a function of
(SESSION HOST PORT ORIGIN-ADDRESS ORIGIN-PORT) returning true to allow a
forwarded connection.  ON-TCPIP-FORWARD is a function of
(SESSION BIND-ADDRESS BIND-PORT) returning the port actually bound, or NIL to
refuse a remote forwarding request; ON-CANCEL-TCPIP-FORWARD takes the same
arguments and returns true once the listener is gone.  ON-AGENT-FORWARD is a
function of (SESSION) that creates the Unix socket a forwarded agent listens
on and returns (VALUES FD PATH CLEANUP); the library applies
AllowAgentForwarding, DisableForwarding and the key's no-agent-forwarding
before calling it, watches FD, opens an agent channel for every accepted
connection and relays its bytes.  CLEANUP, when given, removes PATH when the
session ends; without it the library unlinks PATH itself.  ON-ERROR receives
(SESSION CONDITION) (SESSION is NIL for listener errors), ON-CLOSE receives
(SESSION REASON).  X11-AUTHORITY-FILE is a function of (SESSION) returning
the Xauthority file the fake X11 cookie belongs in, or NIL to forward
without recording a cookie; the library creates the loopback display
listener and sets DISPLAY in the session's environment."
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
         (keys (ssh-server-check-host-keys
                (ssh-server-host-key-list host-key host-key-agent)
                (and sshd-config
                     (ssh-server-config-required-rsa-size sshd-config))))
         (certificates
           (ssh-server-pair-host-certificates
            keys (ssh-server-host-certificate-list host-certificate)))
         (server (%make-ssh-server
                  :address address
                  :port port
                  :version software
                  :host-keys keys
                  :host-key-agent host-key-agent
                  :host-certificates certificates
                  :authorized-keys authorized-keys
                  :authorize authorize
                  :authorize-user authorize-user
                  :hostbased-key-allowed hostbased-key-allowed
                  :authorize-password authorize-password
                  :authorize-keyboard-interactive
                  authorize-keyboard-interactive
                  :authorize-login authorize-login
                  :sshd-config sshd-config
                  :user-groups user-groups
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
                  :max-startups-begin (first max-startups)
                  :max-startups-rate (second max-startups)
                  :max-startups-full (third max-startups)
                  :per-source-max-startups per-source-max-startups
                  :per-source-net-block-size-ipv4
                  (first per-source-net-block-size)
                  :per-source-net-block-size-ipv6
                  (second per-source-net-block-size)
                  :unused-connection-timeout unused-connection-timeout
                  :channel-timeouts channel-timeouts
                  :tcp-keep-alive tcp-keep-alive
                  :accept-env accept-env
                  :on-session on-session
                  :on-channel on-channel
                  :on-direct-tcpip on-direct-tcpip
                  :on-direct-streamlocal on-direct-streamlocal
                  :on-tcpip-forward on-tcpip-forward
                  :on-cancel-tcpip-forward on-cancel-tcpip-forward
                  :on-streamlocal-forward on-streamlocal-forward
                  :on-cancel-streamlocal-forward on-cancel-streamlocal-forward
                  :on-agent-forward on-agent-forward
                  :x11-authority-file x11-authority-file
                  :on-error on-error
                  :on-close on-close
                  :connections (make-hash-table :test #'eq)))
         (listener (cl-pnet:make-tcp-listener
                    address port
                    :v6only v6only
                    :family address-family
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

(defun ssh-server-feature-supported-p (feature)
  "Whether the pure server transport can honour FEATURE.

This is the server-side counterpart of SSH-CLIENT-FEATURE-SUPPORTED-P and
keeps backend selection out of the server application."
  (not (null (member feature '(:remote-forward :streamlocal-forward
                               :x11-forward :agent-forward :mldsa)))))


