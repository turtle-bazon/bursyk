(in-package #:cl-pnet-ssh)

;;;; The public client entry points. The rest of the library is callback
;;;; driven, like cl-pnet-tls: MAKE-SSH-CLIENT returns at once and ON-OPEN
;;;; runs when the session is authenticated and ready for channels.

(defparameter +ssh-default-identity-names+
  '("id_ed25519" "id_ecdsa" "id_rsa")
  "Identity files OpenSSH would try, in the order offered here.

ed25519 comes first because it is what OpenSSH generates by default; ECDSA
and RSA follow because many existing accounts still have only one of those.")

(defun ssh-default-private-keys ()
  "The default identity files that exist, or NIL."
  (iter (for name in +ssh-default-identity-names+)
    (let ((path (merge-pathnames (format nil ".ssh/~A" name)
                                 (user-homedir-pathname))))
      (when (probe-file path) (collect path)))))

(defun ssh-default-private-key ()
  "The first default identity file that exists, or NIL."
  (first (ssh-default-private-keys)))

(defun ssh-load-key-signer (private-key passphrase)
  "PRIVATE-KEY, already loaded or a path, as a signer."
  (if (typep private-key 'ssh-private-key)
      (ssh-private-key-signer private-key)
      (ssh-private-key-signer
       (ssh-load-private-key private-key :passphrase passphrase))))

(defun ssh-load-key-signers (private-keys passphrase)
  "Signers for PRIVATE-KEYS, each already loaded or a path, in order."
  (mapcar (lambda (key) (ssh-load-key-signer key passphrase))
          (if (listp private-keys) private-keys (list private-keys))))

(defun ssh-default-key-sources (private-key)
  "PRIVATE-KEY when given, else every default identity file that exists."
  (if private-key
      private-key
      (ssh-default-private-keys)))

(defun ssh-no-key-condition ()
  "The error to report when no agent or key file is available."
  (make-condition 'ssh-authentication-error
                  :detail (concatenate
                           'string
                           "no key given: pass PRIVATE-KEY or use :AGENT, "
                           "or create ~/.ssh/id_ed25519, id_ecdsa or id_rsa")))

(defun ssh-report-key-signers (keys passphrase on-signers on-error)
  "Load KEY files and deliver their signers, or report why not."
  (handler-case
      (funcall on-signers (ssh-load-key-signers keys passphrase))
    (error (condition) (funcall on-error condition))))

(defun ssh-report-agent-keys (agent keys passphrase on-signers on-error)
  "Deliver the agent's signers followed by KEY files, tolerating either."
  (ssh-agent-signers
   :path agent
   :on-signers (lambda (signers)
                 (handler-case
                     (funcall on-signers
                              (append signers
                                      (ssh-load-key-signers keys passphrase)))
                   (error (condition) (funcall on-error condition))))
   ;; An agent that cannot answer is not fatal while a file remains.
   :on-error (lambda (condition)
               (declare (ignore condition))
               (ssh-report-key-signers
                keys passphrase on-signers on-error))))

(defun ssh-report-agent-signers (agent on-signers on-error)
  "Deliver the agent's signers, or say that it holds no usable key."
  (ssh-agent-signers
   :path agent
   :on-signers
   (lambda (signers)
     (if signers
         (funcall on-signers signers)
         (funcall on-error
                  (ssh-agent-error
                   "the ssh-agent holds no supported keys"))))
   :on-error on-error))

(defun ssh-resolve-signers (private-key agent passphrase on-signers on-error)
  "Find the signers authentication may try, in order, without blocking.

The agent's ssh-ed25519 keys are offered first, then the key files, which
is the order OpenSSH uses.  PRIVATE-KEY may be one key or a list, and the
default ~/.ssh/id_ed25519 fills in when no file is named.  AGENT is T for
SSH_AUTH_SOCK or a socket path; without an explicit key the environment's
agent is used when SSH_AUTH_SOCK is set.  A failing agent does not hide
working key files, and vice versa.  ON-ERROR receives an
ssh-authentication-error only when nothing is left to try."
  (let* ((keys (ssh-default-key-sources private-key))
         (agent (or agent
                    (and (null private-key)
                         (uiop:getenv "SSH_AUTH_SOCK")
                         t))))
    (cond
      ((and keys agent)
       (ssh-report-agent-keys agent keys passphrase on-signers on-error))
      (agent (ssh-report-agent-signers agent on-signers on-error))
      (keys (ssh-report-key-signers keys passphrase on-signers on-error))
      (t (funcall on-error (ssh-no-key-condition))))))

(defun ssh-connect-error (client status)
  (ssh-client-fail
   client
   (make-condition 'ssh-connection-error
                   :detail (format nil "could not connect to ~A:~D (~A)"
                                   (ssh-client-connect-host client)
                                   (or (ssh-client-connect-port client)
                                       (ssh-client-port client))
                                   status))))

(defun ssh-resolution-error (client condition)
  (ssh-client-fail
   client
   (make-condition 'ssh-connection-error
                   :detail (format nil "could not resolve ~A: ~A"
                                   (ssh-client-connect-host client)
                                   condition))))

(defun ssh-dial (client address)
  "Connect CLIENT to the numeric ADDRESS its CONNECT-HOST resolved to."
  (let ((port (or (ssh-client-connect-port client) (ssh-client-port client))))
    (ssh-log "connecting to ~A:~D" address port)
    (let ((connection
            (cl-pnet:tcp-connect
             address
             port
             :read-cb (lambda (data) (ssh-client-receive client data))
             :on-connect (lambda (connection)
                           (ssh-client-connected client connection))
             :on-error (lambda (status) (ssh-connect-error client status)))))
      (if connection
          (setf (ssh-client-connection client) connection)
          (ssh-client-fail
           client
           (make-condition 'ssh-connection-error
                           :detail (format nil "could not connect to ~A:~D"
                                           (ssh-client-connect-host client)
                                           port))))))
  client)

(defun ssh-open-connection (client)
  "Resolve CONNECT-HOST without blocking the loop, then dial it.

Returns CLIENT at once; the connection and every failure report through the
client's callbacks.  CL-PNET's connect takes a numeric address, so a name
has to be resolved first, and BURZAY does that on a worker thread.
A ProxyCommand needs none of that: the helper is what reaches the server."
  (if (ssh-client-proxy-command client)
      (ssh-open-proxy-connection client)
      (progn
        (ssh-log "resolving ~A" (ssh-client-connect-host client))
        (burzay:resolve-host
         (ssh-client-connect-host client)
         (lambda (address) (ssh-dial client address))
         (lambda (condition) (ssh-resolution-error client condition)))
        client)))

(defun ssh-make-client-record (host connect-host host-key-host port connect-port
                               user known-hosts policy connect-timeout
                               server-alive-interval server-alive-count-max
                               proxy-command
                               on-open on-error on-close on-forwarded-tcpip
                               on-forwarded-streamlocal
                               &key kex-algorithms host-key-algorithms
                                 ciphers macs pubkey-accepted-algorithms
                                 ca-signature-algorithms
                                 (revoked-host-keys '())
                                 hash-known-hosts
                                 (tcp-keep-alive t)
                                 (required-rsa-size
                                  +ssh-rsa-minimum-modulus-size+))
  "The CLIENT structure, before any connection exists."
  (%make-ssh-client :host host
                    :connect-host connect-host
                    :host-key-host host-key-host
                    :port port
                    :connect-port (or connect-port port)
                    :user user
                    :known-hosts known-hosts
                    :host-key-policy policy
                    :connect-timeout connect-timeout
                    :server-alive-interval server-alive-interval
                    :server-alive-count-max (or server-alive-count-max 3)
                    :proxy-command (ssh-proxy-command-value proxy-command)
                    :kex-algorithms kex-algorithms
                    :host-key-algorithms host-key-algorithms
                    :ciphers ciphers
                    :macs macs
                    :pubkey-accepted-algorithms pubkey-accepted-algorithms
                    :ca-signature-algorithms ca-signature-algorithms
                    :revoked-host-keys revoked-host-keys
                    :hash-known-hosts hash-known-hosts
                    :tcp-keep-alive tcp-keep-alive
                    :required-rsa-size required-rsa-size
                    :on-open on-open
                    :on-error on-error
                    :on-close on-close
                    :on-forwarded-tcpip on-forwarded-tcpip
                    :on-forwarded-streamlocal on-forwarded-streamlocal))

(defun ssh-filter-signers (signers patterns &key minimum-rsa-size)
  "SIGNERS whose type matches PATTERNS and whose RSA modulus is large enough.

A NIL PATTERNS list leaves every type eligible.  MINIMUM-RSA-SIZE is
RequiredRSASize: it only rejects RSA keys below the floor, as ssh does."
  (remove-if
   (lambda (signer)
     (or (and patterns
              (not (some (lambda (pattern)
                           (ssh-match-pattern pattern
                                              (ssh-signer-type signer)))
                         patterns)))
         (not (ssh-key-rsa-size-allowed-p (ssh-signer-blob signer)
                                          minimum-rsa-size))))
   signers))

(defun ssh-resolve-and-connect (client private-key agent passphrase)
  "Find CLIENT's signers, then start its connection.

Key files load at once; an agent is asked over its socket without blocking,
and the SSH connection starts as soon as the signers are known.  A failure
in either step ends CLIENT through its error callback.  PubkeyAcceptedAlgorithms
is applied here, before any request names a key the configuration forbade."
  (ssh-client-start-connect-timer client)
  (ssh-resolve-signers
   private-key agent passphrase
   (lambda (signers)
     (let ((signers (ssh-filter-signers
                     signers
                     (ssh-client-pubkey-accepted-algorithms client)
                     :minimum-rsa-size (ssh-client-required-rsa-size client))))
       (if (null signers)
           (ssh-client-fail
            client
            (make-condition
             'ssh-authentication-error
             :detail "no key matches PubkeyAcceptedAlgorithms or RequiredRSASize"))
           (progn
             (setf (ssh-client-signers client) signers)
             (ssh-open-connection client)))))
   (lambda (condition)
     (ssh-client-fail client condition)))
  client)

(defun make-ssh-client (host &key connect-host host-key-host (port 22) connect-port
                             (user (ssh-default-user)) private-key agent
                             passphrase known-hosts (host-key-policy :strict)
                             host-key-callback connect-timeout
                             server-alive-interval (server-alive-count-max 3)
                             proxy-command
                             kex-algorithms host-key-algorithms
                             ciphers macs pubkey-accepted-algorithms
                             ca-signature-algorithms
                             (revoked-host-keys '())
                             hash-known-hosts
                             (tcp-keep-alive t)
                             (required-rsa-size
                              +ssh-rsa-minimum-modulus-size+)
                             on-open on-error on-close on-forwarded-tcpip
                             on-forwarded-streamlocal)
  "Connect to HOST as USER, authenticate, return at once.

HOST is the name HOST-KEY checks and KNOWN-HOSTS records; it is resolved
without blocking the loop.  CONNECT-HOST defaults to HOST and is the address
actually dialled, for a tunnel or an alias whose key is still checked under
HOST.  HOST-KEY-HOST overrides the name used for known_hosts alone, for a
config alias whose HostName is what OpenSSH checks.  CONNECT-PORT defaults to
PORT and is the port dialled, so a ProxyJump tunnel can listen on loopback
while PORT still names the server's real one.  PROXY-COMMAND, when given,
replaces the direct connection with a helper that carries the stream on its
stdin and stdout; %h, %n, %p, %r and %% expand as in ssh_config.

Keys: PRIVATE-KEY is an ssh-private-key or a path, and PASSPHRASE decrypts a
protected file.  With no PRIVATE-KEY every default identity file that exists
(~/.ssh/id_ed25519, id_ecdsa, then ~/.ssh/id_rsa) is added.  AGENT (T for
SSH_AUTH_SOCK, or a socket path) offers every key the agent can sign with;
when both are available the agent's keys are tried first, as OpenSSH does.
The default known-hosts file is ~/.ssh/known_hosts.

CONNECT-TIMEOUT, when positive, fails the client if it has not authenticated
within that many seconds.  SERVER-ALIVE-INTERVAL, when positive, sends
keepalive@openssh.com every interval seconds and fails the client after
SERVER-ALIVE-COUNT-MAX unanswered intervals (default 3).

HOST-KEY-POLICY is :STRICT, :ACCEPT-NEW, :INSECURE, or a function of
(CLIENT FINGERPRINT KEY-BLOB) that returns true to trust and record an
unknown key; HOST-KEY-CALLBACK is the same function under a clearer name.

Callbacks: ON-OPEN (CLIENT) runs once authenticated, ON-ERROR (CLIENT
CONDITION) once on failure, ON-CLOSE (CLIENT REASON) once on a clean close.
Channels may be opened before ON-OPEN; their opens are queued.
ON-FORWARDED-STREAMLOCAL (CLIENT PATH) answers a server-initiated
Unix-socket forward, returning a function of CHANNEL that bridges it, or NIL
to refuse.

Only the client role uses this entry point; the protocol core beneath it is
role-neutral."
  (ssh-resolve-and-connect
   (ssh-make-client-record host (or connect-host host) host-key-host
                           port connect-port user
                           known-hosts
                           (or host-key-callback host-key-policy)
                           connect-timeout
                           server-alive-interval server-alive-count-max
                           proxy-command
                           on-open on-error on-close on-forwarded-tcpip
                           on-forwarded-streamlocal
                           :kex-algorithms kex-algorithms
                           :host-key-algorithms host-key-algorithms
                           :ciphers ciphers
                           :macs macs
                           :pubkey-accepted-algorithms
                           pubkey-accepted-algorithms
                           :ca-signature-algorithms ca-signature-algorithms
                           :revoked-host-keys revoked-host-keys
                           :hash-known-hosts hash-known-hosts
                           :tcp-keep-alive tcp-keep-alive
                           :required-rsa-size required-rsa-size)
   private-key agent passphrase))

(defun ssh-client-close (client)
  "Close CLIENT and report every open channel as closed."
  (ssh-client-send-disconnect client)
  (ssh-client-finish client :client-closed :close)
  client)

(defun ssh-client-host-key-fingerprint (client)
  "The fingerprint of the key the server presented, once the KEX has seen it."
  (let ((blob (ssh-client-host-key-blob client)))
    (and blob (ssh-key-fingerprint blob))))
