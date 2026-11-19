(in-package #:cl-pnet-ssh)

;;;; The public client entry points. The rest of the library is callback
;;;; driven, like cl-pnet-tls: MAKE-SSH-CLIENT returns at once and ON-OPEN
;;;; runs when the session is authenticated and ready for channels.

(defun ssh-default-private-key ()
  "~/.ssh/id_ed25519 when it exists, else NIL."
  (let ((path (merge-pathnames ".ssh/id_ed25519" (user-homedir-pathname))))
    (when (probe-file path) path)))

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
  "PRIVATE-KEY when given, else ~/.ssh/id_ed25519 when it exists."
  (or private-key
      (let ((default (ssh-default-private-key)))
        (and default (list default)))))

(defun ssh-no-key-condition ()
  "The error to report when no agent or key file is available."
  (make-condition 'ssh-authentication-error
                  :detail (concatenate
                           'string
                           "no key given: pass PRIVATE-KEY or use :AGENT, "
                           "or create ~/.ssh/id_ed25519")))

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
  "Deliver the agent's signers, or say that it holds no ed25519 key."
  (ssh-agent-signers
   :path agent
   :on-signers
   (lambda (signers)
     (if signers
         (funcall on-signers signers)
         (funcall on-error
                  (ssh-agent-error
                   "the ssh-agent holds no ssh-ed25519 keys"))))
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
has to be resolved first, and BALKORT-RESOLVE does that on a worker thread."
  (balkort.resolve:resolve-host
   (ssh-client-connect-host client)
   (lambda (address) (ssh-dial client address))
   (lambda (condition) (ssh-resolution-error client condition)))
  client)

(defun ssh-make-client-record (host connect-host port connect-port user
                               known-hosts policy on-open on-error on-close)
  "The CLIENT structure, before any connection exists."
  (%make-ssh-client :host host
                    :connect-host connect-host
                    :port port
                    :connect-port (or connect-port port)
                    :user user
                    :known-hosts known-hosts
                    :host-key-policy policy
                    :on-open on-open
                    :on-error on-error
                    :on-close on-close))

(defun ssh-resolve-and-connect (client private-key agent passphrase)
  "Find CLIENT's signers, then start its connection.

Key files load at once; an agent is asked over its socket without blocking,
and the SSH connection starts as soon as the signers are known.  A failure
in either step ends CLIENT through its error callback."
  (ssh-resolve-signers
   private-key agent passphrase
   (lambda (signers)
     (setf (ssh-client-signers client) signers)
     (ssh-open-connection client))
   (lambda (condition)
     (ssh-client-fail client condition)))
  client)

(defun make-ssh-client (host &key connect-host (port 22) connect-port
                             (user (ssh-default-user)) private-key agent
                             passphrase known-hosts (host-key-policy :strict)
                             host-key-callback on-open on-error on-close)
  "Connect to HOST as USER, authenticate, return at once.

HOST is the name HOST-KEY checks and KNOWN-HOSTS records; it is resolved
without blocking the loop.  CONNECT-HOST defaults to HOST and is the address
actually dialled, for a tunnel or an alias whose key is still checked under
HOST.  CONNECT-PORT defaults to PORT and is the port dialled, so a ProxyJump
tunnel can listen on loopback while PORT still names the server's real one.

Keys: PRIVATE-KEY is an ssh-private-key or a path, and PASSPHRASE decrypts a
protected file.  With no PRIVATE-KEY the default ~/.ssh/id_ed25519 is added
when it exists.  AGENT (T for SSH_AUTH_SOCK, or a socket path) offers every
ssh-ed25519 identity the agent holds; when both are available the agent's
keys are tried first, as OpenSSH does.  The default known-hosts file is
~/.ssh/known_hosts.

HOST-KEY-POLICY is :STRICT, :ACCEPT-NEW, :INSECURE, or a function of
(CLIENT FINGERPRINT KEY-BLOB) that returns true to trust and record an
unknown key; HOST-KEY-CALLBACK is the same function under a clearer name.

Callbacks: ON-OPEN (CLIENT) runs once authenticated, ON-ERROR (CLIENT
CONDITION) once on failure, ON-CLOSE (CLIENT REASON) once on a clean close.
Channels may be opened before ON-OPEN; their opens are queued.

Only the client role uses this entry point; the protocol core beneath it is
role-neutral."
  (ssh-resolve-and-connect
   (ssh-make-client-record host (or connect-host host) port connect-port user
                           known-hosts
                           (or host-key-callback host-key-policy)
                           on-open on-error on-close)
   private-key agent passphrase))

(defun ssh-client-close (client)
  "Close CLIENT and report every open channel as closed."
  (ssh-client-finish client :client-closed :close)
  client)

(defun ssh-client-host-key-fingerprint (client)
  "The fingerprint of the key the server presented, once the KEX has seen it."
  (let ((blob (ssh-client-host-key-blob client)))
    (and blob (ssh-key-fingerprint blob))))
