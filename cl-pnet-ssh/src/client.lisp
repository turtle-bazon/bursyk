(in-package #:cl-pnet-ssh)

;;;; The public client entry points. The rest of the library is callback
;;;; driven, like cl-pnet-tls: MAKE-SSH-CLIENT returns at once and ON-OPEN
;;;; runs when the session is authenticated and ready for channels.

(defun ssh-default-user ()
  (or (uiop:getenv "USER")
      (uiop:getenv "LOGNAME")
      "root"))

(defun ssh-default-private-key ()
  "~/.ssh/id_ed25519 when it exists, else NIL."
  (let ((path (merge-pathnames ".ssh/id_ed25519" (user-homedir-pathname))))
    (when (probe-file path) path)))

(defun ssh-resolve-private-key (private-key)
  "PRIVATE-KEY as a loaded key structure."
  (cond
    ((typep private-key 'ssh-private-key) private-key)
    ((or (stringp private-key) (pathnamep private-key))
     (ssh-load-private-key private-key))
    ((null private-key)
     (let ((default (ssh-default-private-key)))
       (unless default
         (error 'ssh-authentication-error
                :detail "no PRIVATE-KEY given and ~/.ssh/id_ed25519 is missing"))
       (ssh-load-private-key default)))
    (t (error 'ssh-authentication-error
              :detail "PRIVATE-KEY is neither a key nor a path"))))

(defun ssh-connect-error (client status)
  (ssh-client-fail
   client
   (make-condition 'ssh-connection-error
                   :detail (format nil "could not connect to ~A:~D (~A)"
                                   (ssh-client-host client)
                                   (ssh-client-port client) status))))

(defun ssh-make-client-record (host port user key known-hosts policy
                               on-open on-error on-close)
  "The CLIENT structure, before any connection exists."
  (%make-ssh-client :host host
                    :port port
                    :user user
                    :private-key key
                    :known-hosts known-hosts
                    :host-key-policy policy
                    :on-open on-open
                    :on-error on-error
                    :on-close on-close))

(defun ssh-open-connection (client)
  "Start CLIENT's TCP connection, or fail it when the connect does not start."
  (let ((connection
          (cl-pnet:tcp-connect
           (ssh-client-host client)
           (ssh-client-port client)
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
                                         (ssh-client-host client)
                                         (ssh-client-port client))))))
  client)

(defun make-ssh-client (host
                        &key
                          (port 22)
                          (user (ssh-default-user))
                          private-key
                          known-hosts
                          (host-key-policy :strict)
                          host-key-callback
                          on-open
                          on-error
                          on-close)
  "Connect to HOST as USER, authenticate with PRIVATE-KEY, return at once.

PRIVATE-KEY is an ssh-private-key or a path; the default is
~/.ssh/id_ed25519.  KNOWN-HOSTS defaults to ~/.ssh/known_hosts.
HOST-KEY-POLICY is :STRICT, :ACCEPT-NEW, :INSECURE, or a function of
(CLIENT FINGERPRINT KEY-BLOB) that returns true to trust and record an
unknown key; HOST-KEY-CALLBACK is the same function under a clearer name.

Callbacks: ON-OPEN (CLIENT) runs once authenticated, ON-ERROR (CLIENT
CONDITION) once on failure, ON-CLOSE (CLIENT REASON) once on a clean close.
Channels may be opened before ON-OPEN; their opens are queued.

Only the client role uses this entry point; the protocol core beneath it is
role-neutral."
  (ssh-open-connection
   (ssh-make-client-record host port user
                           (ssh-resolve-private-key private-key)
                           known-hosts
                           (or host-key-callback host-key-policy)
                           on-open on-error on-close)))

(defun ssh-client-close (client)
  "Close CLIENT and report every open channel as closed."
  (ssh-client-finish client :client-closed :close)
  client)

(defun ssh-client-host-key-fingerprint (client)
  "The fingerprint of the key the server presented, once the KEX has seen it."
  (let ((blob (ssh-client-host-key-blob client)))
    (and blob (ssh-key-fingerprint blob))))
