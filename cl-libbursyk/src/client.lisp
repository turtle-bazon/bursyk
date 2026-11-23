(in-package #:cl-pnet-ssh)

;;;; The public client entry points. The rest of the library is callback
;;;; driven, like cl-pnet-tls: MAKE-SSH-CLIENT returns at once and ON-OPEN
;;;; runs when the session is authenticated and ready for channels.

(defun ssh-default-private-keys ()
  "The default identity files that exist, or NIL."
  (iter (for name in +ssh-default-identity-names+)
    (let ((path (merge-pathnames (format nil ".ssh/~A" name)
                                 (user-homedir-pathname))))
      (when (probe-file path) (collect path)))))

(defun ssh-default-private-key ()
  "The first default identity file that exists, or NIL."
  (first (ssh-default-private-keys)))

(defun ssh-load-key-signer (private-key passphrase &key add-to-agent
                                                      certificate-files-specified)
  "PRIVATE-KEY, already loaded or a path, as a signer.

ADD-TO-AGENT, when given, is the agent path (or T for SSH_AUTH_SOCK); the
loaded key is offered to it before being used, as AddKeysToAgent does.
CERTIFICATE-FILES-SPECIFIED suppresses the KEY-cert.pub lookup, because an
explicit CertificateFile takes its place."
  (let ((key (if (typep private-key 'ssh-private-key)
                 private-key
                 (ssh-load-private-key private-key :passphrase passphrase))))
    (when add-to-agent
      (ssh-agent-add-identity
       key :path add-to-agent
       :on-error (lambda (condition)
                   (ssh-log "could not add a key to the agent: ~A"
                            condition))))
    (ssh-private-key-signer
     key :certificate-files-specified certificate-files-specified)))

(defun ssh-load-key-signers (private-keys passphrase &key add-to-agent
                                                        certificate-files-specified)
  "Signers for PRIVATE-KEYS, each already loaded or a path, in order."
  (mapcar (lambda (key)
            (ssh-load-key-signer
             key passphrase
             :add-to-agent add-to-agent
             :certificate-files-specified certificate-files-specified))
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

(defun ssh-report-key-signers (keys passphrase on-signers on-error
                               &key add-to-agent certificate-files-specified)
  "Load KEY files and deliver their signers, or report why not."
  (handler-case
      (funcall on-signers
               (ssh-load-key-signers
                keys passphrase
                :add-to-agent add-to-agent
                :certificate-files-specified certificate-files-specified))
    (error (condition) (funcall on-error condition))))

(defun ssh-report-agent-keys (agent keys passphrase on-signers on-error
                              &key add-to-agent certificate-files-specified)
  "Deliver the agent's signers followed by KEY files, tolerating either."
  (ssh-agent-signers
   :path agent
   :on-signers (lambda (signers)
                 (handler-case
                     (funcall on-signers
                              (append signers
                                      (ssh-load-key-signers
                                       keys passphrase
                                       :add-to-agent add-to-agent
                                       :certificate-files-specified
                                       certificate-files-specified)))
                   (error (condition) (funcall on-error condition))))
   ;; An agent that cannot answer is not fatal while a file remains.
   :on-error (lambda (condition)
               (declare (ignore condition))
               (ssh-report-key-signers
                keys passphrase on-signers on-error
                :add-to-agent add-to-agent
                :certificate-files-specified certificate-files-specified))))

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

(defun ssh-resolve-signers (private-key agent passphrase on-signers on-error
                            &key add-keys-to-agent certificate-files)
  "Find the signers authentication may try, in order, without blocking.

The agent's ssh-ed25519 keys are offered first, then the key files, which
is the order OpenSSH uses.  PRIVATE-KEY may be one key or a list, and the
default ~/.ssh/id_ed25519 fills in when no file is named.  AGENT is T for
SSH_AUTH_SOCK or a socket path; without an explicit key the environment's
agent is used when SSH_AUTH_SOCK is set.  A failing agent does not hide
working key files, and vice versa.  ON-ERROR receives an
ssh-authentication-error only when nothing is left to try.

CERTIFICATE-FILES are CertificateFile paths.  Each certificate is attached
to the signer whose key it certifies, file or agent, and the automatic
KEY-cert.pub lookup is disabled, as in ssh."
  (let* ((keys (ssh-default-key-sources private-key))
         (agent (or agent
                    (and (null private-key)
                         (uiop:getenv "SSH_AUTH_SOCK")
                         t)))
         (certificates (ssh-load-certificate-files certificate-files))
         (certificate-files-specified (not (null certificates)))
         (deliver
           (if certificates
               (lambda (signers)
                 (funcall on-signers
                          (ssh-signers-with-certificates
                           signers certificates)))
               on-signers)))
    (let ((add-to-agent (and add-keys-to-agent agent)))
      (cond
        ((and keys agent)
         (ssh-report-agent-keys agent keys passphrase deliver on-error
                                :add-to-agent add-to-agent
                                :certificate-files-specified
                                certificate-files-specified))
        (agent (ssh-report-agent-signers agent deliver on-error))
        (keys (ssh-report-key-signers
               keys passphrase deliver on-error
               :add-to-agent add-to-agent
               :certificate-files-specified certificate-files-specified))
        (t (funcall on-error (ssh-no-key-condition)))))))

(defun ssh-connect-error (client status)
  "Report a failed connect, retrying while ConnectionAttempts remain."
  (let ((attempt (1+ (ssh-client-connection-attempt client)))
        (limit (ssh-client-connection-attempts client)))
    (if (< attempt limit)
        (progn
          (setf (ssh-client-connection-attempt client) attempt)
          (ssh-log "connect failed (~A); trying again (~D/~D)"
                   status attempt limit)
          ;; ssh gives every attempt its own ConnectTimeout.
          (ssh-client-cancel-connect-timer client)
          (ssh-client-start-connect-timer client)
          (setf (ssh-client-retry-timer client)
                (cl-pnet:timer-start
                 1 0
                 (lambda ()
                   (setf (ssh-client-retry-timer client) nil)
                   (unless (ssh-client-closed client)
                     (ssh-open-connection client))))))
        (ssh-client-fail
         client
         (make-condition 'ssh-connection-error
                         :detail (format nil "could not connect to ~A:~D (~A)"
                                         (ssh-client-connect-host client)
                                         (or (ssh-client-connect-port client)
                                             (ssh-client-port client))
                                         status))))))

(defun ssh-resolution-error (client condition)
  (ssh-client-fail
   client
   (make-condition 'ssh-connection-error
                   :detail (format nil "could not resolve ~A: ~A"
                                   (ssh-client-connect-host client)
                                   condition))))

(defun ssh-dial (client address)
  "Connect CLIENT to the numeric ADDRESS its CONNECT-HOST resolved to."
  (cond
    ((and (or (ssh-client-bind-address client)
              (ssh-client-bind-interface client))
          (not (ssh-client-bind-address-resolved-p client address)))
     (ssh-client-resolve-bind-address
      client address (lambda () (ssh-dial-bound client address))))
    ((or (ssh-client-bind-address client)
         (ssh-client-bind-interface client))
     (ssh-dial-bound client address))
    (t
     (ssh-dial-direct client address))))

(defun ssh-dial-direct (client address)
  "Dial ADDRESS without a bound source, through CL-PNET."
  (let ((port (or (ssh-client-connect-port client) (ssh-client-port client))))
    (setf (ssh-client-remote-address client) address)
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

(defun ssh-client-bind-description (client)
  "How to name CLIENT's configured source, for error messages."
  (let ((address (or (ssh-client-bind-address-resolved client)
                     (ssh-client-bind-address client))))
    (or address
        (format nil "interface ~A" (ssh-client-bind-interface client)))))

(defun ssh-proxy-connect-complete (client)
  "Finish a non-blocking bound connect once FD turns writable."
  (let ((proxy (ssh-client-pipe client)))
    (when (and proxy (not (ssh-proxy-closed proxy)))
      (let ((fd (ssh-proxy-read-fd proxy)))
        (ssh-proxy-cancel-write-watcher proxy)
        (multiple-value-bind (errno answered)
            (cl-pnet-sockets:socket-error fd)
          (cond
            ((not answered)
             (ssh-proxy-close client)
             (ssh-connect-error client errno))
            ((zerop errno)
             (setf (ssh-proxy-read-watcher proxy)
                   (cl-pnet:fd-watch
                    fd
                    :on-readable
                    (lambda (watcher)
                      (declare (ignore watcher))
                      (ssh-proxy-readable client))))
             (ssh-log "connected")
             (ssh-client-connected client nil))
            (t
             (ssh-proxy-close client)
             (ssh-connect-error client errno))))))))

(defun ssh-dial-bound (client address)
  "Dial ADDRESS from CLIENT's BindAddress or BindInterface.

The descriptor is a socket rather than a CL-PNET connection, so it travels
through the same event-loop watchers the proxy path uses."
  (let* ((port (or (ssh-client-connect-port client) (ssh-client-port client)))
         (bind (or (ssh-client-bind-address-resolved client)
                   (ssh-client-bind-address client)))
         (interface (ssh-client-bind-interface client)))
    (setf (ssh-client-remote-address client) address)
    (ssh-log "connecting to ~A:~D bound to ~A"
             address port (ssh-client-bind-description client))
    (multiple-value-bind (fd state errno stage)
        (cl-pnet-sockets:connect-tcp address port
                                     :bind-address bind
                                     :bind-interface interface)
      (cond
        ((null fd)
         (if (eq stage :connect)
             (ssh-connect-error client errno)
             (ssh-client-fail
              client
              (make-condition
               'ssh-connection-error
               :detail
               (format nil "could not bind ~A for ~A:~D (~A)"
                       (ssh-client-bind-description client)
                       (ssh-client-connect-host client)
                       port
                       (cl-pnet-sockets:c-strerror errno))))))
        ((eq state :connected)
         (setf (ssh-client-pipe client)
               (%make-ssh-proxy :read-fd fd :write-fd fd :close-fds t))
         (ssh-proxy-connect-complete client))
        (t
         (let ((proxy (%make-ssh-proxy :read-fd fd :write-fd fd
                                       :close-fds t)))
           (setf (ssh-client-pipe client) proxy
                 (ssh-proxy-write-watcher proxy)
                 (cl-pnet:fd-watch
                  fd
                  :on-writable
                  (lambda (watcher)
                    (declare (ignore watcher))
                    (ssh-proxy-connect-complete client)))))))))
  client)



(defun ssh-open-connection (client)
  "Look up SSHFP records, then open CLIENT's transport.

Returns CLIENT at once; the connection and every failure report through the
client's callbacks."
  (if (ssh-client-host-key-dns-needed-p client)
      (ssh-client-query-host-key-dns
       client (lambda () (ssh-open-transport client)))
      (ssh-open-transport client))
  client)

;; SSH-CLIENT-BIND-ADDRESS-RESOLVED-P and SSH-CLIENT-RESOLVE-BIND-ADDRESS
;; live in CLIENT-POLICY, shared with the libssh backend.

(defun ssh-open-transport (client)
  "Resolve CONNECT-HOST without blocking the loop, then dial it.

CL-PNET's connect takes a numeric address, so a name has to be resolved
first, and BURZAY does that on a worker thread.  CanonicalDomains candidates
are tried before the name itself.  A ProxyCommand needs none of that: the
helper is what reaches the server.  BindAddress is resolved once the remote
address is known, because it has to be in the same family."
  (if (ssh-client-proxy-command client)
      (ssh-open-proxy-connection client)
      (ssh-open-direct-transport client))
  client)

(defun ssh-client-address-family-name (client)
  "CLIENT's AddressFamily as the word an error message uses."
  (case (ssh-client-address-family client)
    (:inet "IPv4")
    (:inet6 "IPv6")
    (t "any")))

(defun ssh-client-address-in-family-p (client address)
  "Whether numeric ADDRESS belongs to CLIENT's AddressFamily."
  (case (ssh-client-address-family client)
    (:inet (not (cl-pnet-sockets:ipv6-address-p address)))
    (:inet6 (cl-pnet-sockets:ipv6-address-p address))
    (t t)))

;; SSH-CLIENT-RESOLVER-FUNCTION-P and SSH-CLIENT-RESOLVE-HOST live in
;; CLIENT-POLICY, shared with the libssh backend.

(defun ssh-open-direct-transport (client)
  "Resolve and dial CONNECT-HOST for a connection that is not proxied."
  (let ((original (ssh-client-connect-host client)))
    (labels ((dial (name on-failure)
               ;; NAME becomes CONNECT-HOST before the family check, so an
               ;; error names the candidate that actually resolved badly.
               (lambda (address)
                 (setf (ssh-client-connect-host client) name)
                 (if (ssh-client-address-in-family-p client address)
                     (ssh-dial client address)
                     (funcall on-failure
                              (make-condition
                               'simple-error
                               :format-control "~A is not an ~A address"
                               :format-arguments
                               (list address
                                     (ssh-client-address-family-name
                                      client)))))))
             (try (names)
               (if names
                   (let ((next (lambda (condition)
                                 (declare (ignore condition))
                                 (try (rest names)))))
                     (ssh-log "resolving ~A" (first names))
                     (ssh-client-resolve-host client (first names)
                                              (dial (first names) next)
                                              next))
                   (if (ssh-client-canonicalize-fallback-local client)
                       (progn
                         (ssh-log "resolving ~A" original)
                         (ssh-client-resolve-host
                          client original
                          (dial original
                                (lambda (condition)
                                  (ssh-resolution-error client condition)))
                          (lambda (condition)
                            (ssh-resolution-error client condition))))
                       (ssh-resolution-error
                        client
                        (make-condition
                         'simple-error
                         :format-control
                         "no CanonicalDomains candidate resolved ~A"
                         :format-arguments (list original)))))))
      (let ((candidates (ssh-canonicalize-candidates client)))
        (if candidates
            (try candidates)
            (progn
              (ssh-log "resolving ~A" original)
              (ssh-client-resolve-host
               client original
               (dial original
                     (lambda (condition)
                       (ssh-resolution-error client condition)))
               (lambda (condition)
                 (ssh-resolution-error client condition)))))))))

(defun ssh-make-client-record (host connect-host host-key-host port connect-port
                               user known-hosts policy connect-timeout
                               server-alive-interval server-alive-count-max
                               proxy-command
                               on-open on-error on-close on-forwarded-tcpip
                               on-forwarded-streamlocal
                               &key kex-algorithms host-key-algorithms
                                 ciphers macs pubkey-accepted-algorithms
                                 ca-signature-algorithms                                 (revoked-host-keys '())
                                 hash-known-hosts
                                 known-hosts-command
                                 (add-keys-to-agent :no)
                                 (certificate-files '())
                                 no-host-authentication-for-localhost
                                 host-key-alias
                                 batch-mode
                                 (warn-weak-crypto t)
                                 (obscure-keystroke-timing
                                  +ssh-keystroke-default-interval-ms+)
                                 channel-timeouts
                                 rekey-limit rekey-interval
                                 version-addendum
                                 hostbased-authentication
                                 hostbased-accepted-algorithms
                                 (hostbased-keys '())
                                 (password-authentication t)
                                 (kbd-interactive-authentication t)
                                 number-of-password-prompts
                                 preferred-authentications
                                 (pubkey-authentication t)
                                 password-callback
                                 kbd-interactive-callback
                                 (canonicalize-hostname :no)
                                 (canonical-domains '())
                                 (canonicalize-max-dots 1)
                                 (canonicalize-fallback-local t)
                                 resolver
                                 (update-host-keys :yes)
                                 (fingerprint-hash :sha256)
                                 visual-host-key
                                 check-host-ip
                                 (verify-host-key-dns :no)
                                 host-key-dns-resolver
                                 (ip-qos-interactive #xb8)
                                 (ip-qos-bulk :none)
                                 (tcp-keep-alive t)
                                 set-env
                                 (connection-attempts 1)
                                 (required-rsa-size
                                  +ssh-rsa-minimum-modulus-size+)
                                 proxy-use-fdpass
                                 bind-address
                                 bind-interface
                                 address-family
                                 forward-agent
                                 forward-agent-sock-path
                                 forward-x11
                                 forward-x11-trusted
                                 forward-x11-timeout
                                 xauth-location)
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
                    :proxy-use-fdpass proxy-use-fdpass
                    :bind-address bind-address
                    :bind-interface bind-interface
                    :address-family
                    (ssh-normalize-address-family address-family)
                    :forward-agent forward-agent
                    :forward-agent-sock-path forward-agent-sock-path
                    :forward-x11 forward-x11
                    :forward-x11-trusted forward-x11-trusted
                    :forward-x11-timeout forward-x11-timeout
                    :xauth-location xauth-location
                    :kex-algorithms kex-algorithms
                    :host-key-algorithms host-key-algorithms
                    :ciphers ciphers
                    :macs macs
                    :pubkey-accepted-algorithms pubkey-accepted-algorithms
                    :ca-signature-algorithms ca-signature-algorithms
                    :revoked-host-keys revoked-host-keys
                    :hash-known-hosts hash-known-hosts
                    :known-hosts-command known-hosts-command
                    :add-keys-to-agent add-keys-to-agent
                    :certificate-files certificate-files
                    :no-host-authentication-for-localhost
                    no-host-authentication-for-localhost
                    :host-key-alias host-key-alias
                    :batch-mode batch-mode
                    :warn-weak-crypto warn-weak-crypto
                    :obscure-keystroke-timing obscure-keystroke-timing
                    :channel-timeouts channel-timeouts
                    :rekey-limit (or rekey-limit 0)
                    :rekey-interval (or rekey-interval 0)
                    :version-addendum
                    (and version-addendum
                         (not (eq version-addendum :none))
                         (check-version-addendum version-addendum))
                    :hostbased-authentication hostbased-authentication
                    :hostbased-accepted-algorithms
                    hostbased-accepted-algorithms
                    :hostbased-keys hostbased-keys
                    :password-authentication password-authentication
                    :kbd-interactive-authentication
                    kbd-interactive-authentication
                    :number-of-password-prompts number-of-password-prompts
                    :preferred-authentications preferred-authentications
                    :pubkey-authentication pubkey-authentication
                    :password-callback password-callback
                    :kbd-interactive-callback kbd-interactive-callback
                    :canonicalize-hostname canonicalize-hostname
                    :canonical-domains canonical-domains
                    :canonicalize-max-dots canonicalize-max-dots
                    :canonicalize-fallback-local canonicalize-fallback-local
                    :resolver resolver
                    :update-host-keys update-host-keys
                    :fingerprint-hash fingerprint-hash
                    :visual-host-key visual-host-key
                    :check-host-ip check-host-ip
                    :verify-host-key-dns verify-host-key-dns
                    :host-key-dns-resolver host-key-dns-resolver
                    :ip-qos-interactive ip-qos-interactive
                    :ip-qos-bulk ip-qos-bulk
                    :tcp-keep-alive tcp-keep-alive
                    :set-env set-env
                    :connection-attempts connection-attempts
                    :required-rsa-size required-rsa-size
                    :on-open on-open
                    :on-error on-error
                    :on-close on-close
                    :on-forwarded-tcpip on-forwarded-tcpip
                    :on-forwarded-streamlocal on-forwarded-streamlocal))


(defparameter +ssh-hostbased-default-key-paths+
  '("/etc/ssh/ssh_host_ed25519_key"
    "/etc/ssh/ssh_host_ecdsa_key"
    "/etc/ssh/ssh_host_rsa_key")
  "Where ssh looks for a hostbased client host key.")

(defun ssh-private-key-algorithm (key)
  "The hostbased algorithm name for private KEY."
  (let ((type (ssh-private-key-type key)))
    (if (string= type "ssh-rsa")
        "rsa-sha2-256"
        type)))

(defun ssh-hostbased-key-allowed-p (client key)
  "Whether KEY's type matches HostbasedAcceptedAlgorithms."
  (let ((algorithm (ssh-private-key-algorithm key))
        (patterns (ssh-client-hostbased-accepted-algorithms client)))
    (or (null patterns)
        (some (lambda (pattern) (ssh-match-pattern pattern algorithm))
              patterns))))

(defun ssh-load-hostbased-key (client)
  "The first readable host key that HostbasedAcceptedAlgorithms permits."
  (let ((paths (append (ssh-client-hostbased-keys client)
                       (mapcar #'pathname +ssh-hostbased-default-key-paths+))))
    (dolist (path paths)
      (when (probe-file path)
        (let ((key (handler-case
                       (ssh-load-private-key path)
                     (error () nil))))
          (when (and key (ssh-hostbased-key-allowed-p client key))
            (return key)))))))

(defun ssh-resolve-and-connect (client private-key agent passphrase)
  "Find CLIENT's signers, then start its connection.

Key files load at once; an agent is asked over its socket without blocking,
and the SSH connection starts as soon as the signers are known.  A failure
in either step ends CLIENT through its error callback.  PubkeyAcceptedAlgorithms
is applied here, before any request names a key the configuration forbade."
  (ssh-client-start-connect-timer client)
  (when (ssh-client-hostbased-authentication client)
    (setf (ssh-client-hostbased-key client)
          (ssh-load-hostbased-key client)))
  (ssh-resolve-signers
   private-key agent passphrase
   (lambda (signers)
     (let ((signers (ssh-filter-signers
                     signers
                     (ssh-client-pubkey-accepted-algorithms client)
                     :minimum-rsa-size (ssh-client-required-rsa-size client))))
       (if (and (null signers)
                (null (ssh-client-hostbased-key client))
                (null (ssh-client-password-callback client))
                (null (ssh-client-kbd-interactive-callback client)))
           (ssh-client-fail
            client
            (make-condition
             'ssh-authentication-error
             :detail "no key matches PubkeyAcceptedAlgorithms or RequiredRSASize"))
           (progn
             (setf (ssh-client-signers client) signers)
             (ssh-open-connection client)))))
   (lambda (condition)
     (if (or (ssh-client-hostbased-key client)
             (ssh-client-password-callback client)
             (ssh-client-kbd-interactive-callback client))
         (ssh-open-connection client)
         (ssh-client-fail client condition)))
   :add-keys-to-agent
   (eq (ssh-client-add-keys-to-agent client) :yes)
   :certificate-files (ssh-client-certificate-files client))
  client)

(defun make-ssh-client (host &key connect-host host-key-host (port 22) connect-port
                             (user (ssh-default-user)) private-key agent
                             passphrase known-hosts (host-key-policy :strict)
                             host-key-callback connect-timeout
                             server-alive-interval (server-alive-count-max 3)
                             proxy-command
                             proxy-use-fdpass
                             bind-address
                             bind-interface
                             address-family
                             forward-agent
                             forward-agent-sock-path
                             forward-x11
                             forward-x11-trusted
                             forward-x11-timeout
                             xauth-location
                             kex-algorithms host-key-algorithms
                             ciphers macs pubkey-accepted-algorithms
                             ca-signature-algorithms
                             (revoked-host-keys '())
                             hash-known-hosts
                             known-hosts-command
                             (add-keys-to-agent :no)
                             (certificate-files '())
                             no-host-authentication-for-localhost
                             host-key-alias
                             batch-mode
                             (warn-weak-crypto t)
                             (obscure-keystroke-timing
                              +ssh-keystroke-default-interval-ms+)
                             channel-timeouts
                             rekey-limit rekey-interval
                             version-addendum
                             hostbased-authentication
                             hostbased-accepted-algorithms
                             (hostbased-keys '())
                             (password-authentication t)
                             (kbd-interactive-authentication t)
                             number-of-password-prompts
                             preferred-authentications
                             (pubkey-authentication t)
                             password-callback
                             kbd-interactive-callback
                             (canonicalize-hostname :no)
                             (canonical-domains '())
                             (canonicalize-max-dots 1)
                             (canonicalize-fallback-local t)
                             resolver
                             (update-host-keys :yes)
                             (fingerprint-hash :sha256)
                             visual-host-key
                             check-host-ip
                             (verify-host-key-dns :no)
                             (host-key-dns-resolver #'ssh-dns-resolve-sshfp)
                             (ip-qos-interactive #xb8)
                             (ip-qos-bulk :none)
                             (tcp-keep-alive t)
                             set-env
                             (connection-attempts 1)
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
PROXY-USE-FDPASS, when true with PROXY-COMMAND, instead has the helper
connect the socket and send its descriptor back over the pair, as
ProxyUseFdpass does; a helper that exits without sending one fails the
connection rather than falling back to a direct dial.

BIND-ADDRESS is a local address a direct connection is made from, as
ssh_config's BindAddress and ssh -b; BIND-INTERFACE names an interface
instead, and BIND-ADDRESS wins when both are set, as in ssh.  A ProxyCommand
carries the stream itself, so neither applies there.

ADDRESS-FAMILY is NIL for any, or :INET / :INET6 to resolve and dial only
IPv4 or IPv6, as ssh -4, ssh -6 and AddressFamily do.  BURZAY's resolver
specifications - the default, :SYSTEM and :DNS - receive the family, so the
system resolver asks for one family and DNS asks for A or AAAA; a
caller-supplied resolver function keeps its (HOST ON-SUCCESS ON-ERROR)
shape, and its answer is checked against ADDRESS-FAMILY before the
connection is dialled.

FORWARD-AGENT, when true, asks the peer to forward its agent connections,
as ssh -A and ssh_config's ForwardAgent; FORWARD-AGENT-SOCK-PATH names the
agent socket to use instead of SSH_AUTH_SOCK, matching ForwardAgent's path
form.  Each server-initiated agent channel is dialled to that socket and
relayed.  With no usable agent socket the request is skipped, as ssh's
check_agent_present clears it.

FORWARD-X11, when true, asks the peer to forward X11 connections, as ssh -X
and ssh_config's ForwardX11; FORWARD-X11-TRUSTED allows forwarding without a
cookie in the user's Xauthority, as ssh -Y does, and FORWARD-X11-TIMEOUT is
how many seconds after authentication untrusted forwarding may still open an
x11 channel (0 for no limit, NIL for OpenSSH's 1200-second default; trusted
forwarding never expires).  The real MIT-MAGIC-COOKIE-1 never leaves the
client: x11-req carries a fake one, and each x11 channel's first message has
it replaced.  This client has no X Security extension, so -X cannot create
the weaker untrusted cookie sshd's -X would; the forwarded display has the
same access as the local session.  XAUTH-LOCATION is accepted for ssh_config
parity; cookies are read from $XAUTHORITY or ~/.Xauthority directly.

PASSWORD-AUTHENTICATION and KBD-INTERACTIVE-AUTHENTICATION default to true,
as ssh_config does.  PASSWORD-CALLBACK is a function of (CLIENT PROMPT)
returning the password to send, or NIL to skip the method; the prompt is
already formatted as ssh's.  KBD-INTERACTIVE-CALLBACK is a function of
(CLIENT NAME INSTRUCTION PROMPTS), each prompt being (TEXT ECHO-P), returning
one answer per prompt or NIL to cancel.  NUMBER-OF-PASSWORD-PROMPTS bounds
the password attempts (default 3), and PREFERRED-AUTHENTICATIONS orders the
methods the server offers.  BatchMode suppresses both methods without calling
their callbacks, as ssh does.

Keys: PRIVATE-KEY is an ssh-private-key or a path, and PASSPHRASE decrypts a
protected file.  With no PRIVATE-KEY every default identity file that exists
(~/.ssh/id_ed25519, id_ecdsa, then ~/.ssh/id_rsa) is added.  AGENT (T for
SSH_AUTH_SOCK, or a socket path) offers every key the agent can sign with;
when both are available the agent's keys are tried first, as OpenSSH does.
CERTIFICATE-FILES lists user certificate files; each is offered with the
private key it certifies, and naming one stops the KEY-cert.pub automatic
lookup, as in ssh.
The default known-hosts file is ~/.ssh/known_hosts.

NO-HOST-AUTHENTICATION-FOR-LOCALHOST, when true, accepts a loopback peer's
host key without consulting known_hosts and without recording it, unless
HOST-KEY-ALIAS names the host.

CONNECT-TIMEOUT, when positive, fails the client if it has not authenticated
within that many seconds.  SERVER-ALIVE-INTERVAL, when positive, sends
keepalive@openssh.com every interval seconds and fails the client after
SERVER-ALIVE-COUNT-MAX unanswered intervals (default 3).

HOST-KEY-POLICY is :STRICT, :ACCEPT-NEW, :INSECURE, or a function of
(CLIENT FINGERPRINT KEY-BLOB) that returns true to trust and record an
unknown key; HOST-KEY-CALLBACK is the same function under a clearer name.
BATCH-MODE, when true, never asks: an unknown host key fails even when a
confirmation callback was supplied.  WARN-WEAK-CRYPTO, on by default, shows
OpenSSH 10.6's post-quantum notice after the initial key exchange when it used
no post-quantum algorithm and KexAlgorithms was left at its default.
OBSCURE-KEYSTROKE-TIMING is the number of milliseconds between quantised
keystrokes on a pty, or 0 to send each keystroke as it arrives; the
application applies it because it owns stdin.
VERSION-ADDENDUM is appended after a space to the identification string,
matching sshd's VersionAddendum.

CHANNEL-TIMEOUTS is a list of (PATTERN . SECONDS) pairs, as ssh_config's
ChannelTimeout: a channel that matches PATTERN and sees no traffic for
SECONDS is closed, and the pattern \"global\" closes every channel once none
of them has been used for that long.

VERIFY-HOST-KEY-DNS is :NO, :YES or :ASK.  With :YES, a matching SSHFP record
whose answer carries the DNSSEC authenticated-data bit trusts the host key
without known_hosts; :ASK looks the records up but never accepts on its own.
HOST-KEY-DNS-RESOLVER, when given, is a function of (HOST ON-SUCCESS
ON-ERROR); ON-SUCCESS receives the record list and the DNSSEC flag, and the
default resolver queries the system nameserver through CL-PNET-DNS.

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
                           :known-hosts-command known-hosts-command
                           :add-keys-to-agent add-keys-to-agent
                           :certificate-files certificate-files
                           :no-host-authentication-for-localhost
                           no-host-authentication-for-localhost
                           :host-key-alias host-key-alias
                           :batch-mode batch-mode
                           :warn-weak-crypto warn-weak-crypto
                           :obscure-keystroke-timing
                           obscure-keystroke-timing
                           :channel-timeouts channel-timeouts
                           :rekey-limit rekey-limit
                           :rekey-interval rekey-interval
                           :version-addendum version-addendum
                           :hostbased-authentication hostbased-authentication
                           :hostbased-accepted-algorithms
                           hostbased-accepted-algorithms
                           :hostbased-keys hostbased-keys
                           :password-authentication password-authentication
                           :kbd-interactive-authentication
                           kbd-interactive-authentication
                           :number-of-password-prompts
                           number-of-password-prompts
                           :preferred-authentications
                           preferred-authentications
                           :pubkey-authentication pubkey-authentication
                           :password-callback password-callback
                           :kbd-interactive-callback
                           kbd-interactive-callback
                           :canonicalize-hostname canonicalize-hostname
                           :canonical-domains canonical-domains
                           :canonicalize-max-dots canonicalize-max-dots
                           :canonicalize-fallback-local
                           canonicalize-fallback-local
                           :resolver resolver
                           :update-host-keys update-host-keys
                           :fingerprint-hash fingerprint-hash
                           :visual-host-key visual-host-key
                           :check-host-ip check-host-ip
                           :verify-host-key-dns verify-host-key-dns
                           :host-key-dns-resolver host-key-dns-resolver
                           :ip-qos-interactive ip-qos-interactive
                           :ip-qos-bulk ip-qos-bulk
                           :tcp-keep-alive tcp-keep-alive
                           :set-env set-env
                           :connection-attempts connection-attempts
                           :required-rsa-size required-rsa-size
                           :proxy-use-fdpass proxy-use-fdpass
                           :bind-address bind-address
                           :bind-interface bind-interface
                           :address-family address-family
                           :forward-agent forward-agent
                           :forward-agent-sock-path forward-agent-sock-path
                           :forward-x11 forward-x11
                           :forward-x11-trusted forward-x11-trusted
                           :forward-x11-timeout forward-x11-timeout
                           :xauth-location xauth-location)
   private-key agent passphrase))

(defun ssh-client-close (client)
  "Close CLIENT and report every open channel as closed."
  (ssh-client-send-disconnect client)
  (ssh-client-finish client :client-closed :close)
  client)

(defun ssh-client-host-key-fingerprint (client)
  "The fingerprint of the key the server presented, once the KEX has seen it."
  (let ((blob (ssh-client-host-key-blob client)))
    (and blob (ssh-key-fingerprint
               blob (ssh-client-fingerprint-hash client)))))

(defun ssh-client-feature-supported-p (feature)
  "Whether the pure transport can honour FEATURE.

Applications ask this through CL-PNET-SSH instead of testing which backend
was built, so the same client code runs unchanged against either transport."
  (not (null (member feature '(:remote-forward :streamlocal-forward
                               :x11-forward :hostbased-authentication
                               :version-addendum :agent-forward)))))

(defun ssh-client-supported-authentication-methods ()
  "The client authentication method names the pure transport implements."
  '("publickey" "hostbased" "keyboard-interactive" "password"))
