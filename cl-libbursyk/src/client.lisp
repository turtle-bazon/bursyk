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

(defun ssh-canonicalize-candidates (client)
  "The names CanonicalDomains adds to CONNECT-HOST, or NIL to skip."
  (let ((mode (ssh-client-canonicalize-hostname client))
        (host (ssh-client-connect-host client)))
    (when (and (member mode '(:yes :always))
               (or (eq mode :always)
                   (null (ssh-client-proxy-command client)))
               (or (eq mode :always)
                   (<= (count #\. host)
                       (ssh-client-canonicalize-max-dots client))))
      (mapcar (lambda (domain)
                (if (zerop (length domain))
                    (concatenate 'string host ".")
                    (format nil "~A.~A" host domain)))
              (ssh-client-canonical-domains client)))))

(defun ssh-client-dns-host (client)
  "The name SSHFP records are looked up under."
  (or (ssh-client-host-key-host client) (ssh-client-host client)))

(defun ssh-client-host-key-dns-needed-p (client)
  "Whether CLIENT should look up SSHFP records before connecting."
  (let ((host (ssh-client-dns-host client)))
    (and (null (ssh-client-host-key-dns-queried client))
         (member (ssh-client-verify-host-key-dns client) '(:yes :ask))
         (ssh-client-host-key-dns-resolver client)
         host
         (not (burzay:numeric-address-p host)))))

(defun ssh-client-query-host-key-dns (client done)
  "Ask for CLIENT's SSHFP records, then call DONE.

The query runs on the event loop.  Any failure is only logged and DONE runs
anyway: VerifyHostKeyDNS supplements known_hosts and must not turn a DNS
outage into a refusal to connect."
  (setf (ssh-client-host-key-dns-queried client) t)
  (handler-case
      (funcall (ssh-client-host-key-dns-resolver client)
               (ssh-client-dns-host client)
               (lambda (records secure)
                 (unless (ssh-client-closed-p client)
                   (setf (ssh-client-host-key-dns-records client) records
                         (ssh-client-host-key-dns-secure client) secure)
                   (when records
                     (ssh-log "found ~D SSHFP record~:P for ~A~:[ (insecure)~;~]"
                              (length records) (ssh-client-dns-host client)
                              secure))
                   (funcall done)))
               (lambda (condition)
                 (unless (ssh-client-closed-p client)
                   (ssh-log "SSHFP lookup failed: ~A" condition)
                   (funcall done))))
    (error (condition)
      (ssh-log "SSHFP lookup failed: ~A" condition)
      (funcall done))))

(defun ssh-open-connection (client)
  "Look up SSHFP records, then open CLIENT's transport.

Returns CLIENT at once; the connection and every failure report through the
client's callbacks."
  (if (ssh-client-host-key-dns-needed-p client)
      (ssh-client-query-host-key-dns
       client (lambda () (ssh-open-transport client)))
      (ssh-open-transport client))
  client)

(defun ssh-open-transport (client)
  "Resolve CONNECT-HOST without blocking the loop, then dial it.

CL-PNET's connect takes a numeric address, so a name has to be resolved
first, and BURZAY does that on a worker thread.  CanonicalDomains candidates
are tried before the name itself.  A ProxyCommand needs none of that: the
helper is what reaches the server."
  (if (ssh-client-proxy-command client)
      (ssh-open-proxy-connection client)
      (let ((resolve (or (ssh-client-resolver client) #'burzay:resolve-host))
            (original (ssh-client-connect-host client)))
        (labels ((dial (name)
                   (lambda (address)
                     (setf (ssh-client-connect-host client) name)
                     (ssh-dial client address)))
                 (try (names)
                   (if names
                       (progn
                         (ssh-log "resolving ~A" (first names))
                         (funcall resolve (first names)
                                  (dial (first names))
                                  (lambda (condition)
                                    (declare (ignore condition))
                                    (try (rest names)))))
                       (if (ssh-client-canonicalize-fallback-local client)
                           (progn
                             (ssh-log "resolving ~A" original)
                             (funcall resolve original (dial original)
                                      (lambda (condition)
                                        (ssh-resolution-error
                                         client condition))))
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
                  (funcall resolve original (dial original)
                           (lambda (condition)
                             (ssh-resolution-error client condition))))))))))

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
                                 version-addendum
                                 hostbased-authentication
                                 hostbased-accepted-algorithms
                                 (hostbased-keys '())
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
                                 proxy-use-fdpass)
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
                    :version-addendum
                    (and version-addendum
                         (not (eq version-addendum :none))
                         (check-version-addendum version-addendum))
                    :hostbased-authentication hostbased-authentication
                    :hostbased-accepted-algorithms
                    hostbased-accepted-algorithms
                    :hostbased-keys hostbased-keys
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
                (null (ssh-client-hostbased-key client)))
           (ssh-client-fail
            client
            (make-condition
             'ssh-authentication-error
             :detail "no key matches PubkeyAcceptedAlgorithms or RequiredRSASize"))
           (progn
             (setf (ssh-client-signers client) signers)
             (ssh-open-connection client)))))
   (lambda (condition)
     (if (ssh-client-hostbased-key client)
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
                             version-addendum
                             hostbased-authentication
                             hostbased-accepted-algorithms
                             (hostbased-keys '())
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
                           :version-addendum version-addendum
                           :hostbased-authentication hostbased-authentication
                           :hostbased-accepted-algorithms
                           hostbased-accepted-algorithms
                           :hostbased-keys hostbased-keys
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
                           :proxy-use-fdpass proxy-use-fdpass)
   private-key agent passphrase))

(defun ssh-client-close (client)
  "Close CLIENT and report every open channel as closed."
  (ssh-client-send-disconnect client)
  (ssh-client-finish client :client-closed :close)
  client)

(defun ssh-client-host-key-randomart (client)
  "The randomart picture of CLIENT's host key, once KEX has seen it."
  (let ((blob (ssh-client-host-key-blob client)))
    (and blob (ssh-key-randomart
               blob (ssh-client-fingerprint-hash client)))))

(defun ssh-client-host-key-fingerprint (client)
  "The fingerprint of the key the server presented, once the KEX has seen it."
  (let ((blob (ssh-client-host-key-blob client)))
    (and blob (ssh-key-fingerprint
               blob (ssh-client-fingerprint-hash client)))))
