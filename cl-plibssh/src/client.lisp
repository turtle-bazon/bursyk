(in-package #:cl-pnet-ssh)

;;;; The libssh client role.  The session is put in non-blocking mode from the
;;;; first byte, and every libssh call is retried from the event loop: a call
;;;; that would wait returns SSH_AGAIN and the descriptor watch comes back when
;;;; the socket moves.  Name resolution happens off the loop through
;;;; BURZAY and the TCP connection is made here, because libssh's
;;;; SSH_OPTIONS_HOST path would call getaddrinfo on this thread.

(defconstant +ssh-eof+ -127)

;;; EINPROGRESS and friends; connect(2) says "wait for writability" this way.
(defparameter *connect-pending-errno* '(36 37 114 115))

;;; ---- Small helpers ----

(defun ssh-plibssh-close-fd (fd)
  (when (and fd (not (minusp fd)))
    (cl-pnet-sockets:c-close fd)))

(defun ssh-client-transport-fd (client)
  "The descriptor carrying CLIENT's stream, or NIL.

A ProxyCommand hands libssh a pipe and CLIENT never holds the descriptor, so
per-socket options such as IPQoS have nothing to act on there."
  (let ((fd (ssh-client-fd client)))
    (and fd (not (minusp fd)) fd)))

(defun ssh-plibssh-verify-host-key (client)
  "Apply CLIENT's host-key policy to the key the server presented, or signal.

The policy itself is CLIENT-POLICY's, shared with the pure backend, so
known_hosts markers, RevokedHostKeys, RequiredRSASize, SSHFP records and
NoHostAuthenticationForLocalhost decide identically on either transport."
  (let ((blob (ssh-plibssh-server-key-blob client)))
    (unless blob
      (error 'ssh-host-key-error
             :detail "the server did not present a host key"))
    (setf (ssh-client-host-key-blob client) blob)
    (ssh-client-verify-host-key client blob)))

(defun ssh-client-send-chaff-packet (client)
  "Put one decoy packet on the wire while the session is idle."
  (let ((session (ssh-client-session client)))
    (when session
      (ssh-send-ignore session "chaff"))))

(defun ssh-plibssh-server-key-blob (client)
  "The host key CLIENT's server presented, as the SSH wire blob."
  (cffi:with-foreign-object (pointer :pointer)
    (when (zerop (ssh-get-server-publickey (ssh-client-session client) pointer))
      (let ((key (cffi:mem-ref pointer :pointer)))
        (unwind-protect
             (ssh-plibssh-public-key-blob key)
          (ssh-key-free key))))))

;;; ---- TCP connection ----

(defun ssh-plibssh-client-connect-failed (client errno)
  (ssh-client-fail
   client
   (make-condition 'ssh-connection-error
                   :detail (format nil "could not connect to ~A:~D (~A)"
                                   (ssh-client-connect-host client)
                                   (or (ssh-client-connect-port client)
                                       (ssh-client-port client))
                                   (cl-pnet-sockets:c-strerror errno)))))

(defun ssh-plibssh-client-check-connect (client)
  "The connect socket is writable: see whether the kernel connected it."
  (multiple-value-bind (errno answered) (cl-pnet-sockets:socket-error
                                         (ssh-client-fd client))
    (cond
      ((not answered) (ssh-plibssh-client-connect-failed
                       client (cl-pnet-sockets:c-errno)))
      ((zerop errno) (ssh-plibssh-client-tcp-connected client))
      (t (ssh-plibssh-client-connect-failed client errno)))))

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

(defun ssh-plibssh-client-bind-failed (client errno)
  "Report a source address the kernel refused."
  (ssh-client-fail
   client
   (make-condition
    'ssh-connection-error
    :detail
    (format nil "could not bind ~A for ~A:~D (~A)"
            (let ((address (or (ssh-client-bind-address-resolved client)
                               (ssh-client-bind-address client))))
              (or address
                  (format nil "interface ~A"
                          (ssh-client-bind-interface client))))
            (ssh-client-connect-host client)
            (or (ssh-client-connect-port client) (ssh-client-port client))
            (cl-pnet-sockets:c-strerror errno)))))

(defun ssh-plibssh-client-start-tcp (client address)
  "Open a non-blocking TCP connection to ADDRESS for CLIENT.

The descriptor is made here rather than by libssh so BindAddress and
BindInterface reach the socket before connect(2), exactly as the pure
backend does; the connected descriptor is then handed to libssh."
  (setf (ssh-client-remote-address client) address)
  (let ((port (or (ssh-client-connect-port client) (ssh-client-port client)))
        (bind (or (ssh-client-bind-address-resolved client)
                  (ssh-client-bind-address client)))
        (interface (ssh-client-bind-interface client)))
    (ssh-log "connecting to ~A:~D~@[ bound to ~A~]"
             address port
             (and (or bind interface)
                  (or bind (format nil "interface ~A" interface))))
    (multiple-value-bind (fd state errno stage)
        (cl-pnet-sockets:connect-tcp address port
                                     :bind-address bind
                                     :bind-interface interface)
      (cond
        ((null fd)
         (if (eq stage :connect)
             (ssh-plibssh-client-connect-failed client errno)
             (ssh-plibssh-client-bind-failed client errno)))
        ((eq state :connected)
         (ssh-plibssh-client-take-fd client fd))
        (t
         (setf (ssh-client-fd client) fd
               (ssh-client-watcher client)
               (cl-pnet:fd-watch
                fd
                :on-writable
                (lambda (watcher)
                  (declare (ignore watcher))
                  (ssh-plibssh-client-check-connect client))))))))
  client)

(defun ssh-plibssh-client-dial (client address)
  "Dial ADDRESS, resolving CLIENT's BindAddress first when it is a name."
  (if (and (or (ssh-client-bind-address client)
               (ssh-client-bind-interface client))
           (not (ssh-client-bind-address-resolved-p client address)))
      (ssh-client-resolve-bind-address
       client address (lambda () (ssh-plibssh-client-start-tcp client address)))
      (ssh-plibssh-client-start-tcp client address))
  client)

(defun ssh-plibssh-client-open-direct (client)
  "Resolve CONNECT-HOST for CLIENT and dial it, honouring CanonicalDomains."
  (let ((original (ssh-client-connect-host client)))
    (labels ((dial (name on-failure)
               ;; NAME becomes CONNECT-HOST before the family check, so an
               ;; error names the candidate that actually resolved badly.
               (lambda (address)
                 (setf (ssh-client-connect-host client) name)
                 (if (ssh-client-address-in-family-p client address)
                     (ssh-plibssh-client-dial client address)
                     (funcall
                      on-failure
                      (make-condition
                       'ssh-connection-error
                       :detail (format nil "~A is not an ~A address"
                                       address
                                       (ssh-client-address-family-name client)))))))
             (try (names)
               (if names
                   (let ((next (lambda (condition)
                                 (declare (ignore condition))
                                 (try (rest names)))))
                     (ssh-log "resolving ~A" (first names))
                     (ssh-client-resolve-host
                      client (first names) (dial (first names) next) next))
                   (if (ssh-client-canonicalize-fallback-local client)
                       (progn
                         (ssh-log "resolving ~A" original)
                         (ssh-client-resolve-host
                          client original
                          (dial original
                                (lambda (condition)
                                  (ssh-client-fail
                                   client
                                   (make-condition
                                    'ssh-connection-error
                                    :detail (format nil "could not resolve ~A: ~A"
                                                    original condition)))))
                          (lambda (condition)
                            (ssh-client-fail
                             client
                             (make-condition
                              'ssh-connection-error
                              :detail (format nil "could not resolve ~A: ~A"
                                              original condition))))))
                       (ssh-client-fail
                        client
                        (make-condition
                         'ssh-connection-error
                         :detail
                         (format nil "no CanonicalDomains candidate resolved ~A"
                                 original)))))))
      (let ((candidates (ssh-canonicalize-candidates client)))
        (if candidates
            (try candidates)
            (progn
              (ssh-log "resolving ~A" original)
              (ssh-client-resolve-host
               client original
               (dial original
                     (lambda (condition)
                       (ssh-client-fail
                        client
                        (make-condition
                         'ssh-connection-error
                         :detail (format nil "could not resolve ~A: ~A"
                                         original condition)))))
               (lambda (condition)
                 (ssh-client-fail
                  client
                  (make-condition
                   'ssh-connection-error
                   :detail (format nil "could not resolve ~A: ~A"
                                   original condition))))))))))
  client)

(defun ssh-plibssh-client-open (client)
  "Look up SSHFP records when needed, then open CLIENT's transport."
  (labels ((proceed ()
             (if (ssh-client-proxy-command client)
                 (ssh-plibssh-client-start-proxy client)
                 (ssh-plibssh-client-open-direct client))))
    (if (ssh-client-host-key-dns-needed-p client)
        (ssh-client-query-host-key-dns client #'proceed)
        (proceed)))
  client)


(defun ssh-plibssh-client-take-fd (client fd)
  "CLIENT's TCP connection is FD: hand it to a session and start SSH."
  (setf (ssh-client-fd client) fd)
  (ssh-plibssh-client-tcp-connected client))

(defun ssh-plibssh-apply-algorithm-option (session code names option)
  "Ask libssh to offer NAMES for OPTION, or keep its defaults when NIL.

NAMES is already this build's resolved list, so libssh naming one it cannot
use is a real mismatch: report it rather than let libssh quietly fall back
to its wider default, which is exactly the silent widening ssh_config is
meant to prevent."
  (when names
    (let ((text (format nil "~{~A~^,~}" names)))
      (when (minusp (ssh-plibssh-set-string-option session code text))
        (error 'ssh-connection-error
               :detail (format nil "libssh rejected ~A ~A: ~A"
                               option text
                               (ssh-plibssh-error session))))))
  session)

(defun ssh-plibssh-client-new-session (client &key fd proxy-command)
  "Make CLIENT's libssh session.

FD is an already-connected socket to hand over.  PROXY-COMMAND instead asks
libssh to start the helper and run the protocol on its socketpair, so the
host is named but no descriptor is passed: libssh dials nothing itself."
  (let ((session (ssh-new)))
    (when (ssh-plibssh-null-p session)
      (error 'ssh-connection-error :detail "could not allocate a libssh session"))
    (setf (ssh-client-session client) session)
    (ssh-plibssh-register-session session client)
    ;; This library owns ~/.ssh/config; libssh must not read it again behind
    ;; the caller's back, nor dial from the options it would add.
    (when (minusp (ssh-plibssh-set-int-option
                   session +ssh-options-process-config+ 0))
      (error 'ssh-connection-error
             :detail (format nil "libssh rejected the config flag: ~A"
                             (ssh-plibssh-error session))))
    (when (minusp (ssh-plibssh-set-string-option
                   session +ssh-options-host+
                   (ssh-client-connect-host client)))
      (error 'ssh-connection-error
             :detail (format nil "libssh rejected the host: ~A"
                             (ssh-plibssh-error session))))
    (when (minusp (ssh-plibssh-set-int-option
                   session +ssh-options-port+
                   (or (ssh-client-connect-port client)
                       (ssh-client-port client))))
      (error 'ssh-connection-error
             :detail (format nil "libssh rejected the port: ~A"
                             (ssh-plibssh-error session))))
    (when (ssh-client-user client)
      (ssh-plibssh-set-string-option session +ssh-options-user+
                                     (ssh-client-user client)))
    ;; ssh_config's algorithm choices reach libssh here.  Each direction
    ;; gets the same list, as OpenSSH uses one preference order both ways.
    (ssh-plibssh-apply-algorithm-option
     session +ssh-options-ciphers-c-s+ (ssh-client-ciphers client) "Ciphers")
    (ssh-plibssh-apply-algorithm-option
     session +ssh-options-ciphers-s-c+ (ssh-client-ciphers client) "Ciphers")
    (ssh-plibssh-apply-algorithm-option
     session +ssh-options-hmac-c-s+ (ssh-client-macs client) "MACs")
    (ssh-plibssh-apply-algorithm-option
     session +ssh-options-hmac-s-c+ (ssh-client-macs client) "MACs")
    ;; Compression is delayed: libssh offers the OpenSSH name and starts the
    ;; stream after authentication, matching the pure transport.  This list is
    ;; what "Compression yes" sets internally; libssh's default leaves
    ;; compression off unless the server insists.
    (when (ssh-client-compression client)
      (dolist (code (list +ssh-options-compression-c-s+
                          +ssh-options-compression-s-c+))
        (when (minusp (ssh-plibssh-set-string-option
                       session code "zlib@openssh.com,none"))
          (error 'ssh-connection-error
                 :detail (format nil "libssh rejected Compression: ~A"
                                 (ssh-plibssh-error session))))))
    (ssh-plibssh-apply-algorithm-option
     session +ssh-options-key-exchange+ (ssh-client-kex-algorithms client)
     "KexAlgorithms")
    (ssh-plibssh-apply-algorithm-option
     session +ssh-options-hostkeys+ (ssh-client-host-key-algorithms client)
     "HostKeyAlgorithms")
    (ssh-plibssh-apply-algorithm-option
     session +ssh-options-publickey-accepted-types+
     (ssh-client-pubkey-accepted-algorithms client)
     "PubkeyAcceptedAlgorithms")
    (when (and (ssh-client-agent client)
               (not (eq (ssh-client-agent client) t)))
      (ssh-plibssh-set-string-option session +ssh-options-identity-agent+
                                     (ssh-client-agent client)))
    (when proxy-command
      (when (minusp (ssh-plibssh-set-string-option
                     session +ssh-options-proxy-command+ proxy-command))
        (error 'ssh-connection-error
               :detail (format nil "libssh rejected the ProxyCommand: ~A"
                               (ssh-plibssh-error session)))))
    ;; RekeyLimit uses OpenSSH's meaning: the byte volume that forces a
    ;; rekey, plus an optional interval.  Zero leaves libssh's own default.
    (when (and (ssh-client-rekey-limit client)
               (plusp (ssh-client-rekey-limit client)))
      (when (minusp (ssh-plibssh-set-u64-option
                     session +ssh-options-rekey-data+
                     (ssh-client-rekey-limit client)))
        (error 'ssh-connection-error
               :detail (format nil "libssh rejected RekeyLimit: ~A"
                               (ssh-plibssh-error session)))))
    (when (and (ssh-client-rekey-interval client)
               (plusp (ssh-client-rekey-interval client)))
      (when (minusp (ssh-plibssh-set-u32-option
                     session +ssh-options-rekey-time+
                     (ssh-client-rekey-interval client)))
        (error 'ssh-connection-error
               :detail (format nil "libssh rejected RekeyInterval: ~A"
                               (ssh-plibssh-error session)))))
    (when fd
      (cffi:with-foreign-object (pointer :int)
        (setf (cffi:mem-ref pointer :int) fd)
        (when (minusp (ssh-options-set session +ssh-options-fd+ pointer))
          (error 'ssh-connection-error
                 :detail (format nil "libssh rejected the socket: ~A"
                                 (ssh-plibssh-error session))))))
    (ssh-set-blocking session 0)
    session))

(defun ssh-plibssh-client-tcp-connected (client)
  "The TCP connection is up: watch it and begin the SSH handshake."
  (let ((fd (ssh-client-fd client)))
    (unless (ssh-client-session client)
      (ssh-plibssh-client-new-session client :fd (ssh-client-fd client)))
    (when (ssh-client-watcher client)
      (let ((watcher (ssh-client-watcher client)))
        (setf (ssh-client-watcher client) nil)
        (cl-pnet:fd-unwatch watcher)))
    (setf (ssh-client-phase client) :kex
          (ssh-client-watcher client)
          (cl-pnet:fd-watch
           fd
           :on-readable
           (lambda (watcher)
             (declare (ignore watcher))
             ;; Bytes arrived, which is the proof of life a keepalive is
             ;; looking for even when libssh consumes the reply internally.
             (setf (ssh-client-alive-misses client) 0)
             (ssh-plibssh-client-pump client))))
    ;; The session type is not known yet; the application raises this to the
    ;; interactive value once it decides whether to request a pty, exactly as
    ;; the pure backend does.
    (ssh-client-set-ip-qos client nil)
    (ssh-plibssh-client-pump client)
    client))

;;; ---- Session pump ----

(defun ssh-plibssh-client-write-descriptor (client)
  "CLIENT's descriptor for the writable watcher, duplicated on first use."
  (or (ssh-client-write-fd client)
      (setf (ssh-client-write-fd client)
            (ssh-plibssh-dup-fd (ssh-client-fd client)))))

(defun ssh-plibssh-client-sync-watchers (client)
  "Arm the write watch exactly when libssh is waiting to send."
  (let ((watcher (ssh-client-write-watcher client))
        (session (ssh-client-session client))
        (fd (ssh-client-fd client)))
    (if (and session fd (not (ssh-client-closed client))
             (logtest (ssh-get-poll-flags session) +ssh-write-pending+))
        (unless watcher
          (setf (ssh-client-write-watcher client)
                (cl-pnet:fd-watch
                 (ssh-plibssh-client-write-descriptor client)
                 :on-writable
                 (lambda (watcher)
                   (declare (ignore watcher))
                   (ssh-plibssh-client-pump client)))))
        (when watcher
          (setf (ssh-client-write-watcher client) nil)
          (cl-pnet:fd-unwatch watcher)))))

(defun ssh-plibssh-start-alive-timer (client)
  "Start the ServerAliveInterval timer once CLIENT can carry channels.

libssh consumes the keepalive reply itself, so the timer treats a readable
socket in the interval as the proof of life OpenSSH looks for."
  (when (and (ssh-client-server-alive-interval client)
             (plusp (ssh-client-server-alive-interval client))
             (not (ssh-client-alive-timer client)))
    (setf (ssh-client-alive-timer client)
          (cl-pnet:timer-start
           (ssh-client-server-alive-interval client)
           (ssh-client-server-alive-interval client)
           (lambda ()
             (when (and (not (ssh-client-closed client))
                        (eq (ssh-client-phase client) :ready))
               (incf (ssh-client-alive-misses client))
               (let ((count-max (or (ssh-client-server-alive-count-max
                                     client)
                                    3)))
                 (if (and (plusp count-max)
                          (> (ssh-client-alive-misses client) count-max))
                     (ssh-client-fail
                      client
                      (make-condition
                       'ssh-connection-error
                       :detail (format nil "server ~A stopped responding"
                                       (ssh-client-host client))))
                     (let ((session (ssh-client-session client)))
                       (when session
                         (ssh-send-keepalive session)
                         ;; libssh may only buffer the request; arm the
                         ;; write watch so the event loop actually flushes it.
                         (ssh-plibssh-client-sync-watchers client)))))))))))

(defun ssh-plibssh-client-pump (client)
  "Advance CLIENT's state machine as far as the socket allows."
  (when (and (ssh-client-session client)
             (not (ssh-client-closed client)))
    (handler-case
        (progn
          (ecase (ssh-client-phase client)
            (:kex (ssh-plibssh-client-drive-connect client))
            (:auth (ssh-plibssh-client-drive-auth client))
            (:ready (ssh-plibssh-client-drive-ready client))
            (:connecting nil)
            (:closed nil))
          (ssh-plibssh-client-sync-watchers client))
      (error (condition) (ssh-client-fail client condition)))))

(defun ssh-plibssh-client-drive-connect (client)
  "Run SSH-CONNECT until the handshake completes."
  (let ((rc (ssh-connect (ssh-client-session client))))
    (cond
      ((zerop rc)
       (setf (ssh-client-server-version client)
             (ssh-get-serverbanner (ssh-client-session client)))
       (ssh-plibssh-verify-host-key client)
       (setf (ssh-client-phase client) :auth)
       (ssh-plibssh-client-drive-auth client))
      ((= rc +ssh-again+) nil)
      (t
       (error 'ssh-connection-error
              :detail (format nil "SSH handshake failed: ~A"
                              (ssh-plibssh-error (ssh-client-session client))))))))

;;; ---- Authentication ----

(defun ssh-plibssh-default-key-paths ()
  "The default identity files that exist, in the order OpenSSH offers them."
  (iter (for name in '("id_ed25519" "id_ecdsa" "id_rsa"))
    (let ((path (merge-pathnames (format nil ".ssh/~A" name)
                                 (user-homedir-pathname))))
      (when (probe-file path) (collect path)))))

(defun ssh-plibssh-default-key-path ()
  "The first default identity file that exists, or NIL."
  (first (ssh-plibssh-default-key-paths)))

(defun ssh-plibssh-key-path (key)
  (if (typep key 'ssh-private-key)
      (ssh-private-key-path key)
      key))

(defun ssh-plibssh-copy-certificate (key certificate-path)
  "Attach CERTIFICATE-PATH's certificate to the imported libssh KEY."
  (cffi:with-foreign-object (pointer :pointer)
    (if (zerop (ssh-pki-import-cert-file
                (namestring certificate-path) pointer))
        (let ((certificate-key (cffi:mem-ref pointer :pointer)))
          (unwind-protect
               (unless (zerop (ssh-pki-copy-cert-to-privkey
                               certificate-key key))
                 (error 'ssh-authentication-error
                        :detail
                        (format nil
                                "could not attach certificate ~A"
                                certificate-path)))
            (ssh-key-free certificate-key)))
        (error 'ssh-authentication-error
               :detail (format nil "could not load certificate ~A"
                               certificate-path))))
  key)

(defun ssh-plibssh-attach-certificate (key path)
  "Attach PATH's -cert.pub to the imported KEY when one exists.

libssh offers whatever key it is given, so a certificate has to be copied
onto the private key first.  The certificate is parsed here to check that it
certifies KEY itself: libssh copies without that check, and pairing the wrong
certificate would authenticate as its owner.  A mismatch is an error rather
than a quiet fallback to the plain key, matching ssh."
  (let ((certificate-path
          (concatenate 'string (namestring path) "-cert.pub")))
    (when (probe-file certificate-path)
      (let* ((blob (ssh-public-key-file-blob certificate-path))
             (certificate (and blob (ssh-certificate-parse blob))))
        (unless (and certificate
                     (ssh-octets= (ssh-certificate-plain-blob certificate)
                                  (ssh-plibssh-public-key-blob key)))
          (error 'ssh-authentication-error
                 :detail
                 (format nil
                         "certificate ~A does not match private key ~A"
                         certificate-path path)))
        (ssh-plibssh-copy-certificate key certificate-path)))
    key))

(defun ssh-plibssh-import-key (path passphrase)
  "Import the private key at PATH, using PASSPHRASE when it is encrypted."
  (cffi:with-foreign-object (pointer :pointer)
    (let ((rc (if passphrase
                  (cffi:with-foreign-string (secret passphrase)
                    (ssh-pki-import-privkey-file
                     (namestring path) secret
                     (cffi:null-pointer) (cffi:null-pointer) pointer))
                  (ssh-pki-import-privkey-file
                   (namestring path) (cffi:null-pointer)
                   (cffi:null-pointer) (cffi:null-pointer) pointer))))
      (if (zerop rc)
          (ssh-plibssh-attach-certificate
           (cffi:mem-ref pointer :pointer) path)
          (error 'ssh-authentication-error
                 :detail (format nil "could not load ~A" path))))))

(defun ssh-plibssh-key-sources (client)
  "The private keys CLIENT may offer, in order.

An explicit PRIVATE-KEY wins; otherwise the default key joins the agent,
which is also what OpenSSH does when both are available.  NIL is valid when
an agent is configured, and an error only when neither source exists."
  (or (let ((source (ssh-client-private-key client)))
        (when source (if (listp source) source (list source))))
      (let ((defaults (ssh-plibssh-default-key-paths)))
        (cond
          (defaults defaults)
          ((ssh-client-agent client) nil)
          (t (error 'ssh-authentication-error
                    :detail (concatenate
                             'string
                             "no key given: pass PRIVATE-KEY or use "
                             ":AGENT, or create ~/.ssh/id_ed25519, id_ecdsa "
                             "or id_rsa")))))))

(defun ssh-plibssh-attach-explicit-certificates (client handles)
  "Attach each CertificateFile to the imported key it certifies.

A bad or non-user certificate is logged and skipped, as ssh does, and a
certificate that matches no imported key is skipped too."
  (dolist (path (ssh-client-certificate-files client))
    (let ((blob (and path (ssh-public-key-file-blob path))))
      (cond
        ((null blob)
         (ssh-log "could not load certificate file ~A" path))
        ((not (ssh-certificate-blob-p blob))
         (ssh-log "~A is not a certificate" path))
        (t
         (let ((certificate (ssh-certificate-parse blob)))
           (cond
             ((null certificate)
              (ssh-log "~A is not a readable certificate" path))
             ((/= (ssh-certificate-cert-type certificate) 1)
              (ssh-log "ignoring certificate ~A: not a user certificate"
                       path))
             (t
              (let ((plain (ssh-certificate-plain-blob certificate)))
                (dolist (key handles)
                  (when (ssh-octets= plain
                                     (ssh-plibssh-public-key-blob key))
                    (ssh-plibssh-copy-certificate key path))))))))))))

(defun ssh-plibssh-load-client-keys (client passphrase)
  "Import every key CLIENT may offer, in order."
  (let ((handles
          (iter (for key in (ssh-plibssh-key-sources client))
            (collect (ssh-plibssh-import-key
                      (or (ssh-plibssh-key-path key)
                          (error 'ssh-authentication-error
                                 :detail
                                 "a private key has no file path libssh can load"))
                      passphrase)))))
    (ssh-plibssh-attach-explicit-certificates client handles)
    (setf (ssh-client-key-handles client) handles
          (ssh-client-key-index client) 0)))

(defun ssh-plibssh-client-agent-pending-p (client)
  "True while the agent has not answered for this connection."
  (and (ssh-client-agent client)
       (not (ssh-client-agent-tried client))))

(defparameter +ssh-client-auth-method-order+
  '("hostbased" "publickey" "keyboard-interactive" "password")
  "Methods to try, in OpenSSH's order, when PreferredAuthentications is unset.

The same list the pure backend uses, so a PreferredAuthentications value
resolves identically on either backend.  Hostbased stays in the order but is
never enabled here: libssh exposes no userauth API for it.")

(defun ssh-client-auth-option-on-p (value)
  "Whether an authentication switch VALUE leaves its method on.

Programs pass T/NIL and the configuration layer passes :YES/:NO, so :NO must
not count as truth."
  (not (or (null value) (eq value :no))))

(defun ssh-client-auth-method-enabled-p (client method)
  "Whether CLIENT may try METHOD.

BatchMode forbids the interactive methods outright, so their callbacks are
never called when the user asked not to be asked anything."
  (cond
    ((string= method "hostbased")
     (and (ssh-client-auth-option-on-p
           (ssh-client-hostbased-authentication client))
          (ssh-client-hostbased-key client)))
    ((string= method "publickey")
     (ssh-client-auth-option-on-p (ssh-client-pubkey-authentication client)))
    ((string= method "keyboard-interactive")
     (and (ssh-client-auth-option-on-p
           (ssh-client-kbd-interactive-authentication client))
          (not (ssh-client-batch-mode client))
          (ssh-client-kbd-interactive-callback client)))
    ((string= method "password")
     (and (ssh-client-auth-option-on-p
           (ssh-client-password-authentication client))
          (not (ssh-client-batch-mode client))
          (ssh-client-password-callback client)))
    (t nil)))

(defun ssh-client-auth-method-order (client)
  "The methods CLIENT may try, in the order it should try them."
  (let ((preferred (ssh-client-preferred-authentications client)))
    (remove-if-not
     (lambda (method)
       (ssh-client-auth-method-enabled-p client method))
     (or preferred +ssh-client-auth-method-order+))))

(defun ssh-plibssh-client-note-offered-methods (client)
  "Cache the methods the server's last USERAUTH_FAILURE named.

SSH-USERAUTH-LIST is libssh's view of that same reply, so this costs no
round trip.  A zero bitmask means the server has not answered yet; :NONE
records a server that named no method we can use."
  (let ((bits (and (ssh-client-session client)
                   (ssh-client-user client)
                   (ssh-userauth-list (ssh-client-session client)
                                      (ssh-client-user client)))))
    (when (and bits (plusp bits))
      (let ((methods
              (remove
               nil
               (list (and (logtest bits +ssh-auth-method-publickey+)
                          "publickey")
                     (and (logtest bits +ssh-auth-method-interactive+)
                          "keyboard-interactive")
                     (and (logtest bits +ssh-auth-method-password+)
                          "password")))))
        (setf (ssh-client-auth-offered-methods client)
              (or methods :none))))))

(defun ssh-plibssh-client-offered-method-p (client method)
  "Whether the server said it accepts METHOD.

NIL in AUTH-OFFERED-METHODS means it has not said anything yet, so the
configured order is tried as written."
  (let ((offered (ssh-client-auth-offered-methods client)))
    (cond
      ((null offered) t)
      ((eq offered :none) nil)
      (t (member method offered :test #'string=)))))

(defun ssh-client-next-auth-method (client)
  "Make the next untried method the server offered current, and return it.

A method the last USERAUTH_FAILURE did not name is skipped when the server
has told us what it accepts, so a PreferredAuthentications list cannot make
the client prompt for a method the server refused."
  (ssh-plibssh-client-note-offered-methods client)
  (let ((offered (ssh-client-auth-offered-methods client)))
    (loop for method in (ssh-client-auth-method-order client)
          unless (member method
                         (ssh-client-auth-methods-tried client)
                         :test #'string=)
          unless (and offered
                      (not (member method offered :test #'string=)))
          do (setf (ssh-client-auth-method client) method
                   (ssh-client-last-auth-method client) method)
             (push method (ssh-client-auth-methods-tried client))
             (return method))))

(defun ssh-plibssh-client-abandon-method (client)
  "Move from the current method to the next one, or fail if none remains."
  (setf (ssh-client-auth-method client) nil)
  (ssh-plibssh-client-drive-auth client))

(defun ssh-plibssh-client-drive-auth (client)
  "Try the configured methods in OpenSSH's order until one logs in.

Publickey keeps its agent-then-keys behaviour; keyboard-interactive answers
one INFO_REQUEST round per call; password asks the callback for a secret.
A refusal moves on to the next method the server named."
  (let ((method (or (ssh-client-auth-method client)
                    (ssh-client-next-auth-method client))))
    (cond
      ((null method)
       (ssh-client-fail
        client
        (make-condition 'ssh-authentication-error
                        :detail "the server refused every authentication method")))
      ((string= method "publickey")
       (ssh-plibssh-client-drive-publickey client))
      ((string= method "keyboard-interactive")
       (ssh-plibssh-client-drive-kbdint client))
      ((string= method "password")
       (ssh-plibssh-client-drive-password client))
      (t (ssh-plibssh-client-abandon-method client)))))

(defun ssh-plibssh-client-try-current-key (client)
  "Try the current imported key, or report DENIED when there is none."
  (let* ((keys (ssh-client-key-handles client))
         (index (ssh-client-key-index client))
         (key (nth index keys)))
    (if key
        (ssh-userauth-publickey (ssh-client-session client)
                                (ssh-client-user client) key)
        +ssh-auth-denied+)))

(defun ssh-plibssh-client-drive-publickey (client)
  "Offer the agent, then each imported key, in non-blocking mode.

OpenSSH tries the agent's keys before the identity files, so a Denied from
the agent is not the end: the keys that were loaded alongside it still get
their turn.  When every key is refused the next method starts."
  (if (ssh-plibssh-client-agent-pending-p client)
      (let ((rc (ssh-userauth-agent (ssh-client-session client)
                                    (ssh-client-user client))))
        (cond
          ((zerop rc) (ssh-plibssh-client-ready client))
          ;; User authentication has its own "try again" code, 4, not the
          ;; connection-level SSH_AGAIN of -2.
          ((= rc +ssh-auth-again+) nil)
          ((= rc +ssh-auth-partial+)
           (ssh-plibssh-client-handle-publickey-partial client))
          (t
           (setf (ssh-client-agent-tried client) t)
           (ssh-plibssh-client-drive-publickey client))))
      (let ((rc (ssh-plibssh-client-try-current-key client)))
        (cond
          ((zerop rc) (ssh-plibssh-client-ready client))
          ((= rc +ssh-auth-again+) nil)
          ((= rc +ssh-auth-partial+)
           (ssh-plibssh-client-handle-publickey-partial client))
          ((= rc +ssh-auth-denied+)
           (if (ssh-plibssh-client-next-key-p client)
               (ssh-plibssh-client-drive-publickey client)
               (ssh-plibssh-client-abandon-method client)))
          (t
           (error 'ssh-authentication-error
                  :detail (format nil "authentication failed: ~A"
                                  (ssh-plibssh-error
                                   (ssh-client-session client)))))))))

(defun ssh-plibssh-client-handle-publickey-partial (client)
  "Continue after one AuthenticationMethods entry admitted a key.

The server may require publickey again for a second key -- sshd's
publickey,publickey -- so another key is tried when it still names publickey.
Otherwise the next method starts."
  (ssh-plibssh-client-note-offered-methods client)
  (if (and (ssh-plibssh-client-offered-method-p client "publickey")
           (ssh-plibssh-client-next-key-p client))
      (ssh-plibssh-client-drive-publickey client)
      (ssh-plibssh-client-abandon-method client)))

(defun ssh-plibssh-client-next-key-p (client)
  (let ((next (1+ (ssh-client-key-index client))))
    (when (< next (length (ssh-client-key-handles client)))
      (setf (ssh-client-key-index client) next)
      t)))

(defun ssh-plibssh-client-answer-kbdint (client)
  "Answer the INFO_REQUEST libssh just reported and continue the exchange."
  (let* ((session (ssh-client-session client))
         (count (ssh-userauth-kbdint-getnprompts session))
         (name (or (ssh-userauth-kbdint-getname session) ""))
         (instruction (or (ssh-userauth-kbdint-getinstruction session) ""))
         (prompts '()))
    (when (minusp count)
      (error 'ssh-authentication-error
             :detail (format nil "keyboard-interactive prompts unavailable: ~A"
                             (ssh-plibssh-error session))))
    (dotimes (index count)
      (declare (ignore index))
      (cffi:with-foreign-object (echo :char)
        (let ((text (ssh-userauth-kbdint-getprompt session index echo)))
          (push (list (or text "")
                      (not (zerop (cffi:mem-ref echo :char))))
                prompts))))
    (setf prompts (nreverse prompts))
    (let ((answers
            (funcall (ssh-client-kbd-interactive-callback client)
                     client name instruction prompts)))
      (cond
        ;; A zero-prompt INFO_REQUEST only displays a message, so NIL is an
        ;; empty answer list there, not a cancellation.
        ((and (null answers) (plusp count))
         (ssh-client-fail
          client
          (make-condition 'ssh-authentication-error
                          :detail "keyboard-interactive cancelled")))
        ((/= (length (or answers '())) count)
         (error 'ssh-protocol-error
                :detail "keyboard-interactive answer count does not match"))
        (t
         (loop for index from 0
               for answer in answers
               do (ssh-userauth-kbdint-setanswer session index answer))
         (ssh-plibssh-client-drive-kbdint client))))))

(defun ssh-plibssh-client-drive-kbdint (client)
  "Advance one step of the keyboard-interactive exchange."
  (let ((rc (ssh-userauth-kbdint (ssh-client-session client)
                                 (ssh-client-user client) "")))
    (cond
      ((zerop rc) (ssh-plibssh-client-ready client))
      ((= rc +ssh-auth-again+) nil)
      ((= rc +ssh-auth-info+) (ssh-plibssh-client-answer-kbdint client))
      ((= rc +ssh-auth-partial+) (ssh-plibssh-client-abandon-method client))
      ((= rc +ssh-auth-denied+) (ssh-plibssh-client-abandon-method client))
      (t
       (error 'ssh-authentication-error
              :detail (format nil "keyboard-interactive failed: ~A"
                              (ssh-plibssh-error
                               (ssh-client-session client))))))))

(defun ssh-plibssh-client-drive-password (client)
  "Ask PASSWORD-CALLBACK for a secret and offer it.

A refusal re-prompts up to NumberOfPasswordPrompts while the server still
names password; NIL from the callback skips the method, as ssh does."
  (let* ((prompt (format nil "~A@~A's password: "
                         (ssh-client-user client) (ssh-client-host client)))
         (password (funcall (ssh-client-password-callback client)
                            client prompt)))
    (when (null password)
      (return-from ssh-plibssh-client-drive-password
        (ssh-plibssh-client-abandon-method client)))
    (incf (ssh-client-password-attempts client))
    (let ((rc (ssh-userauth-password (ssh-client-session client)
                                     (ssh-client-user client) password)))
      (cond
        ((zerop rc) (ssh-plibssh-client-ready client))
        ((= rc +ssh-auth-again+) nil)
        ((= rc +ssh-auth-partial+)
         (ssh-plibssh-client-note-offered-methods client)
         (if (and (ssh-plibssh-client-offered-method-p client "password")
                  (< (ssh-client-password-attempts client)
                     (or (ssh-client-number-of-password-prompts client) 3)))
             (ssh-plibssh-client-drive-password client)
             (ssh-plibssh-client-abandon-method client)))
        ((= rc +ssh-auth-denied+)
         (if (and (< (ssh-client-password-attempts client)
                     (or (ssh-client-number-of-password-prompts client) 3))
                  (ssh-plibssh-client-offered-method-p client "password"))
             (ssh-plibssh-client-drive-password client)
             (ssh-plibssh-client-abandon-method client)))
        (t
         (error 'ssh-authentication-error
                :detail (format nil "password authentication failed: ~A"
                                (ssh-plibssh-error
                                 (ssh-client-session client)))))))))

(defun ssh-plibssh-client-read-banner (client)
  "Remember the server's authentication banner, if it sent one.

libssh keeps the text until the session ends and hands out a copy that the
caller frees, so the record keeps its own string."
  (let ((pointer (ssh-get-issue-banner (ssh-client-session client))))
    (unless (ssh-plibssh-null-p pointer)
      (unwind-protect
           (setf (ssh-client-banner client)
                 (cffi:foreign-string-to-lisp pointer))
        (ssh-string-free-char pointer)))))

(defun ssh-plibssh-client-ready (client)
  "Authenticated: let the application start channels."
  (setf (ssh-client-phase client) :ready)
  (ssh-plibssh-client-read-banner client)
  (ssh-plibssh-cancel-connect-timer client)
  (ssh-plibssh-start-alive-timer client)
  (when (ssh-client-on-open client)
    (funcall (ssh-client-on-open client) client))
  (ssh-plibssh-client-drive-ready client))

;;; ---- Ready state ----

(defun ssh-plibssh-client-channels (client)
  (iter (for (id channel) in-hashtable (ssh-client-channels client))
    (declare (ignore id))
    (collect channel)))

(defun ssh-plibssh-client-drain-messages (client)
  "Let libssh process packets that carry no channel data.

SSH-CHANNEL-POLL stops calling into libssh once the peer has sent EOF, so
the CHANNEL-CLOSE that follows would never be seen on a session the server
keeps open.  SSH-MESSAGE-GET reads and dispatches packets; a client should
not receive requests, so anything it does report gets the default answer
and is freed."
  (let ((session (ssh-client-session client)))
    (loop
      (let ((message (ssh-message-get session)))
        (when (ssh-plibssh-null-p message) (return))
        (unwind-protect
             (ssh-message-reply-default message)
          (ssh-message-free message))))))

(defun ssh-plibssh-client-drive-ready (client)
  "Give every channel its turn, then notice a server that went away."
  (ssh-plibssh-client-drain-messages client)
  (let ((channels (ssh-plibssh-client-channels client)))
    (iter (for channel in channels)
      (ssh-plibssh-drive-channel channel))
    (unless (or (ssh-client-closed client)
                (plusp (ssh-is-connected (ssh-client-session client))))
      (ssh-client-finish client :peer-closed :close))))

;;; ---- Closing ----

(defun ssh-plibssh-client-release (client)
  "Free the session, socket and keys, once."
  (ssh-plibssh-stop-timers client)
  (let ((watcher (ssh-client-watcher client))
        (write-watcher (ssh-client-write-watcher client))
        (session (ssh-client-session client))
        (callbacks (ssh-client-callbacks client))
        (fd (ssh-client-fd client))
        (write-fd (ssh-client-write-fd client)))
    (setf (ssh-client-watcher client) nil
          (ssh-client-write-watcher client) nil
          (ssh-client-session client) nil
          (ssh-client-callbacks client) nil
          (ssh-client-fd client) nil
          (ssh-client-write-fd client) nil)
    (when watcher (cl-pnet:fd-unwatch watcher))
    (when write-watcher (cl-pnet:fd-unwatch write-watcher))
    (when session
      (ssh-plibssh-unregister-session session)
      (ssh-disconnect session)
      (ssh-free session))
    (when callbacks (cffi:foreign-free callbacks))
    (ssh-plibssh-close-fd fd)
    (when write-fd (ssh-plibssh-close-fd write-fd))
    (iter (for key in (ssh-client-key-handles client))
      (ssh-key-free key))
    (setf (ssh-client-key-handles client) nil)))

(defun ssh-plibssh-client-terminate-channels (client kind reason)
  "Report the end of every channel still registered."
  (let ((channels (ssh-plibssh-client-channels client)))
    (iter (for channel in channels)
      (unless (ssh-channel-close-reported channel)
        (setf (ssh-channel-close-reported channel) t
              (ssh-channel-state channel) :closed)
        (ecase kind
          (:error (when (ssh-channel-on-error channel)
                    (funcall (ssh-channel-on-error channel) channel reason)))
          (:close (when (ssh-channel-on-close channel)
                    (funcall (ssh-channel-on-close channel) channel
                             (ssh-channel-exit-status channel))))))
      (remhash (ssh-channel-local-id channel)
               (ssh-client-channels client)))))

(defun ssh-client-finish (client reason kind)
  "End CLIENT once, reporting REASON through the callback KIND selects."
  (unless (ssh-client-closed client)
    (setf (ssh-client-closed client) t
          (ssh-client-phase client) :closed
          (ssh-client-close-reason client) reason)
    (ssh-plibssh-client-release client)
    (ssh-plibssh-client-terminate-channels client kind reason)
    (ecase kind
      (:error (when (ssh-client-on-error client)
                (funcall (ssh-client-on-error client) client reason)))
      (:close (when (ssh-client-on-close client)
                (funcall (ssh-client-on-close client) client reason))))))

(defun ssh-client-fail (client condition)
  "End CLIENT because of CONDITION, telling its error callback once."
  (ssh-client-finish client condition :error))

;;; ---- Entry points ----

(defun ssh-plibssh-client-start-proxy (client)
  "Let libssh run CLIENT's ProxyCommand and watch the socketpair it uses.

libssh forks the helper itself, expanding %h, %p and %r, and reports the
socketpair through ssh_get_fd; from there the ordinary handshake and pump
take over, exactly as on a TCP descriptor."
  (let* ((session (ssh-plibssh-client-new-session
                   client :proxy-command (ssh-client-proxy-command client)))
         (rc (ssh-connect session)))
    (cond
      ((or (zerop rc) (= rc +ssh-again+)) nil)
      (t
       (error 'ssh-connection-error
              :detail (format nil "ProxyCommand failed to start: ~A"
                              (ssh-plibssh-error session)))))
    (setf (ssh-client-phase client) :kex)
    (let ((fd (ssh-get-fd session)))
      (when (minusp fd)
        (error 'ssh-connection-error
               :detail "libssh created no descriptor for the ProxyCommand"))
      (setf (ssh-client-fd client) fd)
      (setf (ssh-client-watcher client)
            (cl-pnet:fd-watch
             fd
             :on-readable
             (lambda (watcher)
               (declare (ignore watcher))
               (setf (ssh-client-alive-misses client) 0)
               (ssh-plibssh-client-pump client)))))
    (ssh-plibssh-client-pump client)
    client))

(defun ssh-plibssh-start-client (client passphrase)
  "Load CLIENT's keys, then resolve and dial its address off the loop.

A ProxyCommand skips both the resolution and the socket: libssh runs the
helper and hands back a socketpair to watch."
  (ssh-plibssh-start-connect-timer client)
  (handler-case
      (progn
        (ssh-plibssh-load-client-keys client passphrase)
        (ssh-plibssh-client-open client))
    (error (condition) (ssh-client-fail client condition))))

(defun ssh-plibssh-option-meaningful-p (value)
  "Whether VALUE asks for something, treating :NO as off.

Programs pass NIL or T; ssh_config passes :YES or :NO.  :NO must not read as
a request just because a symbol is true."
  (and value (not (eq value :no))))

(defun ssh-plibssh-reject-option (name value)
  "Refuse VALUE for NAME while this backend cannot honour it.

Silently ignoring a configured feature would make the two backends behave
differently without saying so, which is exactly what the matrix is meant to
prevent.  The condition is the facade's, so an application can turn any
transport limitation into the same diagnostic."
  (when (ssh-plibssh-option-meaningful-p value)
    (error 'ssh-unsupported-feature
           :feature name
           :detail "by the libssh transport")))

(defun ssh-client-feature-supported-p (feature)
  "Whether the libssh transport can honour FEATURE.

Agent forwarding, password and keyboard-interactive authentication and the
common option surface are implemented; the remaining entries are not, and
callers learn that through the facade rather than a backend test."
  (not (null (member feature '(:agent-forward :compression)))))

(defun ssh-client-supported-authentication-methods ()
  "The client authentication method names the libssh transport implements."
  '("publickey" "keyboard-interactive" "password"))

(defun make-ssh-client (host
                        &key
                          connect-host
                          host-key-host
                          (port 22)
                          connect-port
                          (user (ssh-default-user))
                          private-key
                          agent
                          passphrase
                          known-hosts
                          global-known-hosts
                          (host-key-policy :ask)
                          host-key-callback
                          connect-timeout
                          server-alive-interval
                          (server-alive-count-max 3)
                          (obscure-keystroke-timing
                           +ssh-keystroke-default-interval-ms+)
                          proxy-command
                          kex-algorithms
                          host-key-algorithms
                          ciphers
                          macs
                          compression
                          pubkey-accepted-algorithms
                          (password-authentication t)
                          (kbd-interactive-authentication t)
                          number-of-password-prompts
                          preferred-authentications
                          (pubkey-authentication t)
                          (batch-mode nil)
                          password-callback
                          kbd-interactive-callback
                          ;; The rest of the pure backend's interface is
                          ;; accepted so callers use one set of arguments.
                          ;; Anything this backend cannot honour is refused
                          ;; rather than dropped.
                          hostbased-authentication
                          hostbased-accepted-algorithms
                          hostbased-keys
                          certificate-files
                          no-host-authentication-for-localhost
                          host-key-alias
                          canonicalize-hostname
                          canonical-domains
                          (canonicalize-max-dots 1)
                          (canonicalize-fallback-local t)
                          resolver
                          verify-host-key-dns
                          host-key-dns-resolver
                          bind-address
                          bind-interface
                          rekey-limit
                          rekey-interval
                          version-addendum
                          (warn-weak-crypto t)
                          channel-timeouts
                          ca-signature-algorithms
                          (revoked-host-keys '())
                          hash-known-hosts
                          known-hosts-command
                          (add-keys-to-agent :no)
                          (update-host-keys :yes)
                          (fingerprint-hash :sha256)
                          visual-host-key
                          check-host-ip
                          (required-rsa-size +ssh-rsa-minimum-modulus-size+)
                          (ip-qos-interactive #xb8)
                          (ip-qos-bulk #x00)
                          (tcp-keep-alive t)
                          set-env
                          (connection-attempts 1)
                          proxy-use-fdpass
                          forward-agent
                          forward-agent-sock-path
                          forward-x11
                          forward-x11-trusted
                          forward-x11-timeout
                          xauth-location
                          address-family
                          on-open
                          on-error
                          on-close
                          on-forwarded-tcpip
                          on-forwarded-streamlocal)
  "Connect to HOST as USER, authenticate, return at once.

The libssh backend resolves HOST off the event loop and dials the address
itself, so no descriptor is ever waited on in the calling thread.  The
arguments are the same as the pure backend's; HOST is still the name the
host key is checked under, HOST-KEY-HOST overrides that name for known_hosts
alone, and CONNECT-PORT is the port dialled while PORT stays the server's
logical one.  CONNECT-TIMEOUT and SERVER-ALIVE-INTERVAL work as they do in
the pure backend.  PROXY-COMMAND asks libssh to run the helper and carry the
stream on its pipes instead of dialling."
  (ssh-plibssh-reject-option "HostbasedAuthentication" hostbased-authentication)
  (ssh-plibssh-reject-option "HostbasedKeys" hostbased-keys)
  ;; libssh owns its banner and hashes it into the exchange hash, so a
  ;; VersionAddendum cannot be applied by this transport.
  (ssh-plibssh-reject-option "VersionAddendum" version-addendum)
  ;; The libssh channel API has no x11 channel interface, so ForwardX11 and
  ;; ForwardX11Trusted are refused rather than silently left off.
  (ssh-plibssh-reject-option "X11 forwarding"
                             (or forward-x11 forward-x11-trusted))
  (let ((client (%make-ssh-client
                 :host host
                 :connect-host (or connect-host host)
                 :host-key-host host-key-host
                 :port port
                 :connect-port (or connect-port port)
                 :user user
                 :known-hosts known-hosts
                 :global-known-hosts global-known-hosts
                 :host-key-policy (or host-key-policy :ask)
                 :host-key-callback host-key-callback
                 :private-key private-key
                 :agent agent
                 :passphrase passphrase
                 :connect-timeout connect-timeout
                 :server-alive-interval server-alive-interval
                 :server-alive-count-max (or server-alive-count-max 3)
                 :obscure-keystroke-timing obscure-keystroke-timing
                 :proxy-command (ssh-proxy-command-value proxy-command)
                 :kex-algorithms kex-algorithms
                 :host-key-algorithms host-key-algorithms
                 :ciphers ciphers
                 :macs macs
                 :compression compression
                 :pubkey-accepted-algorithms pubkey-accepted-algorithms
                 :password-authentication password-authentication
                 :kbd-interactive-authentication
                 kbd-interactive-authentication
                 :number-of-password-prompts number-of-password-prompts
                 :preferred-authentications preferred-authentications
                 :pubkey-authentication pubkey-authentication
                 :batch-mode batch-mode
                 :password-callback password-callback
                 :kbd-interactive-callback kbd-interactive-callback
                 :hostbased-authentication hostbased-authentication
                 :hostbased-accepted-algorithms hostbased-accepted-algorithms
                 :hostbased-keys hostbased-keys
                 :certificate-files certificate-files
                 :no-host-authentication-for-localhost
                 no-host-authentication-for-localhost
                 :host-key-alias host-key-alias
                 :canonicalize-hostname (or canonicalize-hostname :no)
                 :canonical-domains canonical-domains
                 :canonicalize-max-dots canonicalize-max-dots
                 :canonicalize-fallback-local canonicalize-fallback-local
                 :resolver resolver
                 :verify-host-key-dns (or verify-host-key-dns :no)
                 :host-key-dns-resolver host-key-dns-resolver
                 :bind-address bind-address
                 :bind-interface bind-interface
                 :warn-weak-crypto warn-weak-crypto
                 :channel-timeouts channel-timeouts
                 :rekey-limit (or rekey-limit 0)
                 :rekey-interval (or rekey-interval 0)
                 :ca-signature-algorithms ca-signature-algorithms
                 :revoked-host-keys revoked-host-keys
                 :hash-known-hosts hash-known-hosts
                 :known-hosts-command known-hosts-command
                 :add-keys-to-agent add-keys-to-agent
                 :update-host-keys update-host-keys
                 :fingerprint-hash fingerprint-hash
                 :visual-host-key visual-host-key
                 :check-host-ip check-host-ip
                 :required-rsa-size required-rsa-size
                 :ip-qos-interactive ip-qos-interactive
                 :ip-qos-bulk ip-qos-bulk
                 :tcp-keep-alive tcp-keep-alive
                 :set-env set-env
                 :connection-attempts connection-attempts
                 :proxy-use-fdpass proxy-use-fdpass
                 :forward-agent forward-agent
                 :forward-agent-sock-path forward-agent-sock-path
                 :forward-x11 forward-x11
                 :forward-x11-trusted forward-x11-trusted
                 :forward-x11-timeout forward-x11-timeout
                 :xauth-location xauth-location
                 :address-family (ssh-normalize-address-family address-family)
                 :on-open on-open
                 :on-error on-error
                 :on-close on-close
                 :on-forwarded-tcpip on-forwarded-tcpip
                 :on-forwarded-streamlocal on-forwarded-streamlocal)))
    (ssh-plibssh-start-client client passphrase)
    client))

(defun ssh-client-close (client)
  "Close CLIENT and report every open channel as closed."
  (ssh-client-finish client :client-closed :close)
  client)

(defun ssh-client-host-key-fingerprint (client)
  "The fingerprint of the key the server presented, once the KEX has seen it."
  (let ((blob (ssh-client-host-key-blob client)))
    (and blob (ssh-key-fingerprint blob))))
