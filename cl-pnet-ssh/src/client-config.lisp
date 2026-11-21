(in-package #:cl-pnet-ssh)

;;;; Connecting the way ssh_config says.  The parser lives in CL-LIBBURSYK;
;;;; this is the policy layer every client program needs on top of it: which
;;;; identity and agent to offer, which known_hosts files to check, how to
;;;; read StrictHostKeyChecking, and how to tunnel through ProxyJump.  A
;;;; command line should not have to repeat any of it.

;;; ---- Reading the options ----

(defparameter +ssh-system-config-file+ #p"/etc/ssh/ssh_config"
  "The system-wide ssh_config OpenSSH reads before the user's file.

Its Include directives are followed, which is how a distribution's
/etc/ssh/ssh_config.d/*.conf files take effect.")

(defun ssh-config-user-file ()
  (merge-pathnames ".ssh/config" (user-homedir-pathname)))

(defun ssh-config-client-source (config &optional options)
  "CONFIG as an SSH-CONFIG; NIL means the user and system ssh_config files.

OpenSSH reads ~/.ssh/config first and then the system file, keeping the
first value each keyword obtains; combining them in that order gives the
same answers, so a user setting wins over a system default.  An explicit
CONFIG (-F) replaces both, as it does in ssh.

A caller may pass \"none\" to read no configuration at all, as ssh -F none
does.  OPTIONS are the command-line -o answers; they are applied as if they
came before the files, so every keyword they name wins over them the way ssh
itself orders them."
  (let ((source
          (typecase config
            (ssh-config config)
            (null (ssh-config-combine
                   (ssh-config-load (ssh-config-user-file) :user-config t)
                   (ssh-config-load +ssh-system-config-file+
                                    :user-config nil)))
            (t (if (and (stringp config) (string-equal config "none"))
                   (ssh-config-combine)
                   (or (ssh-config-load config :user-config t)
                       (error 'ssh-config-error
                              :path (namestring (pathname config))
                              :detail "cannot read the ssh config")))))))
    (if options
        (ssh-config-add-options source options)
        source)))

(defun ssh-config-client-policy (options)
  "StrictHostKeyChecking as a MAKE-SSH-CLIENT policy."
  (let ((value (ssh-config-options-strict-host-key-checking options)))
    (cond ((null value) :strict)
          ((member value '("no" "off") :test #'string=) :insecure)
          ((string= value "accept-new") :accept-new)
          (t :strict))))

(defun ssh-config-client-agent (options explicit)
  "The agent to use: EXPLICIT, or the one the config and environment select.

OpenSSH uses SSH_AUTH_SOCK unless IdentityAgent or IdentitiesOnly says
otherwise, so an identity file alone does not disable the agent."
  (cond
    ((null explicit)
     (if (ssh-config-options-identities-only options)
         nil
         (let ((value (ssh-config-options-identity-agent options)))
           (case value
             (:none nil)
             (:environment t)
             ((nil) (and (uiop:getenv "SSH_AUTH_SOCK") t))
             (t value)))))
    ((eq explicit :none) nil)
    ((and (stringp explicit) (string-equal explicit "none")) nil)
    ((and (stringp explicit) (string-equal explicit "SSH_AUTH_SOCK")) t)
    (t explicit)))

(defun ssh-config-client-identities (options explicit)
  "The private keys to offer, EXPLICIT or every IdentityFile in order."
  (or explicit
      (let ((files (ssh-config-options-identity-files options)))
        (when files (reverse files)))))

(defun ssh-config-client-known-hosts (options explicit)
  "The known_hosts files, EXPLICIT or the config's user then global ones."
  (or explicit
      (let ((user (ssh-config-options-known-hosts options))
            (global (ssh-config-options-global-known-hosts options)))
        (when (or user global) (append user global)))))

(defun ssh-config-client-seconds (value)
  "VALUE as a positive number of seconds, or NIL when it is off or absent.

The parser keeps :NONE for ssh's \"none\" and 0 for a disabled timeout; both
mean the feature is off to MAKE-SSH-CLIENT."
  (and (integerp value) (plusp value) value))

(defun ssh-config-client-count-max (value)
  "VALUE as a non-negative count, or NIL when it was not configured."
  (and (integerp value) value))

(defun ssh-config-client-algorithms (options accessor supported option
                                     &key (all supported))
  "OPTIONS' algorithm choice as this build's ordered offer, or NIL for default.

Turning it into a list here means an algorithm this build lacks stops the
client instead of quietly widening what it offers.  ALL is the set a pattern
may name when that differs from the default offer."
  (let ((names (funcall accessor options)))
    (when names
      (ssh-resolve-algorithm-list names supported option :all all))))

(defun ssh-config-client-parameters (host options
                                     &key user port private-key agent passphrase
                                       known-hosts host-key-policy
                                       host-key-callback proxy-command)
  "MAKE-SSH-CLIENT's arguments for HOST, given resolved OPTIONS.

USER and PORT win over the file; the remaining keywords are explicit
overrides.  NIL leaves the decision to the config and then to
MAKE-SSH-CLIENT's own defaults."
  (list :host host
        :connect-host (or (ssh-config-options-hostname options) host)
        :host-key-host (or (ssh-config-options-hostname options) host)
        :port (or port (ssh-config-options-port options) 22)
        :user (or user (ssh-config-options-user options) (ssh-default-user))
        :private-key (ssh-config-client-identities options private-key)
        :agent (ssh-config-client-agent options agent)
        :passphrase passphrase
        :known-hosts (ssh-config-client-known-hosts options known-hosts)
        :kex-algorithms
        (ssh-config-client-algorithms
         options #'ssh-config-options-kex-algorithms
         +ssh-kex-real-algorithms+ "KexAlgorithms")
        :host-key-algorithms
        (ssh-config-client-algorithms
         options #'ssh-config-options-host-key-algorithms
         +ssh-host-key-algorithms+ "HostKeyAlgorithms")
        :ciphers
        (ssh-config-client-algorithms
         options #'ssh-config-options-ciphers
         +ssh-ciphers+ "Ciphers")
        :macs
        (ssh-config-client-algorithms
         options #'ssh-config-options-macs
         +ssh-macs+ "MACs")
        :pubkey-accepted-algorithms
        (ssh-config-client-algorithms
         options #'ssh-config-options-pubkey-accepted-algorithms
         +ssh-signature-algorithms+ "PubkeyAcceptedAlgorithms")
        :revoked-host-keys
        (reverse (ssh-config-options-revoked-host-keys options))
        :hash-known-hosts
        (ssh-config-options-hash-known-hosts options)
        :tcp-keep-alive (ssh-config-options-tcp-keep-alive options)
        :set-env (ssh-config-options-set-env options)
        :connection-attempts
        (or (ssh-config-options-connection-attempts options) 1)
        :ca-signature-algorithms
        (ssh-config-client-algorithms
         options #'ssh-config-options-ca-signature-algorithms
         +ssh-server-ca-signature-algorithms+ "CASignatureAlgorithms"
         :all +ssh-server-ca-signature-algorithm-names+)
        :required-rsa-size
        (or (ssh-config-options-required-rsa-size options)
            +ssh-rsa-minimum-modulus-size+)
        :host-key-policy (or host-key-policy
                             (and (null host-key-callback)
                                  (ssh-config-client-policy options)))
        :host-key-callback host-key-callback
        :connect-timeout
        (ssh-config-client-seconds
         (ssh-config-options-connect-timeout options))
        :server-alive-interval
        (ssh-config-client-seconds
         (ssh-config-options-server-alive-interval options))
        :server-alive-count-max
        (ssh-config-client-count-max
         (ssh-config-options-server-alive-count-max options))
        :proxy-command
        (ssh-proxy-command-value
         (or proxy-command (ssh-config-options-proxy-command options)))))

;;; ---- ProxyJump descriptors ----

(defun ssh-config-jump-list (value)
  "VALUE as a list of jump host strings; NONE and empty mean direct."
  (cond
    ((null value) nil)
    ((listp value) value)
    (t (let ((text (string-trim '(#\Space #\Tab) value)))
         (if (or (zerop (length text)) (string-equal text "none"))
             nil
             (loop with start = 0
                   for comma = (position #\, text :start start)
                   collect (string-trim '(#\Space #\Tab)
                                        (subseq text start comma))
                   while comma
                   do (setf start (1+ comma))))))))

(defun ssh-config-split-user (text)
  "TEXT as (VALUES HOST USER), splitting at the first @."
  (let ((at (position #\@ text)))
    (if at
        (values (subseq text (1+ at)) (subseq text 0 at))
        (values text nil))))

(defun ssh-config-split-host-port (text)
  "TEXT as (VALUES HOST PORT-STRING), bracketing IPv6 literals."
  (if (and (plusp (length text)) (char= (char text 0) #\[))
      (let ((close (position #\] text)))
        (if close
            (let ((rest (subseq text (1+ close))))
              (values (subseq text 1 close)
                      (and (> (length rest) 1)
                           (char= (char rest 0) #\:)
                           (subseq rest 1))))
            (values text nil)))
      (let ((colon (position #\: text :from-end t)))
        (if colon
            (values (subseq text 0 colon) (subseq text (1+ colon)))
            (values text nil)))))

(defun ssh-config-port-number (text)
  "TEXT as a port number, or NIL unless it is all digits."
  (when text
    (multiple-value-bind (value end) (parse-integer text :junk-allowed t)
      (when (and value (= end (length text))) value))))

(defun ssh-config-jump-descriptor (text)
  "One ProxyJump entry as a plist of :HOST, :USER and :PORT."
  (multiple-value-bind (destination user) (ssh-config-split-user text)
    (multiple-value-bind (host port) (ssh-config-split-host-port destination)
      (list :host host :user user :port (ssh-config-port-number port)))))

(defun ssh-config-proxy-jumps (options explicit)
  "The jump descriptors EXPLICIT or the config asks for, in order."
  (let ((value (or explicit (ssh-config-options-proxy-jump options))))
    (mapcar #'ssh-config-jump-descriptor (ssh-config-jump-list value))))

(defun ssh-config-proxy-command (options explicit)
  "The ProxyCommand EXPLICIT or the config asks for, or NIL for none.

A ProxyCommand is a transport of its own, so it replaces ProxyJump: OpenSSH
uses whichever of the two it saw first instead of chaining them."
  (ssh-proxy-command-value
   (or explicit (ssh-config-options-proxy-command options))))

;;; ---- Resolving every host ----

(defun ssh-config-client-error (condition on-config-error)
  (if on-config-error
      (funcall on-config-error condition)
      (error condition)))

(defun ssh-config-resolve-hops (source descriptors exec-matcher on-hops on-error)
  "Resolve each jump host's own options in turn, without blocking."
  (labels ((next (remaining collected)
             (if (null remaining)
                 (funcall on-hops (nreverse collected))
                 (let ((descriptor (first remaining)))
                   (ssh-config-resolve
                    source (getf descriptor :host)
                    :original-host (getf descriptor :host)
                    :exec-matcher exec-matcher
                    :on-options
                    (lambda (options)
                      (next (rest remaining)
                            (cons (cons descriptor options) collected)))
                    :on-error on-error)))))
    (next descriptors nil)))

;;; ---- ProxyJump forwarding ----

(defstruct (ssh-config-tunnel (:constructor %make-ssh-config-tunnel))
  chain jump host port listener connection channel
  (to-channel (make-array 0 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer 0))
  (to-connection (make-array 0 :element-type '(unsigned-byte 8)
                               :adjustable t :fill-pointer 0))
  (local-eof nil)
  (eof-sent nil))

(defstruct (ssh-config-chain (:constructor %make-ssh-config-chain))
  target
  (tunnels nil)
  (error nil)
  (closed nil))

(defun ssh-config-buffer-append (buffer data)
  (iter (for octet in-vector data) (vector-push-extend octet buffer))
  buffer)

(defun ssh-config-buffer-drain (buffer)
  (when (plusp (fill-pointer buffer))
    (prog1 (subseq buffer 0 (fill-pointer buffer))
      (setf (fill-pointer buffer) 0))))

(defun ssh-config-chain-fail (chain condition)
  "Report CONDITION to the target, or remember it until the target exists."
  (if (ssh-config-chain-target chain)
      (ssh-client-fail (ssh-config-chain-target chain) condition)
      (unless (ssh-config-chain-error chain)
        (setf (ssh-config-chain-error chain) condition))))

(defun ssh-config-tunnel-close (tunnel)
  (when (ssh-config-tunnel-listener tunnel)
    (cl-pnet:close-listener (ssh-config-tunnel-listener tunnel))
    (setf (ssh-config-tunnel-listener tunnel) nil))
  (when (ssh-config-tunnel-connection tunnel)
    (cl-pnet:close-connection (ssh-config-tunnel-connection tunnel))
    (setf (ssh-config-tunnel-connection tunnel) nil))
  (when (ssh-config-tunnel-channel tunnel)
    (let ((channel (ssh-config-tunnel-channel tunnel)))
      (setf (ssh-config-tunnel-channel tunnel) nil)
      (ssh-channel-close channel))))

(defun ssh-config-chain-close (chain)
  (unless (ssh-config-chain-closed chain)
    (setf (ssh-config-chain-closed chain) t)
    (dolist (tunnel (ssh-config-chain-tunnels chain))
      (ssh-config-tunnel-close tunnel))))

(defun ssh-config-tunnel-fail (tunnel condition)
  (ssh-config-chain-fail (ssh-config-tunnel-chain tunnel) condition)
  (ssh-config-tunnel-close tunnel))

(defun ssh-config-tunnel-send (tunnel data)
  "Move bytes from the jump channel toward the local client."
  (if (ssh-config-tunnel-connection tunnel)
      (cl-pnet:send-data (ssh-config-tunnel-connection tunnel) data)
      (ssh-config-buffer-append (ssh-config-tunnel-to-connection tunnel) data)))

(defun ssh-config-tunnel-flush-to-connection (tunnel)
  (when (ssh-config-tunnel-connection tunnel)
    (let ((data (ssh-config-buffer-drain
                 (ssh-config-tunnel-to-connection tunnel))))
      (when data
        (cl-pnet:send-data (ssh-config-tunnel-connection tunnel) data)))))

(defun ssh-config-tunnel-read (tunnel data)
  "Move bytes from the local client toward the jump channel."
  (cond
    ((null data)
     (setf (ssh-config-tunnel-local-eof tunnel) t)
     (when (ssh-config-tunnel-channel tunnel)
       (ssh-channel-eof (ssh-config-tunnel-channel tunnel))))
    ((ssh-config-tunnel-channel tunnel)
     (ssh-channel-write (ssh-config-tunnel-channel tunnel) data))
    (t (ssh-config-buffer-append (ssh-config-tunnel-to-channel tunnel) data))))

(defun ssh-config-tunnel-flush (tunnel)
  "Send whatever waited for the channel, then report a local EOF once."
  (when (ssh-config-tunnel-channel tunnel)
    (let ((data (ssh-config-buffer-drain (ssh-config-tunnel-to-channel tunnel))))
      (when data
        (ssh-channel-write (ssh-config-tunnel-channel tunnel) data)))
    (when (and (ssh-config-tunnel-local-eof tunnel)
               (not (ssh-config-tunnel-eof-sent tunnel)))
      (setf (ssh-config-tunnel-eof-sent tunnel) t)
      (ssh-channel-eof (ssh-config-tunnel-channel tunnel)))))

(defun ssh-config-tunnel-accept (tunnel connection)
  (setf (ssh-config-tunnel-connection tunnel) connection)
  (when (ssh-config-tunnel-listener tunnel)
    (cl-pnet:close-listener (ssh-config-tunnel-listener tunnel))
    (setf (ssh-config-tunnel-listener tunnel) nil))
  (ssh-config-tunnel-flush tunnel)
  (ssh-config-tunnel-flush-to-connection tunnel))

(defun ssh-config-tunnel-open (tunnel)
  "Open the direct-tcpip half of TUNNEL once its jump host is ready."
  (unless (or (ssh-config-tunnel-channel tunnel)
              (ssh-config-chain-closed (ssh-config-tunnel-chain tunnel)))
    (handler-case
        (let ((channel
                (ssh-open-direct-tcpip
                 (ssh-config-tunnel-jump tunnel)
                 (ssh-config-tunnel-host tunnel)
                 (ssh-config-tunnel-port tunnel)
                 :on-data (lambda (channel data kind)
                            (declare (ignore channel kind))
                            (ssh-config-tunnel-send tunnel data))
                 :on-eof (lambda (channel)
                           (declare (ignore channel))
                           (ssh-config-tunnel-close tunnel))
                 :on-close (lambda (channel reason)
                             (declare (ignore channel reason))
                             (ssh-config-tunnel-close tunnel))
                 :on-error (lambda (channel condition)
                             (declare (ignore channel))
                             (ssh-config-tunnel-fail tunnel condition)))))
          (setf (ssh-config-tunnel-channel tunnel) channel)
          (ssh-config-tunnel-flush tunnel)
          (ssh-config-tunnel-flush-to-connection tunnel))
      (error (condition) (ssh-config-tunnel-fail tunnel condition)))))

(defun ssh-config-tunnel-listen (tunnel)
  "Bind 127.0.0.1:0 for TUNNEL and return the port actually bound."
  (let ((listener
          (cl-pnet:make-tcp-listener
           "127.0.0.1" 0
           :on-accept (lambda (connection)
                        (ssh-config-tunnel-accept tunnel connection))
           :read-cb (lambda (connection data)
                      (declare (ignore connection))
                      (ssh-config-tunnel-read tunnel data)))))
    (unless listener
      (error 'ssh-connection-error
             :detail "cannot listen for a ProxyJump tunnel"))
    (setf (ssh-config-tunnel-listener tunnel) listener)
    (cl-pnet:listener-port listener)))

;;; ---- Building the client ----

(defun ssh-config-launch-client (parameters options
                                 connect-host connect-port
                                 on-open on-error on-close
                                 &key on-forwarded-tcpip
                                   on-forwarded-streamlocal)
  "Make the client PARAMETERS describes and remember OPTIONS on it."
  (let ((client
          (make-ssh-client
           (getf parameters :host)
           :connect-host (or connect-host (getf parameters :connect-host))
           :host-key-host (getf parameters :host-key-host)
           :connect-port (or connect-port (getf parameters :port))
           :port (getf parameters :port)
           :user (getf parameters :user)
           :private-key (getf parameters :private-key)
           :agent (getf parameters :agent)
           :passphrase (getf parameters :passphrase)
           :known-hosts (getf parameters :known-hosts)
           :host-key-policy (getf parameters :host-key-policy)
           :host-key-callback (getf parameters :host-key-callback)
           :kex-algorithms (getf parameters :kex-algorithms)
           :host-key-algorithms (getf parameters :host-key-algorithms)
           :ciphers (getf parameters :ciphers)
           :macs (getf parameters :macs)
           :pubkey-accepted-algorithms
           (getf parameters :pubkey-accepted-algorithms)
           :ca-signature-algorithms (getf parameters :ca-signature-algorithms)
           :revoked-host-keys (getf parameters :revoked-host-keys)
           :hash-known-hosts (getf parameters :hash-known-hosts)
           :tcp-keep-alive (getf parameters :tcp-keep-alive)
           :set-env (getf parameters :set-env)
           :connection-attempts (getf parameters :connection-attempts)
           :required-rsa-size (getf parameters :required-rsa-size)
           :connect-timeout (getf parameters :connect-timeout)
           :server-alive-interval (getf parameters :server-alive-interval)
           :server-alive-count-max (getf parameters :server-alive-count-max)
           :proxy-command (getf parameters :proxy-command)
           :on-open on-open
           :on-error on-error
           :on-close on-close
           :on-forwarded-tcpip on-forwarded-tcpip
           :on-forwarded-streamlocal on-forwarded-streamlocal)))
    (setf (ssh-client-config-options client) options)
    client))

(defun ssh-config-hop-parameters (descriptor options overrides)
  "MAKE-SSH-CLIENT arguments for one jump host.

The jump's own @user and :port beat its Host block, as they do in SSH;
the destination's user and port do not apply to it."
  (let ((parameters
          (ssh-config-client-parameters
           (getf descriptor :host) options
           :private-key (getf overrides :private-key)
           :agent (getf overrides :agent)
           :passphrase (getf overrides :passphrase)
           :known-hosts (getf overrides :known-hosts)
           :host-key-policy (getf overrides :host-key-policy)
           :host-key-callback (getf overrides :host-key-callback))))
    (when (getf descriptor :user)
      (setf (getf parameters :user) (getf descriptor :user)))
    (when (getf descriptor :port)
      (setf (getf parameters :port) (getf descriptor :port)))
    parameters))

(defun ssh-config-start-jump (chain tunnel parameters connect-host connect-port)
  (ssh-config-launch-client
   parameters nil connect-host connect-port
   (lambda (client)
     (setf (ssh-config-tunnel-jump tunnel) client)
     (ssh-config-tunnel-open tunnel))
   (lambda (client condition)
     (declare (ignore client))
     (ssh-config-chain-fail chain condition))
   (lambda (client reason)
     (declare (ignore client reason))
     nil)))

(defun ssh-config-hop-tunnel (chain next target-parameters)
  "Bind a loopback listener that leads to the next hop or to the target."
  (let* ((destination (or next target-parameters))
         (tunnel (%make-ssh-config-tunnel
                  :chain chain
                  :host (getf destination :connect-host)
                  :port (getf destination :port))))
    (values tunnel (ssh-config-tunnel-listen tunnel))))

(defun ssh-config-start-chain (hops overrides target-options target-parameters
                               on-open on-error on-close
                               &key on-forwarded-tcpip
                                 on-forwarded-streamlocal)
  "Build every jump client and the target, and return the target client.

The listeners exist before the clients that dial them, so the whole chain
is constructed in one pass; bytes that arrive before a channel is open wait
in the tunnel's buffers."
  (let ((chain (%make-ssh-config-chain))
        (previous-port nil)
        (tunnels nil))
    (loop for hop in hops
          for rest = (rest hops) then (rest rest)
          do (multiple-value-bind (tunnel port)
                 (ssh-config-hop-tunnel chain (first rest) target-parameters)
               (push tunnel tunnels)
               (ssh-config-start-jump
                chain tunnel hop
                (if previous-port "127.0.0.1" (getf hop :connect-host))
                (or previous-port (getf hop :port)))
               (setf previous-port port)))
    (setf (ssh-config-chain-tunnels chain) (nreverse tunnels))
    (let ((target
            (ssh-config-launch-client
             target-parameters target-options "127.0.0.1" previous-port
             on-open
             (lambda (client condition)
               (ssh-config-chain-close chain)
               (when on-error (funcall on-error client condition)))
             (lambda (client reason)
               (ssh-config-chain-close chain)
               (when on-close (funcall on-close client reason)))
             :on-forwarded-tcpip on-forwarded-tcpip
             :on-forwarded-streamlocal on-forwarded-streamlocal)))
      (setf (ssh-config-chain-target chain) target)
      (when (ssh-config-chain-error chain)
        (ssh-client-fail target (ssh-config-chain-error chain)))
      target)))

(defun ssh-config-finish-client (host options hops overrides
                                 on-open on-error on-close
                                 &key proxy-command on-forwarded-tcpip
                                   on-forwarded-streamlocal)
  "Build the target client for HOST, directly or through HOPS."
  (let ((target (ssh-config-client-parameters
                 host options
                 :user (getf overrides :user)
                 :port (getf overrides :port)
                 :private-key (getf overrides :private-key)
                 :agent (getf overrides :agent)
                 :passphrase (getf overrides :passphrase)
                 :known-hosts (getf overrides :known-hosts)
                 :host-key-policy (getf overrides :host-key-policy)
                 :host-key-callback (getf overrides :host-key-callback)
                 :proxy-command proxy-command)))
    (cond
      (hops
       (ssh-config-start-chain
        (mapcar (lambda (entry)
                  (ssh-config-hop-parameters
                   (car entry) (cdr entry) overrides))
                hops)
        overrides options target on-open on-error on-close
        :on-forwarded-tcpip on-forwarded-tcpip
        :on-forwarded-streamlocal on-forwarded-streamlocal))
      (t
       (ssh-config-launch-client target options nil nil
                                 on-open on-error on-close
                                 :on-forwarded-tcpip on-forwarded-tcpip
                                 :on-forwarded-streamlocal
                                 on-forwarded-streamlocal)))))

;;; ---- Entry point ----

(defun ssh-config-client-overrides (user port private-key agent passphrase
                                    known-hosts host-key-policy
                                    host-key-callback)
  "The explicit command-line answers, as a plist for the chain builder."
  (list :user user :port port
        :private-key private-key :agent agent
        :passphrase passphrase
        :known-hosts known-hosts
        :host-key-policy host-key-policy
        :host-key-callback host-key-callback))

(defun ssh-config-build-client (source host options proxy-jump proxy-command
                                exec-matcher overrides on-open on-error
                                on-close fail on-built
                                &key on-forwarded-tcpip
                                  on-forwarded-streamlocal)
  "Resolve the jumps for OPTIONS, build the target, and call ON-BUILT."
  (handler-case
      (let ((command (ssh-config-proxy-command options proxy-command)))
        (ssh-config-resolve-hops
         source
         ;; A ProxyCommand carries the stream itself, so there is no chain.
         (if command nil (ssh-config-proxy-jumps options proxy-jump))
         exec-matcher
         (lambda (hops)
           (funcall on-built
                    (ssh-config-finish-client
                     host options hops overrides
                     on-open on-error on-close
                     :proxy-command command
                     :on-forwarded-tcpip on-forwarded-tcpip
                     :on-forwarded-streamlocal
                     on-forwarded-streamlocal)))
         fail))
    (error (condition) (funcall fail condition))))

(defun make-ssh-client-from-config
    (host &key config original-host user port private-key agent passphrase
              known-hosts host-key-policy host-key-callback proxy-jump
              proxy-command exec-matcher options on-client on-config-error
              on-open on-error on-close on-forwarded-tcpip
              on-forwarded-streamlocal)
  "Connect to HOST exactly as ssh_config describes, return at once.

CONFIG is an ssh-config, a path, or NIL for ~/.ssh/config; its HostName,
User, Port, identities, agent, known-hosts files, policy, timeouts,
keepalive, ProxyJump and ProxyCommand are honoured while the explicit
arguments win.  OPTIONS are free-form -o answers, each a \"Keyword value\"
string or a (KEYWORD . VALUE) cons; they are applied before CONFIG, so any
keyword wins over the file.  EXEC-MATCHER answers Match exec; ON-CLIENT
receives an asynchronous client; ON-CONFIG-ERROR reports resolution
failures."
  (let* ((source (ssh-config-client-source config options))
         (overrides (ssh-config-client-overrides
                     user port private-key agent passphrase
                     known-hosts host-key-policy host-key-callback))
         (finished nil)
         (client nil)
         (on-built (lambda (value)
                     (setf client value finished t)
                     (when on-client (funcall on-client value))))
         (fail (lambda (condition)
                 (setf finished t)
                 (ssh-config-client-error condition on-config-error))))
    (ssh-config-resolve
     source host
     :original-host (or original-host host)
     :user user
     :port port
     :exec-matcher exec-matcher
     :on-options
     (lambda (options)
       (ssh-config-build-client source host options proxy-jump proxy-command
                                exec-matcher overrides on-open on-error
                                on-close fail on-built
                                :on-forwarded-tcpip on-forwarded-tcpip
                                :on-forwarded-streamlocal
                                on-forwarded-streamlocal))
     :on-error (lambda (condition) (funcall fail condition)))
    (when (and (not finished) (null on-client))
      (error 'ssh-config-error
             :detail "ssh_config resolution is asynchronous; pass :ON-CLIENT"))
    client))

(defun ssh-client-send-env (client)
  "The SendEnv names resolved for CLIENT, or NIL when it has no config."
  (let ((options (ssh-client-config-options client)))
    (and options (ssh-config-options-send-env options))))
