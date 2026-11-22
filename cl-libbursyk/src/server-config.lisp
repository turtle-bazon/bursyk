(in-package #:cl-pnet-ssh)

;;;; sshd_config: the server's configuration file, in OpenSSH's format and
;;;; with OpenSSH's semantics.  The syntax is identical to ~/.ssh/config, so
;;;; the tokenizer, glob matcher and Include expansion are shared.  The
;;;; values are sshd's, though: a relative Include is relative to /etc/ssh,
;;;; the first value obtained for a keyword wins, and a keyword this build
;;;; cannot honour stops the server at startup instead of being silently
;;;; dropped -- a server config typo must never become a policy hole.

(defparameter +ssh-server-config-directory+ #p"/etc/ssh/"
  "The directory sshd resolves a relative Include against.")

(defparameter +ssh-server-config-default-file+
  (merge-pathnames "sshd_config" +ssh-server-config-directory+)
  "The sshd_config sshd reads when -f is not given.")

(defparameter +ssh-server-config-default-authorized-keys-files+
  '("%h/.ssh/authorized_keys" "%h/.ssh/authorized_keys2")
  "sshd's default AuthorizedKeysFile, expanded per user at authentication.

authorized_keys2 is deprecated but OpenSSH still reads it by default.")

(defparameter +ssh-server-config-log-levels+
  '(("quiet" . :quiet) ("fatal" . :fatal) ("error" . :error)
    ("info" . :info) ("verbose" . :verbose) ("debug" . :debug)
    ("debug1" . :debug1) ("debug2" . :debug2) ("debug3" . :debug3))
  "LogLevel names, as sshd spells them.")

(defparameter +ssh-server-default-login-grace-time+ 120
  "sshd's default LoginGraceTime in seconds.")

(defparameter +ssh-server-default-client-alive-interval+ 0
  "sshd's default ClientAliveInterval; zero sends no probes.")

(defparameter +ssh-server-default-client-alive-count-max+ 3
  "sshd's default ClientAliveCountMax; zero never disconnects.")

(defparameter +ssh-server-max-time-value+ 2147483647
  "Largest time value sshd's convtime accepts, because it uses int.")

(defparameter +ssh-server-config-gateway-ports-values+
  '(("no" . :no) ("yes" . :yes) ("clientspecified" . :clientspecified)))

(defparameter +ssh-server-config-tcp-forwarding-values+
  '(("no" . :no) ("yes" . :yes) ("all" . :yes)
    ("local" . :local) ("remote" . :remote)))

(defparameter +ssh-server-config-permit-root-login-values+
  '(("yes" . :yes) ("no" . :no)
    ("prohibit-password" . :prohibit-password)
    ("without-password" . :prohibit-password)
    ("forced-commands-only" . :forced-commands-only))
  "PermitRootLogin values; without-password is the old spelling of
prohibit-password and means the same thing.")

;;; sshd parses its file twice: global directives once at startup, and the
;;; directives of each Match block again when a connection's account is
;;; known.  These are the keywords OpenSSH marks SSHCFG_GLOBAL: the ones a
;;; Match block may not contain, because they describe the process rather
;;; than one connection.
(defparameter +ssh-server-config-global-only-keywords+
  '("usepam" "pamauthenticationviakbdint"
    "port" "hostkey" "hostdsakey" "hostkeyagent" "pidfile" "modulifile"
    "serverkeybits" "logingracetime" "keyregenerationinterval"
    "syslogfacility" "rhostsauthentication" "hostkeyalgorithms"
    "dsaauthentication" "kerberosorlocalpasswd" "kerberosticketcleanup"
    "kerberosgetafstoken" "kerberostgtpassing" "afstokenpassing"
    "gssapicleanupcredentials" "gssapistrictacceptorcheck" "checkmail"
    "listenaddress" "addressfamily" "printmotd" "printlastlog"
    "xauthlocation"
    "permituserenvironment" "uselogin" "compression" "tcpkeepalive"
    "keepalive" "ciphers" "macs" "protocol" "maxstartups"
    "persourcemaxstartups" "persourcenetblocksize"
    "persourcepenalties" "persourcepenaltyexemptlist" "usedns"
    "verifyreversemapping" "reversemappingcheck" "useprivilegeseparation"
    "hostcertificate" "kexalgorithms" "versionaddendum" "fingerprinthash"
    "securitykeyprovider" "ignoreuserknownhosts" "strictmodes"
    "hostkeyagent")
  "sshd_config keywords OpenSSH allows only outside a Match block.

Inside a Match block sshd refuses one of these with \"Directive ... is not
allowed within a Match block\"; so does this server, instead of accepting a
line whose value it could not apply per connection.")

(defparameter +ssh-server-config-match-attributes+
  '(("user" . :user)
    ("group" . :group)
    ("host" . :host)
    ("address" . :address)
    ("localport" . :localport))
  "The Match attributes this server can evaluate.

OpenSSH also has LocalAddress and RDomain; this server refuses those two
rather than treating them as always false, because it cannot read the local
socket address and has no routing domains.")

;;; The memories of the first parse: every directive read inside a Match
;;; block, tagged with the criteria in force at that line.
(defstruct (ssh-server-match (:constructor %make-ssh-server-match))
  (criteria '())
  (line nil))

;;; Keywords that are valid sshd_config but cannot change anything this
;;; server does.  They are accepted (so a stock file still loads) and named
;;; in a warning, never silently dropped.
(defparameter +ssh-server-config-ignored-keywords+
  '("printmotd" "printlastlog" "logverbose" "fingerprinthash"
    "syslogfacility" "protocol" "useprivilegeseparation" "x11displayoffset"
    "x11uselocalhost" "xauthlocation" "modulifile" "ipqos" "rdomain"
    "usedns" "securitykeyprovider" "gssapicleanupcredentials"
    "gssapistrictacceptorcheck" "kerberosorlocalpasswd"
    "kerberosticketcleanup" "kerberosgetafstoken"
    "authorizedkeysfile2"
    ;; 10.6 directives that describe OpenSSH's privsep helpers or features
    ;; this server refuses outright (PAM and GSSAPI).
    "sshdauthpath" "sshdsessionpath" "pamservicename"
    "gssapidelegatecredentials" "warnweakcrypto"))

;;; Keywords whose default or "off" value describes this server exactly.  A
;;; configuration that asks for that value is fine; asking for anything else
;;; would change behaviour this build does not have, so it is refused.
(defparameter +ssh-server-config-accepted-off-keywords+
  '(("x11forwarding" . "no")
    ("permittunnel" . "no")
    ("passwordauthentication" . "no")
    ("kbdinteractiveauthentication" . "no")
    ("challengeresponseauthentication" . "no")
    ("skeyauthentication" . "no")
    ("usepam" . "no")
    ("permitemptypasswords" . "no")
    ("gssapiauthentication" . "no")
    ("kerberosauthentication" . "no")
    ("permittty" . "yes")
    ("permituserrc" . "yes")
    ("compression" . "no")))

;;; Recognised sshd keywords this server does not implement at all.
(defparameter +ssh-server-config-unsupported-keywords+
  '())

(defstruct (ssh-server-config (:constructor %make-ssh-server-config))
  (path nil)
  (directives '())
  (ports '())
  (ports-from-command-line nil)
  (listen-addresses '())
  (listen-addresses-from-command-line nil)
  (address-family nil)
  (host-key-files '())
  ;; HostKeyAgent: an agent socket that signs for host keys whose private
  ;; half is not on disk, or NIL.
  (host-key-agent nil)
  ;; HostCertificate files, in the order read.  Each must certify one of
  ;; HostKey's public keys; sshd pairs them at startup and drops the rest.
  (host-certificate-files '())
  ;; AuthenticationMethods: NIL when absent, :ANY for the "any" pseudo-method,
  ;; or a list of comma-separated method-list strings.  Only lists this
  ;; server can complete (publickey) are usable at connection time.
  (authentication-methods nil)
  ;; NIL means the default; sshd's "none" entries are skipped, so a list of
  ;; only "none" disables public-key authentication.
  (authorized-keys-files nil)
  ;; Certificate authentication.  TrustedUserCAKeys is a file of CA public
  ;; keys; the principals file is a pattern expanded per user with %h/%u/%U.
  ;; The command is sshd's AuthorizedPrincipalsCommand, run as the account it
  ;; names, and the signature list is CASignatureAlgorithms after sshd's
  ;; + / - / ^ resolution.
  (trusted-user-ca-keys nil)
  (authorized-principals-file nil)
  (authorized-principals-command nil)
  (authorized-principals-command-user nil)
  (ca-signature-algorithms nil)
  ;; AuthorizedKeysCommand prints authorized_keys lines for the offered key;
  ;; sshd runs it after AuthorizedKeysFile and requires the account named by
  ;; AuthorizedKeysCommandUser.  This build has no privilege separation, so
  ;; only the server's own account can be used.
  (authorized-keys-command nil)
  (authorized-keys-command-user nil)
  ;; RevokedKeys is a list of files holding public keys that may not log
  ;; in, or :none.  sshd keeps the first line's list and validates later
  ;; ones; the files are read for each authentication attempt, so a KRL can
  ;; be replaced while the server runs.
  (revoked-keys nil)
  (accept-env '())
  (permit-open '())
  (permit-listen '())
  ;; Algorithm choices.  NIL means this build's default; a list is the exact
  ;; order the directive chose, already resolved from sshd's + / - / ^ form.
  ;; Ciphers, MACs, KexAlgorithms and HostKeyAlgorithms are global-only;
  ;; PubkeyAcceptedAlgorithms and RequiredRSASize may come from a Match block.
  (ciphers nil)
  (macs nil)
  (kex-algorithms nil)
  (host-key-algorithms nil)
  (pubkey-accepted-algorithms nil)
  ;; PubkeyAuthOptions: NIL unset, :NONE for an explicit "none", or a list of
  ;; :TOUCH-REQUIRED and :VERIFY-REQUIRED (which only affect FIDO keys, none
  ;; of which this build accepts).  MAX-PUBKEY-OK is the separate probe
  ;; budget, 0-255, with sshd's default of 6 when NIL.
  (pubkey-auth-options nil)
  (max-pubkey-ok nil)
  (required-rsa-size nil)
  (gateway-ports nil)
  (allow-tcp-forwarding nil)
  ;; AllowAgentForwarding: :YES or :NO.  NIL is sshd's default of yes.
  (allow-agent-forwarding nil)
  ;; AgentSocketPath: "none", "shared:DIRECTORY" or "user:DIRECTORY", where
  ;; the directory may use ~ and %u/%U/%h.  NIL leaves sshd's default of
  ;; user:~/.ssh/agent, which BURSYK-SERVER creates per session.
  (agent-socket-path nil)
  ;; AllowStreamLocalForwarding: :YES, :NO, :LOCAL or :REMOTE.  NIL leaves
  ;; this server's own default, which refuses stream-local forwarding.
  (allow-streamlocal-forwarding nil)
  ;; HostbasedAuthentication and its policy.  The flags use :YES/:NO so a
  ;; Match block can override a global value; NIL means sshd's default.
  (hostbased-authentication nil)
  (hostbased-accepted-algorithms nil)
  (hostbased-uses-name-from-packet-only nil)
  ;; IgnoreRhosts: :YES, :NO or :SHOSTS-ONLY.  IgnoreUserKnownHosts and
  ;; StrictModes are global.
  (ignore-rhosts nil)
  (ignore-user-known-hosts nil)
  (strict-modes nil)
  ;; StreamLocalBindMask and StreamLocalBindUnlink for remote Unix-socket
  ;; listeners; sshd's defaults are 0177 and no.
  (streamlocal-bind-mask nil)
  (streamlocal-bind-unlink nil)
  (disable-forwarding nil)
  ;; DisableForwarding is the one Match keyword whose "no" is a value of its
  ;; own rather than the absence of one, so a match block that says no must
  ;; be able to override a global yes.  This records that the directive was
  ;; read at all; sshd's tri-state (-1/0/1) does the same job.
  (disable-forwarding-set-p nil)
  ;; RefuseConnection: :YES terminates the connection after the account is
  ;; known, :NO (or NIL) does not.  Match can turn a global yes off.
  (refuse-connection nil)
  (subsystems '())
  (log-level nil)
  ;; Access control.  Each list holds sshd patterns and accumulates across
  ;; lines; an empty list means the rule is not in force.
  (allow-users '())
  (deny-users '())
  (allow-groups '())
  (deny-groups '())
  (permit-root-login nil)
  ;; Limits and identity.  NIL means the server keeps its own default.
  (max-auth-tries nil)
  (max-sessions nil)
  ;; Time limits in seconds.  NIL means the directive was absent, so
  ;; MAKE-SSH-SERVER keeps sshd's default; zero is a value of its own.
  (login-grace-time nil)
  (client-alive-interval nil)
  (client-alive-count-max nil)
  ;; RekeyLimit: the byte volume before rekeying (0 is OpenSSH's "default",
  ;; the cipher's own limit) and the optional time interval in seconds
  ;; (0 disables time-based rekeying).  Each is first-value-wins separately,
  ;; as sshd's readconf tracks rekey_limit and rekey_interval independently.
  (rekey-limit nil)
  (rekey-interval nil)
  ;; MaxStartups: BEGIN:RATE:FULL, the sshd defaults when NIL.  Only global
  ;; directives set these, and sshd's parser lets a later line replace them.
  (max-startups-begin nil)
  (max-startups-rate nil)
  (max-startups-full nil)
  ;; PerSourceMaxStartups.  NIL is sshd's "none", no per-source limit.
  (per-source-max-startups nil)
  ;; PerSourceNetBlockSize, IPv4 and IPv6 prefix lengths.  NIL keeps sshd's
  ;; 32 and 128, which treat every address by itself.
  (per-source-net-block-size-ipv4 nil)
  (per-source-net-block-size-ipv6 nil)
  ;; PerSourcePenalties: a plist of the fields that were set, including
  ;; :ENABLED.  NIL means the directive was absent, which leaves penalties
  ;; off in this server; sshd 10.6 enables them by default.
  (per-source-penalties nil)
  (per-source-penalty-exempt nil)
  ;; UnusedConnectionTimeout in seconds; 0 is sshd's "none".
  (unused-connection-timeout nil)
  ;; ChannelTimeout as (TYPE-PATTERN . SECONDS) pairs in the order the
  ;; winning line gave them, or :NONE for an explicit "none" that disables
  ;; every channel timeout.  NIL means the directive was absent.
  (channel-timeouts nil)
  ;; TCPKeepAlive: :YES or :NO; NIL keeps sshd's default of yes.
  (tcp-keep-alive nil)
  ;; PermitUserEnvironment: NIL (unset, means no), :YES, :NO, or a list of
  ;; patterns naming the variables a user may set.
  (permit-user-environment nil)
  ;; ExposeAuthInfo: :YES writes sshd's SSH_USER_AUTH file for the
  ;; connection, :NO (or NIL, unset) writes none.
  (expose-auth-info nil)
  ;; SetEnv assignments, "NAME=VALUE", in the order they were read.
  (set-env '())
  (pid-file nil)
  ;; ForceCommand: the command sshd runs instead of whatever the client
  ;; asked for, kept verbatim because sshd passes it to the login shell
  ;; exactly as written.  NIL means no forced command.
  (force-command nil)
  ;; ChrootDirectory: a path with %h/%u/%U tokens, or :NONE for no chroot.
  (chroot-directory nil)
  ;; Banner is a file read for every connection, or :none to send nothing.
  (banner nil)
  (version-addendum nil)
  ;; Directives read inside Match blocks, in file order, as
  ;; (SSH-SERVER-MATCH . SSH-CONFIG-LINE) pairs.  The first parse validates
  ;; them; SSH-SERVER-CONFIG-FOR-CONNECTION applies the matching ones again
  ;; once a connection's account is known, as sshd's second parse does.
  (match-lines '())
  (warnings '()))

;;; ---- Errors and warnings ----

(defun ssh-server-config-line-error (line control &rest arguments)
  (error 'ssh-server-config-error
         :path (ssh-config-line-path line)
         :line (ssh-config-line-number line)
         :keyword (ssh-config-line-keyword line)
         :detail (apply #'format nil control arguments)))

(defun ssh-server-config-warn (config control &rest arguments)
  (push (apply #'format nil control arguments)
        (ssh-server-config-warnings config)))

;;; ---- Reading values ----

(defun ssh-server-config-one-argument (line)
  "The single argument of LINE, or an error naming the keyword."
  (let ((arguments (ssh-config-line-args line)))
    (cond
      ((null arguments)
       (ssh-server-config-line-error line "~A needs an argument"
                                     (ssh-config-line-keyword line)))
      ((rest arguments)
       (ssh-server-config-line-error line "~A takes one argument, not ~D"
                                     (ssh-config-line-keyword line)
                                     (length arguments)))
      (t (first arguments)))))

(defun ssh-server-config-env-name-p (name)
  "Whether NAME is usable as an environment variable name.

sshd's valid_env_name allows letters, digits and underscores only; a name
carrying = or a space cannot be passed to execve safely."
  (and (plusp (length name))
       (every (lambda (character)
                (or (char<= #\a character #\z)
                    (char<= #\A character #\Z)
                    (char<= #\0 character #\9)
                    (char= character #\_)))
              name)))

(defun ssh-server-config-flag (line argument)
  "ARGUMENT as a sshd boolean; anything but yes or no is an error."
  (cond
    ((string-equal argument "yes") t)
    ((string-equal argument "no") nil)
    (t (ssh-server-config-line-error line "~A must be yes or no, not ~A"
                                     (ssh-config-line-keyword line)
                                     argument))))

(defparameter +ssh-authentication-method-names+
  '("none" "publickey" "password" "keyboard-interactive" "hostbased"
    "gssapi-with-mic")
  "The method names OpenSSH's authmethods table accepts.

Only publickey can actually complete on this server; the others are still
valid in the file, and a list that needs one is skipped at connection time
as sshd skips a list naming a disabled method.")

(defun ssh-server-config-check-authentication-methods (line argument)
  "Refuse ARGUMENT unless it is a comma-separated list of known methods."
  (when (zerop (length argument))
    (ssh-server-config-line-error
     line "AuthenticationMethods has an empty method list"))
  (dolist (method (uiop:split-string argument :separator ","))
    (let* ((colon (position #\: method))
           (name (if colon (subseq method 0 colon) method)))
      (unless (member name +ssh-authentication-method-names+
                      :test #'string=)
        (ssh-server-config-line-error
         line "unknown authentication method ~A" name)))))

(defun ssh-server-config-multistate (line argument table keyword)
  "ARGUMENT's value in TABLE, or an error naming the keyword."
  (or (cdr (assoc (string-downcase argument) table :test #'string=))
      (ssh-server-config-line-error line "bad ~A argument ~A"
                                    keyword argument)))

(defun ssh-server-config-port-string (argument)
  "ARGUMENT as a port number, or NIL."
  (when (and (plusp (length argument))
             (every #'digit-char-p argument))
    (let ((port (ignore-errors (parse-integer argument))))
      (and port (<= 1 port 65535) port))))

(defun ssh-server-config-port-number (line argument)
  (or (ssh-server-config-port-string argument)
      (ssh-server-config-line-error line "bad port ~A" argument)))

(defun ssh-server-config-count (line argument)
  "ARGUMENT as a non-negative decimal integer, or an error."
  (unless (and (plusp (length argument))
               (every #'digit-char-p argument))
    (ssh-server-config-line-error
     line "~A must be a non-negative number, not ~A"
     (ssh-config-line-keyword line) argument))
  (parse-integer argument))

(defun ssh-server-config-resolve-algorithms (line names supported option
                                             &key all)
  "NAMES resolved by SSH-RESOLVE-ALGORITHM-LIST, as a config error on LINE.

The shared resolver reports an ssh_config error, whose detail names the
algorithm and the option; re-signalling it as an sshd_config error keeps the
file and line number an operator needs."
  (handler-case
      (ssh-resolve-algorithm-list names supported option :all (or all supported))
    (ssh-config-error (condition)
      (ssh-server-config-line-error line "~A" (ssh-error-detail condition)))))

(defun ssh-parse-time (value)
  "VALUE as sshd's convtime reads a time, in seconds, or NIL.

A time is one or more decimal numbers, each followed by an optional unit:
s, m, h, d or w for seconds, minutes, hours, days and weeks.  A bare number
is seconds, so \"90\", \"1m30s\" and \"2W\" all work.  NIL is answered for
anything sshd would refuse, including a negative or out-of-range value."
  (when (and (stringp value) (plusp (length value)))
    (let ((position 0)
          (total 0)
          (length (length value)))
      (loop
        (when (>= position length)
          (return-from ssh-parse-time
            (if (<= total +ssh-server-max-time-value+) total nil)))
        ;; sshd's convtime is strtol-based and accepts a leading plus on
        ;; each component.
        (when (char= (char value position) #\+)
          (incf position))
        (let ((start position))
          (loop while (and (< position length)
                           (digit-char-p (char value position)))
                do (incf position))
          (when (= position start)
            (return-from ssh-parse-time nil))
          (let ((number (parse-integer value :start start :end position))
                (multiplier 1))
            (when (< position length)
              (let ((unit (char-downcase (char value position))))
                (incf position)
                (case unit
                  (#\s nil)
                  (#\m (setf multiplier 60))
                  (#\h (setf multiplier (* 60 60)))
                  (#\d (setf multiplier (* 60 60 24)))
                  (#\w (setf multiplier (* 60 60 24 7)))
                  (t (return-from ssh-parse-time nil)))))
            (when (> number (floor +ssh-server-max-time-value+
                                   multiplier))
              (return-from ssh-parse-time nil))
            (incf total (* number multiplier))
            (when (> total +ssh-server-max-time-value+)
              (return-from ssh-parse-time nil))))))))

(defun ssh-server-config-time-value (line argument)
  "ARGUMENT as a time in seconds, or an error naming LINE."
  (or (ssh-parse-time argument)
      (ssh-server-config-line-error
       line "~A needs a time value, not ~A"
       (ssh-config-line-keyword line) argument)))

(defun ssh-server-config-channel-timeout-pair (line argument)
  "VALUES TYPE-PATTERN SECONDS for one ChannelTimeout TYPE=INTERVAL argument.

The type may contain wildcards, as sshd's match_pattern allows, but must not
be empty.  INTERVAL uses sshd's time syntax and may be zero, which disables
that type's timeout."
  (let ((equals (position #\= argument)))
    (when (or (null equals) (zerop equals))
      (ssh-server-config-line-error
       line "invalid channel timeout ~A" argument))
    (let ((seconds (ssh-parse-time (subseq argument (1+ equals)))))
      (unless seconds
        (ssh-server-config-line-error
         line "invalid channel timeout ~A" argument))
      (values (subseq argument 0 equals) seconds))))

(defun ssh-server-config-split-host-port (line argument)
  "VALUES HOST, PORT-STRING for a sshd HOST[:PORT] argument.

A bracketed IPv6 literal may carry a port; a bare address with several
colons is a host with no port, as in OpenSSH."
  (let ((length (length argument)))
    (cond
      ((and (plusp length) (char= (char argument 0) #\[))
       (let ((close (position #\] argument)))
         (unless close
           (ssh-server-config-line-error line "bad address ~A" argument))
         (let* ((host (subseq argument 1 close))
                (rest (subseq argument (1+ close))))
           (cond
             ((zerop (length rest)) (values host nil))
             ((char= (char rest 0) #\:)
              (values host (subseq rest 1)))
             (t (ssh-server-config-line-error line "bad address ~A"
                                              argument))))))
      (t
       (let ((colon (position #\: argument)))
         (if (and colon
                  (not (position #\: argument :start (1+ colon))))
             (values (subseq argument 0 colon) (subseq argument (1+ colon)))
             (values argument nil)))))))

;;; ---- Keeping first obtained values ----

(defun ssh-server-config-set-once (config slot value)
  "Set SLOT unless an earlier directive already claimed it."
  (unless (slot-value config slot)
    (setf (slot-value config slot) value)))

(defun ssh-server-config-add-port (config line argument &key cmdline)
  "Add a Port value, refusing two listeners this server cannot serve.

A command-line Port (sshd's -o, or -p in the program) wins over the file's,
as sshd's ports_from_cmdline makes the file's Port lines fall on the floor."
  (let ((port (ssh-server-config-port-number line argument))
        (existing (ssh-server-config-ports config)))
    (cond
      ((null existing)
       (setf (ssh-server-config-ports config) (list port)))
      ((member port existing)
       ;; A repeated identical Port asks for nothing new.
       nil)
      ((and cmdline (ssh-server-config-ports-from-command-line config))
       (ssh-server-config-line-error
        line "multiple Port values are not supported; this server listens on one port"))
      ((ssh-server-config-ports-from-command-line config)
       ;; A file line after a command-line Port is ignored, as sshd's -p does.
       nil)
      (t
       (ssh-server-config-line-error
        line "multiple Port values are not supported; this server listens on one port")))))

(defun ssh-server-config-add-listen-address (config line argument &key cmdline)
  (when (and (not cmdline)
             (ssh-server-config-listen-addresses-from-command-line config))
    ;; A command-line ListenAddress replaced the file's, so stop here.
    (return-from ssh-server-config-add-listen-address nil))
  (when (ssh-server-config-listen-addresses config)
    (ssh-server-config-line-error
     line "multiple ListenAddress values are not supported; this server binds one address"))
  (multiple-value-bind (host port)
      (ssh-server-config-split-host-port line argument)
    (when (zerop (length host))
      (ssh-server-config-line-error line "bad ListenAddress ~A" argument))
    (let ((port (and port (ssh-server-config-port-number line port))))
      (push (cons host port)
            (ssh-server-config-listen-addresses config)))))

;;; ---- Match blocks ----

(defun ssh-server-config-cidr-valid-p (pattern)
  "Whether PATTERN is a CIDR this server can match, as sshd validates one."
  (let ((slash (position #\/ pattern)))
    (when slash
      (let* ((network (subseq pattern 0 slash))
             (bits-text (subseq pattern (1+ slash)))
             (bits (and (plusp (length bits-text))
                        (every #'digit-char-p bits-text)
                        (ignore-errors (parse-integer bits-text)))))
        (and bits
             (or (and (ssh-config-ipv4-octets network)
                      (<= 0 bits 32))
                 (and (ssh-config-ipv6-words network)
                      (<= 0 bits 128))))))))

(defun ssh-server-config-address-pattern-valid-p (patterns)
  "Whether every comma-separated element of PATTERNS is usable.

A CIDR must parse; every other element is an address glob, exactly the set
addr_match_list accepts.  An empty element or a bare ! is an error."
  (every (lambda (pattern)
           (let* ((negated (and (plusp (length pattern))
                                (char= (char pattern 0) #\!)))
                  (pattern (if negated (subseq pattern 1) pattern)))
             (and (plusp (length pattern))
                  (or (null (position #\/ pattern))
                      (ssh-server-config-cidr-valid-p pattern)))))
         (uiop:split-string patterns :separator ",")))

(defun ssh-server-config-match-criteria (line)
  "LINE's Match criteria as an SSH-SERVER-MATCH, or an error.

Attributes are ANDed, as sshd's match_cfg_line does; each takes one
comma-separated pattern argument, except all, which stands alone."
  (let ((arguments (ssh-config-line-args line))
        (criteria '()))
    (when (null arguments)
      (ssh-server-config-line-error line "Match needs criteria"))
    (loop while arguments
      do (let ((attribute (string-downcase (pop arguments))))
        (cond
          ((string= attribute "all")
           (when (or criteria arguments)
             (ssh-server-config-line-error
              line "'all' cannot be combined with other Match attributes"))
           (return-from ssh-server-config-match-criteria
             (%make-ssh-server-match :criteria '((:all)) :line line)))
          ((string= attribute "localaddress")
           (ssh-server-config-line-error
            line "Match LocalAddress is not supported by this server"))
          ((string= attribute "rdomain")
           (ssh-server-config-line-error
            line "Match RDomain is not supported by this server"))
          (t
           (let ((type (cdr (assoc attribute
                                   +ssh-server-config-match-attributes+
                                   :test #'string=))))
             (unless type
               (ssh-server-config-line-error
                line "unsupported Match attribute ~A" attribute))
             (let ((value (pop arguments)))
               (when (or (null value) (zerop (length value)))
                 (ssh-server-config-line-error
                  line "Missing Match criteria for ~A" attribute))
               (when (eq type :address)
                 (unless (ssh-server-config-address-pattern-valid-p value)
                   (ssh-server-config-line-error
                    line "Invalid Match address argument ~A" value)))
               (when (eq type :localport)
                 (unless (ssh-server-config-port-string value)
                   (ssh-server-config-line-error
                    line "Invalid LocalPort ~A on Match line" value)))
               (push (cons type value) criteria)))))))
    (when (null criteria)
      (ssh-server-config-line-error line "Match needs criteria"))
    (%make-ssh-server-match :criteria (nreverse criteria) :line line)))

(defun ssh-server-config-match-p (match
                                  &key user groups (groups-known t)
                                    address hostname local-port)
  "Whether MATCH's criteria all hold for one connection.

USER and GROUPS describe the account, ADDRESS and HOSTNAME the peer, and
LOCAL-PORT the listener that accepted it.  HOSTNAME defaults to ADDRESS
because this server's UseDNS is off, as sshd's default; HOST patterns are
matched case-insensitively.  An attribute whose value is unavailable is an
error, never an accidental no-match: sshd fatals in the same situation."
  (dolist (criterion (ssh-server-match-criteria match) t)
    (destructuring-bind (type . pattern) criterion
      (ecase type
        (:all t)
        (:user
         (unless user
           (error 'ssh-server-config-error
                  :path (ssh-config-line-path (ssh-server-match-line match))
                  :line (ssh-config-line-number
                         (ssh-server-match-line match))
                  :detail "Match User needs a user name"))
         (unless (ssh-match-pattern-list (list pattern) user)
           (return-from ssh-server-config-match-p nil)))
        (:group
         (unless groups-known
           (error 'ssh-server-config-error
                  :path (ssh-config-line-path (ssh-server-match-line match))
                  :line (ssh-config-line-number
                         (ssh-server-match-line match))
                  :detail "Match Group needs a user-groups callback"))
         ;; sshd's ga_match_pattern_list: a group matching a negated pattern
         ;; vetoes the whole block, whatever any other group matched.
         (let ((matched nil)
               (denied nil))
           (dolist (group groups)
             (cond
               ((ssh-pattern-list-denied-p (list pattern) group)
                (setf denied t))
               ((ssh-match-pattern-list (list pattern) group)
                (setf matched t))))
           (unless (and matched (not denied))
             (return-from ssh-server-config-match-p nil))))
        (:host
         (unless hostname
           (error 'ssh-server-config-error
                  :path (ssh-config-line-path (ssh-server-match-line match))
                  :line (ssh-config-line-number
                         (ssh-server-match-line match))
                  :detail "Match Host needs a host name"))
         (unless (ssh-match-pattern-list
                  (list (string-downcase pattern))
                  (string-downcase hostname))
           (return-from ssh-server-config-match-p nil)))
        (:address
         (unless address
           (error 'ssh-server-config-error
                  :path (ssh-config-line-path (ssh-server-match-line match))
                  :line (ssh-config-line-number
                         (ssh-server-match-line match))
                  :detail "Match Address needs a peer address"))
         (unless (ssh-address-pattern-match-p address pattern)
           (return-from ssh-server-config-match-p nil)))
        (:localport
         (unless local-port
           (error 'ssh-server-config-error
                  :path (ssh-config-line-path (ssh-server-match-line match))
                  :line (ssh-config-line-number
                         (ssh-server-match-line match))
                  :detail "Match LocalPort needs a local port"))
         (unless (= (ssh-server-config-port-string pattern) local-port)
           (return-from ssh-server-config-match-p nil)))))))

(defparameter +ssh-server-config-match-slots+
  '(permit-root-login max-auth-tries max-sessions
    client-alive-interval client-alive-count-max
    rekey-limit rekey-interval
    force-command chroot-directory banner authorized-keys-files accept-env permit-open
    permit-listen pubkey-accepted-algorithms required-rsa-size
    pubkey-auth-options max-pubkey-ok
    authentication-methods subsystems log-level
    hostbased-authentication hostbased-accepted-algorithms
    hostbased-uses-name-from-packet-only ignore-rhosts
    gateway-ports allow-tcp-forwarding allow-agent-forwarding
    agent-socket-path allow-streamlocal-forwarding
    streamlocal-bind-mask streamlocal-bind-unlink
    disable-forwarding set-env
    expose-auth-info refuse-connection
    unused-connection-timeout channel-timeouts
    trusted-user-ca-keys authorized-principals-file
    authorized-principals-command authorized-principals-command-user
    ca-signature-algorithms revoked-keys
    authorized-keys-command authorized-keys-command-user
    allow-users deny-users allow-groups deny-groups)
  "The fields a matching Match block may override.

They are the per-connection settings this server stores, the same set
sshd's copy_set_server_options merges from its second parse into the
running options.")

(defun ssh-server-config-merge-match (config overrides)
  "CONFIG with every non-empty field of OVERRIDES copied over it."
  (let ((copy (copy-structure config)))
    (dolist (slot +ssh-server-config-match-slots+ copy)
      (let ((value (slot-value overrides slot)))
        (cond
          ;; "DisableForwarding no" in a matching block turns off a global
          ;; yes, so this copies the flag even when the value is NIL.
          ((eq slot 'disable-forwarding)
           (when (ssh-server-config-disable-forwarding-set-p overrides)
             (setf (slot-value copy slot) value)))
          ((not (null value))
           (setf (slot-value copy slot) value)))))))

(defun ssh-server-config-for-connection (config
                                         &key user groups (groups-known t)
                                           address hostname local-port)
  "CONFIG with the Match blocks that hold for this connection applied.

This is sshd's second parse: global directives are not reconsidered, and
among the matching blocks the first obtained value wins, so a Match value
overrides the global one while later matches cannot override it.  CONFIG
itself is untouched; a copy is returned."
  (if (null (ssh-server-config-match-lines config))
      config
      (let ((overrides (%make-ssh-server-config))
            (matched nil))
        (dolist (entry (ssh-server-config-match-lines config))
          (when (ssh-server-config-match-p
                 (car entry)
                 :user user :groups groups :groups-known groups-known
                 :address address :hostname (or hostname address)
                 :local-port local-port)
            (setf matched t)
            (ssh-server-config-apply-line overrides (cdr entry))))
        (if matched
            (ssh-server-config-merge-match
             config (ssh-server-config-finalize overrides))
            config))))

;;; ---- Include ----

(defun ssh-server-config-include-path (argument)
  "An Include argument as a pathname, relative ones under /etc/ssh."
  (let ((value (ssh-config-expand-home argument)))
    (if (ssh-config-absolute-path-p value)
        (pathname value)
        (merge-pathnames value +ssh-server-config-directory+))))

(defun ssh-server-config-include (config line depth)
  (let ((arguments (ssh-config-line-args line)))
    (unless arguments
      (ssh-server-config-line-error line "Include needs a filename"))
    (push line (ssh-server-config-directives config))
    (dolist (argument arguments)
      (when (zerop (length argument))
        (ssh-server-config-line-error line "Include has an empty argument"))
      (dolist (file (ssh-config-include-files
                     (ssh-server-config-include-path argument)))
        (ssh-server-config-read-file config file (1+ depth))))))

;;; ---- Applying one directive ----

(defun ssh-server-config-apply-line (config line &key cmdline match)
  "Apply LINE to CONFIG, with sshd's validation and first-value-wins rule.

CMDLINE is true for a -o answer, which takes precedence over the file's
Port and ListenAddress the way sshd's own command-line options do.  MATCH is
true while checking a line inside a Match block: a keyword OpenSSH allows
only in the global section is refused, and so is a setting this server
cannot apply per connection."
  (let ((keyword (ssh-config-line-keyword line))
        (arguments (ssh-config-line-args line)))
    (when match
      (when (member keyword +ssh-server-config-global-only-keywords+
                    :test #'string=)
        (ssh-server-config-line-error
         line "~A is not allowed within a Match block" keyword)))
    (cond
      ;; ---- where to listen ----
      ((string= keyword "port")
       (ssh-server-config-add-port
        config line (ssh-server-config-one-argument line) :cmdline cmdline)
       (when cmdline
         (setf (ssh-server-config-ports-from-command-line config) t)))
      ((string= keyword "listenaddress")
       (ssh-server-config-add-listen-address
        config line (ssh-server-config-one-argument line) :cmdline cmdline)
       (when cmdline
         (setf (ssh-server-config-listen-addresses-from-command-line config)
               t)))
      ((string= keyword "addressfamily")
       (let ((value (string-downcase
                     (ssh-server-config-one-argument line))))
         (unless (member value '("inet" "any") :test #'string=)
           (ssh-server-config-line-error
            line "AddressFamily ~A is not supported; this server binds one IPv4 listener"
            value))
         (ssh-server-config-set-once config 'address-family value)))
      ;; ---- host keys and authentication ----
      ((string= keyword "hostkey")
       (push (ssh-config-expand-home
              (ssh-server-config-one-argument line))
             (ssh-server-config-host-key-files config)))
      ((string= keyword "hostkeyagent")
       (let ((value (ssh-server-config-one-argument line)))
         (ssh-server-config-set-once
          config 'host-key-agent
          (if (string-equal value "none") nil value))))
      ((string= keyword "hostcertificate")
       (push (ssh-config-expand-home
              (ssh-server-config-one-argument line))
             (ssh-server-config-host-certificate-files config)))
      ((string= keyword "authenticationmethods")
       ;; sshd keeps the first line's lists but validates every line; "any"
       ;; must stand alone, and later lines cannot add to the first.
       (when (null arguments)
         (ssh-server-config-line-error
          line "AuthenticationMethods needs a method list"))
       (let ((first (null (ssh-server-config-authentication-methods config)))
             (any-seen nil)
             (count 0))
         (dolist (argument arguments)
           (cond
             ((string-equal argument "any")
              ;; 10.6's rule: "any" must be alone on its own line.  A later
              ;; line is validated and then ignored because the first wins.
              (when (plusp count)
                (ssh-server-config-line-error
                 line "AuthenticationMethods \"any\" must appear alone"))
              (setf any-seen t))
             (any-seen
              (ssh-server-config-line-error
               line "AuthenticationMethods \"any\" must appear alone"))
             (t
              (ssh-server-config-check-authentication-methods
               line argument)))
           (incf count))
         (when first
           (setf (ssh-server-config-authentication-methods config)
                 (if any-seen :any arguments)))))
      ((string= keyword "authorizedkeysfile")
       (unless (ssh-server-config-authorized-keys-files config)
         (cond
           ((null arguments)
            (ssh-server-config-line-error
             line "AuthorizedKeysFile needs a filename"))
           (t
            ;; sshd keeps each name and skips the literal "none" while
            ;; authenticating, so "none" may sit beside real files.
            (setf (ssh-server-config-authorized-keys-files config)
                  (mapcar #'ssh-config-expand-home arguments))))))
      ((string= keyword "authorizedkeyscommand")
       (let ((value (ssh-config-line-raw line)))
         (when (zerop (length value))
           (ssh-server-config-line-error
            line "AuthorizedKeysCommand needs a command"))
         ;; sshd's parse_command: the program must be an absolute path, or
         ;; the word "none" to leave no command.
         (unless (or (char= (char value 0) #\/)
                     (string-equal value "none"))
           (ssh-server-config-line-error
            line "AuthorizedKeysCommand must be an absolute path"))
         (ssh-server-config-set-once
          config 'authorized-keys-command
          (if (string-equal value "none") :none value))))
      ((string= keyword "authorizedkeyscommanduser")
       (ssh-server-config-set-once
        config 'authorized-keys-command-user
        (ssh-server-config-one-argument line)))
      ((string= keyword "revokedkeys")
       ;; sshd's parse_filenames: one line may list several files, "none" must
       ;; appear alone, and only the first list is kept -- but every line is
       ;; still parsed, so a malformed later one is an error.
       (when (null arguments)
         (ssh-server-config-line-error
          line "RevokedKeys needs a filename"))
       (when (and (find "none" arguments :test #'string-equal)
                  (or (rest arguments)
                      (not (string-equal (first arguments) "none"))))
         (ssh-server-config-line-error
          line "RevokedKeys \"none\" must appear alone"))
       (unless (ssh-server-config-revoked-keys config)
         (setf (ssh-server-config-revoked-keys config)
               (if (string-equal (first arguments) "none")
                   :none
                   (mapcar #'ssh-config-expand-home arguments)))))
      ((string= keyword "trustedusercakeys")
       (let ((value (ssh-config-expand-home
                     (ssh-server-config-one-argument line))))
         (ssh-server-config-set-once
          config 'trusted-user-ca-keys
          (if (string-equal value "none") :none value))))
      ((string= keyword "authorizedprincipalsfile")
       ;; sshd keeps the pattern and expands %h/%u/%U for the account that is
       ;; logging in, so the file is not opened while the config is read.
       (let ((value (ssh-config-expand-home
                     (ssh-server-config-one-argument line))))
         (ssh-server-config-set-once
          config 'authorized-principals-file
          (if (string-equal value "none") :none value))))
      ((string= keyword "authorizedprincipalscommand")
       (let ((value (ssh-config-line-raw line)))
         (when (zerop (length value))
           (ssh-server-config-line-error
            line "AuthorizedPrincipalsCommand needs a command"))
         ;; sshd's parse_command, shared with AuthorizedKeysCommand: the
         ;; program must be an absolute path, or the word "none".
         (unless (or (char= (char value 0) #\/)
                     (string-equal value "none"))
           (ssh-server-config-line-error
            line "AuthorizedPrincipalsCommand must be an absolute path"))
         (ssh-server-config-set-once
          config 'authorized-principals-command value)))
      ((string= keyword "authorizedprincipalscommanduser")
       (ssh-server-config-set-once
        config 'authorized-principals-command-user
        (ssh-server-config-one-argument line)))
      ((string= keyword "hostbasedauthentication")
       (ssh-server-config-set-once
        config 'hostbased-authentication
        (if (ssh-server-config-flag
             line (ssh-server-config-one-argument line))
            :yes :no)))
      ((member keyword '("hostbasedacceptedalgorithms"
                         "hostbasedacceptedkeytypes")
               :test #'string=)
       (ssh-server-config-set-once
        config 'hostbased-accepted-algorithms
        (ssh-server-config-resolve-algorithms
         line arguments +ssh-server-host-key-preference+
         (ssh-config-line-keyword line)
         :all +ssh-server-host-key-all-algorithms+)))
      ((string= keyword "hostbasedusesnamefrompacketonly")
       (ssh-server-config-set-once
        config 'hostbased-uses-name-from-packet-only
        (if (ssh-server-config-flag
             line (ssh-server-config-one-argument line))
            :yes :no)))
      ((string= keyword "ignorerhosts")
       (ssh-server-config-set-once
        config 'ignore-rhosts
        (ssh-server-config-multistate
         line (ssh-server-config-one-argument line)
         '(("yes" . :yes) ("no" . :no) ("shosts-only" . :shosts-only))
         "IgnoreRhosts")))
      ((string= keyword "ignoreuserknownhosts")
       (ssh-server-config-set-once
        config 'ignore-user-known-hosts
        (ssh-server-config-flag
         line (ssh-server-config-one-argument line))))
      ((string= keyword "strictmodes")
       (ssh-server-config-set-once
        config 'strict-modes
        (if (ssh-server-config-flag
             line (ssh-server-config-one-argument line))
            :yes :no)))
      ((string= keyword "casignaturealgorithms")
       ;; Like PubkeyAcceptedAlgorithms this names signatures, not key types;
       ;; a plain name this build cannot verify stops startup instead of
       ;; quietly shrinking the set of certificates that would be accepted.
       (ssh-server-config-set-once
        config 'ca-signature-algorithms
        (ssh-server-config-resolve-algorithms
         line arguments +ssh-server-ca-signature-algorithms+
         "CASignatureAlgorithms"
         :all +ssh-server-ca-signature-algorithm-names+)))
      ;; ---- algorithms ----
      ;; sshd resolves these with kex_assemble_names: the configured text may
      ;; replace the default list or adjust it with + - ^.  Resolving here
      ;; means a typo stops the server at startup instead of narrowing the
      ;; offer silently, and the stored list is the exact order KEXINIT uses.
      ((string= keyword "ciphers")
       (ssh-server-config-set-once
        config 'ciphers
        (ssh-server-config-resolve-algorithms
         line arguments +ssh-ciphers+ "Ciphers")))
      ((string= keyword "macs")
       (ssh-server-config-set-once
        config 'macs
        (ssh-server-config-resolve-algorithms
         line arguments +ssh-macs+ "MACs")))
      ((string= keyword "kexalgorithms")
       (ssh-server-config-set-once
        config 'kex-algorithms
        ;; The strict-KEX and EXT_INFO markers are not negotiable methods;
        ;; they are added to every offer after this list is chosen.
        (ssh-server-config-resolve-algorithms
         line arguments +ssh-kex-real-algorithms+ "KexAlgorithms")))
      ((string= keyword "hostkeyalgorithms")
       (ssh-server-config-set-once
        config 'host-key-algorithms
        (ssh-server-config-resolve-algorithms
         line arguments +ssh-server-host-key-preference+
         "HostKeyAlgorithms"
         :all +ssh-server-host-key-all-algorithms+)))
      ((or (string= keyword "pubkeyacceptedalgorithms")
           (string= keyword "pubkeyacceptedkeytypes"))
       ;; PubkeyAcceptedKeyTypes is the obsolete name for the same field;
       ;; sshd keeps whichever line it reads first.
       (ssh-server-config-set-once
        config 'pubkey-accepted-algorithms
        (ssh-server-config-resolve-algorithms
         line arguments +ssh-server-user-key-algorithms+
         (ssh-config-line-keyword line)
         :all +ssh-server-user-key-all-algorithms+)))
      ((string= keyword "pubkeyauthoptions")
       ;; sshd keeps the first line's flags and max-pk-ok budget but still
       ;; validates every later line.
       (when (null arguments)
         (ssh-server-config-line-error
          line "PubkeyAuthOptions needs an option"))
       (let ((first (null (ssh-server-config-pubkey-auth-options config)))
             (flags '())
             (max nil)
             (saw nil))
         (dolist (argument arguments)
           (cond
             ((string-equal argument "none")
              (setf saw t))
             ((string-equal argument "touch-required")
              (setf saw t)
              (push :touch-required flags))
             ((string-equal argument "verify-required")
              (setf saw t)
              (push :verify-required flags))
             ((and (>= (length argument) 10)
                   (string-equal "max-pk-ok:" argument :end2 10))
              (let* ((text (subseq argument 10))
                     (value (and (plusp (length text))
                                 (every #'digit-char-p text)
                                 (parse-integer text))))
                (unless (and value (<= 0 value 255))
                  (ssh-server-config-line-error
                   line "bad PubkeyAuthOptions max-pk-ok value ~A" text))
                (setf saw t max value)))
             (t
              (ssh-server-config-line-error
               line "unsupported PubkeyAuthOptions option ~A" argument))))
         (unless saw
           (ssh-server-config-line-error
            line "PubkeyAuthOptions needs an option"))
         (when first
           (setf (ssh-server-config-pubkey-auth-options config)
                 (if flags (nreverse flags) :none)
                 (ssh-server-config-max-pubkey-ok config) max))))
      ((string= keyword "requiredrsasize")
       (ssh-server-config-set-once
        config 'required-rsa-size
        (ssh-server-config-count
         line (ssh-server-config-one-argument line))))
      ;; ---- environment ----
      ((string= keyword "acceptenv")
       (dolist (argument arguments)
         (when (or (zerop (length argument))
                   (find #\= argument))
           (ssh-server-config-line-error
            line "invalid environment name ~A" argument))
         (push argument (ssh-server-config-accept-env config))))
      ((string= keyword "setenv")
       ;; sshd honours only the first SetEnv directive; a later one is
       ;; ignored entirely, because the first is the value it obtains.
       (unless (ssh-server-config-set-env config)
         (when (null arguments)
           (ssh-server-config-line-error line "SetEnv needs an argument"))
         (dolist (argument arguments)
           (unless (and (plusp (length argument))
                        (find #\= argument))
             (ssh-server-config-line-error
              line "invalid SetEnv assignment ~A" argument))
           ;; A repeated name on the same line is ignored too.
           (let* ((equals (position #\= argument))
                  (name (subseq argument 0 equals)))
             (unless (find name (ssh-server-config-set-env config)
                           :key (lambda (assignment)
                                  (subseq assignment 0 (position #\= assignment)))
                           :test #'string=)
               (setf (ssh-server-config-set-env config)
                     (append (ssh-server-config-set-env config)
                             (list argument))))))))
      ((string= keyword "permituserenvironment")
       (let ((value (ssh-server-config-one-argument line)))
         (ssh-server-config-set-once
          config 'permit-user-environment
          (cond
            ((string-equal value "yes") :yes)
            ((string-equal value "no") :no)
            (t
             ;; Anything else is a pattern list of the names a user may set.
             (let ((patterns (uiop:split-string value :separator ",")))
               (when (some #'zerop (mapcar #'length patterns))
                 (ssh-server-config-line-error
                  line "empty PermitUserEnvironment pattern"))
               patterns))))))
      ((string= keyword "exposeauthinfo")
       ;; sshd's parse_flag: first value wins, and "no" is a value rather
       ;; than the absence of one, so a Match block can turn a global yes off.
       (ssh-server-config-set-once
        config 'expose-auth-info
        (if (ssh-server-config-flag
             line (ssh-server-config-one-argument line))
            :yes
            :no)))
      ((string= keyword "refuseconnection")
       ;; 10.6's flag: first value wins, and a Match block can turn a global
       ;; yes off, so "no" is stored as a value of its own.
       (ssh-server-config-set-once
        config 'refuse-connection
        (if (ssh-server-config-flag
             line (ssh-server-config-one-argument line))
            :yes
            :no)))
      ;; ---- forwarding policy ----
      ((string= keyword "permitopen")
       (when (null (ssh-server-config-permit-open config))
         (if (and (cdr arguments)
                  (member (string-downcase (first arguments))
                          '("any" "none") :test #'string=))
             (ssh-server-config-line-error
              line "PermitOpen ~A takes no other argument"
              (first arguments))
             (if (and (= (length arguments) 1)
                      (member (string-downcase (first arguments))
                              '("any" "none") :test #'string=))
                 (setf (ssh-server-config-permit-open config)
                       (list (string-downcase (first arguments))))
                 (dolist (argument arguments)
                   (multiple-value-bind (host port)
                       (ssh-server-config-split-host-port line argument)
                     (unless (and (plusp (length host))
                                  port
                                  (or (string= port "*")
                                      (ssh-server-config-port-string port)))
                       (ssh-server-config-line-error
                        line "bad PermitOpen ~A" argument))
                     (push argument
                           (ssh-server-config-permit-open config))))))))
      ((string= keyword "permitlisten")
       ;; PermitListen is PermitOpen's remote-forwarding counterpart.  sshd
       ;; treats a bare port as "*:port", because a client that asks for a
       ;; port without a host means every address.
       (when (null (ssh-server-config-permit-listen config))
         (if (and (cdr arguments)
                  (member (string-downcase (first arguments))
                          '("any" "none") :test #'string=))
             (ssh-server-config-line-error
              line "PermitListen ~A takes no other argument"
              (first arguments))
             (if (and (= (length arguments) 1)
                      (member (string-downcase (first arguments))
                              '("any" "none") :test #'string=))
                 (setf (ssh-server-config-permit-listen config)
                       (list (string-downcase (first arguments))))
                 (dolist (argument arguments)
                   (if (not (find #\: argument))
                       (let ((port (ssh-server-config-port-string argument)))
                         (unless port
                           (ssh-server-config-line-error
                            line "bad PermitListen ~A" argument))
                         (push (format nil "*:~A" argument)
                               (ssh-server-config-permit-listen config)))
                       (multiple-value-bind (host port)
                           (ssh-server-config-split-host-port line argument)
                         (unless (and (plusp (length host))
                                      port
                                      (or (string= port "*")
                                          (ssh-server-config-port-string port)))
                           (ssh-server-config-line-error
                            line "bad PermitListen ~A" argument))
                         (push argument
                               (ssh-server-config-permit-listen config)))))))))
      ((string= keyword "gatewayports")
       (ssh-server-config-set-once
        config 'gateway-ports
        (ssh-server-config-multistate
         line (ssh-server-config-one-argument line)
         +ssh-server-config-gateway-ports-values+ "GatewayPorts")))
      ((string= keyword "allowtcpforwarding")
       (ssh-server-config-set-once
        config 'allow-tcp-forwarding
        (ssh-server-config-multistate
         line (ssh-server-config-one-argument line)
         +ssh-server-config-tcp-forwarding-values+ "AllowTcpForwarding")))
      ((string= keyword "allowagentforwarding")
       (ssh-server-config-set-once
        config 'allow-agent-forwarding
        (if (ssh-server-config-flag
             line (ssh-server-config-one-argument line))
            :yes :no)))
      ((string= keyword "agentsocketpath")
       (let ((argument (ssh-server-config-one-argument line)))
         (when (and (not (string-equal argument "none"))
                    (not (and (> (length argument) 7)
                              (string-equal (subseq argument 0 7) "shared:")
                              (char= (char argument 7) #\/)))
                    (not (and (> (length argument) 5)
                              (string-equal (subseq argument 0 5) "user:"))))
           (ssh-server-config-line-error
            line "Invalid AgentSocketPath ~A" argument))
         (ssh-server-config-set-once
          config 'agent-socket-path argument)))
      ((string= keyword "allowstreamlocalforwarding")
       (ssh-server-config-set-once
        config 'allow-streamlocal-forwarding
        (ssh-server-config-multistate
         line (ssh-server-config-one-argument line)
         +ssh-server-config-tcp-forwarding-values+
         "AllowStreamLocalForwarding")))
      ((string= keyword "streamlocalbindmask")
       (let* ((text (ssh-server-config-one-argument line))
              (value (handler-case
                         (parse-integer text :radix 8)
                       (error () nil))))
         (unless (and value (<= 0 value #o777))
           (ssh-server-config-line-error
            line "Invalid StreamLocalBindMask ~A" text))
         (ssh-server-config-set-once
          config 'streamlocal-bind-mask value)))
      ((string= keyword "streamlocalbindunlink")
       (ssh-server-config-set-once
        config 'streamlocal-bind-unlink
        (ssh-server-config-flag
         line (ssh-server-config-one-argument line))))
      ((string= keyword "disableforwarding")
       (unless (ssh-server-config-disable-forwarding-set-p config)
         (setf (ssh-server-config-disable-forwarding config)
               (ssh-server-config-flag
                line (ssh-server-config-one-argument line))
               (ssh-server-config-disable-forwarding-set-p config) t)))
      ;; ---- account and connection policy ----
      ((member keyword '("allowusers" "denyusers"
                         "allowgroups" "denygroups")
               :test #'string=)
       (when (null arguments)
         (ssh-server-config-line-error line "~A needs a pattern" keyword))
       (let ((slot (cdr (assoc keyword
                               '(("allowusers" . allow-users)
                                 ("denyusers" . deny-users)
                                 ("allowgroups" . allow-groups)
                                 ("denygroups" . deny-groups))
                               :test #'string=))))
         (dolist (argument arguments)
           (when (zerop (length argument))
             (ssh-server-config-line-error line "empty ~A pattern" keyword))
           ;; An empty host part after @ would match nothing at all; sshd
           ;; rejects it, so a typo cannot quietly loosen the rule.
           (let ((at (position #\@ argument)))
             (when (and at (= (1+ at) (length argument)))
               (ssh-server-config-line-error
                line "~A pattern ~A names no host" keyword argument)))
           (push argument (slot-value config slot)))))
      ((string= keyword "permitrootlogin")
       (ssh-server-config-set-once
        config 'permit-root-login
        (ssh-server-config-multistate
         line (ssh-server-config-one-argument line)
         +ssh-server-config-permit-root-login-values+ "PermitRootLogin")))
      ((string= keyword "maxauthtries")
       (ssh-server-config-set-once
        config 'max-auth-tries
        (ssh-server-config-count
         line (ssh-server-config-one-argument line))))
      ((string= keyword "maxsessions")
       (ssh-server-config-set-once
        config 'max-sessions
        (ssh-server-config-count
         line (ssh-server-config-one-argument line))))
      ((string= keyword "logingracetime")
       (ssh-server-config-set-once
        config 'login-grace-time
        (ssh-server-config-time-value
         line (ssh-server-config-one-argument line))))
      ((string= keyword "clientaliveinterval")
       (ssh-server-config-set-once
        config 'client-alive-interval
        (ssh-server-config-time-value
         line (ssh-server-config-one-argument line))))
      ((string= keyword "clientalivecountmax")
       (ssh-server-config-set-once
        config 'client-alive-count-max
        (ssh-server-config-count
         line (ssh-server-config-one-argument line))))
      ((string= keyword "rekeylimit")
       (let ((arguments (ssh-config-line-args line)))
         (unless (<= 1 (length arguments) 2)
           (ssh-server-config-line-error
            line "RekeyLimit takes a size and an optional time"))
         (let* ((size-argument (first arguments))
                (bytes (if (string= size-argument "default")
                           0
                           (or (ssh-parse-scaled size-argument)
                               (ssh-server-config-line-error
                                line "Bad RekeyLimit number ~A"
                                size-argument)))))
           (when (and (plusp bytes) (< bytes 16))
             (ssh-server-config-line-error line "RekeyLimit too small"))
           (ssh-server-config-set-once config 'rekey-limit bytes)
           (when (second arguments)
             (let ((interval-argument (second arguments)))
               (unless (string= interval-argument "none")
                 (ssh-server-config-set-once
                  config 'rekey-interval
                  (ssh-server-config-time-value line interval-argument))))))))
      ;; ---- startup and idle limits ----
      ((string= keyword "maxstartups")
       ;; sshd takes BEGIN:RATE:FULL, or one number that is both the begin
       ;; and full value, and its later lines replace the earlier ones.
       (let ((parts (uiop:split-string
                     (ssh-server-config-one-argument line)
                     :separator ":")))
         (case (length parts)
           (1
            (let ((value (ssh-server-config-count line (first parts))))
              (unless (plusp value)
                (ssh-server-config-line-error line "Invalid MaxStartups spec"))
              (setf (ssh-server-config-max-startups-begin config) value
                    (ssh-server-config-max-startups-full config) value)))
           (3
            (let ((begin (ssh-server-config-count line (first parts)))
                  (rate (ssh-server-config-count line (second parts)))
                  (full (ssh-server-config-count line (third parts))))
              (unless (and (plusp begin)
                           (<= 1 rate 100)
                           (plusp full)
                           (<= begin full))
                (ssh-server-config-line-error line "Invalid MaxStartups spec"))
              (setf (ssh-server-config-max-startups-begin config) begin
                    (ssh-server-config-max-startups-rate config) rate
                    (ssh-server-config-max-startups-full config) full)))
           (otherwise
            (ssh-server-config-line-error line "Invalid MaxStartups spec")))))
      ((string= keyword "persourcemaxstartups")
       (let ((argument (ssh-server-config-one-argument line)))
         (setf (ssh-server-config-per-source-max-startups config)
               (unless (string-equal argument "none")
                 (ssh-server-config-count line argument)))))
      ((string= keyword "persourcenetblocksize")
       (let ((parts (uiop:split-string
                     (ssh-server-config-one-argument line)
                     :separator ":")))
         (unless (<= 1 (length parts) 2)
           (ssh-server-config-line-error
            line "Invalid PerSourceNetBlockSize spec"))
         (let ((ipv4 (ssh-server-config-count line (first parts))))
           (unless (<= 0 ipv4 32)
             (ssh-server-config-line-error
              line "Invalid PerSourceNetBlockSize spec"))
           (setf (ssh-server-config-per-source-net-block-size-ipv4 config)
                 ipv4))
         (when (second parts)
           (let ((ipv6 (ssh-server-config-count line (second parts))))
             (unless (<= 0 ipv6 128)
               (ssh-server-config-line-error
                line "Invalid PerSourceNetBlockSize spec"))
             (setf (ssh-server-config-per-source-net-block-size-ipv6 config)
                   ipv6)))))
      ((string= keyword "persourcepenaltyexemptlist")
       (let ((value (ssh-server-config-one-argument line)))
         (unless (ssh-server-config-address-pattern-valid-p value)
           (ssh-server-config-line-error
            line "Invalid PerSourcePenaltyExemptList"))
         (ssh-server-config-set-once
          config 'per-source-penalty-exempt value)))
      ((string= keyword "persourcepenalties")
       (when (null arguments)
         (ssh-server-config-line-error
          line "PerSourcePenalties needs an argument"))
       (let ((stored (ssh-server-config-per-source-penalties config))
             (duration-keys
               '(("crash:" . :crash)
                 ("authfail:" . :authfail)
                 ("invaliduser:" . :invaliduser)
                 ("noauth:" . :noauth)
                 ("grace-exceeded:" . :grace)
                 ("refuseconnection:" . :refuseconnection)
                 ("max:" . :max)
                 ("min:" . :min)
                 ("max-sources4:" . :max-sources4)
                 ("max-sources6:" . :max-sources6))))
         (dolist (argument arguments)
           (cond
             ((member argument '("no" "yes") :test #'string-equal)
              (when (rest arguments)
                (ssh-server-config-line-error
                 line "PerSourcePenalties ~A must appear alone" argument))
              (unless (member :enabled stored)
                (setf stored (append stored
                                    (list :enabled
                                          (string-equal argument "yes"))))))
             ((string-equal argument "overflow:deny-all")
              (unless (member :overflow4 stored)
                (setf stored (append stored (list :overflow4 :deny-all)))
                (unless (member :enabled stored)
                  (setf stored (append stored (list :enabled t))))))
             ((string-equal argument "overflow:permissive")
              (unless (member :overflow4 stored)
                (setf stored (append stored (list :overflow4 :permissive)))
                (unless (member :enabled stored)
                  (setf stored (append stored (list :enabled t))))))
             ((string-equal argument "overflow6:deny-all")
              (unless (member :overflow6 stored)
                (setf stored (append stored (list :overflow6 :deny-all)))
                (unless (member :enabled stored)
                  (setf stored (append stored (list :enabled t))))))
             ((string-equal argument "overflow6:permissive")
              (unless (member :overflow6 stored)
                (setf stored (append stored (list :overflow6 :permissive)))
                (unless (member :enabled stored)
                  (setf stored (append stored (list :enabled t))))))
             (t
              (let ((pair
                      (find-if
                       (lambda (entry)
                         (let ((prefix (car entry)))
                           (and (>= (length argument) (length prefix))
                                (string-equal prefix argument
                                              :end2 (length prefix)))))
                       duration-keys)))
                (unless pair
                  (ssh-server-config-line-error
                   line "unsupported PerSourcePenalties keyword ~A"
                   argument))
                (let* ((key (cdr pair))
                       (text (subseq argument (length (car pair))))
                       (value
                         (if (member key '(:max-sources4 :max-sources6))
                             (and (plusp (length text))
                                  (every #'digit-char-p text)
                                  (parse-integer text))
                             (ssh-parse-time text))))
                  (unless (and value (>= value 0))
                    (ssh-server-config-line-error
                     line "invalid PerSourcePenalties value ~A" text))
                  (unless (member key stored)
                    (setf stored (append stored (list key value))))
                  (unless (member :enabled stored)
                    (setf stored (append stored (list :enabled t)))))))))
         (setf (ssh-server-config-per-source-penalties config) stored)))
      ((string= keyword "unusedconnectiontimeout")
       (let ((argument (ssh-server-config-one-argument line)))
         (if (string-equal argument "none")
             ;; sshd stores 0 for "none" without the first-value test, so this
             ;; line turns the timeout off even after an earlier value.
             (setf (ssh-server-config-unused-connection-timeout config) 0)
             (ssh-server-config-set-once
              config 'unused-connection-timeout
              (ssh-server-config-time-value line argument)))))
      ((string= keyword "channeltimeout")
       ;; sshd keeps the first ChannelTimeout line as a whole: its pairs are
       ;; tried in order, and a later line cannot add to or replace them.
       ;; Every line is still validated, so a typo late in the file is fatal.
       ;; "none" must stand alone and means no channel times out.
       (when (null arguments)
         (ssh-server-config-line-error
          line "ChannelTimeout needs an argument"))
       (if (string-equal (first arguments) "none")
           (progn
             (when (rest arguments)
               (ssh-server-config-line-error
                line "ChannelTimeout \"none\" argument must appear alone"))
             (unless (ssh-server-config-channel-timeouts config)
               (setf (ssh-server-config-channel-timeouts config) :none)))
           (let ((pairs
                   (mapcar (lambda (argument)
                             (multiple-value-bind (type seconds)
                                 (ssh-server-config-channel-timeout-pair
                                  line argument)
                               (cons type seconds)))
                           arguments)))
             (unless (ssh-server-config-channel-timeouts config)
               (setf (ssh-server-config-channel-timeouts config) pairs)))))
      ((member keyword '("tcpkeepalive" "keepalive") :test #'string=)
       (ssh-server-config-set-once
        config 'tcp-keep-alive
        (if (ssh-server-config-flag
             line (ssh-server-config-one-argument line))
            :yes
            :no)))
      ((string= keyword "pidfile")
       ;; "none" disables the file, as in sshd; it is a value like any other
       ;; for first-wins purposes, so the reader keeps the spelling and the
       ;; writer recognises it.
       (ssh-server-config-set-once
        config 'pid-file (ssh-server-config-one-argument line)))
      ((string= keyword "forcecommand")
       ;; sshd keeps the whole remainder of the line, quotes included, and
       ;; hands it to the user's login shell with -c.  internal-sftp is an
       ;; in-process server this build does not have, so name the problem
       ;; instead of running a command that would fail obscurely.
       (let ((value (ssh-config-line-raw line)))
         (when (zerop (length value))
           (ssh-server-config-line-error
            line "ForceCommand needs a command"))
         (when (eql 0 (search "internal-sftp" value))
           (ssh-server-config-line-error
            line "ForceCommand internal-sftp is not supported; name an external sftp-server"))
         (ssh-server-config-set-once config 'force-command value)))
      ((string= keyword "chrootdirectory")
       ;; sshd expands ~ and %h/%u/%U when the session starts, so the raw
       ;; value is kept here; "none" clears the setting.
       (let ((value (ssh-server-config-one-argument line)))
         (ssh-server-config-set-once
          config 'chroot-directory
          (if (string-equal value "none") :none value))))
      ((string= keyword "banner")
       ;; sshd reads this file for each connection and ignores one it cannot
       ;; read, so the reader keeps the path and the program reads it later.
       (let ((value (ssh-server-config-one-argument line)))
         (ssh-server-config-set-once
          config 'banner
          (if (string-equal value "none") :none value))))
      ((string= keyword "versionaddendum")
       (let ((value (ssh-server-config-one-argument line)))
         ;; sshd allows a space here: the addendum is the comment after the
         ;; version in "SSH-2.0-name comment".  CR and LF would split the
         ;; greeting in two, so they are the one thing refused.
         (when (find-if (lambda (character)
                          (member character '(#\Return #\Newline)))
                        value)
           (ssh-server-config-line-error
            line "VersionAddendum must be one line"))
         (ssh-server-config-set-once
          config 'version-addendum
          (if (string-equal value "none") :none value))))
      ;; ---- subsystems ----
      ((string= keyword "subsystem")
       (unless (= (length arguments) 2)
         (ssh-server-config-line-error
          line "Subsystem needs a name and a command"))
       (let ((name (first arguments))
             (command (second arguments)))
         (when (zerop (length name))
           (ssh-server-config-line-error line "empty Subsystem name"))
         (when (zerop (length command))
           (ssh-server-config-line-error
            line "Subsystem ~A needs a command" name))
         (if (assoc name (ssh-server-config-subsystems config)
                    :test #'string=)
             (ssh-server-config-warn
              config "ignoring a duplicate Subsystem ~A" name)
             (push (cons name command)
                   (ssh-server-config-subsystems config)))))
      ;; ---- diagnostics ----
      ((string= keyword "loglevel")
       (ssh-server-config-set-once
        config 'log-level
        (ssh-server-config-multistate
         line (ssh-server-config-one-argument line)
         +ssh-server-config-log-levels+ "LogLevel")))
      ;; ---- no effect on this server ----
      ((member keyword +ssh-server-config-ignored-keywords+ :test #'string=)
       (ssh-server-config-warn
        config "ignoring ~A; this server has nothing for it to configure"
        keyword))
      ((assoc keyword +ssh-server-config-accepted-off-keywords+
              :test #'string=)
       (let ((required (cdr (assoc keyword
                                   +ssh-server-config-accepted-off-keywords+
                                   :test #'string=))))
         (dolist (argument arguments)
           (unless (string-equal argument required)
             (ssh-server-config-line-error
              line "~A ~A is not supported; this server behaves as if it were ~A"
              keyword argument required)))))
      ;; ---- refused ----
      ((string= keyword "match")
       (ssh-server-config-line-error
        line "Match is not allowed in a -o option"))
      ((member keyword +ssh-server-config-unsupported-keywords+
               :test #'string=)
       (ssh-server-config-line-error line "~A is not supported by this server"
                                     keyword))
      (t
       (ssh-server-config-line-error line "unknown keyword ~A" keyword)))))

;;; ---- Reading files ----

(defvar *ssh-server-config-match* nil
  "The Match criteria in force while reading, or NIL in the global section.")

(defun ssh-server-config-read-file (config path depth)
  "Read PATH into CONFIG, following Include lines as they appear.

Lines inside a Match block are recorded with their criteria and checked for
syntax; they are not applied until a connection's account is known.  Include
keeps the surrounding Match state, as sshd's include handling does."
  (when (> depth +ssh-config-max-depth+)
    (error 'ssh-server-config-error
           :path (namestring path)
           :detail "Include nesting is too deep"))
  (when (probe-file path)
    (with-open-file (stream path :direction :input :external-format :utf-8)
      (loop for text = (read-line stream nil nil)
            while text
            for number from 1
            do (let ((tokens (ssh-config-tokenize text)))
                 (when (and tokens
                            (plusp (length (first tokens)))
                            (not (char= (char (first tokens) 0) #\#)))
                   (let* ((keyword (string-downcase (first tokens)))
                          (line (%make-ssh-config-line
                                 :keyword keyword
                                 :args (rest tokens)
                                 :raw (ssh-config-line-remainder text)
                                 :path path
                                 :number number)))
                     (cond
                       ((string= keyword "include")
                        (ssh-server-config-include config line depth))
                       ((string= keyword "match")
                        (push line (ssh-server-config-directives config))
                        (setf *ssh-server-config-match*
                              (ssh-server-config-match-criteria line)))
                       (*ssh-server-config-match*
                        ;; Check the line without letting it touch the
                        ;; global values, as sshd's inactive first parse does.
                        (let ((check (%make-ssh-server-config)))
                          (ssh-server-config-apply-line check line :match t)
                          ;; Warnings about keywords with nothing to configure
                          ;; still belong to the file as a whole.
                          (dolist (warning (ssh-server-config-warnings check))
                            (push warning
                                  (ssh-server-config-warnings config))))
                        (push line (ssh-server-config-directives config))
                        (push (cons *ssh-server-config-match* line)
                              (ssh-server-config-match-lines config)))
                       (t
                        (push line (ssh-server-config-directives config))
                        (ssh-server-config-apply-line config line)))))))))
  config)

(defun ssh-server-config-apply-option-line (config text &key (source "command line"))
  "Apply one directive from TEXT, the way sshd applies -o.

OPTION lines are applied before the file, so under first-value-wins they
take precedence over it, exactly as sshd's -o does."
  (let ((tokens (ssh-config-tokenize text)))
    (cond
      ((null tokens)
       (error 'ssh-server-config-error :path source :line 0
              :detail "empty option"))
      ((char= (char (first tokens) 0) #\#)
       config)
      (t
       (let* ((keyword (string-downcase (first tokens)))
              (line (%make-ssh-config-line
                     :keyword keyword
                     :args (rest tokens)
                     :raw (ssh-config-line-remainder text)
                     :path source
                     :number 0)))
         (when (string= keyword "include")
           (ssh-server-config-line-error
            line "Include is not allowed on the command line"))
         (when (string= keyword "match")
           (ssh-server-config-line-error
            line "Match is not allowed on the command line"))
         (push line (ssh-server-config-directives config))
         (ssh-server-config-apply-line config line :cmdline t)
         config)))))

(defun ssh-server-config-finalize (config)
  "Put the accumulated lists in file order and return CONFIG."
  (macrolet ((reverse-slot (slot)
               `(setf (,slot config) (nreverse (,slot config)))))
    (reverse-slot ssh-server-config-directives)
    (reverse-slot ssh-server-config-ports)
    (reverse-slot ssh-server-config-listen-addresses)
    (reverse-slot ssh-server-config-host-key-files)
    (reverse-slot ssh-server-config-host-certificate-files)
    (reverse-slot ssh-server-config-accept-env)
    (reverse-slot ssh-server-config-permit-open)
    (reverse-slot ssh-server-config-permit-listen)
    (reverse-slot ssh-server-config-allow-users)
    (reverse-slot ssh-server-config-deny-users)
    (reverse-slot ssh-server-config-allow-groups)
    (reverse-slot ssh-server-config-deny-groups)
    (reverse-slot ssh-server-config-subsystems)
    (reverse-slot ssh-server-config-match-lines)
    (reverse-slot ssh-server-config-warnings))
  config)

(defun ssh-server-config-check-command-users (config)
  "Refuse an authorization command without its user.

This is sshd's startup check for AuthorizedKeysCommand and
AuthorizedPrincipalsCommand.  A Match block can still set the command and
inherit a user from the global section, so the check is made on the global
config once it has been read rather than per line.  \"none\" disables a
command and needs no user, as sshd's check allows."
  (let ((keys-command (ssh-server-config-authorized-keys-command config))
        (principals-command
          (ssh-server-config-authorized-principals-command config))
        (path (and (ssh-server-config-path config)
                   (namestring (ssh-server-config-path config)))))
    (when (and keys-command
               (not (eq keys-command :none))
               (null (ssh-server-config-authorized-keys-command-user config)))
      (error 'ssh-server-config-error
             :path path
             :detail "AuthorizedKeysCommand set without AuthorizedKeysCommandUser"))
    (when (and principals-command
               (not (string-equal principals-command "none"))
               (null (ssh-server-config-authorized-principals-command-user
                      config)))
      (error 'ssh-server-config-error
             :path path
             :detail
             "AuthorizedPrincipalsCommand set without AuthorizedPrincipalsCommandUser"))))

(defun ssh-server-config-load (path &key options)
  "Parse the sshd_config at PATH into an SSH-SERVER-CONFIG.

OPTIONS are directive lines applied before the file, as sshd's -o does.
PATH may be NIL, in which case only OPTIONS are read.  A missing file is an
error: the caller decides whether a default file is optional."
  (let ((config (%make-ssh-server-config :path path))
        (*ssh-server-config-match* nil))
    (dolist (option options)
      (ssh-server-config-apply-option-line config option))
    (when path
      (unless (probe-file path)
        (error 'ssh-server-config-error
               :path (namestring path)
               :detail "cannot read the server config"))
      (ssh-server-config-read-file config path 0))
    (ssh-server-config-finalize config)
    (ssh-server-config-check-command-users config)
    config))
