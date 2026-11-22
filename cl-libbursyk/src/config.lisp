(in-package #:cl-pnet-ssh)

;;;; ~/.ssh/config: the OpenSSH client configuration format, parsed the way
;;;; libssh parses it.  Keywords that cannot affect this client are accepted
;;;; and ignored; keywords that can affect a connection are turned into an
;;;; SSH-CONFIG-OPTIONS record.  Every parameter is "first obtained value
;;;; wins", and a Host or Match block only applies while it is selected.
;;;;
;;;; MATCH EXEC needs to run a command, which may take arbitrary time, so it
;;;; is a callback (EXEC-MATCHER) instead of a blocking POPEN: the library
;;;; never waits, and a caller may answer from the event loop.

(defparameter +ssh-config-max-depth+ 16
  "Include nesting limit, matching OpenSSH's own guard.")

(defparameter +ssh-config-directory+ #p"/etc/ssh/"
  "Where OpenSSH keeps ssh_config and sshd_config; a system configuration's
relative Include is anchored here.")

(defparameter +ssh-config-version+ "cl-pnet-ssh_0.0.1.19")

;;; Every keyword ssh's readconf.c accepts, plus this client's own
;;; HostbasedKey extension.  The parser below handles the ones that can
;;; change a connection; the rest are valid ssh_config that simply has
;;; nothing to configure here.  A keyword outside this set is a typo or
;;; belongs to a different program, and OpenSSH refuses it unless
;;; IgnoreUnknown names it, so this parser does the same.
(defparameter +ssh-config-client-keywords+
  '(
    "addkeystoagent" "addressfamily" "afstokenpassing" "batchmode" "bindaddress"
    "bindinterface" "canonicaldomains" "canonicalizefallbacklocal"
    "canonicalizehostname" "canonicalizemaxdots" "canonicalizepermittedcnames"
    "casignaturealgorithms" "certificatefile" "challengeresponseauthentication"
    "channeltimeout" "checkhostip" "cipher" "ciphers" "clearallforwardings"
    "compression" "compressionlevel" "connectionattempts" "connecttimeout"
    "controlmaster" "controlpath" "controlpersist" "dsaauthentication"
    "dynamicforward" "enableescapecommandline" "enablesshkeysign" "escapechar"
    "exitonforwardfailure" "fallbacktorsh" "fingerprinthash"
    "forkafterauthentication" "forwardagent" "forwardx11" "forwardx11timeout"
    "forwardx11trusted" "gatewayports" "globalknownhostsfile"
    "globalknownhostsfile2" "gssapiauthentication" "gssapidelegatecredentials"
    "hashknownhosts" "host" "hostbasedacceptedalgorithms" "hostbasedauthentication"
    "hostbasedkey" "hostbasedkeytypes" "hostkeyalgorithms" "hostkeyalias"
    "hostname" "identitiesonly" "identityagent" "identityfile" "identityfile2"
    "ignoreunknown" "include" "ipqos" "kbdinteractiveauthentication"
    "kbdinteractivedevices" "keepalive" "kerberosauthentication"
    "kerberostgtpassing" "kexalgorithms" "knownhostscommand" "localcommand"
    "localforward" "loglevel" "logverbose" "macs" "match"
    "nohostauthenticationforlocalhost" "numberofpasswordprompts"
    "obscurekeystroketiming" "passwordauthentication" "permitlocalcommand"
    "permitremoteopen" "pkcs11provider" "port" "preferredauthentications"
    "protocol" "proxycommand" "proxyjump" "proxyusefdpass"
    "pubkeyacceptedalgorithms" "pubkeyacceptedkeytypes" "pubkeyauthentication"
    "refuseconnection" "rekeylimit" "remotecommand" "remoteforward" "requesttty"
    "requiredrsasize" "revokedhostkeys" "rhostsauthentication"
    "rhostsrsaauthentication" "rsaauthentication" "securitykeyprovider" "sendenv"
    "serveralivecountmax" "serveraliveinterval" "sessiontype" "setenv"
    "skeyauthentication" "smartcarddevice" "stdinnull" "streamlocalbindmask"
    "streamlocalbindunlink" "stricthostkeychecking" "syslogfacility" "tag"
    "tcpkeepalive" "tisauthentication" "tunnel" "tunneldevice" "updatehostkeys"
    "useprivilegedport" "user" "userknownhostsfile" "userknownhostsfile2"
    "useroaming" "usersh" "verifyhostkeydns" "versionaddendum" "visualhostkey"
    "warnweakcrypto" "xauthlocation")
  "The client keywords this parser knows by name.

This is OpenSSH 10.6's keyword table with HostbasedKey, which OpenSSH does
not have and this client uses to name its host key for hostbased
authentication.  Knowing a name does not mean acting on it: a keyword that
has nothing to configure here stays accepted and ignored, exactly as before.
The table exists so a line that is not a keyword at all can be refused the
way ssh refuses it.")

(defstruct (ssh-config (:constructor %make-ssh-config))
  (path nil)
  (directives nil))

(defstruct (ssh-config-line (:constructor %make-ssh-config-line))
  (keyword nil)
  (args nil)
  ;; The arguments as they were written, after the keyword.  ProxyCommand
  ;; needs this: OpenSSH hands the rest of the line to the shell verbatim, so
  ;; quotes and internal spacing have to survive tokenization.
  (raw nil)
  (path nil)
  (number nil))

(defstruct (ssh-config-context (:constructor %make-ssh-config-context))
  (original-host nil)
  (user nil)
  (port 22)
  (tag nil)
  (local-addresses nil))

(defstruct (ssh-config-options (:constructor %make-ssh-config-options))
  (hostname nil)
  ;; Set when a Match final line asked for the second configuration pass that
  ;; OpenSSH runs after hostname canonicalization.
  (final-pass-wanted nil)
  ;; CanonicalizeHostname and its search rules.
  (canonicalize-hostname :no)
  (canonical-domains '())
  (canonicalize-max-dots 1)
  (canonicalize-fallback-local t)
  (canonicalize-permitted-cnames '())
  (user nil)
  (port nil)
  (identity-files nil)
  (certificate-files nil)
  (identity-agent nil)
  ;; HostbasedAuthentication and its host keys.  EnableSSHKeysign is parsed
  ;; for compatibility; this client signs with a readable host key directly.
  (hostbased-authentication nil)
  (hostbased-accepted-algorithms nil)
  (hostbased-keys '())
  (enable-ssh-keysign nil)
  ;; AddKeysToAgent: :YES adds keys loaded from files to the agent.
  (add-keys-to-agent nil)
  ;; HostKeyAlias: the name known_hosts is checked and written under.
  (host-key-alias nil)
  (identities-only nil)
  (known-hosts nil)
  (global-known-hosts nil)
  ;; NoHostAuthenticationForLocalhost: trust a loopback host's key as-is.
  (no-host-authentication-for-localhost nil)
  (hash-known-hosts nil)
  (known-hosts-command nil)
  ;; IgnoreUnknown: a comma-separated pattern list naming unknown keywords to
  ;; accept instead of refusing, as ssh does.
  (ignored-unknown nil)
  ;; UpdateHostKeys: :YES adds keys the server proves it owns, :NO does
  ;; nothing, and :ASK is treated as no by this non-interactive client.
  (update-host-keys nil)
  ;; FingerprintHash: :SHA256 (the default) or :MD5 for displayed
  ;; fingerprints.
  (fingerprint-hash nil)
  (visual-host-key nil)
  (check-host-ip nil)
  ;; VerifyHostKeyDNS: :YES accepts a matching SSHFP record only when the
  ;; answer was DNSSEC-validated; :ASK looks records up but always leaves the
  ;; decision to known_hosts; :NO skips DNS.
  (verify-host-key-dns nil)
  ;; RevokedHostKeys: files of host keys and certificates that may not be
  ;; used, in the order read; NONE clears the list.
  (revoked-host-keys '())
  (strict-host-key-checking nil)
  (host-key-algorithms nil)
  (pubkey-accepted-algorithms nil)
  ;; CASignatureAlgorithms: signature algorithms a certificate authority may
  ;; use; SHA-1 ssh-rsa is not in the default list.
  (ca-signature-algorithms nil)
  (kex-algorithms nil)
  (ciphers nil)
  (macs nil)
  (compression nil)
  (connect-timeout nil)
  (connection-attempts nil)
  (server-alive-interval nil)
  (server-alive-count-max nil)
  (bind-address nil)
  (address-family nil)
  (batch-mode nil)
  ;; WarnWeakCrypto: :NO suppresses the post-quantum key-exchange warning,
  ;; :YES asks for it, and NIL means ssh's default of yes.  The 10.6
  ;; "no-pq-kex" spelling also selects :NO, as readconf's multistate does.
  (warn-weak-crypto nil)
  ;; ObscureKeystrokeTiming: the interval in milliseconds between quantised
  ;; keystrokes, 0 when disabled, or NIL when the file did not say.  ssh's
  ;; default is 20ms.
  (obscure-keystroke-timing nil)
  (preferred-authentications nil)
  (pubkey-authentication nil)
  ;; Both default to yes in ssh; a slot of NIL would otherwise make an
  ;; unset keyword indistinguishable from an explicit "no" in -G.
  (password-authentication t)
  (kbd-interactive-authentication t)
  (number-of-password-prompts nil)
  (send-env nil)
  ;; SetEnv: NAME=VALUE pairs sent to the server on every session, in the
  ;; order the first active SetEnv line named them.
  (set-env nil)
  (proxy-jump nil)
  (proxy-command nil)
  ;; RekeyLimit: the byte volume before rekeying and the optional time
  ;; interval, each NIL until an active line sets it.  0 is OpenSSH's
  ;; "default" volume, meaning the cipher's own limit, and a 0 interval
  ;; disables time-based rekeying.
  (rekey-limit nil)
  (rekey-interval nil)
  ;; ForwardAgent: T enables it, NIL leaves it off.  A path instead of yes
  ;; selects the agent socket to forward, as ssh 10.6 allows.
  (forward-agent nil)
  (forward-agent-sock-path nil)
  (forward-x11 nil)
  (forward-x11-trusted nil)
  ;; ForwardX11Timeout: how long untrusted forwarding keeps accepting new
  ;; X11 channels.  NIL is OpenSSH's 1200-second default and 0 disables the
  ;; limit, as ssh_config's NONE and 0 do.
  (forward-x11-timeout nil)
  (gateway-ports nil)
  ;; GSSAPIAuthentication and GSSAPIDelegateCredentials have no
  ;; implementation here; they are parsed so an ssh_config that turns them
  ;; off (the usual default) is not refused, and -G can print the value.
  (gssapi-authentication nil)
  (gssapi-delegate-credentials nil)
  ;; BindInterface names the local interface whose address ssh binds the
  ;; source to.  Parsed for diagnosis; the dialer has no interface support.
  (bind-interface nil)
  ;; KbdInteractiveDevices, PKCS11Provider, SecurityKeyProvider, SyslogFacility
  ;; and XAuthLocation are inert here but are part of ssh's effective
  ;; configuration, so -G can report them.
  (kbd-interactive-devices nil)
  (pkcs11-provider nil)
  (security-key-provider nil)
  (syslog-facility nil)
  (xauth-location nil)
  ;; ProxyUseFdpass asks the ProxyCommand helper to pass back a connected
  ;; descriptor; this build reads the helper's stdout instead.
  (proxy-use-fdpass nil)
  ;; Tunnel and TunnelDevice: :NO, :YES, :ETHERNET or :POINT-TO-POINT, and a
  ;; (LOCAL . REMOTE) pair where each side is an integer or :ANY.
  (tunnel nil)
  (tunnel-device nil)
  ;; IPQoS: the DSCP value for interactive and bulk sessions; :NONE means
  ;; the operating system default.  ssh's defaults are ef and none.
  (ip-qos-interactive #xb8)
  (ip-qos-bulk :none)
  (exit-on-forward-failure nil)
  ;; PermitRemoteOpen: NIL or :ANY permits every remote-forward target,
  ;; :NONE permits none, and a list holds (HOST . PORT) entries where either
  ;; part may be :ANY.
  (permit-remote-open nil)
  ;; TCPKeepAlive defaults to yes, as it does in ssh.
  (tcp-keep-alive t)
  ;; RequiredRSASize: the smallest RSA modulus this client will use for a
  ;; host key or an authentication key; OpenSSH's default is 1024.
  (required-rsa-size nil)
  ;; StreamLocalBindMask and StreamLocalBindUnlink for Unix-socket listeners
  ;; this client creates; OpenSSH's defaults are 0177 and no.
  (streamlocal-bind-mask nil)
  (streamlocal-bind-unlink nil)
  (clear-all-forwardings nil)
  (local-forwards nil)
  (remote-forwards nil)
  (dynamic-forwards nil)
  (request-tty nil)
  ;; EscapeChar and EnableEscapeCommandline: the interactive escape
  ;; character, and whether its command line may be opened.
  (escape-char nil)
  (enable-escape-commandline nil)
  ;; LocalCommand and PermitLocalCommand: a shell command run locally after
  ;; the connection is up, but only when explicitly permitted.
  (local-command nil)
  (permit-local-command nil)
  ;; RemoteCommand: the command ssh runs on the peer when the command line
  ;; names none.  Stored as written; the caller expands its % tokens.
  (remote-command nil)
  ;; VersionAddendum: text appended to our identification string, "" for an
  ;; explicit "none", or NIL when the keyword never appeared.
  (version-addendum nil)
  ;; SessionType and StdinNull: whether to open a session at all, whether the
  ;; command names a subsystem, and whether stdin is /dev/null.
  (session-type nil)
  (stdin-null nil)
  (fork-after-authentication nil)
  ;; ChannelTimeout: the PATTERN=INTERVAL arguments as written, in the order
  ;; the first active line named them, :NONE for an explicit "none", or NIL
  ;; when the keyword never appeared.  A "global" pattern bounds the whole
  ;; connection.  The text is kept for -G; the policy layer parses it.
  (channel-timeouts nil)
  ;; ControlMaster, ControlPath and ControlPersist: whether this client may
  ;; listen for multiplexed sessions, where the control socket lives, and how
  ;; long a background master outlives its last session.  :YES, :NO, :ASK,
  ;; :AUTO and :AUTOASK are the ControlMaster values; :NONE on the path means
  ;; multiplexing is disabled, and :NO or a number of seconds is the persist
  ;; timeout.
  (control-master nil)
  (control-path nil)
  (control-persist nil)
  (tag nil)
  ;; LogLevel and LogVerbose: how much this client logs, and per-area
  ;; overrides.  LogVerbose is accepted for ssh_config compatibility; this
  ;; client has no per-area log categories to turn up.
  (log-level nil)
  (log-verbose nil)
  (extra nil))

(defparameter +ssh-default-identity-names+
  '("id_ed25519" "id_ecdsa" "id_rsa")
  "Identity files OpenSSH would try, in the order offered here.

ed25519 comes first because it is what OpenSSH generates by default; ECDSA
and RSA follow because many existing accounts still have only one of those.
This is a config default rather than backend state, so the libssh build
reports the same identityfile lines as the pure one.")

(defun ssh-default-user ()
  "The local user name, or ROOT when the environment does not say."
  (or (uiop:getenv "USER")
      (uiop:getenv "LOGNAME")
      "root"))

;;; ---- Tokens ----

(defun ssh-config-whitespace-p (character)
  (member character '(#\Space #\Tab #\Return #\Newline)))

(defun ssh-config-escapable-p (character)
  (member character '(#\\ #\' #\" #\Space #\Tab)))

(defun ssh-config-tokenize (line)
  "LINE as config tokens.

Whitespace and, around the keyword only, an unquoted '=' separate tokens;
single or double quotes group a value and are removed.  A backslash drops
only before a quote, a backslash or whitespace, exactly like OpenSSH's argv
splitter.

Only the keyword may use Keyword=value: an argument keeps every '=' it has,
so \"SetEnv LANG=en_US.UTF-8\" is one assignment and not two tokens."
  (let ((tokens '())
        (token (make-string-output-stream))
        (started nil)
        (quote nil))
    (labels ((emit-token ()
               (when started
                 (push (get-output-stream-string token) tokens)
                 (setf started nil))))
      (loop with length = (length line)
            for index from 0 below length
            for character = (char line index)
            do (cond
                 (quote
                  (cond
                    ((char= character quote)
                     (setf quote nil started t))
                    ((char= character #\\)
                     (if (and (< (1+ index) length)
                              (ssh-config-escapable-p (char line (1+ index))))
                         (progn (incf index)
                                (write-char (char line index) token)
                                (setf started t))
                         (write-char character token)))
                    (t
                     (write-char character token)
                     (setf started t))))
                 ((or (ssh-config-whitespace-p character)
                      ;; A '=' after the keyword has begun a second token is
                      ;; part of that value.
                      (and (char= character #\=)
                           (or (null tokens) (not started))))
                  (emit-token))
                 ((or (char= character #\') (char= character #\"))
                  (setf quote character started t))
                 ((char= character #\\)
                  (if (and (< (1+ index) length)
                           (ssh-config-escapable-p (char line (1+ index))))
                      (progn (incf index)
                             (write-char (char line index) token))
                      (write-char character token))
                  (setf started t))
                 (t
                  (write-char character token)
                  (setf started t))))
      (emit-token))
    (nreverse tokens)))

(defun ssh-config-line-remainder (text)
  "TEXT after its first token, with the original quotes and spacing kept.

The keyword is TEXT's first token; whatever follows the whitespace or '='
that separates it is returned verbatim, because OpenSSH passes a
ProxyCommand's arguments to the shell exactly as written."
  (let* ((length (length text))
         (start (position-if-not #'ssh-config-whitespace-p text))
         (end (and start
                   (position-if (lambda (character)
                                  (or (ssh-config-whitespace-p character)
                                      (char= character #\=)))
                                text :start start))))
    (if end
        (string-trim '(#\Space #\Tab #\Return)
                     (subseq text (if (char= (char text end) #\=)
                                      (1+ end)
                                      end)))
        "")))

;;; ---- Globs ----

(defun ssh-config-class-match-p (pattern start character)
  "Whether CHARACTER is in the bracket class at START.

Returns (values MATCHED END).  END is NIL when the class is unterminated, so
the caller can treat the '[' literally."
  (let ((length (length pattern))
        (index (1+ start))
        (negated nil)
        (matched nil)
        (first t))
    (when (and (< index length)
               (member (char pattern index) '(#\! #\^)))
      (setf negated t)
      (incf index))
    (loop while (< index length)
          do (let ((character-in-class (char pattern index)))
               (cond
                 ((and (char= character-in-class #\]) (not first))
                  (return (values (if negated (not matched) matched)
                                  (1+ index))))
                 ((and (< (+ index 2) length)
                       (char= (char pattern (1+ index)) #\-)
                       (not (char= (char pattern (+ index 2)) #\])))
                  (when (and character
                             (char<= character-in-class character
                                     (char pattern (+ index 2))))
                    (setf matched t))
                  (incf index 3))
                 (t
                  (when (and character (char= character-in-class character))
                    (setf matched t))
                  (incf index)))
               (setf first nil)))
    (values nil nil)))

(defun ssh-config-glob-match (pattern text)
  "A case-sensitive glob match supporting *, ? and [..] classes."
  (labels ((match (pattern-index text-index)
             (cond
               ((= pattern-index (length pattern))
                (= text-index (length text)))
               ((char= (char pattern pattern-index) #\*)
                (or (match (1+ pattern-index) text-index)
                    (and (< text-index (length text))
                         (match pattern-index (1+ text-index)))))
               ((char= (char pattern pattern-index) #\?)
                (and (< text-index (length text))
                     (match (1+ pattern-index) (1+ text-index))))
               ((char= (char pattern pattern-index) #\[)
                (multiple-value-bind (matched next)
                    (ssh-config-class-match-p
                     pattern pattern-index
                     (and (< text-index (length text)) (char text text-index)))
                  (if next
                      (and matched (match next (1+ text-index)))
                      (and (< text-index (length text))
                           (char= #\[ (char text text-index))
                           (match (1+ pattern-index) (1+ text-index))))))
               (t
                (and (< text-index (length text))
                     (char= (char pattern pattern-index)
                            (char text text-index))
                     (match (1+ pattern-index) (1+ text-index)))))))
    (match 0 0)))

;;; ---- Paths and Include ----

(defun ssh-config-absolute-path-p (path)
  (let ((directory (pathname-directory (pathname path))))
    (and directory (eq (car directory) :absolute))))

(defun ssh-config-expand-home (path)
  "Replace a leading ~ with the current user's home directory."
  (cond
    ((string= path "~") (namestring (user-homedir-pathname)))
    ((and (> (length path) 1) (string= (subseq path 0 2) "~/"))
     (namestring (merge-pathnames (subseq path 2) (user-homedir-pathname))))
    (t path)))

(defun ssh-config-expand-variables (value)
  "Expand $NAME and ${NAME} from the environment, leaving unknown names."
  (with-output-to-string (out)
    (loop with length = (length value)
          for index from 0 below length
          for character = (char value index)
          do (if (char= character #\$)
                 (let* ((braced (and (< (1+ index) length)
                                     (char= (char value (1+ index)) #\{)))
                        (start (+ index (if braced 2 1)))
                        (end (and braced (position #\} value :start start)))
                        (stop (or end
                                  (position-if (lambda (c)
                                                 (or (ssh-config-whitespace-p c)
                                                     (member c '(#\/ #\: #\,))))
                                               value :start start)
                                  length)))
                   (if (< start stop)
                       (let ((name (subseq value start stop))
                             (replacement (and (< start stop)
                                               (uiop:getenv
                                                (subseq value start stop)))))
                         (if replacement
                             (progn (write-string replacement out)
                                    (setf index (if end end (1- stop))))
                             (write-char character out)))
                       (write-char character out)))
                 (write-char character out)))))

(defun ssh-config-connection-hash (local-host host port user jump-host)
  "The %C value: SHA-1 over the connection's identity, as lowercase hex."
  (format nil "~{~2,'0x~}"
          (coerce
           (ssh-hash :sha1
                     (ssh-string-octets
                      (format nil "~A~A~A~A~A"
                              local-host host port user jump-host)))
           'list)))

(defun ssh-config-expand-tokens (value options context &key strict jump-host)
  "Expand the OpenSSH % tokens VALUE may contain.

%h is the configured HostName, %n the host as written, and the rest follow
ssh: %p port, %r remote user, %u local user, %d home, %i uid, %k
HostKeyAlias, %j jump host, %l and %L the local name, %C the connection
hash.  An unknown token is copied literally unless STRICT is set, in which
case it is an error as it is for VersionAddendum."
  (let* ((context-host (or (ssh-config-context-original-host context) ""))
         (host (or (ssh-config-options-hostname options) context-host))
         (user (or (ssh-config-options-user options)
                   (ssh-config-context-user context)
                   (ssh-default-user)))
         (port (or (ssh-config-options-port options)
                   (ssh-config-context-port context)
                   22))
         (local-user (ssh-default-user))
         (local-host (or (uiop:getenv "HOSTNAME")
                         (machine-instance)
                         "localhost"))
         (short-host (subseq local-host 0
                             (or (position #\. local-host)
                                 (length local-host))))
         (key-alias (or (ssh-config-options-host-key-alias options) ""))
         (jump (or jump-host "")))
    (with-output-to-string (out)
      (loop with length = (length value)
            for index from 0 below length
            for character = (char value index)
            do (if (and (char= character #\%)
                        (< (1+ index) length))
                   (let ((token (char value (1+ index))))
                     (case token
                       (#\% (write-char #\% out) (incf index))
                       (#\h (princ host out) (incf index))
                       (#\n (princ context-host out) (incf index))
                       (#\p (princ port out) (incf index))
                       (#\r (princ user out) (incf index))
                       (#\u (princ local-user out) (incf index))
                       (#\d (princ (string-right-trim
                                    "/" (namestring (user-homedir-pathname)))
                                   out)
                            (incf index))
                       (#\i (princ (or (uiop:getenv "UID") "") out) (incf index))
                       (#\k (princ key-alias out) (incf index))
                       (#\j (princ jump out) (incf index))
                       (#\l (princ local-host out) (incf index))
                       (#\L (princ short-host out) (incf index))
                       (#\C (princ (ssh-config-connection-hash
                                    local-host host port user jump)
                                   out)
                            (incf index))
                       (t (if strict
                              (error 'ssh-config-error
                                     :detail
                                     (format nil
                                             "unknown percent token %~A in ~S"
                                             token value))
                              (write-char character out)))))
                   (write-char character out))))))

(defun ssh-config-path-argument (value options context)
  "VALUE as a pathname with %, $ and ~ expanded."
  (let ((value (ssh-config-expand-variables
                (ssh-config-expand-tokens value options context))))
    (let ((value (ssh-config-expand-home value)))
      (if (ssh-config-absolute-path-p value)
          (pathname value)
          (merge-pathnames value (user-homedir-pathname))))))

(defun ssh-config-path-value (line options context)
  "A path argument with %, $ and ~ expanded."
  (ssh-config-path-argument (ssh-config-arg line) options context))

(defun ssh-config-include-path (argument &key (user-config t))
  "An Include argument as a pathname, relative ones anchored like OpenSSH.

A user configuration resolves a relative Include under ~/.ssh and a system
configuration under /etc/ssh."
  (let ((value (ssh-config-expand-home argument)))
    (if (ssh-config-absolute-path-p value)
        (pathname value)
        (merge-pathnames value
                         (if user-config
                             (merge-pathnames ".ssh/"
                                              (user-homedir-pathname))
                             +ssh-config-directory+)))))

(defun ssh-config-include-files (path)
  "The existing files PATH names, expanding wildcards in its last component."
  (let* ((path (pathname path))
         (name (file-namestring path))
         (directory (directory-namestring path)))
    (cond
      ((find-if (lambda (c) (member c '(#\* #\? #\[))) directory)
       (sort (directory path) #'string< :key #'namestring))
      ((find-if (lambda (c) (member c '(#\* #\? #\[))) name)
       (remove-if-not (lambda (file)
                        (ssh-config-glob-match name (file-namestring file)))
                      (handler-case (uiop:directory-files directory)
                        (file-error () '()))))
      ((probe-file path) (list (probe-file path)))
      (t nil))))

(defun ssh-config-read-directives (path depth &key (user-config t))
  "Read PATH into directives, expanding Include lines as they appear.

USER-CONFIG says whether PATH is a user configuration, which decides where a
relative Include is anchored and whether ~ is allowed in one."
  (when (> depth +ssh-config-max-depth+)
    (error 'ssh-config-error
           :path (namestring path)
           :detail "Include nesting is too deep"))
  (unless (probe-file path)
    (return-from ssh-config-read-directives '()))
  (let ((directives '())
        (number 0))
    (with-open-file (stream path :direction :input :external-format :utf-8)
      (loop for line = (read-line stream nil nil)
            while line
            do (incf number)
               (let ((tokens (ssh-config-tokenize line)))
                 (when (and tokens
                            (plusp (length (first tokens)))
                            (not (char= (char (first tokens) 0) #\#)))
                   (let ((keyword (string-downcase (first tokens))))
                     (if (string= keyword "include")
                         (dolist (argument (rest tokens))
                           (when (and (not user-config)
                                      (plusp (length argument))
                                      (char= (char argument 0) #\~))
                             (error 'ssh-config-error
                                    :path (namestring path)
                                    :line number
                                    :keyword "include"
                                    :detail
                                    (format nil "a system configuration may not include ~A"
                                            argument)))
                           (dolist (file (ssh-config-include-files
                                          (ssh-config-include-path
                                           argument :user-config user-config)))
                             (setf directives
                                   (nconc directives
                                          (ssh-config-read-directives
                                           file (1+ depth)
                                           :user-config user-config)))))
                         (push (%make-ssh-config-line
                                :keyword keyword
                                :args (rest tokens)
                                :raw (ssh-config-line-remainder line)
                                :path path
                                :number number)
                               directives)))))))
    (nreverse directives)))

(defun ssh-config-load (path &key (user-config t))
  "Parse the ssh_config file at PATH into an SSH-CONFIG, or NIL if absent.

USER-CONFIG selects user-configuration Include anchoring, as OpenSSH does for
~/.ssh/config and for a -F file; NIL is the system ssh_config."
  (let ((path (pathname (ssh-config-expand-home (namestring path)))))
    (when (probe-file path)
      (%make-ssh-config :path path
                        :directives (ssh-config-read-directives path 0)))))

(defun ssh-config-combine (&rest configs)
  "CONFIGS as one directive stream, in the order given, skipping absent ones.

OpenSSH reads ~/.ssh/config first and the system file after it, and keeps
the first value it obtains for each keyword, so appending in that order
preserves the same precedence."
  (let ((present (remove nil configs)))
    (cond
      ((null present) (%make-ssh-config))
      ((null (rest present)) (first present))
      (t
       (%make-ssh-config
        :path (ssh-config-path (first present))
        :directives
        (mapcan (lambda (config)
                  (copy-list (ssh-config-directives config)))
                present))))))

;;; ---- Command-line -o options ----

(defun ssh-config-option-line (option)
  "One -o OPTION as an SSH-CONFIG-LINE.

OPTION is the text ssh itself accepts after -o, either \"Keyword value\" or
\"Keyword=value\", or a cons of a keyword and its argument (or arguments).
Every keyword the file understands works here too, including HostName."
  (flet ((line (keyword args &optional raw)
           (unless (plusp (length keyword))
             (error 'ssh-config-error :detail "an -o option has no keyword"))
           (%make-ssh-config-line
            :keyword (string-downcase keyword)
            :args (mapcar (lambda (arg) (princ-to-string arg)) args)
            :raw (or raw
                     (format nil "~{~A~^ ~}"
                             (mapcar (lambda (arg) (princ-to-string arg))
                                     args))))))
    (etypecase option
      (string
       (let ((tokens (ssh-config-tokenize option)))
         (unless tokens
           (error 'ssh-config-error
                  :detail (format nil "empty -o option ~S" option)))
         (line (first tokens) (rest tokens)
               (ssh-config-line-remainder option))))
      (cons
       (let ((keyword (etypecase (car option)
                        (string (car option))
                        (symbol (symbol-name (car option)))))
             (args (cdr option)))
         (line keyword
               (cond
                 ((null args) nil)
                 ((listp args)
                  (if (and (null (rest args)) (listp (first args)))
                      (first args)
                      args))
                 ((stringp args) (list args))
                 (t (list args)))))))))

(defun ssh-config-option-lines (options)
  "OPTIONS as a list of SSH-CONFIG-LINE, in the order given."
  (mapcar #'ssh-config-option-line options))

(defun ssh-config-add-options (config options)
  "CONFIG with the command-line OPTIONS applied before its own directives.

OpenSSH gives -o options the first value on every keyword, exactly as if
they were the first lines of the file; prepending them to the parsed stream
does that without a temporary file."
  (let ((lines (ssh-config-option-lines options)))
    (if (null lines)
        config
        (%make-ssh-config
         :path (and config (ssh-config-path config))
         :directives (append lines
                             (and config (ssh-config-directives config)))))))

;;; ---- Values ----

(defun ssh-config-line-error (line control &rest arguments)
  (make-condition 'ssh-config-error
                  :detail (apply #'format nil control arguments)
                  :path (and (ssh-config-line-path line)
                             (namestring (ssh-config-line-path line)))
                  :line (ssh-config-line-number line)
                  :keyword (ssh-config-line-keyword line)))

(defun ssh-config-arg (line &optional (index 0))
  "Argument INDEX of LINE, or a config error naming the line."
  (or (nth index (ssh-config-line-args line))
      (error (ssh-config-line-error line "requires an argument"))))

(defun ssh-config-boolean (line value)
  (cond ((string-equal value "yes") t)
        ((string-equal value "no") nil)
        (t (error (ssh-config-line-error line "expected yes or no, got ~S"
                                         value)))))

(defun ssh-config-integer (line value &key minimum maximum)
  (let ((number (handler-case (parse-integer value :junk-allowed nil)
                  (parse-error () nil))))
    (unless (and number
                 (or (null minimum) (>= number minimum))
                 (or (null maximum) (<= number maximum)))
      (error (ssh-config-line-error line "invalid number ~S" value)))
    number))

(defun ssh-parse-scaled (value)
  "VALUE as scan_scaled reads a size in bytes, or NIL when it is invalid.

The syntax is digits with an optional decimal fraction and an optional
B/K/M/G/T/P/E suffix, as OpenSSH's RekeyLimit accepts.  The suffix is a
power of 1024, case-insensitively, and anything after it is invalid.  A
negative size is refused: OpenSSH's scan_scaled accepts it, but every
directive that uses it rejects the result."
  (when (and (stringp value) (plusp (length value)))
    (let ((position 0)
          (length (length value)))
      (loop while (and (< position length)
                       (member (char value position)
                               '(#\Space #\Tab #\Return #\Linefeed)))
            do (incf position))
      (when (and (< position length)
                 (char= (char value position) #\+))
        (incf position))
      (when (and (< position length)
                 (char= (char value position) #\-))
        (return-from ssh-parse-scaled nil))
      (let ((whole 0)
            (fraction 0)
            (fraction-digits 0)
            (digits 0))
        (loop while (and (< position length)
                         (digit-char-p (char value position)))
              do (setf whole (+ (* whole 10)
                                (digit-char-p (char value position))))
                 (incf digits)
                 (incf position))
        (when (and (< position length) (char= (char value position) #\.))
          (incf position)
          (loop while (and (< position length)
                           (digit-char-p (char value position)))
                do (setf fraction (+ (* fraction 10)
                                     (digit-char-p (char value position))))
                   (incf digits)
                   (incf fraction-digits)
                   (incf position)))
        (unless (plusp digits)
          (return-from ssh-parse-scaled nil))
        (let ((multiplier 1))
          (when (< position length)
            (setf multiplier
                  (case (char-upcase (char value position))
                    (#\B 1)
                    (#\K (expt 1024 1))
                    (#\M (expt 1024 2))
                    (#\G (expt 1024 3))
                    (#\T (expt 1024 4))
                    (#\P (expt 1024 5))
                    (#\E (expt 1024 6))
                    (t (return-from ssh-parse-scaled nil))))
            (incf position))
          (when (< position length)
            (return-from ssh-parse-scaled nil))
          (let ((result
                  (+ (* whole multiplier)
                     (if (plusp fraction-digits)
                         (floor (* fraction multiplier)
                                (expt 10 fraction-digits))
                         0))))
            (if (> result (1- (expt 2 63)))
                nil
                result)))))))

(defun ssh-config-atoi-error (value)
  "OpenSSH's strtonum diagnostic for VALUE, or NIL when it parses as an int.

readconf's atoi_err gives strtonum the bytes after \"interval:\" and prints
its error string verbatim, so an empty tail, a non-number and a value that
does not fit an int each read the way ssh reports them."
  (cond
    ((zerop (length value)) "missing")
    (t
     (let ((number (handler-case (parse-integer value :junk-allowed nil)
                     (error () nil))))
       (cond
         ((null number) "invalid")
         ((> number 2147483647) "too large")
         ((< number 0) "too small")
         (t nil))))))

(defun ssh-config-seconds (line value)
  "A time argument as seconds, :NONE for unlimited, or an error."
  (if (string-equal value "none")
      :none
      (let ((total 0)
            (number 0)
            (digits 0))
        (flet ((flush (multiplier)
                 (unless (plusp digits)
                   (error (ssh-config-line-error line "invalid time ~S" value)))
                 (incf total (* number multiplier))
                 (setf number 0 digits 0)))
          (loop for character across value
                do (cond
                     ((digit-char-p character)
                      (setf number (+ (* number 10)
                                      (digit-char-p character)))
                      (incf digits))
                     ((member character '(#\s #\S)) (flush 1))
                     ((member character '(#\m #\M)) (flush 60))
                     ((member character '(#\h #\H)) (flush 3600))
                     ((member character '(#\d #\D)) (flush 86400))
                     ((member character '(#\w #\W)) (flush 604800))
                     (t (error (ssh-config-line-error line
                                                      "invalid time ~S" value)))))
          (when (plusp digits) (flush 1)))
        total)))

(defun ssh-config-split-list (value)
  (remove "" (uiop:split-string value :separator ",") :test #'string=))

(defun ssh-config-channel-timeout-pair (line argument)
  "VALUES PATTERN SECONDS for one ChannelTimeout PATTERN=INTERVAL argument.

The pattern may contain wildcards, as ssh's match_pattern allows, but must
not be empty.  INTERVAL uses ssh's time syntax and may be zero, which
disables that pattern's timeout."
  (let ((equals (position #\= argument)))
    (when (or (null equals) (zerop equals))
      (error (ssh-config-line-error line "invalid channel timeout ~A"
                                    argument)))
    (let ((seconds (ssh-parse-time (subseq argument (1+ equals)))))
      (unless seconds
        (error (ssh-config-line-error line "invalid channel timeout ~A"
                                      argument)))
      (values (subseq argument 0 equals) seconds))))

(defun ssh-config-set-once (seen options key thunk)
  "Apply THUNK unless KEY was already set, as OpenSSH keeps first values.

A later active line is still parsed and validated: readconf checks every
argument before its first-value test, so a malformed duplicate is an error
even though its value cannot win.  Running the thunk on a copy leaves those
checks in place without letting the discarded value touch the result."
  (if (gethash key seen)
      (funcall thunk (copy-structure options))
      (progn
        (setf (gethash key seen) t)
        (funcall thunk options))))

(defun ssh-config-canonical-client-keyword (keyword)
  "KEYWORD itself, or the name ssh's opcode table gives an obsolete alias.

Aliases share one opcode, so their first-value-wins bookkeeping must share
one key too: an earlier ChallengeResponseAuthentication keeps a later
KbdInteractiveAuthentication from winning, exactly as ssh does."
  (cond
    ((member keyword '("challengeresponseauthentication"
                       "skeyauthentication" "tisauthentication")
             :test #'string=)
     "kbdinteractiveauthentication")
    ((string= keyword "dsaauthentication") "pubkeyauthentication")
    ((string= keyword "identityfile2") "identityfile")
    ;; SmartcardDevice is PKCS11Provider's old name; one opcode, one
    ;; first-value-wins key.
    ((string= keyword "smartcarddevice") "pkcs11provider")
    (t keyword)))

(defun ssh-config-permitted-cnames-value (line)
  "LINE's CanonicalizePermittedCNAMEs rules, as (SOURCE . TARGET) pairs.

OpenSSH accepts \"none\" alone (disables CNAME following), \"*\" (allow
everything), or \"source-list:target-list\".  Each list is comma-separated
glob patterns; both arguments are lowercased and matched case-insensitively."
  (let ((arguments (ssh-config-line-args line)))
    (when (null arguments)
      (error (ssh-config-line-error line "requires an argument")))
    (when (and (some (lambda (argument) (string-equal argument "none"))
                     arguments)
               (not (and (null (rest arguments))
                         (string-equal (first arguments) "none"))))
      (error (ssh-config-line-error line "\"none\" must appear alone")))
    (loop for argument in arguments
          collect
          (cond
            ((string-equal argument "none")
             (cons "none" ""))
            ((string= argument "*")
             (cons "*" "*"))
            (t
             (let* ((argument (string-downcase argument))
                    (colon (position #\: argument)))
               (when (or (null colon)
                         (= colon (1- (length argument))))
                 (error (ssh-config-line-error
                         line "invalid permitted CNAME ~S" argument)))
               (cons (subseq argument 0 colon)
                     (subseq argument (1+ colon)))))))))

;;; ---- Host patterns ----

(defun ssh-config-pattern-list-match-p (patterns text &key case-insensitive)
  "Whether TEXT matches PATTERNS, a list of possibly negated globs.

A matching negated pattern vetoes the list; a positive match is otherwise
enough.  Commas in a pattern are separators, as in ssh_config."
  (let ((matched nil)
        (patterns (loop for pattern in patterns
                        append (uiop:split-string pattern :separator ","))))
    (dolist (pattern patterns matched)
      (let ((negated (and (plusp (length pattern))
                          (char= (char pattern 0) #\!))))
        (when negated
          (setf pattern (subseq pattern 1)))
        (when (ssh-config-glob-match
               (if case-insensitive (string-downcase pattern) pattern)
               (if case-insensitive (string-downcase text) text))
          (if negated
              (return-from ssh-config-pattern-list-match-p nil)
              (setf matched t)))))))

(defun ssh-config-host-block-matches-p (line options context)
  "Whether LINE's Host pattern matches the name this pass works on.

The first pass follows a HostName directive that has already been read; the
final pass follows the canonical name placed in HOSTNAME by its caller.
ORIGINAL-HOST remains the name the user typed, for %n and OriginalHost."
  (ssh-config-pattern-list-match-p
   (ssh-config-line-args line)
   (or (ssh-config-options-hostname options)
       (ssh-config-context-original-host context))
   :case-insensitive t))

(defun ssh-config-ipv4-integer (octets)
  (reduce (lambda (whole octet) (+ (ash whole 8) octet)) octets))

(defun ssh-config-ipv4-octets (string)
  (let ((parts (uiop:split-string string :separator ".")))
    (when (= 4 (length parts))
      (let ((octets (handler-case
                        (mapcar #'parse-integer parts)
                      (error () nil))))
        (when (and octets (every (lambda (o) (<= 0 o 255)) octets))
          octets)))))

(defun ssh-config-ipv4-cidr-match-p (cidr address)
  (let* ((slash (position #\/ cidr))
         (network (ssh-config-ipv4-octets
                   (if slash (subseq cidr 0 slash) cidr)))
         (bits (if slash
                   (handler-case
                       (parse-integer cidr :start (1+ slash))
                     (parse-error () nil))
                   32))
         (host (ssh-config-ipv4-octets address)))
    (and network host bits (<= 0 bits 32)
         (let ((mask (if (zerop bits)
                         0
                         (logand #xFFFFFFFF
                                 (ash #xFFFFFFFF (- 32 bits))))))
           (= (logand (ssh-config-ipv4-integer network) mask)
              (logand (ssh-config-ipv4-integer host) mask))))))

(defun ssh-config-ipv6-words (string)
  "The eight 16-bit words of an IPv6 literal, or NIL when it is not one.

A trailing dotted quad is accepted, as in \"::ffff:192.168.1.1\", and one
\"::\" stands for however many zero words are needed."
  (let ((failed nil))
    (labels ((words (part)
               (if (zerop (length part))
                   '()
                   (uiop:split-string part :separator ":")))
             (word (text)
               (if (and (plusp (length text))
                        (<= (length text) 4)
                        (every (lambda (c) (digit-char-p c 16)) text))
                   (parse-integer text :radix 16)
                   (progn (setf failed t) nil)))
             (v4-words (text)
               (let ((octets (ssh-config-ipv4-octets text)))
                 (if octets
                     (list (+ (ash (first octets) 8) (second octets))
                           (+ (ash (third octets) 8) (fourth octets)))
                     (progn (setf failed t) nil))))
             (expand (parts)
               (let ((result '()))
                 (dolist (part parts (nreverse result))
                   (if (find #\. part)
                       (dolist (w (v4-words part)) (push w result))
                       (push (word part) result))))))
      (let* ((double (search "::" string))
             (left (expand (words (if double (subseq string 0 double) string))))
             (right (and double
                         (expand (words (subseq string (+ double 2)))))))
        (unless failed
          (cond
            ((null double)
             (when (= 8 (length left)) left))
            ((<= (+ (length left) (length right)) 8)
             (append left
                     (make-list (- 8 (length left) (length right))
                                :initial-element 0)
                     right))))))))

(defun ssh-config-ipv6-cidr-match-p (cidr address)
  "Whether IPv6 ADDRESS is inside CIDR, whose prefix counts high-order bits.

sshd accepts these in AllowUsers/DenyUsers host patterns, so a deny list must
understand them rather than silently match nothing."
  (let* ((slash (position #\/ cidr))
         (network (ssh-config-ipv6-words (if slash (subseq cidr 0 slash) cidr)))
         (bits (if slash
                   (handler-case
                       (parse-integer cidr :start (1+ slash) :junk-allowed t)
                     (parse-error () nil))
                   128))
         (host (ssh-config-ipv6-words address)))
    (and network host bits (<= 0 bits 128)
         (let* ((full (floor bits 16))
                (rest (mod bits 16))
                (mask (if (zerop rest)
                          0
                          (logand #xFFFF (ash #xFFFF (- 16 rest))))))
           (and (loop for index below full
                      always (= (nth index network) (nth index host)))
                (or (zerop rest)
                    (= (logand (nth full network) mask)
                       (logand (nth full host) mask))))))))

(defun ssh-config-localnetwork-match-p (cidrs local-addresses)
  (let ((cidrs (loop for cidr in (uiop:split-string cidrs :separator ",")
                     collect cidr)))
    (and local-addresses
         (some (lambda (address)
                 (some (lambda (cidr)
                         (or (ssh-config-ipv4-cidr-match-p cidr address)
                             (ssh-config-ipv6-cidr-match-p cidr address)))
                       cidrs))
               local-addresses))))

;;; ---- Applying directives ----

(defun ssh-config-apply-address (line options seen context)
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((string= keyword "hostname")
       (ssh-config-set-once
        seen options :hostname
        (lambda (options)
          (setf (ssh-config-options-hostname options)
                (ssh-config-expand-variables
                 (ssh-config-expand-tokens (ssh-config-arg line)
                                           options context))))))
      ((string= keyword "port")
       (ssh-config-set-once
        seen options :port
        (lambda (options)
          (setf (ssh-config-options-port options)
                (ssh-config-integer line (ssh-config-arg line)
                                    :minimum 1 :maximum 65535)))))
      ((string= keyword "user")
       (ssh-config-set-once
        seen options :user
        (lambda (options)
          (setf (ssh-config-options-user options)
                (ssh-config-expand-variables (ssh-config-arg line))))))
      ((string= keyword "canonicalizehostname")
       (ssh-config-set-once
        seen options :canonicalize-hostname
        (lambda (options)
          (let ((value (string-downcase (ssh-config-arg line))))
            (unless (member value '("yes" "no" "always" "true" "false")
                            :test #'string=)
              (error (ssh-config-line-error line
                                            "invalid CanonicalizeHostname ~S"
                                            value)))
            (setf (ssh-config-options-canonicalize-hostname options)
                  (cond ((string= value "always") :always)
                        ((member value '("true" "yes") :test #'string=) :yes)
                        (t :no)))))))
      ((string= keyword "canonicaldomains")
       (ssh-config-set-once
        seen options :canonical-domains
        (lambda (options)
          (setf (ssh-config-options-canonical-domains options)
                (ssh-config-line-args line)))))
      ((string= keyword "canonicalizemaxdots")
       (ssh-config-set-once
        seen options :canonicalize-max-dots
        (lambda (options)
          (setf (ssh-config-options-canonicalize-max-dots options)
                (ssh-config-integer line (ssh-config-arg line)
                                    :minimum 0)))))
      ((string= keyword "canonicalizefallbacklocal")
       (ssh-config-set-once
        seen options :canonicalize-fallback-local
        (lambda (options)
          (setf (ssh-config-options-canonicalize-fallback-local options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((string= keyword "canonicalizepermittedcnames")
       (ssh-config-set-once
        seen options :canonicalize-permitted-cnames
        (lambda (options)
          (setf (ssh-config-options-canonicalize-permitted-cnames options)
                (ssh-config-permitted-cnames-value line)))))
      ((string= keyword "hostkeyalias")
       (ssh-config-set-once
        seen options :host-key-alias
        (lambda (options)
          (setf (ssh-config-options-host-key-alias options)
                (ssh-config-expand-variables (ssh-config-arg line)))))))))

(defun ssh-config-apply-identity (line options seen context)
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((member keyword '("identityfile" "identityfile2") :test #'string=)
       ;; IdentityFile2 is OpenSSH's obsolete spelling of IdentityFile; it
       ;; still names an identity and joins the same ordered list.
       (push (ssh-config-path-value line options context)
             (ssh-config-options-identity-files options)))
      ((string= keyword "certificatefile")
       (push (ssh-config-path-value line options context)
             (ssh-config-options-certificate-files options)))
      ((string= keyword "identityagent")
       (ssh-config-set-once
        seen options :identity-agent
        (lambda (options)
          (setf (ssh-config-options-identity-agent options)
                (let ((value (ssh-config-arg line)))
                  (cond
                    ((string-equal value "none") :none)
                    ((string-equal value "SSH_AUTH_SOCK") :environment)
                    (t (ssh-config-path-value line options context))))))))
      ((string= keyword "identitiesonly")
       (ssh-config-set-once
        seen options :identities-only
        (lambda (options)
          (setf (ssh-config-options-identities-only options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((string= keyword "hostbasedauthentication")
       (ssh-config-set-once
        seen options :hostbased-authentication
        (lambda (options)
          (setf (ssh-config-options-hostbased-authentication options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((member keyword '("hostbasedacceptedalgorithms" "hostbasedkeytypes")
               :test #'string=)
       (ssh-config-set-once
        seen options :hostbased-accepted-algorithms
        (lambda (options)
          (setf (ssh-config-options-hostbased-accepted-algorithms options)
                (ssh-config-split-list (ssh-config-arg line))))))
      ((string= keyword "hostbasedkey")
       (push (ssh-config-path-value line options context)
             (ssh-config-options-hostbased-keys options)))
      ((string= keyword "enablesshkeysign")
       (ssh-config-set-once
        seen options :enable-ssh-keysign
        (lambda (options)
          (setf (ssh-config-options-enable-ssh-keysign options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((string= keyword "addkeystoagent")
       (ssh-config-set-once
        seen options :add-keys-to-agent
        (lambda (options)
          (let ((value (string-downcase (ssh-config-arg line))))
            (setf (ssh-config-options-add-keys-to-agent options)
                  (cond ((member value '("yes" "true" "on") :test #'string=)
                         :yes)
                        ((member value '("no" "false" "off") :test #'string=)
                         :no)
                        ((string= value "ask") :ask)
                        ((string= value "confirm") :confirm)
                        (t
                         (error (ssh-config-line-error
                                 line "invalid AddKeysToAgent ~S" value))))))))))))

(defun ssh-config-known-host-paths (line options context)
  "The paths on a known-hosts line; :NONE for the literal none."
  (let ((values (ssh-config-line-args line)))
    (if (and values (string-equal (first values) "none"))
        :none
        (mapcar (lambda (value)
                  (let ((value (ssh-config-expand-variables
                                (ssh-config-expand-tokens value options context))))
                    (let ((value (ssh-config-expand-home value)))
                      (if (ssh-config-absolute-path-p value)
                          (pathname value)
                          (merge-pathnames value (user-homedir-pathname))))))
                values))))

(defun ssh-config-apply-policy (line options seen context)
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((string= keyword "userknownhostsfile")
       (ssh-config-set-once
        seen options :known-hosts
        (lambda (options)
          (let ((paths (ssh-config-known-host-paths line options context)))
            (setf (ssh-config-options-known-hosts options)
                  (if (eq paths :none) nil paths))))))
      ((string= keyword "globalknownhostsfile")
       (ssh-config-set-once
        seen options :global-known-hosts
        (lambda (options)
          (let ((paths (ssh-config-known-host-paths line options context)))
            (setf (ssh-config-options-global-known-hosts options)
                  (if (eq paths :none) nil paths))))))
      ((string= keyword "updatehostkeys")
       (ssh-config-set-once
        seen options :update-host-keys
        (lambda (options)
          (let ((value (string-downcase (ssh-config-arg line))))
            (setf (ssh-config-options-update-host-keys options)
                  (cond ((member value '("yes" "true" "on")
                                 :test #'string=)
                         :yes)
                        ((member value '("no" "false" "off")
                                 :test #'string=)
                         :no)
                        ((string= value "ask") :ask)
                        (t
                         (error (ssh-config-line-error
                                 line "invalid UpdateHostKeys ~S" value)))))))))
      ((string= keyword "knownhostscommand")
       (ssh-config-set-once
        seen options :known-hosts-command
        (lambda (options)
          (setf (ssh-config-options-known-hosts-command options)
                (let ((raw (ssh-config-line-raw line)))
                  (if (and raw (plusp (length raw))) raw value))))))
      ((string= keyword "ignoreunknown")
       (let ((arguments (ssh-config-line-args line)))
         (unless (= 1 (length arguments))
           (error (ssh-config-line-error
                   line "IgnoreUnknown takes exactly one argument")))
         (when (zerop (length (first arguments)))
           (error (ssh-config-line-error
                   line "IgnoreUnknown requires an argument")))
         (ssh-config-set-once
          seen options :ignored-unknown
          (lambda (options)
            (setf (ssh-config-options-ignored-unknown options)
                  (first arguments))))))
      ((string= keyword "fingerprinthash")
       (ssh-config-set-once
        seen options :fingerprint-hash
        (lambda (options)
          (let ((value (string-downcase (ssh-config-arg line))))
            (unless (member value '("sha256" "md5") :test #'string=)
              (error (ssh-config-line-error line
                                            "invalid FingerprintHash ~S"
                                            value)))
            (setf (ssh-config-options-fingerprint-hash options)
                  (intern (string-upcase value) :keyword))))))
      ((string= keyword "checkhostip")
       (ssh-config-set-once
        seen options :check-host-ip
        (lambda (options)
          (setf (ssh-config-options-check-host-ip options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((string= keyword "nohostauthenticationforlocalhost")
       (ssh-config-set-once
        seen options :no-host-authentication-for-localhost
        (lambda (options)
          (setf (ssh-config-options-no-host-authentication-for-localhost
                 options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((string= keyword "verifyhostkeydns")
       (ssh-config-set-once
        seen options :verify-host-key-dns
        (lambda (options)
          (let ((value (string-downcase (ssh-config-arg line))))
            (setf (ssh-config-options-verify-host-key-dns options)
                  (cond ((member value '("yes" "true" "on")
                                 :test #'string=)
                         :yes)
                        ((member value '("no" "false" "off")
                                 :test #'string=)
                         :no)
                        ((string= value "ask") :ask)
                        (t
                         (error (ssh-config-line-error
                                 line "invalid VerifyHostKeyDNS ~S" value)))))))))
      ((string= keyword "visualhostkey")
       (ssh-config-set-once
        seen options :visual-host-key
        (lambda (options)
          (setf (ssh-config-options-visual-host-key options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((string= keyword "hashknownhosts")
       (ssh-config-set-once
        seen options :hash-known-hosts
        (lambda (options)
          (setf (ssh-config-options-hash-known-hosts options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((string= keyword "revokedhostkeys")
       ;; Unlike most keywords this accumulates, and NONE clears what came
       ;; before it, as ssh's oRevokedHostKeys does.
       (let ((values (ssh-config-line-args line)))
         (if (and (= 1 (length values))
                  (string-equal (first values) "none"))
             (setf (ssh-config-options-revoked-host-keys options) nil)
             (dolist (value values)
               (push (ssh-config-path-argument value options context)
                     (ssh-config-options-revoked-host-keys options))))))
      ((string= keyword "stricthostkeychecking")
       (ssh-config-set-once
        seen options :strict-host-key-checking
        (lambda (options)
          (let ((value (string-downcase (ssh-config-arg line))))
            (unless (member value '("yes" "no" "off" "ask" "accept-new")
                            :test #'string=)
              (error (ssh-config-line-error line
                                            "invalid StrictHostKeyChecking ~S"
                                            value)))
            (setf (ssh-config-options-strict-host-key-checking options)
                  value)))))
      ((string= keyword "connecttimeout")
       (ssh-config-set-once
        seen options :connect-timeout
        (lambda (options)
          (setf (ssh-config-options-connect-timeout options)
                (ssh-config-seconds line (ssh-config-arg line))))))
      ((string= keyword "connectionattempts")
       (ssh-config-set-once
        seen options :connection-attempts
        (lambda (options)
          (setf (ssh-config-options-connection-attempts options)
                (ssh-config-integer line (ssh-config-arg line)
                                    :minimum 1)))))
      ((string= keyword "addressfamily")
       (ssh-config-set-once
        seen options :address-family
        (lambda (options)
          (let ((value (string-downcase (ssh-config-arg line))))
            (unless (member value '("any" "inet" "inet6") :test #'string=)
              (error (ssh-config-line-error line "invalid AddressFamily ~S"
                                            value)))
            (setf (ssh-config-options-address-family options)
                  (intern (string-upcase value) :keyword))))))
      ((string= keyword "batchmode")
       (ssh-config-set-once
        seen options :batch-mode
        (lambda (options)
          (setf (ssh-config-options-batch-mode options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((string= keyword "warnweakcrypto")
       ;; A multistate, not a boolean: readconf also accepts no-pq-kex, which
       ;; its table maps to the same false value as no, and rejects anything
       ;; else with "unsupported option".
       (ssh-config-set-once
        seen options :warn-weak-crypto
        (lambda (options)
          (let ((value (ssh-config-arg line)))
            (setf (ssh-config-options-warn-weak-crypto options)
                  (cond
                    ((member value '("yes" "true") :test #'string-equal)
                     :yes)
                    ((member value '("no" "false" "no-pq-kex")
                             :test #'string-equal)
                     :no)
                    (t
                     (error (ssh-config-line-error
                             line "unsupported option ~S" value))))))))))))

(defun ssh-config-apply-algorithms (line options seen)
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((string= keyword "ciphers")
       (ssh-config-set-once
        seen options :ciphers
        (lambda (options)
          (setf (ssh-config-options-ciphers options)
                (ssh-config-split-list (ssh-config-arg line))))))
      ((string= keyword "macs")
       (ssh-config-set-once
        seen options :macs
        (lambda (options)
          (setf (ssh-config-options-macs options)
                (ssh-config-split-list (ssh-config-arg line))))))
      ((string= keyword "kexalgorithms")
       (ssh-config-set-once
        seen options :kex-algorithms
        (lambda (options)
          (setf (ssh-config-options-kex-algorithms options)
                (ssh-config-split-list (ssh-config-arg line))))))
      ((string= keyword "hostkeyalgorithms")
       (ssh-config-set-once
        seen options :host-key-algorithms
        (lambda (options)
          (setf (ssh-config-options-host-key-algorithms options)
                (ssh-config-split-list (ssh-config-arg line))))))
      ((string= keyword "casignaturealgorithms")
       (ssh-config-set-once
        seen options :ca-signature-algorithms
        (lambda (options)
          (setf (ssh-config-options-ca-signature-algorithms options)
                (ssh-config-split-list (ssh-config-arg line))))))
      ((member keyword '("pubkeyacceptedalgorithms" "pubkeyacceptedkeytypes")
               :test #'string=)
       (ssh-config-set-once
        seen options :pubkey-accepted-algorithms
        (lambda (options)
          (setf (ssh-config-options-pubkey-accepted-algorithms options)
                (ssh-config-split-list (ssh-config-arg line))))))
      ((string= keyword "compression")
       (ssh-config-set-once
        seen options :compression
        (lambda (options)
          (let ((value (string-downcase (ssh-config-arg line))))
            (unless (member value '("yes" "no") :test #'string=)
              (error (ssh-config-line-error line "invalid Compression ~S"
                                            value)))
            (setf (ssh-config-options-compression options)
                  (string= value "yes"))))))
      ((string= keyword "rekeylimit")
       (let ((arguments (ssh-config-line-args line)))
         (unless (<= 1 (length arguments) 2)
           (error (ssh-config-line-error
                   line "RekeyLimit takes a size and an optional time")))
         (let* ((size-argument (first arguments))
                (bytes (if (string= size-argument "default")
                           0
                           (or (ssh-parse-scaled size-argument)
                               (error (ssh-config-line-error
                                       line "Bad number ~S" size-argument))))))
           (when (and (plusp bytes) (< bytes 16))
             (error (ssh-config-line-error line "RekeyLimit too small")))
           (ssh-config-set-once
            seen options :rekey-limit
            (lambda (options)
              (setf (ssh-config-options-rekey-limit options) bytes)))
           (when (second arguments)
             (let ((interval-argument (second arguments)))
               (unless (string= interval-argument "none")
                 (let ((seconds (or (ssh-parse-time interval-argument)
                                    (error (ssh-config-line-error
                                            line "invalid time value ~S"
                                            interval-argument)))))
                   (ssh-config-set-once
                    seen options :rekey-interval
                    (lambda (options)
                      (setf (ssh-config-options-rekey-interval options)
                            seconds)))))))))))))

(defparameter +ssh-config-ip-qos-names+
  '(("af11" . #x28) ("af12" . #x30) ("af13" . #x38)
    ("af21" . #x48) ("af22" . #x50) ("af23" . #x58)
    ("af31" . #x68) ("af32" . #x70) ("af33" . #x78)
    ("af41" . #x88) ("af42" . #x90) ("af43" . #x98)
    ("cs0" . #x00) ("cs1" . #x20) ("cs2" . #x40) ("cs3" . #x60)
    ("cs4" . #x80) ("cs5" . #xa0) ("cs6" . #xc0) ("cs7" . #xe0)
    ("ef" . #xb8) ("le" . #x04) ("va" . #xb0))
  "IPQoS names and their DSCP values.")

(defun ssh-config-ip-qos-value (line value)
  "VALUE as an IPQoS DSCP integer or :NONE."
  (let ((name (string-downcase value)))
    (cond
      ((string= name "none") :none)
      ((member name '("lowdelay" "throughput" "reliability")
               :test #'string=)
       ;; ssh ignores the deprecated names and uses the system default.
       :none)
      ((cdr (assoc name +ssh-config-ip-qos-names+ :test #'string=)))
      (t
       (let ((number (handler-case (parse-integer value)
                       (error () nil))))
         (unless (and number (<= 0 number 255))
           (error (ssh-config-line-error line "invalid IPQoS ~S" value)))
         number)))))

(defun ssh-config-apply-session (line options seen)
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((string= keyword "ipqos")
       (ssh-config-set-once
        seen options :ip-qos
        (lambda (options)
          (let ((arguments (ssh-config-line-args line)))
            (unless (<= 1 (length arguments) 2)
              (error (ssh-config-line-error line "invalid IPQoS arguments")))
            (let ((interactive (ssh-config-ip-qos-value
                                line (first arguments))))
              (setf (ssh-config-options-ip-qos-interactive options)
                    interactive
                    (ssh-config-options-ip-qos-bulk options)
                    (if (second arguments)
                        (ssh-config-ip-qos-value line (second arguments))
                        interactive)))))))
      ((string= keyword "sendenv")
       (setf (ssh-config-options-send-env options)
             (append (ssh-config-options-send-env options)
                     (ssh-config-line-args line))))
      ((string= keyword "setenv")
       ;; ssh keeps the first active SetEnv line and ignores duplicates by
       ;; variable name, so the same shape is used here.
       (ssh-config-set-once
        seen options :set-env
        (lambda (options)
          (let ((assignments (ssh-config-line-args line)))
            (dolist (assignment assignments)
              (unless (find #\= assignment)
                (error (ssh-config-line-error line "Invalid SetEnv ~S"
                                              assignment))))
            (setf (ssh-config-options-set-env options)
                  (remove-duplicates
                   assignments
                   :test #'string=
                   :from-end t
                   :key (lambda (assignment)
                          (subseq assignment 0
                                  (position #\= assignment)))))))))
      ((member keyword '("localforward" "remoteforward" "dynamicforward")
               :test #'string=)
       ;; Keep the tokens as written for callers that want them, and also
       ;; keep each forwarding line as one string: the destination follows
       ;; ssh_config's two-word form ("port host:hostport"), which is not
       ;; what the command line's single colon-separated argument looks
       ;; like, so the text is preserved and the caller decides.
       (let ((value (format nil "~{~A~^ ~}" (ssh-config-line-args line))))
         (push (cons keyword (ssh-config-line-args line))
               (ssh-config-options-extra options))
         (cond
           ((string= keyword "localforward")
            (push value (ssh-config-options-local-forwards options)))
           ((string= keyword "remoteforward")
            (push value (ssh-config-options-remote-forwards options)))
           (t
            (push value (ssh-config-options-dynamic-forwards options))))))
      ((string= keyword "tag")
       (ssh-config-set-once
        seen options :tag
        (lambda (options)
          (setf (ssh-config-options-tag options) (ssh-config-arg line)))))
      ((string= keyword "channeltimeout")
       ;; ssh keeps the first active ChannelTimeout line as a whole, but parses
       ;; every argument on every active line, so a typo in a later line is
       ;; fatal just as it is in ssh.  "none" must stand alone.
       (let ((arguments (ssh-config-line-args line)))
         (unless arguments
           (error (ssh-config-line-error
                   line "ChannelTimeout needs an argument")))
         (if (string-equal (first arguments) "none")
             (progn
               (when (rest arguments)
                 (error (ssh-config-line-error
                         line "ChannelTimeout \"none\" argument must appear alone")))
               (ssh-config-set-once
                seen options :channel-timeouts
                (lambda (options)
                  (setf (ssh-config-options-channel-timeouts options)
                        :none))))
             (progn
               (dolist (argument arguments)
                 (ssh-config-channel-timeout-pair line argument))
               (ssh-config-set-once
                seen options :channel-timeouts
                (lambda (options)
                  (setf (ssh-config-options-channel-timeouts options)
                        (copy-list arguments))))))))
      ((string= keyword "obscurekeystroketiming")
       ;; readconf accepts exactly one argument, reassigns only the first
       ;; active line, but parses every line so a mistake later is still fatal.
       (let ((arguments (ssh-config-line-args line)))
         (unless arguments
           (error (ssh-config-line-error line "missing argument")))
         (when (rest arguments)
           (error (ssh-config-line-error line "invalid arguments")))
         (let* ((argument (first arguments))
                (value
                  (cond
                    ((or (string= argument "yes")
                         (string= argument "true"))
                     +ssh-keystroke-default-interval-ms+)
                    ((or (string= argument "no") (string= argument "false"))
                     0)
                    ((and (>= (length argument) 9)
                          (string= argument "interval:" :end1 9 :end2 9))
                     (let* ((number (subseq argument 9))
                            (problem (ssh-config-atoi-error number)))
                       (when problem
                         (error (ssh-config-line-error
                                 line "integer value ~A." problem)))
                       (let ((milliseconds (parse-integer number)))
                         (when (or (< milliseconds 1)
                                   (> milliseconds 1000))
                           (error (ssh-config-line-error
                                   line "value out of range.")))
                         milliseconds)))
                    (t
                     (error (ssh-config-line-error
                             line "unsupported argument ~S" argument))))))
           (ssh-config-set-once
            seen options :obscure-keystroke-timing
            (lambda (options)
              (setf (ssh-config-options-obscure-keystroke-timing options)
                    value))))))
      (t
       (ssh-config-set-once
        seen options
        (intern (string-upcase
                 (ssh-config-canonical-client-keyword keyword))
                :keyword)
        (lambda (options)
          (ssh-config-apply-session-value line options keyword)))))))

(defun ssh-config-remote-open-entry (line argument)
  "One PermitRemoteOpen ARGUMENT as (HOST . PORT), either part :ANY."
  (let ((colon (position #\: argument :from-end t)))
    (unless (and colon (plusp colon) (< (1+ colon) (length argument)))
      (error (ssh-config-line-error line
                                    "invalid PermitRemoteOpen ~S"
                                    argument)))
    (let ((host (subseq argument 0 colon))
          (port (subseq argument (1+ colon))))
      (when (and (>= (length host) 2)
                 (char= (char host 0) #\[)
                 (char= (char host (1- (length host))) #\]))
        (setf host (subseq host 1 (1- (length host)))))
      (cons host
            (if (string= port "*")
                :any
                (let ((value (handler-case
                                 (parse-integer port)
                               (error () nil))))
                  (unless (and value (<= 1 value 65535))
                    (error (ssh-config-line-error
                            line "invalid PermitRemoteOpen port ~S" port)))
                  value))))))

(defun ssh-config-escape-char-value (value)
  "VALUE as an escape character, or :NONE."
  (cond
    ((string-equal value "none") :none)
    ((and (= 2 (length value)) (char= (char value 0) #\^))
     (let ((character (char-upcase (char value 1))))
       (if (char= character #\?)
           127
           (logand (char-code character) #x1f))))
    ((= 1 (length value)) (char value 0))
    (t nil)))

(defun ssh-config-tunnel-id (line value)
  "One end of a TunnelDevice as an interface number or :ANY.

misc.c's a2tun accepts \"any\" or 0..SSH_TUNID_MAX and reports anything else
as \"Bad tun device.\"; the bound keeps the maximum clear of the two
sentinels OpenSSH reserves."
  (if (string-equal value "any")
      :any
      (let ((number
              (handler-case
                  (ssh-config-integer line value
                                      :minimum 0 :maximum 2147483645)
                (ssh-config-error () nil))))
        (unless number
          (error (ssh-config-line-error line "Bad tun device.")))
        number)))

(defun ssh-config-tunnel-device (line value)
  "LINE's TunnelDevice VALUE as (LOCAL . REMOTE).

A single value leaves the remote side any, as a2tun does when no colon is
present."
  (let* ((colon (position #\: value))
         (local (ssh-config-tunnel-id
                 line (if colon (subseq value 0 colon) value)))
         (remote (if colon
                     (ssh-config-tunnel-id line (subseq value (1+ colon)))
                     :any)))
    (cons local remote)))

(defun ssh-config-apply-session-value (line options keyword)
  (let ((value (ssh-config-arg line)))
    (flet ((boolean () (ssh-config-boolean line value))
           (integer (&key minimum maximum)
             (ssh-config-integer line value :minimum minimum :maximum maximum)))
      (cond
        ((string= keyword "proxyjump")
         (setf (ssh-config-options-proxy-jump options) value))
        ((string= keyword "proxycommand")
         (ssh-config-arg line)
         (setf (ssh-config-options-proxy-command options)
               (let ((raw (ssh-config-line-raw line)))
                 (if (and raw (plusp (length raw))) raw value))))
        ((string= keyword "bindaddress")
         (setf (ssh-config-options-bind-address options) value))
        ((string= keyword "serveraliveinterval")
         (setf (ssh-config-options-server-alive-interval options)
               (ssh-config-seconds line value)))
        ((string= keyword "serveralivecountmax")
         (setf (ssh-config-options-server-alive-count-max options)
               (integer :minimum 0)))
        ((string= keyword "forwardagent")
         ;; readconf accepts yes/no/true/false, and treats anything else as
         ;; the path of the agent socket to forward.
         (cond
           ((member value '("yes" "true") :test #'string-equal)
            (setf (ssh-config-options-forward-agent options) t))
           ((member value '("no" "false") :test #'string-equal)
            (setf (ssh-config-options-forward-agent options) nil))
           ((plusp (length value))
            (setf (ssh-config-options-forward-agent options) t
                  (ssh-config-options-forward-agent-sock-path options) value))
           (t
            (error (ssh-config-line-error line
                                          "missing ForwardAgent argument")))))
        ((string= keyword "forwardx11")
         (setf (ssh-config-options-forward-x11 options) (boolean)))
        ((string= keyword "forwardx11trusted")
         (setf (ssh-config-options-forward-x11-trusted options) (boolean)))
        ((string= keyword "forwardx11timeout")
         ;; parse_time accepts "none", but fill_default_options turns the
         ;; resulting -1 back into 1200, so NONE means the default here too.
         (setf (ssh-config-options-forward-x11-timeout options)
               (let ((seconds (ssh-config-seconds line value)))
                 (if (eq seconds :none) nil seconds))))
        ((string= keyword "gssapiauthentication")
         (setf (ssh-config-options-gssapi-authentication options) (boolean)))
        ((string= keyword "gssapidelegatecredentials")
         (setf (ssh-config-options-gssapi-delegate-credentials options)
               (boolean)))
        ((string= keyword "bindinterface")
         (setf (ssh-config-options-bind-interface options) value))
        ((string= keyword "kbdinteractivedevices")
         (setf (ssh-config-options-kbd-interactive-devices options) value))
        ((member keyword '("pkcs11provider" "smartcarddevice")
                 :test #'string=)
         ;; CLEAR_ON_NONE drops the provider after parsing, so -G prints
         ;; nothing for "none"; :NONE records that decision.
         (setf (ssh-config-options-pkcs11-provider options)
               (if (string-equal value "none") :none value)))
        ((string= keyword "securitykeyprovider")
         (setf (ssh-config-options-security-key-provider options)
               (if (string-equal value "none") :none value)))
        ((string= keyword "proxyusefdpass")
         (setf (ssh-config-options-proxy-use-fdpass options) (boolean)))
        ((string= keyword "syslogfacility")
         (let ((facility (string-upcase value)))
           (unless (member facility
                           '("DAEMON" "USER" "AUTH" "AUTHPRIV"
                             "LOCAL0" "LOCAL1" "LOCAL2" "LOCAL3"
                             "LOCAL4" "LOCAL5" "LOCAL6" "LOCAL7")
                           :test #'string=)
             (error (ssh-config-line-error
                     line "unsupported log facility '~A'" value)))
           (setf (ssh-config-options-syslog-facility options) facility)))
        ((string= keyword "tunnel")
         (let ((setting (string-downcase value)))
           (unless (member setting
                           '("ethernet" "point-to-point" "true" "yes"
                             "false" "no")
                           :test #'string=)
             (error (ssh-config-line-error line
                                           "unsupported option \"~A\"."
                                           value)))
           (setf (ssh-config-options-tunnel options)
                 (cond ((string= setting "ethernet") :ethernet)
                       ((string= setting "point-to-point") :point-to-point)
                       ((member setting '("true" "yes") :test #'string=) :yes)
                       (t :no)))))
        ((string= keyword "tunneldevice")
         (setf (ssh-config-options-tunnel-device options)
               (ssh-config-tunnel-device line value)))
        ((string= keyword "xauthlocation")
         (setf (ssh-config-options-xauth-location options) value))
        ((string= keyword "gatewayports")
         (setf (ssh-config-options-gateway-ports options) (boolean)))
        ((string= keyword "exitonforwardfailure")
         (setf (ssh-config-options-exit-on-forward-failure options)
               (boolean)))
        ((string= keyword "permitremoteopen")
         ;; The first active line wins; NIL is how "not set" is spelled, so
         ;; no seen table is needed here.
         (unless (ssh-config-options-permit-remote-open options)
           (let ((arguments (ssh-config-line-args line)))
             (setf (ssh-config-options-permit-remote-open options)
                   (cond
                     ((and (= 1 (length arguments))
                           (string-equal (first arguments) "any"))
                      :any)
                     ((and (= 1 (length arguments))
                           (string-equal (first arguments) "none"))
                      :none)
                     (t
                      (mapcar (lambda (argument)
                                (ssh-config-remote-open-entry
                                 line argument))
                              arguments)))))))
        ((string= keyword "clearallforwardings")
         (setf (ssh-config-options-clear-all-forwardings options)
               (boolean)))
        ((member keyword '("tcpkeepalive" "keepalive") :test #'string=)
         (setf (ssh-config-options-tcp-keep-alive options) (boolean)))
        ((string= keyword "refuseconnection")
         ;; ssh treats this as fatal while the active block is read, so a
         ;; managed configuration can stop a connection before it starts.
         (error (ssh-config-line-error line "RefuseConnection: ~A" value)))
        ((string= keyword "requiredrsasize")
         (setf (ssh-config-options-required-rsa-size options)
               (integer)))
        ((string= keyword "streamlocalbindmask")
         (let ((mask (handler-case (parse-integer value :radix 8)
                       (error () nil))))
           (unless (and mask (<= 0 mask #o777))
             (error (ssh-config-line-error
                     line "invalid StreamLocalBindMask ~S" value)))
           (setf (ssh-config-options-streamlocal-bind-mask options) mask)))
        ((string= keyword "streamlocalbindunlink")
         (setf (ssh-config-options-streamlocal-bind-unlink options)
               (boolean)))
        ((string= keyword "permitlocalcommand")
         (setf (ssh-config-options-permit-local-command options) (boolean)))
        ((string= keyword "localcommand")
         (unless (ssh-config-options-local-command options)
           (setf (ssh-config-options-local-command options)
                 (let ((raw (ssh-config-line-raw line)))
                   (if (and raw (plusp (length raw))) raw value)))))
        ((string= keyword "remotecommand")
         ;; The first active line wins; NIL is how "not set" is spelled.
         (unless (ssh-config-options-remote-command options)
           (setf (ssh-config-options-remote-command options)
                 (let ((raw (ssh-config-line-raw line)))
                   (if (and raw (plusp (length raw))) raw value)))))
        ((string= keyword "versionaddendum")
         ;; The whole rest of the line is the comment, spaces included, up to
         ;; a '#' as in ssh.  "none" is an explicit empty value, distinct from
         ;; the keyword never appearing.
         (unless (ssh-config-options-version-addendum options)
           (let* ((raw (ssh-config-line-raw line))
                  (text (if (and raw (plusp (length raw))) raw value))
                  (hash (position #\# text)))
             (when hash (setf text (subseq text 0 hash)))
             (setf text (string-trim '(#\Space #\Tab #\Return) text))
             (when (zerop (length text))
               (error (ssh-config-line-error
                       line "VersionAddendum missing argument")))
             (setf (ssh-config-options-version-addendum options)
                   (if (string-equal text "none") "" text)))))
        ((string= keyword "loglevel")
         (let ((level (string-downcase value)))
           (unless (member level '("quiet" "fatal" "error" "info" "verbose"
                                   "debug" "debug1" "debug2" "debug3")
                           :test #'string=)
             (error (ssh-config-line-error line "invalid LogLevel ~S"
                                           value)))
           (setf (ssh-config-options-log-level options) level)))
        ((string= keyword "logverbose")
         (unless (ssh-config-options-log-verbose options)
           (setf (ssh-config-options-log-verbose options)
                 (ssh-config-line-args line))))
        ((string= keyword "escapechar")
         (let ((value (ssh-config-escape-char-value value)))
           (unless value
             (error (ssh-config-line-error line "invalid EscapeChar ~S"
                                           (ssh-config-arg line))))
           (setf (ssh-config-options-escape-char options) value)))
        ((string= keyword "enableescapecommandline")
         (setf (ssh-config-options-enable-escape-commandline options)
               (boolean)))
        ((string= keyword "sessiontype")
         (let ((value (string-downcase value)))
           (unless (member value '("none" "subsystem" "default")
                           :test #'string=)
             (error (ssh-config-line-error line "invalid SessionType ~S"
                                           value)))
           (setf (ssh-config-options-session-type options) value)))
        ((string= keyword "stdinnull")
         (setf (ssh-config-options-stdin-null options) (boolean)))
        ((string= keyword "forkafterauthentication")
         (setf (ssh-config-options-fork-after-authentication options)
               (boolean)))
        ((string= keyword "controlmaster")
         (let ((setting (string-downcase value)))
           (unless (member setting '("yes" "no" "ask" "auto" "autoask")
                           :test #'string=)
             (error (ssh-config-line-error line
                                           "invalid ControlMaster ~S" value)))
           (setf (ssh-config-options-control-master options)
                 (intern (string-upcase setting) :keyword))))
        ((string= keyword "controlpath")
         (setf (ssh-config-options-control-path options)
               (if (string-equal value "none") :none value)))
        ((string= keyword "controlpersist")
         (setf (ssh-config-options-control-persist options)
               (cond
                 ((string-equal value "yes") :yes)
                 ((string-equal value "no") :no)
                 (t (ssh-config-seconds line value)))))
        ((string= keyword "requesttty")
         (setf (ssh-config-options-request-tty options) (string-downcase value)))
        ((string= keyword "preferredauthentications")
         (setf (ssh-config-options-preferred-authentications options)
               (ssh-config-split-list value)))
        ((member keyword '("pubkeyauthentication" "dsaauthentication")
                 :test #'string=)
         ;; DSAAuthentication is the obsolete name ssh still maps to the
         ;; public-key switch.
         (setf (ssh-config-options-pubkey-authentication options)
               (if (boolean) :yes :no)))
        ((string= keyword "passwordauthentication")
         (setf (ssh-config-options-password-authentication options)
               (boolean)))
        ((member keyword '("kbdinteractiveauthentication"
                           "challengeresponseauthentication"
                           "skeyauthentication" "tisauthentication")
                 :test #'string=)
         ;; Three obsolete names that ssh maps to the keyboard-interactive
         ;; switch.
         (setf (ssh-config-options-kbd-interactive-authentication options)
               (boolean)))
        ((string= keyword "numberofpasswordprompts")
         (setf (ssh-config-options-number-of-password-prompts options)
               (integer :minimum 1)))))))

(defun ssh-config-known-client-keyword-p (keyword)
  "Whether KEYWORD is one ssh's client configuration parser accepts."
  (member keyword +ssh-config-client-keywords+ :test #'string=))

(defun ssh-config-check-client-keyword (line options)
  "Refuse LINE's keyword when it is not an ssh_config keyword at all.

A name in +SSH-CONFIG-CLIENT-KEYWORDS+ is always accepted, even when this
client has nothing to do with it: an ssh_config written for OpenSSH must keep
loading.  A name outside the table is a typo or belongs to another program,
and OpenSSH refuses it with \"Bad configuration option\" unless IgnoreUnknown
already named it.  The check happens whether or not the surrounding Host
block is active, as ssh's parse_token does."
  (let ((keyword (ssh-config-line-keyword line)))
    (unless (ssh-config-known-client-keyword-p keyword)
      (let ((ignored (ssh-config-options-ignored-unknown options)))
        (unless (and ignored
                     (ssh-config-pattern-list-match-p
                      (list ignored) keyword :case-insensitive t))
          (error (ssh-config-line-error line
                                        "Bad configuration option: ~A"
                                        keyword)))))))

(defun ssh-config-apply-directive (line options seen context)
  "Apply one non-block directive when the current block is selected."
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((member keyword '("hostname" "port" "user" "hostkeyalias"
                         "canonicalizehostname" "canonicaldomains"
                         "canonicalizemaxdots" "canonicalizefallbacklocal"
                         "canonicalizepermittedcnames")
               :test #'string=)
       (ssh-config-apply-address line options seen context))
      ((member keyword '("identityfile" "identityfile2" "certificatefile"
                         "identityagent"
                         "identitiesonly" "addkeystoagent"
                         "hostbasedauthentication" "hostbasedacceptedalgorithms"
                         "hostbasedkeytypes" "hostbasedkey"
                         "enablesshkeysign")
               :test #'string=)
       (ssh-config-apply-identity line options seen context))
      ((member keyword '("userknownhostsfile" "globalknownhostsfile"
                         "hashknownhosts" "knownhostscommand"
                         "updatehostkeys"
                         "fingerprinthash"
                         "visualhostkey" "checkhostip" "verifyhostkeydns"
                         "nohostauthenticationforlocalhost"
                         "revokedhostkeys"
                         "stricthostkeychecking"
                         "connecttimeout" "connectionattempts"
                         "addressfamily" "batchmode" "ignoreunknown"
                         "warnweakcrypto")
               :test #'string=)
       (ssh-config-apply-policy line options seen context))
      ((member keyword '("ciphers" "macs" "kexalgorithms" "hostkeyalgorithms"
                         "pubkeyacceptedalgorithms" "pubkeyacceptedkeytypes"
                         "casignaturealgorithms" "compression" "rekeylimit")
               :test #'string=)
       (ssh-config-apply-algorithms line options seen))
      ((member keyword '("proxyjump" "proxycommand" "bindaddress" "sendenv"
                         "serveraliveinterval" "serveralivecountmax"
                         "forwardagent" "forwardx11" "forwardx11trusted"
                         "forwardx11timeout" "gssapiauthentication"
                         "gssapidelegatecredentials" "bindinterface"
                         "kbdinteractivedevices" "pkcs11provider"
                         "smartcarddevice" "securitykeyprovider"
                         "proxyusefdpass" "syslogfacility" "tunnel"
                         "tunneldevice" "xauthlocation"
                         "gatewayports" "ipqos" "exitonforwardfailure"
                         "permitremoteopen" "clearallforwardings"
                         "tcpkeepalive" "keepalive"
                         "refuseconnection" "requiredrsasize"
                         "remotecommand" "localcommand"
                         "permitlocalcommand" "escapechar"
                         "enableescapecommandline"
                         "versionaddendum"
                         "loglevel" "logverbose"
                         "sessiontype" "stdinnull"
                         "forkafterauthentication"
                         "channeltimeout"
                         "obscurekeystroketiming"
                         "controlmaster" "controlpath" "controlpersist"
                         "streamlocalbindmask" "streamlocalbindunlink"
                         "requesttty" "tag"
                         "localforward" "remoteforward" "dynamicforward"
                         "setenv"
                         "preferredauthentications" "pubkeyauthentication"
                         "passwordauthentication"
                         "kbdinteractiveauthentication"
                         "dsaauthentication"
                         "challengeresponseauthentication"
                         "skeyauthentication" "tisauthentication"
                         "numberofpasswordprompts")
               :test #'string=)
       (ssh-config-apply-session line options seen))
      (t nil))))

;;; ---- Match ----

(defun ssh-config-match-value (line keyword options context)
  "Whether the current host matches one Match predicate, without negation."
  (let ((value (ssh-config-arg line 1)))
    (cond
      ((string= keyword "host")
       (ssh-config-pattern-list-match-p
        (list value)
        (or (ssh-config-options-hostname options)
            (ssh-config-context-original-host context))
        :case-insensitive t))
      ((string= keyword "originalhost")
       (ssh-config-pattern-list-match-p
        (list value) (ssh-config-context-original-host context)
        :case-insensitive t))
      ((string= keyword "user")
       (ssh-config-pattern-list-match-p
        (list value)
        (or (ssh-config-options-user options)
            (ssh-config-context-user context))))
      ((string= keyword "localuser")
       (ssh-config-pattern-list-match-p (list value) (ssh-default-user)))
      ((string= keyword "localnetwork")
       (ssh-config-localnetwork-match-p
        value (ssh-config-context-local-addresses context)))
      ((string= keyword "version")
       (ssh-config-pattern-list-match-p (list value) +ssh-config-version+))
      ((string= keyword "tagged")
       (ssh-config-pattern-list-match-p
        (list value)
        (or (ssh-config-options-tag options)
            (ssh-config-context-tag context)
            "")))
      (t (error (ssh-config-line-error line "unknown Match condition ~S"
                                       keyword))))))

(defun ssh-config-eval-match (line options context exec-matcher final-pass
                               on-result on-error)
  "Evaluate a Match line, possibly continuing from EXEC-MATCHER's callback.

FINAL-PASS is true while the configuration is re-read after hostname
canonicalization (or because a Match final line asked for it).  Match final
records that the second pass is wanted and, like Match canonical, matches
only during that pass."
  (let ((tokens (ssh-config-line-args line))
        (result t)
        (stopped nil))
    (labels
        ((complete ()
           (unless stopped (funcall on-result result)))
         (advance (remaining)
           (when stopped (return-from advance nil))
           (when (null remaining)
             (return-from advance (complete)))
           (let* ((token (first remaining))
                  (negated (and (plusp (length token))
                                (char= (char token 0) #\!)))
                  (keyword (string-downcase
                            (if negated (subseq token 1) token))))
             (cond
               ((string= keyword "all")
                (cond
                  ((cdr remaining)
                   (setf stopped t)
                   (funcall on-error
                            (ssh-config-line-error
                             line "Match all cannot be combined with conditions")))
                  (t
                   (setf result (and result (not negated)))
                   (advance nil))))
               ((member keyword '("final" "canonical") :test #'string=)
                (when (and (string= keyword "final") (not negated))
                  (setf (ssh-config-options-final-pass-wanted options) t))
                ;; Both criteria look at the pass, not at the hostname.
                (setf result
                      (and result (if negated (not final-pass) final-pass)))
                (advance (rest remaining)))
               ((null (cdr remaining))
                (setf stopped t)
                (funcall on-error
                         (ssh-config-line-error
                          line "Match ~A requires an argument" keyword)))
               ((string= keyword "exec")
                (if (not result)
                    (advance (cddr remaining))
                    (if exec-matcher
                        (funcall exec-matcher
                                 (second remaining)
                                 (lambda (matched)
                                   (setf result
                                         (if negated (not matched) matched))
                                   (advance (cddr remaining)))
                                 (lambda (condition)
                                   (setf stopped t)
                                   (funcall on-error condition)))
                        (progn
                          (setf stopped t)
                          (funcall on-error
                                   (ssh-config-line-error
                                    line "Match exec needs an :EXEC-MATCHER"))))))
               (t
                (let ((matched
                        (ssh-config-match-value
                         line keyword options context)))
                  (setf result (and result (if negated (not matched) matched)))
                  (advance (cddr remaining))))))))
      (advance tokens))))

;;; ---- Resolution ----

(defun ssh-config-resolve (config host
                           &key original-host user port tag
                             exec-matcher local-addresses
                             final-pass options seen
                             on-options on-error)
  "Turn CONFIG into SSH-CONFIG-OPTIONS for HOST.

HOST is the name the user typed; ORIGINAL-HOST defaults to it.  USER and
PORT are the values already decided before config, so a HostName or User
line can still override them.  OPTIONS are delivered to ON-OPTIONS, which
may run before this function returns unless a Match exec had to wait.
EXEC-MATCHER is (COMMAND ON-RESULT ON-ERROR) and must call ON-RESULT with a
boolean; without it a Match exec is an error rather than a blocking POPEN.

FINAL-PASS re-reads the configuration the way OpenSSH does after hostname
canonicalization: HOST is the canonical name, OPTIONS and SEEN continue the
first pass, and Match canonical/final are active.  The caller sets OPTIONS'
HOSTNAME to HOST before the pass, as ssh.c does.

Returns CONFIG."
  (let* ((directives (coerce (or (ssh-config-directives config) '()) 'vector))
         (options (or options (%make-ssh-config-options)))
         (seen (or seen (make-hash-table :test #'equal)))
         (context (%make-ssh-config-context
                   :original-host (or original-host host)
                   :user (or user (ssh-default-user))
                   :port (or port 22)
                   :tag tag
                   :local-addresses local-addresses))
         (stopped nil))
    (labels
        ((report (condition)
           (unless stopped
             (setf stopped t)
             (when on-error (funcall on-error condition))))
         (complete ()
           (unless stopped
             (when on-options (funcall on-options options))))
         (advance (index parsing)
           (handler-case
               (progn
                 (when stopped (return-from advance nil))
                 (loop while (< index (length directives))
                       do (let ((line (aref directives index)))
                            (cond
                              ((string= (ssh-config-line-keyword line) "host")
                               (setf parsing
                                     (ssh-config-host-block-matches-p
                                      line options context))
                               (incf index))
                              ((string= (ssh-config-line-keyword line) "match")
                               (return
                                 (ssh-config-eval-match
                                  line options context exec-matcher final-pass
                                  (lambda (matched)
                                    (advance (1+ index) matched))
                                  #'report)))
                              (t
                               (ssh-config-check-client-keyword line options)
                               (when parsing
                                 (ssh-config-apply-directive
                                  line options seen context))
                               (incf index)))))
                 (complete))
             (error (condition) (report condition)))))
      (advance 0 t))
    config))

;;; ---- Canonicalization ----
;;;
;;; resolve_canonicalize() in ssh.c: try CanonicalDomains candidates, follow a
;;; CNAME when CanonicalizePermittedCNAMEs allows it, then re-read the
;;; configuration so stanzas matching the canonical name take effect.

(defun ssh-config-permitted-cnames-p (options)
  "Whether OPTIONS has a CanonicalizePermittedCNAMEs rule that permits CNAMEs."
  (let ((rules (ssh-config-options-canonicalize-permitted-cnames options)))
    (and rules
         (not (and (null (rest rules))
                   (string-equal (caar rules) "none"))))))

(defun ssh-config-canonical-cname (rules host cname)
  "The name HOST becomes when RULES permit following CNAME, else NIL.

Mirrors check_follow_cname(): both the name being replaced and the canonical
name must match their side of some rule, and the result is lowercased."
  (when (and rules cname (not (string= host cname)))
    (dolist (rule rules)
      (when (and (ssh-config-pattern-list-match-p
                  (list (car rule)) host :case-insensitive t)
                 (ssh-config-pattern-list-match-p
                  (list (cdr rule)) cname :case-insensitive t))
        (return-from ssh-config-canonical-cname
          (string-downcase cname))))))

(defun ssh-config-canonicalize-host
    (host options direct resolve on-host on-error)
  "Compute HOST's canonical name and call ON-HOST with it.

DIRECT is true when neither a ProxyCommand nor a ProxyJump carries the
connection; only then (or with CanonicalizeHostname=always) is a name that a
proxy will interpret handed to the resolver.  RESOLVE is
(HOST ON-SUCCESS ON-ERROR) and calls ON-SUCCESS with (ADDRESS &OPTIONAL
CANONICAL-NAME).  Mirrors resolve_canonicalize() in ssh.c."
  (let ((mode (ssh-config-options-canonicalize-hostname options))
        (rules (ssh-config-options-canonicalize-permitted-cnames options))
        (permitted (ssh-config-permitted-cnames-p options))
        (finished nil))
    (labels
        ((finish (name)
           (unless finished
             (setf finished t)
             (funcall on-host name)))
         (fail (condition)
           (unless finished
             (setf finished t)
             (funcall on-error condition)))
         (follow (name canonical)
           (finish (or (ssh-config-canonical-cname rules name canonical)
                       name)))
         (resolved (name)
           (lambda (address &optional canonical)
             (declare (ignore address))
             (follow name canonical)))
         (not-found (name)
           (if (ssh-config-options-canonicalize-fallback-local options)
               (cname-only name)
               (fail (make-condition
                      'ssh-config-error
                      :detail (format nil "Could not resolve host \"~A\""
                                      name)))))
         (cname-only (name)
           ;; The second ssh.c block: no CanonicalDomains result, but the
           ;; system resolver's own search rules may still yield a CNAME.
           (cond
             ((or (not permitted)
                  (not (or direct (eq mode :always))))
              (finish name))
             (t
              (funcall resolve
                       name
                       (resolved name)
                       (lambda (condition)
                         ;; A proxied name that does not resolve is left
                         ;; alone; a direct one is fatal in ssh.
                         (if direct
                             (fail condition)
                             (finish name)))))))
         (try-domains (domains)
           (if (null domains)
               (not-found host)
               (let ((domain (first domains)))
                 (if (string-equal domain "none")
                     (not-found host)
                     (let ((candidate
                             (if (zerop (length domain))
                                 (format nil "~A." host)
                                 (format nil "~A.~A." host domain))))
                       (funcall resolve
                                candidate
                                (lambda (address &optional canonical)
                                  (declare (ignore address))
                                  (follow (subseq candidate
                                                  0 (1- (length candidate)))
                                          canonical))
                                (lambda (condition)
                                  (declare (ignore condition))
                                  (try-domains (rest domains))))))))))
      (cond
        ((and host (burzay:numeric-address-p host))
         (finish host))
        ((eq mode :no)
         (finish host))
        ((and (not direct) (not (eq mode :always)))
         (finish host))
        ((and (plusp (length host))
              (char= (char host (1- (length host))) #\.))
         ;; Already fully qualified: resolve as-is, then drop the final dot.
         (funcall resolve
                  host
                  (lambda (address &optional canonical)
                    (declare (ignore address))
                    (follow (subseq host 0 (1- (length host))) canonical))
                  (lambda (condition)
                    (declare (ignore condition))
                    (not-found host))))
        ((> (count #\. host)
            (ssh-config-options-canonicalize-max-dots options))
         (cname-only host))
        (t
         (try-domains (ssh-config-options-canonical-domains options)))))))

(defun ssh-config-options-direct-p (options)
  "Whether OPTIONS lets the hostname be resolved locally, not by a proxy.

ssh.c calls this `direct`: no ProxyCommand and no ProxyJump."
  (let ((command (ssh-config-options-proxy-command options))
        (jump (ssh-config-options-proxy-jump options)))
    (and (or (null command)
             (let ((text (string-trim '(#\Space #\Tab)
                                      (if (stringp command)
                                          command
                                          (princ-to-string command)))))
               (or (zerop (length text)) (string-equal text "none"))))
         (or (null jump)
             (let ((text (string-trim '(#\Space #\Tab) jump)))
               (or (zerop (length text)) (string-equal text "none")))))))

(defun ssh-config-canonicalize
    (config host
     &key original-host user port tag exec-matcher local-addresses
       (resolver #'burzay:resolve-host-canonical) direct
       on-options on-error)
  "Resolve CONFIG for HOST, canonicalize the name, and re-read if needed.

This is ssh.c's sequence: resolve the first pass, apply resolve_canonicalize(),
then, when canonicalization ran or a Match final line asked for it, re-read the
configuration with the canonical name in HOSTNAME and Match canonical/final
active.  ON-OPTIONS receives (OPTIONS CANONICAL-HOST); the caller builds the
client from those.  RESOLVER is (HOST ON-SUCCESS ON-ERROR) and may report a
canonical name as ON-SUCCESS's second argument."
  (let ((seen (make-hash-table :test #'equal))
        (original (or original-host host)))
    (labels
        ((finish (options canonical)
           (when on-options (funcall on-options options canonical)))
         (second-pass (options canonical)
           (if (or (ssh-config-options-final-pass-wanted options)
                   (not (eq (ssh-config-options-canonicalize-hostname options)
                            :no)))
               (progn
                 (setf (ssh-config-options-hostname options) canonical)
                 (ssh-config-resolve
                  config canonical
                  :original-host original
                  :user user :port port :tag tag
                  :exec-matcher exec-matcher
                  :local-addresses local-addresses
                  :final-pass t :options options :seen seen
                  :on-options (lambda (options) (finish options canonical))
                  :on-error on-error))
               (finish options canonical)))
         (first-pass (options)
           (let* ((input (or (ssh-config-options-hostname options) host))
                  (direct
                    (cond ((functionp direct) (funcall direct options))
                          ((null direct) (ssh-config-options-direct-p options))
                          (t direct)))
                  (effective
                    (if (and input (not (burzay:numeric-address-p input)))
                        (string-downcase input)
                        input)))
             (ssh-config-canonicalize-host
              effective options direct resolver
              (lambda (canonical) (second-pass options canonical))
              on-error))))
      (ssh-config-resolve
       config host
       :original-host original
       :user user :port port :tag tag
       :exec-matcher exec-matcher
       :local-addresses local-addresses
       :seen seen
       :on-options #'first-pass
       :on-error on-error))))

;;; ---- ProxyCommand ----

(defun ssh-proxy-command-value (command)
  "COMMAND as a ProxyCommand string, or NIL for none.

OpenSSH's \"ProxyCommand none\" turns the proxy off, so an empty or NONE
answer means the direct path rather than a helper named none."
  (when command
    (let ((text (if (stringp command)
                    (string-trim '(#\Space #\Tab) command)
                    command)))
      (unless (and (stringp text)
                   (or (zerop (length text))
                       (string-equal text "none")))
        text))))
