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

(defparameter +ssh-max-identity-files+ 100
  "SSH_MAX_IDENTITY_FILES: readconf refuses more IdentityFile entries.")

(defparameter +ssh-max-certificate-files+ 100
  "SSH_MAX_CERTIFICATE_FILES: readconf refuses more CertificateFile entries.")

(defvar *ssh-config-identity-count-seed* 0
  "Command-line -i entries a caller has already recorded.

ssh processes -i while it parses its arguments, so those files occupy the
first identity slots before readconf sees an -o or a file line.  A caller
that parses -i itself binds this so the shared 100-file limit counts them.")

(defvar *ssh-config-certificate-count-seed* 0
  "Command-line entries counted before readconf's certificate-file limit.")

(defvar *ssh-config-error-function* nil
  "A function of one string for readconf-style configuration diagnostics.

readconf writes each rejected line to stderr as it parses it, then a file's
closing \"terminating, N bad configuration options\" line.  The library calls
this reporter with those exact strings when it is bound; otherwise callers
only see the condition SSH-CONFIG-RESOLVE hands to ON-ERROR.")

(defun ssh-config-readconf-message (condition)
  "CONDITION as the single line readconf would print for its config error.

PATH is the file, or \"command-line\" for an -o option; an error about an
unknown keyword puts the colon after the path, which is how parse_token
formats it.  The caller adds the terminating summary for a file."
  (let ((path (or (ssh-config-error-path condition) "command-line"))
        (line (or (ssh-config-error-line condition) 0))
        (detail (ssh-error-detail condition)))
    (if (ssh-config-error-bare condition)
        detail
        (if (ssh-config-error-bad-option condition)
            (format nil "~A: line ~D: ~A" path line detail)
            (format nil "~A line ~D: ~A" path line detail)))))

(defparameter +ssh-config-directory+ #p"/etc/ssh/"
  "Where OpenSSH keeps ssh_config and sshd_config; a system configuration's
relative Include is anchored here.")

(defparameter +ssh-default-global-known-hosts+
  (list (namestring (merge-pathnames "ssh_known_hosts" +ssh-config-directory+))
        (namestring (merge-pathnames "ssh_known_hosts2"
                                     +ssh-config-directory+)))
  "The system-wide known_hosts files OpenSSH consults by default.")

(defun ssh-default-user-known-hosts ()
  "The user known_hosts files, in the order OpenSSH consults them."
  (list (merge-pathnames ".ssh/known_hosts" (user-homedir-pathname))
        (merge-pathnames ".ssh/known_hosts2" (user-homedir-pathname))))

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
    "hostbasedkeytypes" "hostkeyalgorithms" "hostkeyalias"
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

(defparameter +ssh-config-deprecated-keywords+
  '("cipher" "fallbacktorsh" "globalknownhostsfile2" "rhostsauthentication"
    "userknownhostsfile2" "useroaming" "usersh" "useprivilegedport")
  "Keywords readconf still recognises only to report them as deprecated.

OpenSSH reports these at debug level, so they appear with -v and vanish with
-q.  A -o option never shows the notice at all, because ssh applies it before
it initialises logging.  PROTOCOL is the exception, which readconf ignores
silently.")

(defparameter +ssh-config-unsupported-keywords+
  '("afstokenpassing" "kerberosauthentication" "kerberostgtpassing"
    "rsaauthentication" "rhostsrsaauthentication" "compressionlevel"
    ;; readconf maps these two to oUnsupported when OpenSSH is built without
    ;; GSSAPI, and this build has none either.
    "gssapiauthentication" "gssapidelegatecredentials")
  "Keywords accepted but reported, as readconf's oUnsupported entries.

readconf prints these by default and a single -q silences them, which is the
warning reporter's own rule; the option itself never takes effect.")

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
  (number nil)
  ;; How IdentityFile was supplied, as OpenSSH records it: 1 from -i on the
  ;; command line, 2 from -o or a user configuration file (-F or
  ;; ~/.ssh/config), and 0 from the system ssh_config.  A nonzero value is
  ;; what ssh -Z marks "explicit"; the exact value also decides which
  ;; duplicate paths collapse, because readconf's add_identity_file compares
  ;; it too.
  (userprovided 0)
  ;; True for a line that came from -o, where readconf treats Host, Include
  ;; and Match as file structure and refuses them.  The flag is set only when
  ;; the option list is turned into lines, so a caller that builds a line for
  ;; a file-like block is not affected.
  (command-line nil)
  ;; True when the argument text leaves a quote open.  readconf runs
  ;; argv_split() on the remainder after the keyword for every directive and
  ;; reports "invalid quotes" before the directive is applied, so the line is
  ;; kept and the parser raises the error in its proper place.
  (invalid-quotes nil))

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
  ;; Parallel to IDENTITY-FILES, in the same order: whether each file came from
  ;; a user configuration, which ssh -Z reports as "explicit".
  (identity-files-userprovided nil)
  (certificate-files nil)
  (certificate-files-userprovided nil)
  (identity-agent nil)
  ;; HostbasedAuthentication and its host keys.  EnableSSHKeysign is parsed
  ;; for compatibility; this client signs with a readable host key directly.
  (hostbased-authentication nil)
  (hostbased-accepted-algorithms nil)
  (hostbased-keys '())
  (enable-ssh-keysign nil)
  ;; AddKeysToAgent: :YES adds keys loaded from files to the agent.
  ;; The lifespan is the optional lifetime in seconds ("confirm 5m" or a
  ;; bare "5m"); zero means unlimited.
  (add-keys-to-agent nil)
  (add-keys-to-agent-lifespan 0)
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
  ;; GSSAPIAuthentication and GSSAPIDelegateCredentials are unsupported in
  ;; this build, exactly as in an OpenSSH compiled without GSSAPI: readconf
  ;; reports them and they configure nothing, so no slot records them.
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
  (ip-qos-bulk #x00)
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
  '("id_rsa" "id_ecdsa" "id_ecdsa_sk" "id_ed25519" "id_ed25519_sk"
    "id_mldsa44_ed25519")
  "Identity files OpenSSH tries when no IdentityFile is configured.

The names and their order match OpenSSH 10.6's readconf.c, so -G and ssh -Z
report the same default identityfile lines.  This is a config default rather
than backend state, so the libssh build reports the same lines as the pure
one.")

(defun ssh-default-user ()
  "The local user name, or ROOT when the environment does not say."
  (or (uiop:getenv "USER")
      (uiop:getenv "LOGNAME")
      "root"))

(defun ssh-config-command-value (value)
  "VALUE as a command string, or NIL when unset or the literal none.

readconf clears LocalCommand, RemoteCommand, ProxyCommand and
KnownHostsCommand when the argument is \"none\" (option_clear_or_none), so
the literal spelling means no command even though the keyword was present."
  (cond ((null value) nil)
        ((eq value :none) nil)
        ((and (stringp value)
              (string-equal (string-trim '(#\Space #\Tab) value) "none"))
         nil)
        (t value)))

(defun ssh-config-update-host-keys-default (options)
  "The UpdateHostKeys value readconf fills in when no line set one.

YES only when VerifyHostKeyDNS is unset or explicitly no (readconf tests
verify_host_key_dns <= 0, so both yes and ask disable it) and the user's
known-hosts list is absent or the single default spelling
~/.ssh/known_hosts.  The test runs before ssh.c expands those paths, which
is why the raw spelling matters here."
  (or (ssh-config-options-update-host-keys options)
      (let ((dns (ssh-config-options-verify-host-key-dns options))
            (files (ssh-config-options-known-hosts options)))
        (if (and (or (null dns) (eq dns :no))
                 (or (null files)
                     (and (consp files)
                          (null (rest files))
                          (string= (namestring (first files))
                                   "~/.ssh/known_hosts"))))
            :yes
            :no))))

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
        (quote nil)
        (equals-skipped nil))
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
                 ((ssh-config-whitespace-p character)
                  (emit-token))
                 ;; Exactly one '=' separates the keyword from its value,
                 ;; whether it follows the keyword directly or after
                 ;; whitespace.  A second '=' already belongs to the value,
                 ;; so -o User== keeps the leading '=' for readconf.
                 ((and (char= character #\=)
                       (null tokens))
                  (emit-token)
                  (setf equals-skipped t))
                 ((and (char= character #\=)
                       (not started)
                       (not equals-skipped))
                  (setf equals-skipped t))
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

(defun ssh-config-argv-split (text &key terminate-on-comment)
  "TEXT as an argument list, split the way misc.c's argv_split does.

Quotes group words and are removed, a backslash escapes only a quote, a
backslash, or (outside quotes) a space, and whitespace outside quotes ends a
word.  A '#' at the start of a word begins a comment when
TERMINATE-ON-COMMENT.  Returns (values ARGUMENTS OK); OK is NIL when a quote
is still open at the end, which readconf reports as \"invalid quotes\"."
  (let ((arguments '())
        (length (length text))
        (index 0)
        (ok t))
    (loop while (and ok (< index length))
          do (let ((character (char text index)))
               (cond
                 ((member character '(#\Space #\Tab))
                  (incf index))
                 ((and terminate-on-comment (char= character #\#))
                  (return))
                 (t
                  (let ((token (make-string-output-stream))
                        (quote nil)
                        (finished nil))
                    (loop while (and (not finished) (< index length))
                          do (let ((c (char text index)))
                               (cond
                                 ((char= c #\\)
                                  (if (and (< (1+ index) length)
                                           (let ((next (char text (1+ index))))
                                             (or (char= next #\')
                                                 (char= next #\")
                                                 (char= next #\\)
                                                 (and (null quote)
                                                      (char= next #\Space)))))
                                      (progn
                                        (incf index)
                                        (write-char (char text index) token))
                                      (write-char c token)))
                                 ((and (null quote)
                                       (member c '(#\Space #\Tab)))
                                  (setf finished t))
                                 ((and (null quote)
                                       (member c '(#\" #\')))
                                  (setf quote c))
                                 ((and quote (char= c quote))
                                  (setf quote nil))
                                 (t
                                  (write-char c token)))
                               (incf index)))
                    (when quote
                      (setf ok nil))
                    (push (get-output-stream-string token) arguments))))))
    (values (if ok (nreverse arguments) nil) ok)))

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

(defun ssh-config-tilde-user-home (user)
  "USER's home directory from the local password database, or NIL.

ssh's tilde_expand() calls getpwnam; the password file answers the same
question for the accounts this client is likely to name."
  (and (plusp (length user))
       (handler-case
           (with-open-file (stream "/etc/passwd" :if-does-not-exist nil)
             (when stream
               (loop for line = (read-line stream nil nil)
                     while line
                     for fields = (uiop:split-string line :separator ":")
                     when (and (>= (length fields) 6)
                               (string= (first fields) user))
                       return (sixth fields))))
         (error () nil))))

(defun ssh-config-expand-tilde (path)
  "PATH with a leading ~ or ~USER replaced, as tilde_expand() does.

Returns (values EXPANDED NIL) on success or (values NIL USER) when USER
does not exist.  The directory always keeps a trailing slash, which is how
ssh spells the result for \"~\" and \"~user\"."
  (if (or (zerop (length path)) (char/= (char path 0) #\~))
      (values path nil)
      (let* ((slash (position #\/ path))
             (user (subseq path 1 (or slash (length path))))
             (rest (if slash (string-left-trim "/" (subseq path slash)) ""))
             (home (if (string= user "")
                       (namestring (user-homedir-pathname))
                       (ssh-config-tilde-user-home user))))
        (if (null home)
            (values nil user)
            (values (concatenate 'string
                                 (if (and (plusp (length home))
                                          (char= (char home (1- (length home)))
                                                #\/))
                                     home
                                     (concatenate 'string home "/"))
                                 rest)
                    nil)))))

(defun ssh-config-expand-variables (value)
  "Expand ${NAME} from the environment, leaving an unknown NAME literal.

OpenSSH's percent_dollar_expand substitutes only the braced form; a bare
$NAME stays literal except for IdentityAgent and ForwardAgent, which read it
as an environment variable name.  A reference that cannot be resolved is
left as written here; the caller that cares rejects it."
  (with-output-to-string (out)
    (loop with length = (length value)
          for index from 0 below length
          for character = (char value index)
          do (if (and (char= character #\$)
                      (< (1+ index) length)
                      (char= (char value (1+ index)) #\{))
                 (let* ((start (+ index 2))
                        (end (position #\} value :start start)))
                   (if (and end (< start end))
                       (let ((replacement (uiop:getenv
                                           (subseq value start end))))
                         (if replacement
                             (progn (write-string replacement out)
                                    (setf index end))
                             (progn (write-string value out :start index
                                                  :end (1+ end))
                                    (setf index end))))
                       (write-char character out)))
                 (write-char character out)))))

(defun ssh-config-variable-expansion-problem (value)
  "OpenSSH's dollar_expand() diagnostic for VALUE, or NIL when it is fine.

Only the braced ${NAME} form is expanded, so a value without \"${\" is
always fine.  A missing closing brace, an empty name and an unset variable
are the three failures."
  (loop with start = 0
        for open = (search "${" value :start2 start)
        while open
        do (let* ((name-start (+ open 2))
                  (end (position #\} value :start name-start)))
             (cond
               ((null end)
                (return (format nil
                                "environment variable '~A' missing closing '}'"
                                (subseq value name-start))))
               ((= end name-start)
                (return "zero-length environment variable"))
               ((null (uiop:getenv (subseq value name-start end)))
                (return (format nil "env var ${~A} has no value"
                                (subseq value name-start end))))
               (t (setf start (1+ end)))))))

(defun ssh-config-valid-environment-name-p (name)
  "Whether NAME is a valid environment variable name, as readconf checks one."
  (and (plusp (length name))
       (loop for character across name
             always (or (alphanumericp character)
                        (char= character #\_)))))

(defun ssh-config-report-diagnostic (line text)
  "Write one of dollar_expand()'s own diagnostics for LINE.

An -o option is parsed before log_init, so its diagnostic always reaches
stderr; a configuration file's goes through the log reporter, which honours
-q.  LINE is NIL for a command-line flag such as -L, whose diagnostics
also bypass the log."
  (if (or (null line) (ssh-config-line-command-line line))
      (progn (format *error-output* "~A~%" (ssh-log-escape text))
             (finish-output *error-output*))
      (when *ssh-config-error-function*
        (funcall *ssh-config-error-function* text))))

(defun ssh-forward-expand-value (value line)
  "VALUE with ${NAME} expanded as parse_forward's dollar_expand does.

Reports the helper's own diagnostic for LINE and answers NIL when VALUE
cannot be expanded; otherwise the expanded string is returned.  A bare
$NAME is left alone, as dollar_expand leaves it."
  (let ((problem (ssh-config-variable-expansion-problem value)))
    (when problem
      (ssh-config-report-diagnostic
       line (format nil "vdollar_percent_expand: ~A" problem))
      (return-from ssh-forward-expand-value nil)))
  (ssh-config-expand-variables value))

(defun ssh-config-validate-agent-path (line value)
  "Reject VALUE as readconf validates IdentityAgent and ForwardAgent.

readconf runs dollar_expand() while it reads the line, before checking
whether the block is active, and reports the helper's diagnostic followed by
its own \"Invalid environment expansion\" error.  A legacy $NAME argument is
then checked as an environment variable name."
  (let ((problem (ssh-config-variable-expansion-problem value)))
    (when problem
      (ssh-config-report-diagnostic
       line (format nil "vdollar_percent_expand: ~A" problem))
      (error (ssh-config-line-error
              line "Invalid environment expansion ~A." value))))
  (when (and (plusp (length value))
             (char= (char value 0) #\$)
             (or (= (length value) 1)
                 (char/= (char value 1) #\{))
             (not (ssh-config-valid-environment-name-p (subseq value 1))))
    (error (ssh-config-line-error
            line "Invalid environment name ~A." value))))


(defun ssh-config-connection-hash (local-host host port user jump-host)
  "The %C value: SHA-1 over the connection's identity, as lowercase hex.

FORMAT's ~X directive writes A-F in upper case, while ssh uses the
lower-case spelling, so the result is downcased."
  (string-downcase
   (format nil "~{~2,'0x~}"
           (coerce
            (ssh-hash :sha1
                      (ssh-string-octets
                       (format nil "~A~A~A~A~A"
                               local-host host port user jump-host)))
            'list))))

(defun ssh-config-token-values (options context &key jump-host)
  "The % token replacements ssh uses, as an alist keyed by token character.

The values follow DEFAULT_CLIENT_PERCENT_EXPAND_ARGS: %h is the configured
HostName, %n the host as written, and the rest are the connection's own
names, the local host and user, and the connection hash."
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
         (key-alias (or (ssh-config-options-host-key-alias options)
                        context-host
                        ""))
         (jump (or jump-host "")))
    (list (cons #\h host)
          (cons #\n context-host)
          (cons #\p (format nil "~D" port))
          (cons #\r user)
          (cons #\u local-user)
          (cons #\d (string-right-trim
                     "/" (namestring (user-homedir-pathname))))
          (cons #\i (or (uiop:getenv "UID") ""))
          (cons #\k key-alias)
          (cons #\j jump)
          (cons #\l local-host)
          (cons #\L short-host)
          (cons #\C (ssh-config-connection-hash
                     local-host host port user jump)))))

(defun ssh-config-expand-tokens (value options context &key strict jump-host)
  "Expand the OpenSSH % tokens VALUE may contain.

%h is the configured HostName, %n the host as written, and the rest follow
ssh: %p port, %r remote user, %u local user, %d home, %i uid, %k
HostKeyAlias, %j jump host, %l and %L the local name, %C the connection
hash.  An unknown token is copied literally unless STRICT is set, in which
case it is an error as it is for VersionAddendum."
  (let ((values (ssh-config-token-values options context
                                         :jump-host jump-host)))
    (with-output-to-string (out)
      (loop with length = (length value)
            for index from 0 below length
            for character = (char value index)
            do (if (and (char= character #\%)
                        (< (1+ index) length))
                   (let ((token (char value (1+ index))))
                     (if (char= token #\%)
                         (progn (write-char #\% out) (incf index))
                         (let ((replacement (cdr (assoc token values))))
                           (cond
                             (replacement
                              (write-string replacement out)
                              (incf index))
                             (strict
                              (error 'ssh-config-error
                                     :detail
                                     (format nil
                                             "unknown percent token %~A in ~S"
                                             token value)))
                             (t (write-char character out))))))
                   (write-char character out))))))

(defun ssh-config-percent-dollar-expand (value options context &key no-user)
  "VALUE expanded as ssh.c's default_client_percent_dollar_expand does.

Returns (values EXPANDED NIL NIL) on success, or (values NIL MESSAGE KIND)
where KIND is :MISSING-ENV for an unset ${NAME} and :SYNTAX for anything
vdollar_percent_expand treats as a parse error.  The two kinds matter
because ssh reports them with different fatals.  NO-USER leaves %r and %C
unknown, as DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER does for User."
  (block expand
    (let ((values (ssh-config-token-values options context)))
      (with-output-to-string (out)
        (loop with length = (length value)
              for index from 0 below length
              for character = (char value index)
              do (cond
                   ((and (char= character #\$)
                         (< (1+ index) length)
                         (char= (char value (1+ index)) #\{))
                    (let* ((start (+ index 2))
                           (end (position #\} value :start start)))
                      (cond
                        ((null end)
                         (return-from expand
                           (values nil
                                   (format nil
                                           "environment variable '~A' missing closing '}'"
                                           (subseq value start))
                                   :syntax)))
                        ((= end start)
                         (return-from expand
                           (values nil "zero-length environment variable"
                                   :syntax)))
                        (t
                         (let* ((name (subseq value start end))
                                (replacement (uiop:getenv name)))
                           (unless replacement
                             (return-from expand
                               (values nil
                                       (format nil
                                               "env var ${~A} has no value"
                                               name)
                                       :missing-env)))
                           (write-string replacement out)
                           (setf index end))))))
                   ((char= character #\%)
                    (cond
                      ((>= (1+ index) length)
                       (return-from expand
                         (values nil "invalid format" :syntax)))
                      ((char= (char value (1+ index)) #\%)
                       (write-char #\% out)
                       (incf index))
                      (t
                       (let* ((token (char value (1+ index)))
                              (replacement
                                (and (not (and no-user
                                               (member token '(#\r #\C))))
                                     (cdr (assoc token values)))))
                         (unless replacement
                           (return-from expand
                             (values nil
                                     (format nil "unknown key %~A" token)
                                     :syntax)))
                         (write-string replacement out)
                         (incf index)))))
                   (t (write-char character out))))))))

(defun ssh-config-path-argument (value options context)
  "VALUE as a pathname with %, $ and ~ expanded.

A relative path stays relative: readconf stores it as written and the file
is opened against the process's own directory, not the home directory."
  (let ((value (ssh-config-expand-variables
                (ssh-config-expand-tokens value options context))))
    (pathname (ssh-config-expand-home value))))

(defun ssh-config-path-value (line options context)
  "A path argument with %, $ and ~ expanded."
  (ssh-config-path-argument (ssh-config-string-arg line) options context))

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
  ;; readconf's loop simply ends when getline() fails, so a path that opens
  ;; but cannot be read (a directory, for one) is an empty configuration.
  ;; ssh -F /tmp therefore connects with the built-in defaults instead of
  ;; reporting an error.
  (when (uiop:directory-exists-p path)
    (return-from ssh-config-read-directives '()))
  (let ((directives '())
        (number 0))
    (with-open-file (stream path :direction :input :external-format :utf-8)
      (loop for line = (read-line stream nil nil)
            while line
            do (incf number)
               (let* ((tokens (ssh-config-tokenize line))
                      (remainder (and tokens (ssh-config-line-remainder line)))
                      ;; readconf runs argv_split() on the text after the
                      ;; keyword before it applies anything, so an open quote
                      ;; rejects the line no matter which directive it names.
                      (invalid (and remainder
                                    (not (nth-value
                                          1 (ssh-config-argv-split
                                             remainder
                                             :terminate-on-comment t))))))
                 (when (and tokens
                            (plusp (length (first tokens)))
                            (not (char= (char (first tokens) 0) #\#)))
                   (let ((keyword (string-downcase (first tokens))))
                     (if (string= keyword "include")
                         (progn
                           ;; Keep the Include line itself so the resolver
                           ;; validates its arguments.  An empty one is a bad
                           ;; configuration option, as in readconf; the files
                           ;; themselves are expanded here.  A line with an
                           ;; open quote never reaches the include handling,
                           ;; because argv_split() failed first.
                           (push (%make-ssh-config-line
                                  :keyword keyword
                                  :args (rest tokens)
                                  :raw remainder
                                  :path path
                                  :number number
                                  :invalid-quotes invalid
                                  :userprovided (if user-config 2 0))
                                 directives)
                           (unless invalid
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
                               (unless (zerop (length argument))
                                 (dolist (file (ssh-config-include-files
                                                (ssh-config-include-path
                                                 argument :user-config user-config)))
                                   ;; DIRECTIVES is held reversed, so push each
                                   ;; included line in turn to keep the file
                                   ;; content where the Include appeared.
                                   (dolist (directive
                                            (ssh-config-read-directives
                                             file (1+ depth)
                                             :user-config user-config))
                                     (push directive directives)))))))
                         (push (%make-ssh-config-line
                                :keyword keyword
                                :args (rest tokens)
                                :raw remainder
                                :path path
                                :number number
                                :invalid-quotes invalid
                                :userprovided (if user-config 2 0))
                               directives)))))))
    (nreverse directives)))

(defun ssh-config-load (path &key (user-config t))
  "Parse the ssh_config file at PATH into an SSH-CONFIG, or NIL if absent.

USER-CONFIG selects user-configuration Include anchoring, as OpenSSH does for
~/.ssh/config and for a -F file; NIL is the system ssh_config."
  (let ((path (pathname (ssh-config-expand-home (namestring path)))))
    (when (probe-file path)
      (%make-ssh-config :path path
                        :directives (ssh-config-read-directives
                                     path 0 :user-config user-config)))))

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
  (flet ((line (keyword args &optional raw invalid-quotes)
           (unless (plusp (length keyword))
             (error 'ssh-config-error :detail "an -o option has no keyword"))
           (%make-ssh-config-line
            :keyword (string-downcase keyword)
            :args (mapcar (lambda (arg) (princ-to-string arg)) args)
            ;; -o goes through process_config_line with SSHCONF_USERCONF, so
            ;; readconf records it as 2, the same as a user config file.
            :userprovided 2
            :invalid-quotes invalid-quotes
            :raw (or raw
                     (format nil "~{~A~^ ~}"
                             (mapcar (lambda (arg) (princ-to-string arg))
                                     args))))))
    (etypecase option
      (string
       (let* ((tokens (ssh-config-tokenize option))
              (remainder (ssh-config-line-remainder option)))
         (unless tokens
           (error 'ssh-config-error
                  :detail (format nil "empty -o option ~S" option)))
         (line (first tokens) (rest tokens) remainder
               (not (nth-value 1 (ssh-config-argv-split
                                  remainder :terminate-on-comment t))))))
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
  "OPTIONS as a list of SSH-CONFIG-LINE, in the order given.

The lines are marked as command-line options, which is what makes readconf
refuse Host, Include and Match from -o."
  (mapcar (lambda (option)
            (let ((line (ssh-config-option-line option)))
              (setf (ssh-config-line-command-line line) t)
              line))
          options))

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

(defun %ssh-config-line-error (line detail &key bad-option bare fatal)
  "An SSH-CONFIG-ERROR for LINE with DETAIL already formatted.

LINE may be NIL for a value the command line supplies, which has neither a
path nor a line number to report."
  (make-condition 'ssh-config-error
                  :detail detail
                  :path (and line
                             (ssh-config-line-path line)
                             (namestring (ssh-config-line-path line)))
                  :line (and line (ssh-config-line-number line))
                  :keyword (and line (ssh-config-line-keyword line))
                  :bad-option bad-option
                  :bare bare
                  :fatal fatal))

(defun ssh-config-line-error (line control &rest arguments)
  (apply #'%ssh-config-line-error line
         (apply #'format nil control arguments) '()))

(defun ssh-config-say (line control &rest arguments)
  "Write a readconf diagnostic for LINE now, before the final error.

readconf's parse_multistate_value and kex_names_valid print their own line
and then the caller prints a second one, so the two are separate."
  (when *ssh-config-error-function*
    (funcall *ssh-config-error-function*
             (ssh-config-readconf-message
              (apply #'ssh-config-line-error line control arguments)))))

(defun ssh-config-arg (line &optional (index 0))
  "Argument INDEX of LINE; empty arguments are returned as empty strings.

readconf treats an absent argument and an empty one differently: the former
is reported by the caller as \"no argument after keyword\", while each
directive decides what to say about \"\"."
  (nth index (ssh-config-line-args line)))

(defun ssh-config-string-arg (line &optional (index 0))
  "Argument INDEX of LINE as readconf's parse_string accepts one.

A string directive refuses both an absent and an empty argument with
\"Missing argument.\", so an ssh_config with User \"\" is invalid even
though the tokenizer preserved the empty word."
  (let ((value (ssh-config-arg line index)))
    (when (or (null value) (zerop (length value)))
      (error (ssh-config-line-error line "Missing argument.")))
    value))

(defun ssh-config-domain (line value)
  "VALUE as misc.c's valid_domain(makelower=1) accepts it, or signal.

Returns the lowercased name with a trailing dot removed, which is what
readconf stores for CanonicalDomains."
  (let ((length (length value)))
    (cond
      ((zerop length)
       (error (ssh-config-line-error line "empty domain name")))
      ((not (or (alpha-char-p (char value 0))
                (digit-char-p (char value 0))
                (char= (char value 0) #\_)))
       (error (ssh-config-line-error
               line "domain name \"~A\" starts with invalid character"
               value))))
    (let ((last nil))
      (loop for character across value
            for lower = (char-downcase character)
            do (when (and last (char= last #\.) (char= lower #\.))
                 (error (ssh-config-line-error
                         line "domain name \"~A\" contains consecutive separators"
                         value)))
               (unless (or (char= lower #\.)
                           (char= lower #\-)
                           (alphanumericp lower)
                           (char= lower #\_))
                 (error (ssh-config-line-error
                         line "domain name \"~A\" contains invalid characters"
                         value)))
               (setf last lower)))
    (string-right-trim "." (string-downcase value))))

(defun ssh-config-boolean (line value)
  "VALUE as a readconf flag; anything else is \"unsupported option\"."
  (cond ((or (string-equal value "yes") (string-equal value "true")) t)
        ((or (string-equal value "no") (string-equal value "false")) nil)
        (t
         (when (zerop (length value))
           (ssh-config-say line "missing argument."))
         (error (ssh-config-line-error line "unsupported option \"~A\"." value)))))

(defun ssh-config-multistate (line value table)
  "VALUE looked up in TABLE, an alist of name to value, or an error.

readconf's parse_multistate_value prints \"missing argument.\" for an empty
argument and the caller then prints \"unsupported option\" for the same
argument, so a bad value is two lines."
  (let ((entry (assoc value table :test #'string-equal)))
    (cond
      (entry (cdr entry))
      (t
       (when (zerop (length value))
         (ssh-config-say line "missing argument."))
       (error (ssh-config-line-error line "unsupported option \"~A\"." value))))))

(defun ssh-config-integer (line value &key minimum maximum)
  "VALUE as readconf's atoi_err reads an integer, 0..INT_MAX.

MINIMUM and MAXIMUM narrow that range for the few keywords that have their
own bound; going outside any of them is what strtonum calls \"too small\"
or \"too large\"."
  (let ((problem (ssh-config-atoi-error value)))
    (when problem
      (error (ssh-config-line-error line "integer value ~A." problem))))
  (let ((number (parse-integer value)))
    (unless (and (or (null minimum) (>= number minimum))
                 (or (null maximum) (<= number maximum)))
      (error (ssh-config-line-error
              line "integer value ~A."
              (if (and minimum (< number minimum)) "too small" "too large"))))
    number))

(defun ssh-a2port-service (name)
  "NAME's TCP port from the platform services database, or NIL.

a2port falls back to getservbyname, so \"Port ssh\" and \"-p http\" name
services.  Reading the database directly keeps this portable across the
platforms this client runs on."
  (let ((path
          (if (uiop:os-windows-p)
              (let ((root (uiop:getenv "SystemRoot")))
                (and root
                     (merge-pathnames
                      "System32/drivers/etc/services"
                      (uiop:ensure-directory-pathname root))))
              #p"/etc/services")))
    (when (and path (probe-file path))
      (with-open-file (stream path :if-does-not-exist nil)
        (when stream
          (loop for line = (read-line stream nil nil)
                while line
                do (let ((hash (position #\# line)))
                     (when hash (setf line (subseq line 0 hash)))
                     (let ((fields (remove-if (lambda (field)
                                                (zerop (length field)))
                                              (uiop:split-string
                                               line
                                               :separator '(#\Space #\Tab)))))
                       (when (and (>= (length fields) 2)
                                  (or (string= (first fields) name)
                                      (member name (cddr fields)
                                              :test #'string=)))
                         (let* ((slash (position #\/ (second fields)))
                                (number-text
                                  (if slash
                                      (subseq (second fields) 0 slash)
                                      (second fields)))
                                (service (and slash
                                              (subseq (second fields)
                                                      (1+ slash))))
                                (number
                                  (handler-case
                                      (parse-integer number-text)
                                    (error () nil))))
                           (when (and number
                                      (<= 0 number 65535)
                                      (or (null service)
                                          (string-equal service "tcp")))
                             (return-from ssh-a2port-service number))))))))))))

(defun ssh-a2port (value)
  "VALUE as OpenSSH's a2port reads it: 0..65535, a TCP service name, or NIL."
  (let ((number (handler-case (parse-integer value :junk-allowed nil)
                  (error () nil))))
    (cond
      ((and number (<= 0 number 65535)) number)
      (t (ssh-a2port-service value)))))

(defun ssh-config-port (line value)
  "VALUE as readconf's a2port reads a port: 1..65535 or \"Bad port\"."
  (when (zerop (length value))
    (error (ssh-config-line-error line "Missing argument.")))
  (let ((number (ssh-a2port value)))
    (unless (and number (plusp number))
      (error (ssh-config-line-error line "Bad port '~A'." value)))
    number))

(defun ssh-parse-scaled (value)
  "VALUE as scan_scaled reads a size in bytes, or NIL when it is invalid.

The syntax is digits with an optional decimal fraction and an optional
B/K/M/G/T/P/E suffix, as OpenSSH's RekeyLimit accepts.  The suffix is a
power of 1024, case-insensitively, and anything after it is invalid.  A
leading minus is accepted, because scan_scaled accepts one; each directive
then decides whether a negative size is usable."
  (when (and (stringp value) (plusp (length value)))
    (let ((position 0)
          (length (length value))
          (negative nil))
      (loop while (and (< position length)
                       (member (char value position)
                               '(#\Space #\Tab #\Return #\Linefeed)))
            do (incf position))
      (when (and (< position length)
                 (member (char value position) '(#\+ #\-)))
        (setf negative (char= (char value position) #\-))
        (incf position))
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
            (cond
              ((> result (1- (expt 2 63))) nil)
              (negative (- result))
              (t result))))))))

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
  (when (zerop (length value))
    (error (ssh-config-line-error line "missing time value.")))
  (if (string-equal value "none")
      :none
      (let ((total 0)
            (number 0)
            (digits 0))
        (flet ((flush (multiplier)
                 (unless (plusp digits)
                   (error (ssh-config-line-error line "invalid time value.")))
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
                                                      "invalid time value.")))))
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
      (error (%ssh-config-line-error
              line (format nil "invalid channel timeout ~A" argument)
              :fatal t)))
    (let ((seconds (ssh-parse-time (subseq argument (1+ equals)))))
      (unless seconds
        (error (%ssh-config-line-error
                line (format nil "invalid channel timeout ~A" argument)
                :fatal t)))
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
                         line "Invalid permitted CNAME ~S" argument)))
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
  "VALUES MATCHED PATTERN SKIPPED for LINE's Host patterns.

MATCHED says whether the block applies.  PATTERN is the first positive
pattern that selected it, which is the one readconf names in its \"Applying
options for\" debug line, and SKIPPED is the negated pattern that vetoed the
block, if a negation is why it does not apply.

The first pass follows a HostName directive that has already been read; the
final pass follows the canonical name placed in HOSTNAME by its caller.
ORIGINAL-HOST remains the name the user typed, for %n and OriginalHost."
  (let ((text (or (ssh-config-options-hostname options)
                  (ssh-config-context-original-host context)))
        (matched nil)
        (pattern nil))
    (dolist (argument (ssh-config-line-args line))
      (when (zerop (length argument))
        (error (ssh-config-line-error line "keyword host empty argument")))
      (dolist (piece (uiop:split-string argument :separator ","))
        (let ((negated (and (plusp (length piece))
                            (char= (char piece 0) #\!))))
          (when negated
            (setf piece (subseq piece 1)))
          (when (ssh-config-glob-match (string-downcase piece)
                                       (string-downcase text))
            (if negated
                (return-from ssh-config-host-block-matches-p
                  (values nil nil piece))
                (unless matched
                  (setf matched t
                        pattern argument)))))))
    (values matched pattern nil)))

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
  (declare (ignore context))
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((string= keyword "hostname")
       (ssh-config-set-once
        seen options :hostname
        (lambda (options)
          ;; readconf stores HostName exactly as written.  ssh.c expands
          ;; only %h in it, at connection time, and lowercases the result;
          ;; $ and ${} are never expanded.  The caller does that through
          ;; SSH-CONFIG-CANONICALIZE's :PREPARE-OPTIONS.
          (setf (ssh-config-options-hostname options)
                (ssh-config-string-arg line)))))
      ((string= keyword "port")
       (ssh-config-set-once
        seen options :port
        (lambda (options)
          (setf (ssh-config-options-port options)
                (ssh-config-port line (ssh-config-arg line))))))
      ((string= keyword "user")
       (ssh-config-set-once
        seen options :user
        (lambda (options)
          (setf (ssh-config-options-user options)
                (ssh-config-expand-variables
                 (ssh-config-string-arg line))))))
      ((string= keyword "canonicalizehostname")
       (ssh-config-set-once
        seen options :canonicalize-hostname
        (lambda (options)
          (setf (ssh-config-options-canonicalize-hostname options)
                (ssh-config-multistate
                 line (ssh-config-arg line)
                 '(("yes" . :yes) ("true" . :yes)
                   ("no" . :no) ("false" . :no)
                   ("always" . :always)))))))
      ((string= keyword "canonicaldomains")
       (let ((domains (mapcar (lambda (argument)
                                (ssh-config-domain line argument))
                              (ssh-config-line-args line))))
         (ssh-config-set-once
          seen options :canonical-domains
          (lambda (options)
            (setf (ssh-config-options-canonical-domains options) domains)))))
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
          ;; HostKeyAlias gets no expansion at all; ssh only lowercases it
          ;; after reading the configuration.
          (setf (ssh-config-options-host-key-alias options)
                (ssh-config-string-arg line))))))))

(defun ssh-config-path-duplicate-p (paths flags value userprovided)
  "Whether PATHS already names VALUE with the same USERPROVIDED marker.

readconf's add_identity_file ignores a second entry with the same spelling
and the same userprovided value, so -i duplicates and -o duplicates collapse
while an -i and an -o naming the same file both survive.  The check compares
the strings as written: ~ is only expanded when the file is loaded."
  (loop for path in paths
        for flag in flags
        thereis (and (eql flag userprovided)
                     (string= (namestring path) value))))

(defun ssh-config-apply-identity (line options seen context &key (active t))
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((member keyword '("identityfile" "identityfile2") :test #'string=)
       ;; IdentityFile2 is OpenSSH's obsolete spelling of IdentityFile; it
       ;; still names an identity and joins the same ordered list.
       ;;
       ;; The path is kept as written.  ssh prints it unchanged in -G and
       ;; only expands ~ and tokens when it loads the file, so expanding it
       ;; here would show the wrong spelling and lose readconf's duplicate
       ;; check.
       (let ((value (ssh-config-string-arg line))
             (userprovided (ssh-config-line-userprovided line)))
         (when (and active
                    (>= (+ *ssh-config-identity-count-seed*
                           (length (ssh-config-options-identity-files options)))
                        +ssh-max-identity-files+))
           (error (ssh-config-line-error
                   line "Too many identity files specified (max ~D)."
                   +ssh-max-identity-files+)))
         (unless (ssh-config-path-duplicate-p
                  (ssh-config-options-identity-files options)
                  (ssh-config-options-identity-files-userprovided options)
                  value userprovided)
           (push (pathname value)
                 (ssh-config-options-identity-files options))
           (push userprovided
                 (ssh-config-options-identity-files-userprovided options)))))
      ((string= keyword "certificatefile")
       (let ((value (ssh-config-string-arg line))
             (userprovided (ssh-config-line-userprovided line)))
         (when (and active
                    (>= (+ *ssh-config-certificate-count-seed*
                           (length
                            (ssh-config-options-certificate-files options)))
                        +ssh-max-certificate-files+))
           (error (ssh-config-line-error
                   line "Too many certificate files specified (max ~D)."
                   +ssh-max-certificate-files+)))
         (unless (ssh-config-path-duplicate-p
                  (ssh-config-options-certificate-files options)
                  (ssh-config-options-certificate-files-userprovided options)
                  value userprovided)
           (push (pathname value)
                 (ssh-config-options-certificate-files options))
           (push userprovided
                 (ssh-config-options-certificate-files-userprovided options)))))
      ((string= keyword "identityagent")
       (let ((raw (ssh-config-arg line)))
         ;; readconf reports an empty argument with its own capitalised
         ;; wording, before any environment checks.
         (when (zerop (length raw))
           (error (ssh-config-line-error line "Missing argument.")))
         ;; readconf validates the argument before it checks whether the
         ;; value is already set, so a later bad line is still an error.
         (ssh-config-validate-agent-path line raw)
         (ssh-config-set-once
          seen options :identity-agent
          (lambda (options)
            (setf (ssh-config-options-identity-agent options)
                  (cond
                    ((string-equal raw "none") :none)
                    ((string-equal raw "SSH_AUTH_SOCK") :environment)
                    ;; readconf stores the spelling; ssh.c expands ~ and
                    ;; ${} and % tokens after the whole file is read.
                    (t (pathname raw))))))))
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
          (let ((value (ssh-config-string-arg line)))
            (ssh-config-validate-algorithm-names
             line value +ssh-config-config-key-names+
             :wildcards t
             :on-bad (lambda (name)
                       (declare (ignore name))
                       (error (ssh-config-line-error
                               line "Bad key types '~A'." value))))
            (setf (ssh-config-options-hostbased-accepted-algorithms options)
                  (ssh-config-split-list value))))))
      ((string= keyword "enablesshkeysign")
       (ssh-config-set-once
        seen options :enable-ssh-keysign
        (lambda (options)
          (setf (ssh-config-options-enable-ssh-keysign options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((string= keyword "addkeystoagent")
       ;; readconf's oAddKeysToAgent is not a plain multistate: an invalid
       ;; first word may be a bare lifetime ("5m" means yes), "confirm" may
       ;; take a lifetime, and its error line carries no argument.
       (ssh-config-set-once
        seen options :add-keys-to-agent
        (lambda (options)
          (let* ((arguments (ssh-config-line-args line))
                 (raw (first arguments))
                 (extra (second arguments))
                 (lower (string-downcase raw))
                 (state (cond ((member lower '("yes" "true") :test #'string=)
                               :yes)
                              ((member lower '("no" "false") :test #'string=)
                               :no)
                              ((string= lower "ask") :ask)
                              ((string= lower "confirm") :confirm)
                              (t nil)))
                 (lifespan 0))
            (cond
              ((and (eq state :confirm) extra)
               (let ((seconds (ssh-parse-time extra)))
                 (unless seconds
                   (error (ssh-config-line-error line "invalid time value.")))
                 (setf lifespan seconds
                       (ssh-config-options-add-keys-to-agent options) :confirm)))
              ((and (null state) (null extra))
               (when (zerop (length raw))
                 (ssh-config-say line "missing argument."))
               (let ((seconds (and (plusp (length raw))
                                   (ssh-parse-time raw))))
                 (if seconds
                     (setf lifespan seconds
                           (ssh-config-options-add-keys-to-agent options) :yes)
                     (error (ssh-config-line-error
                             line "unsupported option")))))
              ((or (null state) extra)
               (when (zerop (length raw))
                 (ssh-config-say line "missing argument."))
               (error (ssh-config-line-error line "unsupported option")))
              (t
               (setf (ssh-config-options-add-keys-to-agent options)
                     state)))
            (setf (ssh-config-options-add-keys-to-agent-lifespan options)
                  lifespan))))))))

(defun ssh-config-known-host-paths (line options context)
  "The paths on a known-hosts line; :NONE for the literal none.

readconf stores these spellings exactly as written.  ssh.c later expands
tilde, % tokens and ${} in the user's list but leaves GlobalKnownHostsFile
alone; the caller applies that difference."
  (declare (ignore options context))
  (let ((values (ssh-config-line-args line))
        (keyword (ssh-config-line-keyword line)))
    (dolist (value values)
      (when (zerop (length value))
        (error (ssh-config-line-error
                line "keyword ~A empty argument" keyword))))
    (when (and (some (lambda (value) (string-equal value "none")) values)
               (not (and (null (rest values))
                         (string-equal (first values) "none"))))
      (error (ssh-config-line-error
              line "keyword ~A \"none\" argument must appear alone."
              keyword)))
    (if (and values (string-equal (first values) "none"))
        :none
        (mapcar #'pathname values))))

(defun ssh-config-apply-policy (line options seen context)
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((string= keyword "userknownhostsfile")
       (ssh-config-set-once
        seen options :known-hosts
        (lambda (options)
          (let ((paths (ssh-config-known-host-paths
                        line options context)))
            ;; NONE is distinct from unset: the default names two files,
            ;; while "none" names none.
            (setf (ssh-config-options-known-hosts options)
                  (if (eq paths :none) :none paths))))))
      ((string= keyword "globalknownhostsfile")
       (ssh-config-set-once
        seen options :global-known-hosts
        (lambda (options)
          (let ((paths (ssh-config-known-host-paths line options context)))
            (setf (ssh-config-options-global-known-hosts options)
                  (if (eq paths :none) :none paths))))))
      ((string= keyword "updatehostkeys")
       (ssh-config-set-once
        seen options :update-host-keys
        (lambda (options)
          (setf (ssh-config-options-update-host-keys options)
                (ssh-config-multistate
                 line (ssh-config-arg line)
                 '(("yes" . :yes) ("true" . :yes)
                   ("no" . :no) ("false" . :no)
                   ("ask" . :ask)))))))
      ((string= keyword "knownhostscommand")
       (ssh-config-set-once
        seen options :known-hosts-command
        (lambda (options)
          (setf (ssh-config-options-known-hosts-command options)
                (let ((raw (ssh-config-line-raw line)))
                  (let ((text (if (and raw (plusp (length raw)))
                                  raw
                                  (ssh-config-arg line))))
                    (if (string-equal text "none") :none text)))))))
      ((string= keyword "ignoreunknown")
       (let ((arguments (ssh-config-line-args line)))
         (when (> (length arguments) 1)
           (error (ssh-config-line-error
                   line "keyword ignoreunknown extra arguments at end of line")))
         (ssh-config-set-once
          seen options :ignored-unknown
          (lambda (options)
            (setf (ssh-config-options-ignored-unknown options)
                  (ssh-config-string-arg line))))))
      ((string= keyword "fingerprinthash")
       (ssh-config-set-once
        seen options :fingerprint-hash
        (lambda (options)
          (let* ((argument (ssh-config-string-arg line))
                 (value (string-downcase argument)))
            (unless (member value '("md5" "sha1" "sha256" "sha384" "sha512")
                            :test #'string=)
              (error (ssh-config-line-error
                      line "Invalid hash algorithm \"~A\"." argument)))
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
          (setf (ssh-config-options-verify-host-key-dns options)
                (ssh-config-multistate
                 line (ssh-config-arg line)
                 '(("yes" . :yes) ("true" . :yes)
                   ("no" . :no) ("false" . :no)
                   ("ask" . :ask)))))))
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
         (dolist (value values)
           (when (zerop (length value))
             (error (ssh-config-line-error
                     line "keyword revokedhostkeys empty argument"))))
         (when (and (some (lambda (value) (string-equal value "none")) values)
                    (not (and (= 1 (length values))
                              (string-equal (first values) "none"))))
           (error (ssh-config-line-error
                   line "keyword revokedhostkeys \"none\" argument must appear alone.")))
         (if (and (= 1 (length values))
                  (string-equal (first values) "none"))
             (setf (ssh-config-options-revoked-host-keys options) nil)
             (dolist (value values)
               ;; readconf stores each spelling; ssh.c expands ~, ${} and
               ;; % tokens once the whole configuration is read.
               (push (pathname value)
                     (ssh-config-options-revoked-host-keys options))))))
      ((string= keyword "stricthostkeychecking")
       (ssh-config-set-once
        seen options :strict-host-key-checking
        (lambda (options)
          (setf (ssh-config-options-strict-host-key-checking options)
                (ssh-config-multistate
                 line (ssh-config-arg line)
                 '(("yes" . "yes") ("true" . "yes")
                   ("no" . "no") ("false" . "no")
                   ("off" . "off") ("ask" . "ask")
                   ("accept-new" . "accept-new")))))))
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
                (ssh-config-integer line (ssh-config-arg line))))))
      ((string= keyword "addressfamily")
       (ssh-config-set-once
        seen options :address-family
        (lambda (options)
          (setf (ssh-config-options-address-family options)
                (ssh-config-multistate
                 line (ssh-config-arg line)
                 '(("any" . :any) ("inet" . :inet) ("inet6" . :inet6)))))))
      ((string= keyword "batchmode")
       (ssh-config-set-once
        seen options :batch-mode
        (lambda (options)
          (setf (ssh-config-options-batch-mode options)
                (ssh-config-boolean line (ssh-config-arg line))))))
      ((string= keyword "warnweakcrypto")
       ;; A multistate, not a boolean: readconf also accepts no-pq-kex, which
       ;; its table maps to the same false value as no, and an empty or
       ;; unknown word is "missing argument." plus "unsupported option".
       (ssh-config-set-once
        seen options :warn-weak-crypto
        (lambda (options)
          (setf (ssh-config-options-warn-weak-crypto options)
                (ssh-config-multistate
                 line (ssh-config-arg line)
                 '(("yes" . :yes) ("true" . :yes)
                   ("no" . :no) ("false" . :no)
                   ("no-pq-kex" . :no))))))))))

(defun ssh-config-say-bare (text)
  "Write TEXT to readconf's diagnostic stream with no file or line prefix."
  (when *ssh-config-error-function*
    (funcall *ssh-config-error-function* text)))

(defun ssh-config-validate-algorithm-names (line value names
                                            &key wildcards plain-only on-bad)
  "Check VALUE against NAMES as readconf validates an algorithm keyword.

A leading '-' is readconf's \"remove\" form and is not validated at all; '+'
and '^' have already been stripped before ciphers_valid sees the list."
  (unless (and (plusp (length value)) (char= (char value 0) #\-))
    (let ((text (if (and (plusp (length value))
                         (member (char value 0) '(#\+ #\^)))
                    (subseq value 1)
                    value)))
      (dolist (name (uiop:split-string text :separator ","))
        ;; strsep stops at an empty element, so anything after it is ignored.
        (when (zerop (length name))
          (return))
        (let ((ok
                (if wildcards
                    (and (or (not plain-only) (not (search "-cert" name)))
                         (some (lambda (known)
                                 (ssh-match-pattern name known))
                               names))
                    (member name names :test #'string=))))
          (unless ok
            (funcall on-bad name)))))))

(defun ssh-config-check-algorithm-argument (line value message)
  "Refuse an empty algorithm argument the way readconf's cases do."
  (when (zerop (length value))
    (error (ssh-config-line-error line "Missing argument.")))
  message)

(defun ssh-config-apply-algorithms (line options seen)
  (let ((keyword (ssh-config-line-keyword line)))
    (flet ((check ()
             (let ((value (ssh-config-arg line)))
               (when (zerop (length value))
                 (error (ssh-config-line-error line "Missing argument.")))
               value))
           (bad (message value name)
             (declare (ignore name))
             (error (ssh-config-line-error
                     line "~A" (format nil message value)))))
      (declare (ignorable #'bad))
      (cond
      ((string= keyword "ciphers")
       (ssh-config-set-once
        seen options :ciphers
        (lambda (options)
          (let ((value (check)))
            (ssh-config-validate-algorithm-names
             line value +ssh-all-ciphers+
             :on-bad (lambda (name)
                       (bad "Bad SSH2 cipher spec '~A'." value name)))
            (setf (ssh-config-options-ciphers options)
                  (ssh-config-split-list value))))))
      ((string= keyword "macs")
       (ssh-config-set-once
        seen options :macs
        (lambda (options)
          (let ((value (check)))
            (ssh-config-validate-algorithm-names
             line value +ssh-all-macs+
             :on-bad (lambda (name)
                       (bad "Bad SSH2 MAC spec '~A'." value name)))
            (setf (ssh-config-options-macs options)
                  (ssh-config-split-list value))))))
      ((string= keyword "kexalgorithms")
       (ssh-config-set-once
        seen options :kex-algorithms
        (lambda (options)
          (let ((value (check)))
            (ssh-config-validate-algorithm-names
             line value +ssh-kex-real-algorithms+
             :on-bad (lambda (name)
                       (ssh-config-say-bare
                        (format nil "Unsupported KEX algorithm \"~A\"" name))
                       (bad "Bad SSH2 KexAlgorithms '~A'." value name)))
            (setf (ssh-config-options-kex-algorithms options)
                  (ssh-config-split-list value))))))
      ((string= keyword "hostkeyalgorithms")
       (ssh-config-set-once
        seen options :host-key-algorithms
        (lambda (options)
          (let ((value (check)))
            (ssh-config-validate-algorithm-names
             line value +ssh-config-config-key-names+
             :wildcards t
             :on-bad (lambda (name)
                       (bad "Bad key types '~A'." value name)))
            (setf (ssh-config-options-host-key-algorithms options)
                  (ssh-config-split-list value))))))
      ((string= keyword "casignaturealgorithms")
       (ssh-config-set-once
        seen options :ca-signature-algorithms
        (lambda (options)
          (let ((value (check)))
            (ssh-config-validate-algorithm-names
             line value +ssh-config-config-key-names+
             :wildcards t :plain-only t
             :on-bad (lambda (name)
                       (bad "Bad key types '~A'." value name)))
            (setf (ssh-config-options-ca-signature-algorithms options)
                  (ssh-config-split-list value))))))
      ((member keyword '("pubkeyacceptedalgorithms" "pubkeyacceptedkeytypes")
               :test #'string=)
       (ssh-config-set-once
        seen options :pubkey-accepted-algorithms
        (lambda (options)
          (let ((value (check)))
            (ssh-config-validate-algorithm-names
             line value +ssh-config-config-key-names+
             :wildcards t
             :on-bad (lambda (name)
                       (bad "Bad key types '~A'." value name)))
            (setf (ssh-config-options-pubkey-accepted-algorithms options)
                  (ssh-config-split-list value))))))
      ((string= keyword "compression")
       (ssh-config-set-once
        seen options :compression
        (lambda (options)
          (setf (ssh-config-options-compression options)
                (ssh-config-multistate
                 line (ssh-config-arg line)
                 '(("yes" . t) ("no" . nil)))))))
      ((string= keyword "rekeylimit")
       (let ((arguments (ssh-config-line-args line)))
         (when (> (length arguments) 2)
           (error (ssh-config-line-error
                   line "keyword rekeylimit extra arguments at end of line")))
         (let* ((size-argument (first arguments))
                (bytes
                  (cond
                    ((zerop (length size-argument))
                     (error (ssh-config-line-error line "Missing argument.")))
                    ((string= size-argument "default") 0)
                    (t
                     (or (ssh-parse-scaled size-argument)
                         (error (ssh-config-line-error
                                 line "Bad number '~A': Invalid argument"
                                 size-argument)))))))
           (when (and (/= bytes 0) (< bytes 16))
             (error (ssh-config-line-error line "RekeyLimit too small")))
           (ssh-config-set-once
            seen options :rekey-limit
            (lambda (options)
              (setf (ssh-config-options-rekey-limit options) bytes)))
           (when (second arguments)
             (let ((interval-argument (second arguments)))
               (unless (string= interval-argument "none")
                 (let ((seconds (ssh-config-seconds line interval-argument)))
                   (ssh-config-set-once
                    seen options :rekey-interval
                    (lambda (options)
                      (setf (ssh-config-options-rekey-interval options)
                            seconds))))))))))))))

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
           (error (ssh-config-line-error line "Bad IPQoS value: ~A" value)))
         number)))))

(defun ssh-config-forward-field (text start)
  "One field of a forwarding specification starting at START.

Fields end at an unescaped ':' or the end of TEXT; a backslash quotes the
next character, and a field starting with '[' runs to the matching ']'.
A field that contains '/' is a Unix socket path.  The result is
\(ARG ISPATH NEXT) or NIL when the field is malformed, mirroring
parse_fwd_field."
  (let ((length (length text)))
    (when (>= start length)
      (return-from ssh-config-forward-field nil))
    (when (char= (char text start) #\[)
      (let* ((close (position #\] text :start (1+ start)))
             (end (and close (1+ close))))
        (unless (and close
                     (or (= end length) (char= (char text end) #\:)))
          (return-from ssh-config-forward-field nil))
        (let ((argument (subseq text (1+ start) close)))
          (return-from ssh-config-forward-field
            (list argument (and (find #\/ argument) t)
                  (if (= end length) length (1+ end)))))))
    (let ((argument (make-string-output-stream))
          (path nil)
          (index start))
      (loop while (< index length)
            for character = (char text index)
            do (cond
                 ((char= character #\\)
                  (incf index)
                  (when (>= index length)
                    (return-from ssh-config-forward-field nil))
                  (write-char (char text index) argument)
                  (incf index))
                 ((char= character #\/)
                  (setf path t)
                  (write-char character argument)
                  (incf index))
                 ((char= character #\:)
                  (return-from ssh-config-forward-field
                    (list (get-output-stream-string argument) path
                          (1+ index))))
                 (t
                  (write-char character argument)
                  (incf index))))
      (list (get-output-stream-string argument) path length))))

(defun ssh-config-forward-fields (text)
  "TEXT as a list of (ARG . ISPATH), or NIL when parse_forward would fail."
  (let ((fields '())
        (start 0)
        (length (length text)))
    (loop while (and (< start length) (< (length fields) 4))
          do (let ((field (ssh-config-forward-field text start)))
               (unless field
                 (return-from ssh-config-forward-fields nil))
               (push (cons (first field) (second field)) fields)
               (setf start (third field))))
    (when (< start length)
      (return-from ssh-config-forward-fields nil))
    (nreverse fields)))

(defun ssh-config-forward-port (text)
  "TEXT as a2port reads it: 0..65535, a TCP service name, or -1."
  (or (ssh-a2port text) -1))

(defun ssh-config-forwarding-valid-p (spec dynamicfwd remotefwd)
  "Whether SPEC is a forwarding specification parse_forward would accept."
  (let ((fields (ssh-config-forward-fields spec)))
    (unless fields
      (return-from ssh-config-forwarding-valid-p nil))
    (let* ((count (length fields))
           (path (lambda (index)
                   (cdr (nth index fields))))
           (arg (lambda (index)
                  (car (nth index fields))))
           (listen-path nil) (listen-port :unset) (listen-host nil)
           (connect-path nil) (connect-port :unset) (connect-host nil)
           (ok t))
      (cond
        ((= count 1)
         (if (funcall path 0)
             (setf listen-path (funcall arg 0) listen-port :streamlocal)
             (setf listen-host nil
                   listen-port (ssh-config-forward-port (funcall arg 0))))
         ;; A one-word RemoteForward is readconf's dynamic form: the server
         ;; picks the listening port and the client speaks SOCKS to it, which
         ;; parse_forward records as the "socks" target on port 0.
         (setf connect-host "socks"
               connect-port (if remotefwd 0 :unset)))
        ((= count 2)
         (cond
           ((and (funcall path 0) (funcall path 1))
            (setf listen-path (funcall arg 0) listen-port :streamlocal
                  connect-path (funcall arg 1) connect-port :streamlocal))
           ((funcall path 1)
            (setf listen-host nil
                  listen-port (ssh-config-forward-port (funcall arg 0))
                  connect-path (funcall arg 1) connect-port :streamlocal))
           (t
            (setf listen-host (funcall arg 0)
                  listen-port (ssh-config-forward-port (funcall arg 1))
                  connect-host "socks"))))
        ((= count 3)
         (cond
           ((funcall path 0)
            (setf listen-path (funcall arg 0) listen-port :streamlocal
                  connect-host (funcall arg 1)
                  connect-port (ssh-config-forward-port (funcall arg 2))))
           ((funcall path 2)
            (setf listen-host (funcall arg 0)
                  listen-port (ssh-config-forward-port (funcall arg 1))
                  connect-path (funcall arg 2) connect-port :streamlocal))
           (t
            (setf listen-host nil
                  listen-port (ssh-config-forward-port (funcall arg 0))
                  connect-host (funcall arg 1)
                  connect-port (ssh-config-forward-port (funcall arg 2))))))
        ((= count 4)
         (setf listen-host (funcall arg 0)
               listen-port (ssh-config-forward-port (funcall arg 1))
               connect-host (funcall arg 2)
               connect-port (ssh-config-forward-port (funcall arg 3))))
        (t (setf ok nil)))
      (when ok
        (if dynamicfwd
            (unless (member count '(1 2)) (setf ok nil))
            (progn
              (unless (member count '(3 4))
                (unless (or connect-path listen-path)
                  (setf ok nil)))
              (when (and (or (eq connect-port :unset)
                             (and (integerp connect-port)
                                  (not (plusp connect-port))))
                         (null connect-path)
                         (not (equal connect-host "socks")))
                (setf ok nil)))))
      (when ok
        (when (or (and (or (eq listen-port :unset)
                           (and (integerp listen-port)
                                (minusp listen-port)))
                       (null listen-path))
                  (and (not remotefwd)
                       (eql listen-port 0)))
          (setf ok nil)))
      (when ok
        (flet ((too-long (value limit)
                 (and value (>= (length value) limit))))
          (when (or (too-long connect-host 1025)
                    (too-long connect-path 108)
                    (too-long listen-host 1025)
                    (too-long listen-path 108))
            (setf ok nil))))
      ok)))

(defun ssh-config-apply-session (line options seen &key (active t))
  (let ((keyword (ssh-config-line-keyword line)))
    (when (string= keyword "forwardagent")
      ;; readconf validates a socket-path argument on every line, before the
      ;; first-value test; yes/no/true/false are the flag forms and skip it.
      (let ((argument (ssh-config-arg line)))
        (when (and (plusp (length argument))
                   (not (member argument '("yes" "true" "no" "false")
                                :test #'string-equal)))
          (ssh-config-validate-agent-path line argument))))
    (cond
      ((string= keyword "ipqos")
       (ssh-config-set-once
        seen options :ip-qos
        (lambda (options)
          (let ((arguments (ssh-config-line-args line)))
            (when (> (length arguments) 2)
              (error (ssh-config-line-error
                      line "keyword ipqos extra arguments at end of line")))
            (let ((interactive (ssh-config-ip-qos-value
                                line (first arguments))))
              (setf (ssh-config-options-ip-qos-interactive options)
                    interactive
                    (ssh-config-options-ip-qos-bulk options)
                    (if (second arguments)
                        (ssh-config-ip-qos-value line (second arguments))
                        interactive)))))))
      ((string= keyword "sendenv")
       (dolist (argument (ssh-config-line-args line))
         (when (or (zerop (length argument)) (find #\= argument))
           (error (ssh-config-line-error line "Invalid environment name."))))
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
                (error (ssh-config-line-error line "Invalid SetEnv."))))
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
       (let* ((arguments (ssh-config-line-args line))
              (first-argument (first arguments))
              (second-argument (second arguments)))
         ;; readconf validates each specification as it parses the line, so
         ;; a bad forward is reported with the line number even for a Host
         ;; block that does not match.
         (when (or (null first-argument) (zerop (length first-argument)))
           (error (ssh-config-line-error line "Missing argument.")))
         (cond
           ((string= keyword "dynamicforward")
            (let ((expanded (ssh-forward-expand-value first-argument line)))
              (unless (and expanded
                           (ssh-config-forwarding-valid-p expanded t nil))
                (error (ssh-config-line-error
                        line "Bad forwarding specification.")))
              (setf arguments (list expanded))))
           ((string= keyword "localforward")
            (when (or (null second-argument)
                      (zerop (length second-argument)))
              (error (ssh-config-line-error line "Missing target argument.")))
            (let ((expanded (ssh-forward-expand-value
                             (format nil "~A:~A" first-argument second-argument)
                             line)))
              (unless (and expanded
                           (ssh-config-forwarding-valid-p expanded nil nil))
                (error (ssh-config-line-error
                        line "Bad forwarding specification.")))
              (setf arguments
                    (list (or (ssh-forward-expand-value first-argument line)
                              first-argument)
                          (or (ssh-forward-expand-value second-argument line)
                              second-argument)))))
           (t
            ;; A RemoteForward with a single word is readconf's dynamic
            ;; form; the server chooses the listening port.
            (if (or (null second-argument)
                    (zerop (length second-argument)))
                (let ((expanded (ssh-forward-expand-value first-argument line)))
                  (unless (and expanded
                               (ssh-config-forwarding-valid-p expanded t t))
                    (error (ssh-config-line-error
                            line "Bad forwarding specification.")))
                  (setf arguments (list expanded)))
                (let ((expanded (ssh-forward-expand-value
                                 (format nil "~A:~A" first-argument
                                         second-argument)
                                 line)))
                  (unless (and expanded
                               (ssh-config-forwarding-valid-p expanded nil t))
                    (error (ssh-config-line-error
                            line "Bad forwarding specification.")))
                  (setf arguments
                        (list (or (ssh-forward-expand-value first-argument line)
                                  first-argument)
                              (or (ssh-forward-expand-value second-argument line)
                                  second-argument)))))))
         (let ((value (format nil "~{~A~^ ~}" arguments)))
           ;; ssh keeps forward lines in one array per direction, in the order
           ;; readconf saw them.  The source is recorded too: -G prints the
           ;; command line's forwards before the configuration file's, and an
           ;; -o line sits at its own position among the dedicated flags.
           (push (list* keyword
                        (if (ssh-config-line-command-line line) :option :file)
                        arguments)
                 (ssh-config-options-extra options))
           (cond
             ((string= keyword "localforward")
              (push value (ssh-config-options-local-forwards options)))
             ((string= keyword "remoteforward")
              (push value (ssh-config-options-remote-forwards options)))
             (t
              (push value (ssh-config-options-dynamic-forwards options)))))))
      ((string= keyword "tag")
       (ssh-config-set-once
        seen options :tag
        (lambda (options)
          (setf (ssh-config-options-tag options)
                (ssh-config-string-arg line)))))
      ((string= keyword "channeltimeout")
       ;; ssh keeps the first active ChannelTimeout line as a whole, but parses
       ;; every argument on every active line, so a typo in a later line is
       ;; fatal just as it is in ssh.  "none" must stand alone.
       (let ((arguments (ssh-config-line-args line)))
         (if (some (lambda (argument) (string-equal argument "none"))
                   arguments)
             (if (and (= 1 (length arguments))
                      (string-equal (first arguments) "none"))
                 (ssh-config-set-once
                  seen options :channel-timeouts
                  (lambda (options)
                    (setf (ssh-config-options-channel-timeouts options)
                          :none)))
                 (error (ssh-config-line-error
                         line
                         "keyword channeltimeout \"none\" argument must appear alone.")))
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
       ;; It walks the arguments and treats a second one as "invalid
       ;; arguments", while the first one's own value decides the message.
       (let ((arguments (ssh-config-line-args line))
             (value 0)
             (value-seen nil))
         (dolist (argument arguments)
           (when value-seen
             (error (ssh-config-line-error line "invalid arguments")))
           (setf value
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
                            line "unsupported argument \"~A\"" argument)))))
           (setf value-seen t))
         (unless value-seen
           (error (ssh-config-line-error line "missing argument")))
         (ssh-config-set-once
          seen options :obscure-keystroke-timing
          (lambda (options)
            (setf (ssh-config-options-obscure-keystroke-timing options)
                  value)))))
      (t
       (ssh-config-set-once
        seen options
        (intern (string-upcase
                 (ssh-config-canonical-client-keyword keyword))
                :keyword)
        (lambda (options)
          (ssh-config-apply-session-value line options keyword
                                          :active active)))))))

(defun ssh-config-hpdelim (argument)
  "Split ARGUMENT as misc.c's hpdelim does.

Returns the host part and the remaining port text.  The host part is NIL
when hpdelim would reject the argument outright (an unterminated bracket or
a slash), which readconf reports as \"missing host\"; the port text is NIL
when no ':' delimiter was present."
  (cond
    ((zerop (length argument))
     (values argument nil))
    ((char= (char argument 0) #\[)
     (let ((close (position #\] argument)))
       (if (null close)
           (values nil nil)
           (let ((after (subseq argument (1+ close)))
                 (host (subseq argument 0 (1+ close))))
             (cond
               ((zerop (length after)) (values host nil))
               ((char= (char after 0) #\:) (values host (subseq after 1)))
               (t (values nil nil)))))))
    (t
     (let ((colon (position #\: argument))
           (slash (position #\/ argument)))
       (cond
         ((and slash (or (null colon) (< slash colon)))
          (values nil nil))
         (colon
          (values (subseq argument 0 colon) (subseq argument (1+ colon))))
         (t (values argument nil)))))))

(defun ssh-config-clean-hostname (host)
  "HOST with an IPv6 bracket pair removed, as cleanhostname does."
  (if (and (>= (length host) 2)
           (char= (char host 0) #\[)
           (char= (char host (1- (length host))) #\]))
      (subseq host 1 (1- (length host)))
      host))

(defun ssh-config-remote-open-entry (line argument)
  "One PermitRemoteOpen ARGUMENT as (RAW HOST . PORT), either part :ANY.

The wording and fatality mirror readconf's oPermitRemoteOpen, which reports
unparseable hosts and ports through fatal() and so never prints a file
summary afterwards.  RAW is kept because readconf stores the argument as
written and -G reprints it unchanged."
  (multiple-value-bind (host port)
      (ssh-config-hpdelim argument)
    (unless host
      (error (%ssh-config-line-error
              line "missing host in permitremoteopen" :fatal t)))
    (let ((host (ssh-config-clean-hostname host)))
      (cond
        ((null port)
         (error (%ssh-config-line-error
                 line "bad port number in permitremoteopen" :fatal t)))
        ((string= port "*")
         (list argument host :any))
        (t
         (let ((number (ssh-a2port port)))
           (unless (and number (plusp number))
             (error (%ssh-config-line-error
                     line "bad port number in permitremoteopen" :fatal t)))
           (list argument host number)))))))


(defun ssh-config-escape-char-value (value)
  "VALUE as an escape character, or :NONE.

readconf accepts one character, \"none\", or a caret followed by a character
whose code is 64..127, which it masks to a control code.  That range is what
makes \"^?\" invalid here, as it is in OpenSSH."
  (cond
    ((string-equal value "none") :none)
    ((= 1 (length value)) (char value 0))
    ((and (= 2 (length value))
          (char= (char value 0) #\^)
          (<= 64 (char-code (char value 1)) 127))
     (logand (char-code (char value 1)) 31))
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

(defun ssh-config-url-decode (text)
  "TEXT decoded as misc.c's urldecode, or NIL when it holds a bad escape."
  (let ((out (make-string-output-stream))
        (length (length text))
        (index 0))
    (loop while (< index length)
          for character = (char text index)
          do (cond
               ((char= character #\+)
                (write-char #\Space out)
                (incf index))
               ((char= character #\%)
                (if (and (< (+ index 2) length)
                         (digit-char-p (char text (1+ index)) 16)
                         (digit-char-p (char text (+ index 2)) 16))
                    (let ((value (parse-integer text :start (1+ index)
                                                :end (+ index 3)
                                                :radix 16)))
                      (when (zerop value)
                        (return-from ssh-config-url-decode nil))
                      (write-char (code-char value) out)
                      (incf index 3))
                    (return-from ssh-config-url-decode nil)))
               (t
                (write-char character out)
                (incf index))))
    (get-output-stream-string out)))

(defun ssh-config-valid-uri-domain-p (text)
  "Whether TEXT passes misc.c's valid_domain(name, 0)."
  (and (plusp (length text))
       (let ((first (char-downcase (char text 0))))
         (or (alpha-char-p first)
             (digit-char-p first)
             (char= first #\_)))
       (let ((last nil))
         (loop for character across text
               for lower = (char-downcase character)
               always (progn
                        (when (and last (char= last #\.) (char= lower #\.))
                          (return nil))
                        (unless (or (char= lower #\.)
                                    (char= lower #\-)
                                    (alphanumericp lower)
                                    (char= lower #\_))
                          (return nil))
                        (setf last lower))))))

(defun ssh-config-hpdelim2 (text)
  "TEXT split as misc.c's hpdelim2.

Returns (values HOST TAIL DELIMITER); DELIMITER is NIL at the end, #\\: or
#\\/.  Returns NIL when a bracket is unterminated."
  (if (and (plusp (length text)) (char= (char text 0) #\[))
      (let ((close (position #\] text)))
        (unless close
          (return-from ssh-config-hpdelim2 nil))
        (let ((host (subseq text 0 (1+ close)))
              (after (subseq text (1+ close))))
          (cond
            ((zerop (length after))
             (values host nil nil))
            ((member (char after 0) '(#\: #\/))
             (values host (subseq after 1) (char after 0)))
            (t nil))))
      (let ((colon (position #\: text))
            (slash (position #\/ text)))
        (cond
          ((null colon)
           (if slash
               (values (subseq text 0 slash) (subseq text (1+ slash)) #\/)
               (values text nil nil)))
          ((and slash (< slash colon))
           (values (subseq text 0 slash) (subseq text (1+ slash)) #\/))
          (t
           (values (subseq text 0 colon) (subseq text (1+ colon)) #\:))))))

(defun ssh-config-uri-destination (text)
  "TEXT as parse_ssh_uri: (values KIND USER HOST PORT).

KIND is :URI on success, :NOT-URI when TEXT does not start with ssh://, and
NIL when the URI is malformed.  The scheme is case-sensitive, the host must
be a valid domain, and a path after the port is rejected."
  (unless (and (>= (length text) 6)
               (string= text "ssh://" :end1 6 :end2 6))
    (return-from ssh-config-uri-destination
      (values :not-uri nil nil nil)))
  (let ((rest (subseq text 6))
        (user nil))
    ;; Optional userinfo, up to the first @.
    (let ((at (position #\@ rest)))
      (when at
        (let ((userinfo (subseq rest 0 at)))
          (setf rest (subseq rest (1+ at)))
          (let ((semicolon (position #\; userinfo)))
            (when semicolon
              (setf userinfo (subseq userinfo 0 semicolon))))
          (when (zerop (length userinfo))
            (return-from ssh-config-uri-destination (values nil nil nil nil)))
          (setf user (ssh-config-url-decode userinfo))
          (unless user
            (return-from ssh-config-uri-destination (values nil nil nil nil))))))
    (when (zerop (length rest))
      (return-from ssh-config-uri-destination (values nil nil nil nil)))
    (multiple-value-bind (hostpart tail delimiter)
        (ssh-config-hpdelim2 rest)
      (unless (and hostpart (plusp (length hostpart)))
        (return-from ssh-config-uri-destination (values nil nil nil nil)))
      (let ((host (ssh-config-clean-hostname hostpart))
            (port -1))
        ;; valid_domain() judges the name as written, then strips one
        ;; trailing dot, so "host." is accepted but "host.." is not.
        (unless (ssh-config-valid-uri-domain-p host)
          (return-from ssh-config-uri-destination (values nil nil nil nil)))
        (when (and (plusp (length host))
                   (char= (char host (1- (length host))) #\.))
          (setf host (subseq host 0 (1- (length host)))))
        (when tail
          (cond
            ((eq delimiter #\/)
             ;; A bare path is not allowed.
             (return-from ssh-config-uri-destination (values nil nil nil nil)))
            ((plusp (length tail))
             (let ((slash (position #\/ tail)))
               (when slash
                 (return-from ssh-config-uri-destination
                   (values nil nil nil nil)))
               (let ((number (ssh-a2port tail)))
                 (unless (and number (plusp number))
                   (return-from ssh-config-uri-destination
                     (values nil nil nil nil)))
                 (setf port number))))))
        (values :uri user host port)))))

(defun ssh-config-user-host-port (text)
  "TEXT as misc.c's parse_user_host_port: (values OK USER HOST PORT)."
  (let ((rest text)
        (user nil))
    (let ((at (position #\@ rest :from-end t)))
      (when at
        (let ((candidate (subseq rest 0 at)))
          (when (zerop (length candidate))
            (return-from ssh-config-user-host-port (values nil nil nil nil)))
          (setf user candidate
                rest (subseq rest (1+ at))))))
    (multiple-value-bind (hostpart tail delimiter)
        (ssh-config-hpdelim2 rest)
      (unless (and hostpart (plusp (length hostpart)))
        (return-from ssh-config-user-host-port (values nil nil nil nil)))
      (when (eq delimiter #\/)
        ;; hpdelim refuses a slash.
        (return-from ssh-config-user-host-port (values nil nil nil nil)))
      (let ((host (ssh-config-clean-hostname hostpart))
            (port -1))
        (when (and tail (plusp (length tail)))
          (let ((number (ssh-a2port tail)))
            (unless (and number (plusp number))
              (return-from ssh-config-user-host-port (values nil nil nil nil)))
            (setf port number)))
        (values t user host port)))))

(defparameter +ssh-config-jump-hostname-refusals+ "'`\"$\\;&<>|(){},"
  "Characters readconf's ssh_valid_hostname refuses, besides whitespace.")

(defparameter +ssh-config-jump-user-refusals+ "'`\";&<>|(){}$\\"
  "Characters readconf's ssh_valid_ruser refuses.")

(defun ssh-config-jump-hostname-p (host)
  "Whether HOST passes ssh_valid_hostname."
  (and (plusp (length host))
       (char/= (char host 0) #\-)
       (loop for character across host
             never (or (find character +ssh-config-jump-hostname-refusals+)
                       (ssh-config-whitespace-p character)
                       (< (char-code character) 32)))))

(defun ssh-config-jump-user-p (user)
  "Whether USER passes ssh_valid_ruser."
  (and (plusp (length user))
       (char/= (char user 0) #\-)
       (loop for index from 0 below (length user)
             for character = (char user index)
             never (or (< (char-code character) 32)
                       (find character +ssh-config-jump-user-refusals+)
                       (and (ssh-config-whitespace-p character)
                            (< (1+ index) (length user))
                            (char= (char user (1+ index)) #\-))))))

(defun ssh-config-jump-dump-hop (user host port)
  "One parsed ProxyJump hop as readconf's dump prints it."
  (let ((bracket (or (find #\: host)
                     (and (plusp (length host))
                          (every (lambda (character)
                                   (find character "1234567890."))
                                 host)))))
    (format nil "~@[~A@~]~A~A~A~A"
            user
            (if bracket "[" "")
            host
            (if bracket "]" "")
            (if (and (integerp port) (plusp port))
                (format nil ":~D" port)
                ""))))

(defun ssh-config-parse-proxy-jump (value strict)
  "VALUE as readconf's parse_jump with STRICT, as -G would print it.

Returns (values DUMP-SPELLING REASON).  DUMP-SPELLING is NIL when a hop is
invalid, and REASON is then the parse_jump diagnostic strict validation
would print.  The literal none returns :NONE.  Earlier hops keep their
original spelling, matching how readconf stores jump_extra; only the last
hop is parsed and reprinted.  readconf walks the list right to left, which
decides both which hop is stored and which failure is reported first."
  (when (string-equal value "none")
    (return-from ssh-config-parse-proxy-jump (values :none nil)))
  (let* ((hash (position #\# value))
         (orig (string-right-trim '(#\Space #\Tab #\Return #\Newline)
                                  (if hash (subseq value 0 hash) value))))
    (when (zerop (length orig))
      (return-from ssh-config-parse-proxy-jump (values nil nil)))
    (let* ((last-comma (position #\, orig :from-end t))
           (prefix (and last-comma (subseq orig 0 last-comma)))
           (hops (loop with start = 0
                       for comma = (position #\, orig :start start)
                       collect (subseq orig start comma)
                       while comma
                       do (setf start (1+ comma)))))
      (when (some #'zerop (mapcar #'length hops))
        (return-from ssh-config-parse-proxy-jump (values nil nil)))
      (let ((stored nil))
        (dolist (hop (reverse hops))
          (let ((parsed
                  (multiple-value-bind (kind uri-user uri-host uri-port)
                      (ssh-config-uri-destination hop)
                    (if (eq kind :not-uri)
                        (multiple-value-list
                         (ssh-config-user-host-port hop))
                        (list kind uri-user uri-host uri-port)))))
            (destructuring-bind (ok user host port) parsed
              (when (or (null ok) (null host))
                (return-from ssh-config-parse-proxy-jump (values nil nil)))
              (when strict
                (unless (ssh-config-jump-hostname-p host)
                  (return-from ssh-config-parse-proxy-jump
                    (values nil
                            (format nil "parse_jump: invalid hostname \"~A\""
                                    host))))
                (when (and user (not (ssh-config-jump-user-p user)))
                  (return-from ssh-config-parse-proxy-jump
                    (values nil
                            (format nil "parse_jump: invalid username \"~A\""
                                    user)))))
              ;; The rightmost hop is jump_host; the others are only
              ;; syntax-checked, as readconf's first-pass does.
              (unless stored
                (setf stored (list user host (or port -1)))))))
        (let ((user (first stored))
              (host (second stored))
              (port (third stored)))
          (values
           (if prefix
               (format nil "~A,~A" prefix
                       (ssh-config-jump-dump-hop user host port))
               (ssh-config-jump-dump-hop user host port))
           nil))))))

(defun ssh-config-apply-session-value (line options keyword
                                       &key (active t))
  (let ((value (ssh-config-arg line)))
    (flet ((boolean () (ssh-config-boolean line value))
           (integer (&key minimum maximum)
             (ssh-config-integer line value :minimum minimum :maximum maximum)))
      (cond
        ((string= keyword "proxyjump")
         (let* ((raw (or (ssh-config-line-raw line) value))
                (text (string-left-trim '(#\Space #\Tab #\= #\Return) raw)))
           (multiple-value-bind (parsed reason)
               (ssh-config-parse-proxy-jump
                text (ssh-config-line-command-line line))
             (when reason
               (ssh-config-report-diagnostic line reason))
             (unless parsed
               (error (ssh-config-line-error
                       line "Invalid ProxyJump \"~A\"" text)))
           ;; readconf's parse_jump keeps the first jump or command; the
           ;; literal "none" may still be stored when a ProxyCommand came
           ;; first, because fill_default_options clears it later.
           (cond
             ((and (eq parsed :none)
                   active
                   (null (ssh-config-options-proxy-jump options)))
              (setf (ssh-config-options-proxy-jump options) :none))
             ((and active
                   (null (ssh-config-options-proxy-jump options))
                   (null (ssh-config-options-proxy-command options)))
              (setf (ssh-config-options-proxy-jump options) parsed
                    (ssh-config-options-proxy-command options) "none"))))))
        ((string= keyword "proxycommand")
         ;; parse_command stores the remainder verbatim, and only the first
         ;; ProxyCommand or ProxyJump wins (the latter stores "none").
         (unless (ssh-config-options-proxy-command options)
           (let ((raw (ssh-config-line-raw line)))
             (setf (ssh-config-options-proxy-command options)
                   (let ((text (if (and raw (plusp (length raw))) raw value)))
                     (string-left-trim '(#\Space #\Tab #\= #\Return)
                                       text))))))
        ((string= keyword "bindaddress")
         (setf (ssh-config-options-bind-address options)
               (ssh-config-string-arg line)))
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
            (error (ssh-config-line-error line "missing argument.")))))
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
        ((string= keyword "bindinterface")
         (setf (ssh-config-options-bind-interface options)
               (ssh-config-string-arg line)))
        ((string= keyword "kbdinteractivedevices")
         (setf (ssh-config-options-kbd-interactive-devices options)
               (ssh-config-string-arg line)))
        ((member keyword '("pkcs11provider" "smartcarddevice")
                 :test #'string=)
         ;; CLEAR_ON_NONE drops the provider after parsing, so -G prints
         ;; nothing for "none"; :NONE records that decision.
         (let ((value (ssh-config-string-arg line)))
           (setf (ssh-config-options-pkcs11-provider options)
                 (if (string-equal value "none") :none value))))
        ((string= keyword "securitykeyprovider")
         (let ((value (ssh-config-string-arg line)))
           (setf (ssh-config-options-security-key-provider options)
                 (if (string-equal value "none") :none value))))
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
         (setf (ssh-config-options-tunnel options)
               (ssh-config-multistate
                line value
                '(("ethernet" . :ethernet)
                  ("point-to-point" . :point-to-point)
                  ("yes" . :yes) ("true" . :yes)
                  ("no" . :no) ("false" . :no)))))
        ((string= keyword "tunneldevice")
         (when (zerop (length value))
           (error (ssh-config-line-error line "Missing argument.")))
         (setf (ssh-config-options-tunnel-device options)
               (ssh-config-tunnel-device line value)))
        ((string= keyword "xauthlocation")
         (setf (ssh-config-options-xauth-location options)
               (ssh-config-string-arg line)))
        ((string= keyword "gatewayports")
         (setf (ssh-config-options-gateway-ports options) (boolean)))
        ((string= keyword "exitonforwardfailure")
         (setf (ssh-config-options-exit-on-forward-failure options)
               (boolean)))
        ((string= keyword "permitremoteopen")
         ;; The first active line wins, but every argument of every line is
         ;; parsed, and any/none may only stand alone.  NIL is how "not set"
         ;; is spelled, so no seen table is needed here.
         (let* ((arguments (ssh-config-line-args line))
                (alone (and (= 1 (length arguments))
                            (member (first arguments) '("any" "none")
                                    :test #'string-equal)))
                (value
                  (cond
                    (alone
                     (if (string-equal (first arguments) "any") :any :none))
                    (t
                     (dolist (argument arguments)
                       (when (member argument '("any" "none")
                                     :test #'string-equal)
                         (error (ssh-config-line-error
                                 line
                                 "keyword permitremoteopen \"~A\" argument must appear alone."
                                 argument))))
                     (mapcar (lambda (argument)
                               (ssh-config-remote-open-entry line argument))
                             arguments)))))
           (unless (ssh-config-options-permit-remote-open options)
             (setf (ssh-config-options-permit-remote-open options) value))))
        ((string= keyword "clearallforwardings")
         (setf (ssh-config-options-clear-all-forwardings options)
               (boolean)))
        ((member keyword '("tcpkeepalive" "keepalive") :test #'string=)
         (setf (ssh-config-options-tcp-keep-alive options) (boolean)))
        ((string= keyword "refuseconnection")
         ;; readconf validates the argument on every line, but only an
         ;; active block makes it fatal, and that fatal() has no summary.
         (let ((value (ssh-config-string-arg line)))
           (when active
             (error (%ssh-config-line-error
                     line (format nil "RefuseConnection: ~A" value)
                     :fatal t)))))
        ((string= keyword "requiredrsasize")
         (setf (ssh-config-options-required-rsa-size options)
               (integer)))
        ((string= keyword "streamlocalbindmask")
         (when (zerop (length value))
           (error (ssh-config-line-error
                   line "Missing StreamLocalBindMask argument.")))
         ;; readconf uses strtol(arg, &end, 8): leading octal digits count
         ;; and any trailing junk is ignored, so "5m" is 05 and "50%" is 050.
         (let* ((end (or (position-if-not
                          (lambda (character)
                            (digit-char-p character 8))
                          value)
                         (length value)))
                (digits (subseq value 0 end))
                (mask (and (plusp (length digits))
                           (ignore-errors
                             (parse-integer digits :radix 8)))))
           (unless (and mask (<= 0 mask #o777))
             (error (ssh-config-line-error line "Bad mask.")))
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
                   (let ((text (if (and raw (plusp (length raw))) raw value)))
                     (if (string-equal (string-trim '(#\Space #\Tab) text)
                                       "none")
                         :none
                         text))))))
        ((string= keyword "remotecommand")
         ;; The first active line wins; :NONE is how the literal "none" is
         ;; kept so a later line cannot replace it before readconf clears it.
         (unless (ssh-config-options-remote-command options)
           (setf (ssh-config-options-remote-command options)
                 (let ((raw (ssh-config-line-raw line)))
                   (let ((text (if (and raw (plusp (length raw))) raw value)))
                     (if (string-equal (string-trim '(#\Space #\Tab) text)
                                       "none")
                         :none
                         text))))))
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
             (error (ssh-config-line-error
                     line "unsupported log level '~A'" value)))
           (setf (ssh-config-options-log-level options) level)))
        ((string= keyword "logverbose")
         (dolist (argument (ssh-config-line-args line))
           (when (zerop (length argument))
             (error (ssh-config-line-error
                     line "keyword logverbose empty argument"))))
         (unless (ssh-config-options-log-verbose options)
           (setf (ssh-config-options-log-verbose options)
                 (ssh-config-line-args line))))
        ((string= keyword "escapechar")
         (let ((value (ssh-config-escape-char-value
                       (ssh-config-string-arg line))))
           (unless value
             (error (ssh-config-line-error line "Bad escape character.")))
           (setf (ssh-config-options-escape-char options) value)))
        ((string= keyword "enableescapecommandline")
         (setf (ssh-config-options-enable-escape-commandline options)
               (boolean)))
        ((string= keyword "sessiontype")
         (setf (ssh-config-options-session-type options)
               (ssh-config-multistate
                line value
                '(("none" . "none") ("subsystem" . "subsystem")
                  ("default" . "default")))))
        ((string= keyword "stdinnull")
         (setf (ssh-config-options-stdin-null options) (boolean)))
        ((string= keyword "forkafterauthentication")
         (setf (ssh-config-options-fork-after-authentication options)
               (boolean)))
        ((string= keyword "controlmaster")
         (setf (ssh-config-options-control-master options)
               (ssh-config-multistate
                line value
                '(("yes" . :yes) ("true" . :yes)
                  ("no" . :no) ("false" . :no)
                  ("ask" . :ask) ("auto" . :auto)
                  ("autoask" . :autoask)))))
        ((string= keyword "controlpath")
         (let ((value (ssh-config-string-arg line)))
           (setf (ssh-config-options-control-path options)
                 (if (string-equal value "none") :none value))))
        ((string= keyword "controlpersist")
         (setf (ssh-config-options-control-persist options)
               (cond
                 ((zerop (length value))
                  (error (ssh-config-line-error
                          line "Missing ControlPersist argument.")))
                 ((string= value "no") :no)
                 ((string= value "false") :no)
                 ((string= value "yes") :yes)
                 ((string= value "true") :yes)
                 (t
                  (let ((seconds
                          (handler-case (ssh-config-seconds line value)
                            (ssh-config-error () nil))))
                       (unless (and seconds (not (eq seconds :none)))
                         (error (ssh-config-line-error
                                 line "Bad ControlPersist argument.")))
                       seconds)))))
        ((string= keyword "requesttty")
         (setf (ssh-config-options-request-tty options)
               (ssh-config-multistate
                line value
                '(("yes" . "yes") ("true" . "yes")
                  ("no" . "no") ("false" . "no")
                  ("force" . "force") ("auto" . "auto")))))
        ((string= keyword "preferredauthentications")
         (setf (ssh-config-options-preferred-authentications options)
               (ssh-config-split-list
                (ssh-config-string-arg line))))
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
               (integer)))))))

(defun ssh-config-known-client-keyword-p (keyword)
  "Whether KEYWORD is one ssh's client configuration parser accepts."
  (member keyword +ssh-config-client-keywords+ :test #'string=))

(defun ssh-config-note-legacy-option (line)
  "Report LINE when readconf would call its option deprecated or unsupported.

Neither notice depends on the surrounding Host block matching, so this runs
with the keyword check rather than while applying the directive.  Deprecated
options are reported at debug level and unsupported ones through the warning
reporter, matching readconf's log() and error().  PROTOCOL is absent from
both tables because readconf ignores it silently."
  (let* ((keyword (ssh-config-line-keyword line))
         (where (if (ssh-config-line-path line)
                    (namestring (ssh-config-line-path line))
                    "command-line"))
         (number (or (ssh-config-line-number line) 0)))
    (cond
      ((member keyword +ssh-config-unsupported-keywords+ :test #'string=)
       (if (ssh-config-line-path line)
           (ssh-warn "~A line ~D: Unsupported option \"~A\""
                     where number keyword)
           ;; A command-line option is applied before log_init, so its
           ;; notice reaches stderr even under -q or -E.
           (ssh-warn-always "~A line ~D: Unsupported option \"~A\""
                            where number keyword)))
      ((member keyword +ssh-config-deprecated-keywords+ :test #'string=)
       ;; ssh applies a -o option while it is still parsing its own
       ;; arguments, before log_init, so the debug-level notice for a
       ;; command-line option is never shown even with -v.  Only a
       ;; configuration file's deprecation is visible.
       (when (ssh-config-line-path line)
         (ssh-log "~A line ~D: Deprecated option \"~A\""
                  where number keyword))))))

(defun ssh-config-check-client-keyword (line options)
  "Refuse LINE's keyword when it is not an ssh_config keyword at all.

A name in +SSH-CONFIG-CLIENT-KEYWORDS+ is always accepted, even when this
client has nothing to do with it: an ssh_config written for OpenSSH must keep
loading.  A name outside the table is a typo or belongs to another program,
and OpenSSH refuses it with \"Bad configuration option\" unless IgnoreUnknown
already named it.  The check happens whether or not the surrounding Host
block is active, as ssh's parse_token does, and that is also where the
deprecated and unsupported notices belong."
  (let ((keyword (ssh-config-line-keyword line)))
    (unless (ssh-config-known-client-keyword-p keyword)
      (let ((ignored (ssh-config-options-ignored-unknown options)))
        (unless (and ignored
                     (ssh-config-pattern-list-match-p
                      (list ignored) keyword :case-insensitive t))
          (error (%ssh-config-line-error
                  line (format nil "Bad configuration option: ~A" keyword)
                  :bad-option t)))))
    (ssh-config-note-legacy-option line)))

(defparameter +ssh-config-fixed-argument-keywords+
  '(;; address and identity settings
    ("hostname" . 1) ("port" . 1) ("user" . 1) ("hostkeyalias" . 1)
    ("canonicalizehostname" . 1) ("canonicalizemaxdots" . 1)
    ("canonicalizefallbacklocal" . 1)
    ("identityfile" . 1) ("identityfile2" . 1) ("certificatefile" . 1)
    ("identityagent" . 1) ("identitiesonly" . 1) ("addkeystoagent" . 2)
    ("hostbasedauthentication" . 1) ("hostbasedacceptedalgorithms" . 1)
    ("hostbasedkeytypes" . 1) ("enablesshkeysign" . 1)
    ;; known-hosts and policy settings
    ("hashknownhosts" . 1) ("updatehostkeys" . 1) ("fingerprinthash" . 1)
    ("visualhostkey" . 1) ("checkhostip" . 1) ("verifyhostkeydns" . 1)
    ("nohostauthenticationforlocalhost" . 1) ("stricthostkeychecking" . 1)
    ("connecttimeout" . 1) ("connectionattempts" . 1) ("addressfamily" . 1)
    ("batchmode" . 1) ("ignoreunknown" . 1) ("warnweakcrypto" . 1)
    ;; algorithms
    ("ciphers" . 1) ("macs" . 1) ("kexalgorithms" . 1)
    ("hostkeyalgorithms" . 1) ("pubkeyacceptedalgorithms" . 1)
    ("pubkeyacceptedkeytypes" . 1) ("casignaturealgorithms" . 1)
    ("compression" . 1) ("rekeylimit" . 2)
    ;; session settings
    ("bindaddress" . 1) ("serveraliveinterval" . 1)
    ("serveralivecountmax" . 1) ("forwardagent" . 1) ("forwardx11" . 1)
    ("forwardx11trusted" . 1) ("forwardx11timeout" . 1)
    ("bindinterface" . 1) ("kbdinteractivedevices" . 1)
    ("pkcs11provider" . 1) ("smartcarddevice" . 1)
    ("securitykeyprovider" . 1) ("proxyusefdpass" . 1)
    ("syslogfacility" . 1) ("tunnel" . 1) ("tunneldevice" . 1)
    ("xauthlocation" . 1) ("gatewayports" . 1) ("ipqos" . 2)
    ("exitonforwardfailure" . 1) ("clearallforwardings" . 1)
    ("tcpkeepalive" . 1) ("keepalive" . 1) ("refuseconnection" . 1)
    ("requiredrsasize" . 1) ("permitlocalcommand" . 1) ("escapechar" . 1)
    ("enableescapecommandline" . 1) ("loglevel" . 1) ("sessiontype" . 1)
    ("stdinnull" . 1) ("forkafterauthentication" . 1)
    ("controlmaster" . 1) ("controlpath" . 1) ("controlpersist" . 1)
    ("streamlocalbindmask" . 1) ("streamlocalbindunlink" . 1)
    ("requesttty" . 1) ("tag" . 1) ("localforward" . 2)
    ("remoteforward" . 2) ("dynamicforward" . 1)
    ("preferredauthentications" . 1) ("pubkeyauthentication" . 1)
    ("passwordauthentication" . 1) ("kbdinteractiveauthentication" . 1)
    ("dsaauthentication" . 1) ("challengeresponseauthentication" . 1)
    ("skeyauthentication" . 1) ("tisauthentication" . 1)
    ("numberofpasswordprompts" . 1))
  "Keywords process_config_line reads a fixed number of arguments from.

Every other directive either loops over its arguments or takes the rest of
the line verbatim.  readconf checks for leftover words once the directive
has been applied, so a rejected value reports its own diagnostic instead.")

(defun ssh-config-check-extra-arguments (line)
  "Reject the words left after a fixed-argument directive, as readconf does.

process_config_line ends with \"if (ac > 0) error(... extra arguments at end
of line)\", so User bob extra is a bad option while SendEnv a b is not.  The
check runs after the directive so a bad first value keeps its own message."
  (let ((arity (cdr (assoc (ssh-config-line-keyword line)
                           +ssh-config-fixed-argument-keywords+
                           :test #'string=))))
    (when (and arity
               (> (length (ssh-config-line-args line)) arity))
      (error (ssh-config-line-error
              line "keyword ~A extra arguments at end of line"
              (ssh-config-line-keyword line))))))

(defun ssh-config-apply-directive (line options seen context
                                   &key (active t))
  "Apply one non-block directive when the current block is selected.

OPTIONS and SEEN may be throwaway copies when the surrounding block is not
selected, so validation still runs; ACTIVE says whether this line's own
block applies, which matters only for the few directives readconf runs its
side effects on unconditionally.

readconf checks for leftover words only after the directive has run, so a
bad value reports its own diagnostic first."
  (prog1 (ssh-config-apply-directive-body line options seen context active)
    (ssh-config-check-extra-arguments line)))

(defun ssh-config-apply-directive-body (line options seen context active)
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((string= keyword "include")
       ;; The file contents are already spliced in at load time; the line
       ;; itself is here so readconf's empty-argument diagnostic survives.
       (dolist (argument (ssh-config-line-args line))
         (when (zerop (length argument))
           (error (ssh-config-line-error
                   line "keyword include empty argument")))))
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
                         "hostbasedkeytypes"
                         "enablesshkeysign")
               :test #'string=)
       (ssh-config-apply-identity line options seen context :active active))
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
                         "forwardx11timeout" "bindinterface"
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
       (ssh-config-apply-session line options seen :active active))
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
                             line "'all' cannot be combined with other Match attributes")))
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
                          line "missing argument for Match '~A'" keyword)))
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
         (given options)
         (options (or options (%make-ssh-config-options)))
         (seen (or seen (make-hash-table :test #'equal)))
         (context (%make-ssh-config-context
                   :original-host (or original-host host)
                   :user (or user (ssh-default-user))
                   :port (or port 22)
                   :tag tag
                   :local-addresses local-addresses))
         (pending nil)
         (pending-path nil)
         (pending-count 0)
         ;; readconf validates every directive even inside a Host block that
         ;; did not match; only the assignment is skipped.  Sending those
         ;; lines through a scratch record gives the same diagnostics without
         ;; letting the values take effect.
         (scratch-options (%make-ssh-config-options))
         (scratch-seen (make-hash-table :test #'equal))
         (stopped nil))
    ;; ssh applies -l and -p while parsing its arguments, before it reads
    ;; any configuration, so those values win over User and Port lines and
    ;; over -o.  Seeding the record and the seen table gives that order.
    (when (null given)
      (when user
        (setf (ssh-config-options-user options) user)
        (setf (gethash :user seen) t))
      (when port
        (setf (ssh-config-options-port options) port)
        (setf (gethash :port seen) t)))
    (labels
        ((say (condition)
           (when *ssh-config-error-function*
             (funcall *ssh-config-error-function*
                      (ssh-config-readconf-message condition))))
         (flush-pending ()
           ;; readconf marks a file bad only after reading all of it, then
           ;; fatals with the count.  Nothing after that file is parsed.
           (when pending
             (when *ssh-config-error-function*
               (funcall *ssh-config-error-function*
                        (format nil
                                "~A: terminating, ~D bad configuration options"
                                pending-path pending-count)))
             (setf stopped t)
             (when on-error (funcall on-error (first pending)))
             (setf pending nil pending-path nil pending-count 0)))
         (report (condition)
           (unless stopped
             (setf stopped t)
             (when on-error (funcall on-error condition))))
         (line-error (condition)
           (let ((path (ssh-config-error-path condition)))
             (cond
               ;; ssh applies -o before log_init and exits on the first bad
               ;; one; it has no surrounding file to summarise.
               ((null path)
                (say condition)
                (setf stopped t)
                (when on-error (funcall on-error condition)))
               ;; A readconf fatal() prints its one line and leaves at once.
               ((ssh-config-error-fatal condition)
                (say condition)
                (setf stopped t)
                (when on-error (funcall on-error condition)))
               ;; match_cfg_line names the bad criterion and its caller then
               ;; prints "Bad Match condition"; the file is abandoned.
               ((equal (ssh-config-error-keyword condition) "match")
                (say condition)
                (when *ssh-config-error-function*
                  (funcall *ssh-config-error-function*
                           (format nil "~A line ~D: Bad Match condition"
                                   path (ssh-config-error-line condition))))
                (push condition pending)
                (incf pending-count)
                (setf pending-path path)
                (flush-pending))
               ;; Another file starts only after the previous one was clean.
               ((and pending-path (not (equal path pending-path)))
                (flush-pending))
               (t
                (say condition)
                (unless pending-path (setf pending-path path))
                (setf pending (nconc pending (list condition)))
                (incf pending-count)))))
         (complete ()
           (unless stopped
             (when on-options (funcall on-options options))))
         (advance (index parsing)
           (when stopped (return-from advance nil))
           (loop while (< index (length directives))
                 do (let ((line (aref directives index)))
                      (handler-case
                          (progn
                            ;; readconf rejects a bare keyword before it
                            ;; even looks the name up.
                            (when (null (ssh-config-line-args line))
                              (error (ssh-config-line-error
                                      line "no argument after keyword \"~A\""
                                      (ssh-config-line-keyword line))))
                            ;; argv_split() runs after parse_token() found
                            ;; the keyword, so the keyword's own notices come
                            ;; first and the open quote is then the line's one
                            ;; bad option.  Nothing is applied either way.
                            (when (ssh-config-line-invalid-quotes line)
                              (handler-case
                                  (ssh-config-check-client-keyword line options)
                                (ssh-config-error (condition) (say condition)))
                              ;; readconf reports the open quote before the
                              ;; directive switch, so a Match line rejected
                              ;; here must not gain "Bad Match condition".
                              (error (make-condition
                                      'ssh-config-error
                                      :detail "invalid quotes"
                                      :path (and (ssh-config-line-path line)
                                                 (namestring
                                                  (ssh-config-line-path line)))
                                      :line (ssh-config-line-number line))))
                            (cond
                            ;; readconf's oHost, oInclude and oMatch refuse
                            ;; to run from -o: they are file structure, not
                            ;; settings.
                            ((and (ssh-config-line-command-line line)
                                  (member (ssh-config-line-keyword line)
                                          '("host" "include" "match")
                                          :test #'string=))
                             (error (%ssh-config-line-error
                                     line
                                     (format nil "~A directive not supported as a command-line option"
                                             (string-capitalize
                                              (ssh-config-line-keyword line)))
                                     :bare t)))
                            ((string= (ssh-config-line-keyword line) "host")
                             (multiple-value-bind (matched pattern skipped)
                                 (ssh-config-host-block-matches-p
                                  line options context)
                               ;; readconf names the block it applies and,
                               ;; when a negation is why it does not, the
                               ;; pattern that vetoed it.
                               (let ((where
                                       (if (ssh-config-line-path line)
                                           (namestring
                                            (ssh-config-line-path line))
                                           "command-line")))
                                 (when skipped
                                   (ssh-log
                                    "~A line ~D: Skipping Host block because of negated match for ~A"
                                    where (ssh-config-line-number line)
                                    skipped))
                                 (when matched
                                   (ssh-log "~A line ~D: Applying options for ~A"
                                            where (ssh-config-line-number line)
                                            pattern)))
                               (setf parsing matched)))
                             ((string= (ssh-config-line-keyword line) "match")
                             (return
                               (ssh-config-eval-match
                                line options context exec-matcher final-pass
                                (lambda (matched)
                                  (advance (1+ index) matched))
                                #'line-error)))
                            (t
                             (ssh-config-check-client-keyword line options)
                             (ssh-config-apply-directive
                              line
                              (if parsing options scratch-options)
                              (if parsing seen scratch-seen)
                              context
                              :active parsing))))
                        (ssh-config-error (condition)
                          (line-error condition))
                        (error (condition)
                          (report condition)))
                      (when stopped (return-from advance nil))
                      ;; A rejected line is recorded but parsing goes on, so
                      ;; move past it even when it signaled.
                      (incf index)))
           (when pending (flush-pending))
           (unless stopped (complete))))
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
       (resolver #'burzay:resolve-host-canonical) direct prepare-options
       on-options on-error)
  "Resolve CONFIG for HOST, canonicalize the name, and re-read if needed.

This is ssh.c's sequence: resolve the first pass, apply resolve_canonicalize(),
then, when canonicalization ran or a Match final line asked for it, re-read the
configuration with the canonical name in HOSTNAME and Match canonical/final
active.  ON-OPTIONS receives (OPTIONS CANONICAL-HOST); the caller builds the
client from those.  RESOLVER is (HOST ON-SUCCESS ON-ERROR &KEY FAMILY) and
may report a canonical name as ON-SUCCESS's second argument.  It receives
the AddressFamily the first pass resolved, so a name is canonicalized in
the same family the connection will dial."
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
           ;; ssh.c tidies the resolved options before canonicalisation;
           ;; PREPARE-OPTIONS is where it expands %h in HostName.
           (when prepare-options
             (funcall prepare-options options))
           (let* ((input (or (ssh-config-options-hostname options) host))
                  (direct
                    (cond ((functionp direct) (funcall direct options))
                          ((null direct) (ssh-config-options-direct-p options))
                          (t direct)))
                  (effective
                    (or (ssh-canonical-address-string input)
                        (if (and input (not (burzay:numeric-address-p input)))
                            (string-downcase input)
                            input))))
             (ssh-config-canonicalize-host
              effective options direct
              ;; The name is resolved in the family the connection will
              ;; use, so CanonicalizeHostname cannot follow an address the
              ;; dialer would reject.
              (lambda (name on-success on-error)
                (funcall resolver name on-success on-error
                         :family (ssh-config-options-address-family
                                  options)))
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

;;; ---- AddressFamily ----

(defun ssh-normalize-address-family (value)
  "VALUE as NIL for any, or :INET / :INET6.

The ssh_config reader already stores a keyword, but MAKE-SSH-CLIENT is a
public entry point too, so the spellings a caller might pass are accepted
here as well.  Anything else is a programming error rather than a config
line, so a plain ERROR names the bad value."
  (cond
    ((null value) nil)
    ((eq value :any) nil)
    ((eq value :inet) :inet)
    ((eq value :inet6) :inet6)
    ((stringp value)
     (cond ((string-equal value "any") nil)
           ((string-equal value "inet") :inet)
           ((string-equal value "inet6") :inet6)
           (t (error "invalid AddressFamily ~S" value))))
    (t (error "invalid AddressFamily ~S" value))))

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
