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
    "hostbasedusesnamefrompacketonly" "authorizedkeysfile2"
    "casignaturealgorithms"))

;;; Keywords whose default or "off" value describes this server exactly.  A
;;; configuration that asks for that value is fine; asking for anything else
;;; would change behaviour this build does not have, so it is refused.
(defparameter +ssh-server-config-accepted-off-keywords+
  '(("allowagentforwarding" . "no")
    ("x11forwarding" . "no")
    ("permittunnel" . "no")
    ("passwordauthentication" . "no")
    ("kbdinteractiveauthentication" . "no")
    ("challengeresponseauthentication" . "no")
    ("skeyauthentication" . "no")
    ("usepam" . "no")
    ("permitemptypasswords" . "no")
    ("hostbasedauthentication" . "no")
    ("gssapiauthentication" . "no")
    ("kerberosauthentication" . "no")
    ("strictmodes" . "no")
    ("ignorerhosts" . "yes")
    ("permittty" . "yes")
    ("permituserrc" . "yes")
    ("compression" . "no")
    ("allowstreamlocalforwarding" . "no")))

;;; Recognised sshd keywords this server does not implement at all.
(defparameter +ssh-server-config-unsupported-keywords+
  '("chrootdirectory"
    "authorizedkeyscommand" "authorizedkeyscommanduser"
    "authorizedprincipalsfile" "authorizedprincipalscommand"
    "authorizedprincipalscommanduser"
    "trustedusercakeys" "revokedkeys" "hostcertificate"
    "authenticationmethods" "maxstartups"
    "persourcemaxstartups" "persourcenetblocksize"
    "channeltimeout"
    "unusedconnectiontimeout" "tcpkeepalive"
    "ciphers" "macs" "kexalgorithms" "hostkeyalgorithms"
    "pubkeyacceptedalgorithms" "pubkeyacceptedkeytypes"
    "hostbasedacceptedalgorithms" "hostbasedacceptedkeytypes"
    "pubkeyauthoptions" "requiredrsasize" "hostkeyagent"
    "permitlisten" "streamlocalbindmask" "streamlocalbindunlink"
    "exposeauthinfo"))

(defstruct (ssh-server-config (:constructor %make-ssh-server-config))
  (path nil)
  (directives '())
  (ports '())
  (ports-from-command-line nil)
  (listen-addresses '())
  (listen-addresses-from-command-line nil)
  (address-family nil)
  (host-key-files '())
  ;; NIL means the default; sshd's "none" entries are skipped, so a list of
  ;; only "none" disables public-key authentication.
  (authorized-keys-files nil)
  (accept-env '())
  (permit-open '())
  (gateway-ports nil)
  (allow-tcp-forwarding nil)
  (disable-forwarding nil)
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
  ;; PermitUserEnvironment: NIL (unset, means no), :YES, :NO, or a list of
  ;; patterns naming the variables a user may set.
  (permit-user-environment nil)
  ;; SetEnv assignments, "NAME=VALUE", in the order they were read.
  (set-env '())
  (pid-file nil)
  ;; ForceCommand: the command sshd runs instead of whatever the client
  ;; asked for, kept verbatim because sshd passes it to the login shell
  ;; exactly as written.  NIL means no forced command.
  (force-command nil)
  ;; Banner is a file read for every connection, or :none to send nothing.
  (banner nil)
  (version-addendum nil)
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

(defun ssh-server-config-apply-line (config line &key cmdline)
  "Apply LINE to CONFIG, with sshd's validation and first-value-wins rule.

CMDLINE is true for a -o answer, which takes precedence over the file's
Port and ListenAddress the way sshd's own command-line options do."
  (let ((keyword (ssh-config-line-keyword line))
        (arguments (ssh-config-line-args line)))
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
      ((string= keyword "disableforwarding")
       (when (ssh-server-config-flag
              line (ssh-server-config-one-argument line))
         (setf (ssh-server-config-disable-forwarding config) t)))
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
        line "Match blocks are not supported by this server"))
      ((member keyword +ssh-server-config-unsupported-keywords+
               :test #'string=)
       (ssh-server-config-line-error line "~A is not supported by this server"
                                     keyword))
      (t
       (ssh-server-config-line-error line "unknown keyword ~A" keyword)))))

;;; ---- Reading files ----

(defun ssh-server-config-read-file (config path depth)
  "Read PATH into CONFIG, following Include lines as they appear."
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
                     (if (string= keyword "include")
                         (ssh-server-config-include config line depth)
                         (progn
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
    (reverse-slot ssh-server-config-accept-env)
    (reverse-slot ssh-server-config-permit-open)
    (reverse-slot ssh-server-config-allow-users)
    (reverse-slot ssh-server-config-deny-users)
    (reverse-slot ssh-server-config-allow-groups)
    (reverse-slot ssh-server-config-deny-groups)
    (reverse-slot ssh-server-config-subsystems)
    (reverse-slot ssh-server-config-warnings))
  config)

(defun ssh-server-config-load (path &key options)
  "Parse the sshd_config at PATH into an SSH-SERVER-CONFIG.

OPTIONS are directive lines applied before the file, as sshd's -o does.
PATH may be NIL, in which case only OPTIONS are read.  A missing file is an
error: the caller decides whether a default file is optional."
  (let ((config (%make-ssh-server-config :path path)))
    (dolist (option options)
      (ssh-server-config-apply-option-line config option))
    (when path
      (unless (probe-file path)
        (error 'ssh-server-config-error
               :path (namestring path)
               :detail "cannot read the server config"))
      (ssh-server-config-read-file config path 0))
    (ssh-server-config-finalize config)))
