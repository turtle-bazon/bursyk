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
  (hash-known-hosts nil)
  (known-hosts-command nil)
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
  (preferred-authentications nil)
  (pubkey-authentication nil)
  (password-authentication nil)
  (kbd-interactive-authentication nil)
  (number-of-password-prompts nil)
  (send-env nil)
  ;; SetEnv: NAME=VALUE pairs sent to the server on every session, in the
  ;; order the first active SetEnv line named them.
  (set-env nil)
  (proxy-jump nil)
  (proxy-command nil)
  (rekey-limit nil)
  (forward-agent nil)
  (forward-x11 nil)
  (forward-x11-trusted nil)
  (gateway-ports nil)
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
  ;; SessionType and StdinNull: whether to open a session at all, whether the
  ;; command names a subsystem, and whether stdin is /dev/null.
  (session-type nil)
  (stdin-null nil)
  (fork-after-authentication nil)
  (tag nil)
  ;; LogLevel and LogVerbose: how much this client logs, and per-area
  ;; overrides.  LogVerbose is accepted for ssh_config compatibility; this
  ;; client has no per-area log categories to turn up.
  (log-level nil)
  (log-verbose nil)
  (extra nil))

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

(defun ssh-config-expand-tokens (value options context)
  "Expand the OpenSSH % tokens VALUE may contain."
  (let* ((context-host (ssh-config-context-original-host context))
         (host (or (ssh-config-options-hostname options) context-host))
         (user (or (ssh-config-options-user options)
                   (ssh-config-context-user context)))
         (port (or (ssh-config-options-port options)
                   (ssh-config-context-port context)
                   22))
         (local-user (ssh-default-user)))
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
                       (#\d (princ (namestring (user-homedir-pathname)) out)
                            (incf index))
                       (#\i (princ (or (uiop:getenv "UID") "") out) (incf index))
                       (t (write-char character out))))
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

(defun ssh-config-set-once (seen options key thunk)
  "Apply THUNK unless KEY was already set, as OpenSSH keeps first values."
  (unless (gethash key seen)
    (setf (gethash key seen) t)
    (funcall thunk options)))

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

(defun ssh-config-host-block-matches-p (line context)
  (ssh-config-pattern-list-match-p
   (ssh-config-line-args line)
   (ssh-config-context-original-host context)
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
            (unless (member value '("yes" "no" "always" "none")
                            :test #'string=)
              (error (ssh-config-line-error line
                                            "invalid CanonicalizeHostname ~S"
                                            value)))
            (setf (ssh-config-options-canonicalize-hostname options)
                  (intern (string-upcase value) :keyword))))))
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
                (ssh-config-line-args line)))))
      ((string= keyword "hostkeyalias")
       (ssh-config-set-once
        seen options :host-key-alias
        (lambda (options)
          (setf (ssh-config-options-host-key-alias options)
                (ssh-config-expand-variables (ssh-config-arg line)))))))))

(defun ssh-config-apply-identity (line options seen context)
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((string= keyword "identityfile")
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
                (ssh-config-boolean line (ssh-config-arg line)))))))))

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
       (ssh-config-set-once
        seen options :rekey-limit
        (lambda (options)
          (setf (ssh-config-options-rekey-limit options)
                (ssh-config-line-args line))))))))

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
      (t
       (ssh-config-set-once
        seen options (intern (string-upcase keyword) :keyword)
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
         (setf (ssh-config-options-forward-agent options) (boolean)))
        ((string= keyword "forwardx11")
         (setf (ssh-config-options-forward-x11 options) (boolean)))
        ((string= keyword "forwardx11trusted")
         (setf (ssh-config-options-forward-x11-trusted options) (boolean)))
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
        ((string= keyword "requesttty")
         (setf (ssh-config-options-request-tty options) (string-downcase value)))
        ((string= keyword "preferredauthentications")
         (setf (ssh-config-options-preferred-authentications options)
               (ssh-config-split-list value)))
        ((string= keyword "pubkeyauthentication")
         (setf (ssh-config-options-pubkey-authentication options)
               (if (boolean) :yes :no)))
        ((string= keyword "passwordauthentication")
         (setf (ssh-config-options-password-authentication options)
               (boolean)))
        ((string= keyword "kbdinteractiveauthentication")
         (setf (ssh-config-options-kbd-interactive-authentication options)
               (boolean)))
        ((string= keyword "numberofpasswordprompts")
         (setf (ssh-config-options-number-of-password-prompts options)
               (integer :minimum 1)))))))

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
      ((member keyword '("identityfile" "certificatefile" "identityagent"
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
                         "revokedhostkeys"
                         "stricthostkeychecking"
                         "connecttimeout" "connectionattempts"
                         "addressfamily" "batchmode")
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
                         "gatewayports" "ipqos" "exitonforwardfailure"
                         "permitremoteopen" "clearallforwardings"
                         "tcpkeepalive" "keepalive"
                         "refuseconnection" "requiredrsasize"
                         "remotecommand" "localcommand"
                         "permitlocalcommand" "escapechar"
                         "enableescapecommandline"
                         "loglevel" "logverbose"
                         "sessiontype" "stdinnull"
                         "forkafterauthentication"
                         "streamlocalbindmask" "streamlocalbindunlink"
                         "requesttty" "tag"
                         "localforward" "remoteforward" "dynamicforward"
                         "setenv"
                         "preferredauthentications" "pubkeyauthentication"
                         "passwordauthentication"
                         "kbdinteractiveauthentication"
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

(defun ssh-config-eval-match (line options context exec-matcher on-result on-error)
  "Evaluate a Match line, possibly continuing from EXEC-MATCHER's callback."
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
                             on-options on-error)
  "Turn CONFIG into SSH-CONFIG-OPTIONS for HOST.

HOST is the name the user typed; ORIGINAL-HOST defaults to it.  USER and
PORT are the values already decided before config, so a HostName or User
line can still override them.  OPTIONS are delivered to ON-OPTIONS, which
may run before this function returns unless a Match exec had to wait.
EXEC-MATCHER is (COMMAND ON-RESULT ON-ERROR) and must call ON-RESULT with a
boolean; without it a Match exec is an error rather than a blocking POPEN.

Returns CONFIG."
  (let* ((directives (coerce (or (ssh-config-directives config) '()) 'vector))
         (options (%make-ssh-config-options))
         (seen (make-hash-table :test #'equal))
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
                                      line context))
                               (incf index))
                              ((string= (ssh-config-line-keyword line) "match")
                               (return
                                 (ssh-config-eval-match
                                  line options context exec-matcher
                                  (lambda (matched)
                                    (advance (1+ index) matched))
                                  #'report)))
                              (t
                               (when parsing
                                 (ssh-config-apply-directive
                                  line options seen context))
                               (incf index)))))
                 (complete))
             (error (condition) (report condition)))))
      (advance 0 t))
    config))

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
