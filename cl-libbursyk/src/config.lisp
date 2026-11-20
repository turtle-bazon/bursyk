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

(defparameter +ssh-config-version+ "cl-pnet-ssh_0.0.1.1")

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
  (user nil)
  (port nil)
  (identity-files nil)
  (certificate-files nil)
  (identity-agent nil)
  (identities-only nil)
  (known-hosts nil)
  (global-known-hosts nil)
  (strict-host-key-checking nil)
  (host-key-algorithms nil)
  (pubkey-accepted-algorithms nil)
  (kex-algorithms nil)
  (ciphers nil)
  (macs nil)
  (compression nil)
  (connect-timeout nil)
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
  (proxy-jump nil)
  (proxy-command nil)
  (rekey-limit nil)
  (forward-agent nil)
  (gateway-ports nil)
  (local-forwards nil)
  (remote-forwards nil)
  (dynamic-forwards nil)
  (request-tty nil)
  (tag nil)
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

Whitespace and an unquoted '=' separate tokens; single or double quotes group
a value and are removed.  A backslash drops only before a quote, a backslash
or whitespace, exactly like OpenSSH's argv splitter."
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
                      (char= character #\=))
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

(defun ssh-config-path-value (line options context)
  "A path argument with %, $ and ~ expanded."
  (let ((value (ssh-config-expand-variables
                (ssh-config-expand-tokens (ssh-config-arg line) options context))))
    (let ((value (ssh-config-expand-home value)))
      (if (ssh-config-absolute-path-p value)
          (pathname value)
          (merge-pathnames value (user-homedir-pathname))))))

(defun ssh-config-include-path (argument)
  "An Include argument as a pathname, relative ones under ~/.ssh."
  (let ((value (ssh-config-expand-home argument)))
    (if (ssh-config-absolute-path-p value)
        (pathname value)
        (merge-pathnames value (merge-pathnames ".ssh/"
                                                (user-homedir-pathname))))))

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

(defun ssh-config-read-directives (path depth)
  "Read PATH into directives, expanding Include lines as they appear."
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
                           (dolist (file (ssh-config-include-files
                                          (ssh-config-include-path argument)))
                             (setf directives
                                   (nconc directives
                                          (ssh-config-read-directives
                                           file (1+ depth))))))
                         (push (%make-ssh-config-line
                                :keyword keyword
                                :args (rest tokens)
                                :raw (ssh-config-line-remainder line)
                                :path path
                                :number number)
                               directives)))))))
    (nreverse directives)))

(defun ssh-config-load (path)
  "Parse the ssh_config file at PATH into an SSH-CONFIG, or NIL if absent."
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
                                 (ash #xFFFFFFFF (- bits 32))))))
           (= (logand (ssh-config-ipv4-integer network) mask)
              (logand (ssh-config-ipv4-integer host) mask))))))

(defun ssh-config-localnetwork-match-p (cidrs local-addresses)
  (let ((cidrs (loop for cidr in (uiop:split-string cidrs :separator ",")
                     collect cidr)))
    (and local-addresses
         (some (lambda (address)
                 (some (lambda (cidr)
                         (ssh-config-ipv4-cidr-match-p cidr address))
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
                (ssh-config-boolean line (ssh-config-arg line)))))))))

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

(defun ssh-config-apply-session (line options seen)
  (let ((keyword (ssh-config-line-keyword line)))
    (cond
      ((string= keyword "sendenv")
       (setf (ssh-config-options-send-env options)
             (append (ssh-config-options-send-env options)
                     (ssh-config-line-args line))))
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
        ((string= keyword "gatewayports")
         (setf (ssh-config-options-gateway-ports options) (boolean)))
        ((string= keyword "requesttty")
         (setf (ssh-config-options-request-tty options) (string-downcase value)))
        ((string= keyword "preferredauthentications")
         (setf (ssh-config-options-preferred-authentications options)
               (ssh-config-split-list value)))
        ((string= keyword "pubkeyauthentication")
         (setf (ssh-config-options-pubkey-authentication options)
               (boolean)))
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
      ((member keyword '("hostname" "port" "user") :test #'string=)
       (ssh-config-apply-address line options seen context))
      ((member keyword '("identityfile" "certificatefile" "identityagent"
                         "identitiesonly")
               :test #'string=)
       (ssh-config-apply-identity line options seen context))
      ((member keyword '("userknownhostsfile" "globalknownhostsfile"
                         "stricthostkeychecking" "connecttimeout"
                         "addressfamily" "batchmode")
               :test #'string=)
       (ssh-config-apply-policy line options seen context))
      ((member keyword '("ciphers" "macs" "kexalgorithms" "hostkeyalgorithms"
                         "pubkeyacceptedalgorithms" "pubkeyacceptedkeytypes"
                         "compression" "rekeylimit")
               :test #'string=)
       (ssh-config-apply-algorithms line options seen))
      ((member keyword '("proxyjump" "proxycommand" "bindaddress" "sendenv"
                         "serveraliveinterval" "serveralivecountmax"
                         "forwardagent" "gatewayports" "requesttty" "tag"
                         "localforward" "remoteforward" "dynamicforward"
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
