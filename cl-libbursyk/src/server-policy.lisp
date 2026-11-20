(in-package #:cl-pnet-ssh)

;;;; Policies both server backends apply.  The key list is the same text
;;;; sshd reads and the env list is the same AcceptEnv scope, so neither
;;;; depends on which transport is in use.

;;; ---- authorized_keys ----

(defun ssh-authorized-key-line-fields (line)
  "Split LINE into whitespace-separated fields, honouring double quotes.

authorized_keys options may carry a quoted value with spaces in it, so a
plain split at whitespace would tear an `environment=\"A=b c\"' option in
half and could mistake part of it for the key type."
  (let ((fields '())
        (start nil)
        (quoted nil)
        (escaped nil))
    (loop for index from 0 below (length line)
          for character = (char line index)
          do (cond
               (escaped (setf escaped nil))
               ;; sshd's sshkey_advance_past_options only treats \" as an
               ;; escape; any other backslash is an ordinary character.
               ((and (char= character #\\)
                     (< (1+ index) (length line))
                     (char= (char line (1+ index)) #\"))
                (setf escaped t)
                (unless start (setf start index)))
               ((char= character #\")
                (setf quoted (not quoted))
                (unless start (setf start index)))
               ((and (member character '(#\Space #\Tab #\Return #\Newline))
                     (not quoted))
                (when start
                  (push (subseq line start index) fields)
                  (setf start nil)))
               (t (unless start (setf start index))))
          finally (when start (push (subseq line start) fields)))
    (nreverse fields)))

(defparameter +ssh-authorized-key-types+
  '("ssh-ed25519" "ssh-rsa"
    "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521")
  "The key types an authorized_keys line may name.")

(defun ssh-authorized-key-line-options-and-rest (line)
  "VALUES OPTIONS REST for one LINE.

sshd reads the options as everything before the first whitespace that is not
inside a double-quoted value, so a value with spaces must be quoted.  REST
is the remainder, starting with the key type."
  (let ((position (length line))
        (quoted nil)
        (escaped nil))
    (loop for index from 0 below (length line)
          for character = (char line index)
          do (cond
               (escaped (setf escaped nil))
               ;; Only \" is an escape, as in sshkey_advance_past_options.
               ((and (char= character #\\)
                     (< (1+ index) (length line))
                     (char= (char line (1+ index)) #\"))
                (setf escaped t))
               ((char= character #\") (setf quoted (not quoted)))
               ((and (not quoted)
                     (member character
                             '(#\Space #\Tab #\Return #\Newline)))
                (setf position index)
                (return))))
    (values (subseq line 0 position)
            (string-left-trim '(#\Space #\Tab #\Return #\Newline)
                              (subseq line position)))))

(defun ssh-authorized-key-line-parts (line)
  "The key blob, options text and parsed options of one authorized_keys LINE.

Returns (VALUES BLOB OPTIONS OPTIONS-STRUCT), or three NILs when the line
holds no recognised key or an option sshd would refuse."
  (let ((trimmed (string-trim '(#\Space #\Tab #\Return #\Newline) line)))
    (when (and (plusp (length trimmed))
               (not (char= (char trimmed 0) #\#)))
      (multiple-value-bind (first rest)
          (ssh-authorized-key-line-options-and-rest trimmed)
        (multiple-value-bind (options fields)
            ;; A line with no options starts with the key type itself.
            (if (member first +ssh-authorized-key-types+ :test #'string=)
                (values "" (ssh-authorized-key-line-fields trimmed))
                (values first (ssh-authorized-key-line-fields rest)))
          (when (and (member (first fields) +ssh-authorized-key-types+
                             :test #'string=)
                     (second fields))
            (let ((blob (handler-case
                            (ssh-base64-octets (second fields))
                          (cl-base64:bad-base64-character () nil))))
              (multiple-value-bind (parsed valid)
                  (ssh-authorized-key-options-parse options)
                (if (and blob valid)
                    (values blob options parsed)
                    (values nil nil nil))))))))))

(defun ssh-authorized-key-line-blob (line)
  "The public key blob on one authorized_keys LINE, or NIL."
  (nth-value 0 (ssh-authorized-key-line-parts line)))

(defun ssh-authorized-key-option-tokens (options)
  "The comma-separated options in OPTIONS, keeping quoted values whole.

Only \\\" is an escape, matching sshd's sshkey_advance_past_options, so a
backslash before anything else is an ordinary character."
  (let ((tokens '())
        (start 0)
        (quoted nil)
        (escaped nil))
    (loop for index from 0 below (length options)
          for character = (char options index)
          do (cond
               (escaped (setf escaped nil))
               ((and (char= character #\\)
                     (< (1+ index) (length options))
                     (char= (char options (1+ index)) #\"))
                (setf escaped t))
               ((char= character #\") (setf quoted (not quoted)))
               ((and (not quoted) (char= character #\,))
                (push (subseq options start index) tokens)
                (setf start (1+ index))))
          finally (push (subseq options start) tokens))
    (nreverse tokens)))

(defun ssh-authorized-key-option-unquote (value)
  "VALUE with a surrounding pair of quotes and its \\\" escapes removed.

Like sshd's opt_dequote, only a backslash before a double quote escapes
anything; every other backslash is kept as it is.  Returns (VALUES TEXT
VALID); an opening quote with no closing one is malformed and sshd refuses
the whole line."
  (cond
    ((and (plusp (length value)) (char= (char value 0) #\"))
     (if (and (>= (length value) 2)
              (char= (char value (1- (length value))) #\"))
         (let ((body (subseq value 1 (1- (length value)))))
           (values
            (with-output-to-string (out)
              (loop for index from 0 below (length body)
                    for character = (char body index)
                    do (if (and (char= character #\\)
                                (< (1+ index) (length body))
                                (char= (char body (1+ index)) #\"))
                           (progn
                             (write-char #\" out)
                             (incf index))
                           (write-char character out))))
            t))
         (values value nil)))
    (t (values value t))))

;;; sshd's sshauthopt_parse reads every option on the key line and refuses
;;; the whole line on anything it cannot honour.  These records carry the
;;; answer to the transport, which enforces it when the client later asks for
;;; a pty or a forwarded connection.

(defstruct (ssh-authorization-options
             (:constructor %make-ssh-authorization-options
                 (&key (permit-pty t)
                       (permit-port-forwarding t)
                       (permit-agent-forwarding t)
                       (permit-x11-forwarding t)
                       (permit-user-rc t)
                       restricted from force-command permit-open permit-listen
                       valid-before (environments '()))))
  "What the authorized_keys line that admitted a key permits.

The defaults are sshd's for a line with no options: every feature is
allowed.  FROM is one sshd address pattern list (\"10.0.0.0/8,!10.1.2.3\"),
FORCE-COMMAND replaces the client's command, PERMIT-OPEN and PERMIT-LISTEN
are (HOST . PORT) pairs with :ANY for a wildcard port, and VALID-BEFORE is a
UNIVERSAL-TIME after which the key stops working."
  (permit-pty t)
  (permit-port-forwarding t)
  (permit-agent-forwarding t)
  (permit-x11-forwarding t)
  (permit-user-rc t)
  (restricted nil)
  (from nil)
  (force-command nil)
  (permit-open nil)
  (permit-listen nil)
  (valid-before nil)
  (environments '()))

(defun ssh-authorization-options-permit-pty-p (options)
  "Whether OPTIONS allow a pty request; NIL options keep sshd's default."
  (or (null options) (ssh-authorization-options-permit-pty options)))

(defun ssh-authorization-options-permit-port-forwarding-p (options)
  "Whether OPTIONS allow forwarding at all; NIL options allow it."
  (or (null options) (ssh-authorization-options-permit-port-forwarding options)))

(defun ssh-authorization-options-permit-address-p (options address)
  "Whether ADDRESS may use the key described by OPTIONS.

The from= option is one sshd address list; when it is present and the
backend did not report an address, the key is refused rather than trusted."
  (or (null options)
      (let ((from (ssh-authorization-options-from options)))
        (or (null from)
            (and address (ssh-address-pattern-match-p address from))))))

(defun ssh-authorization-options-permit-now-p
    (options &optional (now (get-universal-time)))
  "Whether the expiry-time on OPTIONS, if any, still admits the key at NOW."
  (or (null options)
      (let ((valid-before (ssh-authorization-options-valid-before options)))
        (or (null valid-before) (>= valid-before now)))))

(defun ssh-authorization-permit-entry-port-p (entry-port port)
  "Whether an authorized_keys permit entry's PORT allows PORT."
  (or (eq entry-port :any) (eql entry-port port)))

(defun ssh-authorization-options-permit-open-p (options host port)
  "Whether OPTIONS allow a local forward to HOST:PORT.

A permitopen= option restricts the key to the listed destinations; without
one the key inherits the server's own PermitOpen policy."
  (or (null options)
      (let ((permits (ssh-authorization-options-permit-open options)))
        (or (null permits)
            (some (lambda (permit)
                    (and (ssh-authorization-permit-entry-port-p
                          (cdr permit) port)
                         (let ((allowed (car permit)))
                           (or (string= allowed "*")
                               (string= allowed host)))))
                  permits)))))

(defun ssh-authorization-options-permit-listen-p (options host port)
  "Whether OPTIONS allow a remote forward to listen on HOST:PORT.

Unlike permitopen=, sshd matches a permitlisten= host with its wildcard
matcher against the lower-cased request, so \"*\" is useful here."
  (or (null options)
      (let ((permits (ssh-authorization-options-permit-listen options)))
        (or (null permits)
            (some (lambda (permit)
                    (and (ssh-authorization-permit-entry-port-p
                          (cdr permit) port)
                         (let ((allowed (car permit)))
                           (or (string= allowed "*")
                               (ssh-match-pattern
                                allowed (string-downcase (or host "")))))))
                  permits)))))

(defun ssh-authorized-key-option-name-value (token)
  "NAME and VALUE of TOKEN when it is NAME=VALUE."
  (let ((equals (position #\= token)))
    (when equals
      (values (subseq token 0 equals) (subseq token (1+ equals))))))

(defun ssh-authorized-key-option-flag-value (token name allow-negate)
  "VALUES MATCHED VALUE for the flag NAME in TOKEN.

With ALLOW-NEGATE, \"no-NAME\" matches too and yields NIL.  Option names are
case-insensitive, as sshd's opt_flag(3) is."
  (cond
    ((string-equal token name) (values t t))
    ((and allow-negate
          (> (length token) 3)
          (string-equal (subseq token 0 3) "no-")
          (string-equal (subseq token 3) name))
     (values t nil))
    (t (values nil nil))))

(defun ssh-authorization-option-quoted (token name)
  "VALUES TEXT MATCHED VALID for the NAME=VALUE option in TOKEN.

Like sshd's opt_dequote, the value must be quoted; an unquoted value means
the line is refused.  TEXT has the quotes and the \\\" escapes removed."
  (multiple-value-bind (option value)
      (ssh-authorized-key-option-name-value token)
    (if (and option (string-equal option name))
        (if (and (plusp (length value)) (char= (char value 0) #\"))
            (multiple-value-bind (text valid)
                (ssh-authorized-key-option-unquote value)
              (values text t valid))
            (values nil t nil))
        (values nil nil nil))))

(defun ssh-parse-absolute-time (text)
  "The UNIVERSAL-TIME that sshd's expiry-time TEXT names, or NIL.

sshd accepts YYYYMMDD, YYYYMMDDHHMM and YYYYMMDDHHMMSS, with an optional
trailing Z or UTC meaning the value is already in UTC."
  (let* ((length (length text))
         (utc nil))
    (cond
      ((and (> length 1)
            (string-equal (subseq text (1- length)) "Z"))
       (setf utc t length (1- length)))
      ((and (> length 3)
            (string-equal (subseq text (- length 3)) "UTC"))
       (setf utc t length (- length 3))))
    (when (member length '(8 12 14))
      (when (every #'digit-char-p (subseq text 0 length))
        (let ((year (parse-integer text :start 0 :end 4))
              (month (parse-integer text :start 4 :end 6))
              (day (parse-integer text :start 6 :end 8))
              (hour (if (>= length 10)
                        (parse-integer text :start 8 :end 10)
                        0))
              (minute (if (>= length 12)
                          (parse-integer text :start 10 :end 12)
                          0))
              (second (if (>= length 14)
                          (parse-integer text :start 12 :end 14)
                          0)))
          (handler-case
              (let ((time (encode-universal-time
                           second minute hour day month year
                           (if utc 0 nil))))
                ;; Universal time zero is 1900, which sshd treats as absent.
                (and (plusp time) time))
            (error () nil)))))))

(defun ssh-authorized-key-split-permit (text allow-bare-port)
  "VALUES HOST PORT VALID for one permitopen=/permitlisten= value.

The host may be bracketed, the port may be * (returned as :ANY), and
permitlisten= additionally accepts a bare port, which sshd turns into
\"*:PORT\"."
  (let ((host nil)
        (port-text nil))
    (cond
      ((and (plusp (length text)) (char= (char text 0) #\[))
       (let ((close (position #\] text)))
         (when (and close
                    (< (1+ close) (length text))
                    (char= (char text (1+ close)) #\:))
           (setf host (subseq text 1 close)
                 port-text (subseq text (+ close 2))))))
      ((position #\: text)
       (let ((colon (position #\: text)))
         (setf host (subseq text 0 colon)
               port-text (subseq text (1+ colon)))))
      (allow-bare-port
       (setf host "*" port-text text)))
    (when (and port-text (plusp (length port-text)))
      (let ((port (if (string= port-text "*")
                      :any
                      (let ((number (and (every #'digit-char-p port-text)
                                         (parse-integer port-text))))
                        ;; a2port parses 0, but handle_permit refuses <= 0.
                        (and number (<= 1 number 65535) number)))))
        (when port
          (values (or host "") port t))))))

(defun ssh-authorized-key-options-parse (options)
  "Parse one authorized_keys OPTIONS string.

Returns (VALUES OPTIONS-STRUCT VALID).  VALID is NIL when sshd would refuse
the whole line: an unknown or malformed option, a duplicate command= or
from=, or an option this server cannot honour.  Refusing the line is how a
restriction we do not implement stays a restriction."
  (if (or (null options) (zerop (length options)))
      (values (%make-ssh-authorization-options) t)
      (let ((parsed (%make-ssh-authorization-options))
            (valid t)
            (flag-value nil)
            (environments '())
            (permit-open '())
            (permit-listen '()))
        (labels ((fail () (setf valid nil))
                 (flag (token name allow-negate)
                   (multiple-value-bind (matched value)
                       (ssh-authorized-key-option-flag-value
                        token name allow-negate)
                     (when matched
                       (setf flag-value value))
                     matched))
                 (environment-name (assignment)
                   (let ((equals (position #\= assignment)))
                     (and equals (subseq assignment 0 equals))))
                 (add-environment (assignment)
                   (unless (some (lambda (other)
                                   (string=
                                    (environment-name assignment)
                                    (environment-name other)))
                                 environments)
                     (push assignment environments))))
          (dolist (token (ssh-authorized-key-option-tokens options))
            (unless valid (return))
            (cond
              ((zerop (length token)) (fail))
              ((string-equal token "restrict")
               (setf (ssh-authorization-options-restricted parsed) t
                     (ssh-authorization-options-permit-pty parsed) nil
                     (ssh-authorization-options-permit-port-forwarding parsed) nil
                     (ssh-authorization-options-permit-agent-forwarding parsed) nil
                     (ssh-authorization-options-permit-x11-forwarding parsed) nil
                     (ssh-authorization-options-permit-user-rc parsed) nil))
              ((string-equal token "cert-authority")
               ;; The line marks a certificate authority.  Treating it as a
               ;; plain login key would be a privilege escalation.
               (fail))
              ((flag token "port-forwarding" t)
               (setf (ssh-authorization-options-permit-port-forwarding parsed)
                     flag-value))
              ((flag token "agent-forwarding" t)
               (setf (ssh-authorization-options-permit-agent-forwarding parsed)
                     flag-value))
              ((flag token "x11-forwarding" t)
               (setf (ssh-authorization-options-permit-x11-forwarding parsed)
                     flag-value))
              ((flag token "pty" t)
               (setf (ssh-authorization-options-permit-pty parsed) flag-value))
              ((flag token "user-rc" t)
               ;; ~/.ssh/rc is not run at all.  no-user-rc asks for less and
               ;; is safe; user-rc would silently lose the feature.
               (when flag-value (fail))
               (setf (ssh-authorization-options-permit-user-rc parsed)
                     flag-value))
              ((flag token "touch-required" t)
               (when flag-value (fail)))
              ((flag token "verify-required" t)
               (when flag-value (fail)))
              (t
               (multiple-value-bind (name value)
                   (ssh-authorized-key-option-name-value token)
                 (cond
                   ((null name) (fail))
                   ((string-equal name "command")
                    (multiple-value-bind (text matched value-valid)
                        (ssh-authorization-option-quoted token "command")
                      (if (or (not matched)
                              (not value-valid)
                              (ssh-authorization-options-force-command parsed))
                          (fail)
                          (setf (ssh-authorization-options-force-command parsed)
                                text))))
                   ((string-equal name "from")
                    (multiple-value-bind (text matched value-valid)
                        (ssh-authorization-option-quoted token "from")
                      (if (or (not matched)
                              (not value-valid)
                              (ssh-authorization-options-from parsed))
                          (fail)
                          (setf (ssh-authorization-options-from parsed)
                                text))))
                   ((string-equal name "expiry-time")
                    (multiple-value-bind (text matched value-valid)
                        (ssh-authorization-option-quoted token "expiry-time")
                      (let ((time (and matched value-valid
                                       (ssh-parse-absolute-time text))))
                        (if (null time)
                            (fail)
                            (let ((current
                                    (ssh-authorization-options-valid-before
                                     parsed)))
                              ;; sshd keeps the earliest expiry when the
                              ;; option appears more than once.
                              (when (or (null current) (< time current))
                                (setf (ssh-authorization-options-valid-before
                                       parsed) time)))))))
                   ((string-equal name "environment")
                    (multiple-value-bind (text matched value-valid)
                        (ssh-authorization-option-quoted token "environment")
                      (let ((equals (and matched value-valid
                                         (position #\= text))))
                        (if (and equals
                                 (ssh-server-config-env-name-p
                                  (subseq text 0 equals))
                                 ;; sshd checks before appending, so
                                 ;; SSH_AUTHOPT_ENV_MAX + 1 entries survive.
                                 (<= (length environments) 1024))
                            (add-environment text)
                            (fail)))))
                   ((string-equal name "permitopen")
                    (multiple-value-bind (text matched value-valid)
                        (ssh-authorization-option-quoted token "permitopen")
                      (multiple-value-bind (host port valid-p)
                          (and matched value-valid
                               (ssh-authorized-key-split-permit text nil))
                        (if (and valid-p (<= (length permit-open) 4096))
                            (push (cons host port) permit-open)
                            (fail)))))
                   ((string-equal name "permitlisten")
                    (multiple-value-bind (text matched value-valid)
                        (ssh-authorization-option-quoted token "permitlisten")
                      (multiple-value-bind (host port valid-p)
                          (and matched value-valid
                               (ssh-authorized-key-split-permit text t))
                        (if (and valid-p (<= (length permit-listen) 4096))
                            (push (cons host port) permit-listen)
                            (fail)))))
                   ((or (string-equal name "principals")
                        (string-equal name "tunnel"))
                    ;; Certificate principals and TUN devices are features
                    ;; this server does not implement; accepting the line
                    ;; would quietly drop a permission or a restriction.
                    (fail))
                   (t (fail))))))))
        (if valid
            (progn
              (setf (ssh-authorization-options-environments parsed)
                    (nreverse environments)
                    (ssh-authorization-options-permit-open parsed)
                    (nreverse permit-open)
                    (ssh-authorization-options-permit-listen parsed)
                    (nreverse permit-listen))
              (values parsed t))
            (values nil nil)))))

(defun ssh-authorized-key-line-environments (line)
  "The environment assignments attached to the key on one LINE."
  (let ((options (nth-value 2 (ssh-authorized-key-line-parts line))))
    (and options (ssh-authorization-options-environments options))))

(defparameter +ssh-server-user-key-algorithms+
  '("ssh-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    "rsa-sha2-512"
    "rsa-sha2-256")
  "Public-key signature algorithms the server accepts for user auth.

This is what EXT_INFO's server-sig-algs names.  SHA-1 ssh-rsa is accepted
for old clients but not advertised, matching modern OpenSSH defaults.")

(defun ssh-server-user-key-algorithm-p (key-blob algorithm)
  "Whether KEY-BLOB may sign as ALGORITHM in a userauth request.

The key type decides the names it may use: an ECDSA key signs under its
curve's name, an RSA key under any RFC 8332 name, and ed25519 under its own.
A blob that does not parse is never acceptable."
  (handler-case
      (multiple-value-bind (type data) (ssh-public-key-parts key-blob)
        (declare (ignore data))
        (cond
          ((string= type "ssh-ed25519")
           (string= algorithm "ssh-ed25519"))
          ((string= type "ssh-rsa")
           (not (null (ssh-rsa-digest-keyword algorithm))))
          ((member type '("ecdsa-sha2-nistp256"
                          "ecdsa-sha2-nistp384"
                          "ecdsa-sha2-nistp521")
                   :test #'string=)
           (string= algorithm type))
          (t nil)))
    (error () nil)))

(defun ssh-authorized-key-file-entries (path)
  "Every well-formed (BLOB OPTIONS) in the file at PATH."
  (if (probe-file path)
      (with-open-file (stream path :direction :input :if-does-not-exist nil
                                   :external-format :utf-8)
        (iter (for line = (read-line stream nil nil))
          (while line)
          (multiple-value-bind (blob options-text options)
              (ssh-authorized-key-line-parts line)
            (declare (ignore options-text))
            (when blob
              (collect (list blob options))))))
      nil))

(defun ssh-authorized-key-file-blobs (path)
  "Every well-formed key blob in the authorized_keys file at PATH."
  (mapcar #'car (ssh-authorized-key-file-entries path)))

(defun ssh-authorized-key-source-entries (source)
  "SOURCE's authorized_keys lines as (BLOB OPTIONS) pairs."
  (cond
    ((listp source)
     (if (every (lambda (item)
                  (typep item '(vector (unsigned-byte 8))))
                source)
         (mapcar (lambda (blob)
                   (list blob (%make-ssh-authorization-options)))
                 source)
         (iter (for line in source)
           (multiple-value-bind (blob options-text options)
               (ssh-authorized-key-line-parts line)
             (declare (ignore options-text))
             (when blob
               (collect (list blob options)))))))
    ((pathnamep source) (ssh-authorized-key-file-entries source))
    ((stringp source)
     (if (probe-file source)
         (ssh-authorized-key-file-entries source)
         (multiple-value-bind (blob options-text options)
             (ssh-authorized-key-line-parts source)
           (declare (ignore options-text))
           (if blob
               (list (list blob options))
               nil))))
    (t nil)))

(defun ssh-authorized-key-blob-match
    (source key-blob &key address (now (get-universal-time)))
  "Whether KEY-BLOB is listed in SOURCE, and the options it carries.

Returns (VALUES MATCHED ENVIRONMENTS OPTIONS).  sshd applies the options of
the key line that authenticated the user, so the first line whose key
matches and whose from=/expiry-time= restrictions admit this connection
supplies them; a key with no options has an empty environment list and
permissive defaults."
  (iter (for entry in (ssh-authorized-key-source-entries source))
    (when (ssh-octets= (car entry) key-blob)
      (let ((options (second entry)))
        (when (and (ssh-authorization-options-permit-now-p options now)
                   (ssh-authorization-options-permit-address-p
                    options address))
          (return-from ssh-authorized-key-blob-match
            (values t
                    (ssh-authorization-options-environments options)
                    options))))))
  (values nil nil nil))

(defun ssh-authorized-key-blob-p (source key-blob)
  "Whether KEY-BLOB is listed in SOURCE, a file, a list, or one line."
  (nth-value 0 (ssh-authorized-key-blob-match source key-blob)))

(defun ssh-server-authorized-key-p (server user key-blob &key address)
  "Whether KEY-BLOB may log in as USER on SERVER.

Returns (VALUES MATCHED ENVIRONMENTS OPTIONS) so the caller can apply the
authorized_keys line's environment= options and enforce the rest of its
policy.  A custom AUTHORIZE function is called with (USER KEY-BLOB ADDRESS)
and may return the same values; ADDRESS is SESSION's peer address, which
from= needs."
  (let ((authorize (ssh-server-authorize server)))
    (cond
      ((functionp authorize) (funcall authorize user key-blob address))
      ((ssh-server-authorized-keys server)
       (ssh-authorized-key-blob-match (ssh-server-authorized-keys server)
                                      key-blob :address address))
      (t (values nil nil nil)))))

;;; ---- Per-session policy ----
;;;
;;; Authentication records the options of the line that admitted the key on
;;; the session.  The channel and forwarding paths consult these helpers so a
;;; no-pty or permitopen= line is enforced by the transport rather than by
;;; every program that embeds it.

(defun ssh-session-remote-ip (session)
  "SESSION's peer IP as text, or NIL when the backend did not report it."
  (let ((address (ssh-session-remote-address session)))
    (and (listp address) (getf address :address))))

(defun ssh-session-permits-pty-p (session)
  "Whether the key that authenticated SESSION may request a pty."
  (ssh-authorization-options-permit-pty-p
   (ssh-session-authorization session)))

(defun ssh-session-permits-direct-tcpip-p (session host port)
  "Whether SESSION may open a local forward to HOST:PORT."
  (let ((options (ssh-session-authorization session)))
    (and (ssh-authorization-options-permit-port-forwarding-p options)
         (ssh-authorization-options-permit-open-p options host port))))

(defun ssh-session-permits-tcpip-forward-p (session host port)
  "Whether SESSION may ask the server to listen on HOST:PORT."
  (let ((options (ssh-session-authorization session)))
    (and (ssh-authorization-options-permit-port-forwarding-p options)
         (ssh-authorization-options-permit-listen-p options host port))))

;;; ---- AcceptEnv ----

(defun ssh-match-pattern (pattern text)
  "Whether TEXT matches PATTERN, with sshd's match_pattern(3) semantics.

Only * and ? are special; a * matches any run of characters, a ? exactly one,
and nothing else is quoted.  This is what AcceptEnv uses, which is narrower
than the bracket classes an ssh_config Host pattern allows."
  (cond
    ((zerop (length pattern)) (zerop (length text)))
    ((char= (char pattern 0) #\*)
     (let ((rest (string-left-trim "*" pattern)))
       (if (zerop (length rest))
           t
           (loop for index from 0 to (length text)
                 thereis (ssh-match-pattern rest (subseq text index))))))
    ((zerop (length text)) nil)
    ((or (char= (char pattern 0) #\?)
         (char= (char pattern 0) (char text 0)))
     (ssh-match-pattern (subseq pattern 1) (subseq text 1)))
    (t nil)))

(defun ssh-match-pattern-list (patterns text)
  "Whether TEXT matches PATTERNS, sshd's match_pattern_list(3) semantics.

PATTERNS may hold commas; a leading ! vetoes a match, and any other match is
enough.  Used for PermitUserEnvironment's allowlist."
  (let ((matched nil))
    (dolist (pattern (loop for pattern in patterns
                           append (uiop:split-string pattern :separator ","))
             matched)
      (let ((negated (and (plusp (length pattern))
                          (char= (char pattern 0) #\!))))
        (when negated (setf pattern (subseq pattern 1)))
        (when (ssh-match-pattern pattern text)
          (if negated
              (return-from ssh-match-pattern-list nil)
              (setf matched t)))))))

(defun ssh-server-permit-user-environment-p (server name)
  "Whether SERVER lets a user set the environment variable NAME.

A pattern list is an allowlist, as sshd's PermitUserEnvironment turns into
permit_user_env_allowlist; NIL and :NO permit nothing."
  (let ((policy (ssh-server-permit-user-environment server)))
    (cond
      ((eq policy :yes) t)
      ((consp policy) (and (ssh-match-pattern-list policy name) t))
      (t nil))))

(defun ssh-server-env-allowed-p (server name value)
  "Whether SERVER's AcceptEnv policy admits NAME=VALUE."
  (let ((policy (ssh-server-accept-env server)))
    (cond
      ((eq policy t) t)
      ((functionp policy) (funcall policy name value))
      ((listp policy)
       (some (lambda (pattern) (ssh-match-pattern pattern name)) policy))
      (t nil))))

;;; ---- AllowUsers / DenyUsers / AllowGroups / DenyGroups ----
;;;
;;; sshd matches these at the moment a user name first appears, before any
;;; authentication method runs.  The list belongs to the server config, but
;;; the matching lives here so the same rules do not have to be rebuilt by
;;; every program that embeds the server.

(defun ssh-address-pattern-match-p (address patterns)
  "Whether ADDRESS matches PATTERNS, sshd's addr_match_list.

PATTERNS is one comma-separated list.  Each element may be negated with a
leading !, may be a CIDR network, or may be an address wildcard.  A negated
match vetoes the whole list, as in sshd; a list of nothing but negations
matches every address they do not veto, which is what makes
\"!10.0.0.0/8\" mean \"anywhere else\"."
  (let ((matched nil)
        (positive nil))
    (dolist (pattern (uiop:split-string patterns :separator ",")
                     (or matched (not positive)))
      (let ((negated (and (plusp (length pattern))
                          (char= (char pattern 0) #\!))))
        (unless negated
          (setf positive t))
        (when negated
          (setf pattern (subseq pattern 1)))
        (when (or (ssh-config-ipv4-cidr-match-p pattern address)
                  (ssh-config-ipv6-cidr-match-p pattern address)
                  (ssh-match-pattern pattern address))
          (if negated
              (return-from ssh-address-pattern-match-p nil)
              (setf matched t)))))))

(defun ssh-user-pattern-match-p (pattern user address)
  "Whether USER at ADDRESS matches one AllowUsers/DenyUsers PATTERN.

A pattern without @ matches the user name; one with @ matches the name and
then the address, which sshd takes from the connection because UseDNS is
off by default."
  (let ((at (position #\@ pattern)))
    (if (null at)
        (ssh-match-pattern pattern user)
        (and (ssh-match-pattern (subseq pattern 0 at) user)
             (ssh-address-pattern-match-p address
                                          (subseq pattern (1+ at)))))))

(defun ssh-group-pattern-match-p (pattern groups)
  "Whether any of GROUPS matches PATTERN, with sshd's globbing."
  (some (lambda (group) (ssh-match-pattern pattern group)) groups))

(defun ssh-server-user-allowed-p (config user address groups)
  "Whether sshd's account lists admit USER at ADDRESS in GROUPS.

sshd's order is DenyUsers, AllowUsers, DenyGroups, AllowGroups: a deny list
wins outright, and an allow list that is present must match."
  (let ((allow-users (ssh-server-config-allow-users config))
        (deny-users (ssh-server-config-deny-users config))
        (allow-groups (ssh-server-config-allow-groups config))
        (deny-groups (ssh-server-config-deny-groups config)))
    (and (not (some (lambda (pattern)
                      (ssh-user-pattern-match-p pattern user address))
                    deny-users))
         (or (null allow-users)
             (some (lambda (pattern)
                     (ssh-user-pattern-match-p pattern user address))
                   allow-users))
         (not (some (lambda (pattern)
                      (ssh-group-pattern-match-p pattern groups))
                    deny-groups))
         (or (null allow-groups)
             (some (lambda (pattern)
                     (ssh-group-pattern-match-p pattern groups))
                   allow-groups)))))

(defun ssh-root-login-allowed-p (mode method &key force-command)
  "Whether a root login may proceed under PermitRootLogin MODE.

METHOD is the authentication method that just succeeded.  MODE NIL keeps
sshd's default, prohibit-password.  FORCED-COMMANDS-ONLY needs a forced
command: pass the authenticating key's command= as FORCE-COMMAND, or NIL
when the key has none."
  (case (or mode :prohibit-password)
    (:yes t)
    (:no nil)
    (:prohibit-password
     (not (null (member method '("publickey" "hostbased" "gssapi-with-mic")
                        :test #'string=))))
    (:forced-commands-only (not (null force-command)))
    (t nil)))
