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
                       restricted cert-authority cert-principals cert-from
                       from force-command permit-open permit-listen
                       valid-before (environments '()))))
  "What the authorized_keys line that admitted a key permits.

The defaults are sshd's for a line with no options: every feature is
allowed.  FROM is one sshd address pattern list (\"10.0.0.0/8,!10.1.2.3\"),
FORCE-COMMAND replaces the client's command, PERMIT-OPEN and PERMIT-LISTEN
are (HOST . PORT) pairs with :ANY for a wildcard port, and VALID-BEFORE is a
UNIVERSAL-TIME after which the key stops working.

CERT-AUTHORITY marks the line's key as a CA rather than a login key,
CERT-PRINCIPALS is its principals= list, and CERT-FROM is the source-address
critical option read from a certificate."
  (permit-pty t)
  (permit-port-forwarding t)
  (permit-agent-forwarding t)
  (permit-x11-forwarding t)
  (permit-user-rc t)
  (restricted nil)
  (cert-authority nil)
  (cert-principals nil)
  (cert-from nil)
  (from nil)
  (force-command nil)
  (permit-open nil)
  (permit-listen nil)
  (valid-before nil)
  (environments '()))

(defun ssh-certificate-authorization-options-empty ()
  "An authorization record whose every permission is off.

Certificates grant features through their extensions, so a certificate that
carries no extension permits nothing; sshd starts from sshauthopt_new(), not
the permissive defaults of an authorized_keys line."
  (%make-ssh-authorization-options
   :permit-pty nil
   :permit-port-forwarding nil
   :permit-agent-forwarding nil
   :permit-x11-forwarding nil
   :permit-user-rc nil))

(defun ssh-authorization-options-permit-pty-p (options)
  "Whether OPTIONS allow a pty request; NIL options keep sshd's default."
  (or (null options) (ssh-authorization-options-permit-pty options)))

(defun ssh-authorization-options-permit-port-forwarding-p (options)
  "Whether OPTIONS allow forwarding at all; NIL options allow it."
  (or (null options) (ssh-authorization-options-permit-port-forwarding options)))

(defun ssh-authorization-options-permit-address-p (options address)
  "Whether ADDRESS may use the key described by OPTIONS.

The from= option is one sshd address list; when it is present and the
backend did not report an address, the key is refused rather than trusted.
A certificate's source-address critical option is a separate list and must
also admit the peer."
  (or (null options)
      (let ((from (ssh-authorization-options-from options))
            (cert-from (ssh-authorization-options-cert-from options)))
        (and (or (null from)
                 (and address (ssh-address-pattern-match-p address from)))
             (or (null cert-from)
                 (and address
                      (ssh-address-pattern-match-p address cert-from)))))))

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
               ;; The line marks a certificate authority.  The key itself
               ;; cannot log in; only certificates it signed can.
               (setf (ssh-authorization-options-cert-authority parsed) t))
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
                   ((string-equal name "principals")
                    (multiple-value-bind (text matched value-valid)
                        (ssh-authorization-option-quoted token "principals")
                      (if (or (not matched)
                              (not value-valid)
                              (ssh-authorization-options-cert-principals
                               parsed))
                          (fail)
                          (setf (ssh-authorization-options-cert-principals
                                 parsed) text))))
                   ((string-equal name "tunnel")
                    ;; TUN devices are a feature this server does not
                    ;; implement; accepting the line would quietly drop a
                    ;; restriction.
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

;;;; ---- Certificate options ----
;;;
;;; A certificate starts with every permission off and turns features on
;;; through its extension list.  Critical options restrict further and an
;;; unknown critical option makes the certificate unusable, as sshd's
;;; cert_option_list does; unknown extensions are ignored.

(defun ssh-certificate-authorization-options-from-certificate (certificate)
  "VALUES AUTHORIZATION VALID for CERTIFICATE's critical options.

Critical options this build knows are force-command, source-address and
verify-required.  An unknown one invalidates the certificate rather than
being ignored, because it may be the only thing stopping a wider login."
  (let ((options (ssh-certificate-authorization-options-empty))
        (valid t))
    (dolist (entry (ssh-certificate-critical certificate))
      (let ((name (car entry))
            (value (cdr entry)))
        (cond
          ((string= name "force-command")
           (if (ssh-authorization-options-force-command options)
               (setf valid nil)
               (setf (ssh-authorization-options-force-command options)
                     value)))
          ((string= name "source-address")
           (if (ssh-authorization-options-cert-from options)
               (setf valid nil)
               (setf (ssh-authorization-options-cert-from options) value)))
          ((string= name "verify-required")
           ;; User-presence verification needs a security key, which this
           ;; build cannot ask for, so honouring the option is impossible;
           ;; such a certificate is refused rather than weakened.
           (setf valid nil))
          (t (setf valid nil)))))
    (when valid
      (dolist (entry (ssh-certificate-extensions certificate))
        (let ((name (car entry)))
          (cond
            ((string= name "permit-X11-forwarding")
             (setf (ssh-authorization-options-permit-x11-forwarding options) t))
            ((string= name "permit-agent-forwarding")
             (setf (ssh-authorization-options-permit-agent-forwarding options)
                   t))
            ((string= name "permit-port-forwarding")
             (setf (ssh-authorization-options-permit-port-forwarding options)
                   t))
            ((string= name "permit-pty")
             (setf (ssh-authorization-options-permit-pty options) t))
            ((string= name "permit-user-rc")
             (setf (ssh-authorization-options-permit-user-rc options) t))
            ;; no-touch-required and unknown extensions do not change any
            ;; permission this server can grant.
            (t nil)))))
    (values options valid)))

(defun ssh-authorization-options-merge (primary additional)
  "PRIMARY and ADDITIONAL merged as sshd's sshauthopt_merge does.

Permission flags are logical-AND (the certificate must grant a feature and
the key or principals line must not withhold it), while restrictive values
are combined.  Force-command clauses must agree; NIL means the two cannot be
merged.  Certificate authorities and principals are cleared, as sshd does."
  (when (and primary additional)
    (let ((result (ssh-certificate-authorization-options-empty)))
      (setf (ssh-authorization-options-permit-pty result)
            (and (ssh-authorization-options-permit-pty primary)
                 (ssh-authorization-options-permit-pty additional))
            (ssh-authorization-options-permit-port-forwarding result)
            (and (ssh-authorization-options-permit-port-forwarding primary)
                 (ssh-authorization-options-permit-port-forwarding additional))
            (ssh-authorization-options-permit-agent-forwarding result)
            (and (ssh-authorization-options-permit-agent-forwarding primary)
                 (ssh-authorization-options-permit-agent-forwarding additional))
            (ssh-authorization-options-permit-x11-forwarding result)
            (and (ssh-authorization-options-permit-x11-forwarding primary)
                 (ssh-authorization-options-permit-x11-forwarding additional))
            (ssh-authorization-options-permit-user-rc result)
            (and (ssh-authorization-options-permit-user-rc primary)
                 (ssh-authorization-options-permit-user-rc additional))
            (ssh-authorization-options-restricted result)
            (or (ssh-authorization-options-restricted primary)
                (ssh-authorization-options-restricted additional))
            (ssh-authorization-options-from result)
            (or (ssh-authorization-options-from primary)
                (ssh-authorization-options-from additional))
            (ssh-authorization-options-cert-from result)
            (or (ssh-authorization-options-cert-from primary)
                (ssh-authorization-options-cert-from additional))
            (ssh-authorization-options-permit-open result)
            (or (ssh-authorization-options-permit-open primary)
                (ssh-authorization-options-permit-open additional))
            (ssh-authorization-options-permit-listen result)
            (or (ssh-authorization-options-permit-listen primary)
                (ssh-authorization-options-permit-listen additional))
            (ssh-authorization-options-environments result)
            (or (ssh-authorization-options-environments primary)
                (ssh-authorization-options-environments additional)))
      (let ((left (ssh-authorization-options-force-command primary))
            (right (ssh-authorization-options-force-command additional)))
        (cond
          ((and left right (not (string= left right))) (return-from
                                                         ssh-authorization-options-merge
                                                         nil))
          (t (setf (ssh-authorization-options-force-command result)
                   (or left right)))))
      (let ((left (ssh-authorization-options-valid-before primary))
            (right (ssh-authorization-options-valid-before additional)))
        (setf (ssh-authorization-options-valid-before result)
              (cond
                ((null left) right)
                ((null right) left)
                (t (min left right)))))
      result)))

(defun ssh-certificate-principals-match-p (certificate names)
  "Whether any principal in CERTIFICATE is named in the comma-separated NAMES."
  (let ((wanted (uiop:split-string names :separator ",")))
    (some (lambda (principal)
            (member principal wanted :test #'string=))
          (ssh-certificate-principals certificate))))

(defun ssh-principals-line-principal-and-options (line)
  "VALUES PRINCIPAL OPTIONS for one AuthorizedPrincipalsFile LINE.

sshd takes the last whitespace-separated field as the principal and treats
everything before it as authorized_keys-style options; a line with no options
is just a principal.  Comments and blank lines yield NIL."
  (let* ((trimmed (string-trim '(#\Space #\Tab #\Return #\Newline) line))
         (hash (position #\# trimmed))
         (text (if hash (string-right-trim
                          '(#\Space #\Tab #\Return #\Newline)
                          (subseq trimmed 0 hash))
                   trimmed)))
    (when (plusp (length text))
      (let ((last (max (or (position #\Space text :from-end t) -1)
                       (or (position #\Tab text :from-end t) -1))))
        (if (< last 0)
            (values text nil)
            (values (string-left-trim '(#\Space #\Tab) (subseq text (1+ last)))
                    (string-right-trim '(#\Space #\Tab)
                                       (subseq text 0 (1+ last)))))))))

(defun ssh-authorization-principals-file-match (source certificate)
  "Values OPTIONS FOUND from an AuthorizedPrincipalsFile SOURCE.

SOURCE is a path, a list of lines, or one line.  The first line whose
principal equals a certificate principal supplies its options; the
principal comparison is exact, as sshd's auth_check_principals_line."
  (let ((entries
          (cond
            ((listp source) source)
            ((pathnamep source)
             (if (probe-file source)
                 (with-open-file (stream source :direction :input
                                                :if-does-not-exist nil
                                                :external-format :utf-8)
                   (loop for line = (read-line stream nil nil)
                         while line collect line))
                 '()))
            ((stringp source)
             (if (probe-file source)
                 (ssh-authorization-principals-file-match (pathname source)
                                                          certificate)
                 (list source)))
            (t '()))))
    (dolist (line entries (values nil nil))
      (multiple-value-bind (principal options-text)
          (ssh-principals-line-principal-and-options line)
        (when (and principal
                   (member principal (ssh-certificate-principals certificate)
                           :test #'string=))
          (multiple-value-bind (options valid)
              (ssh-authorized-key-options-parse (or options-text ""))
            (when (and valid
                       (not (ssh-authorization-options-cert-authority options)))
              (return-from ssh-authorization-principals-file-match
                (values options t)))))))))


(defparameter +ssh-certificate-type-suffix+ "-cert-v01@openssh.com")

(defun ssh-certificate-userauth-signature-algorithm (algorithm)
  "The signature blob's own algorithm for a userauth request ALGORITHM.

A certificate names itself with its certificate key type in the request, but
the signature it carries is made by the certified key and named for the plain
algorithm.  OpenSSH's RSA certificates also use rsa-sha2-256/512 names."
  (if (and (> (length algorithm) (length +ssh-certificate-type-suffix+))
           (string= +ssh-certificate-type-suffix+ algorithm
                    :start2 (- (length algorithm)
                               (length +ssh-certificate-type-suffix+))))
      (subseq algorithm 0 (- (length algorithm)
                             (length +ssh-certificate-type-suffix+)))
      algorithm))

(defun ssh-server-user-key-algorithm-p (key-blob algorithm)
  "Whether KEY-BLOB may sign as ALGORITHM in a userauth request.

A plain key type decides the names it may use: an ECDSA key signs under its
curve's name, an RSA key under any RFC 8332 name, and ed25519 under its own.
A certificate is offered under its certificate type name (and, for RSA, the
rsa-sha2 certificate names), while the signature inside is made by the
certified key.  A blob that does not parse is never acceptable."
  (handler-case
      (if (ssh-certificate-blob-p key-blob)
          (let ((certificate (ssh-certificate-parse key-blob)))
            (and certificate
                 (let ((plain (ssh-certificate-plain-key-type certificate)))
                   (cond
                     ((string= plain "ssh-rsa")
                      (member algorithm
                              '("ssh-rsa-cert-v01@openssh.com"
                                "rsa-sha2-256-cert-v01@openssh.com"
                                "rsa-sha2-512-cert-v01@openssh.com")
                              :test #'string=))
                     ((string= plain "ssh-ed25519")
                      (string= algorithm
                               "ssh-ed25519-cert-v01@openssh.com"))
                     ((member plain '("ecdsa-sha2-nistp256"
                                      "ecdsa-sha2-nistp384"
                                      "ecdsa-sha2-nistp521")
                              :test #'string=)
                      (string= algorithm
                               (concatenate 'string plain
                                            +ssh-certificate-type-suffix+)))
                     (t nil)))))
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
              (t nil))))
    (error () nil)))

(defun ssh-certificate-signature-algorithm-allowed-p (certificate allowed)
  "Whether CERTIFICATE's CA signature algorithm is in ALLOWED.

ALLOWED is a list of algorithm names, or NIL for the default.  OpenSSH
checks the certificate's signature type, not the user's signature type."
  (and certificate
       (let ((algorithm (ssh-certificate-signature-algorithm certificate)))
         (and algorithm
              (member algorithm (or allowed
                                    +ssh-server-ca-signature-algorithms+)
                      :test #'string=)))))

(defun ssh-session-user-key-algorithm-p (session key-blob algorithm)
  "Whether SESSION accepts KEY-BLOB signing as ALGORITHM.

This is SSH-SERVER-USER-KEY-ALGORITHM-P plus the connection's
PubkeyAcceptedAlgorithms choice.  Without the directive the server keeps
accepting SHA-1 ssh-rsa for old clients even though it does not advertise it;
naming the directive makes its resolved list the whole answer."
  (and (ssh-server-user-key-algorithm-p key-blob algorithm)
       (let ((configured
               (ssh-session-setting
                session #'ssh-server-config-pubkey-accepted-algorithms)))
         (or (null configured)
             (member algorithm configured :test #'string=)))))

(defun ssh-session-required-rsa-size (session)
  "SESSION's RequiredRSASize, or NIL when the directive is absent."
  (ssh-session-setting session #'ssh-server-config-required-rsa-size))

(defun ssh-session-user-key-length-p (session key-blob)
  "Whether KEY-BLOB is long enough for SESSION's RequiredRSASize."
  (ssh-key-rsa-size-allowed-p key-blob
                              (ssh-session-required-rsa-size session)))

(defun ssh-server-host-key-required-rsa-size (server)
  "The RequiredRSASize SERVER applied to its host keys when it loaded them.

sshd filters host keys at startup from the global setting; a Match block's
RequiredRSASize governs user keys only, so a lower per-connection value must
not bring a skipped host key back."
  (let ((config (ssh-server-sshd-config server)))
    (and config (ssh-server-config-required-rsa-size config))))

(defun ssh-server-presentable-host-keys (server)
  "SERVER's host keys that RequiredRSASize allows it to present.

sshd skips an RSA key that is too short while loading, logging the error and
carrying on with the rest, so one bad file never stops the listener."
  (let ((size (ssh-server-host-key-required-rsa-size server)))
    (remove-if-not (lambda (key)
                     (ssh-key-rsa-size-allowed-p
                      (ssh-public-key-blob-of key) size))
                   (ssh-server-host-keys server))))

(defun ssh-server-check-host-keys (keys required-rsa-size)
  "Signal unless KEYS, when supplied, holds a key REQUIRED-RSA-SIZE allows.

sshd exits when every configured HostKey is rejected, rather than listening
with no key it could present.  A NIL KEYS list is the caller's own choice and
stays an error left to the transport."
  (when (and keys
             (null (remove-if-not
                    (lambda (key)
                      (ssh-key-rsa-size-allowed-p
                       (ssh-public-key-blob-of key) required-rsa-size))
                    keys)))
    (error 'ssh-connection-error
           :detail
           (format nil "no host key is at least ~D bits"
                   (or required-rsa-size
                       +ssh-rsa-minimum-modulus-size+))))
  keys)

(defun ssh-session-host-keys (session)
  "SESSION's host keys that RequiredRSASize allows it to present."
  (ssh-server-presentable-host-keys (ssh-session-server session)))

(defun ssh-session-algorithm-list (session accessor default)
  "SESSION's list from ACCESSOR, or DEFAULT.

Ciphers, MACs, KexAlgorithms and HostKeyAlgorithms are global directives, so
before the account name is known SESSION's effective config is the server's
base config, which is the same value sshd uses to build KEXINIT."
  (or (ssh-session-setting session accessor) default))

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

(defun ssh-certificate-check
    (certificate user &key address (now (get-universal-time))
                          ca-signature-algorithms require-principal)
  "VALUES VALID OPTIONS for a USER certificate at a connection.

VALID means the certificate is a user certificate, is inside its validity
window, carries a CA signature this build accepts, its source-address critical
option admits ADDRESS, and (when REQUIRE-PRINCIPAL is true) it names at least
one principal.  OPTIONS is the permission set the certificate itself grants; a
caller still has to establish that one of the certificate's principals may log
in as USER."
  (let ((unix-now (ssh-unix-time now)))
    (when (and certificate
               (= (ssh-certificate-cert-type certificate) 1)
               (<= (ssh-certificate-valid-after certificate) unix-now)
               (< unix-now (ssh-certificate-valid-before certificate))
               (or (not require-principal)
                   (plusp (length (ssh-certificate-principals certificate))))
               (ssh-certificate-signature-valid-p certificate)
               (ssh-certificate-signature-algorithm-allowed-p
                certificate ca-signature-algorithms))
      (multiple-value-bind (options valid)
          (ssh-certificate-authorization-options-from-certificate certificate)
        (when (and valid
                   (ssh-authorization-options-permit-address-p
                    options address))
          (values t options))))))

(defun ssh-certificate-principal-p (certificate user)
  "Whether USER is an acceptable principal of CERTIFICATE.

An empty principal list means any principal, which is how OpenSSH treats a
certificate used without AuthorizedPrincipalsFile."
  (or (null (ssh-certificate-principals certificate))
      (member user (ssh-certificate-principals certificate)
              :test #'string=)))

(defun ssh-certificate-ca-listed-p (ca source)
  "Whether the CA public key blob CA appears in SOURCE."
  (some (lambda (entry)
          (ssh-octets= (car entry) ca))
        (ssh-authorized-key-source-entries source)))

(defun ssh-certificate-user-authorized-p
    (user key-blob
     &key address (now (get-universal-time))
          ca-keys principals-source ca-signature-algorithms)
  "VALUES MATCHED ENVIRONMENTS OPTIONS for certificate KEY-BLOB as USER.

This is sshd's user_cert_trusted_ca: the CA must be listed in CA-KEYS, and
when a PRINCIPALS-SOURCE is given one of the certificate's principals must
appear on a line there, whose options are merged with the certificate's own.
Without a principals source the certificate principal list must name USER, or
be empty."
  (let ((certificate (ssh-certificate-parse key-blob)))
    (multiple-value-bind (valid cert-options)
        (ssh-certificate-check certificate user :address address :now now
                               :ca-signature-algorithms
                               ca-signature-algorithms
                               :require-principal (null principals-source))
      (when (and valid
                 ca-keys
                 (ssh-certificate-ca-listed-p
                  (ssh-certificate-signature-key certificate) ca-keys))
        (if principals-source
            (multiple-value-bind (principals-options found)
                (ssh-authorization-principals-file-match
                 principals-source certificate)
              (when found
                (let ((merged (ssh-authorization-options-merge
                               principals-options cert-options)))
                  (when merged
                    (values t
                            (ssh-authorization-options-environments merged)
                            merged)))))
            (when (ssh-certificate-principal-p certificate user)
              (values t
                      (ssh-authorization-options-environments cert-options)
                      cert-options)))))))

(defun ssh-certificate-authorized-key-match
    (source certificate user
     &key address (now (get-universal-time))
          ca-signature-algorithms)
  "VALUES MATCHED ENVIRONMENTS OPTIONS when SOURCE authorizes CERTIFICATE.

SOURCE is an authorized_keys file or line list.  A cert-authority line whose
key is the certificate's CA admits it; principals= on the line must name one
of the certificate's principals, and otherwise USER must be one.  The line's
options and the certificate's options are merged."
  (let ((ca (ssh-certificate-signature-key certificate)))
    (iter (for entry in (ssh-authorized-key-source-entries source))
      (let ((options (second entry)))
        (when (and options
                   (ssh-authorization-options-cert-authority options)
                   (ssh-octets= (first entry) ca)
                   (ssh-authorization-options-permit-now-p options now)
                   (ssh-authorization-options-permit-address-p
                    options address))
          (let ((named (ssh-authorization-options-cert-principals options)))
            (when (if named
                      (ssh-certificate-principals-match-p certificate named)
                      (ssh-certificate-principal-p certificate user))
              (multiple-value-bind (valid cert-options)
                  (ssh-certificate-check certificate user
                                         :address address :now now
                                         :ca-signature-algorithms
                                         ca-signature-algorithms)
                (when valid
                  (let ((merged (ssh-authorization-options-merge
                                 options cert-options)))
                    (when merged
                      (return-from ssh-certificate-authorized-key-match
                        (values t
                                (ssh-authorization-options-environments merged)
                                merged)))))))))))
    (values nil nil nil)))

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
        ;; A cert-authority line names a CA and never logs the CA key in
        ;; itself; only certificates it signed may use the line.
        (when (and (not (ssh-authorization-options-cert-authority options))
                   (ssh-authorization-options-permit-now-p options now)
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

(defun ssh-server-revoked-key-p (server session key-blob)
  "Whether KEY-BLOB is revoked by the RevokedKeys in force for SESSION.

A configured file that cannot be read or parsed counts as revoked: sshd
refuses public-key authentication in that case rather than ignoring the
list.  When SESSION is NIL the server's startup config is consulted."
  (let ((files
          (cond
            (session
             (ssh-session-setting session #'ssh-server-config-revoked-keys))
            (t
             (let ((config (ssh-server-sshd-config server)))
               (and config (ssh-server-config-revoked-keys config)))))))
    (if (or (null files) (eq files :none))
        nil
        (handler-case
            (ssh-key-revoked-p key-blob files)
          (error (condition)
            (ssh-log "RevokedKeys check failed: ~A" condition)
            t)))))

(defun ssh-server-authorized-key-p (server user key-blob
                                   &key address session)
  "Whether KEY-BLOB may log in as USER on SERVER.

Returns (VALUES MATCHED ENVIRONMENTS OPTIONS) so the caller can apply the
authorized_keys line's environment= options and enforce the rest of its
policy.  A custom AUTHORIZE function is called with
(USER KEY-BLOB ADDRESS SESSION) and may return the same values; ADDRESS is
SESSION's peer address, which from= needs, and SESSION is there because
AuthorizedKeysFile and PermitRootLogin may come from a Match block.

A key named by RevokedKeys is refused before AUTHORIZE runs, and a
certificate is checked both through itself and through its CA key."
  (if (ssh-server-revoked-key-p server session key-blob)
      (values nil nil nil)
      (let ((authorize (ssh-server-authorize server)))
        (cond
          ((functionp authorize)
           (funcall authorize user key-blob address session))
          ((ssh-server-authorized-keys server)
           (ssh-authorized-key-blob-match (ssh-server-authorized-keys server)
                                          key-blob :address address))
          (t (values nil nil nil))))))

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

;;; ---- Per-connection sshd_config ----
;;;
;;; sshd reads its file twice: globally at startup and again per connection
;;; once the account name is known, which is what makes Match work.  The
;;; resolved config is kept on the session so every later decision -- the
;;; banner, MaxAuthTries, forwarding, ForceCommand -- uses the same values.

(defun ssh-session-effective-config (session)
  "SESSION's Match-resolved sshd_config, else the server's base config."
  (or (ssh-session-config session)
      (let ((server (ssh-session-server session)))
        (and server (ssh-server-sshd-config server)))))

(defun ssh-session-setting (session accessor)
  "ACCESSOR applied to SESSION's effective config, or NIL without one."
  (let ((config (ssh-session-effective-config session)))
    (and config (funcall accessor config))))

(defparameter +ssh-server-enabled-auth-methods+ '("publickey")
  "Authentication methods this server can complete.

AuthenticationMethods is valid with any OpenSSH method name, but a list that
needs password, keyboard-interactive, hostbased or GSSAPI can never finish
here, so sshd's rule of skipping a list that names a disabled method leaves
only publickey sequences.")

(defun ssh-server-auth-method-lists (config)
  "CONFIG's AuthenticationMethods lists that this server can complete.

NIL means no multi-method requirement, :IMPOSSIBLE means the directive was
set but no usable list remains, and otherwise the result is a list of
method lists, each in the order it must be completed."
  (let ((methods (and config
                      (ssh-server-config-authentication-methods config))))
    (cond
      ((or (null methods) (eq methods :any))
       nil)
      (t
       (let ((lists
               (remove-if-not
                (lambda (text)
                  (let ((parts (uiop:split-string text :separator ",")))
                    (and parts
                         (every (lambda (method)
                                  (member method
                                          +ssh-server-enabled-auth-methods+
                                          :test #'string=))
                                parts))))
                methods)))
         (if lists
             (mapcar (lambda (text)
                       (uiop:split-string text :separator ","))
                     lists)
             :impossible))))))

(defun ssh-server-auth-info-line (key-blob)
  "The ExposeAuthInfo line for KEY-BLOB, as sshd's sshkey_format_text."
  (multiple-value-bind (type data)
      (ssh-public-key-parts key-blob)
    (declare (ignore data))
    (format nil "publickey ~A ~A" type (ssh-octets-base64 key-blob))))

(defun ssh-session-resolve-config (session user)
  "Resolve SESSION's Match blocks for USER and remember the result.

Runs once per user name, before authentication, as sshd's getpwnamallow
does.  A server with no base config, or a config with no Match blocks, keeps
the session's config NIL so the server-level settings stay in force."
  (let* ((server (ssh-session-server session))
         (base (ssh-server-sshd-config server)))
    (when base
      (unless (and (ssh-session-config session)
                   (equal user (ssh-session-config-user session)))
        (let ((groups-hook (ssh-server-user-groups server)))
          (setf (ssh-session-config session)
                (ssh-server-config-for-connection
                 base
                 :user user
                 :groups (and groups-hook (funcall groups-hook user))
                 :groups-known (not (null groups-hook))
                 :address (ssh-session-remote-ip session)
                 :hostname (ssh-session-remote-ip session)
                 :local-port (ssh-server-port server)))
          (setf (ssh-session-config-user session) user)
          ;; A new user starts with a fresh method history, as sshd's
          ;; per-connection Authctxt does not carry one user's partial
          ;; authentication into another's.
          (setf (ssh-session-auth-method-lists session)
                (ssh-server-auth-method-lists
                 (ssh-session-effective-config session))
                (ssh-session-auth-used-keys session) '()
                (ssh-session-auth-merged-options session) nil
                (ssh-session-auth-merged-key-env session) '()
                (ssh-session-auth-info-lines session) '()))))
    (ssh-session-config session)))

(defun ssh-read-banner-file (path)
  "The text of sshd's Banner file at PATH, or NIL when there is none.

sshd reads the file for every connection and ignores one it cannot read, one
that is empty, and one larger than a megabyte, so a bad banner never stops a
login."
  (handler-case
      (when (and (stringp path) (probe-file path))
        (with-open-file (in path :direction :input :if-does-not-exist nil)
          (when in
            (let ((length (file-length in)))
              (when (and (integerp length)
                         (plusp length)
                         (<= length (* 1024 1024)))
                (let ((text (make-string length)))
                  (read-sequence text in)
                  text))))))
    (error () nil)))

(defun ssh-session-banner-text (session)
  "The Banner text SESSION should send, after Match resolution.

A Banner in the resolved config names a file, as in sshd_config; a banner
handed to MAKE-SSH-SERVER is text or a function returning it, and that is
used when no config names one."
  (let ((configured (ssh-session-setting session
                                         #'ssh-server-config-banner)))
    (cond
      ((eq configured :none) nil)
      (configured (ssh-read-banner-file configured))
      (t
       (let ((server (ssh-session-server session)))
         (when server
           (let ((banner (ssh-server-banner server)))
             (when banner
               (let ((text (if (functionp banner) (funcall banner) banner)))
                 (when (and text (plusp (length text)))
                   text))))))))))

(defun ssh-session-permit-user-environment-p (session name)
  "Whether SESSION's PermitUserEnvironment lets the user set NAME."
  (let* ((server (ssh-session-server session))
         (policy (or (ssh-session-setting
                      session
                      #'ssh-server-config-permit-user-environment)
                     (and server
                          (ssh-server-permit-user-environment server)))))
    (cond
      ((eq policy :yes) t)
      ((consp policy) (and (ssh-match-pattern-list policy name) t))
      (t nil))))

(defun ssh-session-env-allowed-p (session name value)
  "Whether SESSION's AcceptEnv policy admits NAME=VALUE.

A policy handed to MAKE-SSH-SERVER wins over the config file's, because it
is what the program set directly; otherwise the Match-resolved AcceptEnv
applies."
  (let* ((server (ssh-session-server session))
         (policy (or (and server (ssh-server-accept-env server))
                     (ssh-session-setting
                      session #'ssh-server-config-accept-env))))
    (cond
      ((eq policy t) t)
      ((functionp policy) (funcall policy name value))
      ((listp policy)
       (some (lambda (pattern) (ssh-match-pattern pattern name)) policy))
      (t nil))))

(defun ssh-session-permits-pty-p (session)
  "Whether the key that authenticated SESSION may request a pty."
  (ssh-authorization-options-permit-pty-p
   (ssh-session-authorization session)))

(defun ssh-session-permits-direct-tcpip-p (session host port)
  "Whether SESSION may open a local forward to HOST:PORT."
  (let ((options (ssh-session-authorization session)))
    (and (ssh-authorization-options-permit-port-forwarding-p options)
         (ssh-authorization-options-permit-open-p options host port))))

(defun ssh-server-permit-listen-allows-p (rules host port)
  "Whether sshd_config PermitListen RULES allow a listener on HOST:PORT.

RULES is the directive's value: NIL or \"any\" permits every listen address,
\"none\" refuses them all, and each HOST:PORT entry matches the requested host
with match_pattern, lower-cased first, and the port exactly unless the entry
says *.  A bare port was stored as *:PORT while the config was read."
  (cond
    ((null rules) t)
    ((member "none" rules :test #'string-equal) nil)
    ((member "any" rules :test #'string-equal) t)
    (t
     (let ((wanted-host (string-downcase (or host ""))))
       (some (lambda (rule)
               (multiple-value-bind (rule-host rule-port valid)
                   (ssh-authorized-key-split-permit rule nil)
                 (and valid
                      (ssh-authorization-permit-entry-port-p rule-port port)
                      (ssh-match-pattern rule-host wanted-host))))
             rules)))))

(defun ssh-session-permits-tcpip-forward-p (session host port)
  "Whether SESSION may ask the server to listen on HOST:PORT.

Both restrictions apply, as in sshd: the key's permitlisten= options and the
administrator's PermitListen, if either names one."
  (let ((options (ssh-session-authorization session)))
    (and (ssh-authorization-options-permit-port-forwarding-p options)
         (ssh-authorization-options-permit-listen-p options host port)
         (ssh-server-permit-listen-allows-p
          (ssh-session-setting session #'ssh-server-config-permit-listen)
          host port))))

;;; ---- AcceptEnv ----

(defun ssh-match-pattern-list-state (patterns text)
  "TEXT against PATTERNS as sshd's match_pattern_list(3): :DENIED, :MATCHED or NIL.

PATTERNS may hold commas; a leading ! vetoes a match.  A veto returns
:DENIED at once, exactly as match_pattern_list returns -1, so a caller that
combines several strings (Match Group, say) can let the veto win."
  (let ((matched nil))
    (dolist (pattern (loop for pattern in patterns
                           append (uiop:split-string pattern :separator ",")))
      (let ((negated (and (plusp (length pattern))
                          (char= (char pattern 0) #\!))))
        (when negated (setf pattern (subseq pattern 1)))
        (when (ssh-match-pattern pattern text)
          (if negated
              (return-from ssh-match-pattern-list-state :denied)
              (setf matched t)))))
    (and matched :matched)))

(defun ssh-match-pattern-list (patterns text)
  "Whether TEXT matches PATTERNS, sshd's match_pattern_list(3) semantics.

PATTERNS may hold commas; a leading ! vetoes a match, and any other match is
enough.  Used for PermitUserEnvironment's allowlist."
  (eq :matched (ssh-match-pattern-list-state patterns text)))

(defun ssh-pattern-list-denied-p (patterns text)
  "Whether TEXT matches one of PATTERNS' negated entries."
  (eq :denied (ssh-match-pattern-list-state patterns text)))

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

;;; ---- Connection limits and idle timeout ----
;;;
;;; sshd counts a connection as unauthenticated from accept until its first
;;; successful userauth.  MaxStartups throttles those connections, and
;;; PerSourceMaxStartups adds a per-network cap; UnusedConnectionTimeout then
;;; closes an authenticated connection that opens no channel.

(defun ssh-server-unauthenticated-sessions (server)
  "The sessions SERVER has accepted but whose user has not authenticated."
  (loop for session being the hash-values of (ssh-server-sessions server)
        when (not (ssh-session-authenticated session))
          collect session))

(defun ssh-server-should-drop-connection-p (server startups
                                            &key (random (random 100)))
  "Whether sshd's MaxStartups drops a connection with STARTUPS peers waiting.

STARTUPS counts the unauthenticated connections already established, which
is the value sshd passes to should_drop_connection: below BEGIN nothing is
dropped, at FULL everything is, and in between the chance rises linearly
from RATE percent to 100.  RANDOM is 0-99 so a test can fix the answer."
  (let ((begin (ssh-server-max-startups-begin server))
        (full (ssh-server-max-startups-full server))
        (rate (ssh-server-max-startups-rate server)))
    (cond
      ((< startups begin) nil)
      ((>= startups full) t)
      ((>= rate 100) t)
      (t
       (let ((probability
               (+ rate
                  (floor (* (- 100 rate) (- startups begin))
                         (- full begin)))))
         (< random probability))))))

(defun ssh-server-source-session-count (sessions address ipv4-bits ipv6-bits)
  "How many SESSIONS come from ADDRESS's masked network.

ADDRESS is grouped the way sshd's PerSourceNetBlockSize says: IPV4-BITS for
an IPv4 literal, IPV6-BITS for IPv6.  An address of neither family matches
no peer, the same allowance sshd makes when it cannot convert the sockaddr."
  (cond
    ((ssh-config-ipv4-octets address)
     (let ((cidr (format nil "~A/~D" address ipv4-bits)))
       (count-if (lambda (session)
                   (let ((peer (ssh-session-remote-ip session)))
                     (and peer
                          (ssh-config-ipv4-cidr-match-p cidr peer))))
                 sessions)))
    ((ssh-config-ipv6-words address)
     (let ((cidr (format nil "~A/~D" address ipv6-bits)))
       (count-if (lambda (session)
                   (let ((peer (ssh-session-remote-ip session)))
                     (and peer
                          (ssh-config-ipv6-cidr-match-p cidr peer))))
                 sessions)))
    (t 0)))

;;; ---- PerSourcePenalties ----
;;;
;;; sshd 10.6 keeps one penalty entry per masked source network.  An entry
;;; becomes active once more than the "min" threshold has accrued and refuses
;;; new connections until it expires; repeated penalties accumulate up to
;;; "max".  This server leaves penalties off unless PerSourcePenalties is
;;; configured, rather than enabling sshd's default set.

(defun ssh-server-penalty-settings (server)
  "SERVER's PerSourcePenalties settings as a plist.

The values are sshd's defaults except that :ENABLED is true only when the
directive turned it on; an absent directive leaves penalties off."
  (let* ((config (ssh-server-sshd-config server))
         (stored (and config
                      (ssh-server-config-per-source-penalties config)))
         (overflow (if (member :overflow4 stored)
                       (getf stored :overflow4)
                       :permissive)))
    (list :enabled (and (member :enabled stored)
                        (getf stored :enabled))
          :crash (or (getf stored :crash) 90)
          :authfail (or (getf stored :authfail) 5)
          :invaliduser (or (getf stored :invaliduser) 5)
          :noauth (or (getf stored :noauth) 1)
          :grace (or (getf stored :grace) 10)
          :refuseconnection (or (getf stored :refuseconnection) 10)
          :max (or (getf stored :max) 600)
          :min (or (getf stored :min) 15)
          :max-sources4 (or (getf stored :max-sources4) 65536)
          :max-sources6 (or (getf stored :max-sources6) 65536)
          :overflow4 overflow
          :overflow6 (if (member :overflow6 stored)
                         (getf stored :overflow6)
                         overflow))))

(defun ssh-server-penalty-exempt-p (server address)
  "Whether ADDRESS is named by SERVER's PerSourcePenaltyExemptList."
  (let ((config (ssh-server-sshd-config server)))
    (let ((patterns (and config
                         (ssh-server-config-per-source-penalty-exempt
                          config))))
      (and patterns
           (some (lambda (pattern)
                   (and (plusp (length pattern))
                        (not (char= (char pattern 0) #\!))
                        (or (ssh-config-ipv4-cidr-match-p pattern address)
                            (ssh-config-ipv6-cidr-match-p pattern address)
                            (ssh-match-pattern pattern address))))
                 (uiop:split-string patterns :separator ","))))))

(defun ssh-server-penalty-network (server address)
  "VALUES KEY FAMILY for ADDRESS masked by PerSourceNetBlockSize."
  (cond
    ((ssh-config-ipv4-octets address)
     (let* ((bits (ssh-server-per-source-net-block-size-ipv4 server))
            (mask (if (zerop bits)
                      0
                      (logand #xFFFFFFFF (ash #xFFFFFFFF (- 32 bits)))))
            (value (logand (ssh-config-ipv4-integer
                            (ssh-config-ipv4-octets address))
                           mask)))
       (values (format nil "4:~8,'0X/~D" value bits) 4)))
    ((ssh-config-ipv6-words address)
     (let* ((bits (ssh-server-per-source-net-block-size-ipv6 server))
            (full (floor bits 16))
            (rest (mod bits 16))
            (masked
              (loop for word in (ssh-config-ipv6-words address)
                    for index from 0
                    collect (cond
                              ((< index full) word)
                              ((= index full)
                               (if (zerop rest)
                                   0
                                   (logand word
                                           (logand #xFFFF
                                                   (ash #xFFFF (- 16 rest))))))
                              (t 0)))))
       (values (format nil "6:~{~4,'0X~}/~D" masked bits) 6)))
    (t (values nil nil))))

(defun ssh-server-penalty-expire (server)
  "Drop every expired entry from SERVER's penalty table."
  (let ((table (ssh-server-per-source-penalties server))
        (now (ssh-session-now))
        (expired '()))
    (maphash (lambda (key value)
               (when (< (first value) now)
                 (push key expired)))
             table)
    (dolist (key expired) (remhash key table))))

(defun ssh-server-penalty-count (server family)
  "How many entries SERVER holds for address FAMILY, 4 or 6."
  (let ((prefix (if (= family 4) "4:" "6:"))
        (count 0))
    (maphash (lambda (key value)
               (declare (ignore value))
               (when (and (>= (length key) 2)
                          (string= prefix key :end2 2))
                 (incf count)))
             (ssh-server-per-source-penalties server))
    count))

(defun ssh-server-penalty-evict-soonest (server family)
  "Remove the soonest-expiring entry for FAMILY, as permissive overflow does."
  (let ((prefix (if (= family 4) "4:" "6:"))
        (soonest nil)
        (soonest-key nil))
    (maphash (lambda (key value)
               (when (and (>= (length key) 2)
                          (string= prefix key :end2 2)
                          (or (null soonest) (< (first value) soonest)))
                 (setf soonest (first value) soonest-key key)))
             (ssh-server-per-source-penalties server))
    (when soonest-key
      (remhash soonest-key (ssh-server-per-source-penalties server)))))

(defun ssh-server-penalty-check (server address)
  "VALUES ALLOWED REASON for a new connection from ADDRESS."
  (let ((settings (ssh-server-penalty-settings server)))
    (if (or (not (getf settings :enabled))
            (null address)
            (ssh-server-penalty-exempt-p server address))
        (values t nil)
        (progn
          (ssh-server-penalty-expire server)
          (multiple-value-bind (key family)
              (ssh-server-penalty-network server address)
            (if (null key)
                (values t nil)
                (let ((entry
                        (gethash key
                                 (ssh-server-per-source-penalties server))))
                  (cond
                    ((and entry (second entry)
                          (>= (first entry) (ssh-session-now)))
                     (values nil (third entry)))
                    (t
                     (let* ((limit (if (= family 4)
                                       (getf settings :max-sources4)
                                       (getf settings :max-sources6)))
                            (mode (if (= family 4)
                                      (getf settings :overflow4)
                                      (getf settings :overflow6))))
                       (if (and (>= (ssh-server-penalty-count server family)
                                    limit)
                                (eq mode :deny-all))
                           (values nil "too many penalised addresses")
                           (values t nil))))))))))))

(defun ssh-server-penalise (server address type)
  "Add TYPE's penalty to SERVER's entry for ADDRESS."
  (let ((settings (ssh-server-penalty-settings server)))
    (when (and (getf settings :enabled)
               address
               (not (ssh-server-penalty-exempt-p server address)))
      (let ((seconds (case type
                       (:crash (getf settings :crash))
                       (:authfail (getf settings :authfail))
                       (:invaliduser (getf settings :invaliduser))
                       (:noauth (getf settings :noauth))
                       (:grace (getf settings :grace))
                       (:refuseconnection (getf settings :refuseconnection))
                       (t 0)))
            (reason (case type
                      (:crash "penalty: caused crash")
                      (:authfail "penalty: failed authentication")
                      (:invaliduser "penalty: attempted authentication by invalid user")
                      (:noauth "penalty: connections without attempting authentication")
                      (:grace "penalty: exceeded LoginGraceTime")
                      (:refuseconnection "penalty: connection prohibited by RefuseConnection")
                      (t "penalty"))))
        (when (and seconds (plusp seconds))
          (ssh-server-penalty-expire server)
          (multiple-value-bind (key family)
              (ssh-server-penalty-network server address)
            (when key
              (let* ((table (ssh-server-per-source-penalties server))
                     (now (ssh-session-now))
                     (max (getf settings :max))
                     (min (getf settings :min))
                     (entry (gethash key table)))
                (if entry
                    (let ((expiry (min (+ now max)
                                       (+ (first entry) seconds))))
                      (setf (first entry) expiry)
                      (when (and (> (- expiry now) min)
                                 (not (second entry)))
                        (setf (second entry) t
                              (third entry) reason)))
                    (let* ((limit (if (= family 4)
                                      (getf settings :max-sources4)
                                      (getf settings :max-sources6)))
                           (mode (if (= family 4)
                                     (getf settings :overflow4)
                                     (getf settings :overflow6)))
                           (count (ssh-server-penalty-count server family)))
                      (when (and (>= count limit) (eq mode :permissive))
                        (ssh-server-penalty-evict-soonest server family))
                      (when (or (< count limit) (eq mode :permissive))
                        (setf (gethash key table)
                              (list (+ now seconds)
                                    (> seconds min)
                                    reason)))))))))))))

(defun ssh-server-session-penalty (session)
  "Apply SESSION's close-time PerSourcePenalties reason, if any."
  (unless (ssh-session-penalty-applied-p session)
    (setf (ssh-session-penalty-applied-p session) t)
    (let ((server (ssh-session-server session))
          (address (ssh-session-remote-ip session)))
      (when (and server address
                 (not (eq (ssh-session-close-reason session)
                          :server-closed)))
        (cond
          ((ssh-session-refused-p session)
           (ssh-server-penalise server address :refuseconnection))
          ((ssh-session-grace-exceeded-p session)
           (ssh-server-penalise server address :grace))
          ((ssh-session-invalid-user-p session)
           (ssh-server-penalise server address :invaliduser))
          ((and (not (ssh-session-authenticated session))
                (plusp (ssh-session-auth-failures session)))
           (ssh-server-penalise server address :authfail))
          ((and (not (ssh-session-authenticated session))
                (zerop (ssh-session-auth-attempts session)))
           (ssh-server-penalise server address :noauth)))))))

(defun ssh-server-connection-allowed-p (server peer-address
                                        &key (random (random 100)))
  "Whether SERVER may keep a newly accepted connection.

PEER-ADDRESS is CL-PNET's (:ADDRESS IP :PORT PORT).  MaxStartups and
PerSourceMaxStartups both count the unauthenticated connections already
accepted, as sshd's startup table does, and either can refuse this one."
  (let ((startups (ssh-server-unauthenticated-sessions server)))
    (and (not (ssh-server-should-drop-connection-p
               server (length startups) :random random))
         (let ((limit (ssh-server-per-source-max-startups server)))
           (or (null limit)
               (< (ssh-server-source-session-count
                   startups
                   (getf peer-address :address)
                   (ssh-server-per-source-net-block-size-ipv4 server)
                   (ssh-server-per-source-net-block-size-ipv6 server))
                  limit))))))

(defun ssh-server-apply-tcp-keepalive (server fd)
  "Turn TCP keepalives on FD on or off, as SERVER's TCPKeepAlive says.

The event loop enables SO_KEEPALIVE on every accepted socket by default, so
this only has work when the config turns it off."
  (when fd
    (cl-pnet-sockets:set-socket-option
     fd cl-pnet-sockets:+sol-socket+ cl-pnet-sockets:+so-keepalive+
     (if (ssh-server-tcp-keep-alive server) 1 0))))

(defun ssh-server-session-open-channel-p (session)
  "Whether SESSION has a channel still open or opening."
  (loop for channel being the hash-values of (ssh-session-channels session)
        thereis (not (eq (ssh-server-channel-state channel) :closed))))

(defun ssh-session-unused-connection-timeout (session)
  "SESSION's UnusedConnectionTimeout in seconds, or 0 for none."
  (or (ssh-session-setting
       session #'ssh-server-config-unused-connection-timeout)
      (ssh-server-unused-connection-timeout (ssh-session-server session))))

(defun ssh-session-stop-unused-timer (session)
  "Disarm SESSION's UnusedConnectionTimeout, if it is armed."
  (setf (ssh-session-unused-connection-timer session)
        (ssh-session-cancel-timer
         (ssh-session-unused-connection-timer session))))

(defun ssh-session-start-unused-timer (session)
  "Arm SESSION's UnusedConnectionTimeout when no channel is open.

sshd starts the clock once authentication finishes and restarts it whenever
the last channel closes; a timeout with a channel still open never fires."
  (ssh-session-stop-unused-timer session)
  (let ((seconds (ssh-session-unused-connection-timeout session)))
    (when (and seconds
               (plusp seconds)
               (ssh-session-authenticated session)
               (not (ssh-session-closed session)))
      (setf (ssh-session-unused-connection-timer session)
            (cl-pnet:timer-start
             seconds 0
             (lambda ()
               (setf (ssh-session-unused-connection-timer session) nil)
               (when (and (not (ssh-session-closed session))
                          (not (ssh-server-session-open-channel-p session)))
                 (ssh-session-finish
                  session "terminating inactive connection" :close))))))))

(defun ssh-session-channel-timeouts (session)
  "SESSION's effective ChannelTimeout value.

A Match block's list, including :NONE, replaces the server's; NIL keeps the
server value.  :NONE is an explicit directive that disables every timeout."
  (let ((timeouts (ssh-session-setting
                   session #'ssh-server-config-channel-timeouts)))
    (if (null timeouts)
        (ssh-server-channel-timeouts (ssh-session-server session))
        timeouts)))

(defun ssh-channel-type-matches-p (pattern type)
  "Whether ChannelTimeout PATTERN selects channel TYPE.

OpenSSH 10.6 uses the single name \"session\" for every session channel,
while 9.x names session:shell, session:command and session:subsystem:*.
Accept both so an older sshd_config keeps its meaning.  \"global\" is a
connection-wide timeout and never selects one channel."
  (cond
    ((string= pattern "global") nil)
    ((string= pattern "session")
     (or (string= type "session")
         (let ((prefix "session:"))
           (and (>= (length type) (length prefix))
                (string= prefix type :end2 (length prefix))))))
    (t (ssh-match-pattern pattern type))))

(defun ssh-server-channel-resolve-timeout (channel)
  "CHANNEL's inactivity limit in seconds, or 0 when no pattern matches.

The first ChannelTimeout pattern matching the channel's extended type wins,
as sshd's lookup_timeout returns the first match.  Until a session request
labels the channel, its plain type is what sshd matches, so \"session=2\"
starts counting at open and, in 10.6, keeps applying after the label."
  (let ((timeouts (ssh-session-channel-timeouts
                   (ssh-server-channel-session channel))))
    (when (consp timeouts)
      (let ((type (or (ssh-server-channel-x-type channel)
                      (ssh-server-channel-type channel))))
        (loop for (pattern . seconds) in timeouts
              when (ssh-channel-type-matches-p pattern type)
                return seconds)))))

(defun ssh-session-global-channel-timeout (session)
  "SESSION's global ChannelTimeout in seconds, or NIL when none is set."
  (let ((timeouts (ssh-session-channel-timeouts session)))
    (when (consp timeouts)
      (cdr (assoc "global" timeouts :test #'string=)))))

(defun ssh-server-channel-refresh-inactivity-timeout (channel)
  "Re-resolve CHANNEL's limit after its extended type changes.

sshd's channel_set_xtype only recomputes the deadline; the activity clock
keeps running from the last byte, so a channel that has been idle longer than
the new limit is closed on the next wakeup."
  (when (eq (ssh-server-channel-state channel) :open)
    (setf (ssh-server-channel-inactive-timeout channel)
          (or (ssh-server-channel-resolve-timeout channel) 0))
    (ssh-session-refresh-channel-timeout-timer
     (ssh-server-channel-session channel))))

(defun ssh-server-channel-start-inactivity-timeout (channel)
  "Start CHANNEL's inactivity clock from now.

sshd starts it when the channel becomes usable: at open confirmation for an
incoming or forwarded channel, and when its target connects for direct-tcpip."
  (when (eq (ssh-server-channel-state channel) :open)
    (setf (ssh-server-channel-last-used channel) (ssh-session-now))
    (ssh-server-channel-refresh-inactivity-timeout channel)))

(defun ssh-server-channel-set-x-type (channel type)
  "Give CHANNEL sshd's extended type and re-resolve its inactivity limit."
  (setf (ssh-server-channel-x-type channel) type)
  (ssh-server-channel-refresh-inactivity-timeout channel))

(defun ssh-server-channel-note-activity (channel)
  "Move CHANNEL's inactivity deadline to now."
  (when (eq (ssh-server-channel-state channel) :open)
    (setf (ssh-server-channel-last-used channel) (ssh-session-now))))

(defun ssh-session-stop-channel-timeout-timer (session)
  "Disarm SESSION's ChannelTimeout timer."
  (setf (ssh-session-channel-timeout-timer session)
        (ssh-session-cancel-timer
         (ssh-session-channel-timeout-timer session))))

(defun ssh-session-refresh-channel-timeout-timer (session)
  "Arm SESSION's timer for the earliest open-channel inactivity deadline.

One timer per connection is enough: activity only moves a channel's
LAST-USED, so a timer that fires early simply recomputes and rearms."
  (let ((earliest nil)
        (now (ssh-session-now))
        (timeouts (ssh-session-channel-timeouts session)))
    (when (and (not (ssh-session-closed session)) (consp timeouts))
      (loop for channel being the hash-values of
              (ssh-session-channels session)
            do (let ((deadline (+ (ssh-server-channel-last-used channel)
                                  (ssh-server-channel-inactive-timeout
                                   channel))))
                 (when (and (eq (ssh-server-channel-state channel) :open)
                            (plusp (ssh-server-channel-inactive-timeout channel))
                            (or (null earliest) (< deadline earliest)))
                   (setf earliest deadline))))
      ;; A global timeout runs from the newest activity on any open channel.
      (let ((global (ssh-session-global-channel-timeout session))
            (latest nil))
        (when (and global (plusp global))
          (loop for channel being the hash-values of
                  (ssh-session-channels session)
                when (and (eq (ssh-server-channel-state channel) :open)
                          (plusp (ssh-server-channel-last-used channel)))
                  do (setf latest
                           (if latest
                               (max latest (ssh-server-channel-last-used
                                            channel))
                               (ssh-server-channel-last-used channel))))
          (when latest
            (let ((deadline (+ latest global)))
              (when (or (null earliest) (< deadline earliest))
                (setf earliest deadline)))))))
    (ssh-session-stop-channel-timeout-timer session)
    (when earliest
      (setf (ssh-session-channel-timeout-timer session)
            (cl-pnet:timer-start
             (max 0.05 (- earliest now)) 0
             (lambda ()
               (setf (ssh-session-channel-timeout-timer session) nil)
               (ssh-session-channel-timeout-tick session)))))))

(defun ssh-session-channel-timeout-tick (session)
  "Close every open channel whose ChannelTimeout has expired.

The per-channel limits are checked first; a global timeout then closes all
channels still open once the newest activity on any of them is older than
the global interval."
  (unless (ssh-session-closed session)
    (let ((now (ssh-session-now)))
      (dolist (channel (iter (for (id channel) in-hashtable
                                    (ssh-session-channels session))
                        (collect channel)))
        (when (and (eq (ssh-server-channel-state channel) :open)
                   (plusp (ssh-server-channel-inactive-timeout channel))
                   (>= now (+ (ssh-server-channel-last-used channel)
                              (ssh-server-channel-inactive-timeout channel))))
          (ssh-server-channel-force-close channel)))
      (let ((global (ssh-session-global-channel-timeout session))
            (latest nil))
        (when (and global (plusp global))
          (loop for channel being the hash-values of
                  (ssh-session-channels session)
                when (and (eq (ssh-server-channel-state channel) :open)
                          (plusp (ssh-server-channel-last-used channel)))
                  do (setf latest
                           (if latest
                               (max latest (ssh-server-channel-last-used
                                            channel))
                               (ssh-server-channel-last-used channel))))
          (when (and latest (>= now (+ latest global)))
            (dolist (channel (iter (for (id channel) in-hashtable
                                        (ssh-session-channels session))
                                (collect channel)))
              (when (eq (ssh-server-channel-state channel) :open)
                (ssh-server-channel-force-close channel)))))))
    (ssh-session-refresh-channel-timeout-timer session)))

(defun ssh-session-note-channel-change (session)
  "React to SESSION's channels opening or closing.

An open channel suspends UnusedConnectionTimeout; once the last one closes,
the full timeout starts again.  A new open channel also shortens the
ChannelTimeout wakeup when its deadline comes first."
  (unless (ssh-session-closed session)
    (if (ssh-server-session-open-channel-p session)
        (ssh-session-stop-unused-timer session)
        (ssh-session-start-unused-timer session))
    (ssh-session-refresh-channel-timeout-timer session)))

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
