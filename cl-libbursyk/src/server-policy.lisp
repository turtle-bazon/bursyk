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
               ((char= character #\\)
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

(defun ssh-authorized-key-line-parts (line)
  "The key blob, options and environment of one authorized_keys LINE.

The options are the comma-separated words before the key type; sshd parses
them for from=, command=, environment= and the rest.  Returns
(VALUES BLOB OPTIONS ENVIRONMENTS), or three NILs when the line holds no
recognised key or an environment= option sshd would refuse."
  (let* ((trimmed (string-trim '(#\Space #\Tab #\Return #\Newline) line))
         (fields (and (plusp (length trimmed))
                      (not (char= (char trimmed 0) #\#))
                      (ssh-authorized-key-line-fields trimmed))))
    (when fields
      (let ((position (position-if
                       (lambda (field)
                         (member field '("ssh-ed25519" "ssh-rsa"
                                         "ecdsa-sha2-nistp256"
                                         "ecdsa-sha2-nistp384"
                                         "ecdsa-sha2-nistp521")
                                 :test #'string=))
                       fields)))
        (when (and position (< (1+ position) (length fields)))
          (let ((blob (handler-case
                          (ssh-base64-octets (nth (1+ position) fields))
                        (cl-base64:bad-base64-character () nil)))
                (options (format nil "~{~A~^ ~}" (subseq fields 0 position))))
            (multiple-value-bind (environments valid)
                (ssh-authorized-key-options-environments options)
              (if (and blob valid)
                  (values blob options environments)
                  (values nil nil nil)))))))))

(defun ssh-authorized-key-line-blob (line)
  "The public key blob on one authorized_keys LINE, or NIL."
  (nth-value 0 (ssh-authorized-key-line-parts line)))

(defun ssh-authorized-key-option-tokens (options)
  "The comma-separated options in OPTIONS, keeping quoted values whole."
  (let ((tokens '())
        (start 0)
        (quoted nil)
        (escaped nil))
    (loop for index from 0 below (length options)
          for character = (char options index)
          do (cond
               (escaped (setf escaped nil))
               ((and quoted (char= character #\\)) (setf escaped t))
               ((char= character #\") (setf quoted (not quoted)))
               ((and (not quoted) (char= character #\,))
                (push (subseq options start index) tokens)
                (setf start (1+ index))))
          finally (push (subseq options start) tokens))
    (nreverse tokens)))

(defun ssh-authorized-key-option-unquote (value)
  "VALUE with a surrounding pair of quotes and its backslash escapes removed.

Returns (VALUES TEXT VALID); an opening quote with no closing one is
malformed and sshd refuses the whole line."
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
                                (< (1+ index) (length body)))
                           (progn
                             (write-char (char body (1+ index)) out)
                             (incf index))
                           (write-char character out))))
            t))
         (values value nil)))
    (t (values value t))))

(defun ssh-authorized-key-options-environments (options)
  "The environment assignments in an authorized_keys OPTIONS string.

Returns (VALUES ASSIGNMENTS VALID).  Only `environment=\"NAME=VALUE\"' is
read here.  sshd refuses a line whose option is malformed, so VALID is NIL
when a variable name or the quoting is unusable; the caller then skips the
key line instead of accepting a key with an option it could not honour."
  (let ((environments '())
        (valid t))
    (dolist (token (ssh-authorized-key-option-tokens (or options "")))
      (let ((equals (position #\= token)))
        (when (and equals
                   (string-equal (string-trim '(#\Space #\Tab)
                                              (subseq token 0 equals))
                                 "environment"))
          (multiple-value-bind (value value-valid)
              (ssh-authorized-key-option-unquote
               (string-trim '(#\Space #\Tab)
                            (subseq token (1+ equals))))
            (let ((name-end (and value-valid (position #\= value))))
              (if (and name-end
                       (ssh-server-config-env-name-p
                        (subseq value 0 name-end)))
                  (push value environments)
                  (setf valid nil)))))))
    (values (nreverse environments) valid)))

(defun ssh-authorized-key-line-environments (line)
  "The environment assignments attached to the key on one LINE."
  (nth-value 2 (ssh-authorized-key-line-parts line)))

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
  "Every well-formed (BLOB . ENVIRONMENTS) in the file at PATH."
  (if (probe-file path)
      (with-open-file (stream path :direction :input :if-does-not-exist nil
                                   :external-format :utf-8)
        (iter (for line = (read-line stream nil nil))
          (while line)
          (multiple-value-bind (blob options environments)
              (ssh-authorized-key-line-parts line)
            (declare (ignore options))
            (when blob
              (collect (cons blob environments))))))
      nil))

(defun ssh-authorized-key-file-blobs (path)
  "Every well-formed key blob in the authorized_keys file at PATH."
  (mapcar #'car (ssh-authorized-key-file-entries path)))

(defun ssh-authorized-key-source-entries (source)
  "SOURCE's authorized_keys lines as (BLOB . ENVIRONMENTS) pairs."
  (cond
    ((listp source)
     (if (every (lambda (item)
                  (typep item '(vector (unsigned-byte 8))))
                source)
         (mapcar #'list source)
         (iter (for line in source)
           (multiple-value-bind (blob options environments)
               (ssh-authorized-key-line-parts line)
             (declare (ignore options))
             (when blob
               (collect (cons blob environments)))))))
    ((pathnamep source) (ssh-authorized-key-file-entries source))
    ((stringp source)
     (if (probe-file source)
         (ssh-authorized-key-file-entries source)
         (multiple-value-bind (blob options environments)
             (ssh-authorized-key-line-parts source)
           (declare (ignore options))
           (if blob
               (list (cons blob environments))
               nil))))
    (t nil)))

(defun ssh-authorized-key-blob-match (source key-blob)
  "Whether KEY-BLOB is listed in SOURCE, and the environment it carries.

Returns (VALUES MATCHED ENVIRONMENTS).  sshd applies the `environment='
options of the key line that authenticated the user, so the first matching
line supplies them; a key with no options has an empty list."
  (iter (for entry in (ssh-authorized-key-source-entries source))
    (when (ssh-octets= (car entry) key-blob)
      (return-from ssh-authorized-key-blob-match
        (values t (cdr entry)))))
  (values nil nil))

(defun ssh-authorized-key-blob-p (source key-blob)
  "Whether KEY-BLOB is listed in SOURCE, a file, a list, or one line."
  (nth-value 0 (ssh-authorized-key-blob-match source key-blob)))

(defun ssh-server-authorized-key-p (server user key-blob)
  "Whether KEY-BLOB may log in as USER on SERVER.

Returns (VALUES MATCHED ENVIRONMENTS) so the caller can apply the
authorized_keys line's environment= options.  A custom AUTHORIZE function
answers only MATCHED, unless it returns a second value."
  (let ((authorize (ssh-server-authorize server)))
    (cond
      ((functionp authorize) (funcall authorize user key-blob))
      ((ssh-server-authorized-keys server)
       (ssh-authorized-key-blob-match (ssh-server-authorized-keys server)
                                      key-blob))
      (t (values nil nil)))))

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
command, which this server does not implement yet, so it refuses every
root login rather than pretending the command would be forced."
  (case (or mode :prohibit-password)
    (:yes t)
    (:no nil)
    (:prohibit-password
     (not (null (member method '("publickey" "hostbased" "gssapi-with-mic")
                        :test #'string=))))
    (:forced-commands-only (not (null force-command)))
    (t nil)))
