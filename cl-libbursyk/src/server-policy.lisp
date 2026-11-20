(in-package #:cl-pnet-ssh)

;;;; Policies both server backends apply.  The key list is the same text
;;;; sshd reads and the env list is the same AcceptEnv scope, so neither
;;;; depends on which transport is in use.

;;; ---- authorized_keys ----

(defun ssh-authorized-key-line-blob (line)
  "The public key blob on one authorized_keys LINE, or NIL."
  (let* ((trimmed (string-trim '(#\Space #\Tab #\Return #\Newline) line))
         (fields (remove "" (uiop:split-string
                             trimmed :separator '(#\Space #\Tab))
                         :test #'string=)))
    (when (and (plusp (length trimmed))
               (not (char= (char trimmed 0) #\#)))
      (let ((position (position-if
                       (lambda (field)
                         (member field '("ssh-ed25519" "ssh-rsa"
                                         "ecdsa-sha2-nistp256"
                                         "ecdsa-sha2-nistp384"
                                         "ecdsa-sha2-nistp521")
                                 :test #'string=))
                       fields)))
        (when (and position (< (1+ position) (length fields)))
          ;; A malformed key on one line must not abort the whole file; skip
          ;; only the decode failure, not every possible error.
          (handler-case
              (ssh-base64-octets (nth (1+ position) fields))
            (cl-base64:bad-base64-character () nil)))))))

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

(defun ssh-authorized-key-file-blobs (path)
  "Every well-formed key blob in the authorized_keys file at PATH."
  (if (probe-file path)
      (with-open-file (stream path :direction :input :if-does-not-exist nil
                                   :external-format :utf-8)
        (iter (for line = (read-line stream nil nil))
          (while line)
          (let ((blob (ssh-authorized-key-line-blob line)))
            (when blob (collect blob)))))
      nil))

(defun ssh-authorized-key-blob-p (source key-blob)
  "Whether KEY-BLOB is listed in SOURCE, a file, a list, or one line."
  (let ((blobs (cond
                 ((listp source)
                  (if (every (lambda (item)
                               (typep item '(vector (unsigned-byte 8))))
                             source)
                      source
                      (mapcar #'ssh-authorized-key-line-blob source)))
                 ((pathnamep source) (ssh-authorized-key-file-blobs source))
                 ((stringp source)
                  (if (probe-file source)
                      (ssh-authorized-key-file-blobs source)
                      (list (ssh-authorized-key-line-blob source))))
                 (t nil))))
    (iter (for blob in blobs)
      (thereis (and blob (ssh-octets= blob key-blob))))))

(defun ssh-server-authorized-key-p (server user key-blob)
  "Whether KEY-BLOB may log in as USER on SERVER."
  (let ((authorize (ssh-server-authorize server)))
    (cond
      ((functionp authorize) (funcall authorize user key-blob))
      ((ssh-server-authorized-keys server)
       (ssh-authorized-key-blob-p (ssh-server-authorized-keys server)
                                  key-blob))
      (t nil))))

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

(defun ssh-server-env-allowed-p (server name value)
  "Whether SERVER's AcceptEnv policy admits NAME=VALUE."
  (let ((policy (ssh-server-accept-env server)))
    (cond
      ((eq policy t) t)
      ((functionp policy) (funcall policy name value))
      ((listp policy)
       (some (lambda (pattern) (ssh-match-pattern pattern name)) policy))
      (t nil))))
