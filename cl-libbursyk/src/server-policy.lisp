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
                                         "ecdsa-sha2-nistp256")
                                 :test #'string=))
                       fields)))
        (when (and position (< (1+ position) (length fields)))
          ;; A malformed key on one line must not abort the whole file; skip
          ;; only the decode failure, not every possible error.
          (handler-case
              (ssh-base64-octets (nth (1+ position) fields))
            (cl-base64:bad-base64-character () nil)))))))

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

(defun ssh-server-env-allowed-p (server name value)
  "Whether SERVER's AcceptEnv policy admits NAME=VALUE."
  (let ((policy (ssh-server-accept-env server)))
    (cond
      ((eq policy t) t)
      ((functionp policy) (funcall policy name value))
      ((listp policy) (member name policy :test #'string=))
      (t nil))))
