(in-package #:cl-pnet-ssh)

;;;; What authentication needs from a key: its type and public blob, and a
;;;; function that signs the session exchange.  A key loaded from a file and
;;;; a key held by an agent implement the same interface, so the transport
;;;; never knows which one it got.
;;;;
;;;; SIGN takes DATA, an ON-SIGNATURE callback and an ON-ERROR callback.  A
;;;; local key calls back before returning; an agent answers later, from the
;;;; event loop, without ever blocking the thread that asked.

(defstruct (ssh-signer (:constructor %make-ssh-signer))
  (type nil)
  (blob nil)
  (sign nil))

(defun ssh-public-key-file-blob (path)
  "The key blob on the first non-blank line of PATH, or NIL.

The file may be a bare public key, as ssh-keygen writes, or any line that
starts with a key type and its base64; a comment after it is ignored."
  (handler-case
      (with-open-file (stream path :direction :input
                                   :if-does-not-exist nil)
        (when stream
          (loop for line = (read-line stream nil nil)
                while line
                for fields = (uiop:split-string
                              line :separator '(#\Space #\Tab #\Return))
                when (and fields (second fields))
                  do (return-from ssh-public-key-file-blob
                       (handler-case (ssh-base64-octets (second fields))
                         (cl-base64:bad-base64-character () nil))))))
    (error () nil)))

(defun ssh-private-key-certificate (key)
  "VALUES CERTIFICATE BLOB for the certificate next to KEY's file, or NIL.

OpenSSH looks for PRIVATE-KEY-cert.pub whenever it loads PRIVATE-KEY.  A
certificate whose plain key is not this key is an error, as ssh refuses to
pair them; silently offering the wrong identity would be worse."
  (let ((path (ssh-private-key-path key)))
    (when path
      (let* ((certificate-path
               (concatenate 'string (namestring path) "-cert.pub"))
             (blob (ssh-public-key-file-blob certificate-path)))
        (when (and blob (ssh-certificate-blob-p blob))
          (let ((certificate (ssh-certificate-parse blob)))
            (cond
              ((null certificate)
               (error "~A is not a readable certificate" certificate-path))
              ((not (ssh-octets= (ssh-certificate-plain-blob certificate)
                                 (ssh-public-key-blob-of key)))
               (error "certificate ~A does not match private key ~A"
                      certificate-path path))
              (t (values certificate blob)))))))))

(defun ssh-certificate-signer-type (certificate)
  "The userauth algorithm name for CERTIFICATE.

An RSA certificate is offered under an RFC 8332 certificate name so that the
signature inside it, which this client makes with SHA-256, is the algorithm
that name implies.  The other key types use their own certificate name."
  (if (string= (ssh-certificate-plain-key-type certificate) "ssh-rsa")
      "rsa-sha2-256-cert-v01@openssh.com"
      (ssh-certificate-key-type certificate)))

(defun ssh-private-key-signer (key &key certificate-files-specified)
  "A signer backed by a loaded private KEY.

The signature needs no I/O, so ON-SIGNATURE runs before SIGN returns.
ed25519, RSA and ECDSA keys all sign locally.  When KEY's file has a
matching CERT.pub beside it, the signer offers the certificate and names its
certificate type, while the signature is still made by the private key.

CERTIFICATE-FILES-SPECIFIED suppresses that automatic lookup: ssh uses the
CERT.pub beside a key only when no CertificateFile was configured."
  (multiple-value-bind (certificate certificate-blob)
      (if certificate-files-specified
          (values nil nil)
          (ssh-private-key-certificate key))
    (let ((type (ssh-private-key-type key)))
      (when (and (null certificate) (string= type "ssh-rsa"))
        ;; The request names the signature algorithm, not the key type, so an
        ;; RSA key signs as rsa-sha2-256 while its blob stays ssh-rsa.
        (setf type (ssh-rsa-signature-algorithm :sha256)))
      (%make-ssh-signer
       :type (if certificate
                 (ssh-certificate-signer-type certificate)
                 type)
       :blob (or certificate-blob (ssh-public-key-blob-of key))
       :sign (lambda (data on-signature on-error)
               (handler-case
                   (funcall on-signature
                            (ssh-private-key-signature-blob key data))
                 (error (condition) (funcall on-error condition))))))))

(defun ssh-load-certificate-files (paths)
  "Load the certificates named by PATHS, as (CERT-BLOB . CERTIFICATE) pairs.

A missing or unreadable file, a file that does not hold a key, and a key that
is not a user certificate are logged and skipped, as ssh does: one bad
CertificateFile must not hide a good one.  The plain key each certificate
certifies is available as SSH-CERTIFICATE-PLAIN-BLOB."
  (let ((certificates '()))
    (dolist (path paths)
      (let ((blob (and path (ssh-public-key-file-blob path))))
        (cond
          ((null blob)
           (ssh-log "could not load certificate file ~A" path))
          ((not (ssh-certificate-blob-p blob))
           (ssh-log "~A is not a certificate" path))
          (t
           (let ((certificate (ssh-certificate-parse blob)))
             (cond
               ((null certificate)
                (ssh-log "~A is not a readable certificate" path))
               ((/= (ssh-certificate-cert-type certificate) 1)
                (ssh-log "ignoring certificate ~A: not a user certificate"
                         path))
               (t
                (push (cons blob certificate) certificates))))))))
    (nreverse certificates)))

(defun ssh-signer-plain-blob (signer)
  "SIGNER's public key without a certificate wrapper, when it has one."
  (let ((blob (ssh-signer-blob signer)))
    (if (ssh-certificate-blob-p blob)
        (let ((certificate (ssh-certificate-parse blob)))
          (if certificate
              (ssh-certificate-plain-blob certificate)
              blob))
        blob)))

(defun ssh-signer-with-certificate (signer certificate blob)
  "SIGNER offering CERTIFICATE, whose wire blob is BLOB.

The private key is still SIGNER's, so its signing function is reused; only
the advertised type and public blob change."
  (%make-ssh-signer
   :type (ssh-certificate-signer-type certificate)
   :blob blob
   :sign (ssh-signer-sign signer)))

(defun ssh-signers-with-certificates (signers certificates)
  "SIGNERS with each matching certificate in CERTIFICATES offered instead.

A certificate applies to the signer whose plain public key it certifies,
whether that key came from a file or an agent, which is what ssh does when it
pairs a certificate with the private key that can complete its signature.
Certified signers move to the front, because ssh tries certificates listed in
the configuration before uncertified keys."
  (if (null certificates)
      signers
      (let ((certified '())
            (rest '()))
        (dolist (signer signers)
          (let* ((plain (ssh-signer-plain-blob signer))
                 (pair
                   (find-if (lambda (candidate)
                              (ssh-octets=
                               plain
                               (ssh-certificate-plain-blob (cdr candidate))))
                            certificates)))
            (if pair
                (push (ssh-signer-with-certificate
                       signer (cdr pair) (car pair))
                      certified)
                (push signer rest))))
        (append (nreverse certified) (nreverse rest)))))

(defparameter +ssh-agent-key-types+
  '("ssh-ed25519" "ssh-rsa"
    "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521")
  "Key types this client can offer through an agent.

An agent signs, so a curve it supports is enough; the client only has to
name the key type the same way the protocol does.")

(defparameter +ssh-signature-algorithms+
  '("ssh-ed25519" "rsa-sha2-256"
    "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521"
    ;; A certificate authenticates under its certificate type name, so
    ;; PubkeyAcceptedAlgorithms has to be able to name those as well;
    ;; OpenSSH's default list carries them beside the plain names.
    "ssh-ed25519-cert-v01@openssh.com"
    "rsa-sha2-256-cert-v01@openssh.com"
    "ecdsa-sha2-nistp256-cert-v01@openssh.com"
    "ecdsa-sha2-nistp384-cert-v01@openssh.com"
    "ecdsa-sha2-nistp521-cert-v01@openssh.com")
  "Signature algorithms a signer here can name.

RSA signs as rsa-sha2-256 rather than the SHA-1 ssh-rsa, so
PubkeyAcceptedAlgorithms is resolved against this list; naming ssh-rsa is
an error rather than a silent downgrade.  Certificate types are here because
a certificate signs in under its own name, not the plain key's.")

(defun ssh-agent-signer (key-blob path)
  "A signer that has the agent at PATH sign with KEY-BLOB."
  (multiple-value-bind (type data) (ssh-public-key-parts key-blob)
    (declare (ignore data))
    (let ((algorithm (if (string= type "ssh-rsa")
                         (ssh-rsa-signature-algorithm :sha256)
                         type))
          ;; ssh-agent flag 2 asks an RSA key for rsa-sha2-256; the other
          ;; key types ignore the flags.
          (flags (if (string= type "ssh-rsa") 2 0)))
      (%make-ssh-signer
       :type algorithm
       :blob key-blob
       :sign (lambda (data on-signature on-error)
               (ssh-agent-sign key-blob data
                               :path path
                               :flags flags
                               :on-signature on-signature
                               :on-error on-error))))))

(defun ssh-agent-signers (&key path on-signers on-error)
  "The agent's usable signers, delivered to ON-SIGNERS without blocking.

Key types the transport cannot name are skipped, so one unsupported identity
does not hide the rest."
  (handler-case
      (let ((path (ssh-agent-path path)))
        (ssh-agent-identities
         :path path
         :on-identities
         (lambda (entries)
           (handler-case
               (funcall on-signers
                        (iter (for entry in entries)
                          (let ((blob (car entry)))
                            (multiple-value-bind (type data)
                                (ssh-public-key-parts blob)
                              (declare (ignore data))
                              (when (member type +ssh-agent-key-types+
                                            :test #'string=)
                                (collect (ssh-agent-signer blob path)))))))
             (error (condition) (funcall on-error condition))))
         :on-error on-error))
    (error (condition) (funcall on-error condition))))
