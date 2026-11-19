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

(defun ssh-private-key-signer (key)
  "A signer backed by a loaded private KEY.

The signature needs no I/O, so ON-SIGNATURE runs before SIGN returns.
ed25519, RSA and ECDSA keys all sign locally."
  (let ((type (ssh-private-key-type key)))
    (when (string= type "ssh-rsa")
      ;; The request names the signature algorithm, not the key type, so an
      ;; RSA key signs as rsa-sha2-256 while its blob stays ssh-rsa.
      (setf type (ssh-rsa-signature-algorithm :sha256)))
    (%make-ssh-signer
     :type type
     :blob (ssh-public-key-blob-of key)
     :sign (lambda (data on-signature on-error)
             (handler-case
                 (funcall on-signature
                          (ssh-private-key-signature-blob key data))
               (error (condition) (funcall on-error condition)))))))

(defparameter +ssh-agent-key-types+
  '("ssh-ed25519" "ssh-rsa"
    "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521")
  "Key types this client can offer through an agent.

An agent signs, so a curve it supports is enough; the client only has to
name the key type the same way the protocol does.")

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
