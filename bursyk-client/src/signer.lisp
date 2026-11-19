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

The signature needs no I/O, so ON-SIGNATURE runs before SIGN returns."
  (%make-ssh-signer
   :type (ssh-private-key-type key)
   :blob (ssh-public-key-blob-of key)
   :sign (lambda (data on-signature on-error)
           (handler-case
               (funcall on-signature (ssh-ed25519-signature-blob key data))
             (error (condition) (funcall on-error condition))))))

(defun ssh-agent-signer (key-blob path)
  "A signer that has the agent at PATH sign with KEY-BLOB."
  (multiple-value-bind (type data) (ssh-public-key-parts key-blob)
    (declare (ignore data))
    (%make-ssh-signer
     :type type
     :blob key-blob
     :sign (lambda (data on-signature on-error)
             (ssh-agent-sign key-blob data
                             :path path
                             :on-signature on-signature
                             :on-error on-error)))))

(defun ssh-agent-signers (&key path on-signers on-error)
  "The agent's ssh-ed25519 signers, delivered to ON-SIGNERS without blocking.

Other key types are skipped: this client only offers ssh-ed25519, and asking
the agent for a key the transport cannot name would just fail the request."
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
                              (when (string= type "ssh-ed25519")
                                (collect (ssh-agent-signer blob path)))))))
             (error (condition) (funcall on-error condition))))
         :on-error on-error))
    (error (condition) (funcall on-error condition))))
