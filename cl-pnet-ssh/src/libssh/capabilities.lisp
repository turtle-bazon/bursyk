(in-package #:cl-pnet-ssh)

;;;; What the loaded libssh can negotiate.
;;;;
;;;; libssh builds its algorithm tables at compile time, and they differ
;;;; between 0.10, 0.12 and whatever the system has next.  This adapter must
;;;; not assume a version: it asks the library which names it accepts with
;;;; the same SSH_OPTIONS_SET call the connection uses.  A name the library
;;;; accepts is offered; a name it refuses is left out of -Q, the defaults
;;;; and config validation, and refused with SSH-UNSUPPORTED-FEATURE when a
;;;; caller names it explicitly.
;;;;
;;;; Libssh has no API that lists its algorithms, so a scratch session is the
;;;; probe.  Creating and freeing it opens no socket and sends no packets.

(defvar *ssh-plibssh-algorithm-support* (make-hash-table :test #'eq)
  "Per-kind cache of the names the loaded libssh accepted.
The library's tables do not change during a run, so each kind is probed
once.")

(defun ssh-plibssh-probe-option (code name)
  "Whether the loaded libssh accepts NAME for SSH_OPTIONS_SET code CODE."
  (let ((session (ssh-new)))
    (when (ssh-plibssh-null-p session)
      (error 'ssh-connection-error
             :detail "could not allocate a libssh session"))
    (unwind-protect
         (zerop (ssh-plibssh-set-string-option session code name))
      (ssh-free session))))

(defun ssh-plibssh-algorithm-code (kind)
  "The SSH_OPTIONS_SET code that validates algorithm KIND."
  (ecase kind
    (:kex +ssh-options-key-exchange+)
    (:host-key-algorithms
     +ssh-options-hostkeys+)
    ((:signature-algorithms :ca-signature-algorithms)
     +ssh-options-publickey-accepted-types+)
    (:ciphers +ssh-options-ciphers-c-s+)
    (:macs +ssh-options-hmac-c-s+)
    (:compressions +ssh-options-compression-c-s+)))

(defun ssh-plibssh-algorithm-names (kind)
  "The core table of names to probe for algorithm KIND."
  (ecase kind
    (:kex +ssh-kex-real-algorithms+)
    (:host-key-algorithms +ssh-host-key-all-algorithms+)
    (:signature-algorithms +ssh-signature-all-algorithms+)
    (:ca-signature-algorithms +ssh-server-ca-signature-algorithm-names+)
    (:ciphers +ssh-all-ciphers+)
    (:macs +ssh-all-macs+)
    (:compressions +ssh-compressions+)))

(defun ssh-plibssh-supported-algorithms (kind)
  "Every name of KIND the loaded libssh can negotiate, in core order."
  (or (gethash kind *ssh-plibssh-algorithm-support*)
      (let ((code (ssh-plibssh-algorithm-code kind)))
        (setf (gethash kind *ssh-plibssh-algorithm-support*)
              (remove-if-not (lambda (name)
                               (ssh-plibssh-probe-option code name))
                             (ssh-plibssh-algorithm-names kind))))))

(defun ssh-plibssh-algorithm-supported-p (kind name)
  "Whether the loaded libssh can negotiate NAME as KIND."
  (not (null (member name (ssh-plibssh-supported-algorithms kind)
                     :test #'string=))))

(defun ssh-client-supported-algorithms (kind)
  "The client algorithm names of KIND the libssh transport can negotiate."
  (ssh-plibssh-supported-algorithms kind))

(defun ssh-server-supported-algorithms (kind)
  "The server algorithm names of KIND the libssh transport can negotiate.
The probe registry is shared with the client, but the server returns its own
preference tables filtered by what the library accepted."
  (if (member kind '(:host-key-algorithms :signature-algorithms
                     :ca-signature-algorithms))
      (let ((names (ecase kind
                     (:host-key-algorithms
                      +ssh-server-host-key-all-algorithms+)
                     (:signature-algorithms
                      +ssh-server-user-key-all-algorithms+)
                     (:ca-signature-algorithms
                      +ssh-server-ca-signature-algorithm-names+))))
        (remove-if-not (lambda (name)
                         (ssh-plibssh-algorithm-supported-p kind name))
                       names))
      (ssh-plibssh-supported-algorithms kind)))

(defun ssh-plibssh-unsupported-feature (kind name)
  "The facade feature NAME asks for, for the purpose of an error about KIND."
  (case kind
    (:kex (cond
            ((ssh-sntrup761-hybrid-p name) :sntrup)
            ((ssh-mlkem768-hybrid-p name) :mlkem)
            ((ssh-kex-post-quantum-p name) :post-quantum-kex)
            (t :kex)))
    ((:host-key-algorithms :signature-algorithms :ca-signature-algorithms)
     (if (ssh-mldsa44-ed25519-algorithm-p name) :mldsa kind))
    (:macs (cond
             ((ssh-mac-umac-p name) :umac)
             ((ssh-mac-legacy-p name) :legacy-macs)
             (t :macs)))
    (t kind)))

(defun ssh-plibssh-check-algorithms (supported kind names option)
  "Refuse NAMES when SUPPORTED lacks one, naming OPTION in the error.
An explicitly configured algorithm this libssh cannot negotiate is a real
mismatch; silently dropping it would widen or narrow the offer behind the
caller's back."
  (dolist (name names)
    (unless (member name supported :test #'string=)
      (error 'ssh-unsupported-feature
             :feature (ssh-plibssh-unsupported-feature kind name)
             :detail (format nil "~A by the libssh transport" option)))))

(defun ssh-plibssh-check-client-algorithms (kind names option)
  "Refuse a client algorithm selection the loaded libssh cannot negotiate."
  (ssh-plibssh-check-algorithms
   (ssh-client-supported-algorithms kind) kind names option))

(defun ssh-plibssh-check-server-algorithms (kind names option)
  "Refuse a server algorithm selection the loaded libssh cannot negotiate."
  (ssh-plibssh-check-algorithms
   (ssh-server-supported-algorithms kind) kind names option))

(defun ssh-client-transport-feature-supported-p (feature)
  "Client capabilities the libssh adapter implements by construction.
Algorithm-shaped features come from the facade's supported lists; these are
the role features that have no algorithm name."
  (not (null (member feature '(:agent-forward)))))

(defun ssh-server-transport-feature-supported-p (feature)
  "Server capabilities the libssh adapter implements by construction."
  (not (null (member feature '(:agent-forward)))))
