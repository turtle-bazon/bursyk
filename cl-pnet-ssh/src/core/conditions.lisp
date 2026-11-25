(in-package #:cl-pnet-ssh)

;;;; Conditions signalled by the client and by the shared protocol core.

(define-condition ssh-error (error)
  ((detail :initarg :detail :initform nil :reader ssh-error-detail))
  (:report (lambda (condition stream)
             (format stream "SSH error~@[: ~A~]" (ssh-error-detail condition)))))

(define-condition ssh-protocol-error (ssh-error) ()
  (:report (lambda (condition stream)
             (format stream "SSH protocol error~@[: ~A~]"
                     (ssh-error-detail condition)))))

(define-condition ssh-algorithm-negotiation-error (ssh-protocol-error)
  ((reason :initarg :reason :initform nil :reader ssh-negotiation-reason)
   (peer-offer :initarg :peer-offer :initform nil
               :reader ssh-negotiation-peer-offer))
  (:report (lambda (condition stream)
             (format stream "Unable to negotiate: ~A. Their offer: ~{~A~^,~}"
                     (ssh-negotiation-reason condition)
                     (ssh-negotiation-peer-offer condition)))))

(define-condition ssh-connection-error (ssh-error)
  ((kind :initarg :kind :initform nil :reader ssh-connection-error-kind)
   (host :initarg :host :initform nil :reader ssh-connection-error-host)
   (port :initarg :port :initform nil :reader ssh-connection-error-port)
   (reason :initarg :reason :initform nil :reader ssh-connection-error-reason)
   ;; The peer's proposal when a key exchange failed to agree on one.
   (peer-offer :initarg :peer-offer :initform nil
               :reader ssh-connection-error-peer-offer))
  (:report (lambda (condition stream)
             (format stream "SSH connection error~@[: ~A~]"
                     (ssh-error-detail condition)))))

(defun ssh-resolver-error-text (condition)
  "CONDITION's lookup failure in getaddrinfo's own words.

ssh prints a failed lookup through ssh_gai_strerror, so a missing name reads
\"Name or service not known\" rather than the resolver binding's internal
call description.  CL-PNET-SOCKETS signals a SIMPLE-ERROR whose second format
argument is the getaddrinfo code; other resolvers' conditions pass through
unchanged."
  (let* ((arguments (and (typep condition 'simple-error)
                         (simple-condition-format-arguments condition)))
         (code (and arguments (second arguments))))
    (case code
      (-1 "Bad value for ai_flags")
      (-2 "Name or service not known")
      (-3 "Temporary failure in name resolution")
      (-4 "Non-recoverable failure in name resolution")
      (-5 "No address associated with hostname")
      (-6 "ai_family not supported")
      (-8 "Servname not supported for ai_socktype")
      (-9 "ai_socktype not supported")
      (-10 "Memory allocation failure")
      (t (princ-to-string condition)))))

(define-condition ssh-unsupported-feature (ssh-connection-error)
  ((feature :initarg :feature :reader ssh-unsupported-feature-name))
  (:report (lambda (condition stream)
             (format stream "~A is not supported by this transport~@[: ~A~]"
                     (ssh-unsupported-feature-name condition)
                     (ssh-error-detail condition)))))

(define-condition ssh-authentication-error (ssh-error) ()
  (:report (lambda (condition stream)
             (format stream "SSH authentication failed~@[: ~A~]"
                     (ssh-error-detail condition)))))

(define-condition ssh-keygen-error (ssh-error) ()
  (:report (lambda (condition stream)
             (format stream "SSH key error~@[: ~A~]"
                     (ssh-error-detail condition)))))

(define-condition ssh-host-key-error (ssh-error)
  ((fingerprint :initarg :fingerprint :initform nil
                :reader ssh-host-key-error-fingerprint))
  (:report (lambda (condition stream)
             (format stream "SSH host key rejected~@[: ~A~]~@[ (fingerprint ~A)~]"
                     (ssh-error-detail condition)
                     (ssh-host-key-error-fingerprint condition)))))

(define-condition ssh-channel-error (ssh-error)
  ((channel :initarg :channel :initform nil :reader ssh-channel-error-channel))
  (:report (lambda (condition stream)
             (format stream "SSH channel error~@[: ~A~]"
                     (ssh-error-detail condition)))))

(define-condition ssh-config-error (ssh-error)
  ((path :initarg :path :initform nil :reader ssh-config-error-path)
   (line :initarg :line :initform nil :reader ssh-config-error-line)
   (keyword :initarg :keyword :initform nil :reader ssh-config-error-keyword)
   (bad-option :initarg :bad-option :initform nil
                :reader ssh-config-error-bad-option)
   (bare :initarg :bare :initform nil :reader ssh-config-error-bare)
   (fatal :initarg :fatal :initform nil :reader ssh-config-error-fatal))
  (:report (lambda (condition stream)
             (format stream "SSH config error~@[ in ~A~]~@[ at line ~D~]~
                             ~@[ (~A)~]~@[: ~A~]"
                     (ssh-config-error-path condition)
                     (ssh-config-error-line condition)
                     (ssh-config-error-keyword condition)
                     (ssh-error-detail condition)))))

(define-condition ssh-server-config-error (ssh-error)
  ((path :initarg :path :initform nil :reader ssh-server-config-error-path)
   (line :initarg :line :initform nil :reader ssh-server-config-error-line)
   (keyword :initarg :keyword :initform nil
            :reader ssh-server-config-error-keyword))
  (:report (lambda (condition stream)
             (format stream "sshd config error~@[ in ~A~]~@[ at line ~D~]~
                             ~@[ (~A)~]~@[: ~A~]"
                     (ssh-server-config-error-path condition)
                     (ssh-server-config-error-line condition)
                     (ssh-server-config-error-keyword condition)
                     (ssh-error-detail condition)))))

(define-condition ssh-revoked-keys-error (ssh-error)
  ((path :initarg :path :initform nil :reader ssh-revoked-keys-error-path))
  (:report (lambda (condition stream)
             (format stream "revoked keys error~@[ in ~A~]~@[: ~A~]"
                     (ssh-revoked-keys-error-path condition)
                     (ssh-error-detail condition)))))
