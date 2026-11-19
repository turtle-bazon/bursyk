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

(define-condition ssh-connection-error (ssh-error) ()
  (:report (lambda (condition stream)
             (format stream "SSH connection error~@[: ~A~]"
                     (ssh-error-detail condition)))))

(define-condition ssh-authentication-error (ssh-error) ()
  (:report (lambda (condition stream)
             (format stream "SSH authentication failed~@[: ~A~]"
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
   (keyword :initarg :keyword :initform nil :reader ssh-config-error-keyword))
  (:report (lambda (condition stream)
             (format stream "SSH config error~@[ in ~A~]~@[ at line ~D~]~
                             ~@[ (~A)~]~@[: ~A~]"
                     (ssh-config-error-path condition)
                     (ssh-config-error-line condition)
                     (ssh-config-error-keyword condition)
                     (ssh-error-detail condition)))))
