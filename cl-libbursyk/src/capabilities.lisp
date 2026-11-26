(in-package #:cl-pnet-ssh)

;;;; The pure transport implements the whole protocol core, so its supported
;;;; algorithm lists are the core's tables.  The facade derives the feature
;;;; predicates and capability report from these functions.

(defun ssh-client-supported-algorithms (kind)
  "The client algorithm names of KIND the pure transport can negotiate."
  (ecase kind
    (:kex +ssh-kex-real-algorithms+)
    (:host-key-algorithms +ssh-host-key-all-algorithms+)
    (:signature-algorithms +ssh-signature-all-algorithms+)
    (:ca-signature-algorithms +ssh-server-ca-signature-algorithm-names+)
    (:ciphers +ssh-all-ciphers+)
    (:macs +ssh-all-macs+)
    (:compressions +ssh-compressions+)))

(defun ssh-server-supported-algorithms (kind)
  "The server algorithm names of KIND the pure transport can negotiate."
  (ecase kind
    (:kex +ssh-kex-real-algorithms+)
    (:host-key-algorithms +ssh-server-host-key-all-algorithms+)
    (:signature-algorithms +ssh-server-user-key-all-algorithms+)
    (:ca-signature-algorithms +ssh-server-ca-signature-algorithm-names+)
    (:ciphers +ssh-all-ciphers+)
    (:macs +ssh-all-macs+)
    (:compressions +ssh-compressions+)))

(defun ssh-client-transport-feature-supported-p (feature)
  "The client capabilities the pure transport implements by construction.
The algorithm-shaped features are answered by the facade from the lists
above; these are the role features that have no algorithm name."
  (not (null (member feature '(:remote-forward :streamlocal-forward
                               :remote-dynamic-forward
                               :x11-forward :hostbased-authentication
                               :version-addendum :agent-forward)))))

(defun ssh-server-transport-feature-supported-p (feature)
  "The server capabilities the pure transport implements by construction."
  (not (null (member feature '(:remote-forward :streamlocal-forward
                               :x11-forward :agent-forward)))))
