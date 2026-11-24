(in-package #:cl-pnet-ssh)

;;;; What the selected transport can do.
;;;;
;;;; A build has exactly one transport.  The transport knows which algorithm
;;;; names the library underneath it can negotiate, so this file asks for
;;;; those names instead of testing a backend or hard-coding a version.  The
;;;; facade predicates and the command-line -Q answers all read this same
;;;; report, which keeps the pure and libssh builds honest about differences
;;;; they really have.

(defparameter +ssh-client-features+
  '(:remote-forward :streamlocal-forward :x11-forward
    :hostbased-authentication :version-addendum :agent-forward
    :compression :post-quantum-kex :sntrup :mlkem :umac :legacy-macs :mldsa)
  "Every client capability the facade can report.
The algorithm-shaped entries are derived from SSH-CLIENT-SUPPORTED-
ALGORITHMS; the rest come from the transport itself.")

(defparameter +ssh-server-features+
  '(:remote-forward :streamlocal-forward :x11-forward :agent-forward
    :compression :post-quantum-kex :sntrup :mlkem :umac :legacy-macs :mldsa)
  "Every server capability the facade can report.")

(defun ssh-client-capabilities ()
  "The selected client transport's enabled capabilities.

The result is a property list.  Algorithm kinds map to the names this
transport can actually negotiate, in the build's preference order, and
:FEATURES maps every entry of +SSH-CLIENT-FEATURES+ to a boolean.  A caller
that wants to show, offer or validate an algorithm asks here rather than
compiling in a backend's limits."
  (list :kex (ssh-client-supported-algorithms :kex)
        :host-key-algorithms
        (ssh-client-supported-algorithms :host-key-algorithms)
        :signature-algorithms
        (ssh-client-supported-algorithms :signature-algorithms)
        :ca-signature-algorithms
        (ssh-client-supported-algorithms :ca-signature-algorithms)
        :ciphers (ssh-client-supported-algorithms :ciphers)
        :macs (ssh-client-supported-algorithms :macs)
        :compressions (ssh-client-supported-algorithms :compressions)
        :authentication-methods (ssh-client-supported-authentication-methods)
        :features
        (loop for feature in +ssh-client-features+
              append (list feature (ssh-client-feature-supported-p feature)))))

(defun ssh-server-capabilities ()
  "The selected server transport's enabled capabilities.
The server-side counterpart of SSH-CLIENT-CAPABILITIES."
  (list :kex (ssh-server-supported-algorithms :kex)
        :host-key-algorithms
        (ssh-server-supported-algorithms :host-key-algorithms)
        :signature-algorithms
        (ssh-server-supported-algorithms :signature-algorithms)
        :ca-signature-algorithms
        (ssh-server-supported-algorithms :ca-signature-algorithms)
        :ciphers (ssh-server-supported-algorithms :ciphers)
        :macs (ssh-server-supported-algorithms :macs)
        :compressions (ssh-server-supported-algorithms :compressions)
        :features
        (loop for feature in +ssh-server-features+
              append (list feature (ssh-server-feature-supported-p feature)))))

(defun ssh-client-default-algorithms (kind)
  "The names of KIND the client offers when no configuration overrides them.

This is the core's OpenSSH default order filtered to what the transport can
negotiate.  A configuration directive that appends or removes names starts
from this list, so a libssh without sntrup does not fail merely because its
effective default still mentioned one."
  (let ((names (ecase kind
                 (:kex +ssh-kex-default-algorithms+)
                 (:host-key-algorithms +ssh-host-key-algorithms+)
                 (:signature-algorithms +ssh-signature-algorithms+)
                 (:ca-signature-algorithms
                  +ssh-server-ca-signature-algorithms+)
                 (:ciphers +ssh-ciphers+)
                 (:macs +ssh-macs+)
                 (:compressions +ssh-compressions+))))
    (remove-if-not (lambda (name)
                     (member name (ssh-client-supported-algorithms kind)
                             :test #'string=))
                   names)))

(defun ssh-server-default-algorithms (kind)
  "The names of KIND the server offers when no configuration overrides them."
  (let ((names (ecase kind
                 (:kex +ssh-server-default-kex-algorithms+)
                 (:host-key-algorithms +ssh-server-host-key-preference+)
                 (:signature-algorithms +ssh-server-user-key-algorithms+)
                 (:ca-signature-algorithms
                  +ssh-server-ca-signature-algorithms+)
                 (:ciphers +ssh-ciphers+)
                 (:macs +ssh-macs+)
                 (:compressions +ssh-compressions+))))
    (remove-if-not (lambda (name)
                     (member name (ssh-server-supported-algorithms kind)
                             :test #'string=))
                   names)))

(defun ssh-client-feature-supported-p (feature)
  "Whether the selected client transport can honour FEATURE.

Algorithm-shaped features are answered from the transport's supported
algorithm lists, so a newer libssh that learns one of them is enabled here
without changing this function.  Everything else is the transport's own
answer."
  (case feature
    (:post-quantum-kex
     (some #'ssh-kex-post-quantum-p
           (ssh-client-supported-algorithms :kex)))
    (:sntrup
     (some #'ssh-sntrup761-hybrid-p
           (ssh-client-supported-algorithms :kex)))
    (:mlkem
     (some #'ssh-mlkem768-hybrid-p
           (ssh-client-supported-algorithms :kex)))
    (:mldsa
     (some #'ssh-mldsa44-ed25519-algorithm-p
           (append (ssh-client-supported-algorithms :host-key-algorithms)
                   (ssh-client-supported-algorithms :signature-algorithms))))
    (:umac
     (not (null (some #'ssh-mac-umac-p
                      (ssh-client-supported-algorithms :macs)))))
    (:legacy-macs
     (not (null (some #'ssh-mac-legacy-p
                      (ssh-client-supported-algorithms :macs)))))
    (:compression
     (not (null (member "zlib@openssh.com"
                        (ssh-client-supported-algorithms :compressions)
                        :test #'string=))))
    (otherwise
     (ssh-client-transport-feature-supported-p feature))))

(defun ssh-server-feature-supported-p (feature)
  "Whether the selected server transport can honour FEATURE."
  (case feature
    (:post-quantum-kex
     (some #'ssh-kex-post-quantum-p
           (ssh-server-supported-algorithms :kex)))
    (:sntrup
     (some #'ssh-sntrup761-hybrid-p
           (ssh-server-supported-algorithms :kex)))
    (:mlkem
     (some #'ssh-mlkem768-hybrid-p
           (ssh-server-supported-algorithms :kex)))
    (:mldsa
     (some #'ssh-mldsa44-ed25519-algorithm-p
           (append (ssh-server-supported-algorithms :host-key-algorithms)
                   (ssh-server-supported-algorithms :signature-algorithms))))
    (:umac
     (not (null (some #'ssh-mac-umac-p
                      (ssh-server-supported-algorithms :macs)))))
    (:legacy-macs
     (not (null (some #'ssh-mac-legacy-p
                      (ssh-server-supported-algorithms :macs)))))
    (:compression
     (not (null (member "zlib@openssh.com"
                        (ssh-server-supported-algorithms :compressions)
                        :test #'string=))))
    (otherwise
     (ssh-server-transport-feature-supported-p feature))))
