(defsystem #:cl-ssh-core
  :description "Backend-neutral SSH-2 protocol core shared by the pure and libssh transports"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.1.0"
  :depends-on (#:ironclad-unsafe
               #:cl-base64
               #:babel
               #:cl-newzlib
               #:cl-pnet
               #:cl-pnet-sockets
               #:burzay
               #:iterate
               #:uiop)
  ;; Nothing in this system knows which transport will carry the protocol.
  ;; Both CL-LIBBURSKYK and CL-PLIBSSH depend on it and add their own role
  ;; implementations, so no file here is selected by the backend feature.
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "packages")
                             (:file "conditions")
                             (:file "log")
                             (:file "config")
                             (:file "algorithms")
                             (:file "server-config")
                             (:file "wire")
                             (:file "crypto")
                             (:file "x11")
                             (:file "umac")
                             (:file "packet")
                             (:file "keys")
                             (:file "known-hosts")
                             (:file "revoked-keys")
                             (:file "server-policy")
                             (:file "kex")
                             (:file "agent")
                             (:file "channel-fd")
                             (:file "client-signer")
                             (:file "client-dns")
                             ;; Client policy is role-neutral: host key
                             ;; verification, SSHFP trust, the version
                             ;; addendum, weak-crypto notices, chaff and
                             ;; ChannelTimeout.  It reads the slots each
                             ;; backend defines under the same names.
                             (:file "client-policy")))))
