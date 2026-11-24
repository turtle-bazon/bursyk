;;;; CL-PNET-SSH is split into two systems so the protocol core can be
;;;; shared without a dependency cycle:
;;;;
;;;;   CL-PNET-SSH/CORE  backend-neutral SSH-2 protocol code
;;;;   CL-PNET-SSH       the facade, plus exactly one transport
;;;;
;;;; The pure transport (CL-LIBBURSKY) needs the core and the facade needs
;;;; the pure transport, so the core must be a separate system even though
;;;; it lives in this project.  Both systems use the same CL-PNET-SSH
;;;; package; there is no separate package or project for the core.

(asdf:defsystem #:cl-pnet-ssh/core
  :description "Backend-neutral SSH-2 protocol core shared by the pure and libssh transports"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.1.4"
  :depends-on (#:ironclad-unsafe
               #:cl-base64
               #:babel
               #:cl-newzlib
               #:cl-pnet
               #:cl-pnet-sockets
               #:burzay
               #:iterate
               #:uiop)
  ;; Nothing here knows which transport will carry the protocol.  Both
  ;; CL-LIBBURSKY and the libssh adapter add their own role implementations,
  ;; so no file here is selected by the backend feature.
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:module "core"
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
                                            (:file "keygen")
                                            (:file "known-hosts")
                                            (:file "revoked-keys")
                                            (:file "server-policy")
                                            (:file "kex")
                                            (:file "agent")
                                            (:file "channel-fd")
                                            (:file "client-signer")
                                            (:file "capabilities")
                                            (:file "client-dns")
                                            ;; Client policy is role-neutral:
                                            ;; host key verification, SSHFP
                                            ;; trust, the version addendum,
                                            ;; weak-crypto notices, chaff and
                                            ;; ChannelTimeout.  It reads the
                                            ;; slots each backend defines under
                                            ;; the same names.
                                            (:file "client-policy")))))))

(asdf:defsystem #:cl-pnet-ssh
  :description "SSH-2 client and server"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.2.0"
  ;; One backend per build.  The pure stack is CL-LIBBURSKY, a whole SSH
  ;; implementation.  CL-PLIBSSH is only the CFFI binding layer, so the role
  ;; code that turns libssh into this API lives below, in src/libssh, and is
  ;; compiled only for that backend.
  :depends-on (#:cl-pnet-ssh/core
               (:feature (:not :ssh-backend-ffi) #:cl-libbursyk)
               (:feature :ssh-backend-ffi #:cl-plibssh)
               #:burzay
               #:cl-pnet
               #:iterate
               #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:module "libssh"
                               :if-feature :ssh-backend-ffi
                               :serial t
                               :components ((:file "bindings")
                                            (:file "util")
                                            (:file "capabilities")
                                            (:file "client")
                                            (:file "channel")
                                            (:file "server")))
                             (:file "backend")
                             (:file "client-config"))))
  :in-order-to ((test-op (test-op #:cl-pnet-ssh-tests))))
