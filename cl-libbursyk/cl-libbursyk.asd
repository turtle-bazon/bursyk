(defsystem #:cl-libbursyk
  :description "Pure Common Lisp SSH-2 client and server"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.1.42"
  :depends-on (#:ironclad-unsafe
               #:cl-base64
               #:babel
               #:cl-pnet
               #:cl-pnet-sockets
               #:burzay
               #:iterate
               #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "packages")
                             (:file "conditions")
                             ;; Role-neutral: a client and a server both
                             ;; report milestones through the same hook.
                             (:file "log")
                             (:file "config")
                             ;; Algorithm names, the lists this build offers,
                             ;; and the + / - / ^ syntax sshd and ssh share.
                             ;; Early, because sshd_config is validated as it
                             ;; is read.
                             (:file "algorithms")
                             ;; sshd_config, parsed with the same tokenizer
                             ;; and the same Include rules as ssh_config.
                             (:file "server-config")
                             ;; Role-neutral: shared by the client and the server.
                             (:file "wire")
                             (:file "crypto")
                             (:file "packet")
                             (:file "keys")
                             (:file "known-hosts")
                             ;; RevokedKeys: a text key list or a binary KRL.
                             (:file "revoked-keys")
                             (:file "server-policy")
                             (:file "kex")
                             ;; The agent protocol is role-neutral: both roles
                             ;; reach an agent, and the FFI backend exposes the
                             ;; same helpers as the pure one.
                             (:file "agent")
                             ;; Both ends of the protocol.  A build with
                             ;; :ssh-backend-ffi gets these from CL-PLIBSSH
                             ;; instead, so the pure roles are not compiled.
                             ;; Signers describe a key; they are useful to
                             ;; either transport and do not name a socket.
                             (:file "client-signer")
                             (:file "client-state"
                              :if-feature (:not :ssh-backend-ffi))
                             (:file "client-transport"
                              :if-feature (:not :ssh-backend-ffi))
                             (:file "client-proxy"
                              :if-feature (:not :ssh-backend-ffi))
                             (:file "client-channel"
                              :if-feature (:not :ssh-backend-ffi))
                             (:file "client"
                              :if-feature (:not :ssh-backend-ffi))
                             (:file "server-state"
                              :if-feature (:not :ssh-backend-ffi))
                             (:file "server-transport"
                              :if-feature (:not :ssh-backend-ffi))
                             (:file "server-channel"
                              :if-feature (:not :ssh-backend-ffi))
                             (:file "server"
                              :if-feature (:not :ssh-backend-ffi))))))
