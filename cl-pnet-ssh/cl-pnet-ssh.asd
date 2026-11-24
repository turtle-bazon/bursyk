(asdf:defsystem #:cl-pnet-ssh
  :description "SSH-2 client and server"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.1.2"
  ;; One backend per build.  The pure stack is CL-LIBBURSYK, a whole SSH
  ;; implementation.  CL-PLIBSSH is only the CFFI binding layer, so the role
  ;; code that turns libssh into this API lives below, in src/libssh, and is
  ;; compiled only for that backend.
  :depends-on (#:cl-ssh-core
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
                                            (:file "client")
                                            (:file "channel")
                                            (:file "server")))
                             (:file "backend")
                             (:file "client-config"))))
  :in-order-to ((test-op (test-op #:cl-pnet-ssh-tests))))
