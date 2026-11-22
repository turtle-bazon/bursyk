(asdf:defsystem #:cl-pnet-ssh
  :description "SSH-2 client and server"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.1.2"
  :depends-on ((:feature (:not :ssh-backend-ffi) #:cl-libbursyk)
               (:feature :ssh-backend-ffi #:cl-plibssh)
               #:burzay
               #:cl-pnet
               #:iterate
               #:uiop)
  ;; One backend per build: the pure stack is CL-LIBBURSYK alone, and the
  ;; feature swaps it for CL-PLIBSSH (which reuses the core internally).
  ;; CLIENT-CONFIG is the facade's own policy layer over ssh_config.
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "client-config"))))
  :in-order-to ((test-op (test-op #:cl-pnet-ssh-tests))))
