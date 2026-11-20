(defsystem #:cl-plibssh
  :description "libssh CFFI bindings"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.1.9"
  :depends-on (#:cffi
               #:cl-libbursyk
               #:cl-pnet
               #:cl-pnet-sockets
               #:burzay
               #:iterate
               #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "ffi")
                             (:file "util")
                             (:file "client")
                             (:file "channel")
                             (:file "server")))))
