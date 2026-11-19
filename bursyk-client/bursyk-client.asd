(defsystem #:bursyk-client
  :description "Pure Common Lisp SSH-2 client over cl-pnet"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.2.0"
  :depends-on (#:cl-libbursyk
               #:cl-pnet
               #:cl-pnet-sockets
               #:balkort-resolve
               #:iterate
               #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "agent")
                             (:file "signer")
                             (:file "state")
                             (:file "transport")
                             (:file "channel")
                             (:file "client")))))
