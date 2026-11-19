(defsystem #:bursyk-server
  :description "Pure Common Lisp SSH-2 server over cl-pnet"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.2.0"
  :depends-on (#:cl-libbursyk
               #:cl-pnet
               #:balkort-resolve
               #:iterate
               #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "state")
                             (:file "transport")
                             (:file "channel")
                             (:file "server")))))
