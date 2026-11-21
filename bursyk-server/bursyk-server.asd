(defsystem #:bursyk-server
  :description "SSH server command line"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.2.61"
  :depends-on (#:cl-pnet-ssh #:cl-pnet #:cl-pnet-sockets #:cffi
               #:bordeaux-threads #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "packages")
                             (:file "common")
                             (:file "child" :if-feature (:not :win32))
                             (:file "child-windows" :if-feature :win32)
                             (:file "win32" :if-feature :win32)
                             (:file "main"))))
  :build-operation "program-op"
  :build-pathname "../_build/bursyk-server"
  :entry-point "bursyk-server:main")
