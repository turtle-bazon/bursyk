(defsystem #:bursyk-server
  :description "SSH server command line"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.3.0"
  :depends-on (#:cl-pnet-ssh #:cl-pnet #:cl-pnet-sockets #:cffi #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "packages")
                             (:file "child")
                             (:file "main"))))
  :build-operation "program-op"
  :build-pathname "../_build/bursyk-server"
  :entry-point "bursyk-server:main")
