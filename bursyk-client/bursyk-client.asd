(defsystem #:bursyk-client
  :description "SSH client command line"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.3.0"
  :depends-on (#:cl-pnet-ssh #:cl-pnet #:cl-pnet-sockets #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "main"))))
  :build-operation "program-op"
  :build-pathname "../_build/burs"
  :entry-point "burs:main")
