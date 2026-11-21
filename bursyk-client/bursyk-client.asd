(defsystem #:bursyk-client
  :description "SSH client command line"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.2.31"
  :depends-on (#:cl-pnet-ssh #:cl-pnet #:cl-pnet-sockets #:cl-pnet-socks #:clingon
               #:cffi #:bordeaux-threads #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "package")
                             (:file "state")
                             (:file "posix" :if-feature (:not :win32))
                             (:file "windows" :if-feature :win32)
                             (:file "main"))))
  :build-operation "program-op"
  :build-pathname "../_build/burs"
  :entry-point "burs:main")
