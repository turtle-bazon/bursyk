(asdf:defsystem #:cl-pnet-ssh-tests
  :description "Tests for cl-pnet-ssh"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :depends-on (#:cl-pnet-ssh #:cl-pnet #:cl-pnet-dns #:cl-pnet-dns-plain #:fiveam)
  :serial t
  :components ((:module "tests"
                :serial t
                :components ((:file "unit"))))
  :perform (test-op (op c)
             (uiop:symbol-call :fiveam :run! :cl-pnet-ssh)))
