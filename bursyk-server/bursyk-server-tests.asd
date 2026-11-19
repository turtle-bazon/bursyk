(asdf:defsystem #:bursyk-server-tests
  :description "Tests for the SSH server command line"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :depends-on (#:bursyk-server #:cl-pnet-sockets #:fiveam)
  :serial t
  :components ((:module "tests"
                :serial t
                :components ((:file "unit"))))
  :perform (test-op (op c)
             (uiop:symbol-call :fiveam :run! :bursyk-server)))
