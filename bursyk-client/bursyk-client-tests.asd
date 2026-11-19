(asdf:defsystem #:bursyk-client-tests
  :description "Tests for the SSH client command line"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :depends-on (#:bursyk-client #:fiveam)
  :serial t
  :components ((:module "tests"
                :serial t
                :components ((:file "unit"))))
  :perform (test-op (op c)
             (uiop:symbol-call :fiveam :run! :bursyk-client)))
