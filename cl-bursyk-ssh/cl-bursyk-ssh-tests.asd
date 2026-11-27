(asdf:defsystem #:cl-bursyk-ssh-tests
  :description "Internal protocol tests for the pure cl-bursyk-ssh transport"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  ;; These tests drive wire messages and transport state directly.  They are
  ;; not facade behaviour, so they live with the pure backend rather than in
  ;; the backend-agnostic CL-PNET-SSH-TESTS suite.  Only the pure transport's
  ;; own test system loads them.
  ;;
  ;; The shared fixtures (key generation, temporary directories, DNS and
  ;; certificate helpers) stay in CL-PNET-SSH-TESTS, which is why this system
  ;; depends on it.
  :depends-on (#:cl-bursyk-ssh #:cl-pnet-ssh-tests #:fiveam)
  :serial t
  :components ((:module "tests"
                :serial t
                :components ((:file "internals"))))
  :perform (test-op (op c)
             (declare (ignore op c))
             (uiop:symbol-call
              :fiveam :run!
              (find-symbol "LISP-INTERNALS" "CL-PNET-SSH-TESTS"))))
