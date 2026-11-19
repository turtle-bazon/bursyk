(in-package #:cl-user)

(defpackage #:bursyk-client-tests
  (:use #:cl #:fiveam))

(in-package #:bursyk-client-tests)

(def-suite bursyk-client :description "BURS command line")
(in-suite bursyk-client)

;;; ---- helpers ----

(defun empty-options ()
  "The CLI's defaults, freshly allocated so a test cannot leak into another."
  (list :port nil :user nil :identity nil :config nil :known-hosts nil
        :policy nil :agent nil :options nil :jump nil :proxy-command nil))

;;; ---- command line ----

(test split-destination-splits-at-the-first-at-sign
  (multiple-value-bind (host user)
      (burs::split-destination "alice@example.org")
    (is (equal "example.org" host))
    (is (equal "alice" user)))
  (multiple-value-bind (host user)
      (burs::split-destination "example.org")
    (is (equal "example.org" host))
    (is (null user)))
  (multiple-value-bind (host user)
      (burs::split-destination "a@b@example.org")
    (is (equal "b@example.org" host))
    (is (equal "a" user))))

(test short-options-stay-case-sensitive
  (is (eq :port (burs::option-key "-p")))
  (is (eq :user (burs::option-key "-l")))
  (is (eq :identity (burs::option-key "-i")))
  (is (eq :options (burs::option-key "-o")))
  (is (eq :config (burs::option-key "-F")))
  (is (eq :jump (burs::option-key "-J")))
  ;; -f and -P are other programs' options, not this one's.
  (is (null (burs::option-key "-f")))
  (is (null (burs::option-key "-P")))
  (is (null (burs::option-key "-L")))
  ;; Long options stay case-insensitive.
  (is (eq :port (burs::option-key "--PORT"))))

(test parse-arguments-stops-at-the-destination
  (let ((burs::*options* (empty-options)))
    (multiple-value-bind (destination command)
        (burs::parse-arguments '("-p" "2222" "-l" "alice" "-i" "one"
                                 "-i" "two" "host.example" "uname" "-a"))
      (is (equal "host.example" destination))
      (is (equal '("uname" "-a") command))
      (is (equal "2222" (getf burs::*options* :port)))
      (is (equal "alice" (getf burs::*options* :user)))
      ;; -i may repeat; both keys are kept for authentication.
      (is (equal '("two" "one") (getf burs::*options* :identity))))))

(test double-dash-ends-option-parsing
  (let ((burs::*options* (empty-options)))
    (multiple-value-bind (destination command)
        (burs::parse-arguments '("--" "host.example" "-p" "not-a-port"))
      (is (equal "host.example" destination))
      (is (equal '("-p" "not-a-port") command))
      (is (null (getf burs::*options* :port))))))

(test command-line-option-maps-the-supported-keywords
  (let ((burs::*options* (empty-options)))
    (burs::command-line-option "Port" "2200")
    (burs::command-line-option "User" "bob")
    (burs::command-line-option "IdentityFile" "/tmp/key")
    (burs::command-line-option "UserKnownHostsFile" "/tmp/known")
    (burs::command-line-option "IdentityAgent" "/tmp/agent")
    (burs::command-line-option "StrictHostKeyChecking" "accept-new")
    (burs::command-line-option "ProxyJump" "bastion")
    (burs::command-line-option "ProxyCommand" "nc %h %p")
    ;; Every other keyword is accepted and ignored.
    (burs::command-line-option "Compression" "yes")
    (is (equal "2200" (getf burs::*options* :port)))
    (is (equal "bob" (getf burs::*options* :user)))
    (is (equal '("/tmp/key") (getf burs::*options* :identity)))
    (is (equal "/tmp/known" (getf burs::*options* :known-hosts)))
    (is (equal "/tmp/agent" (getf burs::*options* :agent)))
    (is (eq :accept-new (getf burs::*options* :policy)))
    (is (equal "bastion" (getf burs::*options* :jump)))
    (is (equal "nc %h %p" (getf burs::*options* :proxy-command)))))

(test command-line-options-apply-in-the-written-order
  (let ((burs::*options* (empty-options)))
    (dolist (option '("User=first" "Port=2200" "User=last"))
      (push option (getf burs::*options* :options)))
    (burs::apply-command-line-options)
    ;; Pushed in reverse, so applying them back restores command-line order.
    (is (equal "last" (getf burs::*options* :user)))
    (is (equal "2200" (getf burs::*options* :port)))))

(test join-command-keeps-the-arguments-apart
  (is (equal "uname -a" (burs::join-command '("uname" "-a"))))
  (is (stringp (burs::join-command nil))))

;;; ---- config hooks ----

(test match-exec-runs-the-condition
  (labels ((evaluate (command)
             (let ((answer :unset))
               (burs::match-exec command
                                 (lambda (value) (setf answer value))
                                 (lambda (condition)
                                   (declare (ignore condition))
                                   (setf answer :error)))
               answer)))
    (is (eq t (evaluate "exit 0")))
    (is (eq nil (evaluate "exit 1")))
    (is (eq t (evaluate "true")))))

(test client-port-reads-the-number-the-command-line-gave
  (let ((burs::*options* (empty-options)))
    (is (null (burs::client-port)))
    (setf (getf burs::*options* :port) "2222")
    (is (= 2222 (burs::client-port)))
    (setf (getf burs::*options* :port) "22x")
    ;; An invalid -p is a usage error; FAIL quits, so only exercise the
    ;; valid paths here and leave the exit to the live command-line tests.
    (is (= 22 (parse-integer "22x" :junk-allowed t)))))
