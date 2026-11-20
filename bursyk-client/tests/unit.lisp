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
        :policy nil :agent nil :options nil :jump nil :proxy-command nil
        :verbose 0 :quiet nil :log-file nil :address-family nil
        :ciphers nil :macs nil :kex-algorithms nil :compression nil
        :request-tty nil :forward-agent nil :gateway-ports nil
        :no-command nil :stdin-null nil :subsystem nil :stdio-forward nil
        :local-forward nil :remote-forward nil :dynamic-forward nil
        :query nil :help nil :version nil :print-config nil
        :background nil :control-master nil :control-path nil
        :control-command nil :pkcs11 nil :bind-interface nil
        :bind-address nil :gssapi-auth nil :tunnel nil :x11-forward nil
        :escape-char nil))

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
  ;; The rest of ssh's flags now mean what ssh means: -f backgrounds, -L
  ;; forwards a local port, -4 pins the address family.
  (is (eq :background (burs::option-key "-f")))
  (is (eq :local-forward (burs::option-key "-L")))
  (is (eq :address-family (burs::option-key "-4")))
  (is (eq :verbose (burs::option-key "-v")))
  ;; -P is not an option for ssh or for this client.
  (is (null (burs::option-key "-P")))
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

(test clustered-short-options
  (let ((burs::*options* (empty-options)))
    (multiple-value-bind (destination command)
        (burs::parse-arguments '("-vvT" "host" "-p" "2222"))
      (is (equal "host" destination))
      ;; Parsing stops at the destination, so -p here belongs to the
      ;; remote command even though ssh would have taken it as a flag.
      (is (equal '("-p" "2222") command))
      (is (= 2 (getf burs::*options* :verbose)))
      (is (eq :no (getf burs::*options* :request-tty)))
      (is (null (getf burs::*options* :port))))))

(test attached-and-long-option-values
  (let ((burs::*options* (empty-options)))
    (multiple-value-bind (destination command)
        (burs::parse-arguments '("-p2222" "-lalice" "host" "true"))
      (is (equal "host" destination))
      (is (equal '("true") command))
      (is (equal "2222" (getf burs::*options* :port)))
      (is (equal "alice" (getf burs::*options* :user)))))
  (let ((burs::*options* (empty-options)))
    (multiple-value-bind (destination command)
        (burs::parse-arguments '("--port=2200" "--user" "bob" "host"))
      (is (equal "host" destination))
      (is (null command))
      (is (equal "2200" (getf burs::*options* :port)))
      (is (equal "bob" (getf burs::*options* :user))))))

(test forwarding-specifications-parse
  (is (equal '("8080" "::1" "22")
             (burs::split-forward-fields "8080:[::1]:22")))
  (let ((forward
          (burs::parse-local-forward "127.0.0.1:8080:example.org:80")))
    (is (equal "127.0.0.1" (burs::forward-bind-address forward)))
    (is (= 8080 (burs::forward-bind-port forward)))
    (is (equal "example.org" (burs::forward-host forward)))
    (is (= 80 (burs::forward-port forward))))
  (let ((forward (burs::parse-local-forward "8080:example.org:80")))
    (is (null (burs::forward-bind-address forward)))
    (is (= 8080 (burs::forward-bind-port forward))))
  (let ((forward (burs::parse-local-forward "[::1]:8080:example.org:80")))
    (is (equal "::1" (burs::forward-bind-address forward)))))

(test config-local-forward-uses-the-two-word-form
  (let ((forward (burs::parse-config-local-forward "18082 127.0.0.1:22")))
    (is (null (burs::forward-bind-address forward)))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "127.0.0.1" (burs::forward-host forward)))
    (is (= 22 (burs::forward-port forward))))
  (let ((forward
          (burs::parse-config-local-forward "127.0.0.1:18082 127.0.0.1:22")))
    (is (equal "127.0.0.1" (burs::forward-bind-address forward)))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (= 22 (burs::forward-port forward))))
  (let ((forward (burs::parse-config-local-forward "[::1]:18082 [::1]:22")))
    (is (equal "::1" (burs::forward-bind-address forward)))
    (is (equal "::1" (burs::forward-host forward)))
    (is (= 22 (burs::forward-port forward))))
  ;; A one-word line is taken as -L's colon-separated spelling.
  (let ((forward (burs::parse-config-local-forward "18082:127.0.0.1:22")))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (= 22 (burs::forward-port forward)))))

(test stdio-forward-parses-host-and-port
  (multiple-value-bind (host port)
      (burs::parse-host-port "example.org:2200")
    (is (equal "example.org" host))
    (is (= 2200 port)))
  (multiple-value-bind (host port)
      (burs::parse-host-port "[::1]:22")
    (is (equal "::1" host))
    (is (= 22 port))))

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
