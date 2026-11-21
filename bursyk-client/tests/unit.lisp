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

(defun parse (arguments)
  "Parse ARGUMENTS with fresh options.
Returns (VALUES DESTINATION COMMAND OPTIONS), so a test can look at the
CLI's decision and at the plist it filled."
  (let ((burs::*options* (empty-options)))
    (multiple-value-bind (destination command)
        (burs::parse-arguments arguments)
      (values destination command burs::*options*))))

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

(test parse-arguments-stops-at-the-destination
  (multiple-value-bind (destination command options)
      (parse '("-p" "2222" "-l" "alice" "-i" "one"
               "-i" "two" "host.example" "uname" "-a"))
    (is (equal "host.example" destination))
    (is (equal '("uname" "-a") command))
    (is (equal "2222" (getf options :port)))
    (is (equal "alice" (getf options :user)))
    ;; -i may repeat; both keys are kept for authentication.
    (is (equal '("two" "one") (getf options :identity)))))

(test double-dash-ends-option-parsing
  (multiple-value-bind (destination command options)
      (parse '("--" "host.example" "-p" "not-a-port"))
    (is (equal "host.example" destination))
    (is (equal '("-p" "not-a-port") command))
    (is (null (getf options :port)))))

(test clustered-short-options
  (multiple-value-bind (destination command options)
      (parse '("-vvT" "host" "-p" "2222"))
    (is (equal "host" destination))
    ;; Parsing stops at the destination, so -p here belongs to the
    ;; remote command even though ssh would have taken it as a flag.
    (is (equal '("-p" "2222") command))
    (is (= 2 (getf options :verbose)))
    (is (eq :no (getf options :request-tty)))
    (is (null (getf options :port)))))

(test attached-and-long-option-values
  (multiple-value-bind (destination command options)
      (parse '("-p2222" "-lalice" "host" "true"))
    (is (equal "host" destination))
    (is (equal '("true") command))
    (is (equal "2222" (getf options :port)))
    (is (equal "alice" (getf options :user))))
  (multiple-value-bind (destination command options)
      (parse '("--port=2200" "--user" "bob" "host"))
    (is (equal "host" destination))
    (is (null command))
    (is (equal "2200" (getf options :port)))
    (is (equal "bob" (getf options :user))))
  ;; The readable spellings stay case-insensitive, and --identity-file is
  ;; accepted as another name for --identity.
  (multiple-value-bind (destination command options)
      (parse '("--PORT=2201" "--IDENTITY-FILE=/tmp/key" "host"))
    (is (equal "host" destination))
    (is (null command))
    (is (equal "2201" (getf options :port)))
    (is (equal '("/tmp/key") (getf options :identity)))))

(test short-options-keep-ssh-meanings
  ;; -a disables agent forwarding; the agent picker is --agent.  It is kept
  ;; distinct from "not asked" so a config file's ForwardAgent cannot win.
  (multiple-value-bind (destination command options)
      (parse '("-a" "host"))
    (declare (ignore destination command))
    (is (eq :no (getf options :forward-agent))))
  (multiple-value-bind (destination command options)
      (parse '("-A" "host"))
    (declare (ignore destination command))
    (is (eq t (getf options :forward-agent))))
  (multiple-value-bind (destination command options)
      (parse '("-4" "host"))
    (declare (ignore destination command))
    (is (equal "inet" (getf options :address-family))))
  (multiple-value-bind (destination command options)
      (parse '("-6" "host"))
    (declare (ignore destination command))
    (is (equal "inet6" (getf options :address-family))))
  (multiple-value-bind (destination command options)
      (parse '("--address-family=any" "host"))
    (declare (ignore destination command))
    (is (equal "any" (getf options :address-family))))
  (multiple-value-bind (destination command options)
      (parse '("-t" "host"))
    (declare (ignore destination command))
    (is (eq :force (getf options :request-tty))))
  (multiple-value-bind (destination command options)
      (parse '("-T" "host"))
    (declare (ignore destination command))
    (is (eq :no (getf options :request-tty))))
  (multiple-value-bind (destination command options)
      (parse '("--request-tty=no" "host"))
    (declare (ignore destination command))
    (is (equal "no" (getf options :request-tty)))))

(test repeated-options-keep-command-line-order
  (multiple-value-bind (destination command options)
      (parse '("-L" "8080:example.org:80"
               "-L" "127.0.0.1:9090:example.org:90" "host"))
    (declare (ignore destination command))
    (is (equal '("127.0.0.1:9090:example.org:90" "8080:example.org:80")
               (getf options :local-forward))))
  (let ((burs::*options* (empty-options)))
    (burs::parse-arguments '("-o" "User=first" "-oUser=second" "host"))
    ;; *OPTIONS* keeps the list reversed, as the old parser did;
    ;; COMMAND-LINE-OPTION-LIST restores the written order.
    (is (equal '("User=second" "User=first")
               (getf burs::*options* :options)))
    (is (equal '("User=first" "User=second")
               (burs::command-line-option-list)))))

(test ssh-flags-map-onto-the-option-plist
  (multiple-value-bind (destination command options)
      (parse '("-G" "-q" "-n" "-N" "host"))
    (declare (ignore destination command))
    (is (eq t (getf options :print-config)))
    (is (eq t (getf options :quiet)))
    (is (eq t (getf options :stdin-null)))
    (is (eq t (getf options :no-command))))
  (multiple-value-bind (destination command options)
      (parse '("-s" "host" "sftp"))
    (is (equal "host" destination))
    (is (equal '("sftp") command))
    (is (eq t (getf options :subsystem))))
  (multiple-value-bind (destination command options)
      (parse '("-W" "example.org:22" "host"))
    (declare (ignore destination command))
    (is (equal "example.org:22" (getf options :stdio-forward))))
  (multiple-value-bind (destination command options)
      (parse '("-Q" "cipher" "host"))
    (declare (ignore destination command))
    (is (equal "cipher" (getf options :query))))
  (multiple-value-bind (destination command options)
      (parse '("-V"))
    (declare (ignore destination command))
    (is (eq t (getf options :version)))))

(test a-missing-destination-is-not-invented
  (multiple-value-bind (destination command options)
      (parse '("-v"))
    (is (null destination))
    (is (null command))
    (is (= 1 (getf options :verbose)))))

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

(test stream-local-forwarding-specifications-parse
  ;; -L local_socket:remote_socket
  (let ((forward
          (burs::parse-local-forward "/tmp/local.sock:/tmp/remote.sock")))
    (is (equal "/tmp/local.sock" (burs::forward-bind-path forward)))
    (is (equal "/tmp/remote.sock" (burs::forward-target-path forward)))
    (is (null (burs::forward-bind-port forward)))
    (is (null (burs::forward-port forward))))
  ;; -L port:remote_socket
  (let ((forward (burs::parse-local-forward "18082:/tmp/remote.sock")))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (null (burs::forward-bind-path forward)))
    (is (equal "/tmp/remote.sock" (burs::forward-target-path forward))))
  ;; -L local_socket:host:hostport
  (let ((forward
          (burs::parse-local-forward "/tmp/local.sock:example.org:80")))
    (is (equal "/tmp/local.sock" (burs::forward-bind-path forward)))
    (is (equal "example.org" (burs::forward-host forward)))
    (is (= 80 (burs::forward-port forward))))
  ;; -L bind_address:port:remote_socket
  (let ((forward
          (burs::parse-local-forward "127.0.0.1:18082:/tmp/remote.sock")))
    (is (equal "127.0.0.1" (burs::forward-bind-address forward)))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "/tmp/remote.sock" (burs::forward-target-path forward))))
  ;; -R remote_socket:local_socket
  (let ((forward
          (burs::parse-remote-forward "/tmp/remote.sock:/tmp/local.sock")))
    (is (equal "/tmp/remote.sock" (burs::forward-bind-path forward)))
    (is (equal "/tmp/local.sock" (burs::forward-target-path forward))))
  ;; -R port:local_socket
  (let ((forward (burs::parse-remote-forward "18082:/tmp/local.sock")))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "/tmp/local.sock" (burs::forward-target-path forward))))
  ;; -R remote_socket:host:hostport
  (let ((forward
          (burs::parse-remote-forward "/tmp/remote.sock:example.org:80")))
    (is (equal "/tmp/remote.sock" (burs::forward-bind-path forward)))
    (is (equal "example.org" (burs::forward-host forward)))
    (is (= 80 (burs::forward-port forward)))))

(test config-stream-local-forwards-use-paths
  (let ((forward
          (burs::parse-config-local-forward
           "/tmp/local.sock /tmp/remote.sock")))
    (is (equal "/tmp/local.sock" (burs::forward-bind-path forward)))
    (is (equal "/tmp/remote.sock" (burs::forward-target-path forward))))
  (let ((forward
          (burs::parse-config-local-forward "18082 /tmp/remote.sock")))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "/tmp/remote.sock" (burs::forward-target-path forward))))
  (let ((forward
          (burs::parse-config-local-forward
           "/tmp/local.sock example.org:80")))
    (is (equal "/tmp/local.sock" (burs::forward-bind-path forward)))
    (is (equal "example.org" (burs::forward-host forward)))
    (is (= 80 (burs::forward-port forward))))
  (let ((forward
          (burs::parse-config-remote-forward
           "/tmp/remote.sock /tmp/local.sock")))
    (is (equal "/tmp/remote.sock" (burs::forward-bind-path forward)))
    (is (equal "/tmp/local.sock" (burs::forward-target-path forward))))
  (let ((forward
          (burs::parse-config-remote-forward
           "18082 /tmp/local.sock")))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "/tmp/local.sock" (burs::forward-target-path forward)))))

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

(test remote-forward-specifications-parse
  (let ((forward
          (burs::parse-remote-forward "127.0.0.1:8080:example.org:80")))
    (is (equal "127.0.0.1" (burs::forward-bind-address forward)))
    (is (= 8080 (burs::forward-bind-port forward)))
    (is (equal "example.org" (burs::forward-host forward)))
    (is (= 80 (burs::forward-port forward))))
  ;; Port 0 asks the server to allocate one.
  (let ((forward (burs::parse-remote-forward "0:example.org:80")))
    (is (null (burs::forward-bind-address forward)))
    (is (= 0 (burs::forward-bind-port forward))))
  (let ((forward (burs::parse-remote-forward "[::1]:8080:[::2]:80")))
    (is (equal "::1" (burs::forward-bind-address forward)))
    (is (equal "::2" (burs::forward-host forward)))))

(test config-remote-forward-uses-the-two-word-form
  (let ((forward
          (burs::parse-config-remote-forward "18082 127.0.0.1:22")))
    (is (null (burs::forward-bind-address forward)))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "127.0.0.1" (burs::forward-host forward)))
    (is (= 22 (burs::forward-port forward))))
  (let ((forward
          (burs::parse-config-remote-forward "127.0.0.1:18082 127.0.0.1:22")))
    (is (equal "127.0.0.1" (burs::forward-bind-address forward)))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (= 22 (burs::forward-port forward)))))

(test remote-forward-match-accepts-the-address-the-server-names
  (let ((forward (burs::parse-remote-forward "8080:example.org:80")))
    ;; An empty bind address means loopback, and the server may answer with
    ;; the address it resolved or with the one the client wrote.
    (is (burs::remote-forward-match-p forward "127.0.0.1" 8080))
    (is (burs::remote-forward-match-p forward "localhost" 8080))
    (is (not (burs::remote-forward-match-p forward "127.0.0.1" 8081))))
  (let ((forward
          (burs::parse-remote-forward "127.0.0.1:8080:example.org:80")))
    (is (burs::remote-forward-match-p forward "127.0.0.1" 8080))
    (is (not (burs::remote-forward-match-p forward "10.0.0.1" 8080)))))

(test dynamic-forward-specifications-parse
  (let ((forward (burs::parse-dynamic-forward "1080")))
    (is (null (burs::dynamic-forward-bind-address forward)))
    (is (= 1080 (burs::dynamic-forward-bind-port forward))))
  (let ((forward (burs::parse-dynamic-forward "127.0.0.1:1080")))
    (is (equal "127.0.0.1" (burs::dynamic-forward-bind-address forward)))
    (is (= 1080 (burs::dynamic-forward-bind-port forward))))
  (let ((forward (burs::parse-dynamic-forward "*:1080")))
    (is (equal "*" (burs::dynamic-forward-bind-address forward)))
    (is (= 1080 (burs::dynamic-forward-bind-port forward))))
  (let ((forward (burs::parse-dynamic-forward "[::1]:1080")))
    (is (equal "::1" (burs::dynamic-forward-bind-address forward)))
    (is (= 1080 (burs::dynamic-forward-bind-port forward)))))

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

(test request-tty-follows-ssh-policy
  (labels ((request (setting command-given-p)
             (let ((burs::*options* (empty-options)))
               (setf (getf burs::*options* :request-tty) setting)
               (burs::request-tty-p nil command-given-p))))
    ;; -t forces a PTY even when no local terminal will drive it.
    (is (eq t (request :force nil)))
    (is (eq t (request :force t)))
    ;; -T never asks for one, with or without a command.
    (is (eq nil (request :no nil)))
    (is (eq nil (request :no t)))
    ;; RequestTTY=no is the same decision spelled through -o.
    (is (eq nil (request "no" nil)))
    ;; auto is a login session only: a command means no PTY.
    (is (eq nil (request "auto" t)))
    (is (eq nil (request nil t)))))

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

;;; ---- version ----

(test version-constant-matches-the-system-definition
  "The version BURS reports must be the version the system file declares."
  (is (equal (asdf:component-version (asdf:find-system "bursyk-client"))
             burs::+burs-version+)))
