(in-package #:cl-user)

(defpackage #:bursyk-client-tests
  (:use #:cl #:fiveam))

(in-package #:bursyk-client-tests)

(def-suite bursyk-client :description "BURS command line and config")
(in-suite bursyk-client)

;;; ---- helpers ----

(defun empty-options ()
  "The CLI's defaults, freshly allocated so a test cannot leak into another."
  (list :port nil :user nil :identity nil :config nil :known-hosts nil
        :policy nil :agent nil :options nil))

(defun options (initargs)
  "An SSH-CONFIG-OPTIONS carrying INITARGS, for the pure accessors."
  (apply #'cl-pnet-ssh::%make-ssh-config-options initargs))

(defun temporary-directory (name)
  (let ((directory (merge-pathnames
                    (format nil "bursyk-client-~D-~D/"
                            (get-universal-time) (random 1000000))
                    (uiop:temporary-directory))))
    (ensure-directories-exist (merge-pathnames name directory))
    directory))

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
    ;; Every other keyword is accepted and ignored.
    (burs::command-line-option "Compression" "yes")
    (is (equal "2200" (getf burs::*options* :port)))
    (is (equal "bob" (getf burs::*options* :user)))
    (is (equal '("/tmp/key") (getf burs::*options* :identity)))
    (is (equal "/tmp/known" (getf burs::*options* :known-hosts)))
    (is (equal "/tmp/agent" (getf burs::*options* :agent)))
    (is (eq :accept-new (getf burs::*options* :policy)))))

(test join-command-keeps-the-arguments-apart
  (is (equal "uname -a" (burs::join-command '("uname" "-a"))))
  (is (stringp (burs::join-command nil))))

;;; ---- ProxyJump ----

(test split-jump-list-understands-none-and-commas
  (is (null (burs::split-jump-list "none")))
  (is (null (burs::split-jump-list " NONE ")))
  (is (null (burs::split-jump-list "")))
  (is (equal '("jump.example")
             (burs::split-jump-list "jump.example")))
  (is (equal '("one" "user@two:2222" "three")
             (burs::split-jump-list "one, user@two:2222,three"))))

(test split-host-port-brackets-ipv6-literals
  (multiple-value-bind (host port) (burs::split-host-port "example.org")
    (is (equal "example.org" host))
    (is (null port)))
  (multiple-value-bind (host port) (burs::split-host-port "example.org:2200")
    (is (equal "example.org" host))
    (is (equal "2200" port)))
  (multiple-value-bind (host port) (burs::split-host-port "[::1]:2222")
    (is (equal "::1" host))
    (is (equal "2222" port)))
  (multiple-value-bind (host port) (burs::split-host-port "[::1]")
    (is (equal "::1" host))
    (is (null port)))
  (is (eql 2222 (burs::port-string "2222")))
  (is (null (burs::port-string "22x")))
  (is (null (burs::port-string "2222-with"))))

(test jump-host-reads-user-port-and-config
  (let* ((directory (temporary-directory "jump"))
         (file (merge-pathnames "config" directory))
         (burs::*options* (list :config file)))
    (unwind-protect
         (progn
           (with-open-file (stream file :direction :output
                                        :if-exists :supersede
                                        :if-does-not-exist :create)
             (write-line "Host bastion" stream)
             (write-line "  HostName real-bastion.example" stream)
             (write-line "  User gate" stream)
             (write-line "  Port 2200" stream))
           (let ((hop (burs::jump-host "bastion")))
             (is (equal "bastion" (getf hop :host)))
             (is (equal "real-bastion.example" (getf hop :connect-host)))
             (is (equal "gate" (getf hop :user)))
             (is (= 2200 (getf hop :port))))
           (let ((hop (burs::jump-host "alice@other:2201")))
             (is (equal "other" (getf hop :host)))
             (is (equal "alice" (getf hop :user)))
             (is (= 2201 (getf hop :port)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test proxy-jumps-let-the-command-line-win
  (let ((burs::*options* (list :jump "cli.example"
                               :config (merge-pathnames
                                        "missing-config"
                                        (uiop:temporary-directory)))))
    (let ((hops (burs::proxy-jumps nil)))
      (is (= 1 (length hops)))
      (is (equal "cli.example" (getf (first hops) :host))))
    (setf (getf burs::*options* :jump) "none")
    (is (null (burs::proxy-jumps nil))))
  (let* ((burs::*options* (list :config nil))
         (options (options '(:proxy-jump "from-config.example"))))
    (is (equal "from-config.example"
               (getf (first (burs::proxy-jumps options)) :host)))))

;;; ---- config mapping ----

(test config-policy-reads-the-three-answers
  (is (eq :insecure
          (burs::config-policy
           (options '(:strict-host-key-checking "no")))))
  (is (eq :accept-new
          (burs::config-policy
           (options '(:strict-host-key-checking "accept-new")))))
  (is (eq :strict
          (burs::config-policy
           (options '(:strict-host-key-checking "yes")))))
  (is (eq :strict (burs::config-policy nil))))

(test config-agent-maps-none-and-the-environment
  (is (null (burs::config-agent nil)))
  (is (null (burs::config-agent (options '(:identity-agent :none)))))
  (is (eq t (burs::config-agent
             (options '(:identity-agent :environment)))))
  (is (string= "/tmp/agent.sock"
               (namestring
                (burs::config-agent
                 (options '(:identity-agent #p"/tmp/agent.sock")))))))

(test config-known-hosts-puts-the-user-file-first
  (let ((known (burs::config-known-hosts
                (options (list :known-hosts (list #p"/u/known")
                               :global-known-hosts (list #p"/e/known"))))))
    (is (equal '("/u/known" "/e/known")
               (mapcar #'namestring known))))
  (is (null (burs::config-known-hosts nil))))

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

;;; ---- config resolution ----

(test config-options-apply-a-host-block
  (let* ((directory (temporary-directory "config"))
         (file (merge-pathnames "config" directory))
         (burs::*options* (list :config file)))
    (unwind-protect
         (progn
           (with-open-file (stream file :direction :output
                                        :if-exists :supersede
                                        :if-does-not-exist :create)
             (write-line "Host work" stream)
             (write-line "  HostName real.example" stream)
             (write-line "  User alice" stream)
             (write-line "  Port 2222" stream)
             (write-line "  IdentityFile ~/.ssh/work_key" stream)
             (write-line "  IdentityFile ~/.ssh/work_other" stream)
             (write-line "  UserKnownHostsFile ~/.ssh/work_known" stream)
             (write-line "  GlobalKnownHostsFile /etc/ssh/ssh_known_hosts"
                         stream)
             (write-line "  SendEnv FROM_ENV" stream)
             (write-line "  StrictHostKeyChecking accept-new" stream))
           (with-open-file (stream file :direction :output
                                        :if-exists :append
                                        :if-does-not-exist :create)
             (write-line "Match host nothing" stream)
             (write-line "  User nobody" stream))
           (let ((resolved (burs::config-options "work")))
             (is (string= "real.example"
                          (cl-pnet-ssh:ssh-config-options-hostname resolved)))
             (is (string= "alice"
                          (cl-pnet-ssh:ssh-config-options-user resolved)))
             (is (= 2222
                    (cl-pnet-ssh:ssh-config-options-port resolved)))
             (is (equal '("FROM_ENV")
                        (cl-pnet-ssh:ssh-config-options-send-env resolved)))
             (is (equal
                  (mapcar (lambda (name)
                            (namestring
                             (merge-pathnames name (user-homedir-pathname))))
                          (list ".ssh/work_key" ".ssh/work_other"))
                  (mapcar #'namestring
                          (reverse
                           (cl-pnet-ssh:ssh-config-options-identity-files
                            resolved)))))
             (is (equal
                  (cons (namestring
                         (merge-pathnames ".ssh/work_known"
                                          (user-homedir-pathname)))
                        '("/etc/ssh/ssh_known_hosts"))
                  (mapcar #'namestring
                          (burs::config-known-hosts resolved))))
             (is (eq :accept-new (burs::config-policy resolved)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test config-options-understands-match-exec
  (let* ((directory (temporary-directory "match"))
         (file (merge-pathnames "config" directory))
         (burs::*options* (list :config file)))
    (unwind-protect
         (progn
           (with-open-file (stream file :direction :output
                                        :if-exists :supersede
                                        :if-does-not-exist :create)
             (write-line "Match exec \"exit 0\"" stream)
             (write-line "  User matched" stream)
             (write-line "Match exec \"exit 1\"" stream)
             (write-line "  User refused" stream))
           (is (string= "matched"
                        (cl-pnet-ssh:ssh-config-options-user
                         (burs::config-options "anything")))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))
