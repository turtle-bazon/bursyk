(in-package #:cl-user)

(defpackage #:bursyk-server-tests
  (:use #:cl #:fiveam))

(in-package #:bursyk-server-tests)

(def-suite bursyk-server :description "BURSYK-SERVER command line and bridge")
(in-suite bursyk-server)

;;; ---- helpers ----

(defun octets (string)
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

(defun octets-string (octets)
  (map 'string #'code-char octets))

(defun deadline-in (seconds)
  (+ (get-internal-real-time)
     (* seconds internal-time-units-per-second)))

(defun overdue-p (deadline)
  (> (get-internal-real-time) deadline))

#-win32
(defun fd-octets (fd &key (timeout 5))
  "Everything FD yields until EOF, polling while the pipe is empty.

A pty master reports EIO (5) rather than zero once every slave is closed, so
that ends the stream too."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                           :adjustable t :fill-pointer 0))
        (deadline (deadline-in timeout)))
    (loop
      (multiple-value-bind (octets count error)
          (cl-pnet-sockets:read-octets fd 4096)
        (cond
          ((plusp count)
           (loop for index from 0 below count
                 do (vector-push-extend (aref octets index) out)))
          ((or (zerop count) (eql error 5))
           (return (coerce out '(simple-array (unsigned-byte 8) (*)))))
          ((overdue-p deadline)
           (return (coerce out '(simple-array (unsigned-byte 8) (*)))))
          (t (sleep 0.005)))))))

#-win32
(defun fd-write (fd string)
  "Write STRING to FD, waiting briefly for the child to make room."
  (let ((data (octets string))
        (offset 0)
        (deadline (deadline-in 5)))
    (loop while (< offset (length data))
          do (multiple-value-bind (count error)
                 (cl-pnet-sockets:write-octets fd (subseq data offset))
               (declare (ignore error))
               (if (plusp count)
                   (incf offset count)
                   (when (overdue-p deadline) (return)))))))

#-win32
(defun fd-close (fd)
  (bursyk-server::c-close fd))

;;; ---- command line ----

(test command-prefixes-gate-exec
  (let ((bursyk-server::*options* (list :allow '("ls" "git "))))
    (is (bursyk-server::command-allowed-p "ls"))
    (is (bursyk-server::command-allowed-p "ls -l /tmp"))
    (is (bursyk-server::command-allowed-p "git status"))
    (is (not (bursyk-server::command-allowed-p "rm -rf /"))))
  (let ((bursyk-server::*options* (list :allow nil)))
    (is (bursyk-server::command-allowed-p "anything at all"))))

(test short-options-stay-case-sensitive
  (is (eq :address (bursyk-server::option-key "-a")))
  (is (eq :authorized-keys (bursyk-server::option-key "-A")))
  (is (eq :host-key (bursyk-server::option-key "-H")))
  (is (eq :port (bursyk-server::option-key "--port")))
  (is (eq :no-tcp-forwarding
          (bursyk-server::option-key "--no-tcp-forwarding")))
  (is (eq :permit-open (bursyk-server::option-key "--allow-tcpip")))
  (is (null (bursyk-server::option-key "-Z"))))

(test repeated-host-keys-keep-command-line-order
  ;; -H may be repeated so a server can present ed25519, ECDSA and RSA; the
  ;; first key the user named is the first the server advertises.
  (let ((bursyk-server::*options* (list :host-key nil)))
    (bursyk-server::parse-arguments
     '("-H" "first" "--host-key" "second" "-H" "third"))
    (is (equal '("first" "second" "third")
               (bursyk-server::host-key-files))))
  (let ((bursyk-server::*options* (list :host-key nil)))
    (is (equal (list (merge-pathnames ".ssh/id_ed25519"
                                      (user-homedir-pathname)))
               (bursyk-server::host-key-files)))))

;;; ---- forwarded connections ----

(test tcpip-forwarding-is-allowed-by-default
  (let ((bursyk-server::*options* nil))
    (is (bursyk-server::tcpip-allowed-p "example.com" 443))
    (is (bursyk-server::tcpip-allowed-p "127.0.0.1" 22))))

(test no-tcp-forwarding-refuses-every-target
  (let ((bursyk-server::*options* (list :no-tcp-forwarding t)))
    (is (not (bursyk-server::tcpip-allowed-p "example.com" 443)))
    (is (not (bursyk-server::tcpip-allowed-p "127.0.0.1" 22)))))

(test allow-tcpip-narrows-the-destinations
  (let ((bursyk-server::*options*
          (list :permit-open '("db.internal:5432" "*.example.com:*"
                               "[::1]:22"))))
    (is (bursyk-server::tcpip-allowed-p "db.internal" 5432))
    (is (not (bursyk-server::tcpip-allowed-p "db.internal" 5433)))
    (is (bursyk-server::tcpip-allowed-p "api.example.com" 443))
    (is (bursyk-server::tcpip-allowed-p "API.EXAMPLE.COM" 443))
    (is (not (bursyk-server::tcpip-allowed-p "api.example.org" 443)))
    (is (bursyk-server::tcpip-allowed-p "::1" 22))
    (is (not (bursyk-server::tcpip-allowed-p "::1" 23)))
    ;; The master switch still wins over any allow rule.
    (setf (getf bursyk-server::*options* :no-tcp-forwarding) t)
    (is (not (bursyk-server::tcpip-allowed-p "db.internal" 5432)))))

(test host-port-splitting-and-validation
  (multiple-value-bind (host port)
      (bursyk-server::split-host-port "db:5432")
    (is (string= "db" host))
    (is (string= "5432" port)))
  (multiple-value-bind (host port)
      (bursyk-server::split-host-port "[::1]:22")
    (is (string= "::1" host))
    (is (string= "22" port)))
  (multiple-value-bind (host port)
      (bursyk-server::split-host-port "no-port")
    (is (null host))
    (is (null port)))
  (is (null (bursyk-server::split-host-port "")))
  (is (bursyk-server::valid-permit-port-p "22"))
  (is (bursyk-server::valid-permit-port-p "*"))
  (is (not (bursyk-server::valid-permit-port-p "0")))
  (is (not (bursyk-server::valid-permit-port-p "65536")))
  (is (not (bursyk-server::valid-permit-port-p "ssh"))))

(test forwarding-options-parse-as-a-flag-and-a-list
  (let ((bursyk-server::*options* nil))
    (bursyk-server::parse-arguments
     '("--no-tcp-forwarding" "--allow-tcpip" "db:5432"
       "--allow-tcpip" "*.example.com:443"))
    (is (eq t (getf bursyk-server::*options* :no-tcp-forwarding)))
    (is (equal '("*.example.com:443" "db:5432")
               (getf bursyk-server::*options* :permit-open)))))

(test remote-forward-bind-policy
  (let ((bursyk-server::*options* nil))
    (is (string= "127.0.0.1"
                 (bursyk-server::remote-bind-address nil)))
    (is (string= "127.0.0.1"
                 (bursyk-server::remote-bind-address "localhost")))
    ;; A client cannot expose a LAN address unless the server allows it.
    (is (null (bursyk-server::remote-bind-address "0.0.0.0")))
    (is (null (bursyk-server::remote-bind-address "192.0.2.10"))))
  (let ((bursyk-server::*options* (list :gateway-ports t)))
    (is (string= "0.0.0.0"
                 (bursyk-server::remote-bind-address "0.0.0.0")))
    (is (string= "0.0.0.0"
                 (bursyk-server::remote-bind-address "*")))
    (is (string= "192.0.2.10"
                 (bursyk-server::remote-bind-address "192.0.2.10")))))

(test remote-forward-options-parse
  (let ((bursyk-server::*options* nil))
    (bursyk-server::parse-arguments
     '("--no-remote-forwarding" "--gateway-ports"))
    (is (eq t (getf bursyk-server::*options* :no-remote-forwarding)))
    (is (eq t (getf bursyk-server::*options* :gateway-ports)))))

;;; ---- status pipe ----

#-win32
(test bridge-status-reads-the-reported-code
  (flet ((reported (text)
           (let ((bridge (bursyk-server::make-bridge)))
             (setf (bursyk-server::bridge-status-data bridge) (octets text))
             (bursyk-server::bridge-status bridge))))
    (is (eql 7 (reported "7")))
    (is (eql 0 (reported "0")))
    (is (eql 143 (reported "143")))
    ;; The wrapper writes nothing when it never got to run.
    (is (eql 127 (reported "")))
    (is (eql 127 (reported "junk")))))

;;; ---- child processes ----

#-win32
(test spawn-shell-collects-streams-and-status
  (multiple-value-bind (pid stdin stdout stderr status)
      (bursyk-server::spawn-shell "printf out; printf err >&2; exit 7")
    (unwind-protect
         (let ((out (fd-octets stdout))
               (err (fd-octets stderr))
               (code (fd-octets status)))
           (bursyk-server::collect-child pid)
           (is (equal "out" (octets-string out)))
           (is (equal "err" (octets-string err)))
           (is (equal "7" (octets-string code))))
      (fd-close stdin)
      (fd-close stdout)
      (fd-close stderr)
      (fd-close status))))

#-win32
(test spawn-shell-adds-requested-environment
  (multiple-value-bind (pid stdin stdout stderr status)
      (bursyk-server::spawn-shell
       "printf '%s/%s' \"$BURS_TEST_ONE\" \"$HOME\""
       :environment '(("BURS_TEST_ONE" . "added")))
    (unwind-protect
         (let ((out (fd-octets stdout))
               (err (fd-octets stderr))
               (code (fd-octets status)))
           (bursyk-server::collect-child pid)
           (is (string= (format nil "added/~A" (uiop:getenv "HOME"))
                        (octets-string out)))
           (is (equal "" (octets-string err)))
           (is (equal "0" (octets-string code))))
      (fd-close stdin)
      (fd-close stdout)
      (fd-close stderr)
      (fd-close status))))

#-win32
(test spawn-shell-streams-stdin
  (multiple-value-bind (pid stdin stdout stderr status)
      (bursyk-server::spawn-shell "cat")
    (let ((stdin-open t))
      (unwind-protect
           (progn
             (fd-write stdin "ping")
             (fd-close stdin)
             (setf stdin-open nil)
             (let ((out (fd-octets stdout))
                   (err (fd-octets stderr))
                   (code (fd-octets status)))
               (bursyk-server::collect-child pid)
               (is (equal "ping" (octets-string out)))
               (is (equal "" (octets-string err)))
               (is (equal "0" (octets-string code)))))
        (when stdin-open (fd-close stdin))
        (fd-close stdout)
        (fd-close stderr)
        (fd-close status)))))

;;; ---- subsystems ----

(test subsystem-name-and-path-are-split
  (let ((bursyk-server::*options* (list :subsystem '("sftp=/bin/echo"))))
    (is (equal "/bin/echo" (bursyk-server::subsystem-path "sftp")))
    (is (null (bursyk-server::subsystem-path "scp"))))
  (let ((bursyk-server::*options* nil))
    (is (null (bursyk-server::subsystem-path "no-such-subsystem"))))
  (is (equal '("sftp" . "/bin/echo")
             (bursyk-server::split-subsystem "sftp=/bin/echo"))))

;;; ---- version ----

(test version-constant-matches-the-system-definition
  "The version a peer sees must be the version the system file declares."
  (is (equal (asdf:component-version (asdf:find-system "bursyk-server"))
             bursyk-server::+bursyk-server-version+)))

;;; ---- Windows command lines ----

#+win32
(test windows-arguments-are-quoted-for-createprocess
  "CommandLineToArgvW must see one argument, byte for byte."
  (is (equal "plain" (bursyk-server::quote-windows-argument "plain")))
  (is (equal "\"\"" (bursyk-server::quote-windows-argument "")))
  (is (equal "\"a b\"" (bursyk-server::quote-windows-argument "a b")))
  ;; A quote is escaped with one backslash; trailing backslashes double.
  (is (equal "\"a\\\"b\"" (bursyk-server::quote-windows-argument "a\"b")))
  (is (equal "\"a b\\\\\"" (bursyk-server::quote-windows-argument "a b\\")))
  (is (equal "a b c"
             (bursyk-server::windows-command-line '("a" "b" "c")))))

#+win32
(test pty-size-packs-columns-then-rows
  (is (eql #x00320050 (bursyk-server::pty-size 80 50)))
  ;; Zero is never sent: a zero-sized console is rejected.
  (is (eql #x00010001 (bursyk-server::pty-size 0 0))))

;;; ---- pseudo-terminals ----

#-win32
(test spawn-program-runs-without-a-shell
  (multiple-value-bind (pid stdin stdout stderr status)
      (bursyk-server::spawn-program "/bin/echo" '("a b" "c"))
    (unwind-protect
         (let ((out (fd-octets stdout))
               (code (fd-octets status)))
           (bursyk-server::collect-child pid)
           (is (equal (format nil "a b c~%") (octets-string out)))
           (is (equal "0" (octets-string code))))
      (fd-close stdin)
      (fd-close stdout)
      (fd-close stderr)
      (fd-close status))))

#-win32
(test spawn-pty-shell-gets-the-requested-size
  (multiple-value-bind (pid master status)
      (bursyk-server::spawn-pty-shell "stty size" "/bin/sh"
                                      :rows 31 :columns 101)
    (unwind-protect
         (let ((out (string-trim '(#\Space #\Return #\Newline)
                                 (octets-string (fd-octets master))))
               (code (string-trim '(#\Space #\Return #\Newline)
                                  (octets-string (fd-octets status)))))
           (bursyk-server::collect-child pid)
           (is (equal "31 101" out))
           (is (equal "0" code)))
      (fd-close master)
      (fd-close status))))

#-win32
(test spawn-pty-shell-runs-a-command-and-reports-its-status
  (multiple-value-bind (pid master status)
      (bursyk-server::spawn-pty-shell "echo hi; exit 7" "/bin/sh")
    (unwind-protect
         (let ((out (octets-string (fd-octets master)))
               (code (string-trim '(#\Space #\Return #\Newline)
                                  (octets-string (fd-octets status)))))
           (bursyk-server::collect-child pid)
           (is (search "hi" out))
           (is (equal "7" code)))
      (fd-close master)
      (fd-close status))))

;;; ---- sshd_config ----

(defun config-from-text (text)
  "An SSH-SERVER-CONFIG parsed from TEXT, as a file on disk."
  (let ((path (merge-pathnames
               (format nil "bursyk-server-config-~D.conf" (random 1000000))
               (uiop:temporary-directory))))
    (with-open-file (out path :direction :output :if-exists :supersede)
      (write-string text out))
    (unwind-protect
         (cl-pnet-ssh:ssh-server-config-load path)
      (ignore-errors (delete-file path)))))

(defun config-value (accessor text)
  (funcall accessor (config-from-text text)))

(test sshd-config-supplies-the-settings-the-command-line-omits
  (let ((config (config-from-text
                 (format nil "Port 2200~%~
                              ListenAddress 127.0.0.1~%~
                              HostKey /tmp/host_ed25519~%~
                              HostKey /tmp/host_rsa~%~
                              AuthorizedKeysFile %h/.ssh/authorized_keys~%~
                              AcceptEnv LANG LC_*~%~
                              PermitOpen db:5432 *.example.com:443~%~
                              GatewayPorts clientspecified~%~
                              AllowTcpForwarding local~%~
                              Subsystem sftp /usr/lib/openssh/sftp-server~%~
                              LogLevel VERBOSE~%"))))
    (is (equal '(2200)
               (cl-pnet-ssh:ssh-server-config-ports config)))
    (is (equal '(("127.0.0.1"))
               (cl-pnet-ssh:ssh-server-config-listen-addresses config)))
    (is (equal '("/tmp/host_ed25519" "/tmp/host_rsa")
               (cl-pnet-ssh:ssh-server-config-host-key-files config)))
    (is (equal '("%h/.ssh/authorized_keys")
               (cl-pnet-ssh:ssh-server-config-authorized-keys-files config)))
    (is (equal '("LANG" "LC_*")
               (cl-pnet-ssh:ssh-server-config-accept-env config)))
    (is (equal '("db:5432" "*.example.com:443")
               (cl-pnet-ssh:ssh-server-config-permit-open config)))
    (is (eq :clientspecified
            (cl-pnet-ssh:ssh-server-config-gateway-ports config)))
    (is (eq :local
            (cl-pnet-ssh:ssh-server-config-allow-tcp-forwarding config)))
    (is (equal '(("sftp" . "/usr/lib/openssh/sftp-server"))
               (cl-pnet-ssh:ssh-server-config-subsystems config)))
    (is (eq :verbose (cl-pnet-ssh:ssh-server-config-log-level config)))))

(test sshd-config-refuses-what-this-server-cannot-honour
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match User root"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "ChrootDirectory /jail"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "PasswordAuthentication yes"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "NotAKeyword yes"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Port 1
Port 2"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AddressFamily inet6")))

(test sshd-config-accepts-what-describes-this-server
  (is (null (cl-pnet-ssh:ssh-server-config-warnings
             (config-from-text
              "PasswordAuthentication no
PermitRootLogin yes"))))
  (is (equal '("ignoring printmotd; this server has nothing for it to configure")
             (cl-pnet-ssh:ssh-server-config-warnings
              (config-from-text "PrintMotd no")))))

(test sshd-config-reads-banner
  "Banner is a path read per connection, or none for no banner at all."
  (is (equal "/etc/issue.net"
             (config-value #'cl-pnet-ssh:ssh-server-config-banner
                           "Banner /etc/issue.net")))
  (is (eq :none
          (config-value #'cl-pnet-ssh:ssh-server-config-banner
                        "Banner none")))
  ;; first value wins, as everywhere else
  (is (equal "/first"
             (config-value #'cl-pnet-ssh:ssh-server-config-banner
                           "Banner /first
Banner /second")))
  ;; It is no longer something this server merely warns about.
  (is (null (cl-pnet-ssh:ssh-server-config-warnings
             (config-from-text "Banner /etc/issue.net"))))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Banner")))

(test banner-file-reading-matches-sshd
  "A banner that is missing, empty, or unreadable is no banner at all."
  (let ((path (merge-pathnames "bursyk-banner-test.txt"
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (with-open-file (out path :direction :output
                                     :if-exists :supersede
                                     :if-does-not-exist :create)
             (write-string "Authorized use only.
" out))
           (is (equal "Authorized use only.
" (bursyk-server::read-banner-file path)))
           (with-open-file (out path :direction :output :if-exists :supersede))
           (is (null (bursyk-server::read-banner-file path)))
           (is (null (bursyk-server::read-banner-file
                      (merge-pathnames "no-such-banner"
                                       (uiop:temporary-directory))))))
      (ignore-errors (delete-file path)))))

(test sshd-config-reads-environment-policy
  "SetEnv and PermitUserEnvironment carry sshd's first-value rules."
  (let ((config (config-from-text
                 "SetEnv LANG=en_US.UTF-8
SetEnv IGNORED=yes
PermitUserEnvironment LANG,LC_*")))
    (is (equal '("LANG=en_US.UTF-8")
               (cl-pnet-ssh:ssh-server-config-set-env config)))
    (is (equal '("LANG" "LC_*")
               (cl-pnet-ssh:ssh-server-config-permit-user-environment config))))
  (is (eq :yes (config-value
                #'cl-pnet-ssh:ssh-server-config-permit-user-environment
                "PermitUserEnvironment yes")))
  (is (eq :no (config-value
               #'cl-pnet-ssh:ssh-server-config-permit-user-environment
               "PermitUserEnvironment no")))
  ;; Everything on the first SetEnv line is kept, a repeated name is not,
  ;; and a later SetEnv line is ignored entirely, as sshd does.
  (is (equal '("A=1" "B=2")
             (config-value #'cl-pnet-ssh:ssh-server-config-set-env
                           "SetEnv A=1 B=2 A=3
SetEnv C=4")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "SetEnv NOEQUALS"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "SetEnv")))

(test permit-user-environment-controls-names
  (let ((allowlist (cl-pnet-ssh::%make-ssh-server
                    :permit-user-environment '("LANG" "LC_*")))
        (everything (cl-pnet-ssh::%make-ssh-server
                     :permit-user-environment :yes))
        (nothing (cl-pnet-ssh::%make-ssh-server
                  :permit-user-environment :no)))
    (is (cl-pnet-ssh:ssh-server-permit-user-environment-p allowlist "LANG"))
    (is (cl-pnet-ssh:ssh-server-permit-user-environment-p allowlist "LC_ALL"))
    (is (not (cl-pnet-ssh:ssh-server-permit-user-environment-p
              allowlist "PATH")))
    (is (cl-pnet-ssh:ssh-server-permit-user-environment-p everything "PATH"))
    (is (not (cl-pnet-ssh:ssh-server-permit-user-environment-p
              nothing "LANG")))
    (is (not (cl-pnet-ssh:ssh-server-permit-user-environment-p
              (cl-pnet-ssh::%make-ssh-server) "LANG")))))

(test user-environment-file-is-filtered-by-the-allowlist
  "~/.ssh/environment is read only for variables PermitUserEnvironment allows."
  (let ((path (merge-pathnames "bursyk-user-environment-test"
                               (uiop:temporary-directory)))
        (server (cl-pnet-ssh::%make-ssh-server
                 :permit-user-environment '("LANG" "LC_*"))))
    (unwind-protect
         (progn
           (with-open-file (out path :direction :output
                                     :if-exists :supersede
                                     :if-does-not-exist :create)
             (format out "  LANG=en_US.UTF-8~%
# a comment~%
~%
SECRET=no~%
BROKEN~%
LC_ALL=C~%"))
           (let ((environment
                   (bursyk-server::read-user-environment-file
                    path server '(("LANG" . "client")))))
             (is (equal "en_US.UTF-8"
                        (cdr (assoc "LANG" environment :test #'string=))))
             (is (equal "C"
                        (cdr (assoc "LC_ALL" environment :test #'string=))))
             (is (null (assoc "SECRET" environment :test #'string=)))
             (is (null (assoc "BROKEN" environment :test #'string=)))))
      (ignore-errors (delete-file path)))))

#-ssh-backend-ffi
(test session-environment-follows-sshd-precedence
  "SetEnv beats ~/.ssh/environment, which beats the key options and client."
  (let* ((server (cl-pnet-ssh::%make-ssh-server
                  :permit-user-environment :yes
                  :set-env '("LANG=admin" "PATH=/admin/bin")))
         ;; An account that /etc/passwd will not know, so no real environment
         ;; file is read and the key's options are the only user source.
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server
                   :user "bursyk-test-user-with-no-passwd-entry"
                   :key-env '("LANG=key" "TZ=UTC")))
         (channel (cl-pnet-ssh::%make-ssh-server-channel
                   :session session
                   :env '(("LANG" . "client")
                          ("TERM" . "vt100")
                          ("LC_ALL" . "client")))))
    (let ((environment (bursyk-server::session-environment channel)))
      ;; SetEnv wins over the key option.
      (is (equal "admin" (cdr (assoc "LANG" environment :test #'string=))))
      (is (equal "/admin/bin"
                 (cdr (assoc "PATH" environment :test #'string=))))
      ;; A key option with no SetEnv counterpart survives.
      (is (equal "UTC" (cdr (assoc "TZ" environment :test #'string=))))
      ;; Accepted client variables that nothing overrides survive.
      (is (equal "client"
                 (cdr (assoc "LC_ALL" environment :test #'string=))))
      ;; There is one entry per name.
      (is (= 1 (count "LANG" environment :key #'car :test #'string=))))))

(test sshd-config-reads-connection-timers
  "LoginGraceTime and ClientAlive* carry sshd's time syntax and defaults."
  (let ((config (config-from-text
                 "LoginGraceTime 1m30s
ClientAliveInterval 15
ClientAliveCountMax 0")))
    (is (= 90 (cl-pnet-ssh:ssh-server-config-login-grace-time config)))
    (is (= 15 (cl-pnet-ssh:ssh-server-config-client-alive-interval config)))
    (is (= 0
           (cl-pnet-ssh:ssh-server-config-client-alive-count-max config))))
  ;; An absent directive stays NIL so MAKE-SSH-SERVER keeps sshd's default;
  ;; an explicit zero is a value and must not be confused with absence.
  (is (null (config-value
             #'cl-pnet-ssh:ssh-server-config-login-grace-time "")))
  (is (= 0 (config-value
            #'cl-pnet-ssh:ssh-server-config-login-grace-time
            "LoginGraceTime 0")))
  ;; The first value obtained wins, as with every other sshd keyword.
  (is (= 5 (config-value
            #'cl-pnet-ssh:ssh-server-config-login-grace-time
            "LoginGraceTime 5
LoginGraceTime 10")))
  ;; sshd's convtime forms: units, a bare number, and concatenation.
  (is (= 90 (cl-pnet-ssh:ssh-parse-time "1m30s")))
  (is (= 604800 (cl-pnet-ssh:ssh-parse-time "1w")))
  (is (= 90 (cl-pnet-ssh:ssh-parse-time "90")))
  (is (= 2 (cl-pnet-ssh:ssh-parse-time "+2")))
  (is (= 0 (cl-pnet-ssh:ssh-parse-time "0")))
  (dolist (bad '("" "1x" "-1" "1m30q" "m" "1m 30s"))
    (is (null (cl-pnet-ssh:ssh-parse-time bad))))
  (dolist (bad '("LoginGraceTime nope" "LoginGraceTime -1"
                 "ClientAliveInterval 1x" "ClientAliveCountMax 1s"
                 "ClientAliveCountMax -1"))
    (signals cl-pnet-ssh:ssh-server-config-error
      (config-from-text bad))))

(test server-connection-timers-keep-sshd-defaults
  "A server built without timer values uses sshd's 120, 0 and 3."
  (let ((server (cl-pnet-ssh::%make-ssh-server)))
    (is (= 120 (cl-pnet-ssh:ssh-server-login-grace-time server)))
    (is (= 0 (cl-pnet-ssh:ssh-server-client-alive-interval server)))
    (is (= 3 (cl-pnet-ssh:ssh-server-client-alive-count-max server))))
  (let ((server (cl-pnet-ssh::%make-ssh-server
                 :login-grace-time 0
                 :client-alive-interval 5
                 :client-alive-count-max 0)))
    (is (= 0 (cl-pnet-ssh:ssh-server-login-grace-time server)))
    (is (= 5 (cl-pnet-ssh:ssh-server-client-alive-interval server)))
    (is (= 0 (cl-pnet-ssh:ssh-server-client-alive-count-max server)))))

(test sshd-config-takes-the-first-value-it-obtains
  (let ((config (config-from-text
                 "LogLevel VERBOSE
LogLevel DEBUG
Port 2200
Port 2200")))
    (is (equal '(2200) (cl-pnet-ssh:ssh-server-config-ports config)))
    (is (eq :verbose (cl-pnet-ssh:ssh-server-config-log-level config))))
  ;; This server listens on one port, so two different Port lines cannot both
  ;; be honoured and are refused rather than one being silently dropped.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Port 2200
Port 2201")))

(test sshd-config-authorizes-per-user-paths
  (let ((config (config-from-text "AuthorizedKeysFile none")))
    (is (equal '("none")
               (cl-pnet-ssh:ssh-server-config-authorized-keys-files config))))
  (let ((config (config-from-text
                 "AuthorizedKeysFile none %h/keys/%u %h/.ssh/authorized_keys")))
    ;; sshd skips "none" rather than refusing to mix it with real files.
    (is (equal '("none" "%h/keys/%u" "%h/.ssh/authorized_keys")
               (cl-pnet-ssh:ssh-server-config-authorized-keys-files config))))
  (is (equal '("%h/.ssh/authorized_keys" "%h/.ssh/authorized_keys2")
             cl-pnet-ssh:+ssh-server-config-default-authorized-keys-files+)))

(test server-port-comes-from-p-then-listen-address-then-port-then-22
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config* nil))
    (is (= 22 (bursyk-server::server-port)))
    (is (equal "0.0.0.0" (bursyk-server::server-address))))
  (let ((bursyk-server::*options* (list :port "2299"))
        (bursyk-server::*server-config*
          (config-from-text "Port 2200
ListenAddress 127.0.0.2")))
    (is (= 2299 (bursyk-server::server-port)))
    (is (equal "127.0.0.2" (bursyk-server::server-address))))
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text "Port 2200
ListenAddress 127.0.0.2:2201")))
    (is (= 2201 (bursyk-server::server-port)))
    (is (equal "127.0.0.2" (bursyk-server::server-address)))))

(test -f-none-reads-no-config-file
  (let ((bursyk-server::*options* (list :config-file "none")))
    (is (null (bursyk-server::config-file-path))))
  (let ((bursyk-server::*options* nil))
    (is (equal cl-pnet-ssh:+ssh-server-config-default-file+
               (bursyk-server::config-file-path)))))

(test -o-lines-win-over-the-config-file
  (let ((path (merge-pathnames "bursyk-server-option-test.conf"
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (with-open-file (out path :direction :output :if-exists :supersede)
             (write-line "Port 2200" out)
             (write-line "ListenAddress 127.0.0.9" out)
             (write-line "LogLevel VERBOSE" out)
             (write-line "PermitOpen db:5432" out))
           (let ((config (cl-pnet-ssh:ssh-server-config-load
                          path :options '("LogLevel=DEBUG" "PermitOpen=none"
                                          "Port=2210"
                                          "ListenAddress=127.0.0.8"))))
             (is (equal '(2210)
                        (cl-pnet-ssh:ssh-server-config-ports config)))
             (is (equal '(("127.0.0.8"))
                        (cl-pnet-ssh:ssh-server-config-listen-addresses
                         config)))
             (is (eq :debug
                     (cl-pnet-ssh:ssh-server-config-log-level config)))
             (is (equal '("none")
                        (cl-pnet-ssh:ssh-server-config-permit-open config)))))
      (ignore-errors (delete-file path)))))

(test relative-include-is-anchored-at-etc-ssh
  (is (equal "/etc/ssh/conf.d/extra.conf"
             (namestring (cl-pnet-ssh::ssh-server-config-include-path
                          "conf.d/extra.conf"))))
  (is (equal "/absolute/ssh_config"
             (namestring (cl-pnet-ssh::ssh-server-config-include-path
                          "/absolute/ssh_config")))))

(test authorized-keys-patterns-expand-sshd-tokens
  (is (equal "/home/alice/.ssh/authorized_keys"
             (bursyk-server::expand-authorized-keys-path
              "%h/.ssh/authorized_keys" "alice" "/home/alice" "1000")))
  (is (equal "/home/alice/keys/alice/1000"
             (bursyk-server::expand-authorized-keys-path
              "keys/%u/%U" "alice" "/home/alice" "1000")))
  ;; %% is a literal %, and the h after it is not a token.
  (is (equal "/home/alice/%h"
             (bursyk-server::expand-authorized-keys-path
              "%%h" "alice" "/home/alice" "1000"))))

(test accept-env-patterns-use-sshd-globbing
  (let ((server (cl-pnet-ssh::%make-ssh-server
                 :accept-env '("LANG" "LC_*"))))
    (is (cl-pnet-ssh:ssh-server-env-allowed-p server "LANG" "en_US.UTF-8"))
    (is (cl-pnet-ssh:ssh-server-env-allowed-p server "LC_ALL" "C"))
    (is (cl-pnet-ssh:ssh-server-env-allowed-p server "LC_CTYPE" "C"))
    (is (not (cl-pnet-ssh:ssh-server-env-allowed-p server "LANGUAGE" "en")))
    (is (not (cl-pnet-ssh:ssh-server-env-allowed-p server "HOME" "/tmp")))))

(test logging-levels-gate-what-is-printed
  (let ((bursyk-server::*log-level* :quiet))
    (is (not (bursyk-server::log-allowed-p :error))))
  (let ((bursyk-server::*log-level* :info))
    (is (bursyk-server::log-allowed-p :info))
    (is (bursyk-server::log-allowed-p :error))
    (is (not (bursyk-server::log-allowed-p :verbose))))
  (let ((bursyk-server::*log-level* :verbose))
    (is (bursyk-server::log-allowed-p :verbose))
    (is (not (bursyk-server::log-allowed-p :debug)))))

(test verbosity-and-quiet-flags-select-a-level
  (let ((bursyk-server::*options* (list :config-file "none" :verbose 2))
        (bursyk-server::*server-config* nil)
        (bursyk-server::*log-level* :info))
    (bursyk-server::load-server-config)
    (is (eq :debug bursyk-server::*log-level*)))
  (let ((bursyk-server::*options* (list :config-file "none" :quiet t))
        (bursyk-server::*server-config* nil)
        (bursyk-server::*log-level* :info))
    (bursyk-server::load-server-config)
    (is (eq :quiet bursyk-server::*log-level*)))
  (let ((bursyk-server::*options* (list :config-file "none"))
        (bursyk-server::*server-config* nil)
        (bursyk-server::*log-level* :info))
    (bursyk-server::load-server-config)
    (is (eq :info bursyk-server::*log-level*))))

;;; ---- sshd_config feeding policy ----

(test host-keys-come-from-h-then-the-config
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text "HostKey /tmp/host_a
HostKey /tmp/host_b")))
    (is (equal '("/tmp/host_a" "/tmp/host_b")
               (mapcar #'namestring (bursyk-server::host-key-files)))))
  (let ((bursyk-server::*options* (list :host-key '("/tmp/only")))
        (bursyk-server::*server-config*
          (config-from-text "HostKey /tmp/host_a")))
    (is (equal '("/tmp/only")
               (mapcar #'namestring (bursyk-server::host-key-files))))))

(test config-forwarding-policy-drives-the-decisions
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text
           "AllowTcpForwarding local
GatewayPorts clientspecified
PermitOpen db:5432")))
    (is (bursyk-server::tcpip-allowed-p "db" 5432))
    (is (not (bursyk-server::tcpip-allowed-p "web" 443)))
    (is (not (bursyk-server::remote-forwarding-allowed-p)))
    (is (equal "0.0.0.0" (bursyk-server::remote-bind-address "*")))
    (is (equal "10.0.0.5"
               (bursyk-server::remote-bind-address "10.0.0.5"))))
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text "PermitOpen none")))
    (is (not (bursyk-server::tcpip-allowed-p "anything" 22))))
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config* nil))
    ;; Without a config file the defaults stay permissive.
    (is (bursyk-server::tcpip-allowed-p "anything" 22))
    (is (bursyk-server::remote-forwarding-allowed-p))
    (is (equal "127.0.0.1" (bursyk-server::remote-bind-address "*")))))

(test accept-env-comes-from-the-config-when-e-is-absent
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text "AcceptEnv LANG LC_*")))
    (is (equal '("LANG" "LC_*") (bursyk-server::accept-env-names))))
  (let ((bursyk-server::*options* (list :accept-env '("TWO" "ONE")))
        (bursyk-server::*server-config*
          (config-from-text "AcceptEnv LANG LC_*")))
    (is (equal '("ONE" "TWO") (bursyk-server::accept-env-names)))))

#-win32
(test user-home-and-uid-reads-the-passwd-file
  (let ((user (uiop:getenv "USER")))
    (when user
      (multiple-value-bind (home uid)
          (bursyk-server::user-home-and-uid user)
        (is (stringp home))
        (is (plusp (length home)))
        (is (stringp uid))
        (is (every #'digit-char-p uid)))))
  (is (null (bursyk-server::user-home-and-uid "no-such-user-here"))))

(test two-command-line-ports-are-refused
  ;; This server still listens on one port, so two different -o Port answers
  ;; cannot both be honoured and are reported instead of one silently winning.
  (signals cl-pnet-ssh:ssh-server-config-error
    (cl-pnet-ssh:ssh-server-config-load
     nil :options '("Port=2200" "Port=2201"))))

(test authorized-keys-recognise-every-ecdsa-curve
  ;; The authorized_keys reader decides which key lines are worth decoding;
  ;; all three curves OpenSSH can write must be recognised.
  (dolist (type '("ecdsa-sha2-nistp256"
                  "ecdsa-sha2-nistp384"
                  "ecdsa-sha2-nistp521"))
    (is (cl-pnet-ssh::ssh-authorized-key-line-blob
         (format nil "~A AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=" type))))
  (is (null (cl-pnet-ssh::ssh-authorized-key-line-blob
             "ssh-dss AAAAB3NzaC1kc3M="))))

;;; ---- account policy and limits ----

(test sshd-config-reads-account-and-limit-policy
  (let ((config (config-from-text
                 "AllowUsers alice bob
AllowUsers carol
DenyUsers root
AllowGroups wheel admins
DenyGroups banned
PermitRootLogin prohibit-password
MaxAuthTries 4
MaxSessions 0
PidFile /tmp/bursyk-test.pid
VersionAddendum mybuild")))
    (is (equal '("alice" "bob" "carol")
               (cl-pnet-ssh:ssh-server-config-allow-users config)))
    (is (equal '("root")
               (cl-pnet-ssh:ssh-server-config-deny-users config)))
    (is (equal '("wheel" "admins")
               (cl-pnet-ssh:ssh-server-config-allow-groups config)))
    (is (equal '("banned")
               (cl-pnet-ssh:ssh-server-config-deny-groups config)))
    (is (eq :prohibit-password
            (cl-pnet-ssh:ssh-server-config-permit-root-login config)))
    (is (eql 4 (cl-pnet-ssh:ssh-server-config-max-auth-tries config)))
    (is (eql 0 (cl-pnet-ssh:ssh-server-config-max-sessions config)))
    (is (equal "/tmp/bursyk-test.pid"
               (cl-pnet-ssh:ssh-server-config-pid-file config)))
    (is (equal "mybuild"
               (cl-pnet-ssh:ssh-server-config-version-addendum config)))
  (is (eq :none
          (config-value #'cl-pnet-ssh:ssh-server-config-version-addendum
                        "VersionAddendum none")))
  (is (eq :prohibit-password
          (config-value #'cl-pnet-ssh:ssh-server-config-permit-root-login
                        "PermitRootLogin without-password")))
  ;; first value wins, as everywhere else in sshd_config
  (is (eql 3
          (config-value #'cl-pnet-ssh:ssh-server-config-max-auth-tries
                        "MaxAuthTries 3
MaxAuthTries 9")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "PermitRootLogin maybe"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "MaxAuthTries -1"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AllowUsers alice@"))
  ;; "none" leaves the spelling in place for the writer to skip; a later
  ;; PidFile must not override it, because the first value wins.
  (is (equal "none"
             (config-value #'cl-pnet-ssh:ssh-server-config-pid-file
                           "PidFile none")))
  (is (equal "none"
             (config-value #'cl-pnet-ssh:ssh-server-config-pid-file
                           "PidFile none
PidFile /tmp/later.pid")))))

(test allow-and-deny-lists-use-sshd-globbing
  (let ((config (config-from-text
                 "AllowUsers alice bob@10.0.0.0/8 carol@192.168.1.*
DenyUsers root mallory@10.1.2.3")))
    (is (cl-pnet-ssh:ssh-server-user-allowed-p
         config "alice" "203.0.113.9" '("users")))
    (is (cl-pnet-ssh:ssh-server-user-allowed-p
         config "bob" "10.4.5.6" '("users")))
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              config "bob" "192.168.1.1" '("users"))))
    (is (cl-pnet-ssh:ssh-server-user-allowed-p
         config "carol" "192.168.1.7" '("users")))
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              config "dave" "10.0.0.1" '("users"))))
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              config "root" "10.0.0.1" '("users"))))
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              config "mallory" "10.1.2.3" '("users"))))
    ;; The deny list wins even when the allow list also matches.
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              (config-from-text "AllowUsers mallory
DenyUsers mallory")
              "mallory" "10.0.0.1" '("users")))))
  ;; A negated address vetoes the pattern; another address is still free.
  (let ((config (config-from-text "AllowUsers bob@!10.0.0.0/8")))
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              config "bob" "10.1.1.1" '("users"))))
    (is (cl-pnet-ssh:ssh-server-user-allowed-p
         config "bob" "192.168.1.1" '("users")))))

(test group-lists-match-any-group
  (let ((config (config-from-text
                 "AllowGroups wheel admins
DenyGroups banned")))
    (is (cl-pnet-ssh:ssh-server-user-allowed-p
         config "alice" "10.0.0.1" '("users" "wheel")))
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              config "alice" "10.0.0.1" '("users"))))
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              config "alice" "10.0.0.1" '("wheel" "banned")))))
  ;; Explicit denies work even when no allow list exists.
  (let ((config (config-from-text "DenyGroups banned")))
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              config "alice" "10.0.0.1" '("banned"))))
    (is (cl-pnet-ssh:ssh-server-user-allowed-p
         config "alice" "10.0.0.1" '("users")))))

(test allow-and-deny-lists-understand-ipv6-hosts
  (let ((config (config-from-text "DenyUsers mallory@2001:db8::/32")))
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              config "mallory" "2001:db8:0:1::5" '("users"))))
    (is (cl-pnet-ssh:ssh-server-user-allowed-p
         config "mallory" "2001:db9::5" '("users"))))
  (let ((config (config-from-text "AllowUsers alice@::1/128")))
    (is (cl-pnet-ssh:ssh-server-user-allowed-p
         config "alice" "::1" '("users")))
    (is (not (cl-pnet-ssh:ssh-server-user-allowed-p
              config "alice" "::2" '("users"))))))

(test permit-root-login-follows-sshd-modes
  ;; The default is prohibit-password: keys work, passwords would not.
  (is (cl-pnet-ssh:ssh-root-login-allowed-p nil "publickey"))
  (is (not (cl-pnet-ssh:ssh-root-login-allowed-p nil "password")))
  (is (cl-pnet-ssh:ssh-root-login-allowed-p :prohibit-password "publickey"))
  (is (not (cl-pnet-ssh:ssh-root-login-allowed-p :prohibit-password "password")))
  (is (cl-pnet-ssh:ssh-root-login-allowed-p :yes "password"))
  (is (not (cl-pnet-ssh:ssh-root-login-allowed-p :no "publickey")))
  ;; No forced command exists in this build, so this mode refuses.
  (is (not (cl-pnet-ssh:ssh-root-login-allowed-p
            :forced-commands-only "publickey")))
  (is (cl-pnet-ssh:ssh-root-login-allowed-p
       :forced-commands-only "publickey" :force-command "id")))

(test max-auth-tries-counts-failures-and-has-sshd-defaults
  ;; The limit is stored per server; the counter is per connection.
  (let* ((server (cl-pnet-ssh::%make-ssh-server :max-auth-tries 3))
         (session (cl-pnet-ssh::%make-ssh-session :server server)))
    (is (eql 3 (cl-pnet-ssh:ssh-server-max-auth-tries server)))
    (is (zerop (cl-pnet-ssh:ssh-session-auth-failures session)))
    (incf (cl-pnet-ssh:ssh-session-auth-failures session))
    (is (= 1 (cl-pnet-ssh:ssh-session-auth-failures session))))
  (is (= 6 (cl-pnet-ssh:ssh-server-max-auth-tries
            (cl-pnet-ssh::%make-ssh-server))))
  (is (= 10 (cl-pnet-ssh:ssh-server-max-sessions
             (cl-pnet-ssh::%make-ssh-server))))
  ;; The first "none" probe is free; every later failure counts.
  (is (not (cl-pnet-ssh::ssh-server-auth-failure-counts-p 1 "none")))
  (is (cl-pnet-ssh::ssh-server-auth-failure-counts-p 2 "none"))
  (is (cl-pnet-ssh::ssh-server-auth-failure-counts-p 1 "publickey")))
  
(test max-sessions-counts-live-session-channels
  (let* ((server (cl-pnet-ssh::%make-ssh-server :max-sessions 2))
         (session (cl-pnet-ssh::%make-ssh-session :server server)))
    (is (zerop (cl-pnet-ssh:ssh-server-session-channel-count session)))
    (let ((channel (cl-pnet-ssh::%make-ssh-server-channel
                    :session session :local-id 1 :type "session"
                    :state :open)))
      (setf (gethash 1 (cl-pnet-ssh::ssh-session-channels session)) channel)
      (is (= 1 (cl-pnet-ssh:ssh-server-session-channel-count session)))
      (setf (cl-pnet-ssh:ssh-server-channel-state channel) :closed)
      (is (zerop (cl-pnet-ssh:ssh-server-session-channel-count session))))
    ;; A direct-tcpip channel is not a session.
    (let ((channel (cl-pnet-ssh::%make-ssh-server-channel
                    :session session :local-id 2 :type "direct-tcpip"
                    :state :open)))
      (setf (gethash 2 (cl-pnet-ssh::ssh-session-channels session)) channel)
      (is (zerop (cl-pnet-ssh:ssh-server-session-channel-count session))))))
