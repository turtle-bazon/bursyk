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
    (is (bursyk-server::tcpip-allowed-p nil "example.com" 443))
    (is (bursyk-server::tcpip-allowed-p nil "127.0.0.1" 22))))

(test no-tcp-forwarding-refuses-every-target
  (let ((bursyk-server::*options* (list :no-tcp-forwarding t)))
    (is (not (bursyk-server::tcpip-allowed-p nil "example.com" 443)))
    (is (not (bursyk-server::tcpip-allowed-p nil "127.0.0.1" 22)))))

(test allow-tcpip-narrows-the-destinations
  (let ((bursyk-server::*options*
          (list :permit-open '("db.internal:5432" "*.example.com:*"
                               "[::1]:22"))))
    (is (bursyk-server::tcpip-allowed-p nil "db.internal" 5432))
    (is (not (bursyk-server::tcpip-allowed-p nil "db.internal" 5433)))
    (is (bursyk-server::tcpip-allowed-p nil "api.example.com" 443))
    (is (bursyk-server::tcpip-allowed-p nil "API.EXAMPLE.COM" 443))
    (is (not (bursyk-server::tcpip-allowed-p nil "api.example.org" 443)))
    (is (bursyk-server::tcpip-allowed-p nil "::1" 22))
    (is (not (bursyk-server::tcpip-allowed-p nil "::1" 23)))
    ;; The master switch still wins over any allow rule.
    (setf (getf bursyk-server::*options* :no-tcp-forwarding) t)
    (is (not (bursyk-server::tcpip-allowed-p nil "db.internal" 5432)))))

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

(test address-family-flags-parse
  ;; -4 and -6 are their own flags, not -a or -p with a value, and each
  ;; records the family the listener will bind.
  (let ((bursyk-server::*options* nil))
    (bursyk-server::parse-arguments '("-4"))
    (is (eq t (getf bursyk-server::*options* :address-family-4)))
    (is (null (getf bursyk-server::*options* :address-family-6))))
  (let ((bursyk-server::*options* nil))
    (bursyk-server::parse-arguments '("-6"))
    (is (eq t (getf bursyk-server::*options* :address-family-6)))
    (is (null (getf bursyk-server::*options* :address-family-4)))))

(test remote-forward-bind-policy
  (let ((bursyk-server::*options* nil))
    (is (string= "127.0.0.1"
                 (bursyk-server::remote-bind-address nil nil)))
    (is (string= "127.0.0.1"
                 (bursyk-server::remote-bind-address nil "localhost")))
    ;; A client cannot expose a LAN address unless the server allows it.
    (is (null (bursyk-server::remote-bind-address nil "0.0.0.0")))
    (is (null (bursyk-server::remote-bind-address nil "192.0.2.10"))))
  (let ((bursyk-server::*options* (list :gateway-ports t)))
    (is (string= "0.0.0.0"
                 (bursyk-server::remote-bind-address nil "0.0.0.0")))
    (is (string= "0.0.0.0"
                 (bursyk-server::remote-bind-address nil "*")))
    (is (string= "192.0.2.10"
                 (bursyk-server::remote-bind-address nil "192.0.2.10")))))

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

(test forcecommand-is-kept-verbatim-and-internal-sftp-is-refused
  ;; sshd hands the rest of the line to the login shell untouched, quotes
  ;; and all, so the reader must not tokenise it.
  (is (equal "/usr/bin/true --flag"
             (config-value #'cl-pnet-ssh:ssh-server-config-force-command
                           "ForceCommand /usr/bin/true --flag")))
  (is (equal "\"/bin/echo hi\""
             (config-value #'cl-pnet-ssh:ssh-server-config-force-command
                           "ForceCommand \"/bin/echo hi\"")))
  ;; The first ForceCommand wins, as sshd's adm_forced_command does.
  (is (equal "one"
             (config-value #'cl-pnet-ssh:ssh-server-config-force-command
                           "ForceCommand one
ForceCommand two")))
  ;; internal-sftp is an in-process server this build does not have.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "ForceCommand internal-sftp"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "ForceCommand internal-sftp -d /srv"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "ForceCommand")))

(test sshd-config-refuses-what-this-server-cannot-honour
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "NotAKeyword yes"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Port 1
Port 2"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AddressFamily ipv7")))

(test sshd-config-reads-password-and-keyboard-interactive-switches
  (let ((config (config-from-text "PasswordAuthentication no
KbdInteractiveAuthentication no")))
    (is (eq :no (cl-pnet-ssh:ssh-server-config-password-authentication config)))
    (is (eq :no (cl-pnet-ssh:ssh-server-config-kbd-interactive-authentication
                 config))))
  ;;
  ;; ChallengeResponseAuthentication is the obsolete spelling of
  ;; KbdInteractiveAuthentication; the first of the two wins.
  (let ((config (config-from-text "ChallengeResponseAuthentication no
KbdInteractiveAuthentication yes")))
    (is (eq :no (cl-pnet-ssh:ssh-server-config-kbd-interactive-authentication
                 config))))
  (let ((password (config-from-text "PasswordAuthentication yes")))
    (is (null (cl-pnet-ssh:ssh-server-config-warnings password)))
    (is (eq :yes
            (cl-pnet-ssh:ssh-server-config-password-authentication password))))
  (let ((kbd (config-from-text "KbdInteractiveAuthentication yes")))
    (is (null (cl-pnet-ssh:ssh-server-config-warnings kbd)))
    (is (eq :yes
            (cl-pnet-ssh:ssh-server-config-kbd-interactive-authentication
             kbd)))))

(test sshd-config-accepts-what-describes-this-server
  (is (null (cl-pnet-ssh:ssh-server-config-warnings
             (config-from-text
              "PasswordAuthentication no
PermitRootLogin yes"))))
  (is (equal "inet6"
             (config-value #'cl-pnet-ssh:ssh-server-config-address-family
                           "AddressFamily inet6")))
  (is (equal '("ignoring printmotd; this server has nothing for it to configure")
             (cl-pnet-ssh:ssh-server-config-warnings
              (config-from-text "PrintMotd no")))))

(test sshd-config-reads-algorithm-policy
  (let ((config (config-from-text
                 "Ciphers +chacha20-poly1305@openssh.com
MACs -hmac-sha2-256
KexAlgorithms +curve25519-sha256@libssh.org
HostKeyAlgorithms ssh-ed25519
PubkeyAcceptedAlgorithms rsa-sha2-512,ssh-ed25519
RequiredRSASize 2048
PermitListen 8080 127.0.0.1:9000")))
    (is (equal '("chacha20-poly1305@openssh.com")
               (cl-pnet-ssh:ssh-server-config-ciphers config)))
    ;; "-name" removes from the build's list and leaves the rest in order.
    (is (equal '("hmac-sha2-512")
               (cl-pnet-ssh:ssh-server-config-macs config)))
    (is (equal '("curve25519-sha256" "curve25519-sha256@libssh.org")
               (cl-pnet-ssh:ssh-server-config-kex-algorithms config)))
    ;; A plain list replaces the default outright.
    (is (equal '("ssh-ed25519")
               (cl-pnet-ssh:ssh-server-config-host-key-algorithms config)))
    (is (equal '("rsa-sha2-512" "ssh-ed25519")
               (cl-pnet-ssh:ssh-server-config-pubkey-accepted-algorithms
                config)))
    (is (eql 2048
           (cl-pnet-ssh:ssh-server-config-required-rsa-size config)))
    ;; A bare port is "*:PORT", as sshd expands PermitListen.
    (is (equal '("*:8080" "127.0.0.1:9000")
               (cl-pnet-ssh:ssh-server-config-permit-listen config))))
  ;; PubkeyAcceptedKeyTypes is the obsolete spelling of the same directive,
  ;; and the first of either name wins.
  (is (equal '("ssh-ed25519")
             (config-value
              #'cl-pnet-ssh:ssh-server-config-pubkey-accepted-algorithms
              "PubkeyAcceptedKeyTypes ssh-ed25519")))
  (is (equal '("ssh-ed25519")
             (config-value
              #'cl-pnet-ssh:ssh-server-config-pubkey-accepted-algorithms
              "PubkeyAcceptedAlgorithms ssh-ed25519
PubkeyAcceptedKeyTypes rsa-sha2-512")))
  ;; An algorithm this build cannot offer is an error, not a quiet drop.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Ciphers aes128-ctr"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "KexAlgorithms no-such-kex"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "HostKeyAlgorithms ssh-dss"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "RequiredRSASize -1"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "PermitListen not-a-port"))
  ;; Ciphers, MACs, KexAlgorithms and HostKeyAlgorithms are global only.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match User alice
  Ciphers chacha20-poly1305@openssh.com")))

(test match-blocks-read-per-connection-algorithm-policy
  (let* ((config (config-from-text
                  "PermitListen *:22
RequiredRSASize 1024
PubkeyAcceptedAlgorithms ssh-ed25519
Match User alice
  PermitListen localhost:8080
  RequiredRSASize 3072
  PubkeyAcceptedAlgorithms rsa-sha2-512"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (equal '("localhost:8080")
               (cl-pnet-ssh:ssh-server-config-permit-listen alice)))
    (is (eql 3072
           (cl-pnet-ssh:ssh-server-config-required-rsa-size alice)))
    (is (equal '("rsa-sha2-512")
               (cl-pnet-ssh:ssh-server-config-pubkey-accepted-algorithms
                alice)))
    (is (equal '("*:22")
               (cl-pnet-ssh:ssh-server-config-permit-listen bob)))
    (is (eql 1024
           (cl-pnet-ssh:ssh-server-config-required-rsa-size bob)))
    (is (equal '("ssh-ed25519")
               (cl-pnet-ssh:ssh-server-config-pubkey-accepted-algorithms
                bob)))))

(test sshd-config-reads-revokedkeys
  "RevokedKeys is a list of files, may be disabled with none, and may be
overridden per connection."
  (is (equal '("/etc/ssh/revoked_keys" "/etc/ssh/extra")
             (config-value #'cl-pnet-ssh:ssh-server-config-revoked-keys
                           "RevokedKeys /etc/ssh/revoked_keys /etc/ssh/extra")))
  (is (eq :none
          (config-value #'cl-pnet-ssh:ssh-server-config-revoked-keys
                        "RevokedKeys none")))
  ;; sshd refuses "none" beside another file, and a directive with no file.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "RevokedKeys none /etc/ssh/revoked_keys"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "RevokedKeys /etc/ssh/revoked_keys none"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "RevokedKeys"))
  ;; The first line wins, as sshd's parse_filenames keeps the first list;
  ;; later lines are still parsed, so a malformed one is still an error.
  (is (equal '("/first")
             (config-value #'cl-pnet-ssh:ssh-server-config-revoked-keys
                           "RevokedKeys /first
 RevokedKeys /second")))
  (is (eq :none
          (config-value #'cl-pnet-ssh:ssh-server-config-revoked-keys
                        "RevokedKeys none
 RevokedKeys /second")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "RevokedKeys /first
 RevokedKeys /second none"))
  ;; A Match block may replace the list, and none there disables it.
  (let* ((config (config-from-text
                  "RevokedKeys /global
 Match User alice
   RevokedKeys /alice
 Match User bob
   RevokedKeys none"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (equal '("/alice")
               (cl-pnet-ssh:ssh-server-config-revoked-keys alice)))
    (is (eq :none
            (cl-pnet-ssh:ssh-server-config-revoked-keys bob)))))

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

;;; ---- Match blocks ----

(defun effective-config (text &key user (groups nil) (groups-known t)
                              (address "192.0.2.9") (local-port 22)
                              (hostname nil))
  (cl-pnet-ssh:ssh-server-config-for-connection
   (config-from-text text)
   :user user :groups groups :groups-known groups-known
   :address address :hostname hostname :local-port local-port))

(test match-blocks-override-global-settings
  (let ((text "PermitRootLogin yes
MaxAuthTries 6
AcceptEnv LANG
Match User alice
  PermitRootLogin no
  MaxAuthTries 2
  AcceptEnv LC_*
Match Address 192.0.2.0/24
  AllowTcpForwarding local
  PermitOpen db:5432
"))
    (let ((alice (effective-config text :user "alice"
                                        :address "198.51.100.4")))
      (is (eq :no (cl-pnet-ssh:ssh-server-config-permit-root-login alice)))
      (is (eql 2 (cl-pnet-ssh:ssh-server-config-max-auth-tries alice)))
      ;; A list set in a matching block replaces the global list, as sshd's
      ;; copy_set_server_options does.
      (is (equal '("LC_*")
                 (cl-pnet-ssh:ssh-server-config-accept-env alice))))
    (let ((bob (effective-config text :user "bob" :address "192.0.2.9")))
      (is (eq :yes (cl-pnet-ssh:ssh-server-config-permit-root-login bob)))
      (is (eql 6 (cl-pnet-ssh:ssh-server-config-max-auth-tries bob)))
      (is (equal '("LANG")
                 (cl-pnet-ssh:ssh-server-config-accept-env bob)))
      (is (eq :local
              (cl-pnet-ssh:ssh-server-config-allow-tcp-forwarding bob)))
      (is (equal '("db:5432")
                 (cl-pnet-ssh:ssh-server-config-permit-open bob))))
    (let ((carol (effective-config text :user "carol"
                                         :address "198.51.100.4")))
      (is (null (cl-pnet-ssh:ssh-server-config-allow-tcp-forwarding carol)))
      (is (null (cl-pnet-ssh:ssh-server-config-permit-open carol))))))

(test match-can-turn-forwarding-back-on
  ;; DisableForwarding no is a value, not the absence of one: a matching
  ;; block must be able to turn off a global yes, as sshd's tri-state does.
  (let ((text "DisableForwarding yes
Match User alice
  DisableForwarding no
"))
    (is (null (cl-pnet-ssh:ssh-server-config-disable-forwarding
               (effective-config text :user "alice"))))
    (is (eq t (cl-pnet-ssh:ssh-server-config-disable-forwarding
               (effective-config text :user "bob")))))
  ;; The first obtained value still wins inside a block, and globally.
  (let ((text "DisableForwarding no
DisableForwarding yes
Match User alice
  DisableForwarding no
  DisableForwarding yes
"))
    (is (null (cl-pnet-ssh:ssh-server-config-disable-forwarding
               (config-from-text text))))
    (is (null (cl-pnet-ssh:ssh-server-config-disable-forwarding
               (effective-config text :user "alice"))))))

(test match-first-value-wins-and-criteria-are-anded
  (let ((text "Match User alice
  MaxAuthTries 2
Match User alice
  MaxAuthTries 3
Match Address 192.0.2.0/24
  MaxSessions 1
Match User alice Address 192.0.2.0/24
  ForceCommand /usr/bin/true
"))
    (let ((both (effective-config text :user "alice"
                                        :address "192.0.2.9")))
      ;; The first obtained value wins, so the second block's 3 is ignored.
      (is (eql 2 (cl-pnet-ssh:ssh-server-config-max-auth-tries both)))
      (is (eql 1 (cl-pnet-ssh:ssh-server-config-max-sessions both)))
      (is (equal "/usr/bin/true"
                 (cl-pnet-ssh:ssh-server-config-force-command both))))
    (let ((address-only (effective-config text :user "alice"
                                                :address "198.51.100.4")))
      (is (eql 2 (cl-pnet-ssh:ssh-server-config-max-auth-tries address-only)))
      ;; The address block does not match, and the combined one needs both.
      (is (null (cl-pnet-ssh:ssh-server-config-max-sessions address-only)))
      (is (null (cl-pnet-ssh:ssh-server-config-force-command address-only))))
    (let ((user-only (effective-config text :user "bob"
                                             :address "192.0.2.9")))
      (is (null (cl-pnet-ssh:ssh-server-config-max-auth-tries user-only)))
      (is (eql 1 (cl-pnet-ssh:ssh-server-config-max-sessions user-only))))))

(test match-group-negation-and-all
  (let ((text "Match Group wheel
  MaxAuthTries 1
Match Group *,!wheel
  MaxSessions 7
Match All
  Banner /banner
"))
    (let ((wheel (effective-config text :user "bob" :groups '("wheel"))))
      (is (eql 1 (cl-pnet-ssh:ssh-server-config-max-auth-tries wheel)))
      ;; A negated group match vetoes the block however the other names match.
      (is (null (cl-pnet-ssh:ssh-server-config-max-sessions wheel)))
      (is (equal "/banner" (cl-pnet-ssh:ssh-server-config-banner wheel))))
    (let ((other (effective-config text :user "bob" :groups '("users"))))
      (is (null (cl-pnet-ssh:ssh-server-config-max-auth-tries other)))
      (is (eql 7 (cl-pnet-ssh:ssh-server-config-max-sessions other))))
    ;; Without a group callback Match Group can never be evaluated, and sshd
    ;; treats the situation as an error rather than a silent no-match.
    (signals cl-pnet-ssh:ssh-server-config-error
      (cl-pnet-ssh:ssh-server-config-for-connection
       (config-from-text text)
       :user "bob" :groups-known nil))))

(test match-access-lists-apply-per-connection
  (let* ((config (config-from-text "AllowUsers alice
Match User bob
  AllowUsers bob
  DenyUsers mallory
"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session-for
           (lambda (user)
             (let ((session (cl-pnet-ssh::%make-ssh-session
                             :server server :user user)))
               (setf (cl-pnet-ssh:ssh-session-remote-address session)
                     (list :address "192.0.2.9"))
               (cl-pnet-ssh:ssh-session-resolve-config session user)
               session)))
         (alice (funcall session-for "alice"))
         (bob (funcall session-for "bob")))
    ;; The global list still governs every user it names.
    (is (bursyk-server::user-allowed-p alice "alice"))
    (is (not (bursyk-server::user-allowed-p alice "bob")))
    ;; Bob's own Match block replaces both lists for his connection.
    (is (bursyk-server::user-allowed-p bob "bob"))
    (is (not (bursyk-server::user-allowed-p bob "alice")))
    (is (not (bursyk-server::user-allowed-p bob "mallory")))))

(test match-host-and-localport
  (let ((text "Match Host example.com
  MaxSessions 3
Match LocalPort 2222
  MaxAuthTries 1
"))
    (let ((config (effective-config text :user "u"
                                         :hostname "EXAMPLE.COM"
                                         :local-port 2222)))
      (is (eql 3 (cl-pnet-ssh:ssh-server-config-max-sessions config)))
      (is (eql 1 (cl-pnet-ssh:ssh-server-config-max-auth-tries config))))
    (let ((config (effective-config text :user "u"
                                         :hostname "other.example.com"
                                         :local-port 22)))
      (is (null (cl-pnet-ssh:ssh-server-config-max-sessions config)))
      (is (null (cl-pnet-ssh:ssh-server-config-max-auth-tries config))))))

(test match-refuses-criteria-and-keywords-it-cannot-honour
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match LocalAddress 127.0.0.1"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match RDomain dmz"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match User"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match Address not-a-network/33"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match LocalPort 0"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match All User alice"))
  ;; OpenSSH's global-only keywords are refused here with the same intent.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match User alice
 Port 2200"))
  ;; 10.6 allows LogLevel in Match; the connection's level overrides the
  ;; global one for messages about that connection.
  (let* ((config (config-from-text
                  "LogLevel INFO
Match User alice
  LogLevel DEBUG"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (eq :debug (cl-pnet-ssh:ssh-server-config-log-level alice)))
    (is (eq :info (cl-pnet-ssh:ssh-server-config-log-level bob))))
  ;; PermitUserEnvironment is global-only in OpenSSH 9.2 as well.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match User alice
 PermitUserEnvironment yes"))
  ;; An empty Match block is valid, as sshd accepts it; nothing is silently
  ;; dropped because there is nothing in it.
  (is (null (cl-pnet-ssh:ssh-server-config-warnings
             (config-from-text "Match User alice"))))
  ;; sshd's -o cannot introduce a Match block either.
  (signals cl-pnet-ssh:ssh-server-config-error
    (cl-pnet-ssh:ssh-server-config-load
     nil :options '("Match=User alice"))))

(test match-banner-is-read-per-connection
  (let ((path (merge-pathnames "bursyk-match-banner.txt"
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (with-open-file (out path :direction :output
                                     :if-exists :supersede
                                     :if-does-not-exist :create)
             (write-string "match banner" out))
           (let* ((config (config-from-text
                           (format nil "Banner /no-such-global-banner~%~
                                        Match User alice~%~
                                        Banner ~A~%" path)))
                  (server (cl-pnet-ssh::%make-ssh-server
                           :sshd-config config))
                  (alice (cl-pnet-ssh::%make-ssh-session
                          :server server :user "alice"))
                  (bob (cl-pnet-ssh::%make-ssh-session
                        :server server :user "bob")))
             (cl-pnet-ssh:ssh-session-resolve-config alice "alice")
             (cl-pnet-ssh:ssh-session-resolve-config bob "bob")
             (is (equal "match banner"
                        (cl-pnet-ssh:ssh-session-banner-text alice)))
             ;; Bob keeps the global Banner, whose file does not exist.
             (is (null (cl-pnet-ssh:ssh-session-banner-text bob)))))
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

(test sshd-config-reads-expose-auth-info
  "ExposeAuthInfo is a flag whose first value wins, and Match can turn it off."
  (is (null (config-value
             #'cl-pnet-ssh:ssh-server-config-expose-auth-info "")))
  (is (eq :yes (config-value
                #'cl-pnet-ssh:ssh-server-config-expose-auth-info
                "ExposeAuthInfo yes")))
  (is (eq :no (config-value
               #'cl-pnet-ssh:ssh-server-config-expose-auth-info
               "ExposeAuthInfo no")))
  (is (eq :yes (config-value
                #'cl-pnet-ssh:ssh-server-config-expose-auth-info
                "ExposeAuthInfo yes
ExposeAuthInfo no")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "ExposeAuthInfo maybe"))
  (let* ((config (config-from-text
                  "ExposeAuthInfo yes
Match User bob
  ExposeAuthInfo no"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (eq :yes (cl-pnet-ssh:ssh-server-config-expose-auth-info alice)))
    (is (eq :no (cl-pnet-ssh:ssh-server-config-expose-auth-info bob)))))

(test sshd-config-reads-authentication-methods
  "AuthenticationMethods keeps the first line, validates later ones, and
can be overridden by Match."
  (is (equal '("publickey,publickey")
             (config-value
              #'cl-pnet-ssh:ssh-server-config-authentication-methods
              "AuthenticationMethods publickey,publickey")))
  (is (eq :any
          (config-value
           #'cl-pnet-ssh:ssh-server-config-authentication-methods
           "AuthenticationMethods any")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AuthenticationMethods publickey,not-a-method"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AuthenticationMethods any publickey"))
  ;; A later line is validated but ignored, and 10.6 permits a later "any"
  ;; because the first line already won.
  (is (equal '("publickey")
             (config-value
              #'cl-pnet-ssh:ssh-server-config-authentication-methods
              "AuthenticationMethods publickey
AuthenticationMethods any")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text
     "AuthenticationMethods publickey
AuthenticationMethods publickey,not-a-method"))
  (let* ((config (config-from-text
                  "AuthenticationMethods publickey
Match User bob
  AuthenticationMethods publickey,publickey"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (equal '("publickey")
               (cl-pnet-ssh:ssh-server-config-authentication-methods alice)))
    (is (equal '("publickey,publickey")
               (cl-pnet-ssh:ssh-server-config-authentication-methods bob)))))

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
                    path
                    (cl-pnet-ssh::%make-ssh-session :server server)
                    '(("LANG" . "client")))))
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

(test sshd-config-reads-startup-limits
  "MaxStartups, PerSource* and UnusedConnectionTimeout follow sshd's syntax."
  (let ((config (config-from-text
                 "MaxStartups 5:50:20
PerSourceMaxStartups 3
PerSourceNetBlockSize 24:64
UnusedConnectionTimeout 30
TCPKeepAlive no")))
    (is (= 5 (cl-pnet-ssh:ssh-server-config-max-startups-begin config)))
    (is (= 50 (cl-pnet-ssh:ssh-server-config-max-startups-rate config)))
    (is (= 20 (cl-pnet-ssh:ssh-server-config-max-startups-full config)))
    (is (= 3 (cl-pnet-ssh:ssh-server-config-per-source-max-startups config)))
    (is (= 24
           (cl-pnet-ssh:ssh-server-config-per-source-net-block-size-ipv4
            config)))
    (is (= 64
           (cl-pnet-ssh:ssh-server-config-per-source-net-block-size-ipv6
            config)))
    (is (= 30
           (cl-pnet-ssh:ssh-server-config-unused-connection-timeout config)))
    (is (eq :no (cl-pnet-ssh:ssh-server-config-tcp-keep-alive config))))
  ;; Absent directives stay NIL, so the server keeps sshd's 10:30:100,
  ;; "none", 32:128, none and yes.
  (let ((config (config-from-text "")))
    (is (null (cl-pnet-ssh:ssh-server-config-max-startups-begin config)))
    (is (null (cl-pnet-ssh:ssh-server-config-per-source-max-startups config)))
    (is (null (cl-pnet-ssh:ssh-server-config-unused-connection-timeout
               config)))
    (is (null (cl-pnet-ssh:ssh-server-config-tcp-keep-alive config))))
  ;; One MaxStartups number is both the begin and full value; the rate keeps
  ;; sshd's default of 30.
  (let ((config (config-from-text "MaxStartups 7")))
    (is (= 7 (cl-pnet-ssh:ssh-server-config-max-startups-begin config)))
    (is (null (cl-pnet-ssh:ssh-server-config-max-startups-rate config)))
    (is (= 7 (cl-pnet-ssh:ssh-server-config-max-startups-full config))))
  ;; MaxStartups is global-only and a later line replaces the earlier one.
  (let ((config (config-from-text
                 "MaxStartups 5:50:20
MaxStartups 10:30:100")))
    (is (= 10 (cl-pnet-ssh:ssh-server-config-max-startups-begin config)))
    (is (= 30 (cl-pnet-ssh:ssh-server-config-max-startups-rate config)))
    (is (= 100 (cl-pnet-ssh:ssh-server-config-max-startups-full config))))
  ;; "none" turns the per-source limit off and UnusedConnectionTimeout off.
  (let ((config (config-from-text
                 "PerSourceMaxStartups none
UnusedConnectionTimeout none")))
    (is (null (cl-pnet-ssh:ssh-server-config-per-source-max-startups config)))
    (is (= 0
           (cl-pnet-ssh:ssh-server-config-unused-connection-timeout config))))
  ;; UnusedConnectionTimeout is a time, and "none" wins even after a value,
  ;; as sshd's own special case stores zero without the first-value test.
  (is (= 90 (config-value
             #'cl-pnet-ssh:ssh-server-config-unused-connection-timeout
             "UnusedConnectionTimeout 1m30s")))
  (is (= 5 (config-value
            #'cl-pnet-ssh:ssh-server-config-unused-connection-timeout
            "UnusedConnectionTimeout 5
UnusedConnectionTimeout 10")))
  (is (= 0 (config-value
            #'cl-pnet-ssh:ssh-server-config-unused-connection-timeout
            "UnusedConnectionTimeout 30
UnusedConnectionTimeout none")))
  ;; TCPKeepAlive's old spelling is the same directive.
  (is (eq :yes (config-value
                #'cl-pnet-ssh:ssh-server-config-tcp-keep-alive
                "KeepAlive yes")))
  (is (eq :no (config-value
               #'cl-pnet-ssh:ssh-server-config-tcp-keep-alive
               "TCPKeepAlive no
TCPKeepAlive yes")))
  ;; PerSourceNetBlockSize names IPv4, and optionally IPv6.
  (let ((config (config-from-text "PerSourceNetBlockSize 24")))
    (is (= 24
           (cl-pnet-ssh:ssh-server-config-per-source-net-block-size-ipv4
            config)))
    (is (null
         (cl-pnet-ssh:ssh-server-config-per-source-net-block-size-ipv6
          config))))
  ;; The startup limits are global-only in sshd 9.2.
  (dolist (keyword '("MaxStartups 10" "PerSourceMaxStartups 5"
                     "PerSourceNetBlockSize 24" "TCPKeepAlive no"))
    (signals cl-pnet-ssh:ssh-server-config-error
      (config-from-text
       (format nil "Match User alice~%~A" keyword))))
  ;; UnusedConnectionTimeout is per connection and allowed in a Match.
  (let* ((config (config-from-text
                  "UnusedConnectionTimeout 30
Match User alice
 UnusedConnectionTimeout 1m"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (alice (cl-pnet-ssh::%make-ssh-session
                 :server server :user "alice"))
         (bob (cl-pnet-ssh::%make-ssh-session
               :server server :user "bob")))
    (cl-pnet-ssh:ssh-session-resolve-config alice "alice")
    (cl-pnet-ssh:ssh-session-resolve-config bob "bob")
    (is (= 60 (cl-pnet-ssh::ssh-session-unused-connection-timeout alice)))
    (is (= 30 (cl-pnet-ssh::ssh-session-unused-connection-timeout bob))))
  ;; Bad values are reported instead of silently replaced by defaults.
  (dolist (bad '("MaxStartups" "MaxStartups 0" "MaxStartups 10:0:20"
                 "MaxStartups 30:50:20" "MaxStartups 10:30"
                 "MaxStartups 10:30:20:5" "MaxStartups nope"
                 "PerSourceMaxStartups -1" "PerSourceMaxStartups many"
                 "PerSourceNetBlockSize 33" "PerSourceNetBlockSize 24:129"
                 "PerSourceNetBlockSize 24:64:128" "PerSourceNetBlockSize x"
                 "UnusedConnectionTimeout nope" "UnusedConnectionTimeout -1"
                 "TCPKeepAlive maybe"))
    (signals cl-pnet-ssh:ssh-server-config-error
      (config-from-text bad))))

(test sshd-config-reads-channel-timeouts
  "ChannelTimeout is sshd's TYPE=TIME list, parsed whole on the first line."
  (let ((config (config-from-text
                 "ChannelTimeout session:*=5m direct-tcpip=10 session:subsystem:sftp=0")))
    (is (equal '(("session:*" . 300) ("direct-tcpip" . 10)
                 ("session:subsystem:sftp" . 0))
               (cl-pnet-ssh:ssh-server-config-channel-timeouts config))))
  ;; 10.6's connection-wide timeout and its single session type.
  (is (equal '(("global" . 600) ("session" . 300))
             (cl-pnet-ssh:ssh-server-config-channel-timeouts
              (config-from-text "ChannelTimeout global=10m session=5m"))))
  ;; sshd's time syntax applies to each interval.
  (is (equal '(("session:*" . 5400))
             (cl-pnet-ssh:ssh-server-config-channel-timeouts
              (config-from-text "ChannelTimeout session:*=1h30m"))))
  ;; The first line is the whole answer, even when a later one adds a type.
  (is (equal '(("session:*" . 300))
             (cl-pnet-ssh:ssh-server-config-channel-timeouts
              (config-from-text
               "ChannelTimeout session:*=5m
ChannelTimeout direct-tcpip=10"))))
  ;; "none" must stand alone and disables every timeout; an earlier "none"
  ;; also keeps a later line from taking effect, as sshd's array does.
  (is (eq :none
          (cl-pnet-ssh:ssh-server-config-channel-timeouts
           (config-from-text "ChannelTimeout none"))))
  (is (eq :none
          (cl-pnet-ssh:ssh-server-config-channel-timeouts
           (config-from-text
            "ChannelTimeout none
ChannelTimeout session:*=5m"))))
  ;; A zero interval is kept as a value, not treated as absence.
  (is (equal '(("session:*" . 0))
             (cl-pnet-ssh:ssh-server-config-channel-timeouts
              (config-from-text "ChannelTimeout session:*=0"))))
  ;; Malformed types and intervals are errors, not silently dropped.
  (dolist (bad '("ChannelTimeout"
                 "ChannelTimeout none direct-tcpip=10"
                 "ChannelTimeout =5"
                 "ChannelTimeout session:*"
                 "ChannelTimeout session:*="
                 "ChannelTimeout session:*=-1"
                 "ChannelTimeout session:*=5x"
                 ;; A later line is ignored for values but still validated.
                 "ChannelTimeout session:*=5m
ChannelTimeout session:*=bogus"))
    (signals cl-pnet-ssh:ssh-server-config-error
      (config-from-text bad))))

(test match-blocks-read-per-connection-channel-timeouts
  "A Match ChannelTimeout replaces the global list for that connection."
  (let* ((config (config-from-text
                  "ChannelTimeout session:*=5m
Match Address 192.0.2.0/24
 ChannelTimeout direct-tcpip=10"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (near (cl-pnet-ssh::%make-ssh-session
                :server server :user "alice"))
         (far (cl-pnet-ssh::%make-ssh-session
               :server server :user "alice")))
    (setf (cl-pnet-ssh::ssh-session-remote-address near)
          '(:address "192.0.2.7" :port 2200)
          (cl-pnet-ssh::ssh-session-remote-address far)
          '(:address "203.0.113.7" :port 2200))
    (cl-pnet-ssh:ssh-session-resolve-config near "alice")
    (cl-pnet-ssh:ssh-session-resolve-config far "alice")
    (is (equal '(("direct-tcpip" . 10))
               (cl-pnet-ssh::ssh-session-channel-timeouts near)))
    (is (equal '(("session:*" . 300))
               (cl-pnet-ssh::ssh-session-channel-timeouts far))))
  ;; An explicit "none" in the block turns the global timeouts off.
  (let* ((config (config-from-text
                  "ChannelTimeout session:*=5m
Match Address 192.0.2.0/24
 ChannelTimeout none"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server :user "alice")))
    (setf (cl-pnet-ssh::ssh-session-remote-address session)
          '(:address "192.0.2.7" :port 2200))
    (cl-pnet-ssh:ssh-session-resolve-config session "alice")
    (is (eq :none
            (cl-pnet-ssh::ssh-session-channel-timeouts session)))))

(test server-startup-limits-keep-sshd-defaults
  "A server built without limit values uses sshd's 10:30:100 and friends."
  (let ((server (cl-pnet-ssh::%make-ssh-server)))
    (is (= 10 (cl-pnet-ssh:ssh-server-max-startups-begin server)))
    (is (= 30 (cl-pnet-ssh:ssh-server-max-startups-rate server)))
    (is (= 100 (cl-pnet-ssh:ssh-server-max-startups-full server)))
    (is (null (cl-pnet-ssh:ssh-server-per-source-max-startups server)))
    (is (= 32 (cl-pnet-ssh:ssh-server-per-source-net-block-size-ipv4 server)))
    (is (= 128
           (cl-pnet-ssh:ssh-server-per-source-net-block-size-ipv6 server)))
    (is (= 0 (cl-pnet-ssh:ssh-server-unused-connection-timeout server)))
    (is (cl-pnet-ssh:ssh-server-tcp-keep-alive server)))
  (let ((server (cl-pnet-ssh::%make-ssh-server
                 :max-startups-begin 5
                 :max-startups-rate 50
                 :max-startups-full 20
                 :per-source-max-startups 3
                 :per-source-net-block-size-ipv4 24
                 :per-source-net-block-size-ipv6 64
                 :unused-connection-timeout 30
                 :tcp-keep-alive nil)))
    (is (= 5 (cl-pnet-ssh:ssh-server-max-startups-begin server)))
    (is (= 50 (cl-pnet-ssh:ssh-server-max-startups-rate server)))
    (is (= 20 (cl-pnet-ssh:ssh-server-max-startups-full server)))
    (is (= 3 (cl-pnet-ssh:ssh-server-per-source-max-startups server)))
    (is (= 24 (cl-pnet-ssh:ssh-server-per-source-net-block-size-ipv4 server)))
    (is (= 64 (cl-pnet-ssh:ssh-server-per-source-net-block-size-ipv6 server)))
    (is (= 30 (cl-pnet-ssh:ssh-server-unused-connection-timeout server)))
    (is (not (cl-pnet-ssh:ssh-server-tcp-keep-alive server)))))

(test max-startups-drops-with-sshd-probability
  "MaxStartups starts dropping at BEGIN and takes everything at FULL."
  (let ((server (cl-pnet-ssh::%make-ssh-server
                 :max-startups-begin 10
                 :max-startups-rate 30
                 :max-startups-full 100)))
    ;; Below the begin value every connection is accepted.
    (is (not (cl-pnet-ssh::ssh-server-should-drop-connection-p
              server 9 :random 0)))
    ;; At FULL and above every connection is dropped.
    (is (cl-pnet-ssh::ssh-server-should-drop-connection-p
         server 100 :random 0))
    (is (cl-pnet-ssh::ssh-server-should-drop-connection-p
         server 101 :random 99))
    ;; At BEGIN the chance is exactly RATE percent.
    (is (cl-pnet-ssh::ssh-server-should-drop-connection-p
         server 10 :random 29))
    (is (not (cl-pnet-ssh::ssh-server-should-drop-connection-p
              server 10 :random 30)))
    ;; Halfway to FULL the chance has risen linearly, to 65 percent here.
    (is (cl-pnet-ssh::ssh-server-should-drop-connection-p
         server 55 :random 64))
    (is (not (cl-pnet-ssh::ssh-server-should-drop-connection-p
              server 55 :random 65)))
    ;; A single MaxStartups value makes BEGIN and FULL the same.
    (let ((single (cl-pnet-ssh::%make-ssh-server
                   :max-startups-begin 7
                   :max-startups-rate 30
                   :max-startups-full 7)))
      (is (cl-pnet-ssh::ssh-server-should-drop-connection-p
           single 7 :random 99))))
  ;; A rate of 100 means every connection at or above BEGIN is dropped.
  (let ((server (cl-pnet-ssh::%make-ssh-server
                 :max-startups-begin 5
                 :max-startups-rate 100
                 :max-startups-full 50)))
    (is (cl-pnet-ssh::ssh-server-should-drop-connection-p
         server 5 :random 99))))

(test per-source-limit-counts-masked-addresses
  "PerSourceMaxStartups groups peers by PerSourceNetBlockSize."
  (let ((server (cl-pnet-ssh::%make-ssh-server
                 :max-startups-begin 100
                 :max-startups-full 100
                 :per-source-max-startups 2
                 :per-source-net-block-size-ipv4 24
                 :per-source-net-block-size-ipv6 32))
        (sessions nil))
    (flet ((add (address)
             (let ((session (cl-pnet-ssh::%make-ssh-session
                             :server server
                             :remote-address (list :address address
                                                   :port 2200))))
               (push session sessions)
               (setf (gethash session
                              (cl-pnet-ssh::ssh-server-sessions server))
                     session)
               session)))
      (add "192.0.2.1")
      (add "192.0.2.2")
      (add "198.51.100.1")
      ;; Two peers share 192.0.2.0/24 even though their addresses differ.
      (is (= 2 (cl-pnet-ssh::ssh-server-source-session-count
                sessions "192.0.2.9" 24 128)))
      (is (= 1 (cl-pnet-ssh::ssh-server-source-session-count
                sessions "198.51.100.9" 24 128)))
      ;; The third connection from that /24 is refused; another network is
      ;; unaffected.
      (is (not (cl-pnet-ssh:ssh-server-connection-allowed-p
                server '(:address "192.0.2.9" :port 2200))))
      (is (cl-pnet-ssh:ssh-server-connection-allowed-p
           server '(:address "203.0.113.9" :port 2200))))
    ;; A wider IPv6 prefix groups two different IPv6 subnets.
    (let ((session (cl-pnet-ssh::%make-ssh-session
                    :server server
                    :remote-address '(:address "2001:db8:1::1" :port 2200))))
      (setf (gethash session (cl-pnet-ssh::ssh-server-sessions server))
            session)
      (is (= 1 (cl-pnet-ssh::ssh-server-source-session-count
                (list session) "2001:db8:2::1" 32 32))))
    ;; No per-source limit means every network is allowed.
    (let ((unlimited (cl-pnet-ssh::%make-ssh-server
                      :max-startups-begin 100
                      :max-startups-full 100)))
      (is (cl-pnet-ssh:ssh-server-connection-allowed-p
           unlimited '(:address "192.0.2.9" :port 2200))))))

(test unused-connection-timer-tracks-open-channels
  "UnusedConnectionTimeout counts every open channel, not just sessions."
  (let* ((server (cl-pnet-ssh::%make-ssh-server
                  :unused-connection-timeout 30))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (channel (cl-pnet-ssh::%make-ssh-server-channel
                   :session session :state :open)))
    (is (= 30 (cl-pnet-ssh::ssh-session-unused-connection-timeout session)))
    (setf (gethash 0 (cl-pnet-ssh::ssh-session-channels session)) channel)
    (is (cl-pnet-ssh::ssh-server-session-open-channel-p session))
    (setf (cl-pnet-ssh::ssh-server-channel-state channel) :closed)
    (is (not (cl-pnet-ssh::ssh-server-session-open-channel-p session))))
  ;; A Match block narrows the timeout per connection.
  (let* ((config (config-from-text
                  "UnusedConnectionTimeout 30
Match Address 192.0.2.0/24
 UnusedConnectionTimeout 5"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (near (cl-pnet-ssh::%make-ssh-session
                :server server :user "alice"))
         (far (cl-pnet-ssh::%make-ssh-session
               :server server :user "alice")))
    (setf (cl-pnet-ssh::ssh-session-remote-address near)
          '(:address "192.0.2.7" :port 2200)
          (cl-pnet-ssh::ssh-session-remote-address far)
          '(:address "203.0.113.7" :port 2200))
    (cl-pnet-ssh:ssh-session-resolve-config near "alice")
    (cl-pnet-ssh:ssh-session-resolve-config far "alice")
    (is (= 5 (cl-pnet-ssh::ssh-session-unused-connection-timeout near)))
    (is (= 30 (cl-pnet-ssh::ssh-session-unused-connection-timeout far)))))

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

(test server-address-follows-address-family
  ;; AddressFamily picks the wildcard the server binds, -4 and -6 outrank
  ;; it, and an explicit literal is used only when it belongs to the family.
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config* nil))
    (is (equal "0.0.0.0" (bursyk-server::server-address))))
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text "AddressFamily inet6")))
    (is (equal "::" (bursyk-server::server-address))))
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text "AddressFamily inet6
ListenAddress *")))
    (is (equal "::" (bursyk-server::server-address))))
  (let ((bursyk-server::*options* '(:address-family-6 t))
        (bursyk-server::*server-config* nil))
    (is (equal "::" (bursyk-server::server-address))))
  (let ((bursyk-server::*options* '(:address-family-4 t))
        (bursyk-server::*server-config*
          (config-from-text "AddressFamily inet6")))
    (is (equal "0.0.0.0" (bursyk-server::server-address))))
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text "AddressFamily inet6
ListenAddress ::1")))
    (is (equal "::1" (bursyk-server::server-address))))
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text "AddressFamily inet6
ListenAddress 127.0.0.1")))
    (signals error (bursyk-server::server-address)))
  ;; The listener resolves a named address in this family, and :INET6 also
  ;; turns on IPV6_V6ONLY so the wildcard refuses IPv4-mapped peers.
  (let ((bursyk-server::*options* '(:address-family-6 t))
        (bursyk-server::*server-config* nil))
    (is (eq :inet6 (bursyk-server::listener-family))))
  (let ((bursyk-server::*options* '(:address-family-4 t))
        (bursyk-server::*server-config* nil))
    (is (eq :inet (bursyk-server::listener-family))))
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config* nil))
    (is (null (bursyk-server::listener-family)))))

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

(test host-certificates-come-from-the-command-line-and-config
  (let ((config (config-from-text
                 "HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub")))
    (is (equal '("/etc/ssh/ssh_host_ed25519_key-cert.pub"
                 "/etc/ssh/ssh_host_rsa_key-cert.pub")
               (cl-pnet-ssh:ssh-server-config-host-certificate-files
                config))))
  (let ((bursyk-server::*options*
          (list :host-certificate '("/tmp/cli-cert.pub")))
        (bursyk-server::*server-config*
          (config-from-text "HostCertificate /tmp/config-cert.pub")))
    (is (equal '("/tmp/cli-cert.pub" "/tmp/config-cert.pub")
               (mapcar #'namestring
                       (bursyk-server::host-certificate-files)))))
  ;; HostCertificate is global only, like HostKey.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match User alice
  HostCertificate /tmp/cert.pub")))

(test config-forwarding-policy-drives-the-decisions
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text
           "AllowTcpForwarding local
GatewayPorts clientspecified
PermitOpen db:5432")))
    (is (bursyk-server::tcpip-allowed-p nil "db" 5432))
    (is (not (bursyk-server::tcpip-allowed-p nil "web" 443)))
    (is (not (bursyk-server::remote-forwarding-allowed-p nil)))
    (is (equal "0.0.0.0" (bursyk-server::remote-bind-address nil "*")))
    (is (equal "10.0.0.5"
               (bursyk-server::remote-bind-address nil "10.0.0.5"))))
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text "PermitOpen none")))
    (is (not (bursyk-server::tcpip-allowed-p nil "anything" 22))))
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config* nil))
    ;; Without a config file the defaults stay permissive.
    (is (bursyk-server::tcpip-allowed-p nil "anything" 22))
    (is (bursyk-server::remote-forwarding-allowed-p nil))
    (is (equal "127.0.0.1" (bursyk-server::remote-bind-address nil "*")))))

(test accept-env-comes-from-the-config-when-e-is-absent
  (let ((bursyk-server::*options* nil)
        (bursyk-server::*server-config*
          (config-from-text "AcceptEnv LANG LC_*")))
    ;; The command line is empty, so the session's resolved config supplies
    ;; AcceptEnv; the server is not handed a duplicate answer.
    (is (null (bursyk-server::accept-env-names)))
    (let* ((config bursyk-server::*server-config*)
           (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
           (session (cl-pnet-ssh::%make-ssh-session
                     :server server
                     :config (cl-pnet-ssh:ssh-server-config-for-connection
                              config
                              :user "alice" :address "192.0.2.9"))))
      (is (cl-pnet-ssh:ssh-session-env-allowed-p session "LANG" "C"))
      (is (cl-pnet-ssh:ssh-session-env-allowed-p session "LC_ALL" "C"))))
  (let ((bursyk-server::*options* (list :accept-env '("TWO" "ONE")))
        (bursyk-server::*server-config*
          (config-from-text "AcceptEnv LANG LC_*")))
    ;; -e is the explicit answer and wins over the file.
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
  ;; Even in this mode a key without command= cannot log root in; one with
  ;; a forced command can.
  (is (not (cl-pnet-ssh:ssh-root-login-allowed-p
            :forced-commands-only "publickey")))
  (is (cl-pnet-ssh:ssh-root-login-allowed-p
       :forced-commands-only "publickey" :force-command "id")))

(test password-hashes-are-checked-with-crypt
  ;; The DES hash of "secret"; crypt(3) accepts the traditional setting too.
  (is (bursyk-server::password-hash-valid-p "secret" "abNANd1rDfiNc"))
  (is (not (bursyk-server::password-hash-valid-p "wrong" "abNANd1rDfiNc")))
  ;; A locked or empty account, and an empty answer, never authenticate.
  (is (not (bursyk-server::password-hash-valid-p "secret" "!locked")))
  (is (not (bursyk-server::password-hash-valid-p "secret" "*")))
  (is (not (bursyk-server::password-hash-valid-p "" "abNANd1rDfiNc")))
  (is (not (bursyk-server::password-hash-valid-p "secret" ""))))

(test shadow-and-passwd-password-files-are-read-in-order
  ;; The real /etc/shadow is not readable in the test environment, so use
  ;; fixture files through the rebindable paths.
  (let* ((directory (merge-pathnames
                     (format nil "bursyk-server-shadow-~D/"
                             (random 1000000))
                     (uiop:temporary-directory)))
         (shadow (merge-pathnames "shadow" directory))
         (passwd (merge-pathnames "passwd" directory))
         (hash "abNANd1rDfiNc"))
    (ensure-directories-exist shadow)
    (flet ((write-lines (path &rest lines)
             (with-open-file (out path :direction :output
                                       :if-exists :supersede
                                       :if-does-not-exist :create)
               (dolist (line lines)
                 (format out "~A~%" line)))))
      (unwind-protect
           (progn
             ;; The modern layout: the hash is in shadow and passwd says "x".
             (write-lines shadow (format nil "tester:~A:19000:0:99999:7:::"
                                         hash))
             (write-lines passwd
                          "tester:x:1001:1001:Test User:/home/tester:/bin/sh")
             (let ((bursyk-server::*shadow-file* shadow)
                   (bursyk-server::*passwd-file* passwd))
               (is (equal hash
                          (bursyk-server::shadow-password-hash "tester")))
               (is (bursyk-server::verify-user-password "tester" "secret"))
               (is (not (bursyk-server::verify-user-password
                         "tester" "wrong")))
               (is (null (bursyk-server::verify-user-password
                          "nobody-here" "secret"))))
             ;; Without a shadow file the passwd field is the hash, as on an
             ;; account that never moved to shadow.
             (write-lines passwd
                          (format nil "tester:~A:1001:1001:Test User:/home/tester:/bin/sh"
                                  hash))
             (let ((bursyk-server::*shadow-file*
                     (merge-pathnames "absent-shadow" directory))
                   (bursyk-server::*passwd-file* passwd))
               (is (bursyk-server::verify-user-password "tester" "secret"))
               (is (not (bursyk-server::verify-user-password
                         "tester" "wrong"))))
             ;; A locked shadow entry wins over the passwd field.
             (write-lines shadow (format nil "tester:!~A:19000:0:99999:7:::"
                                         hash))
             (let ((bursyk-server::*shadow-file* shadow)
                   (bursyk-server::*passwd-file* passwd))
               (is (not (bursyk-server::verify-user-password
                         "tester" "secret"))))
             ;; An empty shadow hash is refused and does not fall back.
             (write-lines shadow "tester::19000:0:99999:7:::")
             (let ((bursyk-server::*shadow-file* shadow)
                   (bursyk-server::*passwd-file* passwd))
               (is (not (bursyk-server::verify-user-password
                         "tester" "secret")))))
        (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test keyboard-interactive-asks-once-and-checks-the-answer
  (let ((request (list :responses '())))
    (let ((step (bursyk-server::keyboard-interactive-authentication
                 nil "tester" request)))
      (is (getf step :prompts))
      (is (equal "Password: " (first (first (getf step :prompts)))))
      (is (not (second (first (getf step :prompts)))))))
  ;; Only the account policy and crypt(3) decide the answer round, so an
  ;; unknown user fails without pretending a prompt is still due.
  (is (eq :failure
          (bursyk-server::keyboard-interactive-authentication
           nil "these-accounts-do-not-exist" (list :responses '("x"))))))

(test forced-commands-only-root-needs-a-forced-command
  ;; PermitRootLogin forced-commands-only is decided when the key matches:
  ;; a key carrying command= admits root, one without it does not.
  (if (null (nth-value 1 (bursyk-server::user-home-and-uid "root")))
      (skip "no local root account")
      (let* ((directory (merge-pathnames
                         (format nil "bursyk-server-root-~D/"
                                 (random 1000000))
                         (uiop:temporary-directory)))
             (blob (concatenate
                    'string
                    "AAAAB3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5"
                    "C9okWi0dh2l9GKJl"))
             (with-command (merge-pathnames "with_command" directory))
             (without-command (merge-pathnames "without_command" directory))
             (config (config-from-text
                      "PermitRootLogin forced-commands-only")))
        (ensure-directories-exist with-command)
        (unwind-protect
             (let ((bursyk-server::*server-config* config)
                   (key (cl-pnet-ssh:ssh-authorized-key-line-blob
                         (format nil "ssh-ed25519 ~A" blob))))
               (with-open-file (out with-command :direction :output
                                               :if-exists :supersede
                                               :if-does-not-exist :create)
                 (format out "command=\"id\",no-pty ssh-ed25519 ~A~%" blob))
               (with-open-file (out without-command :direction :output
                                                   :if-exists :supersede
                                                   :if-does-not-exist :create)
                 (format out "no-pty ssh-ed25519 ~A~%" blob))
               ;; The pre-authentication gate defers this mode to the key.
               (is (bursyk-server::root-login-allowed-p nil "root"))
               (let* ((bursyk-server::*options*
                        (list :authorized-keys with-command))
                      (server (cl-pnet-ssh::%make-ssh-server
                               :sshd-config config))
                      (session (cl-pnet-ssh::%make-ssh-session
                                :server server)))
                 (multiple-value-bind (matched environment authorization)
                     (bursyk-server::authorized-keys-p "root" key nil session)
                   (declare (ignore environment))
                   (is (not (null matched)))
                   (is (equal "id"
                              (cl-pnet-ssh:ssh-authorization-options-force-command
                               authorization)))))
               (let* ((bursyk-server::*options*
                        (list :authorized-keys without-command))
                      (server (cl-pnet-ssh::%make-ssh-server
                               :sshd-config config))
                      (session (cl-pnet-ssh::%make-ssh-session
                                :server server)))
                 (is (null (bursyk-server::authorized-keys-p
                            "root" key nil session)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test forced-commands-only-root-admits-only-a-public-key
  ;; Password, keyboard-interactive and hostbased cannot carry command=, so
  ;; they must not satisfy PermitRootLogin forced-commands-only.
  (if (null (nth-value 1 (bursyk-server::user-home-and-uid "root")))
      (skip "no local root account")
      (let ((bursyk-server::*server-config*
              (config-from-text "PermitRootLogin forced-commands-only")))
        (is (bursyk-server::root-login-allowed-p nil "root" "publickey"))
        (dolist (method '("password" "keyboard-interactive" "hostbased"))
          (is (not (bursyk-server::root-login-allowed-p
                    nil "root" method))
              method)))))

(test prohibit-password-root-refuses-interactive-methods
  (if (null (nth-value 1 (bursyk-server::user-home-and-uid "root")))
      (skip "no local root account")
      (let ((bursyk-server::*server-config*
              (config-from-text "PermitRootLogin prohibit-password")))
        (is (bursyk-server::root-login-allowed-p nil "root" "publickey"))
        (is (bursyk-server::root-login-allowed-p nil "root" "hostbased"))
        (is (not (bursyk-server::root-login-allowed-p nil "root" "password")))
        (is (not (bursyk-server::root-login-allowed-p
                  nil "root" "keyboard-interactive"))))))

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
  
(test forced-command-replaces-the-clients-choice
  "command= runs instead of exec or shell and carries SSH_ORIGINAL_COMMAND."
  (let* ((authorization
           (nth-value 0
                      (cl-pnet-ssh:ssh-authorized-key-options-parse
                       "command=\"echo forced\"")))
         (session (cl-pnet-ssh::%make-ssh-session))
         (channel (cl-pnet-ssh::%make-ssh-server-channel
                   :session session :local-id 1 :type "session"
                   :state :open))
         (started '()))
    (setf (cl-pnet-ssh:ssh-session-authorization session) authorization)
    (labels ((start (channel command &key extra-environment chroot)
               (declare (ignore channel chroot))
               (push (list command extra-environment) started)
               nil))
      (let ((original (symbol-function 'bursyk-server::start-command)))
        (unwind-protect
             (progn
               (setf (symbol-function 'bursyk-server::start-command) #'start)
               (bursyk-server::install-channel-handlers channel)
               (funcall (cl-pnet-ssh:ssh-server-channel-on-exec channel)
                        channel "client-command")
               (funcall (funcall (cl-pnet-ssh:ssh-server-channel-on-shell channel)
                                 channel))
               ;; The key's command replaces both requests; only the exec one
               ;; leaves the client's own command visible as the original.
               (is (equal '(("echo forced"
                             (("SSH_ORIGINAL_COMMAND" . "client-command")))
                            ("echo forced" nil))
                          (nreverse started))))
          (setf (symbol-function 'bursyk-server::start-command) original))))))

(test match-subsystem-overrides-the-global-list
  "10.6 allows Subsystem in Match; a matching block replaces the global list."
  (let* ((config (config-from-text
                  "Subsystem sftp /global/sftp
Match User alice
  Subsystem sftp /alice/sftp"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (equal '(("sftp" . "/alice/sftp"))
               (cl-pnet-ssh:ssh-server-config-subsystems alice)))
    (is (equal '(("sftp" . "/global/sftp"))
               (cl-pnet-ssh:ssh-server-config-subsystems bob)))))

(test admin-forced-command-wins-over-the-keys
  "ForceCommand replaces exec, shell and subsystem, and outranks command=."
  (let* ((authorization
           (nth-value 0
                      (cl-pnet-ssh:ssh-authorized-key-options-parse
                       "command=\"echo from-key\"")))
         (config (config-from-text
                  "ForceCommand echo from-config
Subsystem sftp /usr/lib/openssh/sftp-server"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (channel (cl-pnet-ssh::%make-ssh-server-channel
                   :session session :local-id 1 :type "session"
                   :state :open))
         (bursyk-server::*server-config* config)
         (started '()))
    (setf (cl-pnet-ssh:ssh-session-authorization session) authorization)
    (labels ((start (channel command &key extra-environment chroot)
               (declare (ignore channel chroot))
               (push (list command extra-environment) started)
               nil))
      (let ((original (symbol-function 'bursyk-server::start-command)))
        (unwind-protect
             (progn
               (setf (symbol-function 'bursyk-server::start-command) #'start)
               (bursyk-server::install-channel-handlers channel)
               (funcall (cl-pnet-ssh:ssh-server-channel-on-exec channel)
                        channel "client-command")
               (funcall (funcall (cl-pnet-ssh:ssh-server-channel-on-shell channel)
                                 channel))
               (funcall (funcall
                         (cl-pnet-ssh:ssh-server-channel-on-subsystem channel)
                         channel "sftp"))
               ;; The admin command outranks the key's command= and runs for
               ;; all three requests, with each original command exported.
               (is (equal '(("echo from-config"
                             (("SSH_ORIGINAL_COMMAND" . "client-command")))
                            ("echo from-config" nil)
                            ("echo from-config"
                             (("SSH_ORIGINAL_COMMAND"
                               . "/usr/lib/openssh/sftp-server"))))
                          (nreverse started))))
          (setf (symbol-function 'bursyk-server::start-command) original))))))

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

;;; ---- Certificate authentication ----

(defun certificate-test-keygen-available-p ()
  (handler-case
      (zerop (nth-value 2 (uiop:run-program '("sh" "-c" "command -v ssh-keygen")
                                            :ignore-error-status t
                                            :output nil :error-output nil)))
    (error () nil)))

(defun certificate-test-keygen (&rest arguments)
  (uiop:run-program (cons "ssh-keygen" arguments)
                    :output :string :error-output :string))

(defun certificate-test-key-blob (path)
  "The base64 key blob on the first line of PATH."
  (let ((line (with-open-file (stream path :direction :input)
                (read-line stream))))
    (cl-pnet-ssh:ssh-base64-octets
     (second (uiop:split-string line :separator " ")))))

(defun certificate-test-directory (prefix)
  (merge-pathnames
   (format nil "~A-~D-~D/" prefix (get-universal-time) (random 1000000))
   (uiop:temporary-directory)))

#-win32
(test trusted-user-ca-keys-authorizes-a-user-certificate
  "A certificate from TrustedUserCAKeys logs in through its principal, and
the certificate's force-command and source-address are enforced."
  (if (not (certificate-test-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (certificate-test-directory "bursyk-server-cert"))
             (ca (merge-pathnames "ca" directory))
             (user (merge-pathnames "user" directory))
             (ca-pub (merge-pathnames "ca.pub" directory))
             (principals (merge-pathnames "principals" directory)))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (certificate-test-keygen "-q" "-t" "ed25519" "-N" ""
                                        "-f" (namestring ca))
               (certificate-test-keygen "-q" "-t" "ed25519" "-N" ""
                                        "-f" (namestring user))
               (certificate-test-keygen
                "-q" "-s" (namestring ca) "-I" "server-id"
                "-n" "turtle" "-V" "-1m:+52w"
                "-O" "force-command=echo certified"
                "-O" "source-address=127.0.0.1/32"
                (namestring (merge-pathnames "user.pub" directory)))
               (with-open-file (stream principals :direction :output
                                                  :if-exists :supersede)
                 (write-string "turtle" stream))
               (let* ((cert-blob
                        (certificate-test-key-blob
                         (merge-pathnames "user-cert.pub" directory)))
                      (config
                        (config-from-text
                         (format nil "TrustedUserCAKeys ~A~%~
                                      AuthorizedPrincipalsFile ~A~%~
                                      AuthorizedKeysFile none~%"
                                 ca-pub principals))))
                 (let ((bursyk-server::*server-config* config)
                       (bursyk-server::*options* nil))
                   ;; The principal in the file admits the login; the
                   ;; certificate's force-command becomes the session's.
                   (multiple-value-bind (matched environment options)
                       (bursyk-server::authorized-keys-p
                        "turtle" cert-blob "127.0.0.1")
                     (declare (ignore environment))
                     (is (not (null matched)))
                     (is (string=
                          "echo certified"
                          (cl-pnet-ssh:ssh-authorization-options-force-command
                           options))))
                   ;; A principal the file does not name is refused.
                   (is (null (bursyk-server::authorized-keys-p
                              "other" cert-blob "127.0.0.1")))
                   ;; source-address excludes any other client address.
                   (is (null (bursyk-server::authorized-keys-p
                              "turtle" cert-blob "10.0.0.1"))))
                 ;; A cert-authority line in -A works without TrustedUserCAKeys.
                 (let ((authkeys (merge-pathnames "authkeys" directory)))
                   (with-open-file (stream authkeys :direction :output
                                                    :if-exists :supersede)
                     (format stream "cert-authority,principals=\"turtle\" ~A~%"
                             (with-open-file (ca-file ca-pub)
                               (read-line ca-file))))
                   (let ((bursyk-server::*server-config* nil)
                         (bursyk-server::*options*
                           (list :authorized-keys authkeys)))
                     (multiple-value-bind (matched environment options)
                         (bursyk-server::authorized-keys-p
                          "turtle" cert-blob "127.0.0.1")
                       (declare (ignore environment))
                       (is (not (null matched)))
                       (is (string=
                            "echo certified"
                            (cl-pnet-ssh:ssh-authorization-options-force-command
                             options))))
                     ;; The CA's own key is not a login key on such a line.
                     (is (null (bursyk-server::authorized-keys-p
                                "turtle"
                                (certificate-test-key-blob ca-pub)
                                "127.0.0.1")))))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test certificate-command-line-splitting-follows-sshd
  "AuthorizedPrincipalsCommand is split the way argv_split does."
  (is (equal '("echo" "one" "two words")
             (bursyk-server::split-command-arguments
              "echo one \"two words\"")))
  (is (equal '("a b" "c")
             (bursyk-server::split-command-arguments "a\\ b c")))
  (is (string= "echo turtle xssh-ed25519"
               (bursyk-server::expand-command-tokens
                "echo %u x%T"
                (list (cons #\u "turtle") (cons #\T "ssh-ed25519")))))
  ;; %% is a literal percent sign.
  (is (string= "100%" (bursyk-server::expand-command-tokens
                       "100%%" (list (cons #\% "%")))))
  (let ((unmatched
          (handler-case
              (progn (bursyk-server::split-command-arguments "\"unclosed") nil)
            (error () t))))
    (is (not (null unmatched)))))

;;; ---- RevokedKeys ----

(defun revoked-test-key (seed)
  "An ssh-ed25519 public key blob for a deterministic test key."
  (cl-pnet-ssh:ssh-make-public-key-blob
   "ssh-ed25519"
   (make-array 32 :element-type '(unsigned-byte 8) :initial-element seed)))

(defun revoked-test-file (contents &key binary)
  (let ((path (merge-pathnames
               (format nil "bursyk-revoked-~D-~D"
                       (get-universal-time) (random 1000000))
               (uiop:temporary-directory))))
    (with-open-file (stream path :direction :output :if-exists :supersede
                                 :element-type (if binary
                                                   '(unsigned-byte 8)
                                                   'character))
      (if binary
          (write-sequence contents stream)
          (write-string contents stream)))
    path))

(defun revoked-test-string (octets)
  (let ((writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-string writer octets)
    (cl-pnet-ssh:ssh-writer-output writer)))

(defun revoked-test-krl-header (writer)
  (cl-pnet-ssh:ssh-write-octets writer cl-pnet-ssh::+ssh-krl-magic+)
  (cl-pnet-ssh:ssh-write-u32 writer 1)
  (cl-pnet-ssh:ssh-write-u64 writer 0)
  (cl-pnet-ssh:ssh-write-u64 writer 0)
  (cl-pnet-ssh:ssh-write-u64 writer 0)
  (cl-pnet-ssh:ssh-write-string writer #())       ; reserved
  (cl-pnet-ssh:ssh-write-string writer #())       ; comment
  writer)

(defun revoked-test-krl (sections)
  "A KRL from SECTIONS, a list of (TYPE . DATA-OCTETS) pairs."
  (let ((writer (revoked-test-krl-header (cl-pnet-ssh:ssh-writer))))
    (dolist (section sections)
      (cl-pnet-ssh:ssh-write-u8 writer (car section))
      (cl-pnet-ssh:ssh-write-string writer (cdr section)))
    (cl-pnet-ssh:ssh-writer-output writer)))

(defun revoked-test-extension (name critical)
  (let ((writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-text writer name)
    (cl-pnet-ssh:ssh-write-boolean writer critical)
    (cl-pnet-ssh:ssh-write-string writer #())
    (cl-pnet-ssh:ssh-writer-output writer)))

(defun revoked-test-cert-section (ca-key subsection-type subsection-writer)
  "A certificates KRL section for CA-KEY with one subsection."
  (let ((writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-string writer ca-key)
    (cl-pnet-ssh:ssh-write-string writer #())
    (cl-pnet-ssh:ssh-write-u8 writer subsection-type)
    (cl-pnet-ssh:ssh-write-string
     writer (funcall subsection-writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-writer-output writer)))

(defun revoked-test-serial-subsection (writer)
  (cl-pnet-ssh:ssh-write-u64 writer 42)
  (cl-pnet-ssh:ssh-writer-output writer))

(defun revoked-test-key-id-subsection (writer)
  (cl-pnet-ssh:ssh-write-text writer "revoked-test-id")
  (cl-pnet-ssh:ssh-writer-output writer))

(test revoked-keys-text-file-revokes-a-listed-key
  "A text RevokedKeys file refuses the key it names and no other key."
  (let* ((key (revoked-test-key 1))
         (other (revoked-test-key 2))
         (path (revoked-test-file
                (format nil "# revoked~%ssh-ed25519 ~A listed~%"
                        (cl-pnet-ssh:ssh-octets-base64 key)))))
    (unwind-protect
         (progn
           (is (cl-pnet-ssh:ssh-key-revoked-in-file-p key path))
           (is (not (cl-pnet-ssh:ssh-key-revoked-in-file-p other path)))
           (is (cl-pnet-ssh:ssh-key-revoked-p key (list path)))
           (is (not (cl-pnet-ssh:ssh-key-revoked-p other (list path)))))
      (ignore-errors (delete-file path)))))

(test revoked-keys-unreadable-or-malformed-fails-closed
  "A broken list signals so the server refuses, as sshd does."
  (let ((key (revoked-test-key 3))
        (path (revoked-test-file "this is not a public key")))
    (unwind-protect
         (signals cl-pnet-ssh:ssh-revoked-keys-error
           (cl-pnet-ssh:ssh-key-revoked-in-file-p key path))
      (ignore-errors (delete-file path))))
  (signals cl-pnet-ssh:ssh-revoked-keys-error
    (cl-pnet-ssh:ssh-key-revoked-in-file-p
     (revoked-test-key 4) "/nonexistent/bursyk-revoked-keys"))
  ;; A truncated KRL is a parse error, not a quiet "not revoked".
  (let* ((key (revoked-test-key 11))
         (krl (revoked-test-krl
               (list (cons 2 (revoked-test-string key)))))
         (path (revoked-test-file (subseq krl 0 20) :binary t)))
    (unwind-protect
         (signals cl-pnet-ssh:ssh-revoked-keys-error
           (cl-pnet-ssh:ssh-key-revoked-in-file-p key path))
      (ignore-errors (delete-file path))))
  ;; A certificate section naming a malformed CA key cannot revoke what it
  ;; was meant to, so the whole KRL is refused.
  (let ((path (revoked-test-file
               (revoked-test-krl
                (list (cons 1
                            (revoked-test-cert-section
                             #(1 2 3) #x20
                             #'revoked-test-serial-subsection))))
               :binary t)))
    (unwind-protect
         (signals cl-pnet-ssh:ssh-revoked-keys-error
           (cl-pnet-ssh:ssh-key-revoked-in-file-p (revoked-test-key 12) path))
      (ignore-errors (delete-file path))))
  ;; A truncated key line is a parse error, not a silent no-match.
  (let* ((key (revoked-test-key 13))
         (short (subseq key 0 (1- (length key))))
         (path (revoked-test-file
                (format nil "ssh-ed25519 ~A~%"
                        (cl-pnet-ssh:ssh-octets-base64 short)))))
    (unwind-protect
         (signals cl-pnet-ssh:ssh-revoked-keys-error
           (cl-pnet-ssh:ssh-key-revoked-in-file-p key path))
      (ignore-errors (delete-file path)))))

(test revoked-keys-krl-explicit-key-and-fingerprint
  "A KRL revokes an explicit key and a key by its SHA256 fingerprint."
  (let* ((key (revoked-test-key 5))
         (other (revoked-test-key 6))
         (explicit (revoked-test-krl
                    (list (cons 2 (revoked-test-string key)))))
         (fingerprint
           (revoked-test-krl
            (list (cons 5 (revoked-test-string
                           (cl-pnet-ssh:ssh-hash :sha256 key))))))
         (explicit-path (revoked-test-file explicit :binary t))
         (fingerprint-path (revoked-test-file fingerprint :binary t)))
    (unwind-protect
         (progn
           (is (cl-pnet-ssh:ssh-key-revoked-in-file-p key explicit-path))
           (is (not (cl-pnet-ssh:ssh-key-revoked-in-file-p
                     other explicit-path)))
           (is (cl-pnet-ssh:ssh-key-revoked-in-file-p key fingerprint-path))
           (is (not (cl-pnet-ssh:ssh-key-revoked-in-file-p
                     other fingerprint-path))))
      (ignore-errors (delete-file explicit-path))
      (ignore-errors (delete-file fingerprint-path)))))

(test revoked-keys-krl-extension-and-signature-sections
  "A non-critical extension is skipped and a critical one refuses the KRL;
OpenSSH refuses a KRL whose signature section it cannot verify."
  (let* ((key (revoked-test-key 7))
         (ignored
           (revoked-test-krl
            (list (cons 255 (revoked-test-extension "vendor@example" nil))
                  (cons 2 (revoked-test-string key)))))
         (ignored-path (revoked-test-file ignored :binary t))
         (critical
           (revoked-test-krl
            (list (cons 255 (revoked-test-extension "vendor@example" t))
                  (cons 2 (revoked-test-string key)))))
         (critical-path (revoked-test-file critical :binary t)))
    (unwind-protect
         (progn
           (is (cl-pnet-ssh:ssh-key-revoked-in-file-p key ignored-path))
           (signals cl-pnet-ssh:ssh-revoked-keys-error
             (cl-pnet-ssh:ssh-key-revoked-in-file-p key critical-path)))
      (ignore-errors (delete-file ignored-path))
      (ignore-errors (delete-file critical-path))))
  ;; A signature section carries two strings, not one section-data string,
  ;; and OpenSSH 9.4 and later refuse the whole KRL because of it.
  (let* ((key (revoked-test-key 8))
         (writer (revoked-test-krl-header (cl-pnet-ssh:ssh-writer))))
    (cl-pnet-ssh:ssh-write-u8 writer 4)
    (cl-pnet-ssh:ssh-write-string writer #())
    (cl-pnet-ssh:ssh-write-string writer #())
    (cl-pnet-ssh:ssh-write-u8 writer 2)
    (cl-pnet-ssh:ssh-write-string writer (revoked-test-string key))
    (let ((path (revoked-test-file
                 (cl-pnet-ssh:ssh-writer-output writer) :binary t)))
      (unwind-protect
           (signals cl-pnet-ssh:ssh-revoked-keys-error
             (cl-pnet-ssh:ssh-key-revoked-in-file-p key path))
        (ignore-errors (delete-file path))))))

(test server-refuses-a-revoked-key
  "The authorization hook refuses a key listed in RevokedKeys and fails
closed when the configured file cannot be read."
  (let* ((key (revoked-test-key 9))
         (line (format nil "ssh-ed25519 ~A"
                       (cl-pnet-ssh:ssh-octets-base64 key)))
         (path (revoked-test-file (format nil "~A~%" line)))
         (allowed (cl-pnet-ssh::%make-ssh-server
                   :authorized-keys (list line)))
         (revoked (cl-pnet-ssh::%make-ssh-server
                   :authorized-keys (list line)
                   :sshd-config
                   (config-from-text
                    (format nil "RevokedKeys ~A" (namestring path)))))
         (missing (cl-pnet-ssh::%make-ssh-server
                   :authorized-keys (list line)
                   :sshd-config
                   (config-from-text
                    "RevokedKeys /nonexistent/bursyk-revoked-keys"))))
    (unwind-protect
         (progn
           (is (cl-pnet-ssh::ssh-server-authorized-key-p
                allowed "turtle" key))
           (is (null (cl-pnet-ssh::ssh-server-authorized-key-p
                      revoked "turtle" key)))
           (is (null (cl-pnet-ssh::ssh-server-authorized-key-p
                      missing "turtle" key))))
      (ignore-errors (delete-file path)))))

#-win32
(test revoked-keys-refuses-a-revoked-certificate
  "A text list naming the CA revokes its certificates; a KRL can revoke the
certificate's plain key, its serial, or its key ID."
  (if (not (certificate-test-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (certificate-test-directory "bursyk-revoked-cert"))
             (ca (merge-pathnames "ca" directory))
             (user (merge-pathnames "user" directory))
             (ca-pub (merge-pathnames "ca.pub" directory))
             (user-pub (merge-pathnames "user.pub" directory)))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (certificate-test-keygen "-q" "-t" "ed25519" "-N" ""
                                        "-f" (namestring ca))
               (certificate-test-keygen "-q" "-t" "ed25519" "-N" ""
                                        "-f" (namestring user))
               (certificate-test-keygen
                "-q" "-s" (namestring ca) "-I" "revoked-test-id"
                "-n" "turtle" "-V" "-1m:+52w" "-z" "42"
                (namestring user-pub))
               (let* ((ca-blob (certificate-test-key-blob ca-pub))
                      (user-blob (certificate-test-key-blob user-pub))
                      (cert-blob
                        (certificate-test-key-blob
                         (merge-pathnames "user-cert.pub" directory)))
                      (ca-text (revoked-test-file
                                (with-open-file (stream ca-pub)
                                  (read-line stream))))
                      (plain-text (revoked-test-file
                                   (with-open-file (stream user-pub)
                                     (read-line stream))))
                      (cert-text
                        (revoked-test-file
                         (with-open-file
                             (stream
                              (merge-pathnames "user-cert.pub" directory))
                           (read-line stream))))
                      (explicit-path
                        (revoked-test-file
                         (revoked-test-krl
                          (list (cons 2 (revoked-test-string user-blob))))
                         :binary t))
                      (serial-path
                        (revoked-test-file
                         (revoked-test-krl
                          (list (cons 1
                                      (revoked-test-cert-section
                                       ca-blob #x20
                                       #'revoked-test-serial-subsection))))
                         :binary t))
                      (key-id-path
                        (revoked-test-file
                         (revoked-test-krl
                          (list (cons 1
                                      (revoked-test-cert-section
                                       ca-blob #x23
                                       #'revoked-test-key-id-subsection))))
                         :binary t)))
                 ;; A text list revokes a certificate through its CA.
                 (is (cl-pnet-ssh:ssh-key-revoked-in-file-p cert-blob ca-text))
                 ;; The plain key is compared by key material, so naming the
                 ;; certified key revokes the certificate too.
                 (is (cl-pnet-ssh:ssh-key-revoked-in-file-p
                      cert-blob plain-text))
                 ;; A certificate line in the text list stands for the plain
                 ;; key it certifies, as sshkey_equal_public compares them.
                 (is (cl-pnet-ssh:ssh-key-revoked-in-file-p
                      user-blob cert-text))
                 ;; A KRL's explicit-key section does match the plain key.
                 (is (cl-pnet-ssh:ssh-key-revoked-in-file-p
                      cert-blob explicit-path))
                 (is (cl-pnet-ssh:ssh-key-revoked-in-file-p
                      cert-blob serial-path))
                 (is (cl-pnet-ssh:ssh-key-revoked-in-file-p
                      cert-blob key-id-path))
                 ;; The serial is per CA and the certificate's serial is 42.
                 (let ((other-serial
                         (revoked-test-file
                          (revoked-test-krl
                           (list (cons 1
                                       (revoked-test-cert-section
                                        ca-blob #x20
                                        (lambda (writer)
                                          (cl-pnet-ssh:ssh-write-u64 writer 43)
                                          (cl-pnet-ssh:ssh-writer-output
                                           writer))))))
                          :binary t)))
                   (unwind-protect
                        (is (not (cl-pnet-ssh:ssh-key-revoked-in-file-p
                                  cert-blob other-serial)))
                     (ignore-errors (delete-file other-serial))))
                 ;; A serial range and a serial bitmap also match serial 42.
                 (flet ((serial-file (type writer)
                          (revoked-test-file
                           (revoked-test-krl
                            (list (cons 1
                                        (revoked-test-cert-section
                                         ca-blob type writer))))
                           :binary t)))
                   (let ((range-path
                           (serial-file
                            #x21
                            (lambda (writer)
                              (cl-pnet-ssh:ssh-write-u64 writer 10)
                              (cl-pnet-ssh:ssh-write-u64 writer 50)
                              (cl-pnet-ssh:ssh-writer-output writer))))
                         (bitmap-path
                           (serial-file
                            #x22
                            (lambda (writer)
                              (cl-pnet-ssh:ssh-write-u64 writer 40)
                              (cl-pnet-ssh:ssh-write-mpint writer 4)
                              (cl-pnet-ssh:ssh-writer-output writer))))
                         (bad-range-path
                           (serial-file
                            #x21
                            (lambda (writer)
                              (cl-pnet-ssh:ssh-write-u64 writer 1)
                              (cl-pnet-ssh:ssh-write-u64 writer 2)
                              (cl-pnet-ssh:ssh-write-u64 writer 3)
                              (cl-pnet-ssh:ssh-write-u64 writer 4)
                              (cl-pnet-ssh:ssh-writer-output writer)))))
                     (unwind-protect
                          (progn
                            (is (cl-pnet-ssh:ssh-key-revoked-in-file-p
                                 cert-blob range-path))
                            (is (cl-pnet-ssh:ssh-key-revoked-in-file-p
                                 cert-blob bitmap-path))
                            ;; A range subsection holds exactly one pair.
                            (signals cl-pnet-ssh:ssh-revoked-keys-error
                              (cl-pnet-ssh:ssh-key-revoked-in-file-p
                               cert-blob bad-range-path)))
                       (dolist (path (list range-path bitmap-path
                                           bad-range-path))
                         (ignore-errors (delete-file path))))))
                 (dolist (path (list ca-text plain-text cert-text
                                     explicit-path serial-path key-id-path))
                   (ignore-errors (delete-file path))))
               (ignore-errors
                 (delete-file (merge-pathnames "user-cert.pub" directory))))
          (ignore-errors
            (uiop:delete-directory-tree directory :validate t))))))

#-win32
(test revoked-keys-reads-a-krl-written-by-ssh-keygen
  "The KRL ssh-keygen writes is parsed like the one OpenSSH reads."
  (if (not (certificate-test-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (certificate-test-directory "bursyk-real-krl"))
             (key (merge-pathnames "key" directory))
             (other (merge-pathnames "other" directory))
             (krl (merge-pathnames "revoked.krl" directory)))
        (ensure-directories-exist key)
        (unwind-protect
             (progn
               (certificate-test-keygen "-q" "-t" "ed25519" "-N" ""
                                        "-f" (namestring key))
               (certificate-test-keygen "-q" "-t" "ed25519" "-N" ""
                                        "-f" (namestring other))
               (certificate-test-keygen "-q" "-k" "-f" (namestring krl)
                                        (namestring
                                         (merge-pathnames "key.pub" directory)))
               (is (cl-pnet-ssh:ssh-key-revoked-in-file-p
                    (certificate-test-key-blob
                     (merge-pathnames "key.pub" directory))
                    krl))
               (is (not (cl-pnet-ssh:ssh-key-revoked-in-file-p
                         (certificate-test-key-blob
                          (merge-pathnames "other.pub" directory))
                         krl))))
          (ignore-errors
            (uiop:delete-directory-tree directory :validate t))))))

;;; ---- AuthorizedKeysCommand ----

(test sshd-config-reads-authorizedkeyscommand
  "AuthorizedKeysCommand keeps its arguments, needs an absolute program and
a user, may be disabled with none, and is a per-connection Match setting."
  (is (equal "/usr/local/bin/find-keys %u"
             (config-value
              #'cl-pnet-ssh:ssh-server-config-authorized-keys-command
              "AuthorizedKeysCommand /usr/local/bin/find-keys %u
AuthorizedKeysCommandUser keys")))
  (is (equal "keys"
             (config-value
              #'cl-pnet-ssh:ssh-server-config-authorized-keys-command-user
              "AuthorizedKeysCommand /usr/local/bin/find-keys
AuthorizedKeysCommandUser keys")))
  ;; The first line wins, but a later line is still validated.
  (is (equal "/first"
             (config-value
              #'cl-pnet-ssh:ssh-server-config-authorized-keys-command
              "AuthorizedKeysCommand /first
AuthorizedKeysCommand /second
AuthorizedKeysCommandUser keys")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text
     "AuthorizedKeysCommand /first
AuthorizedKeysCommand not-absolute
AuthorizedKeysCommandUser keys"))
  ;; none needs no user and disables the command.
  (is (eq :none
          (config-value
           #'cl-pnet-ssh:ssh-server-config-authorized-keys-command
           "AuthorizedKeysCommand none")))
  ;; sshd refuses a program that is not an absolute path, and a command
  ;; with no account to run it as.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text
     "AuthorizedKeysCommand find-keys
AuthorizedKeysCommandUser keys"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AuthorizedKeysCommand /usr/local/bin/find-keys"))
  ;; A Match block may name the command, and none there disables a global
  ;; command while the inherited user stays in place.
  (let* ((config (config-from-text
                  "AuthorizedKeysCommand /global/keys
AuthorizedKeysCommandUser keys
Match User alice
  AuthorizedKeysCommand /alice/keys
Match User bob
  AuthorizedKeysCommand none"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (equal "/alice/keys"
               (cl-pnet-ssh:ssh-server-config-authorized-keys-command alice)))
    (is (equal "keys"
               (cl-pnet-ssh:ssh-server-config-authorized-keys-command-user
                alice)))
    (is (eq :none
            (cl-pnet-ssh:ssh-server-config-authorized-keys-command bob)))))

(test sshd-config-reads-authorizedprincipalscommand
  "The principals command keeps its arguments, needs an absolute program and
a user, and may be disabled with none."
  (is (equal "/usr/local/bin/find-principals %u"
             (config-value
              #'cl-pnet-ssh:ssh-server-config-authorized-principals-command
              "AuthorizedPrincipalsCommand /usr/local/bin/find-principals %u
AuthorizedPrincipalsCommandUser keys")))
  (is (equal "keys"
             (config-value
              #'cl-pnet-ssh:ssh-server-config-authorized-principals-command-user
              "AuthorizedPrincipalsCommand /usr/local/bin/find-principals
AuthorizedPrincipalsCommandUser keys")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text
     "AuthorizedPrincipalsCommand find-principals
AuthorizedPrincipalsCommandUser keys"))
  ;; sshd's startup check refuses a command with no account to run it as,
  ;; but "none" needs none.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AuthorizedPrincipalsCommand /usr/local/bin/find-principals"))
  (is (not (null (config-from-text "AuthorizedPrincipalsCommand none"))))
  ;; A command only inside a Match block does not fail the global startup
  ;; check; it authorizes nothing at connection time until a user is set.
  (is (not (null (config-from-text
                  "Match User alice
  AuthorizedPrincipalsCommand /usr/local/bin/find-principals")))))

#-win32
(defun authorized-keys-command-temp-path (prefix)
  "An unused path under the temporary directory."
  (merge-pathnames
   (format nil "bursyk-~A-~D-~D" prefix (get-universal-time) (random 1000000))
   (uiop:temporary-directory)))

#-win32
(defun authorized-keys-command-script (body)
  "A temporary executable shell script running BODY."
  (let ((path (authorized-keys-command-temp-path "authorized-keys")))
    (with-open-file (stream path :direction :output :if-exists :supersede
                                 :if-does-not-exist :create)
      (format stream "#!/bin/sh~%~A~%" body))
    (uiop:run-program (list "chmod" "700" (namestring path)))
    path))

#-win32
(test authorized-keys-command-supplies-a-key
  "The command's output is read as authorized_keys, its tokens expand, and
its options are applied like a file's."
  (let* ((user (bursyk-server::current-user-name))
         (key (revoked-test-key 21))
         (other (revoked-test-key 22))
         (line (format nil "ssh-ed25519 ~A"
                       (cl-pnet-ssh:ssh-octets-base64 key)))
         (args (authorized-keys-command-temp-path "command-args"))
         (output (authorized-keys-command-temp-path "command-out")))
    (unwind-protect
         (progn
           (with-open-file (stream output :direction :output
                                          :if-exists :supersede
                                          :if-does-not-exist :create)
             (format stream "command=\"echo hi\" ~A~%" line))
           (let* ((script
                    (authorized-keys-command-script
                     (format nil "printf '%s\\n' \"$@\" > ~A~%cat ~A"
                             (namestring args) (namestring output))))
                  (config
                    (config-from-text
                     (format nil "AuthorizedKeysCommand ~A %u %U %t %f %k %% %D~%AuthorizedKeysCommandUser ~A"
                             (namestring script) user))))
             (multiple-value-bind (home uid)
                 (bursyk-server::user-home-and-uid user)
               (declare (ignore home))
               (let ((bursyk-server::*server-config* config)
                     (bursyk-server::*options* nil))
                 (multiple-value-bind (matched environment authorization)
                     (bursyk-server::authorized-keys-p
                      user key "127.0.0.1")
                   (declare (ignore environment))
                   (is (not (null matched)))
                   (is (string=
                        "echo hi"
                        (cl-pnet-ssh:ssh-authorization-options-force-command
                         authorization)))
                   ;; sshd's tokens for this command.
                   (is (equal (list user
                                    (or uid "")
                                    "ssh-ed25519"
                                    (cl-pnet-ssh:ssh-key-fingerprint key)
                                    (cl-pnet-ssh:ssh-octets-base64 key)
                                    "%"
                                    "")
                              (uiop:read-file-lines args)))
                   ;; A key the command does not print is not authorized.
                   (is (null (bursyk-server::authorized-keys-p
                              user other "127.0.0.1")))))))
      (ignore-errors (delete-file args))
      (ignore-errors (delete-file output))))))

#-win32
(test authorized-keys-command-runs-after-the-key-files
  "A key found in AuthorizedKeysFile is not looked for in the command, and
a command that exits nonzero authorizes nothing even if it printed the key."
  (let* ((user (bursyk-server::current-user-name))
         (key (revoked-test-key 23))
         (line (format nil "ssh-ed25519 ~A"
                       (cl-pnet-ssh:ssh-octets-base64 key)))
         (marker (authorized-keys-command-temp-path "command-ran"))
         (output (authorized-keys-command-temp-path "command-keys"))
         (keys-file (revoked-test-file (format nil "~A~%" line))))
    (unwind-protect
         (progn
           (with-open-file (stream output :direction :output
                                          :if-exists :supersede
                                          :if-does-not-exist :create)
             (format stream "~A~%" line))
           (let* ((script
                    (authorized-keys-command-script
                     (format nil "printf ran > ~A" (namestring marker))))
                  (config
                    (config-from-text
                     (format nil "AuthorizedKeysFile ~A~%AuthorizedKeysCommand ~A~%AuthorizedKeysCommandUser ~A"
                             (namestring keys-file)
                             (namestring script) user))))
             (let ((bursyk-server::*server-config* config)
                   (bursyk-server::*options* nil))
               (is (not (null (bursyk-server::authorized-keys-p
                               user key "127.0.0.1"))))
               (is (not (probe-file marker)))))
           ;; A nonzero exit discards a matching line.
           (let* ((script
                    (authorized-keys-command-script
                     (format nil "cat ~A; exit 1" (namestring output))))
                  (config
                    (config-from-text
                     (format nil "AuthorizedKeysCommand ~A~%AuthorizedKeysCommandUser ~A"
                             (namestring script) user))))
             (let ((bursyk-server::*server-config* config)
                   (bursyk-server::*options* nil))
               (is (null (bursyk-server::authorized-keys-p
                          user key "127.0.0.1"))))))
      (ignore-errors (delete-file keys-file))
      (ignore-errors (delete-file marker))
      (ignore-errors (delete-file output)))))

#-win32
(test authorized-keys-command-refuses-a-missing-or-different-user
  "Without a user, or with an account this server cannot switch to, the
command yields no keys.  A command with no argument gets the user's name."
  (let* ((user (bursyk-server::current-user-name))
         (key (revoked-test-key 24))
         (line (format nil "ssh-ed25519 ~A"
                       (cl-pnet-ssh:ssh-octets-base64 key)))
         (script (authorized-keys-command-script
                  (format nil "printf '%s\\n' '~A'" line)))
         (args (authorized-keys-command-temp-path "command-args"))
         (recorder
           (authorized-keys-command-script
            (format nil "printf '%s\\n' \"$@\" > ~A; printf '%s\\n' '~A'"
                    (namestring args) line))))
    (unwind-protect
         (progn
           (is (null (bursyk-server::authorized-keys-command-lines
                      (namestring script) nil user nil nil key)))
           (is (null (bursyk-server::authorized-keys-command-lines
                      (namestring script) "not-the-server-account"
                      user nil nil key)))
           (is (not (null (bursyk-server::authorized-keys-command-lines
                           (namestring recorder) user user nil nil key))))
           (is (equal (list user) (uiop:read-file-lines args))))
      (ignore-errors (delete-file script))
      (ignore-errors (delete-file recorder))
      (ignore-errors (delete-file args)))))

#-win32
(test authorized-keys-command-can-name-a-certificate-authority
  "A cert-authority line printed by the command admits a certificate when
no file or TrustedUserCAKeys does."
  (if (not (certificate-test-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (certificate-test-directory "bursyk-command-cert"))
             (ca (merge-pathnames "ca" directory))
             (user-key (merge-pathnames "user" directory))
             (ca-pub (merge-pathnames "ca.pub" directory)))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (certificate-test-keygen "-q" "-t" "ed25519" "-N" ""
                                        "-f" (namestring ca))
               (certificate-test-keygen "-q" "-t" "ed25519" "-N" ""
                                        "-f" (namestring user-key))
               (certificate-test-keygen
                "-q" "-s" (namestring ca) "-I" "server-id"
                "-n" "turtle" "-V" "-1m:+52w"
                (namestring (merge-pathnames "user.pub" directory)))
               (let* ((cert-blob
                        (certificate-test-key-blob
                         (merge-pathnames "user-cert.pub" directory)))
                      (ca-line
                        (with-open-file (stream ca-pub)
                          (read-line stream)))
                      (output
                        (revoked-test-file
                         (format nil "cert-authority ~A~%" ca-line)))
                      (script
                        (authorized-keys-command-script
                         (format nil "cat ~A" (namestring output))))
                      (config
                        (config-from-text
                         (format nil "AuthorizedKeysCommand ~A~%AuthorizedKeysCommandUser ~A"
                                 (namestring script)
                                 (bursyk-server::current-user-name)))))
                 (unwind-protect
                      (let ((bursyk-server::*server-config* config)
                            (bursyk-server::*options* nil))
                        (is (not (null (bursyk-server::authorized-keys-p
                                        "turtle" cert-blob "127.0.0.1"))))
                        ;; Another user is not the certificate's principal.
                        (is (null (bursyk-server::authorized-keys-p
                                   "other" cert-blob "127.0.0.1"))))
                   (ignore-errors (delete-file output)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

;;; ---- ExposeAuthInfo ----

#-win32
(test expose-auth-info-writes-the-authenticated-key
  "SSH_USER_AUTH names a 0600 file holding sshd's publickey line, and the
file is removed with the session."
  (let* ((key (revoked-test-key 25))
         (config (config-from-text "ExposeAuthInfo yes"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server :user "alice" :authorized-key key)))
    (unwind-protect
         (let ((path (bursyk-server::write-auth-info-file session)))
           (is (stringp path))
           (is (probe-file path))
           (is (equal (list (format nil "publickey ssh-ed25519 ~A"
                                    (cl-pnet-ssh:ssh-octets-base64 key)))
                      (uiop:read-file-lines path)))
           ;; sshd's mkstemp makes the file readable only by its owner.
           (is (equal "600"
                      (uiop:run-program
                       (list "stat" "-c" "%a" path)
                       :output '(:string :stripped t))))
           (is (equal path (bursyk-server::auth-info-file session))))
      (bursyk-server::delete-auth-info-file session)
      (is (null (bursyk-server::auth-info-file session))))))

(test expose-auth-info-writes-a-certificate-as-its-own-type
  "A certificate is written as its certificate type and certificate blob,
as sshd's sshkey_format_text does for the key that authenticated."
  (let* ((key (cl-pnet-ssh:ssh-make-public-key-blob
               "ssh-ed25519-cert-v01@openssh.com"
               (make-array 16 :element-type '(unsigned-byte 8)
                              :initial-element 7)))
         (config (config-from-text "ExposeAuthInfo yes"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server :user "alice" :authorized-key key)))
    (unwind-protect
         (let ((path (bursyk-server::write-auth-info-file session)))
           (is (equal (list (format nil "publickey ssh-ed25519-cert-v01@openssh.com ~A"
                                    (cl-pnet-ssh:ssh-octets-base64 key)))
                      (uiop:read-file-lines path))))
      (bursyk-server::delete-auth-info-file session))))

(test expose-auth-info-reaches-the-child-environment
  "SSH_USER_AUTH is in the session environment and beats an admin SetEnv."
  (let* ((key (revoked-test-key 26))
         (config (config-from-text
                  "ExposeAuthInfo yes
SetEnv SSH_USER_AUTH=/wrong"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server
                   :user "bursyk-test-user-with-no-passwd-entry"
                   :authorized-key key))
         (channel (cl-pnet-ssh::%make-ssh-server-channel :session session)))
    (unwind-protect
         (let* ((path (bursyk-server::write-auth-info-file session))
                (environment (bursyk-server::session-environment channel)))
           (is (equal path
                      (cdr (assoc "SSH_USER_AUTH" environment
                                  :test #'string=))))
           ;; One entry per name, as sshd's child_set_env leaves it.
           (is (= 1 (count "SSH_USER_AUTH" environment
                           :key #'car :test #'string=))))
      (bursyk-server::delete-auth-info-file session))))

(test expose-auth-info-is-off-by-default
  "Without the directive no file is written and no path is remembered."
  (let* ((key (revoked-test-key 27))
         (server (cl-pnet-ssh::%make-ssh-server))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server :user "alice" :authorized-key key)))
    (is (null (bursyk-server::write-auth-info-file session)))
    (is (null (bursyk-server::auth-info-file session)))))

;;; ---- AuthorizedPrincipalsCommand ----

#-win32
(test authorized-principals-command-requires-a-user
  "Without AuthorizedPrincipalsCommandUser nothing runs, and another account
is refused because this server cannot switch users."
  (let* ((user (bursyk-server::current-user-name))
         (marker (authorized-keys-command-temp-path "principals-ran"))
         (script (authorized-keys-command-script
                  (format nil "printf ran > ~A; printf 'turtle\\n'"
                          (namestring marker)))))
    (unwind-protect
         (progn
           (is (null (bursyk-server::authorized-principals-command-lines
                      (namestring script) nil user nil nil nil nil)))
           (is (not (probe-file marker)))
           (is (null (bursyk-server::authorized-principals-command-lines
                      (namestring script) "not-the-server-account"
                      user nil nil nil nil)))
           (is (not (probe-file marker)))
           ;; Invalid quotes are refused rather than signalling into auth.
           (is (null (bursyk-server::authorized-principals-command-lines
                      "\"unclosed" user user nil nil nil nil)))
           (is (not (probe-file marker))))
      (ignore-errors (delete-file script))
      (ignore-errors (delete-file marker)))))

#-win32
(test authorized-principals-command-prints-principals
  "The command runs as the server's account and its output is the principal
list; its arguments expand the certificate's tokens."
  (if (not (certificate-test-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory
               (certificate-test-directory "bursyk-principals-command"))
             (ca (merge-pathnames "ca" directory))
             (user-key (merge-pathnames "user" directory))
             (args (authorized-keys-command-temp-path "principals-args")))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (certificate-test-keygen "-q" "-t" "ed25519" "-N" ""
                                        "-f" (namestring ca))
               (certificate-test-keygen "-q" "-t" "ed25519" "-N" ""
                                        "-f" (namestring user-key))
               (certificate-test-keygen
                "-q" "-s" (namestring ca) "-I" "principals-id"
                "-n" "turtle" "-V" "-1m:+52w"
                (namestring (merge-pathnames "user.pub" directory)))
               (let* ((cert-blob
                        (certificate-test-key-blob
                         (merge-pathnames "user-cert.pub" directory)))
                      (certificate (cl-pnet-ssh:ssh-certificate-parse cert-blob))
                      (script
                        (authorized-keys-command-script
                         (format nil
                                 "printf '%s\\n' \"$@\" > ~A; printf 'turtle\\n'"
                                 (namestring args))))
                      (server-user (bursyk-server::current-user-name)))
                 ;; The trailing newline leaves an empty last line, which
                 ;; the principals matcher ignores like any blank line.
                 (is (equal '("turtle" "")
                            (bursyk-server::authorized-principals-command-lines
                             (format nil "~A %u %i" (namestring script))
                             server-user "turtle" nil nil
                             cert-blob certificate)))
                 (is (equal (list "turtle" "principals-id")
                            (uiop:read-file-lines args)))))
          (ignore-errors (delete-file args))
          (ignore-errors
           (uiop:delete-directory-tree directory :validate t))))))

(test expose-auth-info-writes-one-line-per-method
  "A login that completed several methods records each key's line."
  (let* ((config (config-from-text "ExposeAuthInfo yes"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server :user "alice"
                   :auth-info-lines
                   '("publickey ssh-ed25519 AAAA"
                     "publickey ssh-ed25519 BBBB"))))
    (unwind-protect
         (let ((path (bursyk-server::write-auth-info-file session)))
           (is (equal '("publickey ssh-ed25519 AAAA"
                        "publickey ssh-ed25519 BBBB")
                      (uiop:read-file-lines path))))
      (bursyk-server::delete-auth-info-file session))))

(test sshd-config-recognises-the-10.6-additions
  "10.6 directives that only describe OpenSSH's own helpers are accepted
with a warning rather than becoming unknown keywords."
  (let ((config (config-from-text
                 "SshdSessionPath /usr/libexec/sshd-session
SshdAuthPath /usr/libexec/sshd-auth
PAMServiceName sshd
GSSAPIDelegateCredentials no
WarnWeakCrypto no")))
    (is (plusp (length (cl-pnet-ssh:ssh-server-config-warnings config)))))
  ;; HostKeyAgent is implemented, not ignored.
  (is (equal "/run/agent.sock"
             (config-value
              #'cl-pnet-ssh:ssh-server-config-host-key-agent
              "HostKeyAgent /run/agent.sock"))))

(test sshd-config-reads-agent-forwarding
  "AllowAgentForwarding is a flag and AgentSocketPath accepts sshd's three
forms; a bare path is refused, as 10.6 does."
  (is (eq :yes (config-value
                #'cl-pnet-ssh:ssh-server-config-allow-agent-forwarding
                "AllowAgentForwarding yes")))
  (is (eq :no (config-value
               #'cl-pnet-ssh:ssh-server-config-allow-agent-forwarding
               "AllowAgentForwarding no")))
  (dolist (path '("none" "user:~/.ssh/agent" "shared:/run/agent"))
    (is (equal path
               (config-value
                #'cl-pnet-ssh:ssh-server-config-agent-socket-path
                (format nil "AgentSocketPath ~A" path)))))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AgentSocketPath /run/agent.sock"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AgentSocketPath shared:relative"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AgentSocketPath user:")))

#-win32
(test agent-socket-path-tokens-expand
  "AgentSocketPath's ~ and % tokens expand to the connecting account's
directory and identity, and an unknown token or another account is refused
rather than guessed."
  (let ((home "/home/turtle/"))
    (flet ((expand (text &optional (uid "1000"))
             (bursyk-server::expand-agent-directory text "turtle" home uid)))
      (is (equal "/home/turtle/agent" (expand "~/agent")))
      (is (equal "/home/turtle/agent" (expand "agent")))
      (is (equal "/home/turtle/turtle" (expand "%u")))
      (is (equal "/home/turtle/1000" (expand "%U")))
      (is (equal home (expand "%h")))
      (is (equal "/home/turtle/100%" (expand "100%%")))
      (is (null (expand "~other/agent")))
      (is (null (expand "%q")))
      (is (null (expand ""))))))

#-win32
(defun agent-forward-test-session (pathspec
                                   &optional (user (bursyk-server::current-user-name)))
  "A session whose sshd_config names PATHSPEC for agent forwarding."
  (let* ((config
           (config-from-text
            (format nil "AllowAgentForwarding yes~%AgentSocketPath ~A"
                    pathspec)))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config)))
    (cl-pnet-ssh::%make-ssh-session :server server :user user)))

#-win32
(test agent-forward-listener-is-created-and-removed
  "start-agent-forward follows AgentSocketPath: shared: gets a private
temporary directory per session, user: listens directly in the named
directory, and cleanup removes the socket it made."
  (let ((root (merge-pathnames
               (format nil "bursyk-agent-~D/" (random 1000000))
               (uiop:temporary-directory))))
    (unwind-protect
         (flet ((check (pathspec expected-directory)
                  (let* ((session (agent-forward-test-session pathspec))
                         (fd nil)
                         (path nil)
                         (cleanup nil))
                    (unwind-protect
                         (progn
                           (multiple-value-setq (fd path cleanup)
                             (bursyk-server::start-agent-forward session))
                           (is (integerp fd))
                           (is (stringp path))
                           (is (uiop:subpathp (pathname path)
                                              expected-directory))
                           ;; A leftover file would not accept a connection,
                           ;; so connecting proves the listener is live.
                           (multiple-value-bind (client status)
                               (cl-pnet-sockets:connect-unix path)
                             (declare (ignore status))
                             (is (integerp client))
                             (when client
                               (cl-pnet-sockets:close-open-fd client)))
                           (funcall cleanup)
                           (setf cleanup nil)
                           (is (not (probe-file path))))
                      (when cleanup (funcall cleanup))
                      (when fd (cl-pnet-sockets:close-open-fd fd))))))
           (let ((shared (merge-pathnames "shared/" root))
                 (user-directory (merge-pathnames "user/" root)))
             (check (format nil "shared:~A" (namestring shared)) shared)
             ;; shared: removes the per-session directory as well.
             (is (or (not (uiop:directory-exists-p shared))
                     (null (uiop:subdirectories shared))))
             (check (format nil "user:~A" (namestring user-directory))
                    user-directory)
             ;; none creates nothing at all.
             (is (null (bursyk-server::start-agent-forward
                        (agent-forward-test-session "none"))))))
      (ignore-errors (uiop:delete-directory-tree root :validate t)))))

(test sshd-config-reads-pubkey-auth-options
  "PubkeyAuthOptions keeps the first line's flags and probe budget."
  (let ((config (config-from-text
                 "PubkeyAuthOptions touch-required verify-required max-pk-ok:3")))
    (is (equal '(:touch-required :verify-required)
               (cl-pnet-ssh:ssh-server-config-pubkey-auth-options config)))
    (is (= 3 (cl-pnet-ssh:ssh-server-config-max-pubkey-ok config))))
  (is (eq :none
          (config-value
           #'cl-pnet-ssh:ssh-server-config-pubkey-auth-options
           "PubkeyAuthOptions none")))
  (is (= 0
         (config-value
          #'cl-pnet-ssh:ssh-server-config-max-pubkey-ok
          "PubkeyAuthOptions max-pk-ok:0")))
  ;; A later line is validated but cannot replace the first.
  (let ((config (config-from-text
                 "PubkeyAuthOptions max-pk-ok:2
PubkeyAuthOptions touch-required")))
    (is (= 2 (cl-pnet-ssh:ssh-server-config-max-pubkey-ok config)))
    (is (eq :none
            (cl-pnet-ssh:ssh-server-config-pubkey-auth-options config))))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "PubkeyAuthOptions max-pk-ok:256"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "PubkeyAuthOptions max-pk-ok:"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "PubkeyAuthOptions bogus"))
  (let* ((config (config-from-text
                  "PubkeyAuthOptions max-pk-ok:2
Match User alice
  PubkeyAuthOptions max-pk-ok:5"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (= 5 (cl-pnet-ssh:ssh-server-config-max-pubkey-ok alice)))
    (is (= 2 (cl-pnet-ssh:ssh-server-config-max-pubkey-ok bob)))))

(test sshd-config-reads-refuse-connection
  "RefuseConnection is a Match-aware flag whose first value wins."
  (is (eq :yes
          (config-value
           #'cl-pnet-ssh:ssh-server-config-refuse-connection
           "RefuseConnection yes")))
  (is (eq :no
          (config-value
           #'cl-pnet-ssh:ssh-server-config-refuse-connection
           "RefuseConnection no")))
  (is (eq :yes
          (config-value
           #'cl-pnet-ssh:ssh-server-config-refuse-connection
           "RefuseConnection yes
RefuseConnection no")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "RefuseConnection maybe"))
  (let* ((config (config-from-text
                  "RefuseConnection yes
Match User alice
  RefuseConnection no"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (eq :no (cl-pnet-ssh:ssh-server-config-refuse-connection alice)))
    (is (eq :yes (cl-pnet-ssh:ssh-server-config-refuse-connection bob)))))

(test sshd-config-reads-per-source-penalties
  "PerSourcePenalties keeps the first value of each field and validates all."
  (let ((penalties
          (config-value
           #'cl-pnet-ssh:ssh-server-config-per-source-penalties
           "PerSourcePenalties authfail:10s min:20s max:5m max-sources4:100 overflow:deny-all")))
    (is (eq t (getf penalties :enabled)))
    (is (= 10 (getf penalties :authfail)))
    (is (= 20 (getf penalties :min)))
    (is (= 300 (getf penalties :max)))
    (is (= 100 (getf penalties :max-sources4)))
    (is (eq :deny-all (getf penalties :overflow4))))
  (is (eq t (getf (config-value
                   #'cl-pnet-ssh:ssh-server-config-per-source-penalties
                   "PerSourcePenalties yes")
                  :enabled)))
  (is (eq nil (getf (config-value
                     #'cl-pnet-ssh:ssh-server-config-per-source-penalties
                     "PerSourcePenalties no")
                    :enabled)))
  ;; The first line's fields win, but a later line is still validated.
  (let ((penalties
          (config-value
           #'cl-pnet-ssh:ssh-server-config-per-source-penalties
           "PerSourcePenalties authfail:10
PerSourcePenalties authfail:20 min:3")))
    (is (= 10 (getf penalties :authfail)))
    (is (= 3 (getf penalties :min))))
  (dolist (bad '("PerSourcePenalties no authfail:5"
                 "PerSourcePenalties bogus:5"
                 "PerSourcePenalties max-sources4:x"
                 "PerSourcePenalties"
                 "PerSourcePenalties min:-1"))
    (signals cl-pnet-ssh:ssh-server-config-error
      (config-from-text bad)))
  (is (equal "127.0.0.1/32,10.0.0.0/8"
             (config-value
              #'cl-pnet-ssh:ssh-server-config-per-source-penalty-exempt
              "PerSourcePenaltyExemptList 127.0.0.1/32,10.0.0.0/8")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "PerSourcePenaltyExemptList 192.0.2.0/33"))
  ;; Both directives are global only.
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match User alice
  PerSourcePenalties yes"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match User alice
  PerSourcePenaltyExemptList 127.0.0.1")))

(test sshd-config-reads-chroot-directory
  "ChrootDirectory keeps its tokens, none disables it, and Match overrides."
  (is (equal "/srv/%u"
             (config-value
              #'cl-pnet-ssh:ssh-server-config-chroot-directory
              "ChrootDirectory /srv/%u")))
  (is (eq :none
          (config-value
           #'cl-pnet-ssh:ssh-server-config-chroot-directory
           "ChrootDirectory none")))
  (is (equal "/first"
             (config-value
              #'cl-pnet-ssh:ssh-server-config-chroot-directory
              "ChrootDirectory /first
ChrootDirectory /second")))
  (let* ((config (config-from-text
                  "ChrootDirectory /global
Match User alice
  ChrootDirectory /alice"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (equal "/alice"
               (cl-pnet-ssh:ssh-server-config-chroot-directory alice)))
    (is (equal "/global"
               (cl-pnet-ssh:ssh-server-config-chroot-directory bob))))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "ChrootDirectory")))

(test chroot-path-expansion-and-safety
  "ChrootDirectory expands ~ and %h/%u/%U, and refuses an unsafe directory."
  (is (equal "/srv/alice/%"
             (bursyk-server::expand-session-path
              "/srv/%u/%%" "alice" "/home/alice" "1000")))
  (is (equal "/home/alice/alice"
             (bursyk-server::expand-session-path
              "~/%u" "alice" "/home/alice" "1000")))
  #+sbcl
  (progn
    (is (bursyk-server::safely-chroot-path-p "/"))
    (is (not (bursyk-server::safely-chroot-path-p "/tmp")))
    (is (not (bursyk-server::safely-chroot-path-p "relative"))))
  (let* ((config (config-from-text "ChrootDirectory /"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server :user "root")))
    (is (equal "/" (bursyk-server::session-chroot-directory session))))
  (dolist (value '("/tmp" "relative"))
    (let* ((config (config-from-text
                    (format nil "ChrootDirectory ~A" value)))
           (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
           (session (cl-pnet-ssh::%make-ssh-session
                     :server server :user "root")))
      (signals error
        (bursyk-server::session-chroot-directory session)))))

#-win32
(test spawn-shell-refuses-an-unreachable-chroot
  "A child that cannot chroot reports it instead of running the command."
  #+sbcl
  (if (zerop (sb-posix:getuid))
      (skip "running as root, where chroot succeeds")
      (multiple-value-bind (pid stdin stdout stderr status)
          (bursyk-server::spawn-shell "true" :chroot "/")
        (unwind-protect
             (let ((out (fd-octets stdout))
                   (err (fd-octets stderr))
                   (code (fd-octets status)))
               (bursyk-server::collect-child pid)
               (is (equal "" (octets-string out)))
               (is (search "chroot failed" (octets-string err)))
               ;; The wrapper never ran, so no status text was written.
               (is (equal "" (octets-string code))))
          (fd-close stdin)
          (fd-close stdout)
          (fd-close stderr)
          (fd-close status))))
  #-sbcl
  (skip "sb-posix is needed to tell whether this test can chroot"))

(test match-loglevel-controls-session-messages
  "A Match LogLevel filters this server's connection messages and the
library's protocol milestones."
  (let* ((config (config-from-text
                  "LogLevel ERROR
Match User alice
  LogLevel DEBUG"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (alice (cl-pnet-ssh::%make-ssh-session
                 :server server :user "alice"))
         (bob (cl-pnet-ssh::%make-ssh-session
               :server server :user "bob")))
    (cl-pnet-ssh:ssh-session-resolve-config alice "alice")
    (cl-pnet-ssh:ssh-session-resolve-config bob "bob")
    (is (eq :debug (bursyk-server::session-log-level alice)))
    (is (eq :error (bursyk-server::session-log-level bob)))
    (is (not (null (cl-pnet-ssh::ssh-session-log-enabled-p alice))))
    (is (null (cl-pnet-ssh::ssh-session-log-enabled-p bob)))
    (let ((bursyk-server::*log-level* :info)
          (out (make-string-output-stream)))
      (let ((*error-output* out))
        (bursyk-server::log-at-session alice :info "hello ~A" "alice")
        (bursyk-server::log-at-session bob :info "hello ~A" "bob"))
      (let ((text (get-output-stream-string out)))
        (is (search "hello alice" text))
        (is (not (search "hello bob" text)))))))

(test sshd-config-reads-allow-stream-local-forwarding
  "AllowStreamLocalForwarding takes sshd's four values and is Match-aware."
  (is (eq :yes
          (config-value
           #'cl-pnet-ssh:ssh-server-config-allow-streamlocal-forwarding
           "AllowStreamLocalForwarding yes")))
  (is (eq :no
          (config-value
           #'cl-pnet-ssh:ssh-server-config-allow-streamlocal-forwarding
           "AllowStreamLocalForwarding no")))
  (is (eq :local
          (config-value
           #'cl-pnet-ssh:ssh-server-config-allow-streamlocal-forwarding
           "AllowStreamLocalForwarding local")))
  (is (eq :remote
          (config-value
           #'cl-pnet-ssh:ssh-server-config-allow-streamlocal-forwarding
           "AllowStreamLocalForwarding remote")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "AllowStreamLocalForwarding sometimes"))
  (let* ((config (config-from-text
                  "AllowStreamLocalForwarding no
Match User alice
  AllowStreamLocalForwarding yes"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (eq :yes
            (cl-pnet-ssh:ssh-server-config-allow-streamlocal-forwarding
             alice)))
    (is (eq :no
            (cl-pnet-ssh:ssh-server-config-allow-streamlocal-forwarding
             bob)))))

(test sshd-config-reads-stream-local-bind-options
  "StreamLocalBindMask and StreamLocalBindUnlink are Match-aware."
  (is (= #o177
         (config-value
          #'cl-pnet-ssh:ssh-server-config-streamlocal-bind-mask
          "StreamLocalBindMask 0177")))
  (is (= #o700
         (config-value
          #'cl-pnet-ssh:ssh-server-config-streamlocal-bind-mask
          "StreamLocalBindMask 700")))
  (is (eq t
          (config-value
           #'cl-pnet-ssh:ssh-server-config-streamlocal-bind-unlink
           "StreamLocalBindUnlink yes")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "StreamLocalBindMask 888"))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "StreamLocalBindMask nope"))
  (let* ((config (config-from-text
                  "StreamLocalBindMask 0177
Match User alice
  StreamLocalBindMask 0700
  StreamLocalBindUnlink yes"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (= #o700
           (cl-pnet-ssh:ssh-server-config-streamlocal-bind-mask alice)))
    (is (eq t
            (cl-pnet-ssh:ssh-server-config-streamlocal-bind-unlink alice)))
    (is (= #o177
           (cl-pnet-ssh:ssh-server-config-streamlocal-bind-mask bob)))))

(test sshd-config-reads-hostbased-authentication
  "HostbasedAuthentication and its policy fields are parsed and Match-aware."
  (is (eq :yes
          (config-value
           #'cl-pnet-ssh:ssh-server-config-hostbased-authentication
           "HostbasedAuthentication yes")))
  (is (eq :no
          (config-value
           #'cl-pnet-ssh:ssh-server-config-hostbased-authentication
           "HostbasedAuthentication no")))
  (is (equal '("ssh-ed25519" "rsa-sha2-512")
             (config-value
              #'cl-pnet-ssh:ssh-server-config-hostbased-accepted-algorithms
              "HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512")))
  (is (eq :yes
          (config-value
           #'cl-pnet-ssh:ssh-server-config-hostbased-uses-name-from-packet-only
           "HostbasedUsesNameFromPacketOnly yes")))
  (is (eq :no
          (config-value
           #'cl-pnet-ssh:ssh-server-config-ignore-rhosts
           "IgnoreRhosts no")))
  (is (eq :shosts-only
          (config-value
           #'cl-pnet-ssh:ssh-server-config-ignore-rhosts
           "IgnoreRhosts shosts-only")))
  (is (eq t
          (config-value
           #'cl-pnet-ssh:ssh-server-config-ignore-user-known-hosts
           "IgnoreUserKnownHosts yes")))
  (is (eq :yes
          (config-value
           #'cl-pnet-ssh:ssh-server-config-strict-modes
           "StrictModes yes")))
  (is (eq :no
          (config-value
           #'cl-pnet-ssh:ssh-server-config-strict-modes
           "StrictModes no")))
  (let* ((config (config-from-text
                  "HostbasedAuthentication no
Match User alice
  HostbasedAuthentication yes"))
         (alice (cl-pnet-ssh:ssh-server-config-for-connection
                 config :user "alice"))
         (bob (cl-pnet-ssh:ssh-server-config-for-connection
               config :user "bob")))
    (is (eq :yes
            (cl-pnet-ssh:ssh-server-config-hostbased-authentication alice)))
    (is (eq :no
            (cl-pnet-ssh:ssh-server-config-hostbased-authentication bob)))))

(test hostbased-rhosts-file-rules
  "Rhosts lines match host or IP, an optional user, and negations."
  (let ((path (merge-pathnames "bursyk-rhosts-test"
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (with-open-file (out path :direction :output
                                     :if-exists :supersede
                                     :if-does-not-exist :create)
             (write-string
              "client.example turtle
-other.example turtle
192.0.2.1
+ ignored
" out))
           (is (eq :allow
                   (bursyk-server::rhosts-file-decision
                    path "client.example" "192.0.2.9" "turtle" "turtle")))
           (is (eq :deny
                   (bursyk-server::rhosts-file-decision
                    path "other.example" "192.0.2.9" "turtle" "turtle")))
           (is (eq :allow
                   (bursyk-server::rhosts-file-decision
                    path "third.example" "192.0.2.1" "turtle" "turtle")))
           (is (null
                (bursyk-server::rhosts-file-decision
                 path "third.example" "192.0.2.9" "turtle" "turtle"))))
      (ignore-errors (delete-file path)))))

(test hostbased-known-host-check-uses-known-hosts
  "A hostbased client host key must be known for the lookup name."
  (let* ((key (revoked-test-key 31))
         (other (revoked-test-key 32))
         (type (nth-value 0 (cl-pnet-ssh:ssh-public-key-parts key)))
         (path (revoked-test-file
                (format nil "client.example ~A ~A~%"
                        type (cl-pnet-ssh:ssh-octets-base64 key))))
         (config (config-from-text "IgnoreUserKnownHosts yes"))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server)))
    (unwind-protect
         (let ((bursyk-server::*hostbased-system-known-hosts* (list path)))
           (is (bursyk-server::hostbased-known-host-p
                session "client.example" key))
           (is (not (bursyk-server::hostbased-known-host-p
                     session "other.example" key)))
           (is (not (bursyk-server::hostbased-known-host-p
                     session "client.example" other))))
      (ignore-errors (delete-file path)))))

(test sshd-config-reads-host-key-agent
  "HostKeyAgent names an agent socket, none clears it, and it is global-only."
  (is (equal "/run/agent.sock"
             (config-value
              #'cl-pnet-ssh:ssh-server-config-host-key-agent
              "HostKeyAgent /run/agent.sock")))
  (is (null
       (config-value
        #'cl-pnet-ssh:ssh-server-config-host-key-agent
        "HostKeyAgent none")))
  (signals cl-pnet-ssh:ssh-server-config-error
    (config-from-text "Match User alice
  HostKeyAgent /run/agent.sock")))
