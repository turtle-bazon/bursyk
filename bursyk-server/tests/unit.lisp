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
    (config-from-text "PermitRootLogin no"))
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
