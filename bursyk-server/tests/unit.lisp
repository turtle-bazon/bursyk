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
  (is (null (bursyk-server::option-key "-Z"))))

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
