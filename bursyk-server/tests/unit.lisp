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

(defun fd-octets (fd &key (timeout 5))
  "Everything FD yields until EOF, polling while the pipe is empty."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                           :adjustable t :fill-pointer 0))
        (deadline (deadline-in timeout)))
    (loop
      (multiple-value-bind (octets count error)
          (cl-pnet-sockets:read-octets fd 4096)
        (declare (ignore error))
        (cond
          ((plusp count)
           (loop for index from 0 below count
                 do (vector-push-extend (aref octets index) out)))
          ((zerop count)
           (return (coerce out '(simple-array (unsigned-byte 8) (*)))))
          ((overdue-p deadline)
           (return (coerce out '(simple-array (unsigned-byte 8) (*)))))
          (t (sleep 0.005)))))))

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
