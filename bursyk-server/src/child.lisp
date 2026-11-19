(in-package #:bursyk-server)

;;;; Children are forked and exec'd here rather than started through
;;;; SB-EXT:RUN-PROGRAM.  RUN-PROGRAM asks SBCL's SIGCHLD bookkeeping for the
;;;; exit status, and that bookkeeping does not finish while the event loop is
;;;; parked inside its foreign wait: the child is still reaped by the time the
;;;; loop looks, but the status is lost, so the session never learns that the
;;;; command ended.  A child of our own is not enough on its own either while
;;;; the loop is running, so the exit status does not come from WAITPID at
;;;; all: the wrapper shell writes it on a fourth pipe.
;;;;
;;;; Everything between FORK and EXEC runs on the forked child's copy of the
;;;; heap, so it touches only C: descriptor shuffling, then EXECVE.  All of
;;;; the strings and the environment vector are built before the fork.

(cffi:defcfun ("pipe" c-pipe) :int (fds :pointer))
(cffi:defcfun ("fork" c-fork) :int)
(cffi:defcfun ("dup2" c-dup2) :int (old :int) (new :int))
(cffi:defcfun ("close" c-close) :int (fd :int))
(cffi:defcfun ("execve" c-execve) :int
  (path :pointer) (argv :pointer) (envp :pointer))
(cffi:defcfun ("_exit" c-quit-now) :void (status :int))
(cffi:defcfun ("waitpid" c-waitpid) :int
  (pid :int) (status :pointer) (options :int))
(cffi:defcfun ("kill" c-kill) :int (pid :int) (signal :int))
(cffi:defcfun ("getrlimit" c-getrlimit) :int
  (resource :int) (limits :pointer))

(cffi:defcstruct rlimit
  (current :unsigned-long)
  (maximum :unsigned-long))

(defconstant +sigkill+ 9)
(defconstant +rlimit-nofile+ 7)
(defconstant +status-descriptor+ 3)
(defconstant +exec-failed-status+ 127)

(defparameter *shell-program* "/bin/sh")

(defparameter *shell-script*
  ;; The command arrives as $1, so it is never spliced into a script and
  ;; needs no quoting.  The inner shell is waited for by this one, which then
  ;; reports its status on descriptor 3; that survives an EXIT in the command.
  "/bin/sh -c \"$1\" ; printf '%d' \"$?\" >&3")

(defun make-pipe ()
  "One (READ . WRITE) descriptor pair."
  (cffi:with-foreign-object (fds :int 2)
    (when (minusp (c-pipe fds))
      (error "cannot create a pipe: ~A"
             (cl-pnet-sockets:c-strerror (cl-pnet-sockets:c-errno))))
    (cons (cffi:mem-aref fds :int 0)
          (cffi:mem-aref fds :int 1))))

(defun close-pipe (pipe)
  (c-close (car pipe))
  (c-close (cdr pipe)))

(defun make-argv (strings)
  "A foreign argv holding STRINGS, released with FREE-ARGV."
  (let* ((count (length strings))
         (argv (cffi:foreign-alloc :pointer :count (1+ count))))
    (loop for index from 0
          for string in strings
          do (setf (cffi:mem-aref argv :pointer index)
                   (cffi:foreign-string-alloc string)))
    (setf (cffi:mem-aref argv :pointer count) (cffi:null-pointer))
    argv))

(defun free-argv (argv)
  (loop for index from 0
        for pointer = (cffi:mem-aref argv :pointer index)
        until (cffi:null-pointer-p pointer)
        do (cffi:foreign-string-free pointer))
  (cffi:foreign-free argv))

(defun environment-pointer ()
  "The C environment vector a child inherits."
  (cffi:mem-ref (cffi:foreign-symbol-pointer "environ") :pointer))

(defun environment-count ()
  "How many strings the current environment holds."
  (let ((environ (environment-pointer)))
    (loop for index from 0
          until (cffi:null-pointer-p (cffi:mem-aref environ :pointer index))
          finally (return index))))

(defun make-environment (extra)
  "The current environment plus EXTRA, a list of (NAME . VALUE) pairs.

Returns (VALUES VECTOR ALLOCATED).  Existing entries are shared with the
parent's environment, which stays alive across the fork; only the added
strings and the vector itself are allocated, and FREE-ENVIRONMENT releases
them after the fork."
  (let* ((environ (environment-pointer))
         (existing (environment-count))
         (total (+ existing (length extra)))
         (envp (cffi:foreign-alloc :pointer :count (1+ total)))
         (allocated nil))
    (loop for index below existing
          do (setf (cffi:mem-aref envp :pointer index)
                   (cffi:mem-aref environ :pointer index)))
    (loop for (name . value) in extra
          for index from existing
          for pointer = (cffi:foreign-string-alloc
                         (format nil "~A=~A" name value))
          do (push pointer allocated)
             (setf (cffi:mem-aref envp :pointer index) pointer))
    (setf (cffi:mem-aref envp :pointer total) (cffi:null-pointer))
    (values envp allocated)))

(defun free-environment (envp allocated)
  "Release what MAKE-ENVIRONMENT allocated; the inherited vector is not ours."
  (when allocated
    (dolist (pointer allocated) (cffi:foreign-string-free pointer))
    (cffi:foreign-free envp)))

(defun child-close-extras ()
  "Close every descriptor above the status pipe, before exec."
  (cffi:with-foreign-object (limits 'rlimit)
    (let ((limit (if (zerop (c-getrlimit +rlimit-nofile+ limits))
                     (min 65536
                          (cffi:foreign-slot-value limits 'rlimit 'current))
                     1024)))
      (loop for fd from (1+ +status-descriptor+) below limit
            do (c-close fd)))))

(defun child-exec (path argv envp stdin stdout stderr status)
  "Become PATH with the pipes moved onto 0, 1, 2 and 3.

The status pipe moves last: descriptor 3 may already be the read end of
STDIN, and duplicating it away first keeps the source valid."
  (c-dup2 stdin 0)
  (c-dup2 stdout 1)
  (c-dup2 stderr 2)
  (c-dup2 status +status-descriptor+)
  (child-close-extras)
  (c-execve path argv envp)
  (c-quit-now +exec-failed-status+))

(defun spawn-shell (command &key environment)
  "Run COMMAND under a shell; return (VALUES PID STDIN STDOUT STDERR STATUS).

ENVIRONMENT, an alist of (NAME . VALUE), is added to the child's environment,
which is otherwise inherited.  The descriptors are non-blocking and belong to
the caller.  STATUS yields the command's exit status as decimal text once the
wrapper shell is done."
  (let* ((argv (make-argv (list *shell-program* "-c" *shell-script* "sh" command)))
         (path (cffi:foreign-string-alloc *shell-program*))
         (in (make-pipe))
         (out (make-pipe))
         (err (make-pipe))
         (status (make-pipe))
         (pipes (list in out err status))
         (envp nil)
         (allocated nil)
         (pid nil))
    (multiple-value-setq (envp allocated) (make-environment environment))
    (setf pid (c-fork))
    (cond
      ((minusp pid)
       (dolist (pipe pipes) (close-pipe pipe))
       (free-argv argv)
       (free-environment envp allocated)
       (cffi:foreign-string-free path)
       (error "cannot fork: ~A"
              (cl-pnet-sockets:c-strerror (cl-pnet-sockets:c-errno))))
      ((zerop pid)
       (child-exec path argv envp (car in) (cdr out) (cdr err) (cdr status)))
      (t
       (c-close (car in))
       (c-close (cdr out))
       (c-close (cdr err))
       (c-close (cdr status))
       (free-argv argv)
       (free-environment envp allocated)
       (cffi:foreign-string-free path)
       (dolist (fd (list (cdr in) (car out) (car err) (car status)))
         (cl-pnet-sockets:set-nonblocking fd))
       (values pid (cdr in) (car out) (car err) (car status))))))

(defun collect-child (pid)
  "Reap PID, which has already exited, without waiting for anything."
  (cffi:with-foreign-object (status :int)
    (c-waitpid pid status 0))
  (values))

(defun kill-child (pid)
  "Terminate PID and reap it."
  (c-kill pid +sigkill+)
  (collect-child pid))
