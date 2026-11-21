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
(cffi:defcfun ("posix_openpt" c-posix-openpt) :int (flags :int))
(cffi:defcfun ("grantpt" c-grantpt) :int (fd :int))
(cffi:defcfun ("unlockpt" c-unlockpt) :int (fd :int))
(cffi:defcfun ("ptsname" c-ptsname) :string (fd :int))
(cffi:defcfun ("open" c-open) :int
  (path :string) (flags :int) (mode :int))
(cffi:defcfun ("umask" c-umask) :unsigned-int (mask :unsigned-int))
(cffi:defcfun ("chroot" c-chroot) :int (path :string))
(cffi:defcfun ("chdir" c-chdir) :int (path :string))
(cffi:defcfun ("write" c-write) :int (fd :int) (buffer :string) (count :int))
(cffi:defcfun ("setsid" c-setsid) :int)
(cffi:defcfun ("ioctl" c-ioctl) :int
  (fd :int) (request :unsigned-long) (argument :pointer))

(cffi:defcstruct winsize
  (rows :unsigned-short)
  (columns :unsigned-short)
  (x-pixels :unsigned-short)
  (y-pixels :unsigned-short))

;; Linux values.  BURSYK-SERVER is a Linux sshd; the constants are not
;; abstracted because no other platform runs this binary today.
(defconstant +o-rdwr+ 2)
(defconstant +o-noctty+ #o400)
(defconstant +tiocsctty+ #x540E)
(defconstant +tiocswinsz+ #x5414)
(defconstant +sighup+ 1)

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

(defparameter *program-script*
  "\"$@\" ; printf '%d' \"$?\" >&3"
  "Runs a named program and its arguments, then reports the status on 3.")

(defparameter *pty-shell-script*
  "if [ -n \"$2\" ]; then \"$1\" -c \"$2\"; else \"$1\" -l; fi; printf '%d' \"$?\" >&3"
  "Runs the user's shell on the allocated pty and reports the status on 3.

$1 is the shell and $2 the command, empty for a login session.  The shell
is a child of this wrapper, which survives to write the status after the
shell exits.")

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

(defun child-enter-chroot (chroot)
  "Chroot the child to CHROOT and make / its working directory.

CHROOT is a foreign string or NIL.  A failure is reported on the child's
stderr and ends it with the same status an exec failure uses."
  (when chroot
    (when (minusp (c-chroot chroot))
      (c-write 2 "chroot failed" 13)
      (c-quit-now +exec-failed-status+))
    (when (minusp (c-chdir "/"))
      (c-write 2 "chdir after chroot failed" 25)
      (c-quit-now +exec-failed-status+))))

(defun child-exec (path argv envp stdin stdout stderr status chroot)
  "Become PATH with the pipes moved onto 0, 1, 2 and 3.

The status pipe moves last: descriptor 3 may already be the read end of
STDIN, and duplicating it away first keeps the source valid.  CHROOT, when
non-NIL, is entered before the exec."
  (c-dup2 stdin 0)
  (c-dup2 stdout 1)
  (c-dup2 stderr 2)
  (c-dup2 status +status-descriptor+)
  (child-close-extras)
  (child-enter-chroot chroot)
  (c-execve path argv envp)
  (c-quit-now +exec-failed-status+))

(defun spawn-with-pipes (argv environment &key chroot)
  "Fork a child running ARGV with pipes on its three standard streams.

CHROOT, when given, is entered before the exec.  Returns (VALUES PID STDIN
STDOUT STDERR STATUS); STATUS is a fourth pipe on which the wrapper writes
the exit code as decimal text."
  (let* ((path (cffi:foreign-string-alloc *shell-program*))
         (chroot-path (and chroot (cffi:foreign-string-alloc chroot)))
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
       (when chroot-path (cffi:foreign-string-free chroot-path))
       (error "cannot fork: ~A"
              (cl-pnet-sockets:c-strerror (cl-pnet-sockets:c-errno))))
      ((zerop pid)
       (child-exec path argv envp (car in) (cdr out) (cdr err) (cdr status)
                   chroot-path))
      (t
       (c-close (car in))
       (c-close (cdr out))
       (c-close (cdr err))
       (c-close (cdr status))
       (free-argv argv)
       (free-environment envp allocated)
       (cffi:foreign-string-free path)
       (when chroot-path (cffi:foreign-string-free chroot-path))
       (dolist (fd (list (cdr in) (car out) (car err) (car status)))
         (cl-pnet-sockets:set-nonblocking fd))
       (values pid (cdr in) (car out) (car err) (car status))))))

(defun spawn-shell (command &key environment chroot)
  "Run COMMAND under a shell; return (VALUES PID STDIN STDOUT STDERR STATUS).

ENVIRONMENT, an alist of (NAME . VALUE), is added to the child's environment,
which is otherwise inherited.  CHROOT is entered before the exec.  The
descriptors are non-blocking and belong to the caller.  STATUS yields the
command's exit status as decimal text once the wrapper shell is done."
  (spawn-with-pipes
   (make-argv (list *shell-program* "-c" *shell-script* "sh" command))
   environment :chroot chroot))

(defun spawn-program (program arguments &key environment chroot)
  "Run PROGRAM with ARGUMENTS, no shell expansion, and report its status.

The same four pipes as SPAWN-SHELL come back, so a subsystem and a command
share one bridge."
  (spawn-with-pipes
   (make-argv (append (list *shell-program* "-c" *program-script* "sh" program)
                      arguments))
   environment :chroot chroot))

;;; ---- pseudo-terminals ----

(defun make-pty ()
  "Allocate a pty; return (VALUES MASTER SLAVE).
The slave is opened without becoming this process's controlling terminal."
  (let ((master (c-posix-openpt (logior +o-rdwr+ +o-noctty+))))
    (when (minusp master)
      (error "cannot allocate a pty: ~A"
             (cl-pnet-sockets:c-strerror (cl-pnet-sockets:c-errno))))
    (when (or (minusp (c-grantpt master)) (minusp (c-unlockpt master)))
      (c-close master)
      (error "cannot open a pty pair: ~A"
             (cl-pnet-sockets:c-strerror (cl-pnet-sockets:c-errno))))
    (let ((slave (c-open (c-ptsname master)
                         (logior +o-rdwr+ +o-noctty+) 0)))
      (if (minusp slave)
          (progn
            (c-close master)
            (error "cannot open the pty slave: ~A"
                   (cl-pnet-sockets:c-strerror
                    (cl-pnet-sockets:c-errno))))
          (values master slave)))))

(defun set-pty-size (master rows columns)
  "Set MASTER's terminal size, which the slave inherits and SIGWINCHs on."
  (cffi:with-foreign-object (size 'winsize)
    (setf (cffi:foreign-slot-value size 'winsize 'rows) (max 0 rows)
          (cffi:foreign-slot-value size 'winsize 'columns) (max 0 columns)
          (cffi:foreign-slot-value size 'winsize 'x-pixels) 0
          (cffi:foreign-slot-value size 'winsize 'y-pixels) 0)
    (c-ioctl master +tiocswinsz+ size)))

(defun child-exec-pty (path argv envp slave status chroot)
  "Become PATH on the pty SLAVE, with the status pipe on descriptor 3.

SETSID makes the child a session and process-group leader, and TIOCSCTTY
makes the slave its controlling terminal, so the shell gets job control and
the kernel delivers SIGWINCH when the master is resized.  CHROOT, when
non-NIL, is entered before the exec."
  (c-setsid)
  (c-ioctl slave +tiocsctty+ (cffi:null-pointer))
  (c-dup2 slave 0)
  (c-dup2 slave 1)
  (c-dup2 slave 2)
  (c-dup2 status +status-descriptor+)
  (child-close-extras)
  (child-enter-chroot chroot)
  (c-execve path argv envp)
  (c-quit-now +exec-failed-status+))

(defun spawn-pty (argv environment rows columns &key chroot)
  "Fork ARGV on a new pty; return (VALUES PID MASTER STATUS).

The child's stdin, stdout and stderr all refer to the slave, so the peer
sees one merged terminal stream, while STATUS still reports the exit code on
a pipe the terminal protocol cannot corrupt.  CHROOT is entered before the
exec."
  (multiple-value-bind (master slave) (make-pty)
    (set-pty-size master rows columns)
    (let* ((path (cffi:foreign-string-alloc *shell-program*))
           (chroot-path (and chroot (cffi:foreign-string-alloc chroot)))
           (status (make-pipe))
           (envp nil)
           (allocated nil)
           (pid nil))
      (multiple-value-setq (envp allocated) (make-environment environment))
      (setf pid (c-fork))
      (cond
        ((minusp pid)
         (c-close master)
         (c-close slave)
         (close-pipe status)
         (free-argv argv)
         (free-environment envp allocated)
         (cffi:foreign-string-free path)
         (when chroot-path (cffi:foreign-string-free chroot-path))
         (error "cannot fork: ~A"
                (cl-pnet-sockets:c-strerror (cl-pnet-sockets:c-errno))))
        ((zerop pid)
         (child-exec-pty path argv envp slave (cdr status) chroot-path))
        (t
         (c-close slave)
         (c-close (cdr status))
         (free-argv argv)
         (free-environment envp allocated)
         (cffi:foreign-string-free path)
         (when chroot-path (cffi:foreign-string-free chroot-path))
         (cl-pnet-sockets:set-nonblocking master)
         (cl-pnet-sockets:set-nonblocking (car status))
         (values pid master (car status)))))))

(defun spawn-pty-shell (command shell &key environment rows columns chroot)
  "Run the user's login shell or COMMAND on a pty.

The login shell runs when COMMAND is NIL or empty; otherwise SHELL -c runs
COMMAND.  The returned master is both the pty's input and its output."
  (spawn-pty
   (make-argv (list *shell-program* "-c" *pty-shell-script* "sh"
                    (or shell *shell-program*) (or command "")))
   environment (or rows 24) (or columns 80) :chroot chroot))

(defun spawn-pty-program (program arguments &key environment rows columns chroot)
  "Run PROGRAM with ARGUMENTS on a pty, for a subsystem that wants one."
  (spawn-pty
   (make-argv (append (list *shell-program* "-c" *program-script* "sh" program)
                      arguments))
   environment (or rows 24) (or columns 80) :chroot chroot))

(defun set-child-window (master rows columns)
  "Resize MASTER; the kernel sends SIGWINCH to the child's terminal group."
  (set-pty-size master rows columns))

(defun collect-child (pid)
  "Reap PID, which has already exited, without waiting for anything."
  (cffi:with-foreign-object (status :int)
    (c-waitpid pid status 0))
  (values))

(defun kill-child (pid)
  "Terminate PID and reap it."
  (c-kill pid +sigkill+)
  (collect-child pid))

(defun kill-child-group (pid)
  "Terminate PID and every process in its session, then reap the leader.

A pty child called SETSID, so it is the process-group leader and -PID names
the whole group; the shell it launched must go with it rather than outlive
the channel."
  (when (plusp pid)
    (c-kill (- pid) +sighup+)
    (c-kill (- pid) +sigkill+)
    (collect-child pid)))
