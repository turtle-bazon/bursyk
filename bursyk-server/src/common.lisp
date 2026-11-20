(in-package #:bursyk-server)

;;;; Channel facts shared by both process backends.  These read the library's
;;;; channel record; nothing here starts a child or touches a descriptor, so
;;;; the POSIX and Windows bridges can agree on what a pty request asked for.

(defun channel-pty-p (channel)
  (cl-pnet-ssh:ssh-server-channel-pty-p channel))

(defun channel-rows (channel)
  (let ((rows (cl-pnet-ssh:ssh-server-channel-pty-rows channel)))
    (if (and rows (plusp rows)) rows 24)))

(defun channel-columns (channel)
  (let ((columns (cl-pnet-ssh:ssh-server-channel-pty-columns channel)))
    (if (and columns (plusp columns)) columns 80)))

(defun environment-put (environment name value)
  "NAME=VALUE in ENVIRONMENT, replacing earlier assignments of NAME.

A later entry is what execve sees, so the newest assignment wins; the list
keeps one pair per name as sshd's child_set_env does."
  (cons (cons name value)
        (remove name environment :key #'car :test #'string=)))

(defun environment-assignment-parts (assignment)
  "NAME and VALUE of one \"NAME=VALUE\" string, or NIL."
  (let ((equals (position #\= assignment)))
    (when equals
      (values (subseq assignment 0 equals)
              (subseq assignment (1+ equals))))))

(defun session-environment-permits-p (session name)
  "Whether SESSION's PermitUserEnvironment lets the user set NAME."
  (cl-pnet-ssh:ssh-session-permit-user-environment-p session name))

(defun apply-environment-assignment (environment assignment session)
  "Add ASSIGNMENT to ENVIRONMENT when PermitUserEnvironment admits its name."
  (multiple-value-bind (name value)
      (environment-assignment-parts assignment)
    (if (and name (session-environment-permits-p session name))
        (environment-put environment name value)
        environment)))

(defun read-user-environment-file (path session environment)
  "ENVIRONMENT plus the assignments in the user's ~/.ssh/environment at PATH.

sshd reads this file only under PermitUserEnvironment, strips leading
whitespace, skips blank lines and comments, and silently ignores a line
without =.  A missing or unreadable file means no assignments."
  (handler-case
      (if (probe-file path)
          (with-open-file (stream path :direction :input
                                       :if-does-not-exist nil
                                       :external-format :utf-8)
            (when stream
              ;; sshd refuses more than 1000 lines; dropping the rest is the
              ;; safe half of that rule for a long-lived server.
              (loop repeat 1000
                    for line = (read-line stream nil nil)
                    while line
                    for trimmed = (string-left-trim '(#\Space #\Tab) line)
                    unless (or (zerop (length trimmed))
                               (char= (char trimmed 0) #\#))
                      do (setf environment
                               (apply-environment-assignment
                                environment trimmed session)))
              environment))
          environment)
    (error () environment)))

(defun session-environment (channel)
  "The child's environment: AcceptEnv, the key's options, ~/.ssh/environment
and SetEnv, in sshd's order of precedence.

The library already applied AcceptEnv, so the pairs here are exactly the
ones the client was allowed to send.  PermitUserEnvironment then adds the
authorized_keys environment= options and the user's own file, and the
administrator's SetEnv overrides both.  A pty's TERM replaces any TERM the
client sent, as sshd sets s->term after the accepted environment.  The
Per-connection config decides which values apply, so a Match block's SetEnv
replaces the global one here as it does in sshd."
  (let* ((session (cl-pnet-ssh:ssh-server-channel-session channel))
         (server (cl-pnet-ssh:ssh-session-server session))
         (environment (copy-list (cl-pnet-ssh:ssh-server-channel-env channel))))
    (when (and (channel-pty-p channel)
               (cl-pnet-ssh:ssh-server-channel-pty-term channel))
      (setf environment
            (environment-put environment "TERM"
                             (cl-pnet-ssh:ssh-server-channel-pty-term channel))))
    (dolist (assignment (cl-pnet-ssh:ssh-session-key-env session))
      (setf environment
            (apply-environment-assignment environment assignment session)))
    (when (let ((policy (or (session-config-setting
                             session
                             #'cl-pnet-ssh:ssh-server-config-permit-user-environment)
                            (cl-pnet-ssh:ssh-server-permit-user-environment
                             server))))
            (or (eq policy :yes) (consp policy)))
      (multiple-value-bind (home uid)
          (user-home-and-uid (cl-pnet-ssh:ssh-session-user session))
        (declare (ignore uid))
        (when home
          (setf environment
                (read-user-environment-file
                 (merge-pathnames ".ssh/environment"
                                  (uiop:ensure-directory-pathname home))
                 session environment)))))
    (let ((set-env (or (session-config-setting
                        session #'cl-pnet-ssh:ssh-server-config-set-env)
                       (cl-pnet-ssh:ssh-server-set-env server))))
      (dolist (assignment set-env)
        (multiple-value-bind (name value)
            (environment-assignment-parts assignment)
          (when name
            (setf environment (environment-put environment name value))))))
    environment))

(defun user-shell ()
  "The shell a login session starts, as sshd takes it from the passwd file.

The environment's SHELL is the best available answer while BURSYK-SERVER
still runs every child as its own uid rather than the authenticated user."
  (or (uiop:getenv "SHELL") "/bin/sh"))
