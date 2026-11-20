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

(defun session-environment (channel)
  "The child's environment: accepted SendEnv variables plus TERM for a pty.

The library already applied AcceptEnv, so the pairs here are exactly the
ones the client was allowed to send."
  (let ((environment (copy-list (cl-pnet-ssh:ssh-server-channel-env channel))))
    (when (and (channel-pty-p channel)
               (cl-pnet-ssh:ssh-server-channel-pty-term channel)
               (not (assoc "TERM" environment :test #'string=)))
      (push (cons "TERM" (cl-pnet-ssh:ssh-server-channel-pty-term channel))
            environment))
    environment))

(defun user-shell ()
  "The shell a login session starts, as sshd takes it from the passwd file.

The environment's SHELL is the best available answer while BURSYK-SERVER
still runs every child as its own uid rather than the authenticated user."
  (or (uiop:getenv "SHELL") "/bin/sh"))
