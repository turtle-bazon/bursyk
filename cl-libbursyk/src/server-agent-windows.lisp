;;;; Windows named-pipe listener for forwarded agents.
;;;;
;;;; The library's POSIX forwarding path watches a Unix-socket listener and
;;;; accepts with accept(2).  A named pipe cannot be polled that way, so the
;;;; application gets a listener object instead: a thread waits for each
;;;; connection and hands the accepted handle to the event loop, which adopts
;;;; it with SSH-SERVER-AGENT-ADOPT-PIPE.  The pipe is non-blocking only in
;;;; the sense that the polling relay reads it, so one thread per listener is
;;;; enough.
;;;;
;;;; This component is built on Windows only.

(in-package #:cl-pnet-ssh)

(cffi:define-foreign-library cl-pnet-ssh-server-agent-kernel32
  (:windows "kernel32.dll"))
(cffi:use-foreign-library cl-pnet-ssh-server-agent-kernel32)

(cffi:defcfun ("CreateNamedPipeW" c-server-agent-create-pipe) :pointer
  (name :pointer) (open-mode :unsigned-long) (pipe-mode :unsigned-long)
  (max-instances :unsigned-long) (out-size :unsigned-long)
  (in-size :unsigned-long) (timeout :unsigned-long) (security :pointer))
(cffi:defcfun ("ConnectNamedPipe" c-server-agent-connect-pipe) :int
  (handle :pointer) (overlapped :pointer))
(cffi:defcfun ("DisconnectNamedPipe" c-server-agent-disconnect-pipe) :int
  (handle :pointer))

(defconstant +server-agent-pipe-duplex+ 3
  "PIPE_ACCESS_DUPLEX.")
(defconstant +server-agent-pipe-instances+ 4
  "Enough instances for concurrent agent requests from one session.")

(defstruct (ssh-agent-pipe-listener
             (:constructor %make-ssh-agent-pipe-listener))
  session
  path
  handle
  thread
  (stop nil))

(defun ssh-agent-pipe-name-p (name)
  "NAME as the canonical \\\\.\\pipe\\... spelling, or NIL."
  (let ((canonical (substitute #\\ #\/ name)))
    (and (>= (length canonical) 9)
         (string-equal canonical "\\\\.\\pipe\\" :end1 9 :end2 9)
         canonical)))

(defun ssh-agent-pipe-default-name ()
  (format nil "\\\\.\\pipe\\openssh-agent-~D-~D-~D"
          (get-universal-time) (random 1000000) (random 1000000)))

(defun ssh-agent-pipe-create (path)
  "A new listening instance of the pipe at PATH."
  (multiple-value-bind (pointer length)
      (windows-utf16-pointer path)
    (declare (ignore length))
    (unwind-protect
         (let ((handle (c-server-agent-create-pipe
                        pointer +server-agent-pipe-duplex+ 0
                        +server-agent-pipe-instances+
                        65536 65536 0 (cffi:null-pointer))))
           (when (agent-invalid-handle-p handle)
             (error 'ssh-error
                    :detail
                    (format nil "cannot create agent pipe ~A: ~A"
                            path
                            (agent-error-text (c-agent-last-error)))))
           handle)
      (cffi:foreign-free pointer))))

(defun ssh-agent-pipe-wait (handle)
  "Wait for a client on HANDLE; T when one connected.

ERROR_PIPE_CONNECTED (535) means the client arrived before ConnectNamedPipe
was called, which is still a connection."
  (let ((connected (c-server-agent-connect-pipe handle (cffi:null-pointer))))
    (or (plusp connected)
        (eql (c-agent-last-error) 535))))

(defun ssh-agent-pipe-serve (listener)
  "Accept connections forever, adopting each one on the event loop."
  (let ((session (ssh-agent-pipe-listener-session listener))
        (path (ssh-agent-pipe-listener-path listener))
        (handle (ssh-agent-pipe-listener-handle listener)))
    (unwind-protect
         (loop
           (when (ssh-agent-pipe-listener-stop listener)
             (return))
           (unless (ssh-agent-pipe-wait handle)
             (return))
           (when (ssh-agent-pipe-listener-stop listener)
             (return))
           ;; Keep an instance listening while the accepted handle is on its
           ;; way to the loop, so a second agent connection never finds the
           ;; pipe name missing.  ACCEPTED is a fresh binding: the closure
           ;; below must not see the handle variable rebound to NEXT.
           (let* ((accepted handle)
                  (next (handler-case (ssh-agent-pipe-create path)
                          (error () nil))))
             (unless (cl-pnet:call-on-loop
                      (lambda ()
                        (ssh-server-agent-adopt-pipe session accepted)))
               (ignore-errors (c-agent-close-handle accepted))
               (when next (ignore-errors (c-agent-close-handle next)))
               (return))
             (unless next
               (return))
             (setf handle next)))
      (ignore-errors (c-agent-close-handle handle)))))

(defun ssh-agent-pipe-stop (listener)
  "Stop LISTENER, waking its blocked ConnectNamedPipe with a client."
  (unless (ssh-agent-pipe-listener-stop listener)
    (setf (ssh-agent-pipe-listener-stop listener) t)
    (ignore-errors
     (multiple-value-bind (pointer length)
         (windows-utf16-pointer (ssh-agent-pipe-listener-path listener))
       (declare (ignore length))
       (unwind-protect
            (let ((handle
                    (c-agent-create-file
                     pointer
                     (logior +agent-generic-read+ +agent-generic-write+)
                     0 (cffi:null-pointer) +agent-open-existing+
                     +agent-file-attribute-normal+ (cffi:null-pointer))))
              (unless (agent-invalid-handle-p handle)
                (ignore-errors (c-agent-close-handle handle))))
         (cffi:foreign-free pointer))))))

(defun ssh-server-agent-forward-pipe-listener (session &key name)
  "Create a named-pipe listener for SESSION's forwarded agent.

Returns (VALUES PATH CLEANUP), or NIL when the pipe cannot be created.  NAME,
when it names a pipe, is used as is; otherwise a unique pipe name is made.
CLEANUP stops the listener and is what the on-agent-forward hook's third
value carries."
  (let ((path (or (and name (ssh-agent-pipe-name-p name))
                  (ssh-agent-pipe-default-name))))
    (handler-case
        (let* ((handle (ssh-agent-pipe-create path))
               (listener (%make-ssh-agent-pipe-listener
                          :session session :path path :handle handle)))
          (setf (ssh-agent-pipe-listener-thread listener)
                (sb-thread:make-thread
                 (lambda () (ssh-agent-pipe-serve listener))
                 :name "ssh agent pipe listener"))
          (values path (lambda () (ssh-agent-pipe-stop listener))))
      (error () nil))))
