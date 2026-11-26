;;;; Windows ssh-agent transport.
;;;;
;;;; OpenSSH on Windows speaks the same agent protocol over a named pipe,
;;;; normally \\.\pipe\openssh-ssh-agent, instead of a Unix socket.  The
;;;; event loop has no polling primitive for a pipe, and CL-PNET:CALL-ON-LOOP
;;;; drops work posted before the loop starts - which is when identities are
;;;; gathered.  The exchange therefore completes inline, the way Win32-OpenSSH
;;;; itself talks to its agent.  Agent messages are small and local; the Unix
;;;; transport remains non-blocking for callers that need that.
;;;; This component is built on Windows only; agent.lisp dispatches to
;;;; SSH-AGENT-REQUEST-WINDOWS and keeps its non-blocking Unix transport.

(in-package #:cl-pnet-ssh)

(cffi:define-foreign-library cl-pnet-ssh-agent-kernel32
  (:windows "kernel32.dll"))
(cffi:use-foreign-library cl-pnet-ssh-agent-kernel32)

(cffi:defcfun ("CreateFileW" c-agent-create-file) :pointer
  (name :pointer) (access :unsigned-long) (share :unsigned-long)
  (security :pointer) (creation :unsigned-long) (flags :unsigned-long)
  (template :pointer))
(cffi:defcfun ("ReadFile" c-agent-read-file) :int
  (handle :pointer) (buffer :pointer) (length :unsigned-long)
  (read :pointer) (overlapped :pointer))
(cffi:defcfun ("WriteFile" c-agent-write-file) :int
  (handle :pointer) (buffer :pointer) (length :unsigned-long)
  (written :pointer) (overlapped :pointer))
(cffi:defcfun ("CloseHandle" c-agent-close-handle) :int (handle :pointer))
(cffi:defcfun ("GetLastError" c-agent-last-error) :unsigned-long)
(cffi:defcfun ("WaitNamedPipeW" c-agent-wait-named-pipe) :int
  (name :pointer) (timeout :unsigned-long))
(cffi:defcfun ("PeekNamedPipe" c-agent-peek-named-pipe) :int
  (handle :pointer) (buffer :pointer) (size :unsigned-long)
  (read :pointer) (available :pointer) (left :pointer))

(defconstant +agent-generic-read+ #x80000000)
(defconstant +agent-generic-write+ #x40000000)
(defconstant +agent-open-existing+ 3)
(defconstant +agent-file-attribute-normal+ #x80)

(defparameter +ssh-default-agent-pipe+ "\\\\.\\pipe\\openssh-ssh-agent"
  "The pipe Win32-OpenSSH's ssh-add and ssh use when SSH_AUTH_SOCK is unset.")

(defun agent-invalid-handle-p (handle)
  (cffi:pointer-eq
   handle
   (cffi:make-pointer
    (1- (ash 1 (* 8 (cffi:foreign-type-size :pointer)))))))

(defun agent-error-text (errno)
  (cl-pnet-sockets:c-strerror errno))

(defun agent-open-pipe (path)
  "Open the named pipe at PATH, or signal an authentication error.

A busy agent (ERROR_PIPE_BUSY, 231) is waited for once, as Win32-OpenSSH's
ssh-add does, rather than failing a login while another client finishes."
  (multiple-value-bind (name name-length)
      (windows-utf16-pointer (substitute #\\ #\/ path))
    (declare (ignore name-length))
    (labels ((open-handle ()
               (c-agent-create-file
                name
                (logior +agent-generic-read+ +agent-generic-write+)
                0 (cffi:null-pointer) +agent-open-existing+
                +agent-file-attribute-normal+ (cffi:null-pointer))))
      (unwind-protect
           (let ((handle (open-handle)))
             (when (and (agent-invalid-handle-p handle)
                        (eql (c-agent-last-error) 231)
                        (plusp (c-agent-wait-named-pipe name 2000)))
               (setf handle (open-handle)))
             (when (agent-invalid-handle-p handle)
               (error 'ssh-authentication-error
                      :detail (format nil "cannot connect to the ssh-agent at ~A: ~A"
                                      path
                                      (agent-error-text (c-agent-last-error)))))
             handle)
        (cffi:foreign-free name)))))

(defun agent-write-all (handle octets)
  "Write every octet of OCTETS to HANDLE."
  (cffi:with-pointer-to-vector-data (pointer octets)
    (loop with length = (length octets)
          with offset = 0
          while (< offset length)
          do (cffi:with-foreign-object (count :unsigned-long)
               (unless (plusp (c-agent-write-file
                               handle (cffi:inc-pointer pointer offset)
                               (- length offset) count (cffi:null-pointer)))
                 (error 'ssh-authentication-error
                        :detail (format nil "cannot write to the ssh-agent: ~A"
                                        (agent-error-text
                                         (c-agent-last-error)))))
               (let ((written (cffi:mem-ref count :unsigned-long)))
                 (when (zerop written)
                   (error 'ssh-authentication-error
                          :detail "the ssh-agent closed the connection"))
                 (incf offset written))))))

(defun agent-read-exactly (handle count)
  "COUNT octets from HANDLE, or signal an authentication error."
  (let ((buffer (make-array count :element-type '(unsigned-byte 8))))
    (cffi:with-pointer-to-vector-data (pointer buffer)
      (loop with offset = 0
            while (< offset count)
            do (cffi:with-foreign-object (read :unsigned-long)
                 (unless (plusp (c-agent-read-file
                                 handle (cffi:inc-pointer pointer offset)
                                 (- count offset) read (cffi:null-pointer)))
                   (error 'ssh-authentication-error
                          :detail (format nil "cannot read from the ssh-agent: ~A"
                                          (agent-error-text
                                           (c-agent-last-error)))))
                 (let ((got (cffi:mem-ref read :unsigned-long)))
                   (when (zerop got)
                     (error 'ssh-authentication-error
                            :detail "the ssh-agent closed the connection"))
                   (incf offset got)))))
    buffer))

(defun agent-read-reply (handle)
  "One length-prefixed agent reply from HANDLE."
  (let ((length (ssh-octets-uint32 (agent-read-exactly handle 4))))
    (when (or (zerop length) (> length (* 1024 1024)))
      (error 'ssh-authentication-error
             :detail "the ssh-agent sent an invalid reply length"))
    (agent-read-exactly handle length)))

(defun agent-pipe-available (handle)
  "VALUES BYTES BROKEN-P for the agent pipe HANDLE.

PeekNamedPipe never blocks, so the event loop can poll a pipe the way it
watches a socket."
  (cffi:with-foreign-object (available :unsigned-long)
    (setf (cffi:mem-ref available :unsigned-long) 0)
    (if (plusp (c-agent-peek-named-pipe handle (cffi:null-pointer) 0
                                        (cffi:null-pointer) available
                                        (cffi:null-pointer)))
        (values (cffi:mem-ref available :unsigned-long) nil)
        (let ((errno (c-agent-last-error)))
          ;; ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED and the closing
          ;; state all mean the other end is gone.
          (if (member errno '(109 232 233))
              (values 0 t)
              (error 'ssh-authentication-error
                     :detail (format nil "cannot check the ssh-agent pipe: ~A"
                                     (agent-error-text errno))))))))

(defun agent-read-some (handle size)
  "VALUES OCTETS COUNT read from HANDLE; COUNT is zero at end of file.

Only call this after AGENT-PIPE-AVAILABLE reports octets, because ReadFile
blocks when the pipe is empty."
  (let ((buffer (make-array size :element-type '(unsigned-byte 8))))
    (cffi:with-pointer-to-vector-data (pointer buffer)
      (cffi:with-foreign-object (read :unsigned-long)
        (if (plusp (c-agent-read-file handle pointer size read
                                      (cffi:null-pointer)))
            (let ((count (cffi:mem-ref read :unsigned-long)))
              (values (subseq buffer 0 count) count))
            (let ((errno (c-agent-last-error)))
              (if (member errno '(109 232 233))
                  (values (make-array 0 :element-type '(unsigned-byte 8)) 0)
                  (error 'ssh-authentication-error
                         :detail
                         (format nil "cannot read from the ssh-agent: ~A"
                                 (agent-error-text errno))))))))))

(defun ssh-agent-request-windows (path payload on-response on-error)
  "Send PAYLOAD to the named-pipe agent at PATH and report its reply.

Named pipes have no poll primitive here, so the exchange completes before
this returns and the callback runs on the caller's thread.  This is the
same blocking shape Win32-OpenSSH uses for its agent, and it is what lets
identity discovery finish before the event loop starts."
  (let ((message (ssh-concat (ssh-uint32-octets (length payload)) payload)))
    (handler-case
        (let ((handle (agent-open-pipe path)))
          (unwind-protect
               (progn
                 (agent-write-all handle message)
                 (funcall on-response (agent-read-reply handle)))
            (ignore-errors (c-agent-close-handle handle))))
      (error (condition)
        (funcall on-error condition))))
  t)

(defun ssh-windows-agent-available-p
    (&optional (path +ssh-default-agent-pipe+))
  "Whether the Windows agent pipe at PATH has an instance free.

WaitNamedPipe with a zero timeout only asks; it does not connect, so
checking availability many times cannot consume the agent's instances."
  (handler-case
      (multiple-value-bind (name name-length)
          (windows-utf16-pointer (substitute #\\ #\/ path))
        (declare (ignore name-length))
        (unwind-protect
             (plusp (c-agent-wait-named-pipe name 0))
          (cffi:foreign-free name)))
    (error () nil)))
