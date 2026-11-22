(in-package #:cl-pnet-ssh)

;;;; ProxyCommand: reaching a server only through a helper program.
;;;;
;;;; netcat, nc -X, cloudflared and bastion wrappers all work the same way:
;;;; the helper carries the SSH byte stream on its stdin and stdout.  The
;;;; helper runs as a child of this process and CL-PNET's event loop watches
;;;; its two pipes, so the protocol code above never learns that the bytes
;;;; did not come from a TCP socket.
;;;;
;;;; Only what OpenSSH's ProxyCommand means is here: the command is run by
;;;; the shell with %h, %n, %p, %r and %% expanded, its stderr is inherited,
;;;; and it is killed when the session closes.

(defparameter +ssh-eagain+
  #+(or darwin freebsd netbsd openbsd dragonfly) 35
  #-(or darwin freebsd netbsd openbsd dragonfly) 11
  "The errno a non-blocking read or write reports when it should wait.")

(defstruct (ssh-proxy (:constructor %make-ssh-proxy))
  command
  process
  ;; PARENT writes the child's stdin, PARENT reads the child's stdout.
  input-stream
  output-stream
  read-fd
  write-fd
  read-watcher
  write-watcher
  ;; ProxyUseFdpass: the socketpair end on which the helper sends the
  ;; connected descriptor, and a watcher waiting for it.
  control-fd
  control-watcher
  ;; Whether READ-FD and WRITE-FD are raw descriptors this structure owns.
  ;; Pipe mode leaves them to the streams; fdpass mode owns them.
  (close-fds nil)
  (queue (make-array 0 :element-type '(unsigned-byte 8)
                       :adjustable t :fill-pointer 0))
  (position 0)
  (closed nil))

;;; ---- Reading the command ----

(defun ssh-proxy-expand-command (command client)
  "COMMAND with OpenSSH's ProxyCommand escapes filled in.

%h is the host actually dialled (HostName in ssh_config), %n the name the
user typed, %p the port and %r the remote user; %% is a literal percent.
An escape this client does not know is left alone rather than eaten."
  (let ((host (ssh-client-connect-host client))
        (original (ssh-client-host client))
        (port (or (ssh-client-connect-port client) (ssh-client-port client)))
        (user (or (ssh-client-user client) ""))
        (out (make-string-output-stream)))
    (loop with length = (length command)
          for index = 0 then (1+ index)
          while (< index length)
          do (let ((character (char command index)))
               (cond
                 ((and (char= character #\%)
                       (< (1+ index) length))
                  (let ((escape (char command (1+ index))))
                    (incf index)
                    (case escape
                      (#\% (write-char #\% out))
                      (#\h (write-string host out))
                      (#\n (write-string original out))
                      (#\p (princ port out))
                      (#\r (write-string user out))
                      (t (write-char #\% out)
                         (write-char escape out)))))
                 (t (write-char character out)))))
    (get-output-stream-string out)))

(defun ssh-proxy-stream-fd (stream)
  "The descriptor behind STREAM, or signal when this Lisp cannot tell."
  #+sbcl (sb-sys:fd-stream-fd stream)
  #-(or sbcl)
  (declare (ignore stream))
  #-(or sbcl)
  (error 'ssh-connection-error
         :detail "ProxyCommand needs a Lisp that exposes a stream's descriptor"))

(defun ssh-proxy-fail (client control &rest arguments)
  (ssh-client-fail
   client
   (make-condition 'ssh-connection-error
                   :detail (apply #'format nil control arguments))))

(defun ssh-proxy-launch-helper (command)
  "Start COMMAND under /bin/sh and return its process.

The helper is a child process, so the shell forks netcat rather than
replacing itself.  Shutdown closes the pipes and kills the shell; a helper
that reads its stdin then sees EOF, as nc and socat do."
  (uiop:launch-program (list "/bin/sh" "-c" command)
                       :input :stream
                       :output :stream
                       :element-type '(unsigned-byte 8)))

(defun ssh-proxy-kill-process (process)
  "Kill PROCESS.  Reaping is left to the Lisp's SIGCHLD handling.

Waiting here would be wrong: shutdown often runs inside an event-loop
callback, where a blocking wait on an already-exited helper can hang."
  (when process
    (ignore-errors (uiop:terminate-process process :urgent t))))

(defun ssh-proxy-send (client octets)
  "Queue OCTETS for CLIENT's helper and write what the pipe accepts now."
  (let ((proxy (ssh-client-pipe client)))
    (when (and proxy (ssh-client-proxy-open-p proxy))
      (when (and octets (plusp (length octets)))
        (let* ((queue (ssh-proxy-queue proxy))
               (start (fill-pointer queue))
               (total (+ start (length octets))))
          (setf queue (adjust-array queue total :fill-pointer total)
                (ssh-proxy-queue proxy) queue)
          (replace queue octets :start1 start)))
      (ssh-proxy-flush client)))
  (not (ssh-client-closed client)))

(defun ssh-client-proxy-open-p (proxy)
  "Whether PROXY still has live pipes to use."
  (and proxy
       (not (ssh-proxy-closed proxy))
       (ssh-proxy-write-fd proxy)))

(defun ssh-proxy-flush (client)
  "Write queued bytes until the helper's stdin blocks or the queue drains."
  (let ((proxy (ssh-client-pipe client)))
    (when (and proxy (ssh-client-proxy-open-p proxy))
      (let ((queue (ssh-proxy-queue proxy)))
        (loop while (< (ssh-proxy-position proxy) (fill-pointer queue))
              do (multiple-value-bind (count errno)
                     (cl-pnet-sockets:write-octets
                      (ssh-proxy-write-fd proxy) queue
                      :start (ssh-proxy-position proxy))
                   (cond
                     ((plusp count)
                      (incf (ssh-proxy-position proxy) count))
                     ((and (minusp count) (/= errno +ssh-eagain+))
                      (ssh-proxy-fail
                       client "the ProxyCommand stopped reading its input (~A)"
                       (cl-pnet-sockets:c-strerror errno))
                      (return))
                     (t (return)))))
        (when (>= (ssh-proxy-position proxy) (fill-pointer queue))
          (setf (fill-pointer queue) 0
                (ssh-proxy-position proxy) 0)
          (ssh-proxy-cancel-write-watcher proxy))
        (when (and (ssh-proxy-write-fd proxy)
                   (not (ssh-proxy-closed proxy))
                   (< (ssh-proxy-position proxy) (fill-pointer queue))
                   (not (ssh-proxy-write-watcher proxy)))
          (setf (ssh-proxy-write-watcher proxy)
                (cl-pnet:fd-watch
                 (ssh-proxy-write-fd proxy)
                 :on-writable
                 (lambda (watcher)
                   (declare (ignore watcher))
                   (ssh-proxy-flush client)))))))
  t))

(defun ssh-proxy-cancel-write-watcher (proxy)
  (let ((watcher (ssh-proxy-write-watcher proxy)))
    (when watcher
      (setf (ssh-proxy-write-watcher proxy) nil)
      (ignore-errors (cl-pnet:fd-unwatch watcher)))))

(defun ssh-proxy-cancel-control-watcher (proxy)
  (let ((watcher (ssh-proxy-control-watcher proxy)))
    (when watcher
      (setf (ssh-proxy-control-watcher proxy) nil)
      (ignore-errors (cl-pnet:fd-unwatch watcher)))))

;;; ---- ProxyUseFdpass ----

(defun ssh-proxy-fdpass-child-stream (fd)
  "FD as a stream for the helper's stdin and stdout.

A real SBCL file stream is what makes RUN-PROGRAM hand the descriptor
itself to the child; wrapping it in a Lisp-visible stream would make the
child inherit a pipe, and a pipe cannot carry SCM_RIGHTS."
  #+sbcl
  (sb-sys:make-fd-stream fd :input t :output t :buffering :none)
  #-sbcl
  (progn
    (declare (ignore fd))
    (error 'ssh-connection-error
           :detail "ProxyUseFdpass needs a Lisp that can hand a descriptor to a child")))

(defun ssh-proxy-launch-fdpass-helper (command fd)
  "Run COMMAND with FD as both its stdin and stdout, returning the process.

The child keeps its own descriptor for FD, so this side closes the stream
at once; the parent waits on its end of the socketpair for the connected
socket the helper sends back."
  (let ((stream nil))
    (unwind-protect
         (progn
           (setf stream (ssh-proxy-fdpass-child-stream fd))
           (uiop:launch-program (list "/bin/sh" "-c" command)
                                :input stream :output stream))
      (if stream
          (ignore-errors (close stream))
          (ignore-errors (cl-pnet-sockets:c-close fd))))))

(defun ssh-proxy-adopt-fd (client fd)
  "Use FD, a connected socket the helper sent, as CLIENT's transport."
  (let ((proxy (ssh-client-pipe client)))
    (cond
      ((or (null proxy) (ssh-proxy-closed proxy))
       (ignore-errors (cl-pnet-sockets:c-close fd)))
      (t
       ;; The control socket has done its job; the connected socket replaces
       ;; it and is now this structure's to close.
       (ssh-proxy-cancel-control-watcher proxy)
       (when (ssh-proxy-control-fd proxy)
         (ignore-errors
          (cl-pnet-sockets:c-close (ssh-proxy-control-fd proxy)))
         (setf (ssh-proxy-control-fd proxy) nil))
       (cl-pnet-sockets:set-nonblocking fd)
       (setf (ssh-proxy-read-fd proxy) fd
             (ssh-proxy-write-fd proxy) fd
             (ssh-proxy-close-fds proxy) t
             (ssh-proxy-read-watcher proxy)
             (cl-pnet:fd-watch
              fd
              :on-readable
              (lambda (watcher)
                (declare (ignore watcher))
                (ssh-proxy-readable client))))
       (ssh-log "ProxyUseFdpass received the connected socket")
       (ssh-client-connected client nil)))))

(defun ssh-proxy-fdpass-receive (client)
  "Take the helper's connected descriptor, then start the handshake on it."
  (let ((proxy (ssh-client-pipe client)))
    (when (and proxy
               (not (ssh-proxy-closed proxy))
               (ssh-proxy-control-fd proxy))
      (multiple-value-bind (fd errno)
          (cl-pnet-sockets:receive-fd (ssh-proxy-control-fd proxy))
        (cond
          (fd (ssh-proxy-adopt-fd client fd))
          ((eql errno +ssh-eagain+) nil)
          ((zerop errno)
           (ssh-proxy-fail
            client
            "the ProxyCommand closed the descriptor channel without passing a connection"))
          (t
           (ssh-proxy-fail
            client "receiving a ProxyCommand descriptor failed (~A)"
            (cl-pnet-sockets:c-strerror errno))))))))

(defun ssh-open-fdpass-connection (client)
  "Run CLIENT's ProxyCommand with a socketpair and take back a connected fd."
  (handler-case
      (let ((command (ssh-proxy-expand-command
                      (ssh-client-proxy-command client) client)))
        (if (string= command "-")
            (ssh-proxy-fail
             client "ProxyCommand=- and ProxyUseFDPass are incompatible")
            (multiple-value-bind (parent child errno)
                (cl-pnet-sockets:make-socketpair)
              (if (null parent)
                  (ssh-proxy-fail
                   client
                   "could not create the ProxyUseFdpass socketpair (~A)"
                   (cl-pnet-sockets:c-strerror errno))
                  (let ((process nil))
                    (handler-case
                        (setf process
                              (ssh-proxy-launch-fdpass-helper command child))
                      (error (condition)
                        (ignore-errors (cl-pnet-sockets:c-close parent))
                        (error condition)))
                    (cl-pnet-sockets:set-nonblocking parent)
                    (let ((proxy (%make-ssh-proxy
                                  :command command
                                  :process process
                                  :control-fd parent)))
                      (ssh-log "started ProxyUseFdpass helper: ~A" command)
                      (setf (ssh-client-pipe client) proxy
                            (ssh-proxy-control-watcher proxy)
                            (cl-pnet:fd-watch
                             parent
                             :on-readable
                             (lambda (watcher)
                               (declare (ignore watcher))
                               (ssh-proxy-fdpass-receive client))))))))))
    (error (condition) (ssh-client-fail client condition)))
  client)

(defun ssh-proxy-readable (client)
  "Hand what the helper wrote to the protocol, and report its exit as EOF."
  (let ((proxy (ssh-client-pipe client)))
    (when (and proxy
               (not (ssh-proxy-closed proxy))
               (not (ssh-client-closed client)))
      (multiple-value-bind (octets count errno)
          (cl-pnet-sockets:read-octets (ssh-proxy-read-fd proxy) 65536)
        (cond
          ((and octets (plusp count))
           (ssh-client-receive client octets))
          ((zerop count)
           ;; The helper closed its output: one close, not a hang.
           (ssh-client-receive client nil))
          ((= errno +ssh-eagain+)
           nil)
          (t
           (ssh-proxy-fail
            client "reading from the ProxyCommand failed (~A)"
            (cl-pnet-sockets:c-strerror errno))))))))

(defun ssh-proxy-close (client)
  "Stop watching CLIENT's helper, kill it, and close its pipes."
  (let ((proxy (ssh-client-pipe client)))
    (when proxy
      (setf (ssh-client-pipe client) nil)
      (ssh-proxy-shutdown proxy))))

(defun ssh-proxy-shutdown (proxy)
  "Release every resource PROXY holds; safe to call more than once."
  (unless (ssh-proxy-closed proxy)
    (setf (ssh-proxy-closed proxy) t)
    (dolist (watcher (list (ssh-proxy-read-watcher proxy)
                           (ssh-proxy-write-watcher proxy)
                           (ssh-proxy-control-watcher proxy)))
      (when watcher
        (ignore-errors (cl-pnet:fd-unwatch watcher))))
    (setf (ssh-proxy-read-watcher proxy) nil
          (ssh-proxy-write-watcher proxy) nil
          (ssh-proxy-control-watcher proxy) nil)
    ;; Close the helper's stdin and the read end first: EOF and EPIPE make a
    ;; well-behaved helper (nc, socat) exit on its own before the kill below.
    (dolist (stream (list (ssh-proxy-input-stream proxy)
                          (ssh-proxy-output-stream proxy)))
      (when stream
        (ignore-errors (close stream))))
    (setf (ssh-proxy-input-stream proxy) nil
          (ssh-proxy-output-stream proxy) nil)
    ;; In fdpass mode the descriptors are ours rather than a stream's.
    (when (ssh-proxy-close-fds proxy)
      (let ((read-fd (ssh-proxy-read-fd proxy))
            (write-fd (ssh-proxy-write-fd proxy)))
        (when read-fd
          (ignore-errors (cl-pnet-sockets:c-close read-fd)))
        (when (and write-fd (/= write-fd read-fd))
          (ignore-errors (cl-pnet-sockets:c-close write-fd)))))
    (when (ssh-proxy-control-fd proxy)
      (ignore-errors (cl-pnet-sockets:c-close (ssh-proxy-control-fd proxy))))
    (when (ssh-proxy-process proxy)
      (ssh-proxy-kill-process (ssh-proxy-process proxy))
      (setf (ssh-proxy-process proxy) nil))
    (setf (ssh-proxy-read-fd proxy) nil
          (ssh-proxy-write-fd proxy) nil
          (ssh-proxy-control-fd proxy) nil)))

(defun ssh-open-proxy-connection (client)
  "Start CLIENT's ProxyCommand and begin the handshake over its pipes.

ProxyUseFdpass changes the contract: the helper connects the socket and
sends the descriptor back, so that path waits for it before greeting."
  (if (ssh-client-proxy-use-fdpass client)
      (ssh-open-fdpass-connection client)
      (handler-case
          (let* ((command (ssh-proxy-expand-command
                           (ssh-client-proxy-command client) client))
                 (process (ssh-proxy-launch-helper command))
                 (input (uiop:process-info-input process))
                 (output (uiop:process-info-output process)))
            (handler-case
                (let* ((write-fd (ssh-proxy-stream-fd input))
                       (read-fd (ssh-proxy-stream-fd output))
                       (proxy (%make-ssh-proxy
                               :command command
                               :process process
                               :input-stream input
                               :output-stream output
                               :write-fd write-fd
                               :read-fd read-fd)))
                  (cl-pnet-sockets:set-nonblocking write-fd)
                  (cl-pnet-sockets:set-nonblocking read-fd)
                  (setf (ssh-client-pipe client) proxy)
                  (setf (ssh-proxy-read-watcher proxy)
                        (cl-pnet:fd-watch
                         read-fd
                         :on-readable
                         (lambda (watcher)
                           (declare (ignore watcher))
                           (ssh-proxy-readable client))))
                  ;; GREET through the pipe: CONNECTED only needs the transport
                  ;; ready, and the version line then queues on the same path.
                  (ssh-client-connected client nil))
              (error (condition)
                (ssh-proxy-kill-process process)
                (ignore-errors (close input))
                (ignore-errors (close output))
                (error condition))))
        (error (condition) (ssh-client-fail client condition))))
  client)
