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
                           (ssh-proxy-write-watcher proxy)))
      (when watcher
        (ignore-errors (cl-pnet:fd-unwatch watcher))))
    (setf (ssh-proxy-read-watcher proxy) nil
          (ssh-proxy-write-watcher proxy) nil)
    ;; Close the helper's stdin and the read end first: EOF and EPIPE make a
    ;; well-behaved helper (nc, socat) exit on its own before the kill below.
    (dolist (stream (list (ssh-proxy-input-stream proxy)
                          (ssh-proxy-output-stream proxy)))
      (when stream
        (ignore-errors (close stream))))
    (setf (ssh-proxy-input-stream proxy) nil
          (ssh-proxy-output-stream proxy) nil)
    (when (ssh-proxy-process proxy)
      (ssh-proxy-kill-process (ssh-proxy-process proxy))
      (setf (ssh-proxy-process proxy) nil))
    (setf (ssh-proxy-read-fd proxy) nil
          (ssh-proxy-write-fd proxy) nil)))

(defun ssh-open-proxy-connection (client)
  "Start CLIENT's ProxyCommand and begin the handshake over its pipes."
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
    (error (condition) (ssh-client-fail client condition)))
  client)
