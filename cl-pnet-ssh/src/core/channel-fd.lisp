(in-package #:cl-pnet-ssh)

;;;; A raw descriptor bridged to an SSH channel.
;;;;
;;;; Agent forwarding is the first user: the bytes travel between a local
;;;; Unix socket and a channel, and both sides of the protocol need exactly
;;;; the same event-loop plumbing.  The relay owns the descriptor and its
;;;; watchers, queues what the socket cannot take yet, and reports data, EOF
;;;; and errors through callbacks, so neither role has to duplicate the
;;;; non-blocking loop.

(defstruct (ssh-fd-relay (:constructor %make-ssh-fd-relay))
  (fd nil)
  ;; A Windows named-pipe handle when the relay bridges a pipe instead of a
  ;; socket; FD is then NIL and PIPE-TIMER polls PeekNamedPipe.
  (pipe nil)
  (pipe-timer nil)
  ;; :CONNECTING until a non-blocking connect finishes, then :CONNECTED.
  (phase :connected)
  (read-watcher nil)
  (write-watcher nil)
  ;; Octets the socket has not accepted yet.  SENT tracks how much of the
  ;; front of the vector is already on its way.
  (outgoing (make-array 0 :element-type '(unsigned-byte 8)
                          :adjustable t :fill-pointer 0))
  (sent 0)
  (read-closed nil)
  (closed nil)
  ;; (RELAY OCTETS) sends data toward the SSH channel.
  (on-data nil)
  ;; (RELAY) runs once the socket reaches EOF.
  (on-eof nil)
  ;; (RELAY CONDITION) runs once, after the descriptor is already closed.
  (on-error nil))

(defun ssh-fd-relay-unwatch-read (relay)
  (when (ssh-fd-relay-read-watcher relay)
    (ignore-errors (cl-pnet:fd-unwatch (ssh-fd-relay-read-watcher relay)))
    (setf (ssh-fd-relay-read-watcher relay) nil)))

(defun ssh-fd-relay-unwatch-write (relay)
  (when (ssh-fd-relay-write-watcher relay)
    (ignore-errors (cl-pnet:fd-unwatch (ssh-fd-relay-write-watcher relay)))
    (setf (ssh-fd-relay-write-watcher relay) nil)))

(defun ssh-fd-relay-close (relay)
  "Stop watching RELAY's descriptor and close it, once."
  (unless (ssh-fd-relay-closed relay)
    (setf (ssh-fd-relay-closed relay) t)
    (ssh-fd-relay-unwatch-read relay)
    (ssh-fd-relay-unwatch-write relay)
    (when (ssh-fd-relay-pipe-timer relay)
      (ignore-errors (cl-pnet:timer-stop (ssh-fd-relay-pipe-timer relay)))
      (setf (ssh-fd-relay-pipe-timer relay) nil))
    #+win32
    (when (ssh-fd-relay-pipe relay)
      (ignore-errors (c-agent-close-handle (ssh-fd-relay-pipe relay)))
      (setf (ssh-fd-relay-pipe relay) nil))
    (let ((fd (ssh-fd-relay-fd relay)))
      (when (and fd (>= fd 0))
        (ignore-errors (cl-pnet-sockets:close-open-fd fd)))
      (setf (ssh-fd-relay-fd relay) nil))))

#+win32
(defun ssh-fd-relay-pipe-eof (relay)
  "Report a pipe's end of file once, stopping its poll timer."
  (unless (or (ssh-fd-relay-closed relay)
              (ssh-fd-relay-read-closed relay))
    (setf (ssh-fd-relay-read-closed relay) t)
    (when (ssh-fd-relay-pipe-timer relay)
      (ignore-errors (cl-pnet:timer-stop (ssh-fd-relay-pipe-timer relay)))
      (setf (ssh-fd-relay-pipe-timer relay) nil))
    (when (ssh-fd-relay-on-eof relay)
      (funcall (ssh-fd-relay-on-eof relay) relay))))

#+win32
(defun ssh-fd-relay-pipe-fail (relay condition)
  "Close a pipe relay and report CONDITION through ON-ERROR."
  (unless (ssh-fd-relay-closed relay)
    (ssh-fd-relay-close relay)
    (when (ssh-fd-relay-on-error relay)
      (funcall (ssh-fd-relay-on-error relay) relay condition))))

#+win32
(defun ssh-fd-relay-pipe-poll (relay)
  "Move one pipe read's worth of octets to the channel.

PeekNamedPipe says how much is there, so ReadFile cannot block the loop."
  (unless (or (ssh-fd-relay-closed relay)
              (ssh-fd-relay-read-closed relay)
              (null (ssh-fd-relay-pipe relay)))
    (handler-case
        (multiple-value-bind (available broken)
            (agent-pipe-available (ssh-fd-relay-pipe relay))
          (cond
            (broken
             (ssh-fd-relay-pipe-eof relay))
            ((plusp available)
             (multiple-value-bind (octets count)
                 (agent-read-some (ssh-fd-relay-pipe relay)
                                  (min available 65536))
               (if (plusp count)
                   (when (ssh-fd-relay-on-data relay)
                     (funcall (ssh-fd-relay-on-data relay) relay octets))
                   (ssh-fd-relay-pipe-eof relay))))))
      (error (condition)
        (ssh-fd-relay-pipe-fail relay condition)))))

(defun ssh-fd-relay-fail (relay errno)
  "Close RELAY and report a socket error."
  (unless (ssh-fd-relay-closed relay)
    (let ((condition
            (make-condition 'ssh-channel-error
                            :detail (format nil "agent connection failed (~A)"
                                            (cl-pnet-sockets:c-strerror errno)))))
      (ssh-fd-relay-close relay)
      (when (ssh-fd-relay-on-error relay)
        (funcall (ssh-fd-relay-on-error relay) relay condition)))))

(defun ssh-fd-relay-watch-read (relay)
  (unless (or (ssh-fd-relay-closed relay)
              (ssh-fd-relay-read-closed relay)
              (ssh-fd-relay-read-watcher relay))
    (setf (ssh-fd-relay-read-watcher relay)
          (cl-pnet:fd-watch
           (ssh-fd-relay-fd relay)
           :on-readable
           (lambda (watcher)
             (declare (ignore watcher))
             (ssh-fd-relay-readable relay))))))

(defun ssh-fd-relay-watch-write (relay)
  (unless (or (ssh-fd-relay-closed relay)
              (ssh-fd-relay-write-watcher relay))
    (setf (ssh-fd-relay-write-watcher relay)
          (cl-pnet:fd-watch
           (ssh-fd-relay-fd relay)
           :on-writable
           (lambda (watcher)
             (declare (ignore watcher))
             (ssh-fd-relay-writable relay))))))

(defun ssh-fd-relay-readable (relay)
  "Move every available octet from the descriptor to the channel."
  (unless (ssh-fd-relay-closed relay)
    (loop
      (multiple-value-bind (octets count errno)
          (cl-pnet-sockets:receive-octets (ssh-fd-relay-fd relay) 32768)
        (cond
          ((plusp count)
           (when (ssh-fd-relay-on-data relay)
             (funcall (ssh-fd-relay-on-data relay) relay octets)))
          ((zerop count)
           ;; EOF: say so once, then stop watching a descriptor that would
           ;; keep reporting it.
           (ssh-fd-relay-unwatch-read relay)
           (setf (ssh-fd-relay-read-closed relay) t)
           (when (ssh-fd-relay-on-eof relay)
             (funcall (ssh-fd-relay-on-eof relay) relay))
           (return))
          ((member errno '(11 35))
           (return))
          (t
           (ssh-fd-relay-fail relay errno)
           (return)))))))

(defun ssh-fd-relay-compact (relay)
  "Drop octets the descriptor has accepted, once it has taken all of them."
  (let ((outgoing (ssh-fd-relay-outgoing relay)))
    (when (= (ssh-fd-relay-sent relay) (fill-pointer outgoing))
      (setf (fill-pointer outgoing) 0
            (ssh-fd-relay-sent relay) 0)
      (ssh-fd-relay-unwatch-write relay))))

(defun ssh-fd-relay-flush (relay)
  "Send as much of the queued octets as the descriptor accepts now."
  (when (and (eq (ssh-fd-relay-phase relay) :connected)
             (not (ssh-fd-relay-closed relay)))
    (let ((outgoing (ssh-fd-relay-outgoing relay)))
      (loop while (< (ssh-fd-relay-sent relay) (fill-pointer outgoing))
            do (multiple-value-bind (count errno)
                   (cl-pnet-sockets:send-octets
                    (ssh-fd-relay-fd relay)
                    outgoing :start (ssh-fd-relay-sent relay))
                 (cond
                   ((plusp count)
                    (incf (ssh-fd-relay-sent relay) count))
                   ((member errno '(11 35))
                    (ssh-fd-relay-watch-write relay)
                    (return))
                   (t
                    (ssh-fd-relay-fail relay errno)
                    (return)))))
      (ssh-fd-relay-compact relay))))

(defun ssh-fd-relay-writable (relay)
  "Finish a pending connect, then write what is queued."
  (unless (ssh-fd-relay-closed relay)
    (if (eq (ssh-fd-relay-phase relay) :connecting)
        (multiple-value-bind (errno answered)
            (cl-pnet-sockets:socket-error (ssh-fd-relay-fd relay))
          (cond
            ((not answered)
             (ssh-fd-relay-fail relay errno))
            ((zerop errno)
             (ssh-fd-relay-unwatch-write relay)
             (setf (ssh-fd-relay-phase relay) :connected)
             (ssh-fd-relay-watch-read relay)
             (ssh-fd-relay-flush relay))
            (t
             (ssh-fd-relay-fail relay errno))))
        (ssh-fd-relay-flush relay))))

(defun ssh-fd-relay-queue (relay octets)
  "Queue OCTETS for the descriptor, writing what it will take now."
  (unless (ssh-fd-relay-closed relay)
    (cond
      ((ssh-fd-relay-pipe relay)
       #+win32 (handler-case
                   (agent-write-all (ssh-fd-relay-pipe relay) octets)
                 (error (condition)
                   (ssh-fd-relay-pipe-fail relay condition)))
       #-win32 nil)
      (t
       (let ((outgoing (ssh-fd-relay-outgoing relay)))
         (loop for octet across octets
               do (vector-push-extend octet outgoing))
         (ssh-fd-relay-flush relay))))))

(defun ssh-fd-relay-start (relay)
  "Begin watching RELAY's descriptor for input, or for connect completion."
  (cond
    ((ssh-fd-relay-pipe relay)
     #+win32
     (unless (ssh-fd-relay-pipe-timer relay)
       (setf (ssh-fd-relay-pipe-timer relay)
             (cl-pnet:timer-start
              0 0.01
              (lambda () (ssh-fd-relay-pipe-poll relay)))))
     #-win32 nil)
    ((eq (ssh-fd-relay-phase relay) :connecting)
     (ssh-fd-relay-watch-write relay))
    (t
     (ssh-fd-relay-watch-read relay))))

(defun ssh-fd-relay-shutdown-write (relay)
  "Tell the descriptor the channel will send nothing more."
  (cond
    ((ssh-fd-relay-pipe relay)
     ;; A named pipe has no half-close: closing it is how the other end
     ;; learns that no more requests will arrive.
     #+win32
     (progn
       (let ((pipe (ssh-fd-relay-pipe relay)))
         (setf (ssh-fd-relay-pipe relay) nil)
         (ignore-errors (c-agent-close-handle pipe)))
       (ssh-fd-relay-pipe-eof relay))
     #-win32 nil)
    ((or (ssh-fd-relay-closed relay)
         (eq (ssh-fd-relay-phase relay) :connecting))
     nil)
    (t
     (let ((fd (ssh-fd-relay-fd relay)))
       (when fd
         (ignore-errors (cl-pnet-sockets:c-shutdown fd 1)))))))
