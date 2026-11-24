(in-package #:burs)

;;;; OpenSSH connection multiplexing.
;;;;
;;;; A control master keeps one SSH connection and listens on a Unix-domain
;;;; socket.  A later client connects to that socket, asks the master to open
;;;; a session on the existing connection, and hands over its stdin, stdout
;;;; and stderr descriptors.  The bytes then move directly between those
;;;; descriptors and the SSH channel, so the control socket carries only
;;;; small messages.  The framing, message numbers and SCM_RIGHTS descriptor
;;;; passing follow OpenSSH's mux.c, so ssh(1) and burs can share a master.
;;;;
;;;; The master runs on the event loop, because it owns the SSH connection.
;;;; A client that attaches to an existing master has nothing else to do and
;;;; uses blocking reads, so it never starts a loop.

;;; ---- Wire protocol ----

(defconstant +mux-version+ 4)

(defconstant +mux-msg-hello+ #x00000001)
(defconstant +mux-c-new-session+ #x10000002)
(defconstant +mux-c-alive-check+ #x10000004)
(defconstant +mux-c-terminate+ #x10000005)
(defconstant +mux-c-open-fwd+ #x10000006)
(defconstant +mux-c-close-fwd+ #x10000007)
(defconstant +mux-c-new-stdio-fwd+ #x10000008)
(defconstant +mux-c-stop-listening+ #x10000009)
(defconstant +mux-c-proxy+ #x1000000f)
(defconstant +mux-c-ext-info+ #x20000001)

(defconstant +mux-s-ok+ #x80000001)
(defconstant +mux-s-permission-denied+ #x80000002)
(defconstant +mux-s-failure+ #x80000003)
(defconstant +mux-s-exit-message+ #x80000004)
(defconstant +mux-s-alive+ #x80000005)
(defconstant +mux-s-session-opened+ #x80000006)
(defconstant +mux-s-remote-port+ #x80000007)
(defconstant +mux-s-tty-alloc-fail+ #x80000008)
(defconstant +mux-s-proxy+ #x8000000f)
(defconstant +mux-s-ext-info+ #x90000001)

(defconstant +mux-fwd-local+ 1)
(defconstant +mux-fwd-remote+ 2)
(defconstant +mux-fwd-dynamic+ 3)

(defconstant +mux-port-streamlocal+ #xfffffffe)
(defconstant +mux-max-frame+ (* 16 1024 1024))

(defun mux-u32 (octets position)
  (logior (ash (aref octets position) 24)
          (ash (aref octets (+ position 1)) 16)
          (ash (aref octets (+ position 2)) 8)
          (aref octets (+ position 3))))

(defun mux-frame (payload)
  "PAYLOAD with the four-byte length prefix mux.c puts in front of a packet."
  (let ((frame (make-array (+ 4 (length payload))
                           :element-type '(unsigned-byte 8))))
    (setf (aref frame 0) (ldb (byte 8 24) (length payload))
          (aref frame 1) (ldb (byte 8 16) (length payload))
          (aref frame 2) (ldb (byte 8 8) (length payload))
          (aref frame 3) (ldb (byte 8 0) (length payload)))
    (replace frame payload :start1 4)
    frame))

(defun mux-payload (&rest fields)
  "A payload of u32 and string fields, in the order given.

A string field is a cons (\"string\" . value); every other field is written
as a u32, which is how every mux message is built."
  (let ((writer (cl-pnet-ssh:ssh-writer)))
    (dolist (field fields)
      (if (consp field)
          (cl-pnet-ssh:ssh-write-text writer (or (cdr field) ""))
          (cl-pnet-ssh::ssh-write-u32 writer field)))
    (cl-pnet-ssh:ssh-writer-output writer)))

(defun mux-hello-payload (&optional extensions)
  "HELLO with EXTENSIONS, an alist of (NAME . VALUE).

The client sends none, as ssh(1) does; the master advertises the ones it
implements.  Both sides skip the pairs they do not recognise."
  (let ((writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh::ssh-write-u32 writer +mux-msg-hello+)
    (cl-pnet-ssh::ssh-write-u32 writer +mux-version+)
    (dolist (extension extensions)
      (cl-pnet-ssh:ssh-write-text writer (car extension))
      (cl-pnet-ssh:ssh-write-text writer (cdr extension)))
    (cl-pnet-ssh:ssh-writer-output writer)))

(defun mux-request-payload (type request-id &rest fields)
  (apply #'mux-payload type request-id fields))

(defun mux-ok-payload (request-id)
  (mux-request-payload +mux-s-ok+ request-id))

(defun mux-error-payload (type request-id message)
  (mux-request-payload type request-id (cons "error" message)))

(defun mux-process-id ()
  #+win32 0
  #-win32 (cffi:foreign-funcall "getpid" :int))

;;; ---- Blocking helpers for the client side ----

#-win32
(defun mux-read-exact (fd count)
  "Read exactly COUNT octets from the blocking descriptor FD."
  (let ((buffer (make-array count :element-type '(unsigned-byte 8)))
        (have 0))
    (loop while (< have count)
          do (multiple-value-bind (octets got error)
                 (cl-pnet-sockets:read-octets fd (- count have))
               (cond
                 ((plusp got)
                  (replace buffer octets :start1 have)
                  (incf have got))
                 ((and (minusp got) (eql error 4))) ; EINTR
                 (t
                  (error "the control socket closed before ~D octets" count)))))
    buffer))

#-win32
(defun mux-write-all (fd octets)
  (let ((have 0)
        (end (length octets)))
    (loop while (< have end)
          do (multiple-value-bind (count error)
                 (cl-pnet-sockets:write-octets fd octets :start have :end end)
               (cond
                 ((plusp count) (incf have count))
                 ((and (minusp count) (eql error 4)))
                 (t
                  (error "write to the control socket failed (~A)" error)))))))

#-win32
(defun mux-read-packet (fd)
  (let* ((header (mux-read-exact fd 4))
         (length (mux-u32 header 0)))
    (when (> length +mux-max-frame+)
      (error "the control master sent an oversized frame"))
    (mux-read-exact fd length)))

#-win32
(defun mux-write-packet (fd payload)
  (mux-write-all fd (mux-frame payload)))

#-win32
(defun mux-connect (path)
  "A blocking descriptor connected to the control socket PATH, or NIL."
  (let ((fd (cl-pnet-sockets:c-socket cl-pnet-sockets:+af-unix+
                                      cl-pnet-sockets:+sock-stream+ 0)))
    (when (minusp fd)
      (return-from mux-connect nil))
    (multiple-value-bind (address length)
        (cl-pnet-sockets:make-sockaddr-un path)
      (unwind-protect
           (if (minusp (cl-pnet-sockets:c-connect fd address length))
               (let ((errno (cl-pnet-sockets:c-errno)))
                 (cl-pnet-sockets:c-close fd)
                 (values nil errno))
               fd)
        (cffi:foreign-free address)))))

#-win32
(defun mux-close (fd)
  (when (and fd (>= fd 0))
    (ignore-errors (cl-pnet-sockets:close-open-fd fd))))

(cffi:defcfun ("link" mux-c-link) :int
  (old-path :string) (new-path :string))

(defun mux-tilde-expand (path)
  "PATH with a leading ~ or ~USER replaced by that account's directory."
  (if (or (zerop (length path)) (not (char= (char path 0) #\~)))
      path
      (let* ((slash (position #\/ path))
             (user (subseq path 1 (or slash (length path))))
             (rest (if slash (subseq path slash) ""))
             (home
               (cond
                 ((string= user "") (uiop:getenv "HOME"))
                 (t
                  (handler-case
                      (with-open-file (stream "/etc/passwd")
                        (loop for line = (read-line stream nil nil)
                              while line
                              for fields = (uiop:split-string line :separator ":")
                              when (and (>= (length fields) 6)
                                        (string= (first fields) user))
                                return (sixth fields)))
                    (error () nil))))))
        (if home (concatenate 'string home rest) path))))

#-win32
(defun mux-temporary-control-path (path)
  "A path beside PATH that a listener can be bound to before it is linked."
  (format nil "~A.~36R-~D" path (get-universal-time) (mux-process-id)))

#-win32
(defun mux-handshake (fd)
  "Exchange HELLO with the master on FD; return its extension names.

The master speaks first, as OpenSSH's does.  Its hello may carry (NAME
VALUE) pairs after the version; only the names matter to this client, and
unknown names are ignored exactly as ssh(1) ignores them."
  (let* ((payload (mux-read-packet fd))
         (type (and (>= (length payload) 4) (mux-u32 payload 0))))
    (unless (eql type +mux-msg-hello+)
      (error "the control socket did not answer with a mux hello"))
    (when (< (length payload) 8)
      (error "the control master sent a truncated hello"))
    (let ((version (mux-u32 payload 4))
          (extensions '()))
      (unless (= version +mux-version+)
        (error "unsupported control master version ~D" version))
      (let ((reader (cl-pnet-ssh:ssh-make-reader payload 8)))
        (loop while (plusp (cl-pnet-ssh:ssh-reader-remaining reader))
              do (let ((name (cl-pnet-ssh:ssh-read-text reader)))
                   (cl-pnet-ssh:ssh-read-text reader) ; value
                   (push name extensions))))
      (mux-write-packet fd (mux-hello-payload))
      (nreverse extensions))))

#-win32
(defun mux-alive (fd)
  "Ask the master for its pid."
  (mux-write-packet fd (mux-request-payload +mux-c-alive-check+ 0))
  (let ((payload (mux-read-packet fd)))
    (unless (eql (mux-u32 payload 0) +mux-s-alive+)
      (error "the control master did not answer the alive check"))
    (mux-u32 payload 8)))

#-win32
(defun mux-read-reply (fd request-id)
  "The reply to REQUEST-ID as (VALUES TYPE READER)."
  (let* ((payload (mux-read-packet fd))
         (type (mux-u32 payload 0))
         (rid (mux-u32 payload 4)))
    (unless (= rid request-id)
      (error "the control master answered request ~D, not ~D" rid request-id))
    (values type (cl-pnet-ssh:ssh-make-reader payload 8))))

(defstruct (mux-request (:constructor %make-mux-request))
  (want-tty nil)
  (want-subsystem nil)
  (escape-char #xffffffff)
  term
  command
  env)

#-win32
(defun mux-new-session-payload (request-id request)
  (let ((writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh::ssh-write-u32 writer +mux-c-new-session+)
    (cl-pnet-ssh::ssh-write-u32 writer request-id)
    (cl-pnet-ssh:ssh-write-string
     writer (make-array 0 :element-type '(unsigned-byte 8))) ; reserved
    (cl-pnet-ssh::ssh-write-u32
     writer (if (mux-request-want-tty request) 1 0))
    (cl-pnet-ssh::ssh-write-u32 writer 0) ; X11
    (cl-pnet-ssh::ssh-write-u32 writer 0) ; agent
    (cl-pnet-ssh::ssh-write-u32
     writer (if (mux-request-want-subsystem request) 1 0))
    (cl-pnet-ssh::ssh-write-u32 writer (mux-request-escape-char request))
    (cl-pnet-ssh:ssh-write-text writer (or (mux-request-term request) ""))
    (cl-pnet-ssh:ssh-write-text writer (or (mux-request-command request) ""))
    (dolist (entry (mux-request-env request))
      (cl-pnet-ssh:ssh-write-text writer entry))
    (cl-pnet-ssh:ssh-writer-output writer)))

#-win32
(defun mux-open-forward-payload (request-id cancel-p type listen-host
                                 listen-port connect-host connect-port)
  (mux-request-payload (if cancel-p +mux-c-close-fwd+ +mux-c-open-fwd+)
                       request-id
                       type
                       (cons "listen" (or listen-host ""))
                       (or listen-port 0)
                       (cons "connect" (or connect-host ""))
                       (or connect-port 0)))

#-win32
(defun mux-send-forwards (fd forwards cancel-p)
  "Send FORWARDS, a list of plists, and fail on the first refusal."
  (dolist (forward forwards)
    (let* ((request-id 2)
           (type (getf forward :type))
           (listen-host (or (getf forward :listen-host) ""))
           (listen-port (or (getf forward :listen-port) 0))
           (connect-host (or (getf forward :connect-host) ""))
           (connect-port (or (getf forward :connect-port) 0)))
      (mux-write-packet
       fd (mux-open-forward-payload request-id cancel-p type listen-host
                                    listen-port connect-host connect-port))
      (multiple-value-bind (reply reader) (mux-read-reply fd request-id)
        (cond
          ((eql reply +mux-s-ok+) nil)
          ((eql reply +mux-s-remote-port+)
           (let ((port (cl-pnet-ssh:ssh-read-u32 reader)))
             (unless (getf *options* :quiet)
               (format *error-output*
                       "Allocated port ~D for remote forward to ~A:~A~%"
                       port connect-host connect-port))))
          (t
           (error "the control master refused forward ~A:~A: ~A"
                  listen-host listen-port
                  (cl-pnet-ssh:ssh-read-text reader))))))))

#-win32
(defun mux-client-session (fd request &key master-pid)
  "Run REQUEST through the master on FD; return its exit status.

The three standard descriptors are passed after the request.  While the
session runs this process only waits, so the master can write the output
straight to the terminal without a relay here."
  (let ((request-id 1)
        (raw nil))
    (when (and (mux-request-want-tty request) (stdin-terminal-p))
      (setf raw t)
      (terminal-enter-raw))
    (unwind-protect
         (progn
           (mux-write-packet fd (mux-new-session-payload request-id request))
           (dolist (descriptor (list 0 1 2))
             (unless (cl-pnet-sockets:send-fd fd descriptor)
               (error "could not pass the session descriptors to the master")))
           (multiple-value-bind (type reader) (mux-read-reply fd request-id)
             (case type
               (#.+mux-s-session-opened+
                (let ((session-id (cl-pnet-ssh:ssh-read-u32 reader)))
                  (when (and raw master-pid)
                    (mux-client-watch-winch master-pid))
                  (mux-client-wait-exit fd session-id)))
               (#.+mux-s-permission-denied+
                (error "the control master refused the session: ~A"
                       (cl-pnet-ssh:ssh-read-text reader)))
               (#.+mux-s-failure+
                (error "the control master failed: ~A"
                       (cl-pnet-ssh:ssh-read-text reader)))
               (t
                (error "unexpected reply from the control master: 0x~8,'0X"
                       type)))))
      (when raw (restore-terminal)))))

#-win32
(defun mux-client-wait-exit (fd session-id)
  "Read messages until SESSION-ID exits; return its status."
  (loop
    (let ((payload
            (handler-case (mux-read-packet fd)
              (error (condition)
                                (return-from mux-client-wait-exit 255)))))
      (let ((type (mux-u32 payload 0))
            (id (mux-u32 payload 4)))
                (cond
          ((and (eql type +mux-s-exit-message+) (= id session-id))
           (return-from mux-client-wait-exit
             (if (>= (length payload) 12) (mux-u32 payload 8) 255)))
          ((and (eql type +mux-s-tty-alloc-fail+) (= id session-id))
           (return 255))
          (t nil))))))

#-win32
(defun mux-client-stdio-forward (fd host port)
  "Ask the master to connect FD's stdin and stdout to HOST:PORT.

The master opens the channel, so this process only waits for the session to
finish and reports its status, exactly as it does for a multiplexed session."
  (let ((request-id 1))
    (mux-write-packet
     fd (mux-request-payload +mux-c-new-stdio-fwd+ request-id
                              (cons "reserved" "")
                              (cons "host" host)
                              (or port 0)))
    (dolist (descriptor (list 0 1))
      (unless (cl-pnet-sockets:send-fd fd descriptor)
        (error "could not pass the stdio descriptors to the master")))
    (multiple-value-bind (type reader) (mux-read-reply fd request-id)
      (case type
        (#.+mux-s-session-opened+
         (mux-client-wait-exit fd (cl-pnet-ssh:ssh-read-u32 reader)))
        (#.+mux-s-permission-denied+
         (error "the control master refused stdio forwarding: ~A"
                (cl-pnet-ssh:ssh-read-text reader)))
        (#.+mux-s-failure+
         (error "the control master failed stdio forwarding: ~A"
                (cl-pnet-ssh:ssh-read-text reader)))
        (t
         (error "unexpected reply from the control master: 0x~8,'0X"
                type))))))

#-win32
(defun mux-client-watch-winch (master-pid)
  "Ask the master to resize when the local terminal does.

OpenSSH relays SIGWINCH by signal; the master owns the channel, so it is
the process that may send window-change.  The master's pid is discovered
through the alive check before the session starts."
  #+(and sbcl (not win32))
  (ignore-errors
   (sb-sys:enable-interrupt
    sb-unix:sigwinch
    (lambda (signal code context)
      (declare (ignore signal code context))
      (when (and master-pid (plusp master-pid))
        (ignore-errors
         (sb-unix:unix-kill master-pid sb-unix:sigwinch))))))
  #-(and sbcl (not win32))
  (declare (ignore master-pid)))

;;; ---- The master's control connections ----

(defstruct (mux-connection (:constructor %make-mux-connection))
  fd
  (input (make-array 0 :element-type '(unsigned-byte 8)
                       :adjustable t :fill-pointer 0))
  (frame-length nil)
  (output (make-array 0 :element-type '(unsigned-byte 8)
                        :adjustable t :fill-pointer 0))
  read-watcher
  write-watcher
  (closed nil)
  ;; Descriptors arrive one sendmsg behind the request.  WANTED counts the
  ;; ones still expected and CONTINUATION consumes them together.
  (fds-wanted 0)
  (fds-received nil)
  (fds-continuation nil)
  (hello nil)
  ;; OpenSSH's master allows one session per control connection.
  session
  on-message
  on-close)

(defun mux-connection-open (fd master)
  "Wrap FD in a MUX-CONNECTION whose messages MASTER handles."
  (let ((connection
          (%make-mux-connection
           :fd fd
           :on-message (lambda (connection type reader payload)
                         (mux-master-message master connection
                                             type reader payload))
           :on-close (lambda (connection)
                       (mux-master-forget master connection)))))
    (setf (mux-connection-read-watcher connection)
          (cl-pnet:fd-watch
           fd :on-readable
           (lambda (watcher)
             (declare (ignore watcher))
             (mux-connection-readable connection))))
    (mux-connection-send connection
                         (mux-hello-payload '(("info" . "0"))))
    connection))

(defun mux-connection-closed-p (connection)
  (mux-connection-closed connection))

(defun mux-connection-stop (connection)
  (unless (mux-connection-closed-p connection)
    (setf (mux-connection-closed connection) t)
    (when (mux-connection-read-watcher connection)
      (ignore-errors
       (cl-pnet:fd-unwatch (mux-connection-read-watcher connection)))
      (setf (mux-connection-read-watcher connection) nil))
    (when (mux-connection-write-watcher connection)
      (ignore-errors
       (cl-pnet:fd-unwatch (mux-connection-write-watcher connection)))
      (setf (mux-connection-write-watcher connection) nil))
    (dolist (fd (mux-connection-fds-received connection))
      (mux-close fd))
    (setf (mux-connection-fds-received connection) nil
          (mux-connection-fds-wanted connection) 0)
    (mux-close (mux-connection-fd connection))
    (when (mux-connection-on-close connection)
      (funcall (mux-connection-on-close connection) connection))))

(defun mux-connection-send (connection payload)
  "Queue PAYLOAD for the control client and try to write it now."
  (unless (mux-connection-closed-p connection)
    (let ((frame (mux-frame payload))
          (output (mux-connection-output connection)))
      (loop for octet across frame
            do (vector-push-extend octet output)))
    (mux-connection-flush connection)))

(defun mux-connection-flush (connection)
  (unless (mux-connection-closed-p connection)
    (let ((output (mux-connection-output connection)))
      (loop while (plusp (fill-pointer output))
            do (multiple-value-bind (count error)
                   (cl-pnet-sockets:write-octets
                    (mux-connection-fd connection) output)
                 (cond
                   ((plusp count)
                    (replace output output :start2 count)
                    (decf (fill-pointer output) count))
                   ((and (minusp count) (eql error 11))
                    (mux-connection-watch-writable connection)
                    (return))
                   ((and (minusp count) (eql error 4)))
                   (t
                    (mux-connection-stop connection)
                    (return)))))
      (when (and (not (mux-connection-closed-p connection))
                 (zerop (fill-pointer output))
                 (mux-connection-write-watcher connection))
        (ignore-errors
         (cl-pnet:fd-unwatch (mux-connection-write-watcher connection)))
        (setf (mux-connection-write-watcher connection) nil)))))

(defun mux-connection-watch-writable (connection)
  (unless (mux-connection-write-watcher connection)
    (setf (mux-connection-write-watcher connection)
          (cl-pnet:fd-watch
           (mux-connection-fd connection)
           :on-writable
           (lambda (watcher)
             (declare (ignore watcher))
             (mux-connection-flush connection))))))

(defun mux-connection-append (connection octets count)
  (let ((input (mux-connection-input connection)))
    (loop for i below count
          do (vector-push-extend (aref octets i) input))))

(defun mux-connection-process-frame (connection)
  "Dispatch one complete frame, then reset the buffer.

Reads never overshoot a frame: NEW_SESSION is followed by the client's three
descriptors as ancillary data, and a bulk read would swallow the dummy byte
each one rides on."
  (let* ((input (mux-connection-input connection))
         (length (mux-connection-frame-length connection))
         (payload (subseq input 4 (+ 4 length))))
    (setf (fill-pointer input) 0
          (mux-connection-frame-length connection) nil)
    (funcall (mux-connection-on-message connection) connection
             (mux-u32 payload 0)
             (cl-pnet-ssh:ssh-make-reader payload 4)
             payload)))

(defun mux-connection-read-frame (connection)
  (unless (mux-connection-closed-p connection)
    (let ((input (mux-connection-input connection)))
      (when (and (null (mux-connection-frame-length connection))
                 (>= (fill-pointer input) 4))
        (let ((length (mux-u32 input 0)))
          (when (> length +mux-max-frame+)
            (mux-connection-stop connection)
            (return-from mux-connection-read-frame nil))
          (setf (mux-connection-frame-length connection) length)))
      (when (and (mux-connection-frame-length connection)
                 (>= (fill-pointer input)
                     (+ 4 (mux-connection-frame-length connection))))
        (mux-connection-process-frame connection))
      (when (and (not (mux-connection-closed-p connection))
                 (< (fill-pointer input)
                    (if (mux-connection-frame-length connection)
                        (+ 4 (mux-connection-frame-length connection))
                        4)))
        (multiple-value-bind (octets count error)
            (cl-pnet-sockets:read-octets
             (mux-connection-fd connection)
             (let ((length (mux-connection-frame-length connection)))
               (if length
                   (- (+ 4 length) (fill-pointer input))
                   4)))
          (cond
            ((plusp count)
             (mux-connection-append connection octets count)
             (mux-connection-read-frame connection))
            ((and (minusp count) (eql error 11)) nil)
            ((and (minusp count) (eql error 4)) nil)
            (t (mux-connection-stop connection))))))))

(defun mux-connection-take-fds (connection)
  (loop while (plusp (mux-connection-fds-wanted connection))
        do (multiple-value-bind (fd error)
               (cl-pnet-sockets:receive-fd
                (mux-connection-fd connection))
             (cond
               (fd
                (push fd (mux-connection-fds-received connection))
                (decf (mux-connection-fds-wanted connection)))
               ((eql error 11) (return))
               (t
                (mux-connection-stop connection)
                (return)))))
  (when (and (not (mux-connection-closed-p connection))
             (zerop (mux-connection-fds-wanted connection))
             (mux-connection-fds-continuation connection))
    (let ((fds (nreverse (mux-connection-fds-received connection)))
          (continuation (mux-connection-fds-continuation connection)))
      (setf (mux-connection-fds-received connection) nil
            (mux-connection-fds-continuation connection) nil)
      (funcall continuation fds))))

(defun mux-connection-readable (connection)
  (unless (mux-connection-closed-p connection)
    (if (plusp (mux-connection-fds-wanted connection))
        (mux-connection-take-fds connection)
        (mux-connection-read-frame connection))))

(defun mux-connection-expect-fds (connection count continuation)
  (setf (mux-connection-fds-wanted connection) count
        (mux-connection-fds-received connection) nil
        (mux-connection-fds-continuation connection) continuation)
  (mux-connection-take-fds connection))

;;; ---- The master ----

(defstruct (mux-master (:constructor %make-mux-master))
  path
  fd
  watcher
  mode
  persist
  (connections nil)
  (sessions nil)
  (next-session-id 1)
  ;; A ControlPersist timeout only starts once this master has carried a
  ;; client; a master that has never been used is not idle.
  (seen-client nil)
  (idle-timer nil)
  (stopping nil)
  (stopped nil)
  (winch nil))

(defvar *mux-master* nil
  "The control master this process runs, or NIL.")
(defvar *mux-daemon* nil
  "True in the background process that only keeps a master alive.")
;; Set by MAIN when this invocation should listen for later clients once it
;; authenticates.  PERSIST is :NO, :YES or a number, as ControlPersist says.
(defvar *mux-create-master* nil)
(defvar *mux-create-path* nil)
(defvar *mux-create-mode* :yes)
(defvar *mux-create-persist* :no)

(defun mux-master-note-session (master)
  "A client attached: the idle timeout no longer applies."
  (when (mux-master-idle-timer master)
    (ignore-errors (cl-pnet:timer-stop (mux-master-idle-timer master)))
    (setf (mux-master-idle-timer master) nil)))

(defun mux-master-register (master connection)
  (setf (mux-master-seen-client master) t)
  (push connection (mux-master-connections master)))

(defun mux-master-forget (master connection)
  (setf (mux-master-connections master)
        (delete connection (mux-master-connections master)))
  (mux-master-schedule-idle master))

(defun mux-master-schedule-idle (master)
  "Stop the master when it has been idle for ControlPersist seconds.

ControlPersist=yes (or a zero timeout) keeps it forever after the first
session.  With no persistence the owning client's own FINISH stops it once
its session ends, so this timer is only for a configured timeout."
  (when (and (not (mux-master-stopping master))
             (mux-master-seen-client master)
             (null (mux-master-connections master)))
    (let ((persist (mux-master-persist master)))
      (cond
        ((or (null persist) (eq persist :no)) nil)
        ((eq persist :yes) nil)
        ((and (numberp persist) (zerop persist)) nil)
        ((numberp persist)
         (when (mux-master-idle-timer master)
           (ignore-errors
            (cl-pnet:timer-stop (mux-master-idle-timer master))))
         (setf (mux-master-idle-timer master)
               (cl-pnet:timer-start
                persist 0
                (lambda ()
                  (setf (mux-master-idle-timer master) nil)
                  (when (and (null (mux-master-connections master))
                             (null (mux-master-sessions master)))
                    (mux-master-shutdown master))))))))))

(defun mux-master-shutdown (master)
  (unless (mux-master-stopping master)
    (setf (mux-master-stopping master) t)
    (mux-master-stop master)
    (finish 0)))

(defun mux-master-stop (master)
  (unless (mux-master-stopped master)
    (setf (mux-master-stopped master) t)
    (when (mux-master-idle-timer master)
      (ignore-errors (cl-pnet:timer-stop (mux-master-idle-timer master)))
      (setf (mux-master-idle-timer master) nil))
    (when (mux-master-winch master)
      (ignore-errors (cl-pnet:signal-stop (mux-master-winch master)))
      (setf (mux-master-winch master) nil))
    (when (mux-master-watcher master)
      (ignore-errors (cl-pnet:fd-unwatch (mux-master-watcher master)))
      (setf (mux-master-watcher master) nil))
    (when (mux-master-fd master)
      (mux-close (mux-master-fd master))
      (setf (mux-master-fd master) nil))
    (ignore-errors (delete-file (mux-master-path master)))
    (dolist (connection (copy-list (mux-master-connections master)))
      (mux-connection-stop connection))
    (setf (mux-master-connections master) nil)
    (when (eq master *mux-master*)
      (setf *mux-master* nil))))

(defun mux-start-master (path mode client &key persist)
  "Listen on PATH for sessions multiplexed over CLIENT.

MODE is the effective ControlMaster keyword; PERSIST is ControlPersist.
The listener is bound beside PATH and hard-linked into place, as mux.c does,
so another process never sees a bound but unready socket."
  (let* ((temporary (mux-temporary-control-path path))
         (fd (cl-pnet-sockets:listen-unix temporary :backlog 64 :unlink nil
                                                     :mask #o177)))
    (when (minusp (mux-c-link temporary path))
      (let ((errno (cl-pnet-sockets:c-errno)))
        (mux-close fd)
        (ignore-errors (delete-file temporary))
        (if (eql errno 17)           ; EEXIST: someone else got there first
            (progn
              (format *error-output*
                      "burs: ControlSocket ~A already exists, disabling multiplexing~%"
                      path)
              (return-from mux-start-master nil))
            (error "cannot move the control socket to ~A: ~A"
                   path (cl-pnet-sockets:c-strerror errno)))))
    (ignore-errors (delete-file temporary))
    (let ((master (%make-mux-master :path path :fd fd :mode mode
                                    :persist persist)))
      (setf *mux-master* master)
      (setf (mux-master-watcher master)
            (cl-pnet:fd-watch
             fd :on-readable
             (lambda (watcher)
               (declare (ignore watcher))
               (mux-master-accept master))))
      (mux-master-watch-winch master)
      (mux-master-schedule-idle master)
      (log-line "control master listening on ~A" path)
      master)))

(defun mux-master-watch-winch (master)
  #-win32
  (setf (mux-master-winch master)
        (ignore-errors
         (cl-pnet:signal-start
          #+sbcl sb-unix:sigwinch
          #-sbcl 28
          (lambda ()
            (dolist (session (copy-list (mux-master-sessions master)))
              (when (and (mux-session-want-tty session)
                         (not (mux-session-closed session)))
                (ignore-errors
                 (mux-session-window-change session)))))))))

(defun mux-master-accept (master)
  (loop
    (let ((fd (cl-pnet-sockets:accept-socket (mux-master-fd master))))
      (unless fd (return))
      (handler-case
          (progn
            (cl-pnet-sockets:set-nonblocking fd)
            (let ((connection (mux-connection-open fd master)))
              (mux-master-register master connection)))
        (error ()
          (mux-close fd))))))

(defun mux-master-host-name ()
  (or (and *client* (cl-pnet-ssh:ssh-client-host *client*))
      "the master"))

(defun mux-master-asks-p (master)
  "Whether a new session must be confirmed on the terminal."
  (member (mux-master-mode master) '(:ask :autoask)))

(defun mux-permission-p (master prompt)
  (if (not (mux-master-asks-p master))
      t
      (let ((tty (probe-file "/dev/tty")))
        ;; A detached master has no terminal to ask on, and ssh-askpass is
        ;; not part of this client, so refusing is the fail-closed answer.
        (and tty
             (handler-case
                 (let ((saved (and (stdin-terminal-p)
                                   (mux-tty-stty '("-g")))))
                   (unwind-protect
                        (progn
                          ;; An attached client left the terminal raw; line
                          ;; editing and echo have to come back for the
                          ;; answer.  With stdin redirected there was no
                          ;; attached client, so the tty is already usable.
                          (when saved
                            (mux-tty-stty '("icanon" "echo" "icrnl")))
                          (with-open-file (stream tty :direction :io
                                                       :if-does-not-exist nil)
                            (when stream
                              (format stream "~A(yes/no)? " prompt)
                              (finish-output stream)
                              (let* ((answer (read-line stream nil nil))
                                     (answer (and answer
                                                  (string-trim '(#\Space #\Tab)
                                                               answer))))
                                ;; ask_permission in readpass.c accepts an
                                ;; empty answer or the word "yes", and treats
                                ;; EOF as a refusal.
                                (and answer
                                     (or (zerop (length answer))
                                         (string-equal answer "yes")))))))
                     (when (and saved (plusp (length saved)))
                       (mux-tty-stty (list saved)))))
               (error () nil))))))

(defun mux-tty-stty (arguments)
  "Run STTY with ARGUMENTS on this process's terminal; trimmed output or NIL.

The child must inherit fd 0: run-program hangs when the same terminal is
opened again just to be handed over as INPUT, while INHERIT works."
  (handler-case
      (string-trim '(#\Newline #\Return)
                   (call-with-deferrable-signals-unblocked
                    (lambda ()
                      (uiop:run-program
                       (cons "stty" arguments)
                       :input :interactive :output :string :error-output nil))))
    (error () nil)))

(defun mux-local-host-name ()
  "This machine's hostname, as connection_info_message reports it."
  (or (ignore-errors (uiop:hostname)) "unknown"))

(defun mux-format-timeframe (seconds)
  "SECONDS as OpenSSH's fmt_timeframe spells a duration."
  (let* ((seconds (max 0 (floor (or seconds 0))))
         (sec (mod seconds 60))
         (minutes (floor seconds 60))
         (min (mod minutes 60))
         (hours (floor minutes 60))
         (hrs (mod hours 24))
         (days (floor hours 24))
         (weeks (floor days 7)))
    (cond
      ((plusp weeks)
       (format nil "~2,'0dw~1,'0dd~2,'0dh" weeks (mod days 7) hrs))
      ((plusp days)
       (format nil "~1,'0dd~2,'0dh~2,'0dm" days hrs min))
      (t
       (format nil "~2,'0d:~2,'0d:~2,'0d" hrs min sec)))))

(defun mux-format-scaled (bytes)
  "BYTES as OpenSSH's fmt_scaled spells it, e.g. 3.3K."
  (let* ((number (or bytes 0))
         (abval (abs number))
         (scales (vector 1 1024 1048576 1073741824
                         1099511627776 1125899906842624))
         (chars "BKMGTPE")
         (index 0)
         (fract 0))
    (loop for i below (length scales)
          when (< (floor abval 1024) (aref scales i))
            do (setf index i
                     fract (if (zerop i) 0 (mod abval (aref scales i)))
                     number (floor number (aref scales i)))
               (when (plusp i)
                 (setf fract (floor fract (aref scales (1- i)))))
               (return))
    (setf fract (floor (+ (* 10 fract) 512) 1024))
    (when (>= fract 10)
      (setf number (if (minusp number) (1- number) (1+ number))
            fract 0))
    (cond
      ((zerop number) "0B")
      ((or (zerop index) (>= number 100) (<= number -100))
       (when (>= fract 5)
         (setf number (if (minusp number) (1- number) (1+ number))))
       (format nil "~D~C" number (char chars index)))
      (t
       (format nil "~D.~D~C" number fract (char chars index))))))

(defun mux-dedupe-names (in out)
  "IN and OUT as one name, or \"IN in, OUT out\" when they differ."
  (let ((in (or in "<implicit>"))
        (out (or out "<implicit>")))
    (if (string= in out)
        in
        (format nil "~A in, ~A out" in out))))

(defun mux-implicit-mac-p (cipher)
  "Whether CIPHER carries its own authentication, leaving no separate MAC."
  (and cipher
       (or (string= cipher "chacha20-poly1305@openssh.com")
           (search "-gcm@" cipher))))

(defun mux-write-crlf (stream)
  "Write the CRLF that OpenSSH's mux info text uses between lines."
  (write-char #\Return stream)
  (write-char #\Newline stream))

(defun mux-connection-info-message (master)
  "The text -O conninfo returns, matching OpenSSH's connection_info_message.

The parts a transport cannot report are left out rather than guessed."
  (declare (ignore master))
  (let* ((info (and *client*
                    (cl-pnet-ssh::ssh-client-connection-info *client*)))
         (endpoints (getf info :endpoints))
         (traffic (getf info :traffic))
         (cipher-in (getf info :cipher-in))
         (cipher-out (getf info :cipher-out))
         (limit (getf info :rekey-limit))
         (interval (getf info :rekey-interval)))
    (with-output-to-string (out)
      (format out "Connection information for ~A pid ~D"
              (mux-local-host-name) (mux-process-id))
      (mux-write-crlf out)
      (format out "  versions ~A -> ~A"
              (or (getf info :client-version) "unknown")
              (or (getf info :server-version) "unknown"))
      (mux-write-crlf out)
      (when (and (first endpoints) (second endpoints)
                 (third endpoints) (fourth endpoints))
        (format out "  tcp ~A:~D -> ~A:~D"
                (first endpoints) (second endpoints)
                (third endpoints) (fourth endpoints))
        (mux-write-crlf out))
      (format out "  duration ~A"
              (mux-format-timeframe
               (if (getf info :connected-at)
                   (- (get-universal-time) (getf info :connected-at))
                   0)))
      (mux-write-crlf out)
      (format out "  kexalgorithm ~A" (or (getf info :kex) "unknown"))
      (mux-write-crlf out)
      (format out "  hostkeyalgorithm ~A"
              (or (getf info :host-key) "unknown"))
      (mux-write-crlf out)
      (format out "  cipher ~A" (mux-dedupe-names cipher-in cipher-out))
      (mux-write-crlf out)
      (format out "  mac ~A"
              (mux-dedupe-names
               (unless (mux-implicit-mac-p cipher-in) (getf info :mac-in))
               (unless (mux-implicit-mac-p cipher-out) (getf info :mac-out))))
      (mux-write-crlf out)
      (format out "  compression ~A"
              ;; A transport that cannot report compression still prints the
              ;; default rather than OpenSSH's <implicit>, which means AEAD MAC.
              (mux-dedupe-names (or (getf info :compression-in) "none")
                                (or (getf info :compression-out) "none")))
      (mux-write-crlf out)
      (format out "  rekey ~A ~A"
              (if (and limit (plusp limit))
                  (format nil "limit blocks ~D" limit)
                  "limit none")
              (if (and interval (plusp interval))
                  (format nil "interval ~A" (mux-format-timeframe interval))
                  "interval none"))
      (mux-write-crlf out)
      (when traffic
        ;; fmt_scaled already carries its unit; format_traffic_stats appends
        ;; the "B" that turns "3.3K" into "3.3KB".
        (format out "  traffic ~D pkts ~D blks ~AB in, ~D pkts ~D blks ~AB out"
                (getf traffic :received-packets)
                (getf traffic :received-blocks)
                (mux-format-scaled (getf traffic :received-bytes))
                (getf traffic :sent-packets)
                (getf traffic :sent-blocks)
                (mux-format-scaled (getf traffic :sent-bytes)))
        (mux-write-crlf out)))))

(defun mux-channel-open-message (master)
  "The text -O channels returns: one line per open multiplexed session."
  (with-output-to-string (out)
    (format out "The following connections are open:")
    (mux-write-crlf out)
    (dolist (session (reverse (mux-master-sessions master)))
      (unless (mux-session-closed session)
        (format out "  #~D ~A (~A)"
                (mux-session-sid session)
                (mux-session-remote-name session)
                (if (mux-session-opened session) "open" "opening"))
        (mux-write-crlf out)))))

(defun mux-master-ext-info (master connection reader)
  "Answer a MUX_C_EXT_INFO request for the connection or channel list."
  (let ((request-id (cl-pnet-ssh:ssh-read-u32 reader))
        (name (cl-pnet-ssh:ssh-read-text reader)))
    (multiple-value-bind (status message)
        (cond
          ((string= name "connection")
           (values 1 (mux-connection-info-message master)))
          ((string= name "channels")
           (values 1 (mux-channel-open-message master)))
          (t
           (values 0 "info request type not supported")))
      (let ((writer (cl-pnet-ssh:ssh-writer)))
        (cl-pnet-ssh::ssh-write-u32 writer +mux-s-ext-info+)
        (cl-pnet-ssh::ssh-write-u32 writer request-id)
        (cl-pnet-ssh::ssh-write-u32 writer status)
        (cl-pnet-ssh:ssh-write-text writer message)
        (mux-connection-send connection
                             (cl-pnet-ssh:ssh-writer-output writer))))))

(defun mux-master-message (master connection type reader payload)
  "Handle one frame from a control client; READER starts after TYPE."
  (declare (ignore payload))
  (cond
    ((eql type +mux-msg-hello+)
     (let ((version (cl-pnet-ssh:ssh-read-u32 reader)))
       (if (= version +mux-version+)
           (setf (mux-connection-hello connection) t)
           (progn
             (log-line "control client asked for mux version ~D" version)
             (mux-connection-stop connection)))))
    ((not (mux-connection-hello connection))
     (log-line "control client sent a message before its hello")
     (mux-connection-stop connection))
    ((eql type +mux-c-alive-check+)
     (let ((request-id (cl-pnet-ssh:ssh-read-u32 reader))
           (writer (cl-pnet-ssh:ssh-writer)))
       (cl-pnet-ssh::ssh-write-u32 writer +mux-s-alive+)
       (cl-pnet-ssh::ssh-write-u32 writer request-id)
       (cl-pnet-ssh::ssh-write-u32 writer (mux-process-id))
       (mux-connection-send connection (cl-pnet-ssh:ssh-writer-output writer))))
    ((eql type +mux-c-new-session+)
     (mux-master-new-session master connection reader))
    ((eql type +mux-c-new-stdio-fwd+)
     (mux-master-new-stdio-forward master connection reader))
    ((eql type +mux-c-terminate+)
     (let ((request-id (cl-pnet-ssh:ssh-read-u32 reader)))
       (if (mux-permission-p master "Terminate shared connection? ")
           (progn
             (mux-connection-send connection (mux-ok-payload request-id))
             (mux-master-shutdown master))
           (mux-connection-send
            connection
            (mux-error-payload +mux-s-permission-denied+ request-id
                               "Permission denied")))))
    ((eql type +mux-c-stop-listening+)
     (let ((request-id (cl-pnet-ssh:ssh-read-u32 reader)))
       (if (mux-permission-p
            master "Disable further multiplexing on shared connection? ")
           (progn
             (mux-connection-send connection (mux-ok-payload request-id))
             (mux-master-stop-listening master))
           (mux-connection-send
            connection
            (mux-error-payload +mux-s-permission-denied+ request-id
                               "Permission denied")))))
    ((eql type +mux-c-open-fwd+)
     (mux-master-forward master connection reader nil))
    ((eql type +mux-c-close-fwd+)
     (mux-master-forward master connection reader t))
    ((eql type +mux-c-ext-info+)
     (mux-master-ext-info master connection reader))
    (t
     (mux-connection-send
      connection
      (mux-error-payload +mux-s-failure+ 0
                         (format nil "unsupported mux request 0x~8,'0X" type))))))

(defun mux-master-stop-listening (master)
  (when (mux-master-watcher master)
    (ignore-errors (cl-pnet:fd-unwatch (mux-master-watcher master)))
    (setf (mux-master-watcher master) nil))
  (when (mux-master-fd master)
    (mux-close (mux-master-fd master))
    (setf (mux-master-fd master) nil))
  (ignore-errors (delete-file (mux-master-path master))))

;;; ---- A multiplexed session ----

(defstruct (mux-session (:constructor %make-mux-session))
  master
  connection
  request-id
  sid
  channel
  stdin-fd
  stdout-fd
  stderr-fd
  stdin-watcher
  stdout-watcher
  stderr-watcher
  (stdout-buffer (make-array 0 :element-type '(unsigned-byte 8)
                               :adjustable t :fill-pointer 0))
  (stderr-buffer (make-array 0 :element-type '(unsigned-byte 8)
                               :adjustable t :fill-pointer 0))
  (want-tty nil)
  ;; The command, subsystem or "session" shown by -O channels.
  (remote-name "session")
  (exit-status 255)
  (opened nil)
  (closed nil))

(defun mux-master-new-session (master connection reader)
  (let ((request-id (cl-pnet-ssh:ssh-read-u32 reader)))
    (cl-pnet-ssh:ssh-read-string reader) ; reserved
    (let ((want-tty (plusp (cl-pnet-ssh:ssh-read-u32 reader)))
          (want-x11 (cl-pnet-ssh:ssh-read-u32 reader))
          (want-agent (cl-pnet-ssh:ssh-read-u32 reader))
          (want-subsystem (plusp (cl-pnet-ssh:ssh-read-u32 reader)))
          (escape-char (cl-pnet-ssh:ssh-read-u32 reader))
          (term (cl-pnet-ssh:ssh-read-text reader))
          (command (cl-pnet-ssh:ssh-read-text reader))
          (environment '()))
      (declare (ignore want-x11 want-agent escape-char))
      (loop while (plusp (cl-pnet-ssh:ssh-reader-remaining reader))
            do (push (cl-pnet-ssh:ssh-read-text reader) environment))
      (mux-connection-expect-fds
       connection 3
       (lambda (fds)
         (destructuring-bind (stdin stdout stderr) fds
           (cond
             ((mux-connection-session connection)
              ;; The descriptors were already received, as OpenSSH does
              ;; before it discovers the connection is busy.
              (dolist (fd fds) (mux-close fd))
              (mux-connection-send
               connection
               (mux-error-payload +mux-s-failure+ request-id
                                  "Multiple sessions not supported")))
             ((not (mux-permission-p
                    master
                    (format nil "Allow shared connection to ~A?"
                            (mux-master-host-name))))
              (dolist (fd fds) (mux-close fd))
              (mux-connection-send
               connection
               (mux-error-payload +mux-s-permission-denied+
                                  request-id "Permission denied")))
             (t
              (mux-open-remote-session
               master connection request-id want-tty want-subsystem
               term command (nreverse environment)
               stdin stdout stderr)))))))))

(defun mux-open-remote-session (master connection request-id want-tty
                                want-subsystem term command environment
                                stdin stdout stderr)
  (mux-master-note-session master)
  (let ((session (%make-mux-session
                  :master master :connection connection
                  :request-id request-id
                  :sid (prog1 (mux-master-next-session-id master)
                         (incf (mux-master-next-session-id master)))
                  :stdin-fd stdin :stdout-fd stdout :stderr-fd stderr
                  :want-tty want-tty
                  :remote-name (if (plusp (length command))
                                   command
                                   "session"))))
    (dolist (fd (list stdin stdout stderr))
      (ignore-errors (cl-pnet-sockets:set-nonblocking fd)))
    (setf (mux-connection-session connection) session)
    (push session (mux-master-sessions master))
    (handler-case
        (let ((channel
                (cl-pnet-ssh::ssh-open-channel
                 *client* "session"
                 :on-open
                 (lambda (channel)
                   (mux-session-send-commands session channel want-tty
                                              want-subsystem term command
                                              environment))
                 :on-data
                 (lambda (channel data kind)
                   (declare (ignore channel))
                   (mux-session-output session kind data))
                 :on-eof
                 (lambda (channel)
                   (declare (ignore channel))
                   nil)
                 :on-exit
                 (lambda (channel status)
                   (declare (ignore channel))
                   (setf (mux-session-exit-status session) status))
                 :on-close
                 (lambda (channel status)
                   (declare (ignore channel))
                   (unless (mux-session-closed session)
                     (when (and (not (mux-session-opened session))
                                status)
                       (setf (mux-session-exit-status session) status))
                     (mux-session-close session)))
                 :on-error
                 (lambda (channel condition)
                   (declare (ignore channel))
                   (unless (mux-session-closed session)
                     (mux-connection-send
                      connection
                      (mux-error-payload +mux-s-failure+ request-id
                                         (format nil "~A" condition)))
                     (mux-session-close session))))))
          (setf (mux-session-channel session) channel)
          (setf (mux-session-stdin-watcher session)
                (cl-pnet:fd-watch
                 stdin :on-readable
                 (lambda (watcher)
                   (declare (ignore watcher))
                   (mux-session-read-stdin session)))))
      (error (condition)
        (mux-connection-send
         connection
         (mux-error-payload +mux-s-failure+ request-id
                            (format nil "~A" condition)))
        (mux-session-close session)))))

(defun mux-session-send-commands (session channel want-tty want-subsystem
                                  term command environment)
  (unless (mux-session-closed session)
    (when want-tty
      (multiple-value-bind (rows columns)
          (mux-fd-size (mux-session-stdin-fd session))
        (send-channel-request
         channel "pty-req" t
         (lambda (writer)
           (cl-pnet-ssh:ssh-write-text writer (or term "xterm"))
           (cl-pnet-ssh::ssh-write-u32 writer columns)
           (cl-pnet-ssh::ssh-write-u32 writer rows)
           (cl-pnet-ssh::ssh-write-u32 writer 0)
           (cl-pnet-ssh::ssh-write-u32 writer 0)
           (cl-pnet-ssh:ssh-write-string
            writer (make-array 0 :element-type '(unsigned-byte 8)))))))
    (dolist (entry environment)
      (let ((equals (position #\= entry)))
        (when (and equals (plusp equals))
          (cl-pnet-ssh:ssh-channel-env channel
                                       (subseq entry 0 equals)
                                       (subseq entry (1+ equals))))))
    (cond
      (want-subsystem
       (send-channel-request
        channel "subsystem" t
        (lambda (writer)
          (cl-pnet-ssh:ssh-write-text writer command))))
      ((plusp (length command))
       (send-channel-request
        channel "exec" t
        (lambda (writer)
          (cl-pnet-ssh:ssh-write-text writer command))))
      (t
       (send-channel-request
        channel "shell" t
        (lambda (writer) (declare (ignore writer))))))
    (setf (mux-session-opened session) t)
    (mux-connection-send
     (mux-session-connection session)
     (mux-request-payload +mux-s-session-opened+
                          (mux-session-request-id session)
                          (mux-session-sid session)))))

(defun mux-session-window-change (session)
  (multiple-value-bind (rows columns)
      (mux-fd-size (mux-session-stdin-fd session))
    (send-channel-request
     (mux-session-channel session) "window-change" nil
     (lambda (writer)
       (cl-pnet-ssh::ssh-write-u32 writer columns)
       (cl-pnet-ssh::ssh-write-u32 writer rows)
       (cl-pnet-ssh::ssh-write-u32 writer 0)
       (cl-pnet-ssh::ssh-write-u32 writer 0)))))

(defun mux-session-read-stdin (session)
  (unless (mux-session-closed session)
    (multiple-value-bind (octets count error)
        (cl-pnet-sockets:read-octets (mux-session-stdin-fd session) 65536)
            (cond
        ((plusp count)
         (ignore-errors
          (cl-pnet-ssh:ssh-channel-write
           (mux-session-channel session) octets)))
        ((zerop count)
         (when (mux-session-stdin-watcher session)
           (ignore-errors
            (cl-pnet:fd-unwatch (mux-session-stdin-watcher session)))
           (setf (mux-session-stdin-watcher session) nil))
         (ignore-errors
          (cl-pnet-ssh:ssh-channel-eof (mux-session-channel session))))
        ((member error '(4 11)) nil)
        (t
         (when (mux-session-stdin-watcher session)
           (ignore-errors
            (cl-pnet:fd-unwatch (mux-session-stdin-watcher session)))
           (setf (mux-session-stdin-watcher session) nil))
         (ignore-errors
          (cl-pnet-ssh:ssh-channel-eof
           (mux-session-channel session))))))))

(defun mux-session-output (session kind data)
  (let ((stderr-p (eq kind :stderr)))
    (let ((buffer (if stderr-p
                      (mux-session-stderr-buffer session)
                      (mux-session-stdout-buffer session)))
          (fd (if stderr-p
                  (mux-session-stderr-fd session)
                  (mux-session-stdout-fd session))))
      (loop for octet across data
            do (vector-push-extend octet buffer))
      (mux-session-flush session fd buffer stderr-p))))

(defun mux-session-flush (session fd buffer stderr-p)
  (loop while (plusp (fill-pointer buffer))
        do (multiple-value-bind (count error)
               (cl-pnet-sockets:write-octets fd buffer)
             (cond
               ((plusp count)
                (replace buffer buffer :start2 count)
                (decf (fill-pointer buffer) count))
               ((and (minusp count) (member error '(4 11)))
                (mux-session-watch-output session fd buffer stderr-p)
                (return))
               (t
                (setf (fill-pointer buffer) 0)
                (return)))))
  (when (zerop (fill-pointer buffer))
    (mux-session-unwatch-output session stderr-p)))

(defun mux-session-watch-output (session fd buffer stderr-p)
  (unless (if stderr-p
              (mux-session-stderr-watcher session)
              (mux-session-stdout-watcher session))
    (let ((watcher
            (cl-pnet:fd-watch
             fd :on-writable
             (lambda (watcher)
               (declare (ignore watcher))
               (mux-session-flush session fd buffer stderr-p)))))
      (if stderr-p
          (setf (mux-session-stderr-watcher session) watcher)
          (setf (mux-session-stdout-watcher session) watcher)))))

(defun mux-session-unwatch-output (session stderr-p)
  (let ((watcher (if stderr-p
                     (mux-session-stderr-watcher session)
                     (mux-session-stdout-watcher session))))
    (when watcher
      (ignore-errors (cl-pnet:fd-unwatch watcher))
      (if stderr-p
          (setf (mux-session-stderr-watcher session) nil)
          (setf (mux-session-stdout-watcher session) nil)))))

(defun mux-session-close (session)
  (unless (mux-session-closed session)
    (setf (mux-session-closed session) t)
    (when (mux-session-stdin-watcher session)
      (ignore-errors
       (cl-pnet:fd-unwatch (mux-session-stdin-watcher session)))
      (setf (mux-session-stdin-watcher session) nil))
    (mux-session-unwatch-output session nil)
    (mux-session-unwatch-output session t)
    (when (mux-session-opened session)
      (let ((connection (mux-session-connection session)))
        (unless (mux-connection-closed-p connection)
          (mux-connection-send
           connection
           (mux-request-payload +mux-s-exit-message+
                                (mux-session-sid session)
                                (mux-session-exit-status session))))))
    ;; Flush what the peer already wrote before the descriptors go away.
    (dolist (pair (list (cons (mux-session-stdout-fd session)
                              (mux-session-stdout-buffer session))
                        (cons (mux-session-stderr-fd session)
                              (mux-session-stderr-buffer session))))
      (let ((fd (car pair))
            (buffer (cdr pair)))
        (when (and fd buffer (plusp (fill-pointer buffer)))
          (ignore-errors
           (mux-session-flush session fd buffer
                              (eq buffer (mux-session-stderr-buffer session)))))))
    (let ((fds (list (mux-session-stdin-fd session)
                     (mux-session-stdout-fd session)
                     (mux-session-stderr-fd session))))
      (setf (mux-session-stdin-fd session) nil
            (mux-session-stdout-fd session) nil
            (mux-session-stderr-fd session) nil)
      (dolist (fd fds) (mux-close fd)))
    (let ((connection (mux-session-connection session)))
      (when (eq (mux-connection-session connection) session)
        (setf (mux-connection-session connection) nil))
      (setf (mux-master-sessions (mux-session-master session))
            (delete session (mux-master-sessions (mux-session-master session))))
      (mux-connection-stop connection))
    (mux-master-schedule-idle (mux-session-master session))))

(defun mux-fd-size (fd)
  "The (VALUES ROWS COLUMNS) of the terminal behind FD, or 24 by 80."
  #+win32
  (declare (ignore fd))
  #+win32
  (values 24 80)
  #-win32
  (if (or (null fd) (minusp fd))
      (values 24 80)
      (cffi:with-foreign-object (size :unsigned-short 4)
        (if (zerop (cffi:foreign-funcall
                    "ioctl"
                    :int fd
                    :unsigned-long #+linux #x5413 #-linux #x40087468
                    :pointer size
                    :int))
            (let ((rows (cffi:mem-aref size :unsigned-short 0))
                  (columns (cffi:mem-aref size :unsigned-short 1)))
              (if (and (plusp rows) (plusp columns))
                  (values rows columns)
                  (values 24 80)))
            (values 24 80)))))

;;; ---- Forwarding requests over the control socket ----

(defun mux-forward-fields (reader)
  (list :type (cl-pnet-ssh:ssh-read-u32 reader)
        :listen-host (cl-pnet-ssh:ssh-read-text reader)
        :listen-port (cl-pnet-ssh:ssh-read-u32 reader)
        :connect-host (cl-pnet-ssh:ssh-read-text reader)
        :connect-port (cl-pnet-ssh:ssh-read-u32 reader)))

(defun mux-master-forward (master connection reader cancel-p)
  (let* ((request-id (cl-pnet-ssh:ssh-read-u32 reader))
         (fields (mux-forward-fields reader))
         (type (getf fields :type))
         (listen-host (getf fields :listen-host))
         (listen-port (getf fields :listen-port))
         (connect-host (getf fields :connect-host))
         (connect-port (getf fields :connect-port))
         (defer (and (= type +mux-fwd-remote+) (zerop listen-port))))
    (handler-case
        (cond
          (cancel-p
           (mux-cancel-forward type listen-host listen-port)
           (mux-connection-send connection (mux-ok-payload request-id)))
          ((mux-forward-registered-p type listen-host listen-port)
           ;; OpenSSH acknowledges a forward it already holds rather than
           ;; trying to listen on the same port twice.
           (mux-forward-reply connection request-id type listen-port
                              (mux-registered-forward-port
                               type listen-host listen-port)))
          (t
           (when (mux-master-asks-p master)
             (unless (mux-permission-p
                      master
                      (format nil "Open ~A forward ~A:~A on ~A?"
                              (case type
                                (#.+mux-fwd-local+ "local")
                                (#.+mux-fwd-remote+ "remote")
                                (t "dynamic"))
                              listen-host listen-port
                              (mux-master-host-name)))
               (return-from mux-master-forward
                 (mux-connection-send
                  connection
                  (mux-error-payload +mux-s-permission-denied+ request-id
                                     "Permission denied")))))
           (let ((forward
                   (mux-apply-forward
                    type listen-host listen-port connect-host connect-port
                    :on-remote-allocated
                    (and defer
                         (lambda (port)
                           (unless (mux-connection-closed-p connection)
                             (mux-connection-send
                              connection
                              (mux-request-payload
                               +mux-s-remote-port+ request-id port)))))
                    :on-remote-failed
                    (and defer
                         (lambda ()
                           (unless (mux-connection-closed-p connection)
                             (mux-connection-send
                              connection
                              (mux-error-payload
                               +mux-s-failure+ request-id
                               "remote forward refused"))))))))
             (unless defer
               (mux-forward-reply connection request-id type listen-port
                                  (and forward (forward-bind-port forward)))))))
      (error (condition)
        (mux-connection-send
         connection
         (mux-error-payload +mux-s-failure+ request-id
                            (format nil "~A" condition)))))))

(defun mux-forward-reply (connection request-id type listen-port port)
  "Acknowledge a forward, reporting PORT after a request for port 0."
  (if (and (= type +mux-fwd-remote+) (zerop listen-port)
           (integerp port) (plusp port))
      (mux-connection-send
       connection
       (mux-request-payload +mux-s-remote-port+ request-id port))
      (mux-connection-send connection (mux-ok-payload request-id))))

(defun mux-forward-registered-p (type listen-host listen-port)
  "Whether TYPE's LISTEN-HOST:LISTEN-PORT is already forwarded."
  (case type
    (#.+mux-fwd-local+
     (some (lambda (forward)
             (mux-forward-bind-matches-p
              (forward-bind-address forward) (forward-bind-port forward)
              (forward-bind-path forward) listen-host listen-port))
           *forwards*))
    (#.+mux-fwd-dynamic+
     (some (lambda (forward)
             (mux-forward-bind-matches-p
              (dynamic-bind-address forward)
              (dynamic-forward-bind-port forward) nil
              listen-host listen-port))
           *dynamic-forwards*))
    (#.+mux-fwd-remote+
     (some (lambda (forward)
             (mux-forward-bind-matches-p
              (forward-bind-address forward) (forward-bind-port forward)
              (forward-bind-path forward) listen-host listen-port))
           *remote-forwards*))
    (t nil)))

(defun mux-registered-forward-port (type listen-host listen-port)
  "The port of the forward TYPE holds for LISTEN-HOST:LISTEN-PORT, or 0."
  (let ((forward
          (case type
            (#.+mux-fwd-local+
             (find-if (lambda (candidate)
                        (mux-forward-bind-matches-p
                         (forward-bind-address candidate)
                         (forward-bind-port candidate)
                         (forward-bind-path candidate)
                         listen-host listen-port))
                      *forwards*))
            (#.+mux-fwd-dynamic+
             (find-if (lambda (candidate)
                        (mux-forward-bind-matches-p
                         (dynamic-bind-address candidate)
                         (dynamic-forward-bind-port candidate) nil
                         listen-host listen-port))
                      *dynamic-forwards*))
            (#.+mux-fwd-remote+
             (find-if (lambda (candidate)
                        (mux-forward-bind-matches-p
                         (forward-bind-address candidate)
                         (forward-bind-port candidate)
                         (forward-bind-path candidate)
                         listen-host listen-port))
                      *remote-forwards*)))))
    (or (and forward
             (case type
               (#.+mux-fwd-dynamic+
                (dynamic-forward-bind-port forward))
               (t (forward-bind-port forward))))
        0)))

(defun mux-forward-bind-matches-p (address port path listen-host listen-port)
  (if (= listen-port +mux-port-streamlocal+)
      (equal (or path "") (or listen-host ""))
      (and (eql (or port 0) (or listen-port 0))
           (string= (or address "") (or listen-host "")))))

(defun mux-cancelled-forward-p (forward listen-host listen-port)
  (and (equal (or (forward-bind-address forward) "") (or listen-host ""))
       (eql (or (forward-bind-port forward) 0)
            (if (= listen-port +mux-port-streamlocal+)
                0 listen-port))
       (equal (or (forward-bind-path forward) "")
              (if (= listen-port +mux-port-streamlocal+)
                  listen-host
                  ""))))

(defun mux-cancel-forward (type listen-host listen-port)
  (declare (ignore type))
  (let ((forward (find-if (lambda (candidate)
                            (mux-cancelled-forward-p
                             candidate listen-host listen-port))
                          (append *forwards* *remote-forwards*))))
    (when forward
      (setf *forwards* (delete forward *forwards*)
            *remote-forwards* (delete forward *remote-forwards*))
      (when (forward-listener forward)
        (ignore-errors (cl-pnet:close-listener (forward-listener forward)))
        (setf (forward-listener forward) nil))
      (when (forward-listener-watcher forward)
        (ignore-errors
         (cl-pnet:fd-unwatch (forward-listener-watcher forward)))
        (setf (forward-listener-watcher forward) nil))
      (when (forward-listener-fd forward)
        (ignore-errors
         (cl-pnet-sockets:close-open-fd (forward-listener-fd forward)))
        (setf (forward-listener-fd forward) nil)))))

(defun mux-apply-forward (type listen-host listen-port connect-host connect-port
                          &key on-remote-allocated on-remote-failed)
  (let* ((streamlocal (or (= listen-port +mux-port-streamlocal+)
                          (= connect-port +mux-port-streamlocal+)))
         (forward
           (%make-forward
            :bind-address (unless (= listen-port +mux-port-streamlocal+)
                            (unless (string= listen-host "") listen-host))
            :bind-port (unless (= listen-port +mux-port-streamlocal+)
                         listen-port)
            :bind-path (and (= listen-port +mux-port-streamlocal+)
                            listen-host)
            :host (unless (= connect-port +mux-port-streamlocal+)
                    (unless (string= connect-host "") connect-host))
            :port (unless (= connect-port +mux-port-streamlocal+)
                    connect-port)
            :target-path (and (= connect-port +mux-port-streamlocal+)
                              connect-host))))
    (declare (ignore streamlocal))
    (unless (case type
              (#.+mux-fwd-local+ (start-local-forward *client* forward))
              (#.+mux-fwd-remote+
               (start-remote-forward *client* forward
                                     :on-allocated on-remote-allocated
                                     :on-failed on-remote-failed))
              (#.+mux-fwd-dynamic+ (start-dynamic-forward *client* forward))
              (t (error "unknown forwarding type ~D" type)))
      (error "cannot start the requested forward"))
    forward))

;;; ---- Stdio forwarding over the control socket ----

(defun mux-master-new-stdio-forward (master connection reader)
  (let ((request-id (cl-pnet-ssh:ssh-read-u32 reader)))
    (cl-pnet-ssh:ssh-read-string reader) ; reserved
    (let ((host (cl-pnet-ssh:ssh-read-text reader))
          (port (cl-pnet-ssh:ssh-read-u32 reader)))
      (mux-connection-expect-fds
       connection 2
       (lambda (fds)
         (destructuring-bind (stdin stdout) fds
           (cond
             ((mux-connection-session connection)
              (mux-close stdin)
              (mux-close stdout)
              (mux-connection-send
               connection
               (mux-error-payload +mux-s-failure+ request-id
                                  "Multiple sessions not supported")))
             ((not (mux-permission-p
                    master
                    (if (= port +mux-port-streamlocal+)
                        (format nil "Allow forward to path ~A?" host)
                        (format nil "Allow forward to [~A]:~D?" host port))))
              (mux-close stdin)
              (mux-close stdout)
              (mux-connection-send
               connection
               (mux-error-payload +mux-s-permission-denied+
                                  request-id "Permission denied")))
             (t
              (mux-open-stdio-forward master connection request-id
                                      host port stdin stdout)))))))))

(defun mux-open-stdio-forward (master connection request-id host port
                               stdin stdout)
  (mux-master-note-session master)
  (dolist (fd (list stdin stdout))
    (ignore-errors (cl-pnet-sockets:set-nonblocking fd)))
  (let ((session (%make-mux-session
                  :master master :connection connection
                  :request-id request-id
                  :sid (prog1 (mux-master-next-session-id master)
                         (incf (mux-master-next-session-id master)))
                  :stdin-fd stdin :stdout-fd stdout :stderr-fd stdout
                  ;; A direct channel has no remote command and no exit
                  ;; status; a normal close is success.
                  :exit-status 0)))
    (setf (mux-connection-session connection) session)
    (push session (mux-master-sessions master))
    (handler-case
        (let ((channel
                (if (= port +mux-port-streamlocal+)
                    (cl-pnet-ssh:ssh-open-direct-streamlocal
                     *client* host
                     :on-open (lambda (channel)
                                (mux-stdio-opened session channel))
                     :on-data (lambda (channel data kind)
                                (declare (ignore channel))
                                (mux-session-output session kind data))
                     :on-close (lambda (channel status)
                                 (declare (ignore channel status))
                                 (unless (mux-session-closed session)
                                   (mux-session-close session)))
                     :on-error (lambda (channel condition)
                                 (declare (ignore channel))
                                 (mux-stdio-failed session condition)))
                    (cl-pnet-ssh:ssh-open-direct-tcpip
                     *client* host port
                     :on-open (lambda (channel)
                                (mux-stdio-opened session channel))
                     :on-data (lambda (channel data kind)
                                (declare (ignore channel))
                                (mux-session-output session kind data))
                     :on-close (lambda (channel status)
                                 (declare (ignore channel status))
                                 (unless (mux-session-closed session)
                                   (mux-session-close session)))
                     :on-error (lambda (channel condition)
                                 (declare (ignore channel))
                                 (mux-stdio-failed session condition))))))
          (setf (mux-session-channel session) channel)
          (setf (mux-session-stdin-watcher session)
                (cl-pnet:fd-watch
                 stdin :on-readable
                 (lambda (watcher)
                   (declare (ignore watcher))
                   (mux-session-read-stdin session)))))
      (error (condition)
        (mux-connection-send
         connection
         (mux-error-payload +mux-s-failure+ request-id
                            (format nil "~A" condition)))
        (mux-session-close session)))))

(defun mux-stdio-opened (session channel)
  (declare (ignore channel))
  (unless (mux-session-closed session)
    (setf (mux-session-opened session) t)
    (mux-connection-send
     (mux-session-connection session)
     (mux-request-payload +mux-s-session-opened+
                          (mux-session-request-id session)
                          (mux-session-sid session)))))

(defun mux-stdio-failed (session condition)
  (let ((connection (mux-session-connection session)))
    (unless (mux-connection-closed-p connection)
      (mux-connection-send
       connection
       (mux-error-payload +mux-s-failure+ (mux-session-request-id session)
                          (format nil "~A" condition))))
    (mux-session-close session)))

;;; ---- Deciding whether to attach, and starting a master ----

(defun mux-control-path-from-options (options)
  "The ControlPath in OPTIONS, expanded, or NIL when multiplexing is off."
  (let ((path (or (getf *options* :control-path)
                  (and options
                       (cl-pnet-ssh:ssh-config-options-control-path options)))))
    (when (and path (not (eq path :none)) (not (string-equal path "none")))
      (mux-expand-control-path
       (mux-tilde-expand path)
       :original (or (getf *options* :host) "")
       :hostname (or (and options
                          (cl-pnet-ssh:ssh-config-options-hostname options))
                     (getf *options* :host)
                     "")
       :port (or (and options
                      (cl-pnet-ssh:ssh-config-options-port options))
                 (client-port)
                 22)
       :user (or (and options
                      (cl-pnet-ssh:ssh-config-options-user options))
                 (getf *options* :user)
                 (uiop:getenv "USER")
                 (uiop:getenv "LOGNAME")
                 "root")))))

(defun mux-control-path-from-client (client)
  "CLIENT's ControlPath, expanded with the names it actually uses."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client))
        (path (or (getf *options* :control-path)
                  (and (cl-pnet-ssh:ssh-client-config-options client)
                       (cl-pnet-ssh:ssh-config-options-control-path
                        (cl-pnet-ssh:ssh-client-config-options client))))))
    (when (and path (not (eq path :none)) (not (string-equal path "none")))
      (mux-expand-control-path
       (mux-tilde-expand path)
       :original (or (cl-pnet-ssh:ssh-client-host client) "")
       :hostname (or (cl-pnet-ssh:ssh-client-connect-host client)
                     (cl-pnet-ssh:ssh-client-host client)
                     "")
       :port (or (cl-pnet-ssh:ssh-client-connect-port client)
                 (and options (cl-pnet-ssh:ssh-config-options-port options))
                 22)
       :user (or (cl-pnet-ssh:ssh-client-user client)
                 (uiop:getenv "USER")
                 (uiop:getenv "LOGNAME")
                 "root")))))

(defun mux-control-master (&optional options)
  "The effective ControlMaster keyword."
  (cond
    ((getf *options* :control-master) :yes)
    (options
     (or (cl-pnet-ssh:ssh-config-options-control-master options) :no))
    (t :no)))

(defun mux-control-persist (&optional options)
  "The effective ControlPersist value: :NO, :YES, or seconds."
  (if (getf *options* :no-control-persist)
      :no
      (or (and options
               (cl-pnet-ssh:ssh-config-options-control-persist options))
          :no)))

(defun mux-local-hostname ()
  (or (uiop:getenv "HOSTNAME")
      (ignore-errors (machine-instance))
      "localhost"))

(defun mux-expand-control-path (path &key original hostname port user)
  "PATH with the ControlPath percent tokens expanded.

%L is the local host without its domain, %l the local host, %h the resolved
remote host, %n the name as typed, %p the port, %r the remote user, %C a
SHA1 over %l%h%p%r, and %% a literal percent."
  (let* ((port (or port 22))
         (user (or user "root"))
         (original (or original ""))
         (hostname (or hostname original))
         (local (mux-local-hostname))
         (short-local (subseq local 0 (or (position #\. local) (length local))))
         (connection (format nil "~A~A~D~A" local hostname port user)))
    (with-output-to-string (out)
      (loop with length = (length path)
            for index from 0 below length
            for character = (char path index)
            do (if (and (char= character #\%)
                        (< (1+ index) length))
                   (let ((token (char path (1+ index))))
                     (incf index)
                     (case token
                       (#\% (write-char #\% out))
                       (#\L (write-string short-local out))
                       (#\l (write-string local out))
                       (#\h (write-string hostname out))
                       (#\n (write-string original out))
                       (#\p (format out "~D" port))
                       (#\r (write-string user out))
                       (#\C (write-string (mux-sha1-hex connection) out))
                       (t (write-char #\% out)
                          (write-char token out))))
                   (write-char character out))))))

(defun mux-sha1-hex (text)
  "Lowercase SHA1 hex of TEXT, as ssh(1) writes %C."
  (let ((digest (cl-pnet-ssh:ssh-hash
                 :sha1 (map '(vector (unsigned-byte 8)) #'char-code text))))
    (string-downcase
     (with-output-to-string (out)
       (loop for octet across digest
             do (format out "~2,'0X" octet))))))

(defun mux-config-options (&optional host)
  "Resolve HOST's ssh_config now, so a control socket can be found before
the SSH connection is even attempted."
  (let ((result nil)
        (failure nil))
    (handler-case
        (let ((source (cl-pnet-ssh:ssh-config-client-source
                       (getf *options* :config)
                       (command-line-option-list))))
          (cl-pnet-ssh:ssh-config-resolve
           source (or host (getf *options* :host) "")
           :original-host (or host (getf *options* :host) "")
           :user (getf *options* :user)
           :port (client-port)
           :exec-matcher #'match-exec
           :on-options (lambda (options) (setf result options))
           :on-error (lambda (condition) (setf failure condition))))
      (cl-pnet-ssh:ssh-config-error (condition)
        (setf failure condition)))
    (when failure
      (fail "~A" failure))
    result))

(defun mux-tty-request-p (options command-given-p)
  "Whether a request wants a PTY, following RequestTTY without a client."
  (let ((setting (or (getf *options* :request-tty)
                     (and options
                          (cl-pnet-ssh:ssh-config-options-request-tty
                           options))))
        (terminal (stdin-terminal-p)))
    (cond
      ((null setting) (and (null command-given-p) terminal))
      ((member setting '(:no "no" "off" "false") :test #'equal) nil)
      ((member setting '(:force "force") :test #'equal) t)
      ((member setting '(:yes "yes") :test #'equal) terminal)
      ((member setting '(:auto "auto") :test #'equal)
       (and (null command-given-p) terminal))
      (t (and (null command-given-p) terminal)))))

(defun mux-build-request (options command command-given-p subsystem-p)
  "A MUX-REQUEST for this invocation, from resolved OPTIONS."
  (let ((environment '()))
    (when options
      (dolist (name (cl-pnet-ssh:ssh-config-options-send-env options))
        (let ((value (uiop:getenv name)))
          (when value
            (push (format nil "~A=~A" name value) environment))))
      (dolist (assignment (cl-pnet-ssh:ssh-config-options-set-env options))
        (push assignment environment)))
    (%make-mux-request
     :want-tty (mux-tty-request-p options command-given-p)
     :want-subsystem subsystem-p
     :escape-char (mux-escape-char-number options)
     :term (uiop:getenv "TERM")
     :command (or command "")
     :env (nreverse environment))))

(defun mux-escape-char-number (options)
  (let ((explicit (getf *options* :escape-char))
        (value (and options
                    (cl-pnet-ssh:ssh-config-options-escape-char options))))
    (cond
      (explicit
       (let ((parsed (cl-pnet-ssh::ssh-config-escape-char-value explicit)))
         (if (and parsed (not (eq parsed :none))) parsed #xffffffff)))
      ((and value (not (eq value :none))) value)
      (t (char-code #\~)))))

(defun mux-forward-plist-for (forward type)
  (case type
    ((#.+mux-fwd-local+ #.+mux-fwd-remote+)
     (list :type type
           :listen-host (or (forward-bind-address forward)
                            (forward-bind-path forward) "")
           :listen-port (or (forward-bind-port forward)
                            (and (forward-bind-path forward)
                                 +mux-port-streamlocal+)
                            0)
           :connect-host (or (forward-host forward)
                             (forward-target-path forward) "")
           :connect-port (or (forward-port forward)
                             (and (forward-target-path forward)
                                  +mux-port-streamlocal+)
                             0)))
    (:dynamic
     (list :type +mux-fwd-dynamic+
           :listen-host (or (dynamic-forward-bind-address forward) "")
           :listen-port (or (dynamic-forward-bind-port forward) 0)
           :connect-host ""
           :connect-port 0))))

(defun mux-forward-plists ()
  "The command line's -L/-R/-D specifications as mux forwarding fields."
  (append
   (mapcar (lambda (forward)
             (mux-forward-plist-for forward +mux-fwd-local+))
           (getf *options* :local-forward))
   (mapcar (lambda (forward)
             (mux-forward-plist-for forward +mux-fwd-remote+))
           (getf *options* :remote-forward))
   (mapcar (lambda (forward)
             (mux-forward-plist-for forward :dynamic))
           (getf *options* :dynamic-forward))))

(defun mux-config-forward-plists (options)
  "The LocalForward, RemoteForward and DynamicForward lines in OPTIONS."
  (when options
    (append
     (mapcar (lambda (spec)
               (mux-forward-plist-for
                (parse-config-local-forward spec) +mux-fwd-local+))
             (reverse (cl-pnet-ssh:ssh-config-options-local-forwards options)))
     (mapcar (lambda (spec)
               (mux-forward-plist-for
                (parse-config-remote-forward spec) +mux-fwd-remote+))
             (reverse (cl-pnet-ssh:ssh-config-options-remote-forwards options)))
     (mapcar (lambda (spec)
               (mux-forward-plist-for
                (parse-dynamic-forward spec) :dynamic))
             (reverse (cl-pnet-ssh:ssh-config-options-dynamic-forwards
                       options))))))

(defun mux-attach-forwards (fd options)
  "Give the master the forwards this invocation asks for, as ssh(1) does."
  (unless (and options
               (cl-pnet-ssh:ssh-config-options-clear-all-forwardings options))
    (let ((specs (append (mux-config-forward-plists options)
                         (mux-forward-plists))))
      (when specs
        (mux-send-forwards fd specs nil)))))

(defun mux-client-info (fd name)
  "Ask the master on FD for its info NAME and return the text.

NAME is \"connection\" for -O conninfo or \"channels\" for -O channels.  The
master formats the text, including its CRLF line endings, so it is printed
unchanged."
  (mux-write-packet fd (mux-request-payload +mux-c-ext-info+ 0
                                            (cons "name" name)))
  (multiple-value-bind (type reader) (mux-read-reply fd 0)
    (unless (eql type +mux-s-ext-info+)
      (error "the control master refused the info request: ~A"
             (cl-pnet-ssh:ssh-read-text reader)))
    (let ((status (cl-pnet-ssh:ssh-read-u32 reader))
          (message (cl-pnet-ssh:ssh-read-text reader)))
      (if (plusp status)
          message
          (error "the control master refused the info request: ~A" message)))))

(defun mux-client-control (fd command options &optional extensions)
  "Run one -O COMMAND against the master on FD and return a status.

EXTENSIONS are the names the master advertised in its hello."
  (cond
    ((or (null command) (string-equal command "check"))
     (format t "Master running (pid=~D)~%" (mux-alive fd))
     0)
    ((member command '("exit" "terminate") :test #'string-equal)
     (mux-write-packet fd (mux-request-payload +mux-c-terminate+ 0))
     ;; The master may exit before its acknowledgement reaches the socket,
     ;; which ssh(1) treats as success for this command.
     (let ((message nil))
       (handler-case
           (multiple-value-bind (type reader) (mux-read-reply fd 0)
             (when (member type (list +mux-s-permission-denied+
                                      +mux-s-failure+))
               (setf message (cl-pnet-ssh:ssh-read-text reader))))
         (error () nil))
       (when message
         (error "the control master refused to terminate: ~A" message)))
     (format *error-output* "Exit request sent.~%")
     0)
    ((string-equal command "stop")
     (mux-write-packet fd (mux-request-payload +mux-c-stop-listening+ 0))
     (mux-read-reply fd 0)
     (format *error-output* "Stop listening request sent.~%")
     0)
    ((string-equal command "forward")
     (mux-send-forwards
      fd (append (mux-config-forward-plists options)
                 (mux-forward-plists))
      nil)
     0)
    ((string-equal command "cancel")
     (mux-send-forwards
      fd (append (mux-config-forward-plists options)
                 (mux-forward-plists))
      t)
     0)
    ((member command '("conninfo" "channels") :test #'string-equal)
     ;; A master that did not advertise the extension has no info handler;
     ;; asking anyway would only produce a generic "unsupported request".
     (unless (member "info" extensions :test #'string-equal)
       (error "mux server does not support info request"))
     (princ (mux-client-info
             fd (if (string-equal command "conninfo")
                    "connection"
                    "channels")))
     (finish-output)
     0)
    (t
     (error "unsupported control command ~S" command))))

#-win32
(defun mux-attach (path options command command-given-p mode)
  "Try to run this invocation as a client of the master at PATH.

Returns a status when the master answered, or (VALUES NIL REASON) so the
caller can connect normally; REASON explains why no master was used.  Once
the hello exchange has succeeded the master is alive, and any later refusal
is fatal rather than a reason to fall back to an unshared connection."
  (multiple-value-bind (fd errno) (mux-connect path)
    (cond
      ((null fd)
       ;; ssh(1) unlinks a socket that refuses connections while
       ;; ControlMaster is not "no"; a refused socket has no master behind it.
       (when (and (eql errno 111) (not (eq mode :no)))
         (log-line "stale control socket ~A; unlinking" path)
         (ignore-errors (delete-file path)))
       (values nil (and errno (cl-pnet-sockets:c-strerror errno))))
      (t
       (let ((alive nil)
             (extensions nil))
         (handler-case
             (progn
               (setf extensions (mux-handshake fd))
               (setf alive t)
               (cond
                 ((getf *options* :control-command)
                  (let ((status (mux-client-control
                                 fd (getf *options* :control-command)
                                 options extensions)))
                    (mux-close fd)
                    (finish status)))
                 ((getf *options* :stdio-forward)
                  (multiple-value-bind (host port)
                      (parse-host-port (getf *options* :stdio-forward))
                    (let ((status (mux-client-stdio-forward fd host port)))
                      (mux-close fd)
                      status)))
                 (t
                  (mux-attach-forwards fd options)
                  (let* ((master-pid (mux-alive fd))
                         (request (mux-build-request
                                   options command command-given-p
                                   (not (null (getf *options* :subsystem)))))
                         (status (mux-client-session
                                  fd request :master-pid master-pid)))
                    (mux-close fd)
                    status))))
           (error (condition)
             (mux-close fd)
             (if alive
                 (fail "~A" condition)
                 (progn
                   (log-line "control master attach failed: ~A" condition)
                   (values nil (format nil "~A" condition)))))))))))

(defun mux-start-requested-p (mode)
  (member mode '(:yes :ask :auto :autoask)))

#+win32
(defun mux-attach (path options command command-given-p mode)
  (declare (ignore path options command command-given-p mode))
  nil)

;;; ---- Wiring into the ordinary client ----

#-win32
(defun mux-detach-process ()
  "Leave the controlling terminal behind, as a persistent master must.

SETSID only succeeds when this process is not already a process-group
leader, which is the usual case for a freshly launched child; a refusal
means the caller is already detached enough, so it is not an error."
  (ignore-errors (cffi:foreign-funcall "setsid" :int))
  nil)

#-win32
(defun mux-detach-standard-streams ()
  "Send this process's standard streams to /dev/null.

A background master keeps running after the client that started it has
gone; it must not keep writing to that client's terminal or pipes."
  (let ((null (c-open "/dev/null" 2 0)))
    (when (>= null 0)
      (c-dup2 null 0)
      (c-dup2 null 1)
      (c-dup2 null 2)
      (when (> null 2)
        (c-close null)))))

#-win32
(defun mux-start-daemon (path options command command-given-p)
  "Start a detached master, wait until it listens, then attach to it."
  (let ((process
          (uiop:launch-program
           (cons (or (uiop:argv0) "/proc/self/exe")
                 (cons "--control-master-daemon"
                       (uiop:command-line-arguments)))
           :input nil
           :output :stream
           :error-output nil)))
    (let ((line (read-line (uiop:process-info-output process) nil nil)))
      (unless (equal line "BURS-MASTER-READY")
        (ignore-errors (uiop:terminate-process process))
        (ignore-errors (uiop:wait-process process))
        (fail "the background control master did not start")))
    (multiple-value-bind (status reason)
        (mux-attach path options command command-given-p :yes)
      (if status
          (finish status)
          (progn
            (ignore-errors (uiop:terminate-process process))
            (fail "the background control master is not accepting connections~@[: ~A~]"
                  reason))))))

#-win32
(defun mux-prepare (host command command-given-p)
  "Attach to a master, or arrange for this client to become one.

Runs before the SSH connection is attempted, because a usable master makes
that connection unnecessary.  As in mux.c, only ControlMaster=no, auto and
autoask try an existing master; yes and ask go straight to listening, so a
second invocation cannot quietly join a master it was told to own."
  (let* ((options (mux-config-options host))
         (path (mux-control-path-from-options options))
         (mode (mux-control-master options))
         (persist (mux-control-persist options)))
    (when path
      (when *mux-daemon*
        (setf *mux-create-master* t
              *mux-create-path* path
              *mux-create-mode* :yes
              *mux-create-persist* persist)
        (return-from mux-prepare t))
      (when (or (getf *options* :control-command)
                (member mode '(:no :auto :autoask)))
        (multiple-value-bind (status reason)
            (mux-attach path options command command-given-p mode)
          (when status (finish status))
          (when (getf *options* :control-command)
            (fail "Control socket connect(~A): ~A"
                  path (or reason "no control master is running")))))
      (when (mux-start-requested-p mode)
        (when (and (member mode '(:ask :autoask))
                   (not (eq persist :no)))
          (fail "ControlMaster=~A cannot keep a detached master because it must ask on a terminal"
                (string-downcase (symbol-name mode))))
        (if (eq persist :no)
            (setf *mux-create-master* t
                  *mux-create-path* path
                  *mux-create-mode* mode
                  *mux-create-persist* persist)
            (if (probe-file path)
                ;; ssh(1) disables multiplexing when the socket name is taken
                ;; and connects normally rather than detaching a master.
                (format *error-output*
                        "burs: ControlSocket ~A already exists, disabling multiplexing~%"
                        path)
                (mux-start-daemon path options command command-given-p)))))
    t))

(defun mux-start-configured-master (client)
  "Start the listener MAIN arranged for, once CLIENT is authenticated."
  (when *mux-create-master*
    (let ((path (or *mux-create-path*
                    (mux-control-path-from-client client))))
      (cond
        ((null path)
         (format *error-output* "burs: ControlMaster needs a ControlPath~%")
         (finish 255))
        ((probe-file path)
         ;; ssh(1) treats an existing socket that no master answered on as a
         ;; stale one: it warns and connects without multiplexing.
         (format *error-output*
                 "burs: ControlSocket ~A already exists, disabling multiplexing~%"
                 path))
        (t
         (handler-case
             (mux-start-master path *mux-create-mode* client
                               :persist *mux-create-persist*)
           (error (condition)
             (format *error-output* "burs: cannot start the control master: ~A~%"
                     condition)
             (finish 255))))))))

#+win32
(defun mux-detach-process () nil)
#+win32
(defun mux-prepare (host command command-given-p)
  (declare (ignore host command command-given-p))
  nil)
#+win32
(defun mux-start-configured-master (client)
  (declare (ignore client))
  nil)
