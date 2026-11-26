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

(defun mux-cstring-at (payload position)
  "The length-prefixed string at POSITION, or an empty string.
Some mux.c client replies read their error message directly after the type,
without skipping the request id; decoding the id as a length then yields the
empty string for the usual request id 0, which the message must reproduce."
  (if (> (+ position 4) (length payload))
      ""
      (let ((length (mux-u32 payload position)))
        (if (> (+ position 4 length) (length payload))
            ""
            (map 'string #'code-char
                 (subseq payload (+ position 4) (+ position 4 length)))))))


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
(define-condition mux-io-error (error)
  ((operation :initarg :operation :reader mux-io-error-operation)
   (errno :initarg :errno :reader mux-io-error-errno)
   (text :initarg :text :reader mux-io-error-text))
  (:report (lambda (condition stream)
             (write-string (mux-io-error-text condition) stream))))

#-win32
(defun mux-io-strerror (condition)
  "The C library text for CONDITION's errno, as mux.c's strerror() prints it."
  (let ((errno (mux-io-error-errno condition)))
    (if (and errno (plusp errno))
        (cl-pnet-sockets:c-strerror errno)
        "Unknown error")))

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
                  ;; mux.c turns a zero-length read into EPIPE.
                  (error 'mux-io-error
                         :operation :read
                         :errno (if (and error (plusp error)) error 32)
                         :text (format nil
                                       "the control socket closed before ~D octets"
                                       count))))))
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
                  (error 'mux-io-error
                         :operation :write
                         :errno error
                         :text (format nil
                                       "write to the control socket failed (~A)"
                                       error))))))))

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

VALUES EXTENSIONS EXCHANGED-P.  The master speaks first, as OpenSSH's does.
Its hello may carry (NAME VALUE) pairs after the version; only the names
matter to this client, and unknown names are ignored exactly as ssh(1)
ignores them.

mux_client_hello_exchange() writes the client hello before reading the
master's and, except for a buffer too short to parse, reports a failure and
lets ssh(1) fall back to a direct connection instead of dying."
  (handler-case (mux-write-packet fd (mux-hello-payload))
    (mux-io-error ()
      ;; mux.c debug-logs the write failure; muxclient() reports the
      ;; exchange failure itself.
      (log-error "muxclient: master hello exchange failed")
      (return-from mux-handshake (values nil nil))))
  (let ((payload
          (handler-case (mux-read-packet fd)
            (mux-io-error () nil))))
    (unless payload
      (log-error "muxclient: master hello exchange failed")
      (return-from mux-handshake (values nil nil)))
    (when (< (length payload) 4)
      (log-fatal "mux_client_hello_exchange: parse type: incomplete message"))
    (let ((type (mux-u32 payload 0)))
      (unless (eql type +mux-msg-hello+)
        (log-error "mux_client_hello_exchange: expected HELLO (~D) got ~D"
                   +mux-msg-hello+ type)
        (log-error "muxclient: master hello exchange failed")
        (return-from mux-handshake (values nil nil))))
    (when (< (length payload) 8)
      (log-fatal "mux_client_hello_exchange: parse version: incomplete message"))
    (let ((version (mux-u32 payload 4))
          (extensions '()))
      (unless (= version +mux-version+)
        (log-error "Unsupported multiplexing protocol version ~D (expected ~D)"
                   version +mux-version+)
        (log-error "muxclient: master hello exchange failed")
        (return-from mux-handshake (values nil nil)))
      (let ((reader (cl-pnet-ssh:ssh-make-reader payload 8)))
        (loop while (plusp (cl-pnet-ssh:ssh-reader-remaining reader))
              do (handler-case
                     (let ((name (cl-pnet-ssh:ssh-read-text reader)))
                       (cl-pnet-ssh:ssh-read-text reader) ; value
                       (push name extensions))
                   (error ()
                     (log-error
                      "mux_client_hello_exchange: parse extension: incomplete message")
                     (log-error "muxclient: master hello exchange failed")
                     (return-from mux-handshake (values nil nil))))))
      (values (nreverse extensions) t))))

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
(defun mux-send-forwards (fd forwards cancel-p &key forward-command-p)
  "Send FORWARDS, a list of plists, and report whether every one was accepted.

mux.c's mux_client_forwards() keeps going after a refusal: each rejected
forward logs its own line, the command still fails at the end, and
-O forward prints an allocated remote port on stdout.  The verbose line only
appears at LogLevel VERBOSE or above, which -q and the default do not reach."
  (let ((failed nil)
        (request-id 0))
    (dolist (forward forwards)
      (let* ((type (getf forward :type))
             (listen-host (or (getf forward :listen-host) ""))
             (listen-port (or (getf forward :listen-port) 0))
             (connect-host (or (getf forward :connect-host) ""))
             (connect-port (or (getf forward :connect-port) 0))
             (payload nil))
        (handler-case
            (mux-write-packet
             fd (mux-open-forward-payload request-id cancel-p type listen-host
                                          listen-port connect-host connect-port))
          (mux-io-error (condition)
            (log-fatal "mux_client_forward: write packet: ~A"
                       (mux-io-strerror condition))))
        (setf payload
              (handler-case (mux-read-packet fd)
                (mux-io-error () nil)))
        (if (null payload)
            ;; mux_client_forward() returns -1 silently and the caller
            ;; keeps trying the remaining forwards.
            (setf failed t)
            (progn
              (when (< (length payload) 8)
                (log-fatal "mux_client_forward: parse: incomplete message"))
              (let ((reply (mux-u32 payload 0))
                    (rid (mux-u32 payload 4)))
                (unless (= rid request-id)
                  (log-fatal
                   "mux_client_forward: out of sequence reply: my id ~D theirs ~D"
                   request-id rid))
                (case reply
                  (#.+mux-s-ok+ (incf request-id))
                  (#.+mux-s-remote-port+
                   (when cancel-p
                     (log-fatal
                      "mux_client_forward: got MUX_S_REMOTE_PORT for cancel"))
                   (when (< (length payload) 12)
                     (log-fatal "mux_client_forward: parse port: incomplete message"))
                   (let ((port (mux-u32 payload 8)))
                     (when (plusp (getf *options* :verbose 0))
                       (log-message
                        "Allocated port ~D for remote forward to ~A:~A"
                        port connect-host connect-port))
                     (when forward-command-p
                       (format t "~D~%" port)
                       (finish-output)))
                   (incf request-id))
                  (#.+mux-s-permission-denied+
                   (log-error "Master refused forwarding request: ~A"
                              (mux-cstring-at payload 8))
                   (setf failed t))
                  (#.+mux-s-failure+
                   (log-error "mux_client_forward: forwarding request failed: ~A"
                              (mux-cstring-at payload 8))
                   (setf failed t))
                  (t
                   (log-fatal
                    "mux_client_forward: unexpected response from master 0x~8,'0X"
                    reply))))))))
    (not failed)))


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
                (log-error "Master refused session request: ~A"
                           (cl-pnet-ssh:ssh-read-text reader))
                :refused)
               (#.+mux-s-failure+
                ;; mux_client_request_session() reports through error_f(),
                ;; whose showfunc prefix appears even without -v.
                (log-error
                 "mux_client_request_session: session request failed: ~A"
                 (cl-pnet-ssh:ssh-read-text reader))
                :refused)
               (t
                (log-error
                 "mux_client_request_session: unexpected response from master 0x~8,'0X"
                 type)
                :refused))))
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

(defun mux-client-wait-stdio (fd)
  "Wait for the master to finish a stdio forward, as ssh's client does.

A stdio forward has no exit status.  The master passes the channel's bytes
over the descriptors it received and, when the channel ends, closes the
control connection; ssh reads once more and treats the resulting EPIPE as
success.  A packet arriving there instead means the master broke the
protocol, which ssh treats as fatal."
  (handler-case
      (let ((payload (mux-read-packet fd)))
        (fail "master returned unexpected message 0x~8,'0X"
              (mux-u32 payload 0)))
    (error () 0)))

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
         (mux-client-wait-stdio fd))
        (#.+mux-s-permission-denied+
         (log-fatal "Master refused stdio forwarding request: ~A"
                    (cl-pnet-ssh:ssh-read-text reader)))
        (#.+mux-s-failure+
         (log-fatal "Stdio forwarding request failed: ~A"
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
  ;; mux.c gives every attached client a "mux-control" channel; its id is
  ;; reserved for the connection's lifetime, like that channel's slot.
  control-channel-id
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
    (when (and *client* (mux-connection-control-channel-id connection))
      (cl-pnet-ssh:ssh-client-release-channel-ids
       *client* (list (mux-connection-control-channel-id connection))))
    (setf (mux-connection-control-channel-id connection) nil)
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
each one rides on.  A frame too short to hold a type is what mux.c calls a
malformed message."
  (let* ((input (mux-connection-input connection))
         (length (mux-connection-frame-length connection))
         (payload (subseq input 4 (+ 4 length))))
    (setf (fill-pointer input) 0
          (mux-connection-frame-length connection) nil)
    (if (< length 4)
        (progn
          (log-error "mux_master_read_cb: malformed message")
          (mux-connection-stop connection))
        (funcall (mux-connection-on-message connection) connection
                 (mux-u32 payload 0)
                 (cl-pnet-ssh:ssh-make-reader payload 4)
                 payload))))

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
  ;; mux.c's listener is a channel too (SSH_CHANNEL_MUX_LISTENER, type 15),
  ;; hidden from -O channels but holding the slot.
  listener-id
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
    ;; mux.c's listener is an ordinary channel, so it owns the lowest free id.
    ;; Reserving it keeps the numbers in "channel N:" diagnostics identical.
    (let ((listener-id
            (cl-pnet-ssh:ssh-client-reserve-channel-ids client 1))
          (master (%make-mux-master :path path :fd fd :mode mode
                                    :persist persist)))
      (setf (mux-master-listener-id master) (first listener-id))
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
              ;; Each attached client has a mux-control channel of its own.
              (setf (mux-connection-control-channel-id connection)
                    (first (cl-pnet-ssh:ssh-client-reserve-channel-ids
                            *client* 1)))
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

(defun mux-format-channel-status
    (out id remote-name type ctype remote-id-p remote-id mux-p
     istate input-length ostate output-length extended-usage extended-length
     rfd wfd efd sock ctl-chan ctl-child-p ctl-child-id io-want io-ready
     tty-flag bulk-flag)
  "Write one channel_format_status() line, as channels.c spells it."
  (format out
          "  #~D ~A (t~D [~A] ~A~D ~A0 i~D/~D o~D/~D e[~A]/~D fd ~D/~D/~D sock ~D cc ~D ~A~D io 0x~2,'0X/0x~2,'0X ~A~A)"
          id remote-name type ctype
          (if remote-id-p "r" "nr") remote-id (if mux-p "m" "nm")
          istate input-length ostate output-length
          extended-usage extended-length
          rfd wfd efd sock ctl-chan
          (if ctl-child-p "c" "nc") ctl-child-id
          io-want io-ready tty-flag bulk-flag)
  (mux-write-crlf out))

(defun mux-control-channel-status (out connection child-id)
  "Write the mux-control channel mux.c gives every attached client."
  (let ((fd (mux-connection-fd connection))
        (output (mux-connection-output connection)))
    (mux-format-channel-status
     out (mux-connection-control-channel-id connection) "mux-control"
     16 "mux-control" nil 0 t
     ;; The control channel has no SSH buffer state of its own.
     0 0 0 0 "closed" 0
     fd fd -1 fd -1
     (and child-id t) (or child-id 0)
     1 (if (and output (plusp (fill-pointer output))) 0 1)
     "" "I")))

(defun mux-session-channel-status (out session)
  "Write the channel a mux client's session runs on.

A normal session is channels.c's client-session; a -W stdio forward is a
stdio-forward channel created by channel_connect_stdio_fwd()."
  (let* ((channel (mux-session-channel session))
         (connection (mux-session-connection session))
         (state (and channel (cl-pnet-ssh::ssh-channel-state channel)))
         (open (member state '(:open :closing)))
         (remote-id (and channel (cl-pnet-ssh::ssh-channel-remote-id channel)))
         (x-type (and channel (cl-pnet-ssh::ssh-channel-x-type channel)))
         (ctype (or x-type
                    (and channel (cl-pnet-ssh::ssh-channel-type channel))
                    "session"))
         (eof (and channel (cl-pnet-ssh::ssh-channel-sent-eof channel)))
         (write-queue (and channel (cl-pnet-ssh::ssh-channel-write-queue channel)))
         (stdin (if (mux-session-stdin-watcher session)
                    (mux-session-stdin-fd session)
                    -1))
         (stderr (if (mux-session-closed session)
                     -1
                     (mux-session-stderr-fd session))))
    (if (mux-session-stdio session)
        (mux-format-channel-status
         out (cl-pnet-ssh::ssh-channel-local-id channel)
         (or (mux-session-remote-name session) "stdio-forward")
         (if open 4 3) "stdio-forward" (and remote-id t) (or remote-id 0) nil
         (if eof 3 0) 0
         (if (eq state :closing) 3 0)
         (if write-queue (fill-pointer write-queue) 0)
         "closed" 0
         stdin (mux-session-stdout-fd session) -1 -1
         (mux-connection-control-channel-id connection) nil 0
         1 0 "" "B")
        (mux-format-channel-status
         out (cl-pnet-ssh::ssh-channel-local-id channel) "client-session"
         (if open 4 3) ctype (and remote-id t) (or remote-id 0) nil
         ;; i3 is CHAN_INPUT_CLOSED: the local side has sent EOF.
         (if eof 3 0) 0
         (if (eq state :closing) 3 0)
         (if write-queue (fill-pointer write-queue) 0)
         (if (= stderr -1) "closed" "write")
         (fill-pointer (mux-session-stderr-buffer session))
         stdin (mux-session-stdout-fd session) stderr -1
         (mux-connection-control-channel-id connection) nil 0
         0 0
         (if (mux-session-want-tty session) "T" "")
         ;; CHANNEL_NONBLOCK_STDIO marks the stdio-backed session bulk.
         "B"))))

(defun mux-generic-channel-status (out channel)
  "Write a channel the mux layer did not create itself, such as a forwarded
connection.  Its remote name is whatever the forwarding code recorded."
  (let* ((state (cl-pnet-ssh::ssh-channel-state channel))
         (open (member state '(:open :closing)))
         (remote-id (cl-pnet-ssh::ssh-channel-remote-id channel))
         (ctype (or (cl-pnet-ssh::ssh-channel-x-type channel)
                    (cl-pnet-ssh::ssh-channel-type channel)
                    "unknown"))
         (name (or (cl-pnet-ssh::ssh-channel-remote-name channel) ctype))
         (write-queue (cl-pnet-ssh::ssh-channel-write-queue channel)))
    (mux-format-channel-status
     out (cl-pnet-ssh::ssh-channel-local-id channel) name
     (if open 4 3) ctype (and remote-id t) (or remote-id 0) nil
     0 0 (if (eq state :closing) 3 0)
     (if write-queue (fill-pointer write-queue) 0)
     "closed" 0
     -1 -1 -1 -1 -1 nil 0
     0 0 "" "B")))

(defun mux-channel-open-message (master)
  "The text -O channels returns, matching channels.c's channel_open_message.

Every entry is printed from the real channel table, so the ids, the
client-session/mux-control names and the control/session links agree with
the numbers \"channel N:\" diagnostics use.  Descriptor numbers and the
libssh input/output flags are this implementation's own."
  (let ((entries '())
        (printed (make-hash-table :test #'eql)))
    (dolist (connection (mux-master-connections master))
      (when (mux-connection-control-channel-id connection)
        (let* ((session (mux-connection-session connection))
               (channel (and session (mux-session-channel session)))
               (child-id (and channel
                              (cl-pnet-ssh::ssh-channel-local-id channel))))
          (setf (gethash (mux-connection-control-channel-id connection)
                         printed)
                t)
          (push (cons (mux-connection-control-channel-id connection)
                      (lambda (out)
                        (mux-control-channel-status out connection child-id)))
                entries))))
    (dolist (session (mux-master-sessions master))
      (unless (mux-session-closed session)
        (let ((channel (mux-session-channel session)))
          (when channel
            (let ((id (cl-pnet-ssh::ssh-channel-local-id channel)))
              (setf (gethash id printed) t)
              (push (cons id
                          (lambda (out)
                            (mux-session-channel-status out session)))
                    entries))))))
    ;; Everything else the client holds open, such as a forwarded
    ;; connection the master is carrying.
    (when *client*
      (maphash
       (lambda (id channel)
         (unless (or (gethash id printed)
                     (eql id (mux-master-listener-id master))
                     (eq (cl-pnet-ssh::ssh-channel-state channel) :closed))
           (push (cons id
                       (lambda (out)
                         (mux-generic-channel-status out channel)))
                 entries)))
       (cl-pnet-ssh::ssh-client-channels *client*)))
    (with-output-to-string (out)
      (format out "The following connections are open:")
      (mux-write-crlf out)
      (dolist (entry (sort entries #'< :key #'car))
        (funcall (cdr entry) out)))))

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
  (cond
    ((eql type +mux-msg-hello+)
     (cond
       ((mux-connection-hello connection)
        (log-error "mux_master_process_hello: HELLO received twice")
        (mux-connection-stop connection))
       ((< (length payload) 8)
        (log-error "mux_master_process_hello: parse: incomplete message")
        (mux-connection-stop connection))
       (t
        (let ((version (cl-pnet-ssh:ssh-read-u32 reader)))
          (cond
            ((/= version +mux-version+)
             (log-error
              "mux_master_process_hello: unsupported multiplexing protocol version ~D (expected ~D)"
              version +mux-version+)
             (mux-connection-stop connection))
            (t
             (handler-case
                 ;; No extensions are presently defined; the pairs still
                 ;; have to parse, as mux.c checks.
                 (progn
                   (loop while (plusp (cl-pnet-ssh:ssh-reader-remaining
                                       reader))
                         do (cl-pnet-ssh:ssh-read-text reader) ; name
                            (cl-pnet-ssh:ssh-read-string reader)) ; value
                   (setf (mux-connection-hello connection) t))
               (error ()
                 (log-error
                  "mux_master_process_hello: parse extension: incomplete message")
                 (mux-connection-stop connection)))))))))
    ((not (mux-connection-hello connection))
     (log-error
      "mux_master_read_cb: expected MUX_MSG_HELLO(0x~8,'0X), received 0x~8,'0X"
      +mux-msg-hello+ type)
     (mux-connection-stop connection))
    ((< (length payload) 8)
     (log-error "mux_master_read_cb: malformed message")
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
     (log-error "mux_master_read_cb: unsupported mux message 0x~8,'0X" type)
     (mux-connection-send
      connection
      (mux-error-payload +mux-s-failure+ (mux-u32 payload 4)
                         "unsupported request")))))

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
  ;; A -W stdio forward is a direct channel: ssh sends no exit status for
  ;; it, closing the control channel instead, so the slave must not expect
  ;; one.
  (stdio nil)
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
                   ;; mux_session_confirm() reports a refused session open
                   ;; with one fixed string, whatever the peer said, while
                   ;; the master's own log carries the reason.
                   (log-channel-open-failure channel condition)
                   (unless (mux-session-closed session)
                     (mux-connection-send
                      connection
                      (mux-error-payload +mux-s-failure+ request-id
                                         "Session open refused by peer"))
                     (mux-session-close session))))))
          (setf (mux-session-channel session) channel)
          (setf (mux-session-stdin-watcher session)
                (mux-watch-input
                 stdin
                 (lambda (watch)
                   (declare (ignore watch))
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
    ;; clientloop.c's client_session2_setup() records the same extended
    ;; type, which -O channels shows in brackets.
    (cl-pnet-ssh::ssh-channel-set-x-type
     channel
     (cond
       (want-subsystem (format nil "session:subsystem:~A" command))
       ((plusp (length command)) "session:command")
       (t "session:shell")))
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
         (mux-session-stop-stdin session)
         (ignore-errors
          (cl-pnet-ssh:ssh-channel-eof (mux-session-channel session))))
        ((member error '(4 11)) nil)
        (t
         (mux-session-stop-stdin session)
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

(defstruct (mux-input-watch (:constructor %make-mux-input-watch))
  fd
  watcher
  timer)

(defun mux-watch-input (fd reader)
  "Watch FD for input, falling back to a timer when the backend refuses it.

epoll cannot register descriptors such as /dev/null or a regular file, and
those are the usual stdin of a non-interactive multiplex client.  Such an fd
is always readable, so a repeating timer drives READER instead.  READER is
called with the watch and stops it with MUX-STOP-INPUT-WATCH at EOF."
  (let ((watch (%make-mux-input-watch :fd fd)))
    (handler-case
        (setf (mux-input-watch-watcher watch)
              (cl-pnet:fd-watch
               fd :on-readable
               (lambda (watcher)
                 (declare (ignore watcher))
                 (funcall reader watch))))
      (error ()
        (setf (mux-input-watch-timer watch)
              (cl-pnet:timer-start
               0.001 0.001
               (lambda () (funcall reader watch))))))
    watch))

(defun mux-stop-input-watch (watch)
  (when watch
    (when (mux-input-watch-watcher watch)
      (ignore-errors
       (cl-pnet:fd-unwatch (mux-input-watch-watcher watch)))
      (setf (mux-input-watch-watcher watch) nil))
    (when (mux-input-watch-timer watch)
      (ignore-errors
       (cl-pnet:timer-stop (mux-input-watch-timer watch)))
      (setf (mux-input-watch-timer watch) nil)))
  nil)

(defun mux-session-stop-stdin (session)
  (when (mux-session-stdin-watcher session)
    (mux-stop-input-watch (mux-session-stdin-watcher session))
    (setf (mux-session-stdin-watcher session) nil)))

(defun mux-session-close (session)
  (unless (mux-session-closed session)
    (setf (mux-session-closed session) t)
    (mux-session-stop-stdin session)
    (mux-session-unwatch-output session nil)
    (mux-session-unwatch-output session t)
    (when (and (mux-session-opened session)
               (not (mux-session-stdio session)))
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

(defun mux-open-forward-invalid-p (type listen-host listen-port
                                   connect-host connect-port)
  "Whether mux_master_process_open_fwd() refuses this forward.

Returns the logit() text it prints, or NIL when the request is acceptable."
  (cond
    ((not (member type (list +mux-fwd-local+ +mux-fwd-remote+
                             +mux-fwd-dynamic+)))
     (format nil "invalid forwarding type ~D" type))
    ((and (= type +mux-fwd-dynamic+)
          (= listen-port +mux-port-streamlocal+))
     "streamlocal and dynamic forwards are mutually exclusive")
    ((and (/= listen-port +mux-port-streamlocal+) (>= listen-port 65536))
     (format nil "invalid listen port ~D" listen-port))
    ((and (/= connect-port +mux-port-streamlocal+) (>= connect-port 65536))
     (format nil "invalid connect port ~D" connect-port))
    ((and (/= type +mux-fwd-dynamic+) (/= type +mux-fwd-remote+)
          (zerop connect-port))
     "invalid connect port 0")
    ((and (/= type +mux-fwd-dynamic+) (string= connect-host ""))
     "missing connect host")))

(defun mux-master-forward (master connection reader cancel-p)
  (let* ((request-id (cl-pnet-ssh:ssh-read-u32 reader))
         (fields (mux-forward-fields reader))
         (type (getf fields :type))
         (listen-host (getf fields :listen-host))
         (listen-port (getf fields :listen-port))
         (connect-host (getf fields :connect-host))
         (connect-port (getf fields :connect-port))
         (invalid (and (not cancel-p)
                       (mux-open-forward-invalid-p
                        type listen-host listen-port
                        connect-host connect-port)))
         (defer (and (= type +mux-fwd-remote+) (zerop listen-port))))
    (when invalid
      (log-info "mux_master_process_open_fwd: ~A" invalid)
      (return-from mux-master-forward
        (mux-connection-send
         connection
         (mux-error-payload +mux-s-failure+ request-id
                            "Invalid forwarding request"))))
    (handler-case
        (cond
          (cancel-p
           (if (mux-cancel-forward type listen-host listen-port)
               (mux-connection-send connection (mux-ok-payload request-id))
               ;; mux_master_process_close_fwd() reports a forward it never
               ;; held instead of pretending it cancelled something.
               (mux-connection-send
                connection
                (mux-error-payload +mux-s-failure+ request-id
                                   "port not forwarded"))))
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
                                  (and (= type +mux-fwd-remote+)
                                       forward
                                       (forward-bind-port forward)))))))
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
              (dynamic-forward-bind-address forward)
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
  "Stop the forward TYPE names; true when it was registered."
  (if (= type +mux-fwd-dynamic+)
      (let ((forward (find-if
                      (lambda (candidate)
                        (mux-forward-bind-matches-p
                         (dynamic-forward-bind-address candidate)
                         (dynamic-forward-bind-port candidate) nil
                         listen-host listen-port))
                      *dynamic-forwards*)))
        (when forward
          (close-dynamic-forward-listeners forward)
          (setf *dynamic-forwards* (delete forward *dynamic-forwards*))
          (release-dynamic-forward-channel-id *client* forward))
        (and forward t))
      (let ((forward (find-if (lambda (candidate)
                                (mux-cancelled-forward-p
                                 candidate listen-host listen-port))
                              (append *forwards* *remote-forwards*))))
        (when forward
          (setf *forwards* (delete forward *forwards*)
                *remote-forwards* (delete forward *remote-forwards*))
          (close-forward-listeners forward)
          (when (forward-listener-watcher forward)
            (ignore-errors
             (cl-pnet:fd-unwatch (forward-listener-watcher forward)))
            (setf (forward-listener-watcher forward) nil))
          (when (forward-listener-fd forward)
            (ignore-errors
             (cl-pnet-sockets:close-open-fd (forward-listener-fd forward)))
            (setf (forward-listener-fd forward) nil))
          ;; The listener channels' slots are free again, as channels.c's
          ;; channel_free() makes them.
          (release-forward-channel-id *client* forward))
        (and forward t))))

(defun mux-apply-forward (type listen-host listen-port connect-host connect-port
                          &key on-remote-allocated on-remote-failed)
  (if (= type +mux-fwd-dynamic+)
      ;; -D is one entry of ssh's local_forwards with connect_port 0, and the
      ;; master installs it with channel_setup_local_fwd_listener().
      (let ((forward
              (%make-dynamic-forward
               :bind-address (unless (= listen-port +mux-port-streamlocal+)
                               (unless (string= listen-host "") listen-host))
               :bind-port (unless (= listen-port +mux-port-streamlocal+)
                            listen-port)
               :bind-path (and (= listen-port +mux-port-streamlocal+)
                               listen-host))))
        (unless (start-dynamic-forward *client* forward)
          (error "cannot start the requested forward"))
        forward)
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
                  (t (error "unknown forwarding type ~D" type)))
          (error "cannot start the requested forward"))
        forward)))

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
                  :stdio t
                  :exit-status 0
                  ;; channel_connect_stdio_fwd() names the channel from
                  ;; port_open_helper(), whose socket is -1.
                  :remote-name
                  (format nil "~A: listening port 0 for ~A port ~D, connect from 127.0.0.1 port 65535 to UNKNOWN port 65536"
                          (if (= port +mux-port-streamlocal+)
                              "direct-streamlocal@openssh.com"
                              "direct-tcpip")
                          host
                          (if (= port +mux-port-streamlocal+) -2 port)))))
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
                                 (mux-stdio-failed session channel condition)))
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
                                 (mux-stdio-failed session channel
                                                   condition))))))
          (setf (mux-session-channel session) channel)
          (setf (mux-session-stdin-watcher session)
                (mux-watch-input
                 stdin
                 (lambda (watch)
                   (declare (ignore watch))
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

(defun mux-stdio-failed (session channel condition)
  ;; channels.c logs the refused open in the master, then mux_stdio_confirm()
  ;; sends the same generic text to the client.
  (log-channel-open-failure channel condition)
  (let ((connection (mux-session-connection session)))
    (unless (mux-connection-closed-p connection)
      (mux-connection-send
       connection
       (mux-error-payload +mux-s-failure+ (mux-session-request-id session)
                          "Session open refused by peer")))
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
      (fail-config-error failure))
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
           :listen-host (or (dynamic-forward-bind-address forward)
                            (dynamic-forward-bind-path forward) "")
           :listen-port (or (dynamic-forward-bind-port forward)
                            (and (dynamic-forward-bind-path forward)
                                 +mux-port-streamlocal+)
                            0)
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
  "Give the master the forwards this invocation asks for, as ssh(1) does.

Returns true when every forward was accepted."
  (if (and options
           (cl-pnet-ssh:ssh-config-options-clear-all-forwardings options))
      t
      (let ((specs (append (mux-config-forward-plists options)
                           (mux-forward-plists))))
        (or (null specs) (mux-send-forwards fd specs nil)))))

(defun mux-client-info (fd name)
  "Ask the master on FD for its info NAME and return the text.

NAME is \"connection\" for -O conninfo or \"channels\" for -O channels.  The
master formats the text, including its CRLF line endings, so it is printed
unchanged.  mux.c ignores the status word and returns the message either
way, and its error path reads the message right after the type, so the
request id is decoded as a length; both quirks are reproduced here."
  (handler-case
      (mux-write-packet fd (mux-request-payload +mux-c-ext-info+ 0
                                                (cons "name" name)))
    (mux-io-error (condition)
      (log-fatal "mux_client_request_info: write packet: ~A"
                 (mux-io-strerror condition))))
  (let ((payload (handler-case (mux-read-packet fd)
                   (mux-io-error () nil))))
    (unless payload
      ;; mux_client_request_info() returns NULL and muxclient() dies with
      ;; its own message.
      (log-fatal "muxclient: info request failed"))
    (when (< (length payload) 4)
      (log-fatal "mux_client_request_info: parse type: incomplete message"))
    (let ((type (mux-u32 payload 0)))
      (unless (eql type +mux-s-ext-info+)
        (log-fatal "mux_client_request_info: master returned error: ~A"
                   (mux-cstring-at payload 4)))
      (when (< (length payload) 8)
        (log-fatal "mux_client_request_info: parse remote ID: incomplete message"))
      (let ((rid (mux-u32 payload 4)))
        (unless (zerop rid)
          (log-fatal
           "mux_client_request_info: out of sequence reply: my id 0 theirs ~D"
           rid)))
      (when (< (length payload) 16)
        (log-fatal
         "mux_client_request_info: parse connection info: incomplete message"))
      (mux-u32 payload 8)               ; status, which mux.c ignores
      (mux-cstring-at payload 12))))

(defun mux-client-alive-check (fd)
  "Ask the master on FD for its pid, as mux_client_request_alive() does."
  (handler-case
      (mux-write-packet fd (mux-request-payload +mux-c-alive-check+ 0))
    (mux-io-error (condition)
      (log-fatal "mux_client_request_alive: write packet: ~A"
                 (mux-io-strerror condition))))
  (let ((payload (handler-case (mux-read-packet fd)
                   (mux-io-error () nil))))
    (unless payload
      ;; A failed read makes mux_client_request_alive() return 0, which
      ;; muxclient() reports with its own function name.
      (log-fatal "muxclient: master alive check failed"))
    (when (< (length payload) 4)
      (log-fatal "mux_client_request_alive: parse type: incomplete message"))
    (let ((type (mux-u32 payload 0)))
      (unless (eql type +mux-s-alive+)
        (log-fatal "mux_client_request_alive: master returned error: ~A"
                   (mux-cstring-at payload 4)))
      (when (< (length payload) 8)
        (log-fatal "mux_client_request_alive: parse remote ID: incomplete message"))
      (let ((rid (mux-u32 payload 4)))
        (unless (zerop rid)
          (log-fatal
           "mux_client_request_alive: out of sequence reply: my id 0 theirs ~D"
           rid)))
      (when (< (length payload) 12)
        (log-fatal "mux_client_request_alive: parse PID: incomplete message"))
      (mux-u32 payload 8))))

(defun mux-client-reply-type-and-id (fd function)
  "Read a reply on FD and return TYPE and REQUEST-ID.

FUNCTION names the mux.c client routine for the fatal messages, matching
fatal_fr()'s \"parse\" wording when the packet is too short."
  (let ((payload (mux-read-packet fd)))
    (when (< (length payload) 8)
      (log-fatal "~A: parse: incomplete message" function))
    (values (mux-u32 payload 0) (mux-u32 payload 4) payload)))

(defun mux-client-terminate (fd)
  "Send MUX_C_TERMINATE and handle its reply the way mux.c does."
  (handler-case
      (mux-write-packet fd (mux-request-payload +mux-c-terminate+ 0))
    (mux-io-error (condition)
      (log-fatal "mux_client_request_terminate: write packet: ~A"
                 (mux-io-strerror condition))))
  (handler-case
      (multiple-value-bind (type rid payload)
          (mux-client-reply-type-and-id fd "mux_client_request_terminate")
        (unless (zerop rid)
          (log-fatal
           "mux_client_request_terminate: out of sequence reply: my id 0 theirs ~D"
           rid))
        (case type
          (#.+mux-s-ok+ nil)
          (#.+mux-s-permission-denied+
           (log-fatal "Master refused termination request: ~A"
                      (mux-cstring-at payload 8)))
          (#.+mux-s-failure+
           (log-fatal
            "mux_client_request_terminate: termination request failed: ~A"
            (mux-cstring-at payload 8)))
          (t
           (log-fatal
            "mux_client_request_terminate: unexpected response from master 0x~8,'0X"
            type))))
    (mux-io-error (condition)
      ;; The master usually exits before its acknowledgement arrives; mux.c
      ;; treats EPIPE as success and any other read error as fatal.
      (unless (eql (mux-io-error-errno condition) 32)
        (log-fatal "mux_client_request_terminate: read from master failed: ~A"
                   (mux-io-strerror condition))))))

(defun mux-client-stop-listening (fd)
  "Send MUX_C_STOP_LISTENING and handle its reply the way mux.c does."
  (handler-case
      (mux-write-packet fd (mux-request-payload +mux-c-stop-listening+ 0))
    (mux-io-error (condition)
      (log-fatal "mux_client_request_stop_listening: write packet: ~A"
                 (mux-io-strerror condition))))
  (handler-case
      (multiple-value-bind (type rid payload)
          (mux-client-reply-type-and-id fd "mux_client_request_stop_listening")
        (unless (zerop rid)
          (log-fatal
           "mux_client_request_stop_listening: out of sequence reply: my id 0 theirs ~D"
           rid))
        (case type
          (#.+mux-s-ok+ nil)
          (#.+mux-s-permission-denied+
           (log-fatal "Master refused stop listening request: ~A"
                      (mux-cstring-at payload 8)))
          (#.+mux-s-failure+
           (log-fatal
            "mux_client_request_stop_listening: stop listening request failed: ~A"
            (mux-cstring-at payload 8)))
          (t
           (log-fatal
            "mux_client_request_stop_listening: unexpected response from master 0x~8,'0X"
            type))))
    (mux-io-error (condition)
      (log-fatal "mux_client_request_stop_listening: read from master failed: ~A"
                 (mux-io-strerror condition)))))

(defun mux-client-control (fd command options &optional extensions)
  "Run one -O COMMAND against the master on FD and return a status.

EXTENSIONS are the names the master advertised in its hello."
  (cond
    ((or (null command) (string-equal command "check"))
     ;; mux.c writes this one with fprintf(stderr), not through log.c, so it
     ;; goes to stderr even when -E redirects the log.
     (format *error-output* "Master running (pid=~D)~%"
             (mux-client-alive-check fd))
     0)
    ((member command '("exit" "terminate") :test #'string-equal)
     (mux-client-terminate fd)
     (unless (fatal-message-suppressed-p)
       (format *error-output* "Exit request sent.~%"))
     0)
    ((string-equal command "stop")
     (mux-client-stop-listening fd)
     (unless (fatal-message-suppressed-p)
       (format *error-output* "Stop listening request sent.~%"))
     0)
    ((string-equal command "forward")
     (unless (mux-send-forwards
              fd (append (mux-config-forward-plists options)
                         (mux-forward-plists))
              nil :forward-command-p t)
       (log-fatal "muxclient: master forward request failed"))
     0)
    ((string-equal command "cancel")
     (unless (mux-send-forwards
              fd (append (mux-config-forward-plists options)
                         (mux-forward-plists))
              t)
       ;; mux.c logs the failure at ERROR and still exits 0 for cancel.
       (log-error "muxclient: master cancel forward request failed"))
     0)
    ((member command '("conninfo" "channels") :test #'string-equal)
     ;; A master that did not advertise the extension has no info handler;
     ;; asking anyway would only produce a generic "unsupported request".
     (unless (member "info" extensions :test #'string-equal)
       (log-fatal "mux server does not support info request"))
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
             (extensions nil)
             (stdio (and (getf *options* :stdio-forward)
                         (multiple-value-list
                          (parse-stdio-forward
                           (getf *options* :stdio-forward))))))
         (handler-case
             (progn
               (multiple-value-bind (names exchanged)
                   (mux-handshake fd)
                 (unless exchanged
                   (mux-close fd)
                   ;; ssh(1) connects directly when the master cannot even
                   ;; complete the hello exchange; it does not fail here.
                   (return-from mux-attach (values nil :hello-failed)))
                 (setf extensions names))
               (setf alive t)
               (cond
                 ((getf *options* :control-command)
                  (let ((status (mux-client-control
                                 fd (getf *options* :control-command)
                                 options extensions)))
                    (mux-close fd)
                    (finish status)))
                 ((and stdio (first stdio))
                  ;; ssh leaves stdio_forward_host NULL for a bare port, and
                  ;; muxclient() then takes its OPEN path instead, so an
                  ;; ordinary session is attached.
                  (let ((status
                          (mux-client-stdio-forward
                           fd (first stdio)
                           (if (third stdio)
                               +mux-port-streamlocal+
                               (second stdio)))))
                    (mux-close fd)
                    status))
                 (t
                  (if (mux-attach-forwards fd options)
                      (let* ((master-pid (mux-alive fd))
                             (request (mux-build-request
                                       options command command-given-p
                                       (not (null (getf *options* :subsystem)))))
                             (status (mux-client-session
                                      fd request :master-pid master-pid)))
                        (mux-close fd)
                        (if (eq status :refused)
                            ;; mux_client() returns -1 after a refused session
                            ;; request, so ssh(1) connects directly instead of
                            ;; giving up; do the same.
                            (values nil :session-refused)
                            status))
                      (progn
                        ;; mux_client_forwards() reports and returns -1, so
                        ;; ssh(1) falls back to a direct connection.
                        (log-error "muxclient: master forward request failed")
                        (mux-close fd)
                        (values nil :forward-refused))))))
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
      (cond
        (status (finish status))
        ((eq reason :session-refused)
         ;; The master answered and refused the session; ssh(1) then
         ;; connects directly, and a persistent master keeps running.
         nil)
        (t
         (ignore-errors (uiop:terminate-process process))
         (fail "the background control master is not accepting connections~@[: ~A~]"
               reason))))))

#-win32
(defun mux-prepare (host command command-given-p &optional options)
  "Attach to a master, or arrange for this client to become one.

Runs before the SSH connection is attempted, because a usable master makes
that connection unnecessary.  As in mux.c, only ControlMaster=no, auto and
autoask try an existing master; yes and ask go straight to listening, so a
second invocation cannot quietly join a master it was told to own.

OPTIONS is the already-resolved configuration when the caller needed it for
an earlier check, so the file is not read a second time."
  (let* ((options (or options (mux-config-options host)))
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
          (when (and (getf *options* :control-command)
                     (not (eq reason :hello-failed)))
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
