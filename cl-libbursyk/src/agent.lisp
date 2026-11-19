(in-package #:cl-pnet-ssh)

;;;; SSH agent client: the protocol OpenSSH and gpg-agent speak over
;;;; SSH_AUTH_SOCK.  It lists the identities the agent holds and asks the
;;;; agent to sign, so a passphrase-protected or hardware-backed key never
;;;; leaves the agent process.
;;;;
;;;; Every socket here is non-blocking and part of CL-PNET's event loop: a
;;;; connection is opened, written and read through FD-WATCH, so an agent
;;;; that is stopped, slow or missing cannot stall the other connections
;;;; sharing the loop.  One request uses one short-lived socket.

(defconstant +ssh-agent-failure+ 5)
(defconstant +ssh-agent-success+ 6)
(defconstant +ssh-agentc-request-identities+ 11)
(defconstant +ssh-agent-identities-answer+ 12)
(defconstant +ssh-agentc-sign-request+ 13)
(defconstant +ssh-agent-sign-response+ 14)

(defstruct (ssh-agent-call (:constructor %make-ssh-agent-call))
  (path nil)
  (fd nil)
  (outgoing nil)
  (sent 0)
  (incoming (make-array 0 :element-type '(unsigned-byte 8)
                          :adjustable t :fill-pointer 0))
  (phase :connecting)
  (read-watcher nil)
  (write-watcher nil)
  (on-response nil)
  (on-error nil)
  (done nil))

(defun ssh-agent-path (&optional explicit)
  "The agent socket to use.

EXPLICIT may be T for SSH_AUTH_SOCK or a path.  A missing socket is an
authentication error, not a protocol error: the caller asked for an agent
that is not there."
  (let ((path (if (eq explicit t)
                  (uiop:getenv "SSH_AUTH_SOCK")
                  explicit)))
    (or path
        (error 'ssh-authentication-error
               :detail "no ssh-agent: SSH_AUTH_SOCK is not set"))))

(defun ssh-agent-error (control &rest arguments)
  (make-condition 'ssh-authentication-error
                  :detail (apply #'format nil control arguments)))

(defun ssh-agent-call-close (call)
  "Close CALL's descriptor, if it is still open."
  (let ((fd (ssh-agent-call-fd call)))
    (when (and fd (>= fd 0))
      (cl-pnet-sockets:close-open-fd fd))
    (setf (ssh-agent-call-fd call) nil)))

(defun ssh-agent-call-unwatch (call)
  (when (ssh-agent-call-read-watcher call)
    (cl-pnet:fd-unwatch (ssh-agent-call-read-watcher call))
    (setf (ssh-agent-call-read-watcher call) nil))
  (when (ssh-agent-call-write-watcher call)
    (cl-pnet:fd-unwatch (ssh-agent-call-write-watcher call))
    (setf (ssh-agent-call-write-watcher call) nil)))

(defun ssh-agent-call-fail (call condition)
  "End CALL because of CONDITION, reporting it exactly once."
  (unless (ssh-agent-call-done call)
    (setf (ssh-agent-call-done call) t)
    (ssh-agent-call-unwatch call)
    (ssh-agent-call-close call)
    (funcall (ssh-agent-call-on-error call) condition)))

(defun ssh-agent-call-succeed (call response)
  "End CALL with RESPONSE, reporting it exactly once."
  (unless (ssh-agent-call-done call)
    (setf (ssh-agent-call-done call) t)
    (ssh-agent-call-unwatch call)
    (ssh-agent-call-close call)
    (funcall (ssh-agent-call-on-response call) response)))

(defun ssh-agent-watch-read (call)
  (unless (or (ssh-agent-call-read-watcher call)
              (ssh-agent-call-done call))
    (setf (ssh-agent-call-read-watcher call)
          (cl-pnet:fd-watch
           (ssh-agent-call-fd call)
           :on-readable
           (lambda (watcher)
             (declare (ignore watcher))
             (ssh-agent-readable call))))))

(defun ssh-agent-watch-write (call)
  (unless (or (ssh-agent-call-write-watcher call)
              (ssh-agent-call-done call))
    (setf (ssh-agent-call-write-watcher call)
          (cl-pnet:fd-watch
           (ssh-agent-call-fd call)
           :on-writable
           (lambda (watcher)
             (declare (ignore watcher))
             (ssh-agent-writable call))))))

(defun ssh-agent-unwatch-write (call)
  (when (ssh-agent-call-write-watcher call)
    (cl-pnet:fd-unwatch (ssh-agent-call-write-watcher call))
    (setf (ssh-agent-call-write-watcher call) nil)))

(defun ssh-agent-writable (call)
  "Finish a pending connect, then send whatever is left of the request."
  (unless (ssh-agent-call-done call)
    (if (eq (ssh-agent-call-phase call) :connecting)
        (multiple-value-bind (error connected)
            (cl-pnet-sockets:socket-error (ssh-agent-call-fd call))
          (cond
            ((not connected)
             (ssh-agent-call-fail
              call
              (ssh-agent-error "cannot check the ssh-agent connection: ~A"
                               (cl-pnet-sockets:c-strerror error))))
            ((zerop error)
             (ssh-agent-unwatch-write call)
             (setf (ssh-agent-call-phase call) :sending)
             (ssh-agent-write call))
            (t
             (ssh-agent-call-fail
              call
              (ssh-agent-error "cannot connect to the ssh-agent at ~A: ~A"
                               (ssh-agent-call-path call)
                               (cl-pnet-sockets:c-strerror error))))))
        (ssh-agent-write call))))

(defun ssh-agent-write (call)
  "Send CALL's request, waiting for writability when the socket is full."
  (let* ((outgoing (ssh-agent-call-outgoing call))
         (length (length outgoing))
         (sent (ssh-agent-call-sent call)))
    (loop while (< sent length)
          do (multiple-value-bind (result errno)
                 (cl-pnet-sockets:send-octets
                  (ssh-agent-call-fd call) outgoing :start sent)
               (cond
                 ((plusp result) (incf sent result))
                 ((member errno '(11 35))
                  (setf (ssh-agent-call-sent call) sent)
                  (ssh-agent-watch-write call)
                  (return))
                 (t
                  (ssh-agent-call-fail
                   call
                   (ssh-agent-error "cannot write to the ssh-agent: ~A"
                                    (cl-pnet-sockets:c-strerror errno)))
                  (return)))))
    (when (= sent length)
      (setf (ssh-agent-call-sent call) sent)
      (ssh-agent-unwatch-write call)
      (setf (ssh-agent-call-phase call) :reading)
      (ssh-agent-watch-read call))))

(defun ssh-agent-append-octets (call octets)
  (let ((incoming (ssh-agent-call-incoming call)))
    (loop for octet across octets
          do (vector-push-extend octet incoming))))

(defun ssh-agent-receive-some (call)
  "One read from CALL's socket.

Returns :CONTINUE after octets arrived, :WAIT when nothing is ready yet,
:CLOSED at EOF, or (:ERROR . ERRNO)."
  (multiple-value-bind (octets count errno)
      (cl-pnet-sockets:receive-octets (ssh-agent-call-fd call) 4096)
    (cond
      ((plusp count)
       (ssh-agent-append-octets call octets)
       :continue)
      ((zerop count) :closed)
      (t (if (member errno '(11 35))
             :wait
             (cons :error errno))))))

(defun ssh-agent-complete-message (call)
  "The reply payload once CALL's buffer holds a whole message, else NIL."
  (let ((incoming (ssh-agent-call-incoming call)))
    (when (>= (fill-pointer incoming) 4)
      (let ((length (ssh-octets-uint32 incoming)))
        (when (>= (fill-pointer incoming) (+ 4 length))
          (let ((response (subseq incoming 4 (+ 4 length))))
            (setf (fill-pointer incoming) 0)
            response))))))

(defun ssh-agent-readable (call)
  "Take every complete reply from CALL's socket."
  (unless (ssh-agent-call-done call)
    (loop
      (multiple-value-bind (kind detail)
          (ssh-agent-receive-some call)
        (cond
          ((eq kind :continue))
          ((eq kind :wait) (return))
          ((eq kind :closed)
           (ssh-agent-call-fail
            call
            (ssh-agent-error "the ssh-agent closed the connection"))
           (return))
          (t
           (ssh-agent-call-fail
            call
            (ssh-agent-error "cannot read from the ssh-agent: ~A"
                             (cl-pnet-sockets:c-strerror detail)))
           (return))))
      (let ((response (ssh-agent-complete-message call)))
        (when response
          (ssh-agent-call-succeed call response)
          (return))))))

(defun ssh-agent-start (call)
  "Open a non-blocking Unix socket to CALL's agent."
  (handler-case
      (multiple-value-bind (fd status)
          (cl-pnet-sockets:connect-unix (ssh-agent-call-path call))
        (cond
          ((null fd)
           (ssh-agent-call-fail
            call
            (ssh-agent-error "cannot connect to the ssh-agent at ~A: ~A"
                             (ssh-agent-call-path call)
                             (cl-pnet-sockets:c-strerror status))))
          (t
           (setf (ssh-agent-call-fd call) fd)
           (if (eq status :connected)
               (progn
                 (setf (ssh-agent-call-phase call) :sending)
                 (ssh-agent-write call))
               (ssh-agent-watch-write call)))))
    (error (condition)
      (ssh-agent-call-fail call condition))))

(defun ssh-agent-request (path payload on-response on-error)
  "Send PAYLOAD to the agent at PATH; call ON-RESPONSE with its one reply.

Asynchronous like the rest of the client: this returns at once, and the
callbacks run on the loop that owns PATH's socket.  PAYLOAD is the agent
message body; the protocol's length prefix is added here."
  (let ((call (%make-ssh-agent-call
               :path path
               :outgoing (ssh-concat (ssh-uint32-octets (length payload))
                                     payload)
               :on-response on-response
               :on-error on-error)))
    (ssh-agent-start call)
    call))

(defun ssh-agent-parse-identities (response)
  "The (KEY-BLOB . COMMENT) pairs in an identity response."
  (let* ((reader (ssh-make-reader response))
         (type (ssh-read-u8 reader)))
    (cond
      ((= type +ssh-agent-identities-answer+)
       (iter (for i below (ssh-read-u32 reader))
         (collect (cons (ssh-read-string reader)
                        (ssh-read-text reader)))))
      ((= type +ssh-agent-failure+)
       (error 'ssh-authentication-error
              :detail "the ssh-agent refused the identity request"))
      (t (error 'ssh-protocol-error
                :detail (format nil "unexpected ssh-agent reply ~D" type))))))

(defun ssh-agent-identities (&key path on-identities on-error)
  "Ask the agent at PATH for its identities, without blocking.

ON-IDENTITIES receives the (KEY-BLOB . COMMENT) pairs; ON-ERROR receives an
ssh-authentication-error when the agent cannot be reached or refuses."
  (handler-case
      (let ((writer (ssh-writer)))
        (ssh-write-u8 writer +ssh-agentc-request-identities+)
        (ssh-agent-request
         (ssh-agent-path path)
         (ssh-writer-output writer)
         (lambda (response)
           (handler-case
               (funcall on-identities (ssh-agent-parse-identities response))
             (error (condition) (funcall on-error condition))))
         on-error))
    (error (condition) (funcall on-error condition))))

(defun ssh-agent-parse-sign (response)
  "The signature blob in a sign response."
  (let* ((reader (ssh-make-reader response))
         (type (ssh-read-u8 reader)))
    (cond
      ((= type +ssh-agent-sign-response+) (ssh-read-string reader))
      ((= type +ssh-agent-failure+)
       (error 'ssh-authentication-error
              :detail "the ssh-agent refused to sign"))
      (t (error 'ssh-protocol-error
                :detail (format nil "unexpected ssh-agent reply ~D" type))))))

(defun ssh-agent-sign (key-blob data &key path flags on-signature on-error)
  "Ask the agent at PATH to sign DATA with KEY-BLOB, without blocking.

ON-SIGNATURE receives the SSH signature blob.  FLAGS selects an algorithm
for key types that have more than one (RSA: 2 for rsa-sha2-256, 4 for
rsa-sha2-512); ed25519 uses 0."
  (handler-case
      (let ((writer (ssh-writer)))
        (ssh-write-u8 writer +ssh-agentc-sign-request+)
        (ssh-write-string writer key-blob)
        (ssh-write-string writer data)
        (ssh-write-u32 writer (or flags 0))
        (ssh-agent-request
         (ssh-agent-path path)
         (ssh-writer-output writer)
         (lambda (response)
           (handler-case
               (funcall on-signature (ssh-agent-parse-sign response))
             (error (condition) (funcall on-error condition))))
         on-error))
    (error (condition) (funcall on-error condition))))
