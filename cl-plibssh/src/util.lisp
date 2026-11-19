(in-package #:cl-pnet-ssh)

;;;; State shared by the libssh client and server roles, plus the small
;;;; helpers that talk to libssh and to CL-PNET's event loop.
;;;;
;;;; The public structures keep the same names and accessors as the pure
;;;; backend, so callers and the tests do not know which one is selected.

;;; ---- Client state ----

(defstruct (ssh-client (:constructor %make-ssh-client))
  host
  connect-host
  (port 22)
  connect-port
  (user nil)
  session
  (fd nil)
  watcher
  write-watcher
  (phase :connecting)
  (channels (make-hash-table :test #'eql))
  (next-channel-id 0)
  private-key
  agent
  passphrase
  known-hosts
  (host-key-policy :strict)
  host-key-blob
  server-version
  (key-handles nil)
  (key-index 0)
  (auth-key nil)
  (agent-tried nil)
  on-open
  on-error
  on-close
  ;; The resolved ssh_config this client was built from, if any.
  config-options
  (closed nil)
  close-reason)

(defstruct (ssh-channel (:constructor %make-ssh-channel))
  client
  handle
  local-id
  (remote-id nil)
  (type "session")
  (state :queued)
  target-host
  target-port
  (origin-address "0.0.0.0")
  (origin-port 0)
  (write-queue (make-array 0 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))
  (write-callbacks nil)
  (requests nil)
  (request-active nil)
  (eof-received nil)
  (exit-status 0)
  (exit-signal nil)
  (exit-reported nil)
  (eof-reported nil)
  (sent-eof nil)
  (want-eof nil)
  (sent-close nil)
  (want-close nil)
  (close-reported nil)
  on-data
  on-eof
  on-exit
  on-close
  on-error)

;;; ---- Server state ----

(defstruct (ssh-server (:constructor %make-ssh-server))
  (address "0.0.0.0")
  (port 22)
  listener
  watcher
  bind
  host-key
  authorized-keys
  authorize
  (accept-env nil)
  (on-session nil)
  (on-channel nil)
  (on-direct-tcpip nil)
  (on-error nil)
  (on-close nil)
  (sessions (make-hash-table :test #'eq))
  (closed nil))

(defstruct (ssh-session (:constructor %make-ssh-session))
  server
  handle
  (fd nil)
  watcher
  write-watcher
  remote-address
  (phase :key-exchange)
  (client-version nil)
  (user nil)
  (authenticated nil)
  (channels (make-hash-table :test #'eql))
  (next-channel-id 0)
  (closed nil)
  close-reason)

(defstruct (ssh-server-channel (:constructor %make-ssh-server-channel))
  session
  handle
  local-id
  (remote-id nil)
  (type "session")
  (state :opening)
  remote-address
  target
  (command nil)
  (env nil)
  (write-queue (make-array 0 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))
  (stderr-queue (make-array 0 :element-type '(unsigned-byte 8)
                              :adjustable t :fill-pointer 0))
  (write-callbacks nil)
  (eof-received nil)
  (exit-status nil)
  (exit-sent nil)
  (eof-reported nil)
  (close-reported nil)
  (sent-eof nil)
  (want-eof nil)
  (sent-close nil)
  (want-close nil)
  on-data
  on-eof
  on-exec
  on-close
  on-error)

;;; ---- Small octets helpers ----

(defun ssh-plibssh-error (session)
  "libssh's last error text for SESSION, never NIL."
  (or (ssh-get-error session) "unknown libssh error"))

(defun ssh-plibssh-null-p (pointer)
  "Whether POINTER is a null foreign pointer.

CFFI's null pointer is an object, not NIL, so a bare UNLESS on a pointer
that libssh failed to allocate takes the success branch.  Every pointer
libssh returns goes through this test instead."
  (or (null pointer) (cffi:null-pointer-p pointer)))

(defun ssh-plibssh-buffer-append (buffer data)
  "Append DATA to the adjustable octet BUFFER."
  (iter (for octet in-vector data)
    (vector-push-extend octet buffer))
  buffer)

(defun ssh-plibssh-buffer-drop (buffer count)
  "Drop the first COUNT octets of BUFFER."
  (when (plusp count)
    (replace buffer buffer :start1 0 :start2 count)
    (decf (fill-pointer buffer) count))
  buffer)

(defun ssh-plibssh-write-octets (function data start count)
  "Copy COUNT octets of DATA from START into a foreign buffer and call FUNCTION.

FUNCTION receives (BUFFER COUNT) and must return libssh's byte count."
  (cffi:with-foreign-object (buffer :unsigned-char count)
    (iter (for i below count)
      (setf (cffi:mem-aref buffer :unsigned-char i)
            (aref data (+ start i))))
    (funcall function buffer count)))

(defun ssh-plibssh-fill-octets (buffer count)
  "The first COUNT octets of foreign BUFFER as a fresh simple vector."
  (let ((octets (make-array count :element-type '(unsigned-byte 8))))
    (iter (for i below count)
      (setf (aref octets i) (cffi:mem-aref buffer :unsigned-char i)))
    octets))

;;; ---- Options ----

(defun ssh-plibssh-set-string-option (session code value)
  "ssh_options_set SESSION CODE to the string VALUE."
  (cffi:with-foreign-string (pointer (princ-to-string value))
    (ssh-options-set session code pointer)))

(defun ssh-plibssh-set-int-option (session code value)
  "ssh_options_set SESSION CODE to the integer VALUE."
  (cffi:with-foreign-object (pointer :uint)
    (setf (cffi:mem-ref pointer :uint) value)
    (ssh-options-set session code pointer)))

(defun ssh-plibssh-bind-string-option (bind code value)
  (cffi:with-foreign-string (pointer (princ-to-string value))
    (ssh-bind-options-set bind code pointer)))

(defun ssh-plibssh-bind-int-option (bind code value)
  (cffi:with-foreign-object (pointer :uint)
    (setf (cffi:mem-ref pointer :uint) value)
    (ssh-bind-options-set bind code pointer)))

(defun ssh-plibssh-public-key-blob (key)
  "KEY as the SSH wire blob, or NIL.
libssh exports the blob as base64, the same text a public key file holds."
  (cffi:with-foreign-object (pointer :pointer)
    (when (zerop (ssh-pki-export-pubkey-base64 key pointer))
      (let ((base64 (cffi:mem-ref pointer :pointer)))
        (unwind-protect
             (ssh-base64-octets
              (cffi:foreign-string-to-lisp base64))
          (ssh-string-free-char base64))))))

;;; ---- Event-loop watchers ----

(defun ssh-plibssh-set-nonblocking (fd)
  "Keep FD non-blocking.
libssh's socket callback clears O_NONBLOCK when it sees the first POLLOUT
on a socket it did not create, so this is repeated after every pump."
  (cl-pnet-sockets:set-nonblocking fd)
  fd)
