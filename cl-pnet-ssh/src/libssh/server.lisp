(in-package #:cl-pnet-ssh)

;;;; The libssh server role.  The listening socket, the accepted descriptors
;;;; and all data are owned here; libssh only runs the protocol on a descriptor
;;;; it is handed.  That keeps accept(2) off the blocking DNS/connect path and
;;;; lets the event loop decide when a session may make progress.
;;;;
;;;; Each call that can wait is called from a descriptor watch.  A call that
;;;; would wait returns SSH_AGAIN and the watch comes back when the socket
;;;; moves, exactly as on the client side.

(defun ssh-plibssh-listen (address port &key v6only family)
  "Bind and listen on ADDRESS:PORT, returning a non-blocking descriptor.

FAMILY and V6ONLY mirror the pure backend's listener: a name is resolved
within FAMILY, and an IPv6 wildcard with V6ONLY refuses IPv4 clients instead
of accepting them through the dual-stack socket."
  (multiple-value-bind (bind-address bind-family)
      (cl-pnet-sockets:resolve-bind-address address :family family)
    (unless bind-address
      (error 'ssh-connection-error
             :detail (format nil "not an address: ~A" address)))
    (let ((fd (cl-pnet-sockets:c-socket
               (if (eq bind-family :inet6)
                   cl-pnet-sockets:+af-inet6+
                   cl-pnet-sockets:+af-inet+)
               cl-pnet-sockets:+sock-stream+
               cl-pnet-sockets:+ipproto-tcp+)))
      (when (minusp fd)
        (error 'ssh-connection-error
               :detail (format nil "could not make a socket (~A)"
                               (cl-pnet-sockets:c-strerror
                                (cl-pnet-sockets:c-errno)))))
      (flet ((fail (detail)
               (cl-pnet-sockets:c-close fd)
               (error 'ssh-connection-error :detail detail)))
        ;; Best effort: a refused REUSEADDR must not stop a listener from
        ;; binding a fresh port, only a restart from reusing a fresh one.
        (cl-pnet-sockets:set-socket-option
         fd cl-pnet-sockets:+sol-socket+ cl-pnet-sockets:+so-reuseaddr+ 1)
        (when (and v6only (eq bind-family :inet6))
          (cl-pnet-sockets:set-socket-option
           fd cl-pnet-sockets:+ipproto-ipv6+
           cl-pnet-sockets:+ipv6-v6only+ 1))
        (multiple-value-bind (sockaddr length)
            (cl-pnet-sockets:make-sockaddr bind-address port)
          (unless sockaddr
            (fail (format nil "not an address: ~A" address)))
          (let ((result (cl-pnet-sockets:c-bind fd sockaddr length)))
            (cffi:foreign-free sockaddr)
            (when (minusp result)
              (fail (format nil "could not bind ~A:~D (~A)"
                            address port
                            (cl-pnet-sockets:c-strerror
                             (cl-pnet-sockets:c-errno)))))))
        (when (minusp (cl-pnet-sockets:c-listen fd 128))
          (fail (format nil "could not listen on ~A:~D (~A)"
                        address port
                        (cl-pnet-sockets:c-strerror
                         (cl-pnet-sockets:c-errno)))))
        (cl-pnet-sockets:set-nonblocking fd)
        fd))))

(defun ssh-plibssh-bound-port (fd)
  "The port FD is actually bound to; needed when the caller asked for zero."
  (cffi:with-foreign-objects
      ((address '(:struct cl-pnet-sockets:sockaddr-in6))
       (length :unsigned-int))
    (setf (cffi:mem-ref length :unsigned-int)
          cl-pnet-sockets:+sockaddr-in6-size+)
    (when (>= (cl-pnet-sockets:c-getsockname fd address length) 0)
      (multiple-value-bind (ip port)
          (cl-pnet-sockets:sockaddr-to-string address)
        (declare (ignore ip))
        port))))

(defun ssh-plibssh-peer-address (fd)
  "FD's peer as (:ADDRESS IP :PORT PORT), the shape CL-PNET reports."
  (cffi:with-foreign-objects
      ((address '(:struct cl-pnet-sockets:sockaddr-in6))
       (length :unsigned-int))
    (setf (cffi:mem-ref length :unsigned-int)
          cl-pnet-sockets:+sockaddr-in6-size+)
    (when (>= (cl-pnet-sockets:c-getpeername fd address length) 0)
      (multiple-value-bind (ip port)
          (cl-pnet-sockets:sockaddr-to-string address)
        (when ip (list :address ip :port port))))))

;;; ---- Sessions ----

(defun ssh-plibssh-session-channels (session)
  (iter (for (id channel) in-hashtable (ssh-session-channels session))
    (declare (ignore id))
    (collect channel)))

(defun ssh-plibssh-session-write-descriptor (session)
  "SESSION's descriptor for the writable watcher, duplicated on first use."
  (or (ssh-session-write-fd session)
      (setf (ssh-session-write-fd session)
            (ssh-plibssh-dup-fd (ssh-session-fd session)))))

(defun ssh-plibssh-session-sync-watchers (session)
  "Arm the write watch exactly when libssh has bytes it could not send."
  (let ((watcher (ssh-session-write-watcher session))
        (handle (ssh-session-handle session))
        (fd (ssh-session-fd session)))
    (if (and handle fd (not (ssh-session-closed session))
             (logtest (ssh-get-poll-flags handle) +ssh-write-pending+))
        (unless watcher
          (setf (ssh-session-write-watcher session)
                (cl-pnet:fd-watch
                 (ssh-plibssh-session-write-descriptor session)
                 :on-writable
                 (lambda (watcher)
                   (declare (ignore watcher))
                   (ssh-plibssh-session-pump session)))))
        (when watcher
          (setf (ssh-session-write-watcher session) nil)
          (cl-pnet:fd-unwatch watcher)))))

(defun ssh-plibssh-session-pump (session)
  "Advance SESSION as far as its descriptor allows."
  (when (and (ssh-session-handle session)
             (not (ssh-session-closed session)))
    (ssh-session-note-input session)
    (handler-case
        (progn
          (case (ssh-session-phase session)
            (:key-exchange (ssh-plibssh-session-drive-key-exchange session))
            (:authenticating (ssh-plibssh-session-drive-messages session))
            (:ready (ssh-plibssh-session-drive-messages session))
            (:closed nil))
          (unless (ssh-session-closed session)
            (ssh-plibssh-session-sync-watchers session)))
      (error (condition)
        (ssh-session-fail session condition)))))

(defun ssh-plibssh-session-drive-key-exchange (session)
  "Run SSH_HANDLE_KEY_EXCHANGE until the handshake completes."
  (let ((rc (ssh-handle-key-exchange (ssh-session-handle session))))
    (cond
      ((zerop rc)
       (setf (ssh-session-phase session) :authenticating
             (ssh-session-client-version session)
             (ssh-get-clientbanner (ssh-session-handle session)))
       (ssh-plibssh-session-drive-messages session))
      ((= rc +ssh-again+) nil)
      (t
       (error 'ssh-connection-error
              :detail (format nil "SSH handshake failed: ~A"
                              (ssh-plibssh-error (ssh-session-handle session))))))))

(defun ssh-plibssh-session-drive-messages (session)
  "Drain every request libssh has, then move any channel's bytes."
  (loop
    (when (ssh-session-closed session) (return))
    (let ((message (ssh-message-get (ssh-session-handle session))))
      (when (ssh-plibssh-null-p message)
        (unless (plusp (ssh-is-connected (ssh-session-handle session)))
          (ssh-session-finish session :peer-closed :close))
        (return))
      (unwind-protect
           (ssh-plibssh-session-handle-message session message)
        (ssh-message-free message))
      ;; A policy refusal decided inside the callback (MaxAuthTries) takes
      ;; effect now, with libssh no longer holding the message.
      (let ((reason (ssh-session-pending-close session)))
        (when reason
          (setf (ssh-session-pending-close session) nil)
          (ssh-session-finish session reason :close)
          (return)))))
  (when (and (not (ssh-session-closed session))
             (eq (ssh-session-phase session) :ready))
    (iter (for channel in (ssh-plibssh-session-channels session))
      (ssh-plibssh-server-channel-drive channel))
    (unless (or (ssh-session-closed session)
                (plusp (ssh-is-connected (ssh-session-handle session))))
      (ssh-session-finish session :peer-closed :close))))

(defun ssh-plibssh-session-handle-message (session message)
  "Dispatch one libssh request."
  (let ((type (ssh-message-type message)))
    (cond
      ((= type +ssh-request-auth+)
       (ssh-plibssh-session-handle-auth session message))
      ((= type +ssh-request-service+)
       (ssh-message-reply-default message))
      ((and (= type +ssh-request-channel-open+)
            (eq (ssh-session-phase session) :ready))
       (ssh-plibssh-session-handle-open session message))
      ((and (= type +ssh-request-channel+)
            (eq (ssh-session-phase session) :ready))
       (ssh-plibssh-session-handle-channel-request session message))
      (t (ssh-message-reply-default message)))))

;;; ---- Authentication ----

;;; ---- Account policy helpers shared with the pure backend's API ----
;;;
;;; The pure backend defines these in CL-LIBBURSKY's server files, which a
;;; :ssh-backend-ffi build does not compile.  The names are part of the public
;;; server API either way, so this backend carries its own copies.

(defun ssh-server-auth-failure-counts-p (attempt method)
  "Whether a failed ATTEMPT using METHOD counts toward MaxAuthTries.

sshd exempts the first \"none\" probe every client sends to learn the
allowed methods; everything after it counts."
  (or (/= 1 attempt)
      (not (string= method "none"))))

(defun ssh-server-session-channel-count (session)
  "How many session channels SESSION still has open or opening."
  (loop for channel being the hash-values of (ssh-session-channels session)
        counting (and (string= (ssh-server-channel-type channel) "session")
                      (not (eq (ssh-server-channel-state channel) :closed)))))

(defun ssh-server-user-permitted-p (session user)
  "Whether the application admits USER on SESSION, cached per name.

The connection's Match blocks are resolved first, as sshd's getpwnamallow
does, so the hook sees the per-connection values."
  (ssh-session-resolve-config session user)
  (let ((hook (ssh-server-authorize-user (ssh-session-server session))))
    (if (null hook)
        t
        (let ((cached (assoc user (ssh-session-allowed-users session)
                             :test #'string=)))
          (if cached
              (cdr cached)
              (let ((allowed (and (funcall hook session user) t)))
                (push (cons user allowed)
                      (ssh-session-allowed-users session))
                allowed))))))

(defun ssh-server-banner-text (server)
  "The Banner text SERVER should send now, or NIL."
  (let ((banner (ssh-server-banner server)))
    (when banner
      (let ((text (if (functionp banner) (funcall banner) banner)))
        (when (and text (plusp (length text)))
          text)))))

(defun ssh-plibssh-session-send-banner-text (session text)
  "Send TEXT to SESSION as a USERAUTH_BANNER, or do nothing when empty."
  (when (and text (plusp (length text)))
    (let* ((octets (ssh-string-octets text))
           (string (ssh-string-new (length octets))))
      (unwind-protect
           (progn
             (cffi:with-pointer-to-vector-data (pointer octets)
               (ssh-string-fill string pointer (length octets)))
             (ssh-send-issue-banner (ssh-session-handle session) string))
        (ssh-string-free string)))))

(defun ssh-plibssh-session-send-banner (session)
  "Send the configured Banner, as sshd does on the first auth request."
  (ssh-plibssh-session-send-banner-text session (ssh-session-banner-text session)))

(defun ssh-plibssh-allowed-auth-methods (session)
  "The methods SESSION may try next, as sshd's authmethods_get reports.

An impossible AuthenticationMethods setting leaves no method, which makes
every attempt fail rather than quietly falling back to publickey.  Hostbased
is removed because libssh exposes no userauth API for it; advertising a
method this backend cannot complete would be a lie."
  (let ((lists (ssh-session-auth-method-lists session)))
    (remove
     "hostbased"
     (cond
       ((eq lists :impossible) '())
       ((null lists) (ssh-server-enabled-auth-methods session))
       (t (remove-duplicates (mapcar #'first lists) :test #'string=)))
     :test #'string=)))

(defun ssh-plibssh-auth-method-bit (name)
  "libssh's bit for the SSH method name NAME, or 0 when it has none."
  (cond
    ((string= name "publickey") +ssh-auth-method-publickey+)
    ((string= name "password") +ssh-auth-method-password+)
    ((string= name "keyboard-interactive") +ssh-auth-method-interactive+)
    ((string= name "hostbased") +ssh-auth-method-hostbased+)
    (t 0)))

(defun ssh-plibssh-auth-methods-bits (session)
  "libssh's bitmask for the methods SESSION can still complete."
  (let ((bits 0))
    (dolist (name (ssh-plibssh-allowed-auth-methods session))
      (setf bits (logior bits (ssh-plibssh-auth-method-bit name))))
    bits))

(defun ssh-plibssh-auth-failure (session message)
  "Refuse a request, advertising the methods SESSION can still complete."
  (ssh-message-auth-set-methods message (ssh-plibssh-auth-methods-bits session))
  (ssh-message-reply-default message))

(defun ssh-plibssh-session-partial-failure (session message)
  "Report that one AuthenticationMethods entry is done, not the login.

RFC 4252 carries this as USERAUTH_FAILURE with the partial-success flag, and
the method list still names what the client must do next.  It does not count
toward MaxAuthTries, as sshd does not count a completed entry."
  (ssh-message-auth-set-methods message (ssh-plibssh-auth-methods-bits session))
  (ssh-message-auth-reply-success message 1))

(defun ssh-plibssh-session-auth-failure (session message &key (count t))
  "Refuse one userauth attempt, counting it toward MaxAuthTries when COUNT.

A limit reached inside a libssh callback cannot close the session there, so
the reason is recorded and the pump finishes it after the callback returns."
  (when count
    (incf (ssh-session-auth-failures session))
    (when (>= (ssh-session-auth-failures session)
              (or (ssh-session-setting
                   session #'ssh-server-config-max-auth-tries)
                  (ssh-server-max-auth-tries (ssh-session-server session))))
      (setf (ssh-session-pending-close session) :auth-failures)))
  (ssh-plibssh-auth-failure session message))

(defun ssh-plibssh-session-auth-key-used-p (session key-blob)
  "Whether KEY-BLOB already completed a method on SESSION."
  (some (lambda (used) (ssh-octets= used key-blob))
        (ssh-session-auth-used-keys session)))

(defun ssh-plibssh-session-record-auth-success (session method key-blob)
  "Record METHOD with KEY-BLOB and add its ExposeAuthInfo line.

Password and keyboard-interactive carry no key, so they neither consume a key
nor contribute an auth-info line."
  (when key-blob
    (push key-blob (ssh-session-auth-used-keys session)))
  (let ((line (ssh-server-auth-info-line method key-blob)))
    (when line
      (setf (ssh-session-auth-info-lines session)
            (append (ssh-session-auth-info-lines session) (list line))))))

(defun ssh-plibssh-session-auth-method-succeeded
    (session message user method key-blob key-env authorization)
  "Record one successful method and either finish or ask for the next.

Without AuthenticationMethods this is the whole login.  With it, METHOD is
removed from the front of every remaining list; a list that becomes empty
finishes the login, and otherwise the client is told the method was a partial
success.  Options from all successful keys are merged, and a key already used
for a method is never accepted again."
  (let ((lists (ssh-session-auth-method-lists session)))
    (cond
      ((eq lists :impossible)
       (ssh-plibssh-session-auth-failure session message))
      ((null lists)
       (ssh-plibssh-session-record-auth-success session method key-blob)
       (ssh-plibssh-session-complete-auth
        session message user method key-blob key-env authorization))
      ((not (some (lambda (list)
                    (and list (string= (first list) method)))
                  lists))
       ;; No remaining list starts with this method; do not advance.
       (ssh-plibssh-session-auth-failure session message))
      (t
       (let* ((empty (ssh-certificate-authorization-options-empty))
              (merged (ssh-authorization-options-merge
                       (or (ssh-session-auth-merged-options session) empty)
                       (or authorization empty))))
         (unless merged
           ;; Inconsistent options, such as two different force-commands.
           (ssh-plibssh-session-auth-failure session message)
           (return-from ssh-plibssh-session-auth-method-succeeded nil))
         (let ((remaining (mapcar #'rest lists)))
           (ssh-plibssh-session-record-auth-success session method key-blob)
           (setf (ssh-session-auth-merged-options session) merged
                 (ssh-session-auth-merged-key-env session)
                 (append (ssh-session-auth-merged-key-env session) key-env))
           (if (some #'null remaining)
               (ssh-plibssh-session-complete-auth
                session message user method key-blob
                (ssh-session-auth-merged-key-env session) merged)
               (progn
                 (setf (ssh-session-auth-method-lists session) remaining)
                 (ssh-plibssh-session-partial-failure session message)))))))))

(defun ssh-plibssh-session-complete-auth
    (session message user method key-blob key-env authorization)
  "Accept USER for SESSION, then let the application run.

METHOD names the userauth method that completed, KEY-BLOB is its key when
the method has one, KEY-ENV holds the environment= assignments from the
authorized_keys line, and AUTHORIZATION the rest of that line's options.
The auth-info lines were recorded by SSH-PLIBSSH-SESSION-AUTH-METHOD-SUCCEEDED."
  (setf (ssh-session-user session) user
        (ssh-session-authorized-key session) key-blob
        (ssh-session-key-env session) key-env
        (ssh-session-authorization session) authorization)
  (let ((hook (ssh-server-authorize-login (ssh-session-server session))))
    (when (and hook (not (funcall hook session user)))
      (ssh-message-reply-default message)
      (ssh-session-finish session "Access denied" :close)
      (return-from ssh-plibssh-session-complete-auth nil)))
  ;; Login messages a pre-success hook collected -- PAM account text -- go
  ;; out as a banner before USERAUTH_SUCCESS, as in sshd.
  (let ((messages (ssh-session-login-messages session)))
    (when messages
      (ssh-plibssh-session-send-banner-text
       session
       (with-output-to-string (stream)
         (dolist (text (nreverse messages))
           (write-string text stream)
           (terpri stream))))))
  (setf (ssh-session-authenticated session) t
        (ssh-session-phase session) :ready)
  (setf (ssh-session-login-grace-timer session)
        (ssh-session-cancel-timer (ssh-session-login-grace-timer session)))
  (ssh-message-auth-reply-success message 0)
  (ssh-session-start-client-alive-timer session)
  (when (ssh-server-on-session (ssh-session-server session))
    (funcall (ssh-server-on-session (ssh-session-server session)) session))
  ;; sshd starts UnusedConnectionTimeout once authentication finishes.
  (ssh-session-note-channel-change session))

(defun ssh-plibssh-send-info-request (message name instruction prompts)
  "Send one keyboard-interactive INFO_REQUEST for PROMPTS.

PROMPTS is a list of (TEXT ECHO-P).  The strings and arrays libssh needs are
freed as soon as the request is queued."
  (let* ((count (length prompts))
         (strings (cffi:foreign-alloc :pointer :count (max count 1)))
         (echo (cffi:foreign-alloc :char :count (max count 1)))
         (allocated '()))
    (unwind-protect
         (progn
           (loop for prompt in prompts
                 for index from 0
                 do (let ((text (cffi:foreign-string-alloc
                                 (or (first prompt) ""))))
                      (push text allocated)
                      (setf (cffi:mem-aref strings :pointer index) text)
                      (setf (cffi:mem-aref echo :char index)
                            (if (second prompt) 1 0))))
           (not (minusp
                 (ssh-message-auth-interactive-request
                  message (or name "") (or instruction "")
                  count strings echo))))
      (dolist (text allocated)
        (cffi:foreign-string-free text))
      (cffi:foreign-free strings)
      (cffi:foreign-free echo))))

(defun ssh-plibssh-session-kbdint-result (session message user result)
  "Act on the keyboard-interactive hook's RESULT for USER."
  (cond
    ((or (eq result :success) (eq result t))
     (setf (ssh-session-kbd-interactive-pending session) nil)
     (ssh-plibssh-session-auth-method-succeeded
      session message user "keyboard-interactive" nil nil nil))
    ((or (null result) (eq result :failure))
     (setf (ssh-session-kbd-interactive-pending session) nil)
     (ssh-plibssh-session-auth-failure session message))
    (t
     (let ((prompts (getf result :prompts))
           (name (getf result :name))
           (instruction (getf result :instruction)))
       ;; A round may carry text and no prompts, which sshd sends for
       ;; PAM_TEXT_INFO/PAM_ERROR_MSG; the client answers with an empty
       ;; INFO_RESPONSE.  A round with nothing at all would spin.
       (unless (or prompts
                   (and name (plusp (length name)))
                   (and instruction (plusp (length instruction))))
         (setf (ssh-session-kbd-interactive-pending session) nil)
         (ssh-plibssh-session-auth-failure session message)
         (return-from ssh-plibssh-session-kbdint-result nil))
       (if (ssh-plibssh-send-info-request message name instruction prompts)
           (setf (ssh-session-kbd-interactive-pending session) t)
           (progn
             (setf (ssh-session-kbd-interactive-pending session) nil)
             (ssh-plibssh-session-auth-failure session message)))))))

(defun ssh-plibssh-session-handle-kbdint (session message user count)
  "Start a keyboard-interactive exchange for USER."
  (let ((hook (ssh-server-authorize-keyboard-interactive
               (ssh-session-server session))))
    (if (null hook)
        (ssh-plibssh-session-auth-failure session message :count count)
        (progn
          (setf (ssh-session-kbd-interactive-user session) user
                (ssh-session-kbd-interactive-pending session) t)
          (ssh-plibssh-session-kbdint-result
           session message user
           (funcall hook session user (list :responses '())))))))

(defun ssh-plibssh-session-handle-kbdint-response (session message)
  "Feed one keyboard-interactive INFO_RESPONSE back to the hook."
  (unless (ssh-session-kbd-interactive-pending session)
    (ssh-plibssh-session-auth-failure session message)
    (return-from ssh-plibssh-session-handle-kbdint-response nil))
  (let* ((handle (ssh-session-handle session))
         (count (ssh-userauth-kbdint-getnanswers handle))
         (answers '()))
    (when (minusp count)
      (setf (ssh-session-kbd-interactive-pending session) nil)
      (ssh-plibssh-session-auth-failure session message)
      (return-from ssh-plibssh-session-handle-kbdint-response nil))
    (dotimes (index count)
      (declare (ignore index))
      (let ((answer (ssh-userauth-kbdint-getanswer
                     handle (length answers))))
        (push (or answer "") answers)))
    (let ((hook (ssh-server-authorize-keyboard-interactive
                 (ssh-session-server session)))
          (user (ssh-session-kbd-interactive-user session)))
      (if (null hook)
          (progn
            (setf (ssh-session-kbd-interactive-pending session) nil)
            (ssh-plibssh-session-auth-failure session message))
          (ssh-plibssh-session-kbdint-result
           session message user
           (funcall hook session user (list :responses (nreverse answers))))))))

(defun ssh-plibssh-session-handle-password (session message user count)
  "Accept one password attempt when the application's hook admits it.

libssh discards the RFC 4252 change-password boolean before handing the
message over, so a client that asks to change its password is treated as an
ordinary login attempt; ssh's own client never sets that flag."
  (let ((hook (ssh-server-authorize-password (ssh-session-server session)))
        (password (ssh-message-auth-password message)))
    (if (and hook password (funcall hook session user password))
        (ssh-plibssh-session-auth-method-succeeded
         session message user "password" nil nil nil)
        (ssh-plibssh-session-auth-failure session message :count count))))

(defun ssh-plibssh-session-handle-auth (session message)
  "Answer one USER AUTH REQUEST from MESSAGE."
  (let ((method (ssh-message-subtype message)))
    ;; An INFO_RESPONSE is the continuation of the exchange, not a new
    ;; attempt: it carries no username and must not count against MaxAuthTries.
    (when (and (= method +ssh-auth-method-interactive+)
               (plusp (ssh-message-auth-kbdint-is-response message)))
      (return-from ssh-plibssh-session-handle-auth
        (ssh-plibssh-session-handle-kbdint-response session message)))
    (let ((user (ssh-message-auth-user message)))
      (setf (ssh-session-user session) user)
      (when (zerop (ssh-session-auth-attempts session))
        ;; Resolve Match blocks once the account name is known, before the
        ;; Banner they may choose, as sshd's getpwnamallow does.
        (ssh-session-resolve-config session user)
        (ssh-plibssh-session-send-banner session))
      ;; RefuseConnection is checked once the account is known, before any
      ;; method runs, as sshd's monitor does after getpwnamallow.
      (when (eq (ssh-session-setting
                 session #'ssh-server-config-refuse-connection)
                :yes)
        (setf (ssh-session-refused-p session) t
              (ssh-session-pending-close session) :refused)
        (return-from ssh-plibssh-session-handle-auth nil))
      (incf (ssh-session-auth-attempts session))
      ;; A new USER AUTH REQUEST abandons any half-finished kbdint exchange.
      (setf (ssh-session-kbd-interactive-pending session) nil)
      (let* ((method-name
               (cond ((= method +ssh-auth-method-none+) "none")
                     ((= method +ssh-auth-method-publickey+) "publickey")
                     ((= method +ssh-auth-method-password+) "password")
                     ((= method +ssh-auth-method-interactive+)
                      "keyboard-interactive")
                     ((= method +ssh-auth-method-hostbased+) "hostbased")
                     (t "other")))
             (count (ssh-server-auth-failure-counts-p
                     (ssh-session-auth-attempts session)
                     method-name)))
        (cond
          ((not (ssh-server-user-permitted-p session user))
           (ssh-plibssh-session-auth-failure session message :count count))
          ((not (member method-name
                        (ssh-plibssh-allowed-auth-methods session)
                        :test #'string=))
           (ssh-plibssh-session-auth-failure session message :count count))
          ((= method +ssh-auth-method-none+)
           (ssh-plibssh-session-auth-failure session message :count count))
          ((= method +ssh-auth-method-publickey+)
           (ssh-plibssh-session-handle-publickey session message user count))
          ((= method +ssh-auth-method-password+)
           (ssh-plibssh-session-handle-password session message user count))
          ((= method +ssh-auth-method-interactive+)
           (ssh-plibssh-session-handle-kbdint session message user count))
          (t (ssh-plibssh-session-auth-failure session message :count count)))))))

(defun ssh-server-max-pubkey-ok (session)
  "SESSION's PubkeyAuthOptions max-pk-ok budget, defaulting to sshd's 6."
  (or (ssh-session-setting session #'ssh-server-config-max-pubkey-ok) 6))

(defun ssh-server-publickey-offer-counts-p (session)
  "Record a rejected unsigned publickey probe and say whether it counts.

The first MAX-PK-OK probes do not count against MaxAuthTries, so a client can
test keys without burning its authentication budget; later ones do."
  (incf (ssh-session-pk-ok-failures session))
  (> (ssh-session-pk-ok-failures session)
     (ssh-server-max-pubkey-ok session)))

(defun ssh-plibssh-session-publickey-failure (session message signed count)
  "Refuse a publickey attempt, applying the probe budget only to offers."
  (if signed
      (ssh-plibssh-session-auth-failure session message :count count)
      (ssh-plibssh-session-auth-failure
       session message
       :count (and (ssh-server-publickey-offer-counts-p session)
                   count))))

(defun ssh-plibssh-session-handle-publickey (session message user
                                            &optional (count t))
  "Handle a publickey offer (state NONE) or a signed attempt (state VALID).

COUNT is false for an accepted offer, which sshd does not treat as a failed
authentication attempt."
  (let* ((key (ssh-message-auth-pubkey message))
         (state (ssh-message-auth-publickey-state message))
         (blob (and key (ssh-plibssh-public-key-blob key)))
         (authorized nil)
         (key-env nil)
         (authorization nil)
         (signed (= state +ssh-publickey-state-valid+)))
    (when blob
      (multiple-value-setq (authorized key-env authorization)
        (ssh-server-authorized-key-p
         (ssh-session-server session) user blob
         :address (ssh-session-remote-ip session)
         :session session)))
    (cond
      ((null key)
       (ssh-plibssh-session-publickey-failure session message signed count))
      ;; sshd refuses a key that already completed a method, even its probe.
      ((and blob (ssh-plibssh-session-auth-key-used-p session blob))
       (ssh-plibssh-session-publickey-failure session message signed count))
      ((and authorized (= state +ssh-publickey-state-none+))
       (ssh-message-auth-reply-pk-ok-simple message))
      ((and authorized signed)
       (ssh-plibssh-session-auth-method-succeeded
        session message user "publickey" blob key-env authorization))
      (t
       (ssh-plibssh-session-publickey-failure session message signed count)))))

;;; ---- Channel opens ----

(defun ssh-plibssh-session-register-channel (session handle type)
  "Wrap HANDLE in the server's channel record and announce it."
  (let* ((id (ssh-session-next-channel-id session))
         (channel (%make-ssh-server-channel
                   :session session
                   :handle handle
                   :local-id id
                   :type type
                   :state :open
                   :remote-address (ssh-session-remote-address session))))
    (incf (ssh-session-next-channel-id session))
    (setf (gethash id (ssh-session-channels session)) channel)
    (ssh-session-note-channel-change session)
    (ssh-server-channel-start-inactivity-timeout channel)
    (ssh-plibssh-session-install-agent-callback channel)
    channel))

(defun ssh-plibssh-session-handle-open (session message)
  "Accept or refuse one CHANNEL OPEN request."
  (case (ssh-message-subtype message)
    (#.+ssh-channel-session+
     (ssh-plibssh-session-open-session session message))
    (#.+ssh-channel-direct-tcpip+
     (ssh-plibssh-session-open-direct-tcpip session message))
    (t (ssh-message-reply-default message))))

(defun ssh-plibssh-session-open-session (session message)
  "Accept a session channel and offer it to the application.

MaxSessions bounds how many may be live at once, as in sshd: a further open
is refused instead of allocated."
  (let ((limit (or (ssh-session-setting
                    session #'ssh-server-config-max-sessions)
                   (ssh-server-max-sessions (ssh-session-server session)))))
    (when (and limit
               (>= (ssh-server-session-channel-count session) limit))
      (ssh-message-reply-default message)
      (return-from ssh-plibssh-session-open-session nil)))
  (let ((handle (ssh-message-open-reply-accept message)))
    (when (ssh-plibssh-null-p handle)
      (error 'ssh-channel-error
             :channel nil
             :detail "could not accept a session channel"))
    (let ((channel (ssh-plibssh-session-register-channel
                    session handle "session")))
      (when (ssh-server-on-channel (ssh-session-server session))
        (funcall (ssh-server-on-channel (ssh-session-server session))
                 channel))
      channel)))

(defun ssh-plibssh-session-open-direct-tcpip (session message)
  "Ask the application about a forwarded connection, then accept it."
  (let* ((host (ssh-message-open-destination message))
         (port (ssh-message-open-destination-port message))
         (origin (ssh-message-open-originator message))
         (origin-port (ssh-message-open-originator-port message))
         (handler (ssh-server-on-direct-tcpip (ssh-session-server session)))
         (allowed (and (ssh-session-permits-direct-tcpip-p session host port)
                       handler
                       (funcall handler session host port origin origin-port))))
    (unless allowed
      (ssh-message-reply-default message)
      (return-from ssh-plibssh-session-open-direct-tcpip nil))
    (let ((handle (ssh-message-open-reply-accept message)))
      (when (ssh-plibssh-null-p handle)
        (error 'ssh-channel-error
               :channel nil
               :detail "could not accept a direct-tcpip channel"))
      (let ((channel (ssh-plibssh-session-register-channel
                      session handle "direct-tcpip")))
        (ssh-plibssh-server-connect-target channel host port)
        channel))))

;;; ---- Channel requests ----

(defun ssh-plibssh-session-channel-for-handle (session handle)
  "The channel record whose libssh handle is HANDLE."
  (loop for channel being the hash-values of (ssh-session-channels session)
        when (cffi:pointer-eq (ssh-server-channel-handle channel) handle)
          return channel))

;;; ---- Agent forwarding ----

(cffi:defcallback ssh-plibssh-channel-agent-request-callback
    :void ((session :pointer) (handle :pointer) (userdata :pointer))
  (declare (ignore userdata))
  (let ((object (ssh-plibssh-session-object session)))
    (when object
      (let ((channel
              (ssh-plibssh-session-channel-for-handle object handle)))
        (when channel
          (ssh-plibssh-session-handle-agent-request channel))))))

(defun ssh-plibssh-session-install-agent-callback (channel)
  "Register the per-channel callback libssh uses for auth-agent requests.

libssh answers the request itself when a callback is present, so it is only
installed where the application offers an agent-forwarding hook."
  (when (and (ssh-server-on-agent-forward
              (ssh-session-server (ssh-server-channel-session channel)))
             (ssh-server-channel-handle channel))
    (let* ((type 'ssh-channel-callbacks-struct)
           (struct (cffi:foreign-alloc (list :struct type))))
      (setf (cffi:foreign-slot-value struct (list :struct type) 'cl-plibssh::size)
            (ssh-plibssh-callback-struct-size type))
      (dolist (slot '(cl-plibssh::userdata
                      cl-plibssh::channel-data-function
                      cl-plibssh::channel-eof-function
                      cl-plibssh::channel-close-function
                      cl-plibssh::channel-signal-function
                      cl-plibssh::channel-exit-status-function
                      cl-plibssh::channel-exit-signal-function
                      cl-plibssh::channel-pty-request-function
                      cl-plibssh::channel-shell-request-function
                      cl-plibssh::channel-x11-req-function
                      cl-plibssh::channel-pty-window-change-function
                      cl-plibssh::channel-exec-request-function
                      cl-plibssh::channel-env-request-function
                      cl-plibssh::channel-subsystem-request-function
                      cl-plibssh::channel-write-wontblock-function))
        (setf (cffi:foreign-slot-value struct (list :struct type) slot)
              (cffi:null-pointer)))
      (setf (cffi:foreign-slot-value
             struct (list :struct type) 'cl-plibssh::channel-auth-agent-req-function)
            (cffi:callback ssh-plibssh-channel-agent-request-callback))
      (if (minusp (ssh-set-channel-callbacks
                   (ssh-server-channel-handle channel) struct))
          (cffi:foreign-free struct)
          (setf (ssh-server-channel-callbacks channel) struct)))))

(defun ssh-plibssh-session-handle-agent-request (channel)
  "Create the listener an auth-agent request asks for.

libssh has already answered success once this callback runs; the pure
backend's policy checks still decide whether a listener is created."
  (let ((session (ssh-server-channel-session channel)))
    (unless (ssh-session-agent-forward session)
      (if (not (ssh-session-permits-agent-forwarding-p session))
          (ssh-log "agent forwarding disabled")
          (let ((hook (ssh-server-on-agent-forward
                       (ssh-session-server session))))
            (when hook
              (multiple-value-bind (fd path cleanup)
                  (funcall hook session)
                (when (and fd path)
                  (let ((agent (%make-ssh-agent-forward
                                :session session
                                :fd fd
                                :path path
                                :cleanup cleanup)))
                    (setf (ssh-session-agent-forward session) agent)
                    (push (cons "SSH_AUTH_SOCK" path)
                          (ssh-server-channel-env channel))
                    (setf (ssh-agent-forward-watcher agent)
                          (cl-pnet:fd-watch
                           fd :on-readable
                           (lambda (watcher)
                             (declare (ignore watcher))
                             (ssh-plibssh-session-agent-accept agent)))))))))))))

(defun ssh-plibssh-session-agent-accept (agent)
  "Turn every pending connection on AGENT's listener into a channel."
  (loop for fd = (cl-pnet-sockets:accept-socket (ssh-agent-forward-fd agent))
        while fd
        do (if (minusp (cl-pnet-sockets:set-nonblocking fd))
               (ignore-errors (cl-pnet-sockets:close-open-fd fd))
               (ssh-plibssh-session-open-agent-channel agent fd))))

(defun ssh-plibssh-session-open-agent-channel (agent fd)
  "Open an auth-agent channel toward the client and bridge FD to it."
  (let* ((session (ssh-agent-forward-session agent))
         (handle (ssh-channel-new (ssh-session-handle session)))
         (id (ssh-session-next-channel-id session)))
    (if (ssh-plibssh-null-p handle)
        (progn
          (ignore-errors (cl-pnet-sockets:close-open-fd fd))
          nil)
        (let ((channel (%make-ssh-server-channel
                        :session session
                        :handle handle
                        :local-id id
                        :type "auth-agent@openssh.com"
                        :state :opening
                        :remote-address (ssh-session-remote-address session))))
          (incf (ssh-session-next-channel-id session))
          (setf (gethash id (ssh-session-channels session)) channel)
          (let ((relay (%make-ssh-fd-relay
                        :fd fd
                        :on-data
                        (lambda (relay octets)
                          (declare (ignore relay))
                          (ssh-server-channel-write channel octets))
                        :on-eof
                        (lambda (relay)
                          (declare (ignore relay))
                          (ssh-server-channel-eof channel))
                        :on-error
                        (lambda (relay condition)
                          (declare (ignore relay))
                          (ssh-plibssh-server-channel-fail channel condition)))))
            (setf (ssh-server-channel-agent-relay channel) relay
                  (ssh-server-channel-on-data channel)
                  (lambda (channel data kind)
                    (declare (ignore channel kind))
                    (ssh-fd-relay-queue relay data))
                  (ssh-server-channel-on-eof channel)
                  (lambda (channel)
                    (declare (ignore channel))
                    (ssh-fd-relay-shutdown-write relay))
                  (ssh-server-channel-on-close channel)
                  (lambda (channel)
                    (declare (ignore channel))
                    (ssh-fd-relay-close relay))
                  (ssh-server-channel-on-error channel)
                  (lambda (channel condition)
                    (declare (ignore channel condition))
                    (ssh-fd-relay-close relay)))
            (ssh-plibssh-session-drive-agent-channel channel)
            channel)))))

(defun ssh-plibssh-session-drive-agent-channel (channel)
  "Retry opening CHANNEL until the client accepts, then start the relay."
  (when (eq (ssh-server-channel-state channel) :opening)
    (let ((rc (ssh-channel-open-auth-agent
               (ssh-server-channel-handle channel))))
      (cond
        ((zerop rc)
         (setf (ssh-server-channel-state channel) :open)
         (when (ssh-server-channel-agent-relay channel)
           (ssh-fd-relay-start (ssh-server-channel-agent-relay channel))))
        ((= rc +ssh-again+) nil)
        (t
         (ssh-plibssh-server-channel-fail
          channel
          (make-condition 'ssh-channel-error
                          :channel channel
                          :detail
                          (format nil "could not open an agent channel: ~A"
                                  (ssh-plibssh-error
                                   (ssh-session-handle
                                    (ssh-server-channel-session channel)))))))))))

(defun ssh-plibssh-session-close-agent-forward (session)
  "Remove SESSION's agent listener and its socket, once."
  (let ((agent (ssh-session-agent-forward session)))
    (when agent
      (setf (ssh-session-agent-forward session) nil)
      (when (ssh-agent-forward-watcher agent)
        (ignore-errors
         (cl-pnet:fd-unwatch (ssh-agent-forward-watcher agent))))
      (when (ssh-agent-forward-fd agent)
        (ignore-errors
         (cl-pnet-sockets:close-open-fd (ssh-agent-forward-fd agent))))
      (when (ssh-agent-forward-cleanup agent)
        (ignore-errors (funcall (ssh-agent-forward-cleanup agent)))))))

(defun ssh-plibssh-session-handle-channel-request (session message)
  "Dispatch one CHANNEL REQUEST message."
  (let* ((handle (ssh-message-channel-request-channel message))
         (channel (ssh-plibssh-session-channel-for-handle session handle)))
    (if (null channel)
        (ssh-message-reply-default message)
        (case (ssh-message-subtype message)
          (#.+ssh-channel-request-pty+
           (ssh-plibssh-session-handle-pty channel message))
          (#.+ssh-channel-request-env+
           (ssh-plibssh-session-handle-env channel message))
          (#.+ssh-channel-request-shell+
           (ssh-plibssh-session-handle-shell channel message))
          (#.+ssh-channel-request-exec+
           (ssh-plibssh-session-handle-exec channel message))
          (#.+ssh-channel-request-subsystem+
           (ssh-plibssh-session-handle-subsystem channel message))
          (#.+ssh-channel-request-window-change+
           (ssh-plibssh-session-handle-window-change channel message))
          (t (ssh-message-reply-default message))))))

(defun ssh-plibssh-session-handle-env (channel message)
  "Record an accepted environment variable, or refuse it."
  (let* ((name (ssh-message-channel-request-env-name message))
         (value (ssh-message-channel-request-env-value message))
         (session (ssh-server-channel-session channel)))
    (if (ssh-session-env-allowed-p session name value)
        (progn
          (push (cons name value) (ssh-server-channel-env channel))
          (ssh-message-channel-request-reply-success message))
        (ssh-message-reply-default message))))

(defun ssh-plibssh-session-handle-pty (channel message)
  "Remember the peer's terminal, as the pure backend does.

The application's ON-PTY predicate decides whether the request succeeds.
libssh does not expose the encoded mode list, so it is passed as NIL; the
terminal name and both sizes are kept."
  (let* ((term (ssh-message-channel-request-pty-term message))
         (columns (ssh-message-channel-request-pty-width message))
         (rows (ssh-message-channel-request-pty-height message))
         (width (ssh-message-channel-request-pty-pxwidth message))
         (height (ssh-message-channel-request-pty-pxheight message))
         (handler (ssh-server-channel-on-pty channel))
         (ok (and (ssh-session-permits-pty-p
                   (ssh-server-channel-session channel))
                  handler
                  (funcall handler channel term columns rows width height
                           nil))))
    (when ok
      (setf (ssh-server-channel-pty-p channel) t
            (ssh-server-channel-pty-term channel) term
            (ssh-server-channel-pty-columns channel) columns
            (ssh-server-channel-pty-rows channel) rows))
    (if ok
        (ssh-message-channel-request-reply-success message)
        (ssh-message-reply-default message))))

(defun ssh-plibssh-session-handle-exec (channel message)
  "Run the command in MESSAGE through the application's handler."
  (let ((command (ssh-message-channel-request-command message))
        (handler (ssh-server-channel-on-exec channel)))
    (setf (ssh-server-channel-command channel) command)
    ;; sshd labels the channel before do_exec, success or not.
    (ssh-server-channel-set-x-type channel "session:command")
    (if handler
        (progn
          (ssh-message-channel-request-reply-success message)
          (funcall handler channel command))
        (ssh-message-reply-default message))))

(defun ssh-plibssh-session-handle-shell (channel message)
  "Ask the application for the login shell thunk, then answer and run it."
  (let* ((handler (ssh-server-channel-on-shell channel))
         (start (and handler (funcall handler channel))))
    ;; sshd labels the channel before running the shell, even if starting it
    ;; fails; the label selects ChannelTimeout from here on.
    (ssh-server-channel-set-x-type channel "session:shell")
    (if start
        (progn
          (ssh-message-channel-request-reply-success message)
          (funcall start))
        (ssh-message-reply-default message))))

(defun ssh-plibssh-session-handle-subsystem (channel message)
  "Ask the application to start the named subsystem, then run its thunk."
  (let* ((name (ssh-message-channel-request-subsystem message))
         (handler (ssh-server-channel-on-subsystem channel))
         (start (and handler (funcall handler channel name))))
    (when start
      (setf (ssh-server-channel-subsystem channel) name))
    (if start
        (progn
          (ssh-message-channel-request-reply-success message)
          (ssh-server-channel-set-x-type
           channel (format nil "session:subsystem:~A" name))
          (funcall start))
        (ssh-message-reply-default message))))

(defun ssh-plibssh-session-handle-window-change (channel message)
  "Store the peer's new terminal size and tell the application."
  (let ((columns (ssh-message-channel-request-pty-width message))
        (rows (ssh-message-channel-request-pty-height message)))
    (setf (ssh-server-channel-pty-columns channel) columns
          (ssh-server-channel-pty-rows channel) rows)
    (when (ssh-server-channel-on-window-change channel)
      (funcall (ssh-server-channel-on-window-change channel)
               channel columns rows))
    ;; RFC 4254 says a window-change never wants a reply, and libssh's
    ;; success reply sends nothing when the peer did not ask for one.
    (ssh-message-channel-request-reply-success message)))

;;; ---- Channel data and flow control ----

(defun ssh-plibssh-server-channel-queue (channel data stderr)
  (ssh-plibssh-buffer-append
   (if stderr (ssh-server-channel-stderr-queue channel)
       (ssh-server-channel-write-queue channel))
   (ssh-ensure-octets data)))

(defun ssh-plibssh-server-flush-queue (channel queue stderr)
  "Send QUEUE as far as libssh's window allows; return the bytes left."
  (loop
    (unless (plusp (fill-pointer queue)) (return 0))
    (let* ((count (min (fill-pointer queue) +ssh-read-chunk+))
           (written
             (ssh-plibssh-write-octets
              (lambda (buffer length)
                (if stderr
                    (ssh-plibssh-channel-write-stderr
                     (ssh-server-channel-handle channel) buffer length)
                    (ssh-plibssh-channel-write
                     (ssh-server-channel-handle channel) buffer length)))
              queue 0 count)))
      (cond
        ((plusp written) (ssh-plibssh-buffer-drop queue written))
        ((zerop written) (return (fill-pointer queue)))
        (t (return (fill-pointer queue)))))))

(defun ssh-plibssh-server-run-callbacks (channel)
  (let ((callbacks (nreverse (ssh-server-channel-write-callbacks channel))))
    (setf (ssh-server-channel-write-callbacks channel) nil)
    (iter (for callback in callbacks) (funcall callback))))

(defun ssh-plibssh-server-after-queue (channel)
  "Send the exit status, EOF and close once the queues are empty."
  (when (and (ssh-server-channel-handle channel)
             (not (ssh-server-channel-close-reported channel)))
    (ssh-plibssh-server-run-callbacks channel)
    (ssh-plibssh-server-send-exit channel)
    (ssh-plibssh-server-send-eof channel)
    (ssh-plibssh-server-send-close channel)))

(defun ssh-plibssh-server-send-exit (channel)
  (let ((status (ssh-server-channel-exit-status channel)))
    (when (and status
               (not (ssh-server-channel-exit-sent channel))
               (ssh-server-channel-handle channel))
      (ssh-channel-request-send-exit-status
       (ssh-server-channel-handle channel) status)
      (setf (ssh-server-channel-exit-sent channel) t))))

(defun ssh-plibssh-server-send-eof (channel)
  (when (and (ssh-server-channel-want-eof channel)
             (not (ssh-server-channel-sent-eof channel))
             (eq (ssh-server-channel-state channel) :open)
             (ssh-server-channel-handle channel))
    (when (zerop (ssh-channel-send-eof (ssh-server-channel-handle channel)))
      (setf (ssh-server-channel-sent-eof channel) t))))

(defun ssh-plibssh-server-send-close (channel)
  (when (and (ssh-server-channel-want-close channel)
             (not (ssh-server-channel-sent-close channel))
             (member (ssh-server-channel-state channel) '(:open :closing))
             (ssh-server-channel-handle channel))
    (when (zerop (ssh-plibssh-channel-close
                  (ssh-server-channel-handle channel)))
      (setf (ssh-server-channel-sent-close channel) t
            (ssh-server-channel-state channel) :closing))))

(defun ssh-plibssh-server-channel-flush (channel)
  "Move both queues, then send whatever end the application asked for."
  (when (eq (ssh-server-channel-state channel) :open)
    (ssh-plibssh-server-flush-queue
     channel (ssh-server-channel-write-queue channel) nil)
    (ssh-plibssh-server-flush-queue
     channel (ssh-server-channel-stderr-queue channel) t))
  (when (and (zerop (fill-pointer
                     (ssh-server-channel-write-queue channel)))
             (zerop (fill-pointer
                     (ssh-server-channel-stderr-queue channel))))
    (ssh-plibssh-server-after-queue channel)))

(defun ssh-plibssh-server-channel-dispatch (channel data stderr)
  "Hand DATA to the target connection or the application."
  (if (string= (ssh-server-channel-type channel) "direct-tcpip")
      (ssh-plibssh-server-channel-write-target channel data)
      (when (ssh-server-channel-on-data channel)
        (funcall (ssh-server-channel-on-data channel) channel data
                 (if stderr :stderr :stdin)))))

(defun ssh-plibssh-server-channel-read (channel stderr)
  "Drain one direction of CHANNEL into its consumer."
  (cffi:with-foreign-object (buffer :unsigned-char +ssh-read-chunk+)
    (loop
      (let ((handle (ssh-server-channel-handle channel)))
        (unless handle (return))
        (let ((rc (ssh-channel-read-nonblocking
                   handle buffer +ssh-read-chunk+ (if stderr 1 0))))
          (cond
            ((plusp rc)
             (ssh-server-channel-note-activity channel)
             (ssh-plibssh-server-channel-dispatch
              channel (ssh-plibssh-fill-octets buffer rc) stderr))
            ((or (zerop rc) (= rc +ssh-eof+)) (return))
            (t
             ;; A vanished peer is not a channel error: end the session and
             ;; report the connection closed, as the pure backend does.
             (let* ((session (ssh-server-channel-session channel))
                    (session-handle (ssh-session-handle session)))
               (if (and session-handle
                        (plusp (ssh-is-connected session-handle)))
                   (ssh-plibssh-server-channel-fail
                    channel
                    (make-condition
                     'ssh-channel-error :channel channel
                     :detail (format nil "channel read failed: ~A"
                                     (ssh-plibssh-error session-handle))))
                   (ssh-session-finish session :peer-closed :close)))
             (return))))))))

(defun ssh-plibssh-server-channel-report-eof (channel)
  (let ((handle (ssh-server-channel-handle channel)))
    (when (and handle
               (plusp (ssh-channel-is-eof handle))
               (not (ssh-server-channel-eof-reported channel)))
      (setf (ssh-server-channel-eof-reported channel) t
            (ssh-server-channel-eof-received channel) t)
      (when (ssh-server-channel-on-eof channel)
        (funcall (ssh-server-channel-on-eof channel) channel)))))

(defun ssh-plibssh-server-channel-drive (channel)
  "Read, write and finish CHANNEL as far as its descriptor allows."
  (unless (ssh-server-channel-close-reported channel)
    (case (ssh-server-channel-state channel)
      (:opening
       (ssh-plibssh-session-drive-agent-channel channel)
       (when (eq (ssh-server-channel-state channel) :open)
         (ssh-plibssh-server-channel-drive channel)))
      (:open
       (ssh-plibssh-server-channel-read channel nil)
       (ssh-plibssh-server-channel-read channel t)
       (ssh-plibssh-server-channel-report-eof channel)
       (ssh-plibssh-server-channel-flush channel)
       (ssh-plibssh-server-channel-check-close channel))
      (:closing
       (ssh-plibssh-server-channel-check-close channel))
      (:closed nil))))

(defun ssh-plibssh-server-channel-check-close (channel)
  (let ((handle (ssh-server-channel-handle channel)))
    (when (and handle
               (plusp (ssh-channel-is-closed handle)))
      (ssh-plibssh-server-channel-finish channel))))

;;; ---- Channel termination ----

(defun ssh-plibssh-server-channel-finish (channel)
  "Mark CHANNEL closed once, unregister it, and report its end."
  (unless (ssh-server-channel-close-reported channel)
    (setf (ssh-server-channel-close-reported channel) t
          (ssh-server-channel-state channel) :closed)
    (remhash (ssh-server-channel-local-id channel)
             (ssh-session-channels
              (ssh-server-channel-session channel)))
    (ssh-session-note-channel-change (ssh-server-channel-session channel))
    (ssh-plibssh-server-channel-close-target channel)
    (when (ssh-server-channel-agent-relay channel)
      (ssh-fd-relay-close (ssh-server-channel-agent-relay channel))
      (setf (ssh-server-channel-agent-relay channel) nil))
    (when (ssh-server-channel-callbacks channel)
      (cffi:foreign-free (ssh-server-channel-callbacks channel))
      (setf (ssh-server-channel-callbacks channel) nil))
    (let ((handle (ssh-server-channel-handle channel)))
      (setf (ssh-server-channel-handle channel) nil)
      (when handle (ssh-channel-free handle)))
    (when (ssh-server-channel-on-close channel)
      (funcall (ssh-server-channel-on-close channel) channel))))

(defun ssh-server-channel-force-close (channel)
  "End CHANNEL at once, as sshd's channel_force_close does for an idle one.

libssh sends the CHANNEL_CLOSE itself; the record is then released and the
application's ON-CLOSE runs without waiting for the peer's half."
  (let ((handle (ssh-server-channel-handle channel)))
    (when (and handle
               (not (ssh-server-channel-sent-close channel))
               (member (ssh-server-channel-state channel) '(:open :closing)))
      (ssh-plibssh-channel-close handle)
      (setf (ssh-server-channel-sent-close channel) t)))
  (ssh-plibssh-server-channel-finish channel))

(defun ssh-plibssh-server-channel-fail (channel condition)
  "Report CONDITION, then close CHANNEL."
  (when (ssh-server-channel-on-error channel)
    (funcall (ssh-server-channel-on-error channel) channel condition))
  (ssh-server-channel-close channel))

(defun ssh-plibssh-server-channel-close-target (channel)
  (let ((target (ssh-server-channel-target channel)))
    (when target
      (setf (ssh-server-channel-target channel) nil)
      (cl-pnet:close-connection target))))

;;; ---- Public channel operations ----

(defun ssh-server-channel-write (channel data &key on-done)
  "Queue DATA for the client; ON-DONE runs when all of it has been sent."
  (when (eq (ssh-server-channel-state channel) :closed)
    (error 'ssh-channel-error :channel channel :detail "channel is closed"))
  (when (ssh-plibssh-channel-usable-p channel)
    (ssh-plibssh-server-channel-queue channel data nil)
    (ssh-server-channel-note-activity channel)
    (when on-done
      (push on-done (ssh-server-channel-write-callbacks channel)))
    (ssh-plibssh-server-channel-flush channel))
  channel)

(defun ssh-server-channel-write-stderr (channel data &key on-done)
  "Queue DATA as extended data, the SSH equivalent of stderr."
  (when (eq (ssh-server-channel-state channel) :closed)
    (error 'ssh-channel-error :channel channel :detail "channel is closed"))
  (when (ssh-plibssh-channel-usable-p channel)
    (ssh-plibssh-server-channel-queue channel data t)
    (ssh-server-channel-note-activity channel)
    (when on-done
      (push on-done (ssh-server-channel-write-callbacks channel)))
    (ssh-plibssh-server-channel-flush channel))
  channel)

(defun ssh-server-channel-eof (channel)
  "Say no more output follows, after everything already queued."
  (setf (ssh-server-channel-want-eof channel) t)
  (ssh-plibssh-server-channel-flush channel)
  channel)

(defun ssh-server-channel-close (channel)
  "Start the close handshake, after everything already queued."
  (when (member (ssh-server-channel-state channel) '(:open :opening))
    (setf (ssh-server-channel-want-close channel) t)
    (ssh-plibssh-server-channel-flush channel))
  channel)

(defun ssh-server-channel-exit (channel status)
  "Send an exit status and end the channel's output."
  (setf (ssh-server-channel-exit-status channel) status
        (ssh-server-channel-want-eof channel) t)
  (ssh-plibssh-server-channel-flush channel)
  channel)

(defun ssh-plibssh-channel-usable-p (channel)
  "Whether CHANNEL still has a live libssh handle."
  (and (ssh-server-channel-handle channel)
       (not (ssh-server-channel-close-reported channel))))

;;; ---- direct-tcpip target ----

(defun ssh-plibssh-server-channel-write-target (channel data)
  "Send client channel DATA to CHANNEL's forwarded target."
  (let ((target (ssh-server-channel-target channel)))
    (when target
      (cl-pnet:send-data
       target data
       :on-error
       (lambda (status)
         (ssh-plibssh-server-channel-fail
          channel
          (make-condition 'ssh-connection-error
                          :detail (format nil "target send failed (~A)"
                                          status))))))))

(defun ssh-plibssh-server-connect-target (channel host port)
  "Connect CHANNEL to HOST:PORT without blocking, then pipe both ways."
  (handler-case
      (burzay:resolve-host
       host
       (lambda (address)
         (ssh-plibssh-server-dial-target channel address port))
       (lambda (condition)
         (ssh-plibssh-server-channel-fail channel condition)))
    (error (condition) (ssh-plibssh-server-channel-fail channel condition))))

(defun ssh-plibssh-server-dial-target (channel address port)
  "Open the forwarded target for CHANNEL once its name resolved."
  (let ((connection
          (cl-pnet:tcp-connect
           address port
           :read-cb (lambda (data)
                      (if data
                          (ssh-server-channel-write channel data)
                          (ssh-server-channel-eof channel)))
           :on-error
           (lambda (status)
             (ssh-plibssh-server-channel-fail
              channel
              (make-condition 'ssh-connection-error
                              :detail (format nil "target connect failed (~A)"
                                              status)))))))
    (if connection
        (setf (ssh-server-channel-target channel) connection)
        (ssh-plibssh-server-channel-fail
         channel
         (make-condition 'ssh-connection-error
                         :detail (format nil "could not connect to ~A:~D"
                                         address port))))))

;;; ---- Connection timers ----
;;;
;;; The same policy as the pure backend, driven from the event loop.  libssh
;;; itself is asked to send the probe, which is its keepalive@openssh.com
;;; global request.

(defun ssh-session-now ()
  "Monotonic time in seconds, for the connection timers."
  (/ (get-internal-real-time) internal-time-units-per-second))

(defun ssh-session-cancel-timer (timer)
  "Stop TIMER when it is set, answering NIL for the caller to store."
  (when timer
    (cl-pnet:timer-stop timer))
  nil)

(defun ssh-session-stop-timers (session)
  "Disarm SESSION's login-grace, client-alive and channel timers, once."
  (setf (ssh-session-login-grace-timer session)
        (ssh-session-cancel-timer (ssh-session-login-grace-timer session))
        (ssh-session-client-alive-timer session)
        (ssh-session-cancel-timer (ssh-session-client-alive-timer session))
        (ssh-session-unused-connection-timer session)
        (ssh-session-cancel-timer
         (ssh-session-unused-connection-timer session))
        (ssh-session-channel-timeout-timer session)
        (ssh-session-cancel-timer
         (ssh-session-channel-timeout-timer session))))

(defun ssh-session-start-login-grace-timer (session)
  "Close SESSION if it has not authenticated in LoginGraceTime seconds."
  (let ((seconds (ssh-server-login-grace-time (ssh-session-server session))))
    (when (and seconds
               (plusp seconds)
               (not (ssh-session-login-grace-timer session))
               (not (ssh-session-closed session)))
      (setf (ssh-session-login-grace-timer session)
            (cl-pnet:timer-start
             seconds 0
             (lambda ()
               (setf (ssh-session-login-grace-timer session) nil)
               (unless (or (ssh-session-closed session)
                           (ssh-session-authenticated session))
                 (ssh-session-finish session
                                     "Timeout before authentication"
                                     :close))))))))

(defun ssh-session-schedule-client-alive (session delay)
  "Arm SESSION's next client-alive probe after DELAY seconds."
  (when (and (not (ssh-session-closed session))
             (not (ssh-session-client-alive-timer session)))
    (setf (ssh-session-client-alive-timer session)
          (cl-pnet:timer-start
           (max 0.05 delay) 0
           (lambda ()
             (setf (ssh-session-client-alive-timer session) nil)
             (ssh-session-client-alive-tick session))))))

(defun ssh-session-client-alive-tick (session)
  "Probe SESSION if it has been quiet, and disconnect once it stops answering."
  (unless (ssh-session-closed session)
    (let* ((server (ssh-session-server session))
           (interval (or (ssh-session-setting
                          session #'ssh-server-config-client-alive-interval)
                         (ssh-server-client-alive-interval server)))
           (count-max (or (ssh-session-setting
                           session
                           #'ssh-server-config-client-alive-count-max)
                          (ssh-server-client-alive-count-max server))))
      (when (and interval (plusp interval))
        (let ((idle (- (ssh-session-now)
                       (ssh-session-last-input-time session))))
          (if (< idle interval)
              (ssh-session-schedule-client-alive
               session (- interval idle))
              (progn
                (incf (ssh-session-client-alive-misses session))
                (if (and (plusp count-max)
                         (> (ssh-session-client-alive-misses session)
                            count-max))
                    (ssh-session-finish
                     session "Timeout, client not responding" :close)
                    (progn
                      (ssh-session-send-keepalive session)
                      (setf (ssh-session-last-input-time session)
                            (ssh-session-now))
                      (ssh-session-schedule-client-alive session
                                                         interval))))))))))

(defun ssh-session-start-client-alive-timer (session)
  "Start probing SESSION once authentication has finished."
  (let ((interval (or (ssh-session-setting
                       session #'ssh-server-config-client-alive-interval)
                      (ssh-server-client-alive-interval
                       (ssh-session-server session)))))
    (when (and interval
               (plusp interval)
               (not (ssh-session-client-alive-timer session))
               (not (ssh-session-closed session)))
      (setf (ssh-session-last-input-time session) (ssh-session-now)
            (ssh-session-client-alive-misses session) 0)
      (ssh-session-schedule-client-alive session interval))))

(defun ssh-session-note-input (session)
  "Record that SESSION's peer sent bytes, resetting its keepalive misses."
  (setf (ssh-session-last-input-time session) (ssh-session-now)
        (ssh-session-client-alive-misses session) 0))

(defun ssh-session-send-keepalive (session)
  "Ask libssh for its keepalive@openssh.com global request."
  (let ((handle (ssh-session-handle session)))
    (when handle
      (ssh-send-keepalive handle))))

;;; ---- Session termination ----

(defun ssh-plibssh-session-terminate-channels (session kind reason)
  "Report the end of every channel still registered on SESSION."
  (let ((channels (iter (for (id channel) in-hashtable
                              (ssh-session-channels session))
                    (collect (cons id channel)))))
    (iter (for (id . channel) in channels)
      (remhash id (ssh-session-channels session))
      (setf (ssh-server-channel-state channel) :closed
            (ssh-server-channel-close-reported channel) t
            (ssh-server-channel-handle channel) nil)
      (ssh-plibssh-server-channel-close-target channel)
      (ecase kind
        (:error
         (when (ssh-server-channel-on-error channel)
           (funcall (ssh-server-channel-on-error channel) channel reason)))
        (:close
         (when (ssh-server-channel-on-close channel)
           (funcall (ssh-server-channel-on-close channel) channel)))))))

(defun ssh-plibssh-session-release (session)
  "Stop watching SESSION's descriptor and let libssh free it."
  (let ((watcher (ssh-session-watcher session))
        (write-watcher (ssh-session-write-watcher session))
        (handle (ssh-session-handle session))
        (write-fd (ssh-session-write-fd session)))
    (setf (ssh-session-watcher session) nil
          (ssh-session-write-watcher session) nil
          (ssh-session-handle session) nil
          (ssh-session-fd session) nil
          (ssh-session-write-fd session) nil)
    (when watcher (cl-pnet:fd-unwatch watcher))
    (when write-watcher (cl-pnet:fd-unwatch write-watcher))
    (when handle
      (ssh-plibssh-unregister-session handle)
      (ssh-disconnect handle)
      (ssh-free handle))
    (when write-fd (ssh-plibssh-close-fd write-fd))))

(defun ssh-session-finish (session reason kind)
  "Close SESSION once, reporting REASON through the callback KIND selects."
  (unless (ssh-session-closed session)
    (setf (ssh-session-closed session) t
          (ssh-session-phase session) :closed
          (ssh-session-close-reason session) reason)
    (ssh-server-session-penalty session)
    (ssh-session-stop-timers session)
    (ssh-plibssh-session-close-agent-forward session)
    (let ((server (ssh-session-server session)))
      (when server
        (remhash session (ssh-server-sessions server))))
    (ssh-plibssh-session-terminate-channels session kind reason)
    (ssh-plibssh-session-release session)
    (let ((server (ssh-session-server session)))
      (ecase kind
        (:error
         (when (and server (ssh-server-on-error server))
           (funcall (ssh-server-on-error server) session reason)))
        (:close
         (when (and server (ssh-server-on-close server))
           (funcall (ssh-server-on-close server) session reason)))))))

(defun ssh-session-fail (session condition)
  "End SESSION because of CONDITION, telling the server once."
  (ssh-session-finish session condition :error))

(defun ssh-session-close (session)
  "Close SESSION and every channel it carries."
  (ssh-session-finish session :client-closed :close)
  session)

;;; ---- Accepting connections ----

(defun ssh-plibssh-server-accept (server fd)
  "Wrap a freshly accepted FD in a session and start its handshake."
  (let ((handle (ssh-new)))
    (when (ssh-plibssh-null-p handle)
      (cl-pnet-sockets:c-close fd)
      (error 'ssh-connection-error :detail "could not allocate a libssh session"))
    (let ((session (%make-ssh-session
                    :server server
                    :handle handle
                    :fd fd
                    :remote-address (ssh-plibssh-peer-address fd))))
      (let ((rc (ssh-bind-accept-fd (ssh-server-bind server) handle fd)))
        (unless (zerop rc)
          (let ((detail (ssh-plibssh-error handle)))
            (ssh-free handle)
            (cl-pnet-sockets:c-close fd)
            (error 'ssh-connection-error
                   :detail (format nil "could not attach a session: ~A"
                                   detail)))))
      ;; Compression no narrows the offer to "none".  libssh's server default
      ;; is "none,zlib@openssh.com", which already matches sshd, and the
      ;; client's preference order decides whether the stream is used.
      (let ((config (ssh-server-sshd-config server)))
        (when (and config
                   (eq (ssh-server-config-compression config) :no))
          (dolist (code (list +ssh-options-compression-c-s+
                              +ssh-options-compression-s-c+))
            (when (minusp (ssh-plibssh-set-string-option handle code "none"))
              (error 'ssh-connection-error
                     :detail (format nil "libssh rejected Compression: ~A"
                                     (ssh-plibssh-error handle)))))))
      (setf (gethash session (ssh-server-sessions server)) session)
      (ssh-plibssh-register-session handle session)
      (ssh-session-start-login-grace-timer session)
      (setf (ssh-session-watcher session)
            (cl-pnet:fd-watch
             fd
             :on-readable
             (lambda (watcher)
               (declare (ignore watcher))
               (ssh-plibssh-session-pump session))))
      (ssh-set-blocking handle 0)
      (ssh-plibssh-session-pump session)
      session)))

(defun ssh-plibssh-refuse-connection (fd)
  "Send sshd's MaxStartups notice on FD, best effort, and close it."
  (let ((notice (format nil "Exceeded MaxStartups~C~C"
                        #\Return #\Linefeed)))
    (cffi:with-foreign-string (buffer notice)
      (cl-pnet-sockets:c-send fd buffer (length notice) 0)))
  (cl-pnet-sockets:c-close fd))

(defun ssh-plibssh-server-accept-loop (server)
  "Drain every waiting connection on SERVER's listener."
  (loop
    (let ((fd (cl-pnet-sockets:accept-socket
               (ssh-server-listener server))))
      (unless (and fd (not (ssh-server-closed server)))
        (return))
      (cl-pnet-sockets:set-nonblocking fd)
      (handler-case
          (let ((peer (ssh-plibssh-peer-address fd)))
            (if (ssh-server-connection-allowed-p server peer)
                (progn
                  (ssh-server-apply-tcp-keepalive server fd)
                  (ssh-plibssh-server-accept server fd))
                (progn
                  (ssh-log
                   "drop connection from ~A past MaxStartups or PerSourceMaxStartups"
                   (getf peer :address))
                  (ssh-plibssh-refuse-connection fd))))
        (error (condition)
          (when (ssh-server-on-error server)
            (funcall (ssh-server-on-error server) nil condition)))))))

;;; ---- Public entry points ----

(defun ssh-plibssh-bind-algorithm-option (bind code option value)
  "Set bind algorithm list VALUE (a list of names) for OPTION.
A NIL VALUE leaves libssh's own default in place.  A value libssh refuses is
this program's error, because a configured list is meant exactly as written."
  (when value
    (when (minusp (ssh-plibssh-bind-string-option
                   bind code (format nil "~{~A~^,~}" value)))
      (let ((detail (ssh-plibssh-error bind)))
        (ssh-bind-free bind)
        (error 'ssh-connection-error
               :detail (format nil "libssh rejected ~A: ~A" option detail))))))

(defun make-ssh-server (address port
                        &key
                          host-key
                          host-certificate
                          host-key-agent
                          authorized-keys
                          authorize
                          authorize-user
                          hostbased-key-allowed
                          authorize-password
                          authorize-keyboard-interactive
                          authorize-login
                          sshd-config
                          user-groups
                          banner
                          permit-user-environment
                          set-env
                          max-auth-tries
                          max-sessions
                          login-grace-time
                          client-alive-interval
                          client-alive-count-max
                          (max-startups '(10 30 100))
                          per-source-max-startups
                          (per-source-net-block-size '(32 128))
                          (unused-connection-timeout 0)
                          channel-timeouts
                          (tcp-keep-alive t)
                          v6only
                          address-family
                          accept-env
                          server-version
                          version-addendum
                          on-session
                          on-channel
                          on-direct-tcpip
                          on-direct-streamlocal
                          on-tcpip-forward
                          on-cancel-tcpip-forward
                          on-streamlocal-forward
                          on-cancel-streamlocal-forward
                          on-agent-forward
                          x11-authority-file
                          on-error
                          on-close)
  "Listen on ADDRESS:PORT and serve SSH clients, returning at once.

The libssh backend owns the listener and every accepted descriptor, so no
call in this file waits for a peer.  BANNER is the sshd Banner text, a
function of no arguments returning it, or NIL for none.  The arguments are the same as the pure
backend's; HOST-KEY may be an ssh-private-key, a path, or a list of those.
libssh needs a file for each key it presents, so a key parsed from octets
without a path is refused here.  SERVER-VERSION is the part of the greeting
after \"SSH-2.0-\"; libssh adds that prefix itself.

PERMIT-USER-ENVIRONMENT and SET-ENV carry sshd's same-named settings; they
reach the child through the application, which reads the session record.

LOGIN-GRACE-TIME, CLIENT-ALIVE-INTERVAL and CLIENT-ALIVE-COUNT-MAX carry
sshd's connection timers in seconds; a NIL argument keeps sshd's defaults of
120, 0 and 3.

MAX-STARTUPS, PER-SOURCE-MAX-STARTUPS, PER-SOURCE-NET-BLOCK-SIZE,
UNUSED-CONNECTION-TIMEOUT and TCP-KEEP-ALIVE are the pure backend's, with
the same meanings and defaults.  CHANNEL-TIMEOUTS is sshd's ChannelTimeout
list, applied by the same inactivity accounting as the pure backend."
  (declare (ignore on-tcpip-forward on-cancel-tcpip-forward
                   x11-authority-file))
  (when host-certificate
    (error 'ssh-connection-error
           :detail "the libssh backend cannot present host certificates"))
  (let* ((required-rsa-size
           (and sshd-config
                (ssh-server-config-required-rsa-size sshd-config)))
         (keys (mapcar (lambda (value)
                         (if (typep value 'ssh-private-key)
                             value
                             (ssh-load-private-key value)))
                       (if (listp host-key) host-key (list host-key))))
         ;; sshd loads each HostKey and skips an RSA one that RequiredRSASize
         ;; rejects; the smallest allowed size (1024) applies even when the
         ;; directive is absent or lower.  Filtering here keeps libssh from
         ;; aborting startup over one bad file.
         (keys (remove-if-not
                (lambda (key)
                  (ssh-key-rsa-size-allowed-p
                   (ssh-public-key-blob-of key) required-rsa-size))
                keys))
         (mldsa-host-key
           (find-if (lambda (key)
                      (string= (ssh-private-key-type key)
                               "ssh-mldsa44-ed25519"))
                    keys))
         (version (if server-version
                      (check-server-version server-version)
                      (subseq +ssh-server-version+
                              (length "SSH-2.0-"))))
         (addendum (and version-addendum
                        (not (eq version-addendum :none))
                        (check-version-addendum version-addendum)))
         (server (%make-ssh-server
                  :address address
                  :port port
                  :host-keys keys
                  :host-key-agent host-key-agent
                  :authorized-keys authorized-keys
                  :authorize authorize
                  :authorize-user authorize-user
                  :hostbased-key-allowed hostbased-key-allowed
                  :authorize-password authorize-password
                  :authorize-keyboard-interactive
                  authorize-keyboard-interactive
                  :authorize-login authorize-login
                  :sshd-config sshd-config
                  :user-groups user-groups
                  :banner banner
                  :permit-user-environment permit-user-environment
                  :set-env set-env
                  :max-auth-tries (or max-auth-tries 6)
                  :max-sessions (or max-sessions 10)
                  :login-grace-time
                  (or login-grace-time
                      +ssh-server-default-login-grace-time+)
                  :client-alive-interval
                  (or client-alive-interval
                      +ssh-server-default-client-alive-interval+)
                  :client-alive-count-max
                  (or client-alive-count-max
                      +ssh-server-default-client-alive-count-max+)
                  :max-startups-begin (first max-startups)
                  :max-startups-rate (second max-startups)
                  :max-startups-full (third max-startups)
                  :per-source-max-startups per-source-max-startups
                  :per-source-net-block-size-ipv4
                  (first per-source-net-block-size)
                  :per-source-net-block-size-ipv6
                  (second per-source-net-block-size)
                  :unused-connection-timeout unused-connection-timeout
                  :channel-timeouts channel-timeouts
                  :tcp-keep-alive tcp-keep-alive
                  :accept-env accept-env
                  :on-session on-session
                  :on-channel on-channel
                  :on-direct-tcpip on-direct-tcpip
                  :on-direct-streamlocal on-direct-streamlocal
                  :on-streamlocal-forward on-streamlocal-forward
                  :on-cancel-streamlocal-forward on-cancel-streamlocal-forward
                  :on-agent-forward on-agent-forward
                  :on-error on-error
                  :on-close on-close))
         (bind (ssh-bind-new)))
    (when (ssh-plibssh-null-p bind)
      (error 'ssh-connection-error :detail "could not allocate a libssh bind"))
    (setf (ssh-server-bind server) bind)
    ;; libssh prepends "SSH-2.0-" to the banner, so the option takes only the
    ;; version tail.  A program that names itself must appear that way in a
    ;; peer's log instead of being hidden behind libssh's own string.
    (when (minusp (ssh-plibssh-bind-string-option
                   bind +ssh-bind-options-banner+
                   (if addendum
                       (format nil "~A ~A" version addendum)
                       version)))
      (let ((detail (ssh-plibssh-error bind)))
        (ssh-bind-free bind)
        (error 'ssh-connection-error
               :detail (format nil "libssh rejected the server version: ~A"
                               detail))))
    ;; The library must not read /etc/ssh/sshd_config behind the caller's
    ;; back: this server's host key and policy are the arguments it was given.
    (when (minusp (ssh-plibssh-bind-int-option
                   bind +ssh-bind-options-process-config+ 0))
      (let ((detail (ssh-plibssh-error bind)))
        (ssh-bind-free bind)
        (error 'ssh-connection-error
               :detail (format nil "libssh rejected the config flag: ~A"
                               detail))))
    ;; The configured algorithm lists replace libssh's own defaults only when
    ;; the directive was present; an unset directive leaves the backend's
    ;; defaults, as it did before these options existed.  libssh appends the
    ;; strict-KEX and EXT_INFO markers itself, so KexAlgorithms is the plain
    ;; method list.  RequiredRSASize is set before the host keys so libssh
    ;; applies it to them as well as to user keys.
    (when sshd-config
      (ssh-plibssh-reject-pq-kex-algorithms
       (ssh-server-config-kex-algorithms sshd-config) "KexAlgorithms")
      (ssh-plibssh-bind-algorithm-option
       bind +ssh-bind-options-key-exchange+ "KexAlgorithms"
       (ssh-server-config-kex-algorithms sshd-config))
      (ssh-plibssh-bind-algorithm-option
       bind +ssh-bind-options-ciphers-c-s+ "Ciphers"
       (ssh-server-config-ciphers sshd-config))
      (ssh-plibssh-bind-algorithm-option
       bind +ssh-bind-options-ciphers-s-c+ "Ciphers"
       (ssh-server-config-ciphers sshd-config))
      (ssh-plibssh-bind-algorithm-option
       bind +ssh-bind-options-hmac-c-s+ "MACs"
       (ssh-server-config-macs sshd-config))
      (ssh-plibssh-bind-algorithm-option
       bind +ssh-bind-options-hmac-s-c+ "MACs"
       (ssh-server-config-macs sshd-config))
      (ssh-plibssh-bind-algorithm-option
       bind +ssh-bind-options-hostkey-algorithms+ "HostKeyAlgorithms"
       (ssh-server-config-host-key-algorithms sshd-config))
      (ssh-plibssh-bind-algorithm-option
       bind +ssh-bind-options-pubkey-accepted-key-types+
       "PubkeyAcceptedAlgorithms"
       (ssh-server-config-pubkey-accepted-algorithms sshd-config))
      ;; libssh rejects a value between 1 and 767 and then applies its own
      ;; 1024-bit floor (2048 under FIPS).  sshd likewise lets its 1024-bit
      ;; floor win over any smaller RequiredRSASize, so a smaller value is
      ;; simply left unset rather than handed to libssh as an error.
      (when (and required-rsa-size
                 (>= required-rsa-size +ssh-rsa-minimum-modulus-size+))
        (when (minusp (ssh-plibssh-bind-int-option
                       bind +ssh-bind-options-rsa-min-size+
                       required-rsa-size))
          (let ((detail (ssh-plibssh-error bind)))
            (ssh-bind-free bind)
            (error 'ssh-connection-error
                   :detail (format nil "libssh rejected RequiredRSASize: ~A"
                                   detail))))))
    (when mldsa-host-key
      (ssh-bind-free bind)
      (error 'ssh-unsupported-feature
             :feature :mldsa
             :detail "host keys by the libssh transport"))
    (unless keys
      (ssh-bind-free bind)
      (error 'ssh-connection-error
             :detail (if host-key
                         (format nil "no host key is at least ~D bits"
                                 (or required-rsa-size
                                     +ssh-rsa-minimum-modulus-size+))
                         "no host key given")))
    (dolist (key keys)
      (let ((path (or (ssh-private-key-path key)
                      (progn
                        (ssh-bind-free bind)
                        (error 'ssh-connection-error
                               :detail "the host key has no file path")))))
        (when (minusp (ssh-plibssh-bind-string-option
                       bind +ssh-bind-options-host-key+ path))
          (let ((detail (ssh-plibssh-error bind)))
            (ssh-bind-free bind)
            (error 'ssh-connection-error
                   :detail (format nil "libssh rejected the host key ~A: ~A"
                                   path detail))))))
    (handler-case
        (let ((fd (ssh-plibssh-listen address port
                                      :v6only v6only
                                      :family address-family)))
          (setf (ssh-server-listener server) fd
                (ssh-server-port server) (or (ssh-plibssh-bound-port fd) port)
                (ssh-server-watcher server)
                (cl-pnet:fd-watch
                 fd
                 :on-readable
                 (lambda (watcher)
                   (declare (ignore watcher))
                   (ssh-plibssh-server-accept-loop server)))))
      (error (condition)
        (setf (ssh-server-bind server) nil)
        (ssh-bind-free bind)
        (error condition)))
    server))

(defun ssh-server-close (server)
  "Stop accepting connections and close every session."
  (unless (ssh-server-closed server)
    (setf (ssh-server-closed server) t)
    (let ((watcher (ssh-server-watcher server))
          (listener (ssh-server-listener server))
          (bind (ssh-server-bind server)))
      (setf (ssh-server-watcher server) nil
            (ssh-server-listener server) nil
            (ssh-server-bind server) nil)
      (when watcher (cl-pnet:fd-unwatch watcher))
      (when listener (cl-pnet-sockets:c-close listener))
      (let ((sessions (iter (for (session value) in-hashtable
                                  (ssh-server-sessions server))
                        (declare (ignore value))
                        (collect session))))
        (iter (for session in sessions)
          (ssh-session-finish session :server-closed :close)))
      (when bind (ssh-bind-free bind))))
  server)

(defun ssh-server-feature-supported-p (feature)
  "Whether the libssh server transport can honour FEATURE.

Agent forwarding is implemented; remote forwarding and X11 forwarding are
not, and the server application learns that through the facade."
  (not (null (member feature '(:agent-forward)))))

(defun ssh-server-open-forwarded-tcpip (session bind-address bind-port
                                       &rest arguments)
  "Refuse to open a forwarded-tcpip channel; libssh cannot carry one."
  (declare (ignore session bind-address bind-port arguments))
  (error 'ssh-unsupported-feature
         :feature "forwarded-tcpip"
         :detail "the libssh transport cannot open forwarded channels"))

(defun ssh-server-open-forwarded-streamlocal (session path &rest arguments)
  "Refuse to open a forwarded-streamlocal channel; libssh cannot carry one."
  (declare (ignore session path arguments))
  (error 'ssh-unsupported-feature
         :feature "forwarded-streamlocal@openssh.com"
         :detail "the libssh transport cannot open forwarded channels"))
