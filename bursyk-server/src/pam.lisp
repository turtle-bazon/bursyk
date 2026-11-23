(in-package #:bursyk-server)

;;;; PAM.  sshd delegates password, keyboard-interactive, account and session
;;;; processing to the system's Pluggable Authentication Modules when UsePAM
;;;; is on, and Linux distributions ship it that way.  This file is the
;;;; program's PAM layer: it binds libpam, carries a PAM conversation over the
;;;; existing authentication hooks, and never interprets PAM's policy itself.
;;;;
;;;; A PAM module's conversation is synchronous: pam_authenticate calls back
;;;; and waits.  The server's event loop must not wait, so keyboard-interactive
;;;; runs pam_authenticate in a worker thread and every conversation round is
;;;; handed back as one keyboard-interactive round.  Password authentication
;;;; has no round trips to spend, so it answers echo-off prompts with the
;;;; password it already has, as sshd's passwd_conv does.
;;;;
;;;; Account management, an expired-password change and the session hooks all
;;;; run through the same handle, once per connection, so a module sees one
;;;; transaction from authentication to logout.

#-win32
(progn

(cffi:define-foreign-library libpam
  (:unix (:or "libpam.so.0" "libpam.so"))
  (t (:default "libpam")))

(defvar *pam-library-loaded* nil
  "True once libpam has been loaded into this process.")

(defun load-pam ()
  "Load libpam, answering whether the system has it."
  (unless *pam-library-loaded*
    (setf *pam-library-loaded*
          (handler-case
              (progn (cffi:load-foreign-library 'libpam) t)
            (error () nil))))
  *pam-library-loaded*)

;;; Linux-PAM's flags and return values, from <security/_pam_types.h>.  They
;;; are stable ABI: the library reports them to every client.
(defconstant +pam-success+ 0)
(defconstant +pam-open-err+ 1)
(defconstant +pam-system-err+ 4)
(defconstant +pam-buf-err+ 5)
(defconstant +pam-auth-err+ 7)
(defconstant +pam-credentials-insufficient+ 8)
(defconstant +pam-authinfo-unavail+ 9)
(defconstant +pam-user-unknown+ 10)
(defconstant +pam-maxtries+ 11)
(defconstant +pam-new-authtok-reqd+ 12)
(defconstant +pam-account-expired+ 13)
(defconstant +pam-session-err+ 14)
(defconstant +pam-conv-err+ 19)
(defconstant +pam-authtok-err+ 20)
(defconstant +pam-authtok-recovery-err+ 21)
(defconstant +pam-authtok-lock-busy+ 22)
(defconstant +pam-authtok-disable-aging+ 23)
(defconstant +pam-try-again+ 24)
(defconstant +pam-ignore+ 25)
(defconstant +pam-abort+ 26)

(defconstant +pam-silent+ #x8000)
(defconstant +pam-disallow-null-authtok+ #x0001)
(defconstant +pam-change-expired-authtok+ #x0004)
(defconstant +pam-establish-cred+ #x0001)
(defconstant +pam-delete-cred+ #x0002)
(defconstant +pam-reinitialize-cred+ #x0004)
(defconstant +pam-refresh-cred+ #x0008)

(defconstant +pam-prompt-echo-off+ 1)
(defconstant +pam-prompt-echo-on+ 2)
(defconstant +pam-error-msg+ 3)
(defconstant +pam-text-info+ 4)

(defconstant +pam-service-item+ 1)
(defconstant +pam-user-item+ 2)
(defconstant +pam-tty-item+ 3)
(defconstant +pam-rhost-item+ 4)
(defconstant +pam-conv-item+ 5)
(defconstant +pam-authtok-item+ 6)
(defconstant +pam-ruser-item+ 8)

(cffi:defcstruct pam-message
  (msg-style :int)
  (msg :pointer))

(cffi:defcstruct pam-response
  (resp :pointer)
  (resp-retcode :int))

(cffi:defcstruct pam-conv
  (conv :pointer)
  (appdata-ptr :pointer))

(cffi:defcfun ("pam_strerror" %pam-strerror) :pointer
  (handle :pointer) (status :int))

(cffi:defcfun ("pam_start" %pam-start) :int
  (service :string) (user :string) (conversation :pointer) (handle :pointer))

(cffi:defcfun ("pam_start_confdir" %pam-start-confdir) :int
  (service :string) (user :string) (conversation :pointer) (confdir :string)
  (handle :pointer))

(cffi:defcfun ("pam_end" %pam-end) :int
  (handle :pointer) (status :int))

(cffi:defcfun ("pam_set_item" %pam-set-item) :int
  (handle :pointer) (item :int) (value :pointer))

(cffi:defcfun ("pam_get_item" %pam-get-item) :int
  (handle :pointer) (item :int) (value :pointer))

(cffi:defcfun ("pam_authenticate" %pam-authenticate) :int
  (handle :pointer) (flags :int))

(cffi:defcfun ("pam_acct_mgmt" %pam-acct-mgmt) :int
  (handle :pointer) (flags :int))

(cffi:defcfun ("pam_chauthtok" %pam-chauthtok) :int
  (handle :pointer) (flags :int))

(cffi:defcfun ("pam_setcred" %pam-setcred) :int
  (handle :pointer) (flags :int))

(cffi:defcfun ("pam_open_session" %pam-open-session) :int
  (handle :pointer) (flags :int))

(cffi:defcfun ("pam_close_session" %pam-close-session) :int
  (handle :pointer) (flags :int))

(cffi:defcfun ("pam_getenvlist" %pam-getenvlist) :pointer
  (handle :pointer))

(cffi:defcfun ("pam_putenv" %pam-putenv) :int
  (handle :pointer) (assignment :string))

(cffi:defcfun ("free" c-free) :void
  (pointer :pointer))

(defvar *pam-conf-dir* nil
  "A configuration directory for PAM instead of /etc/pam.d.

Linux-PAM 1.4 added pam_start_confdir.  The tests use it to load fixture
services without touching the system's PAM configuration.")

(defvar *pam-conversation-handler* nil
  "The Lisp function answering the PAM conversation on this thread.

It receives the number of messages, the C array of PAM messages and the C
array of responses to fill.  It is a special because PAM calls back on the
thread that called pam_authenticate.")

(defun pam-message-at (messages index)
  "The style and text of MESSAGES[INDEX]."
  (let* ((message (cffi:mem-aref messages :pointer index))
         (style (cffi:foreign-slot-value
                 message '(:struct pam-message) 'msg-style))
         (text (cffi:foreign-slot-value
                message '(:struct pam-message) 'msg)))
    (values style (if (cffi:null-pointer-p text)
                      ""
                      (cffi:foreign-string-to-lisp text)))))

(defun pam-response-at (responses index)
  "A pointer to RESPONSES[INDEX], a struct pam_response.

MEM-AREF of an aggregate type yields the struct's value, so MEM-APTR is the
accessor that can be handed to FOREIGN-SLOT-VALUE."
  (cffi:mem-aptr responses '(:struct pam-response) index))

(defun pam-response-resp (response)
  (cffi:foreign-slot-value response '(:struct pam-response) 'resp))

(defun (setf pam-response-resp) (value response)
  (setf (cffi:foreign-slot-value response '(:struct pam-response) 'resp)
        value))

(defun pam-response-retcode (response)
  (cffi:foreign-slot-value response '(:struct pam-response) 'resp-retcode))

(defun (setf pam-response-retcode) (value response)
  (setf (cffi:foreign-slot-value response '(:struct pam-response)
                                 'resp-retcode)
        value))

(cffi:defcallback pam-conversation :int
    ((count :int) (messages :pointer) (responses :pointer) (appdata :pointer))
  (declare (ignore appdata))
  (handler-case
      (let ((handler *pam-conversation-handler*))
        (if handler
            (funcall handler count messages responses)
            +pam-conv-err+))
    (error () +pam-conv-err+)))

(defvar *pam-conversation* (cffi:foreign-alloc '(:struct pam-conv))
  "The pam_conv handed to libpam; its conversation is always the callback.")

(defun pam-conversation-pointer ()
  (setf (cffi:foreign-slot-value *pam-conversation* '(:struct pam-conv)
                                 'conv)
        (cffi:callback pam-conversation)
        (cffi:foreign-slot-value *pam-conversation* '(:struct pam-conv)
                                 'appdata-ptr)
        (cffi:null-pointer))
  *pam-conversation*)

(defun pam-allocate-responses (count)
  (let ((responses (cffi:foreign-alloc '(:struct pam-response)
                                       :count (max count 1))))
    (dotimes (index (max count 1))
      (let ((response (pam-response-at responses index)))
        (setf (pam-response-resp response) (cffi:null-pointer)
              (pam-response-retcode response) 0)))
    responses))

(defun pam-free-responses (responses count)
  (dotimes (index (max count 1))
    (let ((pointer (pam-response-resp (pam-response-at responses index))))
      (unless (cffi:null-pointer-p pointer)
        (cffi:foreign-string-free pointer))))
  (cffi:foreign-free responses))

(defun pam-answer-response (response text)
  (setf (pam-response-resp response)
        (cffi:foreign-string-alloc (or text ""))
        (pam-response-retcode response) 0))

(defun pam-status-text (handle status)
  "STATUS as libpam describes it, or a plain number when it cannot."
  (when handle
    (handler-case
        (let ((pointer (%pam-strerror handle status)))
          (unless (cffi:null-pointer-p pointer)
            (return-from pam-status-text
              (cffi:foreign-string-to-lisp pointer))))
      (error () nil)))
  (format nil "PAM status ~D" status))

(defun pam-error (context handle status)
  (error 'cl-pnet-ssh:ssh-connection-error
         :detail (format nil "~A: ~A" context
                         (pam-status-text handle status))))

;;; ---- conversation handlers ----

(defun pam-text-message-p (style)
  (or (= style +pam-error-msg+) (= style +pam-text-info+)))

(defun pam-converse-password (count messages responses password collected)
  "Answer PAM's password conversation with PASSWORD.

An echo-off prompt gets the password, as sshd's passwd_conv does; text and
error messages are collected for the client's banner.  An echo-on prompt or
any other style fails, because password authentication has no way to ask the
user a second question."
  (let ((array (pam-allocate-responses count)))
    (handler-case
        (progn
          (dotimes (index count)
            (multiple-value-bind (style text)
                (pam-message-at messages index)
              (let ((response (pam-response-at array index)))
                (cond
                  ((= style +pam-prompt-echo-off+)
                   (if (null password)
                       (error "PAM asked for a password but none was given")
                       (pam-answer-response response password)))
                  ((pam-text-message-p style)
                   (when (plusp (length text))
                     (push text (car collected))))
                  (t
                   (error
                    "PAM asked a question password authentication cannot answer"))))))
          (setf (cffi:mem-ref responses :pointer) array)
          +pam-success+)
      (error ()
        (pam-free-responses array count)
        +pam-conv-err+))))

(defun pam-converse-store (count messages responses collected)
  "Collect text messages and refuse every prompt, as sshd's store_conv."
  (let ((array (pam-allocate-responses count)))
    (handler-case
        (progn
          (dotimes (index count)
            (multiple-value-bind (style text)
                (pam-message-at messages index)
              (unless (pam-text-message-p style)
                (error "PAM asked a question outside an interactive round"))
              (when (plusp (length text))
                (push text (car collected)))
              (let ((response (pam-response-at array index)))
                (setf (pam-response-resp response) (cffi:null-pointer)
                      (pam-response-retcode response) 0))))
          (setf (cffi:mem-ref responses :pointer) array)
          +pam-success+)
      (error ()
        (pam-free-responses array count)
        +pam-conv-err+))))

;;; ---- handle and item management ----

(defun pam-start (service user &key (conf-dir *pam-conf-dir*))
  "Start a PAM transaction for USER and return its handle."
  (unless (load-pam)
    (error 'cl-pnet-ssh:ssh-connection-error :detail "libpam is not available"))
  (cffi:with-foreign-object (handle :pointer)
    (setf (cffi:mem-ref handle :pointer) (cffi:null-pointer))
    (flet ((finish (status)
             (if (= status +pam-success+)
                 (cffi:mem-ref handle :pointer)
                 (progn
                   ;; pam_start may have produced a handle even on failure;
                   ;; end it so the partial transaction is not left behind.
                   (let ((created (cffi:mem-ref handle :pointer)))
                     (unless (cffi:null-pointer-p created)
                       (%pam-end created status)))
                   (pam-error "pam_start" nil status)))))
      (if conf-dir
          (let ((symbol (cffi:foreign-symbol-pointer "pam_start_confdir"
                                                     :library 'libpam)))
            (unless symbol
              (error 'cl-pnet-ssh:ssh-connection-error
                     :detail "this libpam has no pam_start_confdir"))
            (finish
             (cffi:foreign-funcall-pointer
              symbol ()
              :string service :string user
              :pointer (pam-conversation-pointer)
              :string (if (stringp conf-dir) conf-dir (namestring conf-dir))
              :pointer handle
              :int)))
          (finish (%pam-start service user (pam-conversation-pointer)
                              handle))))))

(defun pam-end (handle status)
  (when (and handle (not (cffi:null-pointer-p handle)))
    (ignore-errors (%pam-end handle status)))
  nil)

(defun pam-set-string (handle item value &key (context "pam_set_item"))
  (let ((pointer (cffi:foreign-string-alloc value)))
    (unwind-protect
         (let ((status (%pam-set-item handle item pointer)))
           (unless (= status +pam-success+)
             (pam-error context handle status)))
      (cffi:foreign-string-free pointer))))

(defun pam-get-user (handle)
  (cffi:with-foreign-object (value :pointer)
    (let ((status (%pam-get-item handle +pam-user-item+ value)))
      (when (= status +pam-success+)
        (let ((pointer (cffi:mem-ref value :pointer)))
          (unless (cffi:null-pointer-p pointer)
            (cffi:foreign-string-to-lisp pointer)))))))

(defun pam-putenv (handle assignment)
  (let ((status (%pam-putenv handle assignment)))
    (unless (= status +pam-success+)
      (pam-error "pam_putenv" handle status))))

(defun pam-environment (handle)
  "HANDLE's PAM environment as a list of NAME=VALUE strings."
  (let ((array (%pam-getenvlist handle)))
    (if (cffi:null-pointer-p array)
        '()
        (unwind-protect
             (loop for index from 0
                   for pointer = (cffi:mem-aref array :pointer index)
                   until (cffi:null-pointer-p pointer)
                   collect (cffi:foreign-string-to-lisp pointer))
          ;; pam_getenvlist gives ownership of the vector and its strings.
          (loop for index from 0
                for pointer = (cffi:mem-aref array :pointer index)
                until (cffi:null-pointer-p pointer)
                do (c-free pointer))
          (c-free array)))))

;;; ---- non-interactive operations ----

(defun pam-authenticate-password (handle password &key permit-empty)
  "Authenticate PASSWORD, returning (VALUES STATUS MESSAGES).

An empty password is refused unless PERMIT-EMPTY, and libpam is told the same
with PAM_DISALLOW_NULL_AUTHTOK so a module cannot quietly accept one."
  (let ((collected (list nil)))
    (let ((*pam-conversation-handler*
            (lambda (count message-pointers response-pointers)
              (pam-converse-password count message-pointers response-pointers
                                     password collected))))
      (values (%pam-authenticate
               handle
               (if permit-empty 0 +pam-disallow-null-authtok+))
              (nreverse (car collected))))))

(defun pam-store-call (handle call)
  "Run CALL on HANDLE, collecting PAM's text messages for the banner."
  (let ((collected (list nil)))
    (let ((*pam-conversation-handler*
            (lambda (count message-pointers response-pointers)
              (pam-converse-store count message-pointers response-pointers
                                  collected))))
      (values (funcall call handle) (nreverse (car collected))))))

(defun pam-account (handle)
  (pam-store-call handle (lambda (h) (%pam-acct-mgmt h 0))))

(defun pam-establish-credentials (handle)
  (pam-store-call handle
                  (lambda (h) (%pam-setcred h +pam-establish-cred+))))

(defun pam-delete-credentials (handle)
  (pam-store-call handle
                  (lambda (h) (%pam-setcred h +pam-delete-cred+))))

(defun pam-change-expired-password (handle)
  (pam-store-call handle
                  (lambda (h)
                    (%pam-chauthtok h +pam-change-expired-authtok+))))

;;; ---- keyboard-interactive bridge ----

(defstruct (pam-attempt (:constructor %make-pam-attempt
                                     (&key handle user service permit-empty)))
  handle
  user
  service
  (permit-empty nil)
  (lock (bordeaux-threads:make-lock "pam attempt"))
  (condition (bordeaux-threads:make-condition-variable
              :name "pam attempt"))
  ;; Conversation rounds not yet handed to the event loop, oldest first.
  (events '())
  ;; The client's answers for the round that is out, if any.
  reply
  (reply-ready nil)
  (cancelled nil)
  (done nil)
  (status nil)
  thread)

(defvar *pam-attempt* nil
  "The attempt whose PAM conversation is running on this thread.")

(defun pam-attempt-notify (attempt)
  (bordeaux-threads:condition-notify (pam-attempt-condition attempt)))

(defun pam-attempt-publish (attempt event)
  (bordeaux-threads:with-lock-held ((pam-attempt-lock attempt))
    (setf (pam-attempt-events attempt)
          (nconc (pam-attempt-events attempt) (list event)))
    (pam-attempt-notify attempt)))

(defun pam-attempt-ask (attempt texts prompts)
  "Publish one conversation round and wait for the client's answers."
  (pam-attempt-publish attempt (list :round texts prompts))
  (bordeaux-threads:with-lock-held ((pam-attempt-lock attempt))
    (loop until (or (pam-attempt-cancelled attempt)
                    (pam-attempt-reply-ready attempt))
          do (bordeaux-threads:condition-wait
              (pam-attempt-condition attempt)
              (pam-attempt-lock attempt)))
    (if (pam-attempt-cancelled attempt)
        (error "the PAM conversation was cancelled")
        (prog1 (pam-attempt-reply attempt)
          (setf (pam-attempt-reply attempt) nil
                (pam-attempt-reply-ready attempt) nil)))))

(defun pam-attempt-tell (attempt texts)
  "Publish a text-only round; PAM does not wait for an answer."
  (pam-attempt-publish attempt (list :round texts '())))

(defun pam-converse-interactive (count messages responses)
  "Carry one PAM conversation round to the client and back.

Every message in one PAM conversation call becomes one INFO_REQUEST: text
messages form its instruction and prompts become its prompts.  sshd sends
each text message as its own zero-prompt request; combining them with a
prompt keeps the user's answers aligned with the prompts PAM asked."
  (let ((attempt *pam-attempt*)
        (array (pam-allocate-responses count))
        (texts '())
        (prompts '())
        (prompt-indices '()))
    (if (null attempt)
        (progn
          (pam-free-responses array count)
          +pam-conv-err+)
        (handler-case
            (progn
              (dotimes (index count)
                (multiple-value-bind (style text)
                    (pam-message-at messages index)
                  (cond
                    ((or (= style +pam-prompt-echo-off+)
                         (= style +pam-prompt-echo-on+))
                     (push (list text (= style +pam-prompt-echo-on+)) prompts)
                     (push index prompt-indices))
                    ((pam-text-message-p style)
                     (when (plusp (length text))
                       (push text texts)))
                    (t
                     (error "PAM used an unsupported message style")))))
              (setf prompts (nreverse prompts)
                    prompt-indices (nreverse prompt-indices)
                    texts (nreverse texts))
              (if prompts
                  (let ((answers (pam-attempt-ask attempt texts prompts)))
                    (loop for index in prompt-indices
                          for answer in answers
                          do (pam-answer-response
                              (pam-response-at array index) answer)))
                  ;; Text alone never needs an answer from the client; the
                  ;; event loop still shows it before the login continues.
                  ;; An empty message is not worth a round of its own.
                  (when texts
                    (pam-attempt-tell attempt texts)))
              (setf (cffi:mem-ref responses :pointer) array)
              +pam-success+)
          (error ()
            (pam-free-responses array count)
            +pam-conv-err+)))))

(defun pam-attempt-next-event (attempt timeout)
  "The next event from ATTEMPT, or :TIMEOUT.

Events are (:ROUND TEXTS PROMPTS) or (:DONE STATUS)."
  (bordeaux-threads:with-lock-held ((pam-attempt-lock attempt))
    (loop
      (when (pam-attempt-events attempt)
        (return (pop (pam-attempt-events attempt))))
      (when (pam-attempt-done attempt)
        (return (list :done (pam-attempt-status attempt))))
      (unless (bordeaux-threads:condition-wait
               (pam-attempt-condition attempt)
               (pam-attempt-lock attempt)
               :timeout timeout)
        (return :timeout)))))

(defun pam-attempt-answer (attempt answers)
  "Give ATTEMPT the client's ANSWERS for the round that is out."
  (bordeaux-threads:with-lock-held ((pam-attempt-lock attempt))
    (setf (pam-attempt-reply attempt) (copy-list answers)
          (pam-attempt-reply-ready attempt) t)
    (pam-attempt-notify attempt)))

(defun pam-attempt-cancel (attempt)
  "Tell ATTEMPT's worker to stop; the worker owns the handle afterwards."
  (when attempt
    (bordeaux-threads:with-lock-held ((pam-attempt-lock attempt))
      (setf (pam-attempt-cancelled attempt) t)
      (pam-attempt-notify attempt))))

(defun pam-attempt-join (attempt)
  (when (and attempt (pam-attempt-thread attempt))
    (bordeaux-threads:join-thread (pam-attempt-thread attempt)))
  attempt)

(defun pam-run-interactive (attempt)
  "Run pam_authenticate, account management and a password change for ATTEMPT.

This is sshd's PAM keyboard-interactive thread: an expired password is
changed in the same conversation before the login is accepted."
  (let* ((handle (pam-attempt-handle attempt))
         (*pam-attempt* attempt)
         (*pam-conversation-handler* #'pam-converse-interactive)
         (status (%pam-authenticate
                  handle (if (pam-attempt-permit-empty attempt)
                             0 +pam-disallow-null-authtok+))))
    (when (= status +pam-success+)
      (let ((pam-user (pam-get-user handle)))
        (unless (and pam-user
                     (string= pam-user (pam-attempt-user attempt)))
          (setf status +pam-user-unknown+))))
    (when (= status +pam-success+)
      (setf status (%pam-acct-mgmt handle 0)))
    (when (= status +pam-new-authtok-reqd+)
      (setf status (%pam-chauthtok handle +pam-change-expired-authtok+)))
    status))

(defun pam-start-interactive (handle user service &key permit-empty)
  "Start the PAM conversation for HANDLE in a worker; return the ATTEMPT."
  (let ((attempt (%make-pam-attempt
                  :handle handle :user user :service service
                  :permit-empty permit-empty)))
    (setf (pam-attempt-thread attempt)
          (bordeaux-threads:make-thread
           (lambda ()
             (let ((status +pam-system-err+))
               (handler-case
                   (setf status (pam-run-interactive attempt))
                 (error () (setf status +pam-system-err+)))
               (bordeaux-threads:with-lock-held ((pam-attempt-lock attempt))
                 (setf (pam-attempt-done attempt) t
                       (pam-attempt-status attempt) status)
                 ;; A cancelled attempt is no longer the program's: the
                 ;; session is closing, so this thread ends the transaction.
                 (when (pam-attempt-cancelled attempt)
                   (ignore-errors (%pam-end (pam-attempt-handle attempt)
                                            status))
                   (setf (pam-attempt-handle attempt) nil))
                 (pam-attempt-notify attempt))))
           :name "bursyk-server PAM"))
    attempt))

;;; ---- per-session state ----

(defparameter +pam-login-timeout+ 120
  "Seconds to wait for one PAM conversation round before giving up.

sshd's LoginGraceTime bounds the whole exchange; this only keeps a broken
module from stalling the event loop forever.")

(defstruct (pam-session (:constructor %make-pam-session (&key user)))
  user
  handle
  attempt
  ;; :PROMPT when a prompted round is out, :TEXT for a text-only round, NIL
  ;; when the worker owes nothing.
  (pending nil)
  (accounted nil)
  (authenticated nil)
  (credentials nil)
  (session-open nil)
  (force-change nil)
  (environment '()))

(defvar *pam-sessions* (make-hash-table :test #'eq)
  "PAM state per connection, keyed by the session that owns it.")

(defun pam-abandon-attempt (state)
  "Cancel and join STATE's worker, dropping the handle it ended."
  (let ((attempt (pam-session-attempt state)))
    (when attempt
      (pam-attempt-cancel attempt)
      (pam-attempt-join attempt)
      ;; The worker ends a cancelled transaction itself.
      (unless (pam-attempt-handle attempt)
        (setf (pam-session-handle state) nil))
      (setf (pam-session-attempt state) nil))))

(defun pam-forget-session (state)
  "End STATE's PAM transaction so a different account can start afresh."
  (pam-abandon-attempt state)
  (let ((handle (pam-session-handle state)))
    (when handle
      (ignore-errors (%pam-end handle +pam-success+))
      (setf (pam-session-handle state) nil)))
  (setf (pam-session-accounted state) nil
        (pam-session-authenticated state) nil
        (pam-session-credentials state) nil
        (pam-session-session-open state) nil
        (pam-session-force-change state) nil
        (pam-session-environment state) '()))

(defun pam-enabled-p (session)
  "Whether SESSION's configuration asked for PAM.

There is no session before a connection, and no sshd_config is UsePAM's
default of off, so both answer nil."
  (and session
       (eq (cl-pnet-ssh:ssh-session-setting
            session #'cl-pnet-ssh:ssh-server-config-use-pam)
           :yes)))

(defun pam-session-for (session user)
  "SESSION's PAM state for USER, starting over when the name changes.

A PAM handle is authenticated as one account, so reusing it for a second
name would admit that name on the first one's credentials.  sshd keeps one
Authctxt per connection; this does the equivalent for PAM."
  (let ((state (gethash session *pam-sessions*)))
    (cond
      ((null state)
       (setf (gethash session *pam-sessions*)
             (%make-pam-session :user user)))
      ((string= (pam-session-user state) user)
       state)
      (t
       (pam-forget-session state)
       (setf (pam-session-user state) user)
       state))))

(defun pam-session-service (session)
  (or (cl-pnet-ssh:ssh-session-setting
       session #'cl-pnet-ssh:ssh-server-config-pam-service-name)
      "sshd"))

(defun pam-permit-empty-p (session)
  (eq (cl-pnet-ssh:ssh-session-setting
       session #'cl-pnet-ssh:ssh-server-config-permit-empty-passwords)
      :yes))

(defun pam-ensure-handle (state session)
  "STATE's PAM handle, starting a transaction on first use."
  (or (pam-session-handle state)
      (let ((handle (pam-start (pam-session-service session)
                               (pam-session-user state))))
        ;; sshd sets PAM_TTY to "ssh" because modules such as pam_time demand
        ;; a tty before one has been allocated, and PAM_RHOST to the peer.
        (handler-case
            (pam-set-string handle +pam-tty-item+ "ssh")
          (error () nil))
        (let ((remote (cl-pnet-ssh:ssh-session-remote-ip session)))
          (when remote
            (handler-case
                (pam-set-string handle +pam-rhost-item+ remote)
              (error () nil))))
        ;; sshd exposes the authentication information to account and
        ;; session modules as SSH_AUTH_INFO_0.
        (handler-case
            (pam-putenv handle
                        (format nil "SSH_AUTH_INFO_0=~A"
                                (or (pam-auth-info-text session) "")))
          (error () nil))
        (setf (pam-session-handle state) handle)
        handle)))

(defun pam-auth-info-text (session)
  (let ((lines (cl-pnet-ssh:ssh-session-auth-info-lines session)))
    (when lines
      (with-output-to-string (stream)
        (dolist (line lines)
          (write-string line stream)
          (terpri stream))))))

(defun pam-record-messages (session messages)
  "Add MESSAGES to the banner sent just before USERAUTH_SUCCESS."
  (dolist (message messages)
    (let ((text (string-right-trim '(#\Return #\Linefeed) message)))
      (when (plusp (length text))
        (push text (cl-pnet-ssh:ssh-session-login-messages session))))))

(defun pam-check-account (state session handle status)
  "Verify PAM kept the user and run account management after STATUS."
  (when (= status +pam-success+)
    (let ((pam-user (pam-get-user handle)))
      (unless (and pam-user
                   (string= pam-user (pam-session-user state)))
        (setf status +pam-user-unknown+))))
  (when (= status +pam-success+)
    (multiple-value-bind (account messages) (pam-account handle)
      (pam-record-messages session messages)
      (cond
        ((= account +pam-success+)
         (setf status +pam-success+))
        ((= account +pam-new-authtok-reqd+)
         ;; sshd lets the login continue and marks the session for a forced
         ;; password change; keyboard-interactive changes it inline, and a
         ;; password login is restricted to a tty.
         (setf (pam-session-force-change state) t
               status +pam-success+))
        (t
         (setf status account)))))
  status)

(defun pam-password-check (session user password)
  "Authenticate USER's PASSWORD with PAM, answering whether it succeeded."
  (unless (pam-enabled-p session)
    (return-from pam-password-check nil))
  (let* ((state (pam-session-for session user))
         (handle (pam-ensure-handle state session)))
    (multiple-value-bind (status messages)
        (pam-authenticate-password handle password
                                   :permit-empty (pam-permit-empty-p session))
      (pam-record-messages session messages)
      (setf status (pam-check-account state session handle status))
      (when (= status +pam-success+)
        (setf (pam-session-authenticated state) t
              (pam-session-accounted state) t)
        t))))

(defun pam-keyboard-interactive (session user request)
  "PAM keyboard-interactive, as one round per answer.

REQUEST carries the previous round's answers; the first call starts the PAM
transaction.  An expired password is changed before :SUCCESS."
  (unless (pam-enabled-p session)
    (return-from pam-keyboard-interactive :failure))
  (let* ((state (pam-session-for session user))
         (attempt (pam-session-attempt state))
         (responses (getf request :responses)))
    (unless attempt
      (let ((handle (pam-ensure-handle state session)))
        (setf attempt (pam-start-interactive
                       handle user (pam-session-service session)
                       :permit-empty (pam-permit-empty-p session))
              (pam-session-attempt state) attempt
              (pam-session-pending state) nil)))
    (when (eq (pam-session-pending state) :prompt)
      (pam-attempt-answer attempt responses))
    (setf (pam-session-pending state) nil)
    (loop
      (let ((event (pam-attempt-next-event attempt +pam-login-timeout+)))
        (cond
          ((eq event :timeout)
           (pam-abandon-attempt state)
           (return :failure))
          ((eq (first event) :done)
           (pam-attempt-join attempt)
           (setf (pam-session-attempt state) nil)
           (let ((status (second event)))
             (if (= status +pam-success+)
                 (progn
                   (setf (pam-session-authenticated state) t
                         (pam-session-accounted state) t)
                   (return :success))
                 (return :failure))))
          (t
           (destructuring-bind (mark texts prompts) event
             (declare (ignore mark))
             (setf (pam-session-pending state)
                   (if prompts :prompt :text))
             (return
               (list :name ""
                     :instruction (format nil "~{~A~^~%~}" texts)
                     :prompts prompts)))))))))

(defun pam-authorize-login (session user)
  "Run PAM account management for a method that did not authenticate via PAM.

Password and keyboard-interactive already ran it on the same handle, so the
flag keeps a module from being asked twice."
  (if (not (pam-enabled-p session))
      t
      (let* ((state (pam-session-for session user))
             (handle (pam-ensure-handle state session)))
        (if (pam-session-accounted state)
            t
            (multiple-value-bind (status messages) (pam-account handle)
              (pam-record-messages session messages)
              (setf (pam-session-accounted state) t)
              (cond
                ((= status +pam-success+) t)
                ((= status +pam-new-authtok-reqd+)
                 (setf (pam-session-force-change state) t)
                 t)
                (t nil)))))))

(defun pam-open-session (session)
  "Establish credentials and open SESSION's PAM session."
  (when (pam-enabled-p session)
    (let ((state (gethash session *pam-sessions*)))
      (when (and state (pam-session-handle state))
        (let ((handle (pam-session-handle state)))
          ;; Now that every method has succeeded, refresh the authentication
          ;; information sshd exposes to session modules.
          (handler-case
              (pam-putenv handle
                          (format nil "SSH_AUTH_INFO_0=~A"
                                  (or (pam-auth-info-text session) "")))
            (error () nil))
          (multiple-value-bind (status messages)
              (pam-establish-credentials handle)
            (when (= status +pam-success+)
              (setf (pam-session-credentials state) t))
            (pam-record-messages session messages))
          (multiple-value-bind (status messages)
              (pam-store-call handle (lambda (h) (%pam-open-session h 0)))
            (when (= status +pam-success+)
              (setf (pam-session-session-open state) t))
            (pam-record-messages session messages))
          (handler-case
              (setf (pam-session-environment state) (pam-environment handle))
            (error () nil)))))))

(defun pam-close-session (session)
  "Close and end SESSION's PAM transaction, if one was started."
  (let ((state (gethash session *pam-sessions*)))
    (when state
      (pam-abandon-attempt state)
      (let ((handle (pam-session-handle state)))
        (when handle
          (let ((*pam-conversation-handler*
                  (lambda (count messages responses)
                    (pam-converse-store count messages responses (list nil)))))
            (when (pam-session-session-open state)
              (ignore-errors (%pam-close-session handle +pam-silent+)))
            (when (pam-session-credentials state)
              (ignore-errors (%pam-setcred handle +pam-delete-cred+)))
            (ignore-errors (%pam-end handle +pam-success+)))))
      (remhash session *pam-sessions*))))

(defun pam-name-denied-p (name)
  (flet ((prefix (string prefix)
           (let ((length (length prefix)))
             (and (>= (length string) length)
                  (string= string prefix :end1 length)))))
    (or (prefix name "SSH_AUTH_INFO")
        (prefix name "SSH_CONNECTION"))))

(defun pam-environment-for-session (session)
  "The PAM environment SESSION should inherit, without sshd's own entries."
  (let ((state (gethash session *pam-sessions*)))
    (when state
      (remove-if
       (lambda (assignment)
         (let ((equals (position #\= assignment)))
           (and equals (pam-name-denied-p (subseq assignment 0 equals)))))
       (pam-session-environment state)))))

(setf *session-environment-extension* #'pam-environment-for-session)

) ; #-win32
