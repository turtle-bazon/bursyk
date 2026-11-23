(in-package #:cl-pnet-ssh)

;;;; CFFI bindings for libssh 0.10.  Only what the two roles use is bound:
;;;; sessions, options, authentication, channels, and the server message API.
;;;;
;;;; libssh is loaded at run time.  A build with :ssh-backend-ffi needs the
;;;; shared object present; the pure bursyk backend needs nothing from here.

(cffi:define-foreign-library libssh
  (:unix (:or "libssh.so.4" "libssh.so" "libssh.dylib" "libssh.so.0"))
  (:windows (:or "ssh.dll" "libssh.dll"))
  (t (:default "libssh")))

(unless (cffi:foreign-library-loaded-p 'libssh)
  (cffi:use-foreign-library libssh))

;;; A session needs a readable watcher and, while libssh has bytes it could
;;; not send, a writable one.  CL-PNET's libuv and puma backends register one
;;; watcher per descriptor, unlike libev, so the write side polls a dup of
;;; the socket instead.  The descriptor and the file description are shared;
;;; only the number the event loop registers is different.
#+unix
(cffi:defcfun ("dup" ssh-dup-fd) :int (fd :int))
#+windows
(cffi:defcfun ("_dup" ssh-dup-fd) :int (fd :int))

(cffi:defctype ssh-session :pointer)
(cffi:defctype ssh-channel :pointer)
(cffi:defctype ssh-key :pointer)
(cffi:defctype ssh-bind :pointer)
(cffi:defctype ssh-message :pointer)
(cffi:defctype ssh-string :pointer)

;;; Callback structures.  Only the fields this library fills are named, but
;;; every field up to the one used must be present, because libssh copies the
;;; opaque layout by size.  The sizes below are the ones libssh 0.10 compiles.
(cffi:defcstruct ssh-callbacks-struct
  (size :size)
  (userdata :pointer)
  (auth-function :pointer)
  (log-function :pointer)
  (connect-status-function :pointer)
  (global-request-function :pointer)
  (channel-open-request-x11-function :pointer)
  (channel-open-request-auth-agent-function :pointer))

(cffi:defcstruct ssh-channel-callbacks-struct
  (size :size)
  (userdata :pointer)
  (channel-data-function :pointer)
  (channel-eof-function :pointer)
  (channel-close-function :pointer)
  (channel-signal-function :pointer)
  (channel-exit-status-function :pointer)
  (channel-exit-signal-function :pointer)
  (channel-pty-request-function :pointer)
  (channel-shell-request-function :pointer)
  (channel-auth-agent-req-function :pointer)
  (channel-x11-req-function :pointer)
  (channel-pty-window-change-function :pointer)
  (channel-exec-request-function :pointer)
  (channel-env-request-function :pointer)
  (channel-subsystem-request-function :pointer)
  (channel-write-wontblock-function :pointer))

;;; SSH return codes.
(defconstant +ssh-ok+ 0)
(defconstant +ssh-error+ -1)
(defconstant +ssh-again+ -2)

;;; libssh reports the poll events it wants with POLLIN/POLLOUT numbers.
;;; Linux, the BSDs and Darwin all use 1 and 4, the platforms this runs on.
(defconstant +poll-in+ 1)
(defconstant +poll-out+ 4)

;;; The bits SSH_GET_POLL_FLAGS reports (not the POLLIN/POLLOUT numbers).
(defconstant +ssh-read-pending+ #x02)
(defconstant +ssh-write-pending+ #x08)

;;; enum ssh_options_e
(defconstant +ssh-options-host+ 0)
(defconstant +ssh-options-port+ 1)
(defconstant +ssh-options-fd+ 3)
(defconstant +ssh-options-user+ 4)
(defconstant +ssh-options-identity+ 6)
(defconstant +ssh-options-known-hosts+ 8)
(defconstant +ssh-options-ciphers-c-s+ 15)
(defconstant +ssh-options-ciphers-s-c+ 16)
(defconstant +ssh-options-proxy-command+ 19)
(defconstant +ssh-options-key-exchange+ 24)
(defconstant +ssh-options-hostkeys+ 25)
(defconstant +ssh-options-hmac-c-s+ 29)
(defconstant +ssh-options-hmac-s-c+ 30)
(defconstant +ssh-options-global-known-hosts+ 35)
(defconstant +ssh-options-strict-host-key-check+ 21)
(defconstant +ssh-options-publickey-accepted-types+ 37)
(defconstant +ssh-options-process-config+ 38)
(defconstant +ssh-options-identity-agent+ 42)

;;; enum ssh_bind_options_e
(defconstant +ssh-bind-options-bind-address+ 0)
(defconstant +ssh-bind-options-bind-port+ 1)
(defconstant +ssh-bind-options-host-key+ 3)
(defconstant +ssh-bind-options-banner+ 6)
(defconstant +ssh-bind-options-key-exchange+ 11)
(defconstant +ssh-bind-options-ciphers-c-s+ 12)
(defconstant +ssh-bind-options-ciphers-s-c+ 13)
(defconstant +ssh-bind-options-hmac-c-s+ 14)
(defconstant +ssh-bind-options-hmac-s-c+ 15)
(defconstant +ssh-bind-options-pubkey-accepted-key-types+ 17)
(defconstant +ssh-bind-options-hostkey-algorithms+ 18)
(defconstant +ssh-bind-options-process-config+ 19)
(defconstant +ssh-bind-options-rsa-min-size+ 21)

;;; enum ssh_requests_e
(defconstant +ssh-request-auth+ 1)
(defconstant +ssh-request-channel-open+ 2)
(defconstant +ssh-request-channel+ 3)
(defconstant +ssh-request-service+ 4)
(defconstant +ssh-request-global+ 5)

;;; enum ssh_channel_type_e / ssh_channel_requests_e
(defconstant +ssh-channel-session+ 1)
(defconstant +ssh-channel-direct-tcpip+ 2)
(defconstant +ssh-channel-request-pty+ 1)
(defconstant +ssh-channel-request-exec+ 2)
(defconstant +ssh-channel-request-shell+ 3)
(defconstant +ssh-channel-request-env+ 4)
(defconstant +ssh-channel-request-subsystem+ 5)
(defconstant +ssh-channel-request-window-change+ 6)

;;; enum ssh_publickey_state_e
(defconstant +ssh-publickey-state-none+ 0)
(defconstant +ssh-publickey-state-valid+ 1)
(defconstant +ssh-publickey-state-wrong+ 2)

;;; enum ssh_known_hosts_e
(defconstant +ssh-known-hosts-error+ -2)
(defconstant +ssh-known-hosts-not-found+ -1)
(defconstant +ssh-known-hosts-unknown+ 0)
(defconstant +ssh-known-hosts-ok+ 1)
(defconstant +ssh-known-hosts-changed+ 2)
(defconstant +ssh-known-hosts-other+ 3)

(defconstant +ssh-auth-method-none+ #x0001)
(defconstant +ssh-auth-method-password+ #x0002)
(defconstant +ssh-auth-method-publickey+ #x0004)
(defconstant +ssh-auth-method-hostbased+ #x0008)
(defconstant +ssh-auth-method-interactive+ #x0010)
(defconstant +ssh-auth-success+ 0)
(defconstant +ssh-auth-denied+ 1)
(defconstant +ssh-auth-partial+ 2)
(defconstant +ssh-auth-info+ 3)
(defconstant +ssh-auth-again+ 4)
(defconstant +ssh-auth-error+ -1)

;;; ---- Sessions and options ----

(cffi:defcfun ("ssh_new" ssh-new) ssh-session)
(cffi:defcfun ("ssh_free" ssh-free) :void (session ssh-session))
(cffi:defcfun ("ssh_disconnect" ssh-disconnect) :void (session ssh-session))
(cffi:defcfun ("ssh_connect" ssh-connect) :int (session ssh-session))
(cffi:defcfun ("ssh_options_set" ssh-options-set) :int
  (session ssh-session) (type :int) (value :pointer))
(cffi:defcfun ("ssh_set_blocking" ssh-set-blocking) :void
  (session ssh-session) (blocking :int))
(cffi:defcfun ("ssh_get_fd" ssh-get-fd) :int (session ssh-session))
(cffi:defcfun ("ssh_is_connected" ssh-is-connected) :int (session ssh-session))
(cffi:defcfun ("ssh_get_poll_flags" ssh-get-poll-flags) :int (session ssh-session))
(cffi:defcfun ("ssh_get_error" ssh-get-error) :string (session ssh-session))
(cffi:defcfun ("ssh_get_error_code" ssh-get-error-code) :int (session ssh-session))
(cffi:defcfun ("ssh_get_serverbanner" ssh-get-serverbanner) :string
  (session ssh-session))
(cffi:defcfun ("ssh_get_clientbanner" ssh-get-clientbanner) :string
  (session ssh-session))
;;; The authentication banner (USERAUTH_BANNER), not the identification
;;; string above.  libssh returns a fresh C string the caller frees.
(cffi:defcfun ("ssh_get_issue_banner" ssh-get-issue-banner) :pointer
  (session ssh-session))
(cffi:defcfun ("ssh_send_issue_banner" ssh-send-issue-banner) :int
  (session ssh-session) (banner ssh-string))
(cffi:defcfun ("ssh_string_new" ssh-string-new) ssh-string
  (size :size))
(cffi:defcfun ("ssh_string_fill" ssh-string-fill) :int
  (string ssh-string) (data :pointer) (len :size))
(cffi:defcfun ("ssh_string_free" ssh-string-free) :void
  (string ssh-string))
(cffi:defcfun ("ssh_set_auth_methods" ssh-set-auth-methods) :void
  (session ssh-session) (methods :int))
(cffi:defcfun ("ssh_send_keepalive" ssh-send-keepalive) :int
  (session ssh-session))
;; Chaff: a decoy packet an observer cannot tell from traffic.  libssh has no
;; OpenSSH PING packet, so SSH_MSG_IGNORE serves the same purpose.
(cffi:defcfun ("ssh_send_ignore" ssh-send-ignore) :int
  (session ssh-session) (data :string))

;;; ---- Host keys and known hosts ----

(cffi:defcfun ("ssh_get_server_publickey" ssh-get-server-publickey) :int
  (session ssh-session) (key (:pointer ssh-key)))
(cffi:defcfun ("ssh_pki_export_pubkey_base64" ssh-pki-export-pubkey-base64) :int
  (key ssh-key) (base64 (:pointer :string)))
(cffi:defcfun ("ssh_string_free_char" ssh-string-free-char) :void (string :pointer))
(cffi:defcfun ("ssh_key_free" ssh-key-free) :void (key ssh-key))
(cffi:defcfun ("ssh_session_is_known_server" ssh-session-is-known-server) :int
  (session ssh-session))
(cffi:defcfun ("ssh_write_knownhost" ssh-write-knownhost) :int
  (session ssh-session))

;;; ---- Client authentication ----

(cffi:defcfun ("ssh_userauth_agent" ssh-userauth-agent) :int
  (session ssh-session) (username :string))
(cffi:defcfun ("ssh_userauth_list" ssh-userauth-list) :int
  (session ssh-session) (username :string))
(cffi:defcfun ("ssh_userauth_publickey" ssh-userauth-publickey) :int
  (session ssh-session) (username :string) (key ssh-key))
(cffi:defcfun ("ssh_userauth_password" ssh-userauth-password) :int
  (session ssh-session) (username :string) (password :string))
;;; Keyboard-interactive: the first call starts the exchange; SSH_AUTH_INFO
;;; means prompts are ready, and the same call is repeated after the answers
;;; are set.  ECHO is a char the caller provides for GETPROMPT.
(cffi:defcfun ("ssh_userauth_kbdint" ssh-userauth-kbdint) :int
  (session ssh-session) (username :string) (submethods :string))
(cffi:defcfun ("ssh_userauth_kbdint_getname" ssh-userauth-kbdint-getname) :string
  (session ssh-session))
(cffi:defcfun ("ssh_userauth_kbdint_getinstruction"
          ssh-userauth-kbdint-getinstruction) :string
  (session ssh-session))
(cffi:defcfun ("ssh_userauth_kbdint_getnprompts"
          ssh-userauth-kbdint-getnprompts) :int
  (session ssh-session))
(cffi:defcfun ("ssh_userauth_kbdint_getprompt" ssh-userauth-kbdint-getprompt)
    :string
  (session ssh-session) (index :uint) (echo (:pointer :char)))
(cffi:defcfun ("ssh_userauth_kbdint_setanswer" ssh-userauth-kbdint-setanswer)
    :int
  (session ssh-session) (index :uint) (answer :string))
(cffi:defcfun ("ssh_pki_import_privkey_file" ssh-pki-import-privkey-file) :int
  (filename :string) (passphrase :string) (auth-function :pointer)
  (auth-data :pointer) (key (:pointer ssh-key)))
(cffi:defcfun ("ssh_pki_import_cert_file" ssh-pki-import-cert-file) :int
  (filename :string) (key (:pointer ssh-key)))
(cffi:defcfun ("ssh_pki_copy_cert_to_privkey" ssh-pki-copy-cert-to-privkey) :int
  (cert-key ssh-key) (private-key ssh-key))

;;; ---- Channels ----

(cffi:defcfun ("ssh_channel_new" ssh-channel-new) ssh-channel (session ssh-session))
(cffi:defcfun ("ssh_channel_free" ssh-channel-free) :void (channel ssh-channel))
(cffi:defcfun ("ssh_channel_open_session" ssh-channel-open-session) :int
  (channel ssh-channel))
(cffi:defcfun ("ssh_channel_open_auth_agent" ssh-channel-open-auth-agent) :int
  (channel ssh-channel))
(cffi:defcfun ("ssh_set_callbacks" ssh-set-callbacks) :int
  (session ssh-session) (callbacks :pointer))
(cffi:defcfun ("ssh_set_channel_callbacks" ssh-set-channel-callbacks) :int
  (channel ssh-channel) (callbacks :pointer))
(cffi:defcfun ("ssh_channel_open_forward" ssh-channel-open-forward) :int
  (channel ssh-channel) (remotehost :string) (remoteport :int)
  (sourcehost :string) (localport :int))
(cffi:defcfun ("ssh_channel_request_exec" ssh-channel-request-exec) :int
  (channel ssh-channel) (command :string))
(cffi:defcfun ("ssh_channel_request_env" ssh-channel-request-env) :int
  (channel ssh-channel) (name :string) (value :string))
(cffi:defcfun ("ssh_channel_request_pty_size" ssh-channel-request-pty-size) :int
  (channel ssh-channel) (term :string) (columns :int) (rows :int))
(cffi:defcfun ("ssh_channel_request_shell" ssh-channel-request-shell) :int
  (channel ssh-channel))
(cffi:defcfun ("ssh_channel_request_subsystem" ssh-channel-request-subsystem) :int
  (channel ssh-channel) (subsystem :string))
(cffi:defcfun ("ssh_channel_change_pty_size" ssh-channel-change-pty-size) :int
  (channel ssh-channel) (columns :int) (rows :int))
(cffi:defcfun ("ssh_channel_request_auth_agent" ssh-channel-request-auth-agent) :int
  (channel ssh-channel))
(cffi:defcfun ("ssh_channel_request_x11" ssh-channel-request-x11) :int
  (channel ssh-channel) (single-connection :int) (protocol :string)
  (cookie :string) (screen-number :int))
(cffi:defcfun ("ssh_channel_read_nonblocking" ssh-channel-read-nonblocking) :int
  (channel ssh-channel) (buffer :pointer) (length :uint32) (stderr :int))
(cffi:defcfun ("ssh_channel_poll" ssh-channel-poll) :int
  (channel ssh-channel) (stderr :int))
(cffi:defcfun ("ssh_channel_write" ssh-plibssh-channel-write) :int
  (channel ssh-channel) (buffer :pointer) (length :uint32))
(cffi:defcfun ("ssh_channel_write_stderr" ssh-plibssh-channel-write-stderr) :int
  (channel ssh-channel) (buffer :pointer) (length :uint32))
(cffi:defcfun ("ssh_channel_send_eof" ssh-channel-send-eof) :int
  (channel ssh-channel))
(cffi:defcfun ("ssh_channel_close" ssh-plibssh-channel-close) :int (channel ssh-channel))
(cffi:defcfun ("ssh_channel_is_open" ssh-channel-is-open) :int (channel ssh-channel))
(cffi:defcfun ("ssh_channel_is_closed" ssh-channel-is-closed) :int
  (channel ssh-channel))
(cffi:defcfun ("ssh_channel_is_eof" ssh-channel-is-eof) :int (channel ssh-channel))
(cffi:defcfun ("ssh_channel_get_exit_status" ssh-channel-get-exit-status) :int
  (channel ssh-channel))
(cffi:defcfun ("ssh_channel_request_send_exit_status"
          ssh-channel-request-send-exit-status) :int
  (channel ssh-channel) (status :int))

;;; ---- Server: bind, key exchange, messages ----

(cffi:defcfun ("ssh_bind_new" ssh-bind-new) ssh-bind)
(cffi:defcfun ("ssh_bind_free" ssh-bind-free) :void (bind ssh-bind))
(cffi:defcfun ("ssh_bind_options_set" ssh-bind-options-set) :int
  (bind ssh-bind) (type :int) (value :pointer))
(cffi:defcfun ("ssh_bind_listen" ssh-bind-listen) :int (bind ssh-bind))
(cffi:defcfun ("ssh_bind_get_fd" ssh-bind-get-fd) :int (bind ssh-bind))
(cffi:defcfun ("ssh_bind_accept_fd" ssh-bind-accept-fd) :int
  (bind ssh-bind) (session ssh-session) (fd :int))
(cffi:defcfun ("ssh_handle_key_exchange" ssh-handle-key-exchange) :int
  (session ssh-session))

(cffi:defcfun ("ssh_message_get" ssh-message-get) ssh-message (session ssh-session))
(cffi:defcfun ("ssh_message_free" ssh-message-free) :void (message ssh-message))
(cffi:defcfun ("ssh_message_type" ssh-message-type) :int (message ssh-message))
(cffi:defcfun ("ssh_message_subtype" ssh-message-subtype) :int (message ssh-message))
(cffi:defcfun ("ssh_message_reply_default" ssh-message-reply-default) :int
  (message ssh-message))
(cffi:defcfun ("ssh_message_service_reply_success"
          ssh-message-service-reply-success) :int
  (message ssh-message))

(cffi:defcfun ("ssh_message_auth_user" ssh-message-auth-user) :string
  (message ssh-message))
(cffi:defcfun ("ssh_message_auth_pubkey" ssh-message-auth-pubkey) ssh-key
  (message ssh-message))
(cffi:defcfun ("ssh_message_auth_publickey_state"
          ssh-message-auth-publickey-state) :int
  (message ssh-message))
(cffi:defcfun ("ssh_message_auth_set_methods" ssh-message-auth-set-methods) :int
  (message ssh-message) (methods :int))
(cffi:defcfun ("ssh_message_auth_reply_success" ssh-message-auth-reply-success) :int
  (message ssh-message) (partial :int))
(cffi:defcfun ("ssh_message_auth_reply_pk_ok_simple"
          ssh-message-auth-reply-pk-ok-simple) :int
  (message ssh-message))
(cffi:defcfun ("ssh_message_auth_password" ssh-message-auth-password) :string
  (message ssh-message))
;;; Send one keyboard-interactive INFO_REQUEST.  PROMPTS is a (char **) of
;;; NUM-PROMPTS strings and ECHO a (char *) of the same length.
(cffi:defcfun ("ssh_message_auth_interactive_request"
          ssh-message-auth-interactive-request) :int
  (message ssh-message) (name :string) (instruction :string)
  (num-prompts :uint) (prompts :pointer) (echo :pointer))
;;; True on the USERAUTH_INFO_RESPONSE that answers an INFO_REQUEST.  The
;;; answers are the same session kbdint slots the client getters read, so
;;; ssh_userauth_kbdint_getnanswers/getanswer serve the server role too.
(cffi:defcfun ("ssh_message_auth_kbdint_is_response"
          ssh-message-auth-kbdint-is-response) :int
  (message ssh-message))
(cffi:defcfun ("ssh_userauth_kbdint_getnanswers"
          ssh-userauth-kbdint-getnanswers) :int
  (session ssh-session))
(cffi:defcfun ("ssh_userauth_kbdint_getanswer" ssh-userauth-kbdint-getanswer)
    :string
  (session ssh-session) (index :uint))

(cffi:defcfun ("ssh_message_channel_request_open_destination"
          ssh-message-open-destination) :string
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_open_destination_port"
          ssh-message-open-destination-port) :int
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_open_originator"
          ssh-message-open-originator) :string
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_open_originator_port"
          ssh-message-open-originator-port) :int
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_open_reply_accept"
          ssh-message-open-reply-accept) ssh-channel
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_open_reply_accept_channel"
          ssh-message-open-reply-accept-channel) :int
  (message ssh-message) (channel ssh-channel))

(cffi:defcfun ("ssh_message_channel_request_channel"
          ssh-message-channel-request-channel) ssh-channel
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_pty_term"
          ssh-message-channel-request-pty-term) :string
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_pty_width"
          ssh-message-channel-request-pty-width) :int
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_pty_height"
          ssh-message-channel-request-pty-height) :int
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_pty_pxwidth"
          ssh-message-channel-request-pty-pxwidth) :int
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_pty_pxheight"
          ssh-message-channel-request-pty-pxheight) :int
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_command"
          ssh-message-channel-request-command) :string
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_env_name"
          ssh-message-channel-request-env-name) :string
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_env_value"
          ssh-message-channel-request-env-value) :string
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_subsystem"
          ssh-message-channel-request-subsystem) :string
  (message ssh-message))
(cffi:defcfun ("ssh_message_channel_request_reply_success"
          ssh-message-channel-request-reply-success) :int
  (message ssh-message))
(cffi:defcfun ("ssh_channel_request_send_exit_signal"
          ssh-channel-request-send-exit-signal) :int
  (channel ssh-channel) (signal :string) (core-dumped :int)
  (error-message :string) (language :string))
