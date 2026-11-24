;;;; CFFI bindings for libssh 0.10, and nothing else.
;;;;
;;;; This system must not depend on CL-SSH-CORE: a binding layer can be
;;;; loaded on its own, and the adapter that turns these calls into the
;;;; CL-PNET-SSH API lives in CL-PNET-SSH.  The functions, constants and
;;;; foreign types the adapter calls are exported here, so importing them is
;;;; a plain package operation.  Structure slot names stay internal: the
;;;; adapter qualifies the few it reads, because names such as SIZE and
;;;; USERDATA already belong to CL-PNET-SSH.

(defpackage #:cl-plibssh
  (:use #:cl)
  (:export
   #:ssh-callbacks-struct #:ssh-channel-callbacks-struct
   #:ssh-bind #:ssh-bind-accept-fd #:ssh-bind-free #:ssh-bind-get-fd
   #:ssh-bind-listen #:ssh-bind-new #:ssh-bind-options-set #:libssh-channel
   #:ssh-channel-change-pty-size #:ssh-channel-free
   #:ssh-channel-get-exit-status #:ssh-channel-is-closed #:ssh-channel-is-eof
   #:ssh-channel-is-open #:ssh-channel-new #:ssh-channel-open-auth-agent
   #:ssh-channel-open-forward #:ssh-channel-open-forward-unix
   #:ssh-channel-open-session #:ssh-channel-poll
   #:ssh-channel-read-nonblocking #:ssh-channel-request-auth-agent
   #:ssh-channel-request-env #:ssh-channel-request-exec
   #:ssh-channel-request-pty-size #:ssh-channel-request-send-exit-signal
   #:ssh-channel-request-send-exit-status #:ssh-channel-request-shell
   #:ssh-channel-request-subsystem #:ssh-channel-request-x11
   #:ssh-channel-send-eof #:ssh-connect #:ssh-disconnect #:ssh-dup-fd
   #:ssh-free #:ssh-get-cipher-in #:ssh-get-cipher-out #:ssh-get-clientbanner
   #:ssh-get-error #:ssh-get-error-code #:ssh-get-fd #:ssh-get-hmac-in
   #:ssh-get-hmac-out #:ssh-get-issue-banner #:ssh-get-kex-algo
   #:ssh-get-poll-flags #:ssh-get-server-publickey #:ssh-get-serverbanner
   #:ssh-handle-key-exchange #:ssh-is-connected #:ssh-key #:ssh-key-free
   #:ssh-message #:ssh-message-auth-interactive-request
   #:ssh-message-auth-kbdint-is-response #:ssh-message-auth-password
   #:ssh-message-auth-pubkey #:ssh-message-auth-publickey-state
   #:ssh-message-auth-reply-pk-ok-simple #:ssh-message-auth-reply-success
   #:ssh-message-auth-set-methods #:ssh-message-auth-user
   #:ssh-message-channel-request-channel
   #:ssh-message-channel-request-command
   #:ssh-message-channel-request-env-name
   #:ssh-message-channel-request-env-value
   #:ssh-message-channel-request-pty-height
   #:ssh-message-channel-request-pty-pxheight
   #:ssh-message-channel-request-pty-pxwidth
   #:ssh-message-channel-request-pty-term
   #:ssh-message-channel-request-pty-width
   #:ssh-message-channel-request-reply-success
   #:ssh-message-channel-request-subsystem #:ssh-message-free
   #:ssh-message-get #:ssh-message-open-destination
   #:ssh-message-open-destination-port #:ssh-message-open-originator
   #:ssh-message-open-originator-port #:ssh-message-open-reply-accept
   #:ssh-message-open-reply-accept-channel #:ssh-message-reply-default
   #:ssh-message-service-reply-success #:ssh-message-subtype
   #:ssh-message-type #:ssh-new #:ssh-options-set
   #:ssh-pki-copy-cert-to-privkey #:ssh-pki-export-pubkey-base64
   #:ssh-pki-import-cert-file #:ssh-pki-import-privkey-file
   #:ssh-plibssh-channel-close #:ssh-plibssh-channel-write
   #:ssh-plibssh-channel-write-stderr #:ssh-send-ignore
   #:ssh-send-issue-banner #:ssh-send-keepalive #:libssh-session
   #:ssh-session-is-known-server #:ssh-set-auth-methods #:ssh-set-blocking
   #:ssh-set-callbacks #:ssh-set-channel-callbacks #:ssh-string
   #:ssh-string-fill #:ssh-string-free #:ssh-string-free-char
   #:ssh-string-new #:ssh-userauth-agent #:ssh-userauth-kbdint
   #:ssh-userauth-kbdint-getanswer #:ssh-userauth-kbdint-getinstruction
   #:ssh-userauth-kbdint-getname #:ssh-userauth-kbdint-getnanswers
   #:ssh-userauth-kbdint-getnprompts #:ssh-userauth-kbdint-getprompt
   #:ssh-userauth-kbdint-setanswer #:ssh-userauth-list
   #:ssh-userauth-password #:ssh-userauth-publickey #:ssh-write-knownhost
   #:+poll-in+ #:+poll-out+ #:+ssh-again+ #:+ssh-auth-again+
   #:+ssh-auth-denied+ #:+ssh-auth-error+ #:+ssh-auth-info+
   #:+ssh-auth-method-hostbased+ #:+ssh-auth-method-interactive+
   #:+ssh-auth-method-none+ #:+ssh-auth-method-password+
   #:+ssh-auth-method-publickey+ #:+ssh-auth-partial+ #:+ssh-auth-success+
   #:+ssh-bind-options-banner+ #:+ssh-bind-options-bind-address+
   #:+ssh-bind-options-bind-port+ #:+ssh-bind-options-ciphers-c-s+
   #:+ssh-bind-options-ciphers-s-c+ #:+ssh-bind-options-hmac-c-s+
   #:+ssh-bind-options-hmac-s-c+ #:+ssh-bind-options-host-key+
   #:+ssh-bind-options-hostkey-algorithms+ #:+ssh-bind-options-key-exchange+
   #:+ssh-bind-options-process-config+
   #:+ssh-bind-options-pubkey-accepted-key-types+
   #:+ssh-bind-options-rsa-min-size+ #:+ssh-channel-direct-tcpip+
   #:+ssh-channel-request-env+ #:+ssh-channel-request-exec+
   #:+ssh-channel-request-pty+ #:+ssh-channel-request-shell+
   #:+ssh-channel-request-subsystem+ #:+ssh-channel-request-window-change+
   #:+ssh-channel-session+ #:+ssh-error+ #:+ssh-known-hosts-changed+
   #:+ssh-known-hosts-error+ #:+ssh-known-hosts-not-found+
   #:+ssh-known-hosts-ok+ #:+ssh-known-hosts-other+
   #:+ssh-known-hosts-unknown+ #:+ssh-ok+ #:+ssh-options-ciphers-c-s+
   #:+ssh-options-ciphers-s-c+ #:+ssh-options-compression-c-s+
   #:+ssh-options-compression-s-c+ #:+ssh-options-fd+
   #:+ssh-options-global-known-hosts+ #:+ssh-options-hmac-c-s+
   #:+ssh-options-hmac-s-c+ #:+ssh-options-host+ #:+ssh-options-hostkeys+
   #:+ssh-options-identity+ #:+ssh-options-identity-agent+
   #:+ssh-options-key-exchange+ #:+ssh-options-known-hosts+
   #:+ssh-options-port+ #:+ssh-options-process-config+
   #:+ssh-options-proxy-command+ #:+ssh-options-publickey-accepted-types+
   #:+ssh-options-rekey-data+ #:+ssh-options-rekey-time+
   #:+ssh-options-strict-host-key-check+ #:+ssh-options-user+
   #:+ssh-publickey-state-none+ #:+ssh-publickey-state-valid+
   #:+ssh-publickey-state-wrong+ #:+ssh-read-pending+ #:+ssh-request-auth+
   #:+ssh-request-channel+ #:+ssh-request-channel-open+
   #:+ssh-request-global+ #:+ssh-request-service+ #:+ssh-write-pending+
   ))
