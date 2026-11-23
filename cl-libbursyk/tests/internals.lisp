;;;; Wire- and state-level tests for the pure cl-libbursyk transport.
;;;; They drive internal functions and raw protocol messages, so they are
;;;; not part of the backend-agnostic facade suite.

(in-package #:cl-pnet-ssh-tests)

(def-suite lisp-internals
  :description "Internal protocol tests for the pure SSH transport")

(in-suite lisp-internals)

(defun kexinit-message-types (already-sent)
  "Types of the messages HANDLE-KEXINIT sends when our KEXINIT was ALREADY-SENT."
  (let ((sent '())
        (client (cl-pnet-ssh::%make-ssh-client)))
    (setf (cl-pnet-ssh::ssh-client-kexinit-sent client) already-sent)
    (let ((original (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)))
      (unwind-protect
           (progn
             (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                   (lambda (client payload)
                     (declare (ignore client))
                     (push (aref payload 0) sent)
                     t))
             (cl-pnet-ssh::ssh-client-handle-kexinit
              client (ssh-make-kexinit-payload)))
        (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload) original)))
    (nreverse sent)))

(defun captured-channel-messages (channel thunk)
  "Payloads THUNK sends on CHANNEL, in order."
  (let ((sent '()))
    (let ((original (symbol-function 'cl-pnet-ssh::ssh-channel-send)))
      (unwind-protect
           (progn
             (setf (symbol-function 'cl-pnet-ssh::ssh-channel-send)
                   (lambda (channel payload)
                     (declare (ignore channel))
                     (push payload sent)
                     t))
             (funcall thunk))
        (setf (symbol-function 'cl-pnet-ssh::ssh-channel-send) original)))
    (nreverse sent)))

(defun test-server-algorithm-keys (directory)
  "Generate ed25519 and 2048-bit RSA keys under DIRECTORY, as a list."
  (let ((ed25519 (merge-pathnames "ed25519" directory))
        (rsa (merge-pathnames "rsa-2048" directory)))
    (ensure-directories-exist ed25519)
    (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                      "-f" (namestring ed25519)))
    (ssh-keygen (list "-q" "-t" "rsa" "-b" "2048" "-N" ""
                      "-f" (namestring rsa)))
    (list (ssh-load-private-key ed25519)
          (ssh-load-private-key rsa))))

(defun channel-request-parts (payload)
  "TYPE, REMOTE-ID, REQUEST, WANT-REPLY and the remaining text fields."
  (let ((reader (ssh-make-reader payload)))
    (values (ssh-read-u8 reader)
            (ssh-read-u32 reader)
            (ssh-read-text reader)
            (ssh-read-boolean reader)
            (iter (while (plusp (ssh-reader-remaining reader)))
              (collect (ssh-read-text reader))))))

(test certificate-files-pair-with-their-private-key
  "CertificateFile attaches the listed certificate to the key it certifies
and suppresses the automatic KEY-cert.pub lookup, while a certificate for
another key is not attached."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-certfile"))
             (ca (merge-pathnames "ca" directory))
             (user (merge-pathnames "user" directory))
             (other (merge-pathnames "other" directory)))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ca)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring user)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring other)))
               (ssh-keygen
                (list "-q" "-s" (namestring ca) "-I" "explicit-id"
                      "-n" "turtle" "-V" "-1m:+52w"
                      (namestring (merge-pathnames "user.pub" directory))))
               (ssh-keygen
                (list "-q" "-s" (namestring ca) "-I" "other-id"
                      "-n" "turtle" "-V" "-1m:+52w"
                      (namestring (merge-pathnames "other.pub" directory))))
               ;; Move the certificate off its automatic path, so only an
               ;; explicit CertificateFile can find it.
               (rename-file
                (merge-pathnames "user-cert.pub" directory)
                (merge-pathnames "explicit-cert.pub" directory))
               (let* ((explicit
                        (merge-pathnames "explicit-cert.pub" directory))
                      (cert-blob (ssh-test-certificate-blob explicit))
                      (signers
                        (ssh-test-resolved-signers
                         user :certificate-files (list explicit))))
                 (is (= 1 (length signers)))
                 (is (string= "ssh-ed25519-cert-v01@openssh.com"
                              (cl-pnet-ssh::ssh-signer-type
                               (first signers))))
                 (is (equalp cert-blob
                             (cl-pnet-ssh::ssh-signer-blob
                              (first signers))))
                 ;; Without CertificateFile the moved cert is invisible and
                 ;; the key is offered plain, not certified.
                 (let ((plain (ssh-test-resolved-signers user)))
                   (is (= 1 (length plain)))
                   (is (string= "ssh-ed25519"
                                (cl-pnet-ssh::ssh-signer-type
                                 (first plain)))))
                 ;; A certificate that certifies a different key must not be
                 ;; offered with this key.
                 (let ((mismatch
                         (ssh-test-resolved-signers
                          user
                          :certificate-files
                          (list (merge-pathnames "other-cert.pub"
                                                 directory)))))
                   (is (= 1 (length mismatch)))
                   (is (string= "ssh-ed25519"
                                (cl-pnet-ssh::ssh-signer-type
                                 (first mismatch)))))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test address-family-check-classifies-numeric-addresses
  (flet ((fits (family address)
           (let ((client (cl-pnet-ssh::%make-ssh-client
                          :address-family family)))
             (cl-pnet-ssh::ssh-client-address-in-family-p client address))))
    (is (fits nil "127.0.0.1"))
    (is (fits nil "::1"))
    (is (fits :inet "127.0.0.1"))
    (is (not (fits :inet "::1")))
    (is (fits :inet6 "::1"))
    (is (not (fits :inet6 "127.0.0.1")))))

(test resolver-specs-reach-burzay-with-the-family
  "A BURZAY resolver specification is not a function to call: :DNS must reach
BURZAY (which now asks for AAAA under :INET6) instead of being funcalled."
  (let ((client (cl-pnet-ssh::%make-ssh-client
                 :resolver :dns :address-family :inet6))
        (result nil)
        (failure nil))
    ;; A numeric host short-circuits resolution inside BURZAY, so reaching
    ;; ON-SUCCESS proves the spec was passed on rather than called.
    (cl-pnet-ssh::ssh-client-resolve-host
     client "::1"
     (lambda (address) (setf result address))
     (lambda (condition) (setf failure condition)))
    (is (equal "::1" result))
    (is (null failure)))
  ;; A real function resolver keeps its three-argument shape.
  (let ((client
          (cl-pnet-ssh::%make-ssh-client
           :resolver (lambda (host on-success on-error)
                       (declare (ignore on-error))
                       (funcall on-success (concatenate 'string host "!")))))
        (result nil))
    (cl-pnet-ssh::ssh-client-resolve-host
     client "name"
     (lambda (address) (setf result address))
     #'error)
    (is (equal "name!" result))))

(test loopback-address-detection
  "Only 127/8, ::1 and their IPv4-mapped form count as loopback."
  (is (cl-pnet-ssh::ssh-loopback-address-p "127.0.0.1"))
  (is (cl-pnet-ssh::ssh-loopback-address-p "127.255.1.2"))
  (is (cl-pnet-ssh::ssh-loopback-address-p "::1"))
  (is (cl-pnet-ssh::ssh-loopback-address-p "::ffff:127.0.0.1"))
  (is (not (cl-pnet-ssh::ssh-loopback-address-p "10.0.0.1")))
  (is (not (cl-pnet-ssh::ssh-loopback-address-p "128.0.0.1")))
  (is (not (cl-pnet-ssh::ssh-loopback-address-p "::2")))
  (is (not (cl-pnet-ssh::ssh-loopback-address-p nil))))

(test sshfp-dns-query-reads-a-secure-record
  "The default resolver sends an SSHFP query and reads the AD bit."
  (let* ((server (cl-pnet:udp-listen "127.0.0.1" 0))
         (connection (and server
                          (cl-pnet::%make-connection :backend cl-pnet:*backend*
                                                     :handle server)))
         (port (and connection (cl-pnet:socket-bound-port connection)))
         (rdata (vector 4 2 1 2 3 4))
         (result nil)
         (secure nil)
         (failure nil)
         (done nil)
         (server-error nil))
    (unwind-protect
         (progn
           (is (not (null server)))
           (cl-pnet:udp-recv
            server
            (lambda (data peer)
              (handler-case
                  (let* ((query (cl-pnet-dns:decode-dns-message data))
                         (question (first (cl-pnet-dns:dns-message-questions
                                           query)))
                         (response
                           (cl-pnet-dns:make-dns-message
                            :id (cl-pnet-dns:dns-message-id query)
                            :flags (logior #x8180 #x0020)
                            :questions (list question)
                            :answers
                            (list (cl-pnet-dns:make-dns-rr
                                   :name (cl-pnet-dns:dns-question-name question)
                                   :type 44 :class 1 :ttl 60
                                   :rdata rdata)))))
                    (is (= 44 (cl-pnet-dns:dns-question-type question)))
                    (cl-pnet:udp-send server
                                      (cl-pnet-dns:encode-dns-message response)
                                      peer))
                (error (condition)
                  (setf server-error condition done t)))))
           (let ((cl-pnet-ssh::*ssh-dns-server* "127.0.0.1")
                 (cl-pnet-ssh::*ssh-dns-port* port))
             (cl-pnet-ssh::ssh-dns-resolve-sshfp
              "sshfp.test"
              (lambda (records secure-p)
                (setf result records secure secure-p done t))
              (lambda (condition)
                (setf failure condition done t))))
           (loop repeat 10000 until done do (cl-pnet:event-loop-run-once))
           (is (null server-error))
           (is (null failure))
           (is (not (null done)))
           (is (eq t secure))
           (is (= 1 (length result)))
           (is (equalp (subseq rdata 2) (third (first result))))
           (is (= 4 (first (first result))))
           (is (= 2 (second (first result)))))
      (when server (ignore-errors (cl-pnet:udp-close server))))))

(test none-agent-is-not-the-environment-agent
  "AGENT :NONE disables the agent even when SSH_AUTH_SOCK is set, which is
what IdentityAgent none and IdentitiesOnly ask for."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-no-agent"))
             (path (merge-pathnames "id_ed25519" directory))
             (delivered '())
             (failure nil))
        (ensure-directories-exist path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring path)))
               (cl-pnet-ssh::ssh-resolve-signers
                (list (ssh-load-private-key path)) :none nil
                (lambda (signers) (setf delivered signers))
                (lambda (condition) (setf failure condition)))
               (is (null failure))
               (is (= 1 (length delivered)))
               (is (string= "ssh-ed25519"
                            (cl-pnet-ssh::ssh-signer-type (first delivered))))
               ;; With no key file the agent would be the only source; :NONE
               ;; must leave nothing to try instead of consulting the socket.
               (setf delivered nil failure nil)
               (cl-pnet-ssh::ssh-resolve-signers
                nil :none nil
                (lambda (signers) (setf delivered signers))
                (lambda (condition) (setf failure condition)))
               (is (null delivered))
               (is (typep failure 'ssh-authentication-error)))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test client-builds-a-hostbased-request
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-hostbased-request"))
             (key-path (merge-pathnames "host_key" directory)))
        (ensure-directories-exist key-path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring key-path)))
               (let* ((key (ssh-load-private-key key-path))
                      (session-id (make-array 32
                                              :element-type '(unsigned-byte 8)
                                              :initial-element 7))
                      (client (cl-pnet-ssh::%make-ssh-client
                               :user "tester"
                               :hostbased-key key
                               :session-id session-id))
                      (unsigned (cl-pnet-ssh::ssh-client-hostbased-request-unsigned
                                 client))
                      (reader (ssh-make-reader unsigned)))
                 (is (= cl-pnet-ssh::+ssh-msg-userauth-request+
                        (ssh-read-u8 reader)))
                 (is (equal "tester" (ssh-read-text reader)))
                 (is (equal "ssh-connection" (ssh-read-text reader)))
                 (is (equal "hostbased" (ssh-read-text reader)))
                 (is (equal "ssh-ed25519" (ssh-read-text reader)))
                 (is (equalp (ssh-public-key-blob-of key)
                             (ssh-read-string reader)))
                 (let ((host (ssh-read-text reader)))
                   (is (plusp (length host)))
                   (is (char= #\. (char host (1- (length host))))))
                 (is (equal (ssh-default-user) (ssh-read-text reader)))
                 ;; The signature covers the session id and the request.
                 (let* ((data (let ((writer (ssh-writer)))
                                (ssh-write-string writer session-id)
                                (ssh-write-octets writer unsigned)
                                (ssh-writer-output writer)))
                        (signature (cl-pnet-ssh::ssh-private-key-signature-blob
                                    key data)))
                   (is (cl-pnet-ssh::ssh-public-key-signature-valid-p
                        (ssh-public-key-blob-of key) signature data)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test client-known-hosts-command-supplies-keys
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-khc"))
         (script (merge-pathnames "keys.sh" directory))
         (blob (ssh-make-public-key-blob "ssh-ed25519"
                                         (ssh-random-octets 32)))
         (other (ssh-make-public-key-blob "ssh-ed25519"
                                          (ssh-random-octets 32))))
    (ensure-directories-exist script)
    (unwind-protect
         (progn
           (with-open-file (out script :direction :output
                                       :if-exists :supersede
                                       :if-does-not-exist :create)
             (format out "#!/bin/sh~%printf '%s ssh-ed25519 ~A~%' \"$1\"~%"
                     (ssh-octets-base64 blob)))
           (ignore-errors (uiop:run-program (list "chmod" "700"
                                                  (namestring script))))
           (let ((client (cl-pnet-ssh::%make-ssh-client
                          :host "example.org"
                          :known-hosts '()
                          :known-hosts-command
                          (format nil "~A %H" (namestring script)))))
             (is (eq :match
                     (cl-pnet-ssh::ssh-client-known-host-status-for
                      client "example.org" blob)))
             (is (eq :mismatch
                     (cl-pnet-ssh::ssh-client-known-host-status-for
                      client "example.org" other)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test client-check-host-ip-records-and-refuses
  (let* ((directory (ssh-test-directory "cl-pnet-ssh-checkip"))
         (path (merge-pathnames "known_hosts" directory))
         (blob (ssh-make-public-key-blob "ssh-ed25519"
                                         (ssh-random-octets 32)))
         (other (ssh-make-public-key-blob "ssh-ed25519"
                                          (ssh-random-octets 32))))
    (ensure-directories-exist path)
    (unwind-protect
         (flet ((client ()
                  (cl-pnet-ssh::%make-ssh-client
                   :host "example.org"
                   :known-hosts (list path)
                   :check-host-ip t
                   :remote-address "192.0.2.1")))
           ;; An unknown address is recorded beside the host.
           (cl-pnet-ssh::ssh-client-check-host-address (client) blob)
           (is (eq :match (ssh-known-host-status path "192.0.2.1" blob)))
           ;; A conflicting address entry is refused.
           (with-open-file (out path :direction :output
                                     :if-exists :supersede
                                     :if-does-not-exist :create)
             (format out "192.0.2.1 ssh-ed25519 ~A~%"
                     (ssh-octets-base64 other)))
           (signals ssh-host-key-error
             (cl-pnet-ssh::ssh-client-check-host-address (client) blob))
           ;; Loopback and a host that is already its address are skipped.
           (let ((loopback (cl-pnet-ssh::%make-ssh-client
                            :host "localhost"
                            :known-hosts (list path)
                            :check-host-ip t
                            :remote-address "192.0.2.1")))
             (is (null (cl-pnet-ssh::ssh-client-check-host-address
                        loopback blob)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test proxy-fdpass-adopts-the-helper-socket
  "The connected descriptor a helper sends replaces the control socket, and
the client greets over it."
  (multiple-value-bind (control-parent control-helper)
      (cl-pnet-sockets:make-socketpair)
    (multiple-value-bind (adopted-peer adopted-server)
        (cl-pnet-sockets:make-socketpair)
      (let ((client nil)
            (proxy nil))
        (unwind-protect
             (progn
               (setf client
                     (cl-pnet-ssh::%make-ssh-client
                      :host "fdpass.example"
                      :connect-host "fdpass.example"
                      :host-key-host "fdpass.example"
                      :port 22 :connect-port 22
                      :client-version "SSH-2.0-fdpass")
                     proxy
                     (cl-pnet-ssh::%make-ssh-proxy
                      :command "helper"
                      :control-fd control-parent)
                     (cl-pnet-ssh::ssh-client-pipe client) proxy)
               (is (cl-pnet-sockets:send-fd control-helper adopted-peer))
               (cl-pnet-ssh::ssh-proxy-fdpass-receive client)
               ;; Adopting closed the control socket and kept the connected
               ;; descriptor.
               (is (null (cl-pnet-ssh::ssh-proxy-control-fd proxy)))
               (is (integerp (cl-pnet-ssh::ssh-proxy-read-fd proxy)))
               (multiple-value-bind (octets count errno)
                   (cl-pnet-sockets:read-octets
                    adopted-server (length "SSH-2.0-fdpass"))
                 (declare (ignore errno))
                 (is (plusp count))
                 (is (equal "SSH-2.0-fdpass"
                            (map 'string #'code-char octets)))))
          (when proxy
            (cl-pnet-ssh::ssh-proxy-shutdown proxy))
          (ignore-errors (cl-pnet-sockets:c-close control-helper))
          (ignore-errors (cl-pnet-sockets:c-close adopted-peer))
          (ignore-errors (cl-pnet-sockets:c-close adopted-server)))))))

(test client-refusal-of-x11-req-is-not-a-channel-error
  "A refused x11-req only warns, as ssh's CONFIRM_WARN does; the session
keeps going.  A later request failure still reaches ON-ERROR."
  (flet ((message (type)
           (let ((writer (ssh-writer)))
             (ssh-write-u8 writer type)
             (ssh-write-u32 writer 3)
             (ssh-writer-output writer))))
    (let* ((client (cl-pnet-ssh::%make-ssh-client))
           (channel (cl-pnet-ssh::%make-ssh-channel
                     :client client :local-id 3 :remote-id 9
                     :type "session" :state :open))
           (errors '()))
      (setf (gethash 3 (cl-pnet-ssh::ssh-client-channels client)) channel
            (cl-pnet-ssh::ssh-channel-on-error channel)
            (lambda (channel condition)
              (declare (ignore channel))
              (push condition errors))
            (cl-pnet-ssh::ssh-channel-x11-reply-pending channel) t)
      ;; Success clears the flag and is otherwise silent.
      (cl-pnet-ssh::ssh-client-handle-channel-message
       client (message cl-pnet-ssh::+ssh-msg-channel-success+))
      (is (null (cl-pnet-ssh::ssh-channel-x11-reply-pending channel)))
      (is (null errors))
      ;; Failure of the request the flag tracks is the x11-req refusal.
      (setf (cl-pnet-ssh::ssh-channel-x11-reply-pending channel) t)
      (cl-pnet-ssh::ssh-client-handle-channel-message
       client (message cl-pnet-ssh::+ssh-msg-channel-failure+))
      (is (null errors))
      (is (null (cl-pnet-ssh::ssh-channel-x11-reply-pending channel)))
      ;; With no x11 reply outstanding the same message is a channel error.
      (cl-pnet-ssh::ssh-client-handle-channel-message
       client (message cl-pnet-ssh::+ssh-msg-channel-failure+))
      (is (= 1 (length errors))))))

(test x11-timeout-follows-openssh
  "Untrusted forwarding expires after OpenSSH's 1200-second default, 0
disables the limit, and trusted forwarding never expires."
  (flet ((armed (trusted timeout)
           (let ((client (cl-pnet-ssh::%make-ssh-client
                          :forward-x11 t
                          :forward-x11-trusted trusted
                          :forward-x11-timeout timeout)))
             (cl-pnet-ssh::ssh-client-x11-start-timeout client)
             (cl-pnet-ssh::ssh-client-x11-refuse-time client))))
    (let ((before (cl-pnet-ssh::ssh-client-now))
          (deadline (armed nil nil))
          (after (cl-pnet-ssh::ssh-client-now)))
      (is (<= (+ before 1200) deadline (+ after 1200))))
    (is (null (armed nil 0)))
    (is (null (armed t nil)))
    (is (null (armed t 600)))
    (let ((before (cl-pnet-ssh::ssh-client-now))
          (deadline (armed nil 600))
          (after (cl-pnet-ssh::ssh-client-now)))
      (is (<= (+ before 600) deadline (+ after 600))))))

(test server-x11-config-and-policy
  "X11Forwarding and its companions parse, and a session asks for X11 only
when the config, DisableForwarding and the key's options all allow it."
  (flet ((session (&rest options)
           (let* ((config (ssh-server-config-load nil :options options))
                  (server (cl-pnet-ssh::%make-ssh-server :sshd-config config)))
             (values config (cl-pnet-ssh::%make-ssh-session :server server)))))
    (multiple-value-bind (config session)
        (session "X11Forwarding yes" "X11DisplayOffset 20"
                 "X11UseLocalhost yes" "XAuthLocation /usr/bin/xauth")
      (is (eq :yes (cl-pnet-ssh:ssh-server-config-x11-forwarding config)))
      (is (= 20 (cl-pnet-ssh:ssh-server-config-x11-display-offset config)))
      (is (eq :yes (cl-pnet-ssh:ssh-server-config-x11-use-localhost config)))
      (is (string= "/usr/bin/xauth"
                   (cl-pnet-ssh:ssh-server-config-xauth-location config)))
      (is (cl-pnet-ssh:ssh-session-permits-x11-p session)))
    ;; X11Forwarding defaults to no.
    (multiple-value-bind (config session) (session)
      (is (null (cl-pnet-ssh:ssh-server-config-x11-forwarding config)))
      (is (not (cl-pnet-ssh:ssh-session-permits-x11-p session))))
    (multiple-value-bind (config session) (session "X11Forwarding no")
      (declare (ignore config))
      (is (not (cl-pnet-ssh:ssh-session-permits-x11-p session))))
    (multiple-value-bind (config session)
        (session "X11Forwarding yes" "DisableForwarding yes")
      (declare (ignore config))
      (is (not (cl-pnet-ssh:ssh-session-permits-x11-p session))))
    (multiple-value-bind (config session) (session "X11Forwarding yes")
      (declare (ignore config))
      (setf (ssh-session-authorization session)
            (nth-value 0
                       (cl-pnet-ssh:ssh-authorized-key-options-parse
                        "no-x11-forwarding")))
      (is (not (cl-pnet-ssh:ssh-session-permits-x11-p session))))
    ;; A key that only restricts something else keeps X11 forwarding.
    (multiple-value-bind (config session) (session "X11Forwarding yes")
      (declare (ignore config))
      (setf (ssh-session-authorization session)
            (nth-value 0
                       (cl-pnet-ssh:ssh-authorized-key-options-parse
                        "no-agent-forwarding")))
      (is (cl-pnet-ssh:ssh-session-permits-x11-p session)))))

(test server-x11-request-binds-a-display-and-writes-the-cookie
  "An accepted x11-req binds a display, sets DISPLAY and records the fake
cookie in the account's Xauthority; one directive short and it refuses."
  (flet ((attempt (options body)
           (let* ((directory (ssh-test-directory "cl-pnet-ssh-x11-req"))
                  (authority (namestring
                              (merge-pathnames "Xauthority" directory)))
                  (config (ssh-server-config-load nil :options options))
                  (server (cl-pnet-ssh::%make-ssh-server
                           :sshd-config config
                           :x11-authority-file
                           (lambda (session)
                             (declare (ignore session))
                             authority)))
                  (session (cl-pnet-ssh::%make-ssh-session :server server))
                  (channel (cl-pnet-ssh::%make-ssh-server-channel
                            :session session
                            :local-id 0
                            :type "session"
                            :state :open
                            :remote-window 2097152
                            :remote-max-packet 32768
                            :local-window 2097152
                            :local-max-packet 32768))
                  (cookie (make-array 16 :element-type '(unsigned-byte 8)
                                         :initial-contents
                                         (loop for index below 16
                                               collect (* index 17))))
                  (writer (ssh-writer)))
             (ensure-directories-exist authority)
             (ssh-write-boolean writer nil)
             (ssh-write-text writer "MIT-MAGIC-COOKIE-1")
             (ssh-write-text writer (cl-pnet-ssh::ssh-x11-cookie-hex cookie))
             (ssh-write-u32 writer 0)
             (unwind-protect
                  (let ((accepted
                          (cl-pnet-ssh::ssh-server-handle-x11-request
                           session channel
                           (cl-pnet-ssh::ssh-make-reader
                            (ssh-writer-output writer))
                           nil)))
                    (funcall body accepted session channel cookie authority))
               ;; The listener belongs to the session; close it before the
               ;; temporary directory goes away.
               (when (cl-pnet-ssh::ssh-session-x11-forward session)
                 (cl-pnet-ssh::ssh-session-close-x11 session))
               (ignore-errors (delete-file authority))
               (ignore-errors (delete-directory directory))))))
    (attempt '("X11Forwarding yes")
         (lambda (accepted session channel cookie authority)
           (is (not (null accepted)))
           (let* ((x11 (cl-pnet-ssh::ssh-session-x11-forward session))
                  (number (cl-pnet-ssh::ssh-x11-forward-display-number x11))
                  (display (cl-pnet-ssh::%make-ssh-x11-display
                            :host "localhost" :number number :screen 0)))
             (is (not (null x11)))
             (is (>= number 10))
             (is (string= "localhost"
                          (cl-pnet-ssh::ssh-x11-forward-display-host x11)))
             (is (equal (format nil "localhost:~D.0" number)
                        (cdr (assoc "DISPLAY" (ssh-server-channel-env channel)
                                    :test #'string=))))
             (multiple-value-bind (name data)
                 (cl-pnet-ssh::ssh-x11-authority-cookie authority display)
               (is (cl-pnet-ssh::ssh-x11-octets-equal-text-p
                    name "MIT-MAGIC-COOKIE-1"))
               (is (equalp cookie data))))))
    ;; X11Forwarding defaults to no, so the request is refused.
    (attempt '()
         (lambda (accepted session channel cookie authority)
           (declare (ignore channel cookie authority))
           (is (null accepted))
           (is (null (cl-pnet-ssh::ssh-session-x11-forward session)))))))

(test keyboard-interactive-info-request-carries-prompts-and-answers
  (flet ((request (name instruction prompts)
           (let ((writer (ssh-writer)))
             (ssh-write-u8 writer
                           cl-pnet-ssh::+ssh-msg-userauth-info-request+)
             (ssh-write-text writer name)
             (ssh-write-text writer instruction)
             (ssh-write-text writer "")
             (ssh-write-u32 writer (length prompts))
             (dolist (prompt prompts)
               (ssh-write-text writer (first prompt))
               (ssh-write-boolean writer (second prompt)))
             (ssh-writer-output writer))))
    (let* ((seen nil)
           (client (cl-pnet-ssh::%make-ssh-client
                    :kbd-interactive-callback
                    (lambda (client name instruction prompts)
                      (declare (ignore client))
                      (push (list name instruction prompts) seen)
                      (mapcar (lambda (prompt)
                                (format nil "answer to ~A" (first prompt)))
                              prompts))))
           (sent '()))
      (setf (cl-pnet-ssh::ssh-client-last-auth-method client)
            "keyboard-interactive")
      (let ((original
              (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)))
        (unwind-protect
             (progn
               (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                     (lambda (client payload)
                       (declare (ignore client))
                       (push payload sent)
                       t))
               ;; A message with prompts asks for one answer each, and the
               ;; echo flag reaches the callback so a password can be hidden.
               (cl-pnet-ssh::ssh-client-handle-info-request
                client
                (request "Fixture" "Instruction"
                         '(("Password: " nil) ("Code: " t))))
               ;; A zero-prompt message only displays text; its empty answer
               ;; list is not a cancellation.
               (cl-pnet-ssh::ssh-client-handle-info-request
                client (request "Notice" "" '())))
          (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                original)))
      (is (equal '(("Fixture" "Instruction"
                    (("Password: " nil) ("Code: " t)))
                   ("Notice" "" nil))
                 (nreverse seen)))
      (let ((reader (ssh-make-reader (second sent))))
        (is (= cl-pnet-ssh::+ssh-msg-userauth-info-response+
               (ssh-read-u8 reader)))
        (is (= 2 (ssh-read-u32 reader)))
        (is (equal "answer to Password: " (ssh-read-text reader)))
        (is (equal "answer to Code: " (ssh-read-text reader))))
      (let ((reader (ssh-make-reader (first sent))))
        (is (= cl-pnet-ssh::+ssh-msg-userauth-info-response+
               (ssh-read-u8 reader)))
        (is (zerop (ssh-read-u32 reader)))))))

(test server-accepts-a-direct-streamlocal-open
  "A permitted direct-streamlocal open records the socket path."
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes")))
         (server (cl-pnet-ssh::%make-ssh-server
                  :sshd-config config
                  :on-direct-streamlocal
                  (lambda (session path)
                    (declare (ignore session))
                    (string= path "/tmp/sock"))))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-channel-open+)
    (cl-pnet-ssh:ssh-write-text writer "direct-streamlocal@openssh.com")
    (cl-pnet-ssh:ssh-write-u32 writer 7)
    (cl-pnet-ssh:ssh-write-u32 writer 2097152)
    (cl-pnet-ssh:ssh-write-u32 writer 32768)
    (cl-pnet-ssh:ssh-write-text writer "/tmp/sock")
    (cl-pnet-ssh:ssh-write-text writer "")
    (cl-pnet-ssh:ssh-write-u32 writer 0)
    (cl-pnet-ssh::ssh-server-handle-channel-message
     session (cl-pnet-ssh:ssh-writer-output writer))
    (let ((channel (gethash 0 (cl-pnet-ssh::ssh-session-channels session))))
      (is (not (null channel)))
      (is (equal "direct-streamlocal@openssh.com"
                 (cl-pnet-ssh:ssh-server-channel-type channel)))
      (is (equal "/tmp/sock"
                 (cl-pnet-ssh:ssh-server-channel-streamlocal-path channel)))))
  ;; The application hook can refuse a path.
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes")))
         (server (cl-pnet-ssh::%make-ssh-server
                  :sshd-config config
                  :on-direct-streamlocal (lambda (session path)
                                           (declare (ignore session path))
                                           nil)))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-channel-open+)
    (cl-pnet-ssh:ssh-write-text writer "direct-streamlocal@openssh.com")
    (cl-pnet-ssh:ssh-write-u32 writer 7)
    (cl-pnet-ssh:ssh-write-u32 writer 2097152)
    (cl-pnet-ssh:ssh-write-u32 writer 32768)
    (cl-pnet-ssh:ssh-write-text writer "/tmp/sock")
    (cl-pnet-ssh:ssh-write-text writer "")
    (cl-pnet-ssh:ssh-write-u32 writer 0)
    (cl-pnet-ssh::ssh-server-handle-channel-message
     session (cl-pnet-ssh:ssh-writer-output writer))
    (is (null (gethash 0 (cl-pnet-ssh::ssh-session-channels session))))))

(test server-handles-streamlocal-forward-requests
  "A streamlocal-forward request reaches the application hook; a cancel does
too, and a refused policy never calls it."
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes")))
         (seen '())
         (server (cl-pnet-ssh::%make-ssh-server
                  :sshd-config config
                  :on-streamlocal-forward
                  (lambda (session path)
                    (declare (ignore session))
                    (push (cons :forward path) seen)
                    t)
                  :on-cancel-streamlocal-forward
                  (lambda (session path)
                    (declare (ignore session))
                    (push (cons :cancel path) seen)
                    t)))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-global-request+)
    (cl-pnet-ssh:ssh-write-text writer "streamlocal-forward@openssh.com")
    (cl-pnet-ssh:ssh-write-boolean writer nil)
    (cl-pnet-ssh:ssh-write-text writer "/tmp/sock")
    (cl-pnet-ssh::ssh-server-handle-global-request
     session (cl-pnet-ssh:ssh-writer-output writer))
    (setf writer (cl-pnet-ssh:ssh-writer))
    (cl-pnet-ssh:ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-global-request+)
    (cl-pnet-ssh:ssh-write-text writer "cancel-streamlocal-forward@openssh.com")
    (cl-pnet-ssh:ssh-write-boolean writer nil)
    (cl-pnet-ssh:ssh-write-text writer "/tmp/sock")
    (cl-pnet-ssh::ssh-server-handle-global-request
     session (cl-pnet-ssh:ssh-writer-output writer))
    (is (equal '((:forward . "/tmp/sock") (:cancel . "/tmp/sock"))
               (nreverse seen))))
  ;; The library's policy gate keeps a hook from running when the directive
  ;; does not allow remote stream-local forwarding.
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding no")))
         (called nil)
         (server (cl-pnet-ssh::%make-ssh-server
                  :sshd-config config
                  :on-streamlocal-forward
                  (lambda (session path)
                    (declare (ignore session path))
                    (setf called t)
                    t)))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-global-request+)
    (cl-pnet-ssh:ssh-write-text writer "streamlocal-forward@openssh.com")
    (cl-pnet-ssh:ssh-write-boolean writer nil)
    (cl-pnet-ssh:ssh-write-text writer "/tmp/sock")
    (cl-pnet-ssh::ssh-server-handle-global-request
     session (cl-pnet-ssh:ssh-writer-output writer))
    (is (null called))))

(test server-opens-a-forwarded-streamlocal-channel
  "The forwarded-streamlocal channel carries the listen path and reserved field."
  (let* ((config (ssh-server-config-load
                  nil :options '("AllowStreamLocalForwarding yes")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session :server server))
         (channel
           (cl-pnet-ssh:ssh-server-open-forwarded-streamlocal
            session "/tmp/sock")))
    (is (eq :opening (cl-pnet-ssh:ssh-server-channel-state channel)))
    (is (equal "forwarded-streamlocal@openssh.com"
               (cl-pnet-ssh:ssh-server-channel-type channel)))
    (is (equal "/tmp/sock"
               (cl-pnet-ssh:ssh-server-channel-streamlocal-path channel)))))

(test client-opens-a-direct-streamlocal-channel
  "The client's open carries the socket path and the two reserved fields."
  (let* ((client (cl-pnet-ssh::%make-ssh-client))
         (channel (ssh-open-direct-streamlocal client "/tmp/sock"))
         (reader (ssh-make-reader
                  (cl-pnet-ssh::ssh-channel-open-extra channel))))
    (is (equal "direct-streamlocal@openssh.com"
               (cl-pnet-ssh::ssh-channel-type channel)))
    (is (equal "/tmp/sock" (ssh-read-text reader)))
    (is (equal "" (ssh-read-text reader)))
    (is (= 0 (ssh-read-u32 reader)))
    ;; Nothing is sent before the transport is ready.
    (is (eq :connecting (cl-pnet-ssh:ssh-client-phase client)))))

(test client-accepts-a-forwarded-streamlocal-channel
  "A requested path is accepted and handed to the application's setup hook;
an unrequested one is refused with a CHANNEL_OPEN_FAILURE."
  (flet ((open-message (path)
           (let ((writer (ssh-writer)))
             (ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-channel-open+)
             (ssh-write-text writer "forwarded-streamlocal@openssh.com")
             (ssh-write-u32 writer 7)
             (ssh-write-u32 writer 2097152)
             (ssh-write-u32 writer 32768)
             (ssh-write-text writer path)
             (ssh-write-text writer "")
             (ssh-write-u32 writer 0)
             (ssh-writer-output writer))))
    (let* ((client (cl-pnet-ssh::%make-ssh-client))
           (seen '())
           (setup-channel nil)
           (sent '()))
      (setf (cl-pnet-ssh::ssh-client-on-forwarded-streamlocal client)
            (lambda (client path)
              (declare (ignore client))
              (push path seen)
              (lambda (channel) (setf setup-channel channel))))
      (let ((original (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)))
        (unwind-protect
             (progn
               (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                     (lambda (client payload)
                       (declare (ignore client))
                       (push payload sent)
                       t))
               (cl-pnet-ssh::ssh-client-handle-channel-message
                client (open-message "/tmp/sock")))
          (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                original)))
      (is (equal '("/tmp/sock") seen))
      (is (not (null setup-channel)))
      (is (equal "forwarded-streamlocal@openssh.com"
                 (cl-pnet-ssh::ssh-channel-type setup-channel)))
      (is (eq :open (cl-pnet-ssh::ssh-channel-state setup-channel)))
      ;; The confirmation names the server's sender id.
      (let ((reader (ssh-make-reader (first sent))))
        (is (= cl-pnet-ssh::+ssh-msg-channel-open-confirmation+
               (ssh-read-u8 reader)))
        (is (= 7 (ssh-read-u32 reader)))))
    ;; With no handler the path is refused and no channel is created.
    (let* ((client (cl-pnet-ssh::%make-ssh-client))
           (sent '()))
      (let ((original (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)))
        (unwind-protect
             (progn
               (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                     (lambda (client payload)
                       (declare (ignore client))
                       (push payload sent)
                       t))
               (cl-pnet-ssh::ssh-client-handle-channel-message
                client (open-message "/tmp/other.sock")))
          (setf (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)
                original)))
      (is (null (cl-pnet-ssh::ssh-client-channel-for client 0)))
      (let ((reader (ssh-make-reader (first sent))))
        (is (= cl-pnet-ssh::+ssh-msg-channel-open-failure+ (ssh-read-u8 reader)))
        (is (= 7 (ssh-read-u32 reader)))))))

(test server-accepts-a-hostbased-request
  "A hostbased request is verified with the client host key and handed to
the application's trust hook."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-hostbased"))
             (key-path (merge-pathnames "host_key" directory)))
        (ensure-directories-exist key-path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring key-path)))
               (let* ((private (ssh-load-private-key key-path))
                      (blob (ssh-public-key-blob-of private))
                      (session-id
                        (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 9))
                      (run
                        (lambda (config allowed)
                          (let* ((server
                                   (cl-pnet-ssh::%make-ssh-server
                                    :sshd-config config
                                    :hostbased-key-allowed
                                    (lambda (session user cuser chost key)
                                      (declare (ignore session user cuser
                                                       chost key))
                                      allowed)))
                                 (session
                                   (cl-pnet-ssh::%make-ssh-session
                                    :server server
                                    :session-id session-id))
                                 (signed
                                   (cl-pnet-ssh::ssh-server-hostbased-signed-data
                                    session "turtle" "ssh-ed25519" blob
                                    "client.example" "turtle"))
                                 (signature
                                   (cl-pnet-ssh::ssh-ed25519-signature-blob
                                    private signed))
                                 (writer (cl-pnet-ssh:ssh-writer)))
                            (cl-pnet-ssh:ssh-write-u8
                             writer cl-pnet-ssh::+ssh-msg-userauth-request+)
                            (cl-pnet-ssh:ssh-write-text writer "turtle")
                            (cl-pnet-ssh:ssh-write-text writer "ssh-connection")
                            (cl-pnet-ssh:ssh-write-text writer "hostbased")
                            (cl-pnet-ssh:ssh-write-text writer "ssh-ed25519")
                            (cl-pnet-ssh:ssh-write-string writer blob)
                            (cl-pnet-ssh:ssh-write-text writer "client.example")
                            (cl-pnet-ssh:ssh-write-text writer "turtle")
                            (cl-pnet-ssh:ssh-write-string writer signature)
                            (cl-pnet-ssh::ssh-server-handle-userauth-request
                             session (cl-pnet-ssh:ssh-writer-output writer))
                            (cl-pnet-ssh::ssh-session-authenticated
                             session)))))
                 (is (funcall
                      run
                      (ssh-server-config-load
                       nil :options '("HostbasedAuthentication yes"))
                      t))
                 (is (not (funcall
                           run
                           (ssh-server-config-load
                            nil :options '("HostbasedAuthentication yes"))
                           nil)))
                 (is (not (funcall
                           run
                           (ssh-server-config-load
                            nil :options '("HostbasedAuthentication no"))
                           t)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-host-key-list-falls-back-to-the-agent
  "A HostKey whose private half is absent becomes an agent-backed key when
HostKeyAgent is configured."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-agent-hostkey"))
             (key-path (merge-pathnames "host_key" directory)))
        (ensure-directories-exist key-path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring key-path)))
               (let* ((private (ssh-load-private-key key-path))
                      (blob (ssh-public-key-blob-of private))
                      (public-path (concatenate 'string
                                                (namestring key-path) ".pub")))
                 (ignore-errors (delete-file key-path))
                 (let ((keys (cl-pnet-ssh::ssh-server-host-key-list
                              (list key-path) "/tmp/agent.sock")))
                   (is (= 1 (length keys)))
                   (is (cl-pnet-ssh::ssh-agent-host-key-p (first keys)))
                   (is (equalp blob
                               (ssh-public-key-blob-of (first keys))))
                   (is (equalp blob
                               (cl-pnet-ssh::ssh-public-key-file-blob
                                public-path))))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-kex-signs-with-an-agent-host-key
  "An agent-backed host key sends the exchange hash to the agent and finishes
the KEX from its signature."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-agent-kex"))
             (key-path (merge-pathnames "host_key" directory))
             (agent-path (namestring (merge-pathnames "agent.sock" directory))))
        (ensure-directories-exist key-path)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring key-path)))
               (let* ((private (ssh-load-private-key key-path))
                      (blob (ssh-public-key-blob-of private))
                      (agent
                        (fake-agent-open
                         agent-path
                         (lambda (payload)
                           (let ((reader (ssh-make-reader payload)))
                             (is (= (ssh-read-u8 reader)
                                    cl-pnet-ssh::+ssh-agentc-sign-request+))
                             (is (equalp blob (ssh-read-string reader)))
                             (let* ((data (ssh-read-string reader))
                                    (signature
                                      (cl-pnet-ssh::ssh-ed25519-signature-blob
                                       private data))
                                    (writer (ssh-writer)))
                               (ssh-write-u8
                                writer cl-pnet-ssh::+ssh-agent-sign-response+)
                               (ssh-write-string writer signature)
                               (ssh-writer-output writer))))))
                      (server
                        (cl-pnet-ssh::%make-ssh-server
                         :host-keys
                         (list (cl-pnet-ssh::%make-ssh-agent-host-key
                                :blob blob :type "ssh-ed25519"
                                :path key-path))
                         :host-key-agent agent-path))
                      (session
                        (cl-pnet-ssh::%make-ssh-session
                         :server server
                         :client-version "SSH-2.0-test-client"
                         :server-version "SSH-2.0-test-server"
                         :client-kexinit (make-array 1 :element-type
                                                     '(unsigned-byte 8)
                                                     :initial-element 0)
                         :server-kexinit (make-array 1 :element-type
                                                     '(unsigned-byte 8)
                                                     :initial-element 0)
                         :negotiated
                         (list :kex "curve25519-sha256"
                               :host-key "ssh-ed25519"
                               :cipher-c2s "chacha20-poly1305@openssh.com"
                               :cipher-s2c "chacha20-poly1305@openssh.com"
                               :mac-c2s "hmac-sha2-256"
                               :mac-s2c "hmac-sha2-256"
                               :ext-info nil :strict nil)))
                      (writer (ssh-writer)))
                 (multiple-value-bind (client-private client-public)
                     (ssh-curve25519-keypair)
                   (declare (ignore client-private))
                   (ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-kex-ecdh-init+)
                   (ssh-write-string writer client-public))
                 (cl-pnet-ssh::ssh-server-handle-kex-init
                  session (ssh-writer-output writer))
                 (is (cl-pnet-ssh::ssh-session-kex-signature-pending session))
                 (loop repeat 10000
                       until (cl-pnet-ssh::ssh-session-derived-keys session)
                       do (cl-pnet:event-loop-run-once))
                 (is (not (null (cl-pnet-ssh::ssh-session-derived-keys
                                 session))))
                 (is (not (cl-pnet-ssh::ssh-session-kex-signature-pending
                           session)))
                 (fake-agent-close agent)))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test ext-info-records-the-ping-extension
  "EXT_INFO enables chaff only for ping@openssh.com version 0; other names are
ignored and an unsupported version leaves chaff off."
  (flet ((payload (&rest extensions)
           (let ((writer (cl-pnet-ssh::ssh-writer)))
             (cl-pnet-ssh::ssh-write-u8 writer cl-pnet-ssh::+ssh-msg-ext-info+)
             (cl-pnet-ssh::ssh-write-u32 writer (length extensions))
             (dolist (extension extensions)
               (cl-pnet-ssh::ssh-write-text writer (car extension))
               (cl-pnet-ssh::ssh-write-text writer (cdr extension)))
             (cl-pnet-ssh::ssh-writer-output writer)))
         (supports-p (client)
           (cl-pnet-ssh:ssh-client-ping-supported client)))
    (let ((client (cl-pnet-ssh::%make-ssh-client)))
      (cl-pnet-ssh::ssh-client-handle-ext-info
       client (payload (cons "server-sig-algs" "ssh-ed25519")
                       (cons "ping@openssh.com" "0")))
      (is (supports-p client)))
    (let ((client (cl-pnet-ssh::%make-ssh-client)))
      (cl-pnet-ssh::ssh-client-handle-ext-info
       client (payload (cons "ping@openssh.com" "1")))
      (is (not (supports-p client))))
    (let ((client (cl-pnet-ssh::%make-ssh-client)))
      (cl-pnet-ssh::ssh-client-handle-ext-info
       client (payload (cons "unknown@example.com" "0")))
      (is (not (supports-p client))))))

(test server-advertises-ping-version-zero
  "The server EXT_INFO names server-sig-algs and ping@openssh.com version 0."
  (let* ((payload (cl-pnet-ssh::ssh-server-ext-info-payload))
         (reader (cl-pnet-ssh::ssh-make-reader payload))
         (extensions nil))
    (is (= 7 (cl-pnet-ssh::ssh-read-u8 reader)))
    (let ((count (cl-pnet-ssh::ssh-read-u32 reader)))
      (is (= 3 count))
      (dotimes (index count)
        (declare (ignore index))
        (push (cons (cl-pnet-ssh::ssh-read-text reader)
                    (cl-pnet-ssh::ssh-read-string reader))
              extensions)))
    (is (plusp (length (cdr (assoc "server-sig-algs" extensions
                                    :test #'string=)))))
    (is (equalp (cl-pnet-ssh::ssh-string-octets "0")
                (cdr (assoc "ping@openssh.com" extensions
                            :test #'string=))))
    (is (equalp (cl-pnet-ssh::ssh-string-octets "0")
                (cdr (assoc "agent-forward" extensions
                            :test #'string=))))))

(test rekey-sends-our-kexinit-before-ecdh-init
  ;; A server-initiated exchange has not seen our KEXINIT yet, so both go out;
  ;; the initial exchange already sent ours and only needs the ECDH half.
  (is (equal (kexinit-message-types nil)
             (list cl-pnet-ssh::+ssh-msg-kexinit+
                   cl-pnet-ssh::+ssh-msg-kex-ecdh-init+)))
  (is (equal (kexinit-message-types t)
             (list cl-pnet-ssh::+ssh-msg-kex-ecdh-init+))))

(test strict-kex-survives-a-rekey
  "The strict-KEX marker appears only in the first KEXINIT.
OpenSSH keeps resetting sequence numbers at every NEWKEYS, so dropping the
flag at a rekey would make the two sides count packets differently."
  (flet ((strict-after (initial negotiated)
           (let ((client (cl-pnet-ssh::%make-ssh-client)))
             (setf (cl-pnet-ssh::ssh-client-strict-kex client) initial)
             (let ((original-negotiate
                     (symbol-function 'cl-pnet-ssh::ssh-negotiate))
                   (original-send
                     (symbol-function 'cl-pnet-ssh::ssh-client-send-payload)))
               (unwind-protect
                    (progn
                      (setf (symbol-function 'cl-pnet-ssh::ssh-negotiate)
                            (lambda (offers &rest arguments)
                              (declare (ignore offers arguments))
                              (list :kex "curve25519-sha256"
                                    :host-key "ssh-ed25519"
                                    :cipher-c2s "chacha20-poly1305@openssh.com"
                                    :cipher-s2c "chacha20-poly1305@openssh.com"
                                    :mac-c2s "hmac-sha2-256"
                                    :mac-s2c "hmac-sha2-256"
                                    :compression-c2s "none"
                                    :compression-s2c "none"
                                    :strict negotiated)))
                      (setf (symbol-function
                             'cl-pnet-ssh::ssh-client-send-payload)
                            (lambda (client payload)
                              (declare (ignore client payload))
                              t))
                      (cl-pnet-ssh::ssh-client-handle-kexinit
                       client (ssh-make-kexinit-payload))
                      (cl-pnet-ssh::ssh-client-strict-kex client))
                 (setf (symbol-function 'cl-pnet-ssh::ssh-negotiate)
                       original-negotiate
                       (symbol-function
                        'cl-pnet-ssh::ssh-client-send-payload)
                       original-send))))))
    (is (eq t (strict-after nil t)))
    (is (eq t (strict-after t nil)))
    (is (null (strict-after nil nil)))))

(test channel-env-precedes-a-queued-exec
  (let ((channel (cl-pnet-ssh::%make-ssh-channel
                  :client (cl-pnet-ssh::%make-ssh-client)
                  :remote-id 7 :state :opening)))
    (ssh-channel-env channel "GIT_PROTOCOL" "version=2")
    (ssh-channel-exec channel "git-upload-pack 'repo'")
    (let* ((confirmation (concatenated
                          (ssh-uint32-octets 7)
                          (ssh-uint32-octets 1048576)
                          (ssh-uint32-octets 32768)))
           (messages
             (captured-channel-messages
              channel
              (lambda ()
                (cl-pnet-ssh::ssh-channel-handle-open-confirmation
                 channel (ssh-make-reader confirmation))))))
      (is (= 2 (length messages)))
      (multiple-value-bind (type remote request reply fields)
          (channel-request-parts (first messages))
        (is (= type cl-pnet-ssh::+ssh-msg-channel-request+))
        (is (= remote 7))
        (is (string= request "env"))
        (is (not reply))
        (is (equal fields '("GIT_PROTOCOL" "version=2"))))
      (multiple-value-bind (type remote request reply fields)
          (channel-request-parts (second messages))
        (is (= type cl-pnet-ssh::+ssh-msg-channel-request+))
        (is (= remote 7))
        (is (string= request "exec"))
        (is (eq t reply))
        (is (equal fields '("git-upload-pack 'repo'")))))))

(test server-kexinit-honours-configured-algorithms
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let ((directory (ssh-test-directory "cl-pnet-ssh-algos")))
        (unwind-protect
             (let* ((keys (test-server-algorithm-keys directory))
                    (config
                      (ssh-server-config-load
                       nil
                       :options
                       '("Ciphers chacha20-poly1305@openssh.com"
                         "MACs hmac-sha2-512"
                         "KexAlgorithms curve25519-sha256@libssh.org"
                         "HostKeyAlgorithms rsa-sha2-512")))
                    (server (cl-pnet-ssh::%make-ssh-server
                             :host-keys keys :sshd-config config))
                    (session (cl-pnet-ssh::%make-ssh-session :server server))
                    (offer
                      (ssh-parse-kexinit-payload
                       (cl-pnet-ssh::ssh-server-make-kexinit-payload
                        session))))
               ;; The chosen method, then the markers a KexAlgorithms value
               ;; must never remove.
               (is (equal '("curve25519-sha256@libssh.org"
                            "kex-strict-s-v00@openssh.com"
                            "ext-info-s")
                          (getf offer :kex)))
               ;; Only rsa-sha2-512 was chosen and the RSA key can sign it.
               (is (equal '("rsa-sha2-512") (getf offer :host-keys)))
               (is (equal '("chacha20-poly1305@openssh.com")
                          (getf offer :ciphers-c2s)))
               (is (equal '("hmac-sha2-512") (getf offer :macs-c2s)))
               ;; Negotiation must pick from the same restricted lists, not
               ;; merely advertise them.
               (let ((negotiated
                       (cl-pnet-ssh::ssh-server-negotiate
                        session
                        '(:kex ("curve25519-sha256"
                                "curve25519-sha256@libssh.org")
                          :host-keys ("ssh-ed25519" "rsa-sha2-512")
                          :ciphers-c2s ("chacha20-poly1305@openssh.com")
                          :ciphers-s2c ("chacha20-poly1305@openssh.com")
                          :macs-c2s ("hmac-sha2-256" "hmac-sha2-512")
                          :macs-s2c ("hmac-sha2-256" "hmac-sha2-512")
                          :compressions-c2s ("none")
                          :compressions-s2c ("none")))))
                 (is (equal "curve25519-sha256@libssh.org"
                            (getf negotiated :kex)))
                 (is (equal "rsa-sha2-512" (getf negotiated :host-key)))
                 (is (equal "hmac-sha2-512"
                            (getf negotiated :mac-c2s)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-host-keys-obey-required-rsa-size
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let ((directory (ssh-test-directory "cl-pnet-ssh-rsasize")))
        (unwind-protect
             (let* ((short (merge-pathnames "rsa-1024" directory))
                    (long (merge-pathnames "rsa-2048" directory))
                    (ed25519 (merge-pathnames "ed25519" directory)))
               (ensure-directories-exist short)
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "1024" "-N" ""
                                 "-f" (namestring short)))
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "2048" "-N" ""
                                 "-f" (namestring long)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ed25519)))
               (let* ((short-key (ssh-load-private-key short))
                      (long-key (ssh-load-private-key long))
                      (ed-key (ssh-load-private-key ed25519))
                      (restricted
                        (ssh-server-config-load
                         nil :options '("RequiredRSASize 2048")))
                      (default (ssh-server-config-load nil))
                      (session-for
                        (lambda (config)
                          (let ((server (cl-pnet-ssh::%make-ssh-server
                                         :host-keys (list short-key long-key
                                                          ed-key)
                                         :sshd-config config)))
                            (cl-pnet-ssh::%make-ssh-session
                             :server server)))))
                 ;; 2048 is the minimum, so the 1024-bit key is skipped and
                 ;; the other two are still presentable.
                 (let ((keys (cl-pnet-ssh::ssh-session-host-keys
                              (funcall session-for restricted))))
                   (is (= 2 (length keys)))
                   (is (not (member short-key keys :test #'eq)))
                   (is (member long-key keys :test #'eq))
                   (is (member ed-key keys :test #'eq))
                   ;; Only the remaining keys' algorithms are advertised.
                   (is (equal '("ssh-ed25519" "rsa-sha2-512" "rsa-sha2-256"
                                "ssh-rsa")
                              (cl-pnet-ssh::ssh-server-host-key-algorithms-for
                               (funcall session-for restricted)))))
                 ;; Without the directive sshd still enforces its own 1024-bit
                 ;; floor, which the short key meets.
                 (is (= 3
                        (length (cl-pnet-ssh::ssh-session-host-keys
                                 (funcall session-for default)))))
                 ;; Host keys are filtered once at startup from the global
                 ;; directive; a Match block that lowers RequiredRSASize must
                 ;; not bring a key sshd already skipped back into KEXINIT.
                 (let ((session
                         (cl-pnet-ssh::%make-ssh-session
                          :server (cl-pnet-ssh::%make-ssh-server
                                   :host-keys (list short-key long-key ed-key)
                                   :sshd-config restricted)
                          :config
                          (ssh-server-config-load
                           nil :options '("RequiredRSASize 1024")))))
                   (is (= 2 (length (cl-pnet-ssh::ssh-session-host-keys
                                     session))))
                   (is (not (member short-key
                                    (cl-pnet-ssh::ssh-session-host-keys session)
                                    :test #'eq))))
                 ;; sshd refuses to start rather than listen with no usable
                 ;; host key; the caller's own NIL list is left alone.
                 (signals ssh-connection-error
                   (cl-pnet-ssh::ssh-server-check-host-keys
                    (list short-key) 2048))
                 (is (equal (list short-key)
                            (cl-pnet-ssh::ssh-server-check-host-keys
                             (list short-key) nil)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-user-key-policy-follows-config
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let ((directory (ssh-test-directory "cl-pnet-ssh-userkey")))
        (unwind-protect
             (let* ((short (merge-pathnames "rsa-1024" directory))
                    (ed25519 (merge-pathnames "ed25519" directory)))
               (ensure-directories-exist short)
               (ssh-keygen (list "-q" "-t" "rsa" "-b" "1024" "-N" ""
                                 "-f" (namestring short)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ed25519)))
               (let* ((rsa-blob (ssh-public-key-blob-of
                                 (ssh-load-private-key short)))
                      (ed-blob (ssh-public-key-blob-of
                                (ssh-load-private-key ed25519)))
                      (restricted
                        (ssh-server-config-load
                         nil
                         :options
                         '("PubkeyAcceptedAlgorithms rsa-sha2-512"
                           "RequiredRSASize 2048")))
                      (default (ssh-server-config-load nil))
                      (session-for
                        (lambda (config)
                          (let ((server (cl-pnet-ssh::%make-ssh-server
                                         :host-keys nil :sshd-config config)))
                            (cl-pnet-ssh::%make-ssh-session
                             :server server)))))
                 (let ((session (funcall session-for restricted)))
                   ;; The configured list replaces the default, so an
                   ;; ed25519 signature and SHA-1 ssh-rsa are both refused.
                   (is (not (cl-pnet-ssh::ssh-session-user-key-algorithm-p
                             session ed-blob "ssh-ed25519")))
                   (is (cl-pnet-ssh::ssh-session-user-key-algorithm-p
                        session rsa-blob "rsa-sha2-512"))
                   (is (not (cl-pnet-ssh::ssh-session-user-key-algorithm-p
                             session rsa-blob "ssh-rsa")))
                   ;; RequiredRSASize 2048 rejects the 1024-bit key.
                   (is (not (cl-pnet-ssh::ssh-session-user-key-length-p
                             session rsa-blob)))
                   (is (cl-pnet-ssh::ssh-session-user-key-length-p
                        session ed-blob)))
                 ;; Without the directives, the old SHA-1 name stays usable
                 ;; for old clients and the built-in 1024-bit floor passes.
                 (let ((session (funcall session-for default)))
                   (is (cl-pnet-ssh::ssh-session-user-key-algorithm-p
                        session rsa-blob "ssh-rsa"))
                   (is (cl-pnet-ssh::ssh-session-user-key-length-p
                        session rsa-blob)))))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-permit-listen-restricts-remote-forwards
  (let* ((config
           (ssh-server-config-load
            nil
            :options '("PermitListen 8080 localhost:9000")))
         (server (cl-pnet-ssh::%make-ssh-server :sshd-config config))
         (session (cl-pnet-ssh::%make-ssh-session
                   :server server
                   :authorization
                   (cl-pnet-ssh::%make-ssh-authorization-options))))
    ;; A bare port is a wildcard host.
    (is (ssh-session-permits-tcpip-forward-p session "" 8080))
    (is (ssh-session-permits-tcpip-forward-p session "example.com" 8080))
    ;; A named host matches case-insensitively and only that host.
    (is (ssh-session-permits-tcpip-forward-p session "localhost" 9000))
    (is (ssh-session-permits-tcpip-forward-p session "LOCALHOST" 9000))
    (is (not (ssh-session-permits-tcpip-forward-p session "" 9000)))
    (is (not (ssh-session-permits-tcpip-forward-p session "example.com" 9000)))
    (is (not (ssh-session-permits-tcpip-forward-p session "localhost" 8081)))
    ;; PermitListen none refuses every listener.
    (let* ((none (ssh-server-config-load
                  nil :options '("PermitListen none")))
           (session (cl-pnet-ssh::%make-ssh-session
                     :server (cl-pnet-ssh::%make-ssh-server :sshd-config none)
                     :authorization
                     (cl-pnet-ssh::%make-ssh-authorization-options))))
      (is (not (ssh-session-permits-tcpip-forward-p session "" 8080))))
    ;; The key's own permitlisten= narrows the administrator's list further.
    (let ((session (cl-pnet-ssh::%make-ssh-session
                    :server server
                    :authorization
                    (cl-pnet-ssh::%make-ssh-authorization-options
                     :permit-listen '(("localhost" . 8080))))))
      (is (ssh-session-permits-tcpip-forward-p session "localhost" 8080))
      (is (not (ssh-session-permits-tcpip-forward-p
                session "example.com" 8080))))))

(test server-sends-newkeys-and-ext-info-in-one-write
  ;; libssh decides how to sign an RSA key from server-sig-algs before its
  ;; next read of the socket.  An EXT_INFO left in a second segment makes it
  ;; fall back to SHA-1 ssh-rsa and refuse the key without ever asking, so
  ;; the two packets must leave in one write, as OpenSSH's server sends them.
  (let* ((original (symbol-function 'cl-pnet:send-data))
         (writes '())
         (capture
           (lambda (negotiated)
             (setf writes nil)
             (let* ((server (cl-pnet-ssh::%make-ssh-server :host-keys nil))
                    (session (cl-pnet-ssh::%make-ssh-session
                              :server server)))
               (setf (cl-pnet-ssh::ssh-session-connection session) :captured
                     (cl-pnet-ssh::ssh-session-negotiated session)
                     negotiated)
               (cl-pnet-ssh::ssh-server-send-newkeys session)
               (values (length writes) (first writes))))))
    (unwind-protect
         (progn
           (setf (symbol-function 'cl-pnet:send-data)
                 (lambda (connection data &key on-error on-write)
                   (declare (ignore connection on-error on-write))
                   (push (copy-seq data) writes)
                   (length data)))
           (multiple-value-bind (write-count wire)
               (funcall capture '(:ext-info t))
             ;; One write, holding NEWKEYS then EXT_INFO.
             (is (= 1 write-count))
             (let ((state (cl-pnet-ssh::ssh-make-cipher-state)))
               (multiple-value-bind (payload consumed)
                   (ssh-decode-packet wire state)
                 (is (= cl-pnet-ssh::+ssh-msg-newkeys+ (aref payload 0)))
                 (let ((ext (ssh-decode-packet (subseq wire consumed) state)))
                   (is (= cl-pnet-ssh::+ssh-msg-ext-info+ (aref ext 0)))
                   (let ((reader (ssh-make-reader ext)))
                     (ssh-read-u8 reader)
                     (is (= 3 (ssh-read-u32 reader)))
                     (is (string= "server-sig-algs" (ssh-read-text reader)))
                     (is (member "rsa-sha2-512"
                                 (ssh-read-name-list reader)
                                 :test #'string=))
                     (is (string= "ping@openssh.com"
                                  (ssh-read-text reader)))
                     (is (equalp (cl-pnet-ssh::ssh-string-octets "0")
                                 (ssh-read-string reader))))))))
           ;; Without a client that asked for extensions, only NEWKEYS.
           (multiple-value-bind (plain-count plain-wire)
               (funcall capture '(:ext-info nil))
             (is (= 1 plain-count))
             (let ((decoded (ssh-decode-packet
                             plain-wire
                             (cl-pnet-ssh::ssh-make-cipher-state))))
               (is (= cl-pnet-ssh::+ssh-msg-newkeys+ (aref decoded 0))))))
      (setf (symbol-function 'cl-pnet:send-data) original))))

(defun compression-payload (length)
  "A deterministic payload of LENGTH octets that compresses well."
  (let ((octets (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length octets)
      (setf (aref octets i) (+ 65 (mod i 26))))))

(defun compressed-round-trip (sender receiver payload)
  "Encode PAYLOAD through SENDER and decode it through RECEIVER."
  (let ((wire (ssh-encode-packet payload sender)))
    (multiple-value-bind (decoded consumed) (ssh-decode-packet wire receiver)
      (is (= (length wire) consumed))
      decoded)))

(test compression-is-delayed-until-authentication
  "zlib@openssh.com leaves the stream plain until USERAUTH_SUCCESS."
  (let ((sender (cl-pnet-ssh::ssh-make-cipher-state))
        (receiver (cl-pnet-ssh::ssh-make-cipher-state))
        (payload (compression-payload 200)))
    (cl-pnet-ssh::ssh-install-send-compression sender "zlib@openssh.com")
    (cl-pnet-ssh::ssh-install-receive-compression receiver "zlib@openssh.com")
    ;; Both codecs exist but stay idle, so this first packet is plain.  A
    ;; sender that compressed here would hand the receiver its compressed
    ;; bytes as the payload, which is exactly what the equality catches.
    (is (equalp payload (compressed-round-trip sender receiver payload)))
    (is (not (cl-pnet-ssh::ssh-cipher-state-send-compression-enabled sender)))
    (cl-pnet-ssh::ssh-enable-delayed-compression sender)
    (cl-pnet-ssh::ssh-enable-delayed-compression receiver)
    (is (cl-pnet-ssh::ssh-cipher-state-send-compression-enabled sender))
    ;; Now the same bytes must survive a compressed round trip in both
    ;; directions, which a codec on only one side cannot fake.
    (is (equalp payload (compressed-round-trip sender receiver payload)))))

(test compression-resets-at-newkeys
  "A rekey resets both streams and the new zlib header rides the next packet."
  (let ((sender (cl-pnet-ssh::ssh-make-cipher-state))
        (receiver (cl-pnet-ssh::ssh-make-cipher-state))
        (payload (compression-payload 500)))
    (cl-pnet-ssh::ssh-install-send-compression sender "zlib@openssh.com"
                                              :after-authentication t)
    (cl-pnet-ssh::ssh-install-receive-compression receiver "zlib@openssh.com"
                                                  :after-authentication t)
    (is (equalp payload (compressed-round-trip sender receiver payload)))
    ;; NEWKEYS: both directions discard their window.  The compressor hands
    ;; back the fresh zlib header, which must lead the next packet.
    (cl-pnet-ssh::ssh-install-send-compression sender "zlib@openssh.com"
                                              :after-authentication t)
    (is (not (null (cl-pnet-ssh::ssh-cipher-state-send-compression-prefix
                    sender))))
    (cl-pnet-ssh::ssh-install-receive-compression receiver "zlib@openssh.com"
                                                  :after-authentication t)
    (is (equalp payload (compressed-round-trip sender receiver payload)))
    (is (null (cl-pnet-ssh::ssh-cipher-state-send-compression-prefix
               sender)))))

(test compression-round-trips-a-window-sized-packet
  "A packet larger than the codec's 32 KiB chunk survives both directions."
  (let ((sender (cl-pnet-ssh::ssh-make-cipher-state))
        (receiver (cl-pnet-ssh::ssh-make-cipher-state))
        (payload (compression-payload 70000)))
    (cl-pnet-ssh::ssh-install-send-compression sender "zlib@openssh.com"
                                              :after-authentication t)
    (cl-pnet-ssh::ssh-install-receive-compression receiver "zlib@openssh.com"
                                                  :after-authentication t)
    (is (equalp payload (compressed-round-trip sender receiver payload)))))

(test compression-round-trips-a-one-octet-packet
  "An empty block still has a flushed packet boundary to inflate."
  (let ((sender (cl-pnet-ssh::ssh-make-cipher-state))
        (receiver (cl-pnet-ssh::ssh-make-cipher-state))
        (payload (compression-payload 1)))
    (cl-pnet-ssh::ssh-install-send-compression sender "zlib@openssh.com"
                                              :after-authentication t)
    (cl-pnet-ssh::ssh-install-receive-compression receiver "zlib@openssh.com"
                                                  :after-authentication t)
    (is (equalp payload (compressed-round-trip sender receiver payload)))))

(test compression-none-installs-no-codec
  "Negotiated none never creates a compressor or inflater."
  (let ((state (cl-pnet-ssh::ssh-make-cipher-state))
        (payload (compression-payload 100)))
    (cl-pnet-ssh::ssh-install-send-compression state "none")
    (cl-pnet-ssh::ssh-install-receive-compression state "none")
    (is (null (cl-pnet-ssh::ssh-cipher-state-send-compression state)))
    (is (null (cl-pnet-ssh::ssh-cipher-state-receive-compression state)))
    (let ((wire (ssh-encode-packet payload state)))
      (multiple-value-bind (decoded consumed) (ssh-decode-packet wire state)
        (is (= (length wire) consumed))
        (is (equalp payload decoded))))))

(test compression-corrupt-stream-is-refused
  "Garbage on a compressed stream is a protocol error, not a packet."
  (let ((state (cl-pnet-ssh::ssh-make-cipher-state)))
    (cl-pnet-ssh::ssh-install-receive-compression state "zlib@openssh.com"
                                                  :after-authentication t)
    (signals cl-pnet-ssh::ssh-protocol-error
      (cl-pnet-ssh::ssh-decompress-payload
       (make-array 8 :element-type '(unsigned-byte 8)
                     :initial-element #xff)
       state))))

(test kexinit-compression-offer-follows-the-request
  "A -C client offers zlib first; the default leaves it second."
  (let ((default (ssh-parse-kexinit-payload (ssh-make-kexinit-payload)))
        (requested
          (ssh-parse-kexinit-payload
           (ssh-make-kexinit-payload
            :compressions cl-pnet-ssh::+ssh-compressions-preferred+))))
    (is (equal '("none" "zlib@openssh.com")
               (getf default :compressions-c2s)))
    (is (equal '("zlib@openssh.com" "none")
               (getf requested :compressions-c2s)))
    (is (equal (getf requested :compressions-c2s)
               (getf requested :compressions-s2c)))))

(test negotiate-honours-the-client-compression-order
  "The client's list decides compression, not the server's own order."
  (let ((server-offer
          (ssh-parse-kexinit-payload
           (ssh-make-kexinit-payload
            :compressions '("none" "zlib@openssh.com")))))
    (let ((negotiated (ssh-negotiate server-offer)))
      (is (string= "none" (getf negotiated :compression-c2s)))
      (is (string= "none" (getf negotiated :compression-s2c))))
    (let ((negotiated
            (ssh-negotiate
             server-offer
             :compressions cl-pnet-ssh::+ssh-compressions-preferred+)))
      (is (string= "zlib@openssh.com" (getf negotiated :compression-c2s)))
      (is (string= "zlib@openssh.com" (getf negotiated :compression-s2c))))))

(test server-compression-offer-follows-compression-no
  "sshd offers zlib by default and only none when Compression is off."
  (let ((on (cl-pnet-ssh::%make-ssh-server :host-keys nil))
        (off (cl-pnet-ssh::%make-ssh-server
              :host-keys nil
              :sshd-config (ssh-server-config-load
                            nil :options '("Compression no")))))
    (is (equal '("none" "zlib@openssh.com")
               (cl-pnet-ssh::ssh-server-compression-offer
                (cl-pnet-ssh::%make-ssh-session :server on))))
    (is (equal '("none")
               (cl-pnet-ssh::ssh-server-compression-offer
                (cl-pnet-ssh::%make-ssh-session :server off))))))

(test rekey-limit-triggers-on-volume-or-time
  "The client rekeys only after auth, and only once a packet has crossed."
  (let ((client (cl-pnet-ssh::%make-ssh-client)))
    ;; Before authentication no limit applies, as OpenSSH's
    ;; after_authentication gate requires.
    (setf (cl-pnet-ssh::ssh-client-phase client) :ready
          (cl-pnet-ssh::ssh-client-rekey-limit client) 16
          (cl-pnet-ssh::ssh-client-sent-packets client) 1
          (cl-pnet-ssh::ssh-client-sent-blocks client) 3)
    (is (not (cl-pnet-ssh::ssh-client-need-rekey-p client)))
    (setf (cl-pnet-ssh::ssh-client-after-authentication client) t)
    ;; A 16-byte limit on this build's 8-byte cipher blocks is two blocks.
    (is (cl-pnet-ssh::ssh-client-need-rekey-p client))
    ;; OpenSSH's one-packet-in-or-out rule keeps an idle connection idle.
    (setf (cl-pnet-ssh::ssh-client-sent-packets client) 0
          (cl-pnet-ssh::ssh-client-sent-blocks client) 0)
    (is (not (cl-pnet-ssh::ssh-client-need-rekey-p client)))
    ;; Time-based rekeying needs the same traffic.
    (setf (cl-pnet-ssh::ssh-client-rekey-limit client) 0
          (cl-pnet-ssh::ssh-client-rekey-interval client) 10
          (cl-pnet-ssh::ssh-client-rekey-time client)
          (- (cl-pnet-ssh::ssh-client-now) 20)
          (cl-pnet-ssh::ssh-client-received-packets client) 1)
    (is (cl-pnet-ssh::ssh-client-need-rekey-p client))))

(test rekey-queues-application-packets
  "While a rekey is in progress, only key-exchange messages go out directly."
  (let ((client (cl-pnet-ssh::%make-ssh-client))
        (payload (cl-pnet-ssh::ssh-writer-output
                  (let ((writer (cl-pnet-ssh::ssh-writer)))
                    (cl-pnet-ssh::ssh-write-u8 writer 90)
                    (cl-pnet-ssh::ssh-write-string writer
                                                   (cl-pnet-ssh::ssh-string-octets "x"))
                    writer))))
    (setf (cl-pnet-ssh::ssh-client-rekeying client) t)
    (is (null (cl-pnet-ssh::ssh-client-send-payload client payload)))
    (is (= 1 (length (cl-pnet-ssh::ssh-client-outgoing-queue client))))
    (is (eq payload
            (first (cl-pnet-ssh::ssh-client-outgoing-queue client))))
    ;; A KEXINIT is transport traffic and bypasses the queue.
    (let ((kexinit (cl-pnet-ssh::ssh-make-kexinit-payload)))
      (setf (cl-pnet-ssh::ssh-client-outgoing-queue client) nil)
      (cl-pnet-ssh::ssh-client-send-payload client kexinit)
      (is (null (cl-pnet-ssh::ssh-client-outgoing-queue client))))))

(test client-rekeys-after-rekeylimit-volume
  "A small client RekeyLimit makes the client start its own exchange and then
finish the session normally."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let ((count 0)
            (original (symbol-function
                       'cl-pnet-ssh::ssh-client-start-rekey)))
        (unwind-protect
             (progn
               (setf (symbol-function
                      'cl-pnet-ssh::ssh-client-start-rekey)
                     (lambda (client)
                       (let ((started (funcall original client)))
                         (when started (incf count))
                         started)))
               (multiple-value-bind (stdout stderr status)
                   (ssh-test-loopback-result :rekey-limit 16)
                 (is (= 3 status))
                 (is (string= "hello" stdout))
                 (is (string= "oops" stderr))
                 (is (plusp count))))
          (setf (symbol-function 'cl-pnet-ssh::ssh-client-start-rekey)
                original)))))

(test server-rekeys-after-rekeylimit-volume
  "A small sshd RekeyLimit makes the server start its own exchange, which the
client answers before the session continues."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let ((count 0)
            (original (symbol-function
                       'cl-pnet-ssh::ssh-session-start-rekey)))
        (unwind-protect
             (progn
               (setf (symbol-function
                      'cl-pnet-ssh::ssh-session-start-rekey)
                     (lambda (session)
                       (let ((started (funcall original session)))
                         (when started (incf count))
                         started)))
               (multiple-value-bind (stdout stderr status)
                   (ssh-test-loopback-result :sshd-options '("RekeyLimit 16"))
                 (is (= 3 status))
                 (is (string= "hello" stdout))
                 (is (string= "oops" stderr))
                 (is (plusp count))))
          (setf (symbol-function 'cl-pnet-ssh::ssh-session-start-rekey)
                original)))))

(test proxy-command-expands-ssh-escapes
  (let ((client (cl-pnet-ssh::%make-ssh-client
                 :host "alias" :connect-host "real.example"
                 :port 2222 :connect-port 2222 :user "alice")))
    (is (equal "nc real.example 2222"
               (cl-pnet-ssh::ssh-proxy-expand-command "nc %h %p" client)))
    (is (equal "alias:alice:100%"
               (cl-pnet-ssh::ssh-proxy-expand-command
                "%n:%r:100%%" client)))
    ;; An escape this client does not know stays literal rather than eaten.
    (is (equal "%z and %" (cl-pnet-ssh::ssh-proxy-expand-command
                           "%z and %" client)))))

;;; ---- Behaviour the pure transport provides and libssh does not ----
;;;
;;; These are end-to-end SSH features, but not features libssh implements:
;;; its client has no hostbased userauth, no banner setter (the banner is
;;; hashed into the exchange hash), and its server KEX cannot present a host
;;; certificate or parse a hostbased request.  The backend-neutral facade
;;; suite therefore cannot require them of every backend; they are tested
;;; here, with the transport that implements them.  The application layer
;;; (bursyk-client/bursyk-server) owns the policy that selects them.

(test client-version-addendum-reaches-the-server
  "A login still verifies when the addendum is part of the greeting, and the
server records the full string."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-addendum"))
             (server-key (merge-pathnames "host_key" directory))
             (client-key (merge-pathnames "client_key" directory))
             (authorized (merge-pathnames "authorized_keys" directory))
             (known-hosts (merge-pathnames "known_hosts" directory))
             (stdout (make-string-output-stream))
             (seen nil)
             (server nil))
        (ensure-directories-exist server-key)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring server-key)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring client-key)))
               (ssh-test-write-authorized-keys
                (merge-pathnames "client_key.pub" directory) authorized)
               (setf server
                     (make-ssh-server
                      "127.0.0.1" 0
                      :host-key server-key
                      :authorized-keys authorized
                      :on-session
                      (lambda (session)
                        (setf seen (cl-pnet-ssh:ssh-session-client-version
                                    session)))
                      :on-channel
                      (lambda (channel)
                        (setf (cl-pnet-ssh::ssh-server-channel-on-exec channel)
                              (lambda (channel command)
                                (ssh-test-run-command channel command))))))
               (is (= 3
                      (ssh-test-loopback-run
                       server client-key known-hosts stdout
                       (make-string-output-stream)
                       :version-addendum "cl-pnet-test")))
               (is (string= "hello"
                            (get-output-stream-string stdout)))
               (is (not (null (search "cl-pnet-test" (or seen ""))))))
          (when server (ssh-server-close server))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test server-loopback-host-certificate
  ;; The server presents the certificate, the client checks its CA against
  ;; @cert-authority in known_hosts, and the KEX signature is verified with
  ;; the plain key inside the certificate.
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-hostcert-loop"))
             (ca (merge-pathnames "ca" directory))
             (host-key (merge-pathnames "host_key" directory))
             (client-key (merge-pathnames "client_key" directory))
             (authorized (merge-pathnames "authorized_keys" directory))
             (known-hosts (merge-pathnames "known_hosts" directory))
             (stdout (make-string-output-stream))
             (stderr (make-string-output-stream))
             (server nil))
        (ensure-directories-exist ca)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring ca)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring host-key)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring client-key)))
               (ssh-keygen
                (list "-q" "-s" (namestring ca) "-I" "host-id"
                      "-h" "-n" "127.0.0.1" "-V" "-1m:+52w"
                      (namestring (merge-pathnames "host_key.pub" directory))))
               (ssh-test-write-authorized-keys
                (merge-pathnames "client_key.pub" directory) authorized)
               (setf server
                     (make-ssh-server
                      "127.0.0.1" 0
                      :host-key host-key
                      :host-certificate
                      (merge-pathnames "host_key-cert.pub" directory)
                      :authorized-keys authorized
                      :on-channel
                      (lambda (channel)
                        (setf (cl-pnet-ssh::ssh-server-channel-on-exec channel)
                              (lambda (channel command)
                                (ssh-test-run-command channel command))))))
               ;; The host's known_hosts name includes the ephemeral port.
               (with-open-file (out known-hosts :direction :output
                                               :if-exists :supersede
                                               :if-does-not-exist :create)
                 (with-open-file (in (merge-pathnames "ca.pub" directory))
                   (format out "@cert-authority [127.0.0.1]:~D ~A~%"
                           (ssh-server-port server)
                           (string-trim '(#\Space #\Return #\Newline)
                                        (read-line in)))))
               ;; Strict policy: only the certificate's CA can admit the host.
               (let ((status (ssh-test-loopback-run
                              server client-key known-hosts stdout stderr
                              :host-key-policy :strict)))
                 (is (equal "hello" (get-output-stream-string stdout)))
                 (is (equal "oops" (get-output-stream-string stderr)))
                 (is (eql 3 status))))
          (when server (ssh-server-close server))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test client-loopback-hostbased-authentication
  "The client authenticates with a host key and the server's hostbased hook."
  (if (not (ssh-keygen-available-p))
      (skip "ssh-keygen is not installed")
      (let* ((directory (ssh-test-directory "cl-pnet-ssh-hostbased-loop"))
             (server-key (merge-pathnames "server_key" directory))
             (hostbased-key (merge-pathnames "client_host_key" directory))
             (known-hosts (merge-pathnames "known_hosts" directory))
             (stdout (make-string-output-stream))
             (stderr (make-string-output-stream))
             (server nil))
        (ensure-directories-exist server-key)
        (unwind-protect
             (progn
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring server-key)))
               (ssh-keygen (list "-q" "-t" "ed25519" "-N" ""
                                 "-f" (namestring hostbased-key)))
               (setf server
                     (make-ssh-server
                      "127.0.0.1" 0
                      :host-key server-key
                      :sshd-config
                      (ssh-server-config-load
                       nil :options '("HostbasedAuthentication yes"))
                      :hostbased-key-allowed
                      (lambda (session user client-user client-host key)
                        (declare (ignore session user client-user client-host
                                         key))
                        t)
                      :on-channel
                      (lambda (channel)
                        (setf (cl-pnet-ssh::ssh-server-channel-on-exec channel)
                              (lambda (channel command)
                                (ssh-test-run-command channel command))))))
               (let ((status (ssh-test-loopback-run
                              server nil known-hosts stdout stderr
                              :host-key-policy :insecure
                              :hostbased-key hostbased-key)))
                 (is (equal "hello" (get-output-stream-string stdout)))
                 (is (equal "oops" (get-output-stream-string stderr)))
                 (is (eql 3 status))))
          (when server (ssh-server-close server))
          (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

;;; ---- Post-quantum key exchange ----

(test mlkem768-hybrids-agree
  "Each ML-KEM-768 hybrid derives one shared secret on both sides."
  (dolist (entry '(("mlkem768x25519-sha256" 1216 1120)
                   ("mlkem768nistp256-sha256" 1249 1153)))
    (destructuring-bind (kex client-size server-size) entry
      (let* ((state (cl-pnet-ssh::ssh-mlkem768-hybrid-client-keypair kex))
             (client-public
               (cl-pnet-ssh::ssh-mlkem768-hybrid-state-public state)))
        ;; ML-KEM-768 encapsulation key (1184) then the classical key.
        (is (= client-size (length client-public)))
        (multiple-value-bind (server-public shared)
            (cl-pnet-ssh::ssh-mlkem768-hybrid-server-shared
             kex client-public)
          ;; ML-KEM-768 ciphertext (1088) then the classical key.
          (is (= server-size (length server-public)))
          ;; OpenSSH hashes the ML-KEM and classical secrets together, so the
          ;; shared secret both sides use is one SHA-256 digest.
          (is (= 32 (length shared)))
          (is (equalp shared
                      (cl-pnet-ssh::ssh-mlkem768-hybrid-client-shared
                       state server-public)))))))
  (dolist (kex '("mlkem768x25519-sha256" "mlkem768nistp256-sha256"))
    (signals cl-pnet-ssh:ssh-protocol-error
      (cl-pnet-ssh::ssh-mlkem768-hybrid-server-shared
       kex (make-array 10 :element-type '(unsigned-byte 8))))))

(test mlkem768nistp256-is-selectable-but-not-default
  "mlkem768nistp256-sha256 is implemented yet absent from the default offer."
  (is (member "mlkem768nistp256-sha256"
              cl-pnet-ssh:+ssh-kex-real-algorithms+ :test #'string=))
  (is (not (member "mlkem768nistp256-sha256"
                   cl-pnet-ssh:+ssh-kex-default-algorithms+ :test #'string=)))
  (is (cl-pnet-ssh::ssh-kex-post-quantum-p "mlkem768nistp256-sha256"))
  ;; The default KEXINIT leaves it out; naming it puts it in.
  (let ((offers (cl-pnet-ssh::ssh-parse-kexinit-payload
                 (cl-pnet-ssh::ssh-make-kexinit-payload))))
    (is (not (member "mlkem768nistp256-sha256" (getf offers :kex)
                     :test #'string=))))
  (let ((offers (cl-pnet-ssh::ssh-parse-kexinit-payload
                 (cl-pnet-ssh::ssh-make-kexinit-payload
                  :kex '("mlkem768nistp256-sha256")))))
    (is (member "mlkem768nistp256-sha256" (getf offers :kex)
                :test #'string=)))
  ;; A peer that offers only the new method is matched when it is named.
  (let ((negotiated
          (cl-pnet-ssh::ssh-negotiate
           (list :kex '("mlkem768nistp256-sha256")
                 :host-keys cl-pnet-ssh:+ssh-host-key-algorithms+
                 :ciphers-c2s cl-pnet-ssh:+ssh-ciphers+
                 :ciphers-s2c cl-pnet-ssh:+ssh-ciphers+
                 :macs-c2s cl-pnet-ssh:+ssh-macs+
                 :macs-s2c cl-pnet-ssh:+ssh-macs+
                 :compressions-c2s '("none")
                 :compressions-s2c '("none"))
           :kex-algorithms '("mlkem768nistp256-sha256")
           :host-key-algorithms cl-pnet-ssh:+ssh-host-key-algorithms+
           :ciphers cl-pnet-ssh:+ssh-ciphers+
           :macs cl-pnet-ssh:+ssh-macs+
           :compressions '("none"))))
    (is (string= "mlkem768nistp256-sha256" (getf negotiated :kex)))))

;;; ---- NIST-curve ECDH key exchange ----

(test nist-curve-ecdh-agrees
  "Each NIST curve derives one shared secret on both sides."
  (dolist (entry '(("ecdh-sha2-nistp256" 32 :sha256)
                   ("ecdh-sha2-nistp384" 48 :sha384)
                   ("ecdh-sha2-nistp521" 66 :sha512)))
    (destructuring-bind (kex size digest) entry
      (multiple-value-bind (curve actual-size actual-digest)
          (cl-pnet-ssh::ssh-ecdh-kex-parameters kex)
        (is (not (null curve)))
        (is (= size actual-size))
        (is (eq digest actual-digest)))
      (multiple-value-bind (private-a public-a)
          (cl-pnet-ssh::ssh-ecdh-keypair kex)
        (multiple-value-bind (private-b public-b)
            (cl-pnet-ssh::ssh-ecdh-keypair kex)
          (let ((ab (cl-pnet-ssh::ssh-ecdh-shared private-a public-b kex))
                (ba (cl-pnet-ssh::ssh-ecdh-shared private-b public-a kex)))
            ;; The wire point is uncompressed SEC1; the secret is only X.
            (is (= (1+ (* 2 size)) (length public-a)))
            (is (= 4 (aref public-a 0)))
            (is (= size (length ab)))
            (is (equalp ab ba)))))))
  ;; A peer point that is not on the curve is a protocol error, not a crash.
  (signals cl-pnet-ssh:ssh-protocol-error
    (cl-pnet-ssh::ssh-ecdh-shared
     (multiple-value-bind (private public)
         (cl-pnet-ssh::ssh-ecdh-keypair "ecdh-sha2-nistp256")
       (declare (ignore public))
       private)
     (make-array 65 :element-type '(unsigned-byte 8) :initial-element 0)
     "ecdh-sha2-nistp256")))

(test nist-curve-kex-is-offered
  "The three NIST-curve methods follow curve25519 in the default offer."
  (is (equal '("ecdh-sha2-nistp256" "ecdh-sha2-nistp384"
               "ecdh-sha2-nistp521")
             (last cl-pnet-ssh:+ssh-kex-real-algorithms+ 3)))
  (dolist (kex '("ecdh-sha2-nistp256" "ecdh-sha2-nistp384"
                 "ecdh-sha2-nistp521"))
    (let ((negotiated
            (cl-pnet-ssh::ssh-negotiate
             (list :kex (list kex)
                   :host-keys cl-pnet-ssh:+ssh-host-key-algorithms+
                   :ciphers-c2s cl-pnet-ssh:+ssh-ciphers+
                   :ciphers-s2c cl-pnet-ssh:+ssh-ciphers+
                   :macs-c2s cl-pnet-ssh:+ssh-macs+
                   :macs-s2c cl-pnet-ssh:+ssh-macs+
                   :compressions-c2s '("none")
                   :compressions-s2c '("none"))
             :kex-algorithms (list kex)
             :host-key-algorithms cl-pnet-ssh:+ssh-host-key-algorithms+
             :ciphers cl-pnet-ssh:+ssh-ciphers+
             :macs cl-pnet-ssh:+ssh-macs+
             :compressions '("none"))))
      (is (string= kex (getf negotiated :kex))))))
