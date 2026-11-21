(in-package #:cl-pnet-ssh)

;;;; The client's transport state machine: version exchange, KEX, NEWKEYS,
;;;; userauth, then dispatch to channels. Everything runs from cl-pnet
;;;; callbacks, so no function here waits for the peer.

(defun ssh-client-set-ip-qos (client interactive-p)
  "Apply CLIENT's IPQoS DSCP value for an interactive or bulk session."
  (let ((value (if interactive-p
                   (ssh-client-ip-qos-interactive client)
                   (ssh-client-ip-qos-bulk client)))
        (connection (ssh-client-connection client)))
    (when (and connection (integerp value))
      (let ((fd (cl-pnet:connection-fileno connection)))
        (when fd
          (cl-pnet-sockets:set-socket-option
           fd cl-pnet-sockets:+ipproto-ip+
           cl-pnet-sockets:+ip-tos+ value))))))

(defun ssh-client-connected (client connection)
  "CLIENT's TCP connection is up: greet and offer our KEXINIT."
  (setf (ssh-client-connection client) connection
        (ssh-client-phase client) :version)
  ;; The session type is not known yet; the application may raise this to
  ;; the interactive value once it decides whether to request a pty.
  (ssh-client-set-ip-qos client nil)
  (unless (ssh-client-tcp-keep-alive client)
    (let ((fd (cl-pnet:connection-fileno connection)))
      (when fd
        (cl-pnet-sockets:set-socket-option
         fd cl-pnet-sockets:+sol-socket+
         cl-pnet-sockets:+so-keepalive+ 0))))
  (ssh-client-send-bytes
   client
   (ssh-string-octets (concatenate 'string
                                   (ssh-client-client-version client)
                                   (string #\Return)
                                   (string #\Newline))))
  (let ((kexinit (ssh-make-kexinit-payload
                  :kex (ssh-client-kex-algorithms client)
                  :host-keys (ssh-client-host-key-algorithms client)
                  :ciphers (ssh-client-ciphers client)
                  :macs (ssh-client-macs client))))
    (setf (ssh-client-client-kexinit client) kexinit
          (ssh-client-kexinit-sent client) t)
    (ssh-client-send-payload client kexinit)))

(defun ssh-client-read-version-line (client)
  "Consume one line of the version exchange.

Returns :VERSION when the peer line arrived, :BANNER for a pre-version
line, and NIL while the line is still incomplete."
  (let* ((buffer (ssh-client-incoming client))
         (newline (position 10 buffer)))
    (when newline
      (let ((line (string-right-trim
                   '(#\Return)
                   (map 'string #'code-char (subseq buffer 0 newline)))))
        (ssh-client-buffer-consume client (1+ newline))
        (if (and (>= (length line) 4) (string= (subseq line 0 4) "SSH-"))
            (progn
              (setf (ssh-client-server-version client) line
                    (ssh-client-phase client) :kex)
              (ssh-log "remote version ~A" line)
              :version)
            (progn
              (ssh-log "remote banner ~A" line)
              :banner))))))

(defun ssh-client-advance (client)
  "Process every complete message in CLIENT's receive buffer."
  (handler-case
      (iter (while (not (ssh-client-closed-p client)))
        (if (eq (ssh-client-phase client) :version)
            (unless (ssh-client-read-version-line client) (leave))
            (multiple-value-bind (payload consumed)
                (ssh-decode-packet (ssh-client-incoming client)
                                   (ssh-client-cipher client))
              (when (eq payload :incomplete) (leave))
              (ssh-client-buffer-consume client consumed)
              (ssh-client-handle-payload client payload))))
    (error (condition)
      (ssh-client-fail client condition))))

(defun ssh-client-receive (client data)
  "The event loop has DATA for CLIENT, or NIL at the end of the connection."
  (unless (ssh-client-closed-p client)
    (if (null data)
        (ssh-client-finish client :peer-closed :close)
        (progn
          (ssh-client-buffer-append client data)
          (ssh-client-advance client)))))

(defun ssh-client-handle-payload (client payload)
  "Dispatch one decrypted protocol message."
  ;; Any traffic from the peer answers a keepalive, as OpenSSH counts it:
  ;; even an unrelated packet proves the server is still there.
  (setf (ssh-client-alive-misses client) 0)
  (when (ssh-client-ignore-next-kex-packet client)
    (setf (ssh-client-ignore-next-kex-packet client) nil)
    (when (<= +ssh-msg-kex-ecdh-init+ (aref payload 0)
              +ssh-msg-kex-ecdh-reply+)
      (return-from ssh-client-handle-payload nil)))
  (let ((type (aref payload 0)))
    (cond
      ((= type +ssh-msg-disconnect+)
       (ssh-client-handle-disconnect client payload))
      ((= type +ssh-msg-kexinit+)
       (ssh-client-handle-kexinit client payload))
      ((= type +ssh-msg-kex-ecdh-reply+)
       (ssh-client-handle-kex-reply client payload))
      ((= type +ssh-msg-newkeys+)
       (ssh-client-handle-newkeys client))
      ((= type +ssh-msg-ext-info+)
       ;; RFC 8308 server-sig-algs and friends.  This client already knows
       ;; which signatures it can offer, so the announcement adds nothing.
       nil)
      ((= type +ssh-msg-service-accept+)
       (ssh-client-handle-service-accept client payload))
      ((= type +ssh-msg-userauth-banner+)
       (ssh-client-handle-banner client payload))
      ((= type +ssh-msg-userauth-success+)
       (ssh-client-handle-auth-success client))
      ((= type +ssh-msg-userauth-failure+)
       (ssh-client-handle-auth-failure client payload))
      ((= type +ssh-msg-global-request+)
       (ssh-client-handle-global-request client payload))
      ((= type +ssh-msg-request-success+)
       (ssh-client-handle-global-reply client payload t))
      ((= type +ssh-msg-request-failure+)
       (ssh-client-handle-global-reply client payload nil))
      ((<= +ssh-msg-channel-open+ type +ssh-msg-channel-failure+)
       (ssh-client-handle-channel-message client payload)))))

(defun ssh-client-handle-disconnect (client payload)
  "The peer is going away: report its reason."
  (let* ((reader (ssh-make-reader payload))
         (reason (progn (ssh-read-u8 reader) (ssh-read-u32 reader)))
         (description (ssh-read-text reader)))
    (declare (ignore reason))
    (ssh-client-fail
     client
     (make-condition 'ssh-connection-error
                     :detail (format nil "disconnected by peer: ~A" description)))))

;;; ---- Key exchange ----

(defun ssh-client-handle-kexinit (client payload)
  "Remember the peer's offer, choose, and start curve25519.

A server-initiated rekey starts here too. Then we have not sent a KEXINIT for
this exchange yet, and must do so before ECDH_INIT; the initial exchange sent
its KEXINIT when the connection came up."
  (unless (ssh-client-kexinit-sent client)
    (let ((kexinit (ssh-make-kexinit-payload
                    :kex (ssh-client-kex-algorithms client)
                    :host-keys (ssh-client-host-key-algorithms client)
                    :ciphers (ssh-client-ciphers client)
                    :macs (ssh-client-macs client))))
      (setf (ssh-client-client-kexinit client) kexinit
            (ssh-client-kexinit-sent client) t)
      (ssh-client-send-payload client kexinit)))
  (let ((offers (ssh-parse-kexinit-payload payload)))
    (setf (ssh-client-server-kexinit client) payload
          (ssh-client-negotiated client)
          (ssh-negotiate offers
                         :kex-algorithms (ssh-client-kex-algorithms client)
                         :host-key-algorithms
                         (ssh-client-host-key-algorithms client)
                         :ciphers (ssh-client-ciphers client)
                         :macs (ssh-client-macs client))
          ;; Strict KEX is negotiated once.  A rekey's KEXINIT leaves the
          ;; marker out, but the connection stays strict, so neither side may
          ;; forget it or the sequence resets at NEWKEYS stop matching.
          (ssh-client-strict-kex client)
          (or (ssh-client-strict-kex client)
              (getf (ssh-client-negotiated client) :strict))
          (ssh-client-ignore-next-kex-packet client)
          (getf (ssh-client-negotiated client) :guess-wrong))
    (let ((negotiated (ssh-client-negotiated client)))
      (ssh-log "key exchange ~A, host key ~A, cipher ~A, mac ~A"
               (getf negotiated :kex)
               (getf negotiated :host-key)
               (getf negotiated :cipher)
               (getf negotiated :mac)))
    (ssh-client-send-kex-init client)))

(defun ssh-client-send-kex-init (client)
  (multiple-value-bind (private public) (ssh-curve25519-keypair)
    (setf (ssh-client-ephemeral-private client) private
          (ssh-client-ephemeral-public client) public)
    (let ((writer (ssh-writer)))
      (ssh-write-u8 writer +ssh-msg-kex-ecdh-init+)
      (ssh-write-string writer public)
      (ssh-client-send-payload client (ssh-writer-output writer)))))

(defun ssh-client-handle-kex-reply (client payload)
  "Check the peer's host key and signature, derive keys, send NEWKEYS."
  (let* ((reader (ssh-make-reader payload))
         (host-key (progn (ssh-read-u8 reader) (ssh-read-string reader)))
         (server-public (ssh-read-string reader))
         (signature (ssh-read-string reader))
         (shared (ssh-curve25519-shared
                  (ssh-client-ephemeral-private client) server-public))
         (hash (ssh-exchange-hash
                (ssh-client-client-version client)
                (ssh-client-server-version client)
                (ssh-client-client-kexinit client)
                (ssh-client-server-kexinit client)
                host-key
                (ssh-client-ephemeral-public client)
                server-public
                shared)))
    (ssh-verify-host-signature host-key signature hash)
    (ssh-client-verify-host-key client host-key)
    (setf (ssh-client-session-id client)
          (or (ssh-client-session-id client) hash)
          (ssh-client-host-key-blob client) host-key
          (ssh-client-derived-keys client)
          (ssh-session-keys (ssh-client-negotiated client)
                            shared hash (ssh-client-session-id client)))
    (ssh-client-send-newkeys client)))

(defun ssh-client-send-newkeys (client)
  "Send NEWKEYS, then switch our sending half to the negotiated keys."
  (let ((keys (ssh-client-derived-keys client)))
    (ssh-client-send-payload
     client (make-array 1 :element-type '(unsigned-byte 8)
                          :initial-element +ssh-msg-newkeys+))
    (when (ssh-client-strict-kex client)
      (ssh-reset-send-sequence (ssh-client-cipher client)))
    (ssh-install-keys (ssh-client-cipher client)
                      :encrypt (getf keys :encrypt)
                      :encrypt-mac-key (getf keys :encrypt-mac-key)
                      :encrypt-mac (getf keys :encrypt-mac)
                      :aead (getf keys :aead))
    (setf (ssh-client-keys-sent client) t)
    (ssh-client-maybe-finish-kex client)))

(defun ssh-client-handle-newkeys (client)
  "The peer's NEWKEYS arrived: switch our receiving half, then proceed."
  (let ((keys (ssh-client-derived-keys client)))
    (when (ssh-client-strict-kex client)
      (ssh-reset-receive-sequence (ssh-client-cipher client)))
    (ssh-install-keys (ssh-client-cipher client)
                      :decrypt (getf keys :decrypt)
                      :decrypt-mac-key (getf keys :decrypt-mac-key)
                      :decrypt-mac (getf keys :decrypt-mac)
                      :aead (getf keys :aead))
    (setf (ssh-client-keys-received client) t
          (ssh-client-kexinit-sent client) nil)
    (ssh-client-maybe-finish-kex client)))

(defun ssh-client-maybe-finish-kex (client)
  "Once both NEWKEYS have crossed, ask for the userauth service."
  (when (and (ssh-client-keys-sent client)
             (ssh-client-keys-received client)
             (eq (ssh-client-phase client) :kex))
    (setf (ssh-client-phase client) :auth)
    ;; ConnectTimeout keeps running through authentication, as it does in
    ;; OpenSSH: a server that completes the key exchange and then stalls
    ;; must not hang the caller forever.
    (ssh-client-send-service-request client)))

;;; ---- Host key policy ----

(defun ssh-client-host-spec (client)
  "The host as known_hosts spells it: bracketed on a non-default port.

HOST-KEY-HOST names the HostName a config alias resolved to, so a
\"Host gh / HostName github.com\" connection is checked against github.com
as OpenSSH does, not against the alias."
  (let ((host (or (ssh-client-host-key-host client) (ssh-client-host client))))
    (if (= (ssh-client-port client) 22)
        host
        (format nil "[~A]:~D" host (ssh-client-port client)))))

(defun ssh-client-known-hosts-files (client)
  "The known-hosts files CLIENT checks, in order.

KNOWN-HOSTS is one path, a list of paths, or NIL for ~/.ssh/known_hosts."
  (let ((source (ssh-client-known-hosts client)))
    (cond
      ((null source)
       (list (merge-pathnames ".ssh/known_hosts" (user-homedir-pathname))))
      ((listp source) source)
      (t (list source)))))

(defun ssh-client-known-hosts-file (client)
  "The first known-hosts file, the one a newly trusted key is written to."
  (first (ssh-client-known-hosts-files client)))

(defun ssh-client-remember-host-key (client host-key)
  "Record HOST-KEY for this client's host, trust-on-first-use."
  (multiple-value-bind (type data) (ssh-public-key-parts host-key)
    (declare (ignore data))
    (ssh-remember-known-host (ssh-client-known-hosts-file client)
                             (ssh-client-host-spec client)
                             type host-key
                             :hash (ssh-client-hash-known-hosts client))))

(defun ssh-client-known-host-status (client host-key)
  "How HOST-KEY stands for CLIENT's host across every known-hosts file.

A key found in any file wins over a mismatch in another: the same host may
be listed in both the user's file and the system-wide one."
  (let ((host (ssh-client-host-spec client))
        (status :unknown))
    (dolist (file (ssh-client-known-hosts-files client) status)
      (case (ssh-known-host-status file host host-key)
        (:match (return :match))
        (:mismatch (setf status :mismatch))))))

(defun ssh-client-host-certificate-trusted-p (client certificate)
  "Whether CERTIFICATE is a valid host certificate for CLIENT.

The CA must appear in a @cert-authority line for the host, the certificate
must be a host certificate inside its validity window, carry no critical
options, and name the host or have no principals.  The host name used for
the principal is the real host, not the [host]:port spelling known_hosts
uses."
  (let* ((host (ssh-client-host-spec client))
         (name (or (ssh-client-host-key-host client)
                   (ssh-client-host client)))
         (now (ssh-unix-time (get-universal-time))))
    (and (some (lambda (file)
                 (ssh-known-host-certificate-authority-p
                  file host certificate))
               (ssh-client-known-hosts-files client))
         (= (ssh-certificate-cert-type certificate) 2)
         (null (ssh-certificate-critical certificate))
         (<= (ssh-certificate-valid-after certificate) now)
         (< now (ssh-certificate-valid-before certificate))
         (ssh-certificate-signature-valid-p certificate)
         (ssh-certificate-signature-algorithm-allowed-p
          certificate (ssh-client-ca-signature-algorithms client))
         (or (null (ssh-certificate-principals certificate))
             (member name (ssh-certificate-principals certificate)
                     :test #'string=)))))

(defun ssh-client-host-certificate-revoked-p (client host-key certificate)
  "Whether a @revoked line for CLIENT's host names the certificate, its key
or its CA."
  (let ((host (ssh-client-host-spec client))
        (blobs (list host-key
                     (ssh-certificate-plain-blob certificate)
                     (ssh-certificate-signature-key certificate))))
    (some (lambda (file)
            (ssh-known-host-key-revoked-p file host blobs))
          (ssh-client-known-hosts-files client))))

(defun ssh-client-verify-host-key (client host-key)
  "Apply the client's host key policy to HOST-KEY, or signal.

A host certificate is accepted when a @cert-authority line for the host
names its CA and the certificate itself checks out.  Otherwise OpenSSH
drops the certificate and checks the plain key it certifies, so a host with
only a plain known_hosts entry still connects.  A @revoked line for the
certificate, its plain key or its CA refuses it without that fallback."
  (unless (ssh-key-rsa-size-allowed-p
           host-key (ssh-client-required-rsa-size client))
    (error 'ssh-host-key-error
           :detail (format nil
                           "the host key for ~A has an RSA modulus below RequiredRSASize"
                           (ssh-client-host-spec client))
           :fingerprint (ssh-key-fingerprint host-key (ssh-client-fingerprint-hash client))))
  (let ((revoked
          (handler-case
              (ssh-key-revoked-p host-key
                                 (ssh-client-revoked-host-keys client))
            (ssh-revoked-keys-error (condition)
              (error 'ssh-host-key-error
                     :detail (format nil "cannot check RevokedHostKeys: ~A"
                                     condition)
                     :fingerprint (ssh-key-fingerprint host-key (ssh-client-fingerprint-hash client)))))))
    (when revoked
      (error 'ssh-host-key-error
             :detail (format nil "the host key for ~A is revoked"
                             (ssh-client-host-spec client))
             :fingerprint (ssh-key-fingerprint host-key (ssh-client-fingerprint-hash client)))))
  (let ((certificate (and (ssh-certificate-blob-p host-key)
                          (ssh-certificate-parse host-key))))
    (cond
      ((and certificate
            (ssh-client-host-certificate-revoked-p
             client host-key certificate))
       (error 'ssh-host-key-error
              :detail (format nil "the host key for ~A is revoked"
                              (ssh-client-host-spec client))
              :fingerprint (ssh-key-fingerprint host-key (ssh-client-fingerprint-hash client))))
      ((and certificate
            (ssh-client-host-certificate-trusted-p client certificate))
       (setf (ssh-client-host-key-known client) t)
       t)
      (certificate
       (ssh-client-verify-host-key
        client (ssh-certificate-plain-blob certificate)))
      (t
       (let* ((host (ssh-client-host-spec client))
              (status (ssh-client-known-host-status client host-key))
              (fingerprint (ssh-key-fingerprint host-key (ssh-client-fingerprint-hash client))))
         (ecase status
           (:match
            (setf (ssh-client-host-key-known client) t)
            t)
           (:mismatch
            (error 'ssh-host-key-error
                   :detail (format nil "the host key for ~A changed" host)
                   :fingerprint fingerprint))
           (:unknown
            (setf (ssh-client-host-key-known client) nil)
            (ssh-client-accept-unknown-host-key
             client host-key fingerprint))))))))

(defun ssh-client-accept-unknown-host-key (client host-key fingerprint)
  "Decide what to do with a host key never seen before."
  (let ((policy (ssh-client-host-key-policy client)))
    (cond
      ((eq policy :insecure) nil)
      ((eq policy :accept-new)
       (ssh-client-remember-host-key client host-key))
      ((eq policy :strict)
       (error 'ssh-host-key-error
              :detail "the host key is not in known_hosts"
              :fingerprint fingerprint))
      ((functionp policy)
       (if (funcall policy client fingerprint host-key)
           (ssh-client-remember-host-key client host-key)
           (error 'ssh-host-key-error
                  :detail (format nil "the host key for ~A was rejected"
                                  (ssh-client-host-spec client))
                  :fingerprint fingerprint)))
      (t (error 'ssh-host-key-error
                :detail (format nil "unknown host key policy ~S" policy)
                :fingerprint fingerprint)))))

;;; ---- User authentication ----

(defun ssh-client-send-service-request (client)
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-service-request+)
    (ssh-write-text writer "ssh-userauth")
    (ssh-client-send-payload client (ssh-writer-output writer))))

(defun ssh-client-handle-service-accept (client payload)
  (let* ((reader (ssh-make-reader payload))
         (service (progn (ssh-read-u8 reader) (ssh-read-text reader))))
    (when (string= service "ssh-userauth")
      (ssh-client-send-auth-request client))))

(defparameter +ssh-auth-attempt-limit+ 6
  "Keys to offer before giving up, matching OpenSSH's default.")

(defun ssh-client-current-signer (client)
  "The signer the next publickey request uses."
  (nth (ssh-client-auth-index client) (ssh-client-signers client)))

(defun ssh-client-auth-request-unsigned (client)
  "The publickey request without its signature."
  (let ((writer (ssh-writer))
        (signer (ssh-client-current-signer client)))
    (unless signer
      (error 'ssh-authentication-error :detail "no key left to offer"))
    (ssh-write-u8 writer +ssh-msg-userauth-request+)
    (ssh-write-text writer (ssh-client-user client))
    (ssh-write-text writer "ssh-connection")
    (ssh-write-text writer "publickey")
    (ssh-write-boolean writer t)
    (ssh-write-text writer (ssh-signer-type signer))
    (ssh-write-string writer (ssh-signer-blob signer))
    (ssh-writer-output writer)))

(defun ssh-client-send-auth-signed (client unsigned signature)
  "Send a publickey request that carries SIGNATURE."
  (let ((writer (ssh-writer)))
    (ssh-write-octets writer unsigned)
    (ssh-write-string writer signature)
    (ssh-client-send-payload client (ssh-writer-output writer))))

(defun ssh-client-send-auth-request (client)
  "Offer the current key, signing the session id and the request.

The signer may answer at once (a local key) or later (an agent), so the
request goes out from the callback rather than from this function's tail."
  (handler-case
      (let* ((signer (ssh-client-current-signer client))
             (unsigned (ssh-client-auth-request-unsigned client))
             (signature-data (let ((writer (ssh-writer)))
                               (ssh-write-string writer
                                                 (ssh-client-session-id client))
                               (ssh-write-octets writer unsigned)
                               (ssh-writer-output writer))))
        (funcall (ssh-signer-sign signer)
                 signature-data
                 (lambda (signature)
                   (unless (ssh-client-closed-p client)
                     (ssh-client-send-auth-signed client unsigned signature)))
                 (lambda (condition)
                   (ssh-client-fail client condition))))
    (error (condition)
      (ssh-client-fail client condition))))

(defun ssh-client-handle-banner (client payload)
  "Store a USER AUTH BANNER, which the program shows as it likes.

The second string is a language tag; sshd leaves it empty and this client
has no use for it either."
  (let* ((reader (ssh-make-reader payload))
         (type (ssh-read-u8 reader))
         (text (ssh-read-text reader))
         (language (ssh-read-text reader)))
    (declare (ignore type language))
    (setf (ssh-client-banner client) text)))

(defun ssh-client-handle-auth-success (client)
  "Authenticated: let the queued channel work start."
  (ssh-log "authenticated as ~A" (ssh-client-user client))
  (setf (ssh-client-phase client) :ready)
  (ssh-client-cancel-connect-timer client)
  (ssh-client-start-alive-timer client)
  (let ((actions (nreverse (ssh-client-pending-actions client))))
    (setf (ssh-client-pending-actions client) nil)
    (when (ssh-client-on-open client)
      (funcall (ssh-client-on-open client) client))
    (iter (for action in actions) (funcall action))))

(defun ssh-client-next-signer-p (client)
  "Move to the next signer; NIL when none is left or the limit is reached."
  (let ((next (1+ (ssh-client-auth-index client))))
    (when (and (< next (length (ssh-client-signers client)))
               (< next +ssh-auth-attempt-limit+))
      (setf (ssh-client-auth-index client) next)
      t)))

(defun ssh-client-handle-auth-failure (client payload)
  (let* ((reader (ssh-make-reader payload))
         (methods (progn (ssh-read-u8 reader) (ssh-read-name-list reader)))
         ;; RFC 4252's partial-success flag: one method of an
         ;; AuthenticationMethods list is done and another must follow.
         (partial (ssh-read-boolean reader)))
    (if (ssh-client-next-signer-p client)
        (progn
          (ssh-log "~:[publickey rejected~;partial success~]; trying the next key"
                   partial)
          (ssh-client-send-auth-request client))
        (ssh-client-fail
         client
         (make-condition 'ssh-authentication-error
                         :detail (format nil "server accepts ~{~A~^, ~}"
                                         methods))))))

(defun ssh-client-send-global-request (client name &key fields on-success
                                                     on-failure)
  "Send the global request NAME to CLIENT's peer, expecting an answer.

FIELDS, when given, writes the request's arguments.  ON-SUCCESS receives a
reader over the success reply after its message type, so it can read an
allocated port; ON-FAILURE takes no arguments.  The peer answers requests in
order, which is how the callbacks stay paired with their requests."
  (let ((writer (ssh-writer)))
    (ssh-write-u8 writer +ssh-msg-global-request+)
    (ssh-write-text writer name)
    (ssh-write-boolean writer t)
    (when fields (funcall fields writer))
    (setf (ssh-client-pending-global-requests client)
          (append (ssh-client-pending-global-requests client)
                  (list (list :on-success on-success
                              :on-failure on-failure))))
    (ssh-client-send-payload client (ssh-writer-output writer))
    t))

(defun ssh-client-handle-global-reply (client payload success-p)
  (let ((pending (ssh-client-pending-global-requests client)))
    (when pending
      (setf (ssh-client-pending-global-requests client) (cdr pending))
      (let ((entry (car pending))
            (reader (ssh-make-reader payload)))
        (ssh-read-u8 reader)
        (if success-p
            (when (getf entry :on-success)
              (funcall (getf entry :on-success) reader))
            (when (getf entry :on-failure)
              (funcall (getf entry :on-failure))))))))

(defun ssh-client-handle-global-request (client payload)
  (let* ((reader (ssh-make-reader payload))
         (name (progn (ssh-read-u8 reader) (ssh-read-text reader)))
         (want-reply (ssh-read-boolean reader)))
    (declare (ignore name))
    (when want-reply
      (let ((writer (ssh-writer)))
        (ssh-write-u8 writer +ssh-msg-request-failure+)
        (ssh-client-send-payload client (ssh-writer-output writer))))))
