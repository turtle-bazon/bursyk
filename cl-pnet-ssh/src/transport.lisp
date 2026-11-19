(in-package #:cl-pnet-ssh)

;;;; The client's transport state machine: version exchange, KEX, NEWKEYS,
;;;; userauth, then dispatch to channels. Everything runs from cl-pnet
;;;; callbacks, so no function here waits for the peer.

(defun ssh-client-connected (client connection)
  "CLIENT's TCP connection is up: greet and offer our KEXINIT."
  (setf (ssh-client-connection client) connection
        (ssh-client-phase client) :version)
  (ssh-client-send-bytes
   client
   (ssh-string-octets (concatenate 'string
                                   (ssh-client-client-version client)
                                   (string #\Return)
                                   (string #\Newline))))
  (let ((kexinit (ssh-make-kexinit-payload)))
    (setf (ssh-client-client-kexinit client) kexinit)
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
              :version)
            :banner)))))

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
      ((= type +ssh-msg-service-accept+)
       (ssh-client-handle-service-accept client payload))
      ((= type +ssh-msg-userauth-success+)
       (ssh-client-handle-auth-success client))
      ((= type +ssh-msg-userauth-failure+)
       (ssh-client-handle-auth-failure client payload))
      ((= type +ssh-msg-global-request+)
       (ssh-client-handle-global-request client payload))
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
  "Remember the peer's offer, choose, and start curve25519."
  (let ((offers (ssh-parse-kexinit-payload payload)))
    (setf (ssh-client-server-kexinit client) payload
          (ssh-client-negotiated client) (ssh-negotiate offers)
          (ssh-client-strict-kex client)
          (getf (ssh-client-negotiated client) :strict)
          (ssh-client-ignore-next-kex-packet client)
          (getf (ssh-client-negotiated client) :guess-wrong))
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
    (setf (ssh-client-keys-received client) t)
    (ssh-client-maybe-finish-kex client)))

(defun ssh-client-maybe-finish-kex (client)
  "Once both NEWKEYS have crossed, ask for the userauth service."
  (when (and (ssh-client-keys-sent client)
             (ssh-client-keys-received client)
             (eq (ssh-client-phase client) :kex))
    (setf (ssh-client-phase client) :auth)
    (ssh-client-send-service-request client)))

;;; ---- Host key policy ----

(defun ssh-client-host-spec (client)
  "The host as known_hosts spells it: bracketed on a non-default port."
  (if (= (ssh-client-port client) 22)
      (ssh-client-host client)
      (format nil "[~A]:~D" (ssh-client-host client) (ssh-client-port client))))

(defun ssh-client-known-hosts-file (client)
  (or (ssh-client-known-hosts client)
      (merge-pathnames ".ssh/known_hosts" (user-homedir-pathname))))

(defun ssh-client-remember-host-key (client host-key)
  "Record HOST-KEY for this client's host, trust-on-first-use."
  (multiple-value-bind (type data) (ssh-public-key-parts host-key)
    (declare (ignore data))
    (ssh-remember-known-host (ssh-client-known-hosts-file client)
                             (ssh-client-host-spec client)
                             type host-key)))

(defun ssh-client-verify-host-key (client host-key)
  "Apply the client's host key policy to HOST-KEY, or signal."
  (let* ((file (ssh-client-known-hosts-file client))
         (host (ssh-client-host-spec client))
         (status (ssh-known-host-status file host host-key))
         (fingerprint (ssh-key-fingerprint host-key)))
    (ecase status
      (:match t)
      (:mismatch
       (error 'ssh-host-key-error
              :detail (format nil "the host key for ~A changed" host)
              :fingerprint fingerprint))
      (:unknown
       (ssh-client-accept-unknown-host-key client host-key fingerprint)))))

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
       (when (funcall policy client fingerprint host-key)
         (ssh-client-remember-host-key client host-key)))
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

(defun ssh-client-auth-request-unsigned (client)
  "The publickey request without its signature."
  (let ((writer (ssh-writer))
        (key (ssh-client-private-key client)))
    (ssh-write-u8 writer +ssh-msg-userauth-request+)
    (ssh-write-text writer (ssh-client-user client))
    (ssh-write-text writer "ssh-connection")
    (ssh-write-text writer "publickey")
    (ssh-write-boolean writer t)
    (ssh-write-text writer (ssh-private-key-type key))
    (ssh-write-string writer (ssh-public-key-blob-of key))
    (ssh-writer-output writer)))

(defun ssh-client-send-auth-request (client)
  "Offer the public key, signing the session id and the request."
  (let* ((key (ssh-client-private-key client))
         (unsigned (ssh-client-auth-request-unsigned client))
         (signature-data (let ((writer (ssh-writer)))
                           (ssh-write-string writer (ssh-client-session-id client))
                           (ssh-write-octets writer unsigned)
                           (ssh-writer-output writer)))
         (signature (ssh-ed25519-signature-blob key signature-data))
         (writer (ssh-writer)))
    (ssh-write-octets writer unsigned)
    (ssh-write-string writer signature)
    (ssh-client-send-payload client (ssh-writer-output writer))))

(defun ssh-client-handle-auth-success (client)
  "Authenticated: let the queued channel work start."
  (setf (ssh-client-phase client) :ready)
  (let ((actions (nreverse (ssh-client-pending-actions client))))
    (setf (ssh-client-pending-actions client) nil)
    (when (ssh-client-on-open client)
      (funcall (ssh-client-on-open client) client))
    (iter (for action in actions) (funcall action))))

(defun ssh-client-handle-auth-failure (client payload)
  (let* ((reader (ssh-make-reader payload))
         (methods (progn (ssh-read-u8 reader) (ssh-read-name-list reader))))
    (ssh-client-fail
     client
     (make-condition 'ssh-authentication-error
                     :detail (format nil "server accepts ~{~A~^, ~}" methods)))))

(defun ssh-client-handle-global-request (client payload)
  (let* ((reader (ssh-make-reader payload))
         (name (progn (ssh-read-u8 reader) (ssh-read-text reader)))
         (want-reply (ssh-read-boolean reader)))
    (declare (ignore name))
    (when want-reply
      (let ((writer (ssh-writer)))
        (ssh-write-u8 writer +ssh-msg-request-failure+)
        (ssh-client-send-payload client (ssh-writer-output writer))))))
