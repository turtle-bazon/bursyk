(in-package #:cl-pnet-ssh)

;;;; Client policy shared by both backends: host key verification, SSHFP
;;;; lookups, CanonicalDomains, the version addendum, weak-crypto notices,
;;;; chaff, and ChannelTimeout bookkeeping.  These functions read only the
;;;; SSH-CLIENT and SSH-CHANNEL slots, so CL-PLIBSSH builds the same clauses
;;;; and the facade suite sees one behaviour.

;;; ---- SSHFP lookups ----

(defun ssh-client-dns-host (client)
  "The name SSHFP records are looked up under."
  (or (ssh-client-host-key-host client) (ssh-client-host client)))

(defun ssh-client-host-key-dns-needed-p (client)
  "Whether CLIENT should look up SSHFP records before connecting."
  (let ((host (ssh-client-dns-host client)))
    (and (null (ssh-client-host-key-dns-queried client))
         (member (ssh-client-verify-host-key-dns client) '(:yes :ask))
         (ssh-client-host-key-dns-resolver client)
         host
         (not (burzay:numeric-address-p host)))))

(defun ssh-client-query-host-key-dns (client done)
  "Ask for CLIENT's SSHFP records, then call DONE.

The query runs on the event loop.  Any failure is only logged and DONE runs
anyway: VerifyHostKeyDNS supplements known_hosts and must not turn a DNS
outage into a refusal to connect."
  (setf (ssh-client-host-key-dns-queried client) t)
  (handler-case
      (funcall (ssh-client-host-key-dns-resolver client)
               (ssh-client-dns-host client)
               (lambda (records secure)
                 (unless (ssh-client-closed-p client)
                   (setf (ssh-client-host-key-dns-records client) records
                         (ssh-client-host-key-dns-secure client) secure)
                   (when records
                     (ssh-log "found ~D SSHFP record~:P for ~A~:[ (insecure)~;~]"
                              (length records) (ssh-client-dns-host client)
                              secure))
                   (funcall done)))
               (lambda (condition)
                 (unless (ssh-client-closed-p client)
                   (ssh-log "SSHFP lookup failed: ~A" condition)
                   (funcall done))))
    (error (condition)
      (ssh-log "SSHFP lookup failed: ~A" condition)
      (funcall done))))

;;; ---- Resolution ----

(defun ssh-client-resolver-function-p (resolver)
  "Whether RESOLVER is a function rather than a BURZAY resolver spec.

BURZAY's spec is NIL, :SYSTEM, :DNS, (:DNS :ENDPOINT ENDPOINT) or a function.
A non-keyword symbol may name a function, so it is treated as one."
  (and resolver
       (or (functionp resolver)
           (and (symbolp resolver) (not (keywordp resolver))))))

(defun ssh-client-resolve-host (client host on-success on-error)
  "Resolve HOST for CLIENT, honouring AddressFamily when it can.

BURZAY's resolver specifications - the default, :SYSTEM, :DNS and
\(:DNS :ENDPOINT ENDPOINT) - all receive the family, so the system resolver
asks for IPv4 or IPv6 alone and the DNS resolver asks for A or AAAA.  A
caller-supplied function keeps its (HOST ON-SUCCESS ON-ERROR) shape and
chooses the family itself; the address it returns is still checked against
CLIENT's AddressFamily before dialling.  HOST is left alone when it is
already a numeric address, just as BURZAY does."
  (let ((resolver (ssh-client-resolver client)))
    (if (ssh-client-resolver-function-p resolver)
        (funcall resolver host on-success on-error)
        (burzay:resolve-host host on-success on-error
                             :resolver resolver
                             :family (ssh-client-address-family client)))))

(defun ssh-client-bind-address-resolved-p (client remote-address)
  "Whether CLIENT's source address is ready for REMOTE-ADDRESS's family.

A numeric BindAddress needs nothing, and an interface's address is picked
by the socket layer once the remote family is known."
  (let ((raw (ssh-client-bind-address client))
        (cached (ssh-client-bind-address-resolved client)))
    (cond
      ((null raw) t)
      ((burzay:numeric-address-p raw) t)
      (cached
       (eql (cl-pnet-sockets:ipv6-address-p cached)
            (cl-pnet-sockets:ipv6-address-p remote-address)))
      (t nil))))

(defun ssh-client-resolve-bind-address (client remote-address done)
  "Resolve CLIENT's BindAddress for REMOTE-ADDRESS's family, then call DONE."
  (let* ((family (if (cl-pnet-sockets:ipv6-address-p remote-address)
                     :inet6
                     :inet))
         (name (ssh-client-bind-address client))
         (resolver (ssh-client-resolver client)))
    (flet ((succeed (address)
             (setf (ssh-client-bind-address-resolved client) address)
             (funcall done))
           (fail (condition)
             (ssh-client-fail
              client
              (make-condition
               'ssh-connection-error
               :detail (format nil "could not resolve BindAddress ~A: ~A"
                               name condition)))))
      (handler-case
          ;; The default resolver can ask the system for one family, which
          ;; is what makes "BindAddress localhost" match an IPv4 peer.  A
          ;; caller-supplied resolver keeps its (HOST ON-SUCCESS ON-ERROR)
          ;; shape; a family mismatch then fails at bind.
          (if (or (null resolver) (eq resolver :system))
              (burzay:resolve-host name #'succeed #'fail :family family)
              (funcall resolver name #'succeed #'fail))
        (error (condition) (fail condition))))))

;;; ---- CanonicalDomains ----

(defun ssh-canonicalize-candidates (client)
  "The names CanonicalDomains adds to CONNECT-HOST, or NIL to skip."
  (let ((mode (ssh-client-canonicalize-hostname client))
        (host (ssh-client-connect-host client)))
    (when (and (member mode '(:yes :always))
               (or (eq mode :always)
                   (null (ssh-client-proxy-command client)))
               (or (eq mode :always)
                   (<= (count #\. host)
                       (ssh-client-canonicalize-max-dots client))))
      (mapcar (lambda (domain)
                (if (zerop (length domain))
                    (concatenate 'string host ".")
                    (format nil "~A.~A" host domain)))
              (ssh-client-canonical-domains client)))))

;;; ---- Identification and warning notices ----

(defun ssh-client-version-string (client)
  "CLIENT's identification string, with VersionAddendum when configured.

Both the greeting and the key-exchange hash use this exact string, as
RFC 4253 requires."
  (let ((addendum (ssh-client-version-addendum client)))
    (if (and addendum (plusp (length addendum)))
        (concatenate 'string (ssh-client-client-version client)
                     " " addendum)
        (ssh-client-client-version client))))

(defun ssh-client-check-weak-crypto (client)
  "Print OpenSSH 10.6's post-quantum warning after the initial key exchange.

ssh warns when the selected exchange is not post-quantum and the user did not
set KexAlgorithms; setting it means the choice was deliberate.  This build
offers only classical exchanges, so a default connection warns every time,
exactly as an ssh built without PQ support does.  The notice is printed once,
as ssh sets non_pq_kex_warned after showing it."
  (let ((kex (getf (ssh-client-negotiated client) :kex)))
    (when (and kex
               (ssh-client-warn-weak-crypto client)
               (null (ssh-client-kex-algorithms client))
               (not (ssh-kex-post-quantum-p kex))
               (not (ssh-client-non-pq-kex-warned client)))
      (setf (ssh-client-non-pq-kex-warned client) t)
      (ssh-warn "** WARNING: connection is not using a post-quantum key exchange algorithm.")
      (ssh-warn "** This session may be vulnerable to \"store now, decrypt later\" attacks.")
      (ssh-warn "** The server may need to be upgraded. See https://openssh.com/pq.html"))))

(defun ssh-client-send-chaff (client)
  "Send a PING decoy when the server advertised ping@openssh.com.

Returns true when a packet went out.  The payload has the size of a one-byte
CHANNEL_DATA, so an observer watching an idle session cannot tell that the
user stopped typing."
  (when (and (ssh-client-ping-supported client)
             (eq (ssh-client-phase client) :ready)
             (not (ssh-client-kexinit-sent client))
             (not (ssh-client-closed-p client)))
    (ssh-client-send-chaff-packet client)
    (ssh-log "sent chaff keystroke packet")
    t))

;;; ---- Host key policy ----

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
  (ssh-client-known-host-status-for client (ssh-client-host-spec client)
                                    host-key))

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
    (and (or (some (lambda (file)
                     (ssh-known-host-certificate-authority-p
                      file host certificate))
                   (ssh-client-known-hosts-files client))
             (ssh-client-known-hosts-command-certificate-authority-p
              client host certificate))
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
    (or (some (lambda (file)
                (ssh-known-host-key-revoked-p file host blobs))
              (ssh-client-known-hosts-files client))
        (ssh-client-known-hosts-command-revoked-p
         client host blobs host-key))))

(defun ssh-sshfp-algorithm (key-blob)
  "The SSHFP algorithm number for KEY-BLOB, or NIL when DNS cannot name it."
  (multiple-value-bind (type data) (ssh-public-key-parts key-blob)
    (declare (ignore data))
    (cond
      ((string= type "ssh-rsa") 1)
      ((string= type "ssh-dss") 2)
      ((and (> (length type) (length "ecdsa-sha2-"))
            (string= "ecdsa-sha2-" type
                     :end2 (length "ecdsa-sha2-")))
       3)
      ((string= type "ssh-ed25519") 4)
      ((string= type "ssh-ed448") 6)
      (t nil))))

(defun ssh-sshfp-digest (key-blob digest-type)
  "KEY-BLOB's SSHFP digest for DIGEST-TYPE, or NIL when unsupported."
  (case digest-type
    (1 (ssh-hash :sha1 key-blob))
    (2 (ssh-hash :sha256 key-blob))
    (t nil)))

(defun ssh-client-sshfp-status (client host-key)
  "How HOST-KEY compares with CLIENT's SSHFP records.

Returns (VALUES STATUS SECURE) where STATUS is :MATCH when a record names
this key, :MISMATCH when records exist but none names it, and :NONE when no
usable record was fetched.  SECURE is the DNSSEC authenticated-data result."
  (let ((records (ssh-client-host-key-dns-records client))
        (algorithm (ssh-sshfp-algorithm (ssh-key-plain-blob host-key)))
        (status :none))
    (when (and records algorithm)
      (dolist (record records)
        (when (= algorithm (first record))
          (let ((digest (ssh-sshfp-digest
                         (ssh-key-plain-blob host-key) (second record))))
            (when digest
              (if (and (= (length digest) (length (third record)))
                       (every #'= digest (third record)))
                  (setf status :match)
                  (when (eq status :none)
                    (setf status :mismatch))))))))
    (values status (ssh-client-host-key-dns-secure client))))

(defun ssh-loopback-address-p (address)
  "Whether ADDRESS, a numeric peer address, is a loopback one.

Inet 127/8 and inet6 ::1, including an IPv4-mapped ::ffff:127.x.x.x, are
loopback to sockaddr_is_local and therefore to ssh."
  (when (and address (plusp (length address)))
    (let ((text (string-downcase address)))
      (let ((zone (position #\% text)))
        (when zone (setf text (subseq text 0 zone))))
      (cond
        ((string= text "::1") t)
        ((and (> (length text) 7)
              (string= text "::ffff:" :end1 7))
         (ssh-loopback-address-p (subseq text 7)))
        ((and (>= (length text) 4)
              (string= text "127." :end1 4))
         t)
        (t nil)))))

(defun ssh-client-verify-host-key-main (client host-key)
  "Apply the client's host key policy to HOST-KEY, or signal.

A host certificate is accepted when a @cert-authority line for the host
names its CA and the certificate itself checks out.  Otherwise OpenSSH
drops the certificate and checks the plain key it certifies, so a host with
only a plain known_hosts entry still connects.  A @revoked line for the
certificate, its plain key or its CA refuses it without that fallback."
  ;; NoHostAuthenticationForLocalhost: loopback addresses are trusted as-is,
  ;; because on an NFS-mounted home the same name may mean a different machine.
  (when (and (ssh-client-no-host-authentication-for-localhost client)
             (null (ssh-client-host-key-alias client))
             (ssh-loopback-address-p (ssh-client-remote-address client)))
    (ssh-log "forcing acceptance of the host key for ~A"
             (ssh-client-host-spec client))
    (setf (ssh-client-update-host-keys client) :no
          (ssh-client-check-host-ip client) nil)
    (return-from ssh-client-verify-host-key-main t))
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
       (let ((host (ssh-client-host-spec client))
             (fingerprint (ssh-key-fingerprint
                           host-key (ssh-client-fingerprint-hash client))))
         (multiple-value-bind (dns-status secure)
             (ssh-client-sshfp-status client host-key)
           (case dns-status
             (:match
              (if secure
                  (ssh-log "matching host key fingerprint for ~A found in DNS (secure)"
                           host)
                  (ssh-log "matching host key fingerprint for ~A found in DNS, but the answer is not DNSSEC-validated"
                           host)))
             (:mismatch
              (ssh-log "mismatching host key fingerprint for ~A found in DNS"
                       host)))
           (when (and (eq dns-status :match)
                      secure
                      (eq (ssh-client-verify-host-key-dns client) :yes))
             (setf (ssh-client-host-key-known client) t
                   (ssh-client-host-key-dns-accepted client) t)
             (ssh-log "host key for ~A verified by DNS SSHFP" host)
             (return-from ssh-client-verify-host-key-main t)))
         (let ((status (ssh-client-known-host-status client host-key)))
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
               client host-key fingerprint)))))))))

(defun ssh-client-expand-known-hosts-command (client host host-key command)
  "Expand the ssh % tokens in a KnownHostsCommand string."
  (multiple-value-bind (type data) (ssh-public-key-parts host-key)
    (declare (ignore data))
    (let ((address (or (ssh-client-remote-address client) ""))
          (name (ssh-client-host client))
          (port (or (ssh-client-connect-port client) 22))
          (user (ssh-client-user client))
          (uid (or (uiop:getenv "UID") ""))
          (local (or (uiop:getenv "HOSTNAME") ""))
          (fingerprint (ssh-key-fingerprint
                        host-key (ssh-client-fingerprint-hash client)))
          (encoded (ssh-octets-base64 host-key)))
      (with-output-to-string (out)
        (loop with length = (length command)
              for index from 0 below length
              for character = (char command index)
              do (if (and (char= character #\%)
                          (< (1+ index) length))
                     (let ((token (char command (1+ index))))
                       (case token
                         (#\% (write-char #\% out) (incf index))
                         (#\H (princ host out) (incf index))
                         (#\I (princ address out) (incf index))
                         (#\n (princ name out) (incf index))
                         (#\p (princ port out) (incf index))
                         (#\r (princ user out) (incf index))
                         (#\u (princ (cl-pnet-ssh:ssh-default-user) out)
                              (incf index))
                         (#\d (princ (namestring (user-homedir-pathname)) out)
                              (incf index))
                         (#\i (princ uid out) (incf index))
                         (#\l (princ local out) (incf index))
                         (#\L (princ local out) (incf index))
                         (#\f (princ fingerprint out) (incf index))
                         (#\t (princ type out) (incf index))
                         (#\K (princ encoded out) (incf index))
                         (t (write-char character out))))
                     (write-char character out)))))))

(defun ssh-client-known-hosts-command-entries (client host host-key)
  "The known_hosts entries KnownHostsCommand prints for HOST, or NIL."
  (let ((command (ssh-client-known-hosts-command client)))
    (when (and command (plusp (length command)))
      (let* ((expanded
               (ssh-client-expand-known-hosts-command
                client host host-key command))
             (shell (or (uiop:getenv "SHELL") "/bin/sh"))
             (output
               (handler-case
                   (uiop:run-program (list shell "-c" expanded)
                                     :output :string
                                     :error-output :string
                                     :ignore-error-status nil)
                 (error (condition)
                   (error 'ssh-host-key-error
                          :detail (format nil "KnownHostsCommand failed: ~A"
                                          condition)
                          :fingerprint
                          (ssh-key-fingerprint
                           host-key
                           (ssh-client-fingerprint-hash client)))))))
        (loop for line in (uiop:split-string output :separator '(#\Newline))
              for entry = (ssh-known-host-line-entry line)
              when entry collect entry)))))

(defun ssh-client-known-hosts-command-status (client host host-key)
  "How the command's entries stand for HOST-KEY at HOST."
  (let ((blob (ssh-copy-octets host-key))
        (seen nil))
    (dolist (entry (ssh-client-known-hosts-command-entries
                    client host host-key))
      (when (and (ssh-known-host-entry-matches-p entry host)
                 (not (equal (ssh-known-host-entry-marker entry)
                             "@cert-authority")))
        (setf seen t)
        (unless (equal (ssh-known-host-entry-marker entry) "@revoked")
          (when (ssh-octets= blob (ssh-known-host-entry-key-blob entry))
            (return-from ssh-client-known-hosts-command-status :match)))))
    (if seen :mismatch :unknown)))

(defun ssh-client-known-hosts-command-certificate-authority-p
    (client host certificate)
  "Whether the command's output names CERTIFICATE's CA for HOST."
  (let ((ca (ssh-certificate-signature-key certificate)))
    (and ca
         (some (lambda (entry)
                 (and (equal (ssh-known-host-entry-marker entry)
                             "@cert-authority")
                      (ssh-known-host-entry-matches-p entry host)
                      (ssh-octets= ca (ssh-known-host-entry-key-blob entry))))
               (ssh-client-known-hosts-command-entries
                client host certificate)))))

(defun ssh-client-known-hosts-command-revoked-p (client host key-blobs key)
  "Whether the command's output revokes one of KEY-BLOBS for HOST."
  (some (lambda (entry)
          (and (equal (ssh-known-host-entry-marker entry) "@revoked")
               (ssh-known-host-entry-matches-p entry host)
               (some (lambda (blob)
                       (ssh-octets= blob
                                    (ssh-known-host-entry-key-blob entry)))
                     key-blobs)))
        (ssh-client-known-hosts-command-entries client host key)))

(defun ssh-client-known-host-status-for (client host host-key)
  "How HOST-KEY stands for HOST across CLIENT's known-hosts files."
  (let ((status :unknown))
    (dolist (file (ssh-client-known-hosts-files client))
      (case (ssh-known-host-status file host host-key)
        (:match (return-from ssh-client-known-host-status-for :match))
        (:mismatch (setf status :mismatch))))
    (case (ssh-client-known-hosts-command-status client host host-key)
      (:match :match)
      (:mismatch :mismatch)
      (t status))))

(defun ssh-client-check-host-address (client host-key)
  "Apply CheckHostIP to HOST-KEY, adding or refusing its address entry."
  (when (and (ssh-client-check-host-ip client)
             (not (ssh-client-host-key-ip-checked client))
             (ssh-client-remote-address client)
             (null (ssh-client-proxy-command client))
             (not (ssh-certificate-blob-p host-key)))
    (setf (ssh-client-host-key-ip-checked client) t)
    (let* ((address (ssh-client-remote-address client))
           (host (ssh-client-host client))
           (port (or (ssh-client-connect-port client) 22))
           (ip-host (if (= port 22)
                        address
                        (format nil "[~A]:~D" address port))))
      (unless (or (string= host address)
                  (member (string-downcase host)
                          '("localhost" "127.0.0.1" "::1")
                          :test #'string=))
        (case (ssh-client-known-host-status-for client ip-host host-key)
          (:mismatch
           (error 'ssh-host-key-error
                  :detail (format nil
                                  "the host key for ~A differs from the key for its address ~A"
                                  (ssh-client-host-spec client) ip-host)
                  :fingerprint (ssh-key-fingerprint
                                host-key
                                (ssh-client-fingerprint-hash client))))
          (:unknown
           (multiple-value-bind (type data) (ssh-public-key-parts host-key)
             (declare (ignore data))
             (ignore-errors
               (ssh-remember-known-host
                (ssh-client-known-hosts-file client)
                ip-host type host-key
                :hash (ssh-client-hash-known-hosts client)))))
          (t nil))))))

(defun ssh-client-verify-host-key (client host-key)
  "Check HOST-KEY's policy and, when configured, its address entry."
  (prog1 (ssh-client-verify-host-key-main client host-key)
    (unless (ssh-client-host-key-dns-accepted client)
      (ssh-client-check-host-address client host-key))))

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
      ;; BatchMode forbids asking, so a confirmation callback is not called;
      ;; OpenSSH treats an unanswered confirmation as a refusal.
      ((and (ssh-client-batch-mode client) (functionp policy))
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

;;; ---- Channel inactivity timeouts ----

(defun ssh-client-channel-list (client)
  "The channels CLIENT currently has, in no particular order."
  (loop for channel being the hash-values of (ssh-client-channels client)
        collect channel))

(defun ssh-client-channel-type-timeout (client type)
  "CLIENT's ChannelTimeout for channel TYPE in seconds, or NIL.

The first pattern matching TYPE wins, as ssh's lookup_timeout returns the
first match.  Unlike sshd's older session:shell aliases, the client's extended
types are already specific (session:command, session:subsystem:NAME), and ssh
matches them literally, so \"session\" alone selects the plain channel type
and leaves those labels to their own patterns."
  (let ((timeouts (ssh-client-channel-timeouts client)))
    (when (consp timeouts)
      (loop for (pattern . seconds) in timeouts
            when (and (not (string= pattern "global"))
                      (ssh-match-pattern pattern type))
              return seconds))))

(defun ssh-client-global-channel-timeout (client)
  "CLIENT's global ChannelTimeout in seconds, or NIL when none is set.

ssh's channel_add_timeout assigns the global deadline for every "global"
entry, so a repeated pattern keeps the last value."
  (let ((timeouts (ssh-client-channel-timeouts client))
        (seconds nil))
    (when (consp timeouts)
      (loop for (pattern . value) in timeouts
            when (string= pattern "global")
              do (setf seconds value))
      seconds)))

(defun ssh-client-channel-note-activity (channel)
  "Move CHANNEL's and its connection's inactivity clocks to now."
  (when (eq (ssh-channel-state channel) :open)
    (let ((now (ssh-client-now)))
      (setf (ssh-channel-last-used channel) now
            (ssh-client-channel-last-used (ssh-channel-client channel))
            now))))

(defun ssh-client-channel-start-timeout (channel)
  "Start CHANNEL's inactivity clock from now.

ssh starts it when the channel becomes usable, whether we or the peer opened
it, and a new channel also resets the connection-wide clock."
  (when (eq (ssh-channel-state channel) :open)
    (let ((client (ssh-channel-client channel))
          (now (ssh-client-now)))
      (setf (ssh-channel-last-used channel) now
            (ssh-client-channel-last-used client) now
            (ssh-channel-inactive-timeout channel)
            (or (ssh-client-channel-type-timeout
                 client (ssh-channel-type channel))
                0))
      (ssh-client-note-channel-change client))))

(defun ssh-channel-set-x-type (channel type)
  "Give CHANNEL ssh's extended type and re-resolve its inactivity limit.

Only a specific, non-zero match overrides the limit the channel already had,
as ssh's channel_set_xtype does; the activity clock keeps running from the
last byte, so a channel already idle longer than the new limit expires at
once."
  (setf (ssh-channel-x-type channel) type)
  (when (eq (ssh-channel-state channel) :open)
    (let* ((client (ssh-channel-client channel))
           (seconds (ssh-client-channel-type-timeout client type)))
      (when (and seconds (plusp seconds))
        (setf (ssh-channel-inactive-timeout channel) seconds))
      (ssh-client-refresh-channel-timeout-timer client))))

(defun ssh-client-stop-channel-timeout-timer (client)
  "Disarm CLIENT's ChannelTimeout timer."
  (setf (ssh-client-channel-timeout-timer client)
        (ssh-client-cancel-timer
         (ssh-client-channel-timeout-timer client))))

(defun ssh-client-refresh-channel-timeout-timer (client)
  "Arm CLIENT's timer for the earliest open-channel inactivity deadline."
  (let ((earliest nil)
        (now (ssh-client-now))
        (timeouts (ssh-client-channel-timeouts client)))
    (when (and (not (ssh-client-closed client)) (consp timeouts))
      (let ((open nil))
        (dolist (channel (ssh-client-channel-list client))
          (let ((used (ssh-channel-last-used channel))
                (limit (ssh-channel-inactive-timeout channel)))
            (when (eq (ssh-channel-state channel) :open)
              (setf open t)
              (when (and used (plusp limit))
                (let ((deadline (+ used limit)))
                  (when (or (null earliest) (< deadline earliest))
                    (setf earliest deadline)))))))
        ;; A global timeout runs from the newest activity on any channel,
        ;; closed ones included, and only matters while one is open.
        (let ((global (ssh-client-global-channel-timeout client))
              (last-used (ssh-client-channel-last-used client)))
          (when (and open global (plusp global) last-used)
            (let ((deadline (+ last-used global)))
              (when (or (null earliest) (< deadline earliest))
                (setf earliest deadline)))))))
    (ssh-client-stop-channel-timeout-timer client)
    (when earliest
      (setf (ssh-client-channel-timeout-timer client)
            (cl-pnet:timer-start
             (max 0.05 (- earliest now)) 0
             (lambda ()
               (setf (ssh-client-channel-timeout-timer client) nil)
               (ssh-client-channel-timeout-tick client)))))))

(defun ssh-client-channel-timeout-tick (client)
  "Close every open channel whose ChannelTimeout has expired.

Per-channel limits are checked first; a global timeout then closes all
channels that remain, as ssh's channel_handler does with the shorter of the
channel and global deadlines."
  (let ((now (ssh-client-now)))
    (dolist (channel (ssh-client-channel-list client))
      (let ((used (ssh-channel-last-used channel))
            (limit (ssh-channel-inactive-timeout channel)))
        (when (and (eq (ssh-channel-state channel) :open)
                   used (plusp limit)
                   (>= now (+ used limit)))
          (ssh-log "channel ~D: closing after ~A seconds of inactivity"
                   (ssh-channel-local-id channel) limit)
          (ssh-channel-handle-close channel))))
    (let ((global (ssh-client-global-channel-timeout client))
          (last-used (ssh-client-channel-last-used client)))
      (when (and global (plusp global) last-used
                 (>= now (+ last-used global)))
        (dolist (channel (ssh-client-channel-list client))
          (when (eq (ssh-channel-state channel) :open)
            (ssh-log "closing channel ~D: global ChannelTimeout expired"
                     (ssh-channel-local-id channel))
            (ssh-channel-handle-close channel))))))
  (ssh-client-refresh-channel-timeout-timer client))

(defun ssh-client-note-channel-change (client)
  "React to CLIENT's channels opening or closing."
  (unless (ssh-client-closed client)
    (ssh-client-refresh-channel-timeout-timer client)))

;;; ---- Session controls both backends expose ----

(defun ssh-client-set-ip-qos (client interactive-p)
  "Apply CLIENT's IPQoS DSCP value for an interactive or bulk session.

ssh sets the bulk value when the connection is made and raises it to the
interactive value once it knows a pty will carry the session.  The value is
:NO when the directive says none, and a number otherwise."
  (let ((value (if interactive-p
                   (ssh-client-ip-qos-interactive client)
                   (ssh-client-ip-qos-bulk client)))
        (fd (ssh-client-transport-fd client)))
    (when (and fd (integerp value))
      (cl-pnet-sockets:set-socket-option
       fd cl-pnet-sockets:+ipproto-ip+
       cl-pnet-sockets:+ip-tos+ value))))

(defun ssh-client-host-key-randomart (client)
  "The randomart picture of CLIENT's host key, once KEX has seen it.

VisualHostKey prints this instead of the bare fingerprint.  Both transports
keep the server's key blob, so the picture is built the same way."
  (let ((blob (ssh-client-host-key-blob client)))
    (and blob (ssh-key-randomart
               blob (ssh-client-fingerprint-hash client)))))

;;; ---- Signer filtering ----

(defun ssh-filter-signers (signers patterns &key minimum-rsa-size)
  "SIGNERS whose type matches PATTERNS and whose RSA modulus is large enough.

A NIL PATTERNS list leaves every type eligible.  MINIMUM-RSA-SIZE is
RequiredRSASize: it only rejects RSA keys below the floor, as ssh does."
  (remove-if
   (lambda (signer)
     (or (and patterns
              (not (some (lambda (pattern)
                           (ssh-match-pattern pattern
                                              (ssh-signer-type signer)))
                         patterns)))
         (not (ssh-key-rsa-size-allowed-p (ssh-signer-blob signer)
                                          minimum-rsa-size))))
   signers))

