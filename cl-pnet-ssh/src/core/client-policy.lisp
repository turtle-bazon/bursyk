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

(defun ssh-ipv4-literal-p (text)
  "Whether TEXT is a dotted-quad IPv4 address."
  (let ((parts (uiop:split-string text :separator ".")))
    (and (= (length parts) 4)
         (every (lambda (part)
                  (and (plusp (length part))
                       (<= (length part) 3)
                       (every #'digit-char-p part)
                       (<= (parse-integer part) 255)))
                parts))))

(defun ssh-ipv6-hex-field-p (text)
  "Whether TEXT is one 16-bit group of an IPv6 literal."
  (and (plusp (length text))
       (<= (length text) 4)
       (every (lambda (character) (digit-char-p character 16)) text)))

(defun ssh-ipv6-field-count (text)
  "The 16-bit groups TEXT accounts for, or NIL when TEXT is malformed.

TEXT is a non-empty run of ':'-separated fields; a trailing dotted quad
counts as the two groups it stands for."
  (if (zerop (length text))
      0
      (let* ((fields (uiop:split-string text :separator ":"))
             (last (car (last fields))))
        (if (find #\. last)
            (and (ssh-ipv4-literal-p last)
                 (loop for field in (butlast fields)
                       always (ssh-ipv6-hex-field-p field))
                 (+ (1- (length fields)) 2))
            (and (loop for field in fields
                       always (ssh-ipv6-hex-field-p field))
                 (length fields))))))

(defun ssh-ipv6-literal-p (text)
  "Whether TEXT is an IPv6 literal such as ::1 or 2001:db8::1."
  (and (stringp text)
       (find #\: text)
       (let ((double (search "::" text)))
         (when (or (null double)
                   (null (search "::" text :start2 (+ double 2))))
           (let* ((head (if double (subseq text 0 double) text))
                  (tail (if double (subseq text (+ double 2)) ""))
                  (head-count (ssh-ipv6-field-count head))
                  (tail-count (ssh-ipv6-field-count tail)))
             (and head-count tail-count
                  (if double
                      (< (+ head-count tail-count) 8)
                      (= (+ head-count tail-count) 8))))))))

(defun ssh-address-literal-p (host)
  "Whether HOST is a real numeric address.

BURZAY treats any colon as an IPv6 literal, so the client re-checks the
literal before short-circuiting resolution: a name such as \"a:b\" has to
reach the system resolver and fail there, as ssh's getaddrinfo call does."
  (and (stringp host)
       (plusp (length host))
       (or (ssh-ipv4-literal-p host)
           (ssh-ipv6-literal-p host))))

(defun ssh-inet-number (text)
  "TEXT as one inet_aton component, or NIL.

inet_aton, and so getaddrinfo with AI_NUMERICHOST, reads a leading 0x as
hexadecimal, a leading 0 as octal and anything else as decimal."
  (when (plusp (length text))
    (cond
      ((and (> (length text) 2)
            (char= (char text 0) #\0)
            (member (char text 1) '(#\x #\X)))
       (let ((digits (subseq text 2)))
         (when (and (plusp (length digits))
                    (every (lambda (character) (digit-char-p character 16))
                           digits))
           (parse-integer digits :radix 16))))
      ((and (> (length text) 1) (char= (char text 0) #\0))
       (let ((digits (subseq text 1)))
         (when (every (lambda (character) (digit-char-p character 8)) digits)
           (parse-integer digits :radix 8))))
      ((every #'digit-char-p text)
       (parse-integer text))
      (t nil))))

(defun ssh-ipv4-inet-aton-p (text)
  "Whether TEXT is an IPv4 address in any spelling inet_aton accepts.

\"127.1\", \"2130706433\", \"0x7f000001\" and \"0177.0.0.1\" all name
127.0.0.1, and ssh prints them that way because resolve_addr() canonicalises
a numeric host with getnameinfo(NI_NUMERICHOST).  A value that does not fit
the octets is not an address and must not be handed to the resolver: glibc
would look a name such as \"999.1\" up in DNS."
  (and (stringp text)
       (let* ((parts (uiop:split-string text :separator "."))
              (numbers (mapcar #'ssh-inet-number parts))
              (count (length parts)))
         (and (<= 1 count 4)
              (every #'identity numbers)
              (loop for number in (butlast numbers)
                    always (< number 256))
              (< (car (last numbers)) (ash 1 (* 8 (- 5 count))))))))

(defun ssh-canonical-address-string (host &key family)
  "HOST in the numeric form ssh prints, or NIL when it is a name.

ssh canonicalises a numeric host before printing or dialling it, so a
short or hexadecimal spelling is shown as the dotted quad the system
resolver reads.  A name is left alone: nothing here may trigger a DNS
lookup that ssh would not make.  FAMILY is the AddressFamily the
connection will use: ssh's resolve_addr() passes it to getaddrinfo, so an
address of the other family does not canonicalise and the caller keeps the
spelling the user wrote."
  (when (and (stringp host)
             (plusp (length host))
             (or (find #\: host)
                 (ssh-ipv4-inet-aton-p host)))
    (handler-case
        (cl-pnet-sockets:lookup-host-canonical host :family family)
      (error () nil))))

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
    (cond
      ((and (burzay:numeric-address-p host)
            (not (ssh-address-literal-p host)))
       ;; A numeric answer is reached without the network, so asking the
       ;; system resolver here cannot stall the loop.
       (handler-case
           (funcall on-success
                    (cl-pnet-sockets:lookup-host-canonical
                     host :family (ssh-client-address-family client)))
         (error (condition)
           (funcall on-error condition))))
      ((ssh-client-resolver-function-p resolver)
       (funcall resolver host on-success on-error))
      (t
       (burzay:resolve-host host on-success on-error
                            :resolver resolver
                            :family (ssh-client-address-family client))))))

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

(defun ssh-client-known-hosts-source-files (source default)
  "SOURCE as a list of files: NONE for :NONE, DEFAULT when unset."
  (cond
    ((eq source :none) '())
    ((null source) default)
    ((listp source) source)
    (t (list source))))

(defun ssh-client-known-hosts-files (client)
  "The known-hosts files CLIENT checks, in order.

KNOWN-HOSTS names the user files and GLOBAL-KNOWN-HOSTS the system ones.
Each is one path, a list of paths, :NONE for no file, or NIL for OpenSSH's
defaults."
  (append
   (ssh-client-known-hosts-source-files
    (ssh-client-known-hosts client)
    (ssh-default-user-known-hosts))
   (ssh-client-known-hosts-source-files
    (ssh-client-global-known-hosts client)
    +ssh-default-global-known-hosts+)))

(defun ssh-client-known-hosts-file (client)
  "The first user known-hosts file, where a newly trusted key is written.

The global files are read but never written; with UserKnownHostsFile none
there is no file to write and this is NIL."
  (first (ssh-client-known-hosts-source-files
          (ssh-client-known-hosts client)
          (ssh-default-user-known-hosts))))

(defun ssh-client-remember-host-key (client host-key)
  "Record HOST-KEY for this client's host, trust-on-first-use.

A client with no known-hosts file has nowhere to write; OpenSSH logs that
failure and still connects, so this returns NIL rather than signalling.  On
success the same warning ssh prints is reported at the default log level."
  (let ((file (ssh-client-known-hosts-file client)))
    (when file
      (handler-case
          (progn
            (multiple-value-bind (type data) (ssh-public-key-parts host-key)
              (declare (ignore data))
              (ssh-remember-known-host file
                                       (ssh-client-host-spec client)
                                       type host-key
                                       :hash (ssh-client-hash-known-hosts client)))
            (ssh-warn "Warning: Permanently added '~A' (~A) to the list of known hosts."
                      (ssh-client-host-spec client) (ssh-key-type-name host-key))
            t)
        ;; ssh reports a failed write and keeps going rather than losing the
        ;; connection over a read-only home directory.
        (error ()
          (ssh-warn "Failed to add the host to the list of known hosts (~A)."
                    file)
          nil)))))

(defun ssh-client-known-host-status (client host-key)
  "How HOST-KEY stands for CLIENT's host across every known-hosts file.

A key found in any file wins over a mismatch in another: the same host may
be listed in both the user's file and the system-wide one.

A non-default port is checked twice: first as known_hosts spells it,
\"[host]:port\", then, when that is unknown, under the bare host name.
OpenSSH accepts a key recorded without the port, so an old entry keeps
working after a server moves to a new port."
  (let ((status
          (ssh-client-known-host-status-for client
                                            (ssh-client-host-spec client)
                                            host-key)))
    (if (and (eq status :unknown)
             (null (ssh-client-host-key-alias client))
             (/= (ssh-client-port client) 22)
             (eq :match
                 (ssh-client-known-host-status-for
                  client
                  (or (ssh-client-host-key-host client)
                      (ssh-client-host client))
                  host-key)))
        :match
        status)))

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

(defun ssh-client-known-host-mismatch (client host host-key)
  "The (VALUES ENTRY FILE) that made HOST-KEY a changed key for HOST.

NIL when the mismatch came from KnownHostsCommand rather than a file."
  (dolist (file (ssh-client-known-hosts-files client))
    (let ((entry (ssh-known-host-mismatch-entry file host host-key)))
      (when entry
        (return-from ssh-client-known-host-mismatch
          (values entry file)))))
  nil)

(defun ssh-client-auth-switch-on-p (value)
  "Whether an authentication switch VALUE leaves its method on."
  (and value (not (eq value :no))))

(defun ssh-client-warn-changed-host-key (client host-key fingerprint)
  "Print ssh's warning for a HOST-KEY that does not match known_hosts."
  (let* ((host (ssh-client-host-spec client))
         (type (ssh-key-type-name host-key)))
    (multiple-value-bind (entry file)
        (ssh-client-known-host-mismatch client host host-key)
      (ssh-warn "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
      (ssh-warn "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @")
      (ssh-warn "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
      (ssh-warn "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!")
      (ssh-warn "Someone could be eavesdropping on you right now (man-in-the-middle attack)!")
      (ssh-warn "It is also possible that a host key has just been changed.")
      (ssh-warn "The fingerprint for the ~A key sent by the remote host is~%~A."
                type fingerprint)
      (ssh-warn "Please contact your system administrator.")
      (when file
        (ssh-warn "Add correct host key in ~A to get rid of this message."
                  file))
      (when entry
        (ssh-warn "Offending ~A key in ~A:~D"
                  (ssh-key-type-name (ssh-known-host-entry-key-blob entry))
                  (or file "<unknown>")
                  (or (ssh-known-host-entry-line-number entry) 0))))))

(defun ssh-client-continue-with-changed-host-key (client)
  "Keep the connection after a changed key, as StrictHostKeyChecking=no does.

The key is not recorded: the warning asks the user to fix known_hosts.  What
can be impersonated once the host is untrusted is turned off: the two
password-style authentications, agent and X11 forwarding, port forwarding
(the caller checks HOST-KEY-UNTRUSTED before starting one) and UpdateHostKeys."
  (setf (ssh-client-host-key-untrusted client) t)
  (when (ssh-client-auth-switch-on-p
         (ssh-client-password-authentication client))
    (setf (ssh-client-password-authentication client) nil)
    (ssh-warn "Password authentication is disabled to avoid man-in-the-middle attacks."))
  (when (ssh-client-auth-switch-on-p
         (ssh-client-kbd-interactive-authentication client))
    (setf (ssh-client-kbd-interactive-authentication client) nil)
    (ssh-warn "Keyboard-interactive authentication is disabled to avoid man-in-the-middle attacks."))
  (when (ssh-client-forward-agent client)
    (setf (ssh-client-forward-agent client) nil)
    (ssh-warn "Agent forwarding is disabled to avoid man-in-the-middle attacks."))
  (when (ssh-client-forward-x11 client)
    (setf (ssh-client-forward-x11 client) nil)
    (ssh-warn "X11 forwarding is disabled to avoid man-in-the-middle attacks."))
  (unless (eq (ssh-client-update-host-keys client) :no)
    (setf (ssh-client-update-host-keys client) :no)
    (ssh-warn "UpdateHostkeys is disabled because the host key is not trusted."))
  t)

(defun ssh-client-note-changed-host-key (client host-key fingerprint)
  "Warn about HOST-KEY's change and apply the host key policy.

StrictHostKeyChecking=no continues with a weakened connection; every other
policy refuses, as OpenSSH does for a changed key."
  (ssh-client-warn-changed-host-key client host-key fingerprint)
  (if (eq (ssh-client-host-key-policy client) :insecure)
      (ssh-client-continue-with-changed-host-key client)
      (error 'ssh-host-key-error
             :detail (format nil
                             "Host key for ~A has changed and you have requested strict checking."
                             (ssh-client-host-spec client))
             :fingerprint fingerprint)))

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
              ;; StrictHostKeyChecking=no continues after a changed key, but
              ;; only after turning off everything a man in the middle could
              ;; exploit.  Every other policy still refuses.
              (ssh-client-note-changed-host-key client host-key fingerprint))
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
    ;; A changed key is already untrusted, and CheckHostIP must not turn the
    ;; continuation into a second refusal.
    (unless (or (ssh-client-host-key-dns-accepted client)
                (ssh-client-host-key-untrusted client))
      (ssh-client-check-host-address client host-key))))

(defun ssh-client-host-key-untrusted-p (client)
  "Whether CLIENT continued past a changed host key.

StrictHostKeyChecking=no warns and keeps the connection, but the caller must
not start port forwarding: it is disabled just as ssh disables it."
  (ssh-client-host-key-untrusted client))

(defun ssh-client-accept-unknown-host-key (client host-key fingerprint)
  "Decide what to do with a host key never seen before."
  (let ((policy (ssh-client-host-key-policy client)))
    (flet ((refuse ()
             (error 'ssh-host-key-error
                    :detail "the host key is not in known_hosts"
                    :fingerprint fingerprint))
           (confirm (callback)
             (if (funcall callback client fingerprint host-key)
                 (ssh-client-remember-host-key client host-key)
                 (error 'ssh-host-key-error
                        :detail (format nil "the host key for ~A was rejected"
                                        (ssh-client-host-spec client))
                        :fingerprint fingerprint))))
      (cond
        ;; StrictHostKeyChecking=no accepts and records the key, exactly as a
        ;; confirmed prompt would; it is not a policy that forgets the answer.
        ((eq policy :insecure)
         (ssh-client-remember-host-key client host-key)
         t)
        ((eq policy :accept-new)
         (ssh-client-remember-host-key client host-key)
         t)
        ((eq policy :strict) (refuse))
        ;; BatchMode forbids asking, so a confirmation callback is not called;
        ;; OpenSSH treats an unanswered confirmation as a refusal.
        ((and (ssh-client-batch-mode client)
              (or (eq policy :ask) (functionp policy)))
         (refuse))
        ((eq policy :ask)
         (let ((callback (ssh-client-host-key-callback client)))
           (if callback
               (confirm callback)
               (refuse))))
        ((functionp policy) (confirm policy))
        (t (error 'ssh-host-key-error
                  :detail (format nil "unknown host key policy ~S" policy)
                  :fingerprint fingerprint))))))

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

(defun ssh-signature-algorithm-base (name)
  "NAME without its certificate suffix, the signature it is made with.

The suffix is removed by spelling, not by looking the remainder up in the
plain key types: an RSA certificate is named rsa-sha2-512-cert-v01@openssh.com
even though rsa-sha2-512 is a signature name rather than a key type."
  (flet ((strip (suffix)
           (let ((start (- (length name) (length suffix))))
             (when (and (not (minusp start))
                        (string= suffix name :start2 start))
               (subseq name 0 start)))))
    (or (strip +ssh-certificate-suffix+)
        (strip +ssh-mldsa-certificate-suffix+)
        name)))

(defun ssh-select-signature-algorithm (names patterns server-algorithms)
  "The first of NAMES that PATTERNS and SERVER-ALGORITHMS allow, or NIL.

NAMES is in the signer's own preference order.  PATTERNS is the configured
PubkeyAcceptedAlgorithms or HostbasedAcceptedAlgorithms list, tried in its
order so an explicit ordering wins; NIL leaves every name eligible.
SERVER-ALGORITHMS is RFC 8308's server-sig-algs, which limits publickey to
the names the server says it verifies; NIL means the server said nothing.
A certificate name is checked by the signature it carries, because
server-sig-algs lists signatures, not certificate key types, and only RSA
has more than one signature spelling to choose between."
  (let ((candidates names))
    (when server-algorithms
      (setf candidates
            (remove-if-not
             (lambda (name)
               (let ((base (ssh-signature-algorithm-base name)))
                 (or (null (ssh-rsa-digest-keyword base))
                     (member base server-algorithms :test #'string=))))
             candidates)))
    (when candidates
      (if (null patterns)
          (first candidates)
          (block select
            (dolist (pattern patterns)
              (let ((match (find-if (lambda (name)
                                      (ssh-match-pattern pattern name))
                                    candidates)))
                (when match (return-from select match)))))))))

(defun ssh-signer-signature-algorithm (signer patterns &key server-algorithms)
  "The algorithm name SIGNER should use, or NIL when none is allowed."
  (ssh-select-signature-algorithm (ssh-signer-signature-algorithms signer)
                                  patterns server-algorithms))

(defun ssh-filter-signers (signers patterns &key minimum-rsa-size)
  "SIGNERS that PATTERNS allow and whose RSA modulus is large enough.

A signer matches when any algorithm it can answer matches a pattern, so an
RSA key is kept for PubkeyAcceptedAlgorithms rsa-sha2-512 alone.  A NIL
PATTERNS list leaves every type eligible.  MINIMUM-RSA-SIZE is
RequiredRSASize: it only rejects RSA keys below the floor, as ssh does."
  (remove-if
   (lambda (signer)
     (or (and patterns
              (not (some (lambda (pattern)
                           (some (lambda (algorithm)
                                   (ssh-match-pattern pattern algorithm))
                                 (ssh-signer-signature-algorithms signer)))
                         patterns)))
         (not (ssh-key-rsa-size-allowed-p (ssh-signer-blob signer)
                                          minimum-rsa-size))))
   signers))


;;; ---- Connection information for mux -O conninfo ----

(defgeneric ssh-client-traffic-stats (client)
  (:documentation
   "Packet, block and byte counters for CLIENT, or NIL when the transport
cannot see them.  OpenSSH reports both directions since the last NEWKEYS.")
  (:method ((client t)) nil))

(defgeneric ssh-client-connection-endpoints (client)
  (:documentation
   "CLIENT's socket endpoints as (VALUES LOCAL-IP LOCAL-PORT REMOTE-IP
REMOTE-PORT), or NIL when the transport is not a socket.")
  (:method ((client t)) nil))

(defun ssh-socket-endpoints (fd)
  "FD's local and remote endpoints as (VALUES LIP LPORT RIP RPORT)."
  (flet ((endpoint (function)
           (cffi:with-foreign-objects
               ((address '(:struct cl-pnet-sockets:sockaddr-in6))
                (length :unsigned-int))
             (setf (cffi:mem-ref length :unsigned-int)
                   cl-pnet-sockets:+sockaddr-in6-size+)
             (when (>= (funcall function fd address length) 0)
               (multiple-value-bind (ip port)
                   (cl-pnet-sockets:sockaddr-to-string address)
                 (values ip port))))))
    (multiple-value-bind (local-ip local-port)
        (endpoint #'cl-pnet-sockets:c-getsockname)
      (multiple-value-bind (remote-ip remote-port)
          (endpoint #'cl-pnet-sockets:c-getpeername)
        (values local-ip local-port remote-ip remote-port)))))

(defun ssh-socket-data-pending-p (fd)
  "True when FD has unread data waiting in its receive queue.

A non-blocking MSG_PEEK answers without consuming the data, so the event
loop's own read still sees it.  The packet layer uses this to tell a peer
that sent its identification before resetting the connection from one that
reset it before sending anything at all."
  (and fd
       (plusp
        (cffi:with-foreign-object (buffer :unsigned-char 1)
          (cl-pnet-sockets:c-recv
           fd buffer 1
           (logior cl-pnet-sockets:+msg-peek+
                   cl-pnet-sockets:+msg-dontwait+))))))

(defun ssh-client-release-string (client)
  "CLIENT's identification without the SSH-2.0- prefix, as SSH_RELEASE is."
  (let ((version (ssh-client-version-string client)))
    (if (and version
             (>= (length version) 8)
             (string= version "SSH-2.0-" :end1 8))
        (subseq version 8)
        version)))

(defun ssh-client-connection-info (client)
  "A plist describing CLIENT's connection, as -O conninfo reports it.

The values the transport does not expose are NIL; the caller prints what it
has rather than inventing numbers."
  (let ((negotiated (ssh-client-negotiated client)))
    (list :client-version (ssh-client-release-string client)
          :server-version (ssh-client-server-version client)
          :connected-at (ssh-client-connected-at client)
          :kex (getf negotiated :kex)
          :host-key (getf negotiated :host-key)
          :cipher-in (getf negotiated :cipher-s2c)
          :cipher-out (getf negotiated :cipher-c2s)
          :mac-in (getf negotiated :mac-s2c)
          :mac-out (getf negotiated :mac-c2s)
          :compression-in (getf negotiated :compression-s2c)
          :compression-out (getf negotiated :compression-c2s)
          :rekey-limit (or (ssh-client-rekey-limit client) 0)
          :rekey-interval (or (ssh-client-rekey-interval client) 0)
          :endpoints (multiple-value-list
                      (ssh-client-connection-endpoints client))
          :traffic (ssh-client-traffic-stats client))))
