(in-package #:cl-pnet-ssh)

;;;; Algorithm preferences and the glob matching that names them.
;;;;
;;;; Both roles read the same lists and the same sshd/ssh algorithm syntax:
;;;; a plain list replaces the default, + appends, - removes and ^ puts names
;;;; first.  The lists live here, before SERVER-CONFIG, so an sshd_config can
;;;; be validated while it is read instead of when the first peer arrives.

(defparameter +ssh-kex-real-algorithms+
  '("mlkem768x25519-sha256"
    "mlkem768nistp256-sha256"
    "curve25519-sha256"
    "curve25519-sha256@libssh.org"
    "ecdh-sha2-nistp256"
    "ecdh-sha2-nistp384"
    "ecdh-sha2-nistp521")
  "Every key-exchange method this build implements, without the markers.

This is the set KexAlgorithms may name, not the default offer.  In
particular mlkem768nistp256-sha256 is implemented but, as in OpenSSH, left
out of the default list; a user who names it can still match a peer that
offers it.")

(defparameter +ssh-kex-default-algorithms+
  '("mlkem768x25519-sha256"
    "curve25519-sha256"
    "curve25519-sha256@libssh.org"
    "ecdh-sha2-nistp256"
    "ecdh-sha2-nistp384"
    "ecdh-sha2-nistp521")
  "The default key-exchange offer, in OpenSSH's order.

mlkem768x25519-sha256 is OpenSSH's default post-quantum hybrid.  It needs
ML-KEM-768 and X25519, both of which this build has, so it is offered first
and a peer that does not know it falls back to curve25519.  The NIST-curve
ECDH methods come last, so a peer that offers only one of them still
negotiates.  KEXINIT and -G use this list; -Q kex and KexAlgorithms use
+SSH-KEX-REAL-ALGORITHMS+.")

(defparameter +ssh-kex-algorithms+
  (append +ssh-kex-default-algorithms+
          ;; Not algorithms: markers asking the peer to answer EXT_INFO and
          ;; to reset packet sequence numbers at NEWKEYS (OpenSSH's strict
          ;; KEX).  They ride along with whatever KexAlgorithms selects.
          '("ext-info-c"
            "kex-strict-c-v00@openssh.com")))

(defparameter +ssh-post-quantum-kex-algorithms+
  '("mlkem768x25519-sha256"
    "mlkem768nistp256-sha256"
    "sntrup761x25519-sha512"
    "sntrup761x25519-sha512@openssh.com")
  "OpenSSH's post-quantum key exchanges.

mlkem768x25519-sha256 is offered by the pure transport; the others are
listed so WarnWeakCrypto recognises them and so a later implementation needs
only to add the method to the offer.  A transport without one leaves it out
of the list it resolves KexAlgorithms against.")

(defun ssh-kex-post-quantum-p (name)
  "Whether NAME is one of OpenSSH's post-quantum key exchanges."
  (and name
       (member name +ssh-post-quantum-kex-algorithms+ :test #'string=)
       t))

(defparameter +ssh-host-key-algorithms+
  '("ssh-ed25519-cert-v01@openssh.com"
    "ecdsa-sha2-nistp256-cert-v01@openssh.com"
    "ecdsa-sha2-nistp384-cert-v01@openssh.com"
    "ecdsa-sha2-nistp521-cert-v01@openssh.com"
    "rsa-sha2-512-cert-v01@openssh.com"
    "rsa-sha2-256-cert-v01@openssh.com"
    "ssh-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    ;; RSA host keys keep the ssh-rsa key format while rsa-sha2 names the
    ;; signature; SHA-1 ssh-rsa stays last for servers that never learned
    ;; the newer names.
    "rsa-sha2-512"
    "rsa-sha2-256"
    "ssh-rsa")
  "Host key algorithms offered to a server, in preference order.

Certificate names come first, as in OpenSSH, but a server only selects one
when it actually has the matching certificate.")

(defparameter +ssh-server-host-key-preference+
  '("ssh-ed25519-cert-v01@openssh.com"
    "ecdsa-sha2-nistp256-cert-v01@openssh.com"
    "ecdsa-sha2-nistp384-cert-v01@openssh.com"
    "ecdsa-sha2-nistp521-cert-v01@openssh.com"
    "rsa-sha2-512-cert-v01@openssh.com"
    "rsa-sha2-256-cert-v01@openssh.com"
    "ssh-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    "rsa-sha2-512"
    "rsa-sha2-256"
    "ssh-rsa")
  "Host key algorithms a server can present, in preference order.

A server advertises only those its loaded keys can actually sign with, so a
client never selects an algorithm that would fail at KEX_ECDH_REPLY.  A
certificate algorithm is offered only when a HostCertificate supplies the
certificate for the key, and then it outranks the plain key, as in sshd.")

(defparameter +ssh-server-host-key-all-algorithms+
  (append +ssh-server-host-key-preference+
          ;; Not offered by default, but an administrator may still name the
          ;; SHA-1 certificate form, as OpenSSH's own list allows.
          '("ssh-rsa-cert-v01@openssh.com"))
  "Every host key algorithm a HostKeyAlgorithms directive may name.")

(defparameter +ssh-server-user-key-algorithms+
  '("ssh-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    "rsa-sha2-512"
    "rsa-sha2-256")
  "Public-key signature algorithms the server accepts for user auth.

This is what EXT_INFO's server-sig-algs names.  SHA-1 ssh-rsa is accepted
for old clients but not advertised, matching modern OpenSSH defaults.
PubkeyAcceptedAlgorithms may add it explicitly; +SSH-SERVER-USER-KEY-ALL-
ALGORITHMS+ is the set such a name resolves against.")

(defparameter +ssh-server-user-key-all-algorithms+
  (append +ssh-server-user-key-algorithms+
          ;; Not advertised by default, but an administrator may name it, as
          ;; OpenSSH's sshkey_alg_list does.  Certificate type names are not
          ;; advertised, but PubkeyAcceptedAlgorithms may still name them
          ;; because a certificate logs in under its cert type name.
          '("ssh-rsa"
            "ssh-ed25519-cert-v01@openssh.com"
            "ecdsa-sha2-nistp256-cert-v01@openssh.com"
            "ecdsa-sha2-nistp384-cert-v01@openssh.com"
            "ecdsa-sha2-nistp521-cert-v01@openssh.com"
            "ssh-rsa-cert-v01@openssh.com"
            "rsa-sha2-256-cert-v01@openssh.com"
            "rsa-sha2-512-cert-v01@openssh.com"))
  "Every user public-key algorithm this server can enforce a choice from.")

(defparameter +ssh-server-ca-signature-algorithms+
  '("ssh-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    "rsa-sha2-512"
    "rsa-sha2-256")
  "CASignatureAlgorithms' default, without the security-key names this
build cannot verify.  SHA-1 ssh-rsa is deliberately absent, as in sshd.")

(defparameter +ssh-server-ca-signature-algorithm-names+
  (append +ssh-server-ca-signature-algorithms+ '("ssh-rsa"))
  "Every CA signature name a config may select.

This is sshd's all-signatures set minus the security-key names: ssh-rsa is
verifiable here, so an administrator may opt back into it, but it is not a
default.")

(defparameter +ssh-ciphers+
  '("chacha20-poly1305@openssh.com"
    "aes128-gcm@openssh.com"
    "aes256-gcm@openssh.com"
    "aes128-ctr"
    "aes192-ctr"
    "aes256-ctr")
  "The ciphers this build implements, in OpenSSH's default order.

The CBC modes OpenSSH still lists for old peers are not here: this build
offers only the CTR and AEAD constructions it implements.")

;; chacha20-poly1305@openssh.com is an AEAD and ignores the MAC, but RFC 4253
;; still negotiates one of these, and OpenSSH expects a common choice.
(defparameter +ssh-macs+
  '("hmac-sha2-256-etm@openssh.com"
    "hmac-sha2-512-etm@openssh.com"
    "hmac-sha1-etm@openssh.com"
    "hmac-sha2-256"
    "hmac-sha2-512"
    "hmac-sha1")
  "The MACs this build implements, in OpenSSH's default order.

The UMAC constructions OpenSSH lists first are not here, but every HMAC it
offers is, with the encrypt-then-MAC variants ahead of the plain ones.")

(defparameter +ssh-compressions+ '("none" "zlib@openssh.com")
  "The compression methods this build understands, in the order OpenSSH
offers them when compression is not requested.  Negotiation takes the first
entry of the client's list that the server also offers, so \"none\" first
leaves compression off unless the client asks for it.")

(defparameter +ssh-compressions-preferred+ '("zlib@openssh.com" "none")
  "The offer a client makes after -C or Compression yes, as OpenSSH does.")

(defparameter +ssh-rsa-minimum-modulus-size+ 1024
  "OpenSSH's SSH_RSA_MINIMUM_MODULUS_SIZE, the floor under RequiredRSASize.")

(defun ssh-match-pattern (pattern text)
  "Whether TEXT matches PATTERN, with sshd's match_pattern(3) semantics.

Only * and ? are special; a * matches any run of characters, a ? exactly one,
and nothing else is quoted.  This is what AcceptEnv and algorithm names use,
which is narrower than the bracket classes an ssh_config Host pattern allows."
  (cond
    ((zerop (length pattern)) (zerop (length text)))
    ((char= (char pattern 0) #\*)
     (let ((rest (string-left-trim "*" pattern)))
       (if (zerop (length rest))
           t
           (loop for index from 0 to (length text)
                 thereis (ssh-match-pattern rest (subseq text index))))))
    ((zerop (length text)) nil)
    ((or (char= (char pattern 0) #\?)
         (char= (char pattern 0) (char text 0)))
     (ssh-match-pattern (subseq pattern 1) (subseq text 1)))
    (t nil)))

(defun ssh-choose-algorithm (ours theirs)
  "The first of OURS that is also in THEIRS, or NIL."
  (iter (for candidate in ours)
    (when (member candidate theirs :test #'string=)
      (leave candidate))))

(defun ssh-algorithm-pattern-matches (pattern supported option)
  "SUPPORTED names matching the glob PATTERN, in SUPPORTED order."
  (when (and (plusp (length pattern)) (char= (char pattern 0) #\!))
    (error 'ssh-config-error
           :keyword option
           :detail (format nil "negated pattern ~A is not allowed here"
                           pattern)))
  (let ((matches (remove-if-not (lambda (name)
                                  (ssh-match-pattern pattern name))
                                supported)))
    (unless matches
      (error 'ssh-config-error
             :keyword option
             :detail (format nil "~A matches no algorithm this build offers (~{~A~^, ~})"
                             pattern supported)))
    matches))

(defun ssh-resolve-algorithm-list (names supported option &key (all supported))
  "NAMES, a configured algorithm list, as the ordered list this build offers.

NAMES is the comma-separated list ssh_config or an sshd_config gave, split
into strings.  ssh's prefixes apply: a leading + appends to SUPPORTED, -
removes from it, and ^ puts the named algorithms first.  A plain list
replaces SUPPORTED outright, so an algorithm absent from this build is an
error instead of being silently dropped.

SUPPORTED is the list a bare list replaces and the base the prefixes adjust;
ALL is the set a pattern may name.  They differ where a server accepts an
algorithm it does not advertise, such as PubkeyAcceptedAlgorithms with
ssh-rsa, while the default list still leaves it out."
  (let* ((text (format nil "~{~A~^,~}" (remove "" names :test #'string=)))
         (head (and (plusp (length text)) (char text 0)))
         (mode (cond ((null head) :replace)
                     ((char= head #\+) :append)
                     ((char= head #\-) :remove)
                     ((char= head #\^) :prepend)
                     (t :replace)))
         (patterns (if (eq mode :replace) text (subseq text 1))))
    (flet ((expand ()
             (let ((result '()))
               (dolist (pattern (uiop:split-string patterns :separator ",")
                        (nreverse result))
                 (dolist (name (ssh-algorithm-pattern-matches
                                pattern all option))
                   (pushnew name result :test #'string=))))))
      (ecase mode
        (:replace
         (expand))
        (:append
         (let ((result (copy-list supported)))
           (dolist (name (expand) result)
             (unless (member name result :test #'string=)
               (setf result (append result (list name)))))))
        (:prepend
         (let ((result (expand)))
           (dolist (name supported result)
             (unless (member name result :test #'string=)
               (setf result (append result (list name)))))))
        (:remove
         (let ((kept (remove-if (lambda (name)
                                  (some (lambda (pattern)
                                          (ssh-match-pattern pattern name))
                                        (uiop:split-string
                                         patterns :separator ",")))
                                supported)))
           (unless kept
             (error 'ssh-config-error
                    :keyword option
                    :detail (format nil "~A removes every algorithm this build offers"
                                    text)))
           kept))))))
