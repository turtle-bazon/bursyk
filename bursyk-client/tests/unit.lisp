(in-package #:cl-user)

(defpackage #:bursyk-client-tests
  (:use #:cl #:fiveam))

(in-package #:bursyk-client-tests)

(def-suite bursyk-client :description "BURS command line")
(in-suite bursyk-client)

;;; ---- helpers ----

(defun empty-options ()
  "The CLI's defaults, freshly allocated so a test cannot leak into another."
  (list :port nil :user nil :identity nil :identity-arguments nil
        :config nil :known-hosts nil
        :policy nil :agent nil :options nil :jump nil :proxy-command nil
        :verbose 0 :quiet nil :log-file nil :address-family nil
        :ciphers nil :macs nil :kex-algorithms nil :compression nil
        :request-tty nil :forward-agent nil :gateway-ports nil
        :no-command nil :stdin-null nil :subsystem nil :stdio-forward nil
        :local-forward nil :remote-forward nil :dynamic-forward nil
        :query nil :help nil :version nil :print-config nil
        :dump-public-keys nil
        :background nil :background-child nil :control-master-daemon nil
        :control-master nil :control-path nil
        :control-command nil :host nil :no-control-persist nil
        :pkcs11 nil :bind-interface nil
        :bind-address nil :gssapi-auth nil :tunnel nil :x11-forward nil
        :tag nil :protocol-1 nil :protocol-2 nil
        :escape-char nil))

(defun parse (arguments)
  "Parse ARGUMENTS with fresh options.
Returns (VALUES DESTINATION COMMAND OPTIONS), so a test can look at the
CLI's decision and at the plist it filled."
  (let ((burs::*options* (empty-options)))
    (multiple-value-bind (destination command)
        (burs::parse-arguments arguments)
      (values destination command burs::*options*))))

;;; ---- command line ----

(test split-destination-splits-at-the-first-at-sign
  (multiple-value-bind (host user)
      (burs::split-destination "alice@example.org")
    (is (equal "example.org" host))
    (is (equal "alice" user)))
  (multiple-value-bind (host user)
      (burs::split-destination "example.org")
    (is (equal "example.org" host))
    (is (null user)))
  (multiple-value-bind (host user)
      (burs::split-destination "a@b@example.org")
    (is (equal "b@example.org" host))
    (is (equal "a" user))))

(test parse-arguments-stops-at-the-destination
  (multiple-value-bind (destination command options)
      (parse '("-p" "2222" "-l" "alice" "-i" "one"
               "-i" "two" "host.example" "uname" "-a"))
    (is (equal "host.example" destination))
    (is (equal '("uname" "-a") command))
    (is (equal "2222" (getf options :port)))
    (is (equal "alice" (getf options :user)))
    ;; -i may repeat; both keys are kept for authentication.
    (is (equal '("two" "one") (getf options :identity)))))

(test protocol-flags-and-tag-are-accepted
  ;; ssh keeps -1 and -2 for old scripts.  -2 is the default and inert; -1
  ;; is recorded here and refused before connecting.
  (multiple-value-bind (destination command options)
      (parse '("-2" "-1" "-P" "work" "host"))
    (declare (ignore destination command))
    (is (getf options :protocol-2))
    (is (getf options :protocol-1))
    (is (equal "work" (getf options :tag)))))

(test algorithm-queries-cover-ssh-spellings
  (let ((plain (burs::query-answer "sig"))
        (all (burs::query-answer "key-sig")))
    ;; sig is the plain signature list; key-sig adds certificate names.
    (is (member "rsa-sha2-512" plain :test #'string=))
    (is (not (member "ssh-ed25519-cert-v01@openssh.com" plain
                     :test #'string=)))
    (is (member "ssh-ed25519-cert-v01@openssh.com" all :test #'string=))
    ;; sshkey_alg_list order, with the implemented SHA-1 ssh-rsa signature
    ;; that -Q lists even though the default offer disables it.
    (is (equal (if (cl-pnet-ssh:ssh-client-feature-supported-p :mldsa)
                   '("ssh-ed25519"
                     "ssh-mldsa44-ed25519"
                     "ecdsa-sha2-nistp256"
                     "ecdsa-sha2-nistp384"
                     "ecdsa-sha2-nistp521"
                     "ssh-rsa"
                     "rsa-sha2-256"
                     "rsa-sha2-512")
                   '("ssh-ed25519"
                     "ecdsa-sha2-nistp256"
                     "ecdsa-sha2-nistp384"
                     "ecdsa-sha2-nistp521"
                     "ssh-rsa"
                     "rsa-sha2-256"
                     "rsa-sha2-512"))
               plain))
    (is (equal (mapcan (lambda (name)
                         (list name (burs::query-certificate-name name)))
                       plain)
               all)))
  (is (equal '("none" "zlib@openssh.com")
             (burs::query-answer "compression")))
  (is (equal '("2") (burs::query-answer "protocol-version")))
  ;; ssh 10.6's -Q help names exactly these queries.
  (is (equal '("cipher" "cipher-auth" "compression" "kex" "key" "key-cert"
               "key-plain" "key-sig" "mac" "protocol-version" "sig")
             (burs::query-answer "help")))
  (is (equal (burs::query-answer "cipher")
             (burs::query-answer "Ciphers")))
  ;; -Q cipher-auth lists only the AEAD constructions; the CTR and CBC
  ;; ciphers rely on the negotiated MAC and belong to -Q cipher alone.
  (let ((ciphers (burs::query-answer "cipher"))
        (auth (burs::query-answer "cipher-auth")))
    (is (member "aes128-ctr" ciphers :test #'string=))
    (is (not (member "aes128-ctr" auth :test #'string=)))
    (is (member "aes128-gcm@openssh.com" auth :test #'string=))
    (is (member "chacha20-poly1305@openssh.com" auth :test #'string=))
    ;; CBC is implemented and listed, but not offered unless named.
    (dolist (cipher '("3des-cbc" "aes128-cbc" "aes192-cbc" "aes256-cbc"))
      (is (member cipher ciphers :test #'string=))
      (is (not (member cipher auth :test #'string=)))
      (is (not (member cipher cl-pnet-ssh:+ssh-ciphers+ :test #'string=)))))
  ;; -Q key splits cleanly into plain and certificate spellings.
  (is (every (lambda (name)
               (not (burs::certificate-algorithm-name-p name)))
             (burs::query-answer "key-plain")))
  (is (every #'burs::certificate-algorithm-name-p
             (burs::query-answer "key-cert")))
  ;; -Q key pairs each key type with its certificate, as ssh does, and names
  ;; RSA as ssh-rsa, the key format, not the rsa-sha2-* signature names.
  (let ((key (burs::query-answer "key")))
    (is (equal "ssh-ed25519" (first key)))
    (is (equal "ssh-ed25519-cert-v01@openssh.com" (second key)))
    (is (equal "ssh-rsa" (nth (- (length key) 2) key)))
    (is (equal "ssh-rsa-cert-v01@openssh.com" (car (last key)))))
  (is (member "ssh-rsa" (burs::query-answer "key-plain") :test #'string=))
  (is (not (member "rsa-sha2-256" (burs::query-answer "key-plain")
                   :test #'string=))))

(test kex-queries-follow-the-transport
  "A transport without ML-KEM neither lists nor accepts the hybrid."
  (let ((kex (burs::query-answer "kex"))
        (supported (cl-pnet-ssh:ssh-client-feature-supported-p
                    :post-quantum-kex)))
    (is (eq supported
            (not (null (member "mlkem768x25519-sha256" kex
                               :test #'string=)))))
    (is (member "curve25519-sha256" kex :test #'string=))
    (is (eq supported
            (not (null (member "mlkem768x25519-sha256"
                               (burs::supported-kex-algorithms)
                               :test #'string=)))))
    ;; The P-256 ML-KEM hybrid is implemented too, and -Q lists every method
    ;; the transport can negotiate, not just the default offer.
    (is (eq supported
            (not (null (member "mlkem768nistp256-sha256" kex
                               :test #'string=)))))
    (is (eq supported
            (not (null (member "mlkem768nistp256-sha256"
                               (burs::supported-kex-algorithms)
                               :test #'string=)))))
    ;; The MODP groups are implemented by both transports and listed by -Q.
    (dolist (name '("diffie-hellman-group14-sha256"
                    "diffie-hellman-group16-sha512"
                    "diffie-hellman-group18-sha512"))
      (is (member name kex :test #'string=)))
    ;; -G's default offer includes the SHA-256/512 groups, not the legacy pair.
    (dolist (name '("diffie-hellman-group14-sha256"
                    "diffie-hellman-group16-sha512"
                    "diffie-hellman-group18-sha512"))
      (is (member name (burs::default-kex-algorithms) :test #'string=)))
    (dolist (name '("diffie-hellman-group1-sha1"
                    "diffie-hellman-group14-sha1"))
      (is (not (member name (burs::default-kex-algorithms)
                       :test #'string=))))
    ;; RFC 4419 group exchange is implemented by both transports and listed.
    (dolist (name '("diffie-hellman-group-exchange-sha256"
                    "diffie-hellman-group-exchange-sha1"))
      (is (member name kex :test #'string=)))
    (is (member "diffie-hellman-group-exchange-sha256"
                (burs::default-kex-algorithms) :test #'string=))
    (is (not (member "diffie-hellman-group-exchange-sha1"
                     (burs::default-kex-algorithms) :test #'string=)))
    ;; -G reports the default offer, which leaves that hybrid out, as ssh does.
    (is (not (member "mlkem768nistp256-sha256"
                     (burs::default-kex-algorithms) :test #'string=)))))

(test mac-queries-cover-the-transport
  "The default offer stays OpenSSH's while -Q mac lists every implementation."
  (let ((all (burs::query-answer "mac"))
        (default (burs::default-mac-algorithms))
        (umac (cl-pnet-ssh:ssh-client-feature-supported-p :umac))
        (legacy (cl-pnet-ssh:ssh-client-feature-supported-p :legacy-macs)))
    (is (eq legacy
            (not (null (member "hmac-sha1-96" all :test #'string=)))))
    (is (eq legacy
            (not (null (member "hmac-md5" all :test #'string=)))))
    (is (eq umac
            (not (null (member "umac-64@openssh.com" all
                               :test #'string=)))))
    ;; The legacy MACs are implemented but neither offered by default nor
    ;; present in the default list -G prints.
    (is (not (member "hmac-md5" default :test #'string=)))
    (is (not (member "hmac-sha1-96" default :test #'string=)))
    ;; -Q mac follows ssh's macs[] order, not the default preference order.
    (is (equal (if legacy
                   '("hmac-sha1" "hmac-sha1-96" "hmac-sha2-256"
                     "hmac-sha2-512" "hmac-md5" "hmac-md5-96")
                   '("hmac-sha1" "hmac-sha2-256" "hmac-sha2-512"))
               (subseq all 0 (if legacy 6 3))))))

(test mldsa-queries-follow-the-transport
  "A transport without ML-DSA neither lists nor accepts the composite key."
  (let ((supported (cl-pnet-ssh:ssh-client-feature-supported-p :mldsa)))
    (dolist (name '("ssh-mldsa44-ed25519" "ssh-mldsa44-ed25519-cert"))
      (is (eq supported
              (not (null (member name (burs::query-answer "key")
                                 :test #'string=))))))
    (is (eq supported
            (not (null (member "ssh-mldsa44-ed25519"
                               (burs::query-answer "sig")
                               :test #'string=)))))
    (is (eq supported
            (not (null (member "ssh-mldsa44-ed25519-cert"
                               (burs::query-answer "key-sig")
                               :test #'string=)))))
    ;; OpenSSH spells this certificate with the short -cert suffix, so the
    ;; long -cert-v01@ form must never appear.
    (is (not (member "ssh-mldsa44-ed25519-cert-v01@openssh.com"
                     (burs::query-answer "key-sig") :test #'string=)))
    ;; The default CA list follows sshd and leaves ML-DSA out, while -Q
    ;; key-ca-sign names every signature the build can check.
    (is (not (member "ssh-mldsa44-ed25519"
                     (burs::supported-ca-signature-algorithms)
                     :test #'string=)))
    (is (eq supported
            (not (null (member "ssh-mldsa44-ed25519"
                               (burs::query-answer "key-ca-sign")
                               :test #'string=)))))))

(test double-dash-ends-option-parsing
  (multiple-value-bind (destination command options)
      (parse '("--" "host.example" "-p" "not-a-port"))
    (is (equal "host.example" destination))
    (is (equal '("-p" "not-a-port") command))
    (is (null (getf options :port)))))

(test clustered-short-options
  (multiple-value-bind (destination command options)
      (parse '("-vvT" "host" "-p" "2222"))
    (is (equal "host" destination))
    ;; Parsing stops at the destination, so -p here belongs to the
    ;; remote command even though ssh would have taken it as a flag.
    (is (equal '("-p" "2222") command))
    (is (= 2 (getf options :verbose)))
    (is (eq :no (getf options :request-tty)))
    (is (null (getf options :port)))))

(test attached-and-long-option-values
  (multiple-value-bind (destination command options)
      (parse '("-p2222" "-lalice" "host" "true"))
    (is (equal "host" destination))
    (is (equal '("true") command))
    (is (equal "2222" (getf options :port)))
    (is (equal "alice" (getf options :user))))
  (multiple-value-bind (destination command options)
      (parse '("--port=2200" "--user" "bob" "host"))
    (is (equal "host" destination))
    (is (null command))
    (is (equal "2200" (getf options :port)))
    (is (equal "bob" (getf options :user))))
  ;; The readable spellings stay case-insensitive, and --identity-file is
  ;; accepted as another name for --identity.
  (multiple-value-bind (destination command options)
      (parse '("--PORT=2201" "--IDENTITY-FILE=/tmp/key" "host"))
    (is (equal "host" destination))
    (is (null command))
    (is (equal "2201" (getf options :port)))
    (is (equal '("/tmp/key") (getf options :identity)))))

(test short-options-keep-ssh-meanings
  ;; -a disables agent forwarding; the agent picker is --agent.  It is kept
  ;; distinct from "not asked" so a config file's ForwardAgent cannot win.
  (multiple-value-bind (destination command options)
      (parse '("-a" "host"))
    (declare (ignore destination command))
    (is (eq :no (getf options :forward-agent))))
  (multiple-value-bind (destination command options)
      (parse '("-A" "host"))
    (declare (ignore destination command))
    (is (eq t (getf options :forward-agent))))
  (multiple-value-bind (destination command options)
      (parse '("-4" "host"))
    (declare (ignore destination command))
    (is (equal "inet" (getf options :address-family))))
  (multiple-value-bind (destination command options)
      (parse '("-6" "host"))
    (declare (ignore destination command))
    (is (equal "inet6" (getf options :address-family))))
  (multiple-value-bind (destination command options)
      (parse '("--address-family=any" "host"))
    (declare (ignore destination command))
    (is (equal "any" (getf options :address-family))))
  (multiple-value-bind (destination command options)
      (parse '("-t" "host"))
    (declare (ignore destination command))
    (is (eq :force (getf options :request-tty))))
  (multiple-value-bind (destination command options)
      (parse '("-T" "host"))
    (declare (ignore destination command))
    (is (eq :no (getf options :request-tty))))
  (multiple-value-bind (destination command options)
      (parse '("--request-tty=no" "host"))
    (declare (ignore destination command))
    (is (equal "no" (getf options :request-tty)))))

(test repeated-options-keep-command-line-order
  (multiple-value-bind (destination command options)
      (parse '("-L" "8080:example.org:80"
               "-L" "127.0.0.1:9090:example.org:90" "host"))
    (declare (ignore destination command))
    (is (equal '("127.0.0.1:9090:example.org:90" "8080:example.org:80")
               (getf options :local-forward))))
  (let ((burs::*options* (empty-options)))
    (burs::parse-arguments '("-o" "User=first" "-oUser=second" "host"))
    ;; *OPTIONS* keeps the list reversed, as the old parser did;
    ;; COMMAND-LINE-OPTION-LIST restores the written order.
    (is (equal '("User=second" "User=first")
               (getf burs::*options* :options)))
    (is (equal '("User=first" "User=second")
               (burs::command-line-option-list)))))

(test ssh-flags-map-onto-the-option-plist
  (multiple-value-bind (destination command options)
      (parse '("-G" "-q" "-n" "-N" "host"))
    (declare (ignore destination command))
    (is (eq t (getf options :print-config)))
    (is (eq t (getf options :quiet)))
    (is (eq t (getf options :stdin-null)))
    (is (eq t (getf options :no-command))))
  (multiple-value-bind (destination command options)
      (parse '("-s" "host" "sftp"))
    (is (equal "host" destination))
    (is (equal '("sftp") command))
    (is (eq t (getf options :subsystem))))
  (multiple-value-bind (destination command options)
      (parse '("-W" "example.org:22" "host"))
    (declare (ignore destination command))
    (is (equal "example.org:22" (getf options :stdio-forward))))
  (multiple-value-bind (destination command options)
      (parse '("-Q" "cipher" "host"))
    (declare (ignore destination command))
    (is (equal "cipher" (getf options :query))))
  (multiple-value-bind (destination command options)
      (parse '("-V"))
    (declare (ignore destination command))
    (is (eq t (getf options :version)))))

(test a-missing-destination-is-not-invented
  (multiple-value-bind (destination command options)
      (parse '("-v"))
    (is (null destination))
    (is (null command))
    (is (= 1 (getf options :verbose)))))

(test forwarding-specifications-parse
  (is (equal '("8080" "::1" "22")
             (burs::split-forward-fields "8080:[::1]:22")))
  (let ((forward
          (burs::parse-local-forward "127.0.0.1:8080:example.org:80")))
    (is (equal "127.0.0.1" (burs::forward-bind-address forward)))
    (is (= 8080 (burs::forward-bind-port forward)))
    (is (equal "example.org" (burs::forward-host forward)))
    (is (= 80 (burs::forward-port forward))))
  (let ((forward (burs::parse-local-forward "8080:example.org:80")))
    (is (null (burs::forward-bind-address forward)))
    (is (= 8080 (burs::forward-bind-port forward))))
  (let ((forward (burs::parse-local-forward "[::1]:8080:example.org:80")))
    (is (equal "::1" (burs::forward-bind-address forward)))))

(test cancel-listen-spec-parses
  (multiple-value-bind (address port path)
      (burs::parse-cancel-listen "18082")
    (is (null address))
    (is (= 18082 port))
    (is (null path)))
  (multiple-value-bind (address port path)
      (burs::parse-cancel-listen "127.0.0.1:18082")
    (is (equal "127.0.0.1" address))
    (is (= 18082 port))
    (is (null path)))
  (multiple-value-bind (address port path)
      (burs::parse-cancel-listen "/tmp/sock")
    (is (null address))
    (is (null port))
    (is (equal "/tmp/sock" path))))

(test escape-filter-handles-sequences
  (let ((burs::*escape-char* #\~)
        (burs::*escape-pending* nil)
        (burs::*escape-line-start* t)
        (help 0)
        (forwards 0)
        (disconnected 0))
    (setf burs::*escape-help-function* (lambda () (incf help))
          burs::*escape-forwards-function* (lambda () (incf forwards))
          burs::*escape-disconnect-function* (lambda () (incf disconnected)))
    (flet ((filter (text)
             (setf burs::*escape-pending* nil
                   burs::*escape-line-start* t)
             (map 'string #'code-char
                  (burs::escape-filter
                   (map '(vector (unsigned-byte 8)) #'char-code text)))))
      (is (equal "" (filter "~?")))
      (is (= 1 help))
      (is (equal "~" (filter "~~")))
      (is (equal "" (filter "~.")))
      (is (= 1 disconnected))
      ;; A tilde away from the start of a line is ordinary input.
      (is (equal "abc~." (filter "abc~.")))
      (is (equal "a~b" (filter "a~b")))
      (is (= 0 forwards)))))

(test log-level-settings-map
  (multiple-value-bind (quiet verbose) (burs::log-level-settings "quiet")
    (is (eq t quiet))
    (is (zerop verbose)))
  (multiple-value-bind (quiet verbose) (burs::log-level-settings "error")
    (is (eq t quiet))
    (is (zerop verbose)))
  (multiple-value-bind (quiet verbose) (burs::log-level-settings "debug")
    (is (not quiet))
    (is (= 1 verbose)))
  (multiple-value-bind (quiet verbose) (burs::log-level-settings "debug3")
    (is (not quiet))
    (is (= 3 verbose)))
  (multiple-value-bind (quiet verbose) (burs::log-level-settings "info")
    (is (not quiet))
    (is (zerop verbose))))

(test local-command-reads-the-config
  (let* ((client (cl-pnet-ssh::%make-ssh-client))
         (options (cl-pnet-ssh::%make-ssh-config-options
                   :local-command "printf local"
                   :permit-local-command t)))
    (is (null (burs::config-local-command client)))
    (is (null (burs::permit-local-command-p client)))
    (setf (cl-pnet-ssh:ssh-client-config-options client) options)
    (is (equal "printf local" (burs::config-local-command client)))
    (is (burs::permit-local-command-p client))))

(test remote-command-tokens-expand
  (let ((client (cl-pnet-ssh::%make-ssh-client
                 :host "alias"
                 :connect-host "real.example"
                 :port 2200
                 :connect-port 2200
                 :user "bob")))
    (is (equal "real.example 2200 bob alias %"
               (burs::expand-remote-command client "%h %p %r %n %%")))))

(test permit-remote-open-matches
  (flet ((allowed (permit host port)
           (let ((client (cl-pnet-ssh::%make-ssh-client)))
             (setf (cl-pnet-ssh:ssh-client-config-options client)
                   (cl-pnet-ssh::%make-ssh-config-options
                    :permit-remote-open permit))
             (burs::permit-remote-open-allowed-p client host port))))
    ;; Unset and "any" permit everything; "none" permits nothing.
    (is (allowed nil "example.org" 80))
    (is (allowed :any "example.org" 80))
    (is (not (allowed :none "example.org" 80)))
    (let ((permit '(("example.org" . 80))))
      (is (allowed permit "example.org" 80))
      (is (not (allowed permit "example.org" 81)))
      (is (not (allowed permit "other.example" 80)))
      ;; A streamlocal path only matches a port wildcard.
      (is (not (allowed permit "/tmp/sock" :streamlocal))))
    (let ((permit '(("example.org" . 80) ("*" . :any))))
      ;; *:* permits any other destination, including a socket path.
      (is (allowed permit "other.example" 22))
      (is (allowed permit "/tmp/sock" :streamlocal)))))

(test clear-all-forwardings-reads-the-config
  (let* ((client (cl-pnet-ssh::%make-ssh-client))
         (options (cl-pnet-ssh::%make-ssh-config-options
                   :clear-all-forwardings t)))
    (is (null (burs::clear-all-forwardings-p client)))
    (setf (cl-pnet-ssh:ssh-client-config-options client) options)
    (is (burs::clear-all-forwardings-p client))))

(test session-type-and-stdin-null-read-the-config
  (let* ((client (cl-pnet-ssh::%make-ssh-client))
         (options (cl-pnet-ssh::%make-ssh-config-options
                   :session-type "none"
                   :stdin-null t)))
    (setf (cl-pnet-ssh:ssh-client-config-options client) options)
    (is (burs::session-type-none-p client))
    (let ((burs::*client* client)
          (burs::*options* (empty-options)))
      (is (burs::stdin-null-p))
      (is (not (burs::subsystem-request-p))))
    (setf (cl-pnet-ssh:ssh-config-options-session-type options) "subsystem")
    (let ((burs::*client* client)
          (burs::*options* (empty-options)))
      (is (burs::subsystem-request-p)))))

(test exit-on-forward-failure-reads-the-config
  (let ((client (cl-pnet-ssh::%make-ssh-client)))
    (is (null (burs::exit-on-forward-failure-p client)))
    (setf (cl-pnet-ssh:ssh-client-config-options client)
          (cl-pnet-ssh::%make-ssh-config-options
           :exit-on-forward-failure t))
    (is (burs::exit-on-forward-failure-p client))))

(test gssapi-config-does-not-block-other-methods
  "A distribution's stock ssh_config sets GSSAPIAuthentication yes.  The
directive only toggles a method this build lacks, so it must not stop the
client from falling through to publickey."
  (let ((client (cl-pnet-ssh::%make-ssh-client)))
    (setf (cl-pnet-ssh:ssh-client-config-options client)
          (cl-pnet-ssh::%make-ssh-config-options
           :gssapi-authentication t))
    (is (null (burs::check-config-supported client)))))

(test compression-config-is-accepted
  "Compression is implemented, so -C and Compression yes must not be refused."
  (let ((client (cl-pnet-ssh::%make-ssh-client)))
    (setf (cl-pnet-ssh:ssh-client-config-options client)
          (cl-pnet-ssh::%make-ssh-config-options :compression t))
    (is (null (burs::check-config-supported client)))))

(test stream-local-forwarding-specifications-parse
  ;; -L local_socket:remote_socket
  (let ((forward
          (burs::parse-local-forward "/tmp/local.sock:/tmp/remote.sock")))
    (is (equal "/tmp/local.sock" (burs::forward-bind-path forward)))
    (is (equal "/tmp/remote.sock" (burs::forward-target-path forward)))
    (is (null (burs::forward-bind-port forward)))
    (is (null (burs::forward-port forward))))
  ;; -L port:remote_socket
  (let ((forward (burs::parse-local-forward "18082:/tmp/remote.sock")))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (null (burs::forward-bind-path forward)))
    (is (equal "/tmp/remote.sock" (burs::forward-target-path forward))))
  ;; -L local_socket:host:hostport
  (let ((forward
          (burs::parse-local-forward "/tmp/local.sock:example.org:80")))
    (is (equal "/tmp/local.sock" (burs::forward-bind-path forward)))
    (is (equal "example.org" (burs::forward-host forward)))
    (is (= 80 (burs::forward-port forward))))
  ;; -L bind_address:port:remote_socket
  (let ((forward
          (burs::parse-local-forward "127.0.0.1:18082:/tmp/remote.sock")))
    (is (equal "127.0.0.1" (burs::forward-bind-address forward)))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "/tmp/remote.sock" (burs::forward-target-path forward))))
  ;; -R remote_socket:local_socket
  (let ((forward
          (burs::parse-remote-forward "/tmp/remote.sock:/tmp/local.sock")))
    (is (equal "/tmp/remote.sock" (burs::forward-bind-path forward)))
    (is (equal "/tmp/local.sock" (burs::forward-target-path forward))))
  ;; -R port:local_socket
  (let ((forward (burs::parse-remote-forward "18082:/tmp/local.sock")))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "/tmp/local.sock" (burs::forward-target-path forward))))
  ;; -R remote_socket:host:hostport
  (let ((forward
          (burs::parse-remote-forward "/tmp/remote.sock:example.org:80")))
    (is (equal "/tmp/remote.sock" (burs::forward-bind-path forward)))
    (is (equal "example.org" (burs::forward-host forward)))
    (is (= 80 (burs::forward-port forward)))))

(test config-stream-local-forwards-use-paths
  (let ((forward
          (burs::parse-config-local-forward
           "/tmp/local.sock /tmp/remote.sock")))
    (is (equal "/tmp/local.sock" (burs::forward-bind-path forward)))
    (is (equal "/tmp/remote.sock" (burs::forward-target-path forward))))
  (let ((forward
          (burs::parse-config-local-forward "18082 /tmp/remote.sock")))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "/tmp/remote.sock" (burs::forward-target-path forward))))
  (let ((forward
          (burs::parse-config-local-forward
           "/tmp/local.sock example.org:80")))
    (is (equal "/tmp/local.sock" (burs::forward-bind-path forward)))
    (is (equal "example.org" (burs::forward-host forward)))
    (is (= 80 (burs::forward-port forward))))
  (let ((forward
          (burs::parse-config-remote-forward
           "/tmp/remote.sock /tmp/local.sock")))
    (is (equal "/tmp/remote.sock" (burs::forward-bind-path forward)))
    (is (equal "/tmp/local.sock" (burs::forward-target-path forward))))
  (let ((forward
          (burs::parse-config-remote-forward
           "18082 /tmp/local.sock")))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "/tmp/local.sock" (burs::forward-target-path forward)))))

(test config-local-forward-uses-the-two-word-form
  (let ((forward (burs::parse-config-local-forward "18082 127.0.0.1:22")))
    (is (null (burs::forward-bind-address forward)))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "127.0.0.1" (burs::forward-host forward)))
    (is (= 22 (burs::forward-port forward))))
  (let ((forward
          (burs::parse-config-local-forward "127.0.0.1:18082 127.0.0.1:22")))
    (is (equal "127.0.0.1" (burs::forward-bind-address forward)))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (= 22 (burs::forward-port forward))))
  (let ((forward (burs::parse-config-local-forward "[::1]:18082 [::1]:22")))
    (is (equal "::1" (burs::forward-bind-address forward)))
    (is (equal "::1" (burs::forward-host forward)))
    (is (= 22 (burs::forward-port forward))))
  ;; A one-word line is taken as -L's colon-separated spelling.
  (let ((forward (burs::parse-config-local-forward "18082:127.0.0.1:22")))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (= 22 (burs::forward-port forward)))))

(test remote-forward-specifications-parse
  (let ((forward
          (burs::parse-remote-forward "127.0.0.1:8080:example.org:80")))
    (is (equal "127.0.0.1" (burs::forward-bind-address forward)))
    (is (= 8080 (burs::forward-bind-port forward)))
    (is (equal "example.org" (burs::forward-host forward)))
    (is (= 80 (burs::forward-port forward))))
  ;; Port 0 asks the server to allocate one.
  (let ((forward (burs::parse-remote-forward "0:example.org:80")))
    (is (null (burs::forward-bind-address forward)))
    (is (= 0 (burs::forward-bind-port forward))))
  (let ((forward (burs::parse-remote-forward "[::1]:8080:[::2]:80")))
    (is (equal "::1" (burs::forward-bind-address forward)))
    (is (equal "::2" (burs::forward-host forward)))))

(test config-remote-forward-uses-the-two-word-form
  (let ((forward
          (burs::parse-config-remote-forward "18082 127.0.0.1:22")))
    (is (null (burs::forward-bind-address forward)))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (equal "127.0.0.1" (burs::forward-host forward)))
    (is (= 22 (burs::forward-port forward))))
  (let ((forward
          (burs::parse-config-remote-forward "127.0.0.1:18082 127.0.0.1:22")))
    (is (equal "127.0.0.1" (burs::forward-bind-address forward)))
    (is (= 18082 (burs::forward-bind-port forward)))
    (is (= 22 (burs::forward-port forward)))))

(test remote-forward-match-accepts-the-address-the-server-names
  (let ((forward (burs::parse-remote-forward "8080:example.org:80")))
    ;; An empty bind address means loopback, and the server may answer with
    ;; the address it resolved or with the one the client wrote.
    (is (burs::remote-forward-match-p forward "127.0.0.1" 8080))
    (is (burs::remote-forward-match-p forward "localhost" 8080))
    (is (not (burs::remote-forward-match-p forward "127.0.0.1" 8081))))
  (let ((forward
          (burs::parse-remote-forward "127.0.0.1:8080:example.org:80")))
    (is (burs::remote-forward-match-p forward "127.0.0.1" 8080))
    (is (not (burs::remote-forward-match-p forward "10.0.0.1" 8080)))))

(test dynamic-forward-specifications-parse
  (let ((forward (burs::parse-dynamic-forward "1080")))
    (is (null (burs::dynamic-forward-bind-address forward)))
    (is (= 1080 (burs::dynamic-forward-bind-port forward))))
  (let ((forward (burs::parse-dynamic-forward "127.0.0.1:1080")))
    (is (equal "127.0.0.1" (burs::dynamic-forward-bind-address forward)))
    (is (= 1080 (burs::dynamic-forward-bind-port forward))))
  (let ((forward (burs::parse-dynamic-forward "*:1080")))
    (is (equal "*" (burs::dynamic-forward-bind-address forward)))
    (is (= 1080 (burs::dynamic-forward-bind-port forward))))
  (let ((forward (burs::parse-dynamic-forward "[::1]:1080")))
    (is (equal "::1" (burs::dynamic-forward-bind-address forward)))
    (is (= 1080 (burs::dynamic-forward-bind-port forward)))))

(test stdio-forward-parses-host-and-port
  (multiple-value-bind (host port)
      (burs::parse-host-port "example.org:2200")
    (is (equal "example.org" host))
    (is (= 2200 port)))
  (multiple-value-bind (host port)
      (burs::parse-host-port "[::1]:22")
    (is (equal "::1" host))
    (is (= 22 port))))

(test command-line-option-maps-the-supported-keywords
  (let ((burs::*options* (empty-options)))
    (burs::command-line-option "Port" "2200")
    (burs::command-line-option "User" "bob")
    (burs::command-line-option "IdentityFile" "/tmp/key")
    (burs::command-line-option "UserKnownHostsFile" "/tmp/known")
    (burs::command-line-option "IdentityAgent" "/tmp/agent")
    (burs::command-line-option "StrictHostKeyChecking" "accept-new")
    (is (eq :accept-new (getf burs::*options* :policy)))
    (burs::command-line-option "StrictHostKeyChecking" "ask")
    (is (eq :ask (getf burs::*options* :policy)))
    (burs::command-line-option "ProxyJump" "bastion")
    (burs::command-line-option "ProxyCommand" "nc %h %p")
    ;; Every other keyword is accepted and ignored.
    (burs::command-line-option "Compression" "yes")
    ;; Forwarding lines stay with the ssh_config resolver; recording them
    ;; here as well would start every -o forward twice.
    (burs::command-line-option "RemoteForward" "/tmp/a /tmp/b")
    (is (null (getf burs::*options* :remote-forward)))
    (is (equal "2200" (getf burs::*options* :port)))
    (is (equal "bob" (getf burs::*options* :user)))
    (is (equal '("/tmp/key") (getf burs::*options* :identity)))
    ;; UserKnownHostsFile stays with the resolver: only it expands ~ and
    ;; understands "none", and a raw value here would override the parsed one.
    (is (null (getf burs::*options* :known-hosts)))
    (is (equal "/tmp/agent" (getf burs::*options* :agent)))
    (is (equal "bastion" (getf burs::*options* :jump)))
    (is (equal "nc %h %p" (getf burs::*options* :proxy-command)))))

(test command-line-options-apply-in-the-written-order
  (let ((burs::*options* (empty-options)))
    (dolist (option '("User=first" "Port=2200" "User=last"))
      (push option (getf burs::*options* :options)))
    (burs::apply-command-line-options)
    ;; Pushed in reverse, so applying them back restores command-line order.
    (is (equal "last" (getf burs::*options* :user)))
    (is (equal "2200" (getf burs::*options* :port)))))

(test join-command-keeps-the-arguments-apart
  (is (equal "uname -a" (burs::join-command '("uname" "-a"))))
  (is (stringp (burs::join-command nil))))

(test request-tty-follows-ssh-policy
  (labels ((request (setting command-given-p)
             (let ((burs::*options* (empty-options)))
               (setf (getf burs::*options* :request-tty) setting)
               (burs::request-tty-p nil command-given-p))))
    ;; -t forces a PTY even when no local terminal will drive it.
    (is (eq t (request :force nil)))
    (is (eq t (request :force t)))
    ;; -T never asks for one, with or without a command.
    (is (eq nil (request :no nil)))
    (is (eq nil (request :no t)))
    ;; RequestTTY=no is the same decision spelled through -o.
    (is (eq nil (request "no" nil)))
    ;; auto is a login session only: a command means no PTY.
    (is (eq nil (request "auto" t)))
    (is (eq nil (request nil t)))))

;;; ---- config hooks ----

(test match-exec-runs-the-condition
  (labels ((evaluate (command)
             (let ((answer :unset))
               (burs::match-exec command
                                 (lambda (value) (setf answer value))
                                 (lambda (condition)
                                   (declare (ignore condition))
                                   (setf answer :error)))
               answer)))
    (is (eq t (evaluate "exit 0")))
    (is (eq nil (evaluate "exit 1")))
    (is (eq t (evaluate "true")))))

(test client-port-reads-the-number-the-command-line-gave
  (let ((burs::*options* (empty-options)))
    (is (null (burs::client-port)))
    (setf (getf burs::*options* :port) "2222")
    (is (= 2222 (burs::client-port)))
    (setf (getf burs::*options* :port) "22x")
    ;; An invalid -p is a usage error; FAIL quits, so only exercise the
    ;; valid paths here and leave the exit to the live command-line tests.
    (is (= 22 (parse-integer "22x" :junk-allowed t)))))

;;; ---- connection multiplexing ----

(test control-master-command-line-flags
  (multiple-value-bind (destination command options)
      (parse '("-M" "-S" "/tmp/cm.sock" "-O" "check" "host.example"))
    (is (equal "host.example" destination))
    (is (null command))
    (is (eq t (getf options :control-master)))
    (is (equal "/tmp/cm.sock" (getf options :control-path)))
    (is (equal "check" (getf options :control-command)))))

(test mux-frame-and-payload-round-trip
  (let ((frame (burs::mux-frame (vector 1 2 3))))
    (is (equalp #(0 0 0 3 1 2 3) frame))
    (is (= 3 (burs::mux-u32 frame 0))))
  (let* ((payload (burs::mux-request-payload
                   burs::+mux-c-new-session+ 7
                   (cons "host" "example.org")
                   2222))
         (reader (cl-pnet-ssh:ssh-make-reader payload 0)))
    (is (= burs::+mux-c-new-session+
           (cl-pnet-ssh:ssh-read-u32 reader)))
    (is (= 7 (cl-pnet-ssh:ssh-read-u32 reader)))
    (is (equal "example.org" (cl-pnet-ssh:ssh-read-text reader)))
    (is (= 2222 (cl-pnet-ssh:ssh-read-u32 reader)))))

#-win32
(test mux-handshake-keeps-the-masters-extension-names
  "The client records the master's extension names and answers with a bare hello."
  (multiple-value-bind (client master)
      (cl-pnet-sockets:make-socketpair)
    (unwind-protect
         (progn
           (burs::mux-write-packet
            master (burs::mux-hello-payload '(("info" . "0")
                                              ("other" . "1"))))
           (is (equal '("info" "other")
                      (burs::mux-handshake client)))
           ;; A client hello carries no extensions, so it is just the type and
           ;; version.
           (let ((reply (burs::mux-read-packet master)))
             (is (= burs::+mux-msg-hello+ (burs::mux-u32 reply 0)))
             (is (= burs::+mux-version+ (burs::mux-u32 reply 4)))
             (is (= 8 (length reply)))))
      (ignore-errors (cl-pnet-sockets:close-open-fd client))
      (ignore-errors (cl-pnet-sockets:close-open-fd master)))))

(test mux-connection-info-message-describes-the-negotiated-connection
  "The master's -O conninfo text reports what the transport negotiated."
  (let ((burs::*client*
          (cl-pnet-ssh::%make-ssh-client
           :host "example.org" :port 22
           :server-version "SSH-2.0-OpenSSH_10.6"
           :negotiated
           (list :kex "mlkem768x25519-sha256"
                 :host-key "ssh-ed25519"
                 :cipher-c2s "chacha20-poly1305@openssh.com"
                 :cipher-s2c "chacha20-poly1305@openssh.com"
                 :mac-c2s "hmac-sha2-256"
                 :mac-s2c "hmac-sha2-256"
                 :compression-c2s "none"
                 :compression-s2c "none"))))
    (let ((text (burs::mux-connection-info-message nil)))
      (is (not (null (search "Connection information for " text))))
      (is (not (null (search "  versions cl-pnet-ssh_" text))))
      (is (not (null (search " -> SSH-2.0-OpenSSH_10.6" text))))
      (is (not (null (search "  duration " text))))
      (is (not (null (search "  kexalgorithm mlkem768x25519-sha256" text))))
      (is (not (null (search "  hostkeyalgorithm ssh-ed25519" text))))
      (is (not (null (search "  cipher chacha20-poly1305@openssh.com" text))))
      ;; chacha20-poly1305 authenticates itself, as OpenSSH's <implicit> says.
      (is (not (null (search "  mac <implicit>" text))))
      (is (not (null (search "  compression none" text))))
      (is (not (null (search "  rekey limit none interval none" text))))
      (is (char= #\Return (char text (- (length text) 2)))))))

(test mux-channel-open-message-lists-open-sessions
  "The master's -O channels text names each open multiplexed session."
  (let* ((master (burs::%make-mux-master))
         (session (burs::%make-mux-session
                   :sid 1 :remote-name "echo hi" :opened t)))
    (setf (burs::mux-master-sessions master) (list session))
    (let ((text (burs::mux-channel-open-message master)))
      (is (not (null (search "The following connections are open:" text))))
      (is (not (null (search "  #1 echo hi (open)" text)))))))

(test mux-expands-control-path-tokens
  (is (equal "/tmp/cm-alice@203.0.113.7-2222"
             (burs::mux-expand-control-path
              "/tmp/cm-%r@%h-%p"
              :original "alias" :hostname "203.0.113.7"
              :port 2222 :user "alice")))
  (is (equal "alias-100%"
             (burs::mux-expand-control-path
              "%n-100%%" :original "alias")))
  ;; %C is the SHA1 connection hash, so it is forty lowercase hex digits.
  (let ((expanded (burs::mux-expand-control-path
                   "%C" :original "alias" :hostname "203.0.113.7"
                   :port 2222 :user "alice")))
    (is (= 40 (length expanded)))
    (is (every (lambda (character)
                 (find character "0123456789abcdef"))
               expanded)))
  ;; Unknown tokens are left alone rather than silently swallowed.
  (is (equal "%z" (burs::mux-expand-control-path
                   "%z" :original "alias"))))

(test mux-expands-a-leading-tilde
  (let ((home (uiop:getenv "HOME"))
        (missing (burs::mux-tilde-expand "~definitely-no-such-user/x")))
    (is (string= (concatenate 'string home "/.ssh/cm")
                 (burs::mux-tilde-expand "~/.ssh/cm")))
    (is (string= home (burs::mux-tilde-expand "~")))
    (is (equal "relative/socket"
               (burs::mux-tilde-expand "relative/socket")))
    (is (equal "~definitely-no-such-user/x" missing))))

(test mux-forward-plists-describe-every-forward
  (let ((burs::*options* (empty-options))
        (local (burs::%make-forward :bind-address "127.0.0.1"
                                    :bind-port 8080
                                    :host "target.example" :port 80))
        (remote (burs::%make-forward :bind-port 9000
                                     :host "elsewhere.example" :port 25))
        (dynamic (burs::%make-dynamic-forward
                  :bind-address "127.0.0.1" :bind-port 1080)))
    (setf (getf burs::*options* :local-forward) (list local)
          (getf burs::*options* :remote-forward) (list remote)
          (getf burs::*options* :dynamic-forward) (list dynamic))
    (let ((specs (burs::mux-forward-plists)))
      (is (= 3 (length specs)))
      (let ((first (first specs))
            (second (second specs))
            (third (third specs)))
        (is (= burs::+mux-fwd-local+ (getf first :type)))
        (is (equal "127.0.0.1" (getf first :listen-host)))
        (is (= 8080 (getf first :listen-port)))
        (is (equal "target.example" (getf first :connect-host)))
        (is (= 80 (getf first :connect-port)))
        (is (= burs::+mux-fwd-remote+ (getf second :type)))
        (is (equal "elsewhere.example" (getf second :connect-host)))
        (is (= burs::+mux-fwd-dynamic+ (getf third :type)))
        (is (= 1080 (getf third :listen-port)))
        (is (equal "" (getf third :connect-host)))))))

(test mux-config-forward-plists-parse-file-lines
  (let* ((options
           (cl-pnet-ssh::%make-ssh-config-options
            :local-forwards '("8080 target.example:80")
            :remote-forwards '("9000 elsewhere.example:25")
            :dynamic-forwards '("127.0.0.1:1080")))
         (specs (burs::mux-config-forward-plists options)))
    (is (= 3 (length specs)))
    (is (= burs::+mux-fwd-local+ (getf (first specs) :type)))
    (is (= 8080 (getf (first specs) :listen-port)))
    (is (equal "target.example" (getf (first specs) :connect-host)))
    (is (= burs::+mux-fwd-remote+ (getf (second specs) :type)))
    (is (= 9000 (getf (second specs) :listen-port)))
    (is (= burs::+mux-fwd-dynamic+ (getf (third specs) :type)))
    (is (= 1080 (getf (third specs) :listen-port))))
  (is (null (burs::mux-config-forward-plists nil))))

;;; ---- version ----

(test version-constant-matches-the-system-definition
  "The version BURS reports must be the version the system file declares."
  (is (equal (asdf:component-version (asdf:find-system "bursyk-client"))
             burs::+burs-version+)))

;;; ---- ObscureKeystrokeTiming ----

(test obscure-keystroke-timing-interval
  "The obfuscation applies only to the channel that asked for a pty, and only
while the interval is positive."
  (let ((client (cl-pnet-ssh::%make-ssh-client
                 :obscure-keystroke-timing 50))
        (burs::*client* nil)
        (burs::*pty-channel* nil))
    (setf burs::*client* client
          burs::*pty-channel* :pty)
    (is (= 50 (burs::keystroke-obfuscation-interval :pty)))
    (is (null (burs::keystroke-obfuscation-interval :other)))
    (setf (cl-pnet-ssh:ssh-client-obscure-keystroke-timing client) 0)
    (is (null (burs::keystroke-obfuscation-interval :pty)))
    (setf burs::*pty-channel* nil)
    (is (null (burs::keystroke-obfuscation-interval :pty)))))

(test obscure-keystroke-delay-stays-in-fuzz-range
  "A quantised interval is the requested one, less up to ten percent, plus
this session's fixed offset."
  (dotimes (index 20)
    (declare (ignore index))
    (let ((delay (burs::keystroke-delay 20 0.002)))
      (is (<= 0.0199 delay))
      (is (< delay 0.022))))
  (is (= 20 cl-pnet-ssh:+ssh-keystroke-default-interval-ms+)))

;;; ---- -G output ----

(test command-line-source-binding-reaches-config
  "A dedicated -b or -B becomes a config line, so resolution and -G both
see the source that will actually be used."
  (let ((burs::*options* (empty-options)))
    (setf (getf burs::*options* :bind-address) "127.0.0.2"
          (getf burs::*options* :bind-interface) "eth0")
    (let ((lines (burs::resolver-option-list)))
      (is (member "BindAddress 127.0.0.2" lines :test #'equal))
      (is (member "BindInterface eth0" lines :test #'equal)))))

(test command-line-address-family-reaches-config
  "-4, -6 and --address-family become an AddressFamily line, so resolution
and -G both see the family that will be dialled; no flag leaves the file
alone."
  (flet ((lines (family)
           (let ((burs::*options* (empty-options)))
             (setf (getf burs::*options* :address-family) family)
             (burs::resolver-option-list))))
    (is (member "AddressFamily inet" (lines "inet") :test #'equal))
    (is (member "AddressFamily inet6" (lines "inet6") :test #'equal))
    (is (member "AddressFamily any" (lines "any") :test #'equal))
    (is (notany (lambda (line)
                  (search "AddressFamily" line :test #'char-equal))
                (lines nil)))))

(test command-line-agent-forwarding-reaches-config
  "-A and -a outrank the file and -o through the same first-value rule the
other dedicated flags use; neither flag leaves the config alone."
  (flet ((lines (option)
           (let ((burs::*options* (empty-options)))
             (setf (getf burs::*options* :forward-agent) option)
             (burs::resolver-option-list))))
    (is (member "ForwardAgent yes" (lines t) :test #'equal))
    (is (member "ForwardAgent no" (lines :no) :test #'equal))
    (is (notany (lambda (line)
                  (search "ForwardAgent" line :test #'char-equal))
                (lines nil)))))

(test command-line-compression-reaches-config
  "-C becomes a Compression yes line, so resolution and -G both see the
request; no flag leaves the file alone."
  (flet ((lines (option)
           (let ((burs::*options* (empty-options)))
             (setf (getf burs::*options* :compression) option)
             (burs::resolver-option-list))))
    (is (member "Compression yes" (lines t) :test #'equal))
    (is (notany (lambda (line)
                  (search "Compression" line :test #'char-equal))
                (lines nil)))))

(test print-config-reports-a-forward-agent-socket-path
  "ForwardAgent's path form is printed as the path, as ssh -G does, while
-a still reports no even when the file named a socket."
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "ForwardAgent /run/user/1000/agent.sock"))))
         (options nil))
    (cl-pnet-ssh:ssh-config-resolve
     config "agent.example"
     :on-options (lambda (value) (setf options value)))
    (let ((burs::*options* (empty-options)))
      (is (search "forwardagent /run/user/1000/agent.sock"
                  (with-output-to-string (*standard-output*)
                    (burs::print-config-options "agent.example" options nil)))))
    (let ((burs::*options* (empty-options)))
      (setf (getf burs::*options* :forward-agent) :no)
      (is (search "forwardagent no"
                  (with-output-to-string (*standard-output*)
                    (burs::print-config-options "agent.example" options nil)))))))

(test password-prompts-read-a-line-and-report-end-of-input
  ;; A closed stdin means the user cancelled: NIL, not an empty password.
  (let ((*standard-input* (make-string-input-stream (format nil "secret~%")))
        (*error-output* (make-string-output-stream)))
    (is (equal "secret" (burs::read-prompt-line "Password: ")))
    (is (equal "Password: " (get-output-stream-string *error-output*))))
  (let ((*standard-input* (make-string-input-stream ""))
        (*error-output* (make-string-output-stream)))
    (is (null (burs::read-prompt-line "Password: ")))))

(test keyboard-interactive-prompts-show-the-server-text-and-read-answers
  (let ((*standard-input* (make-string-input-stream
                           (format nil "one~%two~%")))
        (*error-output* (make-string-output-stream)))
    (is (equal '("one" "two")
               (burs::read-keyboard-interactive-answers
                "Fixture" "Answer carefully"
                '(("First: " t) ("Second: " t)))))
    (let ((text (get-output-stream-string *error-output*)))
      (dolist (expected '("Fixture" "Answer carefully" "First: " "Second: "))
        (is (search expected text) expected))))
  ;; Input that ends before the last prompt cancels the exchange.
  (let ((*standard-input* (make-string-input-stream (format nil "one~%")))
        (*error-output* (make-string-output-stream)))
    (is (null (burs::read-keyboard-interactive-answers
               nil nil '(("First: " t) ("Second: " t)))))))

(test print-config-reports-openssh-defaults
  "The lines ssh -G always prints appear even when nothing configured them,
and ProxyJump/ProxyCommand stay off the output when unset."
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line "Port 22"))))
         (options nil))
    (cl-pnet-ssh:ssh-config-resolve
     config "alias.example"
     :on-options (lambda (value) (setf options value)))
    (let ((burs::*options* (empty-options))
          (text (with-output-to-string (*standard-output*)
                  (burs::print-config-options
                   "alias.example" options nil))))
      (dolist (line (list "canonicaldomains none"
                          (format nil "globalknownhostsfile ~{~A~^ ~}"
                                  cl-pnet-ssh::+ssh-default-global-known-hosts+)
                          (format nil "userknownhostsfile ~{~A~^ ~}"
                                  (mapcar
                                   #'namestring
                                   (cl-pnet-ssh::ssh-default-user-known-hosts)))
                          "revokedhostkeys none"
                          "logverbose none"
                          "channeltimeout none"
                          "permitremoteopen any"
                          "addkeystoagent false"
                          "forwardagent no"
                          "connecttimeout none"
                          "tunneldevice any:any"
                          "canonicalizepermittedcnames none"
                          "controlpersist no"
                          "rekeylimit 0 0"
                          "streamlocalbindmask 0177"
                          "syslogfacility USER"
                          "compression no"
                          "stricthostkeychecking ask"
                          "identitiesonly no"
                          "kbdinteractiveauthentication yes"
                          "passwordauthentication yes"
                          "proxyusefdpass no"
                          "pubkeyauthentication true"
                          "tcpkeepalive true"
                          "updatehostkeys true"
                          "numberofpasswordprompts 3"
                          "serveralivecountmax 3"
                          "serveraliveinterval 0"
                          "ipqos ef cs0"))
        (is (search line text) line))
      ;; OpenSSH's default PK_ALG lists certificate names before the plain
      ;; keys they certify, for both user and hostbased authentication.
      (is (search "pubkeyacceptedalgorithms ssh-ed25519-cert-v01@openssh.com,"
                  text))
      (is (search "hostbasedacceptedalgorithms ssh-ed25519-cert-v01@openssh.com,"
                  text))
      ;; RSA appears under both RFC 8332 names, SHA-512 first, for the
      ;; certificate and the plain key alike.
      (is (search (concatenate 'string
                               "rsa-sha2-512-cert-v01@openssh.com,"
                               "rsa-sha2-256-cert-v01@openssh.com,")
                  text))
      (is (search "rsa-sha2-512,rsa-sha2-256" text))
      ;; The composite ML-DSA key follows the RSA names in the signature
      ;; lists, and only a transport that implements it advertises it.
      (let ((mldsa (cl-pnet-ssh:ssh-client-feature-supported-p :mldsa)))
        (is (eq mldsa
                (not (null (search "ssh-mldsa44-ed25519-cert" text)))))
        (is (eq mldsa
                (not (null (search "rsa-sha2-256,ssh-mldsa44-ed25519"
                                   text))))))
      (is (search "identityfile" text))
      (is (not (search "proxyjump" text)))
      (is (not (search "proxycommand" text))))))

(test print-config-reports-configured-values
  "Values from the file are printed the way OpenSSH spells them."
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "PasswordAuthentication no")
                  (cl-pnet-ssh::ssh-config-option-line
                   "KbdInteractiveAuthentication no")
                  (cl-pnet-ssh::ssh-config-option-line
                   "ServerAliveInterval 30")
                  (cl-pnet-ssh::ssh-config-option-line
                   "ServerAliveCountMax 5")
                  (cl-pnet-ssh::ssh-config-option-line
                   "NumberOfPasswordPrompts 1")
                  (cl-pnet-ssh::ssh-config-option-line
                   "Tag work")
                  (cl-pnet-ssh::ssh-config-option-line
                   "PermitRemoteOpen host:22")
                  (cl-pnet-ssh::ssh-config-option-line
                   "BindAddress 127.0.0.2")
                  (cl-pnet-ssh::ssh-config-option-line
                   "BindInterface eth0")
                  (cl-pnet-ssh::ssh-config-option-line
                   "ProxyCommand nc %h %p")
                  (cl-pnet-ssh::ssh-config-option-line
                   "ProxyUseFdpass yes")
                  (cl-pnet-ssh::ssh-config-option-line
                   "UpdateHostKeys ask"))))
         (options nil))
    (cl-pnet-ssh:ssh-config-resolve
     config "alias.example"
     :on-options (lambda (value) (setf options value)))
    (let ((burs::*options* (empty-options))
          (text (with-output-to-string (*standard-output*)
                  (burs::print-config-options
                   "alias.example" options nil))))
      (dolist (line '("passwordauthentication no"
                      "kbdinteractiveauthentication no"
                      "bindaddress 127.0.0.2"
                      "bindinterface eth0"
                      "serveraliveinterval 30"
                      "serveralivecountmax 5"
                      "numberofpasswordprompts 1"
                      "tag work"
                      "permitremoteopen host:22"
                      "proxycommand nc %h %p"
                      "proxyusefdpass yes"
                      "updatehostkeys ask"))
        (is (search line text) line)))))

;;; ---- ssh -Z ----

(defun dump-key-blob (&optional (fill 7))
  "A syntactically valid ssh-ed25519 public key blob for -Z tests."
  (let ((writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-string writer
                                  (cl-pnet-ssh:ssh-string-octets "ssh-ed25519"))
    (cl-pnet-ssh:ssh-write-string
     writer (make-array 32 :element-type '(unsigned-byte 8)
                           :initial-element fill))
    (cl-pnet-ssh:ssh-writer-output writer)))

(defun dump-certificate-blob ()
  "A blob whose type marks it as a certificate, for ordering tests."
  (let ((writer (cl-pnet-ssh:ssh-writer)))
    (cl-pnet-ssh:ssh-write-string
     writer
     (cl-pnet-ssh:ssh-string-octets
      "ssh-ed25519-cert-v01@openssh.com"))
    (cl-pnet-ssh:ssh-write-string
     writer (make-array 32 :element-type '(unsigned-byte 8)
                           :initial-element 9))
    (cl-pnet-ssh:ssh-writer-output writer)))

(defun write-public-key (path blob)
  "Write BLOB to PATH in authorized_keys format."
  (ensure-directories-exist path)
  (with-open-file (stream path :direction :output :if-exists :supersede
                               :if-does-not-exist :create)
    (format stream "ssh-ed25519 ~A test~%"
            (cl-pnet-ssh:ssh-octets-base64 blob)))
  path)

(defmacro with-dump-directory ((variable) &body body)
  "Bind VARIABLE to a fresh temporary directory, removing it afterwards."
  `(let ((,variable
           (merge-pathnames
            (format nil "burs-z-~D-~D/" (get-universal-time)
                    (random 1000000))
            (uiop:temporary-directory))))
     (ensure-directories-exist ,variable)
     (unwind-protect (progn ,@body)
       (ignore-errors
         (uiop:delete-directory-tree ,variable :validate t)))))

(defun dump-lines (host)
  "The ssh -Z output for HOST under the current *OPTIONS*."
  (with-output-to-string (stream)
    (burs::dump-public-key-identities host stream)))

(test dump-public-key-line-matches-format-identity
  (let ((blob (dump-key-blob)))
    (is (equal
         (format nil "~A ED25519 ~A explicit~%"
                 "/k" (cl-pnet-ssh:ssh-key-fingerprint blob))
         (with-output-to-string (stream)
           (burs::dump-public-key-line stream "/k" blob 1 nil))))
    (is (equal
         (format nil "~A ED25519 ~A~%"
                 "/k" (cl-pnet-ssh:ssh-key-fingerprint blob))
         (with-output-to-string (stream)
           (burs::dump-public-key-line stream "/k" blob 0 nil))))
    ;; A file that could not be read keeps the separator but no type or
    ;; fingerprint, exactly as format_identity writes it.
    (is (equal (format nil "/k  explicit~%")
               (with-output-to-string (stream)
                 (burs::dump-public-key-line stream "/k" nil 1 nil))))
    (is (equal (format nil "/k ~%")
               (with-output-to-string (stream)
                 (burs::dump-public-key-line stream "/k" nil 0 nil))))
    (is (equal
         (format nil "~A ED25519 ~A agent~%"
                 "/k" (cl-pnet-ssh:ssh-key-fingerprint blob))
         (with-output-to-string (stream)
           (burs::dump-public-key-line stream "/k" blob 0 t))))))

(test dump-sort-identities-keeps-explicit-entries-in-place
  (let* ((plain-a (list "a" (dump-key-blob 1) 0))
         (plain-b (list "b" (dump-key-blob 2) 0))
         (cert (list "c" (dump-certificate-blob) 0))
         (explicit (list "e" (dump-key-blob 3) 1))
         (sorted (burs::dump-sort-identities
                  (list plain-a explicit plain-b cert))))
    ;; Certificates sort before plain keys, and the explicit key does not
    ;; move, so it stays between the two slots the others fill.
    (is (equal '("c" "e" "a" "b")
               (mapcar #'first sorted)))))

(test dump-public-key-identities-reads-config-identities
  (with-dump-directory (directory)
    (let* ((present (merge-pathnames "id_ed25519" directory))
           (missing (merge-pathnames "gone" directory))
           (config (merge-pathnames "config" directory))
           (blob (dump-key-blob)))
      (write-public-key (merge-pathnames "id_ed25519.pub" directory) blob)
      (with-open-file (stream config :direction :output :if-exists :supersede
                                     :if-does-not-exist :create)
        (format stream "IdentityFile ~A~%IdentityFile ~A~%"
                (namestring present) (namestring missing)))
      (let ((burs::*options* (empty-options)))
        (setf (getf burs::*options* :config) (namestring config))
        (let ((text (dump-lines "example.org")))
          (is (search (format nil "~A ED25519 ~A explicit~%"
                              (namestring present)
                              (cl-pnet-ssh:ssh-key-fingerprint blob))
                      text))
          ;; A missing configured identity is still listed, with an empty
          ;; type and fingerprint.
          (is (search (format nil "~A  explicit~%" (namestring missing))
                      text))
          (is (= 2 (count #\Newline text))))))))

(test dump-public-key-identities-drops-a-missing-i-path
  (let ((burs::*options* (empty-options)))
    (setf (getf burs::*options* :config) "none"
          (getf burs::*options* :identity-arguments)
          (list "/definitely/not/here"))
    (let ((text (dump-lines "example.org")))
      ;; ssh's option parser drops a -i path that does not exist, so the
      ;; default names are offered instead.
      (is (not (search "/definitely/not/here" text)))
      (is (search "id_rsa" text))
      (is (not (search "explicit" text))))))

(test dump-public-key-identities-keeps-i-and-config-duplicates
  (with-dump-directory (directory)
    (let* ((path (merge-pathnames "id_ed25519" directory))
           (config (merge-pathnames "config" directory))
           (blob (dump-key-blob)))
      (write-public-key (merge-pathnames "id_ed25519.pub" directory) blob)
      ;; -i is kept only when the named path itself exists, even though the
      ;; public half is what gets read.
      (with-open-file (stream path :direction :output :if-exists :supersede
                                   :if-does-not-exist :create)
        (write-line "placeholder" stream))
      (with-open-file (stream config :direction :output :if-exists :supersede
                                     :if-does-not-exist :create)
        (format stream "IdentityFile ~A~%" (namestring path)))
      (let ((burs::*options* (empty-options)))
        (setf (getf burs::*options* :config) (namestring config)
              (getf burs::*options* :identity-arguments)
              (list (namestring path)))
        ;; -i records userprovided 1 and a config file 2, so readconf keeps
        ;; both copies rather than collapsing them.
        (is (= 2 (count #\Newline (dump-lines "example.org"))))))))

;;; ---- Child processes and the signal mask ----

(test child-waits-with-deferrable-signals-unblocked
  "A child wait does not abort SBCL when a deferrable signal is blocked.

The puma backend blocks SIGWINCH so its signalfd sees terminal resizes, and
SBCL refuses to serve events while a deferrable signal is blocked.  Running
STTY or a LocalCommand in that state used to kill the client instead of
returning; the helper unblocks the signal for the child and restores the
mask afterwards."
  #-sbcl (skip "SBCL-only signal mask")
  #+sbcl
  (let ((handle (handler-case
                    (cl-pnet:signal-start sb-unix:sigwinch (lambda () nil))
                  (error () nil))))
    (unwind-protect
         (is (eql 0
                  (nth-value
                   2
                   (burs::call-with-deferrable-signals-unblocked
                    (lambda ()
                      (uiop:run-program '("/bin/sh" "-c" "exit 0")
                                        :ignore-error-status t))))))
      (when handle
        (ignore-errors (cl-pnet:signal-stop handle))))))

