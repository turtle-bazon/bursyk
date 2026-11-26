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

(test split-destination-splits-at-the-last-at-sign
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
    (is (equal "example.org" host))
    (is (equal "a@b" user))))

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
  (let* ((kex (burs::query-answer "kex"))
         (mlkem (cl-pnet-ssh:ssh-client-feature-supported-p :mlkem))
         (sntrup (cl-pnet-ssh:ssh-client-feature-supported-p :sntrup)))
    (is (eq (cl-pnet-ssh:ssh-client-feature-supported-p :post-quantum-kex)
            (or mlkem sntrup)))
    (is (eq mlkem
            (not (null (member "mlkem768x25519-sha256" kex
                               :test #'string=)))))
    (is (member "curve25519-sha256" kex :test #'string=))
    (is (eq mlkem
            (not (null (member "mlkem768x25519-sha256"
                               (burs::supported-kex-algorithms)
                               :test #'string=)))))
    ;; The P-256 ML-KEM hybrid is implemented too, and -Q lists every method
    ;; the transport can negotiate, not just the default offer.
    (is (eq mlkem
            (not (null (member "mlkem768nistp256-sha256" kex
                               :test #'string=)))))
    (is (eq mlkem
            (not (null (member "mlkem768nistp256-sha256"
                               (burs::supported-kex-algorithms)
                               :test #'string=)))))
    ;; sntrup761 is its own family; a transport may learn ML-KEM without it.
    (dolist (name '("sntrup761x25519-sha512"
                    "sntrup761x25519-sha512@openssh.com"))
      (is (eq sntrup
              (not (null (member name kex :test #'string=)))))
      (is (eq sntrup
              (not (null (member name (burs::default-kex-algorithms)
                                 :test #'string=))))))
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
    ;; ssh restarts its option scan after the destination, so a flag written
    ;; before the remote command's first word is still an ssh flag.
    (is (null command))
    (is (= 2 (getf options :verbose)))
    (is (eq :no (getf options :request-tty)))
    (is (equal "2222" (getf options :port)))))

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
    ;; As in ssh, one -t asks for a tty (REQUEST_TTY_YES) and a second one
    ;; forces it (REQUEST_TTY_FORCE).
    (is (eq :yes (getf options :request-tty))))
  (multiple-value-bind (destination command options)
      (parse '("-tt" "host"))
    (declare (ignore destination command))
    (is (eq :force (getf options :request-tty))))
  (multiple-value-bind (destination command options)
      (parse '("-T" "host"))
    (declare (ignore destination command))
    (is (eq :no (getf options :request-tty))))
  (multiple-value-bind (destination command options)
      (parse '("--request-tty=no" "host"))
    (declare (ignore destination command))
    (is (eq :no (getf options :request-tty)))))

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
    (setf (cl-pnet-ssh:ssh-client-config-options client)
          (cl-pnet-ssh::%make-ssh-config-options
           :port 2200 :user "bob"))
    (is (equal "real.example 2200 bob alias %"
               (burs::expand-remote-command client "%h %p %r %n %%")))
    ;; %k falls back to the alias and %j is empty without a jump host.
    (is (equal "alias "
               (burs::expand-remote-command client "%k %j")))))

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
    (let ((permit '(("example.org:80" "example.org" 80))))
      (is (allowed permit "example.org" 80))
      (is (not (allowed permit "example.org" 81)))
      (is (not (allowed permit "other.example" 80)))
      ;; A streamlocal path only matches a port wildcard.
      (is (not (allowed permit "/tmp/sock" :streamlocal))))
    (let ((permit '(("example.org:80" "example.org" 80) ("*:*" "*" :any))))
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
  "A distribution's stock ssh_config sets GSSAPIAuthentication yes.  This
build has no GSSAPI, so the parser reports the line as unsupported, as
readconf does, but it configures nothing and must not stop the client from
falling through to publickey."
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "GSSAPIAuthentication yes"))))
         (options nil)
         (client (cl-pnet-ssh::%make-ssh-client)))
    (cl-pnet-ssh:ssh-config-resolve
     config "alias.example"
     :on-options (lambda (value) (setf options value)))
    (setf (cl-pnet-ssh:ssh-client-config-options client) options)
    (let ((burs::*options* (empty-options)))
      (is (null (burs::check-config-supported client))))))

(test gssapi-flags-are-accepted-and-ignored
  "ssh accepts -K and -k even when built without GSSAPI; they only switch on
a method that does not exist, so they cannot refuse the connection."
  (dolist (flag '("-K" "-k"))
    (multiple-value-bind (destination command options)
        (parse (list flag "host.example"))
      (declare (ignore destination command))
      (let ((burs::*options* options))
        (is (null (burs::check-supported-options)) flag)))))

(test print-config-omits-gssapi-options
  "-G prints a GSSAPI build's two lines only when it has GSSAPI; with none
compiled in, an ssh_config that sets them is reported while resolving and
the lines never reach the output."
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "GSSAPIAuthentication yes")
                  (cl-pnet-ssh::ssh-config-option-line
                   "GSSAPIDelegateCredentials yes"))))
         (options nil))
    (cl-pnet-ssh:ssh-config-resolve
     config "alias.example"
     :on-options (lambda (value) (setf options value)))
    (let ((burs::*options* (empty-options))
          (text (with-output-to-string (*standard-output*)
                  (burs::print-config-options "alias.example" options nil))))
      (is (not (search "gssapi" text))))))

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
    (is (= 1080 (burs::dynamic-forward-bind-port forward))))
  ;; A socket path listens locally as a streamlocal SOCKS proxy.
  (let ((forward (burs::parse-dynamic-forward "/tmp/d.sock")))
    (is (equal "/tmp/d.sock" (burs::dynamic-forward-bind-path forward)))
    (is (null (burs::dynamic-forward-bind-port forward)))))

(test remote-dynamic-forward-specifications-parse
  ;; A one-word -R is the dynamic form: the server listens and the client
  ;; speaks SOCKS, which readconf records as the "socks" target on port 0.
  (let ((forward (burs::parse-remote-forward "8080")))
    (is (= 8080 (burs::forward-bind-port forward)))
    (is (equal "socks" (burs::forward-host forward)))
    (is (= 0 (burs::forward-port forward))))
  (let ((forward (burs::parse-remote-forward "/tmp/r.sock")))
    (is (equal "/tmp/r.sock" (burs::forward-bind-path forward)))
    (is (equal "socks" (burs::forward-host forward))))
  ;; ssh retries a two-field -R with dynamicfwd=1.
  (let ((forward (burs::parse-remote-forward "8080:1080")))
    (is (equal "8080" (burs::forward-bind-address forward)))
    (is (= 1080 (burs::forward-bind-port forward)))
    (is (equal "socks" (burs::forward-host forward))))
  ;; a2port falls back to the TCP services database.
  (let ((forward (burs::parse-remote-forward "8080:socks")))
    (is (= 1080 (burs::forward-bind-port forward)))
    (is (equal "socks" (burs::forward-host forward))))
  ;; The same one-word form in a configuration file or an -o line.
  (let ((forward (burs::parse-config-remote-forward "8080")))
    (is (= 8080 (burs::forward-bind-port forward)))
    (is (equal "socks" (burs::forward-host forward))))
  (let ((forward (burs::parse-config-remote-forward "8080:1080")))
    (is (equal "8080" (burs::forward-bind-address forward)))
    (is (equal "socks" (burs::forward-host forward))))
  ;; A three-field configuration line stays invalid: readconf treats the
  ;; single word as the dynamic form, which takes at most two fields.
  (is (null (cl-pnet-ssh::ssh-config-forwarding-valid-p
             "8080:localhost:80" t t))))

(test forwarding-service-ports-match-a2port
  (let ((forward (burs::parse-local-forward "8080:localhost:http")))
    (is (= 80 (burs::forward-port forward))))
  (let ((forward (burs::parse-local-forward "http:localhost:80")))
    (is (= 80 (burs::forward-bind-port forward)))))

(test dynamic-forward-field-rules-match-parse-forward
  ;; A two-field dynamic specification always treats its first field as the
  ;; listening address, even when that field contains a slash.
  (let ((forward (burs::parse-dynamic-forward "/home/turtle:8080")))
    (is (equal "/home/turtle" (burs::dynamic-forward-bind-address forward)))
    (is (= 8080 (burs::dynamic-forward-bind-port forward)))
    (is (null (burs::dynamic-forward-bind-path forward))))
  (let ((forward (burs::parse-dynamic-forward ":8080")))
    (is (equal "" (burs::dynamic-forward-bind-address forward)))
    (is (= 8080 (burs::dynamic-forward-bind-port forward))))
  ;; A socket target keeps the local array entry: the dump prints both the
  ;; dynamic forward and the local one readconf derives from it.
  (let ((forward (burs::parse-dynamic-forward "8080:/tmp/x")))
    (is (= 8080 (burs::dynamic-forward-bind-port forward)))
    (is (equal "/tmp/x" (burs::dynamic-forward-target-path forward))))
  (let ((forward (burs::parse-dynamic-forward "/a:/b")))
    (is (equal "/a" (burs::dynamic-forward-bind-path forward)))
    (is (equal "/b" (burs::dynamic-forward-target-path forward))))
  ;; parse_forward's dynamic branch accepts one or two fields only; the
  ;; library's validator is the non-exiting way to check that boundary.
  (dolist (spec '("1:2:3" "1:2:3:4" "0" "127.0.0.1:0" "65536"))
    (is (null (cl-pnet-ssh::ssh-config-forwarding-valid-p spec t nil))
        spec))
  (dolist (spec '("8080" "65535" "/tmp/d.sock" "[::1]:1080" "8080:/tmp/x"
                  "/a:/b" ":8080"))
    (is (cl-pnet-ssh::ssh-config-forwarding-valid-p spec t nil)
        spec)))

(test forward-specifications-expand-environment-variables
  ;; parse_forward runs dollar_expand before it classifies the fields.
  (is (equal (format nil "~A/s" (uiop:getenv "HOME"))
             (burs::dynamic-forward-bind-path
              (burs::parse-dynamic-forward "${HOME}/s"))))
  (let ((forward (burs::parse-local-forward "a${HOME}b:/tmp/x")))
    (is (equal (format nil "a~Ab" (uiop:getenv "HOME"))
               (burs::forward-bind-path forward)))
    (is (equal "/tmp/x" (burs::forward-target-path forward)))))

(test forward-dump-endpoints-match-readconf
  (is (equal "[localhost]:80"
             (burs::dump-forward-endpoint "localhost" 80 nil)))
  (is (equal "80" (burs::dump-forward-endpoint nil 80 nil)))
  (is (equal "/tmp/x"
             (burs::dump-forward-endpoint nil nil "/tmp/x"))))

(test tunnel-device-parses-without-a-configuration-line
  ;; -w is validated like a2tun before -G prints anything, so the same
  ;; reader has to work without a line to blame.
  (is (equal '(4 . 5) (cl-pnet-ssh::ssh-config-tunnel-device nil "4:5")))
  (is (equal '(4 . :any) (cl-pnet-ssh::ssh-config-tunnel-device nil "4")))
  (is (equal '(:any . :any)
             (cl-pnet-ssh::ssh-config-tunnel-device nil "any:any")))
  (is (typep (handler-case
                 (progn (cl-pnet-ssh::ssh-config-tunnel-device nil "x:y") nil)
               (cl-pnet-ssh:ssh-config-error (condition) condition))
             'cl-pnet-ssh:ssh-config-error)))

(test stdio-forward-parses-host-and-port
  (multiple-value-bind (host port)
      (burs::parse-host-port "example.org:2200")
    (is (equal "example.org" host))
    (is (= 2200 port)))
  (multiple-value-bind (host port)
      (burs::parse-host-port "[::1]:22")
    (is (equal "::1" host))
    (is (= 22 port))))

(test stdio-forward-recognises-a-socket-path
  "ssh reads -W with parse_forward(dynamicfwd=1), so a one-field socket path
is a direct-streamlocal target while host:port stays a TCP destination."
  (multiple-value-bind (host port streamlocal)
      (burs::parse-stdio-forward "/tmp/agent.sock")
    (is (equal "/tmp/agent.sock" host))
    (is (not (null streamlocal))))
  (multiple-value-bind (host port streamlocal)
      (burs::parse-stdio-forward "example.org:2200")
    (is (equal "example.org" host))
    (is (= 2200 port))
    (is (not streamlocal)))
  (multiple-value-bind (host port streamlocal)
      (burs::parse-stdio-forward "[::1]:22")
    (is (equal "::1" host))
    (is (= 22 port))
    (is (not streamlocal)))
  ;; Two fields where both name sockets use the listening path, exactly as
  ;; ssh.c copies fwd.listen_path.
  (multiple-value-bind (host port streamlocal)
      (burs::parse-stdio-forward "/tmp/a.sock:/tmp/b.sock")
    (is (equal "/tmp/a.sock" host))
    (is (not (null streamlocal)))))

(test stdio-forward-expands-the-environment-before-parsing
  (let ((old (uiop:getenv "BURS_TEST_DIR")))
    (unwind-protect
         (progn
           (setf (uiop:getenv "BURS_TEST_DIR") "/tmp")
           (multiple-value-bind (host port streamlocal)
               (burs::parse-stdio-forward "${BURS_TEST_DIR}/agent.sock")
             (is (equal "/tmp/agent.sock" host))
             (is (not (null streamlocal)))))
      (setf (uiop:getenv "BURS_TEST_DIR") (or old "")))))

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
    ;; User and Port are left to the ssh_config resolver, which validates
    ;; them like readconf and keeps the first value the command line gave.
    (is (null (getf burs::*options* :port)))
    (is (null (getf burs::*options* :user)))
    ;; IdentityFile also stays with the resolver: readconf keeps the spelling
    ;; as written, so -G can print it unchanged, and expands it only when the
    ;; file is loaded.
    (is (null (getf burs::*options* :identity)))
    ;; UserKnownHostsFile stays with the resolver: only it expands ~ and
    ;; understands "none", and a raw value here would override the parsed one.
    (is (null (getf burs::*options* :known-hosts)))
    (is (equal "/tmp/agent" (getf burs::*options* :agent)))
    (is (equal "bastion" (getf burs::*options* :jump)))
    (is (equal "nc %h %p" (getf burs::*options* :proxy-command)))))

(test command-line-options-keep-the-first-value
  (let ((burs::*options* (empty-options)))
    (dolist (option '("User=first" "Port=2200" "User=last"))
      (push option (getf burs::*options* :options)))
    ;; Pushed in reverse, so the resolver list is command-line order.  Like
    ;; readconf, the first value for a keyword is the one that stays.
    (let ((options nil))
      (cl-pnet-ssh:ssh-config-resolve
       (cl-pnet-ssh::ssh-config-add-options
        (cl-pnet-ssh::%make-ssh-config :directives nil)
        (burs::resolver-option-list))
       "alias"
       :on-options (lambda (value) (setf options value)))
      (is (equal "first" (cl-pnet-ssh:ssh-config-options-user options)))
      (is (= 2200 (cl-pnet-ssh:ssh-config-options-port options))))))

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
    ;; The last case is a command with no side effects that succeeds, spelled
    ;; for the shell the client runs: sh on POSIX, cmd.exe on Windows.
    (is (eq t (evaluate #-win32 "true" #+win32 "exit /b 0")))))

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

(test print-config-accepts-sha1-rsa-names
  "HostKeyAlgorithms and the accepted-key lists may name SHA-1 ssh-rsa."
  (let* ((config
           (cl-pnet-ssh::%make-ssh-config
            :directives
            (list (cl-pnet-ssh::ssh-config-option-line
                   "HostKeyAlgorithms ssh-rsa")
                  (cl-pnet-ssh::ssh-config-option-line
                   "PubkeyAcceptedAlgorithms ssh-rsa-cert-v01@openssh.com")
                  (cl-pnet-ssh::ssh-config-option-line
                   "HostbasedAcceptedAlgorithms ssh-rsa"))))
         (options nil))
    (cl-pnet-ssh:ssh-config-resolve
     config "alias.example"
     :on-options (lambda (value) (setf options value)))
    (let ((burs::*options* (empty-options))
          (text (with-output-to-string (*standard-output*)
                  (burs::print-config-options
                   "alias.example" options nil))))
      (flet ((line (value)
               (search (format nil "~A~%" value) text)))
        (is (line "hostkeyalgorithms ssh-rsa"))
        (is (line "pubkeyacceptedalgorithms ssh-rsa-cert-v01@openssh.com"))
        (is (line "hostbasedacceptedalgorithms ssh-rsa")))))
  ;; The default offer keeps them out; only a configuration names them.
  (is (not (member "ssh-rsa" (burs::supported-signature-algorithms)
                   :test #'string=)))
  (is (member "ssh-rsa" (burs::supported-signature-all-algorithms)
              :test #'string=))
  (is (not (member "ssh-rsa" (burs::supported-host-key-algorithms)
                   :test #'string=)))
  (is (member "ssh-rsa" (burs::supported-host-key-all-algorithms)
              :test #'string=)))

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
        ;; IdentitiesOnly keeps an agent that happens to run in the test
        ;; environment from adding lines this test counts.
        (format stream "IdentitiesOnly yes~%IdentityFile ~A~%IdentityFile ~A~%"
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
        (format stream "IdentitiesOnly yes~%IdentityFile ~A~%"
                (namestring path)))
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
  #-(and sbcl (not win32)) (skip "SBCL's POSIX signal mask only")
  #+(and sbcl (not win32))
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


;;; ---- BURS KEYGEN ----

(defun keygen-call (arguments &key (input ""))
  "VALUES STATUS OUTPUT ERROR for keygen ARGUMENTS, reading INPUT as stdin.

The prompt text goes to the error stream on this implementation, so both
streams are captured; an empty INPUT stands for end of input."
  (let ((output (make-string-output-stream))
        (error-output (make-string-output-stream)))
    (values (let ((*standard-output* output)
                  (*error-output* error-output)
                  (*standard-input* (make-string-input-stream input)))
              (burs::keygen-main arguments))
            (get-output-stream-string output)
            (get-output-stream-string error-output))))

(defun keygen-public-parts (path)
  "TYPE, BLOB and COMMENT on PATH's first public-key line."
  (with-open-file (stream path :direction :input)
    (let* ((line (string-trim '(#\Space #\Tab #\Return #\Newline)
                              (read-line stream)))
           (first (position #\Space line))
           (second (and first (position #\Space line :start (1+ first)))))
      (values (subseq line 0 first)
              (subseq line (1+ first) second)
              (if second (subseq line (1+ second)) "")))))

;;; ---- PEM fixtures for the keygen command ----

(defparameter +keygen-pem-passphrase+ "pem pass")

(defparameter +keygen-pem-rsa+
  "-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDNOaxK3xPyXKpvCagd7jtmY8DenWnHdoRQ5mgmFOMohJj2P6NI
BLpmOFVkA8oFGS7I+SkHcGosDW1giFHcWsmSDnddYI7/1GQL9qvNi+0D4VFOGL+D
XR36o/mnXR6Qbq1KEIku81XNi+TWDruBn1cnf/ErwrCrydyiDZy0kpUGdwIDAQAB
AoGAav0kGyxNA87Xc2e/Y0stYGWkyOmbmcbpmBtmNGQzQI5QCCCJCSSd4GiB69Al
456LS27Juv0Z/LlLSkYHFy+lYTWkBIBRA8kePmirLgNnaEISOj8gnP7Kv26yeBuW
W/TOsPl6lg0RLV6GikWgmNZQzU2H0zyNkw4xKORieXLkqvECQQD5GsOoDVHZd65Y
QLBINXOh6MZHEShZfCt6oUQU0GD5fxcz9Ys5GBwiS7SXX+EZ8X5ywYkTUXq2QlWv
iwDV85slAkEA0uf3TbzEbX0KcQuALjO1Cphgmz8pOKc7e2R5p9XiSa/uYDqg1n6n
D0PqkpC7lA5IJtkaQLYvtvHdyqzKOFYWawJBANo9mZc8/C2jjgphuk+5DLKYJkaT
AJ/NiqYobWYy3hMYRnLOOAhwWA2v9+r7JFK/YcIWTwquwuy1Fy7xgGzxvUUCQEre
n/MPvOdlSSyiOYmtP2qYd0sFW/vJmhsOqwVCr0cbVlMA3RHn+iQ4JvCKwpwnicOI
tIIeasfWCrclKdBf9ysCQQDwp/pHj7SKW84E1VrVOWABMlYCN4YZgu4CyNR0wfGJ
2wcdkOtF/7kCfnZ36ocHPFiejAZqCsca5mHKQFf3t9Vh
-----END RSA PRIVATE KEY-----
"
  "A 1024-bit RSA key in traditional PKCS#1 form.")

(defparameter +keygen-pem-rsa-encrypted+
  "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AE1738854067CA20D84E91862C823999

ovUwPMO/I8gQTkOYejvGyzvg36ryvU5qtpHfss4vgly30EMdCmerUBJiZ42oRPKG
TAvhphZY4ggIeB3RCuY0wA+b2WMdLXd3WvNU3nLD9XpMJhD2fafNu5JRE9wZvG44
1GjxuIvCeqMS4ZV5WnXgmIaRNRKebaimKSvmaaJ/F9OYccqWsv63JzzbCCw/yRdp
6ps1iejTpf+g5ZFYVMO9WBGGUj+NcNHMARRFmdbcv5HmOi7U8LG+CNMcRVTJLDjD
i2O263ORC4ood/+GYEjKI8e+nyI3aqJ2U1ZHSw8GvibIe9c5F/ozFEITloUbrfnQ
FeKjzKlgVnMcQGYgpPCO3JBd+cNFZjzQWfYWWAQx8hRp6j9ZKUy9KyFDDQxwuaLx
/Fv8o/Jo4jmI2zoMhBIi0ZuoiFg8CknWhod7ylOMJQH8kDVTPHO5sYT2qoBHre5F
ckz78DjRh/7oTK2K4FlbGwnyKuGKPUaAI1DOEepjs4vSAVtZth97IspK79nQDm2w
wNJmt5SpbImUDbY/VpithAWDqOMuy+lcTeyhO9NGItNxXV7NnaVKrt+brKui7+P7
LvOOmrZXGsxq6aBqq0RSFq/8L+KvvXVZILkcNkFh6q5ejgZQsLOhAoGN8XWP10HK
VkOdYlt+QQnnCXgvB/TFktBfx+3MzM2y9AA4jC/Obs7EYidbHTv43q8bZHeiRiLG
OvU46AEHSylkgCLLZuj6JGPOSW+0Yptz4RceDUDQLh7djKdEB0MxpbHDwkxN4RaI
2EjgCouXxlkYU6ZahWwBrZZmlCG+J2mDm1X3MN4M8/fKYGPeDfhGTQTOZE34PYdJ
-----END RSA PRIVATE KEY-----
"
  "The same key in traditional PEM, encrypted with AES-128-CBC.")

(defparameter +keygen-pem-ed25519+
  "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ5fosgLKZgyVf3n+Ra5xgSjoVFyEQa4fDEBRloNZev/
-----END PRIVATE KEY-----
"
  "An Ed25519 key in unencrypted PKCS#8 form.")

(defparameter +keygen-pem-ec-withparams+
  "-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICdVYYmBLD522JutAb7OdD9aFh7112+exITfFTTvwMaJoAoGCCqGSM49
AwEHoUQDQgAEjbniMywTyVV9C8pMa7qnKz/OOMZJxiqUS1x86+U0q+5iChZGzrGh
NZwIuJlMZhXY/aLxegbougv9Uavb7GiF4g==
-----END EC PRIVATE KEY-----
"
  "An EC key preceded by the EC PARAMETERS block openssl ecparam writes.")

(defparameter +keygen-pem-rsa-public+
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDNOaxK3xPyXKpvCagd7jtmY8DenWnHdoRQ5mgmFOMohJj2P6NIBLpmOFVkA8oFGS7I+SkHcGosDW1giFHcWsmSDnddYI7/1GQL9qvNi+0D4VFOGL+DXR36o/mnXR6Qbq1KEIku81XNi+TWDruBn1cnf/ErwrCrydyiDZy0kpUGdw==")

(defparameter +keygen-pem-ed25519-public+
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOm4JHu0PTDjcpwl/RrNP6ZeUUxjKvVsB6TQnfcMP/Ot")


(defun keygen-write-pem (path text)
  "Write TEXT to PATH with the mode ssh-keygen demands of a private key."
  (ensure-directories-exist path)
  (cl-pnet-ssh::ssh-write-octets-file (map 'vector #'char-code text) path)
  #+(and sbcl (not win32))
  (sb-posix:chmod (namestring path) #o600)
  path)

(defun keygen-first-line-of (path)
  (with-open-file (stream path :direction :input)
    (read-line stream)))

(defun keygen-public-comment-of (path)
  (with-open-file (stream path :direction :input)
    (burs::keygen-public-line-comment (read-line stream))))

(test keygen-parses-ssh-keygen-options
  (let ((options (burs::keygen-parse-arguments
                  '("-t" "rsa" "-b2048" "-f/tmp/x" "-N" "pw" "-C" "me" "-q"))))
    (is (string= "rsa" (getf options :type)))
    (is (= 2048 (getf options :bits)))
    (is (string= "/tmp/x" (getf options :file)))
    (is (string= "pw" (getf options :new-passphrase)))
    (is (string= "me" (getf options :comment)))
    (is (eq t (getf options :quiet))))
  ;; Switches cluster, and -E selects the fingerprint hash.
  (let ((options (burs::keygen-parse-arguments '("-ly" "-E" "md5"))))
    (is (eq t (getf options :fingerprint)))
    (is (eq t (getf options :print-public)))
    (is (eq :md5 (getf options :hash))))
  (let ((options (burs::keygen-parse-arguments '("-h" "-ly" "-E" "md5"))))
    (is (eq t (getf options :fingerprint)))
    (is (eq t (getf options :print-public)))
    (is (eq :md5 (getf options :hash))))
  ;; A missing value, a bad number, a bad hash, a feature this command does
  ;; not have, and a stray argument are all errors rather than defaults.
  ;; getopt-style errors carry ssh-keygen's wording.
  (signals error (burs::keygen-parse-arguments '("-t")))
  (signals error (burs::keygen-parse-arguments '("-b" "many")))
  (signals error (burs::keygen-parse-arguments '("-E" "bogus")))
  (signals error (burs::keygen-parse-arguments '("-s" "ca")))
  (signals error (burs::keygen-parse-arguments '("stray")))
  (flet ((message (arguments)
           (handler-case (burs::keygen-parse-arguments arguments)
             (burs::keygen-usage-error (condition)
               (burs::keygen-usage-error-message condition)))))
    ;; ssh-keygen has no --help; its getopt reports the second dash as the
    ;; unknown option and prints the usage.
    (is (string= "unknown option -- -" (message '("--help"))))
    (is (string= "unknown option -- x" (message '("-x"))))
    (is (string= "option requires an argument -- f" (message '("-f"))))
    (is (string= "Too many arguments." (message '("-q" "stray"))))))

(test keygen-default-file-names-follow-the-type
  (is (string= "id_ed25519" (burs::keygen-default-name "ed25519")))
  (is (string= "id_rsa" (burs::keygen-default-name "rsa")))
  (is (string= "id_ecdsa" (burs::keygen-default-name "ecdsa")))
  (is (string= "id_ecdsa" (burs::keygen-default-name "ecdsa-sha2-nistp384")))
  (is (string= "id_mldsa44_ed25519"
               (burs::keygen-default-name "mldsa44-ed25519")))
  ;; -f wins over the default, whether or not it is absolute.
  (let ((options (list :file "/tmp/elsewhere" :type "ed25519")))
    ;; Compare through the platform's native spelling: Windows turns the
    ;; separators round, and the pathname object is not EQ across calls.
    (is (string= (uiop:native-namestring
                  (uiop:parse-native-namestring "/tmp/elsewhere"))
                 (uiop:native-namestring (burs::keygen-path options))))))

(test keygen-generation-defaults-match-openssh-10
  ;; ssh-keygen's default type is ed25519 even when -b is given without -t,
  ;; and the announcement echoes the -t spelling instead of a canonical
  ;; short name.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (plain (merge-pathnames "id_ed25519" directory))
         (ecdsa (merge-pathnames "id_ecdsa" directory)))
    (ensure-directories-exist plain)
    (unwind-protect
         (progn
           (multiple-value-bind (status output)
               (keygen-call (list "-b" "512" "-f" (namestring plain)
                                  "-N" ""))
             (is (eql 0 status))
             (is (search "Generating public/private ed25519 key pair."
                         output)))
           (is (string= "ssh-ed25519"
                        (nth-value 0 (keygen-public-parts
                                      (burs::keygen-public-path plain)))))
           ;; -b chooses the curve even when -t names a different one, and
           ;; the message keeps the name the user typed.
           (multiple-value-bind (status output)
               (keygen-call
                (list "-t" "ecdsa-sha2-nistp256" "-b" "384"
                      "-f" (namestring ecdsa) "-N" ""))
             (is (eql 0 status))
             (is (search
                  "Generating public/private ecdsa-sha2-nistp256 key pair."
                  output)))
           (is (string= "ecdsa-sha2-nistp384"
                        (nth-value 0 (keygen-public-parts
                                      (burs::keygen-public-path ecdsa))))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-refuses-too-open-private-keys
  ;; ssh-keygen warns and refuses a private key that other users can read.
  ;; -l still fingerprints from the public file without a warning.
  #-(and sbcl (not win32)) (skip "POSIX mode bits only")
  #+(and sbcl (not win32))
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory))
         (native (namestring path)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" native "-N" "" "-q")))))
           (sb-posix:chmod native #o644)
           (multiple-value-bind (status output error)
               (keygen-call (list "-y" "-f" native))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search "WARNING: UNPROTECTED PRIVATE KEY FILE!" error))
             (is (search "Permissions 0644 for '" error))
             (is (search "This private key will be ignored." error))
             (is (search (format nil "Load key \"~A\": bad permissions"
                                 native)
                         error)))
           (multiple-value-bind (status output error)
               (keygen-call (list "-p" "-P" "" "-N" "x" "-f" native))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search (format nil "Failed to load key ~A: bad permissions"
                                 native)
                         error)))
           (multiple-value-bind (status output error)
               (keygen-call (list "-c" "-C" "x" "-f" native))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search (format nil "Cannot load private key \"~A\": bad permissions"
                                 native)
                         error)))
           (multiple-value-bind (status output error)
               (keygen-call (list "-l" "-f" native))
             (declare (ignore error))
             (is (eql 0 status))
             (is (search "ED25519" output)))
           (sb-posix:chmod native #o600)
           (multiple-value-bind (status output error)
               (keygen-call (list "-y" "-f" native))
             (declare (ignore error))
             (is (eql 0 status))
             (is (search "ssh-ed25519" output))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-refuses-a-too-open-windows-acl
  ;; Windows checks ACLs rather than mode bits: Win32-OpenSSH refuses a
  ;; private key whose DACL admits anyone but its owner, Administrators,
  ;; SYSTEM and TrustedInstaller.  A key keygen just wrote must pass, and
  ;; granting Everyone write access must make -y refuse it.
  #-win32 (skip "Windows ACLs only")
  #+win32
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory))
         (native (namestring path)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" native "-N" "" "-q")))))
           (multiple-value-bind (status output error)
               (keygen-call (list "-y" "-f" native))
             (declare (ignore output))
             (is (eql 0 status))
             (is (not (search "WARNING: UNPROTECTED PRIVATE KEY FILE!" error))))
           ;; The well-known SID keeps icacls working on localized Windows.
           (uiop:run-program (list "icacls" native "/grant" "*S-1-1-0:(W)")
                             :output nil :error-output nil)
           (multiple-value-bind (status output error)
               (keygen-call (list "-y" "-f" native))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search "WARNING: UNPROTECTED PRIVATE KEY FILE!" error))
             (is (search "Permissions for '" error))
             (is (search "are too open." error))
             (is (search "This private key will be ignored." error))
             (is (search (format nil "Load key \"~A\": bad permissions"
                                 native)
                         error)))
           ;; -l still fingerprints the .pub without the warning.
           (multiple-value-bind (status output error)
               (keygen-call (list "-l" "-f" native))
             (declare (ignore error))
             (is (eql 0 status))
             (is (search "ED25519" output))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-reports-a-missing-or-empty-key-path
  ;; open("") fails with ENOENT, so ssh-keygen reports an empty -f as a
  ;; missing name.  SBCL's pathname layer would instead turn "" into the
  ;; current directory, which is why every mode must check before reading.
  ;; -p and -c used to read the format before loading, so a missing path
  ;; escaped as a raw stream error there.
  (let ((missing (namestring
                  (merge-pathnames
                   (format nil "burs-keygen-missing-~D"
                           (random 1000000))
                   (uiop:temporary-directory)))))
    (flet ((call (arguments)
             (keygen-call arguments)))
      (dolist (path (list "" missing))
        (dolist (arguments (list (list "-l" "-f" path)
                                 (list "-y" "-f" path)
                                 (list "-p" "-N" "" "-f" path)
                                 (list "-c" "-C" "x" "-f" path)))
          (multiple-value-bind (status output error)
              (call arguments)
            (declare (ignore output))
            (is (eql 255 status))
            (is (search ": No such file or directory" error))
            (is (not (search "is not a public key file." error)))
            (is (not (search "is not a key file." error)))))
      (multiple-value-bind (status output error)
          (call (list "-q" "-t" "ed25519" "-N" "" "-f" ""))
        (is (eql 1 status))
        (is (search "Saving key \"\" failed: No such file or directory"
                    error))
        (is (not (search "Overwrite" output))))))))

(test keygen-reports-unreadable-and-malformed-keys
  ;; ssh-keygen says "invalid format" for garbage and the OS message for a
  ;; directory or an unreadable key, without asking for a passphrase.
  #-(and sbcl (not win32)) (skip "POSIX file modes only")
  #+(and sbcl (not win32))
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (garbage (merge-pathnames "garbage" directory))
         (folder (merge-pathnames "folder/" directory))
         (unreadable (merge-pathnames "unreadable" directory)))
    (ensure-directories-exist folder)
    (dolist (path (list garbage unreadable))
      (with-open-file (stream path :direction :output
                                   :if-exists :supersede)
        (write-string "garbage" stream))
      (sb-posix:chmod (namestring path) #o600))
    (sb-posix:chmod (namestring folder) #o700)
    (sb-posix:chmod (namestring unreadable) #o000)
    (flet ((call (arguments)
             (keygen-call arguments)))
      (unwind-protect
           (let ((native (namestring garbage)))
             (multiple-value-bind (status output error)
                 (call (list "-y" "-f" native))
               (declare (ignore output))
               (is (eql 255 status))
               (is (search (format nil "Load key \"~A\": invalid format"
                                   native)
                           error))
               (is (not (search "Enter passphrase" error))))
             (multiple-value-bind (status output error)
                 (call (list "-p" "-P" "" "-N" "x" "-f" native))
               (declare (ignore output))
               (is (eql 255 status))
               (is (search (format nil "Failed to load key ~A: invalid format"
                                   native)
                           error)))
             (multiple-value-bind (status output error)
                 (call (list "-c" "-C" "x" "-f" native))
               (declare (ignore output))
               (is (eql 255 status))
               (is (search
                    (format nil "Cannot load private key \"~A\": invalid format"
                            native)
                    error)))
             ;; A 0700 directory gets past the mode check, so loading it
             ;; reports the system error.
             (multiple-value-bind (status output error)
                 (call (list "-y" "-f" (namestring folder)))
               (declare (ignore output))
               (is (eql 255 status))
               (is (search "Is a directory" error)))
             ;; Root ignores the mode, so only test the unreadable file as
             ;; an ordinary user.
             (unless (zerop (sb-posix:getuid))
               (multiple-value-bind (status output error)
                   (call (list "-y" "-f" (namestring unreadable)))
                 (declare (ignore output))
                 (is (eql 255 status))
                 (is (search "Permission denied" error)))))
        (ignore-errors (sb-posix:chmod (namestring unreadable) #o600))
        (ignore-errors
          (uiop:delete-directory-tree directory :validate t))))))

(test keygen-comments-are-clamped-like-ssh-keygen
  ;; ssh-keygen copies comments through a KEY_COMMENT_MAX buffer, so both
  ;; -C and a typed -c comment stop at 2048 characters.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory))
         (long (make-string 3000 :initial-element #\x)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" (namestring path)
                                "-N" "" "-C" long "-q")))))
           (multiple-value-bind (type blob comment)
               (keygen-public-parts (burs::keygen-public-path path))
             (declare (ignore type blob))
             (is (= 2048 (length comment)))
             (is (every (lambda (character) (char= character #\x))
                        comment)))
           (multiple-value-bind (status output error)
               (keygen-call (list "-c" "-C" long "-N" "" "-q"
                                  "-f" (namestring path)))
             (declare (ignore output error))
             (is (eql 0 status)))
           (multiple-value-bind (type blob comment)
               (keygen-public-parts (burs::keygen-public-path path))
             (declare (ignore type blob))
             (is (= 2048 (length comment)))
             (is (every (lambda (character) (char= character #\x))
                        comment))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-asks-for-the-file-when-f-is-absent
  ;; Without -f ssh-keygen prints the default path and reads stdin: an
  ;; empty line takes the default, end of input cancels with status 1.
  #-win32
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory))
         (home (merge-pathnames "home/" directory))
         (native (namestring path))
         (old-home (uiop:getenv "HOME")))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" native
                                "-N" "" "-q")))))
           ;; -l asks for the key file and accepts the typed path.
           (multiple-value-bind (status output error)
               (keygen-call (list "-l") :input (format nil "~A~%" native))
             (declare (ignore error))
             (is (eql 0 status))
             (is (search "Enter file in which the key is (" output))
             (is (search "id_ed25519): " output))
             (is (search "ED25519" output)))
           ;; End of input cancels the prompt.
           (multiple-value-bind (status output error)
               (keygen-call (list "-l") :input "")
             (declare (ignore error))
             (is (eql 1 status))
             (is (search "Enter file in which the key is (" output)))
           ;; An empty answer takes ~/.ssh/id_ed25519, and generation
           ;; creates ~/.ssh for it.
           (setf (uiop:getenv "HOME") (namestring home))
           (multiple-value-bind (status output error)
               (keygen-call (list "-t" "ed25519" "-N" "" "-q")
                            :input (format nil "~%"))
             (declare (ignore output error))
             (is (eql 0 status)))
           (is (probe-file (merge-pathnames ".ssh/id_ed25519" home)))
           (is (probe-file (merge-pathnames ".ssh/id_ed25519.pub" home))))
      (setf (uiop:getenv "HOME") old-home)
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-writes-a-key-and-public-file
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory)))
    (ensure-directories-exist path)
    (unwind-protect
         (flet ((invoke (&rest arguments)
                  (let ((*standard-output* (make-broadcast-stream))
                        (*error-output* (make-broadcast-stream)))
                    (burs::keygen-main arguments))))
           (is (eql 0 (invoke "-t" "ed25519" "-f" (namestring path)
                           "-N" "" "-C" "test@example" "-q")))
           (is (probe-file path))
           (is (probe-file (concatenate 'string (namestring path) ".pub")))
           (let ((key (cl-pnet-ssh:ssh-load-private-key path)))
             (is (string= "ssh-ed25519"
                          (cl-pnet-ssh:ssh-private-key-type key)))
             (is (string= "test@example"
                          (cl-pnet-ssh:ssh-private-key-comment key))))
           ;; -y and -l both read the file back, and -y prints one line.
           (let ((line (with-output-to-string (out)
                         (let ((*standard-output* out))
                           (burs::keygen-main
                            (list "-y" "-f" (namestring path)))))))
             (is (string= "ssh-ed25519" (subseq line 0 11)))
             (is (search "test@example" line)))
           (let ((line (with-output-to-string (out)
                         (let ((*standard-output* out))
                           (burs::keygen-main
                            (list "-l" "-f" (namestring path)))))))
             (is (search "SHA256:" line))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-writes-comments-as-utf-8
  ;; ssh-keygen writes the comment through fprintf, so its characters become
  ;; their UTF-8 bytes; -l and -y read the same bytes back.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_utf8" directory))
         (public (concatenate 'string (namestring path) ".pub")))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (multiple-value-bind (status output error)
               (keygen-call (list "-q" "-t" "ed25519" "-N" ""
                                  "-C" "ünïcode" "-f" (namestring path)))
             (is (eql 0 status))
             (is (string= "" output))
             (is (string= "" error)))
           (with-open-file (stream public :direction :input
                                          :element-type '(unsigned-byte 8))
             (let ((octets (make-array (file-length stream)
                                       :element-type '(unsigned-byte 8))))
               (read-sequence octets stream)
               ;; "ünïcode" as UTF-8, not the comment's low bytes.
               (is (search #(195 188 110 195 175 99 111 100 101)
                           octets))))
           (multiple-value-bind (status output error)
               (keygen-call (list "-l" "-f" (namestring path)))
             (declare (ignore error))
             (is (eql 0 status))
             (is (search "ünïcode" output))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-keeps-arbitrary-comment-bytes
  ;; A comment is free-form bytes.  A file written by another tool can hold
  ;; a byte that is not valid UTF-8: -l escapes it as OpenSSH's mprintf does,
  ;; while -y and a rewrite keep the byte itself.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_raw" directory))
         (public (concatenate 'string (namestring path) ".pub"))
         (comment-octets
           (make-array 3 :element-type '(unsigned-byte 8)
                         :initial-contents '(120 252 121)))) ; x, 0xFC, y
    (ensure-directories-exist path)
    (unwind-protect
         (let ((key (cl-pnet-ssh:ssh-generate-private-key
                     "ed25519" :comment "x\\374y")))
           (setf (cl-pnet-ssh:ssh-private-key-comment-octets key)
                 comment-octets)
           (cl-pnet-ssh:ssh-write-private-key key path)
           (cl-pnet-ssh:ssh-write-public-key key public)
           ;; The public file carries the bytes, not their escapes.
           (with-open-file (stream public :direction :input
                                          :element-type '(unsigned-byte 8))
             (let ((octets (make-array (file-length stream)
                                       :element-type '(unsigned-byte 8))))
               (read-sequence octets stream)
               (is (search comment-octets octets))))
           ;; -l prints the escaped form for both the private key and the
           ;; public key, exactly as ssh-keygen's mprintf does.
           (dolist (target (list path public))
             (multiple-value-bind (status output error)
                 (keygen-call (list "-l" "-f" (namestring target)))
               (declare (ignore error))
               (is (eql 0 status))
               (is (search "x\\374y" output))))
           ;; A rewrite keeps the raw bytes; -y emits them unchanged.
           (let ((reloaded (cl-pnet-ssh:ssh-load-private-key path)))
             (is (equalp comment-octets
                         (cl-pnet-ssh:ssh-private-key-comment-octets
                          reloaded)))
             (is (search comment-octets
                         (cl-pnet-ssh:ssh-public-key-line-octets reloaded)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-public-file-mode-follows-umask
  ;; sshkey_save_public opens a new file with mode 0644, so the umask masks
  ;; that rather than fopen's 0666.  The private file is always 0600.
  #-(and sbcl (not win32)) (skip "POSIX file modes only")
  #+(and sbcl (not win32))
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_mode" directory))
         (public (concatenate 'string (namestring path) ".pub"))
         (saved (sb-posix:umask #o022)))
    (ensure-directories-exist path)
    (unwind-protect
         (flet ((mode (file)
                  (logand #o777
                          (sb-posix:stat-mode (sb-posix:stat file))))
                (reset ()
                  (ignore-errors (delete-file path))
                  (ignore-errors (delete-file public))))
           (dolist (spec (list (cons #o022 #o644) (cons #o077 #o600)
                               (cons #o027 #o640)))
             (reset)
             (sb-posix:umask (car spec))
             (multiple-value-bind (status output error)
                 (keygen-call (list "-q" "-t" "ed25519" "-N" ""
                                    "-f" (namestring path)))
               (declare (ignore output error))
               (is (eql 0 status)))
             (is (eql #o600 (mode (namestring path))))
             (is (eql (cdr spec) (mode public))))
           ;; A rewrite keeps the mode the public file already had.
           (reset)
           (sb-posix:umask #o022)
           (keygen-call (list "-q" "-t" "ed25519" "-N" ""
                              "-f" (namestring path)))
           (sb-posix:chmod public #o600)
           (multiple-value-bind (status output error)
               (keygen-call (list "-q" "-c" "-C" "changed" "-P" ""
                                  "-f" (namestring path)))
             (declare (ignore output error))
             (is (eql 0 status)))
           (is (eql #o600 (mode public))))
      (sb-posix:umask saved)
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-fingerprints-public-keys-on-stdin
  ;; do_fingerprint reads the key list from stdin for -f - and labels the
  ;; source (stdin).  A private key there is not a public key file.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_stdin" directory))
         (public (concatenate 'string (namestring path) ".pub")))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (keygen-call (list "-q" "-t" "ed25519" "-N" "" "-C" "stdin@test"
                              "-f" (namestring path)))
           (let ((text (with-open-file (stream public :direction :input)
                         (let ((line (read-line stream)))
                           (concatenate 'string line (string #\Newline))))))
             (dolist (arguments (list (list "-l" "-f" "-")
                                      (list "-B" "-f" "-")))
               (multiple-value-bind (status output error)
                   (keygen-call arguments :input text)
                 (declare (ignore error))
                 (is (eql 0 status))
                 (is (if (search "-B" arguments)
                         (search "(ED25519)" output)
                         (search "stdin@test" output))))))
           (let ((private
                   (with-open-file (stream path :direction :input)
                     (let ((line (read-line stream)))
                       (concatenate 'string line (string #\Newline))))))
             (multiple-value-bind (status output error)
                 (keygen-call (list "-l" "-f" "-") :input private)
               (declare (ignore output))
               (is (eql 255 status))
               (is (search "(stdin) is not a public key file." error)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-treats-a-tilde-path-literally
  ;; ssh-keygen does not expand ~ in -f; the path is passed to open() as is.
  ;; A ~ must therefore not turn into a FORMAT directive in the message.
  (let ((name (concatenate 'string
                           "~/burs-keygen-tilde-"
                           (princ-to-string (get-universal-time))
                           "-" (princ-to-string (random 1000000)))))
    (multiple-value-bind (status output error)
        (keygen-call (list "-l" "-f" name))
      (declare (ignore output))
      (is (eql 255 status))
      (is (search (format nil "~A: No such file or directory" name) error))
      (is (not (search "FORMAT" error))))))

(test keygen-does-not-create-missing-directories
  ;; ssh-keygen creates only ~/.ssh; any other missing parent makes the
  ;; save fail with its message and status 1, leaving no directory behind.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "missing/key" directory)))
    (ensure-directories-exist directory)
    (unwind-protect
         (progn
           (multiple-value-bind (status output error)
               (keygen-call (list "-t" "ed25519" "-f" (namestring path)
                                  "-N" "" "-q"))
             (declare (ignore output))
             (is (eql 1 status))
             (is (search "Saving key" error))
             (is (search "No such file or directory" error))
             (is (not (probe-file (merge-pathnames "missing/" directory)))))
           ;; A directory target is refused after the overwrite answer.
           (multiple-value-bind (status output error)
               (keygen-call
                (list "-t" "ed25519" "-f" (namestring directory)
                      "-N" "" "-q")
                :input (format nil "y~%"))
             (declare (ignore output))
             (is (eql 1 status))
             (is (search "Is a directory" error))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-comment-change-preserves-encryption
  ;; -c rewrites both halves of the pair.  It must keep an unprotected key
  ;; unprotected even when the caller passes a stray -P, and keep a
  ;; protected key protected under the passphrase that opened it.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (plain (merge-pathnames "id_plain" directory))
         (locked (merge-pathnames "id_locked" directory)))
    (ensure-directories-exist plain)
    (labels ((invoke (&rest arguments)
               (let ((*standard-output* (make-broadcast-stream))
                     (*error-output* (make-broadcast-stream)))
                 (burs::keygen-main arguments)))
             (public-comment (path)
               (with-open-file (stream (burs::keygen-public-path path))
                 (burs::keygen-public-line-comment (read-line stream)))))
      (unwind-protect
           (progn
             (is (eql 0 (invoke "-t" "ed25519" "-f" (namestring plain)
                                "-N" "" "-C" "before" "-q")))
             (is (eql 0 (invoke "-c" "-C" "after" "-P" "stray"
                                "-f" (namestring plain) "-q")))
             (is (not (cl-pnet-ssh:ssh-private-key-file-encrypted-p plain)))
             (is (string= "after"
                          (cl-pnet-ssh:ssh-private-key-comment
                           (cl-pnet-ssh:ssh-load-private-key plain))))
             (is (string= "after" (public-comment plain)))
             ;; A missing .pub is recreated, and the messages match
             ;; ssh-keygen's, which -q does not silence.
             (delete-file (burs::keygen-public-path plain))
             (let ((text (with-output-to-string (out)
                           (let ((*standard-output* out))
                             (burs::keygen-main
                              (list "-c" "-C" "later" "-P" ""
                                    "-f" (namestring plain) "-q"))))))
               (is (search "Old comment: after" text))
               (is (search "Comment 'later' applied" text)))
             (is (string= "later" (public-comment plain)))
             (is (eql 0 (invoke "-t" "ed25519" "-f" (namestring locked)
                                "-N" "pw" "-C" "before" "-q")))
             (is (eql 0 (invoke "-c" "-C" "after" "-P" "pw"
                                "-f" (namestring locked) "-q")))
             (is (cl-pnet-ssh:ssh-private-key-file-encrypted-p locked))
             (is (string= "after"
                          (cl-pnet-ssh:ssh-private-key-comment
                           (cl-pnet-ssh:ssh-load-private-key
                            locked :passphrase "pw"))))
             (is (string= "after" (public-comment locked))))
        (ignore-errors (uiop:delete-directory-tree directory :validate t))))))

(test keygen-fingerprint-format-matches-ssh-keygen
  ;; -E md5 is lower case.  A bare public key without a comment reads
  ;; "no comment", while -l on the private path reads the .pub and
  ;; substitutes its name when that line has no comment, as ssh-keygen
  ;; does.  Without a .pub an empty private comment prints as two spaces.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory))
         (public (burs::keygen-public-path path)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0
                       (keygen-call
                        (list "-t" "ed25519" "-f" (namestring path)
                              "-N" "" "-C" "" "-q")))))
           ;; Directly on the .pub there is no comment field at all.
           (multiple-value-bind (status output)
               (keygen-call
                (list "-l" "-E" "md5" "-f" (namestring public)))
             (is (eql 0 status))
             (is (search "MD5:" output))
             (is (search "no comment" output))
             (let* ((start (search "MD5:" output))
                    (end (position #\Space output :start start)))
               (is (notany #'upper-case-p
                           (subseq output (+ start 4) end)))))
           ;; ssh-keygen -E also takes the other digests it knows, with the
           ;; digest name as the prefix and no base64 padding.
           (dolist (hash '("sha1" "sha256" "sha384" "sha512"))
             (multiple-value-bind (status output)
                 (keygen-call
                  (list "-l" "-E" hash "-f" (namestring public)))
               (is (eql 0 status))
               (is (search (concatenate 'string
                                        (string-upcase hash) ":")
                           output))
               (is (not (find #\= output)))))
           ;; An unknown digest is ssh-keygen's fatal error.
           (multiple-value-bind (status output error)
               (keygen-call
                (list "-l" "-E" "bogus" "-f" (namestring public)))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search "Invalid hash algorithm \"bogus\"" error)))
           ;; Through the private path, the empty .pub comment becomes the
           ;; .pub file name.
           (multiple-value-bind (status output)
               (keygen-call (list "-l" "-f" (namestring path)))
             (is (eql 0 status))
             (is (search (uiop:native-namestring public) output)))
           (delete-file public)
           (multiple-value-bind (status output)
               (keygen-call (list "-l" "-f" (namestring path)))
             (is (eql 0 status))
             (is (not (search "no comment" output)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-fingerprint-walks-every-line-and-prefix
  ;; -l reads every line.  An authorized_keys prefix keeps its trailing
  ;; comment, a known_hosts prefix with no comment prints the host, a bare
  ;; key with no comment prints "no comment", and blank, #, @ and invalid
  ;; lines are skipped.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (ed (merge-pathnames "id_ed25519" directory))
         (rsa (merge-pathnames "id_rsa" directory))
         (ecdsa (merge-pathnames "id_ecdsa" directory))
         (file (merge-pathnames "keys.txt" directory)))
    (ensure-directories-exist ed)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" (namestring ed)
                                "-N" "" "-C" "ed@example" "-q")))))
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "rsa" "-b" "2048"
                                "-f" (namestring rsa)
                                "-N" "" "-C" "rsa@example" "-q")))))
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ecdsa" "-f" (namestring ecdsa)
                                "-N" "" "-C" "ecdsa@example" "-q")))))
           (multiple-value-bind (ed-type ed-blob ed-comment)
               (keygen-public-parts (burs::keygen-public-path ed))
             (multiple-value-bind (rsa-type rsa-blob)
                 (keygen-public-parts (burs::keygen-public-path rsa))
               (multiple-value-bind (ecdsa-type ecdsa-blob)
                   (keygen-public-parts (burs::keygen-public-path ecdsa))
                 (with-open-file
                     (stream file :direction :output
                                  :if-exists :supersede
                                  :if-does-not-exist :create
                                  :external-format :utf-8)
                   (format stream "~%# a comment~%not a key~%")
                   (format stream "command=\"echo hi\",no-pty ~A ~A ~A~%"
                           ed-type ed-blob ed-comment)
                   (format stream "known.example ~A ~A~%"
                           rsa-type rsa-blob)
                   (format stream "~A ~A~%" ecdsa-type ecdsa-blob)
                   (format stream "@cert-authority *.example ~A ~A~%"
                           ed-type ed-blob))
                 (multiple-value-bind (status output)
                     (keygen-call (list "-l" "-f" (namestring file)))
                   (is (eql 0 status))
                   (is (= 3 (count #\Newline output)))
                   (is (search "ed@example" output))
                   (is (search "known.example" output))
                   (is (search "no comment" output))
                   (is (search "(ED25519)" output))
                   (is (search "(RSA)" output))
                   (is (search "(ECDSA)" output)))))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-verbose-fingerprints-add-randomart
  ;; -l -v appends the randomart after the fingerprint line; -E picks the
  ;; hash in its footer and -B leaves the picture alone.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory))
         (public (burs::keygen-public-path path))
         (known (merge-pathnames "known_hosts" directory)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-N" "" "-C" "one"
                                "-q" "-f" (namestring path))))))
           (multiple-value-bind (status output)
               (keygen-call (list "-l" "-v" "-f" (namestring public)))
             (is (eql 0 status))
             (is (search "+--[ED25519 256]--+" output))
             (is (search "+----[SHA256]-----+" output)))
           (multiple-value-bind (status output)
               (keygen-call (list "-l" "-v" "-E" "md5"
                                  "-f" (namestring public)))
             (is (eql 0 status))
             (is (search "+------[MD5]------+" output)))
           (multiple-value-bind (status output)
               (keygen-call (list "-l" "-v" "-B" "-f" (namestring public)))
             (is (eql 0 status))
             (is (search "+----[SHA256]-----+" output)))
           ;; -v is accepted even where it changes nothing.
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-y" "-v" "-f" (namestring path))))))
           (with-open-file (stream known :direction :output
                                         :if-exists :supersede)
             (format stream "a.example ~A~%"
                     (string-right-trim '(#\Newline #\Return)
                                        (uiop:read-file-string public))))
           (multiple-value-bind (status output)
               (keygen-call (list "-F" "a.example" "-l" "-v"
                                  "-f" (namestring known)))
             (is (eql 0 status))
             (is (search "+--[ED25519 256]--+" output))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-fingerprint-errors-match-ssh-keygen
  ;; A missing file, an empty file and a directory are all ssh-keygen's
  ;; "not a public key file" failures with status 255.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (missing (merge-pathnames "missing" directory))
         (empty (merge-pathnames "empty" directory)))
    (ensure-directories-exist empty)
    (with-open-file (stream empty :direction :output
                                  :if-exists :supersede
                                  :if-does-not-exist :create)
      (declare (ignore stream)))
    (unwind-protect
         (progn
           (multiple-value-bind (status output error)
               (keygen-call (list "-l" "-f" (namestring missing)))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search "No such file or directory" error)))
           (dolist (path (list empty directory))
             (multiple-value-bind (status output error)
                 (keygen-call (list "-l" "-f" (namestring path)))
               (declare (ignore output))
               (is (eql 255 status))
               (is (search "is not a public key file." error)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

;;; ---- PEM private keys at the command line ----

(test keygen-prints-public-from-a-pem-private-key
  ;; -y loads every PEM form and prints the same line; a protected one
  ;; needs its passphrase and answers a wrong one like ssh-keygen.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (clear (merge-pathnames "id_rsa_pem" directory))
         (locked (merge-pathnames "id_rsa_pem_locked" directory)))
    (unwind-protect
         (progn
           (keygen-write-pem clear +keygen-pem-rsa+)
           (multiple-value-bind (status output)
               (keygen-call (list "-y" "-f" (namestring clear)))
             (is (eql 0 status))
             (is (string= +keygen-pem-rsa-public+
                          (string-right-trim '(#\Return #\Newline) output))))
           (keygen-write-pem locked +keygen-pem-rsa-encrypted+)
           (multiple-value-bind (status output)
               (keygen-call (list "-y" "-P" +keygen-pem-passphrase+
                                  "-f" (namestring locked)))
             (is (eql 0 status))
             (is (string= +keygen-pem-rsa-public+
                          (string-right-trim '(#\Return #\Newline) output))))
           (multiple-value-bind (status output error)
               (keygen-call (list "-y" "-P" "wrong" "-f" (namestring locked)))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search
                  "incorrect passphrase supplied to decrypt private key"
                  error))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-fingerprints-pem-private-keys
  ;; A clear PEM key fingerprints as "no comment"; a protected one has no
  ;; cleartext header, so -l stops with "is not a key file." unless a .pub
  ;; sits beside it.  An EC PARAMETERS block first is not a private key to
  ;; -l at all, matching ssh-keygen's first-line test.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (clear (merge-pathnames "id_rsa_pem" directory))
         (locked (merge-pathnames "id_rsa_pem_locked" directory))
         (params (merge-pathnames "id_ec_params" directory)))
    (unwind-protect
         (progn
           (keygen-write-pem clear +keygen-pem-rsa+)
           (multiple-value-bind (status output error)
               (keygen-call (list "-l" "-f" (namestring clear)))
             (declare (ignore error))
             (is (eql 0 status))
             (is (search "1024 SHA256:" output))
             (is (search " no comment (RSA)" output)))
           (multiple-value-bind (status output)
               (keygen-call (list "-B" "-f" (namestring clear)))
             (is (eql 0 status))
             (is (search " no comment (RSA)" output)))
           (keygen-write-pem locked +keygen-pem-rsa-encrypted+)
           (multiple-value-bind (status output error)
               (keygen-call (list "-l" "-f" (namestring locked)))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search (format nil "~A is not a key file."
                                 (namestring locked))
                         error)))
           ;; With a .pub beside it, -l reads that and keeps its comment.
           (with-open-file (stream (burs::keygen-public-path locked)
                                   :direction :output
                                   :if-exists :supersede
                                   :if-does-not-exist :create)
             (format stream "~A pub comment~%" +keygen-pem-rsa-public+))
           (multiple-value-bind (status output)
               (keygen-call (list "-l" "-f" (namestring locked)))
             (is (eql 0 status))
             (is (search " pub comment (RSA)" output)))
           (keygen-write-pem params +keygen-pem-ec-withparams+)
           (multiple-value-bind (status output error)
               (keygen-call (list "-l" "-f" (namestring params)))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search "is not a public key file." error))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-changes-a-pem-passphrase
  ;; -p rewrites PEM as openssh-key-v1, prints no comment line because the
  ;; format has none, and writes no .pub.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (clear (merge-pathnames "id_clear" directory))
         (locked (merge-pathnames "id_locked" directory)))
    (unwind-protect
         (progn
           (keygen-write-pem clear +keygen-pem-rsa+)
           (multiple-value-bind (status output)
               (keygen-call (list "-p" "-N" "new-pw"
                                  "-f" (namestring clear)))
             (is (eql 0 status))
             (is (search
                  "Your identification has been saved with the new passphrase."
                  output))
             (is (not (search "Key has comment" output))))
           (is (string= "-----BEGIN OPENSSH PRIVATE KEY-----"
                        (keygen-first-line-of clear)))
           (is (not (probe-file (burs::keygen-public-path clear))))
           (is (string= "ssh-rsa"
                        (cl-pnet-ssh:ssh-private-key-type
                         (cl-pnet-ssh:ssh-load-private-key
                          clear :passphrase "new-pw"))))
           (keygen-write-pem locked +keygen-pem-rsa-encrypted+)
           (multiple-value-bind (status output)
               (keygen-call (list "-p" "-P" +keygen-pem-passphrase+
                                  "-N" "" "-f" (namestring locked)))
             (is (eql 0 status))
             (is (search
                  "Your identification has been saved with the new passphrase."
                  output))
             (is (not (search "Key has comment" output))))
           (is (not (cl-pnet-ssh:ssh-private-key-file-encrypted-p locked)))
           (is (string= "ssh-rsa"
                        (cl-pnet-ssh:ssh-private-key-type
                         (cl-pnet-ssh:ssh-load-private-key locked)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-changes-a-pem-comment
  ;; -c says "No existing comment" for PEM, not "Old comment:", rewrites as
  ;; openssh-key-v1 and always writes the .pub, even for an empty comment.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (clear (merge-pathnames "id_clear" directory))
         (empty (merge-pathnames "id_empty" directory))
         (locked (merge-pathnames "id_locked" directory))
         (public (burs::keygen-public-path clear)))
    (unwind-protect
         (progn
           (keygen-write-pem clear +keygen-pem-rsa+)
           (multiple-value-bind (status output)
               (keygen-call (list "-c" "-C" "new comment" "-P" ""
                                  "-f" (namestring clear)))
             (is (eql 0 status))
             (is (search "No existing comment" output))
             (is (not (search "Old comment:" output)))
             (is (search "Comment 'new comment' applied" output)))
           (is (string= "-----BEGIN OPENSSH PRIVATE KEY-----"
                        (keygen-first-line-of clear)))
           (is (string= "new comment" (keygen-public-comment-of public)))
           (is (string= "new comment"
                        (cl-pnet-ssh:ssh-private-key-comment
                         (cl-pnet-ssh:ssh-load-private-key clear))))
           ;; Another PEM key, this time removing its (absent) comment.
           (keygen-write-pem empty +keygen-pem-rsa+)
           (multiple-value-bind (status output)
               (keygen-call (list "-c" "-C" "" "-P" ""
                                  "-f" (namestring empty)))
             (is (eql 0 status))
             (is (search "No existing comment" output))
             (is (search "Comment removed" output)))
           (is (string= ""
                        (keygen-public-comment-of
                         (burs::keygen-public-path empty))))
           ;; Once rewritten, the key is openssh-key-v1 and -c reports its
           ;; comment the ordinary way.
           (multiple-value-bind (status output)
               (keygen-call (list "-c" "-C" "" "-P" ""
                                  "-f" (namestring clear)))
             (is (eql 0 status))
             (is (search "Old comment: new comment" output))
             (is (search "Comment removed" output)))
           (is (string= "" (keygen-public-comment-of public)))
           (keygen-write-pem locked +keygen-pem-rsa-encrypted+)
           (multiple-value-bind (status output)
               (keygen-call (list "-c" "-C" "locked comment"
                                  "-P" +keygen-pem-passphrase+
                                  "-f" (namestring locked)))
             (is (eql 0 status))
             (is (search "No existing comment" output)))
           (is (cl-pnet-ssh:ssh-private-key-file-encrypted-p locked))
           (is (string= "locked comment"
                        (cl-pnet-ssh:ssh-private-key-comment
                         (cl-pnet-ssh:ssh-load-private-key
                          locked :passphrase +keygen-pem-passphrase+)))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-passphrase-change-reports-and-keeps-comment
  ;; -p prints both messages even under -q, rewrites only the private key,
  ;; and keeps the comment.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory))
         (public (burs::keygen-public-path path)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" (namestring path)
                                "-N" "" "-C" "keep@example" "-q")))))
           (let ((before (with-open-file (stream public)
                           (read-line stream))))
             (multiple-value-bind (status output)
                 (keygen-call
                  (list "-p" "-P" "" "-N" "new-pw"
                        "-f" (namestring path) "-q"))
               (is (eql 0 status))
               (is (search "Key has comment 'keep@example'" output))
               (is (search "Your identification has been saved with the new passphrase."
                           output)))
             (is (cl-pnet-ssh:ssh-private-key-file-encrypted-p path))
             (is (string= "keep@example"
                          (cl-pnet-ssh:ssh-private-key-comment
                           (cl-pnet-ssh:ssh-load-private-key
                            path :passphrase "new-pw"))))
             (with-open-file (stream public)
               (is (string= before (read-line stream))))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-ciphers-match-openssh-key-files
  ;; -Z takes every cipher ssh-keygen 10.6 knows for private keys; each one
  ;; writes a file that reads back, and the authenticated ciphers keep
  ;; their tag outside the private section string.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (ciphers '("none" "3des-cbc"
                    "aes128-cbc" "aes192-cbc" "aes256-cbc"
                    "aes128-ctr" "aes192-ctr" "aes256-ctr"
                    "aes128-gcm@openssh.com" "aes256-gcm@openssh.com"
                    "chacha20-poly1305@openssh.com")))
    (ensure-directories-exist directory)
    (unwind-protect
         (progn
           (dolist (cipher ciphers)
             (let ((path (merge-pathnames
                          (format nil "key-~A" cipher) directory)))
               (multiple-value-bind (status output error)
                   (keygen-call (list "-q" "-t" "ed25519" "-N" "pw"
                                      "-Z" cipher "-f" (namestring path)))
                 (declare (ignore output))
                 (is (eql 0 status) "~A generation: ~A" cipher error))
               (multiple-value-bind (status output error)
                   (keygen-call (list "-y" "-P" "pw" "-f" (namestring path)))
                 (declare (ignore error))
                 (is (eql 0 status) cipher)
                 (is (search "ssh-ed25519 " output)))
               ;; A bcrypt KDF demands the passphrase even under the none
               ;; cipher, and end of input counts as a wrong one.
               (multiple-value-bind (status output error)
                   (keygen-call (list "-y" "-f" (namestring path)))
                 (declare (ignore output))
                 (is (eql 255 status) cipher)
                 (is (search "incorrect passphrase supplied" error)))
               ;; -l reads the cleartext public header and never prompts.
               (multiple-value-bind (status output error)
                   (keygen-call (list "-l" "-f" (namestring path)))
                 (declare (ignore error))
                 (is (eql 0 status) cipher)
                 (is (search "SHA256:" output)))
               ;; -p rewrites the file with the same cipher.
               (multiple-value-bind (status output error)
                   (keygen-call (list "-p" "-P" "pw" "-N" "pw2"
                                      "-Z" cipher "-q"
                                      "-f" (namestring path)))
                 (declare (ignore output error))
                 (is (eql 0 status) cipher))
               (multiple-value-bind (status output error)
                   (keygen-call (list "-y" "-P" "pw2" "-f" (namestring path)))
                 (declare (ignore error))
                 (is (eql 0 status) cipher)
                 (is (search "ssh-ed25519 " output)))))
           ;; Anything outside ssh-keygen's table is refused at once.
           (multiple-value-bind (status output error)
               (keygen-call
                (list "-q" "-t" "ed25519" "-N" "pw" "-Z" "twofish-cbc"
                      "-f" (namestring (merge-pathnames "bad" directory))))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search "Invalid OpenSSH-format cipher 'twofish-cbc'" error))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-comment-change-prompts-and-stops-at-end-of-input
  ;; -c names the current comment, prompts with ssh-keygen's "New comment:",
  ;; and treats end of input as a cancellation with status 1.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory))
         (public (burs::keygen-public-path path)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" (namestring path)
                                "-N" "" "-C" "before" "-q")))))
           (multiple-value-bind (status output)
               (keygen-call (list "-c" "-f" (namestring path)) :input "")
             (is (eql 1 status))
             (is (search "Old comment: before" output))
             (is (search "New comment: " output)))
           (is (string= "before"
                        (cl-pnet-ssh:ssh-private-key-comment
                         (cl-pnet-ssh:ssh-load-private-key path))))
           (multiple-value-bind (status output)
               (keygen-call (list "-c" "-f" (namestring path))
                            :input (format nil "fresh comment~%"))
             (is (eql 0 status))
             (is (search "Old comment: before" output))
             (is (search "Comment 'fresh comment' applied" output)))
           (is (string= "fresh comment"
                        (cl-pnet-ssh:ssh-private-key-comment
                         (cl-pnet-ssh:ssh-load-private-key path))))
           (with-open-file (stream public)
             (is (search "fresh comment" (read-line stream))))
           ;; Rewriting with the same comment changes nothing.
           (multiple-value-bind (status output)
               (keygen-call (list "-c" "-C" "fresh comment"
                                  "-f" (namestring path)))
             (is (eql 0 status))
             (is (search "No change to comment" output))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-comment-change-accepts-new-passphrase-as-the-opener
  ;; ssh-keygen uses -N as the passphrase that opens a protected key when
  ;; -P is absent, and keeps the key protected under it.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" (namestring path)
                                "-N" "pw" "-C" "before" "-q")))))
           (multiple-value-bind (status output)
               (keygen-call
                (list "-c" "-C" "after" "-N" "pw"
                      "-f" (namestring path)))
             (is (eql 0 status))
             (is (search "Comment 'after' applied" output)))
           (is (cl-pnet-ssh:ssh-private-key-file-encrypted-p path))
           (is (string= "after"
                        (cl-pnet-ssh:ssh-private-key-comment
                         (cl-pnet-ssh:ssh-load-private-key
                          path :passphrase "pw")))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-find-host-prints-matching-lines-and-fingerprints
  ;; -F repeats every matching known_hosts line, and -l turns that into
  ;; HOST TYPE FINGERPRINT [COMMENT]; -B selects Bubble Babble and -q
  ;; hides the "# Host ... found" banner.  Marker and hashed lines match too.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory))
         (known (merge-pathnames "known_hosts" directory)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" (namestring path)
                                "-N" "" "-C" "alice@example" "-q")))))
           (multiple-value-bind (type blob comment)
               (keygen-public-parts (burs::keygen-public-path path))
             (let* ((octets (cl-pnet-ssh:ssh-base64-octets blob))
                    (fingerprint (cl-pnet-ssh:ssh-key-fingerprint octets :sha256))
                    (bubble (cl-pnet-ssh:ssh-key-bubblebabble octets)))
               (with-open-file (stream known :direction :output
                                             :if-exists :supersede
                                             :if-does-not-exist :create
                                             :external-format :utf-8)
                 (format stream "a.example ~A ~A ~A~%" type blob comment)
                 (format stream "~A ~A ~A~%"
                         (cl-pnet-ssh::ssh-hashed-known-host "a.example")
                         type blob)
                 (format stream "@cert-authority *.example ~A ~A ca@example~%"
                         type blob))
               (multiple-value-bind (status output)
                   (keygen-call (list "-F" "a.example" "-f" (namestring known)))
                 (is (eql 0 status))
                 (is (= 6 (count #\Newline output)))
                 (is (search "# Host a.example found: line 1 " output))
                 (is (search (format nil "a.example ~A ~A ~A"
                                     type blob comment)
                             output)))
               (multiple-value-bind (status output)
                   (keygen-call
                    (list "-F" "a.example" "-l" "-f" (namestring known)))
                 (is (eql 0 status))
                 (is (search (format nil "a.example ED25519 ~A alice@example"
                                     fingerprint)
                             output))
                 ;; The hashed line has no comment, so no trailing space.
                 (is (search (format nil "a.example ED25519 ~A~%"
                                     fingerprint)
                             output))
                 (is (search (format nil "a.example ED25519 ~A ca@example"
                                     fingerprint)
                             output))
                 (is (search "# Host a.example found: line 3 CA" output)))
               (multiple-value-bind (status output)
                   (keygen-call
                    (list "-F" "a.example" "-l" "-B"
                          "-f" (namestring known)))
                 (is (eql 0 status))
                 (is (search (format nil "a.example ED25519 ~A alice@example"
                                     bubble)
                             output)))
               (multiple-value-bind (status output)
                   (keygen-call
                    (list "-F" "a.example" "-l" "-q"
                          "-f" (namestring known)))
                 (is (eql 0 status))
                 (is (not (search "# Host" output)))
                 (is (search fingerprint output)))
               (multiple-value-bind (status output)
                   (keygen-call
                    (list "-F" "absent.invalid" "-f" (namestring known)))
                 (is (eql 1 status))
                 (is (zerop (length output)))))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-generation-reads-piped-passphrases
  ;; Without -N ssh-keygen reads the answer from standard input even when
  ;; it is a pipe, asks twice, and retries a mismatch.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (retry (merge-pathnames "retry" directory))
         (empty (merge-pathnames "empty" directory)))
    (ensure-directories-exist retry)
    (unwind-protect
         (progn
           (multiple-value-bind (status output error)
               (keygen-call
                (list "-t" "ed25519" "-f" (namestring retry) "-q")
                :input (format nil "one~%two~%three~%three~%"))
             (is (eql 0 status))
             ;; 10.6 names the file the passphrase will protect.
             (is (search
                  (format nil "Enter passphrase for \"~A\" (empty for no passphrase): "
                          (namestring retry))
                  error))
             (is (search "Passphrases do not match.  Try again." output)))
           (is (cl-pnet-ssh:ssh-private-key-file-encrypted-p retry))
           (is (string= "ssh-ed25519"
                        (cl-pnet-ssh:ssh-private-key-type
                         (cl-pnet-ssh:ssh-load-private-key
                          retry :passphrase "three"))))
           ;; End of input stands for an empty passphrase, so no encryption.
           (multiple-value-bind (status)
               (keygen-call
                (list "-t" "ed25519" "-f" (namestring empty) "-q")
                :input "")
             (is (eql 0 status)))
           (is (not (cl-pnet-ssh:ssh-private-key-file-encrypted-p empty))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-print-public-prompts-for-a-passphrase
  ;; Without -P, -y asks for the passphrase on standard input and reports
  ;; ssh-keygen's Load key message when it does not decrypt the key.  An
  ;; explicit empty -P is used as-is, so it does not prompt.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" (namestring path)
                                "-N" "pw" "-q")))))
           (multiple-value-bind (status output error)
               (keygen-call (list "-y" "-f" (namestring path))
                            :input (format nil "pw~%"))
             (is (eql 0 status))
             (is (search "ssh-ed25519" output))
             (is (search (format nil "Enter passphrase for \"~A\": "
                                 (namestring path))
                         error)))
           (multiple-value-bind (status output error)
               (keygen-call (list "-y" "-f" (namestring path)) :input "")
             (declare (ignore output))
             (is (eql 255 status))
             (is (search "Load key" error))
             (is (search "incorrect passphrase supplied to decrypt private key"
                         error)))
           (multiple-value-bind (status output error)
               (keygen-call (list "-y" "-P" "" "-f" (namestring path))
                            :input (format nil "pw~%"))
             (declare (ignore output))
             (is (eql 255 status))
             (is (not (search "Enter passphrase" error)))
             (is (search "Load key" error))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-passphrase-change-prompts-for-the-new-passphrase
  ;; -p reads the new passphrase twice, gives up on a mismatch with status
  ;; 1 and touches nothing, and reports a wrong old passphrase as ssh-keygen
  ;; does.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" (namestring path)
                                "-N" "old" "-q")))))
           (multiple-value-bind (status output error)
               (keygen-call (list "-p" "-P" "old" "-f" (namestring path))
                            :input (format nil "a~%b~%"))
             (is (eql 1 status))
             (is (search "Pass phrases do not match.  Try again." output))
             (is (search "Enter new passphrase (empty for no passphrase): "
                         error)))
           (is (cl-pnet-ssh:ssh-private-key-file-encrypted-p path))
           (is (string= "ssh-ed25519"
                        (cl-pnet-ssh:ssh-private-key-type
                         (cl-pnet-ssh:ssh-load-private-key
                          path :passphrase "old"))))
           (multiple-value-bind (status)
               (keygen-call (list "-p" "-P" "old" "-f" (namestring path))
                            :input (format nil "new~%new~%"))
             (is (eql 0 status)))
           (is (string= "ssh-ed25519"
                        (cl-pnet-ssh:ssh-private-key-type
                         (cl-pnet-ssh:ssh-load-private-key
                          path :passphrase "new"))))
           (multiple-value-bind (status output error)
               (keygen-call (list "-p" "-P" "wrong" "-N" "other"
                                  "-f" (namestring path)))
             (declare (ignore output))
             (is (eql 255 status))
             (is (search "Failed to load key" error))
             (is (search "incorrect passphrase supplied to decrypt private key"
                         error)))
           ;; An explicit empty -P is used without asking.
           (multiple-value-bind (status output error)
               (keygen-call (list "-p" "-P" "" "-N" "other"
                                  "-f" (namestring path))
                            :input (format nil "new~%"))
             (declare (ignore output))
             (is (eql 255 status))
             (is (not (search "Enter old passphrase" error)))
             (is (search "Failed to load key" error))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-comment-change-prompts-for-the-opener
  ;; -c without -P or -N asks for the passphrase that opens the key and
  ;; keeps the key protected by it.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (is (eql 0 (nth-value
                       0 (keygen-call
                          (list "-t" "ed25519" "-f" (namestring path)
                                "-N" "pw" "-C" "before" "-q")))))
           (multiple-value-bind (status output error)
               (keygen-call (list "-c" "-C" "after" "-f" (namestring path))
                            :input (format nil "pw~%"))
             (is (eql 0 status))
             (is (search "Enter passphrase: " error))
             (is (search "Comment 'after' applied" output)))
           (is (cl-pnet-ssh:ssh-private-key-file-encrypted-p path))
           (is (string= "after"
                        (cl-pnet-ssh:ssh-private-key-comment
                         (cl-pnet-ssh:ssh-load-private-key
                          path :passphrase "pw")))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test keygen-overwrite-question-matches-ssh-keygen
  ;; The question is asked even without a terminal, and any answer other
  ;; than y (including end of input) cancels with ssh-keygen's status 1.
  ;; Only y replaces the key.
  (let* ((directory (merge-pathnames
                     (format nil "burs-keygen-~D-~D/"
                             (get-universal-time) (random 1000000))
                     (uiop:temporary-directory)))
         (path (merge-pathnames "id_ed25519" directory)))
    (ensure-directories-exist path)
    (unwind-protect
         (progn
           (with-open-file (stream path :direction :output
                                        :if-exists :supersede
                                        :if-does-not-exist :create)
             (write-line "existing" stream))
           (multiple-value-bind (status output)
               (keygen-call
                (list "-t" "ed25519" "-f" (namestring path) "-N" "" "-q")
                :input "")
             (is (eql 1 status))
             (is (search "already exists." output))
             (is (search "Overwrite (y/n)?" output)))
           (dolist (answer (list (format nil "n~%") (format nil "nope~%")
                                 (format nil "~%")))
             (multiple-value-bind (status)
                 (keygen-call
                  (list "-t" "ed25519" "-f" (namestring path) "-N" "" "-q")
                  :input answer)
               (is (eql 1 status)))
             (with-open-file (stream path)
               (is (string= "existing" (read-line stream)))))
           (multiple-value-bind (status)
               (keygen-call
                (list "-t" "ed25519" "-f" (namestring path) "-N" "" "-q")
                :input (format nil "y~%"))
             (is (eql 0 status)))
           (with-open-file (stream path)
             (is (not (string= "existing" (read-line stream))))))
      (ignore-errors (uiop:delete-directory-tree directory :validate t)))))

(test command-line-name-validation
  "The command line rejects what ssh_valid_hostname and ssh_valid_ruser do."
  (is (burs::ssh-valid-hostname-p "example.com"))
  (is (burs::ssh-valid-hostname-p "::1"))
  (is (burs::ssh-valid-hostname-p "127.0.0.1"))
  (is (not (burs::ssh-valid-hostname-p "")))
  (is (not (burs::ssh-valid-hostname-p "-host")))
  (is (not (burs::ssh-valid-hostname-p "a b")))
  (is (not (burs::ssh-valid-hostname-p "a,b")))
  (is (not (burs::ssh-valid-hostname-p "a;b")))
  (is (not (burs::ssh-valid-hostname-p "a`b")))
  (is (burs::ssh-valid-ruser-p "a b"))
  (is (burs::ssh-valid-ruser-p "a--b"))
  (is (burs::ssh-valid-ruser-p "ab-"))
  (is (not (burs::ssh-valid-ruser-p "")))
  (is (not (burs::ssh-valid-ruser-p "-x")))
  (is (not (burs::ssh-valid-ruser-p "a -b")))
  (is (not (burs::ssh-valid-ruser-p "a;b")))
  (is (not (burs::ssh-valid-ruser-p "a$b"))))
