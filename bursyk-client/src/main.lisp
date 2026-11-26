(in-package #:burs)

;;;; A small SSH client command line over cl-pnet-ssh.  It runs one command
;;;; on the remote host and streams its output and stdin, without blocking the
;;;; event loop: stdin is watched with CL-PNET:FD-WATCH, never read in a loop.
;;;;
;;;; The option surface follows ssh(1): the same short flags, clustered where
;;;; they are flags and with an attached value where they take one.  Features
;;;; the selected transport cannot honour (X11 forwarding, remote forwarding,
;;;; PKCS#11, TUN devices) are refused with a diagnostic instead of being
;;;; silently ignored.  GSSAPIAuthentication is only a switch for a method this
;;;; build lacks, so a config that sets it is ignored as OpenSSH without GSSAPI
;;;; ignores it; -K and -k are accepted for the same reason.

;;; ---- Command line ----

(defun print-version ()
  (format t "burs ~A~%" +burs-version+)
  (finish-output))

(defun fail (format-string &rest arguments)
  (format *error-output* "burs: ~?~%" format-string arguments)
  (finish-output *error-output*)
  (restore-terminal)
  (uiop:quit 255))

(defvar *config-error-reported* nil
  "Whether a readconf-style configuration diagnostic has been printed.

The library writes each rejected line and the file's terminating summary
itself when SSH-CONFIG-ERROR-FUNCTION is bound, so the condition that ends
resolution must not be printed a second time.")

(defun fail-config-error (condition)
  "Leave after CONDITION stopped configuration resolution.

When the library already printed readconf's lines, only the exit status is
left to do; otherwise the condition is the whole diagnostic."
  (if *config-error-reported*
      (progn
        (restore-terminal)
        (uiop:quit 255))
      (fail "~A" condition)))

(defun unsupported (option &optional (detail "not implemented by this client"))
  (fail "~A is not supported: ~A" option detail))

(defun split-destination (destination)
  "DESTINATION as (VALUES HOST USER), splitting USER@HOST at the last @.

ssh.c looks for the last at-sign, so `a@b@host' names user `a@b' and host
`host'."
  (let ((at (position #\@ destination :from-end t)))
    (if at
        (values (subseq destination (1+ at)) (subseq destination 0 at))
        (values destination nil))))

(defun destination-usage ()
  "Leave as ssh.c's usage(): explain the grammar and exit 255."
  (clingon:print-usage *burs-command* *error-output*)
  (finish-output *error-output*)
  (restore-terminal)
  (uiop:quit 255))

(defun resolve-destination (destination &optional user port)
  "DESTINATION as ssh.c takes it: (VALUES HOST USER PORT).

An ssh:// URI is parsed first; otherwise the text is split at its last
at-sign.  ssh fills options.user and options.port only while they are still
unset, so -l, -o User, -p and -o Port all win over what the destination
names; USER and PORT are those already-decided values.  An empty user, a
malformed URI, or a URI with a path reaches ssh.c's usage(), which leaves
at once."
  (multiple-value-bind (kind uri-user uri-host uri-port)
      (cl-pnet-ssh::ssh-config-uri-destination destination)
    (cond
      ((null kind) (destination-usage))
      ((eq kind :uri)
       (values uri-host
               (or user uri-user)
               (or port
                   (and (/= uri-port -1) (format nil "~D" uri-port)))))
      (t
       (multiple-value-bind (host split-user) (split-destination destination)
         (when (and split-user (zerop (length split-user)))
           (destination-usage))
         (values host (or user split-user) port))))))

;;; ssh(1)'s option surface, built once as a CLINGON command.  CLINGON parses
;;; the clustered and attached forms (-vvT, -p2222, -oPort=22), writes the
;;; help text, and reports unknown options and missing values.  The parser
;;; here only finds the destination first, because ssh stops looking for
;;; options there and CLINGON does not.

(defvar *burs-command* nil
  "The command parsed most recently, so MAIN can print its usage.")

(defvar *forwarding-command-line-kind* nil
  "The -L/-R/-D/-W option whose specification is being parsed, or NIL.

ssh validates a command-line forwarding specification while it reads its
arguments and prints one bare line, so a parse failure there has to say which
flag it came from instead of the ssh_config wording used later.  The scanner
that binds it runs before this file's definition of FORWARDING-FAIL, so the
declaration lives here.")

(defvar *forwarding-escape-kind* nil
  "The -L/-R/-D command line being parsed, when it came from the ~C console.

A bad specification there is a logit() line and goes back to the session, not
the command-line fatal ssh uses while reading argv.")

(defun burs-flag (key description &key short long)
  (clingon:make-option :flag
                       :key key
                       :description description
                       :short-name short
                       :long-name long))

(defun burs-string (key description &key short long (parameter "VALUE"))
  (clingon:make-option :string
                       :key key
                       :description description
                       :short-name short
                       :long-name long
                       :parameter parameter))

(defun burs-list (key description &key short long (parameter "VALUE"))
  "An option that may repeat, keeping the values in command-line order."
  (clingon:make-option :list
                       :key key
                       :description description
                       :short-name short
                       :long-name long
                       :parameter parameter))

(defun make-burs-options ()
  "A fresh option set for one parse.

CLINGON keeps the parsed value in the option object, so building new ones
for every invocation keeps two parses from sharing state."
  (list
   ;; -a and -A keep ssh's meanings.  -a is inert because this client never
   ;; forwards the agent; the agent *picker* is --agent or -o IdentityAgent=.
   (burs-flag :forward-agent "Forward the authentication agent" :short #\A)
   (burs-flag :no-forward-agent "Do not forward the authentication agent"
              :short #\a)
   (burs-flag :compression "Request compression" :short #\C
              :long "compression")
   (burs-flag :background "Background before command execution" :short #\f
              :long "background")
   (burs-flag :background-child "Internal: signal the waiting parent"
              :long "background-child")
   (burs-flag :control-master-daemon
              "Internal: keep a control master alive"
              :long "control-master-daemon")
   (burs-flag :print-config "Print the effective configuration and exit"
              :short #\G :long "print-config")
   (burs-flag :gateway-ports "Allow remote hosts to use forwarded ports"
              :short #\g :long "gateway-ports")
   ;; ssh still accepts the protocol flags so old scripts do not trip over
   ;; them: -1 is refused because protocol 1 is gone, -2 is the default and
   ;; is ignored.
   (burs-flag :protocol-1 "Request SSH protocol 1 (refused)" :short #\1)
   (burs-flag :protocol-2 "Request SSH protocol 2 (the default)" :short #\2)
   (burs-flag :gssapi-auth "Enable GSSAPI authentication" :short #\K)
   (burs-flag :no-gssapi-auth "Disable GSSAPI authentication" :short #\k)
   (burs-flag :control-master "Enable control-master mode" :short #\M)
   (burs-flag :no-command "Do not execute a remote command" :short #\N
              :long "no-command")
   (burs-flag :stdin-null "Redirect stdin from /dev/null" :short #\n
              :long "stdin-null")
   (burs-flag :quiet "Suppress diagnostic messages" :short #\q
              :long "quiet")
   (burs-flag :request-tty-no "Disable pseudo-terminal allocation" :short #\T)
   (burs-flag :request-tty-force "Force pseudo-terminal allocation" :short #\t)
   (burs-flag :subsystem "Request a subsystem; the name follows the destination"
              :short #\s :long "subsystem")
   (burs-flag :x11-yes "Forward the X11 display" :short #\X)
   (burs-flag :x11-no "Do not forward the X11 display" :short #\x)
   (burs-flag :x11-trust "Forward X11 with trusted cookies" :short #\Y)
   (burs-flag :version "Display the client version and exit" :short #\V
              :long "version")
   (burs-flag :dump-public-keys "Dump the public keys and exit" :short #\Z)
   (clingon:make-option :counter
                        :key :verbose
                        :description "Increase logging verbosity (repeatable)"
                        :short-name #\v
                        :long-name "verbose")
   (burs-flag :address-family-4 "Use IPv4 only" :short #\4)
   (burs-flag :address-family-6 "Use IPv6 only" :short #\6)
   (burs-string :bind-interface "Bind the source to an interface"
                :short #\B :long "bind-interface" :parameter "INTERFACE")
   (burs-string :bind-address "Bind the source to a local address"
                :short #\b :long "bind-address" :parameter "ADDRESS")
   (burs-string :ciphers "Select the cipher specification"
                :short #\c :long "ciphers" :parameter "SPEC")
   (burs-list :dynamic-forward "Dynamic SOCKS forwarding"
              :short #\D :long "dynamic-forward" :parameter "ADDRESS")
   (burs-string :log-file "Append debug output to a file"
                :short #\E :long "log-file" :parameter "FILE")
   (burs-string :escape-char "Set the escape character"
                :short #\e :parameter "CHAR")
   (burs-string :config "Read an alternative ssh_config file"
                :short #\F :long "config" :parameter "FILE")
   (burs-string :pkcs11 "Use a PKCS#11 provider" :short #\I
                :parameter "PROVIDER")
   (burs-list :identity "Select a private key file" :short #\i
              :long "identity" :parameter "FILE")
   (burs-string :jump "Connect through a jump host" :short #\J
                :long "jump" :parameter "DESTINATION")
   (burs-list :local-forward "Forward a local port to the remote side"
              :short #\L :long "local-forward" :parameter "SPEC")
   (burs-string :user "Specify the remote login name" :short #\l
                :long "user" :parameter "NAME")
   (burs-string :macs "Select the MAC specification" :short #\m
                :long "macs" :parameter "SPEC")
   (burs-string :control-command "Control a running master connection"
                :short #\O :parameter "COMMAND")
   (burs-list :options "Set an ssh_config option" :short #\o
              :long "option" :parameter "OPTION")
   (burs-string :port "Connect to this remote port" :short #\p
                :long "port" :parameter "PORT")
   (burs-string :query "Query supported algorithms and exit" :short #\Q
                :parameter "QUERY")
   (burs-list :remote-forward "Forward a remote port to the local side"
              :short #\R :long "remote-forward" :parameter "SPEC")
   (burs-string :control-path "Use this control socket" :short #\S
                :parameter "PATH")
   (burs-string :stdio-forward "Forward stdin and stdout to a remote host"
                :short #\W :long "stdio-forward" :parameter "HOST:PORT")
   (burs-string :tunnel "Tunnel a TUN device" :short #\w
                :parameter "LOCAL[:REMOTE]")
   (burs-string :tag "Tag this connection for ssh_config selection"
                :short #\P :parameter "TAG")
   ;; The readable spellings this client has always had.  ssh itself spells
   ;; everything through -o.
   (burs-string :address-family "Select the address family"
                :long "address-family" :parameter "FAMILY")
   (burs-string :agent "Select the authentication agent socket"
                :long "agent" :parameter "SOCKET")
   (burs-string :known-hosts "Read known hosts from this file"
                :long "known-hosts" :parameter "FILE")
   (burs-string :request-tty "Control pseudo-terminal allocation"
                :long "request-tty" :parameter "STATE")))

(defun make-burs-command ()
  (let ((command
          (clingon:make-command
           :name "burs"
           :description "Connect to a remote host over SSH"
           :version +burs-version+
           :usage "[options] destination [command [argument ...]]"
           :options (make-burs-options))))
    ;; ssh spells the version flag -V and prints one line.  CLINGON's own
    ;; --version would print "burs version ...", so drop that default and
    ;; keep the --version/-V pair defined above.  ssh has no --help either:
    ;; like any other unknown option it is a one-line refusal and the usage
    ;; text, so CLINGON's default help flag is dropped as well.
    (setf (clingon:command-options command)
          (remove-if (lambda (option)
                       (let ((long (clingon:option-long-name option)))
                         (or (eq option clingon:*default-version-flag*)
                             (and long (string= long "help")))))
                     (clingon:command-options command)))
    command))

(defun find-burs-short-option (command character)
  (find character (clingon:command-options command)
        :key (lambda (option)
               (or (clingon:option-short-name option) #\Nul))
        :test #'char=))

(defun find-burs-long-option (command name)
  (find name (clingon:command-options command)
        :key (lambda (option) (or (clingon:option-long-name option) ""))
        :test #'string=))

(defun split-at-destination (arguments command)
  "Split ARGUMENTS at the destination, normalising long option names.

Returns (VALUES OPTION-ARGUMENTS DESTINATION COMMAND-ARGUMENTS).  ssh(1)
takes the first non-option word as the destination and then restarts its
option scan, so options may also appear between the destination and the
remote command.  The first word after that which is not an option begins
the command, whose own arguments are left alone: `uname -a' must not have
its -a read as an ssh flag.  CLINGON keeps parsing options among free
arguments, so the destination and the command are handed to it behind `--'.

The scan also lower-cases a long option name and expands the
--identity-file alias, which CLINGON would otherwise take literally."
  (let ((option-arguments '())
        (remaining arguments)
        (destination nil)
        (command-arguments nil))
    (labels
        ((take-value ()
           (let ((value (pop remaining)))
             (when value
               (push value option-arguments))))
         (scan-short (argument)
           (push argument option-arguments)
           (loop with length = (length argument)
                 for index from 1 below length
                 for option = (find-burs-short-option
                               command (char argument index))
                 do (cond
                      ((null option)
                       ;; CLINGON reports the unknown option itself.
                       (return))
                      ((clingon:option-parameter option)
                       ;; A value attached to the option (-p2222) is already
                       ;; in this argument; otherwise it is the next one.
                       (when (= (1+ index) length)
                         (take-value))
                       (return)))))
         (scan-long (argument)
           (let* ((equals (position #\= argument))
                  (end (or equals (length argument)))
                  (name (string-downcase (subseq argument 2 end)))
                  (name (if (string= name "identity-file") "identity" name))
                  (token (concatenate 'string
                                      "--" name
                                      (if equals (subseq argument equals) "")))
                  (option (find-burs-long-option command name)))
             (push token option-arguments)
             (when (and (null equals)
                        option
                        (clingon:option-parameter option))
               (take-value))))
         (scan-option (argument)
           (cond
             ((and (> (length argument) 2)
                   (char= (char argument 0) #\-)
                   (char= (char argument 1) #\-))
              (scan-long argument)
              t)
             ((and (> (length argument) 1)
                   (char= (char argument 0) #\-))
              (scan-short argument)
              t)
             (t nil)))
         (finish ()
           (values (nreverse option-arguments) destination command-arguments)))
      (loop
        for argument = (pop remaining)
        do (cond
             ((null argument) (return (finish)))
             ((string= argument "--")
              (setf destination (pop remaining)
                    command-arguments remaining)
              (return (finish)))
             ((scan-option argument))
             (t
              (setf destination argument)
              (return
               (loop
                 for word = (pop remaining)
                 do (cond
                      ((null word) (return (finish)))
                      ((string= word "--")
                       (setf command-arguments remaining)
                       (return (finish)))
                      ((scan-option word))
                      (t
                       (setf command-arguments (cons word remaining))
                       (return (finish))))))))))))

(defun parsed-list (command key)
  "The values of KEY in command-line order, or NIL."
  (reverse (clingon:getopt command key)))

(defun apply-parsed-options (command arguments)
  "Copy COMMAND's values into *OPTIONS*.

Every key is written, even when it is NIL, so a second parse cannot inherit
a value from the first.  The list options are stored in reverse, which is
the order the old push-based parser kept them in."
  (let ((getopt (lambda (key) (clingon:getopt command key))))
    (labels ((value (key) (funcall getopt key))
             (flag (key) (funcall getopt key)))
      (setf (getf *options* :port) (value :port)
            (getf *options* :user) (value :user)
            ;; -i only.  -o IdentityFile values are pushed into :IDENTITY
            ;; later, and ssh -Z has to tell the two apart: readconf records
            ;; -i as userprovided 1 and -o as 2, so their duplicate paths do
            ;; not collapse together.
            (getf *options* :identity-arguments)
            (parsed-list command :identity)
            (getf *options* :identity) (parsed-list command :identity)
            (getf *options* :config) (value :config)
            (getf *options* :known-hosts) (value :known-hosts)
            (getf *options* :policy) nil
            (getf *options* :agent) (value :agent)
            (getf *options* :options) (parsed-list command :options)
            (getf *options* :jump) (value :jump)
            (getf *options* :proxy-command) nil
            (getf *options* :verbose) (or (value :verbose) 0)
            (getf *options* :quiet) (flag :quiet)
            (getf *options* :log-level) (and (flag :quiet) "quiet")
            (getf *options* :log-file) (value :log-file)
            (getf *options* :address-family)
            (cond ((flag :address-family-4) "inet")
                  ((flag :address-family-6) "inet6")
                  (t (value :address-family)))
            (getf *options* :ciphers) (value :ciphers)
            (getf *options* :macs) (value :macs)
            (getf *options* :kex-algorithms) nil
            (getf *options* :compression) (flag :compression)
            (getf *options* :request-tty)
            (or (command-line-request-tty-state command arguments)
                (value :request-tty))
            (getf *options* :forward-agent)
            (cond ((flag :forward-agent) t)
                  ((flag :no-forward-agent) :no)
                  (t nil))
            (getf *options* :gateway-ports) (flag :gateway-ports)
            (getf *options* :no-command) (flag :no-command)
            (getf *options* :stdin-null) (flag :stdin-null)
            (getf *options* :subsystem) (flag :subsystem)
            (getf *options* :stdio-forward) (value :stdio-forward)
            (getf *options* :local-forward) (parsed-list command :local-forward)
            (getf *options* :remote-forward)
            (parsed-list command :remote-forward)
            (getf *options* :dynamic-forward)
            (parsed-list command :dynamic-forward)
            (getf *options* :query) (value :query)
            (getf *options* :help) nil
            (getf *options* :version) (flag :version)
            (getf *options* :print-config) (flag :print-config)
            (getf *options* :dump-public-keys) (flag :dump-public-keys)
            (getf *options* :background) (flag :background)
            (getf *options* :background-child) (flag :background-child)
            (getf *options* :control-master-daemon)
            (flag :control-master-daemon)
            (getf *options* :control-master) (flag :control-master)
            (getf *options* :control-path) (value :control-path)
            (getf *options* :control-command) (value :control-command)
            (getf *options* :pkcs11) (value :pkcs11)
            (getf *options* :bind-interface) (value :bind-interface)
            (getf *options* :bind-address) (value :bind-address)
            (getf *options* :protocol-1) (flag :protocol-1)
            (getf *options* :protocol-2) (flag :protocol-2)
            (getf *options* :tag) (value :tag)
            (getf *options* :gssapi-auth) (flag :gssapi-auth)
            (getf *options* :tunnel) (value :tunnel)
            (getf *options* :x11-forward)
            (cond ((flag :x11-yes) :yes)
                  ((flag :x11-trust) :trust)
                  ((flag :x11-no) :no)
                  (t nil))
            (getf *options* :escape-char) (value :escape-char)))
    (values)))

(defun parse-arguments (arguments)
  "Fill *OPTIONS* from ARGUMENTS; return (VALUES DESTINATION COMMAND).

CLINGON parses the options and produces the help.  Splitting the line at the
destination first is the one part of ssh(1)'s grammar CLINGON does not
model: after the destination everything belongs to the remote command."
  (let ((command (make-burs-command)))
    (multiple-value-bind (option-arguments destination command-arguments)
        (split-at-destination arguments command)
      (setf *burs-command* command)
      (handler-case
          (let* ((line (append option-arguments
                               (when destination
                                 (cons "--"
                                       (cons destination command-arguments)))))
                 (parsed (clingon:parse-command-line command line))
                 (free (clingon:command-arguments parsed)))
            (apply-parsed-options parsed arguments)
            (values (first free) (rest free)))
        (clingon:exit-error (condition)
          ;; --help and --version have already written their answer.
          (uiop:quit (clingon:exit-error-code condition)))
        (clingon:unknown-option (condition)
          (fail "unknown option ~A" (clingon:unknown-option-name condition)))
        (clingon:missing-option-argument (condition)
          (let ((option (clingon:missing-option-argument-item condition)))
            (fail "~A needs a value"
                  (if (clingon:option-short-name option)
                      (format nil "-~A" (clingon:option-short-name option))
                      (format nil "--~A"
                              (clingon:option-long-name option))))))
        (clingon:missing-required-option-value (condition)
          (fail "~A" condition))
        (clingon:option-derive-error (condition)
          (fail "~A" condition))))))

;;; ---- Checking what this client can actually do ----

(defun split-list (text)
  "TEXT as a comma-separated list of names, trimming and dropping empties."
  (loop with start = 0
        for comma = (position #\, text :start start)
        for piece = (string-trim '(#\Space #\Tab)
                                 (subseq text start comma))
        when (plusp (length piece)) collect piece
        while comma
        do (setf start (1+ comma))))

(defun transport-supports-algorithm-p (name kind)
  "Whether this build's client transport can negotiate NAME as KIND.

KIND is one of the facade's capability kinds: :KEX, :HOST-KEY-ALGORITHMS,
:SIGNATURE-ALGORITHMS, :CA-SIGNATURE-ALGORITHMS, :CIPHERS, :MACS or
:COMPRESSIONS.  The answer comes from the transport, so a libssh that gains
sntrup is reflected here without a version test."
  (member name (cl-pnet-ssh:ssh-client-supported-algorithms kind)
          :test #'string=))

(defun transport-supported-algorithms (names kind)
  "NAMES filtered to those the transport can negotiate as KIND, in NAMES order."
  (remove-if-not (lambda (name)
                   (transport-supports-algorithm-p name kind))
                 names))

(defun transport-supports-key-type-p (name)
  "Whether NAME is a key type either a host or a user key may use."
  (or (transport-supports-algorithm-p name :host-key-algorithms)
      (transport-supports-algorithm-p name :signature-algorithms)))

(defun supported-kex-algorithms ()
  "Every key exchange this build's transport can actually negotiate.

The transport reports its own KEX names, so OpenSSH's post-quantum hybrids
appear when the library implements them and disappear when it does not, with
no backend or version test here.  -Q kex and KexAlgorithms answer from this
list, so a name the transport cannot use is refused before the connection
instead of after it."
  (transport-supported-algorithms cl-pnet-ssh:+ssh-kex-real-algorithms+
                                  :kex))

(defun default-mac-algorithms ()
  "The MACs this build offers when MACs is not configured, in ssh's order.

The transport drops any construction it cannot negotiate, so UMAC disappears
on a libssh that lacks it and stays when it gains it."
  (transport-supported-algorithms cl-pnet-ssh:+ssh-macs+ :macs))

(defun supported-mac-algorithms ()
  "Every MAC this build's transport can actually negotiate.

The pure transport implements the whole OpenSSH table, including the legacy
MD5 and 96-bit truncated HMACs its default offer leaves out.  A transport
without them simply reports a shorter list."
  (transport-supported-algorithms cl-pnet-ssh:+ssh-all-macs+ :macs))

(defun query-mac-algorithms ()
  "Every MAC the transport can negotiate, in -Q mac's macs[] order.

OpenSSH lists its whole table in that order, which is not the default
preference order."
  (let ((supported (supported-mac-algorithms)))
    (remove-if-not (lambda (name)
                     (member name supported :test #'string=))
                   cl-pnet-ssh:+ssh-all-macs+)))

(defun default-kex-algorithms ()
  "The key exchanges this build offers when KexAlgorithms is not set.

This is OpenSSH's default order, filtered to what the transport can
negotiate.  It offers the ML-KEM and sntrup761 hybrids when the transport has
them, but leaves mlkem768nistp256-sha256 out even though it is implemented;
-G reports this list, as ssh does."
  (transport-supported-algorithms cl-pnet-ssh:+ssh-kex-default-algorithms+
                                  :kex))

(defun supported-host-key-algorithms ()
  "Host key algorithms this build's transport can actually present.
The transport's capability list is authoritative, so the composite ML-DSA
key appears exactly when the library underneath can verify it."
  (transport-supported-algorithms
   cl-pnet-ssh::+ssh-host-key-algorithms+ :host-key-algorithms))

(defun supported-host-key-all-algorithms ()
  "Every host key algorithm HostKeyAlgorithms may name.

The SHA-1 ssh-rsa forms are implemented but outside the default offer, as in
OpenSSH; a configuration may still name them when the transport has them."
  (transport-supported-algorithms
   cl-pnet-ssh::+ssh-host-key-all-algorithms+ :host-key-algorithms))

(defun supported-signature-algorithms ()
  "Signature algorithms this build's transport can actually use.

This is OpenSSH's PubkeyAcceptedAlgorithms order, filtered to names the
transport can verify."
  (transport-supported-algorithms
   cl-pnet-ssh::+ssh-signature-algorithms+ :signature-algorithms))

(defun supported-signature-all-algorithms ()
  "Every signature name PubkeyAcceptedAlgorithms may select.

The SHA-1 ssh-rsa forms are implemented but outside the default offer, as in
OpenSSH; a configuration may still name them when the transport has them."
  (transport-supported-algorithms
   cl-pnet-ssh::+ssh-signature-all-algorithms+ :signature-algorithms))

(defun supported-ca-signature-algorithms ()
  "CA signature algorithms this build's transport can actually check."
  (transport-supported-algorithms
   cl-pnet-ssh::+ssh-server-ca-signature-algorithms+
   :ca-signature-algorithms))

(defun supported-ca-signature-algorithm-names ()
  "Every CA signature algorithm this build's transport can name."
  (transport-supported-algorithms
   cl-pnet-ssh::+ssh-server-ca-signature-algorithm-names+
   :ca-signature-algorithms))

(defun key-algorithm-name-universe (supported)
  "SUPPORTED plus every key type readconf accepts, for config expansion.

The security-key types are not implemented by this transport, but an
ssh_config that names them must still load and `ssh -G` must be able to show
the configured choice rather than failing before the connection."
  (append supported
          (remove-if (lambda (name)
                       (member name supported :test #'string=))
                     cl-pnet-ssh:+ssh-config-unimplemented-key-names+)))

(defun check-algorithm-list (option value supported &optional all)
  "Reject an algorithm choice this build cannot offer.

ssh's +/-^ prefixes and glob patterns are applied exactly as in ssh_config, so
a name this build lacks is an error instead of a silently widened offer.  ALL
is the set a pattern may name when it is wider than the default offer, as it
is for the CBC ciphers."
  (handler-case
      (cl-pnet-ssh:ssh-resolve-algorithm-list (split-list value) supported option
                                              :all (or all supported))
    (cl-pnet-ssh:ssh-config-error (condition)
      ;; Resolution has already printed the readconf line.
      (fail-config-error condition))))

(defun expand-identity-argument (path)
  "PATH with a leading ~ or ~/ expanded, as ssh's -i does."
  (if (and (plusp (length path))
           (char= (char path 0) #\~)
           (or (= (length path) 1)
               (member (char path 1) '(#\/ #\\))))
      (namestring
       (merge-pathnames
        (if (= (length path) 1) "" (subseq path 2))
        (user-homedir-pathname)))
      path))

(defun fail-command-line-option (control &rest arguments)
  "readconf's -o diagnostic: bare, before log_init, exit 255.

parse_command_line_options applies each -o in turn and leaves on the first
rejected one, so there is no file summary after this line."
  (format *error-output* "~A~%"
          (cl-pnet-ssh::ssh-log-escape
           (format nil "command-line line 0: ~?" control arguments)))
  (finish-output *error-output*)
  (restore-terminal)
  (uiop:quit 255))

(defparameter +getopt-mux-commands+
  '("check" "conninfo" "channels" "forward" "exit" "stop" "cancel" "proxy")
  "The -O commands ssh accepts, in its own spelling and order.")

(defun getopt-fatal (control &rest arguments)
  "Leave with CONTROL as ssh's own getopt-time fatal writes it.

These diagnostics are fprintf/fatal calls made while ssh still reads its
arguments, before log_init, so -q and -E do not hide them and no readconf
file summary follows."
  (format *error-output* "~?~%" control arguments)
  (finish-output *error-output*)
  (restore-terminal)
  (uiop:quit 255))

(defun getopt-algorithm-list-valid-p (value table)
  "Whether VALUE is a comma list ssh's ciphers_valid/mac_valid accepts.

Both helpers walk the list with strsep and stop at the first empty element,
so a leading comma rejects the list while a trailing one is ignored.  At
least one name must be checked before that happens, and each name must be in
TABLE, which is the exact spelling the build knows."
  (when (plusp (length value))
    (let ((start 0)
          (found nil))
      (loop
        (let* ((end (position #\, value :start start))
               (piece (subseq value start end)))
          (when (zerop (length piece))
            (return found))
          (unless (member piece table :test #'string=)
            (return nil))
          (setf found t)
          (when (null end)
            (return found))
          (setf start (1+ end)))))))

(defun getopt-ciphers-valid-p (value)
  "ciphers_valid(VALUE), including its one leading + or ^ skip."
  (if (and (plusp (length value))
           (member (char value 0) '(#\+ #\^)))
      (getopt-algorithm-list-valid-p (subseq value 1)
                                     cl-pnet-ssh:+ssh-all-ciphers+)
      (getopt-algorithm-list-valid-p value
                                     cl-pnet-ssh:+ssh-all-ciphers+)))

(defun getopt-macs-valid-p (value)
  "mac_valid(VALUE), which does not skip a + or ^ prefix."
  (getopt-algorithm-list-valid-p value cl-pnet-ssh:+ssh-all-macs+))

(defun getopt-option-messages (text)
  "The diagnostics readconf writes for one -o TEXT.

Returns (VALUES MESSAGES FAILURE-P).  MESSAGES are the lines ssh would have
written, already escaped, in the order they appear; FAILURE-P is true when
the option stops ssh.  ssh calls process_config_line once per -o, so a line
is resolved on its own record here rather than as part of a larger file."
  (let ((messages '())
        (failure nil))
    (flet ((collect (string) (push string messages)))
      (let ((cl-pnet-ssh::*ssh-forced-warning-function*
              (lambda (line) (collect (format nil "~A~%" line))))
            (cl-pnet-ssh::*ssh-warning-function*
              (lambda (line) (collect (format nil "~A~%" line))))
            (cl-pnet-ssh::*ssh-config-error-function*
              (lambda (line)
                (collect (format nil "~A~%"
                                 (cl-pnet-ssh::ssh-log-escape line))))))
        (let ((config (cl-pnet-ssh::ssh-config-add-options
                       (cl-pnet-ssh::%make-ssh-config :directives nil)
                       (list text))))
          (handler-case
              (cl-pnet-ssh::ssh-config-resolve
               config ""
               :on-error (lambda (condition)
                           (declare (ignore condition))
                           (setf failure t)))
            (cl-pnet-ssh:ssh-config-error () (setf failure t))))))
    (values (nreverse messages) failure)))

(defparameter +getopt-long-short+
  '(("no-command" . #\N) ("subsystem" . #\s)
    ("local-forward" . #\L) ("remote-forward" . #\R)
    ("dynamic-forward" . #\D) ("stdio-forward" . #\W)
    ("option" . #\o) ("jump" . #\J) ("identity" . #\i)
    ("tunnel" . #\w) ("control-command" . #\O)
    ("ciphers" . #\c) ("macs" . #\m) ("port" . #\p)
    ("user" . #\l) ("escape-char" . #\e) ("query" . #\Q)
    ("tag" . #\P) ("version" . #\V))
  "Long spellings this client adds, mapped to the ssh short option they mean.")

(defvar *getopt-session-type* :unset
  "The SessionType value ssh's argument loop leaves, or :UNSET when none.")

(defvar *getopt-mux-command* nil
  "The -O command ssh's argument loop leaves, or NIL when none.")

(defvar *getopt-port* nil
  "The first -p/-o Port spelling ssh's argument loop keeps, or NIL.")

(defvar *getopt-port-given* nil
  "Whether ssh's argument loop set a port, including one from the destination.")

(defvar *getopt-user* nil
  "The first -l/-o User/destination user ssh's argument loop keeps.")

(defvar *getopt-user-given* nil
  "Whether ssh's argument loop set a user, including one from the destination.")

(defvar *getopt-user-command-line* nil
  "Whether the winning user came from -l or the destination.

ssh.c expands a User that came from -o or the configuration file, and
validates it again when the expansion changed the string, but leaves a
command-line user alone.")

(defvar *getopt-tag* nil
  "The first -P tag ssh's argument loop keeps, or NIL.")

(defvar *getopt-tag-given* nil
  "Whether ssh's argument loop set a tag.")

(defvar *getopt-tunnel-device* nil
  "The last -w device ssh's argument loop decoded, or NIL.")

(defvar *getopt-identities* nil
  "The -i paths ssh's argument loop found accessible, newest first.")

(defvar *getopt-jump* nil
  "The ProxyJump ssh's argument loop recorded, or NIL.")

(defvar *getopt-proxy-command* nil
  "The ProxyCommand ssh's argument loop recorded, or NIL.")

(defvar *getopt-host* nil
  "The destination host ssh's argument loop resolved, or NIL.")

(defun run-getopt-phase ()
  "Apply ssh(1)'s getopt-time checks and side effects in argv order.

ssh validates -e, -c, -m, -p, -w, -W, -O, -J, -L, -R, -D, -i and every -o
while it reads its arguments, so the first bad one in the line is the
message the user sees.  It also gives -p, -l, -P and each readconf keyword
only the first value it needs, stats each -i at once, and lets -Q and -V
answer and leave where they appear.  CLINGON cannot express any of that
ordering, so the raw arguments are replayed here before anything else uses
the values."
  (setf cl-pnet-ssh::*ssh-config-notice-consumed* nil
        *getopt-session-type* :unset
        *getopt-mux-command* nil)
  (let ((port nil) (port-given nil)
        (user nil) (user-given nil) (user-command-line nil)
        (host nil)
        (tag nil) (tag-given nil)
        (stdio nil) (mux nil)
        (jump nil) (proxy-command nil)
        (session-type :unset)
        (identities '())
        (certificates '())
        (kept '())
        (tunnel-device nil))
    (labels
        ((fatal (&rest arguments) (apply #'getopt-fatal arguments))
         (say (control &rest arguments)
           (format *error-output* "~?~%" control arguments)
           (finish-output *error-output*))
         ;; add_identity_file/add_certificate_file test the cap before they
         ;; look for a duplicate, so a repeated path at slot 101 still fails.
         (add-file (path userprovided kind table limit)
           (when (>= (length table) limit)
             (if (= userprovided 1)
                 (fatal "Too many ~A files specified (max ~D)" kind limit)
                 (progn
                   (say "command-line line 0: Too many ~A files specified (max ~D)."
                        kind limit)
                   (restore-terminal)
                   (uiop:quit 255))))
           (unless (find-if (lambda (entry)
                              (and (= (cdr entry) userprovided)
                                   (string= (car entry) path)))
                            table)
             (push (cons path userprovided) table)
             t))
         (record-jump (value &key from-flag)
           (if (string-equal value "none")
               ;; parse_jump's short cut only looks at jump_host.
               (when (null jump) (setf jump "none"))
               (multiple-value-bind (parsed reason)
                   (cl-pnet-ssh::ssh-config-parse-proxy-jump value t)
                 (when reason
                   (say "~A" (cl-pnet-ssh::ssh-log-escape reason)))
                 (cond
                   ((not parsed)
                    (when from-flag (fatal "Invalid -J argument")))
                   ;; A successful jump also records the "none" proxy marker.
                   ((and (null jump) (null proxy-command))
                    (setf jump value
                          proxy-command "none"))))))
         (handle-option (text)
           (multiple-value-bind (messages failure)
               (getopt-option-messages text)
             (dolist (message messages)
               (write-string message *error-output*))
             (when failure
               (finish-output *error-output*)
               (restore-terminal)
               (uiop:quit 255)))
           (let* ((line (cl-pnet-ssh::ssh-config-option-line text))
                  (keyword (cl-pnet-ssh::ssh-config-line-keyword line))
                  (raw (cl-pnet-ssh::ssh-config-line-raw line))
                  (remainder (cl-pnet-ssh::ssh-config-line-remainder text))
                  (argument (cl-pnet-ssh::ssh-config-arg line))
                  (value (string-left-trim '(#\Space #\Tab #\=)
                                           (or remainder ""))))
             ;; The getopt phase just showed this notice, so the later
             ;; configuration resolution must consume it silently.
             (when (member keyword
                           cl-pnet-ssh::+ssh-config-unsupported-keywords+
                           :test #'string=)
               (push raw cl-pnet-ssh::*ssh-config-notice-consumed*))
             (cond
               ((string= keyword "identityfile")
                (add-file (or argument "") 2 "identity" identities
                          cl-pnet-ssh::+ssh-max-identity-files+))
               ((string= keyword "certificatefile")
                (add-file (or argument "") 2 "certificate" certificates
                          cl-pnet-ssh::+ssh-max-certificate-files+))
               ((string= keyword "sessiontype")
                (when (eq session-type :unset)
                  (let ((type (session-type-value (or argument ""))))
                    (when type (setf session-type type)))))
               ((string= keyword "proxyjump")
                (record-jump value))
               ((string= keyword "proxycommand")
                (when (and (null proxy-command) (plusp (length value)))
                  (setf proxy-command value)))
               ((and (string= keyword "user") (not user-given))
                (setf user (or argument "") user-given t))
               ((and (string= keyword "port") (not port-given))
                (let ((number (cl-pnet-ssh:ssh-a2port (or argument ""))))
                  (unless (and number (plusp number))
                    (fatal "Bad port '~A'" (or argument "")))
                  ;; The resolver seeds its Port from this spelling, so keep
                  ;; the text rather than the decoded number.
                  (setf port (or argument "") port-given t))))))
         (handle (kind flag value)
           (let ((character (if (eq kind :long)
                                (cdr (assoc flag +getopt-long-short+
                                            :test #'string=))
                                flag)))
             (case character
               (#\1 (fatal "SSH protocol v.1 is no longer supported"))
               (#\O
                (cond
                  (stdio (fatal "Cannot specify multiplexing command with -W"))
                  (mux (fatal "Multiplexing command already specified"))
                  ((member (or value "") +getopt-mux-commands+
                           :test #'string=)
                   (setf mux value))
                  (t (fatal "Invalid multiplex command."))))
               (#\Q (print-query (or value "")))
               (#\V
                (print-version)
                (finish-output *standard-output*)
                (restore-terminal)
                (uiop:quit 0))
               (#\i
                (let ((path (expand-identity-argument (or value ""))))
                  (multiple-value-bind (exists reason)
                      (cl-pnet-ssh::ssh-stat-reason path)
                    (if (not exists)
                        (say "Warning: Identity file ~A not accessible: ~A."
                             path reason)
                        (when (add-file path 1 "identity" identities
                                        cl-pnet-ssh::+ssh-max-identity-files+)
                          (push path kept))))))
               (#\J
                (cond
                  (jump
                   (fatal "Only a single -J option is permitted (use commas to separate multiple jump hops)"))
                  (proxy-command
                   (fatal "Cannot specify -J with ProxyCommand"))
                  (t (record-jump (or value "") :from-flag t))))
               (#\N
                (if (and (not (eq session-type :unset))
                         (not (eq session-type :none)))
                    (fatal "Cannot specify -N with -s/SessionType")
                    (setf session-type :none)))
               (#\s
                (if (and (not (eq session-type :unset))
                         (not (eq session-type :subsystem)))
                    (fatal "Cannot specify -s with -N/SessionType")
                    (setf session-type :subsystem)))
               (#\W
                (cond
                  (stdio (fatal "stdio forward already specified"))
                  (mux (fatal "Cannot specify stdio forward with -O")))
                (let ((expanded
                        (cl-pnet-ssh::ssh-forward-expand-value
                         (or value "") nil)))
                  (unless (and expanded
                               (cl-pnet-ssh::ssh-config-forwarding-valid-p
                                expanded 1 0))
                    (fatal "Bad stdio forwarding specification '~A'"
                           (or value ""))))
                ;; ssh forces the field to none and the tty off.
                (setf stdio t session-type :none))
               (#\w
                (setf tunnel-device
                      (handler-case
                          (cl-pnet-ssh::ssh-config-tunnel-device
                           nil (or value ""))
                        (cl-pnet-ssh:ssh-config-error ()
                          (fatal "Bad tun device '~A'" (or value ""))))))
               (#\e
                (unless (cl-pnet-ssh::ssh-config-escape-char-value
                         (or value ""))
                  (fatal "Bad escape character '~A'." (or value ""))))
               (#\c
                (unless (getopt-ciphers-valid-p (or value ""))
                  (fatal "Unknown cipher type '~A'" (or value ""))))
               (#\m
                (unless (getopt-macs-valid-p (or value ""))
                  (fatal "Unknown mac type '~A'" (or value ""))))
               (#\p
                (unless port-given
                  (let ((number (cl-pnet-ssh:ssh-a2port (or value ""))))
                    (unless (and number (plusp number))
                      (fatal "Bad port '~A'" (or value "")))
                    (setf port (or value "") port-given t))))
               (#\l
                (unless user-given
                  (setf user (or value "") user-given t
                        user-command-line t)))
               (#\P
                (unless tag-given
                  (setf tag (or value "") tag-given t)))
               (#\o (handle-option (or value "")))
               (#\L
                (let ((*forwarding-command-line-kind* "local"))
                  (parse-local-forward (or value ""))))
               (#\R
                (let ((*forwarding-command-line-kind* "remote"))
                  (parse-remote-forward (or value ""))))
               (#\D
                (let ((*forwarding-command-line-kind* "dynamic"))
                  (parse-dynamic-forward (or value ""))))
               (t
                ;; getopt reports an option letter it does not know, then
                ;; ssh.c's default case prints the usage.  A long spelling
                ;; this client adds is only unknown when CLINGON has no
                ;; option of that name; `--port' is ours, `--help' is not.
                (when (and (or (not (eq kind :long))
                               (null (find-burs-long-option
                                      *burs-command* flag)))
                           (or (not (eq kind :short))
                               (not (find character
                                          +command-line-short-options+))))
                  (format *error-output* "unknown option -- ~A~%"
                          (if (eq kind :long) #\- character))
                  (destination-usage)))))))
      (dolist (event (command-line-getopt-events))
        (let ((kind (getf event :kind))
              (flag (getf event :flag))
              (value (getf event :value)))
          (cond
            ((eq kind :host)
             ;; ssh takes the destination between its two getopt passes, so
             ;; its user and port are in place before the options written
             ;; after it are read.
             (multiple-value-bind (resolved-host resolved-user resolved-port)
                 (resolve-destination value user port)
               ;; Only a destination that actually supplies the user makes it
               ;; a command-line value; -l or -o may already have won.
               (when (and (null user) resolved-user)
                 (setf user-command-line t))
               (setf host resolved-host
                     user resolved-user
                     port resolved-port)
               (when user (setf user-given t))
               (when port (setf port-given t))))
            ;; getopt refuses to run out of arguments before ssh sees the
            ;; option at all, and ssh answers with usage().
            ((and (eq kind :short)
                  (find flag +command-line-options-with-values+)
                  (null value))
             (format *error-output* "option requires an argument -- ~A~%"
                     flag)
             (destination-usage))
            (t
             (handle kind flag value)))))
      ;; With no word left for a destination ssh reaches usage().
      (unless host (destination-usage))
      ;; Record what publish-getopt-state applies once CLINGON has parsed:
      ;; the replay runs first, because -Q and -V must answer before a later
      ;; syntactically broken option is reported.
      (setf *getopt-port* port
            *getopt-port-given* port-given
            *getopt-user* user
            *getopt-user-given* user-given
            *getopt-user-command-line* user-command-line
            *getopt-tag* tag
            *getopt-tag-given* tag-given
            *getopt-tunnel-device* tunnel-device
            *getopt-identities* kept
            *getopt-jump* jump
            *getopt-proxy-command* proxy-command
            *getopt-host* host
            *getopt-session-type* session-type
            *getopt-mux-command* mux))))

(defun publish-getopt-state ()
  "Apply the first-value decisions ssh's argument loop made.

CLINGON keeps the last value for every option and knows nothing about the
destination, so its parse is corrected here once it has run."
  (when *getopt-port-given*
    (setf (getf *options* :port) *getopt-port*))
  (when *getopt-user-given*
    (setf (getf *options* :user) *getopt-user*))
  (when *getopt-tag-given*
    (setf (getf *options* :tag) *getopt-tag*))
  (when *getopt-tunnel-device*
    (setf (getf *options* :tunnel-device) *getopt-tunnel-device*))
  ;; :IDENTITY is kept in reverse command-line order, like the other list
  ;; slots, so readers reverse it once.
  (setf (getf *options* :identity) *getopt-identities*)
  ;; readconf's shared limit counts the -i files, which never reach its
  ;; own directive stream.
  (setf cl-pnet-ssh::*ssh-config-identity-count-seed*
        (length *getopt-identities*))
  (setf (getf *options* :jump) *getopt-jump*
        (getf *options* :proxy-command) *getopt-proxy-command*
        (getf *options* :host) *getopt-host*))

(defparameter +command-line-options-with-values+
  "BbcDEeFIiJLlmOopQRSWw"
  "Short options that consume an argument, so the session-type scan can skip
their value instead of mistaking a leading dash in it for another option.")

(defparameter +command-line-short-options+
  (concatenate 'string "1246ACGKMNTVXYZafgknqstvxy"
               +command-line-options-with-values+)
  "Every option letter ssh(1)'s getopt string accepts.

ssh hands this to getopt(3), so any other letter is reported as an unknown
option and ends in the usage text.")

(defun command-line-option-parts (line)
  "LINE's keyword and value, split as readconf splits an -o argument."
  (let ((tokens (cl-pnet-ssh::ssh-config-tokenize line)))
    (values (first tokens)
            (when (rest tokens)
              (format nil "~{~A~^ ~}" (rest tokens))))))

(defun command-line-getopt-events (&optional (command *burs-command*)
                                     (arguments (uiop:command-line-arguments)))
  "Every option ssh's getopt reads from this invocation, in order.

Each event is a plist whose :KIND is :SHORT, :LONG or :HOST, whose :FLAG is
the short character or the lower-cased long name, and whose :VALUE is the
option's argument when the option takes one.  The destination appears as a
:HOST event where getopt reaches it.

ARGUMENTS defaults to this process's own arguments; a test or a second parse
can pass the line it is examining instead.

ssh(1) reads options until the first non-option, takes that word as the
destination, and then, while more arguments remain, resets getopt and keeps
reading options up to the remote command's first word.  The scanner follows
the same path, so an option written after the destination is still applied,
while one written after the command belongs to the command."
  (let ((events '())
        (remaining arguments)
        (host-seen nil)
        (terminated nil)
        (done nil))
    (labels
        ((emit (kind flag value)
           (push (list :kind kind :flag flag :value value) events))
         (value-option-p (character)
           (find character +command-line-options-with-values+))
         (take-value ()
           (pop remaining))
         (scan-short (argument)
           (loop with length = (length argument)
                 for index from 1 below length
                 for character = (char argument index)
                 do (cond
                      ((value-option-p character)
                       ;; A value attached to the option (-p2222) is already
                       ;; in this argument; otherwise it is the next one.
                       (emit :short character
                             (if (< (1+ index) length)
                                 (subseq argument (1+ index))
                                 (take-value)))
                       (return))
                      (t
                       (emit :short character nil)))))
         (scan-long (argument)
           (let* ((equals (position #\= argument))
                  (end (or equals (length argument)))
                  (name (string-downcase (subseq argument 2 end)))
                  (name (if (string= name "identity-file") "identity" name))
                  (option (and command (find-burs-long-option command name)))
                  (inline (and equals (subseq argument (1+ equals)))))
             (emit :long name
                   (cond (inline inline)
                         ((and option (clingon:option-parameter option))
                          (take-value)))))))
      (loop while (and remaining (not done))
            for argument = (pop remaining)
            do (cond
                 (terminated
                  ;; Everything after -- belongs to the destination and
                  ;; command; no further option is read.
                  (if host-seen
                      (setf done t)
                      (progn
                        (setf host-seen t)
                        (emit :host nil argument))))
                 ((string= argument "--")
                  (setf terminated t))
                 ((and (> (length argument) 2)
                       (char= (char argument 0) #\-)
                       (char= (char argument 1) #\-))
                  (scan-long argument))
                 ((and (> (length argument) 1)
                       (char= (char argument 0) #\-))
                  (scan-short argument))
                 (host-seen
                  ;; Options between the destination and the command were
                  ;; read above; this word starts the remote command.
                  (setf done t))
                 (t
                  (setf host-seen t)
                  (emit :host nil argument))))
      (nreverse events))))

(defun command-line-option-event-p (event)
  "Whether EVENT is an -o/--option argument."
  (let ((kind (getf event :kind))
        (flag (getf event :flag)))
    (or (and (eq kind :short) (char= flag #\o))
        (and (eq kind :long) (string= flag "option")))))

(defun command-line-identity-events ()
  "The -i and -o arguments of this invocation, in the order ssh reads them.

Only the identity-related events are kept; -G prints identityfile lines in
this order, before the configuration file's own entries."
  (loop for event in (command-line-getopt-events)
        for kind = (getf event :kind)
        for flag = (getf event :flag)
        for value = (getf event :value)
        when (or (and (eq kind :short) (char= flag #\i))
                 (and (eq kind :long) (string= flag "identity")))
          collect (list :identity value)
        when (command-line-option-event-p event)
          collect (list :option value)))

(defparameter +forward-option-keywords+
  '("localforward" "remoteforward" "dynamicforward")
  "The ssh_config keywords that add a forwarding line.")

(defun command-line-forward-events ()
  "The -L, -R, -D and -o forwarding arguments, in the order ssh reads them.

ssh appends every forwarding specification to the matching array while it
walks its arguments, so the command line's forwards come before the
configuration file's and -G prints them in that order."
  (loop for event in (command-line-getopt-events)
        append (let ((kind (getf event :kind))
                     (flag (getf event :flag))
                     (value (getf event :value)))
                 (cond
                   ((and (eq kind :short) (member flag '(#\L #\R #\D)))
                    (list (list (case flag
                                  (#\L :local)
                                  (#\R :remote)
                                  (t :dynamic))
                                value)))
                   ((and (eq kind :long)
                         (member flag '("local-forward" "remote-forward"
                                        "dynamic-forward")
                                 :test #'string=))
                    (list (list (cond ((string= flag "local-forward") :local)
                                      ((string= flag "remote-forward") :remote)
                                      (t :dynamic))
                                value)))
                   ((command-line-option-event-p event)
                    (multiple-value-bind (keyword setting)
                        (command-line-option-parts (or value ""))
                      (when (and setting
                                 (member (string-downcase (or keyword ""))
                                         +forward-option-keywords+
                                         :test #'string=))
                        (list (list :option value)))))
                   (t nil)))))

(defun request-tty-multistate (value)
  "The RequestTTY state VALUE names, or NIL when it is not one of them."
  (cond
    ((string-equal value "yes") :yes)
    ((string-equal value "true") :yes)
    ((string-equal value "no") :no)
    ((string-equal value "false") :no)
    ((string-equal value "force") :force)
    ((string-equal value "auto") :auto)
    (t nil)))

(defun command-line-request-tty-state (command arguments)
  "The RequestTTY state the raw ARGUMENTS leave, or NIL if none names one.

ssh's getopt loop applies -t, -T, -N, -W and -o RequestTTY as it reads them,
and readconf keeps the first RequestTTY it sees, so the order matters: -t
flips YES to FORCE, -T sets NO, -N and -W also set NO, and a later -o
RequestTTY cannot override a state an earlier option already set.  CLINGON
only reports which flags appeared, so the arguments are scanned again here."
  (declare (ignore command))
  (let ((state nil))
    (dolist (event (command-line-getopt-events command arguments))
      (let ((kind (getf event :kind))
            (flag (getf event :flag))
            (value (getf event :value)))
        (flet ((record-setting (setting)
                 ;; readconf keeps the first RequestTTY it obtains.
                 (when (and (null state) setting)
                   (setf state (request-tty-multistate setting)))))
          (cond
            ((and (eq kind :short) (char= flag #\t))
             (setf state (if (eq state :yes) :force :yes)))
            ((and (eq kind :short) (char= flag #\T))
             (setf state :no))
            ((and (eq kind :short) (member flag '(#\N #\W)))
             (setf state :no))
            ((and (eq kind :long)
                  (member flag '("no-command" "stdio-forward")
                          :test #'string=))
             (setf state :no))
            ((command-line-option-event-p event)
             (multiple-value-bind (keyword setting)
                 (command-line-option-parts (or value ""))
               (when (string-equal (or keyword "") "RequestTTY")
                 (record-setting setting))))
            ((and (eq kind :long) (string= flag "request-tty"))
             (record-setting value))))))
    state))

(defun command-line-identity-entries ()
  "IdentityFile spellings to print for -G, in ssh's own order.

Each element is a string as ssh would print it: an -i path is shown with ~
expanded, because parse_cmdline stats the expanded name before recording it,
while an -o IdentityFile keeps the argument exactly as written.  readconf
ignores a duplicate with the same userprovided marker, so repeated -i
arguments and repeated -o arguments each collapse but an -i and an -o naming
the same file both remain."
  (let ((entries '())
        (seen-i '())
        (seen-o '()))
    (dolist (event (command-line-identity-events))
      (cond
        ((eq (first event) :identity)
         (let ((path (expand-identity-argument (or (second event) ""))))
           (when (and (plusp (length path))
                      (not (member path seen-i :test #'equal))
                      (cl-pnet-ssh:ssh-file-exists-p (pathname path)))
             (push path seen-i)
             (push path entries))))
        ((eq (first event) :option)
         (multiple-value-bind (keyword value)
             (command-line-option-parts (or (second event) ""))
           (when (and keyword value (string-equal keyword "IdentityFile")
                      (not (member value seen-o :test #'equal)))
             (push value seen-o)
             (push value entries))))))
    (values (nreverse entries) (nreverse seen-o))))

(defun session-type-value (text)
  "TEXT as ssh's SessionType value, or NIL when it is not one."
  (cond ((string-equal text "none") :none)
        ((string-equal text "subsystem") :subsystem)
        ((string-equal text "default") :default)
        (t nil)))

(defun check-session-type-arguments (command-given-p)
  "Apply ssh.c's missing-subsystem check for a subsystem session.

-N, -s, -W, -o SessionType and the conflicts around them are settled in
argv order by RUN-GETOPT-PHASE, which leaves the final value in
*GETOPT-SESSION-TYPE*.  What remains is ssh.c's post-getopt check: asking
for a subsystem with no command name prints the message and the usage text
before log_init, so -q cannot hide it."
  (when (and (not command-given-p) (eq *getopt-session-type* :subsystem))
    (format *error-output* "You must specify a subsystem to invoke.~%")
    (finish-output *error-output*)
    (clingon:print-usage *burs-command* *error-output*)
    (restore-terminal)
    (uiop:quit 255)))

(defun check-supported-options ()
  "Fail before connecting on a flag whose feature is not in this build."
  (when (getf *options* :escape-char)
    (unless (cl-pnet-ssh::ssh-config-escape-char-value
             (getf *options* :escape-char))
      (fail "invalid escape character ~A" (getf *options* :escape-char))))
  (when (and (getf *options* :pkcs11)
             (not (getf *options* :print-config)))
    (unsupported "-I" "PKCS#11 keys are not implemented"))
  (when (getf *options* :tunnel)
    ;; ssh validates the device while reading the flag, even for -G.
    (setf (getf *options* :tunnel-device)
          (handler-case
              (cl-pnet-ssh::ssh-config-tunnel-device
               nil (getf *options* :tunnel))
            (cl-pnet-ssh:ssh-config-error ()
              (format *error-output* "Bad tun device '~A'~%"
                      (getf *options* :tunnel))
              (finish-output *error-output*)
              (restore-terminal)
              (uiop:quit 255))))
    ;; -G only reports the configuration, so it does not need the tunnel.
    (unless (getf *options* :print-config)
      (unsupported "-w" "TUN/TAP forwarding is not implemented")))
  (when (getf *options* :protocol-1)
    (fail "SSH protocol v.1 is no longer supported"))
  (when (and (eq (getf *options* :x11-forward) :yes)
             (not (cl-pnet-ssh:ssh-client-feature-supported-p :x11-forward)))
    (unsupported "-X" "X11 forwarding is not implemented by this transport"))
  (when (and (eq (getf *options* :x11-forward) :trust)
             (not (cl-pnet-ssh:ssh-client-feature-supported-p :x11-forward)))
    (unsupported "-Y" "X11 forwarding is not implemented by this transport"))
  (when (getf *options* :compression)
    (when (not (cl-pnet-ssh:ssh-client-feature-supported-p :compression))
      (unsupported "-C" "compression is not implemented by this transport")))
  (when (and (getf *options* :remote-forward)
             (not (cl-pnet-ssh:ssh-client-feature-supported-p
                   :remote-forward)))
    (unsupported "-R" "remote forwarding is not implemented by this transport"))
  (when (getf *options* :ciphers)
    (check-algorithm-list "-c" (getf *options* :ciphers)
                          (transport-supported-algorithms
                           cl-pnet-ssh:+ssh-ciphers+ :ciphers)
                          (transport-supported-algorithms
                           cl-pnet-ssh:+ssh-all-ciphers+ :ciphers)))
  (when (getf *options* :macs)
    (check-algorithm-list "-m" (getf *options* :macs)
                          (supported-mac-algorithms)))
  (when (getf *options* :kex-algorithms)
    (check-algorithm-list "KexAlgorithms" (getf *options* :kex-algorithms)
                          (supported-kex-algorithms)))
  (when (getf *options* :address-family)
    (let ((family (getf *options* :address-family)))
      (unless (member family '("inet" "inet6" "any") :test #'string-equal)
        (fail "invalid address family ~A" family))))
  ;; Parse the forwarding specifications now, so a typo is a command-line
  ;; error rather than a surprise after authentication.  ssh rejects each one
  ;; while reading the arguments and names the flag it came from.
  (setf (getf *options* :local-forward)
        (let ((*forwarding-command-line-kind* "local"))
          (mapcar #'parse-local-forward
                  (reverse (getf *options* :local-forward)))))
  (setf (getf *options* :remote-forward)
        (let ((*forwarding-command-line-kind* "remote"))
          (mapcar #'parse-remote-forward
                  (reverse (getf *options* :remote-forward)))))
  (setf (getf *options* :dynamic-forward)
        (let ((*forwarding-command-line-kind* "dynamic"))
          (mapcar #'parse-dynamic-forward
                  (reverse (getf *options* :dynamic-forward)))))
  (values))

(defun check-config-supported (client)
  "Fail when CLIENT's resolved config asks for a feature this build lacks.

The command line is checked before connecting, but Compression and a
transport limitation on X11 or remote forwarding can arrive from
~/.ssh/config too.  Dropping them silently would leave the user believing
they are on, so they are refused with the same message the matching flag
gets.  An explicit -x still disables X11 and therefore silences the
refusal."
  (let ((options (and client (cl-pnet-ssh:ssh-client-config-options client))))
    (when options
      (when (cl-pnet-ssh:ssh-config-options-compression options)
        (unless (cl-pnet-ssh:ssh-client-feature-supported-p :compression)
          (unsupported "Compression"
                       "compression is not implemented by this transport")))
      (when (and (cl-pnet-ssh:ssh-config-options-remote-forwards options)
                 (not (cl-pnet-ssh:ssh-client-feature-supported-p
                       :remote-forward)))
        (unsupported "RemoteForward"
                     "remote forwarding is not implemented by this transport"))
      (when (and (or (cl-pnet-ssh:ssh-config-options-forward-x11 options)
                     (cl-pnet-ssh:ssh-config-options-forward-x11-trusted
                      options))
                 (not (eq (getf *options* :x11-forward) :no))
                 (not (cl-pnet-ssh:ssh-client-feature-supported-p
                       :x11-forward)))
        (unsupported "ForwardX11"
                     "X11 forwarding is not implemented by this transport"))
      ;; GSSAPIAuthentication and GSSAPIDelegateCredentials are reported by
      ;; the config parser as unsupported options (readconf's oUnsupported
      ;; when OpenSSH has no GSSAPI), so nothing here has to say anything.
      ;; Every one of these is a real request from the configuration.  This
      ;; build cannot honour it, and pretending otherwise would leave the
      ;; user with a weaker or different connection than they asked for.
      (let ((provider
              (cl-pnet-ssh:ssh-config-options-pkcs11-provider options)))
        (when (and provider (not (eq provider :none)))
          (unsupported "PKCS11Provider"
                       "PKCS#11 keys are not implemented")))
      ;; ssh only consults ProxyUseFdpass when a ProxyCommand carries the
      ;; stream; with a direct connection or a ProxyJump it changes nothing.
      ;; ProxyCommand=- together with it is refused by the client itself.
      (let ((tunnel (cl-pnet-ssh:ssh-config-options-tunnel options)))
        (when (and tunnel (not (eq tunnel :no)))
          (unsupported "Tunnel" "TUN/TAP forwarding is not implemented")))
      ;; A one-word RemoteForward asks the server for a SOCKS proxy.  The
      ;; reverse-dynamic path is part of the pure transport; a transport
      ;; without it must say so rather than expose a dead port.
      (let ((dynamic
              (find-if (lambda (forward)
                         (equal (forward-host forward) "socks"))
                       (mapcar #'parse-config-remote-forward
                               (cl-pnet-ssh:ssh-config-options-remote-forwards
                                options)))))
        (when (and dynamic
                   (not (cl-pnet-ssh:ssh-client-feature-supported-p
                         :remote-dynamic-forward)))
          (unsupported "RemoteForward"
                       "remote dynamic (SOCKS) forwarding is not implemented by this transport"))))))

;;; ---- ~/.ssh/config and -o ----

(defun match-exec (command on-result on-error)
  "Answer a Match exec condition.

The config is resolved before the event loop starts, so running the shell
test here costs the process nothing that was concurrent anyway.  The library
itself never blocks: this matcher is what a caller supplies.  The command is
written for the platform shell, as ssh runs it through sh and sshd on Windows
runs it through cmd.exe."
  (handler-case
      (funcall on-result
               (eql 0
                    (nth-value
                     2
                     (uiop:run-program
                      (if (uiop:os-windows-p)
                          (list (or (uiop:getenv "COMSPEC") "cmd.exe")
                                "/c" command)
                          (list "/bin/sh" "-c" command))
                      :ignore-error-status t
                      :output nil
                      :error-output nil))))
    (error (condition) (funcall on-error condition))))

(defun true-value-p (value)
  (member (string-downcase value) '("yes" "true" "on") :test #'string=))

(defun command-line-option (name value)
  "Apply one -o NAME=VALUE to the parsed options."
  (cond
    ;; User and Port are left to the resolver, which validates them like
    ;; readconf and keeps the first value the command line gave them; a
    ;; dedicated -l or -p is seeded ahead of the -o lines for the same reason.
    ((string-equal name "IdentityFile")
     ;; readconf stores the argument as written; ~ and tokens are expanded
     ;; only when the file is loaded, and -G prints the original spelling.
     ;; The value itself reaches the resolver as an -o line, so nothing has
     ;; to be recorded here; :IDENTITY holds -i arguments only.
     nil)
    ((string-equal name "IdentityAgent") (setf (getf *options* :agent) value))
    ((string-equal name "StrictHostKeyChecking")
     (setf (getf *options* :policy)
           (cond ((member (string-downcase value) '("no" "off") :test #'string=)
                  :insecure)
                 ((string-equal value "accept-new") :accept-new)
                 ((string-equal value "ask") :ask)
                 (t :strict))))
    ((string-equal name "ProxyJump") (setf (getf *options* :jump) value))
    ((string-equal name "ProxyCommand")
     (setf (getf *options* :proxy-command) value))
    ;; AddressFamily is not copied into *OPTIONS* here: -o values already
    ;; reach the config through RESOLVER-OPTION-LIST, and writing this slot
    ;; would let an -o override the dedicated -4 or -6, which comes first.
    ;; Ciphers, MACs and KexAlgorithms are left to the resolver too: it
    ;; validates them like readconf, whereas the -c and -m keys belong to
    ;; the dedicated flags and are checked as command-line options.
    ((string-equal name "Compression")
     (setf (getf *options* :compression)
           (not (member (string-downcase value) '("no" "off") :test #'string=))))
    ((string-equal name "LogLevel")
     ;; readconf keeps the first LogLevel it sees, and -v or -q already
     ;; claimed options.log_level while the arguments were read, so only an
     ;; unset level can still be adopted here.
     (let ((level (string-downcase value)))
       (when (and (null (getf *options* :log-level))
                  (zerop (getf *options* :verbose 0))
                  (member level '("quiet" "fatal" "error" "info"
                                  "verbose" "debug" "debug1" "debug2"
                                  "debug3")
                          :test #'string=))
         (multiple-value-bind (quiet verbose) (log-level-settings level)
           (setf (getf *options* :log-level) level
                 (getf *options* :quiet) quiet
                 (getf *options* :verbose) verbose)))))
    ((string-equal name "GatewayPorts")
     (setf (getf *options* :gateway-ports) (true-value-p value)))
    ((string-equal name "ForwardAgent")
     (when (true-value-p value)
       (setf (getf *options* :forward-agent) t)))
    ;; RequestTTY is recorded by command-line-request-tty-state from the raw
    ;; arguments, because -t and -T interleave with -o RequestTTY and readconf
    ;; keeps only the first RequestTTY it sees.
    ((string-equal name "BindAddress")
     (setf (getf *options* :bind-address) value))
    ;; Forwarding keywords stay with the ssh_config resolver: it already
    ;; sees every -o line, so recording them here too would start each
    ;; forward twice.
    ;; Everything else reaches the same resolver through the -o list, or is
    ;; accepted and ignored as SSH itself tolerates keywords a newer client
    ;; wrote.
    (t nil)))

(defun command-line-option-list ()
  "The -o options in the order they were written."
  (reverse (getf *options* :options)))

(defun resolver-option-list ()
  "Every algorithm choice from the command line, as ssh_config lines.

-o values already form a list; -c and -m are separate flags, so they are
turned into Ciphers and MACs lines here.  They come first, and OpenSSH keeps
the first value, so a dedicated flag outranks an -o for the same keyword."
  (let ((options (command-line-option-list)))
    (when (getf *options* :macs)
      (push (format nil "MACs ~A" (getf *options* :macs)) options))
    (when (getf *options* :ciphers)
      (push (format nil "Ciphers ~A" (getf *options* :ciphers)) options))
    ;; -C is a dedicated flag, so it outranks an -o or the file's
    ;; Compression, and -G reports it as a resolved setting.
    (when (getf *options* :compression)
      (push "Compression yes" options))
    ;; A dedicated -b or -B outranks an -o for the same keyword, as every
    ;; dedicated flag does; they also make -G report what will be dialled.
    (when (getf *options* :bind-address)
      (push (format nil "BindAddress ~A" (getf *options* :bind-address))
            options))
    (when (getf *options* :bind-interface)
      (push (format nil "BindInterface ~A" (getf *options* :bind-interface))
            options))
    ;; -4, -6 and --address-family pick the address family.  As with the
    ;; other dedicated flags, this line comes before the -o values so it
    ;; wins the first-value rule.
    (when (getf *options* :address-family)
      (push (format nil "AddressFamily ~A" (getf *options* :address-family))
            options))
    ;; -A and -a are dedicated flags, so they outrank an -o or the file.
    ;; OpenSSH applies them after reading the file; prepending the same
    ;; keyword gives the first value the same effect.
    (case (getf *options* :forward-agent)
      ((t) (push "ForwardAgent yes" options))
      ((:no) (push "ForwardAgent no" options)))
    ;; -X, -Y and -x are dedicated flags too, so they outrank the file.
    (case (getf *options* :x11-forward)
      ((:yes) (push "ForwardX11 yes" options))
      ((:trust) (push "ForwardX11 yes" options)
                (push "ForwardX11Trusted yes" options))
      ((:no) (push "ForwardX11 no" options)))
    ;; -J is not an -o line, so its value only exists in *OPTIONS*.  Adding
    ;; it to the resolved configuration keeps readconf's first-value rule
    ;; against a file or later -o line, exactly as ssh's getopt loop does.
    (when (and (getf *options* :jump)
               (some (lambda (event)
                       (or (and (eq (getf event :kind) :short)
                                (char= (getf event :flag) #\J))
                           (and (eq (getf event :kind) :long)
                                (string= (getf event :flag) "jump"))))
                     (command-line-getopt-events)))
      (push (format nil "ProxyJump ~A" (getf *options* :jump)) options))
    options))

(defun apply-command-line-options ()
  (dolist (option (command-line-option-list))
    (let ((equals (position #\= option))
          (space (position-if (lambda (character)
                                (member character '(#\Space #\Tab)))
                              option)))
      (cond
        (equals
         (command-line-option (subseq option 0 equals)
                              (subseq option (1+ equals))))
        (space
         (command-line-option
          (subseq option 0 space)
          (string-trim '(#\Space #\Tab) (subseq option (1+ space)))))))))

;;; ---- Logging ----

(defun log-line (format-string &rest arguments)
  "Write one progress line, when there is somewhere to write it.

-v puts the familiar debug1 prefix on it; -E alone still records the line,
because a log file that stays empty would be a poor answer to asking for
one.  A closed log stream (the user piped stderr to head, say) turns logging
off instead of raising: logging is a side channel and must not take the
session down."
  (when *log-stream*
    (handler-case
        (let ((line (if (plusp (getf *options* :verbose 0))
                        (format nil "debug1: ~?" format-string arguments)
                        (format nil "~?" format-string arguments))))
          (format *log-stream* "~A~%" (cl-pnet-ssh::ssh-log-escape line))
          (finish-output *log-stream*))
      (error ()
        (setf *log-stream* nil
              cl-pnet-ssh:*ssh-log-function* nil)))))

(defun log-notice (format-string &rest arguments)
  "Write one logit()-level line: to the -E file when one is open, else stderr.

Unlike LOG-LINE this never adds -v's debug1 prefix, because a logit()
message is not a debug message.  The caller has already applied -q."
  (let ((stream (or *log-stream* *error-output*)))
    (handler-case
        (progn
          (format stream "~?" format-string arguments)
          (finish-output stream))
      (error ()
        (setf *log-stream* nil)))))

(defun log-message (format-string &rest arguments)
  "Write one log.c message with the escaping ssh applies, without a prefix.

FATAL and INFO messages are not debug lines, so -v must not add its prefix,
but their text still reaches stderr through log.c's strnvis(), the same way
LOG-LINE escapes its line."
  (let ((stream (or *log-stream* *error-output*)))
    (handler-case
        (let ((line (apply #'format nil format-string arguments)))
          (format stream "~A~%" (cl-pnet-ssh::ssh-log-escape line))
          (finish-output stream))
      (error ()
        (setf *log-stream* nil)))))

(defun fatal-message-suppressed-p ()
  "Whether ssh's log.c would drop a fatal() message.

fatal() logs at SYSLOG_LEVEL_FATAL, which is above QUIET, so only a QUIET
log level silences it.  LogLevel ERROR or FATAL still prints the line even
though they silence logit()."
  (let ((level (getf *options* :log-level)))
    (and level (string-equal level "quiet"))))

(defun log-fatal (format-string &rest arguments)
  "Print a fatal() line, honouring LogLevel QUIET, and leave with status 255.

FINISH runs OpenSSH's cleanup_exit path: it closes the client (and any
ProxyCommand helper) before quitting, instead of leaving a child behind."
  (unless (fatal-message-suppressed-p)
    (apply #'log-message format-string arguments))
  (finish 255))

(defun log-level-setting ()
  "The effective LogLevel name, defaulting to INFO."
  (or (getf *options* :log-level) "info"))

(defun log-info (format-string &rest arguments)
  "Print a logit() line at INFO.

log.c drops INFO when LogLevel is ERROR, FATAL or QUIET, so those levels
silence the channel diagnostics a session still reports by exit status."
  (unless (member (log-level-setting) '("quiet" "fatal" "error")
                  :test #'string-equal)
    (apply #'log-message format-string arguments)))

(defun log-verbose (format-string &rest arguments)
  "Print a verbose() line, which only a VERBOSE or DEBUG log level shows.

verbose() is SYSLOG_LEVEL_VERBOSE, so the default INFO level and -q drop it
and -v or LogLevel=VERBOSE print it without a debug prefix."
  (when (plusp (getf *options* :verbose 0))
    (apply #'log-message format-string arguments)))

(defun log-error (format-string &rest arguments)
  "Print an error() line, which only LogLevel FATAL or QUIET silences."
  (unless (member (log-level-setting) '("quiet" "fatal")
                  :test #'string-equal)
    (apply #'log-message format-string arguments)))

(defun channel-open-reason-text (reason)
  "ssh's reason2txt() for a refused channel open."
  (case reason
    (1 "administratively prohibited")
    (2 "connect failed")
    (3 "unknown channel type")
    (4 "resource shortage")
    (t "unknown reason")))

(defun log-channel-open-failure (channel condition)
  "Print channels.c's refusal line for an ssh-channel-error CONDITION.

channel_input_open_failure() logs at logit() before the channel's confirm
callback runs, so a session, a stdio forward and a mux master all report the
same text for a refused open."
  (when (and condition
             (typep condition 'cl-pnet-ssh:ssh-channel-error)
             (integerp (cl-pnet-ssh:ssh-channel-error-reason condition)))
    (log-info "channel ~D: open failed: ~A: ~A"
              (cl-pnet-ssh::ssh-channel-local-id channel)
              (channel-open-reason-text
               (cl-pnet-ssh:ssh-channel-error-reason condition))
              (or (cl-pnet-ssh:ssh-channel-error-description condition) ""))))

(defun start-logging ()
  (when (and (getf *options* :log-file)
             (null *log-stream*))
    (setf *log-stream*
          (handler-case
              (open (getf *options* :log-file)
                    :direction :output :if-exists :append
                    :if-does-not-exist :create)
            (error (condition)
              (fail "cannot open log file ~A: ~A"
                    (getf *options* :log-file) condition)))))
  (when (and (plusp (getf *options* :verbose 0))
             (not (getf *options* :quiet))
             (null *log-stream*))
    (setf *log-stream* *error-output*))
  (when *log-stream*
    (let ((stream *log-stream*)
          (verbose (plusp (getf *options* :verbose 0))))
      (setf cl-pnet-ssh:*ssh-log-function*
            (lambda (line)
              (handler-case
                  (progn
                    (if verbose
                        (format stream "debug1: ~A~%" line)
                        (format stream "~A~%" line))
                    (finish-output stream))
                (error ()
                  (setf *log-stream* nil
                        cl-pnet-ssh:*ssh-log-function* nil)))))))
  ;; Warnings such as WarnWeakCrypto's post-quantum notice appear at ssh's
  ;; default log level, so they need neither -v nor a log file.  -q still
  ;; silences them, and -E sends them to the same file as the other lines.
  (setf cl-pnet-ssh:*ssh-warning-function*
        (if (getf *options* :quiet)
            (lambda (line) (declare (ignore line)) nil)
            (lambda (line)
              (let ((stream (or *log-stream* *error-output*)))
                (handler-case
                    (progn
                      (format stream "~A~%" line)
                      (finish-output stream))
                  (error ()
                    (setf *log-stream* nil)))))))
  ;; Key files are checked when they are loaded, below the protocol code, so
  ;; the command line tells the library how its platform judges permissions.
  (setf cl-pnet-ssh:*ssh-private-key-permission-check*
        #'private-key-permissions-too-open-p)
  ;; ssh applies a command-line -o while it is still parsing its arguments,
  ;; before -q, -E and -v take effect, so readconf's notice about an
  ;; unsupported one always reaches stderr.
  (setf cl-pnet-ssh:*ssh-forced-warning-function*
        (lambda (line)
          (handler-case
              (progn
                (format *error-output* "~A~%" line)
                (finish-output *error-output*))
            (error () nil))))
  ;; readconf prints each rejected configuration line as it parses it, then
  ;; the file's closing "terminating, N bad configuration options" summary.
  ;; The library formats those lines; the reporter only writes them.
  ;; A file's diagnostics are logged after log_init, so -q (LogLevel QUIET)
  ;; silences them, while readconf's own -o lines are printed during argument
  ;; parsing and always reach stderr, which is why they name command-line.
  (setf *config-error-reported* nil)
  (setf cl-pnet-ssh:*ssh-config-error-function*
        (lambda (line)
          (setf *config-error-reported* t)
          (when (or (not (getf *options* :quiet))
                    (and (>= (length line) 12)
                         (string= line "command-line" :end1 12)
                         (or (= (length line) 12)
                             (member (char line 12) '(#\: #\Space)))))
            (handler-case
                (progn
                  (format *error-output* "~A~%"
                          (cl-pnet-ssh::ssh-log-escape line))
                  (finish-output *error-output*))
              (error () nil))))))

;;; ---- -Q: algorithm queries ----

(defun certificate-algorithm-name-p (name)
  "Whether NAME is a certificate key or signature type."
  (or (search "-cert-v01@" name)
      ;; ML-DSA certificate names end in plain "-cert".
      (and (search "-cert" name)
           (not (search "-cert-v01@" name)))))

(defparameter +query-key-types+
  '("ssh-ed25519"
    "ssh-mldsa44-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    "ssh-rsa")
  "Plain key types this client can load, in -Q key-plain's order.

RSA appears as ssh-rsa, the key format, not as the rsa-sha2-* signature
names; those are signature algorithms and belong to -Q sig and -Q key-sig.")

(defparameter +query-certificate-key-types+
  '("ssh-ed25519-cert-v01@openssh.com"
    "ssh-mldsa44-ed25519-cert"
    "ecdsa-sha2-nistp256-cert-v01@openssh.com"
    "ecdsa-sha2-nistp384-cert-v01@openssh.com"
    "ecdsa-sha2-nistp521-cert-v01@openssh.com"
    "ssh-rsa-cert-v01@openssh.com")
  "The certificate spelling of each plain key type, in the same order.")

(defun query-plain-key-algorithms ()
  "Key types this client can load, without the certificate spellings."
  (remove-if-not #'transport-supports-key-type-p +query-key-types+))

(defun query-certificate-key-algorithms ()
  "Certificate key types this client can present."
  (remove-if-not #'transport-supports-key-type-p
                 +query-certificate-key-types+))

(defparameter +query-plain-signature-names+
  '("ssh-ed25519"
    "ssh-mldsa44-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    "ssh-rsa"
    "rsa-sha2-256"
    "rsa-sha2-512")
  "Signature names this client can make or check, without certificates.

This is sshkey_alg_list's order, the order ssh -Q sig and -Q key-sig use:
it names every implementation, including the SHA-1 ssh-rsa signature that
is implemented but left out of the default PubkeyAcceptedAlgorithms.  The
security-key names are omitted because this build cannot use them.")

(defun query-certificate-name (name)
  "The certificate spelling of signature NAME.

OpenSSH writes most certificate types with the -cert-v01@openssh.com
suffix, but the composite ML-DSA key uses a plain -cert."
  (if (string= name "ssh-mldsa44-ed25519")
      "ssh-mldsa44-ed25519-cert"
      (concatenate 'string name "-cert-v01@openssh.com")))

(defun query-plain-signature-names ()
  "Signature names this client can make or check, without certificates."
  (transport-supported-algorithms +query-plain-signature-names+
                                  :signature-algorithms))

(defun query-signature-algorithms (&key plain-only)
  "Signature names this client can verify, certificate forms included.

PLAIN-ONLY drops the certificate spellings, as -Q sig and -Q key-ca-sign do."
  (let ((names (query-plain-signature-names)))
    (if plain-only
        names
        (loop for name in names
              append (list name (query-certificate-name name))))))

(defun query-name-p (what name &key alias)
  "Whether -Q WHAT names the query NAME.

The lower-case spelling is an exact strcmp in ssh.c.  The capitalised
aliases it also accepts are compared with strcasecmp, so any case of the
alias works while other spellings of the same word do not."
  (or (string= what name)
      (and alias (string-equal what alias))))

(defun query-answer (what)
  (cond
    ((query-name-p what "cipher" :alias "Ciphers")
     (transport-supported-algorithms cl-pnet-ssh:+ssh-all-ciphers+
                                     :ciphers))
    ;; -Q cipher-auth names only the ciphers that authenticate their own
    ;; packets; the CTR and CBC modes rely on the negotiated MAC instead.
    ((string= what "cipher-auth")
     (transport-supported-algorithms
      (remove-if-not #'cl-pnet-ssh::ssh-cipher-aead-p
                     cl-pnet-ssh:+ssh-all-ciphers+)
      :ciphers))
    ((query-name-p what "mac" :alias "MACs")
     (query-mac-algorithms))
    ((query-name-p what "kex" :alias "KexAlgorithms")
     (supported-kex-algorithms))
    ((string= what "compression")
     (transport-supported-algorithms cl-pnet-ssh:+ssh-compressions+
                                     :compressions))
    ((string= what "key")
     ;; -Q key pairs each key type with its certificate, as ssh does.
     (loop for plain in (query-plain-key-algorithms)
           for certificate in (query-certificate-key-algorithms)
           append (list plain certificate)))
    ((string= what "key-plain") (query-plain-key-algorithms))
    ((string= what "key-cert") (query-certificate-key-algorithms))
    ((or (string= what "key-sig")
         (some (lambda (alias) (string-equal what alias))
               '("PubkeyAcceptedKeyTypes" "PubkeyAcceptedAlgorithms"
                 "HostKeyAlgorithms" "HostbasedKeyTypes"
                 "HostbasedAcceptedKeyTypes"
                 "HostbasedAcceptedAlgorithms")))
     (query-signature-algorithms))
    ((or (string= what "sig")
         (string= what "key-ca-sign")
         (string-equal what "CASignatureAlgorithms"))
     (query-signature-algorithms :plain-only t))
    ((string= what "protocol-version") '("2"))
    ((string= what "help")
     '("cipher" "cipher-auth" "compression" "kex"
       "key" "key-cert" "key-plain" "key-sig" "mac" "protocol-version"
       "sig"))
    (t (getopt-fatal "Unsupported query \"~A\"" what))))

(defun print-query (what)
  (dolist (answer (query-answer what))
    (write-line answer))
  (finish-output)
  (uiop:quit 0))

;;; ---- Forwarding specifications ----

(defstruct (forward (:constructor %make-forward))
  bind-address
  bind-port
  bind-path
  host
  port
  target-path
  ;; channels.c resolves a bind address to every matching address and listens
  ;; on each, so the first listener is not the whole forward.  LISTENER stays
  ;; the first one for callers that only need the bound port.
  listener
  listeners
  listener-fd
  listener-watcher
  ;; channels.c creates one listener channel per address, so a running
  ;; forward occupies a slot for each and the ids in "channel N:"
  ;; diagnostics follow them.
  (channel-id nil)
  (channel-ids nil))

(defstruct (forward-tunnel (:constructor %make-forward-tunnel))
  forward
  connection
  channel
  ;; Some channels are not the type they open with on the wire: a -D SOCKS
  ;; connection is a direct-tcpip channel that channels.c calls
  ;; "dynamic-tcpip".  NIL means the wire type is the display type.
  display-type
  (to-channel (make-array 0 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer 0))
  (to-connection (make-array 0 :element-type '(unsigned-byte 8)
                               :adjustable t :fill-pointer 0))
  (local-eof nil)
  (eof-sent nil))

(defstruct (dynamic-forward (:constructor %make-dynamic-forward))
  bind-address
  bind-port
  bind-path
  target-path
  ;; As for -L: one listener channel per resolved address.
  listener
  listeners
  ;; A -D streamlocal SOCKS listener is a raw descriptor with an fd watch,
  ;; not a CL-PNET listener; the handshakes it accepts are tracked here so a
  ;; cancel or shutdown closes them.
  listener-fd
  listener-watcher
  (fd-sessions nil)
  (channel-id nil)
  (channel-ids nil))

(defstruct (socks-session (:constructor %make-socks-session))
  client
  connection
  ;; A reverse dynamic forward (ssh -R port) runs SOCKS on a server-initiated
  ;; channel instead of a local socket.
  channel
  ;; A streamlocal -D accepts a raw descriptor instead of a CL-PNET
  ;; connection.  Once the handshake produces a tunnel, BRIDGE owns FD.
  fd
  watcher
  bridge
  (closed nil)
  ;; The DynamicForward whose listener accepted CONNECTION.  Its bound port
  ;; and address become the "listening port ... to ..." part of the channel's
  ;; remote name, as channels.c takes them from the accepted socket.
  forward
  (state (cl-pnet-socks:make-socks5-server-state))
  ;; channels.c waits for three bytes before it even looks at the SOCKS
  ;; version, and a SOCKS4 request only parses once its NUL-terminated user
  ;; (and host) have arrived.  Bytes held here cover both cases.
  (pending nil))

(defun forwarding-fail (spec control &rest arguments)
  "Report an unusable forwarding SPEC, in ssh's words for the active flag."
  (cond
    (*forwarding-escape-kind*
     ;; process_cmdline() logs one line and keeps the session.
     (log-info "~A"
               (if (string= *forwarding-escape-kind* "close")
                   "Bad forwarding close specification."
                   (format nil "Bad ~A forwarding specification."
                           *forwarding-escape-kind*)))
     (throw 'escape-forward-failure nil))
    (*forwarding-command-line-kind*
     (progn
       (format *error-output* "Bad ~A forwarding specification '~A'~%"
               *forwarding-command-line-kind* spec)
       (finish-output *error-output*)
       (restore-terminal)
       (uiop:quit 255)))
    (t (apply #'fail control arguments))))

(defun expand-forward-spec (spec)
  "SPEC with ${NAME} expanded as parse_forward's dollar_expand does.

OpenSSH expands the environment before it decides which fields are socket
paths, so the expansion can change how many fields the specification has.
A reference that cannot be expanded is reported with the helper's own
diagnostic and then rejected like any other bad specification."
  (or (cl-pnet-ssh::ssh-forward-expand-value spec nil)
      (forwarding-fail spec "invalid forwarding specification ~A" spec)))

(defun split-forward-fields (text)
  "TEXT split at colons, keeping a bracketed IPv6 literal whole.

parse_forward expands ${NAME} first, so the fields come from the expanded
form while messages still name TEXT as the user wrote it."
  (let ((fields '())
        (text (expand-forward-spec text))
        (current (make-string-output-stream)))
    (loop with index = 0
          while (< index (length text))
          for character = (char text index)
          do (cond
               ((char= character #\[)
                (let ((close (position #\] text :start index)))
                  (unless close
                    (forwarding-fail text "unterminated '[' in ~A" text))
                  (write-string (subseq text (1+ index) close) current)
                  (setf index close)))
               ((char= character #\:)
                (push (get-output-stream-string current) fields))
               (t
                (write-char character current)))
          do (incf index)
          finally (push (get-output-stream-string current) fields)
                  (return (nreverse fields)))))

(defun forwarding-port (text spec)
  (let ((port (cl-pnet-ssh:ssh-a2port text)))
    (unless port
      (forwarding-fail spec "invalid port ~S in forwarding specification ~A"
                       text spec))
    port))

(defun path-field-p (text)
  "Whether TEXT names a Unix socket, as OpenSSH decides: it contains \"/\"."
  (find #\/ text))

(defun make-parsed-forward (spec remote-p &key bind-address bind-port bind-path
                                            host port target-path)
  "A FORWARD for a parsed SPEC, or FAIL when it names no usable endpoint.

OpenSSH's rule is used: a forwarding specification needs a target port or
socket path, and a listener that is a socket path or a port.  Only a remote
forward may ask for port 0, which leaves the choice to the server.  A
\"socks\" target is the dynamic form and uses port 0 as its placeholder."
  (unless (or target-path
              (and port (plusp port))
              (and host (string-equal host "socks")))
    (forwarding-fail spec "~A: forwarding needs a target port or socket path"
                     spec))
  (unless (or bind-path
              (and bind-port
                   (if remote-p (<= 0 bind-port) (plusp bind-port))))
    (forwarding-fail spec "~A: forwarding needs a listener port or socket path"
                     spec))
  (%make-forward :bind-address bind-address
                 :bind-port bind-port
                 :bind-path bind-path
                 :host host
                 :port port
                 :target-path target-path))

(defun parse-forward-spec (spec remote-p)
  "SPEC as a FORWARD for ssh's colon-separated -L or -R syntax.

The fields follow OpenSSH's parse_forward: a field containing a slash is a
Unix socket path, anything else is an address or port."
  (let ((fields (split-forward-fields spec)))
    (case (length fields)
      (1
       ;; A one-word -R is readconf's dynamic remote forward: the server
       ;; chooses the port and this client exposes SOCKS through it.
       (destructuring-bind (first) fields
         (unless remote-p
           (forwarding-fail spec "invalid forwarding specification ~A" spec))
         (if (path-field-p first)
             (make-parsed-forward spec remote-p
                                  :bind-path first
                                  :host "socks" :port 0)
             (make-parsed-forward spec remote-p
                                  :bind-port (forwarding-port first spec)
                                  :host "socks" :port 0))))
      (2
       (destructuring-bind (first second) fields
         (cond
           ;; local_socket:remote_socket
           ((and (path-field-p first) (path-field-p second))
            (make-parsed-forward spec remote-p
                                 :bind-path first :target-path second))
           ;; port:remote_socket
           ((path-field-p second)
            (make-parsed-forward spec remote-p
                                 :bind-port (forwarding-port first spec)
                                 :target-path second))
           (t
            ;; bind_address:port, the dynamic form; never a -L or -R.
            (make-parsed-forward spec remote-p
                                 :bind-address (and (plusp (length first))
                                                    first)
                                 :bind-port (forwarding-port second spec))))))
      (3
       (destructuring-bind (first second third) fields
         (cond
           ;; local_socket:host:hostport
           ((path-field-p first)
            (make-parsed-forward spec remote-p
                                 :bind-path first
                                 :host second
                                 :port (forwarding-port third spec)))
           ;; bind_address:port:remote_socket
           ((path-field-p third)
            (make-parsed-forward spec remote-p
                                 :bind-address (and (plusp (length first))
                                                    first)
                                 :bind-port (forwarding-port second spec)
                                 :target-path third))
           ;; port:host:hostport
           (t
            (make-parsed-forward spec remote-p
                                 :bind-port (forwarding-port first spec)
                                 :host second
                                 :port (forwarding-port third spec))))))
      (4
       (destructuring-bind (bind port host hostport) fields
         (make-parsed-forward spec remote-p
                              :bind-address (and (plusp (length bind)) bind)
                              :bind-port (forwarding-port port spec)
                              :host host
                              :port (forwarding-port hostport spec))))
      (t
       (forwarding-fail spec "invalid forwarding specification ~A" spec)))))

(defun parse-local-forward (spec)
  "SPEC as a FORWARD for ssh's -L forms, including Unix-socket paths."
  (parse-forward-spec spec nil))

(defun parse-dynamic-remote-forward (spec)
  "SPEC as parse_forward with dynamicfwd=1 and remotefwd=1 reads it.

ssh checks this form after the ordinary one, so a -R argument with one or
two fields is a remote dynamic forward: the server listens, and this client
answers the channel with SOCKS.  A two-field target that names a socket path
is still the streamlocal listen/target pair."
  (let ((fields (split-forward-fields spec)))
    (case (length fields)
      (1
       (destructuring-bind (first) fields
         (if (path-field-p first)
             (make-parsed-forward spec t
                                  :bind-path first
                                  :host "socks" :port 0)
             (make-parsed-forward spec t
                                  :bind-port (forwarding-port first spec)
                                  :host "socks" :port 0))))
      (2
       (destructuring-bind (first second) fields
         (cond
           ((and (path-field-p first) (path-field-p second))
            (make-parsed-forward spec t
                                 :bind-path first
                                 :target-path second))
           ((path-field-p second)
            (make-parsed-forward spec t
                                 :bind-port (forwarding-port first spec)
                                 :target-path second))
           (t
            (make-parsed-forward spec t
                                 :bind-address first
                                 :bind-port (forwarding-port second spec)
                                 :host "socks" :port 0)))))
      (t
       (forwarding-fail spec "invalid forwarding specification ~A" spec)))))

(defun parse-remote-forward (spec)
  "SPEC as a FORWARD for ssh's -R forms, including the dynamic fallback.

ssh tries parse_forward with dynamicfwd=0 and, when that fails, with
dynamicfwd=1; only a one- or two-field argument can take the second path."
  (let ((fields (split-forward-fields spec)))
    (if (or (= 1 (length fields))
            (and (= 2 (length fields))
                 (not (path-field-p (second fields)))))
        (parse-dynamic-remote-forward spec)
        (parse-forward-spec spec t))))

(defun parse-dynamic-forward (spec)
  "SPEC as a DYNAMIC-FORWARD for [bind_address:]port or a socket path.

parse_forward takes at most two fields when the dynamic flag is set, and a
two-field argument treats the first field as the listening address even when
it contains a slash: only a lone field can be a socket path."
  (let* ((fields (split-forward-fields spec))
         (count (length fields)))
    (case count
      (1
       (let ((first (first fields)))
         (if (path-field-p first)
             (%make-dynamic-forward :bind-path first)
             (let ((port (forwarding-port first spec)))
               (unless (plusp port)
                 (forwarding-fail spec
                                  "invalid forwarding specification ~A" spec))
               (%make-dynamic-forward :bind-port port)))))
      (2
       (destructuring-bind (first second) fields
         (cond
           ((and (path-field-p first) (path-field-p second))
            (%make-dynamic-forward :bind-path first :target-path second))
           ((path-field-p second)
            ;; listen_host stays empty; a2port names the listening port.
            (let ((port (forwarding-port first spec)))
              (unless (plusp port)
                (forwarding-fail spec
                                 "invalid forwarding specification ~A" spec))
              (%make-dynamic-forward :bind-port port :target-path second)))
           (t
            (let ((port (forwarding-port second spec)))
              (unless (plusp port)
                (forwarding-fail spec
                                 "invalid forwarding specification ~A" spec))
              (%make-dynamic-forward :bind-address first :bind-port port))))))
      (t
       (forwarding-fail spec "invalid forwarding specification ~A" spec)))))

(defun split-host-port (text)
  "TEXT as (VALUES HOST PORT-STRING), bracketing IPv6 literals."
  (if (and (plusp (length text)) (char= (char text 0) #\[))
      (let ((close (position #\] text)))
        (if close
            (let ((rest (subseq text (1+ close))))
              (values (subseq text 1 close)
                      (and (> (length rest) 1)
                           (char= (char rest 0) #\:)
                           (subseq rest 1))))
            (values text nil)))
      (let ((colon (position #\: text :from-end t)))
        (if colon
            (values (subseq text 0 colon) (subseq text (1+ colon)))
            (values text nil)))))

(defun parse-host-port (spec)
  "SPEC as (VALUES HOST PORT), or FAIL."
  (multiple-value-bind (host port) (split-host-port spec)
    (unless (and port (plusp (length port)))
      (forwarding-fail spec "~A must be host:port" spec))
    (values host (forwarding-port port spec))))

(defun parse-stdio-forward (spec)
  "SPEC as (VALUES HOST PORT STREAMLOCAL-P), the way ssh.c reads -W.

ssh parses -W with parse_forward(..., dynamicfwd=1, ...) after skipping
leading whitespace, which accepts one or two fields, and then copies
fwd.listen_path when the listener is a socket path and fwd.listen_host
otherwise.  A socket path is therefore a direct-streamlocal target and two
non-path fields are host:port.  A bare port - or a port followed by a target
path - passes parse_forward because only the listening port is checked, but
leaves ssh with a NULL host, so HOST is NIL and nothing is opened.  The
getopt check already rejects everything else, so a failure here only guards
against a value that never went through it."
  (let* ((expanded (cl-pnet-ssh::ssh-forward-expand-value spec nil))
         (text (and expanded
                    (string-left-trim
                     (list #\Space #\Tab #\Newline #\Return #\Page
                           (code-char 11))
                     expanded)))
         (fields (and text
                      (cl-pnet-ssh::ssh-config-forward-fields text))))
    (labels ((bad ()
               (getopt-fatal "Bad stdio forwarding specification '~A'" spec))
             (port (field)
               (cl-pnet-ssh::ssh-config-forward-port (car field)))
             (usable-port (field)
               (let ((value (port field)))
                 (if (plusp value) value (bad)))))
      (unless (and fields (<= 1 (length fields) 2))
        (bad))
      (if (= 1 (length fields))
          (let ((field (first fields)))
            (if (cdr field)
                (values (car field) 0 t)
                (values nil (usable-port field) nil)))
          (destructuring-bind (listener target) fields
            (cond
              ((and (cdr listener) (cdr target))
               (values (car listener) 0 t))
              ((cdr target)
               (values nil (usable-port listener) nil))
              (t
               (values (car listener) (usable-port target) nil))))))))

(defun parse-config-forward (spec remote-p)
  "SPEC as a FORWARD for ssh_config's LocalForward/RemoteForward.

The listener may be [bind_address:]port or a socket path; the target may be
host:hostport or a socket path.  A one-word RemoteForward is readconf's
dynamic form and is parsed with dynamicfwd=1."
  (let ((words (uiop:split-string spec :separator '(#\Space #\Tab))))
    (cond
      ((and remote-p (/= 2 (length words)))
       (parse-dynamic-remote-forward spec))
      ((/= 2 (length words))
       (parse-forward-spec spec remote-p))
      (t
       (destructuring-bind (listen target) words
         (let (bind port bind-path host hostport target-path)
           (if (path-field-p listen)
               (setf bind-path listen)
               (multiple-value-bind (first second) (split-host-port listen)
                 (if second
                     (setf bind (and (plusp (length first)) first)
                           port (forwarding-port second spec))
                     (setf port (forwarding-port first spec)))))
           (if (path-field-p target)
               (setf target-path target)
               (multiple-value-bind (target-host target-port)
                   (split-host-port target)
                 (unless (and target-port (plusp (length target-port)))
                   (fail "~A must be host:port or a socket path" spec))
                 (setf host target-host
                       hostport (forwarding-port target-port spec))))
           (make-parsed-forward spec remote-p
                                :bind-address bind
                                :bind-port port
                                :bind-path bind-path
                                :host host
                                :port hostport
                                :target-path target-path)))))))

(defun parse-config-local-forward (spec)
  "SPEC as a FORWARD for ssh_config's two-word LocalForward form."
  (parse-config-forward spec nil))

(defun parse-config-remote-forward (spec)
  "SPEC as a FORWARD for ssh_config's two-word RemoteForward form."
  (parse-config-forward spec t))

;;; ---- Session ----

;;; A PTY session needs three things the library's session API does not name:
;;; a pty-req channel request before exec/shell, a raw local terminal, and a
;;; window-change request on resize.  They stay here rather than in the
;;; library because they are policy: which terminal settings to save, what
;;; TERM to send, and whether the user asked for a PTY at all.

(defun stop-pty-timer ()
  (when *pty-timer*
    (ignore-errors (cl-pnet:timer-stop *pty-timer*))
    (setf *pty-timer* nil)))

(defun send-channel-request (channel request want-reply fields)
  "Send REQUEST on CHANNEL; FIELDS writes its arguments.

This is the one channel-request form the library does not expose, because
pty-req and window-change are client policy rather than protocol plumbing."
  (cl-pnet-ssh::ssh-channel-send-message
   channel cl-pnet-ssh::+ssh-msg-channel-request+
   :fields (lambda (writer)
             (cl-pnet-ssh::ssh-write-text writer request)
             (cl-pnet-ssh::ssh-write-boolean writer want-reply)
             (funcall fields writer))))

(defun send-pty-request (channel)
  "Ask the peer to attach a PTY to CHANNEL at the terminal's current size.

The terminal-modes string is empty, so sshd applies the defaults of the pty
it allocates.  The local terminal is already raw, and the remote side owns
echo and line editing."
  (multiple-value-bind (rows columns) (terminal-size)
    (unless (and rows columns (plusp rows) (plusp columns))
      (setf rows 24 columns 80))
    (send-channel-request
     channel "pty-req" t
     (lambda (writer)
       (cl-pnet-ssh::ssh-write-text writer (or (uiop:getenv "TERM") "xterm"))
       (cl-pnet-ssh::ssh-write-u32 writer columns)
       (cl-pnet-ssh::ssh-write-u32 writer rows)
       (cl-pnet-ssh::ssh-write-u32 writer 0)
       (cl-pnet-ssh::ssh-write-u32 writer 0)
       (cl-pnet-ssh::ssh-write-string
        writer (make-array 0 :element-type '(unsigned-byte 8)))))))

(defun send-window-change (channel)
  "Tell the peer the terminal size changed."
  (multiple-value-bind (rows columns) (terminal-size)
    (when (and rows columns)
      (send-channel-request
       channel "window-change" nil
       (lambda (writer)
         (cl-pnet-ssh::ssh-write-u32 writer columns)
         (cl-pnet-ssh::ssh-write-u32 writer rows)
         (cl-pnet-ssh::ssh-write-u32 writer 0)
         (cl-pnet-ssh::ssh-write-u32 writer 0))))))

(defun send-exec-request (channel command)
  "Run COMMAND on CHANNEL's PTY."
  (send-channel-request
   channel "exec" t
   (lambda (writer) (cl-pnet-ssh::ssh-write-text writer command)))
  (cl-pnet-ssh::ssh-channel-set-x-type channel "session:command"))

(defun send-shell-request (channel)
  "Start the peer's login shell on CHANNEL, the ssh(1) session default."
  (send-channel-request
   channel "shell" t (lambda (writer) (declare (ignore writer))))
  (cl-pnet-ssh::ssh-channel-set-x-type channel "session:shell"))

(defun send-subsystem-request (channel subsystem)
  (send-channel-request
   channel "subsystem" t
   (lambda (writer) (cl-pnet-ssh::ssh-write-text writer subsystem)))
  (cl-pnet-ssh::ssh-channel-set-x-type
   channel (concatenate 'string "session:subsystem:" subsystem)))

(defun tty-setting (client)
  "The RequestTTY decision, the command line winning over the config file."
  (or (getf *options* :request-tty)
      (let ((options (and client
                          (cl-pnet-ssh:ssh-client-config-options client))))
        (and options
             (cl-pnet-ssh:ssh-config-options-request-tty options)))))

(defun tty-setting-name (setting)
  (cond ((null setting) nil)
        ((stringp setting) (string-downcase setting))
        ((eq setting :force) "force")
        ((eq setting :yes) "yes")
        ((eq setting :no) "no")
        (t (string-downcase (princ-to-string setting)))))

(defun request-tty-p (client command-given-p)
  "Whether to ask for a PTY, following ssh(1)'s -t, -T and RequestTTY.

AUTO is a login session: no remote command and a terminal on stdin.  YES
also asks when a command was given, FORCE asks even without a local terminal,
and NO never asks."
  (let ((setting (tty-setting-name (tty-setting client))))
    (cond
      ((null setting) (and (null command-given-p) (stdin-terminal-p)))
      ((member setting '("no" "off" "false") :test #'string=) nil)
      ((member setting '("force" "yes") :test #'string=)
       (or (string= setting "force") (stdin-terminal-p)))
      ((string= setting "auto")
       (and (null command-given-p) (stdin-terminal-p)))
      (t (and (null command-given-p) (stdin-terminal-p))))))

(defun start-shell-session (channel)
  "Ask for the peer's login shell once CHANNEL opens, without a pty.

The library queues EXEC while a channel opens, but has no queued shell
request, so the state is polled as in the pty path."
  (setf *pty-timer*
        (cl-pnet:timer-start
         0.005 0.005
         (lambda ()
           (case (cl-pnet-ssh::ssh-channel-state channel)
             (:open
              (stop-pty-timer)
              (send-shell-request channel)
              (start-input channel))
             (:closed (stop-pty-timer))
             (t nil))))))

(defun start-pty-session (channel command command-given-p)
  "Wait for CHANNEL to open, then send pty-req, the remote request, and input.

The library sends exec as soon as the open confirmation arrives, but pty-req
must precede it.  Polling the channel state from the event loop keeps that
ordering without adding a request hook to the library."
  (terminal-enter-raw)
  (setf *pty-timer*
        (cl-pnet:timer-start
         0.005 0.005
         (lambda ()
           (case (cl-pnet-ssh::ssh-channel-state channel)
             (:open
              (stop-pty-timer)
              (setf *pty-channel* channel)
              (send-pty-request channel)
              (start-winch channel)
              (cond
                ((and (subsystem-request-p) command-given-p)
                 (send-subsystem-request channel command))
                (command-given-p
                 (send-exec-request channel command))
                (t
                 (send-shell-request channel)))
              (start-input channel))
             (:closed
              (stop-pty-timer))
             (t nil))))))

(defun start-input (channel)
  "Feed stdin to CHANNEL, or report EOF at once under -n."
  (if (stdin-null-p)
      (cl-pnet-ssh:ssh-channel-eof channel)
      (start-stdin channel)))

;;; ---- ObscureKeystrokeTiming ----
;;;
;;; ssh hides the timing of interactive typing by sending keystrokes only at
;;; fixed intervals, so an observer cannot measure pauses between keys.  The
;;; interval is randomised by ten percent, both per keystroke and for the
;;; whole session, and hiding continues for one to three seconds after the
;;; last keystroke.  This application owns stdin, so the policy lives here
;;; while the library carries the configured interval.

(defun keystroke-now ()
  "Seconds on CL's internal real-time clock."
  (/ (float (get-internal-real-time) 1.0d0)
     (float internal-time-units-per-second 1.0d0)))

(defun keystroke-delay (milliseconds rate-fuzz)
  "One randomised interval of MILLISECONDS, offset by RATE-FUZZ seconds."
  (let* ((interval (/ milliseconds 1000.0))
         (fuzz (* interval 0.10)))
    (+ (- interval fuzz) (random fuzz) rate-fuzz)))

(defun keystroke-live-p (channel)
  "Whether CHANNEL can still take input."
  (and channel
       *client*
       (not (cl-pnet-ssh::ssh-client-closed-p *client*))
       (eq (cl-pnet-ssh::ssh-channel-state channel) :open)))

(defun keystroke-obfuscation-interval (channel)
  "CHANNEL's quantisation interval in milliseconds, or NIL when it has none."
  (when (and *client* (eq channel *pty-channel*))
    (let ((interval (cl-pnet-ssh:ssh-client-obscure-keystroke-timing *client*)))
      (and interval (plusp interval) interval))))

(defun stop-keystroke-timer ()
  (when *keystroke-timer*
    (let ((timer *keystroke-timer*))
      (setf *keystroke-timer* nil)
      (ignore-errors (cl-pnet:timer-stop timer)))))

(defun keystroke-schedule (delay milliseconds)
  "Run one tick after DELAY seconds."
  (stop-keystroke-timer)
  (setf *keystroke-timer*
        (cl-pnet:timer-start
         (max 0.001 delay) 0.0
         (lambda () (keystroke-tick milliseconds)))))

(defun keystroke-flush (channel)
  "Write every held keystroke now."
  (when (plusp (fill-pointer *keystroke-pending*))
    (let ((pending (subseq *keystroke-pending* 0
                           (fill-pointer *keystroke-pending*))))
      (setf (fill-pointer *keystroke-pending*) 0)
      (cl-pnet-ssh:ssh-channel-write channel pending))))

(defun keystroke-stop-active ()
  "Stop hiding timing, dropping anything still held."
  (when *keystroke-active*
    (cl-pnet-ssh:ssh-log "stopped obscuring keystroke timing"))
  (stop-keystroke-timer)
  (setf *keystroke-active* nil
        *keystroke-channel* nil
        *keystroke-rate-fuzz* 0
        (fill-pointer *keystroke-pending*) 0))

(defun keystroke-start (channel milliseconds)
  "Release CHANNEL's first keystroke immediately, then begin quantising."
  (let* ((now (keystroke-now))
         (interval (/ milliseconds 1000.0))
         (fuzz (* interval 0.10))
         (rate-fuzz (random fuzz)))
    (setf *keystroke-active* t
          *keystroke-channel* channel
          *keystroke-rate-fuzz* rate-fuzz
          ;; ssh keeps hiding for 1024ms plus up to another 2048ms.
          *keystroke-chaff-until* (+ now 1.024 (random 2.048)))
    (cl-pnet-ssh:ssh-log "obscuring keystroke timing at ~Dms" milliseconds)
    (keystroke-schedule (keystroke-delay milliseconds rate-fuzz)
                        milliseconds)))

(defun keystroke-tick (milliseconds)
  "Release the keystrokes held for the interval that just ended."
  ;; A one-shot timer has already fired; clearing the handle keeps
  ;; STOP-KEYSTROKE-TIMER from stopping a handle the loop has freed.
  (setf *keystroke-timer* nil)
  (let ((channel *keystroke-channel*))
    (cond
      ((not (keystroke-live-p channel))
       (keystroke-stop-active))
      (t
       (let ((now (keystroke-now))
             (flushed nil))
         (when (plusp (fill-pointer *keystroke-pending*))
           (handler-case
               (progn
                 (keystroke-flush channel)
                 (setf flushed t))
             (error ()
               (keystroke-stop-active)
               (return-from keystroke-tick nil)))
           ;; A keystroke was sent, so the chaff window starts over.
           (setf *keystroke-chaff-until* (+ now 1.024 (random 2.048))))
         (cond
           ;; Rekeying and a closed pty stop the hiding, but only after what
           ;; was already typed has gone out.
           ((or (not (eq channel *pty-channel*))
                (cl-pnet-ssh::ssh-client-kexinit-sent *client*))
            (keystroke-stop-active))
           ((and (not flushed)
                 (zerop (fill-pointer *keystroke-pending*))
                 (>= now *keystroke-chaff-until*))
            (keystroke-stop-active))
           (t
            ;; With no keystroke due, a PING the size of one keystroke keeps
            ;; the idle pattern indistinguishable when the server allows it.
            (when (and (not flushed)
                       (zerop (fill-pointer *keystroke-pending*)))
              (handler-case
                  (cl-pnet-ssh:ssh-client-send-chaff *client*)
                (error ()
                  (keystroke-stop-active)
                  (return-from keystroke-tick nil))))
            (keystroke-schedule
             (keystroke-delay milliseconds *keystroke-rate-fuzz*)
             milliseconds))))))))

(defun feed-keystrokes (channel octets)
  "Write OCTETS from stdin to CHANNEL, hiding inter-keystroke timing.

The first keystroke of a burst goes out at once, as ssh's just_started does.
Later ones wait for the next interval.  A paste of more than a few keystrokes
turns the hiding off and is written straight through, matching ssh's
\"output buffer filling\" stop."
  (let ((milliseconds (keystroke-obfuscation-interval channel)))
    (cond
      ((or (null milliseconds) (not (keystroke-live-p channel)))
       (cl-pnet-ssh:ssh-channel-write channel octets))
      ((not (and *keystroke-active*
                 (eq *keystroke-channel* channel)))
       (cl-pnet-ssh:ssh-channel-write channel octets)
       (keystroke-start channel milliseconds))
      (t
       (loop for octet across octets
             do (vector-push-extend octet *keystroke-pending*))
       (when (>= (fill-pointer *keystroke-pending*) 256)
         (let ((pending (subseq *keystroke-pending* 0
                                (fill-pointer *keystroke-pending*))))
           (keystroke-stop-active)
           (cl-pnet-ssh:ssh-channel-write channel pending)))))))

(defun finish-keystrokes (channel)
  "Release CHANNEL's held keystrokes before stdin reports EOF."
  (when (and *keystroke-active* (eq *keystroke-channel* channel))
    (ignore-errors (keystroke-flush channel)))
  (keystroke-stop-active))

(defun stop-keystroke-obfuscation ()
  "Forget the pty channel; the session is over."
  (keystroke-stop-active)
  (setf *pty-channel* nil))

(defun quit-now (status)
  "Leave with STATUS without flushing streams again.

The normal path has already flushed both streams.  On the broken-pipe path
the kernel has rejected stdout, and SB-EXT:EXIT would try to flush it once
more and hang instead of exiting; :ABORT T skips that and the exit hooks."
  (restore-terminal)
  #+sbcl (sb-ext:exit :code status :abort t)
  #-sbcl (uiop:quit status))

(defun report-transfer-stats (client)
  "Print ssh's verbose exit summary: wire bytes and their rates."
  (let* ((info (cl-pnet-ssh::ssh-client-connection-info client))
         (traffic (getf info :traffic))
         (start (or (getf info :connected-at) (get-universal-time)))
         (seconds
           (if *session-loop-start*
               (max 0.0d0
                    (/ (float (- (get-internal-real-time)
                                 *session-loop-start*)
                              1.0d0)
                       (float internal-time-units-per-second 1.0d0)))
               (coerce (max 0 (- (get-universal-time) start)) 'double-float)))
         (sent (or (getf traffic :sent-bytes) 0))
         (received (or (getf traffic :received-bytes) 0)))
    (format *error-output*
            "Transferred: sent ~D, received ~D bytes, in ~,1F seconds~C~C"
            sent received seconds #\Return #\Newline)
    (when (plusp seconds)
      (format *error-output*
              "Bytes per second: sent ~,1F, received ~,1F~C~C"
              (float (/ sent seconds) 1.0d0)
              (float (/ received seconds) 1.0d0)
              #\Return #\Newline))
    (finish-output *error-output*)))

(defun finish (status)
  ;; Closing the client below reports its open channels closed, whose
  ;; callbacks call FINISH again; only the outermost call may quit, or the
  ;; connection (and a ProxyCommand helper) would be left half torn down.
  (unless *finishing*
    (setf *finishing* t)
    (restore-terminal)
    ;; clientloop.c reports a connection the peer dropped before it reports
    ;; the interactive close.
    (when (and *client*
               (eq (cl-pnet-ssh::ssh-client-close-reason *client*)
                   :peer-closed)
               (not (member (log-level-setting)
                            '("quiet" "fatal" "error")
                            :test #'string-equal)))
      (format *error-output*
              "Connection to ~A closed by remote host.~C~C"
              (cl-pnet-ssh:ssh-client-host *client*)
              #\Return #\Newline)
      (finish-output *error-output*))
    ;; client_loop() reports the end of an interactive session before it
    ;; sends DISCONNECT, and only when the log level still shows INFO.
    (when (and *pty-channel* *client*
               (not (member (log-level-setting)
                            '("quiet" "fatal" "error")
                            :test #'string-equal)))
      (format *error-output* "Connection to ~A closed.~C~C"
              (cl-pnet-ssh:ssh-client-host *client*)
              #\Return #\Newline)
      (finish-output *error-output*))
    (stop-pty-timer)
    (stop-winch)
    (stop-stdin)
    (stop-keystroke-obfuscation)
    (when (and *session-loop-started*
               (plusp (getf *options* :verbose 0)))
      (ignore-errors (report-transfer-stats *client*)))
    (stop-forwards)
    ;; Stop listening before the connection goes away, so a client cannot
    ;; connect to a master that is already closing.
    (when *mux-master*
      (mux-master-stop *mux-master*))
    ;; Close the client before leaving: a ProxyCommand's helper is a child
    ;; process, and quitting without closing would leave it running.
    (when *client*
      (let ((client *client*))
        (setf *client* nil)
        (ignore-errors (cl-pnet-ssh:ssh-client-close client))))
    (ignore-errors (finish-output *standard-output*))
    (ignore-errors (finish-output *error-output*))
    (quit-now (or status 255))))

(defun session-error (channel condition)
  "Report a refused session channel open the way ssh.c does.

channels.c logs \"channel N: open failed: reason: message\" and
ssh_session2_setup() returns without a second diagnostic, so the process
leaves with 255 after that one line.  Anything else is a local failure and
keeps the burs: prefix."
  (if (and (typep condition 'cl-pnet-ssh:ssh-channel-error)
           (integerp (cl-pnet-ssh:ssh-channel-error-reason condition)))
      (log-channel-open-failure channel condition)
      (format *error-output* "burs: ~A~%" condition))
  (finish 255))

(defun start-session (client command command-given-p)
  (setf *channel*
        (cl-pnet-ssh:ssh-open-session
         client
         :on-data (lambda (channel data kind)
                    (declare (ignore channel))
                    (write-octets (ecase kind (:stdout *standard-output*)
                                         (:stderr *error-output*))
                                  data))
         :on-exit (lambda (channel status)
                    (declare (ignore channel))
                    (setf *status* status))
         :on-close (lambda (channel status)
                     (declare (ignore channel status))
                     (finish *status*))
         :on-error #'session-error))
  (unless (and (subsystem-request-p) command-given-p)
    (dolist (name (cl-pnet-ssh:ssh-client-send-env client))
      (let ((value (uiop:getenv name)))
        (when value
          (cl-pnet-ssh:ssh-channel-env *channel* name value))))
    (dolist (assignment (cl-pnet-ssh:ssh-client-set-env client))
      (let ((equals (position #\= assignment)))
        (when equals
          (cl-pnet-ssh:ssh-channel-env
           *channel*
           (subseq assignment 0 equals)
           (subseq assignment (1+ equals)))))))
  (if (request-tty-p client command-given-p)
      (start-pty-session *channel* command command-given-p)
      (cond
        ((and (subsystem-request-p) command-given-p)
         (cl-pnet-ssh:ssh-channel-subsystem *channel* command)
         (start-input *channel*))
        (command-given-p
         (cl-pnet-ssh:ssh-channel-exec *channel* command)
         (start-input *channel*))
        (t
         (start-shell-session *channel*)))))

;;; ---- -W: stream stdin and stdout over one channel ----

(defun start-stdio-forward (client host port streamlocal)
  ;; A -W specification with no host (a bare port) leaves ssh's
  ;; stdio_forward_host NULL, so ssh_init_stdio_forwarding returns without
  ;; opening a channel and the connection simply stays up until it closes.
  (when host
    (let ((callbacks
            (list :on-data
                  (lambda (channel data kind)
                    (declare (ignore channel))
                    (write-octets (ecase kind (:stdout *standard-output*)
                                         (:stderr *error-output*))
                                  data))
                  :on-close
                  (lambda (channel status)
                    (declare (ignore channel status))
                    (finish *status*))
                  :on-error
                  (lambda (channel condition)
                    (if (and (typep condition 'cl-pnet-ssh:ssh-channel-error)
                             (integerp
                              (cl-pnet-ssh:ssh-channel-error-reason
                               condition)))
                        (progn
                          ;; channels.c logs the refusal at logit(), then
                          ;; ssh_stdio_confirm() is fatal().
                          (log-channel-open-failure channel condition)
                          (log-fatal "stdio forwarding failed"))
                        (progn
                          (format *error-output* "burs: ~A~%" condition)
                          (finish 255)))))))
      (setf *status* 0
            *channel*
            (if streamlocal
                (apply #'cl-pnet-ssh:ssh-open-direct-streamlocal
                       client host callbacks)
                (apply #'cl-pnet-ssh:ssh-open-direct-tcpip
                       client host port callbacks))))
    (log-line "stdio forward to ~A:~D" host (if streamlocal -2 port))
    (start-input *channel*)))

;;; ---- -L: local forwarding ----

(defun buffer-append (buffer data)
  (loop for octet across data
        do (vector-push-extend octet buffer))
  buffer)

(defun buffer-drain (buffer)
  (when (plusp (fill-pointer buffer))
    (prog1 (subseq buffer 0 (fill-pointer buffer))
      (setf (fill-pointer buffer) 0))))

(defun gateway-ports-p (options)
  (or (getf *options* :gateway-ports)
      (and options
           (cl-pnet-ssh:ssh-config-options-gateway-ports options))))

(defun forward-connection-data (connection data)
  (let ((tunnel (gethash connection *tunnels*)))
    (when tunnel
      (forward-read tunnel data))))

(defun forward-send (tunnel data)
  "Move bytes from the forwarded channel toward the local client."
  (if (forward-tunnel-connection tunnel)
      (cl-pnet:send-data (forward-tunnel-connection tunnel) data)
      (buffer-append (forward-tunnel-to-connection tunnel) data)))

(defun forward-flush-to-connection (tunnel)
  (when (forward-tunnel-connection tunnel)
    (let ((data (buffer-drain (forward-tunnel-to-connection tunnel))))
      (when data
        (cl-pnet:send-data (forward-tunnel-connection tunnel) data)))))

(defun forward-read (tunnel data)
  "Move bytes from the local client toward the forwarded channel."
  (cond
    ((null data)
     (setf (forward-tunnel-local-eof tunnel) t)
     (when (forward-tunnel-channel tunnel)
       (cl-pnet-ssh:ssh-channel-eof (forward-tunnel-channel tunnel))))
    ((forward-tunnel-channel tunnel)
     (cl-pnet-ssh:ssh-channel-write (forward-tunnel-channel tunnel) data))
    (t
     (buffer-append (forward-tunnel-to-channel tunnel) data))))

(defun forward-flush (tunnel)
  "Send whatever waited for the channel, then report a local EOF once."
  (when (forward-tunnel-channel tunnel)
    (let ((data (buffer-drain (forward-tunnel-to-channel tunnel))))
      (when data
        (cl-pnet-ssh:ssh-channel-write (forward-tunnel-channel tunnel) data)))
    (when (and (forward-tunnel-local-eof tunnel)
               (not (forward-tunnel-eof-sent tunnel)))
      (setf (forward-tunnel-eof-sent tunnel) t)
      (cl-pnet-ssh:ssh-channel-eof (forward-tunnel-channel tunnel)))))

(defun forward-close (tunnel)
  (when (forward-tunnel-connection tunnel)
    (let ((connection (forward-tunnel-connection tunnel)))
      (setf (forward-tunnel-connection tunnel) nil)
      (remhash connection *tunnels*)
      (ignore-errors (cl-pnet:close-connection connection))))
  (when (forward-tunnel-channel tunnel)
    (let ((channel (forward-tunnel-channel tunnel)))
      (setf (forward-tunnel-channel tunnel) nil)
      (ignore-errors (cl-pnet-ssh:ssh-channel-close channel)))))

;;; ---- client stream-local tunnels ----
;;;
;;; A -L or -R forward can carry a Unix-domain socket instead of TCP.  The
;;; application owns that descriptor and bridges it to the SSH channel, just
;;; as the server does for its direct/forwarded streamlocal channels.

(defstruct (client-streamlocal (:constructor %make-client-streamlocal))
  channel
  path
  fd
  read-watcher
  write-watcher
  (pending (make-array 0 :element-type '(unsigned-byte 8)
                         :adjustable t :fill-pointer 0))
  (offset 0)
  (input-closed nil)
  (output-closed nil)
  (shutdown-done nil)
  (closed nil))

(defun client-streamlocal-close (bridge)
  "Close BRIDGE's socket and watchers once."
  (unless (client-streamlocal-closed bridge)
    (setf (client-streamlocal-closed bridge) t)
    (when (client-streamlocal-read-watcher bridge)
      (cl-pnet:fd-unwatch (client-streamlocal-read-watcher bridge))
      (setf (client-streamlocal-read-watcher bridge) nil))
    (when (client-streamlocal-write-watcher bridge)
      (cl-pnet:fd-unwatch (client-streamlocal-write-watcher bridge))
      (setf (client-streamlocal-write-watcher bridge) nil))
    (let ((fd (client-streamlocal-fd bridge)))
      (when (and fd (not (minusp fd)))
        (ignore-errors (cl-pnet-sockets:close-open-fd fd))
        (setf (client-streamlocal-fd bridge) nil)))))

(defun client-streamlocal-shutdown-input (bridge)
  "Shut the socket's write side once the channel's queued data has drained."
  (when (and (client-streamlocal-input-closed bridge)
             (not (client-streamlocal-shutdown-done bridge))
             (zerop (fill-pointer (client-streamlocal-pending bridge))))
    (setf (client-streamlocal-shutdown-done bridge) t)
    (let ((fd (client-streamlocal-fd bridge)))
      (when (and fd (not (minusp fd)))
        (ignore-errors (cl-pnet-sockets:c-shutdown fd 1))))))

(defun client-streamlocal-flush (bridge)
  "Send BRIDGE's queued channel data to the Unix socket."
  (unless (or (client-streamlocal-closed bridge)
              (client-streamlocal-input-closed bridge))
    (let* ((fd (client-streamlocal-fd bridge))
           (pending (client-streamlocal-pending bridge))
           (offset (client-streamlocal-offset bridge))
           (failed nil))
      (loop while (< offset (fill-pointer pending))
            do (multiple-value-bind (count error)
                   (cl-pnet-sockets:write-octets fd pending :start offset)
                 (cond
                   ((plusp count) (incf offset count))
                   ((member error '(4 11)) (return))
                   (t (setf failed error) (return)))))
      (setf (client-streamlocal-offset bridge) offset)
      (cond
        (failed
         (client-streamlocal-close bridge)
         (ignore-errors
           (cl-pnet-ssh:ssh-channel-close
            (client-streamlocal-channel bridge))))
        ((>= offset (fill-pointer pending))
         (setf (fill-pointer pending) 0
               (client-streamlocal-offset bridge) 0)
         (when (client-streamlocal-write-watcher bridge)
           (cl-pnet:fd-unwatch (client-streamlocal-write-watcher bridge))
           (setf (client-streamlocal-write-watcher bridge) nil))
         (client-streamlocal-shutdown-input bridge))
        (t
         (unless (client-streamlocal-write-watcher bridge)
           (setf (client-streamlocal-write-watcher bridge)
                 (cl-pnet:fd-watch
                  fd :on-writable
                  (lambda (watcher)
                    (declare (ignore watcher))
                    (setf (client-streamlocal-write-watcher bridge) nil)
                    (client-streamlocal-flush bridge))))))))))

(defun client-streamlocal-on-data (bridge data)
  "Queue channel DATA for the Unix socket."
  (unless (or (client-streamlocal-closed bridge)
              (client-streamlocal-input-closed bridge))
    (let ((pending (client-streamlocal-pending bridge)))
      (loop for octet across data
            do (vector-push-extend octet pending)))
    (client-streamlocal-flush bridge)))

(defun client-streamlocal-on-eof (bridge)
  "The channel sent EOF: drain what it queued, then shut the socket's writer."
  (unless (client-streamlocal-closed bridge)
    (setf (client-streamlocal-input-closed bridge) t)
    (client-streamlocal-shutdown-input bridge)
    (when (client-streamlocal-output-closed bridge)
      (ignore-errors
        (cl-pnet-ssh:ssh-channel-close
         (client-streamlocal-channel bridge))))))

(defun client-streamlocal-on-readable (bridge)
  "Read the Unix socket and send what it yields to the channel."
  (unless (client-streamlocal-closed bridge)
    (multiple-value-bind (data count error)
        (cl-pnet-sockets:read-octets (client-streamlocal-fd bridge) 4096)
      (cond
        ((plusp count)
         (ignore-errors
           (cl-pnet-ssh:ssh-channel-write
            (client-streamlocal-channel bridge) data)))
        ;; A spurious readiness notification is not an error.
        ((and (minusp count) (member error '(4 11))) nil)
        ((or (zerop count) (member error '(5 104 111)))
         ;; EOF, EIO on a closed peer, ECONNRESET or ECONNREFUSED.
         (setf (client-streamlocal-output-closed bridge) t)
         (when (client-streamlocal-read-watcher bridge)
           (cl-pnet:fd-unwatch (client-streamlocal-read-watcher bridge))
           (setf (client-streamlocal-read-watcher bridge) nil))
         (ignore-errors
           (cl-pnet-ssh:ssh-channel-eof
            (client-streamlocal-channel bridge)))
         (when (client-streamlocal-input-closed bridge)
           (ignore-errors
             (cl-pnet-ssh:ssh-channel-close
              (client-streamlocal-channel bridge)))))
        (t
         (client-streamlocal-close bridge)
         (ignore-errors
           (cl-pnet-ssh:ssh-channel-close
            (client-streamlocal-channel bridge))))))))

(defun client-streamlocal-install (bridge)
  "Route CHANNEL's traffic through BRIDGE."
  (let ((channel (client-streamlocal-channel bridge)))
    (setf (cl-pnet-ssh:ssh-channel-on-data channel)
          (lambda (channel data kind)
            (declare (ignore channel kind))
            (client-streamlocal-on-data bridge data))
          (cl-pnet-ssh:ssh-channel-on-eof channel)
          (lambda (channel)
            (declare (ignore channel))
            (client-streamlocal-on-eof bridge))
          (cl-pnet-ssh:ssh-channel-on-close channel)
          (lambda (channel reason)
            (declare (ignore channel reason))
            (client-streamlocal-close bridge)))))

(defun client-streamlocal-connected (bridge)
  "BRIDGE's socket is connected: watch it and send anything already queued."
  (setf (client-streamlocal-read-watcher bridge)
        (cl-pnet:fd-watch
         (client-streamlocal-fd bridge)
         :on-readable
         (lambda (watcher)
           (declare (ignore watcher))
           (client-streamlocal-on-readable bridge))))
  (client-streamlocal-flush bridge))

(defun client-streamlocal-connect-failed (bridge errno)
  "Report that BRIDGE's socket refused its connect, then close both ends."
  (unless (getf *options* :quiet)
    (format *error-output*
            "burs: cannot connect to ~A: ~A~%"
            (client-streamlocal-path bridge)
            (cl-pnet-sockets:c-strerror errno)))
  (client-streamlocal-close bridge)
  (ignore-errors
    (cl-pnet-ssh:ssh-channel-close (client-streamlocal-channel bridge))))

(defun open-client-streamlocal (channel path)
  "Connect CHANNEL to the local Unix socket PATH."
  (multiple-value-bind (fd state)
      (cl-pnet-sockets:connect-unix path)
    (if (null fd)
        (progn
          (unless (getf *options* :quiet)
            (format *error-output*
                    "burs: cannot connect to ~A: ~A~%"
                    path (cl-pnet-sockets:c-strerror state)))
          (ignore-errors (cl-pnet-ssh:ssh-channel-close channel)))
        (let ((bridge (%make-client-streamlocal
                       :channel channel :fd fd :path path)))
          (setf (cl-pnet-ssh::ssh-channel-display-fd channel) fd)
          (client-streamlocal-install bridge)
          (if (eq state :connected)
              (client-streamlocal-connected bridge)
              (setf (client-streamlocal-write-watcher bridge)
                    (cl-pnet:fd-watch
                     fd :on-writable
                     (lambda (watcher)
                       (declare (ignore watcher))
                       (setf (client-streamlocal-write-watcher bridge) nil)
                       (multiple-value-bind (errno answered)
                           (cl-pnet-sockets:socket-error fd)
                         (if (and answered (zerop errno))
                             (client-streamlocal-connected bridge)
                             (client-streamlocal-connect-failed
                              bridge errno)))))))
          bridge))))

(defun open-forward-target-channel (client forward
                                    &key on-data on-open on-eof on-close
                                      on-error)
  "Open the direct channel that carries FORWARD to the peer.

The target is a Unix socket when FORWARD names one and TCP otherwise."
  (if (forward-target-path forward)
      (cl-pnet-ssh:ssh-open-direct-streamlocal
       client (forward-target-path forward)
       :on-data on-data :on-open on-open :on-eof on-eof
       :on-close on-close :on-error on-error)
      (cl-pnet-ssh:ssh-open-direct-tcpip
       client (forward-host forward) (forward-port forward)
       :on-data on-data :on-open on-open :on-eof on-eof
       :on-close on-close :on-error on-error)))

(defun forward-target-name (forward)
  "A human-readable name for what FORWARD dials."
  (or (forward-target-path forward)
      (format nil "~A:~D" (forward-host forward) (forward-port forward))))

(defun connection-local-endpoint (connection)
  "The (VALUES ADDRESS PORT) CONNECTION is bound to, or NIL NIL.

channels.c's remote_name takes both from the accepted socket with
getsockname(), so a wildcard listener reports the address that actually
received the connection rather than the wildcard it bound."
  (let ((fd (and connection
                 (ignore-errors (cl-pnet:connection-fileno connection)))))
    (when (and (integerp fd) (>= fd 0))
      (handler-case
          (cffi:with-foreign-objects
              ((address '(:struct cl-pnet-sockets:sockaddr-in6))
               (length :unsigned-int))
            (setf (cffi:mem-ref length :unsigned-int)
                  cl-pnet-sockets:+sockaddr-in6-size+)
            (when (>= (cl-pnet-sockets:c-getsockname fd address length) 0)
              (cl-pnet-sockets:sockaddr-to-string address)))
        (error () (values nil nil))))))

(defun forward-channel-remote-name (forward connection)
  "channels.c's c->remote_name for a forwarded connection.

The accepted connection supplies the peer and the local address, the
listener the bound port, and the forward what the peer is asked to reach."
  (let* ((peer (and connection
                   (ignore-errors
                    (cl-pnet:connection-peer-address connection))))
         (remote-ip (getf peer :address))
         (remote-port (getf peer :port))
         (listener (forward-listener forward))
         (bound-address (and listener
                             (ignore-errors
                              (cl-pnet:listener-bound-address listener))))
         (bound-port (and listener
                          (ignore-errors (cl-pnet:listener-port listener)))))
    (multiple-value-bind (local-ip local-port)
        (if connection
            (connection-local-endpoint connection)
            (values nil nil))
      (setf local-ip (or local-ip bound-address
                         (forward-bind-address forward) "0.0.0.0")
            local-port (or local-port bound-port
                           (forward-bind-port forward) 0))
      (format nil "~A: listening port ~D for ~A port ~D, connect from ~A port ~D to ~A port ~D"
              (if (forward-target-path forward)
                  "direct-streamlocal@openssh.com"
                  "direct-tcpip")
              (or bound-port (forward-bind-port forward) 0)
              (or (forward-target-path forward)
                  (forward-host forward)
                  "unknown")
              (or (forward-port forward) 0)
              (or remote-ip "unknown") (or remote-port 0)
              local-ip local-port))))

(defun open-forward-channel (client tunnel &key on-open on-error)
  "Open a direct channel for TUNNEL and start bridging bytes.

ON-OPEN runs once the peer confirms the channel.  ON-ERROR, when given,
replaces the usual diagnostic for a failed open; either way the tunnel is
closed afterwards."
  (let ((forward (forward-tunnel-forward tunnel)))
    (flet ((failed (condition)
             (if on-error
                 (funcall on-error condition)
                 ;; channels.c's channel_input_open_failure() already
                 ;; printed the refusal; ssh adds nothing of its own for a
                 ;; local forward, so only report failures that did not go
                 ;; through an SSH open.
                 (unless (and (typep condition 'cl-pnet-ssh:ssh-channel-error)
                              (integerp
                               (cl-pnet-ssh:ssh-channel-error-reason
                                condition)))
                   (unless (getf *options* :quiet)
                     (format *error-output*
                             "burs: forward to ~A failed: ~A~%"
                             (forward-target-name forward)
                             condition))))
             (forward-close tunnel)))
      (handler-case
          (let ((channel
                  (open-forward-target-channel
                   client forward
                   :on-data (lambda (channel data kind)
                              (declare (ignore channel kind))
                              (forward-send tunnel data))
                   :on-open (and on-open
                                 (lambda (channel)
                                   (declare (ignore channel))
                                   (funcall on-open)))
                   :on-eof (lambda (channel)
                             (declare (ignore channel))
                             (forward-close tunnel))
                   :on-close (lambda (channel reason)
                               (declare (ignore channel reason))
                               (forward-close tunnel))
                   :on-error (lambda (channel condition)
                               (log-channel-open-failure channel condition)
                               (failed condition)))))
            (setf (forward-tunnel-channel tunnel) channel)
            (when (forward-tunnel-display-type tunnel)
              (setf (cl-pnet-ssh::ssh-channel-x-type channel)
                    (forward-tunnel-display-type tunnel)))
            (setf (cl-pnet-ssh::ssh-channel-remote-name channel)
                  (forward-channel-remote-name
                   forward (forward-tunnel-connection tunnel)))
            (let ((connection (forward-tunnel-connection tunnel)))
              (when connection
                (setf (cl-pnet-ssh::ssh-channel-display-fd channel)
                      (ignore-errors
                       (cl-pnet:connection-fileno connection)))))
            (forward-flush tunnel)
            (forward-flush-to-connection tunnel))
        (error (condition) (failed condition))))))

(defun forward-accept (client forward connection)
  (let ((tunnel (%make-forward-tunnel :forward forward
                                      :connection connection)))
    (setf (gethash connection *tunnels*) tunnel)
    (open-forward-channel client tunnel)))

(defun escape-char-setting (client)
  "The escape character for CLIENT, NIL when disabled."
  (let ((explicit (getf *options* :escape-char))
        (options (cl-pnet-ssh:ssh-client-config-options client)))
    (cond
      (explicit
       (let ((value (cl-pnet-ssh::ssh-config-escape-char-value explicit)))
         (if (eq value :none) nil (or value #\~))))
      (options
       (let ((value (cl-pnet-ssh:ssh-config-options-escape-char options)))
         (if (eq value :none) nil (or value #\~))))
      (t #\~))))

(defun escape-commandline-enabled-p (client)
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (cl-pnet-ssh:ssh-config-options-enable-escape-commandline
          options))))

(defun print-escape-help ()
  "Print ssh's escape help, in clientloop.c's order and spelling."
  (flet ((line (command text)
           (format *error-output* " ~C~3A - ~A~C~C"
                   *escape-char* command text #\Return #\Newline)))
    (format *error-output* "Supported escape sequences:~C~C"
            #\Return #\Newline)
    (line "." "terminate connection (and any multiplexed sessions)")
    (line "B" "send a BREAK to the remote system")
    (when *escape-commandline-function*
      (line "C" "open a command line"))
    (line "I" "show connection information")
    (line "R" "request rekey")
    (line "V/v" "decrease/increase verbosity (LogLevel)")
    (line "^Z" "suspend ssh")
    (line "#" "list forwarded connections")
    (when *escape-background-function*
      (line "&" "background ssh (when waiting for connections to terminate)"))
    (line "?" "this message")
    (format *error-output* " ~C~C   - send the escape character by typing it twice~C~C"
            *escape-char* *escape-char* #\Return #\Newline)
    (format *error-output*
            "(Note that escapes are only recognized immediately after newline.)~C~C"
            #\Return #\Newline))
  (finish-output *error-output*))

(defun client-session-channel-status (out channel)
  "Write the client-session channel as channel_format_status() spells it.

Remote names, the extended type and the local pty flag come from the
channel; the descriptor numbers are this implementation's own."
  (let* ((state (cl-pnet-ssh::ssh-channel-state channel))
         (open (member state '(:open :closing)))
         (remote-id (cl-pnet-ssh::ssh-channel-remote-id channel))
         (x-type (cl-pnet-ssh::ssh-channel-x-type channel))
         (ctype (or x-type
                    (cl-pnet-ssh::ssh-channel-type channel)
                    "session"))
         (eof (cl-pnet-ssh::ssh-channel-sent-eof channel))
         (write-queue (cl-pnet-ssh::ssh-channel-write-queue channel)))
    (mux-format-channel-status
     out (cl-pnet-ssh::ssh-channel-local-id channel) "client-session"
     (if open 4 3) ctype (and remote-id t) (or remote-id 0) nil
     ;; i3 is CHAN_INPUT_CLOSED: the local side has sent EOF.
     (if eof 3 0) 0
     (if (eq state :closing) 3 0)
     (if write-queue (fill-pointer write-queue) 0)
     "write" 0
     0 1 2 -1 -1 nil 0
     1 1
     ;; remote_has_tty without isatty is "RT"; a pty session requests one.
     (if (eq channel *pty-channel*) "RT" "")
     "I")))

(defun client-channel-open-message ()
  "The text ~# prints: channels.c's channel_open_message() for this client.

Listener channels are hidden by channel_open_message(), as are closed and
abandoned ones, so only the session and any live forwarded connections
remain."
  (with-output-to-string (out)
    (format out "The following connections are open:")
    (mux-write-crlf out)
    (let ((entries '())
          (printed (make-hash-table :test #'eql)))
      (when *channel*
        (setf (gethash (cl-pnet-ssh::ssh-channel-local-id *channel*) printed)
              t)
        (push (cons (cl-pnet-ssh::ssh-channel-local-id *channel*)
                    (lambda (out)
                      (client-session-channel-status out *channel*)))
              entries))
      (when *client*
        (maphash
         (lambda (id channel)
           (unless (or (gethash id printed)
                       (eq channel *channel*)
                       (eq (cl-pnet-ssh::ssh-channel-state channel) :closed))
             (push (cons id
                         (lambda (out)
                           (mux-generic-channel-status out channel)))
                   entries)))
         (cl-pnet-ssh::ssh-client-channels *client*)))
      (dolist (entry (sort entries #'< :key #'car))
        (funcall (cdr entry) out)))))

(defun print-escape-forwards ()
  (princ (client-channel-open-message) *error-output*)
  (finish-output *error-output*))

(defun escape-send-break ()
  "Send a break request, as ~B does."
  (when *channel*
    (send-channel-request
     *channel* "break" nil
     (lambda (writer)
       (cl-pnet-ssh::ssh-write-u32 writer 1000)))))

(defun escape-print-connection-info ()
  "Print connection_info_message(), as ~I does."
  (format *error-output* "~A" (mux-connection-info-message nil))
  (finish-output *error-output*))

(defun escape-request-rekey ()
  "Ask the transport to start a key exchange, as ~R does.

The libssh transport exposes no rekey entry point, so it ignores the
request rather than failing the session."
  (let ((rekey (find-symbol "SSH-CLIENT-START-REKEY" :cl-pnet-ssh)))
    (when (and rekey (fboundp rekey) *client*)
      (funcall rekey *client*))))

(defparameter +escape-log-levels+
  '("quiet" "fatal" "error" "info" "verbose" "debug" "debug2" "debug3")
  "OpenSSH's LogLevel names in order, as log_level_name() spells them.")

(defun escape-adjust-log-level (delta)
  "Raise or lower the log level by DELTA, as ~v and ~V do."
  (let* ((current (string-downcase (or (log-level-setting) "info")))
         (current (if (string= current "debug1") "debug" current))
         (index (or (position current +escape-log-levels+ :test #'string=)
                    3))
         (next (max 0 (min (1- (length +escape-log-levels+))
                           (+ index delta))))
         (name (nth next +escape-log-levels+)))
    (setf (getf *options* :log-level) name)
    (multiple-value-bind (quiet verbose) (log-level-settings name)
      (setf (getf *options* :quiet) quiet
            (getf *options* :verbose) verbose))
    (format *error-output* "~C~C [LogLevel ~A]~C~C"
            *escape-char* (if (plusp delta) #\v #\V)
            (string-upcase name) #\Return #\Newline)
    (finish-output *error-output*)))

(defun stop-forward-listeners ()
  "Close every forwarding listener, leaving established tunnels running.

This is the part of channel_stop_listening() that ~& needs: no new
connections are accepted, but the channels already carrying data stay."
  (dolist (forward *forwards*)
    (close-forward-listeners forward)
    (when (forward-listener-watcher forward)
      (ignore-errors (cl-pnet:fd-unwatch (forward-listener-watcher forward)))
      (setf (forward-listener-watcher forward) nil))
    (when (forward-listener-fd forward)
      (ignore-errors
        (cl-pnet-sockets:close-open-fd (forward-listener-fd forward)))
      (setf (forward-listener-fd forward) nil)))
  (setf *forwards* nil)
  (dolist (forward *dynamic-forwards*)
    (close-dynamic-forward-listeners forward))
  (setf *dynamic-forwards* nil
        *remote-forwards* nil))

(defun escape-background-available-p ()
  "Whether this Lisp can fork into the background, as ~& needs."
  (let* ((package (find-package :sb-posix))
         (fork (and package (find-symbol "FORK" package))))
    (and fork (fboundp fork))))

(defun escape-background ()
  "Detach this client as ~& does, leaving established connections alive.

The listener channels are closed first, stdin is treated as EOF, and the
process forks; the parent exits so the shell gets its prompt back while the
child keeps serving the channels it already carries."
  (unless (escape-background-available-p)
    (return-from escape-background nil))
  (format *error-output* "~C& [backgrounded]~C~C"
          *escape-char* #\Return #\Newline)
  (finish-output *error-output*)
  (restore-terminal)
  (stop-forward-listeners)
  (when *channel*
    (ignore-errors (cl-pnet-ssh:ssh-channel-eof *channel*)))
  (stop-stdin)
  (let* ((package (find-package :sb-posix))
         (fork (and package (find-symbol "FORK" package)))
         (pid (and fork (fboundp fork)
                   (ignore-errors (funcall fork)))))
    (when (and pid (plusp pid))
      ;; This is the parent; the child continues the event loop.
      (quit-now 0))))

(defun escape-suspend ()
  "Print ~^Z's notice, give the terminal back, and stop this process."
  (format *error-output* "~C^Z [suspend ssh]~C~C"
          *escape-char* #\Return #\Newline)
  (finish-output *error-output*)
  (restore-terminal)
  #+(and sbcl (not win32))
  (call-with-deferrable-signals-unblocked
   (lambda ()
     (sb-unix:unix-kill (sb-unix:unix-getpid) sb-unix:sigtstp)))
  ;; The shell may have changed the terminal settings while we were stopped.
  (terminal-enter-raw))

(defun parse-cancel-listen (spec)
  "SPEC as (VALUES ADDRESS PORT PATH) for -KL/-KR/-KD."
  (if (path-field-p spec)
      (values nil nil spec)
      (multiple-value-bind (first second) (split-host-port spec)
        (if second
            (values (and (plusp (length first)) first)
                    (forwarding-port second spec) nil)
            (values nil (forwarding-port first spec) nil)))))

(defun cancel-local-forward (spec)
  "Close the local forward matching SPEC."
  (multiple-value-bind (address port path) (parse-cancel-listen spec)
    (let ((forward
            (find-if
             (lambda (candidate)
               (if path
                   (and (forward-bind-path candidate)
                        (string= path (forward-bind-path candidate)))
                   (and (not (forward-bind-path candidate))
                        (= port (forward-bind-port candidate))
                        (or (null address)
                            (null (forward-bind-address candidate))
                            (string-equal address
                                          (forward-bind-address candidate))))))
             *forwards*)))
      (when forward
        (close-forward-listeners forward)
        (when (forward-listener-watcher forward)
          (cl-pnet:fd-unwatch (forward-listener-watcher forward))
          (setf (forward-listener-watcher forward) nil))
        (when (forward-listener-fd forward)
          (ignore-errors
            (cl-pnet-sockets:close-open-fd (forward-listener-fd forward)))
          (setf (forward-listener-fd forward) nil))
        (setf *forwards* (delete forward *forwards*))
        (release-forward-channel-id *client* forward)
        t))))

(defun cancel-dynamic-forward (spec)
  "Close the dynamic forward matching SPEC."
  (multiple-value-bind (address port path) (parse-cancel-listen spec)
    (let ((forward
            (if path
                (find-if (lambda (candidate)
                           (and (dynamic-forward-bind-path candidate)
                                (string= path
                                         (dynamic-forward-bind-path candidate))))
                         *dynamic-forwards*)
                (find-if (lambda (candidate)
                           (and (not (dynamic-forward-bind-path candidate))
                                (= port (dynamic-forward-bind-port candidate))
                                (or (null address)
                                    (null (dynamic-forward-bind-address
                                           candidate))
                                    (string-equal
                                     address
                                     (dynamic-forward-bind-address
                                      candidate)))))
                         *dynamic-forwards*))))
      (when forward
        (close-dynamic-forward-listeners forward)
        (setf *dynamic-forwards* (delete forward *dynamic-forwards*))
        (release-dynamic-forward-channel-id *client* forward)
        t))))

(defun cancel-remote-forward (spec)
  "Ask the server to stop the remote forward matching SPEC."
  (multiple-value-bind (address port path) (parse-cancel-listen spec)
    (let ((forward
            (find-if
             (lambda (candidate)
               (if path
                   (and (forward-bind-path candidate)
                        (string= path (forward-bind-path candidate)))
                   (and (not (forward-bind-path candidate))
                        (= port (forward-bind-port candidate))
                        (or (null address)
                            (null (forward-bind-address candidate))
                            (string-equal address
                                          (forward-bind-address candidate))))))
             *remote-forwards*)))
      (when forward
        (setf *remote-forwards* (delete forward *remote-forwards*))
        (if path
            (cl-pnet-ssh:ssh-client-send-global-request
             *client* "cancel-streamlocal-forward@openssh.com"
             :fields (lambda (writer)
                       (cl-pnet-ssh::ssh-write-text writer path)))
            (cl-pnet-ssh:ssh-client-send-global-request
             *client* "cancel-tcpip-forward"
             :fields (lambda (writer)
                       (cl-pnet-ssh::ssh-write-text
                        writer (or (forward-bind-address forward) ""))
                       (cl-pnet-ssh::ssh-write-u32
                        writer (forward-bind-port forward)))))
        t))))

(defun escape-commandline-help ()
  "Print clientloop.c's process_cmdline() command list at logit()."
  (log-info "Commands:")
  (log-info "      -L[bind_address:]port:host:hostport    Request local forward")
  (log-info "      -R[bind_address:]port:host:hostport    Request remote forward")
  (log-info "      -D[bind_address:]port                  Request dynamic forward")
  (log-info "      -KL[bind_address:]port                 Cancel local forward")
  (log-info "      -KR[bind_address:]port                 Cancel remote forward")
  (log-info "      -KD[bind_address:]port                 Cancel dynamic forward")
  (when (permit-local-command-p *client*)
    (log-info "      !args                                  Execute local command")))

(defun escape-local-command (command)
  "Run COMMAND locally, as process_cmdline()'s !args does."
  (when (and (permit-local-command-p *client*)
             (plusp (length command)))
    (let ((shell (or (uiop:getenv "SHELL") "/bin/sh")))
      (handler-case
          (call-with-deferrable-signals-unblocked
           (lambda ()
             (uiop:run-program
              (list shell "-c" command)
              :input :interactive :output :interactive
              :error-output :interactive)))
        (error () nil)))))

(defun execute-escape-command (line)
  "Run one ~C command line, in process_cmdline()'s wording."
  (let* ((line (string-trim '(#\Space #\Tab #\Return #\Newline) line))
         (text (if (and (plusp (length line)) (char= (char line 0) #\-))
                   (subseq line 1)
                   line)))
    (cond
      ((zerop (length text)) nil)
      ((member (char text 0) '(#\h #\H #\?))
       (escape-commandline-help))
      ((char= (char text 0) #\!)
       (escape-local-command (subseq text 1)))
      ((and (> (length text) 1) (char-equal (char text 0) #\K)
            (member (char text 1) '(#\L #\R #\D)))
       (let ((letter (char text 1))
             (rest (string-trim '(#\Space #\Tab) (subseq text 2))))
         (catch 'escape-forward-failure
           (let ((*forwarding-escape-kind* "close"))
             (if (case letter
                   (#\L (cancel-local-forward rest))
                   (#\R (cancel-remote-forward rest))
                   (t (cancel-dynamic-forward rest)))
                 (log-info "Canceled forwarding.")
                 (log-info "Unknown port forwarding."))))))
      ((member (char text 0) '(#\L #\R #\D) :test #'char-equal)
       (let ((letter (char text 0))
             (rest (string-trim '(#\Space #\Tab) (subseq text 1))))
         (catch 'escape-forward-failure
           (cond
             ((char-equal letter #\L)
              (let ((*forwarding-escape-kind* "local"))
                (if (start-local-forward *client* (parse-local-forward rest))
                    (log-info "Forwarding port.")
                    (log-info "Port forwarding failed."))))
             ((char-equal letter #\R)
              (let ((*forwarding-escape-kind* "remote"))
                (if (start-remote-forward *client* (parse-remote-forward rest))
                    (log-info "Forwarding port.")
                    (log-info "Port forwarding failed."))))
             (t
              ;; -D is one of options.local_forwards, so ssh uses the same
              ;; "local" wording for a bad dynamic specification.
              (let ((*forwarding-escape-kind* "local"))
                (if (start-dynamic-forward *client* (parse-dynamic-forward rest))
                    (log-info "Forwarding port.")
                    (log-info "Port forwarding failed."))))))))
      (t (log-info "Invalid command.")))))

(defun escape-commandline ()
  "Read and run one command from the interactive escape command line."
  (restore-terminal)
  (unwind-protect
       (progn
         (format *error-output* "~C~Cssh> " #\Return #\Newline)
         (finish-output *error-output*)
         (let ((line (read-line *standard-input* nil nil)))
           (when line
             (handler-case (execute-escape-command line)
               (error (condition)
                 (format *error-output* "~%burs: ~A~%" condition)
                 (finish-output *error-output*))))))
    (terminal-enter-raw)))

(defun config-log-level (client)
  "CLIENT's LogLevel as a lowercase name, or NIL."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options (cl-pnet-ssh:ssh-config-options-log-level options))))

(defun log-level-settings (level)
  "VALUES QUIET VERBOSE for a LogLevel name."
  (cond
    ((member level '("quiet" "fatal" "error") :test #'string=)
     (values t 0))
    ((member level '("verbose" "debug" "debug1") :test #'string=)
     (values nil 1))
    ((string= level "debug2") (values nil 2))
    ((string= level "debug3") (values nil 3))
    (t (values nil 0))))

(defun apply-config-log-level (client)
  "Adopt CLIENT's LogLevel when nothing on the command line set one.

-q and -v assign options.log_level while the arguments are read, and
readconf's own LogLevel only applies while it is still unset.  -o LogLevel
is recorded in :LOG-LEVEL; -v is only a verbosity count, so it needs its own
check here."
  (let ((level (config-log-level client)))
    (when (and level
               (null (getf *options* :log-level))
               (zerop (getf *options* :verbose 0))
               (not (getf *options* :quiet)))
      (multiple-value-bind (quiet verbose) (log-level-settings level)
        (setf (getf *options* :log-level) level
              (getf *options* :quiet) quiet
              (getf *options* :verbose) verbose)
        (start-logging)))))

(defun config-local-command (client)
  "CLIENT's LocalCommand as written, or NIL."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (cl-pnet-ssh:ssh-config-command-value
          (cl-pnet-ssh:ssh-config-options-local-command options)))))

(defun permit-local-command-p (client)
  "Whether PermitLocalCommand allows LocalCommand to run."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (cl-pnet-ssh:ssh-config-options-permit-local-command options))))

(defun run-local-command (client)
  "Run CLIENT's LocalCommand through the shell, reporting only its status."
  (let* ((command (expand-remote-command client
                                         (config-local-command client)))
         (shell (or (uiop:getenv "SHELL") "/bin/sh")))
    (handler-case
        (let ((status (nth-value 2
                                 (call-with-deferrable-signals-unblocked
                                  (lambda ()
                                    (uiop:run-program
                                     (list shell "-c" command)
                                     :output *standard-output*
                                     :error-output *error-output*
                                     :ignore-error-status t))))))
          (unless (eql status 0)
            (log-line "local command exited with status ~A" status)))
      (error (condition)
        (log-line "local command failed: ~A" condition)))))

(defun config-fork-after-authentication-p (client)
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (cl-pnet-ssh:ssh-config-options-fork-after-authentication options))))

(defun config-remote-command (client)
  "CLIENT's RemoteCommand as written, or NIL."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (cl-pnet-ssh:ssh-config-command-value
          (cl-pnet-ssh:ssh-config-options-remote-command options)))))

(defun proxy-jump-target-host (options)
  "The last ProxyJump hop's host in OPTIONS, or NIL for a direct connection.

readconf answers %j with the parsed jump_host, so this reads the normalised
spelling back out and drops any user and port."
  (let ((value (or (and options
                        (cl-pnet-ssh:ssh-config-options-proxy-jump options))
                   (getf *options* :jump))))
    (when (and value (stringp value) (not (string-equal value "none")))
      (let* ((start (1+ (or (position #\, value :from-end t) -1)))
             (hop (subseq value start))
             (at (position #\@ hop))
             (hop (if at (subseq hop (1+ at)) hop)))
        (if (and (plusp (length hop)) (char= (char hop 0) #\[))
            (subseq hop 1 (or (position #\] hop) (length hop)))
            (let ((colon (position #\: hop)))
              (if colon (subseq hop 0 colon) hop)))))))

(defun client-percent-values (options alias canonical port user)
  "ssh.c's DEFAULT_CLIENT_PERCENT_EXPAND_ARGS as an alist of characters."
  (let* ((local-host (or (machine-instance) "localhost"))
         (short-host (subseq local-host 0
                             (or (position #\. local-host)
                                 (length local-host))))
         (key-alias (or (and options
                             (cl-pnet-ssh:ssh-config-options-host-key-alias
                              options))
                        alias
                        ""))
         (jump (proxy-jump-target-host options)))
    (list (cons #\h (or canonical ""))
          (cons #\n (or alias ""))
          (cons #\p (format nil "~D" (or port 22)))
          (cons #\r (or user ""))
          (cons #\u (cl-pnet-ssh:ssh-default-user))
          (cons #\d (string-right-trim
                     "/" (namestring (user-homedir-pathname))))
          (cons #\i (format nil "~D" (sb-posix:getuid)))
          (cons #\k key-alias)
          (cons #\j (or jump ""))
          (cons #\l local-host)
          (cons #\L short-host)
          (cons #\C (cl-pnet-ssh::ssh-config-connection-hash
                     local-host (or canonical "") (or port 22)
                     (or user "") (or jump ""))))))

(defun expand-client-percent (options alias canonical value
                              &key port user)
  "VALUE expanded as ssh.c's percent_expand for RemoteCommand and forwards.

Only % tokens are replaced, so a ${NAME} stays literal.  An unknown token or
a trailing % dies with vdollar_percent_expand's own line followed by
percent_expand: failed; both follow the log level, as ssh's fatal() does."
  (let ((values (client-percent-values options alias canonical
                                       (or port (client-port) 22)
                                       (or user
                                           (and options
                                                (cl-pnet-ssh:ssh-config-options-user
                                                 options))
                                           (getf *options* :user)
                                           (cl-pnet-ssh:ssh-default-user))))
        (quiet (getf *options* :quiet)))
    (labels ((die (message)
               (unless quiet
                 (format *error-output* "vdollar_percent_expand: ~A~%"
                         (cl-pnet-ssh::ssh-log-escape message))
                 (format *error-output* "percent_expand: failed~%")
                 (finish-output *error-output*))
               (restore-terminal)
               (uiop:quit 255)))
      (with-output-to-string (out)
        (loop with length = (length value)
              for index from 0 below length
              for character = (char value index)
              do (cond
                   ((char/= character #\%)
                    (write-char character out))
                   ((>= (1+ index) length)
                    (die "invalid format"))
                   (t
                    (let ((token (char value (1+ index))))
                      (if (char= token #\%)
                          (progn (write-char #\% out) (incf index))
                          (let ((replacement (cdr (assoc token values))))
                            (unless replacement
                              (die (format nil "unknown key %~C" token)))
                            (write-string replacement out)
                            (incf index)))))))))))

(defun expand-remote-command (client value)
  "VALUE with the ssh % tokens RemoteCommand understands."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (expand-client-percent
     options
     (cl-pnet-ssh:ssh-client-host client)
     (cl-pnet-ssh:ssh-client-connect-host client)
     value
     :port (or (cl-pnet-ssh:ssh-client-connect-port client) 22)
     :user (cl-pnet-ssh:ssh-client-user client))))

(defun config-session-type (client)
  "CLIENT's ssh_config SessionType, or NIL when the file did not name one."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options (cl-pnet-ssh:ssh-config-options-session-type options))))

(defun session-type-none-p (client)
  "Whether SessionType none asks for forwards only, like -N."
  (string= (or (config-session-type client) "default") "none"))

(defun subsystem-request-p ()
  "Whether this session asks for a subsystem, by -s or SessionType."
  (or (getf *options* :subsystem)
      (let ((client *client*))
        (and client
             (string= (or (config-session-type client) "default")
                      "subsystem")))))

(defun stdin-null-p ()
  "Whether stdin is /dev/null, by -n or StdinNull."
  (or (getf *options* :stdin-null)
      (let ((client *client*))
        (and client
             (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
               (and options
                    (cl-pnet-ssh:ssh-config-options-stdin-null
                     options)))))))

(defun config-permit-remote-open (client)
  "CLIENT's PermitRemoteOpen choice: NIL/:ANY, :NONE, or (HOST . PORT) entries."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (cl-pnet-ssh:ssh-config-options-permit-remote-open options))))

(defun permit-remote-open-allowed-p (client host port)
  "Whether PermitRemoteOpen lets CLIENT dial HOST:PORT.

PORT is :STREAMLOCAL for a Unix socket path.  No name or address lookup is
performed, matching ssh: the configured host must match exactly, or be *."
  (let ((permit (config-permit-remote-open client)))
    (cond
      ((null permit) t)
      ((eq permit :any) t)
      ((eq permit :none) nil)
      (t
       (some (lambda (entry)
               (let ((permitted-host (second entry))
                     (permitted-port (third entry)))
                 (and (or (string= permitted-host "*")
                          (string= permitted-host host))
                      (or (eq permitted-port :any)
                          (eql permitted-port port)))))
             permit)))))

(defun clear-all-forwardings-p (client)
  "Whether ClearAllForwardings discards every configured forward."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (cl-pnet-ssh:ssh-config-options-clear-all-forwardings options))))

(defun exit-on-forward-failure-p (client)
  "Whether ExitOnForwardFailure asks this client to exit on a failed forward."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (cl-pnet-ssh:ssh-config-options-exit-on-forward-failure options))))

(defun unix-listener-error-text (path condition)
  "channels.c's unix_listener() wording for a failed local Unix bind.

CL-PNET-SOCKETS signals its own text; ssh prints the same reason under the
function name error_f() prepends."
  (let* ((text (princ-to-string condition))
         (bind (format nil "cannot bind ~A: " path))
         (listen (format nil "cannot listen on ~A: " path)))
    (cond
      ((and (>= (length text) (length bind))
            (string= bind text :end2 (length bind)))
       (format nil "unix_listener: cannot bind to path ~A: ~A"
               path (subseq text (length bind))))
      ((and (>= (length text) (length listen))
            (string= listen text :end2 (length listen)))
       (format nil "unix_listener: cannot listen on path ~A: ~A"
               path (subseq text (length listen))))
      (t (format nil "unix_listener: ~A" text)))))

(defun start-local-streamlocal-forward (client forward)
  "Listen on FORWARD's local Unix socket and bridge accepted peers.

StreamLocalBindUnlink and StreamLocalBindMask are honoured here, as ssh
does when it binds a local forwarding socket."
  (let* ((path (forward-bind-path forward))
         (options (cl-pnet-ssh:ssh-client-config-options client))
         (unlink (and options
                      (cl-pnet-ssh:ssh-config-options-streamlocal-bind-unlink
                       options)))
         (mask (or (and options
                        (cl-pnet-ssh:ssh-config-options-streamlocal-bind-mask
                         options))
                   #o177))
         (listener nil)
         (failure nil))
    (handler-case
        (setf listener
              (cl-pnet-sockets:listen-unix path :unlink unlink :mask mask))
      (error (condition) (setf failure condition)))
    (unless listener
      ;; The aggregate forwarding messages belong to START-FORWARDS.
      (log-error "~A" (unix-listener-error-text path failure))
      (return-from start-local-streamlocal-forward nil))
    (setf (forward-listener-fd forward) listener
          (forward-listener-watcher forward)
          (cl-pnet:fd-watch
           listener :on-readable
           (lambda (watcher)
             (declare (ignore watcher))
             (loop for fd = (cl-pnet-sockets:accept-socket listener)
                   while fd
                   do (cl-pnet-sockets:set-nonblocking fd)
                      (let ((bridge (%make-client-streamlocal :fd fd :path path)))
                        (handler-case
                            (let ((channel
                                    (open-forward-target-channel
                                     client forward
                                     :on-data
                                     (lambda (channel data kind)
                                       (declare (ignore channel kind))
                                       (client-streamlocal-on-data bridge data))
                                     :on-eof
                                     (lambda (channel)
                                       (declare (ignore channel))
                                       (client-streamlocal-on-eof bridge))
                                     :on-close
                                     (lambda (channel reason)
                                       (declare (ignore channel reason))
                                       (client-streamlocal-close bridge))
                                     :on-error
                                     (lambda (channel condition)
                                       (log-channel-open-failure
                                        channel condition)
                                       (client-streamlocal-close bridge)))))
                              (setf (client-streamlocal-channel bridge) channel)
                              (setf (cl-pnet-ssh::ssh-channel-display-fd
                                     channel) fd)
                              (client-streamlocal-connected bridge))
                          (error ()
                            (client-streamlocal-close bridge))))))))
    (push forward *forwards*)
    (reserve-forward-channel-id client forward)
    (log-line "local streamlocal forward ~A to ~A"
              path (forward-target-name forward))
    forward))

(defun reserve-forward-channel-id (client forward)
  "Give FORWARD the channel slots channels.c's listener channels would hold."
  (let ((count (max 1 (length (forward-listeners forward)))))
    (setf (forward-channel-ids forward)
          (cl-pnet-ssh:ssh-client-reserve-channel-ids client count)
          (forward-channel-id forward)
          (first (forward-channel-ids forward)))))

(defun release-forward-channel-id (client forward)
  (when (and client (forward-channel-ids forward))
    (cl-pnet-ssh:ssh-client-release-channel-ids
     client (forward-channel-ids forward))
    (setf (forward-channel-id forward) nil
          (forward-channel-ids forward) nil)))

(defun reserve-dynamic-forward-channel-id (client forward)
  (let ((count (max 1 (length (dynamic-forward-listeners forward)))))
    (setf (dynamic-forward-channel-ids forward)
          (cl-pnet-ssh:ssh-client-reserve-channel-ids client count)
          (dynamic-forward-channel-id forward)
          (first (dynamic-forward-channel-ids forward)))))

(defun release-dynamic-forward-channel-id (client forward)
  (when (and client (dynamic-forward-channel-ids forward))
    (cl-pnet-ssh:ssh-client-release-channel-ids
     client (dynamic-forward-channel-ids forward))
    (setf (dynamic-forward-channel-id forward) nil
          (dynamic-forward-channel-ids forward) nil)))

(defun forward-listen-targets (client bind-address)
  "The addresses a client forward on BIND-ADDRESS has to bind.

channels.c resolves the address the way channel_fwd_bind_addr() selects it
and then listens on every answer: a missing address means both loopbacks,
\"*\" and an empty address mean both wildcards, \"localhost\" also means
both loopbacks, and anything else is taken literally.  AddressFamily
restricts the set, as ssh->chanctxt->IPv4or6 does."
  (let* ((options (cl-pnet-ssh:ssh-client-config-options client))
         (gateway (gateway-ports-p options))
         (family (ignore-errors
                   (cl-pnet-ssh::ssh-normalize-address-family
                    (or (and options
                             (cl-pnet-ssh:ssh-config-options-address-family
                              options))
                        (getf *options* :address-family)))))
         (wildcard
           (if (null bind-address)
               gateway
               (or (zerop (length bind-address))
                   (string= bind-address "*")))))
    (cond
      (wildcard
       (let ((targets '()))
         (unless (eq family :inet6) (push "0.0.0.0" targets))
         (unless (eq family :inet) (push "::" targets))
         (nreverse targets)))
      ((or (null bind-address) (string= bind-address "localhost"))
       (let ((targets '()))
         (unless (eq family :inet) (push "::1" targets))
         (unless (eq family :inet6) (push "127.0.0.1" targets))
         (nreverse targets)))
      (t
       ;; channels.c hands every non-wildcard address to getaddrinfo, even one
       ;; that looks like a literal: a malformed quad such as 999.1.1.1 must
       ;; fail there rather than reach bind() as INADDR_NONE.  When the lookup
       ;; fails the condition reaches OPEN-FORWARD-LISTENERS, which prints
       ;; channel_setup_fwd_listener_tcpip()'s message.
       (cl-pnet-sockets:lookup-host-addresses bind-address :family family)))))

(defun ipv6-bind-address-p (address)
  (let ((family (nth-value 1 (cl-pnet-sockets:resolve-bind-address address))))
    (eq family :inet6)))

(defun listen-error-reason (status)
  "channels.c's strerror() text for a listener's error STATUS.

CL-PNET reports a creation failure as a negative errno through the
listener's on-error callback, which is what bind() and listen() report in
channels.c."
  (let ((errno (if (and (integerp status) (minusp status)) (- status) status)))
    (if (and (integerp errno) (plusp errno))
        (cl-pnet-sockets:c-strerror errno)
        "Cannot assign requested address")))

(defun open-forward-listeners (client bind-address port read-cb on-accept
                               describe)
  "Listen for a client forward on every address BIND-ADDRESS resolves to.

Returns the listener objects that bound, in creation order.  channels.c
keeps listening when one address fails, so a partially bound forward still
works; a bind failure is reported at error level only for the last address
and at verbose level for the earlier ones, and a forward that bound nothing
adds \"cannot listen to port\".  A getaddrinfo failure is reported with
channel_setup_fwd_listener_tcpip()'s prefix and counts as no listener."
  (let ((targets
          (handler-case
              (forward-listen-targets client bind-address)
            (error (condition)
              (log-error
               "channel_setup_fwd_listener_tcpip: getaddrinfo(~A): ~A"
               bind-address
               (cl-pnet-ssh:ssh-resolver-error-text condition))
              :failed))))
    (when (eq targets :failed)
      (return-from open-forward-listeners nil))
    (let ((listeners '())
          (remaining targets))
      (dolist (target targets)
        (let ((error-code nil)
              (listener nil))
          (setf listener
                (handler-case
                    (cl-pnet:make-tcp-listener
                     target port
                     :v6only (ipv6-bind-address-p target)
                     :read-cb read-cb
                     :on-accept on-accept
                     :on-error (lambda (status)
                                 (unless error-code
                                   (setf error-code status))
                                 (log-line "~A listen error ~A"
                                           describe status)))
                  (error () nil)))
          (setf remaining (rest remaining))
          (cond
            (listener
             (push listener listeners))
            (t
             ;; channels.c uses strerror(errno) from the failed bind(); the
             ;; callback hands us the same number negated.
             (let ((reason
                     (if error-code
                         (listen-error-reason error-code)
                         (listen-error-reason
                          (- (cl-pnet-sockets:c-errno))))))
               (if (null remaining)
                   (log-error "bind [~A]:~D: ~A" target port reason)
                   (log-verbose "bind [~A]:~D: ~A" target port reason)))))))
      (unless listeners
        (log-error
         "channel_setup_fwd_listener_tcpip: cannot listen to port: ~D" port))
      (nreverse listeners))))

(defun close-forward-listeners (forward)
  (dolist (listener (forward-listeners forward))
    (ignore-errors (cl-pnet:close-listener listener)))
  (setf (forward-listeners forward) nil
        (forward-listener forward) nil))

(defun close-dynamic-forward-listeners (forward)
  (dolist (listener (dynamic-forward-listeners forward))
    (ignore-errors (cl-pnet:close-listener listener)))
  (setf (dynamic-forward-listeners forward) nil
        (dynamic-forward-listener forward) nil)
  (when (dynamic-forward-listener-watcher forward)
    (ignore-errors
      (cl-pnet:fd-unwatch (dynamic-forward-listener-watcher forward)))
    (setf (dynamic-forward-listener-watcher forward) nil))
  (when (dynamic-forward-listener-fd forward)
    (ignore-errors
      (cl-pnet-sockets:close-open-fd (dynamic-forward-listener-fd forward)))
    (setf (dynamic-forward-listener-fd forward) nil))
  (dolist (session (dynamic-forward-fd-sessions forward))
    (setf (socks-session-closed session) t)
    (when (socks-session-watcher session)
      (ignore-errors (cl-pnet:fd-unwatch (socks-session-watcher session)))
      (setf (socks-session-watcher session) nil))
    (let ((fd (socks-session-fd session)))
      (setf (socks-session-fd session) nil)
      (when (and fd (not (minusp fd)))
        (ignore-errors (cl-pnet-sockets:close-open-fd fd)))))
  (setf (dynamic-forward-fd-sessions forward) nil))

(defun start-local-forward (client forward)
  (when (forward-bind-path forward)
    (return-from start-local-forward
      (start-local-streamlocal-forward client forward)))
  (let* ((bind-address (forward-bind-address forward))
         (listeners
           (open-forward-listeners
            client bind-address (forward-bind-port forward)
            #'forward-connection-data
            (lambda (connection)
              (forward-accept client forward connection))
            "-L")))
    (unless listeners
      ;; The aggregate "Could not request local forwarding." and the
      ;; ExitOnForwardFailure decision belong to START-FORWARDS, which sees
      ;; every -L and -D together, as ssh_init_forwarding() does.
      (return-from start-local-forward nil))
    (setf (forward-listeners forward) listeners
          (forward-listener forward) (first listeners))
    (reserve-forward-channel-id client forward)
    (push forward *forwards*)
    (let ((port (cl-pnet:listener-port (first listeners))))
      (log-line "local forward ~A:~D to ~A:~D"
                (or bind-address "localhost") port
                (forward-host forward) (forward-port forward)))
    forward))

;;; ---- -D: dynamic SOCKS forwarding ----
;;;
;;; OpenSSH's -D is a local SOCKS5 proxy whose CONNECT requests become
;;; direct-tcpip channels.  The handshake runs before the tunnel exists, so a
;;; session keeps its bytes until the greeting and request are complete; after
;;; that the ordinary -L tunnel machinery carries the stream.

(defun socks-reply (reply &key (port 0))
  "A SOCKS5 reply with code REPLY and an all-zero bound address.

channels.c's channel_decode_socks5() always reports INADDR_ANY and echoes the
requested destination port."
  (cl-pnet-socks:make-socks5-reply reply :port port))

(defun socks-abandon (session)
  "Forget SESSION and close its connection without a reply."
  (cond
    ((socks-session-bridge session)
     ;; The bridge owns the descriptor and its channel now.
     (setf (socks-session-closed session) t))
    ((socks-session-fd session)
     (setf (socks-session-closed session) t)
     (when (socks-session-watcher session)
       (ignore-errors (cl-pnet:fd-unwatch (socks-session-watcher session)))
       (setf (socks-session-watcher session) nil))
     (let ((fd (socks-session-fd session))
           (forward (socks-session-forward session)))
       (setf (socks-session-fd session) nil)
       (when (and fd (not (minusp fd)))
         (ignore-errors (cl-pnet-sockets:close-open-fd fd)))
       (when forward
         (setf (dynamic-forward-fd-sessions forward)
               (delete session (dynamic-forward-fd-sessions forward))))))
    ((socks-session-channel session)
     (setf (socks-session-closed session) t)
     (ignore-errors
       (cl-pnet-ssh:ssh-channel-close (socks-session-channel session))))
    (t
     (let ((connection (socks-session-connection session)))
       (remhash connection *socks-sessions*)
       (ignore-errors (cl-pnet:close-connection connection))))))

(defun socks-fd-write (fd data)
  "Best-effort write of a SOCKS reply to raw descriptor FD."
  (when (and fd (not (minusp fd)))
    (handler-case
        (cl-pnet-sockets:write-octets fd data)
      (error () nil))))

(defun socks-send (session data)
  "Send DATA to SESSION's client, abandoning the session on a write error."
  (let ((fd (socks-session-fd session))
        (channel (socks-session-channel session))
        (connection (socks-session-connection session)))
    (cond
      ((and fd (not (minusp fd)))
       (handler-case
           (multiple-value-bind (count errno)
               (cl-pnet-sockets:write-octets fd data)
             (when (or (minusp count) (plusp errno))
               (socks-abandon session)))
         (error () (socks-abandon session))))
      (channel
       (handler-case
           (cl-pnet-ssh:ssh-channel-write channel data)
         (error () (socks-abandon session))))
      (connection
       (handler-case
           (cl-pnet:send-data
            connection data
            :on-error (lambda (status)
                        (declare (ignore status))
                        (socks-abandon session)))
         (error () (socks-abandon session)))))))

(defun socks-start-fd-tunnel (session host port remaining socks4)
  "Carry a streamlocal SOCKS request through a direct-tcpip channel.

The accepted descriptor becomes a client-streamlocal bridge, so the SOCKS
client and the SSH channel keep the same byte path a -L streamlocal forward
uses."
  (let* ((client (socks-session-client session))
         (dynamic (socks-session-forward session))
         (fd (socks-session-fd session))
         (bridge (%make-client-streamlocal :fd fd :path "socks"))
         (forward (%make-forward
                   :host host :port port
                   :bind-address (dynamic-forward-bind-address dynamic)
                   :bind-port (dynamic-forward-bind-port dynamic)
                   :bind-path (dynamic-forward-bind-path dynamic))))
    ;; The bridge owns FD from here; the session and the listener stop
    ;; tracking it.
    (setf (socks-session-fd session) nil
          (socks-session-closed session) t)
    (when (socks-session-watcher session)
      (ignore-errors (cl-pnet:fd-unwatch (socks-session-watcher session)))
      (setf (socks-session-watcher session) nil))
    (setf (dynamic-forward-fd-sessions dynamic)
          (delete session (dynamic-forward-fd-sessions dynamic)))
    (when (and remaining (plusp (length remaining)))
      (let ((pending (client-streamlocal-pending bridge)))
        (loop for octet across remaining
              do (vector-push-extend octet pending))))
    (log-line "dynamic forward to ~A:~D" host port)
    (let ((channel
            (open-forward-target-channel
             client forward
             :on-open
             (lambda (channel)
               (declare (ignore channel))
               (socks-fd-write
                fd
                (if socks4
                    #(0 90 0 0 0 0 0 0)
                    (socks-reply cl-pnet-socks:+socks5-reply-success+
                                 :port port))))
             :on-error
             (lambda (channel condition)
               (log-channel-open-failure channel condition)
               (client-streamlocal-close bridge)))))
      (setf (client-streamlocal-channel bridge) channel)
      (setf (cl-pnet-ssh::ssh-channel-display-fd channel) fd)
      (client-streamlocal-install bridge)
      (client-streamlocal-connected bridge))))

(defun socks-start-rdynamic-tunnel (session host port remaining socks4)
  "Finish a reverse dynamic SOCKS request by dialling HOST:PORT locally.

channels.c buffers the success reply while decoding the request and flushes
it only once the local connect succeeds; a refused connect logs
connect_to()'s error and closes the channel with no reply."
  (let* ((channel (socks-session-channel session))
         (client (socks-session-client session)))
    (if (not (permit-remote-open-allowed-p client host port))
        (socks-abandon session)
        (progn
          (setf (cl-pnet-ssh:ssh-channel-on-error channel)
                (lambda (channel condition)
                  (declare (ignore channel condition))
                  (log-error "connect_to ~A port ~D: failed." host port)))
          (cl-pnet-ssh:ssh-client-connect-forward-target
           channel host port
           :on-connected
           (lambda ()
             (socks-send session
                         (if socks4
                             #(0 90 0 0 0 0 0 0)
                             (socks-reply cl-pnet-socks:+socks5-reply-success+
                                          :port port)))
             (when (and remaining (plusp (length remaining)))
               (let* ((symbol (find-symbol "SSH-CHANNEL-TARGET" :cl-pnet-ssh))
                      (target (and symbol (fboundp symbol)
                                   (funcall symbol channel))))
                 (when target
                   (ignore-errors (cl-pnet:send-data target remaining)))))))))))

(defun start-rdynamic-socks (client channel forward)
  "Run the SOCKS handshake on a server-initiated reverse dynamic CHANNEL."
  (let ((session (%make-socks-session :client client :channel channel
                                      :forward forward)))
    (setf (cl-pnet-ssh:ssh-channel-on-data channel)
          (lambda (channel data kind)
            (declare (ignore channel kind))
            (socks-process session data))
          (cl-pnet-ssh:ssh-channel-on-eof channel)
          (lambda (channel)
            (declare (ignore channel))
            (socks-abandon session))
          (cl-pnet-ssh:ssh-channel-on-close channel)
          (lambda (channel &optional status)
            (declare (ignore channel status))
            (setf (socks-session-closed session) t)))
    session))

(defun socks-start-tunnel (session host port remaining &key socks4)
  "Dial HOST:PORT through the SSH connection for SESSION's client.

REMAINING is any stream data the client sent right behind the request; it is
buffered with the tunnel and flushed once the channel is open.  SOCKS4 selects
the four-byte SOCKS4 success reply instead of the SOCKS5 one."
  (cond
    ((socks-session-fd session)
     (return-from socks-start-tunnel
       (socks-start-fd-tunnel session host port remaining socks4)))
    ((socks-session-channel session)
     (return-from socks-start-tunnel
       (socks-start-rdynamic-tunnel session host port remaining socks4))))
  (let* ((connection (socks-session-connection session))
         (client (socks-session-client session))
         (dynamic (socks-session-forward session))
         (listener (and dynamic (dynamic-forward-listener dynamic)))
         (listen-port (and listener
                           (ignore-errors (cl-pnet:listener-port listener))))
         (tunnel (%make-forward-tunnel
                  :forward (%make-forward
                            :host host :port port
                            :bind-address (and dynamic
                                               (dynamic-forward-bind-address
                                                dynamic))
                            :bind-port listen-port
                            :listener listener)
                  :display-type "dynamic-tcpip"
                  :connection connection)))
    (remhash connection *socks-sessions*)
    (setf (gethash connection *tunnels*) tunnel)
    (when (and remaining (plusp (length remaining)))
      (forward-read tunnel remaining))
    (log-line "dynamic forward to ~A:~D" host port)
    (open-forward-channel
     client tunnel
     :on-open
     (lambda ()
       ;; The peer accepted the connection: release the SOCKS client with
       ;; the success reply channels.c composes while parsing the request.
       (handler-case
           (cl-pnet:send-data
            connection
            (if socks4
                #(0 90 0 0 0 0 0 0)
                (socks-reply cl-pnet-socks:+socks5-reply-success+
                             :port port))
            :on-error (lambda (status)
                        (declare (ignore status))
                        (forward-close tunnel)))
         (error () (forward-close tunnel))))
     :on-error
     (lambda (condition)
       (declare (ignore condition))
       ;; channels.c logs the refusal and then frees the channel, so the
       ;; SOCKS client sees its connection closed with no reply at all.
       (setf (forward-tunnel-connection tunnel) nil)
       (remhash connection *tunnels*)
       (ignore-errors (cl-pnet:close-connection connection))))))

(defun socks4-request (data)
  "VALUES (HOST PORT CONSUMED COMMAND) from DATA, or NIL when incomplete."
  (when (< (length data) 9)
    (return-from socks4-request nil))
  (let ((user-end (position 0 data :start 8)))
    (when (or (null user-end) (> user-end 1031))
      (return-from socks4-request nil))
    (let* ((command (aref data 1))
           (port (logior (ash (aref data 2) 8) (aref data 3)))
           (address (subseq data 4 8))
           (socks4a (and (zerop (aref address 0)) (zerop (aref address 1))
                         (zerop (aref address 2))
                         (not (zerop (aref address 3))))))
      (if socks4a
          (let ((host-end (position 0 data :start (1+ user-end))))
            (when (or (null host-end) (> (- host-end user-end 1) 1024))
              (return-from socks4-request nil))
            (values (map 'string #'code-char
                         (subseq data (1+ user-end) host-end))
                    port (1+ host-end) command))
          (values (format nil "~D.~D.~D.~D"
                          (aref address 0) (aref address 1)
                          (aref address 2) (aref address 3))
                  port (1+ user-end) command)))))

(defun socks-process (session data)
  "Feed DATA to SESSION and act on whatever the handshake produced."
  (let ((pending (socks-session-pending session)))
    (when pending
      (setf data (concatenate '(vector (unsigned-byte 8)) pending data)
            (socks-session-pending session) nil)))
  ;; channel_pre_dynamic() needs three bytes before it inspects the version.
  (when (< (length data) 3)
    (setf (socks-session-pending session) (copy-seq data))
    (return-from socks-process nil))
  (case (aref data 0)
    (4
     (multiple-value-bind (host port consumed command)
         (socks4-request data)
       (cond
         ((null host)
          (setf (socks-session-pending session) (copy-seq data)))
         ((/= command 1)
          ;; Only CONNECT is supported; channels.c just drops the channel.
          (socks-abandon session))
         (t
          (socks-start-tunnel session host port
                              (subseq data consumed)
                              :socks4 t)))))
    (5
     (multiple-value-bind (output request error remaining)
         (cl-pnet-socks:socks5-server-consume (socks-session-state session)
                                              data)
       (cond
         (error
          ;; channels.c answers nothing at all when the greeting or request
          ;; cannot be decoded, including an unacceptable auth method.
          (socks-abandon session))
         (request
          (when output
            (socks-send session output))
          (if (= (cl-pnet-socks:socks5-request-command request)
                 cl-pnet-socks:+socks5-cmd-connect+)
              (socks-start-tunnel
               session
               (cl-pnet-socks:socks5-request-host request)
               (cl-pnet-socks:socks5-request-port request)
               remaining)
              (socks-abandon session)))
         (output
          (socks-send session output)))))
    (otherwise
     ;; Unknown SOCKS version: channels.c marks the channel dead.
     (socks-abandon session))))

(defun socks-connection-data (connection data)
  "Listener callback for -D: run the handshake, then bridge bytes."
  (let ((session (gethash connection *socks-sessions*)))
    (if session
        (if data
            (socks-process session data)
            (socks-abandon session))
        (forward-connection-data connection data))))

(defun socks-accept (client connection forward)
  (setf (gethash connection *socks-sessions*)
        (%make-socks-session :client client :connection connection
                             :forward forward)))

(defun socks-fd-readable (session)
  "Read a streamlocal SOCKS client until its tunnel takes the descriptor."
  (unless (or (socks-session-closed session)
              (socks-session-bridge session))
    (multiple-value-bind (data count error)
        (cl-pnet-sockets:read-octets (socks-session-fd session) 4096)
      (cond
        ((plusp count) (socks-process session data))
        ((and (minusp count) (member error '(4 11))) nil)
        (t (socks-abandon session))))))

(defun socks-fd-accept (client forward fd)
  "Start a SOCKS handshake on FD, accepted by FORWARD's Unix listener."
  (let* ((session (%make-socks-session :client client :fd fd
                                       :forward forward))
         (watcher
           (cl-pnet:fd-watch
            fd :on-readable
            (lambda (watcher)
              (declare (ignore watcher))
              (socks-fd-readable session)))))
    (setf (socks-session-watcher session) watcher
          (dynamic-forward-fd-sessions forward)
          (push session (dynamic-forward-fd-sessions forward)))
    session))

(defun start-dynamic-unix-socks (client forward)
  "Listen for SOCKS clients on FORWARD's Unix socket."
  (let* ((path (dynamic-forward-bind-path forward))
         (options (cl-pnet-ssh:ssh-client-config-options client))
         (unlink (and options
                      (cl-pnet-ssh:ssh-config-options-streamlocal-bind-unlink
                       options)))
         (mask (or (and options
                        (cl-pnet-ssh:ssh-config-options-streamlocal-bind-mask
                         options))
                   #o177))
         (listener nil)
         (failure nil))
    (handler-case
        (setf listener
              (cl-pnet-sockets:listen-unix path :unlink unlink :mask mask))
      (error (condition) (setf failure condition)))
    (unless listener
      (log-error "~A" (unix-listener-error-text path failure))
      (return-from start-dynamic-unix-socks nil))
    (setf (dynamic-forward-listener-fd forward) listener
          (dynamic-forward-listener-watcher forward)
          (cl-pnet:fd-watch
           listener :on-readable
           (lambda (watcher)
             (declare (ignore watcher))
             (loop for fd = (cl-pnet-sockets:accept-socket listener)
                   while fd
                   do (cl-pnet-sockets:set-nonblocking fd)
                      (socks-fd-accept client forward fd)))))
    (reserve-dynamic-forward-channel-id client forward)
    (push forward *dynamic-forwards*)
    (log-line "dynamic forward ~A" path)
    forward))

(defun dynamic-bind-address (forward)
  (let ((address (dynamic-forward-bind-address forward)))
    (cond
      ((or (null address) (zerop (length address))) "127.0.0.1")
      ((string= address "*") "0.0.0.0")
      (t address))))

(defun start-dynamic-forward (client forward)
  (cond
    ((dynamic-forward-target-path forward)
     ;; parse_forward accepts two dynamic fields whose second is a path
     ;; (-D port:path, -D path:path).  channels.c turns those into a local
     ;; forward to the streamlocal target, not into SOCKS.
     (start-local-forward
      client
      (%make-forward
       :bind-address (dynamic-forward-bind-address forward)
       :bind-port (dynamic-forward-bind-port forward)
       :bind-path (dynamic-forward-bind-path forward)
       :target-path (dynamic-forward-target-path forward))))
    ((dynamic-forward-bind-path forward)
     (start-dynamic-unix-socks client forward))
    (t
     (let* ((bind-address (dynamic-forward-bind-address forward))
            (listeners
              (open-forward-listeners
               client bind-address (dynamic-forward-bind-port forward)
               #'socks-connection-data
               (lambda (connection)
                 (socks-accept client connection forward))
               "-D")))
       (unless listeners
         (return-from start-dynamic-forward nil))
       (setf (dynamic-forward-listeners forward) listeners
             (dynamic-forward-listener forward) (first listeners))
       (reserve-dynamic-forward-channel-id client forward)
       (push forward *dynamic-forwards*)
       (let ((port (cl-pnet:listener-port (first listeners))))
         (log-line "dynamic forward ~A:~D" (or bind-address "localhost") port))
       forward))))

(defun configure-dynamic-forwards (client)
  "The DynamicForward lines in CLIENT's config, in file order."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (mapcar #'parse-dynamic-forward
                 (reverse (cl-pnet-ssh:ssh-config-options-dynamic-forwards
                           options))))))

(defun configured-local-forwards (client)
  "The LocalForward lines in CLIENT's config, in file order."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (mapcar #'parse-config-local-forward
                 (reverse (cl-pnet-ssh:ssh-config-options-local-forwards
                           options))))))

(defun configured-remote-forwards (client)
  "The RemoteForward lines in CLIENT's config, in file order."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (mapcar #'parse-config-remote-forward
                 (reverse (cl-pnet-ssh:ssh-config-options-remote-forwards
                           options))))))

(defun remote-forward-match-p (forward bind-address bind-port)
  "Whether a forwarded-tcpip opening names FORWARD's listener."
  (and (= (forward-bind-port forward) bind-port)
       (or (null (forward-bind-address forward))
           (string= (forward-bind-address forward) "*")
           (string-equal (forward-bind-address forward) bind-address))))

(defun remote-dynamic-forward-p (forward)
  "Whether FORWARD is a one-port -R reverse dynamic SOCKS forward."
  (equal (forward-host forward) "socks"))

(defun forwarded-tcpip-target (client bind-address bind-port
                               origin-address origin-port)
  "Answer the local target for a server-initiated forwarded-tcpip channel.

The library calls this with the listener the server actually used and the
peer that connected to it; NIL refuses the channel.  A reverse dynamic
forward returns a setup function: its SOCKS request has not arrived yet."
  (declare (ignore origin-address origin-port))
  (let ((forward (find-if (lambda (candidate)
                            (remote-forward-match-p candidate
                                                    bind-address bind-port))
                          *remote-forwards*)))
    (cond
      ((null forward)
       ;; channels.c's channel_connect_by_listen_address() warning.
       (log-error
        "WARNING: Server requests forwarding for unknown listen_port ~D"
        bind-port)
       (values nil nil))
      ((remote-dynamic-forward-p forward)
       (lambda (channel)
         (start-rdynamic-socks client channel forward)))
      ((permit-remote-open-allowed-p client
                                     (forward-host forward)
                                     (forward-port forward))
       (lambda (channel)
         (attach-client-tcp-target channel forward)))
      (t
       (unless (getf *options* :quiet)
         (format *error-output*
                 "burs: PermitRemoteOpen refuses ~A:~D~%"
                 (forward-host forward) (forward-port forward)))
       (values nil nil)))))

(defun report-forward-target-error (forward condition)
  "Log a failed -R target the way channels.c's connect_to() does."
  (let ((host (forward-host forward))
        (port (forward-port forward)))
    (if (typep condition 'cl-pnet-ssh:ssh-channel-error)
        (log-error "connect_to ~A port ~D: failed." host port)
        ;; The resolver's getaddrinfo text, in channel_connect_to_port()'s
        ;; "unknown host" wording.
        (log-error "connect_to ~A: unknown host (~A)"
                   host (cl-pnet-ssh:ssh-resolver-error-text condition)))))

(defun attach-client-tcp-target (channel forward)
  "Bridge a server-initiated channel to FORWARD's TCP target.

The failure messages are channels.c's connect_to() wording."
  (setf (cl-pnet-ssh:ssh-channel-on-error channel)
        (lambda (channel condition)
          (declare (ignore channel))
          (report-forward-target-error forward condition)
          (ignore-errors (cl-pnet-ssh:ssh-channel-close channel))))
  (cl-pnet-ssh:ssh-client-connect-forward-target
   channel (forward-host forward) (forward-port forward)))

(defun forwarded-streamlocal-target (client path)
  "Setup function for a server-initiated forwarded-streamlocal channel."
  (let ((forward
          (find-if (lambda (candidate)
                     (and (forward-bind-path candidate)
                          (string= (forward-bind-path candidate) path)))
                   *remote-forwards*)))
    (if (null forward)
        (progn
          ;; channel_connect_by_listen_path()'s warning, with the same
          ;; 100-character cut.
          (log-error "WARNING: Server requests forwarding for unknown path ~A"
                     (subseq path 0 (min 100 (length path))))
          nil)
        (progn
          ;; A one-word -R path is accepted by readconf, but channels.c's
          ;; streamlocal path has no reverse-dynamic branch: it tries to
          ;; connect to the "socks" placeholder and fails.
          (let ((allowed
                  (if (forward-target-path forward)
                      (permit-remote-open-allowed-p
                       client (forward-target-path forward) :streamlocal)
                      (permit-remote-open-allowed-p
                       client (forward-host forward) (forward-port forward)))))
            (if allowed
                (lambda (channel)
                  (if (forward-target-path forward)
                      (open-client-streamlocal channel
                                               (forward-target-path forward))
                      (attach-client-tcp-target channel forward)))
                (progn
                  (unless (getf *options* :quiet)
                    (format *error-output*
                            "burs: PermitRemoteOpen refuses ~A~%"
                            (forward-target-name forward)))
                  nil)))))))

(defun remote-forward-target-description (forward)
  "The CONNECT half of FORWARD as ssh's forwarding messages format it.

ssh prints `connect_path ? connect_path : connect_host` with connect_port,
and a socket target carries PORT_STREAMLOCAL, which is -2."
  (if (forward-target-path forward)
      (format nil "~A:-2" (forward-target-path forward))
      (format nil "~A:~D" (or (forward-host forward) "")
              (or (forward-port forward) 0))))

(defun remote-forward-failed (client forward on-failed)
  "Report a remote forward the server refused.

A mux master answers the waiting request through ON-FAILED instead of
logging, as mux_confirm_remote_forward() does."
  (setf *remote-forwards* (delete forward *remote-forwards*))
  (when on-failed
    (return-from remote-forward-failed (funcall on-failed)))
  (let ((message
          (if (forward-bind-path forward)
              (format nil "remote port forwarding failed for listen path ~A"
                      (forward-bind-path forward))
              (format nil "remote port forwarding failed for listen port ~D"
                      (or (forward-bind-port forward) 0)))))
    (if (exit-on-forward-failure-p client)
        (log-fatal "Error: ~A" message)
        ;; logit(), so -q and LogLevel=ERROR drop the warning.
        (log-info "Warning: ~A" message))))

(defun start-streamlocal-remote-forward (client forward
                                         &key on-allocated on-failed)
  "Ask the server to listen on FORWARD's Unix socket."
  (push forward *remote-forwards*)
  (cl-pnet-ssh:ssh-client-send-global-request
   client "streamlocal-forward@openssh.com"
   :fields (lambda (writer)
             (cl-pnet-ssh::ssh-write-text writer
                                          (forward-bind-path forward)))
   :on-success
   (lambda (reader)
     (declare (ignore reader))
     (when on-allocated (funcall on-allocated nil))
     (log-line "remote streamlocal forward ~A to ~A"
               (forward-bind-path forward)
               (or (forward-target-path forward)
                   (format nil "~A:~D"
                           (forward-host forward) (forward-port forward)))))
   :on-failure
   (lambda ()
     (remote-forward-failed client forward on-failed)))
  forward)

(defun start-remote-forward (client forward &key on-allocated on-failed)
  "Ask CLIENT's server to listen for FORWARD and relay to this machine."
  (when (forward-bind-path forward)
    (return-from start-remote-forward
      (start-streamlocal-remote-forward client forward
                                        :on-allocated on-allocated
                                        :on-failed on-failed)))
  (let ((address (or (forward-bind-address forward) ""))
        (port (forward-bind-port forward)))
    (push forward *remote-forwards*)
    (cl-pnet-ssh:ssh-client-send-global-request
     client "tcpip-forward"
     :fields (lambda (writer)
               (cl-pnet-ssh::ssh-write-text writer address)
               (cl-pnet-ssh::ssh-write-u32 writer port))
     :on-success
     (lambda (reader)
       ;; RFC 4254 only carries the port back when 0 was requested.
       (let ((allocated (and (zerop port)
                             (cl-pnet-ssh::ssh-read-u32 reader))))
         (cond
           ((and allocated (> allocated 65535))
            ;; ssh_confirm_remote_forward() reports the bad answer and then
            ;; runs the failure path, which cancels the permission.
            (log-error "Invalid allocated port ~D for remote forward to ~A"
                       allocated
                       (remote-forward-target-description forward))
            (remote-forward-failed client forward on-failed))
           (t
            (when allocated
              (setf (forward-bind-port forward) allocated)
              (unless on-allocated
                ;; logit(), printed at the default level.
                (log-info "Allocated port ~D for remote forward to ~A"
                          allocated
                          (remote-forward-target-description forward))))
            ;; A mux master answers the waiting client only now: OK for a
            ;; fixed port, MUX_S_REMOTE_PORT for an allocated one.
            (when on-allocated
              (funcall on-allocated allocated))
            (log-line "remote forward ~A:~D to ~A"
                      address (forward-bind-port forward)
                      (remote-forward-target-description forward))))))
     :on-failure
     (lambda ()
       (remote-forward-failed client forward on-failed)))
    forward))

(defun expand-forward-for-client (client forward)
  "FORWARD with its socket paths percent-expanded for CLIENT."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client))
        (host (cl-pnet-ssh:ssh-client-host client))
        (canonical (cl-pnet-ssh:ssh-client-connect-host client))
        (port (cl-pnet-ssh:ssh-client-connect-port client))
        (user (cl-pnet-ssh:ssh-client-user client)))
    (when (forward-bind-path forward)
      (setf (forward-bind-path forward)
            (expand-client-percent options host canonical
                                   (forward-bind-path forward)
                                   :port port :user user)))
    (when (forward-target-path forward)
      (setf (forward-target-path forward)
            (expand-client-percent options host canonical
                                   (forward-target-path forward)
                                   :port port :user user))))
  forward)

(defun expand-dynamic-forward-for-client (client forward)
  "FORWARD with its socket paths percent-expanded for CLIENT."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client))
        (host (cl-pnet-ssh:ssh-client-host client))
        (canonical (cl-pnet-ssh:ssh-client-connect-host client))
        (port (cl-pnet-ssh:ssh-client-connect-port client))
        (user (cl-pnet-ssh:ssh-client-user client)))
    (when (dynamic-forward-bind-path forward)
      (setf (dynamic-forward-bind-path forward)
            (expand-client-percent options host canonical
                                   (dynamic-forward-bind-path forward)
                                   :port port :user user)))
    (when (dynamic-forward-target-path forward)
      (setf (dynamic-forward-target-path forward)
            (expand-client-percent options host canonical
                                   (dynamic-forward-target-path forward)
                                   :port port :user user))))
  forward)

(defun start-forwards (client)
  (when (clear-all-forwardings-p client)
    (return-from start-forwards nil))
  (let* ((local (mapcar (lambda (forward)
                          (expand-forward-for-client client forward))
                        (append (configured-local-forwards client)
                                (getf *options* :local-forward))))
         (remote (mapcar (lambda (forward)
                           (expand-forward-for-client client forward))
                         (append (configured-remote-forwards client)
                                 (getf *options* :remote-forward))))
         (dynamic (append (mapcar (lambda (forward)
                                    (expand-dynamic-forward-for-client
                                     client forward))
                                  (configure-dynamic-forwards client))
                          (mapcar (lambda (forward)
                                    (expand-dynamic-forward-for-client
                                     client forward))
                                  (getf *options* :dynamic-forward)))))
    (let ((forwards (append local remote dynamic)))
      ;; ssh refuses every forward once a changed host key was accepted under
      ;; StrictHostKeyChecking=no: a forwarded port is exactly what a man in
      ;; the middle wants.
      (when (and forwards
                 (cl-pnet-ssh:ssh-client-host-key-untrusted-p client))
        (cl-pnet-ssh::ssh-warn
         "Port forwarding is disabled to avoid man-in-the-middle attacks.")
        (when (exit-on-forward-failure-p client)
          (fail "Error: forwarding disabled due to host key check failure"))
        (return-from start-forwards nil)))
    (let ((attempted (+ (length local) (length dynamic)))
          (succeeded 0))
      ;; ssh_init_forwarding(): the local and dynamic forwards are one list
      ;; in options.local_forwards, and their success is judged together.
      (dolist (forward local)
        (when (start-local-forward client forward)
          (incf succeeded)))
      (dolist (forward dynamic)
        (when (start-dynamic-forward client forward)
          (incf succeeded)))
      (when (plusp attempted)
        (cond
          ((and (/= succeeded attempted)
                (exit-on-forward-failure-p client))
           (log-fatal "Could not request local forwarding."))
          ((zerop succeeded)
           (log-error "Could not request local forwarding."))))
      (dolist (forward remote)
        (start-remote-forward client forward)))))

(defun stop-dynamic-forwards ()
  (dolist (forward *dynamic-forwards*)
    (close-dynamic-forward-listeners forward))
  (setf *dynamic-forwards* nil)
  (let ((connections '()))
    (maphash (lambda (connection session)
               (declare (ignore session))
               (push connection connections))
             *socks-sessions*)
    (dolist (connection connections)
      (ignore-errors (cl-pnet:close-connection connection))))
  (clrhash *socks-sessions*))

(defun stop-forwards ()
  (stop-dynamic-forwards)
  (dolist (forward *forwards*)
    (close-forward-listeners forward)
    (when (forward-listener-watcher forward)
      (cl-pnet:fd-unwatch (forward-listener-watcher forward))
      (setf (forward-listener-watcher forward) nil))
    (when (forward-listener-fd forward)
      (ignore-errors
        (cl-pnet-sockets:close-open-fd (forward-listener-fd forward)))
      (setf (forward-listener-fd forward) nil)))
  (setf *forwards* nil)
  (setf *remote-forwards* nil)
  (let ((tunnels '()))
    (maphash (lambda (connection tunnel)
               (declare (ignore connection))
               (push tunnel tunnels))
             *tunnels*)
    ;; FORWARD-CLOSE removes from *TUNNELS*, so the list is copied first and
    ;; the table is walked no longer.
    (dolist (tunnel tunnels)
      (forward-close tunnel)))
  (clrhash *tunnels*))

;;; ---- -G: print the effective configuration ----

(defun synchronous-canonical-resolver (host on-success on-error &key family)
  "Resolve HOST on this thread, for the synchronous -G path.

FAMILY, when :INET or :INET6, keeps the canonical name lookup in the family
AddressFamily selected, as the asynchronous path does."
  (handler-case
      (multiple-value-bind (address canonical)
          (cl-pnet-sockets:lookup-host-canonical host :family family)
        (if canonical
            (funcall on-success address canonical)
            (funcall on-success address)))
    (error (condition) (funcall on-error condition))))

(defun session-type-none-options-p (options)
  "Whether OPTIONS' SessionType asks for forwards only, like -N."
  (string= (or (cl-pnet-ssh:ssh-config-options-session-type options)
               "default")
           "none"))

(defun background-without-command-p (options command-given-p)
  "Whether ssh would refuse to fork here, in ssh.c's own terms.

\"Cannot fork into background without a command to execute.\" guards -f and
ForkAfterAuthentication: a command, a RemoteCommand, -N/-W/SessionType none
or a subsystem request all give the forked session something to do."
  (and (or (getf *options* :background)
           (cl-pnet-ssh:ssh-config-options-fork-after-authentication options))
       (not command-given-p)
       (null (cl-pnet-ssh:ssh-config-command-value
              (cl-pnet-ssh:ssh-config-options-remote-command options)))
       (not (getf *options* :no-command))
       (not (getf *options* :stdio-forward))
       (not (session-type-none-options-p options))))

(defun check-resolved-options (options command-given-p)
  "Run ssh.c's post-configuration checks, which readconf does not make.

Both are fatal with status 255 and neither carries a file or line prefix.
Like every message after log_init they are silent under -q."
  (flet ((say (text)
           (unless (getf *options* :quiet)
             (format *error-output* "~A~%" text)
             (finish-output *error-output*))
           (restore-terminal)
           (uiop:quit 255)))
    (when (eql 0 (cl-pnet-ssh:ssh-config-options-connection-attempts options))
      (say "Invalid number of ConnectionAttempts"))
    (when (background-without-command-p options command-given-p)
      (say "Cannot fork into background without a command to execute."))))

(defun check-forward-agent-socket (options)
  "Warn when ForwardAgent names a socket path that does not exist.

readconf accepts anything that is not a boolean as an agent socket path, and
fill_default_options stats it before -G prints or the connection starts; the
loss is reported at ERROR level, so -q hides the line but the connection
still goes ahead."
  (let ((path (and options
                   (cl-pnet-ssh:ssh-config-options-forward-agent-sock-path
                    options))))
    (when path
      (multiple-value-bind (exists reason)
          (cl-pnet-ssh::ssh-stat-reason path)
        (unless exists
          (cl-pnet-ssh:ssh-warn "Cannot forward agent socket path \"~A\": ~A"
                                path reason))))))

(defparameter +ssh-invalid-hostname-characters+ "'`\"$\\;&<>|(){},"
  "Characters ssh_valid_hostname refuses in a command-line host name.")

(defparameter +ssh-invalid-ruser-characters+ "'`\";&<>|(){}$\\"
  "Characters ssh_valid_ruser refuses in a command-line user name.")

(defun ssh-control-character-p (character)
  (or (< (char-code character) 32)
      (= (char-code character) 127)))

(defun ssh-valid-hostname-p (string)
  "Whether STRING passes readconf's ssh_valid_hostname.

Only the host given on the command line is checked; HostName from the
configuration file is used as written."
  (and (plusp (length string))
       (not (char= (char string 0) #\-))
       (loop for character across string
             never (or (ssh-control-character-p character)
                       (char= character #\Space)
                       (find character +ssh-invalid-hostname-characters+
                             :test #'char=)))))

(defun ssh-valid-ruser-p (string)
  "Whether STRING passes readconf's ssh_valid_ruser."
  (and (plusp (length string))
       (not (char= (char string 0) #\-))
       (loop for index from 0 below (length string)
             for character = (char string index)
             never (or (ssh-control-character-p character)
                       (find character +ssh-invalid-ruser-characters+
                             :test #'char=)
                       ;; A dash may not start a whitespace-separated word,
                       ;; so an option-looking token cannot hide in a name.
                       (and (char= character #\Space)
                            (< (1+ index) (length string))
                            (char= (char string (1+ index)) #\-))))))

(defun command-line-user ()
  "The user ssh has chosen before it reads any configuration file.

-l and an explicit user@host win; otherwise the first -o User value, which
readconf applies while it reads the option, is the one it validates."
  (or (getf *options* :user)
      (loop for line in (command-line-option-list)
            do (multiple-value-bind (keyword value)
                   (command-line-option-parts line)
                 (when (and keyword value
                            (string-equal keyword "User"))
                   (return value))))))

(defun check-command-line-identity (host)
  "Run ssh.c's pre-configuration user and host validation.

Both checks run before log_init, so -q does not hide them and their fatal
messages carry no program prefix."
  (flet ((say (text)
           (format *error-output* "~A~%" text)
           (finish-output *error-output*)
           (restore-terminal)
           (uiop:quit 255)))
    (let ((user (command-line-user)))
      (when (and user (not (ssh-valid-ruser-p user)))
        (say "remote username contains invalid characters")))
    (unless (ssh-valid-hostname-p host)
      (say "hostname contains invalid characters"))))

(defun client-expansion-context (host)
  "The % token context ssh.c builds before its string expansions."
  (cl-pnet-ssh::%make-ssh-config-context
   :original-host host
   :user (getf *options* :user)
   :port (client-port)))

(defun expand-client-option-variables (options host)
  "Run ssh.c's default_client_percent_dollar_expand over OPTIONS.

ssh expands these strings after readconf and before -G or connecting.  An
unset ${NAME} is a fatal \"invalid environment variable expansion\"; a
malformed expansion or an unknown % token dies inside percent_dollar_expand
with \"percent_dollar_expand: failed\".  Both follow the log level, so -q
silences them."
  (let ((context (client-expansion-context host))
        (quiet (getf *options* :quiet)))
    (labels ((die (message kind)
               (unless quiet
                 (format *error-output* "vdollar_percent_expand: ~A~%"
                         (cl-pnet-ssh::ssh-log-escape message))
                 (format *error-output* "~A~%"
                         (if (eq kind :missing-env)
                             "invalid environment variable expansion"
                             "percent_dollar_expand: failed"))
                 (finish-output *error-output*))
               (restore-terminal)
               (uiop:quit 255))
             (die-tilde (user)
               (unless quiet
                 (format *error-output* "tilde_expand: No such user ~A~%"
                         (cl-pnet-ssh::ssh-log-escape user))
                 (finish-output *error-output*))
               (restore-terminal)
               (uiop:quit 255))
             (expand (value &key no-user tilde)
               ;; ssh.c tilde-expands path options before the percent and
               ;; environment expansion, so a leading ~ is gone by then.
               (let ((text (namestring value)))
                 (when tilde
                   (multiple-value-bind (expanded user)
                       (cl-pnet-ssh::ssh-config-expand-tilde text)
                     (if user
                         (die-tilde user)
                         (setf text expanded))))
                 (multiple-value-bind (expanded message kind)
                     (cl-pnet-ssh::ssh-config-percent-dollar-expand
                      text options context :no-user no-user)
                   (when message (die message kind))
                   expanded))))
      ;; ssh.c's order: HostKeyAlias is tidied first, then User, ControlPath,
      ;; IdentityAgent, RevokedHostKeys, ForwardAgent's socket path,
      ;; VersionAddendum, the user's known-hosts files, then SetEnv values.
      ;; GlobalKnownHostsFile is not expanded.
      (let ((alias (cl-pnet-ssh:ssh-config-options-host-key-alias options)))
        (when alias
          (setf (cl-pnet-ssh:ssh-config-options-host-key-alias options)
                (string-downcase alias))))
      (when (and (cl-pnet-ssh:ssh-config-options-user options)
                 (not *getopt-user-command-line*))
        (let* ((original (cl-pnet-ssh:ssh-config-options-user options))
               (expanded (expand original :no-user t)))
          (setf (cl-pnet-ssh:ssh-config-options-user options) expanded)
          ;; ssh.c validates a User that came from -o or the file again when
          ;; the expansion changed it, so a ${VAR} containing a quote cannot
          ;; slip through as a remote name.
          (when (and (not (string= original expanded))
                     (not (ssh-valid-ruser-p expanded)))
            (unless quiet
              (format *error-output*
                      "remote username contains invalid characters~%")
              (finish-output *error-output*))
            (restore-terminal)
            (uiop:quit 255))))
      (let ((path (cl-pnet-ssh:ssh-config-options-control-path options)))
        (when (and path (not (eq path :none)) (not (string-equal path "none")))
          (setf (cl-pnet-ssh:ssh-config-options-control-path options)
                (expand path :tilde t))))
      (let ((agent (cl-pnet-ssh:ssh-config-options-identity-agent options)))
        (when (and agent (not (member agent '(:none :environment))))
          (setf (cl-pnet-ssh:ssh-config-options-identity-agent options)
                (pathname (expand agent :tilde t)))))
      (setf (cl-pnet-ssh:ssh-config-options-revoked-host-keys options)
            (mapcar (lambda (path) (pathname (expand path :tilde t)))
                    (cl-pnet-ssh:ssh-config-options-revoked-host-keys
                     options)))
      (let ((path (cl-pnet-ssh:ssh-config-options-forward-agent-sock-path
                   options)))
        (when path
          (setf (cl-pnet-ssh:ssh-config-options-forward-agent-sock-path options)
                (expand path :tilde t))))
      (let ((text (cl-pnet-ssh:ssh-config-options-version-addendum options)))
        (when text
          (setf (cl-pnet-ssh:ssh-config-options-version-addendum options)
                (expand text))))
      (let ((paths (cl-pnet-ssh:ssh-config-options-known-hosts options)))
        (when (listp paths)
          (setf (cl-pnet-ssh:ssh-config-options-known-hosts options)
                (mapcar (lambda (path) (pathname (expand path :tilde t)))
                        paths))))
      (setf (cl-pnet-ssh:ssh-config-options-set-env options)
            (mapcar (lambda (assignment)
                      (let ((equals (position #\= assignment)))
                        (if equals
                            (concatenate
                             'string
                             (subseq assignment 0 (1+ equals))
                             (expand (subseq assignment (1+ equals))))
                            assignment)))
                    (cl-pnet-ssh:ssh-config-options-set-env options)))
      options)))

(defun expand-hostname-percent (value host)
  "VALUE with ssh.c's HostName expansion applied.

ssh.c calls percent_expand with only %h mapped, so every other token is
fatal there rather than at configuration time.  The two lines come from
log.c, so -q silences them, and the exit status stays 255."
  (labels ((die (message)
             (unless (getf *options* :quiet)
               (format *error-output* "vdollar_percent_expand: ~A~%"
                       (cl-pnet-ssh::ssh-log-escape message))
               (format *error-output* "percent_expand: failed~%")
               (finish-output *error-output*))
             (restore-terminal)
             (uiop:quit 255)))
    (let ((out (make-string-output-stream))
          (length (length value))
          (index 0))
      (loop while (< index length)
            do (let ((character (char value index)))
                 (cond
                   ((char/= character #\%)
                    (write-char character out)
                    (incf index))
                   ((>= (1+ index) length)
                    (die "invalid format"))
                   (t
                    (let ((token (char value (1+ index))))
                      (case token
                        (#\h (write-string host out))
                        (#\% (write-char #\% out))
                        (t (die (format nil "unknown key %~C" token))))
                      (incf index 2))))))
      (get-output-stream-string out))))

(defun prepare-client-hostname (options host)
  "Apply ssh.c's post-readconf HostName tidy-up to OPTIONS."
  (let ((value (cl-pnet-ssh:ssh-config-options-hostname options)))
    (when value
      (setf (cl-pnet-ssh:ssh-config-options-hostname options)
            (expand-hostname-percent value host)))))

(defun resolve-config-options (host &key command-given-p)
  "HOST's ssh_config as SSH-CONFIG-OPTIONS and its canonical name, in order.

COMMAND-GIVEN-P says whether a remote command was named; ssh.c's own checks
after reading the configuration need it."
  (check-config-file)
  (let ((result nil)
        (canonical nil)
        (failure nil)
        (source
          (handler-case
              (cl-pnet-ssh:ssh-config-client-source
               (getf *options* :config)
               ;; -c and -m are dedicated flags rather than -o lines, so
               ;; they have to be folded in before the file is resolved.
               (resolver-option-list))
            (cl-pnet-ssh:ssh-config-error (condition)
              ;; Client-source validation reports readconf's own line before
              ;; signalling, so only an unreported condition needs printing.
              (fail-config-error condition)))))
    (cl-pnet-ssh:ssh-config-canonicalize
     source host
     :original-host host
     :user (getf *options* :user)
     :port (client-port)
     :exec-matcher #'match-exec
     :resolver #'synchronous-canonical-resolver
     :prepare-options (lambda (options) (prepare-client-hostname options host))
     :on-options (lambda (options canonical-host)
                   (setf result options canonical canonical-host))
     :on-error (lambda (condition) (setf failure condition)))
    (when failure
      (fail-config-error failure))
    (check-resolved-options result command-given-p)
    (expand-client-option-variables result host)
    (check-forward-agent-socket result)
    (values result canonical)))

(defun print-list-option (name values)
  (dolist (value values)
    (format t "~A ~A~%" name value)))

(defun print-config (host &optional command-given-p)
  (multiple-value-bind (options canonical)
      (resolve-config-options host :command-given-p command-given-p)
    (print-config-options host options canonical))
  (finish-output)
  (uiop:quit 0))

(defun expand-identity-path (path options host)
  "PATH with its % tokens and leading ~ expanded, as a key loader opens it.

readconf records an IdentityFile spelling exactly as written, so -G repeats
it; the expansion happens when the file is actually loaded.  HOST,
IdentityFile and the command-line user answer %h, %n and %r."
  (let* ((context (cl-pnet-ssh::%make-ssh-config-context
                   :original-host host
                   :user (getf *options* :user)
                   :port (client-port)))
         (name (namestring path))
         (text (multiple-value-bind (expanded unknown)
                   (cl-pnet-ssh::ssh-config-expand-tilde name)
                 (when unknown
                   (unless (getf *options* :quiet)
                     (format *error-output* "tilde_expand: No such user ~A~%"
                             (cl-pnet-ssh::ssh-log-escape unknown))
                     (finish-output *error-output*))
                   (restore-terminal)
                   (uiop:quit 255))
                 expanded)))
    (multiple-value-bind (expanded message kind)
        (cl-pnet-ssh::ssh-config-percent-dollar-expand
         text options context)
      (when message
        (unless (getf *options* :quiet)
          (format *error-output* "vdollar_percent_expand: ~A~%"
                  (cl-pnet-ssh::ssh-log-escape message))
          (format *error-output* "~A~%"
                  (if (eq kind :missing-env)
                      "invalid environment variable expansion"
                      "percent_dollar_expand: failed"))
          (finish-output *error-output*))
        (restore-terminal)
        (uiop:quit 255))
      expanded)))

(defun dump-public-key-blob (path)
  "PATH's public key blob, as ssh -Z loads one.

Tries PATH as a public key file, then PATH.pub, then the public half of a
private key at PATH.  An unreadable file yields NIL."
  (let ((name (namestring path)))
    (or (cl-pnet-ssh::ssh-public-key-file-blob name)
        (cl-pnet-ssh::ssh-public-key-file-blob
         (concatenate 'string name ".pub"))
        (handler-case
            (cl-pnet-ssh:ssh-public-key-blob-of
             (cl-pnet-ssh:ssh-load-private-key name))
          (error () nil)))))

(defun dump-public-certificate-blob (path)
  "PATH's certificate blob, trying the name as given and with .pub appended."
  (let ((name (namestring path)))
    (or (cl-pnet-ssh::ssh-public-key-file-blob name)
        (cl-pnet-ssh::ssh-public-key-file-blob
         (concatenate 'string name ".pub")))))

(defun dump-public-key-line (stream name blob explicit-p agent-p)
  "One ssh -Z line: FILENAME TYPE FINGERPRINT [explicit] [agent].

A key that could not be loaded leaves the type and fingerprint empty, as
OpenSSH's format_identity does."
  (format stream "~A ~A~@[ ~A~]~:[~; explicit~]~:[~; agent~]~%"
          name
          (if blob (cl-pnet-ssh:ssh-key-type-name blob) "")
          (and blob (cl-pnet-ssh:ssh-key-fingerprint blob))
          (and (integerp explicit-p) (plusp explicit-p))
          agent-p))

(defun dump-public-key-priority (blob)
  "OpenSSH's identity priority for BLOB: certificates before plain keys.

The SecurityKey priorities (0 and 2) cannot occur here because this client
has no FIDO keys."
  (if (and blob (cl-pnet-ssh::ssh-certificate-blob-p blob)) 1 3))

(defun dump-sort-identities (entries)
  "Sort the non-explicit ENTRIES by key priority, leaving explicit ones put.

ENTRIES are (NAME BLOB USERPROVIDED ...) lists.  OpenSSH's
order_identities_by_prio sorts only identities that did not come from the
command line or a user configuration, so an explicit key keeps its place and
the rest are reordered among the slots they occupy."
  (let* ((sortable (remove-if (lambda (entry)
                                (plusp (or (third entry) 0)))
                              entries))
         (sorted (stable-sort
                  (copy-list sortable) #'<
                  :key (lambda (entry)
                         (dump-public-key-priority (second entry)))))
         (next sorted))
    (mapcar (lambda (entry)
              (if (plusp (or (third entry) 0))
                  entry
                  (prog1 (first next) (setf next (rest next)))))
            entries)))

(defun dump-public-key-identities (host &optional (stream *standard-output*)
                                            command-given-p)
  "Print the keys authentication would offer for HOST, as ssh -Z does.

Mirrors OpenSSH's pubkey_prepare: CertificateFile certificates first, then
agent keys, then identity files.  A key that is both an identity file and in
the agent is shown once, under the file's name, with both annotations.  A
file that cannot be read is still listed with an empty type and fingerprint;
only a -i path that does not exist at all is dropped, as ssh's option parser
drops it."
  (multiple-value-bind (options canonical)
      (resolve-config-options host :command-given-p command-given-p)
    (declare (ignore canonical))
    (let* ((explicit
             (loop for path in (reverse
                                (getf *options* :identity-arguments))
                   for name = (expand-identity-path path options host)
                   when (cl-pnet-ssh:ssh-file-exists-p name)
                     collect name))
           (configured
             (reverse
              (cl-pnet-ssh:ssh-config-options-identity-files options)))
           (configured-userprovided
             (reverse
              (cl-pnet-ssh:ssh-config-options-identity-files-userprovided
               options)))
           (defaults
             (unless (or explicit configured)
               (mapcar
                (lambda (name)
                  (namestring
                   (merge-pathnames (format nil ".ssh/~A" name)
                                    (user-homedir-pathname))))
                cl-pnet-ssh::+ssh-default-identity-names+)))
           (files '()))
      (labels ((add (name blob explicit-p)
                 "Add (NAME BLOB EXPLICIT-P) unless that pair is already there.

                 An IdentityFile of \"none\" is a placeholder readconf records
                 but load_public_identity_files skips with strcasecmp, so -Z
                 never lists it."
                 (unless (or (string-equal name "none")
                             (find-if (lambda (entry)
                                        (and (string= (first entry) name)
                                             (eql (third entry) explicit-p)))
                                      files))
                   (push (list name blob explicit-p) files))))
        (dolist (name explicit)
          (add name (dump-public-key-blob name) 1))
        (loop for path in configured
              for explicit-p in configured-userprovided
              for name = (expand-identity-path path options host)
              do (add name (dump-public-key-blob name) explicit-p))
        (dolist (name defaults)
          (add name (dump-public-key-blob name) 0)))
      (setf files (nreverse files))
      ;; A readable identity also contributes its implicit -cert.pub
      ;; certificate, unless a CertificateFile was named.
      (let ((certificate-files
              (cl-pnet-ssh:ssh-config-options-certificate-files options)))
        (unless certificate-files
          (setf files
                (loop for entry in files
                      append
                      (append
                       (list entry)
                       (let* ((name (first entry))
                              (blob (second entry))
                              (certificate
                                (and blob
                                     (dump-public-certificate-blob
                                      (concatenate 'string
                                                   name "-cert.pub")))))
                         (when (and certificate
                                    (cl-pnet-ssh::ssh-certificate-blob-p
                                     certificate))
                           (list (list name certificate
                                       (third entry)))))))))
        ;; CertificateFile certificates come before everything else.
        (let ((certs
                (loop for path in (reverse certificate-files)
                      for explicit-p in
                        (reverse
                         (cl-pnet-ssh:ssh-config-options-certificate-files-userprovided
                          options))
                      for name = (expand-identity-path path options host)
                      for blob = (dump-public-certificate-blob name)
                      when (and blob
                                (cl-pnet-ssh::ssh-certificate-blob-p blob))
                        collect (list name blob explicit-p)))
              (remaining files)
              (agent-matched '())
              (agent-only '()))
          (setf certs (dump-sort-identities certs))
          (let ((agent (cl-pnet-ssh::ssh-config-client-agent options nil)))
            (when (and agent (not (eq agent :none)))
              (handler-case
                  (dolist (entry
                           (cl-pnet-ssh:ssh-agent-identities-blocking
                            :path agent))
                    (let* ((blob (car entry))
                           (comment (cdr entry))
                           (file (find-if
                                  (lambda (candidate)
                                    (and (second candidate)
                                         (cl-pnet-ssh::ssh-octets=
                                          blob (second candidate))))
                                  remaining)))
                      (if file
                          (progn
                            (setf remaining (delete file remaining))
                            (push (list (first file) blob (third file) t)
                                  agent-matched))
                          (push (list (if (and comment
                                               (plusp (length comment)))
                                          comment
                                          "(none)")
                                      blob nil t)
                                agent-only))))
                (error () nil))))
          (dolist (entry certs)
            (dump-public-key-line stream (first entry) (second entry)
                                  (third entry) nil))
          ;; OpenSSH lists agent keys that are also identity files before the
          ;; agent-only keys, then sorts the non-explicit ones by priority.
          (dolist (entry (dump-sort-identities
                          (append (nreverse agent-matched)
                                  (nreverse agent-only))))
            (dump-public-key-line stream (first entry) (second entry)
                                  (third entry) (fourth entry)))
          (dolist (entry (dump-sort-identities remaining))
            (dump-public-key-line stream (first entry) (second entry)
                                  (third entry) nil)))))))

(defun dump-public-keys (host &optional command-given-p)
  "Print the public keys and exit, as ssh -Z does."
  (dump-public-key-identities host *standard-output* command-given-p)
  (finish-output)
  (uiop:quit 0))

(defun print-list-oneline (name values)
  "Print NAME and VALUES on one line, with ssh -G's \"none\" for empty."
  (format t "~A" name)
  (if values
      (dolist (value values)
        (format t " ~A" value))
      (format t " none"))
  (format t "~%"))

(defun config-escape-char-string (value)
  "VALUE as readconf's dump_client_config shows EscapeChar.

OpenSSH passes the byte through vis(3) with VIS_WHITE, so a control
character becomes \\^A, a space \\040, a backslash \\\\ and a high byte
\\M-x.  NIL is unset, which ssh prints as the default ~."
  (cond
    ((eq value :none) "none")
    ((null value) "~")
    (t
     (let* ((byte (logand (if (characterp value) (char-code value) value)
                          #xff)))
       (cond
         ((= (logand byte #o177) #x20)
          (format nil "\\~3,'0o" byte))
         ((and (<= 33 byte) (<= byte 126))
          (if (= byte 92) "\\\\" (string (code-char byte))))
         ((>= byte 128)
          (let ((low (logand byte #x7f)))
            (format nil "\\M-~A"
                    (cond ((= low 127) "^?")
                          ((< low 32)
                           (format nil "^~C" (code-char (+ low 64))))
                          (t (string (code-char low)))))))
         ((= byte 127) "\\^?")
         (t (format nil "\\^~C" (code-char (+ byte 64)))))))))

(defun proxy-jump-numeric-host-p (host)
  "Whether -G wraps HOST in brackets, as ssh's numeric-address test does."
  (or (find #\: host)
      (and (plusp (length host))
           (every (lambda (character)
                    (find character "1234567890."))
                  host))))

(defun format-proxy-jump-hop (hop)
  "One ProxyJump hop with a numeric host bracketed, as ssh -G prints it."
  (let* ((at (position #\@ hop))
         (user (and at (subseq hop 0 (1+ at))))
         (hostpart (if at (subseq hop (1+ at)) hop)))
    (if (and (plusp (length hostpart))
             (char= (char hostpart 0) #\[))
        hop
        (let* ((colon (position #\: hostpart))
               (host (if colon (subseq hostpart 0 colon) hostpart))
               (port (if colon (subseq hostpart colon) "")))
          (if (proxy-jump-numeric-host-p host)
              (format nil "~A[~A]~A" (or user "") host port)
              hop)))))

(defun format-proxy-jump (value)
  "VALUE's hops, numeric hosts bracketed, joined with commas."
  (let ((hops (cond ((listp value) value)
                    ((stringp value)
                     (uiop:split-string value :separator ","))
                    (t nil))))
    (format nil "~{~A~^,~}" (mapcar #'format-proxy-jump-hop hops))))

(defstruct (dump-forward (:constructor %make-dump-forward))
  kind
  listen-address listen-port listen-path
  host port target-path)

(defun dump-forward-endpoint (address port path)
  "One forwarding endpoint, formatted as dump_cfg_forwards prints it."
  (cond (path path)
        (address (format nil "[~A]:~A" address port))
        (t (format nil "~A" port))))

(defun dump-forward-from-forward (kind forward)
  (%make-dump-forward
   :kind kind
   :listen-address (forward-bind-address forward)
   :listen-port (forward-bind-port forward)
   :listen-path (forward-bind-path forward)
   :host (forward-host forward)
   :port (forward-port forward)
   :target-path (forward-target-path forward)))

(defun dump-forward-from-dynamic (forward)
  (%make-dump-forward
   :kind :dynamic
   :listen-address (dynamic-forward-bind-address forward)
   :listen-port (dynamic-forward-bind-port forward)
   :listen-path (dynamic-forward-bind-path forward)
   :target-path (dynamic-forward-target-path forward)))

(defun dump-forward-from-option (keyword value)
  "A dump record for ssh_config KEYWORD with VALUE, as -o or a file wrote it."
  (let ((value (or (cl-pnet-ssh::ssh-forward-expand-value value nil) value)))
    (cond
      ((string= keyword "localforward")
       (dump-forward-from-forward :local (parse-config-local-forward value)))
      ((string= keyword "remoteforward")
       (dump-forward-from-forward :remote (parse-config-remote-forward value)))
      (t
       ;; DynamicForward takes [bind_address:]port or a socket path.
       (if (path-field-p value)
           (%make-dump-forward :kind :dynamic :listen-path value)
           (dump-forward-from-dynamic (parse-dynamic-forward value)))))))

(defun dump-forward-record (record)
  "The dump record for one command-line forwarding EVENT."
  (case (first record)
    (:local
     (dump-forward-from-forward :local (parse-local-forward (second record))))
    (:remote
     (dump-forward-from-forward :remote (parse-remote-forward (second record))))
    (:dynamic
     (dump-forward-from-dynamic (parse-dynamic-forward (second record))))
    (:option
     (multiple-value-bind (keyword value)
         (command-line-option-parts (second record))
       (dump-forward-from-option (string-downcase (or keyword "")) value)))
    (t nil)))

(defun expand-forward-path (options host canonical path)
  "PATH with ssh.c's percent_expand, or NIL when PATH is NIL.

ssh.c expands LocalForward and RemoteForward listen/connect paths after
readconf and before -G or connecting, so %d and friends have already turned
into their values in the dump."
  (and path
       (expand-client-percent
        options host canonical path
        :port (or (cl-pnet-ssh:ssh-config-options-port options)
                  (client-port)
                  22)
        :user (or (cl-pnet-ssh:ssh-config-options-user options)
                  (getf *options* :user)
                  (cl-pnet-ssh:ssh-default-user)))))

(defun expand-dump-forward-paths (record options host canonical)
  "RECORD with its socket paths expanded, as ssh.c does before -G."
  (setf (dump-forward-listen-path record)
        (expand-forward-path options host canonical
                             (dump-forward-listen-path record))
        (dump-forward-target-path record)
        (expand-forward-path options host canonical
                             (dump-forward-target-path record)))
  record)

(defun forward-dump-records (options host canonical)
  "The forwarding records -G prints, with ssh.c's path expansions applied.

Building the records up front matters: ssh.c expands RemoteCommand and the
forwarding paths before dump_client_config, so a bad % token leaves no
partial dump behind."
  (mapcar (lambda (record)
            (expand-dump-forward-paths record options host canonical))
          (append
           (mapcar #'dump-forward-record (command-line-forward-events))
           (loop for entry in (reverse
                               (cl-pnet-ssh::ssh-config-options-extra options))
                 when (eq (second entry) :file)
                   collect (dump-forward-from-option
                            (first entry)
                            (format nil "~{~A~^ ~}" (cddr entry)))))))

(defun print-forward-dump (records)
  "Print the forwarding lines of -G exactly as readconf dumps them.

readconf keeps one array per direction, so the dynamic entries come first
(including a local forward whose target is a socket path), then every local
forward, then every remote forward, each array in the order the arguments and
configuration lines were read."
  (dolist (record records)
    (when (or (eq (dump-forward-kind record) :dynamic)
              (and (eq (dump-forward-kind record) :local)
                   (null (dump-forward-host record))))
      (format t "dynamicforward ~A~%"
              (dump-forward-endpoint
               (dump-forward-listen-address record)
               (dump-forward-listen-port record)
               (dump-forward-listen-path record)))))
  (dolist (record records)
    (cond
      ((eq (dump-forward-kind record) :local)
       (format t "localforward ~A ~A~%"
               (dump-forward-endpoint
                (dump-forward-listen-address record)
                (dump-forward-listen-port record)
                (dump-forward-listen-path record))
               (dump-forward-endpoint
                (dump-forward-host record)
                (dump-forward-port record)
                (dump-forward-target-path record))))
      ;; A dynamic forward with a socket target sits in readconf's local
      ;; array without a connect host, so it is dumped twice: once as a
      ;; dynamic forward and once as a local one.
      ((and (eq (dump-forward-kind record) :dynamic)
            (dump-forward-target-path record))
       (format t "localforward ~A ~A~%"
               (dump-forward-endpoint
                (dump-forward-listen-address record)
                (dump-forward-listen-port record)
                (dump-forward-listen-path record))
               (dump-forward-target-path record)))))
  (dolist (record records)
    (when (eq (dump-forward-kind record) :remote)
      (format t "remoteforward ~A ~A~%"
              (dump-forward-endpoint
               (dump-forward-listen-address record)
               (dump-forward-listen-port record)
               (dump-forward-listen-path record))
              (dump-forward-endpoint
               (dump-forward-host record)
               (dump-forward-port record)
               (dump-forward-target-path record))))))

(defun print-config-options (host options canonical)
  "Print OPTIONS resolved for HOST, whose canonical name is CANONICAL.

The field set, order and spellings follow OpenSSH 10.6's dump_client_config,
so a script that reads `ssh -G` finds the same configuration from burs.
Values where this build makes a different choice (its own algorithm offers
and known-hosts files) are printed as this client will actually use them."
  (let* ((hostname (or canonical
                       (cl-pnet-ssh:ssh-config-options-hostname options)
                       host))
         ;; ssh.c expands RemoteCommand and every forwarding path before it
         ;; dumps anything, so a bad % token here must leave no output.
         (remote (cl-pnet-ssh:ssh-config-command-value
                  (cl-pnet-ssh:ssh-config-options-remote-command options)))
         (remote-expanded (and remote
                               (expand-client-percent
                                options host hostname remote
                                :port (or (cl-pnet-ssh:ssh-config-options-port
                                           options)
                                          (client-port)
                                          22)
                                :user (or (cl-pnet-ssh:ssh-config-options-user
                                           options)
                                          (getf *options* :user)
                                          (cl-pnet-ssh:ssh-default-user)))))
         (forward-records (forward-dump-records options host hostname)))
    (flet ((yes-no (value) (if value "yes" "no"))
           (true-false (value) (if value "true" "false"))
           (paths (values) (mapcar #'namestring values))
           (algorithms (accessor supported option &optional all)
             (or (cl-pnet-ssh::ssh-config-client-algorithms
                  options accessor supported option
                  :all (or all supported))
                 supported)))
      (format t "host ~A~%" host)
      (format t "user ~A~%"
              (or (cl-pnet-ssh:ssh-config-options-user options)
                  (getf *options* :user)
                  (cl-pnet-ssh:ssh-default-user)))
      (format t "hostname ~A~%" hostname)
      (format t "port ~D~%"
              (or (cl-pnet-ssh:ssh-config-options-port options)
                  (client-port)
                  22))
      (let ((family (or (cl-pnet-ssh:ssh-config-options-address-family
                         options)
                        (getf *options* :address-family))))
        (format t "addressfamily ~A~%"
                (cond ((null family) "any")
                      ((stringp family) (string-downcase family))
                      (t (string-downcase (symbol-name family))))))
      (format t "batchmode ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-batch-mode options)))
      (format t "canonicalizefallbacklocal ~A~%"
              (yes-no
               (cl-pnet-ssh:ssh-config-options-canonicalize-fallback-local
                options)))
      (format t "canonicalizehostname ~A~%"
              (case (cl-pnet-ssh:ssh-config-options-canonicalize-hostname
                     options)
                (:yes "true") (:no "false") (t "always")))
      (format t "checkhostip ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-check-host-ip options)))
      ;; -C is a dedicated flag rather than an -o line, so both sources
      ;; need consulting here.
      (format t "compression ~A~%"
              (yes-no (or (getf *options* :compression)
                          (cl-pnet-ssh:ssh-config-options-compression
                           options))))
      ;; ssh -G spells yes and no as true and false here, and omits
      ;; ControlPath entirely when multiplexing has no socket.
      (let ((master (cl-pnet-ssh:ssh-config-options-control-master options)))
        (format t "controlmaster ~A~%"
                (case master
                  ((:yes) "true")
                  ((nil :no) "false")
                  (t (string-downcase (symbol-name master))))))
      (format t "enablesshkeysign ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-enable-ssh-keysign
                       options)))
      (format t "clearallforwardings ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-clear-all-forwardings
                       options)))
      (format t "exitonforwardfailure ~A~%"
              (yes-no
               (cl-pnet-ssh:ssh-config-options-exit-on-forward-failure
                options)))
      (format t "fingerprinthash ~A~%"
              (string-upcase
               (symbol-name
                (or (cl-pnet-ssh:ssh-config-options-fingerprint-hash options)
                    :sha256))))
      (let ((cli (getf *options* :x11-forward)))
        (format t "forwardx11 ~A~%"
                (cond ((eq cli :no) "no")
                      ((member cli '(:yes :trust) :test #'eq) "yes")
                      (t (yes-no
                          (cl-pnet-ssh:ssh-config-options-forward-x11
                           options))))))
      (format t "forwardx11trusted ~A~%"
              (yes-no
               (if (eq (getf *options* :x11-forward) :trust)
                   t
                   (cl-pnet-ssh:ssh-config-options-forward-x11-trusted
                    options))))
      (format t "gatewayports ~A~%"
              (yes-no (or (getf *options* :gateway-ports)
                          (cl-pnet-ssh:ssh-config-options-gateway-ports
                           options))))
      ;; GSSAPIAuthentication and GSSAPIDelegateCredentials are unsupported
      ;; here, just as in an OpenSSH compiled without GSSAPI: the config
      ;; parser reports them and they configure nothing, so -G prints
      ;; neither line.  -K and -k are accepted the way ssh accepts them, and
      ;; do nothing because no gssapi-with-mic method exists to offer.
      (format t "hashknownhosts ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-hash-known-hosts
                       options)))
      (format t "hostbasedauthentication ~A~%"
              (yes-no
               (cl-pnet-ssh:ssh-config-options-hostbased-authentication
                options)))
      (format t "identitiesonly ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-identities-only
                       options)))
      (format t "kbdinteractiveauthentication ~A~%"
              (yes-no
               (cl-pnet-ssh:ssh-config-options-kbd-interactive-authentication
                options)))
      (format t "nohostauthenticationforlocalhost ~A~%"
              (yes-no
               (cl-pnet-ssh:ssh-config-options-no-host-authentication-for-localhost
                options)))
      (format t "passwordauthentication ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-password-authentication
                       options)))
      (format t "permitlocalcommand ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-permit-local-command
                       options)))
      (format t "proxyusefdpass ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-proxy-use-fdpass
                       options)))
      ;; PubkeyAuthentication is a multistate in 10.6, so yes prints true.
      (format t "pubkeyauthentication ~A~%"
              (if (eq (cl-pnet-ssh:ssh-config-options-pubkey-authentication
                       options)
                      :no)
                  "false"
                  "true"))
      (let ((setting (or (getf *options* :request-tty)
                         (cl-pnet-ssh:ssh-config-options-request-tty
                          options))))
        ;; 10.6 prints the first spelling of RequestTTY's multistate table.
        (format t "requesttty ~A~%"
                (cond
                  ((null setting) "auto")
                  ((eq setting :yes) "true")
                  ((eq setting :no) "false")
                  ((eq setting :force) "force")
                  ((eq setting :auto) "auto")
                  ((stringp setting)
                   (case (request-tty-multistate setting)
                     (:yes "true")
                     (:no "false")
                     (:force "force")
                     (:auto "auto")
                     (t (string-downcase setting))))
                  (t (string-downcase (princ-to-string setting))))))
      (format t "sessiontype ~A~%"
              (or (cl-pnet-ssh:ssh-config-options-session-type options)
                  "default"))
      (format t "stdinnull ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-stdin-null options)))
      (format t "forkafterauthentication ~A~%"
              (yes-no
               (cl-pnet-ssh:ssh-config-options-fork-after-authentication
                options)))
      (format t "streamlocalbindunlink ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-streamlocal-bind-unlink
                       options)))
      ;; -G prints the first spelling of the multistate table that matches
      ;; the value, so yes/true both become "true" and no/off both "false".
      (format t "stricthostkeychecking ~A~%"
              (let ((value
                      (cl-pnet-ssh:ssh-config-options-strict-host-key-checking
                       options)))
                (cond
                  ((null value)
                   (case (getf *options* :policy)
                     (:insecure "false")
                     (:accept-new "accept-new")
                     (:ask "ask")
                     (t "ask")))
                  ((member value '("no" "off") :test #'string-equal) "false")
                  ((member value '("yes" "true") :test #'string-equal) "true")
                  (t value))))
      ;; TCPKeepAlive's multistate prints true/false in 10.6.
      (format t "tcpkeepalive ~A~%"
              (true-false
               (cl-pnet-ssh:ssh-config-options-tcp-keep-alive options)))
      ;; ssh prints Tunnel's multistate name: ethernet, point-to-point,
      ;; true for the default device, or false when disabled.  A -w flag
      ;; asks for point-to-point.
      (format t "tunnel ~A~%"
              (cond
                ((getf *options* :tunnel) "point-to-point")
                (t (case (cl-pnet-ssh:ssh-config-options-tunnel options)
                     (:ethernet "ethernet")
                     ;; SSH_TUNMODE_DEFAULT is SSH_TUNMODE_POINTOPOINT, and
                     ;; the dump names the first table entry with that value.
                     ((:point-to-point :yes) "point-to-point")
                     (t "false")))))
      (format t "verifyhostkeydns ~A~%"
              (case (cl-pnet-ssh:ssh-config-options-verify-host-key-dns
                     options)
                (:ask "ask") (:yes "true") (t "false")))
      (format t "visualhostkey ~A~%"
              (yes-no (cl-pnet-ssh:ssh-config-options-visual-host-key
                       options)))
      ;; 10.6 prints true/false/ask here, and turns UpdateHostKeys off by
      ;; default when VerifyHostKeyDNS asks for DNS keys or the user's
      ;; known-hosts list was changed from the single default file.
      (format t "updatehostkeys ~A~%"
              (case (cl-pnet-ssh:ssh-config-update-host-keys-default options)
                (:yes "true")
                (:ask "ask")
                (t "false")))
      (format t "enableescapecommandline ~A~%"
              (yes-no
               (cl-pnet-ssh:ssh-config-options-enable-escape-commandline
                options)))
      (format t "warnweakcrypto ~A~%"
              (yes-no
               (not (eq (cl-pnet-ssh:ssh-config-options-warn-weak-crypto
                         options)
                        :no))))

      ;; Integer options.
      (format t "canonicalizemaxdots ~D~%"
              (cl-pnet-ssh:ssh-config-options-canonicalize-max-dots options))
      (format t "connectionattempts ~D~%"
              (or (cl-pnet-ssh:ssh-config-options-connection-attempts options)
                  1))
      (format t "forwardx11timeout ~D~%"
              (or (cl-pnet-ssh:ssh-config-options-forward-x11-timeout options)
                  1200))
      (format t "numberofpasswordprompts ~D~%"
              (or (cl-pnet-ssh:ssh-config-options-number-of-password-prompts
                   options)
                  3))
      (format t "serveralivecountmax ~D~%"
              (or (cl-pnet-ssh:ssh-config-options-server-alive-count-max
                   options)
                  3))
      (format t "serveraliveinterval ~D~%"
              (let ((value
                      (cl-pnet-ssh:ssh-config-options-server-alive-interval
                       options)))
                (if (integerp value) value 0)))
      (format t "requiredrsasize ~D~%"
              (or (cl-pnet-ssh:ssh-config-options-required-rsa-size options)
                  cl-pnet-ssh::+ssh-rsa-minimum-modulus-size+))
      (format t "obscurekeystroketiming ~A~%"
              (let ((value
                      (or (cl-pnet-ssh:ssh-config-options-obscure-keystroke-timing
                           options)
                          cl-pnet-ssh:+ssh-keystroke-default-interval-ms+)))
                (cond ((zerop value) "no")
                      ((= value cl-pnet-ssh:+ssh-keystroke-default-interval-ms+)
                       "yes")
                      (t (format nil "~D" value)))))

      ;; String options.  dump_cfg_string prints a line only when the
      ;; value is set, so the optional ones stay silent here.
      (let ((value (or (getf *options* :bind-address)
                       (cl-pnet-ssh:ssh-config-options-bind-address
                        options))))
        (when value
          (format t "bindaddress ~A~%" value)))
      (let ((value (or (getf *options* :bind-interface)
                       (cl-pnet-ssh:ssh-config-options-bind-interface
                        options))))
        (when value
          (format t "bindinterface ~A~%" value)))
      (format t "ciphers ~{~A~^,~}~%"
              (algorithms #'cl-pnet-ssh:ssh-config-options-ciphers
                          (transport-supported-algorithms
                           cl-pnet-ssh::+ssh-ciphers+ :ciphers)
                          "Ciphers"
                          (transport-supported-algorithms
                           cl-pnet-ssh::+ssh-all-ciphers+ :ciphers)))
      (let ((path (cl-pnet-ssh:ssh-config-options-control-path options)))
        (when (and path (not (eq path :none)) (not (string-equal path "none")))
          (format t "controlpath ~A~%"
                  (mux-expand-control-path
                   (mux-tilde-expand path)
                   :original host
                   :hostname hostname
                   :port (or (cl-pnet-ssh:ssh-config-options-port options)
                             (client-port)
                             22)
                   :user (or (cl-pnet-ssh:ssh-config-options-user options)
                             (getf *options* :user)
                             (uiop:getenv "USER")
                             "root")))))
      (format t "hostkeyalgorithms ~{~A~^,~}~%"
              (algorithms
               #'cl-pnet-ssh:ssh-config-options-host-key-algorithms
               (supported-host-key-algorithms) "HostKeyAlgorithms"
               (key-algorithm-name-universe
                (supported-host-key-all-algorithms))))
      (let ((alias (cl-pnet-ssh:ssh-config-options-host-key-alias options)))
        (when alias
          (format t "hostkeyalias ~A~%" alias)))
      (format t "hostbasedacceptedalgorithms ~{~A~^,~}~%"
              (algorithms
               #'cl-pnet-ssh:ssh-config-options-hostbased-accepted-algorithms
               (supported-signature-algorithms)
               "HostbasedAcceptedAlgorithms"
               (key-algorithm-name-universe
                (supported-signature-all-algorithms))))
      (let ((value (or (cl-pnet-ssh:ssh-config-options-identity-agent options)
                       (getf *options* :agent))))
        (when value
          (format t "identityagent ~A~%"
                  (case value
                    (:none "none")
                    (:environment "SSH_AUTH_SOCK")
                    (t (if (stringp value)
                           (cl-pnet-ssh::ssh-config-expand-home value)
                           value))))))
      (let ((ignored (cl-pnet-ssh:ssh-config-options-ignored-unknown options)))
        (when ignored
          (format t "ignoreunknown ~A~%" ignored)))
      (let ((devices
              (cl-pnet-ssh:ssh-config-options-kbd-interactive-devices
               options)))
        (when devices
          (format t "kbdinteractivedevices ~A~%" devices)))
      (format t "kexalgorithms ~{~A~^,~}~%"
              (algorithms
               #'cl-pnet-ssh:ssh-config-options-kex-algorithms
               (default-kex-algorithms) "KexAlgorithms"
               (supported-kex-algorithms)))
      (format t "casignaturealgorithms ~{~A~^,~}~%"
              (algorithms
               #'cl-pnet-ssh:ssh-config-options-ca-signature-algorithms
               (supported-ca-signature-algorithms)
               "CASignatureAlgorithms"
               (key-algorithm-name-universe
                (supported-ca-signature-algorithm-names))))
      (let ((local (cl-pnet-ssh:ssh-config-command-value
                    (cl-pnet-ssh:ssh-config-options-local-command options))))
        (when local
          (format t "localcommand ~A~%" local)))
      (let ((remote remote-expanded))
        (when remote
          ;; ssh.c expands RemoteCommand with percent_expand before -G, so
          ;; %h is the final canonical host and ${NAME} stays literal.
          (format t "remotecommand ~A~%" remote)))
      (format t "loglevel ~A~%"
              (string-upcase
               (or (cl-pnet-ssh:ssh-config-options-log-level options)
                   "info")))
      (format t "macs ~{~A~^,~}~%"
              (algorithms #'cl-pnet-ssh:ssh-config-options-macs
                          (default-mac-algorithms) "MACs"
                          (supported-mac-algorithms)))
      (let ((provider (or (getf *options* :pkcs11)
                          (cl-pnet-ssh:ssh-config-options-pkcs11-provider
                           options))))
        (when (and provider (not (eq provider :none)))
          (format t "pkcs11provider ~A~%" provider)))
      (let ((provider
              (cl-pnet-ssh:ssh-config-options-security-key-provider options)))
        ;; ssh clears "none" after parsing, so no line appears; otherwise
        ;; the default provider is internal.
        (unless (eq provider :none)
          (format t "securitykeyprovider ~A~%"
                  (or provider "internal"))))
      (let ((methods
              (cl-pnet-ssh:ssh-config-options-preferred-authentications
               options)))
        (when methods
          (format t "preferredauthentications ~{~A~^,~}~%" methods)))
      (format t "pubkeyacceptedalgorithms ~{~A~^,~}~%"
              (algorithms
               #'cl-pnet-ssh:ssh-config-options-pubkey-accepted-algorithms
               (supported-signature-algorithms)
               "PubkeyAcceptedAlgorithms"
               (key-algorithm-name-universe
                (supported-signature-all-algorithms))))
      (format t "xauthlocation ~A~%"
              (or (cl-pnet-ssh:ssh-config-options-xauth-location options)
                  "/usr/bin/xauth"))
      (let ((command (cl-pnet-ssh:ssh-config-command-value
                      (cl-pnet-ssh:ssh-config-options-known-hosts-command
                       options))))
        (when command
          (format t "knownhostscommand ~A~%" command)))
      (let ((tag (or (getf *options* :tag)
                     (cl-pnet-ssh:ssh-config-options-tag options))))
        (when tag
          (format t "tag ~A~%" tag)))
      (when (cl-pnet-ssh:ssh-config-options-version-addendum options)
        (format t "versionaddendum ~A~%"
                (or (cl-pnet-ssh::ssh-config-client-version-addendum
                     options host
                     :user (getf *options* :user)
                     :port (client-port))
                    "")))

      ;; Forwarding lines.
      (print-forward-dump forward-records)

      ;; String arrays.
      ;;
      ;; -i, -o IdentityFile and the file's own entries are printed in the
      ;; order ssh recorded them: the command line in argv order (an -i
      ;; spelling is expanded, an -o one is left as written) and then the
      ;; configuration file's entries.  A duplicate the resolver already
      ;; dropped does not reappear here.
      (multiple-value-bind (command-line option-spellings)
          (command-line-identity-entries)
        (let* ((configured
                 (reverse
                  (cl-pnet-ssh:ssh-config-options-identity-files options)))
               (from-file
                 (loop for path in configured
                       for name = (namestring path)
                       unless (member name option-spellings :test #'string=)
                         collect name))
               (files (append command-line from-file)))
          (if files
              (print-list-option "identityfile" files)
              (dolist (name cl-pnet-ssh::+ssh-default-identity-names+)
                (format t "identityfile ~~/.ssh/~A~%" name)))))
      (print-list-oneline
       "canonicaldomains"
       (cl-pnet-ssh:ssh-config-options-canonical-domains options))
      (print-list-option
       "certificatefile"
       (paths (reverse
               (cl-pnet-ssh:ssh-config-options-certificate-files options))))
      (print-list-oneline
       "globalknownhostsfile"
       (let ((files (cl-pnet-ssh:ssh-config-options-global-known-hosts
                     options)))
         (cond ((eq files :none) nil)
               (files (paths files))
               (t cl-pnet-ssh::+ssh-default-global-known-hosts+))))
      (print-list-oneline
       "userknownhostsfile"
       (let ((files (cl-pnet-ssh:ssh-config-options-known-hosts options))
             (cli (getf *options* :known-hosts)))
         (cond (cli (list (cl-pnet-ssh::ssh-config-expand-home cli)))
               ((eq files :none) nil)
               (files (paths files))
               (t (paths (cl-pnet-ssh::ssh-default-user-known-hosts))))))
      (print-list-oneline
       "revokedhostkeys"
       (paths (reverse
               (cl-pnet-ssh:ssh-config-options-revoked-host-keys options))))
      (print-list-option "sendenv"
                         (cl-pnet-ssh:ssh-config-options-send-env options))
      (print-list-option "setenv"
                         (cl-pnet-ssh:ssh-config-options-set-env options))
      (print-list-oneline
       "logverbose"
       (cl-pnet-ssh:ssh-config-options-log-verbose options))
      (print-list-oneline
       "channeltimeout"
       (let ((timeouts
               (cl-pnet-ssh:ssh-config-options-channel-timeouts options)))
         (if (consp timeouts) timeouts nil)))

      ;; Special cases, in 10.6's order.
      (let ((permit (cl-pnet-ssh:ssh-config-options-permit-remote-open
                     options)))
        (print-list-oneline
         "permitremoteopen"
         (cond
           ((eq permit :none) (list "none"))
           ((or (null permit) (eq permit :any)) (list "any"))
           (t (mapcar (lambda (entry)
                        ;; readconf stores the argument as written and -G
                        ;; reprints it, so the raw spelling is what we keep.
                        (first entry))
                      permit)))))
      (let ((state (cl-pnet-ssh:ssh-config-options-add-keys-to-agent
                    options))
            (lifespan
              (cl-pnet-ssh:ssh-config-options-add-keys-to-agent-lifespan
               options)))
        (if (and lifespan (plusp lifespan))
            ;; readconf prints the lifetime and, only for "confirm", the
            ;; word before it.
            (format t "addkeystoagent~A ~D~%"
                    (if (eq state :confirm) " confirm" "")
                    lifespan)
            (format t "addkeystoagent ~A~%"
                    (case state
                      (:yes "true")
                      (:ask "ask")
                      (:confirm "confirm")
                      (t "false")))))
      (format t "forwardagent ~A~%"
              (let* ((cli (getf *options* :forward-agent))
                     (path
                       (and (not (eq cli :no))
                            (cl-pnet-ssh:ssh-config-options-forward-agent-sock-path
                             options)))
                     (value
                       (or cli
                           (cl-pnet-ssh:ssh-config-options-forward-agent
                            options))))
                ;; A path form is what ssh prints when ForwardAgent names a
                ;; socket; yes/no is the flag form.
                (cond (path path)
                      ((eq value :no) "no")
                      (value "yes")
                      (t "no"))))
      (format t "connecttimeout ~A~%"
              (let ((value
                      (cl-pnet-ssh:ssh-config-options-connect-timeout
                       options)))
                (if (integerp value) (format nil "~D" value) "none")))
      (let ((device (or (getf *options* :tunnel-device)
                        (cl-pnet-ssh:ssh-config-options-tunnel-device
                         options))))
        (format t "tunneldevice ~A:~A~%"
                (if device
                    (if (eq (car device) :any) "any" (car device))
                    "any")
                (if (and device (not (eq (cdr device) :any)))
                    (cdr device)
                    "any")))
      (format t "canonicalizepermittedcnames")
      (let ((rules
              (cl-pnet-ssh:ssh-config-options-canonicalize-permitted-cnames
               options)))
        (if (or (null rules)
                (and (null (rest rules))
                     (string-equal (caar rules) "none")))
            (format t " none")
            (dolist (rule rules)
              (format t " ~A:~A" (car rule) (cdr rule)))))
      (format t "~%")
      (let ((persist (cl-pnet-ssh:ssh-config-options-control-persist options)))
        (format t "controlpersist ~A~%"
                (cond ((or (null persist) (eq persist :no)) "no")
                      ((eq persist :yes) "yes")
                      ;; readconf dumps the flag whenever the timeout is
                      ;; zero, so both "yes" and a bare 0 print yes.
                      ((eql persist 0) "yes")
                      (t (format nil "~D" persist)))))
      (format t "escapechar ~A~%"
              (let ((value (cl-pnet-ssh:ssh-config-options-escape-char
                            options)))
                (config-escape-char-string value)))
      (flet ((ip-qos-name (value)
               (cond
                 ((eq value :none) "none")
                 (t (or (car (rassoc value cl-pnet-ssh::+ssh-config-ip-qos-names+
                                     :test #'eql))
                        (string-downcase
                         (format nil "0x~2,'0x" value)))))))
        (format t "ipqos ~A ~A~%"
                (ip-qos-name
                 (cl-pnet-ssh:ssh-config-options-ip-qos-interactive options))
                (ip-qos-name
                 (cl-pnet-ssh:ssh-config-options-ip-qos-bulk options))))
      (format t "rekeylimit ~D ~D~%"
              (or (cl-pnet-ssh:ssh-config-options-rekey-limit options) 0)
              (or (cl-pnet-ssh:ssh-config-options-rekey-interval options) 0))
      (format t "streamlocalbindmask 0~O~%"
              (or (cl-pnet-ssh:ssh-config-options-streamlocal-bind-mask
                   options)
                  #o177))
      (format t "syslogfacility ~A~%"
              (or (cl-pnet-ssh:ssh-config-options-syslog-facility options)
                  "USER"))

      ;; ProxyCommand and ProxyJump share one line: ssh prints the jump
      ;; specification when there is one, otherwise the command, and
      ;; nothing when neither is configured.  readconf's "none" is cleared
      ;; before the dump, so it falls through to the command.
      (let ((jump (cl-pnet-ssh:ssh-config-command-value
                   (or (cl-pnet-ssh:ssh-config-options-proxy-jump options)
                       (getf *options* :jump)))))
        (if jump
            (format t "proxyjump ~A~%" jump)
            (let ((command (cl-pnet-ssh:ssh-config-command-value
                            (or (cl-pnet-ssh:ssh-config-options-proxy-command
                                 options)
                                (getf *options* :proxy-command)))))
              (when command
                (format t "proxycommand ~A~%" command))))))))

;;; ---- Entry point ----

(defun join-command (arguments)
  (format nil "~{~A~^ ~}" arguments))

;;; ---- The target client ----

(defun client-port ()
  "The -p value as a number, or NIL when the command line gave none.

A -p is applied while ssh parses its arguments, before any configuration, so
an unusable value is one bare diagnostic and exit 255, not a readconf error."
  (let ((value (getf *options* :port)))
    (when value
      (let ((port (cl-pnet-ssh:ssh-a2port value)))
        (unless (and port (plusp port))
          (format *error-output* "Bad port '~A'~%" value)
          (finish-output *error-output*)
          (restore-terminal)
          (uiop:quit 255))
        port))))

(defun show-visual-host-key (client)
  "Print the host key randomart when VisualHostKey asks for it."
  (when (and client
             (cl-pnet-ssh:ssh-client-host-key-known client)
             (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
               (and options
                    (cl-pnet-ssh:ssh-config-options-visual-host-key options))))
    (let ((fingerprint
            (cl-pnet-ssh:ssh-client-host-key-fingerprint client))
          (randomart (cl-pnet-ssh:ssh-client-host-key-randomart client)))
      (when (and fingerprint randomart)
        (format *error-output* "Host key fingerprint is ~A~%~A~%"
                fingerprint randomart)
        (finish-output *error-output*)))))

(defun show-banner (client)
  "Print the server's authentication banner, once, as OpenSSH does.

OpenSSH writes it to stderr the moment it arrives; this client shows it as
soon as the connection settles, because the library stores the text instead
of calling back in the middle of authentication."
  (let ((banner (cl-pnet-ssh:ssh-client-banner client)))
    (when banner
      (setf (cl-pnet-ssh:ssh-client-banner client) nil)
      ;; input_userauth_banner prints only at INFO or above, so -q drops it.
      (unless (getf *options* :quiet)
        (format *error-output* "~A" banner)
        (finish-output *error-output*)))))

(defun read-keyboard-interactive-answers (name instruction prompts)
  "Ask each of PROMPTS, a list of (TEXT ECHO-P), and return the answers.

NAME and INSTRUCTION are shown first when the server supplied them, as ssh
does.  NIL means the input ended before every prompt was answered.  The
per-prompt reading is platform specific: READ-PROMPT-LINE lives in POSIX.LISP
or WINDOWS.LISP."
  (when (and name (plusp (length name)))
    (format *error-output* "~A~%" name))
  (when (and instruction (plusp (length instruction)))
    (format *error-output* "~A~%" instruction))
  (finish-output *error-output*)
  (let ((answers '()))
    (dolist (prompt prompts (nreverse answers))
      (let ((answer (read-prompt-line (first prompt)
                                      :echo (second prompt))))
        (unless answer
          (return nil))
        (push answer answers)))))

(defun private-key-permissions-too-open-p (path)
  "Whether PATH is a key file ssh refuses because others may read it.

The rules are OpenSSH's: on Unix only a file owned by the current user is
checked and any group or other permission bit is too much; on Windows the
ACL must admit nobody but its owner, Administrators, SYSTEM or
TrustedInstaller.  The warning goes through SSH-WARN, so -q silences it and
-E sends it to the log, as ssh's error() does."
  #+win32
  (when (handler-case (windows-acl-too-open-p path) (error () t))
    (dolist (line
             (list
              "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
              "@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @"
              "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
              (format nil "Permissions for '~A' are too open."
                      (uiop:native-namestring path))
              "It is required that your private key files are NOT accessible by others."
              "This private key will be ignored."))
      (cl-pnet-ssh:ssh-warn "~A" line))
    t)
  #+(and sbcl (not win32))
  (let ((stat (ignore-errors
               (sb-posix:stat (uiop:native-namestring path)))))
    (when (and stat
               (= (sb-posix:stat-uid stat) (sb-posix:getuid))
               (plusp (logand (sb-posix:stat-mode stat) #o077)))
      (dolist (line
               (list
                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
                "@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @"
                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
                (format nil "Permissions 0~3,'0O for '~A' are too open."
                        (logand (sb-posix:stat-mode stat) #o777)
                        (uiop:native-namestring path))
                "It is required that your private key files are NOT accessible by others."
                "This private key will be ignored."))
        (cl-pnet-ssh:ssh-warn "~A" line))
      t))
  #-(or win32 (and sbcl (not win32)))
  nil)

(defun key-passphrase-prompt (path)
  "Ask for PATH's passphrase the way ssh's load_identity_file does.

ssh reads the answer from the controlling terminal, so a redirected stdin is
not treated as an answer here either; without a terminal there is no prompt
and the key stays unusable.  The text, including its 100-character limit on
the file name, is ssh's own.  The library asks again after a wrong answer
and stops on an empty one."
  (read-tty-line
   (format nil "Enter passphrase for key '~A': "
           (subseq path 0 (min (length path) 100)))))

(defun password-authentication-prompt (client prompt)
  "Ask for a password the way ssh's password method does.

read_passphrase opens the controlling terminal rather than trusting stdin,
turns echo off and writes a carriage return first.  When there is no
terminal at all it answers with an empty string, so the method still sends a
request and NumberOfPasswordPrompts decides when to stop."
  (declare (ignore client))
  (or (read-tty-line prompt) ""))

(defun keyboard-interactive-authentication-prompt
    (client name instruction prompts)
  "Answer the server's keyboard-interactive prompts."
  (declare (ignore client))
  (read-keyboard-interactive-answers name instruction prompts))

(defun host-key-prompt-address (client)
  "The address half of ssh's host-key prompt.

OpenSSH spells a non-default port as [address]:port, both in the
known_hosts name and in the parenthesised address."
  (let ((address (or (cl-pnet-ssh::ssh-client-remote-address client) ""))
        (port (or (cl-pnet-ssh:ssh-client-connect-port client) 22)))
    (if (= port 22) address (format nil "[~A]:~D" address port))))

(defun ask-host-key (client fingerprint host-key)
  "Answer StrictHostKeyChecking=ask on the terminal, as ssh's confirm does.

The prompt is written to /dev/tty rather than stdin, so a redirected stdin
does not swallow it.  An empty answer or \"no\" refuses; \"yes\" or the
fingerprint accepts.  There is no askpass helper here, so a process without
a controlling terminal refuses instead of blocking."
  (let ((tty (probe-file "/dev/tty")))
    (when tty
      (handler-case
          (with-open-file (stream tty :direction :io :if-does-not-exist nil)
            (when stream
              (let ((host (cl-pnet-ssh::ssh-client-host-spec client))
                    (address (host-key-prompt-address client))
                    (type (cl-pnet-ssh:ssh-key-type-name host-key)))
                (loop
                  (format stream "The authenticity of host '~A (~A)' can't be established.~%~A key fingerprint is: ~A~%This key is not known by any other names.~%Are you sure you want to continue connecting (yes/no/[fingerprint])? "
                          host address type fingerprint)
                  (finish-output stream)
                  (let ((answer (read-line stream nil nil)))
                    (cond
                      ((null answer) (return nil))
                      (t
                       (let ((answer (string-trim '(#\Space #\Tab #\Return)
                                                  answer)))
                         (cond
                           ((zerop (length answer)) (return nil))
                           ((string-equal answer "no") (return nil))
                           ((or (string-equal answer "yes")
                                (string= answer fingerprint))
                            (return t))
                           (t
                            (format stream "Please type 'yes', 'no' or the fingerprint: ")
                            (finish-output stream)))))))))))
        (error () nil)))))

(defun report-missing-identity-files (options host)
  "Report an identity file that does not exist, as ssh does.

readconf marks every IdentityFile from a user configuration and from -o as
userprovided, so load_identity_file logs each stat failure at INFO.  A -i
argument is checked earlier, while the options are parsed, and never reaches
this list.  The path is expanded as the loader expands it, because readconf
records the spelling as written.  Identity files load before this client
dials, so the line appears before host-key warnings rather than during
authentication."
  (dolist (path (reverse
                 (cl-pnet-ssh:ssh-config-options-identity-files options)))
    (let ((name (expand-identity-path path options host)))
      (unless (string-equal (namestring path) "none")
        (multiple-value-bind (exists reason)
            (cl-pnet-ssh::ssh-stat-reason name)
          (unless exists
            (cl-pnet-ssh:ssh-warn "no such identity: ~A: ~A"
                                  name reason)))))))

(defun config-open-error-reason (condition)
  "The strerror-like tail of a CONFIG file open failure.

SBCL writes the same reason either after \": \" on one line or after a
trailing \":\" and a newline, depending on the pathname, so take everything
after the last colon and trim the whitespace around it."
  (let* ((text (princ-to-string condition))
         (colon (search ":" text :from-end t)))
    (if colon
        (string-trim '(#\Space #\Tab #\Newline #\Return)
                     (subseq text (1+ colon)))
        text)))

(defun check-config-file ()
  "Leave as ssh does when its explicit -F file cannot be read.

ssh.c calls fatal(\"Can't open user config file %.100s: %.100s\") after
log_init, so LogLevel QUIET keeps the line back but the status is still 255.
-F none asks for no file at all and is never checked."
  (let ((config (getf *options* :config)))
    (when (and (stringp config)
               (not (string-equal config "none")))
      (let ((failure
              (cond
                ;; SBCL merges "" with the default pathname, which would
                ;; make it name the current directory; readconf sees ENOENT.
                ((zerop (length config)) "No such file or directory")
                ;; fopen() does not glob, so a name with wildcard characters
                ;; is simply absent; SBCL would signal while building the
                ;; pathname instead.
                ((wild-pathname-p (pathname config))
                 "No such file or directory")
                (t
                 (handler-case
                     (progn
                       (with-open-file (stream config :direction :input)
                         (declare (ignore stream)))
                       nil)
                   (error (condition) condition))))))
        (when failure
          (unless (getf *options* :quiet)
            (format *error-output* "Can't open user config file ~A: ~A~%"
                    (subseq config 0 (min 100 (length config)))
                    (config-open-error-reason failure))
            (finish-output *error-output*))
          (restore-terminal)
          (uiop:quit 255))))))

(defun start-client (host command command-given-p)
  "Run COMMAND on HOST, letting the library follow ~/.ssh/config for it."
  (check-config-file)
  (cl-pnet-ssh:make-ssh-client-from-config
   host
   :config (getf *options* :config)
   :user (getf *options* :user)
   :port (client-port)
   :private-key (reverse (getf *options* :identity))
   :agent (getf *options* :agent)
   :known-hosts (getf *options* :known-hosts)
   :host-key-policy (getf *options* :policy)
   :host-key-callback #'ask-host-key
   :proxy-jump (getf *options* :jump)
   :proxy-command (getf *options* :proxy-command)
   :mux-fd *mux-proxy-fd*
   ;; Every -o keyword reaches the same resolver the file uses, so facts the
   ;; command line has no dedicated flag for (HostName, ConnectTimeout,
   ;; ServerAliveInterval, ...) work too.
   :options (resolver-option-list)
   :exec-matcher #'match-exec
   ;; ssh.c's own post-configuration checks run before anything dials, so a
   ;; bad ConnectionAttempts or a pointless -f is fatal even for -G.
   :validate-options
   (lambda (options canonical)
     (check-resolved-options options command-given-p)
     (check-forward-agent-socket options)
     ;; ssh attaches to the master before load_public_identity_files(), so an
     ;; -O proxy client never reports identity files it will not load.
     (unless *mux-proxy-fd*
       (report-missing-identity-files options canonical)))
   :on-client (lambda (client)
                (setf *client* client)
                (apply-config-log-level client)
                (when (and (config-fork-after-authentication-p client)
                           (not (getf *options* :background))
                           (not *background-child*))
                  (launch-background-child))
                (check-config-supported client))
   :on-config-error (lambda (condition) (fail-config-error condition))
   :on-forwarded-tcpip #'forwarded-tcpip-target
   :on-forwarded-streamlocal #'forwarded-streamlocal-target
   :password-callback #'password-authentication-prompt
   :kbd-interactive-callback
   #'keyboard-interactive-authentication-prompt
   :passphrase-callback #'key-passphrase-prompt
   :on-open
   (lambda (client)
     (if *mux-daemon*
         ;; A detached master exists only to carry other sessions.  Its
         ;; readiness line tells the launching client that the socket is up.
         (progn
           (mux-start-configured-master client)
           (format t "BURS-MASTER-READY~%")
           (finish-output)
           (mux-detach-standard-streams))
         (progn
           (let ((remote (config-remote-command client)))
             (when remote
               (when command-given-p
                 (fail "Cannot execute command-line and remote command."))
               (setf command (expand-remote-command client remote)
                     command-given-p t)))
           (show-banner client)
           (show-visual-host-key client)
           (cl-pnet-ssh:ssh-client-set-ip-qos
            client (request-tty-p client command-given-p))
           ;; ssh_init_stdio_forwarding() runs before muxserver_listen()
           ;; unless ControlPersist is on: then the master listens first and
           ;; the stdio forward is requested afterwards.  Keeping that order
           ;; keeps "channel N:" diagnostics identical.
           (let* ((stdio (and (getf *options* :stdio-forward)
                              (multiple-value-list
                               (parse-stdio-forward
                                (getf *options* :stdio-forward)))))
                  (deferred (and *mux-create-master*
                                 (not (eq *mux-create-persist* :no)))))
             (when (and stdio (not deferred))
               (start-stdio-forward client (first stdio) (second stdio)
                                    (third stdio))))
           (mux-start-configured-master client)
           (setf *escape-char* nil
                 *escape-pending* nil
                 *escape-line-start* t)
           (when (request-tty-p client command-given-p)
             (setf *escape-char* (escape-char-setting client)
                   *escape-help-function* #'print-escape-help
                   *escape-forwards-function* #'print-escape-forwards
                   *escape-break-function* #'escape-send-break
                   *escape-info-function* #'escape-print-connection-info
                   *escape-rekey-function* #'escape-request-rekey
                   *escape-log-level-function* #'escape-adjust-log-level
                   *escape-suspend-function* #'escape-suspend
                   *escape-background-function*
                   (and (escape-background-available-p)
                        #'escape-background)
                   *escape-disconnect-function*
                   (lambda ()
                     ;; FINISH prints client_loop()'s interactive close line.
                     (finish *status*))
                   *escape-commandline-function*
                   (when (escape-commandline-enabled-p client)
                     #'escape-commandline)))
           (start-forwards client)
           (when (and (config-local-command client)
                      (permit-local-command-p client))
             (run-local-command client))
           ;; ssh_session2() has reached client_loop() from here: a later
           ;; failure still reports the byte summary at -v.
           (setf *session-loop-started* t
                 *session-loop-start* (get-internal-real-time))
           (let ((background (or (getf *options* :background)
                                 (config-fork-after-authentication-p client)
                                 *background-child*)))
             (when background
               (background-ready)))
           (cond
             ((and (getf *options* :stdio-forward)
                   *mux-create-master*
                   (not (eq *mux-create-persist* :no)))
              ;; ControlPersist deferred the stdio forward until after the
              ;; master's listener and control channel were in place.
              (multiple-value-bind (target port streamlocal)
                  (parse-stdio-forward (getf *options* :stdio-forward))
                (start-stdio-forward client target port streamlocal)))
             ((getf *options* :stdio-forward) nil)
             ((or (getf *options* :no-command) (session-type-none-p client)) nil)
             (t
              (start-session client command command-given-p))))))
   :on-error (lambda (client condition)
               (show-banner client)
               ;; ssh reports a refused authentication as "user@host:
               ;; Permission denied (methods)." with the server's own list,
               ;; and only says something else when it never got that far.
               ;; A host key refusal is fatal("Host key verification failed.")
               ;; in ssh.  All of these are log messages, so LogLevel QUIET
               ;; (-q) silences them and only the exit status remains.
               (unless (getf *options* :quiet)
                 (cond
                   ((typep condition 'cl-pnet-ssh:ssh-host-key-error)
                    (log-notice "Host key verification failed.~%"))
                   ((typep condition 'cl-pnet-ssh:ssh-connection-error)
                    ;; ssh reports these through error(), with the configured
                    ;; host name rather than the address it dialled.
                    (let ((kind (cl-pnet-ssh:ssh-connection-error-kind
                                 condition))
                          (host (cl-pnet-ssh:ssh-connection-error-host
                                 condition))
                          (reason (or (cl-pnet-ssh:ssh-connection-error-reason
                                       condition)
                                      (princ-to-string condition))))
                      (case kind
                        (:closed
                         ;; sshpkt_vfatal's logdie() names the peer, or
                         ;; "UNKNOWN port 65535" for a ProxyCommand pipe.
                         (log-notice "~A~%" reason))
                        (:proxy-expand
                         ;; percent_expand's error_f() and fatal_f() lines;
                         ;; the library keeps both in the detail.
                         (log-notice "~A~%"
                                     (cl-pnet-ssh:ssh-error-detail
                                      condition)))
                        (:negotiate
                         ;; ssh's sshpkt_vfatal names the address and port it
                         ;; dialled and the peer's proposal, with no prefix.
                         (log-notice
                          "Unable to negotiate with ~A port ~D: ~A. Their offer: ~{~A~^,~}~%"
                          host
                          (cl-pnet-ssh:ssh-connection-error-port condition)
                          reason
                          (cl-pnet-ssh:ssh-connection-error-peer-offer
                           condition)))
                        (:resolve
                         (log-notice
                          "burs: Could not resolve hostname ~A: ~A~%"
                          host reason))
                        (:connect
                         (log-notice
                          "burs: connect to host ~A port ~D: ~A~%"
                          host
                          (cl-pnet-ssh:ssh-connection-error-port condition)
                          reason))
                        (t
                         (log-notice "burs: ~A~%" condition)))))
                   (t
                    (let ((offered
                            (and (typep condition
                                        'cl-pnet-ssh:ssh-authentication-error)
                                 (cl-pnet-ssh:ssh-client-auth-offered-methods
                                  client))))
                      (if offered
                          (log-notice
                           "~A@~A: Permission denied (~{~A~^,~}).~%"
                           (cl-pnet-ssh:ssh-client-user client)
                           (cl-pnet-ssh:ssh-client-host client)
                           offered)
                          (log-notice "burs: ~A~%" condition))))))
               (finish 255))
   :on-close (lambda (client reason)
               (declare (ignore client reason))
               (finish *status*))))

(defun background-child-arguments ()
  "The current arguments with the marker flag before the destination."
  (cons "--background-child" (uiop:command-line-arguments)))

(defun launch-background-child ()
  "Re-exec this client in the background and wait for authentication.

A fresh process avoids forking the Lisp runtime.  The child writes
BURS-AUTH-OK on stdout once it is authenticated, then detaches its stdio."
  (let ((process
          (uiop:launch-program
           (cons (or (uiop:argv0) "/proc/self/exe")
                 (background-child-arguments))
           :input nil
           :output :stream
           ;; The child's own fatal messages are the user's only explanation
           ;; when it never reaches authentication, so let them through.
           :error-output *error-output*)))
    (let* ((stream (uiop:process-info-output process))
           (line (read-line stream nil nil)))
      (if (equal line "BURS-AUTH-OK")
          (uiop:quit 0)
          (progn
            (ignore-errors (uiop:wait-process process))
            (uiop:quit 255))))))

(defun resolve-multiplex-options (host)
  "Resolve HOST's configuration for -O and leave when it names no socket.

ssh.c checks muxclient_command against options.control_path after the
configuration is read, so a mux command with no ControlPath is a fatal at
the log level: -q keeps it back but the status is still 255.  The resolved
options are returned so the attach path can reuse them."
  (let ((options (mux-config-options host)))
    (unless (mux-control-path-from-options options)
      (cl-pnet-ssh:ssh-warn "No ControlPath specified for \"-O\" command")
      (restore-terminal)
      (uiop:quit 255))
    options))

(defun main ()
  "Entry point for the BURS program."
  (handler-case
      (let ((arguments (uiop:command-line-arguments)))
        ;; `burs keygen` is a second program on the same binary: it has its
        ;; own options and never connects anywhere.
        (when (and arguments (string= (first arguments) "keygen"))
          (uiop:quit (keygen-main (rest arguments))))
        ;; ssh validates its own flags, and answers -Q and -V, while it is
        ;; still reading its arguments: a later option that is syntactically
        ;; incomplete never gets a look.  The replay therefore runs before
        ;; CLINGON's parse and takes the destination itself, which CLINGON
        ;; cannot express.
        (setf *burs-command* (make-burs-command))
        (run-getopt-phase)
        (multiple-value-bind (destination command)
            (parse-arguments arguments)
          (declare (ignore destination))
          (apply-command-line-options)
          (publish-getopt-state)
          (setf *background-child*
                (and (getf *options* :background-child) t))
          ;; -G and -Z leave before anything is dialled, and ssh forks only
          ;; after the connection is authenticated, so neither has a child.
          (when (and (getf *options* :background)
                     (not *background-child*)
                     (not (getf *options* :print-config))
                     (not (getf *options* :dump-public-keys)))
            (launch-background-child))
          (check-supported-options)
          (start-logging)
          (let ((host *getopt-host*))
            ;; ssh's -N/-s/-W and command-line SessionType rules run while
            ;; the arguments are read, before any configuration file or
            ;; connection, so they come first here too.
            (check-session-type-arguments (and command t))
            ;; ssh validates the command-line host and user before it reads
            ;; any configuration, so even -G fails on a bad name.
            (check-command-line-identity host)
            ;; -G wins when both are given: ssh dumps the configuration
            ;; before it reaches the public key dump.
            (when (getf *options* :print-config)
              (print-config host (and command t)))
            ;; mux-config-options reads the configuration before the client
            ;; exists, so an unreadable -F file must be reported here first.
            (check-config-file)
            (setf *mux-daemon*
                  (and (getf *options* :control-master-daemon) t))
            (when *mux-daemon*
              (mux-detach-process)
              ;; A daemon has no session of its own; it only listens.
              (setf (getf *options* :control-master) t))
            ;; ssh checks -O against the configured ControlPath, and attaches
            ;; to a running master, before it loads identities or dumps public
            ;; keys, so `-O check -Z' with no master fails without a dump.
            (let ((mux-options
                    (and *getopt-mux-command*
                         (resolve-multiplex-options host))))
              (mux-prepare host (and command (join-command command))
                           (and command t)
                           mux-options)
              (when (getf *options* :dump-public-keys)
                (dump-public-keys host (and command t))))
            (handler-case
                (start-client host (and command (join-command command))
                              (and command t))
              (cl-pnet-ssh:ssh-config-error (condition)
                ;; An unreadable -F file and similar problems are command
                ;; line errors, which ssh reports with status 255.
                (fail-config-error condition)))
            (cl-pnet:event-loop-run)
            (finish *status*))))
    (stream-error (condition)
      ;; A write to stdout or stderr that the kernel refused is a closed
      ;; pipeline, and ssh leaves that as SIGPIPE's status without a
      ;; message.  Any other stream error keeps its diagnostic.
      (let ((stream (stream-error-stream condition)))
        (if (or (eq stream *standard-output*)
                (eq stream *error-output*))
            (quit-now 141)
            (progn
              (ignore-errors
               (format *error-output* "burs: ~A~%" condition))
              (quit-now 1)))))
    #+sbcl
    (sb-sys:interactive-interrupt ()
      ;; Ctrl-C is not an error: leave the terminal on a fresh line and exit
      ;; with the status a shell reports for SIGINT, instead of dropping into
      ;; SBCL's debugger.
      (format *error-output* "~&")
      (finish-output *error-output*)
      (finish 130))
    (cl-pnet-ssh:ssh-config-error (condition)
      ;; A bad configuration value can surface outside resolution, when -G
      ;; prints the algorithm lists it has to validate.  ssh treats every
      ;; configuration error as fatal with status 255, not 1.
      (fail-config-error condition))
    (error (condition)
      (when (uiop:getenv "BURS_DEBUG")
        (sb-debug:print-backtrace :count 40 :stream *error-output*))
      (format *error-output* "burs: ~A~%" condition)
      (uiop:quit 1))))
