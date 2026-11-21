(in-package #:burs)

;;;; A small SSH client command line over cl-pnet-ssh.  It runs one command
;;;; on the remote host and streams its output and stdin, without blocking the
;;;; event loop: stdin is watched with CL-PNET:FD-WATCH, never read in a loop.
;;;;
;;;; The option surface follows ssh(1): the same short flags, clustered where
;;;; they are flags and with an attached value where they take one.  Features
;;;; this client cannot honour (agent and X11 forwarding, compression, remote
;;;; forwarding, control sockets, TUN devices) are refused with a diagnostic
;;;; instead of being silently ignored.

;;; ---- Command line ----

(defun print-version ()
  (format t "burs ~A~%" +burs-version+)
  (finish-output))

(defun fail (format-string &rest arguments)
  (format *error-output* "burs: ~?~%" format-string arguments)
  (finish-output *error-output*)
  (restore-terminal)
  (uiop:quit 255))

(defun unsupported (option &optional (detail "not implemented by this client"))
  (fail "~A is not supported: ~A" option detail))

(defun split-destination (destination)
  "DESTINATION as (VALUES HOST USER), splitting USER@HOST at the first @."
  (let ((at (position #\@ destination)))
    (if at
        (values (subseq destination (1+ at)) (subseq destination 0 at))
        (values destination nil))))

;;; ssh(1)'s option surface, built once as a CLINGON command.  CLINGON parses
;;; the clustered and attached forms (-vvT, -p2222, -oPort=22), writes the
;;; help text, and reports unknown options and missing values.  The parser
;;; here only finds the destination first, because ssh stops looking for
;;; options there and CLINGON does not.

(defvar *burs-command* nil
  "The command parsed most recently, so MAIN can print its usage.")

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
   (burs-flag :print-config "Print the effective configuration and exit"
              :short #\G :long "print-config")
   (burs-flag :gateway-ports "Allow remote hosts to use forwarded ports"
              :short #\g :long "gateway-ports")
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
    ;; keep the --version/-V pair defined above.
    (setf (clingon:command-options command)
          (remove clingon:*default-version-flag*
                  (clingon:command-options command)
                  :test #'eq))
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
stops looking for options at the destination, so the remote command may
contain things like `uname -a' that would otherwise look like flags.
CLINGON keeps parsing options among free arguments, so the destination and
everything after it are handed to it behind `--'.

The scan also lower-cases a long option name and expands the
--identity-file alias, which CLINGON would otherwise take literally."
  (let ((option-arguments '())
        (remaining arguments))
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
               (take-value)))))
      (loop
        for argument = (pop remaining)
        do (cond
             ((null argument)
              (return (values (nreverse option-arguments) nil nil)))
             ((string= argument "--")
              (return (values (nreverse option-arguments)
                              (pop remaining)
                              remaining)))
             ((and (> (length argument) 2)
                   (char= (char argument 0) #\-)
                   (char= (char argument 1) #\-))
              (scan-long argument))
             ((and (> (length argument) 1)
                   (char= (char argument 0) #\-))
              (scan-short argument))
             (t
              (return (values (nreverse option-arguments)
                              argument
                              remaining))))))))

(defun parsed-list (command key)
  "The values of KEY in command-line order, or NIL."
  (reverse (clingon:getopt command key)))

(defun apply-parsed-options (command)
  "Copy COMMAND's values into *OPTIONS*.

Every key is written, even when it is NIL, so a second parse cannot inherit
a value from the first.  The list options are stored in reverse, which is
the order the old push-based parser kept them in."
  (let ((getopt (lambda (key) (clingon:getopt command key))))
    (labels ((value (key) (funcall getopt key))
             (flag (key) (funcall getopt key)))
      (setf (getf *options* :port) (value :port)
            (getf *options* :user) (value :user)
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
            (cond ((flag :request-tty-no) :no)
                  ((flag :request-tty-force) :force)
                  (t (value :request-tty)))
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
            (getf *options* :background) (flag :background)
            (getf *options* :control-master) (flag :control-master)
            (getf *options* :control-path) (value :control-path)
            (getf *options* :control-command) (value :control-command)
            (getf *options* :pkcs11) (value :pkcs11)
            (getf *options* :bind-interface) (value :bind-interface)
            (getf *options* :bind-address) (value :bind-address)
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
            (apply-parsed-options parsed)
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

(defun check-algorithm-list (option value supported)
  "Reject an algorithm choice this build cannot offer.

ssh's +/-^ prefixes and glob patterns are applied exactly as in ssh_config, so
a name this build lacks is an error instead of a silently widened offer."
  (handler-case
      (cl-pnet-ssh:ssh-resolve-algorithm-list (split-list value) supported option)
    (cl-pnet-ssh:ssh-config-error (condition)
      (fail "~A" condition))))

(defun check-supported-options ()
  "Fail before connecting on a flag whose feature is not in this build."
  (when (getf *options* :pkcs11)
    (unsupported "-I" "PKCS#11 keys are not implemented"))
  (when (getf *options* :bind-interface)
    (unsupported "-B" "binding the source interface is not implemented"))
  (when (getf *options* :bind-address)
    (unsupported "-b" "binding the source address is not implemented"))
  (when (getf *options* :background)
    (unsupported "-f" "backgrounding is not implemented"))
  (when (getf *options* :control-master)
    (unsupported "-M" "connection sharing is not implemented"))
  (when (getf *options* :control-path)
    (unsupported "-S" "connection sharing is not implemented"))
  (when (getf *options* :control-command)
    (unsupported "-O" "connection sharing is not implemented"))
  (when (getf *options* :tunnel)
    (unsupported "-w" "TUN/TAP forwarding is not implemented"))
  (when (getf *options* :gssapi-auth)
    (unsupported "-K" "GSSAPI authentication is not implemented"))
  (when (eq (getf *options* :x11-forward) :yes)
    (unsupported "-X" "X11 forwarding is not implemented"))
  (when (eq (getf *options* :x11-forward) :trust)
    (unsupported "-Y" "X11 forwarding is not implemented"))
  (when (eq (getf *options* :forward-agent) t)
    (unsupported "-A" "agent forwarding is not implemented"))
  (when (getf *options* :compression)
    (unsupported "-C" "only uncompressed streams are implemented"))
  (when (getf *options* :ciphers)
    (check-algorithm-list "-c" (getf *options* :ciphers)
                          cl-pnet-ssh:+ssh-ciphers+))
  (when (getf *options* :macs)
    (check-algorithm-list "-m" (getf *options* :macs)
                          cl-pnet-ssh:+ssh-macs+))
  (when (getf *options* :kex-algorithms)
    (check-algorithm-list "KexAlgorithms" (getf *options* :kex-algorithms)
                          cl-pnet-ssh:+ssh-kex-real-algorithms+))
  (when (getf *options* :address-family)
    (unless (member (getf *options* :address-family) '("inet" "any")
                    :test #'string-equal)
      (unsupported "-6" "this build resolves IPv4 addresses only")))
  (when (and (getf *options* :stdio-forward)
             (getf *options* :subsystem))
    (fail "-W and -s cannot be combined"))
  ;; Parse the forwarding specifications now, so a typo is a command-line
  ;; error rather than a surprise after authentication.
  (setf (getf *options* :local-forward)
        (mapcar #'parse-local-forward
                (reverse (getf *options* :local-forward))))
  (setf (getf *options* :remote-forward)
        (mapcar #'parse-config-remote-forward
                (reverse (getf *options* :remote-forward))))
  (setf (getf *options* :dynamic-forward)
        (mapcar #'parse-dynamic-forward
                (reverse (getf *options* :dynamic-forward))))
  (values))

(defun check-config-supported (client)
  "Fail when CLIENT's resolved config asks for a feature this build lacks.

The command line is checked before connecting, but ForwardAgent,
Compression and X11 forwarding can arrive from ~/.ssh/config too.  Dropping
them silently would leave the user believing they are on, so they are
refused with the same message the matching flag gets.  An explicit -a or -x
still disables the feature and therefore silences the refusal."
  (let ((options (and client (cl-pnet-ssh:ssh-client-config-options client))))
    (when options
      (when (and (cl-pnet-ssh:ssh-config-options-forward-agent options)
                 (not (eq (getf *options* :forward-agent) :no)))
        (unsupported "ForwardAgent" "agent forwarding is not implemented"))
      (when (cl-pnet-ssh:ssh-config-options-compression options)
        (unsupported "Compression" "only uncompressed streams are implemented"))
      (when (and (or (cl-pnet-ssh:ssh-config-options-forward-x11 options)
                     (cl-pnet-ssh:ssh-config-options-forward-x11-trusted
                      options))
                 (not (eq (getf *options* :x11-forward) :no)))
        (unsupported "ForwardX11" "X11 forwarding is not implemented"))
      ;; Every one of these is a real request from the configuration.  This
      ;; build cannot honour it, and pretending otherwise would leave the
      ;; user with a weaker or different connection than they asked for.
      (when (cl-pnet-ssh:ssh-config-options-certificate-files options)
        (unsupported "CertificateFile"
                     "only the KEY-cert.pub beside an IdentityFile is used"))
      (when (cl-pnet-ssh:ssh-config-options-bind-address options)
        (unsupported "BindAddress"
                     "binding the source address is not implemented"))
      (when (cl-pnet-ssh:ssh-config-options-rekey-limit options)
        (unsupported "RekeyLimit" "rekeying is not implemented"))
      (when (eq (cl-pnet-ssh:ssh-config-options-pubkey-authentication options)
                :no)
        (unsupported "PubkeyAuthentication no"
                     "public-key authentication is the only method implemented"))
      (let ((methods
              (cl-pnet-ssh:ssh-config-options-preferred-authentications
               options)))
        (when (and methods
                   (not (member "publickey" methods :test #'string-equal)))
          (unsupported
           "PreferredAuthentications"
           (format nil "~{~A~^,~} excludes publickey, the only method implemented"
                   methods))))
      (when (eq (cl-pnet-ssh:ssh-config-options-address-family options)
                :inet6)
        (unsupported "AddressFamily inet6"
                     "this build resolves IPv4 addresses only")))))

;;; ---- ~/.ssh/config and -o ----

(defun match-exec (command on-result on-error)
  "Answer a Match exec condition.

The config is resolved before the event loop starts, so running the shell
test here costs the process nothing that was concurrent anyway.  The library
itself never blocks: this matcher is what a caller supplies."
  (handler-case
      (funcall on-result
               (eql 0
                    (nth-value 2
                               (uiop:run-program (list "/bin/sh" "-c" command)
                                                 :ignore-error-status t
                                                 :output nil
                                                 :error-output nil))))
    (error (condition) (funcall on-error condition))))

(defun true-value-p (value)
  (member (string-downcase value) '("yes" "true" "on") :test #'string=))

(defun command-line-option (name value)
  "Apply one -o NAME=VALUE to the parsed options."
  (cond
    ((string-equal name "Port") (setf (getf *options* :port) value))
    ((string-equal name "User") (setf (getf *options* :user) value))
    ((string-equal name "IdentityFile")
     (push value (getf *options* :identity)))
    ((string-equal name "UserKnownHostsFile")
     (setf (getf *options* :known-hosts) value))
    ((string-equal name "IdentityAgent") (setf (getf *options* :agent) value))
    ((string-equal name "StrictHostKeyChecking")
     (setf (getf *options* :policy)
           (cond ((member (string-downcase value) '("no" "off") :test #'string=)
                  :insecure)
                 ((string-equal value "accept-new") :accept-new)
                 (t :strict))))
    ((string-equal name "ProxyJump") (setf (getf *options* :jump) value))
    ((string-equal name "ProxyCommand")
     (setf (getf *options* :proxy-command) value))
    ((string-equal name "AddressFamily")
     (setf (getf *options* :address-family) (string-downcase value)))
    ((string-equal name "Ciphers") (setf (getf *options* :ciphers) value))
    ((string-equal name "MACs") (setf (getf *options* :macs) value))
    ((string-equal name "KexAlgorithms")
     (setf (getf *options* :kex-algorithms) value))
    ((string-equal name "Compression")
     (setf (getf *options* :compression)
           (not (member (string-downcase value) '("no" "off") :test #'string=))))
    ((string-equal name "LogLevel")
     (let ((level (string-upcase value)))
       (cond ((member level '("QUIET" "FATAL" "ERROR") :test #'string=)
              (setf (getf *options* :quiet) t))
             ((member level '("VERBOSE" "DEBUG" "DEBUG1" "DEBUG2" "DEBUG3")
                      :test #'string=)
              (setf (getf *options* :verbose) 1)))))
    ((string-equal name "GatewayPorts")
     (setf (getf *options* :gateway-ports) (true-value-p value)))
    ((string-equal name "ForwardAgent")
     (when (true-value-p value)
       (setf (getf *options* :forward-agent) t)))
    ((string-equal name "RequestTTY")
     (setf (getf *options* :request-tty) (string-downcase value)))
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
        (progn
          (if (plusp (getf *options* :verbose 0))
              (format *log-stream* "debug1: ~?~%" format-string arguments)
              (format *log-stream* "~?~%" format-string arguments))
          (finish-output *log-stream*))
      (error ()
        (setf *log-stream* nil
              cl-pnet-ssh:*ssh-log-function* nil)))))

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
                        cl-pnet-ssh:*ssh-log-function* nil))))))))

;;; ---- -Q: algorithm queries ----

(defun query-answer (what)
  (let ((name (string-downcase what)))
    (cond
      ((member name '("cipher" "cipher-auth") :test #'string=)
       cl-pnet-ssh:+ssh-ciphers+)
      ((string= name "mac") cl-pnet-ssh:+ssh-macs+)
      ((string= name "kex")
       (remove-if (lambda (algorithm)
                    (or (search "ext-info" algorithm)
                        (search "kex-strict" algorithm)))
                  cl-pnet-ssh:+ssh-kex-algorithms+))
      ((member name '("key" "key-plain" "key-cert") :test #'string=)
       cl-pnet-ssh:+ssh-host-key-algorithms+)
      ((string= name "protocol-version") '("2"))
      ((string= name "help")
       '("cipher" "cipher-auth" "mac" "kex" "key" "key-cert"
         "key-plain" "protocol-version"))
      (t (fail "unknown query option ~A (try -Q help)" what)))))

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
  listener
  listener-fd
  listener-watcher)

(defstruct (forward-tunnel (:constructor %make-forward-tunnel))
  forward
  connection
  channel
  (to-channel (make-array 0 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer 0))
  (to-connection (make-array 0 :element-type '(unsigned-byte 8)
                               :adjustable t :fill-pointer 0))
  (local-eof nil)
  (eof-sent nil))

(defstruct (dynamic-forward (:constructor %make-dynamic-forward))
  bind-address
  bind-port
  listener)

(defstruct (socks-session (:constructor %make-socks-session))
  client
  connection
  (state (cl-pnet-socks:make-socks5-server-state)))

(defun split-forward-fields (text)
  "TEXT split at colons, keeping a bracketed IPv6 literal whole."
  (let ((fields '())
        (current (make-string-output-stream)))
    (loop with index = 0
          while (< index (length text))
          for character = (char text index)
          do (cond
               ((char= character #\[)
                (let ((close (position #\] text :start index)))
                  (unless close
                    (fail "unterminated '[' in ~A" text))
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
  (multiple-value-bind (port end) (parse-integer text :junk-allowed t)
    (unless (and port (= end (length text)) (<= 0 port 65535))
      (fail "invalid port ~S in forwarding specification ~A" text spec))
    port))

(defun path-field-p (text)
  "Whether TEXT names a Unix socket, as OpenSSH decides: it contains \"/\"."
  (find #\/ text))

(defun make-parsed-forward (spec remote-p &key bind-address bind-port bind-path
                                            host port target-path)
  "A FORWARD for a parsed SPEC, or FAIL when it names no usable endpoint.

OpenSSH's rule is used: a forwarding specification needs a target port or
socket path, and a listener that is a socket path or a port.  Only a remote
forward may ask for port 0, which leaves the choice to the server."
  (unless (or target-path (and port (plusp port)))
    (fail "~A: forwarding needs a target port or socket path" spec))
  (unless (or bind-path
              (and bind-port
                   (if remote-p (<= 0 bind-port) (plusp bind-port))))
    (fail "~A: forwarding needs a listener port or socket path" spec))
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
       (fail "invalid forwarding specification ~A" spec)))))

(defun parse-local-forward (spec)
  "SPEC as a FORWARD for ssh's -L forms, including Unix-socket paths."
  (parse-forward-spec spec nil))

(defun parse-remote-forward (spec)
  "SPEC as a FORWARD for ssh's -R forms, including Unix-socket paths.

A remote forward names the listener on the server (BIND-ADDRESS/BIND-PORT
or BIND-PATH) and the target this client dials (HOST/PORT or TARGET-PATH)."
  (parse-forward-spec spec t))

(defun parse-dynamic-forward (spec)
  "SPEC as a DYNAMIC-FORWARD for [bind_address:]port."
  (multiple-value-bind (first second) (split-host-port spec)
    (if second
        (%make-dynamic-forward :bind-address (if (plusp (length first)) first nil)
                               :bind-port (forwarding-port second spec))
        (%make-dynamic-forward :bind-port (forwarding-port first spec)))))

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
      (fail "~A must be host:port" spec))
    (values host (forwarding-port port spec))))

(defun parse-config-forward (spec remote-p)
  "SPEC as a FORWARD for ssh_config's two-word LocalForward/RemoteForward.

The listener may be [bind_address:]port or a socket path; the target may be
host:hostport or a socket path.  A one-word line is taken as the command
line's colon-separated form."
  (let ((words (uiop:split-string spec :separator '(#\Space #\Tab))))
    (if (/= 2 (length words))
        (parse-forward-spec spec remote-p)
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
                                 :target-path target-path))))))

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
   (lambda (writer) (cl-pnet-ssh::ssh-write-text writer command))))

(defun send-shell-request (channel)
  "Start the peer's login shell on CHANNEL, the ssh(1) session default."
  (send-channel-request
   channel "shell" t (lambda (writer) (declare (ignore writer)))))

(defun send-subsystem-request (channel subsystem)
  (send-channel-request
   channel "subsystem" t
   (lambda (writer) (cl-pnet-ssh::ssh-write-text writer subsystem))))

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
              (send-pty-request channel)
              (start-winch channel)
              (cond
                ((subsystem-request-p)
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

(defun quit-now (status)
  "Leave with STATUS without flushing streams again.

The normal path has already flushed both streams.  On the broken-pipe path
the kernel has rejected stdout, and SB-EXT:EXIT would try to flush it once
more and hang instead of exiting; :ABORT T skips that and the exit hooks."
  (restore-terminal)
  #+sbcl (sb-ext:exit :code status :abort t)
  #-sbcl (uiop:quit status))

(defun finish (status)
  ;; Closing the client below reports its open channels closed, whose
  ;; callbacks call FINISH again; only the outermost call may quit, or the
  ;; connection (and a ProxyCommand helper) would be left half torn down.
  (unless *finishing*
    (setf *finishing* t)
    (restore-terminal)
    (stop-pty-timer)
    (stop-winch)
    (stop-stdin)
    (stop-forwards)
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
  (declare (ignore channel))
  (format *error-output* "burs: ~A~%" condition)
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
  (unless (subsystem-request-p)
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
        ((subsystem-request-p)
         (cl-pnet-ssh:ssh-channel-subsystem *channel* command)
         (start-input *channel*))
        (command-given-p
         (cl-pnet-ssh:ssh-channel-exec *channel* command)
         (start-input *channel*))
        (t
         (start-shell-session *channel*)))))

;;; ---- -W: stream stdin and stdout over one channel ----

(defun start-stdio-forward (client host port)
  (setf *status* 0
        *channel*
        (cl-pnet-ssh:ssh-open-direct-tcpip
         client host port
         :on-data (lambda (channel data kind)
                    (declare (ignore channel))
                    (write-octets (ecase kind (:stdout *standard-output*)
                                         (:stderr *error-output*))
                                  data))
         :on-close (lambda (channel status)
                     (declare (ignore channel status))
                     (finish *status*))
         :on-error (lambda (channel condition)
                     (declare (ignore channel))
                     (format *error-output* "burs: ~A~%" condition)
                     (finish 255))))
  (log-line "stdio forward to ~A:~D" host port)
  (start-input *channel*))

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

(defun open-forward-channel (client tunnel &key on-open on-error)
  "Open a direct channel for TUNNEL and start bridging bytes.

ON-OPEN runs once the peer confirms the channel.  ON-ERROR, when given,
replaces the usual diagnostic for a failed open; either way the tunnel is
closed afterwards."
  (let ((forward (forward-tunnel-forward tunnel)))
    (flet ((failed (condition)
             (if on-error
                 (funcall on-error condition)
                 (unless (getf *options* :quiet)
                   (format *error-output*
                           "burs: forward to ~A failed: ~A~%"
                           (forward-target-name forward)
                           condition)))
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
                               (declare (ignore channel))
                               (failed condition)))))
            (setf (forward-tunnel-channel tunnel) channel)
            (forward-flush tunnel)
            (forward-flush-to-connection tunnel))
        (error (condition) (failed condition))))))

(defun forward-accept (client forward connection)
  (let ((tunnel (%make-forward-tunnel :forward forward
                                      :connection connection)))
    (setf (gethash connection *tunnels*) tunnel)
    (open-forward-channel client tunnel)))

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
  "Adopt CLIENT's LogLevel when the command line did not set one."
  (let ((level (config-log-level client)))
    (when (and level
               (zerop (getf *options* :verbose 0))
               (not (getf *options* :quiet)))
      (multiple-value-bind (quiet verbose) (log-level-settings level)
        (setf (getf *options* :quiet) quiet
              (getf *options* :verbose) verbose)
        (start-logging)))))

(defun config-local-command (client)
  "CLIENT's LocalCommand as written, or NIL."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (cl-pnet-ssh:ssh-config-options-local-command options))))

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
                                 (uiop:run-program
                                  (list shell "-c" command)
                                  :output *standard-output*
                                  :error-output *error-output*
                                  :ignore-error-status t))))
          (unless (eql status 0)
            (log-line "local command exited with status ~A" status)))
      (error (condition)
        (log-line "local command failed: ~A" condition)))))

(defun config-remote-command (client)
  "CLIENT's RemoteCommand as written, or NIL."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (cl-pnet-ssh:ssh-config-options-remote-command options))))

(defun expand-remote-command (client value)
  "VALUE with the ssh % tokens RemoteCommand understands."
  (let ((host (cl-pnet-ssh:ssh-client-connect-host client))
        (name (cl-pnet-ssh:ssh-client-host client))
        (port (or (cl-pnet-ssh:ssh-client-connect-port client) 22))
        (user (cl-pnet-ssh:ssh-client-user client))
        (uid (or (uiop:getenv "UID") ""))
        (local (or (uiop:getenv "HOSTNAME") "")))
    (with-output-to-string (out)
      (loop with length = (length value)
            for index from 0 below length
            for character = (char value index)
            do (if (and (char= character #\%)
                        (< (1+ index) length))
                   (let ((token (char value (1+ index))))
                     (case token
                       (#\% (write-char #\% out) (incf index))
                       (#\h (princ host out) (incf index))
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
                       (t (write-char character out))))
                   (write-char character out))))))

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
               (and (or (string= (car entry) "*")
                        (string= (car entry) host))
                    (or (eq (cdr entry) :any)
                        (eql (cdr entry) port))))
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
         (listener
           (handler-case
               (cl-pnet-sockets:listen-unix path :unlink unlink :mask mask)
             (error () nil))))
    (unless listener
      (unless (getf *options* :quiet)
        (format *error-output*
                "burs: cannot listen on ~A for -L~%" path))
      (if (exit-on-forward-failure-p client)
          (finish 255)
          (return-from start-local-streamlocal-forward nil)))
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
                                       (declare (ignore channel condition))
                                       (client-streamlocal-close bridge)))))
                              (setf (client-streamlocal-channel bridge) channel)
                              (client-streamlocal-connected bridge))
                          (error ()
                            (client-streamlocal-close bridge))))))))
    (push forward *forwards*)
    (log-line "local streamlocal forward ~A to ~A"
              path (forward-target-name forward))
    forward))

(defun start-local-forward (client forward)
  (when (forward-bind-path forward)
    (return-from start-local-forward
      (start-local-streamlocal-forward client forward)))
  (let* ((options (cl-pnet-ssh:ssh-client-config-options client))
         (address (or (forward-bind-address forward)
                      (if (gateway-ports-p options)
                          "0.0.0.0"
                          "127.0.0.1")))
         (listener
           (cl-pnet:make-tcp-listener
            address (forward-bind-port forward)
            :read-cb #'forward-connection-data
            :on-accept (lambda (connection)
                         (forward-accept client forward connection))
            :on-error (lambda (status)
                        (log-line "forward listen error ~A" status)))))
    (unless listener
      (format *error-output*
              "burs: cannot listen on ~A:~D for -L~%"
              address (forward-bind-port forward))
      (if (exit-on-forward-failure-p client)
          (finish 255)
          (return-from start-local-forward nil)))
    (setf (forward-listener forward) listener)
    (push forward *forwards*)
    (let ((port (cl-pnet:listener-port listener)))
      (log-line "local forward ~A:~D to ~A:~D"
                address port (forward-host forward) (forward-port forward))
      (when (and (zerop (forward-bind-port forward))
                 (not (getf *options* :quiet)))
        (format *error-output* "Allocated port ~D for local forward~%" port)))
    forward))

;;; ---- -D: dynamic SOCKS forwarding ----
;;;
;;; OpenSSH's -D is a local SOCKS5 proxy whose CONNECT requests become
;;; direct-tcpip channels.  The handshake runs before the tunnel exists, so a
;;; session keeps its bytes until the greeting and request are complete; after
;;; that the ordinary -L tunnel machinery carries the stream.

(defun socks-reply (reply)
  "A SOCKS5 reply with code REPLY and an all-zero bound address."
  (cl-pnet-socks:make-socks5-reply reply))

(defun socks-write-then-close (connection data)
  "Send DATA and close CONNECTION once the kernel has it."
  (handler-case
      (cl-pnet:send-data
       connection data
       :on-write (lambda (count)
                   (declare (ignore count))
                   (ignore-errors (cl-pnet:close-connection connection)))
       :on-error (lambda (status)
                   (declare (ignore status))
                   (ignore-errors (cl-pnet:close-connection connection))))
    (error () (ignore-errors (cl-pnet:close-connection connection)))))

(defun socks-abandon (session)
  "Forget SESSION and close its connection without a reply."
  (let ((connection (socks-session-connection session)))
    (remhash connection *socks-sessions*)
    (ignore-errors (cl-pnet:close-connection connection))))

(defun socks-fail (session reply)
  "Answer SESSION with SOCKS5 reply REPLY, then close it."
  (let ((connection (socks-session-connection session)))
    (remhash connection *socks-sessions*)
    (socks-write-then-close connection (socks-reply reply))))

(defun socks-send (session data)
  "Send DATA to SESSION's client, abandoning the session on a write error."
  (let ((connection (socks-session-connection session)))
    (when connection
      (handler-case
          (cl-pnet:send-data
           connection data
           :on-error (lambda (status)
                       (declare (ignore status))
                       (socks-abandon session)))
        (error () (socks-abandon session))))))

(defun socks-start-tunnel (session request remaining)
  "Dial REQUEST's target through the SSH connection for SESSION's client.

REMAINING is any stream data the client sent right behind the request; it is
buffered with the tunnel and flushed once the channel is open."
  (let* ((connection (socks-session-connection session))
         (client (socks-session-client session))
         (host (cl-pnet-socks:socks5-request-host request))
         (port (cl-pnet-socks:socks5-request-port request))
         (tunnel (%make-forward-tunnel
                  :forward (%make-forward :host host :port port)
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
       ;; The peer accepted the connection: release the SOCKS client.
       (handler-case
           (cl-pnet:send-data
            connection (socks-reply cl-pnet-socks:+socks5-reply-success+)
            :on-error (lambda (status)
                        (declare (ignore status))
                        (forward-close tunnel)))
         (error () (forward-close tunnel))))
     :on-error
     (lambda (condition)
       (declare (ignore condition))
       ;; The open was refused, so answer the SOCKS request instead of just
       ;; dropping the connection: FORWARD-CLOSE would hide why it failed.
       (setf (forward-tunnel-connection tunnel) nil)
       (remhash connection *tunnels*)
       (socks-write-then-close
        connection
        (socks-reply cl-pnet-socks:+socks5-reply-general-failure+))))))

(defun socks-process (session data)
  "Feed DATA to SESSION and act on whatever the handshake produced."
  (multiple-value-bind (output request error remaining)
      (cl-pnet-socks:socks5-server-consume (socks-session-state session) data)
    (cond
      (error
       ;; OUTPUT is the protocol's own last word: a method refusal, an
       ;; authentication failure, or a reply for a malformed request.
       (let ((connection (socks-session-connection session)))
         (remhash connection *socks-sessions*)
         (if output
             (socks-write-then-close connection output)
             (ignore-errors (cl-pnet:close-connection connection)))))
      (request
       (when output
         (socks-send session output))
       (cond
         ((= (cl-pnet-socks:socks5-request-command request)
             cl-pnet-socks:+socks5-cmd-connect+)
          (socks-start-tunnel session request remaining))
         (t
          (socks-fail session
                      cl-pnet-socks:+socks5-reply-command-unsupported+))))
      (output
       (socks-send session output)))))

(defun socks-connection-data (connection data)
  "Listener callback for -D: run the handshake, then bridge bytes."
  (let ((session (gethash connection *socks-sessions*)))
    (if session
        (if data
            (socks-process session data)
            (socks-abandon session))
        (forward-connection-data connection data))))

(defun socks-accept (client connection)
  (setf (gethash connection *socks-sessions*)
        (%make-socks-session :client client :connection connection)))

(defun dynamic-bind-address (forward)
  (let ((address (dynamic-forward-bind-address forward)))
    (cond
      ((or (null address) (zerop (length address))) "127.0.0.1")
      ((string= address "*") "0.0.0.0")
      (t address))))

(defun start-dynamic-forward (client forward)
  (let* ((address (dynamic-bind-address forward))
         (listener
           (cl-pnet:make-tcp-listener
            address (dynamic-forward-bind-port forward)
            :read-cb #'socks-connection-data
            :on-accept (lambda (connection)
                         (socks-accept client connection))
            :on-error (lambda (status)
                        (log-line "dynamic forward listen error ~A" status)))))
    (unless listener
      (format *error-output*
              "burs: cannot listen on ~A:~D for -D~%"
              address (dynamic-forward-bind-port forward))
      (if (exit-on-forward-failure-p client)
          (finish 255)
          (return-from start-dynamic-forward nil)))
    (setf (dynamic-forward-listener forward) listener)
    (push forward *dynamic-forwards*)
    (let ((port (cl-pnet:listener-port listener)))
      (log-line "dynamic forward ~A:~D" address port)
      (when (and (zerop (dynamic-forward-bind-port forward))
                 (not (getf *options* :quiet)))
        (format *error-output* "Allocated port ~D for dynamic forward~%" port)))
    forward))

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

(defun forwarded-tcpip-target (client bind-address bind-port
                               origin-address origin-port)
  "Answer the local target for a server-initiated forwarded-tcpip channel.

The library calls this with the listener the server actually used and the
peer that connected to it; NIL refuses the channel."
  (declare (ignore origin-address origin-port))
  (let ((forward (find-if (lambda (candidate)
                            (remote-forward-match-p candidate
                                                    bind-address bind-port))
                          *remote-forwards*)))
    (cond
      ((null forward) (values nil nil))
      ((permit-remote-open-allowed-p client
                                     (forward-host forward)
                                     (forward-port forward))
       (values (forward-host forward) (forward-port forward)))
      (t
       (unless (getf *options* :quiet)
         (format *error-output*
                 "burs: PermitRemoteOpen refuses ~A:~D~%"
                 (forward-host forward) (forward-port forward)))
       (values nil nil)))))

(defun attach-client-tcp-target (channel forward)
  "Bridge a server-initiated streamlocal channel to FORWARD's TCP target."
  (setf (cl-pnet-ssh:ssh-channel-on-error channel)
        (lambda (channel condition)
          (declare (ignore condition))
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
    (when forward
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
              nil))))))

(defun start-streamlocal-remote-forward (client forward)
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
     (log-line "remote streamlocal forward ~A to ~A"
               (forward-bind-path forward)
               (or (forward-target-path forward)
                   (format nil "~A:~D"
                           (forward-host forward) (forward-port forward)))))
   :on-failure
   (lambda ()
     (setf *remote-forwards* (delete forward *remote-forwards*))
     (if (exit-on-forward-failure-p client)
         (finish 255)
         (unless (getf *options* :quiet)
           (format *error-output*
                   "burs: remote streamlocal forward ~A was refused~%"
                   (forward-bind-path forward))))))
  forward)

(defun start-remote-forward (client forward)
  "Ask CLIENT's server to listen for FORWARD and relay to this machine."
  (when (forward-bind-path forward)
    (return-from start-remote-forward
      (start-streamlocal-remote-forward client forward)))
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
       (when (zerop port)
         (setf (forward-bind-port forward)
               (cl-pnet-ssh::ssh-read-u32 reader)))
       (log-line "remote forward ~A:~D to ~A:~D"
                 address (forward-bind-port forward)
                 (forward-host forward) (forward-port forward)))
     :on-failure
     (lambda ()
       (setf *remote-forwards* (delete forward *remote-forwards*))
       (if (exit-on-forward-failure-p client)
           (finish 255)
           (unless (getf *options* :quiet)
             (format *error-output*
                     "burs: remote forward ~A:~D was refused~%"
                     address port)))))
    forward))

(defun start-forwards (client)
  (when (clear-all-forwardings-p client)
    (return-from start-forwards nil))
  (dolist (forward (append (configured-local-forwards client)
                           (getf *options* :local-forward)))
    (start-local-forward client forward))
  (dolist (forward (append (configured-remote-forwards client)
                           (getf *options* :remote-forward)))
    (start-remote-forward client forward))
  (dolist (forward (append (configure-dynamic-forwards client)
                           (getf *options* :dynamic-forward)))
    (start-dynamic-forward client forward)))

(defun stop-dynamic-forwards ()
  (dolist (forward *dynamic-forwards*)
    (when (dynamic-forward-listener forward)
      (ignore-errors
        (cl-pnet:close-listener (dynamic-forward-listener forward)))
      (setf (dynamic-forward-listener forward) nil)))
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
    (when (forward-listener forward)
      (ignore-errors (cl-pnet:close-listener (forward-listener forward)))
      (setf (forward-listener forward) nil))
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

(defun resolve-config-options (host)
  "HOST's ssh_config as SSH-CONFIG-OPTIONS, synchronously."
  (let ((result nil)
        (failure nil)
        (source
          (handler-case
              (cl-pnet-ssh:ssh-config-client-source
               (getf *options* :config)
               (command-line-option-list))
            (cl-pnet-ssh:ssh-config-error (condition)
              (fail "~A" condition)))))
    (cl-pnet-ssh:ssh-config-resolve
     source host
     :original-host host
     :user (getf *options* :user)
     :port (client-port)
     :exec-matcher #'match-exec
     :on-options (lambda (options) (setf result options))
     :on-error (lambda (condition) (setf failure condition)))
    (if failure
        (fail "~A" failure)
        result)))

(defun print-list-option (name values)
  (dolist (value values)
    (format t "~A ~A~%" name value)))

(defun print-config (host)
  (let* ((options (resolve-config-options host))
         (hostname (or (cl-pnet-ssh:ssh-config-options-hostname options)
                       host)))
    (format t "host ~A~%" host)
    (format t "hostname ~A~%" hostname)
    (let ((alias (cl-pnet-ssh:ssh-config-options-host-key-alias options)))
      (when alias
        (format t "hostkeyalias ~A~%" alias)))
    (format t "user ~A~%"
            (or (cl-pnet-ssh:ssh-config-options-user options)
                (getf *options* :user)
                (cl-pnet-ssh:ssh-default-user)))
    (format t "port ~D~%"
            (or (cl-pnet-ssh:ssh-config-options-port options)
                (client-port)
                22))
    (format t "addressfamily ~(~A~)~%"
            (or (cl-pnet-ssh:ssh-config-options-address-family options)
                "any"))
    (format t "requesttty ~A~%"
            (or (tty-setting-name (getf *options* :request-tty))
                (cl-pnet-ssh:ssh-config-options-request-tty options)
                "auto"))
    (flet ((ip-qos-name (value)
             (cond
               ((eq value :none) "none")
               (t (or (car (rassoc value cl-pnet-ssh::+ssh-config-ip-qos-names+
                                   :test #'eql))
                      (format nil "0x~2,'0x" value))))))
      (format t "ipqos ~A ~A~%"
              (ip-qos-name
               (cl-pnet-ssh:ssh-config-options-ip-qos-interactive options))
              (ip-qos-name
               (cl-pnet-ssh:ssh-config-options-ip-qos-bulk options))))
    (format t "fingerprinthash ~A~%"
            (string-upcase
             (symbol-name
              (or (cl-pnet-ssh:ssh-config-options-fingerprint-hash options)
                  :sha256))))
    (format t "loglevel ~A~%"
            (string-upcase
             (or (cl-pnet-ssh:ssh-config-options-log-level options)
                 "info")))
    (dolist (line (cl-pnet-ssh:ssh-config-options-log-verbose options))
      (format t "logverbose ~A~%" line))
    (let ((local (cl-pnet-ssh:ssh-config-options-local-command options)))
      (when local
        (format t "localcommand ~A~%" local)))
    (format t "permitlocalcommand ~A~%"
            (if (cl-pnet-ssh:ssh-config-options-permit-local-command
                 options)
                "yes"
                "no"))
    (let ((remote (cl-pnet-ssh:ssh-config-options-remote-command options)))
      (when remote
        (format t "remotecommand ~A~%" remote)))
    (format t "sessiontype ~A~%"
            (or (cl-pnet-ssh:ssh-config-options-session-type options)
                "default"))
    (format t "stdinnull ~A~%"
            (if (cl-pnet-ssh:ssh-config-options-stdin-null options)
                "yes"
                "no"))
    (print-list-option
     "identityfile"
     (or (reverse (cl-pnet-ssh:ssh-config-options-identity-files options))
         (reverse (getf *options* :identity))))
    (print-list-option
     "userknownhostsfile"
     (or (cl-pnet-ssh:ssh-config-options-known-hosts options)
         (and (getf *options* :known-hosts)
              (list (getf *options* :known-hosts)))))
    (format t "clearallforwardings ~A~%"
            (if (cl-pnet-ssh:ssh-config-options-clear-all-forwardings
                 options)
                "yes"
                "no"))
    (format t "connectionattempts ~D~%"
            (or (cl-pnet-ssh:ssh-config-options-connection-attempts options)
                1))
    (format t "tcpkeepalive ~A~%"
            (if (cl-pnet-ssh:ssh-config-options-tcp-keep-alive options)
                "yes"
                "no"))
    (format t "exitonforwardfailure ~A~%"
            (if (cl-pnet-ssh:ssh-config-options-exit-on-forward-failure
                 options)
                "yes"
                "no"))
    (format t "hashknownhosts ~A~%"
            (if (cl-pnet-ssh:ssh-config-options-hash-known-hosts options)
                "yes"
                "no"))
    (let ((revoked (reverse
                    (cl-pnet-ssh:ssh-config-options-revoked-host-keys
                     options))))
      (when revoked
        (format t "revokedhostkeys~{ ~A~}~%"
                (mapcar #'namestring revoked))))
    (format t "stricthostkeychecking ~A~%"
            (or (cl-pnet-ssh:ssh-config-options-strict-host-key-checking
                 options)
                (case (getf *options* :policy)
                  (:insecure "no")
                  (:accept-new "accept-new")
                  (t "yes"))))
    (format t "requiredrsasize ~D~%"
            (or (cl-pnet-ssh:ssh-config-options-required-rsa-size options)
                cl-pnet-ssh::+ssh-rsa-minimum-modulus-size+))
    (format t "casignaturealgorithms ~{~A~^,~}~%"
            (or (cl-pnet-ssh::ssh-config-client-algorithms
                 options
                 #'cl-pnet-ssh:ssh-config-options-ca-signature-algorithms
                 cl-pnet-ssh::+ssh-server-ca-signature-algorithms+
                 "CASignatureAlgorithms"
                 :all cl-pnet-ssh::+ssh-server-ca-signature-algorithm-names+)
                cl-pnet-ssh::+ssh-server-ca-signature-algorithms+))
    (format t "streamlocalbindunlink ~A~%"
            (if (cl-pnet-ssh:ssh-config-options-streamlocal-bind-unlink
                 options)
                "yes"
                "no"))
    (print-list-option "sendenv"
                       (cl-pnet-ssh:ssh-config-options-send-env options))
    (print-list-option "setenv"
                       (cl-pnet-ssh:ssh-config-options-set-env options))
    (let ((permit (cl-pnet-ssh:ssh-config-options-permit-remote-open
                   options)))
      (cond
        ((eq permit :any) (format t "permitremoteopen any~%"))
        ((eq permit :none) (format t "permitremoteopen none~%"))
        ((null permit) nil)
        (t (dolist (entry permit)
             (format t "permitremoteopen ~A:~A~%"
                     (car entry)
                     (if (eq (cdr entry) :any) "*" (cdr entry)))))))
    (print-list-option
     "localforward"
     (reverse (cl-pnet-ssh:ssh-config-options-local-forwards options)))
    (print-list-option
     "remoteforward"
     (reverse (cl-pnet-ssh:ssh-config-options-remote-forwards options)))
    (print-list-option
     "dynamicforward"
     (reverse (cl-pnet-ssh:ssh-config-options-dynamic-forwards options)))
    (format t "proxyjump ~A~%"
            (or (let ((jump (cl-pnet-ssh:ssh-config-options-proxy-jump
                             options)))
                  (cond ((null jump) nil)
                        ((listp jump) (format nil "~{~A~^,~}" jump))
                        (t jump)))
                (getf *options* :jump)
                "none"))
    (format t "proxycommand ~A~%"
            (or (cl-pnet-ssh:ssh-config-options-proxy-command options)
                (getf *options* :proxy-command)
                "none")))
  (finish-output)
  (uiop:quit 0))

;;; ---- Entry point ----

(defun join-command (arguments)
  (format nil "~{~A~^ ~}" arguments))

;;; ---- The target client ----

(defun client-port ()
  "The -p or -o Port value as a number, when the command line gave one."
  (let ((value (getf *options* :port)))
    (when value
      (multiple-value-bind (port end) (parse-integer value :junk-allowed t)
        (if (and port (= end (length value)))
            port
            (fail "invalid port ~A" value))))))

(defun show-banner (client)
  "Print the server's authentication banner, once, as OpenSSH does.

OpenSSH writes it to stderr the moment it arrives; this client shows it as
soon as the connection settles, because the library stores the text instead
of calling back in the middle of authentication."
  (let ((banner (cl-pnet-ssh:ssh-client-banner client)))
    (when banner
      (setf (cl-pnet-ssh:ssh-client-banner client) nil)
      (format *error-output* "~A" banner)
      (finish-output *error-output*))))

(defun start-client (host command command-given-p)
  "Run COMMAND on HOST, letting the library follow ~/.ssh/config for it."
  (cl-pnet-ssh:make-ssh-client-from-config
   host
   :config (getf *options* :config)
   :user (getf *options* :user)
   :port (client-port)
   :private-key (reverse (getf *options* :identity))
   :agent (getf *options* :agent)
   :known-hosts (getf *options* :known-hosts)
   :host-key-policy (getf *options* :policy)
   :proxy-jump (getf *options* :jump)
   :proxy-command (getf *options* :proxy-command)
   ;; Every -o keyword reaches the same resolver the file uses, so facts the
   ;; command line has no dedicated flag for (HostName, ConnectTimeout,
   ;; ServerAliveInterval, ...) work too.
   :options (resolver-option-list)
   :exec-matcher #'match-exec
   :on-client (lambda (client)
                (setf *client* client)
                (apply-config-log-level client)
                (check-config-supported client))
   :on-config-error (lambda (condition) (fail "~A" condition))
   :on-forwarded-tcpip #'forwarded-tcpip-target
   :on-forwarded-streamlocal #'forwarded-streamlocal-target
   :on-open
   (lambda (client)
     (let ((remote (config-remote-command client)))
       (when remote
         (when command-given-p
           (fail "Cannot execute command-line and remote command."))
         (setf command (expand-remote-command client remote)
               command-given-p t)))
     (show-banner client)
     (cl-pnet-ssh:ssh-client-set-ip-qos
      client (request-tty-p client command-given-p))
     (start-forwards client)
     (when (and (config-local-command client)
                (permit-local-command-p client))
       (run-local-command client))
     (cond
       ((getf *options* :stdio-forward)
        (multiple-value-bind (target port)
            (parse-host-port (getf *options* :stdio-forward))
          (start-stdio-forward client target port)))
       ((or (getf *options* :no-command) (session-type-none-p client)) nil)
       (t
        (when (and (subsystem-request-p) (not command-given-p))
          (fail "SessionType subsystem requires a subsystem name"))
        (start-session client command command-given-p))))
   :on-error (lambda (client condition)
               (show-banner client)
               (format *error-output* "burs: ~A~%" condition)
               (finish 255))
   :on-close (lambda (client reason)
               (declare (ignore client reason))
               (finish *status*))))

(defun main ()
  "Entry point for the BURS program."
  (handler-case
      (let ((arguments (uiop:command-line-arguments)))
        (multiple-value-bind (destination command)
            (parse-arguments arguments)
          (when (getf *options* :version)
            (print-version)
            (uiop:quit 0))
          (apply-command-line-options)
          (check-supported-options)
          (start-logging)
          (when (getf *options* :query)
            (print-query (getf *options* :query)))
          (unless destination
            (clingon:print-usage *burs-command* *error-output*)
            (uiop:quit 255))
          (multiple-value-bind (host user) (split-destination destination)
            (when user (setf (getf *options* :user) user))
            (when (and (getf *options* :subsystem) (null command))
              (fail "-s requires a subsystem name"))
            (when (and (getf *options* :stdio-forward) command)
              (fail "-W cannot be combined with a remote command"))
            (when (getf *options* :print-config)
              (print-config host))
            (handler-case
                (start-client host (and command (join-command command))
                              (and command t))
              (cl-pnet-ssh:ssh-config-error (condition)
                ;; An unreadable -F file and similar problems are command
                ;; line errors, which ssh reports with status 255.
                (fail "~A" condition)))
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
    (error (condition)
      (when (uiop:getenv "BURS_DEBUG")
        (sb-debug:print-backtrace :count 40 :stream *error-output*))
      (format *error-output* "burs: ~A~%" condition)
      (uiop:quit 1))))
