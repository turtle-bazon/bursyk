(defpackage #:burs
  (:use #:cl)
  (:export #:main))

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

(defparameter +burs-version+ "0.0.4.0")

(defvar *status* nil
  "The exit status the remote command reported, or NIL before it does.")
(defvar *channel* nil)
(defvar *client* nil
  "The connected client, kept so FINISH can shut it down before quitting.")
(defvar *stdin-watcher* nil)
(defvar *finishing* nil
  "True once FINISH is tearing down, so nested close callbacks do not quit early.")
(defvar *log-stream* nil
  "Where -v writes, or NIL when logging is off.")
(defvar *forwards* nil
  "Local forwarding listeners, in the order they were started.")
(defvar *tunnels* (make-hash-table :test #'eq :size 16)
  "Accepted forwarding connections, keyed by their CL-PNET connection.")
(defvar *pty-timer* nil
  "The watchdog that sends pty-req once the session channel is open.")
(defvar *terminal-saved* nil
  "The terminal settings STTY -G reported, or NIL when not in raw mode.")
(defvar *winch* nil
  "The SIGWINCH watcher that forwards terminal resizes to the remote PTY.")

(defvar *options*
  '(:port nil :user nil :identity nil :config nil :known-hosts nil
    :policy nil :agent nil :options nil :jump nil :proxy-command nil
    :verbose 0 :quiet nil :log-file nil :address-family nil
    :ciphers nil :macs nil :kex-algorithms nil :compression nil
    :request-tty nil :forward-agent nil :gateway-ports nil
    :no-command nil :stdin-null nil :subsystem nil :stdio-forward nil
    :local-forward nil :remote-forward nil :dynamic-forward nil
    :query nil :help nil :version nil :print-config nil
    :background nil :control-master nil :control-path nil :control-command nil
    :pkcs11 nil :bind-interface nil :bind-address nil :gssapi-auth nil
    :tunnel nil :x11-forward nil :escape-char nil)
  "The command line as parsed, before ~/.ssh/config is applied.")

(defun stdin-terminal-p ()
  #+sbcl (plusp (sb-unix:unix-isatty 0))
  #-sbcl nil)

(defun restore-terminal ()
  "Put the terminal back the way TERMINAL-ENTER-RAW found it."
  (when *terminal-saved*
    (let ((saved *terminal-saved*))
      (setf *terminal-saved* nil)
      (ignore-errors
       (uiop:run-program (list "stty" saved)
                         :input :interactive
                         :output nil
                         :error-output nil)))))

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
            (getf *options* :forward-agent) (flag :forward-agent)
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

OpenSSH accepts +/-^ prefixes that edit the default list; the named
algorithms still have to exist here, because the set is fixed at build time."
  (let ((names (split-list value)))
    (unless names
      (fail "~A needs at least one algorithm name" option))
    (dolist (name names)
      (let ((plain (if (and (plusp (length name))
                            (member (char name 0) '(#\+ #\- #\^)))
                       (subseq name 1)
                       name)))
        (unless (member plain supported :test #'string=)
          (fail "~A: unsupported algorithm ~A (this build offers ~{~A~^, ~})"
                option plain supported))))))

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
  (when (getf *options* :remote-forward)
    (unsupported "-R" "the server role does not implement tcpip-forward"))
  (when (getf *options* :dynamic-forward)
    (unsupported "-D" "the SOCKS proxy is not implemented"))
  (when (getf *options* :gssapi-auth)
    (unsupported "-K" "GSSAPI authentication is not implemented"))
  (when (eq (getf *options* :x11-forward) :yes)
    (unsupported "-X" "X11 forwarding is not implemented"))
  (when (eq (getf *options* :x11-forward) :trust)
    (unsupported "-Y" "X11 forwarding is not implemented"))
  (when (getf *options* :forward-agent)
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
                          cl-pnet-ssh:+ssh-kex-algorithms+))
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
  (values))

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
    ((string-equal name "RemoteForward")
     (push value (getf *options* :remote-forward)))
    ((string-equal name "DynamicForward")
     (push value (getf *options* :dynamic-forward)))
    ;; Everything else reaches the ssh_config resolver through the same -o
    ;; list, or is accepted and ignored as SSH itself tolerates keywords a
    ;; newer client wrote.
    (t nil)))

(defun command-line-option-list ()
  "The -o options in the order they were written."
  (reverse (getf *options* :options)))

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
  (when (getf *options* :log-file)
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
  host
  port
  listener)

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

(defun parse-local-forward (spec)
  "SPEC as a FORWARD for [bind_address:]port:host:hostport."
  (let ((fields (split-forward-fields spec)))
    (cond
      ((= (length fields) 3)
       (destructuring-bind (port host hostport) fields
         (when (null (parse-integer hostport :junk-allowed t))
           (fail "~A: streaming to a unix socket is not implemented" spec))
         (%make-forward :bind-port (forwarding-port port spec)
                        :host host
                        :port (forwarding-port hostport spec))))
      ((= (length fields) 4)
       (destructuring-bind (bind port host hostport) fields
         (%make-forward :bind-address (if (plusp (length bind)) bind nil)
                        :bind-port (forwarding-port port spec)
                        :host host
                        :port (forwarding-port hostport spec))))
      ((= (length fields) 2)
       (fail "~A: streaming to a unix socket is not implemented" spec))
      (t
       (fail "invalid forwarding specification ~A" spec)))))

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

(defun parse-config-local-forward (spec)
  "SPEC as a FORWARD for ssh_config's \"[bind_address:]port host:hostport\".

A LocalForward line in a config file has two words, unlike -L's single
colon-separated argument, so both spellings are accepted here.  A one-word
line is handled as the command-line form, which is what a user who wrote
-L's syntax into the file meant."
  (let ((words (uiop:split-string spec :separator '(#\Space #\Tab))))
    (if (/= 2 (length words))
        (parse-local-forward spec)
        (destructuring-bind (listen target) words
          (multiple-value-bind (first second) (split-host-port listen)
            (let (bind port)
              (if second
                  (setf bind first port second)
                  (setf port first))
              (multiple-value-bind (host hostport) (split-host-port target)
                (unless (and hostport (plusp (length hostport)))
                  (fail "~A: streaming to a unix socket is not implemented"
                        spec))
                (%make-forward
                 :bind-address (and bind (plusp (length bind)) bind)
                 :bind-port (forwarding-port port spec)
                 :host host
                 :port (forwarding-port hostport spec)))))))))

;;; ---- Session ----

;;; A PTY session needs three things the library's session API does not name:
;;; a pty-req channel request before exec/shell, a raw local terminal, and a
;;; window-change request on resize.  They stay here rather than in the
;;; library because they are policy: which terminal settings to save, what
;;; TERM to send, and whether the user asked for a PTY at all.

(defun run-stty (&rest arguments)
  "Run stty with ARGUMENTS on our terminal; its output, or NIL.

STTY -G and STTY SIZE talk to stdin, so the child inherits fd 0.  A caller
must already know that stdin is a terminal."
  (handler-case
      (string-trim '(#\Newline #\Return)
                   (uiop:run-program (cons "stty" arguments)
                                     :input :interactive
                                     :output :string
                                     :error-output nil))
    (error () nil)))

(defun terminal-size ()
  "The terminal's (VALUES ROWS COLUMNS), or (VALUES NIL NIL)."
  (let ((text (run-stty "size")))
    (when text
      (let ((space (position #\Space text)))
        (when space
          (let ((rows (parse-integer text :end space :junk-allowed t))
                (columns (parse-integer text :start (1+ space)
                                       :junk-allowed t)))
            (when (and rows columns)
              (values rows columns))))))))

(defun terminal-enter-raw ()
  "Save the terminal settings and stop local line editing and signals.

With a PTY, the remote side echoes and edits.  Leaving the local terminal in
raw mode is also what makes Ctrl-C a byte for the remote shell, as in ssh."
  (when (and (stdin-terminal-p)
             (not (getf *options* :stdin-null)))
    (setf *terminal-saved* (run-stty "-g"))
    (when *terminal-saved*
      (run-stty "raw" "-echo"))))

(defun stop-pty-timer ()
  (when *pty-timer*
    (ignore-errors (cl-pnet:timer-stop *pty-timer*))
    (setf *pty-timer* nil)))

(defun stop-winch ()
  (when *winch*
    (ignore-errors (cl-pnet:signal-stop *winch*))
    (setf *winch* nil)))

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

(defun start-winch (channel)
  "Forward terminal resizes to CHANNEL while the session is open."
  (when (stdin-terminal-p)
    (setf *winch*
          (ignore-errors
           (cl-pnet:signal-start
            #+sbcl sb-unix:sigwinch
            #-sbcl 28
            (lambda ()
              (handler-case (send-window-change channel)
                (error () nil))))))))

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
                ((getf *options* :subsystem)
                 (send-subsystem-request channel command))
                (command-given-p
                 (send-exec-request channel command))
                (t
                 (send-shell-request channel)))
              (start-input channel))
             (:closed
              (stop-pty-timer))
             (t nil))))))

(defun write-octets (stream octets)
  "Write channel output to STREAM, leaving as SIGPIPE would if it is closed.

A shell pipeline such as \"burs host cat | head\" closes our stdout once it
has enough.  SBCL ignores SIGPIPE, so the write raises instead; treating that
as failure and exiting 128+13 keeps the usual pipeline behavior."
  (handler-case
      (progn
        (write-string (cl-pnet-ssh:ssh-octets-string octets) stream)
        (finish-output stream))
    (error () (finish 141))))

(defun stop-stdin ()
  (when *stdin-watcher*
    (cl-pnet:fd-unwatch *stdin-watcher*)
    (setf *stdin-watcher* nil)))

(defun stdin-readable (channel)
  "Move whatever stdin has to CHANNEL; end the input at real EOF.

stdin is a pipe or a terminal, so it is read with READ-OCTETS: RECV would
answer ENOTSOCK.  A count of -1 means nothing is ready yet, not EOF."
  (multiple-value-bind (octets count error)
      (cl-pnet-sockets:read-octets 0 65536)
    (declare (ignore error))
    (cond
      ((plusp count) (cl-pnet-ssh:ssh-channel-write channel octets))
      ((zerop count)
       (stop-stdin)
       (cl-pnet-ssh:ssh-channel-eof channel))
      (t nil))))

(defun start-stdin (channel)
  (setf *stdin-watcher*
        (cl-pnet:fd-watch
         0
         :on-readable
         (lambda (watcher)
           (declare (ignore watcher))
           (handler-case (stdin-readable channel)
             (error () (stop-stdin)))))))

(defun start-input (channel)
  "Feed stdin to CHANNEL, or report EOF at once under -n."
  (if (getf *options* :stdin-null)
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
  (unless (getf *options* :subsystem)
    (dolist (name (cl-pnet-ssh:ssh-client-send-env client))
      (let ((value (uiop:getenv name)))
        (when value
          (cl-pnet-ssh:ssh-channel-env *channel* name value)))))
  (if (request-tty-p client command-given-p)
      (start-pty-session *channel* command command-given-p)
      (progn
        (if (getf *options* :subsystem)
            (cl-pnet-ssh:ssh-channel-subsystem *channel* command)
            (cl-pnet-ssh:ssh-channel-exec *channel* command))
        (start-input *channel*))))

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

(defun open-forward-channel (client tunnel)
  (let ((forward (forward-tunnel-forward tunnel)))
    (handler-case
        (let ((channel
                (cl-pnet-ssh:ssh-open-direct-tcpip
                 client (forward-host forward) (forward-port forward)
                 :on-data (lambda (channel data kind)
                            (declare (ignore channel kind))
                            (forward-send tunnel data))
                 :on-eof (lambda (channel)
                           (declare (ignore channel))
                           (forward-close tunnel))
                 :on-close (lambda (channel reason)
                             (declare (ignore channel reason))
                             (forward-close tunnel))
                 :on-error (lambda (channel condition)
                             (declare (ignore channel))
                             (unless (getf *options* :quiet)
                               (format *error-output*
                                       "burs: forward to ~A:~D failed: ~A~%"
                                       (forward-host forward)
                                       (forward-port forward)
                                       condition))
                             (forward-close tunnel)))))
          (setf (forward-tunnel-channel tunnel) channel)
          (forward-flush tunnel)
          (forward-flush-to-connection tunnel))
      (error (condition)
        (format *error-output* "burs: forward failed: ~A~%" condition)
        (forward-close tunnel)))))

(defun forward-accept (client forward connection)
  (let ((tunnel (%make-forward-tunnel :forward forward
                                      :connection connection)))
    (setf (gethash connection *tunnels*) tunnel)
    (open-forward-channel client tunnel)))

(defun start-local-forward (client forward)
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
      (finish 255))
    (setf (forward-listener forward) listener)
    (push forward *forwards*)
    (let ((port (cl-pnet:listener-port listener)))
      (log-line "local forward ~A:~D to ~A:~D"
                address port (forward-host forward) (forward-port forward))
      (when (and (zerop (forward-bind-port forward))
                 (not (getf *options* :quiet)))
        (format *error-output* "Allocated port ~D for local forward~%" port)))
    forward))

(defun configured-local-forwards (client)
  "The LocalForward lines in CLIENT's config, in file order."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (and options
         (mapcar #'parse-config-local-forward
                 (reverse (cl-pnet-ssh:ssh-config-options-local-forwards
                           options))))))

(defun check-config-features (client)
  "Refuse a config feature this client would otherwise silently drop.

A config file is shared with OpenSSH, so a RemoteForward or DynamicForward
line there is a request this client cannot honour.  Skipping it quietly
would leave the user waiting for a tunnel that was never opened."
  (let ((options (cl-pnet-ssh:ssh-client-config-options client)))
    (when options
      (let ((remote (cl-pnet-ssh:ssh-config-options-remote-forwards options))
            (dynamic (cl-pnet-ssh:ssh-config-options-dynamic-forwards options)))
        (when remote
          (fail "RemoteForward in the ssh config is not supported: ~A"
                (first (reverse remote))))
        (when dynamic
          (fail "DynamicForward in the ssh config is not supported: ~A"
                (first (reverse dynamic))))))))

(defun start-forwards (client)
  (check-config-features client)
  (dolist (forward (append (configured-local-forwards client)
                           (getf *options* :local-forward)))
    (start-local-forward client forward)))

(defun stop-forwards ()
  (dolist (forward *forwards*)
    (when (forward-listener forward)
      (ignore-errors (cl-pnet:close-listener (forward-listener forward)))
      (setf (forward-listener forward) nil)))
  (setf *forwards* nil)
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
    (print-list-option
     "identityfile"
     (or (reverse (cl-pnet-ssh:ssh-config-options-identity-files options))
         (reverse (getf *options* :identity))))
    (print-list-option
     "userknownhostsfile"
     (or (cl-pnet-ssh:ssh-config-options-known-hosts options)
         (and (getf *options* :known-hosts)
              (list (getf *options* :known-hosts)))))
    (format t "stricthostkeychecking ~A~%"
            (or (cl-pnet-ssh:ssh-config-options-strict-host-key-checking
                 options)
                (case (getf *options* :policy)
                  (:insecure "no")
                  (:accept-new "accept-new")
                  (t "yes"))))
    (print-list-option "sendenv"
                       (cl-pnet-ssh:ssh-config-options-send-env options))
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

(defun remote-shell ()
  (or (uiop:getenv "SHELL") "/bin/sh"))

(defun join-command (arguments)
  (if arguments
      (format nil "~{~A~^ ~}" arguments)
      (remote-shell)))

;;; ---- The target client ----

(defun client-port ()
  "The -p or -o Port value as a number, when the command line gave one."
  (let ((value (getf *options* :port)))
    (when value
      (multiple-value-bind (port end) (parse-integer value :junk-allowed t)
        (if (and port (= end (length value)))
            port
            (fail "invalid port ~A" value))))))

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
   :options (command-line-option-list)
   :exec-matcher #'match-exec
   :on-client (lambda (client) (setf *client* client))
   :on-config-error (lambda (condition) (fail "~A" condition))
   :on-open
   (lambda (client)
     (start-forwards client)
     (cond
       ((getf *options* :stdio-forward)
        (multiple-value-bind (target port)
            (parse-host-port (getf *options* :stdio-forward))
          (start-stdio-forward client target port)))
       ((getf *options* :no-command) nil)
       (t (start-session client command command-given-p))))
   :on-error (lambda (client condition)
               (declare (ignore client))
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
                (start-client host (join-command command) (and command t))
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
