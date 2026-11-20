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

(defun usage (&optional (stream *error-output*))
  (format stream
          "usage: burs [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]~%~
           ~10@T[-b bind_address] [-c cipher_spec] [-D [bind_address:]port]~%~
           ~10@T[-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]~%~
           ~10@T[-i identity_file] [-J [user@]host[:port]] [-L address]~%~
           ~10@T[-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option]~%~
           ~10@T[-p port] [-Q query_option] [-R address] [-S ctl_path]~%~
           ~10@T[-W host:port] [-w local_tun[:remote_tun]]~%~
           ~10@Tdestination [command [argument ...]]~%")
  (finish-output stream))

(defun print-version ()
  (format t "burs ~A~%" +burs-version+)
  (finish-output))

(defun fail (format-string &rest arguments)
  (format *error-output* "burs: ~?~%" format-string arguments)
  (finish-output *error-output*)
  (uiop:quit 255))

(defun unsupported (option &optional (detail "not implemented by this client"))
  (fail "~A is not supported: ~A" option detail))

;;; ---- Command line ----

(defun split-destination (destination)
  "DESTINATION as (VALUES HOST USER), splitting USER@HOST at the first @."
  (let ((at (position #\@ destination)))
    (if at
        (values (subseq destination (1+ at)) (subseq destination 0 at))
        (values destination nil))))

(defun short-option-spec (character)
  "The plist describing short option CHARACTER, or NIL.

Short options are case-sensitive, as in SSH itself: -p is the port and -P is
not an option at all."
  (case character
    (#\4 (list :key :address-family :value "inet"))
    (#\6 (list :key :address-family :value "inet6"))
    (#\A (list :key :forward-agent :value t))
    (#\a (list :key :forward-agent :value nil))
    (#\B (list :key :bind-interface :takes-value t))
    (#\b (list :key :bind-address :takes-value t))
    (#\C (list :key :compression :value t))
    (#\c (list :key :ciphers :takes-value t))
    (#\D (list :key :dynamic-forward :takes-value t))
    (#\E (list :key :log-file :takes-value t))
    (#\e (list :key :escape-char :takes-value t))
    (#\F (list :key :config :takes-value t))
    (#\f (list :key :background :value t))
    (#\G (list :key :print-config :value t))
    (#\g (list :key :gateway-ports :value t))
    (#\h (list :key :help :value t))
    (#\I (list :key :pkcs11 :takes-value t))
    (#\i (list :key :identity :takes-value t))
    (#\J (list :key :jump :takes-value t))
    (#\K (list :key :gssapi-auth :value t))
    (#\k (list :key :gssapi-auth :value nil))
    (#\L (list :key :local-forward :takes-value t))
    (#\l (list :key :user :takes-value t))
    (#\M (list :key :control-master :value t))
    (#\m (list :key :macs :takes-value t))
    (#\N (list :key :no-command :value t))
    (#\n (list :key :stdin-null :value t))
    (#\O (list :key :control-command :takes-value t))
    (#\o (list :key :options :takes-value t))
    (#\p (list :key :port :takes-value t))
    (#\q (list :key :quiet :value t))
    (#\Q (list :key :query :takes-value t))
    (#\R (list :key :remote-forward :takes-value t))
    (#\S (list :key :control-path :takes-value t))
    (#\s (list :key :subsystem :value t))
    (#\T (list :key :request-tty :value :no))
    (#\t (list :key :request-tty :value :force))
    (#\V (list :key :version :value t))
    (#\v (list :key :verbose :value t))
    (#\W (list :key :stdio-forward :takes-value t))
    (#\w (list :key :tunnel :takes-value t))
    (#\X (list :key :x11-forward :value :yes))
    (#\x (list :key :x11-forward :value :no))
    (#\Y (list :key :x11-forward :value :trust))
    (otherwise nil)))

(defparameter *long-options*
  ;; (NAME KEY TAKES-VALUE VALUE), matched case-insensitively.  These are the
  ;; readable spellings this client has always had; ssh itself has only -o.
  '(("address-family" :address-family t nil)
    ("agent" :agent t nil)
    ("bind-address" :bind-address t nil)
    ("ciphers" :ciphers t nil)
    ("config" :config t nil)
    ("dynamic-forward" :dynamic-forward t nil)
    ("gateway-ports" :gateway-ports nil t)
    ("help" :help nil t)
    ("identity" :identity t nil)
    ("identity-file" :identity t nil)
    ("jump" :jump t nil)
    ("known-hosts" :known-hosts t nil)
    ("local-forward" :local-forward t nil)
    ("log-file" :log-file t nil)
    ("macs" :macs t nil)
    ("no-command" :no-command nil t)
    ("option" :options t nil)
    ("port" :port t nil)
    ("quiet" :quiet nil t)
    ("remote-forward" :remote-forward t nil)
    ("request-tty" :request-tty t nil)
    ("stdin-null" :stdin-null nil t)
    ("stdio-forward" :stdio-forward t nil)
    ("subsystem" :subsystem nil t)
    ("user" :user t nil)
    ("verbose" :verbose nil t)
    ("version" :version nil t)))

(defun option-key (name)
  "The option NAME selects, or NIL.

A two-character short option and a --long spelling are both accepted.  A
cluster such as -vv is not one option, so it answers NIL here and the parser
walks it character by character."
  (cond
    ((and (> (length name) 2)
          (char= (char name 0) #\-)
          (char= (char name 1) #\-))
     (let* ((body (string-downcase (subseq name 2)))
            (equals (position #\= body))
            (plain (if equals (subseq body 0 equals) body)))
       (second (assoc plain *long-options* :test #'string=))))
    ((and (= (length name) 2) (char= (char name 0) #\-))
     (getf (short-option-spec (char name 1)) :key))
    (t nil)))

(defun record-option (key value)
  (case key
    ((:identity :options :local-forward :remote-forward :dynamic-forward)
     (push value (getf *options* key)))
    (:verbose
     (setf (getf *options* :verbose)
           (1+ (getf *options* :verbose 0))))
    (t (setf (getf *options* key) value))))

(defun parse-arguments (arguments)
  "Fill *OPTIONS* from ARGUMENTS; return (VALUES DESTINATION COMMAND).

Options may be clustered (-vvT) and a value may be attached to its option
(-p2222, -oPort=22, --port=2222) or given as the next argument.  Parsing
stops at the destination; everything after it is the remote command."
  (let ((destination nil)
        (command nil)
        (arguments (copy-list arguments)))
    (labels
        ((take-value (token attached)
           (or attached
               (pop arguments)
               (fail "~A needs a value" token)))
         (apply-spec (spec token attached)
           (let ((key (getf spec :key))
                 (value (getf spec :value)))
             (if (getf spec :takes-value)
                 (record-option key (take-value token attached))
                 (record-option key value))))
         (short-cluster (argument)
           (let ((length (length argument)))
             (loop with index = 1
                   while (< index length)
                   do (let* ((character (char argument index))
                             (spec (short-option-spec character)))
                        (unless spec
                          (fail "unknown option -~C" character))
                        (cond
                          ((getf spec :takes-value)
                           (apply-spec spec argument
                                       (if (< (1+ index) length)
                                           (subseq argument (1+ index))
                                           nil))
                           (setf index length))
                          (t
                           (apply-spec spec argument nil)
                           (incf index)))))))
         (long-option (argument)
           (let* ((body (subseq argument 2))
                  (equals (position #\= body))
                  (name (if equals (subseq body 0 equals) body))
                  (attached (and equals (subseq body (1+ equals))))
                  (entry (assoc (string-downcase name) *long-options*
                                :test #'string=)))
             (unless entry
               (fail "unknown option --~A" name))
             (apply-spec (list :key (second entry)
                               :takes-value (third entry)
                               :value (fourth entry))
                         argument attached))))
      (loop
        (let ((argument (pop arguments)))
          (cond
            ((null argument)
             (return))
            ((string= argument "--")
             (setf destination (pop arguments)
                   command arguments)
             (return))
            ((and (> (length argument) 2)
                  (char= (char argument 0) #\-)
                  (char= (char argument 1) #\-))
             (long-option argument))
            ((and (> (length argument) 1)
                  (char= (char argument 0) #\-))
             (short-cluster argument))
            (t
             (setf destination argument
                   command arguments)
             (return))))))
    (values destination command)))

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
  (when (and (getf *options* :request-tty)
             (not (member (getf *options* :request-tty)
                          '(:no "no" "false" :off)
                          :test #'equal)))
    (unsupported (if (eq (getf *options* :request-tty) :force) "-t" "RequestTTY")
                 "PTY allocation is not implemented"))
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
  #+sbcl (sb-ext:exit :code status :abort t)
  #-sbcl (uiop:quit status))

(defun finish (status)
  ;; Closing the client below reports its open channels closed, whose
  ;; callbacks call FINISH again; only the outermost call may quit, or the
  ;; connection (and a ProxyCommand helper) would be left half torn down.
  (unless *finishing*
    (setf *finishing* t)
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

(defun start-session (client command)
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
  (if (getf *options* :subsystem)
      (cl-pnet-ssh:ssh-channel-subsystem *channel* command)
      (cl-pnet-ssh:ssh-channel-exec *channel* command))
  (start-input *channel*))

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
            (dynamic (cl-pnet-ssh:ssh-config-options-dynamic-forwards options))
            (tty (cl-pnet-ssh:ssh-config-options-request-tty options)))
        (when remote
          (fail "RemoteForward in the ssh config is not supported: ~A"
                (first (reverse remote))))
        (when dynamic
          (fail "DynamicForward in the ssh config is not supported: ~A"
                (first (reverse dynamic))))
        ;; -T on the command line answers this before the file does.
        (unless (member (getf *options* :request-tty)
                        '(:no "no" "false" :off) :test #'equal)
          (when (and tty
                     (not (member tty '("no" "false" "off") :test #'string=)))
            (fail "RequestTTY in the ssh config is not supported: ~A" tty)))))))

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

(defun start-client (host command)
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
       (t (start-session client command))))
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
          (when (getf *options* :help)
            (usage *standard-output*)
            (uiop:quit 0))
          (when (getf *options* :version)
            (print-version)
            (uiop:quit 0))
          (apply-command-line-options)
          (check-supported-options)
          (start-logging)
          (when (getf *options* :query)
            (print-query (getf *options* :query)))
          (unless destination
            (usage)
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
                (start-client host (join-command command))
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
