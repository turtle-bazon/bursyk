(defpackage #:burs
  (:use #:cl)
  (:export #:main))

(in-package #:burs)

;;;; A small SSH client command line over cl-pnet-ssh.  It runs one command
;;;; on the remote host and streams its output and stdin, without blocking the
;;;; event loop: stdin is watched with CL-PNET:FD-WATCH, never read in a loop.

(defvar *status* nil
  "The exit status the remote command reported, or NIL before it does.")
(defvar *channel* nil)
(defvar *stdin-watcher* nil)
(defvar *send-env* nil
  "Environment names from ssh_config's SendEnv to forward per channel.")

(defvar *options*
  '(:port nil :user nil :identity nil :config nil :known-hosts nil
    :policy nil :agent nil :options nil :jump nil :proxy-command nil)
  "The command line as parsed, before ~/.ssh/config is applied.")

(defun usage ()
  (format *error-output*
          "usage: burs [-p PORT] [-l USER] [-i KEY] [-J JUMP] [-o OPTION]...~%~
           ~7@T[-F CONFIG] user@host [command [args...]]~%")
  (finish-output *error-output*))

(defun fail (format-string &rest arguments)
  (format *error-output* "burs: ~?~%" format-string arguments)
  (finish-output *error-output*)
  (uiop:quit 2))

;;; ---- Command line ----

(defun split-destination (destination)
  "DESTINATION as (VALUES HOST USER), splitting USER@HOST at the first @."
  (let ((at (position #\@ destination)))
    (if at
        (values (subseq destination (1+ at)) (subseq destination 0 at))
        (values destination nil))))

(defun option-key (name)
  "The option NAME selects, or NIL.

Short options are case-sensitive, as in SSH itself: -p is the port, -F the
config file, and a -P or -f this client does not have is an error."
  (let ((long (and (> (length name) 2)
                   (string= "--" name :end1 2 :end2 2)
                   (string-downcase name))))
    (cond ((string= name "-p") :port)
          ((string= name "-l") :user)
          ((string= name "-i") :identity)
          ((string= name "-J") :jump)
          ((string= name "-F") :config)
          ((string= name "-o") :options)
          ((string= name "-a") :agent)
          ((equal long "--port") :port)
          ((equal long "--user") :user)
          ((equal long "--identity") :identity)
          ((equal long "--jump") :jump)
          ((equal long "--config") :config)
          ((equal long "--option") :options)
          ((equal long "--agent") :agent)
          (t nil))))

(defun record-option (key value)
  (case key
    (:identity (push value (getf *options* :identity)))
    (:options (push value (getf *options* :options)))
    (t (setf (getf *options* key) value))))

(defun parse-arguments (arguments)
  "Fill *OPTIONS* from ARGUMENTS; return (VALUES DESTINATION COMMAND)."
  (let ((destination nil)
        (command nil))
    (loop
      (let ((argument (first arguments)))
        (cond
          ((null arguments)
           (return))
          ((string= argument "--")
           (setf arguments (rest arguments)
                 destination (first arguments)
                 command (rest arguments))
           (return))
          ((option-key argument)
           (let ((value (second arguments)))
             (unless value (fail "~A needs a value" argument))
             (record-option (option-key argument) value)
             (setf arguments (cddr arguments))))
          ((and (> (length argument) 1) (char= (char argument 0) #\-))
           (fail "unknown option ~A" argument))
          (t
           (setf destination argument
                 command (rest arguments))
           (return)))))
    (values destination command)))

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

(defun config-options (host)
  "The ssh_config options that apply to HOST, or NIL."
  (let ((path (or (getf *options* :config)
                  (merge-pathnames ".ssh/config" (user-homedir-pathname))))
        (result nil))
    (let ((config (cl-pnet-ssh:ssh-config-load path)))
      (when config
        (cl-pnet-ssh:ssh-config-resolve
         config host
         :exec-matcher #'match-exec
         :on-options (lambda (options) (setf result options))
         :on-error (lambda (condition)
                     (format *error-output* "burs: config: ~A~%" condition)))))
    result))

(defun config-agent (config)
  "The IdentityAgent CONFIG names, in MAKE-SSH-CLIENT's terms.

T means the environment's SSH_AUTH_SOCK, which is what the libssh backend
uses in any case; a path is the pure backend's socket."
  (let ((value (and config
                    (cl-pnet-ssh:ssh-config-options-identity-agent config))))
    (case value
      ((nil :none) nil)
      (:environment t)
      (t value))))

(defun config-known-hosts (config)
  "Every known-hosts file CONFIG names, user's first, or NIL."
  (when config
    (append (cl-pnet-ssh:ssh-config-options-known-hosts config)
            (cl-pnet-ssh:ssh-config-options-global-known-hosts config))))

;;; ---- ProxyJump ----

(defun split-jump-list (value)
  "The comma-separated ProxyJump VALUE as a list of host strings.

The literal NONE, and an empty value, mean a direct connection."
  (let ((text (string-trim '(#\Space #\Tab) value)))
    (if (or (zerop (length text)) (string-equal text "none"))
        nil
        (loop with start = 0
              for comma = (position #\, text :start start)
              collect (string-trim '(#\Space #\Tab)
                                   (subseq text start comma))
              while comma
              do (setf start (1+ comma))))))

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

(defun port-string (text)
  "TEXT as a port number, or NIL unless it is all digits."
  (when text
    (multiple-value-bind (value end) (parse-integer text :junk-allowed t)
      (when (and value (= end (length text))) value))))

(defun jump-host (text)
  "One ProxyJump entry as the plist MAKE-SSH-CLIENT needs for it.

The jump host's own Host block supplies the connection details; the
command line still wins for identity, agent and known-hosts, as it does
for the destination."
  (multiple-value-bind (destination user) (split-destination text)
    (multiple-value-bind (host port-text) (split-host-port destination)
      (let ((config (config-options host)))
        (list :host host
              :connect-host (or (and config
                                     (cl-pnet-ssh:ssh-config-options-hostname
                                      config))
                                host)
              :port (or (port-string port-text)
                        (and config (cl-pnet-ssh:ssh-config-options-port config))
                        22)
              :user (or user
                        (and config (cl-pnet-ssh:ssh-config-options-user config))
                        (cl-pnet-ssh:ssh-default-user))
              :identity (or (getf *options* :identity)
                            (and config
                                 (reverse
                                  (cl-pnet-ssh:ssh-config-options-identity-files
                                   config))))
              :known-hosts (or (getf *options* :known-hosts)
                               (config-known-hosts config))
              :agent (or (getf *options* :agent) (config-agent config))
              :policy (or (getf *options* :policy) (config-policy config)))))))

(defun proxy-jumps (config)
  "The jump host plists the config and command line ask for, in order."
  (mapcar #'jump-host
          (split-jump-list
           (or (getf *options* :jump)
               (and config (cl-pnet-ssh:ssh-config-options-proxy-jump config))
               ""))))

(defun reject-unsupported-proxy (config)
  "Refuse a config that asks for a command this client cannot run.

ProxyJump is handled with real forward channels; ProxyCommand would need a
local process in place of the socket, and silently ignoring it would connect
somewhere the user did not ask for."
  (let ((command (or (getf *options* :proxy-command)
                     (and config
                          (cl-pnet-ssh:ssh-config-options-proxy-command
                           config)))))
    (when command
      (fail "ProxyCommand is not supported (~A)" command))))

(defun config-policy (config)
  "The host-key policy CONFIG asks for, as the client understands it."
  (let ((value (and config
                    (cl-pnet-ssh:ssh-config-options-strict-host-key-checking
                     config))))
    (cond ((null value) :strict)
          ((member value '("no" "off") :test #'string=) :insecure)
          ((string= value "accept-new") :accept-new)
          (t :strict))))

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
    ;; Everything else is accepted and ignored, as SSH itself tolerates
    ;; keywords a newer client wrote.
    (t nil)))

(defun apply-command-line-options ()
  (dolist (option (nreverse (getf *options* :options)))
    (let ((equals (position #\= option)))
      (when equals
        (command-line-option (subseq option 0 equals)
                             (subseq option (1+ equals)))))))

;;; ---- Session ----

(defun write-octets (stream octets)
  (write-string (cl-pnet-ssh:ssh-octets-string octets) stream)
  (finish-output stream))

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

(defun finish (status)
  (stop-stdin)
  (finish-output *standard-output*)
  (finish-output *error-output*)
  (uiop:quit (or status 255)))

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
  (dolist (name *send-env*)
    (let ((value (uiop:getenv name)))
      (when value
        (cl-pnet-ssh:ssh-channel-env *channel* name value))))
  (cl-pnet-ssh:ssh-channel-exec *channel* command)
  (start-stdin *channel*))

;;; ---- Entry point ----

(defun remote-shell ()
  (or (uiop:getenv "SHELL") "/bin/sh"))

(defun join-command (arguments)
  (if arguments
      (format nil "~{~A~^ ~}" arguments)
      (remote-shell)))

;;; ---- ProxyJump forwarding ----

(defstruct (tunnel (:constructor %make-tunnel))
  jump host port listener connection channel)

(defvar *tunnels* nil
  "Every live loopback forward, so a shutdown can close them all.")

(defun tunnel-shut (tunnel)
  "Close both ends of TUNNEL once, whichever end reported first."
  (when (tunnel-listener tunnel)
    (cl-pnet:close-listener (tunnel-listener tunnel))
    (setf (tunnel-listener tunnel) nil))
  (when (tunnel-connection tunnel)
    (cl-pnet:close-connection (tunnel-connection tunnel))
    (setf (tunnel-connection tunnel) nil))
  (when (tunnel-channel tunnel)
    (let ((channel (tunnel-channel tunnel)))
      (setf (tunnel-channel tunnel) nil)
      (cl-pnet-ssh:ssh-channel-close channel))))

(defun tunnel-write (tunnel data)
  "Target bytes from the jump channel back to the target client."
  (when (tunnel-connection tunnel)
    (cl-pnet:send-data (tunnel-connection tunnel) data)))

(defun tunnel-accept (tunnel connection)
  "The target client connected: open the forward through the jump host."
  (setf (tunnel-connection tunnel) connection)
  (when (tunnel-listener tunnel)
    (cl-pnet:close-listener (tunnel-listener tunnel))
    (setf (tunnel-listener tunnel) nil))
  (setf (tunnel-channel tunnel)
        (cl-pnet-ssh:ssh-open-direct-tcpip
         (tunnel-jump tunnel) (tunnel-host tunnel) (tunnel-port tunnel)
         :on-data (lambda (channel data kind)
                    (declare (ignore channel kind))
                    (tunnel-write tunnel data))
         :on-eof (lambda (channel)
                   (declare (ignore channel))
                   (tunnel-shut tunnel))
         :on-close (lambda (channel reason)
                     (declare (ignore channel reason))
                     (tunnel-shut tunnel))
         :on-error (lambda (channel condition)
                     (declare (ignore channel))
                     (format *error-output* "burs: tunnel: ~A~%" condition)
                     (tunnel-shut tunnel)))))

(defun tunnel-read (tunnel data)
  "Bytes from the target client, or NIL at its EOF."
  (cond
    ((and data (tunnel-channel tunnel))
     (cl-pnet-ssh:ssh-channel-write (tunnel-channel tunnel) data))
    ((and (null data) (tunnel-channel tunnel))
     (cl-pnet-ssh:ssh-channel-eof (tunnel-channel tunnel)))
    (t nil)))

(defun start-tunnel (jump host port create-client)
  "Forward HOST:PORT through JUMP and hand CREATE-CLIENT the loopback port.

Only 127.0.0.1 is bound, one connection is accepted, and the listener closes
as soon as the target client arrives; a fresh tunnel is made per jump hop."
  (let* ((tunnel (%make-tunnel :jump jump :host host :port port))
         (listener
           (cl-pnet:make-tcp-listener
            "127.0.0.1" 0
            :on-accept (lambda (connection) (tunnel-accept tunnel connection))
            :read-cb (lambda (connection data)
                       (declare (ignore connection))
                       (tunnel-read tunnel data))
            :on-error (lambda (status)
                        (declare (ignore status))
                        (format *error-output*
                                "burs: cannot listen for the tunnel~%")
                        (finish 255)))))
    (unless listener
      (fail "cannot listen for the ProxyJump tunnel"))
    (setf (tunnel-listener tunnel) listener)
    (push tunnel *tunnels*)
    (funcall create-client (cl-pnet:listener-port listener))))

;;; ---- The target client ----

(defun client-parameters (host)
  "Everything MAKE-SSH-CLIENT needs for HOST after config is applied."
  (let ((config (config-options host)))
    (list :host host
          :config config
          :user (or (getf *options* :user)
                    (and config (cl-pnet-ssh:ssh-config-options-user config))
                    (cl-pnet-ssh:ssh-default-user))
          :port (or (and (getf *options* :port)
                         (parse-integer (getf *options* :port)))
                    (and config (cl-pnet-ssh:ssh-config-options-port config))
                    22)
          :connect-host (or (and config
                                 (cl-pnet-ssh:ssh-config-options-hostname config))
                            host)
          :identity (or (getf *options* :identity)
                        (and config
                             (reverse
                              (cl-pnet-ssh:ssh-config-options-identity-files
                               config))))
          :known-hosts (or (getf *options* :known-hosts)
                           (config-known-hosts config))
          :agent (let ((chosen (getf *options* :agent)))
                   (if chosen chosen (config-agent config)))
          :policy (or (getf *options* :policy) (config-policy config)))))

(defun launch-client (parameters command connect-host connect-port)
  "Connect the destination described by PARAMETERS and run COMMAND on it.

CONNECT-HOST and CONNECT-PORT are NIL for a direct connection; a ProxyJump
passes the loopback listener there while the host key is still checked under
the destination's own name and port."
  (let ((host (getf parameters :host)))
    (cl-pnet-ssh:make-ssh-client
     host
     :connect-host (or connect-host (getf parameters :connect-host))
     :connect-port (or connect-port (getf parameters :port))
     :port (getf parameters :port)
     :user (getf parameters :user)
     :private-key (getf parameters :identity)
     :agent (getf parameters :agent)
     :known-hosts (getf parameters :known-hosts)
     :host-key-policy (getf parameters :policy)
     :on-open (lambda (client) (start-session client command))
     :on-error (lambda (client condition)
                 (declare (ignore client))
                 (format *error-output* "burs: ~A~%" condition)
                 (finish 255))
     :on-close (lambda (client reason)
                 (declare (ignore client reason))
                 (finish *status*)))))

(defun launch-jump (hop connect-host connect-port on-open)
  "Connect one jump HOP and call ON-OPEN once it is authenticated."
  (cl-pnet-ssh:make-ssh-client
   (getf hop :host)
   :connect-host connect-host
   :connect-port connect-port
   :port (getf hop :port)
   :user (getf hop :user)
   :private-key (getf hop :identity)
   :agent (getf hop :agent)
   :known-hosts (getf hop :known-hosts)
   :host-key-policy (getf hop :policy)
   :on-open (lambda (client) (funcall on-open client))
   :on-error (lambda (client condition)
               (declare (ignore client))
               (format *error-output* "burs: jump host: ~A~%" condition)
               (finish 255))
   :on-close (lambda (client reason)
               (declare (ignore client reason))
               ;; The destination's own callbacks decide the exit status.
               nil)))

(defun start-jump-chain (hops target-host target-port launch)
  "Reach TARGET-HOST:TARGET-PORT through HOPS, then call LAUNCH with a port.

Each hop is reached through the tunnel the previous hop opens, which is the
same thing a comma-separated ProxyJump means in SSH."
  (labels ((link (remaining connect-host connect-port)
             (let ((hop (first remaining)))
               (launch-jump
                hop connect-host connect-port
                (lambda (client)
                  (if (rest remaining)
                      (let ((next (second remaining)))
                        (start-tunnel
                         client
                         (getf next :connect-host) (getf next :port)
                         (lambda (local-port)
                           (link (rest remaining) "127.0.0.1" local-port))))
                      (start-tunnel
                       client target-host target-port
                       (lambda (local-port)
                         (funcall launch "127.0.0.1" local-port)))))))))
    (let ((first-hop (first hops)))
      (link hops (getf first-hop :connect-host) (getf first-hop :port)))))

(defun start-client (host command)
  (let* ((parameters (client-parameters host))
         (config (getf parameters :config))
         (jumps (proxy-jumps config)))
    (reject-unsupported-proxy config)
    (setf *send-env* (and config
                          (cl-pnet-ssh:ssh-config-options-send-env config)))
    (if jumps
        (start-jump-chain
         jumps (getf parameters :connect-host) (getf parameters :port)
         (lambda (connect-host connect-port)
           (launch-client parameters command connect-host connect-port)))
        (launch-client parameters command nil nil))))

(defun main ()
  "Entry point for the BURS program."
  (handler-case
      (let ((arguments (uiop:command-line-arguments)))
        (when (member (first arguments) '("-h" "--help") :test #'string=)
          (usage)
          (uiop:quit 0))
        (multiple-value-bind (destination command)
            (parse-arguments arguments)
          (unless destination
            (usage)
            (uiop:quit 2))
          (apply-command-line-options)
          (multiple-value-bind (host user) (split-destination destination)
            (when user (setf (getf *options* :user) user))
            (start-client host (join-command command))
            (cl-pnet:event-loop-run)
            (finish *status*))))
    (error (condition)
      (when (uiop:getenv "BURS_DEBUG")
        (sb-debug:print-backtrace :count 40 :stream *error-output*))
      (format *error-output* "burs: ~A~%" condition)
      (uiop:quit 1))))
