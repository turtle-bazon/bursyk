(in-package #:burs)

;;;; State shared by the platform layers and the session logic.  It loads
;;;; before either terminal backend, so the POSIX and Windows files can see
;;;; the options they consult and the handles they save.

(defparameter +burs-version+ "0.0.2.33")

(defvar *status* nil
  "The exit status the remote command reported, or NIL before it does.")
(defvar *channel* nil)
(defvar *client* nil
  "The connected client, kept so FINISH can shut it down before quitting.")
(defvar *stdin-watcher* nil
  "The POSIX readable watch on stdin, or NIL.")
(defvar *stdin-thread* nil
  "The Windows thread that moves stdin to the channel, or NIL.")
(defvar *stdin-stopped* nil
  "True once the Windows stdin thread must stop posting input.")
(defvar *finishing* nil
  "True once FINISH is tearing down, so nested close callbacks do not quit early.")
(defvar *log-stream* nil
  "Where -v writes, or NIL when logging is off.")
(defvar *forwards* nil
  "Local forwarding listeners, in the order they were started.")
(defvar *remote-forwards* nil
  "Remote forwarding requests, in the order they were sent.")
(defvar *dynamic-forwards* nil
  "SOCKS proxy listeners, in the order they were started.")
(defvar *socks-sessions* (make-hash-table :test #'eq :size 16)
  "SOCKS handshakes in progress, keyed by their CL-PNET connection.")
(defvar *tunnels* (make-hash-table :test #'eq :size 16)
  "Accepted forwarding connections, keyed by their CL-PNET connection.")
(defvar *pty-timer* nil
  "The watchdog that sends pty-req once the session channel is open.")
(defvar *terminal-saved* nil
  "The terminal settings STTY -G reported, or NIL when not in raw mode.")
(defvar *winch* nil
  "The SIGWINCH watcher, or Windows console-size timer, forwarding resizes.")

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
