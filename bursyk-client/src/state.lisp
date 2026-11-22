(in-package #:burs)

;;;; State shared by the platform layers and the session logic.  It loads
;;;; before either terminal backend, so the POSIX and Windows files can see
;;;; the options they consult and the handles they save.

(defparameter +burs-version+ "0.0.2.70")

(defvar *background-child* nil
  "True in the re-executed child that will signal authentication success.")
(defvar *background-requested* nil)

;;; Interactive escape handling.  The character is active only in a pty
;;; session, and only at the start of a line, as in ssh.
(defvar *escape-char* nil)
(defvar *escape-pending* nil)
(defvar *escape-line-start* t)
(defvar *escape-help-function* nil)
(defvar *escape-forwards-function* nil)
(defvar *escape-disconnect-function* nil)
(defvar *escape-commandline-function* nil)

(defun escape-filter (octets)
  "Return OCTETS with ssh escape sequences consumed.

The command callbacks are set by the application: they print help, list
forwards, disconnect, or open the escape command line."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                           :adjustable t :fill-pointer 0)))
    (loop for octet across octets
          do (cond
               (*escape-pending*
                (setf *escape-pending* nil)
                (case (code-char octet)
                  (#\# (when *escape-forwards-function*
                          (funcall *escape-forwards-function*))
                        (setf *escape-line-start* t))
                  (#\? (when *escape-help-function*
                          (funcall *escape-help-function*))
                        (setf *escape-line-start* t))
                  (#\. (when *escape-disconnect-function*
                          (funcall *escape-disconnect-function*)))
                  (#\~ (vector-push-extend (char-code *escape-char*) out)
                        (setf *escape-line-start* nil))
                  (#\C (when *escape-commandline-function*
                          (funcall *escape-commandline-function*))
                        (setf *escape-line-start* t))
                  (t
                   (format *error-output* "Unknown escape sequence '~C'.~%"
                           (code-char octet))
                   (setf *escape-line-start* t))))
               ((and *escape-char*
                     *escape-line-start*
                     (= octet (char-code *escape-char*)))
                (setf *escape-pending* t))
               (t
                (vector-push-extend octet out)
                (setf *escape-line-start* (member octet '(10 13))))))
    out))

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
    :background nil :background-child nil :control-master-daemon nil
    :control-master nil :control-path nil :control-command nil
    :host nil :no-control-persist nil
    :pkcs11 nil :bind-interface nil :bind-address nil :gssapi-auth nil
    :tunnel nil :x11-forward nil :escape-char nil)
  "The command line as parsed, before ~/.ssh/config is applied.")
