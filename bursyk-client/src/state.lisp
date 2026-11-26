(in-package #:burs)

;;;; State shared by the platform layers and the session logic.  It loads
;;;; before either terminal backend, so the POSIX and Windows files can see
;;;; the options they consult and the handles they save.

(defparameter +burs-version+ "0.0.2.86")

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
(defvar *escape-break-function* nil)
(defvar *escape-info-function* nil)
(defvar *escape-rekey-function* nil)
(defvar *escape-log-level-function* nil)
(defvar *escape-suspend-function* nil)
(defvar *escape-background-function* nil)

(defun escape-write-command (character)
  "Echo the escape sequence ssh shows before a command's output.

The session terminal is raw, so the line ending has to be spelled out."
  (format *error-output* "~C~C~C~C" *escape-char* character
          #\Return #\Newline)
  (finish-output *error-output*))

(defun escape-filter (octets)
  "Return OCTETS with ssh escape sequences consumed.

The command callbacks are set by the application: they print help, list
forwards, disconnect, send a break, show connection information, rekey,
change the log level, suspend, or open the escape command line."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                           :adjustable t :fill-pointer 0)))
    (loop for octet across octets
          do (cond
               (*escape-pending*
                (setf *escape-pending* nil)
                (case (code-char octet)
                  (#\# (escape-write-command #\#)
                        (when *escape-forwards-function*
                          (funcall *escape-forwards-function*))
                        (setf *escape-line-start* t))
                  (#\? (escape-write-command #\?)
                        (when *escape-help-function*
                          (funcall *escape-help-function*))
                        (setf *escape-line-start* t))
                  (#\. (when *escape-disconnect-function*
                          (funcall *escape-disconnect-function*)))
                  (#\B (escape-write-command #\B)
                        (when *escape-break-function*
                          (funcall *escape-break-function*))
                        (setf *escape-line-start* t))
                  (#\I (escape-write-command #\I)
                        (when *escape-info-function*
                          (funcall *escape-info-function*))
                        (setf *escape-line-start* t))
                  (#\R (when *escape-rekey-function*
                          (funcall *escape-rekey-function*))
                        (setf *escape-line-start* t))
                  (#\V (when *escape-log-level-function*
                          (funcall *escape-log-level-function* -1))
                        (setf *escape-line-start* t))
                  (#\v (when *escape-log-level-function*
                          (funcall *escape-log-level-function* 1))
                        (setf *escape-line-start* t))
                  (#.(code-char 26)
                   (when *escape-suspend-function*
                     (funcall *escape-suspend-function*))
                   (setf *escape-line-start* t))
                  (#\& (if *escape-background-function*
                           (progn
                             (funcall *escape-background-function*)
                             (setf *escape-line-start* t))
                           (progn
                             (vector-push-extend
                              (char-code *escape-char*) out)
                             (vector-push-extend octet out)
                             (setf *escape-line-start*
                                   (member octet '(10 13))))))
                  (#\~ (vector-push-extend (char-code *escape-char*) out)
                        (setf *escape-line-start* nil))
                  (#\C (if *escape-commandline-function*
                           (funcall *escape-commandline-function*)
                           (format *error-output* "commandline disabled~C~C"
                                   #\Return #\Newline))
                        (setf *escape-line-start* t))
                  (t
                   ;; An unrecognised sequence is not an error: ssh sends
                   ;; the escape character and the one after it to the peer
                   ;; unchanged.
                   (vector-push-extend (char-code *escape-char*) out)
                   (vector-push-extend octet out)
                   (setf *escape-line-start* (member octet '(10 13))))))
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
  "The thread that moves an unwatchable stdin to the channel, or NIL.")
(defvar *stdin-stopped* nil
  "True once the stdin thread must stop posting input.")
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
;;; ObscureKeystrokeTiming.  The application owns stdin, and ssh's interval
;;; quantisation lives with it: keystrokes on a pty are held to fixed
;;; intervals instead of being written as they arrive.
(defvar *pty-channel* nil
  "The session channel that asked for a pty, or NIL for a plain session.")
(defvar *session-loop-started* nil
  "True once authentication succeeded and the session loop is set up.

client_loop() prints the verbose byte summary when it returns; a failure
before it starts (an authentication refusal, for example) does not.")
(defvar *session-loop-start* nil
  "CL's internal real-time clock when the session loop began.")
(defvar *keystroke-timer* nil
  "The one-shot timer that releases the next quantised keystroke.")
(defvar *keystroke-active* nil
  "True while keystroke timing is being hidden.")
(defvar *keystroke-channel* nil
  "The channel the active quantisation belongs to.")
(defvar *keystroke-pending*
  (make-array 0 :element-type '(unsigned-byte 8)
                :adjustable t :fill-pointer 0)
  "Keystrokes waiting for the next interval.")
(defvar *keystroke-chaff-until* 0
  "When the idle window that keeps timing hidden ends.")
(defvar *keystroke-rate-fuzz* 0
  "This session's random share of the interval, as ssh perturbs it.")
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
    :tunnel nil :tunnel-device nil :x11-forward nil :escape-char nil)
  "The command line as parsed, before ~/.ssh/config is applied.")
