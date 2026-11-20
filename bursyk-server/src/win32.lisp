(in-package #:bursyk-server)

;;;; The Windows child bridge.
;;;;
;;;; libuv's FD-WATCH is socket-only on Windows, so a child is fed and
;;;; drained by blocking I/O threads instead.  Those threads never touch the
;;;; SSH connection directly: they hand their data to CALL-ON-LOOP, whose
;;;; queue keeps the order the bytes were read, and the event loop does every
;;;; write to the channel.

(defstruct bridge
  channel
  pid
  (input-handle nil)
  (output-handle nil)
  (stderr-handle nil)
  (console nil)
  (pty nil)
  (pending (make-array 0 :element-type '(unsigned-byte 8)
                         :adjustable t :fill-pointer 0))
  (lock (bt:make-lock "bursyk-server bridge"))
  (condition (bt:make-condition-variable :name "bursyk-server bridge"))
  (input-open t)
  (input-eof nil)
  (finished nil)
  (readers 0)
  (exit-status 0)
  writer-thread
  output-thread
  stderr-thread
  status-thread)

(defun bridge-attach (bridge)
  "Route the channel's callbacks to BRIDGE."
  (let ((channel (bridge-channel bridge)))
    (setf (cl-pnet-ssh:ssh-server-channel-on-data channel)
          (lambda (channel data kind)
            (declare (ignore channel kind))
            (bridge-on-data bridge data)))
    (setf (cl-pnet-ssh:ssh-server-channel-on-eof channel)
          (lambda (channel)
            (declare (ignore channel))
            (bridge-on-eof bridge)))
    (setf (cl-pnet-ssh:ssh-server-channel-on-close channel)
          (lambda (channel)
            (declare (ignore channel))
            (bridge-abort bridge)))))

(defun bridge-on-data (bridge octets)
  "Queue OCTETS and wake the writer thread."
  (unless (bridge-finished bridge)
    (bt:with-lock-held ((bridge-lock bridge))
      (when (bridge-input-open bridge)
        (let ((pending (bridge-pending bridge)))
          (loop for octet across octets
                do (vector-push-extend octet pending)))
        (bt:condition-notify (bridge-condition bridge))))))

(defun bridge-on-eof (bridge)
  "The client sent EOF: let the child see it once the queue drains."
  (unless (bridge-finished bridge)
    (bt:with-lock-held ((bridge-lock bridge))
      (setf (bridge-input-eof bridge) t)
      (bt:condition-notify (bridge-condition bridge)))))

(defun bridge-copy-octets (buffer count)
  (let ((octets (make-array count :element-type '(unsigned-byte 8))))
    (loop for index below count
          do (setf (aref octets index)
                   (cffi:mem-aref buffer :unsigned-char index)))
    octets))

(defun bridge-write-all (handle octets)
  "Write every octet of OCTETS to HANDLE; NIL when the pipe is gone."
  (cffi:with-foreign-object (buffer :unsigned-char (length octets))
    (loop for index below (length octets)
          do (setf (cffi:mem-aref buffer :unsigned-char index)
                   (aref octets index)))
    (cffi:with-foreign-object (written :unsigned-long)
      (loop with offset = 0
            while (< offset (length octets))
            do (let ((count (min 65536 (- (length octets) offset))))
                 (unless (plusp (c-write-file handle
                                              (cffi:inc-pointer buffer offset)
                                              count written (cffi:null-pointer)))
                   (return-from bridge-write-all nil))
                 (let ((wrote (cffi:mem-ref written :unsigned-long)))
                   (when (zerop wrote)
                     (return-from bridge-write-all nil))
                   (incf offset wrote)))))
    t))

(defun bridge-writer-loop (bridge)
  "Move queued client input to the child, and close it at EOF."
  (unwind-protect
       (loop
         (let ((chunk nil)
               (close-input nil))
           (bt:with-lock-held ((bridge-lock bridge))
             (loop while (and (bridge-input-open bridge)
                              (not (bridge-input-eof bridge))
                              (zerop (fill-pointer (bridge-pending bridge))))
                   do (bt:condition-wait (bridge-condition bridge)
                                         (bridge-lock bridge)))
             (cond
               ((not (bridge-input-open bridge)) (return))
               ((and (zerop (fill-pointer (bridge-pending bridge)))
                     (bridge-input-eof bridge))
                (setf close-input t))
               (t
                (let ((pending (bridge-pending bridge)))
                  (setf chunk (make-array (fill-pointer pending)
                                          :element-type '(unsigned-byte 8)))
                  (replace chunk pending)
                  (setf (fill-pointer pending) 0)))))
           (when chunk
             (unless (bridge-write-all (bridge-input-handle bridge) chunk)
               (bt:with-lock-held ((bridge-lock bridge))
                 (setf (bridge-input-open bridge) nil))
               (return)))
           (when close-input
             ;; Closing the write end is how a Windows child sees EOF; a
             ;; ConPTY receives the same end-of-input from the console.
             (close-child-fd (bridge-input-handle bridge))
             (setf (bridge-input-handle bridge) nil)
             (bt:with-lock-held ((bridge-lock bridge))
               (setf (bridge-input-open bridge) nil))
             (return))))
    (close-child-fd (bridge-input-handle bridge))))

(defun bridge-reader-loop (bridge handle stderr-p)
  "Drain HANDLE until it breaks, posting each chunk to the event loop."
  (cffi:with-foreign-object (buffer :unsigned-char 65536)
    (cffi:with-foreign-object (read :unsigned-long)
      (unwind-protect
           (loop
             (when (bridge-finished bridge) (return))
             (unless (plusp (c-read-file handle buffer 65536 read
                                         (cffi:null-pointer)))
               (return))
             (let ((count (cffi:mem-ref read :unsigned-long)))
               (when (zerop count) (return))
               (let ((octets (bridge-copy-octets buffer count)))
                 (cl-pnet:call-on-loop
                  (lambda ()
                    (unless (bridge-finished bridge)
                      (let ((channel (bridge-channel bridge)))
                        (unless (eq (cl-pnet-ssh:ssh-server-channel-state channel)
                                    :closed)
                          (if stderr-p
                              (cl-pnet-ssh:ssh-server-channel-write-stderr
                               channel octets)
                              (cl-pnet-ssh:ssh-server-channel-write
                               channel octets))))))))))
        (close-child-fd handle)
        (bt:with-lock-held ((bridge-lock bridge))
          (decf (bridge-readers bridge)))))))

(defun process-exit-status (process)
  (cffi:with-foreign-object (code :unsigned-long)
    (if (plusp (c-get-exit-code-process process code))
        (cffi:mem-ref code :unsigned-long)
        127)))

(defun bridge-report (bridge status)
  "Send the exit status and close the channel, once."
  (unless (bridge-finished bridge)
    (setf (bridge-finished bridge) t
          (bridge-exit-status bridge) status)
    (let ((channel (bridge-channel bridge)))
      (unless (eq (cl-pnet-ssh:ssh-server-channel-state channel) :closed)
        (ignore-errors
         (cl-pnet-ssh:ssh-server-channel-exit channel status)
         (cl-pnet-ssh:ssh-server-channel-close channel))))
    (collect-child (bridge-pid bridge))))

(defun child-forget-console (pid)
  "Drop PID's pseudoconsole handle without closing it again."
  (let ((handles (gethash pid *children*)))
    (when handles
      (setf (third handles) nil))))

(defun bridge-wait-readers (bridge &optional (seconds 5))
  "Wait up to SECONDS for the reader threads to see EOF.

The direct child's exit is the session's end, but a survivor it left behind
can keep an inherited pipe open.  A bounded wait flushes what is already
there without letting such a survivor hang the channel."
  (let ((deadline (+ (get-internal-real-time)
                     (* seconds internal-time-units-per-second))))
    (loop
      (bt:with-lock-held ((bridge-lock bridge))
        (when (zerop (bridge-readers bridge))
          (return t)))
      (when (> (get-internal-real-time) deadline)
        (return nil))
      (sleep 0.01))))

(defun bridge-status-loop (bridge)
  "Wait for the child, close its console, then let the readers finish.

ClosePseudoConsole may emit a final frame, so it must run before the output
reader is allowed to see the broken pipe; the reader thread is already
draining it."
  (let ((handles (child-handles (bridge-pid bridge))))
    (when handles
      (let ((process (first handles))
            (console (third handles)))
        (when process
          (c-wait-for-single-object process +infinite+))
        (let ((status (if process (process-exit-status process) 127)))
          (when console
            (c-close-pseudo-console console)
            (child-forget-console (bridge-pid bridge)))
          (bridge-wait-readers bridge)
          (setf (bridge-console bridge) nil)
          (if (bridge-finished bridge)
              (collect-child (bridge-pid bridge))
              (unless (cl-pnet:call-on-loop
                       (lambda () (bridge-report bridge status)))
                (collect-child (bridge-pid bridge)))))))))

(defun bridge-start (bridge)
  "Start the writer, output readers and the status waiter."
  (setf (bridge-readers bridge) (if (bridge-stderr-handle bridge) 2 1)
        (bridge-writer-thread bridge)
        (bt:make-thread (lambda () (bridge-writer-loop bridge))
                        :name "bursyk-server child stdin")
        (bridge-output-thread bridge)
        (bt:make-thread
         (lambda () (bridge-reader-loop bridge (bridge-output-handle bridge) nil))
         :name "bursyk-server child stdout"))
  (when (bridge-stderr-handle bridge)
    (setf (bridge-stderr-thread bridge)
          (bt:make-thread
           (lambda () (bridge-reader-loop bridge (bridge-stderr-handle bridge) t))
           :name "bursyk-server child stderr")))
  (setf (bridge-status-thread bridge)
        (bt:make-thread (lambda () (bridge-status-loop bridge))
                        :name "bursyk-server child status"))
  bridge)

(defun bridge-abort (bridge)
  "End the child because its channel went away."
  (unless (bridge-finished bridge)
    (setf (bridge-finished bridge) t)
    (bt:with-lock-held ((bridge-lock bridge))
      (setf (bridge-input-open bridge) nil)
      (bt:condition-notify (bridge-condition bridge)))
    ;; The job object kills the whole tree; the status thread closes the
    ;; console and reaps the handles once the readers see the broken pipes.
    (kill-child-group (bridge-pid bridge))))

(defun bridge-resize (bridge columns rows)
  "Resize BRIDGE's pseudoconsole, if it has one."
  (when (and bridge (bridge-pty bridge))
    (set-child-window (bridge-console bridge) rows columns)))

(defun attach-bridge (channel bridge)
  (declare (ignore channel))
  (bridge-attach bridge)
  (bridge-start bridge)
  bridge)

(defun start-command (channel command)
  "Run COMMAND as a child, on a ConPTY when the client asked for a pty."
  (let ((environment (session-environment channel)))
    (if (channel-pty-p channel)
        (multiple-value-bind (pid input output console)
            (spawn-pty-shell command (windows-shell)
                             :environment environment
                             :rows (channel-rows channel)
                             :columns (channel-columns channel))
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :input-handle input :output-handle output
                        :console console :pty t)))
        (multiple-value-bind (pid input output error)
            (spawn-shell command :environment environment)
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :input-handle input :output-handle output
                        :stderr-handle error))))))

(defun start-program (channel program arguments)
  "Run PROGRAM with ARGUMENTS on CHANNEL, without shell interpretation."
  (let ((environment (session-environment channel)))
    (if (channel-pty-p channel)
        (multiple-value-bind (pid input output console)
            (spawn-pty-program program arguments
                               :environment environment
                               :rows (channel-rows channel)
                               :columns (channel-columns channel))
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :input-handle input :output-handle output
                        :console console :pty t)))
        (multiple-value-bind (pid input output error)
            (spawn-program program arguments :environment environment)
          (attach-bridge
           channel
           (make-bridge :channel channel :pid pid
                        :input-handle input :output-handle output
                        :stderr-handle error))))))

(defun start-login-shell (channel)
  "Run the login shell, on the pty when one was requested.

A non-pty login shell keeps its stdout and stderr separate, as sshd does for
-T; a pty merges them, as a terminal does."
  (if (channel-pty-p channel)
      (start-command channel nil)
      (start-program channel (windows-shell) nil)))
