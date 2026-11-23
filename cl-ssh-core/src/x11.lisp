(in-package #:cl-pnet-ssh)

;;;; X11 forwarding.
;;;;
;;;; Three pieces are shared by both roles and by ssh_config/sshd_config:
;;;; parsing a DISPLAY string, reading and writing Xauthority cookies, and
;;;; replacing the MIT-MAGIC-COOKIE-1 cookie at the front of an X11
;;;; connection setup.  The client and server roles add the SSH side in
;;;; CLIENT-X11 and SERVER-X11.
;;;;
;;;; Only MIT-MAGIC-COOKIE-1 is supported, which is what every modern X
;;;; server issues and what the fake-cookie substitution assumes.  A display
;;;; whose authority entry is XDM-AUTHORIZATION-1 cannot be forwarded: its
;;;; data encodes a timestamp and a process id, not a cookie the server could
;;;; hand back.

(defparameter +ssh-x11-protocol+ "MIT-MAGIC-COOKIE-1")
(defconstant +ssh-x11-cookie-length+ 16)
(defconstant +ssh-x11-family-internet+ 0)
(defconstant +ssh-x11-family-local+ 256)
(defconstant +ssh-x11-family-wild+ 65535)
(defconstant +ssh-x11-display-port-base+ 6000
  "TCP port of display 0; display N listens on 6000 + N.")
(defparameter +ssh-x11-unix-directory+ "/tmp/.X11-unix")

(defstruct (ssh-x11-display (:constructor %make-ssh-x11-display))
  ;; NIL, "" or "unix" means the local Unix socket; anything else is a host
  ;; reached over TCP.
  (host nil)
  (number 0)
  (screen 0))



(defun ssh-x11-parse-display (string)
  "STRING as an SSH-X11-DISPLAY, or NIL when it is not one.

The forms ssh accepts are HOST:DISPLAY[.SCREEN], with HOST empty or \"unix\"
for the local socket, and a bracketed IPv6 host such as [::1]:10.0."
  (when (and string (plusp (length string)))
    (let* ((colon (position #\: string :from-end t))
           (close (and colon (position #\] string)))
           (host (and colon (subseq string 0 colon)))
           (rest (and colon (subseq string (1+ colon))))
           (dot (and rest (position #\. rest)))
           (number-text (if dot (subseq rest 0 dot) rest))
           (screen-text (and dot (subseq rest (1+ dot)))))
      (when (and colon
                 (plusp (length number-text))
                 (or (null screen-text)
                     (plusp (length screen-text))))
        (when (and host (plusp (length host))
                   (char= (char host 0) #\[))
          (setf host (subseq host 1 (or close (length host)))))
        (multiple-value-bind (number end)
            (parse-integer number-text :junk-allowed t)
          (when (and number (>= number 0) (= end (length number-text)))
            (let ((screen
                    (if screen-text
                        (multiple-value-bind (value screen-end)
                            (parse-integer screen-text :junk-allowed t)
                          (and value (>= value 0)
                               (= screen-end (length screen-text))
                               value))
                        0)))
              (when (or (null screen-text) screen)
                (%make-ssh-x11-display
                 :host (if (zerop (length host)) nil host)
                 :number number
                 :screen (or screen 0))))))))))

(defun ssh-x11-display-string (display &optional (host "localhost"))
  "DISPLAY as the string an X client's DISPLAY variable wants.

HOST is the name the server-side display listener is reachable under: sshd
uses \"localhost\" with X11UseLocalhost and the machine's own name without."
  (format nil "~A:~D.~D"
          host
          (ssh-x11-display-number display)
          (ssh-x11-display-screen display)))

(defun ssh-x11-display-unix-p (display)
  "Whether DISPLAY's local socket should be used instead of TCP.

ssh uses the Unix socket for \"unix:HOST\" and for no host at all; every other
spelling, \"localhost\" included, is dialled over TCP, because the X server
may be listening on only one of the two."
  (let ((host (ssh-x11-display-host display)))
    (or (null host)
        (zerop (length host))
        (string-equal host "unix"))))

(defun ssh-x11-display-socket-path (display)
  "The Unix socket of DISPLAY, or NIL when it needs TCP."
  (when (ssh-x11-display-unix-p display)
    (format nil "~A/X~D" +ssh-x11-unix-directory+
            (ssh-x11-display-number display))))

(defun ssh-x11-display-host-port (display)
  "DISPLAY's TCP host and port, or NIL when it uses the Unix socket."
  (unless (ssh-x11-display-unix-p display)
    (values (ssh-x11-display-host display)
            (+ +ssh-x11-display-port-base+
               (ssh-x11-display-number display)))))

;;; ---- Xauthority ----

(defun ssh-x11-authority-path (&optional location)
  "The authority file to read or write: LOCATION, $XAUTHORITY, or ~/.Xauthority.

LOCATION is an explicit path.  XAuthLocation names the xauth program in
OpenSSH, not the file, so it is not consulted here; the file lives where the
X libraries look for it."
  (or location
      (let ((environment (uiop:getenv "XAUTHORITY")))
        (and environment (plusp (length environment)) environment))
      (namestring (merge-pathnames ".Xauthority"
                                   (user-homedir-pathname)))))

(defun ssh-x11-read-u16 (octets position)
  (logior (ash (aref octets position) 8)
          (aref octets (1+ position))))

(defun ssh-x11-read-authority-string (octets position)
  "The string at POSITION, as (VALUES OCTETS NEXT-POSITION), or NIL when short.

The result is a fresh octet vector, not a Lisp string: cookie data is
arbitrary bytes, and a round trip through characters would corrupt it."
  (when (<= (+ position 2) (length octets))
    (let ((length (ssh-x11-read-u16 octets position)))
      (when (<= (+ position 2 length) (length octets))
        (values (subseq octets (+ position 2) (+ position 2 length))
                (+ position 2 length))))))

(defun ssh-x11-read-authority-entry (octets position)
  "One Xauthority record at POSITION, as (VALUES ENTRY NEXT-POSITION).

NIL when the record is incomplete, which is how a partially written trailing
entry is skipped without signalling."
  (when (<= (+ position 2) (length octets))
    (let ((family (ssh-x11-read-u16 octets position)))
      (setf position (+ position 2))
      (multiple-value-bind (address next)
          (ssh-x11-read-authority-string octets position)
        (when next
          (setf position next)
          (multiple-value-bind (number next)
              (ssh-x11-read-authority-string octets position)
            (when next
              (setf position next)
              (multiple-value-bind (name next)
                  (ssh-x11-read-authority-string octets position)
                (when next
                  (setf position next)
                  (multiple-value-bind (data next)
                      (ssh-x11-read-authority-string octets position)
                    (when next
                      (values (list :family family
                                    :address address
                                    :number number
                                    :name name
                                    :data data)
                              next))))))))))))

(defun ssh-x11-authority-entries (path)
  "Every entry in the Xauthority file PATH, oldest first.

Each entry is a plist with :FAMILY, :ADDRESS, :NUMBER, :NAME and :DATA, the
last four as octet vectors.  A missing file, or a trailing partial entry, is
skipped instead of signalled: the file is shared with other X clients and may
be rewritten while it is read."
  (handler-case
      (if (probe-file path)
          (with-open-file (stream path :direction :input
                                       :element-type '(unsigned-byte 8)
                                       :if-does-not-exist nil)
            (when stream
              (let* ((octets (make-array (file-length stream)
                                         :element-type '(unsigned-byte 8)))
                     (entries '())
                     (position 0))
                (read-sequence octets stream)
                (loop
                  (multiple-value-bind (entry next)
                      (ssh-x11-read-authority-entry octets position)
                    (unless next (return))
                    (push entry entries)
                    (setf position next)))
                (nreverse entries))))
          '())
    (error () '())))

(defun ssh-x11-octets-equal-text-p (octets text)
  (and (= (length octets) (length text))
       (loop for octet across octets
             for character across text
             always (= octet (char-code character)))))

(defun ssh-x11-authority-cookie (path display)
  "The MIT-MAGIC-COOKIE-1 entry of DISPLAY in PATH, as (VALUES NAME DATA).

NIL when the file has no usable entry.  The display number selects the entry;
both the local and Internet families are accepted, because either names the
machine that issued the cookie and forwarding only needs the cookie itself.
A wildcard entry carries no display number and applies to any of them."
  (let ((entries (ssh-x11-authority-entries path))
        (number (princ-to-string (ssh-x11-display-number display))))
    (flet ((matches-number (entry)
             (let ((entry-number (getf entry :number)))
               (or (ssh-x11-octets-equal-text-p entry-number number)
                   (and (eql (getf entry :family) +ssh-x11-family-wild+)
                        (zerop (length entry-number))))))
           (cookie-p (entry)
             (ssh-x11-octets-equal-text-p (getf entry :name)
                                          +ssh-x11-protocol+)))
      (let ((entry (or (find-if (lambda (entry)
                                  (and (matches-number entry)
                                       (cookie-p entry)))
                                entries)
                       (find-if (lambda (entry)
                                  (and (matches-number entry)
                                       (plusp (length (getf entry :name)))))
                                entries))))
        (when entry
          (values (getf entry :name) (getf entry :data)))))))

(defun ssh-x11-put-authority-string (output text)
  (let ((octets (if (stringp text)
                    (babel:string-to-octets text :encoding :latin-1)
                    text)))
    (vector-push-extend (ldb (byte 8 8) (length octets)) output)
    (vector-push-extend (ldb (byte 8 0) (length octets)) output)
    (loop for octet across octets do (vector-push-extend octet output))))

#-win32
(defun ssh-x11-restrict-authority-file (path)
  "Give a just-created authority file sshd's 0600 mode.

UIOP cannot ask for a creation mode, so the file starts with the process's
umask; tightening it while it is still empty keeps the cookie out of reach
of other local accounts."
  (ignore-errors
   (uiop:run-program (list "chmod" "600" (uiop:native-namestring path))
                     :output nil :error-output nil)))

#+win32
(defun ssh-x11-restrict-authority-file (path)
  (declare (ignore path))
  nil)

(defun ssh-x11-write-authority-entries (path entries)
  "Replace PATH with ENTRIES, an Xauthority file's records."
  (let ((output (make-array 0 :element-type '(unsigned-byte 8)
                              :adjustable t :fill-pointer 0))
        (created (not (ignore-errors (probe-file path)))))
    (dolist (entry entries)
      (let ((family (getf entry :family)))
        (vector-push-extend (ldb (byte 8 8) family) output)
        (vector-push-extend (ldb (byte 8 0) family) output))
      (ssh-x11-put-authority-string output (getf entry :address))
      (ssh-x11-put-authority-string output (getf entry :number))
      (ssh-x11-put-authority-string output (getf entry :name))
      (ssh-x11-put-authority-string output (getf entry :data)))
    (ensure-directories-exist path)
    (with-open-file (stream path :direction :output
                                 :element-type '(unsigned-byte 8)
                                 :if-exists :supersede
                                 :if-does-not-exist :create)
      ;; The file is open but still empty: an existing file keeps its mode,
      ;; a new one gets the 0600 xauth would have created.
      (when created
        (ssh-x11-restrict-authority-file path))
      (write-sequence output stream)))
  path)

(defun ssh-x11-same-display-p (entry number)
  (and (eql (getf entry :family) +ssh-x11-family-local+)
       (ssh-x11-octets-equal-text-p (getf entry :number) number)))

(defun ssh-x11-write-cookie (path display name data)
  "Add NAME/DATA for DISPLAY to PATH, replacing that display's old entry.

The entry is sshd's: cookie lookups and xauth both treat a loopback or
\"localhost\" connection as the Local family, and the address they compare is
the machine's own host name, not the name DISPLAY happens to spell.  Every
other display in the file is kept, so a shared Xauthority keeps working."
  (let* ((number (princ-to-string (ssh-x11-display-number display)))
         (kept (remove-if (lambda (entry)
                            (ssh-x11-same-display-p entry number))
                          (ssh-x11-authority-entries path)))
         (entries (append kept
                          (list (list :family +ssh-x11-family-local+
                                      :address (babel:string-to-octets
                                                (machine-instance)
                                                :encoding :latin-1)
                                      :number (babel:string-to-octets
                                               number :encoding :latin-1)
                                      :name (if (stringp name)
                                                (babel:string-to-octets
                                                 name :encoding :latin-1)
                                                name)
                                      :data data)))))
    (ssh-x11-write-authority-entries path entries)))

(defun ssh-x11-remove-cookie (path display)
  "Remove every local entry for DISPLAY from PATH.

Returns true when the file was rewritten.  A missing file, or a read that
fails, is ignored: the session is ending either way."
  (handler-case
      (when (probe-file path)
        (let* ((number (princ-to-string (ssh-x11-display-number display)))
               (entries (ssh-x11-authority-entries path))
               (kept (remove-if (lambda (entry)
                                  (ssh-x11-same-display-p entry number))
                                entries)))
          (ssh-x11-write-authority-entries path kept)
          t))
    (error () nil)))

(defun ssh-x11-generate-cookie (&optional (length +ssh-x11-cookie-length+))
  "A fresh random cookie of LENGTH octets."
  (ssh-random-octets length))

;;; ---- Hex, as x11-req carries the cookie ---- 

(defun ssh-x11-cookie-hex (octets)
  "OCTETS as the lower-case hex string an x11-req's auth-cookie field holds."
  (with-output-to-string (stream)
    (loop for octet across octets
          do (format stream "~2,'0x" octet))))

(defun ssh-x11-hex-cookie (text)
  "TEXT, an even-length hex string, as octets, or NIL when it is malformed."
  (when (and text (evenp (length text)))
    (handler-case
        (let ((octets (make-array (/ (length text) 2)
                                  :element-type '(unsigned-byte 8))))
          (loop for index from 0 below (length text) by 2
                for byte-index from 0
                do (setf (aref octets byte-index)
                         (parse-integer text :start index :end (+ index 2)
                                             :radix 16)))
          octets)
      (error () nil))))

;;; ---- The first setup message ----

(defun ssh-x11-align4 (value)
  (logand (+ value 3) (lognot 3)))

(defun ssh-x11-setup-header (octets)
  "The X11 connection setup header at the front of OCTETS.

Returns (VALUES PROTOCOL-LENGTH DATA-LENGTH TOTAL-LENGTH BIG-ENDIAN-P), or
NIL when the fixed 12-byte header is not there yet or its byte order is not
one the protocol allows."
  (when (>= (length octets) 12)
    (let* ((order (aref octets 0))
           (big-endian (eql order (char-code #\B))))
      (when (or big-endian (eql order (char-code #\l)))
        (flet ((u16 (position)
                 (if big-endian
                     (ssh-x11-read-u16 octets position)
                     (logior (aref octets position)
                             (ash (aref octets (1+ position)) 8)))))
          (let* ((name-length (u16 6))
                 (data-length (u16 8)))
            (values name-length data-length
                    (+ 12 (ssh-x11-align4 name-length)
                       (ssh-x11-align4 data-length))
                    big-endian)))))))

(defun ssh-x11-substitute-cookie (octets fake-cookie real-cookie)
  "OCTETS with FAKE-COOKIE replaced by REAL-COOKIE.

Returns (VALUES RESULT COMPLETE-P): COMPLETE-P is true once the setup header
is fully present, and RESULT is then safe to forward; while it is false the
caller must keep buffering, because the fixed header or the cookie itself has
not arrived yet.  A setup that is not the cookie protocol, or that carries a
different cookie, is passed through once its header is complete."
  (multiple-value-bind (name-length data-length total)
      (ssh-x11-setup-header octets)
    (cond
      ((null total)
       ;; Either the fixed header is not here yet, or its byte order is
       ;; unknown.  Only the first case is worth waiting for; an unknown
       ;; order is passed through so the X server can reject it.
       (if (>= (length octets) 12)
           (values octets t)
           (values octets nil)))
      ((< (length octets) total)
       (values octets nil))
      (t
       (let* ((name (subseq octets 12 (+ 12 name-length)))
              (data-offset (+ 12 (ssh-x11-align4 name-length)))
              (data (subseq octets data-offset (+ data-offset data-length))))
         (if (and (ssh-x11-octets-equal-text-p name +ssh-x11-protocol+)
                  (= data-length (length fake-cookie))
                  (ssh-octets= data fake-cookie)
                  (= (length real-cookie) (length fake-cookie)))
             (let ((copy (copy-seq octets)))
               (replace copy real-cookie :start1 data-offset)
               (values copy t))
             (values octets t)))))))
