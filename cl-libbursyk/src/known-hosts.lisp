(in-package #:cl-pnet-ssh)

;;;; known_hosts: parsing, host and key matching, trust-on-first-use records.
;;;;
;;;; The file is OpenSSH's: one "hostpatterns keytype base64 [comment]" line
;;;; per key, where a pattern may be a wildcard, a negated wildcard, or a
;;;; hashed "|1|salt|hash" pair. Hosts on a non-default port are written as
;;;; "[host]:port", which is the HOST argument callers pass here.

(defstruct (ssh-known-host-entry (:constructor %make-ssh-known-host-entry))
  (marker nil)
  (patterns nil)
  (key-type nil)
  (key-blob nil)
  (line nil))

(defun ssh-split-host-patterns (field)
  "The comma-separated host patterns in FIELD."
  (uiop:split-string field :separator ","))

(defun ssh-known-host-line-entry (line)
  "LINE as an SSH-KNOWN-HOST-ENTRY, or NIL when it is blank or a comment."
  (let ((trimmed (string-trim '(#\Space #\Tab #\Return #\Newline) line)))
    (when (and (plusp (length trimmed))
               (not (char= (char trimmed 0) #\#)))
      (let ((fields (remove "" (uiop:split-string trimmed
                                                 :separator '(#\Space #\Tab))
                            :test #'string=)))
        (when (>= (length fields) 3)
          (let* ((marker (when (char= (char (first fields) 0) #\@)
                           (first fields)))
                 (rest-fields (if marker (rest fields) fields))
                 (hosts (first rest-fields))
                 (key-type (second rest-fields))
                 (encoded (third rest-fields)))
            (handler-case
                (%make-ssh-known-host-entry
                 :marker marker
                 :patterns (ssh-split-host-patterns hosts)
                 :key-type key-type
                 :key-blob (ssh-base64-octets encoded)
                 :line trimmed)
              (error () nil))))))))

(defun ssh-load-known-hosts (path)
  "The entries in the known_hosts file at PATH; NIL when it does not exist."
  (if (probe-file path)
      (with-open-file (stream path :direction :input
                                   :if-does-not-exist nil
                                   :external-format :utf-8)
        (iter (for line = (read-line stream nil nil))
          (while line)
          (let ((entry (ssh-known-host-line-entry line)))
            (when entry (collect entry)))))
      nil))

(defun ssh-hashed-known-host-p (pattern)
  "True when PATTERN is OpenSSH's hashed form."
  (and (> (length pattern) 3)
       (string= (subseq pattern 0 3) "|1|")))

(defun ssh-known-host-base64 (string)
  "Decode STRING, or NIL when it is not valid base64.

Known-hosts is untrusted input: one corrupt hashed entry is a non-match,
not a reason to abort the file.  Only the decode failure is caught."
  (handler-case (ssh-base64-octets string)
    (cl-base64:bad-base64-character () nil)))

(defun ssh-hashed-known-host-matches-p (pattern host)
  "True when the hashed PATTERN was made for HOST."
  (let* ((rest (subseq pattern 3))
         (bar (position #\| rest))
         (salt (and bar (ssh-known-host-base64 (subseq rest 0 bar))))
         (expected (and bar (ssh-known-host-base64 (subseq rest (1+ bar))))))
    (and salt expected
         (ssh-octets= (ssh-hmac salt (ssh-string-octets host) :sha1) expected))))

(defun ssh-wildcard-match-p (pattern text)
  "Glob match where * is any run and ? any single character."
  (declare (type string pattern text))
  (let ((p 0) (t-index 0) (star nil) (match 0)
        (p-length (length pattern)) (t-length (length text)))
    (iter (while (< t-index t-length))
      (cond
        ((and (< p p-length)
              (or (char= (char pattern p) (char text t-index))
                  (char= (char pattern p) #\?)))
         (incf p) (incf t-index))
        ((and (< p p-length) (char= (char pattern p) #\*))
         (setf star p match t-index) (incf p))
        (star
         (setf p (1+ star) t-index (incf match)))
        (t (return-from ssh-wildcard-match-p nil))))
    (iter (while (and (< p p-length) (char= (char pattern p) #\*)))
      (incf p))
    (= p p-length)))

(defun ssh-known-host-pattern-matches-p (pattern host)
  "True when one host PATTERN applies to HOST."
  (cond
    ((ssh-hashed-known-host-p pattern)
     (ssh-hashed-known-host-matches-p pattern host))
    (t
     (ssh-wildcard-match-p (string-downcase pattern) (string-downcase host)))))

(defun ssh-known-host-entry-matches-p (entry host)
  "True when ENTRY is about HOST and is not excluded by a negated pattern."
  (let ((patterns (ssh-known-host-entry-patterns entry)))
    (and (iter (for pattern in patterns)
           (thereis (and (plusp (length pattern))
                         (not (char= (char pattern 0) #\!))
                         (ssh-known-host-pattern-matches-p pattern host))))
         (not (iter (for pattern in patterns)
                (thereis (and (plusp (length pattern))
                              (char= (char pattern 0) #\!)
                              (ssh-known-host-pattern-matches-p
                               (subseq pattern 1) host))))))))

(defun ssh-known-host-status (path host key-blob)
  "How KEY-BLOB stands for HOST in PATH: :MATCH, :MISMATCH or :UNKNOWN."
  (let ((entries (remove-if-not (lambda (entry)
                                  (ssh-known-host-entry-matches-p entry host))
                                (ssh-load-known-hosts path)))
        (blob (ssh-copy-octets key-blob)))
    (cond
      ((iter (for entry in entries)
         (thereis (and (not (equal (ssh-known-host-entry-marker entry)
                                   "@revoked"))
                       (ssh-octets= blob (ssh-known-host-entry-key-blob entry)))))
       :match)
      (entries :mismatch)
      (t :unknown))))

(defun ssh-known-host-certificate-authority-p (path host certificate)
  "Whether a @cert-authority entry for HOST in PATH names CERTIFICATE's CA."
  (let ((ca (ssh-certificate-signature-key certificate)))
    (and ca
         (some (lambda (entry)
                 (and (equal (ssh-known-host-entry-marker entry)
                             "@cert-authority")
                      (ssh-known-host-entry-matches-p entry host)
                      (ssh-octets= ca (ssh-known-host-entry-key-blob entry))))
               (ssh-load-known-hosts path)))))

(defun ssh-known-host-key-revoked-p (path host key-blobs)
  "Whether a @revoked entry for HOST in PATH names one of KEY-BLOBS."
  (some (lambda (entry)
          (and (equal (ssh-known-host-entry-marker entry) "@revoked")
               (ssh-known-host-entry-matches-p entry host)
               (some (lambda (blob)
                       (ssh-octets= blob
                                    (ssh-known-host-entry-key-blob entry)))
                     key-blobs)))
        (ssh-load-known-hosts path)))

(defun ssh-remember-known-host (path host key-type key-blob)
  "Append HOST's KEY-BLOB to the known_hosts file at PATH."
  (ensure-directories-exist path)
  (with-open-file (stream path :direction :output
                               :if-exists :append
                               :if-does-not-exist :create
                               :external-format :utf-8)
    (format stream "~A ~A ~A~%"
            host key-type (ssh-octets-base64 key-blob)))
  path)
