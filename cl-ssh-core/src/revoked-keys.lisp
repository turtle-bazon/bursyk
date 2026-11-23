(in-package #:cl-pnet-ssh)

;;;; RevokedKeys: OpenSSH's file of public keys that may not authenticate.
;;;;
;;;; The file is either a text list of public keys, one per line, or a
;;;; binary Key Revocation List (KRL) as ssh-keygen -k writes.  Both forms
;;;; are read here; a file that cannot be read or parsed signals
;;;; SSH-REVOKED-KEYS-ERROR, which the server turns into a refusal, because
;;;; sshd refuses public-key authentication when RevokedKeys is unreadable
;;;; rather than ignoring the list.
;;;;
;;;; The checks follow sshd's sshkey_check_revoked: a certificate is
;;;; compared both as itself and through its CA key, a KRL's explicit key
;;;; section matches a certificate's plain key, and a KRL's serial and
;;;; key-ID sections apply to certificates issued by the named CA (or by
;;;; any CA when the section names none).

(defparameter +ssh-krl-magic+
  (make-array 8 :element-type '(unsigned-byte 8)
              :initial-contents '(83 83 72 75 82 76 10 0))
  "The eight bytes of OpenSSH's KRL_MAGIC, \"SSHKRL\\n\\0\".")

(defconstant +ssh-krl-format-version+ 1)

;;; KRL section numbers, from PROTOCOL.krl.
(defconstant +ssh-krl-section-certificates+ 1)
(defconstant +ssh-krl-section-explicit-key+ 2)
(defconstant +ssh-krl-section-fingerprint-sha1+ 3)
(defconstant +ssh-krl-section-signature+ 4)
(defconstant +ssh-krl-section-fingerprint-sha256+ 5)
(defconstant +ssh-krl-section-extension+ 255)

;;; Certificate-section subsections.
(defconstant +ssh-krl-cert-serial-list+ #x20)
(defconstant +ssh-krl-cert-serial-range+ #x21)
(defconstant +ssh-krl-cert-serial-bitmap+ #x22)
(defconstant +ssh-krl-cert-key-id+ #x23)
(defconstant +ssh-krl-cert-extension+ #x39)

(defstruct (ssh-revoked-certificates
            (:constructor %make-ssh-revoked-certificates))
  ;; NIL means the wildcard section that applies to every CA.
  (ca-key nil)
  (serials '())
  ;; (START . BITS), where bit N of BITS revokes serial START + N.
  (bitmaps '())
  (key-ids '()))

(defstruct (ssh-revoked-keys (:constructor %make-ssh-revoked-keys))
  "A parsed KRL, with the header fields kept so the file can describe itself."
  (comment "")
  (version 0)
  (explicit-keys '())
  (sha1 '())
  (sha256 '())
  (certificates '()))

;;; ---- KRL parsing ----

(defun ssh-krl-octets-p (octets)
  "Whether OCTETS begins with the KRL magic."
  (and (>= (length octets) (length +ssh-krl-magic+))
       (loop for index below (length +ssh-krl-magic+)
             always (= (aref octets index)
                       (aref +ssh-krl-magic+ index)))))

(defun ssh-krl-error (control &rest arguments)
  (error 'ssh-revoked-keys-error :detail (apply #'format nil control arguments)))

(defun ssh-krl-read-section (reader)
  "The next section's data as its own reader."
  (ssh-make-reader (ssh-read-string reader)))

(defun ssh-krl-check-section-end (reader type)
  (unless (zerop (ssh-reader-remaining reader))
    (ssh-krl-error "trailing data in KRL section ~D" type)))

(defun ssh-krl-read-extension (reader)
  "Consume an extension, refusing one whose critical flag is set.

OpenSSH has no extensions of its own, so a critical extension means the
reader does not understand the file and must not silently accept it."
  (let* ((name (ssh-read-text reader))
         (critical (ssh-read-boolean reader)))
    (ssh-read-string reader)
    (when critical
      (ssh-krl-error "unsupported critical KRL extension ~A" name))))

(defun ssh-krl-read-hashes (reader length)
  (loop while (plusp (ssh-reader-remaining reader))
        collect (let ((hash (ssh-read-string reader)))
                  (unless (= (length hash) length)
                    (ssh-krl-error "bad KRL fingerprint length ~D"
                                   (length hash)))
                  hash)))

(defun ssh-krl-read-certificates (krl reader)
  "One KRL_SECTION_CERTIFICATES section, added to KRL."
  (let* ((ca (ssh-read-string reader))
         (entry (%make-ssh-revoked-certificates
                 :ca-key (and (plusp (length ca)) ca))))
    ;; A malformed CA key would match nothing and silently leave the
    ;; certificates it was meant to revoke usable, so reject the file, as
    ;; OpenSSH's sshkey_from_blob does.
    (when (plusp (length ca))
      (handler-case (ssh-public-key-parts ca)
        (error ()
          (ssh-krl-error "invalid CA key in KRL"))))
    ;; The reserved field after the CA key is ignored.
    (ssh-read-string reader)
    (loop while (plusp (ssh-reader-remaining reader))
          do (let ((type (ssh-read-u8 reader))
                   (subsection (ssh-krl-read-section reader)))
               (case type
                 (#.+ssh-krl-cert-serial-list+
                  (loop while (plusp (ssh-reader-remaining subsection))
                        do (let ((serial (ssh-read-u64 subsection)))
                             (push (cons serial serial)
                                   (ssh-revoked-certificates-serials entry)))))
                 (#.+ssh-krl-cert-serial-range+
                  ;; A range subsection holds exactly one pair; any further
                  ;; octets are caught as trailing data below.
                  (push (cons (ssh-read-u64 subsection)
                              (ssh-read-u64 subsection))
                        (ssh-revoked-certificates-serials entry)))
                 (#.+ssh-krl-cert-serial-bitmap+
                  ;; The bitmap is an mpint whose bit N revokes serial
                  ;; START + N, so it is kept as an integer and tested with
                  ;; LOGBITP instead of being expanded into a serial list.
                  (let ((start (ssh-read-u64 subsection))
                        (bits (ssh-read-string subsection)))
                    (when (and (plusp (length bits))
                               (logbitp 7 (aref bits 0)))
                      (ssh-krl-error "negative KRL serial bitmap"))
                    (push (cons start (ssh-mpint-integer bits))
                          (ssh-revoked-certificates-bitmaps entry))))
                 (#.+ssh-krl-cert-key-id+
                  (loop while (plusp (ssh-reader-remaining subsection))
                        do (push (ssh-read-text subsection)
                                 (ssh-revoked-certificates-key-ids entry))))
                 (#.+ssh-krl-cert-extension+
                  (ssh-krl-read-extension subsection))
                 (t
                  (ssh-krl-error "unsupported KRL certificate section ~D"
                                 type)))
               (ssh-krl-check-section-end subsection type)))
    (push entry (ssh-revoked-keys-certificates krl))))

(defun ssh-krl-read-section-body (krl type reader)
  (case type
    (#.+ssh-krl-section-certificates+
     (ssh-krl-read-certificates krl reader))
    (#.+ssh-krl-section-explicit-key+
     (loop while (plusp (ssh-reader-remaining reader))
           do (push (ssh-read-string reader)
                    (ssh-revoked-keys-explicit-keys krl))))
    (#.+ssh-krl-section-fingerprint-sha1+
     (setf (ssh-revoked-keys-sha1 krl)
           (nconc (ssh-revoked-keys-sha1 krl)
                  (ssh-krl-read-hashes reader 20))))
    (#.+ssh-krl-section-fingerprint-sha256+
     (setf (ssh-revoked-keys-sha256 krl)
           (nconc (ssh-revoked-keys-sha256 krl)
                  (ssh-krl-read-hashes reader 32))))
    (#.+ssh-krl-section-extension+
     (ssh-krl-read-extension reader))
    (t
     (ssh-krl-error "unsupported KRL section ~D" type)))
  (ssh-krl-check-section-end reader type))

(defun ssh-parse-krl (octets)
  "OCTETS as an SSH-REVOKED-KEYS.

A malformed KRL signals an SSH error; SSH-KEY-REVOKED-IN-FILE-P turns any
of them into SSH-REVOKED-KEYS-ERROR with the file's name."
  (let ((reader (ssh-make-reader octets)))
    (unless (ssh-krl-octets-p octets)
      (ssh-krl-error "bad KRL magic"))
    (ssh-read-octets reader (length +ssh-krl-magic+))
    (let ((format (ssh-read-u32 reader)))
      (unless (= format +ssh-krl-format-version+)
        (ssh-krl-error "unsupported KRL format version ~D" format)))
    (let ((krl (%make-ssh-revoked-keys
                :version (ssh-read-u64 reader))))
      ;; generated date and flags carry no meaning for this check.
      (ssh-read-u64 reader)
      (ssh-read-u64 reader)
      (ssh-read-string reader)          ; reserved
      (setf (ssh-revoked-keys-comment krl) (ssh-read-text reader))
      (loop while (plusp (ssh-reader-remaining reader))
            do (let ((type (ssh-read-u8 reader)))
                 (when (= type +ssh-krl-section-signature+)
                   ;; PROTOCOL.krl: OpenSSH 9.4 and later refuse a KRL that
                   ;; carries a signature section, because they cannot check
                   ;; it.  Skipping the section would trust the signature
                   ;; marker without verifying it, so refuse instead.
                   (ssh-krl-error "KRL signature sections are not supported"))
                 (ssh-krl-read-section-body
                  krl type (ssh-krl-read-section reader))))
      krl)))

;;; ---- Text-file parsing ----

(defun ssh-revoked-key-blob-readable-p (blob)
  "Whether BLOB is a well-formed public key of a type this build knows.

An unknown type is left opaque: it cannot match a key this server accepts,
so there is no fail-open risk in keeping the line.  A known type is checked
field by field, because a truncated or mistyped line must make the whole
file unreadable rather than quietly revoke nothing."
  (handler-case
      (let* ((reader (ssh-make-reader blob))
             (type (ssh-read-text reader))
             (fields (ssh-certificate-key-field-count type)))
        (cond
          ((null fields) t)
          ((string= type "ssh-ed25519")
           (let ((key (ssh-read-string reader)))
             (and (= (length key) 32)
                  (zerop (ssh-reader-remaining reader)))))
          (t
           (dotimes (index fields)
             (declare (ignore index))
             (ssh-read-string reader))
           (zerop (ssh-reader-remaining reader)))))
    (error () nil)))

(defun ssh-revoked-key-line-blob (line path number)
  "The public key blob on one line of a RevokedKeys text file, or NIL.

Blank lines and comments yield NIL.  A line that is not a public key
signals, because sshd stops reading the file at a malformed line and then
refuses every key, rather than quietly ignoring the rest of the list."
  (let ((trimmed (string-trim '(#\Space #\Tab #\Return) line)))
    (cond
      ((zerop (length trimmed)) nil)
      ((char= (char trimmed 0) #\#) nil)
      (t
       (let ((fields (remove "" (uiop:split-string trimmed
                                                   :separator '(#\Space #\Tab))
                             :test #'string=)))
         (unless (>= (length fields) 2)
           (error 'ssh-revoked-keys-error
                  :path (namestring path)
                  :detail (format nil "line ~D is not a public key" number)))
         (let ((declared (first fields))
               (blob (handler-case (ssh-base64-octets (second fields))
                       (error ()
                         (error 'ssh-revoked-keys-error
                                :path (namestring path)
                                :detail
                                (format nil "line ~D is not base64" number))))))
           (multiple-value-bind (type data)
               (handler-case (ssh-public-key-parts blob)
                 (error ()
                   (error 'ssh-revoked-keys-error
                          :path (namestring path)
                          :detail
                          (format nil "line ~D is not a public key" number))))
             (declare (ignore data))
             (unless (string= declared type)
               (error 'ssh-revoked-keys-error
                      :path (namestring path)
                      :detail (format nil "line ~D names ~A but holds ~A"
                                      number declared type)))
             (unless (ssh-revoked-key-blob-readable-p blob)
               (error 'ssh-revoked-keys-error
                      :path (namestring path)
                      :detail (format nil "line ~D is not a readable key"
                                      number)))
             (when (and (ssh-certificate-blob-p blob)
                        (null (ssh-certificate-parse blob)))
               (error 'ssh-revoked-keys-error
                      :path (namestring path)
                      :detail (format nil "line ~D is not a readable certificate"
                                      number)))
             blob)))))))

(defun ssh-parse-revoked-key-text (octets path)
  "The plain public key blobs in OCTETS, a RevokedKeys text file.

sshd compares these keys by public key material with the strict type check
off, so a certificate line stands for the plain key it certifies."
  (let ((text (handler-case (babel:octets-to-string octets :encoding :utf-8)
                (error ()
                  (error 'ssh-revoked-keys-error
                         :path (namestring path)
                         :detail "the file is neither a KRL nor UTF-8 text")))))
    (loop for line in (uiop:split-string text :separator '(#\Newline))
          for number from 1
          for blob = (ssh-revoked-key-line-blob line path number)
          when blob collect (ssh-key-plain-blob blob))))

;;; ---- Checking a key ----

(defun ssh-octets-member-p (needle haystack)
  (and (find needle haystack :test #'ssh-octets=) t))

(defun ssh-revoked-certificates-serial-p (entry serial)
  "Whether SERIAL is revoked by ENTRY's serial or bitmap subsections.

A zero serial is never matched by a serial rule, which is OpenSSH's rule for
certificates that carry the default serial."
  (and (/= serial 0)
       (or (some (lambda (range)
                   (<= (car range) serial (cdr range)))
                 (ssh-revoked-certificates-serials entry))
           (some (lambda (bitmap)
                   (let ((offset (car bitmap)))
                     (and (>= serial offset)
                          (logbitp (- serial offset) (cdr bitmap)))))
                 (ssh-revoked-certificates-bitmaps entry)))))

(defun ssh-revoked-certificate-entry-matches-p (entry certificate)
  "Whether ENTRY revokes CERTIFICATE by serial or key ID."
  (or (and (member (ssh-certificate-key-id certificate)
                   (ssh-revoked-certificates-key-ids entry)
                   :test #'string=)
           t)
      (ssh-revoked-certificates-serial-p
       entry (ssh-certificate-serial certificate))))

(defun ssh-krl-key-revoked-p (krl key-blob)
  "Whether KEY-BLOB, or the CA of a certificate, is revoked by KRL."
  (labels ((explicitly-revoked-p (blob)
             (ssh-octets-member-p
              (ssh-key-plain-blob blob)
              (ssh-revoked-keys-explicit-keys krl)))
           (by-fingerprint-p (blob)
             (or (ssh-octets-member-p (ssh-hash :sha1 blob)
                                      (ssh-revoked-keys-sha1 krl))
                 (ssh-octets-member-p (ssh-hash :sha256 blob)
                                      (ssh-revoked-keys-sha256 krl))))
           (revoked-p (blob)
             (or (by-fingerprint-p blob)
                 (explicitly-revoked-p blob))))
    (or (revoked-p key-blob)
        (let ((certificate (and (ssh-certificate-blob-p key-blob)
                                (ssh-certificate-parse key-blob))))
          (when certificate
            (let ((ca (ssh-certificate-signature-key certificate)))
              (or (revoked-p ca)
                  (some (lambda (entry)
                          (and (or (null (ssh-revoked-certificates-ca-key entry))
                                   (ssh-octets= ca
                                                (ssh-revoked-certificates-ca-key
                                                 entry)))
                               (ssh-revoked-certificate-entry-matches-p
                                entry certificate)))
                        (ssh-revoked-keys-certificates krl)))))))))

(defun ssh-text-key-revoked-p (blobs key-blob)
  "Whether KEY-BLOB, or the CA of a certificate, appears in BLOBS.

This is sshkey_in_file's rule: with the strict type check off, keys compare
by public key material, so a plain key in the list also revokes a
certificate that certifies it.  Check_ca also compares a certificate's
signature key, so a text file can revoke a CA without a KRL."
  (or (ssh-octets-member-p (ssh-key-plain-blob key-blob) blobs)
      (let ((certificate (and (ssh-certificate-blob-p key-blob)
                              (ssh-certificate-parse key-blob))))
        (and certificate
             (ssh-octets-member-p
              (ssh-key-plain-blob
               (ssh-certificate-signature-key certificate))
              blobs)))))

;;; ---- Files ----

(defun ssh-load-revoked-keys-file (path)
  "PATH as octets, signalling SSH-REVOKED-KEYS-ERROR when it cannot be read."
  (handler-case (ssh-read-octets-file path)
    (error (condition)
      (error 'ssh-revoked-keys-error
             :path (namestring path)
             :detail (format nil "cannot read the file: ~A" condition)))))

(defun ssh-key-revoked-in-file-p (key-blob path)
  "Whether KEY-BLOB is revoked by the RevokedKeys file at PATH.

PATH is a KRL when it begins with the KRL magic, and a text list of public
keys otherwise.  A file that cannot be read or parsed signals
SSH-REVOKED-KEYS-ERROR so the caller can refuse authentication."
  (let ((octets (ssh-load-revoked-keys-file path)))
    (handler-case
        (if (ssh-krl-octets-p octets)
            (ssh-krl-key-revoked-p (ssh-parse-krl octets) key-blob)
            (ssh-text-key-revoked-p
             (ssh-parse-revoked-key-text octets path) key-blob))
      (ssh-revoked-keys-error (condition)
        (error condition))
      (error (condition)
        (error 'ssh-revoked-keys-error
               :path (namestring path)
               :detail (format nil "cannot parse the file: ~A" condition))))))

(defun ssh-key-revoked-p (key-blob files)
  "Whether KEY-BLOB is revoked by any file in FILES.

FILES is a list of RevokedKeys paths.  A file that cannot be read or parsed
signals SSH-REVOKED-KEYS-ERROR; sshd refuses public-key authentication then,
so callers must treat the error as revoked."
  (some (lambda (file) (ssh-key-revoked-in-file-p key-blob file)) files))
