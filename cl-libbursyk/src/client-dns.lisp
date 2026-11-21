(in-package #:cl-pnet-ssh)

;;;; SSHFP lookup for VerifyHostKeyDNS.
;;;;
;;;; The DNS codec and the plain UDP transport live in CL-PNET-DNS, which a
;;;; consumer may or may not load.  Every symbol is looked up at call time, so
;;;; this file adds no hard dependency to the SSH library: a build without the
;;;; DNS systems reports an error and the caller falls back to known_hosts,
;;;; exactly as ssh does when its resolver cannot answer.

(defparameter *ssh-dns-server* nil
  "Nameserver to query for SSHFP records, or NIL for /etc/resolv.conf.")

(defparameter *ssh-dns-port* 53)
(defparameter *ssh-dns-timeout* 5)

(defconstant +ssh-dns-type-sshfp+ 44)
(defconstant +ssh-dns-ad-flag+ #x0020)
(defconstant +ssh-dns-tc-flag+ #x0200)

(defun ssh-dns-symbol (name package)
  "NAME's function in PACKAGE, or an error naming what is missing."
  (let ((symbol (and (find-package package) (find-symbol name package))))
    (if (and symbol (fboundp symbol))
        symbol
        (error "~A is not available; load CL-PNET-DNS and CL-PNET-DNS-PLAIN"
               package))))

(defun ssh-dns-accessor (name package)
  "NAME's accessor in PACKAGE, or an error naming what is missing."
  (let ((symbol (and (find-package package) (find-symbol name package))))
    (if (and symbol (fboundp symbol))
        symbol
        (error "the DNS accessor ~A is not available" name))))

(defun ssh-dns-nameserver-token (line)
  "The address in a resolv.conf NAMESERVER LINE, ignoring comments."
  (let* ((comment (position #\# line))
         (text (string-trim '(#\Space #\Tab #\Return)
                            (if comment (subseq line 0 comment) line)))
         (tokens (uiop:split-string text
                                    :separator '(#\Space #\Tab))))
    (when (and tokens (string-equal (first tokens) "nameserver"))
      (second tokens))))

(defun ssh-dns-nameservers ()
  "The nameservers in /etc/resolv.conf, in the order they appear."
  (let ((path (pathname "/etc/resolv.conf")))
    (when (probe-file path)
      (with-open-file (stream path :if-does-not-exist nil)
        (when stream
          (loop for line = (read-line stream nil nil)
                while line
                for server = (ssh-dns-nameserver-token line)
                when server collect server))))))

(defun ssh-dns-server ()
  "The nameserver an SSHFP query uses."
  (or *ssh-dns-server*
      (first (ssh-dns-nameservers))
      (error "no nameserver in /etc/resolv.conf")))

(defun ssh-dns-parse-response (response)
  "The SSHFP records and DNSSEC status in a DNS RESPONSE.

Returns (VALUES RECORDS SECURE).  A truncated answer is refused rather than
trusted partially: without TCP retry its record set is incomplete."
  (let* ((decode (ssh-dns-symbol "DECODE-DNS-MESSAGE" "CL-PNET-DNS"))
         (flags (ssh-dns-accessor "DNS-MESSAGE-FLAGS" "CL-PNET-DNS"))
         (answers (ssh-dns-accessor "DNS-MESSAGE-ANSWERS" "CL-PNET-DNS"))
         (rr-type (ssh-dns-accessor "DNS-RR-TYPE" "CL-PNET-DNS"))
         (rr-rdata (ssh-dns-accessor "DNS-RR-RDATA" "CL-PNET-DNS"))
         (message (funcall decode response)))
    (unless message
      (error "the DNS response could not be decoded"))
    (let ((message-flags (funcall flags message)))
      (when (logtest +ssh-dns-tc-flag+ message-flags)
        (error "the DNS response was truncated"))
      (values
       (loop for rr in (funcall answers message)
             for rdata = (and (= +ssh-dns-type-sshfp+ (funcall rr-type rr))
                              (funcall rr-rdata rr))
             when (and rdata (>= (length rdata) 3))
               collect (list (aref rdata 0)
                             (aref rdata 1)
                             (subseq rdata 2)))
       (logtest +ssh-dns-ad-flag+ message-flags)))))

(defun ssh-dns-resolve-sshfp (host on-success on-error)
  "Ask the system resolver for HOST's SSHFP records, without blocking.

ON-SUCCESS receives the record list and whether the answer was
DNSSEC-validated.  The query has the AD bit set so a validating resolver
reports its result; an insecure answer is still returned, but the caller
will not accept a key from it."
  (handler-case
      (let* ((make-message (ssh-dns-symbol "MAKE-DNS-MESSAGE" "CL-PNET-DNS"))
             (make-question (ssh-dns-symbol "MAKE-DNS-QUESTION"
                                            "CL-PNET-DNS"))
             (encode (ssh-dns-symbol "ENCODE-DNS-MESSAGE" "CL-PNET-DNS"))
             (query (ssh-dns-symbol "DNS-PLAIN-QUERY"
                                    "CL-PNET-DNS-PLAIN"))
             (message
               (funcall make-message
                        :id (random 65536)
                        :flags (logior #x0100 +ssh-dns-ad-flag+)
                        :questions
                        (list (funcall make-question
                                       :name host
                                       :type +ssh-dns-type-sshfp+
                                       :class 1))))
             (wire (funcall encode message)))
        (ssh-log "looking up SSHFP records for ~A" host)
        (funcall query wire
                 :server (ssh-dns-server)
                 :port *ssh-dns-port*
                 :timeout *ssh-dns-timeout*
                 :protocol :udp
                 :on-response
                 (lambda (response)
                   (handler-case
                       (multiple-value-bind (records secure)
                           (ssh-dns-parse-response response)
                         (funcall on-success records secure))
                     (error (condition) (funcall on-error condition))))
                 :on-error on-error))
    (error (condition) (funcall on-error condition))))
