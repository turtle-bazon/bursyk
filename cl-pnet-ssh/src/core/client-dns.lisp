(in-package #:cl-pnet-ssh)

;;;; SSHFP lookup for VerifyHostKeyDNS.
;;;;
;;;; The DNS codec and the plain UDP transport live in CL-PNET-DNS and
;;;; CL-PNET-DNS-PLAIN, which CL-PNET-SSH/CORE depends on in its system
;;;; definition, so those functions are present whenever this file is
;;;; compiled.  A DNS failure at run time is still only logged and the caller
;;;; falls back to known_hosts, exactly as ssh does when its resolver cannot
;;;; answer.

(defparameter *ssh-dns-server* nil
  "Nameserver to query for SSHFP records, or NIL for /etc/resolv.conf.")

(defparameter *ssh-dns-port* 53)
(defparameter *ssh-dns-timeout* 5)

(defconstant +ssh-dns-type-sshfp+ 44)
(defconstant +ssh-dns-ad-flag+ #x0020)
(defconstant +ssh-dns-tc-flag+ #x0200)

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
  (let ((message (cl-pnet-dns:decode-dns-message response)))
    (unless message
      (error "the DNS response could not be decoded"))
    (let ((message-flags (cl-pnet-dns:dns-message-flags message)))
      (when (logtest +ssh-dns-tc-flag+ message-flags)
        (error "the DNS response was truncated"))
      (values
       (loop for rr in (cl-pnet-dns:dns-message-answers message)
             for rdata = (and (= +ssh-dns-type-sshfp+
                                  (cl-pnet-dns:dns-rr-type rr))
                              (cl-pnet-dns:dns-rr-rdata rr))
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
      (let* ((message
               (cl-pnet-dns:make-dns-message
                :id (random 65536)
                :flags (logior #x0100 +ssh-dns-ad-flag+)
                :questions
                (list (cl-pnet-dns:make-dns-question
                       :name host
                       :type +ssh-dns-type-sshfp+
                       :class 1))))
             (wire (cl-pnet-dns:encode-dns-message message)))
        (ssh-log "looking up SSHFP records for ~A" host)
        (cl-pnet-dns-plain:dns-plain-query
         wire
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
