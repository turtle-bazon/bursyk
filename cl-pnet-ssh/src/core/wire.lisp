(in-package #:cl-pnet-ssh)

;;;; SSH data types (RFC 4251 section 5) and a reader/writer over octets.
;;;;
;;;; Everything here is role-neutral: a future server uses the same encoder
;;;; and decoder as the client.

(deftype ssh-octets () '(simple-array (unsigned-byte 8) (*)))

(defun ssh-copy-octets (sequence)
  "SEQUENCE as a fresh simple (unsigned-byte 8) vector."
  (let ((out (make-array (length sequence)
                         :element-type '(unsigned-byte 8))))
    (dotimes (i (length sequence) out)
      (let ((element (elt sequence i)))
        (setf (aref out i)
              (if (characterp element) (char-code element) element))))))

(defun ssh-ensure-octets (data)
  "DATA as octets: a string is UTF-8 encoded, a vector copied."
  (if (stringp data)
      (babel:string-to-octets data :encoding :utf-8)
      (ssh-copy-octets data)))

(defun ssh-concat (&rest sequences)
  "Concatenate SEQUENCES, which hold octets, into one fresh vector."
  (let* ((total (reduce #'+ sequences :key #'length :initial-value 0))
         (out (make-array total :element-type '(unsigned-byte 8)))
         (offset 0))
    (dolist (sequence sequences out)
      (replace out sequence :start1 offset)
      (incf offset (length sequence)))))

(defun ssh-octets= (a b)
  "True when A and B hold the same octets."
  (and (= (length a) (length b))
       (dotimes (i (length a) t)
         (unless (= (aref a i) (aref b i))
           (return nil)))))

(defun ssh-string-octets (string)
  "STRING as UTF-8 octets."
  (babel:string-to-octets string :encoding :utf-8))

(defun ssh-octets-string (octets)
  "OCTETS as a UTF-8 string."
  (babel:octets-to-string octets :encoding :utf-8))

(defun ssh-utf8-escaped-string (octets)
  "OCTETS as a string, escaping bytes that are not printable UTF-8.

OpenSSH prints a key comment through mprintf(), which passes valid UTF-8
through but writes a byte that is not part of a printable character as a
three-digit octal escape.  A comment is the only free-form text in a key
file, so that is where a key written by another tool can hold arbitrary
bytes; mirror the escaping instead of refusing the file."
  (let ((out (make-string-output-stream))
        (n (length octets))
        (i 0))
    (labels ((octet (j) (aref octets j))
             (continuation-p (j)
               (and (< j n) (<= #x80 (octet j) #xBF)))
             (escape (b) (format out "\\~3,'0O" b))
             (emit (code) (write-char (code-char code) out)))
      (loop while (< i n)
            do (let ((b (octet i)))
                 (cond
                   ;; mprintf() passes tab, newline and carriage return
                   ;; through when no width limit is asked for, so only the
                   ;; other C0 controls and DEL are escaped.
                   ((or (and (< b #x20)
                             (/= b #x09) (/= b #x0A) (/= b #x0D))
                        (= b #x7F))
                    (escape b)
                    (incf i))
                   ((< b #x80)
                    (emit b)
                    (incf i))
                   ((and (<= #xC2 b #xDF) (continuation-p (1+ i)))
                    (let ((code (logior (ash (logand b #x1F) 6)
                                        (logand (octet (1+ i)) #x3F))))
                      (cond
                        ((<= #x80 code #x9F)
                         (escape b)
                         (escape (octet (1+ i))))
                        (t
                         (emit code)))
                      (incf i 2)))
                   ((and (<= #xE0 b #xEF)
                         (continuation-p (1+ i))
                         (continuation-p (+ i 2))
                         (or (/= b #xE0) (>= (octet (1+ i)) #xA0))
                         (or (/= b #xED) (<= (octet (1+ i)) #x9F)))
                    (emit (logior (ash (logand b #x0F) 12)
                                  (ash (logand (octet (1+ i)) #x3F) 6)
                                  (logand (octet (+ i 2)) #x3F)))
                    (incf i 3))
                   ((and (<= #xF0 b #xF4)
                         (continuation-p (1+ i))
                         (continuation-p (+ i 2))
                         (continuation-p (+ i 3))
                         (or (/= b #xF0) (>= (octet (1+ i)) #x90))
                         (or (/= b #xF4) (<= (octet (1+ i)) #x8F)))
                    (emit (logior (ash (logand b #x07) 18)
                                  (ash (logand (octet (1+ i)) #x3F) 12)
                                  (ash (logand (octet (+ i 2)) #x3F) 6)
                                  (logand (octet (+ i 3)) #x3F)))
                    (incf i 4))
                   (t
                    (escape b)
                    (incf i))))))
    (get-output-stream-string out)))

(defun ssh-uint32-octets (value)
  "VALUE as four big-endian octets."
  (let ((out (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref out 0) (ldb (byte 8 24) value)
          (aref out 1) (ldb (byte 8 16) value)
          (aref out 2) (ldb (byte 8 8) value)
          (aref out 3) (ldb (byte 8 0) value))
    out))

(defun ssh-uint64-octets (value)
  "VALUE as eight big-endian octets."
  (let ((out (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 out)
      (setf (aref out i) (ldb (byte 8 (* 8 (- 7 i))) value)))))

(defun ssh-octets-uint32 (octets &optional (start 0))
  "The big-endian uint32 at START."
  (logior (ash (aref octets start) 24)
          (ash (aref octets (+ start 1)) 16)
          (ash (aref octets (+ start 2)) 8)
          (aref octets (+ start 3))))

(defun ssh-octets-uint64 (octets &optional (start 0))
  "The big-endian uint64 at START."
  (let ((value 0))
    (dotimes (i 8 value)
      (setf value (logior (ash value 8) (aref octets (+ start i)))))))

;;; ---- mpint ----

(defun ssh-mpint-octets (integer)
  "INTEGER as an SSH mpint (RFC 4251 section 5), without the length prefix.

Only non-negative values are needed: every integer this protocol sends
(group elements, shared secrets) is unsigned."
  (cond
    ((minusp integer)
     (error 'ssh-protocol-error
            :detail "a negative mpint is not part of this protocol"))
    ((zerop integer)
     (make-array 0 :element-type '(unsigned-byte 8)))
    (t
     (let* ((bytes (max 1 (ceiling (integer-length integer) 8)))
            (out (make-array bytes :element-type '(unsigned-byte 8))))
       (dotimes (i bytes out)
         (setf (aref out i)
               (ldb (byte 8 (* 8 (- bytes 1 i))) integer)))
       (if (logbitp (1- (* 8 bytes)) integer)
           (ssh-concat (make-array 1 :element-type '(unsigned-byte 8)
                                     :initial-element 0)
                       out)
           out)))))

(defun ssh-mpint-integer (octets)
  "The unsigned integer an mpint's magnitude OCTETS denotes."
  (let ((value 0))
    (dotimes (i (length octets) value)
      (setf value (logior (ash value 8) (aref octets i))))))

;;; ---- reader ----

(defstruct (ssh-reader (:constructor %make-ssh-reader))
  (data nil :type ssh-octets)
  (position 0 :type fixnum)
  (end 0 :type fixnum))

(defun ssh-make-reader (data &optional (start 0) (end (length data)))
  (%make-ssh-reader :data data :position start :end end))

(defun ssh-reader-remaining (reader)
  (- (ssh-reader-end reader) (ssh-reader-position reader)))

(defun ssh-reader-need (reader count)
  "Signal unless READER still has COUNT octets."
  (when (< (ssh-reader-remaining reader) count)
    (error 'ssh-protocol-error
           :detail (format nil "truncated message: wanted ~D octets, ~D left"
                           count (ssh-reader-remaining reader)))))

(defun ssh-read-u8 (reader)
  (ssh-reader-need reader 1)
  (prog1 (aref (ssh-reader-data reader) (ssh-reader-position reader))
    (incf (ssh-reader-position reader))))

(defun ssh-read-boolean (reader)
  (/= 0 (ssh-read-u8 reader)))

(defun ssh-read-u32 (reader)
  (ssh-reader-need reader 4)
  (prog1 (ssh-octets-uint32 (ssh-reader-data reader)
                            (ssh-reader-position reader))
    (incf (ssh-reader-position reader) 4)))

(defun ssh-read-u64 (reader)
  (ssh-reader-need reader 8)
  (prog1 (ssh-octets-uint64 (ssh-reader-data reader)
                            (ssh-reader-position reader))
    (incf (ssh-reader-position reader) 8)))

(defun ssh-read-octets (reader count)
  "COUNT octets, copied out of READER."
  (ssh-reader-need reader count)
  (let ((start (ssh-reader-position reader)))
    (incf (ssh-reader-position reader) count)
    (subseq (ssh-reader-data reader) start (+ start count))))

(defun ssh-read-string (reader)
  "A length-prefixed string, returned as octets."
  (ssh-read-octets reader (ssh-read-u32 reader)))

(defun ssh-read-text (reader)
  "A length-prefixed string, returned as a UTF-8 string."
  (ssh-octets-string (ssh-read-string reader)))

(defun ssh-read-comment (reader)
  "A length-prefixed key comment, escaped as ssh-keygen prints it.

ssh-keygen stores a comment's octets as given but prints them through
mprintf(), which escapes anything that is not printable UTF-8.  Decoding
that way here keeps a key from another tool readable and makes -l match."
  (ssh-utf8-escaped-string (ssh-read-string reader)))

(defun ssh-read-name-list (reader)
  "A comma-separated name-list as a list of strings; empty means NIL."
  (let ((text (ssh-read-text reader)))
    (if (zerop (length text))
        nil
        (uiop:split-string text :separator ","))))

(defun ssh-read-mpint (reader)
  "An mpint as an integer (non-negative values only)."
  (ssh-mpint-integer (ssh-read-string reader)))

;;; ---- writer ----

(defstruct (ssh-writer (:constructor %make-ssh-writer (&optional (capacity 128))))
  (octets (make-array capacity :element-type '(unsigned-byte 8)
                               :adjustable t :fill-pointer 0)))

(defun ssh-writer (&optional (capacity 128))
  "A fresh writer with room for CAPACITY octets."
  (%make-ssh-writer capacity))

(defun ssh-write-octets (writer octets)
  (let ((vector (ssh-writer-octets writer)))
    (dotimes (i (length octets))
      (vector-push-extend (aref octets i) vector)))
  writer)

(defun ssh-write-u8 (writer value)
  (vector-push-extend (ldb (byte 8 0) value) (ssh-writer-octets writer))
  writer)

(defun ssh-write-boolean (writer value)
  (ssh-write-u8 writer (if value 1 0)))

(defun ssh-write-u32 (writer value)
  (ssh-write-octets writer (ssh-uint32-octets value)))

(defun ssh-write-u64 (writer value)
  (ssh-write-octets writer (ssh-uint64-octets value)))

(defun ssh-write-string (writer octets)
  "A length-prefixed octet string."
  (ssh-write-u32 writer (length octets))
  (ssh-write-octets writer octets))

(defun ssh-write-text (writer string)
  (ssh-write-string writer (ssh-string-octets string)))

(defun ssh-write-name-list (writer names)
  (ssh-write-text writer (format nil "~{~A~^,~}" names)))

(defun ssh-write-mpint (writer integer)
  (ssh-write-string writer (ssh-mpint-octets integer)))

(defun ssh-writer-output (writer)
  "WRITER's octets as a fresh simple vector."
  (ssh-copy-octets (ssh-writer-octets writer)))

