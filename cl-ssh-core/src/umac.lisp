(in-package #:cl-pnet-ssh)

;;;; UMAC (RFC 4418), the message authentication code OpenSSH lists ahead of
;;;; its HMACs.
;;;;
;;;; SSH keys UMAC with 16 octets and asks for an 8-octet tag (umac-64) or a
;;;; 16-octet one (umac-128).  The nonce is the 64-bit packet sequence number.
;;;; Everything below follows the RFC's big-endian notation directly; the
;;;; reference implementation is faster but this one is short enough to audit
;;;; against the test vectors in the RFC's appendix.

(defstruct (ssh-umac-state (:constructor %make-ssh-umac-state))
  ;; The tag length in octets: 8 for umac-64, 16 for umac-128.
  (tag-length 8 :type (unsigned-byte 8))
  ;; AES-128 under KDF(K, 0, 16), the PDF's key.
  (pdf-cipher nil)
  ;; Per-iteration keys, already sliced out of the KDF streams.
  (l1-keys nil)
  (l2-keys nil)
  (l3-keys1 nil)
  (l3-keys2 nil))

(defparameter +ssh-umac-key-length+ 16
  "The external key length UMAC takes, whatever the tag length.")

(defun ssh-umac-u16 (octets start)
  "The big-endian uint16 at START."
  (logior (ash (aref octets start) 8)
          (aref octets (+ start 1))))

(defun ssh-umac-u32 (octets start)
  "The big-endian uint32 at START."
  (logior (ash (aref octets start) 24)
          (ash (aref octets (+ start 1)) 16)
          (ash (aref octets (+ start 2)) 8)
          (aref octets (+ start 3))))

(defun ssh-umac-u64 (octets start)
  "The big-endian uint64 at START."
  (let ((value 0))
    (dotimes (i 8 value)
      (setf value (logior (ash value 8) (aref octets (+ start i)))))))

(defun ssh-umac-u128 (octets start)
  "The big-endian uint128 at START."
  (let ((value 0))
    (dotimes (i 16 value)
      (setf value (logior (ash value 8) (aref octets (+ start i)))))))

(defun ssh-uint128-octets (value)
  "VALUE as sixteen big-endian octets."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16 out)
      (setf (aref out i) (ldb (byte 8 (* 8 (- 15 i))) value)))))

(defun ssh-umac-endian-swap (octets)
  "OCTETS with each 4-octet word byte-reversed.

The RFC reads message words little-endian, which is the same as reversing
each word and then reading it big-endian."
  (let ((out (make-array (length octets) :element-type '(unsigned-byte 8))))
    (dotimes (i (length octets) out)
      (setf (aref out i) (aref octets (logxor i 3))))))

(defun ssh-umac-zero-pad (octets boundary)
  "OCTETS followed by zeroes up to the next multiple of BOUNDARY."
  (let* ((length (length octets))
         (padded (* boundary (ceiling length boundary))))
    (if (= length padded)
        octets
        (let ((out (make-array padded :element-type '(unsigned-byte 8)
                                     :initial-element 0)))
          (replace out octets)
          out))))

(defun ssh-umac-add64 (octets addend)
  "OCTETS as a uint64 plus ADDEND, modulo 2^64, as eight octets."
  (ssh-uint64-octets
   (logand (+ (ssh-octets-uint64 octets) addend) #xffffffffffffffff)))

;;; ---- Key derivation ----

(defun ssh-umac-kdf (cipher index nbytes)
  "NBYTES of KDF stream INDEX, enciphered with the ECB CIPHER keyed by K."
  (let* ((blocks (ceiling nbytes 16))
         (input (make-array (* blocks 16) :element-type '(unsigned-byte 8)
                                            :initial-element 0))
         (output (make-array (* blocks 16)
                             :element-type '(unsigned-byte 8))))
    (dotimes (i blocks)
      (let ((base (* i 16)))
        (dotimes (j 8)
          (setf (aref input (+ base j))
                (ldb (byte 8 (* 8 (- 7 j))) index)
                (aref input (+ base 8 j))
                (ldb (byte 8 (* 8 (- 7 j))) (1+ i))))))
    (ironclad-unsafe:encrypt cipher input output)
    (if (= nbytes (length output))
        output
        (subseq output 0 nbytes))))

;;; ---- L1-HASH and NH ----

(defun ssh-umac-nh (key octets)
  "NH hash of OCTETS, whose length is a multiple of 32, under KEY."
  (let ((words (/ (length octets) 4))
        (y 0))
    (loop for i from 0 below words by 8
          do (loop for j from 0 below 4
                   do (let* ((low (* 4 (+ i j)))
                             (high (* 4 (+ i j 4)))
                             (a (logand (+ (ssh-umac-u32 octets low)
                                           (ssh-umac-u32 key low))
                                        #xffffffff))
                             (b (logand (+ (ssh-umac-u32 octets high)
                                           (ssh-umac-u32 key high))
                                        #xffffffff)))
                        (setf y (logand (+ y (* a b))
                                        #xffffffffffffffff)))))
    (ssh-uint64-octets y)))

(defun ssh-umac-l1-hash (key message)
  "L1-HASH of MESSAGE under the 1024-octet KEY."
  (let* ((length (length message))
         (chunks (max 1 (ceiling (* 8 length) 8192)))
         (result (make-array (* 8 chunks) :element-type '(unsigned-byte 8)))
         (offset 0))
    (dotimes (i (1- chunks))
      (let ((chunk (ssh-umac-endian-swap
                    (subseq message offset (+ offset 1024)))))
        (replace result
                 (ssh-umac-add64 (ssh-umac-nh key chunk) 8192)
                 :start1 (* i 8)))
      (incf offset 1024))
    (let* ((tail (subseq message offset))
           (bits (* 8 (length tail)))
           ;; RFC 4418 hashes an empty message as one all-zero 32-octet
           ;; block, not as no data at all: the key words still multiply.
           (padded (if (zerop (length tail))
                       (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 0)
                       (ssh-umac-zero-pad tail 32)))
           (chunk (ssh-umac-endian-swap padded)))
      (replace result
               (ssh-umac-add64 (ssh-umac-nh key chunk) bits)
               :start1 (* (1- chunks) 8)))
    result))

;;; ---- L2-HASH and POLY ----

(defun ssh-umac-poly (wordbits maxwordrange key octets)
  "POLY hash of OCTETS, whose length is a multiple of WORDBITS/8."
  (let* ((wordbytes (/ wordbits 8))
         (p (if (= wordbits 64)
                #xffffffffffffffc5
                #xffffffffffffffffffffffffffffff61))
         (offset (- (ash 1 wordbits) p))
         (marker (1- p))
         (words (/ (length octets) wordbytes))
         (y 1))
    (dotimes (i words)
      (let ((m (if (= wordbits 64)
                   (ssh-umac-u64 octets (* i 8))
                   (ssh-umac-u128 octets (* i 16)))))
        (if (>= m maxwordrange)
            (setf y (mod (+ (* key y) marker) p)
                  y (mod (+ (* key y) (- m offset)) p))
            (setf y (mod (+ (* key y) m) p)))))
    y))

(defun ssh-umac-l2-hash (key octets)
  "L2-HASH of OCTETS under the 24-octet KEY, as sixteen octets."
  (let* ((mask64 #x01ffffff01ffffff)
         (mask128 #x01ffffff01ffffff01ffffff01ffffff)
         (k64 (logand (ssh-umac-u64 key 0) mask64))
         (k128 (logand (ssh-umac-u128 key 8) mask128)))
    (if (<= (length octets) (ash 1 17))
        (ssh-uint128-octets
         (ssh-umac-poly 64 (- (ash 1 64) (ash 1 32)) k64 octets))
        (let* ((split (ash 1 17))
               (first (subseq octets 0 split))
               (second (ssh-umac-zero-pad
                        (ssh-concat
                         (subseq octets split)
                         (make-array 1 :element-type '(unsigned-byte 8)
                                       :initial-element #x80))
                        16))
               (y (ssh-umac-poly 64 (- (ash 1 64) (ash 1 32)) k64 first)))
          (ssh-uint128-octets
           (ssh-umac-poly 128 (- (ash 1 128) (ash 1 96)) k128
                          (ssh-concat (ssh-uint128-octets y) second)))))))

;;; ---- L3-HASH ----

(defun ssh-umac-l3-hash (key1 key2 octets)
  "L3-HASH of the sixteen-octet OCTETS under KEY1 and KEY2, as four octets."
  (let ((p (- (ash 1 36) 5))
        (y 0))
    (dotimes (i 8)
      (incf y (* (ssh-umac-u16 octets (* i 2))
                 (mod (ssh-umac-u64 key1 (* i 8)) p))))
    (let ((out (ssh-uint32-octets (logand (mod y p) #xffffffff))))
      (dotimes (i 4 out)
        (setf (aref out i)
              (logxor (aref out i) (aref key2 i)))))))

;;; ---- PDF and the tag ----

(defun ssh-umac-pdf (state nonce tag-length)
  "TAG-LENGTH pad octets for the eight-octet NONCE."
  (let* ((value (ssh-octets-uint64 nonce))
         (index (if (<= tag-length 8)
                    (mod value (/ 16 tag-length))
                    0))
         (block (make-array 16 :element-type '(unsigned-byte 8)
                               :initial-element 0))
         (output (make-array 16 :element-type '(unsigned-byte 8))))
    (when (<= tag-length 8)
      ;; The RFC clears the low bit(s) so sequential nonces share one
      ;; enciphering; that is the index the tag takes from the output.
      (setf value (logxor value index)))
    (dotimes (i 8)
      (setf (aref block i) (ldb (byte 8 (* 8 (- 7 i))) value)))
    (ironclad-unsafe:encrypt (ssh-umac-state-pdf-cipher state) block output)
    (subseq output (* index tag-length) (* (1+ index) tag-length))))

(defun ssh-umac-digest (state octets sequence)
  "The UMAC tag of OCTETS under STATE, with SEQUENCE as the nonce."
  (let* ((tag-length (ssh-umac-state-tag-length state))
         (iterations (/ tag-length 4))
         (short (<= (* 8 (length octets)) 8192))
         (result (make-array tag-length :element-type '(unsigned-byte 8))))
    (loop for i below iterations
          for l1 in (ssh-umac-state-l1-keys state)
          for l2 in (ssh-umac-state-l2-keys state)
          for key1 in (ssh-umac-state-l3-keys1 state)
          for key2 in (ssh-umac-state-l3-keys2 state)
          do (let* ((a (ssh-umac-l1-hash l1 octets))
                    (b (if short
                           (ssh-concat
                            (make-array 8 :element-type '(unsigned-byte 8)
                                          :initial-element 0)
                            a)
                           (ssh-umac-l2-hash l2 a)))
                    (c (ssh-umac-l3-hash key1 key2 b)))
               (replace result c :start1 (* i 4))))
    (let ((pad (ssh-umac-pdf state (ssh-uint64-octets sequence) tag-length)))
      (dotimes (i tag-length result)
        (setf (aref result i)
              (logxor (aref result i) (aref pad i)))))))

(defun ssh-make-umac-state (key &key (tag-length 8))
  "The UMAC key schedule for KEY, which must be sixteen octets.

TAG-LENGTH is 8 for umac-64 or 16 for umac-128.  The derived keys are
independent of the message, so one state serves a whole direction."
  (unless (= (length key) +ssh-umac-key-length+)
    (error 'ssh-protocol-error
           :detail (format nil "UMAC needs a ~D-octet key, not ~D"
                           +ssh-umac-key-length+ (length key))))
  (let* ((cipher (ironclad-unsafe:make-cipher :aes :key key :mode :ecb))
         (iterations (/ tag-length 4))
         (l1 (ssh-umac-kdf cipher 1 (+ 1024 (* (1- iterations) 16))))
         (l2 (ssh-umac-kdf cipher 2 (* iterations 24)))
         (l3-1 (ssh-umac-kdf cipher 3 (* iterations 64)))
         (l3-2 (ssh-umac-kdf cipher 4 (* iterations 4))))
    (%make-ssh-umac-state
     :tag-length tag-length
     :pdf-cipher (ironclad-unsafe:make-cipher
                  :aes :key (ssh-umac-kdf cipher 0 16) :mode :ecb)
     :l1-keys (loop for i below iterations
                    collect (subseq l1 (* i 16) (+ (* i 16) 1024)))
     :l2-keys (loop for i below iterations
                    collect (subseq l2 (* i 24) (* (1+ i) 24)))
     :l3-keys1 (loop for i below iterations
                     collect (subseq l3-1 (* i 64) (* (1+ i) 64)))
     :l3-keys2 (loop for i below iterations
                     collect (subseq l3-2 (* i 4) (* (1+ i) 4))))))

(defun ssh-umac (key octets sequence &key (tag-length 8))
  "The UMAC tag of OCTETS under KEY, with SEQUENCE as the nonce."
  (ssh-umac-digest (ssh-make-umac-state key :tag-length tag-length)
                   octets sequence))
