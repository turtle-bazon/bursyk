(in-package #:cl-pnet-ssh)

;;;; The binary packet protocol (RFC 4253 section 6), including OpenSSH's
;;;; chacha20-poly1305@openssh.com, AES-GCM and AES-CTR constructions and
;;;; the hmac-sha2 MACs.
;;;;
;;;; A packet is  uint32 length, byte padding-length, payload, padding
;;;; with LENGTH covering the padding-length byte, payload and padding.  The
;;;; MAC is computed over the sequence number and the *plaintext* packet for
;;;; the hmac-sha2 algorithms.  chacha20-poly1305 and AES-GCM are AEADs: they
;;;; hide the body, authenticate the plaintext length field, and carry their
;;;; own tag, so the negotiated MAC is ignored.  AES-CTR encrypts the whole
;;;; packet and appends the hmac in the clear.

(defconstant +ssh-block-size+ 8)
(defconstant +ssh-max-packet+ 262144
  "Largest packet accepted from a peer. OpenSSH's own limit is 256 KiB.")

(defconstant +ssh-aead-tag-length+ 16)

;;; ---- Cipher descriptions ----

(defun ssh-cipher-chacha-p (cipher)
  (and cipher (string= cipher "chacha20-poly1305@openssh.com")))

(defun ssh-cipher-gcm-p (cipher)
  (and cipher
       (member cipher '("aes128-gcm@openssh.com" "aes256-gcm@openssh.com")
               :test #'string=)))

(defun ssh-cipher-ctr-p (cipher)
  (and cipher
       (member cipher '("aes128-ctr" "aes192-ctr" "aes256-ctr")
               :test #'string=)))

(defun ssh-cipher-cbc-p (cipher)
  (and cipher
       (member cipher '("3des-cbc" "aes128-cbc" "aes192-cbc" "aes256-cbc")
               :test #'string=)))

(defun ssh-cipher-aead-p (cipher)
  "Whether CIPHER authenticates each packet and ignores the negotiated MAC."
  (or (ssh-cipher-chacha-p cipher) (ssh-cipher-gcm-p cipher)))

(defun ssh-cipher-block-cipher (cipher)
  "The ironclad name of CIPHER's block primitive, or NIL for the AEADs."
  (cond ((ssh-cipher-cbc-p cipher)
         (if (string= cipher "3des-cbc") :3des :aes))
        ((ssh-cipher-ctr-p cipher) :aes)
        (t nil)))

(defun ssh-cipher-key-length (cipher)
  "The key length of CIPHER, or NIL when it is not implemented."
  (cond ((ssh-cipher-chacha-p cipher) 64)
        ((member cipher '("aes128-gcm@openssh.com" "aes128-ctr"
                          "aes128-cbc")
                 :test #'string=)
         16)
        ((member cipher '("aes192-ctr" "aes192-cbc") :test #'string=)
         24)
        ((and cipher (string= cipher "3des-cbc")) 24)
        ((member cipher '("aes256-gcm@openssh.com" "aes256-ctr"
                          "aes256-cbc")
                 :test #'string=)
         32)
        (t nil)))

(defun ssh-cipher-iv-length (cipher)
  "The IV length of CIPHER, or NIL when it is not implemented."
  (cond ((ssh-cipher-chacha-p cipher) 0)
        ((ssh-cipher-ctr-p cipher) 16)
        ((and cipher (string= cipher "3des-cbc")) 8)
        ((ssh-cipher-cbc-p cipher) 16)
        ((ssh-cipher-gcm-p cipher) 12)
        (t nil)))

(defun ssh-cipher-block-size (cipher)
  "The block alignment CIPHER gives a packet, or NIL when unknown."
  (cond ((ssh-cipher-chacha-p cipher) 8)
        ((and cipher (string= cipher "3des-cbc")) 8)
        ((or (ssh-cipher-ctr-p cipher) (ssh-cipher-gcm-p cipher)
             (ssh-cipher-cbc-p cipher))
         16)
        (t nil)))

(defun ssh-cipher-tag-length (cipher)
  (if (ssh-cipher-aead-p cipher) +ssh-aead-tag-length+ 0))

(defparameter +ssh-etm-suffix+ "-etm@openssh.com")

(defun ssh-mac-etm-p (mac)
  "Whether MAC is an encrypt-then-MAC name."
  (and mac
       (let ((start (- (length mac) (length +ssh-etm-suffix+))))
         (and (not (minusp start))
              (string= +ssh-etm-suffix+ mac :start2 start)))))

(defparameter +ssh-mac-openssh-suffix+ "@openssh.com")

(defun ssh-mac-base-name (mac)
  "MAC without its -etm@openssh.com or @openssh.com suffix.

UMAC is spelled umac-64@openssh.com while its encrypt-then-MAC variant is
umac-64-etm@openssh.com, so stripping the -etm suffix alone is not enough
to reach the construction's name."
  (let* ((name (if (ssh-mac-etm-p mac)
                   (subseq mac 0 (- (length mac) (length +ssh-etm-suffix+)))
                   mac))
         (start (- (length name) (length +ssh-mac-openssh-suffix+))))
    (if (and (not (minusp start))
             (string= +ssh-mac-openssh-suffix+ name :start2 start))
        (subseq name 0 start)
        name)))

(defun ssh-mac-umac-p (mac)
  "Whether MAC is one of the UMAC constructions."
  (member (ssh-mac-base-name mac) '("umac-64" "umac-128")
          :test #'string=))

(defun ssh-mac-truncated-p (mac)
  "Whether MAC is one of the 96-bit truncated HMAC constructions."
  (member (ssh-mac-base-name mac) '("hmac-sha1-96" "hmac-md5-96")
          :test #'string=))

(defun ssh-mac-legacy-p (mac)
  "Whether MAC is one of the MD5 or 96-bit truncated HMACs.

OpenSSH implements these but leaves them out of its default offer, and
libssh 0.10 does not implement them at all."
  (member (ssh-mac-base-name mac)
          '("hmac-md5" "hmac-md5-96" "hmac-sha1-96")
          :test #'string=))

(defun ssh-mac-hmac-digest (mac)
  "The HMAC digest behind the MAC keyword MAC.

A truncated MAC shares its digest with the full-length name; the keyword
remembers the truncation so the tag length need not be negotiated
separately."
  (case mac
    ((:sha1 :sha1-96) :sha1)
    ((:md5 :md5-96) :md5)
    (t mac)))

(defun ssh-mac-tag (state direction data)
  "The MAC over DATA for DIRECTION, or NIL when none is negotiated.

HMAC prefixes the sequence number to DATA; UMAC takes it as the nonce, so
the two constructions cannot share one call.  A truncated HMAC is cut to
its first SSH-HMAC-LENGTH octets after the full digest is computed."
  (let* ((receive (eq direction :receive))
         (name (if receive
                   (ssh-cipher-state-decrypt-mac state)
                   (ssh-cipher-state-encrypt-mac state)))
         (key (if receive
                  (ssh-cipher-state-decrypt-mac-key state)
                  (ssh-cipher-state-encrypt-mac-key state)))
         (umac (if receive
                   (ssh-cipher-state-decrypt-umac state)
                   (ssh-cipher-state-encrypt-umac state)))
         (sequence (if receive
                       (ssh-cipher-state-receive-sequence state)
                       (ssh-cipher-state-send-sequence state))))
    (when name
      (if umac
          (ssh-umac-digest umac data sequence)
          (let* ((tag (ssh-hmac key
                                (ssh-concat (ssh-uint32-octets sequence) data)
                                (ssh-mac-hmac-digest name)))
                 (length (ssh-hmac-length name)))
            (if (< length (length tag))
                (subseq tag 0 length)
                tag))))))

(defstruct (ssh-cipher-state (:constructor ssh-make-cipher-state))
  ;; ENCRYPT and DECRYPT hold the key material the cipher routines need:
  ;; the two chacha20 keys for chacha20-poly1305, the AES key otherwise.
  (encrypt nil)
  (decrypt nil)
  (encrypt-name nil)
  (decrypt-name nil)
  (encrypt-iv nil)
  (decrypt-iv nil)
  ;; AES-CTR keeps an ECB cipher for keystream generation and a byte offset
  ;; into the stream; AES-GCM counts packets to build each nonce.
  (encrypt-ecb nil)
  (decrypt-ecb nil)
  (encrypt-offset 0)
  (decrypt-offset 0)
  (encrypt-packet 0)
  (decrypt-packet 0)
  ;; CBC keeps a stateful cipher object whose IV chains across packets, and
  ;; a copy of the current IV so a partial packet can peek at its length
  ;; without advancing that chain.
  (encrypt-cbc nil)
  (decrypt-cbc nil)
  (encrypt-cbc-iv nil)
  (decrypt-cbc-iv nil)
  (encrypt-mac-key nil)
  (decrypt-mac-key nil)
  (encrypt-mac nil)
  (decrypt-mac nil)
  (encrypt-etm nil)
  (decrypt-etm nil)
  ;; UMAC's key schedule, when the negotiated MAC is one of its names.
  (encrypt-umac nil)
  (decrypt-umac nil)
  (send-sequence 0 :type (unsigned-byte 32))
  (receive-sequence 0 :type (unsigned-byte 32))
  (block-size +ssh-block-size+)
  (send-block-size +ssh-block-size+)
  (receive-block-size +ssh-block-size+)
  ;; RFC 4253 6.2 compression.  The codec objects live for the whole
  ;; connection and are reset at every NEWKEYS; the ENABLED flags stay false
  ;; for zlib@openssh.com until authentication succeeds, because that method
  ;; starts compressing only after USERAUTH_SUCCESS.
  (send-compression nil)
  (receive-compression nil)
  (send-compression-prefix nil)
  (send-compression-enabled nil)
  (receive-compression-enabled nil))

(defun ssh-packet-padding-length (payload-length
                                  &optional (length-octets 4)
                                            (block-size +ssh-block-size+))
  "The smallest padding of at least four octets that aligns the packet.

LENGTH-OCTETS is how much of the packet OpenSSH counts towards the block
alignment: 4 (the length field) for plain, CTR and EtM framing, 0 for AEAD,
whose length field travels outside the encrypted body.  BLOCK-SIZE is the
cipher's alignment: 8 for chacha20-poly1305, 16 for AES."
  (let ((padding (- block-size
                    (mod (+ length-octets 1 payload-length) block-size))))
    (if (< padding 4) (+ padding block-size) padding)))

(defun ssh-packet-body (payload padding-length)
  "PADDING-LENGTH, PAYLOAD and random padding, ready to encrypt."
  (let* ((padding (ssh-random-octets padding-length))
         (body (make-array (+ 1 (length payload) padding-length)
                           :element-type '(unsigned-byte 8))))
    (setf (aref body 0) padding-length)
    (replace body payload :start1 1)
    (replace body padding :start1 (+ 1 (length payload)))
    body))

;;; ---- AES-CTR and AES-GCM helpers ----

(defun ssh-counter-block (iv index)
  "IV plus INDEX as a 128-bit big-endian counter, 16 octets.

AES-CTR numbers blocks by adding to the whole initial counter block, and
AES-GCM numbers packets by adding to the last four octets of its nonce."
  (let ((block (copy-seq iv))
        (carry index))
    (loop for position from (1- (length block)) downto 0
          while (plusp carry)
          do (let ((sum (+ (aref block position) (logand carry #xff))))
               (setf (aref block position) (logand sum #xff)
                     ;; The byte's own overflow joins the remaining high
                     ;; part, so a counter that wraps 0xff carries onward.
                     carry (+ (ash carry -8) (ash sum -8)))))
    block))

(defun ssh-aes-ctr-xor (ecb iv offset data)
  "XOR DATA with the AES-CTR keystream that starts at byte OFFSET."
  (let* ((length (length data))
         (skip (mod offset 16))
         (first (floor offset 16))
         (blocks (ceiling (+ skip length) 16))
         (counters (make-array (* blocks 16)
                               :element-type '(unsigned-byte 8)))
         (keystream (make-array (* blocks 16)
                                :element-type '(unsigned-byte 8)))
         (output (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (index blocks)
      (replace counters (ssh-counter-block iv (+ first index))
               :start1 (* index 16)))
    (ironclad-unsafe:encrypt ecb counters keystream)
    (dotimes (index length output)
      (setf (aref output index)
            (logxor (aref data index) (aref keystream (+ skip index)))))))

(defun ssh-gcm-nonce (iv counter)
  "IV with its last four octets advanced by COUNTER."
  (ssh-counter-block iv counter))

;;; ---- CBC helpers ----

(defun ssh-cbc-crypt (cipher data decrypt-p)
  "Run DATA through the stateful CBC CIPHER and return fresh octets.

DATA must be a whole number of blocks.  The cipher object carries its IV
from one packet to the next, as SSH's CBC modes require."
  (let ((output (make-array (length data)
                            :element-type '(unsigned-byte 8))))
    (if decrypt-p
        (ironclad-unsafe:decrypt cipher data output)
        (ironclad-unsafe:encrypt cipher data output))
    output))

(defun ssh-cbc-peek-block (ecb iv block)
  "Decrypt one CBC BLOCK with ECB ECB under IV, without touching any chain."
  (let* ((size (length block))
         (plain (make-array size :element-type '(unsigned-byte 8)))
         (output (make-array size :element-type '(unsigned-byte 8))))
    (ironclad-unsafe:decrypt ecb block plain)
    (dotimes (index size output)
      (setf (aref output index)
            (logxor (aref plain index) (aref iv index))))))

(defun ssh-cbc-last-block (octets block-size)
  "The last BLOCK-SIZE octets of OCTETS, as the next packet's CBC IV."
  (subseq octets (- (length octets) block-size)))

;;; ---- Encoding ----

(defun ssh-chacha-encode (payload state)
  "PAYLOAD as an encrypted, tagged chacha20-poly1305 packet."
  (let* ((sequence (ssh-cipher-state-send-sequence state))
         (nonce (ssh-chacha-nonce sequence))
         (padding-length (ssh-packet-padding-length (length payload) 0 8))
         (body (ssh-packet-body payload padding-length))
         (length (+ 1 (length payload) padding-length))
         (key (ssh-cipher-state-encrypt state))
         (encrypted-length (ssh-chacha-encrypt-length key sequence length))
         (encrypted-body (ssh-chacha20-xor (ssh-chacha-packet-key-payload-key key)
                                           nonce 1 body))
         (tag (ssh-poly1305 (ssh-chacha-poly-key key sequence)
                            (ssh-concat encrypted-length encrypted-body))))
    (setf (ssh-cipher-state-send-sequence state) (mod (1+ sequence) (expt 2 32)))
    (ssh-concat encrypted-length encrypted-body tag)))

(defun ssh-gcm-encode (payload state)
  "PAYLOAD as an encrypted, tagged AES-GCM packet.

OpenSSH leaves the length field in the clear and authenticates it as
associated data, so the body alone is padded to the 16-octet block size."
  (let* ((key (ssh-cipher-state-encrypt state))
         (iv (ssh-cipher-state-encrypt-iv state))
         (packet-index (ssh-cipher-state-encrypt-packet state))
         (nonce (ssh-gcm-nonce iv packet-index))
         (padding-length (ssh-packet-padding-length (length payload) 0 16))
         (body (ssh-packet-body payload padding-length))
         (length-octets (ssh-uint32-octets (length body)))
         (mode (ironclad-unsafe:make-authenticated-encryption-mode
                :gcm :cipher-name :aes :key key
                :initialization-vector nonce))
         (ciphertext (ironclad-unsafe:encrypt-message
                      mode body :associated-data length-octets))
         (tag (ironclad-unsafe:produce-tag mode)))
    (setf (ssh-cipher-state-encrypt-packet state)
          (mod (1+ packet-index) (expt 2 32)))
    (ssh-concat length-octets ciphertext tag)))

(defun ssh-plain-encode (payload state)
  "PAYLOAD framed plainly, with an hmac-sha2 tag when one is negotiated."
  (let* ((sequence (ssh-cipher-state-send-sequence state))
         (padding-length (ssh-packet-padding-length (length payload)))
         (body (ssh-packet-body payload padding-length))
         (packet (ssh-concat (ssh-uint32-octets (+ 1 (length payload)
                                                   padding-length))
                             body))
         (mac (ssh-mac-tag state :send packet))
         (output (if mac (ssh-concat packet mac) packet)))
    (setf (ssh-cipher-state-send-sequence state) (mod (1+ sequence) (expt 2 32)))
    output))

(defun ssh-ctr-encode (payload state)
  "PAYLOAD as an AES-CTR packet with an hmac appended in the clear.

With an encrypt-then-MAC algorithm the length field stays plaintext and only
the body enters the cipher stream, so the MAC can be checked before anything
is decrypted.  A plain MAC is computed over the plaintext packet and the
whole packet is then encrypted."
  (let* ((sequence (ssh-cipher-state-send-sequence state))
         (block-size (ssh-cipher-state-send-block-size state))
         (etm (ssh-cipher-state-encrypt-etm state))
         (padding-length (ssh-packet-padding-length
                          (length payload) (if etm 0 4) block-size))
         (body (ssh-packet-body payload padding-length))
         (length-octets (ssh-uint32-octets (length body)))
         (plain (ssh-concat length-octets body))
         (ecb (ssh-cipher-state-encrypt-ecb state))
         (iv (ssh-cipher-state-encrypt-iv state))
         (offset (ssh-cipher-state-encrypt-offset state)))
    (if etm
        (let* ((encrypted-body (ssh-aes-ctr-xor ecb iv offset body))
               (packet (ssh-concat length-octets encrypted-body))
               (mac (ssh-mac-tag state :send packet)))
          (setf (ssh-cipher-state-encrypt-offset state)
                (+ offset (length body))
                (ssh-cipher-state-send-sequence state)
                (mod (1+ sequence) (expt 2 32)))
          (if mac (ssh-concat packet mac) packet))
        (let* ((mac (ssh-mac-tag state :send plain))
               (encrypted (ssh-aes-ctr-xor ecb iv offset plain)))
          (setf (ssh-cipher-state-encrypt-offset state)
                (+ offset (length plain))
                (ssh-cipher-state-send-sequence state)
                (mod (1+ sequence) (expt 2 32)))
          (if mac (ssh-concat encrypted mac) encrypted)))))

(defun ssh-cbc-encode (payload state)
  "PAYLOAD as a CBC packet with an hmac appended in the clear.

CBC chains the IV from one packet into the next, so the cipher object keeps
the state and only the current IV is mirrored here.  With an encrypt-then-MAC
algorithm the length stays plaintext and only the body is chained; a plain
MAC is taken over the plaintext packet before the whole packet is encrypted."
  (let* ((sequence (ssh-cipher-state-send-sequence state))
         (block-size (ssh-cipher-state-send-block-size state))
         (etm (ssh-cipher-state-encrypt-etm state))
         (padding-length (ssh-packet-padding-length
                          (length payload) (if etm 0 4) block-size))
         (body (ssh-packet-body payload padding-length))
         (length-octets (ssh-uint32-octets (length body)))
         (plain (ssh-concat length-octets body))
         (cipher (ssh-cipher-state-encrypt-cbc state)))
    (if etm
        (let* ((encrypted-body (ssh-cbc-crypt cipher body nil))
               (packet (ssh-concat length-octets encrypted-body))
               (mac (ssh-mac-tag state :send packet)))
          (setf (ssh-cipher-state-encrypt-cbc-iv state)
                (ssh-cbc-last-block encrypted-body block-size)
                (ssh-cipher-state-send-sequence state)
                (mod (1+ sequence) (expt 2 32)))
          (if mac (ssh-concat packet mac) packet))
        (let* ((mac (ssh-mac-tag state :send plain))
               (encrypted (ssh-cbc-crypt cipher plain nil)))
          (setf (ssh-cipher-state-encrypt-cbc-iv state)
                (ssh-cbc-last-block encrypted block-size)
                (ssh-cipher-state-send-sequence state)
                (mod (1+ sequence) (expt 2 32)))
          (if mac (ssh-concat encrypted mac) encrypted)))))

(defun ssh-encode-packet (payload state)
  "Cycle STATE's sequence and return PAYLOAD as wire octets."
  (let* ((payload (if (ssh-cipher-state-send-compression-enabled state)
                      (ssh-compress-payload payload state)
                      payload))
         (name (ssh-cipher-state-encrypt-name state)))
    (cond
      ((null (ssh-cipher-state-encrypt state))
       (ssh-plain-encode payload state))
      ((ssh-cipher-chacha-p name)
       (ssh-chacha-encode payload state))
      ((ssh-cipher-gcm-p name)
       (ssh-gcm-encode payload state))
      ((ssh-cipher-ctr-p name)
       (ssh-ctr-encode payload state))
      ((ssh-cipher-cbc-p name)
       (ssh-cbc-encode payload state))
      (t
       (error 'ssh-protocol-error
              :detail (format nil "cannot encrypt with cipher ~A" name))))))

(defun ssh-packet-mac-length (state direction)
  "How many MAC octets a packet in DIRECTION carries."
  (if (eq direction :receive)
      (if (ssh-cipher-state-decrypt-mac state)
          (ssh-hmac-length (ssh-cipher-state-decrypt-mac state))
          0)
      (if (ssh-cipher-state-encrypt-mac state)
          (ssh-hmac-length (ssh-cipher-state-encrypt-mac state))
          0)))

(defun ssh-packet-authentication-length (state direction)
  "The tag or MAC octets a DIRECTION packet carries.

chacha20-poly1305 and AES-GCM hide their tag inside the AEAD construction, so
their negotiated MAC is unused; every other cipher appends its hmac.  Before
the first NEWKEYS there is no cipher state at all, and an unencrypted packet
carries no authentication."
  (if (null state)
      0
      (let* ((receive (eq direction :receive))
             (cipher (if receive
                         (ssh-cipher-state-decrypt state)
                         (ssh-cipher-state-encrypt state)))
             (name (if receive
                       (ssh-cipher-state-decrypt-name state)
                       (ssh-cipher-state-encrypt-name state))))
        (if (and cipher (ssh-cipher-aead-p name))
            +ssh-aead-tag-length+
            (ssh-packet-mac-length state direction)))))

(defun ssh-packet-counted-length (wire-length state direction)
  "WIRE-LENGTH less the MAC a DIRECTION packet carries.

OpenSSH counts this length, the length field plus padding length, payload
and padding, against a cipher's block limits.  The tag is not part of it."
  (- wire-length (ssh-packet-authentication-length state direction)))

(defun ssh-strip-padding (body payload-length)
  "Payload octets from the decrypted BODY, or signal on bad padding."
  (unless (plusp (length body))
    (error 'ssh-protocol-error :detail "empty packet body"))
  (let ((padding-length (aref body 0)))
    (unless (<= 4 padding-length)
      (error 'ssh-protocol-error
             :detail (format nil "packet padding ~D is below the minimum"
                             padding-length)))
    (unless (<= padding-length (- payload-length 1))
      (error 'ssh-protocol-error
             :detail (format nil "packet padding ~D does not fit a ~D-octet body"
                             padding-length payload-length)))
    (subseq body 1 (- payload-length padding-length))))

;;; ---- Decoding ----

(defun ssh-chacha-decode (buffer state)
  "Decode one chacha20-poly1305 packet from BUFFER."
  (when (< (length buffer) 4)
    (return-from ssh-chacha-decode (values :incomplete 0)))
  (let* ((sequence (ssh-cipher-state-receive-sequence state))
         (key (ssh-cipher-state-decrypt state))
         (length (ssh-chacha-decrypt-length key sequence buffer))
         (needed (+ 4 length 16)))
    (unless (<= 1 length +ssh-max-packet+)
      (error 'ssh-protocol-error
             :detail (format nil "packet length ~D outside 1..~D"
                             length +ssh-max-packet+)))
    (when (< (length buffer) needed)
      (return-from ssh-chacha-decode (values :incomplete 0)))
    (let* ((tag-start (+ 4 length))
           (expected (subseq buffer tag-start (+ tag-start 16)))
           (actual (ssh-poly1305 (ssh-chacha-poly-key key sequence)
                                 (subseq buffer 0 tag-start))))
      (unless (ssh-octets= expected actual)
        (error 'ssh-protocol-error :detail "packet MAC does not verify"))
      (let* ((nonce (ssh-chacha-nonce sequence))
             (encrypted (subseq buffer 4 tag-start))
             (body (ssh-chacha20-xor
                    (ssh-chacha-packet-key-payload-key key) nonce 1 encrypted))
             (payload (ssh-strip-padding body length)))
        (setf (ssh-cipher-state-receive-sequence state)
              (mod (1+ sequence) (expt 2 32)))
        (values payload needed)))))

(defun ssh-gcm-decode (buffer state)
  "Decode one AES-GCM packet from BUFFER."
  (when (< (length buffer) 4)
    (return-from ssh-gcm-decode (values :incomplete 0)))
  (let* ((length (ssh-octets-uint32 buffer))
         (needed (+ 4 length 16)))
    (unless (<= 1 length +ssh-max-packet+)
      (error 'ssh-protocol-error
             :detail (format nil "packet length ~D outside 1..~D"
                             length +ssh-max-packet+)))
    (when (< (length buffer) needed)
      (return-from ssh-gcm-decode (values :incomplete 0)))
    (let* ((key (ssh-cipher-state-decrypt state))
           (iv (ssh-cipher-state-decrypt-iv state))
           (packet-index (ssh-cipher-state-decrypt-packet state))
           (nonce (ssh-gcm-nonce iv packet-index))
           (aad (subseq buffer 0 4))
           (ciphertext (subseq buffer 4 (+ 4 length)))
           (tag (subseq buffer (+ 4 length) needed))
           (mode (ironclad-unsafe:make-authenticated-encryption-mode
                  :gcm :cipher-name :aes :key key
                  :initialization-vector nonce :tag tag)))
      (handler-case
          (let ((body (ironclad-unsafe:decrypt-message
                       mode ciphertext :associated-data aad)))
            (setf (ssh-cipher-state-decrypt-packet state)
                  (mod (1+ packet-index) (expt 2 32)))
            (values (ssh-strip-padding body length) needed))
        (ironclad-unsafe:bad-authentication-tag ()
          (error 'ssh-protocol-error :detail "packet MAC does not verify"))))))

(defun ssh-ctr-decode (buffer state)
  "Decode one AES-CTR packet from BUFFER."
  (let* ((block-size (ssh-cipher-state-receive-block-size state))
         (etm (ssh-cipher-state-decrypt-etm state))
         (ecb (ssh-cipher-state-decrypt-ecb state))
         (iv (ssh-cipher-state-decrypt-iv state))
         (offset (ssh-cipher-state-decrypt-offset state))
         (mac-length (ssh-packet-mac-length state :receive)))
    (if etm
        ;; EtM leaves the length in the clear, so the packet is framed and
        ;; authenticated before a single body octet is decrypted.
        (progn
          (when (< (length buffer) 4)
            (return-from ssh-ctr-decode (values :incomplete 0)))
          (let* ((length (ssh-octets-uint32 buffer))
                 (needed (+ 4 length mac-length)))
            (unless (<= 1 length +ssh-max-packet+)
              (error 'ssh-protocol-error
                     :detail (format nil "packet length ~D outside 1..~D"
                                     length +ssh-max-packet+)))
            (when (< (length buffer) needed)
              (return-from ssh-ctr-decode (values :incomplete 0)))
            (let* ((sequence (ssh-cipher-state-receive-sequence state))
                   (wire (subseq buffer 0 (+ 4 length))))
              (when (plusp mac-length)
                (let ((expected (subseq buffer (+ 4 length) needed))
                      (actual (ssh-mac-tag state :receive wire)))
                  (unless (ssh-octets= expected actual)
                    (error 'ssh-protocol-error
                           :detail "packet MAC does not verify"))))
              (let ((body (ssh-aes-ctr-xor ecb iv offset
                                           (subseq wire 4))))
                (setf (ssh-cipher-state-decrypt-offset state)
                      (+ offset length)
                      (ssh-cipher-state-receive-sequence state)
                      (mod (1+ sequence) (expt 2 32)))
                (values (ssh-strip-padding body length) needed)))))
        (progn
          (when (< (length buffer) block-size)
            (return-from ssh-ctr-decode (values :incomplete 0)))
          ;; The length field is encrypted, so decrypt the first block to
          ;; read it without advancing the stream: SSH-AES-CTR-XOR is a pure
          ;; function of OFFSET, and the packet is decrypted again below.
          (let* ((first (ssh-aes-ctr-xor ecb iv offset
                                         (subseq buffer 0 block-size)))
                 (length (ssh-octets-uint32 first))
                 (needed (+ 4 length mac-length)))
            (unless (<= 1 length +ssh-max-packet+)
              (error 'ssh-protocol-error
                     :detail (format nil "packet length ~D outside 1..~D"
                                     length +ssh-max-packet+)))
            (when (< (length buffer) needed)
              (return-from ssh-ctr-decode (values :incomplete 0)))
            (let* ((sequence (ssh-cipher-state-receive-sequence state))
                   (packet (ssh-aes-ctr-xor ecb iv offset
                                            (subseq buffer 0 (+ 4 length)))))
              (when (plusp mac-length)
                (let ((expected (subseq buffer (+ 4 length) needed))
                      (actual (ssh-mac-tag state :receive packet)))
                  (unless (ssh-octets= expected actual)
                    (error 'ssh-protocol-error
                           :detail "packet MAC does not verify"))))
              (setf (ssh-cipher-state-decrypt-offset state)
                    (+ offset 4 length)
                    (ssh-cipher-state-receive-sequence state)
                    (mod (1+ sequence) (expt 2 32)))
              (values (ssh-strip-padding (subseq packet 4) length)
                      needed)))))))

(defun ssh-cbc-decode (buffer state)
  "Decode one CBC packet from BUFFER.

A plain MAC leaves the length encrypted, so the first block is decrypted
under the current IV with a stateless ECB operation: that reads the length
without advancing the chain, and an incomplete packet leaves everything as
it was.  Encrypt-then-MAC keeps the length in the clear, verifies before
decrypting, and chains only the body."
  (let* ((block-size (ssh-cipher-state-receive-block-size state))
         (etm (ssh-cipher-state-decrypt-etm state))
         (cipher (ssh-cipher-state-decrypt-cbc state))
         (mac-length (ssh-packet-mac-length state :receive)))
    (if etm
        (progn
          (when (< (length buffer) 4)
            (return-from ssh-cbc-decode (values :incomplete 0)))
          (let* ((length (ssh-octets-uint32 buffer))
                 (needed (+ 4 length mac-length)))
            (unless (<= 1 length +ssh-max-packet+)
              (error 'ssh-protocol-error
                     :detail (format nil "packet length ~D outside 1..~D"
                                     length +ssh-max-packet+)))
            (unless (zerop (mod length block-size))
              (error 'ssh-protocol-error
                     :detail (format nil "CBC body length ~D is not a multiple of ~D"
                                     length block-size)))
            (when (< (length buffer) needed)
              (return-from ssh-cbc-decode (values :incomplete 0)))
            (let* ((sequence (ssh-cipher-state-receive-sequence state))
                   (encrypted (subseq buffer 4 (+ 4 length)))
                   (wire (subseq buffer 0 (+ 4 length))))
              (when (plusp mac-length)
                (let ((expected (subseq buffer (+ 4 length) needed))
                      (actual (ssh-mac-tag state :receive wire)))
                  (unless (ssh-octets= expected actual)
                    (error 'ssh-protocol-error
                           :detail "packet MAC does not verify"))))
              (let ((body (ssh-cbc-crypt cipher encrypted t)))
                (setf (ssh-cipher-state-decrypt-cbc-iv state)
                      (ssh-cbc-last-block encrypted block-size)
                      (ssh-cipher-state-receive-sequence state)
                      (mod (1+ sequence) (expt 2 32)))
                (values (ssh-strip-padding body length) needed)))))
        (progn
          (when (< (length buffer) block-size)
            (return-from ssh-cbc-decode (values :incomplete 0)))
          (let* ((first (ssh-cbc-peek-block
                         (ssh-cipher-state-decrypt-ecb state)
                         (ssh-cipher-state-decrypt-cbc-iv state)
                         (subseq buffer 0 block-size)))
                 (length (ssh-octets-uint32 first))
                 (needed (+ 4 length mac-length)))
            (unless (<= 1 length +ssh-max-packet+)
              (error 'ssh-protocol-error
                     :detail (format nil "packet length ~D outside 1..~D"
                                     length +ssh-max-packet+)))
            (unless (zerop (mod (+ 4 length) block-size))
              (error 'ssh-protocol-error
                     :detail (format nil "CBC packet length ~D is not a multiple of ~D"
                                     (+ 4 length) block-size)))
            (when (< (length buffer) needed)
              (return-from ssh-cbc-decode (values :incomplete 0)))
            (let* ((sequence (ssh-cipher-state-receive-sequence state))
                   (encrypted (subseq buffer 0 (+ 4 length)))
                   (packet (ssh-cbc-crypt cipher encrypted t)))
              (when (plusp mac-length)
                (let ((expected (subseq buffer (+ 4 length) needed))
                      (actual (ssh-mac-tag state :receive packet)))
                  (unless (ssh-octets= expected actual)
                    (error 'ssh-protocol-error
                           :detail "packet MAC does not verify"))))
              (setf (ssh-cipher-state-decrypt-cbc-iv state)
                    (ssh-cbc-last-block encrypted block-size)
                    (ssh-cipher-state-receive-sequence state)
                    (mod (1+ sequence) (expt 2 32)))
              (values (ssh-strip-padding (subseq packet 4) length)
                      needed)))))))

(defun ssh-plain-decode (buffer state)
  "Decode one plain or hmac-tagged packet from BUFFER."
  (when (< (length buffer) 4)
    (return-from ssh-plain-decode (values :incomplete 0)))
  (let* ((length (ssh-octets-uint32 buffer))
         (mac-length (ssh-packet-mac-length state :receive))
         (needed (+ 4 length mac-length)))
    (unless (<= 1 length +ssh-max-packet+)
      (error 'ssh-protocol-error
             :detail (format nil "packet length ~D outside 1..~D"
                             length +ssh-max-packet+)))
    (when (< (length buffer) needed)
      (return-from ssh-plain-decode (values :incomplete 0)))
    (let* ((sequence (ssh-cipher-state-receive-sequence state))
           (packet (subseq buffer 0 (+ 4 length))))
      (when (plusp mac-length)
        (let ((expected (subseq buffer (+ 4 length) needed))
              (actual (ssh-mac-tag state :receive packet)))
          (unless (ssh-octets= expected actual)
            (error 'ssh-protocol-error :detail "packet MAC does not verify"))))
      (setf (ssh-cipher-state-receive-sequence state)
            (mod (1+ sequence) (expt 2 32)))
      (values (ssh-strip-padding (subseq buffer 4 (+ 4 length)) length)
              needed))))

(defun ssh-decode-packet (buffer state)
  "One packet from BUFFER as (VALUES PAYLOAD CONSUMED), or :INCOMPLETE."
  (let ((name (ssh-cipher-state-decrypt-name state)))
    (multiple-value-bind (payload consumed)
        (cond
          ((null (ssh-cipher-state-decrypt state))
           (ssh-plain-decode buffer state))
          ((ssh-cipher-chacha-p name)
           (ssh-chacha-decode buffer state))
          ((ssh-cipher-gcm-p name)
           (ssh-gcm-decode buffer state))
          ((ssh-cipher-ctr-p name)
           (ssh-ctr-decode buffer state))
          ((ssh-cipher-cbc-p name)
           (ssh-cbc-decode buffer state))
          (t
           (error 'ssh-protocol-error
                  :detail (format nil "cannot decrypt with cipher ~A" name))))
      (if (eq payload :incomplete)
          (values :incomplete 0)
          (values (if (ssh-cipher-state-receive-compression-enabled state)
                      (ssh-decompress-payload payload state)
                      payload)
                  consumed)))))

(defun ssh-compress-payload (payload state)
  "PAYLOAD compressed for the send stream, including any reset header.

zlib@openssh.com wraps one persistent zlib stream around every packet in a
direction.  Each packet is written and partially flushed, so the peer can
inflate it without seeing the end of the stream.  A NEWKEYS reset returns the
new zlib header from the codec; it must ride in front of the next packet."
  (let* ((compressor (ssh-cipher-state-send-compression state))
         (prefix (ssh-cipher-state-send-compression-prefix state))
         (written (cl-newzlib:deflate-state-write compressor payload))
         (flushed (cl-newzlib:deflate-state-flush compressor :mode :partial)))
    (setf (ssh-cipher-state-send-compression-prefix state) nil)
    (if prefix
        (ssh-concat prefix written flushed)
        (ssh-concat written flushed))))

(defun ssh-decompress-payload (payload state)
  "PAYLOAD inflated from the receive stream.

A corrupt stream is a protocol error, and a packet that inflates past the
largest packet this build accepts is refused rather than trusted, matching
OpenSSH's PACKET_MAX_SIZE check."
  (handler-case
      (let ((plain (cl-newzlib:inflate-packet
                    (ssh-cipher-state-receive-compression state) payload)))
        (when (> (length plain) +ssh-max-packet+)
          (error 'ssh-protocol-error
                 :detail (format nil "packet inflates to ~D octets, over the ~D-octet limit"
                                 (length plain) +ssh-max-packet+)))
        plain)
    (cl-newzlib:newzlib-error (condition)
      (error 'ssh-protocol-error
             :detail (format nil "packet decompression failed: ~A"
                             condition)))))

(defun ssh-end-send-compression (state)
  (when (ssh-cipher-state-send-compression state)
    (ignore-errors
      (cl-newzlib:deflate-state-end (ssh-cipher-state-send-compression state))))
  (setf (ssh-cipher-state-send-compression state) nil
        (ssh-cipher-state-send-compression-prefix state) nil
        (ssh-cipher-state-send-compression-enabled state) nil))

(defun ssh-end-receive-compression (state)
  (when (ssh-cipher-state-receive-compression state)
    (ignore-errors
      (cl-newzlib:inflate-state-end
       (ssh-cipher-state-receive-compression state))))
  (setf (ssh-cipher-state-receive-compression state) nil
        (ssh-cipher-state-receive-compression-enabled state) nil))

(defun ssh-install-send-compression (state name &key after-authentication)
  "Prepare STATE's outgoing compression for NAME at NEWKEYS.

NAME is \"none\" or \"zlib@openssh.com\".  A zlib stream is created at the
first NEWKEYS but stays inactive until authentication succeeds, because
zlib@openssh.com is delayed; a later NEWKEYS resets the live stream and keeps
the new zlib header for the first packet that follows."
  (if (not (and name (string= name "zlib@openssh.com")))
      (ssh-end-send-compression state)
      (let ((existing (ssh-cipher-state-send-compression state)))
        (if existing
            (setf (ssh-cipher-state-send-compression-prefix state)
                  (cl-newzlib:deflate-state-reset existing))
            (setf (ssh-cipher-state-send-compression state)
                  (cl-newzlib:make-deflate-state
                   :format :zlib :level 1 :strategy :huffman-only
                   :window-bits 15 :mem-level 8)
                  (ssh-cipher-state-send-compression-prefix state) nil))
        (when (or after-authentication
                  (ssh-cipher-state-send-compression-enabled state))
          (setf (ssh-cipher-state-send-compression-enabled state) t))))
  state)

(defun ssh-install-receive-compression (state name &key after-authentication)
  "Prepare STATE's incoming compression for NAME at NEWKEYS.

The inflate side mirrors SSH-INSTALL-SEND-COMPRESSION: the decoder is created
at the first NEWKEYS, reset on every later one, and starts consuming the
peer's stream only once authentication succeeds."
  (if (not (and name (string= name "zlib@openssh.com")))
      (ssh-end-receive-compression state)
      (let ((existing (ssh-cipher-state-receive-compression state)))
        (if existing
            (cl-newzlib:inflate-state-reset existing)
            (setf (ssh-cipher-state-receive-compression state)
                  (cl-newzlib:make-inflate-state :format :zlib)))
        (when (or after-authentication
                  (ssh-cipher-state-receive-compression-enabled state))
          (setf (ssh-cipher-state-receive-compression-enabled state) t))))
  state)

(defun ssh-enable-delayed-compression (state)
  "Start both directions of a negotiated zlib@openssh.com stream.

OpenSSH calls this once USERAUTH_SUCCESS has crossed: the server after
sending it, the client after receiving it.  A state that was never negotiated
is left alone, and calling this twice is harmless."
  (when (ssh-cipher-state-send-compression state)
    (setf (ssh-cipher-state-send-compression-enabled state) t))
  (when (ssh-cipher-state-receive-compression state)
    (setf (ssh-cipher-state-receive-compression-enabled state) t))
  state)

(defun ssh-install-keys (state &key (encrypt nil encrypt-p)
                                   (decrypt nil decrypt-p)
                                   (encrypt-iv nil encrypt-iv-p)
                                   (decrypt-iv nil decrypt-iv-p)
                                   (encrypt-cipher nil encrypt-cipher-p)
                                   (decrypt-cipher nil decrypt-cipher-p)
                                   (encrypt-mac-key nil encrypt-mac-key-p)
                                   (decrypt-mac-key nil decrypt-mac-key-p)
                                   (encrypt-mac nil encrypt-mac-p)
                                   (decrypt-mac nil decrypt-mac-p)
                                   (encrypt-mac-etm nil encrypt-mac-etm-p)
                                   (decrypt-mac-etm nil decrypt-mac-etm-p)
                                   aead)
  "Put negotiated keys into STATE, leaving the sequence numbers alone.

The caller resets them at the NEWKEYS boundary, which is where strict KEX
requires the reset. Either direction can be installed on its own, which is
what the two NEWKEYS messages require; arguments the caller omits leave that
half unchanged.  ENCRYPT-CIPHER and DECRYPT-CIPHER name the negotiated
ciphers; a caller that omits them and passes AEAD gets
chacha20-poly1305@openssh.com, which keeps the older two-argument form
working.  chacha20-poly1305 takes the raw 64-octet key and turns it into its
two packet keys here; AES-CTR builds its keystream cipher here as well."
  (when encrypt-p
    (let* ((name (if encrypt-cipher-p
                     encrypt-cipher
                     (and aead "chacha20-poly1305@openssh.com")))
           (block-size (or (ssh-cipher-block-size name) +ssh-block-size+))
           (block-cipher (ssh-cipher-block-cipher name))
           (cbc (ssh-cipher-cbc-p name)))
      (setf (ssh-cipher-state-encrypt state)
            (if (ssh-cipher-chacha-p name)
                (ssh-chacha-packet-key encrypt)
                encrypt)
            (ssh-cipher-state-encrypt-name state) name
            (ssh-cipher-state-encrypt-iv state) encrypt-iv
            (ssh-cipher-state-encrypt-ecb state)
            (and block-cipher
                 (ironclad-unsafe:make-cipher block-cipher :key encrypt
                                              :mode :ecb))
            (ssh-cipher-state-encrypt-cbc state)
            (and cbc
                 (ironclad-unsafe:make-cipher block-cipher :key encrypt
                                              :mode :cbc
                                              :initialization-vector
                                              (copy-seq encrypt-iv)))
            (ssh-cipher-state-encrypt-cbc-iv state)
            (and cbc (copy-seq encrypt-iv))
            (ssh-cipher-state-encrypt-offset state) 0
            (ssh-cipher-state-encrypt-packet state) 0
            (ssh-cipher-state-send-block-size state) block-size
            (ssh-cipher-state-block-size state) block-size)))
  (when decrypt-p
    (let* ((name (if decrypt-cipher-p
                     decrypt-cipher
                     (and aead "chacha20-poly1305@openssh.com")))
           (block-size (or (ssh-cipher-block-size name) +ssh-block-size+))
           (block-cipher (ssh-cipher-block-cipher name))
           (cbc (ssh-cipher-cbc-p name)))
      (setf (ssh-cipher-state-decrypt state)
            (if (ssh-cipher-chacha-p name)
                (ssh-chacha-packet-key decrypt)
                decrypt)
            (ssh-cipher-state-decrypt-name state) name
            (ssh-cipher-state-decrypt-iv state) decrypt-iv
            (ssh-cipher-state-decrypt-ecb state)
            (and block-cipher
                 (ironclad-unsafe:make-cipher block-cipher :key decrypt
                                              :mode :ecb))
            (ssh-cipher-state-decrypt-cbc state)
            (and cbc
                 (ironclad-unsafe:make-cipher block-cipher :key decrypt
                                              :mode :cbc
                                              :initialization-vector
                                              (copy-seq decrypt-iv)))
            (ssh-cipher-state-decrypt-cbc-iv state)
            (and cbc (copy-seq decrypt-iv))
            (ssh-cipher-state-decrypt-offset state) 0
            (ssh-cipher-state-decrypt-packet state) 0
            (ssh-cipher-state-receive-block-size state) block-size
            (ssh-cipher-state-block-size state) block-size)))
  (when encrypt-mac-key-p
    (setf (ssh-cipher-state-encrypt-mac-key state) encrypt-mac-key))
  (when decrypt-mac-key-p
    (setf (ssh-cipher-state-decrypt-mac-key state) decrypt-mac-key))
  (when encrypt-mac-p
    (setf (ssh-cipher-state-encrypt-mac state) encrypt-mac
          (ssh-cipher-state-encrypt-umac state)
          (when (member encrypt-mac '(:umac-64 :umac-128))
            (ssh-make-umac-state encrypt-mac-key
                                 :tag-length (ssh-hmac-length encrypt-mac)))))
  (when decrypt-mac-p
    (setf (ssh-cipher-state-decrypt-mac state) decrypt-mac
          (ssh-cipher-state-decrypt-umac state)
          (when (member decrypt-mac '(:umac-64 :umac-128))
            (ssh-make-umac-state decrypt-mac-key
                                 :tag-length (ssh-hmac-length decrypt-mac)))))
  (when encrypt-mac-etm-p
    (setf (ssh-cipher-state-encrypt-etm state) encrypt-mac-etm))
  (when decrypt-mac-etm-p
    (setf (ssh-cipher-state-decrypt-etm state) decrypt-mac-etm))
  state)

(defun ssh-reset-send-sequence (state)
  (setf (ssh-cipher-state-send-sequence state) 0))

(defun ssh-reset-receive-sequence (state)
  (setf (ssh-cipher-state-receive-sequence state) 0))
