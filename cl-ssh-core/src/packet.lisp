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

(defun ssh-cipher-aead-p (cipher)
  "Whether CIPHER authenticates each packet and ignores the negotiated MAC."
  (or (ssh-cipher-chacha-p cipher) (ssh-cipher-gcm-p cipher)))

(defun ssh-cipher-key-length (cipher)
  "The key length of CIPHER, or NIL when it is not implemented."
  (cond ((ssh-cipher-chacha-p cipher) 64)
        ((member cipher '("aes128-gcm@openssh.com" "aes128-ctr")
                 :test #'string=)
         16)
        ((string= cipher "aes192-ctr") 24)
        ((member cipher '("aes256-gcm@openssh.com" "aes256-ctr")
                 :test #'string=)
         32)
        (t nil)))

(defun ssh-cipher-iv-length (cipher)
  "The IV length of CIPHER, or NIL when it is not implemented."
  (cond ((ssh-cipher-chacha-p cipher) 0)
        ((ssh-cipher-ctr-p cipher) 16)
        ((ssh-cipher-gcm-p cipher) 12)
        (t nil)))

(defun ssh-cipher-block-size (cipher)
  "The block alignment CIPHER gives a packet, or NIL when unknown."
  (cond ((ssh-cipher-chacha-p cipher) 8)
        ((or (ssh-cipher-ctr-p cipher) (ssh-cipher-gcm-p cipher)) 16)
        (t nil)))

(defun ssh-cipher-tag-length (cipher)
  (if (ssh-cipher-aead-p cipher) +ssh-aead-tag-length+ 0))

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
  (encrypt-mac-key nil)
  (decrypt-mac-key nil)
  (encrypt-mac nil)
  (decrypt-mac nil)
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
         (mac-key (ssh-cipher-state-encrypt-mac-key state))
         (mac-name (ssh-cipher-state-encrypt-mac state))
         (output (if mac-name
                     (ssh-concat packet
                                 (ssh-hmac mac-key
                                           (ssh-concat (ssh-uint32-octets sequence)
                                                       packet)
                                           mac-name))
                     packet)))
    (setf (ssh-cipher-state-send-sequence state) (mod (1+ sequence) (expt 2 32)))
    output))

(defun ssh-ctr-encode (payload state)
  "PAYLOAD as an AES-CTR packet with an hmac appended in the clear."
  (let* ((sequence (ssh-cipher-state-send-sequence state))
         (block-size (ssh-cipher-state-send-block-size state))
         (padding-length (ssh-packet-padding-length
                          (length payload) 4 block-size))
         (body (ssh-packet-body payload padding-length))
         (packet (ssh-concat (ssh-uint32-octets (length body)) body))
         (mac-key (ssh-cipher-state-encrypt-mac-key state))
         (mac-name (ssh-cipher-state-encrypt-mac state))
         (mac (and mac-name
                   (ssh-hmac mac-key
                             (ssh-concat (ssh-uint32-octets sequence) packet)
                             mac-name)))
         (offset (ssh-cipher-state-encrypt-offset state))
         (encrypted (ssh-aes-ctr-xor
                     (ssh-cipher-state-encrypt-ecb state)
                     (ssh-cipher-state-encrypt-iv state)
                     offset packet)))
    (setf (ssh-cipher-state-encrypt-offset state) (+ offset (length packet))
          (ssh-cipher-state-send-sequence state)
          (mod (1+ sequence) (expt 2 32)))
    (if mac (ssh-concat encrypted mac) encrypted)))

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
         (ecb (ssh-cipher-state-decrypt-ecb state))
         (iv (ssh-cipher-state-decrypt-iv state))
         (offset (ssh-cipher-state-decrypt-offset state)))
    (when (< (length buffer) block-size)
      (return-from ssh-ctr-decode (values :incomplete 0)))
    ;; The length field is encrypted, so decrypt the first block to read it
    ;; without advancing the stream: SSH-AES-CTR-XOR is a pure function of
    ;; OFFSET, and the whole packet is decrypted again below.
    (let* ((first (ssh-aes-ctr-xor ecb iv offset
                                   (subseq buffer 0 block-size)))
           (length (ssh-octets-uint32 first))
           (mac-length (ssh-packet-mac-length state :receive))
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
                (actual (ssh-hmac
                         (ssh-cipher-state-decrypt-mac-key state)
                         (ssh-concat (ssh-uint32-octets sequence) packet)
                         (ssh-cipher-state-decrypt-mac state))))
            (unless (ssh-octets= expected actual)
              (error 'ssh-protocol-error :detail "packet MAC does not verify"))))
        (setf (ssh-cipher-state-decrypt-offset state) (+ offset 4 length)
              (ssh-cipher-state-receive-sequence state)
              (mod (1+ sequence) (expt 2 32)))
        (values (ssh-strip-padding (subseq packet 4) length)
                needed)))))

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
              (actual (ssh-hmac
                       (ssh-cipher-state-decrypt-mac-key state)
                       (ssh-concat (ssh-uint32-octets sequence) packet)
                       (ssh-cipher-state-decrypt-mac state))))
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
           (block-size (or (ssh-cipher-block-size name) +ssh-block-size+)))
      (setf (ssh-cipher-state-encrypt state)
            (if (ssh-cipher-chacha-p name)
                (ssh-chacha-packet-key encrypt)
                encrypt)
            (ssh-cipher-state-encrypt-name state) name
            (ssh-cipher-state-encrypt-iv state) encrypt-iv
            (ssh-cipher-state-encrypt-ecb state)
            (and (ssh-cipher-ctr-p name)
                 (ironclad-unsafe:make-cipher :aes :key encrypt :mode :ecb))
            (ssh-cipher-state-encrypt-offset state) 0
            (ssh-cipher-state-encrypt-packet state) 0
            (ssh-cipher-state-send-block-size state) block-size
            (ssh-cipher-state-block-size state) block-size)))
  (when decrypt-p
    (let* ((name (if decrypt-cipher-p
                     decrypt-cipher
                     (and aead "chacha20-poly1305@openssh.com")))
           (block-size (or (ssh-cipher-block-size name) +ssh-block-size+)))
      (setf (ssh-cipher-state-decrypt state)
            (if (ssh-cipher-chacha-p name)
                (ssh-chacha-packet-key decrypt)
                decrypt)
            (ssh-cipher-state-decrypt-name state) name
            (ssh-cipher-state-decrypt-iv state) decrypt-iv
            (ssh-cipher-state-decrypt-ecb state)
            (and (ssh-cipher-ctr-p name)
                 (ironclad-unsafe:make-cipher :aes :key decrypt :mode :ecb))
            (ssh-cipher-state-decrypt-offset state) 0
            (ssh-cipher-state-decrypt-packet state) 0
            (ssh-cipher-state-receive-block-size state) block-size
            (ssh-cipher-state-block-size state) block-size)))
  (when encrypt-mac-key-p
    (setf (ssh-cipher-state-encrypt-mac-key state) encrypt-mac-key))
  (when decrypt-mac-key-p
    (setf (ssh-cipher-state-decrypt-mac-key state) decrypt-mac-key))
  (when encrypt-mac-p
    (setf (ssh-cipher-state-encrypt-mac state) encrypt-mac))
  (when decrypt-mac-p
    (setf (ssh-cipher-state-decrypt-mac state) decrypt-mac))
  state)

(defun ssh-reset-send-sequence (state)
  (setf (ssh-cipher-state-send-sequence state) 0))

(defun ssh-reset-receive-sequence (state)
  (setf (ssh-cipher-state-receive-sequence state) 0))
