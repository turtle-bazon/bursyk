(in-package #:cl-pnet-ssh)

;;;; The binary packet protocol (RFC 4253 section 6), including OpenSSH's
;;;; chacha20-poly1305@openssh.com construction and the hmac-sha2 MACs.
;;;;
;;;; A packet is  uint32 length, byte padding-length, payload, padding
;;;; with LENGTH covering the padding-length byte, payload and padding.  The
;;;; MAC is computed over the sequence number and the *plaintext* packet for
;;;; the hmac-sha2 algorithms; chacha20-poly1305 is an AEAD: it hides the
;;;; length with one key, encrypts the rest with a second, and tags the
;;;; ciphertext, so its MAC algorithm is negotiated and then ignored.

(defconstant +ssh-block-size+ 8)
(defconstant +ssh-max-packet+ 262144
  "Largest packet accepted from a peer. OpenSSH's own limit is 256 KiB.")

(defstruct (ssh-cipher-state (:constructor ssh-make-cipher-state))
  (encrypt nil)
  (decrypt nil)
  (encrypt-mac-key nil)
  (decrypt-mac-key nil)
  (encrypt-mac nil)
  (decrypt-mac nil)
  (send-sequence 0 :type (unsigned-byte 32))
  (receive-sequence 0 :type (unsigned-byte 32))
  (block-size +ssh-block-size+)
  ;; RFC 4253 6.2 compression.  The codec objects live for the whole
  ;; connection and are reset at every NEWKEYS; the ENABLED flags stay false
  ;; for zlib@openssh.com until authentication succeeds, because that method
  ;; starts compressing only after USERAUTH_SUCCESS.
  (send-compression nil)
  (receive-compression nil)
  (send-compression-prefix nil)
  (send-compression-enabled nil)
  (receive-compression-enabled nil))

(defun ssh-packet-padding-length (payload-length &optional (length-octets 4))
  "The smallest padding of at least four octets that aligns the packet.

LENGTH-OCTETS is how much of the packet OpenSSH counts towards the block
alignment: 4 (the length field) for plain and EtM framing, 0 for AEAD, whose
length field travels outside the encrypted body."
  (let ((padding (- +ssh-block-size+
                    (mod (+ length-octets 1 payload-length) +ssh-block-size+))))
    (if (< padding 4) (+ padding +ssh-block-size+) padding)))

(defun ssh-packet-body (payload padding-length)
  "PADDING-LENGTH, PAYLOAD and random padding, ready to encrypt."
  (let* ((padding (ssh-random-octets padding-length))
         (body (make-array (+ 1 (length payload) padding-length)
                           :element-type '(unsigned-byte 8))))
    (setf (aref body 0) padding-length)
    (replace body payload :start1 1)
    (replace body padding :start1 (+ 1 (length payload)))
    body))

(defun ssh-aead-encode (payload state)
  "PAYLOAD as an encrypted, tagged chacha20-poly1305 packet."
  (let* ((sequence (ssh-cipher-state-send-sequence state))
         (nonce (ssh-chacha-nonce sequence))
         (padding-length (ssh-packet-padding-length (length payload) 0))
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

(defun ssh-encode-packet (payload state)
  "Cycle STATE's sequence and return PAYLOAD as wire octets."
  (let ((payload (if (ssh-cipher-state-send-compression-enabled state)
                     (ssh-compress-payload payload state)
                     payload)))
    (if (ssh-cipher-state-encrypt state)
        (ssh-aead-encode payload state)
        (ssh-plain-encode payload state))))

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

chacha20-poly1305 hides its tag inside the AEAD construction, so its
negotiated MAC is unused; every other cipher appends its hmac.  Before the
first NEWKEYS there is no cipher state at all, and an unencrypted packet
carries no authentication."
  (if (null state)
      0
      (if (eq direction :receive)
          (if (ssh-cipher-state-decrypt state)
              16
              (ssh-packet-mac-length state direction))
          (if (ssh-cipher-state-encrypt state)
              16
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

(defun ssh-aead-decode (buffer state)
  "Decode one chacha20-poly1305 packet from BUFFER."
  (when (< (length buffer) 4)
    (return-from ssh-aead-decode (values :incomplete 0)))
  (let* ((sequence (ssh-cipher-state-receive-sequence state))
         (key (ssh-cipher-state-decrypt state))
         (length (ssh-chacha-decrypt-length key sequence buffer))
         (needed (+ 4 length 16)))
    (unless (<= 1 length +ssh-max-packet+)
      (error 'ssh-protocol-error
             :detail (format nil "packet length ~D outside 1..~D"
                             length +ssh-max-packet+)))
    (when (< (length buffer) needed)
      (return-from ssh-aead-decode (values :incomplete 0)))
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
  (multiple-value-bind (payload consumed)
      (if (ssh-cipher-state-decrypt state)
          (ssh-aead-decode buffer state)
          (ssh-plain-decode buffer state))
    (if (eq payload :incomplete)
        (values :incomplete 0)
        (values (if (ssh-cipher-state-receive-compression-enabled state)
                    (ssh-decompress-payload payload state)
                    payload)
                consumed))))

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
                                   (encrypt-mac-key nil encrypt-mac-key-p)
                                   (decrypt-mac-key nil decrypt-mac-key-p)
                                   (encrypt-mac nil encrypt-mac-p)
                                   (decrypt-mac nil decrypt-mac-p)
                                   aead)
  "Put negotiated keys into STATE, leaving the sequence numbers alone.

The caller resets them at the NEWKEYS boundary, which is where strict KEX
requires the reset. Either direction can be installed on its own, which is
what the two NEWKEYS messages require; arguments the caller omits leave that
half unchanged. AEAD ciphers take the raw 64-octet key and turn it into their
packet key here."
  (when encrypt-p
    (setf (ssh-cipher-state-encrypt state)
          (if (and aead encrypt) (ssh-chacha-packet-key encrypt) encrypt)))
  (when decrypt-p
    (setf (ssh-cipher-state-decrypt state)
          (if (and aead decrypt) (ssh-chacha-packet-key decrypt) decrypt)))
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
