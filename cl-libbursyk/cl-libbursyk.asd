(defsystem #:cl-libbursyk
  :description "Pure Common Lisp SSH-2 protocol core: wire, crypto, packets, keys, KEX"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.2.0"
  :depends-on (#:ironclad-unsafe
               #:cl-base64
               #:babel
               #:iterate
               #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "packages")
                             (:file "conditions")
                             (:file "config")
                             ;; Role-neutral: shared by the client and the server.
                             (:file "wire")
                             (:file "crypto")
                             (:file "packet")
                             (:file "keys")
                             (:file "known-hosts")
                             (:file "kex")))))
