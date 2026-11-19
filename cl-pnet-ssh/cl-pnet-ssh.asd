(asdf:defsystem #:cl-pnet-ssh
  :description "SSH-2 protocol core over cl-pnet"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.1.0"
  :depends-on (#:cl-pnet
               #:ironclad-unsafe
               #:cl-base64
               #:babel
               #:iterate
               #:uiop)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "packages")
                             (:file "conditions")
                             ;; Role-neutral: shared by client and a future server.
                             (:file "wire")
                             (:file "crypto")
                             (:file "packet")
                             (:file "keys")
                             (:file "known-hosts")
                             (:file "kex")
                             ;; Client role.
                             (:file "state")
                             (:file "transport")
                             (:file "channel")
                             (:file "client")))))
