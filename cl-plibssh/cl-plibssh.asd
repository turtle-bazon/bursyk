(defsystem #:cl-plibssh
  :description "libssh CFFI bindings"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.1.77"
  ;; Bindings only: the roles that turn libssh into the CL-PNET-SSH API live
  ;; in CL-PNET-SSH, so this system needs no protocol code and no other
  ;; dependency than CFFI.
  :depends-on (#:cffi)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "packages")
                             (:file "ffi")))))
