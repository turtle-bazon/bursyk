(in-package #:cl-pnet-ssh)

;;;; The libssh bindings live in their own package, CL-PLIBSSH, so that the
;;;; bindings system needs nothing from the SSH protocol.  The roles below are
;;;; written against the C API by name, exactly as the rest of this repository
;;;; calls it, so bring the exported names into this package once, before any
;;;; role file is compiled.
;;;
;;;; IMPORT refuses a name that CL-PNET-SSH already uses for something else.
;;;; That is the collision worth stopping for: the role code would otherwise
;;;; call the protocol function instead of the libssh one.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (do-external-symbols (symbol (find-package '#:cl-plibssh))
    (handler-case (import symbol)
      (package-error (condition)
        (error "importing the libssh binding ~A into CL-PNET-SSH: ~A"
               symbol condition)))))
