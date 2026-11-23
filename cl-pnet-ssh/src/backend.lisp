(in-package #:cl-pnet-ssh)

;;;; One backend, chosen explicitly.
;;;
;;;; CL-PNET-SSH is a facade: it provides the same API whether the SSH stack
;;;; underneath is the pure implementation (CL-LIBBURSK) or the libssh wrapper
;;;; (CL-PLIBSSH).  A build must name exactly one of them, because the two
;;;; cannot be mixed in one image: their files define the same names, and a
;;;; build that silently picked one would let a caller believe it was testing
;;;; the other.
;;;
;;;; The selectors are compile-time features:
;;;;
;;;;   :ssh-backend-lisp  the pure CL-LIBBURSK stack
;;;;   :ssh-backend-ffi   the CL-PLIBSSH wrapper over the system libssh
;;;;
;;;; Neither feature present means no backend was selected.  Both present means
;;;; two were.  Both are mistakes, so they stop the build here rather than
;;;; producing a binary whose behaviour depends on load order.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((pure (member :ssh-backend-lisp *features*))
        (ffi (member :ssh-backend-ffi *features*)))
    (when (and pure ffi)
      (error "Both SSH backends are selected (:ssh-backend-lisp and ~
              :ssh-backend-ffi).  Select exactly one."))
    (unless (or pure ffi)
      (error "No SSH backend is selected.  Push :ssh-backend-lisp for the ~
              pure stack or :ssh-backend-ffi for libssh before loading ~
              CL-PNET-SSH."))))
