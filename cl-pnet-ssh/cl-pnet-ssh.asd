(asdf:defsystem #:cl-pnet-ssh
  :description "SSH-2 client and server facade. Select the backend with the :ssh-backend-ffi feature: default is the pure Common Lisp bursyk stack, the feature selects the libssh binding."
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.3.0"
  :depends-on ((:feature (:not :ssh-backend-ffi) #:bursyk-client)
               (:feature (:not :ssh-backend-ffi) #:bursyk-server)
               (:feature :ssh-backend-ffi #:cl-plibssh))
  ;; The selected backend defines the CL-PNET-SSH package itself, so the
  ;; facade has no components: it is the build-time choice between them.
  :in-order-to ((test-op (test-op #:cl-pnet-ssh-tests))))
