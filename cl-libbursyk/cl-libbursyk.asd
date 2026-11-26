(defsystem #:cl-libbursyk
  :description "Pure Common Lisp SSH-2 client and server"
  :author "pesekey"
  :license "GPL-3.0-or-later"
  :version "0.0.1.88"
  :depends-on (#:cl-pnet-ssh/core
               #:cl-pnet
               #:cl-pnet-sockets
               #:burzay
               #:iterate
               #:uiop)
  ;; This system is the pure transport.  Every file below is part of it
  ;; unconditionally; the backend feature selects between this system and
  ;; CL-PLIBSSH in CL-PNET-SSH, never between files inside either one.
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "capabilities")
                             (:file "client-state")
                             (:file "client-transport")
                             (:file "client-proxy")
                             (:file "client-channel")
                             ;; ForwardX11: choosing the cookie, x11-req, and
                             ;; the x11 channel's bridge to the local display.
                             (:file "client-x11")
                             (:file "client")
                             (:file "server-state")
                             (:file "server-transport")
                             (:file "server-channel")
                             ;; Windows agent forwarding: a named-pipe
                             ;; listener the application hands to the hook.
                             (:file "server-agent-windows"
                                    :if-feature :win32)
                             ;; X11Forwarding: the display listener, the fake
                             ;; cookie and the x11 channel bridge.
                             (:file "server-x11")
                             (:file "server")))))
