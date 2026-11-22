# bursyk -- the SSH client, server, and the SSH stack behind them.
#
# This repository carries bursyk-client, bursyk-server, cl-pnet-ssh (the
# facade), cl-libbursyk (the pure SSH-2 implementation) and cl-plibssh (the
# libssh backend).  The remaining systems they use (cl-pnet, cl-pnet-sockets,
# cl-pnet-socks, cl-pnet-dns, cl-pnet-dns-plain, cl-puma, burzay) still live in
# the pesekey checkout.  ~/.sbclrc adds that directory to
# QL:*LOCAL-PROJECT-DIRECTORIES*, so QL:QUICKLOAD finds them here too; until
# they are published the pesekey checkout is the rest of the dependency set.
#
# The backend selection is a compile-time feature, so this Makefile pushes it
# itself instead of reading another project's test helper.  The defaults are
# the pure stack: puma multiplexes with epoll/kqueue from Lisp and the SSH
# backend is cl-libbursyk.  Neither libev/libuv nor libssh is needed.

LISP            ?= sbcl
QUICKLISP_SETUP ?= $(HOME)/quicklisp/setup.lisp
PESEKEY_DIR     ?= $(HOME)/pesekey
CACHE_ROOT      ?= $(HOME)/.cache/common-lisp
PROJECT_DIR     ?= $(patsubst /%,%,$(CURDIR))
PESEKEY_CACHE   ?= $(patsubst /%,%,$(PESEKEY_DIR))

PNET_BACKEND ?= puma
SSH_BACKEND  ?= lisp

VALID_PNET_BACKENDS := puma libev libuv
VALID_SSH_BACKENDS  := lisp ffi

ifeq ($(filter $(PNET_BACKEND),$(VALID_PNET_BACKENDS)),)
$(error PNET_BACKEND='$(PNET_BACKEND)' is not one of: $(VALID_PNET_BACKENDS))
endif
ifeq ($(filter $(SSH_BACKEND),$(VALID_SSH_BACKENDS)),)
$(error SSH_BACKEND='$(SSH_BACKEND)' is not one of: $(VALID_SSH_BACKENDS))
endif

FEATURE_EVAL = --eval '(pushnew :pnet-backend-$(PNET_BACKEND) *features*)' \
               $(if $(filter ffi,$(SSH_BACKEND)),--eval '(pushnew :ssh-backend-ffi *features*)')

# This checkout first, then pesekey: while the pesekey monorepo still carries
# copies of the systems built here, this repository has to be the one that is
# found.
QL_EVAL = --eval '(unless (find-package "QL") (load "$(QUICKLISP_SETUP)"))' \
          --eval '(pushnew (uiop:ensure-directory-pathname "$(PESEKEY_DIR)/") ql:*local-project-directories* :test (function equalp))' \
          --eval '(pushnew (uiop:ensure-directory-pathname "$(CURDIR)/") ql:*local-project-directories* :test (function equalp))' \
          --eval '(ql:register-local-projects)'

.PHONY: all build clean clean-cache build-burs build-bursyk-server \
        test test-client test-server test-ssh test-ssh-live deps-check

all: build

build: build-burs build-bursyk-server

build-burs: clean-cache deps-check
	@mkdir -p _build
	$(LISP) --non-interactive $(QL_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload "bursyk-client")' \
	  --eval '(asdf:make "bursyk-client")'

build-bursyk-server: clean-cache deps-check
	@mkdir -p _build
	$(LISP) --non-interactive $(QL_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload "bursyk-server")' \
	  --eval '(asdf:make "bursyk-server")'

# The backend is a compile-time feature, and the fasls of the shared systems
# live under PESEKEY_DIR.  Wipe both prefixes so a build never inherits a
# cell compiled with another backend.
clean-cache:
	rm -rf "$(CACHE_ROOT)"/*/"$(PROJECT_DIR)" \
	       "$(CACHE_ROOT)"/*/"$(PESEKEY_CACHE)" 2>/dev/null; true

clean: clean-cache
	rm -rf _build/

deps-check:
	@test -d "$(PESEKEY_DIR)" || \
	  { echo "PESEKEY_DIR=$(PESEKEY_DIR) does not exist; set PESEKEY_DIR to the pesekey checkout" >&2; exit 1; }

test: test-client test-server test-ssh

test-client: clean-cache deps-check
	$(LISP) --non-interactive $(QL_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload :bursyk-client-tests)' \
	  --eval '(sb-ext:exit :abort t :code (if (fiveam:run! (quote bursyk-client-tests::bursyk-client)) 0 1))'

test-server: clean-cache deps-check
	$(LISP) --non-interactive $(QL_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload :bursyk-server-tests)' \
	  --eval '(sb-ext:exit :abort t :code (if (fiveam:run! (quote bursyk-server-tests::bursyk-server)) 0 1))'

# The SSH library and facade suite.  SSH_BACKEND=ffi needs libssh.so.4 at
# runtime; the pure backend needs nothing beyond libc/libm.
test-ssh: clean-cache deps-check
	$(LISP) --non-interactive $(QL_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload :cl-pnet-ssh-tests)' \
	  --eval '(sb-ext:exit :abort t :code (if (fiveam:run! (quote cl-pnet-ssh-tests::cl-pnet-ssh)) 0 1))'

# Optional: a live client test against a reachable sshd.  Kept out of `test`
# because it needs SSH_TEST_HOST, a key and a server; see tests/live.lisp.
test-ssh-live: clean-cache deps-check
	timeout 120 $(LISP) --non-interactive $(QL_EVAL) $(FEATURE_EVAL) \
	  --load cl-pnet-ssh/tests/live.lisp
