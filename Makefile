# bursyk -- the SSH client, server, and the SSH stack behind them.
#
# This repository carries bursyk-client, bursyk-server, cl-pnet-ssh (the
# facade), cl-bursyk-ssh (the pure SSH-2 implementation) and cl-plibssh (the
# libssh CFFI bindings).  The remaining systems they use (cl-pnet,
# cl-pnet-sockets, cl-pnet-socks, cl-pnet-dns, cl-pnet-dns-plain, cl-puma,
# burzay) still live in the pesekey checkout.  ~/.sbclrc adds that directory
# to QL:*LOCAL-PROJECT-DIRECTORIES*, so QL:QUICKLOAD finds them here too;
# until they are published the pesekey checkout is the rest of the dependency
# set.
#
# The backend selection is a compile-time feature, so this Makefile pushes it
# itself instead of reading another project's test helper.  The defaults are
# the pure stack: puma multiplexes with epoll/kqueue from Lisp and the SSH
# backend is cl-bursyk-ssh.  Neither libev/libuv nor libssh is needed.
#
# Each axis has a short matrix name: ev, uv and puma for the event loop, and
# lisp and libssh for the SSH stack (cl-bursyk-ssh, or the adapter in
# cl-pnet-ssh over cl-plibssh).  The underlying spellings libev, libuv and
# ffi are still accepted.
#
# Compiled files go under _build/fasl/<ssh>-<event-loop>/ and never into the
# user's global ASDF cache.  The per-backend directory is what keeps a puma
# build from loading fasls compiled with libev or libssh.

LISP            ?= sbcl
QUICKLISP_SETUP ?= $(HOME)/quicklisp/setup.lisp
PESEKEY_DIR     ?= $(HOME)/pesekey

# A cold private cache compiles the whole dependency set in one image, which
# needs more than SBCL's 1 GiB default, so the compile pass gets extra heap.
# The dump pass only loads those fasls, so it keeps SBCL's default heap and
# each program is dumped from an image sized like its normal runtime instead
# of like the compiler.  The tests compile and run in one image, so they use
# LISP_FLAGS too.  Override either to change it.
LISP_FLAGS      ?= --dynamic-space-size 2048
DUMP_LISP_FLAGS ?=

PNET_BACKEND ?= puma
SSH_BACKEND  ?= lisp

VALID_PNET_BACKENDS := puma libev libuv ev uv
VALID_SSH_BACKENDS  := lisp libssh ffi

# The names the feature pushes and the matrix use, from either spelling.
PNET_BACKEND_NAME = $(if $(filter ev,$(PNET_BACKEND)),libev,$(if $(filter uv,$(PNET_BACKEND)),libuv,$(PNET_BACKEND)))
SSH_BACKEND_NAME  = $(if $(filter ffi,$(SSH_BACKEND)),libssh,$(SSH_BACKEND))

ifeq ($(filter $(PNET_BACKEND),$(VALID_PNET_BACKENDS)),)
$(error PNET_BACKEND='$(PNET_BACKEND)' is not one of: $(VALID_PNET_BACKENDS))
endif
ifeq ($(filter $(SSH_BACKEND),$(VALID_SSH_BACKENDS)),)
$(error SSH_BACKEND='$(SSH_BACKEND)' is not one of: $(VALID_SSH_BACKENDS))
endif

# The private fasl cache.  Override FASL_ROOT to put it somewhere else; the
# matrix passes one directory per cell.
BACKEND_TAG = $(SSH_BACKEND_NAME)-$(PNET_BACKEND_NAME)
FASL_ROOT  ?= _build/fasl/$(BACKEND_TAG)
FASL_ROOT_ABS = $(abspath $(FASL_ROOT))

# Exactly one SSH backend feature is pushed.  CL-PNET-SSH refuses a build
# that has both or neither, so this is also what keeps the matrix honest.
FEATURE_EVAL = --eval '(pushnew :pnet-backend-$(PNET_BACKEND_NAME) *features*)' \
               $(if $(filter libssh,$(SSH_BACKEND_NAME)),--eval '(pushnew :ssh-backend-ffi *features*)',--eval '(pushnew :ssh-backend-lisp *features*)')

# Redirect every system this process compiles, including the pesekey
# dependencies, below _build.  Ignoring inherited configuration means the
# global ~/.cache/common-lisp is never consulted or written.
CACHE_EVAL = --eval '(asdf:initialize-output-translations (quote (:output-translations ("/" "$(FASL_ROOT_ABS)/") :ignore-inherited-configuration)))'

# The build matrix: one cell per event loop and SSH backend.  Override either
# list to run a subset, or override MATRIX_DIR to keep the binaries elsewhere.
MATRIX_PNET_BACKENDS ?= ev uv puma
MATRIX_SSH_BACKENDS  ?= lisp libssh
MATRIX_DIR           ?= _build/matrix
MATRIX_CELLS = $(foreach ssh,$(MATRIX_SSH_BACKENDS),$(foreach pnet,$(MATRIX_PNET_BACKENDS),$(ssh)-$(pnet)))

# This checkout first, then pesekey: while the pesekey monorepo still carries
# copies of the systems built here, this repository has to be the one that is
# found.
QL_EVAL = --eval '(unless (find-package "QL") (load "$(QUICKLISP_SETUP)"))' \
          --eval '(pushnew (uiop:ensure-directory-pathname "$(PESEKEY_DIR)/") ql:*local-project-directories* :test (function equalp))' \
          --eval '(pushnew (uiop:ensure-directory-pathname "$(CURDIR)/") ql:*local-project-directories* :test (function equalp))' \
          --eval '(ql:register-local-projects)'

.PHONY: all build clean clean-cache build-client build-server \
        build-client-compile build-client-dump \
        build-server-compile build-server-dump \
        build-burs build-bursyk-server \
        test test-client test-server test-ssh test-ssh-live deps-check \
        matrix matrix-list build-matrix test-matrix

all: build

# The two programs, in the default cell: the puma event loop over the pure
# SSH stack (lisp-puma).  PNET_BACKEND and SSH_BACKEND still pick another
# cell; the per-cell targets at the end pin one for both programs.
#
# Each program builds in two passes.  The compile pass starts a fresh image
# with the compile heap and compiles the program and every dependency into
# the private cache; it dumps nothing.  The dump pass finds all those fasls,
# so it only loads them and saves the executable, and the image that does the
# saving is the size the program gets when it runs.  The dump pass depends on
# the compile pass rather than sitting beside it, so even `make -j` cannot run
# the second half against a half-built cache.  It also removes the program
# first: program-op treats an existing output newer than its inputs as up to
# date, and with a warm cache the inputs are not rewritten, so without the
# removal a build for another backend would keep the previous executable.
build: build-client build-server

build-client: build-client-dump

build-client-dump: build-client-compile
	@mkdir -p _build "$(FASL_ROOT)"
	@rm -f _build/burs
	$(LISP) $(DUMP_LISP_FLAGS) --non-interactive $(QL_EVAL) $(CACHE_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload "bursyk-client")' \
	  --eval '(asdf:make "bursyk-client")'

build-client-compile: deps-check
	@mkdir -p _build "$(FASL_ROOT)"
	$(LISP) $(LISP_FLAGS) --non-interactive $(QL_EVAL) $(CACHE_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload "bursyk-client")'

build-server: build-server-dump

build-server-dump: build-server-compile
	@mkdir -p _build "$(FASL_ROOT)"
	@rm -f _build/bursyk-server
	$(LISP) $(DUMP_LISP_FLAGS) --non-interactive $(QL_EVAL) $(CACHE_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload "bursyk-server")' \
	  --eval '(asdf:make "bursyk-server")'

build-server-compile: deps-check
	@mkdir -p _build "$(FASL_ROOT)"
	$(LISP) $(LISP_FLAGS) --non-interactive $(QL_EVAL) $(CACHE_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload "bursyk-server")'

# The names these targets had before the matrix; kept for old scripts.
build-burs: build-client
build-bursyk-server: build-server

# Each backend pair has its own cache, so builds normally reuse their fasls.
# This target is the explicit reset; `clean' also removes the programs.
clean-cache:
	rm -rf _build/fasl "$(MATRIX_DIR)"/*/fasl

clean: clean-cache
	rm -rf _build/

deps-check:
	@test -d "$(PESEKEY_DIR)" || \
	  { echo "PESEKEY_DIR=$(PESEKEY_DIR) does not exist; set PESEKEY_DIR to the pesekey checkout" >&2; exit 1; }

test: test-client test-server test-ssh

test-client: deps-check
	$(LISP) $(LISP_FLAGS) --non-interactive $(QL_EVAL) $(CACHE_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload :bursyk-client-tests)' \
	  --eval '(sb-ext:exit :abort t :code (if (fiveam:run! (quote bursyk-client-tests::bursyk-client)) 0 1))'

test-server: deps-check
	$(LISP) $(LISP_FLAGS) --non-interactive $(QL_EVAL) $(CACHE_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload :bursyk-server-tests)' \
	  --eval '(sb-ext:exit :abort t :code (if (fiveam:run! (quote bursyk-server-tests::bursyk-server)) 0 1))'

# The SSH facade suite.  It is the same suite and the same expectations on
# both backends: SSH_BACKEND=libssh needs libssh.so.4 at runtime, while the
# pure lisp backend needs nothing beyond libc/libm.
#
# The pure transport's own wire- and state-level tests live in
# CL-LIBBURSKY-TESTS, not in this facade suite, because libssh owns the wire
# protocol and exposes none of it.  Running them under :ssh-backend-ffi would
# be a test of internals the backend does not have, so they run only for the
# pure stack; the facade results stay comparable across backends.
test-ssh: deps-check
	$(LISP) $(LISP_FLAGS) --non-interactive $(QL_EVAL) $(CACHE_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload :cl-pnet-ssh-tests)' \
	  --eval '(sb-ext:exit :abort t :code (if (fiveam:run! (quote cl-pnet-ssh-tests::cl-pnet-ssh)) 0 1))'
ifeq ($(SSH_BACKEND_NAME),lisp)
	$(LISP) $(LISP_FLAGS) --non-interactive $(QL_EVAL) $(CACHE_EVAL) $(FEATURE_EVAL) \
	  --eval '(ql:quickload :cl-bursyk-ssh-tests)' \
	  --eval '(sb-ext:exit :abort t :code (if (fiveam:run! (quote cl-pnet-ssh-tests::lisp-internals)) 0 1))'
endif

# Optional: a live client test against a reachable sshd.  Kept out of `test`
# because it needs SSH_TEST_HOST, a key and a server; see tests/live.lisp.
test-ssh-live: deps-check
	timeout 120 $(LISP) $(LISP_FLAGS) --non-interactive $(QL_EVAL) $(CACHE_EVAL) $(FEATURE_EVAL) \
	  --load cl-pnet-ssh/tests/live.lisp

# ---- The build matrix ----
#
# Every event loop backend (ev, uv, puma) is built and tested against both
# SSH stacks (lisp = cl-bursyk-ssh, libssh = cl-plibssh).  The cells run one
# at a time, and each keeps its fasls in _build/matrix/<ssh>-<pnet>/fasl so
# a later test-matrix reuses the matching build instead of recompiling it.
# Every cell runs the same facade suite.  The pure transport's internal
# wire/state tests belong to cl-bursyk-ssh and run in the lisp cells only;
# they are not facade behaviour, so the libssh cells neither run nor skip
# them.
#
# MATRIX_ENV carries an extra environment for every cell, for a libssh built
# outside the loader's default search path:
#
#   make test-matrix MATRIX_ENV='LD_LIBRARY_PATH=/opt/libssh/lib'
MATRIX_ENV ?=

matrix: build-matrix

matrix-list:
	@for cell in $(MATRIX_CELLS); do echo "$$cell"; done

# One cell, e.g. `make build-matrix-libssh-uv' or `make test-matrix-libssh-uv'.
# The loops below are just a walk over these, so a single cell behaves exactly
# like it does inside a full matrix run: its own fasls and its own copies of
# the two programs, both under MATRIX_DIR/<cell>/.
build-matrix-%: deps-check
	@set -e; cell="$*"; \
	  case " $(MATRIX_CELLS) " in \
	    *" $$cell "*) ;; \
	    *) echo "unknown matrix cell '$$cell'; one of: $(MATRIX_CELLS)" >&2; exit 2;; \
	  esac; \
	  ssh="$${cell%%-*}"; pnet="$${cell#*-}"; \
	  echo "==> build $$cell"; \
	  $(MATRIX_ENV) $(MAKE) --no-print-directory -j1 build \
	    PNET_BACKEND="$$pnet" SSH_BACKEND="$$ssh" \
	    FASL_ROOT="$(MATRIX_DIR)/$$cell/fasl"; \
	  mkdir -p "$(MATRIX_DIR)/$$cell"; \
	  cp _build/burs _build/bursyk-server "$(MATRIX_DIR)/$$cell/"

test-matrix-%: deps-check
	@set -e; cell="$*"; \
	  case " $(MATRIX_CELLS) " in \
	    *" $$cell "*) ;; \
	    *) echo "unknown matrix cell '$$cell'; one of: $(MATRIX_CELLS)" >&2; exit 2;; \
	  esac; \
	  ssh="$${cell%%-*}"; pnet="$${cell#*-}"; \
	  echo "==> test $$cell"; \
	  $(MATRIX_ENV) $(MAKE) --no-print-directory -j1 test \
	    PNET_BACKEND="$$pnet" SSH_BACKEND="$$ssh" \
	    FASL_ROOT="$(MATRIX_DIR)/$$cell/fasl"

build-matrix: deps-check
	@set -e; for cell in $(MATRIX_CELLS); do \
	  $(MAKE) --no-print-directory -j1 build-matrix-$$cell; \
	done

test-matrix: deps-check
	@set -e; for cell in $(MATRIX_CELLS); do \
	  $(MAKE) --no-print-directory -j1 test-matrix-$$cell; \
	done
