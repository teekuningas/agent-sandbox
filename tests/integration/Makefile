# Tests that need a real podman, and therefore a real host.
#
# Nothing here runs inside an agent sandbox: podman does not run nested without
# privileges, and the point of most of these cases is what a real container and
# a real network do.  Run them on the host and hand the logs back.
#
#   make -C tests/integration image        # build and load the image (once)
#   make -C tests/integration              # integration + acceptance
#   make -C tests/integration integration  # container behaviour only
#   make -C tests/integration acceptance   # the security promises; needs egress
#   make -C tests/integration bundle       # everything, into one reviewable file
#
#   make -C tests/integration acceptance CASE=egress   # one case, by substring
#   make -C tests/integration warm         # pay the first-run cost up front
#
# Each case is capped at CASE_TIMEOUT seconds (default 900).  If a case times
# out on a slow machine, raise it rather than assuming a bug:
#
#   make -C tests/integration integration CASE_TIMEOUT=1800
#
# Logs land in tests/integration/logs/<tier>/<case>.log, one per case, and
# `bundle` concatenates them with a summary at the top.
#
# A case skips rather than fails when the machine cannot run it -- no egress,
# no SSH agent, no GnuPG key.  Skips are reported, and do not fail the suite.

ROOT := $(CURDIR)/../..
LOGS := $(CURDIR)/logs
BUNDLE := $(LOGS)/results.txt
CASE ?=
CASE_TIMEOUT ?= 900
export CASE_TIMEOUT

# The binary under test.  Defaults to this checkout's build, so a run tests the
# tree it is sitting in rather than whatever is installed.
AGENT_SANDBOX_BIN ?= $(ROOT)/result/bin/agent-sandbox
export AGENT_SANDBOX_BIN

.PHONY: all integration acceptance image build warm check bundle clean

all: check integration acceptance

## The launcher this suite drives.
build:
	cd $(ROOT) && nix build

## The container image.  Slow, and needed exactly once per change to the image
## definition -- it is deliberately not a prerequisite of the test targets.
image: build
	$(AGENT_SANDBOX_BIN) ctl load
	@$(MAKE) --no-print-directory warm

## The first container started from a freshly loaded image is far slower than
## every one after it: --userns=keep-id makes podman shift the ownership of the
## whole image filesystem, and this image carries a Nix store closure of tens of
## thousands of files.  That is minutes of real CPU, once, and it looks exactly
## like a hung test if it happens to land inside the first case.
##
## So pay it here, in the open, where it is obviously progress and not a stall.
warm:
	@echo "warming the image (podman shifts ownership under --userns=keep-id;"
	@echo " the first run after a load takes minutes and is cached afterwards)"
	@time $(AGENT_SANDBOX_BIN) -- true < /dev/null
	@echo "warm."

## Refuse to start rather than producing a log full of identical failures.
check:
	@command -v podman >/dev/null 2>&1 \
	  || { echo "podman is not on PATH: this tier cannot run here."; exit 1; }
	@test -x "$(AGENT_SANDBOX_BIN)" \
	  || { echo "no launcher at $(AGENT_SANDBOX_BIN); run: make -C tests/integration build"; exit 1; }
	@podman image exists localhost/agent-sandbox:latest \
	  || { echo "image not loaded; run: make -C tests/integration image"; exit 1; }
	@echo "podman $$(podman --version | awk '{print $$3}'), launcher $(AGENT_SANDBOX_BIN)"

## Does the container come up the way the flags said it would?  Needs podman;
## most cases need no egress.
integration: check
	@./run.sh integration $(LOGS)/integration $(CASE)

## Do the security promises hold?  Needs podman and outbound network.  Cases
## that need credentials (an SSH agent, a GnuPG key, a secret value) skip
## unless the host has them.
acceptance: check
	@./run.sh acceptance $(LOGS)/acceptance $(CASE)

## One file to hand back, with the summary first and every log after it.
bundle:
	@mkdir -p $(LOGS)
	@rm -f $(BUNDLE)
	@{ \
	  echo "agent-sandbox test run: $$(date -Is)"; \
	  echo "host:    $$(uname -srm)"; \
	  echo "podman:  $$(podman --version 2>/dev/null || echo absent)"; \
	  echo "launcher: $(AGENT_SANDBOX_BIN)"; \
	  echo; \
	} > $(BUNDLE)
	-@$(MAKE) --no-print-directory integration 2>&1 | tee -a $(BUNDLE)
	-@$(MAKE) --no-print-directory acceptance  2>&1 | tee -a $(BUNDLE)
	@{ \
	  echo; echo "================ full logs ================"; \
	  for f in $(LOGS)/integration/*.log $(LOGS)/acceptance/*.log; do \
	    [ -e "$$f" ] || continue; \
	    echo; echo "---------------- $$f ----------------"; \
	    cat "$$f"; \
	  done; \
	} >> $(BUNDLE)
	@echo
	@echo "bundle written to $(BUNDLE)"

clean:
	rm -rf $(LOGS)
