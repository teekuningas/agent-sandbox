# Tests that need no container runtime.
#
# Everything here runs anywhere the Rust workspace builds -- including inside an
# agent sandbox, which is the point: podman does not run in a Nix build and does
# not run nested without privileges, so this tier is what an agent working on
# this repo can actually execute before proposing a change.
#
# The tier boundary is a rule, not a preference: a test belongs here if its
# result does not depend on a container existing.  Anything that needs a real
# container, a real network, or a real relay lives in ../integration.
#
#   make -C tests/unit             # rust + docs, the pre-commit set
#   make -C tests/unit rust        # the Rust workspace only
#   make -C tests/unit nix         # the same suite through `nix flake check`
#   make -C tests/unit logs        # everything, with logs under tests/unit/logs
#
# Set CARGO to point at your own toolchain.  The default runs cargo through
# `nix shell` so this works in a checkout with no rustup.

ROOT := $(CURDIR)/../..
LOGDIR := $(CURDIR)/logs

# The `\#` escapes are for make, which would otherwise read the flake fragment
# as a comment and drop the rest of the line.
CARGO ?= nix shell nixpkgs\#cargo nixpkgs\#rustc nixpkgs\#gcc --command cargo
NIX ?= nix

.PHONY: all rust docs nix logs clean fmt-check clippy

all: rust docs

## The whole Rust workspace: the in-crate unit tests plus the integration
## tests under cli/tests, which drive the real launcher binary against a stub
## `podman` on PATH and assert on the argv it produced.
rust:
	cd $(ROOT) && $(CARGO) test --workspace

## The documentation site, built the way GitHub Pages builds it.  A warning is
## a failure here because MkDocs' Python-Markdown silently swallows malformed
## lists and fences rather than erroring (see AGENTS.md).
docs:
	cd $(ROOT) && nix-shell -I nixpkgs=channel:nixos-unstable \
	  -p 'python3.withPackages (ps: with ps; [ mkdocs mkdocs-material ])' \
	  --run 'mkdocs build --strict'

## The same Rust suite as `rust`, but through the Nix build, which is what CI
## and `nix flake check` run.  Slower, and hermetic.
nix:
	cd $(ROOT) && $(NIX) flake check

## Not part of `all`: the tree is not currently rustfmt-clean, and reformatting
## it would bury real changes under unrelated churn.  Useful on files you are
## already touching.
fmt-check:
	cd $(ROOT) && $(CARGO) fmt --all --check

## Also not part of `all`, for the same reason.
clippy:
	cd $(ROOT) && $(CARGO) clippy --workspace --all-targets

## Everything, with output captured.  Use this when handing results to someone
## who was not at the terminal.
logs: | $(LOGDIR)
	@rm -f $(LOGDIR)/*.log
	@set -o pipefail; \
	 fail=0; \
	 for target in rust docs; do \
	   echo "=== $$target ==="; \
	   if $(MAKE) --no-print-directory $$target > $(LOGDIR)/$$target.log 2>&1; then \
	     echo "PASS $$target"; \
	   else \
	     echo "FAIL $$target (see tests/unit/logs/$$target.log)"; \
	     fail=1; \
	   fi; \
	 done; \
	 echo; echo "logs in tests/unit/logs/"; \
	 exit $$fail

$(LOGDIR):
	@mkdir -p $(LOGDIR)

clean:
	rm -rf $(LOGDIR)
