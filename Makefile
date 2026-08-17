.PHONY: all build clean test unittest integration acceptance

all: build

build:
	nix build

# Everything that runs without a container runtime.  This is what an agent
# working on this repo can run, because podman does not run nested.
unittest:
	$(MAKE) -C tests/unit

# Alias, for muscle memory.
test: unittest

# Needs a real podman, so it only runs on the host.  See tests/integration.
integration:
	$(MAKE) -C tests/integration integration

acceptance:
	$(MAKE) -C tests/integration acceptance

clean:
	rm -rf target result result-*
	$(MAKE) -C tests/unit clean
	$(MAKE) -C tests/integration clean
