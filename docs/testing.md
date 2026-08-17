# Testing

The suite is split in two, along the line that actually constrains it: whether
a test needs a container runtime.

| Tier | Where it runs | What it needs | Command |
| --- | --- | --- | --- |
| **unit** | anywhere, including inside a sandbox | a Rust toolchain | `make unittest` |
| **integration** | the host only | a real podman | `make -C tests/integration integration` |
| **acceptance** | the host only | podman and outbound network | `make -C tests/integration acceptance` |

The split is not a convention, it is a constraint. Podman does not run in a Nix
build and does not run nested without privileges, so an agent working on this
repo — inside a sandbox, which is the normal case — can run the unit tier and
nothing else. Keeping that tier genuinely complete is what makes the sandbox a
usable place to develop this project.

## The tier boundary

A test belongs in the unit tier if its result does not depend on a container
existing. That is a wider line than it first appears, because the launcher takes
everything it needs from its environment:

- `$HOME`, `$XDG_RUNTIME_DIR` and the working directory,
- `AGENT_SANDBOX_IMAGE` and `AGENT_SANDBOX_AGENT_SPECS`,
- and `podman` itself, resolved on `$PATH`.

Put a stub `podman` first on `$PATH` and the entire flag → `podman run` mapping
becomes observable as recorded argv. That covers the launcher's largest and
least testable function without a container anywhere in sight.

A test belongs in the integration or acceptance tier when the answer comes from
the container: whether a mount is really read-only, whether a published port
carries traffic, whether a denied request is actually denied.

## The unit tier

```sh
make unittest                    # rust + docs
make -C tests/unit rust          # the Rust workspace only
make -C tests/unit nix           # the same, through `nix flake check`
make -C tests/unit logs          # everything, with logs under tests/unit/logs/
```

It contains three kinds of test:

**In-crate unit tests** (`#[cfg(test)]` throughout `cli/` and `proxy/`) cover
the pure functions: policy matching, the `AGENTS.md` parser, the mount and env
fragments in `launch.rs`, the network summary renderer, the GnuPG home scan.
This is where the largest share of the suite lives, and where new pure logic
belongs.

**Stub-podman tests** (`cli/tests/`) drive the real launcher binary with a
recording `podman` on `$PATH` and assert on the argv it produced —
`launcher_argv.rs` for the flag mapping, `launcher_proxy.rs` for the sidecar
wiring. The harness in `cli/tests/common/mod.rs` builds a throwaway `$HOME`,
workspace and runtime directory per test, and the stub answers the lookups the
sidecar path makes (the network's subnet, the sidecar's address) and writes the
readiness marker the launcher waits on, so a `--proxy` test finishes in
milliseconds rather than timing out.

The stub also snapshots the directories the launcher mounts into the sidecar,
because the launcher's own cleanup removes them on the way out; `World::captured`
is how a test sees the policy the proxy was actually handed.

**The documentation build**, with `--strict`. MkDocs' Python-Markdown swallows
a malformed list or fence silently rather than erroring, so a warning here is a
failure — see the conventions in `AGENTS.md`.

`fmt-check` and `clippy` exist as targets but are not part of `all`: the tree is
not currently rustfmt-clean, and reformatting it wholesale would bury real
changes under unrelated churn.

!!! warning "A new test file must be `git add`ed before Nix can see it"

    `make -C tests/unit rust` runs `cargo test` against the working tree, but
    `nix flake check` builds from the flake source, and a flake copies only
    files git knows about. An untracked test file therefore passes locally and
    is silently *not run* under `nix flake check` — no error, just a smaller
    suite. `git add -N` is enough to make it visible.

## The integration and acceptance tiers

These run on the host and write one log per case.

```sh
make -C tests/integration image        # build and load the image (once)
make -C tests/integration              # both tiers
make -C tests/integration acceptance CASE=egress   # one case, by substring
make -C tests/integration bundle       # everything, into one reviewable file
```

!!! note "The first run after loading the image is slow, and looks like a hang"

    `--userns=keep-id` makes podman shift the ownership of the whole image
    filesystem the first time a container starts from it, and this image carries
    a Nix store closure of tens of thousands of files. That is minutes of real
    CPU — `podman` pegged near 100% is progress, not a stall — and it is cached
    afterwards. `make image` pays it up front via the `warm` target so it cannot
    land inside a timed case; `make warm` runs it on its own.

    Each case is capped at `CASE_TIMEOUT` seconds (default 900). Raise it on a
    slow machine rather than assuming a bug:
    `make -C tests/integration integration CASE_TIMEOUT=1800`.

Each case is a plain shell script under `tests/integration/integration/` or
`tests/integration/acceptance/`, sourcing `lib.sh` for its assertions. The
runner treats exit 0 as a pass, exit 77 as a skip with a reason, and anything
else as a failure.

**Skips are first-class.** A machine with no outbound network, no SSH agent, no
GnuPG key or no krun cannot run every case, and saying which ones were not run
is more useful than a green suite that quietly checked less than it claimed.
Cases declare what they need with `require_image`, `require_network`,
`require_command` and `require_env`.

**Integration** asks whether the container comes up the way the flags said it
would: a command runs and its exit code comes back, `--workspace` is writable
and owned by the host user, the tmpfs home does not leak between sessions while
the agent's own state does, a declared port carries traffic and an undeclared
one does not, `ro` really is read-only, `ctl` finds a running sandbox by the
labels the launcher wrote, `--host-loopback-port` splices a host service into
the sandbox, `agent-sandbox browser` reaches a declared port from a browser
started before the sandbox existed, and `ctl purge` reclaims what a killed
launcher leaked.

**Acceptance** asks whether the security promises hold. Deny-by-default egress,
including the ways around it — a bare IP, a direct DNS query, an unset
`HTTP_PROXY`, a port the rule does not name. L7 routes narrowing a host to a
method and path, with the session CA handed over only when a rule needs it.
Secret injection reaching the origin while remaining unreadable inside the
sandbox. The SSH and GPG relays working for allowed hosts and refusing others,
with the private key never entering the container. A live policy widening and
narrowing mid-session, and both decisions appearing in the connection log.

Acceptance cases that need credentials skip unless the host supplies them:
`40-relay-ssh` needs an `SSH_AUTH_SOCK` with keys, `50-relay-gpg` needs a GnuPG
secret key, `30-secret-injection` needs `AGENT_SANDBOX_TEST_SECRET` set to any
value.

`30-secret-injection` needs one thing more, and deliberately does not arrange it
for itself. A `secret` in an `AGENTS.md` route is a *request* that the host must
authorize in `~/.config/agent-sandbox/trusted.toml` before anything is injected
— an untrusted project file cannot spend your credentials on its own. The case
skips on that refusal and prints the block to add. Authorizing it from inside
the test would forge the very approval the feature exists to require, so that
one step stays yours:

```toml
[[network.allowed_routes]]
host = "httpbingo.org"
method = "GET"
path = "/headers*"
secret = "AGENT_SANDBOX_TEST_SECRET"
header = "X-Test-Token"
prefix = ""
```

Everything else the case does supply. Authorization only says a binding is
allowed; the *value* is resolved on the host by `secretspec` from the
workspace's `secretspec.toml`, so the case writes a throwaway manifest into its
temp workspace and selects the `env` provider through `SECRETSPEC_PROVIDER` —
which reads the `AGENT_SANDBOX_TEST_SECRET` it already requires. The provider is
set on the command rather than in `trusted.toml`, where it would change how
every real session resolves its secrets.

## What the first host run found

The suite paid for itself on its first real run, with two bugs that no unit
test could have reached:

- **`ctl purge` reclaimed containers and stopped**, never the sidecar networks
  or the `/tmp/agent-sandbox-*` directories — although its own help promised
  all three, and the launcher pointed users at it when leaked networks exhaust
  the rootless subnet pool. Twelve networks had accumulated on one host.
- **SSH through the relay failed with `No user exists for uid 0`.** The relay
  runs `ssh` in the sidecar, and the sidecar was started without
  `--userns=keep-id` and without the synthesized `/etc/passwd` the sandbox
  gets, over an image that ships no passwd file. `ssh` could not resolve its
  own uid and gave up before connecting.

Fixing the first turned up a third, one layer down:

- **Purge scanned for orphaned sidecars before removing exited sandboxes.** A
  sidecar counts as orphaned once its target container is gone, so a session
  whose sandbox had exited but not yet been removed still looked live — its
  sidecar survived the pass, and its network with it, until purge was run a
  second time. Each stage's removals are what make the next stage's scan find
  anything, so the stages now run in dependency order.

All three are fixed, and two are now covered in the unit tier as well:
`the_sidecar_gets_a_passwd_database_of_its_own` in `launcher_proxy.rs`, and
`cli/tests/ctl_purge.rs` for the ordering. The acceptance tier found both, but
the stub harness can see them in milliseconds.

`ctl_purge.rs` runs everything under `--dry-run`, deliberately. Purge's
directory scan reads the real `/tmp`, and under a stub podman that answers "no
such container" to every probe, a `--force` run would classify a live session's
directories as leaked and delete them. A test must not be able to do that to
the machine it runs on.

Verifying a signature through the GPG relay remains a boundary rather than a
bug: git writes the payload to a temp file and hands gpg the path, but gpg runs
in the sidecar with its own `/tmp`. Signing travels over stdin/stdout and works,
so `50-relay-gpg` asserts on the `gpgsig` header of the commit object rather
than on `git log --show-signature`.

## Where the coverage still thins out

Worth knowing when choosing what to test next:

- **The entrypoint** (`cli/src/bin/agent-sandbox-entrypoint.rs`) runs inside the
  container, so only the integration tier reaches it, and it currently reaches
  it indirectly. Its PATH-probing helper is pure and could move into the unit
  tier.
- **The sidecar's route syncing** (`agent-sandbox-sidecar.rs`) shells out to
  `ip`. The parsing halves are unit-tested; the installing halves are not
  covered at either tier.
- **`handle_client`** in `proxy/src/main.rs` is the request path itself — around
  650 lines with no direct test. Its decisions are covered through `policy.rs`
  and end to end through acceptance, but nothing exercises the wire handling in
  between. It is reachable from the unit tier over loopback, given a policy that
  allows a local address.
- **The `ctl` subcommands** that only format podman output (`list`, `status`,
  `logs`, `net`) have no tests. The stub-podman harness extends to them: give
  the stub a canned `podman ps` reply and assert on what gets printed.
- **The browser** (`ctl/browser.rs`) has its pure parts covered, and
  `90-browser-ports` drives a real instance — its proxy, its policy files and
  `ctl proxy allow --browser` — with a stub in place of Chromium. Launching
  Chromium itself under bwrap is still untested at any tier, which is where the
  managed-policy layer lives.

## Adding a test

Ask first whether the answer depends on a container.

If it does not, it goes in the unit tier — as an in-crate `#[cfg(test)]` module
if the thing under test is a function, or as a case in `cli/tests/` if it is
about which fragments the launcher assembles for a given command line.

If it does, add a script to the matching directory under `tests/integration/`.
Source `lib.sh`, declare what the case needs up front, and clean up after
itself — the runner isolates logs, not containers.
