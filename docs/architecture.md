# Architecture

`agent-sandbox` is a Nix flake that produces a rootless Podman container image
("agent-sandbox") together with a launcher binary (`agent-sandbox`) and a
management multiplexer (`agent-sandbox ctl`, with the subcommands `load`,
`list`, `status`, `net`, `logs`, `tui`, `proxy`, `mounts`, `attach`, `relay` and `purge`).

This page describes the internal structure. For security implications of individual flags, see [Trust Model](trust-model.md).

## What's in the image

| Category      | Tools                                                |
| ------------- | ---------------------------------------------------- |
| AI coding     | opencode, claude-code (claude), github-copilot-cli (copilot), antigravity-cli (agy), codex |
| Shell / tools | bash, coreutils, ripgrep, fd, jq, curl, wget, …     |
| Languages     | python3, uv, nodejs, gnumake, gcc libs               |
| Git / GitHub  | git, gh                                              |
| Nix           | nix, devenv                                          |
| Containers    | podman, crun, conmon, skopeo, slirp4netns,           |
|               | fuse-overlayfs, docker→podman alias                  |
| Editor        | vim                                                  |

Podman container config files (`containers.conf`, `storage.conf`,
`registries.conf`, `policy.json`) are baked in at `/etc/containers/`, so
nested rootless podman is pre-configured when the sandbox is launched with
`--privileged`.

## Image (`image` attr in `default.nix`)

Built with `pkgs.dockerTools.streamLayeredImage` (`maxLayers = 2`).  All tools are baked into a
`buildEnv` and compressed into a minimal number of layers (2) to optimize `podman load` speed and container
startup latency. They are registered in the Nix store database so `nix` / `devenv` / Nix
builtins inside the container work without re-substituting store paths.

Key layers:

| Path                  | Purpose                                                |
| --------------------- | ------------------------------------------------------ |
| `/etc/nix/nix.conf`   | `sandbox = false`, `flakes` enabled                    |
| `/etc/containers/*`   | Pre-configured rootless podman (crun, overlay driver)  |
| `/usr/bin/env`        | Symlink to coreutils `env` for generic shebangs        |
| `/lib64/ld-linux-*`   | ELF interpreter for prebuilt npm binaries              |
| `/home/user`          | Home directory (uid/gid mapped at runtime)             |
| `/home/user/.agents/skills` | Bundled `agent-sandbox`, `nix`, `nix-flake`, `devenv` and `browser` skills |
| `/workspace`          | Default working directory                              |

The skills are image content, not a launcher-managed mount, and the image links
the canonical tree from each tool's own discovery path. See
[Usage](usage.md#bundled-opencode-skills) for how to replace them.

## Entrypoint (`agent-sandbox-entrypoint`)

1. Loads the Nix store registration on first start (unless `AGENT_SANDBOX_HOST_NIX=1`, in which case the host's `/nix` mount is used, or `AGENT_SANDBOX_SKIP_NIX_INIT=1`, which sidecar launches set because they do not need Nix bootstrap).
2. Seeds `~/.ssh/known_hosts`, unconditionally, so a non-interactive `ssh`
   neither prompts nor fails. Under `--proxy` the source is the file the
   launcher bound in from `trusted.toml` (`AGENT_SANDBOX_KNOWN_HOSTS`);
   otherwise it is the published keys for the common git forges. This is the
   sandbox's copy, and it is the one `ssh` uses when the sandbox runs `ssh`
   itself; under `--proxy --ssh` the real `ssh` runs in the sidecar instead and
   reads the same file from `/sidecar_policy` (see *Relay Architecture* below).
3. When `AGENT_SANDBOX_GPG_AGENT=1`, symlinks the forwarded host gpg-agent
   socket into `~/.gnupg/S.gpg-agent`.
4. When `HTTP_PROXY` is set, compensates for tools that don't honor it on
   their own: dynamically generates `~/.ssh/config` to route SSH through the
   proxy, and sets `NODE_USE_ENV_PROXY=1` so Node's core `http`/`https` and
   built-in `fetch` (undici) stop dialing out directly — this also covers
   the bundled Node-based agent CLIs, which share Node's runtime. An
   operator's own explicit `NODE_USE_ENV_PROXY` setting is left alone.
5. Puts a `socat` TCP listener in front of each `--host-loopback-port` socket,
   because the clients that want them speak TCP and not unix sockets. This is
   also what makes `AGENT_SANDBOX_BROWSER_CDP_PORT` (set by `--browser`)
   reachable from inside — see [Cooperative Browser](browser.md).
6. `exec "$@"`.

## Launcher (`agent-sandbox`)

A Rust binary (`cli/src/bin/agent-sandbox.rs`) that wraps `podman run`; the
per-integration fragments it assembles live in `cli/src/launch.rs`, where they
are unit-tested without a podman.  Call flow:

1. Parse flags: consume known flags (`--ssh`, `--no-git`, `--no-workspace`,
   etc.), collect `--podman-args` up to the `--` sentinel, stop at `--`.
 2. Build the mounts array from toggles (ssh socket, gpg socket, devenv dir,
    podman host socket, CWD workspace) plus the state dirs of whichever agents
    are selected — the positionally-launched one by default, or the set chosen
    via `--agent-mounts`/`--agent-mounts=…` — sourced from `agents.nix`
    (opencode, claude, copilot, antigravity, codex).
3. Build the env array from toggles (SSH_AUTH_SOCK, the flattened git config
   and identity, CONTAINER_HOST, DOCKER_HOST, TERM, COLORTERM).
4. Add `[ports]` and `[mounts]` declared in `AGENTS.md` (`cli/src/agents.rs`),
   under `--ports`/`--mounts`.  An invalid block refuses the launch.
5. Create ephemeral `/etc/passwd` and `/etc/group` with the host user's uid/gid,
   and name the container `agent-sandbox-<workspace>-<word>`, where the word is
   the selector every `ctl` command accepts.
6. Call `podman run` with `--userns=keep-id`, tmpfs for `~/.config`,
   `~/.cache`, `~/.local`, all mounts and env vars, then the image and the
   final command (`bash` by default, the selected agent's command when one is
   named positionally, and anything after `--` overrides both).

`--git` passes the host's *effective* configuration as `GIT_CONFIG_*`
environment variables rather than mounting `.gitconfig`: `[include]` directives
are evaluated on the host, and keys naming a host-only path (`gpg.*.program`,
credential helpers, `core.excludesFile`, `core.hooksPath`) are dropped, since
inside the container they would resolve to nothing.  The variables are passed
indirectly, as `AGENT_SANDBOX_GIT_CONFIG_*`, so the entrypoint can append its
own entry after them — which is how a signing override wins over the host's
`commit.gpgsign`.

## Loader (`agent-sandbox ctl load`)

`podman load < ${image}`

## Proxy sidecar (`--proxy`)

`--proxy` makes the launcher start a second container from the same image,
running `agent-sandbox-sidecar`, and put the sandbox on a `podman network create
--internal --disable-dns` network with no route off-host.  The sidecar is
dual-homed on that network and on `bridge`, so it is the sandbox's only path to
the internet, and the sandbox gets `HTTP_PROXY`/`HTTPS_PROXY` pointing at its
**address**.  It also gets `NO_PROXY=localhost,127.0.0.1,::1`, because the
baseline denies `127.0.0.0/8`: without the exemption a client that does not
special-case loopback -- curl and requests do not -- would send a request aimed
at a server in this very container to the sidecar and collect a `403`.  The
exemption grants nothing, since the sandbox already owns its own netns.

**`--disable-dns` is load-bearing.**  Podman routes a container's whole resolver
through aardvark-dns as soon as *any* of its networks has `dns_enabled` --
`podman-run(1)`, under `--dns`: "passing a custom network whose `dns_enabled` is
set to `true` to `--network` will result in `/etc/resolv.conf` only referring to
the aardvark-dns server".  And aardvark has refused to serve `--internal`
networks since 1.11.0 ("Do not allow 'internal' networks to access DNS"), so the
sidecar's only nameserver would answer NXDOMAIN to every external name: every
request 502s with `dns: Name or service not known`.  Passing `--dns` does not
help, because those servers are demoted to an aardvark upstream that aardvark
then declines to use -- which is why that fix looked right and did nothing.  This
has now been diagnosed three times; with DNS off on both of the sidecar's
networks there is no aardvark in the path and `--dns` lands in `resolv.conf`
verbatim.

The corollary is that `HTTP_PROXY` names an IP, not the sidecar's container name:
without aardvark there is nothing to resolve that name.  That also retires a race
nothing ever gated on -- the readiness handshake never proved aardvark had
published the sidecar's record before the sandbox started.

### Transparent listeners, for clients that cannot be pointed at a proxy

Everything above assumes a client that reads `HTTPS_PROXY`.  One does not, and
cannot be made to: the libgit2 inside `nix` -- and so inside `devenv` -- fetches
a flake input through `git_remote_connect` with a null `git_proxy_options`,
which is `GIT_PROXY_NONE`.  That consults neither the proxy environment nor
`http.proxy`, and it runs on a *detached* remote, which has no repository and
therefore no git config to consult at all.  Nix has no proxy setting of its own
to bridge the gap either -- `http-proxy` is not a `nix.conf` key, and putting it
in `NIX_CONFIG` earns an "unknown setting" warning and nothing else.  (Nix's
plain downloads are libcurl and do read the environment; only its git fetches
take this path.)

So the launcher gives those clients somewhere to land.  Every name the policy
allows is passed to `podman run` as `--add-host NAME:<sidecar>`, and the proxy
binds `:80` and `:443` on that same address under `--transparent`.  A "direct"
connection then arrives at the proxy, which recovers the destination from the
TLS SNI or the `Host` header instead of from a request line, and runs the
identical policy, address re-check, interception and logging path a `CONNECT`
would.  On the TLS path the ClientHello is peeked, not terminated: its bytes are
replayed to the origin verbatim, or handed to rustls through `PrefixedStream`
when an L7 rule means the connection has to be intercepted anyway.

This widens nothing.  Only names already in the allow list are mapped; a
wildcard pattern is not (`/etc/hosts` has no wildcards, and mapping the apex
would assert an allowance the policy never made); and the mapping is inert for
every client that does use the proxy, since such a client never resolves the
name.  A transparent client that is denied gets a closed socket rather than a
`403`, because it is mid-handshake and would read the status line as a TLS
record.

### The proxy

The proxy itself is Rust (`proxy/src/main.rs`; `ipnet` for CIDR matching,
`rustls`/`rcgen`/`webpki-roots` for the MITM path, `ratatui`/`crossterm` for the
TUI): a thread-per-connection HTTP forward proxy handling `CONNECT` and
absolute-form requests, terminating TLS for the hosts that carry an L7 rule.
Policy decisions happen once per connection, before the byte pumps start; an
established tunnel is never re-evaluated.

A cleartext request arrives in absolute-form -- addressed to the proxy -- and
leaves in origin-form, as RFC 9112 §3.2.1 requires of a request to an origin
server. Only the request line's target changes; the path and query are copied
across verbatim rather than taken from the normalized path the L7 check uses,
since that normalization exists to keep `/a/../b` off a rule it does not match.
Most servers accept either form, but not all: `python3 -m http.server` treats
the absolute target as a path and answers 404 for a file it holds.

Three directories, and which side can see them is the design:

| Path | Mounted into | Contents |
| --- | --- | --- |
| `/sidecar_policy` | sidecar, **read-only** | `policy`, `policy.base`, `policy.baseline`, `known_hosts` |
| `/sidecar_shared` | sidecar only | `proxy-ready`, `ready`, `egress-degraded`, `ca.pem`, `connections.jsonl`, `denied-requests.jsonl`, `relay.jsonl` |
| `/sidecar_secrets` | sidecar, **read-only** | `bindings` |
| (host temp dirs) | — | removed by the launcher's `CleanupGuard` on the way out |

### Host loopback ports are a mount, not a relay

`--host-loopback-port` is the one capability that reaches the host without going
through the sidecar.  The launcher binds a unix socket per mapping in a runtime
directory, splices each connection to `127.0.0.1:PORT` on the host from its own
process, and mounts the directory at `/run/agent-sandbox-host`; the entrypoint
puts a `socat TCP-LISTEN` in front of each socket so ordinary TCP clients inside
can reach it.

It is a mount rather than a route because a route would have to be a network
mode, and the sandbox's is always already taken -- pasta by default, the
`--internal` network under `--proxy`, a bridge under `--shared-network`.  Podman
takes one network mode, which is why the pasta `--map-host-loopback` mapping this
replaced could never be had together with `--proxy`.  A bind mount is orthogonal
to all three.

It is deliberately *not* a sidecar relay, unlike `--ssh` and `--gpg` under
`--proxy`.  Those are relayed so their egress stays policed; there is no
equivalent for what a host browser does, since `Page.navigate` to a denied host
is not an HTTP request the proxy could see or refuse.  Routing it through the
sidecar would be more machinery for the same hole, and would work only under
`--proxy`.  So the hole is left visible instead: named ports only, announced at
launch, and documented in [Trust model](trust-model.md).

### The cooperative browser is a second proxy, not a relay

`agent-sandbox browser` runs the same `agent-sandbox-proxy` binary on the host,
outside the sidecar entirely.  That is what the proxy's `--shared-dir` and
`--no-egress-probe` options are for: the three files it writes (`proxy-ready`,
`ca.pem`, `egress-degraded`) were fixed at `/sidecar_shared`, and the readiness
probe is a 30s ceiling that only makes sense when a container's network is still
coming up.

Each invocation owns a mode-0700 directory under `$XDG_RUNTIME_DIR`, named
`agent-sandbox-browser-<session>` -- `--name`'s value, or a uuid8 when it was
left out -- the same shape as the host-port directory:

| File | What it is |
| --- | --- |
| `policy`, `policy.base`, `policy.baseline` | the same trio as `/sidecar_policy` |
| `connections.jsonl`, `denied-requests.jsonl` | the proxy's own logs |
| `policies/managed/agent-sandbox.json` | the Chromium managed policy, bound into place by bwrap |
| `profile/` | Chromium's `--user-data-dir` |
| `meta.json` | session name, CDP port, proxy port and pid, so `ctl proxy --browser` and the launcher's `--browser` can find it |

Reusing the policy file trio rather than inventing a format is what makes
`agent-sandbox ctl proxy allow --browser` work with no new machinery:
`install_policy` validates and swaps the file atomically, and the proxy's
existing watcher picks it up within a second.  The managed policy is rewritten
by the same command, in place and by rename, so the two layers never hold
different permissions -- it was written once at launch, which left every
runtime widening applied to the proxy and refused by the browser.  `--browser` resolves through
`meta.json` instead of a sidecar mount, and sweeps directories whose pid is gone
-- `Drop` does not run on SIGKILL, and a stale directory would otherwise look
like a second running browser.

It is deliberately *not* the sidecar's proxy.  The sandbox's policy governs what
the sandbox connects to; the browser is a separate principal on the host, and
merging the two would mean a rule added for a page the user is looking at also
widens what the agent can fetch directly.  Two policies, one command to change
either.

None of them is mounted into the sandbox — `ca.pem` is bound in as a single
file, not by exposing its directory. That is deliberate and load-bearing: the
agent must not be able to widen the firewall that contains it, nor rewrite the
log of what it did. Changing policy is therefore a host-side operation
(`agent-sandbox ctl proxy`), which is why the old in-container
`agent-sandbox-allow` was deleted rather than repaired.

**Policy format.** The proxy enforces the merged declarative `[network]` blocks
from `AGENTS.md` and any explicitly selected host-owned profiles.
`[network].allowed_hosts` contains domains, wildcard domains, IPs, or CIDR blocks, each
with a port, a port range, or a comma-separated list of both; an entry written
without one is matched against the compiled-in `DEFAULT_ALLOW_PORTS`
(80, 443, 22) instead, which is also what `allow_port` defaults to when the
policy declares none. A host entry carries its whole port list on one line;
the standalone `allow_port` key takes a single port or range, so a wildcard
entry like `"*:80,443"` compiles to one `allow_port` line per element.
`[[network.allowed_routes]]` configures L7 routes and optional secret injection.
Those two keys are the whole surface: an unknown key under `[network]` refuses
the launch rather than being ignored.

The launcher merges and compiles those blocks into the flat, line-oriented policy file the
proxy reads (`allow_host`, `allow_ip`, `allow_port`, `allow_route`,
`secret_route`, `allow_signing`, `deny_ip`, `default`), which is also the
format `agent-sandbox ctl proxy` edits in place. `signing_enabled` is a ninth
key in that same file, but it is never compiled from `AGENTS.md` -- the
launcher writes it directly whenever `--gpg` is passed, independent of any
`[network]` content (see Relay Architecture below).  `secret_route` records a
*route* -- `domain<TAB>method<TAB>path`, like `allow_route` -- not a domain, and
`deny_ip` is written only by the launcher: there is no domain deny list, and
`install_policy` refuses a live edit that changes the deny set.  One host on two
ports is two `allow_host` lines carrying the same pattern; the proxy unions the
ports of every line tied at the winning specificity, so both are in force.
`agent-sandbox-proxy --check-policy FILE` validates it: the launcher writes the
file, the proxy reads it, and the host-side `proxy` command vets its own writes
with the same parser, so there is no second implementation to drift.

`agent-sandbox ctl proxy export` prints that policy back as a fenced
```` ```toml agent-sandbox ```` block, since the launcher parses configuration
only inside that fence; `--plain` drops it for a `--proxy-profile` file, which is
plain TOML.  `ctl mounts export` emits the same fence.

The two JSONL streams under `/sidecar_shared` are bounded — `connections.jsonl`
at 16 MiB, `denied-requests.jsonl` at 4 MiB.  `rotate_if_needed` drops the
*oldest* records to get back under the cap and cuts at a record boundary: every
reader parses one JSON object per line, so a fragment at the top of the file
would fail the first line of every trimmed log.

**Secret Injection.** `--secrets` triggers secret injection via `secretspec`.
The source of authority is a host-controlled TOML file
(`~/.config/agent-sandbox/trusted.toml`), which defines the exact bindings --
host and port, method, path, secret, header, prefix. The launcher calls the
resolver in `cli/src/secrets.rs`, which cross-references that config with the
policy's `secret_route` routes from `AGENTS.md`, and then runs `secretspec export`
on the host to fetch the values. The filtered bindings are written 0600 into
`/sidecar_secrets/bindings`, which only the sidecar mounts, as
`domain<TAB>method<TAB>path<TAB>header<TAB>value`.

The route travels with the binding, and that is the design.  `AGENTS.md` is
untrusted and controls the *other* rules on a host, so recording only the
domain -- verifying the operator's method and path host-side and then throwing
them away -- meant a second, secret-less rule (`method = "*", path = "/**"`)
collected the same token.  `inject::proxy_http1_with_injection` now resolves the
binding *per request*, after the L7 check and against the same normalized path,
so a keep-alive connection carrying several requests is several decisions and
`/user/repos/../../zen` cannot carry the token to `/zen`.

**Host-key trust.** The same host-controlled file carries
`[[network.known_hosts]]`, and the same shape of check applies: `cli/src/trusted.rs`
compares the compiled policy's `allow_signing` entries against it, and a host
authorized for SSH with no key declared for it refuses the launch before any
container exists -- earlier than the secrets check, which has to wait on a
written policy file and a `secretspec` call.  The authorized keys are rendered
to `known_hosts` syntax beside the policy and mounted read-only into the sidecar
(where `relay-server` points `ssh` at them) and, one file at a time, into the
sandbox (where the entrypoint seeds `~/.ssh/known_hosts` from them).  The
built-in forge keys in `proxy/src/known_hosts.rs` are not a trust anchor under
`--proxy`; they only fill in the refusal's suggested block, and they still seed
an unproxied session, which has no policy to authorize against.

**CA trust.** The proxy terminates TLS for any host carrying an L7 rule, using a
CA it generates per session and writes to `/sidecar_shared/ca.pem`. The launcher
binds *that file alone* into the sandbox and points
`AGENT_SANDBOX_PROXY_CA_FILE` at it; the entrypoint merges it with the image's
bundle into `~/.cache` and exports the result under every variable the usual
clients read. The directory itself is never mounted into the sandbox — the
connection log lives there.

The mount is gated on the launch policy actually carrying an `allow_route` line.
With none, `skip_l7` is true for every host and the leaf issuer is never
reached, so a CA in the sandbox's trust store would grant the proxy the ability
to intercept anything for no purpose. The cost is that an L7 rule added
mid-session has no CA behind it; `ctl proxy allow --l7` and the TUI's `h` warn
rather than failing later at certificate validation.

The launcher appends a baseline `deny_ip` list (loopback, RFC1918, link-local,
CGNAT, ULA) to every policy it writes, under `--proxy`.

**Relay Architecture.** When `--ssh` or `--gpg` are used with `--proxy`, the sandbox cannot mount the host sockets directly (they bypass the proxy firewall). Instead, the sidecar runs `relay-server`, exposing a TCP port to the sandbox. Inside the sandbox, `relay-ssh` and `relay-gpg` binaries forward requests to the sidecar over a custom binary protocol. The relay authorizes the two independently: `relay-gpg` requests are allowed whenever `signing_enabled` is `true` in the policy file — a flag the launcher writes unconditionally whenever `--gpg` wires up the relay, with no host to name, since gpg has no destination of its own. `relay-ssh` requests are allowed only when the destination host matches an `allow_signing` entry, which an `allowed_hosts` entry on port 22 is what populates — so `git push` still needs an explicit `"host:22"` declaration even though signing does not.

Because the relay runs the real `ssh` in the sidecar, host-key verification has
to be solved there too. `relay-server` reads `/sidecar_policy/known_hosts` —
the keys the operator authorized, written there by the launcher — and prepends
`-o UserKnownHostsFile=… -o GlobalKnownHostsFile=/dev/null` to the ssh it
spawns. Both halves are necessary: the sandbox's own `known_hosts` is on the
far side of the boundary, and an implicit `~/.ssh/known_hosts` would not be
found either, since the sidecar runs as uid 0 and OpenSSH expands `~` from
`getpwuid` — `/root` — rather than from the image's `HOME=/home/user`. Options
are prepended rather than appended because ssh keeps the first value it sees
for a keyword and stops reading options at the destination.

The injection is unconditional, because argv that would work around it is
refused: `refused_ssh_option` rejects the four host-key options, `-F`, `-J` /
`ProxyJump`, and the four exec options, and it scans the same walk of argv that
finds the destination (`split_ssh_args`) so an option cannot be acted on by ssh
without having been seen by the check. Both run over the caller's argv alone,
so the options the relay prepends are not themselves scanned. See
[Trust model](trust-model.md) for what each of those would otherwise buy.
The sidecar sits on the default bridge as well as the sandbox's internal network,
so without it a policy with no rules -- which is exactly what a bare `--proxy` runs -- could
be asked to reach the host and its LAN on the sandbox's behalf.  Writing it as
ordinary `deny_ip` entries rather than compiling it into the proxy means one
list, visible in `proxy show`, restored by `reset`, and mirrored into the
kernel routes by the same `sync_routes` that handles user rules.
An `allow_ip` entry of equal or greater specificity overrides one of them; that
is why `is_denied_address` breaks prefix ties toward allow.

`sync_routes` mirrors that whole rule, not `deny_ip` alone.  The kernel's
longest-prefix match *is* the specificity comparison the proxy makes, so every
`allow_ip` entry gets a route via the default gateway and beats a shorter
blackhole by itself; the one case a routing table cannot express is the
equal-prefix tie, there being room for a single route per prefix, and that is
handled by not installing the blackhole at all.  Until it did this, a re-allowed
range -- including the documented `allowed_hosts = ["10.0.0.0/8"]` for corporate
git over a VPN, which compiles to `allow_ip` against the baseline -- was
permitted by the proxy and then dropped on the floor by the route, with
`proxy show` reporting the rule as in force.

The sidecar's nameservers, read from its own `/etc/resolv.conf`, are exempted
unconditionally.  Resolution happens in the sidecar via libc, before any rule is
consulted, so a `deny_ip` range containing the resolver blackholes DNS itself
and fails every request rather than only the ones aimed at that range -- and the
baseline's `192.168.0.0/16` does exactly that to a home router.  This is not a
way out: the sandbox has no route into this netns, its only egress is CONNECT to
the proxy, and `is_denied_address` still runs over every resolved address, so a
CONNECT aimed at the resolver stays refused.

Because the sidecar is on that bridge, the proxy binds only the address it holds
on the internal network, selected by subnet membership from `SIDECAR_SUBNET`
rather than by interface name -- podman's eth0/eth1 assignment follows the order
of the `--network` flags and is not something to depend on.

**Startup ordering** matters and is why there are two readiness markers: the
proxy validates policy, probes egress and writes `proxy-ready`; the sidecar then
installs the routes and writes `ready`; only then does the launcher start the
sandbox.  So routes are in place before any traffic can exist, and a bad policy
exits 2 before touching the kernel table.

The corollary is that the probe runs *before* the routes exist and so cannot
catch a policy that blackholes the sidecar's own resolver: it proves egress,
`sync_routes` then breaks it, and the session 502s with a clean startup behind
it.  That is why the nameserver exemption above is unconditional rather than a
reaction to a failed probe.  Reordering the markers would not help either --
proving egress after the routes are installed would only turn a silent failure
into a degraded launch, when the routes can simply be right.

The egress probe is never fatal -- a degraded launch beats a hung one -- but it
is no longer silent: when it gives up it writes `egress-degraded` with the
resolver's own error, and the launcher prints that on the terminal.  Without it
the session looks healthy for 30 seconds and then 502s, which is exactly how the
aardvark problem above stayed hidden.

**Runtime changes.** The proxy polls the policy file's `(mtime, size)` once a
second and swaps an `Arc<ProxyConfig>` under an `RwLock`, clearing the DNS cache
with it; the sidecar reconciles the blackhole routes against the kernel on the
same interval.  A rejected or vanished policy keeps the one already in force.
New connections see the change within a second; established ones do not.
