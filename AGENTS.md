# AGENTS.md – agent-sandbox

## Project overview

`agent-sandbox` is a Nix flake that produces a rootless Podman container image
("agent-sandbox") together with a launcher binary (`agent-sandbox`) and a
management multiplexer (`agent-sandbox-ctl`, with the subcommands `load`,
`list`, `status`, `net`, `logs`, `proxy`, `ports`, `mounts`, `attach` and `purge`).

- **default.nix** – single Nix module; builds the image and every host script.
- **agents.nix** – agent catalog (command + persisted state paths per agent).
- **flake.nix**  – flake entry point; exposes `packages.<system>.default` and
  `apps.<system>.default`.

## Architecture

### Image (`image` attr in `default.nix`)

Built with `pkgs.dockerTools.streamLayeredImage`.  All tools are baked into a
`buildEnv` and registered in the Nix store database so `nix` / `devenv` / Nix
builtins inside the container work without re-substituting store paths.

Key layers:

| Path                  | Purpose                                                |
| --------------------- | ------------------------------------------------------ |
| `/etc/nix/nix.conf`   | `sandbox = false`, `flakes` enabled                    |
| `/etc/containers/*`   | Pre-configured rootless podman (crun, overlay driver)  |
| `/usr/bin/env`        | Symlink to coreutils `env` for generic shebangs        |
| `/lib64/ld-linux-*`   | ELF interpreter for prebuilt npm binaries              |
| `/home/user`          | Home directory (uid/gid mapped at runtime)             |
| `/workspace`          | Default working directory                              |

### Entrypoint (`agent-sandbox-entrypoint`)

1. Loads the Nix store registration on first start (unless `AGENT_SANDBOX_HOST_NIX=1`, in which case the host's `/nix` mount is used, or `AGENT_SANDBOX_SKIP_NIX_INIT=1`, which sidecar launches set because they do not need Nix bootstrap).
2. Sets up `known_hosts` for common git forges to avoid first-time connection prompts.
3. When `AGENT_SANDBOX_GPG_AGENT=1`, symlinks the forwarded host gpg-agent
   socket into `~/.gnupg/S.gpg-agent`.
4. When `HTTP_PROXY` is set, compensates for tools that don't honor it on
   their own: dynamically generates `~/.ssh/config` to route SSH through the
   proxy, and sets `NODE_USE_ENV_PROXY=1` so Node's core `http`/`https` and
   built-in `fetch` (undici) stop dialing out directly — this also covers
   the bundled Node-based agent CLIs, which share Node's runtime. An
   operator's own explicit `NODE_USE_ENV_PROXY` setting is left alone.
5. `exec "$@"`.

### Launcher (`agent-sandbox`)

A bash script that wraps `podman run`.  Call flow:

1. Parse flags: consume known flags (`--ssh`, `--no-git`, `--no-workspace`,
   etc.), pass through `-v` volume mounts (with relative-path expansion),
   stop at `--` sentinel.
 2. Build mounts array from toggles (ssh socket, git config, gpg socket,
    devenv dir, podman host socket, CWD workspace) plus the state dirs of
    whichever agents are selected — the positionally-launched one by default,
    or the set chosen via `--agent-mounts`/`--agent-mounts=…` — sourced from
    `agents.nix` (opencode, claude-code, copilot, antigravity).
3. Build env_args array from toggles (SSH_AUTH_SOCK, git identity,
   CONTAINER_HOST, DOCKER_HOST, TERM, COLORTERM).
4. Create ephemeral `/etc/passwd` and `/etc/group` with the host user's uid/gid.
5. Call `podman run` with `--userns=keep-id`, tmpfs for `~/.config`,
   `~/.cache`, `~/.local`, all mounts and env vars, then the image and the
   final command (default `opencode`, overridable via `-- …`).

### Loader (`agent-sandbox-ctl load`)

`podman load < ${image}`

### Proxy sidecar (`--proxy`)

`--proxy` makes the launcher start a second container from the same image,
running `agent-sandbox-sidecar`, and put the sandbox on a `podman network create
--internal --disable-dns` network with no route off-host.  The sidecar is
dual-homed on that network and on `bridge`, so it is the sandbox's only path to
the internet, and the sandbox gets `HTTP_PROXY`/`HTTPS_PROXY` pointing at its
**address**.

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

The proxy itself is Rust (`proxy/src/main.rs`, `ipnet` its only dependency): a
thread-per-connection HTTP forward proxy handling `CONNECT` and absolute-form
requests.  Policy decisions happen once per connection, before the byte pumps
start; an established tunnel is never re-evaluated.

Three directories, and which side can see them is the design:

| Path | Mounted into | Contents |
| --- | --- | --- |
| `/sidecar_policy` | sidecar, **read-only** | `policy`, `policy.base` |
| `/sidecar_shared` | sidecar only | `proxy-ready`, `ready`, `egress-degraded`, `connections.jsonl` |
| (host temp dirs) | — | removed by the launcher's exit trap |

Neither is mounted into the sandbox. That is deliberate and load-bearing: the
agent must not be able to widen the firewall that contains it, nor rewrite the
log of what it did. Changing policy is therefore a host-side operation
(`agent-sandbox-ctl proxy`), which is why the old in-container
`agent-sandbox-allow` was deleted rather than repaired.

**Policy format.** One `KEY VALUE` per line (`allow_domains`, `deny_domains`,
`allow_ips`, `deny_ips`, `allow_ports`, `default`).  A value containing whitespace
is a hard error.  This replaced four differently-encoded arguments -- allow_domains as argv
words, the rest as space-joined env vars, all parsed as CSV -- where every entry
past the first was silently dropped, and an emptied allow list means allowing
everything.  One entry per line means any fixture with two entries exercises the
case that used to break.

`agent-sandbox-proxy --check-policy FILE` is the single reference validator:
`parse_agents.py` writes the file, the proxy reads it, the host-side `proxy`
command vets its own writes with the same binary, and `checks.firewall-policy`
tests the whole chain.  There is no second implementation to drift.

The launcher appends a baseline `deny_ips` list (loopback, RFC1918, link-local,
CGNAT, ULA) to every policy it writes, under `--proxy`.
The sidecar sits on the default bridge as well as the sandbox's internal network,
so without it a policy with no rules -- which is exactly what a bare `--proxy` runs -- could
be asked to reach the host and its LAN on the sandbox's behalf.  Writing it as
ordinary `deny_ips` entries rather than compiling it into the proxy means one
list, visible in `proxy show`, restored by `reset`, and mirrored into the
kernel routes by the same `sync_routes` that handles user rules.
An `allow_ips` entry of equal or greater specificity overrides one of them; that
is why `is_denied_address` breaks prefix ties toward allow.

`sync_routes` mirrors that whole rule, not `deny_ips` alone.  The kernel's
longest-prefix match *is* the specificity comparison the proxy makes, so every
`allow_ips` entry gets a route via the default gateway and beats a shorter
blackhole by itself; the one case a routing table cannot express is the
equal-prefix tie, there being room for a single route per prefix, and that is
handled by not installing the blackhole at all.  Until it did this, a re-allowed
range -- including the README's own `allow_ips = ["10.0.0.0/8"]` against the
baseline -- was permitted by the proxy and then dropped on the floor by the
route, with `proxy show` reporting the rule as in force.

The sidecar's nameservers, read from its own `/etc/resolv.conf`, are exempted
unconditionally.  Resolution happens in the sidecar via libc, before any rule is
consulted, so a `deny_ips` range containing the resolver blackholes DNS itself
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

## How to add a new integration

1. Add a `want_{name}=1` toggle after the existing toggles (see integration toggles).
2. Add `--{name}` / `--no-{name}` cases in the argument parsing loop.
3. Add the mount/env logic after the existing blocks.
4. If container-side setup is needed in the entrypoint, gate it on an env
   var (e.g. `AGENT_SANDBOX_*`) and pass that var from the launcher.
5. Update the usage comment.
6. Test: `nix flake check`

Note what `nix flake check` cannot cover: podman does not run in a Nix build, so
nothing that starts a container is tested there.  `checks.ctl-args` drives the
`ctl` scripts against a stub podman, and `lib/smoke-firewall.sh` is the hand-run
procedure for the rest (`bash lib/smoke-firewall.sh`, needs a real podman and
network egress).

## How to add a new agent

Add an entry to `agents.nix`. The entry drives:

- inclusion of the agent package in the image PATH,
- accepted agent names in the launcher,
- command dispatch when selecting that agent,
- persisted home-state mounts (`state` directories, `stateFiles` files).

Downstream flakes can override the catalog and default agent via:

`(import ./default.nix { inherit pkgs lib; }).override { agents = ...; defaultAgent = "..."; }`

## How to add a new tool to the image

Add the package to `baseTools`.  It is automatically included in the PATH
and Nix store registration.  No other changes needed.

## Important implementation constraints

- Nix shell scripts are written with `writeShellScriptBin`; the `''` escaping
  inheredoc-style strings is Nix's double-single-quote mechanism.
- The container runs with `--userns=keep-id`, so the uid/gid inside the
  container match the host user.  Passwd/group files are synthesized per-run.
- Tmpfs mounts on `~/.config`, `~/.cache`, `~/.local` provide writable home
  subdirectories by default; persistent tool data (opencode, devenv, …) is
  layered on top via explicit `-v` bind mounts.
- Nested rootless podman inside the container requires `--privileged`.
  The image ships a full podman stack and `/etc/containers` config, so nested
  podman works out of the box when the privilege flag is passed.
- **Host Nix shadowing**: When `--nix` is passed (off by default, but commonly baked in by a `wrapProgram` wrapper), the host `/nix/store` is mounted over the image's own store. Every PATH entry and the entrypoint itself then resolves against the host store rather than the baked-in one. This means the image is not entirely self-contained by default: transferring it to another host, or running garbage collection on a host where it wasn't installed via `nix profile`, may break the container at execution time.
