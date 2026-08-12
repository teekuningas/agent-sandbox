# agent-sandbox

Sandboxed AI coding environment that runs inside a rootless Podman container.
Launch `opencode` (or any other tool) and explicitly opt-in to integrations like
SSH forwarding, GPG signing, Git identity, host Podman socket, and `devenv` state.

## Table of contents

- [Quick start](#quick-start)
- [Usage](#usage)
  - [Flags](#flags)
- [Managing running sandboxes](#managing-running-sandboxes)
- [What's in the image](#whats-in-the-image)
- [How it works](#how-it-works)
- [Trust model](#trust-model)

## Quick start

```sh
git clone https://github.com/datakurre/agent-sandbox
cd agent-sandbox
nix profile add .#          # installs agent-sandbox and agent-sandbox-ctl
```

Or without cloning:

```sh
nix profile add github:datakurre/agent-sandbox
```

Either way, build the container image once before first use:

```sh
agent-sandbox-ctl load
```

Then launch a tool:

```
agent-sandbox [FLAGS] [AGENT] [-- COMMAND...]
```

`agent-sandbox opencode` launches opencode inside the sandbox with the current
working directory mounted at `/workspace` and every integration enabled. If the
current directory contains a `devenv.nix`, opencode is started through a devenv
shell (`devenv shell -- opencode .`) so project dependencies are loaded
automatically. Running `agent-sandbox` with no arguments launches an interactive
`bash` shell with every agent's binary on `PATH`, but no agent's state
pre-mounted — pass `--agent-mounts` to make one, several
(`--agent-mounts=claude-code,copilot`), or every agent's login/config state
available too.

See [Usage](#usage) below for overriding the container command, passing raw
podman flags, and the full [flags reference](#flags).

## Usage

### Override the container command

Everything after the `--` sentinel replaces the default command:

```sh
agent-sandbox                                    # interactive shell (every agent's binary on PATH)
agent-sandbox -- bash -c "nix build .# && echo done"
agent-sandbox opencode -- devenv shell           # devenv shell with opencode default cmd replaced
```

### Pass podman flags

To pass arguments directly to podman there are two forms.

`--podman-args=ARG` passes exactly one argument and is repeatable. It consumes
nothing but itself, so flags after it are still parsed by agent-sandbox. Use
this one when baking defaults into a wrapper.

`--podman-args` (no `=`) passes everything that follows to podman until a `--`
sentinel, which also marks the start of the container command. Because `--` ends
agent-sandbox's own parsing, anything after it is the command, not a flag.

There are also convenient shortcuts like `--privileged` and `-e` for common podman flags.

```sh
agent-sandbox --privileged opencode               # enable nested podman
agent-sandbox --podman-args=--network=host opencode # host network, repeatable form
agent-sandbox --podman-args --network=host -- bash # host network, slurp form
agent-sandbox --podman-args -v ./cache:/cache -- opencode
agent-sandbox -e MY_VAR=1 opencode                # pass environment variable
```

### Configuring Defaults via Nix

All integrations are **disabled by default**. If you are building downstream tooling, you can establish your own defaults by wrapping the `agent-sandbox` binary in Nix. 

Because the CLI evaluates arguments sequentially (the last flag provided wins), any flags added by `wrapProgram` can be overridden by the user at runtime. For example, if the wrapper adds `--ssh`, running `agent-sandbox --no-ssh` will successfully disable SSH forwarding.

Here is an example that restores the historical defaults of `agent-sandbox`:

```nix
agent-sandbox = pkgs.symlinkJoin {
  name = "agent-sandbox";
  paths = [ inputs.agent-sandbox.packages.${pkgs.stdenv.hostPlatform.system}.default ];
  nativeBuildInputs = [ pkgs.makeWrapper ];
  postBuild = ''
    wrapProgram $out/bin/agent-sandbox --add-flags "--workspace --ssh --git --gpg --devenv --nix --ports"
  '';
};
```

Podman flags can be baked in the same way, but only via the `--podman-args=ARG`
form. The slurp form ends in a `--`, which terminates agent-sandbox's own
parsing, so everything the user typed afterwards would be taken as the container
command rather than as flags:

```nix
wrapProgram $out/bin/agent-sandbox --add-flags \
  "--podman-args=--add-host=myhost.tail1234.ts.net:100.64.0.1"
```

### Flags

Every flag in the table below has a corresponding `--no-flag` option (e.g., `--no-workspace`) to explicitly disable it. Since arguments are evaluated sequentially, passing `--ssh` followed by `--no-ssh` will leave the feature disabled. This is how user-provided command line arguments can override defaults built into the script via `wrapProgram`.

`--gpg-agent` and `--gpg-sign` were merged and removed; use `--gpg` / `--no-gpg`.

| Group | Flag | What it does |
| --- | --- | --- |
| Workspace & identity | `--workspace` | Mounts the host's current working directory into `/workspace/<dirname>`. |
| Workspace & identity | `--ssh` | Forwards the host's `SSH_AUTH_SOCK` to the container. |
| Workspace & identity | `--git` | Mounts host Git configurations and passes identity env vars. |
| Workspace & identity | `--gpg` | Enables host GnuPG agent forwarding and git commit signing behavior. |
| Workspace & identity | `--gpg-private` | Exposes `~/.gnupg` even if it holds on-disk secret keys. |
| Workspace & identity | `--devenv` | Persists `~/.local/share/devenv` across sessions. |
| Workspace & identity | `--nix` | Mounts the host `/nix/store` for native Nix execution. |
| Container runtime | `--podman` | Forwards the host rootless Podman socket (sibling containers). See [Trust model](#trust-model). |
| Container runtime | `--selinux` | Applies SELinux shared relabeling (`:z`) to writable binds in the sandbox container. |
| Container runtime | `--krun` | Runs the sandbox as a KVM microVM with its own kernel, using `podman --runtime krun`. See details below and [Trust model](#trust-model). |
| Container runtime | `--krun-memory MiB` | Guest RAM (default `4096`). Values of 128 or below are rejected. |
| Container runtime | `--krun-cpus N` | Guest vCPUs (1–16). Defaults to the host CPU affinity count. |
| Network & firewall | `--proxy` | Isolates the container from the internet and routes HTTP(S)/SSH through a proxy that enforces `AGENTS.md`'s `[proxy]` policy if present (deny-by-default once any allow rule exists, otherwise allow-by-default), and prints a post-run traffic summary. See details below. |
| Ports & mounts | `--ports` | Honors `[ports]` declarations from `AGENTS.md`. |
| Ports & mounts | `--ports-dynamic` | Allows `agent-sandbox-ctl ports add` post-launch. |
| Ports & mounts | `--ports-any-interface` | Permits port binds outside of loopback interfaces. |
| Ports & mounts | `--mounts` | Honors `[mounts]` declarations from `AGENTS.md`. |
| Ports & mounts | `--agent-mounts` | Mounts every known agent's state; `--agent-mounts=a,b` mounts just those (plus any launched agent). |

A few flags are one-off pass-throughs rather than persistent toggles, so they have no `--no-flag` form:

| Flag | What it does |
| --- | --- |
| `--port [HOST:]CONTAINER[/PROTO]` | Publishes a port. |
| `-e NAME=VAL`, `--env NAME=VAL` | Injects an environment variable. |
| `--privileged` | Enables nested podman inside the sandbox (safe — see [Trust model](#trust-model)). |
| `--podman-args ... --` | Passes arguments straight through to `podman` until the `--` sentinel (including `-v/--volume`). |

By default, built-in writable binds stay plain `:rw` so non-SELinux hosts see
no relabel side-effects. On SELinux hosts, pass `--selinux` to apply shared
relabeling (`:z`) to built-in writable binds. Podman volume options passed via
`--podman-args` are preserved exactly as supplied.

`--selinux` relabels the *file* a socket is mounted as, but that alone is not
enough for `--ssh`: connecting to a forwarded `SSH_AUTH_SOCK` (including a
gpg-agent SSH socket) is a separate `unix_stream_socket connectto` check
between the container's process context and the *listening agent's* context —
typically `unconfined_t` for a user's own `ssh-agent`/`gpg-agent` — and
default policy denies that regardless of the file's label, to stop containers
reaching arbitrary host IPC sockets. If `ssh`/`ssh-add` inside the sandbox
reports `Permission denied` right after finding the socket (as opposed to "no
such user" or "could not open a connection"), confirm with
`sudo ausearch -m avc -ts recent | grep connectto` and, if it names your agent
socket, allow it host-wide with:

```
sudo setsebool -P container_connect_any 1
```

This is a persistent, host-wide SELinux policy change, so it is not something
`agent-sandbox` can or should apply on your behalf.

The proxy sidecar is treated as infrastructure: it always runs with SELinux
labeling disabled for `/sidecar_policy` and `/sidecar_shared` so proxy
readiness does not depend on host relabeling flags.

#### `--krun` details

Requires read/write access to `/dev/kvm` (usually the `kvm` group) and a `crun` built with libkrun. Only the sandbox becomes a VM — the proxy sidecar and the port forwarders stay ordinary containers, so `--proxy` and every `agent-sandbox-ctl` subcommand that works by label are unaffected.

- `agent-sandbox-ctl attach` and `agent-sandbox-ctl mounts` **do not work** against a `--krun` sandbox and refuse with an explanation. crun's libkrun handler implements no `exec`, so there is no way into a running guest; and a host-side bind mount lands in the VMM's mount namespace where the guest cannot see it. Run the shell as the sandbox's own command (`agent-sandbox --krun -- bash`), and declare mounts up front with `--podman-args -v ... --`.
- `--podman` is refused under `--krun`; `--privileged` and `--selinux` are accepted with a warning that they are unverified against a guest.

#### `--proxy` details

The `[proxy]` block supports `allow_domains`, `deny_domains`, `allow_ips`, `deny_ips`
and `allow_ports`.

- **Default Policy**: 
  - If you provide any allow list (`allow_domains` or `allow_ips`), the default policy becomes **deny all**.
  - If you only provide deny lists (`deny_domains` or `deny_ips`), the default policy is **allow all**.
  - `allow_ports` does **not** flip the default on its own — only `allow_domains` and `allow_ips` do. It restricts which ports are reachable, not which hosts.
- **Simultaneous Allow & Deny (Most Specific Wins)**: You can specify both allow and deny rules at the same time. When a target matches both, the **more specific rule wins**:
  - For domains, the longer pattern wins (e.g., an explicit rule for `api.github.com` overrides a wildcard rule for `*.github.com`).
  - For IPs, the longer CIDR prefix wins (e.g., `10.1.0.0/24` overrides `10.0.0.0/8`).
- **Wildcards**: Wildcards are supported for domains (e.g., `*.github.com`). A strict domain like `github.com` matches that exact domain and **does not** match subdomains like `status.github.com`. A wildcard matches both the subdomains and the apex, so `*.github.com` alone covers `github.com` as well — which also means a deny rule written `*.github.com` blocks the apex. This applies to both allow and deny domain rules.
- Domain matching is case-insensitive. When an allow and a deny rule match with equal specificity, allow wins.
- Hostnames are also checked against `deny_ips` *after* resolution, so a denied address cannot be reached through an allowed name.
- `default = "allow"` or `default = "deny"` overrides the derived default explicitly.
- An invalid `[proxy]` block, or an unknown key in one, refuses the launch rather than starting with a policy that silently allows more than you wrote.
- `--proxy` with no `AGENTS.md` or no allow rules in it allows every *public* host on every port — it is then a metering proxy. Private and loopback ranges stay refused regardless (see below). The launcher says so at startup, and `agent-sandbox-ctl proxy show` reports `default allow`.
- **A degraded start is a warning, not a failure.** If the proxy cannot prove egress within 30s it serves anyway and the launcher says so. No rule is relaxed by this; requests may simply fail.
- **Cannot be combined with publishing a port.** A published port puts the sandbox on a NAT bridge alongside the proxy's internal network, giving it egress that does not pass through the proxy at all; the launcher refuses the combination rather than filtering some traffic and letting the rest around. `agent-sandbox-ctl ports add` refuses a proxied sandbox for the same reason.
- The proxy accounts each connection itself (host, byte counts each way, verdict), so metering adds no packet capture and no per-byte disk overhead.
- The traffic summary ranks hosts by volume, collapses the tail beyond 15 hosts, and lists denied and failed connections separately:

  ```
  === Network Summary ===  2m 6s · 87 connections · 24.9 MiB in / 362.9 KiB out

    HOST                   CONNS       SENT       RECV
    api.anthropic.com         64  265.2 KiB   11.3 MiB
    registry.npmjs.org         8   11.7 KiB    9.5 MiB
    github.com                11     86 KiB    4.1 MiB

    ── denied ────────────────────────────────────────
    telemetry.example.com      3

    ── failed ────────────────────────────────────────
    proxy.example.com          1  (dns)
  ```

`--proxy` also makes these available while the sandbox runs:

- `agent-sandbox-ctl status` — one screen: proxy mode, rule and traffic counts, ports.
- `agent-sandbox-ctl net` / `net -f` — the summary above for the session so far, or a live feed.
- `agent-sandbox-ctl logs [-f]` — the proxy's own log: the policy it started with, and every denial as it happens.
- `agent-sandbox-ctl proxy show|allow|deny|rm|reset|export` — read and change the policy of a **running** sandbox.
- A connection record is written when it *closes*, plus one when it opens, so a long-lived HTTPS tunnel appears as `in flight` under `── still open ──` rather than as traffic. Individual requests inside a tunnel are never visible; the proxy does not decrypt it.
- The connection log lives on a host temp directory for the lifetime of the session and is removed at exit. `--proxy` additionally prints the summary when the session ends, and keeps the log at `$TMPDIR/agent-sandbox-connections-<pid>.jsonl` if anything was denied or failed. `agent-sandbox-network-summary <log>` re-renders a kept log.
- Neither the policy nor the log is reachable from inside the sandbox, so the agent can neither widen its own firewall nor edit the record of its traffic.

<details>
<summary><strong>What the policy covers</strong> — proxy rule-matching, baseline private/loopback denials, and DNS resolver exemption (expand for full detail)</summary>

#### What the policy covers

The containment itself is separate from the policy: the sandbox gets a single interface on
an internal network with no route off it, so the proxy is the only reachable destination and
an agent that ignores `HTTP_PROXY` simply fails. Everything below is the *policy* applied at
the proxy. Two limits remain by design; they are described at the end of this section.

Rules match on host **and** port, though the port half only engages once the policy is
deny-by-default. Whenever you declare `allow_domains` or `allow_ips`, `allow_ports` defaults
to `80,443,22` — enough for web and git-over-SSH — and anything else has to be named:

```toml
[proxy]
allow_domains = ["github.com", "*.github.com"]
allow_ports = ["443", "8000-8100"]
```

An allow-by-default policy (deny rules only, or `--proxy` with no `[proxy]` block of
your own) leaves ports unrestricted unless you write `allow_ports` yourself. Denials say
which half refused, so an allowed host on an unlisted port is distinguishable from a host
that was never allowed:

```
proxy: deny github.com:8443 (port not in allow_ports; add `allow_ports 8443`)
```

Private and loopback destinations are refused by default under `--proxy`,
with or without any rule of your own — whether they are named directly
or reached through a hostname that resolves to one:
`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`,
`100.64.0.0/10`, `0.0.0.0/8`, `fc00::/7`, `fe80::/10` and `::1/128`. The sidecar itself still sits
on the host's default bridge network as well as the sandbox's internal one — that is how it
gets `HTTP_PROXY`-reachable and keeps a working resolver — so without this baseline the proxy
could otherwise be asked to reach your host and your LAN on the sandbox's behalf. It also
binds only its address on the sandbox's internal network for accepting connections, not that
bridge, so another container of the same user cannot use it as an open proxy either. Allow a
range back explicitly when you need it:

```toml
[proxy]
allow_ips = ["10.0.0.0/8"]   # corporate git over the VPN
```

An `allow_ips` entry of equal or greater specificity than a deny wins, at the proxy *and* in
the sidecar's routing table: the kernel's longest-prefix match is the same rule the proxy
applies, so a re-allowed range is genuinely reachable rather than permitted by the policy and
then dropped by a route.

**The sidecar's own resolvers are always reachable, whatever the policy says.** Names are
resolved in the sidecar, by libc, before any rule is consulted, so a `deny_ips` range that
happens to contain your nameserver would otherwise blackhole resolution itself and fail
*every* request, not only the ones aimed at that range — and the startup egress probe cannot
catch it, because it runs before the routes are installed. The baseline `192.168.0.0/16`
alone covers a great many home resolvers. Exempting them is not a way out of the sandbox: the
sandbox has no route into the sidecar at all, its only egress is `CONNECT` to the proxy, and
the proxy still checks every resolved address against `deny_ips`. A `CONNECT` aimed at your
resolver stays refused.

The host's `search` domains and resolver `options` travel with the nameservers, so an
unqualified name that resolves on the host resolves in the sandbox too.

Hostnames are normalised before matching, so a trailing dot (`github.com.`) and an
IPv4-mapped IPv6 literal (`[::ffff:10.0.0.1]`) match the same rules as their plain forms.
Deny lists are therefore enforcing rather than advisory, in every mode.

Two limits remain by design. The proxy does not decrypt TLS, so it cannot see which host a
tunnel talks to after `CONNECT` — allowing a host that is itself a relay, a CDN with open
forwarding, or a service with an SSRF bug grants everything reachable behind it. And egress
is `CONNECT`-only: UDP, QUIC/HTTP3, ICMP and raw TCP have no path out at all, which is why
some tools need `HTTP_PROXY` honoured explicitly (`NODE_USE_ENV_PROXY=1` is set for Node) and
why SSH is rewritten through a generated `ProxyCommand`.

</details>

### Changing the proxy policy mid-session

```console
$ agent-sandbox-ctl proxy show
silent
  policy      /tmp/agent-sandbox-policy-Xf3a91cD/policy
  default     deny  (only the rules below are reachable)
  allow_domains github.com                         AGENTS.md
  allow_ips     10.0.0.0/8                         AGENTS.md
  deny_ips      127.0.0.0/8                        AGENTS.md
  deny_ips      169.254.0.0/16                     AGENTS.md
  …

$ agent-sandbox-ctl proxy allow api.openai.com
  allowed     api.openai.com                    domains
  reloading   the proxy applies this within a second

$ agent-sandbox-ctl proxy allow 8443
  allowed     8443                              ports
  reloading   the proxy applies this within a second
```

`allow` infers what kind of entry you gave it — domain, address or port — and prints back
what it decided. Ports have no deny form, since `allow_ports` is a global restriction rather
than something scoped to a host, so `proxy deny 8443` is refused. The baseline private and
loopback ranges appear in `show` as ordinary `deny_ips` rules attributed to `AGENTS.md` —
they are included in `policy.base` alongside any user rules and are therefore restored by
`reset`. `proxy export` omits them, since they are always enforced regardless of what
`AGENTS.md` declares and round-tripping them into a new config would be redundant. Setting
`deny_ips = []` in `AGENTS.md` does not disable the baseline; the launcher appends it
unconditionally after processing the declared policy. An `allow_ips` entry of equal or greater
specificity is the only way to open one of those ranges.

Changes take effect for new connections within a second. Connections already established keep running: the proxy checks policy when a connection opens and does not re-check it afterwards, so tightening a rule does not cut a tunnel that is already up — end the session for that. `proxy show` says how many are open when it matters.

`reset` restores the `[proxy]` policy from `AGENTS.md` rather than emptying the rules, since an empty policy allows everything. The baseline denials are part of what it restores, so a reset cannot drop them either.

### Examples

```sh
agent-sandbox opencode                           # opencode, everything on
agent-sandbox opencode --no-ssh                  # drop an integration
agent-sandbox copilot                            # github-copilot-cli (copilot), everything on
agent-sandbox antigravity                        # antigravity-cli (agy), everything on
agent-sandbox opencode --no-workspace            # no CWD mount
agent-sandbox opencode --selinux                 # enable :z on built-in writable binds
agent-sandbox                                    # interactive bash (every agent's binary on PATH)
agent-sandbox opencode -- devenv shell           # devenv shell replacing opencode cmd
agent-sandbox --privileged opencode              # nested podman inside container
```

## Managing running sandboxes

`agent-sandbox-ctl` operates on the host, on sandboxes already running:

| Command | What it does |
| --- | --- |
| `load` | build the image and import it into podman |
| `list [-a] [--roles]` | running sandboxes and their proxy mode; `--roles` also shows sidecars and forwarders |
| `status [WORD] [--sandbox WORD]` | one screen per sandbox, pointing at the commands below |
| `net [-f] [WORD] [--sandbox WORD]` | connection summary, or a live feed |
| `logs [-f] [WORD] [--sandbox WORD]` | the proxy sidecar's log |
| `proxy show\|allow\|deny\|rm\|reset\|export [WORD] [--sandbox WORD]` | read and change the policy of a running sandbox; `export` prints its `[proxy]` section as AGENTS.md TOML |
| `ports ls\|add\|rm\|export [WORD] [--sandbox WORD]` | publish a port after launch (needs `--ports-dynamic`, and no proxy); `export` prints its `[ports]` section as AGENTS.md TOML |
| `mounts ls\|add\|rm\|export [WORD] [--sandbox WORD]` | inspect and manage bind mounts into a running sandbox |
| `attach [WORD] [-- CMD...]` | execute an interactive command inside a running sandbox |
| `purge [--all] [-n]` | reclaim leftovers; running sandboxes are kept unless `--all` |

New sandboxes are shown by a single session word, such as `silent`. Use that
word with any targetable command, either positionally or as `--sandbox silent`.
The full Podman name remains internal. If the same word is present on more than
one sandbox, the command refuses to guess and prints the matching workspaces and
full names. The word may be omitted when only one sandbox is running or when
exactly one matches the current directory.

For example:

```console
$ agent-sandbox-ctl status silent
$ agent-sandbox-ctl net --sandbox silent
$ agent-sandbox-ctl logs silent
$ agent-sandbox-ctl proxy show --sandbox silent
$ agent-sandbox-ctl ports ls silent
$ agent-sandbox-ctl mounts ls --sandbox silent
$ agent-sandbox-ctl attach silent -- bash
```

`purge` defaults to leftovers only: exited sandboxes, forwarders and sidecars
whose sandbox is gone, per-session networks nothing is attached to, and temp
directories from a launcher that was killed before it could clean up. `-n` shows
what it would remove.

## What's in the image

| Category      | Tools                                                |
| ------------- | ---------------------------------------------------- |
| AI coding     | opencode, claude-code, github-copilot-cli (copilot), antigravity-cli (agy) |
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

## How it works

1. `agent-sandbox-ctl load` imports the OCI image (built with `pkgs.dockerTools.streamLayeredImage`) into the host's podman image store.
2. `agent-sandbox` calls `podman run` with `--userns=keep-id`, tmpfs mounts for ephemeral home subdirectories, explicit bind mounts for the selected agent's persistent state (or more, via `--agent-mounts`), devenv, and forwarded sockets (ssh, gpg, podman).
3. A slim entrypoint loads the Nix store registration so `nix` commands work from the start, sets up the gpg-agent symlink when requested, then `exec`s the container command.

## Trust model

By design, `agent-sandbox` includes options that pierce the sandbox boundary. Note that these give any agent running inside the container capabilities on the host:
- `--ssh` (opt-in): The agent can authenticate as you using your forwarded SSH identity (e.g. `git push` to your repos).
- `--gpg` (opt-in): The agent can sign commits or authenticate with any key held by your host GnuPG agent. Note that `agent-sandbox` protects your private key files by checking for them and gracefully failing the GNUPG directory mount if they are present on disk, but the forwarded GnuPG agent socket is still accessible.
- `--podman` (opt-in): Forwards the host rootless podman socket. The agent can use this to launch **sibling containers** on the host, which is equivalent to a full sandbox escape (e.g. `podman run -v /:/host ...`).

#### Running Containers: `--podman` vs `--privileged`
If you want the agent to be able to run its own containers, `agent-sandbox` supports two distinct models:

1. **Nested Containers (Safe):** Pass `--privileged` when launching the sandbox. The sandbox image contains its own baked-in Podman stack. `--privileged` gives the sandbox container enough kernel permissions to run a securely isolated Podman daemon *inside* the sandbox. The agent cannot use this to escape to the host.
2. **Sibling Containers (Unsafe):** Pass `--podman` to forward your host's Podman socket into the sandbox. When the agent runs `podman run`, it talks to your host machine's Podman daemon. The container is created on the host alongside the sandbox. This does *not* require `--privileged`, but it allows the agent to control your host's containers and easily escape the sandbox. Use this only when you need the agent to interact with existing host infrastructure or leverage the host's image cache for performance.

<details>
<summary><strong>A guest kernel: --krun</strong> — full trust-model detail (expand for the boundary diagram and complete analysis)</summary>

#### A guest kernel: `--krun`

`--krun` runs the sandbox as a KVM microVM. The boundary it adds is **additive, not substitutive** — this is the whole of what it is for, and it is easy to overstate.

libkrun's own security model is explicit that the guest and the VMM are one security context, and that containment must come from the host's mechanisms: namespaces. Under podman that context already exists and is exactly the one the sandbox has without the flag. So the boundaries sit in series:

```
agent process
  │  ← guest kernel (libkrunfw), reachable only through virtio + KVM ioctls
VMM (the sandbox container process)
  │  ← rootless userns + mount ns + netns + seccomp   ← what you already had
host
```

A guest-kernel privilege escalation lands the attacker as your unprivileged uid inside the same container the agent started in, facing the boundary that was always there.

What it closes: host-kernel privilege escalation from code the agent runs. That is the entire gain.

What it does **not** close:

- **None of the three flags above.** `--ssh` and `--gpg` hand out host capabilities; forwarding them into a VM forwards them into a VM. (`--podman` is refused outright under `--krun`.)
- **Nothing on egress.** The proxy topology, the policy file and the connection log are unchanged. Networking uses libkrun's Transparent Socket Impersonation, where the guest has no virtual NIC and the VMM performs its `connect()` calls — inside the same `--internal` network namespace, which has no route out. The firewall neither widens nor narrows.
- **Nothing on the workspace.** With `--workspace` the agent can write to your git repository, and code it plants there runs on your host later, as you, outside every boundary described here. For a careless or prompt-injected coding agent this is the operative risk, and no hypervisor addresses it.
- **Nothing against a podman, netns or userns misconfiguration**, since the VMM sits inside that same configuration.

Two things it changes that are easy to miss, both measured rather than assumed (`lib/smoke-krun.sh`):

- **The agent is `uid 0` inside the guest.** `--userns=keep-id` maps the *VMM process* on the host; it does not reach the guest's own user namespace, so a process that is unprivileged uid 33500 in an ordinary sandbox is root in a `--krun` one. This is not an escalation on the host — files the guest writes still land as your uid, because the VMM performs the write — but "the agent runs unprivileged" stops being true inside the boundary, and anything relying on in-container uid separation should not.
- **SELinux confinement of the sandbox process is off.** `--krun` runs the sandbox with `--security-opt label=disable`, because the kernel refuses an SELinux domain transition once a process is multi-threaded and libkrun has already spawned the VM's threads by then. With labeling left on, the guest does not boot at all on an enforcing host. `--selinux` still relabels the bind mounts (`:z`). On an SELinux host, `--krun` therefore trades SELinux confinement of the sandbox process for a guest kernel under the agent.

Nested podman inside a `--krun` guest does not work out of the box, despite `--privileged`. The guest kernel has both `overlay` and `fuse`, so the obstacle is not kernel capability: podman sees uid 0, defaults its storage to `/var/lib/containers`, and virtio-fs declines to create that because the VMM writes as your unprivileged host uid. Pointing podman's graphroot somewhere under `/home/user` is the missing piece.

It is opt-in and should stay that way. The honest reasons to reach for it are running genuinely untrusted code, and nested `--privileged` workloads — and the second of those is currently unfinished, per the paragraph above.

</details>
