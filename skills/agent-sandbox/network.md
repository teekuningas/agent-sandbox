# The sandbox firewall

Read `SKILL.md` first. Everything here applies to a **proxied session** — one
where `$HTTP_PROXY` is set. Without it there is no firewall and none of this is
relevant.

## Before you start

- **There is no `deny` key and no `ctl proxy deny`.** The firewall is
  deny-by-default already; denying something already denied is a no-op.
- **Ports matter.** `"github.com:443"` is not the same as `"github.com"` —
  the latter falls back to just 80/443/22.
- **Most changes are live** (`ctl proxy allow/rm/reset`, `ctl mounts`); an L7
  route needing TLS interception, `[ports]`, `--secrets`, and any launch flag
  need a **relaunch** — see the table near the bottom before promising either.
- **Don't propose `"*"` or a bare `"*:443"`** to work around one missing
  host — ask for the narrowest rule that unblocks the task.

## Topology

```
your process ──► sidecar proxy :8888 ──► the internet
                 relay        :8889 ──► host ssh-agent / gpg-agent
```

The sandbox is on a Podman `--internal` network: no route to the outside, and
DNS is disabled on it. Nothing reaches the network except through the proxy, and
the proxy decides per connection against a deny-by-default policy.

That is also why a forwarded SSH or GPG socket is *not* mounted into a proxied
sandbox — a socket is a capability that would bypass the firewall entirely. The
agent sockets stay with the sidecar. `relay-ssh` reaches the SSH socket only for
hosts the policy authorizes; `relay-gpg` needs no host at all — gpg has no
destination of its own, so signing is gated by `--gpg` alone.

Two consequences worth internalizing:

- A tool that ignores `$HTTP_PROXY` and opens its own socket fails, and usually
  reports it as a DNS error. That is the firewall, not a broken resolver.
- The entrypoint compensates for the common cases: it writes an `~/.ssh/config`
  that routes SSH through the proxy and sets `NODE_USE_ENV_PROXY=1` for Node.
  Anything else with its own HTTP stack may need `--proxy`-style flags of its own.

The firewall governs *egress*, not the sandbox's own loopback. A server you
start here stays reachable at `localhost` — `$NO_PROXY` carries
`localhost,127.0.0.1,::1` so proxy-aware clients dial it directly instead of
asking the sidecar, which would refuse it as a denied address. If some client
ignores `$NO_PROXY` and returns a bodiless `403` for a local URL, that is the
cause; point it at `127.0.0.1` or set its own no-proxy option.

## Reaching a published port from the host

A proxied session can publish ports: `[ports]` entries bound to loopback work
under `--proxy`, because publishing is ingress and the firewall governs egress.
(A bind the wider network can reach is refused, as is a raw `-p` through
`--podman-args` — the launcher cannot check that one's bind address.)

**A server behind a `[ports]` mapping must bind `0.0.0.0`, not `127.0.0.1`.**
Publishing forwards the host's port to the sandbox's *interface* address, so a
server bound to loopback is listening where nothing is delivered: `curl
localhost:PORT` from inside the sandbox works, and the user gets connection
refused from the host. Nothing in the sandbox reports this, so when a user says
a published port is dead, check the bind address first — most dev servers
default to loopback and need to be told otherwise (`--host 0.0.0.0`,
`--bind 0.0.0.0`, `HOST=0.0.0.0`, `app.run(host="0.0.0.0")`).

## Reaching a service on the host

The other direction is opt-in per port. `$AGENT_SANDBOX_HOST_PORTS` lists the
ports the user mapped with `--host-loopback-port`; each is reachable at the
sandbox's own `127.0.0.1:PORT`. The variable is absent when nothing was mapped,
which is the normal case — read it rather than probing, so "not mapped" stays
distinguishable from "not running".

If you need one that is not listed, ask the user to relaunch with
`agent-sandbox --host-loopback-port PORT`; it cannot be turned on in a running
session. Note that this works under `--proxy` and that what it reaches is *not*
covered by the egress policy — so it is not a way around a denied host. For that
the answer is still `ctl proxy allow`.

## Where the policy comes from

| Launch flags | Policy |
| --- | --- |
| `--proxy` | the workspace `AGENTS.md` only |
| `--proxy-profile NAME` | `~/.config/agent-sandbox/profiles/NAME.toml` only; implies `--proxy` |
| both | merged additively |

Profiles are host-owned and never loaded implicitly; `AGENTS.md` is
project-controlled and therefore untrusted. Neither can express a deny — the
firewall is deny-by-default and the only deny rules are the built-in private and
loopback ranges.

## Writing a policy block

`AGENTS.md` configuration lives in a fenced block tagged `agent-sandbox`:

````markdown
```toml agent-sandbox
[network]
allowed_hosts = [
  "github.com:22",
  "github.com:443",
  "*.githubusercontent.com:443",
  "registry.npmjs.org:443",
  "cache.nixos.org:443",
]
```
````

Semantics that decide whether a rule works:

- **Ports matter.** `"github.com:443"` allows that port only. An entry with no
  port (`"github.com"`) falls back to the built-in defaults 80, 443 and 22 — not
  every port. A range or comma-separated list is one entry:
  `"github.com:22,443"`, `"internal:8000-8100,9000"`.
- **`:22` does double duty.** It also authorizes the SSH relay for that host,
  which is what makes `git push` work in a proxied session. Any element
  covering 22 counts, so `"github.com:22,443"` authorizes the relay too. With
  no such entry the relay refuses SSH. Commit signing is separate: it needs no
  `:22` entry, only a session launched with `--gpg`.
- **`:22` also needs a host key the user authorized.** The launch refuses
  outright unless `~/.config/agent-sandbox/trusted.toml` carries a
  `[[network.known_hosts]]` entry for that host. You cannot write that file —
  it is host-owned, and the refusal prints the exact block. If you propose a
  `:22` entry, say that the user will need to paste that block too.
- **Wildcards.** `*.github.com:443` covers subdomains *and* the apex;
  `github.com:443` covers the apex only, never `status.github.com`. Matching is
  case-insensitive.
- **`"*"` or `"*:443"`** allows everything at that port. Do not propose this to
  work around a single missing host.

### L7 routes

`[[network.allowed_routes]]` restricts an HTTPS host by method and path, and is
also how a secret is bound to a route:

```toml
[[network.allowed_routes]]
host = "api.github.com:443"
method = "GET"
path = "/repos/**"
secret = "GITHUB_TOKEN"      # optional; see secretspec.md
header = "Authorization"     # optional
prefix = "Bearer "           # optional
```

`*` matches one path segment, `**` matches several. A host carrying any L7 rule
is **TLS-terminated** by the proxy so it can see the method and path; hosts
without one stay an opaque `CONNECT` tunnel. That interception is why an L7 rule
added mid-session produces certificate errors — the session CA is mounted at
launch, so a live-added route has nothing behind it.

### Combinations the launcher refuses

An invalid policy refuses the launch outright, so a bad suggestion costs the user
a full relaunch. These are rejected (messages quoted from the parser):

- unknown key: `[network]: unknown key 'deny'. Valid keys under [network] are
  'allowed_hosts' and 'allowed_routes'`
- duplicate entry: `allowed_hosts: duplicate entry 'github.com:443'`
- a broadly-allowed host that also carries a secretless route:
  `host 'api.github.com:443' is allowed broadly, making the non-secret
  [[network.allowed_routes]] ineffective. Remove the rule or add a secret.`

There is no `deny` key and no `ctl proxy deny` — denying something already denied
is a no-op.

## The loop the user drives

All of this runs on the host, in another terminal:

```sh
agent-sandbox ctl tui                       # live denials, approve interactively
agent-sandbox ctl proxy allow HOST:PORT     # allow, immediately
agent-sandbox ctl proxy show                # the effective policy
agent-sandbox ctl proxy check HOST:PORT     # dry-run a target
agent-sandbox ctl proxy export >> AGENTS.md # persist the session's policy
agent-sandbox ctl net                       # per-host traffic summary
agent-sandbox ctl logs -f                   # the proxy's log, denials as they happen
agent-sandbox ctl relay                     # what the SSH/GPG relay allowed or refused
```

In the TUI: `a` allow domain, `h` allow HTTP route, `A` allow IP, `v` connections
view, `r` rules view (`x` removes), `d` details, `c` clear, `q` quit.

The denied list also carries the **relay's** refusals, which the proxy never
sees: an SSH destination the policy did not authorize shows as method `SSH` on
port 22, and `a` writes both the `allow_signing` entry the relay reads and the
`:22` host rule the exit summary renders back as TOML. A refused `gpg` call is
shown read-only — signing comes from `--gpg` at launch, and no rule grants it.

For a host denied at `CONNECT`, the encrypted method and path are not visible
yet. The documented trick is a placeholder route that makes the proxy terminate
TLS so the real request becomes observable:

```toml
[[network.allowed_routes]]
host = "pypi.org:443"
method = "GET"
path = "/noop"
```

Retry, read the resulting L7 denial, then replace `/noop` with the real path.

**Your contribution to this loop** is precision: the exact `host:port` values you
need and why each is needed. You cannot read the log, the summary or the TUI from
inside — if you need to know what was denied, ask the user to run `ctl logs` or
`ctl net` and paste it.

## Live versus relaunch

| Change | Applies |
| --- | --- |
| `ctl proxy allow` / `rm` / `reset` | live, immediately |
| SSH relay authorization (`ctl proxy allow <host>:22`) | live — the relay re-reads the policy on every call |
| `ctl mounts add` / `rm` | live (not under `--krun`) |
| A new L7 route needing TLS interception | **relaunch** (session CA is mounted at launch) |
| `[ports]` | **relaunch** |
| `--secrets` and any secret binding | **relaunch** |
| Any flag: `--ssh`, `--gpg`, `--workspace`, `--nix`, `--podman`, `--privileged` | **relaunch** |
| Edits to `AGENTS.md` | **relaunch** |

Say which of the two a request needs. Asking a user to relaunch when
`ctl proxy allow` would have done it wastes their session; the reverse leaves
them with certificate errors.

## Diagnosing from inside

```sh
env | grep -i proxy                      # proxied or not
curl -sv https://example.com 2>&1 | head # 403 with no body = policy denial
curl -sv --noproxy '*' https://example.com 2>&1 | head   # confirms there is no direct route
```

A `403` from the proxy carries no body and no explanation by design — the reason
is recorded host-side. Do not retry it in a loop; it will not change until the
policy does.
