# Configuration

`AGENTS.md` in the root of a project can contain a fenced code block tagged `agent-sandbox` with TOML configuration. The launcher reads it when starting the sandbox and uses it to expose ports, bind host paths, and enforce a network firewall policy. Network policies can also be kept as reusable host-owned profiles.

Configurations must be written in TOML and placed inside a fenced code block tagged with `agent-sandbox`:

````markdown
```toml agent-sandbox
# Configuration goes here
```
````

The launcher parses this configuration when starting the sandbox environment.

## Supported Tables

The following top-level tables are supported:

### 1. `[ports]`

The `[ports]` table is used to declare container ports that should be published to the host, equivalent to Podman's `--publish` (`-p`) flag.

Each entry is a key-value pair where the key is the mapping name. The value can either be an integer (the container port) or a table with the following fields:

- **`container`** (required): The port inside the container (1-65535).
- **`host`** (optional): The port on the host to bind to. Defaults to the `container` port. If set to `0`, the launcher will dynamically allocate a free host port.
- **`bind`** (optional): The IP address on the host to bind to, or `"localhost"`. Defaults to `127.0.0.1`. Note: Binding to an interface other than loopback requires the launcher to be run with `--ports-any-interface`.
- **`protocol`** (optional): The protocol to use, either `"tcp"` or `"udp"`. Defaults to `"tcp"`.

#### Examples

````markdown
```toml agent-sandbox
[ports]
# Simple mapping: host 3000 -> container 3000 (binds to 127.0.0.1)
web = 3000

# Advanced mappings using tables
api = { container = 8080, host = 18080 }
db  = { container = 5432, host = 0 } # 0 means allocate a free host port dynamically
dns = { container = 53, protocol = "udp", bind = "0.0.0.0" }
```
````

#### Who reads this block

The launcher publishes these ports only when it is given `--ports`; without it
the declaration is inert.

[`agent-sandbox browser`](browser.md)
reads the same block whether or not `--ports` was passed, and allows each
loopback-bound entry — as `127.0.0.1:<host>` and as `localhost:<host>` — in the
browser's own deny-by-default policy, so the app under test loads without
naming its port a second time under `[network]`. A `host = 0` entry is
allocated at launch and cannot be allowed ahead of time; give it a fixed host
port if a browser needs to reach it.

### 2. `[mounts]`

The `[mounts]` table allows you to bind mount paths from the host into the sandbox container. 

Each key represents the source path (which can be absolute or relative to the workspace directory). The value can be a string representing the destination path inside the container, or a table with additional options.

Fields when using a table:

- **`destination`** (required): The absolute path inside the container.
- **`options`** (optional): A string or list of strings representing mount options (e.g., `"ro"`, `"rw"`, `"Z"`).

#### Examples

````markdown
```toml agent-sandbox
[mounts]
# Simple source -> destination mapping
"data" = "/workspace/data"

# Advanced mapping with options
"cache" = { destination = "/tmp/cache", options = "ro" }
"logs" = { destination = "/var/log/app", options = ["rw", "Z"] }
```
````

### 3. `[network]`

The `[network]` table configures the egress proxy's firewall policy. The sandbox is **deny-by-default**, meaning all traffic is blocked unless explicitly allowed.

- **`allowed_hosts`** (optional): A list of IP addresses, CIDR blocks, or domains, each with the port it may be reached on (e.g., `"github.com:443"`, `"10.0.0.0/8:80"`). Wildcard domains (e.g., `"*.github.com:443"`) are supported. To allow all traffic (wildcard allow), you can use `"*"` or `"*:port"`.

  An entry may omit the port (`"github.com"`), in which case the built-in
  default ports **80, 443 and 22** apply to it — not every port. Write the
  port explicitly for anything else; a rule that carries one is matched on
  that port alone.

  The port may also be a range or a comma-separated list of ports and ranges:
  `"github.com:22,443"` and `"internal.example.com:8000-8100,9000"` are both
  one entry. Writing them as separate entries works identically — the proxy
  unions the ports of every rule sharing a pattern — so the list is a
  convenience, not a different semantics.

An `allowed_hosts` entry covering port `22` is what authorizes the SSH relay for that
host. Under `--proxy` the host agent sockets are held by the proxy sidecar
rather than mounted into the sandbox, and the relay refuses every SSH request
until a matching entry exists — so `"github.com:22"` is what makes `git push`
work in a proxied sandbox. Commit signing is separate: it needs no network
declaration at all, since GPG has no destination of its own — `--gpg` alone is
sufficient, in a proxied sandbox exactly as in an unproxied one. See
[Usage](usage.md#git-integration-details).

#### L7 HTTP Rules (`[[network.allowed_routes]]`)

For finer-grained HTTP proxy control and secret injection, you can specify an array of tables under `[[network.allowed_routes]]`.

- **`host`** (required): The target host and port to match (e.g., `"api.github.com:443"`).
- **`method`** (required): The HTTP method (e.g., `"GET"`, `"POST"`, or `"*"`) in uppercase.
- **`path`** (required): The path pattern to match (must start with `/`). `*` matches a single
  segment, `**` matches several.
- **`secret`** (optional): The name of a secret to inject into requests matching **this rule**.
- **`header`** (optional): The HTTP header to inject the secret into (e.g., `"Authorization"`).
- **`prefix`** (optional): An optional prefix for the secret value (e.g., `"Bearer "` ).

A host may carry several rules, and `secret` binds to the rule it is written on —
not to the host. Only requests matching that rule's method and path receive the
header; every other rule on the same host is proxied without it. Matching uses the
normalised path, so `..` segments and percent-encoding cannot carry a secret off
its route.

#### Examples

````markdown
```toml agent-sandbox
[network]
allowed_hosts = [
    "github.com:443",
    "*.pypi.org:443",
    "10.0.0.0/8:80"
]

# Allow GET requests to specific GitHub API endpoints and inject a secret token
[[network.allowed_routes]]
host = "api.github.com:443"
method = "GET"
path = "/user/repos"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "

[[network.allowed_routes]]
host = "registry.npmjs.org:443"
method = "*"
path = "/"
```
````

#### The trusted config

`AGENTS.md` is part of the repository and is therefore treated as untrusted: it
may *name* a host, but it may not decide what is trusted about that host.
Anything in that category is authorized in a file only you write,
`~/.config/agent-sandbox/trusted.toml` (or under `$XDG_CONFIG_HOME`). Profile
rules go through the same check.

Two things live under that rule, and both work the same way — the launcher
prints the exact block to paste, and refuses the launch rather than proceeding
unauthorized:

| Declared in `AGENTS.md` | Authorized in `trusted.toml` |
| --- | --- |
| `[[network.allowed_routes]]` with a `secret` | the identical `[[network.allowed_routes]]` block |
| an `allowed_hosts` entry covering port 22 | a `[[network.known_hosts]]` entry for that host |

#### Secrets

A rule's `secret` names a secret, never its value. The launcher will only
inject a secret you have also authorized host-side.

**Copy the block verbatim.** Authorization matches on every field — `host`
(including its port), `method`, `path`, `secret`, `header` and `prefix` — so
the host-side entry is the `AGENTS.md` rule with nothing changed:

```toml
# ~/.config/agent-sandbox/trusted.toml
[[network.allowed_routes]]
host = "api.github.com:443"
method = "GET"
path = "/user/repos"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "
```

Omitting a field does not make it a wildcard: `method` defaults to `"GET"`,
`path` to `"/"` and `header` to `"Authorization"`, and those defaults are then
matched exactly. An entry without the port authorizes nothing for a rule that
has one.

The authorization is what scopes the injection. The secret reaches the proxy
bound to that host, method and path, and is injected only into requests matching
it — so a second `[[network.allowed_routes]]` entry in `AGENTS.md`, on the same host and
without a `secret`, grants plain access and nothing more. You can authorize
several routes on one host; where two of them could match the same request, the
more specific wins (longest domain pattern, then longest path pattern, then an
exact method over `*`).

With `--secrets`, values are resolved on the host with
[`secretspec`](https://secretspec.dev) (from the workspace's `secretspec.toml`)
and handed to the proxy sidecar alone; they never enter the sandbox's
environment. A rule that the selected network sources request but the host config does not
authorize refuses the launch rather than silently injecting nothing, and prints
the exact block to paste. The proxy terminates TLS for hosts carrying a rule, so
the sandbox trusts a per-session CA that exists only for the lifetime of that
sandbox.

#### SSH host keys

An `allowed_hosts` entry covering port 22 authorizes SSH to that host — it is
what makes `git push` work in a proxied sandbox. Which host key is trusted for
it is a separate decision, and a host-side one:

```toml
# ~/.config/agent-sandbox/trusted.toml
[[network.known_hosts]]
host = "github.com:22"
key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
```

`key` is a `known_hosts` key — the type and the base64, without the leading
host, which comes from `host`. Repeat the block for a host's other key types.
A fingerprint is not a key: use one to *verify* what you paste, not in its
place.

Declare `"github.com:22"` with no matching entry and the launch refuses, naming
the host and printing the block to add. For the common forges the key is filled
in for you; for anything else, get it with `ssh-keyscan` **on the host** and
check the result against a fingerprint you already trust — `ssh-keyscan` asks
the server who it is, so it cannot tell you the answer is wrong.

The port matters here as it does everywhere else. An entry for
`"git.example.com:2222"` is what `ssh -p 2222` needs, and it is not
authorization for a connection to port 22.

Under `--proxy` the authorized set is the whole trusted set: the keys are bound
into the sandbox and the sidecar at launch, and nothing running can add to them.
`agent-sandbox ctl proxy allow HOST:22` and the TUI's `a` therefore say so when
they authorize a host you have no key for — the rule takes effect, and SSH to it
will fail host-key verification until you add one and relaunch.

#### Rules the launcher refuses

`[network]` is validated before the sandbox starts; an invalid block refuses the
launch rather than starting with a policy that allows more than you wrote.
Besides malformed values, these combinations are rejected:

- an unknown key under `[network]` (only `allowed_hosts` and `allowed_routes` exist) or an unknown
  field on a rule;
- a duplicate entry in `allowed_hosts`;
- a host allowed outright in `allowed_hosts` that also carries a `[[network.allowed_routes]]`
  entry *without* a secret — the broad allow makes the narrower rule pointless,
  so one of the two is a mistake. The same applies to a wildcard allow (`"*"`,
  `"*:port"`);
- an `allowed_hosts` entry covering port 22 for a host with no
  `[[network.known_hosts]]` entry in `trusted.toml` — SSH would be authorized to
  a host whose identity nothing has vouched for.

There is no `deny` key. The firewall is deny-by-default, and the only deny rules
a policy carries are the built-in private and loopback ranges the launcher adds
to every session. See [Trust model](trust-model.md).

## Reusable Network Profiles

Profiles are explicit, host-owned network policies stored under:

```text
$XDG_CONFIG_HOME/agent-sandbox/profiles/<name>.toml
```

When `XDG_CONFIG_HOME` is unset, the default location is:

```text
~/.config/agent-sandbox/profiles/<name>.toml
```

Profile files are plain TOML and contain only a `[network]` table. They use the
same `allowed_hosts` and `[[network.allowed_routes]]` syntax as `AGENTS.md`:

```toml
[network]
allowed_hosts = ["github.com:443", "registry.npmjs.org:443"]
```

`--proxy-profile NAME` implies `--proxy` and uses the selected profile instead
of the workspace `AGENTS.md` network block. Supplying both `--proxy` and
`--proxy-profile` merges the sources additively. The option may be repeated and
profiles are never loaded implicitly. Invalid or missing profiles refuse the
launch before the sidecar starts.

The same profiles are taken by
[`agent-sandbox browser`](browser.md)
via its own `--proxy-profile`, so one allow list can serve both a sandbox and
the browser testing it. They stay separate policies — selecting a profile for
one does not select it for the other.

Live rules added during a session are not written back automatically. The exit
summary prints a TOML block that can be added to `AGENTS.md` for project-specific
access or merged into a profile for reuse.
