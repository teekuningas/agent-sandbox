# Usage

`agent-sandbox` launches AI coding agents inside an isolated Podman container. All integrations — filesystem access, network, SSH keys, GPG — are **opt-in**. Run it with no flags to get a shell where nothing from your host is exposed.

### Examples

```sh
agent-sandbox opencode                           # opencode, no integrations (all opt-in)
agent-sandbox --workspace --ssh opencode         # opt in to workspace and SSH
agent-sandbox --workspace --proxy opencode       # workspace + deny-by-default network firewall
agent-sandbox --workspace --ssh opencode --no-ssh  # override: drop SSH back out
agent-sandbox copilot                            # github-copilot-cli (copilot)
agent-sandbox antigravity                        # antigravity-cli (agy)
agent-sandbox codex                              # codex
agent-sandbox opencode --selinux                 # enable :z on built-in writable binds
agent-sandbox                                    # interactive bash (every agent's binary on PATH)
agent-sandbox opencode -- devenv shell           # devenv shell replacing opencode cmd
agent-sandbox --privileged opencode              # nested podman inside container
```

### Override the container command

Everything after the `--` sentinel replaces the default command:

```sh
agent-sandbox                                    # interactive shell (every agent's binary on PATH)
agent-sandbox -- bash -c "nix build .# && echo done"
agent-sandbox opencode -- devenv shell           # devenv shell with opencode default cmd replaced
```

### Pass podman flags

To pass arguments directly to podman, use `--podman-args`. All arguments after `--podman-args` will be passed to podman until a `--` sentinel is reached, which marks the start of the container command.

There are also convenient shortcuts like `--privileged` and `-e` for common podman flags.

```sh
agent-sandbox --privileged opencode               # enable nested podman
agent-sandbox --podman-args --network=host -- bash # host network
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

### Flags

Most flags in the table below have a corresponding `--no-flag` option (e.g., `--no-workspace`) to explicitly disable it — the exceptions are the ones taking a value (`--proxy-profile`, `--krun-memory`, `--krun-cpus`) and `--ports-any-interface`. A `--no-proxy` after `--proxy-profile` still turns the proxy off, dropping the profiles with it. Since arguments are evaluated sequentially, passing `--ssh` followed by `--no-ssh` will leave the feature disabled. This is how user-provided command line arguments can override defaults built into the script via `wrapProgram`.

`--gpg-agent` and `--gpg-sign` were merged and removed; use `--gpg` / `--no-gpg`.

| Group | Flag | What it does |
| --- | --- | --- |
| Workspace & identity | `--workspace` | Mounts the host's current working directory into `/workspace/<dirname>`. |
| Workspace & identity | `--ssh` | Forwards the host's `SSH_AUTH_SOCK` to the container and pre-populates `known_hosts`. |
| Workspace & identity | `--git` | Passes host Git configurations (with a blocklist) and identity env vars. |
| Workspace & identity | `--gpg` | Enables host GnuPG agent forwarding and git commit signing behavior. |
| Workspace & identity | `--gpg-private` | Exposes `~/.gnupg` even if it holds on-disk secret keys. |
| Workspace & identity | `--devenv` | Persists `~/.local/share/devenv` across sessions. |
| Workspace & identity | `--nix` | Mounts the host `/nix/store` for native Nix execution. |
| Container runtime | `--podman` | Forwards the host rootless Podman socket (sibling containers). See [Trust model](trust-model.md). |
| Container runtime | `--selinux` | Applies SELinux shared relabeling (`:z`) to writable binds in the sandbox container. |
| Container runtime | `--krun` | Runs the sandbox as a KVM microVM with its own kernel, using `podman --runtime krun`. See [Trust model](trust-model.md). |
| Container runtime | `--krun-memory MiB` | Guest RAM (default `4096`). Values of 128 or below are rejected. |
| Container runtime | `--krun-cpus N` | Guest vCPUs (1–16). Defaults to the host CPU affinity count. |
| Network & firewall | `--proxy` | Isolates the container from the internet and routes HTTP(S)/SSH through a proxy that enforces the workspace `AGENTS.md` `[network]` policy only. Prints a per-host traffic summary when the session ends. See details below. |
| Network & firewall | `--proxy-profile NAME` | Uses a host-owned reusable profile from `~/.config/agent-sandbox/profiles/NAME.toml` instead of `AGENTS.md`; implies `--proxy` and may be repeated. Combine with `--proxy` to merge both sources. |
| Network & firewall | `--secrets` | Uses `secretspec` to resolve and inject HTTP headers (e.g., `Authorization`) into the proxied requests each `[[network.allowed_routes]]` rule authorises — that rule's host, method and path, and no others. Requires `--proxy`. See [Configuration](configuration.md#secrets). |
| Ports & mounts | `--ports` | Honors `[ports]` declarations from `AGENTS.md`. |
| Ports & mounts | `--ports-any-interface` | Permits port binds outside of loopback interfaces. |
| Ports & mounts | `--shared-network` | Joins the shared bridge network so other containers can reach this one by name. See below. |
| Ports & mounts | `--browser` | Attaches every browser `agent-sandbox browser` is running: maps each of their CDP ports and tells the agent which is which. `--browser=alice,bob` picks some of them. See [Cooperative Browser](browser.md). |
| Ports & mounts | `--host-loopback-port PORT` | Makes the host's `127.0.0.1:PORT` reachable at the sandbox's own `127.0.0.1:PORT`, and exports the list as `$AGENT_SANDBOX_HOST_PORTS`. Repeatable; takes `HOST:SANDBOX`. See below. |
| Ports & mounts | `--mounts` | Honors `[mounts]` declarations from `AGENTS.md`. |
| Ports & mounts | `--agent-mounts` | Mounts every known agent's state; `--agent-mounts=a,b` mounts just those (plus any launched agent). |

A few flags are one-off pass-throughs rather than persistent toggles, so they have no `--no-flag` form:

| Flag | What it does |
| --- | --- |
| `-e NAME=VAL`, `--env NAME=VAL` | Injects an environment variable. |
| `--privileged` | Enables nested podman inside the sandbox (safe — see [Trust model](trust-model.md)). |
| `--proxy-log off\|denied\|all` | What to do with the proxy's connection log when the session ends; implies `--proxy`. Unset, a session that had denials offers to save one. See [Trust model](trust-model.md). |
| `--podman-args ... --` | Passes arguments straight through to `podman` until the `--` sentinel (including `-v/--volume` and `-p/--publish`). |

There is no `--port` flag: declare ports in `AGENTS.md` and pass `--ports`, or
publish one directly with `--podman-args -p HOST:CONTAINER --`. Prefer
`--ports`: it defaults each bind to loopback and refuses a wider one unless
`--ports-any-interface` is given, while a raw `-p HOST:CONTAINER` binds
`0.0.0.0` and exposes the port to the LAN.

`--ports` composes with `--proxy` as long as every bind is loopback. Publishing
is ingress — podman forwards into the proxy's internal network without giving
the sandbox a route out of it — so the egress policy is untouched. A bind the
rest of the network can reach is refused under `--proxy`, because anything out
there could pull whatever the agent chose to serve and the proxy would never see
it. A raw `-p` is refused under `--proxy` too: the launcher never parses it, so
it cannot tell the two cases apart.

Whichever you use, the server *inside* the sandbox must bind `0.0.0.0`.
Publishing forwards to the sandbox's interface address, so a server bound to the
sandbox's own `127.0.0.1` answers from inside and refuses from the host.

## Reaching back to the host: `--host-loopback-port`

Publishing sends bytes one way. To reach a service the *user* runs on the host —
a browser's CDP port, say (see the `browser` skill) — name its port:

```sh
agent-sandbox --host-loopback-port 9222 -- bash
```

The host's `127.0.0.1:9222` is then reachable at the sandbox's own
`127.0.0.1:9222`. Nothing else on the host's loopback is, which is the point:
only the ports you name.

This is not on by default and there is no way to get it implicitly. Podman
passes pasta `--no-map-gw`, and the `host.containers.internal` entry it does set
up points at the host's *LAN* address, not its loopback, so it does not reach a
loopback-bound service either.

The flag is a bind-mounted unix socket with the launcher splicing each connection
to the host, **not** a route. That is why it composes with every network mode,
`--proxy` included — a route would have to be a network mode, and the sandbox's
is always already spoken for. It is TCP only.

The sandbox gets the mapped ports as `$AGENT_SANDBOX_HOST_PORTS`, so an agent
inside can test for the channel instead of learning it is missing from a refused
connection. Repeat the flag for more than one, and use `HOST:SANDBOX` when the
sandbox already has something on that number:

```sh
agent-sandbox --host-loopback-port 9222 --host-loopback-port 5432:15432 -- bash
```

!!! warning "This is a capability, not a convenience"
    Under `--proxy` a mapped port is a channel the sidecar never sees. What is
    listening on it fetches on its own account: a CDP port in particular hands
    the agent a fully-privileged, cookie-bearing browser on the host, so the
    egress policy no longer bounds what can be fetched. That is deliberate and
    opt-in — but only for the ports you named. See [Trust model](trust-model.md).

## A cooperative browser: `agent-sandbox browser`

Handing an agent a CDP port is a capability, not a convenience (see the
warning above). `agent-sandbox browser` starts a Chromium behind its own
deny-by-default allow list, seeded from `AGENTS.md`'s `[ports]` block, then
`--browser` attaches it to the sandbox:

```sh
agent-sandbox browser                            # start an allow-listed browser
agent-sandbox --workspace --browser -- claude    # attach it to the sandbox
```

See [Cooperative Browser](browser.md) for multi-user sessions, extensions,
CDP wiring, and the two-layer security model.

### Building a policy interactively

When starting a sandbox on a new codebase or with an unknown set of dependencies, you can build the proxy policy as you go:

1. **Start the Sandbox**: Run `agent-sandbox --proxy`. With no `[network]` block yet, requests are recorded and the ones that do not match a rule are denied.
2. **Open the TUI**: In a **separate terminal**, run `agent-sandbox ctl tui`. This interactive interface lists the requests the sandbox is making, including the denied ones.
3. **Approve**: Use the following keybindings to update the policy in real time:
   - `a`: Allow domain — or, on an SSH row, authorize the relay for that host
   - `h`: Allow HTTP route (domain + method) (creates a `[[network.allowed_routes]]` rule)
   - `A`: Allow IP
   - `v`: Switch between the live Connections view and denied requests
   - `r`: Switch to the Rules view — the live effective policy, with `x` to remove a rule (blocked for rules that came from `AGENTS.md`)
   - `d`: Show sanitized details for the selected row, in the denied-requests view or the Connections view; use `↑`/`↓` to scroll and `Esc` to return
   - `c`: Clear the list of recorded denials
   - `q` or `Esc`: Quit the TUI
   - `Ctrl+C`: Quit the TUI — press twice within 2 seconds to confirm (a single press only shows a warning); also handles an external SIGINT sent to the process
4. **Save Rules**: When you've trained the proxy to your liking, export the complete active policy — the original `AGENTS.md` rules plus the live additions — with `agent-sandbox ctl proxy export`. It prints a fenced ```` ```toml agent-sandbox ```` block, which is the form the launcher reads, so append it to the project's `AGENTS.md` (`agent-sandbox ctl proxy export >> AGENTS.md`) and delete the `[network]` block it supersedes. Redirect with a single `>` only into a scratch file: it would truncate `AGENTS.md`, prose and all. For reusable rules, `agent-sandbox ctl proxy export --plain` prints the same policy without the Markdown fence — that is what a `~/.config/agent-sandbox/profiles/<name>.toml` file wants, launched with `--proxy-profile <name>`. When the sandbox exits, its summary also prints only the rules added live as copy-pasteable `allowed_hosts` and `[[network.allowed_routes]]` TOML.

The proxy source is selected explicitly:

| Flags | Network policy |
| --- | --- |
| `--proxy` | The workspace `AGENTS.md` only |
| `--proxy-profile development` | The named host-owned profile only; profile selection implies `--proxy` |
| `--proxy --proxy-profile development` | The profile and `AGENTS.md`, merged additively |

`--proxy-profile` may be repeated. Profiles are never loaded implicitly. Profile files are plain TOML and use the same declarative `[network]` syntax as `AGENTS.md`:

```toml
[network]
allowed_hosts = ["github.com:443", "registry.npmjs.org:443"]
```

At session exit, rules added live through the TUI or `agent-sandbox ctl proxy allow` are printed as a TOML block. Add that block to `AGENTS.md` for project-specific persistence, or merge it into a profile for reuse across projects.

The TUI tails the connection log and shows recently-denied hosts live (deduplicated, with a repeat count and the specific reason the policy denied them), so you can add the missing rule without leaving the dashboard. Press `v` to switch to the Connections view, which shows all recent allowed, denied, failed, and currently-open connections live. Press `d` on a row in either view to inspect it: the denied-requests view shows the latest sanitized request head — method, target, path, and non-sensitive headers — and the Connections view shows the row's own verdict, timings and byte counts, followed by that head when one was recorded for the destination. Request heads exist for denials only; an allowed HTTPS tunnel is never decrypted unless a route or secret rule covers it, and the detail pane says so rather than showing an empty box. The detail stream is ephemeral, capped at 4 MiB, and the TUI retains at most 200 rows in each view with one bounded detail per denied row. Rows won't offer `h` (allow HTTP route) unless a method was recorded for them — allow the domain first with `a`, then retry from inside the sandbox to trigger a real HTTP-route check. There is no `D` (deny) key, and no `ctl proxy deny`: the firewall is deny-by-default, so denying something already-denied is a no-op. Use the Rules view (`r`, with `x` to remove) if you need to narrow a rule you added.

For an HTTPS domain denied at `CONNECT`, the encrypted method and path are not available yet. The TUI detail view suggests a temporary placeholder L7 rule to let the proxy terminate TLS and observe the real request:

```toml
[[network.allowed_routes]]
host = "pypi.org:443"
method = "GET"
path = "/noop"
```

Retry the request, inspect the resulting L7 denial, then replace `/noop` with the required path or path pattern. The placeholder path itself remains denied; remove the temporary rule when training is complete.

#### Relay denials in the TUI

The relay is a second gate, and it refuses requests the proxy never sees: under
`--proxy --ssh` the real `ssh` runs in the sidecar, authorized by
`allow_signing` rather than by a host/port rule. Those decisions appear in the
same denied-requests list, with `SSH` in the Method column and port `22` — the
port an `allowed_hosts` entry has to name, whatever port `ssh` itself dialled.
`a` on such a row writes both lines the grant needs:

```
allow_signing github.com
allow_host github.com:22
```

`relay-server` re-reads the policy on every call, so a retry works without
relaunching, and the exit summary renders the pair back as
`allowed_hosts = ["github.com:22"]` — one entry, from which a relaunch
re-derives `allow_signing`. `h` and `A` are refused on these rows: nothing
about a relay decision is HTTP, and it authorizes a host rather than an
address.

A refused **`gpg`** call is shown too, but read-only. Signing has no
destination for a policy to name, so it is enabled by launching with `--gpg`
and by nothing else; `a` says so rather than writing a rule that would not
help. `agent-sandbox ctl relay` remains the full record, including SSH calls
whose destination could not be read out of the command line — those have no
host to write a rule for, so the TUI leaves them out rather than offering a
fix it cannot deliver.

### Git Integration Details

When using Git inside the sandbox, be aware of how the integration flags interact:

- `--git` injects your effective Git configuration into the container using environment variables instead of mounting `.gitconfig`. Host-side `[include]` directives are evaluated and flattened on the host, while host-specific file paths (like `gpg.*.program`, credential helpers, global gitignore, and custom hooks) are automatically blocklisted so they don't break Git inside the container.
- `--gpg` is required for `--git` to also include commit signing. Without it, the sandbox explicitly disables signing (`commit.gpgsign = false`, `tag.gpgsign = false`) to prevent signing failures when the host's GnuPG agent is not forwarded.
- `--ssh` is required for `git pull` and `git push` to work with SSH remotes. It forwards your host's `SSH_AUTH_SOCK`. Because we avoid excessive host mounts, we do *not* mount your host's `known_hosts` file. An SSH session in a sandbox is non-interactive, so the alternative to knowing a host key in advance is not a prompt but either a hard failure or a silent trust-on-first-use accept of whatever answered — so the key has to come from somewhere explicit. Under `--proxy` that is `[[network.known_hosts]]` in `~/.config/agent-sandbox/trusted.toml`, and a policy that authorizes SSH to a host you have not declared a key for refuses the launch with the block to paste (see [Configuration](configuration.md#ssh-host-keys)). Without `--proxy` there is no policy to authorize against, and the published keys for GitHub, GitLab and Bitbucket are used.
- Combined with `--proxy`, neither socket is mounted into the sandbox at all: a
  forwarded socket is a capability that does not pass the firewall. The sockets
  go to the proxy sidecar instead, and the sandbox reaches them through
  `relay-ssh`/`relay-gpg`, which the relay authorizes each independently:
  `relay-gpg` needs only `--gpg` itself — signing has no destination to name,
  so no `AGENTS.md` declaration is required, in a proxied sandbox exactly as in
  an unproxied one. `relay-ssh` still needs an explicit `allowed_hosts` entry
  on port 22 for the destination, e.g. `allowed_hosts = ["github.com:22"]`,
  since push/pull genuinely need to name a host; with no such entry `git push`
  is refused. `agent-sandbox ctl relay` shows both states and the decisions
  made against them.
- The authorized host keys are delivered to whichever side actually runs `ssh`.
  Unproxied, that is the sandbox's own `~/.ssh/known_hosts`. Under
  `--proxy --ssh` it is the sidecar, so `relay-server` reads the file the
  launcher wrote beside the policy and passes `-o UserKnownHostsFile=…`: the
  sandbox's copy would be on the wrong side of the boundary, and the sidecar
  runs as `root`, whose home is `/root` rather than the image's `HOME`.
- The relay refuses an `ssh` that tries to decide any of this for itself:
  `UserKnownHostsFile`, `GlobalKnownHostsFile`, `StrictHostKeyChecking`,
  `VerifyHostKeyDNS`, and `-F` (an alternate config could set any of them out
  of sight). It also refuses `-J` / `ProxyJump`, which would pass the
  destination check and then connect somewhere else. If a host's key is not
  trusted, the fix is a `[[network.known_hosts]]` entry in `trusted.toml`, not
  a flag — that is the whole point of having the file.

### Bundled OpenCode skills

The image includes five OpenCode skills at `/home/user/.agents/skills`:

- `agent-sandbox` for the sandbox itself: recognising that it is running in one,
  what the firewall, the ephemeral home directory and the opt-in flags imply, and
  which host-side command to ask the user for when it hits a limit. It also
  covers `secretspec.toml` and how `--secrets` injects credentials the sandbox
  never sees.
- `nix` for running any nixpkgs tool ad hoc, without installing it.
- `nix-flake` for `flake.nix`: packaging software, outputs, checks, and simple
  `nix develop --command` development shells.
- `devenv` for `devenv.nix`: declarative environments with language toolchains
  and supporting services, entered with `devenv shell -- <command>`.
- `browser` for browser automation, in both shapes: headless inside the sandbox
  from nixpkgs, and the cooperative host browser `agent-sandbox browser` starts.
  It covers screenshotting a page for visual analysis, driving it via
  Playwright, and which of the two browsers a given task wants.

Each skill is a `SKILL.md` with the common path plus reference files with
advanced patterns. `nix-flake` additionally carries `uv2nix.md` (packaging
Python projects that have a `uv.lock`) and `images.md` (building OCI container
images from a flake package); `agent-sandbox` carries `network.md` (proxy policy
syntax, the `ctl` loop, live-versus-relaunch changes) and `secretspec.md`;
`browser` carries `reference.md` (form filling, the raw CDP fallback, and a
debugging checklist).

They are bundled into the image rather than mounted by the launcher. To use
user-owned skills instead, mount a replacement tree with
`--podman-args -v HOST:/home/user/.agents/skills --` or declare the mount in
`AGENTS.md` under `[mounts]`. A more specific child mount can replace only one
bundled skill. The canonical tree is also linked from
`~/.claude/skills`, `~/.codex/skills`, `~/.copilot/skills`, `~/.cursor/skills`,
and `~/.gemini/skills` for tools that use those discovery paths.

## Managing running sandboxes

`agent-sandbox ctl` operates on the host, on sandboxes already running:

| Command | What it does |
| --- | --- |
| `load` | build the image and import it into podman |
| `list [-a] [--roles]` | running sandboxes and their proxy mode; `--roles` also shows the proxy sidecars |
| `status [WORD] [--sandbox WORD]` | one screen per sandbox, pointing at the commands below |
| `net [-f] [WORD] [--sandbox WORD]` | connection summary, or a live feed |
| `logs [-f] [--tail N] [WORD] [--sandbox WORD]` | the proxy sidecar's log |
| `tui [WORD] [--sandbox WORD]` | interactive terminal UI: shows denied requests live so you can add the missing rule, a Connections view (`v`) of all recent connections including currently-open ones, plus a Rules view (`r`) to inspect and remove existing rules, without leaving the dashboard |
| `proxy show\|allow\|rm\|reset\|export\|check [WORD] [--sandbox WORD]` | read and change the policy of a running sandbox; `export` prints its `[network]` section as a fenced AGENTS.md block (`--plain` for a bare-TOML profile file); `check HOST[:PORT]` dry-runs whether a target would be allowed |
| `mounts ls\|add\|rm\|export [WORD] [--sandbox WORD]` | inspect and manage bind mounts into a running sandbox; `export` prints its `[mounts]` section as AGENTS.md TOML |
| `relay [-f] [WORD] [--sandbox WORD]` | show whether GPG signing is enabled and which hosts SSH push/pull may reach, plus what the relay has been asked for |
| `attach [WORD] [-- CMD...]` | execute an interactive command inside a running sandbox, with the environment the entrypoint built (see below) |
| `browser [WORD] [--sandbox WORD]` | start a throwaway host browser behind a deny-by-default allow list, for cooperative testing over CDP; `--name` runs several at once (see below) |
| `purge [--all] [-n] [-f]` | reclaim leftovers; running sandboxes are kept unless `--all`, and `-f` skips the confirmation |

New sandboxes are shown by a single session word, such as `silent`. Use that
word with any targetable command, either positionally or as `--sandbox silent`.
The full Podman name remains internal. If the same word is present on more than
one sandbox, the command refuses to guess and prints the matching workspaces and
full names. The word may be omitted when only one sandbox is running or when
exactly one matches the current directory.

For example:

```console
$ agent-sandbox ctl status silent
$ agent-sandbox ctl net --sandbox silent
$ agent-sandbox ctl logs silent
$ agent-sandbox ctl proxy show --sandbox silent
$ agent-sandbox ctl mounts ls --sandbox silent
$ agent-sandbox ctl attach silent -- bash
```

`attach` reproduces the environment the sandbox's own session runs in. `podman
exec` would otherwise start from the container's *configured* environment — what
`podman run` was given — and so miss everything the entrypoint derived at
startup: the merged CA bundle, `GIT_SSH_COMMAND=relay-ssh`, and the flattened
host git config from `--git`. That is why `git clone git@github.com:…` used to
fail in an attached shell while the same clone worked in the session the
launcher started. The entrypoint records those variables at
`~/.config/agent-sandbox/env` and `attach` passes them back in; a sandbox from an
older image simply has no such file and attaches as before.

`purge` defaults to leftovers only: exited sandboxes, sidecars whose sandbox is
gone, per-session networks nothing is attached to, and temp directories from a
launcher that was killed before it could clean up. `-n` shows what it would
remove.
