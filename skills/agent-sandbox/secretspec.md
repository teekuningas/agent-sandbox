# secretspec

Read `SKILL.md` first. This file covers `secretspec.toml` — what it means when
you find one, how to use the tool without leaking anything, and how
`agent-sandbox --secrets` delivers credentials the sandbox itself never holds.

Upstream: <https://secretspec.dev> / <https://github.com/cachix/secretspec>.

## Before you start

- **Never run `secretspec get` or `secretspec export`** to "see" a value, and
  never pipe either into a file, log, or message. Use `secretspec run` to
  inject a secret into a command instead.
- **Always pass `--reason "..."`** — an agent-driven call without one fails
  outright (`require_reason` defaults to `"agents"`).
- **`keyring://` cannot work inside the sandbox** (no session bus/display) —
  that's expected, not a bug to fix. A file-based provider or `--secrets`
  is the way forward here.
- **The three files below must match exactly**, port included — a mismatch
  refuses the launch, and the fix is to paste the printed block, not retype
  it.

## What the file tells you

[secretspec](https://secretspec.dev) separates **declaration** from **storage**.
`secretspec.toml` is committed and says which secrets the project needs; the
values live in a provider on the developer's machine — a system keyring, a
password manager, a vault, a `.env` outside git.

Finding one in a repository means: secrets are expected to arrive from a
provider at run time. So do not write a `.env` with real-looking values, do not
invent placeholder credentials that could be mistaken for real ones, and do not
add secret values to the repo in any form. If a command needs a secret, run it
under `secretspec run` instead of hard-coding anything.

## Manifest shape

Verified against the bundled `secretspec` (0.17.1):

```toml
[project]
name = "demo"
revision = "1.0"

[defaults]
provider = "dotenv"

[providers]
local = "dotenv://.env"
env = "env://"

[profiles.default]
DATABASE_URL = { description = "PostgreSQL DSN", required = true }
API_KEY = { description = "Upstream API token", required = true }
LOG_LEVEL = { description = "Log level", default = "info", required = false }

[profiles.development]
DATABASE_URL = { description = "PostgreSQL DSN", default = "postgresql://localhost/dev" }

[scopes.api]
secrets = ["API_KEY"]
```

- **`description` is mandatory** on every secret. Omitting it fails the whole
  manifest with `Profile '<p>': Secret '<S>': missing description` — a common
  cause of "secretspec suddenly stopped working" after someone adds a key.
- `[profiles.<name>]` — per-environment requirements; `default` is the base.
  A `default` value makes a secret optional in practice.
- `[providers]` — named aliases for provider URIs; `[defaults] provider` picks
  one. Users can also set a machine-wide default with
  `secretspec config global init` (`~/.config/secretspec/config.toml`).
- `[scopes.<name>]` — an allowlist of secrets for one service or command;
  `--scope api` injects only those and strips the rest from the child process.
- Provider URIs include `keyring://`, `dotenv://`, `env://`, `onepassword://`,
  `pass://`, `vault://`, `sops://`, `age://` and roughly thirty more. Newer
  releases add both providers and manifest keys, so a manifest written against a
  newer secretspec may not evaluate under the bundled one.

## Using it without leaking

```sh
secretspec check --reason "why"          # names + descriptions, no values — safe
secretspec schema                        # JSON Schema of the resolved secrets
secretspec run --reason "why" -- <cmd>   # inject into one child process
secretspec run --scope api --reason "why" -- <cmd>   # only that scope's secrets
```

`check` prints one line per secret with a ✓/✗ and its description, never a value.
That is the command to run when you want to know whether the environment is
complete.

**`secretspec get` and `secretspec export` print secret material to stdout.** Do
not run them to "see" a value, do not pipe them into a file in the repository,
and do not echo a resolved value into a log, a commit, or a message. If a task
seems to need the plaintext, it almost certainly needs `secretspec run` instead.

### Two things that will bite you here

**A reason is required.** Version 0.17 defaults `require_reason` to `"agents"`,
so an agent-driven invocation without `--reason` fails:

```
Accessing secrets requires a reason. Provide one with --reason "<why you are
accessing these secrets>", the SECRETSPEC_REASON environment variable, or
Secrets::with_reason() in the SDK. (Policy: require_reason in [project] of
secretspec.toml — defaults to "agents"; set it to false to disable.)
```

Supply an honest, specific `--reason` — it is recorded in the audit log
(`~/.local/state/secretspec/audit.log`, which is on tmpfs in the sandbox and does
not survive the session). Do not disable the policy to make the message go away.

**`keyring://` cannot work inside the sandbox.** There is no session bus or
display, so it fails with:

```
Keyring error: Platform secure storage failure: DBus error: Unable to autolaunch
a dbus-daemon without a $DISPLAY for X11
```

That is expected, not a defect to fix. A file-based provider (`dotenv://`,
`sops://`, `age://`) works in here; a keyring-backed one has to be resolved on
the host — which is exactly what `--secrets` does.

## How `--secrets` works, and why you never see a value

With `agent-sandbox --proxy --secrets`, resolution happens **on the host**:

1. The launcher reads the `[[network.allowed_routes]]` rules that name a `secret`.
2. It checks each one against the host-side authorization file,
   `~/.config/agent-sandbox/trusted.toml`.
3. It runs `secretspec export --file <workspace>/secretspec.toml --format json`
   with a reason, honouring any `profile`, `provider` and `scope` set in that file.
4. The values go to the **proxy sidecar** over a read-only memory mount.
5. The proxy injects the header into requests matching that rule's host, method
   and path — decided per request, so other rules on the same host get nothing.

The secret is never in the sandbox's environment, filesystem, or process table.
If a task requires reading the token itself, the answer is that it cannot be done
this way — say so rather than looking for a workaround.

## The three files that must agree

**1. `secretspec.toml`** (in the repo) declares the name:

```toml
[profiles.default]
GITHUB_TOKEN = { description = "GitHub API token", required = true }
```

**2. `AGENTS.md`** (in the repo) binds it to one route:

````markdown
```toml agent-sandbox
[network]
allowed_hosts = ["github.com:443"]

[[network.allowed_routes]]
host = "api.github.com:443"
method = "GET"
path = "/repos/**"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "
```
````

**3. `~/.config/agent-sandbox/trusted.toml`** (on the host, never in the repo)
authorizes it — **copied verbatim**, minus the `[network]` wrapper:

```toml
[[network.allowed_routes]]
host = "api.github.com:443"
method = "GET"
path = "/repos/**"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "
```

Every field is matched exactly, the port included. Omitted fields are not
wildcards: they take their defaults (`method = "GET"`, `path = "/"`,
`header = "Authorization"`) and are then matched as written. A rule the repo asks
for but the host has not authorized **refuses the launch** and prints the exact
block to paste — when a user reports that refusal, the fix is to copy the printed
block unchanged, not to retype it.

This asymmetry is the point: `AGENTS.md` is untrusted, so it can name a secret
but cannot decide where it goes. Note also that secret injection is HTTP/1.1
only; an h2-only client will fail the TLS handshake against an intercepted host.

## The same file authorizes SSH host keys

`trusted.toml` carries `[[network.known_hosts]]` as well, on the identical
terms: `AGENTS.md` may name a host on port 22, but not say which key that host
has. A policy authorizing SSH to a host with no key declared for it refuses the
launch and prints the block, exactly as an unauthorized secret does:

```toml
[[network.known_hosts]]
host = "github.com:22"
key = "ssh-ed25519 AAAAC3Nza..."
```

Same rule for you as with secrets: you cannot write that file, and the fix for
the refusal is to copy the printed block unchanged. See `network.md` for how
`:22` in `allowed_hosts` pulls the requirement in.
