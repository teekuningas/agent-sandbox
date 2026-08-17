# AGENTS.md – agent-sandbox

## Project overview

`agent-sandbox` is a Nix flake that produces a rootless Podman container image
("agent-sandbox") together with a launcher binary (`agent-sandbox`) and a
management multiplexer (`agent-sandbox ctl`, with the subcommands `load`,
`list`, `status`, `net`, `logs`, `tui`, `proxy`, `mounts`, `attach`, `relay` and
`purge`).

## Repository map

| Path | What it is |
| --- | --- |
| `default.nix` | single Nix module; builds the image and every host script |
| `agents.nix` | agent catalog (command + persisted state paths per agent) |
| `flake.nix` | flake entry point; exposes `packages.<system>.default` and `apps.<system>.default` |
| `cli/` | Rust launcher, entrypoint, sidecar, `ctl` subcommands |
| `proxy/` | Rust egress proxy, TUI, SSH/GPG relay |
| `skills/` | skill trees baked into the image at `/home/user/.agents/skills` |
| `docs/` | user-facing documentation (MkDocs Material, published to GitHub Pages) |

## Where the documentation lives

**`docs/` is the single source of truth for how this project behaves.** Read the
page that covers your task rather than a summary of it here; this file
deliberately keeps no second copy to drift out of date.

| Page | Covers |
| --- | --- |
| [`docs/index.md`](docs/index.md) | what the project is, installation, quick start |
| [`docs/usage.md`](docs/usage.md) | every flag, `ctl` subcommands, the TUI, bundled skills, Git integration |
| [`docs/configuration.md`](docs/configuration.md) | `AGENTS.md` `[ports]`/`[mounts]`/`[network]` syntax, secrets, network profiles |
| [`docs/trust-model.md`](docs/trust-model.md) | what each flag exposes, what the firewall does and does not cover |
| [`docs/architecture.md`](docs/architecture.md) | image, entrypoint, launcher call flow, proxy sidecar, policy format, relay, startup ordering |
| [`docs/development.md`](docs/development.md) | adding an integration, an agent, or an image tool; implementation constraints |
| [`docs/testing.md`](docs/testing.md) | the two test tiers, what each covers, how to add to either |

Code is the source of truth over prose in exactly two places, and the docs defer
to them too:

- flags and their defaults — `cli/src/bin/agent-sandbox.rs` and `cli/src/launch.rs`
- policy semantics — `proxy/src/policy.rs` (`--check-policy` is the reference validator)

## Working on this repo

- **Run `make unittest`.** That is the whole in-container tier: the Rust
  workspace (including the stub-podman tests that cover the flag →
  `podman run` mapping) plus the strict docs build. It needs no container
  runtime, which is the point — podman does not run nested, so this is the
  only tier an agent working in a sandbox can run.
- Anything whose answer comes from a real container — proxy egress, the relays,
  a mount that has to be read-only, krun — lives in `tests/integration/` and
  runs on the host: `make -C tests/integration`. Do not try to run it from
  inside a sandbox; ask for the logs instead.
- [`docs/testing.md`](docs/testing.md) is the page for both tiers: where the
  boundary is, what each one can establish, and where coverage still thins out.
- A change to behaviour is not finished until the page that documents it says
  so. `print_usage` in `cli/src/bin/agent-sandbox.rs` and the flag table in
  `docs/usage.md` are two renderings of one fact and must be edited together.

## Documentation conventions

- MkDocs renders with Python-Markdown, which is stricter than GitHub:
  - a list **must** be preceded by a blank line, or it is swallowed into the
    paragraph above it;
  - a continuation paragraph inside a list item is indented to the item's text,
    not by four spaces, which would make it a code block;
  - SuperFences rejects a two-word info string, so a fence tagged
    `toml agent-sandbox` is not parsed as a code block at all — its contents are
    read as Markdown and the stray delimiters re-pair with later ones, wrecking
    the rest of the page. An example *of* such a block must be nested inside an
    outer four-backtick fence; `docs/configuration.md` shows the pattern.
- Prefer linking between pages over repeating a paragraph. This file exists to
  point at them.


## Agent sandbox for this project

```toml agent-sandbox
[network]
allowed_hosts = [
    "channels.nixos.org:443",
    "github.com:443,22",
    "index.crates.io:443",
    "releases.nixos.org:443",
]
```
