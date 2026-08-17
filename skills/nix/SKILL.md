---
name: nix
description: Run any tool from nixpkgs ad hoc, without installing it. Trigger when a CLI tool is missing, when a command fails with "command not found", when a one-off or temporary environment is needed, when looking up a Nix package name, or when asked to avoid global installation.
compatibility: opencode
metadata:
  workflow: ephemeral-tooling
  audience: developers-and-agents
---

# Ad-hoc Nix

Anything in nixpkgs can be run for one command without installing it. Never
install into the host with `apt`, `brew`, `npm -g`, `pip install`, or
`cargo install` when Nix can provide the tool for the duration of one command.

## Pick the smallest boundary

| Situation | Use |
| --- | --- |
| One missing executable, one command | `nix run nixpkgs#<pkg> -- <args>` |
| Several tools for one command | `nix shell nixpkgs#<a> nixpkgs#<b> --command <cmd>` |
| Repository has `devenv.nix` | `devenv shell -- <cmd>` — see the `devenv` skill |
| Repository has `flake.nix` with a devShell | `nix develop --command <cmd>` — see the `nix-flake` skill |
| The user wants the tool to stay | `nix profile add nixpkgs#<pkg>` — ask first |

Check the repository before reaching for nixpkgs. A project command
(`make test`, a devenv script, a flake app) always beats a guessed package.

## Default path: `nix run`

```sh
nix run nixpkgs#jq -- --version
nix run nixpkgs#ripgrep -- --glob '*.rs' TODO
nix run nixpkgs#hello -- --greeting=hi
```

The `--` separator is not optional. Without it, Nix consumes flags meant for
the program: `nix run nixpkgs#jq -r .name` fails, `nix run nixpkgs#jq -- -r .name` works.

`nix run` executes the package's `meta.mainProgram`, which is often not the
attribute name (`ripgrep` runs `rg`). When a package ships several binaries, or
the one you want is not the main program, use `nix shell` instead.

## Several tools: `nix shell --command`

```sh
nix shell nixpkgs#git nixpkgs#gh --command sh -c 'git log --oneline -5 && gh pr status'
nix shell nixpkgs#gnumake nixpkgs#gcc --command make -C src
```

Always pass `--command`. A bare `nix shell` opens an interactive subshell that
a non-interactive agent session cannot use and cannot exit cleanly.

## Find the attribute name

Guess and verify — it is far faster than searching:

```sh
nix eval --raw nixpkgs#ripgrep.meta.mainProgram   # => rg
nix eval nixpkgs#<pkg>.version
```

If the attribute does not exist, the eval fails immediately and cheaply.
`nix search nixpkgs '^ripgrep$'` works but evaluates all of nixpkgs and can take
minutes on first run — anchor the regex and expect the wait, or use
`search.nixos.org` when the sandbox allows the network.

## Gotchas

- **Unfree or insecure packages** need an explicit opt-in:
  `NIXPKGS_ALLOW_UNFREE=1 nix run --impure nixpkgs#<pkg>`.
- **Pin when the version matters**: `nix run nixpkgs/nixos-25.05#<pkg>`, or a
  revision: `nix run nixpkgs/<rev>#<pkg>`. Plain `nixpkgs#` follows the local
  registry, which may be stale; `--refresh` re-resolves it.
- **Remote flakes execute arbitrary code.** Before `nix run github:owner/repo#x`,
  weigh provenance and whether the project actually needs it.
- **Nothing persists.** Ad-hoc store paths have no GC root and can be collected.
  Do not hard-code a `/nix/store/...` path into scripts or config.
- **Editing Nix expressions** is a different task: validate with `nix fmt`,
  `nix flake check`, and `nix build .#<output>`, and leave `flake.lock` alone
  unless updating inputs was requested.

## More

Read `reference.md` before writing a one-off derivation, a language
environment with extra packages (Python, Node, …), a `nix-shell` shebang
script, an override of a package's build inputs, or when debugging a store
path or an offline/cache-constrained failure — these need patterns not shown
here.
