---
name: nix-flake
description: Use and write flake.nix — package software as a reproducible build, expose apps and checks, and provide a devShell entered non-interactively with nix develop --command. Trigger when a repository has flake.nix or flake.lock, when packaging or building software with Nix, or when adding a development shell, app, check, or formatter.
compatibility: opencode
metadata:
  workflow: project-interface
  audience: developers-and-agents
---

# Flakes

A flake is the project's API: what it builds, how it runs, how it is checked,
and which environment its commands need. Read `flake.nix`, `flake.lock`, the
README, and any `AGENTS.md`/`CLAUDE.md` before inventing setup commands.

Two jobs use this skill: **packaging software** (`packages`, `apps`, `checks`)
and **simple development shells** (`devShells`, entered with
`nix develop --command`). If the project needs services, language runtimes, and
process management, that is a `devenv` job instead — see the `devenv` skill, and
do not replace a `devenv`-managed environment with a hand-written shell.

## Default path: use the flake that exists

```sh
nix flake show                         # what this flake actually provides
nix develop --command <cmd> [args...]  # run one command in the default devShell
nix build .#<output>                   # build an artifact into ./result
nix run .#<app> -- <args>              # run an app output
nix flake check -L                     # the project's own checks
nix fmt                                # the project's formatter (see gotchas)
```

Always use `nix develop --command`. Bare `nix develop` opens an interactive
subshell that a non-interactive session cannot use. Named shells work the same
way: `nix develop .#ci --command make test`.

`nix flake show` is the source of truth for output names — do not guess
`.#default` when the flake exposes something else.

## Flakes only see git-tracked files

A new file that is not staged does not exist as far as the build is concerned:

```sh
git add flake.nix src/new-file.rs
nix build .#default
```

Nix says so explicitly (`error: ... To make it visible to Nix, run: git add ...`)
— when a build cannot find a file you just wrote, this is why. The
`warning: Git tree ... is dirty` message is harmless: uncommitted changes are
included, only untracked ones are not.

## Writing a flake

Match the existing style of the repository. If the flake already has a
`forAllSystems`/`genAttrs` helper, reuse it; do not introduce `flake-utils` or
`flake-parts` into a flake that does not use them. Reuse existing inputs instead
of adding a second source of the same package set.

A complete, working skeleton:

```nix
{
  description = "…";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./package.nix { };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.default ];
          packages = [ pkgs.jq ];
          env.GREETING = "hi";
        };
      });

      checks = forAllSystems (pkgs: {
        build = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
    };
}
```

Points that matter:

- `inputsFrom` gives the shell the package's own build inputs — do not restate
  dependencies in two places.
- Set `meta.mainProgram` on a package so `nix run` picks the right binary.
- Use the ecosystem's builder rather than raw `stdenv.mkDerivation`, and pick it
  by the project's lockfile: `Cargo.lock` → `rustPlatform.buildRustPackage`,
  `go.sum` → `buildGoModule`, `package-lock.json` → `buildNpmPackage`,
  **`uv.lock` → uv2nix (see `uv2nix.md`)**, otherwise
  `python3Packages.buildPythonApplication` or `pkgs.writeShellApplication`.

## Validate before reporting done

```sh
nix fmt                # or `nix fmt .` for a bare nixfmt formatter
nix flake check -L
nix build .#<output> -L
```

`nix flake check` only *builds* checks for the current system and prints
`omitted these incompatible systems` for the rest; `--all-systems` evaluates
them all (it cannot build foreign systems without a remote builder).

## Gotchas

- **`formatter = pkgs.nixfmt` needs a path argument.** Bare `nix fmt` then reads
  stdin and fails with `unexpected end of input`; `nix fmt .` works but warns
  that directory arguments are deprecated. `formatter = pkgs.nixfmt-tree` (a
  treefmt wrapper) makes bare `nix fmt` format the whole tree — prefer it in new
  flakes.
- **Leave `flake.lock` alone** unless updating inputs is part of the task.
  `nix flake update` rewrites every input; `nix flake update nixpkgs` updates
  one. Review the diff rather than accepting a drive-by upgrade.
- **`--impure` defeats the point.** If a build needs it, the expression is
  reaching outside the flake — fix that instead.
- **Pinned is not trusted.** New inputs, overlays, fetchers, and build hooks are
  code someone else wrote; review them as such.

## More

- Read `reference.md` before packaging a new language target, adding a second
  devShell, wiring up an overlay or `follows`/`--override-input`, writing a
  `checks` entry, or debugging evaluation with `nix repl` — per-language
  skeletons, the fixed-output hash workflow, `apps` vs `packages`, and
  templates all live there.
- **If the project has a `uv.lock`, stop and read `uv2nix.md`** — the
  workspace/overlay/pythonSet pipeline, venv vs application outputs, editable
  development shells, build-system overrides, tests as checks, PEP 723
  scripts, and sharing the boilerplate as a flake `lib` output.
- Read `images.md` before turning a flake package into an OCI image —
  `dockerTools.streamLayeredImage`, non-root user, `tini` entry point, labels,
  layer count, and verifying an image without a container runtime.
