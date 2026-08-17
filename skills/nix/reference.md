# Ad-hoc Nix — advanced patterns

Read `SKILL.md` first. Everything here assumes flakes and `nix-command` are
enabled (they are, inside this image).

## Language environments with packages

A one-off interpreter with libraries, without writing any project files:

```sh
nix shell --impure --expr 'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
  [ (python3.withPackages (ps: [ ps.requests ps.rich ])) ]' \
  --command python3 script.py
```

The same shape works for other ecosystems:

- `(python3.withPackages (ps: [ ... ]))`
- `(haskellPackages.ghcWithPackages (ps: [ ... ]))`
- `(texlive.combine { inherit (texlive) scheme-small latexmk; })`
- `nodejs` plus `npx` for Node — npm packages are usually better fetched by
  `npx` inside a `nix shell nixpkgs#nodejs --command ...` than packaged by hand.

`--impure` is required because `builtins.getFlake` and `builtins.currentSystem`
read outside the pure evaluation. That is acceptable for throwaway commands; it
is not acceptable inside a project's `flake.nix`.

## Overriding a package for one command

```sh
# Different version of a source-built package
nix shell --impure --expr 'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
  [ (hello.overrideAttrs (o: { doCheck = false; })) ]' --command hello

# Package with different build inputs / flags
nix shell --impure --expr 'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
  [ (ffmpeg.override { withVaapi = false; }) ]' --command ffmpeg -version
```

Building from source can be slow — check whether the cache has it first:

```sh
nix path-info --store https://cache.nixos.org nixpkgs#<pkg> 2>/dev/null && echo cached
```

## Pinning

```sh
nix run nixpkgs/nixos-25.05#<pkg> -- --version         # release branch
nix run nixpkgs/e8c38b7#<pkg> -- --version             # exact revision
nix run github:nixos/nixpkgs/<rev>#<pkg> -- --version  # explicit, no registry
nix registry list                                       # what nixpkgs# resolves to
nix flake metadata nixpkgs                              # the locked revision in use
```

Use `--refresh` when a registry entry is stale. Prefer a pinned reference in
anything reproducible; use bare `nixpkgs#` for throwaway commands.

## One-off derivations

Build something that is not in nixpkgs, without creating a flake:

Nix's `''` multi-line strings collide with shell single quotes, so put anything
with a build script in a file and use `--file`:

```nix
# build.nix
with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
runCommand "report" { nativeBuildInputs = [ jq ]; } ''
  jq -n '{ built: true }' > $out
''
```

```sh
nix build --impure --file build.nix --print-out-paths
```

For anything reused more than once, write a `flake.nix` instead — see the
`nix-flake` skill.

## Scripts that provision their own tools

A self-contained script that pulls its dependencies when run:

```sh
#!/usr/bin/env nix-shell
#!nix-shell -i bash -p jq curl
set -euo pipefail
curl -fsSL "$1" | jq -r .name
```

The classic (non-flake) interface still works and needs no `#` attribute paths:

```sh
nix-shell -p jq ripgrep --run 'rg --version && jq --version'
```

Note that `nix-shell -p` resolves against `NIX_PATH`/channels, not the flake
registry, so the two can disagree on versions.

## Inspection and debugging

```sh
nix eval nixpkgs#<pkg>.meta --json | jq          # license, platforms, mainProgram
nix eval --raw nixpkgs#<pkg>.outPath             # store path without building
nix build nixpkgs#<pkg> --no-link --print-out-paths
ls "$(nix build nixpkgs#<pkg> --no-link --print-out-paths)/bin"   # what binaries exist
nix path-info -Sh nixpkgs#<pkg>                  # closure size
nix why-depends nixpkgs#<a> nixpkgs#<b>          # why one pulls in the other
nix derivation show nixpkgs#<pkg> | jq           # the actual build inputs
nix log nixpkgs#<pkg>                            # build log, if available
```

`nix repl` is useful for exploration when several lookups are needed:

```sh
nix repl --expr 'import (builtins.getFlake "nixpkgs") { system = builtins.currentSystem; }'
```

## Network, cache, and store hygiene

```sh
nix run --offline nixpkgs#<pkg>          # fail fast instead of downloading
NIX_CONFIG='substituters = https://cache.nixos.org' nix build ...
nix store gc --dry-run                    # what would be collected
nix build .#x --out-link result           # create a GC root when a path must survive
```

In a proxied or firewalled sandbox, `cache.nixos.org` and the flake input hosts
(`github.com`, `api.github.com`) must be reachable. A hang during
"copying path ... from https://cache.nixos.org" is a network policy problem, not
a Nix problem — check the sandbox's allowed hosts before retrying.

## When ad-hoc stops being the right tool

Move up a level once any of these is true:

- The same `nix shell` line is being retyped across commands → project devShell
  (`nix-flake` skill).
- The environment needs services, language versions, or hooks → `devenv` skill.
- The result is an artifact someone else must reproduce → a flake output, not a
  shell command.
