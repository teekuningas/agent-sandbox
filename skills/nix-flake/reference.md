# Flakes — advanced patterns

Read `SKILL.md` first. Two topics have their own files: `uv2nix.md` for Python
projects with a `uv.lock`, and `images.md` for turning a package into an OCI
container image.

## Packaging skeletons

Put the derivation in its own file and wire it up with `pkgs.callPackage
./package.nix { }` — it keeps `flake.nix` readable and makes the package usable
from an overlay or another flake.

### Rust

```nix
{ lib, rustPlatform }:
rustPlatform.buildRustPackage {
  pname = "tool";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;   # no hash to maintain
  meta.mainProgram = "tool";
}
```

### Go

```nix
{ lib, buildGoModule }:
buildGoModule {
  pname = "tool";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  vendorHash = lib.fakeHash;   # replace with the hash from the first build
  meta.mainProgram = "tool";
}
```

### Node

```nix
{ lib, buildNpmPackage }:
buildNpmPackage {
  pname = "tool";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  npmDepsHash = lib.fakeHash;
}
```

### Python

**If the project has a `uv.lock`, stop and read `uv2nix.md`** — the lockfile is
the source of truth there, and hand-translating it into `python3Packages`
attributes throws away the resolution `uv` already did.

For a Python project without `uv.lock`, package it the nixpkgs way:

```nix
{ lib, python3Packages }:
python3Packages.buildPythonApplication {
  pname = "tool";
  version = "0.1.0";
  pyproject = true;
  src = lib.cleanSource ./.;
  build-system = [ python3Packages.hatchling ];
  dependencies = with python3Packages; [ requests ];
}
```

### Shell / glue

```nix
{ writeShellApplication, jq, curl }:
writeShellApplication {
  name = "fetch-name";
  runtimeInputs = [ jq curl ];
  text = ''curl -fsSL "$1" | jq -r .name'';
}
```

`writeShellApplication` runs shellcheck and sets `set -euo pipefail` for you.

## The fixed-output hash workflow

Any hash you cannot know up front (`vendorHash`, `npmDepsHash`, `cargoHash`,
`fetchFromGitHub`'s `hash`) follows the same loop:

1. Write `lib.fakeHash` (or `""`).
2. Build. Nix fails with `specified: sha256-AAAA…` / `got: sha256-<real>`.
3. Paste the `got:` value.

Never invent a hash, and never suppress the check.

## `apps` vs `packages`

`packages` build artifacts; `apps` name something runnable:

```nix
apps = forAllSystems (pkgs: {
  default = {
    type = "app";
    program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/tool";
    meta.description = "…";
  };
});
```

`nix run .#default -- args` uses it. If a package's `meta.mainProgram` already
points at the right binary, `nix run .#<pkg>` works without an `apps` entry —
only add `apps` when the entry point differs from the package's main program.

## Several devShells

```nix
devShells = forAllSystems (pkgs: {
  default = pkgs.mkShell { packages = [ pkgs.rustc pkgs.cargo pkgs.rust-analyzer ]; };
  ci = pkgs.mkShellNoCC { packages = [ pkgs.just pkgs.jq ]; };
});
```

```sh
nix develop .#ci --command just check
```

`mkShellNoCC` omits the C toolchain for shells that do not compile anything.
`shellHook` runs on entry — keep it cheap and side-effect free, since it also
runs for every `--command` invocation.

## Inputs, follows, overlays

```nix
inputs = {
  nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  some-tool = {
    url = "github:owner/some-tool";
    inputs.nixpkgs.follows = "nixpkgs";   # one nixpkgs, not two
  };
};
```

Applying an overlay from an input:

```nix
pkgs = import nixpkgs {
  inherit system;
  overlays = [ some-tool.overlays.default ];
  config.allowUnfree = true;   # only when a needed package requires it
};
```

Temporary overrides without touching the lockfile:

```sh
nix build .#default --override-input nixpkgs github:nixos/nixpkgs/nixos-25.05
nix develop --override-input some-tool path:/local/checkout --command <cmd>
```

## Checks

Checks are derivations that must build. Anything that can run in the sandbox
belongs here:

```nix
checks = forAllSystems (pkgs: {
  build = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
  lint = pkgs.runCommand "lint" { nativeBuildInputs = [ pkgs.shellcheck ]; } ''
    shellcheck ${./scripts}/*.sh
    touch $out
  '';
});
```

Sandboxed checks have no network and no access to untracked files. Tests that
need either belong in a devShell command, not in `checks`.

## Consuming other flakes

```sh
nix build github:owner/repo#package
nix run github:owner/repo -- --help
nix flake show github:owner/repo
nix flake metadata github:owner/repo     # locked rev, inputs, last modified
nix profile add github:owner/repo        # durable install; ask the user first
```

Remote flakes run arbitrary code at evaluation and build time. Pin a revision
(`github:owner/repo/<rev>`) for anything that must stay reproducible.

## Templates and scaffolding

```sh
nix flake init -t templates#rust          # from the official templates flake
nix flake new ./proj -t github:owner/repo#template
nix flake show templates                  # what is available
```

## Debugging evaluation

```sh
nix repl
# then:  :lf .        load the flake
#        outputs      inspect what it evaluates to
#        :p packages.x86_64-linux.default.drvPath

nix eval .#packages.x86_64-linux.default.outPath
nix build .#x -L --keep-going          # full build logs, do not stop at first failure
nix build .#x --rebuild                # check reproducibility
nix flake show --all-systems
nix why-depends .#default nixpkgs#openssl
```

`--show-trace` on any evaluation error turns "attribute missing" into a
usable stack.

## direnv

For humans working in the repo, `.envrc` containing `use flake` auto-enters the
default devShell. Agents should still use `nix develop --command` explicitly —
do not depend on direnv being hooked into a non-interactive shell.
