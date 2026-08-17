# Packaging Python with uv2nix

Read `SKILL.md` first. This file covers projects that use `uv` — the ones with a
`uv.lock`. For a Python package that already exists in nixpkgs style (a
`setup.py`/`pyproject.toml` with no `uv.lock`), use `buildPythonApplication` from
`reference.md` instead.

## Decide first: do you need uv2nix?

uv2nix generates Nix derivations from `uv.lock`, so the Nix build resolves
exactly what `uv` resolved. That is worth the machinery when the project is
**deployed** with Nix — a package, a container image, a CI artifact.

If Nix is only providing a development environment, you do not need uv2nix: a
plain devShell with `pkgs.python3` and `pkgs.uv`, letting `uv sync` manage
`.venv`, is simpler and upstream says so itself. The two can be mixed — impure
shell for development, uv2nix for the release build.

Trigger to reach for this file: the repository has `uv.lock` **and** something
must be built from it.

## Inputs

Three inputs, all following one nixpkgs:

```nix
inputs = {
  nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  pyproject-nix = {
    url = "github:pyproject-nix/pyproject.nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  uv2nix = {
    url = "github:pyproject-nix/uv2nix";
    inputs.pyproject-nix.follows = "pyproject-nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  pyproject-build-systems = {
    url = "github:pyproject-nix/build-system-pkgs";
    inputs.pyproject-nix.follows = "pyproject-nix";
    inputs.uv2nix.follows = "uv2nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };
};
```

`pyproject-nix` provides the builders, `uv2nix` translates the lockfile, and
`pyproject-build-systems` supplies build backends that `uv.lock` does not record.
Skipping the `follows` lines gives you several nixpkgs copies and a Python set
built against the wrong one.

## The pipeline

Four steps, always in this order:

```nix
# 1. Load the workspace (reads pyproject.toml + uv.lock at evaluation time)
workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

# 2. Turn the lockfile into a package overlay
overlay = workspace.mkPyprojectOverlay { sourcePreference = "wheel"; };

# 3. Compose the Python set: builders + build systems + your packages
pythonSet =
  (pkgs.callPackage pyproject-nix.build.packages { python = pkgs.python3; }).overrideScope
    (lib.composeManyExtensions [
      pyproject-build-systems.overlays.wheel
      overlay
    ]);

# 4. Aggregate into something usable
venv = pythonSet.mkVirtualEnv "myapp-env" workspace.deps.default;
```

Individual packages exist as `pythonSet.<name>`, but a single package is rarely
the deliverable — the venv is.

### `sourcePreference`

`"wheel"` downloads prebuilt binaries and mostly just works. `"sdist"` builds
from source and needs build-system overrides far more often. Start with
`"wheel"`; switch per-package only when a wheel is broken or unavailable.

### Dependency presets

`workspace.deps.*` selects what goes into a venv:

| Preset | Contents |
| --- | --- |
| `deps.default` | the project plus its `tool.uv.default-groups` |
| `deps.all` | every optional dependency and dependency group |
| `deps.optionals` | every `project.optional-dependencies` extra |
| `deps.groups` | every `dependency-groups` group |

Or name them explicitly — this is how you build a venv for one purpose:

```nix
pythonSet.mkVirtualEnv "myapp-test-env" { myapp = [ "test" ]; }   # the "test" group only
pythonSet.mkVirtualEnv "myapp-env" { myapp = [ ]; }               # no extras at all
```

## Two shapes to ship

**A virtual environment** — `mkVirtualEnv` — contains the interpreter,
`activate` scripts, `pyvenv.cfg`, and the console scripts of *every* dependency.
Right for a devShell or when consumers expect a Python environment.

**An application** — `mkApplication` — links only the content of your own
package: its `bin`, man pages, systemd units. The interpreter, activation
scripts and dependency binaries are excluded, so "written in Python" stops being
visible in the output.

```nix
let
  inherit (pkgs.callPackages pyproject-nix.build.util { }) mkApplication;
in
mkApplication {
  venv = pythonSet.mkVirtualEnv "myapp-env" workspace.deps.default;
  package = pythonSet.myapp;
}
```

The difference is measurable — for a project depending on `requests`:

```
mkVirtualEnv → bin/{activate,activate.csh,activate.fish,Activate.ps1,
                   myapp,idna,normalizer,python,python3,python3.14}
mkApplication → bin/myapp
```

Use `mkApplication` for anything that goes into a container image or onto a
user's PATH, and feed it to `images.md`.

Shipping extra data (shell completions, for example) is an `overrideAttrs` on
the `mkApplication` result with `pkgs.installShellFiles` in `nativeBuildInputs`.

## Development shell with editable packages

Editable installs put pointers to the source tree in the venv, so edits take
effect without a rebuild. They need a *second* scope, layered on the first:

```nix
editableOverlay = workspace.mkEditablePyprojectOverlay {
  root = "$REPO_ROOT";
  # members = [ "myapp" ];   # optional: restrict to some workspace members
};

editableSet = pythonSet.overrideScope editableOverlay;
virtualenv = editableSet.mkVirtualEnv "myapp-dev-env" workspace.deps.all;

devShells.default = pkgs.mkShell {
  packages = [ virtualenv pkgs.uv ];
  env = {
    UV_NO_SYNC = "1";              # uv must not manage a venv; uv2nix owns it
    UV_PYTHON = editableSet.python.interpreter;
    UV_PYTHON_DOWNLOADS = "never"; # interpreters come from Nix, not astral
  };
  shellHook = ''
    unset PYTHONPATH               # nixpkgs Python builders leak into unrelated builds
    export REPO_ROOT=$(git rev-parse --show-toplevel)
  '';
};
```

`REPO_ROOT` is what `root = "$REPO_ROOT"` resolves against at runtime — without
it the editable pointers dangle.

**Do not run `uv run` inside this shell.** It provisions uv's own virtualenv and
shadows everything above. The entry points are already on PATH; call them
directly (`nix develop --command myapp`, `nix develop --command pytest`).

## Tests as checks

Runtime and test dependencies are not present at build time — by design. Tests
belong in their own derivation, attached to `passthru.tests` by an override
overlay and re-exported as flake checks:

```nix
pyprojectOverrides = final: prev: {
  myapp = prev.myapp.overrideAttrs (old: {
    passthru = old.passthru // {
      tests = (old.tests or { }) // {
        pytest =
          let
            venv = final.mkVirtualEnv "myapp-pytest-env" { myapp = [ "test" ]; };
          in
          pkgs.stdenv.mkDerivation {
            name = "${final.myapp.name}-pytest";
            inherit (final.myapp) src;
            nativeBuildInputs = [ venv ];
            dontConfigure = true;
            buildPhase = ''
              runHook preBuild
              pytest
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              touch $out
              runHook postInstall
            '';
          };
      };
    };
  });
};
```

Add `pyprojectOverrides` to the `composeManyExtensions` list (last), then:

```nix
checks = forAllSystems (system: {
  inherit (pythonSets.${system}.myapp.passthru.tests) pytest;
});
```

Sandboxed checks have no network. Tests that need one belong in a devShell
command instead.

## Gotchas

- **`pyproject-build-systems.overlays.default` is the `sdist` overlay, not the
  wheel one.** Pairing it with `sourcePreference = "wheel"` means your
  dependencies come from wheels while their build backends are compiled from
  source — it works, but it is slower than intended. Use `overlays.wheel`
  alongside `sourcePreference = "wheel"`.
- **uv does not lock build systems.** Source builds fail with a missing build
  backend. Fix it in this order:
  1. `tool.uv.extra-build-dependencies` in `pyproject.toml` — uv2nix reads it,
     and the fix stays with the project.
  2. An overlay entry:
     ```nix
     pyzmq = prev.pyzmq.overrideAttrs (old: {
       nativeBuildInputs = old.nativeBuildInputs ++ final.resolveBuildSystem {
         cmake = [ ]; ninja = [ ]; scikit-build-core = [ ]; cython = [ ];
       };
     });
     ```
  3. A PR to `build-system-pkgs` if the backend is a common one.
- **Wheels needing system libraries.** Wheels are patched with
  `autoPatchelfHook`, but a wheel that expects a system library still needs
  `buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.<lib> ]` (upstream's example:
  `numba` needing a newer `tbb`).
- **Never filter sources at `workspaceRoot`.** uv2nix reads that path during
  evaluation, so filtering there forces import-from-derivation and breaks
  editable packages. Filter per package:
  `myapp = prev.myapp.overrideAttrs (old: { src = lib.cleanSource old.src; });`
- **Interpreter choice.** `pkgs.python3` is fine when it satisfies
  `requires-python`. To derive it from the project instead:
  ```nix
  python = lib.head (pyproject-nix.lib.util.filterPythonInterpreters {
    inherit (workspace) requires-python;
    inherit (pkgs) pythonInterpreters;
  });
  ```
- **Flakes ignore untracked files** — `git add pyproject.toml uv.lock src/`
  before building, or the workspace loads as empty or stale.

## Single-file scripts (PEP 723)

Scripts carrying inline metadata are a separate entry point, not a workspace:

```sh
uv lock --script scripts/example.py     # writes scripts/example.py.lock
```

```nix
script = uv2nix.lib.scripts.loadScript { script = ./scripts/example.py; };

pythonSet =
  (pkgs.callPackage pyproject-nix.build.packages { python = pkgs.python3; }).overrideScope
    (lib.composeManyExtensions [
      pyproject-build-systems.overlays.wheel
      (script.mkOverlay { sourcePreference = "wheel"; })
    ]);

packages.default = pkgs.writeScript script.name (
  script.renderScript { venv = script.mkVirtualEnv { inherit pythonSet; }; }
);
```

`renderScript` rewrites the shebang to the generated venv's interpreter, so the
result is a directly executable file. Map over `builtins.readDir ./scripts` to
package a whole directory of them.

## Sharing the boilerplate across repositories

The pipeline is identical in every project, so a shared flake can expose it as a
`lib` output that sibling repositories consume:

```nix
lib.mkPythonApp =
  { pkgs, python, workspaceRoot ? ./., sourcePreference ? "wheel",
    overrides ? _final: _prev: { } }:
  let
    workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };
    pythonSet =
      (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).overrideScope
        (pkgs.lib.composeManyExtensions [
          pyproject-build-systems.overlays.wheel
          (workspace.mkPyprojectOverlay { inherit sourcePreference; })
          overrides
        ]);
    pyprojectName =
      (builtins.fromTOML (builtins.readFile (workspaceRoot + "/pyproject.toml"))).project.name;
    inherit (pkgs.callPackages pyproject-nix.build.util { }) mkApplication;
  in
  {
    inherit workspace pythonSet;
    package = mkApplication {
      venv = pythonSet.mkVirtualEnv "${pyprojectName}-env" workspace.deps.default;
      package = pythonSet.${pyprojectName};
    };
  };
```

Reading `project.name` out of `pyproject.toml` is what makes the helper generic —
the attribute in `pythonSet` matches the project name.

Consumers pass their own `pkgs` and keep the `overrides` escape hatch:

```nix
inputs.nix-utils.url = "github:org/nix-utils";

app = nix-utils.lib.mkPythonApp {
  inherit pkgs;
  python = pkgs.python3;
  workspaceRoot = ./.;
};
packages.default = app.package;   # also: app.pythonSet, app.workspace
```

Returning `pythonSet` and `workspace` alongside `package` is what keeps the
helper usable — a consumer that needs a devShell, a test check, or a different
venv builds it from those without forking the helper.

`workspaceRoot` must stay a real path; passing a filtered or derived source
reintroduces the IFD problem above.

## Starting from a template

```sh
nix flake init --template github:pyproject-nix/uv2nix#hello-world
nix flake init --template github:pyproject-nix/uv2nix#inline-metadata
```

Upstream documentation: <https://pyproject-nix.github.io/uv2nix/> — the chapters
on overriding, conflicts, cross compilation, and platform quirks go deeper than
this file.
