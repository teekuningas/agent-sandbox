# Container images from flake packages

Read `SKILL.md` first. This file turns a package that already builds into an OCI
image. Package it first, image it second — `dockerTools` copies a store closure
into layers, so a broken package is a broken image.

## `streamLayeredImage` vs `buildLayeredImage`

`pkgs.dockerTools.streamLayeredImage` builds a *script* that writes the tarball
to stdout; `buildLayeredImage` materializes a multi-gigabyte tarball in the Nix
store first. Prefer streaming:

```sh
nix build .#image
./result | podman load          # or: docker load
./result > image.tar            # or: | skopeo copy docker-archive:/dev/stdin …
```

Both take the same arguments, so switching later is a one-word change.

## The skeleton

```nix
packages.image = pkgs.dockerTools.streamLayeredImage {
  name = "registry.example.com/org/myapp";
  tag = "latest";
  created = "now";
  maxLayers = 2;

  contents = [
    (pkgs.dockerTools.fakeNss.override {
      extraPasswdLines = [ "container:x:65:65:Container user:/var/empty:/bin/sh" ];
      extraGroupLines = [ "container:!:65:" ];
    })
    pkgs.busybox
    pkgs.dockerTools.usrBinEnv
    pkgs.tini
    myapp
  ];

  extraCommands = ''
    mkdir -p tmp && chmod a+rxwt tmp
  '';

  config = {
    Entrypoint = [
      "${pkgs.tini}/bin/tini"
      "--"
      "${myapp}/bin/myapp"
    ];
    Env = [
      "TMPDIR=/tmp"
      "HOME=/tmp"
    ];
    Labels = builtins.fromJSON (builtins.readFile ./labels.json);
    User = "nobody";
  };
};
```

Why each piece is there:

- **`fakeNss`** provides `/etc/passwd`, `/etc/group`, and `/etc/nsswitch.conf`.
  Without it `User = "nobody"` cannot be resolved and anything calling
  `getpwuid()` fails. The `extraPasswdLines`/`extraGroupLines` override adds a
  fixed uid/gid for a platform that requires one.
- **`tini` as PID 1** reaps zombies and forwards signals, so `podman stop` and
  Kubernetes termination work instead of timing out. The `--` separates tini's
  own flags from the command.
- **`usrBinEnv`** creates `/usr/bin/env` for scripts with generic shebangs;
  `busybox` gives a shell and the basic utilities for `exec`ing into the
  container. Drop both for a genuinely minimal image — nothing in a Nix closure
  needs them.
- **`TMPDIR`/`HOME` pointing at `/tmp`** keeps libraries that insist on writing
  to `$HOME` working when the rest of the filesystem is read-only, which is what
  the world-writable sticky `/tmp` from `extraCommands` is for.
- **`User = "nobody"`** — run as non-root unless something genuinely needs root.
- **`Labels` from a JSON file** keeps the OCI annotations
  (`org.opencontainers.image.source`, `…revision`, `…created`) where CI can
  generate them, instead of hard-coding them in Nix.
- **`created = "now"`** gives a real timestamp at the cost of bit-for-bit
  reproducibility. Omit it (epoch 0) when reproducible digests matter more than
  a sensible `docker images` listing.

## Layer count

`maxLayers` splits the closure across layers, most-shared first. The default
(100) maximizes reuse between related images and is right for a registry. A
small number is right when the image is loaded locally: this repository uses
`maxLayers = 2` in `default.nix` deliberately, to cut `podman load` extraction
and container startup time for a single large image that is never pushed.

## Feeding it a Python application

Give the image a `mkApplication` result, never a raw virtualenv (see
`uv2nix.md`): the venv drags in the interpreter, activation scripts, and every
dependency's console scripts, and its `bin/python3` becomes an accidental
entry point.

```nix
let
  app = mkApplication {
    venv = pythonSet.mkVirtualEnv "myapp-env" workspace.deps.default;
    package = pythonSet.myapp;
  };
in
pkgs.dockerTools.streamLayeredImage {
  # …
  contents = [ … app ];
  config.Entrypoint = [ "${pkgs.tini}/bin/tini" "--" "${app}/bin/myapp" ];
}
```

The closure still contains the interpreter — Python needs it — but only your
entry point is reachable on PATH.

## A reusable helper

Every image in an organization differs by four values, so the pattern belongs in
a shared flake's `lib` output next to `mkPythonApp`:

```nix
lib.mkContainerImage =
  { pkgs, path, package, callable, labels, extraPackages ? [ ] }:
  pkgs.dockerTools.streamLayeredImage {
    name = path;
    tag = "latest";
    created = "now";
    maxLayers = 2;
    contents = [ … package ] ++ extraPackages;
    config = {
      Entrypoint = [ "${pkgs.tini}/bin/tini" "--" "${package}/bin/${callable}" ];
      Labels = builtins.fromJSON (builtins.readFile labels);
      User = "nobody";
    };
  };
```

`callable` is separate from `package` because the binary name and the package
name diverge often enough (`mkApplication` output named after the project,
entry point named after the command).

## Verifying without a container runtime

The stream script's output is an ordinary tarball, so the image can be checked
where no daemon or rootless podman is available:

```sh
nix build .#image && ./result > image.tar
tar -tf image.tar                                    # manifest + layers
tar -xOf image.tar <sha>.json | jq .config           # entrypoint, env, user, labels
tar -xOf image.tar <sha>/layer.tar | tar -tv | grep -E 'etc/passwd|^d.*tmp'
```

That confirms the entry point path, the label set, the non-root user, and the
`/tmp` permissions before anything is pushed.

Once a runtime is available:

```sh
./result | podman load
podman run --rm registry.example.com/org/myapp:latest
```
