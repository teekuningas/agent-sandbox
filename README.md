# agent-sandbox

Sandboxed AI coding environment that runs inside a rootless Podman container.
Launch `opencode` (or any other tool) with SSH agent, GPG signing, Git identity,
host Podman socket, and `devenv` state all wired through automatically.

## Install

### From a local clone

```sh
git clone https://github.com/datakurre/agent-sandbox
cd agent-sandbox
nix profile add .#          # installs agent-sandbox and agent-sandbox-ctl
```

### From a remote flake

```sh
nix profile add github:datakurre/agent-sandbox
```

After installing, build the container image (one-time):

```sh
agent-sandbox-ctl load
```

## Usage

```
agent-sandbox [FLAGS] [-- PODMAN_ARGS...] [-- COMMAND...]
```

**With no arguments** `agent-sandbox` launches opencode inside the sandbox with
the current working directory mounted at `/workspace` and every integration
enabled.  If the current directory contains a `devenv.nix`, opencode is started
through a devenv shell (`devenv shell -- opencode .`) so project dependencies
are loaded automatically.

### Override the container command

Everything after the second `--` replaces the default command:

```sh
agent-sandbox -- -- bash                            # interactive shell
agent-sandbox -- -- bash -c "nix build .# && echo done"
agent-sandbox -- -- devenv shell
```

### Pass podman flags

To pass arguments directly to podman there are two forms.

`--podman-args=ARG` passes exactly one argument and is repeatable. It consumes
nothing but itself, so flags after it are still parsed by agent-sandbox. Use
this one when baking defaults into a wrapper.

`--podman-args` (no `=`) passes everything that follows to podman until a `--`
sentinel, which also marks the start of the container command. Because `--` ends
agent-sandbox's own parsing, anything after it is the command, not a flag.

There are also convenient shortcuts like `--privileged` and `-e` for common podman flags.

```sh
agent-sandbox --privileged opencode                 # enable nested podman
agent-sandbox --podman-args=--network=host opencode # host network
agent-sandbox --podman-args --network=host -- bash  # same, slurp form
agent-sandbox -e MY_VAR=1 opencode                  # pass environment variable
```

The repeatable form is what makes a wrapped default work, since it leaves the
rest of the command line alone:

```nix
wrapProgram $out/bin/agent-sandbox --add-flags \
  "--podman-args=--add-host=myhost.tail1234.ts.net:100.64.0.1"
```

### Flags

Some integrations are **on by default** while others are opt-in. Enable or disable with the matching flag.

| Flag                    | Default | What it does                                          |
| ----------------------- | ------- | ----------------------------------------------------- |
| `--workspace` / `--no-workspace` | on | mount `$PWD` as `/workspace/<dirname>:rw`              |
| `--selinux` / `--no-selinux`     | off | add SELinux shared relabel (`:z`) to built-in writable mounts |
| `--ssh` / `--no-ssh`             | on | forward `SSH_AUTH_SOCK`                                |
| `--git` / `--no-git`             | on | mount `~/.gitconfig`, forward `user.name`/`user.email` |
| `--gpg-agent` / `--no-gpg-agent` | on | forward host gpg-agent socket for commit signing       |
| `--gpg-sign` / `--no-gpg-sign`   | on | enable/disable git commit signing inside container     |
| `--devenv` / `--no-devenv`       | on | mount `~/.local/share/devenv` across sessions          |
| `--podman` / `--no-podman`       | off | forward host rootless podman socket (sibling containers) |
| `--nix` / `--no-nix`             | on | mount host `/nix/store` to delegate builds to host daemon |
| `--gnupg-private` / `--no-gnupg-private` | off | expose `~/.gnupg` even when it holds on-disk secret keys |
| `--firewall` / `--no-firewall`   | off | route container traffic through a domain-filtering proxy |
| `--meter-network` / `--no-meter-network` | off | capture network traffic for a post-run summary           |
| `--ports` / `--no-ports`         | on  | honour `[ports]` declarations in `AGENTS.md` |
| `--ports-dynamic` / `--no-ports-dynamic` | off | allow `agent-sandbox-ctl port add` later |
| `--ports-any-interface`          | off | permit port binds outside loopback |

You can use `--port [HOST:]CONTAINER[/PROTO]` to publish a port.

You can pass `-e NAME=VAL` or `--env NAME=VAL` to inject environment variables.

You can also pass `-v` / `-v*` volume mounts before `--`.  Relative paths in
the source are resolved against `$PWD`; relative destinations are prefixed with
`/workspace/`.

By default, built-in writable binds stay plain `:rw` so non-SELinux hosts see
no relabel side-effects.  On SELinux hosts, pass `--selinux` to apply shared
relabeling (`:z`) to built-in writable binds.  User-provided `-v` options are
preserved exactly as supplied.

### Examples

```sh
agent-sandbox                                    # opencode, everything on
agent-sandbox --no-ssh                           # drop an integration
agent-sandbox --copilot                          # github-copilot-cli (copilot), everything on
agent-sandbox --antigravity                      # antigravity-cli (agy), everything on
agent-sandbox --no-workspace                     # no CWD mount
agent-sandbox --selinux                          # enable :z on built-in writable binds
agent-sandbox -- -- bash                           # interactive bash with all integrations
agent-sandbox -- -- devenv shell                   # devenv shell with opencode config mounted
agent-sandbox --privileged                         # nested podman inside container
```

## What's in the image

| Category      | Tools                                                |
| ------------- | ---------------------------------------------------- |
| AI coding     | opencode, claude-code, github-copilot-cli (copilot), antigravity-cli (agy) |
| Shell / tools | bash, coreutils, ripgrep, fd, jq, curl, wget, …     |
| Languages     | python3, uv, nodejs, gnumake, gcc libs               |
| Git / GitHub  | git, gh                                              |
| Nix           | nix, devenv                                          |
| Containers    | podman, crun, conmon, skopeo, slirp4netns,           |
|               | fuse-overlayfs, docker→podman alias                  |
| Editor        | vim                                                  |

Podman container config files (`containers.conf`, `storage.conf`,
`registries.conf`, `policy.json`) are baked in at `/etc/containers/`, so
nested rootless podman is pre-configured when the sandbox is launched with
`--privileged`.

## How it works

1. `agent-sandbox-ctl load` imports the OCI image (built with `pkgs.dockerTools.streamLayeredImage`) into the host's podman image store.
2. `agent-sandbox` calls `podman run` with `--userns=keep-id`, tmpfs mounts for ephemeral home subdirectories, explicit bind mounts for persistent state (opencode, devenv, …), and forwarded sockets (ssh, gpg, podman).
3. A slim entrypoint loads the Nix store registration so `nix` commands work from the start, sets up the gpg-agent symlink when requested, then `exec`s the container command.

## Trust model

By design, `agent-sandbox` includes options that pierce the sandbox boundary. Note that these give any agent running inside the container capabilities on the host:
- `--ssh` (on by default): The agent can authenticate as you using your forwarded SSH identity (e.g. `git push` to your repos).
- `--gpg-agent` (on by default): The agent can sign commits or authenticate with any key held by your host GnuPG agent. Note that `agent-sandbox` protects your private key files by checking for them and gracefully failing the GNUPG directory mount if they are present on disk, but the forwarded GnuPG agent socket is still accessible.
- `--podman` (opt-in): Forwards the host rootless podman socket. The agent can use this to launch **sibling containers** on the host, which is equivalent to a full sandbox escape (e.g. `podman run -v /:/host ...`).

#### Running Containers: `--podman` vs `--privileged`
If you want the agent to be able to run its own containers, `agent-sandbox` supports two distinct models:

1. **Nested Containers (Safe):** Pass `--privileged` when launching the sandbox. The sandbox image contains its own baked-in Podman stack. `--privileged` gives the sandbox container enough kernel permissions to run a securely isolated Podman daemon *inside* the sandbox. The agent cannot use this to escape to the host.
2. **Sibling Containers (Unsafe):** Pass `--podman` to forward your host's Podman socket into the sandbox. When the agent runs `podman run`, it talks to your host machine's Podman daemon. The container is created on the host alongside the sandbox. This does *not* require `--privileged`, but it allows the agent to control your host's containers and easily escape the sandbox. Use this only when you need the agent to interact with existing host infrastructure or leverage the host's image cache for performance.
