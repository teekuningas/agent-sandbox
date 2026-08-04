# agent-sandbox

Sandboxed AI coding environment that runs inside a rootless Podman container.
Launch `opencode` (or any other tool) with SSH agent, GPG signing, Git identity,
host Podman socket, and `devenv` state all wired through automatically.

## Install

### From a local clone

```sh
git clone https://github.com/your-org/agent-sandbox
cd agent-sandbox
nix profile add .#          # agent-sandbox, agent-sandbox-load, agent-sandbox-purge
```

### From a remote flake

```sh
nix profile add github:your-org/agent-sandbox
```

After installing, load the container image into podman (one-time):

```sh
agent-sandbox-load
```

`agent-sandbox-purge` removes the image and container state again.

## Usage

```
agent-sandbox [FLAGS] [PODMAN_ARGS...] [-- COMMAND...]
```

**With no arguments** `agent-sandbox` launches opencode inside the sandbox with
the current working directory mounted at `/workspace/<dirname>` (also the
working directory) and every integration enabled.  If the current directory
contains a `devenv.nix`, the agent is started through a devenv shell
(`devenv shell --no-tui -- opencode .`) so project dependencies are loaded
automatically.

### Override the container command

Everything after `--` replaces the default command:

```sh
agent-sandbox -- bash                            # interactive shell
agent-sandbox -- bash -c "nix build .# && echo done"
agent-sandbox -- devenv shell
```

### Pass podman flags

Anything before `--` that is not a known flag is passed straight to
`podman run`:

```sh
agent-sandbox --privileged                        # enable nested podman
agent-sandbox --network=host                      # host network
agent-sandbox --privileged -- bash                 # podman flag + bash
agent-sandbox --no-workspace -v ~/src:/workspace:rw   # custom workspace mount
```

### Flags

Every integration is **on by default**.  Disable with the matching `--no-*` flag.

| Flag                    | Default | What it does                                          |
| ----------------------- | ------- | ----------------------------------------------------- |
| `--workspace` / `--no-workspace` | on | mount `$PWD` as `/workspace/<dirname>:rw`              |
| `--ssh` / `--no-ssh`             | on | forward `SSH_AUTH_SOCK`                                |
| `--git` / `--no-git`             | on | mount `~/.gitconfig` and `~/.config/git/config`, forward `user.name`/`user.email` |
| `--gpg-agent` / `--no-gpg-agent` | on | forward host gpg-agent socket for commit signing       |
| `--gpg-sign` / `--no-gpg-sign`   | on | git commit signing (`--no-gpg-sign` forces it off)     |
| `--<agent>` / `--no-<agent>`     | on | mount that agent's config dirs (e.g. `--opencode`)     |
| `--agent NAME`                   |    | launch agent `NAME` instead of the default             |
| `--devenv` / `--no-devenv`       | on | mount `~/.local/share/devenv` across sessions          |
| `--nix` / `--no-nix`             | on | share the host `/nix` (read-only + host daemon for multi-user nix, overlay otherwise) |
| `--podman` / `--no-podman`       | on | forward host rootless podman socket (sibling containers) |

You can also pass `-v` / `-v*` volume mounts before `--`.  Relative paths in
the source are resolved against `$PWD`; relative destinations are prefixed with
`/workspace/`.

### Examples

```sh
agent-sandbox                                    # opencode, everything on
agent-sandbox --no-podman --no-ssh                # drop two integrations
agent-sandbox --no-workspace                      # no CWD mount
agent-sandbox -- bash                              # interactive bash with all integrations
agent-sandbox -- devenv shell                      # devenv shell with opencode config mounted
agent-sandbox --privileged                         # nested podman inside container
agent-sandbox --agent claude-code                  # launch a different agent
```

## Agents

An agent is a packaged CLI plus the home paths that persist its login state.
opencode is built in; add more from a downstream flake or NixOS config and pick
the default:

```nix
callPackage (inputs.agent-sandbox + "/default.nix") {
  defaultAgent = "claude-code";
  defaultArgs = [ "--no-podman" ];   # flags prepended to every invocation
  extraAgents = [{
    name = "claude-code";
    package = claude-code;
    command = [ "claude" ];
    state = [ ".claude" ];            # dirs to persist
    stateFiles = [ ".claude.json" ];  # files (initialised to {} if absent)
    # enable = false;                 # state not mounted unless --claude-code
  }];
}
```

Each agent gets `--<name>` / `--no-<name>` (config persistence) and is
launchable with `--agent <name>`.

## What's in the image

| Category      | Tools                                                |
| ------------- | ---------------------------------------------------- |
| AI coding     | opencode                                             |
| Shell / tools | bash, coreutils, ripgrep, fd, jq, curl, wget, …     |
| Languages     | python3, uv, nodejs, gnumake, gcc libs               |
| Git / GitHub  | git, git-lfs, gh, gnupg, openssh                     |
| Nix           | nix, devenv                                          |
| Containers    | podman, crun, conmon, skopeo, slirp4netns,           |
|               | fuse-overlayfs, docker→podman alias                  |
| Editor        | vim                                                  |

Podman container config files (`containers.conf`, `storage.conf`,
`registries.conf`, `policy.json`) are baked in at `/etc/containers/`, so
nested rootless podman is pre-configured when the sandbox is launched with
`--privileged`.

## How it works

1. `agent-sandbox-load` imports the OCI image (built with `pkgs.dockerTools.buildImage`) into the host's podman image store.
2. `agent-sandbox` calls `podman run` with `--userns=keep-id`, tmpfs mounts for ephemeral home subdirectories, explicit bind mounts for persistent state (agent config, devenv, host `/nix`, …), and forwarded sockets (ssh, gpg, podman).
3. A slim entrypoint prepares the container: it loads the Nix store registration when the host `/nix` is *not* shared, wires up the forwarded gpg-agent, seeds `~/.ssh/known_hosts` for common git forges, then `exec`s the container command.
