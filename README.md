# agent-sandbox

[![Docs](https://img.shields.io/badge/docs-GitHub_Pages-blue.svg)](https://datakurre.github.io/agent-sandbox/)

**Sandboxed AI coding environment** built on rootless Podman and Nix. Run AI coding agents in an isolated container — `opencode`, `claude`, `copilot`, `codex`, `antigravity`, or any bundled tool — and opt in only to the integrations you need. All integrations are **disabled by default**.

## Full Documentation

Please visit the **[documentation site](https://datakurre.github.io/agent-sandbox/)** for:

- [Usage & Flags](https://datakurre.github.io/agent-sandbox/usage/) — common patterns, flag reference, and `ctl` subcommands
- [Configuration](https://datakurre.github.io/agent-sandbox/configuration/) — `AGENTS.md` syntax for ports, mounts, and network policy
- [Trust Model](https://datakurre.github.io/agent-sandbox/trust-model/) — security implications of each flag
- [Architecture](https://datakurre.github.io/agent-sandbox/architecture/) — how the image, launcher, proxy, and relay fit together

## Quick start

```sh
git clone https://github.com/datakurre/agent-sandbox
cd agent-sandbox
nix profile add .#          # installs agent-sandbox
```

Or without cloning:

```sh
nix profile add github:datakurre/agent-sandbox
```

Either way, build the container image once before first use:

```sh
agent-sandbox ctl load
```

Then launch an agent:

```sh
# Interactive shell — every agent is on PATH, nothing from the host is exposed
agent-sandbox

# Mount your project and launch opencode
agent-sandbox --workspace opencode

# Add a deny-by-default network firewall enforced by this project's AGENTS.md
agent-sandbox --workspace --proxy opencode

# Use a reusable host-owned profile instead of AGENTS.md
agent-sandbox --workspace --proxy-profile development opencode

# Merge a reusable profile with AGENTS.md (additive)
agent-sandbox --workspace --proxy --proxy-profile development opencode

# Reattach to a running sandbox
agent-sandbox ctl attach

# Publish a port declared in AGENTS.md's [ports] block, and mount [mounts]
agent-sandbox --workspace --ports --mounts opencode

# Drive a visible, allow-listed browser from inside the sandbox
agent-sandbox browser &
agent-sandbox --workspace --browser -- claude
```

Every agent also gets built-in skills (`agent-sandbox`, `nix`, `nix-flake`, `devenv`, `browser`) baked into the image, so it already knows how the sandbox works. Advanced features like SSH forwarding (`--ssh`), GPG signing (`--gpg`), host Podman socket forwarding (`--podman`), and `devenv` integration are available but opt-in. See the full documentation for details.
