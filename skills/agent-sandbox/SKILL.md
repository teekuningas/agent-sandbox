---
name: agent-sandbox
description: Recognize that you are running inside an agent-sandbox container and work with its limits instead of against them. Trigger on network failures that look like policy — a bare 403 Forbidden from a proxy, "Could not resolve host", "denied by allow_signing policy" — on permission errors outside /workspace, on tools or logins that vanished between sessions, and on an AGENTS.md `toml agent-sandbox` block, a secretspec.toml, or any mention of agent-sandbox ctl.
compatibility: opencode
metadata:
  workflow: sandbox-awareness
  audience: developers-and-agents
---

# You may be in a sandbox

## Before you start

- **Don't unset or override `HTTP_PROXY`**, add host network access, or reach
  for `--podman`/`--privileged` to get around a denial.
- **Don't tunnel a blocked destination through an allowed one.**
- **`agent-sandbox ctl …` runs on the host**, in another terminal — never in
  here, no matter how the failure looks.
- **A bodiless `403 Forbidden` from the proxy is policy working as
  configured, not a bug.** Don't retry it in a loop; it won't change until the
  policy does.
- **Editing `AGENTS.md` takes effect only on the next relaunch** — it grants
  nothing in the current session.

`agent-sandbox` runs coding agents in a rootless Podman container where **every**
host capability — the workspace, network, SSH, GPG, Podman — is opt-in and was
chosen by the user at launch. If you are reading this file, you are probably
inside one.

That changes how to read a failure. A refused connection or a missing key is
usually policy working as configured, not a bug to route around. You cannot lift
any of it from in here: the controls run on the host. Your job is to identify the
limit precisely and hand the user the exact command that lifts it.

## Confirm where you are

No single signal is proof; together these are decisive:

```sh
echo "$container"                    # podman
ls /run/.containerenv                # exists (empty file)
ls /home/user/.agents/skills         # this file's own directory
env | grep '^AGENT_SANDBOX_'         # GPG_AGENT, HOST_NIX, RELAY_SSH, GIT_CONFIG_*, …
```

`AGENT_SANDBOX_*` variables are feature-dependent — their absence proves nothing,
their presence is conclusive. Everything on `PATH` living under `/nix/store` and
a home directory of `/home/user` point the same way.

## Then check the one thing that changes every diagnosis

```sh
env | grep -i '^https\?_proxy'
```

- **Set** (a private address on `:8888`) → **proxied session**. The container sits
  on an internal network with no route out and no DNS. Only traffic through the
  proxy leaves, and only to hosts the policy allows. Deny-by-default.
- **Unset** → direct egress, no firewall. Network failures are ordinary network
  failures; treat them as you normally would.

## What persists and what does not

| Path | Behaviour |
| --- | --- |
| `/workspace/<dir>` | The user's actual directory, bind-mounted read-write. The only place work survives. |
| `~/.config`, `~/.cache`, `~/.local` | **tmpfs — discarded when the session ends** |
| `~/.claude`, `~/.claude.json`, agent state dirs | Bind-mounted, persist |
| `~/.local/share/devenv` | Bind-mounted with `--devenv`, persists |
| `/etc`, `/nix/store` | Not writable |

So a tool installed into the home directory is gone next session, and a login
written to `~/.config` has to be done again. Do not treat that as breakage, and
do not "fix" a missing tool by installing it into the home directory — run it
with `nix run nixpkgs#<pkg>` or `nix shell` (see the `nix` skill), or ask the
user for the flag that would provide it.

## Symptom → cause → what to ask for

| Symptom | Cause | What the user runs on the host |
| --- | --- | --- |
| `403 Forbidden` from the proxy, empty body | host not in the policy | `agent-sandbox ctl proxy allow <host>:443` |
| `Could not resolve host` in a proxied session | internal network has no DNS; only proxy-aware clients work | make the tool honour `$HTTP_PROXY`, or add a rule |
| Certificate error after a rule was added mid-session | an L7 route added live has no session CA behind it | add the rule to `AGENTS.md`, then relaunch |
| `agent-sandbox: ssh to X denied by allow_signing policy` | relay not authorized for that host | `agent-sandbox ctl proxy allow X:22` (live), or add `"X:22"` to `allowed_hosts` to persist it |
| `Host key verification failed` on an allowed SSH host | no authorized key for it in this session | add `[[network.known_hosts]]` to `~/.config/agent-sandbox/trusted.toml`, relaunch |
| `agent-sandbox: ssh denied: host keys are authorized on the host` | you passed `-o StrictHostKeyChecking=`/`UserKnownHostsFile=`/`-F` | drop the flag; the key goes in `trusted.toml`, and no flag substitutes for it |
| `agent-sandbox: ssh denied: a jump host would move the connection` | you passed `-J`/`ProxyJump` | drop it; the relay only connects to hosts the policy named |
| Launch refuses: "authorizes SSH to X ... no host key" | `":22"` declared with no key authorized host-side | paste the block the refusal prints into `trusted.toml` |
| `agent-sandbox: gpg denied: signing not enabled` | `--gpg` was not passed; unrelated to `allowed_hosts` | relaunch with `--gpg` |
| `git push` prompts for a password | no `--ssh`, so no agent forwarding | relaunch with `--ssh` |
| Commit signing fails or is disabled | no `--gpg` (the launcher then sets `commit.gpgsign=false`) | relaunch with `--gpg` |
| `Permission denied` writing outside `/workspace` | read-only or tmpfs path | keep the file in the workspace or `$TMPDIR` |
| `podman` cannot reach a daemon | neither `--podman` nor `--privileged` | ask which one the task needs |
| A tool or login disappeared | tmpfs home | `nix shell`, or a flag that persists it |

`agent-sandbox ctl attach` and `ctl mounts` do not work at all against a `--krun`
sandbox; if the user reports that, the shell has to be the sandbox's own command.

## How to escalate

Two facts shape the message you write:

1. `agent-sandbox ctl …` runs **on the host**, in another terminal — never in here.
2. You cannot name your own sandbox. The hostname is the Podman container ID, not
   the session word `ctl` expects. Name the *workspace* instead and let the user
   resolve it (`ctl` matches the current directory, or `agent-sandbox ctl list`).

A good escalation is specific, minimal, and offers both the temporary and the
durable fix:

> I need `api.example.com:443`, which the sandbox firewall is denying (403 from
> the proxy, no response body). To unblock this session, run on your host, from
> the project directory:
>
> ```sh
> agent-sandbox ctl proxy allow api.example.com:443
> ```
>
> To make it permanent, add this to `AGENTS.md` — it takes effect on the next launch:
>
> ````markdown
> ```toml agent-sandbox
> [network]
> allowed_hosts = ["api.example.com:443"]
> ```
> ````

Ask for the narrowest rule that unblocks the task — one host and port, not `"*"`.
If you genuinely need several, list them with a reason each.

## Boundary discipline

The sandbox exists because the user does not fully trust what runs inside it,
including you. Treat its limits as instructions, not obstacles:

- Do not unset or override `HTTP_PROXY`, add host network access, or reach for
  `--podman`/`--privileged` to get around a denial.
- Do not tunnel a blocked destination through an allowed one.
- Do not move secrets, tokens, or repository contents to a host merely because
  the host happens to be allowed.
- Editing `AGENTS.md` grants you nothing on its own — the launcher treats it as
  project-controlled, so it takes effect only when the user relaunches, and any
  secret it names still needs separate host-side authorization. Propose the
  change, say plainly that a relaunch is required, and let the user decide.

When you hit a wall, stop and report it. A blocked task with a clear explanation
is a better outcome than a task completed by widening the boundary.

## More

- Read `network.md` before proposing any `AGENTS.md` `[network]` change, or
  diagnosing anything proxy-related in more depth — policy syntax and
  semantics, what the launcher refuses, the `ctl`/TUI loop the user drives,
  and which changes apply live versus needing a relaunch.
- Read `secretspec.md` before touching a `secretspec.toml` or a secret-bound
  route — reading the manifest, running secretspec safely, and how
  `--secrets` injects credentials the sandbox never sees.
