#!/usr/bin/env bash
# agent-sandbox launcher.  Wraps `podman run` with the host integrations the
# sandboxed agent needs, and nothing else.
#
# The Nix wrapper prepends definitions for AGENT_SANDBOX_IMAGE and
# AGENT_SANDBOX_NETWORK, and puts podman, git, and the agent-sandbox-* helpers
# on PATH.  Commands *inside* the container are named bare (opencode, claude,
# …) and resolve through the image's own PATH.



if ! podman image exists "$AGENT_SANDBOX_IMAGE" 2>/dev/null; then
  echo "agent-sandbox: image $AGENT_SANDBOX_IMAGE not found. Run 'agent-sandbox-ctl load' first." >&2
  exit 1
fi

# ── Defaults ────────────────────────────────────────────────────────────────
# Everything is off by default, including the integrations an agent needs to be
# useful in a normal git workflow.  Nothing pierces the sandbox boundary unless
# it was asked for, at the cost of a bare launcher doing very little: downstream
# tooling is expected to bake in its own defaults with wrapProgram --add-flags,
# which the user can still override because the last flag wins (see README).
want_ssh=0
want_git=0
want_gpg=0
want_gpg_private=0
want_devenv=0
want_nix=0
want_podman=0
want_workspace=0
want_selinux=0
want_ports=0
want_ports_dynamic=0
want_ports_any_interface=0
want_mounts=0
want_agent_mounts_mode="auto"   # auto | all | none | list
agent_mounts_list=()
want_proxy=0
want_krun=0
# Tracked separately from the podman_args passthrough, because --krun warns on it.
want_privileged=0

# Empty means "not asked for".  --krun defaults the memory below, once it is
# known that --krun is on at all; the CPU count is left to crun, which uses the
# process's CPU affinity capped at LIBKRUN_MAX_VCPUS.
krun_ram_mib=""
krun_cpus=""

agent=""
want_help=0

# The Nix wrapper pins this to an absolute store path, so podman never has to
# resolve a bare runtime name against containers.conf.  The bare name is only a
# fallback for running this script straight out of the tree.
if [[ -z "${AGENT_SANDBOX_KRUN_RUNTIME:-}" ]]; then
  AGENT_SANDBOX_KRUN_RUNTIME="krun"
fi

if [[ -z "${AGENT_SANDBOX_AGENT_SPECS:-}" ]]; then
  AGENT_SANDBOX_AGENT_SPECS=$'opencode\t["opencode","."]\t[".local/share/opencode",".config/opencode",".cache/opencode"]\t[]\nclaude-code\t["claude"]\t[".claude"]\t[".claude.json"]\ncopilot\t["copilot"]\t[".copilot"]\t[]\nantigravity\t["agy","."]\t[".local/share/antigravity-cli",".config/antigravity-cli",".cache/antigravity-cli",".gemini"]\t[]'
fi

declare -a agent_names=()
declare -A agent_cmd_json=()
declare -A agent_state_json=()
declare -A agent_state_files_json=()

while IFS=$'\t' read -r name cmd_json state_json state_files_json; do
  [[ -n "$name" ]] || continue
  agent_names+=("$name")
  agent_cmd_json["$name"]="$cmd_json"
  agent_state_json["$name"]="$state_json"
  agent_state_files_json["$name"]="$state_files_json"
done <<< "${AGENT_SANDBOX_AGENT_SPECS}"

agent_list="${agent_names[*]}"

usage() {
  cat <<USAGE
agent-sandbox [FLAGS] [AGENT] [-- COMMAND...]

Runs an AI coding agent inside a rootless podman container.
Use flags to opt-in to integrations like mounting the current directory,
forwarding SSH, or exposing Git identity.

  agent-sandbox                      launch interactive bash (no agent state mounted)
  agent-sandbox opencode             launch opencode with its own state mounted
  agent-sandbox --agent-mounts       launch interactive bash with every agent's state mounted
  agent-sandbox --podman opencode    launch opencode with podman enabled
  agent-sandbox opencode -- bash     launch bash with opencode's state mounted
  agent-sandbox --privileged opencode
                                     pass --privileged to podman run

Agents:
  ${agent_list}

Integrations (use --X to enable, --no-X to disable):
  --workspace       $([[ "$want_workspace" == "1" ]] && echo "[on ]" || echo "[off]") Mounts the host's current working directory into /workspace/<dirname>.
  --ssh             $([[ "$want_ssh" == "1" ]] && echo "[on ]" || echo "[off]") Forwards the host's SSH_AUTH_SOCK to the container.
  --git             $([[ "$want_git" == "1" ]] && echo "[on ]" || echo "[off]") Mounts host Git configurations and passes identity env vars.
  --gpg             $([[ "$want_gpg" == "1" ]] && echo "[on ]" || echo "[off]") Enables host GnuPG agent forwarding and git commit signing behavior.
  --gpg-private     $([[ "$want_gpg_private" == "1" ]] && echo "[on ]" || echo "[off]") Exposes ~/.gnupg even if it holds on-disk secret keys.
  --devenv          $([[ "$want_devenv" == "1" ]] && echo "[on ]" || echo "[off]") Persists ~/.local/share/devenv across sessions.
  --nix             $([[ "$want_nix" == "1" ]] && echo "[on ]" || echo "[off]") Mounts the host /nix/store for native Nix execution.
  --podman          $([[ "$want_podman" == "1" ]] && echo "[on ]" || echo "[off]") Forwards the host rootless Podman socket (sibling containers).
  --selinux         $([[ "$want_selinux" == "1" ]] && echo "[on ]" || echo "[off]") Applies SELinux shared relabeling (:z) to writable binds.
  --proxy           $([[ "$want_proxy" == "1" ]] && echo "[on ]" || echo "[off]") Routes HTTP(S)/SSH through a proxy, enforcing AGENTS.md's [proxy] policy if present (blocks direct internet access).
                         Also enables 'agent-sandbox-ctl net' for the running sandbox.
  --krun            $([[ "$want_krun" == "1" ]] && echo "[on ]" || echo "[off]") Runs the sandbox as a KVM microVM with its own kernel (needs /dev/kvm).
                         Adds a guest-kernel boundary inside the existing container boundary.
                         'agent-sandbox-ctl attach' and 'ctl mounts' do not work against a krun sandbox.

Ports:
  --port [HOST:]CONTAINER[/PROTO]          Publish a port, repeatable.
  --ports / --no-ports               $([[ "$want_ports" == "1" ]] && echo "[on ]" || echo "[off]") Honors [ports] declarations from AGENTS.md.
  --ports-dynamic                          Allows \`agent-sandbox-ctl ports add\` post-launch.
  --ports-any-interface                    Permits port binds outside of loopback interfaces.

Mounts:
  --mounts / --no-mounts             $([[ "$want_mounts" == "1" ]] && echo "[on ]" || echo "[off]") Honors [mounts] declarations from AGENTS.md.

Agent state:
  --agent-mounts                     $([[ "$want_agent_mounts_mode" == "all" ]] && echo "[on ]" || echo "[off]") Mount every agent's state, not just the one launched.
  --agent-mounts=AGENT[,AGENT...]    Mount only these agents' state (plus any launched agent). Only the "=" form takes a list.
  --no-agent-mounts                  Mount no agent state, even for the launched agent.

Podman / Environment:
  --privileged              pass --privileged to podman run (for nested podman)
  --krun-memory MiB         guest RAM under --krun (default 4096, must exceed 128)
  --krun-cpus N             guest vCPUs under --krun (1-16, default: host affinity)
  -e, --env NAME=VAL        pass environment variable to podman
  --podman-args=ARG         pass one arg to podman run; repeatable, and safe to
                            bake into a wrapper since it consumes nothing else
  --podman-args             treat all following args (until --) as podman args

--podman, --ssh and --gpg each hand the agent a capability that reaches
outside the sandbox. --podman forwards the host podman socket, allowing the
agent to create sibling containers on the host (a full sandbox escape).
To safely let the agent run containers, use --privileged instead to enable
securely nested containers inside the sandbox. See README for details.

--krun closes none of those three. It adds a guest kernel under the agent, so
code the agent runs faces a hypervisor before it faces the host kernel, but the
VM runs inside the same container namespaces and the same proxy topology as
before. It is not a substitute for leaving the three flags off.
USAGE
}

mounts=()
env_args=()
podman_args=()
cmd_args=()
port_specs=()

# ── Helpers ─────────────────────────────────────────────────────────────────

# Expand a mount spec from AGENTS.md [mounts]. Relative sources resolve against
# $PWD and relative destinations land under /workspace.
expand_v() {
  local spec="$1" src dest opts
  IFS=':' read -r src dest opts <<< "$spec"
  src="${src/#\~/$HOME}"
  [[ "$src" == "." ]] && src="$PWD"
  [[ "$src" != /* ]] && src="$PWD/$src"
  if [[ -z "$dest" ]]; then
    dest="$src"
  elif [[ "$dest" != /* ]]; then
    [[ "$dest" == "." ]] && dest="/workspace" || dest="/workspace/$dest"
  fi
  printf '%s\n' "$src:$dest${opts:+:$opts}"
}

# Bind a host path read-write, creating it first.  Used for every persistent
# tool-state directory, which is why they all pick up $rw_mount_opts together.
mount_rw() {
  local host="$1" container="$2"
  mkdir -p "$host"
  mounts+=("-v" "$host:$container:$rw_mount_opts")
}

# Validate a --port spec and normalise it to bind:host:container/proto.
parse_port_spec() {
  local spec="$1" host container proto=tcp
  if [[ "$spec" == */* ]]; then
    proto="${spec##*/}"
    spec="${spec%/*}"
  fi
  if [[ "$spec" == *:* ]]; then
    host="${spec%%:*}"
    container="${spec##*:}"
  else
    host="$spec"
    container="$spec"
  fi
  if [[ ! "$host" =~ ^[0-9]+$ || ! "$container" =~ ^[0-9]+$ ]]; then
    echo "agent-sandbox: --port '$1': expected [HOST:]CONTAINER[/PROTO]" >&2
    exit 1
  fi
  if (( host < 1 || host > 65535 || container < 1 || container > 65535 )); then
    echo "agent-sandbox: --port '$1': ports must be within 1-65535" >&2
    exit 1
  fi
  if [[ "$proto" != tcp && "$proto" != udp ]]; then
    echo "agent-sandbox: --port '$1': protocol must be tcp or udp" >&2
    exit 1
  fi
  printf '%s\n' "$bind_address:$host:$container/$proto"
}

# ── Flag parsing ────────────────────────────────────────────────────────────
# Phase 1: agent-sandbox flags and podman options. The first -- ends it.
# Phase 2: the command to run inside the container.

parsing_podman=0

while [[ $# -gt 0 ]]; do
  if [[ "$parsing_podman" == "1" ]]; then
    if [[ "$1" == "--" ]]; then
      parsing_podman=0
      shift
      cmd_args=("$@")
      break
    else
      podman_args+=("$1")
      shift
      continue
    fi
  fi

  if [[ -n "${agent_cmd_json[$1]:-}" ]]; then
    agent="$1"
    shift
    continue
  fi

  case "$1" in
    -h|--help)      want_help=1 ;;

    --ssh)          want_ssh=1 ;;
    --no-ssh)       want_ssh=0 ;;
    --git)          want_git=1 ;;
    --no-git)       want_git=0 ;;
    --gpg)          want_gpg=1 ;;
    --no-gpg)       want_gpg=0 ;;
    --gpg-private)    want_gpg_private=1 ;;
    --no-gpg-private) want_gpg_private=0 ;;
    --devenv)       want_devenv=1 ;;
    --no-devenv)    want_devenv=0 ;;
    --nix)          want_nix=1 ;;
    --no-nix)       want_nix=0 ;;
    --podman)       want_podman=1 ;;
    --no-podman)    want_podman=0 ;;
    --workspace)    want_workspace=1 ;;
    --no-workspace) want_workspace=0 ;;
    --selinux)      want_selinux=1 ;;
    --no-selinux)   want_selinux=0 ;;

    --ports)        want_ports=1 ;;
    --no-ports)     want_ports=0 ;;
    --ports-dynamic)    want_ports_dynamic=1 ;;
    --no-ports-dynamic) want_ports_dynamic=0 ;;
    --ports-any-interface) want_ports_any_interface=1 ;;
    --mounts)           want_mounts=1 ;;
    --no-mounts)        want_mounts=0 ;;
    --agent-mounts)      want_agent_mounts_mode="all" ;;
    --no-agent-mounts)   want_agent_mounts_mode="none" ;;
    --agent-mounts=*)
      want_agent_mounts_mode="list"
      IFS=',' read -r -a agent_mounts_list <<< "${1#--agent-mounts=}"
      for a in "${agent_mounts_list[@]}"; do
        [[ -n "${agent_cmd_json[$a]:-}" ]] || {
          echo "agent-sandbox: --agent-mounts: unknown agent '$a' (valid: ${agent_list})" >&2
          exit 1
        }
      done
      ;;
    --proxy)            want_proxy=1 ;;
    --no-proxy)         want_proxy=0 ;;
    --port)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox: --port needs an argument" >&2; exit 1; }
      port_specs+=("$1")
      ;;
    --port=*)       port_specs+=("${1#--port=}") ;;

    --krun)         want_krun=1 ;;
    --no-krun)      want_krun=0 ;;
    --krun-memory)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox: --krun-memory needs an argument" >&2; exit 1; }
      krun_ram_mib="$1"
      ;;
    --krun-memory=*) krun_ram_mib="${1#--krun-memory=}" ;;
    --krun-cpus)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox: --krun-cpus needs an argument" >&2; exit 1; }
      krun_cpus="$1"
      ;;
    --krun-cpus=*)  krun_cpus="${1#--krun-cpus=}" ;;

    -v|-v*)
      echo "agent-sandbox: '$1' is not an agent-sandbox flag." >&2
      echo "               Use podman passthrough instead:" >&2
      echo "               agent-sandbox --podman-args $1 ... -- <command>" >&2
      exit 1
      ;;

    --podman-args=*)
      podman_args+=("${1#--podman-args=}")
      ;;
    --podman-args)
      parsing_podman=1
      ;;
    --privileged)
      want_privileged=1
      podman_args+=("--privileged")
      ;;
    -e|--env)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox: -e/--env needs an argument" >&2; exit 1; }
      env_args+=("-e" "$1")
      ;;
    -e*)
      env_args+=("-e" "${1#-e}")
      ;;
    --env=*)
      env_args+=("-e" "${1#--env=}")
      ;;

    --) 
      shift
      cmd_args=("$@")
      break
      ;;

    --*)
      echo "agent-sandbox: '$1' is not an agent-sandbox flag." >&2
      echo "               To pass a podman flag: agent-sandbox --podman-args=$1" >&2
      exit 1
      ;;
    *)
      echo "agent-sandbox: unexpected argument '$1'." >&2
      echo "               Valid agents: ${agent_list}" >&2
      exit 1
      ;;
  esac
  shift
done

if [[ "$want_help" == "1" ]]; then
  usage
  exit 0
fi

# ── --krun preflight ────────────────────────────────────────────────────────
# Checked here: after parsing, so the flags are final, and before anything is
# created -- no temp dirs, no network, no relabel -- so a refusal leaves nothing
# behind.  Same discipline as the --proxy/--port conflict check further down.
#
# Ordered cheapest and most portable first.  The /dev/kvm probe is last because
# it is the one check that depends on the machine rather than on the arguments,
# and putting it there keeps every refusal above it reachable in a test harness.
if [[ "$want_krun" == "1" ]]; then
  # A hypervisor around a forwarded host podman socket is theatre: the socket is
  # a full escape on its own, and the guest reaches it through the same virtio-fs
  # tree as everything else.
  if [[ "$want_podman" == "1" ]]; then
    echo "agent-sandbox: --krun cannot be combined with --podman." >&2
    echo "               --podman forwards the host podman socket, which is a full" >&2
    echo "               sandbox escape whether or not the sandbox is a VM." >&2
    echo "               Use --privileged for containers nested inside the guest." >&2
    exit 1
  fi

  # crun discards a krun.ram_mib of *exactly* LIBKRUN_MINIMUM_RAM_MIB or less
  # (the check is `<=`, not `<`) and falls back to the OCI memory limit and then
  # to 1 GiB, without printing anything.  Refusing here is the only way the user
  # learns that the number they chose was ignored.
  if [[ -n "$krun_ram_mib" ]]; then
    if [[ ! "$krun_ram_mib" =~ ^[0-9]+$ ]] || [[ "$krun_ram_mib" -le 128 ]]; then
      echo "agent-sandbox: --krun-memory needs a whole number of MiB greater than 128." >&2
      echo "               Got '$krun_ram_mib'.  libkrun silently discards anything at" >&2
      echo "               or below its 128 MiB minimum and falls back to 1024, so a" >&2
      echo "               smaller value would look accepted and would not be." >&2
      exit 1
    fi
  else
    # crun's own default is 1024, which a Node-based agent will not survive.
    krun_ram_mib=4096
  fi

  if [[ -n "$krun_cpus" ]]; then
    if [[ ! "$krun_cpus" =~ ^[0-9]+$ ]] || [[ "$krun_cpus" -lt 1 ]] || [[ "$krun_cpus" -gt 16 ]]; then
      echo "agent-sandbox: --krun-cpus needs a whole number between 1 and 16." >&2
      echo "               Got '$krun_cpus'.  16 is libkrun's LIBKRUN_MAX_VCPUS." >&2
      exit 1
    fi
  fi

  # Warnings, not errors: neither has been measured against a real guest, and
  # guessing wrong in the refusing direction would block the two workloads the
  # flag exists for.
  # Measured, not guessed: libkrunfw does carry overlay and fuse, so the kernel
  # is not the obstacle.  Podman inside the guest sees uid 0 and reaches for
  # rootful storage under /var/lib, which virtio-fs then refuses because the VMM
  # writes as your unprivileged uid.  Left as a warning rather than a refusal --
  # it is a storage-location problem, and pointing podman elsewhere fixes it.
  if [[ "$want_privileged" == "1" ]]; then
    echo "agent-sandbox: warning: nested podman inside a --krun guest needs storage" >&2
    echo "               configuration that is not done for you.  The guest kernel has" >&2
    echo "               overlay and fuse, but the agent is uid 0 inside the guest, so" >&2
    echo "               podman defaults to /var/lib/containers -- which virtio-fs will" >&2
    echo "               not create, because the VMM writes as your host uid." >&2
  fi
  # Not a refusal: :z relabeling of the binds still happens and still matters.
  # It is the *process* label that has to go, and saying so is the point --
  # otherwise --selinux would look like it confines the sandbox when it does not.
  if [[ "$want_selinux" == "1" ]]; then
    echo "agent-sandbox: note: --krun runs the sandbox with 'label=disable'." >&2
    echo "               --selinux still relabels the bind mounts (:z), but the sandbox" >&2
    echo "               process itself cannot be SELinux-confined: the kernel refuses a" >&2
    echo "               domain transition once libkrun has spawned the VM's threads," >&2
    echo "               and the guest would not boot at all with labeling left on." >&2
  fi

  if ! "$AGENT_SANDBOX_KRUN_RUNTIME" --version 2>/dev/null | grep -q '+LIBKRUN'; then
    echo "agent-sandbox: $AGENT_SANDBOX_KRUN_RUNTIME was built without libkrun." >&2
    echo "               --krun needs a crun with +LIBKRUN in 'crun --version'." >&2
    exit 1
  fi

  if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    echo "agent-sandbox: --krun needs read/write access to /dev/kvm." >&2
    echo "               Check that the host has KVM (nested virtualisation is often" >&2
    echo "               off in cloud VMs) and that you are in the 'kvm' group." >&2
    exit 1
  fi
fi

if [[ -z "$agent" && ${#cmd_args[@]} -eq 0 ]]; then
  cmd_args=(bash)
fi

rw_mount_opts="rw"
if [[ "$want_selinux" == "1" ]]; then
  rw_mount_opts="rw,z"
fi

bind_address="127.0.0.1"
if [[ "$want_ports_any_interface" == "1" ]]; then
  bind_address="0.0.0.0"
fi

# ── Agent selection ─────────────────────────────────────────────────────────
if [[ -z "$agent" ]]; then
  agent_argv=()
else
  mapfile -t agent_argv < <(jq -r '.[]' <<< "${agent_cmd_json[$agent]}")
fi

# A devenv.nix in the workspace means project dependencies belong on PATH
# before the agent starts.
if [[ ${#cmd_args[@]} -eq 0 && -n "$agent" ]]; then
  if [[ -f "$PWD/devenv.nix" ]]; then
    cmd_args=(devenv shell --no-tui -- "${agent_argv[@]}")
  else
    cmd_args=("${agent_argv[@]}")
  fi
fi

# ── Workspace ───────────────────────────────────────────────────────────────

if [[ "$want_workspace" == "1" ]]; then
  workspace_name=$(basename "$PWD")
  workspace_dir="/workspace/$workspace_name"
  mounts+=("-v" "$PWD:$workspace_dir:$rw_mount_opts")
else
  workspace_dir="/workspace"
fi

# ── Agent state ─────────────────────────────────────────────────────────────
# By default only the positionally-selected agent's state is mounted, so we
# avoid creating host-side state directories for tools that never run.
# --agent-mounts widens this (to all agents, or a chosen subset) for
# interactive shells that want more than one tool available; --no-agent-mounts
# mounts none, even if an agent was selected.
declare -A agent_mount_set=()
case "$want_agent_mounts_mode" in
  none) : ;;
  all)  for a in "${agent_names[@]}"; do agent_mount_set["$a"]=1; done ;;
  list) for a in "${agent_mounts_list[@]}"; do agent_mount_set["$a"]=1; done
        [[ -n "$agent" ]] && agent_mount_set["$agent"]=1 ;;
  auto) [[ -n "$agent" ]] && agent_mount_set["$agent"]=1 ;;
esac

for a in "${!agent_mount_set[@]}"; do
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    mount_rw "$HOME/$rel" "/home/user/$rel"
  done < <(jq -r '.[]' <<< "${agent_state_json[$a]}")

  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    [[ -s "$HOME/$rel" ]] || printf '{}\n' > "$HOME/$rel"
    mounts+=("-v" "$HOME/$rel:/home/user/$rel:$rw_mount_opts")
  done < <(jq -r '.[]' <<< "${agent_state_files_json[$a]}")
done

# ── SSH ─────────────────────────────────────────────────────────────────────

if [[ "$want_ssh" == "1" && -S "${SSH_AUTH_SOCK:-}" ]]; then
  mounts+=("-v" "$SSH_AUTH_SOCK:/agent.sock:$rw_mount_opts")
  env_args+=("-e" "SSH_AUTH_SOCK=/agent.sock")
fi

# ── Git ─────────────────────────────────────────────────────────────────────

if [[ "$want_git" == "1" ]]; then
  git_config_mounted=0
  if [[ -f "$HOME/.gitconfig" ]]; then
    mounts+=("-v" "$HOME/.gitconfig:/home/user/.gitconfig:ro")
    git_config_mounted=1
  fi
  if [[ -f "$HOME/.config/git/config" ]]; then
    mounts+=("-v" "$HOME/.config/git/config:/home/user/.config/git/config:ro")
    git_config_mounted=1
  fi
  if [[ "$git_config_mounted" == "1" ]]; then
    git_name=$(git config --global user.name 2>/dev/null || true)
    git_email=$(git config --global user.email 2>/dev/null || true)
    [[ -n "$git_name" ]]  && env_args+=("-e" "GIT_AUTHOR_NAME=$git_name"   "-e" "GIT_COMMITTER_NAME=$git_name")
    [[ -n "$git_email" ]] && env_args+=("-e" "GIT_AUTHOR_EMAIL=$git_email" "-e" "GIT_COMMITTER_EMAIL=$git_email")
  fi
fi

# ── GnuPG ───────────────────────────────────────────────────────────────────
# The agent socket is forwarded so host keys can sign commits.  The keyring
# directory is a separate decision: it is only exposed when it holds no usable
# secret on disk (the smart-card case), unless --gpg-private overrides.

if [[ "$want_gpg" == "1" ]]; then
  if command -v gpgconf >/dev/null 2>&1; then
    gpg_socket=$(gpgconf --list-dir agent-socket 2>/dev/null || true)
  fi
  gpg_socket="${gpg_socket:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/gnupg/S.gpg-agent}"
  if [[ -S "$gpg_socket" ]]; then
    mounts+=("-v" "$gpg_socket:/run/host-gpg-agent:ro")
    env_args+=("-e" "AGENT_SANDBOX_GPG_AGENT=1")
  fi

  if [[ -d "$HOME/.gnupg" ]]; then
    gnupg_offenders=""
    gnupg_status=0
    gnupg_offenders=$(agent-sandbox-gnupg-scan "$HOME/.gnupg") || gnupg_status=$?

    if [[ "$gnupg_status" == "0" || "$want_gpg_private" == "1" ]]; then
      if [[ "$gnupg_status" != "0" ]]; then
        echo "agent-sandbox: exposing ~/.gnupg with on-disk secret keys (--gpg-private)." >&2
      fi
      # Public material only: the keyring so gpg can name the signing key, and
      # the trust database so it believes the answer.
      for keyring in pubring.kbx pubring.gpg trustdb.gpg; do
        if [[ -f "$HOME/.gnupg/$keyring" ]]; then
          mounts+=("-v" "$HOME/.gnupg/$keyring:/run/host-gnupg/$keyring:ro")
        fi
      done
      if [[ "$want_gpg_private" == "1" && -d "$HOME/.gnupg/private-keys-v1.d" ]]; then
        mounts+=("-v" "$HOME/.gnupg/private-keys-v1.d:/run/host-gnupg/private-keys-v1.d:ro")
      fi
    else
      echo "agent-sandbox: not exposing ~/.gnupg -- it holds secret keys on disk:" >&2
      while IFS= read -r offender; do
        printf '               %s\n' "$offender" >&2
      done <<< "$gnupg_offenders"
      echo "               A smart-card setup keeps only stubs here and is exposed normally." >&2
      echo "               Override with --gpg-private, or silence this with --no-gpg." >&2
      exit 1
    fi
  fi
fi

if [[ "$want_gpg" == "0" ]]; then
  env_args+=("-e" "GIT_CONFIG_COUNT=1")
  env_args+=("-e" "GIT_CONFIG_KEY_0=commit.gpgsign")
  env_args+=("-e" "GIT_CONFIG_VALUE_0=false")
fi

# ── devenv / nix ────────────────────────────────────────────────────────────

if [[ "$want_devenv" == "1" ]]; then
  mount_rw "$HOME/.local/share/devenv" /home/user/.local/share/devenv
fi

if [[ "$want_nix" == "1" ]]; then
  daemon_socket=/nix/var/nix/daemon-socket/socket
  if [[ -S "$daemon_socket" ]]; then
    # Multi-user nix: read-only store, builds delegated to the host daemon.
    mounts+=("-v" "/nix/store:/nix/store:ro")
    mounts+=("-v" "$daemon_socket:/nix/var/nix/daemon-socket/socket:$rw_mount_opts")
    env_args+=("-e" "NIX_REMOTE=daemon")
  elif [[ -d /nix/store ]]; then
    # Single-user nix: overlay, so the container can write without touching
    # the host store.
    mounts+=("-v" "/nix:/nix:O")
  fi
  env_args+=("-e" "AGENT_SANDBOX_HOST_NIX=1")
fi

# ── Host podman socket ──────────────────────────────────────────────────────

if [[ "$want_podman" == "1" ]]; then
  host_socket="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
  if [[ -S "$host_socket" ]]; then
    mounts+=("-v" "$host_socket:/run/podman/podman.sock:$rw_mount_opts")
    env_args+=("-e" "CONTAINER_HOST=unix:///run/podman/podman.sock")
    env_args+=("-e" "DOCKER_HOST=unix:///run/podman/podman.sock")
  else
    echo "agent-sandbox: --podman requested but no socket at $host_socket." >&2
    echo "               Start it with: systemctl --user start podman.socket" >&2
  fi
fi

# ── Ports ───────────────────────────────────────────────────────────────────
# Two sources, both ending as validated bind:host:container/proto triples.
# Nothing from AGENTS.md is ever passed to podman as an argument of its own.

publish_args=()
published=()

for spec in "${port_specs[@]}"; do
  triple=$(parse_port_spec "$spec")
  publish_args+=("-p" "$triple")
  published+=("$triple")
done

if [[ "$want_ports" == "1" && -f "$PWD/AGENTS.md" ]]; then
  parse_flags=()
  [[ "$want_ports_any_interface" == "1" ]] && parse_flags+=(--ports-any-interface)
  if ! declared=$(agent-sandbox-parse-agents "${parse_flags[@]}" "$PWD/AGENTS.md"); then
    echo "agent-sandbox: refusing to launch on an invalid [ports] block (use --no-ports to skip)." >&2
    exit 1
  fi
  while IFS= read -r triple; do
    [[ -n "$triple" ]] || continue
    publish_args+=("-p" "$triple")
    published+=("$triple")
  done <<< "$declared"
fi

if [[ "$want_mounts" == "1" && -f "$PWD/AGENTS.md" ]]; then
  if ! declared_mounts=$(agent-sandbox-parse-agents --mounts "$PWD/AGENTS.md"); then
    echo "agent-sandbox: refusing to launch on an invalid [mounts] block (use --no-mounts to skip)." >&2
    exit 1
  fi
  while IFS= read -r spec; do
    [[ -n "$spec" ]] || continue
    mounts+=("-v" "$(expand_v "$spec")")
  done <<< "$declared_mounts"
fi

# Publishing a port and running a proxy are mutually exclusive, because the two
# network topologies contradict each other.  The shared network below is a normal
# NAT bridge, and the sandbox would be attached to it *as well as* the proxy's
# --internal network -- giving it a route to the internet that does not pass
# through the proxy at all.  The firewall would still filter what went through
# it, and everything else would simply go around.
#
# Checked here: after the [ports] block is parsed, so a declaration that yields
# nothing is not treated as a request, and before any network is created, so the
# refusal leaves nothing behind.
if [[ "$want_proxy" == "1" ]]; then
  conflict=""
  if [[ ${#published[@]} -gt 0 ]]; then
    conflict="a published port (${published[0]})"
  elif [[ "$want_ports_dynamic" == "1" ]]; then
    conflict="--ports-dynamic"
  fi

  if [[ -n "$conflict" ]]; then
    echo "agent-sandbox: --proxy cannot be combined with $conflict." >&2
    echo "               A published port puts the sandbox on the shared bridge network," >&2
    echo "               which routes to the internet around the proxy, so the policy" >&2
    echo "               would only be advisory." >&2
    echo "               Drop the port, or drop --proxy." >&2
    exit 1
  fi
fi

# A shared network is what makes `agent-sandbox-ctl ports add` possible later:
# podman cannot add a binding to a running container, so a sidecar has to
# reach this one by name.  Created lazily so that a launch with no ports at
# all keeps podman's default rootless networking untouched.
network_args=()
if [[ ${#published[@]} -gt 0 || "$want_ports_dynamic" == "1" ]]; then
  if ! podman network exists "$AGENT_SANDBOX_NETWORK" 2>/dev/null; then
    podman network create "$AGENT_SANDBOX_NETWORK" >/dev/null
  fi
  network_args=(--network "$AGENT_SANDBOX_NETWORK")
fi

if [[ ${#published[@]} -gt 0 ]]; then
  echo "agent-sandbox: publishing ${published[*]}" >&2
  echo "               (a server inside must bind 0.0.0.0, not 127.0.0.1)" >&2
fi

# ── Identity ────────────────────────────────────────────────────────────────

# Temp passwd/group so tools resolve the username inside the container.
passwd_tmp=$(mktemp)
group_tmp=$(mktemp)

# Declared before the trap is installed: it fires on any signal, including one
# that arrives between here and the sidecar block below, and under nounset an
# unset variable would abort the trap partway through cleaning up.
sidecar_id=""
sidecar_shared=""
sidecar_policy=""

cleanup() {
  rm -f "$passwd_tmp" "$group_tmp"
  if [[ -n "$sidecar_id" ]]; then
    podman stop -t 1 "$sidecar_id" >/dev/null 2>&1 || true
    # Not --rm: a sidecar that exits before signalling readiness has to stay
    # around long enough for `podman logs` to say why.
    podman rm -f "$sidecar_id" >/dev/null 2>&1 || true

    # || true: this runs inside the EXIT trap under errexit, and the rm -rf
    # below still has to happen even if the report cannot be rendered.
    agent-sandbox-network-summary "$sidecar_shared/connections.jsonl" || true
    # The rm -rf below would take the per-connection timings with it, and
    # those are what distinguish "failed instantly" from "burned the whole
    # retry window".  Keep the log whenever anything went wrong.
    if grep -q '"verdict":"\(deny\|error\)"' "$sidecar_shared/connections.jsonl" 2>/dev/null; then
      saved_log="${TMPDIR:-/tmp}/agent-sandbox-connections-$$.jsonl"
      if cp "$sidecar_shared/connections.jsonl" "$saved_log" 2>/dev/null; then
        printf '  connection log kept at %s\n\n' "$saved_log"
      fi
    fi

    # podman tears a --rm container down asynchronously after `stop` returns, so
    # a single attempt here loses the race often enough to leak one --internal
    # network per session -- and each of those holds a subnet from the rootless
    # pool until `agent-sandbox-ctl purge` reclaims it.
    for _ in $(seq 1 20); do
      podman network rm "$sidecar_id" >/dev/null 2>&1 && break
      podman network exists "$sidecar_id" 2>/dev/null || break
      sleep 0.25
    done

    [[ -n "$sidecar_shared" ]] && rm -rf "$sidecar_shared"
    [[ -n "$sidecar_policy" ]] && rm -rf "$sidecar_policy"
  fi
}
trap cleanup EXIT
printf 'root:x:0:0:root:/root:/bin/sh\nuser:x:%s:%s::/home/user:/bin/bash\nnobody:x:65534:65534:Nobody:/:/bin/sh\n' "$(id -u)" "$(id -g)" > "$passwd_tmp"
printf 'root:x:0:\nuser:x:%s:\nnobody:x:65534:\n' "$(id -g)" > "$group_tmp"
# World-readable like a real /etc/passwd (no secrets in it): mktemp's default
# 0600 can end up unreadable to the container's mapped uid across extra
# user-namespace layers (nested sandboxes, hosts with no /etc/subuid range),
# which otherwise surfaces as ssh/git failing to resolve "who am I".
chmod 644 "$passwd_tmp" "$group_tmp"

# Include the workspace path and a short random word in the container name so
# agent-sandbox-ctl can identify sandboxes without guessing network/PID
# relationships. The word is the user-facing selector accepted by ctl.
workspace_slug=$(basename "$PWD")
workspace_slug="${workspace_slug//[^A-Za-z0-9_.-]/-}"

# A short word is easier to read and copy than a numeric identifier. Keep the
# pool deliberately larger than the usual number of concurrent sandboxes.
session_words=(autumn hidden bitter misty silent empty dry dark summer icy delicate quiet white cool spring winter patient twilight dawn crimson wispy weathered blue billowing broken cold damp falling frosty green long late lingering bold little morning muddy old red rough still small sparkling throbbing shy wandering withered wild black young holy solitary fragrant aged snowy proud floral restless divine polished ancient purple lively nameless)
existing_sandbox_names=()
mapfile -t existing_sandbox_names < <(
  podman ps -a --filter "label=agent-sandbox.role=sandbox" --format '{{.Names}}' 2>/dev/null || true
)
session_word=""
for _ in $(seq 1 100); do
  candidate_word="${session_words[$((RANDOM % ${#session_words[@]}))]}"
  candidate_used=0
  for existing_name in "${existing_sandbox_names[@]}"; do
    if [[ "$existing_name" == *-"$candidate_word" ]]; then
      candidate_used=1
      break
    fi
  done
  if [[ "$candidate_used" == "0" ]]; then
    session_word="$candidate_word"
    break
  fi
done
if [[ -z "$session_word" ]]; then
  echo "agent-sandbox: could not allocate a unique session word" >&2
  exit 1
fi

container_name="agent-sandbox-${workspace_slug:0:32}-${session_word}"

# ── Sidecar Proxy & Metering ────────────────────────────────────────────────
if [[ "$want_proxy" == "1" ]]; then
  sidecar_id="agent-sandbox-sidecar-$(head -c 12 /proc/sys/kernel/random/uuid 2>/dev/null || echo $$)"
  # Identifiable templates, so `agent-sandbox-ctl purge` can recognise the dirs
  # left behind by a launcher that was killed before its trap could run.
  sidecar_shared=$(mktemp -d -t "agent-sandbox-sidecar-XXXXXXXX")
  sidecar_policy=$(mktemp -d -t "agent-sandbox-policy-XXXXXXXX")
  # --disable-dns is load-bearing, not tidiness.  Podman routes a container's
  # whole resolver through aardvark-dns as soon as *any* of its networks has
  # dns_enabled -- podman-run(1), under --dns: "passing a custom network whose
  # dns_enabled is set to true to --network will result in /etc/resolv.conf only
  # referring to the aardvark-dns server".  And aardvark has refused to forward
  # for --internal networks since 1.11.0 ("Do not allow 'internal' networks to
  # access DNS"), so the sidecar's only nameserver would be one that answers
  # NXDOMAIN to every external name.  That is the "dns: Name or service not
  # known" 502, and it is why the --dns servers below were inert: they were
  # demoted to an aardvark upstream that aardvark then declined to use.
  #
  # With DNS off on both of the sidecar's networks there is no aardvark in the
  # path at all and --dns lands in resolv.conf verbatim.  The cost is that the
  # sandbox can no longer resolve the sidecar by container name, which is why
  # HTTP_PROXY is addressed by IP further down.
  #
  # Not `|| true`: the known failure is a rootless subnet pool exhausted by
  # leaked networks, and swallowing it just moves the error to `podman run`,
  # where it reads as an unrelated problem.
  if ! podman network create --internal --disable-dns "$sidecar_id" >/dev/null; then
    echo "agent-sandbox: could not create the sidecar network $sidecar_id" >&2
    echo "               (leaked networks exhaust the rootless subnet pool:" >&2
    echo "                reclaim them with 'agent-sandbox-ctl purge')" >&2
    exit 1
  fi

  # The sidecar is also on the default bridge (below), so the proxy binding
  # 0.0.0.0 would be reachable from any other container of the same user on
  # that network.  Handing the sidecar its own internal-network subnet lets it
  # bind only the address it has there instead -- see agent-sandbox-sidecar.sh.
  sidecar_subnet=$(podman network inspect "$sidecar_id" \
    --format '{{(index .Subnets 0).Subnet}}' 2>/dev/null) || sidecar_subnet=""
  if [[ -z "$sidecar_subnet" ]]; then
    echo "agent-sandbox: could not determine the subnet of $sidecar_id" >&2
    exit 1
  fi

  # The policy file is the single channel by which policy reaches the proxy.  It
  # replaced four separately-encoded arguments, where a space-separated list met a
  # comma-separated parser and every entry past the first was silently dropped --
  # which for an allow list means allowing everything.
  #
  # Written into a directory mounted ro into the sidecar and NOT into the sandbox:
  # the agent must not be able to widen the firewall that contains it.
  : > "$sidecar_policy/policy"
  if [[ -f "$PWD/AGENTS.md" ]]; then
    # Strict, like the [ports] block above: a policy the operator got wrong must
    # not silently become no policy at all.
    if ! agent-sandbox-parse-agents --proxy-policy "$PWD/AGENTS.md" \
         > "$sidecar_policy/policy"; then
      echo "agent-sandbox: refusing to launch on an invalid [proxy] block (use --no-proxy to skip)." >&2
      exit 1
    fi
  fi

  # Refused in every mode -- --proxy, with or without any
  # user rule -- so a proxy with no rules (or deny-only rules) cannot be used to
  # reach the host or its LAN.  The sidecar sits on the default bridge alongside
  # the proxy; the sandbox has no route there at all, but it can ask the proxy
  # to go there on its behalf.  Written as ordinary deny_ips entries into the
  # same file the proxy reads and the sidecar mirrors into kernel blackhole
  # routes (sync_routes), so this is the only place this list is written
  # down.  An allow_ips entry of equal or greater specificity overrides one of
  # these -- see is_allowed_ip/is_denied_address in proxy/src/main.rs.
  baseline_deny_ips=(
    127.0.0.0/8 ::1/128 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
    169.254.0.0/16 100.64.0.0/10 0.0.0.0/8 fc00::/7 fe80::/10
  )
  for cidr in "${baseline_deny_ips[@]}"; do
    printf 'deny_ips %s\n' "$cidr" >> "$sidecar_policy/policy"
    # policy.baseline records just the launcher-added entries so that
    # `agent-sandbox-ctl proxy export` can omit them: they are always enforced
    # regardless of what AGENTS.md declares, so round-tripping them is misleading.
    printf 'deny_ips %s\n' "$cidr" >> "$sidecar_policy/policy.baseline"
  done

  # Kept pristine so `agent-sandbox-ctl proxy reset` has something to restore
  # and `proxy show` can tell declared rules from ones added at runtime.
  # The baseline above is included, so a reset cannot lose it either.
  cp "$sidecar_policy/policy" "$sidecar_policy/policy.base"

  # (domains|ips) only: allow_ports alone does not make the policy
  # deny-by-default -- only allow_domains/allow_ips do, and in the branch
  # below allow_ports is unrestricted too, not the 80/443/22 default.
  if ! grep -qE '^allow_(domains|ips) ' "$sidecar_policy/policy"; then
    echo "agent-sandbox: --proxy is active with no allow rules, so every host is allowed" >&2
    echo "               on every port. Declare allow_domains/allow_ips (and optionally" >&2
    echo "               allow_ports) in a [proxy] block to restrict it." >&2
  fi

  # NET_ADMIN backs the blackhole routes installed for deny_ips.  Metering used
  # to also need NET_RAW for packet capture; it is now accounted by the proxy.
  sidecar_caps=("--cap-add=NET_ADMIN")

  # Nameservers for the sidecar, read from the host.  With DNS disabled on both
  # of its networks (see --disable-dns above) these land in the container's
  # /etc/resolv.conf verbatim and are queried directly, rather than becoming an
  # upstream for an aardvark that would refuse to use it.
  #
  # Only bare IP literals survive the filter.  A scoped address -- "fe80::1%eth0",
  # which RA-configured hosts do write -- is rejected by podman, and a rejected
  # --dns takes the whole sidecar down.  Loopback and link-local entries are
  # dropped for a different reason: they name a resolver on the *host's* stack,
  # which is not reachable from the container's netns.
  usable_nameservers() { # FILE
    [[ -r "$1" ]] || return 0
    local line candidate lower
    # `|| [[ -n "$line" ]]` so a file with no trailing newline does not lose its
    # last entry -- silently dropping a nameserver is how this whole area got
    # its reputation.
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ ^[[:space:]]*nameserver[[:space:]]+([^[:space:]]+) ]] || continue
      candidate="${BASH_REMATCH[1]}"
      lower="${candidate,,}"
      case "$lower" in
        127.*|169.254.*|::1|fe80:*|*%*) continue ;;
      esac
      [[ "$candidate" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$candidate" =~ ^[0-9A-Fa-f:]+$ ]] \
        || continue
      printf '%s\n' "$candidate"
    done < "$1"
  }

  # `search` (and its legacy `domain` spelling) from the same file, so an
  # unqualified name that resolves on the host resolves in the sidecar too.
  # Carrying the nameservers without them leaves a split-horizon setup half
  # configured: the resolver knows the internal zone, the query never names it,
  # and the proxy answers 502 for a host the operator can reach.
  #
  # Same conservative shape as above -- podman rejecting a value takes the whole
  # sidecar down, and a search domain is worth less than a working session.
  usable_search() { # FILE
    [[ -r "$1" ]] || return 0
    local line word
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ ^[[:space:]]*(search|domain)[[:space:]]+(.*) ]] || continue
      for word in ${BASH_REMATCH[2]}; do
        [[ "$word" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || continue
        printf '%s\n' "$word"
      done
    done < "$1"
  }

  usable_dns_options() { # FILE
    [[ -r "$1" ]] || return 0
    local line word
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ ^[[:space:]]*options[[:space:]]+(.*) ]] || continue
      for word in ${BASH_REMATCH[1]}; do
        [[ "$word" =~ ^[a-z0-9-]+(:[0-9]+)?$ ]] || continue
        printf '%s\n' "$word"
      done
    done < "$1"
  }

  sidecar_nameservers=()
  sidecar_resolv=/etc/resolv.conf
  mapfile -t sidecar_nameservers < <(usable_nameservers "$sidecar_resolv")
  # systemd-resolved publishes 127.0.0.53 as the only nameserver, which the
  # filter above correctly discards.  Its own file carries the real upstreams;
  # using them keeps split-horizon and corporate names resolving instead of
  # quietly defecting to a public resolver.
  if [[ ${#sidecar_nameservers[@]} -eq 0 ]]; then
    sidecar_resolv=/run/systemd/resolve/resolv.conf
    mapfile -t sidecar_nameservers < <(usable_nameservers "$sidecar_resolv")
  fi
  # Nothing on the host was usable.  The search list goes with it: a public
  # resolver cannot answer for an internal zone, so carrying the suffixes would
  # only add failed lookups to every name.
  if [[ ${#sidecar_nameservers[@]} -eq 0 ]]; then
    sidecar_nameservers=(8.8.8.8 1.1.1.1)
    sidecar_resolv=""
  fi

  sidecar_dns_args=()
  for sidecar_ns in "${sidecar_nameservers[@]}"; do
    sidecar_dns_args+=(--dns "$sidecar_ns")
  done
  if [[ -n "$sidecar_resolv" ]]; then
    while read -r sidecar_search; do
      sidecar_dns_args+=(--dns-search "$sidecar_search")
    done < <(usable_search "$sidecar_resolv")
    while read -r sidecar_dns_option; do
      sidecar_dns_args+=(--dns-option "$sidecar_dns_option")
    done < <(usable_dns_options "$sidecar_resolv")
  fi

  # The sidecar is infrastructure, not agent workload. Keep its policy/log
  # mounts SELinux-safe by default regardless of --selinux so readiness does not
  # depend on host labeling conventions.
  sidecar_security_opts=("--security-opt" "label=disable")

  # Not --rm: the cleanup trap removes it, so a sidecar that dies early is still
  # around for `podman logs` to explain itself.
  #
  # Labelled like every other container the project creates: without this the
  # sidecar could only be found by guessing at its random name, which is why
  # nothing could report on the proxy or reach its log.  target= points
  # back at the sandbox, mirroring the port forwarders.
  # stdout is just the container id, so it goes to /dev/null -- but stderr does
  # not.  Under errexit a silenced failure here aborted the launcher with no
  # output whatsoever, which is the worst possible way to learn that a --dns
  # value or a mount was rejected.
  if ! podman run -d --name "$sidecar_id" \
    --label "agent-sandbox.role=proxy" \
    --label "agent-sandbox.target=$container_name" \
    --label "agent-sandbox.workspace=$PWD" \
    --network bridge --network "$sidecar_id" \
    "${sidecar_dns_args[@]}" \
    "${sidecar_security_opts[@]}" \
    "${sidecar_caps[@]}" -v "$sidecar_shared:/sidecar_shared:$rw_mount_opts" \
    -v "$sidecar_policy:/sidecar_policy:ro" \
    -e "AGENT_SANDBOX_SKIP_NIX_INIT=1" \
    -e "SIDECAR_SUBNET=$sidecar_subnet" \
    "$AGENT_SANDBOX_IMAGE" agent-sandbox-sidecar >/dev/null; then
    echo "agent-sandbox: could not start the proxy sidecar" >&2
    exit 1
  fi

  # Wait for the sidecar to signal readiness via the shared volume.  It writes
  # that marker only after the proxy can resolve names (see wait_for_egress in
  # proxy/src/main.rs) and after the blackhole routes are installed, so this has
  # to outlast the proxy's own READY_TIMEOUT -- cutting it short would start the
  # agent against a proxy that cannot reach anything yet, which is exactly the
  # race this fixes.
  sidecar_ready=0
  for _ in $(seq 1 350); do
    if [[ -f "$sidecar_shared/ready" ]]; then
      sidecar_ready=1
      break
    fi
    # A rejected policy exits the proxy immediately; waiting out the full 35s
    # would bury the reason under a timeout that suggests a network problem.
    if ! podman container inspect --format '{{.State.Running}}' "$sidecar_id" 2>/dev/null \
         | grep -qx true; then
      echo "agent-sandbox: the proxy sidecar exited before signalling readiness:" >&2
      podman logs "$sidecar_id" 2>&1 | sed 's/^/               /' >&2
      exit 1
    fi
    sleep 0.1
  done
  if [[ "$sidecar_ready" != "1" ]]; then
    echo "agent-sandbox: warning: proxy did not signal readiness in 35s" >&2
    echo "               (continuing; check: podman logs $sidecar_id)" >&2
  fi

  # The proxy starts even when it could not prove egress -- a degraded launch
  # beats a hung one -- but that used to be visible only in the sidecar's log,
  # so the session looked healthy right up until the first request came back
  # 502.  Say it here, where the person who ran the command is looking.
  if [[ -s "$sidecar_shared/egress-degraded" ]]; then
    echo "agent-sandbox: warning: the proxy could not resolve names at startup" >&2
    sed 's/^/               /' "$sidecar_shared/egress-degraded" >&2
    echo "               (continuing; requests may fail. Full log: agent-sandbox-ctl logs)" >&2
  fi

  network_args+=(--network "$sidecar_id")
  # /sidecar_shared is deliberately NOT mounted into the sandbox.  It used to be,
  # for the sake of agent-sandbox-allow (now gone), and since the sandbox runs
  # --userns=keep-id it had write access to connections.jsonl -- so the agent
  # could truncate or forge the log of its own network activity.  Nothing inside
  # needs the directory: the readiness marker is read by the launcher on the host,
  # and `agent-sandbox-ctl net` reads the log through the sidecar.
  #
  # By address, not by name.  The internal network is --disable-dns (see the
  # network create above), so there is no aardvark to resolve the sidecar's
  # container name -- and even when there was, nothing in the readiness
  # handshake proved aardvark had published the record before the sandbox
  # started, which is one more startup race that simply stops existing here.
  #
  # This necessarily agrees with the address the proxy itself binds to inside
  # the sidecar (agent-sandbox-sidecar.sh selects one from $sidecar_subnet on
  # the same interface), since both are just two ways of reading the one IP
  # podman assigned the container on $sidecar_id.
  sidecar_ip=""
  for _ in $(seq 1 20); do
    # `container inspect`, not plain `inspect`: the network carries the same
    # name, and which one a bare inspect resolves to is podman's business.
    sidecar_ip=$(podman container inspect --format \
      "{{(index .NetworkSettings.Networks \"$sidecar_id\").IPAddress}}" \
      "$sidecar_id" 2>/dev/null) || sidecar_ip=""
    [[ -n "$sidecar_ip" ]] && break
    sleep 0.1
  done
  if [[ -z "$sidecar_ip" ]]; then
    echo "agent-sandbox: the proxy sidecar has no address on $sidecar_id" >&2
    echo "               (check: podman logs $sidecar_id)" >&2
    exit 1
  fi

  env_args+=("-e" "HTTP_PROXY=http://$sidecar_ip:8888" "-e" "HTTPS_PROXY=http://$sidecar_ip:8888")
fi

env_args+=("-e" "TERM=${TERM:-xterm-256color}")
[[ -n "${COLORTERM:-}" ]] && env_args+=("-e" "COLORTERM=$COLORTERM")

# Recorded as a label so `agent-sandbox-ctl list` can show it and `port add` can
# refuse to weaken it.  Always set, including "off": an absent label is
# indistinguishable from a container created before this existed, which would
# make the column ambiguous exactly when it matters.
proxy_mode=off
if [[ "$want_proxy" == "1" ]]; then
  proxy_mode=proxy
fi

# Likewise always recorded, for the same reason: `ctl attach` and `ctl mounts`
# have to refuse against a krun sandbox, and the label is their only way to know.
# Resources go in as OCI annotations, which is the only channel crun's libkrun
# handler reads them from.
krun_args=()
sandbox_runtime=crun
if [[ "$want_krun" == "1" ]]; then
  sandbox_runtime=krun
  krun_args=(--runtime "$AGENT_SANDBOX_KRUN_RUNTIME"
             --annotation "krun.ram_mib=$krun_ram_mib")
  [[ -n "$krun_cpus" ]] && krun_args+=(--annotation "krun.cpus=$krun_cpus")

  # Without this, the guest does not boot at all on an SELinux-enforcing host:
  #
  #   write to file `thread-self/attr/current`: Permission denied
  #
  # The kernel refuses to set a process's SELinux context once that process has
  # more than one thread, and libkrun has already spawned the VM's threads by
  # the time crun's handler attempts the domain transition.  So this is not a
  # host misconfiguration to work around but a property of running the VMM in
  # the container process, and no label choice makes it succeed.
  #
  # Same reasoning, and the same flag, as the sidecar above.  The trade is real
  # and belongs in the README: on an SELinux host, --krun exchanges SELinux
  # confinement of the sandbox process for a guest kernel under the agent.
  # --selinux still governs :z relabeling of the binds, which is unaffected.
  krun_args+=(--security-opt label=disable)
fi

# Only allocate a TTY when there is one to allocate, so piped and CI
# invocations (agent-sandbox -- bash -c '…' | tee log) still work.
# GPG_TTY is deliberately not set here: the correct value is the tty podman
# allocates inside the container, which only the entrypoint can observe.
tty_args=()
if [[ -t 0 && -t 1 ]]; then
  tty_args=(--tty)
fi

# Not exec'd: the EXIT trap above still has temp files to clean up.
podman run \
  --rm \
  --interactive \
  "${tty_args[@]}" \
  --userns=keep-id \
  --name "$container_name" \
  --label "agent-sandbox.role=sandbox" \
  --label "agent-sandbox.workspace=$PWD" \
  --label "agent-sandbox.proxy=$proxy_mode" \
  --label "agent-sandbox.runtime=$sandbox_runtime" \
  --label "agent-sandbox.command=${cmd_args[*]}" \
  --workdir "$workspace_dir" \
  -e HOME=/home/user \
  -v "$passwd_tmp:/etc/passwd:ro,z" \
  -v "$group_tmp:/etc/group:ro,z" \
  --mount type=tmpfs,dst=/home/user/.config,U=true \
  --mount type=tmpfs,dst=/home/user/.cache,U=true \
  --mount type=tmpfs,dst=/home/user/.local,U=true \
  "${network_args[@]}" \
  "${publish_args[@]}" \
  "${mounts[@]}" \
  "${env_args[@]}" \
  "${krun_args[@]}" \
  "${podman_args[@]}" \
  "$AGENT_SANDBOX_IMAGE" \
  "${cmd_args[@]}"
