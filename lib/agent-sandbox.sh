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
# On by default: things the agent needs to be useful in a normal git workflow.
# Off by default: things that widen the sandbox boundary (podman socket,
# on-disk gpg secrets) or that only some hosts want (selinux relabelling).
want_ssh=1
want_git=1
want_gpg=1
want_gpg_sign=1
want_gnupg_private=0
want_devenv=1
want_nix=1
want_podman=0
want_workspace=1
want_selinux=0
want_ports=1
want_ports_dynamic=0
want_ports_any_interface=0
want_firewall=0
want_meter_network=0

agent=""
want_help=0

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

if [[ $# -eq 0 ]]; then
  want_help=1
fi

usage() {
  cat <<USAGE
agent-sandbox [FLAGS] [AGENT] [-- COMMAND...]

Runs an AI coding agent inside a rootless podman container with the current
directory mounted at /workspace/<dirname>.

  agent-sandbox                      prints this help
  agent-sandbox opencode             launch opencode with its specific mounts
  agent-sandbox --podman opencode    launch opencode with podman enabled
  agent-sandbox opencode -- bash     launch bash with opencode mounts
  agent-sandbox -- bash              launch bash without agent specific mounts
  agent-sandbox --privileged opencode
                                     pass --privileged to podman run

Agents:
  ${agent_list}

Integrations (--no-X disables):
  --workspace       mount \$PWD at /workspace/<dirname>            $([[ "$want_workspace" == "1" ]] && echo "[on ]" || echo "[off]")
  --ssh             forward SSH_AUTH_SOCK                         $([[ "$want_ssh" == "1" ]] && echo "[on ]" || echo "[off]")
  --git             mount git config, forward identity            $([[ "$want_git" == "1" ]] && echo "[on ]" || echo "[off]")
  --gpg-agent       forward host gpg-agent for commit signing     $([[ "$want_gpg" == "1" ]] && echo "[on ]" || echo "[off]")
  --gpg-sign        allow git commit signing                      $([[ "$want_gpg_sign" == "1" ]] && echo "[on ]" || echo "[off]")
  --gnupg-private   expose ~/.gnupg even if it holds on-disk keys $([[ "$want_gnupg_private" == "1" ]] && echo "[on ]" || echo "[off]")
  --devenv          persist ~/.local/share/devenv                 $([[ "$want_devenv" == "1" ]] && echo "[on ]" || echo "[off]")
  --nix             mount the host /nix                           $([[ "$want_nix" == "1" ]] && echo "[on ]" || echo "[off]")
  --podman          forward the host podman socket (see below)    $([[ "$want_podman" == "1" ]] && echo "[on ]" || echo "[off]")
  --selinux         add :z to built-in writable binds             $([[ "$want_selinux" == "1" ]] && echo "[on ]" || echo "[off]")
  --firewall        route traffic through domain-filtering proxy  $([[ "$want_firewall" == "1" ]] && echo "[on ]" || echo "[off]")
  --meter-network   capture network traffic for a post-run summary $([[ "$want_meter_network" == "1" ]] && echo "[on ]" || echo "[off]")

Ports:
  --port [HOST:]CONTAINER[/PROTO]    publish a port, repeatable
  --ports / --no-ports               honour [ports] in ./AGENTS.md     $([[ "$want_ports" == "1" ]] && echo "[on ]" || echo "[off]")
  --ports-dynamic                    allow \`agent-sandbox-ctl port add\` later
  --ports-any-interface              permit binds outside loopback

Mounts:
  -v SOURCE[:DEST[:OPTS]]   relative SOURCE resolves against \$PWD; relative
                            DEST is placed under /workspace; "." means
                            /workspace itself

Podman / Environment:
  --privileged              pass --privileged to podman run (for nested podman)
  -e, --env NAME=VAL        pass environment variable to podman
  --podman-args=ARG         pass one arg to podman run; repeatable, and safe to
                            bake into a wrapper since it consumes nothing else
  --podman-args             treat all following args (until --) as podman args

--podman, --ssh and --gpg-agent each hand the agent a capability that reaches
outside the sandbox. --podman forwards the host podman socket, allowing the 
agent to create sibling containers on the host (a full sandbox escape).
To safely let the agent run containers, use --privileged instead to enable 
securely nested containers inside the sandbox. See README for details.
USAGE
}

mounts=()
env_args=()
podman_args=()
cmd_args=()
port_specs=()

# ── Helpers ─────────────────────────────────────────────────────────────────

# Expand a -v spec.  Relative sources resolve against $PWD; relative
# destinations land under /workspace.  A spec with no destination mounts at
# the same path it came from, rather than emitting a trailing colon.
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
    --gpg-agent)    want_gpg=1 ;;
    --no-gpg-agent) want_gpg=0 ;;
    --gpg-sign)     want_gpg_sign=1 ;;
    --no-gpg-sign)  want_gpg_sign=0 ;;
    --gnupg-private)    want_gnupg_private=1 ;;
    --no-gnupg-private) want_gnupg_private=0 ;;
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
    --firewall)         want_firewall=1 ;;
    --no-firewall)      want_firewall=0 ;;
    --meter-network)    want_meter_network=1 ;;
    --no-meter-network) want_meter_network=0 ;;
    --port)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox: --port needs an argument" >&2; exit 1; }
      port_specs+=("$1")
      ;;
    --port=*)       port_specs+=("${1#--port=}") ;;

    -v)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox: -v needs an argument" >&2; exit 1; }
      mounts+=("-v" "$(expand_v "$1")")
      ;;
    -v*) mounts+=("-v" "$(expand_v "${1#-v}")") ;;

    --podman-args=*)
      podman_args+=("${1#--podman-args=}")
      ;;
    --podman-args)
      parsing_podman=1
      ;;
    --privileged)
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

if [[ "$want_help" == "1" ]] || [[ -z "$agent" && ${#cmd_args[@]} -eq 0 ]]; then
  usage
  exit 0
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
# Only the selected agent's paths are mounted, so we avoid creating host-side
# state directories for tools that never run.
if [[ -n "$agent" ]]; then
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    mount_rw "$HOME/$rel" "/home/user/$rel"
  done < <(jq -r '.[]' <<< "${agent_state_json[$agent]}")

  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    [[ -s "$HOME/$rel" ]] || printf '{}\n' > "$HOME/$rel"
    mounts+=("-v" "$HOME/$rel:/home/user/$rel:$rw_mount_opts")
  done < <(jq -r '.[]' <<< "${agent_state_files_json[$agent]}")
fi

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
# secret on disk (the smart-card case), unless --gnupg-private overrides.

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

    if [[ "$gnupg_status" == "0" || "$want_gnupg_private" == "1" ]]; then
      if [[ "$gnupg_status" != "0" ]]; then
        echo "agent-sandbox: exposing ~/.gnupg with on-disk secret keys (--gnupg-private)." >&2
      fi
      # Public material only: the keyring so gpg can name the signing key, and
      # the trust database so it believes the answer.
      for keyring in pubring.kbx pubring.gpg trustdb.gpg; do
        if [[ -f "$HOME/.gnupg/$keyring" ]]; then
          mounts+=("-v" "$HOME/.gnupg/$keyring:/run/host-gnupg/$keyring:ro")
        fi
      done
      if [[ "$want_gnupg_private" == "1" && -d "$HOME/.gnupg/private-keys-v1.d" ]]; then
        mounts+=("-v" "$HOME/.gnupg/private-keys-v1.d:/run/host-gnupg/private-keys-v1.d:ro")
      fi
    else
      echo "agent-sandbox: not exposing ~/.gnupg -- it holds secret keys on disk:" >&2
      while IFS= read -r offender; do
        printf '               %s\n' "$offender" >&2
      done <<< "$gnupg_offenders"
      echo "               A smart-card setup keeps only stubs here and is exposed normally." >&2
      echo "               Override with --gnupg-private, or silence this with --no-gpg-agent." >&2
      exit 1
    fi
  fi
fi

if [[ "$want_gpg_sign" == "0" ]]; then
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

# A shared network is what makes `agent-sandbox-ctl port add` possible later:
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

cleanup() {
  rm -f "$passwd_tmp" "$group_tmp"
  if [[ "$want_firewall" == "1" || "$want_meter_network" == "1" ]]; then
    podman stop -t 1 "$sidecar_id" >/dev/null 2>&1 || true
    if [[ "$want_meter_network" == "1" ]]; then
      if [[ -s "$sidecar_shared/traffic.pcap" ]]; then
        printf '\n=== Network Traffic Summary ===\n'
        tshark -r "$sidecar_shared/traffic.pcap" -T fields -e tls.handshake.extensions_server_name -Y 'tls.handshake.type == 1' 2>/dev/null | sort | uniq -c
        printf '\n--- IP Addresses and Byte Volumes ---\n'
        tshark -r "$sidecar_shared/traffic.pcap" -q -z conv,ip 2>/dev/null
      else
        printf '\n=== Network Traffic Summary ===\n'
        printf '(no packets captured)\n'
        if [[ -s "$sidecar_shared/tcpdump.log" ]]; then
          printf '\ntcpdump: %s\n' "$(cat "$sidecar_shared/tcpdump.log")"
        fi
      fi
    fi

    podman network rm "$sidecar_id" >/dev/null 2>&1 || true
    rm -rf "$sidecar_shared"
  fi
}
trap cleanup EXIT
printf 'root:x:0:0:root:/root:/bin/sh\nuser:x:%s:%s::/home/user:/bin/bash\nnobody:x:65534:65534:Nobody:/:/bin/sh\n' "$(id -u)" "$(id -g)" > "$passwd_tmp"
printf 'root:x:0:\nuser:x:%s:\nnobody:x:65534:\n' "$(id -g)" > "$group_tmp"

# Include the hashed workspace path and the launcher PID in the container name so
# agent-sandbox-ctl port and agent-sandbox-ctl purge find sandboxes without guessing
# network/PID relationships.
workspace_slug=$(basename "$PWD")
workspace_slug="${workspace_slug//[^A-Za-z0-9_.-]/-}"
container_name="agent-sandbox-${workspace_slug:0:32}-$$"

# ── Sidecar Proxy & Metering ────────────────────────────────────────────────
if [[ "$want_firewall" == "1" || "$want_meter_network" == "1" ]]; then
  sidecar_id="agent-sandbox-sidecar-$(head -c 12 /proc/sys/kernel/random/uuid 2>/dev/null || echo $$)"
  sidecar_shared=$(mktemp -d)
  podman network create --internal "$sidecar_id" >/dev/null 2>&1 || true

  proxy_domains=()
  if [[ "$want_firewall" == "1" && -f "$PWD/AGENTS.md" ]]; then
    read -ra proxy_domains <<< "$(agent-sandbox-parse-agents --proxy-domains "$PWD/AGENTS.md" 2>/dev/null || true)"
  fi

  sidecar_caps=()
  if [[ "$want_meter_network" == "1" ]]; then
    sidecar_caps=("--cap-add=NET_ADMIN" "--cap-add=NET_RAW")
  fi

  # The sidecar is on both bridge (external) and the internal network.
  # Podman's aardvark-dns injects the internal network's DNS server into
  # /etc/resolv.conf, but --internal blocks its upstream forwarding.
  # Override with the host's nameservers so tinyproxy can resolve external names.
  # Skip loopback (127.*) and link-local (169.254.*) addresses since they are
  # not reachable from inside the container's network namespace.
  sidecar_dns_args=()
  while IFS= read -r ns; do
    if [[ "$ns" =~ ^nameserver[[:space:]]+([^[:space:]]+) ]]; then
      local_ns="${BASH_REMATCH[1]}"
      [[ "$local_ns" =~ ^127\. || "$local_ns" =~ ^169\.254\. ]] && continue
      sidecar_dns_args+=(--dns "$local_ns")
    fi
  done < /etc/resolv.conf
  # Fallback to public DNS if no usable host nameservers found.
  if [[ ${#sidecar_dns_args[@]} -eq 0 ]]; then
    sidecar_dns_args=(--dns 8.8.8.8 --dns 1.1.1.1)
  fi

  # The sidecar is our infrastructure container, not the sandboxed agent code.
  # Disable SELinux labeling so tcpdump can use raw sockets for packet capture.
  sidecar_selinux=()
  if [[ "$want_selinux" == "1" ]]; then
    sidecar_selinux=("--security-opt" "label=disable")
  fi

  podman run -d --rm --name "$sidecar_id" \
    --network bridge --network "$sidecar_id" \
    "${sidecar_dns_args[@]}" \
    "${sidecar_selinux[@]}" \
    "${sidecar_caps[@]}" -v "$sidecar_shared:/sidecar_shared:$rw_mount_opts" \
    -e "METER_NETWORK=$want_meter_network" \
    -e "FIREWALL=$want_firewall" \
    "$AGENT_SANDBOX_IMAGE" agent-sandbox-sidecar "${proxy_domains[@]}" >/dev/null 2>&1

  # Wait for tinyproxy to signal readiness via the shared volume.
  for _ in $(seq 1 50); do
    [[ -f "$sidecar_shared/ready" ]] && break
    sleep 0.1
  done

  network_args+=(--network "$sidecar_id")
  mounts+=("-v" "$sidecar_shared:/sidecar_shared:$rw_mount_opts")
  env_args+=("-e" "HTTP_PROXY=http://$sidecar_id:8888" "-e" "HTTPS_PROXY=http://$sidecar_id:8888")
fi

env_args+=("-e" "TERM=${TERM:-xterm-256color}")
[[ -n "${COLORTERM:-}" ]] && env_args+=("-e" "COLORTERM=$COLORTERM")

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
  --workdir "$workspace_dir" \
  -e HOME=/home/user \
  -v "$passwd_tmp:/etc/passwd:ro" \
  -v "$group_tmp:/etc/group:ro" \
  --mount type=tmpfs,dst=/home/user/.config,U=true \
  --mount type=tmpfs,dst=/home/user/.cache,U=true \
  --mount type=tmpfs,dst=/home/user/.local,U=true \
  "${network_args[@]}" \
  "${publish_args[@]}" \
  "${mounts[@]}" \
  "${env_args[@]}" \
  "${podman_args[@]}" \
  "$AGENT_SANDBOX_IMAGE" \
  "${cmd_args[@]}"
