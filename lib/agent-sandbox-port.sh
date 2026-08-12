#!/usr/bin/env bash
# Publish a port from a *running* sandbox.
#
# Podman cannot add a binding to a container that is already running, and
# --network=container:<id> explicitly forbids port bindings, so there is no
# way to retrofit -p onto a live sandbox.  What does work is a sidecar: a
# second container that publishes the port itself and proxies over a shared
# network to the sandbox, addressed by container name.
#
#   host:8000  ->  sidecar (socat)  ->  sandbox:8000
#
# The sandbox therefore has to be on the shared network.  Rootless podman's
# default netns (pasta/slirp4netns) cannot be joined to one after the fact,
# which is why `agent-sandbox --ports-dynamic` exists: it puts the sandbox on
# the shared network from the start.  Connecting afterwards is attempted
# anyway, since it succeeds for sandboxes launched with ports already.

usage() {
  cat <<'USAGE'
agent-sandbox-ctl ports ls
agent-sandbox-ctl ports add    [WORD] [--sandbox WORD] [HOST:]CONTAINER[/PROTO]
agent-sandbox-ctl ports rm     [WORD] [--sandbox WORD] (HOST | --all)
agent-sandbox-ctl ports export [WORD] [--sandbox WORD]

  ls      show running sandboxes and the ports forwarded into them
  add     start a forwarder for one port
  rm      stop forwarders
  export  print the [ports] section of a running sandbox as AGENTS.md TOML

With one sandbox running, --sandbox may be omitted.  With several, it is
required unless the current directory matches exactly one sandbox workspace.

The server inside the sandbox must bind 0.0.0.0, not 127.0.0.1: the sidecar
reaches it over the container network, not over the sandbox's loopback.
USAGE
}

forwarder_containers() {
  local target="${1:-}"
  if [[ -n "$target" ]]; then
    podman ps --filter "label=agent-sandbox.role=port-forward" \
              --filter "label=agent-sandbox.target=$target" --format '{{.Names}}'
  else
    podman ps --filter "label=agent-sandbox.role=port-forward" --format '{{.Names}}'
  fi
}

cmd_ls() {
  local only="${1:-}"
  local names=() name
  if [[ -n "$only" ]]; then
    names=("$(resolve_sandbox "$only")")
  else
    mapfile -t names < <(sandbox_containers)
  fi

  if [[ ${#names[@]} -eq 0 ]]; then
    echo "No running sandboxes."
  fi

  for name in "${names[@]}"; do
    printf '%s\n' "$name"
    printf '  workspace   %s\n' "$(sandbox_workspace "$name")"

    local published line
    published=$(podman port "$name" 2>/dev/null || true)
    if [[ -n "$published" ]]; then
      while IFS= read -r line; do
        printf '  published   %s\n' "$line"
      done <<< "$published"
    fi

    local forwarders=() forwarder
    mapfile -t forwarders < <(forwarder_containers "$name")
    for forwarder in "${forwarders[@]}"; do
      [[ -n "$forwarder" ]] || continue
      printf '  forwarded   %s  (%s)\n' \
        "$(podman port "$forwarder" 2>/dev/null | tr '\n' ' ')" "$forwarder"
    done
  done

  # Forwarders keep running (and keep holding their host port) after the sandbox
  # they point at is gone.  Listing only live sandboxes hides exactly the ones
  # worth removing.
  [[ -n "$only" ]] && return 0
  local orphans=() forwarder target
  while IFS= read -r forwarder; do
    [[ -n "$forwarder" ]] || continue
    target=$(podman inspect --format '{{index .Config.Labels "agent-sandbox.target"}}' \
             "$forwarder" 2>/dev/null || true)
    podman container exists "$target" || orphans+=("$forwarder")
  done < <(forwarder_containers)

  if [[ ${#orphans[@]} -gt 0 ]]; then
    printf '\norphaned forwarders (their sandbox is gone):\n'
    for forwarder in "${orphans[@]}"; do
      printf '  %s  (%s)\n' \
        "$(podman port "$forwarder" 2>/dev/null | tr '\n' ' ')" "$forwarder"
    done
    printf '  remove with:  agent-sandbox-ctl purge\n'
  fi
}

cmd_add() {
  local sandbox="$1" spec="$2"
  local host container proto=tcp

  # Joining a firewalled sandbox to the shared bridge would hand it a route to
  # the internet that bypasses the proxy -- and unlike the launcher's version of
  # this refusal, here it would silently weaken a session already in progress.
  #
  # The label is authoritative; the /sidecar_shared mount is the fallback for a
  # container started before the label existed, because getting this wrong is the
  # worst outcome in this script.
  local mode
  mode=$(sandbox_proxy_mode "$sandbox")
  if [[ -z "$mode" || "$mode" == "off" ]]; then
    if [[ -n "$(sidecar_mount "$sandbox" /sidecar_shared)" ]]; then
      mode=proxy
    fi
  fi
  case "$mode" in
    proxy)
      echo "agent-sandbox-ctl ports: '$sandbox' was launched with a proxy ($mode)." >&2
      echo "                    Joining it to the $AGENT_SANDBOX_NETWORK network would give it" >&2
      echo "                    egress that does not pass through the proxy." >&2
      echo "                    Relaunch it without --proxy to forward ports." >&2
      exit 1
      ;;
  esac

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
    echo "agent-sandbox-ctl ports: expected [HOST:]CONTAINER[/PROTO], got '$2'" >&2
    exit 1
  fi
  if (( host < 1 || host > 65535 || container < 1 || container > 65535 )); then
    echo "agent-sandbox-ctl ports: ports must be within 1-65535" >&2
    exit 1
  fi
  if [[ "$proto" != tcp && "$proto" != udp ]]; then
    echo "agent-sandbox-ctl ports: protocol must be tcp or udp" >&2
    exit 1
  fi

  if ! podman network exists "$AGENT_SANDBOX_NETWORK" 2>/dev/null; then
    podman network create "$AGENT_SANDBOX_NETWORK" >/dev/null
  fi

  # Best effort: succeeds when the sandbox is already on a bridge network,
  # fails for the rootless default netns.  The error names the fix.
  if ! podman inspect --format '{{json .NetworkSettings.Networks}}' "$sandbox" \
       | grep -q "\"$AGENT_SANDBOX_NETWORK\""; then
    if ! podman network connect "$AGENT_SANDBOX_NETWORK" "$sandbox" 2>/dev/null; then
      echo "agent-sandbox-ctl ports: '$sandbox' is not on the $AGENT_SANDBOX_NETWORK network" >&2
      echo "                    and cannot be joined to it while running." >&2
      echo "                    Relaunch it with: agent-sandbox --ports-dynamic" >&2
      exit 1
    fi
  fi

  local listener="TCP-LISTEN" connector="TCP"
  if [[ "$proto" == udp ]]; then
    listener="UDP-LISTEN"
    connector="UDP"
  fi

  # Match any forwarder on this host port, not just this sandbox's: the name
  # embeds the sandbox, so a per-sandbox check lets a second sandbox get as far
  # as a raw podman bind error.
  # The sandbox name already carries the agent-sandbox- prefix. Keep one
  # prefix for the forwarder role, but do not repeat it in the target portion.
  local target_name="${sandbox#agent-sandbox-}"
  local name="agent-sandbox-fwd-${target_name}-${host}" clash
  clash=$(podman ps -a --filter "label=agent-sandbox.role=port-forward" \
                       --filter "name=^agent-sandbox-fwd-.*-${host}\$" \
                       --format '{{.Names}}' 2>/dev/null | head -n 1)
  if [[ -n "$clash" ]]; then
    echo "agent-sandbox-ctl ports: host port $host is already forwarded ($clash)" >&2
    exit 1
  fi

  podman run --detach --rm \
    --name "$name" \
    --network "$AGENT_SANDBOX_NETWORK" \
    --publish "127.0.0.1:$host:$container/$proto" \
    --label "agent-sandbox.role=port-forward" \
    --label "agent-sandbox.target=$sandbox" \
    "$AGENT_SANDBOX_IMAGE" \
    socat "$listener:$container,fork,reuseaddr" "$connector:$sandbox:$container" \
    > /dev/null

  echo "127.0.0.1:$host -> $sandbox:$container/$proto"
  echo "(the server inside must bind 0.0.0.0, not 127.0.0.1)"
}

cmd_rm() {
  local sandbox="$1" target="$2"
  local target_name="${sandbox#agent-sandbox-}"
  local forwarders=() forwarder removed=0
  mapfile -t forwarders < <(forwarder_containers "$sandbox")

  for forwarder in "${forwarders[@]}"; do
    [[ -n "$forwarder" ]] || continue
    if [[ "$target" == "--all" || "$forwarder" == "agent-sandbox-fwd-${target_name}-${target}" ]]; then
      podman rm -f "$forwarder" > /dev/null
      echo "removed $forwarder"
      removed=$((removed + 1))
    fi
  done

  if [[ "$removed" -eq 0 ]]; then
    echo "agent-sandbox-ctl ports: nothing to remove" >&2
    exit 1
  fi
}

cmd_export() {
  local sandbox="$1"
  local ports_lines=() port_idx=1

  add_ports() {
    local output="$1"
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      if [[ "$line" =~ ^([0-9]+)/([a-z]+)[[:space:]]*-[^:]*:[^0-9]*([0-9.]+|\[.*\]):([0-9]+)$ ]]; then
        local container="${BASH_REMATCH[1]}"
        local proto="${BASH_REMATCH[2]}"
        local bind="${BASH_REMATCH[3]}"
        local host="${BASH_REMATCH[4]}"
        ports_lines+=("port_$port_idx = { container = $container, host = $host, bind = \"$bind\", protocol = \"$proto\" }")
        ((port_idx++))
      fi
    done <<< "$output"
  }

  add_ports "$(podman port "$sandbox" 2>/dev/null || true)"
  local forwarders
  forwarders=$(podman ps --filter "label=agent-sandbox.role=port-forward" \
                         --filter "label=agent-sandbox.target=$sandbox" \
                         --format '{{.Names}}' 2>/dev/null || true)
  local fwd
  for fwd in $forwarders; do
    add_ports "$(podman port "$fwd" 2>/dev/null || true)"
  done

  if [[ ${#ports_lines[@]} -gt 0 ]]; then
    echo '```toml agent-sandbox'
    echo "[ports]"
    local line
    for line in "${ports_lines[@]}"; do
      echo "$line"
    done
    echo '```'
  fi
}

# ── Argument parsing ────────────────────────────────────────────────────────

[[ $# -gt 0 ]] || { usage; exit 1; }

action="$1"
shift

sandbox_name=""
positional=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --sandbox)
      shift
      [[ $# -gt 0 ]] || { echo "agent-sandbox-ctl ports: --sandbox needs a name" >&2; exit 1; }
      sandbox_name="$1"
      ;;
    --sandbox=*) sandbox_name="${1#--sandbox=}" ;;
    --all)       positional+=("--all") ;;
    -*)          echo "agent-sandbox-ctl ports: unknown flag '$1'" >&2; exit 1 ;;
    *)           positional+=("$1") ;;
  esac
  shift
done

case "$action" in
  ls|list)
    if [[ ${#positional[@]} -eq 1 ]]; then
      if [[ -n "$sandbox_name" ]]; then
         echo "agent-sandbox-ctl ports: cannot specify both --sandbox and a positional sandbox name" >&2; exit 1
      fi
      sandbox_name="${positional[0]}"
    elif [[ ${#positional[@]} -gt 1 ]]; then
      echo "agent-sandbox-ctl ports: ls takes at most one argument (the sandbox)" >&2; usage >&2; exit 1
    fi
    cmd_ls "$sandbox_name"
    ;;
  add)
    if [[ ${#positional[@]} -eq 2 ]]; then
      if [[ -n "$sandbox_name" ]]; then
         echo "agent-sandbox-ctl ports: cannot specify both --sandbox and a positional sandbox name" >&2; exit 1
      fi
      sandbox_name="${positional[0]}"
      spec="${positional[1]}"
    elif [[ ${#positional[@]} -eq 1 ]]; then
      spec="${positional[0]}"
    else
      echo "agent-sandbox-ctl ports: add needs a port spec, and optionally a sandbox" >&2; usage >&2; exit 1
    fi
    cmd_add "$(resolve_sandbox "$sandbox_name" --running)" "$spec"
    ;;
  rm|remove)
    if [[ ${#positional[@]} -eq 2 ]]; then
      if [[ -n "$sandbox_name" ]]; then
         echo "agent-sandbox-ctl ports: cannot specify both --sandbox and a positional sandbox name" >&2; exit 1
      fi
      sandbox_name="${positional[0]}"
      target="${positional[1]}"
    elif [[ ${#positional[@]} -eq 1 ]]; then
      target="${positional[0]}"
    else
      echo "agent-sandbox-ctl ports: rm needs a host port or --all" >&2; usage >&2; exit 1
    fi
    # Deliberately not --running: a forwarder outlives its sandbox, and clearing
    # one up is exactly the case where the sandbox has already exited.
    cmd_rm "$(resolve_sandbox "$sandbox_name")" "$target"
    ;;
  export)
    if [[ ${#positional[@]} -eq 1 ]]; then
      if [[ -n "$sandbox_name" ]]; then
         echo "agent-sandbox-ctl ports: cannot specify both --sandbox and a positional sandbox name" >&2; exit 1
      fi
      sandbox_name="${positional[0]}"
    elif [[ ${#positional[@]} -gt 1 ]]; then
      echo "agent-sandbox-ctl ports: export takes at most one argument (the sandbox)" >&2; usage >&2; exit 1
    fi
    cmd_export "$(resolve_sandbox "$sandbox_name" --running)"
    ;;
  -h|--help)
    usage
    ;;
  *)
    echo "agent-sandbox-ctl ports: unknown command '$action'" >&2
    usage >&2
    exit 1
    ;;
esac
