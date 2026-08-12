#!/usr/bin/env bash
# Reclaim what agent-sandbox leaves on the host.
#
# By default only leftovers: containers that have exited, forwarders and sidecars
# whose sandbox is gone, unattached per-session networks, and the temp directories
# of launchers that were killed before their cleanup trap could run.  A running
# session is listed and skipped -- `ctl purge` advertises removing *old*
# containers, and it used to kill live sandboxes and force-disconnect their
# networks without saying so.  --all opts into that.
#
# Selection is by role label rather than by `ancestor=`: sidecars and forwarders
# share the sandbox's image, so filtering on the image reported all three as
# sandboxes, and a rebuilt image moves the tag so already-running containers match
# no ancestor at all.

force=0
dry_run=0
include_running=0

usage() {
  cat <<'USAGE'
agent-sandbox-purge [--all] [-n|--dry-run] [-f|--force]

  (default)      remove leftovers only; running sandboxes are listed and kept
  --all          also remove running sandboxes, their sidecars and networks
  -n, --dry-run  report what would be removed, change nothing
  -f, --force    do not ask for confirmation

Always removes, when unused: exited sandboxes, orphaned port forwarders and
proxy sidecars, per-session networks nothing is attached to, and leftover
/tmp/agent-sandbox-{sidecar,policy}-* directories.  The image is offered last.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)         include_running=1 ;;
    -n|--dry-run)  dry_run=1 ;;
    -f|--force)    force=1 ;;
    -h|--help)     usage; exit 0 ;;
    -*)            echo "${0##*/}: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)             echo "${0##*/}: unexpected argument: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

confirm() {
  [[ "$dry_run" == "1" ]] && return 1
  [[ "$force" == "1" ]] && return 0
  local answer
  # Non-interactive stdin reads EOF; treating that as "no" silently made
  # `purge < /dev/null` look like it had done something.
  if ! read -r -p "$1 [y/N] " answer; then
    echo "(not a terminal; pass --force to remove without asking)" >&2
    return 1
  fi
  [[ "$answer" =~ ^[Yy] ]]
}

# Present a set of things and act on it.  Keeps every section's shape identical:
# list, ask, do -- or, under --dry-run, list and stop.
section() { # title, remover, items...
  local title="$1" remover="$2"
  shift 2
  if [[ $# -eq 0 ]]; then
    printf '%s: none\n\n' "$title"
    return
  fi
  printf '%s:\n' "$title"
  printf '  %s\n' "$@"
  echo
  if [[ "$dry_run" == "1" ]]; then
    printf '  would remove %s\n\n' "$#"
    return
  fi
  if confirm "Remove these?"; then
    "$remover" "$@"
    printf '  removed %s\n\n' "$#"
  else
    printf '  skipped\n\n'
  fi
}

rm_containers()  { podman rm -f "$@" >/dev/null; }
rm_networks() {
  local net
  for net in "$@"; do
    # Not `network rm -f`: that disconnects whatever is still attached, which is
    # how this used to cut the network out from under a live session.  podman
    # tears containers down asynchronously, so retry instead.
    local i
    for ((i = 0; i < 20; i++)); do
      podman network rm "$net" >/dev/null 2>&1 && break
      podman network exists "$net" 2>/dev/null || break
      sleep 0.25
    done
    if podman network exists "$net" 2>/dev/null; then
      echo "  $net is still in use" >&2
    fi
  done
}
rm_dirs() { rm -rf "$@"; }

containers_of_role() { # role, [--running-only|--exited-only]
  local role="$1" filter="${2:-}"
  case "$filter" in
    --running-only) podman ps --filter "label=agent-sandbox.role=$role" --format '{{.Names}}' ;;
    --exited-only)  podman ps -a --filter "label=agent-sandbox.role=$role" \
                                 --filter "status=exited" --format '{{.Names}}'
                    podman ps -a --filter "label=agent-sandbox.role=$role" \
                                 --filter "status=created" --format '{{.Names}}' ;;
    *)              podman ps -a --filter "label=agent-sandbox.role=$role" --format '{{.Names}}' ;;
  esac
}

# A forwarder or sidecar whose target sandbox no longer exists.  These keep
# running -- and a forwarder keeps holding its host port -- so they are leftovers
# even while "up".
orphans_of_role() { # role
  local name target
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    target=$(podman inspect --format '{{index .Config.Labels "agent-sandbox.target"}}' \
             "$name" 2>/dev/null || true)
    if [[ -z "$target" ]] || ! podman container exists "$target"; then
      printf '%s\n' "$name"
    fi
  done < <(containers_of_role "$1")
}

echo "=== agent-sandbox-purge ==="
[[ "$dry_run" == "1" ]] && echo "(dry run: nothing will be removed)"
echo

# ── Running sessions ────────────────────────────────────────────────────────

running=()
mapfile -t running < <(containers_of_role sandbox --running-only)
if [[ ${#running[@]} -gt 0 ]]; then
  if [[ "$include_running" == "1" ]]; then
    section "Running sandboxes" rm_containers "${running[@]}"
  else
    echo "Running sandboxes (kept; pass --all to remove):"
    printf '  %s\n' "${running[@]}"
    echo
  fi
fi

# ── Leftovers ───────────────────────────────────────────────────────────────
# Forwarders first: they hold the shared network open.

orphan_forwarders=()
mapfile -t orphan_forwarders < <(orphans_of_role port-forward)
section "Orphaned port forwarders" rm_containers ${orphan_forwarders[@]+"${orphan_forwarders[@]}"}

orphan_sidecars=()
mapfile -t orphan_sidecars < <(orphans_of_role proxy)
section "Orphaned proxy sidecars" rm_containers ${orphan_sidecars[@]+"${orphan_sidecars[@]}"}

exited=()
mapfile -t exited < <(containers_of_role sandbox --exited-only)
section "Exited sandboxes" rm_containers ${exited[@]+"${exited[@]}"}

# ── Networks ────────────────────────────────────────────────────────────────
# A per-session network with nothing attached is a leak: the launcher removes its
# own, but loses the race often enough to matter, and each one holds a subnet from
# the rootless pool.

unused_networks=()
while IFS= read -r net; do
  [[ -n "$net" ]] || continue
  attached=$(podman network inspect --format '{{len .Containers}}' "$net" 2>/dev/null || echo 0)
  [[ "${attached:-0}" == "0" ]] && unused_networks+=("$net")
done < <(podman network ls --filter "name=^agent-sandbox-sidecar-" --format '{{.Name}}' 2>/dev/null || true)
section "Unused session networks" rm_networks ${unused_networks[@]+"${unused_networks[@]}"}

if podman network exists "$AGENT_SANDBOX_NETWORK" 2>/dev/null; then
  attached=$(podman network inspect --format '{{len .Containers}}' \
             "$AGENT_SANDBOX_NETWORK" 2>/dev/null || echo 0)
  if [[ "${attached:-0}" == "0" || "$include_running" == "1" ]]; then
    section "Shared network" rm_networks "$AGENT_SANDBOX_NETWORK"
  else
    printf 'Shared network: %s (in use by %s container(s); kept)\n\n' \
      "$AGENT_SANDBOX_NETWORK" "$attached"
  fi
fi

# ── Temp directories ────────────────────────────────────────────────────────
# The launcher removes these in its exit trap; one that was SIGKILLed cannot.
# Findable only because the mktemp templates name them.

stale_dirs=()
live_mounts=$(podman ps -a --format '{{.Mounts}}' 2>/dev/null || true)
for dir in "${TMPDIR:-/tmp}"/agent-sandbox-sidecar-* "${TMPDIR:-/tmp}"/agent-sandbox-policy-*; do
  [[ -d "$dir" ]] || continue
  # Still mounted by some container: not ours to remove.
  grep -qF -- "$dir" <<< "$live_mounts" && continue
  stale_dirs+=("$dir")
done
section "Leftover session directories" rm_dirs ${stale_dirs[@]+"${stale_dirs[@]}"}

# ── Image ───────────────────────────────────────────────────────────────────

if podman image exists "$AGENT_SANDBOX_IMAGE" 2>/dev/null; then
  echo "Image: $AGENT_SANDBOX_IMAGE"
  echo
  if [[ "$dry_run" == "1" ]]; then
    echo "  would remove (rebuild with: agent-sandbox-ctl load)"
    echo
  elif confirm "Remove this image?"; then
    podman rmi -f "$AGENT_SANDBOX_IMAGE" >/dev/null
    echo "  removed"
    echo
  else
    echo "  skipped"
    echo
  fi
else
  echo "Image: not loaded"
  echo
fi

echo "Done."
