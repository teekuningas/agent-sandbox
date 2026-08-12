#!/usr/bin/env bash
# List agent-sandbox containers.
#
# Selection is by role label, not by `ancestor=`: the sidecar and the socat port
# forwarders run from the same image as the sandbox, so filtering on the image
# reported infrastructure containers as sandboxes (with an empty workspace
# column).  Labels also survive `agent-sandbox-ctl load` reassigning the tag to a
# rebuilt image, which leaves already-running containers matching no ancestor.

usage() {
  cat <<'USAGE'
agent-sandbox-list [-a|--all] [--roles]

  (default)    running sandboxes for the current workspace
  -a, --all    every sandbox, any workspace, including stopped ones
  --roles      also list the proxy sidecars and port forwarders

The PROXY column is the launch mode: proxy or off.
USAGE
}

list_all=0
show_roles=0

# Sandbox names end in a single-word session selector.
sandbox_word() {
  local sandbox="$1"
  printf '%s\n' "${sandbox##*-}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -a|--all)  list_all=1 ;;
    --roles)   show_roles=1 ;;
    -h|--help) usage; exit 0 ;;
    -*)        echo "${0##*/}: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)         echo "${0##*/}: unexpected argument: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

# Labels come from `podman inspect`, not from the `ps` format string.  Podman's
# ps formatter has no per-key label accessor: `.Label "key"` is Docker's dialect,
# and `index .Labels "key"` is no better, because `table` renders its header row
# by executing the same template against a map of header *strings* -- where
# .Labels is the literal "LABELS".  Either form dies in the header, before a
# single container is printed.  So `ps` is asked only for fields it renders
# plainly, and the header and column alignment are ours rather than podman's.
container_label() { # container key
  podman inspect --format "{{index .Config.Labels \"$2\"}}" "$1" 2>/dev/null || true
}

# Real tabs rather than the `\t` escape, so nothing depends on podman
# normalising the format string.
row_format=$'{{.ID}}\t{{.Names}}\t{{.Status}}'

list_sandboxes() { # ps-args...
  printf 'CONTAINER ID\tNAMES\tSTATUS\tPROXY\tRUNTIME\tWORKSPACE\tCOMMAND\n'
  podman ps "$@" --format "$row_format" |
    while IFS=$'\t' read -r id name status; do
      local ws
      ws="$(container_label "$name" agent-sandbox.workspace)"
      local short_name
      short_name="$(sandbox_word "$name")"
      local cmd
      cmd="$(container_label "$name" agent-sandbox.command)"
      if [[ -z "$cmd" ]]; then
        cmd="$(podman inspect --format '{{range .Config.Cmd}}{{.}} {{end}}' "$name" 2>/dev/null || true)"
        cmd="${cmd% }"
      fi
      # Same fallback as the command column: no label means a launcher that
      # predates it, and only crun existed then.
      local runtime
      runtime="$(container_label "$name" agent-sandbox.runtime)"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$short_name" "$status" \
        "$(container_label "$name" agent-sandbox.proxy)" \
        "${runtime:-crun}" \
        "$ws" \
        "$cmd"
    done
}

list_role() { # ps-args...
  printf 'CONTAINER ID\tNAMES\tSTATUS\tTARGET\n'
  podman ps "$@" --format "$row_format" |
    while IFS=$'\t' read -r id name status; do
      printf '%s\t%s\t%s\t%s\n' "$id" "$name" "$status" \
        "$(container_label "$name" agent-sandbox.target)"
    done
}

if [[ "$list_all" == "1" ]]; then
  echo "All agent-sandbox containers:"
  list_sandboxes -a --filter "label=agent-sandbox.role=sandbox" | column -t -s $'\t'
else
  echo "Agent-sandbox containers for $PWD:"
  list_sandboxes --filter "label=agent-sandbox.role=sandbox" \
                 --filter "label=agent-sandbox.workspace=$PWD" | column -t -s $'\t'
fi

if [[ "$show_roles" == "1" ]]; then
  ps_args=()
  [[ "$list_all" == "1" ]] && ps_args+=(-a)

  echo
  echo "Proxy sidecars:"
  list_role ${ps_args[@]+"${ps_args[@]}"} \
    --filter "label=agent-sandbox.role=proxy" | column -t -s $'\t'

  echo
  echo "Port forwarders:"
  list_role ${ps_args[@]+"${ps_args[@]}"} \
    --filter "label=agent-sandbox.role=port-forward" | column -t -s $'\t'
fi
