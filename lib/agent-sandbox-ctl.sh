#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: agent-sandbox-ctl <command> [args...]"
  echo "Commands:"
  printf '  %-9s%s\n' load     "Load the agent-sandbox image"
  printf '  %-9s%s\n' list     "List sandboxes and their proxy mode"
  printf '  %-9s%s\n' status   "Summarise one running sandbox"
  printf '  %-9s%s\n' proxy    "Show or change the proxy policy of a running sandbox"
  printf '  %-9s%s\n' net      "Show network metering for a running sandbox"
  printf '  %-9s%s\n' logs     "Show the proxy log for a running sandbox"
  printf '  %-9s%s\n' ports    "Manage port forwarding"
  printf '  %-9s%s\n' attach   "Attach to a running sandbox and exec a command"
  printf '  %-9s%s\n' mounts   "Manage bind mounts into a running sandbox"
  printf '  %-9s%s\n' purge    "Reclaim leftover containers, networks and directories"
}

cmd="${1:-}"
if [[ -z "$cmd" ]]; then
  agent-sandbox-list
  echo
  usage >&2
  exit 1
fi
shift

case "$cmd" in
  load)        exec agent-sandbox-load "$@" ;;   # "$@" so `load --help` does not import the image
  purge)       exec agent-sandbox-purge "$@" ;;
  port|ports)  exec agent-sandbox-port "$@" ;;
  mount|mounts) exec agent-sandbox-mount "$@" ;;
  list)        exec agent-sandbox-list "$@" ;;
  attach)      exec agent-sandbox-attach "$@" ;;
  status)      exec agent-sandbox-status "$@" ;;
  proxy|fw)    exec agent-sandbox-firewall "$@" ;;
  net|network) exec agent-sandbox-net "$@" ;;
  logs|log)    exec agent-sandbox-logs "$@" ;;
  -h|--help|help) usage ;;
  *)           echo "agent-sandbox-ctl: unknown command: $cmd" >&2; usage >&2; exit 1 ;;
esac
