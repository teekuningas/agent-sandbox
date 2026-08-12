#!/usr/bin/env bash
# Network metering for a *running* sandbox.
#
# The proxy already accounts every connection into a log, so this needs no
# control channel: it reads that log out of the *sidecar* with `podman exec`.
#
# The sidecar, not the sandbox: the sandbox has no access to the log at all, so
# the code being metered cannot rewrite the record of what it did.  Reading
# through exec rather than from the host side of the bind mount also ties follow
# mode's lifetime to the container, with no watchdog and no race against the
# launcher removing the directory.
#
# Records describe *completed* connections: the proxy writes one when a
# connection closes, plus an "open" record when it starts, so a live tunnel
# shows up as in-flight rather than as traffic.  Nothing here can see individual
# requests inside a tunnel; the proxy never decrypts one.

log_path=/sidecar_shared/connections.jsonl

usage() {
  cat <<'USAGE'
agent-sandbox-net [-f|--follow] [WORD] [--sandbox WORD]

  (no flags)   print the network summary for the sandbox as it stands now
  -f, --follow stream connections as the proxy records them, until Ctrl-C
               or until the sandbox exits

With one sandbox running, --sandbox may be omitted.  With several, it is
required unless the current directory matches exactly one sandbox workspace.

Requires the sandbox to have been launched with --proxy;
without a proxy there is nothing to meter.
USAGE
}

cmd_summary() {
  # An absent log is the normal state before the first connection, so a failed
  # read renders as "no connections" rather than as an error.
  { podman exec "$1" cat "$log_path" 2>/dev/null || true; } |
    agent-sandbox-network-summary -
}

cmd_follow() {
  local sidecar="$1" status=0
  echo "${0##*/}: following $sidecar (Ctrl-C to stop)" >&2
  # -F rather than -f: the proxy creates the log at startup, but a sidecar
  # inspected in its first moments may still beat it to it.  Its stderr is
  # dropped because -F narrates that wait.
  podman exec "$sidecar" tail -n +1 -F -- "$log_path" 2>/dev/null |
    agent-sandbox-network-summary --stream - || status=$?
  # The ordinary way out is the sidecar going away, which makes the exec fail;
  # that is not an error worth a non-zero exit.
  if ! podman container exists "$sidecar"; then
    printf '\n%s stopped.\n' "$sidecar"
    return 0
  fi
  return "$status"
}

follow=0
sandbox_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--follow) follow=1 ;;
    --sandbox)
      shift
      [[ $# -gt 0 ]] || { echo "${0##*/}: --sandbox needs a name" >&2; exit 1; }
      sandbox_name="$1"
      ;;
    --sandbox=*) sandbox_name="${1#--sandbox=}" ;;
    -h|--help)   usage; exit 0 ;;
    -*)          echo "${0##*/}: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)
       if [[ -z "$sandbox_name" ]]; then
         sandbox_name="$1"
       else
         echo "${0##*/}: unexpected argument: $1" >&2; usage >&2; exit 1
       fi
       ;;
  esac
  shift
done

# Anchored on an alphanumeric so a following flag cannot be swallowed as the
# name: `--sandbox --follow` should be an error, not a lookup for a container
# called "--follow".
if [[ -n "$sandbox_name" && ! "$sandbox_name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
  echo "${0##*/}: invalid sandbox name: $sandbox_name" >&2
  exit 1
fi

sandbox=$(resolve_sandbox "$sandbox_name" --running)
sidecar=$(require_sidecar "$sandbox")

if [[ "$follow" == "1" ]]; then
  cmd_follow "$sidecar"
else
  cmd_summary "$sidecar"
fi
