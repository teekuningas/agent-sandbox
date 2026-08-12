#!/usr/bin/env bash
# The proxy sidecar's log for a sandbox.
#
# This is the one log a user cannot otherwise reach: the sandbox's own output is
# already on their terminal (the launcher runs podman in the foreground), while
# the sidecar is a detached container whose name is random and was printed at most
# once, in a warning, if at all.
#
# Structured connection records are `agent-sandbox-ctl net`; this is the proxy's
# stderr -- the effective policy at startup, each denial as it happens, DNS and
# connect failures, and route problems from the sidecar.

usage() {
  cat <<'USAGE'
agent-sandbox-logs [-f|--follow] [--tail N] [WORD] [--sandbox WORD]

Shows the proxy sidecar's log for a sandbox.

  -f, --follow   keep streaming until Ctrl-C or the sidecar stops
  --tail N       show only the last N lines (default: all)

With one sandbox running, --sandbox may be omitted.  Requires the sandbox to
have been launched with --proxy.
USAGE
}

follow=0
tail_lines=""
sandbox_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--follow) follow=1 ;;
    --tail)
      shift
      [[ $# -gt 0 ]] || { echo "${0##*/}: --tail needs a line count" >&2; exit 1; }
      tail_lines="$1"
      ;;
    --tail=*)    tail_lines="${1#--tail=}" ;;
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

if [[ -n "$sandbox_name" && ! "$sandbox_name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
  echo "${0##*/}: invalid sandbox name: $sandbox_name" >&2
  exit 1
fi
if [[ -n "$tail_lines" && ! "$tail_lines" =~ ^[0-9]+$ ]]; then
  echo "${0##*/}: --tail needs a line count, got: $tail_lines" >&2
  exit 1
fi

sandbox=$(resolve_sandbox "$sandbox_name" --running)
sidecar=$(require_sidecar "$sandbox")

logs_args=()
[[ -n "$tail_lines" ]] && logs_args+=(--tail "$tail_lines")
[[ "$follow" == "1" ]] && logs_args+=(--follow)

status=0
podman logs "${logs_args[@]}" "$sidecar" || status=$?

# Following ends when the sidecar goes away, which is the ordinary way out of
# this command rather than a failure.
if [[ "$follow" == "1" ]] && ! podman container exists "$sidecar"; then
  exit 0
fi
exit "$status"
