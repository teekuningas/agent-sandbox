#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
agent-sandbox-attach [WORD] [-- CMD...]

Executes an interactive command inside a running sandbox.
If no command is provided, starts an interactive bash shell.

   WORD    The session word or full container name of the sandbox.
          If omitted, acts on the current workspace's sandbox.
  CMD     The command to execute (default: bash).
USAGE
}

explicit=""
cmd=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --) shift; cmd=("$@"); break ;;
    -*) echo "${0##*/}: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *) 
       if [[ -z "$explicit" ]]; then
         explicit="$1"
       else
         echo "${0##*/}: unexpected argument: $1" >&2; usage >&2; exit 1
       fi
       ;;
  esac
  shift
done

sandbox="$(resolve_sandbox "$explicit" --running)"

# Not left to podman: crun's fallback exec path would enter the *VMM's*
# namespaces on success, giving a shell on the host kernel beside the VM rather
# than inside it -- the wrong side of the boundary --krun was chosen for.
refuse_if_krun "$sandbox" "attach" \
  "crun's libkrun handler implements no exec, so there is no way into the guest." \
  "Either launch a second sandbox on the same workspace, or run the shell as" \
  "the sandbox's own command:  agent-sandbox --krun -- bash"

if [[ ${#cmd[@]} -eq 0 ]]; then
  cmd=(bash)
fi

exec podman exec -it "$sandbox" "${cmd[@]}"
