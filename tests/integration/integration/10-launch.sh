#!/usr/bin/env bash
# A sandbox starts, runs a command, and reports what the command reported.
#
# The stub-podman tests prove the launcher builds the right argv; only a real
# container proves the argv means what it was meant to mean.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

out="$(sandbox_run -- bash -c 'echo alive')"
assert_contains "$out" "alive" "the command's stdout"

sandbox_run -- bash -c 'exit 7' >/dev/null 2>&1
assert_status 7 $? "a failing command's exit code"

# Every agent the catalog declares must actually be on the image's PATH. This
# is the check that catches an agents.nix entry whose package did not land.
agents="$("$AS" --help | sed -n '/^Agents:/{n;p;}')"
for agent in $agents; do
  case "$agent" in
    opencode) cmd=opencode ;;
    claude) cmd=claude ;;
    copilot) cmd=copilot ;;
    antigravity) cmd=agy ;;
    codex) cmd=codex ;;
    *) continue ;;
  esac
  out="$(sandbox_run -- bash -c "command -v $cmd" 2>&1)"
  assert_contains "$out" "$cmd" "$agent's command on the image PATH"
done
