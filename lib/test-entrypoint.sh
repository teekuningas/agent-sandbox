#!/usr/bin/env bash
# Behavioural tests for agent-sandbox-entrypoint's proxy-blind-spot
# compensation: known tools that ignore HTTP_PROXY/HTTPS_PROXY unless given
# an extra opt-in get that opt-in set here, once, for every sandboxed
# project. Node is the current case (NODE_USE_ENV_PROXY, added in Node 24).
#
# Usage: test-entrypoint.sh [path-to-entrypoint]

set -euo pipefail

entrypoint="${1:-$(dirname "$0")/entrypoint.sh}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0

pass() { printf 'ok       %s\n' "$1"; }
fail() {
  printf 'FAIL     %s\n' "$1"
  printf '%s\n' "${2:-}" > "$tmp/msg"
  sed 's/^/           /' "$tmp/msg"
  failures=$((failures + 1))
}

# Runs the entrypoint with a fresh, isolated $HOME, skipping the Nix-store
# and gpg-agent steps (neither applies to a plain script invocation), and
# captures the environment `exec "$@"` would hand to the real command.
run_entrypoint() {
  HOME="$tmp/home-$RANDOM" AGENT_SANDBOX_HOST_NIX=1 bash "$entrypoint" env
}

run_entrypoint_skip_nix() {
  HOME="$tmp/home-$RANDOM" AGENT_SANDBOX_SKIP_NIX_INIT=1 bash "$entrypoint" env
}

# --- HTTP_PROXY set: Node's opt-in is turned on ----------------------------

got=$(HTTP_PROXY=http://10.0.0.1:8888 HTTPS_PROXY=http://10.0.0.1:8888 run_entrypoint)
if grep -qx 'NODE_USE_ENV_PROXY=1' <<< "$got"; then
  pass "HTTP_PROXY set: NODE_USE_ENV_PROXY defaults to 1"
else
  fail "HTTP_PROXY set: NODE_USE_ENV_PROXY defaults to 1" "$got"
fi

# --- an operator's own override is never clobbered -------------------------

got=$(HTTP_PROXY=http://10.0.0.1:8888 NODE_USE_ENV_PROXY=0 run_entrypoint)
if grep -qx 'NODE_USE_ENV_PROXY=0' <<< "$got"; then
  pass "explicit NODE_USE_ENV_PROXY=0 survives"
else
  fail "explicit NODE_USE_ENV_PROXY=0 survives" "$got"
fi

# --- no proxy in play: nothing is forced on ---------------------------------

got=$(unset HTTP_PROXY HTTPS_PROXY; run_entrypoint)
if grep -qx 'NODE_USE_ENV_PROXY=1' <<< "$got"; then
  fail "no HTTP_PROXY: NODE_USE_ENV_PROXY must stay unset" "$got"
else
  pass "no HTTP_PROXY: NODE_USE_ENV_PROXY stays unset"
fi

# --- sidecar path can skip nix bootstrap explicitly --------------------------

got=$(run_entrypoint_skip_nix)
if grep -qx 'AGENT_SANDBOX_SKIP_NIX_INIT=1' <<< "$got"; then
  pass "AGENT_SANDBOX_SKIP_NIX_INIT survives into command env"
else
  fail "AGENT_SANDBOX_SKIP_NIX_INIT survives into command env" "$got"
fi

if [[ "$failures" -gt 0 ]]; then
  printf '\n%s test(s) failed\n' "$failures" >&2
  exit 1
fi

printf '\nall entrypoint tests passed\n'
