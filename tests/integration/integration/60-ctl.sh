#!/usr/bin/env bash
# `ctl` finds a running sandbox and reports it correctly.
#
# Every ctl subcommand resolves its target from container labels, so this is
# also the check that the labels the launcher writes are the labels ctl reads.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

ws="$(make_workspace)"
cleanup() { kill $launcher 2>/dev/null; rm -rf "$ws"; cleanup_sandboxes; }
trap cleanup EXIT
cd "$ws" || exit 1

sandbox_run --workspace -- bash -c 'sleep 60' &
launcher=$!

word="$(wait_for_sandbox 60)" || _fail "no sandbox appeared in ctl list"
pass_note "session word is [$word]"

listed="$("$AS" ctl list 2>&1)"
assert_contains "$listed" "$(basename "$ws")" "ctl list's workspace column"

status="$("$AS" ctl status "$word" 2>&1)"
assert_contains "$status" "$(basename "$ws")" "ctl status for that session"

# `ctl mounts ls` reports the binds added on top of the launcher's own, so the
# workspace bind is deliberately filtered out of the mount list -- it appears
# on the workspace line instead, as the host path. A plain sandbox has no
# added mounts at all, and saying so is the correct answer here.
mounts="$("$AS" ctl mounts ls "$word" 2>&1 || "$AS" ctl mount ls "$word" 2>&1)"
assert_contains "$mounts" "$(basename "$ws")" "ctl mounts' workspace line"
assert_contains "$mounts" "(none)" "ctl mounts on a sandbox with no added binds"

# An unproxied sandbox has no sidecar, and ctl must say so rather than
# resolving to some other session's proxy.
out="$("$AS" ctl proxy show "$word" 2>&1 || true)"
assert_not_contains "$out" "allow " "the policy of a sandbox launched without --proxy"
