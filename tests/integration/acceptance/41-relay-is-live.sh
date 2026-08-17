#!/usr/bin/env bash
# The relay's authorization can be widened mid-session, and every decision it
# makes is recorded with a timestamp.
#
# This is the property the TUI's `a` key stands on: it appends `allow_signing`
# to the live policy and expects the next `git push` to work without a
# relaunch. relay-server re-reads the policy on every call, which is what makes
# that true -- and is not something a unit test can show.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_network
require_command ssh
[ -n "${SSH_AUTH_SOCK:-}" ] || skip "no SSH agent on the host (SSH_AUTH_SOCK is unset)"
ssh-add -l >/dev/null 2>&1 || skip "the host SSH agent holds no keys"
require_trusted_host_key github.com

ws="$(make_workspace)"
cleanup() { kill $launcher 2>/dev/null; rm -rf "$ws"; cleanup_sandboxes; }
trap cleanup EXIT
cd "$ws" || exit 1

# No :22 entry anywhere: the relay starts out refusing every SSH destination.
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["example.com:443"]
```
EOF

sandbox_run --workspace --proxy --ssh -- bash -c 'sleep 180' &
launcher=$!

word="$(wait_for_sandbox 90)" || _fail "no sandbox came up"
pass_note "session word is [$word]"

probe='ssh -o ConnectTimeout=10 -T git@github.com'

out="$("$AS" ctl attach "$word" -- bash -c "$probe 2>&1 || true")"
assert_not_contains "$out" "successfully authenticated" "an SSH probe with no :22 rule"

# The denial is in the relay's own log, with the clock the TUI needs to age it.
logged="$("$AS" ctl relay "$word" 2>&1 || true)"
assert_contains "$logged" '"allowed":false' "the relay log after a refusal"
assert_contains "$logged" "github.com" "the refused destination"
assert_contains "$logged" '"ts":' "a timestamp on the relay record"

# Widening it live is exactly what the TUI keypress does: the host rule plus
# the allow_signing entry the relay actually consults.
allowed="$("$AS" ctl proxy allow github.com:22 "$word" 2>&1)" \
  || _fail "ctl proxy allow failed: $allowed"
assert_contains "$allowed" "ssh (push/pull)" "allow reporting the relay grant"
sleep 3

shown="$("$AS" ctl relay "$word" 2>&1)"
assert_contains "$shown" "github.com" "the relay's authorized hosts after widening"

# The point of the whole exercise: the same container, no relaunch.
out="$("$AS" ctl attach "$word" -- bash -c "$probe 2>&1 || true")"
assert_contains "$out" "successfully authenticated" "an SSH probe after a live grant"

# And back again.
removed="$("$AS" ctl proxy rm allow github.com:22 "$word" 2>&1)" \
  || _fail "ctl proxy rm allow failed: $removed"
sleep 3
out="$("$AS" ctl attach "$word" -- bash -c "$probe 2>&1 || true")"
assert_not_contains "$out" "successfully authenticated" "an SSH probe after narrowing again"
