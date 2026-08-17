#!/usr/bin/env bash
# The policy can be widened and narrowed while the sandbox is running, and
# every decision is recorded.
#
# `ctl proxy allow` writing a file is unit-testable; the proxy noticing that
# write, mid-session, and changing what it lets through is not.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_network

ws="$(make_workspace)"
cleanup() { kill $launcher 2>/dev/null; rm -rf "$ws"; cleanup_sandboxes; }
trap cleanup EXIT
cd "$ws" || exit 1

cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["example.com:443"]
```
EOF

sandbox_run --workspace --proxy -- bash -c 'sleep 120' &
launcher=$!

word="$(wait_for_sandbox 90)" || _fail "no sandbox came up"
pass_note "session word is [$word]"

shown="$("$AS" ctl proxy show "$word" 2>&1)"
assert_contains "$shown" "example.com" "the live policy at startup"
assert_not_contains "$shown" "www.iana.org" "the live policy before widening"

# The rule comes first and the session name second -- `ctl proxy allow` takes
# the target as its leading positional, with the word optional after it.
allowed="$("$AS" ctl proxy allow www.iana.org:443 "$word" 2>&1)" \
  || _fail "ctl proxy allow failed: $allowed"
sleep 3

shown="$("$AS" ctl proxy show "$word" 2>&1)"
assert_contains "$shown" "www.iana.org" "the live policy after widening"

# The reload is what matters: does a request that was denied a moment ago now
# succeed, in the container that is already running?
out="$("$AS" ctl attach "$word" -- \
  curl --silent --max-time 15 -o /dev/null -w '%{http_code}' https://www.iana.org/ 2>&1 || echo BLOCKED)"
assert_contains "$out" "200" "a request to the host just allowed"

# `rm` picks the rule kind as a subcommand: `allow` for an allow_host rule.
removed="$("$AS" ctl proxy rm allow www.iana.org:443 "$word" 2>&1)" \
  || _fail "ctl proxy rm allow failed: $removed"
sleep 3
out="$("$AS" ctl attach "$word" -- \
  curl --silent --max-time 15 -o /dev/null -w '%{http_code}' https://www.iana.org/ 2>&1 || echo BLOCKED)"
assert_contains "$out" "BLOCKED" "the same request after narrowing again"

# Both decisions have to be in the log, or the TUI and the session summary are
# showing something other than what happened.
logged="$("$AS" ctl logs "$word" 2>&1 || true)"
assert_contains "$logged" "www.iana.org" "the connection log"
