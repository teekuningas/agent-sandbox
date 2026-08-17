#!/usr/bin/env bash
# A secret reaches the origin without ever being readable by the agent.
#
# The promise has two halves and both have to hold at once: the request arrives
# authenticated, and nothing in the sandbox -- environment, process list,
# filesystem -- carries the value. A test that checks only the first half would
# pass on an implementation that simply exported the token.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_network
require_env AGENT_SANDBOX_TEST_SECRET "the value to inject; any string will do"

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT
cd "$ws" || exit 1

# Values are resolved on the host by secretspec, from the workspace's own
# manifest -- authorization says the binding is allowed, it does not supply
# anything. The `env` provider reads the variable this case already requires,
# so the manifest can live and die with the temp workspace. Set on the
# command rather than in the user's trusted.toml, which would change the
# provider for every one of their real sessions.
cat > secretspec.toml <<'EOF'
[project]
name = "agent-sandbox-acceptance"
revision = "1.0"

[profiles.default]
AGENT_SANDBOX_TEST_SECRET = { description = "acceptance test value", required = true }
EOF
export SECRETSPEC_PROVIDER="${SECRETSPEC_PROVIDER:-env}"
# The profile is pinned too. secretspec falls back to whatever the host's own
# ~/.config/secretspec/config.toml names as default, and a manifest that only
# declares [profiles.default] fails outright against a host that defaults to,
# say, "development" -- an error about the host's setup, in a case that is not
# about the host's setup.
export SECRETSPEC_PROFILE="${SECRETSPEC_PROFILE:-default}"

# httpbingo.org rather than httpbin.org: this case needs an origin that echoes
# request headers back, and httpbin.org is a famously overloaded free service
# that returns a connection failure often enough to make the case read as a
# broken injector. httpbingo is the maintained Go reimplementation of the same
# API, and it preserves canonical header casing, which the assertions rely on.
cat > AGENTS.md <<'EOF'
# Secret test

```toml agent-sandbox
[network]
allowed_hosts = ["example.com:443"]

[[network.allowed_routes]]
host = "httpbingo.org"
method = "GET"
path = "/headers*"
secret = "AGENT_SANDBOX_TEST_SECRET"
header = "X-Test-Token"
```
EOF

body="$(sandbox_run --workspace --proxy --secrets -- \
  bash -c 'curl --silent --max-time 20 https://httpbingo.org/headers || echo FAILED')"

# A secret definition in AGENTS.md is a request, not an instruction: the host
# has to have authorized that exact binding in ~/.config/agent-sandbox/
# trusted.toml first. That refusal is the feature working, so skip on it
# rather than failing -- this case cannot authorize itself without writing to
# the user's real config, which is the one file it must not forge.
case "$body" in
  *"not authorized"*)
    skip "this secret binding is not authorized on this host. Add to
         ~/.config/agent-sandbox/trusted.toml:
           [[network.allowed_routes]]
           host = \"httpbingo.org\"
           method = \"GET\"
           path = \"/headers*\"
           secret = \"AGENT_SANDBOX_TEST_SECRET\"
           header = \"X-Test-Token\"
           prefix = \"\""
    ;;
  *"secretspec executable not found"*)
    skip "secretspec is not on PATH; the launcher resolves secret values with it"
    ;;
  *"secretspec export failed"*|*"missing required secret"*|*"was not valid JSON"*)
    # Carry secretspec's own words into the skip. Reporting only that it
    # failed costs a whole run to find out why, and this case is expensive to
    # re-run.
    skip "secretspec could not resolve AGENT_SANDBOX_TEST_SECRET with provider
         '${SECRETSPEC_PROVIDER}' and profile '${SECRETSPEC_PROFILE}'. It said:
$(printf '%s' "$body" | grep -v '^note:' | tail -6 | sed 's/^/           /')"
    ;;
esac

# Distinguish "the origin did not answer" from "the header never arrived":
# without this, a flaky origin looks exactly like a broken injector. The
# refusal text above also mentions the header name, which is why this gate
# comes before the assertions and not after.
case "$body" in
  *'"headers"'*) ;;
  *) skip "httpbingo.org did not return its headers document (got: $(printf '%s' "$body" | tr -d '\n' | cut -c1-120))" ;;
esac

assert_contains "$body" "X-Test-Token" "the header the origin saw"
assert_contains "$body" "$AGENT_SANDBOX_TEST_SECRET" "the value the origin saw"

# Now the half that matters more: the sandbox must not be able to read it.
seen="$(sandbox_run --workspace --proxy --secrets -- bash -c '
  env
  cat /proc/self/environ 2>/dev/null | tr "\0" "\n"
  grep -ras . /run /sidecar_secrets /sidecar_shared 2>/dev/null | head -100
' || true)"
assert_not_contains "$seen" "$AGENT_SANDBOX_TEST_SECRET" "everything the sandbox can read"

# And without --secrets the route still works, unauthenticated, rather than
# silently injecting anyway.
body="$(sandbox_run --workspace --proxy -- \
  bash -c 'curl --silent --max-time 20 https://httpbingo.org/headers || echo FAILED')"
assert_not_contains "$body" "$AGENT_SANDBOX_TEST_SECRET" "the request made without --secrets"
