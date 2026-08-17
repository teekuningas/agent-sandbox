#!/usr/bin/env bash
# An [[network.allowed_routes]] rule narrows a host to specific requests.
#
# Enforcing this means terminating TLS on the session CA, so the case also
# checks the two halves that make that safe: the sandbox trusts the CA only
# when a rule needs it, and a denied request is denied after decryption rather
# than before the policy could see it.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_network

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT
cd "$ws" || exit 1

# example.com rather than httpbin.org: this case has to distinguish "the proxy
# refused" from "the origin was flaky", and httpbin is famously the latter.
# example.com serves / and 404s everything else, both from a stable host.
cat > AGENTS.md <<'EOF'
# L7 test

```toml agent-sandbox
[[network.allowed_routes]]
host = "example.com"
method = "GET"
path = "/"
```
EOF

code='curl --silent --show-error --max-time 20 -o /dev/null -w "%{http_code}"'

out="$(sandbox_run --workspace --proxy -- bash -c "$code https://example.com/ || echo BLOCKED")"
assert_contains "$out" "200" "the method and path the route allows"

# A different path on the same host. The origin would answer 404; the proxy
# must not let the request reach it at all.
out="$(sandbox_run --workspace --proxy -- bash -c "$code https://example.com/admin || echo BLOCKED")"
assert_denied "$out" "a path the route does not cover"

out="$(sandbox_run --workspace --proxy -- \
  bash -c "$code -X POST https://example.com/ || echo BLOCKED")"
assert_denied "$out" "a method the route does not allow"

# The CA is handed over only because this policy has an L7 rule.
out="$(sandbox_run --workspace --proxy -- bash -c 'ls /run/agent-sandbox-proxy-ca.pem 2>&1 || echo ABSENT')"
assert_contains "$out" "/run/agent-sandbox-proxy-ca.pem" "the session CA under an L7 policy"

# With no L7 rule there is nothing to intercept, so no CA should be trusted:
# a CA that can mint any name is not something to hand over for free.
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["example.com:443"]
```
EOF
out="$(sandbox_run --workspace --proxy -- bash -c 'ls /run/agent-sandbox-proxy-ca.pem 2>&1 || echo ABSENT')"
assert_contains "$out" "ABSENT" "the session CA under an L4-only policy"

# ...and an L4 rule for the same host still passes traffic through untouched.
out="$(sandbox_run --workspace --proxy -- bash -c "$code https://example.com/ || echo BLOCKED")"
assert_contains "$out" "200" "an L4-allowed host with no interception"
