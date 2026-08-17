#!/usr/bin/env bash
# The headline promise: under --proxy, nothing gets out that was not allowed.
#
# This is the case the whole project exists for, and it is the one thing no
# unit test can establish -- policy.rs's tests prove the decision function is
# right, not that the decision function is the one in the request's path.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_network

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT
cd "$ws" || exit 1

cat > AGENTS.md <<'EOF'
# Egress test

```toml agent-sandbox
[network]
allowed_hosts = ["example.com:443"]
```
EOF

fetch='curl --silent --show-error --max-time 15 -o /dev/null -w "%{http_code}"'

# The allowed host, on the allowed port.
out="$(sandbox_run --workspace --proxy -- bash -c "$fetch https://example.com/ || echo BLOCKED")"
assert_contains "$out" "200" "an allowed host"

# A host that was never mentioned.
out="$(sandbox_run --workspace --proxy -- bash -c "$fetch https://www.iana.org/ || echo BLOCKED")"
assert_denied "$out" "a host that is not in the policy"

# The allowed name on a port the rule does not cover. A rule that carries a
# port is matched on that port alone.
out="$(sandbox_run --workspace --proxy -- bash -c "$fetch http://example.com/ || echo BLOCKED")"
assert_denied "$out" "the allowed host on a port the rule does not name"

# Raw IP, bypassing the name entirely: the proxy checks the resolved address
# too, so this must not be a way around a domain rule.
out="$(sandbox_run --workspace --proxy -- bash -c \
  "curl --silent --max-time 15 -o /dev/null -w '%{http_code}' https://1.1.1.1/ || echo BLOCKED")"
assert_denied "$out" "a bare IP address"

# DNS is not an escape hatch either: without the proxy's resolver in the path
# a direct query should not leave the sandbox.
out="$(sandbox_run --workspace --proxy -- bash -c \
  "timeout 8 getent hosts www.iana.org >/dev/null 2>&1 && echo RESOLVED || echo BLOCKED")"
assert_contains "$out" "BLOCKED" "a direct DNS lookup of a denied name"

# An empty policy denies everything, including the hosts a laxer default might
# have let through.
rm AGENTS.md
out="$(sandbox_run --workspace --proxy -- bash -c "$fetch https://example.com/ || echo BLOCKED")"
assert_denied "$out" "any host under an empty policy"
