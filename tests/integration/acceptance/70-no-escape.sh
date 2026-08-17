#!/usr/bin/env bash
# The routes out that a proxied sandbox must not have.
#
# Each of these is a way the firewall could be true on paper and false in
# practice. They are cheap to check and expensive to discover in the field.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_network

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT
cd "$ws" || exit 1

cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["example.com:443"]
```
EOF

# Host networking would put the sandbox on the host's stack, where the proxy is
# not in the path at all. The launcher refuses rather than quietly complying.
out="$(sandbox_run --workspace --proxy --podman-args --network host -- bash -c 'true' 2>&1 || true)"
assert_contains "$out" "host networking" "a launch with --network host smuggled in"
assert_fails "the same launch" "$AS" --workspace --proxy --podman-args --network host -- bash -c 'true'

# Unsetting the proxy variables must not help: they are a hint to clients, and
# the sandbox's only route out is still the sidecar's internal network.
out="$(sandbox_run --workspace --proxy -- bash -c '
  unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
  curl --silent --max-time 12 -o /dev/null -w "%{http_code}" https://www.iana.org/ || echo BLOCKED
')"
assert_contains "$out" "BLOCKED" "a request with the proxy variables unset"

# The same, for a host the policy does allow: without the proxy in the path
# there is no route, so this must fail too rather than reaching it directly.
out="$(sandbox_run --workspace --proxy -- bash -c '
  unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
  curl --silent --max-time 12 -o /dev/null -w "%{http_code}" https://example.com/ || echo BLOCKED
')"
assert_contains "$out" "BLOCKED" "a direct request to an allowed host"

# The connection log is the record of what the agent did; the agent must not be
# able to edit it.
out="$(sandbox_run --workspace --proxy -- bash -c '
  echo tampered >> /sidecar_shared/connections.jsonl 2>&1 || echo REFUSED
')"
assert_contains "$out" "REFUSED" "an attempt to write the connection log"
