#!/usr/bin/env bash
# Under --proxy, SSH works through the relay and only for allowed hosts.
#
# The point of the relay is that the agent socket stays on the sidecar: the
# sandbox can ask for a signature but cannot use the key for anything the
# policy did not authorize. Both halves are checked here.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_network
require_command ssh
[ -n "${SSH_AUTH_SOCK:-}" ] || skip "no SSH agent on the host (SSH_AUTH_SOCK is unset)"
ssh-add -l >/dev/null 2>&1 || skip "the host SSH agent holds no keys"
require_trusted_host_key github.com

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT
cd "$ws" || exit 1

cat > AGENTS.md <<'EOF'
# Relay test

```toml agent-sandbox
[network]
allowed_hosts = ["github.com:22"]
```
EOF

# GitHub answers an authenticated SSH probe with a greeting and exit 1, so the
# greeting is the signal, not the status.
#
# No StrictHostKeyChecking flag here, deliberately: the probe has to work the
# way `git clone` invokes ssh, with nothing added. relay-server pins the forge
# host keys in the sidecar, because that is where the real ssh runs -- the
# sandbox's own known_hosts is on the wrong side of the boundary, and root's
# home there is /root rather than the image's HOME.
#
# This is also the case that catches the sidecar losing its /etc/passwd: the
# relay runs ssh there rather than in the sandbox, and the sidecar runs without
# --userns=keep-id over an image that ships no passwd file, so ssh fails at
# getpwuid with "No user exists for uid 0" long before any policy is consulted.
out="$(sandbox_run --workspace --proxy --ssh -- \
  bash -c 'ssh -T git@github.com 2>&1 || true')"
assert_contains "$out" "successfully authenticated" "an SSH probe to an allowed host"
assert_not_contains "$out" "Host key verification failed" "the relay's pinned known_hosts"

# Which keys are trusted is the operator's decision, made in trusted.toml, and
# the sandbox does not get to revisit it per invocation. These two options are
# the whole of how you would try, and both are refused.
out="$(sandbox_run --workspace --proxy --ssh -- \
  bash -c 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -T git@github.com 2>&1 || true')"
assert_not_contains "$out" "successfully authenticated" "an SSH probe overriding known_hosts"
assert_contains "$out" "trusted.toml" "the refusal pointing at where keys are authorized"

# A jump host passes the destination check -- the destination really is the
# allowed host -- and then connects somewhere else with the forwarded agent
# along for the ride.
out="$(sandbox_run --workspace --proxy --ssh -- \
  bash -c 'ssh -o ConnectTimeout=10 -J nowhere.invalid -T git@github.com 2>&1 || true')"
assert_not_contains "$out" "successfully authenticated" "an SSH probe through a jump host"
assert_contains "$out" "denied" "the refusal of a jump host"

# One entry, two ports: the relay reads 22 out of the list exactly as it would
# out of a lone ":22" entry, and the proxy still allows 443.
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["github.com:22,443"]
```
EOF
out="$(sandbox_run --workspace --proxy --ssh -- \
  bash -c 'ssh -T git@github.com 2>&1 || true;
           echo "https:$(curl --silent --show-error --max-time 20 -o /dev/null -w "%{http_code}" https://github.com/ 2>&1 || echo BLOCKED)"')"
assert_contains "$out" "successfully authenticated" "an SSH probe with a comma-separated port list"
assert_contains "$out" "https:2" "an HTTPS fetch with a comma-separated port list"

cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["github.com:22"]
```
EOF

# No socket is mounted into the sandbox: the capability is the relay, not the
# agent itself.
out="$(sandbox_run --workspace --proxy --ssh -- bash -c 'echo "${SSH_AUTH_SOCK:-unset}"')"
assert_not_contains "$out" "/run/host-ssh-agent" "SSH_AUTH_SOCK inside a proxied sandbox"

# A host with no :22 rule is refused by the relay, even though the same agent
# holds a key that would work for it.
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["example.com:443"]
```
EOF
out="$(sandbox_run --workspace --proxy --ssh -- \
  bash -c 'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -T git@github.com 2>&1 || true')"
assert_not_contains "$out" "successfully authenticated" "an SSH probe with no :22 rule"
