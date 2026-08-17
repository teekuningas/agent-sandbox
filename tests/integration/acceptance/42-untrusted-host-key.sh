#!/usr/bin/env bash
# A policy that authorizes SSH to a host the operator has not vouched for
# refuses the launch, and leaves nothing behind.
#
# The unit tests cover the decision; what only a real run shows is that the
# refusal happens before any container or network exists. A refusal that leaks
# a podman network is worse than no refusal, because the next launch inherits
# it.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT
cd "$ws" || exit 1

# A host nothing could plausibly have a key for, so this case is decided by the
# policy rather than by whatever the runner happens to trust.
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["git.invalid.example:22"]
```
EOF

before="$(podman network ls --quiet | wc -l)"

out="$(sandbox_run --workspace --proxy -- bash -c 'echo REACHED' 2>&1 || true)"

assert_not_contains "$out" "REACHED" "a sandbox with an unauthorized SSH host"
assert_contains "$out" "trusted.toml" "the refusal naming the file to edit"
assert_contains "$out" "[[network.known_hosts]]" "the refusal carrying the block to paste"
assert_contains "$out" "git.invalid.example" "the refusal naming the host"

after="$(podman network ls --quiet | wc -l)"
assert_eq "$before" "$after" "the podman network count across a refused launch"

# The same policy without the SSH port launches: only :22 pulls the
# requirement in.
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["git.invalid.example:443"]
```
EOF
out="$(sandbox_run --workspace --proxy -- bash -c 'echo REACHED' 2>&1 || true)"
assert_contains "$out" "REACHED" "the same policy with no :22 entry"
