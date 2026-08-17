#!/usr/bin/env bash
# Declared mounts appear with the options they declared -- and `ro` really is.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

ws="$(make_workspace)"
trap 'rm -rf "$ws"' EXIT
mkdir -p "$ws/data" "$ws/readonly"
echo "payload" > "$ws/readonly/file"

cat > "$ws/AGENTS.md" <<'EOF'
# Mount test

```toml agent-sandbox
[mounts]
"data" = "/workspace/data"
"readonly" = { destination = "/mnt/ro", options = "ro" }
```
EOF

cd "$ws" || exit 1

out="$(sandbox_run --workspace --mounts -- bash -c 'cat /mnt/ro/file')"
assert_contains "$out" "payload" "a read-only declared mount"

out="$(sandbox_run --workspace --mounts -- bash -c 'echo x > /mnt/ro/file 2>&1 || echo REFUSED')"
assert_contains "$out" "REFUSED" "a write to a mount declared read-only"

out="$(sandbox_run --workspace --mounts -- bash -c 'echo written > /workspace/data/f && echo ok')"
assert_contains "$out" "ok" "a write to a mount declared read-write"
assert_eq "written" "$(cat "$ws/data/f")" "that write, seen on the host"

# Without --mounts, a declaration binds nothing. AGENTS.md is a project file
# and may be untrusted; it must not be able to reach into the host on its own.
# Asserted on the payload, not on the listing: ls's own "No such file or
# directory" contains the word "file", so a check for the filename passes on
# the failure text too.
out="$(sandbox_run --workspace -- bash -c 'cat /mnt/ro/file 2>&1 || echo ABSENT')"
assert_not_contains "$out" "payload" "the declared mount without --mounts"
