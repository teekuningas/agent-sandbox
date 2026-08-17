#!/usr/bin/env bash
# --workspace mounts the host's cwd, read-write, at the path the launcher says.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

ws="$(make_workspace)"
trap 'rm -rf "$ws"' EXIT
echo "from the host" > "$ws/host-file"
base="$(basename "$ws")"

cd "$ws" || exit 1

out="$(sandbox_run --workspace -- bash -c 'pwd')"
assert_contains "$out" "/workspace/$base" "the working directory inside"

out="$(sandbox_run --workspace -- cat host-file)"
assert_contains "$out" "from the host" "a host file read from inside"

sandbox_run --workspace -- bash -c 'echo "from the sandbox" > sandbox-file' >/dev/null
[ -f "$ws/sandbox-file" ] || _fail "a write inside did not land on the host"
assert_eq "from the sandbox" "$(cat "$ws/sandbox-file")" "a write inside, read on the host"

# Without the flag, nothing of the host is there at all.
out="$(sandbox_run -- bash -c 'ls /workspace 2>&1')"
assert_not_contains "$out" "$base" "an unmounted sandbox's /workspace"

# --userns=keep-id: files created inside belong to the host user, not to root.
# Getting this wrong leaves an agent's output undeletable without sudo.
sandbox_run --workspace -- bash -c 'touch owned-by' >/dev/null
assert_eq "$(id -u)" "$(stat -c %u "$ws/owned-by")" "the owner of a file created inside"
