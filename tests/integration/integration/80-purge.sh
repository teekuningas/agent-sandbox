#!/usr/bin/env bash
# `ctl purge` reclaims what a killed launcher left behind.
#
# Leaked sidecar networks exhaust the rootless subnet pool, at which point no
# sandbox starts at all -- so the recovery path matters as much as the happy one.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_network

ws="$(make_workspace)"
cd "$ws" || exit 1
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["example.com:443"]
```
EOF
# cd out before removing the workspace, or the shell's own cwd goes missing
# and podman complains about it on the way out.
trap 'cd /; rm -rf "$ws"; cleanup_sandboxes' EXIT

before="$(sidecar_networks)"

# SIGKILL the launcher, so its cleanup guard never runs.  The command is short
# because the sandbox has to outlive the launcher and then exit on its own:
# that is what leaves a sidecar with nothing to serve, which is the only thing
# purge is entitled to reclaim.
sandbox_run --workspace --proxy -- bash -c 'sleep 20' &
launcher=$!
sleep 8
kill -9 $launcher 2>/dev/null
wait $launcher 2>/dev/null

# Named, not counted. Purge is entitled to reclaim leaks from earlier runs
# too -- that is its job -- so a count taken beforehand is not a valid
# post-condition. What must hold is that the network this case leaked is gone.
leaked="$(comm -13 <(printf '%s\n' "$before") <(sidecar_networks))"
[ -n "$leaked" ] \
  || skip "the launcher was not killed with a sidecar network live; nothing to purge"
pass_note "a killed launcher leaked $(printf '%s\n' "$leaked" | wc -l) network(s), as expected"

# A sandbox outlives the launcher that started it: --rm cleanup runs when the
# container exits, not when the client dies. Until it does exit, the sidecar
# still has a live target and its network is genuinely in use -- purge keeping
# it would be correct, so asserting before that point would test nothing.
# Wait for the real orphan, and say so rather than failing if it never comes.
sidecar="$(printf '%s\n' "$leaked" | head -1)"
target="$(podman inspect -f '{{index .Config.Labels "agent-sandbox.target"}}' \
  "$sidecar" 2>/dev/null || true)"
if [ -n "$target" ]; then
  for _ in $(seq 1 45); do
    podman container exists "$target" || break
    sleep 1
  done
  podman container exists "$target" \
    && skip "the sandbox outlasted its launcher for longer than the case waits"
  pass_note "the sandbox exited, leaving the sidecar with nothing to serve"
fi

"$AS" ctl purge --force >/dev/null 2>&1

remaining="$(sidecar_networks)"
for net in $leaked; do
  printf '%s\n' "$remaining" | grep -qx "$net" \
    && _fail "purge left the leaked network $net behind"
  # The session's /tmp directories are named after the same id, and the
  # launcher labels them that way precisely so purge can find them.
  [ -e "/tmp/$net" ] \
    && _fail "purge left the leaked directory /tmp/$net behind"
done
pass_note "purge reclaimed every network and directory the killed launcher leaked"
