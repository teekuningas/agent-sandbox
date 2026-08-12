#!/usr/bin/env bash
# Hand-run smoke test for --krun, against real microVMs.
#
# This is the spike that gates the flag.  Nothing about --krun has been measured
# against a running guest: the flag was written from the crun and libkrun
# sources, and every claim it rests on is checked here rather than assumed.
# `nix flake check` covers the argument handling and the two ctl refusals, and
# stops there -- it cannot boot a VM.
#
# Needs, beyond what lib/smoke-firewall.sh needs:
#   * /dev/kvm, readable and writable by you (usually the 'kvm' group).  Cloud
#     VMs frequently have nested virtualisation off, and then nothing here runs.
#   * a crun built with libkrun (`crun --version` prints +LIBKRUN).
#
# Usage:  bash lib/smoke-krun.sh
#
# Assumes `agent-sandbox` and `agent-sandbox-ctl` are on PATH and the image is
# loaded (agent-sandbox-ctl load).
#
# Unlike smoke-firewall.sh there is no in_sandbox() helper, because there is no
# exec: crun's libkrun handler implements none.  Every containment check is a
# fresh one-shot launch whose exit status is the assertion.  That is slow, and
# it is the only honest way to ask a runtime with no exec what it can reach.

set -uo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# smoke-firewall.sh takes this straight from the environment; defaulting it
# instead means this script also works from a plain shell, which matters more
# here because the nested-podman check below is the only user of it.
image="${AGENT_SANDBOX_IMAGE:-localhost/agent-sandbox:latest}"

failures=0
pass() { printf 'ok       %s\n' "$1"; }
fail() { printf 'FAIL     %s\n' "$1"; printf '%s\n' "${2:-}" | sed 's/^/           /'; failures=$((failures + 1)); }
skip() { printf 'skip     %s\n' "$1"; printf '%s\n' "${2:-}" | sed 's/^/           /'; }

# Same baselines as smoke-firewall.sh: a sandbox that was already up owns a
# session network and a policy dir, and counting those as leaks is a false alarm.
nets_before=$(podman network ls --filter "name=^agent-sandbox-sidecar-" --format '{{.Name}}' | wc -l)
dirs_before=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'agent-sandbox-policy-*' 2>/dev/null | wc -l)

mkdir -p "$tmp/work"
cd "$tmp/work" || exit 1

# ── 0a. prerequisites ────────────────────────────────────────────────────────
# Checked rather than assumed, so a machine that simply cannot do this says so
# once instead of failing every check below for the same reason.

if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  pass "/dev/kvm is readable and writable"
else
  fail "/dev/kvm is readable and writable" \
    "$(ls -l /dev/kvm 2>&1). Nothing below can run; stop here."
  exit 1
fi

# Deliberately NOT `crun` from PATH.  The launcher never resolves the runtime
# that way -- default.nix bakes an absolute store path into it precisely so that
# podman does not pick up whatever crun the host has configured -- so checking
# PATH would answer a question nobody asked.  Hosts commonly carry a distro crun
# built without libkrun, and it is not the one that will run the VM.
#
# Resolution order mirrors the launcher: the env override first, then the path
# baked into the agent-sandbox on PATH, and only then a guess.
krun_runtime="${AGENT_SANDBOX_KRUN_RUNTIME:-}"
if [[ -z "$krun_runtime" ]]; then
  launcher_path=$(command -v agent-sandbox 2>/dev/null || true)
  if [[ -n "$launcher_path" ]]; then
    krun_runtime=$(sed -n 's/^AGENT_SANDBOX_KRUN_RUNTIME="\(.*\)"$/\1/p' "$launcher_path" | head -n 1)
  fi
fi
if [[ -z "$krun_runtime" ]]; then
  krun_runtime=$(command -v krun 2>/dev/null || command -v crun 2>/dev/null || true)
fi

if [[ -z "$krun_runtime" ]]; then
  fail "the launcher's krun runtime can be located" \
    "no AGENT_SANDBOX_KRUN_RUNTIME, and no krun or crun on PATH."
  exit 1
fi
printf '         (runtime under test: %s)\n' "$krun_runtime"

# No head: the feature flags are the last line of `crun --version`, so
# truncating the diagnostic hides the one part of it worth reading.
if "$krun_runtime" --version 2>/dev/null | grep -q '+LIBKRUN'; then
  pass "the launcher's runtime is built with libkrun"
else
  fail "the launcher's runtime is built with libkrun" \
    "$("$krun_runtime" --version 2>&1)
If that is a distro crun rather than a store path, the launcher was run from a
tree without the Nix wrapper; use ./result/bin/agent-sandbox, or set
AGENT_SANDBOX_KRUN_RUNTIME to a crun with +LIBKRUN."
  exit 1
fi

host_kernel=$(uname -r)

# ── 0b. does a guest boot at all, and is it really a guest ───────────────────
# The whole document rests on this and on 0d.  A kernel release equal to the
# host's means --runtime silently resolved to plain crun and everything else
# here would be measuring an ordinary container.

guest_kernel=$(agent-sandbox --krun --no-workspace -- uname -r 2>"$tmp/boot.err" | tr -d '\r')
if [[ -z "$guest_kernel" ]]; then
  fail "a --krun sandbox boots" "$(cat "$tmp/boot.err")"
  exit 1
fi
pass "a --krun sandbox boots (guest kernel $guest_kernel)"

if [[ "$guest_kernel" != "$host_kernel" ]]; then
  pass "the guest runs its own kernel (host is $host_kernel)"
else
  fail "the guest runs its own kernel" \
    "guest and host both report $host_kernel -- this is not a VM."
  exit 1
fi

# libkrunfw carries the kernel, so this is a property of the library rather than
# of the host.  Recorded, not asserted: it moves with nixpkgs.
printf '         (libkrunfw kernel: %s)\n' "$guest_kernel"

mem_total=$(agent-sandbox --krun --krun-memory 2048 --no-workspace \
              -- sh -c "grep MemTotal /proc/meminfo" 2>/dev/null)
case "$mem_total" in
  *[0-9]*)
    mem_kb=$(printf '%s' "$mem_total" | tr -dc '0-9')
    # A 2 GiB guest that came up on libkrun's 1 GiB default is the failure this
    # catches: the annotation would have been discarded without a word.
    if [[ -n "$mem_kb" && "$mem_kb" -gt 1258291 ]]; then
      pass "--krun-memory reaches the guest ($((mem_kb / 1024)) MiB for a 2048 MiB request)"
    else
      fail "--krun-memory reaches the guest" \
        "asked for 2048 MiB, guest reports $((mem_kb / 1024)) MiB -- annotation discarded?"
    fi
    ;;
  *) fail "--krun-memory reaches the guest" "could not read /proc/meminfo: $mem_total" ;;
esac

# ── 0c. mounts ───────────────────────────────────────────────────────────────
# virtio-fs serves the container's whole mount tree as the guest root, so -v
# binds arrive without a shares list.  The two open questions are whether uids
# survive --userns=keep-id, and whether submounts are traversed.

mkdir -p "$tmp/share"
if agent-sandbox --krun --no-workspace -v "$tmp/share:/share" \
     -- sh -c 'echo written-from-guest > /share/probe' >/dev/null 2>"$tmp/mount.err"; then
  if [[ -f "$tmp/share/probe" ]]; then
    pass "a -v bind is writable from the guest"
    owner=$(stat -c '%u' "$tmp/share/probe")
    if [[ "$owner" == "$(id -u)" ]]; then
      pass "guest-written files are owned by your uid on the host ($owner)"
    else
      fail "guest-written files are owned by your uid on the host" \
        "expected $(id -u), got $owner -- virtio-fs uid mapping under --userns=keep-id"
    fi
  else
    fail "a -v bind is writable from the guest" "no file appeared on the host"
  fi
else
  fail "a -v bind is writable from the guest" "$(cat "$tmp/mount.err")"
fi

# virtio-fs does not traverse submounts: the tmpfs the launcher stacks on
# /home/user/.cache is invisible inside the guest, which sees the directory from
# the image underneath it instead.  That is recorded rather than failed, because
# the mount *type* was never the requirement.  What the launcher actually needs
# from those three dirs is that an agent can write to them and that nothing
# survives the run, and --rm discards the container layer either way.
#
# Parsed on the host rather than in the guest, to keep the quoting legible.
home_mount=$(agent-sandbox --krun --no-workspace \
               -- grep ' /home/user/.cache ' /proc/mounts 2>/dev/null | tr -d '\r')
home_fs=$(printf '%s\n' "$home_mount" | cut -d' ' -f3)
printf '         (/home/user/.cache in the guest: %s)\n' "${home_fs:-not a separate mount}"

# This is the assertion that matters.  If it fails, --krun is unusable for any
# real agent -- npm, pip, cargo and every CLI in the image write here.
if agent-sandbox --krun --no-workspace \
     -- sh -c 'echo probe > /home/user/.cache/probe && cat /home/user/.cache/probe' \
     >"$tmp/cache.log" 2>&1 && grep -q probe "$tmp/cache.log"; then
  pass "the guest can write to /home/user/.cache"
else
  fail "the guest can write to /home/user/.cache" "$(cat "$tmp/cache.log")"
fi

# Ephemerality, which the tmpfs used to provide and --rm has to provide instead.
if agent-sandbox --krun --no-workspace -- test -e /home/user/.cache/probe >/dev/null 2>&1; then
  fail "a second guest does not see the first one's cache" \
    "/home/user/.cache/probe survived into a fresh sandbox"
else
  pass "a second guest does not see the first one's cache"
fi

for d in .config .local; do
  if agent-sandbox --krun --no-workspace \
       -- sh -c "touch /home/user/$d/probe" >/dev/null 2>&1; then
    pass "the guest can write to /home/user/$d"
  else
    fail "the guest can write to /home/user/$d" "an agent's state directory is read-only"
  fi
done

# ── 0d. containment ──────────────────────────────────────────────────────────
# The single assertion the whole design rests on.  TSI performs the guest's
# connect() in the VMM, and the VMM is the container process, so the guest
# inherits the --internal netns that has no route out.  If egress works here,
# something added a netdev and disabled TSI, and --krun must not ship.

cat > "$tmp/work/AGENTS.md" <<'EOF'
```toml agent-sandbox
[proxy]
allow_domains = ["example.com"]
allow_ports = ["443"]
```
EOF

if agent-sandbox --krun --proxy --no-workspace \
     -- curl -sS -o /dev/null -m 25 https://example.com >"$tmp/allow.log" 2>&1; then
  pass "an allowed host is reachable from the guest"
else
  fail "an allowed host is reachable from the guest" "$(cat "$tmp/allow.log")"
fi

if agent-sandbox --krun --proxy --no-workspace \
     -- curl -sS -o /dev/null -m 25 https://nixos.org >"$tmp/deny.log" 2>&1; then
  fail "a host outside the allow list is refused" \
    "nixos.org was reachable from inside the guest -- TSI may be disabled (check for a netdev)"
else
  pass "a host outside the allow list is refused"
fi

# Not merely filtered: with TSI and an --internal network there should be no
# default route at all, so the failure mode is "no route" rather than "proxy
# said no".  This is what makes the policy enforcing rather than advisory.
routes=$(agent-sandbox --krun --proxy --no-workspace \
           -- sh -c 'ip route show default 2>/dev/null || true' 2>/dev/null | tr -d '\r')
if [[ -z "${routes// /}" ]]; then
  pass "the guest has no default route"
else
  fail "the guest has no default route" "$routes"
fi

# The policy directory is mounted into the sidecar only.  virtio-fs serves the
# container's mount tree wholesale, so it is worth confirming that did not
# quietly widen what the agent can read.
if agent-sandbox --krun --proxy --no-workspace \
     -- sh -c 'test -e /sidecar_policy' >/dev/null 2>&1; then
  fail "the policy directory is invisible to the guest" "/sidecar_policy exists inside the guest"
else
  pass "the policy directory is invisible to the guest"
fi

# ── 0e. exec ─────────────────────────────────────────────────────────────────
# The ctl guards refuse on the label rather than on this error, but the error is
# what the guard's message describes, so it should be the error we think it is.

agent-sandbox --krun --no-workspace -- sleep 120 >"$tmp/vm.log" 2>&1 &
vm_launcher=$!
vm=""
for _ in $(seq 1 60); do
  vm=$(podman ps --filter "label=agent-sandbox.role=sandbox" \
                 --filter "label=agent-sandbox.workspace=$tmp/work" \
                 --format '{{.Names}}' | head -n 1)
  [[ -n "$vm" ]] && break
  kill -0 "$vm_launcher" 2>/dev/null || break
  sleep 1
done

if [[ -z "$vm" ]]; then
  fail "a long-running krun sandbox starts" "$(cat "$tmp/vm.log")"
else
  pass "a long-running krun sandbox starts ($vm)"

  if [[ "$(podman inspect --format '{{index .Config.Labels "agent-sandbox.runtime"}}' "$vm" 2>/dev/null)" == "krun" ]]; then
    pass "the sandbox is labelled agent-sandbox.runtime=krun"
  else
    fail "the sandbox is labelled agent-sandbox.runtime=krun" \
      "the ctl guards key off this label and would not fire"
  fi

  exec_err=$(podman exec "$vm" true 2>&1)
  if grep -qi 'does not support exec' <<< "$exec_err"; then
    pass "podman exec fails with the handler's own message"
  else
    fail "podman exec fails with the handler's own message" "$exec_err"
  fi

  # The two guards, against the real thing rather than a fixture.
  if agent-sandbox-ctl attach "$vm" >"$tmp/attach.log" 2>&1; then
    fail "ctl attach refuses a krun sandbox" "it did not refuse"
  elif grep -q 'microVM' "$tmp/attach.log"; then
    pass "ctl attach refuses a krun sandbox"
  else
    fail "ctl attach refuses a krun sandbox" "$(cat "$tmp/attach.log")"
  fi

  mkdir -p "$tmp/late"
  if agent-sandbox-ctl mounts --sandbox "$vm" "$tmp/late" /mnt/late >"$tmp/mnt.log" 2>&1; then
    fail "ctl mounts refuses a krun sandbox" \
      "it reported success -- the nsenter bind landed in the VMM and the guest saw nothing"
  elif grep -q 'no effect' "$tmp/mnt.log"; then
    pass "ctl mounts refuses a krun sandbox"
  else
    fail "ctl mounts refuses a krun sandbox" "$(cat "$tmp/mnt.log")"
  fi

  # ctl status and net read the sidecar and the labels, never the sandbox, so
  # they are expected to work untouched.  That is the design's central claim.
  if agent-sandbox-ctl status --sandbox "$vm" >"$tmp/status.log" 2>&1; then
    pass "ctl status works against a krun sandbox"
    if grep -q 'runtime' "$tmp/status.log"; then
      pass "ctl status shows the runtime"
    else
      fail "ctl status shows the runtime" "$(cat "$tmp/status.log")"
    fi
  else
    fail "ctl status works against a krun sandbox" "$(cat "$tmp/status.log")"
  fi

  podman rm -f "$vm" >/dev/null 2>&1
fi
wait "$vm_launcher" 2>/dev/null

# ── 0f. cost ─────────────────────────────────────────────────────────────────
# Recorded, not asserted.  There is no threshold worth failing on; the point is
# to replace the "unmeasured" column of the plan with real numbers.

time_it() { # label flags...
  local label="$1"; shift
  local start end
  start=$(date +%s.%N)
  "$@" >/dev/null 2>&1
  end=$(date +%s.%N)
  printf '         %-34s %ss\n' "$label" "$(echo "$end - $start" | bc 2>/dev/null || echo '?')"
}

echo "=== cost (informational) ==="
time_it "boot, plain container"  agent-sandbox --no-krun --no-workspace -- true
time_it "boot, krun microVM"     agent-sandbox --krun --no-workspace -- true
time_it "du -s /nix/store, plain" agent-sandbox --no-krun --no-workspace -- sh -c 'ls /nix/store | head -2000 >/dev/null'
time_it "du -s /nix/store, krun"  agent-sandbox --krun --no-workspace -- sh -c 'ls /nix/store | head -2000 >/dev/null'

# ── 0g. nested podman ────────────────────────────────────────────────────────
# One of the two workloads the flag exists for.  The guest kernel ships with
# libkrun rather than the host, so overlayfs, fuse and user namespaces are its
# properties to have or lack.  Reported as a skip rather than a failure: this is
# the question the spike exists to answer, not a regression.

# First, who the agent actually is inside the guest.  This is worth knowing on
# its own: the host-side checks above prove virtio-fs writes land as uid 33500
# on the host, which says nothing about the uid the guest kernel sees.  A guest
# uid of 0 would also explain podman reaching for rootful storage under /var/lib
# instead of $HOME, which is a configuration problem rather than a missing
# kernel feature -- and those two want opposite fixes.
guest_id=$(agent-sandbox --krun --no-workspace -- id 2>/dev/null | tr -d '\r')
printf '         (guest identity: %s)\n' "${guest_id:-unknown}"
# Single-quoted deliberately: $HOME must be expanded by the guest's shell, not
# by this one.
# shellcheck disable=SC2016
guest_home=$(agent-sandbox --krun --no-workspace -- sh -c 'echo "$HOME"' 2>/dev/null | tr -d '\r')
printf '         (guest HOME: %s)\n' "${guest_home:-unset}"

# The actual 0g question, asked of the kernel rather than of podman: overlayfs
# and fuse have to be in libkrunfw for nested containers to work at all.
guest_fs=$(agent-sandbox --krun --no-workspace -- cat /proc/filesystems 2>/dev/null | tr -d '\r')
for want in overlay fuse; do
  if grep -qw "$want" <<< "$guest_fs"; then
    pass "the guest kernel supports $want"
  else
    fail "the guest kernel supports $want" "nested podman cannot work without it"
  fi
done

if agent-sandbox --krun --privileged --no-workspace \
     -- podman info >"$tmp/nested.log" 2>&1; then
  pass "nested podman initialises inside the guest"
  if agent-sandbox --krun --privileged --no-workspace \
       -- podman run --rm "$image" true >"$tmp/nested-run.log" 2>&1; then
    pass "a nested container runs inside the guest"
  else
    skip "a nested container runs inside the guest" "$(tail -5 "$tmp/nested-run.log")"
  fi
else
  skip "nested podman initialises inside the guest" \
    "$(tail -5 "$tmp/nested.log")
Not a kernel limitation -- overlay and fuse both passed above.  The agent is
uid 0 inside the guest, so podman picks rootful storage under /var/lib, and
virtio-fs refuses to create it because the VMM writes as your host uid.
Pointing podman's graphroot at /home/user is the open follow-up."
fi

# ── teardown ─────────────────────────────────────────────────────────────────
# Same leak checks as smoke-firewall.sh.  A --krun launch that dies between
# creating the sidecar network and starting the VM would strand both, and the
# one-shot style above means many more chances to do it.

sleep 2
nets_after=$(podman network ls --filter "name=^agent-sandbox-sidecar-" --format '{{.Name}}' | wc -l)
dirs_after=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'agent-sandbox-policy-*' 2>/dev/null | wc -l)

if [[ "$nets_after" -le "$nets_before" ]]; then
  pass "no session networks leaked"
else
  fail "no session networks leaked" \
    "$nets_before before, $nets_after after: $(podman network ls --filter "name=^agent-sandbox-sidecar-" --format '{{.Name}}' | tr '\n' ' ')"
fi

if [[ "$dirs_after" -le "$dirs_before" ]]; then
  pass "no policy directories leaked"
else
  fail "no policy directories leaked" "$dirs_before before, $dirs_after after"
fi

if [[ "$failures" -gt 0 ]]; then
  printf '\n%s check(s) failed\n' "$failures" >&2
  exit 1
fi
printf '\nall krun smoke checks passed\n'
