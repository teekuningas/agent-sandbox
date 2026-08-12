#!/usr/bin/env bash
# Hand-run smoke test for the firewall, against real containers.
#
# Everything here needs a working rootless podman and network egress, so it
# cannot be a nix check -- `nix flake check` covers the policy round-trip, the
# argument handling and the proxy's own logic, but nothing that actually starts a
# container.  This script is the written procedure for the rest.
#
# Usage:  bash lib/smoke-firewall.sh
#
# Assumes `agent-sandbox` and `agent-sandbox-ctl` are on PATH and the image is
# loaded (agent-sandbox-ctl load).
#
# This covers the default runtime only: in_sandbox() below is `podman exec`,
# which a --krun sandbox has no answer for.  The equivalent checks against a
# microVM live in lib/smoke-krun.sh, which needs /dev/kvm.  The sidecar-side
# checks here are runtime-agnostic already, which is the point -- --krun changes
# the sandbox and leaves the proxy an ordinary container.

set -uo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"; podman rm -f "$sandbox" >/dev/null 2>&1' EXIT
sandbox=""

# Baselines for the teardown checks below.  A sandbox that was already running
# when this started owns a session network and a policy directory of its own, and
# counting those as leaks is the same mistake as adopting its container.
nets_before=$(podman network ls --filter "name=^agent-sandbox-sidecar-" --format '{{.Name}}' | wc -l)
dirs_before=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'agent-sandbox-policy-*' 2>/dev/null | wc -l)

failures=0
pass() { printf 'ok       %s\n' "$1"; }
fail() { printf 'FAIL     %s\n' "$1"; printf '%s\n' "${2:-}" | sed 's/^/           /'; failures=$((failures + 1)); }

# Two entries in every list: one entry works even with a broken handoff, which is
# exactly how the separator bug survived for so long.
mkdir -p "$tmp/work"
cat > "$tmp/work/AGENTS.md" <<'EOF'
```toml agent-sandbox
[proxy]
allow_domains = ["example.com", "*.example.com"]
deny_domains = ["blocked.example.org", "also-blocked.example.org"]
allow_ips = ["10.0.0.0/8", "192.168.0.0/16"]
deny_ips = ["203.0.113.0/24", "198.51.100.7"]
allow_ports = ["443"]
```
EOF

echo "=== launching a --proxy sandbox in $tmp/work ==="
cd "$tmp/work" || exit 1

# Background, so the checks can run against it; the launcher stays in the
# foreground of its own shell.
agent-sandbox --proxy --no-workspace -- sleep 600 >"$tmp/launch.log" 2>&1 &
launcher=$!

# Filtered by workspace, not just by role.  Taking the first sandbox podman
# happened to list meant that running this script while any other sandbox was up
# -- including the one you are reading this from -- silently tested that
# container instead: no proxy, so half the checks failed and the two that pass
# without a firewall passed for the wrong reason.  Then teardown `podman rm -f`'d
# it.  $tmp is a fresh mktemp dir, so this label matches exactly one container,
# and it is always the one this run launched.
for _ in $(seq 1 60); do
  sandbox=$(podman ps --filter "label=agent-sandbox.role=sandbox" \
                      --filter "label=agent-sandbox.workspace=$tmp/work" \
                      --format '{{.Names}}' | head -n 1)
  [[ -n "$sandbox" ]] && break
  kill -0 "$launcher" 2>/dev/null || break
  sleep 1
done

if [[ -z "$sandbox" ]]; then
  fail "the sandbox started" "$(cat "$tmp/launch.log")"
  exit 1
fi
pass "the sandbox started ($sandbox)"

# ── the policy actually reached the proxy ────────────────────────────────────

rules=$(agent-sandbox-ctl proxy show --sandbox "$sandbox")
for want in \
  "example.com" "*.example.com" \
  "blocked.example.org" "also-blocked.example.org" \
  "10.0.0.0/8" "192.168.0.0/16" \
  "203.0.113.0/24" "198.51.100.7" \
  "443"
do
  if grep -qF -- "$want" <<< "$rules"; then
    pass "policy carries $want"
  else
    fail "policy carries $want" "$rules"
  fi
done

if grep -q "default *deny" <<< "$rules"; then
  pass "an allow list means deny by default"
else
  fail "an allow list means deny by default" "$rules"
fi

# ── the proxy's resolution path ──────────────────────────────────────────────
#
# Regression guard for the third round of the same bug.  Podman routes a
# container's entire resolver through aardvark-dns as soon as *one* of its
# networks has dns_enabled -- podman-run(1) under --dns -- and aardvark has
# refused to forward for --internal networks since 1.11.0.  The sidecar's only
# nameserver then answers NXDOMAIN to every external name and every request
# comes back 502 ("dns: Name or service not known").  The launcher creates the
# network --disable-dns to keep aardvark out of the path; assert it stayed out,
# because the symptom otherwise only shows up as a failed fetch further down and
# reads like an unrelated network problem.
#
# The launcher uses one identifier for both the sidecar container and its
# internal network, so this name addresses either.
sidecar=$(podman ps --filter "label=agent-sandbox.role=proxy" \
                    --filter "label=agent-sandbox.target=$sandbox" \
                    --format '{{.Names}}' | head -n 1)

if [[ -z "$sidecar" ]]; then
  fail "the proxy sidecar was found" "no container labelled target=$sandbox"
else
  pass "the proxy sidecar was found ($sidecar)"

  if [[ "$(podman network inspect "$sidecar" --format '{{.DNSEnabled}}' 2>/dev/null)" == "false" ]]; then
    pass "the internal network has DNS disabled"
  else
    fail "the internal network has DNS disabled" \
      "aardvark-dns will not forward for an --internal network, so the proxy resolves nothing"
  fi

  # aardvark-dns answers on the network's gateway address; the sidecar's
  # resolv.conf must name a real resolver instead.
  resolv=$(podman exec "$sidecar" cat /etc/resolv.conf 2>/dev/null)
  gateways=()
  mapfile -t gateways < <(podman network inspect "$sidecar" \
    --format '{{range .Subnets}}{{.Gateway}}{{"\n"}}{{end}}' 2>/dev/null)
  aardvark=""
  for gw in ${gateways[@]+"${gateways[@]}"}; do
    [[ -n "$gw" ]] || continue
    grep -qE "^[[:space:]]*nameserver[[:space:]]+${gw}[[:space:]]*$" <<< "$resolv" && aardvark="$gw"
  done
  if [[ -n "$aardvark" ]]; then
    fail "the proxy does not resolve through aardvark-dns" \
      "resolv.conf points at the internal gateway $aardvark:"$'\n'"$resolv"
  else
    pass "the proxy does not resolve through aardvark-dns"
  fi

  # Every nameserver the sidecar resolves against carries an exemption route, so
  # that a deny_ips range covering it -- the baseline's own 192.168.0.0/16 covers
  # a great many home resolvers -- cannot blackhole name resolution itself.  The
  # egress probe runs before these routes exist and so cannot catch it; this is
  # the check that can.
  sidecar_ns=()
  mapfile -t sidecar_ns < <(awk '/^[[:space:]]*nameserver/ { print $2 }' <<< "$resolv")
  if [[ ${#sidecar_ns[@]} -eq 0 ]]; then
    fail "the sidecar has a nameserver at all" "$resolv"
  else
    exempt_routes=$(podman exec "$sidecar" ip -o route show proto 200 2>/dev/null || true)
    missing=()
    for ns in "${sidecar_ns[@]}"; do
      grep -qE "^${ns}[[:space:]]" <<< "$exempt_routes" || missing+=("$ns")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
      pass "every nameserver has an exemption route"
    else
      fail "every nameserver has an exemption route" \
        "no route for: ${missing[*]}"$'\n'"$exempt_routes"
    fi
  fi

  # The host's search list travels with its nameservers, or an unqualified name
  # that resolves on the host resolves to nothing here.
  host_search=$(awk '/^[[:space:]]*search/ { print $2 }' /etc/resolv.conf 2>/dev/null | head -n 1)
  if [[ -z "$host_search" ]]; then
    pass "the host declares no search domain (nothing to carry)"
  elif grep -qE "^[[:space:]]*search[[:space:]].*(^|[[:space:]])${host_search}([[:space:]]|\$)" <<< "$resolv"; then
    pass "the host's search domain reached the sidecar"
  else
    fail "the host's search domain reached the sidecar" \
      "wanted $host_search in:"$'\n'"$resolv"
  fi

  # Written only when wait_for_egress gives up, which is the degraded launch the
  # launcher now warns about.  A healthy session must not have one.
  if podman exec "$sidecar" test -e /sidecar_shared/egress-degraded 2>/dev/null; then
    fail "the proxy proved egress at startup" \
      "$(podman exec "$sidecar" cat /sidecar_shared/egress-degraded 2>/dev/null)"
  else
    pass "the proxy proved egress at startup"
  fi

  # The proxy must bind only its internal-network address, not the default
  # bridge it also sits on -- otherwise any other container of the same user
  # on that bridge could use it as an open proxy under this sandbox's policy.
  bridge_ip=$(podman container inspect "$sidecar" \
    --format '{{(index .NetworkSettings.Networks "bridge").IPAddress}}' 2>/dev/null)
  if [[ -z "$bridge_ip" ]]; then
    fail "the proxy is not reachable on the default bridge" \
      "could not determine the sidecar's bridge-network address"
  elif podman run --rm --network bridge "$AGENT_SANDBOX_IMAGE" \
         curl -sS -o /dev/null -m 5 "http://$bridge_ip:8888" >/dev/null 2>&1; then
    fail "the proxy is not reachable on the default bridge" \
      "a sibling container on the bridge reached $bridge_ip:8888"
  else
    pass "the proxy is not reachable on the default bridge"
  fi
fi

# ── enforcement ──────────────────────────────────────────────────────────────

in_sandbox() { podman exec "$sandbox" "$@"; }

if in_sandbox curl -sS -o /dev/null -m 20 https://example.com; then
  pass "an allowed host is reachable"
else
  fail "an allowed host is reachable" "$(agent-sandbox-ctl logs --sandbox "$sandbox" | tail -5)"
fi

# A trailing-dot FQDN is the same host to any resolver; the policy must treat
# it the same as the plain form instead of letting it slip past matching.
if in_sandbox curl -sS -o /dev/null -m 20 "https://example.com."; then
  pass "a trailing-dot form of an allowed host is reachable"
else
  fail "a trailing-dot form of an allowed host is reachable" \
    "$(agent-sandbox-ctl logs --sandbox "$sandbox" | tail -5)"
fi

if in_sandbox curl -sS -o /dev/null -m 20 https://nixos.org 2>/dev/null; then
  fail "a host outside the allow list is refused" "nixos.org was reachable"
else
  pass "a host outside the allow list is refused"
fi

# The second deny_ips entry is a bare address, which used to be dropped on the
# floor by the proxy while the parser accepted it.
if in_sandbox getent hosts 198.51.100.7 >/dev/null 2>&1; then :; fi
if in_sandbox curl -sS -o /dev/null -m 10 http://198.51.100.7 2>/dev/null; then
  fail "a denied bare address is refused" "198.51.100.7 was reachable"
else
  pass "a denied bare address is refused"
fi

# allow_ports = ["443"]: the host is allowed, but plain HTTP on 80 is not.
if in_sandbox curl -sS -o /dev/null -m 10 http://example.com 2>/dev/null; then
  fail "a non-allowed port on an allowed host is refused" "example.com:80 was reachable"
else
  pass "a non-allowed port on an allowed host is refused"
fi

# ── runtime policy change ────────────────────────────────────────────────────

agent-sandbox-ctl proxy allow --sandbox "$sandbox" nixos.org >/dev/null
sleep 2   # the proxy polls the policy once a second

if in_sandbox curl -sS -o /dev/null -m 20 https://nixos.org; then
  pass "firewall allow takes effect without a restart"
else
  fail "firewall allow takes effect without a restart" \
    "$(agent-sandbox-ctl logs --sandbox "$sandbox" | tail -8)"
fi

agent-sandbox-ctl proxy rm --sandbox "$sandbox" nixos.org >/dev/null
sleep 2
if in_sandbox curl -sS -o /dev/null -m 20 https://nixos.org 2>/dev/null; then
  fail "firewall rm takes effect without a restart" "nixos.org still reachable"
else
  pass "firewall rm takes effect without a restart"
fi

# ── the sandbox cannot reach the policy or the log ───────────────────────────

if in_sandbox test -e /sidecar_policy 2>/dev/null; then
  fail "the policy is not visible inside the sandbox" "/sidecar_policy exists"
else
  pass "the policy is not visible inside the sandbox"
fi
if in_sandbox test -e /sidecar_shared 2>/dev/null; then
  fail "the connection log is not visible inside the sandbox" "/sidecar_shared exists"
else
  pass "the connection log is not visible inside the sandbox"
fi

# ── the visibility commands work against a live sandbox ──────────────────────

for cmd in status net logs; do
  if agent-sandbox-ctl "$cmd" --sandbox "$sandbox" >/dev/null 2>"$tmp/err"; then
    pass "ctl $cmd works"
  else
    fail "ctl $cmd works" "$(cat "$tmp/err")"
  fi
done

if agent-sandbox-ctl ports add --sandbox "$sandbox" 18080 2>"$tmp/err"; then
  fail "port add refuses a proxied sandbox" "it succeeded"
else
  if grep -q "does not pass through the proxy" "$tmp/err"; then
    pass "port add refuses a proxied sandbox"
  else
    fail "port add refuses a proxied sandbox" "$(cat "$tmp/err")"
  fi
fi

# ── baseline private/loopback deny with no AGENTS.md policy ──────────────────
# --proxy with no AGENTS.md [proxy] block runs no user policy at all, which
# used to mean the proxy ran with a fully empty config (allow-everything, no
# deny_ips) and could be used to reach the host's own bridge network.  The
# baseline deny list must close that regardless of any user rule.

mkdir -p "$tmp/meter"
(cd "$tmp/meter" && agent-sandbox --proxy --no-workspace -- sleep 300 \
   >"$tmp/meter-launch.log" 2>&1 &)

meter_sandbox=""
for _ in $(seq 1 60); do
  meter_sandbox=$(podman ps --filter "label=agent-sandbox.role=sandbox" \
                            --filter "label=agent-sandbox.workspace=$tmp/meter" \
                            --format '{{.Names}}' | head -n 1)
  [[ -n "$meter_sandbox" ]] && break
  sleep 1
done

if [[ -z "$meter_sandbox" ]]; then
  fail "the --proxy sandbox with no [proxy] block started" "$(cat "$tmp/meter-launch.log")"
else
  pass "the --proxy sandbox with no [proxy] block started ($meter_sandbox)"

  meter_sidecar=$(podman ps --filter "label=agent-sandbox.role=proxy" \
                            --filter "label=agent-sandbox.target=$meter_sandbox" \
                            --format '{{.Names}}' | head -n 1)
  bridge_gw=$(podman network inspect bridge \
    --format '{{(index .Subnets 0).Gateway}}' 2>/dev/null)

  if [[ -z "$meter_sidecar" || -z "$bridge_gw" ]]; then
    fail "the bridge gateway is refused with no [proxy] block" \
      "could not resolve sidecar ($meter_sidecar) or bridge gateway ($bridge_gw)"
  elif podman exec "$meter_sandbox" curl -sS -o /dev/null -m 10 "http://$bridge_gw" 2>/dev/null; then
    fail "the bridge gateway is refused with no [proxy] block" "$bridge_gw was reachable"
  else
    pass "the bridge gateway is refused with no [proxy] block"
  fi

  podman rm -f "$meter_sandbox" >/dev/null 2>&1
fi

# ── a deny_ips covering the sidecar's own resolver ───────────────────────────
# The failure this exists for: resolution happens in the sidecar, by libc, well
# outside the proxy's policy path, so a deny_ips range that happens to contain
# the resolver used to blackhole DNS itself.  Every request then failed, not
# only the ones aimed at the denied range, and nothing said so -- the egress
# probe had already passed, because it runs before the routes are installed.
#
# The range is derived from the resolver the first sidecar actually got, so this
# reproduces the shape rather than assuming any particular network.

dns_ns="${sidecar_ns[0]:-}"
if [[ ! "$dns_ns" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  pass "skipped: the sidecar's resolver ${dns_ns:-(none)} is not an IPv4 literal"
else
  dns_deny="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.0.0/16"
  mkdir -p "$tmp/dns"
  cat > "$tmp/dns/AGENTS.md" <<EOF
\`\`\`toml agent-sandbox
[proxy]
allow_domains = ["example.com", "*.example.com"]
deny_ips = ["$dns_deny"]
\`\`\`
EOF

  (cd "$tmp/dns" && agent-sandbox --proxy --no-workspace -- sleep 300 \
     >"$tmp/dns-launch.log" 2>&1 &)

  dns_sandbox=""
  for _ in $(seq 1 60); do
    dns_sandbox=$(podman ps --filter "label=agent-sandbox.role=sandbox" \
                            --filter "label=agent-sandbox.workspace=$tmp/dns" \
                            --format '{{.Names}}' | head -n 1)
    [[ -n "$dns_sandbox" ]] && break
    sleep 1
  done

  if [[ -z "$dns_sandbox" ]]; then
    fail "the sandbox started with its resolver inside a deny_ips range" \
      "$(cat "$tmp/dns-launch.log")"
  else
    pass "the sandbox started with its resolver inside a deny_ips range ($dns_deny)"

    if podman exec "$dns_sandbox" curl -sS -o /dev/null -m 20 https://example.com 2>/dev/null; then
      pass "an allowed host still resolves with the resolver's range denied"
    else
      fail "an allowed host still resolves with the resolver's range denied" \
        "$(agent-sandbox-ctl logs --sandbox "$dns_sandbox" 2>/dev/null | tail -5)"
    fi

    podman rm -f "$dns_sandbox" >/dev/null 2>&1
  fi
fi

# ── refusals at launch ───────────────────────────────────────────────────────

if agent-sandbox --proxy --port 18081 --no-workspace -- true >"$tmp/err" 2>&1; then
  fail "--proxy with a port is refused" "it launched"
else
  if grep -q "cannot be combined" "$tmp/err"; then
    pass "--proxy with a port is refused"
  else
    fail "--proxy with a port is refused" "$(cat "$tmp/err")"
  fi
fi

mkdir -p "$tmp/bad"
cat > "$tmp/bad/AGENTS.md" <<'EOF'
```toml agent-sandbox
[proxy]
allow_domians = ["example.com"]
```
EOF
if (cd "$tmp/bad" && agent-sandbox --proxy --no-workspace -- true >"$tmp/err" 2>&1); then
  fail "a misspelled [proxy] key refuses the launch" "it launched"
else
  if grep -q "invalid \[proxy\] block" "$tmp/err"; then
    pass "a misspelled [proxy] key refuses the launch"
  else
    fail "a misspelled [proxy] key refuses the launch" "$(cat "$tmp/err")"
  fi
fi

# ── teardown leaves nothing behind ───────────────────────────────────────────

podman rm -f "$sandbox" >/dev/null 2>&1
wait "$launcher" 2>/dev/null
sandbox=""

leftover_nets=$(podman network ls --filter "name=^agent-sandbox-sidecar-" --format '{{.Name}}' | wc -l)
if [[ "$leftover_nets" -le "$nets_before" ]]; then
  pass "no session network is leaked"
else
  fail "no session network is leaked" \
    "$((leftover_nets - nets_before)) left; agent-sandbox-ctl purge reclaims them"
fi

leftover_dirs=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'agent-sandbox-policy-*' 2>/dev/null | wc -l)
if [[ "$leftover_dirs" -le "$dirs_before" ]]; then
  pass "no policy directory is leaked"
else
  fail "no policy directory is leaked" "$((leftover_dirs - dirs_before)) left"
fi

if [[ "$failures" -gt 0 ]]; then
  printf '\n%s check(s) failed\n' "$failures" >&2
  exit 1
fi
printf '\nall firewall smoke checks passed\n'
