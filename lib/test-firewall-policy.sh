#!/usr/bin/env bash
# Round-trip tests for the firewall policy: AGENTS.md -> policy file -> proxy,
# and policy file -> sidecar blackhole routes.
#
# This is the hop that had no coverage, and it is where the fail-open bug lived:
# the launcher handed the lists over space-separated while the proxy split them on
# commas, so everything past the first entry was silently dropped -- and an
# emptied allow list means allowing everything.  Every list in the fixture below
# therefore carries TWO entries: a one-entry fixture cannot tell a working
# handoff from a broken one.
#
# Usage: test-firewall-policy.sh PARSER PROXY SIDECAR_SCRIPT

set -euo pipefail

parser="${1:?usage: test-firewall-policy.sh PARSER PROXY SIDECAR_SCRIPT}"
proxy="${2:?}"
sidecar="${3:?}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0

pass() { printf 'ok       %s\n' "$1"; }
fail() {
  printf 'FAIL     %s\n' "$1"
  printf '%s\n' "${2:-}" > "$tmp/msg"
  sed 's/^/           /' "$tmp/msg"
  failures=$((failures + 1))
}

expect_contains() {
  local label="$1" want="$2" have="$3"
  if grep -qF -- "$want" <<< "$have"; then
    pass "$label"
  else
    fail "$label" "missing: $want"$'\n'"$have"
  fi
}

expect_absent() {
  local label="$1" unwanted="$2" have="$3"
  if grep -qF -- "$unwanted" <<< "$have"; then
    fail "$label" "present but should not be: $unwanted"$'\n'"$have"
  else
    pass "$label"
  fi
}

# ── the fixture ─────────────────────────────────────────────────────────────

cat > "$tmp/AGENTS.md" <<'EOF'
# Project

```toml agent-sandbox
[proxy]
allow_domains = ["github.com", "*.githubusercontent.com"]
deny_domains = ["telemetry.example.com", "ads.example.com"]
allow_ips = ["10.0.0.0/8", "192.168.1.0/24"]
deny_ips = ["10.1.0.0/24", "8.8.8.8"]
allow_ports = ["443", "8000-8100"]
```
EOF

# ── 1. the parser emits one entry per line ──────────────────────────────────

policy=$("$parser" --proxy-policy "$tmp/AGENTS.md")
printf '%s\n' "$policy" > "$tmp/policy"

expected='allow_domains github.com
allow_domains *.githubusercontent.com
deny_domains telemetry.example.com
deny_domains ads.example.com
allow_ips 10.0.0.0/8
allow_ips 192.168.1.0/24
deny_ips 10.1.0.0/24
deny_ips 8.8.8.8
allow_ports 443
allow_ports 8000-8100'

if [[ "$(grep -v '^#' <<< "$policy")" == "$expected" ]]; then
  pass "parser emits one entry per line"
else
  fail "parser emits one entry per line" "$policy"
fi

# ── 2. the proxy reads back every entry ─────────────────────────────────────
# The regression test.  Against the old comma-splitting code the two-entry IP
# lists came back empty, and with allow_ips empty the policy became allow-all.

rules=$("$proxy" --check-policy "$tmp/policy")

for want in \
  "allow_domains github.com" \
  "allow_domains *.githubusercontent.com" \
  "deny_domains telemetry.example.com" \
  "deny_domains ads.example.com" \
  "allow_ips 10.0.0.0/8" \
  "allow_ips 192.168.1.0/24" \
  "deny_ips 10.1.0.0/24" \
  "deny_ips 8.8.8.8" \
  "allow_ports 443" \
  "allow_ports 8000-8100"
do
  expect_contains "proxy keeps '$want'" "$want" "$rules"
done

expect_contains "an allow list means deny by default" "default deny" "$rules"

# ── 3. the old wire format is now a hard error ──────────────────────────────

printf 'allow_ips 10.0.0.0/8 192.168.1.0/24\n' > "$tmp/spaced"
if "$proxy" --check-policy "$tmp/spaced" > "$tmp/out" 2>&1; then
  fail "the old space-separated encoding is rejected" "$(cat "$tmp/out")"
else
  status=$?
  if [[ "$status" == 2 ]]; then
    pass "the old space-separated encoding is rejected"
  else
    fail "the old space-separated encoding is rejected" "exit $status, wanted 2"
  fi
  expect_contains "and the error names the problem" "whitespace" "$(cat "$tmp/out")"
fi

# ── 4. other malformed policies fail closed ─────────────────────────────────

check_rejects() {
  local label="$1" body="$2"
  printf '%s\n' "$body" > "$tmp/bad"
  if "$proxy" --check-policy "$tmp/bad" >/dev/null 2>&1; then
    fail "$label" "accepted: $body"
  else
    pass "$label"
  fi
}

check_rejects "an unknown key is rejected"      "allow_domians github.com"
check_rejects "a bad CIDR is rejected"          "allow_ips not-an-ip"
check_rejects "a bad default is rejected"       "default maybe"
check_rejects "a valueless key is rejected"     "allow_domains"

if "$proxy" --check-policy "$tmp/nonexistent" >/dev/null 2>&1; then
  fail "a missing policy file is rejected" "accepted a nonexistent path"
else
  pass "a missing policy file is rejected"
fi

# ── 5. a malformed [proxy] block refuses to produce a policy ────────────────
# The launcher relies on this exit status; it used to discard it, which turned a
# typo in AGENTS.md into a firewall that allowed everything.

cat > "$tmp/bad-AGENTS.md" <<'EOF'
```toml agent-sandbox
[proxy]
allow_ips = ["not-an-ip"]
```
EOF
if "$parser" --proxy-policy "$tmp/bad-AGENTS.md" >/dev/null 2>&1; then
  fail "an invalid [proxy] block exits non-zero" "accepted an invalid CIDR"
else
  pass "an invalid [proxy] block exits non-zero"
fi

cat > "$tmp/typo-AGENTS.md" <<'EOF'
```toml agent-sandbox
[proxy]
allow_domians = ["github.com"]
```
EOF
if "$parser" --proxy-policy "$tmp/typo-AGENTS.md" >/dev/null 2>&1; then
  fail "a misspelled [proxy] key exits non-zero" "accepted allow_domians"
else
  pass "a misspelled [proxy] key exits non-zero"
fi

# ── 6. the sidecar derives one blackhole route per deny_ips entry ────────────
# Same class of bug on the kernel-route side: these used to come from a
# space-separated env var that only worked by accident for a single entry.

# An empty resolv.conf keeps this section about deny_ips alone; the nameserver
# exemptions get their own section below.  Pinned rather than left to the build
# sandbox's /etc/resolv.conf, which is not something to assert against.
: > "$tmp/resolv-empty.conf"

dry=$(FIREWALL=1 \
      AGENT_SANDBOX_SIDECAR_DRY_RUN=1 \
      AGENT_SANDBOX_SIDECAR_POLICY="$tmp/policy" \
      AGENT_SANDBOX_SIDECAR_RESOLV_CONF="$tmp/resolv-empty.conf" \
      bash "$sidecar")

routes=$(grep -c 'route add blackhole' <<< "$dry" || true)
if [[ "$routes" == 2 ]]; then
  pass "one blackhole route per deny_ips entry"
else
  fail "one blackhole route per deny_ips entry" "found $routes"$'\n'"$dry"
fi
expect_contains "blackhole covers the first entry"  "blackhole 10.1.0.0/24" "$dry"
expect_contains "blackhole covers the second entry" "blackhole 8.8.8.8"     "$dry"
expect_contains "the proxy is given the policy file" "--policy" "$dry"

# ── 6b. the routes mirror is_denied_address, not deny_ips alone ──────────────
# The kernel's longest-prefix match is the same rule the proxy applies, so
# allow_ips has to reach the routing table too.  It did not, and a re-allowed
# range was permitted by the proxy and then dropped by the route -- including
# the README's own `allow_ips = ["10.0.0.0/8"]` against the baseline deny.
#
# The nameservers are exempt whatever the policy says.  Without that, a deny_ips
# covering the sidecar's resolver blackholes name resolution itself and every
# request fails -- and the egress probe cannot catch it, because it runs before
# these routes exist.

cat > "$tmp/resolv-fixture.conf" <<'EOF'
search example.test
nameserver 130.234.16.20
nameserver 130.234.16.10
options single-request-reopen
EOF

cat > "$tmp/policy-routes" <<'EOF'
allow_ips 10.0.0.0/8
allow_ips 10.1.0.0/16
allow_ips 0.0.0.0/0
deny_ips 130.234.0.0/16
deny_ips 8.8.8.8/32
deny_ips 10.0.0.0/8
deny_ips 192.168.0.0/16
EOF

dry_routes=$(FIREWALL=1 \
             AGENT_SANDBOX_SIDECAR_DRY_RUN=1 \
             AGENT_SANDBOX_SIDECAR_POLICY="$tmp/policy-routes" \
             AGENT_SANDBOX_SIDECAR_RESOLV_CONF="$tmp/resolv-fixture.conf" \
             bash "$sidecar")

expect_contains "the first nameserver is exempted from the deny covering it" \
  "route add 130.234.16.20 via" "$dry_routes"
expect_contains "the second nameserver is exempted too" \
  "route add 130.234.16.10 via" "$dry_routes"
expect_contains "the range covering the nameservers is still blackholed" \
  "blackhole 130.234.0.0/16" "$dry_routes"

expect_absent "an allow_ips of equal prefix suppresses the blackhole" \
  "blackhole 10.0.0.0/8" "$dry_routes"
expect_contains "and gets a route of its own instead" \
  "route add 10.0.0.0/8 via" "$dry_routes"
expect_contains "a longer allow_ips is routed over a shorter deny" \
  "route add 10.1.0.0/16 via" "$dry_routes"
expect_contains "a deny with no matching allow is untouched" \
  "blackhole 192.168.0.0/16" "$dry_routes"

# `ip route show` prints a host route without its /32, so installing one with it
# would never match what is read back and would be re-added on every pass.
expect_contains "a /32 deny is installed in the form the kernel reports" \
  "blackhole 8.8.8.8" "$dry_routes"
expect_absent "and not with the suffix the policy wrote" \
  "blackhole 8.8.8.8/32" "$dry_routes"

expect_absent "an allow_ips default route is refused a route of its own" \
  "route add 0.0.0.0/0" "$dry_routes"

exemptions=$(grep -c 'proto 200' <<< "$dry_routes" || true)
if [[ "$exemptions" == 4 ]]; then
  pass "exactly the four expected exemptions are installed"
else
  fail "exactly the four expected exemptions are installed" \
    "found $exemptions"$'\n'"$dry_routes"
fi

# ── 7. --proxy still gets a policy ───────────────────────────────────────────
# The baseline private/loopback deny list only protects sessions with no
# AGENTS.md [proxy] block if the sidecar always hands the proxy a --policy,
# unconditionally.

dry_metering=$(AGENT_SANDBOX_SIDECAR_DRY_RUN=1 \
               AGENT_SANDBOX_SIDECAR_POLICY="$tmp/policy" \
               AGENT_SANDBOX_SIDECAR_RESOLV_CONF="$tmp/resolv-empty.conf" \
               bash "$sidecar")
expect_contains "the proxy is given a policy under --proxy too" \
  "--policy" "$dry_metering"

# ── 8. dry-run never binds a real address ────────────────────────────────────
# There is no interface to inspect outside a container, and no real bind
# happens under dry-run either, so --listen must not appear -- with or without
# SIDECAR_SUBNET set, since a real launch always sets it but dry-run must not
# depend on that to stay usable in a nix build (no podman, no network ns).

dry_listen=$(AGENT_SANDBOX_SIDECAR_DRY_RUN=1 \
             AGENT_SANDBOX_SIDECAR_RESOLV_CONF="$tmp/resolv-empty.conf" \
             AGENT_SANDBOX_SIDECAR_POLICY="$tmp/policy" \
             SIDECAR_SUBNET="10.89.0.0/24" \
             bash "$sidecar")
if grep -qF -- "--listen" <<< "$dry_listen"; then
  fail "dry-run does not pass --listen" "$dry_listen"
else
  pass "dry-run does not pass --listen"
fi

if [[ "$failures" -gt 0 ]]; then
  printf '\n%s test(s) failed\n' "$failures" >&2
  exit 1
fi

printf '\nall firewall-policy tests passed\n'
