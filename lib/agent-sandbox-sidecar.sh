#!/usr/bin/env bash
set -euo pipefail

# Entry point of the proxy sidecar container.
#
# Policy comes from /sidecar_policy/policy, mounted read-only from the host and
# deliberately NOT mounted into the sandbox: the agent must not be able to widen
# the firewall that contains it.  This script does not interpret the policy
# beyond pulling out deny_ips and allow_ips for the kernel routes -- the proxy is
# the reference reader, and it validates before anything observable happens.
#
# The routes mirror is_denied_address, not deny_ips alone: the kernel's
# longest-prefix match is the same rule the proxy applies, so an allow_ips entry
# gets a route of its own and beats a shorter blackhole exactly as it beats a
# shorter deny at the proxy.  See sync_routes.
#
# Ordering matters and is the reason for two readiness markers:
#
#   1. the proxy validates the policy and probes egress, then writes proxy-ready
#   2. this script installs the routes
#   3. only then does it write `ready`, which is what the launcher waits for
#
# So the routes are guaranteed to be in place before the sandbox exists, and an
# unparseable policy stops the proxy (exit 2) before touching the kernel table.
# Note that this ordering also means the egress probe runs *before* the routes
# exist, and so cannot catch a policy that blackholes the sidecar's own
# resolver.  That is why the nameservers are exempted unconditionally rather
# than in response to a failed probe.

policy_file=/sidecar_policy/policy

# Metering is accounted by the proxy itself, which already knows the host, the
# byte counts in each direction and the verdict for every connection.  Capturing
# packets instead would write a second full copy of every transferred byte to
# disk, which is what made throughput degrade as a session went on.
#
# Written whenever a proxy runs, so `agent-sandbox-ctl net` can report on any
# --proxy session -- which is where "why was this blocked?" actually gets
# asked.  A few hundred bytes per connection into a directory the launcher
# removes at exit.
metrics_log=/sidecar_shared/connections.jsonl

# Exemption routes carry a proto of their own so they can be enumerated and
# reconciled the same way the blackholes are enumerated by `type blackhole`:
# an unassigned number, matched by nothing else in the container.
exempt_proto=200

# Written by podman from the launcher's --dns arguments.
resolv_conf=/etc/resolv.conf

# Both side effects go through these so the tests can run the whole script
# without a container: podman is not available in a nix build.  Dry-run also
# relocates the three container paths, which do not exist outside one.
if [[ "${AGENT_SANDBOX_SIDECAR_DRY_RUN:-0}" == "1" ]]; then
  run_ip()    { echo "ip $*"; }
  run_proxy() { echo "agent-sandbox-proxy $*"; }
  # There is no route table to read outside a container, and echoing the query
  # back would parse as a route named "-o".
  installed_blackholes() { :; }
  installed_exemptions() { :; }
  # Fixed so the tests can assert on the emitted commands: there is no default
  # route to read outside a container either.
  default_gateway() { echo "via 10.88.0.1 dev eth0"; }
  policy_file="${AGENT_SANDBOX_SIDECAR_POLICY:-$policy_file}"
  resolv_conf="${AGENT_SANDBOX_SIDECAR_RESOLV_CONF:-$resolv_conf}"
  metrics_log=/dev/null
else
  run_ip()    { ip "$@"; }
  run_proxy() { agent-sandbox-proxy "$@"; }
  installed_blackholes() { ip -o route show type blackhole 2>/dev/null | awk '{ print $2 }'; }
  installed_exemptions() {
    ip -o route show proto "$exempt_proto" 2>/dev/null | awk '{ print $1 }'
  }
  # Nexthop for the exemption routes.  The sandbox's internal network is created
  # --internal and so carries no default route; this is the sidecar's address on
  # the default bridge, which is the only way off the host anyway.  Destinations
  # that are themselves on-link need no exemption: their connected route is more
  # specific than any of the ranges the baseline blackholes.
  default_gateway() { # -4|-6
    ip -o "$1" route show default 2>/dev/null | awk '
      { via = ""; dev = ""
        for (i = 1; i < NF; i++) {
          if ($i == "via") via = $(i + 1)
          if ($i == "dev") dev = $(i + 1)
        }
        if (via != "" && dev != "") { print "via", via, "dev", dev; exit }
      }'
  }
fi

# Graceful shutdown: track the proxy PID and forward signals.
proxy_pid=""
cleanup() {
  [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Values of one policy key, one per line.
policy_values() {
  [[ -f "$policy_file" ]] || return 0
  while read -r key value _rest; do
    [[ "$key" == "$1" ]] || continue
    [[ -n "${value:-}" ]] || continue
    printf '%s\n' "$value"
  done < "$policy_file"
}

# Defence in depth behind the proxy's own deny_ips check: a route the sandbox
# cannot use at all, in case anything ever reaches the sidecar's netns without
# passing through the proxy.  Needs --cap-add=NET_ADMIN.
#
# Reconciles against the kernel rather than against a remembered list, so there
# is no state to keep in sync and nothing to get wrong after a restart.  The
# proxy watches the same file independently; while the two briefly disagree both
# are still deny mechanisms, and the proxy is the one the traffic traverses.
in_list() {
  local needle="$1" item
  shift
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

# The form `ip route show` prints a prefix back in, so that what is installed
# compares equal to what is read.  A host route loses its /32 or /128 there, and
# a policy written `deny_ips 8.8.8.8/32` used to be re-added on every pass --
# each one failing with EEXIST -- because it never matched the `8.8.8.8` the
# kernel reported.  Guarded on `:` so an IPv6 /32 network is left alone.
route_prefix() { # ENTRY
  local entry="$1"
  case "$entry" in
    */32)  [[ "$entry" == *:* ]] || entry="${entry%/32}" ;;
    */128) entry="${entry%/128}" ;;
  esac
  printf '%s\n' "$entry"
}

# The addresses the sidecar itself resolves against, as podman wrote them from
# the launcher's --dns arguments.
resolv_nameservers() {
  [[ -r "$resolv_conf" ]] || return 0
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*nameserver[[:space:]]+([^[:space:]]+) ]] || continue
    printf '%s\n' "${BASH_REMATCH[1]}"
  done < "$resolv_conf"
}

# Routes that must beat a blackhole, installed via the default gateway so the
# kernel's longest-prefix match resolves the overlap.  That match *is* the rule
# is_denied_address applies in the proxy, so mirroring allow_ips here is what
# keeps the two layers from disagreeing -- before this, a re-allowed range was
# permitted by the proxy and then dropped on the floor by the route.
#
# The nameservers are exempt whatever the policy says, and that is not a hole:
# the sandbox has no route into this netns at all, its only egress is CONNECT to
# the proxy, and the proxy still runs is_denied_address over every resolved
# address.  A `CONNECT 10.0.0.53:53` stays refused.  Without this, a deny_ips
# range covering the host's resolver -- which the baseline's own 192.168.0.0/16
# does for a great many home networks -- blackholes name resolution itself and
# every request fails, long after the proxy's egress probe has passed.
want_exemptions() {
  local seen=() entry
  while read -r entry; do
    [[ -n "$entry" ]] || continue
    # An allow rule must not be able to replace the default route.
    [[ "$entry" == 0.0.0.0/0 || "$entry" == ::/0 ]] && continue
    entry=$(route_prefix "$entry")
    # A rule that repeats one already exempt -- an allow_ips naming a nameserver,
    # say -- would otherwise be re-added, and fail, on every pass.
    in_list "$entry" ${seen[@]+"${seen[@]}"} && continue
    seen+=("$entry")
    printf '%s\n' "$entry"
  done < <(policy_values allow_ips; resolv_nameservers)
}

# deny_ips, less anything already exempt.  Two rules of the same prefix length
# can only both match an address by being the same network, so subtracting the
# exemptions is the whole of the equal-specificity tie that is_denied_address
# breaks toward allow -- and the one case a routing table cannot express, there
# being room for a single route per prefix.  It also keeps a deny naming a
# nameserver outright from fighting that nameserver's exemption for the slot.
want_blackholes() {
  local exempt=() entry
  mapfile -t exempt < <(want_exemptions)
  while read -r entry; do
    [[ -n "$entry" ]] || continue
    entry=$(route_prefix "$entry")
    in_list "$entry" ${exempt[@]+"${exempt[@]}"} && continue
    printf '%s\n' "$entry"
  done < <(policy_values deny_ips)
}

sync_routes() {
  local want=() have=() entry gw

  mapfile -t want < <(want_exemptions)
  mapfile -t have < <(installed_exemptions)

  for entry in ${want[@]+"${want[@]}"}; do
    in_list "$entry" ${have[@]+"${have[@]}"} && continue
    if [[ "$entry" == *:* ]]; then gw=$(default_gateway -6); else gw=$(default_gateway -4); fi
    if [[ -z "$gw" ]]; then
      echo "sidecar: no default route to exempt $entry through" >&2
      continue
    fi
    # $gw is a deliberately unquoted `via GW dev DEV`.
    # shellcheck disable=SC2086
    run_ip route add "$entry" $gw proto "$exempt_proto" \
      || echo "sidecar: cannot exempt $entry" >&2
  done

  for entry in ${have[@]+"${have[@]}"}; do
    [[ -n "$entry" ]] || continue
    in_list "$entry" ${want[@]+"${want[@]}"} && continue
    run_ip route del "$entry" proto "$exempt_proto" \
      || echo "sidecar: cannot un-exempt $entry" >&2
  done

  mapfile -t want < <(want_blackholes)
  mapfile -t have < <(installed_blackholes)

  for entry in ${want[@]+"${want[@]}"}; do
    in_list "$entry" ${have[@]+"${have[@]}"} && continue
    # Not fatal -- the proxy is the enforcing layer -- but no longer silent:
    # a rejected route used to vanish into `|| true`.
    run_ip route add blackhole "$entry" \
      || echo "sidecar: cannot blackhole $entry" >&2
  done

  for entry in ${have[@]+"${have[@]}"}; do
    [[ -n "$entry" ]] || continue
    in_list "$entry" ${want[@]+"${want[@]}"} && continue
    run_ip route del blackhole "$entry" \
      || echo "sidecar: cannot un-blackhole $entry" >&2
  done
}

# Nothing to do about DNS here, and that is now true by construction rather than
# by hope.  The launcher creates the internal network --disable-dns, so podman
# writes the host's real nameservers into /etc/resolv.conf instead of pointing it
# at an aardvark-dns that refuses to forward for --internal networks.  Two
# earlier versions of this file rewrote resolv.conf by hand to work around that;
# both were guessing at a configuration the launcher can simply ask for.

proxy_args=(--log "$metrics_log")
# Unconditional under --proxy: the launcher always writes at least the
# baseline private/loopback deny list to this file (see agent-sandbox.sh), so
# a proxy that never reads it would run an empty config and be usable as an
# SSRF pivot onto the host and its LAN.
if [[ ! -f "$policy_file" ]]; then
  echo "sidecar: $policy_file is missing" >&2
  exit 1
fi
proxy_args+=(--policy "$policy_file")

# Bind only the address the sidecar has on its internal network, not every
# interface: the sidecar is also on the default podman bridge (for
# HTTP_PROXY/DNS plumbing the launcher needs), and a proxy listening on
# 0.0.0.0 would be reachable there too, by any other container of the same
# user.  Picked by subnet membership, not by interface name/order -- the
# launcher passes `--network bridge --network "$sidecar_id"`, and which one
# podman assigns as eth0 is not something to depend on.
#
# Skipped under dry-run: there is no real interface to inspect outside a
# container, and no bind actually happens there anyway.
sidecar_listen=""
if [[ "${AGENT_SANDBOX_SIDECAR_DRY_RUN:-0}" != "1" ]]; then
  if [[ -z "${SIDECAR_SUBNET:-}" ]]; then
    echo "sidecar: SIDECAR_SUBNET is not set; refusing to bind on all interfaces" >&2
    exit 1
  fi
  sidecar_listen=$(run_ip -o -4 addr show scope global \
    | awk '{print $4}' \
    | python3 -c '
import ipaddress, sys
subnet = ipaddress.ip_network(sys.argv[1])
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    ip = ipaddress.ip_interface(line).ip
    if ip in subnet:
        print(ip)
        break
' "$SIDECAR_SUBNET")
  if [[ -z "$sidecar_listen" ]]; then
    echo "sidecar: no local address falls inside $SIDECAR_SUBNET" >&2
    exit 1
  fi
  proxy_args+=(--listen "$sidecar_listen:8888")
fi

if [[ "${AGENT_SANDBOX_SIDECAR_DRY_RUN:-0}" == "1" ]]; then
  run_proxy "${proxy_args[@]}"
  sync_routes
  exit 0
fi

run_proxy "${proxy_args[@]}" &
proxy_pid=$!

# The proxy gates proxy-ready on a working name lookup, so allow for its full
# READY_TIMEOUT.  Give up if it dies first: with a rejected policy it exits
# immediately, and waiting out the timeout would hide the reason.
for _ in $(seq 1 350); do
  [[ -f /sidecar_shared/proxy-ready ]] && break
  kill -0 "$proxy_pid" 2>/dev/null || break
  sleep 0.1
done

if ! kill -0 "$proxy_pid" 2>/dev/null; then
  echo "sidecar: the proxy exited before signalling readiness" >&2
  wait "$proxy_pid"   # propagate its exit status (2 = bad policy)
  exit 1
fi

sync_routes

# Tells the launcher the sandbox may start.
printf 'ready\n' > /sidecar_shared/ready

# The policy can change while the session runs (agent-sandbox-ctl proxy), and
# the proxy reloads it on its own; these routes have to follow.  Same interval,
# and cheap: one `ip route show` per second.
while kill -0 "$proxy_pid" 2>/dev/null; do
  sleep 1
  sync_routes
done

wait "$proxy_pid"
