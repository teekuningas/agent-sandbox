#!/usr/bin/env bash
# --host-loopback-port reaches a service on the host's loopback from inside.
#
# This is the one direction podman's own networking cannot give a sandbox that
# is on the proxy's internal network, which is why the launcher splices unix
# sockets instead. Only a real container shows whether the splice carries data.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

hostport=18123
server="$(start_host_http_server "$hostport" 127.0.0.1)" \
  || skip "no way to start an HTTP server on the host (no python3, no nix)"
trap 'kill $server 2>/dev/null; cleanup_sandboxes' EXIT

for _ in $(seq 1 30); do
  curl --silent --max-time 2 -o /dev/null "http://127.0.0.1:$hostport/" && break
  sleep 1
done

out="$(sandbox_run --host-loopback-port "$hostport" -- \
  bash -c "curl --silent --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:$hostport/ || echo failed")"
assert_contains "$out" "200" "a host loopback service, fetched from inside"

# Without the flag the host's loopback is not the sandbox's loopback, and
# nothing should answer there.
out="$(sandbox_run -- \
  bash -c "curl --silent --max-time 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:$hostport/ || echo refused")"
assert_contains "$out" "refused" "the same address without the flag"
