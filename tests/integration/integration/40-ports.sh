#!/usr/bin/env bash
# A declared port, published with --ports, actually carries traffic.
#
# The stub tests prove the -p argument is built correctly. This proves the
# thing that argument is for, including the part that trips people up: a server
# binding 127.0.0.1 inside the container is not reachable from the host.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_command curl
# The server runs inside the sandbox, so it is the image that needs python3,
# not the host.

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT

port=18099
cat > "$ws/AGENTS.md" <<EOF
# Port test

\`\`\`toml agent-sandbox
[ports]
web = { container = 8080, host = $port }
\`\`\`
EOF

cd "$ws" || exit 1

# A server bound to 0.0.0.0 inside, reachable on the host's loopback.
sandbox_run --workspace --ports -- \
  bash -c 'python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1' &
launcher=$!
trap 'kill $launcher 2>/dev/null; rm -rf "$ws"; cleanup_sandboxes' EXIT

for _ in $(seq 1 40); do
  curl --silent --max-time 2 -o /dev/null "http://127.0.0.1:$port/" && break
  sleep 0.5
done

code="$(curl --silent --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/" || true)"
assert_eq "200" "$code" "the published port answers on the host"

kill $launcher 2>/dev/null
wait $launcher 2>/dev/null
cleanup_sandboxes

# Without --ports the declaration is inert: AGENTS.md alone must never open a
# hole in the host's network.
sandbox_run --workspace -- bash -c 'sleep 5' &
launcher=$!
sleep 3
code="$(curl --silent --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/" || echo "refused")"
# curl writes its 000 placeholder before the `||` fires, so the reply is
# "000refused", not "refused" alone. Either half proves nothing answered.
assert_contains "$code" "refused" "the same port without --ports"
kill $launcher 2>/dev/null
wait $launcher 2>/dev/null

# `wait` on a process we just killed reports 143, and as the last command in
# the file that would become the case's own exit status -- a green run
# reported as a failure. Every assertion above has already passed by the time
# we reach here, because _fail exits on the spot. So say so explicitly.
exit 0
