#!/usr/bin/env bash
# The policed browser reaches the app a declared [ports] entry names.
#
# Two things this tier can establish that the unit tests cannot. First the
# documented order: the browser starts *before* the sandbox, so its allow list
# has to come from what AGENTS.md declares rather than from what podman can be
# asked about -- that ordering was a 403 on every loopback fetch. Second the
# request the app actually receives: a proxy must send origin-form upstream,
# and `python3 -m http.server` is the server that notices when it does not,
# answering 404 for a request it would otherwise serve.
#
# No real Chromium is involved. The browser's own proxy is the thing under
# test and curl speaks to it directly, which also keeps the case runnable on a
# machine with no display.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_command curl

ws="$(make_workspace)"
name="astest-browser-$$"
rt="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agent-sandbox-browser-$name"

port=18096
undeclared=18097
widened=18098

cat > "$ws/AGENTS.md" <<EOF
# Browser port test

\`\`\`toml agent-sandbox
[ports]
web = { container = 8080, host = $port }
\`\`\`
EOF

# Stands in for Chromium: it must simply stay alive, because the browser tears
# its runtime directory down as soon as the browser process exits.
cat > "$ws/fake-chromium" <<'EOF'
#!/usr/bin/env bash
sleep 600
EOF
chmod +x "$ws/fake-chromium"

cd "$ws" || exit 1

cleanup() {
  kill "${browser:-}" 2>/dev/null
  kill "${launcher:-}" 2>/dev/null
  rm -rf "$ws"
  cleanup_sandboxes
}
trap cleanup EXIT

# ── the browser, with nothing running yet ───────────────────────────────────

"$AS" ctl browser --name "$name" --no-extensions --chromium "$ws/fake-chromium" \
  >"$ws/browser.log" 2>&1 &
browser=$!

for _ in $(seq 1 40); do
  [ -f "$rt/meta.json" ] && [ -f "$rt/proxy-ready" ] && break
  sleep 0.5
done
[ -f "$rt/meta.json" ] || _fail "the browser never wrote $rt/meta.json ($(cat "$ws/browser.log"))"

proxy_port="$(grep -o '"proxy_port"[^0-9]*[0-9]*' "$rt/meta.json" | grep -o '[0-9]*$')"
[ -n "$proxy_port" ] || _fail "no proxy port in $rt/meta.json"

policy="$(cat "$rt/policy")"
assert_contains "$policy" "allow_ip 127.0.0.1/32:$port" "the declared port, with no sandbox running"
assert_contains "$policy" "allow_host localhost:$port" "the same port under its name"

# ── the sandbox it was declared for ─────────────────────────────────────────

sandbox_run --workspace --ports -- \
  bash -c "echo hello > index.html; python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1" &
launcher=$!

for _ in $(seq 1 40); do
  curl --silent --max-time 2 -o /dev/null "http://127.0.0.1:$port/" && break
  sleep 0.5
done

# Through the browser's proxy, which is the whole point: the same fetch the
# browser would make.
code="$(curl --silent --max-time 5 -o /dev/null -w '%{http_code}' \
  -x "http://127.0.0.1:$proxy_port" "http://127.0.0.1:$port/" || true)"
assert_eq "200" "$code" "the declared port through the browser's proxy"

# The 404 that started this: an absolute-form request line reaches http.server
# as a path, and it serves nothing under that name.
body="$(curl --silent --max-time 5 -x "http://127.0.0.1:$proxy_port" \
  "http://127.0.0.1:$port/index.html" || true)"
assert_contains "$body" "hello" "the file the app serves, not a 404 page"

# The name has to work too: to the proxy `localhost` is a domain, not an
# address, and it never reaches the allow_ip rule.
code="$(curl --silent --max-time 5 -o /dev/null -w '%{http_code}' \
  -x "http://127.0.0.1:$proxy_port" "http://localhost:$port/" || true)"
assert_eq "200" "$code" "the same app under localhost"

# Nothing else on the operator's loopback.
out="$(curl --silent --max-time 5 -o /dev/null -w '%{http_code}' \
  -x "http://127.0.0.1:$proxy_port" "http://127.0.0.1:$undeclared/" 2>&1 || echo BLOCKED)"
assert_denied "$out" "a port nobody declared"

# ── widening a running browser reaches both layers ──────────────────────────

"$AS" ctl proxy allow "127.0.0.1:$widened" --browser "$name" >/dev/null 2>&1 \
  || _fail "ctl proxy allow --browser failed"
managed="$(cat "$rt/policies/managed/agent-sandbox.json")"
assert_contains "$managed" "127.0.0.1:$widened" "the managed allow list after widening"
assert_contains "$managed" "\"URLBlocklist\"" "the managed policy is otherwise intact"

kill $launcher 2>/dev/null
wait $launcher 2>/dev/null
kill $browser 2>/dev/null
wait $browser 2>/dev/null

# `wait` on a killed process reports 143, which as the last command would be
# the case's exit status. Every assertion has already passed by here.
exit 0
