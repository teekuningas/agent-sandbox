#!/usr/bin/env bash
# Fixture tests for agent-sandbox-network-summary.
#
# The renderer is the only consumer of the proxy's log format, and the two are
# versioned independently: a log written by an older proxy has no "ev" field at
# all, and must keep rendering as it did before open/close events existed.  The
# open/close cases are here because an unpaired "open" that leaked into the
# connection count would silently inflate every summary printed at session exit.
#
# Usage: test-network-summary.sh [path-to-renderer]

set -euo pipefail

renderer="${1:-$(dirname "$0")/agent-sandbox-network-summary.sh}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
now=$(date +%s)

render() {
  bash "$renderer" "$@" 2>&1
}

# Indent a failing report under its label.  Via a file, because sed on a
# here-string is what SC2001 objects to.
show() {
  printf '%s\n' "$1" > "$tmp/out"
  sed 's/^/           /' "$tmp/out"
}

# Assert that the rendered fixture contains (or does not contain) a substring.
expect_out() {
  local label="$1" want="$2" report="$3"
  if grep -qF -- "$want" <<< "$report"; then
    printf 'ok       %s\n' "$label"
  else
    printf 'FAIL     %s (missing: %s)\n' "$label" "$want"
    show "$report"
    failures=$((failures + 1))
  fi
}

refute_out() {
  local label="$1" unwanted="$2" report="$3"
  if grep -qF -- "$unwanted" <<< "$report"; then
    printf 'FAIL     %s (unexpected: %s)\n' "$label" "$unwanted"
    show "$report"
    failures=$((failures + 1))
  else
    printf 'ok       %s\n' "$label"
  fi
}

close_row() { # host port verdict up down [err]
  local extra=""
  [[ -n "${6:-}" ]] && extra=",\"err\":\"$6\""
  printf '{"ts":%s,"host":"%s","port":%s,"verdict":"%s","up":%s,"down":%s,"ms":120%s}\n' \
    "$now" "$1" "$2" "$3" "$4" "$5" "$extra"
}

# --- empty and unreadable inputs -------------------------------------------

expect_out "missing log" "(no connections recorded)" "$(render "$tmp/nonexistent.jsonl")"

: > "$tmp/empty.jsonl"
expect_out "empty log" "(no connections recorded)" "$(render "$tmp/empty.jsonl")"

# --- the pre-events log format ---------------------------------------------

{
  close_row a.example.com 443 allow 100 2048
  close_row a.example.com 443 allow 10 1048576
  close_row b.example.com 443 deny 0 0
  close_row d.example.com 443 error 0 0 "dns: no such host"
} > "$tmp/legacy.jsonl"
legacy=$(render "$tmp/legacy.jsonl")

expect_out "counts only connections"        "4 connections"   "$legacy"
expect_out "aggregates a host"              "a.example.com"   "$legacy"
expect_out "totals bytes"                   "1 MiB in"        "$legacy"
expect_out "denied section"                 "── denied"       "$legacy"
expect_out "failed section"                 "── failed"       "$legacy"
expect_out "names the failure reason"       "(dns: no such host)" "$legacy"
refute_out "no in-flight noise"             "in flight"       "$legacy"
refute_out "no still-open section"          "── still open"   "$legacy"

# A record still being written must cost only itself, not the whole report.
{ cat "$tmp/legacy.jsonl"; printf '{"ts":%s,"host":"trunc' "$now"; } > "$tmp/torn.jsonl"
torn=$(render "$tmp/torn.jsonl")
expect_out "torn final line is skipped"     "4 connections"   "$torn"
refute_out "torn line does not abort"       "could not parse" "$torn"

# --- host ranking and the collapsed tail -----------------------------------

: > "$tmp/many.jsonl"
for i in $(seq 1 18); do
  close_row "host$i.example.com" 443 allow "$i" $((i * 1000)) >> "$tmp/many.jsonl"
done
many=$(render "$tmp/many.jsonl")
expect_out "ranks by volume"                "host18.example.com" "$many"
expect_out "collapses the tail"             "… and 3 more hosts" "$many"
refute_out "tail hosts are not listed"      "host1.example.com"  "$many"

# --- open / close events ---------------------------------------------------

{
  printf '{"ev":"open","id":"7-1","ts":%s,"host":"tunnel.example.com","port":443}\n' "$((now - 90))"
  printf '{"ev":"open","id":"7-2","ts":%s,"host":"done.example.com","port":443}\n' "$((now - 60))"
  printf '{"ev":"close","id":"7-2","ts":%s,"host":"done.example.com","port":443,"verdict":"allow","up":50,"down":500,"ms":59000}\n' "$now"
} > "$tmp/events.jsonl"
events=$(render "$tmp/events.jsonl")

expect_out "closed pair counts once"        "1 connection"        "$events"
refute_out "close is not double-counted"    "2 connections"       "$events"
expect_out "unclosed open is in flight"     "1 in flight"         "$events"
expect_out "still-open section"             "── still open"       "$events"
expect_out "still-open names host and port" "tunnel.example.com:443" "$events"
refute_out "closed host is not still open"  "done.example.com:443" "$events"
expect_out "closed host appears as traffic" "done.example.com"    "$events"

# An "open" with no verdict must not be mistaken for a completed connection
# and must not trigger the "nothing got through" advice, which exists to
# explain a session where the proxy itself could not reach the network.
{
  printf '{"ev":"open","id":"9-1","ts":%s,"host":"slow.example.com","port":443}\n' "$((now - 5))"
  close_row broken.example.com 443 error 0 0 "connect: timed out"
} > "$tmp/orphan.jsonl"
orphan=$(render "$tmp/orphan.jsonl")
expect_out "orphan open is in flight"       "1 in flight"     "$orphan"
refute_out "in-flight suppresses the hint"  "Nothing got through" "$orphan"

# With nothing in flight the hint must still fire.
close_row broken.example.com 443 error 0 0 "connect: timed out" > "$tmp/allfail.jsonl"
expect_out "hint fires when all failed"     "Nothing got through" \
  "$(render "$tmp/allfail.jsonl")"

# --- stream mode -----------------------------------------------------------

stream=$(render --stream "$tmp/events.jsonl")
expect_out "stream marks an open"           "open   tunnel.example.com:443" "$stream"
expect_out "stream marks a verdict"         "allow" "$stream"
expect_out "stream formats bytes"           "500 B" "$stream"

# One malformed line must not end a follow session.
junk=$(printf 'not json\n\n%s' "$(close_row ok.example.com 80 allow 1 2)" | render --stream -)
expect_out "stream skips junk lines"        "ok.example.com:80" "$junk"

# --- stdin parity ----------------------------------------------------------

if diff <(render "$tmp/legacy.jsonl") <(render - < "$tmp/legacy.jsonl") >/dev/null; then
  printf 'ok       stdin matches the file path\n'
else
  printf 'FAIL     stdin matches the file path\n'
  failures=$((failures + 1))
fi

if [[ "$failures" -gt 0 ]]; then
  printf '\n%s test(s) failed\n' "$failures" >&2
  exit 1
fi

printf '\nall network-summary tests passed\n'
