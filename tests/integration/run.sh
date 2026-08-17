#!/usr/bin/env bash
# Runs one directory of cases, writing a log per case and a summary at the end.
#
#   ./run.sh integration [logdir]
#   ./run.sh acceptance  [logdir] [case-name-filter]
#
# Exits non-zero if any case failed. Skips are not failures: a machine without
# an SSH agent, without krun, or without egress cannot run every case, and
# saying so is more useful than pretending the suite passed.

set -u

here="$(cd "$(dirname "$0")" && pwd)"
tier="${1:?usage: run.sh <integration|acceptance> [logdir] [filter]}"
logdir="${2:-$here/logs/$tier}"
filter="${3:-}"

dir="$here/$tier"
[ -d "$dir" ] || { echo "no such tier: $tier" >&2; exit 2; }

# Per case. Raise it for a slow machine, or for the first run against a freshly
# loaded image -- see the note about --userns=keep-id in the Makefile's `warm`.
CASE_TIMEOUT="${CASE_TIMEOUT:-900}"

mkdir -p "$logdir"
rm -f "$logdir"/*.log

pass=0; fail=0; skipped=0
failed_cases=()
skipped_cases=()

echo "== $tier =="
echo "   binary: ${AGENT_SANDBOX_BIN:-<resolved by lib.sh>}"
echo "   logs:   $logdir"
echo

for case_file in "$dir"/*.sh; do
  [ -e "$case_file" ] || continue
  name="$(basename "$case_file" .sh)"
  if [ -n "$filter" ] && [[ "$name" != *"$filter"* ]]; then
    continue
  fi

  log="$logdir/$name.log"
  printf '%-40s' "$name"

  {
    echo "### $name"
    echo "### $(date -Is)"
    echo
  } > "$log"

  # A case that hangs is a failure, not a stalled suite: the proxy paths have
  # their own 35s readiness window, so the ceiling has to sit well above it.
  #
  # stdin comes from /dev/null because the launcher passes --interactive to
  # `podman run`.  Left attached to the terminal, a container would compete
  # with the runner for the same stdin, which looks exactly like a hang.
  start=$SECONDS
  timeout --signal=TERM --kill-after=30 "$CASE_TIMEOUT" \
    bash "$case_file" >> "$log" 2>&1 < /dev/null
  status=$?
  elapsed=$((SECONDS - start))

  case $status in
    0)   echo "PASS  (${elapsed}s)";       pass=$((pass + 1)) ;;
    77)  echo "SKIP  ($(grep -m1 'SKIP:' "$log" | sed 's/.*SKIP: //'))"
         skipped=$((skipped + 1)); skipped_cases+=("$name") ;;
    124) echo "FAIL  (timed out after ${CASE_TIMEOUT}s)"
         fail=$((fail + 1)); failed_cases+=("$name") ;;
    *)   echo "FAIL  (exit $status, ${elapsed}s)"
         fail=$((fail + 1)); failed_cases+=("$name") ;;
  esac
done

echo
echo "-- $tier: $pass passed, $fail failed, $skipped skipped --"

if [ ${#failed_cases[@]} -gt 0 ]; then
  echo
  echo "failed:"
  for name in "${failed_cases[@]}"; do
    echo "  $name  ($logdir/$name.log)"
    sed -n 's/^  FAIL: /    → /p' "$logdir/$name.log"
  done
fi

if [ ${#skipped_cases[@]} -gt 0 ]; then
  echo
  echo "skipped:"
  for name in "${skipped_cases[@]}"; do
    printf '  %-32s %s\n' "$name" "$(sed -n 's/.*SKIP: //p' "$logdir/$name.log" | head -1)"
  done
fi

[ "$fail" -eq 0 ]
