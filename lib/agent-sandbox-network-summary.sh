#!/usr/bin/env bash
set -euo pipefail

# Render the proxy's connection log: one JSON object per connection (see
# proxy/src/main.rs), aggregated per host.  Hosts are ranked by volume and the
# tail is collapsed so a long session cannot flood the terminal.
#
# Kept out of the launcher so that `agent-sandbox-ctl net` prints the identical
# report for a *running* sandbox, and so a log kept after a failed session can
# be re-rendered on demand.

usage() {
  cat <<'EOF'
Usage: agent-sandbox-network-summary [--stream] [LOG|-]

Reads the proxy connection log (NDJSON) and writes a report to stdout.
Reads stdin when LOG is "-" or omitted.

  --stream   One line per record as it arrives, instead of the aggregate
             report.  Records describe *completed connections*, so a
             long-lived tunnel only appears once it closes.
EOF
}

mode=summary
log=-
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stream)  mode=stream ;;
    -h|--help) usage; exit 0 ;;
    -)         log=- ;;
    -*)        echo "${0##*/}: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)         log="$1" ;;
  esac
  shift
done

# Shared by both modes so the byte formatting cannot drift between the report
# and the live feed.
#
# The $names below are jq variables, so these programs must stay single-quoted.
# SC2016's exemption for arguments of jq does not extend to assignments.
# shellcheck disable=SC2016
jq_helpers='
    def human:
      if . < 1024 then "\(.) B"
      elif . < 1048576 then "\(. / 1024 * 10 | round / 10) KiB"
      elif . < 1073741824 then "\(. / 1048576 * 10 | round / 10) MiB"
      else "\(. / 1073741824 * 10 | round / 10) GiB"
      end;
    def dur:
      if . < 60 then "\(.)s"
      elif . < 3600 then "\(. / 60 | floor)m \(. % 60)s"
      else "\(. / 3600 | floor)h \(. % 3600 / 60 | floor)m"
      end;
    def pad($n): tostring | . + (if length < $n then " " * ($n - length) else "" end);
    def lpad($n): tostring | (if length < $n then " " * ($n - length) else "" end) + .;
    def clip($n): if length > $n then .[0:($n - 1)] + "…" else . end;
'

# An "open" record has no verdict and no byte counts; it is superseded by the
# matching "close".  Treating a record without .ev as a close keeps logs written
# by an older proxy rendering exactly as before.
# shellcheck disable=SC2016
summary_body='
    . as $rows
    | [$rows[] | select((.ev // "close") == "close")] as $all
    | ([$rows[] | select(.ev == "close") | .id | select(. != null)
        | {(tostring): true}] | add // {}) as $closed
    | [$rows[] | select(.ev == "open") | select($closed[.id | tostring] | not)] as $live
    | ($all | map(select(.verdict == "allow"))) as $ok
    | ($all | map(select(.verdict == "deny")) | group_by(.host)
        | map({host: .[0].host, conns: length}) | sort_by(-.conns)) as $den
    | ($all | map(select(.verdict == "error"))
        | group_by([.host, (.err // "?")])
        | map({host: .[0].host, conns: length, err: (.[0].err // "?")})
        | sort_by(-.conns)) as $fail
    | ($ok | group_by(.host)
        | map({host: .[0].host, conns: length,
               up: (map(.up) | add), down: (map(.down) | add)})
        | sort_by(-(.up + .down))) as $hosts
    | ($hosts[0:15]) as $shown
    | ($hosts[15:]) as $rest
    | ([20] + (($shown + $den + $fail) | map(.host | length))
            + ($live | map("\(.host):\(.port)" | length)) | max) as $w0
    | (if $w0 > 40 then 40 else $w0 end) as $w
    | (($rows | map(.ts) | max) - ($rows | map(.ts) | min)) as $span
    | ($ok | map(.up) | add // 0) as $tup
    | ($ok | map(.down) | add // 0) as $tdown
    | [ "",
        "=== Network Summary ===  \($span | dur) · \($all | length) connection\(if ($all | length) == 1 then "" else "s" end)"
          + (if ($ok | length) > 0 then " · \($tdown | human) in / \($tup | human) out" else "" end)
          + (if ($live | length) > 0 then " · \($live | length) in flight" else "" end) ]
      + (if ($shown | length) > 0 then [""] else [] end)
      + (if ($shown | length) > 0 then
          ["  " + ("HOST" | pad($w)) + ("CONNS" | lpad(7))
                + ("SENT" | lpad(11)) + ("RECV" | lpad(11))]
          + ($shown | map("  " + (.host | clip($w) | pad($w)) + (.conns | lpad(7))
                              + (.up | human | lpad(11)) + (.down | human | lpad(11))))
          + (if ($rest | length) > 0 then
              ["  " + ("… and \($rest | length) more hosts" | clip($w) | pad($w))
                    + (($rest | map(.conns) | add) | lpad(7))
                    + (($rest | map(.up) | add) | human | lpad(11))
                    + (($rest | map(.down) | add) | human | lpad(11))]
             else [] end)
         else [] end)
      + (if ($den | length) > 0 then
          ["", "  ── denied " + ("─" * ($w + 19))]
          + ($den | map("  " + (.host | clip($w) | pad($w)) + (.conns | lpad(7))))
         else [] end)
      + (if ($fail | length) > 0 then
          ["", "  ── failed " + ("─" * ($w + 19))]
          + ($fail | map("  " + (.host | clip($w) | pad($w)) + (.conns | lpad(7))
                              + "  (" + .err + ")"))
         else [] end)
      + (if ($live | length) > 0 then
          ["", "  ── still open " + ("─" * ($w + 15))]
          + ($live | sort_by(.ts)
             | map("  " + ("\(.host):\(.port)" | clip($w) | pad($w))
                        + ((((now | floor) - .ts) | if . < 0 then 0 else . end | dur) | lpad(9))))
         else [] end)
      + (if ($ok | length) == 0 and ($fail | length) > 0 and ($live | length) == 0 then
          ["", "  Nothing got through. The sidecar could not reach the network;",
               "  see the proxy log:  podman logs <sidecar>"]
         else [] end)
      + [""]
    | .[]
'

# One line per record.  Times are wall clock so a reader can line the feed up
# against whatever the agent was doing.
# shellcheck disable=SC2016
stream_body='
    (fromjson? // empty)
    | def ms: if . < 1000 then "\(.)ms" else ((. / 1000 | floor) | dur) end;
      (try (.ts | strflocaltime("%H:%M:%S")) catch "--:--:--") as $t
    | if .ev == "open" then
        "\($t)  open   " + ("\(.host):\(.port)" | clip(40))
      else
        "\($t)  " + ((.verdict // "?") | pad(6)) + " "
        + ("\(.host):\(.port)" | clip(40) | pad(40))
        + (.up | human | lpad(11)) + (.down | human | lpad(11))
        + (.ms | ms | lpad(9))
        + (if .err then "  (\(.err))" else "" end)
      end
'

if [[ "$mode" == "summary" ]]; then
  # An absent or empty log is the normal state of a session that made no
  # connections, not an error.
  if [[ "$log" != "-" && ! -s "$log" ]]; then
    printf '\n=== Network Summary ===\n(no connections recorded)\n'
    exit 0
  fi
  set --
  [[ "$log" != "-" ]] && set -- "$log"
  # Reading as raw lines and parsing each one individually (rather than jq -s)
  # keeps a torn final line -- a record still being written -- from discarding
  # the entire report.
  jq -rRn "[inputs|fromjson?] | ($jq_helpers $summary_body)" "$@" 2>/dev/null ||
    printf '\n=== Network Summary ===\n(could not parse %s)\n' "$log"
else
  [[ "$log" == "-" ]] || exec < "$log"
  # --unbuffered or nothing reaches the terminal until 4 KiB has accumulated.
  jq -rR --unbuffered "$jq_helpers $stream_body" || true
fi
