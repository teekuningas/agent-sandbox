#!/usr/bin/env bash
# One screen of state for a running sandbox.
#
# Deliberately an index, not a report: counts and names only, each line ending in
# the command that shows the detail.  `net` renders traffic, `proxy show`
# renders the policy, `ports ls` renders the forwards; if this printed those
# lists too there would be three commands disagreeing about the same thing.
#
# AGENTS.md TOML for a running sandbox is not printed here: `proxy export`,
# `ports export` and `mounts export` each print their own section, since each is
# already the command that owns that piece of state.

usage() {
  cat <<'USAGE'
agent-sandbox-status [WORD] [--sandbox WORD]

Summarises one running sandbox: workspace, proxy mode, policy and traffic
counts, and published ports.  Each line names the command that shows more.

With one sandbox running, --sandbox may be omitted.
USAGE
}

sandbox_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sandbox)
      shift
      [[ $# -gt 0 ]] || { echo "${0##*/}: --sandbox needs a name" >&2; exit 1; }
      sandbox_name="$1"
      ;;
    --sandbox=*) sandbox_name="${1#--sandbox=}" ;;
    -h|--help)   usage; exit 0 ;;
    -*)          echo "${0##*/}: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)
       if [[ -z "$sandbox_name" ]]; then
         sandbox_name="$1"
       else
         echo "${0##*/}: unexpected argument: $1" >&2; usage >&2; exit 1
       fi
       ;;
  esac
  shift
done

if [[ -n "$sandbox_name" && ! "$sandbox_name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
  echo "${0##*/}: invalid sandbox name: $sandbox_name" >&2
  exit 1
fi

sandbox=$(resolve_sandbox "$sandbox_name" --running)
workspace_dir=$(sandbox_workspace "$sandbox")
sidecar=$(sidecar_for_sandbox "$sandbox")

row() { printf '  %-12s%s\n' "$1" "$2"; }

printf '%s\n' "$(sandbox_word "$sandbox")"
row workspace "$workspace_dir"
row uptime    "$(podman ps --filter "name=^${sandbox}\$" --format '{{.Status}}' 2>/dev/null)"

mode=$(sandbox_proxy_mode "$sandbox")
case "$mode" in
  proxy) row proxy "on  ($sidecar)" ;;
  off)   row proxy "off  (direct network access)" ;;
  # Pre-dates the label: fall back to whether a sidecar is actually there.
  *)     row proxy "$([[ -n "$sidecar" ]] && echo "on  ($sidecar)" || echo unknown)" ;;
esac

# An absent label means a launcher that predates it, which could only have
# started an ordinary container.
case "$(sandbox_runtime "$sandbox")" in
  krun) row runtime "krun  (microVM; no attach, no mounts)" ;;
  *)    row runtime "crun" ;;
esac

networks=$(podman inspect --format \
  '{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}' "$sandbox" 2>/dev/null || true)
[[ -n "${networks// /}" ]] && row networks "${networks% }"

# ── policy ──────────────────────────────────────────────────────────────────

if [[ -n "$sidecar" ]]; then
  policy_dir=$(sidecar_mount "$sidecar" /sidecar_policy)
  if [[ -n "$policy_dir" && -r "$policy_dir/policy" ]]; then
    rules=$(grep -cE '^(allow|deny)_' "$policy_dir/policy" 2>/dev/null || true)
    if grep -q '^allow_' "$policy_dir/policy" 2>/dev/null; then
      default=deny
    else
      default=allow
    fi
    if grep -q '^default ' "$policy_dir/policy" 2>/dev/null; then
      default=$(awk '$1 == "default" { print $2 }' "$policy_dir/policy" | tail -n 1)
    fi
    row policy "${rules:-0} rule(s), default $default        agent-sandbox-ctl proxy show"
  fi

  # ── traffic ───────────────────────────────────────────────────────────────

  log=$(sidecar_mount "$sidecar" /sidecar_shared)
  if [[ -n "$log" && -r "$log/connections.jsonl" ]]; then
    # In flight is opens minus closes, not opens minus allows: a record written
    # before open/close events existed has no "ev" at all, and counting those as
    # closes would report a negative or phantom backlog.
    counts=$(awk '
      /"ev":"open"/ { opens++; next }
      {
        if (/"ev":"close"/)      closes++
        if (/"verdict":"allow"/) ok++
        else if (/"verdict":"deny"/)  deny++
        else if (/"verdict":"error"/) err++
      }
      END {
        live = opens - closes
        if (live < 0) live = 0
        printf "%d %d %d %d", ok+0, deny+0, err+0, live
      }
    ' "$log/connections.jsonl")
    read -r ok deny err live <<< "$counts"
    summary="$ok connection(s)"
    [[ "$deny" -gt 0 ]] && summary+=", $deny denied"
    [[ "$err" -gt 0 ]] && summary+=", $err failed"
    [[ "$live" -gt 0 ]] && summary+=", $live in flight"
    row network "$summary        agent-sandbox-ctl net"
    row log "                         agent-sandbox-ctl logs"
  fi
fi

# ── ports ───────────────────────────────────────────────────────────────────

published=$(podman port "$sandbox" 2>/dev/null | tr '\n' ' ' || true)
forwarded=$(podman ps --filter "label=agent-sandbox.role=port-forward" \
                      --filter "label=agent-sandbox.target=$sandbox" \
                      --format '{{.Names}}' 2>/dev/null | wc -l)
if [[ -n "${published// /}" || "$forwarded" -gt 0 ]]; then
  detail="${published:-}"
  [[ "$forwarded" -gt 0 ]] && detail+="($forwarded forwarder(s))"
  row ports "$detail        agent-sandbox-ctl ports ls"
else
  row ports "none published        agent-sandbox-ctl ports add"
fi
