#!/usr/bin/env bash
# Inspect and change the firewall policy of a running sandbox.
#
# Authority is host-side by construction: the policy lives on a directory mounted
# read-only into the proxy sidecar and not mounted into the sandbox at all, so the
# agent cannot widen the firewall that contains it.  (That is why the old
# in-container `agent-sandbox-allow` is gone rather than repaired.)
#
# Every write is validated by the proxy binary itself -- the same build the
# sidecar runs -- and installed by an atomic rename, so a running proxy can never
# read a half-written or invalid policy.  The proxy notices the change within a
# second; nothing here has to talk to it.

prog="agent-sandbox-ctl proxy"

usage() {
  cat <<USAGE
$prog show   [WORD] [--sandbox WORD]
$prog allow  [WORD] [--sandbox WORD] ENTRY...
$prog deny   [WORD] [--sandbox WORD] ENTRY...
$prog rm     [WORD] [--sandbox WORD] ENTRY...
$prog reset  [WORD] [--sandbox WORD]
$prog export [WORD] [--sandbox WORD]

  show    the rules in force, and which came from AGENTS.md
  allow   permit a domain or IP, from now on
  deny    block a domain or IP, from now on
  rm      drop an entry from both lists
  reset   discard runtime changes and restore the AGENTS.md policy
  export  print the [proxy] section as AGENTS.md TOML, omitting the baseline
          private/loopback denials every sandbox gets regardless of policy

ENTRY is a domain (github.com, *.github.com), an address or CIDR block
(10.0.0.0/8, 8.8.8.8), or a port or port range (443, 8000-8100); which one is
inferred and printed back.  Ports are not scoped to a host and have no deny
form -- allow_ports is a global restriction, so "deny" refuses a port entry.

Changes apply to new connections within a second.  Connections already
established are not re-checked -- end the session to cut those.
USAGE
}

action="${1:-}"
# Before the flag loop, which never sees the first word.
case "$action" in
  "")             usage >&2; exit 1 ;;
  -h|--help|help) usage; exit 0 ;;
esac
shift

sandbox_name=""
entries=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sandbox)
      shift
      [[ $# -gt 0 ]] || { echo "$prog: --sandbox needs a name" >&2; exit 1; }
      sandbox_name="$1"
      ;;
    --sandbox=*) sandbox_name="${1#--sandbox=}" ;;
    -h|--help)   usage; exit 0 ;;
    -*)          echo "$prog: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)           entries+=("$1") ;;
  esac
  shift
done

if [[ -n "$sandbox_name" && ! "$sandbox_name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
  echo "$prog: invalid sandbox name: $sandbox_name" >&2
  exit 1
fi

# Domain or address?  Sniffing is only safe because the verdict is printed back
# and anything unrecognisable is refused rather than guessed at.
classify() {
  local entry="$1"
  if [[ "$entry" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] \
     || [[ "$entry" == *:* ]]; then
    printf 'ips\n'
  elif [[ "$entry" =~ ^[0-9]{1,5}(-[0-9]{1,5})?$ ]]; then
    printf 'ports\n'
  elif [[ "$entry" =~ ^(\*\.)?[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$ ]]; then
    printf 'domains\n'
  else
    return 1
  fi
}

# Write a candidate policy from stdin, but only if the proxy accepts it.
#
# The validator is the proxy binary, so the rules that decide what is installable
# are exactly the rules that decide what is enforceable -- there is no second
# implementation to drift.  The rename is atomic within the directory, which is
# why the *directory* is the bind mount: a single-file mount would keep the old
# inode and the proxy would never see the change.
install_policy() {
  local dir="$1"
  cat > "$dir/.policy.new"
  if ! agent-sandbox-proxy --check-policy "$dir/.policy.new" >/dev/null; then
    rm -f "$dir/.policy.new"
    echo "$prog: refusing to install an invalid policy" >&2
    exit 1
  fi
  mv "$dir/.policy.new" "$dir/policy"
}

sandbox=$(resolve_sandbox "$sandbox_name" --running)
sidecar=$(require_sidecar "$sandbox")

policy_dir=$(sidecar_mount "$sidecar" /sidecar_policy)
if [[ -z "$policy_dir" || ! -d "$policy_dir" ]]; then
  echo "$prog: cannot find the policy directory of $sidecar" >&2
  echo "               (it was launched by an older agent-sandbox)" >&2
  exit 1
fi
policy="$policy_dir/policy"
base="$policy_dir/policy.base"

# Copy a policy to stdout, dropping every allow_*/deny_* rule whose value is one
# of the given entries; sets FILTERED_COUNT to how many were dropped.
#
# String comparison, never a regex: entries legitimately contain '*' and '.',
# which a grep pattern would treat as metacharacters.
FILTERED_COUNT=0
filter_out_entries() {
  local file="$1"
  shift
  local drop=("$@") line key value entry keep
  FILTERED_COUNT=0
  while IFS= read -r line; do
    key="${line%% *}"
    value="${line#* }"
    keep=1
    case "$key" in
      allow_*|deny_*)
        for entry in "${drop[@]}"; do
          if [[ "$value" == "$entry" ]]; then
            keep=0
            FILTERED_COUNT=$((FILTERED_COUNT + 1))
          fi
        done
        ;;
    esac
    if [[ "$keep" == 1 ]]; then
      printf '%s\n' "$line"
    fi
  done < "$file"
}

need_entries() {
  if [[ ${#entries[@]} -eq 0 ]]; then
    echo "$prog: $action needs at least one domain or address" >&2
    usage >&2
    exit 1
  fi
}

case "$action" in
  show|ls|list)
    if [[ ${#entries[@]} -eq 1 ]]; then
      if [[ -n "$sandbox_name" ]]; then
         echo "$prog: cannot specify both --sandbox and a positional sandbox name" >&2; exit 1
      fi
      sandbox_name="${entries[0]}"
      entries=()
    elif [[ ${#entries[@]} -gt 1 ]]; then
      echo "$prog: show takes at most one argument (the sandbox)" >&2; exit 1
    fi
    printf '%s\n' "$sandbox"
    printf '  policy      %s\n' "$policy"

    # (domains|ips) only: allow_ports alone does not make the policy
    # deny-by-default -- only allow_domains/allow_ips do.
    if grep -qE '^allow_(domains|ips) ' "$policy" 2>/dev/null; then
      printf '  default     deny  (only the rules below are reachable)\n'
    else
      printf '  default     allow  (no allow rules declared, so every host is reachable)\n'
    fi
    if grep -q '^default ' "$policy" 2>/dev/null; then
      printf '  default     %s  (set explicitly)\n' \
        "$(awk '$1 == "default" { print $2 }' "$policy" | tail -n 1)"
    fi

    # Runtime additions are the difference from the pristine AGENTS.md policy.
    while read -r key value _rest; do
      [[ -n "${key:-}" && "$key" != "#"* ]] || continue
      [[ "$key" == "default" ]] && continue
      origin="AGENTS.md"
      if [[ -f "$base" ]] && ! grep -qxF "$key $value" "$base"; then
        origin="added at runtime"
      fi
      printf '  %-14s%-34s%s\n' "$key" "$value" "$origin"
    done < "$policy"

    if ! grep -qE '^(allow|deny)_' "$policy" 2>/dev/null; then
      printf '  (no rules)\n'
    fi

    # Only meaningful for connections that are still open; the count is free.
    log_dir=$(sidecar_mount "$sidecar" /sidecar_shared)
    if [[ -n "$log_dir" && -r "$log_dir/connections.jsonl" ]]; then
      live=$(awk '
        /"ev":"open"/  { opens++ }
        /"ev":"close"/ { closes++ }
        END { live = opens - closes; print (live > 0 ? live : 0) }
      ' "$log_dir/connections.jsonl")
      if [[ "${live:-0}" -gt 0 ]]; then
        printf '\n  note: %s connection(s) are already open and are not re-checked;\n' "$live"
        printf '        end the session to cut those.\n'
      fi
    fi
    ;;

  allow|deny)
    if [[ -z "$sandbox_name" && ${#entries[@]} -gt 0 ]]; then
      if sandbox_running "${entries[0]}"; then
        sandbox_name="${entries[0]}"
        entries=("${entries[@]:1}")
      fi
    fi
    need_entries
    list_prefix="allow"
    [[ "$action" == "deny" ]] && list_prefix="deny"

    added=()
    for entry in "${entries[@]}"; do
      if ! kind=$(classify "$entry"); then
        echo "$prog: not a domain or address: $entry" >&2
        exit 1
      fi
      added+=("${list_prefix}_${kind} $entry")
    done

    # Existing rules for the same entry are dropped first, so allowing something
    # that is currently denied reads as a change rather than leaving two
    # contradictory rules for the specificity tie-break to settle.
    filter_out_entries "$policy" "${entries[@]}" > "$policy_dir/.policy.next"
    printf '%s\n' "${added[@]}" >> "$policy_dir/.policy.next"
    install_policy "$policy_dir" < "$policy_dir/.policy.next"
    rm -f "$policy_dir/.policy.next"

    verb=allowed
    [[ "$action" == "deny" ]] && verb=denied
    for rule in "${added[@]}"; do
      key="${rule%% *}"
      # The inferred kind is printed, not just used: sniffing domain-vs-address
      # is only safe if the user can see what it decided.
      printf '  %-12s%-34s%s\n' "$verb" "${rule#* }" "${key#*_}"
    done
    printf '  %-12s%s\n' "reloading" "the proxy applies this within a second"
    ;;

  rm|remove)
    if [[ -z "$sandbox_name" && ${#entries[@]} -gt 0 ]]; then
      if sandbox_running "${entries[0]}"; then
        sandbox_name="${entries[0]}"
        entries=("${entries[@]:1}")
      fi
    fi
    need_entries
    filter_out_entries "$policy" "${entries[@]}" > "$policy_dir/.policy.next"

    if [[ "$FILTERED_COUNT" -eq 0 ]]; then
      rm -f "$policy_dir/.policy.next"
      echo "$prog: no rule matches: ${entries[*]}" >&2
      exit 1
    fi

    install_policy "$policy_dir" < "$policy_dir/.policy.next"
    rm -f "$policy_dir/.policy.next"
    printf '  %-12s%s rule(s)\n' removed "$FILTERED_COUNT"
    printf '  %-12s%s\n' "reloading" "the proxy applies this within a second"
    ;;

  reset)
    if [[ ${#entries[@]} -eq 1 ]]; then
      if [[ -n "$sandbox_name" ]]; then
         echo "$prog: cannot specify both --sandbox and a positional sandbox name" >&2; exit 1
      fi
      sandbox_name="${entries[0]}"
      entries=()
    elif [[ ${#entries[@]} -gt 1 ]]; then
      echo "$prog: reset takes at most one argument (the sandbox)" >&2; exit 1
    fi
    if [[ ! -f "$base" ]]; then
      echo "$prog: no baseline policy to restore" >&2
      exit 1
    fi
    # Restores the declared policy rather than emptying it: an empty policy is
    # allow-everything for a deny-only ruleset, which is the opposite of what
    # "reset" suggests.
    install_policy "$policy_dir" < "$base"
    printf '  %-12s%s\n' restored "the [proxy] policy from AGENTS.md"
    ;;

  export)
    if [[ ${#entries[@]} -eq 1 ]]; then
      if [[ -n "$sandbox_name" ]]; then
         echo "$prog: cannot specify both --sandbox and a positional sandbox name" >&2; exit 1
      fi
      sandbox_name="${entries[0]}"
      entries=()
    elif [[ ${#entries[@]} -gt 1 ]]; then
      echo "$prog: export takes at most one argument (the sandbox)" >&2; exit 1
    fi

    # Baseline entries (always enforced regardless of AGENTS.md) are omitted
    # from the export so the output round-trips cleanly.  Falls back to
    # /dev/null when the sidecar predates policy.baseline.
    baseline_file="${policy_dir}/policy.baseline"
    [[ -f "$baseline_file" ]] || baseline_file="/dev/null"
    proxy_toml=$(awk -v baseline="$baseline_file" '
      BEGIN {
        while ((getline line < baseline) > 0) {
          split(line, a, " "); skip[a[1]" "a[2]] = 1
        }
        close(baseline)
      }
      $1 ~ /^(allow_domains|deny_domains|allow_ips|deny_ips|allow_ports)$/ {
        if (!skip[$1" "$2])
          list[$1] = list[$1] "\"" $2 "\", "
      }
      $1 == "default" { def = $2 }
      END {
        for (k in list) {
          val = list[k]
          sub(/, $/, "", val)
          print k " = [" val "]"
        }
        if (def != "") print "default = \"" def "\""
      }
    ' "$policy")

    if [[ -n "$proxy_toml" ]]; then
      echo '```toml agent-sandbox'
      echo "[proxy]"
      echo "$proxy_toml"
      echo '```'
    fi
    ;;

  *)
    echo "$prog: unknown command '$action'" >&2
    usage >&2
    exit 1
    ;;
esac
