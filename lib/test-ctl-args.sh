#!/usr/bin/env bash
# Behavioural tests for the agent-sandbox-ctl subcommands, against a stub podman.
#
# Podman cannot run in a nix build (nor in most CI), but almost every bug these
# scripts have had is in argument handling and container selection, which do not
# need a real container -- only believable answers to `podman ps` / `podman
# inspect`.  The stub answers from fixtures and records its own argv, so a test
# can assert both what the script decided and that it did not touch anything it
# should not have.
#
# The scripts are composed here the same way default.nix composes them (preamble
# + shared resolve helper + body) rather than run from the built store paths:
# writeShellApplication PREPENDS its runtimeInputs to PATH, so a built script
# always finds the real podman and a stub could never take effect.  The
# composition itself is covered by checks.scripts, which shellchecks the
# generated text.
#
# Usage: test-ctl-args.sh LIB_DIR [PROXY_BIN]
#
# PROXY_BIN is the policy validator the firewall command shells out to; the
# firewall tests are skipped without it.

set -euo pipefail

lib="${1:?usage: test-ctl-args.sh LIB_DIR [PROXY_BIN]}"
proxy_bin="${2:-}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

# /usr/bin/env does not exist inside a nix build, so every generated script gets
# the interpreter this test is running under.
bash_bin="${BASH:-$(command -v bash)}"

# Mirror default.nix: preamble, then the inlined resolve helper, then the body.
compose() { # name source...
  local out="$tmp/bin/$1"
  shift
  {
    printf '#!%s\n' "$bash_bin"
    printf 'AGENT_SANDBOX_IMAGE="localhost/agent-sandbox:latest"\n'
    printf 'AGENT_SANDBOX_NETWORK="agent-sandbox"\n'
    printf 'AGENT_SANDBOX_KRUN_RUNTIME="%s"\n' "$tmp/bin/krun-stub"
    local src
    for src in "$@"; do
      tail -n +2 "$lib/$src"   # strip the shebang, as scriptBody does
    done
  } > "$out"
  chmod +x "$out"
}

compose agent-sandbox-port   agent-sandbox-resolve.sh agent-sandbox-port.sh
compose agent-sandbox-mount  agent-sandbox-resolve.sh agent-sandbox-mount.sh
compose agent-sandbox-net    agent-sandbox-resolve.sh agent-sandbox-net.sh
compose agent-sandbox-logs   agent-sandbox-resolve.sh agent-sandbox-logs.sh
compose agent-sandbox-status agent-sandbox-resolve.sh agent-sandbox-status.sh
compose agent-sandbox-load   agent-sandbox-load.sh
compose agent-sandbox-firewall agent-sandbox-resolve.sh agent-sandbox-firewall.sh
compose agent-sandbox-attach agent-sandbox-resolve.sh agent-sandbox-attach.sh
compose agent-sandbox-purge  agent-sandbox-purge.sh
purge_bin="$tmp/bin/agent-sandbox-purge"
# The launcher, for --krun flag handling.  Everything asserted below refuses
# during the preflight, which runs before the AGENTS.md and gnupg machinery.
compose agent-sandbox        agent-sandbox.sh
launcher_bin="$tmp/bin/agent-sandbox"

# Stands in for `crun --version`.  The real preflight greps for +LIBKRUN, so the
# stub can flip that answer without a crun anywhere near the build.
{ printf '#!%s\n' "$bash_bin"
  printf 'echo "crun version 1.27.1"\n'
  printf 'echo "spec: 1.0.0"\n'
  # Single-quoted on purpose: the parameter expansion belongs to the stub, and
  # has to survive being written into it rather than expanding here.
  # shellcheck disable=SC2016
  printf 'echo "+SYSTEMD +SELINUX +SECCOMP ${KRUN_STUB_LIBKRUN:-+LIBKRUN} +YAJL"\n'
} > "$tmp/bin/krun-stub"
chmod +x "$tmp/bin/krun-stub"
# Standalone: list reads its labels with `podman inspect` rather than composing
# the resolve helper.
compose agent-sandbox-list   agent-sandbox-list.sh
list_bin="$tmp/bin/agent-sandbox-list"
# net shells out to the renderer, so it has to be on PATH like the rest.
compose agent-sandbox-network-summary agent-sandbox-network-summary.sh
firewall_bin="$tmp/bin/agent-sandbox-firewall"
# The firewall command validates with the real proxy binary, so it has to be on
# PATH next to the stub podman.
[[ -n "$proxy_bin" ]] && ln -sf "$proxy_bin" "$tmp/bin/agent-sandbox-proxy"

port_bin="$tmp/bin/agent-sandbox-port"
net_bin="$tmp/bin/agent-sandbox-net"
logs_bin="$tmp/bin/agent-sandbox-logs"
status_bin="$tmp/bin/agent-sandbox-status"
load_bin="$tmp/bin/agent-sandbox-load"
mount_bin="$tmp/bin/agent-sandbox-mount"
attach_bin="$tmp/bin/agent-sandbox-attach"

failures=0

# ── the stub ────────────────────────────────────────────────────────────────
# Fixture protocol, all under $tmp/fixture:
#   running       newline-separated names of running sandboxes
#   all           newline-separated names of all sandboxes (defaults to running)
#   forwarders    newline-separated forwarder names
#   labels.<name> KEY=VALUE lines, answering inspect --format '{{index .Config.Labels "KEY"}}'
#   exists        newline-separated names for which `container exists` is true
# Every invocation is appended to $tmp/argv.
{ printf '#!%s\n' "$bash_bin"; cat <<'STUB'
f="$FIXTURE"
printf '%s\n' "$*" >> "$ARGV_LOG"

fixture() { [[ -f "$f/$1" ]] && cat "$f/$1" || true; }

case "$1" in
  ps)
    all=0; labels=(); want_name=""; want_status=""; want_row=0
    for a in "$@"; do
      case "$a" in
        -a|--all) all=1 ;;
        label=*)  labels+=("${a#label=}") ;;
        name=*)   want_name="${a#name=}" ;;
        status=*) want_status="${a#status=}" ;;
        # The multi-column row format agent-sandbox-list asks for, as opposed to
        # the bare '{{.Names}}' every other caller uses.
        *'{{.ID}}'*) want_row=1 ;;
      esac
    done

    emit() { # name
      if [[ "$want_row" == 1 ]]; then
        printf '%s\t%s\t%s\n' "id-$1" "$1" "Up 2 minutes"
      else
        printf '%s\n' "$1"
      fi
    }
    src=running
    [[ "$all" == 1 && -f "$f/all" ]] && src=all
    # A status filter selects from its own fixture, so "exited" does not silently
    # match everything.
    [[ -n "$want_status" ]] && src="status.$want_status"

    role=""; target=""; workspace=""
    for l in ${labels[@]+"${labels[@]}"}; do
      case "$l" in
        agent-sandbox.role=*)      role="${l#agent-sandbox.role=}" ;;
        agent-sandbox.target=*)    target="${l#agent-sandbox.target=}" ;;
        agent-sandbox.workspace=*) workspace="${l#agent-sandbox.workspace=}" ;;
      esac
    done

    case "$role" in
      port-forward)
        while IFS= read -r n; do
          [[ -n "$n" ]] || continue
          if [[ -n "$target" ]]; then
            [[ "$(fixture "labels.$n" | sed -n 's/^agent-sandbox\.target=//p')" == "$target" ]] || continue
          fi
          if [[ -n "$want_name" ]]; then
            # podman's name filter is a regex; ^...$ anchors are common here.
            [[ "$n" =~ ${want_name} ]] || continue
          fi
          emit "$n"
        done < <(fixture forwarders)
        ;;
      proxy)
        while IFS= read -r n; do
          [[ -n "$n" ]] || continue
          if [[ -n "$target" ]]; then
            [[ "$(fixture "labels.$n" | sed -n 's/^agent-sandbox\.target=//p')" == "$target" ]] || continue
          fi
          emit "$n"
        done < <(fixture sidecars)
        ;;
      *)
        while IFS= read -r n; do
          [[ -n "$n" ]] || continue
          if [[ -n "$workspace" ]]; then
            [[ "$(fixture "labels.$n" | sed -n 's/^agent-sandbox\.workspace=//p')" == "$workspace" ]] || continue
          fi
          emit "$n"
        done < <(fixture "$src")
        ;;
    esac
    ;;
  inspect)
    # ${!#} is the last positional: the container.  Not ${*##* }, which applies
    # the pattern to each argument separately.
    name="${!#}"
    all="$*"
    key=$(sed -n 's/.*Config.Labels "\([^"]*\)".*/\1/p' <<< "$all")
    dest=$(sed -n 's/.*eq .Destination "\([^"]*\)".*/\1/p' <<< "$all")
    if [[ -n "$key" ]]; then
      fixture "labels.$name" | sed -n "s|^${key}=||p"
    elif [[ -n "$dest" ]]; then
      fixture "mount.$name${dest//\//.}"
    elif [[ "$all" == *NetworkSettings.Networks* ]]; then
      fixture "networks.$name"
    elif [[ "$all" == *State.Running* ]]; then
      grep -qxF "$name" <(fixture running) && echo true || echo false
    fi
    ;;
  container)
    [[ "$2" == exists ]] || exit 0
    grep -qxF "$3" <(fixture exists) || grep -qxF "$3" <(fixture all) \
      || grep -qxF "$3" <(fixture running) || grep -qxF "$3" <(fixture forwarders)
    ;;
  port|logs|load|rm|network|run|exec) exit 0 ;;
  *) exit 0 ;;
esac
STUB
} > "$tmp/bin/podman"
chmod +x "$tmp/bin/podman"

# ── harness ─────────────────────────────────────────────────────────────────

fixture_reset() {
  rm -rf "$tmp/fixture"
  mkdir -p "$tmp/fixture"
}

fixture_set() { printf '%s\n' "${@:2}" > "$tmp/fixture/$1"; }

# run LABEL BIN ARGS...  -> populates $status, $output, $argv
run() {
  : > "$tmp/argv"
  status=0
  output=$(FIXTURE="$tmp/fixture" ARGV_LOG="$tmp/argv" PATH="$tmp/bin:$PATH" \
           "$@" 2>&1) || status=$?
  argv=$(cat "$tmp/argv")
}

pass() { printf 'ok       %s\n' "$1"; }
fail() {
  printf 'FAIL     %s\n' "$1"
  printf '%s\n' "${2:-}" | sed 's/^/           /'
  failures=$((failures + 1))
}

expect_status() {
  local label="$1" want="$2"
  if [[ "$status" == "$want" ]]; then
    pass "$label"
  else
    fail "$label" "exit $status, wanted $want"$'\n'"$output"
  fi
}

expect_out() {
  local label="$1" want="$2"
  if grep -qF -- "$want" <<< "$output"; then
    pass "$label"
  else
    fail "$label" "missing: $want"$'\n'"$output"
  fi
}

expect_no_argv() {
  local label="$1" unwanted="$2"
  if grep -qF -- "$unwanted" <<< "$argv"; then
    fail "$label" "podman was called with: $unwanted"$'\n'"$argv"
  else
    pass "$label"
  fi
}

# ── load ────────────────────────────────────────────────────────────────────

fixture_reset
run "$load_bin" --help
expect_status "load --help exits 0" 0
expect_out    "load --help prints usage" "Usage: agent-sandbox-ctl load"
expect_no_argv "load --help does not import the image" "load"

run "$load_bin" typo
expect_status "load rejects an argument" 1
expect_no_argv "load typo does not import the image" "load"

# ── port rm against a STOPPED sandbox (the resolve_sandbox regression) ───────

fixture_reset
fixture_set running
fixture_set all "agent-sandbox-repo-1"
fixture_set forwarders "agent-sandbox-fwd-repo-1-8080"
fixture_set "labels.agent-sandbox-fwd-repo-1-8080" \
  "agent-sandbox.target=agent-sandbox-repo-1"

run "$port_bin" rm --sandbox agent-sandbox-repo-1 8080
expect_status "port rm works on a stopped sandbox" 0
expect_out    "port rm removes the forwarder" "removed agent-sandbox-fwd-repo-1-8080"

# ── port add requires a RUNNING sandbox ─────────────────────────────────────

run "$port_bin" add --sandbox agent-sandbox-repo-1 8080
expect_status "port add refuses a stopped sandbox" 1
expect_out    "port add says why" "is not running"

# ── port add must not weaken a proxied sandbox ──────────────────────────────
# The important half of this is the argv assertion: refusing is only useful if it
# happens before podman is asked to create or join a network.

fixture_reset
fixture_set running "agent-sandbox-fw-1"
fixture_set "labels.agent-sandbox-fw-1" "agent-sandbox.proxy=proxy"

run "$port_bin" add --sandbox agent-sandbox-fw-1 8080
expect_status  "port add refuses a proxied sandbox" 1
expect_out     "port add explains the egress risk" "does not pass through the proxy"
expect_no_argv "port add creates no network" "network create"
expect_no_argv "port add joins no network" "network connect"
expect_no_argv "port add starts no forwarder" "run --detach"

# A sandbox from before the label still has the shared mount to give it away.
fixture_set "labels.agent-sandbox-fw-1" "agent-sandbox.proxy="
fixture_set "mount.agent-sandbox-fw-1.sidecar_shared" "/tmp/whatever"
run "$port_bin" add --sandbox agent-sandbox-fw-1 8080
expect_status "port add falls back to the shared mount" 1

# And an unproxied sandbox is still allowed through.
fixture_reset
fixture_set running "agent-sandbox-plain-1"
fixture_set "labels.agent-sandbox-plain-1" "agent-sandbox.proxy=off"
run "$port_bin" add --sandbox agent-sandbox-plain-1 8080
expect_status "port add still works without a proxy" 0
if grep -qF -- "--name agent-sandbox-fwd-plain-1-8080" <<< "$argv"; then
  pass "port add does not duplicate the sandbox prefix"
else
  fail "port add does not duplicate the sandbox prefix" "$argv"
fi

# ── port ls ─────────────────────────────────────────────────────────────────

fixture_reset
fixture_set running "agent-sandbox-repo-1"
fixture_set forwarders "agent-sandbox-fwd-ghost-9000"
fixture_set "labels.agent-sandbox-fwd-ghost-9000" "agent-sandbox.target=ghost"

run "$port_bin" ls 8080 8081
expect_status "port ls rejects two positionals" 1
expect_out    "port ls says why" "ls takes at most one argument"

run "$port_bin" ls
expect_status "port ls succeeds" 0
expect_out    "port ls reports orphaned forwarders" "orphaned forwarders"

# ── port export ─────────────────────────────────────────────────────────────

run "$port_bin" export
expect_status "port export succeeds" 0

run "$port_bin" export one two
expect_status "port export rejects two positionals" 1
expect_out    "port export says why" "export takes at most one argument"

# ── mounts ──────────────────────────────────────────────────────────────────

run "$mount_bin" ls one two
expect_status "mounts ls rejects two positionals" 1
expect_out    "mounts ls says why" "ls takes at most one argument"

run "$mount_bin" add only-one
expect_status "mounts add rejects one positional" 1
expect_out    "mounts add says why" "add needs HOST_PATH CONTAINER_PATH"

run "$mount_bin" rm
expect_status "mounts rm rejects empty input" 1
expect_out    "mounts rm says why" "rm needs CONTAINER_PATH"

run "$mount_bin" --sandbox s1 1 2 3
expect_status "mounts add rejects --sandbox and 3 positionals" 1
expect_out    "mounts add says why" "cannot specify both --sandbox and a positional sandbox name"

run "$mount_bin" 1 2 3 4
expect_status "mounts legacy add rejects 4 positionals" 1
expect_out    "mounts legacy add says why" "expected [SANDBOX] HOST_PATH CONTAINER_PATH"

run "$mount_bin" --sandbox agent-sandbox-plain-1 /does-not-exist /container/path
expect_status "mounts add rejects missing host path" 1
expect_out    "mounts add says why" "does not exist or is not a directory"

tmp_mount_src="$tmp/mount-src"
mkdir -p "$tmp_mount_src"
run "$mount_bin" add --sandbox agent-sandbox-repo-1 "$tmp_mount_src" /container/path
expect_status "mounts add succeeds" 0
expect_out    "mounts add confirms mount" "Mounted"

run "$mount_bin" rm --sandbox agent-sandbox-repo-1 /container/path
expect_status "mounts rm succeeds" 0
expect_out    "mounts rm confirms unmount" "Unmounted"

# ── mounts export ───────────────────────────────────────────────────────────

run "$mount_bin" export
expect_status "mounts export succeeds" 0

run "$mount_bin" export one two
expect_status "mounts export rejects two positionals" 1
expect_out    "mounts export says why" "export takes at most one argument"

# ── net argument handling ───────────────────────────────────────────────────

fixture_reset
fixture_set running "agent-sandbox-repo-1"

run "$net_bin" --sandbox --follow
expect_status "net rejects a flag as a sandbox name" 1
expect_out    "net names the bad value" "invalid sandbox name"

run "$net_bin" --sandbox
expect_status "net rejects an empty --sandbox" 1
expect_out    "net says --sandbox needs a name" "--sandbox needs a name"

run "$net_bin" --nope
expect_status "net rejects an unknown flag" 1

run "$net_bin" stray extra
expect_status "net rejects a second positional" 1

# The metering log lives only in the sidecar now, so that the sandbox cannot
# rewrite the record of its own traffic.
fixture_reset
fixture_set running "agent-sandbox-repo-1"
run "$net_bin"
expect_status "net refuses a sandbox with no proxy" 1

fixture_set sidecars "agent-sandbox-sidecar-abc123"
fixture_set "labels.agent-sandbox-sidecar-abc123" "agent-sandbox.target=agent-sandbox-repo-1"
run "$net_bin"
expect_status "net succeeds with a sidecar" 0
if grep -qE "exec agent-sandbox-sidecar-abc123 cat" <<< "$argv"; then
  pass "net reads the log from the sidecar"
else
  fail "net reads the log from the sidecar" "$argv"
fi
if grep -qE "exec agent-sandbox-repo-1 " <<< "$argv"; then
  fail "net never reads the log from the sandbox" "$argv"
else
  pass "net never reads the log from the sandbox"
fi

# ── logs: sidecar discovery is by label ─────────────────────────────────────

fixture_reset
fixture_set running "agent-sandbox-repo-1"
fixture_set "labels.agent-sandbox-repo-1" "agent-sandbox.proxy=off"

run "$logs_bin"
expect_status "logs refuses a sandbox with no proxy" 1
expect_out    "logs says how to get one" "Relaunch it with"
expect_no_argv "logs does not try to read a log" "logs"

fixture_set sidecars "agent-sandbox-sidecar-abc123"
fixture_set "labels.agent-sandbox-sidecar-abc123" "agent-sandbox.target=agent-sandbox-repo-1"
fixture_set "labels.agent-sandbox-repo-1" "agent-sandbox.proxy=proxy"

run "$logs_bin"
expect_status "logs finds the sidecar by label" 0

run "$logs_bin" --tail nope
expect_status "logs validates --tail" 1
expect_out    "logs says what --tail wants" "needs a line count"

run "$logs_bin" --sandbox --follow
expect_status "logs rejects a flag as a sandbox name" 1

# ── status ──────────────────────────────────────────────────────────────────

# Give the sidecar real policy and log directories, so status has to find them
# the way it does in practice: through the sidecar's bind mounts.
mkdir -p "$tmp/policy" "$tmp/shared"
printf 'allow_domains github.com\nallow_ips 10.0.0.0/8\n' > "$tmp/policy/policy"
{
  printf '{"ts":1,"host":"github.com","port":443,"verdict":"allow","up":1,"down":2,"ms":3}\n'
  printf '{"ts":2,"host":"blocked.example.com","port":443,"verdict":"deny","up":0,"down":0,"ms":1}\n'
  printf '{"ev":"open","id":"1-9","ts":3,"host":"live.example.com","port":443}\n'
} > "$tmp/shared/connections.jsonl"
fixture_set "mount.agent-sandbox-sidecar-abc123.sidecar_policy" "$tmp/policy"
fixture_set "mount.agent-sandbox-sidecar-abc123.sidecar_shared" "$tmp/shared"

run "$status_bin"
expect_status "status succeeds" 0
expect_out    "status names the sandbox"  "1"
expect_out    "status reports proxy mode" "on  (agent-sandbox-sidecar-abc123)"
expect_out    "status counts the policy rules" "2 rule(s), default deny"
expect_out    "status counts traffic" "1 connection(s), 1 denied"
expect_out    "status counts what is in flight" "in flight"
expect_out    "status points at the detail commands" "agent-sandbox-ctl net"

run "$status_bin" stray extra
expect_status "status rejects a second positional" 1

run "$status_bin" agent-sandbox-repo-1
expect_status "status accepts sandbox as positional" 0
expect_out    "status names the sandbox"  "1"

# New sandboxes expose only their session word to users. Resolution
# must still pass the full Podman name to every operation.
fixture_reset
fixture_set running "agent-sandbox-repo-silent"
fixture_set all "agent-sandbox-repo-silent"
fixture_set "labels.agent-sandbox-repo-silent" \
  "agent-sandbox.workspace=$PWD" "agent-sandbox.proxy=off"
run "$status_bin" silent
expect_status "status accepts a session word" 0
expect_out    "status displays the session word" "silent"
if grep -qF "name=^agent-sandbox-repo-silent\$" <<< "$argv"; then
  pass "status resolves the word to the full container name"
else
  fail "status resolves the word to the full container name" "$argv"
fi

fixture_reset
fixture_set running "agent-sandbox-repo-silent" "agent-sandbox-other-silent"
fixture_set all "agent-sandbox-repo-silent" "agent-sandbox-other-silent"
fixture_set "labels.agent-sandbox-repo-silent" "agent-sandbox.workspace=$PWD"
fixture_set "labels.agent-sandbox-other-silent" "agent-sandbox.workspace=/other"
run "$status_bin" --sandbox silent
expect_status "duplicate session words are rejected" 1
expect_out    "duplicate session words explain the ambiguity" "is ambiguous"
expect_out    "duplicate session words list full names" "agent-sandbox-other-silent"

# ── firewall ────────────────────────────────────────────────────────────────

if [[ -n "$proxy_bin" ]]; then
  fixture_reset
  fixture_set running "agent-sandbox-repo-1"
  fixture_set "labels.agent-sandbox-repo-1" "agent-sandbox.proxy=proxy"
  fixture_set sidecars "agent-sandbox-sidecar-abc123"
  fixture_set "labels.agent-sandbox-sidecar-abc123" "agent-sandbox.target=agent-sandbox-repo-1"

  fw_policy="$tmp/fwpolicy"
  mkdir -p "$fw_policy"
  fixture_set "mount.agent-sandbox-sidecar-abc123.sidecar_policy" "$fw_policy"
  reset_policy() {
    printf 'allow_domains github.com\nallow_ips 10.0.0.0/8\n' > "$fw_policy/policy"
    cp "$fw_policy/policy" "$fw_policy/policy.base"
  }
  reset_policy

  run "$firewall_bin" show
  expect_status "firewall show succeeds" 0
  expect_out    "firewall show lists a rule"  "github.com"
  expect_out    "firewall show names the default" "default"
  expect_out    "firewall show marks provenance" "AGENTS.md"

  run "$firewall_bin" allow api.openai.com
  expect_status "firewall allow succeeds" 0
  expect_out    "firewall allow echoes the classification" "domains"
  if grep -qxF "allow_domains api.openai.com" "$fw_policy/policy"; then
    pass "firewall allow writes the rule"
  else
    fail "firewall allow writes the rule" "$(cat "$fw_policy/policy")"
  fi

  run "$firewall_bin" show
  expect_out "firewall show marks a runtime addition" "added at runtime"

  run "$firewall_bin" allow 10.1.0.0/24
  expect_out "firewall allow classifies a CIDR block" "ips"

  # deny of an already-allowed host must replace, not accumulate.
  reset_policy
  run "$firewall_bin" deny github.com
  expect_status "firewall deny succeeds" 0
  if grep -qxF "allow_domains github.com" "$fw_policy/policy"; then
    fail "firewall deny replaces the allow rule" "$(cat "$fw_policy/policy")"
  else
    pass "firewall deny replaces the allow rule"
  fi

  reset_policy
  run "$firewall_bin" rm github.com
  expect_status "firewall rm succeeds" 0
  if grep -q "github.com" "$fw_policy/policy"; then
    fail "firewall rm drops the rule" "$(cat "$fw_policy/policy")"
  else
    pass "firewall rm drops the rule"
  fi

  run "$firewall_bin" rm nothing.example.com
  expect_status "firewall rm reports an unknown rule" 1

  # reset restores the declared policy rather than emptying it.
  run "$firewall_bin" reset
  expect_status "firewall reset succeeds" 0
  if grep -qxF "allow_domains github.com" "$fw_policy/policy"; then
    pass "firewall reset restores the baseline"
  else
    fail "firewall reset restores the baseline" "$(cat "$fw_policy/policy")"
  fi

  run "$firewall_bin" allow "not a domain"
  expect_status "firewall rejects an unclassifiable entry" 1
  expect_out    "firewall says what it could not classify" "not a domain or address"

  run "$firewall_bin" allow
  expect_status "firewall allow needs an entry" 1

  run "$firewall_bin" bogus
  expect_status "firewall rejects an unknown verb" 1


  # An invalid policy must never be installed, whatever produced it.
  printf 'allow_ips 10.0.0.0/8\n' > "$fw_policy/policy"
  cp "$fw_policy/policy" "$fw_policy/policy.base"
  printf 'garbage line\n' > "$fw_policy/policy.base"
  run "$firewall_bin" reset
  expect_status "an invalid policy is refused" 1
  expect_out    "and says so" "refusing to install an invalid policy"
  if grep -qxF "allow_ips 10.0.0.0/8" "$fw_policy/policy"; then
    pass "the policy in force is left untouched"
  else
    fail "the policy in force is left untouched" "$(cat "$fw_policy/policy")"
  fi
  if [[ -e "$fw_policy/.policy.new" ]]; then
    fail "no half-written policy is left behind" "$fw_policy/.policy.new exists"
  else
    pass "no half-written policy is left behind"
  fi

  # --help must be recognised before the verb is consumed, and must not go
  # looking for a sandbox.
  fixture_reset
  run "$firewall_bin" --help
  expect_status  "firewall --help exits 0" 0
  expect_out     "firewall --help prints usage" "agent-sandbox-ctl proxy show"
  expect_no_argv "firewall --help touches no container" "ps"

  run "$firewall_bin"
  expect_status "firewall with no verb exits 1" 1

  # ── firewall export (agent-sandbox-ctl proxy export) ───────────────────────

  fixture_reset
  fixture_set running "agent-sandbox-repo-1"
  fixture_set "labels.agent-sandbox-repo-1" "agent-sandbox.proxy=proxy"
  fixture_set sidecars "agent-sandbox-sidecar-abc123"
  fixture_set "labels.agent-sandbox-sidecar-abc123" "agent-sandbox.target=agent-sandbox-repo-1"

  fw_policy="$tmp/fwpolicy-export"
  mkdir -p "$fw_policy"
  fixture_set "mount.agent-sandbox-sidecar-abc123.sidecar_policy" "$fw_policy"
  printf 'allow_domains github.com\ndeny_ips 127.0.0.0/8\n' > "$fw_policy/policy"
  printf 'deny_ips 127.0.0.0/8\n' > "$fw_policy/policy.baseline"

  run "$firewall_bin" export
  expect_status "firewall export succeeds" 0
  expect_out    "firewall export fences the block" '```toml agent-sandbox'
  expect_out    "firewall export names the section" "[proxy]"
  expect_out    "firewall export carries a declared rule" "github.com"
  if grep -qF "127.0.0.0" <<< "$output"; then
    fail "firewall export omits the baseline deny_ips" "$output"
  else
    pass "firewall export omits the baseline deny_ips"
  fi

  run "$firewall_bin" export one two
  expect_status "firewall export rejects two positionals" 1
  expect_out    "firewall export says why" "export takes at most one argument"
else
  printf 'skip     firewall tests (no proxy binary given)\n'
fi

# ── purge ───────────────────────────────────────────────────────────────────
# The point of the rework: a live session survives it, and orphans do not.

fixture_reset
fixture_set running "agent-sandbox-live-1"
fixture_set all "agent-sandbox-live-1" "agent-sandbox-dead-2"
fixture_set "status.exited" "agent-sandbox-dead-2"
fixture_set forwarders "agent-sandbox-fwd-ghost-9000"
fixture_set "labels.agent-sandbox-fwd-ghost-9000" "agent-sandbox.target=ghost"
fixture_set sidecars "agent-sandbox-sidecar-orphan"
fixture_set "labels.agent-sandbox-sidecar-orphan" "agent-sandbox.target=ghost"

run "$purge_bin" --dry-run
expect_status  "purge --dry-run succeeds" 0
expect_out     "purge keeps a running sandbox" "Running sandboxes (kept"
expect_out     "purge names the running sandbox" "agent-sandbox-live-1"
expect_out     "purge finds the orphaned forwarder" "agent-sandbox-fwd-ghost-9000"
expect_out     "purge finds the orphaned sidecar" "agent-sandbox-sidecar-orphan"
expect_out     "purge says it would remove" "would remove"
expect_no_argv "purge --dry-run removes nothing" "rm -f"
expect_no_argv "purge --dry-run removes no image" "rmi"

run "$purge_bin" --force
expect_status "purge --force succeeds" 0
if grep -qF "rm -f agent-sandbox-fwd-ghost-9000" <<< "$argv"; then
  pass "purge removes the orphaned forwarder"
else
  fail "purge removes the orphaned forwarder" "$argv"
fi
if grep -qF "rm -f agent-sandbox-live-1" <<< "$argv"; then
  fail "purge does not remove a running sandbox" "$argv"
else
  pass "purge does not remove a running sandbox"
fi

run "$purge_bin" --all --force
if grep -qF "rm -f agent-sandbox-live-1" <<< "$argv"; then
  pass "purge --all removes a running sandbox"
else
  fail "purge --all removes a running sandbox" "$argv"
fi

# `network rm -f` is what used to cut a live session's network out from under it.
if grep -qF "network rm -f" <<< "$argv"; then
  fail "purge never force-removes a network" "$argv"
else
  pass "purge never force-removes a network"
fi

run "$purge_bin" --nope
expect_status "purge rejects an unknown flag" 1

# ── list ────────────────────────────────────────────────────────────────────
#
# The stub cannot reproduce podman's template engine, so these cover selection
# and the label columns, not the format string itself -- the two template bugs
# this command shipped with are only reproducible against a real podman.

fixture_reset
fixture_set running "agent-sandbox-here-1" "agent-sandbox-elsewhere-1"
fixture_set all "agent-sandbox-here-1" "agent-sandbox-elsewhere-1" "agent-sandbox-old-1"
fixture_set "labels.agent-sandbox-here-1" \
  "agent-sandbox.proxy=proxy" "agent-sandbox.workspace=$PWD"
fixture_set "labels.agent-sandbox-elsewhere-1" \
  "agent-sandbox.proxy=off" "agent-sandbox.workspace=/somewhere/else"

run "$list_bin"
expect_status "list succeeds" 0
expect_out    "list heads the workspace" "Agent-sandbox containers for $PWD"
expect_out    "list names the local sandbox" "1"
expect_out    "list shows the proxy label" "proxy"
expect_out    "list shows the workspace label" "$PWD"
if grep -qF "agent-sandbox-elsewhere-1" <<< "$output"; then
  fail "list hides sandboxes from another workspace" "$output"
else
  pass "list hides sandboxes from another workspace"
fi

run "$list_bin" --all
expect_status "list --all succeeds" 0
expect_out    "list --all spans workspaces" "agent-sandbox-elsewhere-1"
expect_out    "list --all shows the other proxy mode" "off"
if grep -qF -- "-a" <<< "$argv"; then
  pass "list --all asks podman for stopped containers"
else
  fail "list --all asks podman for stopped containers" "$argv"
fi

# A sandbox predating the proxy label must not shift the workspace column.
# The runtime column is the one exception that still renders: a container older
# than that label can only have been started by a launcher that had no --krun,
# so "crun" is a fact about it rather than a guess.
run "$list_bin" --all
if grep -qE '1 +Up 2 minutes +crun *$' <<< "$output"; then
  pass "list tolerates a container with no labels"
else
  fail "list tolerates a container with no labels" "$output"
fi

fixture_set sidecars "agent-sandbox-proxy-agent-sandbox-here-1"
fixture_set forwarders "agent-sandbox-fwd-here-1-8080"
fixture_set "labels.agent-sandbox-proxy-agent-sandbox-here-1" \
  "agent-sandbox.target=agent-sandbox-here-1"
fixture_set "labels.agent-sandbox-fwd-here-1-8080" \
  "agent-sandbox.target=agent-sandbox-here-1"

run "$list_bin" --roles
expect_status "list --roles succeeds" 0
expect_out    "list --roles lists the sidecar" "agent-sandbox-proxy-agent-sandbox-here-1"
expect_out    "list --roles lists the forwarder" "agent-sandbox-fwd-here-1-8080"
expect_out    "list --roles shows the target label" "TARGET"

run "$list_bin" --help
expect_status "list --help exits 0" 0
expect_out    "list --help prints usage" "agent-sandbox-list"

run "$list_bin" --nope
expect_status "list rejects an unknown flag" 1

run "$list_bin" extra
expect_status "list rejects a positional" 1

fixture_reset
fixture_set running "agent-sandbox-here-silent"
fixture_set "labels.agent-sandbox-here-silent" \
  "agent-sandbox.proxy=off" "agent-sandbox.workspace=$PWD"
run "$list_bin"
expect_status "list succeeds with a session word sandbox" 0
expect_out    "list shows only the session word" "silent"
if grep -qE 'id-agent-sandbox-here-silent +silent +Up' <<< "$output"; then
  pass "list puts only the session word in the names column"
else
  fail "list puts only the session word in the names column" "$output"
fi

# ── merged --gpg flags ───────────────────────────────────────────────────────

fixture_reset

gpg_home="$tmp/gpg-home"
mkdir -p "$gpg_home"
gpg_run="$tmp/gpg-run"
mkdir -p "$gpg_run"

run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" -- true
expect_status "default launch forces commit.gpgsign=false" 0
if grep -qE -- '--name agent-sandbox-[A-Za-z0-9_.-]+-[a-z]+' <<< "$argv"; then
  pass "launcher names new sandboxes with a session word"
else
  fail "launcher names new sandboxes with a session word" "$argv"
fi
if grep -qF "GIT_CONFIG_KEY_0=commit.gpgsign" <<< "$argv"; then
  pass "default launch passes commit.gpgsign=false override"
else
  fail "default launch passes commit.gpgsign=false override" "$argv"
fi

run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" --gpg -- true
expect_status "canonical --gpg launch succeeds" 0
if grep -qF "GIT_CONFIG_KEY_0=commit.gpgsign" <<< "$argv"; then
  fail "--gpg removes commit.gpgsign=false override" "$argv"
else
  pass "--gpg removes commit.gpgsign=false override"
fi
if grep -qF "deprecated" <<< "$output"; then
  fail "--gpg emits no deprecation warning" "$output"
else
  pass "--gpg emits no deprecation warning"
fi

run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" --gpg-private -- true
expect_status "--gpg-private is accepted after rename" 0

run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" --gnupg-private -- true
expect_status "--gnupg-private is rejected after rename" 1
expect_out "--gnupg-private rejection points to valid flags" "'--gnupg-private' is not an agent-sandbox flag."

run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" --gpg-sign -- true
expect_status "--gpg-sign is rejected after the hard merge" 1
expect_out "--gpg-sign rejection points to valid flags" "'--gpg-sign' is not an agent-sandbox flag."

run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" --no-gpg-agent -- true
expect_status "--no-gpg-agent is rejected after the hard merge" 1
expect_out "--no-gpg-agent rejection points to valid flags" "'--no-gpg-agent' is not an agent-sandbox flag."

# --ssh and --proxy behavior should remain independent from merged gpg parsing.
run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" --gpg --ssh -- true
expect_status "--ssh still works with merged --gpg" 0
if grep -qF "SSH_AUTH_SOCK=/agent.sock" <<< "$argv"; then
  fail "--ssh without a real host socket does not inject SSH_AUTH_SOCK" "$argv"
else
  pass "--ssh without a real host socket does not inject SSH_AUTH_SOCK"
fi

run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" --gpg --proxy --port 8080 -- true
expect_status "--proxy conflict checks still run with merged --gpg" 1
expect_out "--proxy conflict message is unchanged by merged --gpg" "--proxy cannot be combined with a published port"
expect_no_argv "--proxy conflict still refuses before podman run" "run --rm"

# Volume flags are now podman-only passthrough; launcher-level -v is refused.
run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" -v ./host:/container -- true
expect_status "launcher-level -v is rejected" 1
expect_out    "launcher-level -v points to passthrough" "Use podman passthrough instead:"
expect_out    "launcher-level -v shows the passthrough form" "--podman-args -v"
expect_no_argv "launcher-level -v refuses before podman run" "run --rm"

run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" -v./host:/container -- true
expect_status "launcher-level -vSPEC is rejected" 1
expect_out    "launcher-level -vSPEC points to passthrough" "Use podman passthrough instead:"
expect_no_argv "launcher-level -vSPEC refuses before podman run" "run --rm"

run env HOME="$gpg_home" XDG_RUNTIME_DIR="$gpg_run" "$launcher_bin" --podman-args -v ./host:/container -- true
expect_status "podman passthrough -v is accepted" 0
if grep -qF -- "-v ./host:/container" <<< "$argv"; then
  pass "podman passthrough keeps -v unchanged"
else
  fail "podman passthrough keeps -v unchanged" "$argv"
fi

# ── --krun preflight ────────────────────────────────────────────────────────
# Every case here must refuse before podman is asked to do anything, so each is
# paired with an argv assertion.  A --krun sandbox that got as far as `podman
# run` with a bad memory value would boot on libkrun's 1 GiB default and give no
# sign that the number was ignored.

run "$launcher_bin" --krun --podman -- true
expect_status  "--krun refuses --podman" 1
expect_out     "--krun says why --podman is refused" "full"
expect_no_argv "--krun --podman starts no container" "run --rm"

# 128 exactly, because the handler's check is `<=` rather than `<`.
# An empty value is deliberately absent from this list: it is indistinguishable
# from the flag not being passed, and falls through to the 4096 default.
for bad in 0 64 128 abc 12.5; do
  run "$launcher_bin" --krun --krun-memory "$bad" -- true
  expect_status  "--krun-memory rejects '$bad'" 1
  expect_out     "--krun-memory '$bad' explains the 128 MiB floor" "greater than 128"
  expect_no_argv "--krun-memory '$bad' starts no container" "run --rm"
done

run "$launcher_bin" --krun --krun-memory 129 --krun-cpus 0 -- true
expect_status  "--krun-cpus rejects 0" 1
expect_no_argv "--krun-cpus 0 starts no container" "run --rm"

run "$launcher_bin" --krun --krun-cpus 17 -- true
expect_status  "--krun-cpus rejects 17 (LIBKRUN_MAX_VCPUS is 16)" 1
expect_no_argv "--krun-cpus 17 starts no container" "run --rm"

run "$launcher_bin" --krun --krun-memory -- true
expect_status "--krun-memory alone is an error" 1
run "$launcher_bin" --krun --krun-cpus -- true
expect_status "--krun-cpus alone is an error" 1

# Without --krun the values are never examined, so a bogus one must not refuse a
# perfectly ordinary launch.
run "$launcher_bin" --krun --no-krun --krun-memory 64 -- true
expect_status "--no-krun disarms the memory check" 0

# The wrapProgram --add-flags contract: a baked-in --krun has to be switchable
# off by the user, which is the whole reason the --no- form exists.
run "$launcher_bin" --krun --no-krun -- true
expect_status "--no-krun wins when it comes last" 0
expect_no_argv "--no-krun passes no runtime to podman" "--runtime"
expect_no_argv "--no-krun passes no krun annotation" "krun.ram_mib"

# A crun without the handler must be caught by name, not by a confusing podman
# failure at first boot.
status=0
output=$(FIXTURE="$tmp/fixture" ARGV_LOG="$tmp/argv" PATH="$tmp/bin:$PATH" \
         KRUN_STUB_LIBKRUN="-LIBKRUN" "$launcher_bin" --krun -- true 2>&1) || status=$?
if [[ "$status" == 1 && "$output" == *"without libkrun"* ]]; then
  pass "--krun refuses a crun built without libkrun"
else
  fail "--krun refuses a crun built without libkrun" "exit $status"$'\n'"$output"
fi

# Advisory, not refusals: --privileged is one of the two workloads --krun exists
# for, and --selinux still does useful work on the binds.  Both messages describe
# measured behaviour (see lib/smoke-krun.sh), so they assert on the cause rather
# than on the word "unverified" they used to carry.
run "$launcher_bin" --krun --privileged -- true
expect_out "--krun warns that nested podman needs storage configuration" "/var/lib/containers"
run "$launcher_bin" --krun --selinux -- true
expect_out "--krun says the sandbox process is not SELinux-confined" "label=disable"

# /dev/kvm is the one thing no test can conjure, so the assertion follows the
# machine rather than pretending.  Either way --krun must not reach podman.
run "$launcher_bin" --krun --krun-cpus 4 -- true
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  expect_status "--krun proceeds past the preflight when /dev/kvm is usable" 0
  # Only reachable on a KVM host, so this is the one assertion that the run line
  # is actually wired up rather than merely well-formed.  lib/smoke-krun.sh
  # covers it against a real guest.
  for want in "--runtime" "krun.ram_mib=4096" "krun.cpus=4" "agent-sandbox.runtime=krun"; do
    if grep -qF -- "$want" <<< "$argv"; then
      pass "--krun passes $want to podman"
    else
      fail "--krun passes $want to podman" "$argv"
    fi
  done
else
  expect_status  "--krun refuses without /dev/kvm" 1
  expect_out     "--krun names /dev/kvm" "/dev/kvm"
  expect_no_argv "--krun starts no container without /dev/kvm" "run --rm"
fi

# ── ctl refusals against a krun sandbox ─────────────────────────────────────
# attach and mount are the two commands that enter the sandbox, and both must
# refuse on the label.  mount is the sharper case: its nsenter --bind succeeds
# against the VMM and changes nothing in the guest, so an unguarded mount would
# report success and silently do nothing.

fixture_reset
fixture_set running "agent-sandbox-vm-1"
fixture_set all     "agent-sandbox-vm-1"
fixture_set "labels.agent-sandbox-vm-1" "agent-sandbox.runtime=krun"

run "$attach_bin" agent-sandbox-vm-1
expect_status  "attach refuses a krun sandbox" 1
expect_out     "attach says it is a microVM" "microVM"
expect_out     "attach offers a workaround" "agent-sandbox --krun -- bash"
expect_no_argv "attach execs nothing" "exec"

run "$mount_bin" --sandbox agent-sandbox-vm-1 "$tmp" /mnt/x
expect_status  "mount refuses a krun sandbox" 1
expect_out     "mount explains the silent no-op" "no effect"
expect_no_argv "mount execs nothing" "exec"
expect_no_argv "mount starts no relabel container" "--entrypoint"

# The label is absent on anything an older launcher started, and those are
# ordinary containers: refusing them would be a regression, not a safeguard.
fixture_reset
fixture_set running "agent-sandbox-old-1"
fixture_set all     "agent-sandbox-old-1"

run "$attach_bin" agent-sandbox-old-1
expect_status "attach still works on a sandbox predating the runtime label" 0
if grep -qF -- "exec" <<< "$argv"; then
  pass "attach execs into an unlabelled sandbox"
else
  fail "attach execs into an unlabelled sandbox" "$argv"
fi

# ── error output goes to stderr ─────────────────────────────────────────────

status=0
FIXTURE="$tmp/fixture" ARGV_LOG="$tmp/argv" PATH="$tmp/bin:$PATH" \
  "$net_bin" --nope 2>/dev/null 1>"$tmp/stdout" || status=$?
if [[ -s "$tmp/stdout" ]]; then
  fail "net writes errors to stderr, not stdout" "$(cat "$tmp/stdout")"
else
  pass "net writes errors to stderr, not stdout"
fi

if [[ "$failures" -gt 0 ]]; then
  printf '\n%s test(s) failed\n' "$failures" >&2
  exit 1
fi

printf '\nall ctl-args tests passed\n'
