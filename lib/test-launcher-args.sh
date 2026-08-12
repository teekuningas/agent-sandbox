#!/usr/bin/env bash
# Argument-parsing tests for the agent-sandbox launcher.
#
#   bash test-launcher-args.sh /path/to/agent-sandbox.sh
#
# The launcher is run against a stub podman that records the argv it was given,
# so these assert what actually reaches `podman run` rather than re-implementing
# the parser.

set -euo pipefail

LAUNCHER="${1:?usage: test-launcher-args.sh <launcher>}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin"
cat > "$tmp/bin/podman" <<'STUB'
#!/usr/bin/env bash
case "$1 $2" in
  "image exists"|"network exists") exit 0 ;;
esac
if [[ "$1" == "run" ]]; then printf '%s\n' "$@" > "$PODMAN_ARGV"; fi
exit 0
STUB
chmod +x "$tmp/bin/podman"

export PODMAN_ARGV="$tmp/argv"
export AGENT_SANDBOX_IMAGE=stub-image
export AGENT_SANDBOX_NETWORK=stub-net
export AGENT_SANDBOX_AGENT_SPECS=$'opencode\t["opencode","."]\t[".config/opencode"]\t[]'

fails=0

launch() {
	rm -f "$PODMAN_ARGV"
	PATH="$tmp/bin:$PATH" HOME="$tmp/home" bash "$LAUNCHER" \
		--no-ssh --no-workspace --no-git --no-gnupg-private \
		--no-firewall --no-ports "$@" >/dev/null 2>&1 || true
}

# Assert $2 appears in the recorded argv, labelled $1.
has() {
	if grep -qxF -- "$2" "$PODMAN_ARGV" 2>/dev/null; then
		echo "ok   $1"
	else
		echo "FAIL $1 — '$2' not passed to podman run"
		fails=$((fails + 1))
	fi
}

# Assert $2 appears before $3 in the recorded argv.
before() {
	local a b
	a="$(grep -nxF -- "$2" "$PODMAN_ARGV" 2>/dev/null | head -1 | cut -d: -f1 || true)"
	b="$(grep -nxF -- "$3" "$PODMAN_ARGV" 2>/dev/null | head -1 | cut -d: -f1 || true)"
	if [[ -n "$a" && -n "$b" && "$a" -lt "$b" ]]; then
		echo "ok   $1"
	else
		echo "FAIL $1 — '$2' ($a) not before '$3' ($b)"
		fails=$((fails + 1))
	fi
}

echo "# --podman-args=ARG is repeatable"
launch --podman-args=--add-host=a:1.2.3.4 --podman-args=--net=host opencode
has "first --podman-args=ARG" "--add-host=a:1.2.3.4"
has "second --podman-args=ARG" "--net=host"
before "podman args precede the image" "--net=host" "stub-image"

echo "# --podman-args=ARG consumes nothing else, so later flags still parse"
launch --podman-args=--add-host=a:1.2.3.4 --privileged opencode
has "--privileged still handled as a launcher flag" "--privileged"
has "--podman-args=ARG still passed" "--add-host=a:1.2.3.4"
has "agent command still reached" "opencode"

echo "# the legacy slurp form keeps working"
launch --podman-args --privileged --cap-add=NET_ADMIN -- opencode
has "legacy first arg" "--privileged"
has "legacy second arg" "--cap-add=NET_ADMIN"
has "legacy command after --" "opencode"

echo ""
if [[ "$fails" -ne 0 ]]; then
	echo "$fails check(s) failed"
	exit 1
fi
echo "all launcher argument checks passed"
