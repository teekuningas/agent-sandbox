#!/usr/bin/env bash
set -euo pipefail

# Sandbox discovery, shared by the host-side scripts that act on a sandbox
# (agent-sandbox-port, agent-sandbox-net).  Podman labels are the whole
# discovery protocol; see the --label arguments in lib/agent-sandbox.sh.
#
# Inlined into each consumer at build time rather than shipped as its own
# binary, so error messages carry the calling script's name via $0.

sandbox_containers() {
  podman ps --filter "label=agent-sandbox.role=sandbox" --format '{{.Names}}'
}

# Including stopped sandboxes.  Cleanup commands need these: a forwarder
# outlives the sandbox it points at, and removing it is exactly the case where
# the sandbox is already gone.
# Not every consumer of this shared helper calls every function.
# shellcheck disable=SC2329
sandbox_containers_all() {
  podman ps -a --filter "label=agent-sandbox.role=sandbox" --format '{{.Names}}'
}

# Not every consumer of this shared helper calls every function.
# shellcheck disable=SC2329
sandbox_workspace() {
  podman inspect --format '{{index .Config.Labels "agent-sandbox.workspace"}}' "$1" 2>/dev/null || true
}

sandbox_running() {
  podman ps --format '{{.Names}}' | grep -qxF "$1"
}

# Sandboxes end in a single-word session selector.
sandbox_word() {
  local sandbox="$1"
  printf '%s\n' "${sandbox##*-}"
}

# proxy | off, and empty for a container predating the label.
# Not every consumer of this shared helper calls every function.
# shellcheck disable=SC2329
sandbox_proxy_mode() {
  podman inspect --format '{{index .Config.Labels "agent-sandbox.proxy"}}' "$1" 2>/dev/null || true
}

# krun | crun, and empty for a container predating the label.  Callers must
# treat empty as crun: a sandbox started by an older launcher is an ordinary
# container, and refusing to exec into it would be a regression.
# Not every consumer of this shared helper calls every function.
# shellcheck disable=SC2329
sandbox_runtime() {
  podman inspect --format '{{index .Config.Labels "agent-sandbox.runtime"}}' "$1" 2>/dev/null || true
}

# Commands that enter the sandbox have to refuse against a microVM: crun's
# libkrun handler leaves .exec_func NULL, so `podman exec` fails outright, and
# a host-side bind mount lands in the VMM's namespace where the guest cannot see
# it.  Refusing on the label rather than on the podman error is deliberate --
# the failure is silent in the mount case, and misleading in the exec case.
# Not every consumer of this shared helper calls every function.
# shellcheck disable=SC2329
refuse_if_krun() { # sandbox verb remedy...
  local sandbox="$1" verb="$2"
  shift 2
  [[ "$(sandbox_runtime "$sandbox")" == "krun" ]] || return 0
  echo "${0##*/}: '$sandbox' is a --krun microVM; $verb is not available." >&2
  local line
  for line in "$@"; do
    echo "               $line" >&2
  done
  exit 1
}

# The proxy sidecar serving a sandbox, by label.  Empty when the sandbox was
# launched without a proxy, or by a launcher that predates the label.
# Not every consumer of this shared helper calls every function.
# shellcheck disable=SC2329
sidecar_for_sandbox() {
  podman ps --filter "label=agent-sandbox.role=proxy" \
            --filter "label=agent-sandbox.target=$1" --format '{{.Names}}' 2>/dev/null | head -n 1
}

# Host-side source of one of a container's bind mounts.  How the policy and
# connection-log directories are located without recording their paths anywhere:
# they are mktemp dirs whose names nothing else knows.
# Not every consumer of this shared helper calls every function.
# shellcheck disable=SC2329
sidecar_mount() { # container destination
  podman inspect --format \
    "{{range .Mounts}}{{if eq .Destination \"$2\"}}{{.Source}}{{end}}{{end}}" \
    "$1" 2>/dev/null || true
}

# Fails with a remediation hint rather than letting the caller produce a
# confusing podman error.  Echoes the sidecar name.
# Not every consumer of this shared helper calls every function.
# shellcheck disable=SC2329
require_sidecar() {
  local sandbox="$1" sidecar
  sidecar=$(sidecar_for_sandbox "$sandbox")
  if [[ -z "$sidecar" ]]; then
    echo "${0##*/}: '$sandbox' is running without a proxy." >&2
    echo "               Relaunch it with:  agent-sandbox --proxy" >&2
    exit 1
  fi
  printf '%s\n' "$sidecar"
}

# Resolve which sandbox to act on: an explicit --sandbox, the only one
# running, or the one whose workspace is the current directory.
#
# Pass --running when the command needs a live container (anything that execs
# into it, or reads from the proxy).  Cleanup commands deliberately do not, so
# they still work once the sandbox has exited.
resolve_sandbox() {
  local explicit="$1" want_running=0
  [[ "${2:-}" == "--running" ]] && want_running=1

  if [[ -n "$explicit" ]]; then
    local all_names=()
    mapfile -t all_names < <(sandbox_containers_all)

    local valid_matches=()
    for name in "${all_names[@]}"; do
      if [[ "$name" == "$explicit" || "$name" == *"-${explicit}" ]]; then
        valid_matches+=("$name")
      fi
    done

    if [[ ${#valid_matches[@]} -eq 1 ]]; then
      if [[ "$want_running" == "1" ]] && ! sandbox_running "${valid_matches[0]}"; then
        # Preserve the exact error message that test-ctl-args.sh expects
        if [[ "$explicit" == "${valid_matches[0]}" ]]; then
          echo "${0##*/}: '$explicit' is not running" >&2
        else
          echo "${0##*/}: '${valid_matches[0]}' is not running" >&2
        fi
        exit 1
      fi
      printf '%s\n' "${valid_matches[0]}"
      return
    elif [[ ${#valid_matches[@]} -gt 1 ]]; then
      echo "${0##*/}: '$explicit' is ambiguous, matches multiple sandboxes:" >&2
      for m in "${valid_matches[@]}"; do
        printf '  %s\t%s\n' "$(sandbox_word "$m")" "$(sandbox_workspace "$m")" >&2
        printf '    full name: %s\n' "$m" >&2
      done
      exit 1
    fi

    echo "${0##*/}: no container named '$explicit'" >&2
    exit 1
  fi

  local names=()
  if [[ "$want_running" == "1" ]]; then
    mapfile -t names < <(sandbox_containers)
  else
    mapfile -t names < <(sandbox_containers_all)
  fi

  if [[ ${#names[@]} -eq 0 ]]; then
    if [[ "$want_running" == "1" ]]; then
      echo "${0##*/}: no running sandboxes." >&2
    else
      echo "${0##*/}: no sandboxes found." >&2
    fi
    exit 1
  fi
  if [[ ${#names[@]} -eq 1 ]]; then
    printf '%s\n' "${names[0]}"
    return
  fi

  local matches=() name
  for name in "${names[@]}"; do
    [[ "$(sandbox_workspace "$name")" == "$PWD" ]] && matches+=("$name")
  done
  if [[ ${#matches[@]} -eq 1 ]]; then
    printf '%s\n' "${matches[0]}"
    return
  fi

  echo "${0##*/}: several sandboxes are running; pass --sandbox NAME:" >&2
  for name in "${names[@]}"; do
    printf '  %s\t%s\n' "$name" "$(sandbox_workspace "$name")" >&2
  done
  exit 1
}
