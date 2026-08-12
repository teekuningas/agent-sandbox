#!/usr/bin/env bash
# Manage host bind mounts of a running sandbox.

: "${AGENT_SANDBOX_NETWORK:?}"  # keep shellcheck quiet about the unused variable from preamble

prog="agent-sandbox-ctl mounts"

usage() {
  cat <<USAGE
$prog ls     [WORD] [--sandbox WORD]
$prog add    [WORD] [--sandbox WORD] HOST_PATH CONTAINER_PATH
$prog rm     [WORD] [--sandbox WORD] CONTAINER_PATH
$prog export [WORD] [--sandbox WORD]

  ls      show non-baseline bind mounts of running sandboxes
  add     bind-mount a host directory into a running sandbox
  rm      unmount a container path from a running sandbox
  export  print the [mounts] section of a running sandbox as AGENTS.md TOML

Compatibility: \`agent-sandbox-ctl mount [WORD] HOST_PATH CONTAINER_PATH\`
still works as an alias of \`$prog add ...\`.
USAGE
}

filter_non_baseline_mounts() {
  jq -r --arg ws "$1" '
    .[] | select(.Type == "bind") |
    select(.Destination != "/workspace") |
    select(.Destination != "/home/user/.local/share/devenv") |
    select(.Destination | test("^/home/user/.(local|config|cache)/") | not) |
    select(.Destination | test("^/home/user/.(gitconfig|gnupg|ssh)") | not) |
    select(.Destination | test("^/run/") | not) |
    select(.Destination | test("^/sidecar_") | not) |
    select(.Destination | test("^/nix") | not) |
    select(.Destination | test("^/etc/") | not)
  '
}

mounts_tsv() { # sandbox workspace
  podman inspect --format '{{json .Mounts}}' "$1" 2>/dev/null \
    | filter_non_baseline_mounts "$2" \
    | jq -r '[.Source, .Destination, ((.Options // []) | join(","))] | @tsv' || true
}

mounts_toml() { # sandbox workspace
  podman inspect --format '{{json .Mounts}}' "$1" 2>/dev/null \
    | filter_non_baseline_mounts "$2" \
    | jq -r --arg ws "$2" '
      .Source as $src | .Destination as $dst | .Options as $opts |
      (
        if ($src | startswith($ws + "/")) then
          "." + ($src | ltrimstr($ws))
        elif ($src == $ws) then
          "."
        else
          $src
        end
      ) as $rel_src |
      (
        if ($opts | index("ro")) then
          "\"" + $rel_src + "\" = { destination = \"" + $dst + "\", options = \"ro\" }"
        elif ($opts | index("z")) then
          "\"" + $rel_src + "\" = { destination = \"" + $dst + "\", options = \"z\" }"
        else
          "\"" + $rel_src + "\" = \"" + $dst + "\""
        end
      )
    ' || true
}

cmd_ls() {
  local only="${1:-}" names=() sandbox workspace line src dst opts
  if [[ -n "$only" ]]; then
    names=("$(resolve_sandbox "$only" --running)")
  else
    mapfile -t names < <(sandbox_containers)
  fi

  if [[ ${#names[@]} -eq 0 ]]; then
    echo "No running sandboxes."
  fi

  for sandbox in "${names[@]}"; do
    printf '%s\n' "$sandbox"
    workspace="$(sandbox_workspace "$sandbox")"
    printf '  workspace   %s\n' "$workspace"
    local found=0
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      found=1
      IFS=$'\t' read -r src dst opts <<< "$line"
      if [[ -n "$opts" ]]; then
        printf '  mount       %s -> %s (%s)\n' "$src" "$dst" "$opts"
      else
        printf '  mount       %s -> %s\n' "$src" "$dst"
      fi
    done < <(mounts_tsv "$sandbox" "$workspace")
    if [[ "$found" == 0 ]]; then
      printf '  mount       (none)\n'
    fi
  done
}

cmd_add() { # sandbox host_path container_path
  local sandbox="$1" host_path="$2" container_path="$3"

  if [[ ! -d "$host_path" ]]; then
    echo "$prog: host path '$host_path' does not exist or is not a directory" >&2
    exit 1
  fi
  host_path="$(readlink -f "$host_path")"

  # Before the relabel below, which would otherwise start a throwaway container
  # for nothing.  This refusal matters more than attach's: the nsenter --bind at
  # the end of this script *succeeds* against a microVM and changes nothing the
  # guest can see, so without the guard the command would report success and do
  # nothing at all.
  refuse_if_krun "$sandbox" "mounts add" \
    "A host-side bind lands in the VMM's mount namespace, not in the guest, so it" \
    "would appear to succeed and have no effect.  virtio-fs cannot take a new" \
    "share after boot.  Relaunch with the mount in place:  agent-sandbox --krun -v ..."

  local pid has_selinux
  pid="$(podman inspect --format '{{.State.Pid}}' "$sandbox")"

  # Check if SELinux relabeling is implied by existing mounts (i.e., started with --selinux)
  has_selinux="$(podman inspect --format '{{range .Mounts}}{{.Mode}} {{end}}' "$sandbox" | grep -qw 'z' && echo 1 || echo 0)"
  if [[ "$has_selinux" == "1" ]]; then
    # Use podman's native relabeling instead of guessing chcon commands
    podman run --rm --entrypoint /bin/true -v "$host_path:/tmp/relabel:z" "$AGENT_SANDBOX_IMAGE" >/dev/null 2>&1 || true
  fi

  podman exec "$sandbox" mkdir -p "$container_path"
  podman unshare nsenter -t "$pid" -m mount --bind "$host_path" "$container_path"
  echo "Mounted $host_path to $sandbox:$container_path"
}

cmd_rm() { # sandbox container_path
  local sandbox="$1" container_path="$2" pid
  refuse_if_krun "$sandbox" "mounts rm" \
    "A host-side unmount acts in the VMM namespace, not in the guest." \
    "Relaunch the --krun sandbox without the mount, or manage mounts before launch."
  pid="$(podman inspect --format '{{.State.Pid}}' "$sandbox")"
  podman unshare nsenter -t "$pid" -m umount "$container_path"
  echo "Unmounted $sandbox:$container_path"
}

cmd_export() { # sandbox
  local sandbox="$1" workspace mounts
  workspace="$(sandbox_workspace "$sandbox")"
  mounts="$(mounts_toml "$sandbox" "$workspace")"
  if [[ -n "$mounts" ]]; then
    echo '```toml agent-sandbox'
    echo "[mounts]"
    echo "$mounts"
    echo '```'
  fi
}

[[ $# -gt 0 ]] || { usage; exit 1; }

action="${1:-}"
case "$action" in
  ls|list|add|rm|remove|export) shift ;;
  -h|--help|help) usage; exit 0 ;;
  *) action="legacy-add" ;;
esac

sandbox_name=""
positional=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --sandbox)
      shift
      [[ $# -gt 0 ]] || { echo "$prog: --sandbox needs a name" >&2; exit 1; }
      sandbox_name="$1"
      ;;
    --sandbox=*) sandbox_name="${1#--sandbox=}" ;;
    -*)          echo "$prog: unknown flag '$1'" >&2; exit 1 ;;
    *)           positional+=("$1") ;;
  esac
  shift
done

case "$action" in
  ls|list)
    if [[ ${#positional[@]} -eq 1 ]]; then
      if [[ -n "$sandbox_name" ]]; then
        echo "$prog: cannot specify both --sandbox and a positional sandbox name" >&2
        exit 1
      fi
      sandbox_name="${positional[0]}"
    elif [[ ${#positional[@]} -gt 1 ]]; then
      echo "$prog: ls takes at most one argument (the sandbox)" >&2
      usage >&2
      exit 1
    fi
    cmd_ls "$sandbox_name"
    ;;

  export)
    if [[ ${#positional[@]} -eq 1 ]]; then
      if [[ -n "$sandbox_name" ]]; then
        echo "$prog: cannot specify both --sandbox and a positional sandbox name" >&2
        exit 1
      fi
      sandbox_name="${positional[0]}"
    elif [[ ${#positional[@]} -gt 1 ]]; then
      echo "$prog: export takes at most one argument (the sandbox)" >&2
      usage >&2
      exit 1
    fi
    cmd_export "$(resolve_sandbox "$sandbox_name" --running)"
    ;;

  add|legacy-add)
    if [[ ${#positional[@]} -eq 3 ]]; then
      if [[ -n "$sandbox_name" ]]; then
        echo "$prog: cannot specify both --sandbox and a positional sandbox name" >&2
        exit 1
      fi
      sandbox_name="${positional[0]}"
      host_path="${positional[1]}"
      container_path="${positional[2]}"
    elif [[ ${#positional[@]} -eq 2 ]]; then
      host_path="${positional[0]}"
      container_path="${positional[1]}"
    else
      if [[ "$action" == "legacy-add" ]]; then
        echo "$prog: expected [SANDBOX] HOST_PATH CONTAINER_PATH" >&2
      else
        echo "$prog: add needs HOST_PATH CONTAINER_PATH, and optionally a sandbox" >&2
      fi
      usage >&2
      exit 1
    fi
    cmd_add "$(resolve_sandbox "$sandbox_name" --running)" "$host_path" "$container_path"
    ;;

  rm|remove)
    if [[ ${#positional[@]} -eq 2 ]]; then
      if [[ -n "$sandbox_name" ]]; then
        echo "$prog: cannot specify both --sandbox and a positional sandbox name" >&2
        exit 1
      fi
      sandbox_name="${positional[0]}"
      container_path="${positional[1]}"
    elif [[ ${#positional[@]} -eq 1 ]]; then
      container_path="${positional[0]}"
    else
      echo "$prog: rm needs CONTAINER_PATH, and optionally a sandbox" >&2
      usage >&2
      exit 1
    fi
    cmd_rm "$(resolve_sandbox "$sandbox_name" --running)" "$container_path"
    ;;

  *)
    echo "$prog: unknown command '$action'" >&2
    usage >&2
    exit 1
    ;;
esac
