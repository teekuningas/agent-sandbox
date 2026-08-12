#!/usr/bin/env bash
# Container entrypoint.  Everything here is setup that can only be done from
# inside the container, gated on AGENT_SANDBOX_* variables the launcher sets.

# The image ships a pre-registered Nix store database.  When the host's /nix
# is mounted over it, the host's own database comes along and this would
# clobber it.
if [[ "${AGENT_SANDBOX_SKIP_NIX_INIT:-0}" != "1" && "${AGENT_SANDBOX_HOST_NIX:-}" != "1" ]]; then
  if [[ ! -f /nix/var/nix/db/db.sqlite ]]; then
    nix-store --load-db < /nix/registration
  fi
fi

# Forward the host gpg-agent into the user's gnupg home so signed commits and
# tag operations reuse host keys (or the smart card behind them).
if [[ "${AGENT_SANDBOX_GPG_AGENT:-}" == "1" && -S /run/host-gpg-agent ]]; then
  mkdir -p ~/.gnupg
  chmod 700 ~/.gnupg
  rm -f ~/.gnupg/S.gpg-agent
  ln -s /run/host-gpg-agent ~/.gnupg/S.gpg-agent

  # pinentry prompts on this tty.  It has to be resolved here: the launcher
  # cannot know which pts podman will allocate.
  if [[ -t 0 ]]; then
    GPG_TTY=$(readlink /proc/self/fd/0 2>/dev/null) && export GPG_TTY
  fi

  # The launcher binds only public key material (see agent-sandbox-gnupg-scan),
  # so this copies whatever it decided to expose. Copies rather than symlinks
  # because gpg wants to write lock files next to the keyring.
  if [[ -d /run/host-gnupg ]]; then
    for source in /run/host-gnupg/*; do
      [[ -f "$source" ]] || continue
      target=~/.gnupg/$(basename "$source")
      [[ -e "$target" ]] && continue
      cp --no-preserve=mode "$source" "$target" 2>/dev/null || true
    done
  fi

  # Off by default: fetching a key from a public keyserver is network egress
  # the user did not ask for, and it imports third-party material into the
  # container keyring.
  if [[ "${AGENT_SANDBOX_GPG_RECV_KEY:-}" == "1" ]]; then
    if signing_key=$(git config --get user.signingkey 2>/dev/null); then
      gpg --keyserver keyserver.ubuntu.com --recv-keys "$signing_key" 2>/dev/null || true
    fi
  fi
fi

# Pre-populate known_hosts so a first-time git push does not stop on host key
# verification.  These are the published fingerprints for the three forges as
# of 2026-08; a rotation makes the matching host unreachable until refreshed.
#
#   Refresh with: ssh-keyscan github.com gitlab.com bitbucket.org
#
# Only written when absent, so an operator's own entries always win.
if [[ -S /agent.sock ]]; then
  mkdir -p ~/.ssh
  chmod 700 ~/.ssh
  if [[ -f ~/.ssh/known_hosts && ! -w ~/.ssh/known_hosts ]]; then
    chmod 644 ~/.ssh/known_hosts 2>/dev/null || rm -f ~/.ssh/known_hosts
  fi
  if ! grep -qs 'github.com' ~/.ssh/known_hosts 2>/dev/null; then
    cat >> ~/.ssh/known_hosts << 'KNOWN_HOSTS'
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=
gitlab.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf
gitlab.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9
bitbucket.org ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIQmuzMBuKdWeF4+a2sjSSpBK0iqitSQ+5BM9KhpexuGt20JpTVM7u5BDZngncgrqDMbWdxMWWOGtZ9UgbqgZE=
bitbucket.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO
bitbucket.org ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQeJzhupRu0u0cdegZIa8e86EG2qOCsIsD1Xw0xSeiPDlCr7kq97NLmMbpKTX6Esc30NuoqEEHCuc7yWtwp8dI76EEEB1VqY9QJq6vk+aySyboD5QF61I/1WeTwu+deCbgKMGbUijeXhtfbxSxm6JwGrXrhBdofTsbKRUsrN1WoNgUa8uqN1Vx6WAJw1JHPhglEGGHea6QICwJOAr/6mrui/oB7pkaWKHj3z7d1IC4KWLtY47elvjbaTlkN04Kc/5LFEirorGYVbt15kAUlqGM65pk6ZBxtaO3+30LVlORZkxOh+LKL/BvbZ/iRNhItLqNyieoQj/uh/7Iv4uyH/cV/0b4WDSd3DptigWq84lJubb9t/DnZlrJazxyDCulTmKdOR7vs9gMTo+uoIrPSb8ScTtvw65+odKAlBj59dhnVp9zd7QUojOpXlL62Aw56U4oO+FALuevvMjiWeavKhJqlR7i5n9srYcrNV7ttmDw7kf/97P5zauIhxcjX+xHv4M=
KNOWN_HOSTS
  fi
fi

if [[ -n "${HTTP_PROXY:-}" ]]; then
  mkdir -p ~/.ssh
  chmod 700 ~/.ssh
  if [[ ! -f ~/.ssh/config && ! -h ~/.ssh/config ]]; then
    proxy_host_port="${HTTP_PROXY#*://}"
    proxy_host="${proxy_host_port%:*}"
    proxy_port="${proxy_host_port##*:}"
    cat >> ~/.ssh/config << SSH_CONFIG
Host *
  ProxyCommand socat - PROXY:${proxy_host}:%h:%p,proxyport=${proxy_port}
SSH_CONFIG
    chmod 600 ~/.ssh/config
  fi

  # Node's core http/https and built-in fetch (undici) ignore HTTP_PROXY /
  # HTTPS_PROXY unless explicitly told to honor them (Node >= 24). This also
  # covers the bundled Node-based agent CLIs, which all run under the same
  # runtime. An operator's own explicit setting still wins.
  : "${NODE_USE_ENV_PROXY:=1}"
  export NODE_USE_ENV_PROXY
fi

exec "$@"
