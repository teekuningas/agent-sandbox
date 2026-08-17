---
name: devenv
description: Use and write devenv.nix — declarative development environments with pinned packages, language toolchains, scripts, git hooks, and supporting services such as databases, run non-interactively with devenv shell -- <command>. Trigger when a repository has devenv.nix, devenv.yaml, or devenv.lock, when a project command needs its declared environment, or when a service like postgres or redis must run for development or tests.
compatibility: opencode
metadata:
  workflow: declared-development-environment
  audience: developers-and-agents
---

# devenv

When a repository declares an environment, every project command runs inside it.

```sh
devenv shell -- <command> [args...]
```

```sh
devenv shell -- cargo test
devenv shell -- npm test
devenv shell -- pytest -q
```

Use the `--` form, not bare `devenv shell`: it runs one command in the declared
environment and returns its exit status, instead of opening an interactive
subshell a non-interactive session cannot use.

## Which environment to use

1. `devenv.nix` exists → `devenv shell -- <cmd>`, and make environment changes
   in `devenv.nix`.
2. No devenv, but `flake.nix` exposes a devShell → `nix develop --command <cmd>`;
   see the `nix-flake` skill.
3. Neither → follow the project's documented commands, and use `nix run` for an
   isolated missing tool; see the `nix` skill.

Never work around a declared environment by installing packages on the host.

## The files

| File | Role |
| --- | --- |
| `devenv.nix` | The environment: packages, languages, env, scripts, services, hooks, tasks |
| `devenv.yaml` | Inputs (nixpkgs and any overlays/flakes) |
| `devenv.lock` | Pinned inputs — commit it, do not hand-edit |
| `devenv.local.nix` | Untracked local overrides; never commit machine-specific settings into `devenv.nix` |
| `.devenv/` | Generated state, including `.devenv/state/<service>`; gitignored |

## Editing devenv.nix

```nix
{ pkgs, lib, config, ... }:
{
  packages = [ pkgs.jq pkgs.git ];

  env.DATABASE_URL = "postgresql://localhost/app";

  languages.python.enable = true;
  languages.python.version = "3.12";
  languages.python.uv.enable = true;
  languages.python.venv.enable = true;

  scripts.check.exec = "ruff check . && pytest -q";

  services.postgres.enable = true;
  services.postgres.listen_addresses = "127.0.0.1";
  services.postgres.initialDatabases = [ { name = "app"; } ];

  processes.web.exec = "uvicorn app:api --reload";

  git-hooks.hooks.ruff.enable = true;

  enterTest = ''
    pytest -q
  '';
}
```

Prefer a project-defined `scripts` entry or task over retyping the command it
wraps — `devenv shell -- check` keeps working when the underlying command
changes. Add new commands as `scripts` rather than as shell one-liners in
documentation.

`enterShell` runs on every environment entry, including every `--command`
invocation; keep it cheap. Put one-time setup in `tasks` instead.

## Services

```sh
devenv up -d                     # start every process/service in the background
devenv up postgres               # start one, in the foreground
devenv processes wait            # block until they report ready — do not sleep
devenv processes list            # status of each
devenv processes logs web        # logs for one
devenv processes restart web
devenv processes down            # stop everything
```

Service data lives under `.devenv/state/<service>`; deleting that directory
resets a database. Services listen on localhost — inside a sandboxed container
that is the container's localhost, so a host client will not see them unless the
port was published at launch.

## Tests and checks

```sh
devenv test              # runs enterTest plus the configured git hooks
devenv tasks list
devenv tasks run app:build
```

`devenv test` is the closest thing to a project-wide check; run it before
reporting work as done when the repository defines `enterTest` or git hooks.

## Inputs

```sh
devenv inputs add rust-overlay github:oxalica/rust-overlay --follows nixpkgs
devenv update             # update every input in devenv.lock
devenv update nixpkgs     # update one
```

Some options require an input to be present — for example
`languages.rust.channel` fails with the exact `devenv inputs add` command to
run. Read that error rather than guessing.

Do not run `devenv update` unless updating inputs is part of the task; review
the `devenv.lock` diff when you do.

## Gotchas

- **First entry is slow.** Changing `devenv.nix` rebuilds the environment, and
  a language toolchain or database can take minutes to substitute. That is
  expected — do not kill it and fall back to host tools.
- **Secrets are not config.** Use `dotenv.enable = true` with an untracked
  `.env`, not literals in `devenv.nix`.
- **Unknown option errors are precise.** devenv prints
  `The option '<name>' does not exist` with suggestions; that is the fastest way
  to confirm an option name.
- **`devenv info`** prints the resolved packages, env, and processes when
  something is not what you expect.

## More

Read `reference.md` when the task needs any of: a specific language toolchain
setup, a process readiness probe or service dependency ordering, service
configuration beyond `enable = true`, splitting config with `imports`, a
one-off `-O` override, a container output, CI caching, or devenv driven from
inside a flake.
