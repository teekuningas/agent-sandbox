# devenv — advanced patterns

Read `SKILL.md` first. Option names below are valid in devenv 2.x; confirm any
uncertain one with `devenv eval <attr>`, which fails with
`The option '<name>' does not exist` plus suggestions.

## Language toolchains

```nix
languages.python.enable = true;
languages.python.version = "3.12";     # exact interpreter version
languages.python.uv.enable = true;     # or poetry.enable / venv.enable
languages.python.venv.enable = true;

languages.javascript.enable = true;
languages.javascript.package = pkgs.nodejs_22;
languages.javascript.npm.install.enable = true;   # npm ci on shell entry

languages.go.enable = true;

languages.java.enable = true;
languages.java.jdk.package = pkgs.jdk21;

languages.rust.enable = true;
languages.rust.channel = "stable";     # requires the rust-overlay input
```

Some language options need an extra input. devenv says exactly which:

```sh
devenv inputs add rust-overlay github:oxalica/rust-overlay --follows nixpkgs
```

Prefer `languages.<x>` over adding a compiler to `packages` — it wires up the
environment variables, linkers, and per-project state directories too.

## Processes and services

```nix
process.manager.implementation = "process-compose";   # default

processes.web = {
  exec = "uvicorn app:api --host 127.0.0.1 --port 8000";
  process-compose = {
    depends_on.postgres.condition = "process_healthy";
    readiness_probe.http_get = { host = "127.0.0.1"; port = 8000; path = "/health"; };
  };
};
```

Readiness probes plus `devenv processes wait` replace `sleep` in scripts and CI:
the wait returns when the service is actually accepting connections.

```nix
services.postgres = {
  enable = true;
  listen_addresses = "127.0.0.1";
  initialDatabases = [ { name = "app"; } ];
  initialScript = "CREATE EXTENSION IF NOT EXISTS pg_trgm;";
};
services.redis.enable = true;
services.mysql.enable = true;
services.caddy = {
  enable = true;
  virtualHosts.":8080".extraConfig = "respond \"ok\"";
};
```

Each service exports its own variables (`PGDATA`, `PGHOST`, `REDISDATA`, …) —
check with `devenv info` or `devenv eval env` instead of hard-coding paths.
State lives in `.devenv/state/<service>`; delete that directory to reset.

Local TLS and hostnames:

```nix
certificates = [ "example.local" ];
hosts."example.local" = "127.0.0.1";
```

## Tasks

Tasks are ordered, cached units of work — use them where `enterShell` would be
too slow or too eager:

```nix
tasks."app:migrate" = {
  exec = "alembic upgrade head";
  after = [ "devenv:enterShell" ];
  status = "test -f .devenv/state/.migrated";   # skip when this succeeds
};
```

```sh
devenv tasks list
devenv tasks run app:migrate
```

`before`/`after` accept other task names, including the built-ins
`devenv:enterShell` and `devenv:enterTest`.

## Splitting configuration

```nix
{
  imports = [
    ./nix/services.nix
    ./nix/python.nix
  ];
}
```

Machine-specific settings belong in `devenv.local.nix` (untracked), never in the
committed `devenv.nix`. One-off overrides need no file at all:

```sh
devenv -O services.postgres.enable:bool false shell -- pytest -q
devenv -O languages.python.version:string 3.13 shell -- python --version
```

Types are required: `string`, `int`, `float`, `bool`, `path`, `pkg`, `pkgs`.

## Tests and CI

```nix
enterTest = ''
  pytest -q
'';
```

`devenv test` starts every declared `processes`/`services` entry before running
`enterTest` and stops them after. Call `wait_for_port <port> [timeout]` at the
top of `enterTest` before touching a service — it blocks until the port
accepts connections, so the test never races a service that is still starting:

```nix
{ pkgs, ... }:
{
  services.nginx = {
    enable = true;
    httpConfig = ''
      server {
        listen 8080;
        location / { return 200 "Hello, world!"; }
      }
    '';
  };

  enterTest = ''
    wait_for_port 8080
    curl -sf localhost:8080 | grep "Hello, world!"
  '';
}
```

`wait_for_port` is a shell function devenv injects only for `enterTest`, not a
general-purpose script — it is not available in `enterShell` or plain
`devenv shell`. For a process with a `readiness_probe` (above), prefer
`devenv processes wait` in scripts/CI outside of `enterTest`; inside
`enterTest`, `wait_for_port` is the simpler equivalent for a TCP/HTTP port.

```sh
devenv test                        # enterTest + git hooks
devenv test --override-dotfile     # isolated .devenv, for CI or parallel runs
```

`git-hooks.hooks.<name>.enable` configures pre-commit hooks (ruff, nixfmt,
shellcheck, prettier, …); `devenv test` runs them, so a green `devenv test` is a
reasonable definition of done for a repository that configures them.

Caching in CI:

```nix
cachix.enable = true;
cachix.pull = [ "pre-commit-hooks" ];
```

## Containers and devcontainers

```sh
devenv container build processes
devenv container copy processes --registry docker://ghcr.io/owner/
devenv container run processes
```

```nix
containers.processes.name = "app";
devcontainer.enable = true;    # generates .devcontainer.json
```

## Extra outputs

Expose derivations built from the environment definition:

```nix
outputs.docs = pkgs.runCommand "docs" { } "mkdir -p $out";
```

```sh
devenv build outputs.docs
```

## devenv inside a flake

A repository can drive devenv from `flake.nix` (`inputs.devenv.flakeModule` with
flake-parts, or `devenv.lib.mkShell`). Those shells generally require
`nix develop --impure`, because devenv reads project state outside the pure
evaluation. If a project is set up that way, follow its README rather than
adding a parallel `devenv.nix`.

## Housekeeping

```sh
devenv info          # resolved packages, env, processes, services
devenv gc            # delete old generations and free store space
devenv search <term> # nixpkgs search scoped to devenv options and packages
devenv repl          # inspect the evaluated configuration interactively
```

`direnv` users get auto-activation via `devenv direnvrc` / `.envrc` containing
`eval "$(devenv direnvrc)"` and `use devenv`; agents should keep using
`devenv shell -- <cmd>` explicitly instead of relying on it.
