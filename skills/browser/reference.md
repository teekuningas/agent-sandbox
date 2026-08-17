# Browser — advanced patterns

Read `SKILL.md` first. The headless sections assume `playwright-python` is
what you reach for; this file covers what it wraps and when to bypass it.

## The raw `nix build`/`nix shell` invocation

`playwright-python script.py` (see `SKILL.md`) is this, wrapped into one
command:

```sh
export PLAYWRIGHT_BROWSERS_PATH=$(nix build --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}; playwright-driver.browsers' \
  --no-link --print-out-paths) && \
nix shell --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}; python3.withPackages (ps: [ ps.playwright ])' \
  --command python3 script.py
```

Reach for this instead of the wrapper when the shell needs more than
`python3` + Playwright — extra fonts (below), other packages — or when
running outside this image, where `playwright-python` isn't on `PATH`.
**Don't rely on the `export` surviving into a later tool call** — if your
next command is a separate shell invocation, this variable is gone. Keep it
and whatever uses it in one invocation, or write it into the script/session
you're about to run rather than a throwaway shell line.

## Fonts, in full

The image ships `dejavu_fonts` and `liberation_ttf` and sets `FONTCONFIG_FILE`,
which covers Latin text. It does not ship a full desktop font set: CJK,
Arabic, Devanagari and emoji all render as boxes or nothing.

`pkgs.makeFontsConf` is nixpkgs' own helper for this (it's what NixOS's
headless-browser tests use) — it builds a `fonts.conf` pointing at the font
packages you give it, with no need for a real `/etc/fonts` to exist:

```sh
nix build --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
   makeFontsConf { fontDirectories = [ dejavu_fonts liberation_ttf noto-fonts-color-emoji ]; }' \
  --no-link --print-out-paths
```

Add `noto-fonts-color-emoji` (or other script-specific font packages) if the
pages you're rendering need non-Latin scripts or emoji.

Note that a `nix shell --command` inherits `FONTCONFIG_FILE` from the
environment, so the image's value applies unless something overrides it. To
debug font resolution directly, add `fontconfig` to a `nix shell` and run
`fc-list` — it lists every font the active config wired in.

## Filling forms, waiting, multiple tabs

```python
page.fill("#email", "user@example.com")
page.select_option("#country", label="Finland")
page.check("#agree-to-terms")

page.wait_for_selector("text=Loading…", state="hidden")
page.wait_for_url("**/dashboard")

# a second tab/popup opened by the page
with page.expect_popup() as popup_info:
    page.click("a[target=_blank]")
popup = popup_info.value
popup.wait_for_load_state()
```

`page.goto(url, wait_until=...)` accepts `"load"`, `"domcontentloaded"`, or
`"networkidle"` — prefer `"load"` for typical pages; `"networkidle"` is slower
and unnecessary unless the page keeps polling in the background.

## PDF export

Only Chromium supports it (`p.chromium`, not `p.firefox`/`p.webkit`), and only
in headless mode:

```python
page.pdf(path="page.pdf", format="A4")
```

## Output directory

Write screenshots, traces, and PDFs to a fixed scratch directory rather than
scattering them wherever a script happens to run — `/tmp/playwright-output`
is a reasonable default. Create it fresh at the top of a script:

```python
import os
import shutil
OUTPUT_DIR = "/tmp/playwright-output"
shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
os.makedirs(OUTPUT_DIR)
```

This is container-local, not a host mount — it disappears with the session.
Read results back with the agent's own tools (e.g. Claude Code's `Read` for a
screenshot) before the session ends rather than expecting the directory to
persist.

## Raw CDP fallback

If Playwright itself is undesirable (want the browser process directly, or the
Python/driver combo is broken), Chromium can be driven over the Chrome
DevTools Protocol without Playwright:

```sh
nix shell --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
   [ chromium fontconfig dejavu_fonts liberation_ttf ]' \
  --command chromium --headless=new --no-sandbox --disable-dev-shm-usage \
  --remote-debugging-port=9222 --remote-debugging-address=127.0.0.1
```

This exposes a WebSocket CDP endpoint (`http://127.0.0.1:9222/json/version`
lists it) — but you still need a CDP client to do anything with it (e.g.
Playwright's own `chromium.connect_over_cdp(...)`, or a raw websocket library
sending `Page.navigate` / `Page.captureScreenshot` calls by hand). This is
materially more work than launching through Playwright directly and is a last
resort, not a default.

## Version skew between playwright and playwright-driver

On nixpkgs-unstable these can drift by a patch release — observed live:
`python3Packages.playwright` at `1.61.0` while `playwright-driver` (and hence
`playwright-driver.browsers`) was already at `1.61.1`. This is expected, not a
bug to chase: the Python package always symlinks its driver to whatever
`playwright-driver` currently resolves to in the same nixpkgs snapshot
(`pkgs/development/python-modules/playwright/default.nix`), and both carry a
`skipBulkUpdate` marker specifically so they get bumped together by the
project's own update script. A one-patch gap between snapshots doesn't break
anything in practice. If exact reproducibility ever matters (e.g. pinned CI),
pin the whole expression to one nixpkgs revision instead of trying to pin the
two packages independently:

```sh
nix build --impure --expr \
  'with (builtins.getFlake "nixpkgs/nixos-25.05").legacyPackages.${builtins.currentSystem}; ...'
```

## A browser the user already had open

`agent-sandbox browser` is the path to prefer: it is disposable, it carries an
allow list, and it prints the relaunch line. But the user may have their own
Chrome open already — with their logins, their extensions, a session they do
not want to recreate — and want *that* driven.

That browser is not policed by anything. What it fetches is on their account,
and `--host-loopback-port` is a channel the sandbox's proxy never sees. Say so
when suggesting it, and treat it as the exception.

They need two things, in one message:

```sh
google-chrome --user-data-dir=/tmp/cdp-profile \
              --remote-debugging-port=9222 \
              --remote-debugging-address=127.0.0.1
# or chromium, same flags
```

```sh
agent-sandbox --host-loopback-port 9222 -- <their usual command>
```

The separate `--user-data-dir` is **required**, not optional: Chrome 136+
refuses `--remote-debugging-port` on the default profile outright, and an
already-running Chrome silently ignores the flag. Keep
`--remote-debugging-address` on `127.0.0.1`, never `0.0.0.0` — CDP has no
authentication, so reachability is the only thing standing between "the sandbox
can drive this tab" and "anything on the network can read every cookie and run
arbitrary JS in it."

If the sandbox already has something on 9222, the user can move the inside
number: `--host-loopback-port 9222:19222` puts the host's 9222 on the sandbox's
19222, and `$AGENT_SANDBOX_HOST_PORTS` then lists `19222`.

Attach with `connect_over_cdp` exactly as in `SKILL.md`.

## Debugging checklist

| Symptom | Cause | Fix |
| --- | --- | --- |
| Screenshot is a flat, uniform color | no usable fonts | check `$FONTCONFIG_FILE` and `fc-list`; rebuild it with the scripts the page needs (see above) |
| `page.goto()` hangs or times out | proxied sandbox denying the host | check `$HTTPS_PROXY`, pass it explicitly, ask for `ctl proxy allow` |
| "Failed to move to new namespace" / renderer crash | container can't create Chromium's own sandbox | add `--no-sandbox` to `launch(args=[...])` |
| Renderer crashes under load, blank/partial screenshot | `/dev/shm` too small (often 64 MB in containers) | add `--disable-dev-shm-usage` |
| `browserType.launch` complains about a missing executable | `PLAYWRIGHT_BROWSERS_PATH` unset — running raw `python3` instead of `playwright-python`, or `export`ed in a separate tool call that didn't carry into this one | use `playwright-python`, or re-derive it in the *same* command as the failing one, see `SKILL.md` |
| `$AGENT_SANDBOX_HOST_PORTS` is unset, or missing the port | launched without `--browser`, so nothing reaches the host's `127.0.0.1:9222` | ask the user to run `agent-sandbox browser`, then relaunch with `--browser`, see `SKILL.md` |
| `connect_over_cdp` refuses/times out with the port listed | the channel exists, so nothing is listening on the host's `127.0.0.1:9222` | the browser was closed, or a hand-started Chrome had no separate `--user-data-dir` |
| `$AGENT_SANDBOX_BROWSER_CDP_PORT` is unset even though the port is reachable | relaunched with a bare `--host-loopback-port` instead of `--browser` | use `--browser`, or add the variable with `-e` |
| Only one browser reachable when two were started | the second was started after the sandbox, so `--browser` never saw it | start every browser before the sandbox; the channel is set at launch |
| `ctl proxy … --browser` says several browsers are running | more than one session, so the target is ambiguous | name one: `--browser alice` |
| A page in the host browser fails to load, `curl` from here reaches it | the browser's allow list is separate from the sandbox's | `agent-sandbox ctl proxy allow <host>:443 --browser` |
| `socat` reports it could not bind, or the port answers the wrong service | something in the sandbox already listens on that number | relaunch with `--host-loopback-port 9222:19222` and dial 19222 inside |
| `host.containers.internal` refuses even though the host's service is up | that name is podman's `--map-guest-addr`, which resolves to the host's *LAN* address, not its loopback | bind the host service to `0.0.0.0` to use that name, or map it with `--host-loopback-port` for a loopback-bound one |
