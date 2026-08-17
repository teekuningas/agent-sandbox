---
name: browser
description: Drive a browser to screenshot a page for visual/image analysis or to interact with it (navigate, click, fill, wait) — either headless inside the sandbox, or a visible browser on the user's host over CDP. Trigger when asked to look at a rendered web page, verify what a UI looks like, screenshot a site, automate clicks/form-fills against a page, or work in a real browser the user can watch and click along with.
compatibility: opencode
metadata:
  workflow: headless-browser-automation
  audience: developers-and-agents
---

## Before you start

- **Default to headless** unless the task needs a window the user can watch or
  click in themselves.
- **Never run `playwright install`** — the nixpkgs driver is already paired
  with the Python package; that command tries to hit a CDN and isn't needed.
- **Use `playwright-python script.py`**, not a raw `python3` call — it derives
  `PLAYWRIGHT_BROWSERS_PATH` and runs your script in one shot, so there's
  nothing to `export` and lose to the next tool call. The raw derivation still
  matters if you need extra fonts or are running outside this image — see
  below and `reference.md`.
- **Bind a server behind a published port to `0.0.0.0`**, not `127.0.0.1` —
  publishing forwards to the sandbox's interface address, not its loopback.
- A denied host is the sandbox's egress policy working as intended — ask the
  user for `ctl proxy allow`, don't unset the proxy or add a browser-level
  proxy of your own to route around it.

# Two browsers, and which one you want

| | Headless, in here | Cooperative, on the host |
| --- | --- | --- |
| Needs the user to do anything | no | yes, once |
| The user can watch and click | no | yes |
| Real fonts, GPU, their logins | no | yes |
| Egress policy | the sandbox's `--proxy` policy | a separate allow list of its own |
| Start it with | `playwright-python`, below | ask the user to run `agent-sandbox browser` |

**Default to headless.** It needs nothing from the user, so it costs no round
trip. Reach for the host browser only when the task actually needs a visible
window — the user watching, clicking things themselves between your calls, or a
page that only behaves in their real browser.

---

# Headless, inside the sandbox

Pull a browser and its driver from nixpkgs for the duration of one script or
session — same philosophy as the `nix` skill, no host install.
`python3Packages.playwright` is the scripting API and
`playwright-driver.browsers` the actual chromium / firefox / webkit binaries.
The Python package's driver is symlinked to nixpkgs' own `playwright-driver` at
build time, so the two are always protocol-compatible — never run `playwright
install`, it tries to hit a CDN and isn't needed.

## Get the browser

```sh
playwright-python script.py
```

`playwright-python` is on the image `PATH`. It derives `PLAYWRIGHT_BROWSERS_PATH`
and execs `python3` with the matching Playwright package, both in the one
process — the env var never has to survive into a separate tool call. The
underlying build resolves to a cached, content-addressed store path, so
re-running this costs nothing after the first time within a session.

Under `--proxy`, that first run needs `cache.nixos.org:443` allowed — the same
requirement any other on-demand nixpkgs fetch has under the sandbox's egress
policy (see the `nix` skill). Ask the user for `ctl proxy allow` if it's
denied.

For the raw `nix build`/`nix shell` invocation instead — extra fonts, or
running outside this image — see `reference.md`.

## Fonts

The image ships a minimal font set (DejaVu and Liberation) and exports
`FONTCONFIG_FILE`, so screenshots taken from anything that inherits the image
environment render text correctly.

Two cases still need attention:

- **A `nix shell` that overrides `FONTCONFIG_FILE`, or a page needing scripts
  those two fonts don't cover** (CJK, emoji). Build a config with the fonts you
  need:

  ```sh
  export FONTCONFIG_FILE=$(nix build --impure --expr \
    'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
     makeFontsConf { fontDirectories = [ dejavu_fonts liberation_ttf noto-fonts-color-emoji ]; }' \
    --no-link --print-out-paths)
  ```

  This is the manual/advanced path, so the same caveat as the raw
  `PLAYWRIGHT_BROWSERS_PATH` derivation in `reference.md` applies: chain this
  into the same command as the script that needs it, don't `export` it as a
  standalone step.

- **Knowing the failure mode.** With no usable fonts, headless Chromium fails
  *silently*: `page.goto()` succeeds, `page.title()` and `page.content()` return
  correct data, and `page.screenshot()` comes back a flat, uniform colour — no
  error, no crash. If a screenshot is one solid colour, suspect fonts before
  anything else. `echo $FONTCONFIG_FILE` and `fc-list` say which fonts are
  actually wired in.

## Wait for the app

Navigating before the target is actually listening produces a stale tab
followed by `ERR_EMPTY_RESPONSE` — easy to mistake for a browser problem when
it's really a timing one. Wait for a real response first:

```sh
for i in $(seq 1 30); do
  curl -sf http://127.0.0.1:8000/ >/dev/null && break
  sleep 1
done
```

Adjust the URL and port to whatever the app under test actually serves.

## Script it: navigate, screenshot, click

```sh
playwright-python script.py
```

```python
# script.py
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage"],  # container defaults
    )
    page = browser.new_page(viewport={"width": 1280, "height": 800})

    # Attach before navigating -- messages logged during page.goto() itself
    # are otherwise missed.
    page.on("console", lambda msg: print(f"[{msg.type}] {msg.text}"))
    page.on("pageerror", lambda exc: print(f"pageerror: {exc}"))
    page.on("requestfailed", lambda req: print(f"failed: {req.url} {req.failure}"))

    page.goto("https://example.com", wait_until="load")

    page.screenshot(path="page.png")              # for visual/image analysis
    print(page.locator("body").aria_snapshot())    # text-only accessibility tree

    page.click("text=Learn more")
    page.wait_for_load_state("load")

    browser.close()
```

`msg.type` is `"log"` / `"warning"` / `"error"` / etc.; `msg.text` is the
formatted message. This is the way to see what a page's own script is doing —
network failures, thrown exceptions, `console.log` debugging output — the
same signal DevTools' console gives a human, and it's cheap enough to leave in
by default rather than adding only after something looks wrong.

Then read `page.png` with your own image-viewing tool (e.g. Claude Code's
`Read`) to actually look at it — this skill gets the pixels on disk, not in
front of the model. Prefer `aria_snapshot()` or `page.content()` over a
screenshot when the task is pure text/structure, not appearance — it's cheaper
and immune to the fonts gotcha.

## Sandbox network

This is `agent-sandbox`: a proxied session firewalls all egress
deny-by-default (see the `agent-sandbox` skill and its `network.md`). A
headless browser makes requests to whatever host the page needs, and those are
blocked the same as any other request. Check first:

```sh
env | grep -i '^https\?_proxy'
```

If set, pass it to Playwright explicitly rather than relying on it being
picked up automatically:

```python
import os
proxy = {"server": os.environ["HTTPS_PROXY"]} if os.environ.get("HTTPS_PROXY") else None
browser = p.chromium.launch(headless=True, proxy=proxy, args=[...])
```

A denied host is policy working as configured — ask the user to run
`agent-sandbox ctl proxy allow <host>:443` on the host, the same escalation the
`agent-sandbox` skill teaches. Don't unset the proxy or add `--no-proxy-server`
to route around it.

---

# A visible browser: `agent-sandbox browser` on the host

There's no X server in here, so a headed browser has to run on the **host**,
with this side as a CDP *client*. `agent-sandbox browser` starts one that is
disposable and carries an allow list of its own, and prints the line the user
needs to paste.

## Ask the user for one thing

The sandbox flag can only be set at launch, so this needs a relaunch either
way. Give them the whole thing in one message:

> Run `agent-sandbox browser` in another terminal, then relaunch the sandbox
> with `--browser` added to whatever flags you already use:
> `agent-sandbox --browser -- claude`.

What they'll see:

```
$ agent-sandbox browser
browser: 'e4c1a80f' -- CDP on 127.0.0.1:9222, egress deny-by-default
browser: allowed: 127.0.0.1:3000
browser:   agent-sandbox ctl proxy allow <host>:443 --browser e4c1a80f
browser:
browser: now run, keeping whatever flags you already use:
browser:   agent-sandbox --browser -- claude
```

`--browser` attaches whatever browsers are running: it maps their CDP ports and
tells the agent which is which, via `$AGENT_SANDBOX_BROWSER_CDP_PORT` (see
below).

If they don't have Chromium on their host, `nix run
github:datakurre/agent-sandbox#browser` runs it with a pinned one.

## What it can reach

With no arguments the browser's allow list is **the loopback ports the running
sandbox publishes, and nothing else** — so it can load the app under test and
not the internet. That is the common case for UI work and needs no
configuration.

Anything wider is opt-in, and the escalation is the same shape as everywhere
else — ask the user, don't route around it:

```sh
agent-sandbox ctl proxy allow example.com:443 --browser   # applies within a second, no restart
agent-sandbox browser --allow example.com:443             # or up front, at start
agent-sandbox browser --proxy-profile development         # or a reusable profile
```

A denied host shows up as a failed request in the page, and appears in the
traffic summary the command prints when the browser closes.

## Check the channel before dialing

The launcher sets `$AGENT_SANDBOX_HOST_PORTS` to the ports it mapped, and only
those:

```sh
case ",$AGENT_SANDBOX_HOST_PORTS," in
  *,9222,*) ;;
  *) echo "ask the user to run: agent-sandbox browser"; exit 1 ;;
esac
curl -s http://127.0.0.1:9222/json/version
```

Port missing from the list means this session has no channel to it — say so and
ask for the relaunch, rather than guessing at other ports.

## Drive it: connect over CDP

With `AGENT_SANDBOX_BROWSER_CDP_PORT` set, connect a Playwright script
directly to that port. A remote connection, not a local launch, so
`PLAYWRIGHT_BROWSERS_PATH` and `FONTCONFIG_FILE` aren't needed:

```python
from playwright.sync_api import sync_playwright

p = sync_playwright().start()
browser = p.chromium.connect_over_cdp("http://127.0.0.1:9222")
page = browser.contexts[0].pages[0]     # the browser's already-open tab
page.goto("http://127.0.0.1:3000")
```

Dialing `127.0.0.1` also sidesteps Chrome's DevTools host check, which rejects a
`Host:` header that is not an IP or `localhost`.

## Two users at once

A separate profile is a separate user, so testing an interaction between two
people — a shared document, a chat, a buyer and a seller — means asking for two
browsers rather than one:

> Run these two, then use the command the **second** one prints:
>
> ```sh
> agent-sandbox browser --name alice --keep-profile ~/.cache/browsers/alice
> agent-sandbox browser --name bob   --keep-profile ~/.cache/browsers/bob
> ```

Then the same `agent-sandbox --browser -- claude` as always: `--browser` picks
up every browser that is running, so the command does not grow with the number
of users. Ports walk up from 9222, so alice is 9222 and bob is 9223.

Ask for both up front. The channel is established at launch, so a second browser
started after the sandbox is not reachable until the next relaunch — which is
the one round trip worth avoiding.

With two attached, alice is on 9222 and bob on 9223 (see above) — say which
user you are acting as by choosing the port you connect to. From a script,
hold both connections at once:

```python
alice = p.chromium.connect_over_cdp("http://127.0.0.1:9222")
bob   = p.chromium.connect_over_cdp("http://127.0.0.1:9223")
a_page, b_page = alice.contexts[0].pages[0], bob.contexts[0].pages[0]
a_page.fill("#message", "hello"); a_page.click("text=Send")
b_page.reload()                                    # bob should now see it
```

`--keep-profile` is what makes a login survive: without it every session starts
signed out, which is right for a disposable browser and wrong for a scenario you
re-run. Each session also has its own allow list —
`agent-sandbox ctl proxy allow <host>:443 --browser alice` widens only alice.

## What this does and does not bound

The browser's allow list governs what that browser fetches. It is a **separate**
policy from the sandbox's — widening one does not widen the other, and a host
allowed there is not allowed for a `curl` from in here.

It is also not absolute. Don't try to get around it: creating a browser context
with a proxy of its own, or otherwise working around the allow list, is the
same category of thing as unsetting `HTTPS_PROXY`. If a host is denied, ask.

## Serving to it

To point that browser at a server running *in* the sandbox, publish a port —
that is also what seeds the allow list, so the two fit together:

```sh
agent-sandbox --ports --browser -- bash
```

Bind that server to `0.0.0.0` inside the sandbox: publishing forwards to the
sandbox's interface address, so a loopback-bound one is reachable from inside
and dead from the host.

## More

`reference.md` covers form filling and waiting, multiple tabs, PDF export, the
raw CDP fallback, driving a browser the user already had open (rather than one
`agent-sandbox browser` started), a version-skew note between
`python3Packages.playwright` and `playwright-driver` on nixpkgs-unstable, the
raw `nix build`/`nix shell` invocation `playwright-python` wraps, an output
directory convention, and a debugging checklist.
