//! `agent-sandbox browser` starts whether or not there is a sandbox to seed
//! its allow list from.
//!
//! The sandbox is an optional source of published ports, not a prerequisite:
//! the ordinary way to use this command is to start the browser first and the
//! sandbox against it afterwards. Every case here drives the real binary with
//! a stub podman, a stub proxy and a stub Chromium, so what is asserted is
//! what the command does end to end rather than what one function returns.

mod common;

use common::World;

/// Stands in for the host proxy. The browser waits for a `proxy-ready` marker
/// in the directory it passes as `--shared-dir` before it will start Chromium,
/// so a stub that never writes one turns every case here into a five-second
/// stall.
const STUB_PROXY: &str = r#"#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    --shared-dir) shift; : > "$1/proxy-ready" ;;
  esac
  shift
done
# Outlive Chromium; the browser's guard kills this on the way out.  `exec`, so
# the process the guard kills is this sleep and not a shell wrapped around it:
# a surviving grandchild holds the inherited stderr pipe open, and the test
# waits out the whole sleep rather than the command.
exec sleep 30
"#;

/// A Chromium that starts and exits cleanly, so the command runs to its own
/// end instead of the test having to interrupt it.
const STUB_CHROMIUM: &str = "#!/bin/sh\nexit 0\n";

fn browser_world() -> World {
    World::new()
        .stub_bin("agent-sandbox-proxy", STUB_PROXY)
        .stub_bin("chromium", STUB_CHROMIUM)
}

/// A sandbox is running -- for somewhere else. `ps` reports it and `inspect`
/// answers with a workspace that is not the one the browser is started from.
fn sandbox_running_elsewhere(world: World) -> World {
    world
        .podman_reply(
            "ps",
            "agent-sandbox-elsewhere-quiet\tUp 2 minutes\t2 minutes ago\n",
            0,
        )
        .podman_reply("inspect", "/some/other/workspace\n", 0)
}

/// The regression: resolving the sandbox to seed ports from used to go through
/// `resolve_sandbox`, which exits the process when it finds nothing. A guard
/// asked podman whether *anything* was running first -- but "something is
/// running" and "something is running here" are different questions, so a
/// sandbox belonging to another workspace sent the browser down the exiting
/// path and `agent-sandbox browser` died with a message about a sandbox the
/// operator had not asked for.
#[test]
fn a_sandbox_in_another_workspace_does_not_stop_the_browser() {
    let out = sandbox_running_elsewhere(browser_world()).run(&["browser"]);

    assert!(
        !out.stderr.contains("no sandbox running for current workspace"),
        "the browser refused to start over a sandbox it only wanted ports \
         from:\n--- stderr ---\n{}",
        out.stderr
    );
    assert_eq!(
        out.code,
        Some(0),
        "the browser did not run to completion\n--- stderr ---\n{}",
        out.stderr
    );
}

/// The case that always worked, kept so a fix to the one above cannot be a
/// blanket "never resolve a sandbox".
#[test]
fn no_sandbox_at_all_does_not_stop_the_browser() {
    let out = browser_world().podman_reply("ps", "", 0).run(&["browser"]);

    assert_eq!(
        out.code,
        Some(0),
        "the browser did not run to completion\n--- stderr ---\n{}",
        out.stderr
    );
}

/// Naming a sandbox is a claim that it exists. The browser still starts --
/// a thinner allow list is not a reason to refuse -- but silently ignoring
/// the name would leave the operator waiting for ports that were never
/// seeded.
#[test]
fn a_named_sandbox_that_cannot_be_found_is_said_out_loud() {
    let out = browser_world()
        .podman_reply("ps", "", 0)
        .podman_reply("inspect", "", 1)
        .run(&["browser", "nosuchword"]);

    assert!(
        out.stderr.contains("nosuchword"),
        "the browser said nothing about the sandbox it was pointed at:\n\
         --- stderr ---\n{}",
        out.stderr
    );
    assert_eq!(
        out.code,
        Some(0),
        "a sandbox that cannot be found is a note, not a failure\n\
         --- stderr ---\n{}",
        out.stderr
    );
}
