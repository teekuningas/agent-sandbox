//! The order `ctl purge` does its work in, checked against a stub `podman`.
//!
//! Purge is a pipeline: each stage's removals are what make the next stage's
//! scan find anything. Removing exited sandboxes turns their sidecars into
//! orphans; removing orphaned sidecars turns their networks and directories
//! into reclaimable ones. Get the order wrong and every stage still passes its
//! own test while a single run stops reclaiming anything past the first --
//! which is exactly the bug the acceptance tier caught.
//!
//! Everything here runs `--dry-run` on purpose. Purge's directory scan reads
//! the real `/tmp`, and under a stub podman that answers "no such container"
//! to everything, a `--force` run would treat a live session's directories as
//! leaked and delete them. A test must not be able to do that to the machine
//! it runs on.

mod common;

use common::World;

/// A world whose stub answers the lookups purge makes: one container per `ps`,
/// one sidecar network, and "no such container" for every existence probe.
fn purgeable_world() -> World {
    World::new()
        .podman_reply("ps", "agent-sandbox-ws-quiet\n", 0)
        .podman_reply("network-ls", "agent-sandbox-sidecar-deadbeef\n", 0)
        .podman_reply("container-exists", "", 1)
}

fn position(calls: &[Vec<String>], pred: impl Fn(&[String]) -> bool) -> Option<usize> {
    calls.iter().position(|c| pred(c))
}

fn is_ps_for(call: &[String], filter: &str) -> bool {
    call.first().map(String::as_str) == Some("ps") && call.iter().any(|a| a == filter)
}

#[test]
fn exited_sandboxes_are_cleared_before_the_orphan_scan() {
    let out = purgeable_world().run(&["ctl", "purge", "--dry-run"]);

    let exited = position(&out.calls, |c| is_ps_for(c, "status=exited"))
        .unwrap_or_else(|| panic!("purge never looked for exited sandboxes: {:?}", out.calls));
    let orphans = position(&out.calls, |c| {
        is_ps_for(c, "label=agent-sandbox.role=proxy")
    })
    .unwrap_or_else(|| panic!("purge never looked for orphaned sidecars: {:?}", out.calls));

    assert!(
        exited < orphans,
        "a sidecar whose sandbox has exited but not yet been removed still looks \
         live, so scanning for orphans first leaves it -- and its network -- \
         behind until purge is run a second time\n--- calls ---\n{:?}",
        out.calls
    );
}

#[test]
fn networks_are_scanned_after_the_containers_that_hold_them_are_gone() {
    let out = purgeable_world().run(&["ctl", "purge", "--dry-run"]);

    let orphans = position(&out.calls, |c| {
        is_ps_for(c, "label=agent-sandbox.role=proxy")
    })
    .expect("purge never looked for orphaned sidecars");
    let networks = position(&out.calls, |c| {
        c.first().map(String::as_str) == Some("network") && c.get(1).map(String::as_str) == Some("ls")
    })
    .unwrap_or_else(|| panic!("purge never looked for leaked networks: {:?}", out.calls));

    assert!(
        orphans < networks,
        "a network whose sidecar is still present is not reclaimable, so the \
         network scan has to come after the sidecars are removed\n--- calls ---\n{:?}",
        out.calls
    );
}

#[test]
fn a_dry_run_removes_nothing_at_all() {
    let out = purgeable_world().run(&["ctl", "purge", "--dry-run"]);

    let destructive: Vec<&Vec<String>> = out
        .calls
        .iter()
        .filter(|c| {
            let head = c.first().map(String::as_str);
            head == Some("rm")
                || (head == Some("network") && c.get(1).map(String::as_str) == Some("rm"))
        })
        .collect();

    assert!(
        destructive.is_empty(),
        "--dry-run is the flag people reach for to find out what purge would \
         take away; it must not take anything: {:?}",
        destructive
    );
    assert!(
        out.stdout.contains("dry run"),
        "a dry run should say so: {}",
        out.stdout
    );
}

/// The session word is the name the launcher hands out, the only one the other
/// commands take back, and unique across sandboxes. Purge listed podman's
/// container name instead -- workspace-qualified and prefixed -- so what it
/// offered to remove was not what the reader had ever typed.
#[test]
fn sandboxes_are_listed_by_their_session_word() {
    let out = purgeable_world().run(&["ctl", "purge", "--dry-run"]);

    assert!(
        out.stdout.contains("\n  quiet\n"),
        "the sandbox was not listed by its session word: {}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("agent-sandbox-ws-quiet"),
        "the podman container name leaked into the listing: {}",
        out.stdout
    );
}

/// The networks purge reclaims are matched by name, and the name is the one
/// the launcher gives a session's sidecar. A prefix that stops matching is a
/// silent regression: purge keeps reporting success and reclaims nothing.
///
/// Matching is on the full name; only the printing drops the shared
/// `agent-sandbox-` prefix, so the reported name is the tail of the real one.
#[test]
fn only_sidecar_networks_are_considered() {
    let out = World::new()
        .podman_reply("ps", "", 0)
        .podman_reply(
            "network-ls",
            "podman\nbridge\nagent-sandbox-sidecar-deadbeef\nsome-other-net\n",
            0,
        )
        .podman_reply("container-exists", "", 1)
        .run(&["ctl", "purge", "--dry-run"]);

    assert!(
        out.stdout.contains("sidecar-deadbeef"),
        "the sidecar network was not recognised: {}",
        out.stdout
    );
    for foreign in ["podman", "bridge", "some-other-net"] {
        assert!(
            !out.stdout.contains(foreign),
            "purge proposed removing {}, which is not its to touch: {}",
            foreign,
            out.stdout
        );
    }
}
