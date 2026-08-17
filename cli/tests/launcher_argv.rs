//! The flag -> `podman run` mapping, checked against a stub `podman`.
//!
//! This is the layer between the argument parser and the container runtime:
//! unit tests cover the fragments `launch.rs` and `agents.rs` produce, and the
//! integration suite covers what a real container does with them, but nothing
//! covered *which* fragments the launcher assembles for a given command line.
//! That is what breaks when a flag is added and wired to the wrong block.

mod common;

use common::{World, TEST_IMAGE};

// ── the shape every launch has ──────────────────────────────────────────────

#[test]
fn a_bare_launch_runs_the_default_shell_in_a_disposable_container() {
    let out = World::new().run(&[]);
    let run = out.run_call();

    assert!(
        run.has("--rm"),
        "sandboxes are disposable: {}",
        run.joined()
    );
    assert!(run.has("--userns=keep-id"), "{}", run.joined());
    assert_eq!(run.value_of("--workdir"), Some("/workspace"));
    assert_eq!(run.command(), vec!["bash"]);
}

#[test]
fn every_launch_is_labelled_so_ctl_can_find_it_without_guessing() {
    let out = World::new().run(&["opencode"]);
    let run = out.run_call();
    let labels = run.values_of("--label");

    assert!(labels.contains(&"agent-sandbox.role=sandbox"));
    assert!(labels.contains(&"agent-sandbox.proxy=off"));
    assert!(labels.contains(&"agent-sandbox.runtime=crun"));
    assert!(labels.contains(&"agent-sandbox.command=opencode ."));
}

#[test]
fn the_image_is_the_last_argument_before_the_agent_command() {
    let out = World::new().run(&["opencode"]);
    let run = out.run_call();
    let idx = run.0.iter().position(|a| a == TEST_IMAGE).expect("image");

    assert_eq!(
        run.0.len() - idx - 1,
        run.command().len(),
        "everything after the image is the agent's own command line: {}",
        run.joined()
    );
}

#[test]
fn the_launcher_forwards_podmans_exit_code() {
    let world = World::new().podman_reply("run", "", 42);
    assert_eq!(world.run(&["opencode"]).code, Some(42));
}

// ── --workspace ─────────────────────────────────────────────────────────────

#[test]
fn without_workspace_nothing_from_the_host_is_mounted_and_no_workspace_is_labelled() {
    let out = World::new().run(&[]);
    let run = out.run_call();

    assert!(
        !run.values_of("--label")
            .iter()
            .any(|l| l.starts_with("agent-sandbox.workspace=")),
        "an unmounted sandbox has no workspace to record: {}",
        run.joined()
    );
    assert!(
        run.values_of("-v")
            .iter()
            .all(|m| m.contains("/etc/passwd") || m.contains("/etc/group")),
        "only the synthesized passwd/group files: {}",
        run.joined()
    );
}

#[test]
fn workspace_mounts_the_cwd_under_its_own_basename_and_works_there() {
    let world = World::new();
    let ws = world.workspace().display().to_string();
    let out = world.run(&["--workspace", "opencode"]);
    let run = out.run_call();

    assert_eq!(run.value_of("--workdir"), Some("/workspace/ws"));
    assert_eq!(
        run.mount_to("/workspace/ws"),
        Some(format!("{}:/workspace/ws:rw", ws).as_str()),
        "{}",
        run.joined()
    );
    assert!(run
        .values_of("--label")
        .contains(&format!("agent-sandbox.workspace={}", ws).as_str()));
}

#[test]
fn no_workspace_cancels_a_workspace_that_came_earlier_on_the_line() {
    let out = World::new().run(&["--workspace", "--no-workspace", "opencode"]);
    assert_eq!(out.run_call().value_of("--workdir"), Some("/workspace"));
}

// ── agent selection and its persisted state ─────────────────────────────────

#[test]
fn each_agent_gets_its_own_command() {
    let world = World::new();
    assert_eq!(
        world.run(&["opencode"]).run_call().command(),
        vec!["opencode", "."]
    );
    assert_eq!(
        world.run(&["claude"]).run_call().command(),
        vec!["claude"]
    );
}

#[test]
fn only_the_selected_agents_state_is_mounted() {
    let out = World::new().run(&["claude"]);
    let run = out.run_call();

    assert!(
        run.mount_to("/home/user/.claude").is_some(),
        "{}",
        run.joined()
    );
    assert!(
        run.mount_to("/home/user/.config/opencode").is_none(),
        "another agent's state must not follow along: {}",
        run.joined()
    );
}

#[test]
fn agent_state_files_are_created_on_the_host_so_the_bind_is_a_file_not_a_directory() {
    let world = World::new();
    let out = world.run(&["claude"]);

    assert!(out.run_call().mount_to("/home/user/.claude.json").is_some());
    assert!(
        world.home().join(".claude.json").is_file(),
        "podman would otherwise create a directory in its place"
    );
}

#[test]
fn agent_mounts_all_carries_every_agents_state() {
    let out = World::new().run(&["--agent-mounts", "opencode"]);
    let run = out.run_call();

    assert!(
        run.mount_to("/home/user/.claude").is_some(),
        "{}",
        run.joined()
    );
    assert!(run.mount_to("/home/user/.config/opencode").is_some());
}

#[test]
fn agent_mounts_none_starts_the_agent_with_no_history() {
    let out = World::new().run(&["--no-agent-mounts", "opencode"]);
    let run = out.run_call();

    assert!(
        run.mount_to("/home/user/.config/opencode").is_none(),
        "{}",
        run.joined()
    );
    assert_eq!(run.command(), vec!["opencode", "."]);
}

// ── the writable home ───────────────────────────────────────────────────────

#[test]
fn the_writable_home_subdirectories_are_tmpfs_owned_by_the_mapped_user() {
    let out = World::new().run(&[]);
    let run = out.run_call();
    let mounts = run.values_of("--mount");

    for dir in [".config", ".cache", ".local"] {
        let want = format!("type=tmpfs,dst=/home/user/{},U=true", dir);
        assert!(
            mounts.contains(&want.as_str()),
            "{} is missing from {:?}",
            want,
            mounts
        );
    }
}

// ── SELinux ─────────────────────────────────────────────────────────────────

#[test]
fn selinux_relabels_shared_binds_and_privately_labels_the_synthesized_files() {
    let out = World::new().run(&["--workspace", "--selinux", "opencode"]);
    let run = out.run_call();

    assert!(
        run.mount_to("/workspace/ws").unwrap().ends_with(":rw,z"),
        "a shared bind takes the shared label: {}",
        run.joined()
    );
    assert!(
        run.values_of("-v")
            .iter()
            .find(|m| m.contains(":/etc/passwd:"))
            .unwrap()
            .ends_with(":ro,Z"),
        "a private file takes the private label: {}",
        run.joined()
    );
}

#[test]
fn without_selinux_no_relabelling_flag_is_added() {
    let out = World::new().run(&["--workspace", "opencode"]);
    assert_eq!(
        out.run_call()
            .mount_to("/workspace/ws")
            .unwrap()
            .rsplit(':')
            .next(),
        Some("rw")
    );
}

// ── declared ports ──────────────────────────────────────────────────────────

const PORTS_AGENTS_MD: &str = "\
# Test project

```toml agent-sandbox
[ports]
web = 3000
api = { container = 8080, host = 18080 }
```
";

#[test]
fn declared_ports_are_ignored_until_ports_is_passed() {
    let out = World::new()
        .file("AGENTS.md", PORTS_AGENTS_MD)
        .run(&["--workspace", "opencode"]);

    assert!(
        out.run_call().values_of("-p").is_empty(),
        "AGENTS.md must not open a port on its own: {}",
        out.run_call().joined()
    );
}

#[test]
fn ports_publishes_the_declared_mappings_on_loopback_by_default() {
    let out = World::new().file("AGENTS.md", PORTS_AGENTS_MD).run(&[
        "--workspace",
        "--ports",
        "opencode",
    ]);
    let run = out.run_call();
    let published = run.values_of("-p");

    assert!(
        published.contains(&"127.0.0.1:3000:3000/tcp"),
        "{:?}",
        published
    );
    assert!(
        published.contains(&"127.0.0.1:18080:8080/tcp"),
        "{:?}",
        published
    );
}

#[test]
fn a_wider_bind_needs_the_flag_that_names_the_risk() {
    let agents_md = "\
```toml agent-sandbox
[ports]
web = { container = 3000, bind = \"0.0.0.0\" }
```
";
    let world = World::new().file("AGENTS.md", agents_md);

    let refused = world.run(&["--workspace", "--ports", "opencode"]);
    assert!(
        !refused.reached_podman_run(),
        "a bind past loopback must not be taken from AGENTS.md alone"
    );

    let allowed = world.run(&[
        "--workspace",
        "--ports",
        "--ports-any-interface",
        "opencode",
    ]);
    assert!(allowed
        .run_call()
        .values_of("-p")
        .contains(&"0.0.0.0:3000:3000/tcp"));
}

// ── declared mounts ─────────────────────────────────────────────────────────

#[test]
fn declared_mounts_are_ignored_until_mounts_is_passed() {
    let world = World::new()
        .file(
            "AGENTS.md",
            "```toml agent-sandbox\n[mounts]\n\"data\" = \"/workspace/data\"\n```\n",
        )
        .file("data/keep", "");

    let without = world.run(&["--workspace", "opencode"]);
    assert!(without.run_call().mount_to("/workspace/data").is_none());

    let with = world.run(&["--workspace", "--mounts", "opencode"]);
    assert!(
        with.run_call().mount_to("/workspace/data").is_some(),
        "{}",
        with.run_call().joined()
    );
}

#[test]
fn a_declared_mount_keeps_the_options_it_declared() {
    let out = World::new()
        .file(
            "AGENTS.md",
            "```toml agent-sandbox\n[mounts]\n\"cache\" = { destination = \"/tmp/cache\", options = \"ro\" }\n```\n",
        )
        .file("cache/keep", "")
        .run(&["--workspace", "--mounts", "opencode"]);

    assert!(
        out.run_call()
            .mount_to("/tmp/cache")
            .unwrap()
            .ends_with(":ro"),
        "{}",
        out.run_call().joined()
    );
}

// ── passthrough ─────────────────────────────────────────────────────────────

#[test]
fn podman_args_reach_podman_verbatim_and_after_the_launchers_own() {
    let out = World::new().run(&["--podman-args", "-p", "9000:9000", "--", "opencode"]);
    let run = out.run_call();

    assert!(
        run.values_of("-p").contains(&"9000:9000"),
        "an operator's publish is not rewritten to loopback: {}",
        run.joined()
    );

    let passthrough = run.0.iter().position(|a| a == "9000:9000").unwrap();
    let image = run.0.iter().position(|a| a == TEST_IMAGE).unwrap();
    assert!(
        passthrough < image,
        "passthrough belongs to podman, not the agent"
    );
}

#[test]
fn env_is_forwarded_in_both_spellings() {
    let out = World::new().run(&["-e", "FOO=1", "--env=BAR=2", "opencode"]);
    let run = out.run_call();

    assert_eq!(run.env_value("FOO"), Some("1"));
    assert_eq!(run.env_value("BAR"), Some("2"));
}

#[test]
fn the_terminal_type_follows_the_host_into_the_container() {
    let out = World::new()
        .env("TERM", "screen-256color")
        .run(&["opencode"]);
    assert_eq!(out.run_call().env_value("TERM"), Some("screen-256color"));
}

// ── refusals: the flags that must not be silently combined ──────────────────

#[test]
fn proxy_refuses_host_networking_smuggled_through_podman_args() {
    for spec in [
        vec!["--podman-args", "--network", "host", "--"],
        vec!["--podman-args", "--network=host", "--"],
    ] {
        let mut args = vec!["--workspace", "--proxy"];
        args.extend(spec.iter());
        args.push("opencode");

        let out = World::new().run(&args);
        assert!(
            !out.reached_podman_run(),
            "host networking defeats the firewall entirely: {:?}",
            args
        );
        assert!(out.stderr.contains("host networking"), "{}", out.stderr);
    }
}

#[test]
fn krun_and_podman_are_refused_together() {
    let out = World::new().run(&["--krun", "--podman", "opencode"]);

    assert!(!out.reached_podman_run());
    assert!(out.stderr.contains("--krun"), "{}", out.stderr);
}

#[test]
fn an_unknown_flag_stops_the_launch_rather_than_reaching_podman() {
    let out = World::new().run(&["--definitely-not-a-flag", "opencode"]);

    assert!(!out.reached_podman_run());
    assert!(out.failed());
    assert!(
        out.stderr.contains("is not an agent-sandbox flag"),
        "{}",
        out.stderr
    );
}

#[test]
fn a_removed_flag_says_what_replaced_it() {
    let out = World::new().run(&["--port", "3000", "opencode"]);

    assert!(!out.reached_podman_run());
    assert!(
        out.stderr.contains("[ports]") && out.stderr.contains("--ports"),
        "a removed flag should name its replacement: {}",
        out.stderr
    );
}

#[test]
fn an_invalid_network_block_refuses_the_launch_under_proxy() {
    let out = World::new()
        .file(
            "AGENTS.md",
            "```toml agent-sandbox\n[network]\nallowed_hostz = [\"example.com:443\"]\n```\n",
        )
        .run(&["--workspace", "--proxy", "opencode"]);

    assert!(
        !out.reached_podman_run(),
        "a policy that does not parse must never be downgraded to no policy"
    );
    assert!(out.failed());
}

#[test]
fn network_rules_without_proxy_warn_rather_than_pretending_to_enforce() {
    let out = World::new()
        .file(
            "AGENTS.md",
            "```toml agent-sandbox\n[network]\nallowed_hosts = [\"example.com:443\"]\n```\n",
        )
        .run(&["--workspace", "opencode"]);

    assert!(
        out.reached_podman_run(),
        "no proxy is not an error, only a warning"
    );
    assert!(
        out.stderr.contains("--proxy"),
        "the warning must name the flag that would enforce them: {}",
        out.stderr
    );
    assert!(
        out.run_call()
            .values_of("--label")
            .contains(&"agent-sandbox.proxy=off"),
        "and the container records that it is unproxied"
    );
}

// ── krun ────────────────────────────────────────────────────────────────────

#[test]
fn krun_selects_the_vm_runtime_and_records_it_on_the_container() {
    let out = World::new().run(&[
        "--krun",
        "--krun-memory",
        "4096",
        "--krun-cpus",
        "2",
        "opencode",
    ]);
    let run = out.run_call();

    assert_eq!(run.value_of("--runtime"), Some("krun"));
    assert!(run
        .values_of("--label")
        .contains(&"agent-sandbox.runtime=krun"));
    let annotations = run.values_of("--annotation");
    assert!(
        annotations.contains(&"krun.ram_mib=4096"),
        "{:?}",
        annotations
    );
    assert!(annotations.contains(&"krun.cpus=2"), "{:?}", annotations);
}

// ── privileged ──────────────────────────────────────────────────────────────

#[test]
fn privileged_is_passed_through_and_is_off_by_default() {
    let world = World::new();
    assert!(!world.run(&["opencode"]).run_call().has("--privileged"));
    assert!(world
        .run(&["--privileged", "opencode"])
        .run_call()
        .has("--privileged"));
}

// ── help ────────────────────────────────────────────────────────────────────

#[test]
fn help_never_starts_a_container() {
    let out = World::new().run(&["--help"]);

    assert!(!out.reached_podman_run());
    assert_eq!(out.code, Some(0));
    assert!(out.stdout.contains("--workspace"), "{}", out.stdout);
}

#[test]
fn help_lists_exactly_the_agents_the_catalog_declares() {
    let out = World::new()
        .env("AGENT_SANDBOX_AGENT_SPECS", "solo\t[\"solo\"]\t[]\t[]")
        .run(&["--help"]);

    assert!(out.stdout.contains("solo"), "{}", out.stdout);
    assert!(
        !out.stdout.contains("claude"),
        "the help text must come from the catalog, not a second copy of it"
    );
}
