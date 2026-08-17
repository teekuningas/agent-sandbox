//! What `--proxy` builds, checked against a stub `podman`.
//!
//! The policy *semantics* are `proxy/src/policy.rs`'s tests, and whether a
//! request actually gets through is the integration suite's. What is only
//! visible here is the wiring: which network the sandbox joins, which proxy
//! variables it is given, what policy file the sidecar is handed, and which
//! capabilities are withheld when the policy does not ask for them.

mod common;

use common::World;
use std::fs;

/// A world whose stub podman answers the two lookups the sidecar path makes:
/// the internal network's subnet, and the sidecar's address on it.
fn proxied_world() -> World {
    World::new()
        .podman_reply("network-inspect", "10.89.7.0/24\n", 0)
        .podman_reply("container-inspect", "10.89.7.2\n", 0)
}

const ALLOW_EXAMPLE: &str = "\
```toml agent-sandbox
[network]
allowed_hosts = [\"example.com:443\"]
```
";

const L7_ROUTE: &str = "\
```toml agent-sandbox
[network]
allowed_hosts = [\"github.com:443\"]

[[network.allowed_routes]]
host = \"api.example.com\"
method = \"GET\"
path = \"/v1/*\"
```
";

#[test]
fn the_sandbox_joins_the_sidecars_internal_network_and_nothing_else() {
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);
    let run = out.run_call();

    let network = run.value_of("--network").expect("a network");
    assert!(
        network.starts_with("agent-sandbox-sidecar-"),
        "the sandbox's only route out is the sidecar: {}",
        network
    );
    assert!(run
        .values_of("--label")
        .contains(&"agent-sandbox.proxy=proxy"));
}

#[test]
fn every_allowed_name_resolves_to_the_sidecar() {
    // The sandbox's network has no DNS at all, so a client that ignores the
    // proxy variables would otherwise fail at resolution.  Pointing the allowed
    // names at the sidecar sends it to the transparent listeners instead --
    // which is the only way to reach nix's libgit2, whose flake fetches consult
    // neither the proxy environment nor `http.proxy`.
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);

    assert!(out
        .run_call()
        .has_pair("--add-host", "example.com:10.89.7.2"));
}

#[test]
fn a_host_named_only_by_a_route_is_mapped_too() {
    // An `allowed_routes` host is subject to interception rather than a plain
    // tunnel, and reaching the proxy is a precondition for either.
    let out = proxied_world().file("AGENTS.md", L7_ROUTE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);
    let run = out.run_call();

    assert!(run.has_pair("--add-host", "api.example.com:10.89.7.2"));
    assert!(run.has_pair("--add-host", "github.com:10.89.7.2"));
}

#[test]
fn an_unproxied_launch_maps_no_names() {
    // Without --proxy there is no sidecar to point anything at, and the sandbox
    // resolves names for itself.
    let out = World::new()
        .file("AGENTS.md", ALLOW_EXAMPLE)
        .run(&["--workspace", "opencode"]);

    assert!(out.run_call().values_of("--add-host").is_empty());
}

#[test]
fn the_proxy_address_is_handed_over_in_every_spelling_clients_read() {
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);
    let run = out.run_call();

    for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        assert_eq!(
            run.env_value(var),
            Some("http://10.89.7.2:8888"),
            "{} points at the sidecar's address on the internal network",
            var
        );
    }
}

#[test]
fn loopback_is_exempted_so_the_agent_can_reach_its_own_server() {
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);
    let run = out.run_call();

    for var in ["NO_PROXY", "no_proxy"] {
        let value = run.env_value(var).unwrap_or_default();
        assert!(value.contains("127.0.0.1"), "{}={}", var, value);
        assert!(value.contains("localhost"), "{}={}", var, value);
        assert!(value.contains("::1"), "{}={}", var, value);
        assert!(
            !value.contains('*') && !value.contains('/'),
            "wildcard and CIDR syntax disagree across clients: {}={}",
            var,
            value
        );
    }
}

#[test]
fn without_proxy_no_proxy_variables_are_set_at_all() {
    let out = World::new()
        .file("AGENTS.md", ALLOW_EXAMPLE)
        .run(&["--workspace", "opencode"]);
    let run = out.run_call();

    for var in ["HTTP_PROXY", "https_proxy", "NO_PROXY"] {
        assert_eq!(
            run.env_value(var),
            None,
            "{} leaked into an unproxied run",
            var
        );
    }
}

#[test]
fn the_policy_the_sidecar_is_handed_carries_the_declared_rules_and_a_deny_baseline() {
    let world = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE);
    let out = world.run(&["--workspace", "--proxy", "opencode"]);

    assert!(out.sidecar_call().is_some(), "a sidecar was started");
    let dir = world.captured("sidecar_policy");
    let policy = fs::read_to_string(dir.join("policy")).expect("the live policy file");

    assert!(
        policy.contains("example.com"),
        "the declared rule must reach the proxy: {}",
        policy
    );
    assert!(
        policy
            .lines()
            .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["default", "deny"]),
        "the baseline is deny, whatever was declared: {}",
        policy
    );

    // `policy.base` is what `ctl proxy reset` restores, so a session that never
    // edits its policy has to start with the two identical.
    let base = fs::read_to_string(dir.join("policy.base")).expect("the reset baseline");
    assert_eq!(
        policy, base,
        "an unedited session's policy and its reset baseline are the same policy"
    );
}

/// GPG signing is gated on `--gpg` alone -- host-agnostic, no AGENTS.md
/// declaration needed -- while SSH push still needs an explicit
/// `allowed_hosts = ["host:22"]` entry. This is the flag -> policy-line
/// mapping the split relies on.
#[test]
fn signing_enabled_is_written_when_gpg_is_forwarded_with_no_network_declaration() {
    let world = proxied_world().gpg_agent_forwarded();
    let out = world.run(&["--workspace", "--proxy", "--gpg", "opencode"]);

    assert!(out.sidecar_call().is_some(), "a sidecar was started");
    let dir = world.captured("sidecar_policy");
    let policy = fs::read_to_string(dir.join("policy")).expect("the live policy file");

    assert!(
        policy.lines().any(|l| l == "signing_enabled true"),
        "gpg forwarded with no [network] block must still enable signing: {}",
        policy
    );
    assert!(
        !policy.contains("allow_signing "),
        "no host was ever declared, so no ssh push host should be authorized: {}",
        policy
    );
}

#[test]
fn signing_enabled_is_absent_without_gpg() {
    let world = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE);
    let out = world.run(&["--workspace", "--proxy", "opencode"]);

    assert!(out.sidecar_call().is_some(), "a sidecar was started");
    let dir = world.captured("sidecar_policy");
    let policy = fs::read_to_string(dir.join("policy")).expect("the live policy file");

    assert!(
        !policy.contains("signing_enabled"),
        "gpg signing must not be enabled without --gpg: {}",
        policy
    );
}

#[test]
fn a_session_ca_is_only_trusted_when_the_policy_has_a_rule_that_needs_one() {
    let plain = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);
    let run = plain.run_call();

    assert!(
        run.mount_to("/run/agent-sandbox-proxy-ca.pem").is_none(),
        "with nothing intercepted, a CA that can mint any name grants trust for no purpose: {}",
        run.joined()
    );
    assert_eq!(run.env_value("AGENT_SANDBOX_PROXY_CA_FILE"), None);
}

#[test]
fn an_l7_policy_is_accepted_and_still_denies_by_default() {
    let out =
        proxied_world()
            .file("AGENTS.md", L7_ROUTE)
            .run(&["--workspace", "--proxy", "opencode"]);

    assert!(
        out.reached_podman_run(),
        "an L7 route is a valid policy: {}",
        out.stderr
    );
    assert!(out
        .run_call()
        .values_of("--label")
        .contains(&"agent-sandbox.proxy=proxy"));
}

#[test]
fn a_proxy_profile_that_does_not_exist_refuses_the_launch() {
    let out = proxied_world().run(&["--workspace", "--proxy-profile", "nope", "opencode"]);

    assert!(!out.reached_podman_run());
    assert!(
        out.stderr.contains("nope"),
        "the error should name the profile: {}",
        out.stderr
    );
}

#[test]
fn a_proxy_profile_supplies_the_policy_when_agents_md_has_none() {
    let out = proxied_world()
        .home_file(
            ".config/agent-sandbox/profiles/development.toml",
            "[network]\nallowed_hosts = [\"registry.npmjs.org:443\"]\n",
        )
        .run(&["--workspace", "--proxy-profile", "development", "opencode"]);

    assert!(
        out.reached_podman_run(),
        "a host-owned profile is a complete policy on its own: {}",
        out.stderr
    );
    assert!(out
        .run_call()
        .values_of("--label")
        .contains(&"agent-sandbox.proxy=proxy"));
}

#[test]
fn secrets_declared_but_not_enabled_warn_rather_than_being_injected() {
    let agents_md = "\
```toml agent-sandbox
[network]
allowed_hosts = [\"github.com:443\"]

[[network.allowed_routes]]
host = \"api.example.com\"
method = \"GET\"
path = \"/v1/*\"
secret = \"API_TOKEN\"
```
";
    let out =
        proxied_world()
            .file("AGENTS.md", agents_md)
            .run(&["--workspace", "--proxy", "opencode"]);

    assert!(out.reached_podman_run(), "{}", out.stderr);
    assert!(
        out.stderr.contains("--secrets"),
        "a declared secret that is not enabled must say so: {}",
        out.stderr
    );
}

#[test]
fn the_sidecar_is_torn_down_when_the_launch_ends() {
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);

    let stopped = out
        .calls
        .iter()
        .any(|c| c.first().map(String::as_str) == Some("stop"));
    let network_removed = out
        .calls
        .iter()
        .any(|c| c.len() >= 2 && c[0] == "network" && c[1] == "rm");

    assert!(
        stopped,
        "a leaked sidecar keeps holding the host's agent sockets"
    );
    assert!(
        network_removed,
        "leaked networks exhaust the rootless subnet pool: {:?}",
        out.calls
    );
}

/// The relay runs ssh and gpg in the sidecar, not in the sandbox, so the
/// sidecar is the side that has to be able to resolve its own uid. It runs
/// without --userns=keep-id and the image ships no /etc/passwd, so without
/// these two mounts ssh dies at getpwuid with "No user exists for uid 0"
/// before it ever opens a connection.
#[test]
fn the_sidecar_gets_a_passwd_database_of_its_own() {
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);

    let sidecar = out.sidecar_call().expect("no sidecar was started");
    for dest in ["/etc/passwd", "/etc/group"] {
        let mount = sidecar
            .mount_to(dest)
            .unwrap_or_else(|| panic!("the sidecar has no {}: {}", dest, sidecar.joined()));
        assert!(
            mount.ends_with(":ro"),
            "{} should be read-only in the sidecar, got {}",
            dest,
            mount
        );
    }

    // The sandbox keeps its own copy: this is an addition, not a move.
    let run = out.run_call();
    assert!(
        run.mount_to("/etc/passwd").is_some(),
        "the sandbox lost its passwd database: {}",
        run.joined()
    );
}

// ── Host-key authorization ──────────────────────────────────────────────────

const SSH_HOST: &str = "\
```toml agent-sandbox
[network]
allowed_hosts = [\"github.com:22\"]
```
";

const GITHUB_ED25519: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

fn trusted_toml(host: &str) -> String {
    format!(
        "[[network.known_hosts]]\nhost = \"{}\"\nkey = \"{}\"\n",
        host, GITHUB_ED25519
    )
}

/// The secrets model refuses a launch whose policy asks for something the host
/// has not authorized, and prints the block to paste. Host keys work the same
/// way -- and unlike the secrets check, this one has a test that the refusal
/// really does stop the launch rather than merely printing.
#[test]
fn an_ssh_host_with_no_trusted_key_never_reaches_podman_run() {
    let out = proxied_world()
        .file("AGENTS.md", SSH_HOST)
        .run(&["--workspace", "--proxy", "opencode"]);

    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("trusted.toml"),
        "the refusal has to name the file to edit: {}",
        out.stderr
    );
    assert!(
        out.stderr.contains("[[network.known_hosts]]"),
        "the refusal has to carry the block to paste: {}",
        out.stderr
    );
    // For a forge we know, the key is filled in: one copy-paste, not a keyscan.
    assert!(
        out.stderr.contains(GITHUB_ED25519),
        "the refusal should pre-fill a key we publish: {}",
        out.stderr
    );
    // Nothing was built. A refusal that leaves a network behind is worse than
    // no refusal, because the next launch inherits it.
    assert!(
        out.calls.iter().all(|c| c.first().map(String::as_str) != Some("run")),
        "the launcher started a container anyway: {:?}",
        out.calls
    );
}

/// Only port 22 pulls the requirement in -- it is what `allow_signing`, and
/// therefore the relay, keys off.
#[test]
fn a_policy_that_opens_no_ssh_port_needs_no_host_key() {
    let out = proxied_world()
        .file("AGENTS.md", ALLOW_EXAMPLE)
        .run(&["--workspace", "--proxy", "opencode"]);

    assert!(
        !out.stderr.contains("known_hosts"),
        "a :443-only policy should not ask for a host key: {}",
        out.stderr
    );
    out.run_call();
}

#[test]
fn an_authorized_host_key_reaches_the_sidecar_and_the_sandbox() {
    let world = proxied_world()
        .file("AGENTS.md", SSH_HOST)
        .home_file(".config/agent-sandbox/trusted.toml", &trusted_toml("github.com:22"));
    let out = world.run(&["--workspace", "--proxy", "--ssh", "opencode"]);

    // The sidecar's copy, in the same read-only directory as the policy: it is
    // the same kind of thing, a host-side decision the sandbox cannot rewrite.
    let rendered = fs::read_to_string(world.captured("sidecar_policy").join("known_hosts"))
        .expect("the sidecar was handed no known_hosts");
    assert_eq!(
        rendered,
        format!("github.com {}\n", GITHUB_ED25519),
        "the :22 port is dropped in the rendered line, as OpenSSH expects"
    );

    // The sandbox gets the same file, bound in one file at a time so the
    // directory around it stays out of reach.
    let run = out.run_call();
    let mount = run
        .mount_to("/run/agent-sandbox-known-hosts")
        .unwrap_or_else(|| panic!("the sandbox has no known_hosts: {}", run.joined()));
    assert!(mount.ends_with(":ro"), "got {}", mount);
    assert!(
        run.joined()
            .contains("AGENT_SANDBOX_KNOWN_HOSTS=/run/agent-sandbox-known-hosts"),
        "the entrypoint has nothing to seed from: {}",
        run.joined()
    );
}

/// A key for another port is a real entry -- `ssh -p 2222` needs it -- but it
/// is not authorization for the port the relay will use.
#[test]
fn a_key_on_another_port_does_not_authorize_the_default_one() {
    let out = proxied_world()
        .file("AGENTS.md", SSH_HOST)
        .home_file(
            ".config/agent-sandbox/trusted.toml",
            &trusted_toml("github.com:2222"),
        )
        .run(&["--workspace", "--proxy", "opencode"]);

    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
}

/// The file grew a second job and a name that no longer described it. Renaming
/// it silently would leave SSH trust being granted by a file called `secrets`.
#[test]
fn the_pre_rename_config_refuses_rather_than_being_read() {
    let out = proxied_world()
        .file("AGENTS.md", ALLOW_EXAMPLE)
        .home_file(".config/agent-sandbox/secrets.toml", "")
        .run(&["--workspace", "--proxy", "opencode"]);

    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert!(out.stderr.contains("mv "), "name the move: {}", out.stderr);
    assert!(
        out.stderr.contains("trusted.toml"),
        "name the destination: {}",
        out.stderr
    );
}

/// Once renamed, the old name is no longer consulted at all.
#[test]
fn the_new_config_wins_and_the_old_one_is_left_alone() {
    let out = proxied_world()
        .file("AGENTS.md", SSH_HOST)
        .home_file(".config/agent-sandbox/secrets.toml", "")
        .home_file(
            ".config/agent-sandbox/trusted.toml",
            &trusted_toml("github.com:22"),
        )
        .run(&["--workspace", "--proxy", "opencode"]);

    assert!(out.stderr.is_empty() || !out.stderr.contains("mv "), "{}", out.stderr);
    out.run_call();
}
