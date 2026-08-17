#![forbid(unsafe_code)]
//! Host-side pieces of `agent-sandbox run`: the mount/env fragments each
//! integration flag contributes, and the naming of the container itself.
//!
//! These live here rather than inline in the launcher so they can be tested
//! without a podman.  The rewrite in 0b4289a lost every one of these blocks
//! silently, because nothing observed the launcher's argv but podman.

use std::path::Path;

/// Mount options for the launcher's own writable binds.  Plain `rw` unless
/// `--selinux` asks for shared relabeling.
pub fn rw_mount_opts(want_selinux: bool) -> &'static str {
    if want_selinux {
        "rw,z"
    } else {
        "rw"
    }
}

fn bind(host: &str, container: &str, opts: &str) -> Vec<String> {
    vec!["-v".to_string(), format!("{}:{}:{}", host, container, opts)]
}

fn env(name: &str, value: &str) -> Vec<String> {
    vec!["-e".to_string(), format!("{}={}", name, value)]
}

// ── SSH ─────────────────────────────────────────────────────────────────────

/// The agent socket is bound at a fixed path so `SSH_AUTH_SOCK` can name it
/// without the launcher and the entrypoint having to agree on anything else.
/// This is the un-proxied route; under `--proxy` the socket goes to the
/// sidecar and `relay-ssh` stands in for it instead.
pub fn ssh_direct(sock: &str, rw: &str) -> (Vec<String>, Vec<String>) {
    (
        bind(sock, "/agent.sock", rw),
        env("SSH_AUTH_SOCK", "/agent.sock"),
    )
}

// ── Git ─────────────────────────────────────────────────────────────────────

/// Host-specific settings that name a path only the host has.  `git config
/// --list --global` has already flattened `[include]`, so re-exporting the
/// directive would send the container back to a file it cannot read.
pub fn is_blocked_git_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    let (section, rest) = match key.split_once('.') {
        Some(parts) => parts,
        None => return false,
    };
    match section {
        // Global gitignore and custom hooks: host paths.
        "core" => rest == "excludesfile" || rest == "hookspath",
        // credential.helper and credential.<url>.helper.
        "credential" => rest == "helper" || rest.ends_with(".helper"),
        // gpg.program and gpg.<format>.program.
        "gpg" => rest == "program" || rest.ends_with(".program"),
        // Already flattened; the paths are host-side.
        "include" => true,
        _ => section.starts_with("includeif"),
    }
}

/// Parse `git config --list --global --null`: NUL between entries, newline
/// between key and value.  The `=`-separated form cannot be parsed
/// unambiguously, because a value may contain newlines (`alias.*` routinely
/// does) and would silently lose everything past the first one.
pub fn parse_git_config_null(output: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for entry in output.split('\0') {
        if entry.is_empty() {
            continue;
        }
        // A valueless key (`[section] flag`) has no newline; git renders it as
        // boolean true, which is what an omitted value means to the container.
        let (key, value) = match entry.split_once('\n') {
            Some((k, v)) => (k, v),
            None => (entry, "true"),
        };
        pairs.push((key.to_string(), value.to_string()));
    }
    pairs
}

/// Turn the host's effective global config into the indirect
/// `AGENT_SANDBOX_GIT_CONFIG_*` variables the entrypoint re-exports as
/// `GIT_CONFIG_*`.  Indirect because the entrypoint has to append its own
/// entry (the signing include) after these, and it can only do that if it
/// controls the count.
pub fn git_config_env(pairs: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let mut count = 0usize;
    for (key, value) in pairs {
        if key.is_empty() || is_blocked_git_key(key) {
            continue;
        }
        out.extend(env(&format!("AGENT_SANDBOX_GIT_CONFIG_KEY_{}", count), key));
        out.extend(env(
            &format!("AGENT_SANDBOX_GIT_CONFIG_VALUE_{}", count),
            value,
        ));
        count += 1;
    }
    let mut prefixed = env("AGENT_SANDBOX_GIT_CONFIG_COUNT", &count.to_string());
    prefixed.extend(out);
    prefixed
}

/// Identity is passed separately from the config above: git reads these even
/// when the config it was given is incomplete, and they are what shows up in
/// `git log` for a commit the agent makes.
pub fn git_identity_env(pairs: &[(String, String)]) -> Vec<String> {
    let lookup = |wanted: &str| {
        pairs
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(wanted))
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    };
    let mut out = Vec::new();
    if let Some(name) = lookup("user.name") {
        out.extend(env("GIT_AUTHOR_NAME", name));
        out.extend(env("GIT_COMMITTER_NAME", name));
    }
    if let Some(email) = lookup("user.email") {
        out.extend(env("GIT_AUTHOR_EMAIL", email));
        out.extend(env("GIT_COMMITTER_EMAIL", email));
    }
    out
}

// ── GnuPG ───────────────────────────────────────────────────────────────────

/// Public keyring material only: the keyring so gpg can name the signing key,
/// and the trust database so it believes the answer.  Secret keys are a
/// separate decision made by the caller (see `gpg::scan_gnupg_home`).
pub fn gnupg_public_mounts(gnupg_home: &Path, want_private: bool) -> Vec<String> {
    let mut out = Vec::new();
    for keyring in ["pubring.kbx", "pubring.gpg", "trustdb.gpg"] {
        let path = gnupg_home.join(keyring);
        if path.is_file() {
            out.extend(bind(
                &path.to_string_lossy(),
                &format!("/run/host-gnupg/{}", keyring),
                "ro",
            ));
        }
    }
    let private = gnupg_home.join("private-keys-v1.d");
    if want_private && private.is_dir() {
        out.extend(bind(
            &private.to_string_lossy(),
            "/run/host-gnupg/private-keys-v1.d",
            "ro",
        ));
    }
    out
}

// ── devenv / nix / podman ───────────────────────────────────────────────────

/// Multi-user nix delegates builds to the host daemon over its socket, so the
/// store can stay read-only.  Single-user nix has no daemon, so the whole tree
/// is overlaid instead and the container writes into the upper layer.
pub fn nix_mounts(
    daemon_socket_is_socket: bool,
    store_exists: bool,
    rw: &str,
) -> (Vec<String>, Vec<String>) {
    let mut mounts = Vec::new();
    let mut envs = Vec::new();
    if daemon_socket_is_socket {
        mounts.extend(bind("/nix/store", "/nix/store", "ro"));
        mounts.extend(bind(
            "/nix/var/nix/daemon-socket/socket",
            "/nix/var/nix/daemon-socket/socket",
            rw,
        ));
        envs.extend(env("NIX_REMOTE", "daemon"));
    } else if store_exists {
        mounts.push("-v".to_string());
        mounts.push("/nix:/nix:O".to_string());
    }
    envs.extend(env("AGENT_SANDBOX_HOST_NIX", "1"));
    (mounts, envs)
}

pub fn podman_socket_mounts(host_socket: &str, rw: &str) -> (Vec<String>, Vec<String>) {
    let mut envs = env("CONTAINER_HOST", "unix:///run/podman/podman.sock");
    envs.extend(env("DOCKER_HOST", "unix:///run/podman/podman.sock"));
    (bind(host_socket, "/run/podman/podman.sock", rw), envs)
}

// ── krun ────────────────────────────────────────────────────────────────────

/// Resources go in as OCI annotations, which is the only channel crun's
/// libkrun handler reads them from.  `label=disable` is not optional: the
/// kernel refuses to set a process's SELinux context once libkrun has spawned
/// the VM's threads, so the guest does not boot at all on an enforcing host.
pub fn krun_args(runtime: &str, ram_mib: &str, cpus: &str) -> Vec<String> {
    let mut out = vec![
        "--runtime".to_string(),
        runtime.to_string(),
        "--annotation".to_string(),
        format!("krun.ram_mib={}", ram_mib),
    ];
    if !cpus.is_empty() {
        out.push("--annotation".to_string());
        out.push(format!("krun.cpus={}", cpus));
    }
    out.push("--security-opt".to_string());
    out.push("label=disable".to_string());
    out
}

// ── Naming ──────────────────────────────────────────────────────────────────

/// A short word is easier to read and copy than a numeric identifier, and it
/// is the selector every `agent-sandbox ctl` command accepts.  Keep the pool
/// deliberately larger than the usual number of concurrent sandboxes.
pub const SESSION_WORDS: &[&str] = &[
    "autumn",
    "hidden",
    "bitter",
    "misty",
    "silent",
    "empty",
    "dry",
    "dark",
    "summer",
    "icy",
    "delicate",
    "quiet",
    "white",
    "cool",
    "spring",
    "winter",
    "patient",
    "twilight",
    "dawn",
    "crimson",
    "wispy",
    "weathered",
    "blue",
    "billowing",
    "broken",
    "cold",
    "damp",
    "falling",
    "frosty",
    "green",
    "long",
    "late",
    "lingering",
    "bold",
    "little",
    "morning",
    "muddy",
    "old",
    "red",
    "rough",
    "still",
    "small",
    "sparkling",
    "throbbing",
    "shy",
    "wandering",
    "withered",
    "wild",
    "black",
    "young",
    "holy",
    "solitary",
    "fragrant",
    "aged",
    "snowy",
    "proud",
    "floral",
    "restless",
    "divine",
    "polished",
    "ancient",
    "purple",
    "lively",
    "nameless",
];

pub fn sanitize_workspace_slug(basename: &str) -> String {
    let mapped: String = basename
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    mapped.chars().take(32).collect()
}

/// `taken` is the set of existing sandbox container names; a word already
/// suffixing one of them is not offered again, so `ctl status <word>` stays
/// unambiguous.  `pick` returns an index into `SESSION_WORDS` and is a
/// parameter so the search is testable without an RNG.
pub fn choose_session_word<F: FnMut() -> usize>(taken: &[String], mut pick: F) -> Option<String> {
    for _ in 0..100 {
        let candidate = SESSION_WORDS[pick() % SESSION_WORDS.len()];
        let suffix = format!("-{}", candidate);
        if !taken.iter().any(|name| name.ends_with(&suffix)) {
            return Some(candidate.to_string());
        }
    }
    None
}

pub fn container_name(workspace_slug: &str, session_word: &str) -> String {
    format!("agent-sandbox-{}-{}", workspace_slug, session_word)
}

// ── Policy ──────────────────────────────────────────────────────────────────

/// Where a host-owned network profile lives.  Shared by the launcher's
/// `--proxy-profile` and by `agent-sandbox browser`, which takes the same
/// profiles so one allow list can serve a sandbox and the browser testing it.
///
/// The name is checked rather than joined blindly: it comes from the command
/// line, and a profile is read from the operator's config directory.
pub fn proxy_profile_path(home: &str, name: &str) -> Result<std::path::PathBuf, String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(format!(
            "agent-sandbox: invalid proxy profile name '{}'; use letters, numbers, '.', '_' or '-'",
            name
        ));
    }
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(home).join(".config"));
    Ok(config_home
        .join("agent-sandbox")
        .join("profiles")
        .join(format!("{}.toml", name)))
}

/// Refused in every mode, so a proxy with no rules cannot be used to reach the
/// host or its LAN.  Written as ordinary `deny_ip` entries into the same file
/// the proxy reads and the sidecar mirrors into kernel blackhole routes, so
/// this is the only place the list is written down.
pub const BASELINE_DENY_IPS: &[&str] = &[
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "0.0.0.0/8",
    "fc00::/7",
    "fe80::/10",
];

/// `allow_port` alone does not make a policy deny-by-default -- only
/// `allow_host`/`allow_ip` do -- so those are what this looks for.
pub fn policy_has_allow_rules(policy: &str) -> bool {
    policy
        .lines()
        .any(|l| l.starts_with("allow_host ") || l.starts_with("allow_ip "))
}

/// The host names to resolve to the sidecar in the sandbox's `/etc/hosts`.
///
/// Under `--proxy` the sandbox is on an `--internal --disable-dns` network, so
/// *no* name resolves and everything has to go through the proxy environment.
/// A client that ignores that environment therefore fails at DNS -- and one
/// client cannot be made to honour it at all: the libgit2 inside `nix` (so also
/// inside `devenv`) fetches flake inputs through `git_remote_connect` with a
/// null `git_proxy_options`, which reads neither `https_proxy` nor `http.proxy`,
/// on a detached remote that has no git config to read either.
///
/// Pointing the allowed names at the sidecar gives those clients somewhere to
/// land: the proxy's `--transparent` listeners recover the destination from the
/// TLS SNI or the `Host` header and apply the very same policy.  It widens
/// nothing -- only names the policy already allows are mapped, and the mapping
/// is inert for every client that does use the proxy, which never resolves the
/// name in the first place.
///
/// Entries carrying a port suffix are mapped by name; `*.` patterns are
/// dropped, because `/etc/hosts` has no wildcards and mapping the apex instead
/// would assert something the policy did not say.  `localhost` is dropped too:
/// an entry for it would shadow the image's own loopback line and send every
/// client in the sandbox that talks to its own server off to the sidecar, which
/// the baseline `deny_ip 127.0.0.0/8` would then refuse.
pub fn transparent_host_names(allow_host: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for entry in allow_host {
        let name = entry.split(':').next().unwrap_or(entry).trim();
        if name.is_empty() || name.contains('*') || name.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }
        let name = name.to_ascii_lowercase();
        if name == "localhost" || name.ends_with(".localhost") || name == "localhost.localdomain" {
            continue;
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Whether any host in this policy is subject to TLS interception.
///
/// The proxy only terminates TLS for a host carrying an L7 rule, so with none
/// the session CA is never used -- `skip_l7` is true for every host and the
/// leaf issuer is never reached.  Gating the CA mount on this keeps ordinary
/// HTTPS end-to-end authenticated: without the CA in its trust store, the
/// sandbox would notice if the proxy started intercepting.
pub fn policy_has_l7_rules(policy: &str) -> bool {
    policy.lines().any(|l| l.starts_with("allow_route\t"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_blocklist_covers_documented_categories() {
        for blocked in [
            "core.excludesFile",
            "core.hooksPath",
            "credential.helper",
            "credential.https://example.com.helper",
            "gpg.program",
            "gpg.ssh.program",
            "gpg.openpgp.program",
            "include.path",
            "includeIf.gitdir:~/work/.path",
        ] {
            assert!(is_blocked_git_key(blocked), "{} should be blocked", blocked);
        }
        for kept in [
            "user.name",
            "user.email",
            "user.signingkey",
            "commit.gpgsign",
            "core.editor",
            "init.defaultbranch",
            "safe.directory",
        ] {
            assert!(!is_blocked_git_key(kept), "{} should be kept", kept);
        }
    }

    #[test]
    fn git_config_env_indexes_from_zero_and_counts_kept_keys() {
        let pairs = parse_git_config_null(
            "user.name\nAda\0core.hookspath\n/home/ada/hooks\0user.email\nada@example.com\0",
        );
        assert_eq!(
            git_config_env(&pairs),
            vec![
                "-e",
                "AGENT_SANDBOX_GIT_CONFIG_COUNT=2",
                "-e",
                "AGENT_SANDBOX_GIT_CONFIG_KEY_0=user.name",
                "-e",
                "AGENT_SANDBOX_GIT_CONFIG_VALUE_0=Ada",
                "-e",
                "AGENT_SANDBOX_GIT_CONFIG_KEY_1=user.email",
                "-e",
                "AGENT_SANDBOX_GIT_CONFIG_VALUE_1=ada@example.com",
            ]
        );
    }

    #[test]
    fn git_config_survives_values_with_equals_and_newlines() {
        let pairs = parse_git_config_null("alias.lg\nlog --format=%h %s\0alias.two\na\nb\0");
        assert_eq!(pairs[0].1, "log --format=%h %s");
        assert_eq!(pairs[1].1, "a\nb");
        let flag = parse_git_config_null("http.sslverify\0");
        assert_eq!(flag[0], ("http.sslverify".to_string(), "true".to_string()));
    }

    #[test]
    fn git_identity_comes_from_the_effective_config() {
        let pairs = parse_git_config_null("user.name\nAda\0user.email\nada@example.com\0");
        assert_eq!(
            git_identity_env(&pairs),
            vec![
                "-e",
                "GIT_AUTHOR_NAME=Ada",
                "-e",
                "GIT_COMMITTER_NAME=Ada",
                "-e",
                "GIT_AUTHOR_EMAIL=ada@example.com",
                "-e",
                "GIT_COMMITTER_EMAIL=ada@example.com",
            ]
        );
        assert!(git_identity_env(&parse_git_config_null("user.email\n\0")).is_empty());
    }

    #[test]
    fn ssh_socket_lands_on_the_path_the_entrypoint_probes() {
        let (mounts, envs) = ssh_direct("/run/user/1000/keyring/ssh", "rw");
        assert_eq!(
            mounts,
            vec!["-v", "/run/user/1000/keyring/ssh:/agent.sock:rw"]
        );
        assert_eq!(envs, vec!["-e", "SSH_AUTH_SOCK=/agent.sock"]);
    }

    #[test]
    fn multi_user_nix_keeps_the_store_read_only() {
        let (mounts, envs) = nix_mounts(true, true, "rw");
        assert!(mounts.contains(&"/nix/store:/nix/store:ro".to_string()));
        assert!(envs.contains(&"NIX_REMOTE=daemon".to_string()));
        assert!(envs.contains(&"AGENT_SANDBOX_HOST_NIX=1".to_string()));
    }

    #[test]
    fn single_user_nix_overlays_the_whole_tree() {
        let (mounts, envs) = nix_mounts(false, true, "rw");
        assert_eq!(mounts, vec!["-v", "/nix:/nix:O"]);
        assert!(envs.contains(&"AGENT_SANDBOX_HOST_NIX=1".to_string()));
    }

    #[test]
    fn krun_args_carry_resources_as_annotations() {
        let args = krun_args("/nix/store/x/bin/krun", "4096", "8");
        assert_eq!(args[0], "--runtime");
        assert_eq!(args[1], "/nix/store/x/bin/krun");
        assert!(args.contains(&"krun.ram_mib=4096".to_string()));
        assert!(args.contains(&"krun.cpus=8".to_string()));
        // Without it the guest does not boot on an enforcing host.
        assert!(args.contains(&"label=disable".to_string()));
    }

    #[test]
    fn krun_cpus_annotation_is_omitted_when_unset() {
        let args = krun_args("krun", "4096", "");
        assert!(!args.iter().any(|a| a.starts_with("krun.cpus=")));
    }

    #[test]
    fn session_word_skips_words_already_in_use() {
        let taken = vec!["agent-sandbox-repo-silent".to_string()];
        let silent = SESSION_WORDS.iter().position(|w| *w == "silent").unwrap();
        let misty = SESSION_WORDS.iter().position(|w| *w == "misty").unwrap();
        let mut picks = vec![misty, silent].into_iter();
        let word = choose_session_word(&taken, || picks.next().unwrap());
        assert_eq!(word, Some("misty".to_string()));
    }

    #[test]
    fn session_word_gives_up_rather_than_colliding() {
        let taken: Vec<String> = SESSION_WORDS
            .iter()
            .map(|w| format!("agent-sandbox-repo-{}", w))
            .collect();
        assert_eq!(choose_session_word(&taken, || 0), None);
    }

    #[test]
    fn workspace_slug_is_safe_and_bounded() {
        assert_eq!(sanitize_workspace_slug("my repo/x"), "my-repo-x");
        assert_eq!(sanitize_workspace_slug(&"a".repeat(64)).len(), 32);
        assert_eq!(
            container_name(&sanitize_workspace_slug("agent-sandbox"), "silent"),
            "agent-sandbox-agent-sandbox-silent"
        );
    }

    #[test]
    fn allow_rules_are_detected_only_from_domains_and_ips() {
        assert!(policy_has_allow_rules("allow_host github.com\n"));
        assert!(policy_has_allow_rules(
            "deny_ip 10.0.0.0/8\nallow_ip 1.2.3.4\n"
        ));
        assert!(!policy_has_allow_rules("allow_port 443\ndefault deny\n"));
    }

    #[test]
    fn only_allowed_names_are_pointed_at_the_sidecar() {
        // The port suffix is part of the policy entry, not of the name, and one
        // host declared twice is still one /etc/hosts line.
        assert_eq!(
            transparent_host_names(&[
                "github.com:443,22".to_string(),
                "GitHub.com".to_string(),
                "channels.nixos.org".to_string(),
            ]),
            vec!["github.com", "channels.nixos.org"]
        );
    }

    #[test]
    fn wildcards_and_addresses_are_left_out_of_etc_hosts() {
        // /etc/hosts has no wildcards.  Mapping the apex instead would assert
        // an allowance the policy never made -- `*.example.com` does not permit
        // `example.com` -- and an address needs no name to resolve at all.
        assert!(transparent_host_names(&["*.example.com".to_string()]).is_empty());
        assert!(transparent_host_names(&["*".to_string()]).is_empty());
        assert!(transparent_host_names(&["1.2.3.4".to_string()]).is_empty());
        assert!(transparent_host_names(&["".to_string()]).is_empty());
    }

    #[test]
    fn loopback_is_never_redirected_at_the_sandbox() {
        // Mapping localhost would shadow the image's own loopback line, so a
        // server the agent started in its own container would suddenly be
        // addressed at the sidecar -- and refused by the baseline deny.  This is
        // the one name that must never be pointed away.
        assert!(transparent_host_names(&["localhost:8080".to_string()]).is_empty());
        assert!(transparent_host_names(&["LOCALHOST".to_string()]).is_empty());
        assert!(transparent_host_names(&["app.localhost".to_string()]).is_empty());
        assert!(transparent_host_names(&["localhost.localdomain".to_string()]).is_empty());
    }

    #[test]
    fn l7_rules_are_what_gate_the_session_ca() {
        // Only `allow_route` makes the proxy intercept TLS.  A secret route always
        // comes with one, so it is covered; an ordinary allow list is not, and
        // must not pull a CA into the sandbox's trust store.
        assert!(policy_has_l7_rules(
            "allow_host api.github.com\nallow_route\tapi.github.com\tGET\t/user\n"
        ));
        assert!(!policy_has_l7_rules(
            "allow_host github.com\nallow_port 443\ndefault deny\n"
        ));
        assert!(!policy_has_l7_rules(""));
    }
}
