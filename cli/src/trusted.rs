//! The host-owned trust file, `~/.config/agent-sandbox/trusted.toml`.
//!
//! `AGENTS.md` is part of the repository and therefore untrusted: it may name a
//! host, but it may not decide what is trusted about that host.  Anything in
//! that category is authorized here instead, in a file only the operator
//! writes, by copying the block the launcher prints.
//!
//! Two things live under that rule today.  `[[network.allowed_routes]]` with a
//! `secret` authorizes an injection (see [`crate::secrets`]), and
//! `[[network.known_hosts]]` authorizes an SSH host key.  Both refuse the
//! launch rather than proceeding unauthorized, and both print the exact block
//! to paste.
//!
//! The file was called `secrets.toml` until it grew its second job.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

/// `$XDG_CONFIG_HOME/agent-sandbox/trusted.toml`, or `$HOME/.config/…`.
///
/// One resolver for the whole file, so the secrets half and the host-key half
/// can never read different paths.  `XDG_CONFIG_HOME` is honoured because
/// [`crate::launch::proxy_profile_path`] honours it for the sibling profiles
/// directory, and an operator who moved their config expects both to follow.
pub fn config_path(home: &str) -> PathBuf {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home).join(".config"));
    config_home.join("agent-sandbox").join("trusted.toml")
}

/// The pre-rename path, refused rather than read.
fn legacy_config_path(home: &str) -> PathBuf {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home).join(".config"));
    config_home.join("agent-sandbox").join("secrets.toml")
}

/// The refusal for a config that has not been renamed yet, or `None` when
/// there is nothing to say.
///
/// A silent fallback was the alternative and is worse: the file now authorizes
/// host keys as well as secrets, and a name that says `secrets` while granting
/// SSH trust is exactly the kind of thing an operator should have to look at
/// once.
pub fn legacy_path_refusal(home: &str) -> Option<String> {
    let new = config_path(home);
    let old = legacy_config_path(home);
    if new.exists() || !old.exists() {
        return None;
    }
    Some(format!(
        "agent-sandbox: {} has been renamed to trusted.toml.\n\
         \x20              It now authorizes SSH host keys as well as secrets, so the\n\
         \x20              name no longer fit. The contents are unchanged:\n\n\
         mv {} {}\n",
        old.display(),
        old.display(),
        new.display()
    ))
}

/// One authorized host key, as written in `[[network.known_hosts]]`.
///
/// `key` is the `known_hosts` key itself -- type and base64, without the
/// leading host, which comes from `host`.
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnownHost {
    pub host: String,
    pub key: String,
}

#[derive(Debug, Default, serde::Deserialize)]
struct TrustedFile {
    #[serde(default)]
    network: NetworkTable,
}

#[derive(Debug, Default, serde::Deserialize)]
struct NetworkTable {
    #[serde(default)]
    known_hosts: Vec<KnownHost>,
}

/// Reads the `[[network.known_hosts]]` entries, validating every one.
///
/// A missing file is not an error here -- it becomes one only when something
/// actually needed authorizing, which is how the secrets half behaves too.
/// Malformed TOML and an invalid key both are: a key that is wrong does not
/// fail here but much later, as an opaque `Host key verification failed` from
/// inside a container.
pub fn load_known_hosts(path: &Path) -> Result<Vec<KnownHost>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => bail!(
            "agent-sandbox: cannot read the trusted config at {}: {}",
            path.display(),
            e
        ),
    };
    // Unknown keys are rejected rather than ignored: a typo in a field name
    // silently means "this key authorizes nothing", which surfaces as a
    // refusal the operator has already tried to fix.
    let parsed: TrustedFile = toml::from_str(&text).map_err(|e| {
        anyhow::anyhow!(
            "agent-sandbox: the trusted config at {} is malformed: {}",
            path.display(),
            e
        )
    })?;

    for entry in &parsed.network.known_hosts {
        validate_known_host(entry)?;
    }
    Ok(parsed.network.known_hosts)
}

fn validate_known_host(entry: &KnownHost) -> Result<()> {
    let host = entry.host.trim();
    if host.is_empty() {
        bail!("agent-sandbox: [[network.known_hosts]] has an empty 'host'");
    }
    // A hashed host cannot be matched against a policy that names hosts in
    // clear, nor rendered back out with the right port syntax.
    if host.starts_with("|") {
        bail!(
            "agent-sandbox: [[network.known_hosts]] host {:?} is a hashed known_hosts entry. \
             Write the host in clear -- the file is matched against the hosts your policy names.",
            host
        );
    }

    let key = entry.key.trim();
    if key.is_empty() {
        bail!(
            "agent-sandbox: [[network.known_hosts]] for {:?} has an empty 'key'. \
             Use the type and base64 from a known_hosts line, e.g. \"ssh-ed25519 AAAAC3Nza...\".",
            entry.host
        );
    }
    // These markers change what the entry *means* -- @cert-authority delegates
    // trust to a signing key, which authorizes far more than "this host has
    // this key". If that is ever wanted it should be asked for deliberately,
    // not arrive by copying a line.
    if key.starts_with('@') {
        bail!(
            "agent-sandbox: [[network.known_hosts]] for {:?}: marker {:?} is not supported. \
             Only a plain host key is, not @cert-authority or @revoked.",
            entry.host,
            key.split_whitespace().next().unwrap_or(key)
        );
    }

    // A fingerprint is what `ssh-keyscan | ssh-keygen -lf` prints and what a
    // forge publishes on its docs page, so it is the thing most likely to be
    // reached for. It cannot go in known_hosts at all.
    if key.starts_with("SHA256:") || key.starts_with("MD5:") {
        bail!(
            "agent-sandbox: [[network.known_hosts]] for {:?}: {:?} is a fingerprint, not a key. \
             known_hosts needs the key itself -- use it to verify the key you paste, not in its place.",
            entry.host,
            key
        );
    }

    let mut fields = key.split_whitespace();
    let key_type = fields.next().unwrap_or_default();
    let material = match fields.next() {
        Some(material) => material,
        None => bail!(
            "agent-sandbox: [[network.known_hosts]] for {:?}: key {:?} is not a \"<type> <base64>\" pair.",
            entry.host,
            key
        ),
    };

    // The whole known_hosts line pasted in, host and all, is the mistake this
    // catches -- common enough that guessing at it beats a generic message.
    if !is_base64ish(material) {
        if fields.clone().next().is_some() && is_base64ish(fields.next().unwrap_or_default()) {
            bail!(
                "agent-sandbox: [[network.known_hosts]] for {:?}: key {:?} looks like a whole \
                 known_hosts line. Drop the leading host -- it comes from the 'host' field.",
                entry.host,
                key_type
            );
        }
        bail!(
            "agent-sandbox: [[network.known_hosts]] for {:?}: {:?} is not base64 key material. \
             Use the key itself, not a SHA256: fingerprint or a file path.",
            entry.host,
            material
        );
    }
    // Short enough to be a fingerprint or a truncated paste rather than a key.
    if material.len() < 32 {
        bail!(
            "agent-sandbox: [[network.known_hosts]] for {:?}: key material is too short to be a \
             host key. Copy the whole base64 field.",
            entry.host
        );
    }
    // The key *type* is deliberately not checked against a list: OpenSSH gains
    // types, and this field is echoed into known_hosts verbatim.
    Ok(())
}

fn is_base64ish(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Splits a `host` field into its domain and its optional port.
fn split_host(host: &str) -> (String, Option<String>) {
    let (domain, port) = crate::agents::parse_host_port(host.trim());
    (domain.to_ascii_lowercase(), port)
}

/// The entries rendered as an OpenSSH `known_hosts` file.
///
/// Port 22 (or none) is the bare form; any other port takes the bracketed
/// form, which is what OpenSSH writes and matches for a non-default port.
pub fn render_known_hosts(hosts: &[KnownHost]) -> String {
    let mut out = String::new();
    for entry in hosts {
        let (domain, port) = split_host(&entry.host);
        let pattern = match port.as_deref() {
            None | Some("22") => domain,
            Some(port) => format!("[{}]:{}", domain, port),
        };
        out.push_str(&format!("{} {}\n", pattern, entry.key.trim()));
    }
    out
}

/// Whether a trusted entry authorizes SSH to `domain` on the default port.
///
/// Exact, case-insensitive string match on the domain -- so an
/// `allow_signing *.github.com` needs `host = "*.github.com"`, the same
/// pattern the relay matches with.  The port must be 22 or unwritten: an entry
/// for `[git.example.com]:2222` is a real and useful entry, but it is not
/// authorization for a connection to 22, and treating it as one would leave a
/// hole that surfaces as a verification failure long after the launch.
fn authorizes(entry: &KnownHost, domain: &str) -> bool {
    let (entry_domain, entry_port) = split_host(&entry.host);
    entry_domain == domain.trim().to_ascii_lowercase()
        && matches!(entry_port.as_deref(), None | Some("22"))
}

/// The `allow_signing` hosts that no trusted entry authorizes.
pub fn unauthorized_signing_hosts(allow_signing: &[String], trusted: &[KnownHost]) -> Vec<String> {
    allow_signing
        .iter()
        .filter(|host| !trusted.iter().any(|entry| authorizes(entry, host)))
        .cloned()
        .collect()
}

/// The refusal, with the block to paste.
///
/// Flush-left on purpose, exactly as the secrets refusal is: the operator
/// copies it into a TOML file, and prompt indentation would have to be
/// stripped by hand.
pub fn refusal(unauthorized: &[String], path: &Path) -> String {
    let mut out = String::new();
    for host in unauthorized {
        out.push_str(&format!(
            "agent-sandbox: the selected network policy authorizes SSH to '{}'\n\
             \x20              (an allowed_hosts entry covering port 22), but no host key for\n\
             \x20              it is trusted in {}.\n\n\
             \x20              To authorize it, add:\n\n",
            host,
            path.display()
        ));

        let pinned = agent_sandbox_proxy::known_hosts::pinned_keys_for(host);
        if pinned.is_empty() {
            out.push_str("[[network.known_hosts]]\n");
            out.push_str(&format!("host = \"{}:22\"\n", host));
            out.push_str("key = \"\"\n\n");
            out.push_str(&format!(
                "\x20              Fill in the key. On the host, not in the sandbox:\n\
                 \x20                  ssh-keyscan {}\n\
                 \x20              and check what it returns against a fingerprint you already\n\
                 \x20              trust -- keyscan asks the server who it is, so it cannot\n\
                 \x20              tell you the answer is wrong.\n\n",
                host
            ));
        } else {
            for key in pinned {
                out.push_str("[[network.known_hosts]]\n");
                out.push_str(&format!("host = \"{}:22\"\n", host));
                out.push_str(&format!("key = \"{}\"\n\n", key));
            }
            out.push_str(
                "\x20              These are the keys agent-sandbox used to pin itself. Verify\n\
                 \x20              them against the forge's published fingerprints before\n\
                 \x20              trusting them; one key is enough if you prefer.\n\n",
            );
        }

        out.push_str(
            "\x20              Or drop port 22 from the allowed_hosts entry if SSH is not needed.\n\n",
        );
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    fn entry(host: &str, key: &str) -> KnownHost {
        KnownHost {
            host: host.to_string(),
            key: key.to_string(),
        }
    }

    fn write(dir: &tempfile::TempDir, name: &str, body: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    // ── the file itself ─────────────────────────────────────────────────────

    #[test]
    fn a_missing_file_is_not_an_error_by_itself() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = load_known_hosts(&dir.path().join("absent.toml")).expect("not an error");
        assert!(hosts.is_empty());
    }

    #[test]
    fn entries_are_read_in_order_with_repeats_per_host() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            "trusted.toml",
            &format!(
                "[[network.known_hosts]]\nhost = \"github.com:22\"\nkey = \"{ED25519}\"\n\n\
                 [[network.known_hosts]]\nhost = \"github.com:22\"\nkey = \"ssh-rsa {}\"\n",
                "A".repeat(64)
            ),
        );
        let hosts = load_known_hosts(&path).expect("parses");
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].host, "github.com:22");
    }

    #[test]
    fn an_unknown_field_is_rejected_rather_than_ignored() {
        // A typo'd field name silently authorizing nothing is the failure mode
        // this prevents -- it surfaces as a refusal the operator already tried
        // to fix.
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            "trusted.toml",
            &format!("[[network.known_hosts]]\nhost = \"github.com:22\"\nkeys = \"{ED25519}\"\n"),
        );
        assert!(load_known_hosts(&path).is_err());
    }

    // ── key validation ──────────────────────────────────────────────────────

    #[test]
    fn a_real_key_of_each_type_validates() {
        for key in [
            ED25519,
            &format!("ssh-rsa {}", "B".repeat(300)),
            &format!("ecdsa-sha2-nistp256 {}", "C".repeat(90)),
            // Trailing comments are part of the format.
            &format!("{} user@host", ED25519),
        ] {
            validate_known_host(&entry("github.com:22", key)).unwrap_or_else(|e| {
                panic!("rejected a valid key: {e}");
            });
        }
    }

    #[test]
    fn a_fingerprint_is_not_a_key() {
        let err = validate_known_host(&entry(
            "github.com:22",
            "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("fingerprint"), "{err}");
    }

    #[test]
    fn a_whole_known_hosts_line_says_to_drop_the_host() {
        let err = validate_known_host(&entry("github.com:22", &format!("github.com {ED25519}")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("Drop the leading host"), "{err}");
    }

    #[test]
    fn markers_and_hashed_hosts_are_refused() {
        let err = validate_known_host(&entry(
            "github.com:22",
            &format!("@cert-authority {ED25519}"),
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("@cert-authority"), "{err}");

        let err = validate_known_host(&entry("|1|abc=|def=", ED25519))
            .unwrap_err()
            .to_string();
        assert!(err.contains("hashed"), "{err}");
    }

    #[test]
    fn an_empty_or_truncated_key_is_refused() {
        assert!(validate_known_host(&entry("github.com:22", "")).is_err());
        assert!(validate_known_host(&entry("github.com:22", "ssh-ed25519")).is_err());
        assert!(validate_known_host(&entry("github.com:22", "ssh-ed25519 AAAAC3Nza")).is_err());
        assert!(validate_known_host(&entry("", ED25519)).is_err());
    }

    // ── rendering ───────────────────────────────────────────────────────────

    #[test]
    fn port_22_renders_bare_and_any_other_port_bracketed() {
        let rendered = render_known_hosts(&[
            entry("github.com:22", ED25519),
            entry("gitlab.com", ED25519),
            entry("git.example.com:2222", ED25519),
        ]);
        assert!(
            rendered.contains(&format!("github.com {ED25519}\n")),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("gitlab.com {ED25519}\n")),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("[git.example.com]:2222 {ED25519}\n")),
            "{rendered}"
        );
        // known_hosts is line-oriented; a missing final newline corrupts an append.
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn the_host_is_lowercased_but_the_key_is_untouched() {
        let rendered = render_known_hosts(&[entry("GitHub.COM:22", ED25519)]);
        assert!(rendered.starts_with("github.com "), "{rendered}");
        assert!(rendered.contains(ED25519), "{rendered}");
    }

    // ── the requirement ─────────────────────────────────────────────────────

    #[test]
    fn a_matching_entry_authorizes_the_host() {
        let trusted = vec![entry("github.com:22", ED25519)];
        let signing = vec!["github.com".to_string()];
        assert!(unauthorized_signing_hosts(&signing, &trusted).is_empty());
    }

    #[test]
    fn a_portless_entry_authorizes_the_default_port() {
        let trusted = vec![entry("github.com", ED25519)];
        assert!(unauthorized_signing_hosts(&["github.com".to_string()], &trusted).is_empty());
    }

    #[test]
    fn matching_is_case_insensitive_on_the_domain() {
        let trusted = vec![entry("GitHub.com:22", ED25519)];
        assert!(unauthorized_signing_hosts(&["github.com".to_string()], &trusted).is_empty());
    }

    #[test]
    fn a_different_domain_authorizes_nothing() {
        let trusted = vec![entry("gitlab.com:22", ED25519)];
        assert_eq!(
            unauthorized_signing_hosts(&["github.com".to_string()], &trusted),
            vec!["github.com".to_string()]
        );
    }

    #[test]
    fn a_wildcard_is_matched_as_written_not_expanded() {
        // The relay matches `*.github.com` as a pattern, so the trusted entry
        // has to be that pattern -- an apex entry does not stand in for it.
        let trusted = vec![entry("github.com:22", ED25519)];
        assert_eq!(
            unauthorized_signing_hosts(&["*.github.com".to_string()], &trusted),
            vec!["*.github.com".to_string()]
        );

        let trusted = vec![entry("*.github.com:22", ED25519)];
        assert!(unauthorized_signing_hosts(&["*.github.com".to_string()], &trusted).is_empty());
    }

    #[test]
    fn an_entry_for_another_port_does_not_authorize_port_22() {
        // It is still rendered into the file for `ssh -p 2222`; it just is not
        // authorization for the port the relay will actually use.
        let trusted = vec![entry("git.example.com:2222", ED25519)];
        assert_eq!(
            unauthorized_signing_hosts(&["git.example.com".to_string()], &trusted),
            vec!["git.example.com".to_string()]
        );
        assert!(render_known_hosts(&trusted).contains("[git.example.com]:2222"));
    }

    #[test]
    fn a_csv_port_list_pulls_the_requirement_in_the_same_way() {
        // The launcher derives allow_signing from any port spec covering 22,
        // and the requirement follows that rather than the TOML text -- so a
        // list and a range are caught on the same terms as a lone `:22`.
        let trusted = vec![entry("github.com:22", ED25519)];
        for spec in ["github.com:22", "github.com:443,22", "github.com:20-30"] {
            let agents_md = format!(
                "```agent-sandbox\n[network]\nallowed_hosts = [\"{}\"]\n```\n",
                spec
            );
            let policy = crate::agents::parse_proxy(&agents_md).expect("parses");
            assert_eq!(
                policy.allow_signing,
                vec!["github.com".to_string()],
                "{spec}"
            );
            assert!(
                unauthorized_signing_hosts(&policy.allow_signing, &trusted).is_empty(),
                "{spec}"
            );
            assert_eq!(
                unauthorized_signing_hosts(&policy.allow_signing, &[]),
                vec!["github.com".to_string()],
                "{spec}"
            );
        }
    }

    #[test]
    fn a_policy_that_opens_no_ssh_port_requires_nothing() {
        let agents_md = "```agent-sandbox\n[network]\nallowed_hosts = [\"github.com:443\"]\n```\n";
        let policy = crate::agents::parse_proxy(agents_md).expect("parses");
        assert!(policy.allow_signing.is_empty());
        assert!(unauthorized_signing_hosts(&policy.allow_signing, &[]).is_empty());
    }

    // ── the refusal ─────────────────────────────────────────────────────────

    #[test]
    fn the_refusal_for_a_known_forge_carries_the_key() {
        let text = refusal(&["github.com".to_string()], Path::new("/c/trusted.toml"));
        assert!(text.contains("github.com"), "{text}");
        assert!(text.contains("/c/trusted.toml"), "{text}");
        // Flush-left, so it can be pasted without stripping indentation.
        assert!(
            text.contains("\n[[network.known_hosts]]\nhost = \"github.com:22\"\n"),
            "{text}"
        );
        assert!(
            text.contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkV"),
            "{text}"
        );
    }

    #[test]
    fn the_refusal_for_an_unknown_host_asks_for_a_keyscan() {
        let text = refusal(
            &["git.example.com".to_string()],
            Path::new("/c/trusted.toml"),
        );
        assert!(text.contains("key = \"\""), "{text}");
        assert!(text.contains("ssh-keyscan git.example.com"), "{text}");
    }

    #[test]
    fn every_block_the_refusal_prints_is_a_block_the_loader_accepts() {
        // The advice has to work. Paste the suggestion back in and it must
        // both parse and satisfy the requirement it was printed for.
        let dir = tempfile::tempdir().unwrap();
        let text = refusal(&["github.com".to_string()], Path::new("/c/trusted.toml"));
        let blocks: String = text
            .lines()
            .skip_while(|l| !l.starts_with("[[network.known_hosts]]"))
            .filter(|l| {
                l.starts_with("[[network.known_hosts]]")
                    || l.starts_with("host = ")
                    || l.starts_with("key = ")
                    || l.is_empty()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let path = write(&dir, "trusted.toml", &blocks);

        let trusted = load_known_hosts(&path).unwrap_or_else(|e| {
            panic!("the loader rejected the refusal's own suggestion: {e}\n{blocks}")
        });
        assert!(!trusted.is_empty(), "{blocks}");
        assert!(
            unauthorized_signing_hosts(&["github.com".to_string()], &trusted).is_empty(),
            "{blocks}"
        );
    }

    // ── paths ───────────────────────────────────────────────────────────────

    #[test]
    fn the_config_path_follows_xdg_when_it_is_set() {
        // Serialised with the other env-var test: std::env::set_var is process
        // global, and these two would otherwise race.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        assert_eq!(
            config_path("/home/nobody"),
            dir.path().join("agent-sandbox/trusted.toml")
        );
        std::env::remove_var("XDG_CONFIG_HOME");
        assert_eq!(
            config_path("/home/nobody"),
            PathBuf::from("/home/nobody/.config/agent-sandbox/trusted.toml")
        );
    }

    #[test]
    fn the_legacy_refusal_fires_only_before_the_rename() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::fs::create_dir_all(dir.path().join("agent-sandbox")).unwrap();

        // Neither file: nothing to say.
        assert!(legacy_path_refusal("/home/nobody").is_none());

        // Only the old one: refuse, naming the mv.
        std::fs::write(dir.path().join("agent-sandbox/secrets.toml"), "").unwrap();
        let msg = legacy_path_refusal("/home/nobody").expect("a refusal");
        assert!(msg.contains("renamed to trusted.toml"), "{msg}");
        assert!(msg.contains("mv "), "{msg}");

        // Both: the new one wins and the old is left alone.
        std::fs::write(dir.path().join("agent-sandbox/trusted.toml"), "").unwrap();
        assert!(legacy_path_refusal("/home/nobody").is_none());

        std::env::remove_var("XDG_CONFIG_HOME");
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
