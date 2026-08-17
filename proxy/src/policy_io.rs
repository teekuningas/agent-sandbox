use crate::policy;
use std::fs;

/// Reads the raw `KEY VALUE` lines of a policy file, or an empty list if it
/// doesn't exist yet (e.g. a sandbox launched without any `[network]` rules).
pub fn load_policy_lines(policy_dir: &str) -> Vec<String> {
    let policy_path = format!("{}/policy", policy_dir);
    if let Ok(content) = fs::read_to_string(&policy_path) {
        content.lines().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    }
}

/// Every `deny_ip` line in a policy, as written.
fn deny_ip_lines(text: &str) -> std::collections::BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("deny_ip "))
        .map(str::to_string)
        .collect()
}

/// Validates `entries` as a policy file, then installs it atomically (write a
/// temp file, then rename over the live one) so the proxy's file watcher
/// never observes a half-written policy.
///
/// Denies are built-in only.  This is the single writer behind every
/// `agent-sandbox ctl proxy` mutation and every TUI edit, so refusing any
/// change to the `deny_ip` set here is what fixes the baseline at launch:
/// the ranges protecting the host and its LAN can be neither removed nor
/// added to for the life of the sandbox.  Widening is still possible, and
/// still an *allow*: an `allow_ip` entry of equal or greater specificity
/// beats a baseline range at the proxy and in the routing table.
pub fn install_policy(policy_dir: &str, entries: &[String]) -> Result<(), String> {
    let policy_path = format!("{}/policy", policy_dir);
    let new_path = format!("{}/.policy.new", policy_dir);

    let content = entries.join("\n") + "\n";
    policy::parse_policy(&content)?;

    // The baseline file is written once, at launch, beside the policy.
    if let Ok(baseline) = fs::read_to_string(format!("{}/policy.baseline", policy_dir)) {
        let want = deny_ip_lines(&baseline);
        let got = deny_ip_lines(&content);
        if got != want {
            let added: Vec<_> = got.difference(&want).cloned().collect();
            let removed: Vec<_> = want.difference(&got).cloned().collect();
            let mut detail = Vec::new();
            if !added.is_empty() {
                detail.push(format!("would add {}", added.join(", ")));
            }
            if !removed.is_empty() {
                detail.push(format!("would remove {}", removed.join(", ")));
            }
            return Err(format!(
                "deny rules are built-in only and cannot be changed while the sandbox runs ({}). \
                 Allow a range back with an allow_ip entry of equal or greater specificity instead.",
                detail.join("; ")
            ));
        }
    }

    if let Err(e) = fs::write(&new_path, &content) {
        let _ = fs::remove_file(&new_path);
        return Err(e.to_string());
    }
    if let Err(e) = fs::rename(&new_path, &policy_path) {
        let _ = fs::remove_file(&new_path);
        return Err(e.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASELINE: &str = "deny_ip 127.0.0.0/8\ndeny_ip 10.0.0.0/8\n";

    fn sandbox_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("policy.baseline"), BASELINE).expect("baseline");
        fs::write(
            dir.path().join("policy"),
            format!("allow_host github.com\n{BASELINE}"),
        )
        .expect("policy");
        dir
    }

    fn install(dir: &tempfile::TempDir, lines: &[&str]) -> Result<(), String> {
        let owned: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
        install_policy(&dir.path().to_string_lossy(), &owned)
    }

    #[test]
    fn an_allow_rule_installs_normally() {
        let dir = sandbox_dir();
        install(
            &dir,
            &[
                "allow_host github.com",
                "allow_host api.openai.com",
                "deny_ip 127.0.0.0/8",
                "deny_ip 10.0.0.0/8",
            ],
        )
        .expect("adding an allow rule must work");
        let written = fs::read_to_string(dir.path().join("policy")).expect("read");
        assert!(written.contains("api.openai.com"), "{written}");
    }

    #[test]
    fn dropping_a_baseline_deny_is_refused() {
        // The whole point of "denies are built-in only": no live edit, from
        // `ctl proxy` or the TUI, can take a baseline range out.
        let dir = sandbox_dir();
        let err = install(&dir, &["allow_host github.com", "deny_ip 127.0.0.0/8"])
            .expect_err("removing a baseline deny must be refused");
        assert!(err.contains("built-in only"), "{err}");
        assert!(err.contains("10.0.0.0/8"), "the message names what went missing: {err}");
        // ...and the live policy is untouched.
        let written = fs::read_to_string(dir.path().join("policy")).expect("read");
        assert!(written.contains("deny_ip 10.0.0.0/8"), "{written}");
    }

    #[test]
    fn adding_a_new_deny_is_refused_too() {
        let dir = sandbox_dir();
        let err = install(
            &dir,
            &[
                "allow_host github.com",
                "deny_ip 127.0.0.0/8",
                "deny_ip 10.0.0.0/8",
                "deny_ip 8.8.8.8/32",
            ],
        )
        .expect_err("adding a deny must be refused");
        assert!(err.contains("built-in only"), "{err}");
        assert!(err.contains("8.8.8.8"), "{err}");
    }

    #[test]
    fn re_allowing_a_baseline_range_is_still_possible() {
        // Widening is an allow, not a deny, and stays available -- it is how a
        // corporate VPN range is reached.
        let dir = sandbox_dir();
        install(
            &dir,
            &[
                "allow_host github.com",
                "allow_ip 10.0.0.0/8",
                "deny_ip 127.0.0.0/8",
                "deny_ip 10.0.0.0/8",
            ],
        )
        .expect("an equal-specificity allow_ip must install");
    }

    #[test]
    fn reset_to_the_launch_policy_still_installs() {
        let dir = sandbox_dir();
        let base = fs::read_to_string(dir.path().join("policy")).expect("read");
        let lines: Vec<&str> = base.lines().collect();
        install(&dir, &lines).expect("`ctl proxy reset` must pass the guard");
    }
}
