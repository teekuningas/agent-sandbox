use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::fs;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-relay",
    about = "Show the SSH/GPG relay policy of a running sandbox, and what it has been asked for"
)]
pub struct RelayArgs {
    #[arg(short, long, help = "keep streaming relay decisions until Ctrl-C")]
    pub follow: bool,

    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,

    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
}

/// The two axes the relay authorizes independently: which hosts `git push`/
/// `pull` may reach (`allow_signing` lines), and whether GPG signing is on at
/// all (`signing_enabled`, set unconditionally by `--gpg`, host-agnostic).
/// Printed first since they explain every denial below them. Mirrors
/// `relay_server::load_signing_policy`, which reads the same file.
struct SigningPolicy {
    ssh_hosts: Vec<String>,
    gpg_enabled: bool,
}

fn load_signing_policy(policy_dir: &str) -> SigningPolicy {
    let mut ssh_hosts = Vec::new();
    let mut gpg_enabled = false;
    let text = fs::read_to_string(format!("{}/policy", policy_dir)).unwrap_or_default();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if let Some(key) = parts.next() {
            match key {
                "allow_signing" => {
                    if let Some(val) = parts.next() {
                        ssh_hosts.push(val.to_string());
                    }
                }
                "signing_enabled" => {
                    gpg_enabled = parts.next() == Some("true");
                }
                _ => {}
            }
        }
    }
    SigningPolicy {
        ssh_hosts,
        gpg_enabled,
    }
}

pub fn run(args: RelayArgs) -> Result<()> {
    let explicit = args.container.clone().or_else(|| args.word.clone());
    let sandbox = resolve_sandbox(explicit.as_deref(), true)?;
    let sidecar = require_sidecar(&sandbox)?;

    let policy_dir = sidecar_mount(&sidecar, "/sidecar_policy")?;
    if policy_dir.is_empty() {
        eprintln!(
            "agent-sandbox ctl relay: cannot find the policy mount for sandbox '{}'",
            sandbox_word(&sandbox)
        );
        std::process::exit(1);
    }

    let policy = load_signing_policy(&policy_dir);
    let hosts = &policy.ssh_hosts;
    println!("{}", sandbox_word(&sandbox));
    println!(
        "  gpg signing    {}",
        if policy.gpg_enabled {
            "enabled"
        } else {
            "disabled -- relaunch with --gpg"
        }
    );
    if hosts.is_empty() {
        println!("  ssh (push/pull) (none) -- git push/pull through the relay are refused");
        println!(
            "                 Declare an SSH port in AGENTS.md, e.g. allowed_hosts = [\"github.com:22\"]."
        );
    } else {
        for host in hosts {
            println!("  ssh (push/pull) {}", host);
        }
    }

    let has_ssh = Command::new("podman")
        .args(["exec", &sidecar, "test", "-S", "/run/host-ssh-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let has_gpg = Command::new("podman")
        .args(["exec", &sidecar, "test", "-S", "/run/host-gpg-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    println!(
        "  ssh agent      {}",
        if has_ssh {
            "forwarded"
        } else {
            "not forwarded (relaunch with --ssh)"
        }
    );
    println!(
        "  gpg agent      {}",
        if has_gpg {
            "forwarded"
        } else {
            "not forwarded (relaunch with --gpg)"
        }
    );

    // Read through the sidecar, like `ctl net` and `ctl logs`: the shared
    // directory is deliberately not mounted into the sandbox, and the host
    // path is an implementation detail of the launcher.
    let log = "/sidecar_shared/relay.jsonl";
    println!("  requests");
    let mut podman = Command::new("podman");
    podman.args(["exec", &sidecar]);
    if args.follow {
        podman.args(["tail", "-n", "+1", "-F", "--", log]);
    } else {
        podman.args(["cat", log]);
    }
    let output = podman.output()?;
    if !output.status.success() {
        println!("    (none yet)");
        return Ok(());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if text.trim().is_empty() {
        println!("    (none yet)");
    } else {
        for line in text.lines() {
            println!("    {}", line);
        }
    }
    Ok(())
}
