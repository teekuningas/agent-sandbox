use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-purge",
    about = "Reclaim leftover containers, networks and directories"
)]
pub struct PurgeArgs {
    #[arg(
        long,
        help = "also remove running sandboxes, their sidecars and networks"
    )]
    pub all: bool,

    #[arg(
        short = 'n',
        long,
        help = "report what would be removed, change nothing"
    )]
    pub dry_run: bool,

    #[arg(short = 'f', long, help = "do not ask for confirmation")]
    pub force: bool,
}

fn confirm(msg: &str, force: bool, dry_run: bool) -> bool {
    if dry_run {
        return false;
    }
    if force {
        return true;
    }
    print!("{} [y/N] ", msg);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let trimmed = input.trim();
        return trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes");
    }
    eprintln!("(not a terminal; pass --force to remove without asking)");
    false
}

fn containers_of_role(role: &str, filter: &str) -> Vec<String> {
    let mut cmd = Command::new("podman");
    cmd.arg("ps");
    match filter {
        "--running-only" => {
            cmd.arg("--filter")
                .arg(format!("label=agent-sandbox.role={}", role));
        }
        "--exited-only" => {
            cmd.arg("-a")
                .arg("--filter")
                .arg(format!("label=agent-sandbox.role={}", role))
                .arg("--filter")
                .arg("status=exited")
                .arg("--filter")
                .arg("status=created");
        }
        _ => {
            cmd.arg("-a")
                .arg("--filter")
                .arg(format!("label=agent-sandbox.role={}", role));
        }
    }
    cmd.arg("--format").arg("{{.Names}}");
    let out = cmd.output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect()
}

fn orphans_of_role(role: &str) -> Vec<String> {
    let mut orphans = Vec::new();
    for name in containers_of_role(role, "") {
        if name.is_empty() {
            continue;
        }
        let target = podman_inspect_label(&name, "agent-sandbox.target").unwrap_or_default();
        if target.is_empty() {
            orphans.push(name);
        } else {
            let exists = Command::new("podman")
                .arg("container")
                .arg("exists")
                .arg(&target)
                .status()
                .unwrap();
            if !exists.success() {
                orphans.push(name);
            }
        }
    }
    orphans
}

/// The launcher names a session's sidecar container, its network, and its
/// three `/tmp` directories after one uuid, so the container is what says
/// whether the rest is still in use.  Everything below keys off that.
const SIDECAR_PREFIX: &str = "agent-sandbox-sidecar-";

fn sidecar_gone(name: &str) -> bool {
    !Command::new("podman")
        .args(["container", "exists", name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Networks whose sidecar no longer exists.  These are the leak that hurts:
/// the rootless subnet pool is finite, and once it is exhausted no sandbox
/// starts with `--proxy` at all.
fn leaked_networks() -> Vec<String> {
    let Ok(out) = Command::new("podman")
        .args(["network", "ls", "--format", "{{.Name}}"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|n| n.starts_with(SIDECAR_PREFIX) && sidecar_gone(n))
        .map(String::from)
        .collect()
}

/// `/tmp/agent-sandbox-{sidecar,policy,secrets}-<uuid>`, left behind when a
/// launcher was killed before its cleanup guard could run.  The connection
/// logs are deliberately not included: they outlive their session by design,
/// so the summary stays re-renderable.
fn leaked_dirs() -> Vec<PathBuf> {
    let prefixes = [
        SIDECAR_PREFIX,
        "agent-sandbox-policy-",
        "agent-sandbox-secrets-",
    ];
    let uid = nix::unistd::getuid().as_raw();
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir("/tmp") else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(uuid) = prefixes.iter().find_map(|p| name.strip_prefix(*p)) else {
            continue;
        };
        // Someone else's session in a shared /tmp is not ours to reclaim.
        match entry.metadata() {
            Ok(m) if m.is_dir() && m.uid() == uid => {}
            _ => continue,
        }
        if sidecar_gone(&format!("{}{}", SIDECAR_PREFIX, uuid)) {
            found.push(entry.path());
        }
    }
    found.sort();
    found
}

pub fn run(args: PurgeArgs) -> Result<()> {
    println!("=== agent-sandbox-purge ===");
    if args.dry_run {
        println!("(dry run: nothing will be removed)");
    }
    println!();

    // Running sessions
    let running = containers_of_role("sandbox", "--running-only");
    if !running.is_empty() {
        if args.all {
            println!("Running sandboxes:");
            for r in &running {
                println!("  {}", sandbox_word(r));
            }
            println!();
            if args.dry_run {
                println!("  would remove {}\n", running.len());
            } else if confirm("Remove these?", args.force, args.dry_run) {
                let mut cmd = Command::new("podman");
                cmd.arg("rm").arg("-f").args(&running);
                cmd.output()?;
                println!("  removed {}\n", running.len());
            } else {
                println!("  skipped\n");
            }
        } else {
            println!("Running sandboxes (kept; pass --all to remove):");
            for r in &running {
                println!("  {}", sandbox_word(r));
            }
            println!();
        }
    }

    // Exited sandboxes come before the orphan scan below, and the order is the
    // whole point rather than a matter of taste.  A sidecar counts as orphaned
    // when its target container is gone, so a session whose sandbox has exited
    // but not yet been removed still looks live: scanning first would leave its
    // sidecar behind, and its network with it, until a second run of purge.
    // Clearing the dead sandboxes first makes one pass finish the job.
    let exited = containers_of_role("sandbox", "--exited-only");
    if !exited.is_empty() {
        println!("Exited sandboxes:");
        for e in &exited {
            println!("  {}", sandbox_word(e));
        }
        println!();
        if args.dry_run {
            println!("  would remove {}\n", exited.len());
        } else if confirm("Remove these?", args.force, args.dry_run) {
            Command::new("podman")
                .arg("rm")
                .arg("-f")
                .args(&exited)
                .output()?;
            println!("  removed {}\n", exited.len());
        } else {
            println!("  skipped\n");
        }
    }

    let orphans_proxy = orphans_of_role("proxy");
    if !orphans_proxy.is_empty() {
        println!("Orphaned proxy sidecars:");
        for o in &orphans_proxy {
            println!("  {}", short_name(o));
        }
        println!();
        if args.dry_run {
            println!("  would remove {}\n", orphans_proxy.len());
        } else if confirm("Remove these?", args.force, args.dry_run) {
            Command::new("podman")
                .arg("rm")
                .arg("-f")
                .args(&orphans_proxy)
                .output()?;
            println!("  removed {}\n", orphans_proxy.len());
        } else {
            println!("  skipped\n");
        }
    }

    // Networks and directories outlive the containers that used them, and both
    // sections run last on purpose: the container removals above are what turn
    // a live session's network and dirs into reclaimable ones, so scanning
    // after them means a single --all pass finishes the job.
    let networks = leaked_networks();
    if !networks.is_empty() {
        println!("Leaked sidecar networks:");
        for n in &networks {
            println!("  {}", short_name(n));
        }
        println!();
        if args.dry_run {
            println!("  would remove {}\n", networks.len());
        } else if confirm("Remove these?", args.force, args.dry_run) {
            let mut removed = 0;
            for n in &networks {
                let ok = Command::new("podman")
                    .args(["network", "rm", n])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if ok {
                    removed += 1;
                } else {
                    eprintln!("  could not remove {} (still in use?)", short_name(n));
                }
            }
            println!("  removed {}\n", removed);
        } else {
            println!("  skipped\n");
        }
    }

    let dirs = leaked_dirs();
    if !dirs.is_empty() {
        println!("Leaked session directories:");
        for d in &dirs {
            println!("  {}", d.display());
        }
        println!();
        if args.dry_run {
            println!("  would remove {}\n", dirs.len());
        } else if confirm("Remove these?", args.force, args.dry_run) {
            let mut removed = 0;
            for d in &dirs {
                match fs::remove_dir_all(d) {
                    Ok(()) => removed += 1,
                    Err(e) => eprintln!("  could not remove {}: {}", d.display(), e),
                }
            }
            println!("  removed {}\n", removed);
        } else {
            println!("  skipped\n");
        }
    }

    println!("Done.");
    Ok(())
}
