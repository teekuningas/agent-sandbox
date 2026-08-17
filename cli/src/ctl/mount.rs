use super::resolve::*;
use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::path::Path;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-mount",
    about = "Inspect and manage bind mounts into a running sandbox"
)]
pub struct MountArgs {
    #[command(subcommand)]
    pub command: MountCommand,
}

#[derive(Subcommand, Debug)]
pub enum MountCommand {
    #[command(
        about = "Show the bind mounts added on top of the launcher's own",
        alias = "list"
    )]
    Ls(TargetArgs),
    #[command(about = "Bind-mount a host directory into a running sandbox")]
    Add(AddArgs),
    #[command(
        about = "Unmount a container path from a running sandbox",
        alias = "remove"
    )]
    Rm(RmArgs),
    #[command(about = "Print the sandbox's mounts as an AGENTS.md [mounts] TOML block")]
    Export(TargetArgs),
}

#[derive(Parser, Debug)]
pub struct TargetArgs {
    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
}

#[derive(Parser, Debug)]
pub struct AddArgs {
    #[arg(help = "Host directory to bind")]
    pub host_path: String,
    #[arg(help = "Absolute path inside the sandbox")]
    pub container_path: String,
    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
}

#[derive(Parser, Debug)]
pub struct RmArgs {
    #[arg(help = "Path inside the sandbox to unmount")]
    pub container_path: String,
    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PodmanMount {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Source")]
    source: String,
    #[serde(rename = "Destination")]
    destination: String,
    #[serde(rename = "Options", default)]
    options: Vec<String>,
}

/// Everything the launcher binds itself: the workspace, agent state, the
/// forwarded sockets, the synthesized passwd/group.  What is left is what
/// someone declared or added deliberately, which is the only thing worth
/// listing or round-tripping into `AGENTS.md`.
///
/// `workspace_dir` is the container path the host CWD was mounted at; a
/// *different* path under `/workspace` is a declared `[mounts]` entry and
/// stays in the listing.
fn is_launcher_bind(destination: &str, workspace_dir: &str) -> bool {
    let baseline = [
        "/workspace",
        "/agent.sock",
        "/home/user/.local/share/devenv",
    ];
    if baseline.contains(&destination) || destination == workspace_dir {
        return true;
    }
    let prefixes = [
        "/home/user/.local/share/opencode",
        "/home/user/.local/share/antigravity-cli",
        "/home/user/.config/",
        "/home/user/.cache/",
        "/home/user/.claude",
        "/home/user/.copilot",
        "/home/user/.gemini",
        "/home/user/.gitconfig",
        "/home/user/.gnupg",
        "/home/user/.ssh",
        "/run/",
        "/sidecar_",
        "/nix",
        "/etc/",
    ];
    prefixes.iter().any(|p| destination.starts_with(p))
}

/// The container path the workspace was mounted at, derived from the label the
/// launcher records.  Empty when the sandbox was launched with `--no-workspace`.
fn workspace_dir(sandbox: &str) -> String {
    let workspace = sandbox_workspace(sandbox).unwrap_or_default();
    match Path::new(&workspace).file_name() {
        Some(name) if !workspace.is_empty() => format!("/workspace/{}", name.to_string_lossy()),
        _ => String::new(),
    }
}

fn added_mounts(sandbox: &str) -> Result<Vec<PodmanMount>> {
    let out = Command::new("podman")
        .args(["inspect", "--format", "{{json .Mounts}}", sandbox])
        .output()?;
    if !out.status.success() {
        return Ok(Vec::new());
    }
    let workspace_dir = workspace_dir(sandbox);
    let parsed: Vec<PodmanMount> = serde_json::from_slice(&out.stdout).unwrap_or_default();
    Ok(parsed
        .into_iter()
        .filter(|m| m.kind == "bind" && !is_launcher_bind(&m.destination, &workspace_dir))
        .collect())
}

fn target(word: &Option<String>, sandbox: &Option<String>) -> Option<String> {
    sandbox.clone().or_else(|| word.clone())
}

fn container_pid(sandbox: &str) -> Result<String> {
    let out = Command::new("podman")
        .args(["inspect", "--format", "{{.State.Pid}}", sandbox])
        .output()?;
    let pid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || pid.is_empty() || pid == "0" {
        eprintln!(
            "agent-sandbox ctl mounts: '{}' has no running process",
            sandbox_word(sandbox)
        );
        std::process::exit(1);
    }
    Ok(pid)
}

fn run_ls(args: TargetArgs) -> Result<()> {
    let explicit = target(&args.word, &args.container);
    let names = if explicit.is_some() {
        vec![resolve_sandbox(explicit.as_deref(), true)?]
    } else {
        sandbox_containers()?
    };

    if names.is_empty() {
        println!("No running sandboxes.");
        return Ok(());
    }

    for sandbox in names {
        println!("{}", sandbox_word(&sandbox));
        println!(
            "  workspace   {}",
            sandbox_workspace(&sandbox).unwrap_or_default()
        );
        let mounts = added_mounts(&sandbox)?;
        if mounts.is_empty() {
            println!("  mount       (none)");
        }
        for m in mounts {
            if m.options.is_empty() {
                println!("  mount       {} -> {}", m.source, m.destination);
            } else {
                println!(
                    "  mount       {} -> {} ({})",
                    m.source,
                    m.destination,
                    m.options.join(",")
                );
            }
        }
    }
    Ok(())
}

fn run_export(args: TargetArgs) -> Result<()> {
    let explicit = target(&args.word, &args.container);
    let sandbox = resolve_sandbox(explicit.as_deref(), true)?;
    let workspace = sandbox_workspace(&sandbox).unwrap_or_default();
    let mounts = added_mounts(&sandbox)?;
    if mounts.is_empty() {
        return Ok(());
    }

    println!("```toml agent-sandbox");
    println!("[mounts]");
    for m in mounts {
        // A source under the workspace comes back as a relative path, which is
        // what makes the block portable to another checkout.
        let source = if !workspace.is_empty() && m.source == workspace {
            ".".to_string()
        } else if !workspace.is_empty() && m.source.starts_with(&format!("{}/", workspace)) {
            m.source[workspace.len() + 1..].to_string()
        } else {
            m.source.clone()
        };
        // Only the options AGENTS.md can express; the rest are podman defaults
        // that a declaration would not have set.
        let declared: Vec<&str> = m
            .options
            .iter()
            .filter(|o| *o == "ro" || *o == "rw" || *o == "z" || *o == "Z")
            .map(|o| o.as_str())
            .collect();
        if declared.is_empty() || declared == ["rw"] {
            println!("\"{}\" = \"{}\"", source, m.destination);
        } else {
            println!(
                "\"{}\" = {{ destination = \"{}\", options = \"{}\" }}",
                source,
                m.destination,
                declared.join(",")
            );
        }
    }
    println!("```");
    Ok(())
}

fn run_add(args: AddArgs) -> Result<()> {
    let explicit = target(&args.word, &args.container);
    let sandbox = resolve_sandbox(explicit.as_deref(), true)?;

    let host_path = Path::new(&args.host_path);
    if !host_path.is_dir() {
        eprintln!(
            "agent-sandbox ctl mounts: host path '{}' does not exist or is not a directory",
            args.host_path
        );
        std::process::exit(1);
    }
    let host_path = host_path.canonicalize()?.to_string_lossy().into_owned();

    if !args.container_path.starts_with('/') {
        eprintln!("agent-sandbox ctl mounts: container path must be absolute");
        std::process::exit(1);
    }

    // Before the relabel below, which would otherwise start a throwaway
    // container for nothing.  This refusal matters more than attach's: the
    // nsenter --bind at the end *succeeds* against a microVM and changes
    // nothing the guest can see, so without the guard the command would report
    // success and do nothing at all.
    refuse_if_krun(
        &sandbox,
        "mounts add",
        &[
            "A host-side bind lands in the VMM's mount namespace, not in the guest, so it",
            "would appear to succeed and have no effect.  virtio-fs cannot take a new",
            "share after boot.  Relaunch with the mount in place:",
            "  agent-sandbox --krun --podman-args -v HOST:CONTAINER --",
        ],
    )?;

    // Launched with --selinux: use podman's own relabeling rather than
    // guessing chcon arguments.
    let modes = Command::new("podman")
        .args([
            "inspect",
            "--format",
            "{{range .Mounts}}{{.Mode}} {{end}}",
            &sandbox,
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if modes.split_whitespace().any(|m| m == "z" || m == "Z") {
        if let Ok(image) = std::env::var("AGENT_SANDBOX_IMAGE") {
            let _ = Command::new("podman")
                .args(["run", "--rm", "--entrypoint", "/bin/true", "-v"])
                .arg(format!("{}:/tmp/relabel:z", host_path))
                .arg(image)
                .output();
        }
    }

    let pid = container_pid(&sandbox)?;
    let made = Command::new("podman")
        .args(["exec", &sandbox, "mkdir", "-p", &args.container_path])
        .status()?;
    if !made.success() {
        eprintln!(
            "agent-sandbox ctl mounts: could not create {} in {}",
            args.container_path,
            sandbox_word(&sandbox)
        );
        std::process::exit(1);
    }

    let bound = Command::new("podman")
        .args([
            "unshare",
            "nsenter",
            "-t",
            &pid,
            "-m",
            "mount",
            "--bind",
            &host_path,
            &args.container_path,
        ])
        .status()?;
    if !bound.success() {
        eprintln!("agent-sandbox ctl mounts: bind mount failed");
        std::process::exit(1);
    }
    println!(
        "Mounted {} to {}:{}",
        host_path,
        sandbox_word(&sandbox),
        args.container_path
    );
    Ok(())
}

fn run_rm(args: RmArgs) -> Result<()> {
    let explicit = target(&args.word, &args.container);
    let sandbox = resolve_sandbox(explicit.as_deref(), true)?;
    refuse_if_krun(
        &sandbox,
        "mounts rm",
        &[
            "A host-side unmount acts in the VMM namespace, not in the guest.",
            "Relaunch the --krun sandbox without the mount, or manage mounts before launch.",
        ],
    )?;
    let pid = container_pid(&sandbox)?;
    let status = Command::new("podman")
        .args([
            "unshare",
            "nsenter",
            "-t",
            &pid,
            "-m",
            "umount",
            &args.container_path,
        ])
        .status()?;
    if !status.success() {
        eprintln!(
            "agent-sandbox ctl mounts: could not unmount {}",
            args.container_path
        );
        std::process::exit(1);
    }
    println!(
        "Unmounted {}:{}",
        sandbox_word(&sandbox),
        args.container_path
    );
    Ok(())
}

pub fn run(args: MountArgs) -> Result<()> {
    match args.command {
        MountCommand::Ls(a) => run_ls(a),
        MountCommand::Add(a) => run_add(a),
        MountCommand::Rm(a) => run_rm(a),
        MountCommand::Export(a) => run_export(a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_binds_are_filtered_out_of_the_listing() {
        for baseline in [
            "/workspace",
            "/workspace/repo",
            "/agent.sock",
            "/etc/passwd",
            "/etc/group",
            "/nix/store",
            "/run/host-gpg-agent",
            "/sidecar_policy",
            "/home/user/.claude",
            "/home/user/.local/share/opencode",
            "/home/user/.local/share/devenv",
        ] {
            assert!(
                is_launcher_bind(baseline, "/workspace/repo"),
                "{} should be filtered",
                baseline
            );
        }
        for added in ["/data", "/var/log/app", "/tmp/cache", "/home/user/scratch"] {
            assert!(
                !is_launcher_bind(added, "/workspace/repo"),
                "{} should be listed",
                added
            );
        }
    }

    #[test]
    fn a_declared_mount_under_workspace_is_not_mistaken_for_the_workspace() {
        // `"data" = "/workspace/data"` from AGENTS.md: not the CWD bind, so it
        // has to survive into `ls` and `export`.
        assert!(!is_launcher_bind("/workspace/data", "/workspace/repo"));
        assert!(is_launcher_bind("/workspace/repo", "/workspace/repo"));
    }
}
