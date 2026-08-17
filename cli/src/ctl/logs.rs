use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-logs",
    about = "Shows the proxy sidecar's log for a sandbox."
)]
pub struct LogsArgs {
    #[arg(short, long, help = "keep streaming until Ctrl-C or the sidecar stops")]
    pub follow: bool,

    #[arg(long, help = "show only the last N lines (default: all)")]
    pub tail: Option<String>,

    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,

    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
}

pub fn run(args: LogsArgs) -> Result<()> {
    let mut sandbox_name = None;
    if let Some(s) = args.container {
        sandbox_name = Some(s);
    } else if let Some(w) = args.word {
        sandbox_name = Some(w);
    }

    if let Some(ref name) = sandbox_name {
        let valid = name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');
        let starts_valid = name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false);
        if !valid || !starts_valid {
            eprintln!("agent-sandbox-logs: invalid sandbox name: {}", name);
            std::process::exit(1);
        }
    }

    if let Some(ref t) = args.tail {
        if !t.chars().all(|c| c.is_ascii_digit()) {
            eprintln!("agent-sandbox-logs: --tail needs a line count, got: {}", t);
            std::process::exit(1);
        }
    }

    let sandbox = resolve_sandbox(sandbox_name.as_deref(), true)?;
    let sidecar = require_sidecar(&sandbox)?;

    let mut podman = Command::new("podman");
    podman.arg("logs");
    if let Some(t) = args.tail {
        podman.arg("--tail").arg(t);
    }
    if args.follow {
        podman.arg("--follow");
    }
    podman.arg(&sidecar);

    let status = podman.status()?;

    if args.follow {
        let exists = Command::new("podman")
            .arg("container")
            .arg("exists")
            .arg(&sidecar)
            .status()?;
        if !exists.success() {
            std::process::exit(0);
        }
    }
    std::process::exit(status.code().unwrap_or(1));
}
