use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-net",
    about = "Show network metering for a running sandbox"
)]
pub struct NetArgs {
    #[arg(
        short,
        long,
        help = "stream connections as the proxy records them, until Ctrl-C"
    )]
    pub follow: bool,

    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,

    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
}

pub fn run(args: NetArgs) -> Result<()> {
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
            eprintln!("agent-sandbox-net: invalid sandbox name: {}", name);
            std::process::exit(1);
        }
    }

    let sandbox = resolve_sandbox(sandbox_name.as_deref(), true)?;
    let sidecar = require_sidecar(&sandbox)?;
    let log_path = "/sidecar_shared/connections.jsonl";

    if args.follow {
        eprintln!(
            "agent-sandbox-net: following {} (Ctrl-C to stop)",
            sandbox_word(&sandbox)
        );
        let mut tail_child = Command::new("podman")
            .arg("exec")
            .arg(&sidecar)
            .arg("tail")
            .arg("-n")
            .arg("+1")
            .arg("-F")
            .arg("--")
            .arg(log_path)
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        let mut summary_cmd = Command::new("agent-sandbox-network-summary")
            .arg("--stream")
            .arg("-")
            .stdin(tail_child.stdout.take().unwrap())
            .spawn()?;

        let status = summary_cmd.wait()?;
        tail_child.kill().ok();

        let exists = Command::new("podman")
            .arg("container")
            .arg("exists")
            .arg(&sidecar)
            .status()?;
        if !exists.success() {
            println!("\n{} stopped.", sandbox_word(&sandbox));
            std::process::exit(0);
        }
        std::process::exit(status.code().unwrap_or(1));
    } else {
        let cat_out = Command::new("podman")
            .arg("exec")
            .arg(&sidecar)
            .arg("cat")
            .arg(log_path)
            .output();

        let mut summary_cmd = Command::new("agent-sandbox-network-summary")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()?;

        if let Ok(out) = cat_out {
            if out.status.success() {
                use std::io::Write;
                if let Some(mut stdin) = summary_cmd.stdin.take() {
                    stdin.write_all(&out.stdout).ok();
                }
            }
        }

        let status = summary_cmd.wait()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}
