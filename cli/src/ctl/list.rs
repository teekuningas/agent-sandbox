use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::env;
use std::io::{BufRead, BufReader};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-list",
    about = "List agent-sandbox containers.",
    after_help = "The PROXY column is the launch mode: proxy or off."
)]
pub struct ListArgs {
    #[arg(
        short,
        long,
        help = "every sandbox, any workspace, including stopped ones"
    )]
    pub all: bool,

    #[arg(long, help = "also list the proxy sidecars")]
    pub roles: bool,
}

fn container_label(name: &str, label: &str) -> String {
    podman_inspect_label(name, label).unwrap_or_default()
}

fn list_sandboxes(args: &[&str]) -> Result<()> {
    println!("CONTAINER ID\tNAMES\tSTATUS\tPROXY\tRUNTIME\tWORKSPACE\tCOMMAND");
    let mut cmd = Command::new("podman");
    cmd.arg("ps");
    for a in args {
        cmd.arg(a);
    }
    cmd.arg("--format").arg("{{.ID}}\t{{.Names}}\t{{.Status}}");

    let mut child = cmd.stdout(std::process::Stdio::piped()).spawn()?;
    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let id = parts[0];
                let name = parts[1];
                let status = parts[2];
                let ws = container_label(name, "agent-sandbox.workspace");
                let short_name = sandbox_word(name);
                let mut cmd_label = container_label(name, "agent-sandbox.command");
                if cmd_label.is_empty() {
                    let mut inspect = Command::new("podman");
                    inspect
                        .arg("inspect")
                        .arg("--format")
                        .arg("{{range .Config.Cmd}}{{.}} {{end}}")
                        .arg(name);
                    if let Ok(out) = inspect.output() {
                        cmd_label = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    }
                }
                let mut runtime = container_label(name, "agent-sandbox.runtime");
                if runtime.is_empty() {
                    runtime = "crun".to_string();
                }
                let proxy = container_label(name, "agent-sandbox.proxy");

                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    id, short_name, status, proxy, runtime, ws, cmd_label
                );
            }
        }
    }
    child.wait()?;
    Ok(())
}

fn list_role(args: &[&str]) -> Result<()> {
    println!("CONTAINER ID\tNAMES\tSTATUS\tTARGET");
    let mut cmd = Command::new("podman");
    cmd.arg("ps");
    for a in args {
        cmd.arg(a);
    }
    cmd.arg("--format").arg("{{.ID}}\t{{.Names}}\t{{.Status}}");

    let mut child = cmd.stdout(std::process::Stdio::piped()).spawn()?;
    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let id = parts[0];
                let name = parts[1];
                let status = parts[2];
                let target = container_label(name, "agent-sandbox.target");
                let target = if target.is_empty() {
                    target
                } else {
                    sandbox_word(&target)
                };
                println!("{}\t{}\t{}\t{}", id, short_name(name), status, target);
            }
        }
    }
    child.wait()?;
    Ok(())
}

pub fn run(args: ListArgs) -> Result<()> {
    let mut filter_args = vec!["--filter", "label=agent-sandbox.role=sandbox"];
    if args.all {
        println!("All agent-sandbox containers:");
        let mut ps_args = vec!["-a"];
        ps_args.extend(filter_args);
        list_sandboxes(&ps_args)?;
    } else {
        let pwd = env::current_dir()?.to_string_lossy().to_string();
        let pwd_filter = format!("label=agent-sandbox.workspace={}", pwd);
        println!("Agent-sandbox containers for {}:", pwd);
        filter_args.push("--filter");
        filter_args.push(&pwd_filter);
        list_sandboxes(&filter_args)?;
    }

    if args.roles {
        let mut ps_args = vec![];
        if args.all {
            ps_args.push("-a");
        }

        println!("\nProxy sidecars:");
        let mut proxy_args = ps_args.clone();
        proxy_args.push("--filter");
        proxy_args.push("label=agent-sandbox.role=proxy");
        list_role(&proxy_args)?;
    }

    Ok(())
}
