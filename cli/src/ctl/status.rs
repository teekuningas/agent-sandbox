use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-status",
    about = "Summarises one running sandbox: workspace, proxy mode, policy and traffic\ncounts, and published ports.  Each line names the command that shows more.\n\nWith one sandbox running, --sandbox may be omitted."
)]
pub struct StatusArgs {
    #[arg(short, long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,

    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
}

pub fn run(args: StatusArgs) -> Result<()> {
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
            eprintln!("agent-sandbox-status: invalid sandbox name: {}", name);
            std::process::exit(1);
        }
    }

    let sandbox = resolve_sandbox(sandbox_name.as_deref(), true)?;
    let workspace_dir = sandbox_workspace(&sandbox)?;
    let sidecar = sidecar_for_sandbox(&sandbox)?;

    let row = |k: &str, v: &str| {
        println!("  {:<12}{}", k, v);
    };

    println!("{}", sandbox_word(&sandbox));
    row("workspace", &workspace_dir);

    let mut status_cmd = Command::new("podman");
    status_cmd
        .arg("ps")
        .arg("--filter")
        .arg(format!("name=^{}$", sandbox))
        .arg("--format")
        .arg("{{.Status}}");
    let uptime = String::from_utf8(status_cmd.output()?.stdout)?
        .trim()
        .to_string();
    row("uptime", &uptime);

    let mode = sandbox_proxy_mode(&sandbox)?;
    match mode.as_str() {
        "proxy" => row("proxy", &format!("on  ({})", short_name(&sidecar))),
        "off" => row("proxy", "off  (direct network access)"),
        _ => {
            let s = format!("on  ({})", short_name(&sidecar));
            row("proxy", if !sidecar.is_empty() { &s } else { "unknown" })
        }
    }

    let runtime = sandbox_runtime(&sandbox)?;
    if runtime == "krun" {
        row("runtime", "krun  (microVM; no attach, no mounts)");
    } else {
        row("runtime", "crun");
    }

    let mut net_cmd = Command::new("podman");
    net_cmd
        .arg("inspect")
        .arg("--format")
        .arg("{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}")
        .arg(&sandbox);
    if let Ok(out) = net_cmd.output() {
        let nets = String::from_utf8(out.stdout)?.trim().to_string();
        if !nets.is_empty() {
            row("networks", &nets);
        }
    }

    if !sidecar.is_empty() {
        if let Ok(policy_dir) = sidecar_mount(&sidecar, "/sidecar_policy") {
            if !policy_dir.is_empty() {
                let policy_file = format!("{}/policy", policy_dir);
                if std::path::Path::new(&policy_file).exists() {
                    let rules_cmd = Command::new("grep")
                        .arg("-cE")
                        .arg("^(allow|deny)_")
                        .arg(&policy_file)
                        .output()?;
                    let rules = String::from_utf8(rules_cmd.stdout)?.trim().to_string();
                    let rules = if rules.is_empty() { "0" } else { &rules };

                    let mut default = "allow".to_string();
                    let allow_cmd = Command::new("grep")
                        .arg("-q")
                        .arg("^allow_")
                        .arg(&policy_file)
                        .status()?;
                    if allow_cmd.success() {
                        default = "deny".to_string();
                    }

                    let def_cmd = Command::new("grep")
                        .arg("^default ")
                        .arg(&policy_file)
                        .output()?;
                    let def_out = String::from_utf8(def_cmd.stdout)?;
                    if let Some(last_line) = def_out.lines().last() {
                        let parts: Vec<&str> = last_line.split_whitespace().collect();
                        if parts.len() >= 2 && parts[0] == "default" {
                            default = parts[1].to_string();
                        }
                    }

                    row(
                        "policy",
                        &format!(
                            "{} rule(s), default {}        agent-sandbox ctl proxy show",
                            rules, default
                        ),
                    );
                }
            }
        }

        if let Ok(log_dir) = sidecar_mount(&sidecar, "/sidecar_shared") {
            if !log_dir.is_empty() {
                let log_file = format!("{}/connections.jsonl", log_dir);
                if std::path::Path::new(&log_file).exists() {
                    let awk_script = r#"
                        /"ev":"open"/ { opens++; next }
                        {
                            if (/"ev":"close"/) closes++
                            if (/"verdict":"allow"/) ok++
                            else if (/"verdict":"deny"/) deny++
                            else if (/"verdict":"error"/) err++
                        }
                        END {
                            live = opens - closes
                            if (live < 0) live = 0
                            printf "%d %d %d %d", ok+0, deny+0, err+0, live
                        }
                    "#;
                    let awk_cmd = Command::new("awk")
                        .arg(awk_script)
                        .arg(&log_file)
                        .output()?;
                    let awk_out = String::from_utf8(awk_cmd.stdout)?;
                    let counts: Vec<&str> = awk_out.trim().split_whitespace().collect();
                    if counts.len() == 4 {
                        let ok: i32 = counts[0].parse().unwrap_or(0);
                        let deny: i32 = counts[1].parse().unwrap_or(0);
                        let err: i32 = counts[2].parse().unwrap_or(0);
                        let live: i32 = counts[3].parse().unwrap_or(0);

                        let mut summary = format!("{} connection(s)", ok);
                        if deny > 0 {
                            summary.push_str(&format!(", {} denied", deny));
                        }
                        if err > 0 {
                            summary.push_str(&format!(", {} failed", err));
                        }
                        if live > 0 {
                            summary.push_str(&format!(", {} in flight", live));
                        }

                        row(
                            "network",
                            &format!("{}        agent-sandbox ctl net", summary),
                        );
                        row("log", "                         agent-sandbox ctl logs");
                    }
                }
            }
        }
    }

    let mut pub_cmd = Command::new("podman");
    let pub_out = pub_cmd.arg("port").arg(&sandbox).output()?;
    let published = String::from_utf8_lossy(&pub_out.stdout).replace('\n', " ");
    let published = published.trim();

    if !published.is_empty() {
        row("ports", &published.to_string());
    } else {
        row("ports", "none published");
    }

    Ok(())
}
