use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::os::unix::process::CommandExt;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-attach",
    about = "Executes an interactive command inside a running sandbox.\nIf no command is provided, starts an interactive bash shell."
)]
pub struct AttachArgs {
    #[arg(
        help = "The session word or full container name of the sandbox.\nIf omitted, acts on the current workspace's sandbox."
    )]
    pub word: Option<String>,

    #[arg(last = true, help = "The command to execute (default: bash)")]
    pub cmd: Vec<String>,
}

pub fn run(args: AttachArgs) -> Result<()> {
    let sandbox = resolve_sandbox(args.word.as_deref(), true)?;

    refuse_if_krun(
        &sandbox,
        "attach",
        &[
            "crun's libkrun handler implements no exec, so there is no way into the guest.",
            "Either launch a second sandbox on the same workspace, or run the shell as",
            "the sandbox's own command:  agent-sandbox --krun -- bash",
        ],
    )?;

    let mut cmd = args.cmd;
    if cmd.is_empty() {
        cmd.push("bash".to_string());
    }

    let mut podman = Command::new("podman");
    podman.arg("exec").arg("-it");

    for var in runtime_env(&sandbox) {
        podman.arg("--env").arg(var);
    }

    podman.arg(&sandbox).args(&cmd);

    let err = podman.exec();
    Err(anyhow::anyhow!("exec failed: {}", err))
}

/// The environment the entrypoint built after `podman run` handed it the
/// container's own.
///
/// `podman exec` starts from the container's configured environment, which is
/// what the launcher passed to `podman run` -- so everything the entrypoint
/// derived at startup (the merged CA bundle, the SSH relay wiring, the
/// flattened host git config) was missing from an attached shell, and
/// `git clone git@github.com:...` failed there while succeeding in the session
/// the launcher started.  The entrypoint writes those variables to
/// `ENV_FILE`; this reads them back.
///
/// Best-effort by design: a sandbox from an older image has no such file, and
/// attaching to it must still work, just with the barer environment it had
/// before.
fn runtime_env(sandbox: &str) -> Vec<String> {
    const ENV_FILE: &str = "/home/user/.config/agent-sandbox/env";

    let Ok(out) = Command::new("podman")
        .args(["exec", sandbox, "cat", ENV_FILE])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| {
            // NAME=VALUE with a non-empty name; anything else would be passed
            // to podman as a request to *forward* a host variable of that name.
            l.split_once('=').is_some_and(|(name, _)| !name.is_empty())
        })
        .map(|l| l.to_string())
        .collect()
}
