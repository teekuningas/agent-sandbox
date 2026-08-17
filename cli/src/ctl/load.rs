use anyhow::Result;
use clap::Parser;
use std::env;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-load",
    about = "Build the agent-sandbox image and import it into podman. Takes no options."
)]
pub struct LoadArgs {}

pub fn run(_args: LoadArgs) -> Result<()> {
    let image = env::var("AGENT_SANDBOX_IMAGE").unwrap_or_else(|_| "agent-sandbox".to_string());
    let stream = env::var("AGENT_SANDBOX_IMAGE_STREAM").unwrap_or_else(|_| "".to_string());

    println!("Loading {} into podman...", image);

    if stream.is_empty() {
        eprintln!("AGENT_SANDBOX_IMAGE_STREAM is not set");
        std::process::exit(1);
    }

    let mut child = Command::new(&stream)
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let mut podman = Command::new("podman")
        .arg("load")
        .stdin(child.stdout.take().unwrap())
        .spawn()?;

    let status = podman.wait()?;
    if status.success() {
        println!("Done. Run 'agent-sandbox' to start a session.");
    } else {
        eprintln!("Failed to load image");
        std::process::exit(1);
    }

    Ok(())
}
