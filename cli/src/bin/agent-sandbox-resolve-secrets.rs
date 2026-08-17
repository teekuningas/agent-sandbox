#![forbid(unsafe_code)]
use agent_sandbox_cli::secrets::resolve_secrets_logic;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-resolve-secrets")]
#[command(about = "Resolve secrets for agent-sandbox")]
struct Cli {
    #[arg(long, help = "Path to sidecar policy file")]
    policy: PathBuf,

    #[arg(long, help = "Path to secrets config file")]
    config: PathBuf,

    #[arg(long, help = "Path to secretspec manifest")]
    file: PathBuf,

    #[arg(long, help = "Path to AGENTS.md")]
    workspace: PathBuf,
}

fn main() {
    let args = Cli::parse();
    match resolve_secrets_logic(&args.policy, &args.config, &args.file, &args.workspace) {
        Ok(bindings) => {
            for line in bindings {
                println!("{}", line);
            }
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.ends_with('\n') {
                eprint!("{}", err_str);
            } else {
                eprintln!("{}", err_str);
            }
            std::process::exit(1);
        }
    }
}
