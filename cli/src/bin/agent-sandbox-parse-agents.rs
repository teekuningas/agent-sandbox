#![forbid(unsafe_code)]

use agent_sandbox_cli::agents::{
    allocate, format_proxy_policy, parse_mounts, parse_ports, parse_proxy, MAX_PORTS,
};
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-parse-agents",
    about = "Emit podman --publish operands declared in an AGENTS.md."
)]
struct Args {
    #[arg(help = "path to AGENTS.md")]
    path: PathBuf,

    #[arg(long = "ports-any-interface", help = "permit binds outside loopback")]
    ports_any_interface: bool,

    #[arg(long, default_value_t = MAX_PORTS, help = "cap on mappings (default 32)")]
    max: usize,

    #[arg(
        long = "no-allocate",
        help = "leave `host = 0` unresolved instead of picking a free port"
    )]
    no_allocate: bool,

    #[arg(
        long = "proxy-policy",
        help = "emit the [proxy] policy file the proxy reads, instead of port mappings"
    )]
    proxy_policy: bool,

    #[arg(long, help = "emit -v volume specs instead of port mappings")]
    mounts: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let text = match fs::read_to_string(&args.path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agent-sandbox: cannot read {}: {}", args.path.display(), e);
            return ExitCode::FAILURE;
        }
    };

    if args.proxy_policy {
        let policy = match parse_proxy(&text) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("agent-sandbox: {}: {}", args.path.display(), e);
                return ExitCode::FAILURE;
            }
        };
        print!(
            "{}",
            format_proxy_policy(&policy, &args.path.to_string_lossy())
        );
        return ExitCode::SUCCESS;
    }

    if args.mounts {
        let mounts = match parse_mounts(&text) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("agent-sandbox: {}: {}", args.path.display(), e);
                return ExitCode::FAILURE;
            }
        };
        for spec in mounts {
            println!("{}", spec);
        }
        return ExitCode::SUCCESS;
    }

    let mut mappings = match parse_ports(&text, args.ports_any_interface, args.max) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("agent-sandbox: {}: {}", args.path.display(), e);
            return ExitCode::FAILURE;
        }
    };

    if !args.no_allocate {
        let mut allocated = Vec::new();
        for m in mappings {
            match allocate(m) {
                Ok(a) => allocated.push(a),
                Err(e) => {
                    eprintln!("agent-sandbox: cannot allocate a host port: {}", e);
                    return ExitCode::FAILURE;
                }
            }
        }
        mappings = allocated;
    }

    for mapping in mappings {
        println!("{}", mapping.spec());
    }

    ExitCode::SUCCESS
}
