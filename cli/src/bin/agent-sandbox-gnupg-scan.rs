#![forbid(unsafe_code)]

use agent_sandbox_cli::gpg::{scan_gnupg_home, GpgScanStatus};
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::process;

/// Decide whether a GnuPG home is safe to expose to the sandbox.
#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-gnupg-scan")]
struct Args {
    /// The GnuPG home directory to scan. Defaults to ~/.gnupg if not provided.
    #[arg(name = "GNUPGHOME")]
    gnupg_home: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let gnupg_home = match args.gnupg_home {
        Some(path) => PathBuf::from(path),
        None => {
            if let Some(home) = std::env::var_os("HOME") {
                let mut path = PathBuf::from(home);
                path.push(".gnupg");
                path
            } else {
                eprintln!("Error: GNUPGHOME not provided and HOME environment variable not set.");
                process::exit(1);
            }
        }
    };

    match scan_gnupg_home(&gnupg_home) {
        Ok(GpgScanStatus::Safe) => {
            process::exit(0);
        }
        Ok(GpgScanStatus::Unsafe(offenders)) => {
            for offender in offenders {
                println!("{}", offender.display());
            }
            process::exit(2);
        }
        Err(e) => {
            eprintln!("Error scanning GnuPG home: {}", e);
            process::exit(1);
        }
    }
}
