#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use agent_sandbox_cli::net_summary::{process_stream, process_summary, read_records};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-network-summary",
    about = "Reads the proxy connection log (NDJSON) and writes a report to stdout.\nReads stdin when LOG is \"-\" or omitted.",
    disable_help_flag = true
)]
struct Args {
    /// One line per record as it arrives, instead of the aggregate report.
    /// Records describe *completed connections*, so a long-lived tunnel only appears once it closes.
    #[arg(long)]
    stream: bool,

    /// Log file to read from
    #[arg(default_value = "-")]
    log: String,

    #[arg(short = 'h', long = "help", action = clap::ArgAction::Help, help = "Print help")]
    help: Option<bool>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let is_stdin = args.log == "-";

    if !args.stream && !is_stdin {
        let path = Path::new(&args.log);
        if !path.exists() || path.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            println!("\n=== Network Summary ===");
            println!("(no connections recorded)");
            return Ok(());
        }
    }

    let reader: Box<dyn BufRead> = if is_stdin {
        Box::new(BufReader::new(io::stdin()))
    } else {
        let file = File::open(&args.log).with_context(|| format!("Failed to open {}", args.log))?;
        Box::new(BufReader::new(file))
    };

    if args.stream {
        process_stream(reader)?;
    } else {
        process_summary(read_records(reader));
    }

    Ok(())
}
