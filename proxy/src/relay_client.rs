use std::env;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::exit;
use std::thread;

use crate::relay_protocol::{read_frame, write_frame, CommandType, Frame, RelayHeader};

pub fn run_client(cmd_type: CommandType) {
    let relay_addr = env::var("AGENT_SANDBOX_RELAY_ADDRESS")
        .expect("AGENT_SANDBOX_RELAY_ADDRESS environment variable must be set");

    let args: Vec<String> = env::args().skip(1).collect();

    // Collect envs (for SSH we'll forward GIT_* and SSH_*, maybe all for simplicity? Let's just forward GIT_ and SSH_)
    let mut envs = Vec::new();
    for (k, v) in env::vars() {
        if k.starts_with("GIT_") || k.starts_with("SSH_") {
            envs.push((k, v));
        }
    }

    let req = RelayHeader {
        cmd: cmd_type,
        args,
        envs,
    };

    let mut stream = TcpStream::connect(&relay_addr).unwrap_or_else(|e| {
        eprintln!("relay-client: failed to connect to {}: {}", relay_addr, e);
        exit(1);
    });

    req.write_to(&mut stream).unwrap_or_else(|e| {
        eprintln!("relay-client: failed to send request header: {}", e);
        exit(1);
    });

    let mut stream_read = stream.try_clone().expect("Failed to clone TCP stream");
    let mut stream_write = stream;

    // Spawn a thread to read stdin and send it as Stdin frames
    thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    // EOF on stdin, send empty Stdin frame to signal EOF?
                    // Let's send an empty Stdin frame as EOF.
                    let _ = write_frame(&mut stream_write, &Frame::Stdin(vec![]));
                    break;
                }
                Ok(n) => {
                    if write_frame(&mut stream_write, &Frame::Stdin(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Main thread reads frames from the server
    loop {
        match read_frame(&mut stream_read) {
            Ok(Frame::Stdout(data)) => {
                let mut stdout = io::stdout();
                if stdout.write_all(&data).is_err() || stdout.flush().is_err() {
                    break;
                }
            }
            Ok(Frame::Stderr(data)) => {
                let mut stderr = io::stderr();
                if stderr.write_all(&data).is_err() || stderr.flush().is_err() {
                    break;
                }
            }
            Ok(Frame::Exit(code)) => {
                exit(code);
            }
            Ok(Frame::Stdin(_)) => {
                eprintln!("relay-client: received unexpected Stdin frame from server");
                exit(1);
            }
            Err(e) => {
                eprintln!("relay-client: failed to read frame: {}", e);
                exit(1);
            }
        }
    }
}
