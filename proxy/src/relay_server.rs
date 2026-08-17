#[path = "relay_protocol.rs"]
mod relay_protocol;

use relay_protocol::{read_frame, write_frame, CommandType, Frame, RelayHeader};
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

/// The authorized host keys, written by the launcher beside the policy.
///
/// Read rather than written here, and read from the ro-mounted policy
/// directory rather than assembled in the sidecar, because the set is an
/// operator decision: it is exactly what `trusted.toml` authorized.  Nothing
/// in this process may add to it.
///
/// It has to be an explicit `-o` rather than a file in `$HOME`.  The sidecar
/// runs as uid 0 against a passwd whose root entry is `/root`, and OpenSSH
/// expands `~` from `getpwuid`, not the environment -- so a file written to
/// the image's `HOME=/home/user` would never be read.
const DEFAULT_KNOWN_HOSTS: &str = "/sidecar_policy/known_hosts";

/// The options that point `ssh` at the authorized keys, ready to be
/// *prepended*: ssh takes the first value it sees for a keyword, and options
/// have to come before the destination.
///
/// Unconditional, because a caller who set either of these themselves is
/// refused outright before we get here.  There is no per-invocation opt-out:
/// which keys are trusted is settled in `trusted.toml`, on the host.
fn known_hosts_args(path: &str) -> Vec<String> {
    vec![
        "-o".to_string(),
        format!("UserKnownHostsFile={}", path),
        "-o".to_string(),
        "GlobalKnownHostsFile=/dev/null".to_string(),
    ]
}

/// Options whose next argument is a value rather than the host.  Complete list
/// from ssh(1), shared by everything here that has to walk argv the way ssh
/// does -- a table that disagrees with itself between two walkers is a way for
/// an option to be scanned by one and acted on by the other.
const TAKES_ARG: &[&str] = &[
    "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p",
    "-Q", "-R", "-S", "-W", "-w",
];

/// Would make ssh run a command of the caller's choosing: arbitrary execution
/// in the sidecar, next to the forwarded agent socket.
const EXEC_OPTIONS: &[&str] = &[
    "proxycommand",
    "proxyusefdpass",
    "localcommand",
    "permitlocalcommand",
];

/// Would change *who ssh actually connects to*, which is the one thing
/// `allow_signing` exists to decide.  `ssh -J evil.example git@github.com`
/// passes the destination check -- the destination really is github.com --
/// and then opens a connection to evil.example and authenticates to it with
/// the forwarded agent on the way.
const JUMP_OPTIONS: &[&str] = &["proxyjump"];

/// Would move host-key verification off the keys the operator authorized:
/// another file, or no checking at all, or keys fetched from DNS.
const HOST_KEY_OPTIONS: &[&str] = &[
    "userknownhostsfile",
    "globalknownhostsfile",
    "stricthostkeychecking",
    "verifyhostkeydns",
];

/// The argv entries ssh would read as options, and the destination if one
/// could be identified.
///
/// One walk, so the arguments that get scanned for dangerous options and the
/// argument that gets checked against the policy can never be a different set.
/// On an argument neither of us understands it stops and reports no
/// destination, which the caller turns into a refusal -- everything collected
/// up to that point is still returned, so the scan sees it too.
fn split_ssh_args(args: &[String]) -> (Vec<&str>, Option<String>) {
    let mut options = Vec::new();
    let mut skip_next = false;
    let mut saw_separator = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            options.push(arg.as_str());
            continue;
        }
        if saw_separator || !arg.starts_with('-') {
            // First non-option after the flags is the destination; whatever
            // follows is the remote command, which is not ours to police.
            let dest = match arg.split_once('@') {
                Some((_, host)) => host,
                None => arg.as_str(),
            };
            return (options, Some(dest.to_string()));
        }
        options.push(arg.as_str());
        if arg == "--" {
            saw_separator = true;
            continue;
        }
        // Pure flag with no argument (e.g. -4, -6, -v, -N).
        if arg.len() == 2 && !TAKES_ARG.contains(&arg.as_str()) {
            continue;
        }
        if TAKES_ARG.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        // Combined form: -p2222 -- the value is inline, so nothing to skip.
        if TAKES_ARG.contains(&&arg[..2]) {
            continue;
        }
        // Bundled single-char flags without arguments: -vvv, -46.
        let no_arg_chars = "1246AaCfGgKkMNnqsTtVvXxYy";
        if arg[1..].chars().all(|c| no_arg_chars.contains(c)) {
            continue;
        }
        // Unrecognized: fail closed rather than guess what ssh will make of it.
        return (options, None);
    }
    (options, None)
}

fn extract_ssh_destination(args: &[String]) -> Option<String> {
    split_ssh_args(args).1
}

/// Why this ssh invocation is refused, if it is.
///
/// Scans only what ssh would read as options, so a repository path or remote
/// command containing one of these words -- `git-upload-pack
/// /srv/userknownhostsfile.git` is a legitimate request -- is not a spurious
/// denial.  *Within* an option the match is a plain substring, deliberately:
/// over-refusing a spelling nobody anticipated (`-4oUserKnownHostsFile=x`) is
/// the safe direction for a gate, and the cost is refusing an option that
/// merely mentions one of these words in a value, which nothing legitimate
/// does.
///
/// `-F` is refused as a category: an alternate config file can set any of the
/// above out of sight, so allowing it would mean the list below bounds
/// nothing.
fn refused_ssh_option(args: &[String]) -> Option<&'static str> {
    let (options, _) = split_ssh_args(args);
    for opt in options {
        let lower = opt.to_ascii_lowercase();
        if EXEC_OPTIONS.iter().any(|name| lower.contains(name)) {
            return Some("dangerous options detected");
        }
        if JUMP_OPTIONS.iter().any(|name| lower.contains(name)) || opt == "-J" {
            return Some(
                "a jump host would move the connection off the host the policy authorized",
            );
        }
        if HOST_KEY_OPTIONS.iter().any(|name| lower.contains(name)) {
            return Some(
                "host keys are authorized on the host, in trusted.toml, and cannot be \
                 overridden per invocation -- add a [[network.known_hosts]] entry instead",
            );
        }
        if opt == "-F" || (opt.starts_with("-F") && opt.len() > 2) {
            return Some("an alternate ssh config could set any of the options above out of sight");
        }
    }
    None
}

fn domain_match(domain: &str, pattern: &str) -> bool {
    let domain = domain.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix('*') {
        if suffix.starts_with('.') {
            domain == &pattern[2..] || domain.ends_with(suffix)
        } else {
            domain.ends_with(suffix)
        }
    } else {
        domain == pattern
    }
}

const RELAY_LOG: &str = "/sidecar_shared/relay.jsonl";
/// Smaller than the proxy's own logs: one line per relay call, and a
/// commit-signing loop can make a lot of them.  Bounded at all because the TUI
/// rescans the file from the top when it starts.
const RELAY_LOG_MAX_BYTES: u64 = 1024 * 1024;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn log_relay(cmd: &str, dest: Option<&str>, allowed: bool, reason: &str) {
    // `ts` is what lets a reader age a record -- the TUI shows relay denials
    // beside the proxy's, and "17s ago" needs a clock.  Note there is no port
    // here on purpose: the relay authorizes by host, and its ssh egress never
    // goes through the proxy, so any port in this record would be a guess.
    let mut record = serde_json::json!({
        "cmd": cmd,
        "allowed": allowed,
        "reason": reason,
        "ts": now_secs(),
    });
    if let Some(d) = dest {
        record["dest"] = serde_json::Value::String(d.to_string());
    }
    let line = format!("{}\n", record);

    // read as well as append: rotation seeks and truncates.
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(RELAY_LOG)
    {
        let _ = agent_sandbox_proxy::logfile::rotate_if_needed(
            &mut file,
            line.len() as u64,
            RELAY_LOG_MAX_BYTES,
        );
        let _ = file.write_all(line.as_bytes());
    }
}

fn validate_gpg_args(args: &[String]) -> bool {
    let mut has_signing_intent = false;
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        if lower.starts_with("--homedir")
            || lower.contains("export")
            || lower.contains("decrypt")
            || lower == "-d"
        {
            return false;
        }

        if lower == "--sign"
            || lower == "--detach-sign"
            || lower == "--clearsign"
            || lower == "--verify"
            || lower == "--clear-sign"
        {
            has_signing_intent = true;
        } else if lower.starts_with('-') && !lower.starts_with("--") {
            if lower.contains('s') || lower.contains('b') || lower.contains('v') {
                has_signing_intent = true;
            }
        }
    }
    has_signing_intent
}

/// The two authorization axes the relay enforces, read from the same policy
/// file: `ssh_hosts` gates which destinations `git push`/`pull` may reach,
/// while `gpg_enabled` gates GPG signing on its own -- host-agnostic, since
/// gpg has no destination of its own.
struct SigningPolicy {
    ssh_hosts: Vec<String>,
    gpg_enabled: bool,
}

fn load_signing_policy(policy_path: &str) -> SigningPolicy {
    let mut ssh_hosts = Vec::new();
    let mut gpg_enabled = false;
    if let Ok(file) = File::open(policy_path) {
        for line in BufReader::new(file).lines().flatten() {
            let mut parts = line.split_whitespace();
            if let Some(key) = parts.next() {
                match key {
                    "allow_signing" => {
                        if let Some(val) = parts.next() {
                            ssh_hosts.push(val.to_string());
                        }
                    }
                    "signing_enabled" => {
                        gpg_enabled = parts.next() == Some("true");
                    }
                    _ => {}
                }
            }
        }
    }
    SigningPolicy {
        ssh_hosts,
        gpg_enabled,
    }
}

fn handle_client(mut stream: TcpStream, policy_path: &str, known_hosts: Option<&str>) {
    let req = match RelayHeader::read_from(&mut stream) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("relay-server: failed to read request header: {}", e);
            return;
        }
    };

    let signing_policy = load_signing_policy(policy_path);

    let (bin, is_ssh) = match req.cmd {
        CommandType::Gpg => {
            let allowed = signing_policy.gpg_enabled;
            let safe_args = validate_gpg_args(&req.args);

            log_relay(
                "gpg",
                None,
                allowed && safe_args,
                if !allowed {
                    "gpg signing not enabled"
                } else if !safe_args {
                    "disallowed gpg arguments"
                } else {
                    ""
                },
            );
            if !allowed || !safe_args {
                let msg = if !allowed {
                    b"agent-sandbox: gpg denied: signing not enabled -- relaunch with --gpg\n".as_slice()
                } else {
                    b"agent-sandbox: gpg denied: disallowed or dangerous arguments detected\n"
                        .as_slice()
                };
                let _ = write_frame(&mut stream, &Frame::Stderr(msg.to_vec()));
                let _ = write_frame(&mut stream, &Frame::Exit(255));
                return;
            }
            // Resolved through PATH: the image is a Nix closure, where the
            // only thing under /usr/bin is `env`.
            ("gpg", false)
        }
        CommandType::Ssh => {
            let host = extract_ssh_destination(&req.args);

            // Refused argv is refused whatever the destination: an option that
            // moves the connection or the trust anchor is not something the
            // policy check downstream can compensate for.
            if let Some(reason) = refused_ssh_option(&req.args) {
                eprintln!("relay-server: ssh denied: {}", reason);
                log_relay("ssh", host.as_deref(), false, reason);
                let _ = write_frame(
                    &mut stream,
                    &Frame::Stderr(format!("agent-sandbox: ssh denied: {}\n", reason).into_bytes()),
                );
                let _ = write_frame(&mut stream, &Frame::Exit(255));
                return;
            }

            // The keys are the operator's, so an ssh the relay cannot point at
            // them is an ssh it should not run.  Unreachable in a healthy
            // session -- a policy authorizing SSH to a host with no key for it
            // never got past the launcher -- so say that rather than letting
            // ssh produce its own opaque failure.
            if known_hosts.is_none() {
                let reason = "no authorized host keys in this sandbox -- add a \
                              [[network.known_hosts]] entry to trusted.toml and relaunch";
                eprintln!("relay-server: ssh denied: {}", reason);
                log_relay("ssh", host.as_deref(), false, reason);
                let _ = write_frame(
                    &mut stream,
                    &Frame::Stderr(format!("agent-sandbox: ssh denied: {}\n", reason).into_bytes()),
                );
                let _ = write_frame(&mut stream, &Frame::Exit(255));
                return;
            }
            match host {
                Some(dest) => {
                    let mut allowed = false;
                    for rule in &signing_policy.ssh_hosts {
                        if domain_match(&dest, rule) {
                            allowed = true;
                            break;
                        }
                    }

                    log_relay(
                        "ssh",
                        Some(&dest),
                        allowed,
                        if allowed {
                            ""
                        } else {
                            "denied by allow_signing policy"
                        },
                    );

                    if !allowed {
                        eprintln!(
                            "relay-server: ssh to {} denied by allow_signing policy",
                            dest
                        );
                        let _ = write_frame(
                            &mut stream,
                            &Frame::Stderr(
                                format!(
                                    "agent-sandbox: ssh to {} denied by allow_signing policy\n",
                                    dest
                                )
                                .into_bytes(),
                            ),
                        );
                        let _ = write_frame(&mut stream, &Frame::Exit(255));
                        return;
                    }
                }
                None => {
                    log_relay("ssh", None, false, "could not determine destination");
                    let _ = write_frame(
                        &mut stream,
                        &Frame::Stderr(
                            b"agent-sandbox: ssh denied: could not determine destination host\n"
                                .to_vec(),
                        ),
                    );
                    let _ = write_frame(&mut stream, &Frame::Exit(255));
                    return;
                }
            }
            ("ssh", true)
        }
    };

    let mut cmd = Command::new(bin);
    // Prepended, never appended: ssh keeps the first value it sees for a
    // keyword and stops reading options at the destination.  Both the
    // destination extraction and the dangerous-option scan above ran over
    // `req.args` alone, so neither sees these.
    if is_ssh {
        if let Some(path) = known_hosts {
            cmd.args(known_hosts_args(path));
        }
    }
    cmd.args(&req.args);

    // Only pass through a strict whitelist of safe environment variables from the sandbox
    for (k, v) in req.envs {
        let k_str = k.as_str();
        if k_str == "LANG" || k_str.starts_with("LC_") || k_str == "TZ" || k_str == "TERM" {
            cmd.env(k, v);
        }
    }

    if is_ssh {
        cmd.env("SSH_AUTH_SOCK", "/run/host-ssh-agent");
    } else {
        // gpg uses the host agent mounted at /run/host-gpg-agent by the sidecar
    }

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = write_frame(
                &mut stream,
                &Frame::Stderr(
                    format!("relay-server: failed to spawn {}: {}\n", bin, e).into_bytes(),
                ),
            );
            let _ = write_frame(&mut stream, &Frame::Exit(255));
            return;
        }
    };

    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    let mut stream_read = stream.try_clone().unwrap();
    let mut stream_write_stdout = stream.try_clone().unwrap();
    let mut stream_write_stderr = stream.try_clone().unwrap();
    let mut stream_write_exit = stream;

    // Thread to read client frames (Stdin) and write to child stdin
    let t_stdin = thread::spawn(move || {
        loop {
            match read_frame(&mut stream_read) {
                Ok(Frame::Stdin(data)) => {
                    if data.is_empty() {
                        // EOF
                        break;
                    }
                    if child_stdin.write_all(&data).is_err() || child_stdin.flush().is_err() {
                        break;
                    }
                }
                Ok(_) => {
                    // Ignore other frames from client
                }
                Err(_) => {
                    break;
                }
            }
        }
        // child_stdin is dropped here, closing it
    });

    let t_stdout = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match child_stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if write_frame(&mut stream_write_stdout, &Frame::Stdout(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let t_stderr = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match child_stderr.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if write_frame(&mut stream_write_stderr, &Frame::Stderr(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let status = child.wait().unwrap();
    let _ = t_stdin.join();
    let _ = t_stdout.join();
    let _ = t_stderr.join();

    let code = status.code().unwrap_or(255);
    let _ = write_frame(&mut stream_write_exit, &Frame::Exit(code));
}

fn main() {
    let mut args = env::args().skip(1);
    let mut listen_addr = "0.0.0.0:8889".to_string();
    let mut policy_path = "/sidecar_policy/policy".to_string();
    let mut known_hosts_path = DEFAULT_KNOWN_HOSTS.to_string();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                if let Some(val) = args.next() {
                    listen_addr = val;
                }
            }
            "--policy" => {
                if let Some(val) = args.next() {
                    policy_path = val;
                }
            }
            "--known-hosts" => {
                if let Some(val) = args.next() {
                    known_hosts_path = val;
                }
            }
            _ => {}
        }
    }

    // Absent when trusted.toml authorized no keys.  Nothing is injected then,
    // and ssh fails closed on its own -- which is right, because a policy that
    // authorized an SSH host without a key for it would have been refused
    // before this sidecar was started.
    let known_hosts = Path::new(&known_hosts_path)
        .exists()
        .then_some(known_hosts_path);

    let listener = TcpListener::bind(&listen_addr).unwrap_or_else(|e| {
        eprintln!("relay-server: failed to bind {}: {}", listen_addr, e);
        std::process::exit(1);
    });

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let pp = policy_path.clone();
                let kh = known_hosts.clone();
                thread::spawn(move || {
                    handle_client(s, &pp, kh.as_deref());
                });
            }
            Err(e) => {
                eprintln!("relay-server: accept failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_host() {
        let args = vec!["github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn user_at_host() {
        let args = vec!["git@github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn option_with_separate_value() {
        let args = vec!["-p".into(), "2222".into(), "github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn combined_option_value() {
        let args = vec!["-p2222".into(), "github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn combined_option_o() {
        let args = vec!["-oStrictHostKeyChecking=no".into(), "github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn double_dash_separator() {
        let args = vec!["--".into(), "github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn bundled_flags() {
        let args = vec!["-vvv".into(), "github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn no_args_returns_none() {
        let args: Vec<String> = vec![];
        assert_eq!(extract_ssh_destination(&args), None);
    }

    #[test]
    fn only_flags_returns_none() {
        let args = vec!["-v".into(), "-N".into()];
        assert_eq!(extract_ssh_destination(&args), None);
    }

    #[test]
    fn real_git_ssh_invocation() {
        // git push typically does: ssh [-p port] [user@]host git-upload-pack 'repo'
        let args = vec![
            "-o".into(),
            "SendEnv=GIT_PROTOCOL".into(),
            "git@github.com".into(),
            "git-upload-pack".into(),
            "user/repo.git".into(),
        ];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    // ── host-key authorization ──────────────────────────────────────────────

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_keys_are_pinned_unconditionally() {
        // No skip branch any more: a caller who names their own file is
        // refused, so there is nothing left to defer to.
        assert_eq!(
            known_hosts_args("/run/kh"),
            args(&[
                "-o",
                "UserKnownHostsFile=/run/kh",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
            ])
        );
    }

    #[test]
    fn an_ordinary_git_invocation_is_not_refused() {
        assert!(refused_ssh_option(&args(&[
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "git@github.com",
            "git-upload-pack",
            "user/repo.git",
        ]))
        .is_none());
        assert!(refused_ssh_option(&args(&["-p", "2222", "-4", "git@github.com"])).is_none());
        assert!(refused_ssh_option(&args(&["-T", "git@github.com"])).is_none());
    }

    #[test]
    fn overriding_the_host_keys_is_refused_in_every_spelling() {
        for spelling in [
            vec!["-o", "UserKnownHostsFile=/dev/null"],
            vec!["-oUserKnownHostsFile=/dev/null"],
            vec!["-o", "UserKnownHostsFile /dev/null"],
            vec!["-o", "userknownhostsfile=/dev/null"],
            vec!["-o", "GlobalKnownHostsFile=/dev/null"],
            vec!["-o", "StrictHostKeyChecking=no"],
            vec!["-oStrictHostKeyChecking=accept-new"],
            vec!["-o", "VerifyHostKeyDNS=yes"],
        ] {
            let mut argv = spelling.clone();
            argv.push("git@github.com");
            let reason = refused_ssh_option(&args(&argv))
                .unwrap_or_else(|| panic!("not refused: {:?}", spelling));
            assert!(reason.contains("trusted.toml"), "{reason}");
        }
    }

    /// `-4oUserKnownHostsFile=x` bundles a no-arg flag with `-o`. Nobody writes
    /// that on purpose, which is exactly why the scan matches on a substring
    /// rather than parsing: over-refusing an unanticipated spelling is the safe
    /// direction.
    #[test]
    fn a_bundled_spelling_is_refused_too() {
        assert!(refused_ssh_option(&args(&["-4oUserKnownHostsFile=/dev/null"])).is_some());
    }

    /// An alternate config could set any of them out of sight, which would
    /// make the list bound nothing.
    #[test]
    fn an_alternate_ssh_config_is_refused() {
        for argv in [
            vec!["-F", "/tmp/ssh_config", "git@github.com"],
            vec!["-F/tmp/ssh_config", "git@github.com"],
        ] {
            let reason = refused_ssh_option(&args(&argv))
                .unwrap_or_else(|| panic!("not refused: {:?}", argv));
            assert!(reason.contains("config"), "{reason}");
        }
    }

    /// A jump host passes the destination check and then connects somewhere
    /// else entirely, with the forwarded agent along for the ride -- so the
    /// destination gate has to refuse it rather than measure it.
    #[test]
    fn a_jump_host_is_refused_even_with_an_allowed_destination() {
        for argv in [
            vec!["-J", "evil.example", "git@github.com"],
            vec!["-o", "ProxyJump=evil.example", "git@github.com"],
        ] {
            assert_eq!(
                extract_ssh_destination(&args(&argv)),
                Some("github.com".into()),
                "the destination check alone would pass this: {:?}",
                argv
            );
            let reason = refused_ssh_option(&args(&argv))
                .unwrap_or_else(|| panic!("not refused: {:?}", argv));
            assert!(reason.contains("jump host"), "{reason}");
        }
    }

    #[test]
    fn the_exec_options_are_still_refused() {
        for opt in [
            "ProxyCommand=nc evil 22",
            "LocalCommand=id",
            "PermitLocalCommand=yes",
            "ProxyUseFdpass=yes",
        ] {
            assert!(
                refused_ssh_option(&args(&["-o", opt, "git@github.com"])).is_some(),
                "{opt}"
            );
        }
    }

    /// The scan reads what ssh reads as options and stops at the destination,
    /// so a repository path is never mistaken for one.
    #[test]
    fn a_remote_command_is_not_scanned() {
        assert!(refused_ssh_option(&args(&[
            "git@github.com",
            "git-upload-pack",
            "/srv/userknownhostsfile.git",
        ]))
        .is_none());
        assert!(refused_ssh_option(&args(&[
            "git@github.com",
            "git-upload-pack",
            "/srv/proxycommand.git",
        ]))
        .is_none());
    }

    #[test]
    fn the_injected_options_do_not_move_the_destination() {
        // They are prepended to argv, but every check the relay makes runs over
        // the caller's args alone -- so the destination the policy was checked
        // against is the destination ssh will use.
        let caller = args(&[
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "git@github.com",
            "git-upload-pack",
            "user/repo.git",
        ]);
        let mut full = known_hosts_args("/run/kh");
        full.extend(caller.iter().cloned());
        assert_eq!(
            extract_ssh_destination(&caller),
            extract_ssh_destination(&full)
        );
        assert_eq!(extract_ssh_destination(&full), Some("github.com".into()));
    }

    /// The two walks have to agree: an option the scan never sees is an option
    /// the policy check cannot compensate for.
    #[test]
    fn everything_before_the_destination_is_scanned() {
        let argv = args(&[
            "-4",
            "-p",
            "2222",
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "git@github.com",
            "git-upload-pack",
        ]);
        let (options, dest) = split_ssh_args(&argv);
        assert_eq!(dest, Some("github.com".into()));
        assert_eq!(
            options,
            vec!["-4", "-p", "2222", "-o", "SendEnv=GIT_PROTOCOL"]
        );
    }

    #[test]
    fn an_argument_neither_of_us_understands_fails_closed() {
        let argv = args(&["--frobnicate", "git@github.com"]);
        let (options, dest) = split_ssh_args(&argv);
        assert_eq!(dest, None, "an unparseable argv has no trusted destination");
        assert_eq!(options, vec!["--frobnicate"], "and is still scanned");
    }

    #[test]
    fn domain_match_exact() {
        assert!(domain_match("github.com", "github.com"));
        assert!(!domain_match("github.com", "gitlab.com"));
    }

    #[test]
    fn domain_match_wildcard() {
        assert!(domain_match("api.github.com", "*.github.com"));
        assert!(domain_match("github.com", "*.github.com"));
        assert!(!domain_match("github.org", "*.github.com"));
    }

    #[test]
    fn signing_policy_decouples_gpg_from_ssh_hosts() {
        // --gpg alone must enable gpg with no ssh destination named at all --
        // that is the whole point of the split.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy");
        std::fs::write(&path, "signing_enabled true\n").unwrap();

        let policy = load_signing_policy(path.to_str().unwrap());
        assert!(policy.gpg_enabled);
        assert!(policy.ssh_hosts.is_empty());
    }

    #[test]
    fn signing_policy_reads_ssh_hosts_independently_of_gpg() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy");
        std::fs::write(&path, "allow_signing github.com\n").unwrap();

        let policy = load_signing_policy(path.to_str().unwrap());
        assert!(!policy.gpg_enabled);
        assert_eq!(policy.ssh_hosts, vec!["github.com".to_string()]);
    }
}
