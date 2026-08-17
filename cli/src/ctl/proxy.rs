use super::resolve::*;
use crate::agents::{format_policy_as_network_toml, is_ip_or_cidr, parse_host_port};
use agent_sandbox_proxy::policy::{parse_csv_ports, parse_policy, ProxyConfig};
use agent_sandbox_proxy::policy_io::{install_policy, load_policy_lines};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::fs;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-proxy",
    about = "Manage proxy rules for a running sandbox"
)]
pub struct ProxyArgs {
    #[command(subcommand)]
    pub command: ProxyCommand,
}

#[derive(Subcommand, Debug)]
pub enum ProxyCommand {
    #[command(about = "Print the running sandbox's current policy")]
    Show(TargetArgs),
    #[command(about = "Allow a domain, IP/CIDR, port, or (with --l7) an HTTP route")]
    Allow(AllowArgs),
    #[command(about = "Remove a previously added rule")]
    Rm(RmArgs),
    #[command(about = "Reset the policy back to how the sandbox was launched")]
    Reset(TargetArgs),
    #[command(about = "Print the current policy as an AGENTS.md [network] TOML block")]
    Export(ExportArgs),
    #[command(
        about = "Check whether a host (and optionally port) would be allowed under the current policy"
    )]
    Check(CheckArgs),
}

#[derive(Parser, Debug)]
pub struct TargetArgs {
    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
    #[arg(
        long,
        help = "Target a running 'agent-sandbox browser' instead of a sandbox"
    )]
    pub browser: bool,
}

#[derive(Parser, Debug)]
pub struct ExportArgs {
    /// A profile is a plain TOML file, so it wants the block without the
    /// Markdown fence `AGENTS.md` needs.
    #[arg(
        long,
        help = "Print bare TOML, without the ```toml agent-sandbox fence (for a --proxy-profile file)"
    )]
    pub plain: bool,
    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
    #[arg(
        long,
        help = "Target a running 'agent-sandbox browser' instead of a sandbox"
    )]
    pub browser: bool,
}

#[derive(Parser, Debug)]
pub struct AllowArgs {
    #[arg(help = "Domain name, IP/CIDR, or port/port-range to allow")]
    pub target: String,
    #[arg(
        long,
        value_name = "METHOD",
        help = "Allow an HTTP route on TARGET instead of the whole domain (combine with --path)"
    )]
    pub l7: Option<String>,
    #[arg(long, default_value = "/*", help = "Path pattern for --l7")]
    pub path: String,
    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
    #[arg(
        long,
        help = "Target a running 'agent-sandbox browser' instead of a sandbox"
    )]
    pub browser: bool,
}

#[derive(Parser, Debug)]
pub struct CheckArgs {
    #[arg(help = "Host or host:port to check, e.g. api.example.com or api.example.com:443")]
    pub target: String,
    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
    #[arg(
        long,
        help = "Target a running 'agent-sandbox browser' instead of a sandbox"
    )]
    pub browser: bool,
}

#[derive(Parser, Debug)]
pub struct RmArgs {
    #[command(subcommand)]
    pub kind: RmKind,
}

#[derive(Subcommand, Debug)]
pub enum RmKind {
    #[command(about = "Remove an allow_host/allow_ip/allow_port rule")]
    Allow(RmTargetArgs),
    #[command(about = "Remove an allow_route rule")]
    L7(RmL7Args),
}

#[derive(Parser, Debug)]
pub struct RmTargetArgs {
    #[arg(help = "Domain name, IP/CIDR, or port/port-range to remove")]
    pub target: String,
    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
    #[arg(
        long,
        help = "Target a running 'agent-sandbox browser' instead of a sandbox"
    )]
    pub browser: bool,
}

#[derive(Parser, Debug)]
pub struct RmL7Args {
    pub host: String,
    pub method: String,
    pub path: String,
    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,
    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
    #[arg(
        long,
        help = "Target a running 'agent-sandbox browser' instead of a sandbox"
    )]
    pub browser: bool,
}

fn sandbox_target(word: &Option<String>, sandbox: &Option<String>) -> Option<String> {
    sandbox.clone().or_else(|| word.clone())
}

/// Resolves `word`/`--sandbox` to the running sandbox's policy directory on
/// the host — the same directory `agent-sandbox ctl tui` writes to.
///
/// With `--browser` the target is an `agent-sandbox browser` instead. Its
/// policy directory is a plain runtime directory rather than a container mount,
/// but it holds the same `policy`/`policy.base`/`policy.baseline` trio, so
/// everything downstream — `install_policy`, the delta rendering, the export —
/// works on it unchanged.
fn policy_dir(
    word: &Option<String>,
    sandbox: &Option<String>,
    browser: bool,
) -> Result<(String, String)> {
    if browser {
        return browser_policy_dir(sandbox_target(word, sandbox).as_deref());
    }
    let explicit = sandbox_target(word, sandbox);
    let sandbox_name = resolve_sandbox(explicit.as_deref(), true)?;
    let sidecar = require_sidecar(&sandbox_name)?;
    let dir = sidecar_mount(&sidecar, "/sidecar_policy")?;
    if dir.is_empty() {
        eprintln!(
            "agent-sandbox ctl proxy: cannot find the policy mount for sandbox '{}'",
            sandbox_word(&sandbox_name)
        );
        std::process::exit(1);
    }
    // The session word, not the container name: the callers only print this,
    // and a browser's own name comes back from the branch above unchanged.
    Ok((sandbox_word(&sandbox_name), dir))
}

/// Find the one running browser's policy directory, or say which ones there
/// are.
///
/// Ambiguity is refused rather than guessed at, the same way `resolve_sandbox`
/// refuses an ambiguous sandbox name: widening the wrong browser's allow list
/// would be silent, and the operator would be left wondering why the denial
/// they were watching did not clear.
fn browser_policy_dir(explicit: Option<&str>) -> Result<(String, String)> {
    let mut found = crate::ctl::browser::running_instances();
    if let Some(want) = explicit {
        found.retain(|inst| inst.name == want || inst.cdp_port.to_string() == want);
    }
    match found.len() {
        0 => {
            eprintln!("agent-sandbox ctl proxy: no running 'agent-sandbox browser' found.");
            eprintln!("               Start one with: agent-sandbox browser");
            std::process::exit(1);
        }
        1 => Ok((found[0].name.clone(), found[0].dir.clone())),
        _ => {
            eprintln!("agent-sandbox ctl proxy: several browsers are running; name one:");
            for inst in &found {
                eprintln!("               {} (CDP {})", inst.name, inst.cdp_port);
            }
            std::process::exit(1);
        }
    }
}

fn parse_lines(lines: &[String]) -> Result<ProxyConfig> {
    let text = lines.join("\n") + "\n";
    match parse_policy(&text) {
        Ok(cfg) => Ok(cfg),
        Err(e) => {
            eprintln!("agent-sandbox ctl proxy: current policy is invalid: {}", e);
            std::process::exit(1);
        }
    }
}

fn apply(policy_dir: &str, lines: Vec<String>) -> Result<()> {
    if let Err(e) = install_policy(policy_dir, &lines) {
        eprintln!("agent-sandbox ctl proxy: {}", e);
        std::process::exit(1);
    }
    // A browser target has a second layer holding the same permission, and it
    // is stale the moment the policy changes.  Keyed off the file's existence
    // rather than a `--browser` branch: a sandbox has no such file, and neither
    // does a browser started with `--no-policy-overlay`.
    if let Err(e) = crate::ctl::browser::sync_managed_allowlist(policy_dir, &lines) {
        eprintln!(
            "agent-sandbox ctl proxy: the proxy has the new policy, but the browser's \
             managed allow list could not be updated ({}); the browser may still refuse it",
            e
        );
    }
    println!("  reloading   the proxy applies this within a second");
    Ok(())
}

/// What kind of `[network]` entry a bare target string looks like: an
/// IP/CIDR, a bare port list or range (`8443`, `8000-8100`, `80,443`), or —
/// the fallback — a domain name.
///
/// The port test has to accept the whole comma-separated syntax, not one
/// range: a `80,443` that falls through to "domains" installs `allow_host
/// 80,443`, which the proxy happily reads as a literal domain nothing will
/// ever match.
fn target_kind(target: &str) -> &'static str {
    let (host_part, _port_part) = parse_host_port(target);
    if is_ip_or_cidr(&host_part) {
        "ips"
    } else if parse_csv_ports(target).is_ok_and(|ports| !ports.is_empty()) {
        "ports"
    } else {
        "domains"
    }
}

#[cfg(test)]
mod tests {
    use super::{signing_host, target_kind};

    #[test]
    fn target_kind_infers_ip_port_or_domain() {
        assert_eq!(target_kind("10.0.0.0/8"), "ips");
        assert_eq!(target_kind("169.254.169.254"), "ips");
        assert_eq!(target_kind("10.0.0.0/8:8443"), "ips");
        assert_eq!(target_kind("169.254.169.254:80"), "ips");
        assert_eq!(target_kind("8443"), "ports");
        assert_eq!(target_kind("8000-8100"), "ports");
        assert_eq!(target_kind("api.openai.com"), "domains");
        assert_eq!(target_kind("github.com"), "domains");
        assert_eq!(target_kind("github.com:22"), "domains");
    }

    #[test]
    fn only_a_domain_covering_22_authorizes_the_relay() {
        assert_eq!(signing_host("github.com:22"), Some("github.com".into()));
        assert_eq!(signing_host("github.com:22,443"), Some("github.com".into()));
        assert_eq!(signing_host("github.com:20-30"), Some("github.com".into()));
        assert_eq!(signing_host("github.com:443"), None);
        // A portless entry gets the default ports at the proxy, but nothing
        // here says 22 -- and guessing would grant key use nobody asked for.
        assert_eq!(signing_host("github.com"), None);
        assert_eq!(signing_host("10.0.0.1:22"), None);
        assert_eq!(signing_host("*:22"), None);
    }

    #[test]
    fn a_bare_port_list_is_ports_not_a_domain() {
        // Read as a domain, `80,443` installs an allow_host line the proxy
        // accepts and nothing ever matches.
        assert_eq!(target_kind("80,443"), "ports");
        assert_eq!(target_kind("80,8000-8100"), "ports");
        assert_eq!(target_kind("github.com:22,443"), "domains");
        assert_eq!(target_kind("10.0.0.0/8:80,443"), "ips");
    }
}

pub fn run(args: ProxyArgs) -> Result<()> {
    match args.command {
        ProxyCommand::Show(a) => show(a),
        ProxyCommand::Allow(a) => allow(a),
        ProxyCommand::Rm(a) => rm(a),
        ProxyCommand::Reset(a) => reset(a),
        ProxyCommand::Export(a) => export(a),
        ProxyCommand::Check(a) => check(a),
    }
}

fn show(args: TargetArgs) -> Result<()> {
    let (sandbox_name, dir) = policy_dir(&args.word, &args.container, args.browser)?;
    let lines = load_policy_lines(&dir);
    let cfg = parse_lines(&lines)?;
    let base_lines: HashSet<String> = fs::read_to_string(format!("{}/policy.base", dir))
        .map(|s| s.lines().map(|l| l.to_string()).collect())
        .unwrap_or_default();

    println!("{}", sandbox_name);
    println!("  policy      {}/policy", dir);
    let default_desc = if cfg.default_allow {
        "allow (everything is reachable except the rules below)".to_string()
    } else {
        "deny  (only the rules below are reachable)".to_string()
    };
    println!("  default     {}", default_desc);

    for line in &lines {
        let Some((key, value)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if key == "default" {
            continue;
        }
        let value = value.trim();
        let display_value = if key == "allow_route" {
            value.replace('\t', " ")
        } else {
            value.to_string()
        };
        // A browser's launch rules come from --allow, --proxy-profile and the
        // sandbox's published ports, so naming AGENTS.md there would be wrong.
        let source = if !base_lines.contains(line) {
            ""
        } else if args.browser {
            "at start"
        } else {
            "AGENTS.md"
        };
        println!("  {:<13} {:<34} {}", key, display_value, source);
    }
    Ok(())
}

/// An L7 rule makes the proxy terminate TLS for that host, which only works if
/// the sandbox trusts the session CA -- and the CA is bound in at launch, only
/// when the launch policy already had an L7 rule.  Adding the first one to a
/// running sandbox therefore cannot work, so say it plainly instead of leaving
/// the operator with unexplained certificate errors.
pub(crate) fn warn_if_no_session_ca(policy_dir: &str, host: &str) {
    let launched_with_l7 = fs::read_to_string(format!("{}/policy.base", policy_dir))
        .map(|s| s.lines().any(|l| l.starts_with("allow_route\t")))
        .unwrap_or(true);
    if !launched_with_l7 {
        eprintln!(
            "  warning     this sandbox launched with no L7 rule, so it does not trust the\n\
             \x20             proxy's session CA; TLS to {} will fail certificate validation.\n\
             \x20             Declare the rule in AGENTS.md and relaunch to make it effective.",
            host
        );
    }
}

/// Whether `known_hosts` in the policy dir carries a key for `host`.
///
/// Shared with the TUI's equivalent check via the same file, which is the only
/// thing either of them can see: the authorized set is fixed at launch from
/// trusted.toml, and a live rule cannot add to it.
pub(crate) fn trusts_host_key(policy_dir: &str, host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    fs::read_to_string(format!("{}/known_hosts", policy_dir))
        .map(|text| {
            text.lines()
                .filter_map(|line| line.split_whitespace().next())
                .any(|pattern| pattern.to_ascii_lowercase() == host)
        })
        .unwrap_or(false)
}

/// A live `:22` rule authorizes the relay to *reach* a host, but the host keys
/// are bound in at launch from trusted.toml and a running sandbox cannot be
/// given more.  So the grant works and the connection then fails verification
/// -- fail-safe, but baffling unless said out loud.
pub(crate) fn warn_if_no_trusted_host_key(policy_dir: &str, host: &str) {
    if trusts_host_key(policy_dir, host) {
        return;
    }
    eprintln!(
        "  warning     no host key for {} is trusted in this sandbox, so SSH to it will\n\
         \x20             fail host-key verification. Add a [[network.known_hosts]] entry to\n\
         \x20             ~/.config/agent-sandbox/trusted.toml and relaunch.",
        host
    );
}

fn allow(args: AllowArgs) -> Result<()> {
    let (_, dir) = policy_dir(&args.word, &args.container, args.browser)?;
    let mut lines = load_policy_lines(&dir);
    if let Some(method) = args.l7 {
        if is_ip_or_cidr(&args.target) {
            eprintln!(
                "agent-sandbox ctl proxy: --l7 needs a domain, not an IP/CIDR ('{}')",
                args.target
            );
            std::process::exit(1);
        }
        warn_if_no_session_ca(&dir, &args.target);
        lines.push(format!(
            "allow_route\t{}\t{}\t{}",
            args.target, method, args.path
        ));
        println!(
            "  allowed     {:<34} {}",
            format!("{} {} {}", args.target, method, args.path),
            "http route"
        );
    } else {
        let kind = target_kind(&args.target);
        let key = match kind {
            "ips" => "allow_ip",
            "ports" => "allow_port",
            _ => "allow_host",
        };
        lines.push(format!("{} {}", key, args.target));
        println!("  allowed     {:<34} {}", args.target, kind);

        // The same double duty an AGENTS.md entry does: a host allowed on the
        // SSH port is also what authorizes the relay to reach it. Without this
        // the live rule opens the port and `git push` is still refused, which
        // reads as the rule not having taken effect.
        if let Some(host) = signing_host(&args.target) {
            let line = format!("allow_signing {}", host);
            if !lines.contains(&line) {
                lines.push(line);
                println!("  allowed     {:<34} {}", host, "ssh (push/pull)");
            }
            warn_if_no_trusted_host_key(&dir, &host);
        }
    }
    apply(&dir, lines)
}

/// The host an allow target authorizes the SSH relay for, if any: a domain
/// whose port spec covers 22.
///
/// Not IPs — `allow_signing` is matched against the destination as written on
/// the ssh command line, which is a name.
fn signing_host(target: &str) -> Option<String> {
    let (host, ports) = parse_host_port(target);
    if host == "*" || is_ip_or_cidr(&host) {
        return None;
    }
    let ports = ports?;
    parse_csv_ports(&ports)
        .ok()?
        .iter()
        .any(|r| r.contains(22))
        .then_some(host)
}

/// Drops the first line matching `predicate`; reports whether anything was
/// removed so callers can tell the user when there was nothing to do.
fn remove_matching(lines: &mut Vec<String>, predicate: impl Fn(&str) -> bool) -> bool {
    if let Some(idx) = lines.iter().position(|l| predicate(l)) {
        lines.remove(idx);
        true
    } else {
        false
    }
}

fn rm(args: RmArgs) -> Result<()> {
    let (dir, lines, removed, summary) = match args.kind {
        RmKind::Allow(a) => {
            let (_, dir) = policy_dir(&a.word, &a.container, a.browser)?;
            let mut lines = load_policy_lines(&dir);
            let key = match target_kind(&a.target) {
                "ips" => "allow_ip",
                "ports" => "allow_port",
                _ => "allow_host",
            };
            let removed = remove_matching(&mut lines, |l| l == format!("{} {}", key, a.target));
            // Whatever `allow` added, `rm allow` takes back -- but only when
            // no other rule still covers 22 for that host, or removing one of
            // two entries would silently revoke the relay.
            if let Some(host) = signing_host(&a.target) {
                let still_allowed = lines.iter().any(|l| {
                    l.strip_prefix("allow_host ")
                        .and_then(signing_host)
                        .is_some_and(|h| h == host)
                });
                if !still_allowed {
                    remove_matching(&mut lines, |l| l == format!("allow_signing {}", host));
                }
            }
            (dir, lines, removed, format!("{} {}", key, a.target))
        }
        RmKind::L7(a) => {
            let (_, dir) = policy_dir(&a.word, &a.container, a.browser)?;
            let mut lines = load_policy_lines(&dir);
            let needle = format!("allow_route\t{}\t{}\t{}", a.host, a.method, a.path);
            let removed = remove_matching(&mut lines, |l| l == needle);
            (
                dir,
                lines,
                removed,
                format!("allow_route {} {} {}", a.host, a.method, a.path),
            )
        }
    };
    if !removed {
        eprintln!(
            "agent-sandbox ctl proxy: no matching rule found for '{}'",
            summary
        );
        std::process::exit(1);
    }
    println!("  removed     {}", summary);
    apply(&dir, lines)
}

fn reset(args: TargetArgs) -> Result<()> {
    let (_, dir) = policy_dir(&args.word, &args.container, args.browser)?;
    let base_path = format!("{}/policy.base", dir);
    let base = match fs::read_to_string(&base_path) {
        Ok(text) => text,
        Err(_) => {
            eprintln!(
                "agent-sandbox ctl proxy: no policy.base found for this sandbox (it may not have been launched with --proxy)"
            );
            std::process::exit(1);
        }
    };
    let lines: Vec<String> = base.lines().map(|s| s.to_string()).collect();
    println!("  reset       to the policy this sandbox was launched with");
    apply(&dir, lines)
}

fn export(args: ExportArgs) -> Result<()> {
    let (_, dir) = policy_dir(&args.word, &args.container, args.browser)?;
    // The baseline private/loopback deny_ip ranges are enforced
    // unconditionally regardless of AGENTS.md (see `policy.baseline`,
    // written once at launch with exactly that set), so round-tripping them
    // into an exported config would just be noise.
    let baseline: HashSet<String> = fs::read_to_string(format!("{}/policy.baseline", dir))
        .map(|s| s.lines().map(|l| l.to_string()).collect())
        .unwrap_or_default();
    let lines: Vec<String> = load_policy_lines(&dir)
        .into_iter()
        .filter(|l| !baseline.contains(l))
        .collect();
    let cfg = parse_lines(&lines)?;
    let toml = format_policy_as_network_toml(&cfg);
    if args.plain {
        print!("{}", toml);
    } else {
        // Fenced by default, like `ctl mounts export`: the launcher only reads
        // configuration inside a ```toml agent-sandbox block, so bare TOML
        // appended to AGENTS.md would be silently ignored.
        print!("```toml agent-sandbox\n{}```\n", toml);
    }
    Ok(())
}

fn check(args: CheckArgs) -> Result<()> {
    let (sandbox_name, dir) = policy_dir(&args.word, &args.container, args.browser)?;
    let lines = load_policy_lines(&dir);
    let cfg = parse_lines(&lines)?;
    let (host, port_str) = parse_host_port(&args.target);

    println!("{}", sandbox_name);
    match port_str {
        Some(p) => {
            let Ok(port) = p.parse::<u16>() else {
                eprintln!(
                    "agent-sandbox ctl proxy: '{}' names a set of ports, not one target — check a single HOST:PORT at a time",
                    p
                );
                std::process::exit(1);
            };
            if cfg.is_allowed(&host, port) {
                println!("  allowed     {}:{}", host, port);
            } else {
                println!("  denied      {}:{}", host, port);
                println!("              {}", cfg.why_denied(&host, port));
            }
        }
        None => {
            if cfg.is_allowed_target(&host) {
                println!(
                    "  allowed     {}  (port not checked — pass HOST:PORT for a complete answer)",
                    host
                );
            } else {
                println!(
                    "  denied      {}  (port not checked — pass HOST:PORT for a complete answer)",
                    host
                );
                println!("              {}", cfg.why_target_denied(&host));
            }
        }
    }
    Ok(())
}
