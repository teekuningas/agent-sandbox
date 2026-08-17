#![forbid(unsafe_code)]

use agent_sandbox_cli::agents::{self, format_proxy_policy, parse_proxy, parse_proxy_profile};
use agent_sandbox_cli::ctl;
use agent_sandbox_cli::gpg::{scan_gnupg_home, GpgScanStatus};
use agent_sandbox_cli::launch;
use agent_sandbox_cli::net_summary;
use agent_sandbox_cli::secrets::resolve_secrets_logic_with_profiles;
use agent_sandbox_cli::trusted;
use anyhow::Result;
use clap::{Parser, Subcommand};
use rand::Rng;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::thread;
use tempfile::Builder;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox",
    about = "Agent sandbox control CLI",
    version = "0.1.0"
)]
struct CtlCli {
    #[command(subcommand)]
    command: CtlCommands,
}

#[derive(Subcommand, Debug)]
enum CtlCommands {
    #[command(about = "Load the agent-sandbox image")]
    Load(ctl::load::LoadArgs),
    #[command(about = "List sandboxes and their proxy mode")]
    List(ctl::list::ListArgs),
    #[command(about = "Summarise one running sandbox")]
    Status(ctl::status::StatusArgs),
    #[command(about = "Manage proxy rules")]
    Proxy(ctl::proxy::ProxyArgs),
    #[command(about = "Start a throwaway host browser behind a deny-by-default allow list")]
    Browser(ctl::browser::BrowserArgs),
    #[command(about = "Show network metering for a running sandbox")]
    Net(ctl::net::NetArgs),
    #[command(about = "Show the proxy log for a running sandbox", alias = "log")]
    Logs(ctl::logs::LogsArgs),
    #[command(about = "Attach to a running sandbox and exec a command")]
    Attach(ctl::attach::AttachArgs),
    #[command(about = "Manage bind mounts into a running sandbox", alias = "mounts")]
    Mount(ctl::mount::MountArgs),
    #[command(about = "Show SSH/GPG relay policy and logs")]
    Relay(ctl::relay::RelayArgs),
    #[command(about = "Interactive dashboard: watch denied requests live and add rules for them")]
    Tui(ctl::tui::TuiArgs),
    #[command(about = "Reclaim leftover containers, networks and directories")]
    Purge(ctl::purge::PurgeArgs),
}

#[derive(Debug, Clone, PartialEq)]
enum AgentMountsMode {
    Auto,
    All,
    None,
    List(Vec<String>),
}

/// Expand a `src[:dest[:opts]]` spec declared in `AGENTS.md` against the
/// workspace: a relative source is relative to the host CWD, a relative
/// destination lands under `/workspace`.
fn expand_v(spec: &str, current_dir: &Path, home_dir: &str) -> String {
    let parts: Vec<&str> = spec.split(':').collect();
    let mut src = parts[0].replace('~', home_dir);
    if src == "." {
        src = current_dir.to_string_lossy().into_owned();
    }
    if !src.starts_with('/') {
        src = format!("{}/{}", current_dir.to_string_lossy(), src);
    }

    let dest = if parts.len() > 1 && !parts[1].is_empty() {
        let mut d = parts[1].to_string();
        if !d.starts_with('/') {
            if d == "." {
                d = "/workspace".to_string();
            } else {
                d = format!("/workspace/{}", d);
            }
        }
        d
    } else {
        src.clone()
    };

    if parts.len() > 2 {
        format!("{}:{}:{}", src, dest, parts[2..].join(":"))
    } else {
        format!("{}:{}", src, dest)
    }
}

/// Where the sandbox finds the sockets backing `--host-loopback-port`.  A
/// directory rather than one socket per mount, so the count of mapped ports is
/// not baked into the podman command line.
const HOST_PORT_DIR: &str = "/run/agent-sandbox-host";

/// One `--host-loopback-port HOST[:SANDBOX]` mapping.  Both sides are kept
/// because they differ whenever the sandbox already has something on the host's
/// port number -- the one case the pasta mapping this replaced got for free, its
/// address being distinct from the sandbox's own loopback.
#[derive(Debug, Clone, PartialEq)]
struct HostPort {
    host: u16,
    sandbox: u16,
}

/// An operator-supplied `--host-loopback-port` value, or a refusal.  Validated
/// here rather than at connect time because the alternative is an agent inside
/// meeting a refused connection with no way to tell a typo from a service that
/// is merely down.
fn parse_host_loopback_ports(spec: &str) -> Result<Vec<HostPort>, String> {
    let mut out = Vec::new();
    for entry in spec.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(format!(
                "agent-sandbox: --host-loopback-port: {:?} has an empty entry.",
                spec
            ));
        }
        let (host_str, sandbox_str) = match entry.split_once(':') {
            Some((h, s)) => (h, s),
            None => (entry, entry),
        };
        let port = |s: &str| -> Result<u16, String> {
            s.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| {
                format!(
                    "agent-sandbox: --host-loopback-port: {:?} is not a port in 1-65535.",
                    s
                )
            })
        };
        out.push(HostPort {
            host: port(host_str)?,
            sandbox: port(sandbox_str)?,
        });
    }
    Ok(out)
}

/// Maps every browser `--browser` selected into the sandbox, and reports the
/// port each one answers on *inside* -- which is what the agent dials, and so
/// what `AGENT_SANDBOX_BROWSER_CDP_PORT` has to carry.
///
/// Usually that is the browser's own CDP port, mapped straight through.  An
/// explicit `--host-loopback-port 9222:19222` wins over adding a second
/// mapping: the operator moved the inside number because something in the
/// sandbox already holds 9222, and advertising the outside one would point the
/// agent at a port nothing is listening on.
fn attach_browsers(
    selected: &[ctl::browser::Instance],
    host_ports: &mut Vec<HostPort>,
) -> Vec<(String, u16)> {
    selected
        .iter()
        .map(|inst| {
            let inside = match host_ports.iter().find(|hp| hp.host == inst.cdp_port) {
                Some(hp) => hp.sandbox,
                None => {
                    host_ports.push(HostPort {
                        host: inst.cdp_port,
                        sandbox: inst.cdp_port,
                    });
                    inst.cdp_port
                }
            };
            (inst.name.clone(), inside)
        })
        .collect()
}

/// Serve one `--host-loopback-port` mapping for the life of the session: every
/// connection arriving on the unix socket the sandbox has mounted is spliced to
/// the host's loopback.  A socket rather than a route because a route would have
/// to be a network mode and the sandbox's is already spoken for -- pasta by
/// default, the proxy's `--internal` network under `--proxy`, a bridge under
/// `--shared-network`.  A mount is orthogonal to all three, which is the whole
/// reason this composes where the pasta mapping it replaced could not.
fn serve_host_port(socket: &Path, host_port: u16) -> std::io::Result<()> {
    let listener = UnixListener::bind(socket)?;
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let upstream = match TcpStream::connect(("127.0.0.1", host_port)) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!(
                            "agent-sandbox: host port {} is not answering: {}",
                            host_port, e
                        );
                        return;
                    }
                };
                let (Ok(mut from_sandbox), Ok(mut to_host)) =
                    (stream.try_clone(), upstream.try_clone())
                else {
                    return;
                };
                // Two halves, two threads: CDP is long-lived and full duplex, so
                // neither direction may wait on the other.  Each shuts the far
                // side's write half when its own end closes, or the peer sits on
                // a socket that will never carry anything again.
                let outbound = thread::spawn(move || {
                    let _ = std::io::copy(&mut from_sandbox, &mut to_host);
                    let _ = to_host.shutdown(Shutdown::Write);
                });
                let (mut from_host, mut to_sandbox) = (upstream, stream);
                let _ = std::io::copy(&mut from_host, &mut to_sandbox);
                let _ = to_sandbox.shutdown(Shutdown::Write);
                let _ = outbound.join();
            });
        }
    });
    Ok(())
}

/// Whether a `[ports]` bind address is loopback, which is what decides if a
/// published port is compatible with `--proxy`.  `parse_ports` has already
/// reduced the field to an IP literal (`"localhost"` included), so anything
/// that fails to parse here is not a bind this launcher wrote -- treated as
/// non-loopback, because the refusal is the safe answer.
fn is_loopback_bind(bind: &str) -> bool {
    bind.parse::<IpAddr>().map(|a| a.is_loopback()).unwrap_or(false)
}

fn enforce_selinux_mount_flags(mount_opt: &str, want_selinux: bool) -> String {
    let parts: Vec<&str> = mount_opt.split(':').collect();
    if parts.len() < 2 {
        return mount_opt.to_string();
    }

    let mut new_parts = parts.clone();

    if parts.len() == 2 {
        if want_selinux {
            new_parts.push("Z");
        }
    } else {
        let opts = parts[2..].join(":");
        let mut opt_list: Vec<&str> = opts.split(',').collect();

        if want_selinux {
            if !opt_list.contains(&"z") && !opt_list.contains(&"Z") {
                opt_list.push("Z");
            }
        } else {
            opt_list.retain(|&x| x != "z" && x != "Z");
        }

        if opt_list.is_empty() {
            new_parts.truncate(2);
        } else {
            let joined_opts = opt_list.join(",");
            return format!("{}:{}:{}", parts[0], parts[1], joined_opts);
        }
    }

    new_parts.join(":")
}

/// Nameservers for the sidecar, read from the host.  With DNS disabled on both
/// of its networks these land in the container's `/etc/resolv.conf` verbatim
/// and are queried directly, rather than becoming an upstream for an aardvark
/// that would refuse to use it.
///
/// Only bare IP literals survive the filter.  A scoped address --
/// `fe80::1%eth0`, which RA-configured hosts do write -- is rejected by podman,
/// and a rejected `--dns` takes the whole sidecar down.  Loopback and
/// link-local entries are dropped for a different reason: they name a resolver
/// on the *host's* stack, which is not reachable from the container's netns.
fn usable_nameservers(file: &Path) -> Result<Vec<String>> {
    let mut ns = Vec::new();
    if !file.exists() {
        return Ok(ns);
    }
    let f = File::open(file)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.starts_with("nameserver") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let candidate = parts[1];
        let lower = candidate.to_lowercase();
        if lower.starts_with("127.")
            || lower.starts_with("169.254.")
            || lower == "::1"
            || lower.starts_with("fe80:")
            || lower.contains('%')
        {
            continue;
        }
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            ns.push(candidate.to_string());
        }
    }
    Ok(ns)
}

/// `search` (and its legacy `domain` spelling) from the same file, so an
/// unqualified name that resolves on the host resolves in the sidecar too.
/// Carrying the nameservers without them leaves a split-horizon setup half
/// configured.
fn usable_search(file: &Path) -> Result<Vec<String>> {
    let mut search = Vec::new();
    if !file.exists() {
        return Ok(search);
    }
    let f = File::open(file)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.starts_with("search") && !line.starts_with("domain") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        for word in parts.into_iter().skip(1) {
            let is_valid = !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            if is_valid {
                search.push(word.to_string());
            }
        }
    }
    Ok(search)
}

fn usable_dns_options(file: &Path) -> Result<Vec<String>> {
    let mut opts = Vec::new();
    if !file.exists() {
        return Ok(opts);
    }
    let f = File::open(file)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.starts_with("options") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        for word in parts.into_iter().skip(1) {
            let is_valid = !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == ':');
            if is_valid {
                opts.push(word.to_string());
            }
        }
    }
    Ok(opts)
}

/// The `--dns*` flags the sidecar is started with.  When nothing on the host is
/// usable the search list is dropped along with it: a public resolver cannot
/// answer for an internal zone, so carrying the suffixes would only add failed
/// lookups to every name.
fn sidecar_dns_args() -> Vec<String> {
    let mut source = PathBuf::from("/etc/resolv.conf");
    let mut nameservers = usable_nameservers(&source).unwrap_or_default();
    if nameservers.is_empty() {
        // systemd-resolved publishes 127.0.0.53 as the only nameserver, which
        // the filter above correctly discards.  Its own file carries the real
        // upstreams; using them keeps split-horizon and corporate names
        // resolving instead of quietly defecting to a public resolver.
        source = PathBuf::from("/run/systemd/resolve/resolv.conf");
        nameservers = usable_nameservers(&source).unwrap_or_default();
    }
    if nameservers.is_empty() {
        return vec![
            "--dns".to_string(),
            "8.8.8.8".to_string(),
            "--dns".to_string(),
            "1.1.1.1".to_string(),
        ];
    }

    let mut args = Vec::new();
    for ns in nameservers {
        args.push("--dns".to_string());
        args.push(ns);
    }
    for search in usable_search(&source).unwrap_or_default() {
        args.push("--dns-search".to_string());
        args.push(search);
    }
    for opt in usable_dns_options(&source).unwrap_or_default() {
        args.push("--dns-option".to_string());
        args.push(opt);
    }
    args
}

#[allow(clippy::too_many_arguments)]
fn print_usage(
    agent_list: &str,
    want_workspace: bool,
    want_ssh: bool,
    want_git: bool,
    want_gpg: bool,
    want_gpg_private: bool,
    want_devenv: bool,
    want_nix: bool,
    want_podman: bool,
    want_selinux: bool,
    want_proxy: bool,
    want_proxy_log: Option<ProxyLogLevel>,
    want_secrets: bool,
    want_krun: bool,
    want_ports: bool,
    want_shared_network: bool,
    want_host_ports: bool,
    want_browser: bool,
    want_mounts: bool,
    want_agent_mounts_mode: &AgentMountsMode,
) {
    let fmt = |b: bool| if b { "[on ]" } else { "[off]" };
    let agent_mounts_all = matches!(want_agent_mounts_mode, AgentMountsMode::All);
    // Same width as fmt's markers so the column does not jog.
    let proxy_log_state = match want_proxy_log {
        None => "[ask]",
        Some(ProxyLogLevel::Off) => "[off]",
        Some(ProxyLogLevel::Denied) => "[den]",
        Some(ProxyLogLevel::All) => "[all]",
    };

    // A raw string, not `\n\` continuations: a backslash-newline in a Rust
    // string literal swallows the *following* line's leading whitespace, which
    // is what flattened every indented line of this text after the rewrite.
    println!(
        r#"agent-sandbox [FLAGS] [AGENT] [-- COMMAND...]

Runs an AI coding agent inside a rootless podman container.
Use flags to opt-in to integrations like mounting the current directory,
forwarding SSH, or exposing Git identity.

  agent-sandbox                      launch interactive bash (no agent state mounted)
  agent-sandbox opencode             launch opencode with its own state mounted
  agent-sandbox --agent-mounts       launch interactive bash with every agent's state mounted
  agent-sandbox --podman opencode    launch opencode with podman enabled
  agent-sandbox opencode -- bash     launch bash with opencode's state mounted
  agent-sandbox --privileged opencode
                                     pass --privileged to podman run
  agent-sandbox ctl --help           manage sandboxes that are already running
  agent-sandbox browser              start a throwaway host browser behind a deny-by-default
                                     allow list, for cooperative testing over CDP

Agents:
  {agent_list}

Integrations (use --X to enable, --no-X to disable):
  --workspace       {workspace} Mounts the host's current working directory into /workspace/<dirname>.
  --ssh             {ssh} Forwards the host's SSH_AUTH_SOCK to the container.
  --git             {git} Passes the host's Git configuration (with a blocklist) and identity env vars.
  --gpg             {gpg} Enables host GnuPG agent forwarding and git commit signing behavior.
  --gpg-private     {gpg_private} Exposes ~/.gnupg even if it holds on-disk secret keys.
  --devenv          {devenv} Persists ~/.local/share/devenv across sessions.
  --nix             {nix} Mounts the host /nix/store for native Nix execution.
  --podman          {podman} Forwards the host rootless Podman socket (sibling containers).
  --selinux         {selinux} Applies SELinux shared relabeling (:z) to writable binds.
  --proxy           {proxy} Deny-by-default network firewall enforcing AGENTS.md's [network] policy.
  --proxy-profile NAME     Use a host-owned reusable network profile instead of AGENTS.md.
  --proxy-log LEVEL {proxy_log} What to do with the connection log at exit (off/denied/all); implies --proxy.
  --secrets         {secrets} Injects secretspec-resolved credentials into proxied requests. Requires --proxy.
  --krun            {krun} Runs the sandbox as a KVM microVM with its own kernel (needs /dev/kvm).

Ports:
  --ports / --no-ports               {ports} Honors [ports] declarations from AGENTS.md.
  --ports-any-interface                    Permits port binds outside of loopback interfaces.
  --shared-network                   {shared_network} Joins the shared bridge network so sibling
                                           containers can reach this one by name.
  --browser                          {browser} Attaches every running 'agent-sandbox browser'
                                           session, mapping its CDP port in automatically.
  --host-loopback-port PORT          {host_ports} Makes a host 127.0.0.1:PORT reachable at the
                                           sandbox's own 127.0.0.1:PORT (e.g. a browser's CDP
                                           port). Repeatable; takes HOST:SANDBOX to remap.

Mounts:
  --mounts / --no-mounts             {mounts} Honors [mounts] declarations from AGENTS.md.

Agent state:
  --agent-mounts                     {agent_mounts} Mount every agent's state, not just the one launched.
  --agent-mounts=AGENT[,AGENT...]    Mount only these agents' state (plus any launched agent).
                                     Only the "=" form takes a list.
  --no-agent-mounts                  Mount no agent state, even for the launched agent.

Podman / Environment:
  --privileged              pass --privileged to podman run (for nested podman)
  --krun-memory MiB         guest RAM under --krun (default 4096, must exceed 128)
  --krun-cpus N             guest vCPUs under --krun (1-16, default: host affinity)
  -e, --env NAME=VAL        pass environment variable to podman
  --podman-args             treat all following args (until --) as podman args

--podman, --ssh, --gpg and --krun each interact with the sandbox boundary
differently -- --podman in particular is a full sandbox escape; prefer
--privileged for nested containers. See the trust model:
https://datakurre.github.io/agent-sandbox/trust-model/
Full flag reference and examples: https://datakurre.github.io/agent-sandbox/usage/"#,
        agent_list = agent_list,
        workspace = fmt(want_workspace),
        ssh = fmt(want_ssh),
        git = fmt(want_git),
        gpg = fmt(want_gpg),
        gpg_private = fmt(want_gpg_private),
        devenv = fmt(want_devenv),
        nix = fmt(want_nix),
        podman = fmt(want_podman),
        selinux = fmt(want_selinux),
        proxy = fmt(want_proxy),
        proxy_log = proxy_log_state,
        secrets = fmt(want_secrets),
        krun = fmt(want_krun),
        ports = fmt(want_ports),
        shared_network = fmt(want_shared_network),
        host_ports = fmt(want_host_ports),
        browser = fmt(want_browser),
        mounts = fmt(want_mounts),
        agent_mounts = fmt(agent_mounts_all)
    );
}

/// What to do with the proxy's connection log when the session ends.  The
/// summary is printed either way; this only decides whether the raw record
/// survives the teardown that removes the sidecar's shared directory.
#[derive(Clone, Copy, PartialEq, Debug)]
enum ProxyLogLevel {
    /// Never keep it.
    Off,
    /// Keep it only if something was denied or failed.
    Denied,
    /// Keep every session's log.
    All,
}

/// `None` -- the default -- means "ask": a session that had denials offers to
/// save the log rather than deciding for the operator.
fn parse_proxy_log_level(s: &str) -> Option<ProxyLogLevel> {
    match s {
        "off" => Some(ProxyLogLevel::Off),
        "denied" => Some(ProxyLogLevel::Denied),
        "all" => Some(ProxyLogLevel::All),
        _ => None,
    }
}

fn proxy_profile_path(home: &str, name: &str) -> Result<PathBuf> {
    launch::proxy_profile_path(home, name).map_err(|e| anyhow::anyhow!(e))
}

struct CleanupGuard {
    sidecar_id: String,
    sidecar_shared: String,
    sidecar_policy: String,
    sidecar_secrets: String,
    host_port_dir: String,
    log_level: Option<ProxyLogLevel>,
    session_word: String,
    use_agents_network: bool,
    proxy_profiles: Vec<String>,
}

impl CleanupGuard {
    fn new() -> Self {
        CleanupGuard {
            sidecar_id: String::new(),
            sidecar_shared: String::new(),
            sidecar_policy: String::new(),
            sidecar_secrets: String::new(),
            host_port_dir: String::new(),
            log_level: None,
            session_word: String::new(),
            use_agents_network: false,
            proxy_profiles: Vec::new(),
        }
    }

    /// Where the connection log lands, if anywhere.  Everything here runs from
    /// `Drop`, so nothing may panic or exit: the network reclaim and the
    /// directory removal still have to happen.
    fn print_live_rules(&self) {
        if self.sidecar_policy.is_empty() {
            return;
        }

        let read_lines = |name: &str| -> Vec<String> {
            fs::read_to_string(format!("{}/{}", self.sidecar_policy, name))
                .map(|text| text.lines().map(str::to_string).collect())
                .unwrap_or_default()
        };
        let active = read_lines("policy");
        let base: HashSet<String> = read_lines("policy.base").into_iter().collect();
        let baseline: HashSet<String> = read_lines("policy.baseline").into_iter().collect();
        let delta = agents::policy_delta_lines(&active, &base, &baseline);
        if delta.is_empty() {
            return;
        }
        let Some(toml) = agents::format_policy_lines_as_network_toml(&delta) else {
            return;
        };

        println!("\n  live network rules added during this session:");
        if self.use_agents_network && !self.proxy_profiles.is_empty() {
            println!("  Add this TOML to AGENTS.md for this project, or merge it into a reusable profile:\n");
        } else if self.use_agents_network {
            println!(
                "  Add this TOML to AGENTS.md if these rules should persist for this project:\n"
            );
        } else if let Some(profile) = self.proxy_profiles.first() {
            println!(
                "  Merge this TOML into ~/.config/agent-sandbox/profiles/{}.toml to reuse it:\n",
                profile
            );
        } else {
            println!(
                "  Save this TOML as ~/.config/agent-sandbox/profiles/<name>.toml to reuse it:\n"
            );
        }
        print!("{}", toml);
        println!();
    }

    fn save_log(&self, log: &str, had_failures: bool) {
        let contents = match fs::read_to_string(log) {
            Ok(c) if !c.trim().is_empty() => c,
            _ => return,
        };
        let style = net_summary::Style::detect();

        let name = self.log_file_name();
        let save = match self.log_level {
            Some(ProxyLogLevel::Off) => return,
            Some(ProxyLogLevel::All) => true,
            Some(ProxyLogLevel::Denied) => had_failures,
            None => {
                if !had_failures {
                    return;
                }
                // Nothing to ask on a non-interactive run, and the evidence is
                // about to be deleted -- fall back to the temp copy.
                if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
                    let fallback = format!(
                        "{}/agent-sandbox-connections-{}.jsonl",
                        env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string()),
                        std::process::id()
                    );
                    if fs::write(&fallback, &contents).is_ok() {
                        Self::announce(Path::new(&fallback), style);
                    }
                    return;
                }
                Self::prompt(&name)
            }
        };
        if !save {
            return;
        }

        let target = env::current_dir()
            .map(|d| d.join(&name))
            .unwrap_or_else(|_| PathBuf::from(&name));
        if fs::write(&target, &contents).is_ok() {
            Self::announce(&target, style);
            return;
        }

        let fallback = PathBuf::from(format!(
            "{}/{}",
            env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string()),
            name
        ));
        if fs::write(&fallback, &contents).is_ok() {
            println!("  (could not write to the current directory)");
            Self::announce(&fallback, style);
        } else {
            eprintln!("  could not save the connection log");
        }
    }

    /// Named after the session, so logs from several sandboxes kept in one
    /// working directory stay distinguishable.
    fn log_file_name(&self) -> String {
        let word = if self.session_word.is_empty() {
            "session"
        } else {
            &self.session_word
        };
        format!(
            "agent-sandbox-connections-{}-{}.jsonl",
            word,
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        )
    }

    fn prompt(name: &str) -> bool {
        print!("  Save the connection log to ./{}? [y/N] ", name);
        if std::io::stdout().flush().is_err() {
            return false;
        }
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err() {
            return false;
        }
        matches!(answer.trim(), "y" | "Y" | "yes" | "Yes")
    }

    fn announce(path: &Path, style: net_summary::Style) {
        let display = path.display().to_string();
        let absolute = fs::canonicalize(path)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| display.clone());
        println!(
            "  connection log kept at {}",
            net_summary::hyperlink(&display, &absolute, style)
        );
        println!(
            "{}",
            style.dim(&format!(
                "  re-render it with:     agent-sandbox-network-summary {}",
                display
            ))
        );
        println!("");
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        // Before the sidecar's early return: a session can have host-port
        // sockets without ever having had a proxy, and leaving them behind
        // would leave a live-looking path to the host's loopback in a runtime
        // directory that outlives the sandbox.
        if !self.host_port_dir.is_empty() {
            let _ = fs::remove_dir_all(&self.host_port_dir);
        }

        if self.sidecar_id.is_empty() {
            return;
        }

        let _ = ProcessCommand::new("podman")
            .args(["stop", "-t", "1", &self.sidecar_id])
            .output();
        // Not --rm: a sidecar that exits before signalling readiness has to
        // stay around long enough for `podman logs` to say why.
        let _ = ProcessCommand::new("podman")
            .args(["rm", "-f", &self.sidecar_id])
            .output();

        if !self.sidecar_shared.is_empty() {
            let log = format!("{}/connections.jsonl", self.sidecar_shared);
            let records = match File::open(&log) {
                Ok(file) => net_summary::read_records(BufReader::new(file)),
                Err(_) => Vec::new(),
            };

            // The aggregate report, not the per-record feed: a busy session has
            // hundreds of connections and what the operator wants at exit is
            // where the traffic went.
            let had_failures = records
                .iter()
                .any(|r| matches!(r.verdict.as_deref(), Some("deny") | Some("error")));
            net_summary::process_summary(records);
            self.print_live_rules();

            // The removal below would take the per-connection timings with it,
            // and those are what distinguish "failed instantly" from "burned
            // the whole retry window".
            self.save_log(&log, had_failures);
        }

        // podman tears a --rm container down asynchronously after `stop`
        // returns, so a single attempt here loses the race often enough to
        // leak one --internal network per session -- and each of those holds a
        // subnet from the rootless pool until `agent-sandbox ctl purge`
        // reclaims it.
        for _ in 0..20 {
            if ProcessCommand::new("podman")
                .args(["network", "rm", &self.sidecar_id])
                .output()
                .is_ok()
            {
                if ProcessCommand::new("podman")
                    .args(["network", "exists", &self.sidecar_id])
                    .status()
                    .map(|s| !s.success())
                    .unwrap_or(true)
                {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }

        for dir in [
            &self.sidecar_shared,
            &self.sidecar_policy,
            &self.sidecar_secrets,
        ] {
            if !dir.is_empty() {
                let _ = fs::remove_dir_all(dir);
            }
        }
    }
}

/// For failures *before* the proxy sidecar exists.  Once it does, the launcher
/// has to unwind through a `return` instead: `process::exit` skips every
/// destructor, and the sidecar's is what stops the container and reclaims its
/// network -- a leaked one holds a subnet from the rootless pool until
/// `agent-sandbox ctl purge` takes it back.
fn fail(message: &str) -> ! {
    eprintln!("{}", message);
    std::process::exit(1);
}

/// Same, for after: prints and hands back the exit code, so the caller's
/// `return` runs the cleanup on its way out.
fn refuse(message: &str) -> Result<i32> {
    eprintln!("{}", message);
    Ok(1)
}

fn main() -> Result<()> {
    // `run` owns the cleanup guard; exiting here is safe because it has
    // already been dropped.
    std::process::exit(run()?)
}

fn run() -> Result<i32> {
    let mut want_ssh = false;
    let mut want_git = false;
    let mut want_gpg = false;
    let mut want_gpg_private = false;
    let mut want_devenv = false;
    let mut want_nix = false;
    let mut want_podman = false;
    let mut want_workspace = false;
    let mut want_selinux = false;
    let mut want_ports = false;
    let mut want_ports_any_interface = false;
    let mut want_shared_network = false;
    let mut want_host_ports: Vec<HostPort> = Vec::new();
    // `--browser`, and the session names it was narrowed to (empty = all).
    let mut want_browser = false;
    let mut want_browser_names: Vec<String> = Vec::new();
    let mut want_mounts = false;
    let mut want_agent_mounts_mode = AgentMountsMode::Auto;
    let mut want_proxy = false;
    let mut use_agents_network = false;
    let mut proxy_profiles: Vec<String> = Vec::new();
    let mut want_proxy_log: Option<ProxyLogLevel> = None;
    let mut want_secrets = false;
    let mut want_krun = false;
    let mut want_privileged = false;
    let mut want_help = false;
    let mut krun_ram_mib = String::new();
    let mut krun_cpus = String::new();
    let mut agent = String::new();
    let mut cmd_args: Vec<String> = Vec::new();
    let mut podman_args: Vec<String> = Vec::new();
    let mut env_args: Vec<String> = Vec::new();
    let mut mounts: Vec<String> = Vec::new();
    let mut declared_mounts: Vec<String> = Vec::new();
    let mut sidecar_extra_mounts: Vec<String> = Vec::new();
    let mut sidecar_extra_env: Vec<String> = Vec::new();
    let mut publish_args: Vec<String> = Vec::new();
    let mut published: Vec<String> = Vec::new();

    let krun_runtime =
        env::var("AGENT_SANDBOX_KRUN_RUNTIME").unwrap_or_else(|_| "krun".to_string());
    let default_agent_specs = "opencode\t[\"opencode\",\".\"]\t[\".local/share/opencode\",\".config/opencode\",\".cache/opencode\"]\t[]\nclaude\t[\"claude\"]\t[\".claude\"]\t[\".claude.json\"]\ncopilot\t[\"copilot\"]\t[\".copilot\"]\t[]\nantigravity\t[\"agy\",\".\"]\t[\".local/share/opencode\",\".local/share/antigravity-cli\",\".config/antigravity-cli\",\".cache/antigravity-cli\",\".gemini\"]\t[]\ncodex\t[\"codex\",\".\"]\t[\".codex\"]\t[]".to_string();
    let agent_specs_str = env::var("AGENT_SANDBOX_AGENT_SPECS").unwrap_or(default_agent_specs);

    let mut agent_names = Vec::new();
    let mut agent_cmd_json = HashMap::new();
    let mut agent_state_json = HashMap::new();
    let mut agent_state_files_json = HashMap::new();

    for line in agent_specs_str.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 4 {
            let name = parts[0].to_string();
            if name.is_empty() {
                continue;
            }
            agent_names.push(name.clone());
            agent_cmd_json.insert(name.clone(), parts[1].to_string());
            agent_state_json.insert(name.clone(), parts[2].to_string());
            agent_state_files_json.insert(name.clone(), parts[3].to_string());
        }
    }
    let agent_list = agent_names.join(" ");

    let args: Vec<String> = env::args().skip(1).collect();

    // Subcommand routing for ctl
    let argv0 = env::args().next().unwrap_or_default();
    let is_ctl_bin = argv0.ends_with("agent-sandbox-ctl");

    if is_ctl_bin || !args.is_empty() {
        let ctl_subcommands = [
            "load", "list", "status", "proxy", "net", "logs", "log", "attach", "mount", "mounts",
            "relay", "tui", "purge", "browser",
        ];
        let mut run_ctl = false;
        let mut parse_args = vec!["agent-sandbox".to_string()];

        if is_ctl_bin {
            run_ctl = true;
            if args.is_empty() {
                parse_args.push("--help".to_string());
            } else {
                parse_args.extend(args.iter().cloned());
            }
        } else {
            for (idx, arg) in args.iter().enumerate() {
                if arg == "ctl" {
                    run_ctl = true;
                    if idx + 1 == args.len() {
                        parse_args.push("--help".to_string());
                    } else {
                        parse_args.extend(args.iter().skip(idx + 1).cloned());
                    }
                    break;
                } else if ctl_subcommands.contains(&arg.as_str())
                    && !agent_cmd_json.contains_key(arg)
                {
                    run_ctl = true;
                    parse_args.extend(args.iter().skip(idx).cloned());
                    break;
                }
            }
        }

        if run_ctl {
            let cli = match CtlCli::try_parse_from(parse_args) {
                Ok(c) => c,
                Err(e) => e.exit(),
            };

            match cli.command {
                CtlCommands::Load(a) => ctl::load::run(a)?,
                CtlCommands::List(a) => ctl::list::run(a)?,
                CtlCommands::Status(a) => ctl::status::run(a)?,
                CtlCommands::Proxy(a) => ctl::proxy::run(a)?,
                CtlCommands::Browser(a) => ctl::browser::run(a)?,
                CtlCommands::Net(a) => ctl::net::run(a)?,
                CtlCommands::Logs(a) => ctl::logs::run(a)?,
                CtlCommands::Attach(a) => ctl::attach::run(a)?,
                CtlCommands::Mount(a) => ctl::mount::run(a)?,
                CtlCommands::Relay(a) => ctl::relay::run(a)?,
                CtlCommands::Tui(a) => ctl::tui::run(a)?,
                CtlCommands::Purge(a) => ctl::purge::run(a)?,
            }
            return Ok(0);
        }
    }

    let mut i = 0;
    let mut parsing_podman = false;

    while i < args.len() {
        let arg = &args[i];
        if parsing_podman {
            if arg == "--" {
                i += 1;
                cmd_args.extend(args[i..].iter().cloned());
                break;
            } else {
                podman_args.push(arg.clone());
                i += 1;
                continue;
            }
        }

        if agent_cmd_json.contains_key(arg) {
            agent = arg.clone();
            i += 1;
            continue;
        }

        match arg.as_str() {
            "-h" | "--help" | "help" => want_help = true,
            "--ssh" => want_ssh = true,
            "--no-ssh" => want_ssh = false,
            "--git" => want_git = true,
            "--no-git" => want_git = false,
            "--gpg" => want_gpg = true,
            "--no-gpg" => want_gpg = false,
            "--gpg-private" => want_gpg_private = true,
            "--no-gpg-private" => want_gpg_private = false,
            "--devenv" => want_devenv = true,
            "--no-devenv" => want_devenv = false,
            "--nix" => want_nix = true,
            "--no-nix" => want_nix = false,
            "--podman" => want_podman = true,
            "--no-podman" => want_podman = false,
            "--workspace" => want_workspace = true,
            "--no-workspace" => want_workspace = false,
            "--selinux" => want_selinux = true,
            "--no-selinux" => want_selinux = false,
            "--ports" => want_ports = true,
            "--no-ports" => want_ports = false,
            "--ports-any-interface" => want_ports_any_interface = true,
            "--shared-network" => want_shared_network = true,
            "--no-shared-network" => want_shared_network = false,
            "--no-host-loopback-port" => want_host_ports.clear(),
            "--browser" => want_browser = true,
            "--no-browser" => {
                want_browser = false;
                want_browser_names.clear();
            }
            "--mounts" => want_mounts = true,
            "--no-mounts" => want_mounts = false,
            "--agent-mounts" => want_agent_mounts_mode = AgentMountsMode::All,
            "--no-agent-mounts" => want_agent_mounts_mode = AgentMountsMode::None,
            "--proxy" => {
                want_proxy = true;
                use_agents_network = true;
            }
            "--no-proxy" => {
                want_proxy = false;
                use_agents_network = false;
            }
            "--secrets" => want_secrets = true,
            "--no-secrets" => want_secrets = false,
            "--krun" => want_krun = true,
            "--no-krun" => want_krun = false,
            "--podman-args" => parsing_podman = true,
            "--privileged" => want_privileged = true,
            "--" => {
                i += 1;
                cmd_args.extend(args[i..].iter().cloned());
                break;
            }
            _ => {
                if let Some(list) = arg.strip_prefix("--agent-mounts=") {
                    let list_vec: Vec<String> = list.split(',').map(|s| s.to_string()).collect();
                    for a in &list_vec {
                        if !agent_cmd_json.contains_key(a) {
                            fail(&format!(
                                "agent-sandbox: --agent-mounts: unknown agent '{}' (valid: {})",
                                a, agent_list
                            ));
                        }
                    }
                    want_agent_mounts_mode = AgentMountsMode::List(list_vec);
                } else if arg == "--host-loopback-port" || arg.starts_with("--host-loopback-port=")
                {
                    let value = match arg.strip_prefix("--host-loopback-port=") {
                        Some(v) => v.to_string(),
                        None => {
                            i += 1;
                            if i >= args.len() {
                                fail("agent-sandbox: --host-loopback-port needs an argument (PORT, or HOST:SANDBOX)");
                            }
                            args[i].clone()
                        }
                    };
                    match parse_host_loopback_ports(&value) {
                        Ok(ports) => want_host_ports.extend(ports),
                        Err(e) => fail(&e),
                    }
                } else if let Some(v) = arg.strip_prefix("--browser=") {
                    want_browser = true;
                    want_browser_names
                        .extend(v.split(',').filter(|s| !s.is_empty()).map(str::to_string));
                } else if arg == "--proxy-log" || arg.starts_with("--proxy-log=") {
                    let value = match arg.strip_prefix("--proxy-log=") {
                        Some(v) => v.to_string(),
                        None => {
                            i += 1;
                            if i >= args.len() {
                                fail("agent-sandbox: --proxy-log needs an argument (off, denied, all)");
                            }
                            args[i].clone()
                        }
                    };
                    match parse_proxy_log_level(&value) {
                        Some(level) => want_proxy_log = Some(level),
                        None => fail(&format!(
                            "agent-sandbox: --proxy-log: unknown level '{}' (valid: off, denied, all)",
                            value
                        )),
                    }
                    // Asking what to do with the proxy's log is asking for the
                    // proxy; --no-proxy after this still wins, as with every
                    // other flag here.
                    want_proxy = true;
                    // A profile already selected is the requested policy
                    // source; otherwise --proxy-log has the same source as
                    // plain --proxy.
                    if proxy_profiles.is_empty() {
                        use_agents_network = true;
                    }
                } else if arg == "--proxy-profile" || arg.starts_with("--proxy-profile=") {
                    let value = match arg.strip_prefix("--proxy-profile=") {
                        Some(v) => v.to_string(),
                        None => {
                            i += 1;
                            if i >= args.len() || args[i].starts_with('-') {
                                fail("agent-sandbox: --proxy-profile needs a profile name");
                            }
                            args[i].clone()
                        }
                    };
                    proxy_profiles.push(value);
                    // Selecting a profile selects the proxy, while a later
                    // --no-proxy still wins like the other sequential flags.
                    want_proxy = true;
                } else if arg == "--krun-memory" {
                    i += 1;
                    if i >= args.len() {
                        fail("agent-sandbox: --krun-memory needs an argument");
                    }
                    krun_ram_mib = args[i].clone();
                } else if let Some(v) = arg.strip_prefix("--krun-memory=") {
                    krun_ram_mib = v.to_string();
                } else if arg == "--krun-cpus" {
                    i += 1;
                    if i >= args.len() {
                        fail("agent-sandbox: --krun-cpus needs an argument");
                    }
                    krun_cpus = args[i].clone();
                } else if let Some(v) = arg.strip_prefix("--krun-cpus=") {
                    krun_cpus = v.to_string();
                } else if arg == "-e" || arg == "--env" {
                    i += 1;
                    if i >= args.len() {
                        fail("agent-sandbox: -e/--env needs an argument");
                    }
                    env_args.push("-e".to_string());
                    env_args.push(args[i].clone());
                } else if let Some(v) = arg.strip_prefix("--env=") {
                    env_args.push("-e".to_string());
                    env_args.push(v.to_string());
                } else if arg == "--port" || arg.starts_with("--port=") {
                    fail("agent-sandbox: '--port' was removed. Declare a [ports] block in AGENTS.md and pass --ports,\n               or publish directly with: --podman-args -p HOST:CONTAINER --");
                } else if arg == "--proxy-train" || arg.starts_with("--proxy-train=") {
                    fail("agent-sandbox: '--proxy-train' was removed. Run with --proxy and watch denied\n               requests in 'agent-sandbox ctl tui'.");
                } else if let Some(v) = arg.strip_prefix("-e") {
                    env_args.push("-e".to_string());
                    env_args.push(v.to_string());
                } else if arg.starts_with("-v") {
                    fail(&format!(
                        "agent-sandbox: '{}' is not an agent-sandbox flag.",
                        arg
                    ));
                } else if arg.starts_with("--") {
                    fail(&format!(
                        "agent-sandbox: '{}' is not an agent-sandbox flag.",
                        arg
                    ));
                } else {
                    fail(&format!("agent-sandbox: unexpected argument '{}'.", arg));
                }
            }
        }
        i += 1;
    }

    if want_help {
        print_usage(
            &agent_list,
            want_workspace,
            want_ssh,
            want_git,
            want_gpg,
            want_gpg_private,
            want_devenv,
            want_nix,
            want_podman,
            want_selinux,
            want_proxy,
            want_proxy_log,
            want_secrets,
            want_krun,
            want_ports,
            want_shared_network,
            !want_host_ports.is_empty(),
            want_browser,
            want_mounts,
            &want_agent_mounts_mode,
        );
        std::process::exit(0);
    }

    if want_privileged {
        podman_args.push("--privileged".to_string());
    }

    // A published port is ingress and does not by itself defeat an egress
    // policy -- podman forwards into the proxy's --internal network without
    // giving the sandbox a route out of it.  What decides is the bind address:
    // loopback is this machine, anything wider is a channel the proxy never
    // sees.  A raw -p is refused under --proxy because this launcher never
    // parses it and so cannot tell the two apart; a declared [ports] entry is
    // checked on its bind once that block has been parsed.  Host networking is
    // refused outright -- it is not publishing, it is the host's whole stack.
    if want_proxy {
        let mut idx = 0;
        while idx < podman_args.len() {
            let arg = &podman_args[idx];
            if arg == "--network=host" || arg == "--net=host" {
                fail("agent-sandbox: hard failure: --proxy cannot be combined with host networking via podman-args");
            }
            if (arg == "--network" || arg == "--net")
                && idx + 1 < podman_args.len()
                && podman_args[idx + 1] == "host"
            {
                fail("agent-sandbox: hard failure: --proxy cannot be combined with host networking via podman-args");
            }
            if arg == "-p"
                || arg == "--publish"
                || arg.starts_with("-p=")
                || arg.starts_with("--publish=")
            {
                fail("agent-sandbox: --proxy cannot be combined with a raw -p.\n               The launcher does not parse it, so it cannot tell a loopback\n               bind from one the whole network can pull from, and only the\n               first is compatible with an egress policy.\n               Declare the port in AGENTS.md and pass --ports instead.");
            }
            idx += 1;
        }
    }

    // --shared-network chooses the network mode itself, and would reach podman
    // as a second --network beside the operator's.  Podman can only report that
    // contradiction in its own words, long after the launcher had a chance to
    // say which flag to drop.  Nothing else here does: --host-loopback-port is a
    // mounted socket, so it composes with any --network the operator writes.
    if want_shared_network {
        for arg in &podman_args {
            if arg == "--network"
                || arg == "--net"
                || arg.starts_with("--network=")
                || arg.starts_with("--net=")
            {
                fail(
                    "agent-sandbox: --shared-network cannot be combined with a --network of your\n               own.  It is a --network spec itself, and podman takes only one.\n               Drop --shared-network, or write the whole spec by hand.",
                );
            }
        }
    }

    // `--browser` is the whole browser handshake in one flag: it finds the
    // browsers `agent-sandbox browser` is running, maps each of their CDP ports,
    // and tells the entrypoint which is which.  Resolved here, after parsing, so
    // an explicit --host-loopback-port composes with it and --no-browser can
    // still cancel it.
    if want_browser {
        let running = ctl::browser::running_instances();
        let selected: Vec<_> = if want_browser_names.is_empty() {
            running
        } else {
            for name in &want_browser_names {
                if !running.iter().any(|i| &i.name == name) {
                    fail(&format!(
                        "agent-sandbox: --browser: no running browser named '{}'.\n               Start one with: agent-sandbox browser --name {}",
                        name, name
                    ));
                }
            }
            running
                .into_iter()
                .filter(|i| want_browser_names.contains(&i.name))
                .collect()
        };

        if selected.is_empty() {
            fail(
                "agent-sandbox: --browser: no browser is running.\n               Start one first: agent-sandbox browser\n               (it cannot be attached later -- the channel is set at launch.)",
            );
        }

        let attached = attach_browsers(&selected, &mut want_host_ports);
        env_args.push("-e".to_string());
        env_args.push(format!(
            "AGENT_SANDBOX_BROWSER_CDP_PORT={}",
            ctl::browser::cdp_port_env(&attached)
        ));
        eprintln!(
            "agent-sandbox: --browser: {}",
            selected
                .iter()
                .zip(&attached)
                .map(|(inst, (_, inside))| if *inside == inst.cdp_port {
                    format!("{} on {}", inst.name, inst.cdp_port)
                } else {
                    format!("{} on {} (sandbox {})", inst.name, inst.cdp_port, inside)
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Two mappings landing on one sandbox port would leave whichever socat lost
    // the bind race silently missing, so the collision is named here instead.
    let mut seen_sandbox_ports = HashSet::new();
    for hp in &want_host_ports {
        if !seen_sandbox_ports.insert(hp.sandbox) {
            fail(&format!(
                "agent-sandbox: --host-loopback-port: {} is mapped twice on the sandbox side.\n               Give one of them a different sandbox port, as in HOST:SANDBOX.",
                hp.sandbox
            ));
        }
    }

    if want_secrets && !want_proxy {
        fail("agent-sandbox: --secrets needs --proxy: the proxy is what injects them.");
    }

    if want_krun {
        if want_podman {
            fail("agent-sandbox: --krun cannot be combined with --podman.");
        }
        // Accepted rather than refused, but neither is verified against a
        // guest: --krun already runs the sandbox with SELinux labeling
        // disabled (the kernel refuses a domain transition once libkrun has
        // spawned the VM's threads), and nested podman inside the guest does
        // not work out of the box.  See docs/trust-model.md.
        if want_privileged {
            eprintln!("agent-sandbox: warning: --privileged is unverified under --krun;");
            eprintln!("               nested podman does not work in the guest out of the box.");
        }
        if want_selinux {
            eprintln!("agent-sandbox: warning: --selinux under --krun relabels the bind mounts,");
            eprintln!("               but the sandbox process itself runs with label=disable.");
        }
        if krun_ram_mib.is_empty() {
            krun_ram_mib = "4096".to_string();
        } else {
            match krun_ram_mib.parse::<u32>() {
                Ok(ram) if ram > 128 => {}
                _ => fail(
                    "agent-sandbox: --krun-memory needs a whole number of MiB greater than 128.",
                ),
            }
        }

        if !krun_cpus.is_empty() {
            match krun_cpus.parse::<u32>() {
                Ok(cpus) if (1..=16).contains(&cpus) => {}
                _ => fail("agent-sandbox: --krun-cpus needs a whole number between 1 and 16."),
            }
        }
    }

    if cmd_args.is_empty() {
        if agent.is_empty() {
            cmd_args.push("bash".to_string());
        } else if let Some(command_json) = agent_cmd_json.get(&agent) {
            cmd_args = serde_json::from_str(command_json).unwrap_or_else(|_| {
                fail(&format!(
                    "agent-sandbox: malformed command specification for agent '{}'",
                    agent
                ))
            });
        }
    }

    let rw_mount_opts = launch::rw_mount_opts(want_selinux);
    let home = env::var("HOME").unwrap_or_default();
    let pwd = env::current_dir()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let agents_md_path = Path::new(&pwd).join("AGENTS.md");
    let runtime_dir = env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| format!("/run/user/{}", nix::unistd::getuid().as_raw()));

    // ── Agent state ─────────────────────────────────────────────────────────

    let mut agent_mount_set = HashSet::new();
    match want_agent_mounts_mode {
        AgentMountsMode::None => {}
        AgentMountsMode::All => {
            for a in &agent_names {
                agent_mount_set.insert(a.clone());
            }
        }
        AgentMountsMode::List(ref l) => {
            for a in l {
                agent_mount_set.insert(a.clone());
            }
            if !agent.is_empty() {
                agent_mount_set.insert(agent.clone());
            }
        }
        AgentMountsMode::Auto => {
            if !agent.is_empty() {
                agent_mount_set.insert(agent.clone());
            }
        }
    }

    for a in &agent_mount_set {
        if let Some(json_str) = agent_state_json.get(a) {
            if let Ok(val) = serde_json::from_str::<Value>(json_str) {
                if let Some(arr) = val.as_array() {
                    for item in arr {
                        if let Some(rel) = item.as_str() {
                            let host = format!("{}/{}", home, rel);
                            let container = format!("/home/user/{}", rel);
                            fs::create_dir_all(&host).unwrap_or(());
                            mounts.push("-v".to_string());
                            mounts.push(format!("{}:{}:{}", host, container, rw_mount_opts));
                        }
                    }
                }
            }
        }
        if let Some(json_str) = agent_state_files_json.get(a) {
            if let Ok(val) = serde_json::from_str::<Value>(json_str) {
                if let Some(arr) = val.as_array() {
                    for item in arr {
                        if let Some(rel) = item.as_str() {
                            let host = format!("{}/{}", home, rel);
                            let container = format!("/home/user/{}", rel);
                            if !Path::new(&host).exists() {
                                fs::write(&host, "{}").unwrap_or(());
                            }
                            mounts.push("-v".to_string());
                            mounts.push(format!("{}:{}:{}", host, container, rw_mount_opts));
                        }
                    }
                }
            }
        }
    }

    // ── SSH ─────────────────────────────────────────────────────────────────
    // Under --proxy the socket is handed to the sidecar instead: a socket
    // mounted into the sandbox is a capability that does not pass the
    // firewall, so relay-ssh stands in for it (see docs/architecture.md).

    let mut want_relay_ssh = false;
    if want_ssh {
        match env::var("SSH_AUTH_SOCK") {
            Ok(sock) if !sock.is_empty() && Path::new(&sock).exists() => {
                if want_proxy {
                    sidecar_extra_mounts.push("-v".to_string());
                    sidecar_extra_mounts.push(format!("{}:/run/host-ssh-agent:rw", sock));
                    want_relay_ssh = true;
                } else {
                    let (m, e) = launch::ssh_direct(&sock, rw_mount_opts);
                    mounts.extend(m);
                    env_args.extend(e);
                }
            }
            _ => eprintln!(
                "agent-sandbox: --ssh requested but SSH_AUTH_SOCK does not name a socket."
            ),
        }
    }

    // ── Git ─────────────────────────────────────────────────────────────────
    // The host's *effective* configuration, flattened here rather than mounted:
    // [include] directives are evaluated on the host, and host-specific file
    // paths are dropped so they cannot break git inside the container.

    if want_git {
        let listed = ProcessCommand::new("git")
            .args(["config", "--list", "--global", "--null"])
            .output();
        match listed {
            Ok(out) if out.status.success() => {
                let pairs = launch::parse_git_config_null(&String::from_utf8_lossy(&out.stdout));
                env_args.extend(launch::git_config_env(&pairs));
                env_args.extend(launch::git_identity_env(&pairs));
            }
            _ => eprintln!(
                "agent-sandbox: --git requested but the host git config could not be read."
            ),
        }
    }

    // ── GnuPG ───────────────────────────────────────────────────────────────
    // The agent socket is forwarded so host keys can sign commits.  The keyring
    // directory is a separate decision: it is only exposed when it holds no
    // usable secret on disk (the smart-card case), unless --gpg-private
    // overrides.

    let mut want_relay_gpg = false;
    if want_gpg {
        let gpg_socket = ProcessCommand::new("gpgconf")
            .args(["--list-dir", "agent-socket"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("{}/gnupg/S.gpg-agent", runtime_dir));

        let gnupg_home = PathBuf::from(&home).join(".gnupg");
        let mut gnupg_mounts = Vec::new();
        if gnupg_home.is_dir() {
            match scan_gnupg_home(&gnupg_home) {
                Ok(GpgScanStatus::Safe) => {
                    gnupg_mounts = launch::gnupg_public_mounts(&gnupg_home, want_gpg_private);
                }
                Ok(GpgScanStatus::Unsafe(offenders)) => {
                    if want_gpg_private {
                        eprintln!("agent-sandbox: exposing ~/.gnupg with on-disk secret keys (--gpg-private).");
                        gnupg_mounts = launch::gnupg_public_mounts(&gnupg_home, true);
                    } else {
                        eprintln!(
                            "agent-sandbox: not exposing ~/.gnupg -- it holds secret keys on disk:"
                        );
                        for offender in offenders {
                            eprintln!("               {}", offender.display());
                        }
                        eprintln!("               A smart-card setup keeps only stubs here and is exposed normally.");
                        eprintln!("               Override with --gpg-private, or silence this with --no-gpg.");
                        std::process::exit(1);
                    }
                }
                Err(e) => fail(&format!("agent-sandbox: could not inspect ~/.gnupg: {}", e)),
            }
        }

        if Path::new(&gpg_socket).exists() {
            if want_proxy {
                // gpg runs in the sidecar, next to the socket, and the sandbox
                // reaches it through relay-gpg.  The sidecar boots the same
                // entrypoint, so the same env var sets up its ~/.gnupg there.
                sidecar_extra_mounts.push("-v".to_string());
                sidecar_extra_mounts.push(format!("{}:/run/host-gpg-agent:ro", gpg_socket));
                sidecar_extra_mounts.extend(gnupg_mounts);
                sidecar_extra_env.push("-e".to_string());
                sidecar_extra_env.push("AGENT_SANDBOX_GPG_AGENT=1".to_string());
                want_relay_gpg = true;
            } else {
                mounts.push("-v".to_string());
                mounts.push(format!("{}:/run/host-gpg-agent:ro", gpg_socket));
                mounts.extend(gnupg_mounts);
                env_args.push("-e".to_string());
                env_args.push("AGENT_SANDBOX_GPG_AGENT=1".to_string());
            }
        } else {
            eprintln!(
                "agent-sandbox: --gpg requested but no gpg-agent socket at {}.",
                gpg_socket
            );
        }
    } else {
        // Without a forwarded agent, signing can only fail: say so in config
        // rather than at commit time.
        env_args.push("-e".to_string());
        env_args.push("AGENT_SANDBOX_NO_GPG_SIGN=1".to_string());
    }

    if want_relay_ssh {
        env_args.push("-e".to_string());
        env_args.push("AGENT_SANDBOX_RELAY_SSH=1".to_string());
    }
    if want_relay_gpg {
        env_args.push("-e".to_string());
        env_args.push("AGENT_SANDBOX_RELAY_GPG=1".to_string());
    }

    // ── devenv / nix / podman ───────────────────────────────────────────────

    if want_devenv {
        let devenv_dir = format!("{}/.local/share/devenv", home);
        fs::create_dir_all(&devenv_dir).unwrap_or(());
        mounts.push("-v".to_string());
        mounts.push(format!(
            "{}:/home/user/.local/share/devenv:{}",
            devenv_dir, rw_mount_opts
        ));
    }

    if want_nix {
        let is_socket = fs::metadata("/nix/var/nix/daemon-socket/socket")
            .map(|m| {
                use std::os::unix::fs::FileTypeExt;
                m.file_type().is_socket()
            })
            .unwrap_or(false);
        let (m, e) = launch::nix_mounts(is_socket, Path::new("/nix/store").is_dir(), rw_mount_opts);
        mounts.extend(m);
        env_args.extend(e);
    }

    if want_podman {
        let host_socket = format!("{}/podman/podman.sock", runtime_dir);
        if Path::new(&host_socket).exists() {
            let (m, e) = launch::podman_socket_mounts(&host_socket, rw_mount_opts);
            mounts.extend(m);
            env_args.extend(e);
        } else {
            eprintln!(
                "agent-sandbox: --podman requested but no socket at {}.",
                host_socket
            );
            eprintln!("               Start it with: systemctl --user start podman.socket");
        }
    }

    // ── Workspace ───────────────────────────────────────────────────────────

    let workspace_dir = if want_workspace {
        let workspace_name = Path::new(&pwd)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let dir = format!("/workspace/{}", workspace_name);
        mounts.push("-v".to_string());
        mounts.push(format!("{}:{}:{}", pwd, dir, rw_mount_opts));
        dir
    } else {
        "/workspace".to_string()
    };

    // ── Declared ports and mounts ───────────────────────────────────────────
    // Both are strict: a block the operator got wrong must not silently become
    // no block at all.  Nothing from AGENTS.md is ever passed to podman as an
    // argument of its own.

    if want_ports && agents_md_path.exists() {
        let text = fs::read_to_string(&agents_md_path).unwrap_or_default();
        let declared = match agents::parse_ports(&text, want_ports_any_interface, agents::MAX_PORTS)
        {
            Ok(mappings) => mappings,
            Err(e) => {
                eprintln!("agent-sandbox: {}", e);
                fail("agent-sandbox: refusing to launch on an invalid [ports] block (use --no-ports to skip).");
            }
        };
        for mapping in declared {
            // host = 0 asks for a free port, which can only be found now.
            let mapping = match agents::allocate(mapping) {
                Ok(m) => m,
                Err(e) => fail(&format!("agent-sandbox: {}", e)),
            };
            // Under --proxy the bind address decides.  A loopback publish is
            // ingress from this machine and leaves the egress policy intact:
            // rootlessport forwards into the --internal network, the sandbox
            // still has no route out.  A LAN-reachable one is a channel out by
            // another route -- anything on the network can pull whatever the
            // agent serves -- and the proxy never sees it, so the policy would
            // hold for pushed bytes and not for pulled ones.  Refused before
            // any network is created, so the refusal leaves nothing behind.
            if want_proxy && !is_loopback_bind(&mapping.bind) {
                fail(&format!(
                    "agent-sandbox: --proxy cannot be combined with a port published off loopback ({}).\n               Anything on the network could pull what the agent serves there,\n               which the proxy never sees, so the egress policy would only be\n               advisory.  A loopback bind is fine and needs no flag.\n               Drop --ports-any-interface, or drop --proxy.",
                    mapping.spec()
                ));
            }
            publish_args.push("-p".to_string());
            publish_args.push(mapping.spec());
            published.push(mapping.spec());
        }
    }

    if want_mounts && agents_md_path.exists() {
        let text = fs::read_to_string(&agents_md_path).unwrap_or_default();
        let declared = match agents::parse_mounts(&text) {
            Ok(specs) => specs,
            Err(e) => {
                eprintln!("agent-sandbox: {}", e);
                fail("agent-sandbox: refusing to launch on an invalid [mounts] block (use --no-mounts to skip).");
            }
        };
        for spec in declared {
            // Kept out of `mounts`: the options in a [mounts] declaration are
            // the operator's, like the ones passed through --podman-args, and
            // --selinux governs the launcher's own binds only.
            declared_mounts.push("-v".to_string());
            declared_mounts.push(expand_v(&spec, Path::new(&pwd), &home));
        }
    }

    // Refused for the same reason a published port is: joining the shared
    // bridge *as well as* the proxy's --internal network would hand the sandbox
    // a route to the internet that never passes the proxy, leaving the policy
    // advisory.  Checked separately because the flag no longer needs a port.
    if want_proxy && want_shared_network {
        fail(
            "agent-sandbox: --proxy cannot be combined with --shared-network.\n               The shared bridge routes around the proxy's internal network,\n               so the policy would only be advisory.\n               Drop --shared-network, or drop --proxy.",
        );
    }

    // A shared network is what lets anything else reach this container by name
    // later, and it is opt-in because it is not free: it replaces podman's
    // rootless default (pasta) with a bridge, so anything the operator wants
    // from pasta is given up with it.  Publishing does not need it -- podman
    // publishes under pasta just as well -- and neither does reaching the host's
    // loopback, which --host-loopback-port does through a mounted socket rather
    // than a route.  So the decisions are kept apart, and the flag stands on its
    // own: being reachable by name is useful without publishing anything.
    let mut network_args: Vec<String> = Vec::new();
    if want_shared_network {
        let network =
            env::var("AGENT_SANDBOX_NETWORK").unwrap_or_else(|_| "agent-sandbox".to_string());
        let exists = ProcessCommand::new("podman")
            .args(["network", "exists", &network])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !exists {
            let created = ProcessCommand::new("podman")
                .args(["network", "create", &network])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !created {
                fail(&format!(
                    "agent-sandbox: could not create the network {}",
                    network
                ));
            }
        }
        network_args.push("--network".to_string());
        network_args.push(network);
    }

    // Outside the block above: a port is published in either network mode, and
    // saying so is not the shared network's business.
    if !published.is_empty() {
        eprintln!("agent-sandbox: publishing {}", published.join(" "));
        eprintln!("               (a server inside must bind 0.0.0.0, not 127.0.0.1)");
    }

    // ── Identity ────────────────────────────────────────────────────────────

    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();
    let mut passwd_file = Builder::new()
        .prefix("agent-sandbox-passwd-")
        .tempfile()
        .expect("Failed to create temporary passwd file");
    let mut group_file = Builder::new()
        .prefix("agent-sandbox-group-")
        .tempfile()
        .expect("Failed to create temporary group file");
    // World-readable like a real /etc/passwd (no secrets in it): the default
    // 0600 can end up unreadable to the container's mapped uid across extra
    // user-namespace layers, which surfaces as ssh/git failing to resolve
    // "who am I".
    fs::set_permissions(passwd_file.path(), fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(group_file.path(), fs::Permissions::from_mode(0o644)).unwrap();
    writeln!(passwd_file, "root:x:0:0:root:/root:/bin/sh").unwrap();
    writeln!(passwd_file, "user:x:{}:{}::/home/user:/bin/bash", uid, gid).unwrap();
    writeln!(passwd_file, "nobody:x:65534:65534:Nobody:/:/bin/sh").unwrap();
    writeln!(group_file, "root:x:0:").unwrap();
    writeln!(group_file, "user:x:{}:", gid).unwrap();
    writeln!(group_file, "nobody:x:65534:").unwrap();
    mounts.push("-v".to_string());
    mounts.push(format!(
        "{}:/etc/passwd:ro",
        passwd_file.path().to_string_lossy()
    ));
    mounts.push("-v".to_string());
    mounts.push(format!(
        "{}:/etc/group:ro",
        group_file.path().to_string_lossy()
    ));
    // The sidecar needs the same two files.  It runs without --userns=keep-id,
    // so it is uid 0 inside, and the image ships no /etc/passwd of its own --
    // which leaves the relay's ssh calling getpwuid(0) against an empty passwd
    // database and failing with "No user exists for uid 0" before it opens a
    // connection.  The relay runs ssh and gpg here rather than in the sandbox,
    // so this is the side that has to be able to answer "who am I".
    sidecar_extra_mounts.push("-v".to_string());
    sidecar_extra_mounts.push(format!(
        "{}:/etc/passwd:ro",
        passwd_file.path().to_string_lossy()
    ));
    sidecar_extra_mounts.push("-v".to_string());
    sidecar_extra_mounts.push(format!(
        "{}:/etc/group:ro",
        group_file.path().to_string_lossy()
    ));

    // Include the workspace and a short word in the container name so ctl can
    // identify sandboxes without guessing network/PID relationships.  The word
    // is the user-facing selector; the full podman name stays internal.
    let workspace_slug = launch::sanitize_workspace_slug(
        &Path::new(&pwd)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
    );
    let existing = ctl::resolve::sandbox_containers_all().unwrap_or_default();
    let mut rng = rand::thread_rng();
    let session_word = match launch::choose_session_word(&existing, || {
        rng.gen_range(0..launch::SESSION_WORDS.len())
    }) {
        Some(word) => word,
        None => fail("agent-sandbox: could not allocate a unique session word"),
    };
    let container_name = launch::container_name(&workspace_slug, &session_word);

    // ── Sidecar proxy ───────────────────────────────────────────────────────

    let mut policy_file_content = String::new();
    let mut proxy_configured = false;
    let mut secrets_configured = false;

    let mut merged_policy = agents::ProxyPolicy::default();
    merged_policy.default = vec!["deny".to_string()];

    if use_agents_network && agents_md_path.exists() {
        let text = fs::read_to_string(&agents_md_path).unwrap_or_default();
        match parse_proxy(&text) {
            Ok(policy) => merged_policy.merge(policy),
            Err(e) => {
                eprintln!("agent-sandbox: {}", e);
                return refuse("agent-sandbox: refusing to launch on an invalid [network] block (use --no-proxy to skip).");
            }
        }
    } else if !want_proxy && agents_md_path.exists() {
        // Preserve the existing diagnostic when a project declares network
        // rules but the caller did not enable proxy mode.
        if let Ok(text) = fs::read_to_string(&agents_md_path) {
            match parse_proxy(&text) {
                Ok(policy) => {
                    proxy_configured = !policy.allow_host.is_empty()
                        || !policy.allow_ip.is_empty()
                        || !policy.allow_port.is_empty()
                        || !policy.allow_route.is_empty();
                    secrets_configured = !policy.secret_route.is_empty();
                }
                Err(e) => eprintln!(
                    "agent-sandbox: warning: invalid [network] block in AGENTS.md: {}",
                    e
                ),
            }
        }
    }

    if want_proxy {
        for profile_name in &proxy_profiles {
            let profile_path = proxy_profile_path(&home, profile_name)?;
            let text = fs::read_to_string(&profile_path).map_err(|e| {
                anyhow::anyhow!(
                    "agent-sandbox: cannot read proxy profile '{}': {} ({})",
                    profile_name,
                    e,
                    profile_path.display()
                )
            })?;
            let policy = parse_proxy_profile(&text).map_err(|e| {
                anyhow::anyhow!(
                    "agent-sandbox: invalid proxy profile '{}': {}",
                    profile_name,
                    e
                )
            })?;
            merged_policy.merge(policy);
        }

        // GPG signing is gated on --gpg alone, independent of AGENTS.md: the
        // relay's GPG check is host-agnostic (gpg has no destination of its
        // own), so there is nothing for a network policy to usefully name.
        if want_relay_gpg {
            merged_policy.signing_enabled = true;
        }

        policy_file_content = format_proxy_policy(&merged_policy, "AGENTS.md and proxy profiles");
        proxy_configured = !merged_policy.allow_host.is_empty()
            || !merged_policy.allow_ip.is_empty()
            || !merged_policy.allow_port.is_empty()
            || !merged_policy.allow_route.is_empty();
        secrets_configured = !merged_policy.secret_route.is_empty();
    }

    // ── Host-key authorization ──────────────────────────────────────────────
    // Before the cleanup guard is armed and before any container exists: this
    // check reads no written file and shells out to nothing, so it can fail
    // outright rather than building a network only to tear it down.  The
    // secrets check further down cannot -- it reads the compiled policy back
    // and calls secretspec -- which is why the two run at different points.
    let trusted_config = trusted::config_path(&home);
    if let Some(message) = trusted::legacy_path_refusal(&home) {
        fail(&message);
    }
    let trusted_known_hosts = match trusted::load_known_hosts(&trusted_config) {
        Ok(hosts) => hosts,
        Err(e) => fail(&e.to_string()),
    };
    if want_proxy {
        // `allow_signing` is the policy's own record of "SSH to this host is
        // authorized", and it exists only for an allowed_hosts entry covering
        // port 22.  Keying off it rather than off the TOML means a port range
        // and a comma-separated list are caught on the same terms as a lone
        // `:22`, and an allowed_routes host on :22 is not -- it never reaches
        // the relay either.
        let unauthorized =
            trusted::unauthorized_signing_hosts(&merged_policy.allow_signing, &trusted_known_hosts);
        if !unauthorized.is_empty() {
            fail(&trusted::refusal(&unauthorized, &trusted_config));
        }
    }

    if !want_proxy && (proxy_configured || secrets_configured) {
        eprintln!("agent-sandbox: warning: [network] rules or secrets are configured in AGENTS.md, but proxy is not active.");
        eprintln!("               Launch with --proxy to enforce them.");
    }

    if want_proxy && !want_secrets && secrets_configured {
        eprintln!("agent-sandbox: warning: secrets are configured in AGENTS.md [[network.allowed_routes]], but --secrets is not active.");
        eprintln!("               Launch with --secrets to enable them.");
    }

    let mut cleanup_guard = CleanupGuard::new();
    let mut proxy_env_vars: Vec<String> = Vec::new();
    let image = env::var("AGENT_SANDBOX_IMAGE").unwrap_or_default();

    // ── Host loopback ports ─────────────────────────────────────────────────
    // One unix socket per mapping, in a directory mounted into the sandbox,
    // with the launcher splicing each connection to the host's loopback.  It is
    // deliberately not a route: a route is a network mode, and the sandbox's is
    // already spoken for, which is exactly why the pasta mapping this replaced
    // could not be had together with --proxy.
    if !want_host_ports.is_empty() {
        let dir = format!(
            "{}/agent-sandbox-host-{}",
            runtime_dir,
            &uuid::Uuid::new_v4().to_string()[0..8]
        );

        // A unix socket path has to fit sockaddr_un's 108 bytes, and this one is
        // built from a runtime directory the launcher does not choose.  Checked
        // here because the kernel's own answer is "path must be shorter than
        // SUN_LEN", which names neither the path nor the variable that set it.
        let longest = want_host_ports
            .iter()
            .map(|p| dir.len() + format!("/{}.sock", p.sandbox).len())
            .max()
            .unwrap_or(0);
        if longest >= 108 {
            fail(&format!(
                "agent-sandbox: --host-loopback-port: $XDG_RUNTIME_DIR is too long to hold a\n               socket path ({} of the 107 bytes a unix socket allows).\n               Point XDG_RUNTIME_DIR at a shorter directory, such as /run/user/{}.",
                longest,
                nix::unistd::getuid().as_raw()
            ));
        }

        if let Err(e) = fs::create_dir_all(&dir) {
            fail(&format!(
                "agent-sandbox: --host-loopback-port: could not create {}: {}",
                dir, e
            ));
        }
        // Only this user's, whatever the umask: the sockets in here reach
        // services on their loopback.
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        cleanup_guard.host_port_dir = dir.clone();

        for hp in &want_host_ports {
            let socket = PathBuf::from(&dir).join(format!("{}.sock", hp.sandbox));
            if let Err(e) = serve_host_port(&socket, hp.host) {
                // refuse() rather than fail(): the guard is armed by now, and
                // returning is what lets it remove the directory.  Leaving that
                // behind would leave a live-looking path to the host's loopback
                // in place of one that failed to open.
                return refuse(&format!(
                    "agent-sandbox: --host-loopback-port: could not listen for {}: {}",
                    hp.sandbox, e
                ));
            }
            eprintln!(
                "agent-sandbox: 127.0.0.1:{} in the sandbox reaches the host's 127.0.0.1:{}",
                hp.sandbox, hp.host
            );
            // Probed rather than assumed, and a warning rather than a refusal:
            // the browser flow has the user start Chrome by hand, sometimes
            // after the sandbox.  Saying so now beats a refused connection an
            // agent inside cannot tell from a typo.
            if TcpStream::connect(("127.0.0.1", hp.host)).is_err() {
                eprintln!(
                    "               (nothing is listening there yet; it will connect when there is)"
                );
            }
        }

        if want_proxy {
            eprintln!(
                "agent-sandbox: warning: a mapped host port is outside the egress policy.  The"
            );
            eprintln!(
                "               proxy does not see what the service on it fetches on its own."
            );
        }

        mounts.push("-v".to_string());
        mounts.push(format!("{}:{}:{}", dir, HOST_PORT_DIR, rw_mount_opts));
        // Named so an agent can test for the channel rather than discovering
        // its absence as a refused connection -- and per port, because the
        // whole point is that only the ports named here are reachable.
        env_args.push("-e".to_string());
        env_args.push(format!(
            "AGENT_SANDBOX_HOST_PORTS={}",
            want_host_ports
                .iter()
                .map(|p| p.sandbox.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }

    // Checked before the sidecar rather than at `podman run`: the sidecar comes
    // from the same image, and a missing one would surface as "could not start
    // the proxy sidecar", which sends you looking in the wrong place.
    if !image.is_empty() {
        let status = ProcessCommand::new("podman")
            .args(["image", "exists", &image])
            .status();
        if status.map(|s| !s.success()).unwrap_or(true) {
            fail(&format!(
                "agent-sandbox: image {} not found. Run 'agent-sandbox ctl load' first.",
                image
            ));
        }
    }

    let mut sidecar_ip = String::new();
    if want_proxy {
        let uuid_str = uuid::Uuid::new_v4().to_string();
        let uuid = &uuid_str[0..8];
        let sidecar_id = format!("agent-sandbox-sidecar-{}", uuid);
        // Identifiable templates, so `agent-sandbox ctl purge` can recognise
        // the dirs left behind by a launcher that was killed before its
        // cleanup could run.
        let sidecar_shared = format!("/tmp/agent-sandbox-sidecar-{}", uuid);
        let sidecar_policy = format!("/tmp/agent-sandbox-policy-{}", uuid);
        let sidecar_secrets = format!("/tmp/agent-sandbox-secrets-{}", uuid);

        fs::create_dir_all(&sidecar_shared)?;
        fs::create_dir_all(&sidecar_policy)?;

        cleanup_guard.sidecar_id = sidecar_id.clone();
        cleanup_guard.sidecar_shared = sidecar_shared.clone();
        cleanup_guard.sidecar_policy = sidecar_policy.clone();
        cleanup_guard.log_level = want_proxy_log;
        cleanup_guard.session_word = session_word.clone();
        cleanup_guard.use_agents_network = use_agents_network;
        cleanup_guard.proxy_profiles = proxy_profiles.clone();

        // --disable-dns is load-bearing: podman routes a container's whole
        // resolver through aardvark-dns as soon as any of its networks has
        // dns_enabled, and aardvark refuses to serve --internal networks, so
        // the sidecar's only nameserver would answer NXDOMAIN to every
        // external name.  With DNS off there is no aardvark in the path and
        // --dns lands in resolv.conf verbatim.
        let net_created = ProcessCommand::new("podman")
            .args([
                "network",
                "create",
                "--internal",
                "--disable-dns",
                &sidecar_id,
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !net_created {
            return refuse(&format!(
                "agent-sandbox: could not create the sidecar network {}\n               (leaked networks exhaust the rootless subnet pool:\n                reclaim them with 'agent-sandbox ctl purge')",
                sidecar_id
            ));
        }

        // The sidecar is also on the default bridge, so a proxy binding
        // 0.0.0.0 would be reachable from any other container of the same user
        // there.  Handing it its own internal-network subnet lets it bind only
        // the address it holds on that network.
        let sidecar_subnet = ProcessCommand::new("podman")
            .args([
                "network",
                "inspect",
                &sidecar_id,
                "--format",
                "{{(index .Subnets 0).Subnet}}",
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        if sidecar_subnet.is_empty() {
            return refuse(&format!(
                "agent-sandbox: could not determine the subnet of {}",
                sidecar_id
            ));
        }

        // The policy file is the single channel by which policy reaches the
        // proxy.  Written into a directory mounted ro into the sidecar and NOT
        // into the sandbox: the agent must not be able to widen the firewall
        // that contains it.

        let mut baseline_content = String::new();
        for cidr in launch::BASELINE_DENY_IPS {
            let line = format!("deny_ip {}\n", cidr);
            policy_file_content.push_str(&line);
            // policy.baseline records just the launcher-added entries, so that
            // `ctl proxy export` can omit them: they are always enforced
            // regardless of what AGENTS.md declares.
            baseline_content.push_str(&line);
        }

        fs::write(format!("{}/policy", sidecar_policy), &policy_file_content)?;
        fs::write(
            format!("{}/policy.baseline", sidecar_policy),
            &baseline_content,
        )?;
        // Kept pristine so `ctl proxy reset` has something to restore and
        // `proxy show` can tell declared rules from ones added at runtime.
        fs::write(
            format!("{}/policy.base", sidecar_policy),
            &policy_file_content,
        )?;

        // The authorized host keys travel beside the policy, in the same
        // ro-mounted directory, because they are the same kind of thing: a
        // host-side decision the sandbox may read and may not write.  Every
        // declared entry is written, not only the ones that satisfied a
        // requirement -- an entry on another port is exactly what an
        // `ssh -p 2222` through the proxy needs.
        if !trusted_known_hosts.is_empty() {
            fs::write(
                format!("{}/known_hosts", sidecar_policy),
                trusted::render_known_hosts(&trusted_known_hosts),
            )?;
        }

        if !launch::policy_has_allow_rules(&policy_file_content) {
            eprintln!("agent-sandbox: --proxy is active with no allow rules.");
            eprintln!("               Use 'agent-sandbox ctl tui' to allow connections live,");
            eprintln!("               or declare a [network] allow list in AGENTS.md.");
        }

        if want_secrets {
            fs::create_dir_all(&sidecar_secrets)?;
            cleanup_guard.sidecar_secrets = sidecar_secrets.clone();
            let config = trusted::config_path(&home);
            let manifest = Path::new(&pwd).join("secretspec.toml");
            let profile_paths: Vec<PathBuf> = proxy_profiles
                .iter()
                .filter_map(|name| proxy_profile_path(&home, name).ok())
                .collect();
            let bindings = match resolve_secrets_logic_with_profiles(
                Path::new(&format!("{}/policy", sidecar_policy)),
                &config,
                &manifest,
                &agents_md_path,
                &profile_paths,
            ) {
                Ok(bindings) => bindings,
                Err(e) => return refuse(e.to_string().trim_end()),
            };
            if bindings.is_empty() {
                eprintln!(
                    "agent-sandbox: --secrets resolved no bindings; nothing will be injected."
                );
            } else {
                // Written 0600 and mounted read-only: the values never reach
                // the sandbox, only the proxy that injects them.
                let path = format!("{}/bindings", sidecar_secrets);
                fs::write(&path, format!("{}\n", bindings.join("\n")))?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                sidecar_extra_mounts.push("-v".to_string());
                sidecar_extra_mounts.push(format!("{}:/sidecar_secrets:ro", sidecar_secrets));
            }
        }

        let mut proxy_cmd = ProcessCommand::new("podman");
        proxy_cmd
            .args(["run", "-d", "--name", &sidecar_id])
            .args(["--network", "bridge", "--network", &sidecar_id])
            .args(sidecar_dns_args())
            // NET_ADMIN backs the blackhole routes installed for deny_ip.
            .arg("--cap-add=NET_ADMIN")
            // NET_BIND_SERVICE backs the transparent listeners on :80 and :443.
            // It is in podman's default set, but asked for explicitly so a host
            // that narrowed that set does not turn into a sidecar that exits at
            // bind time for no stated reason.
            .arg("--cap-add=NET_BIND_SERVICE")
            // The sidecar is infrastructure, not agent workload: keep its
            // policy/log mounts SELinux-safe regardless of --selinux, so proxy
            // readiness does not depend on host labeling conventions.
            .args(["--security-opt", "label=disable"])
            .args(["-v", &format!("{}:/sidecar_shared:rw", sidecar_shared)])
            .args(["-v", &format!("{}:/sidecar_policy:ro", sidecar_policy)])
            .args(&sidecar_extra_mounts)
            .args(["-e", "AGENT_SANDBOX_SKIP_NIX_INIT=1"])
            .args(["-e", &format!("SIDECAR_SUBNET={}", sidecar_subnet)])
            .args(&sidecar_extra_env)
            .args(["--label", "agent-sandbox.role=proxy"])
            .args([
                "--label",
                &format!("agent-sandbox.target={}", container_name),
            ]);
        if want_workspace {
            proxy_cmd.args(["--label", &format!("agent-sandbox.workspace={}", pwd)]);
        }
        proxy_cmd
            .arg(&image)
            .arg("agent-sandbox-sidecar")
            .stdout(std::process::Stdio::null());

        if !proxy_cmd.status().map(|s| s.success()).unwrap_or(false) {
            return refuse("agent-sandbox: could not start the proxy sidecar");
        }

        // The sidecar writes its readiness marker only after the proxy can
        // resolve names and the blackhole routes are installed, so this has to
        // outlast the proxy's own timeout: starting the agent against a proxy
        // that cannot reach anything yet is exactly the race this closes.
        let ready_path = format!("{}/ready", sidecar_shared);
        let mut sidecar_ready = false;
        for _ in 0..350 {
            if Path::new(&ready_path).exists() {
                sidecar_ready = true;
                break;
            }
            // A rejected policy exits the proxy immediately; waiting out the
            // full 35s would bury the reason under a timeout that suggests a
            // network problem.
            let running = ProcessCommand::new("podman")
                .args([
                    "container",
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    &sidecar_id,
                ])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
                .unwrap_or(false);
            if !running {
                eprintln!("agent-sandbox: the proxy sidecar exited before signalling readiness:");
                if let Ok(logs_out) = ProcessCommand::new("podman")
                    .args(["logs", &sidecar_id])
                    .output()
                {
                    for line in String::from_utf8_lossy(&logs_out.stderr).lines() {
                        eprintln!("               {}", line);
                    }
                }
                return Ok(1);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        if !sidecar_ready {
            eprintln!("agent-sandbox: warning: proxy did not signal readiness in 35s");
            eprintln!(
                "               (continuing; check: podman logs {})",
                sidecar_id
            );
        }

        let degraded_path = format!("{}/egress-degraded", sidecar_shared);
        if Path::new(&degraded_path).exists() {
            eprintln!("agent-sandbox: warning: the proxy could not resolve names at startup");
            if let Ok(msg) = fs::read_to_string(&degraded_path) {
                for line in msg.lines() {
                    eprintln!("               {}", line);
                }
            }
            eprintln!(
                "               (continuing; requests may fail. Full log: agent-sandbox ctl logs)"
            );
        }

        network_args.push("--network".to_string());
        network_args.push(sidecar_id.clone());

        // By address, not by name: the internal network is --disable-dns, so
        // there is no aardvark to resolve the sidecar's container name.
        for _ in 0..20 {
            let out = ProcessCommand::new("podman")
                .args([
                    "container",
                    "inspect",
                    "--format",
                    &format!(
                        "{{{{(index .NetworkSettings.Networks \"{}\").IPAddress}}}}",
                        sidecar_id
                    ),
                    &sidecar_id,
                ])
                .output();
            if let Ok(out) = out {
                if out.status.success() {
                    let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !ip.is_empty() {
                        sidecar_ip = ip;
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        if sidecar_ip.is_empty() {
            return refuse(&format!(
                "agent-sandbox: the proxy sidecar has no address on {}\n               (check: podman logs {})",
                sidecar_id, sidecar_id
            ));
        }

        proxy_env_vars.push(format!("HTTP_PROXY=http://{}:8888", sidecar_ip));
        proxy_env_vars.push(format!("HTTPS_PROXY=http://{}:8888", sidecar_ip));
        proxy_env_vars.push(format!("http_proxy=http://{}:8888", sidecar_ip));
        proxy_env_vars.push(format!("https_proxy=http://{}:8888", sidecar_ip));
        // Loopback is exempt because proxying it can only fail: curl and
        // requests do not special-case it, so a request to a server the agent
        // just started in its own container would go to the sidecar, resolve to
        // 127.0.0.1, and be refused by the baseline deny.  This grants nothing
        // -- the sandbox already owns its netns, and NO_PROXY is a hint to
        // clients, not a route.  Literal entries only: wildcard and CIDR syntax
        // disagree across curl, requests, Go and undici.
        proxy_env_vars.push("NO_PROXY=localhost,127.0.0.1,::1".to_string());
        proxy_env_vars.push("no_proxy=localhost,127.0.0.1,::1".to_string());
        // ALL_PROXY as well, because it is the only one some clients read --
        // notably anything built on Go's x/net/proxy, and curl's SOCKS-agnostic
        // fallback.  Nix has no proxy setting of its own: `http-proxy` is not a
        // nix.conf key, and passing it via NIX_CONFIG only earns an "unknown
        // setting" warning.  Nix's own downloads are libcurl, which reads these
        // variables; its *git* fetches are the case `--transparent` covers.
        proxy_env_vars.push(format!("ALL_PROXY=http://{}:8888", sidecar_ip));
        proxy_env_vars.push(format!("all_proxy=http://{}:8888", sidecar_ip));

        if want_relay_ssh || want_relay_gpg {
            proxy_env_vars.push(format!("AGENT_SANDBOX_RELAY_ADDRESS={}:8889", sidecar_ip));
        }

        // The proxy terminates TLS for any host carrying an L7 rule, so the
        // sandbox has to trust its session CA or every such request fails
        // certificate validation.  The file only, never /sidecar_shared
        // itself: the agent must not be able to rewrite the log of what it
        // did.
        //
        // Gated on the policy actually having an L7 rule.  With none, nothing
        // is ever intercepted, so handing the sandbox a CA that can mint any
        // name would grant trust for no purpose.  The cost is that an L7 rule
        // added mid-session has no CA to go with it -- `ctl proxy allow --l7`
        // and the TUI's `h` say so rather than failing silently.
        // The sandbox's own ssh still leaves through the CONNECT proxy (the
        // entrypoint writes a ProxyCommand for it), so it needs the same
        // authorized keys the relay uses.  Bound as a single file, like the CA
        // below and for the same reason: the directory it lives in is the
        // policy, and the agent must not be able to rewrite that.
        let known_hosts_file = format!("{}/known_hosts", sidecar_policy);
        if Path::new(&known_hosts_file).exists() {
            mounts.push("-v".to_string());
            mounts.push(format!(
                "{}:/run/agent-sandbox-known-hosts:ro",
                known_hosts_file
            ));
            env_args.push("-e".to_string());
            env_args.push("AGENT_SANDBOX_KNOWN_HOSTS=/run/agent-sandbox-known-hosts".to_string());
        }

        let ca_pem = format!("{}/ca.pem", sidecar_shared);
        if launch::policy_has_l7_rules(&policy_file_content) && Path::new(&ca_pem).exists() {
            mounts.push("-v".to_string());
            mounts.push(format!("{}:/run/agent-sandbox-proxy-ca.pem:ro", ca_pem));
            env_args.push("-e".to_string());
            env_args
                .push("AGENT_SANDBOX_PROXY_CA_FILE=/run/agent-sandbox-proxy-ca.pem".to_string());
        }
    }

    // ── podman run ──────────────────────────────────────────────────────────

    // Applied once, at the end, so every bind gets the same treatment
    // regardless of which block produced it.  Volume options passed through
    // --podman-args are left exactly as supplied.
    let mounts: Vec<String> = {
        let mut out = Vec::new();
        let mut idx = 0;
        while idx < mounts.len() {
            if mounts[idx] == "-v" && idx + 1 < mounts.len() {
                out.push("-v".to_string());
                out.push(enforce_selinux_mount_flags(&mounts[idx + 1], want_selinux));
                idx += 2;
            } else {
                out.push(mounts[idx].clone());
                idx += 1;
            }
        }
        out
    };

    let mut podman_cmd = ProcessCommand::new("podman");
    podman_cmd.arg("run").arg("--rm").arg("--interactive");
    // Only allocate a TTY when there is one to allocate, so piped and CI
    // invocations still work.
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        podman_cmd.arg("--tty");
    }
    podman_cmd.args(["--userns=keep-id", "--name", &container_name]);
    podman_cmd.args(["-e", "HOME=/home/user"]);

    let proxy_mode = if want_proxy { "proxy" } else { "off" };
    let sandbox_runtime = if want_krun { "krun" } else { "crun" };

    // Always recorded, including "off": an absent label is indistinguishable
    // from a container created before this existed, which would make the ctl
    // columns ambiguous exactly when it matters.
    podman_cmd.args(["--label", "agent-sandbox.role=sandbox"]);
    if want_workspace {
        podman_cmd.args(["--label", &format!("agent-sandbox.workspace={}", pwd)]);
    }
    podman_cmd.args(["--label", &format!("agent-sandbox.proxy={}", proxy_mode)]);
    podman_cmd.args([
        "--label",
        &format!("agent-sandbox.runtime={}", sandbox_runtime),
    ]);
    podman_cmd.args([
        "--label",
        &format!("agent-sandbox.command={}", cmd_args.join(" ")),
    ]);
    podman_cmd.args(["--workdir", &workspace_dir]);

    podman_cmd.args(["--mount", "type=tmpfs,dst=/home/user/.config,U=true"]);
    podman_cmd.args(["--mount", "type=tmpfs,dst=/home/user/.cache,U=true"]);
    podman_cmd.args(["--mount", "type=tmpfs,dst=/home/user/.local,U=true"]);

    podman_cmd.args(&network_args);
    podman_cmd.args(&publish_args);

    // Every allowed name resolves to the sidecar, so a client that ignores the
    // proxy environment reaches the proxy's transparent listeners instead of
    // failing at DNS.  `allow_host` is the whole set: a host named by an
    // `allowed_routes` entry is added to it by the same parser.
    if want_proxy && !sidecar_ip.is_empty() {
        for name in launch::transparent_host_names(&merged_policy.allow_host) {
            podman_cmd.arg("--add-host");
            podman_cmd.arg(format!("{}:{}", name, sidecar_ip));
        }
    }

    for proxy_env in proxy_env_vars {
        podman_cmd.arg("-e");
        podman_cmd.arg(proxy_env);
    }

    podman_cmd.arg("-e");
    podman_cmd.arg(format!(
        "TERM={}",
        env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string())
    ));
    if let Ok(colorterm) = env::var("COLORTERM") {
        if !colorterm.is_empty() {
            podman_cmd.arg("-e");
            podman_cmd.arg(format!("COLORTERM={}", colorterm));
        }
    }

    podman_cmd.args(&env_args);
    podman_cmd.args(&mounts);
    podman_cmd.args(&declared_mounts);

    if want_krun {
        podman_cmd.args(launch::krun_args(&krun_runtime, &krun_ram_mib, &krun_cpus));
    }

    podman_cmd.args(&podman_args);

    podman_cmd.arg(&image);
    podman_cmd.args(&cmd_args);

    // Not exec'd: returning is what drops the cleanup guard, which stops the
    // sidecar and prints its traffic summary.
    match podman_cmd.status() {
        Ok(st) => Ok(st.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("Failed to run podman: {}", e);
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_loopback_port_maps_to_the_same_number_inside() {
        assert_eq!(
            parse_host_loopback_ports("9222").unwrap(),
            vec![HostPort {
                host: 9222,
                sandbox: 9222
            }]
        );
    }

    #[test]
    fn host_loopback_ports_take_a_sandbox_side_remap_and_a_list() {
        // HOST:SANDBOX, in that order: the host's port is the one the operator
        // already knows, and the sandbox side is what moves to avoid a clash.
        assert_eq!(
            parse_host_loopback_ports("9222:19222,5432").unwrap(),
            vec![
                HostPort {
                    host: 9222,
                    sandbox: 19222
                },
                HostPort {
                    host: 5432,
                    sandbox: 5432
                }
            ]
        );
    }

    fn browser(name: &str, cdp_port: u16) -> ctl::browser::Instance {
        ctl::browser::Instance {
            dir: format!("/run/user/1000/agent-sandbox-browser-{name}"),
            name: name.to_string(),
            cdp_port,
            pid: 1,
        }
    }

    #[test]
    fn attaching_a_browser_maps_its_cdp_port_straight_through() {
        let mut ports = Vec::new();
        assert_eq!(
            attach_browsers(&[browser("alice", 9222), browser("bob", 9223)], &mut ports),
            vec![("alice".to_string(), 9222), ("bob".to_string(), 9223)]
        );
        assert_eq!(
            ports,
            vec![
                HostPort {
                    host: 9222,
                    sandbox: 9222
                },
                HostPort {
                    host: 9223,
                    sandbox: 9223
                }
            ]
        );
    }

    /// The pair has to agree: whatever number the mapping puts the browser on
    /// inside is the number the agent is told to dial.  Advertising the host's
    /// 9222 while the listener is on 19222 points a CDP client at nothing.
    #[test]
    fn an_explicit_remap_wins_and_is_what_gets_advertised() {
        let mut ports = vec![HostPort {
            host: 9222,
            sandbox: 19222,
        }];
        assert_eq!(
            attach_browsers(&[browser("alice", 9222)], &mut ports),
            vec![("alice".to_string(), 19222)]
        );
        assert_eq!(
            ports,
            vec![HostPort {
                host: 9222,
                sandbox: 19222
            }],
            "a second mapping for the same host port would be a duplicate"
        );
    }

    /// Refused rather than silently dropped: an unmapped port is indisting-
    /// uishable from a service that is down once an agent is inside.
    #[test]
    fn host_loopback_ports_refuse_what_is_not_a_port() {
        for spec in ["0", "70000", "http", "9222:", "", "9222,,5432", "-1"] {
            assert!(
                parse_host_loopback_ports(spec).is_err(),
                "{:?} should not parse",
                spec
            );
        }
    }

    /// The channel itself, end to end: a listener standing in for the host's
    /// service, the socket the sandbox would have mounted, and a full-duplex
    /// exchange over it.  Worth a real socket rather than a mock, since what is
    /// being claimed is that a mount reaches the host where a route cannot.
    #[test]
    fn a_host_port_socket_carries_traffic_both_ways() {
        use std::io::{Read, Write};

        let host = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let host_port = host.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut conn, _) = host.accept().unwrap();
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping\n");
            conn.write_all(b"pong\n").unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        serve_host_port(&socket, host_port).unwrap();

        let mut client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        client.write_all(b"ping\n").unwrap();
        let mut got = String::new();
        client.read_to_string(&mut got).unwrap();
        assert_eq!(got, "pong\n");
    }

    #[test]
    fn expand_v_roots_relative_paths_in_the_workspace() {
        let cwd = Path::new("/home/ada/repo");
        assert_eq!(
            expand_v("data:/workspace/data", cwd, "/home/ada"),
            "/home/ada/repo/data:/workspace/data"
        );
        assert_eq!(
            expand_v("cache:tmp:ro", cwd, "/home/ada"),
            "/home/ada/repo/cache:/workspace/tmp:ro"
        );
        assert_eq!(
            expand_v("~/.cache/x:/cache", cwd, "/home/ada"),
            "/home/ada/.cache/x:/cache"
        );
        assert_eq!(
            expand_v("/etc/hosts", cwd, "/home/ada"),
            "/etc/hosts:/etc/hosts"
        );
    }

    #[test]
    fn selinux_relabeling_follows_the_flag() {
        assert_eq!(enforce_selinux_mount_flags("/a:/b", true), "/a:/b:Z");
        assert_eq!(enforce_selinux_mount_flags("/a:/b:ro", true), "/a:/b:ro,Z");
        assert_eq!(enforce_selinux_mount_flags("/a:/b:ro", false), "/a:/b:ro");
        assert_eq!(enforce_selinux_mount_flags("/a:/b:ro,z", false), "/a:/b:ro");
        // Already labeled: not labeled twice.
        assert_eq!(
            enforce_selinux_mount_flags("/a:/b:rw,Z", true),
            "/a:/b:rw,Z"
        );
    }

    #[test]
    fn proxy_log_levels() {
        assert_eq!(parse_proxy_log_level("off"), Some(ProxyLogLevel::Off));
        assert_eq!(parse_proxy_log_level("denied"), Some(ProxyLogLevel::Denied));
        assert_eq!(parse_proxy_log_level("all"), Some(ProxyLogLevel::All));
        // Refused rather than silently treated as a default: the level decides
        // whether the record of a denied session survives.
        assert_eq!(parse_proxy_log_level("ALL"), None);
        assert_eq!(parse_proxy_log_level("yes"), None);
        assert_eq!(parse_proxy_log_level(""), None);
    }

    /// The saved name has to survive several sandboxes writing into one
    /// directory, so it carries the session word.
    #[test]
    fn saved_log_name_carries_the_session() {
        let mut guard = CleanupGuard::new();
        guard.session_word = "teapot".to_string();
        let name = guard.log_file_name();
        assert!(
            name.starts_with("agent-sandbox-connections-teapot-"),
            "{}",
            name
        );
        assert!(name.ends_with(".jsonl"), "{}", name);

        // A guard that never got a word still produces a usable name.
        assert!(CleanupGuard::new()
            .log_file_name()
            .starts_with("agent-sandbox-connections-session-"));
    }
}
