#![forbid(unsafe_code)]

use agent_sandbox_proxy::policy::parse_ip_target;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Child, Command};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

const POLICY_FILE: &str = "/sidecar_policy/policy";
/// The host keys trusted.toml authorized, written by the launcher beside the
/// policy.  Absent when it authorized none.
const KNOWN_HOSTS_FILE: &str = "/sidecar_policy/known_hosts";
const SECRET_BINDINGS_FILE: &str = "/sidecar_secrets/bindings";
const METRICS_LOG: &str = "/sidecar_shared/connections.jsonl";
const DETAIL_LOG: &str = "/sidecar_shared/denied-requests.jsonl";
const EXEMPT_PROTO: &str = "200";
const RESOLV_CONF: &str = "/etc/resolv.conf";

struct Config {
    dry_run: bool,
    policy_file: String,
    resolv_conf: String,
    metrics_log: String,
}

impl Config {
    fn new() -> Self {
        let dry_run = env::var("AGENT_SANDBOX_SIDECAR_DRY_RUN").unwrap_or_default() == "1";
        let policy_file = if dry_run {
            env::var("AGENT_SANDBOX_SIDECAR_POLICY").unwrap_or_else(|_| POLICY_FILE.to_string())
        } else {
            POLICY_FILE.to_string()
        };
        let resolv_conf = if dry_run {
            env::var("AGENT_SANDBOX_SIDECAR_RESOLV_CONF")
                .unwrap_or_else(|_| RESOLV_CONF.to_string())
        } else {
            RESOLV_CONF.to_string()
        };
        let metrics_log = if dry_run {
            "/dev/null".to_string()
        } else {
            METRICS_LOG.to_string()
        };

        Self {
            dry_run,
            policy_file,
            resolv_conf,
            metrics_log,
        }
    }

    fn run_ip(&self, args: &[&str]) -> Result<()> {
        if self.dry_run {
            println!("ip {}", args.join(" "));
            return Ok(());
        }
        let status = Command::new("ip").args(args).status()?;
        if !status.success() {
            anyhow::bail!("ip command failed");
        }
        Ok(())
    }
}

fn policy_values(file: &str, key_filter: &str) -> Vec<String> {
    let mut values = Vec::new();
    if let Ok(contents) = fs::read_to_string(file) {
        for line in contents.lines() {
            let mut parts = line.split_whitespace();
            if let Some(key) = parts.next() {
                if key == key_filter {
                    if let Some(val) = parts.next() {
                        values.push(val.to_string());
                    }
                }
            }
        }
    }
    values
}

fn resolv_nameservers(file: &str) -> Vec<String> {
    let mut ns = Vec::new();
    if let Ok(contents) = fs::read_to_string(file) {
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with("nameserver ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    ns.push(parts[1].to_string());
                }
            }
        }
    }
    ns
}

/// Normalise a policy value to the prefix `ip route` wants, or `None` if it is
/// not routable (unparseable, or a default route we must not touch).
///
/// Parsing rather than string-slicing is the point: since per-target ports
/// landed, an `allow_ip` value carries a `:port` suffix, and the documented
/// `allow = ["10.0.0.0/8:80"]` reached `ip` verbatim.  That failed on every
/// reconcile pass *and* left the baseline blackhole for the range installed,
/// so the re-allowed range was permitted by the proxy and then dropped on the
/// floor by the routing table -- the exact failure the exemptions exist to
/// prevent.  Truncating to the network also matches what the proxy enforces:
/// `IpNet::contains` masks the address, so `10.1.2.3/8` is the `10.0.0.0/8`
/// rule there and must be that route here.
fn route_prefix(entry: &str) -> Option<String> {
    let net = parse_ip_target(entry).ok()?.target.trunc();
    if net.prefix_len() == 0 {
        return None; // a default route is the gateway's, not ours to install
    }
    let text = net.to_string();
    // A host route is printed by `ip route show` without its prefix length, so
    // strip it here or the reconcile never matches.  Only /32 on v4 and /128 on
    // v6: `2001:db8::/32` is a network, not a host.
    let bare = if text.contains(':') {
        text.strip_suffix("/128")
    } else {
        text.strip_suffix("/32")
    };
    Some(bare.unwrap_or(&text).to_string())
}

fn want_exemptions(config: &Config) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    let mut entries = policy_values(&config.policy_file, "allow_ip");
    entries.extend(resolv_nameservers(&config.resolv_conf));

    for entry in entries {
        let Some(prefix) = route_prefix(&entry) else {
            continue;
        };
        if seen.insert(prefix.clone()) {
            result.push(prefix);
        }
    }
    result
}

fn want_blackholes(config: &Config) -> Vec<String> {
    let exempt = want_exemptions(config);
    let exempt_set: HashSet<String> = exempt.into_iter().collect();
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    let entries = policy_values(&config.policy_file, "deny_ip");
    for entry in entries {
        let Some(prefix) = route_prefix(&entry) else {
            continue;
        };
        if !exempt_set.contains(&prefix) && seen.insert(prefix.clone()) {
            result.push(prefix);
        }
    }
    result
}

fn installed_exemptions(config: &Config) -> Vec<String> {
    if config.dry_run {
        return Vec::new();
    }
    let mut result = Vec::new();
    if let Ok(output) = Command::new("ip")
        .args(["-o", "route", "show", "proto", EXEMPT_PROTO])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                result.push(parts[0].to_string());
            }
        }
    }
    result
}

fn installed_blackholes(config: &Config) -> Vec<String> {
    if config.dry_run {
        return Vec::new();
    }
    let mut result = Vec::new();
    if let Ok(output) = Command::new("ip")
        .args(["-o", "route", "show", "type", "blackhole"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                result.push(parts[1].to_string());
            }
        }
    }
    result
}

fn default_gateway(config: &Config, family: &str) -> Option<(String, String)> {
    if config.dry_run {
        return Some(("10.88.0.1".to_string(), "eth0".to_string()));
    }
    if let Ok(output) = Command::new("ip")
        .args(["-o", family, "route", "show", "default"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let mut via = None;
            let mut dev = None;
            for i in 0..parts.len() {
                if parts[i] == "via" && i + 1 < parts.len() {
                    via = Some(parts[i + 1].to_string());
                }
                if parts[i] == "dev" && i + 1 < parts.len() {
                    dev = Some(parts[i + 1].to_string());
                }
            }
            if let (Some(v), Some(d)) = (via, dev) {
                return Some((v, d));
            }
        }
    }
    None
}

fn sync_routes(config: &Config) {
    let want_ex = want_exemptions(config);
    let have_ex = installed_exemptions(config);
    let want_ex_set: HashSet<_> = want_ex.iter().cloned().collect();
    let have_ex_set: HashSet<_> = have_ex.iter().cloned().collect();

    for entry in &want_ex {
        if have_ex_set.contains(entry) {
            continue;
        }
        let family = if entry.contains(':') { "-6" } else { "-4" };
        if let Some((via, dev)) = default_gateway(config, family) {
            let args = vec![
                "route",
                "add",
                entry,
                "via",
                &via,
                "dev",
                &dev,
                "proto",
                EXEMPT_PROTO,
            ];
            if config.run_ip(&args).is_err() {
                eprintln!("sidecar: cannot exempt {}", entry);
            }
        } else {
            eprintln!("sidecar: no default route to exempt {} through", entry);
        }
    }

    for entry in &have_ex {
        if want_ex_set.contains(entry) {
            continue;
        }
        let args = vec!["route", "del", entry, "proto", EXEMPT_PROTO];
        if config.run_ip(&args).is_err() {
            eprintln!("sidecar: cannot un-exempt {}", entry);
        }
    }

    let want_bh = want_blackholes(config);
    let have_bh = installed_blackholes(config);
    let want_bh_set: HashSet<_> = want_bh.iter().cloned().collect();
    let have_bh_set: HashSet<_> = have_bh.iter().cloned().collect();

    for entry in &want_bh {
        if have_bh_set.contains(entry) {
            continue;
        }
        let args = vec!["route", "add", "blackhole", entry];
        if config.run_ip(&args).is_err() {
            eprintln!("sidecar: cannot blackhole {}", entry);
        }
    }

    for entry in &have_bh {
        if want_bh_set.contains(entry) {
            continue;
        }
        let args = vec!["route", "del", "blackhole", entry];
        if config.run_ip(&args).is_err() {
            eprintln!("sidecar: cannot un-blackhole {}", entry);
        }
    }
}

fn contains(subnet_cidr: &str, ip_cidr: &str) -> bool {
    let parse_cidr = |cidr: &str| -> Option<(IpAddr, u8)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        let ip = IpAddr::from_str(parts[0]).ok()?;
        let len = parts[1].parse::<u8>().ok()?;
        Some((ip, len))
    };

    let (sub_ip, sub_len) = match parse_cidr(subnet_cidr) {
        Some(s) => s,
        None => return false,
    };

    let ip_str = if ip_cidr.contains('/') {
        ip_cidr.split('/').next().unwrap()
    } else {
        ip_cidr
    };
    let ip = match IpAddr::from_str(ip_str) {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match (sub_ip, ip) {
        (IpAddr::V4(sub), IpAddr::V4(ip)) => {
            let mask = if sub_len == 0 {
                0
            } else {
                (!0u32) << (32 - sub_len)
            };
            (u32::from(sub) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(sub), IpAddr::V6(ip)) => {
            let mask = if sub_len == 0 {
                0
            } else {
                (!0u128) << (128 - sub_len)
            };
            (u128::from(sub) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
}

fn get_sidecar_listen() -> Result<String> {
    let subnet = env::var("SIDECAR_SUBNET")
        .context("SIDECAR_SUBNET is not set; refusing to bind on all interfaces")?;

    let output = Command::new("ip")
        .args(["-o", "-4", "addr", "show", "scope", "global"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let ip_cidr = parts[3];
            if contains(&subnet, ip_cidr) {
                return Ok(ip_cidr.split('/').next().unwrap().to_string());
            }
        }
    }
    anyhow::bail!("no local address falls inside {}", subnet);
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn main() -> Result<()> {
    let config = Config::new();

    if !Path::new(&config.policy_file).exists() {
        eprintln!("sidecar: {} is missing", config.policy_file);
        std::process::exit(1);
    }

    let mut proxy_args = vec![
        "--log".to_string(),
        config.metrics_log.clone(),
        "--detail-log".to_string(),
        if config.dry_run {
            "/dev/null".to_string()
        } else {
            DETAIL_LOG.to_string()
        },
        "--policy".to_string(),
        config.policy_file.clone(),
    ];

    if Path::new(SECRET_BINDINGS_FILE).exists() {
        proxy_args.push("--secret-fd".to_string());
        proxy_args.push("3".to_string());
    }

    let mut sidecar_listen = String::new();
    if !config.dry_run {
        match get_sidecar_listen() {
            Ok(listen) => sidecar_listen = listen,
            Err(e) => {
                eprintln!("sidecar: {}", e);
                std::process::exit(1);
            }
        }
        proxy_args.push("--listen".to_string());
        proxy_args.push(format!("{}:8888", sidecar_listen));
        // The sandbox's /etc/hosts resolves every allowed name to this address,
        // so a client that ignores HTTPS_PROXY -- nix's libgit2 is the one that
        // cannot be configured otherwise -- still arrives at the proxy.
        proxy_args.push("--transparent".to_string());
    }

    if config.dry_run {
        println!("agent-sandbox-proxy {}", proxy_args.join(" "));
        sync_routes(&config);
        return Ok(());
    }

    let mut proxy_cmd = if Path::new(SECRET_BINDINGS_FILE).exists() {
        let mut cmd = Command::new("bash");
        cmd.arg("-c");
        cmd.arg(format!(
            "exec 3<'{}'; exec agent-sandbox-proxy \"$@\"",
            SECRET_BINDINGS_FILE
        ));
        cmd.arg("--"); // $0 for bash
        cmd
    } else {
        Command::new("agent-sandbox-proxy")
    };
    proxy_cmd.args(&proxy_args);

    let proxy_child = proxy_cmd.spawn().context("failed to spawn proxy")?;
    let mut proxy_child = ChildGuard(proxy_child);

    if Path::new("/run/host-ssh-agent").exists() || Path::new("/run/host-gpg-agent").exists() {
        Command::new("relay-server")
            .args([
                "--listen",
                &format!("{}:8889", sidecar_listen),
                "--policy",
                &config.policy_file,
                "--known-hosts",
                KNOWN_HOSTS_FILE,
            ])
            .spawn()
            .ok();
    }

    let mut ready = false;
    for _ in 0..350 {
        if Path::new("/sidecar_shared/proxy-ready").exists() {
            ready = true;
            break;
        }
        if let Ok(Some(_)) = proxy_child.0.try_wait() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    if let Ok(Some(status)) = proxy_child.0.try_wait() {
        eprintln!("sidecar: the proxy exited before signalling readiness");
        std::process::exit(status.code().unwrap_or(1));
    }
    if !ready {
        eprintln!("sidecar: the proxy exited before signalling readiness");
        std::process::exit(1);
    }

    sync_routes(&config);

    fs::write("/sidecar_shared/ready", "ready\n").context("failed to write ready file")?;

    while matches!(proxy_child.0.try_wait(), Ok(None)) {
        thread::sleep(Duration::from_secs(1));
        sync_routes(&config);
    }

    let status = proxy_child.0.wait()?;
    std::process::exit(status.code().unwrap_or(0));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn config_for(policy: &str, resolv: &str) -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_file = dir.path().join("policy");
        let resolv_conf = dir.path().join("resolv.conf");
        write!(fs::File::create(&policy_file).expect("policy"), "{}", policy).expect("write");
        write!(fs::File::create(&resolv_conf).expect("resolv"), "{}", resolv).expect("write");
        (
            Config {
                dry_run: true,
                policy_file: policy_file.to_string_lossy().into_owned(),
                resolv_conf: resolv_conf.to_string_lossy().into_owned(),
                metrics_log: "/dev/null".to_string(),
            },
            dir,
        )
    }

    #[test]
    fn route_prefix_strips_the_port_qualifier() {
        // The documented `allow = ["10.0.0.0/8:80"]` used to reach `ip` verbatim.
        assert_eq!(route_prefix("10.0.0.0/8:80").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(route_prefix("10.0.0.0/8").as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn route_prefix_strips_only_a_real_host_route() {
        assert_eq!(route_prefix("1.2.3.4").as_deref(), Some("1.2.3.4"));
        assert_eq!(route_prefix("1.2.3.4/32").as_deref(), Some("1.2.3.4"));
        assert_eq!(route_prefix("::1").as_deref(), Some("::1"));
        // /32 on v6 is a network, not a host: it must keep its prefix length.
        assert_eq!(route_prefix("2001:db8::/32").as_deref(), Some("2001:db8::/32"));
    }

    #[test]
    fn route_prefix_truncates_to_the_network_the_proxy_enforces() {
        assert_eq!(route_prefix("10.1.2.3/8").as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn route_prefix_rejects_defaults_and_junk() {
        assert_eq!(route_prefix("0.0.0.0/0"), None);
        assert_eq!(route_prefix("::/0"), None);
        assert_eq!(route_prefix("not-an-ip"), None);
    }

    #[test]
    fn a_port_qualified_allow_exempts_the_range_from_its_blackhole() {
        // Regression: the exemption carried the ":80", never matched the
        // baseline deny, and the blackhole stayed installed -- so the range was
        // allowed by the proxy and unreachable by the route.
        let (config, _dir) = config_for(
            "allow_ip 10.0.0.0/8:80\ndeny_ip 10.0.0.0/8\ndeny_ip 192.168.0.0/16\n",
            "nameserver 192.168.1.1\n",
        );
        assert!(want_exemptions(&config).contains(&"10.0.0.0/8".to_string()));
        assert!(
            !want_blackholes(&config).contains(&"10.0.0.0/8".to_string()),
            "an exempted range must not also be blackholed"
        );
        // The unrelated baseline range is still blackholed...
        let blackholes = want_blackholes(&config);
        assert!(blackholes.contains(&"192.168.0.0/16".to_string()));
    }

    #[test]
    fn the_resolver_is_exempt_whatever_the_policy_says() {
        let (config, _dir) = config_for(
            "deny_ip 192.168.0.0/16\n",
            "nameserver 192.168.1.1\nsearch example.com\n",
        );
        assert!(want_exemptions(&config).contains(&"192.168.1.1".to_string()));
        // The /16 is still blackholed; only the resolver's own /32 is exempt.
        assert!(want_blackholes(&config).contains(&"192.168.0.0/16".to_string()));
    }
}
