#![forbid(unsafe_code)]

//! Forward proxy for the agent-sandbox sidecar.
//!
//! Usage: agent-sandbox-proxy [--policy FILE] [--log FILE] [--listen ADDR]
//!                            [--allow-domains LIST] [--deny-domains LIST]
//!                            [--allow-ips LIST] [--deny-ips LIST]
//!                            [--allow-ports LIST] [--check-policy FILE]
//!
//! Policy comes from a file (one `KEY VALUE` per line, see `parse_policy`) or
//! from the inline lists, never both.  Anything wrong with it exits 2 before the
//! listener binds, so a policy the operator got wrong cannot degrade into a
//! weaker one that appears to work.
//!
//! `--log` appends newline-delimited JSON, one object per connection event,
//! rendered by agent-sandbox-network-summary.

use ipnet::IpNet;
use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Read timeout on proxied sockets.  This is only a liveness tick so a blocked
/// read can be retried, *not* an idle cap: a stream that goes quiet for longer
/// (a streaming completion waiting on the model, a slow git server) must not be
/// severed.  See `pump`.
const IO_TICK: Duration = Duration::from_secs(300);
/// A client that opens a connection and never sends a request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TTL: Duration = Duration::from_secs(60);
/// Retry floor applied to *every* resolve and connect.  The sidecar's network
/// can wobble well after the proxy binds, so this must not be scoped to
/// startup: doing that turned a transient blip into a hard 502 and made
/// launches flicker.  Successful lookups are cached for `DNS_TTL`, so a host
/// pays this at most once a minute.
const RETRY_WINDOW: Duration = Duration::from_millis(1000);
/// How long after process start the resolve/connect paths keep retrying, on
/// top of `RETRY_WINDOW`.
const STARTUP_GRACE: Duration = Duration::from_secs(10);
/// How long `wait_for_egress` blocks before giving up and starting anyway.
const READY_TIMEOUT: Duration = Duration::from_secs(30);
/// Name resolved to decide the sidecar's network is actually usable.  Only
/// resolved, never connected to, so this stays policy-neutral under
/// `--proxy`.
const READY_PROBE_HOST: &str = "cloudflare.com:443";
/// Written by the proxy, read by the sidecar's readiness gate on the host.
const PROXY_READY: &str = "/sidecar_shared/proxy-ready";
/// Written only when `wait_for_egress` gives up, and carrying why.
const EGRESS_DEGRADED: &str = "/sidecar_shared/egress-degraded";
const BUF_SIZE: usize = 64 * 1024;
const HEAD_MAX: usize = 8192;
const DNS_CACHE_MAX: usize = 512;
/// How often the policy file is checked for changes.
const POLICY_POLL: Duration = Duration::from_secs(1);

// ── Policy ──────────────────────────────────────────────────────────────────

/// A single port, or an inclusive range (`8000-8100`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// Applied when a policy is deny-by-default and does not name `allow_ports`
/// itself: enough for the common case (web + git-over-ssh) without silently
/// widening a policy the operator did not ask to widen.
const DEFAULT_ALLOW_PORTS: [PortRange; 3] = [
    PortRange { start: 80, end: 80 },
    PortRange {
        start: 443,
        end: 443,
    },
    PortRange { start: 22, end: 22 },
];

/// `default_allow` is derived, never supplied: an allow list makes the policy
/// deny-by-default, deny lists alone leave it allow-by-default.  Constructing
/// this struct only through `new`/`parse_policy` is what stops a caller (in
/// particular a reload) from recomputing the lists and forgetting the mode.
#[derive(Debug)]
struct ProxyConfig {
    allow_domains: Vec<String>,
    deny_domains: Vec<String>,
    allow_ips: Vec<IpNet>,
    deny_ips: Vec<IpNet>,
    default_allow: bool,
    /// `None` means unrestricted; `Some(_)` (possibly derived) restricts to
    /// those ranges.  Kept distinct from an empty `Vec` so "not specified" and
    /// "specified as nothing" cannot be confused.
    allow_ports: Option<Vec<PortRange>>,
}

impl ProxyConfig {
    fn new(
        allow_domains: Vec<String>,
        deny_domains: Vec<String>,
        allow_ips: Vec<IpNet>,
        deny_ips: Vec<IpNet>,
        allow_ports_override: Option<Vec<PortRange>>,
        default_override: Option<bool>,
    ) -> ProxyConfig {
        let default_allow = default_override
            .unwrap_or_else(|| allow_domains.is_empty() && allow_ips.is_empty());
        // Mirrors default_allow's own derivation: an explicit value always
        // wins, and otherwise the *mode* decides -- a deny-by-default policy
        // gets a sane default rather than staying wide open on every port.
        let allow_ports = match allow_ports_override {
            Some(v) => Some(v),
            None if default_allow => None,
            None => Some(DEFAULT_ALLOW_PORTS.to_vec()),
        };
        ProxyConfig {
            allow_domains,
            deny_domains,
            allow_ips,
            deny_ips,
            default_allow,
            allow_ports,
        }
    }

    /// One line per rule, for the startup log and for `--check-policy`.
    fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        for d in &self.allow_domains {
            out.push(format!("allow_domains {}", d));
        }
        for d in &self.deny_domains {
            out.push(format!("deny_domains {}", d));
        }
        for n in &self.allow_ips {
            out.push(format!("allow_ips {}", n));
        }
        for n in &self.deny_ips {
            out.push(format!("deny_ips {}", n));
        }
        if let Some(ranges) = &self.allow_ports {
            for r in ranges {
                out.push(format!("allow_ports {}", r));
            }
        }
        out.push(format!(
            "default {}",
            if self.default_allow { "allow" } else { "deny" }
        ));
        out
    }
}

/// Split on commas *and* whitespace.  Only commas are produced by anything that
/// calls this, but a space-separated list used to arrive here and collapse into
/// one unparseable token, silently emptying the list -- and an empty allow list
/// means allow-everything.  Accepting both costs nothing and removes the trap.
fn split_list(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
}

fn parse_csv(s: &str) -> Vec<String> {
    split_list(s).map(|s| s.to_ascii_lowercase()).collect()
}

/// Accept both a CIDR block and a bare address, the latter as a host route.
///
/// `IpNet` alone rejects "8.8.8.8" for want of a prefix, while the AGENTS.md
/// parser accepts it (Python's ip_network treats it as /32).  That disagreement
/// used to be invisible, because unparseable entries were dropped rather than
/// reported: a deny_ips entry written as a bare address silently did nothing.
///
/// Deliberate limitation: this does not fold an IPv4-mapped V6 CIDR (e.g.
/// `::ffff:10.0.0.0/104`) down to a V4 range -- doing so would mean remapping
/// the prefix length across families.  `normalize_host` folds the *request*
/// side instead, which is enough to match a v4-mapped literal against a plain
/// V4 policy entry; nothing in this codebase writes the mapped form as a
/// policy entry itself.
fn parse_net(s: &str) -> Result<IpNet, String> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    match s.parse::<IpAddr>() {
        Ok(ip) => Ok(IpNet::from(ip)),
        Err(e) => Err(format!(
            "{:?} is not an IP address or CIDR block: {}",
            s, e
        )),
    }
}

/// Unparseable entries are an error, never a silent omission: dropping one turns
/// a policy the operator wrote into a weaker one nobody asked for.
fn parse_csv_ips(s: &str) -> Result<Vec<IpNet>, String> {
    split_list(s).map(parse_net).collect()
}

/// Accept a single port (`443`) or an inclusive range (`8000-8100`).
fn parse_port_range(s: &str) -> Result<PortRange, String> {
    let (start, end) = match s.split_once('-') {
        Some((a, b)) => (a, b),
        None => (s, s),
    };
    let parse_one = |p: &str| -> Result<u16, String> {
        p.parse::<u16>()
            .ok()
            .filter(|&n| n != 0)
            .ok_or_else(|| format!("{:?} is not a port in 1-65535", p))
    };
    let start = parse_one(start)?;
    let end = parse_one(end)?;
    if start > end {
        return Err(format!("{:?} has start > end", s));
    }
    Ok(PortRange { start, end })
}

/// Unparseable entries are an error, for the same reason as `parse_csv_ips`.
fn parse_csv_ports(s: &str) -> Result<Vec<PortRange>, String> {
    split_list(s).map(parse_port_range).collect()
}

/// Parse the policy file written by the launcher (and edited by
/// `agent-sandbox-ctl proxy`).
///
/// One `KEY VALUE` pair per line, `#` comments and blank lines ignored:
///
/// ```text
/// allow_domains github.com
/// allow_ips 10.0.0.0/8
/// default deny
/// ```
///
/// A value containing whitespace is rejected rather than split.  That is the
/// whole point of the format: the previous wire format packed a list into one
/// space-separated argument, and every consumer disagreed about how to take it
/// apart.  Rejecting the shape means the old encoding cannot silently reappear.
fn parse_policy(text: &str) -> Result<ProxyConfig, String> {
    let mut allow_domains = Vec::new();
    let mut deny_domains = Vec::new();
    let mut allow_ips = Vec::new();
    let mut deny_ips = Vec::new();
    let mut allow_ports_override: Option<Vec<PortRange>> = None;
    let mut default_override = None;

    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lineno = i + 1;
        let (key, value) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| format!("{}: {:?} is not KEY VALUE", lineno, line))?;
        let value = value.trim();
        if value.is_empty() {
            return Err(format!("{}: {} has no value", lineno, key));
        }
        if value.split_whitespace().count() > 1 {
            return Err(format!(
                "{}: {}: {:?} contains whitespace; write one entry per line",
                lineno, key, value
            ));
        }

        match key {
            "allow_domains" => allow_domains.push(value.to_ascii_lowercase()),
            "deny_domains" => deny_domains.push(value.to_ascii_lowercase()),
            "allow_ips" => allow_ips
                .push(parse_net(value).map_err(|e| format!("{}: allow_ips: {}", lineno, e))?),
            "deny_ips" => deny_ips
                .push(parse_net(value).map_err(|e| format!("{}: deny_ips: {}", lineno, e))?),
            "allow_ports" => {
                let r = parse_port_range(value)
                    .map_err(|e| format!("{}: allow_ports: {}", lineno, e))?;
                allow_ports_override.get_or_insert_with(Vec::new).push(r);
            }
            "default" => {
                default_override = Some(match value {
                    "allow" => true,
                    "deny" => false,
                    other => {
                        return Err(format!(
                            "{}: default: expected 'allow' or 'deny', got {:?}",
                            lineno, other
                        ))
                    }
                })
            }
            other => return Err(format!("{}: unknown key {:?}", lineno, other)),
        }
    }

    Ok(ProxyConfig::new(
        allow_domains,
        deny_domains,
        allow_ips,
        deny_ips,
        allow_ports_override,
        default_override,
    ))
}

fn load_policy(path: &str) -> Result<ProxyConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read policy {}: {}", path, e))?;
    parse_policy(&text).map_err(|e| format!("{}:{}", path, e))
}

/// Fold an IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`,
/// excluding `::` and `::1`) IPv6 literal down to its V4 form, so it matches
/// the same `deny_ips`/`allow_ips` rules as the plain address would.  Anything
/// else is returned unchanged.
///
/// The compatible form is reconstructed from octets rather than the
/// deprecated `Ipv6Addr::to_ipv4()`, which also (mis)classifies `::`/`::1` as
/// address `0.0.0.0`/`0.0.0.1`.
fn fold_ipv6(ip: std::net::Ipv6Addr) -> IpAddr {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }
    let seg = ip.segments();
    if seg[0..6] == [0, 0, 0, 0, 0, 0] && (seg[6] != 0 || seg[7] > 1) {
        let o = ip.octets();
        return IpAddr::V4(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    IpAddr::V6(ip)
}

/// Normalise a request-line host before any policy match.  `host` is assumed
/// already ASCII-lowercased by the caller.  `None` means the host cannot mean
/// anything a policy could sanely list, and is treated as deny -- not a
/// distinct error path, so no future matcher has to remember to consult it.
///
/// Handles two evasions: a trailing-dot FQDN (`github.com.`, which resolvers
/// accept as identical to `github.com`) and an IPv4-mapped/compatible IPv6
/// literal (`[::ffff:10.0.0.1]`), both of which used to compare unequal to
/// the plain form a policy actually lists.
fn normalize_host(host: &str) -> Option<String> {
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return match inner.parse::<std::net::Ipv6Addr>() {
            Ok(ip) => Some(format!("[{}]", fold_ipv6(ip))),
            Err(_) => None,
        };
    }
    if let Ok(IpAddr::V6(ip)) = host.parse::<IpAddr>() {
        return Some(fold_ipv6(ip).to_string());
    }
    if host.parse::<IpAddr>().is_ok() {
        return Some(host.to_string());
    }

    // Domain name path.
    if host.starts_with('.') {
        return None;
    }
    let stripped = host.strip_suffix('.').unwrap_or(host);
    if stripped.is_empty() || stripped.contains("..") {
        return None;
    }
    // Matches parse_agents.py's DOMAIN_RE charset, including '_': some
    // internal hostnames legitimately use it, and excluding it here would
    // silently deny a name a policy already lists.
    if !stripped
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return None;
    }
    Some(stripped.to_string())
}

/// Both arguments must already be lowercase.
fn domain_match(domain: &str, pattern: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(base) => domain == base || domain.ends_with(&pattern[1..]),
        None => domain == pattern,
    }
}

impl ProxyConfig {
    /// More specific wins: the longest matching pattern decides.  On an exact
    /// tie between an allow and a deny rule, allow wins.
    fn is_allowed_domain(&self, domain: &str) -> bool {
        let mut best_len: i32 = -1;
        let mut allowed = self.default_allow;

        for p in &self.allow_domains {
            if domain_match(domain, p) && p.len() as i32 > best_len {
                best_len = p.len() as i32;
                allowed = true;
            }
        }

        for p in &self.deny_domains {
            if domain_match(domain, p) && p.len() as i32 > best_len {
                best_len = p.len() as i32;
                allowed = false;
            }
        }

        allowed
    }

    /// More specific wins: the longest matching CIDR prefix decides.
    fn is_allowed_ip(&self, ip: IpAddr) -> bool {
        let mut best_prefix: i32 = -1;
        let mut allowed = self.default_allow;

        for net in &self.allow_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                allowed = true;
            }
        }

        for net in &self.deny_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                allowed = false;
            }
        }

        allowed
    }

    /// Whether an address is explicitly denied.
    ///
    /// Deliberately *not* `!is_allowed_ip(ip)`: this runs on the addresses a
    /// hostname resolved to, after the name itself already passed policy, so
    /// the deny-by-default fallback must not apply — under an allow list of
    /// domains no address would ever be listed and every connection would be
    /// rejected.  Only an explicit `deny_ips` match counts, and a
    /// more-specific *or equally specific* `allow_ips` rule still overrides
    /// it — the `>=` below, not `>`, is what makes `allow_ips 10.0.0.0/8`
    /// actually override a baseline `deny_ips 10.0.0.0/8` at the same prefix,
    /// matching the tie-break `is_allowed_ip` already uses.
    fn is_denied_address(&self, ip: IpAddr) -> bool {
        let mut best_prefix: i32 = -1;
        let mut denied = false;

        for net in &self.deny_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                denied = true;
            }
        }

        for net in &self.allow_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) >= best_prefix {
                best_prefix = net.prefix_len() as i32;
                denied = false;
            }
        }

        denied
    }

    /// `host` is the literal target from the request line, already lowercased.
    fn is_allowed_target(&self, host: &str) -> bool {
        let host = match normalize_host(host) {
            Some(h) => h,
            None => return false,
        };
        match host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            Ok(ip) => self.is_allowed_ip(ip),
            Err(_) => self.is_allowed_domain(&host),
        }
    }

    fn is_allowed_port(&self, port: u16) -> bool {
        self.allow_ports
            .as_ref()
            .map_or(true, |ranges| ranges.iter().any(|r| r.contains(port)))
    }

    /// `host` is the literal target from the request line, already lowercased.
    ///
    /// `handle_client` calls `is_allowed_target`/`is_allowed_port` separately
    /// so it can log which one denied; this combinator is what the tests use.
    #[cfg_attr(not(test), allow(dead_code))]
    fn is_allowed(&self, host: &str, port: u16) -> bool {
        self.is_allowed_target(host) && self.is_allowed_port(port)
    }
}

// ── Name resolution ─────────────────────────────────────────────────────────

/// Agents reconnect to the same handful of hosts constantly, so a short-TTL
/// cache removes a resolver round trip from most connections.
struct Resolver {
    cache: Mutex<HashMap<String, (Vec<SocketAddr>, Instant)>>,
}

impl Resolver {
    fn new() -> Self {
        Resolver {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Drop every cached lookup.  Called on a policy change: cached *addresses*
    /// are checked against the current deny list, so a stale entry could carry a
    /// newly-denied address for up to DNS_TTL.  Costs one re-resolve per live
    /// host, which refills within a second.
    fn clear(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    /// Resolve, retrying until at least `RETRY_WINDOW` has elapsed (longer if
    /// `retry_until` extends past that).  Only successes are cached — caching a
    /// failure would pin an outage in place for `DNS_TTL`.
    fn resolve(
        &self,
        host: &str,
        port: u16,
        retry_until: Instant,
    ) -> Result<Vec<SocketAddr>, io::Error> {
        let key = format!("{}:{}", host, port);

        if let Ok(cache) = self.cache.lock() {
            if let Some((addrs, cached_at)) = cache.get(&key) {
                if cached_at.elapsed() < DNS_TTL {
                    return Ok(addrs.clone());
                }
            }
        }

        let deadline = (Instant::now() + RETRY_WINDOW).max(retry_until);
        let mut last_err;
        loop {
            match key.to_socket_addrs() {
                Ok(found) => {
                    let addrs: Vec<SocketAddr> = found.collect();
                    if !addrs.is_empty() {
                        if let Ok(mut cache) = self.cache.lock() {
                            if cache.len() >= DNS_CACHE_MAX {
                                cache.clear();
                            }
                            cache.insert(key, (addrs.clone(), Instant::now()));
                        }
                        return Ok(addrs);
                    }
                    last_err = io::Error::new(
                        ErrorKind::NotFound,
                        "resolver returned no addresses",
                    );
                }
                Err(e) => last_err = e,
            }
            if Instant::now() >= deadline {
                return Err(last_err);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

// ── Metering ────────────────────────────────────────────────────────────────

/// One JSON line per connection event, consumed by `agent-sandbox-network-summary`
/// to render the `--proxy` summary and the `agent-sandbox-ctl net` live
/// view.  Cheap enough to leave on: a few hundred bytes per connection, versus
/// the full-payload packet capture it replaces.
///
/// A connection that is allowed writes two lines: `"ev":"open"` when the tunnel
/// is established and `"ev":"close"` when it ends, correlated by `id`.  Without
/// the open line a long-lived tunnel is invisible for as long as it lives, which
/// is precisely the traffic worth watching.  Connections rejected before that
/// point write only their terminal line, with no `ev` and no `id`: they resolve
/// within milliseconds, so a paired open would double every error row without
/// adding anything.
struct MetricsLog {
    file: Mutex<File>,
    /// Process start, in epoch seconds.  Ids embed it so two proxies appending
    /// to the same log cannot mint colliding ids — a correlation id that
    /// silently aliases is worse than none.
    boot: u64,
    next_id: AtomicU64,
}

/// Trim the boilerplate std prepends to resolver errors so the summary stays
/// readable: "failed to lookup address information: Temporary failure in name
/// resolution" carries one useful clause.
fn short_err(e: &io::Error) -> String {
    let s = e.to_string();
    match s.split_once(": ") {
        Some((head, tail)) if head.starts_with("failed to lookup address information") => {
            tail.to_string()
        }
        _ => s,
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Whole seconds since the epoch, or 0 if the clock is before it.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl MetricsLog {
    fn open(path: &str) -> Option<Arc<MetricsLog>> {
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(f) => Some(Arc::new(MetricsLog {
                file: Mutex::new(f),
                boot: now_secs(),
                next_id: AtomicU64::new(1),
            })),
            Err(e) => {
                eprintln!("proxy: cannot open metrics log {}: {}", path, e);
                None
            }
        }
    }

    fn write_line(&self, line: &str) {
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(line.as_bytes());
        }
    }

    fn next_id(&self) -> String {
        format!("{}-{}", self.boot, self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Marks a policy change in the connection log, so `ctl net -f` shows it
    /// interleaved with the connections it affected.
    fn policy_event(&self) {
        self.write_line(&format!(
            "{{\"ev\":\"policy\",\"ts\":{}}}\n",
            now_secs()
        ));
    }

    /// A connection has been established and is now pumping bytes.
    fn open_event(&self, id: &str, host: &str, port: u16) {
        self.write_line(&format!(
            "{{\"ev\":\"open\",\"id\":\"{}\",\"ts\":{},\"host\":\"{}\",\"port\":{}}}\n",
            id,
            now_secs(),
            json_escape(host),
            port
        ));
    }

    /// A connection has reached a terminal state.  `id` is `Some` only for
    /// connections that announced themselves with `open_event`; with `None` the
    /// line is byte-for-byte what earlier versions wrote.
    fn record(
        &self,
        id: Option<&str>,
        host: &str,
        port: u16,
        verdict: &str,
        err: Option<&str>,
        up: u64,
        down: u64,
        ms: u128,
    ) {
        let mut line = String::new();
        if let Some(id) = id {
            line.push_str(&format!("{{\"ev\":\"close\",\"id\":\"{}\",", id));
        } else {
            line.push('{');
        }
        line.push_str(&format!(
            "\"ts\":{},\"host\":\"{}\",\"port\":{},\"verdict\":\"{}\",\"up\":{},\"down\":{},\"ms\":{}",
            now_secs(),
            json_escape(host),
            port,
            verdict,
            up,
            down,
            ms
        ));
        if let Some(e) = err {
            line.push_str(&format!(",\"err\":\"{}\"", e));
        }
        line.push_str("}\n");

        self.write_line(&line);
    }
}

// ── Connection handling ─────────────────────────────────────────────────────

struct Shared {
    /// `RwLock<Arc<_>>` rather than `RwLock<ProxyConfig>`: a handler clones the
    /// Arc and releases the lock immediately, instead of holding a read guard
    /// across `resolve`, which can block for `RETRY_WINDOW`.  Each connection
    /// then evaluates one immutable snapshot for its whole life, so a reload can
    /// never split a decision in half.
    config: RwLock<Arc<ProxyConfig>>,
    resolver: Resolver,
    metrics: Option<Arc<MetricsLog>>,
    /// Instant until which the resolve/connect paths keep retrying.
    startup_until: Instant,
}

impl Shared {
    /// A snapshot of the policy.  Poisoning is degraded into "use the value
    /// anyway" rather than a panic: a handler thread dying on a lock is a worse
    /// outcome than acting on a config someone else was mid-swap on.
    fn config(&self) -> Arc<ProxyConfig> {
        Arc::clone(&self.config.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Install a new policy.  The DNS cache goes with it: the name check runs
    /// before resolution so it is unaffected, but `is_denied_address` is
    /// evaluated against *cached* addresses, and a stale set would let a
    /// just-denied address through for up to DNS_TTL.
    fn replace_config(&self, config: ProxyConfig) {
        eprintln!("proxy: policy reloaded");
        for line in config.describe() {
            eprintln!("proxy:   {}", line);
        }
        if let Ok(mut slot) = self.config.write() {
            *slot = Arc::new(config);
        }
        self.resolver.clear();
        if let Some(m) = &self.metrics {
            m.policy_event();
        }
    }

    fn record(
        &self,
        id: Option<&str>,
        host: &str,
        port: u16,
        verdict: &str,
        err: Option<&str>,
        up: u64,
        down: u64,
        ms: u128,
    ) {
        if let Some(m) = &self.metrics {
            m.record(id, host, port, verdict, err, up, down, ms);
        }
    }

    /// Announce an established connection, returning the id to close it with.
    /// `None` when metering is off, which makes the close path a no-op too.
    fn open_event(&self, host: &str, port: u16) -> Option<String> {
        let m = self.metrics.as_ref()?;
        let id = m.next_id();
        m.open_event(&id, host, port);
        Some(id)
    }
}

/// Copy `src` into `dst` until either side is done, returning the byte count.
///
/// A read timeout means "nothing to say yet", not "hang up" — treating it as
/// fatal severs long-lived idle streams.  On a real end-of-stream the write
/// half of `dst` is shut down so the peer observes EOF immediately, rather
/// than the connection lingering until the opposite direction times out.
fn pump(mut src: TcpStream, mut dst: TcpStream) -> u64 {
    let mut buf = vec![0u8; BUF_SIZE];
    let mut total: u64 = 0;
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(ref e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    || e.kind() == ErrorKind::Interrupted =>
            {
                continue
            }
            Err(_) => break,
        }
    }
    let _ = dst.shutdown(Shutdown::Write);
    total
}

/// Read until the end of the HTTP request head.  A request line can be split
/// across TCP segments, so a single `read` is not enough to parse against.
fn read_head(sock: &mut TcpStream, buf: &mut [u8]) -> Option<usize> {
    let mut n = 0;
    loop {
        if n == buf.len() {
            return Some(n);
        }
        match sock.read(&mut buf[n..]) {
            Ok(0) => return if n > 0 { Some(n) } else { None },
            Ok(k) => {
                // Rescan only the new bytes plus the 3-byte overlap.
                let scan_from = n.saturating_sub(3);
                n += k;
                if buf[scan_from..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    return Some(n);
                }
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return if n > 0 { Some(n) } else { None },
        }
    }
}

/// Connect to the first address that answers, retrying for at least
/// `RETRY_WINDOW` so a momentarily unreachable network does not become a 502.
fn connect_any(addrs: &[SocketAddr], retry_until: Instant) -> Result<TcpStream, io::Error> {
    let deadline = (Instant::now() + RETRY_WINDOW).max(retry_until);
    let mut last_err =
        io::Error::new(ErrorKind::InvalidInput, "no addresses to connect to");
    loop {
        for addr in addrs {
            match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
                Ok(s) => return Ok(s),
                Err(e) => last_err = e,
            }
        }
        if Instant::now() >= deadline {
            return Err(last_err);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn handle_client(mut client_sock: TcpStream, shared: Arc<Shared>) {
    let started = Instant::now();
    let _ = client_sock.set_nodelay(true);
    let _ = client_sock.set_read_timeout(Some(HEAD_TIMEOUT));

    let mut req_buf = [0u8; HEAD_MAX];
    let n = match read_head(&mut client_sock, &mut req_buf) {
        Some(n) => n,
        None => return,
    };

    let req_str = String::from_utf8_lossy(&req_buf[..n]);
    let first_line = req_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 3 {
        let _ = client_sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    }

    let method = parts[0];
    let mut url = parts[1];

    let host;
    let port: u16;

    if method == "CONNECT" {
        if let Some((h, p)) = url.rsplit_once(':') {
            host = h.to_ascii_lowercase();
            port = p.parse().unwrap_or(443);
        } else {
            host = url.to_ascii_lowercase();
            port = 443;
        }
    } else {
        if let Some(idx) = url.find("://") {
            url = &url[idx + 3..];
        }
        let url_no_path = url.split('/').next().unwrap_or("");
        if let Some((h, p)) = url_no_path.rsplit_once(':') {
            host = h.to_ascii_lowercase();
            port = p.parse().unwrap_or(80);
        } else {
            host = url_no_path.to_ascii_lowercase();
            port = 80;
        }
    }

    if host.is_empty() {
        let _ = client_sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    }

    // One snapshot for this connection's lifetime.  Taken after the head is
    // parsed so a reload landing mid-handshake cannot make the name check and the
    // resolved-address check disagree.
    let cfg = shared.config();

    if !cfg.is_allowed_target(&host) {
        let _ = client_sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        eprintln!("proxy: deny {}:{}", host, port);
        shared.record(None, &host, port, "deny", None, 0, 0, started.elapsed().as_millis());
        return;
    }

    if !cfg.is_allowed_port(port) {
        let _ = client_sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        eprintln!(
            "proxy: deny {}:{} (port not in allow_ports; add `allow_ports {}`)",
            host, port, port
        );
        shared.record(
            None,
            &host,
            port,
            "deny",
            Some("port"),
            0,
            0,
            started.elapsed().as_millis(),
        );
        return;
    }

    let addrs = match shared.resolver.resolve(&host, port, shared.startup_until) {
        Ok(a) => a,
        Err(e) => {
            let _ = client_sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            eprintln!("proxy: dns failure {}:{}: {}", host, port, e);
            let detail = format!("dns: {}", short_err(&e));
            shared.record(
                None,
                &host,
                port,
                "error",
                Some(&detail),
                0,
                0,
                started.elapsed().as_millis(),
            );
            return;
        }
    };

    // The policy check above ran on the name.  Re-check what it actually
    // resolves to, so a denied address cannot be reached via an allowed (or
    // merely unlisted) hostname.
    if let Some(bad) = addrs.iter().find(|a| cfg.is_denied_address(a.ip())) {
        let _ = client_sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        eprintln!("proxy: deny {}:{} (resolves to denied address {})", host, port, bad.ip());
        shared.record(None, &host, port, "deny", Some("address"), 0, 0, started.elapsed().as_millis());
        return;
    }

    let mut remote_sock = match connect_any(&addrs, shared.startup_until) {
        Ok(s) => s,
        Err(e) => {
            let _ = client_sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            eprintln!("proxy: connect failure {}:{}: {}", host, port, e);
            let detail = format!("connect: {}", short_err(&e));
            shared.record(
                None,
                &host,
                port,
                "error",
                Some(&detail),
                0,
                0,
                started.elapsed().as_millis(),
            );
            return;
        }
    };

    // Without this both directions pay a Nagle/delayed-ACK stall on every
    // request/response turn: TLS handshakes, HTTP/2 frames, git negotiation.
    let _ = remote_sock.set_nodelay(true);
    let _ = remote_sock.set_read_timeout(Some(IO_TICK));
    let _ = client_sock.set_read_timeout(Some(IO_TICK));

    // Bytes forwarded before the pumps take over, so they still show up in the
    // metered "sent" total.
    let mut head_up: u64 = 0;

    if method == "CONNECT" {
        if client_sock
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }
        // Forward any data that arrived alongside the CONNECT head.
        if let Some(pos) = req_buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            let extra = &req_buf[pos + 4..n];
            if !extra.is_empty() {
                if remote_sock.write_all(extra).is_err() {
                    return;
                }
                head_up += extra.len() as u64;
            }
        }
    } else {
        if remote_sock.write_all(&req_buf[..n]).is_err() {
            return;
        }
        head_up += n as u64;
    }

    let (client_read, remote_write) = match (client_sock.try_clone(), remote_sock.try_clone()) {
        (Ok(c), Ok(r)) => (c, r),
        _ => {
            eprintln!("proxy: cannot duplicate sockets for {}:{}", host, port);
            shared.record(None, &host, port, "error", Some("fd"), 0, 0, started.elapsed().as_millis());
            return;
        }
    };

    // Announced only once the connection can no longer fail synchronously, so
    // every open is followed by exactly one close.
    let id = shared.open_event(&host, port);

    // One direction inline: two threads per connection instead of three.
    let upstream = thread::spawn(move || pump(client_read, remote_write));
    let down = pump(remote_sock, client_sock);
    let up = head_up + upstream.join().unwrap_or(0);

    shared.record(
        id.as_deref(),
        &host,
        port,
        "allow",
        None,
        up,
        down,
        started.elapsed().as_millis(),
    );
}

/// Identity of a policy file, for change detection.
///
/// Size as well as mtime, because a filesystem with one-second timestamps plus a
/// same-second rewrite could otherwise go unnoticed; `None` for absent, so a file
/// appearing or disappearing counts as a change too.
fn policy_stamp(path: &str) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// Apply the policy file once.  Returns whether the running policy changed.
///
/// A rejected or vanished policy keeps the one already in force: the alternative
/// is falling back to a config nobody wrote, which is how an empty allow list --
/// meaning allow everything -- would sneak in.
fn reload_once(path: &str, shared: &Shared) -> bool {
    if policy_stamp(path).is_none() {
        eprintln!(
            "proxy: policy {} is gone; keeping the policy already in force",
            path
        );
        return false;
    }
    match load_policy(path) {
        Ok(config) => {
            shared.replace_config(config);
            true
        }
        Err(e) => {
            eprintln!("proxy: policy rejected, keeping the previous one: {}", e);
            false
        }
    }
}

/// Reload the policy whenever the file changes.
///
/// Polling rather than inotify or a signal: `forbid(unsafe_code)` rules out a
/// hand-rolled handler, `signal_hook` would be the crate's only dependency, and
/// one `stat` a second is free.  A second is also below the threshold where a
/// human running `proxy allow` and immediately retrying would notice.
fn watch_policy(path: String, shared: Arc<Shared>) {
    let mut current = policy_stamp(&path);
    loop {
        thread::sleep(POLICY_POLL);
        let stamp = policy_stamp(&path);
        if stamp == current {
            continue;
        }
        current = stamp;
        reload_once(&path, &shared);
    }
}

/// Block until the sidecar's network can actually resolve a name.
///
/// Binding a listener proves nothing about egress: podman is still wiring up
/// the bridge and internal networks when the proxy starts, and signalling
/// readiness at bind time let the launcher start the agent against a proxy that
/// could not yet reach anything — an instant 502 on the agent's first request.
///
/// Resolution only, never a connection: a DNS query goes to the configured
/// resolver and reaches no third-party host, so this stays policy-neutral under
/// `--proxy`, where dialling out would be egress the allow list never
/// authorised.
///
/// Never fatal.  If egress does not come up we start anyway and say so, because
/// a degraded launch beats a hung one.
///
/// "Say so" used to mean stderr only, which the launcher does not read: the
/// session looked healthy until the agent's first request came back 502.  The
/// reason is now also left in `EGRESS_DEGRADED` for the launcher to surface on
/// the terminal the person is actually looking at.
fn wait_for_egress() {
    let started = Instant::now();
    let mut last_err = String::new();
    while started.elapsed() < READY_TIMEOUT {
        match READY_PROBE_HOST.to_socket_addrs() {
            Ok(mut addrs) => {
                if addrs.next().is_some() {
                    eprintln!("proxy: egress ready after {:?}", started.elapsed());
                    return;
                }
                last_err = "resolver returned no addresses".to_string();
            }
            Err(e) => last_err = short_err(&e),
        }
        thread::sleep(Duration::from_millis(100));
    }
    eprintln!(
        "proxy: WARNING egress not ready after {:?} ({}); starting anyway",
        started.elapsed(),
        last_err
    );
    if let Ok(mut f) = File::create(EGRESS_DEGRADED) {
        let _ = writeln!(
            f,
            "{} did not resolve within {:?}: {}",
            READY_PROBE_HOST, READY_TIMEOUT, last_err
        );
    }
}

const USAGE: &str = "\
Usage: agent-sandbox-proxy [OPTIONS]

  --policy FILE          read the policy from FILE (see parse_policy)
  --check-policy FILE    validate FILE, print the rules it yields, exit
  --log FILE             append one JSON line per connection event
  --listen ADDR          listen address (default 0.0.0.0:8888)
  --allow-domains LIST   comma-separated; mutually exclusive with --policy
  --deny-domains LIST
  --allow-ips LIST
  --deny-ips LIST
  --allow-ports LIST     ports and ranges, e.g. 443,8000-8100
";

/// Exit codes: 2 for anything wrong with the policy, so the sidecar and the
/// launcher can tell a bad policy from a failure to start.
fn fail(msg: &str) -> ! {
    eprintln!("proxy: {}", msg);
    std::process::exit(2);
}

struct Options {
    policy: String,
    log: String,
    listen: String,
    allow_domains: String,
    deny_domains: String,
    allow_ips: String,
    deny_ips: String,
    allow_ports: String,
}

fn parse_args(args: &[String]) -> (Options, Option<String>) {
    let mut o = Options {
        policy: String::new(),
        log: String::new(),
        listen: "0.0.0.0:8888".to_string(),
        allow_domains: String::new(),
        deny_domains: String::new(),
        allow_ips: String::new(),
        deny_ips: String::new(),
        allow_ports: String::new(),
    };
    let mut check = None;
    let mut i = 1;
    while i < args.len() {
        let flag = args[i].as_str();
        let mut value = || {
            i += 1;
            match args.get(i) {
                Some(v) => v.clone(),
                None => fail(&format!("{} needs a value", flag)),
            }
        };
        match flag {
            "--policy" => o.policy = value(),
            "--check-policy" => check = Some(value()),
            "--log" => o.log = value(),
            "--listen" => o.listen = value(),
            "--allow-domains" => o.allow_domains = value(),
            "--deny-domains" => o.deny_domains = value(),
            "--allow-ips" => o.allow_ips = value(),
            "--deny-ips" => o.deny_ips = value(),
            "--allow-ports" => o.allow_ports = value(),
            "-h" | "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            other => fail(&format!("unknown option {:?}\n{}", other, USAGE)),
        }
        i += 1;
    }
    (o, check)
}

/// Build the initial policy.  `--policy` and the inline lists are mutually
/// exclusive rather than one falling back to the other: a fallback means a failed
/// load can quietly become an empty policy, which is allow-everything.
fn initial_config(o: &Options) -> ProxyConfig {
    let inline = [
        &o.allow_domains,
        &o.deny_domains,
        &o.allow_ips,
        &o.deny_ips,
        &o.allow_ports,
    ]
    .iter()
    .any(|s| !s.is_empty());

    if !o.policy.is_empty() {
        if inline {
            fail("--policy and --allow-domains/--deny-domains/--allow-ips/--deny-ips/--allow-ports are mutually exclusive");
        }
        match load_policy(&o.policy) {
            Ok(c) => c,
            Err(e) => fail(&e),
        }
    } else {
        let allow_ips = match parse_csv_ips(&o.allow_ips) {
            Ok(v) => v,
            Err(e) => fail(&format!("--allow-ips: {}", e)),
        };
        let deny_ips = match parse_csv_ips(&o.deny_ips) {
            Ok(v) => v,
            Err(e) => fail(&format!("--deny-ips: {}", e)),
        };
        let allow_ports = if o.allow_ports.is_empty() {
            None
        } else {
            match parse_csv_ports(&o.allow_ports) {
                Ok(v) => Some(v),
                Err(e) => fail(&format!("--allow-ports: {}", e)),
            }
        };
        ProxyConfig::new(
            parse_csv(&o.allow_domains),
            parse_csv(&o.deny_domains),
            allow_ips,
            deny_ips,
            allow_ports,
            None,
        )
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (opts, check) = parse_args(&args);

    // Validation mode: the host runs this to vet a policy before installing it,
    // so an invalid policy can never reach a running proxy.
    if let Some(path) = check {
        match load_policy(&path) {
            Ok(config) => {
                for line in config.describe() {
                    println!("{}", line);
                }
                std::process::exit(0);
            }
            Err(e) => fail(&e),
        }
    }

    // Before anything observable: a policy the operator got wrong must stop the
    // proxy here, not produce a weaker policy that looks like it started fine.
    let config = initial_config(&opts);
    eprintln!("proxy: policy");
    for line in config.describe() {
        eprintln!("proxy:   {}", line);
    }

    let metrics = if opts.log.is_empty() {
        None
    } else {
        MetricsLog::open(&opts.log)
    };

    // Bind before probing egress so a port clash fails immediately rather than
    // after the readiness wait.
    let listener = match TcpListener::bind(&opts.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("proxy: cannot bind {}: {}", opts.listen, e);
            std::process::exit(1);
        }
    };

    wait_for_egress();

    // Started after the egress probe so the grace covers the window right after
    // readiness, which is when the agent's first requests land.
    let shared = Arc::new(Shared {
        config: RwLock::new(Arc::new(config)),
        resolver: Resolver::new(),
        metrics,
        startup_until: Instant::now() + STARTUP_GRACE,
    });

    // Only a file-backed policy can change under us; the inline lists are fixed
    // for the process's life.
    if !opts.policy.is_empty() {
        let path = opts.policy.clone();
        let watched = Arc::clone(&shared);
        if thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || watch_policy(path, watched))
            .is_err()
        {
            eprintln!("proxy: cannot spawn the policy watcher; policy changes will not apply");
        }
    }

    // The sidecar gates its own readiness on this, installs the blackhole routes
    // and only then tells the launcher the sandbox may start -- so the routes are
    // in place before any traffic can exist.
    if let Ok(mut f) = File::create(PROXY_READY) {
        let _ = f.write_all(b"ready\n");
    }

    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                let shared = Arc::clone(&shared);
                // The pump buffers live on the heap, so these threads need very
                // little stack; the default 8 MiB reservation each adds up.
                let spawned = thread::Builder::new()
                    .stack_size(256 * 1024)
                    .spawn(move || handle_client(client, shared));
                if spawned.is_err() {
                    eprintln!("proxy: cannot spawn handler thread");
                }
            }
            Err(_) => {
                // Transient accept errors (fd pressure) must not busy-spin.
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(allow_d: &str, deny_d: &str, allow_i: &str, deny_i: &str) -> ProxyConfig {
        ProxyConfig::new(
            parse_csv(allow_d),
            parse_csv(deny_d),
            parse_csv_ips(allow_i).expect("test allow_ips"),
            parse_csv_ips(deny_i).expect("test deny_ips"),
            None,
            None,
        )
    }

    #[test]
    fn exact_domain_does_not_match_subdomains() {
        assert!(domain_match("github.com", "github.com"));
        assert!(!domain_match("status.github.com", "github.com"));
    }

    #[test]
    fn wildcard_matches_base_and_subdomains() {
        assert!(domain_match("github.com", "*.github.com"));
        assert!(domain_match("api.github.com", "*.github.com"));
        assert!(!domain_match("notgithub.com", "*.github.com"));
    }

    #[test]
    fn allow_list_makes_policy_deny_by_default() {
        let c = cfg("github.com", "", "", "");
        assert!(c.is_allowed("github.com", 443));
        assert!(!c.is_allowed("example.com", 443));
    }

    #[test]
    fn deny_list_alone_leaves_policy_allow_by_default() {
        let c = cfg("", "example.com", "", "");
        assert!(c.is_allowed("github.com", 443));
        assert!(!c.is_allowed("example.com", 443));
    }

    #[test]
    fn more_specific_domain_wins() {
        let c = cfg("api.github.com", "*.github.com", "", "");
        assert!(c.is_allowed("api.github.com", 443));
        assert!(!c.is_allowed("gist.github.com", 443));
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        let c = cfg("api.github.com", "", "", "");
        assert!(c.is_allowed("API.GitHub.com".to_ascii_lowercase().as_str(), 443));
    }

    #[test]
    fn longer_cidr_prefix_wins() {
        let c = cfg("", "", "10.0.0.0/8", "10.1.0.0/24");
        assert!(c.is_allowed("10.2.0.1", 443));
        assert!(!c.is_allowed("10.1.0.5", 443));
    }

    #[test]
    fn bracketed_ipv6_literal_is_matched_as_an_address() {
        let c = cfg("", "", "", "::1/128");
        assert!(!c.is_allowed("[::1]", 443));
    }

    // ── host normalization (F3) ─────────────────────────────────────────────

    #[test]
    fn trailing_dot_is_stripped_before_matching() {
        let c = cfg("", "github.com", "", "");
        assert!(!c.is_allowed("github.com.", 443));
    }

    #[test]
    fn leading_or_repeated_dot_is_rejected() {
        // An empty policy allows everything except a host that cannot mean
        // anything sane.
        let c = cfg("", "", "", "");
        assert!(!c.is_allowed(".github.com", 443));
        assert!(!c.is_allowed("github..com", 443));
    }

    #[test]
    fn ipv4_mapped_ipv6_literal_matches_v4_deny_range() {
        let c = cfg("", "", "", "10.0.0.0/8");
        assert!(!c.is_allowed("[::ffff:10.0.0.1]", 443));
        assert!(!c.is_allowed("::ffff:10.0.0.1", 443));
    }

    #[test]
    fn ipv4_compatible_ipv6_literal_matches_v4_deny_range() {
        let c = cfg("", "", "", "10.0.0.0/8");
        assert!(!c.is_allowed("[::10.0.0.1]", 443));
    }

    #[test]
    fn underscored_hostname_still_matches() {
        let c = cfg("internal_service.example.com", "", "", "");
        assert!(c.is_allowed("internal_service.example.com", 443));
    }

    #[test]
    fn resolved_address_check_ignores_the_deny_by_default_fallback() {
        // An allow list of domains and no allow_ips: every resolved address is
        // unlisted, and must still be reachable.
        let c = cfg("github.com", "", "", "");
        assert!(!c.is_denied_address("140.82.121.4".parse().unwrap()));
    }

    #[test]
    fn resolved_address_check_honours_explicit_deny_ips() {
        let c = cfg("internal.example.com", "", "", "169.254.0.0/16");
        assert!(c.is_denied_address("169.254.169.254".parse().unwrap()));
        assert!(!c.is_denied_address("140.82.121.4".parse().unwrap()));
    }

    #[test]
    fn more_specific_allow_ip_overrides_a_denied_range() {
        let c = cfg("", "", "10.1.0.0/24", "10.0.0.0/8");
        assert!(!c.is_denied_address("10.1.0.5".parse().unwrap()));
        assert!(c.is_denied_address("10.2.0.5".parse().unwrap()));
    }

    // ── baseline private/loopback deny (F2) ────────────────────────────────
    // These ranges are not compiled into the proxy -- the launcher writes them
    // into the policy file as ordinary deny_ips entries, so what actually needs
    // testing here is the *mechanism* the baseline depends on: that any
    // deny_ips range denies both a literal target and a resolved address, and
    // that an equally-specific allow_ips overrides it in both paths.

    #[test]
    fn each_baseline_range_is_denied_under_default_allow() {
        let baseline = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,\
                         192.168.0.0/16,169.254.0.0/16,100.64.0.0/10,\
                         0.0.0.0/8,fc00::/7,fe80::/10";
        let c = cfg("", "", "", baseline);
        assert!(c.default_allow, "deny-only policy must stay allow-by-default");
        for addr in [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "172.16.0.5",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata endpoint
            "100.64.0.1",
            "0.0.0.5",
            "fc00::1",
            "fe80::1",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(!c.is_allowed_ip(ip), "{} should be denied as a literal target", addr);
            assert!(c.is_denied_address(ip), "{} should be denied as a resolved address", addr);
        }
    }

    #[test]
    fn equal_prefix_allow_ip_overrides_a_baseline_deny_for_literal_targets() {
        let c = cfg("", "", "10.0.0.0/8", "10.0.0.0/8");
        assert!(c.is_allowed_ip("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn equal_prefix_allow_ip_overrides_a_baseline_deny_for_resolved_addresses() {
        // Regression test for the is_denied_address tie-break fix: without it,
        // this is the one case where F2's own documented migration path (an
        // allow_ips override at the identical prefix) silently did not work.
        let c = cfg("", "", "10.0.0.0/8", "10.0.0.0/8");
        assert!(!c.is_denied_address("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn more_specific_allow_ip_still_overrides_a_baseline_deny() {
        let c = cfg("", "", "10.1.0.0/24", "10.0.0.0/8");
        assert!(c.is_allowed_ip("10.1.0.5".parse().unwrap()));
        assert!(!c.is_allowed_ip("10.2.0.5".parse().unwrap()));
    }

    #[test]
    fn resolve_failure_reports_the_underlying_error() {
        // A bare `dns` verdict is useless for diagnosis; the resolver's own
        // message has to survive.
        let r = Resolver::new();
        let err = r
            .resolve("no-such-host.invalid", 80, Instant::now())
            .unwrap_err();
        assert!(
            !err.to_string().is_empty(),
            "resolver error must carry a message"
        );
    }

    #[test]
    fn resolve_retries_for_at_least_the_retry_window() {
        // Regression: this used to be scoped to the startup grace, so in steady
        // state a failure got exactly one attempt and a blip became a 502.
        // `retry_until` in the past must not shorten the floor.
        let r = Resolver::new();
        let started = Instant::now();
        let _ = r.resolve("no-such-host.invalid", 80, Instant::now() - Duration::from_secs(60));
        assert!(
            started.elapsed() >= RETRY_WINDOW,
            "expected retries for at least {:?}, gave up after {:?}",
            RETRY_WINDOW,
            started.elapsed()
        );
    }

    #[test]
    fn connect_failure_reports_the_underlying_error() {
        // Port 9 (discard) on a reserved-documentation address: nothing answers.
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let err = connect_any(&[addr], Instant::now()).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn connect_with_no_addresses_is_an_error_not_a_panic() {
        assert!(connect_any(&[], Instant::now()).is_err());
    }

    #[test]
    fn json_escaping_covers_quotes_and_controls() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("a\nb"), "a\\nb");
    }

    /// Write to a scratch log, return the lines it ended up with.
    fn metrics_lines(name: &str, f: impl FnOnce(&MetricsLog)) -> Vec<String> {
        let path = std::env::temp_dir().join(format!("agent-sandbox-metrics-{}.jsonl", name));
        let _ = std::fs::remove_file(&path);
        let log = MetricsLog::open(path.to_str().unwrap()).expect("open metrics log");
        f(&log);
        let body = std::fs::read_to_string(&path).expect("read metrics log");
        let _ = std::fs::remove_file(&path);
        body.lines().map(str::to_string).collect()
    }

    #[test]
    fn open_and_close_share_one_id() {
        let mut id = String::new();
        let lines = metrics_lines("open-close", |log| {
            id = log.next_id();
            log.open_event(&id, "example.com", 443);
            log.record(Some(&id), "example.com", 443, "allow", None, 10, 20, 5);
        });
        assert_eq!(lines.len(), 2, "expected an open and a close: {:?}", lines);
        assert!(lines[0].contains("\"ev\":\"open\""), "{}", lines[0]);
        assert!(lines[1].contains("\"ev\":\"close\""), "{}", lines[1]);
        let needle = format!("\"id\":\"{}\"", id);
        assert!(lines[0].contains(&needle), "{}", lines[0]);
        assert!(lines[1].contains(&needle), "{}", lines[1]);
        // The close carries the accounting; the open cannot, since it has not
        // happened yet.
        assert!(lines[1].contains("\"up\":10"), "{}", lines[1]);
        assert!(!lines[0].contains("\"up\""), "{}", lines[0]);
    }

    /// The summary treats a row without `ev` as a completed connection, and the
    /// launcher greps these lines for a verdict, so an id-less record has to stay
    /// exactly what it always was.
    #[test]
    fn record_without_an_id_carries_no_event_fields() {
        let lines = metrics_lines("no-id", |log| {
            log.record(None, "example.com", 443, "deny", None, 0, 0, 1);
        });
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("{\"ts\":"), "{}", lines[0]);
        assert!(!lines[0].contains("\"ev\""), "{}", lines[0]);
        assert!(!lines[0].contains("\"id\""), "{}", lines[0]);
        assert!(lines[0].contains("\"verdict\":\"deny\""), "{}", lines[0]);
    }

    // ── policy parsing ──────────────────────────────────────────────────────
    // The launcher used to hand these lists over space-separated while this side
    // split on commas, so anything past the first entry was silently discarded --
    // and an emptied allow list means allow-everything.  These pin both halves.

    #[test]
    fn lists_split_on_commas_and_whitespace() {
        assert_eq!(parse_csv("a.example.com,b.example.com").len(), 2);
        assert_eq!(parse_csv("a.example.com b.example.com").len(), 2);
        assert_eq!(
            parse_csv_ips("10.0.0.0/8 192.168.1.0/24").expect("spaces"),
            parse_csv_ips("10.0.0.0/8,192.168.1.0/24").expect("commas")
        );
        assert_eq!(parse_csv_ips("10.0.0.0/8 192.168.1.0/24").unwrap().len(), 2);
    }

    #[test]
    fn an_unparseable_ip_is_an_error_not_an_empty_list() {
        assert!(parse_csv_ips("garbage").is_err());
        assert!(parse_csv_ips("10.0.0.0/8,garbage").is_err());
    }

    #[test]
    fn a_bare_address_is_a_host_route() {
        // The AGENTS.md parser accepts these (python ip_network calls it /32) and
        // IpNet on its own does not, so they used to be dropped in silence.
        let config = parse_policy("deny_ips 8.8.8.8\ndeny_ips 2001:db8::1\n").unwrap();
        assert_eq!(config.deny_ips.len(), 2);
        assert!(config.is_denied_address("8.8.8.8".parse().unwrap()));
        assert!(!config.is_denied_address("8.8.4.4".parse().unwrap()));
        assert!(config.is_denied_address("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn policy_file_carries_every_entry() {
        let config = parse_policy(
            "# comment\n\
             \n\
             allow_domains github.com\n\
             allow_domains *.githubusercontent.com\n\
             deny_domains telemetry.example.com\n\
             allow_ips 10.0.0.0/8\n\
             allow_ips 192.168.1.0/24\n\
             deny_ips 10.1.0.0/24\n",
        )
        .expect("policy");
        assert_eq!(config.allow_domains.len(), 2);
        assert_eq!(config.deny_domains.len(), 1);
        assert_eq!(config.allow_ips.len(), 2);
        assert_eq!(config.deny_ips.len(), 1);
        assert!(!config.default_allow, "an allow list means deny by default");
    }

    #[test]
    fn policy_rejects_the_old_space_separated_encoding() {
        // Exactly what the launcher used to pass as one argument.
        let err = parse_policy("allow_ips 10.0.0.0/8 192.168.1.0/24\n").unwrap_err();
        assert!(err.contains("whitespace"), "{}", err);
    }

    #[test]
    fn policy_rejects_unknown_keys_and_bad_values() {
        assert!(parse_policy("allow_domians github.com\n").is_err());
        assert!(parse_policy("allow_ips not-an-ip\n").is_err());
        assert!(parse_policy("default maybe\n").is_err());
        assert!(parse_policy("allow_domains\n").is_err());
    }

    #[test]
    fn policy_errors_name_the_line() {
        let err = parse_policy("allow_domains ok.example.com\nallow_ips nope\n").unwrap_err();
        assert!(err.starts_with("2:"), "{}", err);
    }

    #[test]
    fn explicit_default_overrides_the_derivation() {
        // Deny lists alone would normally leave the policy allow-by-default.
        let config = parse_policy("deny_domains bad.example.com\ndefault deny\n").unwrap();
        assert!(!config.default_allow);
        assert!(!config.is_allowed("anything.example.com", 443));

        // And the other direction: an allow list with an explicit allow default.
        let config = parse_policy("allow_domains good.example.com\ndefault allow\n").unwrap();
        assert!(config.default_allow);
        assert!(config.is_allowed("anything.example.com", 443));
    }

    #[test]
    fn describe_round_trips_through_parse_policy() {
        // `proxy show` and the startup log render policy with describe(), and
        // the host writes policy files; the two formats must not diverge.
        let original = parse_policy(
            "allow_domains github.com\ndeny_domains bad.example.com\n\
             allow_ips 10.0.0.0/8\ndeny_ips 10.1.0.0/24\nallow_ports 8000-8100\n",
        )
        .unwrap();
        let reparsed = parse_policy(&original.describe().join("\n")).unwrap();
        assert_eq!(original.describe(), reparsed.describe());
    }

    #[test]
    fn an_empty_policy_allows_everything() {
        // Documented behaviour, not an accident: --proxy with no rules is a
        // metering-only proxy.  The launcher says so at startup.
        let config = parse_policy("# nothing here\n").unwrap();
        assert!(config.default_allow);
    }

    // ── allow_ports ─────────────────────────────────────────────────────────

    #[test]
    fn single_port_and_range_parse() {
        assert_eq!(parse_port_range("443").unwrap(), PortRange { start: 443, end: 443 });
        assert_eq!(
            parse_port_range("8000-8100").unwrap(),
            PortRange { start: 8000, end: 8100 }
        );
        assert!(parse_port_range("0").is_err());
        assert!(parse_port_range("70000").is_err());
        assert!(parse_port_range("100-50").is_err());
        assert!(parse_port_range("abc").is_err());
    }

    #[test]
    fn allow_list_derives_the_default_allow_ports() {
        let config = parse_policy("allow_domains github.com\n").unwrap();
        assert!(config.is_allowed("github.com", 443));
        assert!(config.is_allowed("github.com", 22));
        assert!(!config.is_allowed("github.com", 8443));
    }

    #[test]
    fn deny_only_policy_is_unrestricted_on_ports() {
        let config = parse_policy("deny_domains bad.example.com\n").unwrap();
        assert!(config.is_allowed("github.com", 61234));
    }

    #[test]
    fn explicit_allow_ports_overrides_the_derived_default() {
        let config =
            parse_policy("allow_domains github.com\nallow_ports 8443\n").unwrap();
        assert!(!config.is_allowed("github.com", 443));
        assert!(config.is_allowed("github.com", 8443));
    }

    #[test]
    fn port_range_is_inclusive() {
        let config = parse_policy("allow_domains github.com\nallow_ports 8000-8100\n").unwrap();
        assert!(config.is_allowed("github.com", 8000));
        assert!(config.is_allowed("github.com", 8100));
        assert!(!config.is_allowed("github.com", 7999));
        assert!(!config.is_allowed("github.com", 8101));
    }

    #[test]
    fn port_deny_is_distinguishable_from_host_deny() {
        let config = parse_policy("allow_domains github.com\nallow_ports 443\n").unwrap();
        assert!(config.is_allowed_target("github.com"));
        assert!(!config.is_allowed_port(8443));
        assert!(!config.is_allowed("github.com", 8443));
    }

    // ── reload ──────────────────────────────────────────────────────────────

    fn shared_with(policy: &str) -> Shared {
        Shared {
            config: RwLock::new(Arc::new(parse_policy(policy).expect("initial policy"))),
            resolver: Resolver::new(),
            metrics: None,
            startup_until: Instant::now(),
        }
    }

    fn policy_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("agent-sandbox-policy-{}", name))
    }

    #[test]
    fn a_reload_carries_the_derived_default() {
        // The trap this guards: default_allow is derived from the lists, so a
        // reload that rebuilds the lists but keeps the old mode turns a fresh
        // allow-list policy into allow-everything.  Deny-only starts
        // allow-by-default, so the flip has to be observable.
        let shared = shared_with("deny_domains bad.example.com\n");
        assert!(shared.config().is_allowed("anything.example.com", 443));

        let path = policy_path("reload-default");
        std::fs::write(&path, "allow_ips 10.0.0.0/8\nallow_ips 192.168.1.0/24\n").unwrap();
        assert!(reload_once(path.to_str().unwrap(), &shared));
        let _ = std::fs::remove_file(&path);

        assert!(
            !shared.config().is_allowed("anything.example.com", 443),
            "an allow list must make the reloaded policy deny-by-default"
        );
    }

    #[test]
    fn a_rejected_reload_keeps_the_previous_policy() {
        let shared = shared_with("allow_domains github.com\n");
        let path = policy_path("reload-rejected");

        std::fs::write(&path, "allow_ips 10.0.0.0/8 192.168.1.0/24\n").unwrap();
        assert!(!reload_once(path.to_str().unwrap(), &shared));
        let _ = std::fs::remove_file(&path);

        assert!(shared.config().is_allowed("github.com", 443));
        assert!(!shared.config().is_allowed("elsewhere.example.com", 443));
    }

    #[test]
    fn a_vanished_policy_keeps_the_previous_one() {
        // Deleting the file must not read as "no rules": that would be a silent
        // widening to allow-everything.
        let shared = shared_with("allow_domains github.com\n");
        assert!(!reload_once(
            policy_path("definitely-absent").to_str().unwrap(),
            &shared
        ));
        assert!(!shared.config().is_allowed("elsewhere.example.com", 443));
    }

    #[test]
    fn a_reload_widens_and_narrows() {
        let shared = shared_with("allow_domains github.com\n");
        let path = policy_path("reload-widen");

        std::fs::write(&path, "allow_domains github.com\nallow_domains api.openai.com\n").unwrap();
        assert!(reload_once(path.to_str().unwrap(), &shared));
        assert!(shared.config().is_allowed("api.openai.com", 443));

        std::fs::write(&path, "allow_domains github.com\n").unwrap();
        assert!(reload_once(path.to_str().unwrap(), &shared));
        assert!(!shared.config().is_allowed("api.openai.com", 443));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ids_are_unique_and_carry_the_boot_stamp() {
        let lines = metrics_lines("unique-ids", |log| {
            let a = log.next_id();
            let b = log.next_id();
            assert_ne!(a, b);
            assert!(a.starts_with(&format!("{}-", log.boot)), "{}", a);
            log.open_event(&a, "a.example.com", 443);
            log.open_event(&b, "b.example.com", 443);
        });
        assert_eq!(lines.len(), 2);
    }
}
