use ipnet::IpNet;
use std::net::IpAddr;
use crate::secret::SecretBindings;

/// A single port, or an inclusive range (`8000-8100`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
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

pub const DEFAULT_ALLOW_PORTS: [PortRange; 3] = [
    PortRange { start: 80, end: 80 },
    PortRange {
        start: 443,
        end: 443,
    },
    PortRange { start: 22, end: 22 },
];

#[derive(Debug, Clone)]
pub struct L7Rule {
    pub domain: String,
    pub method: String,
    pub path_pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRule<T> {
    pub target: T,
    pub ports: Option<Vec<PortRange>>,
}

impl<T: std::fmt::Display> std::fmt::Display for TargetRule<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.ports {
            Some(ports) => {
                let p: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                write!(f, "{}:{}", self.target, p.join(","))
            }
            None => write!(f, "{}", self.target),
        }
    }
}

#[derive(Debug)]
pub struct ProxyConfig {
    pub allow_host: Vec<TargetRule<String>>,
    /// Routes -- host *and* method *and* path -- that a secret may be injected
    /// into.  Route-scoped rather than domain-scoped on purpose: AGENTS.md is
    /// untrusted and controls the other rules on a host, so a domain-wide
    /// marker let a second, secret-less rule (`method = "*", path = "/**"`)
    /// collect a token the operator authorized for one endpoint.
    pub secret_routes: Vec<L7Rule>,
    /// Hosts the SSH relay may act for -- i.e. which destinations `git push`/
    /// `pull` may reach.  Populated by the launcher from `allow` entries on
    /// port 22; the proxy itself never consults it, but it has to *parse* it,
    /// because `relay-server` and `agent-sandbox ctl relay` read the same
    /// file and an unknown key here aborts the whole sidecar.
    pub allow_signing: Vec<String>,
    /// Whether the GPG relay may sign/authenticate at all.  Host-agnostic --
    /// gpg has no destination of its own -- and set unconditionally by the
    /// launcher whenever `--gpg` wires up the relay, independent of
    /// `AGENTS.md`.
    pub signing_enabled: bool,
    pub allow_ip: Vec<TargetRule<IpNet>>,
    pub deny_ip: Vec<TargetRule<IpNet>>,
    pub default_allow: bool,
    pub allow_port: Option<Vec<PortRange>>,
    pub l7_rules: Vec<L7Rule>,
}

impl ProxyConfig {
    pub fn new(
        allow_host: Vec<TargetRule<String>>,
        secret_routes: Vec<L7Rule>,
        allow_signing: Vec<String>,
        signing_enabled: bool,
        allow_ip: Vec<TargetRule<IpNet>>,
        deny_ip: Vec<TargetRule<IpNet>>,
        allow_port_override: Option<Vec<PortRange>>,
        default_override: Option<bool>,
        l7_rules: Vec<L7Rule>,
    ) -> ProxyConfig {
        let default_allow = default_override.unwrap_or(false);
        let allow_port = match allow_port_override {
            Some(v) => Some(v),
            None if default_allow => None,
            None => Some(DEFAULT_ALLOW_PORTS.to_vec()),
        };
        ProxyConfig {
            allow_host,
            secret_routes,
            allow_signing,
            signing_enabled,
            allow_ip,
            deny_ip,
            default_allow,
            allow_port,
            l7_rules,
        }
    }

    pub fn has_l7_rules(&self, host: &str) -> bool {
        self.l7_rules.iter().any(|r| domain_match(host, &r.domain))
    }

    pub fn is_l7_allowed(&self, host: &str, method: &str, path: &str) -> bool {
        let matching_rules: Vec<_> = self.l7_rules.iter()
            .filter(|r| domain_match(host, &r.domain))
            .collect();
        if matching_rules.is_empty() {
            return true;
        }
        matching_rules.iter().any(|r| {
            (r.method == method || r.method == "*") && crate::l7::glob_match(path, &r.path_pattern)
        })
    }

    /// Human-readable explanation for why an L7 request is denied.  Returns an
    /// empty string when the request is actually allowed, but callers should
    /// only invoke this after `is_l7_allowed` has already returned false.
    pub fn why_l7_denied(&self, host: &str, method: &str, path: &str) -> String {
        let matching_rules: Vec<_> = self.l7_rules.iter()
            .filter(|r| domain_match(host, &r.domain))
            .collect();
        if matching_rules.is_empty() {
            return format!("no L7 allow rules for domain {:?}", host);
        }
        let method_matches: Vec<_> = matching_rules.iter()
            .filter(|r| r.method == method || r.method == "*")
            .collect();
        if method_matches.is_empty() {
            let methods: Vec<_> = matching_rules.iter().map(|r| r.method.as_str()).collect();
            return format!(
                "domain {:?} has L7 rules but none allow method {:?}; configured methods: {}",
                host, method, methods.join(", ")
            );
        }
        let patterns: Vec<_> = method_matches.iter().map(|r| r.path_pattern.as_str()).collect();
        format!(
            "domain {:?} allows method {:?} but path {:?} does not match any configured pattern; configured patterns: {}",
            host, method, path, patterns.join(", ")
        )
    }

    pub fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        for d in &self.allow_host {
            out.push(format!("allow_host {}", d));
        }
        for r in &self.secret_routes {
            out.push(format!("secret_route\t{}\t{}\t{}", r.domain, r.method, r.path_pattern));
        }
        for h in &self.allow_signing {
            out.push(format!("allow_signing {}", h));
        }
        if self.signing_enabled {
            out.push("signing_enabled true".to_string());
        }
        for n in &self.allow_ip {
            out.push(format!("allow_ip {}", n));
        }
        for n in &self.deny_ip {
            out.push(format!("deny_ip {}", n));
        }
        if let Some(ranges) = &self.allow_port {
            for r in ranges {
                out.push(format!("allow_port {}", r));
            }
        }
        for r in &self.l7_rules {
            out.push(format!("allow_route\t{}\t{}\t{}", r.domain, r.method, r.path_pattern));
        }
        out.push(format!(
            "default {}",
            if self.default_allow { "allow" } else { "deny" }
        ));
        out
    }
}

pub fn split_list(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
}

pub fn parse_csv(s: &str) -> Vec<String> {
    split_list(s).map(|s| s.to_ascii_lowercase()).collect()
}

pub fn parse_net(s: &str) -> Result<IpNet, String> {
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

pub fn parse_csv_ips(s: &str) -> Result<Vec<TargetRule<IpNet>>, String> {
    split_list(s).map(parse_ip_target).collect()
}

pub fn parse_csv_domains(s: &str) -> Result<Vec<TargetRule<String>>, String> {
    split_list(s).map(parse_domain_target).collect()
}

pub fn parse_port_range(s: &str) -> Result<PortRange, String> {
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

pub fn parse_csv_ports(s: &str) -> Result<Vec<PortRange>, String> {
    split_list(s).map(parse_port_range).collect()
}

fn parse_target_with_ports(s: &str) -> Result<(String, Option<Vec<PortRange>>), String> {
    if let Some(pos) = s.rfind(':') {
        let left = &s[..pos];
        let right = &s[pos + 1..];
        
        let looks_like_port = !right.is_empty() && right.chars().all(|c| c.is_ascii_digit() || c == ',' || c == '-');
        let is_unbracketed_ipv6 = left.contains(':') && !left.starts_with('[');
        
        if looks_like_port && !is_unbracketed_ipv6 {
            let host = if left.starts_with('[') && left.ends_with(']') {
                &left[1..left.len()-1]
            } else {
                left
            }.to_string();
            let ports = parse_csv_ports(right)?;
            return Ok((host, Some(ports)));
        }
    }
    Ok((s.to_string(), None))
}

pub fn parse_ip_target(s: &str) -> Result<TargetRule<IpNet>, String> {
    let (host, ports) = parse_target_with_ports(s)?;
    let net = parse_net(&host)?;
    Ok(TargetRule { target: net, ports })
}

pub fn parse_domain_target(s: &str) -> Result<TargetRule<String>, String> {
    let (host, ports) = parse_target_with_ports(s)?;
    Ok(TargetRule { target: host.to_ascii_lowercase(), ports })
}

/// `domain<TAB>method<TAB>path`, shared by `allow_route` and `secret_route` so the
/// route a rule allows and the route it may inject into can never be written
/// in two different dialects.
fn parse_l7_fields(key: &str, lineno: usize, value: &str) -> Result<L7Rule, String> {
    let parts: Vec<&str> = value.splitn(3, '\t').collect();
    if parts.len() != 3 {
        return Err(format!("{}: {} expects 3 tab-separated fields", lineno, key));
    }
    if !parts[2].starts_with('/') {
        return Err(format!("{}: {}: path {:?} must start with '/'", lineno, key, parts[2]));
    }
    Ok(L7Rule {
        domain: parts[0].to_lowercase(),
        method: parts[1].to_string(),
        path_pattern: parts[2].to_string(),
    })
}

pub fn parse_policy(text: &str) -> Result<ProxyConfig, String> {
    let mut allow_host = Vec::new();
    let mut secret_routes = Vec::new();
    let mut allow_signing = Vec::new();
    let mut signing_enabled = false;
    let mut allow_ip = Vec::new();
    let mut deny_ip = Vec::new();
    let mut allow_port_override: Option<Vec<PortRange>> = None;
    let mut default_override = None;
    let mut l7_rules = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lineno = i + 1;
        let (key, rest_of_line) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| format!("{}: {:?} is not KEY VALUE", lineno, line))?;
        let value = rest_of_line.trim();
        if value.is_empty() {
            return Err(format!("{}: {} has no value", lineno, key));
        }

        // allow_route and secret_route are intentionally tab-separated
        // (domain<TAB>method<TAB>path), so they are exempt from the "no
        // whitespace in values" rule that guards every other key against the
        // old space-separated encoding.
        if !matches!(key, "allow_route" | "secret_route") && value.chars().any(char::is_whitespace) {
            return Err(format!("{}: {}: {:?} contains whitespace", lineno, key, value));
        }

        match key {
            "allow_host" => allow_host.push(parse_domain_target(value).map_err(|e| format!("{}: allow_host: {}", lineno, e))?),
            "secret_route" => secret_routes.push(parse_l7_fields("secret_route", lineno, value)?),
            "allow_signing" => allow_signing.push(value.to_ascii_lowercase()),
            "signing_enabled" => match value {
                "true" | "false" => signing_enabled = value == "true",
                _ => return Err(format!("{}: signing_enabled: expected 'true' or 'false', got {:?}", lineno, value)),
            },
            "allow_ip" => allow_ip
                .push(parse_ip_target(value).map_err(|e| format!("{}: allow_ip: {}", lineno, e))?),
            "deny_ip" => deny_ip
                .push(parse_ip_target(value).map_err(|e| format!("{}: deny_ip: {}", lineno, e))?),
            "allow_port" => {
                let r = parse_port_range(value)
                    .map_err(|e| format!("{}: allow_port: {}", lineno, e))?;
                allow_port_override.get_or_insert_with(Vec::new).push(r);
            }
            "allow_route" => l7_rules.push(parse_l7_fields("allow_route", lineno, value)?),
            "default" => match value {
                "allow" | "deny" => default_override = Some(value == "allow"),
                "ask" => return Err(format!(
                    "{}: default: 'ask' is no longer supported; use 'allow' or 'deny', and watch denied requests live via `agent-sandbox ctl tui`",
                    lineno
                )),
                _ => return Err(format!("{}: default: expected 'allow' or 'deny', got {:?}", lineno, value)),
            },
            other => return Err(format!("{}: unknown key {:?}", lineno, other)),
        }
    }

    Ok(ProxyConfig::new(
        allow_host,
        secret_routes,
        allow_signing,
        signing_enabled,
        allow_ip,
        deny_ip,
        allow_port_override,
        default_override,
        l7_rules,
    ))
}

pub fn load_policy(path: &str) -> Result<ProxyConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read policy {}: {}", path, e))?;
    parse_policy(&text).map_err(|e| format!("{}:{}", path, e))
}

pub fn fold_ipv6(ip: std::net::Ipv6Addr) -> IpAddr {
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

pub fn normalize_host(host: &str) -> Option<String> {
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

    if host.starts_with('.') {
        return None;
    }
    let stripped = host.strip_suffix('.').unwrap_or(host);
    if stripped.is_empty() || stripped.contains("..") {
        return None;
    }
    if !stripped
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return None;
    }
    Some(stripped.to_string())
}

pub fn domain_match(domain: &str, pattern: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(base) => domain == base || domain.ends_with(&pattern[1..]),
        None => domain == pattern,
    }
}

pub fn overlap_candidates(pattern: &str) -> [String; 2] {
    match pattern.strip_prefix("*.") {
        Some(base) => [base.to_string(), format!("sample.{}", base)],
        None => [pattern.to_string(), pattern.to_string()],
    }
}

pub fn patterns_overlap(a: &str, b: &str) -> bool {
    let [a0, a1] = overlap_candidates(a);
    let [b0, b1] = overlap_candidates(b);
    domain_match(&a0, b) || domain_match(&a1, b) || domain_match(&b0, a) || domain_match(&b1, a)
}

/// Whether any route the policy marks secret-bearing actually has a provider
/// binding behind it.
pub fn has_backed_secret_routes(config: &ProxyConfig, secrets: &SecretBindings) -> bool {
    config.secret_routes.iter().any(|route| {
        secrets
            .entries()
            .iter()
            .any(|binding| patterns_overlap(&route.domain, &binding.domain))
    })
}

/// Union the port sets of every rule tied at the winning specificity.
///
/// A tie is not a mistake: `allowed_hosts = ["github.com:443", "github.com:22"]`
/// compiles to two `allow_host` lines carrying the *same* pattern with
/// different port sets, and taking only the first silently dropped the second
/// port -- which denied SSH on a host the operator had explicitly allowed it
/// on.  `None` from any tied rule means that rule carries no port constraint
/// of its own, which widens the union back to the global `allow_port`.
fn union_ports<'a>(
    rules: impl Iterator<Item = Option<&'a Vec<PortRange>>>,
) -> Option<Vec<PortRange>> {
    let mut out = Vec::new();
    for ports in rules {
        match ports {
            None => return None,
            Some(p) => out.extend(p.iter().copied()),
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn is_port_in_target_ports(port: u16, target_ports: Option<&Vec<PortRange>>, global_ports: Option<&[PortRange]>) -> bool {
    match target_ports {
        Some(ports) => ports.iter().any(|r| r.contains(port)),
        None => global_ports.map_or(true, |ranges| ranges.iter().any(|r| r.contains(port))),
    }
}

impl ProxyConfig {
    /// Longest-pattern-wins, with the ports of *every* rule tied at that
    /// length unioned together (see `union_ports`).
    ///
    /// There is no domain deny list: denies are built-in only, and the
    /// built-in baseline is expressed as `deny_ip`.  A name that resolves
    /// into a denied range is refused by `is_denied_address` after
    /// resolution, which is where a hostname pointing at the host or the LAN
    /// actually gets caught.
    pub fn check_domain(&self, domain: &str) -> (bool, Option<Vec<PortRange>>) {
        let mut best_len: i32 = -1;
        let mut allowed = self.default_allow;

        for rule in &self.allow_host {
            let p = &rule.target;
            if domain_match(domain, p) && p.len() as i32 > best_len {
                best_len = p.len() as i32;
                allowed = true;
            }
        }

        if best_len < 0 {
            return (allowed, None);
        }
        let ports = union_ports(
            self.allow_host
                .iter()
                .filter(|r| r.target.len() as i32 == best_len && domain_match(domain, &r.target))
                .map(|r| r.ports.as_ref()),
        );
        (allowed, ports)
    }

    /// Longest-prefix-wins, with the same tie handling as `check_domain`.
    pub fn check_ip(&self, ip: IpAddr) -> (bool, Option<Vec<PortRange>>) {
        let mut best_prefix: i32 = -1;
        let mut allowed = self.default_allow;
        let mut from_deny = false;

        for rule in &self.allow_ip {
            let net = &rule.target;
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                allowed = true;
                from_deny = false;
            }
        }

        for rule in &self.deny_ip {
            let net = &rule.target;
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                allowed = false;
                from_deny = true;
            }
        }

        if best_prefix < 0 {
            return (allowed, None);
        }
        let tier = if from_deny { &self.deny_ip } else { &self.allow_ip };
        let ports = union_ports(
            tier.iter()
                .filter(|r| r.target.prefix_len() as i32 == best_prefix && r.target.contains(&ip))
                .map(|r| r.ports.as_ref()),
        );
        (allowed, ports)
    }

    pub fn is_allowed_domain(&self, domain: &str) -> bool {
        self.check_domain(domain).0
    }

    pub fn is_allowed_ip(&self, ip: IpAddr) -> bool {
        self.check_ip(ip).0
    }

    pub fn is_denied_address(&self, ip: IpAddr) -> bool {
        let mut best_prefix: i32 = -1;
        let mut denied = false;

        for rule in &self.deny_ip {
            let net = &rule.target;
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                denied = true;
            }
        }

        for rule in &self.allow_ip {
            let net = &rule.target;
            if net.contains(&ip) && (net.prefix_len() as i32) >= best_prefix {
                best_prefix = net.prefix_len() as i32;
                denied = false;
            }
        }

        denied
    }

    pub fn is_allowed_target(&self, host: &str) -> bool {
        let host = match normalize_host(host) {
            Some(h) => h,
            None => return false,
        };
        match host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            Ok(ip) => self.is_allowed_ip(ip),
            Err(_) => self.is_allowed_domain(&host),
        }
    }

    pub fn is_allowed_port(&self, port: u16) -> bool {
        self.allow_port
            .as_ref()
            .map_or(true, |ranges| ranges.iter().any(|r| r.contains(port)))
    }

    pub fn is_allowed(&self, host: &str, port: u16) -> bool {
        let host_normalized = match normalize_host(host) {
            Some(h) => h,
            None => return false,
        };
        match host_normalized.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            Ok(ip) => {
                let (allowed, winner_ports) = self.check_ip(ip);
                allowed
                    && is_port_in_target_ports(
                        port,
                        winner_ports.as_ref(),
                        self.allow_port.as_deref(),
                    )
            }
            Err(_) => {
                let (allowed, winner_ports) = self.check_domain(&host_normalized);
                allowed
                    && is_port_in_target_ports(
                        port,
                        winner_ports.as_ref(),
                        self.allow_port.as_deref(),
                    )
            }
        }
    }

    /// Explains why `is_allowed_domain` returned false for `domain`. Mirrors
    /// its longest-match-wins loop exactly, tracking which pattern actually
    /// decided the verdict rather than just the outcome, so the explanation
    /// can never name a pattern other than the real one. Callers must only
    /// invoke this once denial is already confirmed.
    fn why_domain_denied(&self, domain: &str) -> String {
        let mut best_len: i32 = -1;
        let mut winner: Option<&str> = None;
        for rule in &self.allow_host {
            let p = &rule.target;
            if domain_match(domain, p) && p.len() as i32 > best_len {
                best_len = p.len() as i32;
                winner = Some(p.as_str());
            }
        }
        match winner {
            Some(pattern) => format!("matches allow_host {:?}", pattern),
            None => format!("no allow_host rule matches {:?}; default is deny", domain),
        }
    }

    /// Explains why `is_allowed_ip` returned false for `ip`. Same mirroring
    /// approach as `why_domain_denied`.
    fn why_ip_denied(&self, ip: IpAddr) -> String {
        let mut best_prefix: i32 = -1;
        let mut winner: Option<(&IpNet, bool)> = None;
        for rule in &self.allow_ip {
            let net = &rule.target;
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                winner = Some((net, false));
            }
        }
        for rule in &self.deny_ip {
            let net = &rule.target;
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                winner = Some((net, true));
            }
        }
        match winner {
            Some((net, true)) => format!("matches deny_ip {}", net),
            Some((net, false)) => format!("matches allow_ip {}", net),
            None => format!("no allow_ip rule matches {}; default is deny", ip),
        }
    }

    /// Explains why `is_allowed_target` returned false for `host`. Dispatches
    /// to the domain or IP explanation exactly like `is_allowed_target` picks
    /// between `is_allowed_domain`/`is_allowed_ip`.
    pub fn why_target_denied(&self, host: &str) -> String {
        let normalized = match normalize_host(host) {
            Some(h) => h,
            None => return format!("{:?} is not a valid host", host),
        };
        match normalized.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            Ok(ip) => self.why_ip_denied(ip),
            Err(_) => self.why_domain_denied(&normalized),
        }
    }

    /// Explains why `is_allowed_port` returned false for `port`.
    pub fn why_port_denied(&self, port: u16) -> String {
        match &self.allow_port {
            Some(ranges) => {
                let list: Vec<String> = ranges.iter().map(|r| r.to_string()).collect();
                format!("port {} is not in allow_port (configured: {})", port, list.join(", "))
            }
            None => format!("port {} is not allowed", port),
        }
    }

    /// Explains why `is_denied_address` returned true for a *resolved*
    /// address. Distinct algorithm from `why_ip_denied`/`is_allowed_ip`: a
    /// `deny_ip` entry wins on a strictly greater prefix, but an `allow_ip`
    /// entry of *equal or greater* specificity overrides it (see
    /// `is_denied_address`'s own comment for why the tie-break is
    /// asymmetric). Mirrors that exact algorithm so the explanation can't
    /// disagree with the real decision.
    pub fn why_address_denied(&self, ip: IpAddr) -> String {
        let mut best_prefix: i32 = -1;
        let mut winner: Option<&IpNet> = None;
        for rule in &self.deny_ip {
            let net = &rule.target;
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                winner = Some(net);
            }
        }
        for rule in &self.allow_ip {
            let net = &rule.target;
            if net.contains(&ip) && (net.prefix_len() as i32) >= best_prefix {
                best_prefix = net.prefix_len() as i32;
                winner = None;
            }
        }
        match winner {
            Some(net) => format!("resolved address {} matches deny_ip {}", ip, net),
            None => format!("resolved address {} has no matching deny_ip rule", ip),
        }
    }

    /// Full explanation for a pre-resolution deny (host or port, whichever is
    /// responsible), for `is_allowed(host, port)` returning false. Callers
    /// must only invoke this once denial is already confirmed.
    pub fn why_denied(&self, host: &str, port: u16) -> String {
        let host_normalized = match normalize_host(host) {
            Some(h) => h,
            None => return format!("{:?} is not a valid host", host),
        };
        let (allowed, winner_ports, why_target) = match host_normalized.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            Ok(ip) => {
                let (allowed, winner_ports) = self.check_ip(ip);
                (allowed, winner_ports, self.why_ip_denied(ip))
            }
            Err(_) => {
                let (allowed, winner_ports) = self.check_domain(&host_normalized);
                (allowed, winner_ports, self.why_domain_denied(&host_normalized))
            }
        };

        if !allowed {
            why_target
        } else if !is_port_in_target_ports(port, winner_ports.as_ref(), self.allow_port.as_deref()) {
            match &winner_ports {
                Some(ports) => {
                    let list: Vec<String> = ports.iter().map(|r| r.to_string()).collect();
                    format!("port {} is not in target's allowed ports (configured: {})", port, list.join(", "))
                }
                None => match &self.allow_port {
                    Some(global_ports) => {
                        let list: Vec<String> = global_ports.iter().map(|r| r.to_string()).collect();
                        format!("port {} is not in global allow_port (configured: {})", port, list.join(", "))
                    }
                    None => format!("port {} is not allowed", port),
                }
            }
        } else {
            "unknown denial reason".to_string()
        }
    }

    /// Whether *any* route on this host can carry a secret.
    ///
    /// Deliberately coarse, and used only where the decision has to be made
    /// before a request is in hand: refusing cleartext to the host, and
    /// reporting a missing provider.  Injection itself uses
    /// `is_secret_route`, which is the narrow one.
    pub fn is_secret_host(&self, host: &str) -> bool {
        let host = match normalize_host(host) {
            Some(h) => h,
            None => return false,
        };
        if host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>().is_ok() {
            return false;
        }
        self.secret_routes
            .iter()
            .any(|r| domain_match(&host, &r.domain))
    }

    /// Whether this exact request is one the operator authorized a secret for.
    ///
    /// Matches with `glob_match` against the *normalized* path, the same way
    /// `is_l7_allowed` does, so the policy and the injector can never disagree
    /// about what a path means.
    pub fn is_secret_route(&self, host: &str, method: &str, path: &str) -> bool {
        let host = match normalize_host(host) {
            Some(h) => h,
            None => return false,
        };
        if host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>().is_ok() {
            return false;
        }
        self.secret_routes.iter().any(|r| {
            domain_match(&host, &r.domain)
                && (r.method == method || r.method == "*")
                && crate::l7::glob_match(path, &r.path_pattern)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_policy_reads_allow_route_rules() {
        let text = "default deny\nallow_route\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text).expect("parse should succeed");
        assert_eq!(cfg.l7_rules.len(), 1);
        assert_eq!(cfg.l7_rules[0].domain, "repo.kopla.jyu.fi");
        assert_eq!(cfg.l7_rules[0].method, "GET");
        assert_eq!(cfg.l7_rules[0].path_pattern, "/api/pypi/pypi");
        assert!(cfg.is_l7_allowed("repo.kopla.jyu.fi", "GET", "/api/pypi/pypi"));
        assert!(!cfg.is_l7_allowed("repo.kopla.jyu.fi", "POST", "/api/pypi/pypi"));
    }

    #[test]
    fn parse_policy_reads_allow_signing() {
        // The launcher writes this for every `allow` entry on port 22.  Until
        // it was a known key the proxy exited 2 on its own policy file, so a
        // single `github.com:22` in AGENTS.md stopped the sandbox launching.
        let cfg = parse_policy("allow_host github.com:22\nallow_signing GitHub.com\n")
            .expect("allow_signing must be a known key");
        assert_eq!(cfg.allow_signing, vec!["github.com".to_string()]);
    }

    #[test]
    fn allow_signing_survives_a_describe_round_trip() {
        let cfg = parse_policy("allow_signing github.com\nallow_signing gitlab.com\n").unwrap();
        let reparsed = parse_policy(&cfg.describe().join("\n")).expect("describe must re-parse");
        assert_eq!(reparsed.allow_signing, cfg.allow_signing);
    }

    #[test]
    fn parse_policy_reads_signing_enabled_independently_of_allow_signing() {
        // The launcher writes this whenever --gpg wires up the relay, with no
        // allow_signing host entries at all -- gpg signing must not depend on
        // any host being named.
        let cfg = parse_policy("signing_enabled true\n").expect("signing_enabled must be a known key");
        assert!(cfg.signing_enabled);
        assert!(cfg.allow_signing.is_empty());
    }

    #[test]
    fn parse_policy_rejects_a_non_boolean_signing_enabled() {
        let err = parse_policy("signing_enabled maybe\n").unwrap_err();
        assert!(err.contains("expected 'true' or 'false'"), "unexpected error: {err}");
    }

    #[test]
    fn signing_enabled_survives_a_describe_round_trip() {
        let cfg = parse_policy("signing_enabled true\n").unwrap();
        let reparsed = parse_policy(&cfg.describe().join("\n")).expect("describe must re-parse");
        assert_eq!(reparsed.signing_enabled, cfg.signing_enabled);
    }

    #[test]
    fn parse_policy_rejects_whitespace_in_other_values() {
        let text = "allow_ip 10.0.0.0/8 192.168.0.0/16\n";
        let err = parse_policy(text).unwrap_err();
        assert!(err.contains("whitespace"), "unexpected error: {err}");
    }

    #[test]
    fn why_l7_denied_explains_no_rules_for_domain() {
        let text = "default deny\nallow_route\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text).expect("parse should succeed");
        let reason = cfg.why_l7_denied("other.example.com", "GET", "/");
        assert!(reason.contains("no L7 allow rules for domain"), "{reason}");
        assert!(reason.contains("other.example.com"), "{reason}");
    }

    #[test]
    fn why_l7_denied_explains_method_mismatch() {
        let text = "default deny\nallow_route\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text).expect("parse should succeed");
        let reason = cfg.why_l7_denied("repo.kopla.jyu.fi", "POST", "/api/pypi/pypi");
        assert!(reason.contains("none allow method"), "{reason}");
        assert!(reason.contains("POST"), "{reason}");
        assert!(reason.contains("GET"), "{reason}");
    }

    #[test]
    fn why_l7_denied_explains_path_mismatch() {
        let text = "default deny\nallow_route\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text).expect("parse should succeed");
        let reason = cfg.why_l7_denied("repo.kopla.jyu.fi", "GET", "/packages/wheel.whl");
        assert!(reason.contains("path"), "{reason}");
        assert!(reason.contains("/packages/wheel.whl"), "{reason}");
        assert!(reason.contains("/api/pypi/pypi"), "{reason}");
    }

    #[test]
    fn default_ask_line_produces_an_actionable_error() {
        let err = parse_policy("default ask\n").unwrap_err();
        assert!(err.contains("no longer supported"), "{err}");
        assert!(err.contains("ctl tui"), "{err}");
    }

    #[test]
    fn a_domain_deny_rule_is_not_a_key_at_all() {
        // Denies are built-in only.  A policy carrying a hand-written domain
        // deny refuses to load rather than taking effect, so there is no way
        // to express one that half-works.
        let err = parse_policy("allow_host *.example.com\ndeny_domains internal.example.com\n")
            .unwrap_err();
        assert!(err.contains("unknown key"), "{err}");
        assert!(err.contains("deny_domains"), "{err}");
    }

    #[test]
    fn a_name_resolving_into_a_built_in_range_is_still_refused() {
        // What the domain deny list was reached for.  The check that matters
        // runs after resolution, on the address, and the baseline is what it
        // consults -- so dropping deny_domains removes no protection.
        let cfg = parse_policy("allow_host internal.example.com\ndeny_ip 10.0.0.0/8\n").unwrap();
        assert!(cfg.is_allowed("internal.example.com", 443), "the name itself is allowed");
        assert!(cfg.is_denied_address("10.1.2.3".parse().unwrap()), "the address it resolves to is not");
    }

    #[test]
    fn why_target_denied_explains_the_implicit_default_deny() {
        let cfg = parse_policy("allow_host github.com\n").unwrap();
        assert!(!cfg.is_allowed_target("evil.example.com"));
        let reason = cfg.why_target_denied("evil.example.com");
        assert!(reason.contains("no allow_host rule matches"), "{reason}");
        assert!(reason.contains("default is deny"), "{reason}");
    }

    #[test]
    fn why_target_denied_names_the_winning_deny_ip_pattern() {
        let cfg = parse_policy("allow_ip 10.0.0.0/8\ndeny_ip 10.5.0.0/16\n").unwrap();
        let ip: IpAddr = "10.5.1.1".parse().unwrap();
        assert!(!cfg.is_allowed_target("10.5.1.1"));
        let reason = cfg.why_target_denied("10.5.1.1");
        assert!(reason.contains("deny_ip"), "{reason}");
        assert!(reason.contains(&ip.to_string()) || reason.contains("10.5.0.0/16"), "{reason}");
    }

    #[test]
    fn one_host_on_two_ports_keeps_both() {
        // `allowed_hosts = ["github.com:443", "github.com:22"]` compiles to two lines
        // with the same pattern.  The tie used to go to whichever came first,
        // so the SSH port the operator asked for was quietly denied.
        let cfg = parse_policy("allow_host github.com:443\nallow_host github.com:22\n")
            .unwrap();
        assert!(cfg.is_allowed("github.com", 443));
        assert!(cfg.is_allowed("github.com", 22));
        assert!(!cfg.is_allowed("github.com", 8443), "the union must not open other ports");
    }

    #[test]
    fn one_cidr_on_two_ports_keeps_both() {
        let cfg = parse_policy("allow_ip 10.0.0.0/8:80\nallow_ip 10.0.0.0/8:443\n").unwrap();
        assert!(cfg.is_allowed("10.1.2.3", 80));
        assert!(cfg.is_allowed("10.1.2.3", 443));
        assert!(!cfg.is_allowed("10.1.2.3", 22));
    }

    #[test]
    fn an_unconstrained_tied_rule_widens_to_the_global_ports() {
        // `github.com` alone means "the default ports"; a tied `github.com:22`
        // must not narrow it back down to 22.
        let cfg = parse_policy("allow_host github.com\nallow_host github.com:22\n").unwrap();
        assert!(cfg.is_allowed("github.com", 80));
        assert!(cfg.is_allowed("github.com", 443));
        assert!(cfg.is_allowed("github.com", 22));
    }

    #[test]
    fn a_longer_pattern_still_beats_a_tied_pair() {
        // The union applies within one specificity tier, not across tiers.
        let cfg = parse_policy(
            "allow_host *.github.com:443\nallow_host *.github.com:22\nallow_host api.github.com:8443\n",
        )
        .unwrap();
        assert!(cfg.is_allowed("api.github.com", 8443));
        assert!(!cfg.is_allowed("api.github.com", 22), "the longer pattern wins outright");
        assert!(cfg.is_allowed("gist.github.com", 22));
    }

    #[test]
    fn why_denied_survives_a_tied_pair() {
        let cfg = parse_policy("allow_host github.com:443\nallow_host github.com:22\n")
            .unwrap();
        let reason = cfg.why_denied("github.com", 8443);
        assert!(reason.contains("8443"), "{reason}");
        assert!(reason.contains("443") && reason.contains("22"), "both ports listed: {reason}");
    }

    #[test]
    fn a_target_carries_a_whole_port_list_on_one_line() {
        let cfg = parse_policy("allow_host github.com:22,443\n").unwrap();
        assert!(cfg.is_allowed("github.com", 22));
        assert!(cfg.is_allowed("github.com", 443));
        assert!(!cfg.is_allowed("github.com", 8443));
        // And renders back the way it was written, which is what the exit
        // summary hands to the user as TOML.
        assert_eq!(cfg.allow_host[0].to_string(), "github.com:22,443");
    }

    #[test]
    fn allow_port_takes_one_range_not_a_list() {
        // This asymmetry is deliberate and load-bearing: it is why the
        // launcher splits `*:80,443` into one allow_port line per element.
        assert!(parse_policy("allow_port 80,443\n").is_err());
        assert!(parse_policy("allow_port 80\nallow_port 443\n").is_ok());
    }

    #[test]
    fn why_port_denied_lists_the_configured_ranges() {
        let cfg = parse_policy("allow_host github.com\nallow_port 443\n").unwrap();
        assert!(!cfg.is_allowed_port(8443));
        let reason = cfg.why_port_denied(8443);
        assert!(reason.contains("8443"), "{reason}");
        assert!(reason.contains("443"), "{reason}");
    }

    #[test]
    fn why_address_denied_names_the_matching_baseline_range() {
        let cfg = parse_policy("allow_host github.com\ndeny_ip 169.254.0.0/16\n").unwrap();
        let ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(cfg.is_denied_address(ip));
        let reason = cfg.why_address_denied(ip);
        assert!(reason.contains("deny_ip"), "{reason}");
        assert!(reason.contains("169.254.0.0/16"), "{reason}");
    }

    #[test]
    fn why_denied_prioritizes_the_port_reason_over_the_domain_reason() {
        let cfg = parse_policy("allow_host github.com\nallow_port 443\n").unwrap();
        assert!(cfg.is_allowed_target("github.com"));
        assert!(!cfg.is_allowed("github.com", 8443));
        let reason = cfg.why_denied("github.com", 8443);
        assert!(reason.contains("port"), "{reason}");
    }
}
