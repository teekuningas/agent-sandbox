#![forbid(unsafe_code)]

use agent_sandbox_proxy::policy::ProxyConfig;
use pulldown_cmark::{CodeBlockKind, Event, Parser, Tag};
use serde::Serialize;
use std::collections::HashSet;
use std::net::{IpAddr, TcpListener, UdpSocket};
use thiserror::Error;
use toml::Value;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    Message(String),
}

impl ConfigError {
    pub fn msg<T: std::fmt::Display>(m: T) -> Self {
        ConfigError::Message(m.to_string())
    }
}

pub const MAX_PORTS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub name: String,
    pub bind: String,
    pub host: u16,
    pub container: u16,
    pub protocol: String,
}

impl Mapping {
    pub fn spec(&self) -> String {
        let bind = if self.bind.contains(':') {
            format!("[{}]", self.bind)
        } else {
            self.bind.clone()
        };
        format!(
            "{}:{}:{}/{}",
            bind, self.host, self.container, self.protocol
        )
    }
}

impl ProxyPolicy {
    /// Merge another declarative policy, preserving the first occurrence of
    /// each rule. Profiles and AGENTS.md are intentionally additive: neither
    /// source can use merging to weaken the deny-by-default policy.
    pub fn merge(&mut self, other: ProxyPolicy) {
        fn extend_unique(target: &mut Vec<String>, values: Vec<String>) {
            for value in values {
                if !target.contains(&value) {
                    target.push(value);
                }
            }
        }

        extend_unique(&mut self.allow_host, other.allow_host);
        extend_unique(&mut self.secret_route, other.secret_route);
        extend_unique(&mut self.allow_signing, other.allow_signing);
        self.signing_enabled = self.signing_enabled || other.signing_enabled;
        extend_unique(&mut self.allow_ip, other.allow_ip);
        extend_unique(&mut self.allow_port, other.allow_port);
        extend_unique(&mut self.allow_route, other.allow_route);
        if self.default.is_empty() {
            self.default = other.default;
        }
    }
}

pub fn iter_tagged_blocks(text: &str) -> Vec<String> {
    let parser = Parser::new(text);
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut current_block = String::new();

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(ref info))) => {
                let info_str = info.as_ref();
                if info_str.split_whitespace().any(|s| s == "agent-sandbox") {
                    in_block = true;
                    current_block.clear();
                }
            }
            Event::Text(ref text_ev) => {
                if in_block {
                    current_block.push_str(text_ev.as_ref());
                }
            }
            Event::End(Tag::CodeBlock(_)) => {
                if in_block {
                    blocks.push(current_block.clone());
                    in_block = false;
                }
            }
            _ => {}
        }
    }
    blocks
}

fn _port(name: &str, field: &str, value: &Value, allow_zero: bool) -> Result<u16, ConfigError> {
    let p = value.as_integer().ok_or_else(|| {
        ConfigError::msg(format!("ports.{}.{}: expected an integer", name, field))
    })?;
    let low = if allow_zero { 0 } else { 1 };
    if p < low || p > 65535 {
        return Err(ConfigError::msg(format!(
            "ports.{}.{}: {} is outside {}-65535",
            name, field, p, low
        )));
    }
    Ok(p as u16)
}

fn _bind(name: &str, value: &Value, allow_any_interface: bool) -> Result<String, ConfigError> {
    let s = value
        .as_str()
        .ok_or_else(|| ConfigError::msg(format!("ports.{}.bind: expected a string", name)))?;
    let literal = if s == "localhost" { "127.0.0.1" } else { s };
    let addr: IpAddr = literal.parse().map_err(|_| {
        ConfigError::msg(format!(
            "ports.{}.bind: {:?} is not an IP address literal",
            name, s
        ))
    })?;
    if !addr.is_loopback() && !allow_any_interface {
        return Err(ConfigError::msg(format!(
            "ports.{}.bind: {} is not a loopback address; pass --ports-any-interface to publish there",
            name, addr
        )));
    }
    Ok(addr.to_string())
}

fn _protocol(name: &str, value: &Value) -> Result<String, ConfigError> {
    let s = value.as_str().ok_or_else(|| {
        ConfigError::msg(format!("ports.{}.protocol: expected 'tcp' or 'udp'", name))
    })?;
    let lower = s.to_lowercase();
    if lower != "tcp" && lower != "udp" {
        return Err(ConfigError::msg(format!(
            "ports.{}.protocol: expected 'tcp' or 'udp', got {:?}",
            name, s
        )));
    }
    Ok(lower)
}

fn is_valid_name(n: &str) -> bool {
    if n.is_empty() || n.len() > 64 {
        return false;
    }
    let mut chars = n.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '-' {
            return false;
        }
    }
    true
}

fn parse_entry(
    name: &str,
    value: &Value,
    allow_any_interface: bool,
) -> Result<Mapping, ConfigError> {
    if !is_valid_name(name) {
        return Err(ConfigError::msg(format!(
            "ports.{:?}: name must match pattern",
            name
        )));
    }

    if let Some(table) = value.as_table() {
        let allowed_fields: HashSet<&str> = ["container", "host", "bind", "protocol"]
            .iter()
            .cloned()
            .collect();
        let unknown: Vec<_> = table
            .keys()
            .filter(|k| !allowed_fields.contains(k.as_str()))
            .collect();
        if !unknown.is_empty() {
            return Err(ConfigError::msg(format!(
                "ports.{}: unknown field(s) {:?}",
                name, unknown
            )));
        }
        if !table.contains_key("container") {
            return Err(ConfigError::msg(format!(
                "ports.{}: missing required field 'container'",
                name
            )));
        }
        let container = _port(name, "container", &table["container"], false)?;
        let host = if let Some(h) = table.get("host") {
            _port(name, "host", h, true)?
        } else {
            container
        };
        let bind = if let Some(b) = table.get("bind") {
            _bind(name, b, allow_any_interface)?
        } else {
            "127.0.0.1".to_string()
        };
        let protocol = if let Some(p) = table.get("protocol") {
            _protocol(name, p)?
        } else {
            "tcp".to_string()
        };
        Ok(Mapping {
            name: name.to_string(),
            bind,
            host,
            container,
            protocol,
        })
    } else {
        let container = _port(name, "container", value, false)?;
        Ok(Mapping {
            name: name.to_string(),
            bind: "127.0.0.1".to_string(),
            host: container,
            container,
            protocol: "tcp".to_string(),
        })
    }
}

pub fn parse_ports(
    text: &str,
    allow_any_interface: bool,
    max_ports: usize,
) -> Result<Vec<Mapping>, ConfigError> {
    let mut mappings = std::collections::HashMap::new();
    let blocks = iter_tagged_blocks(text);

    for body in blocks {
        let block: Value = body.parse().map_err(|e| {
            ConfigError::msg(format!("malformed TOML in agent-sandbox block: {}", e))
        })?;

        if let Some(ports) = block.get("ports") {
            let ports_table = ports
                .as_table()
                .ok_or_else(|| ConfigError::msg("[ports] must be a table"))?;

            for (name, value) in ports_table {
                if mappings.contains_key(name) {
                    return Err(ConfigError::msg(format!(
                        "ports.{}: declared more than once",
                        name
                    )));
                }
                let mapping = parse_entry(name, value, allow_any_interface)?;
                mappings.insert(name.clone(), mapping);
            }
        }
    }

    if mappings.len() > max_ports {
        return Err(ConfigError::msg(format!(
            "{} port mappings declared, limit is {}",
            mappings.len(),
            max_ports
        )));
    }

    Ok(mappings.into_values().collect())
}

pub fn allocate(mapping: Mapping) -> Result<Mapping, ConfigError> {
    if mapping.host != 0 {
        return Ok(mapping);
    }
    let bind_addr: IpAddr = mapping
        .bind
        .parse()
        .map_err(|e| ConfigError::msg(format!("invalid bind: {}", e)))?;
    let host_port = if mapping.protocol == "udp" {
        let sock = UdpSocket::bind((bind_addr, 0)).map_err(|e| ConfigError::msg(e))?;
        sock.local_addr().map_err(|e| ConfigError::msg(e))?.port()
    } else {
        let listener = TcpListener::bind((bind_addr, 0)).map_err(|e| ConfigError::msg(e))?;
        listener
            .local_addr()
            .map_err(|e| ConfigError::msg(e))?
            .port()
    };
    let mut m = mapping;
    m.host = host_port;
    Ok(m)
}

pub fn parse_mounts(text: &str) -> Result<Vec<String>, ConfigError> {
    let mut specs = Vec::new();
    let blocks = iter_tagged_blocks(text);
    for body in blocks {
        let block: Value = body.parse().map_err(|e| {
            ConfigError::msg(format!("malformed TOML in agent-sandbox block: {}", e))
        })?;
        if let Some(mounts) = block.get("mounts") {
            let mounts_table = mounts
                .as_table()
                .ok_or_else(|| ConfigError::msg("[mounts] must be a table"))?;
            for (src, value) in mounts_table {
                let (dest, opts) = if let Some(s) = value.as_str() {
                    (s.to_string(), String::new())
                } else if let Some(table) = value.as_table() {
                    let dest = table
                        .get("destination")
                        .and_then(|d| d.as_str())
                        .ok_or_else(|| {
                            ConfigError::msg(format!(
                                "mounts.{}: missing required field 'destination' or not a string",
                                src
                            ))
                        })?
                        .to_string();
                    let mut opts = String::new();
                    if let Some(opts_val) = table.get("options") {
                        if let Some(s) = opts_val.as_str() {
                            opts = s.to_string();
                        } else if let Some(arr) = opts_val.as_array() {
                            let mut opt_strings = Vec::new();
                            for o in arr {
                                if let Some(s) = o.as_str() {
                                    opt_strings.push(s.to_string());
                                } else {
                                    return Err(ConfigError::msg(format!(
                                        "mounts.{}.options: expected a string or list of strings",
                                        src
                                    )));
                                }
                            }
                            opts = opt_strings.join(",");
                        } else {
                            return Err(ConfigError::msg(format!(
                                "mounts.{}.options: expected a string or list of strings",
                                src
                            )));
                        }
                    }
                    let allowed: HashSet<&str> =
                        ["destination", "options"].iter().cloned().collect();
                    let unknown: Vec<_> = table
                        .keys()
                        .filter(|k| !allowed.contains(k.as_str()))
                        .collect();
                    if !unknown.is_empty() {
                        return Err(ConfigError::msg(format!(
                            "mounts.{}: unknown field(s) {:?}",
                            src, unknown
                        )));
                    }
                    (dest, opts)
                } else {
                    return Err(ConfigError::msg(format!(
                        "mounts.{}: expected a string or table",
                        src
                    )));
                };
                let mut spec = format!("{}:{}", src, dest);
                if !opts.is_empty() {
                    spec.push(':');
                    spec.push_str(&opts);
                }
                specs.push(spec);
            }
        }
    }
    Ok(specs)
}

fn is_valid_domain(mut d: &str) -> bool {
    if d.starts_with("*.") {
        d = &d[2..];
    }
    if d.is_empty() {
        return false;
    }
    let mut chars = d.chars().peekable();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    let mut last = first;
    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '-' {
            return false;
        }
        last = c;
    }
    last.is_ascii_alphanumeric()
}

fn _proxy_domain(field: &str, value: &str) -> Result<(), ConfigError> {
    if !is_valid_domain(value) {
        return Err(ConfigError::msg(format!(
            "{}: {:?} is not a valid domain name",
            field, value
        )));
    }
    Ok(())
}

pub(crate) fn is_ip_or_cidr(value: &str) -> bool {
    if let Some((ip_str, mask_str)) = value.split_once('/') {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if let Ok(mask) = mask_str.parse::<u8>() {
                return match ip {
                    IpAddr::V4(_) => mask <= 32,
                    IpAddr::V6(_) => mask <= 128,
                };
            }
        }
        false
    } else {
        value.parse::<IpAddr>().is_ok()
    }
}

fn _proxy_ip(field: &str, value: &str) -> Result<(), ConfigError> {
    if !is_ip_or_cidr(value) {
        return Err(ConfigError::msg(format!(
            "{}: {:?} is not a valid IP address or network",
            field, value
        )));
    }
    Ok(())
}

/// Validates a port spec: a port, a range, or a comma-separated list of both.
///
/// Delegated to the proxy's own parser rather than reimplemented, so what the
/// launcher accepts and what the proxy accepts cannot drift apart -- the
/// asymmetry this closes had the exit summary printing `host:22,443` back as
/// TOML that the launcher then refused on relaunch.
fn _proxy_port(field: &str, value: &str) -> Result<(), ConfigError> {
    // `split_list` drops empty elements, so an empty spec parses as "no ports"
    // rather than failing. Caught here, because `"github.com:"` would otherwise
    // compile to a line the proxy reads back as a literal domain.
    if value.trim().is_empty() || value.split(',').any(|p| p.trim().is_empty()) {
        return Err(ConfigError::msg(format!(
            "{}: {:?} has an empty port. Write a port, a range, or a comma-separated list of them.",
            field, value
        )));
    }
    agent_sandbox_proxy::policy::parse_csv_ports(value).map_err(|_| {
        ConfigError::msg(format!(
            "{}: {:?} is not a port, port range, or comma-separated list of them",
            field, value
        ))
    })?;
    Ok(())
}

/// Whether a port spec covers 22 -- including via a range, which is what
/// `is_allowed(host, 22)` will do at the proxy.
///
/// An `allowed_hosts` entry on the SSH port does double duty: it is also what
/// authorizes the relay to reach that host, so this is what decides whether
/// `git push`/`pull` work in a proxied session.
fn ports_include_ssh(spec: &str) -> bool {
    agent_sandbox_proxy::policy::parse_csv_ports(spec)
        .map(|ranges| ranges.iter().any(|r| r.contains(22)))
        .unwrap_or(false)
}

fn _proxy_list<F>(
    field: &str,
    value: &Value,
    mut validate: F,
    prefix: &str,
) -> Result<Vec<String>, ConfigError>
where
    F: FnMut(&str, &str) -> Result<(), ConfigError>,
{
    let arr = value
        .as_array()
        .ok_or_else(|| ConfigError::msg(format!("{}{}", prefix, field)))?;
    let mut out = Vec::new();
    for item in arr {
        let s = item.as_str().ok_or_else(|| {
            ConfigError::msg(format!("{}{} elements must be strings", prefix, field))
        })?;
        validate(field, s)?;
        out.push(s.to_string());
    }
    Ok(out)
}

/// Splits `host:ports` on the last colon, where `ports` may be a port, a
/// range, or a comma-separated list of both.
///
/// The right-hand side is recognised on the same terms as the proxy's
/// `policy::parse_target_with_ports`, deliberately: what the splitter accepts
/// and what the policy file accepts have to be the same set. `*` is recognised
/// here and rejected by `_proxy_port`, which is what produces the good error
/// message instead of "not a valid domain name".
pub fn parse_host_port(s: &str) -> (String, Option<String>) {
    if let Some(pos) = s.rfind(':') {
        let left = &s[..pos];
        let right = &s[pos + 1..];
        let looks_like_ports = !right.is_empty()
            && right
                .chars()
                .all(|c| c.is_ascii_digit() || c == ',' || c == '-');
        // An unbracketed IPv6 address is all colons and hex; splitting it here
        // would hand `_proxy_domain` a fragment and blame the domain.
        let is_unbracketed_ipv6 = left.contains(':') && !left.starts_with('[');
        if (looks_like_ports || right == "*") && !is_unbracketed_ipv6 {
            let host = if left.starts_with('[') && left.ends_with(']') {
                &left[1..left.len() - 1]
            } else {
                left
            };
            return (host.to_string(), Some(right.to_string()));
        }
    }
    (s.to_string(), None)
}

#[derive(Default, Debug)]
pub struct ProxyPolicy {
    pub allow_host: Vec<String>,
    /// `domain\tmethod\tpath` per rule that names a secret.  Route-scoped, not
    /// domain-scoped: the proxy injects only into requests matching one of
    /// these, so a secret-less rule elsewhere on the same host cannot collect
    /// the token.
    pub secret_route: Vec<String>,
    pub allow_signing: Vec<String>,
    /// Whether the GPG relay should be allowed to sign/authenticate at all,
    /// independent of any host. Never parsed from AGENTS.md TOML -- set
    /// directly by the launcher binary whenever `--gpg` wires up the relay.
    pub signing_enabled: bool,
    pub allow_ip: Vec<String>,
    pub allow_port: Vec<String>,
    pub allow_route: Vec<String>,
    pub default: Vec<String>,
}

pub fn parse_proxy(text: &str) -> Result<ProxyPolicy, ConfigError> {
    let mut policy = ProxyPolicy::default();
    policy.default = vec!["deny".to_string()];

    let blocks = iter_tagged_blocks(text);

    for body in blocks {
        let block: Value = body.parse().map_err(|e| {
            ConfigError::msg(format!("malformed TOML in agent-sandbox block: {}", e))
        })?;

        if let Some(table) = block.as_table() {
            let allowed_tables: HashSet<&str> =
                ["network", "ports", "mounts"].iter().cloned().collect();
            let unknown: Vec<_> = table
                .keys()
                .filter(|k| !allowed_tables.contains(k.as_str()))
                .collect();
            if !unknown.is_empty() {
                return Err(ConfigError::msg(format!(
                    "unknown top-level table(s): {:?}",
                    unknown
                )));
            }
        }

        if let Some(network) = block.get("network") {
            let net_table = network
                .as_table()
                .ok_or_else(|| ConfigError::msg("[network] must be a table"))?;

            let allowed_net: HashSet<&str> =
                ["allowed_hosts", "allowed_routes"].iter().cloned().collect();
            let unknown: Vec<_> = net_table
                .keys()
                .filter(|k| !allowed_net.contains(k.as_str()))
                .collect();
            if let Some(first_unknown) = unknown.first() {
                return Err(ConfigError::msg(format!("[network]: unknown key '{}'. Valid keys under [network] are 'allowed_hosts' and 'allowed_routes' ([[network.allowed_routes]]).", first_unknown)));
            }

            let mut allow_set = HashSet::new();
            let mut allow_has_wildcard = false;
            let mut rules_hosts_no_secret = HashSet::new();
            let mut rules_hosts_with_secret = HashSet::new();
            let mut has_non_secret_rule = false;

            if let Some(rules) = net_table.get("allowed_routes") {
                let rules_arr = rules.as_array().ok_or_else(|| {
                    ConfigError::msg("[network].allowed_routes must be an array of tables")
                })?;
                for (i, rule_val) in rules_arr.iter().enumerate() {
                    let rule = rule_val.as_table().ok_or_else(|| {
                        ConfigError::msg(format!(
                            "[[network.allowed_routes]][{}]: must be a table",
                            i
                        ))
                    })?;

                    let allowed_rule_keys: HashSet<&str> =
                        ["host", "method", "path", "secret", "header", "prefix"]
                            .iter()
                            .cloned()
                            .collect();
                    if let Some(unknown_key) = rule
                        .keys()
                        .find(|k| !allowed_rule_keys.contains(k.as_str()))
                    {
                        return Err(ConfigError::msg(format!("[[network.allowed_routes]][{}]: unknown field '{}'. Valid keys under [[network.allowed_routes]] are 'host', 'method', 'path', 'secret', 'header', and 'prefix'.", i, unknown_key)));
                    }

                    let host_val = rule.get("host").and_then(|v| v.as_str()).ok_or_else(|| ConfigError::msg(format!("[[network.allowed_routes]][{}]: missing required field 'host'. Example: host = \"registry.npmjs.org:443\".", i)))?;
                    let method = rule.get("method").and_then(|v| v.as_str()).ok_or_else(|| ConfigError::msg(format!("[[network.allowed_routes]][{}]: missing required field 'method'. Specify an HTTP method (e.g. method = \"GET\", method = \"POST\", or method = \"*\").", i)))?;
                    let path = rule.get("path").and_then(|v| v.as_str()).ok_or_else(|| ConfigError::msg(format!("[[network.allowed_routes]][{}]: missing required field 'path'. Example: path = \"/api/*\" or path = \"/\".", i)))?;

                    if method != "*"
                        && (!method.chars().all(|c| c.is_ascii_uppercase()) || method.is_empty())
                    {
                        return Err(ConfigError::msg(format!("[[network.allowed_routes]][{}].method: '{}' must be uppercase (e.g. method = \"GET\" or method = \"*\").", i, method)));
                    }
                    if !path.starts_with('/') {
                        return Err(ConfigError::msg(format!("[[network.allowed_routes]][{}].path: 'path' must start with '/'. Change to path = \"/{}\".", i, path.trim_start_matches('/'))));
                    }

                    if rule.contains_key("secret") {
                        rules_hosts_with_secret.insert(host_val.to_string());
                    } else {
                        rules_hosts_no_secret.insert(host_val.to_string());
                        has_non_secret_rule = true;
                    }
                }
            }

            if let Some(allow) = net_table.get("allowed_hosts") {
                let items = _proxy_list("allowed_hosts", allow, |_, _| Ok(()), "[network].")?;
                for item in items {
                    if !allow_set.insert(item.clone()) {
                        return Err(ConfigError::msg(format!(
                            "[network].allowed_hosts: duplicate entry '{}'. Remove the redundant entry.",
                            item
                        )));
                    }
                    if item == "*" || item.starts_with("*:") {
                        allow_has_wildcard = true;
                    }
                    if rules_hosts_no_secret.contains(&item) {
                        return Err(ConfigError::msg(format!("[network]: host '{}' is allowed broadly, making the non-secret [[network.allowed_routes]] ineffective. Remove the rule or add a secret.", item)));
                    }
                }
            }

            if allow_has_wildcard && has_non_secret_rule {
                return Err(ConfigError::msg("[network]: wildcard allow makes non-secret [[network.allowed_routes]] ineffective. Remove the rule or add a secret."));
            }

            if allow_has_wildcard {
                policy.default = vec!["allow".to_string()];
            }

            for item in allow_set {
                let (host_part, port_part) = parse_host_port(&item);
                if host_part != "*" {
                    let combined = match &port_part {
                        Some(p) => format!("{}:{}", host_part, p),
                        None => host_part.clone(),
                    };
                    if is_ip_or_cidr(&host_part) {
                        if !policy.allow_ip.contains(&combined) {
                            policy.allow_ip.push(combined);
                        }
                    } else {
                        _proxy_domain("[network].allowed_hosts", &host_part)?;
                        // One line per entry, so `ctl proxy show` and
                        // `rm allow` operate on the entry as it was written --
                        // including a comma-separated port list, which the
                        // proxy parses on one line. The proxy also unions the
                        // ports of every line sharing a pattern
                        // (`union_ports`), so two entries on one host are two
                        // lines and both are in force.
                        if !policy.allow_host.contains(&combined) {
                            policy.allow_host.push(combined);
                        }
                    }
                }
                if let Some(port) = port_part {
                    _proxy_port("[network].allowed_hosts", &port)?;
                    // An allow entry covering the SSH port is also what
                    // authorizes the relay to reach that host, so it is what
                    // makes `git push`/`pull` work in a proxied session. It
                    // says nothing about GPG signing, which `signing_enabled`
                    // gates on its own, host-agnostic.
                    if ports_include_ssh(&port)
                        && host_part != "*"
                        && !policy.allow_signing.contains(&host_part)
                    {
                        policy.allow_signing.push(host_part.clone());
                    }
                    if host_part == "*" {
                        // One line per element: the proxy's `allow_port` arm
                        // takes a single port or range, unlike the port field
                        // of a host target.
                        for element in port.split(',') {
                            let element = element.to_string();
                            if !policy.allow_port.contains(&element) {
                                policy.allow_port.push(element);
                            }
                        }
                    }
                }
            }

            if let Some(rules) = net_table.get("allowed_routes") {
                let rules_arr = rules.as_array().unwrap();
                for (i, rule_val) in rules_arr.iter().enumerate() {
                    let rule = rule_val.as_table().unwrap();
                    let host_val = rule.get("host").and_then(|v| v.as_str()).unwrap();
                    let method = rule.get("method").and_then(|v| v.as_str()).unwrap();
                    let path = rule.get("path").and_then(|v| v.as_str()).unwrap();

                    let (host_part, port_part) = parse_host_port(host_val);

                    if host_part != "*" {
                        let combined = match &port_part {
                            Some(p) => format!("{}:{}", host_part, p),
                            None => host_part.clone(),
                        };
                        if is_ip_or_cidr(&host_part) {
                            if !policy.allow_ip.contains(&combined) {
                                policy.allow_ip.push(combined);
                            }
                        } else {
                            _proxy_domain(
                                &format!("[[network.allowed_routes]][{}].host", i),
                                &host_part,
                            )?;
                            if !policy.allow_host.contains(&combined) {
                                policy.allow_host.push(combined);
                            }
                        }
                    }

                    if let Some(port) = port_part {
                        _proxy_port(&format!("[[network.allowed_routes]][{}].host", i), &port)?;
                        if host_part == "*" {
                            // One line per element, as in allowed_hosts above.
                            for element in port.split(',') {
                                let element = element.to_string();
                                if !policy.allow_port.contains(&element) {
                                    policy.allow_port.push(element);
                                }
                            }
                        }
                    }

                    policy
                        .allow_route
                        .push(format!("{}\t{}\t{}", host_part, method, path));

                    if let Some(secret) = rule.get("secret") {
                        if !secret.is_str() {
                            return Err(ConfigError::msg(format!(
                                "[[network.allowed_routes]][{}].secret: must be a string",
                                i
                            )));
                        }
                        // The route, not just the host: this is what the proxy
                        // matches a request against before injecting.
                        let route = format!("{}\t{}\t{}", host_part, method, path);
                        if !policy.secret_route.contains(&route) {
                            policy.secret_route.push(route);
                        }
                    }
                }
            }
        }
    }

    Ok(policy)
}

/// Parse a host-owned profile. Profiles are plain TOML rather than Markdown,
/// but otherwise use exactly the same declarative network syntax as AGENTS.md.
pub fn parse_proxy_profile(text: &str) -> Result<ProxyPolicy, ConfigError> {
    let value: Value = text
        .parse()
        .map_err(|e| ConfigError::msg(format!("malformed TOML in proxy profile: {}", e)))?;
    let table = value
        .as_table()
        .ok_or_else(|| ConfigError::msg("proxy profile must contain a TOML table"))?;
    if let Some(unknown) = table.keys().find(|key| *key != "network") {
        return Err(ConfigError::msg(format!(
            "proxy profile: unknown top-level key '{}'; only [network] is supported",
            unknown
        )));
    }
    let network = table
        .get("network")
        .ok_or_else(|| ConfigError::msg("proxy profile must contain a [network] table"))?;
    if !network.is_table() {
        return Err(ConfigError::msg("[network] must be a table"));
    }

    // Reuse the single AGENTS.md validator rather than maintaining a second
    // parser for the profile format.
    let wrapped = format!("```toml agent-sandbox\n{}\n```", text);
    parse_proxy(&wrapped)
}

pub fn format_proxy_policy(policy: &ProxyPolicy, source: &str) -> String {
    let mut lines = vec![format!(
        "# generated by agent-sandbox-parse-agents from {}",
        source
    )];

    for val in &policy.allow_host {
        lines.push(format!("allow_host {}", val));
    }
    for val in &policy.secret_route {
        lines.push(format!("secret_route\t{}", val));
    }
    for val in &policy.allow_signing {
        lines.push(format!("allow_signing {}", val));
    }
    if policy.signing_enabled {
        lines.push("signing_enabled true".to_string());
    }
    for val in &policy.allow_ip {
        lines.push(format!("allow_ip {}", val));
    }
    for val in &policy.allow_port {
        lines.push(format!("allow_port {}", val));
    }

    for val in &policy.allow_route {
        lines.push(format!("allow_route\t{}", val));
    }
    for val in &policy.default {
        lines.push(format!("default {}", val));
    }

    lines.join("\n") + "\n"
}

/// The reverse of `format_proxy_policy`: renders a running sandbox's current
/// (possibly live-edited) policy back as an AGENTS.md `[network]` TOML block,
/// for `agent-sandbox ctl proxy export`.
///
/// Not fully round-trippable: `[network]` only supports `allowed_hosts` (bare
/// host/IP entries) and `[[network.allowed_routes]]` (`allow_route`), so a non-default
/// `allow_port` — which can only be added live, via the TUI or
/// `ctl proxy allow`, never declared in AGENTS.md — is emitted as a trailing
/// advisory comment instead of being silently dropped or invented as an
/// unsupported TOML key.  `deny_ip` is omitted entirely: the baseline is
/// built-in, enforced whatever AGENTS.md says, and cannot be changed, so
/// round-tripping it would be noise.  A `secret = true` on an exported rule
/// is a placeholder too: the policy file records which *route* takes a
/// secret, never which one, so the reference has to be filled in by hand.
#[derive(Serialize)]
struct NetworkDocument {
    network: NetworkToml,
}

#[derive(Serialize)]
struct NetworkToml {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_hosts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_routes: Vec<RouteToml>,
}

#[derive(Serialize)]
struct RouteToml {
    host: String,
    method: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<bool>,
}

/// Return compiled policy lines that were added after the sandbox launched.
/// Exact line matching is intentional: policy files contain canonical lines,
/// and it prevents repeated live edits from producing duplicate output.
pub fn policy_delta_lines(
    active: &[String],
    base: &HashSet<String>,
    baseline: &HashSet<String>,
) -> Vec<String> {
    let mut seen = HashSet::new();
    active
        .iter()
        .filter(|line| !base.contains(*line) && !baseline.contains(*line))
        .filter(|line| seen.insert((*line).clone()))
        .cloned()
        .collect()
}

pub fn format_policy_lines_as_network_toml(lines: &[String]) -> Option<String> {
    let text = lines.join("\n") + "\n";
    let cfg = agent_sandbox_proxy::policy::parse_policy(&text).ok()?;
    Some(format_policy_as_network_toml(&cfg))
}

pub fn format_policy_as_network_toml(cfg: &ProxyConfig) -> String {
    let mut allowed_hosts: Vec<String> = cfg
        .allow_host
        .iter()
        .map(|r| r.to_string())
        .chain(cfg.allow_ip.iter().map(|n| n.to_string()))
        .collect();
    allowed_hosts.sort();
    allowed_hosts.dedup();

    let mut allowed_routes: Vec<RouteToml> = cfg
        .l7_rules
        .iter()
        .map(|r| RouteToml {
            host: r.domain.clone(),
            method: r.method.clone(),
            path: r.path_pattern.clone(),
            // The compiled policy records that a route is secret, not
            // the host-side secret reference.
            secret: cfg
                .secret_routes
                .iter()
                .any(|s| {
                    s.domain == r.domain && s.method == r.method && s.path_pattern == r.path_pattern
                })
                .then_some(true),
        })
        .collect();
    allowed_routes.sort_by(|a, b| {
        (&a.host, &a.method, &a.path, &a.secret).cmp(&(&b.host, &b.method, &b.path, &b.secret))
    });
    allowed_routes.dedup_by(|a, b| {
        a.host == b.host && a.method == b.method && a.path == b.path && a.secret == b.secret
    });

    let mut out = toml::to_string_pretty(&NetworkDocument {
        network: NetworkToml {
            allowed_hosts,
            allowed_routes,
        },
    })
    .expect("network TOML serialization cannot fail");
    out.push('\n');

    let mut advisory: Vec<String> = Vec::new();
    if let Some(ranges) = &cfg.allow_port {
        if ranges.as_slice() != agent_sandbox_proxy::policy::DEFAULT_ALLOW_PORTS.as_slice() {
            for r in ranges {
                advisory.push(format!("allow_port {}", r));
            }
        }
    }
    if !advisory.is_empty() {
        out.push_str(
            "\n# The following have no [network] TOML equivalent (it only supports 'allowed_hosts'\n",
        );
        out.push_str(
            "# and 'allowed_routes') and were left out of the block above. Re-apply them after\n",
        );
        out.push_str("# relaunching with `agent-sandbox ctl proxy allow`:\n");
        for line in advisory {
            out.push_str(&format!("# {}\n", line));
        }
    }

    out
}

#[cfg(test)]
mod export_tests {
    use super::*;
    use agent_sandbox_proxy::policy::parse_policy;

    #[test]
    fn exports_allow_entries_and_l7_rules_as_toml() {
        let cfg = parse_policy(
            "allow_host github.com\n\
             allow_ip 10.0.0.0/8\n\
             secret_route\tapi.github.com\tGET\t/repos/*\n\
             allow_route\tapi.github.com\tGET\t/repos/*\n",
        )
        .unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(toml.contains("[network]\n"), "{toml}");
        assert!(
            toml.contains("allowed_hosts = [\n    \"10.0.0.0/8\",\n    \"github.com\",\n]"),
            "{toml}"
        );
        assert!(toml.contains("[[network.allowed_routes]]"), "{toml}");
        assert!(toml.contains("host = \"api.github.com\""), "{toml}");
        assert!(toml.contains("method = \"GET\""), "{toml}");
        assert!(toml.contains("path = \"/repos/*\""), "{toml}");
        assert!(toml.contains("secret = true"), "{toml}");
    }

    #[test]
    fn export_marks_only_the_rule_that_actually_carries_a_secret() {
        // Two rules on one host, one secret-bearing.  The marker used to be
        // per domain, so both rules came back marked -- which is exactly the
        // over-broad model this replaces.
        let cfg = parse_policy(
            "allow_host api.github.com\n\
             secret_route\tapi.github.com\tGET\t/user/repos\n\
             allow_route\tapi.github.com\tGET\t/user/repos\n\
             allow_route\tapi.github.com\tGET\t/zen\n",
        )
        .unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert_eq!(toml.matches("secret = true").count(), 1, "{toml}");
        let (before_zen, after_zen) = toml.split_once("/zen").expect("both rules exported");
        assert!(before_zen.contains("secret = true"), "{toml}");
        assert!(!after_zen.contains("secret = true"), "{toml}");
    }

    #[test]
    fn roundtrip_allow_with_ports() {
        let cfg = parse_policy("allow_host *.jyu.fi:443\n").unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(toml.contains("allowed_hosts = [\"*.jyu.fi:443\"]"), "{toml}");
        assert!(!toml.contains("allow_port"), "{toml}");
    }

    #[test]
    fn delta_contains_only_live_rules_and_deduplicates_them() {
        let active = vec![
            "allow_host github.com".to_string(),
            "allow_host api.github.com".to_string(),
            "allow_host api.github.com".to_string(),
            "allow_route\tapi.github.com\tGET\t/repos/*".to_string(),
            "deny_ip 127.0.0.0/8".to_string(),
        ];
        let base = HashSet::from(["allow_host github.com".to_string()]);
        let baseline = HashSet::from(["deny_ip 127.0.0.0/8".to_string()]);

        assert_eq!(
            policy_delta_lines(&active, &base, &baseline),
            vec![
                "allow_host api.github.com".to_string(),
                "allow_route\tapi.github.com\tGET\t/repos/*".to_string(),
            ]
        );
    }

    #[test]
    fn formatted_policy_is_valid_toml() {
        let lines = vec![
            "allow_host github.com".to_string(),
            "allow_route\tapi.github.com\tGET\t/repos/*".to_string(),
        ];
        let output = format_policy_lines_as_network_toml(&lines).expect("policy should parse");
        let value: Value = output.parse().expect("formatted output should be TOML");
        assert!(value.get("network").is_some(), "{output}");
        assert!(output.contains("allowed_hosts"), "{output}");
        assert!(output.contains("[[network.allowed_routes]]"), "{output}");
    }

    #[test]
    fn exports_a_non_default_port_range_as_an_advisory_comment() {
        let cfg = parse_policy("allow_port 8000-8100\n").unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(
            !toml.contains("deny ="),
            "deny has no [network] TOML key: {toml}"
        );
        assert!(toml.contains("# allow_port 8000-8100"), "{toml}");
    }

    #[test]
    fn export_omits_the_built_in_deny_baseline() {
        // Built-in denies are enforced whatever AGENTS.md says and cannot be
        // changed, so exporting them would only be noise the operator has to
        // delete before pasting.
        let cfg = parse_policy("allow_host github.com\ndeny_ip 169.254.169.254/32\n").unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(!toml.contains("169.254"), "{toml}");
    }

    /// The link that was missing: `cli` writes the policy file and `proxy`
    /// reads it, but nothing exercised both halves, so `allow_signing` could
    /// be emitted by one and rejected as an unknown key by the other -- which
    /// made the proxy exit 2 on every sandbox whose AGENTS.md declared an SSH
    /// allow entry.  Any new key must round-trip through here.
    #[test]
    fn every_key_the_launcher_writes_is_a_key_the_proxy_parses() {
        let agents_md = "```agent-sandbox\n\
             [network]\n\
             allowed_hosts = [\"github.com:443\", \"github.com:22\", \"10.0.0.0/8:80\"]\n\
             \n\
             [[network.allowed_routes]]\n\
             host = \"api.github.com:443\"\n\
             method = \"GET\"\n\
             path = \"/user/repos\"\n\
             secret = \"GITHUB_TOKEN\"\n\
             ```\n";
        let policy = parse_proxy(agents_md).expect("AGENTS.md must parse");
        let text = format_proxy_policy(&policy, "AGENTS.md");
        let cfg = parse_policy(&text).unwrap_or_else(|e| {
            panic!("the proxy rejected the launcher's own policy: {e}\n{text}")
        });

        assert_eq!(cfg.allow_signing, vec!["github.com".to_string()]);
        assert!(cfg
            .secret_routes
            .iter()
            .any(|r| r.domain == "api.github.com"));
        assert!(cfg.is_allowed("github.com", 443), "{text}");
        assert!(cfg.is_allowed("github.com", 22), "{text}");
        assert!(cfg.is_allowed("10.1.2.3", 80), "{text}");
    }

    #[test]
    fn csv_ports_compile_to_one_line_and_still_authorize_the_relay() {
        let agents_md = "```agent-sandbox\n\
             [network]\n\
             allowed_hosts = [\"github.com:22,443\"]\n\
             ```\n";
        let policy = parse_proxy(agents_md).expect("AGENTS.md must parse");
        assert_eq!(policy.allow_host, vec!["github.com:22,443".to_string()]);
        assert_eq!(policy.allow_signing, vec!["github.com".to_string()]);

        let text = format_proxy_policy(&policy, "AGENTS.md");
        let cfg = parse_policy(&text).unwrap_or_else(|e| {
            panic!("the proxy rejected the launcher's own policy: {e}\n{text}")
        });
        assert!(cfg.is_allowed("github.com", 22), "{text}");
        assert!(cfg.is_allowed("github.com", 443), "{text}");
        assert!(!cfg.is_allowed("github.com", 8443), "{text}");
    }

    #[test]
    fn a_range_covering_22_authorizes_the_relay_too() {
        let agents_md = "```agent-sandbox\n\
             [network]\n\
             allowed_hosts = [\"git.example.com:20-30\"]\n\
             ```\n";
        let policy = parse_proxy(agents_md).expect("AGENTS.md must parse");
        assert_eq!(policy.allow_signing, vec!["git.example.com".to_string()]);
    }

    #[test]
    fn a_wildcard_with_csv_ports_becomes_one_allow_port_line_each() {
        // The proxy's allow_port arm takes a single port or range, so a list
        // has to be split before it is written.
        let agents_md = "```agent-sandbox\n\
             [network]\n\
             allowed_hosts = [\"*:80,443\"]\n\
             ```\n";
        let policy = parse_proxy(agents_md).expect("AGENTS.md must parse");
        assert_eq!(policy.allow_port, vec!["80".to_string(), "443".to_string()]);

        let text = format_proxy_policy(&policy, "AGENTS.md");
        assert!(text.contains("allow_port 80\n"), "{text}");
        assert!(text.contains("allow_port 443\n"), "{text}");
        parse_policy(&text)
            .unwrap_or_else(|e| panic!("the proxy rejected a split allow_port: {e}\n{text}"));
    }

    #[test]
    fn the_exit_summary_round_trips_csv_ports() {
        // `ctl proxy allow github.com:22,443` writes one line, and the exit
        // summary renders every live rule back as [network] TOML. That TOML
        // has to be something AGENTS.md accepts, or the advice it prints is
        // advice that does not work.
        let cfg = parse_policy("allow_host github.com:22,443\ndefault deny\n").expect("policy");
        let toml = format_policy_as_network_toml(&cfg);
        assert!(toml.contains("github.com:22,443"), "{toml}");

        let fenced = format!("```toml agent-sandbox\n{}```\n", toml);
        let policy = parse_proxy(&fenced).unwrap_or_else(|e| {
            panic!("AGENTS.md rejected the exit summary's own TOML: {e}\n{toml}")
        });
        assert_eq!(policy.allow_signing, vec!["github.com".to_string()]);
    }

    #[test]
    fn a_port_spec_has_to_name_at_least_one_port() {
        // `split_list` drops empty elements, so without an explicit check
        // "github.com:" compiles to a line the proxy reads as a literal domain.
        for bad in ["github.com:", "github.com:22,", "github.com:,443"] {
            let agents_md = format!(
                "```agent-sandbox\n[network]\nallowed_hosts = [\"{}\"]\n```\n",
                bad
            );
            assert!(
                parse_proxy(&agents_md).is_err(),
                "'{}' should not compile",
                bad
            );
        }
    }

    #[test]
    fn is_ip_or_cidr_distinguishes_ips_from_domains() {
        assert!(is_ip_or_cidr("10.0.0.0/8"));
        assert!(is_ip_or_cidr("169.254.169.254"));
        assert!(!is_ip_or_cidr("example.com"));
    }

    #[test]
    fn parses_plain_proxy_profiles_with_network_vocabulary() {
        let policy = parse_proxy_profile(
            "[network]\nallowed_hosts = [\"github.com:443\"]\n\n[[network.allowed_routes]]\nhost = \"api.github.com:443\"\nmethod = \"GET\"\npath = \"/user/repos\"\n",
        )
        .unwrap();
        assert_eq!(
            policy.allow_host,
            vec!["github.com:443", "api.github.com:443"]
        );
        assert_eq!(policy.allow_route, vec!["api.github.com\tGET\t/user/repos"]);
    }

    #[test]
    fn merging_profiles_is_additive_and_deduplicates_rules() {
        let mut first =
            parse_proxy_profile("[network]\nallowed_hosts = [\"github.com:443\"]\n").unwrap();
        let second = parse_proxy_profile(
            "[network]\nallowed_hosts = [\"github.com:443\", \"pypi.org:443\"]\n",
        )
        .unwrap();
        first.merge(second);
        assert_eq!(first.allow_host, vec!["github.com:443", "pypi.org:443"]);
    }
}
