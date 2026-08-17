#![forbid(unsafe_code)]
use crate::agents::parse_host_port;
use std::path::Path;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct SecretRule {
    pub host: String,
    pub method: String,
    pub path: String,
    pub secret: String,
    pub header: String,
    pub prefix: String,
}

impl SecretRule {
    pub fn matches_host_binding(&self, hb: &HostBinding) -> bool {
        let (self_domain, self_port) = parse_host_port(&self.host);
        let (hb_domain, hb_port) = parse_host_port(&hb.host);

        self_domain.to_lowercase() == hb_domain.to_lowercase()
            && self_port == hb_port
            && self.method.to_uppercase() == hb.method.to_uppercase()
            && self.path == hb.path
            && self.secret == hb.secret
            && self.header.to_lowercase() == hb.header.to_lowercase()
            && self.prefix == hb.prefix.as_deref().unwrap_or("")
    }
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct HostConfig {
    pub profile: Option<String>,
    pub provider: Option<String>,
    pub scope: Option<String>,
    #[serde(default, alias = "secret", alias = "secrets", alias = "rules")]
    pub bindings: Vec<HostBinding>,
}

#[derive(Debug, serde::Deserialize, Clone)]
pub struct HostBinding {
    #[serde(alias = "domain")]
    pub host: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default = "default_path")]
    pub path: String,
    pub secret: String,
    #[serde(default = "default_header")]
    pub header: String,
    pub prefix: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}
fn default_path() -> String {
    "/".to_string()
}
fn default_header() -> String {
    "Authorization".to_string()
}

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("empty domain")]
    EmptyDomain,
    #[error("malformed dot placement")]
    MalformedDotPlacement,
    #[error("contains invalid characters")]
    ContainsInvalidCharacters,
    #[error("must begin and end with an alphanumeric character")]
    InvalidStartEnd,
    #[error("contains non-token characters")]
    ContainsNonTokenCharacters,
    #[error("reserved header name")]
    ReservedHeaderName,
}

pub fn iter_tagged_blocks(content: &str) -> Vec<String> {
    use pulldown_cmark::{CodeBlockKind, Event, Parser, Tag};
    let mut blocks = Vec::new();
    let parser = Parser::new(content);
    let mut current_block = String::new();
    let mut in_target_block = false;

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(info))) => {
                let info_str = info.into_string();
                if info_str.split_whitespace().any(|s| s == "agent-sandbox") {
                    in_target_block = true;
                    current_block.clear();
                }
            }
            Event::Text(text) => {
                if in_target_block {
                    current_block.push_str(&text);
                }
            }
            Event::End(Tag::CodeBlock(_)) => {
                if in_target_block {
                    blocks.push(current_block.clone());
                    in_target_block = false;
                }
            }
            _ => {}
        }
    }
    blocks
}

pub fn get_requested_rules(workspace: &Path) -> Vec<SecretRule> {
    let mut requested_rules = Vec::new();
    if let Ok(content) = std::fs::read_to_string(workspace) {
        requested_rules.extend(requested_rules_from_agents(&content));
    }
    requested_rules
}

fn requested_rules_from_agents(content: &str) -> Vec<SecretRule> {
    let mut requested_rules = Vec::new();
    for block in iter_tagged_blocks(content) {
        requested_rules.extend(requested_rules_from_toml(&block));
    }
    requested_rules
}

fn requested_rules_from_toml(content: &str) -> Vec<SecretRule> {
    let mut requested_rules = Vec::new();
    if let Ok(block_data) = content.parse::<toml::Value>() {
        if let Some(network) = block_data.get("network").and_then(|v| v.as_table()) {
            if let Some(rules) = network.get("allowed_routes").and_then(|v| v.as_array()) {
                for rule in rules {
                    if let Some(rule_table) = rule.as_table() {
                        if let (Some(secret_val), Some(host_val)) =
                            (rule_table.get("secret"), rule_table.get("host"))
                        {
                            if let (Some(secret), Some(host)) =
                                (secret_val.as_str(), host_val.as_str())
                            {
                                let method = rule_table
                                    .get("method")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("GET");
                                let path = rule_table
                                    .get("path")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("/");
                                let header = rule_table
                                    .get("header")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Authorization");
                                let prefix = rule_table
                                    .get("prefix")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                requested_rules.push(SecretRule {
                                    host: host.to_string(),
                                    method: method.to_string(),
                                    path: path.to_string(),
                                    secret: secret.to_string(),
                                    header: header.to_string(),
                                    prefix: prefix.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    requested_rules
}

pub fn validate_domain(domain: &str) -> Result<(), ValidationError> {
    let bare = if let Some(base) = domain.strip_prefix("*.") {
        base
    } else {
        domain
    };
    if bare.is_empty() {
        return Err(ValidationError::EmptyDomain);
    }
    if bare.starts_with('.') || bare.ends_with('.') || bare.contains("..") {
        return Err(ValidationError::MalformedDotPlacement);
    }
    // ASCII, matching `proxy/src/secret.rs`: a Unicode-alphanumeric domain or
    // header used to pass here and then be rejected by the sidecar's parser,
    // which exits the proxy 2 on a config the launcher had just accepted.
    for c in bare.chars() {
        if !(c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') {
            return Err(ValidationError::ContainsInvalidCharacters);
        }
    }
    let chars: Vec<char> = bare.chars().collect();
    if !chars.first().unwrap().is_ascii_alphanumeric()
        || !chars.last().unwrap().is_ascii_alphanumeric()
    {
        return Err(ValidationError::InvalidStartEnd);
    }
    Ok(())
}

pub fn is_header_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

pub fn validate_header(header: &str) -> Result<(), ValidationError> {
    if !header.chars().all(is_header_char) {
        return Err(ValidationError::ContainsNonTokenCharacters);
    }
    let lower = header.to_lowercase();
    if lower == "host"
        || lower == "connection"
        || lower == "content-length"
        || lower == "transfer-encoding"
        || lower.starts_with("proxy-")
    {
        return Err(ValidationError::ReservedHeaderName);
    }
    Ok(())
}

/// One authorized route, as the policy file records it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SecretRoute {
    domain: String,
    method: String,
    path: String,
}

/// Read the `secret_route` routes out of a compiled policy file.
fn policy_secret_routes(policy: &Path) -> Vec<SecretRoute> {
    let mut routes = Vec::new();
    let Ok(text) = std::fs::read_to_string(policy) else {
        return routes;
    };
    for line in text.lines() {
        let Some(rest) = line.trim_end().strip_prefix("secret_route\t") else {
            continue;
        };
        let parts: Vec<&str> = rest.splitn(3, '\t').collect();
        if parts.len() == 3 {
            routes.push(SecretRoute {
                domain: parts[0].trim().to_lowercase(),
                method: parts[1].trim().to_string(),
                path: parts[2].to_string(),
            });
        }
    }
    routes
}

/// Resolve the bindings the policy's `secret_route` routes authorize, returning
/// one `domain\tmethod\tpath\theader\tvalue` line per binding.  The caller
/// decides where those go: the launcher writes them straight into the
/// sidecar's `bindings` file rather than through a pipe, so the values never
/// reach a terminal.
///
/// The route travels with the binding on purpose.  The host config authorizes
/// a secret for one `host`+`method`+`path`; carrying only the domain to the
/// proxy meant the rest of the authorization was verified and then thrown
/// away, and any other rule the repo's AGENTS.md allowed on that host
/// collected the same token.
pub fn resolve_secrets_logic(
    policy: &Path,
    config: &Path,
    file: &Path,
    workspace: &Path,
) -> anyhow::Result<Vec<String>> {
    resolve_secrets_logic_with_profiles(policy, config, file, workspace, &[])
}

pub fn resolve_secrets_logic_with_profiles(
    policy: &Path,
    config: &Path,
    file: &Path,
    workspace: &Path,
    profiles: &[std::path::PathBuf],
) -> anyhow::Result<Vec<String>> {
    let secret_routes = policy_secret_routes(policy);

    if secret_routes.is_empty() {
        return Ok(Vec::new());
    }

    let mut requested_rules = get_requested_rules(workspace);
    for profile in profiles {
        if let Ok(content) = std::fs::read_to_string(profile) {
            requested_rules.extend(requested_rules_from_toml(&content));
        }
    }

    let (host_config, _toml_val) = match std::fs::read_to_string(config) {
        Ok(c) => {
            let val: toml::Value = match toml::from_str(&c) {
                Ok(v) => v,
                Err(e) => {
                    anyhow::bail!(
                        "agent-sandbox: Secrets config at {} is malformed: {}",
                        config.display(),
                        e
                    );
                }
            };
            if let Some(bindings) = val.get("bindings") {
                if !bindings.is_array() {
                    anyhow::bail!("agent-sandbox: 'bindings' must be a list in secrets config");
                }
            }
            let mut host_config: HostConfig = match toml::from_str(&c) {
                Ok(v) => v,
                Err(e) => {
                    anyhow::bail!(
                        "agent-sandbox: Secrets config at {} is malformed: {}",
                        config.display(),
                        e
                    );
                }
            };

            // manually extract [[network.allowed_routes]] and add to bindings
            if let Some(network) = val.get("network").and_then(|v| v.as_table()) {
                if let Some(rules) = network.get("allowed_routes").and_then(|v| v.as_array()) {
                    for rule in rules {
                        if let Ok(hb) = rule.clone().try_into::<HostBinding>() {
                            host_config.bindings.push(hb);
                        }
                    }
                }
            }

            (host_config, val)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            HostConfig::default(),
            toml::Value::Table(Default::default()),
        ),
        Err(e) => {
            anyhow::bail!(
                "agent-sandbox: Secrets config at {} is malformed: {}",
                config.display(),
                e
            );
        }
    };

    let mut filtered_bindings = Vec::new();
    let mut seen_routes: Vec<SecretRoute> = Vec::new();

    let mut missing_rules = Vec::new();

    for req in requested_rules {
        let mut authorized = false;
        let mut matched_host_binding = None;

        for hb in &host_config.bindings {
            if req.matches_host_binding(hb) {
                authorized = true;
                matched_host_binding = Some(hb.clone());
                break;
            }
        }

        if !authorized {
            missing_rules.push(req);
            continue;
        }

        let hb = matched_host_binding.unwrap();
        let (hb_domain, _hb_port) = parse_host_port(&hb.host);
        let hb_domain = hb_domain.to_lowercase();

        if let Err(e) = validate_domain(&hb_domain) {
            anyhow::bail!(
                "agent-sandbox: Invalid domain '{}' in binding: {}",
                hb_domain,
                e
            );
        }

        if let Err(e) = validate_header(&hb.header) {
            anyhow::bail!(
                "agent-sandbox: Invalid header '{}' in binding: {}",
                hb.header,
                e
            );
        }

        let route = SecretRoute {
            domain: hb_domain.clone(),
            method: hb.method.to_uppercase(),
            path: hb.path.clone(),
        };

        // Only an exact repeat is unresolvable.  Two routes on one host --
        // which the old domain-overlap check refused outright, aborting any
        // launch with two secret rules for the same host -- are ordinary now
        // that injection is scoped to the route.
        if seen_routes.contains(&route) {
            anyhow::bail!(
                "agent-sandbox: duplicate secret binding for {} {} {}",
                route.domain,
                route.method,
                route.path
            );
        }

        if secret_routes.contains(&route) {
            filtered_bindings.push(hb);
            seen_routes.push(route);
        }
    }

    if !missing_rules.is_empty() {
        let mut err_msg = String::new();
        for req in missing_rules {
            err_msg.push_str(&format!(
                "agent-sandbox: selected network policy requests secret '{}' for rule:\n",
                req.secret
            ));
            err_msg.push_str(&format!(
                "               host = \"{}\", method = \"{}\", path = \"{}\"\n",
                req.host, req.method, req.path
            ));
            err_msg.push_str(&format!(
                "               but this secret definition is not authorized in {}.\n\n",
                config.display()
            ));
            err_msg.push_str(&format!("               To authorize this secret definition, add the following block to {}:\n\n", config.display()));
            // Keep the suggested TOML block flush-left so it can be copied
            // directly into trusted.toml without removing prompt indentation.
            err_msg.push_str("[[network.allowed_routes]]\n");
            err_msg.push_str(&format!("host = \"{}\"\n", req.host));
            err_msg.push_str(&format!("method = \"{}\"\n", req.method));
            err_msg.push_str(&format!("path = \"{}\"\n", req.path));
            err_msg.push_str(&format!("secret = \"{}\"\n", req.secret));
            err_msg.push_str(&format!("header = \"{}\"\n", req.header));
            err_msg.push_str(&format!("prefix = \"{}\"\n\n", req.prefix));
            err_msg.push_str("               Or remove 'secret' from the [[network.allowed_routes]] rule if it is not trusted.\n\n");
        }
        anyhow::bail!("{}", err_msg.trim_end());
    }

    if filtered_bindings.is_empty() {
        return Ok(Vec::new());
    }

    let mut cmd = Command::new("secretspec");
    cmd.args(["export", "--file"]);
    cmd.arg(file);
    cmd.args([
        "--format",
        "json",
        "--reason",
        "agent-sandbox secret injection",
    ]);

    if let Some(profile) = &host_config.profile {
        cmd.args(["--profile", profile]);
    }
    if let Some(provider) = &host_config.provider {
        cmd.args(["--provider", provider]);
    }
    if let Some(scope) = &host_config.scope {
        cmd.args(["--scope", scope]);
    }

    let output = match cmd.output() {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("agent-sandbox: secretspec executable not found\n");
        }
        Err(e) => {
            anyhow::bail!("agent-sandbox: secretspec export failed:\n{}\n", e);
        }
    };

    if !output.status.success() {
        anyhow::bail!(
            "agent-sandbox: secretspec export failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let secrets_data: serde_json::Value = match serde_json::from_str(&stdout_str) {
        Ok(v) => v,
        Err(e) => {
            anyhow::bail!(
                "agent-sandbox: secretspec output was not valid JSON: {}\n",
                e
            );
        }
    };

    let secrets_map = if let Some(map) = secrets_data.get("secrets").and_then(|s| s.as_object()) {
        map
    } else if let Some(map) = secrets_data.as_object() {
        map
    } else {
        anyhow::bail!("agent-sandbox: secretspec output was not a JSON object\n");
    };

    let mut lines = Vec::new();
    for b in filtered_bindings {
        let secret_name = &b.secret;
        let (domain, _port) = parse_host_port(&b.host);
        let domain = domain.to_lowercase();
        let method = b.method.to_uppercase();
        let path = &b.path;
        let header = &b.header;
        let prefix = b.prefix.clone().unwrap_or_default();

        if let Some(secret_value) = secrets_map.get(secret_name) {
            let val_str = if let Some(s) = secret_value.as_str() {
                s.to_string()
            } else {
                secret_value.to_string()
            };
            lines.push(format!(
                "{}\t{}\t{}\t{}\t{}{}",
                domain, method, path, header, prefix, val_str
            ));
        } else {
            anyhow::bail!(
                "agent-sandbox: secretspec output missing required secret '{}'\n",
                secret_name
            );
        }
    }

    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_secret_rule_matches() {
        let rule = SecretRule {
            host: "api.github.com:443".to_string(),
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            secret: "GITHUB_TOKEN".to_string(),
            header: "Authorization".to_string(),
            prefix: "Bearer ".to_string(),
        };

        // Exact match
        let mut hb = HostBinding {
            host: "api.github.com:443".to_string(),
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            secret: "GITHUB_TOKEN".to_string(),
            header: "Authorization".to_string(),
            prefix: Some("Bearer ".to_string()),
        };
        assert!(rule.matches_host_binding(&hb));

        // Missing port in HostBinding -> mismatch
        hb.host = "api.github.com".to_string();
        assert!(!rule.matches_host_binding(&hb));

        // Different method -> mismatch
        hb.host = "api.github.com:443".to_string();
        hb.method = "GET".to_string();
        assert!(!rule.matches_host_binding(&hb));

        // Different path -> mismatch
        hb.method = "POST".to_string();
        hb.path = "/v1".to_string();
        assert!(!rule.matches_host_binding(&hb));

        // Different secret -> mismatch
        hb.path = "/graphql".to_string();
        hb.secret = "OTHER_TOKEN".to_string();
        assert!(!rule.matches_host_binding(&hb));

        // Different header -> mismatch
        hb.secret = "GITHUB_TOKEN".to_string();
        hb.header = "X-Api-Key".to_string();
        assert!(!rule.matches_host_binding(&hb));

        // Different prefix -> mismatch
        hb.header = "Authorization".to_string();
        hb.prefix = Some("Basic ".to_string());
        assert!(!rule.matches_host_binding(&hb));
    }

    fn scratch(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, body) in files {
            std::fs::write(dir.path().join(name), body).expect("write");
        }
        dir
    }

    const AGENTS_TWO_RULES: &str = r#"
```agent-sandbox
[network]
allowed_hosts = ["api.github.com:443"]

[[network.allowed_routes]]
host = "api.github.com:443"
method = "GET"
path = "/user/repos"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "

[[network.allowed_routes]]
host = "api.github.com:443"
method = "POST"
path = "/graphql"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "
```
"#;

    const TRUSTED_TOML_TWO_RULES: &str = r#"
[[network.allowed_routes]]
host = "api.github.com:443"
method = "GET"
path = "/user/repos"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "

[[network.allowed_routes]]
host = "api.github.com:443"
method = "POST"
path = "/graphql"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "
"#;

    #[test]
    fn two_secret_rules_on_one_host_are_both_accepted() {
        // Regression: authorization used to be recorded per domain, and the
        // second rule tripped a domain-overlap check that aborted the launch --
        // so a host could carry at most one secret route.  Both are authorized
        // here, so the resolver must get as far as calling secretspec (which is
        // not installed in the test environment, hence the error we assert on)
        // rather than refusing the configuration itself.
        let dir = scratch(&[
            (
                "policy",
                "allow_host api.github.com:443\n\
                 secret_route\tapi.github.com\tGET\t/user/repos\n\
                 secret_route\tapi.github.com\tPOST\t/graphql\n",
            ),
            ("trusted.toml", TRUSTED_TOML_TWO_RULES),
            ("AGENTS.md", AGENTS_TWO_RULES),
            ("secretspec.toml", ""),
        ]);
        let err = resolve_secrets_logic(
            &dir.path().join("policy"),
            &dir.path().join("trusted.toml"),
            &dir.path().join("secretspec.toml"),
            &dir.path().join("AGENTS.md"),
        )
        .expect_err("secretspec is absent in tests")
        .to_string();
        assert!(
            !err.contains("overlaps"),
            "both rules must be authorized: {err}"
        );
        assert!(err.contains("secretspec"), "{err}");
    }

    #[test]
    fn a_rule_the_host_config_does_not_authorize_refuses_the_launch() {
        // AGENTS.md is untrusted: asking for a secret on a route the operator
        // never authorized must stop the launch and print the exact block to
        // paste, not silently inject nothing.
        let dir = scratch(&[
            (
                "policy",
                "allow_host api.github.com:443\n\
                 secret_route\tapi.github.com\tGET\t/user/repos\n\
                 secret_route\tapi.github.com\tPOST\t/graphql\n",
            ),
            (
                "trusted.toml",
                "[[network.allowed_routes]]\n\
                 host = \"api.github.com:443\"\n\
                 method = \"GET\"\n\
                 path = \"/user/repos\"\n\
                 secret = \"GITHUB_TOKEN\"\n\
                 header = \"Authorization\"\n\
                 prefix = \"Bearer \"\n",
            ),
            ("AGENTS.md", AGENTS_TWO_RULES),
            ("secretspec.toml", ""),
        ]);
        let err = resolve_secrets_logic(
            &dir.path().join("policy"),
            &dir.path().join("trusted.toml"),
            &dir.path().join("secretspec.toml"),
            &dir.path().join("AGENTS.md"),
        )
        .expect_err("the unauthorized POST rule must refuse the launch")
        .to_string();
        assert!(err.contains("not authorized"), "{err}");
        assert!(
            err.contains("/graphql"),
            "the message names the offending route: {err}"
        );
        assert!(
            err.contains(
                "\n[[network.allowed_routes]]\nhost = \"api.github.com:443\"\nmethod = \"POST\""
            ),
            "the suggested TOML block must be flush-left: {err}"
        );
    }

    #[test]
    fn a_policy_with_no_secret_routes_resolves_nothing() {
        let dir = scratch(&[
            ("policy", "allow_host api.github.com:443\n"),
            ("trusted.toml", TRUSTED_TOML_TWO_RULES),
            ("AGENTS.md", AGENTS_TWO_RULES),
            ("secretspec.toml", ""),
        ]);
        let lines = resolve_secrets_logic(
            &dir.path().join("policy"),
            &dir.path().join("trusted.toml"),
            &dir.path().join("secretspec.toml"),
            &dir.path().join("AGENTS.md"),
        )
        .expect("no secret routes is not an error");
        assert!(lines.is_empty());
    }

    #[test]
    fn test_get_requested_rules_parsing() {
        let content = r#"
```agent-sandbox
[network]
allowed_hosts = ["github.com:443"]

[[network.allowed_routes]]
host = "api.github.com:443"
method = "POST"
path = "/graphql"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "

[[network.allowed_routes]]
host = "registry.npmjs.org:443"
method = "GET"
path = "/*"
secret = "NPM_TOKEN"
```
"#;
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(content.as_bytes()).unwrap();

        let rules = get_requested_rules(tmp.path());
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].host, "api.github.com:443");
        assert_eq!(rules[0].method, "POST");
        assert_eq!(rules[0].path, "/graphql");
        assert_eq!(rules[0].secret, "GITHUB_TOKEN");
        assert_eq!(rules[0].header, "Authorization");
        assert_eq!(rules[0].prefix, "Bearer ");

        assert_eq!(rules[1].host, "registry.npmjs.org:443");
        assert_eq!(rules[1].method, "GET");
        assert_eq!(rules[1].path, "/*");
        assert_eq!(rules[1].secret, "NPM_TOKEN");
        assert_eq!(rules[1].header, "Authorization");
        assert_eq!(rules[1].prefix, "");
    }
}
