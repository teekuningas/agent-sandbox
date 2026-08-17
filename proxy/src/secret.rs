use std::fmt;
use std::fs::File;
use std::io::Read;

#[derive(Clone, Eq, PartialEq)]
pub struct Secret(String);

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// One authorized injection, scoped to the route the operator named in
/// `~/.config/agent-sandbox/trusted.toml`.  `method`/`path` are carried all the
/// way here rather than being checked host-side and discarded: they are what
/// stops a token authorized for one endpoint riding along on every other
/// request the repo's AGENTS.md happens to allow.
#[derive(Clone, Debug)]
pub struct SecretBinding {
    pub domain: String,
    pub method: String,
    pub path: String,
    pub header: String,
    pub value: Secret,
}

#[derive(Clone, Default, Debug)]
pub struct SecretBindings {
    entries: Vec<SecretBinding>,
}

impl SecretBindings {
    pub fn from_fd(fd: Option<i32>) -> Result<Self, String> {
        let Some(fd) = fd else {
            return Ok(Self::default());
        };
        if fd < 0 {
            return Err(format!("fd {} is negative", fd));
        }
        let mut body = String::new();
        File::open(format!("/proc/self/fd/{fd}"))
            .map_err(|e| format!("cannot open fd {}: {}", fd, e))?
            .read_to_string(&mut body)
            .map_err(|e| format!("cannot read fd {}: {}", fd, e))?;
        Self::parse(&body)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries: Vec<SecretBinding> = Vec::new();
        for (i, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim_end_matches('\r');
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let lineno = i + 1;
            const SHAPE: &str = "expected DOMAIN<TAB>METHOD<TAB>PATH<TAB>HEADER<TAB>VALUE";
            let mut parts = line.splitn(5, '\t');
            let domain = parts
                .next()
                .map(str::trim)
                .ok_or_else(|| format!("{lineno}: missing domain"))?;
            let method = parts
                .next()
                .map(str::trim)
                .ok_or_else(|| format!("{lineno}: {SHAPE}"))?;
            let path = parts
                .next()
                .map(str::trim)
                .ok_or_else(|| format!("{lineno}: {SHAPE}"))?;
            let header = parts
                .next()
                .map(str::trim)
                .ok_or_else(|| format!("{lineno}: {SHAPE}"))?;
            let value = parts.next().ok_or_else(|| format!("{lineno}: {SHAPE}"))?;

            if domain.is_empty() {
                return Err(format!("{lineno}: domain is empty"));
            }
            if header.is_empty() {
                return Err(format!("{lineno}: header is empty"));
            }
            if value.is_empty() {
                return Err(format!("{lineno}: value is empty"));
            }

            let domain = domain.to_ascii_lowercase();
            validate_domain(&domain)
                .map_err(|e| format!("{lineno}: invalid domain {:?}: {}", domain, e))?;
            validate_method(method)
                .map_err(|e| format!("{lineno}: invalid method {:?}: {}", method, e))?;
            validate_path(path)
                .map_err(|e| format!("{lineno}: invalid path {:?}: {}", path, e))?;
            validate_header(header)
                .map_err(|e| format!("{lineno}: invalid header {:?}: {}", header, e))?;
            // A bare CR in the value would split the header line when
            // `rewrite_head` writes it.  Never echo the value in the error.
            validate_value(value).map_err(|e| format!("{lineno}: invalid value: {}", e))?;

            // Overlapping routes are legitimate and resolved by
            // `binding_for_request`'s most-specific-wins; only an exact
            // duplicate is unresolvable.
            if entries
                .iter()
                .any(|e| e.domain == domain && e.method == method && e.path == path)
            {
                return Err(format!(
                    "{lineno}: duplicate binding for {} {} {}",
                    domain, method, path
                ));
            }

            entries.push(SecretBinding {
                domain,
                method: method.to_string(),
                path: path.to_string(),
                header: header.to_string(),
                value: Secret(value.to_string()),
            });
        }

        Ok(Self { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[SecretBinding] {
        &self.entries
    }

    /// The binding authorized for this exact request, or `None`.
    ///
    /// Most-specific-wins, in the same order the policy resolves a target:
    /// longest domain pattern first, then longest path pattern, then an exact
    /// method over `*`.  Two overlapping authorizations are therefore ordered
    /// rather than ambiguous -- `GET /user/repos` beats `GET /user/**` for a
    /// request to `/user/repos`.
    pub fn binding_for_request(
        &self,
        host: &str,
        method: &str,
        path: &str,
    ) -> Option<&SecretBinding> {
        let host = host.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                domain_match(&host, &e.domain)
                    && (e.method == method || e.method == "*")
                    && crate::l7::glob_match(path, &e.path)
            })
            .max_by_key(|e| (e.domain.len(), e.path.len(), usize::from(e.method != "*")))
    }
}

fn validate_method(method: &str) -> Result<(), &'static str> {
    if method == "*" {
        return Ok(());
    }
    if method.is_empty() || !method.chars().all(|c| c.is_ascii_uppercase()) {
        return Err("must be an uppercase HTTP method or '*'");
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/') {
        return Err("must start with '/'");
    }
    if path.chars().any(|c| c.is_ascii_control()) {
        return Err("contains a control character");
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<(), &'static str> {
    if value.chars().any(|c| c.is_ascii_control()) {
        return Err("contains a control character");
    }
    Ok(())
}

fn validate_domain(domain: &str) -> Result<(), &'static str> {
    let bare = domain.strip_prefix("*.").unwrap_or(domain);
    if bare.is_empty() {
        return Err("empty domain");
    }
    if bare.starts_with('.') || bare.ends_with('.') || bare.contains("..") {
        return Err("malformed dot placement");
    }
    if !bare
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return Err("contains invalid characters");
    }
    if !bare
        .chars()
        .next()
        .expect("non-empty")
        .is_ascii_alphanumeric()
        || !bare
            .chars()
            .last()
            .expect("non-empty")
            .is_ascii_alphanumeric()
    {
        return Err("must begin and end with an alphanumeric character");
    }
    Ok(())
}

fn is_header_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

fn validate_header(header: &str) -> Result<(), &'static str> {
    if !header.chars().all(is_header_char) {
        return Err("contains non-token characters");
    }
    let lower = header.to_ascii_lowercase();
    if lower == "host"
        || lower == "connection"
        || lower == "content-length"
        || lower == "transfer-encoding"
        || lower.starts_with("proxy-")
    {
        return Err("reserved header name");
    }
    Ok(())
}

fn domain_match(domain: &str, pattern: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(base) => domain == base || domain.ends_with(&pattern[1..]),
        None => domain == pattern,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let binding =
            SecretBindings::parse("api.example.com\tGET\t/user\tAuthorization\tBearer super-secret\n")
                .expect("parse");
        let dbg = format!("{:?}", binding);
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(!dbg.contains("super-secret"), "{dbg}");
    }

    #[test]
    fn parser_reads_tab_delimited_entries() {
        let parsed = SecretBindings::parse(
            "api.example.com\tGET\t/user\tAuthorization\tBearer abc\n\
             *.example.org\t*\t/**\tX-Api-Key\txyz\n",
        )
        .expect("parse");
        assert_eq!(parsed.len(), 2);
        let binding = parsed
            .binding_for_request("api.example.com", "GET", "/user")
            .expect("binding for api.example.com GET /user");
        assert_eq!(binding.header, "Authorization");
        assert_eq!(binding.value.as_str(), "Bearer abc");
    }

    #[test]
    fn parser_rejects_reserved_header_names() {
        let err = SecretBindings::parse("api.example.com\tGET\t/\tHost\tvalue\n").unwrap_err();
        assert!(err.contains("reserved header name"), "{err}");
    }

    #[test]
    fn parser_rejects_an_exact_duplicate_route() {
        let err = SecretBindings::parse(
            "api.example.com\tGET\t/user\tAuthorization\tone\n\
             api.example.com\tGET\t/user\tAuthorization\ttwo\n",
        )
        .unwrap_err();
        assert!(err.contains("duplicate binding"), "{err}");
    }

    #[test]
    fn overlapping_routes_are_ordered_not_rejected() {
        // Two authorizations on one host is an ordinary configuration now that
        // scoping is per route; the old parser refused it outright.
        let parsed = SecretBindings::parse(
            "api.example.com\tGET\t/user/**\tAuthorization\twide\n\
             api.example.com\tGET\t/user/repos\tAuthorization\tnarrow\n",
        )
        .expect("overlapping routes must parse");
        assert_eq!(
            parsed
                .binding_for_request("api.example.com", "GET", "/user/repos")
                .expect("narrow")
                .value
                .as_str(),
            "narrow"
        );
        assert_eq!(
            parsed
                .binding_for_request("api.example.com", "GET", "/user/orgs")
                .expect("wide")
                .value
                .as_str(),
            "wide"
        );
    }

    #[test]
    fn lookup_prefers_the_longer_domain_pattern() {
        let parsed = SecretBindings::parse(
            "*.example.com\tGET\t/\tAuthorization\twild\n\
             api.example.com\tGET\t/\tAuthorization\texact\n",
        )
        .expect("parse");
        assert_eq!(
            parsed
                .binding_for_request("api.example.com", "GET", "/")
                .expect("binding")
                .value
                .as_str(),
            "exact"
        );
        assert_eq!(
            parsed
                .binding_for_request("cdn.example.com", "GET", "/")
                .expect("binding")
                .value
                .as_str(),
            "wild"
        );
    }

    #[test]
    fn lookup_prefers_an_exact_method_over_a_wildcard() {
        let parsed = SecretBindings::parse(
            "api.example.com\t*\t/user\tAuthorization\tany\n\
             api.example.com\tPOST\t/user\tAuthorization\tpost\n",
        )
        .expect("parse");
        assert_eq!(
            parsed
                .binding_for_request("api.example.com", "POST", "/user")
                .expect("binding")
                .value
                .as_str(),
            "post"
        );
        assert_eq!(
            parsed
                .binding_for_request("api.example.com", "GET", "/user")
                .expect("binding")
                .value
                .as_str(),
            "any"
        );
    }

    #[test]
    fn a_request_outside_every_authorized_route_gets_nothing() {
        // The leak, as a unit test: an authorization for one endpoint must not
        // answer for another endpoint on the same host.
        let parsed =
            SecretBindings::parse("api.example.com\tGET\t/user/repos\tAuthorization\ttok\n")
                .expect("parse");
        assert!(parsed
            .binding_for_request("api.example.com", "GET", "/user/repos")
            .is_some());
        assert!(parsed
            .binding_for_request("api.example.com", "GET", "/zen")
            .is_none());
        assert!(parsed
            .binding_for_request("api.example.com", "POST", "/user/repos")
            .is_none());
        assert!(parsed
            .binding_for_request("other.example.com", "GET", "/user/repos")
            .is_none());
    }

    #[test]
    fn parser_rejects_a_value_that_would_split_the_header() {
        let err = SecretBindings::parse(
            "api.example.com\tGET\t/\tAuthorization\ttok\rX-Evil: 1\n",
        )
        .unwrap_err();
        assert!(err.contains("control character"), "{err}");
        assert!(!err.contains("tok"), "the error must not echo the value: {err}");
    }

    #[test]
    fn parser_rejects_a_malformed_method_or_path() {
        assert!(SecretBindings::parse("api.example.com\tget\t/\tAuthorization\tv\n")
            .unwrap_err()
            .contains("method"));
        assert!(SecretBindings::parse("api.example.com\tGET\tuser\tAuthorization\tv\n")
            .unwrap_err()
            .contains("path"));
    }
}
