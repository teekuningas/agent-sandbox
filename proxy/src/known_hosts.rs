//! Host keys for the git forges, as published by them.
//!
//! Public vendor data, kept in the binary rather than fetched or trusted on
//! first use: an SSH session inside a sandbox is non-interactive, so the
//! alternative to knowing a key in advance is not a prompt but either a hard
//! failure or a silent TOFU accept of whatever answered.
//!
//! **This is not a trust anchor under `--proxy`.** There, the trusted set is
//! exactly what the operator authorized in `trusted.toml`, and this const only
//! supplies the ready-to-paste key in the refusal that asks them to. It is
//! still the seed for an unproxied session, which has no policy to authorize
//! against and no egress restriction to protect.

/// `known_hosts` lines for github.com, gitlab.com and bitbucket.org.
pub const FORGE_KNOWN_HOSTS: &str = "\
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=\n\
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n\
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=\n\
gitlab.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=\n\
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf\n\
gitlab.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9\n\
bitbucket.org ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIQmuzMBuKdWeF4+a2sjSSpBK0iqitSQ+5BM9KhpexuGt20JpTVM7u5BDZngncgrqDMbWdxMWWOGtZ9UgbqgZE=\n\
bitbucket.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO\n\
bitbucket.org ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQeJzhupRu0u0cdegZIa8e86EG2qOCsIsD1Xw0xSeiPDlCr7kq97NLmMbpKTX6Esc30NuoqEEHCuc7yWtwp8dI76EEEB1VqY9QJq6vk+aySyboD5QF61I/1WeTwu+deCbgKMGbUijeXhtfbxSxm6JwGrXrhBdofTsbKRUsrN1WoNgUa8uqN1Vx6WAJw1JHPhglEGGHea6QICwJOAr/6mrui/oB7pkaWKHj3z7d1IC4KWLtY47elvjbaTlkN04Kc/5LFEirorGYVbt15kAUlqGM65pk6ZBxtaO3+30LVlORZkxOh+LKL/BvbZ/iRNhItLqNyieoQj/uh/7Iv4uyH/cV/0b4WDSd3DptigWq84lJubb9t/DnZlrJazxyDCulTmKdOR7vs9gMTo+uoIrPSb8ScTtvw65+odKAlBj59dhnVp9zd7QUojOpXlL62Aw56U4oO+FALuevvMjiWeavKhJqlR7i5n9srYcrNV7ttmDw7kf/97P5zauIhxcjX+xHv4M=\n\
";

/// The `<type> <base64>` keys published for `host`, or empty when it is not one
/// of the forges above.
///
/// Used to fill in the block the launcher prints when a policy authorizes SSH
/// to a host the operator has not yet trusted: for the common case that turns
/// the refusal into one copy-paste instead of a `ssh-keyscan` round trip.
pub fn pinned_keys_for(host: &str) -> Vec<&'static str> {
    let host = host.trim().to_ascii_lowercase();
    FORGE_KNOWN_HOSTS
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter(|(pattern, _)| *pattern == host)
        .map(|(_, key)| key)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_blob_covers_the_forges_the_docs_name() {
        for host in ["github.com", "gitlab.com", "bitbucket.org"] {
            assert!(
                FORGE_KNOWN_HOSTS.contains(host),
                "{} is missing from the published keys",
                host
            );
        }
        // known_hosts is line-oriented; a blob without a trailing newline
        // corrupts whatever is appended after it.
        assert!(FORGE_KNOWN_HOSTS.ends_with('\n'));
        for line in FORGE_KNOWN_HOSTS.lines() {
            assert_eq!(
                line.split_whitespace().count(),
                3,
                "not a host/type/key triple: {}",
                line
            );
        }
    }

    #[test]
    fn every_forge_has_keys_and_nothing_else_does() {
        for host in ["github.com", "gitlab.com", "bitbucket.org"] {
            assert_eq!(
                pinned_keys_for(host).len(),
                3,
                "{host} should have ecdsa, ed25519 and rsa"
            );
        }
        assert!(pinned_keys_for("git.example.com").is_empty());
        // The apex only -- a subdomain is a different host key.
        assert!(pinned_keys_for("gist.github.com").is_empty());
    }

    #[test]
    fn the_keys_are_returned_without_the_host() {
        let keys = pinned_keys_for("GitHub.com");
        assert!(!keys.is_empty());
        for key in keys {
            assert!(!key.starts_with("github.com"), "{key}");
            let mut fields = key.split_whitespace();
            assert!(fields.next().unwrap().starts_with("ssh-") || fields.clone().count() > 0);
            assert!(fields.next().is_some(), "no key material in {key:?}");
        }
    }
}
