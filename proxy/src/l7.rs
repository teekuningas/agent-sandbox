pub fn glob_match(path: &str, pattern: &str) -> bool {
    let mut p_idx = 0;
    let mut pat_idx = 0;
    let p_bytes = path.as_bytes();
    let pat_bytes = pattern.as_bytes();

    let mut star_idx: Option<usize> = None;
    let mut match_idx: Option<usize> = None;

    while p_idx < p_bytes.len() {
        if pat_idx < pat_bytes.len() && pat_bytes[pat_idx] == b'*' {
            if pat_idx + 1 < pat_bytes.len() && pat_bytes[pat_idx + 1] == b'*' {
                // ** matches across slashes
                star_idx = Some(pat_idx + 2);
                match_idx = Some(p_idx);
                pat_idx += 2;
                continue;
            } else {
                // * matches within a path segment
                star_idx = Some(pat_idx + 1);
                match_idx = Some(p_idx);
                pat_idx += 1;
                continue;
            }
        }

        if pat_idx < pat_bytes.len() && p_bytes[p_idx] == pat_bytes[pat_idx] {
            p_idx += 1;
            pat_idx += 1;
            continue;
        }

        if let Some(s_idx) = star_idx {
            // If it was a single *, we cannot consume a slash
            if pat_bytes[s_idx - 1] == b'*' && (s_idx < 2 || pat_bytes[s_idx - 2] != b'*') {
                if p_bytes[match_idx.unwrap()] == b'/' {
                    return false;
                }
            }
            pat_idx = s_idx;
            let m_idx = match_idx.unwrap() + 1;
            match_idx = Some(m_idx);
            p_idx = m_idx;
            continue;
        }
        return false;
    }

    while pat_idx < pat_bytes.len() && pat_bytes[pat_idx] == b'*' {
        pat_idx += 1;
    }

    pat_idx == pat_bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("/foo/bar", "/*/*"));
        assert!(glob_match("/foo/bar", "/**"));
        assert!(!glob_match("/foo/bar/baz", "/*/*"));
        assert!(glob_match("/foo/bar/baz", "/*/**"));
        assert!(glob_match(
            "/user/repo.git/git-upload-pack",
            "/*/*.git/git-upload-pack"
        ));
    }
}
