#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GpgScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
pub enum GpgScanStatus {
    Safe,
    Unsafe(Vec<PathBuf>),
}

pub fn scan_gnupg_home(gnupg_home: &Path) -> Result<GpgScanStatus, GpgScanError> {
    if !gnupg_home.is_dir() {
        return Ok(GpgScanStatus::Safe);
    }

    let mut offenders = Vec::new();

    let private_dir = gnupg_home.join("private-keys-v1.d");
    if private_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&private_dir) {
            let mut paths: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
                .map(|e| e.path())
                .collect();
            paths.sort();

            for path in paths {
                let mut buf = [0; 256];
                use std::io::Read;
                let mut is_unsafe = true; // Default to unsafe
                if let Ok(mut f) = fs::File::open(&path) {
                    let bytes_read = f.read(&mut buf).unwrap_or(0);
                    let content = &buf[..bytes_read];

                    let mut header = String::with_capacity(bytes_read);
                    for &b in content {
                        if b != 0 {
                            header.push(b as char);
                        }
                    }

                    // Equivalent to `tr -s ' \t\n' ' '`
                    let mut squeezed = String::with_capacity(header.len());
                    let mut last_was_space = false;
                    for c in header.chars() {
                        if c == ' ' || c == '\t' || c == '\n' {
                            if !last_was_space {
                                squeezed.push(' ');
                                last_was_space = true;
                            }
                        } else {
                            squeezed.push(c);
                            last_was_space = false;
                        }
                    }

                    if squeezed.contains("(protected-private-key") {
                        is_unsafe = true;
                    } else if squeezed.contains("(shadowed-private-key") {
                        is_unsafe = false;
                    } else if squeezed.contains("(private-key") {
                        is_unsafe = true;
                    } else {
                        is_unsafe = true; // Anything unrecognised counts as unsafe
                    }
                }

                if is_unsafe {
                    offenders.push(path);
                }
            }
        }
    }

    let legacy_secring = gnupg_home.join("secring.gpg");
    if let Ok(metadata) = fs::metadata(&legacy_secring) {
        if metadata.is_file() && metadata.len() > 0 {
            offenders.push(legacy_secring);
        }
    }

    if offenders.is_empty() {
        Ok(GpgScanStatus::Safe)
    } else {
        Ok(GpgScanStatus::Unsafe(offenders))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GnuPG home containing the named key files under `private-keys-v1.d`.
    fn gnupg_home(keys: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        let private = dir.path().join("private-keys-v1.d");
        fs::create_dir_all(&private).expect("private-keys-v1.d");
        for (name, body) in keys {
            fs::write(private.join(name), body).expect("write key");
        }
        dir
    }

    fn offenders(status: GpgScanStatus) -> Vec<String> {
        match status {
            GpgScanStatus::Safe => Vec::new(),
            GpgScanStatus::Unsafe(paths) => paths
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect(),
        }
    }

    fn scan(dir: &tempfile::TempDir) -> Vec<String> {
        offenders(scan_gnupg_home(dir.path()).expect("scan"))
    }

    #[test]
    fn a_gnupg_home_that_does_not_exist_is_nothing_to_expose() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("no-such-home");

        assert!(scan_gnupg_home(&missing).is_ok());
        assert!(offenders(scan_gnupg_home(&missing).unwrap()).is_empty());
    }

    #[test]
    fn an_empty_gnupg_home_is_safe() {
        assert!(scan(&gnupg_home(&[])).is_empty());
    }

    #[test]
    fn a_shadowed_key_is_safe_because_the_secret_lives_elsewhere() {
        // What a smartcard or a forwarded agent leaves behind: a stub that
        // names the key without carrying it.
        let dir = gnupg_home(&[("stub.key", b"(shadowed-private-key (rsa (n #00A1#)))")]);

        assert!(
            scan(&dir).is_empty(),
            "a shadowed stub is the case --gpg exists to support"
        );
    }

    #[test]
    fn a_passphrase_protected_key_is_still_a_key_on_disk() {
        let dir = gnupg_home(&[(
            "protected.key",
            b"(protected-private-key (rsa (n #00A1#) (protected openpgp-s2k3-sha1-aes-cbc)))",
        )]);

        assert_eq!(
            scan(&dir),
            vec!["protected.key"],
            "a passphrase is not a boundary the sandbox can enforce"
        );
    }

    #[test]
    fn an_unprotected_key_is_unsafe() {
        let dir = gnupg_home(&[("bare.key", b"(private-key (rsa (n #00A1#) (d #00B2#)))")]);

        assert_eq!(scan(&dir), vec!["bare.key"]);
    }

    #[test]
    fn an_unrecognised_file_counts_against_the_home_rather_than_being_waved_through() {
        let dir = gnupg_home(&[("mystery.key", b"\x01\x02\x03 not an s-expression")]);

        assert_eq!(
            scan(&dir),
            vec!["mystery.key"],
            "the scan decides whether to expose a key: unknown must fail closed"
        );
    }

    #[test]
    fn a_header_split_across_whitespace_is_still_recognised() {
        // GnuPG writes these canonically, but the format permits the newlines
        // and the scan squeezes whitespace before matching for that reason.
        let dir = gnupg_home(&[("wrapped.key", b"(shadowed-private-key\n\t(rsa\n (n #00A1#)))")]);

        assert!(scan(&dir).is_empty());
    }

    #[test]
    fn one_unsafe_key_among_safe_ones_is_reported_on_its_own() {
        let dir = gnupg_home(&[
            ("a-stub.key", b"(shadowed-private-key (rsa))"),
            ("b-real.key", b"(protected-private-key (rsa))"),
            ("c-stub.key", b"(shadowed-private-key (rsa))"),
        ]);

        assert_eq!(
            scan(&dir),
            vec!["b-real.key"],
            "the message has to name the file the user must deal with"
        );
    }

    #[test]
    fn a_non_empty_legacy_secring_is_unsafe() {
        let dir = gnupg_home(&[]);
        fs::write(dir.path().join("secring.gpg"), b"\x95\x03\x0c").expect("secring");

        assert_eq!(scan(&dir), vec!["secring.gpg"]);
    }

    #[test]
    fn an_empty_legacy_secring_is_the_leftover_file_modern_gnupg_keeps() {
        let dir = gnupg_home(&[]);
        fs::write(dir.path().join("secring.gpg"), b"").expect("secring");

        assert!(
            scan(&dir).is_empty(),
            "GnuPG 2.1+ leaves a zero-length secring.gpg behind; it holds nothing"
        );
    }

    #[test]
    fn subdirectories_of_private_keys_are_not_mistaken_for_keys() {
        let dir = gnupg_home(&[]);
        fs::create_dir_all(dir.path().join("private-keys-v1.d/subdir")).expect("subdir");

        assert!(scan(&dir).is_empty());
    }
}
