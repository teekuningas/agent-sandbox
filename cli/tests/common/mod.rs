//! A throwaway world for driving the launcher without a container runtime.
//!
//! Everything the launcher reads from its environment -- `$HOME`,
//! `$XDG_RUNTIME_DIR`, the working directory, the agent catalog, the image
//! reference -- is already an environment variable or the cwd, and every
//! container operation goes through `podman` resolved on `$PATH`.  Put a stub
//! `podman` first on `$PATH` and the whole flag -> `podman run` mapping becomes
//! observable as recorded argv, which is the layer this project cannot cover in
//! a Nix build and could not cover in a unit test either.
//!
//! What this does *not* cover, on purpose: anything whose answer comes from a
//! real container -- egress through the proxy, the relays, krun, published
//! ports actually carrying traffic.  Those live in `tests/integration/`.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The agent catalog the launcher falls back to when `AGENT_SANDBOX_AGENT_SPECS`
/// is unset, pinned here so a change to `agents.nix` cannot silently rewrite
/// what these tests assert.
pub const TEST_AGENT_SPECS: &str = concat!(
    "opencode\t[\"opencode\",\".\"]\t[\".local/share/opencode\",\".config/opencode\"]\t[]\n",
    "claude\t[\"claude\"]\t[\".claude\"]\t[\".claude.json\"]",
);

pub const TEST_IMAGE: &str = "localhost/agent-sandbox:test";

/// The stub. Records every call, then answers from a canned reply if one was
/// registered for the subcommand and exits 0 otherwise.
///
/// The reply key is the first argument, or the first two joined by `-` when the
/// second is not a flag: `podman image exists` keys on `image-exists`, while
/// `podman ps -a ...` keys on `ps`.
const STUB_PODMAN: &str = r#"#!/bin/sh
{
  for a in "$@"; do printf '%s\n' "$a"; done
  printf '%s\n' '=== end of call ==='
} >> "$STUB_PODMAN_LOG"

# Stand in for the sidecar's readiness handshake.  The launcher waits up to 35s
# for a `ready` file in the directory it bind-mounts at /sidecar_shared, so a
# stub that never writes one turns every --proxy test into a 35s timeout.  The
# mount argument names the directory, so the stub can answer from its own argv.
if [ "$1" = run ]; then
  for a in "$@"; do
    case "$a" in
      */sidecar_shared:rw)
        : > "${a%%:*}/ready"
        ;;
      # The launcher's cleanup removes the policy and secret directories on the
      # way out, so a test that wants to see what the sidecar was handed has to
      # be given a copy at the moment it was handed over.
      */sidecar_policy:ro|*/sidecar_secrets:ro)
        src="${a%%:*}"
        dest="$STUB_PODMAN_CAPTURE/$(basename "${a#*:}" | cut -d: -f1)"
        mkdir -p "$dest"
        cp -a "$src"/. "$dest"/ 2>/dev/null || true
        ;;
    esac
  done
fi

key="$1"
case "$2" in
  ''|-*) ;;
  *) key="$1-$2" ;;
esac

for k in "$key" "$1"; do
  if [ -f "$STUB_PODMAN_REPLIES/$k.out" ]; then
    cat "$STUB_PODMAN_REPLIES/$k.out"
    if [ -f "$STUB_PODMAN_REPLIES/$k.code" ]; then
      exit "$(cat "$STUB_PODMAN_REPLIES/$k.code")"
    fi
    exit 0
  fi
  if [ -f "$STUB_PODMAN_REPLIES/$k.code" ]; then
    exit "$(cat "$STUB_PODMAN_REPLIES/$k.code")"
  fi
done
exit 0
"#;

pub struct World {
    root: PathBuf,
    /// Kept so the temp dir outlives the test.
    _tmp: tempfile::TempDir,
    env: Vec<(String, String)>,
}

impl World {
    pub fn new() -> Self {
        // Short prefix: `--host-loopback-port` refuses an `$XDG_RUNTIME_DIR`
        // whose sockets would not fit sockaddr_un's 108 bytes, and the default
        // temp name plus a per-session subdirectory gets close enough to that
        // to matter on some builders.
        let tmp = tempfile::Builder::new()
            .prefix("as-t")
            .tempdir()
            .expect("temp dir");
        let root = tmp.path().to_path_buf();
        for sub in ["bin", "home", "run", "ws", "replies", "capture"] {
            fs::create_dir_all(root.join(sub)).expect("scaffold");
        }

        let podman = root.join("bin/podman");
        fs::write(&podman, STUB_PODMAN).expect("write stub");
        make_executable(&podman);

        let path = format!(
            "{}:{}",
            root.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );

        let env = vec![
            ("PATH".into(), path),
            ("HOME".into(), root.join("home").display().to_string()),
            (
                "XDG_RUNTIME_DIR".into(),
                root.join("run").display().to_string(),
            ),
            ("AGENT_SANDBOX_IMAGE".into(), TEST_IMAGE.into()),
            ("AGENT_SANDBOX_AGENT_SPECS".into(), TEST_AGENT_SPECS.into()),
            (
                "STUB_PODMAN_LOG".into(),
                root.join("podman.log").display().to_string(),
            ),
            (
                "STUB_PODMAN_REPLIES".into(),
                root.join("replies").display().to_string(),
            ),
            (
                "STUB_PODMAN_CAPTURE".into(),
                root.join("capture").display().to_string(),
            ),
            // Deterministic rendering: the launcher forwards both into the
            // container, and COLORTERM is only forwarded when it is set.
            ("TERM".into(), "xterm-256color".into()),
            ("COLORTERM".into(), String::new()),
        ];

        World {
            root,
            _tmp: tmp,
            env,
        }
    }

    pub fn workspace(&self) -> PathBuf {
        self.root.join("ws")
    }

    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    pub fn runtime_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    /// A snapshot of a directory the launcher mounted into the sidecar, taken
    /// by the stub at mount time. The launcher's cleanup removes the originals,
    /// so this is the only way to see what the proxy was actually handed.
    ///
    /// `name` is the container-side directory: `sidecar_policy` or
    /// `sidecar_secrets`.
    pub fn captured(&self, name: &str) -> PathBuf {
        self.root.join("capture").join(name)
    }

    /// Overwrite or add an environment variable for the launcher.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.retain(|(k, _)| k != key);
        self.env.push((key.into(), value.into()));
        self
    }

    /// Write a file into the workspace, creating parent directories.
    pub fn file(self, rel: &str, contents: &str) -> Self {
        let path = self.workspace().join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent");
        }
        fs::write(path, contents).expect("write workspace file");
        self
    }

    /// Write a file under the fake `$HOME`.
    pub fn home_file(self, rel: &str, contents: &str) -> Self {
        let path = self.home().join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent");
        }
        fs::write(path, contents).expect("write home file");
        self
    }

    /// Teach the stub what to print, and what to exit with, for a subcommand.
    pub fn podman_reply(self, key: &str, stdout: &str, exit_code: i32) -> Self {
        let dir = self.root.join("replies");
        fs::write(dir.join(format!("{}.out", key)), stdout).expect("reply stdout");
        fs::write(dir.join(format!("{}.code", key)), exit_code.to_string()).expect("reply code");
        self
    }

    /// Put an executable of our own first on `$PATH`, the same trick the
    /// `podman` stub uses.  `script` is a whole shell script, `#!` line and all.
    ///
    /// For the commands the launcher shells out to that are not podman: the
    /// host browser's Chromium and its proxy, `gpgconf`, and whatever the next
    /// one turns out to be.
    pub fn stub_bin(self, name: &str, script: &str) -> Self {
        let path = self.root.join("bin").join(name);
        fs::write(&path, script).expect("write stub binary");
        make_executable(&path);
        self
    }

    /// Stub `gpgconf` to report a fake agent socket under the test's
    /// `$XDG_RUNTIME_DIR`, and create that socket file so `--gpg` finds a live
    /// agent to forward.
    pub fn gpg_agent_forwarded(self) -> Self {
        let socket = self.runtime_dir().join("gnupg/S.gpg-agent");
        fs::create_dir_all(socket.parent().expect("socket parent")).expect("gpg socket dir");
        fs::write(&socket, "").expect("stub gpg socket");

        let script = format!("#!/bin/sh\necho '{}'\n", socket.display());
        self.stub_bin("gpgconf", &script)
    }

    pub fn run(&self, args: &[&str]) -> Outcome {
        self.run_bin("agent-sandbox", args)
    }

    pub fn run_bin(&self, bin: &str, args: &[&str]) -> Outcome {
        // Truncated per run so a `World` can be reused across several launches
        // and each `Outcome` sees only its own calls.
        let log = self.root.join("podman.log");
        fs::write(&log, "").expect("reset call log");

        let exe = bin_path(bin);
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .current_dir(self.workspace())
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));

        let out = cmd.output().expect("launcher runs");
        Outcome {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            calls: read_calls(&self.root.join("podman.log")),
        }
    }
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path).expect("stat stub").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod stub");
}

/// Integration tests get the built binaries' paths from Cargo, so the test runs
/// against exactly the binary this build produced.
fn bin_path(name: &str) -> PathBuf {
    match name {
        "agent-sandbox" => PathBuf::from(env!("CARGO_BIN_EXE_agent-sandbox")),
        other => panic!("no CARGO_BIN_EXE path wired up for {}", other),
    }
}

fn read_calls(log: &Path) -> Vec<Vec<String>> {
    let text = fs::read_to_string(log).unwrap_or_default();
    let mut calls = Vec::new();
    let mut current = Vec::new();
    for line in text.lines() {
        if line == "=== end of call ===" {
            calls.push(std::mem::take(&mut current));
        } else {
            current.push(line.to_string());
        }
    }
    calls
}

pub struct Outcome {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// Every `podman` invocation the launcher made, in order.
    pub calls: Vec<Vec<String>>,
}

impl Outcome {
    /// The sandbox's own `podman run` argv, which is the thing most of these
    /// tests are about. Selected by role label rather than by position: under
    /// `--proxy` the sidecar is started with `podman run` first, from the same
    /// image, and picking the wrong one silently inverts every assertion.
    pub fn run_call(&self) -> Argv<'_> {
        self.role_call("sandbox").unwrap_or_else(|| {
            panic!(
                "the launcher never reached the sandbox's `podman run`\n--- stderr ---\n{}\n--- calls ---\n{:?}",
                self.stderr, self.calls
            )
        })
    }

    /// The proxy sidecar's `podman run` argv, when one was started.
    pub fn sidecar_call(&self) -> Option<Argv<'_>> {
        self.role_call("proxy")
    }

    fn role_call(&self, role: &str) -> Option<Argv<'_>> {
        let label = format!("agent-sandbox.role={}", role);
        self.calls
            .iter()
            .find(|c| c.first().map(String::as_str) == Some("run") && c.contains(&label))
            .map(Argv)
    }

    pub fn reached_podman_run(&self) -> bool {
        self.role_call("sandbox").is_some()
    }

    /// The first call whose argv starts with the given words.
    pub fn call_starting(&self, prefix: &[&str]) -> Option<Argv<'_>> {
        self.calls
            .iter()
            .find(|c| c.len() >= prefix.len() && c[..prefix.len()] == *prefix)
            .map(Argv)
    }

    pub fn failed(&self) -> bool {
        self.code != Some(0)
    }
}

/// A recorded argv, with the accessors these assertions keep needing.
pub struct Argv<'a>(pub &'a Vec<String>);

impl Argv<'_> {
    /// Every value that follows an occurrence of `flag`.
    pub fn values_of(&self, flag: &str) -> Vec<&str> {
        self.0
            .windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].as_str())
            .collect()
    }

    /// The single value following `flag`, or None. Panics if `flag` repeats,
    /// which is a real bug in a test that assumed it could not.
    pub fn value_of(&self, flag: &str) -> Option<&str> {
        let all = self.values_of(flag);
        assert!(all.len() <= 1, "{} appears {} times", flag, all.len());
        all.first().copied()
    }

    pub fn has(&self, arg: &str) -> bool {
        self.0.iter().any(|a| a == arg)
    }

    /// Is `flag value` present as an adjacent pair?
    pub fn has_pair(&self, flag: &str, value: &str) -> bool {
        self.values_of(flag).contains(&value)
    }

    /// The `-v` mount whose container-side destination is `dest`, if any.
    pub fn mount_to(&self, dest: &str) -> Option<&str> {
        self.values_of("-v")
            .into_iter()
            .find(|m| m.split(':').nth(1) == Some(dest))
    }

    /// The value of an `-e NAME=VALUE` pair.
    pub fn env_value(&self, name: &str) -> Option<&str> {
        let prefix = format!("{}=", name);
        self.values_of("-e")
            .into_iter()
            .find(|e| e.starts_with(&prefix))
            .map(|e| &e[prefix.len()..])
    }

    /// Everything after the image reference: the command the agent runs.
    pub fn command(&self) -> Vec<&str> {
        match self.0.iter().position(|a| a == TEST_IMAGE) {
            Some(idx) => self.0[idx + 1..].iter().map(String::as_str).collect(),
            None => Vec::new(),
        }
    }

    pub fn joined(&self) -> String {
        self.0.join(" ")
    }
}
