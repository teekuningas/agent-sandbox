#![forbid(unsafe_code)]

use agent_sandbox_proxy::known_hosts::FORGE_KNOWN_HOSTS;
use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() -> Result<()> {
    // 1. nix-store load db
    let skip_nix_init = env::var("AGENT_SANDBOX_SKIP_NIX_INIT").unwrap_or_else(|_| "0".to_string());
    let host_nix = env::var("AGENT_SANDBOX_HOST_NIX").unwrap_or_default();
    if skip_nix_init != "1" && host_nix != "1" {
        let db_path = Path::new("/nix/var/nix/db/db.sqlite");
        let reg_path = Path::new("/nix/registration");
        if !db_path.exists() && reg_path.exists() {
            let file = fs::File::open(reg_path).context("Failed to open /nix/registration")?;
            let status = Command::new("nix-store")
                .arg("--load-db")
                .stdin(Stdio::from(file))
                .status();
            if let Err(e) = status {
                eprintln!("Warning: failed to run nix-store --load-db: {}", e);
            }
        }
    }

    let home = env::var("HOME").context("HOME not set")?;
    let home_path = PathBuf::from(&home);

    // 2. GPG setup
    if env::var("AGENT_SANDBOX_GPG_AGENT").unwrap_or_default() == "1"
        && Path::new("/run/host-gpg-agent").exists()
    {
        let gnupg_dir = home_path.join(".gnupg");
        fs::create_dir_all(&gnupg_dir)?;
        let mut perms = fs::metadata(&gnupg_dir)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&gnupg_dir, perms)?;

        let s_gpg_agent = gnupg_dir.join("S.gpg-agent");
        let _ = fs::remove_file(&s_gpg_agent);
        let _ = std::os::unix::fs::symlink("/run/host-gpg-agent", &s_gpg_agent);

        if io::stdin().is_terminal() {
            if let Ok(tty) = fs::read_link("/proc/self/fd/0") {
                env::set_var("GPG_TTY", tty);
            }
        }

        let host_gnupg = Path::new("/run/host-gnupg");
        if host_gnupg.is_dir() {
            if let Ok(entries) = fs::read_dir(host_gnupg) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let target = gnupg_dir.join(path.file_name().unwrap());
                        if !target.exists() {
                            let _ = fs::copy(&path, &target);
                        }
                    }
                }
            }
        }

        if env::var("AGENT_SANDBOX_GPG_RECV_KEY").unwrap_or_default() == "1" {
            let output = Command::new("git")
                .args(["config", "--get", "user.signingkey"])
                .output();
            if let Ok(out) = output {
                if out.status.success() {
                    let signing_key = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !signing_key.is_empty() {
                        let _ = Command::new("gpg")
                            .args([
                                "--keyserver",
                                "keyserver.ubuntu.com",
                                "--recv-keys",
                                &signing_key,
                            ])
                            .status();
                    }
                }
            }
        }
    }

    // 3. Known hosts
    // Unconditional: `ssh` can leave a sandbox by two different routes, and
    // the one that used to gate this -- a forwarded agent at /agent.sock --
    // is absent on both of the others.  Under --proxy the socket goes to the
    // sidecar instead, and under --proxy without --ssh the sandbox's own ssh
    // still goes out through the CONNECT proxy configured below.
    //
    // Under --proxy the launcher binds in the keys the operator authorized in
    // trusted.toml, and those are the whole trusted set -- the built-in forge
    // keys are not consulted, because a policy that named a host the operator
    // did not authorize would have been refused before the container started.
    // Without --proxy there is no policy to authorize against and no egress
    // restriction either, so the built-in keys stand in; they are public
    // vendor data, and the already-present check keeps a repeat run a no-op.
    //
    // This is the sandbox's copy.  Under --proxy --ssh the real ssh runs in
    // the sidecar and reads the same file from /sidecar_policy.
    {
        let ssh_dir = home_path.join(".ssh");
        fs::create_dir_all(&ssh_dir)?;
        let mut perms = fs::metadata(&ssh_dir)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&ssh_dir, perms)?;

        let known_hosts = ssh_dir.join("known_hosts");
        if known_hosts.exists() {
            let meta = fs::metadata(&known_hosts)?;
            if meta.permissions().readonly() {
                let mut p = meta.permissions();
                p.set_mode(0o644);
                if fs::set_permissions(&known_hosts, p).is_err() {
                    let _ = fs::remove_file(&known_hosts);
                }
            }
        }

        let seed = match env::var("AGENT_SANDBOX_KNOWN_HOSTS") {
            Ok(path) if !path.is_empty() => {
                fs::read_to_string(&path).unwrap_or_else(|_| String::new())
            }
            _ => FORGE_KNOWN_HOSTS.to_string(),
        };

        // Line-wise rather than "does it mention github.com": the authorized
        // set is whatever the operator wrote, and may name none of the forges.
        let existing = fs::read_to_string(&known_hosts).unwrap_or_default();
        let missing: Vec<&str> = seed
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter(|line| !existing.lines().any(|have| have.trim() == line.trim()))
            .collect();

        if !missing.is_empty() {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&known_hosts)?;
            for line in missing {
                writeln!(file, "{}", line)?;
            }
        }
    }

    // 4. HTTP_PROXY
    if let Ok(http_proxy) = env::var("HTTP_PROXY") {
        if !http_proxy.is_empty() {
            let ssh_dir = home_path.join(".ssh");
            fs::create_dir_all(&ssh_dir)?;
            let mut perms = fs::metadata(&ssh_dir)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&ssh_dir, perms)?;

            let ssh_config = ssh_dir.join("config");
            if !ssh_config.exists() && fs::symlink_metadata(&ssh_config).is_err() {
                let proxy_host_port = http_proxy.split("://").last().unwrap_or(&http_proxy);
                let mut parts = proxy_host_port.splitn(2, ':');
                let proxy_host = parts.next().unwrap_or("");
                let proxy_port = parts.next().unwrap_or("");

                // ssh takes the first value it sees for a keyword, so the
                // loopback exemption has to precede the catch-all.  Without it
                // a local ssh is sent to the sidecar, which refuses 127.0.0.1.
                let config_content = format!(
                    "Host localhost 127.0.0.1 ::1\n  ProxyCommand none\n\
                     Host *\n  ProxyCommand socat - PROXY:{proxy_host}:%h:%p,proxyport={proxy_port}\n"
                );
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&ssh_config)?;
                file.write_all(config_content.as_bytes())?;

                let mut p = fs::metadata(&ssh_config)?.permissions();
                p.set_mode(0o600);
                fs::set_permissions(&ssh_config, p)?;
            }

            if env::var("NODE_USE_ENV_PROXY").is_err() {
                env::set_var("NODE_USE_ENV_PROXY", "1");
            }
        }
    }

    // 5. CA bundle
    if let Ok(proxy_ca_file) = env::var("AGENT_SANDBOX_PROXY_CA_FILE") {
        if !proxy_ca_file.is_empty() {
            let proxy_ca_path = Path::new(&proxy_ca_file);
            if !proxy_ca_path.exists() {
                eprintln!(
                    "entrypoint: AGENT_SANDBOX_PROXY_CA_FILE is set but not readable: {}",
                    proxy_ca_file
                );
                std::process::exit(1);
            }

            let base_bundle = env::var("NIX_SSL_CERT_FILE")
                .or_else(|_| env::var("SSL_CERT_FILE"))
                .unwrap_or_else(|_| "/etc/ssl/certs/ca-bundle.crt".to_string());
            let base_bundle_path = Path::new(&base_bundle);
            if !base_bundle_path.exists() {
                eprintln!(
                    "entrypoint: base CA bundle is not readable: {}",
                    base_bundle
                );
                std::process::exit(1);
            }

            let merged_bundle = home_path.join(".cache/agent-sandbox-ca-bundle.pem");
            if let Some(parent) = merged_bundle.parent() {
                fs::create_dir_all(parent)?;
            }

            let base_content = fs::read_to_string(base_bundle_path)?;
            let proxy_content = fs::read_to_string(proxy_ca_path)?;

            let mut file = fs::File::create(&merged_bundle)?;
            file.write_all(base_content.as_bytes())?;
            file.write_all(proxy_content.as_bytes())?;

            let mut p = fs::metadata(&merged_bundle)?.permissions();
            p.set_mode(0o600);
            fs::set_permissions(&merged_bundle, p)?;

            let merged_bundle_str = merged_bundle.to_string_lossy().to_string();
            env::set_var("SSL_CERT_FILE", &merged_bundle_str);
            env::set_var("NIX_SSL_CERT_FILE", &merged_bundle_str);
            env::set_var("GIT_SSL_CAINFO", &merged_bundle_str);
            env::set_var("REQUESTS_CA_BUNDLE", &merged_bundle_str);
            env::set_var("CURL_CA_BUNDLE", &merged_bundle_str);
            env::set_var("NODE_EXTRA_CA_CERTS", &merged_bundle_str);
        }
    }

    // 6. Git config
    //
    // Written whole on every start rather than appended to, because ~/.config
    // survives a container restart and a second generation of these sections
    // would stack up.  The image includes this file from /etc/gitconfig too, so
    // it reaches a `git` that was started without the GIT_CONFIG_* environment
    // below -- a `podman exec` shell, or a git spawned by a tool that scrubs its
    // child environment.
    let run_gitconfig = home_path.join(".config/agent-sandbox/gitconfig");
    if let Some(parent) = run_gitconfig.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut gitconfig_file = fs::File::create(&run_gitconfig)?;

    // git's own libcurl honours http_proxy, but only when it is in the
    // environment; recording it as config covers the invocations where it is
    // not, and costs nothing where it is.
    if let Ok(proxy) = env::var("http_proxy") {
        if !proxy.is_empty() {
            writeln!(gitconfig_file, "[http]\n\tproxy = {}", proxy)?;
        }
    }

    if env::var("AGENT_SANDBOX_RELAY_GPG").unwrap_or_default() == "1" {
        writeln!(gitconfig_file, "[gpg]\n\tprogram = relay-gpg")?;
    }

    if env::var("AGENT_SANDBOX_NO_GPG_SIGN").unwrap_or_default() == "1" {
        // Tags as well as commits: the host config that switched signing on
        // usually switches on both, and either one fails the same way without
        // a forwarded agent.
        writeln!(
            gitconfig_file,
            "[commit]\n\tgpgsign = false\n[tag]\n\tgpgsign = false"
        )?;
    }

    let base_count: usize = env::var("AGENT_SANDBOX_GIT_CONFIG_COUNT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);

    for i in 0..base_count {
        if let Ok(key) = env::var(format!("AGENT_SANDBOX_GIT_CONFIG_KEY_{}", i)) {
            env::set_var(format!("GIT_CONFIG_KEY_{}", i), key);
        }
        if let Ok(val) = env::var(format!("AGENT_SANDBOX_GIT_CONFIG_VALUE_{}", i)) {
            env::set_var(format!("GIT_CONFIG_VALUE_{}", i), val);
        }
    }

    if run_gitconfig.exists() {
        env::set_var("GIT_CONFIG_COUNT", (base_count + 1).to_string());
        env::set_var(format!("GIT_CONFIG_KEY_{}", base_count), "include.path");
        env::set_var(
            format!("GIT_CONFIG_VALUE_{}", base_count),
            run_gitconfig.to_string_lossy().to_string(),
        );
    } else {
        env::set_var("GIT_CONFIG_COUNT", base_count.to_string());
    }

    // 7. SSH relay
    if env::var("AGENT_SANDBOX_RELAY_SSH").unwrap_or_default() == "1" {
        env::set_var("GIT_SSH_COMMAND", "relay-ssh");
        let local_bin = home_path.join(".local/bin");
        fs::create_dir_all(&local_bin)?;

        // Find relay-ssh in PATH or use command -v equivalent
        if let Ok(relay_ssh_path) = which("relay-ssh") {
            let _ = std::os::unix::fs::symlink(&relay_ssh_path, local_bin.join("ssh"));
        }

        let current_path = env::var("PATH").unwrap_or_default();
        env::set_var(
            "PATH",
            format!("{}:{}", local_bin.to_string_lossy(), current_path),
        );
    }

    // 8. Host loopback ports
    // The launcher mounted one socket per mapping and is splicing the far end
    // to a port on the host's loopback; this puts a TCP listener in front of
    // each, because the clients that want them -- CDP, a database driver --
    // speak TCP and not unix sockets.  127.0.0.1 both because NO_PROXY already
    // exempts it under --proxy and because Chrome's DevTools host check accepts
    // an IP but not an arbitrary name.
    //
    // Spawned, not threaded: this process execs below, which would take any
    // thread of ours with it.  socat outlives that as a child of PID 1 and dies
    // with the container.
    if let Ok(ports) = env::var("AGENT_SANDBOX_HOST_PORTS") {
        for port in ports.split(',').filter(|p| !p.is_empty()) {
            let socket = format!("/run/agent-sandbox-host/{}.sock", port);
            let spawned = Command::new("socat")
                .arg(format!("TCP-LISTEN:{},bind=127.0.0.1,fork,reuseaddr", port))
                .arg(format!("UNIX-CONNECT:{}", socket))
                .spawn();
            if let Err(e) = spawned {
                eprintln!("agent-sandbox: could not forward host port {}: {}", port, e);
            }
        }
    }

    // 9. Leave the runtime environment somewhere `ctl attach` can find it.
    //
    // `podman exec` inherits the *container's* environment -- what `podman run`
    // was given -- not the environment this process built on top of it.  So an
    // attached shell had none of what the steps above set: no merged CA bundle,
    // no `GIT_SSH_COMMAND=relay-ssh`, no `GIT_CONFIG_*`.  That is why
    // `git clone git@github.com:...` failed in an attached shell while the same
    // clone worked in the session the launcher started.
    write_attach_env(&home_path);

    // 10. exec "$@"
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let err = Command::new(&args[1]).args(&args[2..]).exec();
        eprintln!("Failed to exec {}: {}", args[1], err);
        std::process::exit(1);
    }

    Ok(())
}

/// Where the entrypoint records the environment it built, for `ctl attach`.
const ATTACH_ENV: &str = ".config/agent-sandbox/env";

/// Variables an attached shell needs that only exist because this process set
/// them.  Anything the launcher passed to `podman run` is already inherited by
/// `podman exec` and is deliberately not repeated here.
///
/// `GIT_CONFIG_*` is written as the count plus that many key/value pairs, since
/// git reads them positionally and a partial set is worse than none.
const ATTACH_ENV_VARS: &[&str] = &[
    "PATH",
    "SSL_CERT_FILE",
    "NIX_SSL_CERT_FILE",
    "GIT_SSL_CAINFO",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSH_COMMAND",
];

fn write_attach_env(home_path: &Path) {
    let path = home_path.join(ATTACH_ENV);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut lines = String::new();
    for name in ATTACH_ENV_VARS {
        if let Ok(value) = env::var(name) {
            // A value with a newline in it cannot survive a line-per-variable
            // file, and `attach` would otherwise pass the tail as its own
            // variable.  None of these ever legitimately contains one.
            if !value.contains('\n') {
                lines.push_str(&format!("{}={}\n", name, value));
            }
        }
    }

    if let Ok(count) = env::var("GIT_CONFIG_COUNT") {
        if let Ok(n) = count.parse::<usize>() {
            lines.push_str(&format!("GIT_CONFIG_COUNT={}\n", n));
            for i in 0..n {
                for name in [
                    format!("GIT_CONFIG_KEY_{}", i),
                    format!("GIT_CONFIG_VALUE_{}", i),
                ] {
                    if let Ok(value) = env::var(&name) {
                        if !value.contains('\n') {
                            lines.push_str(&format!("{}={}\n", name, value));
                        }
                    }
                }
            }
        }
    }

    // Written whole, not appended: a container that restarts must not end up
    // with two generations of the same variable in one file.
    if let Err(e) = fs::write(&path, lines) {
        eprintln!(
            "agent-sandbox: could not write {}: {} ('ctl attach' will get a barer environment)",
            path.display(),
            e
        );
    }
}

fn which(cmd: &str) -> Result<PathBuf, ()> {
    if let Ok(paths) = env::var("PATH") {
        for path in paths.split(':') {
            let p = Path::new(path).join(cmd);
            if p.exists() {
                return Ok(p);
            }
        }
    }
    Err(())
}
