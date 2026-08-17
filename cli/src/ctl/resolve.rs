use anyhow::{anyhow, Result};
use std::env;
use std::process::Command;

pub fn podman_ps_names(all: bool, filter: &str) -> Result<Vec<String>> {
    let mut cmd = Command::new("podman");
    cmd.arg("ps");
    if all {
        cmd.arg("-a");
    }
    cmd.arg("--filter").arg(filter);
    cmd.arg("--format").arg("{{.Names}}");
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(anyhow!("podman ps failed"));
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.lines().map(|s| s.to_string()).collect())
}

pub fn sandbox_containers() -> Result<Vec<String>> {
    podman_ps_names(false, "label=agent-sandbox.role=sandbox")
}

pub fn sandbox_containers_rows(all: bool) -> Result<Vec<(String, String, String)>> {
    let mut cmd = Command::new("podman");
    cmd.arg("ps");
    if all {
        cmd.arg("-a");
    }
    cmd.arg("--filter").arg("label=agent-sandbox.role=sandbox");
    cmd.arg("--format").arg("{{.Names}}\t{{.Status}}\t{{.RunningFor}}");
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(anyhow!("podman ps failed"));
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let name = parts.next()?.to_string();
            let status = parts.next().unwrap_or("").to_string();
            let created = parts.next().unwrap_or("").to_string();
            Some((name, status, created))
        })
        .collect())
}

pub fn sandbox_containers_all() -> Result<Vec<String>> {
    podman_ps_names(true, "label=agent-sandbox.role=sandbox")
}

pub fn sandbox_workspace(name: &str) -> Result<String> {
    podman_inspect_label(name, "agent-sandbox.workspace")
}

pub fn sandbox_running(name: &str) -> Result<bool> {
    let names = sandbox_containers()?;
    Ok(names.iter().any(|n| n == name))
}

/// The prefix the launcher puts on every container, network and session
/// directory it creates.  It exists so our objects are recognisable inside
/// podman's global namespace; it tells a reader of our own output nothing they
/// do not already know, so it comes off before anything is printed.
pub const NAME_PREFIX: &str = "agent-sandbox-";

/// What to call a sandbox in output.  The session word is unique across all
/// sandboxes -- the launcher will not reuse one that suffixes an existing
/// container -- and it is the selector every command takes, so printing
/// anything longer gives the reader a name they cannot type back.
pub fn sandbox_word(name: &str) -> String {
    name.rsplit('-').next().unwrap_or(name).to_string()
}

/// What to call our other objects -- a sidecar, its network -- which are named
/// after a launch uuid rather than a session word.  Nobody types these, but
/// they are listed next to sandboxes, and a bare `sidecar-1a2b3c4d` next to a
/// bare `quiet` reads as one list instead of two.
pub fn short_name(name: &str) -> String {
    name.strip_prefix(NAME_PREFIX).unwrap_or(name).to_string()
}

pub fn sandbox_proxy_mode(name: &str) -> Result<String> {
    podman_inspect_label(name, "agent-sandbox.proxy")
}

pub fn sandbox_runtime(name: &str) -> Result<String> {
    podman_inspect_label(name, "agent-sandbox.runtime")
}

pub fn podman_inspect_label(name: &str, label: &str) -> Result<String> {
    let mut cmd = Command::new("podman");
    cmd.arg("inspect")
        .arg("--format")
        .arg(format!("{{{{index .Config.Labels \"{}\"}}}}", label))
        .arg(name);
    let output = cmd.output()?;
    if !output.status.success() {
        return Ok(String::new());
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.trim().to_string())
}

pub fn refuse_if_krun(sandbox: &str, verb: &str, msgs: &[&str]) -> Result<()> {
    if sandbox_runtime(sandbox)? == "krun" {
        eprintln!(
            "agent-sandbox ctl: '{}' is a --krun microVM; {} is not available.",
            sandbox_word(sandbox),
            verb
        );
        for m in msgs {
            eprintln!("               {}", m);
        }
        std::process::exit(1);
    }
    Ok(())
}

pub fn sidecar_for_sandbox(sandbox: &str) -> Result<String> {
    let mut cmd = Command::new("podman");
    cmd.arg("ps")
        .arg("--filter")
        .arg("label=agent-sandbox.role=proxy")
        .arg("--filter")
        .arg(format!("label=agent-sandbox.target={}", sandbox))
        .arg("--format")
        .arg("{{.Names}}");
    let output = cmd.output()?;
    if !output.status.success() {
        return Ok(String::new());
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.lines().next().unwrap_or("").to_string())
}

pub fn sidecar_mount(sidecar: &str, dest: &str) -> Result<String> {
    let mut cmd = Command::new("podman");
    cmd.arg("inspect")
       .arg("--format")
       .arg(format!("{{{{range .Mounts}}}}{{{{if eq .Destination \"{}\"}}}}{{{{.Source}}}}{{{{end}}}}{{{{end}}}}", dest))
       .arg(sidecar);
    let output = cmd.output()?;
    if !output.status.success() {
        return Ok(String::new());
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.trim().to_string())
}

pub fn require_sidecar(sandbox: &str) -> Result<String> {
    let sidecar = sidecar_for_sandbox(sandbox)?;
    if sidecar.is_empty() {
        eprintln!(
            "agent-sandbox ctl: '{}' is running without a proxy.",
            sandbox_word(sandbox)
        );
        eprintln!("               Relaunch it with:  agent-sandbox --proxy");
        std::process::exit(1);
    }
    Ok(sidecar)
}

/// Why `try_resolve_sandbox` came back empty-handed.
///
/// `message` is what `resolve_sandbox` prints after its own prefix: a headline
/// phrase, then any listing lines, already indented.
pub struct Unresolved {
    pub message: String,
    /// Set when sandboxes did match and only the choice between them was
    /// missing.  A caller for which a sandbox is optional still wants to say
    /// something about this one: it walks away from candidates that are right
    /// there, rather than from an empty machine.
    pub ambiguous: bool,
}

impl Unresolved {
    fn not_found(message: impl Into<String>) -> Self {
        Unresolved {
            message: message.into(),
            ambiguous: false,
        }
    }

    fn ambiguous(lines: Vec<String>) -> Self {
        Unresolved {
            message: lines.join("\n"),
            ambiguous: true,
        }
    }
}

/// `resolve_sandbox` without the exit: the outer `Err` is a podman or
/// environment failure, the inner one is "no sandbox, and here is how to say
/// it".
///
/// Every command that acts *on* a sandbox wants the exiting wrapper below.
/// This one is for the commands a sandbox is merely useful to --
/// `agent-sandbox browser` seeds its allow list from one if there is one and
/// starts perfectly well if there is not, which it cannot do if resolving
/// takes the process down with it.
pub fn try_resolve_sandbox(
    explicit: Option<&str>,
    want_running: bool,
) -> Result<std::result::Result<String, Unresolved>> {
    if let Some(explicit) = explicit {
        // Try to inspect the explicit container ID or name
        let mut cmd = Command::new("podman");
        cmd.arg("inspect")
            .arg("--format")
            .arg("{{.Name}} {{index .Config.Labels \"agent-sandbox.role\"}} {{.State.Running}}")
            .arg(explicit);
        let output = cmd.output()?;
        if !output.status.success() {
            // fallback for backward compatibility with suffix matching
            let all_names = sandbox_containers_all()?;
            let mut valid_matches = Vec::new();
            for name in &all_names {
                if name == explicit || name.ends_with(&format!("-{}", explicit)) {
                    valid_matches.push(name.clone());
                }
            }
            if valid_matches.len() == 1 {
                if want_running && !sandbox_running(&valid_matches[0])? {
                    return Ok(Err(Unresolved::not_found(format!(
                        "'{}' is not running",
                        sandbox_word(&valid_matches[0])
                    ))));
                }
                return Ok(Ok(valid_matches[0].clone()));
            } else if valid_matches.len() > 1 {
                let mut lines = vec![format!(
                    "'{}' is ambiguous, matches multiple sandboxes:",
                    explicit
                )];
                for m in &valid_matches {
                    lines.push(format!(
                        "  {}\t{}",
                        sandbox_word(m),
                        sandbox_workspace(m).unwrap_or_default()
                    ));
                    lines.push(format!("    full name: {}", m));
                }
                return Ok(Err(Unresolved::ambiguous(lines)));
            }
            return Ok(Err(Unresolved::not_found(format!(
                "no container named or id matching '{}'",
                explicit
            ))));
        }
        let stdout = String::from_utf8(output.stdout)?;
        let parts: Vec<&str> = stdout.trim().split_whitespace().collect();
        if parts.len() < 3 || parts[1] != "sandbox" {
            return Ok(Err(Unresolved::not_found(format!(
                "container '{}' is not an agent-sandbox",
                explicit
            ))));
        }
        let is_running = parts[2] == "true";
        if want_running && !is_running {
            return Ok(Err(Unresolved::not_found(format!(
                "'{}' is not running",
                explicit
            ))));
        }
        let mut name = parts[0];
        if name.starts_with('/') {
            name = &name[1..];
        }
        return Ok(Ok(name.to_string()));
    }

    let rows = sandbox_containers_rows(!want_running)?;
    if rows.is_empty() {
        return Ok(Err(Unresolved::not_found(if want_running {
            "no running sandboxes."
        } else {
            "no sandboxes found."
        })));
    }

    let pwd = env::current_dir()?.to_string_lossy().to_string();
    let mut matches = Vec::new();
    for (name, status, created) in &rows {
        if sandbox_workspace(name).unwrap_or_default() == pwd {
            matches.push((name.clone(), status.clone(), created.clone()));
        }
    }
    if matches.is_empty() {
        return Ok(Err(Unresolved::not_found(
            "no sandbox running for current workspace.",
        )));
    }
    if matches.len() == 1 {
        return Ok(Ok(matches[0].0.clone()));
    }

    let mut lines = vec![
        "several sandboxes are running for this workspace; pass --container NAME:".to_string(),
        "  NAME\tCREATED\tSTATUS".to_string(),
    ];
    for (name, status, created) in &matches {
        lines.push(format!("  {}\t{}\t{}", sandbox_word(name), created, status));
    }
    Ok(Err(Unresolved::ambiguous(lines)))
}

/// The sandbox a command was pointed at, or a message and exit 1.
pub fn resolve_sandbox(explicit: Option<&str>, want_running: bool) -> Result<String> {
    match try_resolve_sandbox(explicit, want_running)? {
        Ok(name) => Ok(name),
        Err(unresolved) => {
            eprintln!("agent-sandbox ctl: {}", unresolved.message);
            std::process::exit(1);
        }
    }
}
