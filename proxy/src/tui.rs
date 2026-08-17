use agent_sandbox_proxy::policy_io::{install_policy, load_policy_lines};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState, Wrap},
    Terminal,
};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::{self, BufRead, Seek, SeekFrom},
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Drop guard ensuring terminal state (raw mode & alternate screen) is restored
/// even if a panic or early return occurs.
struct TerminalCleanup;

impl Drop for TerminalCleanup {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A line from `connections.jsonl`. Denials can be id-less when rejected before
/// a tunnel opens, or `close` events when an L7 request is rejected after MITM.
#[derive(Deserialize, Debug, Clone)]
struct ConnEvent {
    ev: Option<String>,
    id: Option<String>,
    verdict: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    pub err: Option<String>,
    pub up: Option<u64>,
    pub down: Option<u64>,
    pub ms: Option<u128>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    ts: Option<u64>,
}

fn is_denied_event(ev: &ConnEvent) -> bool {
    ev.verdict.as_deref() == Some("deny") && (ev.ev.is_none() || ev.ev.as_deref() == Some("close"))
}

fn is_connection_event(ev: &ConnEvent) -> bool {
    ev.ev.as_deref() != Some("policy") && ev.host.is_some() && ev.port.is_some()
}

/// Correlate open/close events while retaining id-less terminal events.
fn ingest_connection_event(connections: &mut Vec<ConnEvent>, event: ConnEvent) {
    if !is_connection_event(&event) {
        return;
    }

    if let Some(id) = event.id.as_deref() {
        if let Some(existing) = connections
            .iter_mut()
            .find(|entry| entry.id.as_deref() == Some(id))
        {
            *existing = event;
        } else {
            connections.push(event);
        }
    } else {
        connections.push(event);
    }

    if connections.len() > MAX_CONNECTION_ROWS {
        if let Some(oldest) = connections
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.ts.unwrap_or(0))
            .map(|(index, _)| index)
        {
            connections.remove(oldest);
        }
    }
}

#[derive(Deserialize, Debug)]
struct DetailEvent {
    host: String,
    port: u16,
    reason: String,
    request: String,
}

/// A line from `relay.jsonl`, written by `relay-server` in the sidecar.
///
/// A separate stream from `connections.jsonl` because it records a separate
/// decision: the relay authorizes *use of the forwarded agent*, and its `ssh`
/// runs in the sidecar without passing through the proxy at all. `dest` is
/// absent for gpg, which has no destination, and for an ssh call whose
/// destination could not be read out of argv. `ts` is `Option` because the
/// host-side TUI and the sidecar image can be different builds.
#[derive(Deserialize, Debug, Clone)]
struct RelayEvent {
    cmd: String,
    dest: Option<String>,
    allowed: bool,
    reason: Option<String>,
    ts: Option<u64>,
}

/// The port an `allowed_hosts` entry has to name for the launcher to derive
/// `allow_signing` from it — whatever port ssh itself ends up using.
const SSH_POLICY_PORT: u16 = 22;

/// The key a GPG denial is filed under. Not a host: gpg has no destination,
/// and port 0 cannot collide with a real denial.
const GPG_ROW_HOST: &str = "gpg";
const GPG_ROW_PORT: u16 = 0;

/// Which decision refused a row, and therefore what would let it through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeniedKind {
    /// The proxy refused a connection: a host/port rule fixes it.
    Egress,
    /// The relay refused to run `ssh` to a destination: `allow_signing` does.
    Ssh,
    /// The relay refused to run `gpg`. Nothing in the policy fixes this —
    /// signing is enabled by launching with `--gpg`.
    Gpg,
}

/// A denied host/port, deduplicated across repeats so a retrying agent
/// doesn't spam the list with one row per attempt.
#[derive(Debug, Clone)]
struct DeniedEntry {
    host: String,
    port: u16,
    reason: Option<String>,
    method: Option<String>,
    detail: Option<String>,
    count: u32,
    last_seen: u64,
    kind: DeniedKind,
}

impl DeniedEntry {
    fn info_cell(&self) -> String {
        let age = now_secs().saturating_sub(self.last_seen);
        let reason = self.reason.as_deref().unwrap_or("denied");
        if self.count > 1 {
            format!("{} (×{}, {}s ago)", reason, self.count, age)
        } else {
            format!("{} ({}s ago)", reason, age)
        }
    }
}

/// `connections.jsonl` has no size cap, so the in-memory denied set doesn't
/// either unless bounded here.
const MAX_DENIED_ROWS: usize = 200;
const MAX_CONNECTION_ROWS: usize = 200;
const MAX_DETAIL_BYTES_PER_ROW: usize = 16 * 1024;

/// Fold a relay decision into the same denied set the proxy's denials go into.
///
/// One map and one key, because for `(host, 22)` the two denials have the same
/// remedy and the relay's grant is a strict superset of the proxy's: it adds
/// `allow_signing` on top of the host rule, and `allow_signing` is inert when
/// no relay is running. Two collections would mean two rows for one problem
/// and two keypresses to fix it.
fn ingest_relay_event(denied: &mut HashMap<(String, u16), DeniedEntry>, event: RelayEvent) {
    if event.allowed {
        return;
    }
    let (host, port, kind, method) = match event.cmd.as_str() {
        "ssh" => match event.dest {
            Some(dest) => (dest, SSH_POLICY_PORT, DeniedKind::Ssh, "SSH"),
            // "could not determine destination": there is no host to write a
            // rule for, so a row offering to allow one would be a lie.
            // `ctl relay` still shows it.
            None => return,
        },
        "gpg" => (
            GPG_ROW_HOST.to_string(),
            GPG_ROW_PORT,
            DeniedKind::Gpg,
            "GPG",
        ),
        _ => return,
    };

    let ts = event.ts.unwrap_or_else(now_secs);
    let entry = denied
        .entry((host.clone(), port))
        .or_insert_with(|| DeniedEntry {
            host,
            port,
            reason: None,
            method: Some(method.to_string()),
            detail: None,
            count: 0,
            last_seen: ts,
            kind,
        });
    entry.count += 1;
    entry.last_seen = ts;
    entry.kind = kind;
    entry.method = Some(method.to_string());
    if let Some(reason) = event.reason.filter(|r| !r.is_empty()) {
        entry.reason = Some(reason);
    }
}

/// Whether `h` (allow HTTP route) makes sense for this row: only once a real
/// HTTP method is known. A domain/IP-level deny before any L7 check ran
/// carries `"CONNECT"` or no method at all, and a rule built from either can
/// never match a real request. A relay denial never has one — nothing about
/// it is HTTP.
fn h_available(kind: DeniedKind, method: Option<&str>) -> bool {
    kind == DeniedKind::Egress && matches!(method, Some(m) if m != "CONNECT")
}

/// Whether `A` (allow IP) makes sense for this row's host: it must actually
/// parse as an IP or CIDR. Most rows carry a domain name instead, and a relay
/// row is authorized by host regardless of what it resolves to.
fn ip_available(kind: DeniedKind, host: &str) -> bool {
    if kind != DeniedKind::Egress {
        return false;
    }
    match host.split_once('/') {
        Some((ip, mask)) => ip.parse::<IpAddr>().is_ok() && mask.parse::<u8>().is_ok(),
        None => host.parse::<IpAddr>().is_ok(),
    }
}

/// Whether the sandbox trusts a host key for `host`.
///
/// The authorized set is written beside the policy at launch, from the
/// operator's `trusted.toml`, and nothing running can add to it — so this is
/// read-only advice, not a gate. A grant for an untrusted host is still
/// correct; it just cannot connect until the operator authorizes a key.
fn trusts_host_key(policy_dir: &str, host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    fs::read_to_string(format!("{}/known_hosts", policy_dir))
        .map(|text| {
            text.lines()
                .filter_map(|line| line.split_whitespace().next())
                .any(|pattern| pattern.to_ascii_lowercase() == host)
        })
        .unwrap_or(false)
}

/// The policy lines that would let a denied row through, in the order they
/// should be written.
///
/// Lifted out of the key handler so the mapping from "what was refused" to
/// "what authorizes it" is testable on its own. An SSH row needs both: the
/// `allow_signing` entry is what the relay consults, and the `:22` host rule
/// is what makes the exit summary render `allowed_hosts = ["host:22"]`, from
/// which a relaunch re-derives `allow_signing`. Write only one and the grant
/// does not survive the session.
fn grant_lines(row: &DeniedEntry) -> Vec<String> {
    match row.kind {
        DeniedKind::Egress => vec![format!("allow_host {}:{}", row.host, row.port)],
        DeniedKind::Ssh => vec![
            format!("allow_signing {}", row.host),
            format!("allow_host {}:{}", row.host, SSH_POLICY_PORT),
        ],
        // Enabled at launch, not by policy.
        DeniedKind::Gpg => Vec::new(),
    }
}

const NO_CONNECTION_DETAIL: &str = "No connection is selected.";

/// What `d` shows for a row in the Connections view.
///
/// Request heads are captured for *denials* only — the proxy never reads the
/// body of an allowed tunnel — so a row without one gets that stated rather
/// than an empty pane that reads like a bug.
fn connection_detail_text(
    ev: &ConnEvent,
    denied_reqs: &HashMap<(String, u16), DeniedEntry>,
) -> String {
    let host = ev.host.clone().unwrap_or_else(|| "?".to_string());
    let port = ev.port.unwrap_or(0);
    let state = if ev.ev.as_deref() == Some("open") {
        "in flight".to_string()
    } else {
        ev.verdict.as_deref().unwrap_or("?").to_string()
    };

    let mut out = format!("{} {}:{}", state, host, port);
    if let Some(method) = ev.method.as_deref() {
        out.push_str(&format!("\nmethod    {}", method));
    }
    if let Some(path) = ev.path.as_deref() {
        out.push_str(&format!("\npath      {}", path));
    }
    if let Some(status) = ev.status {
        out.push_str(&format!("\nstatus    HTTP {}", status));
    }
    if let Some(err) = ev.err.as_deref() {
        out.push_str(&format!("\nerror     {}", err));
    }
    if ev.ev.as_deref() != Some("open") {
        out.push_str(&format!(
            "\ntraffic   up {} / down {} / {}ms",
            ev.up.unwrap_or(0),
            ev.down.unwrap_or(0),
            ev.ms.unwrap_or(0)
        ));
    }

    match denied_reqs
        .get(&(host, port))
        .and_then(|entry| entry.detail.clone())
    {
        Some(detail) => {
            out.push_str("\n\n── last denied request head (redacted) ──\n");
            out.push_str(&detail);
        }
        None => out.push_str(
            "\n\nNo request head was recorded for this destination. \
             The proxy captures heads for denied requests only; an allowed \
             HTTPS tunnel is not decrypted unless a route or secret rule \
             covers it.",
        ),
    }
    out
}

fn clear_allowed_request(
    denied_reqs: &mut HashMap<(String, u16), DeniedEntry>,
    host: &str,
    port: u16,
    selected_idx: &mut usize,
) {
    denied_reqs.remove(&(host.to_string(), port));
    *selected_idx = (*selected_idx).min(denied_reqs.len().saturating_sub(1));
}

#[derive(Clone, Copy, PartialEq)]
enum StatusKind {
    Success,
    Info,
    Error,
}

impl StatusKind {
    fn color(self) -> Color {
        match self {
            StatusKind::Success => Color::Green,
            StatusKind::Info => Color::Yellow,
            StatusKind::Error => Color::Red,
        }
    }
}

/// The two screens this dashboard flips between: the live denied-request
/// feed (default), and a read/remove view of the policy actually in force.
#[derive(Clone, Copy, PartialEq)]
enum View {
    Requests,
    Connections,
    Rules,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: agent-sandbox-tui <sandbox_name> <policy_dir> <shared_dir>");
        std::process::exit(1);
    }
    let sandbox_name = &args[1];
    let sandbox_short_name = sandbox_name.rsplit('-').next().unwrap_or(sandbox_name);
    let sidecar_policy = &args[2];
    let sidecar_shared = &args[3];
    let connections_log = format!("{}/connections.jsonl", sidecar_shared);
    let details_log = format!("{}/denied-requests.jsonl", sidecar_shared);
    let relay_log = format!("{}/relay.jsonl", sidecar_shared);

    let sigint_flag = Arc::new(AtomicBool::new(false));
    {
        let flag = sigint_flag.clone();
        ctrlc::set_handler(move || {
            flag.store(true, Ordering::SeqCst);
        })?;
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _cleanup = TerminalCleanup;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut denied_reqs: HashMap<(String, u16), DeniedEntry> = HashMap::new();
    let mut connections: Vec<ConnEvent> = Vec::new();
    let mut view = View::Requests;
    let mut selected_idx = 0;
    let mut table_state = TableState::default();
    let mut connections_selected_idx = 0;
    let mut connections_table_state = TableState::default();
    let mut rules_selected_idx = 0;
    let mut rules_table_state = TableState::default();
    let mut status_msg = String::new();
    let mut status_kind = StatusKind::Info;
    let mut status_until: Option<Instant> = None;
    let mut ctrlc_armed_until: Option<Instant> = None;

    let mut conn_file = None;
    let mut conn_pos = 0;
    let mut details_file = None;
    let mut details_pos = 0;
    let mut relay_file = None;
    let mut relay_pos = 0;
    let mut show_detail = false;
    let mut detail_scroll = 0;

    loop {
        if let Some(until) = status_until {
            if Instant::now() >= until {
                status_msg.clear();
                status_until = None;
            }
        }

        if sigint_flag.load(Ordering::SeqCst) {
            break;
        }

        if conn_file.is_none() {
            if let Ok(f) = fs::File::open(&connections_log) {
                conn_file = Some(io::BufReader::new(f));
            }
        }
        if let Some(ref mut reader) = conn_file {
            if let Ok(meta) = reader.get_ref().metadata() {
                if meta.len() < conn_pos {
                    conn_pos = 0;
                }
            }
            let _ = reader.seek(SeekFrom::Start(conn_pos));
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 {
                    break;
                }
                if !line.ends_with('\n') {
                    let _ = reader.seek(SeekFrom::Current(-(line.len() as i64)));
                    break;
                }
                if let Ok(ev) = serde_json::from_str::<ConnEvent>(&line) {
                    ingest_connection_event(&mut connections, ev.clone());
                    // Include pre-tunnel denials and L7 denials emitted as a
                    // terminal close event. Allowed close events remain out.
                    if is_denied_event(&ev) {
                        if let (Some(host), Some(port)) = (ev.host.clone(), ev.port) {
                            let ts = ev.ts.unwrap_or_else(now_secs);
                            let key = (host.clone(), port);
                            let is_new = !denied_reqs.contains_key(&key);
                            let entry = denied_reqs.entry(key).or_insert_with(|| DeniedEntry {
                                host,
                                port,
                                reason: None,
                                method: None,
                                detail: None,
                                count: 0,
                                last_seen: ts,
                                kind: DeniedKind::Egress,
                            });
                            entry.count += 1;
                            entry.last_seen = ts;
                            if ev.err.is_some() {
                                entry.reason = ev.err.clone();
                            }
                            if ev.method.is_some() {
                                entry.method = ev.method.clone();
                            }
                            if is_new && denied_reqs.len() > MAX_DENIED_ROWS {
                                if let Some(oldest) = denied_reqs
                                    .iter()
                                    .min_by_key(|(_, v)| v.last_seen)
                                    .map(|(k, _)| k.clone())
                                {
                                    denied_reqs.remove(&oldest);
                                }
                            }
                        }
                    }
                }
                line.clear();
            }
            if let Ok(pos) = reader.stream_position() {
                conn_pos = pos;
            }
        }

        if details_file.is_none() {
            if let Ok(f) = fs::File::open(&details_log) {
                details_file = Some(io::BufReader::new(f));
            }
        }
        if let Some(ref mut reader) = details_file {
            if let Ok(meta) = reader.get_ref().metadata() {
                if meta.len() < details_pos {
                    details_pos = 0;
                }
            }
            let _ = reader.seek(SeekFrom::Start(details_pos));
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 {
                    break;
                }
                if !line.ends_with('\n') {
                    let _ = reader.seek(SeekFrom::Current(-(line.len() as i64)));
                    break;
                }
                if let Ok(ev) = serde_json::from_str::<DetailEvent>(&line) {
                    if let Some(entry) = denied_reqs.get_mut(&(ev.host, ev.port)) {
                        entry.detail = Some(format!(
                            "Reason: {}\n\n{}",
                            ev.reason,
                            ev.request
                                .chars()
                                .take(MAX_DETAIL_BYTES_PER_ROW)
                                .collect::<String>()
                        ));
                        entry.reason = Some(ev.reason.clone());
                    }
                }
                line.clear();
            }
            if let Ok(pos) = reader.stream_position() {
                details_pos = pos;
            }
        }

        // The relay's own decisions. The file only exists in a session
        // launched with --ssh or --gpg, so the open is retried every pass
        // rather than once. A rotation replays the retained tail and inflates
        // `count`, exactly as it does for connections.jsonl; the dedup map
        // absorbs it.
        if relay_file.is_none() {
            if let Ok(f) = fs::File::open(&relay_log) {
                relay_file = Some(io::BufReader::new(f));
            }
        }
        if let Some(ref mut reader) = relay_file {
            if let Ok(meta) = reader.get_ref().metadata() {
                if meta.len() < relay_pos {
                    relay_pos = 0;
                }
            }
            let _ = reader.seek(SeekFrom::Start(relay_pos));
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 {
                    break;
                }
                if !line.ends_with('\n') {
                    let _ = reader.seek(SeekFrom::Current(-(line.len() as i64)));
                    break;
                }
                if let Ok(ev) = serde_json::from_str::<RelayEvent>(&line) {
                    ingest_relay_event(&mut denied_reqs, ev);
                }
                line.clear();
            }
            if let Ok(pos) = reader.stream_position() {
                relay_pos = pos;
            }
        }

        let mut denied_list: Vec<DeniedEntry> = denied_reqs.values().cloned().collect();
        denied_list.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        let mut connections_list = connections.clone();
        connections_list.sort_by_key(|entry| std::cmp::Reverse(entry.ts.unwrap_or(0)));

        // `base_lines` is read every pass, not only in the Rules view: the `h`
        // handler consults it from the Requests view to decide whether the
        // session has a CA behind an L7 rule, and an empty set there made `h`
        // report "no L7 rule" for every sandbox. All three files are small,
        // and this loop already re-reads connections.jsonl at ~10Hz.
        let base_lines: HashSet<String> =
            fs::read_to_string(format!("{}/policy.base", sidecar_policy))
                .map(|s| s.lines().map(|l| l.to_string()).collect())
                .unwrap_or_default();
        let (policy_lines, baseline_lines): (Vec<String>, HashSet<String>) = if view == View::Rules
        {
            let lines = load_policy_lines(sidecar_policy);
            let baseline = fs::read_to_string(format!("{}/policy.baseline", sidecar_policy))
                .map(|s| s.lines().map(|l| l.to_string()).collect())
                .unwrap_or_default();
            (lines, baseline)
        } else {
            (Vec::new(), HashSet::new())
        };

        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(5),
                    Constraint::Length(4),
                    Constraint::Length(1),
                ])
                .split(size);

            let title = Paragraph::new(format!(" Agent Sandbox TUI — {} ", sandbox_short_name))
                .style(Style::default().add_modifier(Modifier::BOLD).bg(Color::DarkGray).fg(Color::Cyan))
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(title, chunks[0]);

            let selected_style = Style::default().add_modifier(Modifier::REVERSED);
            let normal_style = Style::default();

            match view {
                View::Requests => {
                    if show_detail {
                        let mut text = denied_list.get(selected_idx)
                            .and_then(|d| d.detail.clone())
                            .unwrap_or_else(|| "No detailed request is available for this denial yet.".to_string());
                        if let Some(row) = denied_list.get(selected_idx) {
                            match row.kind {
                                DeniedKind::Egress if row.method.as_deref() == Some("CONNECT") => {
                                    text.push_str(&format!(
                                        "\n\nThe inner HTTPS request is unavailable because CONNECT was denied before TLS.\nTo inspect it, temporarily add:\n\n[[network.allowed_routes]]\nhost = \"{}:{}\"\nmethod = \"GET\"\npath = \"/noop\"\n\nThis permits the CONNECT/MITM stage; the placeholder path remains denied. Replace it with the required path after retrying.",
                                        row.host, row.port
                                    ));
                                }
                                DeniedKind::Ssh => {
                                    text.push_str(&format!(
                                        "\n\nThe relay refused to run ssh to this destination: the forwarded agent lives in the sidecar, and it will only be used for a host the policy names on port 22.\n\n[a] adds both lines this needs:\n\n  allow_signing {host}\n  allow_host {host}:22\n\nThe relay re-reads the policy on every call, so a retry works without relaunching. To make it permanent, add to AGENTS.md:\n\n[network]\nallowed_hosts = [\"{host}:22\"]",
                                        host = row.host
                                    ));
                                }
                                DeniedKind::Gpg => {
                                    text.push_str(
                                        "\n\nThe relay refused to run gpg. Signing is not something the network policy can grant: gpg has no destination to name, so it is enabled by the launch flag alone. Relaunch the sandbox with --gpg.",
                                    );
                                }
                                DeniedKind::Egress => {}
                            }
                        }
                        let detail = Paragraph::new(text)
                            .wrap(Wrap { trim: false })
                            .scroll((detail_scroll, 0))
                            .block(Block::default().borders(Borders::ALL).title("Denied Request Details (redacted)"));
                        f.render_widget(detail, chunks[1]);
                    } else if denied_list.is_empty() {
                        let p = Paragraph::new("No denied requests yet. Waiting for sandbox egress...")
                            .style(Style::default().fg(Color::DarkGray))
                            .block(Block::default().borders(Borders::ALL).title("Denied Requests (0)"));
                        f.render_widget(p, chunks[1]);
                        selected_idx = 0;
                        table_state.select(None);
                    } else {
                        if selected_idx >= denied_list.len() {
                            selected_idx = denied_list.len().saturating_sub(1);
                        }
                        table_state.select(Some(selected_idx));

                        let rows = denied_list.iter().enumerate().map(|(i, d)| {
                            let method = d.method.as_deref().unwrap_or("");
                            let style = if i == selected_idx { selected_style } else { normal_style };
                            let method_style = match method {
                                "GET" | "POST" | "PUT" | "DELETE" => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                                "CONNECT" => Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                                // Not the proxy's verdict: a different gate
                                // refused these, so they read differently.
                                "SSH" | "GPG" => Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                                _ => Style::default().fg(Color::White),
                            };
                            // gpg has no destination and no port; a 0 in the
                            // column would read as a real one.
                            let port_cell = if d.kind == DeniedKind::Gpg {
                                String::new()
                            } else {
                                d.port.to_string()
                            };
                            Row::new(vec![
                                ratatui::text::Span::styled(method.to_string(), method_style),
                                ratatui::text::Span::raw(d.host.clone()),
                                ratatui::text::Span::raw(port_cell),
                                ratatui::text::Span::raw(d.info_cell()),
                            ]).style(style)
                        });

                        let table = Table::new(
                            rows,
                            [
                                Constraint::Length(9),
                                Constraint::Percentage(40),
                                Constraint::Length(7),
                                Constraint::Percentage(44),
                            ],
                        )
                        .header(
                            Row::new(vec!["Method", "Destination Host/IP", "Port", "Info"])
                                .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)),
                        )
                        .block(Block::default().borders(Borders::ALL).title(format!("Denied Requests ({})", denied_list.len())));
                        f.render_stateful_widget(table, chunks[1], &mut table_state);
                    }
                }
                View::Connections => {
                    if show_detail && !connections_list.is_empty() {
                        let selected = connections_list
                            .get(connections_selected_idx.min(connections_list.len() - 1));
                        let text = selected
                            .map(|ev| connection_detail_text(ev, &denied_reqs))
                            .unwrap_or_else(|| NO_CONNECTION_DETAIL.to_string());
                        let detail = Paragraph::new(text)
                            .wrap(Wrap { trim: false })
                            .scroll((detail_scroll, 0))
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .title("Connection Details (redacted)"),
                            );
                        f.render_widget(detail, chunks[1]);
                    } else if connections_list.is_empty() {
                        let p = Paragraph::new("No connections yet. Waiting for sandbox egress...")
                            .style(Style::default().fg(Color::DarkGray))
                            .block(Block::default().borders(Borders::ALL).title("Connections (0)"));
                        f.render_widget(p, chunks[1]);
                        connections_selected_idx = 0;
                        connections_table_state.select(None);
                    } else {
                        if connections_selected_idx >= connections_list.len() {
                            connections_selected_idx = connections_list.len().saturating_sub(1);
                        }
                        connections_table_state.select(Some(connections_selected_idx));

                        let rows = connections_list.iter().enumerate().map(|(i, ev)| {
                            let method = ev.method.as_deref().unwrap_or("");
                            let state = if ev.ev.as_deref() == Some("open") {
                                "OPEN".to_string()
                            } else {
                                ev.verdict.as_deref().unwrap_or("?").to_ascii_uppercase()
                            };
                            let target = match (&ev.host, ev.path.as_deref()) {
                                (Some(host), Some(path)) => format!("{}:{}{}", host, ev.port.unwrap_or(0), path),
                                (Some(host), None) => format!("{}:{}", host, ev.port.unwrap_or(0)),
                                _ => "?".to_string(),
                            };
                            let mut info = Vec::new();
                            if let Some(status) = ev.status { info.push(format!("HTTP {}", status)); }
                            if let Some(err) = &ev.err { info.push(err.clone()); }
                            if ev.ev.as_deref() != Some("open") {
                                info.push(format!("up {} / down {} / {}ms", ev.up.unwrap_or(0), ev.down.unwrap_or(0), ev.ms.unwrap_or(0)));
                            }
                            let style = if i == connections_selected_idx { selected_style } else { normal_style };
                            let state_style = match state.as_str() {
                                "ALLOW" => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                                "DENY" | "ERROR" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                                "OPEN" => Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                                _ => Style::default().fg(Color::Yellow),
                            };
                            Row::new(vec![
                                ratatui::text::Span::styled(state, state_style),
                                ratatui::text::Span::raw(method.to_string()),
                                ratatui::text::Span::raw(target),
                                ratatui::text::Span::raw(info.join(", ")),
                            ]).style(style)
                        });

                        let table = Table::new(
                            rows,
                            [Constraint::Length(8), Constraint::Length(9), Constraint::Percentage(38), Constraint::Percentage(42)],
                        )
                        .header(
                            Row::new(vec!["State", "Method", "Destination", "Info"])
                                .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)),
                        )
                        .block(Block::default().borders(Borders::ALL).title(format!("Connections ({})", connections_list.len())));
                        f.render_stateful_widget(table, chunks[1], &mut connections_table_state);
                    }
                }
                View::Rules => {
                    if policy_lines.is_empty() {
                        let p = Paragraph::new("No policy rules yet.")
                            .style(Style::default().fg(Color::DarkGray))
                            .block(Block::default().borders(Borders::ALL).title("Rules (0)"));
                        f.render_widget(p, chunks[1]);
                        rules_selected_idx = 0;
                        rules_table_state.select(None);
                    } else {
                        if rules_selected_idx >= policy_lines.len() {
                            rules_selected_idx = policy_lines.len().saturating_sub(1);
                        }
                        rules_table_state.select(Some(rules_selected_idx));

                        let rows = policy_lines.iter().enumerate().map(|(i, line)| {
                            let style = if i == rules_selected_idx { selected_style } else { normal_style };
                            let (key, value) = line.split_once(char::is_whitespace).unwrap_or((line.as_str(), ""));
                            let display_value = if key == "allow_route" {
                                value.trim().replace('\t', " ")
                            } else {
                                value.trim().to_string()
                            };
                            let source = if baseline_lines.contains(line) {
                                "built-in"
                            } else if base_lines.contains(line) {
                                "AGENTS.md"
                            } else {
                                "live"
                            };
                            Row::new(vec![key.to_string(), display_value, source.to_string()]).style(style)
                        });

                        let table = Table::new(
                            rows,
                            [Constraint::Length(15), Constraint::Percentage(60), Constraint::Length(12)],
                        )
                        .header(
                            Row::new(vec!["Key", "Value", "Source"])
                                .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)),
                        )
                        .block(Block::default().borders(Borders::ALL).title(format!("Rules ({})", policy_lines.len())));
                        f.render_stateful_widget(table, chunks[1], &mut rules_table_state);
                    }
                }
            }

            let legend_text = match view {
                View::Requests | View::Connections if show_detail => "↑/↓ scroll   [d]/[Esc] Back   [q] Quit",
                View::Requests => "↑/↓ select   [d] Details   [a] Allow (domain / SSH host)   [h] Allow HTTP route   [A] Allow IP\n[v] Connections view   [r] Rules view   [c] Clear   [q]/[Esc] Quit",
                View::Connections => "↑/↓ select   [d] Details   [v] Denied requests   [r] Rules view   [q]/[Esc] Quit",
                View::Rules => "↑/↓ select   [x] Remove rule (blocked for built-in/AGENTS.md rules)\n[r] Requests view   [q]/[Esc] Quit",
            };
            let instructions = Paragraph::new(legend_text)
                .block(Block::default().borders(Borders::ALL).title("Keybindings"));
            f.render_widget(instructions, chunks[2]);

            if !status_msg.is_empty() {
                let status = Paragraph::new(status_msg.as_str())
                    .style(Style::default().fg(status_kind.color()).add_modifier(Modifier::BOLD));
                f.render_widget(status, chunks[3]);
            } else {
                f.render_widget(Paragraph::new(""), chunks[3]);
            }
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(until) = ctrlc_armed_until {
                            if Instant::now() < until {
                                break;
                            }
                        }
                        status_msg = "Press Ctrl+C again to quit".to_string();
                        status_kind = StatusKind::Info;
                        status_until = Some(Instant::now() + Duration::from_secs(2));
                        ctrlc_armed_until = Some(Instant::now() + Duration::from_secs(2));
                    }
                    KeyCode::Char('q') => break,
                    KeyCode::Esc if show_detail => {
                        show_detail = false;
                        detail_scroll = 0;
                    }
                    KeyCode::Esc => break,
                    KeyCode::Up => match view {
                        View::Requests | View::Connections if show_detail => {
                            detail_scroll = detail_scroll.saturating_sub(1)
                        }
                        View::Requests => selected_idx = selected_idx.saturating_sub(1),
                        View::Connections => {
                            connections_selected_idx = connections_selected_idx.saturating_sub(1)
                        }
                        View::Rules => rules_selected_idx = rules_selected_idx.saturating_sub(1),
                    },
                    KeyCode::Down => match view {
                        View::Requests | View::Connections if show_detail => {
                            detail_scroll = detail_scroll.saturating_add(1)
                        }
                        View::Requests => {
                            selected_idx =
                                (selected_idx + 1).min(denied_list.len().saturating_sub(1));
                        }
                        View::Connections => {
                            connections_selected_idx = (connections_selected_idx + 1)
                                .min(connections_list.len().saturating_sub(1));
                        }
                        View::Rules => {
                            rules_selected_idx =
                                (rules_selected_idx + 1).min(policy_lines.len().saturating_sub(1));
                        }
                    },
                    KeyCode::Char('r') => {
                        view = match view {
                            View::Rules => View::Requests,
                            _ => View::Rules,
                        };
                    }
                    KeyCode::Char('v') if !show_detail => {
                        view = match view {
                            View::Requests => View::Connections,
                            View::Connections => View::Requests,
                            View::Rules => View::Connections,
                        };
                    }
                    KeyCode::Char('c') if view == View::Requests => {
                        denied_reqs.clear();
                        denied_list.clear();
                        selected_idx = 0;
                    }
                    KeyCode::Char('d') if view == View::Requests && !denied_list.is_empty() => {
                        show_detail = !show_detail;
                        detail_scroll = 0;
                    }
                    KeyCode::Char('d')
                        if view == View::Connections && !connections_list.is_empty() =>
                    {
                        show_detail = !show_detail;
                        detail_scroll = 0;
                    }
                    KeyCode::Char('a') | KeyCode::Char('A') | KeyCode::Char('h')
                        if view == View::Requests && !show_detail =>
                    {
                        if !denied_list.is_empty() && selected_idx < denied_list.len() {
                            let row = denied_list[selected_idx].clone();
                            let host = row.host.clone();
                            let port = row.port;
                            let method = row.method.clone();
                            let kind = row.kind;

                            let mut guard_msg: Option<String> = None;
                            let mut untrusted_key_host: Option<String> = None;
                            let mut detail = String::new();
                            let mut policy = load_policy_lines(sidecar_policy);

                            match key.code {
                                KeyCode::Char('a') if kind == DeniedKind::Gpg => {
                                    guard_msg = Some(
                                        "GPG signing is enabled by launching with --gpg, not by the network policy — gpg has no destination to name. Relaunch the sandbox."
                                            .to_string(),
                                    );
                                }
                                KeyCode::Char('a') => {
                                    // An SSH row takes two lines: allow_signing
                                    // is what the relay reads, and the :22 host
                                    // rule is what the exit summary renders back
                                    // as TOML so the grant can be made permanent.
                                    let lines = grant_lines(&row);
                                    detail = lines.join(" + ");
                                    for line in lines {
                                        if !policy.contains(&line) {
                                            policy.push(line);
                                        }
                                    }
                                    // The grant still goes through -- it is
                                    // correct and it is what was asked for --
                                    // but a host with no authorized key will
                                    // fail verification rather than connect,
                                    // and nothing running can add one.
                                    if kind == DeniedKind::Ssh
                                        && !trusts_host_key(sidecar_policy, &host)
                                    {
                                        untrusted_key_host = Some(host.clone());
                                    }
                                }
                                KeyCode::Char('A') => {
                                    if !ip_available(kind, &host) {
                                        guard_msg = Some(format!(
                                            "'{}' is not an IP — use 'a' to allow the domain instead",
                                            host
                                        ));
                                    } else {
                                        detail = format!("allow_ip {}:{}", host, port);
                                        policy.push(detail.clone());
                                    }
                                }
                                KeyCode::Char('h') => {
                                    if kind != DeniedKind::Egress {
                                        guard_msg = Some(
                                            "This is a relay decision, not an HTTP one — there is no route to allow. Use 'a'."
                                                .to_string(),
                                        );
                                    } else if !h_available(kind, method.as_deref()) {
                                        guard_msg = Some(
                                            "No HTTP method known yet for this row — allow the domain first with 'a'; 'h' becomes available once a real request is seen"
                                                .to_string(),
                                        );
                                    } else if !base_lines
                                        .iter()
                                        .any(|l| l.starts_with("allow_route\t"))
                                    {
                                        // An L7 rule means the proxy terminates TLS for
                                        // that host, and the session CA is bound into the
                                        // sandbox only when the launch policy already had
                                        // one.  Adding the first one here cannot work.
                                        guard_msg = Some(format!(
                                            "This sandbox launched with no L7 rule, so it does not trust the proxy's session CA — TLS to {} would fail. Declare the rule in AGENTS.md and relaunch.",
                                            host
                                        ));
                                    } else {
                                        let m = method.unwrap();
                                        detail = format!("allow_route {} {}", host, m);
                                        policy.push(format!("allow_route\t{}\t{}\t/*", host, m));
                                    }
                                }
                                _ => {}
                            }

                            if let Some(msg) = guard_msg {
                                status_msg = msg;
                                status_kind = StatusKind::Info;
                                status_until = Some(Instant::now() + Duration::from_secs(4));
                            } else if let Err(e) = install_policy(sidecar_policy, &policy) {
                                status_msg = format!("Error: {}", e);
                                status_kind = StatusKind::Error;
                                status_until = None;
                            } else {
                                clear_allowed_request(
                                    &mut denied_reqs,
                                    &host,
                                    port,
                                    &mut selected_idx,
                                );
                                match untrusted_key_host {
                                    Some(host) => {
                                        status_msg = format!(
                                            "Added, but no host key for {} is trusted here — SSH will fail verification. Add [[network.known_hosts]] to trusted.toml and relaunch.",
                                            host
                                        );
                                        status_kind = StatusKind::Info;
                                        status_until =
                                            Some(Instant::now() + Duration::from_secs(6));
                                    }
                                    None => {
                                        status_msg = format!("Added: {}", detail);
                                        status_kind = StatusKind::Success;
                                        status_until =
                                            Some(Instant::now() + Duration::from_secs(3));
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Char('x') if view == View::Rules => {
                        if let Some(line) = policy_lines.get(rules_selected_idx) {
                            if base_lines.contains(line) {
                                let label = if baseline_lines.contains(line) {
                                    "built-in"
                                } else {
                                    "AGENTS.md's baseline"
                                };
                                status_msg = format!(
                                    "'{}' comes from {} policy and can't be removed here — edit AGENTS.md and relaunch, or `agent-sandbox ctl proxy reset` first",
                                    line, label
                                );
                                status_kind = StatusKind::Info;
                                status_until = Some(Instant::now() + Duration::from_secs(5));
                            } else {
                                let mut lines = policy_lines.clone();
                                lines.remove(rules_selected_idx);
                                if let Err(e) = install_policy(sidecar_policy, &lines) {
                                    status_msg = format!("Error: {}", e);
                                    status_kind = StatusKind::Error;
                                    status_until = None;
                                } else {
                                    status_msg = format!("Removed: {}", line);
                                    status_kind = StatusKind::Success;
                                    status_until = Some(Instant::now() + Duration::from_secs(3));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        clear_allowed_request, connection_detail_text, grant_lines, h_available,
        ingest_connection_event, ingest_relay_event, ip_available, is_denied_event, ConnEvent,
        DeniedEntry, DeniedKind, RelayEvent, GPG_ROW_HOST, GPG_ROW_PORT, SSH_POLICY_PORT,
    };
    use std::collections::HashMap;

    fn event(ev: Option<&str>, verdict: Option<&str>) -> ConnEvent {
        ConnEvent {
            ev: ev.map(str::to_string),
            id: None,
            verdict: verdict.map(str::to_string),
            host: None,
            port: None,
            err: None,
            up: None,
            down: None,
            ms: None,
            method: None,
            path: None,
            status: None,
            ts: None,
        }
    }

    #[test]
    fn includes_l7_denial_close_events() {
        assert!(is_denied_event(&event(Some("close"), Some("deny"))));
        assert!(is_denied_event(&event(None, Some("deny"))));
        assert!(!is_denied_event(&event(Some("close"), Some("allow"))));
        assert!(!is_denied_event(&event(Some("open"), Some("deny"))));
    }

    fn connection(ev: &str, id: Option<&str>, ts: u64) -> ConnEvent {
        ConnEvent {
            ev: Some(ev.to_string()),
            id: id.map(str::to_string),
            verdict: if ev == "close" {
                Some("allow".to_string())
            } else {
                None
            },
            host: Some("example.com".to_string()),
            port: Some(443),
            err: None,
            up: Some(10),
            down: Some(20),
            ms: Some(5),
            method: None,
            path: None,
            status: None,
            ts: Some(ts),
        }
    }

    #[test]
    fn correlates_open_and_close_events() {
        let mut connections = Vec::new();
        ingest_connection_event(&mut connections, connection("open", Some("1"), 1));
        ingest_connection_event(&mut connections, connection("close", Some("1"), 2));

        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].ev.as_deref(), Some("close"));
        assert_eq!(connections[0].id.as_deref(), Some("1"));
    }

    #[test]
    fn retains_idless_terminal_events() {
        let mut connections = Vec::new();
        ingest_connection_event(&mut connections, connection("close", None, 1));

        assert_eq!(connections.len(), 1);
        assert!(connections[0].id.is_none());
    }

    #[test]
    fn connection_detail_carries_the_recorded_head_when_there_is_one() {
        let mut denied_reqs = HashMap::new();
        denied_reqs.insert(
            ("example.com".to_string(), 443),
            DeniedEntry {
                host: "example.com".to_string(),
                port: 443,
                reason: Some("no matching rule".to_string()),
                method: Some("GET".to_string()),
                detail: Some("GET /zen HTTP/1.1\r\nAuthorization: <redacted>".to_string()),
                count: 1,
                last_seen: 1,
                kind: DeniedKind::Egress,
            },
        );

        let text = connection_detail_text(&connection("close", Some("1"), 2), &denied_reqs);
        assert!(text.contains("example.com:443"), "{text}");
        assert!(text.contains("GET /zen"), "{text}");
    }

    /// The pane has to say why it is empty: heads exist for denials only, and
    /// an allowed tunnel that was never decrypted has nothing to show.
    #[test]
    fn connection_detail_explains_an_absent_head() {
        let text = connection_detail_text(&connection("open", Some("1"), 1), &HashMap::new());
        assert!(text.contains("in flight"), "{text}");
        assert!(text.contains("denied requests only"), "{text}");
    }

    #[test]
    fn clears_allowed_request_and_clamps_selection() {
        let mut denied_reqs = HashMap::new();
        denied_reqs.insert(
            ("example.com".to_string(), 443),
            DeniedEntry {
                host: "example.com".to_string(),
                port: 443,
                reason: None,
                method: None,
                detail: None,
                count: 1,
                last_seen: 1,
                kind: DeniedKind::Egress,
            },
        );
        denied_reqs.insert(
            ("other.example.com".to_string(), 443),
            DeniedEntry {
                host: "other.example.com".to_string(),
                port: 443,
                reason: None,
                method: None,
                detail: None,
                count: 1,
                last_seen: 1,
                kind: DeniedKind::Egress,
            },
        );
        let mut selected_idx = 1;

        clear_allowed_request(
            &mut denied_reqs,
            "other.example.com",
            443,
            &mut selected_idx,
        );

        assert!(!denied_reqs.contains_key(&("other.example.com".to_string(), 443)));
        assert_eq!(denied_reqs.len(), 1);
        assert_eq!(selected_idx, 0);
    }

    // ── relay denials ───────────────────────────────────────────────────────

    fn relay(cmd: &str, dest: Option<&str>, allowed: bool, reason: &str) -> RelayEvent {
        RelayEvent {
            cmd: cmd.to_string(),
            dest: dest.map(str::to_string),
            allowed,
            reason: Some(reason.to_string()),
            ts: Some(7),
        }
    }

    #[test]
    fn a_denied_ssh_relay_line_becomes_a_requests_row() {
        let mut denied = HashMap::new();
        ingest_relay_event(
            &mut denied,
            relay(
                "ssh",
                Some("github.com"),
                false,
                "denied by allow_signing policy",
            ),
        );

        // Filed under the policy port, not whatever ssh dialled: :22 is what an
        // allowed_hosts entry has to say for the relay to be authorized.
        let row = denied
            .get(&("github.com".to_string(), SSH_POLICY_PORT))
            .expect("a row for the refused destination");
        assert_eq!(row.kind, DeniedKind::Ssh);
        assert_eq!(row.method.as_deref(), Some("SSH"));
        assert_eq!(row.count, 1);
        assert_eq!(
            row.reason.as_deref(),
            Some("denied by allow_signing policy")
        );
    }

    #[test]
    fn repeated_relay_denials_are_one_row() {
        let mut denied = HashMap::new();
        for _ in 0..3 {
            ingest_relay_event(
                &mut denied,
                relay("ssh", Some("github.com"), false, "denied"),
            );
        }
        assert_eq!(denied.len(), 1);
        assert_eq!(denied.values().next().unwrap().count, 3);
    }

    #[test]
    fn an_allowed_relay_line_is_not_a_denial() {
        let mut denied = HashMap::new();
        ingest_relay_event(&mut denied, relay("ssh", Some("github.com"), true, ""));
        assert!(denied.is_empty());
    }

    #[test]
    fn a_relay_line_without_a_destination_is_dropped() {
        // "could not determine destination": there is no host to write a rule
        // for, so offering one would be a lie. `ctl relay` still shows it.
        let mut denied = HashMap::new();
        ingest_relay_event(
            &mut denied,
            relay("ssh", None, false, "could not determine destination"),
        );
        assert!(denied.is_empty());
    }

    #[test]
    fn a_gpg_denial_is_shown_but_offers_no_host_rule() {
        let mut denied = HashMap::new();
        ingest_relay_event(
            &mut denied,
            relay("gpg", None, false, "gpg signing not enabled"),
        );

        let row = denied
            .get(&(GPG_ROW_HOST.to_string(), GPG_ROW_PORT))
            .expect("a row for the refused gpg call");
        assert_eq!(row.kind, DeniedKind::Gpg);
        // Nothing in the policy grants signing; it comes from --gpg at launch.
        assert!(grant_lines(row).is_empty());
    }

    #[test]
    fn granting_an_ssh_row_writes_both_lines() {
        let mut denied = HashMap::new();
        ingest_relay_event(
            &mut denied,
            relay("ssh", Some("github.com"), false, "denied"),
        );
        let row = &denied[&("github.com".to_string(), SSH_POLICY_PORT)];

        assert_eq!(
            grant_lines(row),
            vec![
                "allow_signing github.com".to_string(),
                "allow_host github.com:22".to_string(),
            ]
        );
    }

    #[test]
    fn an_egress_row_still_grants_exactly_one_host_rule() {
        let row = DeniedEntry {
            host: "example.com".to_string(),
            port: 8443,
            reason: None,
            method: Some("CONNECT".to_string()),
            detail: None,
            count: 1,
            last_seen: 1,
            kind: DeniedKind::Egress,
        };
        assert_eq!(grant_lines(&row), vec!["allow_host example.com:8443"]);
    }

    /// Whatever the keypress writes has to be something `install_policy`
    /// accepts, or the grant fails at the moment the user asks for it.
    #[test]
    fn the_lines_a_grant_writes_are_lines_the_proxy_parses() {
        let mut denied = HashMap::new();
        ingest_relay_event(
            &mut denied,
            relay("ssh", Some("github.com"), false, "denied"),
        );
        let row = &denied[&("github.com".to_string(), SSH_POLICY_PORT)];

        let text = grant_lines(row).join("\n") + "\n";
        let cfg = agent_sandbox_proxy::policy::parse_policy(&text)
            .unwrap_or_else(|e| panic!("the proxy rejected a TUI grant: {e}\n{text}"));
        assert_eq!(cfg.allow_signing, vec!["github.com".to_string()]);
        assert!(cfg.is_allowed("github.com", 22));
    }

    #[test]
    fn relay_rows_offer_neither_h_nor_a_capital_a() {
        // Nothing about a relay decision is HTTP, and it authorizes a host
        // rather than an address.
        assert!(!h_available(DeniedKind::Ssh, Some("SSH")));
        assert!(!h_available(DeniedKind::Gpg, Some("GPG")));
        assert!(!ip_available(DeniedKind::Ssh, "10.0.0.1"));
        assert!(!ip_available(DeniedKind::Gpg, "10.0.0.1"));

        // Unchanged for the proxy's own denials.
        assert!(h_available(DeniedKind::Egress, Some("GET")));
        assert!(!h_available(DeniedKind::Egress, Some("CONNECT")));
        assert!(ip_available(DeniedKind::Egress, "10.0.0.1"));
        assert!(!ip_available(DeniedKind::Egress, "example.com"));
    }

    /// A sidecar built before `ts` existed still produces usable rows.
    #[test]
    fn a_relay_line_without_a_timestamp_is_still_ingested() {
        let mut denied = HashMap::new();
        ingest_relay_event(
            &mut denied,
            RelayEvent {
                cmd: "ssh".to_string(),
                dest: Some("github.com".to_string()),
                allowed: false,
                reason: None,
                ts: None,
            },
        );
        let row = &denied[&("github.com".to_string(), SSH_POLICY_PORT)];
        assert!(row.last_seen > 0);
    }
}
