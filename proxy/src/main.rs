#![forbid(unsafe_code)]

//! Forward proxy for the agent-sandbox sidecar.
//!
//! Usage: agent-sandbox-proxy [--policy FILE] [--log FILE] [--listen ADDR]
//!                            [--allow-domains LIST] [--allow-ipss LIST]
//!                            [--allow-portss LIST] [--check-policy FILE]
//!
//! Policy comes from a file (one `KEY VALUE` per line, see `parse_policy`) or
//! from the inline lists, never both.  Anything wrong with it exits 2 before the
//! listener binds, so a policy the operator got wrong cannot degrade into a
//! weaker one that appears to work.
//!
//! `--log` appends newline-delimited JSON, one object per connection event,
//! rendered by agent-sandbox-network-summary. `--detail-log` is a bounded,
//! ephemeral stream of sanitized denied request heads for the TUI.

mod inject;
mod l7;
mod secret;
mod tls;

use agent_sandbox_proxy::logfile::rotate_if_needed;
use ipnet::IpNet;
use secret::{SecretBinding, SecretBindings};
use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tls::SessionCa;

/// Read timeout on proxied sockets.  This is only a liveness tick so a blocked
/// read can be retried, *not* an idle cap: a stream that goes quiet for longer
/// (a streaming completion waiting on the model, a slow git server) must not be
/// severed.  See `pump`.
const IO_TICK: Duration = Duration::from_secs(300);
/// A client that opens a connection and never sends a request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TTL: Duration = Duration::from_secs(60);
/// Retry floor applied to *every* resolve and connect.  The sidecar's network
/// can wobble well after the proxy binds, so this must not be scoped to
/// startup: doing that turned a transient blip into a hard 502 and made
/// launches flicker.  Successful lookups are cached for `DNS_TTL`, so a host
/// pays this at most once a minute.
const RETRY_WINDOW: Duration = Duration::from_millis(1000);
/// How long after process start the resolve/connect paths keep retrying, on
/// top of `RETRY_WINDOW`.
const STARTUP_GRACE: Duration = Duration::from_secs(10);
/// How long `wait_for_egress` blocks before giving up and starting anyway.
const READY_TIMEOUT: Duration = Duration::from_secs(30);
/// Name resolved to decide the sidecar's network is actually usable.  Only
/// resolved, never connected to, so this stays policy-neutral under
/// `--proxy`.
const READY_PROBE_HOST: &str = "cloudflare.com:443";
/// Directory the proxy writes its own state into.  In the sidecar this is the
/// launcher-owned volume the sandbox cannot see; `agent-sandbox browser` runs
/// this same binary on the host and points it at a per-instance runtime dir
/// instead, which is the whole reason the three paths below are derived rather
/// than constant.
const DEFAULT_SHARED_DIR: &str = "/sidecar_shared";
/// Ports the `--transparent` listeners take over.  They are the origin ports a
/// client that ignores the proxy environment would dial, which is the whole
/// point: the launcher resolves every allowed name to the sidecar, so those
/// dials land here instead of nowhere.
const TRANSPARENT_HTTP_PORT: u16 = 80;
const TRANSPARENT_HTTPS_PORT: u16 = 443;

/// The address part of a `HOST:PORT` listen spec, keeping a bracketed IPv6
/// literal intact.
fn listen_ip(listen: &str) -> &str {
    if let Some(end) = listen.rfind(']') {
        return &listen[..=end];
    }
    listen.rsplit_once(':').map(|(h, _)| h).unwrap_or(listen)
}

/// Written by the proxy, read by the sidecar's readiness gate on the host.
fn proxy_ready_path(shared_dir: &str) -> String {
    format!("{}/proxy-ready", shared_dir)
}
/// Public session CA for sandbox trust bootstrap, when MITM-capable secret
/// domains are configured.
fn proxy_ca_pem_path(shared_dir: &str) -> String {
    format!("{}/ca.pem", shared_dir)
}
/// Written only when `wait_for_egress` gives up, and carrying why.
fn egress_degraded_path(shared_dir: &str) -> String {
    format!("{}/egress-degraded", shared_dir)
}
const BUF_SIZE: usize = 64 * 1024;
const HEAD_MAX: usize = 8192;
const DNS_CACHE_MAX: usize = 512;
/// How often the policy file is checked for changes.
const POLICY_POLL: Duration = Duration::from_secs(1);

pub mod policy;
use policy::*;

// ── Name resolution ─────────────────────────────────────────────────────────

/// Agents reconnect to the same handful of hosts constantly, so a short-TTL
/// cache removes a resolver round trip from most connections.
struct Resolver {
    cache: Mutex<HashMap<String, (Vec<SocketAddr>, Instant)>>,
}

impl Resolver {
    fn new() -> Self {
        Resolver {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Drop every cached lookup.  Called on a policy change: cached *addresses*
    /// are checked against the current deny list, so a stale entry could carry a
    /// newly-denied address for up to DNS_TTL.  Costs one re-resolve per live
    /// host, which refills within a second.
    fn clear(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    /// Resolve, retrying until at least `RETRY_WINDOW` has elapsed (longer if
    /// `retry_until` extends past that).  Only successes are cached — caching a
    /// failure would pin an outage in place for `DNS_TTL`.
    fn resolve(
        &self,
        host: &str,
        port: u16,
        retry_until: Instant,
    ) -> Result<Vec<SocketAddr>, io::Error> {
        let key = format!("{}:{}", host, port);

        if let Ok(cache) = self.cache.lock() {
            if let Some((addrs, cached_at)) = cache.get(&key) {
                if cached_at.elapsed() < DNS_TTL {
                    return Ok(addrs.clone());
                }
            }
        }

        let deadline = (Instant::now() + RETRY_WINDOW).max(retry_until);
        let mut last_err;
        loop {
            match key.to_socket_addrs() {
                Ok(found) => {
                    let addrs: Vec<SocketAddr> = found.collect();
                    if !addrs.is_empty() {
                        if let Ok(mut cache) = self.cache.lock() {
                            if cache.len() >= DNS_CACHE_MAX {
                                cache.clear();
                            }
                            cache.insert(key, (addrs.clone(), Instant::now()));
                        }
                        return Ok(addrs);
                    }
                    last_err =
                        io::Error::new(ErrorKind::NotFound, "resolver returned no addresses");
                }
                Err(e) => last_err = e,
            }
            if Instant::now() >= deadline {
                return Err(last_err);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

// ── Metering ────────────────────────────────────────────────────────────────

/// One JSON line per connection event, consumed by `agent-sandbox-network-summary`
/// to render the `--proxy` summary and the `agent-sandbox ctl net` live
/// view.  Cheap enough to leave on: a few hundred bytes per connection, versus
/// the full-payload packet capture it replaces.
///
/// A connection that is allowed writes two lines: `"ev":"open"` when the tunnel
/// is established and `"ev":"close"` when it ends, correlated by `id`.  Without
/// the open line a long-lived tunnel is invisible for as long as it lives, which
/// is precisely the traffic worth watching.  Connections rejected before that
/// point write only their terminal line, with no `ev` and no `id`: they resolve
/// within milliseconds, so a paired open would double every error row without
/// adding anything.
struct MetricsLog {
    file: Mutex<File>,
    detail_file: Option<Mutex<File>>,
    /// Process start, in epoch seconds.  Ids embed it so two proxies appending
    /// to the same log cannot mint colliding ids — a correlation id that
    /// silently aliases is worse than none.
    boot: u64,
    next_id: AtomicU64,
}

const METRICS_LOG_MAX_BYTES: u64 = 16 * 1024 * 1024;
const DETAIL_LOG_MAX_BYTES: u64 = 4 * 1024 * 1024;
const DETAIL_HEAD_MAX_BYTES: usize = 16 * 1024;

fn sensitive_header(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    name == "authorization"
        || name == "proxy-authorization"
        || name == "cookie"
        || name == "set-cookie"
        || name.contains("api-key")
        || name.contains("apikey")
        || name.contains("token")
        || name.contains("secret")
}

fn sanitize_request_head(head: &str) -> String {
    head.lines()
        .map(|line| {
            if let Some((name, _)) = line.split_once(':') {
                if sensitive_header(name) {
                    return format!("{}: <redacted>", name.trim());
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Trim the boilerplate std prepends to resolver errors so the summary stays
/// readable: "failed to lookup address information: Temporary failure in name
/// resolution" carries one useful clause.
fn short_err(e: &io::Error) -> String {
    let s = e.to_string();
    match s.split_once(": ") {
        Some((head, tail)) if head.starts_with("failed to lookup address information") => {
            tail.to_string()
        }
        _ => s,
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Whole seconds since the epoch, or 0 if the clock is before it.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl MetricsLog {
    fn open(path: &str, detail_path: Option<&str>) -> Option<Arc<MetricsLog>> {
        // `read` as well as `append`: bounding the log reads back the tail it
        // keeps (see `rotate_if_needed`), which an append-only handle refuses.
        match OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
        {
            Ok(f) => {
                let detail_file = detail_path
                    .and_then(|path| {
                        OpenOptions::new()
                            .create(true)
                            .append(true)
                            .read(true)
                            .open(path)
                            .ok()
                    })
                    .map(Mutex::new);
                Some(Arc::new(MetricsLog {
                    file: Mutex::new(f),
                    detail_file,
                    boot: now_secs(),
                    next_id: AtomicU64::new(1),
                }))
            }
            Err(e) => {
                eprintln!("proxy: cannot open metrics log {}: {}", path, e);
                None
            }
        }
    }

    fn write_line(&self, line: &str) {
        if let Ok(mut f) = self.file.lock() {
            let _ = rotate_if_needed(&mut f, line.len() as u64, METRICS_LOG_MAX_BYTES);
            let _ = f.write_all(line.as_bytes());
        }
    }

    fn denied_detail(&self, host: &str, port: u16, reason: &str, head: &str) {
        let Some(file) = &self.detail_file else {
            return;
        };
        let head = sanitize_request_head(&String::from_utf8_lossy(
            &head.as_bytes()[..head.len().min(DETAIL_HEAD_MAX_BYTES)],
        ));
        let line = format!(
            "{{\"ts\":{},\"host\":\"{}\",\"port\":{},\"reason\":\"{}\",\"request\":\"{}\"}}\n",
            now_secs(),
            json_escape(host),
            port,
            json_escape(reason),
            json_escape(&head)
        );
        if let Ok(mut file) = file.lock() {
            let _ = rotate_if_needed(&mut file, line.len() as u64, DETAIL_LOG_MAX_BYTES);
            let _ = file.write_all(line.as_bytes());
        }
    }

    fn denied_http_detail(&self, host: &str, port: u16, reason: &str, method: &str, path: &str) {
        let request = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);
        self.denied_detail(host, port, reason, &request);
    }

    fn next_id(&self) -> String {
        format!(
            "{}-{}",
            self.boot,
            self.next_id.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Marks a policy change in the connection log, so `ctl net -f` shows it
    /// interleaved with the connections it affected.
    fn policy_event(&self) {
        self.write_line(&format!("{{\"ev\":\"policy\",\"ts\":{}}}\n", now_secs()));
    }

    /// A connection has been established and is now pumping bytes.
    fn open_event(&self, id: &str, host: &str, port: u16) {
        self.write_line(&format!(
            "{{\"ev\":\"open\",\"id\":\"{}\",\"ts\":{},\"host\":\"{}\",\"port\":{}}}\n",
            id,
            now_secs(),
            json_escape(host),
            port
        ));
    }

    /// A connection has reached a terminal state.  `id` is `Some` only for
    /// connections that announced themselves with `open_event`; with `None` the
    /// line is byte-for-byte what earlier versions wrote.
    fn record(
        &self,
        id: Option<&str>,
        host: &str,
        port: u16,
        verdict: &str,
        err: Option<&str>,
        up: u64,
        down: u64,
        ms: u128,
        method: Option<&str>,
        path: Option<&str>,
        status: Option<u16>,
    ) {
        let mut line = String::new();
        if let Some(id) = id {
            line.push_str(&format!("{{\"ev\":\"close\",\"id\":\"{}\",", id));
        } else {
            line.push('{');
        }
        line.push_str(&format!(
            "\"ts\":{},\"host\":\"{}\",\"port\":{},\"verdict\":\"{}\",\"up\":{},\"down\":{},\"ms\":{}",
            now_secs(),
            json_escape(host),
            port,
            verdict,
            up,
            down,
            ms
        ));
        if let Some(e) = err {
            line.push_str(&format!(",\"err\":\"{}\"", json_escape(e)));
        }
        if let Some(m) = method {
            line.push_str(&format!(",\"method\":\"{}\"", json_escape(m)));
        }
        if let Some(p) = path {
            line.push_str(&format!(",\"path\":\"{}\"", json_escape(p)));
        }
        if let Some(s) = status {
            line.push_str(&format!(",\"status\":{}", s));
        }
        line.push_str("}\n");

        self.write_line(&line);
    }
}

// ── Connection handling ─────────────────────────────────────────────────────

struct Shared {
    /// `RwLock<Arc<_>>` rather than `RwLock<ProxyConfig>`: a handler clones the
    /// Arc and releases the lock immediately, instead of holding a read guard
    /// across `resolve`, which can block for `RETRY_WINDOW`.  Each connection
    /// then evaluates one immutable snapshot for its whole life, so a reload can
    /// never split a decision in half.
    config: RwLock<Arc<ProxyConfig>>,
    secrets: Arc<SecretBindings>,
    session_ca: Option<Arc<SessionCa>>,
    resolver: Resolver,
    metrics: Option<Arc<MetricsLog>>,
    /// Instant until which the resolve/connect paths keep retrying.
    startup_until: Instant,
}

impl Shared {
    /// A snapshot of the policy.  Poisoning is degraded into "use the value
    /// anyway" rather than a panic: a handler thread dying on a lock is a worse
    /// outcome than acting on a config someone else was mid-swap on.
    fn config(&self) -> Arc<ProxyConfig> {
        Arc::clone(&self.config.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Apply the policy ∧ provider gate for one request.
    ///
    /// Called per request rather than per connection: a keep-alive connection
    /// carries many requests, and resolving once at CONNECT time meant a
    /// token authorized for a single route was injected into every request
    /// that followed it on the same socket.
    fn secret_for_request(&self, host: &str, method: &str, path: &str) -> Option<&SecretBinding> {
        if !self.config().is_secret_route(host, method, path) {
            return None;
        }
        let normalized = normalize_host(host)?;
        if normalized
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<IpAddr>()
            .is_ok()
        {
            return None;
        }
        self.secrets.binding_for_request(&normalized, method, path)
    }

    /// Install a new policy.  The DNS cache goes with it: the name check runs
    /// before resolution so it is unaffected, but `is_denied_address` is
    /// evaluated against *cached* addresses, and a stale set would let a
    /// just-denied address through for up to DNS_TTL.
    fn replace_config(&self, config: ProxyConfig) {
        eprintln!("proxy: policy reloaded");
        for line in config.describe() {
            eprintln!("proxy:   {}", line);
        }
        if let Ok(mut slot) = self.config.write() {
            *slot = Arc::new(config);
        }
        self.resolver.clear();
        if let Some(m) = &self.metrics {
            m.policy_event();
        }
    }

    fn denied_detail(&self, host: &str, port: u16, reason: &str, request_head: &str) {
        if let Some(m) = &self.metrics {
            m.denied_detail(host, port, reason, request_head);
        }
    }

    fn denied_http_detail(&self, host: &str, port: u16, reason: &str, method: &str, path: &str) {
        if let Some(m) = &self.metrics {
            m.denied_http_detail(host, port, reason, method, path);
        }
    }

    fn record(
        &self,
        id: Option<&str>,
        host: &str,
        port: u16,
        verdict: &str,
        err: Option<&str>,
        up: u64,
        down: u64,
        ms: u128,
        method: Option<&str>,
        path: Option<&str>,
        status: Option<u16>,
    ) {
        if let Some(m) = &self.metrics {
            m.record(
                id, host, port, verdict, err, up, down, ms, method, path, status,
            );
        }
    }

    /// Announce an established connection, returning the id to close it with.
    /// `None` when metering is off, which makes the close path a no-op too.
    fn open_event(&self, host: &str, port: u16) -> Option<String> {
        let m = self.metrics.as_ref()?;
        let id = m.next_id();
        m.open_event(&id, host, port);
        Some(id)
    }

    fn is_allowed(&self, host: &str, port: u16) -> bool {
        self.config().is_allowed(host, port)
    }

    /// Returns `(true, None)` if the request is allowed, or `(false, Some(reason))`
    /// when it is denied.  The reason is meant for logs only, not for the client.
    pub fn l7_check(&self, host: &str, method: &str, path: &str) -> (bool, Option<String>) {
        let cfg = self.config();
        if cfg.is_l7_allowed(host, method, path) {
            (true, None)
        } else {
            (false, Some(cfg.why_l7_denied(host, method, path)))
        }
    }
}

struct PrefixedStream {
    inner: TcpStream,
    prefix: Vec<u8>,
    pos: usize,
}

impl PrefixedStream {
    fn new(inner: TcpStream, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            pos: 0,
        }
    }

    /// Hand back the underlying socket once the prefix is spent, so the
    /// caller can hand it to something (like `pump`) that wants a real
    /// `TcpStream` rather than this wrapper.  Any unread prefix bytes are
    /// lost, which is only safe once the caller knows none remain.
    fn into_inner(self) -> TcpStream {
        self.inner
    }
}

impl Read for PrefixedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.prefix.len() {
            let remaining = self.prefix.len() - self.pos;
            let copy_len = remaining.min(buf.len());
            buf[..copy_len].copy_from_slice(&self.prefix[self.pos..self.pos + copy_len]);
            self.pos += copy_len;
            return Ok(copy_len);
        }
        self.inner.read(buf)
    }
}

impl Write for PrefixedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// How a connection reached the proxy.
///
/// `Proxy` is the ordinary forward-proxy path: the client addressed *this
/// process*, in HTTP, and can be answered with an HTTP status line.
///
/// The transparent variants exist for clients that ignore the proxy
/// environment altogether.  The one that forced them is the libgit2 inside
/// `nix` (and so inside `devenv`): its flake fetcher calls
/// `git_remote_connect` with a null `git_proxy_options`, which is
/// `GIT_PROXY_NONE` — so it consults neither `https_proxy` nor `http.proxy`,
/// and it works on a *detached* remote, which has no repository and therefore
/// no git config to consult in the first place.  No environment variable and
/// no config file can redirect it.  So the launcher points every allowed name
/// at the sidecar in the sandbox's `/etc/hosts` instead, and the "direct"
/// connection lands here.  The destination is then recovered from the TLS SNI
/// or the `Host` header rather than from a request line, and everything after
/// that — policy, address re-check, L7 interception, logging — is the same
/// code as for a `CONNECT`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ingress {
    Proxy,
    TransparentTls,
    TransparentHttp,
}

impl Ingress {
    /// Whether the peer is an HTTP client that can read a status line.  A
    /// transparent TLS peer is mid-handshake and would only see an
    /// `HTTP/1.1 403` as protocol garbage, so for it a closed socket is the
    /// only signal that carries.
    fn speaks_http(self) -> bool {
        self != Ingress::TransparentTls
    }
}

/// Send an HTTP status line to the client, unless the client is not speaking
/// HTTP yet.  Errors are dropped: every caller is already on its way out.
fn reply(sock: &mut TcpStream, ingress: Ingress, resp: &[u8]) {
    if ingress.speaks_http() {
        let _ = sock.write_all(resp);
    }
}

/// Read one TLS record holding a ClientHello and return it verbatim together
/// with the SNI host name it carries.
///
/// The bytes are returned unparsed as well as parsed because they still belong
/// to the origin: on the pass-through path they are replayed to the upstream
/// socket, and on the interception path they are fed back to rustls through
/// `PrefixedStream`, exactly as the `CONNECT` path replays the bytes that
/// arrived alongside the request head.
///
/// A ClientHello may in principle be fragmented across records; in practice
/// the first flight is one record, and a client that fragments it simply does
/// not get the transparent path.
fn read_client_hello(sock: &mut TcpStream) -> Option<(Vec<u8>, String)> {
    let mut header = [0u8; 5];
    read_exact_tolerant(sock, &mut header)?;
    // Handshake record, and a length that fits TLS's own 2^14 ceiling.
    if header[0] != 0x16 {
        return None;
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len == 0 || len > 16384 {
        return None;
    }
    let mut record = vec![0u8; 5 + len];
    record[..5].copy_from_slice(&header);
    read_exact_tolerant(sock, &mut record[5..])?;
    let sni = parse_client_hello_sni(&record[5..])?;
    Some((record, sni))
}

/// `Read::read_exact`, but retrying the interruptions `pump` also tolerates.
fn read_exact_tolerant(sock: &mut TcpStream, buf: &mut [u8]) -> Option<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match sock.read(&mut buf[filled..]) {
            Ok(0) => return None,
            Ok(k) => filled += k,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(())
}

/// Pull the `server_name` extension out of a ClientHello handshake message.
///
/// Every length in here is attacker-controlled, so each step is bounds-checked
/// against the slice rather than trusted: a malformed hello must yield `None`,
/// never a panic in a thread that is holding a client connection.
fn parse_client_hello_sni(body: &[u8]) -> Option<String> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Option<&[u8]> {
        let end = p.checked_add(n)?;
        let out = body.get(*p..end)?;
        *p = end;
        Some(out)
    };

    // Handshake header: type 1 (client_hello) and a 24-bit length.
    if *take(&mut p, 1)?.first()? != 0x01 {
        return None;
    }
    let _len = take(&mut p, 3)?;
    // legacy_version (2) + random (32)
    take(&mut p, 34)?;
    // legacy_session_id
    let n = *take(&mut p, 1)?.first()? as usize;
    take(&mut p, n)?;
    // cipher_suites
    let n = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?) as usize;
    take(&mut p, n)?;
    // legacy_compression_methods
    let n = *take(&mut p, 1)?.first()? as usize;
    take(&mut p, n)?;

    // extensions
    let ext_len = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?) as usize;
    let ext_end = p.checked_add(ext_len)?;
    while p < ext_end {
        let ext_type = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?);
        let ext_body_len = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?) as usize;
        let ext_body = take(&mut p, ext_body_len)?;
        if ext_type != 0x0000 {
            continue;
        }
        // ServerNameList: 2-byte list length, then entries of
        // { name_type (1), length (2), name }.  Only host_name (0) exists.
        let mut q = 2usize;
        while q + 3 <= ext_body.len() {
            let name_type = ext_body[q];
            let name_len = u16::from_be_bytes([ext_body[q + 1], ext_body[q + 2]]) as usize;
            q += 3;
            let name = ext_body.get(q..q.checked_add(name_len)?)?;
            q += name_len;
            if name_type == 0 {
                return std::str::from_utf8(name).ok().map(|s| s.to_string());
            }
        }
        return None;
    }
    None
}

/// The value of the first `Host:` header in a request head.
fn host_header(head: &str) -> Option<&str> {
    head.lines()
        .skip(1)
        .find(|l| l.len() >= 5 && l[..5].eq_ignore_ascii_case("host:"))
        .map(|l| l[5..].trim())
        .filter(|v| !v.is_empty())
}

/// Copy `src` into `dst` until either side is done, returning the byte count.
///
/// A read timeout means "nothing to say yet", not "hang up" — treating it as
/// fatal severs long-lived idle streams.  On a real end-of-stream the write
/// half of `dst` is shut down so the peer observes EOF immediately, rather
/// than the connection lingering until the opposite direction times out.
fn pump(mut src: TcpStream, mut dst: TcpStream) -> u64 {
    let mut buf = vec![0u8; BUF_SIZE];
    let mut total: u64 = 0;
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(ref e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    || e.kind() == ErrorKind::Interrupted =>
            {
                continue
            }
            Err(_) => break,
        }
    }
    let _ = dst.shutdown(Shutdown::Write);
    total
}

/// Read until the end of the HTTP request head.  A request line can be split
/// across TCP segments, so a single `read` is not enough to parse against.
fn read_head(sock: &mut TcpStream, buf: &mut [u8]) -> Option<usize> {
    let mut n = 0;
    loop {
        if n == buf.len() {
            return Some(n);
        }
        match sock.read(&mut buf[n..]) {
            Ok(0) => return if n > 0 { Some(n) } else { None },
            Ok(k) => {
                // Rescan only the new bytes plus the 3-byte overlap.
                let scan_from = n.saturating_sub(3);
                n += k;
                if buf[scan_from..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    return Some(n);
                }
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return if n > 0 { Some(n) } else { None },
        }
    }
}

fn split_head_and_extra(buf: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        (&buf[..pos + 4], &buf[pos + 4..])
    } else {
        (buf, &[])
    }
}

/// Connect to the first address that answers, retrying for at least
/// `RETRY_WINDOW` so a momentarily unreachable network does not become a 502.
fn connect_any(addrs: &[SocketAddr], retry_until: Instant) -> Result<TcpStream, io::Error> {
    let deadline = (Instant::now() + RETRY_WINDOW).max(retry_until);
    let mut last_err = io::Error::new(ErrorKind::InvalidInput, "no addresses to connect to");
    loop {
        for addr in addrs {
            match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
                Ok(s) => return Ok(s),
                Err(e) => last_err = e,
            }
        }
        if Instant::now() >= deadline {
            return Err(last_err);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Serve one client connection to completion.
///
/// `ingress` decides only how the destination is learned and whether the peer
/// can be answered in HTTP; every policy decision below is the same for all
/// three.
fn serve(mut client_sock: TcpStream, shared: Arc<Shared>, ingress: Ingress) {
    let started = Instant::now();
    let _ = client_sock.set_nodelay(true);
    let _ = client_sock.set_read_timeout(Some(HEAD_TIMEOUT));

    // The port the client actually dialled.  On a transparent listener that is
    // the origin port it believed it was reaching, which is what policy has to
    // be checked against.
    let local_port = client_sock.local_addr().map(|a| a.port()).unwrap_or(0);

    let mut req_buf = [0u8; HEAD_MAX];
    let n;
    // Bytes already read from the client that belong to the origin rather than
    // to us — on the transparent TLS path, the ClientHello we had to consume
    // to learn where the connection was going.
    let mut prelude: Vec<u8> = Vec::new();

    if ingress == Ingress::TransparentTls {
        let (hello, sni) = match read_client_hello(&mut client_sock) {
            Some(v) => v,
            None => return,
        };
        // Synthesised rather than special-cased, so the whole pipeline below —
        // policy, resolution, interception, logging — sees the same shape it
        // sees for a real CONNECT.
        let head = format!("CONNECT {}:{} HTTP/1.1\r\n\r\n", sni, local_port);
        if head.len() > req_buf.len() {
            return;
        }
        req_buf[..head.len()].copy_from_slice(head.as_bytes());
        n = head.len();
        prelude = hello;
    } else {
        n = match read_head(&mut client_sock, &mut req_buf) {
            Some(n) => n,
            None => return,
        };
    }

    let req_str = String::from_utf8_lossy(&req_buf[..n]);
    let first_line = req_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 3 {
        reply(&mut client_sock, ingress, b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    }

    let method = parts[0];
    let mut url = parts[1];

    let raw_host;
    let port: u16;

    if method == "CONNECT" {
        if let Some((h, p)) = url.rsplit_once(':') {
            raw_host = h.to_ascii_lowercase();
            port = p.parse().unwrap_or(443);
        } else {
            raw_host = url.to_ascii_lowercase();
            port = 443;
        }
    } else {
        if let Some(idx) = url.find("://") {
            url = &url[idx + 3..];
        } else if ingress == Ingress::TransparentHttp {
            // Origin-form: a transparent client believes it is talking to the
            // origin server, so the authority is only in the Host header.
            url = host_header(&req_str).unwrap_or("");
        }
        let url_no_path = url.split('/').next().unwrap_or("");
        let default_port = if ingress == Ingress::TransparentHttp {
            local_port
        } else {
            80
        };
        if let Some((h, p)) = url_no_path.rsplit_once(':') {
            raw_host = h.to_ascii_lowercase();
            port = p.parse().unwrap_or(default_port);
        } else {
            raw_host = url_no_path.to_ascii_lowercase();
            port = default_port;
        }
    }

    if raw_host.is_empty() {
        reply(&mut client_sock, ingress, b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    }

    let host = match normalize_host(&raw_host) {
        Some(h) => h,
        None => {
            reply(&mut client_sock, ingress, b"HTTP/1.1 400 Bad Request\r\n\r\n");
            return;
        }
    };

    // From here the two paths converge: whatever the client already sent that
    // is destined for the origin travels as `prelude`.
    if prelude.is_empty() {
        prelude = split_head_and_extra(&req_buf[..n]).1.to_vec();
    }

    // One snapshot for this connection's lifetime.  Taken after the head is
    // parsed so a reload landing mid-handshake cannot make the name check and the
    // resolved-address check disagree.
    let cfg = shared.config();

    if !shared.is_allowed(&host, port) {
        let reason = cfg.why_denied(&host, port);
        reply(&mut client_sock, ingress, b"HTTP/1.1 403 Forbidden\r\n\r\n");
        eprintln!("proxy: deny {}:{} ({})", host, port, reason);
        shared.denied_detail(&host, port, &reason, &req_str);
        shared.record(
            None,
            &host,
            port,
            "deny",
            Some(&reason),
            0,
            0,
            started.elapsed().as_millis(),
            Some(method),
            None,
            None,
        );
        return;
    }

    let addrs = match shared.resolver.resolve(&host, port, shared.startup_until) {
        Ok(a) => a,
        Err(e) => {
            reply(&mut client_sock, ingress, b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            eprintln!("proxy: dns failure {}:{}: {}", host, port, e);
            let detail = format!("dns: {}", short_err(&e));
            shared.record(
                None,
                &host,
                port,
                "error",
                Some(&detail),
                0,
                0,
                started.elapsed().as_millis(),
                None,
                None,
                None,
            );
            return;
        }
    };

    // The policy check above ran on the name.  Re-check what it actually
    // resolves to, so a denied address cannot be reached via an allowed (or
    // merely unlisted) hostname.
    if let Some(bad) = addrs.iter().find(|a| cfg.is_denied_address(a.ip())) {
        let reason = cfg.why_address_denied(bad.ip());
        reply(&mut client_sock, ingress, b"HTTP/1.1 403 Forbidden\r\n\r\n");
        eprintln!("proxy: deny {}:{} ({})", host, port, reason);
        shared.denied_detail(&host, port, &reason, &req_str);
        shared.record(
            None,
            &host,
            port,
            "deny",
            Some(&reason),
            0,
            0,
            started.elapsed().as_millis(),
            None,
            None,
            None,
        );
        return;
    }

    let mut remote_sock = match connect_any(&addrs, shared.startup_until) {
        Ok(s) => s,
        Err(e) => {
            reply(&mut client_sock, ingress, b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            eprintln!("proxy: connect failure {}:{}: {}", host, port, e);
            let detail = format!("connect: {}", short_err(&e));
            shared.record(
                None,
                &host,
                port,
                "error",
                Some(&detail),
                0,
                0,
                started.elapsed().as_millis(),
                None,
                None,
                None,
            );
            return;
        }
    };

    // Without this both directions pay a Nagle/delayed-ACK stall on every
    // request/response turn: TLS handshakes, HTTP/2 frames, git negotiation.
    let _ = remote_sock.set_nodelay(true);
    let _ = remote_sock.set_read_timeout(Some(IO_TICK));
    let _ = client_sock.set_read_timeout(Some(IO_TICK));

    // Snapshot again, since we might have waited for ask
    let cfg = shared.config();

    let is_domain_allowed = cfg.is_allowed_target(&host);
    let has_l7 = cfg.has_l7_rules(&host);
    let skip_l7 = is_domain_allowed && !has_l7;

    if method != "CONNECT" {
        // Host-level on purpose: refuse cleartext to a host that carries
        // any secret route, not only on the routes that would inject.
        if cfg.is_secret_host(&host) {
            reply(&mut client_sock, ingress, b"HTTP/1.1 403 Forbidden\r\n\r\n");
            eprintln!(
                "proxy: deny {}:{} (secret injection requires TLS)",
                host, port
            );
            shared.denied_detail(&host, port, "cleartext-injection", &req_str);
            shared.record(
                None,
                &host,
                port,
                "deny",
                Some("cleartext-injection"),
                0,
                0,
                started.elapsed().as_millis(),
                Some(method),
                None,
                None,
            );
            return;
        }
        let id = shared.open_event(&host, port);
        let mut client_stream = PrefixedStream::new(client_sock, req_buf[..n].to_vec());
        match inject::proxy_http1_with_injection(
            &mut client_stream,
            &mut remote_sock,
            &host,
            port,
            &shared,
        ) {
            Ok(outcome) => {
                let (mut up_bytes, mut down_bytes) = (outcome.up_bytes, outcome.down_bytes);
                if outcome.upgraded {
                    // `101 Switching Protocols`: everything past here is
                    // opaque (WebSocket frames, most commonly), so this
                    // connection finishes the way a CONNECT tunnel does —
                    // spliced byte-for-byte, not parsed.
                    let client_tcp = client_stream.into_inner();
                    match (client_tcp.try_clone(), remote_sock.try_clone()) {
                        (Ok(client_read), Ok(remote_write)) => {
                            let upstream_thread =
                                thread::spawn(move || pump(client_read, remote_write));
                            down_bytes += pump(remote_sock, client_tcp);
                            up_bytes += upstream_thread.join().unwrap_or(0);
                        }
                        _ => {
                            eprintln!(
                                "proxy: cannot duplicate sockets for upgraded {}:{}",
                                host, port
                            );
                        }
                    }
                }
                shared.record(
                    id.as_deref(),
                    &host,
                    port,
                    "allow",
                    None,
                    up_bytes,
                    down_bytes,
                    started.elapsed().as_millis(),
                    outcome.method.as_deref(),
                    outcome.path.as_deref(),
                    outcome.status,
                );
            }
            Err(inject::ProxyHttpError::L7Denied {
                method,
                path,
                reason,
            }) => {
                eprintln!("proxy: deny {}:{} ({})", host, port, reason);
                shared.denied_http_detail(
                    &host,
                    port,
                    &format!("L7 denied: {}", reason),
                    &method,
                    &path,
                );
                shared.record(
                    id.as_deref(),
                    &host,
                    port,
                    "deny",
                    Some(&format!("L7 denied: {}", reason)),
                    0,
                    0,
                    started.elapsed().as_millis(),
                    Some(&method),
                    Some(&path),
                    Some(403),
                );
            }
            Err(inject::ProxyHttpError::Io {
                method,
                path,
                status,
                secret_missing,
                error,
            }) => {
                eprintln!(
                    "proxy: injected HTTP proxying failed {}:{}: {}",
                    host, port, error
                );
                let mut detail = format!("inject-http: {}", short_err(&error));
                if secret_missing {
                    detail.push_str(" (secret missing: domain configured for secret injection in policy, but --secrets was not enabled)");
                }
                shared.record(
                    id.as_deref(),
                    &host,
                    port,
                    "error",
                    Some(&detail),
                    0,
                    0,
                    started.elapsed().as_millis(),
                    method.as_deref(),
                    path.as_deref(),
                    status,
                );
            }
        }
        return;
    } else if port == 443 {
        if !skip_l7 && shared.session_ca.is_some() {
            // A transparent client is already sending TLS; only a client that
            // asked for a tunnel is waiting to be told it has one.
            if ingress.speaks_http()
                && client_sock
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .is_err()
            {
                return;
            }
            let session_ca = shared.session_ca.as_ref().unwrap();

            let requested_host = normalize_host(&host).unwrap_or_else(|| host.clone());
            let leaf = match session_ca.issue_leaf(&requested_host) {
                Ok(leaf) => leaf,
                Err(e) => {
                    eprintln!("proxy: cannot issue leaf cert for {}:{}: {}", host, port, e);
                    shared.record(
                        None,
                        &host,
                        port,
                        "error",
                        Some("leaf-cert"),
                        0,
                        0,
                        started.elapsed().as_millis(),
                        None,
                        None,
                        None,
                    );
                    return;
                }
            };

            let mut client_tls =
                match tls::terminate(PrefixedStream::new(client_sock, prelude.clone()), &leaf) {
                    Ok(stream) => stream,
                    Err(e) => {
                        eprintln!(
                            "proxy: TLS acceptor setup failed for {}:{}: {}",
                            host, port, e
                        );
                        shared.record(
                            None,
                            &host,
                            port,
                            "error",
                            Some("mitm-accept"),
                            0,
                            0,
                            started.elapsed().as_millis(),
                            None,
                            None,
                            None,
                        );
                        return;
                    }
                };

            if let Err(e) = client_tls.conn.complete_io(&mut client_tls.sock) {
                eprintln!(
                    "proxy: TLS client handshake failed for {}:{}: {}",
                    host, port, e
                );
                shared.record(
                    None,
                    &host,
                    port,
                    "error",
                    Some("mitm-client-handshake"),
                    0,
                    0,
                    started.elapsed().as_millis(),
                    None,
                    None,
                    None,
                );
                return;
            }

            // After complete_io succeeds, check ALPN
            let negotiated_alpn = client_tls.conn.alpn_protocol();
            if let Some(proto) = negotiated_alpn {
                if proto != b"http/1.1" {
                    eprintln!(
                        "proxy: deny {}:{} (MITM requires HTTP/1.1 but client negotiated {:?})",
                        host,
                        port,
                        String::from_utf8_lossy(proto)
                    );
                    shared.denied_detail(&host, port, "alpn-unsupported", &req_str);
                    shared.record(
                        None,
                        &host,
                        port,
                        "deny",
                        Some("alpn-unsupported"),
                        0,
                        0,
                        started.elapsed().as_millis(),
                        None,
                        None,
                        None,
                    );
                    return;
                }
            }

            let sni = match client_tls.conn.server_name() {
                Some(name) => name.to_ascii_lowercase(),
                None => {
                    eprintln!("proxy: TLS client sent no SNI for {}:{}", host, port);
                    shared.denied_detail(&host, port, "sni-missing", &req_str);
                    shared.record(
                        None,
                        &host,
                        port,
                        "deny",
                        Some("sni-missing"),
                        0,
                        0,
                        started.elapsed().as_millis(),
                        None,
                        None,
                        None,
                    );
                    return;
                }
            };
            let normalized_sni = match normalize_host(&sni) {
                Some(name) => name,
                None => {
                    eprintln!("proxy: invalid SNI {:?} for {}:{}", sni, host, port);
                    shared.denied_detail(&host, port, "sni-invalid", &req_str);
                    shared.record(
                        None,
                        &host,
                        port,
                        "deny",
                        Some("sni-invalid"),
                        0,
                        0,
                        started.elapsed().as_millis(),
                        None,
                        None,
                        None,
                    );
                    return;
                }
            };
            if normalized_sni != requested_host {
                eprintln!(
                    "proxy: deny {}:{} (SNI {:?} does not match CONNECT authority {:?})",
                    host, port, normalized_sni, requested_host
                );
                shared.denied_detail(&host, port, "sni-mismatch", &req_str);
                shared.record(
                    None,
                    &host,
                    port,
                    "deny",
                    Some("sni-mismatch"),
                    0,
                    0,
                    started.elapsed().as_millis(),
                    None,
                    None,
                    None,
                );
                return;
            }

            let mut upstream_tls = match tls::originate(remote_sock, &requested_host) {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!(
                        "proxy: cannot initialize upstream TLS for {}:{}: {}",
                        host, port, e
                    );
                    shared.record(
                        None,
                        &host,
                        port,
                        "error",
                        Some("mitm-upstream"),
                        0,
                        0,
                        started.elapsed().as_millis(),
                        None,
                        None,
                        None,
                    );
                    return;
                }
            };

            let id = shared.open_event(&host, port);
            match inject::proxy_http1_with_injection(
                &mut client_tls,
                &mut upstream_tls,
                &requested_host,
                port,
                &shared,
            ) {
                Ok(outcome) => {
                    shared.record(
                        id.as_deref(),
                        &host,
                        port,
                        "allow",
                        None,
                        outcome.up_bytes,
                        outcome.down_bytes,
                        started.elapsed().as_millis(),
                        outcome.method.as_deref(),
                        outcome.path.as_deref(),
                        outcome.status,
                    );
                }
                Err(inject::ProxyHttpError::L7Denied {
                    method,
                    path,
                    reason,
                }) => {
                    eprintln!("proxy: deny {}:{} ({})", host, port, reason);
                    shared.denied_http_detail(
                        &host,
                        port,
                        &format!("L7 denied: {}", reason),
                        &method,
                        &path,
                    );
                    shared.record(
                        id.as_deref(),
                        &host,
                        port,
                        "deny",
                        Some(&format!("L7 denied: {}", reason)),
                        0,
                        0,
                        started.elapsed().as_millis(),
                        Some(&method),
                        Some(&path),
                        Some(403),
                    );
                }
                Err(inject::ProxyHttpError::Io {
                    method,
                    path,
                    status,
                    secret_missing,
                    error,
                }) => {
                    eprintln!(
                        "proxy: injected HTTPS proxying failed {}:{}: {}",
                        host, port, error
                    );
                    let mut detail = format!("inject-https: {}", short_err(&error));
                    if secret_missing {
                        detail.push_str(" (secret missing: domain configured for secret injection in policy, but --secrets was not enabled)");
                    }
                    shared.record(
                        id.as_deref(),
                        &host,
                        port,
                        "error",
                        Some(&detail),
                        0,
                        0,
                        started.elapsed().as_millis(),
                        method.as_deref(),
                        path.as_deref(),
                        status,
                    );
                }
            }
            return;
        }
    }

    // Non-CONNECT traffic always returned above; anything reaching here is a
    // CONNECT tunnel.
    if !skip_l7 {
        reply(&mut client_sock, ingress, b"HTTP/1.1 403 Forbidden\r\n\r\n");
        eprintln!(
            "proxy: deny CONNECT {}:{} (L7 rules require TLS interception on port 443)",
            host, port
        );
        shared.denied_detail(&host, port, "connect-l7-unintercepted", &req_str);
        shared.record(
            None,
            &host,
            port,
            "deny",
            Some("connect-l7-unintercepted"),
            0,
            0,
            started.elapsed().as_millis(),
            None,
            None,
            None,
        );
        return;
    }

    // Bytes forwarded before the pumps take over, so they still show up in the
    // metered "sent" total.
    let mut head_up: u64 = 0;

    // A transparent client never asked for a tunnel and has no HTTP parser
    // waiting for the answer; its ClientHello is already in `prelude`.
    if ingress.speaks_http()
        && client_sock
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
    {
        return;
    }
    // Forward any data that arrived alongside the CONNECT head.
    if !prelude.is_empty() {
        if remote_sock.write_all(&prelude).is_err() {
            return;
        }
        head_up += prelude.len() as u64;
    }

    let (client_read, remote_write) = match (client_sock.try_clone(), remote_sock.try_clone()) {
        (Ok(c), Ok(r)) => (c, r),
        _ => {
            eprintln!("proxy: cannot duplicate sockets for {}:{}", host, port);
            shared.record(
                None,
                &host,
                port,
                "error",
                Some("fd"),
                0,
                0,
                started.elapsed().as_millis(),
                None,
                None,
                None,
            );
            return;
        }
    };

    // Announced only once the connection can no longer fail synchronously, so
    // every open is followed by exactly one close.
    let id = shared.open_event(&host, port);

    // One direction inline: two threads per connection instead of three.
    let upstream = thread::spawn(move || pump(client_read, remote_write));
    let down = pump(remote_sock, client_sock);
    let up = head_up + upstream.join().unwrap_or(0);

    shared.record(
        id.as_deref(),
        &host,
        port,
        "allow",
        None,
        up,
        down,
        started.elapsed().as_millis(),
        None,
        None,
        None,
    );
}

/// Identity of a policy file, for change detection.
///
/// Size as well as mtime, because a filesystem with one-second timestamps plus a
/// same-second rewrite could otherwise go unnoticed; `None` for absent, so a file
/// appearing or disappearing counts as a change too.
fn policy_stamp(path: &str) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// Apply the policy file once.  Returns whether the running policy changed.
///
/// A rejected or vanished policy keeps the one already in force: the alternative
/// is falling back to a config nobody wrote, which is how an empty allow list --
/// meaning allow everything -- would sneak in.
fn reload_once(path: &str, shared: &Shared) -> bool {
    if policy_stamp(path).is_none() {
        eprintln!(
            "proxy: policy {} is gone; keeping the policy already in force",
            path
        );
        return false;
    }
    match load_policy(path) {
        Ok(config) => {
            shared.replace_config(config);
            true
        }
        Err(e) => {
            eprintln!("proxy: policy rejected, keeping the previous one: {}", e);
            false
        }
    }
}

/// Reload the policy whenever the file changes.
///
/// Polling rather than inotify or a signal: `forbid(unsafe_code)` rules out a
/// hand-rolled handler, `signal_hook` would be the crate's only dependency, and
/// one `stat` a second is free.  A second is also below the threshold where a
/// human running `proxy allow` and immediately retrying would notice.
fn watch_policy(path: String, shared: Arc<Shared>) {
    let mut current = policy_stamp(&path);
    loop {
        thread::sleep(POLICY_POLL);
        let stamp = policy_stamp(&path);
        if stamp == current {
            continue;
        }
        current = stamp;
        reload_once(&path, &shared);
    }
}

/// Block until the sidecar's network can actually resolve a name.
///
/// Binding a listener proves nothing about egress: podman is still wiring up
/// the bridge and internal networks when the proxy starts, and signalling
/// readiness at bind time let the launcher start the agent against a proxy that
/// could not yet reach anything — an instant 502 on the agent's first request.
///
/// Resolution only, never a connection: a DNS query goes to the configured
/// resolver and reaches no third-party host, so this stays policy-neutral under
/// `--proxy`, where dialling out would be egress the allow list never
/// authorised.
///
/// Never fatal.  If egress does not come up we start anyway and say so, because
/// a degraded launch beats a hung one.
///
/// "Say so" used to mean stderr only, which the launcher does not read: the
/// session looked healthy until the agent's first request came back 502.  The
/// reason is now also left in `EGRESS_DEGRADED` for the launcher to surface on
/// the terminal the person is actually looking at.
fn wait_for_egress(shared_dir: &str) {
    let started = Instant::now();
    let mut last_err = String::new();
    while started.elapsed() < READY_TIMEOUT {
        match READY_PROBE_HOST.to_socket_addrs() {
            Ok(mut addrs) => {
                if addrs.next().is_some() {
                    eprintln!("proxy: egress ready after {:?}", started.elapsed());
                    return;
                }
                last_err = "resolver returned no addresses".to_string();
            }
            Err(e) => last_err = short_err(&e),
        }
        thread::sleep(Duration::from_millis(100));
    }
    eprintln!(
        "proxy: WARNING egress not ready after {:?} ({}); starting anyway",
        started.elapsed(),
        last_err
    );
    if let Ok(mut f) = File::create(egress_degraded_path(shared_dir)) {
        let _ = writeln!(
            f,
            "{} did not resolve within {:?}: {}",
            READY_PROBE_HOST, READY_TIMEOUT, last_err
        );
    }
}

const USAGE: &str = "\
Usage: agent-sandbox-proxy [OPTIONS]

  --policy FILE          read the policy from FILE (see parse_policy)
  --check-policy FILE    validate FILE, print the rules it yields, exit
  --log FILE             append one JSON line per connection event
  --detail-log FILE      bounded sanitized denied-request details
  --listen ADDR          listen address (default 0.0.0.0:8888)
  --transparent          also listen on :80 and :443 of the --listen address,
                         taking the destination from the Host header or the
                         TLS SNI, for clients that ignore the proxy environment
  --shared-dir DIR       where proxy-ready, ca.pem and egress-degraded are
                         written (default /sidecar_shared)
  --no-egress-probe      start serving without waiting for egress to resolve
  --secret-fd FD         internal: read startup secret bindings from FD
  --allow-domains LIST   comma-separated; mutually exclusive with --policy
  --allow-ipss LIST
  --allow-portss LIST     ports and ranges, e.g. 443,8000-8100

Deny rules are built-in only: the launcher writes the baseline deny_ip into
the policy file and there is no flag, and no `ctl` command, that adds another.
";

/// Exit codes: 2 for anything wrong with the policy, so the sidecar and the
/// launcher can tell a bad policy from a failure to start.
fn fail(msg: &str) -> ! {
    eprintln!("proxy: {}", msg);
    std::process::exit(2);
}

struct Options {
    policy: String,
    log: String,
    detail_log: String,
    listen: String,
    transparent: bool,
    shared_dir: String,
    no_egress_probe: bool,
    secret_fd: Option<i32>,
    allow_domains: String,
    allow_ips: String,
    allow_ports: String,
}

fn parse_args(args: &[String]) -> (Options, Option<String>) {
    let mut o = Options {
        policy: String::new(),
        log: String::new(),
        detail_log: String::new(),
        listen: "0.0.0.0:8888".to_string(),
        transparent: false,
        shared_dir: DEFAULT_SHARED_DIR.to_string(),
        no_egress_probe: false,
        secret_fd: None,
        allow_domains: String::new(),
        allow_ips: String::new(),
        allow_ports: String::new(),
    };
    let mut check = None;
    let mut i = 1;
    while i < args.len() {
        let flag = args[i].as_str();
        let mut value = || {
            i += 1;
            match args.get(i) {
                Some(v) => v.clone(),
                None => fail(&format!("{} needs a value", flag)),
            }
        };
        match flag {
            "--policy" => o.policy = value(),
            "--check-policy" => check = Some(value()),
            "--log" => o.log = value(),
            "--detail-log" => o.detail_log = value(),
            "--listen" => o.listen = value(),
            "--transparent" => o.transparent = true,
            "--shared-dir" => o.shared_dir = value(),
            "--no-egress-probe" => o.no_egress_probe = true,
            "--secret-fd" => {
                let raw = value();
                let fd = raw
                    .parse::<i32>()
                    .ok()
                    .filter(|n| *n >= 0)
                    .unwrap_or_else(|| {
                        fail(&format!(
                            "--secret-fd: {:?} is not a non-negative integer",
                            raw
                        ))
                    });
                o.secret_fd = Some(fd);
            }
            "--allow-domains" => o.allow_domains = value(),
            "--allow-ips" => o.allow_ips = value(),
            "--allow-ports" => o.allow_ports = value(),
            "--deny-domains" | "--deny-ips" => {
                let _ = value();
                fail("deny rules are built-in only: the launcher writes the baseline deny_ip and nothing else may add one. Narrow an allow rule instead.");
            }
            "--proxy-train" => {
                let _ = value();
                fail("'--proxy-train' was removed. Run with a policy 'default deny' and watch denied requests via `agent-sandbox ctl tui`.");
            }
            "-h" | "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            other => fail(&format!("unknown option {:?}\n{}", other, USAGE)),
        }
        i += 1;
    }
    (o, check)
}

/// Build the initial policy.  `--policy` and the inline lists are mutually
/// exclusive rather than one falling back to the other: a fallback means a failed
/// load can quietly become an empty policy, which is allow-everything.
fn initial_config(o: &Options) -> ProxyConfig {
    let inline = [&o.allow_domains, &o.allow_ips, &o.allow_ports]
    .iter()
    .any(|s| !s.is_empty());

    if !o.policy.is_empty() {
        if inline {
            fail("--policy and --allow-domains/--allow-ips/--allow-ports are mutually exclusive");
        }
        match load_policy(&o.policy) {
            Ok(c) => c,
            Err(e) => fail(&e),
        }
    } else {
        let allow_ip = match parse_csv_ips(&o.allow_ips) {
            Ok(v) => v,
            Err(e) => fail(&format!("--allow-ips: {}", e)),
        };
        let allow_port = if o.allow_ports.is_empty() {
            None
        } else {
            match parse_csv_ports(&o.allow_ports) {
                Ok(v) => Some(v),
                Err(e) => fail(&format!("--allow-ports: {}", e)),
            }
        };
        let allow_host = match parse_csv_domains(&o.allow_domains) {
            Ok(v) => v,
            Err(e) => fail(&format!("--allow-domains: {}", e)),
        };
        ProxyConfig::new(
            allow_host,
            Vec::new(),
            Vec::new(),
            false,
            allow_ip,
            // Denies are built-in only; the inline lists are a dev path and
            // carry none.
            Vec::new(),
            allow_port,
            None,
            Vec::new(),
        )
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (opts, check) = parse_args(&args);

    // Validation mode: the host runs this to vet a policy before installing it,
    // so an invalid policy can never reach a running proxy.
    if let Some(path) = check {
        match load_policy(&path) {
            Ok(config) => {
                for line in config.describe() {
                    println!("{}", line);
                }
                std::process::exit(0);
            }
            Err(e) => fail(&e),
        }
    }

    // Before anything observable: a policy the operator got wrong must stop the
    // proxy here, not produce a weaker policy that looks like it started fine.
    let config = initial_config(&opts);
    eprintln!("proxy: policy");
    for line in config.describe() {
        eprintln!("proxy:   {}", line);
    }

    let metrics = if opts.log.is_empty() {
        None
    } else {
        MetricsLog::open(
            &opts.log,
            (!opts.detail_log.is_empty()).then_some(opts.detail_log.as_str()),
        )
    };

    let secrets = match SecretBindings::from_fd(opts.secret_fd) {
        Ok(bindings) => bindings,
        Err(e) => fail(&format!("--secret-fd: {}", e)),
    };
    if !secrets.is_empty() {
        eprintln!("proxy: loaded {} secret binding(s)", secrets.len());
    }
    let session_ca = SessionCa::generate().unwrap_or_else(|e| fail(&format!("session CA: {}", e)));
    let ca_pem = proxy_ca_pem_path(&opts.shared_dir);
    if let Err(e) = session_ca.write_public_cert_pem(&ca_pem) {
        fail(&format!("session CA: {}", e));
    }
    eprintln!("proxy: session CA generated at {}", ca_pem);
    let session_ca = Some(Arc::new(session_ca));

    // Bind before probing egress so a port clash fails immediately rather than
    // after the readiness wait.
    let listener = match TcpListener::bind(&opts.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("proxy: cannot bind {}: {}", opts.listen, e);
            std::process::exit(1);
        }
    };

    let mut transparent_listeners = Vec::new();
    if opts.transparent {
        // Same address as the proxy port: on the sidecar that is the address it
        // holds on the sandbox's --internal network, so these listeners are no
        // more reachable than the proxy itself.
        let ip = listen_ip(&opts.listen);
        for (port, ingress) in [
            (TRANSPARENT_HTTP_PORT, Ingress::TransparentHttp),
            (TRANSPARENT_HTTPS_PORT, Ingress::TransparentTls),
        ] {
            let addr = format!("{}:{}", ip, port);
            match TcpListener::bind(&addr) {
                Ok(l) => transparent_listeners.push((l, ingress)),
                Err(e) => {
                    eprintln!("proxy: cannot bind {}: {}", addr, e);
                    std::process::exit(1);
                }
            }
        }
        eprintln!("proxy: transparent listeners on {}:80 and {}:443", ip, ip);
    }

    // On the host -- `agent-sandbox browser` -- egress readiness is not in
    // question and the 30s ceiling would only be a stall on the way to a
    // browser window, so that caller passes --no-egress-probe.
    if !opts.no_egress_probe {
        wait_for_egress(&opts.shared_dir);
    }

    // Started after the egress probe so the grace covers the window right after
    // readiness, which is when the agent's first requests land.
    let shared = Arc::new(Shared {
        config: RwLock::new(Arc::new(config)),
        secrets: Arc::new(secrets),
        session_ca,
        resolver: Resolver::new(),
        metrics,
        startup_until: Instant::now() + STARTUP_GRACE,
    });

    // Only a file-backed policy can change under us; the inline lists are fixed
    // for the process's life.
    if !opts.policy.is_empty() {
        let path = opts.policy.clone();
        let watched = Arc::clone(&shared);
        if thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || watch_policy(path, watched))
            .is_err()
        {
            eprintln!("proxy: cannot spawn the policy watcher; policy changes will not apply");
        }
    }

    // The sidecar gates its own readiness on this, installs the blackhole routes
    // and only then tells the launcher the sandbox may start -- so the routes are
    // in place before any traffic can exist.
    if let Ok(mut f) = File::create(proxy_ready_path(&opts.shared_dir)) {
        let _ = f.write_all(b"ready\n");
    }

    for (l, ingress) in transparent_listeners {
        let shared = Arc::clone(&shared);
        if thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || accept_loop(l, shared, ingress))
            .is_err()
        {
            eprintln!("proxy: cannot spawn the {:?} accept loop", ingress);
        }
    }

    accept_loop(listener, shared, Ingress::Proxy);
}

fn accept_loop(listener: TcpListener, shared: Arc<Shared>, ingress: Ingress) {
    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                let shared = Arc::clone(&shared);
                // The pump buffers live on the heap, so these threads need very
                // little stack; the default 8 MiB reservation each adds up.
                let spawned = thread::Builder::new()
                    .stack_size(256 * 1024)
                    .spawn(move || serve(client, shared, ingress));
                if spawned.is_err() {
                    eprintln!("proxy: cannot spawn handler thread");
                }
            }
            Err(_) => {
                // Transient accept errors (fd pressure) must not busy-spin.
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn dummy_shared() -> Arc<Shared> {
    Arc::new(shared_with("allow_host example.com"))
}

#[cfg(test)]
pub(crate) fn shared_with(policy: &str) -> Shared {
    Shared {
        config: RwLock::new(Arc::new(parse_policy(policy).expect("initial policy"))),
        secrets: Arc::new(SecretBindings::default()),
        session_ca: None,
        resolver: Resolver::new(),
        metrics: None,
        startup_until: Instant::now(),
    }
}

#[cfg(test)]
pub(crate) fn shared_with_secrets(policy: &str, secrets: &str) -> Shared {
    Shared {
        config: RwLock::new(Arc::new(parse_policy(policy).expect("initial policy"))),
        secrets: Arc::new(SecretBindings::parse(secrets).expect("initial secrets")),
        session_ca: None,
        resolver: Resolver::new(),
        metrics: None,
        startup_until: Instant::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reload_once(path: &str, shared: &Shared) -> bool {
        super::reload_once(path, shared)
    }

    /// `deny_d` is gone: there is no domain deny list.  `deny_i` stands in for
    /// the launcher's built-in baseline, which is the only source of denies.
    fn cfg(allow_d: &str, deny_d: &str, allow_i: &str, deny_i: &str) -> ProxyConfig {
        assert!(deny_d.is_empty(), "domain denies no longer exist");
        ProxyConfig::new(
            parse_csv_domains(allow_d).expect("test allow_host"),
            Vec::new(),
            Vec::new(),
            false,
            parse_csv_ips(allow_i).expect("test allow_ip"),
            parse_csv_ips(deny_i).expect("test baseline deny_ip"),
            None,
            None,
            Vec::new(),
        )
    }

    fn args(extra: &[&str]) -> Options {
        let mut argv = vec!["agent-sandbox-proxy".to_string()];
        argv.extend(extra.iter().map(|s| s.to_string()));
        parse_args(&argv).0
    }

    /// A ClientHello carrying `sni`, built the way a client builds one, so the
    /// parser is exercised against the real field order rather than a fixture
    /// shaped to fit it.
    fn client_hello(sni: &str) -> Vec<u8> {
        let mut ext = vec![0x00, 0x00]; // extension_type: server_name
        let mut list = vec![0x00]; // name_type: host_name
        list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        list.extend_from_slice(sni.as_bytes());
        let mut body = (list.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&list);
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);

        let mut hs = vec![0x03, 0x03]; // legacy_version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0x20); // legacy_session_id length
        hs.extend_from_slice(&[0u8; 32]);
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        hs.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut msg = vec![0x01]; // client_hello
        let len = hs.len();
        msg.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        msg.extend_from_slice(&hs);
        msg
    }

    #[test]
    fn the_transparent_path_takes_its_destination_from_the_sni() {
        assert_eq!(
            parse_client_hello_sni(&client_hello("github.com")).as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn a_malformed_client_hello_yields_no_host_rather_than_a_panic() {
        // Every length in a hello is attacker-controlled, and this parser runs
        // on a thread holding a live client connection: a truncation must end
        // the connection, never the thread.
        let full = client_hello("github.com");
        for cut in 0..full.len() {
            assert_eq!(parse_client_hello_sni(&full[..cut]), None, "cut at {}", cut);
        }
        assert_eq!(parse_client_hello_sni(&[]), None);
        // A handshake that is not a ClientHello at all.
        let mut not_hello = full.clone();
        not_hello[0] = 0x02;
        assert_eq!(parse_client_hello_sni(&not_hello), None);
    }

    #[test]
    fn a_client_hello_without_sni_has_no_destination_to_offer() {
        // No SNI means nothing names the origin, so there is nothing to check
        // policy against -- the connection has to be dropped, not guessed at.
        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0x00);
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        hs.extend_from_slice(&[0x01, 0x00]);
        hs.extend_from_slice(&[0x00, 0x00]); // no extensions
        let mut msg = vec![0x01];
        let len = hs.len();
        msg.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        msg.extend_from_slice(&hs);
        assert_eq!(parse_client_hello_sni(&msg), None);
    }

    #[test]
    fn a_transparent_cleartext_request_is_addressed_by_its_host_header() {
        let head = "GET /repo/info/refs HTTP/1.1\r\nHost: github.com\r\nAccept: */*\r\n\r\n";
        assert_eq!(host_header(head), Some("github.com"));
        // Case-insensitive, per RFC 9110, and a port survives.
        assert_eq!(
            host_header("GET / HTTP/1.1\r\nhOsT:  example.com:8080  \r\n\r\n"),
            Some("example.com:8080")
        );
        // The request line is skipped, so a target containing "host:" cannot be
        // mistaken for the header.
        assert_eq!(host_header("GET /host:1 HTTP/1.1\r\n\r\n"), None);
        assert_eq!(host_header("GET / HTTP/1.1\r\nHost:\r\n\r\n"), None);
    }

    /// Drive a whole transparent TLS connection through `serve`, from
    /// ClientHello to origin and back.
    ///
    /// The origin and the transparent listener sit on the same port of two
    /// different loopback addresses, because `serve` takes the port it is
    /// policing from the socket the client dialled -- which on a real
    /// transparent listener is the origin's own port.
    /// Wrap a handshake message in the TLS record the wire actually carries.
    fn tls_record(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x16, 0x03, 0x01];
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_transparent_tls_connection_is_spliced_to_the_host_its_sni_names() {
        let origin = TcpListener::bind("127.0.0.1:0").expect("origin");
        let port = origin.local_addr().unwrap().port();
        let Ok(front) = TcpListener::bind(format!("127.0.0.2:{}", port)) else {
            // The same port on another loopback address was taken by something
            // else; nothing about the proxy is under test in that case.
            return;
        };

        let hello = tls_record(&client_hello("localhost"));
        let expected = hello.clone();
        let origin_thread = thread::spawn(move || {
            let (mut sock, _) = origin.accept().expect("origin accept");
            let mut got = vec![0u8; expected.len()];
            sock.read_exact(&mut got).expect("origin read");
            sock.write_all(b"pong").expect("origin write");
            got
        });

        let shared = Arc::new(shared_with(&format!("allow_host localhost:{}", port)));
        let proxy_thread = thread::spawn(move || {
            let (sock, _) = front.accept().expect("front accept");
            serve(sock, shared, Ingress::TransparentTls);
        });

        let mut client = TcpStream::connect(format!("127.0.0.2:{}", port)).expect("client connect");
        client.write_all(&hello).expect("client write");
        let mut back = Vec::new();
        client.read_to_end(&mut back).expect("client read");

        // The ClientHello reaches the origin byte for byte: the proxy consumed
        // it only to read the SNI, and replayed every byte it took.
        assert_eq!(origin_thread.join().unwrap(), hello);
        // And nothing was prepended on the way back.  A `200 Connection
        // Established` here is what a real TLS client would choke on, and is
        // exactly the bug this path has to avoid.
        assert_eq!(back, b"pong");
        // Let the client→origin pump see EOF so the handler can finish.
        drop(client);
        proxy_thread.join().unwrap();
    }

    #[test]
    fn a_transparent_connection_to_a_denied_host_is_dropped_not_answered() {
        let front = TcpListener::bind("127.0.0.1:0").expect("front");
        let port = front.local_addr().unwrap().port();

        let shared = Arc::new(shared_with("allow_host example.com"));
        let proxy_thread = thread::spawn(move || {
            let (sock, _) = front.accept().expect("front accept");
            serve(sock, shared, Ingress::TransparentTls);
        });

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect");
        client
            .write_all(&tls_record(&client_hello("evil.example.net")))
            .expect("write");
        let mut back = Vec::new();
        client.read_to_end(&mut back).expect("read");

        // A denied transparent client gets a closed socket, never an HTTP
        // status line: it is mid-handshake and would read one as a TLS record.
        assert!(back.is_empty(), "got {:?}", String::from_utf8_lossy(&back));
        proxy_thread.join().unwrap();
    }

    #[test]
    fn the_transparent_listeners_share_the_proxys_own_address() {
        // Never 0.0.0.0 by accident: the sidecar is dual-homed, and a listener
        // on all interfaces would be reachable from the default bridge.
        assert_eq!(listen_ip("10.89.0.2:8888"), "10.89.0.2");
        assert_eq!(listen_ip("[fd00::2]:8888"), "[fd00::2]");
        assert_eq!(listen_ip("0.0.0.0:8888"), "0.0.0.0");
    }

    #[test]
    fn transparent_is_off_unless_asked_for() {
        // `agent-sandbox browser` runs this binary on the host, where binding
        // 80 and 443 would be both privileged and wrong.
        assert!(!args(&[]).transparent);
        assert!(args(&["--transparent"]).transparent);
    }

    #[test]
    fn the_shared_dir_defaults_to_the_sidecar_volume() {
        let o = args(&[]);
        assert_eq!(o.shared_dir, DEFAULT_SHARED_DIR);
        assert_eq!(proxy_ready_path(&o.shared_dir), "/sidecar_shared/proxy-ready");
        assert_eq!(proxy_ca_pem_path(&o.shared_dir), "/sidecar_shared/ca.pem");
        assert_eq!(
            egress_degraded_path(&o.shared_dir),
            "/sidecar_shared/egress-degraded"
        );
        assert!(!o.no_egress_probe, "the sidecar still waits for egress");
    }

    #[test]
    fn a_host_run_relocates_all_three_state_files() {
        // `agent-sandbox browser` runs this binary outside the sidecar, where
        // /sidecar_shared does not exist and writing the CA there is fatal.
        let o = args(&["--shared-dir", "/run/user/1000/b", "--no-egress-probe"]);
        assert_eq!(proxy_ready_path(&o.shared_dir), "/run/user/1000/b/proxy-ready");
        assert_eq!(proxy_ca_pem_path(&o.shared_dir), "/run/user/1000/b/ca.pem");
        assert_eq!(
            egress_degraded_path(&o.shared_dir),
            "/run/user/1000/b/egress-degraded"
        );
        assert!(o.no_egress_probe);
    }

    #[test]
    fn exact_domain_does_not_match_subdomains() {
        assert!(domain_match("github.com", "github.com"));
        assert!(!domain_match("status.github.com", "github.com"));
    }

    #[test]
    fn wildcard_matches_base_and_subdomains() {
        assert!(domain_match("github.com", "*.github.com"));
        assert!(domain_match("api.github.com", "*.github.com"));
        assert!(!domain_match("notgithub.com", "*.github.com"));
    }

    #[test]
    fn allow_list_does_not_change_deny_by_default() {
        let c = cfg("github.com", "", "", "");
        assert!(c.is_allowed("github.com", 443));
        assert!(!c.is_allowed("example.com", 443));
    }

    #[test]
    fn a_baseline_only_policy_is_still_deny_by_default() {
        // The built-in deny_ip baseline is not an allow list: it narrows, it
        // never opens.
        let c = cfg("", "", "", "10.0.0.0/8");
        assert!(!c.is_allowed("github.com", 443));
        assert!(!c.is_allowed("example.com", 443));
    }

    #[test]
    fn more_specific_domain_wins() {
        // Longest pattern decides, so the exact host's port set beats the
        // wildcard's for that host and only for that host.
        let c = cfg("*.github.com:443 api.github.com:8443", "", "", "");
        assert!(c.is_allowed("api.github.com", 8443));
        assert!(!c.is_allowed("api.github.com", 443));
        assert!(c.is_allowed("gist.github.com", 443));
        assert!(!c.is_allowed("gist.github.com", 8443));
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        let c = cfg("api.github.com", "", "", "");
        assert!(c.is_allowed("API.GitHub.com".to_ascii_lowercase().as_str(), 443));
    }

    #[test]
    fn longer_cidr_prefix_wins() {
        let c = cfg("", "", "10.0.0.0/8", "10.1.0.0/24");
        assert!(c.is_allowed("10.2.0.1", 443));
        assert!(!c.is_allowed("10.1.0.5", 443));
    }

    #[test]
    fn bracketed_ipv6_literal_is_matched_as_an_address() {
        let c = cfg("", "", "", "::1/128");
        assert!(!c.is_allowed("[::1]", 443));
    }

    // ── host normalization (F3) ─────────────────────────────────────────────

    #[test]
    fn trailing_dot_is_stripped_before_matching() {
        let c = cfg("github.com", "", "", "");
        assert!(c.is_allowed("github.com.", 443));
        assert!(!c.is_allowed("evil.com.", 443));
    }

    #[test]
    fn leading_or_repeated_dot_is_rejected() {
        // An empty policy allows everything except a host that cannot mean
        // anything sane.
        let c = cfg("", "", "", "");
        assert!(!c.is_allowed(".github.com", 443));
        assert!(!c.is_allowed("github..com", 443));
    }

    #[test]
    fn ipv4_mapped_ipv6_literal_matches_v4_deny_range() {
        let c = cfg("", "", "", "10.0.0.0/8");
        assert!(!c.is_allowed("[::ffff:10.0.0.1]", 443));
        assert!(!c.is_allowed("::ffff:10.0.0.1", 443));
    }

    #[test]
    fn ipv4_compatible_ipv6_literal_matches_v4_deny_range() {
        let c = cfg("", "", "", "10.0.0.0/8");
        assert!(!c.is_allowed("[::10.0.0.1]", 443));
    }

    #[test]
    fn underscored_hostname_still_matches() {
        let c = cfg("internal_service.example.com", "", "", "");
        assert!(c.is_allowed("internal_service.example.com", 443));
    }

    #[test]
    fn resolved_address_check_ignores_the_deny_by_default_fallback() {
        // Even under deny-by-default, is_denied_address only checks explicit blocks
        let c = cfg("github.com", "", "", "");
        assert!(!c.is_denied_address("140.82.121.4".parse().unwrap()));
    }

    #[test]
    fn resolved_address_check_honours_explicit_deny_ip() {
        let c = cfg("internal.example.com", "", "", "169.254.0.0/16");
        assert!(c.is_denied_address("169.254.169.254".parse().unwrap()));
        assert!(!c.is_denied_address("140.82.121.4".parse().unwrap()));
    }

    #[test]
    fn more_specific_allow_ip_overrides_a_denied_range() {
        let c = cfg("", "", "10.1.0.0/24", "10.0.0.0/8");
        assert!(!c.is_denied_address("10.1.0.5".parse().unwrap()));
        assert!(c.is_denied_address("10.2.0.5".parse().unwrap()));
    }

    // ── baseline private/loopback deny (F2) ────────────────────────────────
    // These ranges are not compiled into the proxy -- the launcher writes them
    // into the policy file as ordinary deny_ip entries, so what actually needs
    // testing here is the *mechanism* the baseline depends on: that any
    // deny_ip range denies both a literal target and a resolved address, and
    // that an equally-specific allow_ip overrides it in both paths.

    #[test]
    fn each_baseline_range_is_denied() {
        let baseline = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,\
                         192.168.0.0/16,169.254.0.0/16,100.64.0.0/10,\
                         0.0.0.0/8,fc00::/7,fe80::/10";
        let c = cfg("", "", "", baseline);
        for addr in [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "172.16.0.5",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata endpoint
            "100.64.0.1",
            "0.0.0.5",
            "fc00::1",
            "fe80::1",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(
                !c.is_allowed_ip(ip),
                "{} should be denied as a literal target",
                addr
            );
            assert!(
                c.is_denied_address(ip),
                "{} should be denied as a resolved address",
                addr
            );
        }
    }

    #[test]
    fn equal_prefix_allow_ip_overrides_a_baseline_deny_for_literal_targets() {
        let c = cfg("", "", "10.0.0.0/8", "10.0.0.0/8");
        assert!(c.is_allowed_ip("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn equal_prefix_allow_ip_overrides_a_baseline_deny_for_resolved_addresses() {
        // Regression test for the is_denied_address tie-break fix: without it,
        // this is the one case where F2's own documented migration path (an
        // allow_ip override at the identical prefix) silently did not work.
        let c = cfg("", "", "10.0.0.0/8", "10.0.0.0/8");
        assert!(!c.is_denied_address("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn more_specific_allow_ip_still_overrides_a_baseline_deny() {
        let c = cfg("", "", "10.1.0.0/24", "10.0.0.0/8");
        assert!(c.is_allowed_ip("10.1.0.5".parse().unwrap()));
        assert!(!c.is_allowed_ip("10.2.0.5".parse().unwrap()));
    }

    #[test]
    fn resolve_failure_reports_the_underlying_error() {
        // A bare `dns` verdict is useless for diagnosis; the resolver's own
        // message has to survive.
        let r = Resolver::new();
        let err = r
            .resolve("no-such-host.invalid", 80, Instant::now())
            .unwrap_err();
        assert!(
            !err.to_string().is_empty(),
            "resolver error must carry a message"
        );
    }

    #[test]
    fn resolve_retries_for_at_least_the_retry_window() {
        // Regression: this used to be scoped to the startup grace, so in steady
        // state a failure got exactly one attempt and a blip became a 502.
        // `retry_until` in the past must not shorten the floor.
        let r = Resolver::new();
        let started = Instant::now();
        let _ = r.resolve(
            "no-such-host.invalid",
            80,
            Instant::now() - Duration::from_secs(60),
        );
        assert!(
            started.elapsed() >= RETRY_WINDOW,
            "expected retries for at least {:?}, gave up after {:?}",
            RETRY_WINDOW,
            started.elapsed()
        );
    }

    #[test]
    fn connect_failure_reports_the_underlying_error() {
        // Port 9 (discard) on a reserved-documentation address: nothing answers.
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let err = connect_any(&[addr], Instant::now()).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn connect_with_no_addresses_is_an_error_not_a_panic() {
        assert!(connect_any(&[], Instant::now()).is_err());
    }

    #[test]
    fn json_escaping_covers_quotes_and_controls() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("a\nb"), "a\\nb");
    }

    #[test]
    fn denied_details_redact_credentials() {
        let head = sanitize_request_head(
            "GET http://example.com/x HTTP/1.1\r\nAuthorization: Bearer secret\r\nX-Trace: ok",
        );
        assert!(head.contains("Authorization: <redacted>"));
        assert!(head.contains("X-Trace: ok"));
        assert!(!head.contains("Bearer secret"));
    }

    /// Write to a scratch log, return the lines it ended up with.
    fn metrics_lines(name: &str, f: impl FnOnce(&MetricsLog)) -> Vec<String> {
        let path = std::env::temp_dir().join(format!("agent-sandbox-metrics-{}.jsonl", name));
        let _ = std::fs::remove_file(&path);
        let log = MetricsLog::open(path.to_str().unwrap(), None).expect("open metrics log");
        f(&log);
        let body = std::fs::read_to_string(&path).expect("read metrics log");
        let _ = std::fs::remove_file(&path);
        body.lines().map(str::to_string).collect()
    }

    #[test]
    fn open_and_close_share_one_id() {
        let mut id = String::new();
        let lines = metrics_lines("open-close", |log| {
            id = log.next_id();
            log.open_event(&id, "example.com", 443);
            log.record(
                Some(&id),
                "example.com",
                443,
                "allow",
                None,
                10,
                20,
                5,
                None,
                None,
                None,
            );
        });
        assert_eq!(lines.len(), 2, "expected an open and a close: {:?}", lines);
        assert!(lines[0].contains("\"ev\":\"open\""), "{}", lines[0]);
        assert!(lines[1].contains("\"ev\":\"close\""), "{}", lines[1]);
        let needle = format!("\"id\":\"{}\"", id);
        assert!(lines[0].contains(&needle), "{}", lines[0]);
        assert!(lines[1].contains(&needle), "{}", lines[1]);
        // The close carries the accounting; the open cannot, since it has not
        // happened yet.
        assert!(lines[1].contains("\"up\":10"), "{}", lines[1]);
        assert!(!lines[0].contains("\"up\""), "{}", lines[0]);
    }

    /// The summary treats a row without `ev` as a completed connection, and the
    /// launcher greps these lines for a verdict, so an id-less record has to stay
    /// exactly what it always was.
    #[test]
    fn record_without_an_id_carries_no_event_fields() {
        let lines = metrics_lines("no-id", |log| {
            log.record(
                None,
                "example.com",
                443,
                "deny",
                None,
                0,
                0,
                1,
                None,
                None,
                None,
            );
        });
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("{\"ts\":"), "{}", lines[0]);
        assert!(!lines[0].contains("\"ev\""), "{}", lines[0]);
        assert!(!lines[0].contains("\"id\""), "{}", lines[0]);
        assert!(lines[0].contains("\"verdict\":\"deny\""), "{}", lines[0]);
    }

    /// A denied request's method, when known, is threaded through so a live
    /// TUI reading `connections.jsonl` can offer an L7-route rule directly.
    #[test]
    fn record_with_a_method_carries_it_through() {
        let lines = metrics_lines("with-method", |log| {
            log.record(
                None,
                "example.com",
                443,
                "deny",
                Some("domain"),
                0,
                0,
                1,
                Some("GET"),
                None,
                None,
            );
        });
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"method\":\"GET\""), "{}", lines[0]);
    }

    #[test]
    fn denied_http_detail_records_the_decrypted_request_line() {
        let path = std::env::temp_dir().join("agent-sandbox-detail-log.jsonl");
        let _ = std::fs::remove_file(&path);
        let log = MetricsLog::open(path.to_str().unwrap(), Some(path.to_str().unwrap())).unwrap();
        log.denied_http_detail("pypi.org", 443, "path denied", "GET", "/simple/");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("GET /simple/ HTTP/1.1"), "{}", body);
        let _ = std::fs::remove_file(path);
    }

    // ── policy parsing ──────────────────────────────────────────────────────
    // The launcher used to hand these lists over space-separated while this side
    // split on commas, so anything past the first entry was silently discarded --
    // and an emptied allow list means allow-everything.  These pin both halves.

    #[test]
    fn lists_split_on_commas_and_whitespace() {
        assert_eq!(parse_csv("a.example.com,b.example.com").len(), 2);
        assert_eq!(parse_csv("a.example.com b.example.com").len(), 2);
        assert_eq!(
            parse_csv_ips("10.0.0.0/8 192.168.1.0/24").expect("spaces"),
            parse_csv_ips("10.0.0.0/8,192.168.1.0/24").expect("commas")
        );
        assert_eq!(parse_csv_ips("10.0.0.0/8 192.168.1.0/24").unwrap().len(), 2);
    }

    #[test]
    fn an_unparseable_ip_is_an_error_not_an_empty_list() {
        assert!(parse_csv_ips("garbage").is_err());
        assert!(parse_csv_ips("10.0.0.0/8,garbage").is_err());
    }

    #[test]
    fn a_bare_address_is_a_host_route() {
        // The AGENTS.md parser accepts these (python ip_network calls it /32) and
        // IpNet on its own does not, so they used to be dropped in silence.
        let config = parse_policy("deny_ip 8.8.8.8\ndeny_ip 2001:db8::1\n").unwrap();
        assert_eq!(config.deny_ip.len(), 2);
        assert!(config.is_denied_address("8.8.8.8".parse().unwrap()));
        assert!(!config.is_denied_address("8.8.4.4".parse().unwrap()));
        assert!(config.is_denied_address("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn policy_file_carries_every_entry() {
        let config = parse_policy(
            "# comment\n\
             \n\
             allow_host github.com\n\
             allow_host *.githubusercontent.com\n\
             secret_route\tapi.github.com\tGET\t/user\n\
             allow_signing github.com\n\
             signing_enabled true\n\
             allow_ip 10.0.0.0/8\n\
             allow_ip 192.168.1.0/24\n\
             deny_ip 10.1.0.0/24\n",
        )
        .expect("policy");
        assert_eq!(config.allow_host.len(), 2);
        assert_eq!(config.secret_routes.len(), 1);
        assert_eq!(config.allow_signing.len(), 1);
        assert!(config.signing_enabled);
        assert_eq!(config.allow_ip.len(), 2);
        assert_eq!(config.deny_ip.len(), 1);
        assert!(!config.default_allow, "the policy is deny by default");
    }

    #[test]
    fn policy_rejects_the_old_space_separated_encoding() {
        // Exactly what the launcher used to pass as one argument.
        let err = parse_policy("allow_ip 10.0.0.0/8 192.168.1.0/24\n").unwrap_err();
        assert!(err.contains("whitespace"), "{}", err);
    }

    #[test]
    fn policy_rejects_unknown_keys_and_bad_values() {
        assert!(parse_policy("allow_domians github.com\n").is_err());
        assert!(parse_policy("allow_ip not-an-ip\n").is_err());
        assert!(parse_policy("default maybe\n").is_err());
        assert!(parse_policy("allow_host\n").is_err());
    }

    #[test]
    fn policy_errors_name_the_line() {
        let err = parse_policy("allow_host ok.example.com\nallow_ip nope\n").unwrap_err();
        assert!(err.starts_with("2:"), "{}", err);
    }

    #[test]
    fn explicit_default_overrides_the_derivation() {
        // Deny lists alone would normally leave the policy allow-by-default.
        let config = parse_policy("deny_ip 10.0.0.0/8\ndefault deny\n").unwrap();
        assert!(!config.default_allow);
        assert!(!config.is_allowed("anything.example.com", 443));

        // And the other direction: an allow list with an explicit allow default.
        let config = parse_policy("allow_host good.example.com\ndefault allow\n").unwrap();
        assert!(config.default_allow);
        assert!(config.is_allowed("anything.example.com", 443));
    }

    #[test]
    fn describe_round_trips_through_parse_policy() {
        // `proxy show` and the startup log render policy with describe(), and
        // the host writes policy files; the two formats must not diverge.
        let original = parse_policy(
            "allow_host github.com\n\
             secret_route\tapi.github.com\tGET\t/user\n\
             allow_signing github.com\n\
             signing_enabled true\n\
             allow_route\tapi.github.com\t*\t/**\n\
             allow_ip 10.0.0.0/8\ndeny_ip 10.1.0.0/24\nallow_port 8000-8100\n",
        )
        .unwrap();
        let reparsed = parse_policy(&original.describe().join("\n")).unwrap();
        assert_eq!(original.describe(), reparsed.describe());
    }

    #[test]
    fn an_empty_policy_denies_everything() {
        let config = parse_policy("# nothing here\n").unwrap();
        assert!(!config.default_allow);
    }

    // ── allow_port ─────────────────────────────────────────────────────────

    #[test]
    fn single_port_and_range_parse() {
        assert_eq!(
            parse_port_range("443").unwrap(),
            PortRange {
                start: 443,
                end: 443
            }
        );
        assert_eq!(
            parse_port_range("8000-8100").unwrap(),
            PortRange {
                start: 8000,
                end: 8100
            }
        );
        assert!(parse_port_range("0").is_err());
        assert!(parse_port_range("70000").is_err());
        assert!(parse_port_range("100-50").is_err());
        assert!(parse_port_range("abc").is_err());
    }

    #[test]
    fn allow_list_derives_the_default_allow_ports() {
        let config = parse_policy("allow_host github.com\n").unwrap();
        assert!(config.is_allowed("github.com", 443));
        assert!(config.is_allowed("github.com", 22));
        assert!(!config.is_allowed("github.com", 8443));
    }

    #[test]
    fn deny_only_policy_is_denied_by_default() {
        let config = parse_policy("deny_ip 10.0.0.0/8\n").unwrap();
        assert!(!config.is_allowed("github.com", 61234));
    }

    #[test]
    fn explicit_allow_ports_overrides_the_derived_default() {
        let config = parse_policy("allow_host github.com\nallow_port 8443\n").unwrap();
        assert!(!config.is_allowed("github.com", 443));
        assert!(config.is_allowed("github.com", 8443));
    }

    #[test]
    fn port_range_is_inclusive() {
        let config = parse_policy("allow_host github.com\nallow_port 8000-8100\n").unwrap();
        assert!(config.is_allowed("github.com", 8000));
        assert!(config.is_allowed("github.com", 8100));
        assert!(!config.is_allowed("github.com", 7999));
        assert!(!config.is_allowed("github.com", 8101));
    }

    #[test]
    fn port_deny_is_distinguishable_from_host_deny() {
        let config = parse_policy("allow_host github.com\nallow_port 443\n").unwrap();
        assert!(config.is_allowed_target("github.com"));
        assert!(!config.is_allowed_port(8443));
        assert!(!config.is_allowed("github.com", 8443));
    }

    #[test]
    fn domain_specific_port_isolation() {
        // A target-bound port rule must not leak to other targets: jyu.fi is
        // restricted to 443, github.com keeps the default ports (80, 443, 22).
        let config = parse_policy("allow_host jyu.fi:443\nallow_host github.com\n").unwrap();
        assert!(config.is_allowed("jyu.fi", 443));
        assert!(!config.is_allowed("jyu.fi", 22));
        assert!(config.is_allowed("github.com", 443));
    }

    fn policy_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("agent-sandbox-policy-{}", name))
    }

    #[test]
    fn shared_is_allowed_respects_per_target_ports() {
        // Regression test: `Shared::is_allowed` is the gate `serve` actually
        // calls per-connection, and it used to bypass `ProxyConfig::is_allowed`'s
        // per-target port matching by checking the host and the (global) port
        // independently — which let a domain allowed only on one port through on
        // any default port too.
        let shared = shared_with("allow_host github.com:22\n");
        assert!(shared.is_allowed("github.com", 22));
        assert!(!shared.is_allowed("github.com", 443));
    }

    #[test]
    fn a_reload_carries_the_explicit_default() {
        let shared = shared_with("default allow\n");
        assert!(shared.config().is_allowed("anything.example.com", 443));

        let path = policy_path("reload-default");
        std::fs::write(&path, "allow_ip 10.0.0.0/8\nallow_ip 192.168.1.0/24\n").unwrap();
        assert!(reload_once(path.to_str().unwrap(), &shared));
        let _ = std::fs::remove_file(&path);

        assert!(
            !shared.config().is_allowed("anything.example.com", 443),
            "missing default allow must make the reloaded policy deny-by-default"
        );
    }

    #[test]
    fn secret_injection_requires_both_policy_and_provider() {
        const POLICY: &str =
            "allow_host api.example.com\nsecret_route\tapi.example.com\tGET\t/user\n";
        const PROVIDER: &str = "api.example.com\tGET\t/user\tAuthorization\tBearer provider-token\n";

        let with_both = shared_with_secrets(POLICY, PROVIDER);
        let binding = with_both
            .secret_for_request("api.example.com", "GET", "/user")
            .expect("binding");
        assert_eq!(binding.header, "Authorization");
        assert_eq!(binding.value.as_str(), "Bearer provider-token");

        let policy_only = shared_with(POLICY);
        assert!(policy_only
            .secret_for_request("api.example.com", "GET", "/user")
            .is_none());

        let provider_only = shared_with_secrets("allow_host api.example.com\n", PROVIDER);
        assert!(provider_only
            .secret_for_request("api.example.com", "GET", "/user")
            .is_none());
    }

    #[test]
    fn secret_injection_is_scoped_to_the_authorized_route() {
        // The gate that closes the leak: the policy authorizes GET /user only,
        // so no other route on the same host resolves a binding -- however the
        // repo's AGENTS.md widened the L7 rules.
        let shared = shared_with_secrets(
            "allow_host api.example.com\n\
             secret_route\tapi.example.com\tGET\t/user\n",
            "api.example.com\tGET\t/user\tAuthorization\tBearer tok\n",
        );
        assert!(shared.secret_for_request("api.example.com", "GET", "/user").is_some());
        assert!(shared.secret_for_request("api.example.com", "GET", "/zen").is_none());
        assert!(shared.secret_for_request("api.example.com", "POST", "/user").is_none());
        assert!(shared.secret_for_request("other.example.com", "GET", "/user").is_none());
    }

    #[test]
    fn a_secret_host_is_recognised_whatever_the_route() {
        // The coarse predicate, which is what refuses cleartext to the host.
        let cfg = parse_policy("secret_route\tapi.example.com\tGET\t/user\n").expect("policy");
        assert!(cfg.is_secret_host("api.example.com"));
        assert!(!cfg.is_secret_host("other.example.com"));
        assert!(cfg.is_secret_route("api.example.com", "GET", "/user"));
        assert!(!cfg.is_secret_route("api.example.com", "GET", "/zen"));
    }

    #[test]
    fn backed_secret_routes_require_pattern_overlap() {
        let cfg = parse_policy("secret_route\tapi.example.com\tGET\t/user\n").expect("policy");
        let unrelated =
            SecretBindings::parse("other.example.com\tGET\t/user\tAuthorization\tone\n")
                .expect("secrets");
        assert!(!has_backed_secret_routes(&cfg, &unrelated));

        let wildcard =
            SecretBindings::parse("*.example.com\tGET\t/user\tAuthorization\ttwo\n")
                .expect("secrets");
        assert!(has_backed_secret_routes(&cfg, &wildcard));
    }

    #[test]
    fn a_rejected_reload_keeps_the_previous_policy() {
        let shared = shared_with("allow_host github.com\n");
        let path = policy_path("reload-rejected");

        std::fs::write(&path, "allow_ip 10.0.0.0/8 192.168.1.0/24\n").unwrap();
        assert!(!reload_once(path.to_str().unwrap(), &shared));
        let _ = std::fs::remove_file(&path);

        assert!(shared.config().is_allowed("github.com", 443));
        assert!(!shared.config().is_allowed("elsewhere.example.com", 443));
    }

    #[test]
    fn a_vanished_policy_keeps_the_previous_one() {
        // Deleting the file must not read as "no rules": that would be a silent
        // widening to allow-everything.
        let shared = shared_with("allow_host github.com\n");
        assert!(!reload_once(
            policy_path("definitely-absent").to_str().unwrap(),
            &shared
        ));
        assert!(!shared.config().is_allowed("elsewhere.example.com", 443));
    }

    #[test]
    fn a_reload_widens_and_narrows() {
        let shared = shared_with("allow_host github.com\n");
        let path = policy_path("reload-widen");

        std::fs::write(
            &path,
            "allow_host github.com\nallow_host api.openai.com\n",
        )
        .unwrap();
        assert!(reload_once(path.to_str().unwrap(), &shared));
        assert!(shared.config().is_allowed("api.openai.com", 443));

        std::fs::write(&path, "allow_host github.com\n").unwrap();
        assert!(reload_once(path.to_str().unwrap(), &shared));
        assert!(!shared.config().is_allowed("api.openai.com", 443));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ids_are_unique_and_carry_the_boot_stamp() {
        let lines = metrics_lines("unique-ids", |log| {
            let a = log.next_id();
            let b = log.next_id();
            assert_ne!(a, b);
            assert!(a.starts_with(&format!("{}-", log.boot)), "{}", a);
            log.open_event(&a, "a.example.com", 443);
            log.open_event(&b, "b.example.com", 443);
        });
        assert_eq!(lines.len(), 2);
    }
}
