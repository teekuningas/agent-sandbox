#![forbid(unsafe_code)]

use anyhow::Result;
use chrono::{Local, TimeZone};
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, IsTerminal};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyRecord {
    pub id: Option<String>,
    pub ev: Option<String>,
    pub ts: f64,
    pub host: String,
    pub port: u16,
    pub up: Option<u64>,
    pub down: Option<u64>,
    pub ms: Option<f64>,
    pub verdict: Option<String>,
    pub err: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
}

fn format_human(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1048576 {
        let v = (bytes as f64 / 1024.0 * 10.0).round() / 10.0;
        format!("{} KiB", v)
    } else if bytes < 1073741824 {
        let v = (bytes as f64 / 1048576.0 * 10.0).round() / 10.0;
        format!("{} MiB", v)
    } else {
        let v = (bytes as f64 / 1073741824.0 * 10.0).round() / 10.0;
        format!("{} GiB", v)
    }
}

fn format_dur(secs: f64) -> String {
    if secs < 60.0 {
        format!("{}s", secs.floor() as u64)
    } else if secs < 3600.0 {
        format!(
            "{}m {}s",
            (secs / 60.0).floor() as u64,
            (secs % 60.0).floor() as u64
        )
    } else {
        format!(
            "{}h {}m",
            (secs / 3600.0).floor() as u64,
            ((secs % 3600.0) / 60.0).floor() as u64
        )
    }
}

fn format_ms(ms: f64) -> String {
    if ms < 1000.0 {
        format!("{}ms", ms)
    } else {
        format_dur((ms / 1000.0).floor())
    }
}

fn pad(s: &str, n: usize) -> String {
    let chars_count = s.chars().count();
    if chars_count < n {
        format!("{}{}", s, " ".repeat(n - chars_count))
    } else {
        s.to_string()
    }
}

fn lpad(s: &str, n: usize) -> String {
    let chars_count = s.chars().count();
    if chars_count < n {
        format!("{}{}", " ".repeat(n - chars_count), s)
    } else {
        s.to_string()
    }
}

fn clip(s: &str, n: usize) -> String {
    let chars_count = s.chars().count();
    if chars_count > n {
        let clipped: String = s.chars().take(n - 1).collect();
        format!("{}…", clipped)
    } else {
        s.to_string()
    }
}

/// Width of the volume bar column, in cells.
const BAR_WIDTH: usize = 12;

/// Terminal styling, resolved once per report.
///
/// Every accessor is a no-op when styling is off, so the piped report stays
/// byte-identical to the plain table documented in `docs/trust-model.md` -- the
/// same renderer feeds `agent-sandbox ctl net`, whose output people redirect.
#[derive(Clone, Copy)]
pub struct Style {
    on: bool,
}

impl Style {
    /// Styling only for an interactive stdout, and only when the environment
    /// has not asked for plain text.
    pub fn detect() -> Style {
        Style {
            on: std::io::stdout().is_terminal()
                && std::env::var_os("NO_COLOR").is_none()
                && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true),
        }
    }

    pub fn plain() -> Style {
        Style { on: false }
    }

    pub fn enabled(&self) -> bool {
        self.on
    }

    /// Wraps text that has *already* been padded.  `pad`/`lpad`/`clip` count
    /// chars, so styling anything on its way into them would widen the cell by
    /// the length of the escape sequence and skew every column after it.
    fn paint(&self, s: &str, code: &str) -> String {
        if self.on {
            format!("\x1b[{}m{}\x1b[0m", code, s)
        } else {
            s.to_string()
        }
    }

    fn bold(&self, s: &str) -> String {
        self.paint(s, "1")
    }
    pub fn dim(&self, s: &str) -> String {
        self.paint(s, "2")
    }
    fn red(&self, s: &str) -> String {
        self.paint(s, "31")
    }
    fn yellow(&self, s: &str) -> String {
        self.paint(s, "33")
    }

    /// Dims the unit of an already-padded byte count ("  265.2 KiB"), leaving
    /// the number bright.  Splitting after padding keeps the visible width.
    fn unit(&self, padded: &str) -> String {
        if !self.on {
            return padded.to_string();
        }
        match padded.rsplit_once(' ') {
            Some((head, unit)) if !unit.is_empty() => format!("{} {}", head, self.dim(unit)),
            _ => padded.to_string(),
        }
    }
}

/// A proportional bar for one host's share of the busiest host's traffic.
/// Anything that moved bytes gets at least one block, so a quiet host is still
/// distinguishable from one that transferred nothing.
fn bar(total: u64, max: u64, width: usize) -> String {
    if total == 0 || max == 0 || width == 0 {
        return String::new();
    }
    let blocks = ((width as f64) * (total as f64) / (max as f64)).round() as usize;
    "█".repeat(blocks.clamp(1, width))
}

/// Renders `display` as an OSC 8 terminal hyperlink to `absolute`, so a saved
/// log can be opened straight from the summary.  Terminals that do not support
/// OSC 8 ignore the sequence and show the text; with styling off the bare path
/// is returned, which is also what a pipe or a log file wants.
pub fn hyperlink(display: &str, absolute: &str, style: Style) -> String {
    if !style.enabled() {
        return display.to_string();
    }
    // Only the characters that would end the URL or the escape sequence need
    // encoding; a path is otherwise fine verbatim in a file: URL.
    let mut url = String::with_capacity(absolute.len());
    for c in absolute.chars() {
        match c {
            ' ' => url.push_str("%20"),
            '"' => url.push_str("%22"),
            '#' => url.push_str("%23"),
            '%' => url.push_str("%25"),
            '<' => url.push_str("%3C"),
            '>' => url.push_str("%3E"),
            c if (c as u32) < 0x20 => {}
            c => url.push(c),
        }
    }
    format!("\x1b]8;;file://{}\x1b\\{}\x1b]8;;\x1b\\", url, display)
}

/// Parses a proxy connection log (NDJSON) into records.
///
/// Unreadable and unparseable lines are skipped rather than fatal: the log is
/// read while the proxy may still be appending to it, and a torn final record
/// must not discard the entire report.
pub fn read_records<R: BufRead>(reader: R) -> Vec<ProxyRecord> {
    let mut records = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<ProxyRecord>(&line) {
            records.push(record);
        }
    }
    records
}

pub fn process_stream<R: BufRead>(reader: R) -> Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: ProxyRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let t = match Local.timestamp_opt(record.ts as i64, 0) {
            chrono::LocalResult::Single(dt) => dt.format("%H:%M:%S").to_string(),
            _ => "--:--:--".to_string(),
        };

        let ev = record.ev.as_deref().unwrap_or("close");
        let mut host_port = format!("{}:{}", record.host, record.port);
        if let Some(path) = &record.path {
            host_port.push_str(path);
        }

        if ev == "open" {
            println!("{}  open   {}", t, clip(&host_port, 40));
        } else {
            let verdict = record.verdict.as_deref().unwrap_or("?");

            let up_str = format_human(record.up.unwrap_or(0));
            let down_str = format_human(record.down.unwrap_or(0));
            let ms_str = format_ms(record.ms.unwrap_or(0.0));

            let mut info = Vec::new();
            if let Some(status) = record.status {
                info.push(format!("HTTP {}", status));
            }
            if let Some(err) = &record.err {
                info.push(err.clone());
            }

            let info_str = if info.is_empty() {
                "".to_string()
            } else {
                format!("  ({})", info.join(", "))
            };

            let out_str = format!(
                "{}  {} {}{}{}{}{}",
                t,
                pad(verdict, 6),
                pad(&clip(&host_port, 40), 40),
                lpad(&up_str, 11),
                lpad(&down_str, 11),
                lpad(&ms_str, 9),
                info_str
            );
            println!("{}", out_str);
        }
    }
    Ok(())
}

pub fn process_summary(records: Vec<ProxyRecord>) {
    for line in render_summary(records, Style::detect()) {
        println!("{}", line);
    }
}

/// The report as lines, so the layout can be asserted without capturing
/// stdout.  Tests pin `Style::plain()`; the plain rendering is the one
/// documented in `docs/trust-model.md`.
pub fn render_summary(records: Vec<ProxyRecord>, style: Style) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    if records.is_empty() {
        out.push(String::new());
        out.push(style.bold("=== Network Summary ==="));
        out.push("(no connections recorded)".to_string());
        return out;
    }

    let mut closed_ids = HashSet::new();
    for r in &records {
        let ev = r.ev.as_deref().unwrap_or("close");
        if ev == "close" {
            if let Some(id) = &r.id {
                closed_ids.insert(id.clone());
            }
        }
    }

    let all: Vec<&ProxyRecord> = records
        .iter()
        .filter(|r| r.ev.as_deref().unwrap_or("close") == "close")
        .collect();
    let live: Vec<&ProxyRecord> = records
        .iter()
        .filter(|r| {
            r.ev.as_deref().unwrap_or("close") == "open"
                && r.id.as_ref().map_or(false, |id| !closed_ids.contains(id))
        })
        .collect();

    let mut ok = Vec::new();
    let mut den = Vec::new();
    let mut fail = Vec::new();

    for r in &all {
        let verdict = r.verdict.as_deref().unwrap_or("?");
        if verdict == "allow" {
            ok.push(*r);
        } else if verdict == "deny" {
            den.push(*r);
        } else if verdict == "error" {
            fail.push(*r);
        }
    }

    let mut den_map: HashMap<String, usize> = HashMap::new();
    for r in &den {
        *den_map.entry(r.host.clone()).or_insert(0) += 1;
    }
    let mut den_list: Vec<(String, usize)> = den_map.into_iter().collect();
    den_list.sort_by(|a, b| b.1.cmp(&a.1));

    let mut fail_map: HashMap<(String, String), usize> = HashMap::new();
    for r in &fail {
        let err = r.err.clone().unwrap_or_else(|| "?".to_string());
        *fail_map.entry((r.host.clone(), err)).or_insert(0) += 1;
    }
    let mut fail_list: Vec<((String, String), usize)> = fail_map.into_iter().collect();
    fail_list.sort_by(|a, b| b.1.cmp(&a.1));

    struct HostStats {
        conns: usize,
        up: u64,
        down: u64,
    }
    let mut hosts_map: HashMap<String, HostStats> = HashMap::new();
    for r in &ok {
        let entry = hosts_map.entry(r.host.clone()).or_insert(HostStats {
            conns: 0,
            up: 0,
            down: 0,
        });
        entry.conns += 1;
        entry.up += r.up.unwrap_or(0);
        entry.down += r.down.unwrap_or(0);
    }
    let mut hosts_list: Vec<(String, HostStats)> = hosts_map.into_iter().collect();
    hosts_list.sort_by(|a, b| (b.1.up + b.1.down).cmp(&(a.1.up + a.1.down)));

    let shown = if hosts_list.len() > 15 {
        &hosts_list[0..15]
    } else {
        &hosts_list[..]
    };
    let rest = if hosts_list.len() > 15 {
        &hosts_list[15..]
    } else {
        &[]
    };

    let mut w0 = 20;
    for (h, _) in shown {
        w0 = w0.max(h.chars().count());
    }
    for (h, _) in &den_list {
        w0 = w0.max(h.chars().count());
    }
    for ((h, _), _) in &fail_list {
        w0 = w0.max(h.chars().count());
    }
    for r in &live {
        w0 = w0.max(format!("{}:{}", r.host, r.port).chars().count());
    }

    let w = if w0 > 40 { 40 } else { w0 };

    let mut min_ts = f64::MAX;
    let mut max_ts = f64::MIN;
    for r in &records {
        if r.ts < min_ts {
            min_ts = r.ts;
        }
        if r.ts > max_ts {
            max_ts = r.ts;
        }
    }
    let span = if max_ts >= min_ts {
        max_ts - min_ts
    } else {
        0.0
    };

    let tup: u64 = ok.iter().map(|r| r.up.unwrap_or(0)).sum();
    let tdown: u64 = ok.iter().map(|r| r.down.unwrap_or(0)).sum();

    out.push(String::new());

    let mut header = format!(
        "{}  {} · {} connection{}",
        style.bold("=== Network Summary ==="),
        format_dur(span),
        all.len(),
        if all.len() == 1 { "" } else { "s" }
    );
    if !ok.is_empty() {
        header.push_str(&format!(
            " · {} in / {} out",
            format_human(tdown),
            format_human(tup)
        ));
    }
    if !live.is_empty() {
        header.push_str(&format!(" · {} in flight", live.len()));
    }
    out.push(header);

    // Bars are scaled against the busiest host, which sorting has already put
    // first.  A session where nothing got through has no bar column, and the
    // rules below stay at their unbarred width.
    let max_total = shown.first().map(|(_, s)| s.up + s.down).unwrap_or(0);
    let bars = style.enabled() && max_total > 0;
    // Keeps every rule as wide as the table above it.
    let extra = if bars { 2 + BAR_WIDTH } else { 0 };

    if !shown.is_empty() {
        out.push(String::new());
        if style.enabled() {
            out.push(style.dim(&"─".repeat(2 + w + 7 + 11 + 11 + extra)));
        }
        out.push(style.bold(&format!(
            "  {}{}{}{}",
            pad("HOST", w),
            lpad("CONNS", 7),
            lpad("SENT", 11),
            lpad("RECV", 11)
        )));
        for (h, stats) in shown {
            let row = format!(
                "  {}{}{}{}",
                pad(&clip(h, w), w),
                lpad(&stats.conns.to_string(), 7),
                style.unit(&lpad(&format_human(stats.up), 11)),
                style.unit(&lpad(&format_human(stats.down), 11))
            );
            let b = if bars {
                bar(stats.up + stats.down, max_total, BAR_WIDTH)
            } else {
                String::new()
            };
            if b.is_empty() {
                out.push(row);
            } else {
                out.push(format!("{}  {}", row, style.dim(&b)));
            }
        }
        if !rest.is_empty() {
            let rest_conns: usize = rest.iter().map(|(_, s)| s.conns).sum();
            let rest_up: u64 = rest.iter().map(|(_, s)| s.up).sum();
            let rest_down: u64 = rest.iter().map(|(_, s)| s.down).sum();
            // No bar: the collapsed tail is an aggregate, not a host, and a
            // bar there would read as one host outweighing the ones above it.
            out.push(format!(
                "  {}{}{}{}",
                pad(&clip(&format!("… and {} more hosts", rest.len()), w), w),
                lpad(&rest_conns.to_string(), 7),
                style.unit(&lpad(&format_human(rest_up), 11)),
                style.unit(&lpad(&format_human(rest_down), 11))
            ));
        }
    }

    if !den_list.is_empty() {
        out.push(String::new());
        out.push(format!(
            "  {}",
            style.red(&format!("── denied {}", "─".repeat(w + 19 + extra)))
        ));
        for (h, conns) in &den_list {
            out.push(format!(
                "  {}{}",
                style.red(&pad(&clip(h, w), w)),
                lpad(&conns.to_string(), 7)
            ));
        }
    }

    if !fail_list.is_empty() {
        out.push(String::new());
        out.push(format!(
            "  {}",
            style.yellow(&format!("── failed {}", "─".repeat(w + 19 + extra)))
        ));
        for ((h, err), conns) in &fail_list {
            out.push(format!(
                "  {}{}  {}",
                style.yellow(&pad(&clip(h, w), w)),
                lpad(&conns.to_string(), 7),
                style.dim(&format!("({})", err))
            ));
        }
    }

    if !live.is_empty() {
        out.push(String::new());
        out.push(format!(
            "  {}",
            style.dim(&format!("── still open {}", "─".repeat(w + 15 + extra)))
        ));
        let mut sorted_live = live.clone();
        sorted_live.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap_or(Ordering::Equal));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        for r in sorted_live {
            let hp = format!("{}:{}", r.host, r.port);
            let dur_secs = (now.floor() - r.ts).max(0.0);
            out.push(format!(
                "  {}{}",
                pad(&clip(&hp, w), w),
                style.dim(&lpad(&format_dur(dur_secs), 9))
            ));
        }
    }

    if ok.is_empty() && !fail_list.is_empty() && live.is_empty() {
        out.push(String::new());
        out.push("  Nothing got through. The sidecar could not reach the network;".to_string());
        out.push("  see the proxy log:  podman logs <sidecar>".to_string());
    }

    out.push(String::new());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(line: &str) -> ProxyRecord {
        serde_json::from_str(line).expect("fixture parses")
    }

    /// The proxy appends while this is being read, so the last line can be
    /// half-written.  One torn record must not cost the whole report.
    #[test]
    fn read_records_skips_blank_and_torn_lines() {
        let log = concat!(
            r#"{"ev":"close","id":"1-1","ts":100.0,"host":"a.example","port":443,"up":10,"down":20,"ms":5.0,"verdict":"allow"}"#,
            "\n",
            "\n",
            r#"{"ev":"close","id":"1-2","ts":101.0,"host":"b.exam"#,
            "\n",
        );
        let records = read_records(log.as_bytes());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].host, "a.example");
    }

    #[test]
    fn bar_scales_against_the_busiest_host() {
        assert_eq!(bar(1000, 1000, BAR_WIDTH).chars().count(), BAR_WIDTH);
        assert_eq!(bar(500, 1000, BAR_WIDTH).chars().count(), BAR_WIDTH / 2);
        // Anything that moved bytes stays visible.
        assert_eq!(bar(1, 1_000_000, BAR_WIDTH).chars().count(), 1);
        assert_eq!(bar(0, 1000, BAR_WIDTH), "");
        assert_eq!(bar(10, 0, BAR_WIDTH), "");
    }

    /// Guards the escape-vs-padding trap: styling is applied to already-padded
    /// cells, so the visible layout must not move when it is switched on.
    #[test]
    fn styling_does_not_change_column_positions() {
        let records = vec![
            rec(
                r#"{"ev":"close","id":"1-1","ts":100.0,"host":"api.anthropic.com","port":443,"up":1024,"down":1048576,"ms":5.0,"verdict":"allow"}"#,
            ),
            rec(
                r#"{"ev":"close","id":"1-2","ts":110.0,"host":"telemetry.example.com","port":443,"up":0,"down":0,"ms":1.0,"verdict":"deny"}"#,
            ),
        ];

        let plain = render_summary(records.clone(), Style::plain());
        let styled = render_summary(records, Style { on: true });

        let strip = |s: &str| -> String {
            let mut out = String::new();
            let mut chars = s.chars();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    for c in chars.by_ref() {
                        if c == 'm' {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out
        };
        // Rules are excluded on both sides: they are sized to the table, which
        // the bar column widens on purpose.
        let is_rule = |s: &str| s.trim_start().starts_with('─');

        // The bar column is appended past the last data column, so trimming the
        // end of a styled row leaves the documented row.
        let styled_rows: Vec<String> = styled
            .iter()
            .map(|l| strip(l))
            .filter(|l| !is_rule(l))
            .map(|l| l.trim_end_matches(['█', ' ']).to_string())
            .collect();
        let plain_rows: Vec<String> = plain
            .iter()
            .filter(|l| !is_rule(l))
            .map(|l| l.trim_end().to_string())
            .collect();
        assert_eq!(plain_rows, styled_rows);
    }

    /// The layout `docs/trust-model.md` documents, which `ctl net > file` and
    /// anything parsing the report depend on.
    #[test]
    fn plain_render_matches_the_documented_table() {
        let records = vec![
            rec(
                r#"{"ev":"close","id":"1-1","ts":100.0,"host":"api.anthropic.com","port":443,"up":1024,"down":2048,"ms":5.0,"verdict":"allow"}"#,
            ),
            rec(
                r#"{"ev":"close","id":"1-2","ts":160.0,"host":"proxy.example.com","port":443,"up":0,"down":0,"ms":1.0,"verdict":"error","err":"dns"}"#,
            ),
        ];
        let out = render_summary(records, Style::plain());
        assert!(
            out.iter().all(|l| !l.contains('\x1b')),
            "no escapes when plain"
        );
        assert!(out.iter().all(|l| !l.contains('█')), "no bars when plain");
        assert_eq!(
            out[1],
            "=== Network Summary ===  1m 0s · 2 connections · 2 KiB in / 1 KiB out"
        );
        assert_eq!(
            out[3],
            "  HOST                  CONNS       SENT       RECV"
        );
        assert_eq!(
            out[4],
            "  api.anthropic.com         1      1 KiB      2 KiB"
        );
        assert!(out
            .iter()
            .any(|l| l == "  proxy.example.com         1  (dns)"));
    }

    #[test]
    fn hyperlink_is_a_bare_path_when_plain() {
        assert_eq!(
            hyperlink("log.jsonl", "/tmp/log.jsonl", Style::plain()),
            "log.jsonl"
        );
        let linked = hyperlink("log.jsonl", "/tmp/a b/log.jsonl", Style { on: true });
        assert!(linked.contains("file:///tmp/a%20b/log.jsonl"), "{}", linked);
        assert!(linked.contains("log.jsonl\x1b]8;;"), "{}", linked);
    }
}
