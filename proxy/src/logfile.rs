//! Bounding for the append-only JSONL streams the sidecar writes.
//!
//! Shared rather than per-writer: `connections.jsonl`, `denied-requests.jsonl`
//! and `relay.jsonl` are all read the same way -- one JSON object per line, by
//! `ctl net`, `ctl relay`, the TUI and `agent-sandbox-network-summary` -- so
//! they all have to be trimmed the same way, at a line boundary.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

/// Bound the log by discarding its *oldest* records, keeping the newest half of
/// the budget so trimming is amortised instead of running on every later write.
///
/// Wiping the file instead would throw the whole session away at the moment it
/// got busy enough to be worth reading.  Every reader parses one JSON object
/// per line, so the retained tail is cut at a line boundary: a half record at
/// the top would be a parse error on the first line of every trimmed log.
///
/// Readers tail these files by byte offset, so they must also notice the file
/// getting shorter and start over; see the truncation checks in the TUI.
pub fn rotate_if_needed(file: &mut File, incoming: u64, max: u64) -> io::Result<()> {
    let len = file.metadata()?.len();
    if len.saturating_add(incoming) <= max {
        return Ok(());
    }

    let budget = max / 2;
    let keep = budget.saturating_sub(incoming.min(budget));
    let mut tail = Vec::new();
    if keep > 0 {
        file.seek(SeekFrom::Start(len.saturating_sub(keep)))?;
        file.read_to_end(&mut tail)?;
        match tail.iter().position(|b| *b == b'\n') {
            Some(idx) => {
                tail.drain(..=idx);
            }
            // Not one whole record in the retained window: keep nothing rather
            // than a fragment no reader can parse.
            None => tail.clear(),
        }
    }

    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&tail)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    #[test]
    fn bounded_log_drops_its_oldest_records_before_it_grows_past_limit() {
        let path = std::env::temp_dir().join("agent-sandbox-bounded-log.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .unwrap();
        for line in ["one\n", "two\n", "three\n", "four\n"] {
            file.write_all(line.as_bytes()).unwrap();
        }
        // 19 bytes on disk, a 4-byte write incoming, a 20-byte budget: the
        // newest records survive and the oldest go.
        rotate_if_needed(&mut file, 4, 20).unwrap();
        file.write_all(b"five").unwrap();
        drop(file);

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(!body.contains("one"), "oldest record kept: {body:?}");
        assert!(body.contains("four"), "newest record dropped: {body:?}");
        assert!(
            body.lines()
                .all(|l| ["two", "three", "four", "five"].contains(&l)),
            "a record was cut mid-line: {body:?}"
        );
        let _ = std::fs::remove_file(path);
    }

    /// The budget can be too small for even one whole record; a fragment at the
    /// top of the file would fail to parse for every reader.
    #[test]
    fn bounded_log_keeps_nothing_rather_than_half_a_record() {
        let path = std::env::temp_dir().join("agent-sandbox-bounded-log-tiny.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .unwrap();
        file.write_all(b"a very long single record\n").unwrap();
        rotate_if_needed(&mut file, 5, 8).unwrap();
        file.write_all(b"new!!").unwrap();
        drop(file);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new!!");
        let _ = std::fs::remove_file(path);
    }
}
