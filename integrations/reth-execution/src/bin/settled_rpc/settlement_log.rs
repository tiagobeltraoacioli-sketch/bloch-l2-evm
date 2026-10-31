// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reader of the native follower's finalized settlements.
//!
//! Status schema v3 keeps `status.json` small: it carries the newest entries and the size and
//! digest of an append-only log with one compact JSON entry per finalized settlement. The RPC reads
//! only what it has not read yet, so the cost of one poll does not grow with the history. Schema v2
//! (the whole list inside the status file) is still accepted, so the RPC and the follower can be
//! upgraded in either order, and an RPC stopped by the old 16 MiB limit recovers by upgrading alone.
//!
//! Digest: `d0 = keccak256(LOG_DOMAIN)`, `d(n) = keccak256(d(n-1) || line n, newline included)`.
//! It detects a truncated, rewritten or foreign log; it is not a trust anchor. The log comes from
//! the same local follower as the status file, and every entry is still compared with the local
//! canonical chain by the caller.

use alloy_primitives::{keccak256, B256};
use serde_json::Value;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const STATUS_V2: &str = "bloch.l2.native-follower-status.v2";
pub const STATUS_V3: &str = "bloch.l2.native-follower-status.v3";
/// A v3 status holds a fixed number of entries; anything near this is not one.
pub const MAX_STATUS_V3_BYTES: u64 = 16 * 1_048_576;
/// A v2 status holds every settlement, about 475 bytes each: about 560,000 settlements.
pub const MAX_STATUS_V2_BYTES: u64 = 256 * 1_048_576;
/// Entries of a v2 status compared with the local chain at each poll.
const RECENT_V2: usize = 64;
pub const LOG_DOMAIN: &[u8] = b"BLOCH:L2:SETTLEMENT-LOG:1";

pub fn empty_digest() -> B256 {
    keccak256(LOG_DOMAIN)
}

pub fn next_digest(previous: B256, line: &[u8]) -> B256 {
    let mut data = Vec::with_capacity(32 + line.len());
    data.extend_from_slice(previous.as_slice());
    data.extend_from_slice(line);
    keccak256(&data)
}

/// How far the settlements have been read and matched against the local chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub count: u64,
    bytes: u64,
    /// `None` until a v3 log was read to this point; then the next v3 read starts from the beginning.
    digest: Option<B256>,
}

/// What one read adds. Nothing is committed until the caller adopts `cursor`.
#[derive(Debug)]
pub struct Delta {
    /// Entries above the old cursor, in order, contiguous.
    pub entries: Vec<Value>,
    /// The newest entries, compared with the local chain at every poll; the last one is the tip.
    pub recent: Vec<Value>,
    pub cursor: Cursor,
}

fn number_of(entry: &Value) -> Result<u64, String> {
    entry["l2_number"].as_u64().ok_or_else(|| "bad l2_number".to_string())
}

fn contiguous(entries: &[Value], first: u64) -> Result<(), String> {
    for (offset, entry) in entries.iter().enumerate() {
        if number_of(entry)? != first + offset as u64 {
            return Err("finalized settlements are not contiguous from block 1".into());
        }
    }
    Ok(())
}

/// Read what `status` adds to `cursor`. The list fields are moved out of `status`, which keeps only
/// the scalar facts. `status_path` locates the log, which lies beside the status file.
pub fn read_delta(status_path: &Path, status: &mut Value, cursor: &Cursor) -> Result<Delta, String> {
    let schema = status["schema"].as_str().unwrap_or_default().to_string();
    let object = status.as_object_mut().ok_or("status is not an object")?;
    if schema == STATUS_V2 {
        let list = match object.remove("finalized_settlements") {
            Some(Value::Array(list)) => list,
            _ => return Err("no settlement list".into()),
        };
        contiguous(&list, 1)?;
        let count = list.len() as u64;
        if count < cursor.count {
            return Err(format!("finalized settlements regressed from {} to {count}", cursor.count));
        }
        let recent = list[list.len().saturating_sub(RECENT_V2)..].to_vec();
        let entries = list.into_iter().skip(cursor.count as usize).collect();
        return Ok(Delta { entries, recent, cursor: Cursor { count, bytes: 0, digest: None } });
    }
    if schema != STATUS_V3 {
        return Err("unexpected status schema".into());
    }
    let log = object.remove("settlement_log").ok_or("no settlement log")?;
    let recent = match object.remove("finalized_settlements_recent") {
        Some(Value::Array(list)) => list,
        _ => return Err("no recent settlements".into()),
    };
    let name = log["file"].as_str().filter(|n| !n.is_empty() && !n.contains('/') && *n != "." && *n != "..");
    let name = name.ok_or("bad settlement log name")?;
    let total = log["entries"].as_u64().ok_or("bad settlement log entries")?;
    let size = log["bytes"].as_u64().ok_or("bad settlement log size")?;
    let digest: B256 = log["digest"].as_str().unwrap_or_default().parse().map_err(|_| "bad settlement log digest")?;
    if object.get("finalized_settlements_count").and_then(Value::as_u64) != Some(total) {
        return Err("settlement count differs from the log".into());
    }
    match recent.last() {
        None if total != 0 => return Err("a non-empty log needs recent settlements".into()),
        Some(last) if number_of(last)? != total => return Err("the newest recent settlement is not the log's last".into()),
        Some(_) if recent.len() as u64 > total => return Err("more recent settlements than the log holds".into()),
        Some(_) => contiguous(&recent, total + 1 - recent.len() as u64)?,
        None => {}
    }
    if total < cursor.count {
        return Err(format!("finalized settlements regressed from {} to {total}", cursor.count));
    }
    let (mut read, mut bytes, mut running) = match cursor.digest {
        Some(running) => (cursor.count, cursor.bytes, running),
        None => (0, 0, empty_digest()),
    };
    if size < bytes {
        return Err(format!("settlement log shrank from {bytes} to {size} bytes"));
    }
    let mut entries = Vec::new();
    if size > bytes {
        let path = status_path.parent().unwrap_or(Path::new(".")).join(name);
        let mut file = std::fs::File::open(&path).map_err(|e| format!("settlement log {}: {e}", path.display()))?;
        file.seek(SeekFrom::Start(bytes)).map_err(|e| format!("settlement log: {e}"))?;
        let mut data = Vec::new();
        file.take(size - bytes).read_to_end(&mut data).map_err(|e| format!("settlement log: {e}"))?;
        if data.len() as u64 != size - bytes {
            return Err("settlement log is shorter than the status says".into());
        }
        if data.last() != Some(&b'\n') {
            return Err("settlement log does not end on a whole entry".into());
        }
        for line in data.split_inclusive(|b| *b == b'\n') {
            running = next_digest(running, line);
            read += 1;
            let entry: Value = serde_json::from_slice(line).map_err(|e| format!("settlement log line {read}: {e}"))?;
            if number_of(&entry)? != read {
                return Err("finalized settlements are not contiguous from block 1".into());
            }
            if read > cursor.count {
                entries.push(entry);
            }
        }
        bytes = size;
    }
    if read != total || running != digest {
        return Err(format!(
            "settlement log differs from the status: {read} entries against {total}; restart this RPC only after checking the follower"
        ));
    }
    if let (Some(a), Some(b)) = (entries.last(), recent.last()) {
        if a["l2_hash"] != b["l2_hash"] {
            return Err("the log's last settlement differs from the status".into());
        }
    }
    Ok(Delta { entries, recent, cursor: Cursor { count: total, bytes, digest: Some(digest) } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(number: u64) -> Value {
        json!({"l2_number": number, "l2_hash": format!("{number:064x}"), "native_slot": number + 7})
    }

    /// Write a v3 status and log with `count` entries, as the follower does.
    fn write(dir: &Path, count: u64) -> Value {
        let mut digest = empty_digest();
        let mut text = String::new();
        for number in 1..=count {
            let line = format!("{}\n", entry(number));
            digest = next_digest(digest, line.as_bytes());
            text.push_str(&line);
        }
        std::fs::write(dir.join("status.settlements.jsonl"), &text).unwrap();
        let recent: Vec<Value> = (count.saturating_sub(63).max(1)..=count).map(entry).collect();
        json!({"schema": STATUS_V3, "finalized_settlements_count": count, "finalized_settlements_recent": recent,
               "settlement_log": {"file": "status.settlements.jsonl", "entries": count, "bytes": text.len(),
                                  "digest": alloy_primitives::hex::encode(digest)}})
    }

    #[test]
    fn digest_vector_shared_with_the_follower_and_python() {
        let digest = next_digest(next_digest(empty_digest(), b"{\"l2_number\":1}\n"), b"{\"l2_number\":2}\n");
        assert_eq!(alloy_primitives::hex::encode(digest), "e9e101a8fd7ec4784d28979c4a5472bdbcfe04ff5b9313928fd1f14a8d76b30c");
    }

    #[test]
    fn a_v3_log_is_read_once_and_then_only_what_was_added() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        let mut status = write(dir.path(), 100);
        let first = read_delta(&path, &mut status, &Cursor::default()).unwrap();
        assert_eq!(first.entries.len(), 100);
        assert_eq!(first.recent.len(), 64);
        assert_eq!(first.cursor.count, 100);
        // Same status again: no entries, and the log need not even be there.
        let mut same = write(dir.path(), 100);
        std::fs::remove_file(dir.path().join("status.settlements.jsonl")).unwrap();
        assert!(read_delta(&path, &mut same, &first.cursor).unwrap().entries.is_empty());
        let mut more = write(dir.path(), 103);
        let next = read_delta(&path, &mut more, &first.cursor).unwrap();
        assert_eq!(next.entries.iter().map(|e| number_of(e).unwrap()).collect::<Vec<_>>(), vec![101, 102, 103]);
        assert_eq!(next.cursor.count, 103);
    }

    #[test]
    fn an_empty_v3_log_is_valid_and_needs_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut status = write(dir.path(), 0);
        std::fs::remove_file(dir.path().join("status.settlements.jsonl")).unwrap();
        let delta = read_delta(&dir.path().join("status.json"), &mut status, &Cursor::default()).unwrap();
        assert!(delta.entries.is_empty() && delta.recent.is_empty());
    }

    #[test]
    fn a_damaged_or_regressed_log_is_refused_and_nothing_is_adopted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        let log = dir.path().join("status.settlements.jsonl");
        let read = |status: &mut Value, cursor: &Cursor| read_delta(&path, status, cursor);
        let mut good = write(dir.path(), 10);
        let base = read(&mut good, &Cursor::default()).unwrap().cursor;

        let mut grown = write(dir.path(), 12);
        let text = std::fs::read(&log).unwrap();
        // A flipped byte in a new line: the digest refuses it.
        let mut flipped = text.clone();
        let at = flipped.len() - 3;
        flipped[at] ^= 1;
        std::fs::write(&log, &flipped).unwrap();
        assert!(read(&mut grown.clone(), &base).is_err());
        // Truncated below what the status says.
        std::fs::write(&log, &text[..text.len() - 5]).unwrap();
        assert!(read(&mut grown.clone(), &base).unwrap_err().contains("shorter"));
        // Longer than the status says (a crash between the append and the status): only the prefix counts.
        let mut longer = text.clone();
        longer.extend_from_slice(b"{\"partial");
        std::fs::write(&log, &longer).unwrap();
        assert_eq!(read(&mut grown, &base).unwrap().cursor.count, 12);
        // Fewer entries than already adopted.
        let mut fewer = write(dir.path(), 9);
        assert!(read(&mut fewer, &base).unwrap_err().contains("regressed"));
        // Same count, another history.
        let mut other = write(dir.path(), 10);
        other["settlement_log"]["digest"] = json!(format!("{:064x}", 1));
        assert!(read(&mut other, &base).is_err());
        // A log name outside the status directory.
        let mut escape = write(dir.path(), 11);
        escape["settlement_log"]["file"] = json!("../x");
        assert!(read(&mut escape, &base).unwrap_err().contains("name"));
        // The status lies about the tip.
        let mut tip = write(dir.path(), 11);
        tip["finalized_settlements_recent"] = json!([entry(9)]);
        assert!(read(&mut tip, &base).is_err());
        let mut hash = write(dir.path(), 11);
        hash["finalized_settlements_recent"] = json!([{"l2_number": 11, "l2_hash": "00"}]);
        assert!(read(&mut hash, &base).unwrap_err().contains("differs"));
    }

    #[test]
    fn v2_gives_the_same_entries_and_a_v2_to_v3_upgrade_rereads_nothing_twice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        let mut v2 = json!({"schema": STATUS_V2, "finalized_settlements": (1..=100).map(entry).collect::<Vec<_>>()});
        let first = read_delta(&path, &mut v2, &Cursor::default()).unwrap();
        assert_eq!(first.entries.len(), 100);
        assert_eq!(first.recent.len(), RECENT_V2);
        assert!(v2.get("finalized_settlements").is_none());
        let mut v3 = write(dir.path(), 102);
        let next = read_delta(&path, &mut v3, &first.cursor).unwrap();
        assert_eq!(next.entries.iter().map(|e| number_of(e).unwrap()).collect::<Vec<_>>(), vec![101, 102]);
        let mut gap = json!({"schema": STATUS_V2, "finalized_settlements": [entry(2)]});
        assert!(read_delta(&path, &mut gap, &Cursor::default()).is_err());
        let mut fewer = json!({"schema": STATUS_V2, "finalized_settlements": [entry(1)]});
        assert!(read_delta(&path, &mut fewer, &first.cursor).unwrap_err().contains("regressed"));
        let mut unknown = json!({"schema": "x"});
        assert!(read_delta(&path, &mut unknown, &first.cursor).is_err());
    }
}
