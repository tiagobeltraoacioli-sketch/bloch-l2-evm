// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local audit only: no signing, submission, networking or consensus activation.
#[cfg(unix)]
mod unix {
    use alloy_primitives::B256;
    use bloch_l2_evm::escrow::{Coin, Outpoint};
    use bloch_native_escrow_pq::{
        lock_store::{LockMark, LockStore, RecoveryLimits},
        PqEscrow,
    };
    use serde::Deserialize;
    use std::{
        fs::{self, File},
        io::{self, Read, Write},
        path::Path,
    };
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Allocation {
        outpoint: Outpoint,
        value: u64,
        owner: B256,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Baseline {
        version: u8,
        profile: String,
        network: B256,
        domain: B256,
        capacity: usize,
        expected_commitment: B256,
        #[serde(deserialize_with = "bloch_l2_evm::serde_bounded::vector::<_, _, 4096>")]
        allocations: Vec<Allocation>,
        #[serde(default)]
        recovery: Option<RecoveryConfig>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RecoveryConfig {
        max_batches: u64,
        max_bytes: u64,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Minimum {
        batches: u64,
        digest: B256,
    }
    fn read<T: serde::de::DeserializeOwned>(path: &Path, max: u64) -> Result<T, String> {
        let metadata = fs::symlink_metadata(path).map_err(|_| "input metadata unavailable")?;
        if !metadata.file_type().is_file() || metadata.len() > max {
            return Err("input type or size rejected".into());
        }
        let file = File::open(path).map_err(|_| "input unreadable")?;
        let mut bytes = Vec::new();
        file.take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "input read failed")?;
        if bytes.len() as u64 > max {
            return Err("input size rejected".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "input JSON rejected".into())
    }
    fn audit(args: &[std::ffi::OsString]) -> Result<serde_json::Value, String> {
        let range = if args.len() == 7 {
            if args[4] != "--proofs" {
                return Err("unknown option".into());
            }
            let parse = |arg: &std::ffi::OsString| -> Result<u64, String> {
                let text = arg.to_str().ok_or("invalid sequence")?;
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("sequence must be an unsigned decimal integer".into());
                }
                text.parse().map_err(|_| "sequence overflow".into())
            };
            let start = parse(&args[5])?;
            let end = parse(&args[6])?;
            if end < start || end - start > 4096 {
                return Err("proof range rejected".into());
            }
            Some(start..end)
        } else {
            None
        };
        let config: Baseline = read(Path::new(&args[1]), 1024 * 1024)?;
        let minimum: Minimum = read(Path::new(&args[3]), 4096)?;
        if config.version != 1
            || config.profile != "bloch-local-escrow-v1"
            || config.capacity == 0
            || config.capacity > 10_000
            || config.allocations.len() > 4096
        {
            return Err("baseline profile or limits rejected".into());
        }
        let baseline = PqEscrow::new(
            config.network,
            config.domain,
            config
                .allocations
                .into_iter()
                .map(|a| {
                    (
                        a.outpoint,
                        Coin {
                            value: a.value,
                            owner: a.owner,
                        },
                    )
                })
                .collect(),
            config.capacity,
        )
        .map_err(|_| "baseline allocation rejected")?;
        if baseline.commitment() != config.expected_commitment {
            return Err("baseline commitment mismatch".into());
        }
        let limits = config
            .recovery
            .as_ref()
            .map_or_else(RecoveryLimits::default, |r| RecoveryLimits {
                batches: r.max_batches,
                bytes: r.max_bytes,
            });
        let store = LockStore::open_with_limits(
            Path::new(&args[2]),
            baseline,
            LockMark {
                batches: minimum.batches,
                digest: minimum.digest,
            },
            limits,
        )
        .map_err(|e| format!("history recovery rejected: {e:?}"))?;
        let mark = store.mark().map_err(|_| "history unavailable")?;
        let escrow = store.escrow().map_err(|_| "state unavailable")?;
        if !escrow.conserved() {
            return Err("conservation check failed".into());
        }
        let inbox = escrow.inbox();
        let mut report = serde_json::json!({
            "version": 1, "profile": "bloch-local-escrow-v1",
            "network": config.network, "domain": config.domain,
            "baseline_commitment": config.expected_commitment,
            "mark": { "batches": mark.batches, "digest": mark.digest },
            "state_commitment": escrow.commitment(),
            "inbox": { "root": inbox.root(), "count": inbox.len() },
            "locked_sat": escrow.locked_sat().to_string(),
            "conserved": true,
            "native_finality_verified": false
        });
        if let Some(range) = range {
            let proofs = inbox
                .proofs(range.clone())
                .ok_or("proof range exceeds recovered inbox")?;
            report["proof_batch"] = serde_json::json!({
                "start": range.start, "end": range.end, "proofs": proofs
            });
        }
        Ok(report)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn config(count: usize) -> serde_json::Value {
            serde_json::json!({
                "version": 1, "profile": "bloch-local-escrow-v1",
                "network": B256::repeat_byte(1), "domain": B256::repeat_byte(2),
                "capacity": 10000, "expected_commitment": B256::repeat_byte(3),
                "allocations": (0..count).map(|i| serde_json::json!({
                    "outpoint": {"txid": B256::repeat_byte(4), "vout": i},
                    "value": 1, "owner": B256::repeat_byte(5)
                })).collect::<Vec<_>>()
            })
        }
        #[test]
        fn allocation_decode_accepts_exact_limit_and_rejects_excess_before_nested_content() {
            let mut value = config(4096);
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(bytes.len() <= 1024 * 1024);
            assert_eq!(
                serde_json::from_slice::<Baseline>(&bytes).unwrap().allocations.len(),
                4096
            );
            value["allocations"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"malformed": []}));
            let error = serde_json::from_slice::<Baseline>(&serde_json::to_vec(&value).unwrap())
                .err()
                .unwrap();
            assert!(error.to_string().contains("allocation limit"));
        }
        #[test]
        fn duplicate_baseline_coins_still_fail_after_bounded_decoding() {
            let mut value = config(1);
            let duplicate = value["allocations"][0].clone();
            value["allocations"].as_array_mut().unwrap().push(duplicate);
            let config: Baseline = serde_json::from_value(value).unwrap();
            assert!(PqEscrow::new(
                config.network,
                config.domain,
                config
                    .allocations
                    .into_iter()
                    .map(|a| (
                        a.outpoint,
                        Coin {
                            value: a.value,
                            owner: a.owner
                        }
                    ))
                    .collect(),
                config.capacity
            )
            .is_err());
        }
    }
    pub fn run() -> i32 {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() == 2 && args[1] == "--help" {
            return match writeln!(io::stdout().lock(), "Usage: bloch-escrow-audit BASELINE_JSON JOURNAL MINIMUM_JSON [--proofs START END]\nReplays local signed history. Proof range is [START, END). No native finality claim.") {
                Ok(()) => 0, Err(_) => 3,
            };
        }
        if args.len() != 4 && args.len() != 7 {
            eprintln!("Usage: bloch-escrow-audit BASELINE_JSON JOURNAL MINIMUM_JSON [--proofs START END]");
            return 1;
        }
        match audit(&args) {
            Ok(value) => {
                let mut out = io::stdout().lock();
                if serde_json::to_writer(&mut out, &value).is_err()
                    || out.write_all(b"\n").is_err()
                    || out.flush().is_err()
                {
                    3
                } else {
                    0
                }
            }
            Err(message) => {
                eprintln!("{message}");
                1
            }
        }
    }
}
fn main() {
    #[cfg(unix)]
    std::process::exit(unix::run());
    #[cfg(not(unix))]
    {
        eprintln!("bloch-escrow-audit requires Unix");
        std::process::exit(1);
    }
}
