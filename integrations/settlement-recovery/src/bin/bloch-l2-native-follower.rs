// SPDX-License-Identifier: AGPL-3.0-or-later
//! Continuous native finality verifier for the development network.
//!
//! On start it re-verifies its locally retained history from the pinned genesis
//! with real signatures, Groth16 and FFG (no stored state is trusted). It then
//! follows a loopback validator RPC, fetching only new canonical envelopes up to
//! the node-reported finalized root. That root is a fetch hint: the finality the
//! status file reports is the one this process derived by replay. A block is
//! retained only after it verified. The status file lists every L2 settlement
//! inside the verified finalized prefix; it is evidence for the L2 RPC finality
//! publisher, not a consensus or production finality claim.
#![cfg(unix)]

use alloy_primitives::{hex, B256};
use bloch_pos_committee::interfaces::{ProposalEnvelope, StateReader};
use bloch_pos_node::codec;
use bloch_settlement_recovery::{
    history::load_native_manifest,
    native::{IncrementalNativeVerifierV1, NativeBlockLimitsV1, NativeGenesisTrustV1, NativeReplayBlockV1},
};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const USAGE: &str = "\
usage: bloch-l2-native-follower --manifest PATH --network-pin HEX --rpc-port N --state DIR --status FILE
                                [--poll-seconds N] [--max-blocks N] [--max-fetch N]
Development only. Re-verifies retained history from genesis on start, then follows
finalized native blocks from a loopback RPC and writes verified finality status.
";

struct Options {
    manifest: PathBuf,
    pin: B256,
    rpc_port: u16,
    state: PathBuf,
    status: PathBuf,
    poll: Duration,
    max_blocks: usize,
    max_fetch: usize,
}

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--help" {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("bloch-l2-native-follower: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bloch-l2-native-follower: halted: {e}");
            ExitCode::from(3)
        }
    }
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() % 2 != 0 {
        return Err("options must be --name value pairs".into());
    }
    let mut map = std::collections::BTreeMap::new();
    for pair in args.chunks(2) {
        let name = pair[0].strip_prefix("--").ok_or("options must start with --")?;
        if !["manifest", "network-pin", "rpc-port", "state", "status", "poll-seconds", "max-blocks", "max-fetch"].contains(&name) {
            return Err(format!("unknown option --{name}"));
        }
        if map.insert(name.to_owned(), pair[1].clone()).is_some() {
            return Err(format!("--{name} repeated"));
        }
    }
    let get = |n: &str| map.get(n).cloned().ok_or(format!("missing --{n}"));
    let num = |n: &str, d: u64| -> Result<u64, String> {
        map.get(n).map_or(Ok(d), |v| v.parse().map_err(|_| format!("--{n} must be a number")))
    };
    let pin_text = get("network-pin")?;
    if pin_text.len() != 64 || !pin_text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("--network-pin must be 64 lowercase hex characters".into());
    }
    Ok(Options {
        manifest: PathBuf::from(get("manifest")?),
        pin: pin_text.parse().map_err(|_| "bad --network-pin")?,
        rpc_port: get("rpc-port")?.parse().map_err(|_| "bad --rpc-port")?,
        state: PathBuf::from(get("state")?),
        status: PathBuf::from(get("status")?),
        poll: Duration::from_secs(num("poll-seconds", 10)?.clamp(1, 600)),
        max_blocks: num("max-blocks", 5_000_000)? as usize,
        max_fetch: num("max-fetch", 20_000)? as usize,
    })
}

/// Minimal loopback JSON-RPC client (HTTP/1.0, connection closed per call).
fn rpc(port: u16, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("rpc connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    write!(
        stream,
        "POST / HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .map_err(|e| format!("rpc write: {e}"))?;
    let mut response = Vec::new();
    stream.take(8 * 1_048_576).read_to_end(&mut response).map_err(|e| format!("rpc read: {e}"))?;
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").ok_or("rpc: malformed HTTP response")?;
    let reply: Value = serde_json::from_slice(&response[split + 4..]).map_err(|e| format!("rpc json: {e}"))?;
    if let Some(error) = reply.get("error") {
        return Err(format!("rpc {method}: {error}"));
    }
    reply.get("result").cloned().ok_or_else(|| format!("rpc {method}: no result"))
}

fn decode_block(bytes: &[u8], expected_id: &B256) -> Result<NativeReplayBlockV1, String> {
    let envelope = codec::decode_envelope(bytes).map_err(|_| "native envelope does not decode")?;
    if codec::encode_envelope(&envelope) != bytes || B256::from(*envelope.block_id().as_bytes()) != *expected_id {
        return Err("native envelope is noncanonical or misidentified".into());
    }
    Ok(NativeReplayBlockV1 {
        envelope: ProposalEnvelope { header: envelope.header, proposer_sig: envelope.proposer_sig },
        attestations: envelope.body.attestations,
        transactions: envelope.body.transactions,
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp).map_err(|e| e.to_string())?;
    file.write_all(bytes).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    File::open(path.parent().unwrap_or(Path::new("/"))).and_then(|d| d.sync_all()).map_err(|e| e.to_string())
}

fn run(o: &Options) -> Result<(), String> {
    let (_, genesis, policy) = load_native_manifest(&o.manifest, o.pin, 1_048_576).map_err(|e| e.to_string())?;
    let trust = NativeGenesisTrustV1 { state_root: genesis.state_root().into(), settlement_policy: policy };
    let mut verifier = IncrementalNativeVerifierV1::new(&genesis, trust, o.max_blocks).map_err(|e| e.to_string())?;
    let limits = NativeBlockLimitsV1::default();
    let blocks_dir = o.state.join("blocks");
    fs::create_dir_all(&blocks_dir).map_err(|e| e.to_string())?;
    let index_path = o.state.join("index");

    // 1. Re-verify everything retained, from the pinned genesis.
    let started = SystemTime::now();
    if index_path.exists() {
        for line in BufReader::new(File::open(&index_path).map_err(|e| e.to_string())?).lines() {
            let id: B256 = line.map_err(|e| e.to_string())?.parse().map_err(|_| "corrupt index line")?;
            let bytes = fs::read(blocks_dir.join(format!("{}.bin", hex::encode(id)))).map_err(|e| e.to_string())?;
            verifier.apply(&decode_block(&bytes, &id)?, limits).map_err(|e| format!("retained history: {e}"))?;
        }
    }
    eprintln!(
        "native follower: re-verified {} retained blocks in {:?}",
        verifier.applied(),
        started.elapsed().unwrap_or_default()
    );
    let mut index = OpenOptions::new().create(true).append(true).open(&index_path).map_err(|e| e.to_string())?;

    // 2. Follow finalized native blocks.
    loop {
        match follow_once(o, &mut verifier, limits, &blocks_dir, &mut index) {
            Ok(added) => {
                if let Some(status) = status(&verifier, &policy)? {
                    write_atomic(&o.status, serde_json::to_string_pretty(&status).unwrap().as_bytes())?;
                }
                if added > 0 {
                    eprintln!("native follower: verified {added} new blocks, head {}", hex::encode(verifier.head()));
                }
            }
            Err(Follow::Transient(e)) => eprintln!("native follower: transient: {e}"),
            Err(Follow::Halt(e)) => return Err(e),
        }
        std::thread::sleep(o.poll);
    }
}

enum Follow {
    Transient(String),
    Halt(String),
}

fn follow_once(
    o: &Options,
    verifier: &mut IncrementalNativeVerifierV1,
    limits: NativeBlockLimitsV1,
    blocks_dir: &Path,
    index: &mut File,
) -> Result<usize, Follow> {
    let info = rpc(o.rpc_port, "getchaininfo", json!([])).map_err(Follow::Transient)?;
    let hint: B256 = info["finalized"]["root"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Follow::Transient("getchaininfo has no finalized root".into()))?;
    let head = verifier.head();
    if hint == head {
        return Ok(0);
    }
    // Walk back from the hint to our verified head; the finalized prefix cannot reorganize.
    let mut pending = Vec::new();
    let mut cursor = hint;
    while cursor != head {
        if pending.len() >= o.max_fetch {
            break; // too far behind: verify the oldest part first, the rest next round
        }
        let raw = rpc(o.rpc_port, "getblockraw", json!([hex::encode(cursor)])).map_err(Follow::Transient)?;
        let bytes = hex::decode(raw.as_str().unwrap_or_default()).map_err(|_| Follow::Transient("bad raw hex".into()))?;
        if bytes.len() < 36 || bytes.len() > 4 * 1_048_576 {
            return Err(Follow::Halt("native block outside size bounds".into()));
        }
        let parent = B256::from_slice(&bytes[4..36]);
        pending.push((cursor, bytes));
        if parent.is_zero() || pending.len() > verifier.applied() + o.max_fetch + 1 {
            return Err(Follow::Halt("node's finalized chain does not descend from the verified head".into()));
        }
        cursor = parent;
    }
    if cursor != head {
        // Partial walk: keep only the segment that reaches the verified head next time.
        return Err(Follow::Transient(format!("more than {} blocks behind; fetching in rounds", o.max_fetch)));
    }
    pending.reverse();
    let count = pending.len();
    for (id, bytes) in pending {
        let block = decode_block(&bytes, &id).map_err(Follow::Halt)?;
        verifier.apply(&block, limits).map_err(|e| Follow::Halt(format!("native block {}: {e}", hex::encode(id))))?;
        let path = blocks_dir.join(format!("{}.bin", hex::encode(id)));
        let mut file = File::create(&path).map_err(|e| Follow::Halt(e.to_string()))?;
        file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(|e| Follow::Halt(e.to_string()))?;
        writeln!(index, "{}", hex::encode(id)).and_then(|_| index.sync_data()).map_err(|e| Follow::Halt(e.to_string()))?;
    }
    Ok(count)
}

fn status(
    verifier: &IncrementalNativeVerifierV1,
    policy: &bloch_l2_evm::native_settlement::SettlementPolicyV1,
) -> Result<Option<Value>, String> {
    let verified = match verifier.snapshot() {
        Ok(v) => v,
        Err(bloch_settlement_recovery::native::NativeFinalityErrorV1::NotFinalized) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let report = verified.report();
    let mut settlements = Vec::new();
    for (slot, block, bytes) in verified.finalized_settlements() {
        let tx = bloch_pos_committee::l2_settlement::Transaction::decode_async(bytes).ok_or("settlement decode")?;
        let st = bloch_l2_evm::proof_statement::SettlementStatementV2::decode(&tx.statement).map_err(|_| "statement decode")?;
        settlements.push(json!({
            "native_slot": slot, "native_block": hex::encode(block), "commitment": hex::encode(tx.commitment()),
            "l2_number": st.l2_number, "l2_hash": hex::encode(st.l2_header_hash), "l2_state_root": hex::encode(st.l2_state_root),
        }));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    Ok(Some(json!({
        "schema": "bloch.l2.native-follower-status.v1",
        "written_at_unix": now,
        "network": hex::encode(policy.network),
        "settlement_policy": hex::encode(report.settlement_policy),
        "verified_blocks": report.replayed_blocks,
        "verified_tip": hex::encode(report.replayed_tip),
        "verified_slot": report.replayed_slot,
        "native_finalized_block": hex::encode(report.finalized.block),
        "native_finalized_slot": report.finalized.slot,
        "native_finalized_epoch": report.finalized_epoch,
        "finalized_settlements": settlements,
        "production_finality": false,
    })))
}
