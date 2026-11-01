// SPDX-License-Identifier: AGPL-3.0-or-later
//! Continuous native finality verifier for the L2 (devnet and mainnet).
//!
//! On start it re-verifies its locally retained history from the pinned genesis
//! with real signatures, Groth16 and FFG (no stored state is trusted). It then
//! follows a native node RPC (loopback `--rpc-port`, or a read-only remote
//! `--rpc-url`), fetching only new canonical envelopes up to the node-reported
//! finalized root. The source is untrusted for finality: a wrong or withheld
//! block halts or stalls the replay, it cannot forge a finalized level.
//!
//! Mainnet (`BPOSMAN1` Genesis-4 manifest + `--carryover`): the genesis has no
//! L2 registry; the native transition installs it at the epoch-5850 flag day and
//! the follower halts unless it installs exactly the pinned mainnet policy
//! (`bloch_settlement_recovery::mainnet`). Once that activation block is inside
//! the verified finalized prefix the status reports the L2 genesis as final
//! (`l2_genesis.finalized`), so the RPC publishes block 0 as `finalized`
//! before the first settlement. That root is a fetch hint: the finality the
//! status file reports is the one this process derived by replay. A block is
//! retained only after it verified. The status file and the settlement log beside
//! it list every L2 settlement inside the verified finalized prefix; they are
//! evidence for the L2 RPC finality publisher, not a consensus or production
//! finality claim.
//!
//! `--status-schema` chooses the file format, `v2` by default, so that replacing this binary changes
//! nothing for the readers of the status: a settled RPC of the closed v2.1 release, and any other
//! reader that knows only v2, closes or refuses on v3. Choose `v3` on a host once every reader of
//! that host's status reads it. Changing it needs only a restart, in either direction.
//!
//! Status schema v3: `status.json` stays small. It has the newest settlements and
//! the size and digest of `<status stem>.settlements.jsonl`, an append-only log with
//! one compact JSON entry per settlement, written and synced before the status names
//! it. The log is rewritten from the replay at each start, so a torn append cannot
//! survive a restart. `d0 = keccak256("BLOCH:L2:SETTLEMENT-LOG:1")`,
//! `d(n) = keccak256(d(n-1) || line n, newline included)`.
//!
//! Ethereum-rollup levels (status schema v2): `finalized` = settled in an L1
//! block this process verified as FFG-finalized; `safe` = the settlement the
//! operator's own L1 node reports as accepted at its canonical head
//! (`getl2settlement`), like an OP node reading its L1 client. No checkpoint
//! signature is involved: the only trust anchors are the pinned genesis and,
//! for `safe` alone, the local node. Settlement statements V2 and V3 decode.
#![cfg(unix)]

use alloy_primitives::{hex, B256};
use bloch_pos_committee::interfaces::{ProposalEnvelope, StateReader};
use bloch_pos_node::codec;
use bloch_settlement_recovery::{
    history::load_native_manifest,
    history::load_flag_day_manifest,
    mainnet,
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
usage: bloch-l2-native-follower --manifest PATH --network-pin HEX (--rpc-port N | --rpc-url http://HOST:PORT)
                                --state DIR --status FILE [--carryover TSV]
                                [--poll-seconds N] [--max-blocks N] [--max-fetch N]
                                [--status-schema v2|v3]
Re-verifies retained history from the pinned genesis on start, then follows finalized
native blocks from a native node RPC (read-only methods: getchaininfo, getblockraw,
getl2settlement) and writes verified finality status. A BPOSMAN3 manifest is a
development network with the L2 at genesis; the Genesis-4 mainnet manifest
(BPOSMAN1, --network-pin f47d3e49...1966) needs --carryover (the decompressed
carryover.tsv) and the L2 is checked at its epoch-5850 activation.
";

/// The file format of `--status`. See the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusSchema {
    /// The whole list in the file: a settled RPC of v2.1 stops at 16 MiB of it, about 30,190 settlements.
    V2,
    /// The newest entries in the file, and the rest in the settlement log.
    V3,
}

struct Options {
    manifest: PathBuf,
    carryover: Option<PathBuf>,
    pin: B256,
    rpc: (String, u16),
    state: PathBuf,
    status: PathBuf,
    poll: Duration,
    max_blocks: usize,
    max_fetch: usize,
    status_schema: StatusSchema,
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
        if ![
            "manifest", "carryover", "network-pin", "rpc-port", "rpc-url", "state", "status", "poll-seconds", "max-blocks",
            "max-fetch", "status-schema",
        ]
        .contains(&name)
        {
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
    let rpc = match (map.get("rpc-port"), map.get("rpc-url")) {
        (Some(port), None) => ("127.0.0.1".to_owned(), port.parse().map_err(|_| "bad --rpc-port")?),
        (None, Some(url)) => parse_rpc_url(url)?,
        _ => return Err("exactly one of --rpc-port and --rpc-url is required".into()),
    };
    Ok(Options {
        manifest: PathBuf::from(get("manifest")?),
        carryover: map.get("carryover").map(PathBuf::from),
        pin: pin_text.parse().map_err(|_| "bad --network-pin")?,
        rpc,
        state: PathBuf::from(get("state")?),
        status: PathBuf::from(get("status")?),
        poll: Duration::from_secs(num("poll-seconds", 10)?.clamp(1, 600)),
        max_blocks: num("max-blocks", 5_000_000)? as usize,
        max_fetch: num("max-fetch", 20_000)? as usize,
        status_schema: match map.get("status-schema").map(String::as_str) {
            None | Some("v2") => StatusSchema::V2,
            Some("v3") => StatusSchema::V3,
            Some(_) => return Err("--status-schema must be v2 or v3".into()),
        },
    })
}

/// `http://HOST:PORT` (optional trailing `/`; no path, query, user or TLS).
fn parse_rpc_url(url: &str) -> Result<(String, u16), String> {
    let rest = url.strip_prefix("http://").ok_or("--rpc-url must start with http://")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = rest.rsplit_once(':').ok_or("--rpc-url needs an explicit :PORT")?;
    if host.is_empty()
        || host.len() > 253
        || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err("--rpc-url host must be a hostname or IPv4 address".into());
    }
    Ok((host.to_owned(), port.parse().map_err(|_| "bad --rpc-url port")?))
}

/// Minimal JSON-RPC client (HTTP/1.0, connection closed per call). Only
/// read-only native methods are ever called.
fn rpc((host, port): &(String, u16), method: &str, params: Value) -> Result<Value, String> {
    use std::net::ToSocketAddrs;
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let address = (host.as_str(), *port)
        .to_socket_addrs()
        .map_err(|e| format!("rpc resolve: {e}"))?
        .next()
        .ok_or("rpc resolve: no address")?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10)).map_err(|e| format!("rpc connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
    write!(
        stream,
        "POST / HTTP/1.0\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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

/// Newest settlements repeated in the status file.
const RECENT_SETTLEMENTS: usize = 64;
const SETTLEMENT_LOG_DOMAIN: &[u8] = b"BLOCH:L2:SETTLEMENT-LOG:1";

/// The append-only log of finalized settlements (see the module documentation).
struct SettlementLog {
    path: PathBuf,
    /// `None` until the first sync of this process has rewritten the log.
    file: Option<File>,
    entries: u64,
    bytes: u64,
    digest: B256,
    recent: std::collections::VecDeque<Value>,
}

impl SettlementLog {
    fn beside(status: &Path) -> Self {
        let stem = status.file_stem().map_or("status".into(), |s| s.to_string_lossy().into_owned());
        Self {
            path: status.with_file_name(format!("{stem}.settlements.jsonl")),
            file: None,
            entries: 0,
            bytes: 0,
            digest: alloy_primitives::keccak256(SETTLEMENT_LOG_DOMAIN),
            recent: std::collections::VecDeque::new(),
        }
    }

    /// Serialize `new` (the entries above `self.entries`), and make them durable before the status
    /// names them. The first call of a process writes beside the log and renames, so a reader never
    /// sees the log shorter than the last status said.
    fn append(&mut self, new: Vec<Value>) -> Result<(), String> {
        let mut text = Vec::new();
        let mut digest = self.digest;
        for entry in &new {
            let line = serde_json::to_vec(entry).map_err(|e| e.to_string())?;
            let start = text.len();
            text.extend_from_slice(&line);
            text.push(b'\n');
            digest = alloy_primitives::keccak256([digest.as_slice(), &text[start..]].concat());
        }
        match &mut self.file {
            Some(file) => {
                if !text.is_empty() {
                    file.write_all(&text).and_then(|_| file.sync_data()).map_err(|e| format!("settlement log: {e}"))?;
                }
            }
            None => {
                write_atomic(&self.path, &text).map_err(|e| format!("settlement log: {e}"))?;
                self.file = Some(OpenOptions::new().append(true).open(&self.path).map_err(|e| format!("settlement log: {e}"))?);
            }
        }
        self.bytes += text.len() as u64;
        self.digest = digest;
        self.entries += new.len() as u64;
        self.recent.extend(new);
        while self.recent.len() > RECENT_SETTLEMENTS {
            self.recent.pop_front();
        }
        Ok(())
    }

    fn status_fields(&self) -> Value {
        json!({
            "file": self.path.file_name().map(|n| n.to_string_lossy().into_owned()),
            "entries": self.entries,
            "bytes": self.bytes,
            "digest": hex::encode(self.digest),
        })
    }
}

fn run(o: &Options) -> Result<(), String> {
    let magic = {
        let mut head = [0u8; 8];
        File::open(&o.manifest).and_then(|mut f| f.read_exact(&mut head)).map_err(|e| format!("manifest: {e}"))?;
        head
    };
    let (mut verifier, policy) = if &magic == b"BPOSMAN3" {
        if o.carryover.is_some() {
            return Err("--carryover applies only to a funded (BPOSMAN1/2) manifest".into());
        }
        let (_, genesis, policy) = load_native_manifest(&o.manifest, o.pin, 1_048_576).map_err(|e| e.to_string())?;
        let trust = NativeGenesisTrustV1 { state_root: genesis.state_root().into(), settlement_policy: policy };
        (IncrementalNativeVerifierV1::new(&genesis, trust, o.max_blocks).map_err(|e| e.to_string())?, policy)
    } else {
        // The mainnet flag day is pinned in this build; any other flag-day
        // network only in a qualification build of the native crates
        // (private mainnet-path rehearsal), see mainnet::flag_day_policy.
        let (policy, attestor_set) = mainnet::flag_day_policy(o.pin)
            .ok_or_else(|| format!("a funded manifest must be the Genesis-4 mainnet ({})", mainnet::MAINNET_NETWORK))?;
        let started = SystemTime::now();
        let (_, genesis) = load_flag_day_manifest(&o.manifest, o.carryover.as_deref(), o.pin, 1_048_576)
            .map_err(|e| e.to_string())?;
        let trust = NativeGenesisTrustV1 { state_root: genesis.state_root().into(), settlement_policy: policy };
        eprintln!(
            "native follower: flag-day genesis {} state root {} loaded in {:?}",
            hex::encode(genesis.head().as_bytes()),
            hex::encode(genesis.state_root()),
            started.elapsed().unwrap_or_default()
        );
        let verifier = IncrementalNativeVerifierV1::new_flag_day(&genesis, trust, attestor_set, o.max_blocks)
            .map_err(|e| e.to_string())?;
        (verifier, policy)
    };
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
    let mut walk = None;
    let mut log = SettlementLog::beside(&o.status);
    loop {
        match follow_once(o, &mut verifier, limits, &blocks_dir, &mut index, &mut walk) {
            Ok(added) => {
                let safe = match rpc(&o.rpc, "getl2settlement", json!([])) {
                    Ok(view) => safe_settlement(&view),
                    Err(e) => {
                        eprintln!("native follower: transient: {e}");
                        None
                    }
                };
                if let Some(status) = status(&verifier, &policy, safe, o.status_schema, &mut log)? {
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

/// A walk back from a finalized hint to the verified head that spans several
/// rounds (more than `--max-fetch` blocks). Fetched blocks wait on disk as
/// `<id>.pending` (unverified, never listed in the index); only their ids stay
/// in memory, newest first.
struct Walk {
    ids: Vec<B256>,
    cursor: B256,
}

fn follow_once(
    o: &Options,
    verifier: &mut IncrementalNativeVerifierV1,
    limits: NativeBlockLimitsV1,
    blocks_dir: &Path,
    index: &mut File,
    walk: &mut Option<Walk>,
) -> Result<usize, Follow> {
    let head = verifier.head();
    if walk.is_none() {
        let info = rpc(&o.rpc, "getchaininfo", json!([])).map_err(Follow::Transient)?;
        let hint: B256 = info["finalized"]["root"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Follow::Transient("getchaininfo has no finalized root".into()))?;
        if hint == head {
            return Ok(0);
        }
        *walk = Some(Walk { ids: Vec::new(), cursor: hint });
    }
    let state = walk.as_mut().expect("walk set above");
    // Walk back from the hint to our verified head; the finalized prefix cannot reorganize.
    let mut fetched = 0;
    while state.cursor != head {
        if fetched >= o.max_fetch {
            eprintln!("native follower: walking back to the verified head, {} blocks fetched so far", state.ids.len());
            return Ok(0);
        }
        let raw = rpc(&o.rpc, "getblockraw", json!([hex::encode(state.cursor)])).map_err(Follow::Transient)?;
        let bytes = hex::decode(raw.as_str().unwrap_or_default()).map_err(|_| Follow::Transient("bad raw hex".into()))?;
        if bytes.len() < 36 || bytes.len() > 4 * 1_048_576 {
            return Err(Follow::Halt("native block outside size bounds".into()));
        }
        let parent = B256::from_slice(&bytes[4..36]);
        let pending = blocks_dir.join(format!("{}.pending", hex::encode(state.cursor)));
        fs::write(&pending, &bytes).map_err(|e| Follow::Halt(e.to_string()))?;
        state.ids.push(state.cursor);
        fetched += 1;
        if parent.is_zero() || verifier.applied() + state.ids.len() > o.max_blocks {
            return Err(Follow::Halt("node's finalized chain does not descend from the verified head".into()));
        }
        state.cursor = parent;
    }
    let ids = std::mem::take(&mut state.ids);
    *walk = None;
    let count = ids.len();
    for id in ids.into_iter().rev() {
        let pending = blocks_dir.join(format!("{}.pending", hex::encode(id)));
        let bytes = fs::read(&pending).map_err(|e| Follow::Halt(e.to_string()))?;
        let block = decode_block(&bytes, &id).map_err(Follow::Halt)?;
        verifier.apply(&block, limits).map_err(|e| Follow::Halt(format!("native block {}: {e}", hex::encode(id))))?;
        let path = blocks_dir.join(format!("{}.bin", hex::encode(id)));
        File::open(&pending).and_then(|f| f.sync_all()).map_err(|e| Follow::Halt(e.to_string()))?;
        fs::rename(&pending, &path).map_err(|e| Follow::Halt(e.to_string()))?;
        writeln!(index, "{}", hex::encode(id)).and_then(|_| index.sync_data()).map_err(|e| Follow::Halt(e.to_string()))?;
    }
    Ok(count)
}

/// The L2 fields of a settlement statement, V2 or V3 (V3 adds the outbox).
fn statement_json(statement: &[u8]) -> Result<Value, String> {
    use bloch_l2_evm::proof_statement::{SettlementStatementV2, SettlementStatementV3, SETTLEMENT_STATEMENT_V3_TAG};
    let (base, withdrawals) = if statement.starts_with(SETTLEMENT_STATEMENT_V3_TAG) {
        let v3 = SettlementStatementV3::decode(statement).map_err(|_| "statement V3 decode")?;
        (v3.base, json!({"root": hex::encode(v3.withdrawal_root), "count": v3.withdrawal_count}))
    } else {
        (SettlementStatementV2::decode(statement).map_err(|_| "statement decode")?, Value::Null)
    };
    Ok(json!({
        "l2_number": base.l2_number, "l2_hash": hex::encode(base.l2_header_hash),
        "l2_state_root": hex::encode(base.l2_state_root), "withdrawals": withdrawals,
    }))
}

/// `safe`: the settlement the local node holds at its canonical head. Trusted
/// as the operator's own node is; never used for `finalized`.
fn safe_settlement(view: &Value) -> Option<Value> {
    let accepted = view.get("accepted")?;
    let statement = hex::decode(accepted.get("statement")?.as_str()?).ok()?;
    let mut entry = statement_json(&statement).ok()?;
    entry["commitment"] = accepted.get("commitment")?.clone();
    entry["source"] = json!("local-native-node-head");
    Some(entry)
}

fn status(
    verifier: &IncrementalNativeVerifierV1,
    policy: &bloch_l2_evm::native_settlement::SettlementPolicyV1,
    safe: Option<Value>,
    schema: StatusSchema,
    log: &mut SettlementLog,
) -> Result<Option<Value>, String> {
    let verified = match verifier.snapshot() {
        Ok(v) => v,
        Err(bloch_settlement_recovery::native::NativeFinalityErrorV1::NotFinalized) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let report = verified.report();
    let mut settlements = Vec::new();
    // v3 builds only what the log does not hold yet; v2 repeats the whole list in every file.
    let known = if schema == StatusSchema::V3 { log.entries as usize } else { 0 };
    for (slot, block, bytes) in verified.finalized_settlements().skip(known) {
        let tx = bloch_pos_committee::l2_settlement::Transaction::decode_async(bytes).ok_or("settlement decode")?;
        let mut entry = statement_json(&tx.statement)?;
        entry["native_slot"] = json!(slot);
        entry["native_block"] = json!(hex::encode(block));
        entry["commitment"] = json!(hex::encode(tx.commitment()));
        settlements.push(entry);
    }
    if schema == StatusSchema::V3 {
        log.append(settlements.clone())?;
    }
    // safe is never below finalized.
    let newest = if schema == StatusSchema::V3 { log.recent.back() } else { settlements.last() };
    let finalized_number = newest.and_then(|e| e["l2_number"].as_u64()).unwrap_or(0);
    let safe = safe.filter(|e| e["l2_number"].as_u64().is_some_and(|n| n >= finalized_number));
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut document = json!({
        "written_at_unix": now,
        "network": hex::encode(policy.network),
        "settlement_policy": hex::encode(report.settlement_policy),
        "verified_blocks": report.replayed_blocks,
        "verified_tip": hex::encode(report.replayed_tip),
        "verified_slot": report.replayed_slot,
        "native_finalized_block": hex::encode(report.finalized.block),
        "native_finalized_slot": report.finalized.slot,
        "native_finalized_epoch": report.finalized_epoch,
        "chain_id": policy.chain_id,
        // The L2 genesis is final once the native block that installed the
        // registry with it (`initial_l2_parent`) is inside the finalized prefix.
        "l2_genesis": verified.l2_activation().map(|(block, finalized)| json!({
            "hash": hex::encode(policy.initial_l2_parent_hash),
            "state_root": hex::encode(policy.initial_l2_state_root),
            "activation_block": hex::encode(block.block),
            "activation_slot": block.slot,
            "finalized": finalized,
        })),
        "safe_settlement": safe,
        "production_finality": false,
    });
    let fields = match schema {
        StatusSchema::V2 => json!({
            "schema": "bloch.l2.native-follower-status.v2",
            "finalized_settlements": settlements,
        }),
        StatusSchema::V3 => json!({
            "schema": "bloch.l2.native-follower-status.v3",
            "finalized_settlements_count": log.entries,
            "finalized_settlements_recent": log.recent,
            "settlement_log": log.status_fields(),
        }),
    };
    if let (Some(all), Value::Object(fields)) = (document.as_object_mut(), fields) {
        all.extend(fields);
    }
    Ok(Some(document))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(number: u64) -> Value {
        json!({"l2_number": number, "l2_hash": format!("{number:064x}")})
    }

    #[test]
    fn the_status_schema_defaults_to_v2_and_refuses_anything_else() {
        let args = |extra: &[&str]| -> Vec<String> {
            let pin = "ab".repeat(32);
            let mut all: Vec<String> = ["--manifest", "m", "--network-pin", &pin, "--rpc-port", "1", "--state", "d", "--status", "s"]
                .iter()
                .map(|a| a.to_string())
                .collect();
            all.extend(extra.iter().map(|a| a.to_string()));
            all
        };
        assert_eq!(parse(&args(&[])).map(|o| o.status_schema), Ok(StatusSchema::V2));
        assert_eq!(parse(&args(&["--status-schema", "v2"])).map(|o| o.status_schema), Ok(StatusSchema::V2));
        assert_eq!(parse(&args(&["--status-schema", "v3"])).map(|o| o.status_schema), Ok(StatusSchema::V3));
        assert!(parse(&args(&["--status-schema", "v4"])).is_err());
        assert!(parse(&args(&["--status-schema", ""])).is_err());
    }

    #[test]
    fn the_settlement_log_is_rewritten_at_start_then_appended_with_a_rolling_digest() {
        let dir = std::env::temp_dir().join(format!("settlement-log-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let status = dir.join("follower-status.json");
        let mut log = SettlementLog::beside(&status);
        assert_eq!(log.path, dir.join("follower-status.settlements.jsonl"));
        // Nothing yet: an empty log exists, with the domain digest.
        log.append(vec![]).unwrap();
        assert_eq!(fs::read(&log.path).unwrap(), b"");
        assert_eq!(log.status_fields()["entries"], 0);
        log.append(vec![json!({"l2_number": 1})]).unwrap();
        log.append(vec![]).unwrap();
        log.append(vec![json!({"l2_number": 2})]).unwrap();
        // The vector shared with the RPC and the Python readers.
        assert_eq!(log.status_fields()["digest"], "e9e101a8fd7ec4784d28979c4a5472bdbcfe04ff5b9313928fd1f14a8d76b30c");
        assert_eq!(log.status_fields()["bytes"], 32);
        assert_eq!(fs::read(&log.path).unwrap(), b"{\"l2_number\":1}\n{\"l2_number\":2}\n");

        // A restart with a torn append on disk rewrites the same bytes from the replay.
        OpenOptions::new().append(true).open(&log.path).unwrap().write_all(b"{\"torn").unwrap();
        let mut restarted = SettlementLog::beside(&status);
        restarted.append(vec![json!({"l2_number": 1}), json!({"l2_number": 2})]).unwrap();
        assert_eq!(restarted.status_fields(), log.status_fields());
        assert_eq!(fs::read(&restarted.path).unwrap(), b"{\"l2_number\":1}\n{\"l2_number\":2}\n");

        // Only the newest entries stay in the status.
        let mut long = SettlementLog::beside(&dir.join("long.json"));
        long.append((1..=200).map(entry).collect()).unwrap();
        assert_eq!(long.recent.len(), RECENT_SETTLEMENTS);
        assert_eq!(long.recent.front().unwrap()["l2_number"], 137);
        assert_eq!(long.recent.back().unwrap()["l2_number"], 200);
        fs::remove_dir_all(&dir).unwrap();
    }
}
