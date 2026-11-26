// SPDX-License-Identifier: AGPL-3.0-or-later
//! Continuous native finality verifier for the L2 (devnet and mainnet).
//!
//! On start it re-verifies its locally retained history from the pinned genesis
//! with real signatures, Groth16 and FFG (no stored state is trusted). It then
//! follows a native node RPC (loopback `--rpc-port`, or a read-only remote
//! `--rpc-url`), fetching only new canonical envelopes up to the node-reported
//! finalized root. The source is untrusted for finality: a wrong or withheld
//! block halts or stalls the replay, it cannot forge a finalized level. The
//! `safe` settlement is read only from a loopback node (`safe_source_trusted`).
//!
//! What the source says before anything is verified is its word, not a
//! verification result (audit AUDIT-L1L2-20261123, L2N-03). A reply that is
//! not a block, a block that is not the one asked for, or a chain of blocks
//! that cannot descend from the verified head (slots that do not decrease, a
//! slot at or below the head's, a slot ahead of the clock, more blocks than
//! `--max-blocks`) ends the walk for this round: its unverified files are
//! removed and the follower asks again. Only a block that fails the replay
//! itself is a halt (exit 3). Unverified blocks wait on disk as `.pending`
//! files; none is written when that would leave less than `--min-free-bytes`
//! free on the state filesystem, and all of them are removed at start.
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
                                [--min-free-bytes N] [--status-schema v2|v3]
Re-verifies retained history from the pinned genesis on start, then follows finalized
native blocks from a native node RPC (read-only methods: getchaininfo, getblockraw,
getl2settlement) and writes verified finality status. A BPOSMAN3 manifest is a
development network with the L2 at genesis; the Genesis-4 mainnet manifest
(BPOSMAN1, --network-pin f47d3e49...1966) needs --carryover (the decompressed
carryover.tsv) and the L2 is checked at its epoch-5850 activation.
--min-free-bytes (default 8589934592): fetched blocks wait unverified on disk; none is
written when that would leave less free space than this on the --state filesystem.
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
    /// Free space the unverified walk leaves on the state filesystem.
    min_free_bytes: u64,
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
            "max-fetch", "min-free-bytes", "status-schema",
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
        min_free_bytes: num("min-free-bytes", DEFAULT_MIN_FREE_BYTES)?,
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

/// Whether `host` names this machine (`localhost` or an IPv4 address in 127.0.0.0/8).
fn loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<std::net::Ipv4Addr>().is_ok_and(|address| address.is_loopback())
}

/// Whether the `safe` settlement may be read from the native RPC at `host`
/// (review L2-05). `safe` is the settlement the node holds at its head, read
/// without any proof: whoever controls that node, or an unauthenticated HTTP
/// path to it, could report a settlement at the sequencer's current head and
/// make the RPC publish `safe = latest` with nothing posted on L1. Only a
/// loopback node (the operator's own, or an SSH tunnel to it) is trusted for
/// it; from a remote URL `safe` is withheld and the RPC serves `finalized` as
/// `safe`. Finality never depends on the source: it is replayed and verified.
fn safe_source_trusted(host: &str) -> bool {
    loopback_host(host)
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
    let (mut verifier, policy, clock) = if &magic == b"BPOSMAN3" {
        if o.carryover.is_some() {
            return Err("--carryover applies only to a funded (BPOSMAN1/2) manifest".into());
        }
        let (manifest, genesis, policy) = load_native_manifest(&o.manifest, o.pin, 1_048_576).map_err(|e| e.to_string())?;
        let trust = NativeGenesisTrustV1 { state_root: genesis.state_root().into(), settlement_policy: policy };
        let clock = SlotClock { genesis_time_ms: manifest.genesis_time_ms, slot_ms: manifest.slot_ms };
        (IncrementalNativeVerifierV1::new(&genesis, trust, o.max_blocks).map_err(|e| e.to_string())?, policy, clock)
    } else {
        // The mainnet flag day is pinned in this build; any other flag-day
        // network only in a qualification build of the native crates
        // (private mainnet-path rehearsal), see mainnet::flag_day_policy.
        let (policy, attestor_set) = mainnet::flag_day_policy(o.pin)
            .ok_or_else(|| format!("a funded manifest must be the Genesis-4 mainnet ({})", mainnet::MAINNET_NETWORK))?;
        let started = SystemTime::now();
        let (manifest, genesis) = load_flag_day_manifest(&o.manifest, o.carryover.as_deref(), o.pin, 1_048_576)
            .map_err(|e| e.to_string())?;
        let clock = SlotClock { genesis_time_ms: manifest.genesis_time_ms, slot_ms: manifest.slot_ms };
        let trust = NativeGenesisTrustV1 { state_root: genesis.state_root().into(), settlement_policy: policy };
        eprintln!(
            "native follower: flag-day genesis {} state root {} loaded in {:?}",
            hex::encode(genesis.head().as_bytes()),
            hex::encode(genesis.state_root()),
            started.elapsed().unwrap_or_default()
        );
        let verifier = IncrementalNativeVerifierV1::new_flag_day(&genesis, trust, attestor_set, o.max_blocks)
            .map_err(|e| e.to_string())?;
        (verifier, policy, clock)
    };
    let limits = NativeBlockLimitsV1::default();
    let blocks_dir = o.state.join("blocks");
    fs::create_dir_all(&blocks_dir).map_err(|e| e.to_string())?;
    let index_path = o.state.join("index");
    // Unverified blocks of an earlier process are never trusted, or kept.
    let removed = remove_pending(&blocks_dir).map_err(|e| format!("blocks directory: {e}"))?;
    if removed > 0 {
        eprintln!("native follower: removed {removed} unverified .pending files of an earlier walk");
    }

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
    let safe_trusted = safe_source_trusted(&o.rpc.0);
    if !safe_trusted {
        eprintln!(
            "native follower: the native RPC {} is not loopback: no safe settlement is reported (safe = finalized); \
             run a local node or an SSH tunnel to it for safe",
            o.rpc.0
        );
    }
    loop {
        match follow_once(o, &mut verifier, limits, &blocks_dir, &mut index, &mut walk, &clock) {
            Ok(added) => {
                let safe = if !safe_trusted {
                    None
                } else {
                    match rpc(&o.rpc, "getl2settlement", json!([])) {
                        Ok(view) => safe_settlement(&view),
                        Err(e) => {
                            eprintln!("native follower: transient: {e}");
                            None
                        }
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
#[derive(Default)]
struct Walk {
    ids: Vec<B256>,
    cursor: B256,
    /// Slot of the last block fetched (the child of `cursor`).
    child_slot: Option<u64>,
}

/// Free space the walk leaves on the state filesystem unless `--min-free-bytes` says otherwise.
const DEFAULT_MIN_FREE_BYTES: u64 = 8 * 1_073_741_824;
/// Slots a hinted block may be ahead of this host's clock (32 minutes on mainnet).
const CLOCK_SLACK_SLOTS: u64 = 64;

/// Slot time of the followed network, from its pinned manifest.
struct SlotClock {
    genesis_time_ms: u64,
    slot_ms: u64,
}

impl SlotClock {
    /// The newest slot a block can honestly have now, with [`CLOCK_SLACK_SLOTS`].
    /// `None` when the clock cannot say (a zero slot time, a clock before genesis).
    fn newest_slot(&self, now_ms: u64) -> Option<u64> {
        let elapsed = now_ms.checked_sub(self.genesis_time_ms)?;
        Some((elapsed.checked_div(self.slot_ms)?).saturating_add(CLOCK_SLACK_SLOTS))
    }
}

/// What bounds one round of the walk. Nothing here comes from the source.
struct WalkBounds {
    head: B256,
    /// Slot of the verified head: every descendant has a greater slot.
    head_slot: u64,
    /// Blocks the verifier can still apply (`--max-blocks` minus applied).
    room: usize,
    max_fetch: usize,
    min_free_bytes: u64,
    /// Newest slot the first block of a walk may have.
    newest_slot: Option<u64>,
}

/// The source's reply to `getblockraw`, as bytes within the envelope bounds.
/// Every failure is the source's: the caller retries, it never halts.
fn raw_block(reply: &Value) -> Result<Vec<u8>, String> {
    let text = reply.as_str().ok_or("getblockraw reply is not a hex string")?;
    if text.len() > 2 * 4 * 1_048_576 {
        return Err("getblockraw reply is above the envelope bound".into());
    }
    let bytes = hex::decode(text).map_err(|_| "getblockraw reply is not hex")?;
    if bytes.len() < 36 {
        return Err("getblockraw reply is below the envelope bound".into());
    }
    Ok(bytes)
}

/// Slot and parent of a fetched envelope, after checking that it is canonical
/// and is the block that was asked for (its id is the hash of its bytes).
fn inspect_block(bytes: &[u8], id: &B256) -> Result<(u64, B256), String> {
    let block = decode_block(bytes, id)?;
    Ok((block.envelope.header.slot, B256::from(block.envelope.header.parent)))
}

/// Why block `slot` cannot be the next block of a walk towards a head at
/// `head_slot`: on one chain slots strictly increase from parent to child.
fn check_walk_slot(child_slot: Option<u64>, bounds: &WalkBounds, slot: u64) -> Result<(), String> {
    match child_slot {
        Some(child) if slot >= child => return Err(format!("slot {slot} is not below its child's slot {child}")),
        None if bounds.newest_slot.is_some_and(|newest| slot > newest) => {
            return Err(format!("slot {slot} is ahead of this host's clock"));
        }
        _ => {}
    }
    if slot <= bounds.head_slot {
        return Err(format!("slot {slot} is not above the verified head's slot {}: not a descendant", bounds.head_slot));
    }
    Ok(())
}

/// Free bytes on the filesystem of `dir` for this (unprivileged) process.
fn free_bytes(dir: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is a NUL-terminated string and `stat` is writable storage of the right type.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: statvfs returned 0, so it initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    Ok((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

/// Remove every `.pending` file of `blocks_dir`; returns how many.
fn remove_pending(blocks_dir: &Path) -> std::io::Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(blocks_dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "pending") {
            fs::remove_file(&path)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Drop a walk that will not be verified, with its unverified files.
fn abandon(blocks_dir: &Path, walk: &mut Option<Walk>) {
    for id in walk.take().into_iter().flat_map(|w| w.ids) {
        let _ = fs::remove_file(blocks_dir.join(format!("{}.pending", hex::encode(id))));
    }
}

/// One round of the walk from `walk.cursor` back to `bounds.head`: fetch,
/// check what can be checked without the verifier, store as `.pending`.
/// `Ok(true)`: the head was reached, `walk.ids` is the whole chain, newest
/// first. `Ok(false)`: `max_fetch` blocks fetched, continue next round.
/// `Err`: the source gave something that cannot be the chain above the head
/// (or the disk has no room); the caller abandons the walk and retries.
fn walk_back(
    fetch: &mut dyn FnMut(&B256) -> Result<Value, String>,
    inspect: &dyn Fn(&[u8], &B256) -> Result<(u64, B256), String>,
    free: &dyn Fn() -> std::io::Result<u64>,
    blocks_dir: &Path,
    walk: &mut Walk,
    bounds: &WalkBounds,
) -> Result<bool, String> {
    let mut fetched = 0;
    while walk.cursor != bounds.head {
        if fetched >= bounds.max_fetch {
            return Ok(false);
        }
        if walk.cursor.is_zero() || walk.ids.len() >= bounds.room {
            return Err("the source's finalized chain does not descend from the verified head".into());
        }
        let bytes = raw_block(&fetch(&walk.cursor)?)?;
        let (slot, parent) = inspect(&bytes, &walk.cursor)?;
        check_walk_slot(walk.child_slot, bounds, slot)?;
        let available = free().map_err(|e| format!("free space of the state directory: {e}"))?;
        if available.saturating_sub(bytes.len() as u64) < bounds.min_free_bytes {
            return Err(format!(
                "state filesystem has {available} bytes free, --min-free-bytes is {}: walk of {} unverified blocks dropped",
                bounds.min_free_bytes,
                walk.ids.len()
            ));
        }
        let pending = blocks_dir.join(format!("{}.pending", hex::encode(walk.cursor)));
        // Listed before it is written, so an abandoned walk removes a partial file too.
        walk.ids.push(walk.cursor);
        fs::write(&pending, &bytes).map_err(|e| format!("write {}: {e}", pending.display()))?;
        walk.child_slot = Some(slot);
        walk.cursor = parent;
        fetched += 1;
    }
    Ok(true)
}

fn follow_once(
    o: &Options,
    verifier: &mut IncrementalNativeVerifierV1,
    limits: NativeBlockLimitsV1,
    blocks_dir: &Path,
    index: &mut File,
    walk: &mut Option<Walk>,
    clock: &SlotClock,
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
        *walk = Some(Walk { cursor: hint, ..Walk::default() });
    }
    // Walk back from the hint to our verified head; the finalized prefix cannot reorganize.
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    let bounds = WalkBounds {
        head,
        head_slot: verifier.slot(),
        room: o.max_blocks.saturating_sub(verifier.applied()),
        max_fetch: o.max_fetch,
        min_free_bytes: o.min_free_bytes,
        newest_slot: clock.newest_slot(now_ms),
    };
    let state = walk.as_mut().expect("walk set above");
    let reached = walk_back(
        &mut |id| rpc(&o.rpc, "getblockraw", json!([hex::encode(id)])),
        &inspect_block,
        &|| free_bytes(blocks_dir),
        blocks_dir,
        state,
        &bounds,
    );
    match reached {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("native follower: walking back to the verified head, {} blocks fetched so far", state.ids.len());
            return Ok(0);
        }
        // The source's word, not a verification result: drop the walk and its files, ask again.
        Err(e) => {
            let dropped = state.ids.len();
            abandon(blocks_dir, walk);
            return Err(Follow::Transient(format!("{e} (walk of {dropped} unverified blocks dropped)")));
        }
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

    /// Audit AUDIT-L1L2-20261123 L2N-01. Behind the L1 settler gate a V3
    /// settlement carries an authorization trailer after the proof. The
    /// follower decodes a finalized settlement with the native release it
    /// links, so it follows that release: one that carries the gate reads a
    /// settlement with a trailer exactly like the unsigned one (same L2
    /// fields, same commitment, which does not cover the trailer); one that
    /// predates it does not decode the bytes, as no L1 node of that release
    /// does. The bytes are the vector shared with the native repository
    /// (real hybrid signatures; the native test verifies them).
    /// `BLOCH_NATIVE_HAS_SETTLER_GATE=1` requires the first case.
    #[test]
    fn a_settlement_with_a_settler_authorization_follows_the_linked_native_release() {
        use bloch_pos_committee::l2_settlement::Transaction;
        let vector: Value = serde_json::from_str(include_str!(
            "../../../../deployment/mainnet/testdata/settler-authorization-vector.json"
        ))
        .unwrap();
        let bytes = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
        let unsigned = Transaction::decode_async(&bytes("unsigned_tx")).expect("the form deployed today");
        assert_eq!(hex::encode(unsigned.commitment()), vector["commitment"].as_str().unwrap());
        let expected = statement_json(&unsigned.statement).unwrap();
        let mut decoded = 0;
        for case in ["plain_authorized_tx", "rotation_authorized_tx"] {
            if let Some(signed) = Transaction::decode_async(&bytes(case)) {
                decoded += 1;
                assert_eq!(statement_json(&signed.statement).unwrap(), expected);
                assert_eq!(signed.commitment(), unsigned.commitment());
            }
        }
        assert!(decoded == 0 || decoded == 2, "a release decodes every authorized settlement or none");
        if std::env::var_os("BLOCH_NATIVE_HAS_SETTLER_GATE").is_some() {
            assert_eq!(decoded, 2, "the linked native release does not decode a settler authorization");
        }
        eprintln!("settler authorization: the linked native release decodes the trailer: {}", decoded == 2);
    }

    /// Review L2-05: `safe` is read only from a loopback native RPC.
    #[test]
    fn safe_is_read_only_from_a_loopback_native_rpc() {
        for host in ["127.0.0.1", "127.8.9.10", "localhost", "LOCALHOST"] {
            assert!(safe_source_trusted(host), "{host}");
        }
        for host in ["10.0.0.5", "152.236.5.112", "node.example.org", "localhost.example.org", "128.0.0.1", "0.0.0.0"] {
            assert!(!safe_source_trusted(host), "{host}");
        }
        let pin = "ab".repeat(32);
        let base = ["--manifest", "m", "--network-pin", &pin, "--state", "d", "--status", "s"];
        let with = |extra: [&str; 2]| -> Vec<String> { base.iter().chain(extra.iter()).map(|a| a.to_string()).collect() };
        assert!(safe_source_trusted(&parse(&with(["--rpc-port", "8545"])).unwrap().rpc.0));
        assert!(!safe_source_trusted(&parse(&with(["--rpc-url", "http://10.1.2.3:8545"])).unwrap().rpc.0));
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

    // ---- audit AUDIT-L1L2-20261123, L2N-03: the walk and the source's word ----

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("follower-walk-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pending_files(dir: &Path) -> usize {
        fs::read_dir(dir).unwrap().filter(|e| e.as_ref().unwrap().path().extension().is_some_and(|x| x == "pending")).count()
    }

    /// A canonical native envelope with no signature, attestations or transactions.
    fn envelope(parent: B256, slot: u64) -> (B256, Vec<u8>) {
        use bloch_pos_committee::header::{BlockHeaderV4, VERSION_G4};
        let header = BlockHeaderV4 {
            version: VERSION_G4,
            parent: parent.0,
            state_root: [1; 32],
            body_root: [2; 32],
            slot,
            proposer_index: 0,
            randao_reveal: [3; 32],
            randao_mix: [4; 32],
            justified_root: [5; 32],
            finalized_root: [6; 32],
            attestation_root: [7; 32],
            coherence_root: [8; 32],
        };
        let mut bytes = header.canonical_serialize().to_vec();
        bytes.extend_from_slice(&[0u8; 12]); // empty signature, no attestations, no transactions
        let id = B256::from(*codec::decode_envelope(&bytes).unwrap().block_id().as_bytes());
        (id, bytes)
    }

    fn bounds(head: B256, head_slot: u64) -> WalkBounds {
        WalkBounds { head, head_slot, room: 1_000, max_fetch: 1_000, min_free_bytes: 0, newest_slot: Some(1_000) }
    }

    fn plenty() -> std::io::Result<u64> {
        Ok(u64::MAX)
    }

    /// A chain of `n` real envelopes above `head` at `head_slot`, keyed by id; returns the tip.
    fn chain(head: B256, head_slot: u64, n: u64) -> (B256, std::collections::BTreeMap<B256, Vec<u8>>) {
        let mut blocks = std::collections::BTreeMap::new();
        let mut parent = head;
        for i in 1..=n {
            let (id, bytes) = envelope(parent, head_slot + i);
            blocks.insert(id, bytes);
            parent = id;
        }
        (parent, blocks)
    }

    #[test]
    fn a_reply_that_is_not_a_block_is_the_sources_word_never_a_halt() {
        // The finding's first PoC: `getblockraw -> null` was `Halt("native block outside size bounds")`.
        for reply in [Value::Null, json!(7), json!(""), json!("zz"), json!("00"), json!({"raw": "00"}), json!(["00"])] {
            assert!(raw_block(&reply).is_err(), "{reply}");
        }
        assert!(raw_block(&json!("00".repeat(4 * 1_048_576 + 1))).is_err(), "above the envelope bound");
        assert_eq!(raw_block(&json!("ab".repeat(36))).unwrap(), vec![0xab; 36]);

        let dir = scratch("null");
        let head = B256::repeat_byte(0xaa);
        let (tip, blocks) = chain(head, 10, 3);
        // The source serves two real blocks and then `null`.
        let mut served = 0;
        let mut fetch = |id: &B256| -> Result<Value, String> {
            served += 1;
            Ok(if served == 3 { Value::Null } else { json!(hex::encode(&blocks[id])) })
        };
        let mut walk = Some(Walk { cursor: tip, ..Walk::default() });
        let error = walk_back(&mut fetch, &inspect_block, &plenty, &dir, walk.as_mut().unwrap(), &bounds(head, 10))
            .expect_err("a transient error for the caller, which retries");
        assert_eq!(error, "getblockraw reply is not a hex string");
        assert_eq!(pending_files(&dir), 2);
        abandon(&dir, &mut walk);
        assert!(walk.is_none());
        assert_eq!(pending_files(&dir), 0, "an abandoned walk leaves nothing on disk");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_honest_chain_is_walked_over_several_rounds_and_ends_at_the_head() {
        let dir = scratch("honest");
        let head = B256::repeat_byte(0xaa);
        let (tip, blocks) = chain(head, 10, 5);
        let mut fetch = |id: &B256| -> Result<Value, String> { Ok(json!(hex::encode(&blocks[id]))) };
        let mut walk = Walk { cursor: tip, ..Walk::default() };
        let limits = WalkBounds { max_fetch: 2, ..bounds(head, 10) };
        assert_eq!(walk_back(&mut fetch, &inspect_block, &plenty, &dir, &mut walk, &limits), Ok(false));
        assert_eq!(walk_back(&mut fetch, &inspect_block, &plenty, &dir, &mut walk, &limits), Ok(false));
        assert_eq!(walk_back(&mut fetch, &inspect_block, &plenty, &dir, &mut walk, &limits), Ok(true));
        assert_eq!((walk.ids.len(), walk.ids[0], pending_files(&dir)), (5, tip, 5));
        for id in &walk.ids {
            assert_eq!(fs::read(dir.join(format!("{}.pending", hex::encode(id)))).unwrap(), blocks[id]);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_block_that_is_not_the_one_asked_for_is_refused_before_it_is_written() {
        let dir = scratch("misidentified");
        let head = B256::repeat_byte(0xaa);
        let (tip, blocks) = chain(head, 10, 2);
        let (_, other) = envelope(B256::repeat_byte(0x55), 12);
        // Another canonical envelope under the asked id, then trailing bytes, then junk of envelope size.
        let mut junk = blocks[&tip].clone();
        junk.push(0);
        for wrong in [other, junk, vec![0u8; 316]] {
            let mut fetch = |_: &B256| -> Result<Value, String> { Ok(json!(hex::encode(&wrong))) };
            let mut walk = Walk { cursor: tip, ..Walk::default() };
            assert!(walk_back(&mut fetch, &inspect_block, &plenty, &dir, &mut walk, &bounds(head, 10)).is_err());
            assert_eq!((walk.ids.len(), pending_files(&dir)), (0, 0));
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The finding's second PoC: an endless chain of well-formed, hash-linked blocks that
    /// never reaches the head. Slots decrease from child to parent, so the walk ends at the
    /// head's slot, however long the fabricated chain is below it.
    #[test]
    fn an_endless_fake_chain_ends_at_the_heads_slot_and_leaves_no_file() {
        let dir = scratch("endless");
        let head = B256::repeat_byte(0xaa);
        // 60 fabricated blocks at slots 1..=60 on another root; the verified head is at slot 10.
        let (tip, blocks) = chain(B256::repeat_byte(0xbb), 0, 60);
        let mut fetch = |id: &B256| -> Result<Value, String> { Ok(json!(hex::encode(&blocks[id]))) };
        let mut walk = Some(Walk { cursor: tip, ..Walk::default() });
        let error = walk_back(&mut fetch, &inspect_block, &plenty, &dir, walk.as_mut().unwrap(), &bounds(head, 10))
            .expect_err("the chain does not descend from the head");
        assert!(error.contains("slot 10 is not above the verified head's slot 10: not a descendant"), "{error}");
        // Slots 60..=11 were stored; the block at the head's slot was not.
        assert_eq!((walk.as_ref().unwrap().ids.len(), pending_files(&dir)), (50, 50));
        abandon(&dir, &mut walk);
        assert_eq!(pending_files(&dir), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn slots_must_decrease_stay_above_the_head_and_not_run_ahead_of_the_clock() {
        let b = bounds(B256::ZERO, 100);
        assert_eq!(check_walk_slot(None, &b, 1_000), Ok(()));
        assert!(check_walk_slot(None, &b, 1_001).unwrap_err().contains("ahead of this host's clock"));
        assert_eq!(check_walk_slot(Some(500), &b, 499), Ok(()));
        assert!(check_walk_slot(Some(500), &b, 500).unwrap_err().contains("not below its child's slot"));
        assert!(check_walk_slot(Some(500), &b, 900).unwrap_err().contains("not below its child's slot"));
        assert_eq!(check_walk_slot(Some(500), &b, 101), Ok(()));
        assert!(check_walk_slot(Some(500), &b, 100).unwrap_err().contains("not a descendant"));
        assert!(check_walk_slot(None, &b, 0).unwrap_err().contains("not a descendant"));
        // The clock bound applies to the first block only; later ones are below it by the slot rule.
        assert_eq!(check_walk_slot(Some(5_000), &b, 4_999), Ok(()));
        // No clock (a zero slot time in the manifest): the slot rules still hold.
        let no_clock = WalkBounds { newest_slot: None, ..bounds(B256::ZERO, 100) };
        assert_eq!(check_walk_slot(None, &no_clock, u64::MAX), Ok(()));

        let clock = SlotClock { genesis_time_ms: 1_786_656_679_962, slot_ms: 30_000 };
        assert_eq!(clock.newest_slot(1_786_656_679_962), Some(CLOCK_SLACK_SLOTS));
        assert_eq!(clock.newest_slot(1_786_656_679_962 + 30_000 * 200_000 + 29_999), Some(200_000 + CLOCK_SLACK_SLOTS));
        assert_eq!(clock.newest_slot(0), None, "a clock before genesis bounds nothing");
        assert_eq!(SlotClock { genesis_time_ms: 0, slot_ms: 0 }.newest_slot(5), None);

        // A walk whose first block claims a slot ahead of the clock writes nothing.
        let dir = scratch("clock");
        let head = B256::repeat_byte(0xaa);
        let (tip, blocks) = chain(head, 2_000, 3);
        let mut fetch = |id: &B256| -> Result<Value, String> { Ok(json!(hex::encode(&blocks[id]))) };
        let mut walk = Walk { cursor: tip, ..Walk::default() };
        let error = walk_back(&mut fetch, &inspect_block, &plenty, &dir, &mut walk, &bounds(head, 100)).unwrap_err();
        assert!(error.contains("ahead of this host's clock"), "{error}");
        assert_eq!(pending_files(&dir), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_walk_stops_at_the_block_room_and_at_the_free_space_reserve() {
        let dir = scratch("room");
        let head = B256::repeat_byte(0xaa);
        let (tip, blocks) = chain(head, 10, 6);
        let mut fetch = |id: &B256| -> Result<Value, String> { Ok(json!(hex::encode(&blocks[id]))) };

        // --max-blocks leaves room for 4 more blocks: the fifth is not fetched.
        let mut walk = Some(Walk { cursor: tip, ..Walk::default() });
        let limits = WalkBounds { room: 4, ..bounds(head, 10) };
        let error = walk_back(&mut fetch, &inspect_block, &plenty, &dir, walk.as_mut().unwrap(), &limits).unwrap_err();
        assert!(error.contains("does not descend from the verified head"), "{error}");
        assert_eq!(pending_files(&dir), 4);
        abandon(&dir, &mut walk);
        assert_eq!(pending_files(&dir), 0);

        // The reserve: with 1,000 bytes free and a reserve of 800, a 316-byte block does not fit.
        let mut walk = Walk { cursor: tip, ..Walk::default() };
        let limits = WalkBounds { min_free_bytes: 800, ..bounds(head, 10) };
        let error = walk_back(&mut fetch, &inspect_block, &|| Ok(1_000), &dir, &mut walk, &limits).unwrap_err();
        assert!(error.contains("--min-free-bytes is 800"), "{error}");
        assert_eq!((walk.ids.len(), pending_files(&dir)), (0, 0), "nothing is written below the reserve");
        // An unreadable filesystem is not taken as room.
        let unreadable = || Err(std::io::Error::other("statvfs"));
        assert!(walk_back(&mut fetch, &inspect_block, &unreadable, &dir, &mut walk, &limits).is_err());
        assert_eq!(pending_files(&dir), 0);
        // The real call answers for a real directory.
        assert!(free_bytes(&dir).unwrap() > 0);
        assert!(free_bytes(&dir.join("missing")).is_err());

        // A zero parent ends the walk before any fetch.
        let mut walk = Walk { cursor: B256::ZERO, ..Walk::default() };
        let mut never = |_: &B256| -> Result<Value, String> { panic!("no fetch for the zero id") };
        assert!(walk_back(&mut never, &inspect_block, &plenty, &dir, &mut walk, &bounds(head, 10)).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pending_files_of_an_earlier_process_are_removed_at_start_and_verified_blocks_stay() {
        let dir = scratch("start");
        for name in ["aa.pending", "bb.pending", "cc.bin", "index"] {
            fs::write(dir.join(name), b"x").unwrap();
        }
        assert_eq!(remove_pending(&dir).unwrap(), 2);
        let mut left: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        assert_eq!(left, ["cc.bin", "index"]);
        assert_eq!(remove_pending(&dir).unwrap(), 0);
        assert!(remove_pending(&dir.join("missing")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_free_space_reserve_has_a_default_and_an_option() {
        let args = |extra: &[&str]| -> Vec<String> {
            let pin = "ab".repeat(32);
            let mut all: Vec<String> = ["--manifest", "m", "--network-pin", &pin, "--rpc-port", "1", "--state", "d", "--status", "s"]
                .iter()
                .map(|a| a.to_string())
                .collect();
            all.extend(extra.iter().map(|a| a.to_string()));
            all
        };
        assert_eq!(parse(&args(&[])).map(|o| o.min_free_bytes), Ok(8 * 1_073_741_824));
        assert_eq!(parse(&args(&["--min-free-bytes", "0"])).map(|o| o.min_free_bytes), Ok(0));
        assert!(parse(&args(&["--min-free-bytes", "lots"])).is_err());
    }
}
