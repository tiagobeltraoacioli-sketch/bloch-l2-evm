// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only RPC for the natively settled L2 (devnet 700771, mainnet 700770).
//!
//! Serves the canonical database written by the settlement worker, opened
//! read-only, and follows its head. `safe`/`finalized` are published only in
//! memory (never written to the database), from the native follower's status
//! (schema v2), with the levels of an Ethereum rollup:
//! - `finalized`: the highest L2 block whose settlement lies inside the
//!   natively FFG-finalized prefix that the follower verified by real replay
//!   from the pinned genesis, provided every listed settlement matches the local
//!   canonical header at its height;
//! - `safe`: the settlement the operator's own native node holds at its
//!   canonical head (accepted on L1, not yet finalized), when it matches the
//!   local canonical header; never below `finalized`.
//! No checkpoint signature is involved. Neither level regresses. Both start
//! closed. A status file that is lost, unreadable or whose finalized settlements
//! are inconsistent with the local chain closes both: their tags,
//! `bloch_settlement` and `bloch_getWithdrawalProof` answer -32001 until a valid
//! status returns. A `safe` settlement that differs from the local chain (a third
//! party settled at the L1 head) closes `safe` only. A status for a block not local
//! yet closes nothing and shows as state `lagging`. `bloch_finality` reports the
//! levels with their L1 anchors, and `status` with the state of the follower's
//! status file and its age at the time of the call.
//!
//! `pending` is answered as Ethereum clients expect from a rollup node that
//! publishes no pending block: state at `pending` is the latest state;
//! `eth_call`/`eth_estimateGas` at `pending` run in the next-block environment
//! derived from the latest header (number + 1, wall-clock timestamp, no
//! deposits; RPC-only, never built or stored); block-shaped queries
//! (`eth_getBlockByNumber("pending")`, ...) return the latest block; with
//! `--txpool`, `eth_getTransactionCount(addr, "pending")` also counts the
//! sender's consecutive spooled nonces (the sequencer's view).
//!
//! `--rules mainnet --domain HEX --genesis-time SECS` serves the mainnet
//! profile (chain id 700770, wall-clock genesis); `v3`/`v2` keep the devnet
//! identity.
//!
//! With `--txpool DIR` it is also the development sequencer's front door:
//! `eth_sendRawTransaction` authenticates the canonical signed bytes (EIP-2718
//! encoding, chain id, low-s ECDSA signature, size), then admits it against
//! the head state (security review 2026-10-18, finding 2): the sender holds
//! `value + gas_limit * max_fee`, the nonce is at most 16 above the head nonce,
//! the fee cap covers the next base fee, at most 16 entries per sender (a
//! same-nonce replacement needs a 10% fee bump), at most 4,096 entries in all;
//! the sender holds the summed cost of all its spooled entries; and the
//! transaction is one the settlement worker can include at all (it fits one
//! native DA batch, declares at most the worker's 15,000,000 block gas and at
//! least its intrinsic gas, a priority fee not above its fee cap, initcode
//! within EIP-3860), so a funded sender cannot hold spool slots for free with
//! entries the producer defers forever or drops without charging a fee;
//! when full, stale entries (used nonce, gap, unfunded, underpriced, older than
//! 3 h, undecodable) are evicted, then the cheapest deferred one if the new
//! transaction pays more. Stale entries are also swept every minute. It writes
//! one `<hash>.tx` spool entry (hex) atomically into the pool the settlement
//! worker selects from; the producer still decides inclusion and drops invalid
//! entries with a reason. Without `--txpool`, transactions are refused.
//!
//! `bloch_getWithdrawalProof(index, root?)` serves Merkle proofs of outbox
//! withdrawals covered by finalized settlements (`settled_rpc/withdrawal_proofs.rs`).
#[path = "settled_rpc/withdrawal_proofs.rs"]
mod withdrawal_proofs;
#[path = "settled_rpc/settlement_log.rs"]
mod settlement_log;

use alloy_primitives::B256;
use bloch_l2_evm::ChainSpec;
use bloch_reth_execution::{
    build_eth_api_with, chain_identity_rpc, chain_status_rpc, serve_pending_blocks_as_latest, start_http_rpc,
    BlochBlockchainProvider, BlochEvmConfig, BlochProviderFactory, L2Network, PendingPolicy,
};
use eyre::{bail, ensure, Result};
use reth_db::mdbx::{open_db_read_only, DatabaseArguments};
use reth_network_api::noop::NoopNetwork;
use reth_provider::{
    providers::{BlockchainProvider, RocksDBBuilder, StaticFileProvider},
    AccountReader, BlockNumReader, HeaderProvider, ProviderFactory,
};
use reth_rpc::EthFilter;
use reth_rpc_eth_api::{node::RpcNodeCoreAdapter, EthApiServer, EthFilterApiServer};
use reth_tasks::{RuntimeBuilder, RuntimeConfig, TokioConfig};
use reth_transaction_pool::noop::NoopTransactionPool;
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

const USAGE: &str = "bloch-l2-settled-rpc --data-dir CANONICAL --view-dir NEW_DIR --finality-status FILE --network HEX [--port 8546] [--poll-ms 2000] [--rules v3|v2|mainnet [--domain HEX --genesis-time SECS]] [--txpool DIR] [--min-tip-wei N]\n\
RPC over the settled database; with --txpool, eth_sendRawTransaction spools authenticated\n\
transactions for the settlement worker (the sequencer). finalized comes only from verified native FFG finality of L2 settlements;\n\
safe from the settlement the local native node accepted at its head. --rules selects the settlement\n\
execution rules the canonical database was written under (default v3: ChainSpec::testnet_v3; mainnet:\n\
ChainSpec::mainnet, chain id 700770, with the ceremony's --domain and wall-clock --genesis-time).\n\
pending: latest state, next-block environment for calls/estimates, latest block for block queries.\n";

struct Options {
    data_dir: PathBuf,
    view_dir: PathBuf,
    status: PathBuf,
    network: String,
    port: u16,
    poll: Duration,
    l2: L2Network,
    txpool: Option<PathBuf>,
    /// Smallest priority fee the spool admits and the fee methods suggest.
    min_tip: u128,
}

/// Admission bounds of the spool (security review 2026-10-18, finding 2: an
/// unauthenticated sender must not be able to fill the pool the producer
/// reads). The producer itself refuses a pool above 16,384 entries.
#[derive(Clone, Copy, Debug)]
struct SpoolLimits {
    /// Entries in the spool, all senders.
    max_entries: usize,
    /// Entries per sender.
    max_per_sender: usize,
    /// Highest nonce accepted above the sender's head nonce.
    max_nonce_gap: u64,
    /// Age after which an entry the producer never took is evicted.
    ttl: Duration,
    /// Fee bump (percent) a same-nonce replacement must offer.
    replace_bump_percent: u128,
    /// Highest declared gas: the settlement worker's per-block gas budget
    /// (`max_block_gas`, deployment/mainnet/install-settler-mainnet.py). A
    /// transaction above it is deferred by every block and would hold its slot
    /// (and block its sender's later nonces) until the TTL without paying.
    max_tx_gas: u64,
    /// Smallest effective priority fee per gas admitted, in wei.
    min_tip: u128,
}

const SPOOL_LIMITS: SpoolLimits = SpoolLimits {
    max_entries: 4_096,
    max_per_sender: 16,
    max_nonce_gap: 16,
    ttl: Duration::from_secs(3 * 3_600),
    replace_bump_percent: 10,
    max_tx_gas: 15_000_000,
    min_tip: DEFAULT_MIN_TIP_WEI,
};
/// Smallest priority fee the spool admits. 0.1 gwei is 210 sat on a transfer, against about 19 sat of
/// marginal data-availability cost and a base fee that decays to almost nothing. Not a consensus rule:
/// a block with a lower tip stays valid, and replay never consults this.
const DEFAULT_MIN_TIP_WEI: u128 = 100_000_000;
/// Concurrent EVM simulations (`eth_call`, `eth_estimateGas`, ...): each may
/// burn the full gas cap of CPU; beyond this many, callers wait (up to
/// [`SIMULATION_WAIT`]) instead of occupying every core of the host.
const MAX_CONCURRENT_SIMULATIONS: usize = 4;
const SIMULATION_WAIT: Duration = Duration::from_secs(10);
/// The methods that run the EVM on request.
const SIMULATION_METHODS: [&str; 5] = ["eth_call", "eth_estimateGas", "eth_createAccessList", "eth_callMany", "eth_simulateV1"];
/// Periodic eviction of stale spool entries (also done under pressure at admission).
const SPOOL_SWEEP: Duration = Duration::from_secs(60);

fn parse() -> Result<Options> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help") {
        print!("{USAGE}");
        std::process::exit(0);
    }
    ensure!(args.len() % 2 == 0, "options must be --name value pairs\n{USAGE}");
    let mut map = std::collections::BTreeMap::new();
    for pair in args.chunks(2) {
        ensure!(
            [
                "--data-dir", "--view-dir", "--finality-status", "--network", "--port", "--poll-ms", "--rules", "--domain",
                "--genesis-time", "--txpool", "--min-tip-wei",
            ].contains(&pair[0].as_str()),
            "unknown option {}\n{USAGE}",
            pair[0]
        );
        ensure!(map.insert(pair[0].clone(), pair[1].clone()).is_none(), "{} repeated", pair[0]);
    }
    let get = |k: &str| map.get(k).cloned().ok_or_else(|| eyre::eyre!("missing {k}\n{USAGE}"));
    let network = get("--network")?;
    ensure!(network.len() == 64 && network.bytes().all(|b| b.is_ascii_hexdigit()), "--network must be 64 hex characters");
    Ok(Options {
        data_dir: PathBuf::from(get("--data-dir")?),
        view_dir: PathBuf::from(get("--view-dir")?),
        status: PathBuf::from(get("--finality-status")?),
        network: network.to_lowercase(),
        port: map.get("--port").map_or(Ok(8546), |v| v.parse())?,
        poll: Duration::from_millis(map.get("--poll-ms").map_or(Ok(2000), |v| v.parse())?),
        l2: L2Network::parse(
            map.get("--rules").map_or("v3", String::as_str),
            map.get("--domain").map(String::as_str),
            map.get("--genesis-time").map(String::as_str),
        )
        .map_err(|e| eyre::eyre!("{e}\n{USAGE}"))?,
        txpool: map.get("--txpool").map(PathBuf::from),
        min_tip: map.get("--min-tip-wei").map_or(Ok(DEFAULT_MIN_TIP_WEI), |v| v.parse())?,
    })
}

fn rpc_error(message: impl Into<String>) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObjectOwned::owned(-32000, message.into(), None::<()>)
}

/// What admission needs from one spooled transaction (decoded once per file).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpoolMeta {
    sender: alloy_primitives::Address,
    nonce: u64,
    /// Fee cap per gas (`max_fee_per_gas`, or the legacy gas price).
    max_fee: u128,
    /// Priority fee per gas (the gas price for legacy transactions).
    priority: u128,
    /// `value + gas_limit * max_fee`: what the sender must hold at the head.
    cost: alloy_primitives::U256,
}

impl SpoolMeta {
    fn of(tx: &bloch_l2_evm::AuthenticatedTransaction) -> Self {
        let env = tx.environment();
        Self {
            sender: tx.sender(),
            nonce: env.nonce,
            max_fee: env.gas_price,
            priority: env.gas_priority_fee.unwrap_or(env.gas_price),
            cost: env.value.saturating_add(
                alloy_primitives::U256::from(env.gas_limit).saturating_mul(alloy_primitives::U256::from(env.gas_price)),
            ),
        }
    }
}

/// Why the settlement worker could never include `tx` (so it must not take a
/// spool slot): the producer defers it forever (gas above the block budget) or
/// drops it without charging a fee (larger than one DA batch, below intrinsic
/// gas, priority fee above the fee cap, oversized initcode).
fn never_includable(spec: &ChainSpec, tx: &bloch_l2_evm::AuthenticatedTransaction, limits: SpoolLimits) -> Option<String> {
    use bloch_l2_evm::data_availability::{da_framing_bytes, MAX_DA_PAYLOAD_BYTES};
    use reth_revm::revm::{context_interface::cfg::gas::calculate_initial_tx_gas_for_tx, primitives::eip3860::MAX_INITCODE_SIZE};
    let env = tx.environment();
    let bytes = tx.raw().len();
    if bytes.saturating_add(da_framing_bytes(1)) > MAX_DA_PAYLOAD_BYTES {
        return Some(format!(
            "transaction too large: {bytes} bytes, at most {} fit one L1 data-availability batch",
            MAX_DA_PAYLOAD_BYTES - da_framing_bytes(1)
        ));
    }
    let max_gas = limits.max_tx_gas.min(spec.gas_limit);
    if env.gas_limit > max_gas {
        return Some(format!("exceeds block gas limit: gas limit {} above {max_gas}", env.gas_limit));
    }
    if env.gas_priority_fee.is_some_and(|tip| tip > env.gas_price) {
        return Some("max priority fee per gas higher than max fee per gas".into());
    }
    if env.kind.is_create() && env.data.len() > MAX_INITCODE_SIZE {
        return Some(format!("max initcode size exceeded: {} bytes, at most {MAX_INITCODE_SIZE}", env.data.len()));
    }
    let gas = calculate_initial_tx_gas_for_tx(env.clone(), spec.spec_id);
    let intrinsic = gas.initial_regular_gas.saturating_add(gas.initial_state_gas).max(gas.floor_gas);
    if env.gas_limit < intrinsic {
        return Some(format!("intrinsic gas too low: gas limit {}, needs {intrinsic}", env.gas_limit));
    }
    None
}

/// One `*.tx` file of the spool; `meta` is `None` for bytes that do not decode
/// as a transaction of this chain (always evictable).
#[derive(Clone, Debug)]
struct SpoolEntry {
    name: std::ffi::OsString,
    meta: Option<SpoolMeta>,
    modified: std::time::SystemTime,
    /// Monotonic time this process first saw the entry, and its wall-clock age then.
    seen: std::time::Instant,
    age_when_seen: Duration,
}

/// Sender and fee fields and modification time of each spool entry, cached by
/// file name (entries are immutable: written once by rename, removed by the
/// producer or by eviction), so a scan of a full spool costs one directory
/// read rather than a stat and a decode per entry.
type SpoolIndex = std::collections::HashMap<std::ffi::OsString, (Option<SpoolMeta>, std::time::SystemTime, std::time::Instant, Duration)>;

/// Read the spool directory, decoding only names not yet in `index`; the index
/// forgets names that disappeared. Entries removed while scanning are skipped.
fn scan_spool(spec: &ChainSpec, pool: &Path, index: &mut SpoolIndex) -> std::io::Result<Vec<SpoolEntry>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(pool)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|x| x != "tx") {
            continue;
        }
        let Some(name) = path.file_name().map(|n| n.to_os_string()) else { continue };
        let (meta, modified, seen, age_when_seen) = match index.get(&name) {
            Some(known) => *known,
            None => {
                let modified = match entry.metadata().and_then(|m| m.modified()) {
                    Ok(time) => time,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                let meta = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| alloy_primitives::hex::decode(text.trim()).ok())
                    .and_then(|raw| bloch_l2_evm::decode_signed_transaction(spec, &raw).ok())
                    .map(|tx| SpoolMeta::of(&tx));
                let seen = std::time::Instant::now();
                let age = std::time::SystemTime::now().duration_since(modified).unwrap_or_default();
                index.insert(name.clone(), (meta, modified, seen, age));
                (meta, modified, seen, age)
            }
        };
        entries.push(SpoolEntry { name, meta, modified, seen, age_when_seen });
    }
    let present: std::collections::HashSet<_> = entries.iter().map(|e| e.name.clone()).collect();
    index.retain(|name, _| present.contains(name));
    Ok(entries)
}

/// The head facts admission is decided against: per-sender `(nonce, balance)`
/// of the latest settled state and the next block's base fee.
struct SpoolHead<'a> {
    account: &'a mut dyn FnMut(alloy_primitives::Address) -> (u64, alloy_primitives::U256),
    next_base_fee: u128,
    now: std::time::SystemTime,
}

impl SpoolHead<'_> {
    /// Past the TTL by the monotonic clock, for an entry this process saw while it was young: a forward
    /// clock step must not evict acknowledged transactions, and a backward step must not keep them. An
    /// entry already past the TTL when first seen (after a restart) has only the wall clock to go by.
    fn expired(&self, entry: &SpoolEntry, ttl: Duration) -> bool {
        entry.seen.elapsed() > ttl
            || (entry.age_when_seen > ttl && self.now.duration_since(entry.modified).is_ok_and(|age| age > ttl))
    }

    /// Why `entry` can no longer be included and may be evicted, if it cannot.
    fn stale(&mut self, entry: &SpoolEntry, limits: SpoolLimits) -> Option<&'static str> {
        let Some(meta) = entry.meta else { return Some("undecodable") };
        let (nonce, balance) = (self.account)(meta.sender);
        if meta.nonce < nonce {
            Some("nonce already used")
        } else if meta.nonce > nonce.saturating_add(limits.max_nonce_gap) {
            Some("nonce gap")
        } else if balance < meta.cost {
            Some("insufficient balance")
        } else if meta.max_fee < self.next_base_fee {
            Some("underpriced")
        } else if meta.priority < limits.min_tip {
            Some("below the minimum tip")
        } else if self.expired(entry, limits.ttl) {
            Some("expired")
        } else {
            None
        }
    }
}

/// Admission of `new` into a spool holding `entries`: the names to evict
/// first, or the refusal sent to the client.
///
/// - the sender must hold `value + gas_limit * max_fee` at the head, summed
///   over this transaction and its other live spool entries; its nonce
///   must lie in `[head nonce, head nonce + max_nonce_gap]`, and the fee cap
///   must cover the next block's base fee;
/// - a same-nonce entry of the sender is replaced only by a fee bump;
/// - at most `max_per_sender` entries per sender;
/// - when the spool is full, stale entries (used nonce, gap, unfunded,
///   underpriced, expired, undecodable) are evicted; then the lowest-fee entry
///   deferred behind a nonce gap, else the lowest-fee entry overall provided
///   it pays less than `new`.
fn plan_admission(
    entries: &[SpoolEntry],
    new: &SpoolMeta,
    head: &mut SpoolHead<'_>,
    limits: SpoolLimits,
) -> Result<Vec<std::ffi::OsString>, String> {
    let (nonce, balance) = (head.account)(new.sender);
    if new.nonce < nonce {
        return Err(format!("nonce too low: next nonce is {nonce}"));
    }
    if new.nonce > nonce.saturating_add(limits.max_nonce_gap) {
        return Err(format!("nonce too high: next nonce is {nonce}, at most {} ahead is accepted", limits.max_nonce_gap));
    }
    if balance < new.cost {
        return Err(format!("insufficient funds for gas * price + value: balance {balance}, cost {}", new.cost));
    }
    if new.max_fee < head.next_base_fee {
        return Err(format!("max fee per gas {} below the next base fee {}", new.max_fee, head.next_base_fee));
    }
    let effective_tip = new.priority.min(new.max_fee - head.next_base_fee);
    if effective_tip < limits.min_tip {
        return Err(format!(
            "transaction underpriced: effective priority fee {effective_tip} wei at the next base fee {}, at least {} wei is required",
            head.next_base_fee, limits.min_tip
        ));
    }
    let mut evict = Vec::new();
    let mut own = Vec::new();
    for entry in entries.iter().filter(|e| e.meta.is_some_and(|m| m.sender == new.sender)) {
        if head.stale(entry, limits).is_some() {
            evict.push(entry.name.clone());
        } else {
            own.push(entry);
        }
    }
    if let Some(old) = own.iter().find(|e| e.meta.is_some_and(|m| m.nonce == new.nonce)) {
        let old_meta = old.meta.expect("own entries decode");
        let bumped = |old: u128, new: u128| new.saturating_mul(100) >= old.saturating_mul(100 + limits.replace_bump_percent);
        if !bumped(old_meta.max_fee, new.max_fee) || !bumped(old_meta.priority, new.priority) {
            return Err(format!("replacement transaction underpriced: needs a {}% fee bump", limits.replace_bump_percent));
        }
        evict.push(old.name.clone());
        own.retain(|e| e.name != old.name);
    }
    if own.len() >= limits.max_per_sender {
        return Err(format!("too many pending transactions from this sender (limit {})", limits.max_per_sender));
    }
    // Each entry alone being affordable is not enough: entries the balance
    // cannot cover together are dropped by execution without paying a fee.
    let pending = own
        .iter()
        .filter_map(|e| e.meta)
        .fold(alloy_primitives::U256::ZERO, |sum, m| sum.saturating_add(m.cost));
    if balance < pending.saturating_add(new.cost) {
        return Err(format!(
            "insufficient funds for this and the sender's pending transactions: balance {balance}, cost {}",
            pending.saturating_add(new.cost)
        ));
    }
    if entries.len() - evict.len() < limits.max_entries {
        return Ok(evict);
    }
    // Full: drop every stale entry of any sender.
    let mut live = Vec::new();
    for entry in entries {
        if evict.contains(&entry.name) {
            continue;
        }
        if head.stale(entry, limits).is_some() {
            evict.push(entry.name.clone());
        } else {
            live.push(entry);
        }
    }
    if live.len() < limits.max_entries {
        return Ok(evict);
    }
    // Still full: an entry deferred behind a nonce gap of its sender (cannot be
    // included next) is displaced first, the cheapest of them; otherwise the
    // cheapest entry, only by a transaction paying more.
    let mut next = std::collections::HashMap::new();
    for entry in &live {
        let meta = entry.meta.expect("live entries decode");
        next.entry(meta.sender).or_insert_with(|| (head.account)(meta.sender).0);
    }
    let mut nonces: std::collections::HashMap<alloy_primitives::Address, std::collections::BTreeSet<u64>> =
        std::collections::HashMap::new();
    for entry in &live {
        let meta = entry.meta.expect("live entries decode");
        nonces.entry(meta.sender).or_default().insert(meta.nonce);
    }
    let gapped = |meta: &SpoolMeta| {
        let mut expected = next[&meta.sender];
        for n in &nonces[&meta.sender] {
            if *n == meta.nonce {
                return *n != expected;
            }
            if *n == expected {
                expected += 1;
            }
        }
        true
    };
    let victim = live
        .iter()
        .filter(|e| e.meta.is_some_and(|m| m.sender != new.sender))
        .min_by_key(|e| {
            let meta = e.meta.expect("live entries decode");
            (!gapped(&meta), meta.max_fee, std::cmp::Reverse(e.modified))
        })
        .filter(|e| e.meta.is_some_and(|m| gapped(&m) || m.max_fee < new.max_fee));
    match victim {
        Some(entry) => {
            evict.push(entry.name.clone());
            Ok(evict)
        }
        None => Err("txpool full".into()),
    }
}

/// Remove `.<hash>.partial` files a crash left behind. Admission writes them under the spool lock,
/// which the caller holds, so none of them can be in use.
fn remove_leftover_partials(pool: &Path) {
    let Ok(listing) = std::fs::read_dir(pool) else { return };
    for entry in listing.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') && name.ends_with(".partial") && std::fs::remove_file(entry.path()).is_ok() {
            println!("removed leftover spool file {name}");
        }
    }
}

/// Remove spool files; a file the producer already consumed is not an error.
fn evict_spool(pool: &Path, names: &[std::ffi::OsString], reason: &str) {
    for name in names {
        match std::fs::remove_file(pool.join(name)) {
            Ok(()) => println!("evicted tx file={} ({reason})", Path::new(name).display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => println!("evict {} failed: {e}", Path::new(name).display()),
        }
    }
}

/// The settled RPC's spool: one lock serializes admission, eviction and the
/// pending-nonce view, so the caps hold under concurrent requests.
struct Spool {
    spec: ChainSpec,
    dir: PathBuf,
    index: std::sync::Mutex<SpoolIndex>,
    limits: SpoolLimits,
}

impl Spool {
    fn lock(&self) -> std::sync::MutexGuard<'_, SpoolIndex> {
        self.index.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Head facts of the database tip. The tip is read from the database, not
    /// from the RPC's in-memory canonical head (refreshed every --poll-ms), so
    /// a block the producer has just committed (and whose transactions it has
    /// removed from the spool) is never mistaken for a spool gap.
    fn with_head<T>(
        &self,
        provider: &BlochProviderFactory,
        f: impl FnOnce(&mut SpoolHead<'_>) -> T,
    ) -> Result<T, String> {
        let best = provider.best_block_number().map_err(|e| format!("state unavailable: {e}"))?;
        let header = provider
            .sealed_header(best)
            .map_err(|e| format!("state unavailable: {e}"))?
            .ok_or("state unavailable: head header missing")?;
        let next_base_fee = u128::from(self.spec.next_base_fee(header.0.base_fee_per_gas, header.0.gas_used));
        let state = provider.latest().map_err(|e| format!("state unavailable: {e}"))?;
        let mut cache = std::collections::HashMap::new();
        let mut account = |address| {
            *cache.entry(address).or_insert_with(|| {
                state
                    .basic_account(&address)
                    .ok()
                    .flatten()
                    .map_or((0, alloy_primitives::U256::ZERO), |a| (a.nonce, a.balance))
            })
        };
        Ok(f(&mut SpoolHead { account: &mut account, next_base_fee, now: std::time::SystemTime::now() }))
    }

    /// Admit authenticated `raw` bytes, or say why not.
    fn submit(&self, provider: &BlochProviderFactory, raw: &[u8]) -> Result<B256, String> {
        let tx = bloch_l2_evm::decode_signed_transaction(&self.spec, raw).map_err(|e| format!("transaction rejected: {e:?}"))?;
        if let Some(why) = never_includable(&self.spec, &tx, self.limits) {
            return Err(why);
        }
        let hash = tx.hash();
        let name = format!("{}.tx", alloy_primitives::hex::encode(hash));
        let mut index = self.lock();
        if self.dir.join(&name).exists() {
            return Ok(hash); // already known, not yet consumed
        }
        let entries = scan_spool(&self.spec, &self.dir, &mut index).map_err(|e| format!("txpool unavailable: {e}"))?;
        let meta = SpoolMeta::of(&tx);
        let evict = self.with_head(provider, |head| plan_admission(&entries, &meta, head, self.limits))??;
        evict_spool(&self.dir, &evict, "displaced at admission");
        // Write beside, then rename: the producer only reads complete *.tx files.
        let partial = self.dir.join(format!(".{}.partial", alloy_primitives::hex::encode(hash)));
        let written = std::fs::write(&partial, format!("{}\n", alloy_primitives::hex::encode(tx.raw())))
            .and_then(|()| {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o600))
            })
            .and_then(|()| std::fs::rename(&partial, self.dir.join(&name)));
        if let Err(error) = written {
            let _ = std::fs::remove_file(&partial);
            return Err(format!("txpool write failed: {error}"));
        }
        index.insert(name.into(), (Some(meta), std::time::SystemTime::now(), std::time::Instant::now(), Duration::ZERO));
        println!("spooled tx={hash} from={} nonce={}", meta.sender, meta.nonce);
        Ok(hash)
    }

    /// Evict every stale entry (run periodically, not only under pressure).
    fn sweep(&self, provider: &BlochProviderFactory) -> Result<usize, String> {
        let mut index = self.lock();
        remove_leftover_partials(&self.dir);
        let entries = scan_spool(&self.spec, &self.dir, &mut index).map_err(|e| format!("txpool unavailable: {e}"))?;
        let stale = self.with_head(provider, |head| {
            entries.iter().filter_map(|e| head.stale(e, self.limits).map(|why| (e.name.clone(), why))).collect::<Vec<_>>()
        })?;
        for (name, why) in &stale {
            evict_spool(&self.dir, std::slice::from_ref(name), why);
        }
        Ok(stale.len())
    }
}

/// `eth_sendRawTransaction` into the settlement worker's spool directory.
fn sequencer_rpc(spool: Arc<Spool>, provider: BlochProviderFactory) -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_blocking_method("eth_sendRawTransaction", move |params, _, _| {
            let raw: alloy_primitives::Bytes = params.one()?;
            spool.submit(&provider, &raw).map_err(rpc_error)
        })
        .expect("the send method name is unique in a new module");
    module
}

/// The sender's next nonce in the sequencer's view: `latest` plus every
/// consecutive nonce already waiting in the spool.
fn spooled_next_nonce(
    spec: &ChainSpec,
    pool: &Path,
    index: &std::sync::Mutex<SpoolIndex>,
    sender: alloy_primitives::Address,
    latest: u64,
) -> std::io::Result<u64> {
    let mut index = index.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let nonces: std::collections::BTreeSet<u64> = scan_spool(spec, pool, &mut index)?
        .into_iter()
        .filter_map(|e| e.meta)
        .filter(|m| m.sender == sender)
        .map(|m| m.nonce)
        .collect();
    let mut next = latest;
    while nonces.contains(&next) {
        next += 1;
    }
    Ok(next)
}

/// The sender's nonce at the database tip (see [`Spool::with_head`]).
fn tip_nonce(factory: &BlochProviderFactory, sender: alloy_primitives::Address) -> Result<u64, String> {
    let state = factory.latest().map_err(|e| format!("state unavailable: {e}"))?;
    Ok(state.basic_account(&sender).map_err(|e| format!("state unavailable: {e}"))?.map_or(0, |a| a.nonce))
}

/// `eth_getTransactionCount(addr, "pending")` in the sequencer's view (see
/// [`spooled_next_nonce`]), counted from the later of the RPC's `latest` and
/// the database tip; other tags go to the upstream handler unchanged.
fn spool_pending_nonce(
    module: &mut jsonrpsee::RpcModule<()>,
    spool: Arc<Spool>,
    factory: BlochProviderFactory,
) -> Result<()> {
    let original: jsonrpsee::Methods = module.clone().into();
    ensure!(module.remove_method("eth_getTransactionCount").is_some(), "eth API lacks eth_getTransactionCount");
    module.register_async_method("eth_getTransactionCount", move |params, _, _| {
        let (original, spool, factory) = (original.clone(), spool.clone(), factory.clone());
        async move {
            let mut values: Vec<serde_json::Value> = params.parse()?;
            let pending = values.get(1).and_then(|v| v.as_str()) == Some("pending");
            if pending {
                values[1] = serde_json::Value::String("latest".into());
            }
            let upstream = |error| match error {
                jsonrpsee::core::server::MethodsError::JsonRpc(object) => object,
                other => rpc_error(other.to_string()),
            };
            let count: alloy_primitives::U64 =
                original.call("eth_getTransactionCount", values.clone()).await.map_err(upstream)?;
            if !pending {
                return Ok(count);
            }
            let sender: alloy_primitives::Address = serde_json::from_value(values[0].clone())
                .map_err(|e| jsonrpsee::types::ErrorObjectOwned::owned(-32602, e.to_string(), None::<()>))?;
            tokio::task::spawn_blocking(move || {
                let latest = tip_nonce(&factory, sender)?.max(count.to());
                spooled_next_nonce(&spool.spec, &spool.dir, &spool.index, sender, latest)
                    .map_err(|e| format!("txpool unavailable: {e}"))
            })
            .await
            .map_err(|e| rpc_error(e.to_string()))?
            .map(alloy_primitives::U64::from)
            .map_err(rpc_error)
        }
    })?;
    Ok(())
}

/// A hex quantity raised to `floor`; anything else stays as it is.
fn floored_quantity(value: &serde_json::Value, floor: u128) -> serde_json::Value {
    match value.as_str().and_then(|text| text.strip_prefix("0x")).and_then(|hex| u128::from_str_radix(hex, 16).ok()) {
        Some(number) if number < floor => serde_json::Value::String(format!("0x{floor:x}")),
        _ => value.clone(),
    }
}

/// Keep what wallets are told to pay at or above what the spool admits. Replicas apply it too: a
/// gateway reads fees from either backend and sends the transaction to the sequencer. Wallets differ:
/// viem and ethers read `eth_maxPriorityFeePerGas`, Foundry reads the rewards of `eth_feeHistory`,
/// legacy senders read `eth_gasPrice`.
fn floor_fee_suggestions(
    module: &mut jsonrpsee::RpcModule<()>,
    min_tip: u128,
    factory: BlochProviderFactory,
    spec: ChainSpec,
) -> Result<()> {
    let original: jsonrpsee::Methods = module.clone().into();
    for method in ["eth_maxPriorityFeePerGas", "eth_gasPrice", "eth_feeHistory"] {
        ensure!(module.remove_method(method).is_some(), "eth API lacks {method}");
        let (original, factory, spec) = (original.clone(), factory.clone(), spec.clone());
        module.register_async_method(method, move |params, _, _| {
            let (original, factory, spec) = (original.clone(), factory.clone(), spec.clone());
            async move {
                let values: Vec<serde_json::Value> = if params.as_str().is_none() { vec![] } else { params.parse()? };
                let mut result: serde_json::Value = original.call(method, values).await.map_err(|error| match error {
                    jsonrpsee::core::server::MethodsError::JsonRpc(object) => object,
                    other => rpc_error(other.to_string()),
                })?;
                match method {
                    "eth_maxPriorityFeePerGas" => result = floored_quantity(&result, min_tip),
                    "eth_gasPrice" => {
                        let next_base_fee = tokio::task::spawn_blocking(move || -> Result<u128, String> {
                            let best = factory.best_block_number().map_err(|e| e.to_string())?;
                            let header = factory.sealed_header(best).map_err(|e| e.to_string())?.ok_or("head header missing")?;
                            Ok(u128::from(spec.next_base_fee(header.0.base_fee_per_gas, header.0.gas_used)))
                        })
                        .await
                        .map_err(|e| rpc_error(e.to_string()))?
                        .map_err(rpc_error)?;
                        result = floored_quantity(&result, next_base_fee.saturating_add(min_tip));
                    }
                    _ => floor_rewards(&mut result, min_tip),
                }
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>(result)
            }
        })?;
    }
    Ok(())
}

/// Raise each reward of an `eth_feeHistory` answer to `floor`.
fn floor_rewards(history: &mut serde_json::Value, floor: u128) {
    let Some(blocks) = history.get_mut("reward").and_then(|r| r.as_array_mut()) else { return };
    for rewards in blocks.iter_mut().filter_map(|b| b.as_array_mut()) {
        for reward in rewards.iter_mut() {
            *reward = floored_quantity(reward, floor);
        }
    }
}

/// Run the EVM-simulating methods ([`SIMULATION_METHODS`]) under one
/// semaphore of `permits`: a caller that cannot get a permit within `wait` is
/// told to retry. Other methods are unaffected.
fn limit_simulations(module: &mut jsonrpsee::RpcModule<()>, permits: usize, wait: Duration) -> Result<()> {
    let original: jsonrpsee::Methods = module.clone().into();
    let gate = Arc::new(tokio::sync::Semaphore::new(permits));
    for name in SIMULATION_METHODS {
        if module.remove_method(name).is_none() {
            continue;
        }
        let (original, gate) = (original.clone(), gate.clone());
        module.register_async_method(name, move |params, _, _| {
            let (original, gate) = (original.clone(), gate.clone());
            async move {
                let values: Vec<serde_json::Value> = params.parse()?;
                let _permit = match tokio::time::timeout(wait, gate.acquire_owned()).await {
                    Ok(Ok(permit)) => permit,
                    _ => {
                        return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                            -32005,
                            format!("{name}: too many concurrent EVM simulations, retry later"),
                            None::<()>,
                        ))
                    }
                };
                original.call::<_, serde_json::Value>(name, values).await.map_err(|error| match error {
                    jsonrpsee::core::server::MethodsError::JsonRpc(object) => object,
                    other => rpc_error(other.to_string()),
                })
            }
        })?;
    }
    Ok(())
}

/// Lookups by transaction hash that read the database directly, while state
/// reads at `latest` follow the in-memory head the poll loop refreshes every
/// --poll-ms.
const HEAD_BOUND_METHODS: [&str; 2] = ["eth_getTransactionReceipt", "eth_getTransactionByHash"];

/// Answer a mined transaction or its receipt only once its block is at or
/// below the served head (`null` until then, as an Ethereum node does before
/// it imports the block). Without this, a client that sees its receipt and
/// then reads `latest` (forge script, ethers `wait()` followed by a call) can
/// read the state before its own transaction for up to one poll interval.
fn hide_blocks_above_head(module: &mut jsonrpsee::RpcModule<()>, head: Arc<AtomicU64>) -> Result<()> {
    let original: jsonrpsee::Methods = module.clone().into();
    for method in HEAD_BOUND_METHODS {
        ensure!(module.remove_method(method).is_some(), "eth API lacks {method}");
        let (original, head) = (original.clone(), head.clone());
        module.register_async_method(method, move |params, _, _| {
            let (original, head) = (original.clone(), head.clone());
            async move {
                let values: Vec<serde_json::Value> = if params.as_str().is_none() { vec![] } else { params.parse()? };
                let result: serde_json::Value = original.call(method, values).await.map_err(|error| match error {
                    jsonrpsee::core::server::MethodsError::JsonRpc(object) => object,
                    other => rpc_error(other.to_string()),
                })?;
                let number = result
                    .get("blockNumber")
                    .and_then(|v| v.as_str())
                    .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok());
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>(match number {
                    Some(number) if number > head.load(Ordering::Acquire) => serde_json::Value::Null,
                    _ => result,
                })
            }
        })?;
    }
    Ok(())
}

/// RocksDB's read-only secondary needs a writable scratch directory beside
/// `rocks`; the view keeps it out of the writer's database directory.
fn create_view(data: &Path, view: &Path) -> Result<()> {
    std::fs::create_dir(view)?;
    for directory in ["db", "static", "rocks"] {
        let target = data.join(directory);
        ensure!(std::fs::symlink_metadata(&target)?.is_dir(), "{} is not a directory", target.display());
        std::os::unix::fs::symlink(target, view.join(directory))?;
    }
    Ok(())
}

type Header = reth_primitives_traits::SealedHeader<bloch_reth_execution::BlochNodeHeader>;

/// The status lists a settled L2 block this database has not reached: this RPC lags, and the file's
/// own age and schema still say how current the follower is.
#[derive(Debug)]
struct NotLocalYet {
    number: u64,
    written_at: Option<u64>,
    schema: Option<String>,
}

impl std::fmt::Display for NotLocalYet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "settled L2 block {} is not in the local canonical chain yet", self.number)
    }
}

impl std::error::Error for NotLocalYet {}

/// Whether a failed status read closes the published levels. The follower replaces the file atomically,
/// so anything but a local lag is a real fault. A missing file is `Ok(None)` and closes them too.
/// A local lag closes nothing; it shows as state `lagging` with the file's real age.
fn closes_levels(error: &eyre::Report) -> bool {
    error.downcast_ref::<NotLocalYet>().is_none()
}

/// Methods that accept a block tag, with the position of the tag. `None` means a filter object.
const TAGGED_METHODS: [(&str, Option<usize>); 22] = [
    ("eth_getBlockByNumber", Some(0)),
    ("eth_getHeaderByNumber", Some(0)),
    ("eth_getBlockReceipts", Some(0)),
    ("eth_getBlockTransactionCountByNumber", Some(0)),
    ("eth_getUncleCountByBlockNumber", Some(0)),
    ("eth_getTransactionByBlockNumberAndIndex", Some(0)),
    ("eth_getRawTransactionByBlockNumberAndIndex", Some(0)),
    ("eth_feeHistory", Some(1)),
    ("eth_getBalance", Some(1)),
    ("eth_getCode", Some(1)),
    ("eth_getTransactionCount", Some(1)),
    ("eth_call", Some(1)),
    ("eth_estimateGas", Some(1)),
    ("eth_createAccessList", Some(1)),
    ("eth_getStorageAt", Some(2)),
    ("eth_getProof", Some(2)),
    ("eth_getAccount", Some(1)),
    ("eth_getAccountInfo", Some(1)),
    ("eth_callMany", Some(1)),
    ("eth_simulateV1", Some(1)),
    ("eth_getLogs", None),
    ("eth_newFilter", None),
];

/// Which published levels are closed. Both start closed: nothing is known before the first valid status.
struct ClosedLevels {
    finalized: std::sync::atomic::AtomicBool,
    safe: std::sync::atomic::AtomicBool,
}

impl ClosedLevels {
    fn new(closed: bool) -> Self {
        Self { finalized: closed.into(), safe: closed.into() }
    }

    fn set(&self, finalized: bool, safe: bool) {
        self.finalized.store(finalized, Ordering::Release);
        self.safe.store(safe, Ordering::Release);
    }

    fn tag_closed(&self, tag: Option<&str>) -> bool {
        match tag {
            Some("finalized") => self.finalized.load(Ordering::Acquire),
            Some("safe") => self.safe.load(Ordering::Acquire),
            _ => false,
        }
    }
}

fn names_a_closed_level(values: &[serde_json::Value], position: Option<usize>, closed: &ClosedLevels) -> bool {
    let is_closed = |v: Option<&serde_json::Value>| closed.tag_closed(v.and_then(|v| v.as_str()));
    match position {
        Some(at) => {
            let value = values.get(at);
            // EIP-1898 form: {"blockNumber": tag}.
            is_closed(value) || is_closed(value.and_then(|v| v.get("blockNumber")))
        }
        None => values.first().is_some_and(|f| is_closed(f.get("fromBlock")) || is_closed(f.get("toBlock"))),
    }
}

/// Answers that assert finality without naming a tag: they close with `finalized`, so that "closed" cannot
/// read as "not settled", and a closed process does not say `finalized: true`.
const FINALIZED_RECORD_METHODS: [&str; 2] = ["bloch_settlement", "bloch_getWithdrawalProof"];

/// While a level is closed, refuse every query at it instead of answering from a level this process can
/// no longer back with a follower status. Other tags and methods are untouched.
/// Call it last, so that it wraps every other handler.
fn refuse_closed_levels(module: &mut jsonrpsee::RpcModule<()>, closed: Arc<ClosedLevels>) -> Result<()> {
    fn refused() -> jsonrpsee::types::ErrorObjectOwned {
        jsonrpsee::types::ErrorObjectOwned::owned(
            -32001,
            "finality unavailable: this level is closed; see bloch_finality.status",
            None::<()>,
        )
    }
    let original: jsonrpsee::Methods = module.clone().into();
    let routes = TAGGED_METHODS.iter().map(|(name, position)| (*name, Some(*position))).chain(FINALIZED_RECORD_METHODS.map(|name| (name, None)));
    for (name, position) in routes {
        if module.remove_method(name).is_none() {
            continue;
        }
        let (original, closed) = (original.clone(), closed.clone());
        module.register_async_method(name, move |params, _, _| {
            let (original, closed) = (original.clone(), closed.clone());
            async move {
                let values: Vec<serde_json::Value> = if params.as_str().is_none() { vec![] } else { params.parse()? };
                let refuse = match position {
                    Some(position) => names_a_closed_level(&values, position, &closed),
                    None => closed.finalized.load(Ordering::Acquire),
                };
                if refuse {
                    return Err(refused());
                }
                original.call::<_, serde_json::Value>(name, values).await.map_err(|error| match error {
                    jsonrpsee::core::server::MethodsError::JsonRpc(object) => object,
                    other => rpc_error(other.to_string()),
                })
            }
        })?;
    }
    Ok(())
}

/// The `status` member of `bloch_finality`: state of the follower's file and, when known, its age.
fn status_signal(state: &str, written_at_unix: Option<u64>, schema: Option<&str>) -> serde_json::Value {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    serde_json::json!({
        "state": state,
        "written_at_unix": written_at_unix,
        "age_s": written_at_unix.map(|written| now.saturating_sub(written)),
        // Absent from a settled RPC of v2.1, which is how the monitor tells which limit applies.
        "schema": schema,
    })
}

/// What the follower's status proves against the local canonical chain.
struct Levels {
    finalized: Option<Header>,
    /// `None` when the status has no safe settlement or it is not local yet.
    safe: Option<Header>,
    /// The safe settlement contradicts the local chain or is below finalized: `safe` closes, `finalized` stands.
    safe_refused: Option<String>,
    /// The scalar facts of the status; its settlement lists are moved out.
    status: serde_json::Value,
    /// Settlements above the cursor passed in, already matched against the local chain.
    new_settlements: Vec<serde_json::Value>,
    /// Adopt this to acknowledge `new_settlements`.
    cursor: settlement_log::Cursor,
}

/// The highest L2 header proven final by the follower's verified status, if
/// every listed settlement matches the local canonical chain, and the safe
/// header the local native node reports.
fn verified_levels(
    status_path: &Path,
    network: &str,
    chain_id: u64,
    provider: &BlochBlockchainProvider,
    cursor: &settlement_log::Cursor,
    refused_log: &mut Option<(String, String)>,
) -> Result<Option<Levels>> {
    let size = match std::fs::metadata(status_path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ensure!(size <= settlement_log::MAX_STATUS_V2_BYTES, "finality status too large");
    let bytes = match std::fs::read(status_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut status: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(
        status["schema"] != settlement_log::STATUS_V3 || bytes.len() as u64 <= settlement_log::MAX_STATUS_V3_BYTES,
        "finality status too large"
    );
    drop(bytes);
    ensure!(
        status["schema"] == settlement_log::STATUS_V2 || status["schema"] == settlement_log::STATUS_V3,
        "unexpected status schema"
    );
    ensure!(status["network"] == network, "status is for another native network");
    ensure!(status["production_finality"] == false, "status claims production finality");
    let written_at = status["written_at_unix"].as_u64();
    let schema = status["schema"].as_str().map(str::to_owned);
    // A tip this database has not reached advances nothing, so a syncing RPC does not reread the log at each poll.
    if let Some(tip) = settlement_log::tip_number(&status) {
        if provider.sealed_header(tip)?.is_none() {
            return Err(NotLocalYet { number: tip, written_at, schema }.into());
        }
    }
    // A log read from its start and refused is not read again until it or its status changes.
    let identity = if cursor.reads_from_start() { settlement_log::log_identity(status_path, &status) } else { None };
    if let (Some(identity), Some((seen, why))) = (&identity, &*refused_log) {
        if identity == seen {
            bail!("{why}");
        }
    }
    let delta = match settlement_log::read_delta(status_path, &mut status, cursor) {
        Ok(delta) => delta,
        Err(why) => {
            if let Some(identity) = identity {
                *refused_log = Some((identity, why.clone()));
            }
            bail!("{why}");
        }
    };
    *refused_log = None;
    let genesis = provider.sealed_header(0)?.ok_or_else(|| eyre::eyre!("local L2 genesis header missing"))?;
    let mut best = final_genesis(&status, chain_id, genesis.hash())?.then_some(genesis);
    // New entries once, then the newest ones at every poll: a block hash commits to its parents, so
    // a tip that still matches the local chain covers the older blocks already matched.
    for entry in delta.entries.iter().chain(delta.recent.iter()) {
        let number = entry["l2_number"].as_u64().ok_or_else(|| eyre::eyre!("bad l2_number"))?;
        let hash: B256 = entry["l2_hash"].as_str().unwrap_or_default().parse()?;
        let local = provider
            .sealed_header(number)?
            .ok_or_else(|| NotLocalYet { number, written_at, schema: schema.clone() })?;
        ensure!(local.hash() == hash, "settled L2 block {number} differs from the local canonical header");
        best = Some(local);
    }
    let finalized_number = best.as_ref().map_or(0, |h: &Header| h.0.number);
    let mut safe_refused = None;
    let safe = match status.get("safe_settlement").filter(|v| !v.is_null()) {
        None => None,
        Some(entry) => {
            let number = entry["l2_number"].as_u64().ok_or_else(|| eyre::eyre!("bad safe l2_number"))?;
            let hash: B256 = entry["l2_hash"].as_str().unwrap_or_default().parse()?;
            if number < finalized_number {
                safe_refused = Some(format!("safe settlement {number} is below finalized {finalized_number}"));
                None
            } else {
                match provider.sealed_header(number)? {
                    // Not produced locally yet: keep the previous safe level.
                    None => None,
                    Some(local) if local.hash() == hash => Some(local),
                    Some(_) => {
                        safe_refused = Some(format!("safe L2 block {number} differs from the local canonical header"));
                        None
                    }
                }
            }
        }
    };
    Ok(Some(Levels { finalized: best, safe, safe_refused, status, new_settlements: delta.entries, cursor: delta.cursor }))
}

/// Whether the status proves the local L2 genesis final: the follower reports
/// `l2_genesis.finalized` once the native block that installed the L2 with this
/// genesis (`initial_l2_parent`) is inside its verified finalized prefix. A
/// status for another chain id or another L2 genesis is refused.
fn final_genesis(status: &serde_json::Value, chain_id: u64, local_genesis: B256) -> Result<bool> {
    if let Some(id) = status.get("chain_id").filter(|v| !v.is_null()) {
        ensure!(id.as_u64() == Some(chain_id), "status is for chain id {id}, this RPC serves {chain_id}");
    }
    let Some(genesis) = status.get("l2_genesis").filter(|v| !v.is_null()) else { return Ok(false) };
    let hash: B256 = genesis["hash"].as_str().unwrap_or_default().parse()?;
    ensure!(hash == local_genesis, "the native L2 genesis {hash} differs from the local genesis {local_genesis}");
    Ok(genesis["finalized"] == true)
}

fn level_json(header: &Option<Header>) -> serde_json::Value {
    header.as_ref().map_or(serde_json::Value::Null, |h| {
        serde_json::json!({"number": format!("0x{:x}", h.0.number), "hash": h.hash()})
    })
}

/// `net_*` and `web3_*`, which wallets (MetaMask's network check calls
/// `net_version`) and libraries query besides `eth_chainId`. The node has no
/// peers: the settled RPC serves one operator's canonical chain.
fn net_web3_rpc(chain_id: u64) -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    let version = chain_id.to_string();
    module
        .register_method("net_version", move |_, _, _| Ok::<_, jsonrpsee::types::ErrorObjectOwned>(version.clone()))
        .expect("unique");
    module.register_method("net_listening", |_, _, _| Ok::<_, jsonrpsee::types::ErrorObjectOwned>(true)).expect("unique");
    module.register_method("net_peerCount", |_, _, _| Ok::<_, jsonrpsee::types::ErrorObjectOwned>("0x0")).expect("unique");
    module
        .register_method("web3_clientVersion", |_, _, _| {
            Ok::<_, jsonrpsee::types::ErrorObjectOwned>(concat!("bloch-l2-settled-rpc/v", env!("CARGO_PKG_VERSION")))
        })
        .expect("unique");
    module
        .register_method("web3_sha3", |params, _, _| {
            let data: alloy_primitives::Bytes = params.one()?;
            Ok::<_, jsonrpsee::types::ErrorObjectOwned>(alloy_primitives::keccak256(&data))
        })
        .expect("unique");
    module
}

/// Verified finalized settlements by L2 number (only entries `verified_levels`
/// already matched against the local canonical chain).
type SettlementIndex = std::collections::BTreeMap<u64, Box<str>>;

/// The public fields of one finalized settlement as compact JSON (a small string per
/// settlement, not a parsed document: the index holds the whole history).
fn public_settlement(entry: &serde_json::Value) -> Option<(u64, Box<str>)> {
    let number = entry["l2_number"].as_u64()?;
    let mut out = serde_json::Map::new();
    for key in ["l2_number", "l2_hash", "l2_state_root", "commitment", "native_slot", "native_block", "withdrawals"] {
        out.insert(key.into(), entry.get(key).cloned().unwrap_or(serde_json::Value::Null));
    }
    out.insert("finalized".into(), true.into());
    Some((number, serde_json::Value::Object(out).to_string().into_boxed_str()))
}

/// `bloch_settlement(number)`: the native L1 settlement that finalized L2 block
/// `number` (hex quantity or integer), or `null` when it is not (yet) inside
/// the verified finalized prefix.
fn settlement_rpc(index: Arc<std::sync::RwLock<SettlementIndex>>) -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("bloch_settlement", move |params, _, _| {
            let value: serde_json::Value = params.one()?;
            let number = match &value {
                serde_json::Value::Number(n) => n.as_u64(),
                serde_json::Value::String(text) => {
                    text.strip_prefix("0x").and_then(|hex| u64::from_str_radix(hex, 16).ok())
                }
                _ => None,
            }
            .ok_or_else(|| jsonrpsee::types::ErrorObjectOwned::owned(-32602, "block number must be a hex quantity or an integer", None::<()>))?;
            Ok::<_, jsonrpsee::types::ErrorObjectOwned>(
                index
                    .read()
                    .ok()
                    .and_then(|i| i.get(&number).and_then(|text| serde_json::from_str(text).ok()))
                    .unwrap_or(serde_json::Value::Null),
            )
        })
        .expect("the settlement method name is unique in a new module");
    module
}

/// `bloch_finality`: the L2 levels and their L1 anchors, named like the native
/// node's `getchaininfo` finality fields.
fn finality_rpc(view: Arc<std::sync::RwLock<serde_json::Value>>) -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("bloch_finality", move |_, _, _| {
            let mut answer = view.read().map(|v| v.clone()).unwrap_or_default();
            // The age at this call: the document is stored at each poll, and a poll can stop updating it.
            if let Some(written) = answer["status"]["written_at_unix"].as_u64() {
                answer["status"]["age_s"] = status_signal("", Some(written), None)["age_s"].clone();
            }
            Ok::<_, jsonrpsee::types::ErrorObjectOwned>(answer)
        })
        .expect("the finality method name is unique in a new module");
    module
}

/// Refresh the outbox counter at the head and index newly finalized blocks.
fn follow_withdrawals(
    proofs: &withdrawal_proofs::Shared,
    reader: &BlochBlockchainProvider,
    new_settlements: &[serde_json::Value],
    pending: &mut Vec<withdrawal_proofs::FinalEntry>,
) {
    use reth_provider::{ReceiptProvider, StateProviderFactory};
    use std::sync::atomic::Ordering;
    let counter = reader
        .latest()
        .and_then(|state| state.storage(proofs.outbox, B256::ZERO))
        .map(|slot| u64::try_from(slot.unwrap_or_default()).unwrap_or(u64::MAX));
    match counter {
        Ok(count) => proofs.latest_count.store(count, Ordering::Relaxed),
        Err(error) => println!("withdrawal proofs: outbox counter unavailable: {error}"),
    }
    let indexed = match proofs.index.read() {
        Ok(index) if !index.is_frozen() => index.indexed(),
        _ => return,
    };
    // Each settlement is read once, so one that cannot be parsed stops the index for good: a later
    // settlement cannot be applied without it.
    let after = pending.last().map_or(indexed, |entry: &withdrawal_proofs::FinalEntry| entry.number.max(indexed));
    match withdrawal_proofs::final_entries(new_settlements, after) {
        Ok(entries) => pending.extend(entries),
        Err(error) => {
            println!("withdrawal proofs FROZEN: unreadable finalized settlement: {error}");
            if let Ok(mut index) = proofs.index.write() {
                index.freeze(error);
            }
            return;
        }
    }
    if let Some(last) = pending.last() {
        proofs.finalized.store(last.number, Ordering::Relaxed);
    }
    let outbox = proofs.outbox;
    let result = proofs.catch_up(pending, |number| {
        let receipts = reader
            .receipts_by_block(number.into())
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("no receipts for finalized block {number}"))?;
        receipts
            .iter()
            .flat_map(|receipt| receipt.logs.iter())
            .filter_map(|log| bloch_l2_evm::withdrawal::Withdrawal::from_log(outbox, log))
            .map(|w| w.map_err(|e| format!("block {number}: {e}")))
            .collect()
    });
    if let Err(error) = result {
        let frozen = proofs.index.read().map_or(true, |index| index.is_frozen());
        println!("withdrawal proofs{}: {error}", if frozen { " FROZEN" } else { " not advanced" });
    }
    if let Ok(index) = proofs.index.read() {
        let done = index.indexed();
        pending.retain(|entry| entry.number > done);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = parse()?;
    let runtime = RuntimeBuilder::new(
        RuntimeConfig::default().with_tokio(TokioConfig::ExistingHandle(tokio::runtime::Handle::current())),
    )
    .build()?;
    create_view(&options.data_dir, &options.view_dir)?;
    // The rules, domain and genesis the settlement worker executed under
    // (bloch-l2-produce-dev writes devnet V3 blocks with ChainSpec::testnet_v3).
    let rules = || options.l2.rules.clone();
    let spec = Arc::new(options.l2.chain_spec()?);
    let factory: BlochProviderFactory = ProviderFactory::new(
        Arc::new(open_db_read_only(options.view_dir.join("db"), DatabaseArguments::default())?),
        spec.clone(),
        StaticFileProvider::read_only(options.view_dir.join("static"))?,
        RocksDBBuilder::new(options.view_dir.join("rocks")).with_default_tables().with_read_only(true).build()?,
        runtime.clone(),
    )?
    .with_read_only_sync(true);
    let provider: BlochBlockchainProvider = BlockchainProvider::new(factory.clone())?;
    let kernel = rules();
    let config = BlochEvmConfig::new(&kernel, spec.domain());
    let api = build_eth_api_with(
        RpcNodeCoreAdapter::new(
            provider.clone(),
            NoopTransactionPool::default(),
            NoopNetwork::default().with_chain_id(kernel.chain_id),
            config,
        ),
        runtime.clone(),
        PendingPolicy::LatestDerived,
    );
    let filter = EthFilter::new(api.clone(), reth_rpc_eth_types::EthConfig::default().filter_config(), runtime.clone());
    let mut module = api.into_rpc().remove_context();
    let spool = match &options.txpool {
        Some(pool) => {
            ensure!(std::fs::symlink_metadata(pool)?.is_dir(), "--txpool {} is not a directory", pool.display());
            let spool = Arc::new(Spool {
                spec: rules(),
                dir: pool.clone(),
                index: std::sync::Mutex::new(SpoolIndex::new()),
                limits: SpoolLimits { min_tip: options.min_tip, ..SPOOL_LIMITS },
            });
            // Replace the no-pool method of the read-only API with the spooling one.
            ensure!(module.remove_method("eth_sendRawTransaction").is_some(), "eth API lacks eth_sendRawTransaction");
            module.merge(sequencer_rpc(spool.clone(), factory.clone()))?;
            Some(spool)
        }
        None => None,
    };
    module.merge(filter.into_rpc())?;
    module.merge(chain_identity_rpc(spec.clone()))?;
    module.merge(net_web3_rpc(kernel.chain_id))?;
    module.merge(chain_status_rpc(spec.clone(), provider.clone()))?;
    let finality = Arc::new(std::sync::RwLock::new(serde_json::json!({
        "safe": null,
        "finalized": null,
        "finalized_height": null,
        "status": status_signal("starting", None, None),
    })));
    module.merge(finality_rpc(finality.clone()))?;
    let settlements = Arc::new(std::sync::RwLock::new(SettlementIndex::new()));
    module.merge(settlement_rpc(settlements.clone()))?;
    let withdrawal_proofs = kernel.withdrawal_outbox.map(|outbox| withdrawal_proofs::Shared::new(kernel.chain_id, outbox));
    if let Some(proofs) = &withdrawal_proofs {
        module.merge(withdrawal_proofs::rpc(proofs.clone()))?;
    }
    let mut proof_task: Option<tokio::task::JoinHandle<()>> = None;
    serve_pending_blocks_as_latest(&mut module)?;
    let served_head = Arc::new(AtomicU64::new(0));
    hide_blocks_above_head(&mut module, served_head.clone())?;
    if let Some(spool) = &spool {
        spool_pending_nonce(&mut module, spool.clone(), factory.clone())?;
    }
    floor_fee_suggestions(&mut module, options.min_tip, factory.clone(), rules())?;
    limit_simulations(&mut module, MAX_CONCURRENT_SIMULATIONS, SIMULATION_WAIT)?;
    let levels_closed = Arc::new(ClosedLevels::new(true));
    refuse_closed_levels(&mut module, levels_closed.clone())?;
    let server = start_http_rpc(module, options.port).await?;
    println!(
        "SETTLED L2 RPC (chain id {}) at {}; finality only from verified native FFG settlement; {}",
        kernel.chain_id,
        server.http_url().unwrap_or_default(),
        options.txpool.as_ref().map_or("transactions refused".to_string(), |p| format!("eth_sendRawTransaction spools to {}", p.display()))
    );
    let state = provider.canonical_in_memory_state();
    let mut head_number = u64::MAX;
    let mut finalized: Option<Header> = None;
    let mut safe: Option<Header> = None;
    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    let mut interval = tokio::time::interval(options.poll);
    let mut last_sweep = std::time::Instant::now();
    // Settlements are read once, so those the withdrawal index has not taken yet wait here.
    let mut settlement_cursor = settlement_log::Cursor::default();
    let mut refused_log = None;
    let mut closed_why: Option<String> = None;
    let mut safe_why: Option<String> = None;
    let mut lag_seen = None;
    let mut unindexed: Vec<serde_json::Value> = Vec::new();
    let withdrawal_pending = Arc::new(std::sync::Mutex::new(Vec::new()));
    let result: Result<()> = async {
        loop {
            tokio::select! {
                signal = &mut shutdown => { signal?; break; }
                _ = interval.tick() => {
                    let number = factory.best_block_number()?;
                    if number != head_number {
                        // The producer commits the block number before this read-only view can see the
                        // header. That is a moment of a write, not a fault: the next tick has it.
                        match factory.sealed_header(number)? {
                            None => println!("head block={number} not readable yet"),
                            Some(header) => {
                                state.set_canonical_head(header.clone());
                                served_head.store(number, Ordering::Release);
                                head_number = number;
                                println!("head block={} hash={}", number, header.hash());
                            }
                        }
                    }
                    if let Some(spool) = spool.as_ref().filter(|_| last_sweep.elapsed() >= SPOOL_SWEEP) {
                        last_sweep = std::time::Instant::now();
                        let (spool, factory) = (spool.clone(), factory.clone());
                        match tokio::task::spawn_blocking(move || spool.sweep(&factory)).await {
                            Ok(Ok(0)) => {}
                            Ok(Ok(evicted)) => println!("spool sweep evicted {evicted} stale entries"),
                            Ok(Err(error)) => println!("spool sweep failed: {error}"),
                            Err(error) => println!("spool sweep failed: {error}"),
                        }
                    }
                    let number_of = |h: &Option<Header>| h.as_ref().map_or(0, |h| h.0.number);
                    // Block 0 is a real level (the final L2 genesis): compare
                    // against "nothing published yet", not against number 0.
                    let above = |h: &Header, current: &Option<Header>| current.as_ref().is_none_or(|c| h.0.number > c.0.number);
                    let mut closing: Option<(&str, String)> = None;
                    match verified_levels(&options.status, &options.network, kernel.chain_id, &provider, &settlement_cursor, &mut refused_log) {
                        Ok(Some(levels)) => {
                            if closed_why.take().is_some() {
                                println!("finality status valid again; finalized reopened");
                            }
                            lag_seen = None;
                            if safe_why != levels.safe_refused {
                                match &levels.safe_refused {
                                    Some(why) => println!("safe closed, finalized stands: {why}"),
                                    None => println!("safe reopened"),
                                }
                                safe_why = levels.safe_refused.clone();
                            }
                            levels_closed.set(false, levels.safe_refused.is_some());
                            match levels.finalized {
                                Some(header) if above(&header, &finalized) => {
                                    state.set_finalized(header.clone());
                                    println!("finalized block={} hash={} (verified native FFG settlement)", header.0.number, header.hash());
                                    finalized = Some(header);
                                }
                                Some(header) if header.0.number < number_of(&finalized) => {
                                    println!("finality status regressed to {}; keeping {}", header.0.number, number_of(&finalized));
                                }
                                _ => {}
                            }
                            // safe follows the local node's accepted head, and is never below finalized.
                            let candidate = match levels.safe {
                                _ if levels.safe_refused.is_some() => None,
                                Some(h) if h.0.number >= number_of(&finalized) => Some(h),
                                _ => finalized.clone(),
                            };
                            match candidate {
                                Some(header) if above(&header, &safe) => {
                                    state.set_safe(header.clone());
                                    println!("safe block={} hash={} (settlement accepted on the native head)", header.0.number, header.hash());
                                    safe = Some(header);
                                }
                                Some(header) if header.0.number < number_of(&safe) => {
                                    println!("safe settlement regressed to {}; keeping {}", header.0.number, number_of(&safe));
                                }
                                _ => {}
                            }
                            let s = &levels.status;
                            settlements
                                .write()
                                .expect("settlement lock")
                                .extend(levels.new_settlements.iter().filter_map(public_settlement));
                            settlement_cursor = levels.cursor.clone();
                            if withdrawal_proofs.is_some() {
                                unindexed.extend(levels.new_settlements.iter().cloned());
                            }
                            if let Some(proofs) = withdrawal_proofs.as_ref().filter(|_| proof_task.as_ref().is_none_or(|t| t.is_finished())) {
                                proof_task = Some(tokio::task::spawn_blocking({
                                    let (proofs, reader, new, pending) =
                                        (proofs.clone(), provider.clone(), std::mem::take(&mut unindexed), withdrawal_pending.clone());
                                    move || {
                                        let mut pending = pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                                        follow_withdrawals(&proofs, &reader, &new, &mut pending)
                                    }
                                }));
                            }
                            let latest = factory.sealed_header(head_number)?;
                            *finality.write().expect("finality lock") = serde_json::json!({
                                "latest": level_json(&latest),
                                "safe": if levels.safe_refused.is_some() { serde_json::Value::Null } else { level_json(&safe) },
                                "finalized": level_json(&finalized),
                                "finalized_height": number_of(&finalized),
                                "l2_genesis": s["l2_genesis"],
                                "l1": {
                                    "finalized": {"epoch": s["native_finalized_epoch"], "root": s["native_finalized_block"],
                                                  "slot": s["native_finalized_slot"]},
                                    "verified_tip": s["verified_tip"], "verified_blocks": s["verified_blocks"],
                                    "safe_settlement": s["safe_settlement"],
                                },
                                "status": status_signal("ok", s["written_at_unix"].as_u64(), s["schema"].as_str()),
                                "trust": "finalized: native FFG replay from the pinned genesis; safe: the local native node's head; no checkpoint signatures",
                            });
                        }
                        Ok(None) if finalized.is_none() && safe.is_none() => {}
                        // The cursor and the settlement index stay: what was verified stays verified, closed
                        // readers are refused at the door, and a poll while closed costs what it costs while open.
                        Ok(None) => closing = Some(("missing", "file missing".to_string())),
                        Err(error) if closes_levels(&error) => closing = Some(("invalid", error.to_string())),
                        Err(error) => {
                            if let Some(lag) = error.downcast_ref::<NotLocalYet>() {
                                if lag_seen != Some(lag.number) {
                                    println!("finality not advanced: {error}");
                                    lag_seen = Some(lag.number);
                                }
                                let mut view = finality.write().expect("finality lock");
                                view["status"] = status_signal("lagging", lag.written_at, lag.schema.as_deref());
                                view["status"]["missing_settlement"] = lag.number.into();
                            } else {
                                println!("finality not advanced: {error}");
                            }
                        }
                    }
                    // Nothing already proven becomes false, but this process can no longer back it or show
                    // that it is current, so readers of these levels get an error rather than an old answer.
                    if let Some((state, why)) = closing {
                        if closed_why.as_deref() != Some(&why) {
                            println!("finality status {state}: {why}; safe and finalized closed");
                            closed_why = Some(why);
                        }
                        levels_closed.set(true, true);
                        *finality.write().expect("finality lock") = serde_json::json!({
                            "latest": level_json(&factory.sealed_header(head_number).ok().flatten()),
                            "safe": null,
                            "finalized": null,
                            "finalized_height": null,
                            "status": status_signal(state, None, None),
                        });
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    let _ = server.stop();
    if let Some(proofs) = &withdrawal_proofs {
        proofs.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(task) = proof_task {
        let _ = task.await;
    }
    let _ = std::fs::remove_dir_all(&options.view_dir);
    if !runtime.graceful_shutdown_with_timeout(Duration::from_secs(10)) {
        bail!("runtime graceful shutdown timed out");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Address, Signature, TxKind};
    use k256::ecdsa::SigningKey;

    #[test]
    fn only_queries_at_a_closed_level_are_refused() {
        use serde_json::json;
        let closed = ClosedLevels::new(true);
        let check = |v: serde_json::Value, at| names_a_closed_level(v.as_array().unwrap(), at, &closed);
        assert!(check(json!(["finalized", false]), Some(0)));
        assert!(check(json!(["safe", false]), Some(0)));
        assert!(check(json!(["0xabc", "finalized"]), Some(1)));
        assert!(check(json!(["0xabc", "0x0", "safe"]), Some(2)));
        assert!(check(json!(["0xabc", {"blockNumber": "finalized"}]), Some(1)));
        assert!(check(json!([{"fromBlock": "0x1", "toBlock": "finalized"}]), None));
        assert!(!check(json!(["latest", false]), Some(0)));
        assert!(!check(json!(["0x10", false]), Some(0)));
        assert!(!check(json!(["0xabc"]), Some(1)));
        assert!(!check(json!([{"fromBlock": "0x1", "toBlock": "latest"}]), None));
        closed.set(false, true);
        assert!(check(json!(["safe", false]), Some(0)));
        assert!(!check(json!(["finalized", false]), Some(0)));
    }

    #[tokio::test]
    async fn closed_levels_answer_an_error_and_reopen_one_at_a_time() {
        use serde_json::{json, Value};
        let mut module = jsonrpsee::RpcModule::new(());
        module
            .register_method("eth_getBlockByNumber", |params, _, _| {
                let values: Vec<Value> = params.parse()?;
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>(json!({"tag": values[0]}))
            })
            .unwrap();
        module.register_method("bloch_settlement", |_, _, _| Ok::<_, jsonrpsee::types::ErrorObjectOwned>(json!({"l2_number": 1}))).unwrap();
        let closed = Arc::new(ClosedLevels::new(true));
        refuse_closed_levels(&mut module, closed.clone()).unwrap();
        let ask = |tag: &'static str| {
            let module = module.clone();
            async move { module.call::<_, Value>("eth_getBlockByNumber", [json!(tag), json!(false)]).await }
        };
        let settlement = || {
            let module = module.clone();
            async move { module.call::<_, Value>("bloch_settlement", [json!(1)]).await }
        };
        assert!(ask("finalized").await.is_err(), "closed from the start");
        assert!(ask("safe").await.is_err());
        assert!(settlement().await.is_err());
        assert_eq!(ask("latest").await.unwrap(), json!({"tag": "latest"}));
        closed.set(false, true);
        assert_eq!(ask("finalized").await.unwrap(), json!({"tag": "finalized"}));
        assert!(ask("safe").await.is_err());
        assert!(settlement().await.is_ok());
        closed.set(false, false);
        assert_eq!(ask("safe").await.unwrap(), json!({"tag": "safe"}));
    }

    #[test]
    fn a_status_ahead_of_this_database_does_not_close_the_levels() {
        assert!(!closes_levels(&eyre::Report::new(NotLocalYet { number: 7, written_at: None, schema: None })));
        assert!(closes_levels(&eyre::eyre!("settled L2 block 7 differs from the local canonical header")));
    }

    #[test]
    fn the_status_signal_reports_state_and_age() {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let signal = status_signal("ok", Some(now - 100), Some("v3"));
        assert_eq!(signal["state"], "ok");
        assert!(signal["age_s"].as_u64().unwrap() >= 100);
        assert!(status_signal("missing", None, None)["age_s"].is_null());
    }

    fn spool(dir: &Path, spec: &ChainSpec, key: u8, nonce: u64) {
        let key = SigningKey::from_bytes((&[key; 32]).into()).unwrap();
        let tx = TxEip1559 {
            chain_id: spec.chain_id,
            nonce,
            to: TxKind::Call(Address::repeat_byte(9)),
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            ..Default::default()
        };
        let signature: Signature = key.sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap().into();
        let signed = TxEnvelope::from(tx.into_signed(signature));
        let name = format!("{}.tx", alloy_primitives::hex::encode(signed.tx_hash()));
        std::fs::write(dir.join(name), format!("{}\n", alloy_primitives::hex::encode(signed.encoded_2718()))).unwrap();
    }

    fn address(key: u8) -> Address {
        Address::from_public_key(SigningKey::from_bytes((&[key; 32]).into()).unwrap().verifying_key())
    }

    #[test]
    fn genesis_is_final_only_when_the_status_says_so_for_this_chain_and_genesis() {
        let local = B256::repeat_byte(0x63);
        let status = |chain: serde_json::Value, genesis: serde_json::Value| serde_json::json!({"chain_id": chain, "l2_genesis": genesis});
        let entry = |hash: B256, finalized: bool| serde_json::json!({"hash": alloy_primitives::hex::encode(hash), "finalized": finalized});
        // Older (devnet v2) statuses carry neither field.
        assert!(!final_genesis(&serde_json::json!({}), 700_770, local).unwrap());
        assert!(!final_genesis(&status(700_770.into(), serde_json::Value::Null), 700_770, local).unwrap());
        assert!(!final_genesis(&status(700_770.into(), entry(local, false)), 700_770, local).unwrap());
        assert!(final_genesis(&status(700_770.into(), entry(local, true)), 700_770, local).unwrap());
        assert!(final_genesis(&status(serde_json::Value::Null, entry(local, true)), 700_770, local).unwrap());
        assert!(final_genesis(&status(700_771.into(), entry(local, true)), 700_770, local).is_err());
        assert!(final_genesis(&status(700_770.into(), entry(B256::repeat_byte(1), true)), 700_770, local).is_err());
        assert!(final_genesis(&status(700_770.into(), serde_json::json!({"finalized": true})), 700_770, local).is_err());
    }

    #[tokio::test]
    async fn receipts_and_mined_transactions_wait_for_the_served_head() {
        let mut module = jsonrpsee::RpcModule::new(());
        for method in HEAD_BOUND_METHODS {
            module
                .register_method(method, |params, _, _| {
                    let hash: String = params.one()?;
                    Ok::<_, jsonrpsee::types::ErrorObjectOwned>(match hash.as_str() {
                        "unknown" => serde_json::Value::Null,
                        "pending" => serde_json::json!({"hash": "pending", "blockNumber": null}),
                        _ => serde_json::json!({"hash": hash, "blockNumber": "0x5"}),
                    })
                })
                .unwrap();
        }
        let head = Arc::new(AtomicU64::new(4));
        hide_blocks_above_head(&mut module, head.clone()).unwrap();
        for method in HEAD_BOUND_METHODS {
            let at: serde_json::Value = module.call(method, jsonrpsee::rpc_params!["mined"]).await.unwrap();
            assert!(at.is_null(), "{method} above the head");
            let unknown: serde_json::Value = module.call(method, jsonrpsee::rpc_params!["unknown"]).await.unwrap();
            assert!(unknown.is_null());
            let pending: serde_json::Value = module.call(method, jsonrpsee::rpc_params!["pending"]).await.unwrap();
            assert_eq!(pending["hash"], "pending");
        }
        head.store(5, Ordering::Release);
        for method in HEAD_BOUND_METHODS {
            let at: serde_json::Value = module.call(method, jsonrpsee::rpc_params!["mined"]).await.unwrap();
            assert_eq!(at["blockNumber"], "0x5", "{method} at the head");
        }
    }

    #[tokio::test]
    async fn net_and_web3_answer_like_an_ethereum_node() {
        let module = net_web3_rpc(700_770);
        let version: String = module.call("net_version", jsonrpsee::rpc_params![]).await.unwrap();
        assert_eq!(version, "700770");
        let listening: bool = module.call("net_listening", jsonrpsee::rpc_params![]).await.unwrap();
        assert!(listening);
        let peers: String = module.call("net_peerCount", jsonrpsee::rpc_params![]).await.unwrap();
        assert_eq!(peers, "0x0");
        let client: String = module.call("web3_clientVersion", jsonrpsee::rpc_params![]).await.unwrap();
        assert!(client.starts_with("bloch-l2-settled-rpc/v"));
        let hash: B256 = module.call("web3_sha3", jsonrpsee::rpc_params!["0x"]).await.unwrap();
        assert_eq!(hash, alloy_primitives::KECCAK256_EMPTY);
    }

    #[test]
    fn settlement_index_exposes_only_the_public_fields_of_finalized_entries() {
        let entry = serde_json::json!({"l2_number": 1, "l2_hash": "aa", "l2_state_root": "bb", "commitment": "cc",
            "native_slot": 187300, "native_block": "dd", "withdrawals": {"root": "ee", "count": 0}, "extra": 1});
        let (number, text) = public_settlement(&entry).unwrap();
        assert_eq!(number, 1);
        let public: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(public["native_slot"], 187300);
        assert_eq!(public["finalized"], true);
        assert!(public.get("extra").is_none());
        assert!(public_settlement(&serde_json::json!({"l2_number": "bad"})).is_none());
    }

    #[test]
    fn fee_suggestions_never_fall_below_the_minimum_tip() {
        let quantity = |text: &str| serde_json::Value::String(text.into());
        assert_eq!(floored_quantity(&quantity("0x1"), 256), quantity("0x100"));
        assert_eq!(floored_quantity(&quantity("0x200"), 256), quantity("0x200"));
        assert_eq!(floored_quantity(&serde_json::Value::Null, 256), serde_json::Value::Null);
        let mut history = serde_json::json!({"baseFeePerGas": ["0x1"], "reward": [["0x0", "0x200"], ["0x1"]]});
        floor_rewards(&mut history, 256);
        assert_eq!(history["reward"], serde_json::json!([["0x100", "0x200"], ["0x100"]]));
        assert_eq!(history["baseFeePerGas"], serde_json::json!(["0x1"]));
        let mut none = serde_json::json!({"baseFeePerGas": ["0x1"], "reward": null});
        floor_rewards(&mut none, 256);
        assert!(none["reward"].is_null());
    }

    #[test]
    fn the_spool_refuses_and_evicts_a_tip_below_the_minimum() {
        let limits = SpoolLimits { min_tip: 100_000_000, ..LIMITS };
        let meta = |max_fee: u128, priority: u128| SpoolMeta {
            sender: address(1),
            nonce: 0,
            max_fee,
            priority,
            cost: alloy_primitives::U256::ZERO,
        };
        let mut account = |_| (0, alloy_primitives::U256::MAX);
        let mut head = SpoolHead { account: &mut account, next_base_fee: 1_000, now: std::time::SystemTime::now() };
        let plan = |head: &mut SpoolHead<'_>, new: SpoolMeta| plan_admission(&[], &new, head, limits);
        // Zero tip, the tip one wei short, and a fee cap that leaves too little over the base fee.
        assert!(plan(&mut head, meta(GWEI, 0)).unwrap_err().contains("underpriced"));
        assert!(plan(&mut head, meta(GWEI, 99_999_999)).unwrap_err().contains("underpriced"));
        assert!(plan(&mut head, meta(100_000_999, GWEI)).unwrap_err().contains("underpriced"));
        // Exactly the minimum, in both forms; a legacy price pays price minus base fee.
        assert!(plan(&mut head, meta(GWEI, 100_000_000)).is_ok());
        assert!(plan(&mut head, meta(100_001_000, 100_000_000)).is_ok());
        assert!(plan(&mut head, meta(100_001_000, 100_001_000)).is_ok());
        assert!(plan(&mut head, meta(100_000_999, 100_000_999)).is_err());
        // An entry spooled before this rule goes at the next sweep.
        let now = std::time::SystemTime::now();
        let old = SpoolEntry {
            name: "a.tx".into(),
            meta: Some(meta(GWEI, 1)),
            modified: now,
            seen: std::time::Instant::now(),
            age_when_seen: Duration::ZERO,
        };
        assert_eq!(head.stale(&old, limits), Some("below the minimum tip"));
    }

    #[test]
    fn pending_nonce_counts_only_the_senders_consecutive_spool_entries() {
        let spec = ChainSpec::mainnet();
        let dir = tempfile::tempdir().unwrap();
        let index = std::sync::Mutex::new(SpoolIndex::new());
        let next = |sender, latest| spooled_next_nonce(&spec, dir.path(), &index, sender, latest).unwrap();
        assert_eq!(next(address(1), 5), 5);
        for nonce in [5, 6, 8] {
            spool(dir.path(), &spec, 1, nonce);
        }
        spool(dir.path(), &spec, 2, 0);
        // A transaction for another chain id never counts.
        spool(dir.path(), &ChainSpec::testnet_v3(), 1, 7);
        std::fs::write(dir.path().join("junk.tx"), "zz\n").unwrap();
        std::fs::write(dir.path().join(".partial"), "00\n").unwrap();
        assert_eq!(next(address(1), 5), 7, "5 and 6 are spooled, 7 is missing");
        assert_eq!(next(address(1), 4), 4, "a gap below the spool stays the next nonce");
        assert_eq!(next(address(2), 0), 1);
        assert_eq!(next(address(3), 9), 9);
        // The producer consumed nonce 5: the cache follows the directory.
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            let decoded = alloy_primitives::hex::decode(text.trim())
                .ok()
                .and_then(|raw| bloch_l2_evm::decode_signed_transaction(&spec, &raw).ok());
            if decoded.is_some_and(|tx| tx.sender() == address(1) && tx.environment().nonce == 5) {
                std::fs::remove_file(path).unwrap();
            }
        }
        assert_eq!(next(address(1), 6), 7);
        assert_eq!(next(address(1), 5), 5);
        assert_eq!(index.lock().unwrap().len(), 5);
    }

    fn signed(spec: &ChainSpec, key: u8, nonce: u64, max_fee: u128, value: u64) -> Vec<u8> {
        let key = SigningKey::from_bytes((&[key; 32]).into()).unwrap();
        let tx = TxEip1559 {
            chain_id: spec.chain_id,
            nonce,
            to: TxKind::Call(Address::repeat_byte(9)),
            gas_limit: 21_000,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: max_fee / 2,
            value: alloy_primitives::U256::from(value),
            ..Default::default()
        };
        let signature: Signature = key.sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap().into();
        TxEnvelope::from(tx.into_signed(signature)).encoded_2718()
    }

    fn meta(spec: &ChainSpec, key: u8, nonce: u64, max_fee: u128) -> SpoolMeta {
        SpoolMeta::of(&bloch_l2_evm::decode_signed_transaction(spec, &signed(spec, key, nonce, max_fee, 0)).unwrap())
    }

    #[test]
    fn a_forward_clock_step_does_not_expire_an_entry_seen_while_young() {
        let spec = ChainSpec::mainnet();
        let mut young = entry(&spec, "a.tx", 1, 0, 2 * GWEI);
        let mut account = |_| (0, alloy_primitives::U256::MAX);
        // The wall clock now reads 4 h later, though this process saw the entry a moment ago.
        let later = std::time::SystemTime::now() + Duration::from_secs(4 * 3_600);
        let mut head = SpoolHead { account: &mut account, next_base_fee: GWEI, now: later };
        assert_eq!(head.stale(&young, SPOOL_LIMITS), None);
        // Really held past the TTL by the monotonic clock: it expires.
        let ttl = SPOOL_LIMITS.ttl;
        if let Some(earlier) = std::time::Instant::now().checked_sub(ttl + Duration::from_secs(1)) {
            young.seen = earlier;
            assert_eq!(head.stale(&young, SPOOL_LIMITS), Some("expired"));
        }
    }

    /// Review round 4 (C10). An entry written under a clock that was ahead, held past the TTL by the monotonic
    /// clock after the clock came back.
    #[test]
    fn review_r4_a_backward_clock_step_does_not_hold_an_entry_past_the_ttl() {
        let spec = ChainSpec::mainnet();
        let ttl = SPOOL_LIMITS.ttl;
        let mut held = entry(&spec, "a.tx", 1, 0, 2 * GWEI);
        held.modified = std::time::SystemTime::now() + Duration::from_secs(30 * 24 * 3_600);
        let Some(earlier) = std::time::Instant::now().checked_sub(ttl + Duration::from_secs(1)) else { return };
        held.seen = earlier;
        let mut account = |_| (0, alloy_primitives::U256::MAX);
        let mut head = SpoolHead { account: &mut account, next_base_fee: GWEI, now: std::time::SystemTime::now() };
        assert_eq!(head.stale(&held, SPOOL_LIMITS), Some("expired"), "seen {:?} ago, TTL {ttl:?}", held.seen.elapsed());
    }

    #[test]
    fn a_sweep_removes_only_leftover_partial_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".abcd.partial"), "00\n").unwrap();
        std::fs::write(dir.path().join("keep.tx"), "00\n").unwrap();
        std::fs::write(dir.path().join("keep.partial"), "00\n").unwrap();
        remove_leftover_partials(dir.path());
        assert!(!dir.path().join(".abcd.partial").exists());
        assert!(dir.path().join("keep.tx").exists());
        assert!(dir.path().join("keep.partial").exists());
    }

    fn entry(spec: &ChainSpec, name: &str, key: u8, nonce: u64, max_fee: u128) -> SpoolEntry {
        SpoolEntry {
            name: name.into(),
            meta: Some(meta(spec, key, nonce, max_fee)),
            modified: std::time::SystemTime::now(),
            seen: std::time::Instant::now(),
            age_when_seen: Duration::ZERO,
        }
    }

    const GWEI: u128 = 1_000_000_000;
    const LIMITS: SpoolLimits = SpoolLimits {
        max_entries: 8,
        max_per_sender: 3,
        max_nonce_gap: 4,
        ttl: Duration::from_secs(600),
        replace_bump_percent: 10,
        max_tx_gas: 15_000_000,
        min_tip: 0,
    };

    /// Plan against head nonces/balances per key (absent: nonce 0, rich).
    fn plan(
        entries: &[SpoolEntry],
        new: &SpoolMeta,
        accounts: &[(u8, u64, u128)],
        base_fee: u128,
    ) -> Result<Vec<String>, String> {
        let table: std::collections::HashMap<Address, (u64, alloy_primitives::U256)> = accounts
            .iter()
            .map(|(key, nonce, balance)| (address(*key), (*nonce, alloy_primitives::U256::from(*balance))))
            .collect();
        let mut account = |a: Address| table.get(&a).copied().unwrap_or((0, alloy_primitives::U256::from(u128::MAX)));
        let mut head = SpoolHead { account: &mut account, next_base_fee: base_fee, now: std::time::SystemTime::now() };
        plan_admission(entries, new, &mut head, LIMITS)
            .map(|names| names.into_iter().map(|n| n.into_string().unwrap()).collect())
    }

    #[test]
    fn admission_checks_balance_nonce_window_and_base_fee_at_the_head() {
        let spec = ChainSpec::mainnet();
        let new = meta(&spec, 1, 5, 2 * GWEI);
        assert_eq!(new.cost, alloy_primitives::U256::from(21_000u128 * 2 * GWEI));
        assert_eq!(plan(&[], &new, &[(1, 5, 21_000 * 2 * GWEI)], GWEI), Ok(vec![]));
        let poor = plan(&[], &new, &[(1, 5, 21_000 * 2 * GWEI - 1)], GWEI).unwrap_err();
        assert!(poor.starts_with("insufficient funds"), "{poor}");
        // value counts too
        let costly = SpoolMeta::of(
            &bloch_l2_evm::decode_signed_transaction(&spec, &signed(&spec, 1, 5, 2 * GWEI, 1)).unwrap(),
        );
        assert!(plan(&[], &costly, &[(1, 5, 21_000 * 2 * GWEI)], GWEI).unwrap_err().starts_with("insufficient funds"));
        assert!(plan(&[], &new, &[(1, 6, u128::MAX)], GWEI).unwrap_err().starts_with("nonce too low"));
        assert_eq!(plan(&[], &meta(&spec, 1, 9, 2 * GWEI), &[(1, 5, u128::MAX)], GWEI), Ok(vec![]));
        assert!(plan(&[], &meta(&spec, 1, 10, 2 * GWEI), &[(1, 5, u128::MAX)], GWEI).unwrap_err().starts_with("nonce too high"));
        assert!(plan(&[], &new, &[(1, 5, u128::MAX)], 3 * GWEI).unwrap_err().contains("below the next base fee"));
    }

    #[test]
    fn a_sender_is_capped_and_replaces_only_with_a_fee_bump() {
        let spec = ChainSpec::mainnet();
        let mine: Vec<_> = (0..3).map(|n| entry(&spec, &format!("m{n}.tx"), 1, n, 2 * GWEI)).collect();
        let cap = plan(&mine, &meta(&spec, 1, 3, 2 * GWEI), &[], GWEI).unwrap_err();
        assert!(cap.starts_with("too many pending transactions"), "{cap}");
        // Another sender is not affected.
        assert_eq!(plan(&mine, &meta(&spec, 2, 0, 2 * GWEI), &[], GWEI), Ok(vec![]));
        // Same nonce: a <10% bump is refused, a 10% bump replaces the old file.
        let low = plan(&mine, &meta(&spec, 1, 1, 2 * GWEI + GWEI / 10), &[], GWEI).unwrap_err();
        assert!(low.starts_with("replacement transaction underpriced"), "{low}");
        assert_eq!(plan(&mine, &meta(&spec, 1, 1, 22 * GWEI / 10), &[], GWEI), Ok(vec!["m1.tx".into()]));
        // Entries whose nonce the head already used do not count and are evicted.
        assert_eq!(plan(&mine, &meta(&spec, 1, 3, 2 * GWEI), &[(1, 2, u128::MAX)], GWEI), Ok(vec!["m0.tx".into(), "m1.tx".into()]));
    }

    #[test]
    fn a_full_spool_evicts_stale_then_deferred_cheap_entries_or_refuses() {
        let spec = ChainSpec::mainnet();
        // Eight entries from eight senders (cap 8): key k at nonce 0, fee (k + 1) gwei.
        let mut full: Vec<_> = (10..18u8).map(|k| entry(&spec, &format!("k{k}.tx"), k, 0, u128::from(k - 8) * GWEI)).collect();
        // Full and nothing stale: a transaction paying no more than the cheapest is refused.
        assert_eq!(plan(&full, &meta(&spec, 1, 0, 2 * GWEI), &[], GWEI), Err("txpool full".into()));
        // A better-paying one displaces the cheapest (k10, 2 gwei).
        assert_eq!(plan(&full, &meta(&spec, 1, 0, 3 * GWEI), &[], GWEI), Ok(vec!["k10.tx".into()]));
        // An entry deferred behind a nonce gap goes first, even if it pays more.
        full[7] = entry(&spec, "gap.tx", 17, 2, 9 * GWEI);
        assert_eq!(plan(&full, &meta(&spec, 1, 0, 3 * GWEI), &[], GWEI), Ok(vec!["gap.tx".into()]));
        // Stale entries (used nonce, unfunded, underpriced, expired, undecodable) go without displacing anyone.
        full[0] = entry(&spec, "used.tx", 10, 0, 2 * GWEI);
        full[1] = entry(&spec, "poor.tx", 11, 0, 3 * GWEI);
        full[2].modified = std::time::SystemTime::now() - Duration::from_secs(601);
        full[2].age_when_seen = Duration::from_secs(601);
        full[3] = SpoolEntry {
            name: "junk.tx".into(),
            meta: None,
            modified: std::time::SystemTime::now(),
            seen: std::time::Instant::now(),
            age_when_seen: Duration::ZERO,
        };
        let evicted = plan(&full, &meta(&spec, 1, 0, 2 * GWEI), &[(10, 1, u128::MAX), (11, 0, 1)], GWEI).unwrap();
        assert_eq!(evicted, vec!["used.tx", "poor.tx", "k12.tx", "junk.tx"]);
        // Base fee above an entry's cap: underpriced, evicted under pressure.
        let cheap: Vec<_> = (10..18u8).map(|k| entry(&spec, &format!("c{k}.tx"), k, 0, 2 * GWEI)).collect();
        assert_eq!(plan(&cheap, &meta(&spec, 1, 0, 4 * GWEI), &[], 3 * GWEI).unwrap().len(), 8);
    }

    #[test]
    fn scan_skips_vanished_files_and_tracks_fees() {
        let spec = ChainSpec::mainnet();
        let dir = tempfile::tempdir().unwrap();
        let mut index = SpoolIndex::new();
        std::fs::write(dir.path().join("a.tx"), format!("{}\n", alloy_primitives::hex::encode(signed(&spec, 1, 0, 2 * GWEI, 0)))).unwrap();
        std::fs::write(dir.path().join("b.tx"), "zz\n").unwrap();
        std::fs::write(dir.path().join(".c.partial"), "00\n").unwrap();
        let mut entries = scan_spool(&spec, dir.path(), &mut index).unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].meta.unwrap().max_fee, 2 * GWEI);
        assert_eq!(entries[0].meta.unwrap().priority, GWEI);
        assert!(entries[1].meta.is_none());
        std::fs::remove_file(dir.path().join("a.tx")).unwrap();
        assert_eq!(scan_spool(&spec, dir.path(), &mut index).unwrap().len(), 1);
        assert_eq!(index.len(), 1);
        // Evicting a file the producer already removed is not an error.
        evict_spool(dir.path(), &["a.tx".into(), "b.tx".into()], "test");
        assert!(scan_spool(&spec, dir.path(), &mut index).unwrap().is_empty());
    }

    #[allow(clippy::too_many_arguments)]
    fn authenticated(
        spec: &ChainSpec,
        key: u8,
        nonce: u64,
        gas_limit: u64,
        max_fee: u128,
        priority: u128,
        to: TxKind,
        input: Vec<u8>,
    ) -> bloch_l2_evm::AuthenticatedTransaction {
        let key = SigningKey::from_bytes((&[key; 32]).into()).unwrap();
        let tx = TxEip1559 {
            chain_id: spec.chain_id,
            nonce,
            to,
            gas_limit,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: priority,
            input: input.into(),
            ..Default::default()
        };
        let signature: Signature = key.sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap().into();
        bloch_l2_evm::decode_signed_transaction(spec, &TxEnvelope::from(tx.into_signed(signature)).encoded_2718()).unwrap()
    }

    #[test]
    fn transactions_the_worker_can_never_include_are_refused() {
        let spec = ChainSpec::mainnet();
        let call = TxKind::Call(Address::repeat_byte(9));
        let check = |gas, max_fee, priority, to, input: Vec<u8>| {
            never_includable(&spec, &authenticated(&spec, 1, 0, gas, max_fee, priority, to, input), SPOOL_LIMITS)
        };
        assert_eq!(check(21_000, 2 * GWEI, GWEI, call, vec![]), None);
        assert_eq!(check(15_000_000, 2 * GWEI, GWEI, call, vec![]), None, "exactly the block budget");
        // Deferred by every block (15M budget) although below the 30M protocol limit.
        let above = check(15_000_001, 2 * GWEI, GWEI, call, vec![]).unwrap();
        assert!(above.starts_with("exceeds block gas limit"), "{above}");
        // Dropped by execution without a fee.
        let low = check(20_999, 2 * GWEI, GWEI, call, vec![]).unwrap();
        assert!(low.starts_with("intrinsic gas too low"), "{low}");
        let data = check(21_000, 2 * GWEI, GWEI, call, vec![1; 10]).unwrap();
        assert!(data.contains("needs 21160"), "16 gas per non-zero calldata byte: {data}");
        assert_eq!(check(21_160, 2 * GWEI, GWEI, call, vec![1; 10]), None);
        let create = check(21_000, 2 * GWEI, GWEI, TxKind::Create, vec![]).unwrap();
        assert!(create.contains("needs 53000"), "{create}");
        let tip = check(21_000, 2 * GWEI, 2 * GWEI + 1, call, vec![]).unwrap();
        assert!(tip.starts_with("max priority fee per gas higher"), "{tip}");
        let initcode = check(14_000_000, 2 * GWEI, GWEI, TxKind::Create, vec![0; 49_153]).unwrap();
        assert!(initcode.starts_with("max initcode size exceeded"), "{initcode}");
        // Larger than one DA batch (114,688 bytes with framing) yet under the 128 KiB envelope cap.
        let big = check(14_000_000, 2 * GWEI, GWEI, call, vec![0; 120 * 1024]).unwrap();
        assert!(big.starts_with("transaction too large"), "{big}");
        let fits = 114_688 - bloch_l2_evm::data_availability::da_framing_bytes(1);
        let near = authenticated(&spec, 1, 0, 14_000_000, 2 * GWEI, GWEI, call, vec![0; 110 * 1024]);
        assert!(near.raw().len() <= fits);
        assert_eq!(never_includable(&spec, &near, SPOOL_LIMITS), None);
    }

    #[test]
    fn a_sender_must_cover_all_its_spooled_entries_together() {
        let spec = ChainSpec::mainnet();
        let one = 21_000 * 2 * GWEI;
        let mine: Vec<_> = (0..2).map(|n| entry(&spec, &format!("m{n}.tx"), 1, n, 2 * GWEI)).collect();
        assert_eq!(plan(&mine, &meta(&spec, 1, 2, 2 * GWEI), &[(1, 0, 3 * one)], GWEI), Ok(vec![]));
        let over = plan(&mine, &meta(&spec, 1, 2, 2 * GWEI), &[(1, 0, 3 * one - 1)], GWEI).unwrap_err();
        assert!(over.starts_with("insufficient funds for this and the sender's pending"), "{over}");
        // A replacement is counted once: the old entry no longer counts.
        assert_eq!(plan(&mine, &meta(&spec, 1, 1, 22 * GWEI / 10), &[(1, 0, one + 21_000 * 22 * GWEI / 10)], GWEI), Ok(vec!["m1.tx".into()]));
        // Entries the head already consumed do not count.
        assert_eq!(plan(&mine, &meta(&spec, 1, 2, 2 * GWEI), &[(1, 1, 2 * one)], GWEI), Ok(vec!["m0.tx".into()]));
    }

    #[test]
    fn scan_stats_a_file_once_and_keeps_its_original_time() {
        let spec = ChainSpec::mainnet();
        let dir = tempfile::tempdir().unwrap();
        let mut index = SpoolIndex::new();
        let path = dir.path().join("old.tx");
        std::fs::write(&path, format!("{}\n", alloy_primitives::hex::encode(signed(&spec, 1, 0, 2 * GWEI, 0)))).unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(4 * 3_600);
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(old).unwrap();
        let entries = scan_spool(&spec, dir.path(), &mut index).unwrap();
        assert_eq!(entries[0].modified, old);
        // Later scans take the time from the index (an expired entry stays expired).
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(std::time::SystemTime::now()).unwrap();
        assert_eq!(scan_spool(&spec, dir.path(), &mut index).unwrap()[0].modified, old);
        let mut account = |_| (0, alloy_primitives::U256::MAX);
        let mut head = SpoolHead { account: &mut account, next_base_fee: GWEI, now: std::time::SystemTime::now() };
        assert_eq!(head.stale(&entries[0], SPOOL_LIMITS), Some("expired"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn simulations_share_a_bounded_number_of_permits() {
        let mut module = jsonrpsee::RpcModule::new(());
        module
            .register_async_method("eth_call", |_, _, _| async {
                tokio::time::sleep(Duration::from_millis(400)).await;
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>("0x")
            })
            .unwrap();
        module.register_method("eth_chainId", |_, _, _| Ok::<_, jsonrpsee::types::ErrorObjectOwned>("0xab162")).unwrap();
        limit_simulations(&mut module, 1, Duration::from_millis(100)).unwrap();
        let (first, second, other) = tokio::join!(
            module.call::<_, String>("eth_call", jsonrpsee::rpc_params![serde_json::json!({}), "latest"]),
            async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                module.call::<_, String>("eth_call", jsonrpsee::rpc_params![serde_json::json!({}), "latest"]).await
            },
            async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                module.call::<_, String>("eth_chainId", jsonrpsee::rpc_params![]).await
            },
        );
        assert_eq!(first.unwrap(), "0x");
        let busy = second.unwrap_err().to_string();
        assert!(busy.contains("too many concurrent EVM simulations"), "{busy}");
        assert_eq!(other.unwrap(), "0xab162", "methods outside the limiter are not gated");
        // Once the permit is free the next call runs.
        assert_eq!(module.call::<_, String>("eth_call", jsonrpsee::rpc_params![serde_json::json!({})]).await.unwrap(), "0x");
    }
}
