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
//! No checkpoint signature is involved. Neither level regresses; any
//! inconsistency freezes it and is logged. `bloch_finality` reports both with
//! their L1 anchors.
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

const USAGE: &str = "bloch-l2-settled-rpc --data-dir CANONICAL --view-dir NEW_DIR --finality-status FILE --network HEX [--port 8546] [--poll-ms 2000] [--rules v3|v2|mainnet [--domain HEX --genesis-time SECS]] [--txpool DIR]\n\
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
}

const SPOOL_LIMITS: SpoolLimits = SpoolLimits {
    max_entries: 4_096,
    max_per_sender: 16,
    max_nonce_gap: 16,
    ttl: Duration::from_secs(3 * 3_600),
    replace_bump_percent: 10,
    max_tx_gas: 15_000_000,
};
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
                "--genesis-time", "--txpool",
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
    /// Past the TTL by the wall clock, and confirmed by the monotonic clock for an entry this process
    /// saw while it was young: a forward clock step must not evict acknowledged transactions. An
    /// entry already past the TTL when first seen (after a restart) has only the wall clock to go by.
    fn expired(&self, entry: &SpoolEntry, ttl: Duration) -> bool {
        self.now.duration_since(entry.modified).is_ok_and(|age| age > ttl)
            && (entry.age_when_seen > ttl || entry.seen.elapsed() > ttl)
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

/// What the follower's status proves against the local canonical chain.
struct Levels {
    finalized: Option<Header>,
    /// `None` when the status has no safe settlement or it is not local yet.
    safe: Option<Header>,
    status: serde_json::Value,
}

/// The highest L2 header proven final by the follower's verified status, if
/// every listed settlement matches the local canonical chain, and the safe
/// header the local native node reports.
fn verified_levels(
    status_path: &Path,
    network: &str,
    chain_id: u64,
    provider: &BlochBlockchainProvider,
) -> Result<Option<Levels>> {
    let bytes = match std::fs::read(status_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ensure!(bytes.len() <= 16 * 1_048_576, "finality status too large");
    let status: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(status["schema"] == "bloch.l2.native-follower-status.v2", "unexpected status schema");
    ensure!(status["network"] == network, "status is for another native network");
    ensure!(status["production_finality"] == false, "status claims production finality");
    let settlements = status["finalized_settlements"].as_array().ok_or_else(|| eyre::eyre!("no settlement list"))?;
    let genesis = provider.sealed_header(0)?.ok_or_else(|| eyre::eyre!("local L2 genesis header missing"))?;
    let mut best = final_genesis(&status, chain_id, genesis.hash())?.then_some(genesis);
    let mut expected_number = 1u64;
    for entry in settlements {
        let number = entry["l2_number"].as_u64().ok_or_else(|| eyre::eyre!("bad l2_number"))?;
        let hash: B256 = entry["l2_hash"].as_str().unwrap_or_default().parse()?;
        ensure!(number == expected_number, "finalized settlements are not contiguous from block 1");
        expected_number += 1;
        let local = provider
            .sealed_header(number)?
            .ok_or_else(|| eyre::eyre!("settled L2 block {number} is not in the local canonical chain yet"))?;
        ensure!(local.hash() == hash, "settled L2 block {number} differs from the local canonical header");
        best = Some(local);
    }
    let finalized_number = best.as_ref().map_or(0, |h: &Header| h.0.number);
    let safe = match status.get("safe_settlement").filter(|v| !v.is_null()) {
        None => None,
        Some(entry) => {
            let number = entry["l2_number"].as_u64().ok_or_else(|| eyre::eyre!("bad safe l2_number"))?;
            let hash: B256 = entry["l2_hash"].as_str().unwrap_or_default().parse()?;
            ensure!(number >= finalized_number, "safe settlement {number} is below finalized {finalized_number}");
            match provider.sealed_header(number)? {
                // Not produced locally yet: keep the previous safe level.
                None => None,
                Some(local) => {
                    ensure!(local.hash() == hash, "safe L2 block {number} differs from the local canonical header");
                    Some(local)
                }
            }
        }
    };
    Ok(Some(Levels { finalized: best, safe, status }))
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
type SettlementIndex = std::collections::BTreeMap<u64, serde_json::Value>;

/// The public fields of each finalized settlement in a verified status.
fn settlement_index(status: &serde_json::Value) -> SettlementIndex {
    status["finalized_settlements"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let number = entry["l2_number"].as_u64()?;
            let mut out = serde_json::Map::new();
            for key in ["l2_number", "l2_hash", "l2_state_root", "commitment", "native_slot", "native_block", "withdrawals"] {
                out.insert(key.into(), entry.get(key).cloned().unwrap_or(serde_json::Value::Null));
            }
            out.insert("finalized".into(), true.into());
            Some((number, serde_json::Value::Object(out)))
        })
        .collect()
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
                index.read().ok().and_then(|i| i.get(&number).cloned()).unwrap_or(serde_json::Value::Null),
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
            Ok::<_, jsonrpsee::types::ErrorObjectOwned>(view.read().map(|v| v.clone()).unwrap_or_default())
        })
        .expect("the finality method name is unique in a new module");
    module
}

/// Refresh the outbox counter at the head and index newly finalized blocks.
fn follow_withdrawals(proofs: &withdrawal_proofs::Shared, reader: &BlochBlockchainProvider, status: &serde_json::Value) {
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
    let entries = match withdrawal_proofs::final_entries(status, indexed) {
        Ok(entries) => entries,
        Err(error) => {
            println!("withdrawal proofs: unreadable finality status: {error}");
            return;
        }
    };
    if let Some(last) = entries.last() {
        proofs.finalized.store(last.number, Ordering::Relaxed);
    }
    let outbox = proofs.outbox;
    let result = proofs.catch_up(&entries, |number| {
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
                limits: SPOOL_LIMITS,
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
    let finality = Arc::new(std::sync::RwLock::new(serde_json::Value::Null));
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
    limit_simulations(&mut module, MAX_CONCURRENT_SIMULATIONS, SIMULATION_WAIT)?;
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
    let result: Result<()> = async {
        loop {
            tokio::select! {
                signal = &mut shutdown => { signal?; break; }
                _ = interval.tick() => {
                    let number = factory.best_block_number()?;
                    if number != head_number {
                        let header = factory.sealed_header(number)?.ok_or_else(|| eyre::eyre!("head header missing"))?;
                        state.set_canonical_head(header.clone());
                        served_head.store(number, Ordering::Release);
                        head_number = number;
                        println!("head block={} hash={}", number, header.hash());
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
                    match verified_levels(&options.status, &options.network, kernel.chain_id, &provider) {
                        Ok(Some(levels)) => {
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
                            *settlements.write().expect("settlement lock") = settlement_index(s);
                            if let Some(proofs) = withdrawal_proofs.as_ref().filter(|_| proof_task.as_ref().is_none_or(|t| t.is_finished())) {
                                proof_task = Some(tokio::task::spawn_blocking({
                                    let (proofs, reader, status) = (proofs.clone(), provider.clone(), s.clone());
                                    move || follow_withdrawals(&proofs, &reader, &status)
                                }));
                            }
                            let latest = factory.sealed_header(head_number)?;
                            *finality.write().expect("finality lock") = serde_json::json!({
                                "latest": level_json(&latest),
                                "safe": level_json(&safe),
                                "finalized": level_json(&finalized),
                                "finalized_height": number_of(&finalized),
                                "l2_genesis": s["l2_genesis"],
                                "l1": {
                                    "finalized": {"epoch": s["native_finalized_epoch"], "root": s["native_finalized_block"],
                                                  "slot": s["native_finalized_slot"]},
                                    "verified_tip": s["verified_tip"], "verified_blocks": s["verified_blocks"],
                                    "safe_settlement": s["safe_settlement"],
                                },
                                "trust": "finalized: native FFG replay from the pinned genesis; safe: the local native node's head; no checkpoint signatures",
                            });
                        }
                        Ok(None) => {}
                        Err(error) => println!("finality not advanced: {error}"),
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
        let status = serde_json::json!({"finalized_settlements": [
            {"l2_number": 1, "l2_hash": "aa", "l2_state_root": "bb", "commitment": "cc", "native_slot": 187300,
             "native_block": "dd", "withdrawals": {"root": "ee", "count": 0}, "extra": 1},
            {"l2_number": "bad"},
        ]});
        let index = settlement_index(&status);
        assert_eq!(index.len(), 1);
        assert_eq!(index[&1]["native_slot"], 187300);
        assert_eq!(index[&1]["finalized"], true);
        assert!(index[&1].get("extra").is_none());
        assert!(settlement_index(&serde_json::json!({})).is_empty());
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
