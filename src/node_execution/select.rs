// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic selection of pending signed transactions for one V2 block.
//!
//! The selector runs the SAME incremental kernel as block execution
//! ([`crate::executor::BlockSession`] with the V2 parent rules), so every
//! transaction it returns is valid in that order on that parent: the caller can
//! hand the list to the executor unchanged. It never decides deposits; the
//! trusted deposit list is minted first, exactly as execution does, so a sender
//! funded by a deposit in this block may already spend it.
//!
//! Ordering is a function of the candidate SET, not of arrival order: each
//! sender's candidates run in nonce order, and among the next candidate of every
//! sender the one paying the highest effective priority fee goes first, ties
//! broken by the lowest transaction hash.
//!
//! Every candidate ends in exactly one of three lists:
//! * `transactions` — included, in block order;
//! * `deferred` — valid-looking but not includable now (block limits, a nonce
//!   gap, a fee cap below the base fee): leave it in the pool for a later block;
//! * `dropped` — can never become valid (bad encoding/signature/chain, already
//!   used nonce, duplicate, or refused by execution): remove it, with a reason.
//!
//! A selection also always fits one native DA batch
//! ([`crate::data_availability::MAX_DA_PAYLOAD_BYTES`], framing included): a
//! block whose user transactions could not be published on L1 could never
//! settle under settlement V3 (M3).
//!
//! This is development block production, not a fee market or a Reth pool.

use crate::{
    data_availability::{da_framing_bytes, MAX_DA_PAYLOAD_BYTES},
    executor::BlockSession,
    transactions::{decode_signed_transaction, TransactionAuthError, MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS},
    BlockContext, BlockExecutionError, ChainSpec, DepositMint,
};
use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::{String, ToString},
    vec::Vec,
};
use alloy_primitives::{Address, Bytes, B256};
use revm::{context::TxEnv, database::CacheDB, DatabaseRef};

/// Per-block production limits. Each is clamped to the protocol bound
/// (`spec.gas_limit`, [`MAX_SIGNED_BLOCK_BYTES`], [`MAX_SIGNED_TRANSACTIONS`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectionLimits {
    /// Maximum sum of the declared `gas_limit` of selected user transactions.
    /// Declared (not used) gas keeps the decision independent of execution.
    pub max_gas: u64,
    /// Maximum sum of encoded (EIP-2718) transaction bytes.
    pub max_bytes: usize,
    /// Maximum number of user transactions.
    pub max_transactions: usize,
}

impl SelectionLimits {
    /// The protocol maxima for `spec`.
    pub fn protocol(spec: &ChainSpec) -> Self {
        Self {
            max_gas: spec.gas_limit,
            max_bytes: MAX_SIGNED_BLOCK_BYTES,
            max_transactions: MAX_SIGNED_TRANSACTIONS,
        }
    }

    /// These limits clamped to the protocol maxima.
    pub fn clamp(self, spec: &ChainSpec) -> Self {
        let protocol = Self::protocol(spec);
        Self {
            max_gas: self.max_gas.min(protocol.max_gas),
            max_bytes: self.max_bytes.min(protocol.max_bytes),
            max_transactions: self.max_transactions.min(protocol.max_transactions),
        }
    }
}

/// Why a candidate stays in the pool for a later block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferReason {
    /// Its declared gas does not fit the remaining block gas budget.
    GasLimit,
    /// Its encoded bytes do not fit the remaining byte budget.
    ByteLimit,
    /// The block already holds the maximum number of transactions.
    CountLimit,
    /// Its nonce is above the sender's next nonce.
    NonceGap,
    /// Its fee cap is below this block's base fee.
    FeeBelowBaseFee,
    /// An earlier nonce of the same sender was deferred or dropped.
    SenderBlocked,
}

impl DeferReason {
    /// Stable machine-readable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GasLimit => "gas-limit",
            Self::ByteLimit => "byte-limit",
            Self::CountLimit => "count-limit",
            Self::NonceGap => "nonce-gap",
            Self::FeeBelowBaseFee => "fee-below-base-fee",
            Self::SenderBlocked => "sender-blocked",
        }
    }
}

/// Why a candidate is removed from the pool for good.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// Encoding, replay domain or signature refused ([`decode_signed_transaction`]).
    Authentication(TransactionAuthError),
    /// The same transaction hash appeared earlier in the candidate list.
    Duplicate,
    /// The sender's nonce has already passed this transaction's nonce.
    NonceTooLow {
        /// Next nonce of the sender.
        expected: u64,
        /// Nonce of the transaction.
        got: u64,
    },
    /// Execution refused it (insufficient balance, intrinsic gas, gas above the
    /// protocol block limit, unsupported fields, ...). The kernel's message.
    Execution(String),
}

impl DropReason {
    /// Human-readable reason.
    pub fn describe(&self) -> String {
        match self {
            Self::Authentication(error) => alloc::format!("authentication: {error:?}"),
            Self::Duplicate => "duplicate".to_string(),
            Self::NonceTooLow { expected, got } => alloc::format!("nonce-too-low: expected {expected}, got {got}"),
            Self::Execution(detail) => alloc::format!("execution: {detail}"),
        }
    }
}

/// A candidate left in the pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeferredTransaction {
    /// Position in the caller's candidate list.
    pub index: usize,
    /// Transaction hash.
    pub hash: B256,
    /// Why it was not included.
    pub reason: DeferReason,
}

/// A candidate removed from the pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DroppedTransaction {
    /// Position in the caller's candidate list.
    pub index: usize,
    /// Transaction hash, when the bytes authenticated.
    pub hash: Option<B256>,
    /// Why it can never be included.
    pub reason: DropReason,
}

/// Result of [`select_node_transactions`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockSelection {
    /// One entry per included transaction, in block order (host builds only, see [`TxStats`]).
    #[cfg(feature = "std")]
    pub stats: Vec<TxStats>,
    /// Included signed envelopes, in block order.
    pub transactions: Vec<Bytes>,
    /// Hashes of `transactions`, in the same order.
    pub hashes: Vec<B256>,
    /// Sum of the declared gas limits of `transactions`.
    pub declared_gas: u64,
    /// Sum of the encoded sizes of `transactions`.
    pub bytes: usize,
    /// Candidates left for a later block, in candidate order.
    pub deferred: Vec<DeferredTransaction>,
    /// Candidates removed with a reason, in candidate order.
    pub dropped: Vec<DroppedTransaction>,
}

struct Candidate {
    index: usize,
    hash: B256,
    raw: Bytes,
    env: TxEnv,
}

impl Candidate {
    /// Priority fee per gas actually paid at `base_fee` (0 when the cap is below it).
    fn effective_tip(&self, base_fee: u64) -> u128 {
        let base = u128::from(base_fee);
        let cap = self.env.gas_price.saturating_sub(base);
        match self.env.gas_priority_fee {
            Some(priority) => priority.min(cap),
            None => cap,
        }
    }
}

/// Select, in deterministic order and within `limits`, the candidates that are
/// valid on the V2 parent committed in `db` (`previous_root`), after minting
/// `deposits`. `context` and `deposits` must be the exact values the block
/// will be executed with; a failure there is returned as an error, never
/// attributed to a candidate.
#[allow(clippy::too_many_arguments)]
pub fn select_node_transactions<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: DB,
    previous_root: B256,
    context: &BlockContext,
    deposits: &[DepositMint],
    candidates: &[Bytes],
    limits: SelectionLimits,
) -> Result<BlockSelection, BlockExecutionError> {
    let mut session = BlockSession::begin_with_header(spec, CacheDB::new(db), context, deposits, |db| {
        super::prepare_parent(spec, domain, db, previous_root, context)
    })?;
    select_in_session(spec, &mut session, context, candidates, limits)
}

/// CANDIDATE (forced inclusion): [`select_node_transactions`] after the forced
/// envelopes, which run first, right after the deposits, by the rule of
/// [`crate::forced_inclusion`] and outside `limits` (L1 bounds them). The
/// block body is the included forced envelopes, then the returned selection.
#[cfg(feature = "forced-inclusion")]
#[allow(clippy::too_many_arguments)]
pub fn select_node_transactions_after_forced<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: DB,
    previous_root: B256,
    context: &BlockContext,
    deposits: &[DepositMint],
    forced: &[crate::forced_inclusion::ForcedTransaction],
    candidates: &[Bytes],
    limits: SelectionLimits,
) -> Result<(crate::forced_inclusion::ForcedSelection, BlockSelection), BlockExecutionError> {
    let mut session = BlockSession::begin_with_header(spec, CacheDB::new(db), context, deposits, |db| {
        super::prepare_parent(spec, domain, db, previous_root, context)
    })?;
    let forced = if spec.forced_inclusion || !forced.is_empty() {
        if !spec.forced_inclusion {
            return Err(crate::forced_inclusion::ForcedRuleError::NotEnabled.into());
        }
        crate::forced_inclusion::run_forced(spec, &mut session, forced)?
    } else {
        Default::default()
    };
    let selection = select_in_session(spec, &mut session, context, candidates, limits)?;
    Ok((forced, selection))
}

fn select_in_session<DB: DatabaseRef>(
    spec: &ChainSpec,
    session: &mut BlockSession<DB>,
    context: &BlockContext,
    candidates: &[Bytes],
    limits: SelectionLimits,
) -> Result<BlockSelection, BlockExecutionError> {
    let limits = limits.clamp(spec);
    let mut selection = BlockSelection::default();

    // Authenticate and group by sender in nonce order (stable for equal nonces).
    let mut seen = BTreeSet::new();
    let mut queues: BTreeMap<Address, VecDeque<Candidate>> = BTreeMap::new();
    for (index, raw) in candidates.iter().enumerate() {
        match decode_signed_transaction(spec, raw) {
            Err(error) => selection.dropped.push(DroppedTransaction {
                index,
                hash: None,
                reason: DropReason::Authentication(error),
            }),
            Ok(tx) if !seen.insert(tx.hash()) => selection.dropped.push(DroppedTransaction {
                index,
                hash: Some(tx.hash()),
                reason: DropReason::Duplicate,
            }),
            Ok(tx) => queues.entry(tx.sender()).or_default().push_back(Candidate {
                index,
                hash: tx.hash(),
                raw: tx.raw().clone(),
                env: tx.environment().clone(),
            }),
        }
    }
    let base_fee = context.base_fee_per_gas;
    for queue in queues.values_mut() {
        queue.make_contiguous().sort_by(|a, b| {
            a.env
                .nonce
                .cmp(&b.env.nonce)
                .then(b.effective_tip(base_fee).cmp(&a.effective_tip(base_fee)))
                .then(a.hash.cmp(&b.hash))
        });
    }

    let defer_rest = |queue: &mut VecDeque<Candidate>, deferred: &mut Vec<DeferredTransaction>| {
        for rest in queue.drain(..) {
            deferred.push(DeferredTransaction {
                index: rest.index,
                hash: rest.hash,
                reason: DeferReason::SenderBlocked,
            });
        }
    };

    loop {
        // Best next candidate across senders: highest effective tip, then lowest hash.
        let Some(sender) = queues
            .iter()
            .filter_map(|(sender, queue)| queue.front().map(|c| (*sender, c.effective_tip(base_fee), c.hash)))
            .max_by(|a, b| a.1.cmp(&b.1).then(b.2.cmp(&a.2)))
            .map(|(sender, _, _)| sender)
        else {
            break;
        };
        let queue = queues.get_mut(&sender).expect("selected sender has a queue");
        let candidate = queue.pop_front().expect("selected queue is non-empty");
        let defer = |reason, queue: &mut VecDeque<Candidate>, deferred: &mut Vec<DeferredTransaction>| {
            deferred.push(DeferredTransaction {
                index: candidate.index,
                hash: candidate.hash,
                reason,
            });
            defer_rest(queue, deferred);
        };
        let expected = session.account_nonce(sender)?;
        if candidate.env.nonce < expected {
            selection.dropped.push(DroppedTransaction {
                index: candidate.index,
                hash: Some(candidate.hash),
                reason: DropReason::NonceTooLow {
                    expected,
                    got: candidate.env.nonce,
                },
            });
            continue;
        }
        if candidate.raw.len().saturating_add(da_framing_bytes(1)) > MAX_DA_PAYLOAD_BYTES {
            // No DA batch can ever carry it, so no settleable block can hold it.
            selection.dropped.push(DroppedTransaction {
                index: candidate.index,
                hash: Some(candidate.hash),
                reason: DropReason::Execution("larger than one L1 data-availability batch".to_string()),
            });
            defer_rest(queue, &mut selection.deferred);
            continue;
        }
        if candidate.env.gas_limit > spec.gas_limit {
            // No block can ever hold it.
            selection.dropped.push(DroppedTransaction {
                index: candidate.index,
                hash: Some(candidate.hash),
                reason: DropReason::Execution("gas limit above the protocol block gas limit".to_string()),
            });
            defer_rest(queue, &mut selection.deferred);
            continue;
        }
        // Remaining protocol block gas (deposits already charged) is enforced
        // by the session itself and reported as a gas-limit deferral.
        let reason = if candidate.env.nonce > expected {
            Some(DeferReason::NonceGap)
        } else if candidate.env.gas_price < u128::from(base_fee) {
            Some(DeferReason::FeeBelowBaseFee)
        } else if selection.transactions.len() >= limits.max_transactions {
            Some(DeferReason::CountLimit)
        } else if selection.declared_gas.saturating_add(candidate.env.gas_limit) > limits.max_gas {
            Some(DeferReason::GasLimit)
        } else if selection.bytes.saturating_add(candidate.raw.len()) > limits.max_bytes
            || selection
                .bytes
                .saturating_add(candidate.raw.len())
                .saturating_add(da_framing_bytes(selection.transactions.len() + 1))
                > MAX_DA_PAYLOAD_BYTES
        {
            Some(DeferReason::ByteLimit)
        } else {
            None
        };
        if let Some(reason) = reason {
            defer(reason, queue, &mut selection.deferred);
            continue;
        }
        #[cfg(feature = "std")]
        let (tip, before) = (candidate.effective_tip(base_fee), cached_storage(session.database()));
        match session.try_transaction(&candidate.env, |_| true) {
            Ok(_outcome) => {
                #[cfg(feature = "std")]
                {
                    let gas_used = _outcome.map_or(0, |outcome| outcome.gas_used);
                    let (fresh_slots, cleared_slots) = storage_growth(session.database(), &before)?;
                    selection.stats.push(TxStats {
                        hash: candidate.hash,
                        sender,
                        nonce: candidate.env.nonce,
                        gas_used,
                        effective_tip: tip,
                        fresh_slots,
                        cleared_slots,
                    });
                }
                selection.declared_gas += candidate.env.gas_limit;
                selection.bytes += candidate.raw.len();
                selection.hashes.push(candidate.hash);
                selection.transactions.push(candidate.raw);
            }
            Err(BlockExecutionError::BlockGasLimitExceeded { .. }) => {
                defer(DeferReason::GasLimit, queue, &mut selection.deferred);
            }
            Err(error) => {
                selection.dropped.push(DroppedTransaction {
                    index: candidate.index,
                    hash: Some(candidate.hash),
                    reason: DropReason::Execution(error.to_string()),
                });
                defer_rest(queue, &mut selection.deferred);
            }
        }
    }
    selection.deferred.sort_by_key(|d| d.index);
    selection.dropped.sort_by_key(|d| d.index);
    Ok(selection)
}

// Selection reports for a producer's policy (sequencer budget, write price). Host builds only (`std`): no block rule
// reads them, and keeping them out of the no_std guests keeps every settlement guest ELF byte-identical to a tree
// without them. Kept at the end of the file for the same reason.

/// What one included transaction did, for a producer's own policy. Reported only:
/// no block rule reads it, and replay never computes it.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxStats {
    /// Transaction hash.
    pub hash: B256,
    /// Recovered sender.
    pub sender: Address,
    /// The authenticated transaction nonce (host report only).
    pub nonce: u64,
    /// Gas actually used.
    pub gas_used: u64,
    /// Priority fee per gas paid at this block's base fee.
    pub effective_tip: u128,
    /// Non-zero storage slots this transaction added, per account.
    pub fresh_slots: Vec<(Address, u64)>,
    /// Non-zero storage slots this transaction cleared, per account.
    pub cleared_slots: Vec<(Address, u64)>,
}

#[cfg(feature = "std")]
type StorageView = BTreeMap<Address, BTreeMap<alloy_primitives::U256, alloy_primitives::U256>>;

#[cfg(feature = "std")]
fn cached_storage<DB>(db: &CacheDB<DB>) -> StorageView {
    db.cache
        .accounts
        .iter()
        .map(|(address, account)| (*address, account.storage.iter().map(|(k, v)| (*k, *v)).collect()))
        .collect()
}

/// Slots added and cleared since `before`, per account. A slot the block had not touched
/// yet has its value in the parent state.
#[cfg(feature = "std")]
#[allow(clippy::type_complexity)]
fn storage_growth<DB: DatabaseRef>(
    db: &CacheDB<DB>,
    before: &StorageView,
) -> Result<(Vec<(Address, u64)>, Vec<(Address, u64)>), BlockExecutionError> {
    let (mut fresh, mut cleared) = (Vec::new(), Vec::new());
    for (address, account) in &db.cache.accounts {
        let (mut added, mut removed) = (0u64, 0u64);
        let known = before.get(address);
        for (slot, value) in &account.storage {
            let previous = match known.and_then(|slots| slots.get(slot)) {
                Some(previous) => *previous,
                None => db
                    .db
                    .storage_ref(*address, *slot)
                    .map_err(|_| BlockExecutionError::Database {
                        detail: "parent storage read failed".to_string(),
                    })?,
            };
            match (previous.is_zero(), value.is_zero()) {
                (true, false) => added += 1,
                (false, true) => removed += 1,
                _ => {}
            }
        }
        if added > 0 {
            fresh.push((*address, added));
        }
        if removed > 0 {
            cleared.push((*address, removed));
        }
    }
    fresh.sort();
    cleared.sort();
    Ok((fresh, cleared))
}

/// An unsigned call, as the next transaction of `sender`, for [`quote_node_transaction`]. Host builds only.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteCall {
    /// The account that would sign it.
    pub sender: Address,
    /// `None` creates a contract.
    pub to: Option<Address>,
    /// Call data or init code.
    pub data: Bytes,
    /// Value sent.
    pub value: alloy_primitives::U256,
    /// Declared gas limit.
    pub gas_limit: u64,
    /// The sender's nonce in the parent state (the only nonce a single execution can speak for).
    pub nonce: u64,
    /// Fee cap per gas the sender must be able to pay for (`gas_limit` times this, plus `value`).
    pub max_fee_per_gas: u128,
}

/// What `call` would do as the only user transaction of the next block on the parent committed in `db`:
/// the same session, the same execution and the same new-slot count as [`select_node_transactions`] reports
/// for a signed candidate, without a signature. `Ok(Err(reason))` when it cannot execute (nonce, funds, block
/// gas, static validity). Read-only: nothing is persisted. Host builds only (`std`), kept at the end of the
/// file like the selection reports, so no settlement guest changes.
#[cfg(feature = "std")]
pub fn quote_node_transaction<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: DB,
    previous_root: B256,
    context: &BlockContext,
    call: &QuoteCall,
) -> Result<Result<TxStats, String>, BlockExecutionError> {
    let base = u128::from(context.base_fee_per_gas);
    let Ok(env) = TxEnv::builder()
        .caller(call.sender)
        .kind(match call.to {
            Some(to) => revm::primitives::TxKind::Call(to),
            None => revm::primitives::TxKind::Create,
        })
        .data(call.data.clone())
        .value(call.value)
        .gas_limit(call.gas_limit)
        .max_fee_per_gas(call.max_fee_per_gas)
        .gas_priority_fee(Some(call.max_fee_per_gas.saturating_sub(base)))
        .nonce(call.nonce)
        .chain_id(Some(spec.chain_id))
        .build()
    else {
        return Ok(Err("the call is not a valid EIP-1559 transaction".to_string()));
    };
    if call.max_fee_per_gas < base {
        return Ok(Err("fee cap below the next base fee".to_string()));
    }
    let mut session = BlockSession::begin_with_header(spec, CacheDB::new(db), context, &[], |db| {
        super::prepare_parent(spec, domain, db, previous_root, context)
    })?;
    let before = cached_storage(session.database());
    let gas_used = match session.try_transaction(&env, |_| true) {
        Ok(outcome) => outcome.map_or(0, |outcome| outcome.gas_used),
        Err(BlockExecutionError::Database { detail }) => return Err(BlockExecutionError::Database { detail }),
        Err(error) => return Ok(Err(error.to_string())),
    };
    let (fresh_slots, cleared_slots) = storage_growth(session.database(), &before)?;
    Ok(Ok(TxStats {
        hash: B256::ZERO,
        sender: call.sender,
        nonce: call.nonce,
        gas_used,
        effective_tip: call.max_fee_per_gas.saturating_sub(base),
        fresh_slots,
        cleared_slots,
    }))
}

/// The producer's write price (sequencer policy v2), for [`select_node_transactions_priced`]. Host builds only.
///
/// The rule it is built on (agents/311 section 14): what a sender can claim for free (tip, gas limit, queued
/// nonces) buys nothing; every allowance is bought with fees really paid (`credits`) and consumed by waste.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct WritePrice {
    /// Wei owed per storage slot a transaction adds: it must hold `gas_used * effective_tip >= slots * per_slot`.
    pub per_slot: u128,
    /// Senders that owe no write price.
    pub exempt: BTreeSet<Address>,
    /// Per sender: priority fees it really paid, less the fee value of its work that was executed and left out
    /// (the policy's ledger). A transaction is covered when this is at least `gas_limit * its tip`.
    pub credits: BTreeMap<Address, u128>,
    /// No transaction above this gas limit is executed (the policy's per-transaction cap).
    pub max_tx_gas: u64,
    /// Gas of covered transactions that may be executed and then left out; past it no covered transaction but a
    /// plain transfer is executed.
    pub covered_allowance: u64,
    /// The same for uncovered transactions: their own pool.
    pub uncovered_allowance: u64,
    /// No uncovered transaction above this gas limit is executed, unless it is a plain transfer.
    pub uncovered_max_gas: u64,
    /// Seed of the order of uncovered senders' calls: a value the settler draws per block plan and publishes only
    /// with the block, so no sender can know its place before it submits (review R308-5P-3).
    pub seed: B256,
    /// Part of the block kept for senders without credit: covered transactions go first only while they leave
    /// `1/reserve_divisor` of the block's gas, bytes and places free; then the uncovered ones; then the covered
    /// ones that are left, so room the uncovered did not use goes back (review R308-5P-1). 0: no reserve.
    pub reserve_divisor: u64,
}

#[cfg(feature = "std")]
impl WritePrice {
    fn covers(&self, sender: Address, gas_limit: u64, tip: u128) -> bool {
        self.exempt.contains(&sender)
            || alloy_primitives::U256::from(self.credits.get(&sender).copied().unwrap_or(0))
                >= alloy_primitives::U256::from(gas_limit) * alloy_primitives::U256::from(tip.max(1))
    }

    fn pays(&self, sender: Address, gas_used: u64, tip: u128, fresh: u64) -> bool {
        fresh == 0
            || self.exempt.contains(&sender)
            || alloy_primitives::U256::from(gas_used) * alloy_primitives::U256::from(tip)
                >= alloy_primitives::U256::from(fresh) * alloy_primitives::U256::from(self.per_slot)
    }

    /// Place of an uncovered sender in this block: senders with any credit left (they paid fees and have not
    /// wasted them) before senders with none, and inside each group a hash of the block's seed and the sender.
    /// Tip plays no part. A key that was only funded has no credit: the fee of its funding went to the funder.
    fn rank(&self, sender: Address) -> u128 {
        let mut input = [0u8; 52];
        input[..32].copy_from_slice(self.seed.as_slice());
        input[32..].copy_from_slice(sender.as_slice());
        let place = u128::from_be_bytes(alloy_primitives::keccak256(input)[..16].try_into().expect("16 bytes")) >> 1;
        if self.credits.get(&sender).is_some_and(|credit| *credit > 0) {
            place | 1 << 127
        } else {
            place
        }
    }
}

/// A transaction left out for the write price.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnpaidTransaction {
    /// Transaction hash.
    pub hash: B256,
    /// Recovered sender.
    pub sender: Address,
    /// Its nonce.
    pub nonce: u64,
    /// Gas its execution used before its changes were dropped.
    pub gas_used: u64,
    /// Priority fee per gas it offered at this block's base fee.
    pub effective_tip: u128,
    /// Storage slots it would have added.
    pub fresh_slots: u64,
    /// Whether its sender's credit covered it.
    pub covered: bool,
    /// Whether it is unpaid on the block's start state too (its sender's own doing), or was made unpaid by an
    /// earlier transaction of this block.
    pub own_doing: bool,
}

/// What a priced selection left out, besides the usual deferred and dropped lists.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct LeftUnpaid {
    /// Executed, would add slots it does not pay for, left out; in the order met.
    pub unpaid: Vec<UnpaidTransaction>,
    /// Not executed because the pool of wasted gas of its class was used up in this block; they stay pending.
    pub not_judged: Vec<B256>,
    /// Not executed because its gas limit is above the policy's cap per transaction (with its sender's later ones).
    pub over_gas_cap: Vec<B256>,
    /// Not executed because it is uncovered and above the gas limit of uncovered transactions (with its sender's
    /// later ones): its sender needs credit first.
    pub needs_credit: Vec<B256>,
    /// Gas spent on covered transactions in `unpaid`.
    pub wasted_covered: u64,
    /// Gas spent on uncovered transactions in `unpaid`.
    pub wasted_uncovered: u64,
}

/// [`select_node_transactions`] with the producer's write price judged inside the loop (reviews R308-3P-2 and
/// R308-4P-1): a transaction that would add storage slots it does not pay for is left out, its changes dropped,
/// and the selection goes on with the next candidate on the block WITHOUT it. One pass; a non-payer never
/// displaces a payer; wasted work is accounted per class and per sender. `forced` runs first when given.
/// `db` is read twice (the block, and each left-out transaction alone on the start state). Host builds only.
#[cfg(all(feature = "std", feature = "forced-inclusion"))]
#[allow(clippy::too_many_arguments)]
pub fn select_node_transactions_priced_after_forced<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: &DB,
    previous_root: B256,
    context: &BlockContext,
    deposits: &[DepositMint],
    forced: &[crate::forced_inclusion::ForcedTransaction],
    candidates: &[Bytes],
    limits: SelectionLimits,
    price: &WritePrice,
) -> Result<(crate::forced_inclusion::ForcedSelection, BlockSelection, LeftUnpaid), BlockExecutionError> {
    let mut session = BlockSession::begin_with_header(spec, CacheDB::new(db), context, deposits, |db| {
        super::prepare_parent(spec, domain, db, previous_root, context)
    })?;
    let forced = if spec.forced_inclusion || !forced.is_empty() {
        if !spec.forced_inclusion {
            return Err(crate::forced_inclusion::ForcedRuleError::NotEnabled.into());
        }
        crate::forced_inclusion::run_forced(spec, &mut session, forced)?
    } else {
        Default::default()
    };
    let mut alone = |env: &TxEnv| judged_alone(spec, domain, db, previous_root, context, deposits, env);
    let mut left = LeftUnpaid::default();
    let selection = select_priced_in_session(
        spec,
        &mut session,
        context,
        candidates,
        limits,
        price,
        &mut left,
        &mut alone,
    )?;
    Ok((forced, selection, left))
}

/// [`select_node_transactions_priced_after_forced`] without forced records.
#[cfg(feature = "std")]
#[allow(clippy::too_many_arguments)]
pub fn select_node_transactions_priced<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: &DB,
    previous_root: B256,
    context: &BlockContext,
    deposits: &[DepositMint],
    candidates: &[Bytes],
    limits: SelectionLimits,
    price: &WritePrice,
) -> Result<(BlockSelection, LeftUnpaid), BlockExecutionError> {
    let mut session = BlockSession::begin_with_header(spec, CacheDB::new(db), context, deposits, |db| {
        super::prepare_parent(spec, domain, db, previous_root, context)
    })?;
    let mut alone = |env: &TxEnv| judged_alone(spec, domain, db, previous_root, context, deposits, env);
    let mut left = LeftUnpaid::default();
    let selection = select_priced_in_session(
        spec,
        &mut session,
        context,
        candidates,
        limits,
        price,
        &mut left,
        &mut alone,
    )?;
    Ok((selection, left))
}

// One transaction alone, after the deposits, on the parent state: (gas used, slots added), or None when it cannot
// run there (a queued nonce, funds). Nothing is kept.
#[cfg(feature = "std")]
fn judged_alone<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: &DB,
    previous_root: B256,
    context: &BlockContext,
    deposits: &[DepositMint],
    env: &TxEnv,
) -> Result<Option<(u64, u64)>, BlockExecutionError> {
    let mut session = BlockSession::begin_with_header(spec, CacheDB::new(db), context, deposits, |db| {
        super::prepare_parent(spec, domain, db, previous_root, context)
    })?;
    let mut seen = None;
    match session.try_transaction_judged(env, |gas_used, fresh| {
        seen = Some((gas_used, fresh));
        false
    }) {
        Ok(_) => Ok(seen),
        Err(BlockExecutionError::Database { detail }) => Err(BlockExecutionError::Database { detail }),
        Err(_) => Ok(None),
    }
}

// The loop of `select_in_session`, with the write price judged before a transaction's changes land. A copy, not
// a change of that function: it is compiled into the settlement guests and must keep its bytes and line numbers.
#[cfg(feature = "std")]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn select_priced_in_session<DB: DatabaseRef>(
    spec: &ChainSpec,
    session: &mut BlockSession<DB>,
    context: &BlockContext,
    candidates: &[Bytes],
    limits: SelectionLimits,
    price: &WritePrice,
    left: &mut LeftUnpaid,
    alone: &mut dyn FnMut(&TxEnv) -> Result<Option<(u64, u64)>, BlockExecutionError>,
) -> Result<BlockSelection, BlockExecutionError> {
    let limits = limits.clamp(spec);
    let mut selection = BlockSelection::default();

    // Authenticate and group by sender in nonce order (stable for equal nonces).
    let mut seen = BTreeSet::new();
    let mut queues: BTreeMap<Address, VecDeque<Candidate>> = BTreeMap::new();
    for (index, raw) in candidates.iter().enumerate() {
        match decode_signed_transaction(spec, raw) {
            Err(error) => selection.dropped.push(DroppedTransaction {
                index,
                hash: None,
                reason: DropReason::Authentication(error),
            }),
            Ok(tx) if !seen.insert(tx.hash()) => selection.dropped.push(DroppedTransaction {
                index,
                hash: Some(tx.hash()),
                reason: DropReason::Duplicate,
            }),
            Ok(tx) => queues.entry(tx.sender()).or_default().push_back(Candidate {
                index,
                hash: tx.hash(),
                raw: tx.raw().clone(),
                env: tx.environment().clone(),
            }),
        }
    }
    let base_fee = context.base_fee_per_gas;
    for queue in queues.values_mut() {
        queue.make_contiguous().sort_by(|a, b| {
            a.env
                .nonce
                .cmp(&b.env.nonce)
                .then(b.effective_tip(base_fee).cmp(&a.effective_tip(base_fee)))
                .then(a.hash.cmp(&b.hash))
        });
    }

    let defer_rest = |queue: &mut VecDeque<Candidate>, deferred: &mut Vec<DeferredTransaction>| {
        for rest in queue.drain(..) {
            deferred.push(DeferredTransaction {
                index: rest.index,
                hash: rest.hash,
                reason: DeferReason::SenderBlocked,
            });
        }
    };

    // The block's room is counted in gas really used by what is included; a candidate needs its whole gas limit
    // to fit in what is left, as on any EVM chain. Declared gas that is not used takes nobody's place (R308-5P-1).
    let mut used_gas = 0u64;
    loop {
        // Next candidate across senders: by class, then by the class's key, then lowest hash.
        let Some(sender) = queues
            .iter()
            .filter_map(|(sender, queue)| queue.front().map(|c| (*sender, c.effective_tip(base_fee), c.hash)))
            .map(|(sender, tip, hash)| {
                // Order of classes (reviews R308-4P-1, R308-5P-1): covered transactions by tip while they leave
                // the reserve free; then the plain transfers of uncovered senders by tip (a plain transfer is
                // never left out for the write price, so its bid is always paid: that is the fee market, and
                // the one door nobody can close without outbidding it); then the other uncovered transactions
                // in an order no claim can buy; then the covered ones that did not fit beside the reserve.
                let front = queues[&sender].front().expect("filtered on a front");
                let covered = price.covers(sender, front.env.gas_limit, tip);
                let (class, key) = if covered {
                    let kept = |total: u64| {
                        if price.reserve_divisor == 0 {
                            0
                        } else {
                            total / price.reserve_divisor
                        }
                    };
                    let beside_reserve = used_gas.saturating_add(front.env.gas_limit)
                        <= limits.max_gas - kept(limits.max_gas)
                        && (selection.bytes.saturating_add(front.raw.len()) as u64)
                            <= limits.max_bytes as u64 - kept(limits.max_bytes as u64)
                        && (selection.transactions.len() as u64)
                            < limits.max_transactions as u64 - kept(limits.max_transactions as u64);
                    (if beside_reserve { 3u8 } else { 0 }, tip)
                } else if front.env.gas_limit == 21_000 && front.env.data.is_empty() {
                    (2, tip)
                } else {
                    (1, price.rank(sender))
                };
                (sender, class, key, hash)
            })
            .max_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)).then(b.3.cmp(&a.3)))
            .map(|(sender, _, _, _)| sender)
        else {
            break;
        };
        let queue = queues.get_mut(&sender).expect("selected sender has a queue");
        let candidate = queue.pop_front().expect("selected queue is non-empty");
        let defer = |reason, queue: &mut VecDeque<Candidate>, deferred: &mut Vec<DeferredTransaction>| {
            deferred.push(DeferredTransaction {
                index: candidate.index,
                hash: candidate.hash,
                reason,
            });
            defer_rest(queue, deferred);
        };
        let expected = session.account_nonce(sender)?;
        if candidate.env.nonce < expected {
            selection.dropped.push(DroppedTransaction {
                index: candidate.index,
                hash: Some(candidate.hash),
                reason: DropReason::NonceTooLow {
                    expected,
                    got: candidate.env.nonce,
                },
            });
            continue;
        }
        if candidate.raw.len().saturating_add(da_framing_bytes(1)) > MAX_DA_PAYLOAD_BYTES {
            // No DA batch can ever carry it, so no settleable block can hold it.
            selection.dropped.push(DroppedTransaction {
                index: candidate.index,
                hash: Some(candidate.hash),
                reason: DropReason::Execution("larger than one L1 data-availability batch".to_string()),
            });
            defer_rest(queue, &mut selection.deferred);
            continue;
        }
        if candidate.env.gas_limit > spec.gas_limit {
            // No block can ever hold it.
            selection.dropped.push(DroppedTransaction {
                index: candidate.index,
                hash: Some(candidate.hash),
                reason: DropReason::Execution("gas limit above the protocol block gas limit".to_string()),
            });
            defer_rest(queue, &mut selection.deferred);
            continue;
        }
        // Remaining protocol block gas (deposits already charged) is enforced
        // by the session itself and reported as a gas-limit deferral.
        let reason = if candidate.env.nonce > expected {
            Some(DeferReason::NonceGap)
        } else if candidate.env.gas_price < u128::from(base_fee) {
            Some(DeferReason::FeeBelowBaseFee)
        } else if selection.transactions.len() >= limits.max_transactions {
            Some(DeferReason::CountLimit)
        } else if used_gas.saturating_add(candidate.env.gas_limit) > limits.max_gas {
            Some(DeferReason::GasLimit)
        } else if selection.bytes.saturating_add(candidate.raw.len()) > limits.max_bytes
            || selection
                .bytes
                .saturating_add(candidate.raw.len())
                .saturating_add(da_framing_bytes(selection.transactions.len() + 1))
                > MAX_DA_PAYLOAD_BYTES
        {
            Some(DeferReason::ByteLimit)
        } else {
            None
        };
        if let Some(reason) = reason {
            defer(reason, queue, &mut selection.deferred);
            continue;
        }
        let (tip, before) = (candidate.effective_tip(base_fee), cached_storage(session.database()));
        // What may be executed at all (review R308-4P-1). A plain transfer adds no slot whatever ran before it and
        // is always executed. Anything else: within the policy's gas cap; covered by its sender's credit, or small;
        // and only while a pool of wasted gas it may use has room. Uncovered senders never use the covered pool.
        let plain = candidate.env.gas_limit == 21_000 && candidate.env.data.is_empty();
        let covered = price.covers(sender, candidate.env.gas_limit, tip);
        // A covered transaction that finds the covered pool used up is judged by the rules of the uncovered class
        // instead (small, from the other pool), so paid-for waste ahead of it does not leave a small call unjudged.
        let from_covered_pool = covered && left.wasted_covered < price.covered_allowance;
        let unexecuted = if plain {
            None
        } else if candidate.env.gas_limit > price.max_tx_gas && !price.exempt.contains(&sender) {
            Some(&mut left.over_gas_cap)
        } else if from_covered_pool {
            None
        } else if candidate.env.gas_limit > price.uncovered_max_gas {
            Some(if covered {
                &mut left.not_judged
            } else {
                &mut left.needs_credit
            })
        } else if left.wasted_uncovered >= price.uncovered_allowance {
            Some(&mut left.not_judged)
        } else {
            None
        };
        if let Some(list) = unexecuted {
            list.push(candidate.hash);
            for rest in queue.drain(..) {
                list.push(rest.hash);
            }
            continue;
        }
        let mut refused = None;
        let attempt = session.try_transaction_judged(&candidate.env, |gas_used, fresh| {
            let pays = price.pays(sender, gas_used, tip, fresh);
            if !pays {
                refused = Some((gas_used, fresh));
            }
            pays
        });
        if let (Ok(None), Some((gas_used, fresh))) = (&attempt, refused) {
            // Left out, its changes dropped: the transactions behind it run on the block without it. Its sender's
            // later nonces cannot run in this block, so one sender wastes at most this once per block.
            if from_covered_pool {
                left.wasted_covered = left.wasted_covered.saturating_add(gas_used);
            } else {
                left.wasted_uncovered = left.wasted_uncovered.saturating_add(gas_used);
            }
            // Whose doing: judged once more alone on the block's start state. Paying there means an earlier
            // transaction of this block made it unpaid (review R308-4P-2). A queued nonce cannot run alone: its
            // sender's own earlier transactions are its own doing.
            let own_doing = match alone(&candidate.env)? {
                Some((alone_gas, alone_fresh)) => !price.pays(sender, alone_gas, tip, alone_fresh),
                None => true,
            };
            left.unpaid.push(UnpaidTransaction {
                hash: candidate.hash,
                sender,
                nonce: candidate.env.nonce,
                gas_used,
                effective_tip: tip,
                fresh_slots: fresh,
                covered,
                own_doing,
            });
            continue;
        }
        match attempt {
            Ok(_outcome) => {
                {
                    let gas_used = _outcome.map_or(0, |outcome| outcome.gas_used);
                    used_gas = used_gas.saturating_add(gas_used);
                    let (fresh_slots, cleared_slots) = storage_growth(session.database(), &before)?;
                    selection.stats.push(TxStats {
                        hash: candidate.hash,
                        sender,
                        nonce: candidate.env.nonce,
                        gas_used,
                        effective_tip: tip,
                        fresh_slots,
                        cleared_slots,
                    });
                }
                selection.declared_gas += candidate.env.gas_limit;
                selection.bytes += candidate.raw.len();
                selection.hashes.push(candidate.hash);
                selection.transactions.push(candidate.raw);
            }
            Err(BlockExecutionError::BlockGasLimitExceeded { .. }) => {
                defer(DeferReason::GasLimit, queue, &mut selection.deferred);
            }
            Err(error) => {
                selection.dropped.push(DroppedTransaction {
                    index: candidate.index,
                    hash: Some(candidate.hash),
                    reason: DropReason::Execution(error.to_string()),
                });
                defer_rest(queue, &mut selection.deferred);
            }
        }
    }
    selection.deferred.sort_by_key(|d| d.index);
    selection.dropped.sort_by_key(|d| d.index);
    Ok(selection)
}
