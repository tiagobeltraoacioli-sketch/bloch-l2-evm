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
                        sender, nonce: candidate.env.nonce,
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
                    .map_err(|_| BlockExecutionError::Database { detail: "parent storage read failed".to_string() })?,
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
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct WritePrice {
    /// Wei owed per storage slot a transaction adds: it must hold `gas_used * effective_tip >= slots * per_slot`.
    pub per_slot: u128,
    /// Senders that owe no write price.
    pub exempt: BTreeSet<Address>,
    /// Senders with standing (they have paid before): selected ahead of every other sender, then by tip.
    pub standing: BTreeSet<Address>,
    /// Gas that may be spent executing transactions that are then left out; past it only plain transfers run.
    pub wasted_gas_allowance: u64,
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
}

/// What a priced selection left out, besides the usual deferred and dropped lists.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct LeftUnpaid {
    /// Executed, would add slots it does not pay for, left out; in the order met.
    pub unpaid: Vec<UnpaidTransaction>,
    /// Not executed because the allowance for non-payers was used up; they stay pending.
    pub not_judged: Vec<B256>,
    /// Gas spent on the transactions in `unpaid`.
    pub wasted_gas: u64,
    /// Whether the allowance ran out.
    pub exhausted: bool,
}

/// [`select_node_transactions`] with the producer's write price judged inside the loop (review R308-3P-2, the
/// remedy agents/304 named): a transaction that would add storage slots it does not pay for is left out, its
/// changes dropped, and the selection goes on with the next candidate on the block WITHOUT it. One pass; no
/// transaction is refused for what a refused one did; a non-payer never displaces a payer. Host builds only.
#[cfg(feature = "std")]
#[allow(clippy::too_many_arguments)]
pub fn select_node_transactions_priced<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: DB,
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
    let mut left = LeftUnpaid::default();
    let selection = select_priced_in_session(spec, &mut session, context, candidates, limits, price, &mut left)?;
    Ok((selection, left))
}

/// [`select_node_transactions_priced`] after the forced envelopes (see [`select_node_transactions_after_forced`]).
#[cfg(all(feature = "std", feature = "forced-inclusion"))]
#[allow(clippy::too_many_arguments)]
pub fn select_node_transactions_priced_after_forced<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: DB,
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
    let mut left = LeftUnpaid::default();
    let selection = select_priced_in_session(spec, &mut session, context, candidates, limits, price, &mut left)?;
    Ok((forced, selection, left))
}

// The loop of `select_in_session`, with the write price judged before a transaction's changes land. A copy, not
// a change of that function: it is compiled into the settlement guests and must keep its bytes and line numbers.
#[cfg(feature = "std")]
fn select_priced_in_session<DB: DatabaseRef>(
    spec: &ChainSpec,
    session: &mut BlockSession<DB>,
    context: &BlockContext,
    candidates: &[Bytes],
    limits: SelectionLimits,
    price: &WritePrice,
    left: &mut LeftUnpaid,
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
            .max_by(|a, b| {
                // Senders with standing first, then by tip: a sender that never paid cannot stand ahead of one that did.
                price.standing.contains(&a.0).cmp(&price.standing.contains(&b.0)).then(a.1.cmp(&b.1)).then(b.2.cmp(&a.2))
            })
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
        // The work spent on non-payers is bounded: past the allowance only plain transfers, which add no slot
        // whatever ran before them, are still executed; everything else stays pending, unjudged.
        if left.wasted_gas >= price.wasted_gas_allowance && (candidate.env.gas_limit != 21_000 || !candidate.env.data.is_empty()) {
            left.exhausted = true;
            left.not_judged.push(candidate.hash);
            for rest in queue.drain(..) {
                left.not_judged.push(rest.hash);
            }
            continue;
        }
        let (tip, before) = (candidate.effective_tip(base_fee), cached_storage(session.database()));
        let mut refused = None;
        let attempt = session.try_transaction_judged(&candidate.env, |gas_used, fresh| {
            let pays = fresh == 0
                || price.exempt.contains(&sender)
                || alloy_primitives::U256::from(gas_used) * alloy_primitives::U256::from(tip)
                    >= alloy_primitives::U256::from(fresh) * alloy_primitives::U256::from(price.per_slot);
            if !pays {
                refused = Some((gas_used, fresh));
            }
            pays
        });
        if let (Ok(None), Some((gas_used, fresh))) = (&attempt, refused) {
            // Left out, its changes dropped: the transactions behind it run on the block without it.
            left.wasted_gas = left.wasted_gas.saturating_add(gas_used);
            left.unpaid.push(UnpaidTransaction { hash: candidate.hash, sender, nonce: candidate.env.nonce, gas_used, effective_tip: tip, fresh_slots: fresh });
            continue;
        }
        match attempt {
            Ok(_outcome) => {
                        {
                    let gas_used = _outcome.map_or(0, |outcome| outcome.gas_used);
                    let (fresh_slots, cleared_slots) = storage_growth(session.database(), &before)?;
                    selection.stats.push(TxStats {
                        hash: candidate.hash,
                        sender, nonce: candidate.env.nonce,
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
