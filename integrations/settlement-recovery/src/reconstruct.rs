// SPDX-License-Identifier: AGPL-3.0-or-later
//! Derive every settled L2 block's execution inputs from native (L1) blocks only.
//!
//! The native chain stores hashes; the inputs themselves are in its blocks:
//! `L2Deposit` (0x14) transactions are the inbox records, `L2DataAvailability`
//! (0x15) transactions carry the user-transaction batches, and accepted
//! settlements (0x12/0x13) name, for each L2 block, the anchor, the consumed
//! inbox range, the batch (`da_commitment`) and the resulting header hash and
//! state root. [`derive_settled_blocks`] re-applies the native bookkeeping
//! (inbox order and positions, DA lookup) and returns, per settled block, the
//! deposits and transactions to execute and the roots the execution must
//! reproduce (`bloch-l2-produce-dev reconstruct` executes them).
//!
//! The blocks are trusted to be the finalized native chain in height order
//! (for example the native follower's verified store): a block the native
//! transition accepted applied every transaction it carries, so nothing here
//! re-verifies signatures or proofs.

use alloy_primitives::{Address, Bytes, B256};
use bloch_l2_evm::forced_inclusion::{
    inbox_hash, ForcedRecord, ForcedTransaction, MAX_GAS_PER_SETTLEMENT, MAX_PER_SETTLEMENT,
};
use bloch_l2_evm::{
    data_availability::{da_commitment, decode_da_payload},
    deposits_hash,
    proof_statement::{SettlementStatementV2, SettlementStatementV3, SETTLEMENT_STATEMENT_V3_TAG},
    withdrawal::WithdrawalCommitment,
    DepositMint, DepositProvenance,
};
use bloch_pos_committee::{l2_settlement::InboxRecord, transition::PosTransaction};
use std::collections::BTreeMap;

/// One native block: its height on the L2 registry's own count and its
/// canonical transaction bytes in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeBlockTransactions {
    /// The value the native transition stores in `InboxRecord::height`: the
    /// number of blocks applied since the L2 registry was installed. It equals
    /// the chain height only on a network with the L2 at genesis; see
    /// [`l2_registry_blocks`].
    pub height: u64,
    pub transactions: Vec<Vec<u8>>,
}

/// Inputs and expected outputs of one settled L2 block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettledBlockInputs {
    pub number: u64,
    /// Native height of the block that carried the settlement.
    pub settled_at: u64,
    pub parent_hash: B256,
    pub previous_state_root: B256,
    /// The configuration commitment L1 compared with its policy when it accepted
    /// this settlement: it names the rules this block ran.
    pub configuration: B256,
    pub anchor: B256,
    /// Native slot of the anchored block (the L2 timestamp rule's L1 origin).
    pub anchor_slot: u64,
    pub deposits: Vec<DepositMint>,
    pub transactions: Vec<Bytes>,
    pub header_hash: B256,
    pub state_root: B256,
    /// V3 only: commitments the rebuilt body must reproduce.
    pub deposits_hash: Option<B256>,
    pub transactions_root: Option<B256>,
    /// Zero for V2 and for blocks without user transactions.
    pub da_commitment: B256,
    /// V3 only: the outbox root and count after the block.
    pub withdrawals: Option<WithdrawalCommitment>,
    /// Forced inclusion (candidate): the forced records this settlement
    /// consumed, in queue order, each with the envelope its 0x1C transaction
    /// carried. The rebuilder runs them by the forced rule before
    /// `transactions` (the DA batch holds the sequencer's part only).
    pub forced: Vec<ForcedTransaction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconstructError {
    /// Heights are not strictly increasing.
    Order { height: u64 },
    /// A transaction does not decode under this build's native codec.
    Decode { height: u64, index: usize },
    /// A settlement statement is neither V2 nor V3.
    Statement { height: u64 },
    /// A settlement for another L2 chain.
    Chain { height: u64, chain_id: u64 },
    /// A settlement that does not extend the previous one.
    Successor { height: u64, number: u64 },
    /// A settlement consumes inbox records the blocks never carried.
    Inbox { height: u64, number: u64 },
    /// The minted deposits differ from the statement's `deposits_hash`.
    Deposits { number: u64 },
    /// No L1 batch with the statement's `da_commitment` precedes the settlement.
    DataUnavailable { number: u64, commitment: B256 },
    /// The batch does not decode or its size differs from `user_tx_count`.
    Batch { number: u64 },
    /// The withdrawal count decreased, or the root changed without new
    /// withdrawals (or stayed with new ones) — the native acceptance rules.
    Withdrawals { number: u64 },
}

impl std::fmt::Display for ReconstructError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Order { height } => write!(f, "native block {height} is out of order"),
            Self::Decode { height, index } => write!(f, "native block {height} transaction {index} does not decode"),
            Self::Statement { height } => write!(f, "native block {height} carries an unknown settlement statement"),
            Self::Chain { height, chain_id } => write!(f, "native block {height} settles L2 chain {chain_id}"),
            Self::Successor { height, number } => {
                write!(
                    f,
                    "native block {height} settlement of L2 block {number} does not extend the previous one"
                )
            }
            Self::Inbox { height, number } => {
                write!(
                    f,
                    "native block {height} settlement of L2 block {number} consumes unknown inbox records"
                )
            }
            Self::Deposits { number } => write!(f, "L2 block {number}: deposits do not match deposits_hash"),
            Self::DataUnavailable { number, commitment } => {
                write!(f, "L2 block {number}: no L1 data-availability batch {commitment}")
            }
            Self::Batch { number } => write!(f, "L2 block {number}: DA batch is malformed or has the wrong size"),
            Self::Withdrawals { number } => write!(
                f,
                "L2 block {number}: withdrawal root/count do not extend the previous ones"
            ),
        }
    }
}
impl std::error::Error for ReconstructError {}

fn mint(record: &InboxRecord) -> DepositMint {
    DepositMint {
        recipient: Address::from(record.recipient),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: record.height,
            l1_tx_index: record.tx_index,
            l1_txid: record.txid,
            l1_vout: record.vout,
            l1_sats: record.sats,
        },
    }
}

/// First native slot of the flag-day L2 installed by this build: the transition
/// installs the registry in the first block at or past this slot.
pub fn flag_day_first_slot() -> u64 {
    bloch_pos_committee::params::L2_SETTLEMENT_ACTIVATION_EPOCH * bloch_pos_committee::params::SLOTS_PER_EPOCH
}

/// Number canonical native blocks `(slot, transactions)`, in chain order from
/// native genesis, on the L2 registry's own count.
///
/// `first_slot` is `None` for an L2 configured at genesis: every block counts,
/// so the height is the chain height. It is `Some` for a flag-day L2: the first
/// block at or past that slot installs the registry and is height 1, because
/// the transition advances the new registry within that same block. Earlier
/// blocks cannot carry L2 transactions and are left out.
pub fn l2_registry_blocks(
    blocks: impl IntoIterator<Item = (u64, Vec<Vec<u8>>)>,
    first_slot: Option<u64>,
) -> Vec<NativeBlockTransactions> {
    blocks
        .into_iter()
        .filter(|(slot, _)| first_slot.is_none_or(|first| *slot >= first))
        .zip(1u64..)
        .map(|((_, transactions), height)| NativeBlockTransactions { height, transactions })
        .collect()
}

/// Derive the inputs of every L2 block settled in `blocks` for `chain_id`,
/// starting from the L2 genesis (`genesis_hash`, `genesis_state_root`), under
/// the head reset this build's native consensus would apply, if any.
pub fn derive_settled_blocks(
    blocks: &[NativeBlockTransactions],
    chain_id: u64,
    genesis_hash: B256,
    genesis_state_root: B256,
) -> Result<Vec<SettledBlockInputs>, ReconstructError> {
    let reset = bloch_pos_committee::l2_settlement::mainnet::HEAD_RESET.map(|reset| reset.number);
    derive_settled_blocks_with_reset(blocks, chain_id, genesis_hash, genesis_state_root, reset)
}

/// [`derive_settled_blocks`] with the kept block of an optional head reset named
/// explicitly. A settlement that extends that block while the settled chain has
/// gone past it means the native gate moved the head back: L1 accepted it, so the
/// blocks above are no longer part of the chain and are dropped here too. Without
/// a reset the rule stays that every settlement extends the previous one.
pub fn derive_settled_blocks_with_reset(
    blocks: &[NativeBlockTransactions],
    chain_id: u64,
    genesis_hash: B256,
    genesis_state_root: B256,
    reset: Option<u64>,
) -> Result<Vec<SettledBlockInputs>, ReconstructError> {
    let mut inbox: Vec<InboxRecord> = Vec::new();
    // (L2 number, commitment) -> payload; first publication wins (identical bytes).
    let mut batches: BTreeMap<(u64, B256), Vec<u8>> = BTreeMap::new();
    let mut out: Vec<SettledBlockInputs> = Vec::new();
    let (mut head_hash, mut head_root, mut head_number) = (genesis_hash, genesis_state_root, 0u64);
    let mut head_withdrawals = WithdrawalCommitment::empty();
    // Forced inclusion: the native queue's pending records, oldest first.
    let mut forced_pending: std::collections::VecDeque<ForcedTransaction> = std::collections::VecDeque::new();
    let mut last_height = 0u64;
    for block in blocks {
        if block.height <= last_height {
            return Err(ReconstructError::Order { height: block.height });
        }
        last_height = block.height;
        // DA records become usable from the next native block on.
        let mut published_here: Vec<((u64, B256), Vec<u8>)> = Vec::new();
        let mut deposit_index = 0u32;
        for (index, raw) in block.transactions.iter().enumerate() {
            let tx = PosTransaction::from_canonical_bytes(raw).map_err(|_| ReconstructError::Decode {
                height: block.height,
                index,
            })?;
            match &tx {
                PosTransaction::L2Deposit(deposit) => {
                    inbox.push(InboxRecord {
                        height: block.height,
                        tx_index: deposit_index,
                        txid: tx.txid(),
                        vout: bloch_pos_committee::transition::l2_deposit::ESCROW_VOUT,
                        sats: deposit.amount_sat,
                        recipient: deposit.recipient,
                    });
                    deposit_index += 1;
                }
                PosTransaction::L2ForcedTransaction(forced) if forced.l2_chain_id == chain_id => {
                    // A finalized block applied it, so the native queue holds it (refusals are not applied).
                    forced_pending.push_back(ForcedTransaction {
                        record: ForcedRecord {
                            l1_height: block.height,
                            l1_txid: tx.txid(),
                            envelope_hash: alloy_primitives::keccak256(&forced.envelope),
                            gas_limit: forced.gas_limit,
                        },
                        envelope: forced.envelope.clone().into(),
                    });
                }
                PosTransaction::L2DataAvailability(batch) if batch.l2_chain_id == chain_id => {
                    let key = (batch.l2_block_number, B256::from(batch.commitment()));
                    published_here.push((key, batch.payload.clone()));
                }
                PosTransaction::L2Settlement(settlement) | PosTransaction::L2SettlementAsync(settlement) => {
                    let s = &settlement.statement;
                    let (base, v3) = if s.starts_with(SETTLEMENT_STATEMENT_V3_TAG) {
                        let v3 = SettlementStatementV3::decode(s)
                            .map_err(|_| ReconstructError::Statement { height: block.height })?;
                        (v3.base, Some(v3))
                    } else {
                        let v2 = SettlementStatementV2::decode(s)
                            .map_err(|_| ReconstructError::Statement { height: block.height })?;
                        (v2, None)
                    };
                    if base.chain_id != chain_id {
                        return Err(ReconstructError::Chain {
                            height: block.height,
                            chain_id: base.chain_id,
                        });
                    }
                    let number = base.l2_number;
                    if let Some(kept) = reset.filter(|kept| number == kept + 1 && head_number > *kept) {
                        let target = usize::try_from(kept).ok().filter(|k| *k <= out.len());
                        let (hash, root, withdrawals) = match target {
                            Some(0) => (genesis_hash, genesis_state_root, WithdrawalCommitment::empty()),
                            Some(k) => {
                                let block = &out[k - 1];
                                (
                                    block.header_hash,
                                    block.state_root,
                                    block.withdrawals.unwrap_or_else(WithdrawalCommitment::empty),
                                )
                            }
                            None => {
                                return Err(ReconstructError::Successor {
                                    height: block.height,
                                    number,
                                })
                            }
                        };
                        if base.l2_parent_hash == hash && base.l2_previous_state_root == root {
                            // The native head reset puts records consumed above the kept block back at
                            // the front of the queue, in their order.
                            let dropped: Vec<ForcedTransaction> = out[target.unwrap_or_default()..]
                                .iter()
                                .flat_map(|b| b.forced.iter().cloned())
                                .collect();
                            for f in dropped.into_iter().rev() {
                                forced_pending.push_front(f);
                            }
                            out.truncate(target.unwrap_or_default());
                            (head_hash, head_root, head_number) = (hash, root, kept);
                            head_withdrawals = withdrawals;
                        }
                    }
                    if number != head_number + 1
                        || base.l2_parent_hash != head_hash
                        || base.l2_previous_state_root != head_root
                    {
                        return Err(ReconstructError::Successor {
                            height: block.height,
                            number,
                        });
                    }
                    let range = usize::try_from(base.consumed_start)
                        .ok()
                        .zip(usize::try_from(base.consumed_end).ok());
                    let records = range
                        .filter(|(start, end)| start <= end)
                        .and_then(|(start, end)| inbox.get(start..end))
                        .ok_or(ReconstructError::Inbox {
                            height: block.height,
                            number,
                        })?;
                    let deposits: Vec<DepositMint> = records.iter().map(mint).collect();
                    let mut transactions = Vec::new();
                    let mut consumed_forced = Vec::new();
                    if let Some(v3) = &v3 {
                        let next = WithdrawalCommitment {
                            root: v3.withdrawal_root,
                            count: v3.withdrawal_count,
                        };
                        if next.count < head_withdrawals.count
                            || (next.count == head_withdrawals.count) != (next.root == head_withdrawals.root)
                        {
                            return Err(ReconstructError::Withdrawals { number });
                        }
                        head_withdrawals = next;
                        // The slot is the deposits hash, or the inbox hash over it and the forced records
                        // consumed: a prefix of the queue within the per-settlement bounds.
                        let plain = deposits_hash(&deposits);
                        if plain != v3.deposits_hash {
                            let mut records: Vec<ForcedRecord> = Vec::new();
                            let mut gas = 0u64;
                            let mut found = None;
                            for (n, f) in forced_pending.iter().enumerate().take(MAX_PER_SETTLEMENT) {
                                gas = gas.saturating_add(f.record.gas_limit);
                                if gas > MAX_GAS_PER_SETTLEMENT {
                                    break;
                                }
                                records.push(f.record);
                                if inbox_hash(plain, &records) == v3.deposits_hash {
                                    found = Some(n + 1);
                                    break;
                                }
                            }
                            let n = found.ok_or(ReconstructError::Deposits { number })?;
                            consumed_forced = forced_pending.drain(..n).collect();
                        }
                        if v3.user_tx_count > 0 {
                            let payload =
                                batches
                                    .get(&(number, v3.da_commitment))
                                    .ok_or(ReconstructError::DataUnavailable {
                                        number,
                                        commitment: v3.da_commitment,
                                    })?;
                            // Defensive: the map key is the commitment of these bytes.
                            if da_commitment(chain_id, number, payload) != v3.da_commitment {
                                return Err(ReconstructError::DataUnavailable {
                                    number,
                                    commitment: v3.da_commitment,
                                });
                            }
                            transactions =
                                decode_da_payload(payload).map_err(|_| ReconstructError::Batch { number })?;
                            if transactions.len() as u64 != v3.user_tx_count {
                                return Err(ReconstructError::Batch { number });
                            }
                        }
                    }
                    out.push(SettledBlockInputs {
                        number,
                        settled_at: block.height,
                        parent_hash: base.l2_parent_hash,
                        previous_state_root: base.l2_previous_state_root,
                        configuration: base.configuration,
                        anchor: base.l1_block,
                        anchor_slot: base.l1_slot,
                        deposits,
                        transactions,
                        header_hash: base.l2_header_hash,
                        state_root: base.l2_state_root,
                        deposits_hash: v3.map(|v| v.deposits_hash),
                        transactions_root: v3.map(|v| v.transactions_root),
                        da_commitment: v3.map_or(B256::ZERO, |v| v.da_commitment),
                        withdrawals: v3.map(|v| WithdrawalCommitment {
                            root: v.withdrawal_root,
                            count: v.withdrawal_count,
                        }),
                        forced: consumed_forced,
                    });
                    (head_hash, head_root, head_number) = (base.l2_header_hash, base.l2_state_root, number);
                    // Batches for settled blocks are never needed again.
                    batches.retain(|(n, _), _| *n > number);
                }
                _ => {}
            }
        }
        for (key, payload) in published_here {
            batches.entry(key).or_insert(payload);
        }
    }
    Ok(out)
}
