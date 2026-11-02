// SPDX-License-Identifier: MIT OR Apache-2.0
//! L1 forced inclusion of L2 transactions (CANDIDATE; no shipped rule set or
//! guest uses it, and no program pin changes).
//!
//! The native chain (`bloch-pos-committee` `l2_settlement::forced`, wire 0x1C
//! `L2ForcedTransaction`) queues one signed L2 envelope per L1 transaction as
//! `(l1 height, l1 txid, keccak256(envelope), declared gas limit)`, freezes the
//! queue with the settlement source, and accepts a V3 settlement only if its
//! `deposits_hash` slot equals [`inbox_hash`] over the deposits it minted and
//! the forced records due at its anchor (at most [`MAX_PER_SETTLEMENT`]). Every
//! settler, the sequencer or anyone else, is bound the same way.
//!
//! This module is the L2 half of that rule:
//!
//! * the shared record format and hashes ([`ForcedRecord`], [`forced_hash`],
//!   [`inbox_hash`]), pinned by a golden vector shared with the native crate;
//! * the deterministic selection: forced envelopes run right after the
//!   deposits and before any sequencer transaction, in queue order. One that
//!   does not authenticate, whose own gas limit is above the declared one, or
//!   that revm refuses before execution (nonce, funds, fee cap below the base
//!   fee) is SKIPPED: it leaves no trace in the block but is still consumed, so
//!   an invalid envelope can never block the queue. A valid one is included
//!   even if it reverts. [`push_forced`] is the producer side;
//!   [`check_forced_prefix`] is what a verifier (the guest) runs to prove that
//!   the body starts with exactly that selection;
//! * the statement fields: under forced inclusion `deposits_hash` is
//!   [`inbox_hash`] and `user_tx_count` and the data-availability batch cover
//!   the sequencer's transactions only (forced envelopes are already on L1).
//!
//! What a guest still needs (not done here): take the forced list as private
//! input, run [`check_forced_prefix`] on its witness database, and write the
//! two statement fields with [`statement_fields`]. The sparse witness must
//! cover every forced sender, including skipped ones, because revm reads the
//! sender account to decide the skip.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, Bytes, B256};
use revm::DatabaseRef;

use crate::transactions::{decode_signed_transaction, SignedBlockBuilder, SignedInputError};
use crate::{BlockContext, BlockExecutionError, ChainSpec, DepositMint};

/// Forced records one settlement consumes at most (native `forced::MAX_PER_SETTLEMENT`).
pub const MAX_PER_SETTLEMENT: usize = 16;
/// Declared gas limit bounds (native `forced::MIN_GAS` / `forced::MAX_GAS`).
pub const MIN_GAS: u64 = 21_000;
/// See [`MIN_GAS`].
pub const MAX_GAS: u64 = 300_000;
/// Declared gas one settlement consumes at most (native
/// `forced::MAX_GAS_PER_SETTLEMENT`): forced envelopes bypass the sequencer's
/// proving budget, so this bounds their proving work.
pub const MAX_GAS_PER_SETTLEMENT: u64 = 300_000;
/// One forced envelope at most this long (native `forced::MAX_ENVELOPE_BYTES`).
pub const MAX_ENVELOPE_BYTES: usize = 8 * 1024;
/// Domain of [`inbox_hash`].
pub const INBOX_DOMAIN: &[u8] = b"BLOCH:L2:INBOX:2";

/// One queued forced transaction, exactly as the native chain committed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ForcedRecord {
    /// Native height of the block that included the forced transaction.
    pub l1_height: u64,
    /// Its L1 txid, where a rebuilder reads the envelope.
    pub l1_txid: [u8; 32],
    /// keccak256 of the envelope, which is its L2 transaction hash.
    pub envelope_hash: B256,
    /// Gas limit declared on L1.
    pub gas_limit: u64,
}

impl ForcedRecord {
    /// `l1_height (u64 BE) || l1_txid || envelope_hash || gas_limit (u64 BE)`.
    pub fn encode(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        out[..8].copy_from_slice(&self.l1_height.to_be_bytes());
        out[8..40].copy_from_slice(&self.l1_txid);
        out[40..72].copy_from_slice(self.envelope_hash.as_slice());
        out[72..].copy_from_slice(&self.gas_limit.to_be_bytes());
        out
    }
}

/// keccak256 of the concatenated records (`keccak256("")` when empty).
pub fn forced_hash(records: &[ForcedRecord]) -> B256 {
    let mut buf = Vec::with_capacity(records.len() * 80);
    for r in records {
        buf.extend_from_slice(&r.encode());
    }
    keccak256(&buf)
}

/// The `deposits_hash` slot under forced inclusion: the deposits hash itself
/// when no record is consumed (so such blocks keep their statement bytes), else
/// `keccak256("BLOCH:L2:INBOX:2" || deposits_hash || forced_hash)`.
pub fn inbox_hash(deposits_hash: B256, consumed: &[ForcedRecord]) -> B256 {
    if consumed.is_empty() {
        return deposits_hash;
    }
    let mut buf = Vec::with_capacity(INBOX_DOMAIN.len() + 64);
    buf.extend_from_slice(INBOX_DOMAIN);
    buf.extend_from_slice(deposits_hash.as_slice());
    buf.extend_from_slice(forced_hash(consumed).as_slice());
    keccak256(&buf)
}

/// A forced record with the envelope a rebuilder read from its L1 transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ForcedTransaction {
    /// The committed record.
    pub record: ForcedRecord,
    /// The envelope bytes; must hash to `record.envelope_hash`.
    pub envelope: Bytes,
}

/// Why a forced envelope was skipped. A skip is part of the rule, not an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForcedSkip {
    /// The bytes do not authenticate as a transaction of this chain.
    Authentication(crate::TransactionAuthError),
    /// Its own gas limit is above the gas limit declared on L1.
    GasAboveDeclared {
        /// The envelope's gas limit.
        envelope: u64,
        /// The declared one.
        declared: u64,
    },
    /// revm refused it before execution (nonce, funds, fee cap, ...).
    Execution(alloc::string::String),
}

/// Inputs that are not a valid forced list: an error of the caller, never a skip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForcedInputError {
    /// More than [`MAX_PER_SETTLEMENT`] records.
    TooMany,
    /// More than [`MAX_GAS_PER_SETTLEMENT`] declared gas, or a record's
    /// declared gas outside [`MIN_GAS`]..=[`MAX_GAS`].
    Gas,
    /// An envelope does not hash to its record, or is empty or oversized.
    Envelope {
        /// Position in the forced list.
        index: usize,
    },
    /// The block's builder could not start (header, deposits, spec).
    Builder(alloc::string::String),
    /// The body does not start with exactly the forced selection.
    Prefix {
        /// First body position that differs.
        position: usize,
    },
}

/// The outcome of the forced selection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForcedSelection {
    /// Envelopes included, in order; the body starts with exactly these.
    pub included: Vec<Bytes>,
    /// `(position in the forced list, reason)` of each skipped envelope.
    pub skipped: Vec<(usize, ForcedSkip)>,
}

fn check_inputs(forced: &[ForcedTransaction]) -> Result<(), ForcedInputError> {
    if forced.len() > MAX_PER_SETTLEMENT {
        return Err(ForcedInputError::TooMany);
    }
    let mut gas = 0u64;
    for f in forced {
        if !(MIN_GAS..=MAX_GAS).contains(&f.record.gas_limit) {
            return Err(ForcedInputError::Gas);
        }
        gas = gas.saturating_add(f.record.gas_limit);
    }
    if gas > MAX_GAS_PER_SETTLEMENT {
        return Err(ForcedInputError::Gas);
    }
    for (index, f) in forced.iter().enumerate() {
        if f.envelope.is_empty()
            || f.envelope.len() > MAX_ENVELOPE_BYTES
            || keccak256(&f.envelope) != f.record.envelope_hash
        {
            return Err(ForcedInputError::Envelope { index });
        }
    }
    Ok(())
}

/// Producer side: push the forced envelopes into a fresh builder, before any
/// sequencer transaction. The builder must not have accepted anything yet.
pub fn push_forced<DB: DatabaseRef>(
    spec: &ChainSpec,
    builder: &mut SignedBlockBuilder<DB>,
    forced: &[ForcedTransaction],
) -> Result<ForcedSelection, ForcedInputError> {
    check_inputs(forced)?;
    if !builder.input().transactions.is_empty() {
        return Err(ForcedInputError::Prefix { position: 0 });
    }
    let mut selection = ForcedSelection::default();
    for (index, f) in forced.iter().enumerate() {
        // Decode first to compare the gas limit with the declared one.
        let gas = match decode_signed_transaction(spec, &f.envelope) {
            Ok(tx) => tx.environment().gas_limit,
            Err(reason) => {
                selection.skipped.push((index, ForcedSkip::Authentication(reason)));
                continue;
            }
        };
        if gas > f.record.gas_limit {
            selection.skipped.push((
                index,
                ForcedSkip::GasAboveDeclared {
                    envelope: gas,
                    declared: f.record.gas_limit,
                },
            ));
            continue;
        }
        match builder.try_push(&f.envelope) {
            Ok(_) => selection.included.push(f.envelope.clone()),
            Err(SignedInputError::Authentication { reason, .. }) => {
                selection.skipped.push((index, ForcedSkip::Authentication(reason)));
            }
            Err(SignedInputError::Execution(error)) => {
                selection.skipped.push((index, ForcedSkip::Execution(alloc::format!("{error}"))));
            }
        }
    }
    Ok(selection)
}

/// Verifier side: rerun the selection on the block's pre-state (after the same
/// header rules and deposits) and require `body` to start with exactly the
/// included envelopes. Returns the selection; the sequencer's transactions are
/// `body[selection.included.len()..]`.
pub fn check_forced_prefix<DB: DatabaseRef>(
    spec: &ChainSpec,
    database: DB,
    previous_root: B256,
    context: BlockContext,
    deposits: Vec<DepositMint>,
    forced: &[ForcedTransaction],
    body: &[Bytes],
) -> Result<ForcedSelection, ForcedInputError> {
    check_inputs(forced)?;
    let mut builder = SignedBlockBuilder::new(spec, database, previous_root, context, deposits)
        .map_err(|e: SignedInputError<BlockExecutionError>| ForcedInputError::Builder(alloc::format!("{e:?}")))?;
    let selection = push_forced(spec, &mut builder, forced)?;
    for (position, envelope) in selection.included.iter().enumerate() {
        if body.get(position) != Some(envelope) {
            return Err(ForcedInputError::Prefix { position });
        }
    }
    Ok(selection)
}

/// The two V3 statement fields under forced inclusion: the `deposits_hash`
/// slot and the user transaction count (sequencer transactions only).
pub fn statement_fields(
    deposits_hash: B256,
    consumed: &[ForcedRecord],
    body_transactions: usize,
    included_forced: usize,
) -> Option<(B256, u64)> {
    let sequencer = body_transactions.checked_sub(included_forced)?;
    Some((inbox_hash(deposits_hash, consumed), u64::try_from(sequencer).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared with bloch-pos-committee `forced_hash_matches_the_l2_golden_vector`.
    #[test]
    fn forced_inclusion_golden_vector() {
        let record = ForcedRecord {
            l1_height: 7,
            l1_txid: [0x11; 32],
            envelope_hash: B256::repeat_byte(0x22),
            gas_limit: 21_000,
        };
        assert_eq!(forced_hash(&[]), keccak256([]));
        assert_eq!(inbox_hash(B256::repeat_byte(0x33), &[]), B256::repeat_byte(0x33));
        assert_eq!(
            alloc::format!("{:x}", forced_hash(&[record])),
            "3209df24b99a7f67b3f05d26d89b51fc199a2c2cb2ed89b9677fba958f52e099"
        );
        assert_eq!(
            alloc::format!("{:x}", inbox_hash(keccak256([]), &[record])),
            "364cbe02ac69f9eb79d5b5e2dd5dd0fde2f3d80b7ed81ae0e587cef4d785fea3"
        );
        // The empty deposits hash is this crate's own deposits hash of no deposits.
        assert_eq!(crate::executor::deposits_hash(&[]), keccak256([]));
    }

    #[test]
    fn statement_fields_count_only_sequencer_transactions() {
        let record = ForcedRecord {
            l1_height: 1,
            l1_txid: [1; 32],
            envelope_hash: B256::repeat_byte(2),
            gas_limit: MIN_GAS,
        };
        let d = B256::repeat_byte(9);
        assert_eq!(statement_fields(d, &[], 3, 0), Some((d, 3)));
        assert_eq!(statement_fields(d, &[record], 3, 1), Some((inbox_hash(d, &[record]), 2)));
        // A skipped record is consumed but not in the body.
        assert_eq!(statement_fields(d, &[record, record], 1, 0), Some((inbox_hash(d, &[record, record]), 1)));
        assert_eq!(statement_fields(d, &[record], 0, 1), None);
    }
}
