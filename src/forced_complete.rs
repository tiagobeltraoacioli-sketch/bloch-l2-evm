// SPDX-License-Identifier: MIT OR Apache-2.0
//! L1 forced inclusion on the complete-witness path (CANDIDATE, inert; the
//! `forced-complete` feature only).
//!
//! The rollback fallback program (native `PROGRAM_FALLBACK`) proves the same
//! next rules as the sparse `PROGRAM_NEXT`, but from the complete witness
//! ([`BatchWitness`]). Once forced inclusion is part of those rules
//! (configuration tag 4), the fallback must run the same forced rule, or a
//! rollback would stop settlement at the first due record. This module is the
//! complete-witness copy of what [`crate::sparse_witness`] does for forced
//! inclusion:
//!
//! * [`verify_node_batch_forced`] runs the block like
//!   [`crate::node_execution::verify_node_batch`], but with the forced list
//!   ([`crate::forced_inclusion::run_forced_prefix`]) right after the header
//!   rules and the deposits, and requires the body to start with exactly the
//!   envelopes that were not skipped;
//! * [`execute_settlement_statement_v3_forced`] derives the V3 statement:
//!   under forced inclusion the `deposits_hash` slot is
//!   [`crate::forced_inclusion::inbox_hash`] over the deposits and every
//!   consumed record, and the user count and DA commitment cover only the
//!   sequencer's transactions ([`SettlementStatementV3::from_executed_forced`]);
//! * [`generate_node_batch_witness_forced`] records the complete witness of
//!   such a block. The forced rule's admissibility probe reads the senders of
//!   skipped envelopes without committing them, so the generator records
//!   every read below the block's overlay and adds those accounts to the
//!   witness. In the guest a read the witness does not cover is a database
//!   error, which fails the block and never turns a valid forced transaction
//!   into a skip ([`crate::proving::WitnessBacking`]).
//!
//! The forced list is not part of the [`BatchWitness`] wire format, which the
//! activated program shares. The fallback guest reads it as its own input
//! after the settlement context. Nothing in it is trusted: the statement
//! binds it, and L1 compares the slot with its own queue.
//!
//! The code lives in its own file behind its own feature so that no program
//! built without the feature changes, the sparse guests included.

use alloc::{collections::BTreeSet, vec::Vec};
use core::cell::RefCell;

use alloy_primitives::{Address, B256, U256};
use revm::{
    database::CacheDB,
    state::{AccountInfo, Bytecode},
    Database, DatabaseRef,
};

use crate::{
    executor::BlockSession,
    forced_inclusion::{run_forced_prefix, ForcedTransaction},
    node_execution::{
        head, outcome_record, prepare_parent, NodeExecutionError, NodeExecutionOutcome, NodeWitnessError,
        PendingOutcome,
    },
    node_primitives::NodeBodyV2,
    proof_statement::{
        configuration_commitment, ExecutionStatement, SettlementContextV2, SettlementStatementV2Error,
        SettlementStatementV3,
    },
    proving::{BatchWitness, VerifyError},
    BlockContext, ChainSpec, L2State,
};

/// `run_node_block` with the forced rule after the deposits. Returns the
/// overlay, the pending outcome and the length of the forced prefix of the body.
fn run_node_block_forced<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: CacheDB<DB>,
    previous_root: B256,
    context: &BlockContext,
    body: &NodeBodyV2,
    forced: &[ForcedTransaction],
) -> Result<(CacheDB<DB>, PendingOutcome, usize), NodeExecutionError> {
    let input = body.authenticated_input(spec).map_err(NodeExecutionError::Body)?;
    let mut parent_timestamp = 0;
    let mut session = BlockSession::begin_with_header(spec, db, context, &body.deposits, |db| {
        parent_timestamp = head::read_head_v2(db, spec.block_info)?.base.timestamp;
        prepare_parent(spec, domain, db, previous_root, context)
    })?;
    // The same rule as the producer, the L1 rebuild and the sparse guest: the
    // forced envelopes run first, and the body starts with the included ones.
    let included = run_forced_prefix(spec, &mut session, forced, &body.transactions)
        .map_err(|e| NodeExecutionError::Execution(e.into()))?;
    let sequencer = input.txs.get(included..).ok_or_else(|| {
        NodeExecutionError::Execution(crate::BlockExecutionError::HeaderState {
            detail: "forced inclusion: the body is shorter than its forced prefix".into(),
        })
    })?;
    for tx in sequencer {
        session.try_transaction(tx, |_| true)?;
    }
    let (db, run, (record, receipts)) = session.finish_with_header(|db, run| {
        let (record, receipts) = outcome_record(context, previous_root, run, body, &input.txs)?;
        head::write_head_v2(db, spec.block_info, &record)?;
        Ok((record, receipts))
    })?;
    Ok((
        db,
        PendingOutcome {
            record,
            receipts,
            transactions: run.tx_outcomes,
            withdrawals: run.withdrawals,
            parent_timestamp,
        },
        included,
    ))
}

/// [`crate::node_execution::verify_node_batch`] under the forced rule: also
/// returns how many body transactions are the forced prefix. With an empty
/// list it is exactly `verify_node_batch` (prefix 0); a non-empty list under
/// rules without forced inclusion is refused.
pub fn verify_node_batch_forced(
    spec: &ChainSpec,
    domain: B256,
    witness: &BatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
    forced: &[ForcedTransaction],
) -> Result<(NodeExecutionOutcome, usize), NodeWitnessError> {
    let hydrated = crate::proving::hydrate_and_verify(witness).map_err(NodeWitnessError::Verify)?;
    let (db, pending, included) =
        run_node_block_forced(spec, domain, hydrated.state, witness.prev_state_root, context, body, forced)
            .map_err(NodeWitnessError::Execution)?;
    let root = crate::proving::verify_overlay_root(witness, hydrated.pre_leaves, hydrated.view, &db)
        .map_err(NodeWitnessError::Verify)?;
    Ok((pending.finalize(spec, domain, root), included))
}

/// [`crate::proof_statement::execute_statement`] under the forced rule (the
/// execution artifact's self-check).
pub fn execute_statement_forced(
    spec: &ChainSpec,
    domain: B256,
    witness: &BatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
    forced: &[ForcedTransaction],
) -> Result<ExecutionStatement, NodeWitnessError> {
    let (outcome, _) = verify_node_batch_forced(spec, domain, witness, context, body, forced)?;
    let configuration = configuration_commitment(spec).map_err(|error| {
        NodeWitnessError::Execution(NodeExecutionError::Execution(crate::BlockExecutionError::InvalidChainSpec(
            error,
        )))
    })?;
    Ok(ExecutionStatement {
        configuration,
        domain,
        previous_state_root: witness.prev_state_root,
        header_hash: outcome.header.hash(),
    })
}

/// [`crate::proof_statement::execute_settlement_statement_v3`] under the
/// forced rule: the statement of the complete-witness fallback guest. Under
/// rules with forced inclusion the `deposits_hash` slot is `inbox_hash` over
/// the deposits and every consumed record, skipped ones included, and the
/// user count and DA commitment cover the sequencer's transactions only.
/// With nothing consumed the statement is byte for byte the plain one.
pub fn execute_settlement_statement_v3_forced(
    spec: &ChainSpec,
    domain: B256,
    witness: &BatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
    settlement: SettlementContextV2,
    forced: &[ForcedTransaction],
) -> Result<SettlementStatementV3, SettlementStatementV2Error> {
    let (outcome, included_forced) = verify_node_batch_forced(spec, domain, witness, context, body, forced)
        .map_err(SettlementStatementV2Error::Execution)?;
    if let Some(rule) = spec.block_derivation {
        if rule.timestamp(outcome.parent_timestamp, settlement.l1_slot) != Some(context.timestamp)
            || context.prevrandao != rule.prevrandao
        {
            return Err(SettlementStatementV2Error::BlockDerivation);
        }
    }
    let configuration = configuration_commitment(spec).map_err(|error| {
        SettlementStatementV2Error::Execution(NodeWitnessError::Execution(NodeExecutionError::Execution(
            crate::BlockExecutionError::InvalidChainSpec(error),
        )))
    })?;
    let withdrawals = outcome
        .withdrawals
        .as_ref()
        .map(|summary| summary.commitment)
        .ok_or(SettlementStatementV2Error::Withdrawals)?;
    if spec.forced_inclusion {
        let consumed: Vec<_> = forced.iter().map(|f| f.record).collect();
        return SettlementStatementV3::from_executed_forced(
            configuration,
            &outcome.header,
            body,
            settlement,
            withdrawals,
            &consumed,
            included_forced,
        );
    }
    SettlementStatementV3::from_executed(configuration, &outcome.header, body, settlement, withdrawals)
}

/// A read-through database that records every address read below the block's
/// overlay (account or storage). The forced rule's admissibility probe reads
/// through the session state without committing, so those reads never reach
/// the overlay's cache; this is how the generator still sees them.
struct RecordingRef<D> {
    inner: D,
    addresses: RefCell<BTreeSet<Address>>,
}

impl<D: DatabaseRef> DatabaseRef for RecordingRef<D> {
    type Error = D::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.addresses.borrow_mut().insert(address);
        self.inner.basic_ref(address)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.addresses.borrow_mut().insert(address);
        self.inner.storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash_ref(number)
    }
}

/// [`crate::node_execution::generate_node_batch_witness`] for a block that
/// consumes these forced records. The witness covers every account the block
/// and the forced rule read, the senders of skipped envelopes included, and
/// is re-verified by the guest procedure before it is returned.
pub fn generate_node_batch_witness_forced(
    pre: &L2State,
    spec: &ChainSpec,
    domain: B256,
    context: &BlockContext,
    body: &NodeBodyV2,
    forced: &[ForcedTransaction],
) -> Result<(BatchWitness, NodeExecutionOutcome), NodeWitnessError> {
    let previous_root = pre.state_root();
    let recording = RecordingRef {
        inner: pre.db(),
        addresses: RefCell::new(BTreeSet::new()),
    };
    let (mut db, pending, _) =
        run_node_block_forced(spec, domain, CacheDB::new(&recording), previous_root, context, body, forced)
            .map_err(NodeWitnessError::Execution)?;
    // Accounts read only by the admissibility probe: load them into the
    // overlay unchanged, so that the witness carries them.
    let probed: Vec<Address> = recording.addresses.borrow().iter().copied().collect();
    for address in probed {
        if !db.cache.accounts.contains_key(&address) {
            db.basic(address).map_err(|e| {
                NodeWitnessError::Execution(NodeExecutionError::Execution(crate::BlockExecutionError::HeaderState {
                    detail: alloc::format!("forced inclusion: pre-state read of {address}: {e:?}"),
                }))
            })?;
        }
    }
    let witness = crate::proving::witness_from_overlay(pre, previous_root, &db.cache)
        .map_err(NodeWitnessError::Generate)?;
    let outcome = pending.finalize(spec, domain, witness.new_state_root);
    let (verified, _) = verify_node_batch_forced(spec, domain, &witness, context, body, forced)?;
    if verified.header != outcome.header
        || verified.receipts != outcome.receipts
        || verified.withdrawals != outcome.withdrawals
        || verified.transactions.len() != outcome.transactions.len()
        || !verified.transactions.iter().zip(&outcome.transactions).all(|(a, b)| {
            a.success == b.success
                && a.gas_used == b.gas_used
                && a.created_address == b.created_address
                && a.burned_wei == b.burned_wei
                && a.result == b.result
        })
    {
        return Err(NodeWitnessError::Verify(VerifyError::OutcomeMismatch));
    }
    Ok((witness, outcome))
}

#[cfg(test)]
mod tests;
