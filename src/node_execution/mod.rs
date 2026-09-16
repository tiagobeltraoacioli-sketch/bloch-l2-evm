// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit V2 genesis and committed header metadata, separate from V1 state.
mod head;

pub use head::{genesis_v2, HeadRecordV2};

use crate::{
    executor::BlockSession,
    node_primitives::{NodeBodyError, NodeBodyV2, NodeHeaderV2},
    state::{block_hash_slot, BLOCK_HASH_HISTORY},
    BlockContext, BlockExecutionError, ChainSpec, HeadRecord, L2State, TxOutcome,
};
use alloc::{format, vec::Vec};
use alloy_consensus::{proofs::calculate_receipt_root, Eip658Value, Receipt, ReceiptEnvelope};
use alloy_primitives::{Bloom, B256, U256};
use revm::{database::CacheDB, Database, DatabaseRef};

/// Authentication or execution failure on the explicit V2 path.
#[derive(Debug)]
pub enum NodeExecutionError {
    /// Signed body authentication or bounds failed.
    Body(NodeBodyError),
    /// State transition failed.
    Execution(BlockExecutionError),
}
impl core::fmt::Display for NodeExecutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Body(e) => e.fmt(f),
            Self::Execution(e) => e.fmt(f),
        }
    }
}
impl core::error::Error for NodeExecutionError {}
impl From<BlockExecutionError> for NodeExecutionError {
    fn from(error: BlockExecutionError) -> Self {
        Self::Execution(error)
    }
}

/// Actual V2 execution result; receipts contain only user transactions.
#[derive(Debug)]
pub struct NodeExecutionOutcome {
    /// Header reconstructed after committing metadata and computing the root.
    pub header: NodeHeaderV2,
    /// Typed receipts derived from actual execution results.
    pub receipts: Vec<ReceiptEnvelope>,
    /// Detailed execution outcomes in signed body order.
    pub transactions: Vec<TxOutcome>,
}

/// Reconstruct the V2 head from committed state and trusted configuration.
/// Use this for V2 identity rather than the V1 `L2Header` helpers.
pub fn node_head(spec: &ChainSpec, domain: B256, state: &L2State) -> Result<NodeHeaderV2, BlockExecutionError> {
    let mut db = CacheDB::new(state.db());
    let header = head::read_head_v2(&mut db, spec.block_info)?.header(spec, domain, state.state_root());
    header
        .validate_configuration(spec, domain)
        .map_err(|error| BlockExecutionError::HeaderState {
            detail: format!("{error}"),
        })?;
    Ok(header)
}

fn prepare_parent<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: &mut CacheDB<DB>,
    previous_root: B256,
    context: &BlockContext,
) -> Result<B256, BlockExecutionError> {
    let parent = head::read_head_v2(db, spec.block_info)?.header(spec, domain, previous_root);
    parent
        .validate_configuration(spec, domain)
        .map_err(|e| BlockExecutionError::HeaderState { detail: format!("{e}") })?;
    let expected = parent
        .number
        .checked_add(1)
        .ok_or(BlockExecutionError::InvalidBlockNumber {
            expected: u64::MAX,
            got: context.number,
        })?;
    if context.number != expected {
        return Err(BlockExecutionError::InvalidBlockNumber {
            expected,
            got: context.number,
        });
    }
    if context.timestamp < parent.timestamp {
        return Err(BlockExecutionError::InvalidTimestamp {
            parent: parent.timestamp,
            got: context.timestamp,
        });
    }
    let expected = spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used);
    if context.base_fee_per_gas != expected {
        return Err(BlockExecutionError::InvalidBaseFee {
            expected,
            got: context.base_fee_per_gas,
        });
    }
    let hash = parent.hash();
    let database_error = |e| BlockExecutionError::Database {
        detail: format!("{e:?}"),
    };
    db.insert_account_storage(spec.block_info, block_hash_slot(parent.number), hash.into())
        .map_err(database_error)?;
    for number in context.number.saturating_sub(BLOCK_HASH_HISTORY)..context.number {
        let word = db
            .storage(spec.block_info, block_hash_slot(number))
            .map_err(database_error)?;
        db.cache.block_hashes.insert(U256::from(number), B256::from(word));
    }
    Ok(hash)
}

/// Execute authenticated signed envelopes atomically against a V2 state.
/// `domain` must come from trusted configuration; L1 deposits must be authenticated
/// by the caller. V1 genesis is rejected. This does not activate a node or consensus.
pub fn execute_node_block(
    spec: &ChainSpec,
    domain: B256,
    state: &mut L2State,
    context: &BlockContext,
    body: &NodeBodyV2,
) -> Result<NodeExecutionOutcome, NodeExecutionError> {
    let previous_root = state.commit_root();
    let (db, pending) = run_node_block(spec, domain, CacheDB::new(state.db()), previous_root, context, body)?;
    state.apply_overlay(db.cache);
    Ok(pending.finalize(spec, domain, state.commit_root()))
}

struct PendingOutcome {
    record: HeadRecordV2,
    receipts: Vec<ReceiptEnvelope>,
    transactions: Vec<TxOutcome>,
}
impl PendingOutcome {
    fn finalize(self, spec: &ChainSpec, domain: B256, root: B256) -> NodeExecutionOutcome {
        NodeExecutionOutcome {
            header: self.record.header(spec, domain, root),
            receipts: self.receipts,
            transactions: self.transactions,
        }
    }
}

fn run_node_block<DB: DatabaseRef>(
    spec: &ChainSpec,
    domain: B256,
    db: CacheDB<DB>,
    previous_root: B256,
    context: &BlockContext,
    body: &NodeBodyV2,
) -> Result<(CacheDB<DB>, PendingOutcome), NodeExecutionError> {
    let input = body.authenticated_input(spec).map_err(NodeExecutionError::Body)?;
    let mut session = BlockSession::begin_with_header(spec, db, context, &body.deposits, |db| {
        prepare_parent(spec, domain, db, previous_root, context)
    })?;
    let mut receipts = Vec::with_capacity(input.txs.len());
    let mut cumulative = 0u64;
    for tx in &input.txs {
        let outcome = session.try_transaction(tx, |_| true)?.expect("accepted transaction");
        cumulative += outcome.gas_used;
        let receipt = Receipt {
            status: Eip658Value::Eip658(outcome.success),
            cumulative_gas_used: cumulative,
            logs: outcome.result.logs().to_vec(),
        }
        .with_bloom();
        receipts.push(match tx.tx_type {
            0 => ReceiptEnvelope::Legacy(receipt),
            1 => ReceiptEnvelope::Eip2930(receipt),
            2 => ReceiptEnvelope::Eip1559(receipt),
            _ => unreachable!("authenticated supported transaction"),
        });
    }
    let logs_bloom: Bloom = receipts.iter().flat_map(|receipt| receipt.logs().iter()).collect();
    let (db, run, record) = session.finish_with_header(|db, run| {
        let record = HeadRecordV2 {
            base: HeadRecord {
                number: context.number,
                timestamp: context.timestamp,
                base_fee_per_gas: context.base_fee_per_gas,
                gas_used: run.gas_used,
                prevrandao: context.prevrandao,
                anchor_root: context.anchor_root,
                parent_hash: run.parent_hash,
                deposits_hash: run.deposits_hash,
            },
            user_gas_used: cumulative,
            parent_state_root: previous_root,
            transactions_root: body.transactions_root(),
            receipts_root: calculate_receipt_root(&receipts),
            logs_bloom,
        };
        head::write_head_v2(db, spec.block_info, &record)?;
        Ok(record)
    })?;
    Ok((
        db,
        PendingOutcome {
            record,
            receipts,
            transactions: run.tx_outcomes,
        },
    ))
}

/// V2 witness generation or authenticated re-execution failed.
#[derive(Debug)]
pub enum NodeWitnessError {
    /// Signed execution failed.
    Execution(NodeExecutionError),
    /// Proof generation failed.
    Generate(crate::proving::GenerateError),
    /// Proof hydration, root reconstruction or self-check failed.
    Verify(crate::proving::VerifyError),
}
impl core::fmt::Display for NodeWitnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Execution(e) => e.fmt(f),
            Self::Generate(e) => e.fmt(f),
            Self::Verify(e) => e.fmt(f),
        }
    }
}
impl core::error::Error for NodeWitnessError {}

/// Authenticate pre-state and signed bytes, then derive the V2 post-state root.
/// The caller supplies the trusted V2 domain and authenticates L1 provenance.
/// This is a stateless verifier procedure, not a cryptographic proof backend.
pub fn verify_node_batch(
    spec: &ChainSpec,
    domain: B256,
    witness: &crate::proving::BatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
) -> Result<NodeExecutionOutcome, NodeWitnessError> {
    let hydrated = crate::proving::hydrate_and_verify(witness).map_err(NodeWitnessError::Verify)?;
    let (db, pending) = run_node_block(spec, domain, hydrated.state, witness.prev_state_root, context, body)
        .map_err(NodeWitnessError::Execution)?;
    let root = crate::proving::verify_overlay_root(witness, hydrated.pre_leaves, hydrated.view, &db)
        .map_err(NodeWitnessError::Verify)?;
    Ok(pending.finalize(spec, domain, root))
}

/// Record a sparse V2 execution witness and re-execute it before returning.
/// The pre-state is neither cloned nor mutated.
pub fn generate_node_batch_witness(
    pre: &L2State,
    spec: &ChainSpec,
    domain: B256,
    context: &BlockContext,
    body: &NodeBodyV2,
) -> Result<(crate::proving::BatchWitness, NodeExecutionOutcome), NodeWitnessError> {
    let previous_root = pre.state_root();
    let (db, pending) = run_node_block(spec, domain, CacheDB::new(pre.db()), previous_root, context, body)
        .map_err(NodeWitnessError::Execution)?;
    let witness =
        crate::proving::witness_from_overlay(pre, previous_root, &db.cache).map_err(NodeWitnessError::Generate)?;
    let outcome = pending.finalize(spec, domain, witness.new_state_root);
    let verified = verify_node_batch(spec, domain, &witness, context, body)?;
    if verified.header != outcome.header
        || verified.receipts != outcome.receipts
        || verified.transactions.len() != outcome.transactions.len()
        || !verified.transactions.iter().zip(&outcome.transactions).all(|(a, b)| {
            a.success == b.success
                && a.gas_used == b.gas_used
                && a.created_address == b.created_address
                && a.burned_wei == b.burned_wei
                && a.result == b.result
        })
    {
        return Err(NodeWitnessError::Verify(crate::proving::VerifyError::OutcomeMismatch));
    }
    Ok((witness, outcome))
}
