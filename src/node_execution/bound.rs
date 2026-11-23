// SPDX-License-Identifier: MIT OR Apache-2.0
//! Settlement V3 with a block context the statement determines (audit
//! AUDIT-L1L2-20261123, finding L2N-01).
//!
//! [`crate::proof_statement::execute_settlement_statement_v3`] accepts any
//! `timestamp >= parent` and any `prevrandao`. Both are written to the
//! committed head record, so they shape the post-state root, and neither is a
//! statement field: a prover could settle a block whose state nobody else can
//! rebuild. The functions here refuse every context except the one derived
//! from values the native chain already compares with its own state:
//!
//! * `timestamp = max(parent.timestamp + 1, l1_genesis_time + l1_slot *
//!   l1_slot_millis / 1000)`, with `l1_slot` the statement's anchor slot. This
//!   is the rule every honest builder and rebuilder already applies
//!   (`--timestamp-rule 1:GENESIS:SLOT_MS`);
//! * `prevrandao`: the constant [`LEGACY_PREVRANDAO`] every honest block
//!   carries today, or, from the compiled block number
//!   [`SettlementContextRule::derived_prevrandao_from`] on,
//!   `keccak256(l2_parent_hash || l1_block)` (the design's value, see
//!   [`crate::BlockContext::prevrandao`]).
//!
//! With the rule, a V3 statement has exactly one valid block: number and base
//! fee follow the parent, the anchor and the deposits are L1-checked, the user
//! transactions are the published DA batch, and the context is derived. The
//! 766-byte statement is unchanged.
//!
//! This is a different program from `settlement_v3_mainnet`: a guest that
//! calls [`execute_settlement_statement_v3_bound`] has its own ELF and
//! verifying keys, which the native chain must pin before it protects
//! anything. Nothing here changes what the existing programs accept; the
//! module only adds code, so their compiled paths are untouched.

use super::{head, run_node_block, NodeExecutionError, NodeExecutionOutcome, NodeWitnessError};
use crate::{
    chainspec::{GENESIS4_SLOT_MS, MAINNET_GENESIS_TIMESTAMP},
    node_primitives::NodeBodyV2,
    proof_statement::{
        configuration_commitment, SettlementContextV2, SettlementStatementV2Error, SettlementStatementV3,
    },
    proving::BatchWitness,
    BlockContext, ChainSpec,
};
use alloy_primitives::{keccak256, B256};
use revm::database::CacheDB;

/// `prevrandao` of every block built by the node software up to and including
/// release `bloch-l2-2026-11-17-launch-native-906336fd` (`bloch-l2-produce-dev
/// extend|reconstruct`).
pub const LEGACY_PREVRANDAO: B256 = B256::repeat_byte(7);

/// Block number from which the mainnet rule derives `prevrandao` from the
/// parent hash and the anchor. `u64::MAX`: never; every block keeps
/// [`LEGACY_PREVRANDAO`], which is what honest nodes produce today, so the
/// bound program accepts the honest chain byte for byte whenever the native
/// chain switches to it. Lowering it is a program upgrade (a new ELF) and must
/// be done together with the node release that builds blocks with the derived
/// value from the same number.
pub const MAINNET_DERIVED_PREVRANDAO_FROM_BLOCK: u64 = u64::MAX;

/// Compiled program parameters that fix the block context of a settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementContextRule {
    /// Unix seconds of native slot 0.
    pub l1_genesis_time: u64,
    /// Native slot duration in milliseconds (non-zero).
    pub l1_slot_millis: u64,
    /// First L2 block whose `prevrandao` is `keccak256(parent_hash ||
    /// l1_block)`; earlier blocks carry [`LEGACY_PREVRANDAO`].
    pub derived_prevrandao_from: u64,
}

/// A block context that is not the derived one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextRuleError {
    /// The rule has a zero slot duration.
    Rule,
    /// The derived timestamp does not fit in 64 bits.
    Overflow,
    /// `timestamp` differs from the derived value.
    Timestamp {
        /// Value the rule derives.
        expected: u64,
        /// Value the prover supplied.
        got: u64,
    },
    /// `prevrandao` differs from the derived value.
    Prevrandao {
        /// Value the rule derives.
        expected: B256,
        /// Value the prover supplied.
        got: B256,
    },
}
impl core::fmt::Display for ContextRuleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rule => f.write_str("settlement context rule has a zero slot duration"),
            Self::Overflow => f.write_str("derived L2 timestamp overflows"),
            Self::Timestamp { expected, got } => {
                write!(f, "block timestamp {got} is not the derived timestamp {expected}")
            }
            Self::Prevrandao { expected, got } => {
                write!(f, "block prevrandao {got} is not the derived prevrandao {expected}")
            }
        }
    }
}
impl core::error::Error for ContextRuleError {}

impl SettlementContextRule {
    /// The Bloch L2 mainnet rule: L2 time follows the anchored native slot
    /// from block 1 (`--timestamp-rule 1:1786656679:30000`).
    pub const fn mainnet() -> Self {
        Self {
            l1_genesis_time: MAINNET_GENESIS_TIMESTAMP,
            l1_slot_millis: GENESIS4_SLOT_MS,
            derived_prevrandao_from: MAINNET_DERIVED_PREVRANDAO_FROM_BLOCK,
        }
    }

    /// Start time (unix seconds) of native slot `slot`.
    pub fn l1_time(&self, slot: u64) -> Option<u64> {
        self.l1_genesis_time
            .checked_add(slot.checked_mul(self.l1_slot_millis)? / 1000)
    }

    /// Timestamp of a block on a parent stamped `parent_timestamp`, anchored
    /// to native slot `l1_slot`: the slot's start time, never less than the
    /// parent's timestamp plus one.
    pub fn timestamp(&self, parent_timestamp: u64, l1_slot: u64) -> Option<u64> {
        Some(parent_timestamp.checked_add(1)?.max(self.l1_time(l1_slot)?))
    }

    /// `prevrandao` of block `number` on parent `parent_hash`, anchored to
    /// native block `l1_block`.
    pub fn prevrandao(&self, number: u64, parent_hash: B256, l1_block: B256) -> B256 {
        if number < self.derived_prevrandao_from {
            return LEGACY_PREVRANDAO;
        }
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(parent_hash.as_slice());
        preimage[32..].copy_from_slice(l1_block.as_slice());
        keccak256(preimage)
    }

    /// Refuse `context` unless its timestamp and prevrandao are the derived
    /// ones. `context.number` and `context.anchor_root` are taken as given:
    /// execution compares the number with the parent, and the statement
    /// publishes the anchor as `l1_block`, which the native chain compares
    /// with the block it pinned.
    pub fn check(
        &self,
        context: &BlockContext,
        parent_timestamp: u64,
        parent_hash: B256,
        l1_slot: u64,
    ) -> Result<(), ContextRuleError> {
        if self.l1_slot_millis == 0 {
            return Err(ContextRuleError::Rule);
        }
        let expected = self
            .timestamp(parent_timestamp, l1_slot)
            .ok_or(ContextRuleError::Overflow)?;
        if context.timestamp != expected {
            return Err(ContextRuleError::Timestamp {
                expected,
                got: context.timestamp,
            });
        }
        let expected = self.prevrandao(context.number, parent_hash, context.anchor_root);
        if context.prevrandao != expected {
            return Err(ContextRuleError::Prevrandao {
                expected,
                got: context.prevrandao,
            });
        }
        Ok(())
    }
}

/// Failure of the bound settlement path.
#[derive(Debug)]
pub enum BoundSettlementError {
    /// The prover's context is not the derived one.
    Context(ContextRuleError),
    /// Witness authentication or execution failed.
    Witness(NodeWitnessError),
    /// The executed block does not form a settlement statement.
    Statement(SettlementStatementV2Error),
}
impl core::fmt::Display for BoundSettlementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Context(e) => e.fmt(f),
            Self::Witness(e) => e.fmt(f),
            Self::Statement(e) => e.fmt(f),
        }
    }
}
impl core::error::Error for BoundSettlementError {}

/// [`super::verify_node_batch`] that first compares `context` with the context
/// `rule` derives from the authenticated parent head and `l1_slot`.
///
/// The parent head is read from the witnessed pre-state (the same `BLOCK_INFO`
/// reads execution makes), so its timestamp and hash are the ones under
/// `witness.prev_state_root`, not prover claims. `l1_slot` must be the anchor
/// slot the caller commits to the statement.
pub fn verify_node_batch_bound(
    spec: &ChainSpec,
    domain: B256,
    rule: &SettlementContextRule,
    l1_slot: u64,
    witness: &BatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
) -> Result<NodeExecutionOutcome, BoundSettlementError> {
    let witness_error = |error| BoundSettlementError::Witness(NodeWitnessError::Verify(error));
    let execution_error =
        |error| BoundSettlementError::Witness(NodeWitnessError::Execution(NodeExecutionError::Execution(error)));
    let hydrated = crate::proving::hydrate_and_verify(witness).map_err(witness_error)?;
    {
        let mut view = CacheDB::new(&hydrated.state);
        let parent = head::read_head_v2(&mut view, spec.block_info)
            .map_err(execution_error)?
            .header(spec, domain, witness.prev_state_root);
        rule.check(context, parent.timestamp, parent.hash(), l1_slot)
            .map_err(BoundSettlementError::Context)?;
    }
    let (db, pending) = run_node_block(spec, domain, hydrated.state, witness.prev_state_root, context, body)
        .map_err(|error| BoundSettlementError::Witness(NodeWitnessError::Execution(error)))?;
    let root =
        crate::proving::verify_overlay_root(witness, hydrated.pre_leaves, hydrated.view, &db).map_err(witness_error)?;
    Ok(pending.finalize(spec, domain, root))
}

/// [`crate::proof_statement::execute_settlement_statement_v3`] for a program
/// that fixes the block context: same inputs, same 766-byte statement, but a
/// context other than the one `rule` derives from the parent head and
/// `settlement.l1_slot` is refused before execution.
pub fn execute_settlement_statement_v3_bound(
    spec: &ChainSpec,
    domain: B256,
    rule: &SettlementContextRule,
    witness: &BatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
    settlement: SettlementContextV2,
) -> Result<SettlementStatementV3, BoundSettlementError> {
    let outcome = verify_node_batch_bound(spec, domain, rule, settlement.l1_slot, witness, context, body)?;
    let configuration = configuration_commitment(spec).map_err(|error| {
        BoundSettlementError::Witness(NodeWitnessError::Execution(NodeExecutionError::Execution(
            crate::BlockExecutionError::InvalidChainSpec(error),
        )))
    })?;
    let withdrawals = outcome
        .withdrawals
        .as_ref()
        .map(|summary| summary.commitment)
        .ok_or(BoundSettlementError::Statement(SettlementStatementV2Error::Withdrawals))?;
    SettlementStatementV3::from_executed(configuration, &outcome.header, body, settlement, withdrawals)
        .map_err(BoundSettlementError::Statement)
}
