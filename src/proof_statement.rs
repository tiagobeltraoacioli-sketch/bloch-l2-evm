// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical public statement for V2 stateless execution.
//!
//! This module supplies neither a cryptographic proof nor L1 authentication.
//! A proof backend must authenticate its pinned guest/program identity before
//! passing authenticated public bytes to [`ExecutionStatement::check_expected`].
//! The expected statement must come from independently trusted configuration,
//! parent state and canonical block selection, never from the prover's claims.
//!
//! The guest commits [`execute_statement`]'s exact [`ExecutionStatement::encode`]
//! bytes. A host verifier first checks a cryptographic proof against a trusted
//! guest verification key, then compares its public bytes to the independently
//! expected statement. Neither deserialization nor successful re-execution
//! replaces that proof check. The header commitment covers context, ordered
//! deposits, transactions, receipts and post-state through the full V2 format.
//! Whether those deposits are authorized by finalized L1 remains a separate
//! derivation/consensus check outside this execution statement.

use crate::{
    node_execution::{verify_node_batch, NodeWitnessError},
    node_primitives::NodeBodyV2,
    proving::BatchWitness,
    BlockContext, ChainSpec, ChainSpecError,
};
use alloc::vec::Vec;
use alloy_primitives::{keccak256, B256};

/// Domain separator and wire version; independent of the V2 header version.
pub const STATEMENT_TAG: &[u8] = b"BLOCH:EVM:EXECUTION:1";
/// Exact byte length: tag followed by four 32-byte commitments in field order.
pub const STATEMENT_LEN: usize = STATEMENT_TAG.len() + 128;

/// Hash every validated configuration field using a fixed-width, tagged layout.
/// Integers are big-endian, addresses are raw 20 bytes, reward is 32 bytes.
/// Cancun is named explicitly, never encoded using a dependency's enum ordinal.
/// The layout is ASCII `BLOCH:EVM:CONFIG:1:CANCUN`, then chain ID, gas limit,
/// block time, elasticity, denominator, initial base fee (six u64s), reward,
/// base-fee vault, sequencer vault, supply ledger, block-info address, maximum
/// L1 sats and deposit gas (two u64s). Changing this layout requires a new tag.
pub fn configuration_commitment(spec: &ChainSpec) -> Result<B256, ChainSpecError> {
    spec.validate()?;
    // Exhaustive destructuring makes new configuration fields a compile error.
    let ChainSpec {
        chain_id,
        spec_id: _,
        gas_limit,
        block_time_secs,
        base_fee_elasticity,
        base_fee_denominator,
        initial_base_fee,
        block_reward,
        base_fee_vault,
        sequencer_fee_vault,
        supply_ledger,
        block_info,
        max_l1_sats,
        deposit_gas,
    } = spec;
    let mut bytes = Vec::from(&b"BLOCH:EVM:CONFIG:1:CANCUN"[..]);
    for value in [
        chain_id,
        gas_limit,
        block_time_secs,
        base_fee_elasticity,
        base_fee_denominator,
        initial_base_fee,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&block_reward.to_be_bytes::<32>());
    for address in [base_fee_vault, sequencer_fee_vault, supply_ledger, block_info] {
        bytes.extend_from_slice(address.as_slice());
    }
    for value in [max_l1_sats, deposit_gas] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    Ok(keccak256(bytes))
}

/// Public commitments to the complete configuration and executed transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionStatement {
    /// Tagged commitment to all validated chain parameters.
    pub configuration: B256,
    /// Separately configured V2 execution domain.
    pub domain: B256,
    /// Authenticated pre-state root.
    pub previous_state_root: B256,
    /// Full tagged V2 header hash, including post-state, body and receipt roots.
    pub header_hash: B256,
}

/// Invalid public encoding or mismatch with an independently expected statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementError {
    /// Wrong length, tag or version, including any trailing bytes.
    Encoding,
    /// At least one commitment differs from the trusted expectation.
    Mismatch,
}
impl core::fmt::Display for StatementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Encoding => "invalid execution statement encoding",
            Self::Mismatch => "execution statement differs from trusted expectation",
        })
    }
}
impl core::error::Error for StatementError {}

impl ExecutionStatement {
    /// Encode exactly the tagged, fixed-width public statement.
    pub fn encode(&self) -> [u8; STATEMENT_LEN] {
        let mut bytes = [0; STATEMENT_LEN];
        bytes[..STATEMENT_TAG.len()].copy_from_slice(STATEMENT_TAG);
        for (chunk, value) in bytes[STATEMENT_TAG.len()..].chunks_exact_mut(32).zip([
            self.configuration,
            self.domain,
            self.previous_state_root,
            self.header_hash,
        ]) {
            chunk.copy_from_slice(value.as_slice());
        }
        bytes
    }

    /// Strict decoding; this checks syntax only, not proof or execution validity.
    pub fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        if bytes.len() != STATEMENT_LEN || !bytes.starts_with(STATEMENT_TAG) {
            return Err(StatementError::Encoding);
        }
        let field = |index: usize| {
            B256::from_slice(&bytes[STATEMENT_TAG.len() + index * 32..STATEMENT_TAG.len() + (index + 1) * 32])
        };
        Ok(Self {
            configuration: field(0),
            domain: field(1),
            previous_state_root: field(2),
            header_hash: field(3),
        })
    }

    /// Compare proof-authenticated public bytes with this trusted expectation.
    /// Calling this on unauthenticated bytes does not verify a proof.
    pub fn check_expected(&self, authenticated_public_bytes: &[u8]) -> Result<(), StatementError> {
        if Self::decode(authenticated_public_bytes)? != *self {
            return Err(StatementError::Mismatch);
        }
        Ok(())
    }
}

/// Run the actual sparse-witness V2 verifier and derive its public statement.
/// Witness roots are checked by execution; no caller-supplied outcome is used.
pub fn execute_statement(
    spec: &ChainSpec,
    domain: B256,
    witness: &BatchWitness,
    context: &BlockContext,
    body: &NodeBodyV2,
) -> Result<ExecutionStatement, NodeWitnessError> {
    let outcome = verify_node_batch(spec, domain, witness, context, body)?;
    // Execution already validated the configuration; propagate its error shape.
    let configuration = configuration_commitment(spec).map_err(|error| {
        NodeWitnessError::Execution(crate::node_execution::NodeExecutionError::Execution(
            crate::BlockExecutionError::InvalidChainSpec(error),
        ))
    })?;
    Ok(ExecutionStatement {
        configuration,
        domain,
        previous_state_root: witness.prev_state_root,
        header_hash: outcome.header.hash(),
    })
}
