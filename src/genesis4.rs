// SPDX-License-Identifier: MIT OR Apache-2.0
//! Derive EVM execution context from a host-accepted Genesis-4 source block.
//!
//! This binds execution to Bloch data; it does NOT prove that Bloch accepted
//! the EVM result. The host must authenticate and persist source checkpoints.
//! Deposits stay disabled until a real Genesis-4 escrow verifier exists.

use alloc::{string::String, string::ToString, vec::Vec};
use alloy_primitives::{b256, keccak256, Bytes, B256, U256};

use crate::proving::VerifiedBatch;
use crate::state::{BLOCK_INFO_ANCHOR_ROOT_SLOT, BLOCK_INFO_FLAG_SLOT, BLOCK_INFO_TIMESTAMP_SLOT};
use crate::{verify_signed_batch, BatchWitness, BlockContext, ChainSpec, L2Header, L2State, SignedBlockInput};

/// Native Genesis-4 network profile, distinct from an EVM chain ID.
pub const NETWORK_ID: u32 = 1_228_832_244;
/// Published mainnet genesis identity. The host also pins a WS checkpoint.
pub const GENESIS_ROOT: B256 = b256!("9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415");
/// Mainnet genesis wall time, in seconds (manifest clock).
pub const GENESIS_TIME: u64 = 1_786_656_679;

/// A source reference supplied by the host's checkpoint connector.
/// Deliberately not named a proof or verified checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportedSource {
    /// Native network identity.
    pub network_id: u32,
    /// Expected genesis identity.
    pub genesis_root: B256,
    /// Genesis-4 block identity (SHA3-256 over its canonical header).
    pub block_hash: B256,
    /// Slot of the accepted source block.
    pub slot: u64,
}

/// Source boundary failure, before applying any execution result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// The source is not the configured Genesis-4 network.
    WrongNetwork,
    /// Zero hash, zero slot, or overflowing source clock.
    InvalidSource,
    /// Source time regressed, or the same slot changed its block hash.
    SourceConflict,
    /// A wallet/batch supplied deposits without authenticated escrow.
    DepositsDisabled,
    /// The batch/witness does not bind the host's expected public inputs.
    BindingMismatch,
    /// Existing signature/witness/engine validation rejected the batch.
    Verification(String),
}

impl ReportedSource {
    /// Derive time from the manifest clock, never from an RPC timestamp claim.
    pub fn timestamp(&self) -> Result<u64, SourceError> {
        if self.network_id != NETWORK_ID || self.genesis_root != GENESIS_ROOT {
            return Err(SourceError::WrongNetwork);
        }
        if self.slot == 0 || self.block_hash == B256::ZERO {
            return Err(SourceError::InvalidSource);
        }
        self.slot
            .checked_mul(30)
            .and_then(|offset| GENESIS_TIME.checked_add(offset))
            .ok_or(SourceError::InvalidSource)
    }
}

/// The documented L2 randomness derivation; this is weak, source-bound randomness.
pub fn source_prevrandao(parent_hash: B256, source_hash: B256) -> B256 {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(parent_hash.as_slice());
    bytes[32..].copy_from_slice(source_hash.as_slice());
    keccak256(bytes)
}

/// Prepare signed execution with a real source hash in EIP-4788 and the header.
/// Never import Anvil state or mint credits from a source/RPC claim here.
pub fn prepare_source_batch(
    spec: &ChainSpec,
    state: &L2State,
    source: &ReportedSource,
    transactions: Vec<Bytes>,
) -> Result<SignedBlockInput, SourceError> {
    let timestamp = source.timestamp()?;
    let head = state.head_at(spec.block_info);
    let parent_hash = match &head {
        Some(head) => {
            if timestamp < head.timestamp || (timestamp == head.timestamp && head.anchor_root != source.block_hash) {
                return Err(SourceError::SourceConflict);
            }
            L2Header::from_head(spec.chain_id, head, state.state_root()).hash()
        }
        None => B256::ZERO,
    };
    let mut context = BlockContext::next(spec, state);
    context.timestamp = timestamp;
    context.anchor_root = source.block_hash;
    context.prevrandao = source_prevrandao(parent_hash, source.block_hash);
    Ok(SignedBlockInput {
        context,
        transactions,
        deposits: Vec::new(),
    })
}

/// Re-execute a signed witness while enforcing independently supplied bindings.
/// `source`, `expected_parent_hash`, and `expected_pre_root` must come from the
/// verifier's accepted chain state, not be copied out of the untrusted witness.
pub fn verify_source_batch(
    spec: &ChainSpec,
    source: &ReportedSource,
    expected_parent_hash: B256,
    expected_pre_root: B256,
    witness: &BatchWitness,
    input: &SignedBlockInput,
) -> Result<VerifiedBatch, SourceError> {
    if !input.deposits.is_empty() {
        return Err(SourceError::DepositsDisabled);
    }
    let timestamp = source.timestamp()?;
    if witness.prev_state_root != expected_pre_root
        || input.context.timestamp != timestamp
        || input.context.anchor_root != source.block_hash
        || input.context.prevrandao != source_prevrandao(expected_parent_hash, source.block_hash)
    {
        return Err(SourceError::BindingMismatch);
    }
    let result =
        verify_signed_batch(spec, witness, input).map_err(|error| SourceError::Verification(error.to_string()))?;
    // The witness has now been authenticated and replayed. Enforce the same
    // source progression rule as preparation against its committed pre-state.
    if let Some(account) = witness
        .pre_accounts
        .iter()
        .find(|account| account.address == spec.block_info)
    {
        let slot = |key: U256| {
            account
                .storage
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, value)| *value)
                .unwrap_or(U256::ZERO)
        };
        if !slot(BLOCK_INFO_FLAG_SLOT).is_zero() {
            let before = slot(BLOCK_INFO_TIMESTAMP_SLOT);
            if U256::from(timestamp) < before
                || (U256::from(timestamp) == before
                    && B256::from(slot(BLOCK_INFO_ANCHOR_ROOT_SLOT)) != source.block_hash)
            {
                return Err(SourceError::SourceConflict);
            }
        }
    }
    if result.header.parent_hash != expected_parent_hash {
        return Err(SourceError::BindingMismatch);
    }
    Ok(result)
}
