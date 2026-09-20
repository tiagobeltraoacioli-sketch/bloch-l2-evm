// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bind an L2 header to authenticated native-L1 ancestry without calling it L2 finality.
//!
//! An L2 block can reference a native block that is an ancestor of an externally
//! authenticated finalized checkpoint. That proves the L1 context selected by
//! the L2 header; it does **not** prove that the L2 block itself was committed to
//! or accepted by native consensus.

use crate::{l1::AuthenticatedAncestry, node_primitives::NodeHeaderV2};
use alloy_primitives::B256;

/// L2 header fields bound to a successfully authenticated native ancestry path.
/// Private fields prevent callers from manufacturing this token directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedL1Context {
    chain_id: u64,
    domain: B256,
    l2_number: u64,
    l2_block: B256,
    l2_state_root: B256,
    l1_anchor: B256,
    l1_anchor_slot: u64,
    l1_checkpoint: B256,
    l1_checkpoint_slot: u64,
}

impl AuthenticatedL1Context {
    /// EIP-155 replay domain of the bound L2 header.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    /// Execution-domain identity of the bound L2 header.
    pub fn domain(&self) -> B256 {
        self.domain
    }
    /// Sequential L2 block number.
    pub fn l2_number(&self) -> u64 {
        self.l2_number
    }
    /// Canonical V2 L2 header hash.
    pub fn l2_block(&self) -> B256 {
        self.l2_block
    }
    /// Post-state root committed by the L2 header.
    pub fn l2_state_root(&self) -> B256 {
        self.l2_state_root
    }
    /// Native block selected as the L2 execution context.
    pub fn l1_anchor(&self) -> B256 {
        self.l1_anchor
    }
    /// Consensus slot of the selected native block.
    pub fn l1_anchor_slot(&self) -> u64 {
        self.l1_anchor_slot
    }
    /// Externally authenticated native checkpoint terminating the ancestry path.
    pub fn l1_checkpoint(&self) -> B256 {
        self.l1_checkpoint
    }
    /// Consensus slot of the external checkpoint.
    pub fn l1_checkpoint_slot(&self) -> u64 {
        self.l1_checkpoint_slot
    }
}

/// A malformed or foreign L2 header cannot be bound to native ancestry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L1ContextError {
    /// Chain ID or execution domain differs from independently pinned policy.
    Identity,
    /// Genesis/zero values are not admissible as a finalized execution context.
    Genesis,
    /// The L2 header does not name the authenticated native target block.
    Anchor,
}

/// Bind a non-genesis V2 header to its exact authenticated native target.
///
/// This function deliberately has no `finalized_l2` result: native settlement
/// still needs to commit the L2 header/proof and a monotonic durable cursor.
pub fn authenticate_l1_context(
    expected_chain_id: u64,
    expected_domain: B256,
    header: &NodeHeaderV2,
    ancestry: &AuthenticatedAncestry,
) -> Result<AuthenticatedL1Context, L1ContextError> {
    if expected_chain_id == 0
        || expected_domain == B256::ZERO
        || header.chain_id != expected_chain_id
        || header.domain != expected_domain
    {
        return Err(L1ContextError::Identity);
    }
    if header.number == 0 || header.state_root == B256::ZERO || header.anchor_root == B256::ZERO {
        return Err(L1ContextError::Genesis);
    }
    if header.anchor_root != ancestry.block() {
        return Err(L1ContextError::Anchor);
    }
    let checkpoint = ancestry.checkpoint();
    Ok(AuthenticatedL1Context {
        chain_id: header.chain_id,
        domain: header.domain,
        l2_number: header.number,
        l2_block: header.hash(),
        l2_state_root: header.state_root,
        l1_anchor: ancestry.block(),
        l1_anchor_slot: ancestry.slot(),
        l1_checkpoint: checkpoint.block,
        l1_checkpoint_slot: checkpoint.slot,
    })
}
