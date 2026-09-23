// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed composition from an authenticated source selection to settlement V1.
//!
//! This closes a coordinator-side field-copying gap. It remains a dormant host
//! capability: it does not authenticate the source authority, verify a proof,
//! assign a native transaction tag or activate consensus.

use crate::{Error, ValidatedV2Prefix};
use bloch_l2_evm::{
    native_settlement::{
        SettlementExpectationV1, SettlementPolicyV1, SettlementRegistryV1, SettlementTransactionV1,
        SETTLEMENT_PROOF_V1_BYTES,
    },
    node_primitives::NodeHeaderV2,
    proof_statement::SettlementStatementV2,
};

#[cfg(unix)]
use bloch_l2_evm::native_settlement::store::{
    SettlementStoreErrorV1, SettlementStoreMarkV1, SettlementStoreV1,
};
#[cfg(unix)]
use bloch_l2_evm::native_settlement::{AcceptedSettlementV1, SettlementProofVerifierV1};

/// Failure while framing or durably publishing one validated selection.
#[cfg(unix)]
#[derive(Debug)]
pub enum SettlementSelectionCommitErrorV1 {
    /// Exact proof bytes could not form the fixed settlement transaction.
    Candidate(Error),
    /// The CAS, kernel verification or durable store publication failed.
    Store(SettlementStoreErrorV1),
}

#[cfg(unix)]
impl core::fmt::Display for SettlementSelectionCommitErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Candidate(error) => write!(f, "settlement selection candidate rejected: {error}"),
            Self::Store(error) => write!(f, "settlement selection commit rejected: {error}"),
        }
    }
}

#[cfg(unix)]
impl std::error::Error for SettlementSelectionCommitErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Candidate(error) => Some(error),
            Self::Store(error) => Some(error),
        }
    }
}

/// Independently derived candidate input for the dormant settlement kernel.
///
/// There is no public field constructor. The exact expectation and transaction
/// can only be obtained after the selected source, L2 header, immutable policy
/// and prior accepted head agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedSettlementSelectionV1 {
    expectation: SettlementExpectationV1,
    proof_policy: alloy_primitives::B256,
}

impl ValidatedSettlementSelectionV1 {
    /// Exact kernel expectation derived by the composer.
    pub const fn expectation(&self) -> SettlementExpectationV1 {
        self.expectation
    }

    /// Build the canonical candidate transaction around exact proof bytes.
    /// Cryptographic verification still occurs inside the settlement kernel.
    pub fn transaction(
        &self,
        proof: [u8; SETTLEMENT_PROOF_V1_BYTES],
    ) -> Result<SettlementTransactionV1, Error> {
        SettlementTransactionV1::new(self.proof_policy, self.expectation.statement, proof)
            .map_err(|_| Error::Codec)
    }

    /// Verify and publish this exact selection through the durable CAS store.
    ///
    /// The caller must independently retain every returned mark. This method
    /// does not persist the source registry, authenticate a checkpoint or make
    /// the resulting local head finalized.
    #[cfg(unix)]
    pub fn verify_and_commit<V: SettlementProofVerifierV1>(
        &self,
        store: &mut SettlementStoreV1,
        expected: SettlementStoreMarkV1,
        proof: [u8; SETTLEMENT_PROOF_V1_BYTES],
        verifier: &V,
    ) -> Result<(AcceptedSettlementV1, SettlementStoreMarkV1), SettlementSelectionCommitErrorV1> {
        let transaction = self
            .transaction(proof)
            .map_err(SettlementSelectionCommitErrorV1::Candidate)?;
        store
            .verify_and_commit(expected, &transaction.encode(), &self.expectation, verifier)
            .map_err(SettlementSelectionCommitErrorV1::Store)
    }
}

impl ValidatedV2Prefix {
    /// Compose exact settlement public values without accepting any of those
    /// values from a proposer-supplied statement.
    ///
    /// The prior head is read from `registry`, not accepted as a free-standing
    /// accepted-shaped value. Source predecessor, L2 predecessor and consumed
    /// cursor are derived from that registry head.
    pub fn select_settlement_v1(
        &self,
        header: &NodeHeaderV2,
        policy: SettlementPolicyV1,
        registry: &SettlementRegistryV1,
    ) -> Result<ValidatedSettlementSelectionV1, Error> {
        let execution = self.statement();
        let anchor = self.anchor();
        let consumed = self.range();
        let policy_commitment = policy.commitment().map_err(|_| Error::Configuration)?;
        if execution.header_hash != header.hash()
            || execution.domain != header.domain
            || execution.previous_state_root != header.parent_state_root
            || header.anchor_root != anchor.block
            || self.network() != policy.network
            || self.genesis() != policy.genesis
            || execution.domain != policy.domain
            || execution.configuration != policy.configuration
            || header.chain_id != policy.chain_id
            || registry.policy_commitment() != policy_commitment
        {
            return Err(Error::Identity);
        }

        let (previous_settlement, source_predecessor) = match registry.head() {
            None => {
                if header.number != policy.first_l2_number
                    || header.parent_hash != policy.initial_l2_parent_hash
                    || header.parent_state_root != policy.initial_l2_state_root
                    || consumed.start != 0
                {
                    return Err(Error::Replay);
                }
                (alloy_primitives::B256::ZERO, alloy_primitives::B256::ZERO)
            }
            Some(head) => {
                if header.number != head.l2_number.checked_add(1).ok_or(Error::Replay)?
                    || header.parent_hash != head.l2_header_hash
                    || header.parent_state_root != head.l2_state_root
                    || consumed.start != head.consumed_end
                    || self.inbox_count() < head.inbox_count
                    || anchor.height < head.l1_height
                    || anchor.slot < head.l1_slot
                    || (anchor.height == head.l1_height
                        && (anchor.block != head.l1_block || anchor.slot != head.l1_slot))
                    || (anchor.height > head.l1_height && anchor.slot <= head.l1_slot)
                    || (self.inbox_count() == head.inbox_count && self.inbox_root() != head.inbox_root)
                {
                    return Err(Error::Replay);
                }
                (head.commitment, head.source_commitment)
            }
        };

        let statement = SettlementStatementV2 {
            network: self.network(),
            genesis: self.genesis(),
            domain: execution.domain,
            configuration: execution.configuration,
            program_elf_keccak: policy.program_elf_keccak,
            program_vkey_koalabear: policy.program_vkey_koalabear,
            program_vkey_bn254: policy.program_vkey_bn254,
            previous_settlement,
            chain_id: header.chain_id,
            l2_number: header.number,
            l2_parent_hash: header.parent_hash,
            l2_previous_state_root: header.parent_state_root,
            l2_header_hash: execution.header_hash,
            l2_state_root: header.state_root,
            l1_block: anchor.block,
            l1_slot: anchor.slot,
            l1_height: anchor.height,
            source_commitment: self.source_commitment(),
            inbox_root: self.inbox_root(),
            inbox_count: self.inbox_count(),
            consumed_start: consumed.start,
            consumed_end: consumed.end,
            body_commitment: self.body_commitment(),
        };
        SettlementStatementV2::decode(&statement.encode()).map_err(|_| Error::Configuration)?;
        Ok(ValidatedSettlementSelectionV1 {
            expectation: SettlementExpectationV1 {
                statement,
                source_predecessor,
            },
            proof_policy: policy.proof_policy,
        })
    }
}
