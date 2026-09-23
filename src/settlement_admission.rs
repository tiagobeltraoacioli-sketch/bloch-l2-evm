// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fail-closed composition of authenticated native inclusion and settlement V1.
//!
//! [`AuthenticatedTransactionInclusion`] proves only that exact bytes occur at
//! one position below an externally supplied checkpoint.  This adapter consumes
//! that non-cloneable capability, checks an independently selected admission
//! expectation, and only then invokes the dormant [`SettlementRegistryV1`]
//! transition kernel.  It does not authenticate checkpoint authority and does
//! not turn inclusion into L1 or L2 finality.

use crate::l1::{AuthenticatedTransactionInclusion, FinalizedCheckpoint};
use crate::native_settlement::{
    AcceptedSettlementV1, SettlementError, SettlementExpectationV1, SettlementPolicyV1, SettlementProofVerifierV1,
    SettlementRegistryV1, SettlementTransactionV1,
};
use alloy_primitives::B256;
use sha3::{Digest, Sha3_256};

/// Native inclusion coordinates independently selected for one settlement.
///
/// This is plain data, not an authentication capability.  The embedding
/// consensus implementation must derive it from committed native state rather
/// than copy it from an RPC response or transaction proposer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementAdmissionExpectationV1 {
    /// Expected kernel statement and predecessor.
    pub settlement: SettlementExpectationV1,
    /// Exact native block containing the settlement transaction.
    pub block: B256,
    /// Consensus slot of `block`; this is not a native block height.
    pub slot: u64,
    /// Exact external checkpoint terminating the authenticated ancestry path.
    pub checkpoint: FinalizedCheckpoint,
    /// Exact zero-based transaction position in the complete body.
    pub transaction_index: u32,
}

/// Accepted composition record retained by [`SettlementAdmissionRegistryV1`].
///
/// The record binds kernel acceptance to exact inclusion coordinates.  Its
/// presence is still not a finality capability: checkpoint authority,
/// consensus execution, durable storage and reorg handling remain external.
#[derive(Debug, PartialEq, Eq)]
pub struct AcceptedSettlementAdmissionV1 {
    settlement: AcceptedSettlementV1,
    block: B256,
    slot: u64,
    checkpoint: FinalizedCheckpoint,
    transaction_index: u32,
    admission_commitment: B256,
}

impl AcceptedSettlementAdmissionV1 {
    /// Settlement accepted by the deterministic kernel.
    pub const fn settlement(&self) -> &AcceptedSettlementV1 {
        &self.settlement
    }

    /// Exact authenticated native block.
    pub const fn block(&self) -> B256 {
        self.block
    }

    /// Exact native consensus slot.
    pub const fn slot(&self) -> u64 {
        self.slot
    }

    /// External checkpoint at which the ancestry proof terminated.
    pub const fn checkpoint(&self) -> FinalizedCheckpoint {
        self.checkpoint
    }

    /// Exact transaction position in the authenticated complete body.
    pub const fn transaction_index(&self) -> u32 {
        self.transaction_index
    }

    /// Domain-separated commitment to settlement and inclusion coordinates.
    pub const fn admission_commitment(&self) -> B256 {
        self.admission_commitment
    }
}

/// In-memory composition boundary for exact inclusion and settlement V1.
///
/// The inner registry is deliberately not exposed mutably, so its head cannot
/// advance without a matching authenticated admission record.
#[derive(Debug)]
pub struct SettlementAdmissionRegistryV1 {
    settlement: SettlementRegistryV1,
    head: Option<AcceptedSettlementAdmissionV1>,
}

impl SettlementAdmissionRegistryV1 {
    /// Create an empty adapter under one immutable settlement policy.
    pub fn new(policy: SettlementPolicyV1) -> Result<Self, SettlementAdmissionErrorV1> {
        Ok(Self {
            settlement: SettlementRegistryV1::new(policy).map_err(SettlementAdmissionErrorV1::Settlement)?,
            head: None,
        })
    }

    /// Current included settlement head, if any.
    pub const fn head(&self) -> Option<&AcceptedSettlementAdmissionV1> {
        self.head.as_ref()
    }

    /// Commitment to both the kernel state and its inclusion admission record.
    ///
    /// This does not assign a Genesis-4 state key or prove durable persistence.
    pub fn state_commitment(&self) -> B256 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BLOCH:EXPERIMENTAL:SETTLEMENT-ADMISSION-STATE:1");
        hasher.update(self.settlement.state_commitment());
        match &self.head {
            None => hasher.update([0]),
            Some(head) => {
                hasher.update([1]);
                hasher.update(head.admission_commitment);
            }
        }
        B256::from_slice(&hasher.finalize())
    }

    /// Consume one authenticated inclusion and atomically admit its exact V1
    /// transaction through the settlement kernel.
    ///
    /// Every inclusion coordinate must equal the independently selected
    /// expectation. The statement's source anchor remains a separate field: it
    /// cannot equal the containing block without a circular block/body hash.
    /// The admission commitment binds both facts without conflating them. No
    /// fallible step follows mutation of the inner registry.
    pub fn verify_inclusion_and_apply<V: SettlementProofVerifierV1>(
        &mut self,
        inclusion: AuthenticatedTransactionInclusion,
        expectation: &SettlementAdmissionExpectationV1,
        verifier: &V,
    ) -> Result<&AcceptedSettlementAdmissionV1, SettlementAdmissionErrorV1> {
        if inclusion.block() != expectation.block
            || inclusion.slot() != expectation.slot
            || inclusion.checkpoint() != expectation.checkpoint
            || inclusion.transaction_index() != expectation.transaction_index
        {
            return Err(SettlementAdmissionErrorV1::InclusionExpectation);
        }

        let transaction =
            SettlementTransactionV1::decode(inclusion.transaction()).map_err(SettlementAdmissionErrorV1::Codec)?;
        // The V1 codec is fixed-width today. Keep the explicit round-trip check
        // here so a future decoder relaxation cannot silently weaken admission.
        if transaction.encode().as_slice() != inclusion.transaction() {
            return Err(SettlementAdmissionErrorV1::NonCanonicalEncoding);
        }
        if transaction.statement().l1_block == inclusion.block() || transaction.statement().l1_slot >= inclusion.slot()
        {
            return Err(SettlementAdmissionErrorV1::SourceAnchor);
        }
        let exact_transaction = inclusion.transaction();
        let accepted = self
            .settlement
            .verify_and_apply(exact_transaction, &expectation.settlement, verifier)
            .map_err(SettlementAdmissionErrorV1::Settlement)?;

        let admission_commitment = admission_commitment(&accepted, &inclusion);
        self.head = Some(AcceptedSettlementAdmissionV1 {
            settlement: accepted,
            block: inclusion.block(),
            slot: inclusion.slot(),
            checkpoint: inclusion.checkpoint(),
            transaction_index: inclusion.transaction_index(),
            admission_commitment,
        });
        // Assignment above and borrowing below are infallible; kernel and
        // adapter publication therefore occur as one logical operation.
        Ok(self.head.as_ref().expect("head was assigned immediately above"))
    }
}

fn admission_commitment(accepted: &AcceptedSettlementV1, inclusion: &AuthenticatedTransactionInclusion) -> B256 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BLOCH:EXPERIMENTAL:SETTLEMENT-ADMISSION:1");
    hasher.update(accepted.commitment);
    hasher.update(inclusion.block());
    hasher.update(inclusion.slot().to_le_bytes());
    hasher.update(inclusion.checkpoint().block);
    hasher.update(inclusion.checkpoint().slot.to_le_bytes());
    hasher.update(inclusion.transaction_index().to_le_bytes());
    hasher.update((inclusion.transaction().len() as u64).to_le_bytes());
    hasher.update(inclusion.transaction());
    B256::from_slice(&hasher.finalize())
}

/// Rejection at the inclusion-to-settlement trust boundary.
#[derive(Debug)]
pub enum SettlementAdmissionErrorV1 {
    /// Authenticated coordinates differ from independently selected values.
    InclusionExpectation,
    /// Exact included bytes are not a settlement V1 transaction.
    Codec(SettlementError),
    /// Decode/re-encode changed bytes, so the transaction is not canonical.
    NonCanonicalEncoding,
    /// The source anchor is not strictly earlier than the containing block.
    SourceAnchor,
    /// The settlement kernel rejected policy, expectation, transition or proof.
    Settlement(SettlementError),
}

impl core::fmt::Display for SettlementAdmissionErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InclusionExpectation => f.write_str("authenticated inclusion differs from admission expectation"),
            Self::Codec(error) => write!(f, "included bytes are not canonical settlement V1: {error}"),
            Self::NonCanonicalEncoding => f.write_str("settlement V1 decode/re-encode mismatch"),
            Self::SourceAnchor => f.write_str("settlement source anchor must precede the containing native block"),
            Self::Settlement(error) => write!(f, "settlement kernel rejected admission: {error}"),
        }
    }
}

impl core::error::Error for SettlementAdmissionErrorV1 {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Codec(error) | Self::Settlement(error) => Some(error),
            _ => None,
        }
    }
}
