// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bind a real hybrid-PQ checkpoint capability to exact settlement inclusion.
//! This authenticates the configured weak-subjectivity authority; it is not an
//! independent proof of historical FFG or organizational independence.

use crate::checkpoint::VerifiedCheckpoint;
use alloy_primitives::B256;
use bloch_l2_evm::{
    l1::{L1Error, TransactionInclusionEvidenceV1},
    settlement_admission::{
        authenticate_settlement_inclusion, AuthenticatedSettlementInclusionV1, SettlementAdmissionErrorV1,
        SettlementAdmissionExpectationV1,
    },
};
use sha3::{Digest, Sha3_256};

const AUTHORITY_RECEIPT_TAG: &[u8; 8] = b"BLCPAU01";
/// Exact fixed-width transport for checkpoint-authority audit data.
pub const CHECKPOINT_AUTHORITY_RECEIPT_V1_BYTES: usize = 8 + 32 + 32 + 8 + 8 + 32 + 8 + 1;

/// Failure before a PQ-authority-bound settlement capability can exist.
#[derive(Debug)]
pub enum SettlementAuthorityErrorV1 {
    /// The signed checkpoint and retained ancestry name different anchors.
    Checkpoint,
    /// The independently selected transaction position is outside the body.
    TransactionIndex,
    /// Complete ancestry/body or exact-byte authentication failed.
    Inclusion(L1Error),
    /// Exact settlement codec, coordinates or statement did not match.
    Admission(SettlementAdmissionErrorV1),
    /// Authority receipt framing or required identity was invalid.
    Receipt,
}

/// Audit identity of the real PQ verification that authorized one checkpoint.
/// It is meaningful only with the independently retained checkpoint history and
/// policy; encoding these fields alone cannot recreate signature verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointAuthorityReceiptV1 {
    policy_identity: B256,
    checkpoint_digest: B256,
    checkpoint_epoch: u64,
    checked_at_epoch: u64,
    checkpoint_block: B256,
    checkpoint_slot: u64,
    arrangement_review_due: bool,
}

impl CheckpointAuthorityReceiptV1 {
    pub const fn policy_identity(&self) -> B256 {
        self.policy_identity
    }
    pub const fn checkpoint_digest(&self) -> B256 {
        self.checkpoint_digest
    }
    pub const fn checkpoint_epoch(&self) -> u64 {
        self.checkpoint_epoch
    }
    pub const fn checked_at_epoch(&self) -> u64 {
        self.checked_at_epoch
    }
    pub const fn checkpoint_block(&self) -> B256 {
        self.checkpoint_block
    }
    pub const fn checkpoint_slot(&self) -> u64 {
        self.checkpoint_slot
    }
    pub const fn arrangement_review_due(&self) -> bool {
        self.arrangement_review_due
    }
    /// Fixed-width audit transport. Decoding this value does not recreate PQ
    /// verification or an authority capability.
    pub fn encode(&self) -> [u8; CHECKPOINT_AUTHORITY_RECEIPT_V1_BYTES] {
        let mut bytes = [0u8; CHECKPOINT_AUTHORITY_RECEIPT_V1_BYTES];
        bytes[..8].copy_from_slice(AUTHORITY_RECEIPT_TAG);
        bytes[8..40].copy_from_slice(self.policy_identity.as_slice());
        bytes[40..72].copy_from_slice(self.checkpoint_digest.as_slice());
        bytes[72..80].copy_from_slice(&self.checkpoint_epoch.to_le_bytes());
        bytes[80..88].copy_from_slice(&self.checked_at_epoch.to_le_bytes());
        bytes[88..120].copy_from_slice(self.checkpoint_block.as_slice());
        bytes[120..128].copy_from_slice(&self.checkpoint_slot.to_le_bytes());
        bytes[128] = u8::from(self.arrangement_review_due);
        bytes
    }
    /// Decode audit data only. Callers must cross-check the independently
    /// retained signed checkpoint store before relying on these fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, SettlementAuthorityErrorV1> {
        if bytes.len() != CHECKPOINT_AUTHORITY_RECEIPT_V1_BYTES || &bytes[..8] != AUTHORITY_RECEIPT_TAG {
            return Err(SettlementAuthorityErrorV1::Receipt);
        }
        let value = Self {
            policy_identity: B256::from_slice(&bytes[8..40]),
            checkpoint_digest: B256::from_slice(&bytes[40..72]),
            checkpoint_epoch: u64::from_le_bytes(
                bytes[72..80]
                    .try_into()
                    .map_err(|_| SettlementAuthorityErrorV1::Receipt)?,
            ),
            checked_at_epoch: u64::from_le_bytes(
                bytes[80..88]
                    .try_into()
                    .map_err(|_| SettlementAuthorityErrorV1::Receipt)?,
            ),
            checkpoint_block: B256::from_slice(&bytes[88..120]),
            checkpoint_slot: u64::from_le_bytes(
                bytes[120..128]
                    .try_into()
                    .map_err(|_| SettlementAuthorityErrorV1::Receipt)?,
            ),
            arrangement_review_due: match bytes[128] {
                0 => false,
                1 => true,
                _ => return Err(SettlementAuthorityErrorV1::Receipt),
            },
        };
        if value.policy_identity == B256::ZERO
            || value.checkpoint_digest == B256::ZERO
            || value.checkpoint_block == B256::ZERO
            || value.checked_at_epoch < value.checkpoint_epoch
        {
            return Err(SettlementAuthorityErrorV1::Receipt);
        }
        Ok(value)
    }
    /// Domain-separated identity for later atomic persistence with settlement.
    pub fn commitment(&self) -> B256 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BLOCH:EXPERIMENTAL:SETTLEMENT-CHECKPOINT-AUTHORITY:1");
        hasher.update((CHECKPOINT_AUTHORITY_RECEIPT_V1_BYTES as u64).to_le_bytes());
        hasher.update(self.encode());
        B256::from_slice(&hasher.finalize())
    }
}

/// Non-cloneable composition of PQ checkpoint authority, complete ancestry/body
/// evidence and exact settlement inclusion.
#[derive(Debug)]
pub struct AuthorityBoundSettlementEvidenceV1 {
    inclusion: AuthenticatedSettlementInclusionV1,
    evidence: TransactionInclusionEvidenceV1,
    authority: CheckpointAuthorityReceiptV1,
}

impl AuthorityBoundSettlementEvidenceV1 {
    pub const fn inclusion(&self) -> &AuthenticatedSettlementInclusionV1 {
        &self.inclusion
    }
    pub const fn evidence(&self) -> &TransactionInclusionEvidenceV1 {
        &self.evidence
    }
    pub const fn authority(&self) -> &CheckpointAuthorityReceiptV1 {
        &self.authority
    }
    /// Consume the authority-bound package for the durable settlement composer.
    pub fn into_parts(
        self,
    ) -> (
        AuthenticatedSettlementInclusionV1,
        TransactionInclusionEvidenceV1,
        CheckpointAuthorityReceiptV1,
    ) {
        (self.inclusion, self.evidence, self.authority)
    }
}

/// Compose only after real PQ quorum/header/freshness verification produced
/// `checkpoint`. The selected body index is read from the independent admission
/// expectation and exact-byte uniqueness is rechecked against the full body.
pub fn bind_settlement_checkpoint_authority(
    checkpoint: VerifiedCheckpoint,
    evidence: TransactionInclusionEvidenceV1,
    expectation: &SettlementAdmissionExpectationV1,
) -> Result<AuthorityBoundSettlementEvidenceV1, SettlementAuthorityErrorV1> {
    if checkpoint.anchor() != evidence.checkpoint() || expectation.checkpoint != checkpoint.anchor() {
        return Err(SettlementAuthorityErrorV1::Checkpoint);
    }
    let transaction = evidence
        .transactions()
        .get(expectation.transaction_index as usize)
        .ok_or(SettlementAuthorityErrorV1::TransactionIndex)?;
    let exact = evidence
        .authenticate_exact(transaction)
        .map_err(SettlementAuthorityErrorV1::Inclusion)?;
    let inclusion =
        authenticate_settlement_inclusion(exact, expectation).map_err(SettlementAuthorityErrorV1::Admission)?;
    let anchor = checkpoint.anchor();
    let authority = CheckpointAuthorityReceiptV1 {
        policy_identity: checkpoint.policy_identity(),
        checkpoint_digest: checkpoint.digest(),
        checkpoint_epoch: checkpoint.epoch(),
        checked_at_epoch: checkpoint.checked_at_epoch(),
        checkpoint_block: anchor.block,
        checkpoint_slot: anchor.slot,
        arrangement_review_due: checkpoint.arrangement_review_due(),
    };
    Ok(AuthorityBoundSettlementEvidenceV1 {
        inclusion,
        evidence,
        authority,
    })
}
