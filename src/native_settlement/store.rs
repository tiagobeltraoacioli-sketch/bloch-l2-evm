// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fail-closed, single-host persistence for the dormant settlement registry.
//!
//! This is a local crash-recovery primitive, not consensus, HA, WORM storage,
//! finality, or an authenticated publication service. The rollback floor must
//! be retained independently from this directory.

use super::{
    AcceptedSettlementV1, SettlementError, SettlementExpectationV1, SettlementPolicyV1, SettlementProofVerifierV1,
    SettlementRegistryV1, SettlementTransactionV1, SettlementWireFormat, NATIVE_SETTLEMENT_BYTES,
    SETTLEMENT_TX_V1_BYTES,
};
use crate::{
    l1::{FinalizedCheckpoint, TransactionInclusionEvidenceV1, MAX_INCLUSION_EVIDENCE_V1_BYTES},
    settlement_admission::AuthenticatedSettlementInclusionV1,
};
use alloy_primitives::B256;
use sha3::{Digest, Sha3_256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const POLICY_TAG: &[u8; 8] = b"BLSTPL01";
const RECORD_V2_TAG: &[u8; 8] = b"BLSTRC02";
const RECORD_V3_TAG: &[u8; 8] = b"BLSTRC03";
const RECORD_V4_TAG: &[u8; 8] = b"BLSTRC04";
// V5 retains exact native bytes with canonical zero padding in the old fixed slot.
// It always carries complete inclusion evidence and an authority audit receipt.
const RECORD_V5_TAG: &[u8; 8] = b"BLSTRC05";
const MARK_TAG: &[u8; 8] = b"BLSTMK01";
const ACCEPTED_HEAD_BYTES: usize = 1 + 6 * 32 + 5 * 8;
const ADMISSION_BYTES: usize = 32 + 8 + 32 + 8 + 4 + 32;
const RECORD_BYTES: usize =
    8 + 8 + 32 + 32 + 32 + ACCEPTED_HEAD_BYTES + 1 + SETTLEMENT_TX_V1_BYTES + 1 + ADMISSION_BYTES;
/// Maximum opaque authority-audit transport retained with one settlement.
pub const MAX_SETTLEMENT_AUTHORITY_AUDIT_V1_BYTES: usize = 4096;
const MAX_RECORD_BYTES: usize =
    RECORD_BYTES + 4 + MAX_INCLUSION_EVIDENCE_V1_BYTES + 4 + MAX_SETTLEMENT_AUTHORITY_AUDIT_V1_BYTES;
/// Exact canonical byte length of an external settlement-store mark.
pub const SETTLEMENT_STORE_MARK_V1_BYTES: usize = 8 + 8 + 32 + 32;
const MAX_RECORDS: u64 = 10_000;

/// Exact independently retained rollback floor. It is not trustworthy when
/// copied from the store directory being opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementStoreMarkV1 {
    /// Snapshot generation; generation zero is the empty registry.
    pub generation: u64,
    /// Digest of the complete canonical record bytes.
    pub record_digest: B256,
    /// Registry state commitment in that record.
    pub state_commitment: B256,
}

/// Inclusion receipt retained inside the same create-once settlement record.
///
/// This is replayable audit data, not a finality capability. The header path,
/// complete body and authenticated checkpoint artifact remain external.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementStoreAdmissionV1 {
    transaction: Vec<u8>,
    block: B256,
    slot: u64,
    checkpoint: FinalizedCheckpoint,
    transaction_index: u32,
    admission_commitment: B256,
}

impl SettlementStoreAdmissionV1 {
    /// Exact canonical settlement transaction stored in the record.
    pub fn transaction(&self) -> &[u8] {
        &self.transaction
    }

    /// Native block containing the transaction.
    pub const fn block(&self) -> B256 {
        self.block
    }

    /// Native consensus slot of the containing block.
    pub const fn slot(&self) -> u64 {
        self.slot
    }

    /// External checkpoint terminating the authenticated ancestry path.
    pub const fn checkpoint(&self) -> FinalizedCheckpoint {
        self.checkpoint
    }

    /// Exact zero-based position in the authenticated complete body.
    pub const fn transaction_index(&self) -> u32 {
        self.transaction_index
    }

    /// Domain-separated commitment to the transaction and coordinates.
    pub const fn admission_commitment(&self) -> B256 {
        self.admission_commitment
    }
}

impl SettlementStoreMarkV1 {
    /// Encode a fixed-width transport for independent retention. Encoding does
    /// not authenticate the mark or make storage independent.
    pub fn encode(self) -> [u8; SETTLEMENT_STORE_MARK_V1_BYTES] {
        let mut bytes = [0u8; SETTLEMENT_STORE_MARK_V1_BYTES];
        bytes[..8].copy_from_slice(MARK_TAG);
        bytes[8..16].copy_from_slice(&self.generation.to_le_bytes());
        bytes[16..48].copy_from_slice(self.record_digest.as_slice());
        bytes[48..].copy_from_slice(self.state_commitment.as_slice());
        bytes
    }

    /// Decode exactly one canonical external-floor transport.
    pub fn decode(bytes: &[u8]) -> Result<Self, SettlementStoreErrorV1> {
        if bytes.len() != SETTLEMENT_STORE_MARK_V1_BYTES || &bytes[..8] != MARK_TAG {
            return Err(SettlementStoreErrorV1::Format);
        }
        Ok(Self {
            generation: u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| SettlementStoreErrorV1::Format)?),
            record_digest: B256::from_slice(&bytes[16..48]),
            state_commitment: B256::from_slice(&bytes[48..]),
        })
    }
}

/// Deterministic refusal or uncertain durable publication.
#[derive(Debug)]
pub enum SettlementStoreErrorV1 {
    /// Filesystem operation failed before publication began.
    Io(io::Error),
    /// Another process owns this store.
    Locked,
    /// Noncanonical, partial, unexpected, or unsafe filesystem state.
    Format,
    /// A leftover private publication inode proves a prior commit did not
    /// finish cleanly. Operator reconciliation is required; it is not ignored.
    CrashEvidence,
    /// Local bounded-history limit was exceeded.
    Limit,
    /// The supplied policy does not exactly match the store policy.
    Policy,
    /// The external floor is absent or disagrees with retained history.
    Rollback,
    /// Caller CAS mark is stale or forged.
    Cas,
    /// Native settlement verification rejected the candidate.
    Settlement(SettlementError),
    /// Complete inclusion evidence did not match the consumed capability or
    /// could not be reauthenticated.
    Evidence,
    /// A write, link, unlink, or fsync may have changed durable state. Close
    /// and reopen; blindly retrying is forbidden.
    CommitUncertain(io::Error),
    /// This handle observed an uncertain commit and cannot be used again.
    Poisoned,
}

impl From<io::Error> for SettlementStoreErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl core::fmt::Display for SettlementStoreErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "settlement store refused operation: {self:?}")
    }
}

impl std::error::Error for SettlementStoreErrorV1 {}

/// Borrowed audit data for one proof-reverified, nonempty recovery record.
///
/// The whole history and external floor have not necessarily passed yet. An
/// auditor must only validate this view, never publish it as an acknowledged
/// head or finality capability. The view contains no new checkpoint authority.
#[derive(Debug)]
pub struct SettlementReplayRecordV1<'a> {
    /// Exact record identity, not an independently retained rollback floor.
    pub mark: SettlementStoreMarkV1,
    /// Head reconstructed by the pinned execution-proof verifier and kernel.
    pub accepted: &'a AcceptedSettlementV1,
    /// Exact canonical transaction whose execution proof passed replay.
    pub transaction: &'a [u8],
    /// Native inclusion coordinates, if retained by this record version.
    pub admission: Option<&'a SettlementStoreAdmissionV1>,
    /// Reauthenticated complete native body and ancestry, if retained.
    pub evidence: Option<&'a TransactionInclusionEvidenceV1>,
    /// Opaque audit bytes requiring independent authority authentication.
    pub authority_audit: Option<&'a [u8]>,
}

/// Recovery refused by storage/proof verification or an independently supplied
/// record auditor. Neither variant returns a partially recovered store handle.
#[derive(Debug)]
pub enum SettlementStoreReplayErrorV1<E> {
    /// Storage integrity, rollback floor, resource budget or proof failure.
    Store(SettlementStoreErrorV1),
    /// The independently supplied auditor refused this nonempty record.
    Audit {
        /// First refused record generation, including records before the floor.
        generation: u64,
        /// Auditor's original refusal, without collapsing its cause.
        error: E,
    },
}

impl<E> From<SettlementStoreErrorV1> for SettlementStoreReplayErrorV1<E> {
    fn from(error: SettlementStoreErrorV1) -> Self {
        Self::Store(error)
    }
}

impl<E> From<io::Error> for SettlementStoreReplayErrorV1<E> {
    fn from(error: io::Error) -> Self {
        Self::Store(SettlementStoreErrorV1::Io(error))
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for SettlementStoreReplayErrorV1<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "settlement history recovery refused: {self:?}")
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SettlementStoreReplayErrorV1<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Store(error) => error,
            Self::Audit { error, .. } => error,
        })
    }
}

impl SettlementStoreReplayErrorV1<core::convert::Infallible> {
    fn into_store_error(self) -> SettlementStoreErrorV1 {
        match self {
            Self::Store(error) => error,
            Self::Audit { error, .. } => match error {},
        }
    }
}

/// Exclusively locked local settlement registry and append-only snapshots.
pub struct SettlementStoreV1 {
    directory: PathBuf,
    lock: File,
    registry: SettlementRegistryV1,
    mark: SettlementStoreMarkV1,
    admission: Option<SettlementStoreAdmissionV1>,
    evidence: Option<TransactionInclusionEvidenceV1>,
    authority_audit: Option<Vec<u8>>,
    poisoned: bool,
}

impl Drop for SettlementStoreV1 {
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}

impl SettlementStoreV1 {
    /// Create an owner-only store without replacing any existing path. The
    /// returned generation-zero mark must be retained outside this directory.
    pub fn create(path: impl AsRef<Path>, policy: SettlementPolicyV1) -> Result<Self, SettlementStoreErrorV1> {
        let registry = SettlementRegistryV1::new(policy).map_err(SettlementStoreErrorV1::Settlement)?;
        fs::DirBuilder::new().mode(0o700).create(path.as_ref())?;
        let directory = fs::canonicalize(path)?;
        check_private_directory(&directory)?;
        let lock = create_file(&directory.join("LOCK"))?;
        lock.try_lock().map_err(|_| SettlementStoreErrorV1::Locked)?;
        lock.sync_all()?;
        let mut policy_bytes = Vec::with_capacity(40);
        policy_bytes.extend_from_slice(POLICY_TAG);
        policy_bytes.extend_from_slice(
            policy
                .commitment()
                .map_err(SettlementStoreErrorV1::Settlement)?
                .as_slice(),
        );
        publish_create_once(&directory, "POLICY", &policy_bytes)?;
        let bytes = encode_record(
            0,
            policy,
            B256::ZERO,
            &registry,
            None,
            None,
            RecordExtensions::default(),
        )?;
        publish_create_once(&directory, &record_name(0), &bytes)?;
        directory_file(&directory)?.sync_all()?;
        directory_file(directory.parent().ok_or(SettlementStoreErrorV1::Format)?)?.sync_all()?;
        let mark = mark(0, &bytes, &registry);
        Ok(Self {
            directory,
            lock,
            registry,
            mark,
            admission: None,
            evidence: None,
            authority_audit: None,
            poisoned: false,
        })
    }

    /// Replay all canonical records under the exact policy and require the
    /// independently supplied floor to occur unchanged in that history.
    /// This structural path does not repeat execution-proof verification; use
    /// `open_verified` when recovering proof-verified execution evidence.
    pub fn open(
        path: impl AsRef<Path>,
        policy: SettlementPolicyV1,
        floor: SettlementStoreMarkV1,
    ) -> Result<Self, SettlementStoreErrorV1> {
        Self::open_inner(path, policy, floor, MAX_RECORDS, |_, _| Ok(()), |_| Ok(()))
            .map_err(SettlementStoreReplayErrorV1::into_store_error)
    }

    /// Recover while cryptographically reverifying every retained proof and
    /// policy/successor transition, including records before the external floor.
    /// The budget is checked before any proof verification. No handle escapes
    /// on refusal. This authenticates neither native source authority nor
    /// consensus activation; the verifier must be selected independently.
    pub fn open_verified<V: SettlementProofVerifierV1>(
        path: impl AsRef<Path>,
        policy: SettlementPolicyV1,
        floor: SettlementStoreMarkV1,
        maximum_proofs: u64,
        verifier: &V,
    ) -> Result<Self, SettlementStoreErrorV1> {
        Self::open_verified_with_audit(path, policy, floor, maximum_proofs, verifier, |_| Ok(()))
            .map_err(SettlementStoreReplayErrorV1::into_store_error)
    }

    /// Repeat every execution proof, then audit each nonempty record in order,
    /// including entries before the external floor. The auditor may bind the
    /// retained inclusion/authority data to a separately locked trust store.
    /// It receives each entry once after proof and record integrity checks,
    /// and never receives generation zero. Any refusal aborts recovery and
    /// releases the lock without changing persistent records. Success still
    /// establishes neither native consensus nor permission to publish finality.
    pub fn open_verified_with_audit<V: SettlementProofVerifierV1, E>(
        path: impl AsRef<Path>,
        policy: SettlementPolicyV1,
        floor: SettlementStoreMarkV1,
        maximum_proofs: u64,
        verifier: &V,
        audit: impl FnMut(SettlementReplayRecordV1<'_>) -> Result<(), E>,
    ) -> Result<Self, SettlementStoreReplayErrorV1<E>> {
        Self::open_inner(
            path,
            policy,
            floor,
            maximum_proofs,
            |registry, record| {
                if let Some(transaction) = &record.transaction {
                    let (decoded, _) = SettlementTransactionV1::decode_wire(transaction)
                        .map_err(SettlementStoreErrorV1::Settlement)?;
                    let expectation = SettlementExpectationV1 {
                        statement: *decoded.statement(),
                        source_predecessor: registry.head().map_or(B256::ZERO, |head| head.source_commitment),
                    };
                    let accepted = registry
                        .verify_and_apply(transaction, &expectation, verifier)
                        .map_err(SettlementStoreErrorV1::Settlement)?;
                    if Some(accepted) != record.head {
                        return Err(SettlementStoreErrorV1::Format);
                    }
                }
                Ok(())
            },
            audit,
        )
    }

    fn open_inner<E>(
        path: impl AsRef<Path>,
        policy: SettlementPolicyV1,
        floor: SettlementStoreMarkV1,
        maximum_proofs: u64,
        mut verify: impl FnMut(&mut SettlementRegistryV1, &DecodedRecord) -> Result<(), SettlementStoreErrorV1>,
        mut audit: impl FnMut(SettlementReplayRecordV1<'_>) -> Result<(), E>,
    ) -> Result<Self, SettlementStoreReplayErrorV1<E>> {
        if maximum_proofs > MAX_RECORDS {
            return Err(SettlementStoreErrorV1::Limit.into());
        }
        check_private_directory(path.as_ref())?;
        let directory = fs::canonicalize(path)?;
        regular_private(&directory.join("LOCK"))?;
        let lock = OpenOptions::new().read(true).write(true).open(directory.join("LOCK"))?;
        lock.try_lock().map_err(|_| SettlementStoreErrorV1::Locked)?;
        let commitment = policy.commitment().map_err(SettlementStoreErrorV1::Settlement)?;
        let expected_policy = [POLICY_TAG.as_slice(), commitment.as_slice()].concat();
        if read_exact_bounded(&directory.join("POLICY"), 40)? != expected_policy {
            return Err(SettlementStoreErrorV1::Policy.into());
        }
        let generations = record_generations(&directory)?;
        if generations.is_empty() || generations.len() > maximum_proofs as usize + 1 {
            return Err(SettlementStoreErrorV1::Limit.into());
        }
        let mut registry = SettlementRegistryV1::new(policy).map_err(SettlementStoreErrorV1::Settlement)?;
        let mut previous_digest = B256::ZERO;
        let mut previous_head = None;
        let mut found_floor = false;
        let mut current_mark = None;
        let mut current_admission = None;
        let mut current_evidence = None;
        let mut current_authority_audit = None;
        for (index, generation) in generations.into_iter().enumerate() {
            if generation != index as u64 {
                return Err(SettlementStoreErrorV1::Format.into());
            }
            let bytes = read_record_bounded(&directory.join(record_name(generation)))?;
            let decoded = decode_record(&bytes, generation, policy, previous_digest)?;
            validate_replayed_head(generation, policy, previous_head, decoded.head)?;
            if let Some(bytes) = &decoded.transaction {
                let (tx, format) =
                    SettlementTransactionV1::decode_wire(bytes).map_err(SettlementStoreErrorV1::Settlement)?;
                if format == SettlementWireFormat::NativeV1 {
                    super::check_native_source(
                        tx.statement(),
                        previous_head.map_or(B256::ZERO, |head| head.source_commitment),
                    )
                    .map_err(SettlementStoreErrorV1::Settlement)?;
                }
            }
            verify(&mut registry, &decoded)?;
            registry.head = decoded.head;
            if registry.state_commitment() != decoded.state_commitment {
                return Err(SettlementStoreErrorV1::Format.into());
            }
            let observed = mark(generation, &bytes, &registry);
            if generation == floor.generation {
                if observed != floor {
                    return Err(SettlementStoreErrorV1::Rollback.into());
                }
                found_floor = true;
            }
            if let (Some(accepted), Some(transaction)) = (&decoded.head, &decoded.transaction) {
                audit(SettlementReplayRecordV1 {
                    mark: observed,
                    accepted,
                    transaction,
                    admission: decoded.admission.as_ref(),
                    evidence: decoded.evidence.as_ref(),
                    authority_audit: decoded.authority_audit.as_deref(),
                })
                .map_err(|error| SettlementStoreReplayErrorV1::Audit { generation, error })?;
            }
            previous_digest = observed.record_digest;
            previous_head = decoded.head;
            current_admission = decoded.admission;
            current_evidence = decoded.evidence;
            current_authority_audit = decoded.authority_audit;
            current_mark = Some(observed);
        }
        if !found_floor {
            return Err(SettlementStoreErrorV1::Rollback.into());
        }
        directory_file(&directory)?.sync_all()?;
        Ok(Self {
            directory,
            lock,
            registry,
            mark: current_mark.ok_or(SettlementStoreErrorV1::Format)?,
            admission: current_admission,
            evidence: current_evidence,
            authority_audit: current_authority_audit,
            poisoned: false,
        })
    }

    /// Current externally retainable CAS/rollback mark.
    pub const fn mark(&self) -> SettlementStoreMarkV1 {
        self.mark
    }

    /// Current local registry. This value is not a finalized-L2 capability.
    pub const fn registry(&self) -> &SettlementRegistryV1 {
        &self.registry
    }

    /// Inclusion receipt on the current record, when committed through the
    /// authenticated-inclusion path.
    pub const fn admission(&self) -> Option<&SettlementStoreAdmissionV1> {
        self.admission.as_ref()
    }

    /// Complete body and ancestry evidence on the current record, when the
    /// evidence-bearing commit path was used. Checkpoint authority is external.
    pub const fn evidence(&self) -> Option<&TransactionInclusionEvidenceV1> {
        self.evidence.as_ref()
    }

    /// Opaque authority audit bytes on the current V4 record. These bytes are
    /// not an authentication capability; their owning verifier must recheck
    /// them against independently recovered authority state.
    pub fn authority_audit(&self) -> Option<&[u8]> {
        self.authority_audit.as_deref()
    }

    /// Verify against a private clone, publish one create-once record, and only
    /// then expose the new local registry. Any uncertain I/O poisons the handle.
    pub fn verify_and_commit<V: SettlementProofVerifierV1>(
        &mut self,
        expected: SettlementStoreMarkV1,
        transaction_bytes: &[u8],
        expectation: &SettlementExpectationV1,
        verifier: &V,
    ) -> Result<(AcceptedSettlementV1, SettlementStoreMarkV1), SettlementStoreErrorV1> {
        if self.poisoned {
            return Err(SettlementStoreErrorV1::Poisoned);
        }
        if expected != self.mark {
            return Err(SettlementStoreErrorV1::Cas);
        }
        let generation = self
            .mark
            .generation
            .checked_add(1)
            .ok_or(SettlementStoreErrorV1::Limit)?;
        if generation > MAX_RECORDS {
            return Err(SettlementStoreErrorV1::Limit);
        }
        let mut next = self.registry.clone();
        let accepted = next
            .verify_and_apply(transaction_bytes, expectation, verifier)
            .map_err(SettlementStoreErrorV1::Settlement)?;
        let transaction = transaction_bytes.to_vec();
        self.commit(generation, next, transaction, None, None, None)?;
        Ok((accepted, self.mark))
    }

    /// Consume an authenticated inclusion capability and durably bind its
    /// exact transaction and coordinates to the accepted settlement head.
    pub fn verify_inclusion_and_commit<V: SettlementProofVerifierV1>(
        &mut self,
        expected: SettlementStoreMarkV1,
        inclusion: AuthenticatedSettlementInclusionV1,
        expectation: &SettlementExpectationV1,
        verifier: &V,
    ) -> Result<(AcceptedSettlementV1, SettlementStoreMarkV1, SettlementStoreAdmissionV1), SettlementStoreErrorV1> {
        if self.poisoned {
            return Err(SettlementStoreErrorV1::Poisoned);
        }
        if expected != self.mark {
            return Err(SettlementStoreErrorV1::Cas);
        }
        if inclusion.statement() != &expectation.statement {
            return Err(SettlementStoreErrorV1::Settlement(SettlementError::Expectation));
        }
        let generation = self
            .mark
            .generation
            .checked_add(1)
            .ok_or(SettlementStoreErrorV1::Limit)?;
        if generation > MAX_RECORDS {
            return Err(SettlementStoreErrorV1::Limit);
        }
        let transaction = inclusion.transaction().to_vec();
        let admission = SettlementStoreAdmissionV1 {
            transaction: transaction.clone(),
            block: inclusion.block(),
            slot: inclusion.slot(),
            checkpoint: inclusion.checkpoint(),
            transaction_index: inclusion.transaction_index(),
            admission_commitment: inclusion.admission_commitment(),
        };
        let mut next = self.registry.clone();
        let accepted = next
            .verify_and_apply(&transaction, expectation, verifier)
            .map_err(SettlementStoreErrorV1::Settlement)?;
        self.commit(generation, next, transaction, Some(admission.clone()), None, None)?;
        Ok((accepted, self.mark, admission))
    }

    /// Reauthenticate and atomically retain the complete body/ancestry
    /// envelope together with the settlement receipt and accepted head.
    pub fn verify_evidence_and_commit<V: SettlementProofVerifierV1>(
        &mut self,
        expected: SettlementStoreMarkV1,
        inclusion: AuthenticatedSettlementInclusionV1,
        evidence: TransactionInclusionEvidenceV1,
        expectation: &SettlementExpectationV1,
        verifier: &V,
    ) -> Result<(AcceptedSettlementV1, SettlementStoreMarkV1, SettlementStoreAdmissionV1), SettlementStoreErrorV1> {
        self.verify_evidence_commit_inner(expected, inclusion, evidence, None, expectation, verifier)
    }

    /// Atomically retain complete inclusion evidence plus bounded opaque audit
    /// data produced by an external checkpoint-authority verifier. The bytes
    /// remain audit data and are not authenticated by this portable crate.
    pub fn verify_evidence_and_authority_audit_commit<V: SettlementProofVerifierV1>(
        &mut self,
        expected: SettlementStoreMarkV1,
        inclusion: AuthenticatedSettlementInclusionV1,
        evidence: TransactionInclusionEvidenceV1,
        authority_audit: &[u8],
        expectation: &SettlementExpectationV1,
        verifier: &V,
    ) -> Result<(AcceptedSettlementV1, SettlementStoreMarkV1, SettlementStoreAdmissionV1), SettlementStoreErrorV1> {
        if authority_audit.is_empty() || authority_audit.len() > MAX_SETTLEMENT_AUTHORITY_AUDIT_V1_BYTES {
            return Err(SettlementStoreErrorV1::Limit);
        }
        self.verify_evidence_commit_inner(
            expected,
            inclusion,
            evidence,
            Some(authority_audit.to_vec()),
            expectation,
            verifier,
        )
    }

    fn verify_evidence_commit_inner<V: SettlementProofVerifierV1>(
        &mut self,
        expected: SettlementStoreMarkV1,
        inclusion: AuthenticatedSettlementInclusionV1,
        evidence: TransactionInclusionEvidenceV1,
        authority_audit: Option<Vec<u8>>,
        expectation: &SettlementExpectationV1,
        verifier: &V,
    ) -> Result<(AcceptedSettlementV1, SettlementStoreMarkV1, SettlementStoreAdmissionV1), SettlementStoreErrorV1> {
        if self.poisoned {
            return Err(SettlementStoreErrorV1::Poisoned);
        }
        if expected != self.mark {
            return Err(SettlementStoreErrorV1::Cas);
        }
        if inclusion.statement() != &expectation.statement {
            return Err(SettlementStoreErrorV1::Settlement(SettlementError::Expectation));
        }
        evidence_matches_inclusion(&evidence, &inclusion)?;
        let generation = self
            .mark
            .generation
            .checked_add(1)
            .ok_or(SettlementStoreErrorV1::Limit)?;
        if generation > MAX_RECORDS {
            return Err(SettlementStoreErrorV1::Limit);
        }
        let transaction = inclusion.transaction().to_vec();
        let admission = SettlementStoreAdmissionV1 {
            transaction: transaction.clone(),
            block: inclusion.block(),
            slot: inclusion.slot(),
            checkpoint: inclusion.checkpoint(),
            transaction_index: inclusion.transaction_index(),
            admission_commitment: inclusion.admission_commitment(),
        };
        let mut next = self.registry.clone();
        let accepted = next
            .verify_and_apply(&transaction, expectation, verifier)
            .map_err(SettlementStoreErrorV1::Settlement)?;
        self.commit(
            generation,
            next,
            transaction,
            Some(admission.clone()),
            Some(evidence),
            authority_audit,
        )?;
        Ok((accepted, self.mark, admission))
    }

    fn commit(
        &mut self,
        generation: u64,
        next: SettlementRegistryV1,
        transaction: Vec<u8>,
        admission: Option<SettlementStoreAdmissionV1>,
        evidence: Option<TransactionInclusionEvidenceV1>,
        authority_audit: Option<Vec<u8>>,
    ) -> Result<(), SettlementStoreErrorV1> {
        let bytes = encode_record(
            generation,
            next.policy,
            self.mark.record_digest,
            &next,
            Some(&transaction),
            admission.as_ref(),
            RecordExtensions {
                evidence: evidence.as_ref(),
                authority_audit: authority_audit.as_deref(),
            },
        )?;
        self.poisoned = true;
        if let Err(error) = publish_create_once(&self.directory, &record_name(generation), &bytes) {
            return Err(SettlementStoreErrorV1::CommitUncertain(error));
        }
        self.registry = next;
        self.mark = mark(generation, &bytes, &self.registry);
        self.admission = admission;
        self.evidence = evidence;
        self.authority_audit = authority_audit;
        self.poisoned = false;
        Ok(())
    }
}

struct DecodedRecord {
    transaction: Option<Vec<u8>>,
    state_commitment: B256,
    head: Option<AcceptedSettlementV1>,
    admission: Option<SettlementStoreAdmissionV1>,
    evidence: Option<TransactionInclusionEvidenceV1>,
    authority_audit: Option<Vec<u8>>,
}

#[derive(Default)]
struct RecordExtensions<'a> {
    evidence: Option<&'a TransactionInclusionEvidenceV1>,
    authority_audit: Option<&'a [u8]>,
}

fn encode_record(
    generation: u64,
    policy: SettlementPolicyV1,
    previous_digest: B256,
    registry: &SettlementRegistryV1,
    transaction: Option<&[u8]>,
    admission: Option<&SettlementStoreAdmissionV1>,
    extensions: RecordExtensions<'_>,
) -> Result<Vec<u8>, SettlementStoreErrorV1> {
    let RecordExtensions {
        evidence,
        authority_audit,
    } = extensions;
    let mut native_wire = false;
    let decoded_transaction = match transaction {
        None => None,
        Some(bytes) => {
            let (decoded, format) =
                SettlementTransactionV1::decode_wire(bytes).map_err(|_| SettlementStoreErrorV1::Format)?;
            native_wire = format == SettlementWireFormat::NativeV1;
            if decoded.encode_wire(format) != bytes
                || !transaction_matches_head(&decoded, &registry.head.ok_or(SettlementStoreErrorV1::Format)?)
            {
                return Err(SettlementStoreErrorV1::Format);
            }
            Some(decoded)
        }
    };
    if let Some(admission) = admission {
        if admission.transaction != *transaction.ok_or(SettlementStoreErrorV1::Format)?
            || !admission_matches_transaction(
                decoded_transaction.as_ref().ok_or(SettlementStoreErrorV1::Format)?,
                admission,
            )
        {
            return Err(SettlementStoreErrorV1::Format);
        }
    }
    match (admission, evidence) {
        (None, Some(_)) => return Err(SettlementStoreErrorV1::Format),
        (Some(admission), Some(evidence)) => evidence_matches_admission(evidence, admission)?,
        _ => {}
    }
    if (authority_audit.is_some() && evidence.is_none()) || (native_wire && authority_audit.is_none()) {
        return Err(SettlementStoreErrorV1::Format);
    }
    if authority_audit.is_some_and(|value| value.is_empty() || value.len() > MAX_SETTLEMENT_AUTHORITY_AUDIT_V1_BYTES) {
        return Err(SettlementStoreErrorV1::Limit);
    }
    let evidence_bytes = evidence.map(TransactionInclusionEvidenceV1::encode);
    let mut bytes = Vec::with_capacity(
        RECORD_BYTES
            + evidence_bytes.as_ref().map_or(0, |value| 4 + value.len())
            + authority_audit.map_or(0, |value| 4 + value.len()),
    );
    bytes.extend_from_slice(if native_wire {
        RECORD_V5_TAG
    } else if authority_audit.is_some() {
        RECORD_V4_TAG
    } else if evidence.is_some() {
        RECORD_V3_TAG
    } else {
        RECORD_V2_TAG
    });
    bytes.extend_from_slice(&generation.to_le_bytes());
    bytes.extend_from_slice(
        policy
            .commitment()
            .map_err(SettlementStoreErrorV1::Settlement)?
            .as_slice(),
    );
    bytes.extend_from_slice(previous_digest.as_slice());
    bytes.extend_from_slice(registry.state_commitment().as_slice());
    match registry.head {
        None => {
            if generation != 0 || transaction.is_some() || admission.is_some() {
                return Err(SettlementStoreErrorV1::Format);
            }
            bytes.push(0);
            bytes.resize(8 + 8 + 32 + 32 + 32 + ACCEPTED_HEAD_BYTES, 0);
        }
        Some(head) => {
            if generation == 0 || transaction.is_none() {
                return Err(SettlementStoreErrorV1::Format);
            }
            bytes.push(1);
            for value in [
                head.commitment,
                head.l2_header_hash,
                head.l2_state_root,
                head.l1_block,
                head.source_commitment,
                head.inbox_root,
            ] {
                bytes.extend_from_slice(value.as_slice());
            }
            for value in [
                head.l2_number,
                head.l1_slot,
                head.l1_height,
                head.inbox_count,
                head.consumed_end,
            ] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    match transaction {
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; SETTLEMENT_TX_V1_BYTES]);
        }
        Some(transaction) => {
            bytes.push(if native_wire { 2 } else { 1 });
            bytes.extend_from_slice(transaction);
            bytes.resize(bytes.len() + SETTLEMENT_TX_V1_BYTES - transaction.len(), 0);
        }
    }
    match admission {
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; ADMISSION_BYTES]);
        }
        Some(admission) => {
            bytes.push(1);
            bytes.extend_from_slice(admission.block.as_slice());
            bytes.extend_from_slice(&admission.slot.to_le_bytes());
            bytes.extend_from_slice(admission.checkpoint.block.as_slice());
            bytes.extend_from_slice(&admission.checkpoint.slot.to_le_bytes());
            bytes.extend_from_slice(&admission.transaction_index.to_le_bytes());
            bytes.extend_from_slice(admission.admission_commitment.as_slice());
        }
    }
    if let Some(evidence_bytes) = evidence_bytes {
        bytes.extend_from_slice(&(evidence_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&evidence_bytes);
    }
    if let Some(authority_audit) = authority_audit {
        bytes.extend_from_slice(&(authority_audit.len() as u32).to_le_bytes());
        bytes.extend_from_slice(authority_audit);
    }
    if (evidence.is_none() && bytes.len() != RECORD_BYTES) || bytes.len() > MAX_RECORD_BYTES {
        return Err(SettlementStoreErrorV1::Format);
    }
    Ok(bytes)
}

fn decode_record(
    bytes: &[u8],
    expected_generation: u64,
    policy: SettlementPolicyV1,
    expected_previous: B256,
) -> Result<DecodedRecord, SettlementStoreErrorV1> {
    if bytes.len() < RECORD_BYTES {
        return Err(SettlementStoreErrorV1::Format);
    }
    let version = &bytes[..8];
    if (version == RECORD_V2_TAG && bytes.len() != RECORD_BYTES)
        || (version != RECORD_V2_TAG
            && version != RECORD_V3_TAG
            && version != RECORD_V4_TAG
            && version != RECORD_V5_TAG)
    {
        return Err(SettlementStoreErrorV1::Format);
    }
    let mut reader = Reader(&bytes[8..]);
    if reader.u64()? != expected_generation
        || reader.hash()? != policy.commitment().map_err(SettlementStoreErrorV1::Settlement)?
        || reader.hash()? != expected_previous
    {
        return Err(SettlementStoreErrorV1::Format);
    }
    let state_commitment = reader.hash()?;
    let present = reader.byte()?;
    let head = match present {
        0 => {
            if reader.take(ACCEPTED_HEAD_BYTES - 1)?.iter().any(|byte| *byte != 0) {
                return Err(SettlementStoreErrorV1::Format);
            }
            None
        }
        1 => Some(AcceptedSettlementV1 {
            commitment: reader.hash()?,
            l2_header_hash: reader.hash()?,
            l2_state_root: reader.hash()?,
            l1_block: reader.hash()?,
            source_commitment: reader.hash()?,
            inbox_root: reader.hash()?,
            l2_number: reader.u64()?,
            l1_slot: reader.u64()?,
            l1_height: reader.u64()?,
            inbox_count: reader.u64()?,
            consumed_end: reader.u64()?,
        }),
        _ => return Err(SettlementStoreErrorV1::Format),
    };
    let transaction = match reader.byte()? {
        0 if version != RECORD_V5_TAG => {
            if reader.take(SETTLEMENT_TX_V1_BYTES)?.iter().any(|byte| *byte != 0) {
                return Err(SettlementStoreErrorV1::Format);
            }
            None
        }
        kind @ (1 | 2) if (kind == 2) == (version == RECORD_V5_TAG) => {
            let padded = reader.take(SETTLEMENT_TX_V1_BYTES)?;
            let length = if kind == 2 {
                NATIVE_SETTLEMENT_BYTES
            } else {
                SETTLEMENT_TX_V1_BYTES
            };
            if padded[length..].iter().any(|byte| *byte != 0) {
                return Err(SettlementStoreErrorV1::Format);
            }
            let bytes = padded[..length].to_vec();
            let (decoded, format) =
                SettlementTransactionV1::decode_wire(&bytes).map_err(|_| SettlementStoreErrorV1::Format)?;
            if (format == SettlementWireFormat::NativeV1) != (kind == 2) || decoded.encode_wire(format) != bytes {
                return Err(SettlementStoreErrorV1::Format);
            }
            Some((bytes, decoded))
        }
        _ => return Err(SettlementStoreErrorV1::Format),
    };
    let admission = match reader.byte()? {
        0 => {
            if reader.take(ADMISSION_BYTES)?.iter().any(|byte| *byte != 0) {
                return Err(SettlementStoreErrorV1::Format);
            }
            None
        }
        1 => {
            let (transaction_bytes, transaction) = transaction.as_ref().ok_or(SettlementStoreErrorV1::Format)?;
            let value = SettlementStoreAdmissionV1 {
                transaction: transaction_bytes.clone(),
                block: reader.hash()?,
                slot: reader.u64()?,
                checkpoint: FinalizedCheckpoint {
                    block: reader.hash()?,
                    slot: reader.u64()?,
                },
                transaction_index: reader.u32()?,
                admission_commitment: reader.hash()?,
            };
            if !admission_matches_transaction(transaction, &value) {
                return Err(SettlementStoreErrorV1::Format);
            }
            Some(value)
        }
        _ => return Err(SettlementStoreErrorV1::Format),
    };
    let evidence = if version == RECORD_V3_TAG || version == RECORD_V4_TAG || version == RECORD_V5_TAG {
        let admission = admission.as_ref().ok_or(SettlementStoreErrorV1::Format)?;
        let length = reader.u32()? as usize;
        if length == 0 || length > MAX_INCLUSION_EVIDENCE_V1_BYTES || reader.remaining().len() < length {
            return Err(SettlementStoreErrorV1::Format);
        }
        let evidence = TransactionInclusionEvidenceV1::decode(reader.take(length)?)
            .map_err(|_| SettlementStoreErrorV1::Evidence)?;
        evidence_matches_admission(&evidence, admission)?;
        Some(evidence)
    } else {
        None
    };
    let authority_audit = if version == RECORD_V4_TAG || version == RECORD_V5_TAG {
        let length = reader.u32()? as usize;
        if length == 0 || length > MAX_SETTLEMENT_AUTHORITY_AUDIT_V1_BYTES || reader.remaining().len() != length {
            return Err(SettlementStoreErrorV1::Format);
        }
        Some(reader.take(length)?.to_vec())
    } else {
        None
    };
    if !reader.remaining().is_empty() {
        return Err(SettlementStoreErrorV1::Format);
    }
    match (expected_generation, head.as_ref(), transaction.as_ref()) {
        (0, None, None) => {}
        (0, _, _) | (_, None, _) | (_, _, None) => return Err(SettlementStoreErrorV1::Format),
        (_, Some(head), Some((_, transaction))) if !transaction_matches_head(transaction, head) => {
            return Err(SettlementStoreErrorV1::Format)
        }
        _ => {}
    }
    Ok(DecodedRecord {
        transaction: transaction.map(|(bytes, _)| bytes),
        state_commitment,
        head,
        admission,
        evidence,
        authority_audit,
    })
}

fn evidence_matches_inclusion(
    evidence: &TransactionInclusionEvidenceV1,
    inclusion: &AuthenticatedSettlementInclusionV1,
) -> Result<(), SettlementStoreErrorV1> {
    let authenticated = evidence
        .authenticate_exact(inclusion.transaction())
        .map_err(|_| SettlementStoreErrorV1::Evidence)?;
    if authenticated.block() != inclusion.block()
        || authenticated.slot() != inclusion.slot()
        || authenticated.checkpoint() != inclusion.checkpoint()
        || authenticated.transaction_index() != inclusion.transaction_index()
    {
        return Err(SettlementStoreErrorV1::Evidence);
    }
    Ok(())
}

fn evidence_matches_admission(
    evidence: &TransactionInclusionEvidenceV1,
    admission: &SettlementStoreAdmissionV1,
) -> Result<(), SettlementStoreErrorV1> {
    let authenticated = evidence
        .authenticate_exact(&admission.transaction)
        .map_err(|_| SettlementStoreErrorV1::Evidence)?;
    let (transaction, format) =
        SettlementTransactionV1::decode_wire(&admission.transaction).map_err(|_| SettlementStoreErrorV1::Evidence)?;
    if (format == SettlementWireFormat::NativeV1 && transaction.statement().l1_block != authenticated.parent())
        || authenticated.block() != admission.block
        || authenticated.slot() != admission.slot
        || authenticated.checkpoint() != admission.checkpoint
        || authenticated.transaction_index() != admission.transaction_index
    {
        return Err(SettlementStoreErrorV1::Evidence);
    }
    Ok(())
}

fn transaction_matches_head(transaction: &SettlementTransactionV1, head: &AcceptedSettlementV1) -> bool {
    let statement = transaction.statement();
    transaction.commitment() == head.commitment
        && statement.l2_header_hash == head.l2_header_hash
        && statement.l2_state_root == head.l2_state_root
        && statement.l1_block == head.l1_block
        && statement.source_commitment == head.source_commitment
        && statement.inbox_root == head.inbox_root
        && statement.l2_number == head.l2_number
        && statement.l1_slot == head.l1_slot
        && statement.l1_height == head.l1_height
        && statement.inbox_count == head.inbox_count
        && statement.consumed_end == head.consumed_end
}

fn admission_commitment(transaction_commitment: B256, admission: &SettlementStoreAdmissionV1) -> B256 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BLOCH:EXPERIMENTAL:SETTLEMENT-ADMISSION:1");
    hasher.update(transaction_commitment);
    hasher.update(admission.block);
    hasher.update(admission.slot.to_le_bytes());
    hasher.update(admission.checkpoint.block);
    hasher.update(admission.checkpoint.slot.to_le_bytes());
    hasher.update(admission.transaction_index.to_le_bytes());
    hasher.update((admission.transaction.len() as u64).to_le_bytes());
    hasher.update(&admission.transaction);
    B256::from_slice(&hasher.finalize())
}

fn admission_matches_transaction(
    transaction: &SettlementTransactionV1,
    admission: &SettlementStoreAdmissionV1,
) -> bool {
    transaction.statement().l1_block != admission.block
        && transaction.statement().l1_slot < admission.slot
        && admission.checkpoint.block != B256::ZERO
        && admission.checkpoint.slot >= admission.slot
        && (admission.checkpoint.slot != admission.slot || admission.checkpoint.block == admission.block)
        && admission_commitment(transaction.commitment(), admission) == admission.admission_commitment
}

fn validate_replayed_head(
    generation: u64,
    policy: SettlementPolicyV1,
    previous: Option<AcceptedSettlementV1>,
    current: Option<AcceptedSettlementV1>,
) -> Result<(), SettlementStoreErrorV1> {
    if generation == 0 {
        return if previous.is_none() && current.is_none() {
            Ok(())
        } else {
            Err(SettlementStoreErrorV1::Format)
        };
    }
    let head = current.ok_or(SettlementStoreErrorV1::Format)?;
    if [
        head.commitment,
        head.l2_header_hash,
        head.l2_state_root,
        head.l1_block,
        head.source_commitment,
        head.inbox_root,
    ]
    .contains(&B256::ZERO)
        || head.l1_height == 0
        || head.l1_slot < head.l1_height
        || head.consumed_end > head.inbox_count
        || head.l2_number
            != policy
                .first_l2_number
                .checked_add(generation - 1)
                .ok_or(SettlementStoreErrorV1::Limit)?
    {
        return Err(SettlementStoreErrorV1::Format);
    }
    if let Some(old) = previous {
        if head.l2_number != old.l2_number.checked_add(1).ok_or(SettlementStoreErrorV1::Format)?
            || head.consumed_end < old.consumed_end
            || head.inbox_count < old.inbox_count
            || head.l1_height < old.l1_height
            || head.l1_slot < old.l1_slot
            || (head.l1_height == old.l1_height && (head.l1_block != old.l1_block || head.l1_slot != old.l1_slot))
            || (head.l1_height > old.l1_height && head.l1_slot <= old.l1_slot)
            || (head.inbox_count == old.inbox_count && head.inbox_root != old.inbox_root)
        {
            return Err(SettlementStoreErrorV1::Format);
        }
    }
    Ok(())
}

fn mark(generation: u64, bytes: &[u8], registry: &SettlementRegistryV1) -> SettlementStoreMarkV1 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BLOCH:EXPERIMENTAL:SETTLEMENT-STORE-RECORD:1");
    hasher.update(bytes);
    SettlementStoreMarkV1 {
        generation,
        record_digest: B256::from_slice(&hasher.finalize()),
        state_commitment: registry.state_commitment(),
    }
}

fn record_name(generation: u64) -> String {
    format!("{generation:020}.sst")
}

fn record_generations(directory: &Path) -> Result<Vec<u64>, SettlementStoreErrorV1> {
    let mut values = Vec::new();
    for item in fs::read_dir(directory)? {
        let name = item?
            .file_name()
            .into_string()
            .map_err(|_| SettlementStoreErrorV1::Format)?;
        if name == "LOCK" || name == "POLICY" {
            continue;
        }
        if name.starts_with(".pending-") {
            return Err(SettlementStoreErrorV1::CrashEvidence);
        }
        if name.len() != 24 || !name.ends_with(".sst") || !name.as_bytes()[..20].iter().all(u8::is_ascii_digit) {
            return Err(SettlementStoreErrorV1::Format);
        }
        values.push(name[..20].parse().map_err(|_| SettlementStoreErrorV1::Format)?);
    }
    values.sort_unstable();
    Ok(values)
}

fn create_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn publish_create_once(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let destination = directory.join(name);
    if destination.try_exists()? {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "settlement record exists"));
    }
    let temp = directory.join(format!(
        ".pending-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::hard_link(&temp, &destination)?;
    fs::remove_file(&temp)?;
    directory_file(directory)?.sync_all()
}

fn check_private_directory(path: &Path) -> Result<(), SettlementStoreErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(SettlementStoreErrorV1::Format);
    }
    Ok(())
}

fn regular_private(path: &Path) -> Result<(), SettlementStoreErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.mode() & 0o077 != 0 {
        return Err(SettlementStoreErrorV1::Format);
    }
    Ok(())
}

fn directory_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn read_exact_bounded(path: &Path, expected: usize) -> Result<Vec<u8>, SettlementStoreErrorV1> {
    regular_private(path)?;
    let file = File::open(path)?;
    if file.metadata()?.len() != expected as u64 {
        return Err(SettlementStoreErrorV1::Format);
    }
    let mut bytes = Vec::with_capacity(expected);
    file.take(expected as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != expected {
        return Err(SettlementStoreErrorV1::Format);
    }
    Ok(bytes)
}

fn read_record_bounded(path: &Path) -> Result<Vec<u8>, SettlementStoreErrorV1> {
    regular_private(path)?;
    let file = File::open(path)?;
    let length: usize = file
        .metadata()?
        .len()
        .try_into()
        .map_err(|_| SettlementStoreErrorV1::Limit)?;
    if !(RECORD_BYTES..=MAX_RECORD_BYTES).contains(&length) {
        return Err(SettlementStoreErrorV1::Format);
    }
    let mut bytes = Vec::with_capacity(length);
    file.take(MAX_RECORD_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return Err(SettlementStoreErrorV1::Format);
    }
    Ok(bytes)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], SettlementStoreErrorV1> {
        if count > self.0.len() {
            return Err(SettlementStoreErrorV1::Format);
        }
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, SettlementStoreErrorV1> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, SettlementStoreErrorV1> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| SettlementStoreErrorV1::Format)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, SettlementStoreErrorV1> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| SettlementStoreErrorV1::Format)?,
        ))
    }

    fn hash(&mut self) -> Result<B256, SettlementStoreErrorV1> {
        Ok(B256::from_slice(self.take(32)?))
    }

    const fn remaining(&self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod tests;
