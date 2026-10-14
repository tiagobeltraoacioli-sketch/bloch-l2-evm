// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery of native settlements and durable local finality candidates.
//! This host composition never grants native consensus or an RPC finality capability.
#![cfg(unix)]

use bloch_l2_evm::native_settlement::{store::SettlementStoreMarkV1, SettlementPolicyV1, SettlementProofVerifierV1};
use bloch_native_escrow_pq::{
    checkpoint::CheckpointPolicy,
    checkpoint_store::CheckpointMark,
    settlement_authority::{
        open_proof_verified_authority_stores_with_audit, RecoveredAuthorityStoresV1, SettlementAuthorityStoreErrorV1,
    },
};
use bloch_reth_execution::{
    settlement_binding::{
        with_canonical_settlement_audit, CanonicalSettlementAuditErrorV1, CanonicalSettlementAuditReportV1,
    },
    BlochProviderFactory, ReplayFloor, ReplayLimits,
};
use std::path::Path;

pub mod async_cursor;
pub mod cursor;
pub mod history;
pub mod native;
pub mod proof;
pub mod reconstruct;
pub mod timestamp;

/// Explicit host inputs. Policies, floors and epoch must come from independent
/// trusted sources, never from the files or RPC claims being audited. The host
/// must select compatible native network identities in both policies.
pub struct SettlementRecoveryRequestV1<'a> {
    pub checkpoint_path: &'a Path,
    pub checkpoint_policy: CheckpointPolicy,
    pub checkpoint_floor: CheckpointMark,
    pub settlement_path: &'a Path,
    pub settlement_policy: SettlementPolicyV1,
    pub settlement_floor: SettlementStoreMarkV1,
    pub l2_floor: ReplayFloor,
    pub current_epoch: u64,
    pub maximum_proofs: u64,
    pub canonical_limits: ReplayLimits,
}

#[derive(Debug)]
pub enum SettlementRecoveryErrorV1 {
    /// The two independently supplied policies name different native genesis blocks.
    Policy,
    /// The native entry point requires the compiled complete Groth16 policy.
    ProofPolicy,
    NativeFinality(native::NativeFinalityErrorV1),
    Verification(CanonicalSettlementAuditErrorV1<SettlementAuthorityStoreErrorV1>),
    /// Defensive postcondition: every recovered generation and the exact head
    /// must be represented in the canonical audit before either handle escapes.
    Incomplete,
    /// A retained candidate no longer matches the independently reverified histories.
    Cursor,
}

impl std::fmt::Display for SettlementRecoveryErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "settlement recovery refused: {self:?}")
    }
}

impl std::error::Error for SettlementRecoveryErrorV1 {}

/// Both histories remain locked until this value is dropped or consumed.
/// The report describes recovery-time correspondence, not future mutations,
/// current checkpoint freshness, proof-transport qualification or finality.
pub struct RecoveredCanonicalSettlementsV1 {
    stores: RecoveredAuthorityStoresV1,
    report: CanonicalSettlementAuditReportV1,
    native_finality: Option<native::NativeFinalityReportV1>,
}

impl RecoveredCanonicalSettlementsV1 {
    pub const fn stores(&self) -> &RecoveredAuthorityStoresV1 {
        &self.stores
    }

    pub const fn report(&self) -> &CanonicalSettlementAuditReportV1 {
        &self.report
    }

    /// Informational accounting of a complete native FFG replay, when requested.
    /// Copying this report cannot reconstruct its private verification capability.
    pub const fn native_finality(&self) -> Option<&native::NativeFinalityReportV1> {
        self.native_finality.as_ref()
    }

    /// Consume the recovery result before opening any mutable store access.
    /// Later appends require their own proof/authority/canonical checks.
    pub fn into_stores(self) -> RecoveredAuthorityStoresV1 {
        self.stores
    }
}

/// Recover in one closed composition: bounded canonical preflight, locked
/// checkpoint replay, every execution proof/inclusion/PQ-authority check,
/// exact per-record L2 correspondence, then a fresh canonical-tip fence.
///
/// All source writers, including static-file writers, must be stopped. There
/// is no caller callback that can skip or swallow the canonical record audit.
/// On any error the two store handles are dropped without rewriting history.
/// The proof verifier is a trusted, independently qualified host dependency;
/// this function cannot establish that a supplied verifier is sound.
pub fn recover_canonical_settlements<V: SettlementProofVerifierV1>(
    source: &BlochProviderFactory,
    request: SettlementRecoveryRequestV1<'_>,
    verifier: &V,
) -> Result<RecoveredCanonicalSettlementsV1, SettlementRecoveryErrorV1> {
    recover_with_cursor(source, request, verifier, None, false, None)
}

/// Native-only recovery with the pinned real verifier. Every historical record
/// must retain the exact native envelope; callers cannot substitute a proof double.
pub fn recover_canonical_native_settlements(
    source: &BlochProviderFactory,
    request: SettlementRecoveryRequestV1<'_>,
) -> Result<RecoveredCanonicalSettlementsV1, SettlementRecoveryErrorV1> {
    let verifier = proof::NativeGroth16Verifier::from_policy(&request.settlement_policy)
        .map_err(|_| SettlementRecoveryErrorV1::ProofPolicy)?;
    recover_with_cursor(source, request, &verifier, None, true, None)
}

/// Compose full native consensus/FFG replay with every recovered L2 record.
/// The supplied native capability can only be built by real native replay.
/// Its trust root is independently pinned; no network activation is implied.
pub fn recover_canonical_ffg_settlements(
    source: &BlochProviderFactory,
    request: SettlementRecoveryRequestV1<'_>,
    native: &native::VerifiedNativeFinalityV1,
) -> Result<RecoveredCanonicalSettlementsV1, SettlementRecoveryErrorV1> {
    let verifier = proof::NativeGroth16Verifier::from_policy(&request.settlement_policy)
        .map_err(|_| SettlementRecoveryErrorV1::ProofPolicy)?;
    recover_with_cursor(source, request, &verifier, None, true, Some(native))
}

fn recover_with_cursor<V: SettlementProofVerifierV1>(
    source: &BlochProviderFactory,
    request: SettlementRecoveryRequestV1<'_>,
    verifier: &V,
    previous: Option<bloch_reth_execution::finality_cursor::FinalityCandidateCursorV1>,
    require_native: bool,
    native: Option<&native::VerifiedNativeFinalityV1>,
) -> Result<RecoveredCanonicalSettlementsV1, SettlementRecoveryErrorV1> {
    if request.checkpoint_policy.native_genesis().as_slice() != request.settlement_policy.genesis.as_slice() {
        return Err(SettlementRecoveryErrorV1::Policy);
    }
    if let Some(native) = native {
        if request.settlement_policy.commitment().ok() != Some(native.report().settlement_policy)
            || request.current_epoch < bloch_pos_committee::epoch_of(native.report().replayed_slot)
        {
            return Err(SettlementRecoveryErrorV1::NativeFinality(
                native::NativeFinalityErrorV1::Trust,
            ));
        }
    }
    let current_epoch = request.current_epoch;
    let mut previous_seen = previous.is_none();
    let (stores, report) = with_canonical_settlement_audit(
        source,
        request.settlement_policy,
        request.l2_floor,
        request.canonical_limits,
        |canonical| {
            open_proof_verified_authority_stores_with_audit(
                request.checkpoint_path,
                request.checkpoint_policy,
                request.checkpoint_floor,
                request.settlement_path,
                request.settlement_policy,
                request.settlement_floor,
                request.current_epoch,
                request.maximum_proofs,
                verifier,
                |record| {
                    if let Some(native) = native {
                        native
                            .audit_record(record)
                            .map_err(|e| SettlementAuthorityStoreErrorV1::AdditionalAudit(e.to_string()))?;
                    }
                    if require_native {
                        use bloch_l2_evm::native_settlement::{SettlementTransactionV1, SettlementWireFormat};
                        if !matches!(
                            SettlementTransactionV1::decode_wire(record.transaction),
                            Ok((_, SettlementWireFormat::NativeV1))
                        ) {
                            return Err(SettlementAuthorityStoreErrorV1::AdditionalAudit(
                                "native recovery requires exact native envelope in every record".into(),
                            ));
                        }
                    }
                    canonical
                        .audit_record(record)
                        .map_err(|error| SettlementAuthorityStoreErrorV1::AdditionalAudit(error.to_string()))?;
                    if let Some(previous) = previous {
                        let f = previous.fields();
                        if record.mark.generation == f.settlement_generation {
                            if record.mark.record_digest != f.settlement_record_digest
                                || record.mark.state_commitment != f.settlement_state_commitment
                                || record.accepted.l2_number != f.l2_number
                                || record.accepted.l2_header_hash != f.l2_hash
                                || record.accepted.l2_state_root != f.l2_state_root
                            {
                                return Err(SettlementAuthorityStoreErrorV1::AdditionalAudit(
                                    "saved finality candidate differs from reverified settlement".into(),
                                ));
                            }
                            previous_seen = true;
                        }
                    }
                    Ok(())
                },
            )
        },
    )
    .map_err(SettlementRecoveryErrorV1::Verification)?;
    let settlement_store = stores.settlement_store();
    let head = settlement_store.registry().head();
    if report.audited_records != settlement_store.mark().generation
        || !head
            .zip(report.last_settlement)
            .is_some_and(|(head, last)| head.l2_number == last.number && head.l2_header_hash == last.hash)
    {
        return Err(SettlementRecoveryErrorV1::Incomplete);
    }
    if let Some(previous) = previous {
        let f = previous.fields();
        if !previous_seen || f.l2_genesis != report.genesis || f.settlement_policy != report.policy_commitment {
            return Err(SettlementRecoveryErrorV1::Cursor);
        }
        let retained = stores
            .checkpoint_store()
            .historical_audit(f.checkpoint_epoch, f.checked_at_epoch, current_epoch)
            .map_err(|_| SettlementRecoveryErrorV1::Cursor)?;
        if retained.checkpoint_digest() != f.checkpoint_digest || retained.policy_identity() != f.checkpoint_policy {
            return Err(SettlementRecoveryErrorV1::Cursor);
        }
        if let Some(native) = native {
            native
                .check_checkpoint(retained.anchor(), retained.checkpoint_epoch())
                .map_err(SettlementRecoveryErrorV1::NativeFinality)?;
        }
    }
    Ok(RecoveredCanonicalSettlementsV1 {
        stores,
        report,
        native_finality: native.map(|n| *n.report()),
    })
}
