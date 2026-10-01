// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only recovery of PQ-authorized settlements against exact local L2 blocks.
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
    Verification(CanonicalSettlementAuditErrorV1<SettlementAuthorityStoreErrorV1>),
    /// Defensive postcondition: every recovered generation and the exact head
    /// must be represented in the canonical audit before either handle escapes.
    Incomplete,
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
}

impl RecoveredCanonicalSettlementsV1 {
    pub const fn stores(&self) -> &RecoveredAuthorityStoresV1 {
        &self.stores
    }

    pub const fn report(&self) -> &CanonicalSettlementAuditReportV1 {
        &self.report
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
    if request.checkpoint_policy.native_genesis().as_slice() != request.settlement_policy.genesis.as_slice() {
        return Err(SettlementRecoveryErrorV1::Policy);
    }
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
                    canonical
                        .audit_record(record)
                        .map_err(|error| SettlementAuthorityStoreErrorV1::AdditionalAudit(error.to_string()))
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
    Ok(RecoveredCanonicalSettlementsV1 { stores, report })
}
