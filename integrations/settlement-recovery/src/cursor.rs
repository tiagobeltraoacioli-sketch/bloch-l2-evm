// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable preparation for finality publication. Native consensus qualification
//! is still required; a candidate cannot set safe/finalized or authorize payouts.
use crate::{
    recover_with_cursor, RecoveredCanonicalSettlementsV1, SettlementRecoveryErrorV1, SettlementRecoveryRequestV1,
};
use alloy_primitives::B256;
use bloch_l2_evm::native_settlement::SettlementProofVerifierV1;
use bloch_reth_execution::{
    finality_cursor::{
        read_finality_candidate, reject_unverified_finality_markers, BlochFinalityCandidate, FinalityCandidateCursorV1,
        FinalityCandidateFieldsV1,
    },
    BlochProviderFactory,
};
use reth_db_api::{
    tables::{ChainState, ChainStateKey},
    transaction::{DbTx, DbTxMut},
};
use reth_provider::{BlockNumReader, DBProvider, DatabaseProviderFactory, HeaderProvider};

#[derive(Debug)]
pub enum FinalityCandidateErrorV1 {
    Recovery(SettlementRecoveryErrorV1),
    Storage(String),
    /// Exact independently retained candidate mark disagrees, including deletion.
    CursorFloor,
    /// No currently fresh checkpoint can support a new candidate observation.
    Freshness,
    /// A concurrent writer or non-monotonic update invalidated staging.
    Changed,
}
impl std::fmt::Display for FinalityCandidateErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "finality candidate refused: {self:?}")
    }
}
impl std::error::Error for FinalityCandidateErrorV1 {}
fn storage(error: impl std::fmt::Display) -> FinalityCandidateErrorV1 {
    FinalityCandidateErrorV1::Storage(error.to_string())
}

/// Retains both evidence-store locks. The cursor is persisted audit data, not
/// verified native consensus or permission to publish an Ethereum finality tag.
pub struct StagedFinalityCandidateV1 {
    recovery: RecoveredCanonicalSettlementsV1,
    cursor: FinalityCandidateCursorV1,
}
impl StagedFinalityCandidateV1 {
    pub const fn recovery(&self) -> &RecoveredCanonicalSettlementsV1 {
        &self.recovery
    }
    pub const fn cursor(&self) -> FinalityCandidateCursorV1 {
        self.cursor
    }
    pub fn into_recovery(self) -> RecoveredCanonicalSettlementsV1 {
        self.recovery
    }
}

/// Reverify and atomically replace the local candidate using an exact CAS mark.
/// `None` permits only an empty candidate table. Retain the returned commitment
/// outside this database before acknowledging it. An uncertain commit is an
/// error; do not retry or adopt the on-disk value without independent recovery.
///
/// The saved cursor's settlement is checked inside full proof/PQ/canonical
/// replay, and its checkpoint is reauthenticated at the recorded epoch. A
/// current fresh checkpoint is then required. The final MDBX transaction checks
/// the candidate CAS and canonical tip together before commit. All source and
/// static-file writers must remain stopped as in the underlying recovery API.
pub fn recover_and_stage_finality_candidate<V: SettlementProofVerifierV1>(
    source: &BlochProviderFactory,
    request: SettlementRecoveryRequestV1<'_>,
    verifier: &V,
    expected_cursor: Option<B256>,
) -> Result<StagedFinalityCandidateV1, FinalityCandidateErrorV1> {
    stage_with_wire(source, request, verifier, expected_cursor, false, None)
}

/// Native-only candidate preparation. Uses the compiled real proof verifier and
/// rejects any experimental envelope in the recovered history, including before
/// the retained floor. This candidate still cannot publish RPC finality.
pub fn recover_and_stage_native_finality_candidate(
    source: &BlochProviderFactory,
    request: SettlementRecoveryRequestV1<'_>,
    expected_cursor: Option<B256>,
) -> Result<StagedFinalityCandidateV1, FinalityCandidateErrorV1> {
    let verifier = crate::proof::NativeGroth16Verifier::from_policy(&request.settlement_policy)
        .map_err(|_| FinalityCandidateErrorV1::Recovery(SettlementRecoveryErrorV1::ProofPolicy))?;
    stage_with_wire(source, request, &verifier, expected_cursor, true, None)
}

/// Stage only after complete native FFG and L2 recovery. Every current/historical
/// checkpoint must agree with the replayed native branch and finalized prefix.
/// The persisted candidate remains audit data; every restart must reverify the
/// native history. This does not grant permission to publish RPC finality.
pub fn recover_and_stage_ffg_finality_candidate(
    source: &BlochProviderFactory,
    request: SettlementRecoveryRequestV1<'_>,
    native: &crate::native::VerifiedNativeFinalityV1,
    expected_cursor: Option<B256>,
) -> Result<StagedFinalityCandidateV1, FinalityCandidateErrorV1> {
    let verifier = crate::proof::NativeGroth16Verifier::from_policy(&request.settlement_policy)
        .map_err(|_| FinalityCandidateErrorV1::Recovery(SettlementRecoveryErrorV1::ProofPolicy))?;
    stage_with_wire(source, request, &verifier, expected_cursor, true, Some(native))
}

fn stage_with_wire<V: SettlementProofVerifierV1>(
    source: &BlochProviderFactory,
    request: SettlementRecoveryRequestV1<'_>,
    verifier: &V,
    expected_cursor: Option<B256>,
    require_native: bool,
    native: Option<&crate::native::VerifiedNativeFinalityV1>,
) -> Result<StagedFinalityCandidateV1, FinalityCandidateErrorV1> {
    reject_unverified_finality_markers(source).map_err(storage)?;
    let previous = {
        let reader = source.database_provider_ro().map_err(storage)?;
        read_finality_candidate(reader.tx_ref()).map_err(storage)?
    };
    if previous.map(|cursor| cursor.commitment()) != expected_cursor {
        return Err(FinalityCandidateErrorV1::CursorFloor);
    }
    let current_epoch = request.current_epoch;
    let recovery = recover_with_cursor(source, request, verifier, previous, require_native, native)
        .map_err(FinalityCandidateErrorV1::Recovery)?;
    let checkpoint = recovery
        .stores()
        .checkpoint_store()
        .current(current_epoch)
        .map_err(|_| FinalityCandidateErrorV1::Freshness)?;
    if let Some(native) = native {
        native
            .check_checkpoint(checkpoint.anchor(), checkpoint.epoch())
            .map_err(|e| FinalityCandidateErrorV1::Recovery(SettlementRecoveryErrorV1::NativeFinality(e)))?;
    }
    let settlement = recovery.stores().settlement_store();
    let head = settlement.registry().head().ok_or(FinalityCandidateErrorV1::Changed)?;
    let mark = settlement.mark();
    let cursor = FinalityCandidateCursorV1::from_fields(FinalityCandidateFieldsV1 {
        l2_genesis: recovery.report().genesis,
        settlement_policy: recovery.report().policy_commitment,
        checkpoint_policy: checkpoint.policy_identity(),
        settlement_record_digest: mark.record_digest,
        settlement_state_commitment: mark.state_commitment,
        l2_hash: head.l2_header_hash,
        l2_state_root: head.l2_state_root,
        checkpoint_digest: checkpoint.digest(),
        settlement_generation: mark.generation,
        l2_number: head.l2_number,
        checkpoint_epoch: checkpoint.epoch(),
        checked_at_epoch: current_epoch,
    })
    .map_err(storage)?;
    if let Some(previous) = previous {
        let old = previous.fields();
        let new = cursor.fields();
        if new.settlement_generation < old.settlement_generation
            || new.l2_number < old.l2_number
            || new.checkpoint_epoch < old.checkpoint_epoch
            || new.checked_at_epoch < old.checked_at_epoch
            || new.checkpoint_policy != old.checkpoint_policy
        {
            return Err(FinalityCandidateErrorV1::Changed);
        }
    }
    let writer = source.database_provider_rw().map_err(storage)?;
    if read_finality_candidate(writer.tx_ref()).map_err(storage)? != previous {
        return Err(FinalityCandidateErrorV1::Changed);
    }
    let tip = recovery.report().canonical_head;
    if writer.best_block_number().map_err(storage)? != tip.number
        || writer
            .sealed_header(tip.number)
            .map_err(storage)?
            .map(|h| (h.hash(), h.0.hash()))
            != Some((tip.hash, tip.hash))
    {
        return Err(FinalityCandidateErrorV1::Changed);
    }
    for key in [ChainStateKey::LastSafeBlock, ChainStateKey::LastFinalizedBlock] {
        if writer.tx_ref().get::<ChainState>(key).map_err(storage)?.is_some() {
            return Err(FinalityCandidateErrorV1::Changed);
        }
    }
    writer
        .tx_ref()
        .put::<BlochFinalityCandidate>(0, cursor)
        .map_err(storage)?;
    writer.commit().map_err(storage)?;
    Ok(StagedFinalityCandidateV1 { recovery, cursor })
}
