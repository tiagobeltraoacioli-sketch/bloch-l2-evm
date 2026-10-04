// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable audit candidates for native asynchronous settlements. These records
//! never authorize Ethereum finality tags, bridge actions or network activation.
use crate::native::{
    audit_finalized_async_settlements, NativeFinalityErrorV1, NativeFinalityReportV1, VerifiedNativeFinalityV1,
};
use alloy_primitives::{keccak256, B256};
use bloch_l2_evm::{
    l1::FinalizedCheckpoint, native_settlement::SettlementPolicyV1, proof_statement::SettlementStatementV2,
};
use bloch_reth_execution::{
    async_finality_cursor::{
        read_async_finality_candidate, AsyncFinalityCandidateCursorV1, AsyncFinalityCandidateFieldsV1,
        BlochAsyncFinalityCandidate,
    },
    finality_cursor::reject_unverified_finality_markers,
    settlement_binding::{CanonicalSettlementAuditErrorV1, CanonicalSettlementAuditReportV1},
    BlochProviderFactory, ReplayFloor, ReplayLimits,
};
use reth_db_api::{
    tables::{ChainState, ChainStateKey},
    transaction::{DbTx, DbTxMut},
};
use reth_provider::{BlockNumReader, DBProvider, DatabaseProviderFactory, HeaderProvider};

/// Independent host inputs. Neither floor may be copied from the database under
/// inspection. The epoch is an observation bound, not a freshness certification.
pub struct AsyncFinalityCandidateRequestV1 {
    pub settlement_policy: SettlementPolicyV1,
    pub l2_floor: ReplayFloor,
    pub canonical_limits: ReplayLimits,
    pub expected_cursor: Option<B256>,
    pub current_epoch: u64,
}

#[derive(Debug)]
pub enum AsyncFinalityCandidateErrorV1 {
    Audit(CanonicalSettlementAuditErrorV1<NativeFinalityErrorV1>),
    Native(NativeFinalityErrorV1),
    Storage(String),
    /// Missing, additional or replaced candidate relative to the retained mark.
    CursorFloor,
    /// The saved candidate does not match the fully reverified finalized prefix.
    Previous,
    /// The canonical tip, candidate or numeric markers changed before commit.
    Changed,
}
impl std::fmt::Display for AsyncFinalityCandidateErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "asynchronous finality candidate refused: {self:?}")
    }
}
impl std::error::Error for AsyncFinalityCandidateErrorV1 {}
fn storage(error: impl std::fmt::Display) -> AsyncFinalityCandidateErrorV1 {
    AsyncFinalityCandidateErrorV1::Storage(error.to_string())
}

/// Persisted accounting only. Loading or copying it cannot reconstruct the
/// private native replay capability; every restart must repeat both audits.
pub struct StagedAsyncFinalityCandidateV1 {
    cursor: AsyncFinalityCandidateCursorV1,
    canonical: CanonicalSettlementAuditReportV1,
    native: NativeFinalityReportV1,
}
impl StagedAsyncFinalityCandidateV1 {
    pub const fn cursor(&self) -> AsyncFinalityCandidateCursorV1 {
        self.cursor
    }
    pub const fn canonical(&self) -> &CanonicalSettlementAuditReportV1 {
        &self.canonical
    }
    pub const fn native(&self) -> &NativeFinalityReportV1 {
        &self.native
    }
}

/// Audit the complete finalized async settlement prefix against canonical L2,
/// rederive any saved candidate, then atomically replace the separate singleton.
/// `verified` can only originate in real native signature/proof/FFG replay.
///
/// The host must stop all Reth/static-file writers. The commit compares the old
/// cursor and acknowledged canonical tip in the same MDBX write transaction.
/// Retain the returned commitment independently before acknowledging success.
/// A commit error may be uncertain: do not retry by adopting the on-disk value.
///
/// Prior finalized checkpoints and settlements must remain in the exact prefix;
/// unfinalized native tails may reorganize. This does not require a fresh native
/// checkpoint or publish `safe`/`finalized`; it records bounded recovery evidence.
pub fn recover_and_stage_async_finality_candidate(
    source: &BlochProviderFactory,
    request: AsyncFinalityCandidateRequestV1,
    verified: &VerifiedNativeFinalityV1,
) -> Result<StagedAsyncFinalityCandidateV1, AsyncFinalityCandidateErrorV1> {
    stage(source, request, verified, || {})
}

#[cfg(test)]
pub(crate) fn stage_with_test_hook(
    source: &BlochProviderFactory,
    request: AsyncFinalityCandidateRequestV1,
    verified: &VerifiedNativeFinalityV1,
    before_commit: impl FnOnce(),
) -> Result<StagedAsyncFinalityCandidateV1, AsyncFinalityCandidateErrorV1> {
    stage(source, request, verified, before_commit)
}

// The private hook is exercised by storage race tests; public callers cannot
// insert mutations between verification and publication.
fn stage(
    source: &BlochProviderFactory,
    request: AsyncFinalityCandidateRequestV1,
    verified: &VerifiedNativeFinalityV1,
    before_commit: impl FnOnce(),
) -> Result<StagedAsyncFinalityCandidateV1, AsyncFinalityCandidateErrorV1> {
    use AsyncFinalityCandidateErrorV1 as E;
    reject_unverified_finality_markers(source).map_err(storage)?;
    let previous = {
        let reader = source.database_provider_ro().map_err(storage)?;
        read_async_finality_candidate(reader.tx_ref()).map_err(storage)?
    };
    if previous.map(|cursor| cursor.commitment()) != request.expected_cursor {
        return Err(E::CursorFloor);
    }
    if request.current_epoch < bloch_pos_committee::epoch_of(verified.report().replayed_slot) {
        return Err(E::Native(NativeFinalityErrorV1::Trust));
    }
    let canonical = audit_finalized_async_settlements(
        verified,
        source,
        request.settlement_policy,
        request.l2_floor,
        request.canonical_limits,
    )
    .map_err(E::Audit)?;
    let cursor = derive_candidate(verified, &canonical, request.current_epoch, previous)?;
    before_commit();
    let writer = source.database_provider_rw().map_err(storage)?;
    if read_async_finality_candidate(writer.tx_ref()).map_err(storage)? != previous {
        return Err(E::Changed);
    }
    let tip = canonical.canonical_head;
    if writer.best_block_number().map_err(storage)? != tip.number
        || writer
            .sealed_header(tip.number)
            .map_err(storage)?
            .map(|h| (h.hash(), h.0.hash()))
            != Some((tip.hash, tip.hash))
    {
        return Err(E::Changed);
    }
    for key in [ChainStateKey::LastSafeBlock, ChainStateKey::LastFinalizedBlock] {
        if writer.tx_ref().get::<ChainState>(key).map_err(storage)?.is_some() {
            return Err(E::Changed);
        }
    }
    writer
        .tx_ref()
        .put::<BlochAsyncFinalityCandidate>(0, cursor)
        .map_err(storage)?;
    writer.commit().map_err(storage)?;
    Ok(StagedAsyncFinalityCandidateV1 {
        cursor,
        canonical,
        native: *verified.report(),
    })
}

fn derive_candidate(
    verified: &VerifiedNativeFinalityV1,
    canonical: &CanonicalSettlementAuditReportV1,
    current_epoch: u64,
    previous: Option<AsyncFinalityCandidateCursorV1>,
) -> Result<AsyncFinalityCandidateCursorV1, AsyncFinalityCandidateErrorV1> {
    use AsyncFinalityCandidateErrorV1 as E;
    let report = verified.report();
    if let Some(previous) = previous {
        let f = previous.fields();
        if f.checked_at_epoch > current_epoch
            || f.checked_at_epoch < f.native_finalized_epoch
            || f.native_genesis_state_root != report.genesis_state_root
            || f.settlement_policy != report.settlement_policy
            || f.l2_genesis != canonical.genesis
        {
            return Err(E::Previous);
        }
        verified
            .check_checkpoint(
                FinalizedCheckpoint {
                    block: f.native_finalized_block,
                    slot: f.native_finalized_slot,
                },
                f.native_finalized_epoch,
            )
            .map_err(E::Native)?;
    }
    // Domain-separated audit digest, not a native consensus commitment. The
    // original 0x0F bytes, including proof and tag, remain bound at every step.
    let mut prefix = keccak256(
        [
            b"BLOCH:L2:ASYNC-CANDIDATE-PREFIX:1".as_slice(),
            report.genesis_state_root.as_slice(),
            report.settlement_policy.as_slice(),
            canonical.genesis.as_slice(),
        ]
        .concat(),
    );
    let mut count = 0u64;
    let mut last = None;
    let mut previous_seen = previous.is_none();
    for (slot, block, bytes) in verified.finalized_settlements() {
        let tx = bloch_pos_committee::l2_settlement::Transaction::decode_async(bytes)
            .ok_or(E::Native(NativeFinalityErrorV1::Encoding))?;
        let statement =
            SettlementStatementV2::decode(&tx.statement).map_err(|_| E::Native(NativeFinalityErrorV1::Encoding))?;
        count = count.checked_add(1).ok_or(E::Previous)?;
        let digest = keccak256(bytes);
        prefix = keccak256(
            [
                prefix.as_slice(),
                &slot.to_le_bytes(),
                block.as_slice(),
                digest.as_slice(),
            ]
            .concat(),
        );
        let fields = AsyncFinalityCandidateFieldsV1 {
            native_genesis_state_root: report.genesis_state_root,
            settlement_policy: report.settlement_policy,
            native_finalized_block: report.finalized.block,
            native_settlement_block: block,
            settlement_prefix_digest: prefix,
            l2_genesis: canonical.genesis,
            l2_hash: statement.l2_header_hash,
            l2_state_root: statement.l2_state_root,
            native_settlement_digest: digest,
            native_finalized_epoch: report.finalized_epoch,
            native_finalized_slot: report.finalized.slot,
            native_settlement_slot: slot,
            l2_number: statement.l2_number,
            settlement_count: count,
            checked_at_epoch: current_epoch,
        };
        if let Some(previous) = previous {
            let old = previous.fields();
            if slot <= old.native_finalized_slot && count > old.settlement_count {
                return Err(E::Previous);
            }
            if count == old.settlement_count {
                let reconstructed = AsyncFinalityCandidateFieldsV1 {
                    native_finalized_block: old.native_finalized_block,
                    native_finalized_epoch: old.native_finalized_epoch,
                    native_finalized_slot: old.native_finalized_slot,
                    checked_at_epoch: old.checked_at_epoch,
                    ..fields
                };
                if reconstructed != *old || slot > old.native_finalized_slot {
                    return Err(E::Previous);
                }
                previous_seen = true;
            }
        }
        last = Some(fields);
    }
    let last = last.ok_or(E::Previous)?;
    if !previous_seen
        || count != canonical.audited_records
        || canonical.last_settlement.map(|b| (b.number, b.hash)) != Some((last.l2_number, last.l2_hash))
    {
        return Err(E::Previous);
    }
    AsyncFinalityCandidateCursorV1::from_fields(last).map_err(storage)
}
