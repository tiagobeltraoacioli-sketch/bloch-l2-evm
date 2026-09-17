// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read exactly the stored checkpoint state after checking its present freshness.
//! No arbitrary root or historical-header substitution is accepted by this API.
use crate::{verify_evm_commitment, verify_utxo, StateObservation, StateProofError};
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::l1::height::{check_path_bounds, HeightCursor, HeightError, HeightPosition};
use bloch_l2_evm::l1::{authenticate_body, AuthenticatedBody, L1Error};
use bloch_native_escrow_pq::{
    checkpoint::VerifiedCheckpoint,
    checkpoint_store::{CheckpointStore, StoreError},
};
use bloch_pos_committee::state_root::{EutxoEntry, EvmCommitment};

#[derive(Debug)]
pub enum ReadError {
    Limit,
    DuplicateOutput,
    Checkpoint(StoreError),
    Body(L1Error),
    State(StateProofError),
    Height(HeightError),
}

/// Maximum independent SMT paths per atomic read (2 MiB of sibling hashes).
pub const MAX_UTXO_BATCH: usize = 256;

/// Untrusted borrowed output and its root-to-leaf native SMT path.
pub struct UtxoRequest<'a> {
    pub entry: &'a EutxoEntry,
    pub siblings: &'a [[u8; 32]],
}

/// A checkpoint state observation annotated with a genesis-derived block height.
/// This is block identification, not escrow funding or a permission to mint.
#[derive(Debug)]
pub struct HeightCheckpointObservation<T> {
    observation: CheckpointObservation<T>,
    position: HeightPosition,
}
impl<T> HeightCheckpointObservation<T> {
    pub fn observation(&self) -> &CheckpointObservation<T> {
        &self.observation
    }
    pub fn position(&self) -> HeightPosition {
        self.position
    }
}

/// Read UTXOs at the latest signed checkpoint and atomically advance their
/// identification cursor through a complete chain from its previous position.
/// `headers` includes that previous header and ends at the checkpoint header;
/// only the checkpoint's complete transaction body and state proofs are supplied.
/// The existing reader checks PQ signatures, freshness, body and every SMT path.
/// Neither cursor nor store changes on failure. Successful calls advance only
/// the in-memory cursor; repeated state queries use [`read_utxos`] instead.
pub fn read_utxos_with_height(
    store: &CheckpointStore,
    current_epoch: u64,
    cursor: &mut HeightCursor,
    headers: &[Bytes],
    transactions: &[Bytes],
    requests: &[UtxoRequest<'_>],
) -> Result<Vec<HeightCheckpointObservation<EutxoEntry>>, ReadError> {
    check_path_bounds(headers).map_err(ReadError::Height)?;
    // Bounds established that this header exists and has the exact native length.
    let header = headers.last().ok_or(ReadError::Limit)?;
    let observations = read_utxos(store, current_epoch, header, transactions, requests)?;
    let anchor = observations.first().ok_or(ReadError::Limit)?.state().checkpoint();
    let mut candidate = cursor.clone();
    let position = candidate.advance(anchor, headers).map_err(ReadError::Height)?;
    let result = observations
        .into_iter()
        .map(|observation| HeightCheckpointObservation { observation, position })
        .collect();
    *cursor = candidate;
    Ok(result)
}

/// Read distinct outputs at one checkpoint, preserving request order. All bounds
/// and duplicate keys are checked before PQ work. Signatures and the block body
/// are authenticated once; no partial result escapes if any proof fails.
/// This is neither a complete wallet balance nor funding/mint authorization.
pub fn read_utxos(
    store: &CheckpointStore,
    current_epoch: u64,
    header: &[u8],
    transactions: &[Bytes],
    requests: &[UtxoRequest<'_>],
) -> Result<Vec<CheckpointObservation<EutxoEntry>>, ReadError> {
    if requests.is_empty() || requests.len() > MAX_UTXO_BATCH || requests.iter().any(|r| r.siblings.len() != 256) {
        return Err(ReadError::Limit);
    }
    let mut keys = std::collections::BTreeSet::new();
    for request in requests {
        // The official key binds the outpoint, independently of its claimed value.
        if !keys.insert(bloch_pos_committee::state_root::eutxo_leaf(request.entry).0) {
            return Err(ReadError::DuplicateOutput);
        }
    }
    let (cp, body) = body(store, current_epoch, header, transactions, requests[0].siblings)?;
    requests
        .iter()
        .map(|request| {
            let state = verify_utxo(&body, request.entry, request.siblings).map_err(ReadError::State)?;
            Ok(CheckpointObservation {
                state,
                checkpoint_epoch: cp.epoch(),
                checked_at_epoch: current_epoch,
                signed_digest: cp.digest(),
                review_due: cp.arrangement_review_due(),
            })
        })
        .collect()
}
/// Point-in-time observation, not a perpetual freshness assertion or mint permit.
#[derive(Debug)]
pub struct CheckpointObservation<T> {
    state: StateObservation<T>,
    checkpoint_epoch: u64,
    checked_at_epoch: u64,
    signed_digest: B256,
    review_due: bool,
}
impl<T> CheckpointObservation<T> {
    pub fn state(&self) -> &StateObservation<T> {
        &self.state
    }
    pub fn checkpoint_epoch(&self) -> u64 {
        self.checkpoint_epoch
    }
    pub fn checked_at_epoch(&self) -> u64 {
        self.checked_at_epoch
    }
    pub fn signed_digest(&self) -> B256 {
        self.signed_digest
    }
    pub fn arrangement_review_due(&self) -> bool {
        self.review_due
    }
}
fn body(
    store: &CheckpointStore,
    now: u64,
    header: &[u8],
    transactions: &[Bytes],
    siblings: &[[u8; 32]],
) -> Result<(VerifiedCheckpoint, AuthenticatedBody), ReadError> {
    // Cheap request bounds before PQ verification and before copying the header.
    if header.len() != 304
        || siblings.len() != 256
        || transactions.len() > 4096
        || transactions.iter().fold(0usize, |n, tx| n.saturating_add(tx.len())) > 16 * 1024 * 1024
    {
        return Err(ReadError::Limit);
    }
    let checkpoint = store.current(now).map_err(ReadError::Checkpoint)?;
    // Exactly one header: it must be the signed checkpoint block itself. A path
    // ending at it but proving an older pre-spend state is deliberately excluded.
    let body = authenticate_body(checkpoint.anchor(), &[Bytes::copy_from_slice(header)], transactions)
        .map_err(ReadError::Body)?;
    Ok((checkpoint, body))
}
fn observation<T>(state: StateObservation<T>, cp: VerifiedCheckpoint, now: u64) -> CheckpointObservation<T> {
    CheckpointObservation {
        state,
        checkpoint_epoch: cp.epoch(),
        checked_at_epoch: now,
        signed_digest: cp.digest(),
        review_due: cp.arrangement_review_due(),
    }
}
/// Verify an output in the latest stored signed checkpoint's state. This is not
/// necessarily the network's newest head, and does not prove escrow ownership.
pub fn read_utxo(
    store: &CheckpointStore,
    current_epoch: u64,
    header: &[u8],
    transactions: &[Bytes],
    entry: &EutxoEntry,
    siblings: &[[u8; 32]],
) -> Result<CheckpointObservation<EutxoEntry>, ReadError> {
    let (cp, body) = body(store, current_epoch, header, transactions, siblings)?;
    let state = verify_utxo(&body, entry, siblings).map_err(ReadError::State)?;
    Ok(observation(state, cp, current_epoch))
}
/// Observe the native EVM singleton through the same signed-checkpoint chain.
/// Inclusion does not demonstrate active execution or authorize withdrawals.
pub fn read_evm_commitment(
    store: &CheckpointStore,
    current_epoch: u64,
    header: &[u8],
    transactions: &[Bytes],
    entry: EvmCommitment,
    siblings: &[[u8; 32]],
) -> Result<CheckpointObservation<EvmCommitment>, ReadError> {
    let (cp, body) = body(store, current_epoch, header, transactions, siblings)?;
    let state = verify_evm_commitment(&body, entry, siblings).map_err(ReadError::State)?;
    Ok(observation(state, cp, current_epoch))
}
