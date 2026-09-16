// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read exactly the stored checkpoint state after checking its present freshness.
//! No arbitrary root or historical-header substitution is accepted by this API.
use crate::{verify_evm_commitment, verify_utxo, StateObservation, StateProofError};
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::l1::{authenticate_body, AuthenticatedBody, L1Error};
use bloch_native_escrow_pq::{
    checkpoint::VerifiedCheckpoint,
    checkpoint_store::{CheckpointStore, StoreError},
};
use bloch_pos_committee::state_root::{EutxoEntry, EvmCommitment};

#[derive(Debug)]
pub enum ReadError {
    Limit,
    Checkpoint(StoreError),
    Body(L1Error),
    State(StateProofError),
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
