// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only Genesis-4 state inclusion under an externally trusted checkpoint.
//! Membership is not escrow, fresh unspentness, EVM execution or mint authority.
use alloy_primitives::B256;
use bloch_l2_evm::l1::{AuthenticatedBody, FinalizedCheckpoint};
use bloch_pos_committee::{
    params::DS_STATE,
    state_root::{eutxo_leaf, verify_inclusion, EutxoEntry, EvmCommitment, InclusionProof},
};
use sha3::{Digest, Sha3_256};

#[cfg(unix)]
pub mod checkpoint_reader;

/// Proof rejection before returning an authenticated observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateProofError {
    /// Native SMT requires exactly 256 siblings, root-to-leaf ordered.
    Length,
    /// Key/value/path do not match the authenticated block's state root.
    Inclusion,
}
/// A value observed in one authenticated block state. Private provenance fields.
/// This does not expose a constructor from arbitrary RPC values or roots.
#[derive(Debug, Clone)]
pub struct StateObservation<T> {
    value: T,
    block: B256,
    slot: u64,
    state_root: B256,
    checkpoint: FinalizedCheckpoint,
}
impl<T> StateObservation<T> {
    pub fn value(&self) -> &T {
        &self.value
    }
    pub fn block(&self) -> B256 {
        self.block
    }
    /// Slot, never silently substituted for block height.
    pub fn slot(&self) -> u64 {
        self.slot
    }
    pub fn state_root(&self) -> B256 {
        self.state_root
    }
    /// The externally authenticated checkpoint used for header ancestry.
    pub fn checkpoint(&self) -> FinalizedCheckpoint {
        self.checkpoint
    }
}

fn authenticate<T>(
    body: &AuthenticatedBody,
    value: T,
    key: [u8; 32],
    value_hash: [u8; 32],
    siblings: &[[u8; 32]],
) -> Result<StateObservation<T>, StateProofError> {
    if siblings.len() != 256 {
        return Err(StateProofError::Length);
    }
    let proof = InclusionProof {
        siblings: siblings.to_vec(),
    };
    if !verify_inclusion(&body.state_root().into(), &key, &value_hash, &proof) {
        return Err(StateProofError::Inclusion);
    }
    Ok(StateObservation {
        value,
        block: body.block(),
        slot: body.slot(),
        state_root: body.state_root(),
        checkpoint: body.checkpoint(),
    })
}

/// Verify exact native output data using the official key/value codec and SMT
/// verifier. The coin was unspent at this block, not necessarily at the current head.
pub fn verify_utxo(
    body: &AuthenticatedBody,
    entry: &EutxoEntry,
    siblings: &[[u8; 32]],
) -> Result<StateObservation<EutxoEntry>, StateProofError> {
    let (key, value_hash) = eutxo_leaf(entry);
    authenticate(body, entry.clone(), key, value_hash, siblings)
}

fn state_hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_STATE);
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
/// Existing native singleton key (component 0x10); NOT an execution-domain inbox.
pub fn evm_commitment_key() -> [u8; 32] {
    state_hash(&[&[0x03, 0x10]])
}

/// Verify the existing 80-byte native EVM commitment leaf. This observes what L1
/// commits; it does not prove that an EVM segment ran or authorize withdrawals.
pub fn verify_evm_commitment(
    body: &AuthenticatedBody,
    entry: EvmCommitment,
    siblings: &[[u8; 32]],
) -> Result<StateObservation<EvmCommitment>, StateProofError> {
    let value_hash = state_hash(&[
        &[0x04],
        &entry.account_root,
        &entry.receipts_root,
        &entry.gas_used.to_le_bytes(),
        &entry.base_fee_per_gas.to_le_bytes(),
    ]);
    authenticate(body, entry, evm_commitment_key(), value_hash, siblings)
}
