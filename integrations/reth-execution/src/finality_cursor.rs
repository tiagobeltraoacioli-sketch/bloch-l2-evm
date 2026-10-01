// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded durable candidate accounting, never authority for an RPC finalized tag.
use crate::BlochProviderFactory;
use alloy_evm::block::BlockExecutionError;
use alloy_primitives::{keccak256, B256};
use reth_codecs::{Compress, Decompress, DecompressError};
use reth_db_api::{
    table::{Table, TableInfo},
    tables::{ChainState, ChainStateKey},
    transaction::DbTx,
};
use reth_provider::DatabaseProviderFactory;

const TAG: &[u8; 8] = b"BLFNCU01";
pub const FINALITY_CANDIDATE_BYTES: usize = 8 + 8 * 32 + 4 * 8;

/// Public audit data. Supplying these fields does not authenticate any evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalityCandidateFieldsV1 {
    pub l2_genesis: B256,
    pub settlement_policy: B256,
    pub checkpoint_policy: B256,
    pub settlement_record_digest: B256,
    pub settlement_state_commitment: B256,
    pub l2_hash: B256,
    pub l2_state_root: B256,
    pub checkpoint_digest: B256,
    pub settlement_generation: u64,
    pub l2_number: u64,
    pub checkpoint_epoch: u64,
    pub checked_at_epoch: u64,
}

/// Exactly framed storage data; construction validates framing, not finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalityCandidateCursorV1(FinalityCandidateFieldsV1);

impl FinalityCandidateCursorV1 {
    pub fn from_fields(fields: FinalityCandidateFieldsV1) -> Result<Self, alloy_rlp::Error> {
        let cursor = Self(fields);
        if cursor.hashes().contains(&B256::ZERO)
            || fields.settlement_generation == 0
            || fields.l2_number == 0
            || fields.checked_at_epoch < fields.checkpoint_epoch
        {
            return Err(alloy_rlp::Error::Custom("invalid finality candidate fields"));
        }
        Ok(cursor)
    }

    pub const fn fields(&self) -> &FinalityCandidateFieldsV1 {
        &self.0
    }

    fn hashes(&self) -> [B256; 8] {
        let f = self.0;
        [
            f.l2_genesis,
            f.settlement_policy,
            f.checkpoint_policy,
            f.settlement_record_digest,
            f.settlement_state_commitment,
            f.l2_hash,
            f.l2_state_root,
            f.checkpoint_digest,
        ]
    }

    pub fn encode(&self) -> [u8; FINALITY_CANDIDATE_BYTES] {
        let mut bytes = [0; FINALITY_CANDIDATE_BYTES];
        bytes[..8].copy_from_slice(TAG);
        for (i, hash) in self.hashes().iter().enumerate() {
            bytes[8 + i * 32..8 + (i + 1) * 32].copy_from_slice(hash.as_slice());
        }
        let f = self.0;
        for (i, number) in [
            f.settlement_generation,
            f.l2_number,
            f.checkpoint_epoch,
            f.checked_at_epoch,
        ]
        .iter()
        .enumerate()
        {
            bytes[264 + i * 8..264 + (i + 1) * 8].copy_from_slice(&number.to_le_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, alloy_rlp::Error> {
        if bytes.len() != FINALITY_CANDIDATE_BYTES || &bytes[..8] != TAG {
            return Err(alloy_rlp::Error::Custom("invalid finality candidate framing"));
        }
        let hash = |i: usize| B256::from_slice(&bytes[8 + i * 32..8 + (i + 1) * 32]);
        let number = |i: usize| u64::from_le_bytes(bytes[264 + i * 8..264 + (i + 1) * 8].try_into().unwrap());
        Self::from_fields(FinalityCandidateFieldsV1 {
            l2_genesis: hash(0),
            settlement_policy: hash(1),
            checkpoint_policy: hash(2),
            settlement_record_digest: hash(3),
            settlement_state_commitment: hash(4),
            l2_hash: hash(5),
            l2_state_root: hash(6),
            checkpoint_digest: hash(7),
            settlement_generation: number(0),
            l2_number: number(1),
            checkpoint_epoch: number(2),
            checked_at_epoch: number(3),
        })
    }

    /// Exact CAS/rollback mark to retain outside the inspected database.
    pub fn commitment(&self) -> B256 {
        keccak256(self.encode())
    }
}

impl serde::Serialize for FinalityCandidateCursorV1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.encode())
    }
}
impl Compress for FinalityCandidateCursorV1 {
    type Compressed = Vec<u8>;
    fn compress_to_buf<B: alloy_rlp::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        buf.put_slice(&self.encode());
    }
}
impl Decompress for FinalityCandidateCursorV1 {
    fn decompress(value: &[u8]) -> Result<Self, DecompressError> {
        Self::decode(value).map_err(DecompressError::new)
    }
}

/// A singleton at key zero, independent of Reth's numeric finality markers.
#[derive(Debug)]
pub struct BlochFinalityCandidate;
impl Table for BlochFinalityCandidate {
    const NAME: &'static str = "BlochFinalityCandidate";
    const DUPSORT: bool = false;
    type Key = u64;
    type Value = FinalityCandidateCursorV1;
}
impl TableInfo for BlochFinalityCandidate {
    fn name(&self) -> &'static str {
        <Self as Table>::NAME
    }
    fn is_dupsort(&self) -> bool {
        false
    }
}

/// Read bounded data only. Reverification is required before using a saved cursor.
pub fn read_finality_candidate<T: DbTx>(tx: &T) -> Result<Option<FinalityCandidateCursorV1>, BlockExecutionError> {
    let candidate = tx
        .get::<BlochFinalityCandidate>(0)
        .map_err(BlockExecutionError::other)?;
    if tx
        .entries::<BlochFinalityCandidate>()
        .map_err(BlockExecutionError::other)?
        != usize::from(candidate.is_some())
    {
        return Err(BlockExecutionError::msg("unexpected finality candidate rows"));
    }
    Ok(candidate)
}

/// The current host has no qualified finality publisher. Numeric metadata alone
/// must never survive startup as an authenticated safe/finalized capability.
pub fn reject_unverified_finality_markers(source: &BlochProviderFactory) -> Result<(), BlockExecutionError> {
    let reader = source.database_provider_ro().map_err(BlockExecutionError::other)?;
    for key in [ChainStateKey::LastSafeBlock, ChainStateKey::LastFinalizedBlock] {
        if reader
            .tx_ref()
            .get::<ChainState>(key)
            .map_err(BlockExecutionError::other)?
            .is_some()
        {
            return Err(BlockExecutionError::msg(
                "saved RPC finality marker requires qualified native settlement recovery",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursor_codec_rejects_noncanonical_incomplete_and_oversized_storage() {
        let cursor = FinalityCandidateCursorV1::from_fields(FinalityCandidateFieldsV1 {
            l2_genesis: B256::repeat_byte(1),
            settlement_policy: B256::repeat_byte(2),
            checkpoint_policy: B256::repeat_byte(3),
            settlement_record_digest: B256::repeat_byte(4),
            settlement_state_commitment: B256::repeat_byte(5),
            l2_hash: B256::repeat_byte(6),
            l2_state_root: B256::repeat_byte(7),
            checkpoint_digest: B256::repeat_byte(8),
            settlement_generation: 1,
            l2_number: 1,
            checkpoint_epoch: 100,
            checked_at_epoch: 101,
        })
        .unwrap();
        let bytes = cursor.encode();
        assert_eq!(bytes.len(), 296);
        assert_eq!(FinalityCandidateCursorV1::decompress(&bytes).unwrap(), cursor);
        for length in 0..bytes.len() {
            assert!(FinalityCandidateCursorV1::decompress(&bytes[..length]).is_err());
        }
        assert!(FinalityCandidateCursorV1::decompress(&[bytes.as_slice(), &[0]].concat()).is_err());
        for offset in [0, 8, 264, 272, 288] {
            let mut malformed = bytes;
            let width = if offset == 8 { 32 } else { 8 };
            malformed[offset..offset + width].fill(0);
            assert!(FinalityCandidateCursorV1::decompress(&malformed).is_err());
        }
    }
}
