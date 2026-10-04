// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded asynchronous settlement candidate data, never RPC finality authority.
use alloy_evm::block::BlockExecutionError;
use alloy_primitives::{keccak256, B256};
use reth_codecs::{Compress, Decompress, DecompressError};
use reth_db_api::{
    table::{Table, TableInfo},
    transaction::DbTx,
};

const TAG: &[u8; 8] = b"BLAFNC01";
pub const ASYNC_FINALITY_CANDIDATE_BYTES: usize = 8 + 9 * 32 + 6 * 8;

/// Public audit data. These fields do not authenticate native or L2 evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsyncFinalityCandidateFieldsV1 {
    pub native_genesis_state_root: B256,
    pub settlement_policy: B256,
    pub native_finalized_block: B256,
    pub native_settlement_block: B256,
    pub settlement_prefix_digest: B256,
    pub l2_genesis: B256,
    pub l2_hash: B256,
    pub l2_state_root: B256,
    pub native_settlement_digest: B256,
    pub native_finalized_epoch: u64,
    pub native_finalized_slot: u64,
    pub native_settlement_slot: u64,
    pub l2_number: u64,
    pub settlement_count: u64,
    pub checked_at_epoch: u64,
}

/// Exactly framed storage data; construction checks structure, not authority,
/// freshness, native ancestry or correspondence with canonical L2 storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsyncFinalityCandidateCursorV1(AsyncFinalityCandidateFieldsV1);

impl AsyncFinalityCandidateCursorV1 {
    pub fn from_fields(fields: AsyncFinalityCandidateFieldsV1) -> Result<Self, alloy_rlp::Error> {
        let cursor = Self(fields);
        if cursor.hashes().contains(&B256::ZERO)
            || cursor.numbers().contains(&0)
            || fields.native_settlement_slot > fields.native_finalized_slot
        {
            return Err(alloy_rlp::Error::Custom(
                "invalid asynchronous finality candidate fields",
            ));
        }
        Ok(cursor)
    }

    pub const fn fields(&self) -> &AsyncFinalityCandidateFieldsV1 {
        &self.0
    }

    fn hashes(&self) -> [B256; 9] {
        let f = self.0;
        [
            f.native_genesis_state_root,
            f.settlement_policy,
            f.native_finalized_block,
            f.native_settlement_block,
            f.settlement_prefix_digest,
            f.l2_genesis,
            f.l2_hash,
            f.l2_state_root,
            f.native_settlement_digest,
        ]
    }

    fn numbers(&self) -> [u64; 6] {
        let f = self.0;
        [
            f.native_finalized_epoch,
            f.native_finalized_slot,
            f.native_settlement_slot,
            f.l2_number,
            f.settlement_count,
            f.checked_at_epoch,
        ]
    }

    pub fn encode(&self) -> [u8; ASYNC_FINALITY_CANDIDATE_BYTES] {
        let mut bytes = [0; ASYNC_FINALITY_CANDIDATE_BYTES];
        bytes[..8].copy_from_slice(TAG);
        for (i, hash) in self.hashes().iter().enumerate() {
            bytes[8 + i * 32..8 + (i + 1) * 32].copy_from_slice(hash.as_slice());
        }
        for (i, number) in self.numbers().iter().enumerate() {
            bytes[296 + i * 8..296 + (i + 1) * 8].copy_from_slice(&number.to_le_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, alloy_rlp::Error> {
        if bytes.len() != ASYNC_FINALITY_CANDIDATE_BYTES || &bytes[..8] != TAG {
            return Err(alloy_rlp::Error::Custom(
                "invalid asynchronous finality candidate framing",
            ));
        }
        let hash = |i: usize| B256::from_slice(&bytes[8 + i * 32..8 + (i + 1) * 32]);
        let number = |i: usize| u64::from_le_bytes(bytes[296 + i * 8..296 + (i + 1) * 8].try_into().unwrap());
        Self::from_fields(AsyncFinalityCandidateFieldsV1 {
            native_genesis_state_root: hash(0),
            settlement_policy: hash(1),
            native_finalized_block: hash(2),
            native_settlement_block: hash(3),
            settlement_prefix_digest: hash(4),
            l2_genesis: hash(5),
            l2_hash: hash(6),
            l2_state_root: hash(7),
            native_settlement_digest: hash(8),
            native_finalized_epoch: number(0),
            native_finalized_slot: number(1),
            native_settlement_slot: number(2),
            l2_number: number(3),
            settlement_count: number(4),
            checked_at_epoch: number(5),
        })
    }

    /// Exact CAS/rollback mark to retain outside the inspected database.
    pub fn commitment(&self) -> B256 {
        keccak256(self.encode())
    }
}

impl serde::Serialize for AsyncFinalityCandidateCursorV1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.encode())
    }
}
impl Compress for AsyncFinalityCandidateCursorV1 {
    type Compressed = Vec<u8>;
    fn compress_to_buf<B: alloy_rlp::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        buf.put_slice(&self.encode());
    }
}
impl Decompress for AsyncFinalityCandidateCursorV1 {
    fn decompress(value: &[u8]) -> Result<Self, DecompressError> {
        Self::decode(value).map_err(DecompressError::new)
    }
}

/// A singleton at key zero, separate from WS candidates and RPC finality markers.
#[derive(Debug)]
pub struct BlochAsyncFinalityCandidate;
impl Table for BlochAsyncFinalityCandidate {
    const NAME: &'static str = "BlochAsyncFinalityCandidate";
    const DUPSORT: bool = false;
    type Key = u64;
    type Value = AsyncFinalityCandidateCursorV1;
}
impl TableInfo for BlochAsyncFinalityCandidate {
    fn name(&self) -> &'static str {
        <Self as Table>::NAME
    }
    fn is_dupsort(&self) -> bool {
        false
    }
}

/// Read bounded audit data only. Reverify all evidence before using a saved cursor.
pub fn read_async_finality_candidate<T: DbTx>(
    tx: &T,
) -> Result<Option<AsyncFinalityCandidateCursorV1>, BlockExecutionError> {
    let candidate = tx
        .get::<BlochAsyncFinalityCandidate>(0)
        .map_err(BlockExecutionError::other)?;
    if tx
        .entries::<BlochAsyncFinalityCandidate>()
        .map_err(BlockExecutionError::other)?
        != usize::from(candidate.is_some())
    {
        return Err(BlockExecutionError::msg(
            "unexpected asynchronous finality candidate rows",
        ));
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor() -> AsyncFinalityCandidateCursorV1 {
        AsyncFinalityCandidateCursorV1::from_fields(AsyncFinalityCandidateFieldsV1 {
            native_genesis_state_root: B256::repeat_byte(1),
            settlement_policy: B256::repeat_byte(2),
            native_finalized_block: B256::repeat_byte(3),
            native_settlement_block: B256::repeat_byte(4),
            settlement_prefix_digest: B256::repeat_byte(5),
            l2_genesis: B256::repeat_byte(6),
            l2_hash: B256::repeat_byte(7),
            l2_state_root: B256::repeat_byte(8),
            native_settlement_digest: B256::repeat_byte(9),
            native_finalized_epoch: 2,
            native_finalized_slot: 63,
            native_settlement_slot: 32,
            l2_number: 1,
            settlement_count: 1,
            checked_at_epoch: 3,
        })
        .unwrap()
    }

    #[test]
    fn cursor_roundtrip_preserves_exact_framing_and_commitment() {
        let cursor = cursor();
        let bytes = cursor.encode();
        assert_eq!(bytes.len(), 344);
        assert_eq!(&bytes[..8], b"BLAFNC01");
        assert_eq!(&bytes[296..304], &2u64.to_le_bytes());
        assert_eq!(&bytes[336..344], &3u64.to_le_bytes());
        assert_eq!(AsyncFinalityCandidateCursorV1::decode(&bytes).unwrap(), cursor);
        assert_eq!(AsyncFinalityCandidateCursorV1::decompress(&bytes).unwrap(), cursor);
        assert_eq!(cursor.compress(), bytes.to_vec());
        assert_eq!(cursor.commitment(), keccak256(bytes));
    }

    #[test]
    fn cursor_rejects_every_truncation_suffix_and_foreign_tag() {
        let bytes = cursor().encode();
        for length in 0..bytes.len() {
            assert!(AsyncFinalityCandidateCursorV1::decompress(&bytes[..length]).is_err());
        }
        assert!(AsyncFinalityCandidateCursorV1::decompress(&[bytes.as_slice(), &[0]].concat()).is_err());
        for offset in 0..TAG.len() {
            let mut malformed = bytes;
            malformed[offset] ^= 1;
            assert!(AsyncFinalityCandidateCursorV1::decompress(&malformed).is_err());
        }
    }

    #[test]
    fn cursor_rejects_each_zero_identity_and_required_number() {
        let bytes = cursor().encode();
        for index in 0..9 {
            let mut malformed = bytes;
            malformed[8 + index * 32..8 + (index + 1) * 32].fill(0);
            assert!(AsyncFinalityCandidateCursorV1::decompress(&malformed).is_err());
        }
        for index in 0..6 {
            let mut malformed = bytes;
            malformed[296 + index * 8..296 + (index + 1) * 8].fill(0);
            assert!(AsyncFinalityCandidateCursorV1::decompress(&malformed).is_err());
        }
    }

    #[test]
    fn cursor_requires_containing_slot_within_finalized_prefix_without_claiming_freshness() {
        let mut fields = *cursor().fields();
        fields.native_settlement_slot = fields.native_finalized_slot + 1;
        assert!(AsyncFinalityCandidateCursorV1::from_fields(fields).is_err());
        fields.native_settlement_slot = fields.native_finalized_slot;
        assert!(AsyncFinalityCandidateCursorV1::from_fields(fields).is_ok());
        // A framing codec is not a current-epoch or native authority verifier.
        fields.checked_at_epoch = 1;
        assert!(AsyncFinalityCandidateCursorV1::from_fields(fields).is_ok());
    }
}
