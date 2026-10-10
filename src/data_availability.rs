// SPDX-License-Identifier: MIT OR Apache-2.0
//! L1 data availability for settlement V3 user transactions (milestone M3).
//!
//! The native chain stores only hashes of what an L2 block executed. A block
//! with user transactions therefore settles only after its exact transaction
//! batch is published in a native `L2DataAvailability` transaction (wire
//! `0x15`), and the settlement statement names that batch in
//! [`crate::proof_statement::SettlementStatementV3::da_commitment`]. The
//! native verifier (`bloch_pos_committee::l2_settlement::da`) parses the same
//! bytes independently; the shared vector `tests/fixtures/l2-da-v1` pins both.
//!
//! * Payload (version 1): `count` (u32 BE, at least 1), then for each
//!   transaction `len` (u32 BE, at least 1) followed by the exact signed
//!   EIP-2718 envelope as it appears in [`crate::node_primitives::NodeBodyV2`],
//!   in body order; no trailing bytes; at most [`MAX_DA_PAYLOAD_BYTES`].
//! * Commitment: `keccak256("BLOCH:L2:DA:1" || chain_id (u64 BE) ||
//!   l2_block_number (u64 BE) || payload)`; zero for a block without user
//!   transactions.
//!
//! Deposits are not part of the batch: the native inbox already holds them.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use alloy_primitives::{keccak256, Bytes, B256};

/// Domain separator of the DA commitment.
pub const DA_COMMITMENT_DOMAIN: &[u8] = b"BLOCH:L2:DA:1";
/// Largest batch the native chain accepts in one DA transaction (112 KiB,
/// `bloch_pos_committee::l2_settlement::da::MAX_PAYLOAD_BYTES`). A block whose
/// batch is larger could never settle, so the statement refuses it.
pub const MAX_DA_PAYLOAD_BYTES: usize = 114_688;
/// Framing bytes of a batch with `transactions` entries.
pub const fn da_framing_bytes(transactions: usize) -> usize {
    4 + 4 * transactions
}

/// Why a payload is not one canonical batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaPayloadError {
    /// Empty batch (blocks without user transactions publish nothing).
    Empty,
    /// Larger than [`MAX_DA_PAYLOAD_BYTES`].
    TooLarge,
    /// A zero-length transaction entry.
    EmptyTransaction,
    /// Truncated, inconsistent count or trailing bytes.
    Malformed,
}

impl core::fmt::Display for DaPayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Empty => "DA batch has no transactions",
            Self::TooLarge => "DA batch exceeds the native size cap",
            Self::EmptyTransaction => "DA batch has an empty transaction",
            Self::Malformed => "DA batch is not canonical",
        })
    }
}
impl core::error::Error for DaPayloadError {}

/// Encode the canonical batch of `transactions` (body order).
pub fn encode_da_payload(transactions: &[Bytes]) -> Result<Vec<u8>, DaPayloadError> {
    if transactions.is_empty() {
        return Err(DaPayloadError::Empty);
    }
    let mut size = da_framing_bytes(transactions.len());
    for tx in transactions {
        if tx.is_empty() {
            return Err(DaPayloadError::EmptyTransaction);
        }
        size = size.checked_add(tx.len()).ok_or(DaPayloadError::TooLarge)?;
    }
    if size > MAX_DA_PAYLOAD_BYTES {
        return Err(DaPayloadError::TooLarge);
    }
    let count = u32::try_from(transactions.len()).map_err(|_| DaPayloadError::TooLarge)?;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&count.to_be_bytes());
    for tx in transactions {
        // Bounded by MAX_DA_PAYLOAD_BYTES above.
        out.extend_from_slice(&(tx.len() as u32).to_be_bytes());
        out.extend_from_slice(tx);
    }
    Ok(out)
}

/// Decode a canonical batch back into its transaction envelopes.
pub fn decode_da_payload(payload: &[u8]) -> Result<Vec<Bytes>, DaPayloadError> {
    if payload.len() > MAX_DA_PAYLOAD_BYTES {
        return Err(DaPayloadError::TooLarge);
    }
    let word = |at: usize| -> Result<usize, DaPayloadError> {
        let bytes = payload.get(at..at + 4).ok_or(DaPayloadError::Malformed)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
    };
    let count = word(0)?;
    if count == 0 {
        return Err(DaPayloadError::Empty);
    }
    // Every entry needs at least 5 bytes: no allocation from an inflated count.
    if count > (payload.len() - 4) / 5 {
        return Err(DaPayloadError::Malformed);
    }
    let mut out = Vec::with_capacity(count);
    let mut at = 4usize;
    for _ in 0..count {
        let len = word(at)?;
        if len == 0 {
            return Err(DaPayloadError::EmptyTransaction);
        }
        at += 4;
        let tx = payload.get(at..at + len).ok_or(DaPayloadError::Malformed)?;
        out.push(Bytes::copy_from_slice(tx));
        at += len;
    }
    if at != payload.len() {
        return Err(DaPayloadError::Malformed);
    }
    Ok(out)
}

/// The DA commitment of a canonical payload for one L2 block.
pub fn da_commitment(chain_id: u64, l2_block_number: u64, payload: &[u8]) -> B256 {
    let mut preimage = Vec::with_capacity(DA_COMMITMENT_DOMAIN.len() + 16 + payload.len());
    preimage.extend_from_slice(DA_COMMITMENT_DOMAIN);
    preimage.extend_from_slice(&chain_id.to_be_bytes());
    preimage.extend_from_slice(&l2_block_number.to_be_bytes());
    preimage.extend_from_slice(payload);
    keccak256(&preimage)
}

/// The commitment a V3 statement carries for a block's user transactions:
/// zero without user transactions, otherwise [`da_commitment`] of the batch.
pub fn block_da_commitment(
    chain_id: u64,
    l2_block_number: u64,
    transactions: &[Bytes],
) -> Result<B256, DaPayloadError> {
    if transactions.is_empty() {
        return Ok(B256::ZERO);
    }
    Ok(da_commitment(
        chain_id,
        l2_block_number,
        &encode_da_payload(transactions)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    fn vector_transactions() -> Vec<Bytes> {
        vec![
            Bytes::from_static(&[0x02, 0xc0]),
            Bytes::from((0u8..100).collect::<Vec<_>>()),
        ]
    }

    /// Shared with bloch-validator-payout `da_batch_matches_the_shared_vector`.
    #[test]
    fn da_batch_cross_repository_vector() {
        let payload = encode_da_payload(&vector_transactions()).unwrap();
        let fixture = include_str!("../tests/fixtures/l2-da-v1/batch.hex");
        assert_eq!(hex::encode(&payload), fixture.trim());
        assert_eq!(decode_da_payload(&payload).unwrap(), vector_transactions());
        let expected = include_str!("../tests/fixtures/l2-da-v1/commitment-700771-7.hex");
        assert_eq!(hex::encode(da_commitment(700771, 7, &payload)), expected.trim());
        assert_eq!(
            block_da_commitment(700771, 7, &vector_transactions()).unwrap(),
            da_commitment(700771, 7, &payload)
        );
        assert_eq!(block_da_commitment(700771, 7, &[]).unwrap(), B256::ZERO);
    }

    #[test]
    fn da_payload_codec_rejects_noncanonical_and_oversize() {
        assert_eq!(encode_da_payload(&[]), Err(DaPayloadError::Empty));
        assert_eq!(
            encode_da_payload(&[Bytes::new()]),
            Err(DaPayloadError::EmptyTransaction)
        );
        let fill = MAX_DA_PAYLOAD_BYTES - da_framing_bytes(1);
        let at_cap = encode_da_payload(&[Bytes::from(vec![1u8; fill])]).unwrap();
        assert_eq!(at_cap.len(), MAX_DA_PAYLOAD_BYTES);
        assert_eq!(decode_da_payload(&at_cap).unwrap().len(), 1);
        assert_eq!(
            encode_da_payload(&[Bytes::from(vec![1u8; fill + 1])]),
            Err(DaPayloadError::TooLarge)
        );
        let good = encode_da_payload(&vector_transactions()).unwrap();
        for (bad, error) in [
            (vec![], DaPayloadError::Malformed),
            (vec![0, 0, 0, 0], DaPayloadError::Empty),
            ([good.clone(), vec![0]].concat(), DaPayloadError::Malformed),
            (good[..good.len() - 1].to_vec(), DaPayloadError::Malformed),
            (vec![0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1, 7], DaPayloadError::Malformed),
            (vec![0, 0, 0, 1, 0, 0, 0, 0], DaPayloadError::Malformed),
            (vec![0, 0, 0, 1, 0, 0, 0, 0, 0], DaPayloadError::EmptyTransaction),
        ] {
            assert_eq!(decode_da_payload(&bad), Err(error), "{bad:?}");
        }
    }
}
