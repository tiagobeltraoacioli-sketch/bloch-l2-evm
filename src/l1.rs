// SPDX-License-Identifier: MIT OR Apache-2.0
//! Genesis-4 header ancestry and complete-body authentication.
//!
//! A finalized checkpoint is an EXTERNAL trust input. This module verifies
//! ancestry/inclusion below it, not FFG votes, proposer signatures or finality.
//! It does not interpret escrow transactions or authorize minting/withdrawals.
use alloc::vec::Vec;
use alloy_primitives::{Bytes, B256};
use sha3::{Digest, Sha3_256};

pub mod height;

const HEADER_LEN: usize = 304;
const VERSION: u32 = 0xb10c_0005;
const MAX_HEADERS: usize = 2048;
const MAX_TRANSACTIONS: usize = 4096;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const EVIDENCE_TAG: &[u8] = b"BLOCH:L1:INCLUSION-EVIDENCE:1";
const EVIDENCE_COMMITMENT_TAG: &[u8] = b"BLOCH:L1:INCLUSION-EVIDENCE-COMMITMENT:1";
/// Maximum canonical byte length of a retained inclusion-evidence envelope.
pub const MAX_INCLUSION_EVIDENCE_V1_BYTES: usize =
    EVIDENCE_TAG.len() + 32 + 8 + 4 + MAX_HEADERS * HEADER_LEN + 4 + MAX_TRANSACTIONS * 4 + MAX_BODY_BYTES;

/// Finalized checkpoint authenticated by the embedding application, not an RPC assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedCheckpoint {
    /// Genesis-4 canonical block ID.
    pub block: B256,
    /// Consensus slot, NOT block height.
    pub slot: u64,
}

/// Rejection of unauthenticated, malformed or oversized L1 data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L1Error {
    /// Invalid evidence-envelope version, framing, length or trailing bytes.
    Evidence,
    /// Invalid version, encoding, or checkpoint value.
    Header,
    /// The ancestry path is empty or exceeds the local work limit.
    PathLimit,
    /// A parent link or strictly increasing slot does not match.
    Ancestry,
    /// The path does not terminate at the expected finalized checkpoint.
    Checkpoint,
    /// Local body byte or transaction-count bound exceeded.
    BodyLimit,
    /// Transaction bytes/order do not match the header's body commitment.
    BodyRoot,
    /// An empty byte string cannot identify a native transaction.
    TransactionEmpty,
    /// The exact native transaction is not present in the authenticated body.
    TransactionMissing,
    /// The exact native transaction occurs more than once, so its position is ambiguous.
    TransactionAmbiguous,
}

/// Canonical replay data for reauthenticating one complete native body.
///
/// Construction and decoding both verify the complete target-to-checkpoint
/// ancestry and body root. The checkpoint remains an external trust input: this
/// value preserves its exact identity but does not authenticate validator votes
/// or checkpoint authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionInclusionEvidenceV1 {
    checkpoint: FinalizedCheckpoint,
    headers: Vec<Bytes>,
    transactions: Vec<Bytes>,
}

impl TransactionInclusionEvidenceV1 {
    /// Verify and retain an exact complete-body ancestry package.
    pub fn new(
        checkpoint: FinalizedCheckpoint,
        headers: Vec<Bytes>,
        transactions: Vec<Bytes>,
    ) -> Result<Self, L1Error> {
        authenticate_body(checkpoint, &headers, &transactions)?;
        Ok(Self {
            checkpoint,
            headers,
            transactions,
        })
    }

    /// Exact external checkpoint named by this replay package.
    pub const fn checkpoint(&self) -> FinalizedCheckpoint {
        self.checkpoint
    }

    /// Complete target-to-checkpoint header path, including both endpoints.
    pub fn headers(&self) -> &[Bytes] {
        &self.headers
    }

    /// Complete ordered transaction body committed by the target header.
    pub fn transactions(&self) -> &[Bytes] {
        &self.transactions
    }

    /// Reverify ancestry and body before producing an exact inclusion
    /// capability. No cached successful result is trusted.
    pub fn authenticate_exact(&self, exact_transaction: &[u8]) -> Result<AuthenticatedTransactionInclusion, L1Error> {
        let body = authenticate_body(self.checkpoint, &self.headers, &self.transactions)?;
        authenticate_exact_transaction(&body, exact_transaction)
    }

    /// Encode one strict, bounded envelope. Header lengths are implicit and
    /// transaction lengths are canonical little-endian `u32` values.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(EVIDENCE_TAG);
        out.extend_from_slice(self.checkpoint.block.as_slice());
        out.extend_from_slice(&self.checkpoint.slot.to_le_bytes());
        out.extend_from_slice(&(self.headers.len() as u32).to_le_bytes());
        for header in &self.headers {
            out.extend_from_slice(header);
        }
        out.extend_from_slice(&(self.transactions.len() as u32).to_le_bytes());
        for transaction in &self.transactions {
            out.extend_from_slice(&(transaction.len() as u32).to_le_bytes());
            out.extend_from_slice(transaction);
        }
        out
    }

    /// SHA3-256 identity of the exact canonical envelope, with an independent
    /// domain and encoded-length prefix. Computation streams the retained
    /// fields and does not allocate a second envelope-sized buffer.
    pub fn commitment(&self) -> B256 {
        let mut hasher = Sha3_256::new();
        hasher.update(EVIDENCE_COMMITMENT_TAG);
        hasher.update((self.encoded_len() as u64).to_le_bytes());
        hasher.update(EVIDENCE_TAG);
        hasher.update(self.checkpoint.block);
        hasher.update(self.checkpoint.slot.to_le_bytes());
        hasher.update((self.headers.len() as u32).to_le_bytes());
        for header in &self.headers {
            hasher.update(header);
        }
        hasher.update((self.transactions.len() as u32).to_le_bytes());
        for transaction in &self.transactions {
            hasher.update((transaction.len() as u32).to_le_bytes());
            hasher.update(transaction);
        }
        B256::from_slice(&hasher.finalize())
    }

    /// Decode exactly one canonical envelope and reverify its ancestry and
    /// complete body before returning replay data.
    pub fn decode(bytes: &[u8]) -> Result<Self, L1Error> {
        if bytes.len() > MAX_INCLUSION_EVIDENCE_V1_BYTES || !bytes.starts_with(EVIDENCE_TAG) {
            return Err(L1Error::Evidence);
        }
        let mut reader = EvidenceReader(&bytes[EVIDENCE_TAG.len()..]);
        let checkpoint = FinalizedCheckpoint {
            block: B256::from_slice(reader.take(32)?),
            slot: reader.u64()?,
        };
        let header_count = reader.u32()? as usize;
        if header_count == 0 || header_count > MAX_HEADERS {
            return Err(L1Error::Evidence);
        }
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            headers.push(Bytes::copy_from_slice(reader.take(HEADER_LEN)?));
        }
        let transaction_count = reader.u32()? as usize;
        if transaction_count > MAX_TRANSACTIONS {
            return Err(L1Error::Evidence);
        }
        let mut body_bytes = 0usize;
        let mut transactions = Vec::with_capacity(transaction_count);
        for _ in 0..transaction_count {
            let length = reader.u32()? as usize;
            body_bytes = body_bytes.checked_add(length).ok_or(L1Error::Evidence)?;
            if body_bytes > MAX_BODY_BYTES {
                return Err(L1Error::Evidence);
            }
            transactions.push(Bytes::copy_from_slice(reader.take(length)?));
        }
        if !reader.0.is_empty() {
            return Err(L1Error::Evidence);
        }
        let evidence = Self::new(checkpoint, headers, transactions)?;
        if evidence.encode() != bytes {
            return Err(L1Error::Evidence);
        }
        Ok(evidence)
    }

    fn encoded_len(&self) -> usize {
        EVIDENCE_TAG.len()
            + 32
            + 8
            + 4
            + self.headers.len() * HEADER_LEN
            + 4
            + self.transactions.len() * 4
            + self
                .transactions
                .iter()
                .map(|transaction| transaction.len())
                .sum::<usize>()
    }
}

struct EvidenceReader<'a>(&'a [u8]);

impl<'a> EvidenceReader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], L1Error> {
        let (head, tail) = self.0.split_at_checked(count).ok_or(L1Error::Evidence)?;
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, L1Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| L1Error::Evidence)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, L1Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| L1Error::Evidence)?,
        ))
    }
}

/// A target header proved to be on the complete parent path to an externally
/// authenticated checkpoint. This proves ancestry only: it does not prove the
/// checkpoint's consensus authority or that any L2 commitment was settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedAncestry {
    block: B256,
    slot: u64,
    state_root: B256,
    body_root: B256,
    checkpoint: FinalizedCheckpoint,
}
impl AuthenticatedAncestry {
    /// Canonical ID of the target block.
    pub fn block(&self) -> B256 {
        self.block
    }
    /// Target slot; this must never be substituted for a block height.
    pub fn slot(&self) -> u64 {
        self.slot
    }
    /// State root committed by the target header.
    pub fn state_root(&self) -> B256 {
        self.state_root
    }
    /// External checkpoint that terminates the authenticated path.
    pub fn checkpoint(&self) -> FinalizedCheckpoint {
        self.checkpoint
    }
}

/// Full ordered transaction body authenticated below an external checkpoint.
/// Fields are private: values can only be obtained through verification.
#[derive(Debug, Clone)]
pub struct AuthenticatedBody {
    block: B256,
    slot: u64,
    state_root: B256,
    checkpoint: FinalizedCheckpoint,
    transactions: Vec<Bytes>,
}
impl AuthenticatedBody {
    /// Canonical ID of the target block.
    pub fn block(&self) -> B256 {
        self.block
    }
    /// Target slot; this must never be substituted for a block height.
    pub fn slot(&self) -> u64 {
        self.slot
    }
    /// Committed target state root; no state inclusion proof is performed here.
    pub fn state_root(&self) -> B256 {
        self.state_root
    }
    /// External checkpoint anchoring this result.
    pub fn checkpoint(&self) -> FinalizedCheckpoint {
        self.checkpoint
    }
    /// Complete authenticated transactions in canonical block order.
    pub fn transactions(&self) -> &[Bytes] {
        &self.transactions
    }
}

/// Exact transaction bytes and position proved inside an authenticated native
/// block body. Private fields prevent callers from manufacturing an inclusion
/// capability from an RPC response or a transaction hash alone.
///
/// This proves byte inclusion below the externally authenticated checkpoint. It
/// does not interpret the transaction, prove that native consensus assigns it a
/// settlement transition, verify an execution proof or finalize an L2 block.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedTransactionInclusion {
    block: B256,
    slot: u64,
    checkpoint: FinalizedCheckpoint,
    transaction_index: u32,
    transaction: Bytes,
}
impl AuthenticatedTransactionInclusion {
    /// Native block whose complete body contains the transaction.
    pub fn block(&self) -> B256 {
        self.block
    }
    /// Consensus slot of that native block; this is not a block height.
    pub fn slot(&self) -> u64 {
        self.slot
    }
    /// External checkpoint terminating the authenticated ancestry path.
    pub fn checkpoint(&self) -> FinalizedCheckpoint {
        self.checkpoint
    }
    /// Zero-based position in the complete canonical body.
    pub fn transaction_index(&self) -> u32 {
        self.transaction_index
    }
    /// Exact committed transaction bytes, without an invented transaction-ID rule.
    pub fn transaction(&self) -> &[u8] {
        &self.transaction
    }
}

/// Select one exact, unique transaction from a previously authenticated body.
///
/// Requiring uniqueness prevents a later settlement adapter from accidentally
/// binding a commitment to an unspecified occurrence. The complete-body bounds
/// enforced by [`authenticate_body`] guarantee the index fits in `u32`.
pub fn authenticate_exact_transaction(
    body: &AuthenticatedBody,
    exact_transaction: &[u8],
) -> Result<AuthenticatedTransactionInclusion, L1Error> {
    if exact_transaction.is_empty() {
        return Err(L1Error::TransactionEmpty);
    }
    let mut matches = body
        .transactions
        .iter()
        .enumerate()
        .filter(|(_, transaction)| transaction.as_ref() == exact_transaction);
    let (index, transaction) = matches.next().ok_or(L1Error::TransactionMissing)?;
    if matches.next().is_some() {
        return Err(L1Error::TransactionAmbiguous);
    }
    Ok(AuthenticatedTransactionInclusion {
        block: body.block,
        slot: body.slot,
        checkpoint: body.checkpoint,
        transaction_index: index as u32,
        transaction: transaction.clone(),
    })
}

struct Header {
    id: B256,
    parent: B256,
    state: B256,
    body: B256,
    slot: u64,
}
fn parse(bytes: &[u8]) -> Result<Header, L1Error> {
    if bytes.len() != HEADER_LEN || bytes[..4] != VERSION.to_le_bytes() {
        return Err(L1Error::Header);
    }
    Ok(Header {
        id: hash(&[b"BLCH4:BLOCK\0\0\0\0\0", bytes]),
        parent: B256::from_slice(&bytes[4..36]),
        state: B256::from_slice(&bytes[36..68]),
        body: B256::from_slice(&bytes[68..100]),
        slot: u64::from_le_bytes(bytes[100..108].try_into().map_err(|_| L1Error::Header)?),
    })
}
fn hash(parts: &[&[u8]]) -> B256 {
    let mut h = Sha3_256::new();
    for part in parts {
        h.update(part);
    }
    B256::from_slice(&h.finalize())
}
fn body_root(transactions: &[Bytes]) -> Result<B256, L1Error> {
    if transactions.len() > MAX_TRANSACTIONS {
        return Err(L1Error::BodyLimit);
    }
    let size = transactions.iter().fold(0usize, |n, tx| n.saturating_add(tx.len()));
    if size > MAX_BODY_BYTES {
        return Err(L1Error::BodyLimit);
    }
    let tag = b"BLCH4:BODY\0\0\0\0\0\0";
    if transactions.is_empty() {
        return Ok(hash(&[tag, &[2, 1]]));
    }
    let mut level: Vec<B256> = transactions
        .iter()
        .map(|tx| hash(&[tag, &[0, 1], &(tx.len() as u64).to_le_bytes(), tx]))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(if pair.len() == 2 {
                hash(&[tag, &[1, 1], pair[0].as_slice(), pair[1].as_slice()])
            } else {
                pair[0]
            }); // Genesis-4 promotes odd nodes; it does not duplicate them.
        }
        level = next;
    }
    Ok(level[0])
}

/// Verify a complete target-to-checkpoint header path without requiring the
/// target body. Include both target and checkpoint headers. This is useful for
/// authenticating an L2 header's native anchor while keeping that fact distinct
/// from L2 settlement/finality. Checkpoint consensus authentication remains an
/// external obligation of the embedding application.
pub fn authenticate_ancestry(
    checkpoint: FinalizedCheckpoint,
    headers: &[Bytes],
) -> Result<AuthenticatedAncestry, L1Error> {
    if headers.is_empty() || headers.len() > MAX_HEADERS {
        return Err(L1Error::PathLimit);
    }
    if checkpoint.block == B256::ZERO {
        return Err(L1Error::Checkpoint);
    }
    let target = parse(&headers[0])?;
    let mut previous_id = target.id;
    let mut previous_slot = target.slot;
    for encoded in &headers[1..] {
        let header = parse(encoded)?;
        if header.parent != previous_id || header.slot <= previous_slot {
            return Err(L1Error::Ancestry);
        }
        previous_id = header.id;
        previous_slot = header.slot;
    }
    if previous_id != checkpoint.block || previous_slot != checkpoint.slot {
        return Err(L1Error::Checkpoint);
    }
    Ok(AuthenticatedAncestry {
        block: target.id,
        slot: target.slot,
        state_root: target.state,
        body_root: target.body,
        checkpoint,
    })
}

/// Verify a target body and its forward ancestry path ending at the checkpoint.
/// Include BOTH target and checkpoint headers; adjacent slots may have gaps.
/// The host must cap transport bytes before decoding/allocating input vectors.
/// Successful inclusion proves neither bridge ownership nor semantic validity
/// independently of the external checkpoint's consensus authentication.
pub fn authenticate_body(
    checkpoint: FinalizedCheckpoint,
    headers: &[Bytes],
    transactions: &[Bytes],
) -> Result<AuthenticatedBody, L1Error> {
    let ancestry = authenticate_ancestry(checkpoint, headers)?;
    if body_root(transactions)? != ancestry.body_root {
        return Err(L1Error::BodyRoot);
    }
    Ok(AuthenticatedBody {
        block: ancestry.block,
        slot: ancestry.slot,
        state_root: ancestry.state_root,
        checkpoint: ancestry.checkpoint,
        transactions: transactions.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_exact_bytes_are_not_an_inclusion_capability() {
        let transaction = Bytes::from_static(b"same canonical transaction");
        let body = AuthenticatedBody {
            block: B256::repeat_byte(1),
            slot: 2,
            state_root: B256::repeat_byte(3),
            checkpoint: FinalizedCheckpoint {
                block: B256::repeat_byte(4),
                slot: 5,
            },
            transactions: vec![transaction.clone(), transaction.clone()],
        };
        assert_eq!(
            authenticate_exact_transaction(&body, &transaction).unwrap_err(),
            L1Error::TransactionAmbiguous
        );
    }
}
