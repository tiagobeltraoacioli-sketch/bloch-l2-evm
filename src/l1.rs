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
