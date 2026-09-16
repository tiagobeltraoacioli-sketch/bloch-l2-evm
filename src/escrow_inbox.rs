// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental ordered escrow inclusion, not L1 finality or mint authority.
use crate::escrow::LockedDeposit;
use alloc::vec::Vec;
use alloy_primitives::B256;
use sha3::{Digest, Sha3_256};

/// Authenticated membership summary, not a mint permit or consumption receipt.
/// The caller remains responsible for authenticating the expected root and count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInboxRange {
    root: B256,
    count: u64,
    range: core::ops::Range<u64>,
    total_sat: u128,
}
impl VerifiedInboxRange {
    /// Independently supplied root against which every proof verified.
    pub fn root(&self) -> B256 {
        self.root
    }
    /// Total snapshot length, including deposits outside this interval.
    pub fn count(&self) -> u64 {
        self.count
    }
    /// Exact verified half-open sequence interval.
    pub fn range(&self) -> core::ops::Range<u64> {
        self.range.clone()
    }
    /// Sum of native amounts in this interval, not the full inbox balance.
    pub fn total_sat(&self) -> u128 {
        self.total_sat
    }
}

/// Verify an exact nonempty interval against independently supplied expectations.
/// Missing, extra, reordered and repeated sequences fail as a whole. No cursor
/// advances, and no unverified partial total is exposed on failure.
/// Empty ranges are refused because no inclusion proof can bind their root/count.
pub fn verify_proof_range(
    network: B256,
    domain: B256,
    expected_root: B256,
    expected_count: u64,
    range: core::ops::Range<u64>,
    proofs: &[InboxProof],
) -> Option<VerifiedInboxRange> {
    if range.start >= range.end
        || range.end > expected_count
        || range.end - range.start > 4096
        || proofs.len() as u64 != range.end - range.start
        || proofs.iter().any(|p| p.siblings.len() > 64)
    {
        return None;
    }
    let mut total_sat = 0u128;
    for (sequence, proof) in range.clone().zip(proofs) {
        if proof.deposit.sequence != sequence
            || proof.count != expected_count
            || !proof.verify(network, domain, expected_root)
        {
            return None;
        }
        // At most 4096 u64 amounts, so the sum fits u128.
        total_sat += proof.deposit.amount as u128;
    }
    Some(VerifiedInboxRange {
        root: expected_root,
        count: expected_count,
        range,
        total_sat,
    })
}

fn hash(tag: &[u8], parts: &[&[u8]]) -> B256 {
    let mut h = Sha3_256::new();
    h.update(tag);
    for part in parts {
        h.update(part);
    }
    B256::from_slice(&h.finalize())
}
fn leaf(d: &LockedDeposit) -> B256 {
    hash(
        b"BLOCH:EXPERIMENTAL:INBOX:LEAF:1",
        &[
            d.id.as_slice(),
            d.domain.as_slice(),
            d.recipient.as_slice(),
            &d.amount.to_le_bytes(),
            &d.sequence.to_le_bytes(),
        ],
    )
}
fn parent(left: B256, right: B256) -> B256 {
    hash(b"BLOCH:EXPERIMENTAL:INBOX:NODE:1", &[left.as_slice(), right.as_slice()])
}
fn wrap(network: B256, domain: B256, count: u64, tree: B256) -> B256 {
    hash(
        b"BLOCH:EXPERIMENTAL:INBOX:ROOT:1",
        &[
            network.as_slice(),
            domain.as_slice(),
            &count.to_le_bytes(),
            tree.as_slice(),
        ],
    )
}
fn reduce(nodes: &[B256]) -> Vec<B256> {
    nodes
        .chunks(2)
        .map(|p| if p.len() == 2 { parent(p[0], p[1]) } else { p[0] })
        .collect()
}

/// Immutable local snapshot. Its root still requires independent L1 authentication.
#[derive(Debug, Clone)]
pub struct InboxSnapshot {
    records: Vec<LockedDeposit>,
    levels: Vec<Vec<B256>>,
    root: B256,
}
impl InboxSnapshot {
    /// Generate an exact contiguous range using cached levels. Empty ranges are
    /// valid at or before the snapshot end; no truncation or cursor advance occurs.
    /// Bound matches the execution layer's maximum deposits per block.
    pub fn proofs(&self, range: core::ops::Range<u64>) -> Option<Vec<InboxProof>> {
        if range.start > range.end || range.end > self.records.len() as u64 || range.end - range.start > 4096 {
            return None;
        }
        range.map(|sequence| self.proof(sequence)).collect()
    }
    pub(crate) fn new(network: B256, domain: B256, mut records: Vec<LockedDeposit>) -> Self {
        records.sort_unstable_by_key(|d| d.sequence);
        let mut levels = Vec::new();
        let mut nodes: Vec<_> = records.iter().map(leaf).collect();
        while nodes.len() > 1 {
            let next = reduce(&nodes);
            levels.push(nodes);
            nodes = next;
        }
        let tree = nodes
            .first()
            .copied()
            .unwrap_or_else(|| hash(b"BLOCH:EXPERIMENTAL:INBOX:EMPTY:1", &[]));
        let root = wrap(network, domain, records.len() as u64, tree);
        Self { records, levels, root }
    }
    /// Number of escrow locks in this snapshot.
    pub fn len(&self) -> usize {
        self.records.len()
    }
    /// Whether no locks have been recorded.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Commitment to network, domain, exact count and the ordered Merkle tree.
    pub fn root(&self) -> B256 {
        self.root
    }
    /// Build an inclusion path for a zero-based sequence. Odd nodes are promoted.
    pub fn proof(&self, sequence: u64) -> Option<InboxProof> {
        let mut index = usize::try_from(sequence).ok()?;
        let deposit = self.records.get(index)?.clone();
        let mut siblings = Vec::with_capacity(self.levels.len());
        for nodes in &self.levels {
            if index % 2 == 1 {
                siblings.push(nodes[index - 1]);
            } else if index + 1 < nodes.len() {
                siblings.push(nodes[index + 1]);
            }
            index /= 2;
        }
        Some(InboxProof {
            deposit,
            count: self.records.len() as u64,
            siblings,
        })
    }
}

/// Untrusted inclusion data; verification does not establish finality or unspentness.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InboxProof {
    /// Complete claimed deposit; every field is authenticated by the leaf.
    pub deposit: LockedDeposit,
    /// Exact snapshot count, authenticated by the root wrapper.
    pub count: u64,
    /// Bottom-up path; no sibling is supplied for an odd promoted node.
    pub siblings: Vec<B256>,
}
impl InboxProof {
    /// Check against independently supplied network, domain and expected inbox root.
    /// Never use a root supplied by the same untrusted proof as a trust anchor.
    /// This authenticates membership only; replay consumption belongs to derivation.
    pub fn verify(&self, network: B256, domain: B256, expected_root: B256) -> bool {
        if network == B256::ZERO
            || domain == B256::ZERO
            || self.deposit.domain != domain
            || self.count == 0
            || self.deposit.sequence >= self.count
            || self.siblings.len() > 64
        {
            return false;
        }
        let mut node = leaf(&self.deposit);
        let mut index = self.deposit.sequence;
        let mut width = self.count;
        let mut path = self.siblings.iter();
        while width > 1 {
            if index % 2 == 1 {
                let Some(sibling) = path.next() else {
                    return false;
                };
                node = parent(*sibling, node);
            } else if index < width - 1 {
                let Some(sibling) = path.next() else {
                    return false;
                };
                node = parent(node, *sibling);
            }
            index /= 2;
            width = width / 2 + width % 2;
        }
        path.next().is_none() && wrap(network, domain, self.count, node) == expected_root
    }
}
