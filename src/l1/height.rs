// SPDX-License-Identifier: MIT OR Apache-2.0
//! Block-height identification from complete, checkpoint-authenticated ancestry.
//!
//! A configured genesis block establishes height zero. Each validated parent
//! edge adds one regardless of the slot gap. This identifies observed blocks;
//! it does not authenticate an inbox, authorize deposits or prove FFG finality.

use super::{parse, FinalizedCheckpoint, L1Error, HEADER_LEN, MAX_HEADERS};
use alloy_primitives::{Bytes, B256};

/// Maximum headers per advance, including the previous cursor and new checkpoint.
pub const MAX_HEIGHT_HEADERS: usize = MAX_HEADERS;

/// An invalid genesis, path or cursor extension; rejection preserves the cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeightError {
    /// Genesis must match the independently configured nonzero hash and have no parent.
    Genesis,
    /// Empty/oversized path or an incorrectly sized header.
    Bounds,
    /// Header encoding, parent linkage or final checkpoint is invalid.
    Authentication(L1Error),
    /// The first header is not the exact current cursor block.
    Continuity,
    /// No new block was supplied, or the checkpoint does not move forward.
    Replay,
    /// The derived block height cannot be represented.
    Overflow,
}

/// A block's derived position. No constructor accepts a claimed height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeightPosition {
    genesis: B256,
    block: B256,
    slot: u64,
    height: u64,
}
impl HeightPosition {
    /// Independently configured genesis block identity, not a genesis state root.
    pub fn genesis(&self) -> B256 {
        self.genesis
    }
    /// Exact identified block. Canonicality depends on the caller's checkpoint
    /// authority; this core type does not independently prove finality.
    pub fn block(&self) -> B256 {
        self.block
    }
    /// Consensus slot, retained independently of the derived block height.
    pub fn slot(&self) -> u64 {
        self.slot
    }
    /// Number of connected parent edges from the configured genesis block.
    pub fn height(&self) -> u64 {
        self.height
    }
}

/// In-memory identification cursor. Genesis is trusted configuration; every
/// subsequent position requires a complete path to an externally authenticated
/// checkpoint. No deserialization or arbitrary-height restore is provided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeightCursor {
    position: HeightPosition,
}
impl HeightCursor {
    /// Initialize at the exact configured genesis block (height zero).
    /// The caller must supply its real genesis block hash, not a state root or
    /// an RPC-selected starting block. Its slot is parsed, never used as height.
    pub fn from_genesis(expected_genesis: B256, header: &[u8]) -> Result<Self, HeightError> {
        let genesis = parse(header).map_err(HeightError::Authentication)?;
        if expected_genesis == B256::ZERO || genesis.id != expected_genesis || genesis.parent != B256::ZERO {
            return Err(HeightError::Genesis);
        }
        Ok(Self {
            position: HeightPosition {
                genesis: genesis.id,
                block: genesis.id,
                slot: genesis.slot,
                height: 0,
            },
        })
    }

    /// Last accepted position; initially the independently trusted genesis.
    pub fn position(&self) -> HeightPosition {
        self.position
    }

    /// Authenticate a complete forward path including both the current cursor
    /// and the new checkpoint. Checkpoint authority is external to this core API;
    /// the native checkpoint reader supplies a real PQ-verified checkpoint.
    /// Every failure leaves the original cursor unchanged.
    pub fn advance(
        &mut self,
        checkpoint: FinalizedCheckpoint,
        headers: &[Bytes],
    ) -> Result<HeightPosition, HeightError> {
        check_path_bounds(headers)?;
        let first = parse(&headers[0]).map_err(HeightError::Authentication)?;
        if first.id != self.position.block || first.slot != self.position.slot {
            return Err(HeightError::Continuity);
        }
        if headers.len() == 1 || checkpoint.slot <= self.position.slot || checkpoint.block == self.position.block {
            return Err(HeightError::Replay);
        }
        let mut previous = first;
        for bytes in &headers[1..] {
            let next = parse(bytes).map_err(HeightError::Authentication)?;
            if next.parent != previous.id || next.slot <= previous.slot {
                return Err(HeightError::Authentication(L1Error::Ancestry));
            }
            previous = next;
        }
        if previous.id != checkpoint.block || previous.slot != checkpoint.slot || checkpoint.block == B256::ZERO {
            return Err(HeightError::Authentication(L1Error::Checkpoint));
        }
        let height = self
            .position
            .height
            .checked_add((headers.len() - 1) as u64)
            .ok_or(HeightError::Overflow)?;
        let position = HeightPosition {
            genesis: self.position.genesis,
            block: previous.id,
            slot: previous.slot,
            height,
        };
        self.position = position;
        Ok(position)
    }
}

/// Cheap path bounds, reusable by a host before signature verification.
/// Transport must enforce limits before allocating vectors; this borrows input.
pub fn check_path_bounds(headers: &[Bytes]) -> Result<(), HeightError> {
    if headers.is_empty() || headers.len() > MAX_HEIGHT_HEADERS || headers.iter().any(|h| h.len() != HEADER_LEN) {
        return Err(HeightError::Bounds);
    }
    Ok(())
}
