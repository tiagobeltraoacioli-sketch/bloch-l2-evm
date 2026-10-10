// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental source mapping; no native consensus activation or mint authority.
//!
//! The expected source commitment is explicitly trusted out of band. Neither an
//! observed native transfer nor a UTXO membership proof can supply that authority.
use alloy_primitives::{keccak256, Bytes, B256};
use bloch_l2_evm::{
    domain::TrustedL1Batch,
    escrow::{EscrowLedger, LockedDeposit},
    escrow_execution::{TrustedEscrowBatch, TrustedLockLocation},
    escrow_inbox::{verify_proof_range, InboxProof},
    l1::{
        height::{HeightCursor, HeightPosition},
        FinalizedCheckpoint,
    },
    DepositPosition,
};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(unix)]
pub mod journal;

mod v2;
pub use v2::ValidatedV2Prefix;

mod payload;
pub use payload::{SourcePayload, MAX_SOURCE_PAYLOAD_BYTES};

mod settlement;
pub use settlement::{
    proof_digest, settlement_v2_groth16_proof_policy_commitment, settlement_v3_groth16_proof_policy_commitment,
    SettlementPayload, SettlementPayloadV2,
    MAX_SETTLEMENT_PROOF_BYTES, SETTLEMENT_PAYLOAD_BYTES, SETTLEMENT_PAYLOAD_V2_BYTES, SP1_GROTH16_TRANSPORT_BYTES,
};

mod settlement_selection;
pub use settlement_selection::ValidatedSettlementSelectionV1;
#[cfg(unix)]
pub use settlement_selection::{PersistedSettlementAdmissionV1, SettlementSelectionCommitErrorV1};

const TAG: &[u8] = b"BLOCH:EXPERIMENTAL:SOURCE:1";
/// Entire retained inbox limit, not a per-page limit. No truncation is permitted.
pub const MAX_LOCKS: usize = 4096;
const RECORD_BYTES: usize = 8 + 32 + 32 + 8 + 4 + 4;
const FIXED_BYTES: usize = TAG.len() + 32 * 6 + 8 * 3 + 4;
/// Maximum canonical source message length; checked before allocating records.
pub const MAX_SOURCE_BYTES: usize = FIXED_BYTES + MAX_LOCKS * RECORD_BYTES;

/// Explicit height mapping supplied by the source authority. Slot is never height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceAnchor {
    pub block: B256,
    pub slot: u64,
    pub height: u64,
}

/// Complete source mapping for one finalized experimental inbox snapshot.
/// Decoding or hashing this value authenticates nothing by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBatch {
    pub network: B256,
    pub domain: B256,
    pub genesis: B256,
    pub previous: B256,
    pub anchor: SourceAnchor,
    pub inbox_root: B256,
    pub count: u64,
    pub locations: Vec<TrustedLockLocation>,
}

/// Failure leaves the registry unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Codec,
    Limit,
    Authority,
    Identity,
    Replay,
    Ancestry,
    Incomplete,
    Mapping,
    Conflict,
    Inclusion,
    Body,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "experimental source mapping rejected: {self:?}")
    }
}
impl std::error::Error for Error {}

impl SourceBatch {
    /// Fixed-width little-endian fields in declaration order, then u32 record
    /// count and records (sequence, intent, transaction, height, tx index, vout).
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.locations.len() > MAX_LOCKS || self.count > MAX_LOCKS as u64 {
            return Err(Error::Limit);
        }
        let mut out = Vec::with_capacity(FIXED_BYTES + self.locations.len() * RECORD_BYTES);
        out.extend_from_slice(TAG);
        for value in [
            self.network,
            self.domain,
            self.genesis,
            self.previous,
            self.anchor.block,
        ] {
            out.extend_from_slice(value.as_slice());
        }
        out.extend_from_slice(&self.anchor.slot.to_le_bytes());
        out.extend_from_slice(&self.anchor.height.to_le_bytes());
        out.extend_from_slice(self.inbox_root.as_slice());
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&(self.locations.len() as u32).to_le_bytes());
        for location in &self.locations {
            out.extend_from_slice(&location.sequence.to_le_bytes());
            out.extend_from_slice(location.intent.as_slice());
            out.extend_from_slice(location.transaction.as_slice());
            out.extend_from_slice(&location.position.l1_height.to_le_bytes());
            out.extend_from_slice(&location.position.l1_tx_index.to_le_bytes());
            out.extend_from_slice(&location.position.l1_vout.to_le_bytes());
        }
        Ok(out)
    }

    /// Exact-message decoder: rejects trailing data, unknown versions, malformed
    /// counts and every truncated prefix. No unbounded serde entry point exists.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SOURCE_BYTES {
            return Err(Error::Limit);
        }
        if bytes.len() < FIXED_BYTES || !bytes.starts_with(TAG) {
            return Err(Error::Codec);
        }
        let mut reader = Reader(&bytes[TAG.len()..]);
        let network = B256::from(reader.take::<32>()?);
        let domain = B256::from(reader.take::<32>()?);
        let genesis = B256::from(reader.take::<32>()?);
        let previous = B256::from(reader.take::<32>()?);
        let block = B256::from(reader.take::<32>()?);
        let slot = u64::from_le_bytes(reader.take()?);
        let height = u64::from_le_bytes(reader.take()?);
        let inbox_root = B256::from(reader.take::<32>()?);
        let count = u64::from_le_bytes(reader.take()?);
        let records = u32::from_le_bytes(reader.take()?) as usize;
        if records > MAX_LOCKS || count > MAX_LOCKS as u64 {
            return Err(Error::Limit);
        }
        if reader.0.len() != records * RECORD_BYTES {
            return Err(Error::Codec);
        }
        let mut locations = Vec::with_capacity(records);
        for _ in 0..records {
            locations.push(TrustedLockLocation {
                sequence: u64::from_le_bytes(reader.take()?),
                intent: B256::from(reader.take::<32>()?),
                transaction: B256::from(reader.take::<32>()?),
                position: DepositPosition {
                    l1_height: u64::from_le_bytes(reader.take()?),
                    l1_tx_index: u32::from_le_bytes(reader.take()?),
                    l1_vout: u32::from_le_bytes(reader.take()?),
                },
            });
        }
        Ok(Self {
            network,
            domain,
            genesis,
            previous,
            anchor: SourceAnchor { block, slot, height },
            inbox_root,
            count,
            locations,
        })
    }

    /// Local transport commitment, not a native transaction ID or certificate.
    pub fn commitment(&self) -> Result<B256, Error> {
        Ok(keccak256(self.encode()?))
    }
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);
impl Reader<'_> {
    pub(crate) fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let value = self
            .0
            .get(..N)
            .ok_or(Error::Codec)?
            .try_into()
            .map_err(|_| Error::Codec)?;
        self.0 = &self.0[N..];
        Ok(value)
    }
}

/// Bounded in-memory registry. Source progress is independent of EVM consumption.
/// Restart must replay all accepted batches against independently retained trust;
/// an untrusted serialized snapshot must never bootstrap this object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRegistry {
    network: B256,
    domain: B256,
    genesis: B256,
    cursor: HeightCursor,
    anchor: SourceAnchor,
    commitment: B256,
    inbox_root: B256,
    locations: Vec<TrustedLockLocation>,
    deposits: Vec<LockedDeposit>,
}
impl SourceRegistry {
    /// Explicit trusted bootstrap with an empty experimental inbox. This is not
    /// a native checkpoint verifier and does not infer height from the slot.
    /// Only a genesis cursor is accepted; arbitrary-height restoration is absent.
    pub fn new(network: B256, domain: B256, cursor: HeightCursor) -> Result<Self, Error> {
        let position = cursor.position();
        let anchor = SourceAnchor {
            block: position.block(),
            slot: position.slot(),
            height: position.height(),
        };
        let genesis = position.genesis();
        if network == B256::ZERO
            || domain == B256::ZERO
            || anchor.block == B256::ZERO
            || anchor.height != 0
            || anchor.block != genesis
        {
            return Err(Error::Configuration);
        }
        let inbox_root = EscrowLedger::new(network, domain, vec![], MAX_LOCKS)
            .map_err(|_| Error::Configuration)?
            .inbox()
            .root();
        // The first previous commitment binds even an empty bootstrap's policy.
        let bootstrap = SourceBatch {
            network,
            domain,
            genesis,
            previous: B256::ZERO,
            anchor,
            inbox_root,
            count: 0,
            locations: vec![],
        };
        Ok(Self {
            network,
            domain,
            genesis,
            cursor,
            anchor,
            commitment: bootstrap.commitment()?,
            inbox_root,
            locations: vec![],
            deposits: vec![],
        })
    }

    pub fn network(&self) -> B256 {
        self.network
    }
    pub fn genesis(&self) -> B256 {
        self.genesis
    }
    pub fn domain(&self) -> B256 {
        self.domain
    }

    pub fn commitment(&self) -> B256 {
        self.commitment
    }
    pub fn anchor(&self) -> SourceAnchor {
        self.anchor
    }
    pub fn inbox_root(&self) -> B256 {
        self.inbox_root
    }
    pub fn count(&self) -> u64 {
        self.locations.len() as u64
    }
    /// Mapping only; this function never constructs a mint authorization.
    pub fn locations(&self) -> &[TrustedLockLocation] {
        &self.locations
    }

    /// Join the accepted source mapping with a separately trusted execution
    /// input. This does not authenticate transaction DA or authorize minting.
    /// The escrow execution verifier still enforces its mandatory deposit prefix.
    pub fn execution_batch(
        &self,
        execution: TrustedL1Batch,
        range: std::ops::Range<u64>,
    ) -> Result<TrustedEscrowBatch, Error> {
        if execution.domain != self.domain
            || execution.height != self.anchor.height
            || execution.block != self.anchor.block
            || execution.input == B256::ZERO
        {
            return Err(Error::Identity);
        }
        if range.start > range.end || range.end > self.count() {
            return Err(Error::Incomplete);
        }
        Ok(TrustedEscrowBatch {
            execution,
            inbox_root: self.inbox_root,
            count: self.count(),
            locations: self.locations[range.start as usize..range.end as usize].to_vec(),
        })
    }

    /// Apply an externally authenticated commitment and its complete mapping.
    /// `expected` MUST come from an independent trusted experimental source,
    /// never simply from hashing a proposer-supplied message at this call site.
    /// All historical leaves are re-proven and compared, preventing a new root
    /// from rewriting old locks without requiring an invented consistency proof.
    /// The complete `headers` path must extend the retained native cursor and
    /// reproduce `position`; a separately valid fork position is insufficient.
    pub fn apply(
        &mut self,
        expected: B256,
        position: HeightPosition,
        headers: &[Bytes],
        batch: &SourceBatch,
        proofs: &[InboxProof],
    ) -> Result<(), Error> {
        let commitment = batch.commitment()?;
        if expected == B256::ZERO || commitment != expected {
            return Err(Error::Authority);
        }
        if batch.network != self.network
            || batch.domain != self.domain
            || batch.genesis != self.genesis
            || position.genesis() != self.genesis
            || position.block() != batch.anchor.block
            || position.slot() != batch.anchor.slot
            || position.height() != batch.anchor.height
        {
            return Err(Error::Identity);
        }
        if commitment == self.commitment || batch.anchor.height <= self.anchor.height {
            return Err(Error::Replay);
        }
        if batch.previous != self.commitment
            || batch.anchor.slot <= self.anchor.slot
            || batch.anchor.block == B256::ZERO
            || batch.anchor.block == self.anchor.block
        {
            return Err(Error::Ancestry);
        }
        let mut cursor = self.cursor.clone();
        let identified = cursor
            .advance(
                FinalizedCheckpoint {
                    block: position.block(),
                    slot: position.slot(),
                },
                headers,
            )
            .map_err(|_| Error::Ancestry)?;
        if identified != position {
            return Err(Error::Ancestry);
        }
        if batch.count < self.count() {
            return Err(Error::Conflict);
        }
        if batch.count as usize != batch.locations.len() || proofs.len() != batch.locations.len() {
            return Err(Error::Incomplete);
        }
        if batch.inbox_root == B256::ZERO {
            return Err(Error::Inclusion);
        }
        if batch.count == 0 {
            if batch.inbox_root != self.inbox_root {
                return Err(Error::Inclusion);
            }
        } else {
            verify_proof_range(
                self.network,
                self.domain,
                batch.inbox_root,
                batch.count,
                0..batch.count,
                proofs,
            )
            .ok_or(Error::Inclusion)?;
        }
        if batch.count == self.count() && batch.inbox_root != self.inbox_root {
            return Err(Error::Conflict);
        }
        let mut positions = BTreeSet::new();
        let mut outpoints = BTreeSet::new();
        let mut intents = BTreeSet::new();
        let mut transaction_positions = BTreeMap::new();
        let mut position_transactions = BTreeMap::new();
        for (index, (location, proof)) in batch.locations.iter().zip(proofs).enumerate() {
            if location.sequence != index as u64
                || location.intent != proof.deposit.id
                || location.transaction == B256::ZERO
                || location.intent == B256::ZERO
                || proof.deposit.amount == 0
                || location.position == DepositPosition::NONE
            {
                return Err(Error::Mapping);
            }
            if index < self.locations.len() {
                if self.locations[index] != *location || self.deposits[index] != proof.deposit {
                    return Err(Error::Conflict);
                }
            } else if location.position.l1_height != batch.anchor.height {
                return Err(Error::Mapping);
            }
            if index > 0 && batch.locations[index - 1].position >= location.position {
                return Err(Error::Mapping);
            }
            let tx_position = (location.position.l1_height, location.position.l1_tx_index);
            if transaction_positions
                .insert(location.transaction, tx_position)
                .is_some_and(|old| old != tx_position)
                || position_transactions
                    .insert(tx_position, location.transaction)
                    .is_some_and(|old| old != location.transaction)
                || !positions.insert(location.position)
                || !outpoints.insert((location.transaction, location.position.l1_vout))
                || !intents.insert(location.intent)
            {
                return Err(Error::Conflict);
            }
        }
        // No fallible operations after publication. Allocation failures abort the
        // process rather than exposing a partially accepted logical registry.
        let deposits = proofs.iter().map(|proof| proof.deposit.clone()).collect();
        let locations = batch.locations.clone();
        self.cursor = cursor;
        self.anchor = batch.anchor;
        self.commitment = commitment;
        self.inbox_root = batch.inbox_root;
        self.locations = locations;
        self.deposits = deposits;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
