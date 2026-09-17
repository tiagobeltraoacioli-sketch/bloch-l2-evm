// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental post-genesis payload: no self-header hash, inclusion or authority.
use crate::{Error, Reader, SourceAnchor, SourceBatch, MAX_LOCKS, RECORD_BYTES};
use alloy_primitives::{keccak256, B256};
use bloch_l2_evm::{escrow_execution::TrustedLockLocation, l1::height::HeightPosition, DepositPosition};

const TAG: &[u8] = b"BLOCH:EXPERIMENTAL:SOURCE-PAYLOAD:1";
const FIXED_BYTES: usize = TAG.len() + 32 * 5 + 8 * 3 + 4;
pub const MAX_SOURCE_PAYLOAD_BYTES: usize = FIXED_BYTES + MAX_LOCKS * RECORD_BYTES;

/// Candidate state payload for a future native integration. No native component
/// tag is assigned. Network/genesis already exist; this cannot initialize them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePayload {
    pub network: B256,
    pub domain: B256,
    pub genesis: B256,
    pub previous: B256,
    pub slot: u64,
    pub height: u64,
    pub inbox_root: B256,
    pub count: u64,
    pub locations: Vec<TrustedLockLocation>,
}

impl SourcePayload {
    fn check(&self) -> Result<(), Error> {
        if self.network == B256::ZERO || self.domain == B256::ZERO || self.genesis == B256::ZERO || self.height == 0 {
            return Err(Error::Configuration);
        }
        if self.locations.len() > MAX_LOCKS || self.count > MAX_LOCKS as u64 {
            return Err(Error::Limit);
        }
        if self.count != self.locations.len() as u64 {
            return Err(Error::Incomplete);
        }
        if self
            .locations
            .iter()
            .enumerate()
            .any(|(index, location)| location.sequence != index as u64)
        {
            return Err(Error::Mapping);
        }
        Ok(())
    }

    /// Strip only the current anchor's block hash. This conversion conveys no
    /// proof that the payload was included in that block's native state.
    pub fn from_batch(batch: &SourceBatch) -> Result<Self, Error> {
        if batch.locations.len() > MAX_LOCKS || batch.count > MAX_LOCKS as u64 {
            return Err(Error::Limit);
        }
        let payload = Self {
            network: batch.network,
            domain: batch.domain,
            genesis: batch.genesis,
            previous: batch.previous,
            slot: batch.anchor.slot,
            height: batch.anchor.height,
            inbox_root: batch.inbox_root,
            count: batch.count,
            locations: batch.locations.clone(),
        };
        payload.check()?;
        Ok(payload)
    }

    /// Bind a separately derived header position after its hash is known. A
    /// position identifies ancestry; it does NOT authenticate state inclusion,
    /// this payload's authority, or checkpoint finality. Registry apply still
    /// requires its externally trusted SourceBatch commitment and full proofs.
    pub fn bind(&self, position: HeightPosition) -> Result<SourceBatch, Error> {
        self.check()?;
        if position.genesis() != self.genesis {
            return Err(Error::Identity);
        }
        if position.height() == 0 || position.height() != self.height || position.slot() != self.slot {
            return Err(Error::Mapping);
        }
        Ok(SourceBatch {
            network: self.network,
            domain: self.domain,
            genesis: self.genesis,
            previous: self.previous,
            anchor: SourceAnchor {
                block: position.block(),
                slot: self.slot,
                height: self.height,
            },
            inbox_root: self.inbox_root,
            count: self.count,
            locations: self.locations.clone(),
        })
    }

    /// Tagged fixed-width little-endian encoding; complete ordered mapping.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        let mut out = Vec::with_capacity(FIXED_BYTES + self.locations.len() * RECORD_BYTES);
        out.extend_from_slice(TAG);
        for hash in [self.network, self.domain, self.genesis, self.previous] {
            out.extend_from_slice(hash.as_slice());
        }
        out.extend_from_slice(&self.slot.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
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

    /// Exact bounded decoder. No serde path or claimed authenticated token.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SOURCE_PAYLOAD_BYTES {
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
        let slot = u64::from_le_bytes(reader.take()?);
        let height = u64::from_le_bytes(reader.take()?);
        let inbox_root = B256::from(reader.take::<32>()?);
        let count = u64::from_le_bytes(reader.take()?);
        let records = u32::from_le_bytes(reader.take()?) as usize;
        if count > MAX_LOCKS as u64 || records > MAX_LOCKS {
            return Err(Error::Limit);
        }
        if count != records as u64 {
            return Err(Error::Incomplete);
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
        let payload = Self {
            network,
            domain,
            genesis,
            previous,
            slot,
            height,
            inbox_root,
            count,
            locations,
        };
        payload.check()?;
        Ok(payload)
    }

    /// Distinct from the anchored SourceBatch commitment. Hashing authenticates
    /// neither native state inclusion nor mint permission.
    pub fn commitment(&self) -> Result<B256, Error> {
        Ok(keccak256(self.encode()?))
    }
}

#[cfg(test)]
mod tests;
