// SPDX-License-Identifier: MIT OR Apache-2.0
//! Custom V2 payload containers for Reth type integration, not an Engine API.
use crate::{BlochNodeBlock, BlochNodeBody, BlochNodePrimitives};
use alloy_eips::{eip4895::Withdrawal, eip7685::Requests};
use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_rpc_types_engine::PayloadId;
use bloch_l2_evm::{node_primitives::NodeBodyV2, DepositMint};
use reth_payload_primitives::{BuiltPayload, ExecutionPayload, PayloadAttributes, PayloadTypes};
use reth_primitives_traits::{BlockBody, SealedBlock};
use serde::{Deserialize, Serialize};

/// A transport container preserving the actual tagged block and optional sidecar.
/// Presence of a block access list does not imply execution support: V2 assembly
/// rejects it. Deserialization bounds its allocation before accepting input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlochExecutionPayload {
    /// The canonical V2 block, including deposits.
    pub block: BlochNodeBlock,
    /// Opaque transport data; unsupported by the current V2 execution policy.
    #[serde(with = "bounded_bal")]
    pub block_access_list: Option<Bytes>,
}
impl ExecutionPayload for BlochExecutionPayload {
    fn parent_hash(&self) -> B256 {
        self.block.header.0.parent_hash
    }
    fn block_hash(&self) -> B256 {
        self.block.header.0.hash()
    }
    fn block_number(&self) -> u64 {
        self.block.header.0.number
    }
    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        None
    }
    fn block_access_list(&self) -> Option<&Bytes> {
        self.block_access_list.as_ref()
    }
    fn parent_beacon_block_root(&self) -> Option<B256> {
        Some(self.block.header.0.anchor_root)
    }
    fn timestamp(&self) -> u64 {
        self.block.header.0.timestamp
    }
    fn gas_used(&self) -> u64 {
        self.block.header.0.gas_used
    }
    fn gas_limit(&self) -> u64 {
        self.block.header.0.gas_limit
    }
    fn transaction_count(&self) -> usize {
        self.block.body.transactions().len()
    }
    fn slot_number(&self) -> Option<u64> {
        None
    }
}
/// A caller-supplied assembled block plus fees from trusted execution accounting.
/// Construction seals the header but does not verify execution or the claimed fees.
#[derive(Clone, Debug)]
pub struct BlochBuiltPayload {
    block: SealedBlock<BlochNodeBlock>,
    fees: U256,
}
impl BlochBuiltPayload {
    /// Seal the custom header using its canonical V2 hash; no Ethereum conversion.
    pub fn new(block: BlochNodeBlock, fees: U256) -> Self {
        Self {
            block: SealedBlock::seal_slow(block),
            fees,
        }
    }
}
impl BuiltPayload for BlochBuiltPayload {
    type Primitives = BlochNodePrimitives;
    fn block(&self) -> &SealedBlock<BlochNodeBlock> {
        &self.block
    }
    fn fees(&self) -> U256 {
        self.fees
    }
    fn requests(&self) -> Option<Requests> {
        None
    }
}
impl From<BlochBuiltPayload> for BlochExecutionPayload {
    fn from(value: BlochBuiltPayload) -> Self {
        Self {
            block: value.block.into_block(),
            block_access_list: None,
        }
    }
}
/// Custom build inputs; deposits use the same bounded tagged body codec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BlochPayloadAttributes {
    domain: B256,
    timestamp: u64,
    prevrandao: B256,
    anchor_root: B256,
    deposits: BlochNodeBody,
}
impl BlochPayloadAttributes {
    /// Construct bounded deposits-only attributes for a nonzero trusted domain.
    pub fn try_new(
        domain: B256,
        timestamp: u64,
        prevrandao: B256,
        anchor_root: B256,
        deposits: Vec<DepositMint>,
    ) -> Result<Self, alloy_rlp::Error> {
        if domain.is_zero() {
            return Err(alloy_rlp::Error::Custom("zero V2 payload domain"));
        }
        Ok(Self {
            domain,
            timestamp,
            prevrandao,
            anchor_root,
            deposits: BlochNodeBody::try_from_core(NodeBodyV2 {
                deposits,
                transactions: vec![],
            })?,
        })
    }
    /// Domain identifier committed into the build-job identity.
    pub fn domain(&self) -> B256 {
        self.domain
    }
    /// Randomness committed into the build-job identity.
    pub fn prevrandao(&self) -> B256 {
        self.prevrandao
    }
    /// Anchor commitment consumed by the shared beacon system call.
    pub fn anchor_root(&self) -> B256 {
        self.anchor_root
    }
    /// Host-authenticated deposit sequence in its original order.
    pub fn deposits(&self) -> &[DepositMint] {
        &self.deposits.as_core().deposits
    }
}
impl<'de> Deserialize<'de> for BlochPayloadAttributes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            domain: B256,
            timestamp: u64,
            prevrandao: B256,
            anchor_root: B256,
            deposits: BlochNodeBody,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.domain.is_zero() || !wire.deposits.as_core().transactions.is_empty() {
            return Err(serde::de::Error::custom(
                "V2 attributes require nonzero domain and deposits-only body",
            ));
        }
        Ok(Self {
            domain: wire.domain,
            timestamp: wire.timestamp,
            prevrandao: wire.prevrandao,
            anchor_root: wire.anchor_root,
            deposits: wire.deposits,
        })
    }
}
impl PayloadAttributes for BlochPayloadAttributes {
    fn payload_id(&self, parent_hash: &B256) -> PayloadId {
        let mut bytes = Vec::from(&b"BLOCH:EVM:PAYLOAD:2"[..]);
        bytes.extend_from_slice(self.domain.as_slice());
        bytes.extend_from_slice(parent_hash.as_slice());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(self.prevrandao.as_slice());
        bytes.extend_from_slice(self.anchor_root.as_slice());
        bytes.extend_from_slice(&alloy_rlp::encode(&self.deposits));
        let hash = keccak256(bytes);
        PayloadId::new(hash.as_slice()[..8].try_into().expect("eight-byte payload ID"))
    }
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        None
    }
    fn parent_beacon_block_root(&self) -> Option<B256> {
        Some(self.anchor_root)
    }
    fn slot_number(&self) -> Option<u64> {
        None
    }
}
/// Reth associated types retaining Bloch block identity and deposits.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlochPayloadTypes;
impl PayloadTypes for BlochPayloadTypes {
    type ExecutionData = BlochExecutionPayload;
    type BuiltPayload = BlochBuiltPayload;
    type PayloadAttributes = BlochPayloadAttributes;
    fn block_to_payload(block: SealedBlock<BlochNodeBlock>, bal: Option<Bytes>) -> BlochExecutionPayload {
        BlochExecutionPayload {
            block: block.into_block(),
            block_access_list: bal,
        }
    }
}
mod bounded_bal {
    use super::*;
    use serde::de::{SeqAccess, Visitor};
    const LIMIT: usize = bloch_l2_evm::transactions::MAX_SIGNED_BLOCK_BYTES;
    pub fn serialize<S: serde::Serializer>(value: &Option<Bytes>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            None => serializer.serialize_none(),
            Some(bytes) => {
                if bytes.len() > LIMIT {
                    return Err(serde::ser::Error::custom("V2 sidecar too large"));
                }
                serializer.serialize_some(bytes.as_ref())
            }
        }
    }
    #[cfg(test)]
    pub(super) fn decode_test<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
        Bounded::deserialize(deserializer).map(|_| ())
    }
    struct Bounded(Bytes);
    impl<'de> Deserialize<'de> for Bounded {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct BytesVisitor;
            impl<'de> Visitor<'de> for BytesVisitor {
                type Value = Bounded;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("bounded V2 sidecar byte sequence")
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Bounded, A::Error> {
                    if seq.size_hint().is_some_and(|size| size > LIMIT) {
                        return Err(serde::de::Error::custom("V2 sidecar too large"));
                    }
                    let mut bytes = Vec::new();
                    while let Some(byte) = seq.next_element::<u8>()? {
                        if bytes.len() == LIMIT {
                            return Err(serde::de::Error::custom("V2 sidecar too large"));
                        }
                        bytes.push(byte);
                    }
                    Ok(Bounded(bytes.into()))
                }
                fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Bounded, E> {
                    if bytes.len() > LIMIT {
                        return Err(E::custom("V2 sidecar too large"));
                    }
                    Ok(Bounded(Bytes::copy_from_slice(bytes)))
                }
            }
            d.deserialize_bytes(BytesVisitor)
        }
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Bytes>, D::Error> {
        Ok(Option::<Bounded>::deserialize(d)?.map(|v| v.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sidecar_declared_size_rejects_before_reading_sequence() {
        struct Oversized;
        impl Iterator for Oversized {
            type Item = u8;
            fn next(&mut self) -> Option<u8> {
                panic!("oversized sequence must not be read")
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                let size = bloch_l2_evm::transactions::MAX_SIGNED_BLOCK_BYTES + 1;
                (size, Some(size))
            }
        }
        let deserializer = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(Oversized);
        assert!(bounded_bal::decode_test(deserializer).is_err());
    }
}
