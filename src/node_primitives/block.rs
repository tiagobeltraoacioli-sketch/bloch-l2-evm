// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent V2 block framing; this codec does not execute or activate blocks.
use super::{NodeBodyV2, NodeHeaderError, NodeHeaderV2, MAX_NODE_BODY_BYTES};
use crate::ChainSpec;
use alloy_consensus::ReceiptEnvelope;
use alloy_primitives::B256;
use alloy_rlp::{BufMut, Decodable, Encodable, Error, Header};

/// Canonical block framing tag, distinct from header and body version tags.
pub const NODE_BLOCK_V2_TAG: &[u8] = b"BLOCH:EVM:BLOCK:2";
/// Maximum encoded body plus bounded header and outer/tag RLP framing.
pub const MAX_NODE_BLOCK_BYTES: usize = MAX_NODE_BODY_BYTES + 1024 + 64;

/// Explicit V2 header and body, separate from V1 and Ethereum block formats.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeBlockV2 {
    /// Versioned header committing the body and user receipts.
    pub header: NodeHeaderV2,
    /// Ordered deposits and canonical signed-envelope bytes.
    pub body: NodeBodyV2,
}
impl NodeBlockV2 {
    /// Block identity is its domain-separated header hash.
    pub fn hash(&self) -> B256 {
        self.header.hash()
    }
    /// Delegate body authentication and receipt consistency to the V2 header.
    /// This does not prove execution, L1 provenance or the supplied state root.
    pub fn validate_commitments(
        &self,
        spec: &ChainSpec,
        expected_domain: B256,
        receipts: &[ReceiptEnvelope],
    ) -> Result<(), NodeHeaderError> {
        self.header
            .validate_commitments(spec, expected_domain, &self.body, receipts)
    }
    fn payload_length(&self) -> usize {
        NODE_BLOCK_V2_TAG.length() + self.header.length() + self.body.length()
    }
}
impl Encodable for NodeBlockV2 {
    fn encode(&self, out: &mut dyn BufMut) {
        Header {
            list: true,
            payload_length: self.payload_length(),
        }
        .encode(out);
        NODE_BLOCK_V2_TAG.encode(out);
        self.header.encode(out);
        self.body.encode(out);
    }
    fn length(&self) -> usize {
        let payload = self.payload_length();
        Header {
            list: true,
            payload_length: payload,
        }
        .length()
            + payload
    }
}
impl Decodable for NodeBlockV2 {
    fn decode(input: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let original_len = input.len();
        let mut remaining = *input;
        let outer = Header::decode(&mut remaining)?;
        if !outer.list {
            return Err(Error::UnexpectedString);
        }
        let encoded_len = original_len - remaining.len() + outer.payload_length;
        if encoded_len > MAX_NODE_BLOCK_BYTES {
            return Err(Error::Custom("V2 block size limit exceeded"));
        }
        let (mut payload, tail) = remaining.split_at(outer.payload_length);
        if Header::decode_bytes(&mut payload, false)? != NODE_BLOCK_V2_TAG {
            return Err(Error::Custom("unsupported V2 block tag"));
        }
        let header = NodeHeaderV2::decode(&mut payload)?;
        let body = NodeBodyV2::decode(&mut payload)?;
        if !payload.is_empty() {
            return Err(Error::Custom("extra V2 block fields"));
        }
        *input = tail;
        Ok(Self { header, body })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::transactions::MAX_SIGNED_TRANSACTIONS;
    use alloc::{vec, vec::Vec};
    use alloy_primitives::Bytes;
    fn rejected_without_consumption(encoded: &[u8]) {
        let mut input = encoded;
        assert!(NodeBlockV2::decode(&mut input).is_err());
        assert_eq!(input, encoded);
    }
    #[test]
    fn empty_block_round_trips_and_stream_tail_is_preserved() {
        let block = NodeBlockV2::default();
        let mut encoded = alloy_rlp::encode(&block);
        assert_eq!(encoded.len(), block.length());
        assert_eq!(block.hash(), block.header.hash());
        encoded.extend_from_slice(&[0xde, 0xad]);
        let mut input = encoded.as_slice();
        assert_eq!(NodeBlockV2::decode(&mut input).unwrap(), block);
        assert_eq!(input, &[0xde, 0xad]);
    }
    #[test]
    fn malformed_tag_truncation_and_extra_fields_are_atomic_errors() {
        let block = NodeBlockV2::default();
        let encoded = alloy_rlp::encode(&block);
        for end in 0..encoded.len() {
            rejected_without_consumption(&encoded[..end]);
        }
        let mut wrong = encoded.clone();
        let position = wrong
            .windows(NODE_BLOCK_V2_TAG.len())
            .position(|bytes| bytes == NODE_BLOCK_V2_TAG)
            .unwrap();
        wrong[position + NODE_BLOCK_V2_TAG.len() - 1] = b'1';
        rejected_without_consumption(&wrong);
        let mut payload = Vec::new();
        NODE_BLOCK_V2_TAG.encode(&mut payload);
        block.header.encode(&mut payload);
        block.body.encode(&mut payload);
        payload.push(0x80);
        let mut extra = Vec::new();
        Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut extra);
        extra.extend(payload);
        rejected_without_consumption(&extra);
    }
    #[test]
    fn nested_body_limits_propagate_without_consuming_block_input() {
        let block = NodeBlockV2 {
            header: NodeHeaderV2::default(),
            body: NodeBodyV2 {
                deposits: Vec::new(),
                transactions: vec![Bytes::new(); MAX_SIGNED_TRANSACTIONS + 1],
            },
        };
        rejected_without_consumption(&alloy_rlp::encode(&block));
        let mut oversized = Vec::new();
        Header {
            list: true,
            payload_length: MAX_NODE_BLOCK_BYTES + 1,
        }
        .encode(&mut oversized);
        // Header decoding rejects the missing advertised payload without allocation.
        rejected_without_consumption(&oversized);
    }
}
