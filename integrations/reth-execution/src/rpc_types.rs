// SPDX-License-Identifier: MIT OR Apache-2.0
//! JSON-RPC V2 header views preserving canonical Bloch identity.
//! RPC quantities are hex; this representation is not the consensus RLP codec.
use crate::BlochNodeHeader;
use alloy_consensus::BlockHeader;
use alloy_network_primitives::HeaderResponse;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use bloch_l2_evm::node_primitives::NodeHeaderV2;
use reth_primitives_traits::SealedHeader;
use reth_rpc_convert::{transaction::HeaderConverter, RpcTypes};
use reth_rpc_eth_types::EthApiError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// RPC network types. User transactions and receipts keep their Ethereum envelopes;
/// headers expose the actual separately versioned Bloch fields and hash.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlochRpcTypes;
impl RpcTypes for BlochRpcTypes {
    type Header = BlochRpcHeader;
    type Receipt = alloy_rpc_types_eth::TransactionReceipt;
    type TransactionResponse = alloy_rpc_types_eth::Transaction;
    type TransactionRequest = alloy_rpc_types_eth::TransactionRequest;
}

/// Immutable RPC view; deserialization rejects a hash inconsistent with its fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlochRpcHeader {
    header: BlochNodeHeader,
    size: U256,
}
impl BlochRpcHeader {
    /// The size is the complete canonical block encoding length, supplied by Reth.
    pub fn new(header: BlochNodeHeader, block_size: usize) -> Self {
        Self {
            header,
            size: U256::from(block_size),
        }
    }
    /// Full consensus fields; no Ethereum-header projection is used for hashing.
    pub const fn as_consensus(&self) -> &BlochNodeHeader {
        &self.header
    }
    /// Reported canonical block encoding length, independent of header identity.
    pub const fn size(&self) -> U256 {
        self.size
    }
}
impl HeaderResponse for BlochRpcHeader {
    fn hash(&self) -> B256 {
        self.header.0.hash()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeaderJson {
    hash: B256,
    size: U256,
    // Neutral RPC projections already defined by BlockHeader for this domain.
    // Neither is an additional field in the tagged V2 consensus encoding.
    #[serde(default)]
    difficulty: U256,
    #[serde(default)]
    extra_data: Bytes,
    domain: B256,
    #[serde(with = "alloy_serde::quantity")]
    chain_id: u64,
    #[serde(with = "alloy_serde::quantity")]
    number: u64,
    #[serde(with = "alloy_serde::quantity")]
    timestamp: u64,
    #[serde(with = "alloy_serde::quantity")]
    base_fee_per_gas: u64,
    #[serde(with = "alloy_serde::quantity")]
    gas_limit: u64,
    #[serde(with = "alloy_serde::quantity")]
    gas_used: u64,
    #[serde(with = "alloy_serde::quantity")]
    user_gas_used: u64,
    #[serde(rename = "miner", alias = "beneficiary")]
    beneficiary: Address,
    #[serde(rename = "mixHash", alias = "prevrandao")]
    prevrandao: B256,
    anchor_root: B256,
    parent_hash: B256,
    parent_state_root: B256,
    transactions_root: B256,
    receipts_root: B256,
    deposits_hash: B256,
    logs_bloom: Bloom,
    state_root: B256,
}
impl Serialize for BlochRpcHeader {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        HeaderJson {
            hash: self.hash(),
            size: self.size,
            difficulty: self.difficulty(),
            extra_data: self.extra_data().clone(),
            domain: self.header.0.domain,
            chain_id: self.header.0.chain_id,
            number: self.header.0.number,
            timestamp: self.header.0.timestamp,
            base_fee_per_gas: self.header.0.base_fee_per_gas,
            gas_limit: self.header.0.gas_limit,
            gas_used: self.header.0.gas_used,
            user_gas_used: self.header.0.user_gas_used,
            beneficiary: self.header.0.beneficiary,
            prevrandao: self.header.0.prevrandao,
            anchor_root: self.header.0.anchor_root,
            parent_hash: self.header.0.parent_hash,
            parent_state_root: self.header.0.parent_state_root,
            transactions_root: self.header.0.transactions_root,
            receipts_root: self.header.0.receipts_root,
            deposits_hash: self.header.0.deposits_hash,
            logs_bloom: self.header.0.logs_bloom,
            state_root: self.header.0.state_root,
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for BlochRpcHeader {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let json = HeaderJson::deserialize(deserializer)?;
        if json.difficulty != U256::ZERO || !json.extra_data.is_empty() {
            return Err(serde::de::Error::custom(
                "Bloch V2 RPC requires zero difficulty and empty extraData",
            ));
        }
        let header = BlochNodeHeader(NodeHeaderV2 {
            domain: json.domain,
            chain_id: json.chain_id,
            number: json.number,
            timestamp: json.timestamp,
            base_fee_per_gas: json.base_fee_per_gas,
            gas_limit: json.gas_limit,
            gas_used: json.gas_used,
            user_gas_used: json.user_gas_used,
            beneficiary: json.beneficiary,
            prevrandao: json.prevrandao,
            anchor_root: json.anchor_root,
            parent_hash: json.parent_hash,
            parent_state_root: json.parent_state_root,
            transactions_root: json.transactions_root,
            receipts_root: json.receipts_root,
            deposits_hash: json.deposits_hash,
            logs_bloom: json.logs_bloom,
            state_root: json.state_root,
        });
        if header.0.hash() != json.hash {
            return Err(serde::de::Error::custom(
                "Bloch V2 header hash does not match canonical fields",
            ));
        }
        Ok(Self {
            header,
            size: json.size,
        })
    }
}

/// Checked conversion from an upstream sealed header to the real V2 RPC view.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlochHeaderConverter;
impl HeaderConverter<BlochNodeHeader, BlochRpcHeader> for BlochHeaderConverter {
    type Err = EthApiError;
    fn convert_header(
        &self,
        header: SealedHeader<BlochNodeHeader>,
        block_size: usize,
    ) -> Result<BlochRpcHeader, Self::Err> {
        if header.hash() != header.header().0.hash() {
            return Err(EthApiError::InvalidParams("inconsistent Bloch V2 header seal".into()));
        }
        Ok(BlochRpcHeader::new(header.header().clone(), block_size))
    }
}
impl BlockHeader for BlochRpcHeader {
    fn parent_hash(&self) -> B256 {
        self.header.0.parent_hash
    }
    fn ommers_hash(&self) -> B256 {
        alloy_consensus::EMPTY_OMMER_ROOT_HASH
    }
    fn beneficiary(&self) -> Address {
        self.header.0.beneficiary
    }
    fn state_root(&self) -> B256 {
        self.header.0.state_root
    }
    fn transactions_root(&self) -> B256 {
        self.header.0.transactions_root
    }
    fn receipts_root(&self) -> B256 {
        self.header.0.receipts_root
    }
    fn withdrawals_root(&self) -> Option<B256> {
        None
    }
    fn logs_bloom(&self) -> Bloom {
        self.header.0.logs_bloom
    }
    fn difficulty(&self) -> U256 {
        U256::ZERO
    }
    fn number(&self) -> u64 {
        self.header.0.number
    }
    fn gas_limit(&self) -> u64 {
        self.header.0.gas_limit
    }
    fn gas_used(&self) -> u64 {
        self.header.0.gas_used
    }
    fn timestamp(&self) -> u64 {
        self.header.0.timestamp
    }
    fn mix_hash(&self) -> Option<B256> {
        Some(self.header.0.prevrandao)
    }
    fn nonce(&self) -> Option<B64> {
        None
    }
    fn base_fee_per_gas(&self) -> Option<u64> {
        Some(self.header.0.base_fee_per_gas)
    }
    fn blob_gas_used(&self) -> Option<u64> {
        None
    }
    fn excess_blob_gas(&self) -> Option<u64> {
        None
    }
    fn parent_beacon_block_root(&self) -> Option<B256> {
        Some(self.header.0.anchor_root)
    }
    fn requests_hash(&self) -> Option<B256> {
        None
    }
    fn block_access_list_hash(&self) -> Option<B256> {
        None
    }
    fn slot_number(&self) -> Option<u64> {
        None
    }
    fn extra_data(&self) -> &Bytes {
        static EMPTY: Bytes = Bytes::new();
        &EMPTY
    }
    // A deposit-only Bloch block is not empty even though Ethereum sees no txs.
    fn is_empty(&self) -> bool {
        self.header.0.transactions_root == alloy_consensus::EMPTY_ROOT_HASH
            && self.header.0.deposits_hash == bloch_l2_evm::deposits_hash(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> BlochNodeHeader {
        BlochNodeHeader(NodeHeaderV2 {
            domain: B256::repeat_byte(1),
            chain_id: 42,
            number: 2,
            timestamp: 123,
            base_fee_per_gas: 17,
            gas_limit: 30_000_000,
            gas_used: 42_100,
            user_gas_used: 21_100,
            beneficiary: Address::repeat_byte(2),
            prevrandao: B256::repeat_byte(3),
            anchor_root: B256::repeat_byte(4),
            parent_hash: B256::repeat_byte(5),
            parent_state_root: B256::repeat_byte(6),
            transactions_root: B256::repeat_byte(7),
            receipts_root: B256::repeat_byte(8),
            deposits_hash: B256::repeat_byte(9),
            logs_bloom: Bloom::repeat_byte(10),
            state_root: B256::repeat_byte(11),
        })
    }
    #[test]
    fn rpc_json_preserves_every_v2_field_and_canonical_hash() {
        let header = fixture();
        let rpc = BlochHeaderConverter
            .convert_header(SealedHeader::seal_slow(header.clone()), 999)
            .unwrap();
        let json = serde_json::to_value(&rpc).unwrap();
        assert!(json.is_object());
        assert_eq!(json["hash"], serde_json::to_value(header.0.hash()).unwrap());
        assert_eq!(json["chainId"], "0x2a");
        assert_eq!(json["number"], "0x2");
        assert_eq!(json["size"], "0x3e7");
        assert_eq!(json["difficulty"], "0x0");
        assert_eq!(json["extraData"], "0x");
        assert_eq!(json["gasUsed"], "0xa474");
        assert_eq!(json["userGasUsed"], "0x526c");
        assert_eq!(
            json["parentStateRoot"],
            serde_json::to_value(header.0.parent_state_root).unwrap()
        );
        assert_eq!(
            json["depositsHash"],
            serde_json::to_value(header.0.deposits_hash).unwrap()
        );
        assert_eq!(json["domain"], serde_json::to_value(header.0.domain).unwrap());
        assert_eq!(json["miner"], serde_json::to_value(header.0.beneficiary).unwrap());
        assert_eq!(json["mixHash"], serde_json::to_value(header.0.prevrandao).unwrap());
        assert!(json.get("beneficiary").is_none());
        assert!(json.get("prevrandao").is_none());
        assert!(json.get("sha3Uncles").is_none());
        let decoded: BlochRpcHeader = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.as_consensus(), &header);
        assert_eq!(decoded.hash(), header.0.hash());
        assert_eq!(decoded, rpc);
        assert_eq!(decoded.gas_used(), 42_100);
        assert_eq!(decoded.parent_beacon_block_root(), Some(header.0.anchor_root));
    }
    #[test]
    fn forged_cached_seals_or_changed_json_fields_are_rejected() {
        let header = fixture();
        assert!(BlochHeaderConverter
            .convert_header(SealedHeader::new(header.clone(), B256::ZERO), 1)
            .is_err());
        let rpc = BlochRpcHeader::new(header, 1);
        for (field, value) in [("difficulty", "0x1"), ("extraData", "0x01")] {
            let mut json = serde_json::to_value(&rpc).unwrap();
            json[field] = serde_json::json!(value);
            assert!(serde_json::from_value::<BlochRpcHeader>(json).is_err(), "{field}");
        }
        // Decode older V2 responses which omitted the neutral projections.
        let mut old = serde_json::to_value(&rpc).unwrap();
        old.as_object_mut().unwrap().remove("difficulty");
        old.as_object_mut().unwrap().remove("extraData");
        assert_eq!(serde_json::from_value::<BlochRpcHeader>(old).unwrap(), rpc);
        for field in ["hash", "domain", "depositsHash", "parentStateRoot", "receiptsRoot"] {
            let mut json = serde_json::to_value(&rpc).unwrap();
            json[field] = serde_json::to_value(B256::repeat_byte(99)).unwrap();
            assert!(serde_json::from_value::<BlochRpcHeader>(json).is_err(), "{field}");
        }
        for (canonical, alias) in [("miner", "beneficiary"), ("mixHash", "prevrandao")] {
            let mut json = serde_json::to_value(&rpc).unwrap();
            json[alias] = json[canonical].clone();
            assert!(
                serde_json::from_value::<BlochRpcHeader>(json).is_err(),
                "duplicate alias {alias}"
            );
            let mut json = serde_json::to_value(&rpc).unwrap();
            json[alias] = json.as_object_mut().unwrap().remove(canonical).unwrap();
            assert_eq!(serde_json::from_value::<BlochRpcHeader>(json).unwrap(), rpc);
        }
        let mut json = serde_json::to_value(&rpc).unwrap();
        json["number"] = serde_json::json!("0x10000000000000000");
        assert!(serde_json::from_value::<BlochRpcHeader>(json).is_err());
    }
    #[test]
    fn flattened_rpc_block_keeps_header_identity() {
        let rpc = BlochRpcHeader::new(fixture(), 55);
        let block: alloy_rpc_types_eth::Block<alloy_rpc_types_eth::Transaction, BlochRpcHeader> =
            alloy_rpc_types_eth::Block {
                header: rpc.clone(),
                ..Default::default()
            };
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["hash"], serde_json::to_value(rpc.hash()).unwrap());
        let decoded: alloy_rpc_types_eth::Block<alloy_rpc_types_eth::Transaction, BlochRpcHeader> =
            serde_json::from_value(json).unwrap();
        assert_eq!(decoded.header, rpc);
    }
}
