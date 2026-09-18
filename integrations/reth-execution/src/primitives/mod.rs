// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reth primitive adapters preserving the canonical Bloch V2 wire identity.
//! Serde uses bounded canonical RLP bytes for internal transport, not eth_* JSON.
mod serde_rlp;
use alloy_consensus::BlockHeader as AlloyHeader;
/// Node-storage transaction envelope without unsupported blob sidecars.
pub type BlochRethTransaction = alloy_consensus::EthereumTxEnvelope<alloy_consensus::TxEip4844>;
/// Reth storage receipt with the same typed receipt commitment as the core.
pub type BlochRethReceipt = alloy_consensus::EthereumReceipt;
use alloy_eips::{
    eip2718::{Decodable2718, Encodable2718},
    eip4895::Withdrawals,
};
use alloy_primitives::{Address, Bloom, Bytes, Sealable, B256, B64, U256};
use alloy_rlp::{BufMut, Decodable, Encodable, Error, Header};
use bloch_l2_evm::{
    node_primitives::{
        NodeBlockV2, NodeBodyV2, NodeHeaderV2, MAX_NODE_BLOCK_BYTES, MAX_NODE_BODY_BYTES, MAX_NODE_DEPOSITS,
        NODE_BLOCK_V2_TAG,
    },
    transactions::{MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS},
};
use reth_primitives_traits::{Block, BlockBody, BlockHeader, InMemorySize, NodePrimitives};
use std::hash::{Hash, Hasher};
use BlochRethTransaction as TxEnvelope;

/// Header projection for Reth; sealing always hashes the canonical tagged V2 RLP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlochNodeHeader(pub NodeHeaderV2);
impl Hash for BlochNodeHeader {
    fn hash<H: Hasher>(&self, state: &mut H) {
        alloy_rlp::encode(&self.0).hash(state);
    }
}
impl AsRef<Self> for BlochNodeHeader {
    fn as_ref(&self) -> &Self {
        self
    }
}
impl Encodable for BlochNodeHeader {
    fn encode(&self, out: &mut dyn BufMut) {
        self.0.encode(out);
    }
    fn length(&self) -> usize {
        self.0.length()
    }
}
impl Decodable for BlochNodeHeader {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        NodeHeaderV2::decode(buf).map(Self)
    }
}
impl Sealable for BlochNodeHeader {
    fn hash_slow(&self) -> B256 {
        self.0.hash()
    }
}
impl InMemorySize for BlochNodeHeader {
    fn size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}
impl BlockHeader for BlochNodeHeader {}
impl AlloyHeader for BlochNodeHeader {
    fn parent_hash(&self) -> B256 {
        self.0.parent_hash
    }
    fn ommers_hash(&self) -> B256 {
        alloy_consensus::EMPTY_OMMER_ROOT_HASH
    }
    fn beneficiary(&self) -> Address {
        self.0.beneficiary
    }
    fn state_root(&self) -> B256 {
        self.0.state_root
    }
    fn transactions_root(&self) -> B256 {
        self.0.transactions_root
    }
    fn receipts_root(&self) -> B256 {
        self.0.receipts_root
    }
    fn withdrawals_root(&self) -> Option<B256> {
        None
    }
    fn logs_bloom(&self) -> Bloom {
        self.0.logs_bloom
    }
    fn difficulty(&self) -> U256 {
        U256::ZERO
    }
    fn number(&self) -> u64 {
        self.0.number
    }
    fn gas_limit(&self) -> u64 {
        self.0.gas_limit
    }
    fn gas_used(&self) -> u64 {
        self.0.gas_used
    }
    fn timestamp(&self) -> u64 {
        self.0.timestamp
    }
    fn mix_hash(&self) -> Option<B256> {
        Some(self.0.prevrandao)
    }
    fn nonce(&self) -> Option<B64> {
        None
    }
    fn base_fee_per_gas(&self) -> Option<u64> {
        Some(self.0.base_fee_per_gas)
    }
    fn blob_gas_used(&self) -> Option<u64> {
        None
    }
    fn excess_blob_gas(&self) -> Option<u64> {
        None
    }
    fn parent_beacon_block_root(&self) -> Option<B256> {
        Some(self.0.anchor_root)
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
        self.0.transactions_root == alloy_consensus::EMPTY_ROOT_HASH
            && self.0.deposits_hash == bloch_l2_evm::deposits_hash(&[])
    }
}
impl reth_codecs::Compact for BlochNodeHeader {
    fn to_compact<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) -> usize {
        self.encode(buf);
        self.length()
    }
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let encoded = buf.get(..len).expect("corrupt Bloch V2 header storage length");
        let header = serde_rlp::decode_exact(encoded).expect("corrupt Bloch V2 header storage encoding");
        (header, &buf[len..])
    }
}

impl reth_codecs::Compress for BlochNodeHeader {
    type Compressed = Vec<u8>;
    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        self.encode(buf);
    }
}
impl reth_codecs::Decompress for BlochNodeHeader {
    fn decompress(bytes: &[u8]) -> Result<Self, reth_codecs::DecompressError> {
        serde_rlp::decode_exact(bytes).map_err(reth_codecs::DecompressError::new)
    }
}

/// Immutable dual view: exact V2 signed bytes plus parsed Reth transactions.
/// Construction checks bounds and canonical envelope syntax; execution still
/// authenticates signatures, chain IDs and the supported transaction types.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlochNodeBody {
    core: NodeBodyV2,
    transactions: Vec<TxEnvelope>,
}
impl BlochNodeBody {
    /// Validate limits before parsing and retain the original canonical bytes.
    pub fn try_from_core(core: NodeBodyV2) -> alloy_rlp::Result<Self> {
        if core.deposits.len() > MAX_NODE_DEPOSITS || core.transactions.len() > MAX_SIGNED_TRANSACTIONS {
            return Err(Error::Custom("Bloch V2 body count limit exceeded"));
        }
        let mut total = 0usize;
        for raw in &core.transactions {
            if raw.len() > MAX_RAW_TRANSACTION_BYTES {
                return Err(Error::Custom("Bloch V2 transaction too large"));
            }
            total = total
                .checked_add(raw.len())
                .filter(|n| *n <= MAX_SIGNED_BLOCK_BYTES)
                .ok_or(Error::Custom("Bloch V2 transaction byte budget exceeded"))?;
        }
        let transactions = core
            .transactions
            .iter()
            .map(|raw| {
                let mut bytes = raw.as_ref();
                let tx =
                    TxEnvelope::decode_2718(&mut bytes).map_err(|_| Error::Custom("invalid Bloch signed envelope"))?;
                if !bytes.is_empty() || tx.encoded_2718().as_slice() != raw.as_ref() {
                    return Err(Error::Custom("noncanonical Bloch signed envelope"));
                }
                Ok(tx)
            })
            .collect::<alloy_rlp::Result<Vec<_>>>()?;
        Ok(Self { core, transactions })
    }
    /// Canonical deposits and original signed bytes; immutable to preserve parity.
    pub fn as_core(&self) -> &NodeBodyV2 {
        &self.core
    }
    /// Consume the adapter without losing deposit data.
    pub fn into_core(self) -> NodeBodyV2 {
        self.core
    }
}
impl Encodable for BlochNodeBody {
    fn encode(&self, out: &mut dyn BufMut) {
        self.core.encode(out);
    }
    fn length(&self) -> usize {
        self.core.length()
    }
}
impl Decodable for BlochNodeBody {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut remaining = *buf;
        let body = Self::try_from_core(NodeBodyV2::decode(&mut remaining)?)?;
        *buf = remaining;
        Ok(body)
    }
}
impl InMemorySize for BlochNodeBody {
    fn size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.core.deposits.capacity() * std::mem::size_of::<bloch_l2_evm::DepositMint>()
            + self.core.transactions.capacity() * std::mem::size_of::<Bytes>()
            + self.core.transactions.iter().map(|tx| tx.len()).sum::<usize>()
            + self.transactions.iter().map(InMemorySize::size).sum::<usize>()
    }
}
impl BlockBody for BlochNodeBody {
    type Transaction = TxEnvelope;
    type OmmerHeader = BlochNodeHeader;
    fn transactions(&self) -> &[TxEnvelope] {
        &self.transactions
    }
    /// Ethereum RPC projection omits deposits; never use it for storage or hashing.
    fn into_ethereum_body(self) -> alloy_consensus::BlockBody<TxEnvelope, BlochNodeHeader> {
        alloy_consensus::BlockBody {
            transactions: self.transactions,
            ommers: vec![],
            withdrawals: None,
        }
    }
    fn into_transactions(self) -> Vec<TxEnvelope> {
        self.transactions
    }
    fn withdrawals(&self) -> Option<&Withdrawals> {
        None
    }
    fn ommers(&self) -> Option<&[BlochNodeHeader]> {
        None
    }
    fn calculate_tx_root(&self) -> B256 {
        self.core.transactions_root()
    }
}

/// Full Reth block preserving Bloch V2 body framing and custom header identity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlochNodeBlock {
    /// Canonical header projection.
    pub header: BlochNodeHeader,
    /// Original deposits and signed envelopes.
    pub body: BlochNodeBody,
}
impl BlochNodeBlock {
    /// Consume into the portable V2 format without projecting away deposits.
    pub fn into_core(self) -> NodeBlockV2 {
        NodeBlockV2 {
            header: self.header.0,
            body: self.body.into_core(),
        }
    }
    fn payload_length(&self) -> usize {
        NODE_BLOCK_V2_TAG.length() + self.header.length() + self.body.length()
    }
}
impl Encodable for BlochNodeBlock {
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
        let payload_length = self.payload_length();
        Header {
            list: true,
            payload_length,
        }
        .length()
            + payload_length
    }
}
impl Decodable for BlochNodeBlock {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut remaining = *buf;
        let core = NodeBlockV2::decode(&mut remaining)?;
        let block = Self {
            header: BlochNodeHeader(core.header),
            body: BlochNodeBody::try_from_core(core.body)?,
        };
        *buf = remaining;
        Ok(block)
    }
}
impl InMemorySize for BlochNodeBlock {
    fn size(&self) -> usize {
        self.header.size() + self.body.size()
    }
}
impl Block for BlochNodeBlock {
    type Header = BlochNodeHeader;
    type Body = BlochNodeBody;
    fn new(header: Self::Header, body: Self::Body) -> Self {
        Self { header, body }
    }
    fn header(&self) -> &Self::Header {
        &self.header
    }
    fn body(&self) -> &Self::Body {
        &self.body
    }
    fn split(self) -> (Self::Header, Self::Body) {
        (self.header, self.body)
    }
    fn rlp_length(header: &Self::Header, body: &Self::Body) -> usize {
        let payload_length = NODE_BLOCK_V2_TAG.length() + header.length() + body.length();
        Header {
            list: true,
            payload_length,
        }
        .length()
            + payload_length
    }
}

/// Pinned custom primitives for Bloch V2 node integration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlochNodePrimitives;
impl NodePrimitives for BlochNodePrimitives {
    type Block = BlochNodeBlock;
    type BlockHeader = BlochNodeHeader;
    type BlockBody = BlochNodeBody;
    type SignedTx = TxEnvelope;
    type Receipt = BlochRethReceipt;
}

serde_rlp::impl_serde_rlp!(BlochNodeHeader, 1033);
serde_rlp::impl_serde_rlp!(BlochNodeBody, MAX_NODE_BODY_BYTES);
serde_rlp::impl_serde_rlp!(BlochNodeBlock, MAX_NODE_BLOCK_BYTES);
