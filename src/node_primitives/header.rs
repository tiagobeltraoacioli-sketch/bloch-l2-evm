// SPDX-License-Identifier: MIT OR Apache-2.0
//! Domain-separated V2 header encoding and body/receipt consistency checks.
use super::{NodeBodyError, NodeBodyV2};
use crate::ChainSpec;
use alloy_consensus::{proofs::calculate_receipt_root, Eip658Value, ReceiptEnvelope, TxReceipt};
use alloy_primitives::{keccak256, Address, Bloom, B256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header};

/// First RLP item, distinguishing this format from V1 and Ethereum headers.
pub const NODE_HEADER_V2_TAG: &[u8] = b"BLOCH:EVM:HEADER:2";

/// Experimental node header. Declaration order after the tag is wire order.
/// Hashing commits the canonical RLP list, not an Ethereum header projection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeHeaderV2 {
    /// Explicit identity of the separately configured V2 execution domain.
    pub domain: B256,
    /// Signed transaction replay domain.
    pub chain_id: u64,
    /// Sequential block height.
    pub number: u64,
    /// Block timestamp.
    pub timestamp: u64,
    /// EIP-1559 base fee under the Bloch parameters.
    pub base_fee_per_gas: u64,
    /// Full block gas budget, including deposits.
    pub gas_limit: u64,
    /// Gas consumed by deposits and user transactions.
    pub gas_used: u64,
    /// Gas consumed by user transactions; the final user receipt's cumulative gas.
    pub user_gas_used: u64,
    /// Configured sequencer fee vault / EVM COINBASE.
    pub beneficiary: Address,
    /// EVM PREVRANDAO from authenticated block context.
    pub prevrandao: B256,
    /// Bloch anchor passed to EIP-4788.
    pub anchor_root: B256,
    /// Parent's V2 header hash.
    pub parent_hash: B256,
    /// Parent state root, available without a provider when constructing the EVM.
    pub parent_state_root: B256,
    /// Ordered Ethereum MPT root over canonical signed transaction envelopes.
    pub transactions_root: B256,
    /// Ordered Ethereum MPT root over typed user receipt envelopes.
    pub receipts_root: B256,
    /// Existing Bloch commitment to the ordered deposit list.
    pub deposits_hash: B256,
    /// Bloom computed from actual user receipt logs.
    pub logs_bloom: Bloom,
    /// Full post-state root, calculated after committing V2 head metadata.
    pub state_root: B256,
}

/// A failed structural or commitment check. Success is not execution validity.
#[derive(Debug)]
pub enum NodeHeaderError {
    /// Invalid specification or mismatch with the expected domain/configuration.
    Configuration,
    /// A signed body or deposit bound is invalid.
    Body(NodeBodyError),
    /// Body transaction or deposit commitment mismatch.
    BodyCommitment,
    /// Receipt count, type, status, bloom or cumulative gas is inconsistent.
    Receipts,
    /// Receipt trie or aggregate bloom does not match the header.
    ReceiptCommitment,
    /// User/deposit/total gas does not reconcile with the body and specification.
    GasAccounting,
    /// Parent identity, root, number, timestamp or base fee does not match.
    Parent,
}
impl core::fmt::Display for NodeHeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Configuration => f.write_str("V2 header domain/configuration mismatch"),
            Self::Body(error) => write!(f, "V2 body: {error}"),
            Self::BodyCommitment => f.write_str("V2 body commitment mismatch"),
            Self::Receipts => f.write_str("V2 user receipts are inconsistent"),
            Self::ReceiptCommitment => f.write_str("V2 receipt commitment mismatch"),
            Self::GasAccounting => f.write_str("V2 user/deposit gas does not reconcile"),
            Self::Parent => f.write_str("V2 parent linkage or context mismatch"),
        }
    }
}
impl core::error::Error for NodeHeaderError {}

impl NodeHeaderV2 {
    fn fields(&self) -> [&dyn Encodable; 19] {
        [
            &NODE_HEADER_V2_TAG,
            &self.domain,
            &self.chain_id,
            &self.number,
            &self.timestamp,
            &self.base_fee_per_gas,
            &self.gas_limit,
            &self.gas_used,
            &self.user_gas_used,
            &self.beneficiary,
            &self.prevrandao,
            &self.anchor_root,
            &self.parent_hash,
            &self.parent_state_root,
            &self.transactions_root,
            &self.receipts_root,
            &self.deposits_hash,
            &self.logs_bloom,
            &self.state_root,
        ]
    }
    fn rlp_header(&self) -> Header {
        Header {
            list: true,
            payload_length: self.fields().iter().map(|field| field.length()).sum(),
        }
    }
    /// Hash the unique tagged RLP encoding of every field.
    pub fn hash(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }

    /// Validate domain, configuration and basic gas bounds against trusted inputs.
    pub fn validate_configuration(&self, spec: &ChainSpec, expected_domain: B256) -> Result<(), NodeHeaderError> {
        if spec.validate().is_err()
            || expected_domain.is_zero()
            || self.domain != expected_domain
            || self.chain_id != spec.chain_id
            || self.gas_limit != spec.gas_limit
            || self.beneficiary != spec.coinbase()
        {
            return Err(NodeHeaderError::Configuration);
        }
        if self.user_gas_used > self.gas_used || self.gas_used > self.gas_limit {
            return Err(NodeHeaderError::GasAccounting);
        }
        Ok(())
    }

    /// Check a non-genesis header against an already authenticated parent.
    /// Genesis/domain initialization requires its own explicit activation rule.
    pub fn validate_parent(&self, spec: &ChainSpec, parent: &Self) -> Result<(), NodeHeaderError> {
        self.validate_configuration(spec, parent.domain)?;
        parent.validate_configuration(spec, parent.domain)?;
        if self.parent_hash != parent.hash()
            || self.parent_state_root != parent.state_root
            || parent.number.checked_add(1) != Some(self.number)
            || self.timestamp < parent.timestamp
            || self.base_fee_per_gas != spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used)
        {
            return Err(NodeHeaderError::Parent);
        }
        Ok(())
    }

    /// Authenticate signed body envelopes and reconcile commitments and receipts.
    /// This does not establish receipt execution correctness, state roots or L1
    /// provenance; the V2 executor and authenticated derivation must do that.
    pub fn validate_commitments(
        &self,
        spec: &ChainSpec,
        expected_domain: B256,
        body: &NodeBodyV2,
        receipts: &[ReceiptEnvelope],
    ) -> Result<(), NodeHeaderError> {
        self.validate_configuration(spec, expected_domain)?;
        let input = body.authenticated_input(spec).map_err(NodeHeaderError::Body)?;
        if self.transactions_root != body.transactions_root() || self.deposits_hash != body.deposits_hash() {
            return Err(NodeHeaderError::BodyCommitment);
        }
        if receipts.len() != input.txs.len() {
            return Err(NodeHeaderError::Receipts);
        }
        let mut cumulative = 0u64;
        let mut bloom = Bloom::ZERO;
        for (receipt, tx) in receipts.iter().zip(&input.txs) {
            let next = receipt.cumulative_gas_used();
            let computed: Bloom = receipt.logs().iter().collect();
            if receipt.tx_type() as u8 != tx.tx_type
                || !matches!(receipt.status_or_post_state(), Eip658Value::Eip658(_))
                || next <= cumulative
                || next - cumulative > tx.gas_limit
                || receipt.logs_bloom() != &computed
            {
                return Err(NodeHeaderError::Receipts);
            }
            cumulative = next;
            bloom.accrue_bloom(&computed);
        }
        let count = u64::try_from(body.deposits.len()).map_err(|_| NodeHeaderError::GasAccounting)?;
        let deposit_gas = count
            .checked_mul(spec.deposit_gas)
            .ok_or(NodeHeaderError::GasAccounting)?;
        if cumulative != self.user_gas_used || cumulative.checked_add(deposit_gas) != Some(self.gas_used) {
            return Err(NodeHeaderError::GasAccounting);
        }
        if self.receipts_root != calculate_receipt_root(receipts) || self.logs_bloom != bloom {
            return Err(NodeHeaderError::ReceiptCommitment);
        }
        Ok(())
    }
}

impl Encodable for NodeHeaderV2 {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_header().encode(out);
        for field in self.fields() {
            field.encode(out);
        }
    }
    fn length(&self) -> usize {
        let header = self.rlp_header();
        header.length() + header.payload_length
    }
}
impl Decodable for NodeHeaderV2 {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // All fields have fixed maximum widths; no attacker-controlled allocation.
        let mut remaining = *buf;
        let mut payload = Header::decode_bytes(&mut remaining, true)?;
        if payload.len() > 1024 {
            return Err(alloy_rlp::Error::Custom("V2 header too large"));
        }
        if Header::decode_bytes(&mut payload, false)? != NODE_HEADER_V2_TAG {
            return Err(alloy_rlp::Error::Custom("unsupported Bloch header format"));
        }
        let header = Self {
            domain: Decodable::decode(&mut payload)?,
            chain_id: Decodable::decode(&mut payload)?,
            number: Decodable::decode(&mut payload)?,
            timestamp: Decodable::decode(&mut payload)?,
            base_fee_per_gas: Decodable::decode(&mut payload)?,
            gas_limit: Decodable::decode(&mut payload)?,
            gas_used: Decodable::decode(&mut payload)?,
            user_gas_used: Decodable::decode(&mut payload)?,
            beneficiary: Decodable::decode(&mut payload)?,
            prevrandao: Decodable::decode(&mut payload)?,
            anchor_root: Decodable::decode(&mut payload)?,
            parent_hash: Decodable::decode(&mut payload)?,
            parent_state_root: Decodable::decode(&mut payload)?,
            transactions_root: Decodable::decode(&mut payload)?,
            receipts_root: Decodable::decode(&mut payload)?,
            deposits_hash: Decodable::decode(&mut payload)?,
            logs_bloom: Decodable::decode(&mut payload)?,
            state_root: Decodable::decode(&mut payload)?,
        };
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::Custom("extra V2 header fields"));
        }
        *buf = remaining;
        Ok(header)
    }
}
