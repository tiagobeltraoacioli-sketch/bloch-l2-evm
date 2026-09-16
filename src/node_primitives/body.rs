// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental V2 body codec; independent of the V1 execution-domain format.
use crate::{
    executor::{deposits_hash, validate_block_input, BlockExecutionError},
    transactions::{
        SignedBlockInput, SignedInputError, MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS,
    },
    ChainSpec, DepositMint, DepositProvenance,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use alloy_primitives::{Address, Bytes, B256};
use alloy_rlp::{BufMut, Decodable, Encodable, Error as RlpError, Header};

/// Absolute V2 format work bound; chain-specific deposit gas limits also apply.
pub const MAX_NODE_DEPOSITS: usize = u16::MAX as usize;
/// Maximum complete V2 body encoding, including bounded RLP framing overhead.
pub const MAX_NODE_BODY_BYTES: usize =
    MAX_SIGNED_BLOCK_BYTES + MAX_SIGNED_TRANSACTIONS * 9 + MAX_NODE_DEPOSITS * 90 + 128;
const BODY_TAG: &[u8] = b"BLOCH:EVM:BODY:2";

/// Explicit Bloch body: deposits plus canonical signed transaction byte strings.
/// Legacy transactions are byte strings too, not nested Ethereum body lists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeBodyV2 {
    /// Ordered host-authenticated deposit data; validation does not prove L1 trust.
    pub deposits: Vec<DepositMint>,
    /// Exact ordered signed envelopes, authenticated by [`Self::validate`].
    pub transactions: Vec<Bytes>,
}

/// Format bounds, signature authentication or chain-specific input validation failed.
#[derive(Debug)]
pub enum NodeBodyError {
    /// Deposit count exceeds the V2 format limit.
    DepositsLimit,
    /// Transaction count exceeds the signed execution limit.
    TransactionsLimit,
    /// One signed envelope exceeds its byte limit.
    RawTransactionLimit,
    /// Aggregate signed bytes exceed the block limit.
    TransactionBytesLimit,
    /// Shared signed-input authentication failed.
    SignedInput(SignedInputError<BlockExecutionError>),
    /// Shared stateless block validation failed.
    BlockInput(BlockExecutionError),
}
impl core::fmt::Display for NodeBodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DepositsLimit => f.write_str("V2 deposit count limit exceeded"),
            Self::TransactionsLimit => f.write_str("V2 transaction count limit exceeded"),
            Self::RawTransactionLimit => f.write_str("V2 raw transaction size limit exceeded"),
            Self::TransactionBytesLimit => f.write_str("V2 transaction byte budget exceeded"),
            Self::SignedInput(error) => error.fmt(f),
            Self::BlockInput(error) => error.fmt(f),
        }
    }
}
impl core::error::Error for NodeBodyError {}
impl NodeBodyV2 {
    /// Validate bounds, canonical signatures, chain ID and deposit order/caps.
    /// Deposit provenance is data only: the host must independently verify L1.
    pub fn validate(&self, spec: &ChainSpec) -> Result<(), NodeBodyError> {
        self.authenticated_input(spec).map(|_| ())
    }
    pub(crate) fn authenticated_input(&self, spec: &ChainSpec) -> Result<crate::BlockInput, NodeBodyError> {
        if self.deposits.len() > MAX_NODE_DEPOSITS {
            return Err(NodeBodyError::DepositsLimit);
        }
        if self.transactions.len() > MAX_SIGNED_TRANSACTIONS {
            return Err(NodeBodyError::TransactionsLimit);
        }
        let mut total = 0usize;
        for raw in &self.transactions {
            if raw.len() > MAX_RAW_TRANSACTION_BYTES {
                return Err(NodeBodyError::RawTransactionLimit);
            }
            total = total
                .checked_add(raw.len())
                .filter(|total| *total <= MAX_SIGNED_BLOCK_BYTES)
                .ok_or(NodeBodyError::TransactionBytesLimit)?;
        }
        let input = SignedBlockInput {
            context: Default::default(),
            deposits: self.deposits.clone(),
            transactions: self.transactions.clone(),
        };
        let authenticated = input
            .authenticate::<BlockExecutionError>(spec)
            .map_err(NodeBodyError::SignedInput)?;
        validate_block_input(spec, &authenticated).map_err(NodeBodyError::BlockInput)?;
        Ok(authenticated)
    }
    /// Ordered Keccak MPT root with exact envelope bytes as leaf values.
    /// Call [`Self::validate`] before trusting an unvalidated body's commitment.
    pub fn transactions_root(&self) -> B256 {
        alloy_trie::root::ordered_trie_root_encoded(&self.transactions)
    }
    /// Existing canonical deposit-list commitment, with no new provenance claims.
    pub fn deposits_hash(&self) -> B256 {
        deposits_hash(&self.deposits)
    }
    fn payload_lengths(&self) -> (usize, usize, usize) {
        let deposits = self.deposits.iter().map(deposit_length).sum();
        let transactions = self.transactions.iter().map(Encodable::length).sum();
        (
            deposits,
            transactions,
            BODY_TAG.length() + list_length(deposits) + list_length(transactions),
        )
    }
}
fn list_length(payload: usize) -> usize {
    Header {
        list: true,
        payload_length: payload,
    }
    .length()
        + payload
}
fn deposit_payload(deposit: &DepositMint) -> usize {
    let DepositProvenance::BridgedBlch {
        l1_height,
        l1_tx_index,
        l1_txid,
        l1_vout,
        l1_sats,
    } = deposit.provenance;
    deposit.recipient.length()
        + l1_height.length()
        + l1_tx_index.length()
        + B256::from(l1_txid).length()
        + l1_vout.length()
        + l1_sats.length()
}
fn deposit_length(deposit: &DepositMint) -> usize {
    list_length(deposit_payload(deposit))
}
fn encode_deposit(deposit: &DepositMint, out: &mut dyn BufMut) {
    Header {
        list: true,
        payload_length: deposit_payload(deposit),
    }
    .encode(out);
    let DepositProvenance::BridgedBlch {
        l1_height,
        l1_tx_index,
        l1_txid,
        l1_vout,
        l1_sats,
    } = deposit.provenance;
    deposit.recipient.encode(out);
    l1_height.encode(out);
    l1_tx_index.encode(out);
    B256::from(l1_txid).encode(out);
    l1_vout.encode(out);
    l1_sats.encode(out);
}
impl Encodable for NodeBodyV2 {
    fn encode(&self, out: &mut dyn BufMut) {
        let (deposits, transactions, payload) = self.payload_lengths();
        Header {
            list: true,
            payload_length: payload,
        }
        .encode(out);
        BODY_TAG.encode(out);
        Header {
            list: true,
            payload_length: deposits,
        }
        .encode(out);
        for deposit in &self.deposits {
            encode_deposit(deposit, out)
        }
        Header {
            list: true,
            payload_length: transactions,
        }
        .encode(out);
        for tx in &self.transactions {
            tx.encode(out)
        }
    }
    fn length(&self) -> usize {
        list_length(self.payload_lengths().2)
    }
}
fn decode_deposit(input: &mut &[u8]) -> alloy_rlp::Result<DepositMint> {
    let mut fields = Header::decode_bytes(input, true)?;
    let recipient = Address::decode(&mut fields)?;
    let l1_height = u64::decode(&mut fields)?;
    let l1_tx_index = u32::decode(&mut fields)?;
    let l1_txid = B256::decode(&mut fields)?.0;
    let l1_vout = u32::decode(&mut fields)?;
    let l1_sats = u64::decode(&mut fields)?;
    if !fields.is_empty() {
        return Err(RlpError::Custom("extra V2 deposit fields"));
    }
    Ok(DepositMint {
        recipient,
        provenance: DepositProvenance::BridgedBlch {
            l1_height,
            l1_tx_index,
            l1_txid,
            l1_vout,
            l1_sats,
        },
    })
}
impl Decodable for NodeBodyV2 {
    fn decode(input: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // Borrow slices first. Never allocate from untrusted declared lengths.
        let original_len = input.len();
        let mut remaining = *input;
        let header = Header::decode(&mut remaining)?;
        if !header.list {
            return Err(RlpError::UnexpectedString);
        }
        let encoded_len = original_len - remaining.len() + header.payload_length;
        if encoded_len > MAX_NODE_BODY_BYTES {
            return Err(RlpError::Custom("V2 body size limit exceeded"));
        }
        let (mut payload, tail) = remaining.split_at(header.payload_length);
        if Header::decode_bytes(&mut payload, false)? != BODY_TAG {
            return Err(RlpError::Custom("unsupported V2 body tag"));
        }
        let mut deposit_data = Header::decode_bytes(&mut payload, true)?;
        let mut transaction_data = Header::decode_bytes(&mut payload, true)?;
        if !payload.is_empty() {
            return Err(RlpError::Custom("extra V2 body fields"));
        }
        let mut deposits = Vec::new();
        while !deposit_data.is_empty() {
            if deposits.len() == MAX_NODE_DEPOSITS {
                return Err(RlpError::Custom("V2 deposit count limit exceeded"));
            }
            deposits.push(decode_deposit(&mut deposit_data)?);
        }
        let mut transactions = Vec::new();
        let mut total = 0usize;
        while !transaction_data.is_empty() {
            if transactions.len() == MAX_SIGNED_TRANSACTIONS {
                return Err(RlpError::Custom("V2 transaction count limit exceeded"));
            }
            let raw = Header::decode_bytes(&mut transaction_data, false)?;
            if raw.len() > MAX_RAW_TRANSACTION_BYTES {
                return Err(RlpError::Custom("V2 raw transaction size limit exceeded"));
            }
            total = total
                .checked_add(raw.len())
                .filter(|total| *total <= MAX_SIGNED_BLOCK_BYTES)
                .ok_or(RlpError::Custom("V2 transaction byte budget exceeded"))?;
            transactions.push(Bytes::copy_from_slice(raw));
        }
        *input = tail;
        Ok(Self { deposits, transactions })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::{vec, vec::Vec};
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{bytes, Signature, TxKind};
    use k256::ecdsa::SigningKey;
    fn deposit(height: u64) -> DepositMint {
        DepositMint {
            recipient: Address::repeat_byte(0x11),
            provenance: DepositProvenance::BridgedBlch {
                l1_height: height,
                l1_tx_index: 0,
                l1_txid: [0x22; 32],
                l1_vout: 0,
                l1_sats: 1,
            },
        }
    }
    fn signed(spec: &ChainSpec) -> TxEnvelope {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let tx = TxEip1559 {
            chain_id: spec.chain_id,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            to: TxKind::Call(Address::repeat_byte(0x33)),
            ..Default::default()
        };
        let signature: Signature = key
            .sign_prehash_recoverable(tx.signature_hash().as_slice())
            .unwrap()
            .into();
        tx.into_signed(signature).into()
    }
    fn decode_exact(encoded: &[u8]) -> alloy_rlp::Result<NodeBodyV2> {
        let mut input = encoded;
        let body = NodeBodyV2::decode(&mut input)?;
        if !input.is_empty() {
            return Err(RlpError::UnexpectedLength);
        }
        Ok(body)
    }
    #[test]
    fn maximum_deposit_fields_fit_the_outer_size_budget() {
        let deposit = DepositMint {
            recipient: Address::repeat_byte(0xff),
            provenance: DepositProvenance::BridgedBlch {
                l1_height: u64::MAX,
                l1_tx_index: u32::MAX,
                l1_txid: [0xff; 32],
                l1_vout: u32::MAX,
                l1_sats: u64::MAX,
            },
        };
        let mut encoded = Vec::new();
        encode_deposit(&deposit, &mut encoded);
        assert_eq!(encoded.len(), deposit_length(&deposit));
        assert_eq!(encoded.len(), 84);
        assert!(encoded.len() <= 90, "outer bound budgets 90 bytes per deposit");
        let mut input = encoded.as_slice();
        assert_eq!(decode_deposit(&mut input).unwrap(), deposit);
        assert!(input.is_empty());
    }

    #[test]
    fn empty_body_has_fixed_golden_encoding_and_empty_transaction_root() {
        let body = NodeBodyV2::default();
        let golden = bytes!("d390424c4f43483a45564d3a424f44593a32c0c0");
        assert_eq!(alloy_rlp::encode(&body), golden.as_ref());
        assert_eq!(body.length(), golden.len());
        assert_eq!(decode_exact(&golden).unwrap(), body);
        assert_eq!(body.transactions_root(), alloy_trie::EMPTY_ROOT_HASH);
        body.validate(&ChainSpec::testnet()).unwrap();
    }
    #[test]
    fn explicit_deposit_fields_and_raw_legacy_bytes_round_trip() {
        let body = NodeBodyV2 {
            deposits: vec![deposit(1)],
            transactions: vec![bytes!("02"), bytes!("c001")],
        };
        let mut golden = vec![0xf8, 0x54, 0x90];
        golden.extend_from_slice(BODY_TAG);
        golden.extend_from_slice(&[0xf8, 0x3c, 0xf8, 0x3a, 0x94]);
        golden.extend_from_slice(&[0x11; 20]);
        golden.extend_from_slice(&[1, 0x80, 0xa0]);
        golden.extend_from_slice(&[0x22; 32]);
        golden.extend_from_slice(&[0x80, 1, 0xc4, 2, 0x82, 0xc0, 1]);
        assert_eq!(alloy_rlp::encode(&body), golden);
        assert_eq!(body.length(), golden.len());
        assert_eq!(decode_exact(&golden).unwrap(), body);
        assert!(
            body.validate(&ChainSpec::testnet()).is_err(),
            "codec does not substitute for signature authentication"
        );
        for end in 0..golden.len() {
            assert!(decode_exact(&golden[..end]).is_err());
        }
    }
    #[test]
    fn signed_root_matches_consensus_mpt_and_validation_reuses_deposit_rules() {
        let spec = ChainSpec::testnet();
        let signed = signed(&spec);
        let mut body = NodeBodyV2 {
            deposits: vec![deposit(1), deposit(2)],
            transactions: vec![signed.encoded_2718().into()],
        };
        body.validate(&spec).unwrap();
        assert_eq!(
            body.transactions_root(),
            alloy_consensus::proofs::calculate_transaction_root(&[signed])
        );
        assert_eq!(body.deposits_hash(), deposits_hash(&body.deposits));
        let encoded = alloy_rlp::encode(&body);
        assert_eq!(decode_exact(&encoded).unwrap(), body);
        body.deposits.swap(0, 1);
        assert!(matches!(body.validate(&spec), Err(NodeBodyError::BlockInput(_))));
        body.deposits.clear();
        let foreign = ChainSpec {
            chain_id: spec.chain_id + 1,
            ..spec
        };
        assert!(matches!(body.validate(&foreign), Err(NodeBodyError::SignedInput(_))));
    }
    #[test]
    fn decoder_rejects_wrong_tag_extra_fields_and_noncanonical_rlp() {
        let golden = alloy_rlp::encode(NodeBodyV2::default());
        let mut wrong = golden.clone();
        wrong[17] = b'1';
        assert!(decode_exact(&wrong).is_err());
        let mut extra = golden.clone();
        extra[0] += 1;
        extra.push(0x80);
        assert!(decode_exact(&extra).is_err());
        let mut noncanonical = vec![0xf8, 0x13];
        noncanonical.extend_from_slice(&golden[1..]);
        assert!(matches!(decode_exact(&noncanonical), Err(RlpError::NonCanonicalSize)));
        let mut outer_tail = golden;
        outer_tail.push(0);
        assert!(decode_exact(&outer_tail).is_err());
        let mut invalid_integer = alloy_rlp::encode(NodeBodyV2 {
            deposits: vec![deposit(1)],
            transactions: vec![],
        });
        // Locate the height immediately following the recipient in this fixed fixture.
        let offset = invalid_integer
            .windows(20)
            .position(|slice| slice == [0x11; 20])
            .unwrap()
            + 20;
        invalid_integer[offset] = 0;
        assert!(decode_exact(&invalid_integer).is_err());
    }
    #[test]
    fn count_and_byte_limits_are_enforced_by_decode_and_validate() {
        let spec = ChainSpec::testnet();
        let cases = [
            NodeBodyV2 {
                deposits: vec![],
                transactions: vec![Bytes::new(); MAX_SIGNED_TRANSACTIONS + 1],
            },
            NodeBodyV2 {
                deposits: vec![],
                transactions: vec![Bytes::from(vec![1; MAX_RAW_TRANSACTION_BYTES + 1])],
            },
            NodeBodyV2 {
                deposits: vec![],
                transactions: vec![
                    Bytes::from(vec![1; MAX_RAW_TRANSACTION_BYTES]);
                    MAX_SIGNED_BLOCK_BYTES / MAX_RAW_TRANSACTION_BYTES + 1
                ],
            },
            NodeBodyV2 {
                deposits: vec![deposit(1); MAX_NODE_DEPOSITS + 1],
                transactions: vec![],
            },
        ];
        for body in cases {
            assert!(body.validate(&spec).is_err());
            assert!(decode_exact(&alloy_rlp::encode(&body)).is_err());
        }
        let body = NodeBodyV2 {
            deposits: vec![deposit(1); spec.max_deposits_per_block() as usize + 1],
            transactions: vec![],
        };
        assert!(matches!(body.validate(&spec), Err(NodeBodyError::SignedInput(_))));
        // Declared huge outer payload is rejected without allocating it.
        let mut header = Vec::new();
        Header {
            list: true,
            payload_length: MAX_NODE_BODY_BYTES + 1,
        }
        .encode(&mut header);
        assert!(decode_exact(&header).is_err());
    }
}
