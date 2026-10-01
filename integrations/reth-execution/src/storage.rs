// SPDX-License-Identifier: MIT OR Apache-2.0
//! Chain-specific body storage in the caller's Reth database transaction.
//! Transactions, headers, canonical mappings and state are stored by their own
//! providers. Callers must abort the whole transaction after any write error.
use crate::{BlochNodeBlock, BlochNodeBody};
use alloy_eips::eip2718::Encodable2718;
use alloy_rlp::{Decodable, Encodable, Error};
use bloch_l2_evm::{
    node_primitives::{NodeBodyV2, MAX_NODE_DEPOSITS},
    transactions::{MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS},
    DepositMint,
};
use reth_codecs::{Compress, Decompress, DecompressError};
use reth_db_api::{
    cursor::DbCursorRO,
    table::{Table, TableInfo},
    tables::{TableSet, Tables},
    transaction::{DbTx, DbTxMut},
};
use reth_storage_api::{BlockBodyReader, BlockBodyWriter, DBProvider, ReadBodyInput};
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use std::collections::BTreeSet;

/// Encoded deposits-only body upper bound, checked before storage decoding.
pub const MAX_STORED_DEPOSITS_BYTES: usize = MAX_NODE_DEPOSITS * 90 + 128;

/// Canonical deposits-only V2 body; transactions are persisted separately by Reth.
/// Private fields ensure compression cannot produce an oversized or mixed record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBlochDeposits(NodeBodyV2);
impl StoredBlochDeposits {
    /// Construct bounded storage data. This checks format limits, not L1 provenance.
    pub fn try_new(deposits: Vec<DepositMint>) -> alloy_rlp::Result<Self> {
        if deposits.len() > MAX_NODE_DEPOSITS {
            return Err(Error::Custom("Bloch deposit storage count exceeded"));
        }
        Ok(Self(NodeBodyV2 {
            deposits,
            transactions: vec![],
        }))
    }
    /// The persisted deposit list, including its exact L1 positions and outpoints.
    pub fn deposits(&self) -> &[DepositMint] {
        &self.0.deposits
    }
}
impl serde::Serialize for StoredBlochDeposits {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&alloy_rlp::encode(&self.0))
    }
}
impl Compress for StoredBlochDeposits {
    type Compressed = Vec<u8>;
    fn compress_to_buf<B: alloy_rlp::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        self.0.encode(buf);
    }
}
impl Decompress for StoredBlochDeposits {
    fn decompress(value: &[u8]) -> Result<Self, DecompressError> {
        if value.len() > MAX_STORED_DEPOSITS_BYTES {
            return Err(DecompressError::new(Error::Custom(
                "Bloch deposit storage bytes exceeded",
            )));
        }
        let mut bytes = value;
        let body = NodeBodyV2::decode(&mut bytes).map_err(DecompressError::new)?;
        if !bytes.is_empty() || !body.transactions.is_empty() {
            return Err(DecompressError::new(Error::Custom(
                "noncanonical Bloch deposit storage record",
            )));
        }
        Ok(Self(body))
    }
}

/// Canonical deposit records keyed by block number. Every available body has a row,
/// including an explicit empty list; absence is never interpreted as no deposits.
#[derive(Debug)]
pub struct BlochV2Deposits;
impl Table for BlochV2Deposits {
    const NAME: &'static str = "BlochV2Deposits";
    const DUPSORT: bool = false;
    type Key = u64;
    type Value = StoredBlochDeposits;
}
impl TableInfo for BlochV2Deposits {
    fn name(&self) -> &'static str {
        <Self as Table>::NAME
    }
    fn is_dupsort(&self) -> bool {
        false
    }
}
/// Standard Reth tables plus the Bloch V2 deposits and finality-candidate tables.
/// Register this complete set at database creation and reopen, before sharing it.
#[derive(Debug)]
pub struct BlochTables;
impl TableSet for BlochTables {
    fn tables() -> Box<dyn Iterator<Item = Box<dyn TableInfo>>> {
        Box::new(Tables::tables().chain([
            Box::new(BlochV2Deposits) as Box<dyn TableInfo>,
            Box::new(crate::finality_cursor::BlochFinalityCandidate) as Box<dyn TableInfo>,
        ]))
    }
}

/// Chain-specific Reth storage for the additional Bloch body data.
/// This is a codec/commitment boundary, not consensus or L1 authentication.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlochChainStorage;
fn invalid(message: &'static str) -> ProviderError {
    ProviderError::other(Error::Custom(message))
}
impl<P: DBProvider<Tx: DbTxMut>> BlockBodyWriter<P, BlochNodeBody> for BlochChainStorage {
    fn write_block_bodies(&self, provider: &P, bodies: Vec<(u64, Option<&BlochNodeBody>)>) -> ProviderResult<()> {
        // Finish logical validation and reads before the first mutation. The
        // surrounding database transaction still provides error/abort atomicity.
        let mut seen = BTreeSet::new();
        let mut prepared = Vec::new();
        for (number, body) in bodies {
            if !seen.insert(number) {
                return Err(invalid("duplicate Bloch body height in write batch"));
            }
            let Some(body) = body else { continue };
            let record = StoredBlochDeposits::try_new(body.as_core().deposits.clone()).map_err(ProviderError::other)?;
            if let Some(existing) = provider.tx_ref().get::<BlochV2Deposits>(number)? {
                if existing != record {
                    return Err(invalid("conflicting Bloch deposits; unwind before replacing a body"));
                }
                continue;
            }
            prepared.push((number, record));
        }
        for (number, record) in prepared {
            provider.tx_ref().put::<BlochV2Deposits>(number, record)?;
        }
        Ok(())
    }
    fn remove_block_bodies_above(&self, provider: &P, block: u64) -> ProviderResult<()> {
        let mut cursor = provider.tx_ref().cursor_write::<BlochV2Deposits>()?;
        let mut walker = cursor.walk_back(None)?;
        // Do not swallow a corrupt row or cursor error as successful unwind.
        while let Some(row) = walker.next() {
            let (number, _) = row?;
            if number <= block {
                break;
            }
            walker.delete_current()?;
        }
        Ok(())
    }
}
impl<P: DBProvider> BlockBodyReader<P> for BlochChainStorage {
    type Block = BlochNodeBlock;
    fn read_block_bodies(
        &self,
        provider: &P,
        inputs: Vec<ReadBodyInput<'_, Self::Block>>,
    ) -> ProviderResult<Vec<BlochNodeBody>> {
        inputs
            .into_iter()
            .map(|(header, transactions)| {
                if transactions.len() > MAX_SIGNED_TRANSACTIONS {
                    return Err(invalid("Bloch stored transaction count exceeded"));
                }
                let mut total = 0usize;
                for transaction in &transactions {
                    let length = transaction.encode_2718_len();
                    if length > MAX_RAW_TRANSACTION_BYTES {
                        return Err(invalid("Bloch stored transaction too large"));
                    }
                    total = total
                        .checked_add(length)
                        .filter(|bytes| *bytes <= MAX_SIGNED_BLOCK_BYTES)
                        .ok_or_else(|| invalid("Bloch stored transaction bytes exceeded"))?;
                }
                let record = provider
                    .tx_ref()
                    .get::<BlochV2Deposits>(header.0.number)?
                    .ok_or_else(|| invalid("missing Bloch deposit body record"))?;
                let body = NodeBodyV2 {
                    deposits: record.0.deposits,
                    transactions: transactions.iter().map(|tx| tx.encoded_2718().into()).collect(),
                };
                if body.deposits_hash() != header.0.deposits_hash
                    || body.transactions_root() != header.0.transactions_root
                {
                    return Err(invalid("stored Bloch body does not match header commitments"));
                }
                BlochNodeBody::try_from_core(body).map_err(ProviderError::other)
            })
            .collect()
    }
}

impl reth_provider::providers::ChainStorage<crate::BlochNodePrimitives> for BlochChainStorage {
    fn reader<TX, Types>(
        &self,
    ) -> impl reth_storage_api::ChainStorageReader<reth_provider::DatabaseProvider<TX, Types>, crate::BlochNodePrimitives>
    where
        TX: DbTx + 'static,
        Types: reth_provider::providers::NodeTypesForProvider<Primitives = crate::BlochNodePrimitives>,
    {
        self
    }
    fn writer<TX, Types>(
        &self,
    ) -> impl reth_storage_api::ChainStorageWriter<reth_provider::DatabaseProvider<TX, Types>, crate::BlochNodePrimitives>
    where
        TX: DbTxMut + DbTx + 'static,
        Types: reth_provider::providers::NodeTypesForProvider<Primitives = crate::BlochNodePrimitives>,
    {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes};
    use bloch_l2_evm::DepositProvenance;
    fn deposit() -> DepositMint {
        DepositMint {
            recipient: Address::repeat_byte(7),
            provenance: DepositProvenance::BridgedBlch {
                l1_height: u64::MAX,
                l1_tx_index: u32::MAX,
                l1_txid: [0xff; 32],
                l1_vout: u32::MAX,
                l1_sats: u64::MAX,
            },
        }
    }
    #[test]
    fn storage_codec_is_bounded_canonical_and_deposits_only() {
        let record = StoredBlochDeposits::try_new(vec![deposit()]).unwrap();
        let encoded = record.clone().compress();
        assert_eq!(StoredBlochDeposits::decompress(&encoded).unwrap(), record);
        assert_eq!(
            encoded,
            alloy_rlp::encode(&NodeBodyV2 {
                deposits: vec![deposit()],
                transactions: vec![]
            })
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(StoredBlochDeposits::decompress(&trailing).is_err());
        assert!(StoredBlochDeposits::decompress(&encoded[..encoded.len() - 1]).is_err());
        assert!(StoredBlochDeposits::decompress(&vec![0; MAX_STORED_DEPOSITS_BYTES + 1]).is_err());
        let mixed = NodeBodyV2 {
            deposits: vec![],
            transactions: vec![Bytes::from_static(&[0xff])],
        };
        assert!(StoredBlochDeposits::decompress(&alloy_rlp::encode(&mixed)).is_err());
        assert!(StoredBlochDeposits::try_new(vec![deposit(); MAX_NODE_DEPOSITS + 1]).is_err());
    }
}
