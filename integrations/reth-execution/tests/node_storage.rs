// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual MDBX body-table durability; this is not canonical state unwind.
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Signature, TxKind, B256};
use bloch_l2_evm::{
    node_execution::{genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    ChainSpec, DepositMint, DepositProvenance,
};
use bloch_reth_execution::{
    storage::{BlochChainStorage, BlochTables, BlochV2Deposits, StoredBlochDeposits},
    BlochNodeBody, BlochNodeHeader, BlochRethTransaction,
};
use k256::ecdsa::SigningKey;
use reth_db::{
    mdbx::{init_db_for, DatabaseArguments},
    tables::{RawKey, RawTable, RawValue},
    transaction::{DbTx, DbTxMut},
    Database,
};
use reth_primitives_traits::BlockBody;
use reth_prune_types::PruneModes;
use reth_storage_api::{BlockBodyReader, BlockBodyWriter, DBProvider};
use reth_storage_errors::provider::ProviderResult;

struct Provider<T> {
    tx: T,
    prune: PruneModes,
}
impl<T> Provider<T> {
    fn new(tx: T) -> Self {
        Self {
            tx,
            prune: PruneModes::default(),
        }
    }
}
impl<T: DbTx> DBProvider for Provider<T> {
    type Tx = T;
    fn tx_ref(&self) -> &T {
        &self.tx
    }
    fn tx_mut(&mut self) -> &mut T {
        &mut self.tx
    }
    fn into_tx(self) -> T {
        self.tx
    }
    fn commit(self) -> ProviderResult<()> {
        self.tx.commit().map(|_| ()).map_err(Into::into)
    }
    fn prune_modes_ref(&self) -> &PruneModes {
        &self.prune
    }
}
fn tx(nonce: u64) -> BlochRethTransaction {
    let transaction = TxEip1559 {
        chain_id: ChainSpec::testnet().chain_id,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 2_000_000_000,
        to: TxKind::Call(Address::repeat_byte(9)),
        ..Default::default()
    };
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let signature: Signature = key
        .sign_prehash_recoverable(transaction.signature_hash().as_slice())
        .unwrap()
        .into();
    transaction.into_signed(signature).into()
}
fn body(nonempty: bool) -> BlochNodeBody {
    BlochNodeBody::try_from_core(NodeBodyV2 {
        deposits: if nonempty {
            vec![DepositMint {
                recipient: Address::repeat_byte(33),
                provenance: DepositProvenance::BridgedBlch {
                    l1_height: 1,
                    l1_tx_index: 0,
                    l1_txid: [1; 32],
                    l1_vout: 0,
                    l1_sats: 123,
                },
            }]
        } else {
            vec![]
        },
        transactions: if nonempty {
            vec![tx(0).encoded_2718().into(), tx(1).encoded_2718().into()]
        } else {
            vec![]
        },
    })
    .unwrap()
}
fn header(number: u64, body: &BlochNodeBody) -> BlochNodeHeader {
    let spec = ChainSpec::testnet();
    let state = genesis_v2(&spec, 10).unwrap();
    let mut header = node_head(&spec, B256::repeat_byte(42), &state).unwrap();
    header.number = number;
    header.deposits_hash = body.as_core().deposits_hash();
    header.transactions_root = body.as_core().transactions_root();
    BlochNodeHeader(header)
}
#[test]
fn committed_empty_and_nonempty_bodies_reopen_and_removal_is_transactional() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mdbx");
    let db = init_db_for::<_, BlochTables>(&path, DatabaseArguments::test()).unwrap();
    let storage = BlochChainStorage;
    let empty = body(false);
    let populated = body(true);
    let first = header(1, &empty);
    let second = header(2, &populated);
    {
        let writer = Provider::new(db.tx_mut().unwrap());
        storage
            .write_block_bodies(&writer, vec![(1, Some(&empty)), (2, Some(&populated)), (3, None)])
            .unwrap();
        writer
            .tx_ref()
            .put::<reth_db::tables::Headers<BlochNodeHeader>>(1, first.clone())
            .unwrap();
        writer
            .tx_ref()
            .put::<reth_db::tables::Headers<BlochNodeHeader>>(2, second.clone())
            .unwrap();
        for (index, transaction) in populated.transactions().iter().enumerate() {
            writer
                .tx_ref()
                .put::<reth_db::tables::Transactions<BlochRethTransaction>>(index as u64, transaction.clone())
                .unwrap();
        }
        writer.commit().unwrap();
    }
    // Identical replay is idempotent; conflicts/duplicates preflight the entire batch.
    {
        let writer = Provider::new(db.tx_mut().unwrap());
        storage
            .write_block_bodies(&writer, vec![(2, Some(&populated))])
            .unwrap();
        assert!(storage
            .write_block_bodies(&writer, vec![(4, Some(&empty)), (2, Some(&empty))])
            .is_err());
        assert!(writer.tx_ref().get::<BlochV2Deposits>(4).unwrap().is_none());
        assert!(storage
            .write_block_bodies(&writer, vec![(5, Some(&empty)), (5, Some(&empty))])
            .is_err());
        assert!(writer.tx_ref().get::<BlochV2Deposits>(5).unwrap().is_none());
        writer.commit().unwrap();
    }
    {
        let writer = Provider::new(db.tx_mut().unwrap());
        storage.write_block_bodies(&writer, vec![(3, Some(&empty))]).unwrap();
        // Drop aborts an otherwise valid write.
    }
    {
        let writer = Provider::new(db.tx_mut().unwrap());
        storage.remove_block_bodies_above(&writer, 1).unwrap();
        assert!(writer.tx_ref().get::<BlochV2Deposits>(2).unwrap().is_none());
        // Drop also aborts removal.
    }
    drop(db);
    let db = init_db_for::<_, BlochTables>(&path, DatabaseArguments::test()).unwrap();
    {
        let reader = Provider::new(db.tx().unwrap());
        let stored_first = reader
            .tx_ref()
            .get::<reth_db::tables::Headers<BlochNodeHeader>>(1)
            .unwrap()
            .unwrap();
        let stored_second = reader
            .tx_ref()
            .get::<reth_db::tables::Headers<BlochNodeHeader>>(2)
            .unwrap()
            .unwrap();
        assert_eq!(stored_first, first);
        assert_eq!(stored_second, second);
        let stored_transactions: Vec<_> = (0..2)
            .map(|index| {
                reader
                    .tx_ref()
                    .get::<reth_db::tables::Transactions<BlochRethTransaction>>(index)
                    .unwrap()
                    .unwrap()
            })
            .collect();
        assert_eq!(stored_transactions, populated.transactions());
        let result = storage
            .read_block_bodies(
                &reader,
                vec![(&stored_first, vec![]), (&stored_second, stored_transactions.clone())],
            )
            .unwrap();
        assert_eq!(result, vec![empty.clone(), populated.clone()]);
        assert!(reader
            .tx_ref()
            .get::<BlochV2Deposits>(1)
            .unwrap()
            .unwrap()
            .deposits()
            .is_empty());
        assert!(reader.tx_ref().get::<BlochV2Deposits>(3).unwrap().is_none());
        let mut reversed = stored_transactions.clone();
        reversed.reverse();
        assert!(storage.read_block_bodies(&reader, vec![(&second, reversed)]).is_err());
        let mut wrong = second.clone();
        wrong.0.deposits_hash = B256::ZERO;
        assert!(storage
            .read_block_bodies(&reader, vec![(&wrong, stored_transactions)])
            .is_err());
        assert!(storage
            .read_block_bodies(&reader, vec![(&header(3, &empty), vec![])])
            .is_err());
    }
    {
        let writer = Provider::new(db.tx_mut().unwrap());
        storage.remove_block_bodies_above(&writer, 1).unwrap();
        writer.commit().unwrap();
    }
    drop(db);
    let db = init_db_for::<_, BlochTables>(&path, DatabaseArguments::test()).unwrap();
    let reader = Provider::new(db.tx().unwrap());
    // Body-only removal intentionally does not pretend to unwind canonical headers.
    assert_eq!(
        reader
            .tx_ref()
            .get::<reth_db::tables::Headers<BlochNodeHeader>>(2)
            .unwrap(),
        Some(second.clone())
    );
    assert_eq!(
        storage.read_block_bodies(&reader, vec![(&first, vec![])]).unwrap(),
        vec![empty]
    );
    assert!(storage
        .read_block_bodies(&reader, vec![(&second, populated.transactions().to_vec())])
        .is_err());
}
#[test]
fn malformed_disk_rows_fail_reads_and_body_removal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mdbx");
    let db = init_db_for::<_, BlochTables>(&path, DatabaseArguments::test()).unwrap();
    let empty = body(false);
    let storage = BlochChainStorage;
    {
        let writer = Provider::new(db.tx_mut().unwrap());
        writer
            .tx_ref()
            .put::<BlochV2Deposits>(1, StoredBlochDeposits::try_new(vec![]).unwrap())
            .unwrap();
        writer
            .tx_ref()
            .put::<RawTable<BlochV2Deposits>>(RawKey::new(2), RawValue::from_vec(vec![0xff]))
            .unwrap();
        writer
            .tx_ref()
            .put::<BlochV2Deposits>(3, StoredBlochDeposits::try_new(vec![]).unwrap())
            .unwrap();
        writer.commit().unwrap();
    }
    drop(db);
    let db = init_db_for::<_, BlochTables>(&path, DatabaseArguments::test()).unwrap();
    {
        let reader = Provider::new(db.tx().unwrap());
        assert!(storage
            .read_block_bodies(&reader, vec![(&header(2, &empty), vec![])])
            .is_err());
    }
    {
        let writer = Provider::new(db.tx_mut().unwrap());
        assert!(storage.remove_block_bodies_above(&writer, 0).is_err());
        assert!(writer.tx_ref().get::<BlochV2Deposits>(3).unwrap().is_none());
        // A failed operation requires dropping this transaction; no partial removal is published.
    }
    drop(db);
    let db = init_db_for::<_, BlochTables>(&path, DatabaseArguments::test()).unwrap();
    let reader = Provider::new(db.tx().unwrap());
    assert!(reader.tx_ref().get::<BlochV2Deposits>(1).unwrap().is_some());
    assert!(reader.tx_ref().get::<BlochV2Deposits>(3).unwrap().is_some());
    assert_eq!(
        reader
            .tx_ref()
            .get::<RawTable<BlochV2Deposits>>(RawKey::new(2))
            .unwrap()
            .unwrap()
            .raw_value(),
        &[0xff]
    );
}
