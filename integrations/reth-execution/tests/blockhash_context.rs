// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual upstream BLOCKHASH instruction with Bloch host lookup and inspector.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{eth::EthEvmFactory, Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    decode_signed_transaction,
    state::{block_hash_slot, BLOCK_INFO_FLAG_SLOT},
    ChainSpec,
};
use bloch_reth_execution::{BlochContext, BlochEvmFactory};
use k256::ecdsa::SigningKey;
use reth_revm::revm::{
    context::{BlockEnv, CfgEnv},
    database::InMemoryDB,
    interpreter::Interpreter,
    state::{AccountInfo, Bytecode},
    Database, Inspector,
};
use std::{cell::Cell, rc::Rc};

#[derive(Debug)]
struct Unavailable;
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ring unavailable")
    }
}
impl std::error::Error for Unavailable {}
impl reth_revm::revm::context::DBErrorMarker for Unavailable {}
#[derive(Debug)]
struct ProbeDb {
    inner: InMemoryDB,
    reads: usize,
    blockhash_calls: usize,
    fail_slot: Option<U256>,
}
impl Database for ProbeDb {
    type Error = Unavailable;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.inner.basic(address).unwrap())
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.inner.code_by_hash(hash).unwrap())
    }
    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.reads += 1;
        if self.fail_slot == Some(slot) {
            return Err(Unavailable);
        }
        Ok(self.inner.storage(address, slot).unwrap())
    }
    fn block_hash(&mut self, _: u64) -> Result<B256, Self::Error> {
        self.blockhash_calls += 1;
        Ok(B256::repeat_byte(0xee))
    }
}
#[derive(Clone, Default)]
struct Observed(Rc<Cell<usize>>);
impl Inspector<BlochContext<ProbeDb>> for Observed {
    fn step(&mut self, _: &mut Interpreter, _: &mut BlochContext<ProbeDb>) {
        self.0.set(self.0.get() + 1)
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn tx(spec: &ChainSpec, number: u16) -> Bytes {
    let [high, low] = number.to_be_bytes();
    let transaction = TxEip1559 {
        chain_id: spec.chain_id,
        nonce: 0,
        gas_limit: 100_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        to: TxKind::Create,
        input: Bytes::from(vec![0x61, high, low, 0x40, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3]),
        ..Default::default()
    };
    let signature: Signature = key()
        .sign_prehash_recoverable(transaction.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(transaction.into_signed(signature))
        .encoded_2718()
        .into()
}
fn spec() -> ChainSpec {
    ChainSpec {
        block_info: Address::repeat_byte(0xab),
        ..ChainSpec::testnet()
    }
}
fn database(spec: &ChainSpec, head: bool) -> ProbeDb {
    let mut inner = InMemoryDB::default();
    // Explicit synthetic funding and committed-ring fixture, not L1 authentication.
    inner.insert_account_info(
        sender(),
        AccountInfo {
            balance: U256::from(10u64.pow(18)),
            ..Default::default()
        },
    );
    inner.insert_account_info(
        spec.block_info,
        AccountInfo {
            nonce: 1,
            ..Default::default()
        },
    );
    inner
        .insert_account_storage(spec.block_info, BLOCK_INFO_FLAG_SLOT, U256::from(head as u64))
        .unwrap();
    for (number, byte) in [(299, 0x29), (44, 0x44)] {
        inner
            .insert_account_storage(
                spec.block_info,
                block_hash_slot(number),
                U256::from_be_bytes(B256::repeat_byte(byte).0),
            )
            .unwrap();
    }
    ProbeDb {
        inner,
        reads: 0,
        blockhash_calls: 0,
        fail_slot: None,
    }
}
fn env(spec: &ChainSpec) -> EvmEnv {
    let mut cfg = CfgEnv::new_with_spec(spec.spec_id);
    cfg.chain_id = spec.chain_id;
    EvmEnv::new(
        cfg,
        BlockEnv {
            number: U256::from(300),
            timestamp: U256::from(1_000),
            basefee: spec.initial_base_fee,
            gas_limit: spec.gas_limit,
            beneficiary: spec.coinbase(),
            ..Default::default()
        },
    )
}
#[test]
fn committed_ring_window_and_inspector_use_original_database_without_warming() {
    let spec = spec();
    for (number, expected) in [(299, 0x29), (44, 0x44), (43, 0), (300, 0), (301, 0)] {
        let observed = Observed::default();
        let mut evm =
            BlochEvmFactory::new(&spec).create_evm_with_inspector(database(&spec, true), env(&spec), observed.clone());
        let authenticated = decode_signed_transaction(&spec, &tx(&spec, number)).unwrap();
        let result = evm.transact_raw(authenticated.environment().clone()).unwrap();
        assert!(result.result.is_success());
        assert_eq!(
            result.result.output().unwrap().as_ref(),
            B256::repeat_byte(expected).as_slice()
        );
        assert!(observed.0.get() >= 7);
        assert!(
            !result.state.contains_key(&spec.block_info),
            "raw reads must not warm journal account"
        );
        assert_eq!(evm.db().blockhash_calls, 0);
        assert_eq!(evm.db().reads, if number == 299 || number == 44 { 2 } else { 0 });
        // Same upstream opcode table and gas schedule, independent of hash source.
        let mut upstream = EthEvmFactory::default().create_evm(database(&spec, true), env(&spec));
        let reference = upstream.transact_raw(authenticated.environment().clone()).unwrap();
        assert_eq!(result.result.tx_gas_used(), reference.result.tx_gas_used());
    }
}
#[test]
fn absent_head_ignores_orphan_ring_and_database_errors_propagate() {
    let spec = spec();
    let authenticated = decode_signed_transaction(&spec, &tx(&spec, 299)).unwrap();
    let mut evm = BlochEvmFactory::new(&spec).create_evm(database(&spec, false), env(&spec));
    let result = evm.transact_raw(authenticated.environment().clone()).unwrap();
    assert_eq!(result.result.output().unwrap().as_ref(), B256::ZERO.as_slice());
    assert_eq!(evm.db().reads, 1);
    for slot in [BLOCK_INFO_FLAG_SLOT, block_hash_slot(299)] {
        let mut db = database(&spec, true);
        db.fail_slot = Some(slot);
        let mut evm = BlochEvmFactory::new(&spec).create_evm(db, env(&spec));
        let error = evm.transact_raw(authenticated.environment().clone()).unwrap_err();
        assert!(matches!(
            error,
            reth_revm::revm::context::result::EVMError::Database(Unavailable)
        ));
        assert_eq!(evm.db_mut().basic(sender()).unwrap().unwrap().nonce, 0);
        assert_eq!(evm.db().blockhash_calls, 0);
    }
}
