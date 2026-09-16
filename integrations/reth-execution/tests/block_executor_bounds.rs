// SPDX-License-Identifier: MIT OR Apache-2.0
//! Authentication and configuration bounds before original mutable DB access.
use alloy_consensus::{transaction::Recovered, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{
    block::{BlockExecutor, BlockExecutorFactory},
    Evm, EvmEnv, EvmFactory,
};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    transactions::{MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS},
    BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State,
};
use bloch_reth_execution::{BlochBlockExecutionCtx, BlochBlockExecutor, BlochBlockExecutorFactory, BlochEvmFactory};
use k256::ecdsa::SigningKey;
use reth_revm::revm::{
    context::{BlockEnv, CfgEnv},
    context_interface::block::BlobExcessGasAndPrice,
    database::InMemoryDB,
    inspector::NoOpInspector,
    state::{AccountInfo, Bytecode, EvmState},
    Database, DatabaseCommit,
};
use std::convert::Infallible;

#[derive(Debug)]
struct Probe {
    inner: InMemoryDB,
    reads: usize,
    commits: usize,
}
impl Database for Probe {
    type Error = Infallible;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.reads += 1;
        self.inner.basic(address)
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        self.reads += 1;
        self.inner.code_by_hash(hash)
    }
    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.reads += 1;
        self.inner.storage(address, slot)
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.reads += 1;
        self.inner.block_hash(number)
    }
}
impl DatabaseCommit for Probe {
    fn commit(&mut self, state: EvmState) {
        self.commits += 1;
        self.inner.commit(state)
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn tx(chain_id: u64, size: usize) -> Recovered<TxEnvelope> {
    let tx = TxEip1559 {
        chain_id,
        nonce: 0,
        to: TxKind::Call(Address::repeat_byte(27)),
        input: Bytes::from(vec![1; size]),
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        ..Default::default()
    };
    let signature: Signature = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    Recovered::new_unchecked(tx.into_signed(signature).into(), sender())
}
fn fixture(spec: &ChainSpec) -> (Probe, BlochBlockExecutionCtx) {
    let mut state = L2State::genesis(spec);
    // Synthetic host funding, not a deposit-authentication claim.
    state
        .deposit_mint(
            spec,
            &DepositMint {
                recipient: sender(),
                provenance: DepositProvenance::BridgedBlch {
                    l1_height: 1,
                    l1_tx_index: 0,
                    l1_txid: [1; 32],
                    l1_vout: 0,
                    l1_sats: 100_000_000,
                },
            },
        )
        .unwrap();
    let context = BlochBlockExecutionCtx {
        previous_root: state.commit_root(),
        context: BlockContext::next(spec, &state),
        deposits: Vec::new(),
    };
    (
        Probe {
            inner: state.db().clone(),
            reads: 0,
            commits: 0,
        },
        context,
    )
}
fn env(spec: &ChainSpec, context: &BlockContext) -> EvmEnv {
    let mut cfg = CfgEnv::new_with_spec(spec.spec_id);
    cfg.chain_id = spec.chain_id;
    EvmEnv::new(
        cfg,
        BlockEnv {
            number: U256::from(context.number),
            timestamp: U256::from(context.timestamp),
            basefee: context.base_fee_per_gas,
            gas_limit: spec.gas_limit,
            beneficiary: spec.coinbase(),
            prevrandao: Some(context.prevrandao),
            blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new_with_spec(0, spec.spec_id)),
            ..Default::default()
        },
    )
}
fn executor(spec: &ChainSpec) -> BlochBlockExecutor<Probe, NoOpInspector> {
    let (db, context) = fixture(spec);
    let factory = BlochBlockExecutorFactory::new(spec);
    let evm = factory.evm_factory().create_evm(db, env(spec, &context.context));
    let mut executor = factory.create_executor(evm, context);
    executor.apply_pre_execution_changes().unwrap();
    executor
}
fn rejection(executor: &mut BlochBlockExecutor<Probe, NoOpInspector>, tx: &Recovered<TxEnvelope>) -> String {
    match executor.execute_transaction_without_commit(tx) {
        Ok(_) => panic!("candidate unexpectedly accepted"),
        Err(error) => error.to_string(),
    }
}
#[test]
fn attempt_cap_counts_rejected_and_discarded_candidates_but_not_oversized_preflight() {
    let spec = ChainSpec::testnet();
    let mut executor = executor(&spec);
    let bad = tx(spec.chain_id + 1, 0);
    let oversized = tx(spec.chain_id, MAX_RAW_TRANSACTION_BYTES);
    let valid = tx(spec.chain_id, 0);
    let reads = executor.evm().db().reads;
    let commits = executor.evm().db().commits;
    for _ in 0..=MAX_SIGNED_TRANSACTIONS {
        assert!(rejection(&mut executor, &oversized).contains("too large"));
    }
    for _ in 0..MAX_SIGNED_TRANSACTIONS - 1 {
        let error = rejection(&mut executor, &bad);
        assert!(!error.contains("attempt limit"), "{error}");
    }
    assert_eq!(
        executor.evm().db().reads,
        reads,
        "rejected signatures never consult original DB"
    );
    assert_eq!(executor.evm().db().commits, commits);
    let prepared = executor.execute_transaction_without_commit(&valid).unwrap();
    drop(prepared);
    let after_discard = executor.evm().db().reads;
    assert!(rejection(&mut executor, &valid).contains("attempt limit"));
    assert_eq!(executor.evm().db().reads, after_discard);
    assert_eq!(executor.evm().db().commits, commits);
    assert!(executor.receipts().is_empty());
    assert_eq!(executor.evm().db().inner.cache.accounts[&sender()].info.nonce, 0);
    assert!(
        executor.finish().is_ok(),
        "candidate rejection does not poison a valid empty block"
    );
}
#[test]
fn byte_budget_charges_wrong_chain_candidates_and_rejects_before_database_access() {
    let spec = ChainSpec::testnet();
    let mut executor = executor(&spec);
    let bad = tx(spec.chain_id + 1, 64 * 1024);
    let length = bad.inner().encode_2718_len();
    assert!(length < MAX_RAW_TRANSACTION_BYTES);
    let attempts = MAX_SIGNED_BLOCK_BYTES / length;
    assert!(attempts < MAX_SIGNED_TRANSACTIONS);
    let reads = executor.evm().db().reads;
    let commits = executor.evm().db().commits;
    for _ in 0..attempts {
        let error = rejection(&mut executor, &bad);
        assert!(!error.contains("byte budget"), "{error}");
    }
    assert!(rejection(&mut executor, &bad).contains("byte budget"));
    assert_eq!(executor.evm().db().reads, reads);
    assert_eq!(executor.evm().db().commits, commits);
    // A size-budget preflight rejection does not consume the unused remainder.
    let valid = tx(spec.chain_id, 0);
    assert!(valid.inner().encode_2718_len() <= MAX_SIGNED_BLOCK_BYTES - attempts * length);
    let prepared = executor.execute_transaction_without_commit(&valid).unwrap();
    executor.checked_commit_transaction(prepared).unwrap();
    assert_eq!(executor.receipts().len(), 1);
    assert_eq!(executor.evm().db().inner.cache.accounts[&sender()].info.nonce, 1);
}
#[test]
fn cfg_validation_toggles_and_wrong_block_info_fail_before_any_database_read() {
    let spec = ChainSpec::testnet();
    let factory = BlochBlockExecutorFactory::new(&spec);
    for mode in 0..3 {
        let (db, context) = fixture(&spec);
        let mut environment = env(&spec, &context.context);
        let mut actual_spec = spec.clone();
        match mode {
            0 => environment.cfg_env.disable_nonce_check = true,
            1 => environment.cfg_env.tx_chain_id_check = false,
            _ => actual_spec.block_info = Address::repeat_byte(0xab),
        }
        let evm = BlochEvmFactory::new(&actual_spec).create_evm(db, environment);
        let mut executor = factory.create_executor(evm, context);
        assert!(executor.apply_pre_execution_changes().is_err());
        assert_eq!(executor.evm().db().reads, 0);
        assert_eq!(executor.evm().db().commits, 0);
        assert!(executor.finish().is_err());
    }
}
