// SPDX-License-Identifier: MIT OR Apache-2.0
//! Supplied Alloy EVM/inspector qualification, not a BlockExecutorFactory or node.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{
    eth::{EthEvmContext, EthEvmFactory},
    Evm, EvmEnv, EvmFactory,
};
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
use bloch_l2_evm::{
    decode_signed_transaction, prepare_transaction_effects, ChainSpec, DepositMint, DepositProvenance, L2State,
};
use k256::ecdsa::SigningKey;
use reth_revm::revm::{
    context::{BlockEnv, CfgEnv},
    database::{states::bundle_state::BundleRetention, InMemoryDB, State},
    interpreter::Interpreter,
    Database, Inspector,
};
use std::{cell::Cell, rc::Rc};

#[derive(Clone, Default)]
struct Observed {
    steps: Rc<Cell<usize>>,
    executions: Rc<Cell<usize>>,
}
impl Inspector<EthEvmContext<State<InMemoryDB>>> for Observed {
    fn initialize_interp(&mut self, _: &mut Interpreter, _: &mut EthEvmContext<State<InMemoryDB>>) {
        self.executions.set(self.executions.get() + 1);
    }
    fn step(&mut self, _: &mut Interpreter, _: &mut EthEvmContext<State<InMemoryDB>>) {
        self.steps.set(self.steps.get() + 1);
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn signed(spec: &ChainSpec, code: &[u8]) -> Bytes {
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        nonce: 0,
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        to: TxKind::Create,
        value: U256::from(123),
        input: Bytes::copy_from_slice(code),
        ..Default::default()
    };
    let signature: Signature = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
}
fn funded(spec: &ChainSpec) -> InMemoryDB {
    // Explicitly synthetic provenance; this is a host execution fixture.
    let mut state = L2State::genesis(spec);
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
    state.db().clone()
}
fn env(spec: &ChainSpec) -> EvmEnv {
    let mut cfg = CfgEnv::new_with_spec(spec.spec_id);
    cfg.chain_id = spec.chain_id;
    EvmEnv::new(
        cfg,
        BlockEnv {
            number: U256::from(1),
            timestamp: U256::from(1),
            basefee: spec.initial_base_fee,
            gas_limit: spec.gas_limit,
            beneficiary: spec.coinbase(),
            ..Default::default()
        },
    )
}

#[test]
fn supplied_evm_inspector_and_state_share_prepare_drop_and_commit() {
    let spec = ChainSpec::testnet();
    let state = State::builder()
        .with_database(funded(&spec))
        .with_bundle_update()
        .build();
    let observed = Observed::default();
    let mut evm = EthEvmFactory::default().create_evm_with_inspector(state, env(&spec), observed.clone());
    let raw = signed(&spec, &[0x60, 42, 0x60, 0, 0x55, 0]);
    let tx = decode_signed_transaction(&spec, &raw).unwrap();
    let before = evm.db_mut().basic(sender()).unwrap().unwrap();
    let initial_vault = evm.db_mut().basic(spec.base_fee_vault).unwrap();
    let result = evm.transact_raw(tx.environment().clone()).unwrap();
    let prepared =
        prepare_transaction_effects(&spec, spec.initial_base_fee, tx.environment(), 0, result, evm.db_mut()).unwrap();
    assert!(prepared.outcome().success);
    drop(prepared);
    assert_eq!(evm.db_mut().basic(sender()).unwrap().unwrap(), before);
    assert_eq!(evm.db_mut().basic(spec.base_fee_vault).unwrap(), initial_vault);
    assert!(evm.db_mut().basic(sender().create(0)).unwrap().is_none());
    assert!(evm.db().bundle_state.state.is_empty());
    let result = evm.transact_raw(tx.environment().clone()).unwrap();
    let prepared =
        prepare_transaction_effects(&spec, spec.initial_base_fee, tx.environment(), 0, result, evm.db_mut()).unwrap();
    let committed = prepared.commit(evm.db_mut());
    assert_eq!(observed.executions.get(), 2);
    assert!(observed.steps.get() >= 8);
    assert_eq!(evm.db_mut().basic(sender()).unwrap().unwrap().nonce, 1);
    assert_eq!(
        evm.db_mut().basic(sender()).unwrap().unwrap().balance,
        before.balance - U256::from(123) - committed.base_fee_routed_wei - committed.priority_fee_routed_wei
    );
    assert_eq!(
        evm.db_mut().basic(spec.base_fee_vault).unwrap().unwrap().balance,
        committed.base_fee_routed_wei
    );
    assert_eq!(
        evm.db_mut().basic(spec.sequencer_fee_vault).unwrap().unwrap().balance,
        committed.priority_fee_routed_wei
    );
    assert_eq!(
        evm.db_mut().storage(sender().create(0), U256::ZERO).unwrap(),
        U256::from(42)
    );
    evm.db_mut().merge_transitions(BundleRetention::Reverts);
    assert_eq!(
        evm.db().bundle_state.state[&spec.base_fee_vault]
            .info
            .as_ref()
            .unwrap()
            .balance,
        committed.base_fee_routed_wei
    );
    assert_eq!(evm.db().bundle_state.state[&sender()].info.as_ref().unwrap().nonce, 1);
}

#[test]
fn supplied_state_preserves_vault_destruction_then_protocol_recreation() {
    let spec = ChainSpec {
        base_fee_vault: sender().create(0),
        ..ChainSpec::testnet()
    };
    spec.validate().unwrap();
    let mut backing = funded(&spec);
    // Synthetic prefunding and unread old storage, before the actual signed creation.
    backing.insert_account_info(
        spec.base_fee_vault,
        reth_revm::revm::state::AccountInfo {
            balance: U256::from(777),
            ..Default::default()
        },
    );
    backing
        .insert_account_storage(spec.base_fee_vault, U256::from(123), U256::from(456))
        .unwrap();
    let state = State::builder().with_database(backing).with_bundle_update().build();
    let observed = Observed::default();
    let mut evm = EthEvmFactory::default().create_evm_with_inspector(state, env(&spec), observed.clone());
    let tx = decode_signed_transaction(&spec, &signed(&spec, &[0x30, 0xff])).unwrap();
    let result = evm.transact_raw(tx.environment().clone()).unwrap();
    assert!(result.state[&spec.base_fee_vault].is_selfdestructed());
    let prepared =
        prepare_transaction_effects(&spec, spec.initial_base_fee, tx.environment(), 0, result, evm.db_mut()).unwrap();
    assert_eq!(prepared.outcome().burned_wei, U256::from(900));
    let committed = prepared.commit(evm.db_mut());
    assert_eq!(observed.executions.get(), 1);
    assert!(observed.steps.get() >= 2);
    assert_eq!(
        evm.db_mut().basic(spec.base_fee_vault).unwrap().unwrap().balance,
        committed.base_fee_routed_wei
    );
    assert_eq!(
        evm.db_mut().storage(spec.base_fee_vault, U256::from(123)).unwrap(),
        U256::ZERO
    );
    evm.db_mut().merge_transitions(BundleRetention::Reverts);
    let vault = &evm.db().bundle_state.state[&spec.base_fee_vault];
    assert!(vault.status.was_destroyed());
    assert_eq!(vault.info.as_ref().unwrap().balance, committed.base_fee_routed_wei);
    assert_eq!(vault.original_info.as_ref().unwrap().balance, U256::from(777));
}
