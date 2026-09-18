// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual SDK executor traits, signed ingress, receipts and commit-token isolation.
use alloy_consensus::{transaction::Recovered, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{
    block::{BlockExecutor, BlockExecutorFactory, TxResult},
    Evm, EvmEnv, EvmFactory,
};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, node_head, verify_node_batch},
    node_primitives::NodeBodyV2,
    BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State,
};
use bloch_reth_execution::{BlochBlockExecutionCtx, BlochContext, BlochNodeBlockExecutorFactory};
use k256::ecdsa::SigningKey;
use reth_revm::revm::{
    context::{BlockEnv, CfgEnv},
    context_interface::block::BlobExcessGasAndPrice,
    interpreter::Interpreter,
    Database, Inspector,
};
use std::{cell::Cell, rc::Rc};

#[derive(Clone, Default)]
struct Observed(Rc<Cell<usize>>);
impl<DB: Database> Inspector<BlochContext<DB>> for Observed {
    fn step(&mut self, _: &mut Interpreter, _: &mut BlochContext<DB>) {
        self.0.set(self.0.get() + 1);
    }
}
fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn tx(spec: &ChainSpec, nonce: u64, to: TxKind, input: Bytes) -> TxEnvelope {
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to,
        input,
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        ..Default::default()
    };
    let signature: Signature = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    tx.into_signed(signature).into()
}
fn recovered(tx: TxEnvelope) -> Recovered<TxEnvelope> {
    // Deliberately false pool recovery: the executor must authenticate the envelope.
    Recovered::new_unchecked(tx, Address::repeat_byte(0xcc))
}
fn deposit(index: u32) -> DepositMint {
    DepositMint {
        recipient: sender(),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: index,
            l1_txid: [index as u8 + 1; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    }
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

fn domain() -> B256 {
    B256::repeat_byte(0x42)
}
fn context(spec: &ChainSpec, state: &L2State) -> BlockContext {
    let parent = node_head(spec, domain(), state).unwrap();
    BlockContext {
        number: parent.number + 1,
        timestamp: parent.timestamp + 1,
        base_fee_per_gas: spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
        prevrandao: B256::repeat_byte(1),
        anchor_root: B256::repeat_byte(2),
    }
}
#[test]
fn supplied_v2_evm_matches_core_witness_logs_revert_and_blockhash() {
    let spec = ChainSpec::testnet();
    let factory = BlochNodeBlockExecutorFactory::new(&spec, domain());
    let observed = Observed::default();
    let mut actual_state = genesis_v2(&spec, 10).unwrap();
    let mut reference = actual_state.clone();
    // Runtime emits LOG1(topic42), then returns BLOCKHASH(NUMBER-1).
    let runtime = [
        0x60, 42, 0x60, 0, 0x60, 0, 0xa1, 0x60, 1, 0x43, 0x03, 0x40, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3,
    ];
    let len = runtime.len() as u8;
    let mut code = vec![0x60, len, 0x60, 12, 0x60, 0, 0x39, 0x60, len, 0x60, 0, 0xf3];
    code.extend(runtime);
    let blocks = [
        vec![tx(&spec, 0, TxKind::Create, code.into())],
        vec![
            tx(&spec, 1, TxKind::Call(sender().create(0)), Bytes::new()),
            tx(&spec, 2, TxKind::Create, Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd])),
        ],
        vec![],
    ];
    for (index, transactions) in blocks.into_iter().enumerate() {
        let parent = node_head(&spec, domain(), &reference).unwrap();
        let context = context(&spec, &reference);
        let deposits = if index == 0 { vec![deposit(0)] } else { vec![] };
        let body = NodeBodyV2 {
            deposits: deposits.clone(),
            transactions: transactions.iter().map(|tx| tx.encoded_2718().into()).collect(),
        };
        let (witness, recorded) = generate_node_batch_witness(&reference, &spec, domain(), &context, &body).unwrap();
        let verified = verify_node_batch(&spec, domain(), &witness, &context, &body).unwrap();
        let evm = factory.evm_factory().create_evm_with_inspector(
            actual_state.db().clone(),
            env(&spec, &context),
            observed.clone(),
        );
        let mut executor = factory.create_executor(
            evm,
            BlochBlockExecutionCtx {
                previous_root: actual_state.commit_root(),
                context: context.clone(),
                deposits,
            },
        );
        executor.apply_pre_execution_changes().unwrap();
        if index == 0 {
            let different = tx(&spec, 0, TxKind::Call(Address::repeat_byte(99)), Bytes::new());
            assert_ne!(different.encoded_2718(), body.transactions[0].as_ref());
            drop(
                executor
                    .execute_transaction_without_commit(recovered(different))
                    .unwrap(),
            );
        }
        for transaction in transactions {
            let skipped = executor
                .execute_transaction_without_commit(recovered(transaction.clone()))
                .unwrap();
            assert!(skipped.result().result.tx_gas_used() > 0);
            drop(skipped);
            let prepared = executor
                .execute_transaction_without_commit(recovered(transaction))
                .unwrap();
            executor.checked_commit_transaction(prepared).unwrap();
        }
        let (evm, sdk, finished) = executor.finish_node().unwrap();
        *actual_state.db_mut() = evm.finish().0;
        let actual = finished.finalize(actual_state.commit_root());
        let expected = execute_node_block(&spec, domain(), &mut reference, &context, &body).unwrap();
        for result in [&expected, &recorded, &verified] {
            assert_eq!(actual.header, result.header);
            assert_eq!(actual.receipts, result.receipts);
        }
        assert_eq!(sdk.receipts, actual.receipts);
        assert_eq!(sdk.gas_used, actual.header.gas_used);
        assert_eq!(actual.header.transactions_root, body.transactions_root());
        actual
            .header
            .validate_commitments(&spec, domain(), &body, &actual.receipts)
            .unwrap();
        actual.header.validate_parent(&spec, &parent).unwrap();
        if index == 1 {
            assert!(!actual.transactions[1].success);
            assert_ne!(actual.header.logs_bloom, alloy_primitives::Bloom::ZERO);
            assert_eq!(
                actual.transactions[0].result.output().unwrap().as_ref(),
                parent.hash().as_slice()
            );
        }
    }
    assert!(observed.0.get() > 0);
}
#[test]
fn stale_v2_candidates_poison_and_invalid_prefixes_do_not_write() {
    let spec = ChainSpec::testnet();
    let mut state = genesis_v2(&spec, 10).unwrap();
    let context = context(&spec, &state);
    let root = state.commit_root();
    for (domain, initial) in [(B256::ZERO, state.clone()), (domain(), L2State::genesis(&spec))] {
        let factory = BlochNodeBlockExecutorFactory::new(&spec, domain);
        let evm = factory.evm_factory().create_evm_with_inspector(
            initial.db().clone(),
            env(&spec, &context),
            Observed::default(),
        );
        let mut executor = factory.create_executor(
            evm,
            BlochBlockExecutionCtx {
                previous_root: initial.state_root(),
                context: context.clone(),
                deposits: vec![],
            },
        );
        assert!(executor.apply_pre_execution_changes().is_err());
        let mut unchanged = L2State::new();
        *unchanged.db_mut() = executor.evm().db().clone();
        assert_eq!(unchanged.commit_root(), initial.state_root());
        assert!(executor.finish_node().is_err());
    }
    let factory = BlochNodeBlockExecutorFactory::new(&spec, domain());
    let evm =
        factory
            .evm_factory()
            .create_evm_with_inspector(state.db().clone(), env(&spec, &context), Observed::default());
    let mut executor = factory.create_executor(
        evm,
        BlochBlockExecutionCtx {
            previous_root: root,
            context,
            deposits: vec![deposit(0)],
        },
    );
    executor.apply_pre_execution_changes().unwrap();
    let candidate = executor
        .execute_transaction_without_commit(recovered(tx(
            &spec,
            0,
            TxKind::Call(Address::repeat_byte(22)),
            Bytes::new(),
        )))
        .unwrap();
    let _ = executor.evm_mut();
    assert!(executor.checked_commit_transaction(candidate).is_err());
    assert!(executor.receipts().is_empty());
    assert!(executor.finish_node().is_err());
}

#[test]
fn trait_finish_commits_v2_metadata_into_actual_state_bundle() {
    use reth_revm::revm::database::{states::bundle_state::BundleRetention, OriginalValuesKnown, State};
    let spec = ChainSpec::testnet();
    let mut reference = genesis_v2(&spec, 10).unwrap();
    let mut materialized = reference.clone();
    let context = context(&spec, &reference);
    let factory = BlochNodeBlockExecutorFactory::new(&spec, domain());
    let transaction = tx(
        &spec,
        0,
        TxKind::Create,
        Bytes::from_static(&[0x60, 0, 0x60, 0, 0xa0, 0]),
    );
    let body = NodeBodyV2 {
        deposits: vec![deposit(0)],
        transactions: vec![transaction.encoded_2718().into()],
    };
    let database = State::builder()
        .with_database(reference.db().clone())
        .with_bundle_update()
        .build();
    let observed = Observed::default();
    let evm = factory
        .evm_factory()
        .create_evm_with_inspector(database, env(&spec, &context), observed.clone());
    let mut executor = factory.create_executor(
        evm,
        BlochBlockExecutionCtx {
            previous_root: reference.commit_root(),
            context: context.clone(),
            deposits: body.deposits.clone(),
        },
    );
    executor.apply_pre_execution_changes().unwrap();
    let candidate = executor
        .execute_transaction_without_commit(recovered(transaction))
        .unwrap();
    executor.checked_commit_transaction(candidate).unwrap();
    let (evm, sdk) = BlockExecutor::finish(executor).unwrap();
    let mut database = evm.finish().0;
    database.merge_transitions(BundleRetention::Reverts);
    let (changes, reverts) = database
        .bundle_state
        .to_plain_state_and_reverts(OriginalValuesKnown::Yes);
    assert!(!reverts.accounts.is_empty());
    assert!(changes.storage.iter().any(|entry| entry.address == spec.block_info));
    for (address, info) in changes.accounts {
        match info {
            Some(info) => materialized.db_mut().insert_account_info(address, info),
            None => {
                materialized.db_mut().cache.accounts.remove(&address);
            }
        }
    }
    for change in changes.storage {
        if change.wipe_storage {
            if let Some(account) = materialized.db_mut().cache.accounts.get_mut(&change.address) {
                account.storage.clear();
            }
        }
        for (slot, value) in change.storage {
            materialized
                .db_mut()
                .insert_account_storage(change.address, slot, value)
                .unwrap();
        }
    }
    materialized.db_mut().cache.contracts.extend(changes.contracts);
    let expected = execute_node_block(&spec, domain(), &mut reference, &context, &body).unwrap();
    assert_eq!(materialized.commit_root(), expected.header.state_root);
    assert_eq!(node_head(&spec, domain(), &materialized).unwrap(), expected.header);
    assert_eq!(sdk.receipts, expected.receipts);
    assert_eq!(sdk.gas_used, expected.header.gas_used);
    assert!(observed.0.get() > 0);
}
