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
    execute_signed_block, BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State, SignedBlockInput,
};
use bloch_reth_execution::{BlochBlockExecutionCtx, BlochBlockExecutorFactory, BlochContext, BlochTxResult};
use k256::ecdsa::SigningKey;
use reth_revm::revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    database::InMemoryDB,
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
fn funded(spec: &ChainSpec) -> L2State {
    let mut state = L2State::genesis(spec);
    state.deposit_mint(spec, &deposit(0)).unwrap();
    state
}
fn root(db: &InMemoryDB) -> B256 {
    let mut state = L2State::new();
    *state.db_mut() = db.clone();
    state.commit_root()
}
fn ctx(spec: &ChainSpec, state: &mut L2State) -> BlochBlockExecutionCtx {
    BlochBlockExecutionCtx {
        previous_root: state.commit_root(),
        context: BlockContext::next(spec, state),
        deposits: vec![],
    }
}

#[test]
fn sdk_factory_receipts_and_multiblock_state_match_signed_kernel() {
    fn assert_send<T: Send + 'static>() {}
    assert_send::<BlochTxResult>();
    let spec = ChainSpec::testnet();
    let factory = BlochBlockExecutorFactory::new(&spec);
    let observed = Observed::default();
    let mut reference = L2State::genesis(&spec);
    let mut actual_state = reference.clone();
    let runtime = [
        0x60, 0, 0x35, 0x60, 0, 0x55, 0x60, 1, 0x40, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3,
    ];
    let len = runtime.len() as u8;
    let mut code = vec![0x60, len, 0x60, 12, 0x60, 0, 0x39, 0x60, len, 0x60, 0, 0xf3];
    code.extend(runtime);
    let blocks = [
        vec![
            tx(&spec, 0, TxKind::Create, code.into()),
            tx(
                &spec,
                1,
                TxKind::Create,
                Bytes::from_static(&[0x60, 0, 0x60, 0, 0xa0, 0]),
            ),
        ],
        vec![
            tx(
                &spec,
                2,
                TxKind::Call(sender().create(0)),
                U256::from(42).to_be_bytes::<32>().to_vec().into(),
            ),
            tx(&spec, 3, TxKind::Create, Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd])),
        ],
        vec![],
    ];
    for (index, txs) in blocks.into_iter().enumerate() {
        let mut context = BlockContext::next(&spec, &reference);
        context.timestamp += 1;
        context.anchor_root = B256::repeat_byte(index as u8 + 1);
        let deposits = if index == 0 {
            vec![deposit(0)]
        } else if index == 2 {
            vec![deposit(1)]
        } else {
            vec![]
        };
        let input = SignedBlockInput {
            context: context.clone(),
            deposits: deposits.clone(),
            transactions: txs.iter().map(|tx| tx.encoded_2718().into()).collect(),
        };
        let previous_root = actual_state.commit_root();
        let evm = factory.evm_factory().create_evm_with_inspector(
            actual_state.db().clone(),
            env(&spec, &context),
            observed.clone(),
        );
        let mut executor = factory.create_executor(
            evm,
            BlochBlockExecutionCtx {
                previous_root,
                context,
                deposits,
            },
        );
        executor.apply_pre_execution_changes().unwrap();
        for tx in txs {
            let skipped = executor
                .execute_transaction_without_commit(recovered(tx.clone()))
                .unwrap();
            assert!(skipped.result().result.tx_gas_used() > 0);
            drop(skipped);
            // A malicious prebuilt TxEnv must not override authenticated signed fields.
            let forged = TxEnv {
                caller: Address::repeat_byte(0xdd),
                nonce: 999,
                ..Default::default()
            };
            let prepared = executor
                .execute_transaction_without_commit((forged, recovered(tx)))
                .unwrap();
            executor.checked_commit_transaction(prepared).unwrap();
        }
        let (evm, sdk_result, finished) = executor.finish_bloch().unwrap();
        *actual_state.db_mut() = evm.finish().0;
        let actual = finished.finalize(actual_state.commit_root());
        let expected = execute_signed_block(&spec, &mut reference, &input).unwrap();
        assert_eq!(actual.header, expected.header);
        assert_eq!(sdk_result.gas_used, expected.gas_used);
        assert_eq!(sdk_result.blob_gas_used, 0);
        assert!(sdk_result.requests.is_empty());
        assert_eq!(sdk_result.receipts.len(), expected.tx_outcomes.len());
        let mut user_gas = 0;
        for (receipt, outcome) in sdk_result.receipts.iter().zip(&expected.tx_outcomes) {
            user_gas += outcome.gas_used;
            assert_eq!(receipt.cumulative_gas_used(), user_gas);
            assert_eq!(receipt.status(), outcome.success);
            assert_eq!(receipt.logs(), outcome.result.logs());
        }
        assert_eq!(
            sdk_result.gas_used,
            user_gas + spec.deposit_gas * input.deposits.len() as u64
        );
    }
    assert!(observed.0.get() > 0);
}

#[test]
fn stale_foreign_and_mutable_access_tokens_cannot_commit() {
    let spec = ChainSpec::testnet();
    let factory = BlochBlockExecutorFactory::new(&spec);
    let mut state = funded(&spec);
    let context = ctx(&spec, &mut state);
    let candidate = tx(&spec, 0, TxKind::Call(Address::repeat_byte(0x22)), Bytes::new());
    for mode in 0..3 {
        let evm = factory
            .evm_factory()
            .create_evm(state.db().clone(), env(&spec, &context.context));
        let mut executor = factory.create_executor(evm, context.clone());
        executor.apply_pre_execution_changes().unwrap();
        let pending = executor
            .execute_transaction_without_commit(recovered(candidate.clone()))
            .unwrap();
        match mode {
            0 => {
                let newer = executor
                    .execute_transaction_without_commit(recovered(candidate.clone()))
                    .unwrap();
                executor.checked_commit_transaction(newer).unwrap();
                assert!(executor.checked_commit_transaction(pending).is_err());
                assert_eq!(executor.receipts().len(), 1);
            }
            1 => {
                let evm = factory
                    .evm_factory()
                    .create_evm(state.db().clone(), env(&spec, &context.context));
                let mut foreign = factory.create_executor(evm, context.clone());
                foreign.apply_pre_execution_changes().unwrap();
                assert!(foreign.checked_commit_transaction(pending).is_err());
                assert!(foreign.receipts().is_empty());
                assert!(foreign.finish().is_err());
                assert!(executor.finish().is_ok());
                continue;
            }
            _ => {
                let _ = executor.evm_mut();
                assert_eq!(executor.commit_transaction(pending).tx_gas_used(), 0);
                assert!(executor.receipts().is_empty());
            }
        }
        assert!(executor
            .execute_transaction_without_commit(recovered(candidate.clone()))
            .is_err());
        assert!(executor.finish().is_err());
    }
}

#[test]
fn wrong_environment_and_duplicate_prefix_fail_before_extra_writes() {
    let spec = ChainSpec::testnet();
    let factory = BlochBlockExecutorFactory::new(&spec);
    let mut state = funded(&spec);
    let context = ctx(&spec, &mut state);
    let mut environment = env(&spec, &context.context);
    environment.block_env.beneficiary = Address::ZERO;
    let evm = factory.evm_factory().create_evm(state.db().clone(), environment);
    let mut executor = factory.create_executor(evm, context.clone());
    assert!(executor.apply_pre_execution_changes().is_err());
    assert_eq!(root(executor.evm().db()), root(state.db()));
    assert!(executor.finish().is_err());
    let evm = factory
        .evm_factory()
        .create_evm(state.db().clone(), env(&spec, &context.context));
    let mut executor = factory.create_executor(evm, context);
    executor.apply_pre_execution_changes().unwrap();
    let before = root(executor.evm().db());
    assert!(executor.apply_pre_execution_changes().is_err());
    assert_eq!(root(executor.evm().db()), before);
    assert!(executor.finish().is_err());
}

#[test]
fn blockhash_snapshot_survives_contract_mutation_of_live_ring() {
    let spec = ChainSpec {
        block_info: sender().create(0),
        ..ChainSpec::testnet()
    };
    spec.validate().unwrap();
    let factory = BlochBlockExecutorFactory::new(&spec);
    let mut state = funded(&spec);
    let context = ctx(&spec, &mut state);
    let mut reference = state.clone();
    // A valid deployment at the initially absent block-info address writes
    // flag=1 and ring[0]=0x1234. The second transaction must still see the
    // pre-transaction window (zero for this first block), just like the core.
    let runtime = [0x60, 0, 0x40, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3];
    let mut code = vec![0x60, 1, 0x60, 0, 0x55, 0x61, 0x12, 0x34, 0x61, 1, 0, 0x55];
    let len = runtime.len() as u8;
    code.extend([0x60, len, 0x60, 24, 0x60, 0, 0x39, 0x60, len, 0x60, 0, 0xf3]);
    code.extend(runtime);
    let transactions = vec![
        tx(&spec, 0, TxKind::Create, code.into()),
        tx(&spec, 1, TxKind::Call(spec.block_info), Bytes::new()),
    ];
    let input = SignedBlockInput {
        context: context.context.clone(),
        deposits: vec![],
        transactions: transactions.iter().map(|tx| tx.encoded_2718().into()).collect(),
    };
    let evm = factory
        .evm_factory()
        .create_evm(state.db().clone(), env(&spec, &context.context));
    let mut executor = factory.create_executor(evm, context);
    executor.apply_pre_execution_changes().unwrap();
    for (index, tx) in transactions.into_iter().enumerate() {
        let result = executor.execute_transaction_without_commit(recovered(tx)).unwrap();
        if index == 1 {
            assert_eq!(result.result().result.output().unwrap().as_ref(), B256::ZERO.as_slice());
        }
        executor.checked_commit_transaction(result).unwrap();
    }
    let (evm, _, finished) = executor.finish_bloch().unwrap();
    *state.db_mut() = evm.finish().0;
    let actual = finished.finalize(state.commit_root());
    let expected = execute_signed_block(&spec, &mut reference, &input).unwrap();
    assert_eq!(actual.header, expected.header);
    assert_eq!(actual.tx_outcomes[1].result, expected.tx_outcomes[1].result);
}

#[test]
fn executor_restores_canonical_precompiles_before_candidates() {
    let spec = ChainSpec::testnet();
    let factory = BlochBlockExecutorFactory::new(&spec);
    let mut state = funded(&spec);
    let context = ctx(&spec, &mut state);
    let identity = Address::with_last_byte(4);
    let data = Bytes::from_static(b"canonical identity precompile");
    let mut evm = factory
        .evm_factory()
        .create_evm(state.db().clone(), env(&spec, &context.context));
    evm.components_mut().2.apply_precompile(&identity, |_| None);
    let mut executor = factory.create_executor(evm, context);
    executor.apply_pre_execution_changes().unwrap();
    executor
        .evm_mut()
        .components_mut()
        .2
        .apply_precompile(&identity, |_| None);
    let result = executor
        .execute_transaction_without_commit(recovered(tx(&spec, 0, TxKind::Call(identity), data.clone())))
        .unwrap();
    assert_eq!(result.result().result.output().unwrap(), &data);
    executor.checked_commit_transaction(result).unwrap();
    assert!(executor.finish().is_ok());
}
