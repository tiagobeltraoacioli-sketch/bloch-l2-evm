// SPDX-License-Identifier: MIT OR Apache-2.0
//! Full protocol phases on the actual SDK EVM, compared with the portable kernel.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{Database, Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    chainspec::BEACON_ROOTS_ADDRESS,
    decode_signed_transaction, execute_signed_block, execute_signed_block_on_database,
    executor::lifecycle::{prepare_block_start, FinishedBlock},
    BlockContext, BlockInput, ChainSpec, DepositMint, DepositProvenance, L2State, SignedBlockInput,
};
use bloch_reth_execution::{execution_bundle, BlochContext, BlochEvmFactory};
use k256::ecdsa::SigningKey;
use reth_revm::revm::{
    context::{BlockEnv, CfgEnv},
    context_interface::block::BlobExcessGasAndPrice,
    database::{states::bundle_state::BundleRetention, OriginalValuesKnown, State},
    handler::system_call::SYSTEM_ADDRESS,
    interpreter::Interpreter,
    DatabaseCommit, Inspector,
};
use std::{cell::Cell, rc::Rc};

#[derive(Clone, Default)]
struct Observed(Rc<Cell<usize>>);
impl<DB: Database> Inspector<BlochContext<DB>> for Observed {
    fn step(&mut self, _: &mut Interpreter, _: &mut BlochContext<DB>) {
        self.0.set(self.0.get() + 1);
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn signed(spec: &ChainSpec, nonce: u64, to: TxKind, input: Bytes) -> Bytes {
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
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
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
fn deposit(index: u32, recipient: Address, sats: u64) -> DepositMint {
    DepositMint {
        recipient,
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: index,
            l1_txid: [index as u8 + 1; 32],
            l1_vout: 0,
            l1_sats: sats,
        },
    }
}

fn run_sdk<DB: Database + DatabaseCommit>(
    spec: &ChainSpec,
    database: DB,
    previous_root: B256,
    input: &BlockInput,
    observed: &Observed,
) -> (DB, FinishedBlock) {
    let mut evm =
        BlochEvmFactory::new(spec).create_evm_with_inspector(database, env(spec, &input.context), observed.clone());
    let pending = prepare_block_start(spec, evm.db_mut(), previous_root, input)
        .unwrap()
        .commit(evm.db_mut());
    let system = evm
        .transact_system_call(
            SYSTEM_ADDRESS,
            BEACON_ROOTS_ADDRESS,
            Bytes::copy_from_slice(input.context.anchor_root.as_slice()),
        )
        .unwrap();
    let mut block = pending.complete(system, evm.db_mut()).unwrap();
    block.validate_transaction(&input.txs[0]).unwrap();
    let steps = observed.0.get();
    // Skipping must preserve both the database and the accounting before retry.
    let result = evm.transact_raw(input.txs[0].clone()).unwrap();
    drop(block.prepare_transaction(&input.txs[0], result, evm.db_mut()).unwrap());
    let result = evm.transact_raw(input.txs[0].clone()).unwrap();
    block
        .prepare_transaction(&input.txs[0], result, evm.db_mut())
        .unwrap()
        .commit(evm.db_mut());
    assert!(observed.0.get() > steps);
    let finished = block.prepare_finish(evm.db_mut()).unwrap().commit(evm.db_mut());
    (evm.finish().0, finished)
}

#[test]
fn sdk_phases_match_signed_core_roots_headers_fees_storage_and_burns() {
    let spec = ChainSpec {
        block_info: Address::repeat_byte(0xab),
        ..ChainSpec::testnet()
    };
    let mut reference = L2State::genesis(&spec);
    let mut sdk = reference.clone();
    let observed = Observed::default();
    // Store calldata in slot zero, then return BLOCKHASH(1).
    let runtime = [
        0x60, 0, 0x35, 0x60, 0, 0x55, 0x60, 1, 0x40, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3,
    ];
    let length = runtime.len() as u8;
    let mut creation = vec![0x60, length, 0x60, 12, 0x60, 0, 0x39, 0x60, length, 0x60, 0, 0xf3];
    creation.extend_from_slice(&runtime);
    let transactions = [
        signed(&spec, 0, TxKind::Create, creation.into()),
        signed(
            &spec,
            1,
            TxKind::Call(sender().create(0)),
            U256::from(42).to_be_bytes::<32>().to_vec().into(),
        ),
        signed(&spec, 2, TxKind::Call(sender().create(0)), Bytes::new()),
        signed(&spec, 3, TxKind::Create, Bytes::from_static(&[0x30, 0xff])),
        signed(&spec, 4, TxKind::Create, Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd])),
    ];
    let mut first_hash = B256::ZERO;
    for (index, raw) in transactions.into_iter().enumerate() {
        let mut context = BlockContext::next(&spec, &reference);
        context.timestamp += 1;
        context.anchor_root = B256::repeat_byte(index as u8 + 1);
        let deposits = match index {
            0 => vec![deposit(0, sender(), 100_000_000)],
            3 => vec![deposit(1, sender().create(3), 3)],
            _ => vec![],
        };
        let authenticated = decode_signed_transaction(&spec, &raw).unwrap();
        let input = BlockInput {
            context: context.clone(),
            deposits: deposits.clone(),
            txs: vec![authenticated.environment().clone()],
        };
        let previous_root = sdk.commit_root();
        let signed_input = SignedBlockInput {
            context: context.clone(),
            deposits: deposits.clone(),
            transactions: vec![raw.clone()],
        };
        let portable = execute_signed_block_on_database(&spec, sdk.db(), previous_root, &signed_input).unwrap();
        let expected_bundle = execution_bundle(&portable).unwrap();
        let state = State::builder()
            .with_database(sdk.db().clone())
            .with_bundle_update()
            .build();
        let (mut state, state_finished) = run_sdk(&spec, state, previous_root, &input, &observed);
        state.merge_transitions(BundleRetention::Reverts);
        let mut actual_changes = state.bundle_state.to_plain_state(OriginalValuesKnown::Yes);
        let mut expected_changes = expected_bundle.to_plain_state(OriginalValuesKnown::Yes);
        actual_changes.accounts.sort_by_key(|entry| entry.0);
        expected_changes.accounts.sort_by_key(|entry| entry.0);
        actual_changes.storage.sort_by_key(|entry| entry.address);
        expected_changes.storage.sort_by_key(|entry| entry.address);
        for entry in actual_changes
            .storage
            .iter_mut()
            .chain(expected_changes.storage.iter_mut())
        {
            entry.storage.sort_by_key(|entry| entry.0);
        }
        actual_changes.contracts.sort_by_key(|entry| entry.0);
        expected_changes.contracts.sort_by_key(|entry| entry.0);
        assert_eq!(
            actual_changes.accounts, expected_changes.accounts,
            "State accounts block {index}"
        );
        assert_eq!(
            actual_changes.storage, expected_changes.storage,
            "State storage block {index}"
        );
        assert_eq!(
            actual_changes.contracts, expected_changes.contracts,
            "State code block {index}"
        );
        let (database, finished) = run_sdk(&spec, sdk.db().clone(), previous_root, &input, &observed);
        *sdk.db_mut() = database;
        let actual = finished.finalize(sdk.commit_root());
        assert_eq!(state_finished.finalize(sdk.commit_root()).header, actual.header);
        let expected = execute_signed_block(
            &spec,
            &mut reference,
            &SignedBlockInput {
                context,
                deposits,
                transactions: vec![raw],
            },
        )
        .unwrap();
        assert_eq!(actual.header, expected.header, "block {index}");
        assert_eq!(actual.minted_wei, expected.minted_wei);
        assert_eq!(actual.burned_wei, expected.burned_wei);
        assert_eq!(actual.base_fee_routed_wei, expected.base_fee_routed_wei);
        assert_eq!(actual.priority_fee_routed_wei, expected.priority_fee_routed_wei);
        assert_eq!(actual.tx_outcomes[0].result, expected.tx_outcomes[0].result);
        if index == 0 {
            first_hash = actual.block_hash;
        }
        if index == 1 || index == 2 {
            assert_eq!(
                actual.tx_outcomes[0].result.output().unwrap().as_ref(),
                first_hash.as_slice()
            );
        }
        if index == 3 {
            assert_eq!(actual.burned_wei, U256::from(30_000_000_000u64));
        }
        if index == 4 {
            assert!(!actual.tx_outcomes[0].success);
        }
    }
}
