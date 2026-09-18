// SPDX-License-Identifier: MIT OR Apache-2.0
//! Actual Reth configuration and assembly preserve the tagged V2 domain.
use alloy_consensus::{transaction::Recovered, SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_evm::{
    block::{BlockExecutor, BlockExecutorFactory},
    Evm, EvmFactory,
};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    node_execution::{execute_node_block, genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    ChainSpec, DepositMint, DepositProvenance,
};
use bloch_reth_execution::{BlochEvmConfig, BlochNextBlockEnvCtx, BlochNodeHeader, BlochRethTransaction};
use k256::ecdsa::SigningKey;
use reth_evm::{
    execute::{BlockAssembler, BlockAssemblerInput},
    ConfigureEvm,
};
use reth_primitives_traits::SealedHeader;
use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
use reth_revm::revm::{
    database::{states::bundle_state::BundleRetention, State},
    DatabaseRef,
};

fn domain() -> B256 {
    B256::repeat_byte(0x42)
}
fn attributes() -> BlochNextBlockEnvCtx {
    BlochNextBlockEnvCtx {
        timestamp: 11,
        prevrandao: B256::repeat_byte(3),
        anchor_root: B256::repeat_byte(4),
        deposits: vec![DepositMint {
            recipient: Address::from_public_key(SigningKey::from_bytes((&[7u8; 32]).into()).unwrap().verifying_key()),
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: 0,
                l1_txid: [1; 32],
                l1_vout: 0,
                l1_sats: 100_000_000,
            },
        }],
    }
}
#[test]
fn assembler_reads_actual_committed_bundle_and_preserves_deposits() {
    let spec = ChainSpec::testnet();
    let mut reference = genesis_v2(&spec, 10).unwrap();
    let config = BlochEvmConfig::new(&spec, domain());
    let parent = SealedHeader::seal_slow(BlochNodeHeader(node_head(&spec, domain(), &reference).unwrap()));
    let attributes = attributes();
    let env = config.next_evm_env(&parent, &attributes).unwrap();
    let context = config.context_for_next_block(&parent, attributes.clone()).unwrap();
    let provider: MockEthProvider = MockEthProvider::default();
    for (address, account) in &reference.db().cache.accounts {
        let info = &account.info;
        let mut entry = ExtendedAccount::new(info.nonce, info.balance)
            .extend_storage(account.storage.iter().map(|(key, value)| (B256::from(*key), *value)));
        if !info.is_empty_code_hash() {
            entry = entry.with_bytecode(
                reference
                    .db()
                    .code_by_hash_ref(info.code_hash)
                    .unwrap()
                    .original_bytes(),
            );
        }
        provider.add_account(*address, entry);
    }
    let database = State::builder()
        .with_database(reference.db().clone())
        .with_bundle_update()
        .build();
    let factory = config.block_executor_factory();
    let evm = factory.evm_factory().create_evm(database, env.clone());
    let mut executor = factory.create_executor(evm, context.clone());
    executor.apply_pre_execution_changes().unwrap();
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        to: TxKind::Create,
        input: Bytes::from_static(&[0x60, 0, 0x60, 0, 0xa0, 0]),
        ..Default::default()
    };
    let signature: Signature = SigningKey::from_bytes((&[7u8; 32]).into())
        .unwrap()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    let transaction: BlochRethTransaction = tx.into_signed(signature).into();
    let oversized: BlochRethTransaction = TxEip1559 {
        input: Bytes::from(vec![0; bloch_l2_evm::transactions::MAX_RAW_TRANSACTION_BYTES + 1]),
        ..Default::default()
    }
    .into_signed(Signature::new(U256::from(1), U256::from(1), false))
    .into();
    let unchanged = format!("{:?}", executor.evm().db().bundle_state);
    assert!(executor
        .execute_transaction_without_commit(Recovered::new_unchecked(oversized.clone(), Address::ZERO))
        .is_err());
    assert!(executor.receipts().is_empty());
    assert_eq!(format!("{:?}", executor.evm().db().bundle_state), unchanged);
    let skipped = executor
        .execute_transaction_without_commit(Recovered::new_unchecked(transaction.clone(), Address::ZERO))
        .unwrap();
    drop(skipped);
    let prepared = executor
        .execute_transaction_without_commit(Recovered::new_unchecked(transaction.clone(), Address::ZERO))
        .unwrap();
    executor.checked_commit_transaction(prepared).unwrap();
    assert_eq!(executor.receipts().len(), 1);
    let (evm, output, finished) = executor.finish_node().unwrap();
    let mut database = evm.finish().0;
    database.merge_transitions(BundleRetention::Reverts);
    let body = NodeBodyV2 {
        deposits: attributes.deposits,
        transactions: vec![transaction.encoded_2718().into()],
    };
    let expected = execute_node_block(&spec, domain(), &mut reference, &context.context, &body).unwrap();
    assert_eq!(finished.finalize(expected.header.state_root).header, expected.header);
    let assemble = |bundle: &_, output: &_, env: _, bal| {
        config.block_assembler().assemble_block(BlockAssemblerInput::new(
            env,
            context.clone(),
            &parent,
            vec![transaction.clone()],
            output,
            bundle,
            &provider,
            expected.header.state_root,
            bal,
        ))
    };
    assert!(config
        .block_assembler()
        .assemble_block(BlockAssemblerInput::new(
            env.clone(),
            context.clone(),
            &parent,
            vec![oversized],
            &output,
            &database.bundle_state,
            &provider,
            expected.header.state_root,
            None,
        ))
        .is_err());
    let block = assemble(&database.bundle_state, &output, env.clone(), None).unwrap();
    assert_eq!(block.header.0, expected.header);
    assert_eq!(block.body.as_core(), &body);
    let sealed = reth_primitives_traits::SealedBlock::seal_slow(block);
    let incoming = config.context_for_block(&sealed).unwrap();
    assert_eq!(incoming.previous_root, parent.0.state_root);
    assert_eq!(incoming.deposits, body.deposits);
    assert_eq!(config.evm_env(sealed.header()).unwrap().block_env, env.block_env);
    let mut wrong_env = env.clone();
    wrong_env.block_env.basefee += 1;
    assert!(assemble(&database.bundle_state, &output, wrong_env, None).is_err());
    assert!(assemble(&database.bundle_state, &output, env.clone(), Some(B256::ZERO)).is_err());
    let mut wrong_output = output.clone();
    wrong_output.gas_used += 1;
    assert!(assemble(&database.bundle_state, &wrong_output, env.clone(), None).is_err());
    wrong_output = output.clone();
    wrong_output.blob_gas_used = 1;
    assert!(assemble(&database.bundle_state, &wrong_output, env.clone(), None).is_err());
    let mut tampered = database.bundle_state.clone();
    tampered
        .state
        .get_mut(&spec.block_info)
        .unwrap()
        .storage
        .get_mut(&U256::from(1))
        .unwrap()
        .present_value = U256::from(99);
    assert!(assemble(&tampered, &output, env, None).is_err());
}
#[test]
fn configuration_rejects_wrong_domain_time_number_and_body_commitment() {
    let spec = ChainSpec::testnet();
    let state = genesis_v2(&spec, 10).unwrap();
    let config = BlochEvmConfig::new(&spec, domain());
    let header = BlochNodeHeader(node_head(&spec, domain(), &state).unwrap());
    assert!(BlochEvmConfig::new(&spec, B256::ZERO).evm_env(&header).is_err());
    let mut wrong = header.clone();
    wrong.0.domain = B256::repeat_byte(2);
    assert!(config.evm_env(&wrong).is_err());
    let mut attrs = attributes();
    attrs.timestamp = 9;
    assert!(config.next_evm_env(&header, &attrs).is_err());
    wrong = header.clone();
    wrong.0.number = u64::MAX;
    assert!(config.next_evm_env(&wrong, &attributes()).is_err());
    let body = bloch_reth_execution::BlochNodeBody::try_from_core(NodeBodyV2 {
        deposits: attributes().deposits,
        transactions: vec![],
    })
    .unwrap();
    let block = reth_primitives_traits::SealedBlock::seal_slow(bloch_reth_execution::BlochNodeBlock { header, body });
    assert!(config.context_for_block(&block).is_err());
}
