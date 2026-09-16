// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signed incremental construction must equal the whole-block verifier.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
use bloch_l2_evm::{
    execute_signed_block, stateroot::compute_keccak_mpt_state_root, BlockContext, ChainSpec, DepositMint,
    DepositProvenance, L2State, SignedBlockBuilder, SignedInputError, TransactionAuthError,
};
use k256::ecdsa::SigningKey;
use revm::{database::CacheDB, DatabaseRef};
use std::collections::BTreeSet;

fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn sign(spec: &ChainSpec, nonce: u64, to: TxKind, input: Bytes) -> Bytes {
    sign_with_gas(spec, nonce, to, input, 200_000)
}
fn sign_with_gas(spec: &ChainSpec, nonce: u64, to: TxKind, input: Bytes, gas_limit: u64) -> Bytes {
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to,
        input,
        gas_limit,
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

#[test]
fn skipped_destruction_preserves_backing_storage_and_burn_accounting() {
    let spec = ChainSpec::default();
    let mut initial = L2State::genesis(&spec);
    initial.deposit_mint(&spec, &deposit()).unwrap();
    let doomed = sender().create(0);
    let mut prefund = deposit();
    prefund.recipient = doomed;
    prefund.provenance = DepositProvenance::BridgedBlch {
        l1_height: 1,
        l1_tx_index: 1,
        l1_txid: [2; 32],
        l1_vout: 0,
        l1_sats: 3,
    };
    initial.deposit_mint(&spec, &prefund).unwrap();
    initial
        .db_mut()
        .insert_account_storage(doomed, U256::from(123), U256::from(456))
        .unwrap();
    let root = initial.commit_root();
    let mut builder =
        SignedBlockBuilder::new(&spec, initial.db(), root, BlockContext::next(&spec, &initial), vec![]).unwrap();
    let destroy = sign(&spec, 0, TxKind::Create, Bytes::from_static(&[0x30, 0xff]));
    assert!(builder
        .try_push_with_condition(&destroy, |outcome| {
            assert_eq!(outcome.burned_wei, U256::from(30_000_000_000u64));
            false
        })
        .unwrap()
        .is_none());
    assert_eq!(
        initial.db().storage_ref(doomed, U256::from(123)).unwrap(),
        U256::from(456)
    );
    assert!(builder.try_push(&destroy).unwrap().success);
    let (input, pending) = builder.finish().unwrap();
    let built = materialize(pending.overlay(), &initial);
    assert!(built.account(&doomed).is_none());
    let (_, actual) = pending.finalize(compute_keccak_mpt_state_root(&built));
    let expected = execute_signed_block(&spec, &mut initial, &input).unwrap();
    assert_eq!(actual.header, expected.header);
    assert_eq!(actual.burned_wei, U256::from(30_000_000_000u64));
}

#[test]
fn gas_rejection_can_be_followed_by_a_smaller_valid_candidate() {
    let spec = ChainSpec {
        gas_limit: 200_000,
        ..Default::default()
    };
    let mut initial = L2State::genesis(&spec);
    initial.deposit_mint(&spec, &deposit()).unwrap();
    let root = initial.commit_root();
    let mut builder =
        SignedBlockBuilder::new(&spec, initial.db(), root, BlockContext::next(&spec, &initial), vec![]).unwrap();
    let recipient = Address::repeat_byte(22);
    let first = sign(&spec, 0, TxKind::Call(recipient), Bytes::new());
    builder.try_push(&first).unwrap();
    let too_large = sign(&spec, 1, TxKind::Call(recipient), Bytes::new());
    assert!(matches!(
        builder.try_push(&too_large),
        Err(SignedInputError::Execution(
            bloch_l2_evm::BlockExecutionError::BlockGasLimitExceeded { tx_index: 1 }
        ))
    ));
    let smaller = sign_with_gas(&spec, 1, TxKind::Call(recipient), Bytes::new(), 21_000);
    builder.try_push(&smaller).unwrap();
    let (input, pending) = builder.finish().unwrap();
    assert_eq!(input.transactions, vec![first, smaller]);
    let built = materialize(pending.overlay(), &initial);
    let (_, actual) = pending.finalize(compute_keccak_mpt_state_root(&built));
    let expected = execute_signed_block(&spec, &mut initial, &input).unwrap();
    assert_eq!(actual.header, expected.header);
    assert_eq!(actual.gas_used, 42_000);
}
fn deploy(runtime: &[u8]) -> Bytes {
    let length = u8::try_from(runtime.len()).unwrap();
    let mut code = vec![0x60, length, 0x60, 12, 0x60, 0, 0x39, 0x60, length, 0x60, 0, 0xf3];
    code.extend_from_slice(runtime);
    code.into()
}
fn deposit() -> DepositMint {
    DepositMint {
        recipient: sender(),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: 0,
            l1_txid: [1; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    }
}

/// Complete fixture enumeration is an oracle, not a production root algorithm.
fn materialize<DB: DatabaseRef>(overlay: &CacheDB<DB>, base: &L2State) -> L2State
where
    DB::Error: std::fmt::Debug,
{
    let mut state = L2State::new();
    let addresses: BTreeSet<_> = overlay
        .cache
        .accounts
        .keys()
        .chain(base.db().cache.accounts.keys())
        .copied()
        .collect();
    for address in addresses {
        let Some(mut info) = overlay.basic_ref(address).unwrap() else {
            continue;
        };
        info.code = Some(overlay.code_by_hash_ref(info.code_hash).unwrap());
        state.db_mut().insert_account_info(address, info);
        let slots: BTreeSet<_> = overlay
            .cache
            .accounts
            .get(&address)
            .into_iter()
            .chain(base.db().cache.accounts.get(&address))
            .flat_map(|account| account.storage.keys())
            .copied()
            .collect();
        for slot in slots {
            state
                .db_mut()
                .insert_account_storage(address, slot, overlay.storage_ref(address, slot).unwrap())
                .unwrap();
        }
    }
    state
}

#[test]
fn selected_signed_candidates_equal_verifier_and_do_not_publish_skipped_effects() {
    let spec = ChainSpec::default();
    let mut initial = L2State::genesis(&spec);
    let before = format!("{:?}", initial.db());
    let root = initial.commit_root();
    let mut builder = SignedBlockBuilder::new(
        &spec,
        initial.db(),
        root,
        BlockContext::next(&spec, &initial),
        vec![deposit()],
    )
    .unwrap();
    let creation = sign(&spec, 0, TxKind::Create, deploy(&[0x60, 0, 0x35, 0x60, 0, 0x55, 0]));
    assert!(builder
        .try_push_with_condition(&creation, |outcome| {
            assert!(outcome.success);
            assert!(outcome.gas_used > 0);
            assert_eq!(outcome.created_address, Some(sender().create(0)));
            false
        })
        .unwrap()
        .is_none());
    assert!(builder.input().transactions.is_empty());
    assert!(matches!(
        builder.try_push(&[2]),
        Err(SignedInputError::Authentication { .. })
    ));
    assert!(builder.try_push(&creation).unwrap().success);
    let contract = sender().create(0);
    let invalid_nonce = sign(&spec, 9, TxKind::Call(contract), Bytes::new());
    assert!(matches!(
        builder.try_push(&invalid_nonce),
        Err(SignedInputError::Execution(_))
    ));
    let call = sign(
        &spec,
        1,
        TxKind::Call(contract),
        U256::from(42).to_be_bytes::<32>().to_vec().into(),
    );
    assert!(builder.try_push_with_condition(&call, |_| false).unwrap().is_none());
    assert!(builder.try_push(&call).unwrap().success);
    // A later transaction must retain slots written by an earlier candidate.
    let reverter_creation = sign(&spec, 2, TxKind::Create, deploy(&[0x60, 0, 0x60, 0, 0xfd]));
    assert!(builder.try_push(&reverter_creation).unwrap().success);
    let revert = sign(&spec, 3, TxKind::Call(sender().create(2)), Bytes::new());
    assert!(
        !builder.try_push(&revert).unwrap().success,
        "reverted execution is still included"
    );
    let (input, pending) = builder.finish().unwrap();
    assert_eq!(input.transactions, vec![creation, call, reverter_creation, revert]);
    let built = materialize(pending.overlay(), &initial);
    assert_eq!(built.db().storage_ref(contract, U256::ZERO).unwrap(), U256::from(42));
    let (_, actual) = pending.finalize(compute_keccak_mpt_state_root(&built));
    assert_eq!(format!("{:?}", initial.db()), before, "backing snapshot never changes");
    let expected = execute_signed_block(&spec, &mut initial, &input).unwrap();
    assert_eq!(actual.header, expected.header);
    assert_eq!(actual.block_hash, expected.block_hash);
    assert_eq!(actual.gas_used, expected.gas_used);
    assert_eq!(actual.base_fee_routed_wei, expected.base_fee_routed_wei);
    assert_eq!(actual.priority_fee_routed_wei, expected.priority_fee_routed_wei);
    assert_eq!(actual.minted_wei, expected.minted_wei);
    assert_eq!(actual.burned_wei, expected.burned_wei);
    assert_eq!(actual.tx_outcomes.len(), expected.tx_outcomes.len());
    for (actual, expected) in actual.tx_outcomes.iter().zip(&expected.tx_outcomes) {
        assert_eq!(actual.result, expected.result);
        assert_eq!(actual.gas_used, expected.gas_used);
    }
}

#[test]
fn invalid_candidates_consume_finite_authentication_budget_but_not_block_input() {
    use bloch_l2_evm::transactions::MAX_SIGNED_TRANSACTIONS;
    let spec = ChainSpec::default();
    let mut initial = L2State::genesis(&spec);
    let root = initial.commit_root();
    let mut builder =
        SignedBlockBuilder::new(&spec, initial.db(), root, BlockContext::next(&spec, &initial), vec![]).unwrap();
    for _ in 0..MAX_SIGNED_TRANSACTIONS {
        assert!(matches!(
            builder.try_push(&[2]),
            Err(SignedInputError::Authentication {
                reason: TransactionAuthError::InvalidEncoding,
                ..
            })
        ));
    }
    assert_eq!(builder.attempted_transactions(), MAX_SIGNED_TRANSACTIONS);
    assert!(matches!(
        builder.try_push(&[2]),
        Err(SignedInputError::Authentication {
            reason: TransactionAuthError::TooManyTransactions,
            ..
        })
    ));
    let (input, pending) = builder.finish().unwrap();
    assert!(input.transactions.is_empty());
    let built = materialize(pending.overlay(), &initial);
    let (_, actual) = pending.finalize(compute_keccak_mpt_state_root(&built));
    let expected = execute_signed_block(&spec, &mut initial, &input).unwrap();
    assert_eq!(actual.header, expected.header);
}

#[test]
fn rejected_bytes_are_bounded_without_charging_oversized_preflight_failures() {
    use bloch_l2_evm::transactions::{MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES};
    let spec = ChainSpec::default();
    let mut initial = L2State::genesis(&spec);
    let root = initial.commit_root();
    let mut builder =
        SignedBlockBuilder::new(&spec, initial.db(), root, BlockContext::next(&spec, &initial), vec![]).unwrap();
    assert!(matches!(
        builder.try_push(&vec![0; MAX_RAW_TRANSACTION_BYTES + 1]),
        Err(SignedInputError::Authentication {
            reason: TransactionAuthError::TooLarge,
            ..
        })
    ));
    assert_eq!(builder.attempted_transactions(), 0);
    let raw = vec![0; MAX_RAW_TRANSACTION_BYTES];
    for _ in 0..MAX_SIGNED_BLOCK_BYTES / MAX_RAW_TRANSACTION_BYTES {
        assert!(matches!(
            builder.try_push(&raw),
            Err(SignedInputError::Authentication {
                reason: TransactionAuthError::UnsupportedType,
                ..
            })
        ));
    }
    assert!(matches!(
        builder.try_push(&[2]),
        Err(SignedInputError::Authentication {
            reason: TransactionAuthError::BlockTooLarge,
            ..
        })
    ));
    assert!(builder.finish().unwrap().0.transactions.is_empty());
}
