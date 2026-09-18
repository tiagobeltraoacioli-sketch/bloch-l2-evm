// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cryptographic and execution regressions for the classical L2 wallet boundary.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEip2930, TxEnvelope, TxLegacy};
use alloy_eips::{
    eip2718::Encodable2718,
    eip2930::{AccessList, AccessListItem},
};
use alloy_primitives::{address, keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::transactions::{MAX_RAW_TRANSACTION_BYTES, MAX_SIGNED_BLOCK_BYTES, MAX_SIGNED_TRANSACTIONS};
use bloch_l2_evm::{
    decode_signed_transaction, execute_signed_block, generate_signed_batch_witness, verify_signed_batch, BlockContext,
    ChainSpec, DepositMint, DepositProvenance, L2State, SignedBlockInput, SignedInputError, TransactionAuthError,
};
use k256::ecdsa::SigningKey;

const RECIPIENT: Address = address!("2222222222222222222222222222222222222222");

fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn signature<T: SignableTransaction<Signature>>(tx: &T) -> Signature {
    key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into()
}
fn tx1559(chain_id: u64, nonce: u64) -> TxEip1559 {
    TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 100_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        to: TxKind::Call(RECIPIENT),
        value: U256::from(1234),
        ..Default::default()
    }
}
fn encode1559(tx: TxEip1559) -> Bytes {
    let sig = signature(&tx);
    TxEnvelope::from(tx.into_signed(sig)).encoded_2718().into()
}
fn funded(spec: &ChainSpec) -> L2State {
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
    state.commit_root();
    state
}
fn input(spec: &ChainSpec, state: &L2State, transactions: Vec<Bytes>) -> SignedBlockInput {
    SignedBlockInput {
        context: BlockContext::next(spec, state),
        transactions,
        deposits: vec![],
    }
}
fn assert_auth<E: core::fmt::Debug>(result: Result<E, TransactionAuthError>, expected: TransactionAuthError) {
    assert_eq!(result.unwrap_err(), expected);
}

#[test]
fn canonical_legacy_2930_and_1559_recover_sender_and_preserve_execution_fields() {
    let spec = ChainSpec::testnet();
    let access_list = AccessList(vec![AccessListItem {
        address: RECIPIENT,
        storage_keys: vec![B256::repeat_byte(3)],
    }]);
    let legacy = TxLegacy {
        chain_id: Some(spec.chain_id),
        nonce: 4,
        gas_price: 2_000_000_000,
        gas_limit: 110_000,
        to: TxKind::Create,
        value: U256::from(9),
        input: Bytes::from_static(&[0x60, 0]),
    };
    let sig = signature(&legacy);
    let legacy = TxEnvelope::from(legacy.into_signed(sig));
    let tx1 = TxEip2930 {
        chain_id: spec.chain_id,
        nonce: 5,
        gas_price: 3_000_000_000,
        gas_limit: 120_000,
        to: TxKind::Call(RECIPIENT),
        value: U256::from(10),
        input: Bytes::from_static(&[1, 2]),
        access_list: access_list.clone(),
    };
    let sig = signature(&tx1);
    let tx1 = TxEnvelope::from(tx1.into_signed(sig));
    let mut tx2 = tx1559(spec.chain_id, 6);
    tx2.access_list = access_list.clone();
    for (kind, envelope) in [(0, legacy), (1, tx1)] {
        let bytes = envelope.encoded_2718();
        let auth = decode_signed_transaction(&spec, &bytes).unwrap();
        assert_eq!(auth.sender(), sender());
        assert_eq!(auth.hash(), keccak256(&bytes));
        assert_eq!(auth.raw().as_ref(), bytes);
        let env = auth.environment();
        assert_eq!(env.tx_type, kind);
        assert_eq!(env.chain_id, Some(spec.chain_id));
        assert_eq!(env.gas_priority_fee, None);
        assert_eq!(env.nonce, 4 + kind as u64);
        assert_eq!(env.gas_limit, 110_000 + kind as u64 * 10_000);
        assert_eq!(env.gas_price, 2_000_000_000 + kind as u128 * 1_000_000_000);
        assert_eq!(env.value, U256::from(9 + kind));
        assert_eq!(
            env.kind,
            if kind == 0 {
                TxKind::Create
            } else {
                TxKind::Call(RECIPIENT)
            }
        );
        assert_eq!(env.data.as_ref(), if kind == 0 { &[0x60, 0][..] } else { &[1, 2][..] });
        assert_eq!(
            env.access_list,
            if kind == 0 {
                AccessList::default()
            } else {
                access_list.clone()
            }
        );
        assert!(env.blob_hashes.is_empty() && env.authorization_list.is_empty());
    }
    let auth = decode_signed_transaction(&spec, &encode1559(tx2.clone())).unwrap();
    let env = auth.environment();
    assert_eq!(auth.sender(), sender());
    assert_eq!(env.tx_type, 2);
    assert_eq!(env.nonce, 6);
    assert_eq!(env.gas_price, tx2.max_fee_per_gas);
    assert_eq!(env.gas_priority_fee, Some(tx2.max_priority_fee_per_gas));
    assert_eq!(env.access_list, access_list);
}

#[test]
fn replay_domains_and_unsupported_envelopes_are_rejected() {
    let spec = ChainSpec::testnet();
    assert_auth(
        decode_signed_transaction(&spec, &encode1559(tx1559(spec.chain_id + 1, 0))),
        TransactionAuthError::WrongChain,
    );
    let legacy = TxLegacy {
        chain_id: None,
        gas_limit: 21_000,
        ..Default::default()
    };
    let sig = signature(&legacy);
    assert_auth(
        decode_signed_transaction(&spec, &TxEnvelope::from(legacy.into_signed(sig)).encoded_2718()),
        TransactionAuthError::UnprotectedLegacy,
    );
    for kind in [0u8, 3, 4, 0x7e, 0x7f, 0x80] {
        assert_auth(
            decode_signed_transaction(&spec, &[kind]),
            TransactionAuthError::UnsupportedType,
        );
    }
}

#[test]
fn high_s_invalid_scalars_trailing_data_and_noncanonical_rlp_are_rejected() {
    let spec = ChainSpec::testnet();
    let tx = tx1559(spec.chain_id, 0);
    let sig = signature(&tx);
    let order = U256::from_be_slice(&alloy_primitives::hex!(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    ));
    let high = Signature::new(sig.r(), order - sig.s(), !sig.v());
    let raw = TxEnvelope::from(tx.clone().into_signed(high)).encoded_2718();
    assert_auth(decode_signed_transaction(&spec, &raw), TransactionAuthError::HighS);
    let zero = Signature::new(U256::ZERO, U256::ZERO, false);
    let raw = TxEnvelope::from(tx.clone().into_signed(zero)).encoded_2718();
    assert_auth(
        decode_signed_transaction(&spec, &raw),
        TransactionAuthError::InvalidSignature,
    );
    let mut raw = encode1559(tx).to_vec();
    raw.push(0);
    assert_auth(
        decode_signed_transaction(&spec, &raw),
        TransactionAuthError::NonCanonical,
    );
    // A long-form RLP list with leading-zero length is never canonical.
    assert!(decode_signed_transaction(&spec, &[2, 0xf9, 0, 1, 0x80]).is_err());
}

#[test]
fn malformed_and_oversized_input_never_panics() {
    let spec = ChainSpec::testnet();
    assert_auth(decode_signed_transaction(&spec, &[]), TransactionAuthError::Empty);
    assert_auth(
        decode_signed_transaction(&spec, &vec![2; MAX_RAW_TRANSACTION_BYTES + 1]),
        TransactionAuthError::TooLarge,
    );
    for len in 1..80 {
        for first in [1u8, 2, 0xc0, 0xf8, 0xf9, 0xff] {
            let mut bytes = vec![0x80; len];
            bytes[0] = first;
            assert!(decode_signed_transaction(&spec, &bytes).is_err());
        }
    }
}

#[test]
fn signed_host_execution_and_guest_recovery_agree() {
    let spec = ChainSpec::testnet();
    let mut state = funded(&spec);
    let before = state.state_root();
    let signed = input(&spec, &state, vec![encode1559(tx1559(spec.chain_id, 0))]);
    let (witness, host) = generate_signed_batch_witness(&state, &spec, &signed).unwrap();
    assert_eq!(state.state_root(), before);
    let guest = verify_signed_batch(&spec, &witness, &signed).unwrap();
    let executed = execute_signed_block(&spec, &mut state, &signed).unwrap();
    assert_eq!(host.state_root, guest.new_state_root);
    assert_eq!(executed.state_root, guest.new_state_root);
    assert_eq!(state.balance_of(&RECIPIENT), U256::from(1234));
    assert_eq!(state.nonce_of(&sender()), 1);

    // An attacker keeps the original signature but changes the recipient.
    // Recovery can succeed for a DIFFERENT sender; it must not authorize the
    // funded owner's balance, either in the host or in the guest.
    let tx = tx1559(spec.chain_id, 0);
    let sig = signature(&tx);
    let mut altered = tx;
    altered.to = TxKind::Call(Address::repeat_byte(9));
    let forged: Bytes = TxEnvelope::from(altered.into_signed(sig)).encoded_2718().into();
    assert_ne!(decode_signed_transaction(&spec, &forged).unwrap().sender(), sender());
    let mut tampered = signed.clone();
    tampered.transactions[0] = forged;
    assert!(verify_signed_batch(&spec, &witness, &tampered).is_err());
    let mut pre = funded(&spec);
    assert!(execute_signed_block(&spec, &mut pre, &tampered).is_err());
    assert_eq!(pre.state_root(), before);
    let mut wrong_chain = signed;
    wrong_chain.transactions[0] = encode1559(tx1559(spec.chain_id + 1, 0));
    assert!(matches!(
        verify_signed_batch(&spec, &witness, &wrong_chain),
        Err(SignedInputError::Authentication {
            reason: TransactionAuthError::WrongChain,
            ..
        })
    ));
}

#[test]
fn replay_and_late_bad_signature_leave_the_block_unapplied() {
    let spec = ChainSpec::testnet();
    let mut state = funded(&spec);
    let before = state.state_root();
    let tx = encode1559(tx1559(spec.chain_id, 0));
    let duplicate = input(&spec, &state, vec![tx.clone(), tx.clone()]);
    assert!(execute_signed_block(&spec, &mut state, &duplicate).is_err());
    assert_eq!(state.state_root(), before);
    let invalid = input(&spec, &state, vec![tx.clone(), Bytes::from_static(&[2])]);
    assert!(matches!(
        execute_signed_block(&spec, &mut state, &invalid),
        Err(SignedInputError::Authentication {
            transaction_index: Some(1),
            ..
        })
    ));
    assert_eq!(state.state_root(), before);
    let valid = input(&spec, &state, vec![tx.clone()]);
    execute_signed_block(&spec, &mut state, &valid).unwrap();
    let after = state.state_root();
    let replay = input(&spec, &state, vec![tx]);
    assert!(execute_signed_block(&spec, &mut state, &replay).is_err());
    assert_eq!(state.state_root(), after);
}

#[test]
fn block_resource_bounds_apply_before_recovery_or_execution() {
    let spec = ChainSpec::testnet();
    let mut state = funded(&spec);
    let before = state.state_root();
    let too_many = input(&spec, &state, vec![Bytes::new(); MAX_SIGNED_TRANSACTIONS + 1]);
    assert!(matches!(
        execute_signed_block(&spec, &mut state, &too_many),
        Err(SignedInputError::Authentication {
            reason: TransactionAuthError::TooManyTransactions,
            ..
        })
    ));
    let raw = Bytes::from(vec![2; MAX_RAW_TRANSACTION_BYTES]);
    let too_large = input(
        &spec,
        &state,
        vec![raw; MAX_SIGNED_BLOCK_BYTES / MAX_RAW_TRANSACTION_BYTES + 1],
    );
    assert!(matches!(
        execute_signed_block(&spec, &mut state, &too_large),
        Err(SignedInputError::Authentication {
            reason: TransactionAuthError::BlockTooLarge,
            ..
        })
    ));
    assert_eq!(state.state_root(), before);
}

#[cfg(feature = "serde")]
#[test]
fn guest_wire_round_trip_retains_bytes_and_reauthenticates() {
    let spec = ChainSpec::testnet();
    let state = funded(&spec);
    let signed = input(&spec, &state, vec![encode1559(tx1559(spec.chain_id, 0))]);
    let (witness, host) = generate_signed_batch_witness(&state, &spec, &signed).unwrap();
    let wire = serde_json::to_vec(&signed).unwrap();
    let mut decoded: SignedBlockInput = serde_json::from_slice(&wire).unwrap();
    assert_eq!(decoded.transactions, signed.transactions);
    assert_eq!(
        verify_signed_batch(&spec, &witness, &decoded).unwrap().new_state_root,
        host.state_root
    );
    decoded.transactions[0] = Bytes::from_static(&[2]);
    assert!(matches!(
        verify_signed_batch(&spec, &witness, &decoded),
        Err(SignedInputError::Authentication { .. })
    ));
}

#[test]
fn execution_domain_reexecutes_signed_transfer_and_rejects_mutated_signature() {
    use bloch_l2_evm::domain::{input_commitment, DomainError, EvmDomain, TrustedL1Batch};
    let spec = ChainSpec::default();
    let mut state = funded(&spec);
    let root = state.commit_root();
    let mut signed = input(&spec, &state, vec![encode1559(tx1559(spec.chain_id, 0))]);
    signed.context.anchor_root = B256::repeat_byte(44);
    let (witness, _) = generate_signed_batch_witness(&state, &spec, &signed).unwrap();
    let mut domain = EvmDomain::new(
        B256::repeat_byte(1),
        B256::repeat_byte(2),
        B256::repeat_byte(3),
        spec,
        root,
        16 * 1024 * 1024,
    )
    .unwrap();
    let mut trusted = TrustedL1Batch {
        height: 1,
        block: signed.context.anchor_root,
        domain: domain.id(),
        input: input_commitment(&signed),
    };
    let mut tampered = signed.clone();
    let mut raw = tampered.transactions[0].to_vec();
    *raw.last_mut().unwrap() ^= 1;
    tampered.transactions[0] = raw.into();
    trusted.input = input_commitment(&tampered);
    assert_eq!(
        domain.verify_and_advance(&trusted, &tampered, &witness),
        Err(DomainError::Execution)
    );
    assert_eq!(domain.state_root(), root);
    trusted.input = input_commitment(&signed);
    assert_eq!(
        domain.verify_and_advance(&trusted, &signed, &witness).unwrap().new_root,
        witness.new_state_root
    );
}
