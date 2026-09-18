// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local signed contract lifecycle with synthetic funding and L1 context.
//! Run: cargo run --offline --locked --example developer_contract
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::domain::{input_commitment, EvmDomain, TrustedL1Batch};
use bloch_l2_evm::{
    execute_signed_block, generate_signed_batch_witness, BlockContext, ChainSpec, DepositMint, DepositProvenance,
    ExecutionOutcome, L2State, SignedBlockInput,
};
use k256::ecdsa::SigningKey;

fn sign(key: &SigningKey, chain_id: u64, nonce: u64, to: TxKind, input: Bytes) -> Bytes {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        to,
        input,
        ..Default::default()
    };
    let signature: Signature = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .expect("disposable development key signs")
        .into();
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
}

fn execute_verified(
    spec: &ChainSpec,
    state: &mut L2State,
    domain: &mut EvmDomain,
    transactions: Vec<Bytes>,
    deposits: Vec<DepositMint>,
) -> ExecutionOutcome {
    let mut context = BlockContext::next(spec, state);
    // This anchor is a fixture, not a verified Bloch block.
    context.anchor_root = B256::from(U256::from(context.number).to_be_bytes::<32>());
    let input = SignedBlockInput {
        context,
        transactions,
        deposits,
    };
    let trusted = TrustedL1Batch {
        height: input.context.number,
        block: input.context.anchor_root,
        domain: domain.id(),
        input: input_commitment(&input),
    };
    let (witness, generated) = generate_signed_batch_witness(state, spec, &input).expect("generate witness");
    let previous = (domain.state_root(), domain.next_block());
    let mut forged = witness.clone();
    forged.new_state_root = B256::ZERO;
    assert!(domain.verify_and_advance(&trusted, &input, &forged).is_err());
    assert_eq!((domain.state_root(), domain.next_block()), previous);

    let mut altered = input.clone();
    altered.transactions[0] = Bytes::from_static(&[2]);
    assert!(domain.verify_and_advance(&trusted, &altered, &witness).is_err());
    assert_eq!((domain.state_root(), domain.next_block()), previous);
    let host_before = (state.state_root(), state.head(), state.deposit_cursor());
    assert!(execute_signed_block(spec, state, &altered).is_err());
    assert_eq!((state.state_root(), state.head(), state.deposit_cursor()), host_before);

    let receipt = domain
        .verify_and_advance(&trusted, &input, &witness)
        .expect("verify domain execution");
    let outcome = execute_signed_block(spec, state, &input).expect("execute signed block");
    assert_eq!(receipt.new_root, witness.new_state_root);
    assert_eq!(receipt.new_root, generated.state_root);
    assert_eq!(receipt.new_root, outcome.state_root);
    assert_eq!(receipt.new_root, state.commit_root());
    let accepted = (domain.state_root(), domain.next_block());
    assert!(domain.verify_and_advance(&trusted, &input, &witness).is_err());
    assert_eq!((domain.state_root(), domain.next_block()), accepted);
    let host_after = (state.state_root(), state.head(), state.deposit_cursor());
    assert!(execute_signed_block(spec, state, &input).is_err());
    assert_eq!((state.state_root(), state.head(), state.deposit_cursor()), host_after);
    println!(
        "block {}: gas {}, root {}",
        receipt.number, outcome.gas_used, receipt.new_root
    );
    outcome
}

fn main() {
    println!("LOCAL ONLY: synthetic funding and L1 context; no network, real BLCH, or finality proof.");
    // Public, disposable fixture key. Never fund this address on a live chain.
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).expect("fixture key");
    let sender = Address::from_public_key(key.verifying_key());
    let spec = ChainSpec::default();
    let mut state = L2State::genesis(&spec);
    let root = state.commit_root();
    let mut domain = EvmDomain::new(
        B256::repeat_byte(1),
        B256::repeat_byte(2),
        B256::repeat_byte(3),
        spec.clone(),
        root,
        16 * 1024 * 1024,
    )
    .expect("local domain");

    // Runtime: slot[0] = calldata word 0; return slot[0] as a 32-byte word.
    // Raw EVM bytecode keeps this example independent of a Solidity compiler.
    let runtime = [
        0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
    ];
    let length = u8::try_from(runtime.len()).expect("short runtime");
    let mut initcode = vec![0x60, length, 0x60, 12, 0x60, 0, 0x39, 0x60, length, 0x60, 0, 0xf3];
    initcode.extend_from_slice(&runtime);
    let deposit = DepositMint {
        recipient: sender,
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: 0,
            l1_txid: [1; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    };
    let deployed = execute_verified(
        &spec,
        &mut state,
        &mut domain,
        vec![sign(&key, spec.chain_id, 0, TxKind::Create, initcode.into())],
        vec![deposit],
    );
    let contract = deployed.tx_outcomes[0].created_address.expect("contract deployed");
    assert_eq!(contract, sender.create(0));
    assert!(deployed.tx_outcomes[0].success);
    assert!(deployed.gas_used > spec.deposit_gas);
    assert_eq!(state.nonce_of(&sender), 1);
    println!("sender: {sender}\ncontract: {contract}");

    let value = U256::from(42);
    let called = execute_verified(
        &spec,
        &mut state,
        &mut domain,
        vec![sign(
            &key,
            spec.chain_id,
            1,
            TxKind::Call(contract),
            value.to_be_bytes::<32>().to_vec().into(),
        )],
        vec![],
    );
    assert!(called.tx_outcomes[0].success);
    assert!(called.gas_used > 21_000);
    assert_eq!(state.db().cache.accounts[&contract].storage[&U256::ZERO], value);
    assert_eq!(state.nonce_of(&sender), 2);
    assert_eq!(state.total_minted_wei(), U256::from(10).pow(U256::from(18)));
    assert_eq!(state.total_native_wei(), state.total_minted_wei());
    println!("storage[0]: {value}; sender nonce: 2");
    println!("Host, witness and domain roots agree. Tampering and replay rejected without advancing cursors.");
}
