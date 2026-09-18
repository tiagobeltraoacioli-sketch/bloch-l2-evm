use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::domain::{input_commitment, DomainError, EvmDomain, TrustedL1Batch};
use bloch_l2_evm::{generate_signed_batch_witness, BatchWitness, BlockContext, ChainSpec, L2State, SignedBlockInput};

fn fixture() -> (EvmDomain, TrustedL1Batch, SignedBlockInput, BatchWitness) {
    let spec = ChainSpec::default();
    let mut state = L2State::genesis(&spec);
    let root = state.commit_root();
    let domain = EvmDomain::new(
        B256::repeat_byte(1),
        B256::repeat_byte(2),
        B256::repeat_byte(3),
        spec.clone(),
        root,
        16 * 1024 * 1024,
    )
    .unwrap();
    let mut context = BlockContext::next(&spec, &state);
    context.anchor_root = B256::repeat_byte(4);
    context.timestamp = 100;
    let input = SignedBlockInput {
        context,
        ..Default::default()
    };
    let (witness, _) = generate_signed_batch_witness(&state, &spec, &input).unwrap();
    let trusted = TrustedL1Batch {
        height: 100,
        block: input.context.anchor_root,
        domain: domain.id(),
        input: input_commitment(&input),
    };
    (domain, trusted, input, witness)
}

#[test]
fn reexecution_advances_once_and_receipt_is_bound() {
    let (mut domain, trusted, input, witness) = fixture();
    let receipt = domain.verify_and_advance(&trusted, &input, &witness).unwrap();
    assert_eq!(domain.state_root(), witness.new_state_root);
    assert_eq!(domain.next_block(), 2);
    assert_eq!(
        domain.verify_and_advance(&trusted, &input, &witness),
        Err(DomainError::Continuity)
    );
    let mut changed = receipt.clone();
    changed.anchor.height += 1;
    assert_ne!(receipt.commitment(), changed.commitment());
}

#[test]
fn input_tampering_and_wrong_domain_are_rejected_without_state_mutation() {
    let (mut domain, trusted, input, witness) = fixture();
    let initial = domain.state_root();
    let mut wrong = trusted.clone();
    wrong.domain = B256::ZERO;
    assert_eq!(
        domain.verify_and_advance(&wrong, &input, &witness),
        Err(DomainError::Derivation)
    );
    let mut changed = input.clone();
    changed.context.timestamp += 1;
    assert_eq!(
        domain.verify_and_advance(&trusted, &changed, &witness),
        Err(DomainError::Derivation)
    );
    assert_eq!(domain.state_root(), initial);
    assert_eq!(domain.next_block(), 1);
}

#[test]
fn forged_post_root_does_not_advance_cursor() {
    let (mut domain, trusted, input, mut witness) = fixture();
    let root = domain.state_root();
    witness.new_state_root = B256::repeat_byte(9);
    assert_eq!(
        domain.verify_and_advance(&trusted, &input, &witness),
        Err(DomainError::Execution)
    );
    assert_eq!(domain.state_root(), root);
    assert_eq!(domain.next_block(), 1);
}

#[test]
fn witness_limit_is_enforced_before_execution() {
    let (_, trusted, input, witness) = fixture();
    let mut domain = EvmDomain::new(
        B256::repeat_byte(1),
        B256::repeat_byte(2),
        B256::repeat_byte(3),
        ChainSpec::default(),
        witness.prev_state_root,
        1,
    )
    .unwrap();
    assert_eq!(
        domain.verify_and_advance(&trusted, &input, &witness),
        Err(DomainError::WitnessLimit)
    );
    assert_eq!(domain.next_block(), 1);
}

#[test]
fn anchor_rollback_and_same_height_conflict_fail_closed() {
    let (mut domain, trusted, input, witness) = fixture();
    domain.verify_and_advance(&trusted, &input, &witness).unwrap();
    let mut older = trusted.clone();
    older.height -= 1;
    assert_eq!(
        domain.verify_and_advance(&older, &input, &witness),
        Err(DomainError::AnchorRegression)
    );
    let mut conflicting = trusted;
    conflicting.block = B256::repeat_byte(8);
    let mut input = input;
    input.context.anchor_root = conflicting.block;
    conflicting.input = input_commitment(&input);
    assert_eq!(
        domain.verify_and_advance(&conflicting, &input, &witness),
        Err(DomainError::AnchorRegression)
    );
    assert_eq!(domain.next_block(), 2);
}

#[test]
fn transaction_order_and_boundaries_are_committed() {
    let (_, _, mut input, _) = fixture();
    input.transactions = vec![Bytes::from_static(&[1]), Bytes::from_static(&[2, 3])];
    let original = input_commitment(&input);
    input.transactions.reverse();
    assert_ne!(original, input_commitment(&input));
    input.transactions = vec![Bytes::from_static(&[1, 2]), Bytes::from_static(&[3])];
    assert_ne!(original, input_commitment(&input));
}

#[test]
fn runtime_network_and_configuration_change_domain_identity() {
    let (domain, _, _, witness) = fixture();
    for (network, runtime, mut spec) in [
        (B256::repeat_byte(9), B256::repeat_byte(3), ChainSpec::default()),
        (B256::repeat_byte(1), B256::repeat_byte(9), ChainSpec::default()),
        (B256::repeat_byte(1), B256::repeat_byte(3), ChainSpec::default()),
    ]
    .into_iter()
    {
        if network == B256::repeat_byte(1) && runtime == B256::repeat_byte(3) {
            spec.chain_id += 1;
        }
        let other = EvmDomain::new(
            network,
            B256::repeat_byte(2),
            runtime,
            spec,
            witness.prev_state_root,
            1000,
        )
        .unwrap();
        assert_ne!(domain.id(), other.id());
    }
}

#[test]
fn oversized_envelope_is_rejected_before_hashing_or_execution() {
    let (mut domain, trusted, mut input, witness) = fixture();
    input
        .transactions
        .push(vec![0; bloch_l2_evm::transactions::MAX_RAW_TRANSACTION_BYTES + 1].into());
    assert_eq!(
        domain.verify_and_advance(&trusted, &input, &witness),
        Err(DomainError::InputLimit)
    );
    assert_eq!(domain.next_block(), 1);
}

#[test]
fn contiguous_blocks_can_share_a_finalized_anchor() {
    use bloch_l2_evm::execute_signed_block;
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
    .unwrap();
    for number in 1..=2 {
        let mut context = BlockContext::next(&spec, &state);
        context.timestamp = 100 + number;
        context.anchor_root = B256::repeat_byte(4);
        let input = SignedBlockInput {
            context,
            ..Default::default()
        };
        let (witness, _) = generate_signed_batch_witness(&state, &spec, &input).unwrap();
        let trusted = TrustedL1Batch {
            height: 100,
            block: input.context.anchor_root,
            domain: domain.id(),
            input: input_commitment(&input),
        };
        let receipt = domain.verify_and_advance(&trusted, &input, &witness).unwrap();
        let host = execute_signed_block(&spec, &mut state, &input).unwrap();
        assert_eq!(receipt.new_root, host.state_root);
        assert_eq!(domain.next_block(), number + 1);
    }
}
