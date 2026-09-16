//! Zero-value local demonstration; the L1 context below is synthetic, not verified.
use alloy_primitives::B256;
use bloch_l2_evm::domain::{input_commitment, EvmDomain, TrustedL1Batch};
use bloch_l2_evm::{generate_signed_batch_witness, BlockContext, ChainSpec, L2State, SignedBlockInput};

fn main() {
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
    .expect("valid local configuration");
    let mut context = BlockContext::next(&spec, &state);
    context.anchor_root = B256::repeat_byte(4);
    context.timestamp = 100;
    let input = SignedBlockInput {
        context,
        ..Default::default()
    };
    let (witness, _) = generate_signed_batch_witness(&state, &spec, &input).expect("local witness");
    let trusted = TrustedL1Batch {
        height: 1,
        block: input.context.anchor_root,
        domain: domain.id(),
        input: input_commitment(&input),
    };
    let receipt = domain
        .verify_and_advance(&trusted, &input, &witness)
        .expect("verified execution");
    println!("LOCAL ONLY — synthetic L1 context; no proof, bridge or mainnet transaction");
    println!("domain: {}", receipt.domain);
    println!("previous root: {}", receipt.previous_root);
    println!("new root: {}", receipt.new_root);
    println!("receipt commitment: {}", receipt.commitment());
    assert!(domain.verify_and_advance(&trusted, &input, &witness).is_err());
    println!("Replay rejected; accepted state preserved.");
}
