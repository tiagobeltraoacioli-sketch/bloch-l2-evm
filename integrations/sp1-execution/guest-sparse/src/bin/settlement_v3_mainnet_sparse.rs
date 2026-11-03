// SPDX-License-Identifier: MIT OR Apache-2.0
//! CANDIDATE, inert: settlement V3 with a sparse witness, under the next mainnet rules, lazy BLOCKHASH.
//! No release builds or selects this program, and no L1 configuration names it.
//! The state transition and the 766-byte statement are those of the complete
//! witness. Only the witness and therefore the program identity differ.
#![no_main]

use alloy_rlp::Decodable;
use bloch_l2_evm::{
    chainspec::MAINNET_DOMAIN,
    node_primitives::NodeBodyV2,
    proof_statement::SettlementContextV2,
    sparse_witness::{execute_settlement_statement_v3_sparse, BlockHashes, SparseBatchWitness},
    BlockContext, ChainSpec,
};

sp1_zkvm::entrypoint!(main);

// RELEASE GATE (agent 163, B-1): this program compiles the next mainnet rules,
// whose fee-vault sweep sends every L2 fee to `MAINNET_FEE_SWEEP_RECIPIENT`.
// It does not build while that recipient is unset, the rehearsal placeholder
// 0x…000fee01, or any address the release check refuses.
const _: () = assert!(
    bloch_l2_evm::chainspec::MAINNET_NEXT_RULES_RELEASABLE,
    "next-rules guest: set the owner's fee-sweep recipient first (deployment/mainnet/set-sweep-recipient.py apply)"
);

pub fn main() {
    // Compiled program parameters, never prover-selected.
    let spec = ChainSpec::mainnet();
    let domain = MAINNET_DOMAIN;

    let witness = sp1_zkvm::io::read::<SparseBatchWitness>();
    let context = sp1_zkvm::io::read::<BlockContext>();
    let encoded_body = sp1_zkvm::io::read_vec();
    let settlement = sp1_zkvm::io::read::<SettlementContextV2>();
    let mut input = encoded_body.as_slice();
    let body = NodeBodyV2::decode(&mut input).expect("invalid canonical V2 body");
    assert!(input.is_empty(), "trailing bytes after V2 body");

    let statement = execute_settlement_statement_v3_sparse(&spec, domain, &witness, &context, &body, settlement, BlockHashes::Lazy)
        .expect("invalid settlement V3 transition");
    sp1_zkvm::io::commit_slice(&statement.encode());
}
