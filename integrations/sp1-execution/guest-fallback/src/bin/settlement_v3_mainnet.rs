// SPDX-License-Identifier: MIT OR Apache-2.0
//! CANDIDATE, inert: the rollback fallback program of the Bloch L2 mainnet
//! (native `PROGRAM_FALLBACK`). The next mainnet rules (`ChainSpec::mainnet`,
//! with L1 forced inclusion, configuration tag 4) proved from the complete
//! witness, the same statement as the sparse `PROGRAM_NEXT`.
//!
//! Inputs: the complete witness, the block context, the canonical V2 body and
//! the settlement context, as `../guest`'s `settlement_v3_mainnet`, then the
//! forced records L1 names for this settlement, in queue order, each with its
//! envelope (empty when none is due). They run right after the deposits; the
//! body must start with exactly the envelopes that were not skipped, and the
//! statement's deposits_hash slot binds every consumed record
//! (`bloch_l2_evm::forced_complete`). The kit ships this ELF as
//! `settlement_v3_mainnet_fallback`.
#![no_main]

use alloy_rlp::Decodable;
use bloch_l2_evm::{
    chainspec::MAINNET_DOMAIN,
    forced_complete::execute_settlement_statement_v3_forced,
    forced_inclusion::ForcedTransaction,
    node_primitives::NodeBodyV2,
    proof_statement::SettlementContextV2,
    proving::BatchWitness,
    BlockContext, ChainSpec,
};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Compiled program parameters, never prover-selected.
    let spec = ChainSpec::mainnet();
    let domain = MAINNET_DOMAIN;
    assert!(spec.forced_inclusion, "the fallback proves the next rules with forced inclusion");

    let witness = sp1_zkvm::io::read::<BatchWitness>();
    let context = sp1_zkvm::io::read::<BlockContext>();
    let encoded_body = sp1_zkvm::io::read_vec();
    let settlement = sp1_zkvm::io::read::<SettlementContextV2>();
    let forced = sp1_zkvm::io::read::<Vec<ForcedTransaction>>();
    let mut input = encoded_body.as_slice();
    let body = NodeBodyV2::decode(&mut input).expect("invalid canonical V2 body");
    assert!(input.is_empty(), "trailing bytes after V2 body");

    let statement =
        execute_settlement_statement_v3_forced(&spec, domain, &witness, &context, &body, settlement, &forced)
            .expect("invalid settlement V3 transition");
    sp1_zkvm::io::commit_slice(&statement.encode());
}
