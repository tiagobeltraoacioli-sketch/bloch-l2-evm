// SPDX-License-Identifier: MIT OR Apache-2.0
//! Settlement V3 SP1 program of the Bloch L2 **mainnet** (chain id 700770).
//!
//! Identical to `settlement_v3` (same inputs, same 766-byte
//! `BLOCH:EVM:SETTLEMENT:3` statement, user transactions and the withdrawal
//! outbox) except for the two compiled program parameters: the mainnet
//! execution rules (`ChainSpec::mainnet`) and the mainnet V2 domain
//! (`MAINNET_DOMAIN`, derived from the chain id and the Genesis-4 network).
//! The chain id and domain enter the configuration commitment and every
//! header, so this is a different program, with different keys, from every
//! devnet guest. `settlement_v3` (devnet4) is unchanged.
//!
//! CANDIDATE next program: `ChainSpec::mainnet` now also binds the timestamp and
//! prevrandao to L1 data and installs the fee-vault sweep. The program the
//! activation pinned is this file at f0d53fe (ELF SHA-256 `203114bf…c473`).
#![no_main]

use alloy_rlp::Decodable;
use bloch_l2_evm::{
    chainspec::MAINNET_DOMAIN,
    node_primitives::NodeBodyV2,
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2},
    proving::BatchWitness,
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

    let witness = sp1_zkvm::io::read::<BatchWitness>();
    let context = sp1_zkvm::io::read::<BlockContext>();
    let encoded_body = sp1_zkvm::io::read_vec();
    let settlement = sp1_zkvm::io::read::<SettlementContextV2>();
    let mut input = encoded_body.as_slice();
    let body = NodeBodyV2::decode(&mut input).expect("invalid canonical V2 body");
    assert!(input.is_empty(), "trailing bytes after V2 body");

    let statement = execute_settlement_statement_v3(&spec, domain, &witness, &context, &body, settlement)
        .expect("invalid settlement V3 transition");
    sp1_zkvm::io::commit_slice(&statement.encode());
}
