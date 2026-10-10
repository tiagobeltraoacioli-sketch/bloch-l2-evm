// SPDX-License-Identifier: MIT OR Apache-2.0
//! Settlement V3 SP1 program: identical inputs to `settlement_v2`, but it
//! commits the 766-byte `BLOCH:EVM:SETTLEMENT:3` statement and places no
//! restriction on user transactions in the executed body. Since M4 it executes
//! the settlement V3 rules (`ChainSpec::testnet_v3`: the withdrawal outbox) and
//! commits the post-block withdrawal root and count. `settlement_v2` is
//! unchanged; the two are different programs with different keys.
#![no_main]

use alloy_primitives::B256;
use alloy_rlp::Decodable;
use bloch_l2_evm::{
    node_primitives::NodeBodyV2,
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2},
    proving::BatchWitness,
    BlockContext, ChainSpec,
};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Compiled program parameters, never prover-selected: the V2 testnet rules
    // plus the withdrawal outbox (M4), same chain id and domain.
    let spec = ChainSpec::testnet_v3();
    let domain = B256::repeat_byte(0xd3);

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
