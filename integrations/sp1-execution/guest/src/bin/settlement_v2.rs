// SPDX-License-Identifier: MIT OR Apache-2.0
//! Settlement-specific SP1 program. The legacy execution guest remains intact.
#![no_main]

use alloy_primitives::B256;
use alloy_rlp::Decodable;
use bloch_l2_evm::{
    node_primitives::NodeBodyV2,
    proof_statement::{execute_settlement_statement_v2, SettlementContextV2},
    proving::BatchWitness,
    BlockContext, ChainSpec,
};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let spec = ChainSpec::testnet();
    let domain = B256::repeat_byte(0xd3);

    let witness = sp1_zkvm::io::read::<BatchWitness>();
    let context = sp1_zkvm::io::read::<BlockContext>();
    let encoded_body = sp1_zkvm::io::read_vec();
    let settlement = sp1_zkvm::io::read::<SettlementContextV2>();
    let mut input = encoded_body.as_slice();
    let body = NodeBodyV2::decode(&mut input).expect("invalid canonical V2 body");
    assert!(input.is_empty(), "trailing bytes after V2 body");

    let statement = execute_settlement_statement_v2(&spec, domain, &witness, &context, &body, settlement)
        .expect("invalid settlement V2 transition");
    sp1_zkvm::io::commit_slice(&statement.encode());
}
