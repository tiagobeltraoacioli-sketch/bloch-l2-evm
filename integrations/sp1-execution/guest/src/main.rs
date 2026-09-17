// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixed synthetic-dev execution program; no native L1 authentication.
#![no_main]

use alloy_primitives::B256;
use alloy_rlp::Decodable;
use bloch_l2_evm::{
    node_primitives::NodeBodyV2, proof_statement::execute_statement, proving::BatchWitness, BlockContext, ChainSpec,
};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // These are compiled program parameters, never prover-selected settings.
    let spec = ChainSpec::testnet();
    let domain = B256::repeat_byte(0xd3);

    // SP1 input frames: bincode BatchWitness, bincode BlockContext, raw V2 RLP.
    let witness = sp1_zkvm::io::read::<BatchWitness>();
    let context = sp1_zkvm::io::read::<BlockContext>();
    let encoded_body = sp1_zkvm::io::read_vec();
    let mut input = encoded_body.as_slice();
    let body = NodeBodyV2::decode(&mut input).expect("invalid canonical V2 body");
    assert!(input.is_empty(), "trailing bytes after V2 body");

    let statement =
        execute_statement(&spec, domain, &witness, &context, &body).expect("invalid synthetic-dev V2 transition");
    // No bincode framing: the public stream is exactly the canonical statement.
    sp1_zkvm::io::commit_slice(&statement.encode());
}
