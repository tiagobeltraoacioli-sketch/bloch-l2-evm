// SPDX-License-Identifier: MIT OR Apache-2.0
//! Settlement V3 SP1 program of the Bloch L2 **mainnet** (chain id 700770)
//! with the two guest fixes of audit AUDIT-L1L2-20261123. NOT the deployed
//! program: `settlement_v3_mainnet` is.
//!
//! Same inputs and the same 766-byte `BLOCH:EVM:SETTLEMENT:3` statement layout
//! as `settlement_v3_mainnet`, same domain. Two differences:
//!
//! * L2N-01: the prover's `timestamp` and `prevrandao` must be the values
//!   derived from the authenticated parent head and the statement's anchor
//!   slot (`SettlementContextRule::mainnet`), so a statement has exactly one
//!   valid block and anyone can rebuild it from L1 data;
//! * L2N-02: the deposit cap bounds the outstanding supply (minted minus
//!   withdrawn), not everything ever minted
//!   (`ChainSpec::mainnet_outstanding_cap`), so cumulative deposits of the
//!   whole L1 supply no longer stop the chain.
//!
//! A block built by the node software's mainnet rule (`--timestamp-rule
//! 1:1786656679:30000`, prevrandao `0x07..07`) has the same header hash and
//! state root under both programs; the statements differ only in the
//! configuration commitment.
//!
//! A different program: its own configuration commitment, ELF, verifying keys
//! and native pin. It protects nothing until the native chain accepts
//! settlements of this program only (a gated switch of
//! `l2_settlement::mainnet::PROGRAM`).
#![no_main]

use alloy_rlp::Decodable;
use bloch_l2_evm::{
    chainspec::MAINNET_DOMAIN,
    node_execution::bound::{execute_settlement_statement_v3_bound, SettlementContextRule},
    node_primitives::NodeBodyV2,
    proof_statement::SettlementContextV2,
    proving::BatchWitness,
    BlockContext, ChainSpec,
};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Compiled program parameters, never prover-selected.
    let spec = ChainSpec::mainnet_outstanding_cap();
    let domain = MAINNET_DOMAIN;
    let rule = SettlementContextRule::mainnet();

    let witness = sp1_zkvm::io::read::<BatchWitness>();
    let context = sp1_zkvm::io::read::<BlockContext>();
    let encoded_body = sp1_zkvm::io::read_vec();
    let settlement = sp1_zkvm::io::read::<SettlementContextV2>();
    let mut input = encoded_body.as_slice();
    let body = NodeBodyV2::decode(&mut input).expect("invalid canonical V2 body");
    assert!(input.is_empty(), "trailing bytes after V2 body");

    let statement = execute_settlement_statement_v3_bound(&spec, domain, &rule, &witness, &context, &body, settlement)
        .expect("invalid settlement V3 transition or block context");
    sp1_zkvm::io::commit_slice(&statement.encode());
}
