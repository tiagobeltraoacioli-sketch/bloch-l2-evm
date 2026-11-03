// SPDX-License-Identifier: MIT OR Apache-2.0
//! Security review 2026-10-30, finding on L2 timestamp binding. Logic-level
//! only: no proof is generated.
//!
//! The statement function run by the settlement guest takes both the block
//! timestamp and the anchored native slot, yet never relates them. The rule
//! `timestamp = max(parent + 1, slot time)` lives only in the producer and the
//! rebuilders. This test states the desired property and FAILS on 70eac31.

use alloy_primitives::B256;
use bloch_l2_evm::{
    chainspec::{MAINNET_DOMAIN, MAINNET_GENESIS_TIMESTAMP},
    node_execution::{generate_node_batch_witness, genesis_v2},
    node_primitives::NodeBodyV2,
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2},
    BlockContext, ChainSpec,
};

const SLOT: u64 = 187_201;
const SLOT_SECONDS: u64 = 30;

fn settlement() -> SettlementContextV2 {
    SettlementContextV2 {
        network: B256::repeat_byte(1),
        genesis: B256::repeat_byte(2),
        program_elf_keccak: B256::repeat_byte(3),
        program_vkey_koalabear: B256::repeat_byte(4),
        program_vkey_bn254: B256::repeat_byte(5),
        previous_settlement: B256::ZERO,
        l1_slot: SLOT,
        l1_height: 1,
        source_commitment: B256::repeat_byte(6),
        inbox_root: B256::repeat_byte(7),
        inbox_count: 0,
        consumed_start: 0,
        consumed_end: 0,
    }
}

fn statement_accepts(timestamp: u64) -> bool {
    statement_accepts_with(timestamp, B256::repeat_byte(7))
}

fn statement_accepts_with(timestamp: u64, prevrandao: B256) -> bool {
    let spec = ChainSpec::mainnet_next_or_rehearsal();
    let pre = genesis_v2(&spec, MAINNET_GENESIS_TIMESTAMP).unwrap();
    let context = BlockContext {
        number: 1,
        timestamp,
        base_fee_per_gas: spec.next_base_fee(spec.initial_base_fee, 0),
        prevrandao,
        anchor_root: B256::repeat_byte(9),
    };
    let body = NodeBodyV2 { deposits: vec![], transactions: vec![] };
    let (witness, _) = generate_node_batch_witness(&pre, &spec, MAINNET_DOMAIN, &context, &body).unwrap();
    execute_settlement_statement_v3(&spec, MAINNET_DOMAIN, &witness, &context, &body, settlement()).is_ok()
}

#[test]
fn control_rule_conforming_timestamp_is_accepted() {
    assert!(statement_accepts(MAINNET_GENESIS_TIMESTAMP + SLOT * SLOT_SECONDS));
}

#[test]
fn statement_must_refuse_a_timestamp_unrelated_to_the_anchored_slot() {
    let rule = MAINNET_GENESIS_TIMESTAMP + SLOT * SLOT_SECONDS;
    assert!(
        !statement_accepts(rule + 10 * 365 * 24 * 3600),
        "the statement function accepts a timestamp ten years past the anchored slot"
    );
}

#[test]
fn statement_must_refuse_a_prevrandao_rebuilders_cannot_derive() {
    let rule = MAINNET_GENESIS_TIMESTAMP + SLOT * SLOT_SECONDS;
    assert!(
        !statement_accepts_with(rule, B256::repeat_byte(0x99)),
        "the statement function accepts a prevrandao other than the one rebuilders assume"
    );
}
