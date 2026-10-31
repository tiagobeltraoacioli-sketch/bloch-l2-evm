// SPDX-License-Identifier: AGPL-3.0-or-later
//! Security review 2026-10-30. On a flag-day L2 (mainnet, epoch 5850) the
//! native `InboxRecord.height` counts blocks since activation
//! (`l2.height() + 1`), while `read_l1_follower` numbers blocks from native
//! genesis. Without `l2_registry_blocks`, a rebuild derives different deposit
//! provenance from the one the settlement committed (`Deposits`). Read-only
//! mainnet values on 2026-10-30: chain height 186747, L2 native_height 34733.

use alloy_primitives::{Address, B256};
use bloch_l2_evm::{
    deposits_hash,
    proof_statement::{SettlementStatementV2, SettlementStatementV3},
    withdrawal::empty_withdrawal_root,
    DepositMint, DepositProvenance,
};
use bloch_pos_committee::{
    l2_settlement::Transaction as Settlement,
    transition::{funded::ADMISSION_PQ_KEY_BYTES, FundingInput, L2Deposit, PosTransaction, TransferOutput},
};
use bloch_settlement_recovery::reconstruct::{derive_settled_blocks, flag_day_first_slot, l2_registry_blocks, NativeBlockTransactions};

const CHAIN_ID: u64 = 700_770;
const OFFSET: u64 = 152_014;
const L2_HEIGHT: u64 = 3;

#[test]
fn rebuild_must_derive_the_inbox_height_the_native_chain_committed() {
    let recipient = Address::repeat_byte(0x42);
    let deposit = PosTransaction::L2Deposit(L2Deposit {
        network_domain: [0x91; 32],
        funding_pubkey: vec![0x5a; ADMISSION_PQ_KEY_BYTES],
        inputs: vec![FundingInput { txid: [1; 32], vout: 0 }],
        amount_sat: 5_000_000,
        recipient: recipient.into_array(),
        change: TransferOutput { value: 0, script_hash: [0; 32] },
        tx_bytes: 9_000,
        tip_millisat_per_gas: 0,
        signature: vec![1; 64],
    });
    // The record exactly as `apply_l2_deposit` stores it on an activated L2.
    let minted = DepositMint {
        recipient,
        provenance: DepositProvenance::BridgedBlch {
            l1_height: L2_HEIGHT,
            l1_tx_index: 0,
            l1_txid: deposit.txid(),
            l1_vout: 1,
            l1_sats: 5_000_000,
        },
    };
    let statement = SettlementStatementV3 {
        base: SettlementStatementV2 {
            network: B256::repeat_byte(1),
            genesis: B256::repeat_byte(2),
            domain: B256::repeat_byte(3),
            configuration: B256::repeat_byte(4),
            program_elf_keccak: B256::repeat_byte(5),
            program_vkey_koalabear: B256::repeat_byte(6),
            program_vkey_bn254: B256::repeat_byte(7),
            previous_settlement: B256::ZERO,
            chain_id: CHAIN_ID,
            l2_number: 1,
            l2_parent_hash: B256::repeat_byte(0x11),
            l2_previous_state_root: B256::repeat_byte(0x12),
            l2_header_hash: B256::repeat_byte(0x13),
            l2_state_root: B256::repeat_byte(0x14),
            l1_block: B256::repeat_byte(0x15),
            l1_slot: 187_210,
            l1_height: L2_HEIGHT,
            source_commitment: B256::repeat_byte(0x16),
            inbox_root: B256::repeat_byte(0x17),
            inbox_count: 1,
            consumed_start: 0,
            consumed_end: 1,
            body_commitment: B256::repeat_byte(0x18),
        },
        deposits_hash: deposits_hash(&[minted]),
        transactions_root: B256::repeat_byte(0x19),
        receipts_root: B256::repeat_byte(0x1a),
        user_tx_count: 0,
        withdrawal_root: empty_withdrawal_root(),
        withdrawal_count: 0,
        da_commitment: B256::ZERO,
    };
    let settlement = PosTransaction::L2SettlementAsync(Box::new(Settlement {
        proof_policy: [3; 32],
        statement: statement.encode().to_vec(),
        proof: [0; 356],
    }));
    // Chain order from native genesis, as a follower store holds it. Slots
    // start at the flag day minus OFFSET, so the deposit's block is L2 height
    // L2_HEIGHT only if the numbering starts at the activation block.
    let first_slot = 187_200;
    let mut chain: Vec<(u64, Vec<Vec<u8>>)> = (0..OFFSET).map(|i| (first_slot - OFFSET + i, vec![])).collect();
    chain.push((first_slot, vec![]));
    chain.push((first_slot + 1, vec![]));
    chain.push((first_slot + 2, vec![deposit.canonical_bytes()]));
    chain.push((first_slot + 3, vec![settlement.canonical_bytes()]));
    let blocks = l2_registry_blocks(chain.clone(), Some(first_slot));
    assert_eq!(blocks[2].height, L2_HEIGHT);
    // Control: chain heights, the numbering before the fix, are refused.
    let by_chain_height = l2_registry_blocks(chain, None);
    assert!(matches!(
        derive_settled_blocks(&by_chain_height, CHAIN_ID, B256::repeat_byte(0x11), B256::repeat_byte(0x12)),
        Err(bloch_settlement_recovery::reconstruct::ReconstructError::Deposits { number: 1 })
    ));
    let derived = derive_settled_blocks(&blocks, CHAIN_ID, B256::repeat_byte(0x11), B256::repeat_byte(0x12));
    assert!(derived.is_ok(), "rebuild refuses a settlement the native chain would accept: {derived:?}");
}

#[test]
fn an_l2_at_genesis_keeps_chain_heights() {
    let blocks = l2_registry_blocks(vec![(5, vec![]), (9, vec![])], None);
    assert_eq!(blocks.iter().map(|b| b.height).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(blocks, vec![
        NativeBlockTransactions { height: 1, transactions: vec![] },
        NativeBlockTransactions { height: 2, transactions: vec![] },
    ]);
}

#[test]
fn mainnet_flag_day_is_the_slot_the_chain_reports() {
    // getl2settlement on mainnet: source { height: 1, slot: 187200 } before any settlement.
    if !cfg!(feature = "l2-activation-rehearsal") {
        assert_eq!(flag_day_first_slot(), 187_200);
    }
}
