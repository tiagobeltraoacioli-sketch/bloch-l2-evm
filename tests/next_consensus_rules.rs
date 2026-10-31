// SPDX-License-Identifier: MIT OR Apache-2.0
//! The next mainnet rule set across its boundary, through the stateless path the
//! settlement guest runs: blocks under `mainnet_v1`, then blocks under `mainnet`
//! on top of them. Execution only; no proof is generated.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{b256, Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    chainspec::{
        fee_vault_sweep_code, BASE_FEE_VAULT, GENESIS4_SLOT_MS, L2_BLOCK_PREVRANDAO, MAINNET_DOMAIN,
        MAINNET_FEE_SWEEP_RECIPIENT, MAINNET_GENESIS_TIMESTAMP, SEQUENCER_FEE_VAULT,
    },
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    proof_statement::{
        configuration_commitment, execute_settlement_statement_v3, SettlementContextV2, SettlementStatementV2Error,
    },
    BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State,
};
use k256::ecdsa::SigningKey;
use revm::DatabaseRef;

const V1_CONFIGURATION: B256 = b256!("8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b");
const FIRST_SLOT: u64 = 187_201;

fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}

fn transfer(spec: &ChainSpec, nonce: u64, to: Address, value: U256) -> Bytes {
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to: TxKind::Call(to),
        value,
        gas_limit: 200_000,
        max_fee_per_gas: 3_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        ..Default::default()
    };
    let signature: Signature = key().sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap().into();
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
}

fn settlement(slot: u64, deposits: u64) -> SettlementContextV2 {
    SettlementContextV2 {
        network: B256::repeat_byte(1),
        genesis: B256::repeat_byte(2),
        program_elf_keccak: B256::repeat_byte(3),
        program_vkey_koalabear: B256::repeat_byte(4),
        program_vkey_bn254: B256::repeat_byte(5),
        previous_settlement: B256::ZERO,
        l1_slot: slot,
        l1_height: 1,
        source_commitment: B256::repeat_byte(6),
        inbox_root: B256::repeat_byte(7),
        inbox_count: deposits,
        consumed_start: 0,
        consumed_end: deposits,
    }
}

fn slot_time(slot: u64) -> u64 {
    MAINNET_GENESIS_TIMESTAMP + slot * GENESIS4_SLOT_MS / 1000
}

fn context(spec: &ChainSpec, state: &L2State, timestamp: u64, prevrandao: B256) -> BlockContext {
    let head = node_head(spec, MAINNET_DOMAIN, state).unwrap();
    BlockContext {
        number: head.number + 1,
        timestamp,
        base_fee_per_gas: spec.next_base_fee(head.base_fee_per_gas, head.gas_used),
        prevrandao,
        anchor_root: B256::repeat_byte(9),
    }
}

/// Prove-path check (witness, then the guest's statement function), then commit.
fn settle(
    spec: &ChainSpec,
    state: &mut L2State,
    ctx: &BlockContext,
    body: &NodeBodyV2,
    slot: u64,
) -> Result<B256, SettlementStatementV2Error> {
    let (witness, _) = generate_node_batch_witness(state, spec, MAINNET_DOMAIN, ctx, body).unwrap();
    let statement =
        execute_settlement_statement_v3(spec, MAINNET_DOMAIN, &witness, ctx, body, settlement(slot, body.deposits.len() as u64))?;
    let outcome = execute_node_block(spec, MAINNET_DOMAIN, state, ctx, body).unwrap();
    assert_eq!(statement.base.l2_header_hash, outcome.header.hash());
    Ok(statement.base.configuration)
}

fn balance(state: &L2State, who: Address) -> U256 {
    state.db().basic_ref(who).unwrap().map(|i| i.balance).unwrap_or_default()
}

fn code_len(state: &L2State, who: Address) -> usize {
    let info = state.db().basic_ref(who).unwrap().unwrap_or_default();
    let hash = info.code_hash;
    info.code.map(|c| c.len()).unwrap_or_else(|| state.db().code_by_hash_ref(hash).map_or(0, |c| c.len()))
}

fn supply(state: &L2State, who: &[Address]) -> U256 {
    who.iter().fold(U256::ZERO, |sum, a| sum + balance(state, *a))
}

#[test]
fn the_activated_configuration_and_genesis_are_untouched() {
    assert_eq!(configuration_commitment(&ChainSpec::mainnet_v1()).unwrap(), V1_CONFIGURATION);
    let next = configuration_commitment(&ChainSpec::mainnet()).unwrap();
    assert_ne!(next, V1_CONFIGURATION);
    assert_eq!(ChainSpec::mainnet_rules_for(V1_CONFIGURATION), Some(ChainSpec::mainnet_v1()));
    assert_eq!(ChainSpec::mainnet_rules_for(next), Some(ChainSpec::mainnet()));
    assert_eq!(ChainSpec::mainnet_rules_for(B256::ZERO), None);

    let mut old = genesis_v2(&ChainSpec::mainnet_v1(), MAINNET_GENESIS_TIMESTAMP).unwrap();
    let mut new = genesis_v2(&ChainSpec::mainnet(), MAINNET_GENESIS_TIMESTAMP).unwrap();
    assert_eq!(old.commit_root(), new.commit_root());
    assert_eq!(
        node_head(&ChainSpec::mainnet_v1(), MAINNET_DOMAIN, &old).unwrap().hash(),
        node_head(&ChainSpec::mainnet(), MAINNET_DOMAIN, &new).unwrap().hash()
    );
}

#[test]
fn only_the_derived_values_settle_and_parent_plus_one_still_applies() {
    let spec = ChainSpec::mainnet();
    let mut state = genesis_v2(&spec, MAINNET_GENESIS_TIMESTAMP).unwrap();
    let body = NodeBodyV2::default();
    let rule = slot_time(FIRST_SLOT);
    for (timestamp, prevrandao) in [
        (rule + 1, L2_BLOCK_PREVRANDAO),
        (rule - 1, L2_BLOCK_PREVRANDAO),
        (rule, B256::ZERO),
    ] {
        let ctx = context(&spec, &state, timestamp, prevrandao);
        assert!(matches!(
            settle(&spec, &mut state, &ctx, &body, FIRST_SLOT),
            Err(SettlementStatementV2Error::BlockDerivation)
        ));
    }
    let ctx = context(&spec, &state, rule, L2_BLOCK_PREVRANDAO);
    settle(&spec, &mut state, &ctx, &body, FIRST_SLOT).unwrap();

    // The same anchored slot again: time still moves, by exactly one second.
    let ctx = context(&spec, &state, rule, L2_BLOCK_PREVRANDAO);
    assert!(settle(&spec, &mut state, &ctx, &body, FIRST_SLOT).is_err());
    let ctx = context(&spec, &state, rule + 1, L2_BLOCK_PREVRANDAO);
    settle(&spec, &mut state, &ctx, &body, FIRST_SLOT).unwrap();
}

#[test]
fn settlements_cross_the_boundary_and_recover_the_fees() {
    let (old, new) = (ChainSpec::mainnet_v1(), ChainSpec::mainnet());
    let mut state = genesis_v2(&old, MAINNET_GENESIS_TIMESTAMP).unwrap();
    let friend = Address::repeat_byte(0x55);
    let deposit = DepositMint {
        recipient: sender(),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 7,
            l1_tx_index: 0,
            l1_txid: [1; 32],
            l1_vout: 1,
            l1_sats: 500_000_000,
        },
    };
    let accounts = [sender(), friend, BASE_FEE_VAULT, SEQUENCER_FEE_VAULT, MAINNET_FEE_SWEEP_RECIPIENT];

    // Under the activated rules, a far-future timestamp and a foreign prevrandao
    // still settle: this is the exposure, and old history must replay as it was.
    let ctx = context(&old, &state, slot_time(FIRST_SLOT) + 1_000, B256::repeat_byte(0x99));
    let body = NodeBodyV2 {
        deposits: vec![deposit],
        transactions: vec![transfer(&old, 0, friend, U256::from(1_000))],
    };
    assert_eq!(settle(&old, &mut state, &ctx, &body, FIRST_SLOT).unwrap(), V1_CONFIGURATION);
    let (base_fees, tips) = (balance(&state, BASE_FEE_VAULT), balance(&state, SEQUENCER_FEE_VAULT));
    assert!(base_fees > U256::ZERO && tips > U256::ZERO);
    assert_eq!(code_len(&state, BASE_FEE_VAULT), 0);
    let total = supply(&state, &accounts);
    let v1_head = node_head(&old, MAINNET_DOMAIN, &state).unwrap();

    // First block under the new program: an off-rule parent is tolerated, because
    // the rule is `max(parent + 1, slot time)`. Empty block, code installed.
    let ctx = context(&new, &state, v1_head.timestamp + 1, L2_BLOCK_PREVRANDAO);
    assert_eq!(ctx.number, 2);
    let configuration = settle(&new, &mut state, &ctx, &NodeBodyV2::default(), FIRST_SLOT + 1).unwrap();
    assert_eq!(configuration, configuration_commitment(&new).unwrap());
    let head = node_head(&new, MAINNET_DOMAIN, &state).unwrap();
    assert_eq!(head.parent_hash, v1_head.hash());
    for vault in [BASE_FEE_VAULT, SEQUENCER_FEE_VAULT] {
        assert_eq!(code_len(&state, vault), fee_vault_sweep_code(MAINNET_FEE_SWEEP_RECIPIENT).len());
    }
    assert_eq!((balance(&state, BASE_FEE_VAULT), balance(&state, SEQUENCER_FEE_VAULT)), (base_fees, tips));
    assert_eq!(supply(&state, &accounts), total);

    // Anyone calling a vault sends its whole balance to the compiled recipient.
    let ctx = context(&new, &state, head.timestamp + 1, L2_BLOCK_PREVRANDAO);
    let body = NodeBodyV2 {
        deposits: vec![],
        transactions: vec![
            transfer(&new, 1, BASE_FEE_VAULT, U256::ZERO),
            transfer(&new, 2, SEQUENCER_FEE_VAULT, U256::ZERO),
        ],
    };
    settle(&new, &mut state, &ctx, &body, FIRST_SLOT + 2).unwrap();
    let swept = balance(&state, MAINNET_FEE_SWEEP_RECIPIENT);
    assert!(swept >= base_fees + tips, "recipient holds the fees accumulated under the old rules");
    assert_eq!(supply(&state, &accounts), total, "supply is conserved across the sweep");
    // The sweep block's own fees reach the vaults after its calls and stay there.
    let vaults = balance(&state, BASE_FEE_VAULT) + balance(&state, SEQUENCER_FEE_VAULT);
    assert_eq!(swept + vaults + balance(&state, sender()) + balance(&state, friend), total);
}
