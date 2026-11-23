// SPDX-License-Identifier: MIT OR Apache-2.0
//! Audit AUDIT-L1L2-20261123, finding L2N-02: the deposit cap of the deployed
//! rules bounds the gross, lifetime sum of minted deposits, which withdrawals
//! never lower, so the first deposit after cumulative deposits reach the L1
//! supply cannot be executed although L1 accepted it. Under
//! `SupplyCap::Outstanding` the cap bounds minted minus withdrawn.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{b256, Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    chainspec::{ChainSpecError, SupplyCap, MAINNET_DOMAIN, MAINNET_GENESIS_TIMESTAMP},
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    proof_statement::configuration_commitment,
    withdrawal::{INITIATE_WITHDRAWAL_SELECTOR, L2_TO_L1_MESSAGE_PASSER},
    BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State, ATOM_SCALE,
};
use k256::ecdsa::SigningKey;

const SATS_PER_BLCH: u64 = 100_000_000;
const TOTAL_SUPPLY_SATS: u64 = 100_000_000_000 * SATS_PER_BLCH;

fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn deposit(recipient: Address, l1_height: u64, sats: u64) -> DepositMint {
    DepositMint {
        recipient,
        provenance: DepositProvenance::BridgedBlch {
            l1_height,
            l1_tx_index: 0,
            l1_txid: [l1_height as u8; 32],
            l1_vout: 1,
            l1_sats: sats,
        },
    }
}

fn withdraw(spec: &ChainSpec, nonce: u64, sats: u64) -> Bytes {
    let mut input = INITIATE_WITHDRAWAL_SELECTOR.to_vec();
    input.extend_from_slice(B256::repeat_byte(0x5c).as_slice());
    let tx = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to: TxKind::Call(L2_TO_L1_MESSAGE_PASSER),
        value: U256::from(sats) * U256::from(ATOM_SCALE),
        input: input.into(),
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        ..Default::default()
    };
    let signature: Signature = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into()
}

fn context(spec: &ChainSpec, state: &L2State) -> BlockContext {
    let head = node_head(spec, MAINNET_DOMAIN, state).unwrap();
    BlockContext {
        number: head.number + 1,
        timestamp: head.timestamp + 1_800,
        base_fee_per_gas: spec.next_base_fee(head.base_fee_per_gas, head.gas_used),
        prevrandao: B256::repeat_byte(7),
        anchor_root: B256::repeat_byte(head.number as u8 + 1),
    }
}

/// The finding's history: a deposit of the whole L1 supply and a withdrawal of
/// all but 10 BLCH. Returns the state and the withdrawn sats.
fn after_one_full_round_trip(spec: &ChainSpec) -> (L2State, Address) {
    let user = Address::from_public_key(key().verifying_key());
    let mut state = genesis_v2(spec, MAINNET_GENESIS_TIMESTAMP).unwrap();
    let body = NodeBodyV2 {
        deposits: vec![deposit(user, 10, TOTAL_SUPPLY_SATS)],
        transactions: vec![],
    };
    let ctx = context(spec, &state);
    execute_node_block(spec, MAINNET_DOMAIN, &mut state, &ctx, &body).unwrap();
    let back = TOTAL_SUPPLY_SATS - 10 * SATS_PER_BLCH;
    let body = NodeBodyV2 {
        deposits: vec![],
        transactions: vec![withdraw(spec, 0, back)],
    };
    let ctx = context(spec, &state);
    let out = execute_node_block(spec, MAINNET_DOMAIN, &mut state, &ctx, &body).unwrap();
    assert!(out.transactions[0].success, "the withdrawal executed");
    assert_eq!(
        state.total_minted_wei(),
        U256::from(TOTAL_SUPPLY_SATS) * U256::from(ATOM_SCALE)
    );
    assert_eq!(state.total_withdrawn_wei(), U256::from(back) * U256::from(ATOM_SCALE));
    (state, user)
}

/// The finding's PoC under both rules: the deployed rule stops, the
/// outstanding rule mints the deposit, and the witness path agrees.
#[test]
fn l2n02_a_deposit_after_gross_mints_reach_the_supply_is_minted_under_the_outstanding_cap() {
    let deployed = ChainSpec::mainnet();
    let fixed = ChainSpec::mainnet_outstanding_cap();
    assert_eq!(deployed.supply_cap, SupplyCap::GrossMinted);
    assert_eq!(fixed.supply_cap, SupplyCap::Outstanding);
    assert_eq!(
        ChainSpec {
            supply_cap: SupplyCap::GrossMinted,
            ..fixed.clone()
        },
        deployed
    );

    // Identical history under both rules: same state root, block by block.
    let (old_state, user) = after_one_full_round_trip(&deployed);
    let (mut new_state, _) = after_one_full_round_trip(&fixed);
    assert_eq!(old_state.state_root(), new_state.state_root());
    assert_eq!(
        node_head(&deployed, MAINNET_DOMAIN, &old_state).unwrap().hash(),
        node_head(&fixed, MAINNET_DOMAIN, &new_state).unwrap().hash()
    );

    let body = NodeBodyV2 {
        deposits: vec![deposit(user, 20, SATS_PER_BLCH)],
        transactions: vec![],
    };
    let error = generate_node_batch_witness(
        &old_state,
        &deployed,
        MAINNET_DOMAIN,
        &context(&deployed, &old_state),
        &body,
    )
    .unwrap_err();
    assert!(
        format!("{error:?}").contains("CumulativeSupplyExceeded"),
        "the deployed rule stops: {error}"
    );

    let ctx = context(&fixed, &new_state);
    let (witness, outcome) = generate_node_batch_witness(&new_state, &fixed, MAINNET_DOMAIN, &ctx, &body)
        .expect("the outstanding cap mints the deposit L1 accepted");
    // The guest path re-executes the witness (the withdrawn slot is in it).
    let verified =
        bloch_l2_evm::node_execution::verify_node_batch(&fixed, MAINNET_DOMAIN, &witness, &ctx, &body).unwrap();
    assert_eq!(verified.header, outcome.header);
    execute_node_block(&fixed, MAINNET_DOMAIN, &mut new_state, &ctx, &body).unwrap();
    assert_eq!(
        new_state.balance_of(&user) / U256::from(ATOM_SCALE) / U256::from(SATS_PER_BLCH),
        U256::from(10u64)
    );
    assert_eq!(
        new_state.total_minted_wei(),
        U256::from(TOTAL_SUPPLY_SATS + SATS_PER_BLCH) * U256::from(ATOM_SCALE),
        "the gross counter keeps counting; only the cap moved"
    );
}

/// The outstanding cap is still a cap: the supply on the L2 can never pass
/// the L1 supply, and it is exact at the boundary.
#[test]
fn the_outstanding_cap_still_bounds_the_supply_on_the_l2() {
    let spec = ChainSpec::mainnet_outstanding_cap();
    let (mut state, user) = after_one_full_round_trip(&spec);
    // 10 BLCH are outstanding. Room: the supply minus 10 BLCH, to the sat.
    let room = TOTAL_SUPPLY_SATS - 10 * SATS_PER_BLCH;
    let over = NodeBodyV2 {
        deposits: vec![deposit(user, 20, room + 1)],
        transactions: vec![],
    };
    let ctx = context(&spec, &state);
    let error = execute_node_block(&spec, MAINNET_DOMAIN, &mut state, &ctx, &over).unwrap_err();
    assert!(format!("{error:?}").contains("CumulativeSupplyExceeded"), "{error}");
    let exact = NodeBodyV2 {
        deposits: vec![deposit(user, 20, room)],
        transactions: vec![],
    };
    let ctx = context(&spec, &state);
    execute_node_block(&spec, MAINNET_DOMAIN, &mut state, &ctx, &exact).unwrap();
    let one_more = NodeBodyV2 {
        deposits: vec![deposit(user, 30, 1)],
        transactions: vec![],
    };
    let ctx = context(&spec, &state);
    let error = execute_node_block(&spec, MAINNET_DOMAIN, &mut state, &ctx, &one_more).unwrap_err();
    assert!(format!("{error:?}").contains("CumulativeSupplyExceeded"), "{error}");
    // A single record above the supply is refused under either rule.
    let too_large = NodeBodyV2 {
        deposits: vec![deposit(user, 40, TOTAL_SUPPLY_SATS + 1)],
        transactions: vec![],
    };
    let ctx = context(&spec, &state);
    let error = execute_node_block(&spec, MAINNET_DOMAIN, &mut state, &ctx, &too_large).unwrap_err();
    assert!(format!("{error:?}").contains("ExceedsL1Supply"), "{error}");
}

/// The rule is part of the pinned configuration: the deployed commitments do
/// not move, and the new rule has its own.
#[test]
fn the_cap_rule_is_committed_and_the_deployed_commitments_do_not_move() {
    // identities[3] of l2_settlement::mainnet::PROGRAM (docs/MAINNET-PROGRAM.md).
    assert_eq!(
        configuration_commitment(&ChainSpec::mainnet()).unwrap(),
        b256!("8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b")
    );
    let fixed = configuration_commitment(&ChainSpec::mainnet_outstanding_cap()).unwrap();
    assert_ne!(fixed, configuration_commitment(&ChainSpec::mainnet()).unwrap());
    // Pinned so a change of the version 3 layout is deliberate: the value a
    // native program switch would carry as identities[3].
    assert_eq!(
        fixed,
        b256!("41ddb4dd4aae492e04f500d40be8471ac785e1264d32346dc0f1620d67cc928d")
    );
    for spec in [ChainSpec::testnet(), ChainSpec::testnet_v3(), ChainSpec::mainnet()] {
        assert_eq!(
            spec.supply_cap,
            SupplyCap::GrossMinted,
            "every deployed rule set keeps the gross cap"
        );
    }
    // Without the outbox nothing is ever withdrawn: the rule is refused.
    let invalid = ChainSpec {
        supply_cap: SupplyCap::Outstanding,
        ..ChainSpec::testnet()
    };
    assert_eq!(invalid.validate(), Err(ChainSpecError::OutstandingCapWithoutOutbox));
    assert!(configuration_commitment(&invalid).is_err());
}

/// The candidate program `settlement_v3_mainnet_bound` (outstanding cap and
/// derived context) and the deployed `settlement_v3_mainnet` commit, for a
/// block built by the node's mainnet rule, statements that differ only in the
/// configuration commitment: same header hash, same state root.
#[test]
fn the_candidate_program_statement_differs_from_the_deployed_one_only_in_the_configuration() {
    use bloch_l2_evm::{
        node_execution::bound::{execute_settlement_statement_v3_bound, SettlementContextRule},
        proof_statement::{execute_settlement_statement_v3, SettlementContextV2},
    };
    let (deployed, candidate) = (ChainSpec::mainnet(), ChainSpec::mainnet_outstanding_cap());
    let rule = SettlementContextRule::mainnet();
    let state = genesis_v2(&deployed, MAINNET_GENESIS_TIMESTAMP).unwrap();
    assert_eq!(
        state.state_root(),
        genesis_v2(&candidate, MAINNET_GENESIS_TIMESTAMP).unwrap().state_root(),
        "one genesis"
    );
    let head = node_head(&deployed, MAINNET_DOMAIN, &state).unwrap();
    let (l1_slot, anchor) = (300_000, B256::repeat_byte(0x99));
    let ctx = BlockContext {
        number: 1,
        timestamp: rule.timestamp(head.timestamp, l1_slot).unwrap(),
        base_fee_per_gas: deployed.next_base_fee(head.base_fee_per_gas, head.gas_used),
        prevrandao: rule.prevrandao(1, head.hash(), anchor),
        anchor_root: anchor,
    };
    let user = Address::repeat_byte(0xaa);
    let body = NodeBodyV2 {
        deposits: vec![deposit(user, 10, SATS_PER_BLCH)],
        transactions: vec![],
    };
    let settlement = SettlementContextV2 {
        network: B256::repeat_byte(0x41),
        genesis: B256::repeat_byte(0x42),
        program_elf_keccak: B256::repeat_byte(0x43),
        program_vkey_koalabear: B256::repeat_byte(0x44),
        program_vkey_bn254: B256::repeat_byte(0x45),
        previous_settlement: B256::ZERO,
        l1_slot,
        l1_height: 100_000,
        source_commitment: B256::repeat_byte(0x46),
        inbox_root: B256::repeat_byte(0x47),
        inbox_count: 1,
        consumed_start: 0,
        consumed_end: 1,
    };
    let (old_witness, _) = generate_node_batch_witness(&state, &deployed, MAINNET_DOMAIN, &ctx, &body).unwrap();
    let old =
        execute_settlement_statement_v3(&deployed, MAINNET_DOMAIN, &old_witness, &ctx, &body, settlement).unwrap();
    // The candidate's witness also carries the ledger's withdrawn slot.
    let (new_witness, _) = generate_node_batch_witness(&state, &candidate, MAINNET_DOMAIN, &ctx, &body).unwrap();
    let new =
        execute_settlement_statement_v3_bound(&candidate, MAINNET_DOMAIN, &rule, &new_witness, &ctx, &body, settlement)
            .unwrap();
    assert_eq!(old.base.l2_header_hash, new.base.l2_header_hash);
    assert_eq!(old.base.l2_state_root, new.base.l2_state_root);
    assert_ne!(old.base.configuration, new.base.configuration);
    let mut same = new;
    same.base.configuration = old.base.configuration;
    assert_eq!(same.encode(), old.encode());
}
