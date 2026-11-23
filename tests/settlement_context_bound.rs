// SPDX-License-Identifier: MIT OR Apache-2.0
//! Audit AUDIT-L1L2-20261123, finding L2N-01: the settlement statement must
//! determine the block context. `execute_settlement_statement_v3` (the
//! deployed `settlement_v3_mainnet` program) accepts a prover-chosen
//! `timestamp` and `prevrandao`; `execute_settlement_statement_v3_bound`
//! accepts only the context derived from the parent head and the anchor slot.
use alloy_primitives::{keccak256, Address, B256};
use bloch_l2_evm::{
    chainspec::{GENESIS4_SLOT_MS, MAINNET_DOMAIN, MAINNET_GENESIS_TIMESTAMP},
    node_execution::{
        bound::{
            execute_settlement_statement_v3_bound, BoundSettlementError, ContextRuleError, SettlementContextRule,
            LEGACY_PREVRANDAO, MAINNET_DERIVED_PREVRANDAO_FROM_BLOCK,
        },
        execute_node_block, generate_node_batch_witness, genesis_v2, node_head,
    },
    node_primitives::NodeBodyV2,
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2},
    BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State,
};

const L1_SLOT: u64 = 300_000;

fn settlement(l1_slot: u64, deposits: u64) -> SettlementContextV2 {
    SettlementContextV2 {
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
        inbox_count: deposits,
        consumed_start: 0,
        consumed_end: deposits,
    }
}

fn deposit() -> DepositMint {
    DepositMint {
        recipient: Address::repeat_byte(0xaa),
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 99_990,
            l1_tx_index: 0,
            l1_txid: [1; 32],
            l1_vout: 1,
            l1_sats: 1_000_000_000,
        },
    }
}

struct Chain {
    spec: ChainSpec,
    state: L2State,
}

impl Chain {
    fn mainnet() -> Self {
        let spec = ChainSpec::mainnet();
        let state = genesis_v2(&spec, MAINNET_GENESIS_TIMESTAMP).unwrap();
        Self { spec, state }
    }

    /// The context `rule` derives for the next block anchored to `anchor` at
    /// native slot `l1_slot`.
    fn derived(&self, rule: &SettlementContextRule, anchor: B256, l1_slot: u64) -> BlockContext {
        let head = node_head(&self.spec, MAINNET_DOMAIN, &self.state).unwrap();
        let number = head.number + 1;
        BlockContext {
            number,
            timestamp: rule.timestamp(head.timestamp, l1_slot).unwrap(),
            base_fee_per_gas: self.spec.next_base_fee(head.base_fee_per_gas, head.gas_used),
            prevrandao: rule.prevrandao(number, head.hash(), anchor),
            anchor_root: anchor,
        }
    }

    fn bound(
        &self,
        rule: &SettlementContextRule,
        context: &BlockContext,
        body: &NodeBodyV2,
        l1_slot: u64,
    ) -> Result<bloch_l2_evm::proof_statement::SettlementStatementV3, BoundSettlementError> {
        // The witness generator is the unbound executor: it produces a witness
        // for any context the deployed program accepts.
        let (witness, _) = generate_node_batch_witness(&self.state, &self.spec, MAINNET_DOMAIN, context, body).unwrap();
        execute_settlement_statement_v3_bound(
            &self.spec,
            MAINNET_DOMAIN,
            rule,
            &witness,
            context,
            body,
            settlement(l1_slot, body.deposits.len() as u64),
        )
    }

    fn apply(&mut self, context: &BlockContext, body: &NodeBodyV2) {
        execute_node_block(&self.spec, MAINNET_DOMAIN, &mut self.state, context, body).unwrap();
    }
}

fn context_error(result: Result<impl core::fmt::Debug, BoundSettlementError>) -> ContextRuleError {
    match result {
        Err(BoundSettlementError::Context(error)) => error,
        other => panic!("expected a context refusal, got {other:?}"),
    }
}

#[test]
fn the_mainnet_rule_is_the_node_rule_and_ships_with_the_legacy_prevrandao() {
    let rule = SettlementContextRule::mainnet();
    assert_eq!(rule.l1_genesis_time, 1_786_656_679);
    assert_eq!(rule.l1_slot_millis, 30_000);
    assert_eq!(rule.l1_slot_millis, GENESIS4_SLOT_MS);
    // Inert: the bound program accepts exactly the blocks honest nodes build today.
    assert_eq!(MAINNET_DERIVED_PREVRANDAO_FROM_BLOCK, u64::MAX);
    assert_eq!(rule.derived_prevrandao_from, u64::MAX);
    assert_eq!(LEGACY_PREVRANDAO, B256::repeat_byte(7));
    assert_eq!(
        rule.prevrandao(u64::MAX - 1, B256::repeat_byte(1), B256::repeat_byte(2)),
        LEGACY_PREVRANDAO
    );
    // `--timestamp-rule 1:1786656679:30000`: the anchored slot's start time,
    // never less than parent + 1.
    assert_eq!(rule.timestamp(1_786_656_679, 0), Some(1_786_656_680));
    assert_eq!(rule.timestamp(1_786_656_679, 1), Some(1_786_656_709));
    assert_eq!(
        rule.timestamp(1_786_656_679, L1_SLOT),
        Some(1_786_656_679 + L1_SLOT * 30)
    );
    assert_eq!(rule.timestamp(2_000_000_000, 1), Some(2_000_000_001));
    assert_eq!(rule.timestamp(u64::MAX, 1), None);
    assert_eq!(rule.timestamp(0, u64::MAX), None);
    // Sub-second slots truncate after the multiplication, as the node rule does.
    let fast = SettlementContextRule {
        l1_genesis_time: 1_000,
        l1_slot_millis: 1_500,
        derived_prevrandao_from: 5,
    };
    assert_eq!(fast.l1_time(3), Some(1_004));
    assert_eq!(
        fast.prevrandao(4, B256::repeat_byte(1), B256::repeat_byte(2)),
        LEGACY_PREVRANDAO
    );
    let mut preimage = [1u8; 64];
    preimage[32..].copy_from_slice(&[2u8; 32]);
    assert_eq!(
        fast.prevrandao(5, B256::repeat_byte(1), B256::repeat_byte(2)),
        keccak256(preimage)
    );
}

/// The finding's PoC, against the bound program: the honest block still
/// settles, with the statement the deployed program gives, and the foreign
/// contexts no longer do.
#[test]
fn l2n01_a_prover_chosen_context_no_longer_settles() {
    let rule = SettlementContextRule::mainnet();
    let chain = Chain::mainnet();
    let anchor = B256::repeat_byte(0x99);
    let body = NodeBodyV2 {
        deposits: vec![deposit()],
        transactions: vec![],
    };

    let honest = chain.derived(&rule, anchor, L1_SLOT);
    assert_eq!(honest.timestamp, MAINNET_GENESIS_TIMESTAMP + L1_SLOT * 30);
    assert_eq!(honest.prevrandao, LEGACY_PREVRANDAO);
    let bound = chain
        .bound(&rule, &honest, &body, L1_SLOT)
        .expect("the honest block settles");
    let (witness, _) = generate_node_batch_witness(&chain.state, &chain.spec, MAINNET_DOMAIN, &honest, &body).unwrap();
    let deployed = execute_settlement_statement_v3(
        &chain.spec,
        MAINNET_DOMAIN,
        &witness,
        &honest,
        &body,
        settlement(L1_SLOT, 1),
    )
    .unwrap();
    assert_eq!(bound.encode(), deployed.encode(), "same 766 bytes for an honest block");

    // The PoC's foreign block: a secret prevrandao and the last timestamp.
    let secret = keccak256(b"only the prover knows this");
    let foreign = BlockContext {
        timestamp: u64::MAX,
        prevrandao: secret,
        ..honest
    };
    let (witness, _) = generate_node_batch_witness(&chain.state, &chain.spec, MAINNET_DOMAIN, &foreign, &body).unwrap();
    execute_settlement_statement_v3(
        &chain.spec,
        MAINNET_DOMAIN,
        &witness,
        &foreign,
        &body,
        settlement(L1_SLOT, 1),
    )
    .expect("the deployed program accepts it (the finding)");
    assert_eq!(
        context_error(chain.bound(&rule, &foreign, &body, L1_SLOT)),
        ContextRuleError::Timestamp {
            expected: honest.timestamp,
            got: u64::MAX
        }
    );

    // Each free value alone is refused.
    assert_eq!(
        context_error(chain.bound(
            &rule,
            &BlockContext {
                prevrandao: secret,
                ..honest
            },
            &body,
            L1_SLOT
        )),
        ContextRuleError::Prevrandao {
            expected: LEGACY_PREVRANDAO,
            got: secret
        }
    );
    for timestamp in [
        honest.timestamp + 1,
        honest.timestamp - 1,
        MAINNET_GENESIS_TIMESTAMP + 1,
    ] {
        assert_eq!(
            context_error(chain.bound(&rule, &BlockContext { timestamp, ..honest }, &body, L1_SLOT)),
            ContextRuleError::Timestamp {
                expected: honest.timestamp,
                got: timestamp
            }
        );
    }
    // The anchor slot is the statement's: a context derived for another slot
    // does not settle under this one.
    let other_slot = chain.derived(&rule, anchor, L1_SLOT + 1);
    assert_eq!(
        context_error(chain.bound(&rule, &other_slot, &body, L1_SLOT)),
        ContextRuleError::Timestamp {
            expected: honest.timestamp,
            got: other_slot.timestamp
        }
    );
    chain
        .bound(&rule, &other_slot, &body, L1_SLOT + 1)
        .expect("and settles under its own slot");
}

/// The parent's timestamp is read from the witnessed pre-state: an anchor that
/// lags the parent gives exactly parent + 1, and `>= parent` is not enough.
#[test]
fn a_lagging_anchor_gives_parent_plus_one_and_nothing_else() {
    let rule = SettlementContextRule::mainnet();
    let mut chain = Chain::mainnet();
    let empty = NodeBodyV2::default();
    let first = chain.derived(&rule, B256::repeat_byte(0x91), L1_SLOT);
    chain.bound(&rule, &first, &empty, L1_SLOT).unwrap();
    chain.apply(&first, &empty);

    // Same anchor slot again (two L2 blocks on one native slot), then an older one.
    for l1_slot in [L1_SLOT, L1_SLOT - 10] {
        let next = chain.derived(&rule, B256::repeat_byte(0x92), l1_slot);
        let parent = node_head(&chain.spec, MAINNET_DOMAIN, &chain.state).unwrap().timestamp;
        assert_eq!(next.timestamp, parent + 1);
        // The deployed rule (`>= parent`) admits the parent's own timestamp.
        let equal = BlockContext {
            timestamp: parent,
            ..next
        };
        assert_eq!(
            context_error(chain.bound(&rule, &equal, &empty, l1_slot)),
            ContextRuleError::Timestamp {
                expected: parent + 1,
                got: parent
            }
        );
        chain.bound(&rule, &next, &empty, l1_slot).unwrap();
        chain.apply(&next, &empty);
    }
    // A later slot moves time to the slot start.
    let later = chain.derived(&rule, B256::repeat_byte(0x93), L1_SLOT + 7);
    assert_eq!(later.timestamp, MAINNET_GENESIS_TIMESTAMP + (L1_SLOT + 7) * 30);
    chain.bound(&rule, &later, &empty, L1_SLOT + 7).unwrap();
}

/// A program compiled with a switch block derives prevrandao from the parent
/// hash and the anchor from that block on, and keeps the constant before it.
#[test]
fn derived_prevrandao_applies_from_the_compiled_block_and_binds_parent_and_anchor() {
    let rule = SettlementContextRule {
        derived_prevrandao_from: 2,
        ..SettlementContextRule::mainnet()
    };
    let mut chain = Chain::mainnet();
    let empty = NodeBodyV2::default();

    let first = chain.derived(&rule, B256::repeat_byte(0x91), L1_SLOT);
    assert_eq!(first.prevrandao, LEGACY_PREVRANDAO, "block 1 is below the switch");
    chain.bound(&rule, &first, &empty, L1_SLOT).unwrap();
    chain.apply(&first, &empty);

    let anchor = B256::repeat_byte(0x92);
    let parent = node_head(&chain.spec, MAINNET_DOMAIN, &chain.state).unwrap().hash();
    let second = chain.derived(&rule, anchor, L1_SLOT + 1);
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(parent.as_slice());
    preimage[32..].copy_from_slice(anchor.as_slice());
    assert_eq!(second.prevrandao, keccak256(preimage));
    chain.bound(&rule, &second, &empty, L1_SLOT + 1).unwrap();

    // The legacy constant is refused from the switch on, and so is the value
    // derived for another anchor (the anchor is committed as `l1_block`).
    let legacy = BlockContext {
        prevrandao: LEGACY_PREVRANDAO,
        ..second
    };
    assert_eq!(
        context_error(chain.bound(&rule, &legacy, &empty, L1_SLOT + 1)),
        ContextRuleError::Prevrandao {
            expected: second.prevrandao,
            got: LEGACY_PREVRANDAO
        }
    );
    let other_anchor = BlockContext {
        anchor_root: B256::repeat_byte(0x93),
        ..second
    };
    assert!(matches!(
        context_error(chain.bound(&rule, &other_anchor, &empty, L1_SLOT + 1)),
        ContextRuleError::Prevrandao { .. }
    ));
    // The inert mainnet rule refuses the derived value: it is a different program.
    assert!(matches!(
        context_error(chain.bound(&SettlementContextRule::mainnet(), &second, &empty, L1_SLOT + 1)),
        ContextRuleError::Prevrandao { .. }
    ));
}

/// The rule only adds a refusal: tampered witnesses and bodies fail as before.
#[test]
fn the_bound_path_keeps_every_refusal_of_the_unbound_path() {
    let rule = SettlementContextRule::mainnet();
    let chain = Chain::mainnet();
    let body = NodeBodyV2 {
        deposits: vec![deposit()],
        transactions: vec![],
    };
    let context = chain.derived(&rule, B256::repeat_byte(0x99), L1_SLOT);
    let (witness, _) = generate_node_batch_witness(&chain.state, &chain.spec, MAINNET_DOMAIN, &context, &body).unwrap();
    let run = |witness: &_, context: &_, body: &_, settlement| {
        execute_settlement_statement_v3_bound(&chain.spec, MAINNET_DOMAIN, &rule, witness, context, body, settlement)
    };
    run(&witness, &context, &body, settlement(L1_SLOT, 1)).unwrap();

    let mut tampered = witness.clone();
    tampered.prev_state_root = B256::repeat_byte(0x55);
    assert!(matches!(
        run(&tampered, &context, &body, settlement(L1_SLOT, 1)),
        Err(BoundSettlementError::Witness(_))
    ));
    let no_deposit = NodeBodyV2::default();
    assert!(run(&witness, &context, &no_deposit, settlement(L1_SLOT, 0)).is_err());
    let wrong_number = BlockContext { number: 2, ..context };
    assert!(matches!(
        run(&witness, &wrong_number, &body, settlement(L1_SLOT, 1)),
        Err(BoundSettlementError::Witness(_))
    ));
    let wrong_fee = BlockContext {
        base_fee_per_gas: context.base_fee_per_gas + 1,
        ..context
    };
    assert!(matches!(
        run(&witness, &wrong_fee, &body, settlement(L1_SLOT, 1)),
        Err(BoundSettlementError::Witness(_))
    ));
    // A consumed range that is not the body's deposits is a statement error.
    assert!(matches!(
        run(&witness, &context, &body, settlement(L1_SLOT, 2)),
        Err(BoundSettlementError::Statement(_))
    ));
    let zero_slot = SettlementContextRule {
        l1_slot_millis: 0,
        ..rule
    };
    assert_eq!(
        context_error(execute_settlement_statement_v3_bound(
            &chain.spec,
            MAINNET_DOMAIN,
            &zero_slot,
            &witness,
            &context,
            &body,
            settlement(L1_SLOT, 1)
        )),
        ContextRuleError::Rule
    );
}
