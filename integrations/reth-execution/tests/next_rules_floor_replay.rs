// SPDX-License-Identifier: MIT OR Apache-2.0
//! Review R406-8 (agent 406, round 19). Two validators of the parent link are not on the path of any release
//! binary's `extend`, `reconstruct` or `export`: `BlochConsensus::validate_header_against_parent`, reached
//! through `validate_and_execute_block` from the canonical replay (`replay_canonical_prefix*`, the recovery
//! and audit tools), and the canonical settlement audit (`settlement_binding.rs`). After the F387-1 fixes they
//! were held by one unit test and by the source guard only. Here a chain under the next rules is built across
//! the base-fee floor in real storage and both readers are run over it.
//!
//! Note for whoever reads "through bloch-l2-audit-dev" in the review: that binary is compiled for the
//! development rules only (`ChainSpec::testnet`, one rule set, no floor), so it cannot open a chain that has
//! a floor. The functions it calls are the ones called here.
use alloy_primitives::B256;
use bloch_l2_evm::{native_settlement::SettlementPolicyV1, proof_statement::configuration_commitment, ChainSpec};
use bloch_reth_execution::{
    prepare_genesis, replay_canonical_prefix_with_limits,
    settlement_binding::{with_canonical_settlement_audit, CanonicalSettlementAuditErrorV1},
    BlochChainSpec, BlochNextBlockEnvCtx, BlochProviderFactory, BlochTables, CanonicalCoordinator, ReplayFloor,
    ReplayLimits, RuleSchedule,
};
use reth_chainspec::EthChainSpec;
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockNumReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
};
use std::{path::Path, sync::Arc};

const GENESIS_TIME: u64 = 1_786_656_679;
const SWITCH: u64 = 2;

fn domain() -> B256 {
    B256::repeat_byte(0x70)
}

/// The mainnet rule sets; `switched` fixes the first next-rules block, as a reader of the database would.
fn chain(switched: bool) -> Arc<BlochChainSpec> {
    let rules = RuleSchedule::new(ChainSpec::mainnet_v1(), ChainSpec::mainnet_next_or_rehearsal()).unwrap();
    if switched {
        rules.switch_at(SWITCH).unwrap();
    }
    Arc::new(BlochChainSpec::scheduled(rules, domain(), GENESIS_TIME).unwrap())
}

fn open(path: &Path, spec: Arc<BlochChainSpec>) -> BlochProviderFactory {
    ProviderFactory::new(
        Arc::new(init_db_for::<_, BlochTables>(path.join("db"), DatabaseArguments::test()).unwrap()),
        spec,
        StaticFileProvider::read_write(path.join("static")).unwrap(),
        RocksDBBuilder::new(path.join("rocks"))
            .with_default_tables()
            .build()
            .unwrap(),
        reth_tasks::Runtime::test(),
    )
    .unwrap()
}

/// Quiet blocks: block 1 on the base rules, from `SWITCH` on the next rules, until the base fee has been at
/// the floor for three blocks after the first one whose EIP-1559 step fell under it. Returns the head number
/// and the first block at the floor.
fn build(source: &BlochProviderFactory, spec: &BlochChainSpec) -> (u64, u64) {
    let next = ChainSpec::mainnet_next_or_rehearsal();
    let (floor, derivation) = (
        next.min_base_fee,
        next.block_derivation.expect("the next rules derive the block"),
    );
    assert!(floor > 0);
    let genesis = prepare_genesis(spec, source.latest().unwrap().as_ref()).unwrap();
    let writer = source.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut coordinator = CanonicalCoordinator::attach(source.clone()).unwrap();
    let mut first_at_floor = None;
    loop {
        let parent = coordinator.head().clone();
        let number = parent.0.number + 1;
        let attributes = if number >= SWITCH {
            BlochNextBlockEnvCtx {
                timestamp: derivation.timestamp(parent.0.timestamp, 100 * number).unwrap(),
                prevrandao: derivation.prevrandao,
                anchor_root: B256::repeat_byte(0x22),
                deposits: vec![],
            }
        } else {
            BlochNextBlockEnvCtx {
                timestamp: parent.0.timestamp + 1,
                prevrandao: B256::repeat_byte(7),
                anchor_root: B256::repeat_byte(0x22),
                deposits: vec![],
            }
        };
        let head = coordinator
            .extend(parent.hash(), attributes, vec![])
            .unwrap_or_else(|e| panic!("block {number}: {e}"));
        if head.0.base_fee_per_gas == floor && first_at_floor.is_none() {
            first_at_floor = Some(number);
        }
        assert!(head.0.base_fee_per_gas >= floor || number < SWITCH);
        if first_at_floor.is_some_and(|first| number >= first + 3) {
            return (number, first_at_floor.unwrap());
        }
        assert!(number < 700, "the fee reaches the floor in about 575 blocks");
    }
}

#[test]
fn r406_8_the_canonical_replay_and_the_settlement_audit_cross_the_base_fee_floor() {
    let directory = tempfile::tempdir().unwrap();
    let spec = chain(true);
    let source = open(&directory.path().join("source"), spec.clone());
    let (height, first_at_floor) = build(&source, &spec);
    assert!(
        first_at_floor > 500 && height == first_at_floor + 3,
        "floor at {first_at_floor}, head {height}"
    );
    let head = source.sealed_header(height).unwrap().unwrap();
    let floor_fee = ChainSpec::mainnet_next_or_rehearsal().min_base_fee;
    // The blocks at the floor are blocks the BASE rules would not link: their step is under it.
    let at_floor = source.sealed_header(first_at_floor + 1).unwrap().unwrap();
    assert_eq!(at_floor.0.base_fee_per_gas, floor_fee);
    assert!(ChainSpec::mainnet_v1().next_base_fee(floor_fee, 0) < floor_fee);
    let floor = ReplayFloor {
        number: height,
        hash: head.hash(),
    };

    // 1. The canonical replay (validate_and_execute_block -> BlochConsensus) into fresh storage.
    let target = open(&directory.path().join("target"), spec.clone());
    let outcome = replay_canonical_prefix_with_limits(&source, &target, Some(floor), ReplayLimits::default())
        .unwrap_or_else(|e| panic!("replay across the floor: {e}"));
    assert_eq!((outcome.blocks, outcome.head.hash()), (height, head.hash()));
    assert_eq!(target.best_block_number().unwrap(), height);
    assert_eq!(
        target.sealed_header(first_at_floor).unwrap().unwrap(),
        source.sealed_header(first_at_floor).unwrap().unwrap()
    );

    // 2. The canonical settlement audit: its snapshot links every block to its parent before the consumer
    //    runs. The consumer audits nothing here, so the audit ends "incomplete": AFTER the snapshot was taken.
    let policy = SettlementPolicyV1 {
        network: B256::repeat_byte(1),
        genesis: B256::repeat_byte(2),
        domain: spec.domain(),
        configuration: configuration_commitment(spec.execution()).unwrap(),
        program_elf_keccak: B256::repeat_byte(5),
        program_vkey_koalabear: B256::repeat_byte(6),
        program_vkey_bn254: B256::repeat_byte(7),
        proof_policy: B256::repeat_byte(8),
        chain_id: spec.execution().chain_id,
        first_l2_number: 1,
        initial_l2_parent_hash: spec.genesis_hash(),
        initial_l2_state_root: spec.genesis_header().0.state_root,
    };
    let mut snapshot_taken = false;
    let audit = with_canonical_settlement_audit(&source, policy, floor, ReplayLimits::default(), |_| {
        snapshot_taken = true;
        Ok::<(), ()>(())
    });
    assert!(
        snapshot_taken,
        "the snapshot links all {height} blocks, the ones at the floor included: {audit:?}"
    );
    match audit {
        Err(CanonicalSettlementAuditErrorV1::Canonical(error)) => {
            assert!(error.to_string().contains("incomplete"), "{error}")
        }
        other => panic!("an audit of no record is incomplete: {other:?}"),
    }

    // Not vacuous: the same storage read with a schedule that was never switched (every block judged on the
    // base rules) is refused by both readers, before the audit's consumer runs.
    drop(source);
    let unswitched = chain(false);
    let source = open(&directory.path().join("source"), unswitched.clone());
    let other = open(&directory.path().join("target-unswitched"), unswitched);
    assert!(replay_canonical_prefix_with_limits(&source, &other, Some(floor), ReplayLimits::default()).is_err());
    let mut reached = false;
    let audit = with_canonical_settlement_audit(&source, policy, floor, ReplayLimits::default(), |_| {
        reached = true;
        Ok::<(), ()>(())
    });
    assert!(
        audit.is_err() && !reached,
        "on the base rules the links at the floor do not hold"
    );
}
