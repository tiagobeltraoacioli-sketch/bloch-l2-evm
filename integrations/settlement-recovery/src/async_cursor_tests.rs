// SPDX-License-Identifier: AGPL-3.0-or-later
//! Storage/lifecycle tests: real MDBX and executed Reth blocks, synthetic native
//! capabilities and proof bytes. This child module exists only under cfg(test).
//! These fixtures do not verify signatures, Groth16 proofs or native consensus;
//! the separate native FFG suite exercises the real verification boundary.
#![cfg(unix)]

use super::{NativeFinalityErrorV1, NativeFinalityReportV1, VerifiedNativeFinalityV1};
use crate::async_cursor::{
    recover_and_stage_async_finality_candidate as stage, stage_with_test_hook, AsyncFinalityCandidateErrorV1 as Error,
    AsyncFinalityCandidateRequestV1,
};
use alloy_primitives::{keccak256, B256};
use bloch_l2_evm::{
    l1::FinalizedCheckpoint,
    native_settlement::SettlementPolicyV1,
    proof_statement::{configuration_commitment, SettlementStatementV2},
    ChainSpec,
};
use bloch_pos_committee::l2_settlement::Transaction;
use bloch_reth_execution::{
    async_finality_cursor::{
        read_async_finality_candidate, AsyncFinalityCandidateCursorV1, BlochAsyncFinalityCandidate,
    },
    prepare_genesis, BlochChainSpec, BlochNextBlockEnvCtx, BlochProviderFactory, BlochTables, CanonicalCoordinator,
    ReplayFloor, ReplayLimits,
};
use reth_chainspec::EthChainSpec;
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_db_api::{
    tables::{ChainState, ChainStateKey},
    transaction::{DbTx, DbTxMut},
};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
};
use std::{collections::BTreeMap, path::Path, sync::Arc};

fn h(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}
fn spec() -> Arc<BlochChainSpec> {
    Arc::new(BlochChainSpec::new(ChainSpec::testnet(), h(0xd3), 0).unwrap())
}
fn open(path: &Path) -> BlochProviderFactory {
    ProviderFactory::new(
        Arc::new(init_db_for::<_, BlochTables>(path.join("db"), DatabaseArguments::test()).unwrap()),
        spec(),
        StaticFileProvider::read_write(path.join("static")).unwrap(),
        RocksDBBuilder::new(path.join("rocks"))
            .with_default_tables()
            .build()
            .unwrap(),
        reth_tasks::Runtime::test(),
    )
    .unwrap()
}
fn attrs(number: u64) -> BlochNextBlockEnvCtx {
    BlochNextBlockEnvCtx {
        timestamp: number,
        prevrandao: h(7),
        anchor_root: h(22),
        deposits: vec![],
    }
}
fn policy() -> SettlementPolicyV1 {
    let spec = spec();
    SettlementPolicyV1 {
        network: h(7),
        genesis: h(9),
        domain: spec.domain(),
        configuration: configuration_commitment(spec.execution()).unwrap(),
        program_elf_keccak: h(5),
        program_vkey_koalabear: h(6),
        program_vkey_bn254: h(7),
        proof_policy: h(8),
        chain_id: spec.execution().chain_id,
        first_l2_number: 1,
        initial_l2_parent_hash: spec.genesis_hash(),
        initial_l2_state_root: spec.genesis_header().0.state_root,
    }
}

struct Fixture {
    root: tempfile::TempDir,
    floor: ReplayFloor,
    transactions: Vec<Vec<u8>>,
}
impl Fixture {
    fn create() -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = open(root.path());
        let genesis = prepare_genesis(&spec(), source.latest().unwrap().as_ref()).unwrap();
        let writer = source.database_provider_rw().unwrap();
        writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
        writer.commit().unwrap();
        let mut coordinator = CanonicalCoordinator::attach(source.clone()).unwrap();
        let p = policy();
        let mut previous_settlement = B256::ZERO;
        let mut transactions = Vec::new();
        for number in 1..=2 {
            coordinator
                .extend(coordinator.head().hash(), attrs(number), vec![])
                .unwrap();
            let block = source.block_by_number(number).unwrap().unwrap();
            let header = &block.header.0;
            let statement = SettlementStatementV2 {
                network: p.network,
                genesis: p.genesis,
                domain: p.domain,
                configuration: p.configuration,
                program_elf_keccak: p.program_elf_keccak,
                program_vkey_koalabear: p.program_vkey_koalabear,
                program_vkey_bn254: p.program_vkey_bn254,
                previous_settlement,
                chain_id: p.chain_id,
                l2_number: number,
                l2_parent_hash: header.parent_hash,
                l2_previous_state_root: header.parent_state_root,
                l2_header_hash: header.hash(),
                l2_state_root: header.state_root,
                l1_block: header.anchor_root,
                l1_slot: 1,
                l1_height: 1,
                source_commitment: h(23),
                inbox_root: h(24),
                inbox_count: 0,
                consumed_start: 0,
                consumed_end: 0,
                body_commitment: keccak256(alloy_rlp::encode(block.body.as_core())),
            };
            let tx = Transaction {
                proof_policy: p.proof_policy.0,
                statement: statement.encode().to_vec(),
                // Deliberately invalid as a cryptographic proof. This fixture
                // tests only the consumer's storage and correspondence checks.
                proof: [9; bloch_pos_committee::l2_settlement::PROOF_BYTES],
            };
            previous_settlement = tx.commitment().into();
            transactions.push(tx.encode_async());
        }
        Self {
            root,
            floor: ReplayFloor {
                number: 2,
                hash: source.sealed_header(2).unwrap().unwrap().hash(),
            },
            transactions,
        }
    }

    fn request(&self, expected_cursor: Option<B256>) -> AsyncFinalityCandidateRequestV1 {
        AsyncFinalityCandidateRequestV1 {
            settlement_policy: policy(),
            l2_floor: self.floor,
            canonical_limits: ReplayLimits::default(),
            expected_cursor,
            current_epoch: 3,
        }
    }

    /// Synthetic capability available only to this child of the native module.
    /// Epoch checkpoints are the last blocks strictly before epoch * 32.
    fn synthetic_native(&self, finalized_epoch: u64, tail_variant: u8) -> VerifiedNativeFinalityV1 {
        assert!((1..=2).contains(&finalized_epoch));
        let chain = vec![
            (0, policy().genesis),
            (16, h(31)),
            (31, h(32)),
            (48, h(33 + tail_variant)),
            (63, h(34 + tail_variant)),
            (80, h(35 + tail_variant)),
        ];
        let finalized_index = finalized_epoch as usize * 2;
        VerifiedNativeFinalityV1 {
            report: NativeFinalityReportV1 {
                genesis_state_root: h(10),
                settlement_policy: policy().commitment().unwrap(),
                replayed_tip: chain.last().unwrap().1,
                replayed_state_root: h(36 + tail_variant),
                replayed_blocks: chain.len() - 1,
                replayed_slot: 80,
                finalized: FinalizedCheckpoint {
                    block: chain[finalized_index].1,
                    slot: chain[finalized_index].0,
                },
                finalized_epoch,
            },
            positions: chain
                .iter()
                .enumerate()
                .map(|(i, (slot, id))| (*id, (*slot, i)))
                .collect(),
            settlements: BTreeMap::from([
                (chain[1].1, self.transactions[0].clone()),
                (chain[3].1, self.transactions[1].clone()),
            ]),
            chain,
            finalized_index,
        }
    }
}

fn stored(source: &BlochProviderFactory) -> Option<AsyncFinalityCandidateCursorV1> {
    read_async_finality_candidate(source.database_provider_ro().unwrap().tx_ref()).unwrap()
}
fn put(source: &BlochProviderFactory, key: u64, cursor: AsyncFinalityCandidateCursorV1) {
    let writer = source.database_provider_rw().unwrap();
    writer.tx_ref().put::<BlochAsyncFinalityCandidate>(key, cursor).unwrap();
    writer.commit().unwrap();
}
fn no_numeric_finality(source: &BlochProviderFactory) {
    let reader = source.database_provider_ro().unwrap();
    for key in [ChainStateKey::LastSafeBlock, ChainStateKey::LastFinalizedBlock] {
        assert_eq!(reader.tx_ref().get::<ChainState>(key).unwrap(), None);
    }
}

#[test]
fn storage_candidate_advances_reopens_and_repeats_without_numeric_finality() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let first = stage(&source, fixture.request(None), &fixture.synthetic_native(1, 0)).unwrap();
    assert_eq!(first.cursor().fields().l2_number, 1);
    assert_eq!(first.canonical().audited_records, 1);
    let second = stage(
        &source,
        fixture.request(Some(first.cursor().commitment())),
        &fixture.synthetic_native(2, 0),
    )
    .unwrap();
    let cursor = second.cursor();
    assert_eq!(cursor.fields().l2_number, 2);
    assert_eq!(cursor.fields().settlement_count, 2);
    assert_eq!(cursor.fields().native_finalized_epoch, 2);
    assert_eq!(second.native().replayed_slot, 80);
    assert_ne!(cursor.commitment(), first.cursor().commitment());
    assert_eq!(stored(&source), Some(cursor));
    no_numeric_finality(&source);
    drop(source);
    let reopened = open(fixture.root.path());
    assert_eq!(stored(&reopened), Some(cursor));
    let repeated = stage(
        &reopened,
        fixture.request(Some(cursor.commitment())),
        &fixture.synthetic_native(2, 0),
    )
    .unwrap();
    assert_eq!(repeated.cursor(), cursor);
    no_numeric_finality(&reopened);
}

#[test]
fn storage_missing_stale_deleted_and_extra_rows_fail_closed() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let native = fixture.synthetic_native(2, 0);
    assert!(matches!(
        stage(&source, fixture.request(Some(h(99))), &native),
        Err(Error::CursorFloor)
    ));
    let cursor = stage(&source, fixture.request(None), &native).unwrap().cursor();
    for expected in [None, Some(h(99))] {
        assert!(matches!(
            stage(&source, fixture.request(expected), &native),
            Err(Error::CursorFloor)
        ));
        assert_eq!(stored(&source), Some(cursor));
    }
    put(&source, 1, cursor);
    assert!(matches!(
        stage(&source, fixture.request(Some(cursor.commitment())), &native),
        Err(Error::Storage(_))
    ));
    let writer = source.database_provider_rw().unwrap();
    writer.tx_ref().clear::<BlochAsyncFinalityCandidate>().unwrap();
    writer.commit().unwrap();
    assert!(matches!(
        stage(&source, fixture.request(Some(cursor.commitment())), &native),
        Err(Error::CursorFloor)
    ));
    assert_eq!(stored(&source), None);
    no_numeric_finality(&source);
}

#[test]
fn storage_forged_fields_are_rederived_even_with_a_matching_claimed_commitment() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let native = fixture.synthetic_native(2, 0);
    let cursor = stage(&source, fixture.request(None), &native).unwrap().cursor();
    for case in 0..16 {
        let mut fields = *cursor.fields();
        match case {
            0 => fields.native_genesis_state_root = h(99),
            1 => fields.settlement_policy = h(99),
            2 => fields.native_finalized_block = h(99),
            3 => fields.native_settlement_block = h(99),
            4 => fields.settlement_prefix_digest = h(99),
            5 => fields.l2_genesis = h(99),
            6 => fields.l2_hash = h(99),
            7 => fields.l2_state_root = h(99),
            8 => fields.native_settlement_digest = h(99),
            9 => fields.native_finalized_epoch += 1,
            10 => fields.native_finalized_slot += 1,
            11 => fields.native_settlement_slot += 1,
            12 => fields.l2_number += 1,
            13 => fields.settlement_count += 1,
            14 => fields.checked_at_epoch += 1,
            15 => fields.checked_at_epoch = 1,
            _ => unreachable!(),
        }
        let forged = AsyncFinalityCandidateCursorV1::from_fields(fields).unwrap();
        put(&source, 0, forged);
        assert!(
            stage(&source, fixture.request(Some(forged.commitment())), &native).is_err(),
            "forged field case {case}"
        );
        assert_eq!(stored(&source), Some(forged));
    }
    no_numeric_finality(&source);
}

#[test]
fn storage_finalized_checkpoint_cannot_regress_or_move_to_a_conflicting_branch() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let cursor = stage(&source, fixture.request(None), &fixture.synthetic_native(2, 0))
        .unwrap()
        .cursor();
    for native in [fixture.synthetic_native(1, 0), fixture.synthetic_native(2, 10)] {
        assert!(matches!(
            stage(&source, fixture.request(Some(cursor.commitment())), &native),
            Err(Error::Native(NativeFinalityErrorV1::NotFinalized))
        ));
        assert_eq!(stored(&source), Some(cursor));
    }
    no_numeric_finality(&source);
}

#[test]
fn storage_previously_unfinalized_native_tail_may_reorganize() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let prior_native = fixture.synthetic_native(1, 0);
    let cursor = stage(&source, fixture.request(None), &prior_native).unwrap().cursor();
    let changed_tail = fixture.synthetic_native(2, 10);
    assert_ne!(prior_native.report.replayed_tip, changed_tail.report.replayed_tip);
    let next = stage(&source, fixture.request(Some(cursor.commitment())), &changed_tail)
        .unwrap()
        .cursor();
    assert_eq!(next.fields().settlement_count, 2);
    assert_eq!(next.fields().native_finalized_block, h(44));
    assert_eq!(stored(&source), Some(next));
    no_numeric_finality(&source);
}

#[test]
fn storage_saved_cursor_cannot_omit_a_settlement_inside_its_finalized_prefix() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let first = stage(&source, fixture.request(None), &fixture.synthetic_native(1, 0))
        .unwrap()
        .cursor();
    let mut fields = *first.fields();
    fields.native_finalized_block = h(34);
    fields.native_finalized_epoch = 2;
    fields.native_finalized_slot = 63;
    let omitted = AsyncFinalityCandidateCursorV1::from_fields(fields).unwrap();
    put(&source, 0, omitted);
    assert!(matches!(
        stage(
            &source,
            fixture.request(Some(omitted.commitment())),
            &fixture.synthetic_native(2, 0)
        ),
        Err(Error::Previous)
    ));
    assert_eq!(stored(&source), Some(omitted));
}

#[test]
fn storage_native_replay_cannot_come_from_a_future_observation_epoch() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let mut request = fixture.request(None);
    request.current_epoch = 1;
    assert!(matches!(
        stage(&source, request, &fixture.synthetic_native(2, 0)),
        Err(Error::Native(NativeFinalityErrorV1::Trust))
    ));
    assert_eq!(stored(&source), None);
    no_numeric_finality(&source);
}

#[test]
fn storage_settlement_must_match_canonical_l2_state_and_complete_body() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    for change_state in [true, false] {
        let mut native = fixture.synthetic_native(2, 0);
        let mut tx = Transaction::decode_async(native.settlements.get(&h(31)).unwrap()).unwrap();
        let mut statement = SettlementStatementV2::decode(&tx.statement).unwrap();
        if change_state {
            statement.l2_state_root = h(99);
        } else {
            statement.body_commitment = h(99);
        }
        tx.statement = statement.encode().to_vec();
        native.settlements.insert(h(31), tx.encode_async());
        assert!(matches!(
            stage(&source, fixture.request(None), &native),
            Err(Error::Audit(_))
        ));
        assert_eq!(stored(&source), None);
    }
    // Even the original settlement is refused when a complete persisted body
    // disappears. Absence is not silently interpreted as an empty block.
    let writer = source.database_provider_rw().unwrap();
    writer
        .tx_ref()
        .clear::<bloch_reth_execution::BlochV2Deposits>()
        .unwrap();
    writer.commit().unwrap();
    assert!(matches!(
        stage(&source, fixture.request(None), &fixture.synthetic_native(2, 0)),
        Err(Error::Audit(_))
    ));
    assert_eq!(stored(&source), None);
    no_numeric_finality(&source);
}

#[test]
fn storage_competing_cursor_between_audit_and_commit_is_not_overwritten() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let native = fixture.synthetic_native(2, 0);
    let cursor = stage(&source, fixture.request(None), &native).unwrap().cursor();
    let mut fields = *cursor.fields();
    fields.checked_at_epoch = 4;
    let competing = AsyncFinalityCandidateCursorV1::from_fields(fields).unwrap();
    let result = stage_with_test_hook(&source, fixture.request(Some(cursor.commitment())), &native, || {
        put(&source, 0, competing);
    });
    assert!(matches!(result, Err(Error::Changed)));
    assert_eq!(stored(&source), Some(competing));
    no_numeric_finality(&source);
}

#[test]
fn storage_canonical_tip_change_between_audit_and_commit_aborts_publication() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let mut competing = CanonicalCoordinator::attach(source.clone()).unwrap();
    let result = stage_with_test_hook(&source, fixture.request(None), &fixture.synthetic_native(2, 0), || {
        competing.extend(competing.head().hash(), attrs(3), vec![]).unwrap();
    });
    assert!(matches!(result, Err(Error::Changed)));
    assert_eq!(stored(&source), None);
    no_numeric_finality(&source);
}

#[test]
fn storage_numeric_finality_markers_are_rejected_before_audit_and_at_commit() {
    for key in [ChainStateKey::LastSafeBlock, ChainStateKey::LastFinalizedBlock] {
        let fixture = Fixture::create();
        let source = open(fixture.root.path());
        let native = fixture.synthetic_native(2, 0);
        let result = stage_with_test_hook(&source, fixture.request(None), &native, || {
            let writer = source.database_provider_rw().unwrap();
            writer.tx_ref().put::<ChainState>(key.clone(), 1).unwrap();
            writer.commit().unwrap();
        });
        assert!(matches!(result, Err(Error::Changed)));
        assert_eq!(stored(&source), None);
        assert!(matches!(
            stage(&source, fixture.request(None), &native),
            Err(Error::Storage(_))
        ));
        assert_eq!(stored(&source), None);
        let reader = source.database_provider_ro().unwrap();
        assert_eq!(reader.tx_ref().get::<ChainState>(key).unwrap(), Some(1));
    }
}
