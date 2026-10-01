// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real V2 storage with synthetic native provenance and an explicit proof double.
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{keccak256, Address, Signature, TxKind, B256};
use bloch_l2_evm::{
    native_settlement::{
        store::{SettlementReplayRecordV1, SettlementStoreMarkV1, SettlementStoreReplayErrorV1, SettlementStoreV1},
        AcceptedSettlementV1, SettlementExpectationV1, SettlementPolicyV1, SettlementProofVerifierV1,
        SettlementTransactionV1, SETTLEMENT_PROOF_V1_BYTES,
    },
    proof_statement::{configuration_commitment, SettlementStatementV2},
    ChainSpec, DepositMint, DepositProvenance,
};
use bloch_reth_execution::{
    prepare_genesis,
    settlement_binding::{with_canonical_settlement_audit, CanonicalSettlementAuditErrorV1},
    BlochChainSpec, BlochNextBlockEnvCtx, BlochProviderFactory, BlochTables, CanonicalCoordinator, ReplayFloor,
    ReplayLimits,
};
use k256::ecdsa::SigningKey;
use reth_chainspec::EthChainSpec;
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_db_api::transaction::DbTxMut;
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockIdReader, BlockReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
};
use std::{fs, path::Path, sync::Arc};

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
        prevrandao: B256::ZERO,
        anchor_root: h(22),
        deposits: vec![],
    }
}
fn seed(source: &BlochProviderFactory) {
    let genesis = prepare_genesis(&spec(), source.latest().unwrap().as_ref()).unwrap();
    let writer = source.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut coordinator = CanonicalCoordinator::attach(source.clone()).unwrap();
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    let mut funding = attrs(1);
    funding.deposits.push(DepositMint {
        recipient: sender,
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 70,
            l1_tx_index: 0,
            l1_txid: [22; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    });
    coordinator.extend(coordinator.head().hash(), funding, vec![]).unwrap();
    let tx = TxEip1559 {
        chain_id: ChainSpec::testnet().chain_id,
        to: TxKind::Call(sender),
        gas_limit: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        ..Default::default()
    };
    let signature: Signature = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    coordinator
        .extend(
            coordinator.head().hash(),
            attrs(2),
            vec![tx.into_signed(signature).into()],
        )
        .unwrap();
}
fn policy() -> SettlementPolicyV1 {
    let spec = spec();
    SettlementPolicyV1 {
        network: h(1),
        genesis: h(2),
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
fn floor(source: &BlochProviderFactory) -> ReplayFloor {
    ReplayFloor {
        number: 2,
        hash: source.sealed_header(2).unwrap().unwrap().hash(),
    }
}
struct FixedProof;
impl SettlementProofVerifierV1 for FixedProof {
    fn verify(&self, policy: B256, _: &[u8], proof: &[u8]) -> bool {
        policy == h(8) && proof == [9; SETTLEMENT_PROOF_V1_BYTES]
    }
}
fn history(source: &BlochProviderFactory, path: &Path, wrong_first_body: bool) -> SettlementStoreMarkV1 {
    let p = policy();
    let mut store = SettlementStoreV1::create(path, p).unwrap();
    for number in 1..=2 {
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
            previous_settlement: store.registry().head().map_or(B256::ZERO, |head| head.commitment),
            chain_id: p.chain_id,
            l2_number: number,
            l2_parent_hash: header.parent_hash,
            l2_previous_state_root: header.parent_state_root,
            l2_header_hash: header.hash(),
            l2_state_root: header.state_root,
            l1_block: header.anchor_root,
            l1_slot: 80,
            l1_height: 70,
            source_commitment: h(23),
            inbox_root: h(24),
            inbox_count: 1,
            consumed_start: number - 1,
            consumed_end: 1,
            body_commitment: if number == 1 && wrong_first_body {
                h(99)
            } else {
                keccak256(alloy_rlp::encode(block.body.as_core()))
            },
        };
        let tx = SettlementTransactionV1::new(p.proof_policy, statement, [9; SETTLEMENT_PROOF_V1_BYTES]).unwrap();
        store
            .verify_and_commit(
                store.mark(),
                &tx.encode(),
                &SettlementExpectationV1 {
                    statement,
                    source_predecessor: store
                        .registry()
                        .head()
                        .map_or(B256::ZERO, |head| head.source_commitment),
                },
                &FixedProof,
            )
            .unwrap();
    }
    store.mark()
}

#[test]
fn binds_real_persisted_deposit_and_signed_transaction_blocks_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    let path = directory.path().join("settlements");
    let mark = history(&source, &path, false);
    let pinned = floor(&source);
    drop(source);
    let source = open(directory.path());
    let provider = CanonicalCoordinator::attach(source.clone()).unwrap().provider();
    assert_eq!(provider.finalized_block_num_hash().unwrap(), None);
    assert_eq!(provider.safe_block_num_hash().unwrap(), None);
    let (store, report) =
        with_canonical_settlement_audit(&source, policy(), pinned, ReplayLimits::default(), |audit| {
            SettlementStoreV1::open_verified_with_audit(&path, policy(), mark, 2, &FixedProof, |record| {
                audit.audit_record(&record)
            })
        })
        .unwrap();
    assert_eq!(store.mark(), mark);
    assert_eq!(report.audited_records, 2);
    assert_eq!(report.last_settlement.unwrap().hash, pinned.hash);
    assert_eq!(report.canonical_head.hash, pinned.hash);
    assert_eq!(report.genesis, spec().genesis_hash());
    assert!(report.canonical_bytes > 0);
    assert_eq!(provider.finalized_block_num_hash().unwrap(), None);
    assert_eq!(provider.safe_block_num_hash().unwrap(), None);
}

#[test]
fn rejects_old_body_mismatch_and_ignored_errors_without_exposing_store() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    let path = directory.path().join("settlements");
    let mark = history(&source, &path, true);
    let before: Vec<_> = (0..=2)
        .map(|i| fs::read(path.join(format!("{i:020}.sst"))).unwrap())
        .collect();
    let result = with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |audit| {
        SettlementStoreV1::open_verified_with_audit(&path, policy(), mark, 2, &FixedProof, |record| {
            audit.audit_record(&record)
        })
    });
    assert!(matches!(
        result,
        Err(CanonicalSettlementAuditErrorV1::Consumer(
            SettlementStoreReplayErrorV1::Audit { generation: 1, .. }
        ))
    ));
    let result = with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |audit| {
        SettlementStoreV1::open_verified_with_audit(&path, policy(), mark, 2, &FixedProof, |record| {
            assert!(audit.audit_record(&record).is_err());
            Ok::<(), ()>(()) // Deliberately broken caller; the outer boundary must refuse.
        })
    });
    assert!(matches!(result, Err(CanonicalSettlementAuditErrorV1::Canonical(_))));
    drop(SettlementStoreV1::open(&path, policy(), mark).unwrap());
    for (i, expected) in before.iter().enumerate() {
        assert_eq!(fs::read(path.join(format!("{i:020}.sst"))).unwrap(), *expected);
    }
}

#[test]
fn refuses_wrong_policy_floor_and_budgets_before_calling_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    for case in 0..10 {
        let mut p = policy();
        let mut f = floor(&source);
        let mut limits = ReplayLimits::default();
        match case {
            0 => p.domain = h(99),
            1 => p.configuration = h(99),
            2 => p.chain_id += 1,
            3 => p.initial_l2_parent_hash = h(99),
            4 => p.initial_l2_state_root = h(99),
            5 => p.first_l2_number = u64::MAX,
            6 => f.hash = h(99),
            7 => f.number = 3,
            8 => limits.blocks = 1,
            9 => limits.bytes = 0,
            _ => unreachable!(),
        }
        let result = with_canonical_settlement_audit(&source, p, f, limits, |_| -> Result<(), ()> {
            panic!("invalid preflight reached recovery")
        });
        assert!(
            matches!(result, Err(CanonicalSettlementAuditErrorV1::Canonical(_))),
            "case {case}"
        );
    }
    assert!(
        with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |_| Ok::<
            _,
            (),
        >(
            ()
        ))
        .is_err()
    );
}

#[test]
fn exact_statement_fields_and_record_order_must_match_the_canonical_block() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    let path = directory.path().join("settlements");
    let mark = history(&source, &path, false);
    for case in 0..17 {
        let result =
            with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |audit| {
                SettlementStoreV1::open_verified_with_audit(&path, policy(), mark, 2, &FixedProof, |record| {
                    let mut statement = *SettlementTransactionV1::decode(record.transaction).unwrap().statement();
                    let mut changed_mark = record.mark;
                    let mut proof_policy = h(8);
                    match case {
                        0 => statement.domain = h(99),
                        1 => statement.configuration = h(99),
                        2 => statement.chain_id += 1,
                        3 => statement.l2_header_hash = h(99),
                        4 => statement.l2_parent_hash = h(99),
                        5 => statement.l2_previous_state_root = h(99),
                        6 => statement.l2_state_root = h(99),
                        7 => statement.l1_block = h(99),
                        8 => statement.body_commitment = h(99),
                        9 => statement.consumed_end = 0,
                        10 => changed_mark.generation = 2,
                        11 => statement.network = h(99),
                        12 => statement.genesis = h(99),
                        13 => statement.program_elf_keccak = h(99),
                        14 => statement.program_vkey_koalabear = h(99),
                        15 => statement.program_vkey_bn254 = h(99),
                        16 => proof_policy = h(99),
                        _ => unreachable!(),
                    }
                    let tx = SettlementTransactionV1::new(proof_policy, statement, [9; SETTLEMENT_PROOF_V1_BYTES])
                        .unwrap()
                        .encode();
                    // Alter the supplied view, not the persisted history; public audit
                    // views are data and must never be treated as proof capabilities.
                    let accepted = AcceptedSettlementV1 {
                        commitment: SettlementTransactionV1::decode(&tx).unwrap().commitment(),
                        l2_header_hash: statement.l2_header_hash,
                        l2_state_root: statement.l2_state_root,
                        l1_block: statement.l1_block,
                        consumed_end: statement.consumed_end,
                        ..*record.accepted
                    };
                    audit.audit_record(&SettlementReplayRecordV1 {
                        mark: changed_mark,
                        accepted: &accepted,
                        transaction: &tx,
                        admission: record.admission,
                        evidence: record.evidence,
                        authority_audit: record.authority_audit,
                    })
                })
            });
        assert!(
            matches!(
                result,
                Err(CanonicalSettlementAuditErrorV1::Consumer(
                    SettlementStoreReplayErrorV1::Audit { generation: 1, .. }
                ))
            ),
            "case {case}"
        );
    }
}

#[test]
fn acknowledged_tip_change_discards_recovered_handle() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    let path = directory.path().join("settlements");
    let mark = history(&source, &path, false);
    let mut competing = CanonicalCoordinator::attach(source.clone()).unwrap();
    let result = with_canonical_settlement_audit(&source, policy(), floor(&source), ReplayLimits::default(), |audit| {
        let store = SettlementStoreV1::open_verified_with_audit(&path, policy(), mark, 2, &FixedProof, |record| {
            audit.audit_record(&record)
        })?;
        // Deliberately violate the stopped-writer contract to test the final fence.
        competing.extend(competing.head().hash(), attrs(3), vec![]).unwrap();
        Ok::<_, SettlementStoreReplayErrorV1<alloy_evm::block::BlockExecutionError>>(store)
    });
    assert!(matches!(result, Err(CanonicalSettlementAuditErrorV1::Canonical(_))));
    drop(SettlementStoreV1::open(&path, policy(), mark).unwrap());
}

#[test]
fn missing_complete_body_fails_before_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(directory.path());
    seed(&source);
    let pinned = floor(&source);
    let mut writer = source.database_provider_rw().unwrap();
    writer
        .tx_mut()
        .clear::<bloch_reth_execution::BlochV2Deposits>()
        .unwrap();
    writer.commit().unwrap();
    let result = with_canonical_settlement_audit(
        &source,
        policy(),
        pinned,
        ReplayLimits::default(),
        |_| -> Result<(), ()> { panic!("missing bodies reached recovery") },
    );
    assert!(matches!(result, Err(CanonicalSettlementAuditErrorV1::Canonical(_))));
}
