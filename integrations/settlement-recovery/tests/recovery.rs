// SPDX-License-Identifier: AGPL-3.0-or-later
//! Combined real Reth storage and disposable PQ signatures; execution proof is a double.
#![cfg(unix)]

use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxKind, B256};
use bloch_l2_evm::{
    l1::TransactionInclusionEvidenceV1,
    native_settlement::{
        store::{SettlementStoreMarkV1, SettlementStoreV1},
        SettlementExpectationV1, SettlementPolicyV1, SettlementProofVerifierV1, SettlementTransactionV1,
        SETTLEMENT_PROOF_V1_BYTES,
    },
    proof_statement::{configuration_commitment, SettlementStatementV2},
    settlement_admission::SettlementAdmissionExpectationV1,
    ChainSpec, DepositMint, DepositProvenance,
};
use bloch_native_escrow_pq::{
    checkpoint::{CheckpointPolicy, Phase},
    checkpoint_store::{CheckpointMark, CheckpointStore, StoreError as CheckpointStoreError},
    settlement_authority::{bind_settlement_checkpoint_authority, SettlementAuthorityStoreErrorV1},
};
use bloch_pos_committee::{
    derive::body_root,
    header::{BlockHeaderV4, BlockId},
    ws::{self, CheckpointEnvelope, Signer, SignerSet, WeakSubjectivityCheckpoint},
};
use bloch_reth_execution::finality_cursor::{
    read_finality_candidate, BlochFinalityCandidate, FinalityCandidateCursorV1,
};
use bloch_reth_execution::{
    prepare_genesis, settlement_binding::CanonicalSettlementAuditErrorV1, BlochChainSpec, BlochNextBlockEnvCtx,
    BlochProviderFactory, BlochTables, CanonicalCoordinator, ReplayFloor, ReplayLimits,
};
use bloch_settlement_recovery::cursor::{recover_and_stage_finality_candidate, FinalityCandidateErrorV1};
use bloch_settlement_recovery::{
    recover_canonical_settlements, SettlementRecoveryErrorV1, SettlementRecoveryRequestV1,
};
use k256::ecdsa::SigningKey;
use reth_chainspec::EthChainSpec;
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_db_api::transaction::DbTxMut;
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockIdReader, BlockReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
};
use std::{
    cell::{Cell, RefCell},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

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
fn keys() -> &'static Vec<(Vec<u8>, Vec<u8>)> {
    static KEYS: OnceLock<Vec<(Vec<u8>, Vec<u8>)>> = OnceLock::new();
    KEYS.get_or_init(|| (0..3).map(|_| bloch_crypto::crypto::generate_keypair()).collect())
}
fn checkpoint_policy() -> CheckpointPolicy {
    let set = SignerSet {
        id: 1,
        signers: keys()
            .iter()
            .enumerate()
            .map(|(index, key)| Signer {
                pubkey: key.0[4..].try_into().unwrap(),
                external: index == 2,
            })
            .collect(),
        threshold: 2,
        min_external: 1,
        adopted_epoch: 50,
    };
    CheckpointPolicy::new(7, [9; 32], set, Phase::A).unwrap()
}
fn checkpoint(transactions: &[Bytes], epoch: u64) -> (CheckpointEnvelope, Vec<u8>) {
    let mut header = vec![0; 304];
    header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    header[36..68].fill(11);
    let body = transactions.iter().map(|tx| tx.to_vec()).collect::<Vec<_>>();
    header[68..100].copy_from_slice(&body_root(&body));
    header[100..108].copy_from_slice(&(epoch * 120).to_le_bytes());
    let native = BlockHeaderV4::canonical_deserialize(&header).unwrap();
    let checkpoint = WeakSubjectivityCheckpoint {
        version: ws::WS_FORMAT_VERSION,
        network_id: 7,
        genesis_root: [9; 32],
        epoch,
        block_root: *BlockId::of(&native).as_bytes(),
        state_root: native.state_root,
        validator_set_root: [12; 32],
        issued_at: 12345,
        signer_set_id: 1,
    };
    let digest = checkpoint.ws_digest();
    let signatures = [0u8, 2]
        .into_iter()
        .map(|index| {
            let signature = bloch_crypto::crypto::sign(&keys()[index as usize].1, &digest).unwrap();
            (index, signature[4..].to_vec())
        })
        .collect();
    (CheckpointEnvelope { checkpoint, signatures }, header)
}

#[derive(Default)]
struct FixedProof {
    calls: Cell<u64>,
    reject: Option<u64>,
}
impl SettlementProofVerifierV1 for FixedProof {
    fn verify(&self, policy: B256, values: &[u8], proof: &[u8]) -> bool {
        let call = self.calls.get() + 1;
        self.calls.set(call);
        policy == h(8)
            && SettlementStatementV2::decode(values).is_ok()
            && proof == [9; SETTLEMENT_PROOF_V1_BYTES]
            && self.reject != Some(call)
    }
}
#[derive(Clone, Copy)]
enum FirstRecord {
    Valid,
    WrongBody,
    MissingAuthority,
}
struct Fixture {
    root: tempfile::TempDir,
    checkpoints: PathBuf,
    settlements: PathBuf,
    checkpoint_floor: CheckpointMark,
    settlement_floor: SettlementStoreMarkV1,
    l2_floor: ReplayFloor,
    first_checkpoint_floor: CheckpointMark,
    first_settlement_floor: SettlementStoreMarkV1,
}
impl Fixture {
    fn create(first: FirstRecord) -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = open(root.path());
        seed(&source);
        let checkpoints = root.path().join("checkpoints");
        let settlements = root.path().join("settlements");
        let mut checkpoint_store = CheckpointStore::create(&checkpoints, checkpoint_policy()).unwrap();
        let p = policy();
        let mut settlement_store = SettlementStoreV1::create(&settlements, p).unwrap();
        let mut first_marks = None;
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
                previous_settlement: settlement_store
                    .registry()
                    .head()
                    .map_or(B256::ZERO, |head| head.commitment),
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
                body_commitment: if number == 1 && matches!(first, FirstRecord::WrongBody) {
                    h(99)
                } else {
                    keccak256(alloy_rlp::encode(block.body.as_core()))
                },
            };
            let transaction = SettlementTransactionV1::new(p.proof_policy, statement, [9; SETTLEMENT_PROOF_V1_BYTES])
                .unwrap()
                .encode();
            let transactions = vec![Bytes::from_static(b"unrelated"), Bytes::copy_from_slice(&transaction)];
            let epoch = 98 + number * 2;
            let (envelope, native_header) = checkpoint(&transactions, epoch);
            checkpoint_store.accept(&envelope, &native_header, epoch + 1).unwrap();
            let verified = checkpoint_store.current(epoch + 1).unwrap();
            let expectation = SettlementExpectationV1 {
                statement,
                source_predecessor: settlement_store
                    .registry()
                    .head()
                    .map_or(B256::ZERO, |head| head.source_commitment),
            };
            let mark = settlement_store.mark();
            if number == 1 && matches!(first, FirstRecord::MissingAuthority) {
                settlement_store
                    .verify_and_commit(mark, &transaction, &expectation, &FixedProof::default())
                    .unwrap();
            } else {
                let expected = SettlementAdmissionExpectationV1 {
                    settlement: expectation,
                    block: verified.anchor().block,
                    slot: verified.anchor().slot,
                    checkpoint: verified.anchor(),
                    transaction_index: 1,
                };
                let evidence = TransactionInclusionEvidenceV1::new(
                    verified.anchor(),
                    vec![Bytes::from(native_header)],
                    transactions,
                )
                .unwrap();
                bind_settlement_checkpoint_authority(verified, evidence, &expected)
                    .unwrap()
                    .verify_and_commit(
                        &mut settlement_store,
                        mark,
                        &expected.settlement,
                        &FixedProof::default(),
                    )
                    .unwrap();
            }
            if number == 1 {
                first_marks = Some((checkpoint_store.mark().unwrap(), settlement_store.mark()));
            }
        }
        let l2_floor = ReplayFloor {
            number: 2,
            hash: source.sealed_header(2).unwrap().unwrap().hash(),
        };
        Self {
            root,
            checkpoints,
            settlements,
            l2_floor,
            checkpoint_floor: checkpoint_store.mark().unwrap(),
            settlement_floor: settlement_store.mark(),
            first_checkpoint_floor: first_marks.unwrap().0,
            first_settlement_floor: first_marks.unwrap().1,
        }
    }
    fn request(&self) -> SettlementRecoveryRequestV1<'_> {
        SettlementRecoveryRequestV1 {
            checkpoint_path: &self.checkpoints,
            checkpoint_policy: checkpoint_policy(),
            checkpoint_floor: self.checkpoint_floor,
            settlement_path: &self.settlements,
            settlement_policy: policy(),
            settlement_floor: self.settlement_floor,
            l2_floor: self.l2_floor,
            current_epoch: 103,
            maximum_proofs: 2,
            canonical_limits: ReplayLimits::default(),
        }
    }
    fn bytes(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut paths = [&self.checkpoints, &self.settlements]
            .into_iter()
            .flat_map(|path| fs::read_dir(path).unwrap().map(|entry| entry.unwrap().path()))
            .collect::<Vec<_>>();
        paths.sort();
        paths
            .into_iter()
            .map(|path| {
                let data = fs::read(&path).unwrap();
                (path, data)
            })
            .collect()
    }
    fn assert_unlocked(&self) {
        drop(CheckpointStore::open(&self.checkpoints, checkpoint_policy(), Some(self.checkpoint_floor)).unwrap());
        drop(SettlementStoreV1::open(&self.settlements, policy(), self.settlement_floor).unwrap());
    }
}

fn stored_candidate(source: &BlochProviderFactory) -> Option<FinalityCandidateCursorV1> {
    let reader = source.database_provider_ro().unwrap();
    read_finality_candidate(reader.tx_ref()).unwrap()
}

#[test]
fn candidate_is_durable_monotonic_and_reverified_when_histories_advance() {
    let fixture = Fixture::create(FirstRecord::Valid);
    let source = open(fixture.root.path());
    let original = fixture.bytes();
    let pending_cp = fixture.root.path().join("pending-checkpoint");
    let pending_settlement = fixture.root.path().join("pending-settlement");
    let last_cp = fixture.checkpoints.join(format!("{:020}.ckp", 102));
    let last_settlement = fixture.settlements.join(format!("{:020}.sst", 2));
    fs::rename(&last_cp, &pending_cp).unwrap();
    fs::rename(&last_settlement, &pending_settlement).unwrap();
    let mut request = fixture.request();
    request.checkpoint_floor = fixture.first_checkpoint_floor;
    request.settlement_floor = fixture.first_settlement_floor;
    let verifier = FixedProof::default();
    let staged = recover_and_stage_finality_candidate(&source, request, &verifier, None).unwrap();
    let first = staged.cursor();
    assert_eq!(first.fields().l2_number, 1);
    assert_eq!(stored_candidate(&source), Some(first));
    drop(staged);
    fs::rename(&pending_cp, &last_cp).unwrap();
    fs::rename(&pending_settlement, &last_settlement).unwrap();
    let staged =
        recover_and_stage_finality_candidate(&source, fixture.request(), &verifier, Some(first.commitment())).unwrap();
    let second = staged.cursor();
    assert_eq!(second.fields().l2_number, 2);
    assert_ne!(first.commitment(), second.commitment());
    drop(staged);
    drop(source);
    let source = open(fixture.root.path());
    let staged =
        recover_and_stage_finality_candidate(&source, fixture.request(), &verifier, Some(second.commitment())).unwrap();
    assert_eq!(staged.cursor(), second);
    assert_eq!(verifier.calls.get(), 5); // 1 + 2 + 2, including records below the new floor.
    let provider = CanonicalCoordinator::attach(source.clone()).unwrap().provider();
    assert_eq!(provider.finalized_block_num_hash().unwrap(), None);
    assert_eq!(provider.safe_block_num_hash().unwrap(), None);
    drop(staged.into_recovery());
    fixture.assert_unlocked();
    fs::rename(&last_cp, &pending_cp).unwrap();
    fs::rename(&last_settlement, &pending_settlement).unwrap();
    let mut rolled_back = fixture.request();
    rolled_back.checkpoint_floor = fixture.first_checkpoint_floor;
    rolled_back.settlement_floor = fixture.first_settlement_floor;
    assert!(recover_and_stage_finality_candidate(&source, rolled_back, &verifier, Some(second.commitment())).is_err());
    assert_eq!(stored_candidate(&source), Some(second));
    fs::rename(pending_cp, last_cp).unwrap();
    fs::rename(pending_settlement, last_settlement).unwrap();
    fixture.assert_unlocked();
    assert_eq!(fixture.bytes(), original);
}

#[test]
fn matching_cursor_bytes_never_replace_mandatory_evidence_reverification() {
    let fixture = Fixture::create(FirstRecord::Valid);
    let source = open(fixture.root.path());
    let staged =
        recover_and_stage_finality_candidate(&source, fixture.request(), &FixedProof::default(), None).unwrap();
    let original = staged.cursor();
    drop(staged);
    let before = fixture.bytes();
    for case in 0..9 {
        let mut fields = *original.fields();
        match case {
            0 => fields.l2_hash = h(99),
            1 => fields.l2_state_root = h(99),
            2 => fields.settlement_record_digest = h(99),
            3 => fields.settlement_generation = 3,
            4 => fields.checkpoint_digest = h(99),
            5 => fields.checkpoint_policy = h(99),
            6 => fields.checked_at_epoch = 104,
            7 => fields.settlement_policy = h(99),
            8 => fields.l2_genesis = h(99),
            _ => unreachable!(),
        }
        let forged = FinalityCandidateCursorV1::from_fields(fields).unwrap();
        let writer = source.database_provider_rw().unwrap();
        writer.tx_ref().put::<BlochFinalityCandidate>(0, forged).unwrap();
        writer.commit().unwrap();
        // Even a matching claimed floor cannot turn decoded audit data into authority.
        assert!(
            recover_and_stage_finality_candidate(
                &source,
                fixture.request(),
                &FixedProof::default(),
                Some(forged.commitment())
            )
            .is_err(),
            "case {case}"
        );
        assert_eq!(stored_candidate(&source), Some(forged));
        fixture.assert_unlocked();
    }
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn missing_foreign_and_stale_cursor_rows_fail_before_proof_replay() {
    let fixture = Fixture::create(FirstRecord::Valid);
    let source = open(fixture.root.path());
    let staged =
        recover_and_stage_finality_candidate(&source, fixture.request(), &FixedProof::default(), None).unwrap();
    let cursor = staged.cursor();
    drop(staged);
    let verifier = FixedProof::default();
    for expected in [None, Some(h(99))] {
        assert!(matches!(
            recover_and_stage_finality_candidate(&source, fixture.request(), &verifier, expected),
            Err(FinalityCandidateErrorV1::CursorFloor)
        ));
    }
    let writer = source.database_provider_rw().unwrap();
    writer.tx_ref().put::<BlochFinalityCandidate>(1, cursor).unwrap();
    writer.commit().unwrap();
    assert!(matches!(
        recover_and_stage_finality_candidate(&source, fixture.request(), &verifier, Some(cursor.commitment())),
        Err(FinalityCandidateErrorV1::Storage(_))
    ));
    let mut writer = source.database_provider_rw().unwrap();
    writer.tx_mut().clear::<BlochFinalityCandidate>().unwrap();
    writer.commit().unwrap();
    assert!(matches!(
        recover_and_stage_finality_candidate(&source, fixture.request(), &verifier, Some(cursor.commitment())),
        Err(FinalityCandidateErrorV1::CursorFloor)
    ));
    assert_eq!(verifier.calls.get(), 0);
    fixture.assert_unlocked();
}

#[test]
fn proof_failure_and_checkpoint_expiry_preserve_the_saved_candidate() {
    let fixture = Fixture::create(FirstRecord::Valid);
    let source = open(fixture.root.path());
    let staged =
        recover_and_stage_finality_candidate(&source, fixture.request(), &FixedProof::default(), None).unwrap();
    let cursor = staged.cursor();
    drop(staged);
    let before = fixture.bytes();
    let reject = FixedProof {
        calls: Cell::new(0),
        reject: Some(2),
    };
    assert!(matches!(
        recover_and_stage_finality_candidate(&source, fixture.request(), &reject, Some(cursor.commitment())),
        Err(FinalityCandidateErrorV1::Recovery(_))
    ));
    assert_eq!(reject.calls.get(), 2);
    let mut request = fixture.request();
    request.current_epoch += ws::WS_PERIOD_EPOCHS;
    assert!(matches!(
        recover_and_stage_finality_candidate(&source, request, &FixedProof::default(), Some(cursor.commitment())),
        Err(FinalityCandidateErrorV1::Freshness)
    ));
    assert_eq!(stored_candidate(&source), Some(cursor));
    assert_eq!(fixture.bytes(), before);
    fixture.assert_unlocked();
}

#[test]
fn concurrent_cursor_replacement_is_not_overwritten_after_successful_replay() {
    struct ReplacingProof<'a> {
        source: &'a BlochProviderFactory,
        replacement: FinalityCandidateCursorV1,
        inner: FixedProof,
    }
    impl SettlementProofVerifierV1 for ReplacingProof<'_> {
        fn verify(&self, policy: B256, values: &[u8], proof: &[u8]) -> bool {
            if self.inner.calls.get() == 0 {
                let writer = self.source.database_provider_rw().unwrap();
                writer
                    .tx_ref()
                    .put::<BlochFinalityCandidate>(0, self.replacement)
                    .unwrap();
                writer.commit().unwrap();
            }
            self.inner.verify(policy, values, proof)
        }
    }
    let fixture = Fixture::create(FirstRecord::Valid);
    let source = open(fixture.root.path());
    let staged =
        recover_and_stage_finality_candidate(&source, fixture.request(), &FixedProof::default(), None).unwrap();
    let cursor = staged.cursor();
    drop(staged);
    let mut fields = *cursor.fields();
    fields.checked_at_epoch += 1;
    let replacement = FinalityCandidateCursorV1::from_fields(fields).unwrap();
    let verifier = ReplacingProof {
        source: &source,
        replacement,
        inner: FixedProof::default(),
    };
    assert!(matches!(
        recover_and_stage_finality_candidate(&source, fixture.request(), &verifier, Some(cursor.commitment())),
        Err(FinalityCandidateErrorV1::Changed)
    ));
    assert_eq!(verifier.inner.calls.get(), 2);
    assert_eq!(stored_candidate(&source), Some(replacement));
    fixture.assert_unlocked();
}

#[test]
fn combined_recovery_reopens_real_blocks_and_pq_history_without_publishing_finality() {
    let fixture = Fixture::create(FirstRecord::Valid);
    let source = open(fixture.root.path());
    let before = fixture.bytes();
    let provider = CanonicalCoordinator::attach(source.clone()).unwrap().provider();
    let verifier = FixedProof::default();
    for current_epoch in [103, 103 + ws::WS_PERIOD_EPOCHS] {
        let mut request = fixture.request();
        request.current_epoch = current_epoch;
        let recovered = recover_canonical_settlements(&source, request, &verifier).unwrap();
        assert_eq!(recovered.report().audited_records, 2);
        assert_eq!(recovered.report().last_settlement.unwrap().hash, fixture.l2_floor.hash);
        assert_eq!(recovered.report().policy_commitment, policy().commitment().unwrap());
        assert_eq!(recovered.stores().settlement_store().mark(), fixture.settlement_floor);
        assert_eq!(
            recovered.stores().checkpoint_store().mark(),
            Some(fixture.checkpoint_floor)
        );
        assert!(matches!(
            CheckpointStore::open(
                &fixture.checkpoints,
                checkpoint_policy(),
                Some(fixture.checkpoint_floor)
            ),
            Err(CheckpointStoreError::Locked)
        ));
        assert!(SettlementStoreV1::open(&fixture.settlements, policy(), fixture.settlement_floor).is_err());
        if current_epoch > 103 {
            assert!(recovered.stores().checkpoint_store().current(current_epoch).is_err());
        }
        assert_eq!(provider.finalized_block_num_hash().unwrap(), None);
        assert_eq!(provider.safe_block_num_hash().unwrap(), None);
        drop(recovered.into_stores());
        fixture.assert_unlocked();
    }
    assert_eq!(verifier.calls.get(), 4);
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn a_valid_latest_record_cannot_hide_missing_authority_or_an_older_block_mismatch() {
    for first in [FirstRecord::MissingAuthority, FirstRecord::WrongBody] {
        let fixture = Fixture::create(first);
        let source = open(fixture.root.path());
        let before = fixture.bytes();
        let verifier = FixedProof::default();
        let result = recover_canonical_settlements(&source, fixture.request(), &verifier);
        let Err(SettlementRecoveryErrorV1::Verification(CanonicalSettlementAuditErrorV1::Consumer(
            SettlementAuthorityStoreErrorV1::History { generation: 1, error },
        ))) = result
        else {
            panic!("older record escaped mandatory combined recovery")
        };
        match first {
            FirstRecord::MissingAuthority => assert!(matches!(*error, SettlementAuthorityStoreErrorV1::Missing)),
            FirstRecord::WrongBody => assert!(matches!(*error, SettlementAuthorityStoreErrorV1::AdditionalAudit(_))),
            FirstRecord::Valid => unreachable!(),
        }
        assert_eq!(verifier.calls.get(), 1);
        assert_eq!(fixture.bytes(), before);
        fixture.assert_unlocked();
    }
}

#[test]
fn rejects_changed_pq_signature_before_execution_proof_replay() {
    let fixture = Fixture::create(FirstRecord::Valid);
    let source = open(fixture.root.path());
    let record = fixture.checkpoints.join(format!("{:020}.ckp", 100));
    let original = fs::read(&record).unwrap();
    let signature_start = 8 + 32 + ws::WS_CHECKPOINT_BYTES + 304 + 1 + 1 + 4;
    let mut corrupt = original.clone();
    corrupt[signature_start] ^= 1;
    fs::write(&record, corrupt).unwrap();
    let before = fixture.bytes();
    let verifier = FixedProof::default();
    assert!(matches!(
        recover_canonical_settlements(&source, fixture.request(), &verifier),
        Err(SettlementRecoveryErrorV1::Verification(
            CanonicalSettlementAuditErrorV1::Consumer(SettlementAuthorityStoreErrorV1::Checkpoint(
                CheckpointStoreError::Verify(_)
            ))
        ))
    ));
    assert_eq!(verifier.calls.get(), 0);
    assert_eq!(fixture.bytes(), before);
    // Restore only this disposable fixture; production recovery never repairs data.
    fs::write(record, original).unwrap();
    fixture.assert_unlocked();
}

#[test]
fn all_three_independent_floors_and_replay_budgets_are_required() {
    let fixture = Fixture::create(FirstRecord::Valid);
    let source = open(fixture.root.path());
    let before = fixture.bytes();
    for case in 0..6 {
        let mut request = fixture.request();
        match case {
            0 => request.checkpoint_floor.digest = h(99),
            1 => request.settlement_floor.record_digest = h(99),
            2 => request.l2_floor.hash = h(99),
            3 => request.maximum_proofs = 1,
            4 => request.canonical_limits.bytes = 1,
            5 => request.settlement_policy.genesis = h(99),
            _ => unreachable!(),
        }
        let verifier = FixedProof::default();
        let result = recover_canonical_settlements(&source, request, &verifier);
        if case == 5 {
            assert!(matches!(result, Err(SettlementRecoveryErrorV1::Policy)));
            assert_eq!(verifier.calls.get(), 0);
        } else {
            assert!(result.is_err(), "case {case}");
        }
        fixture.assert_unlocked();
    }
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn late_proof_refusal_releases_both_histories_without_partial_result() {
    let fixture = Fixture::create(FirstRecord::Valid);
    let source = open(fixture.root.path());
    let before = fixture.bytes();
    let verifier = FixedProof {
        calls: Cell::new(0),
        reject: Some(2),
    };
    assert!(matches!(
        recover_canonical_settlements(&source, fixture.request(), &verifier),
        Err(SettlementRecoveryErrorV1::Verification(
            CanonicalSettlementAuditErrorV1::Consumer(SettlementAuthorityStoreErrorV1::Settlement(_))
        ))
    ));
    assert_eq!(verifier.calls.get(), 2);
    assert_eq!(fixture.bytes(), before);
    fixture.assert_unlocked();
}

#[test]
fn canonical_advance_during_proof_replay_discards_both_recovered_handles() {
    struct AdvancingProof {
        inner: FixedProof,
        writer: RefCell<CanonicalCoordinator>,
    }
    impl SettlementProofVerifierV1 for AdvancingProof {
        fn verify(&self, policy: B256, values: &[u8], proof: &[u8]) -> bool {
            if self.inner.calls.get() == 0 {
                // Deliberately violate stopped-writer ownership to exercise the fence.
                let mut writer = self.writer.borrow_mut();
                let parent = writer.head().hash();
                writer.extend(parent, attrs(3), vec![]).unwrap();
            }
            self.inner.verify(policy, values, proof)
        }
    }
    let fixture = Fixture::create(FirstRecord::Valid);
    let source = open(fixture.root.path());
    let before = fixture.bytes();
    let verifier = AdvancingProof {
        inner: FixedProof::default(),
        writer: RefCell::new(CanonicalCoordinator::attach(source.clone()).unwrap()),
    };
    assert!(matches!(
        recover_canonical_settlements(&source, fixture.request(), &verifier),
        Err(SettlementRecoveryErrorV1::Verification(
            CanonicalSettlementAuditErrorV1::Canonical(_)
        ))
    ));
    assert_eq!(verifier.inner.calls.get(), 2);
    assert_eq!(fixture.bytes(), before);
    fixture.assert_unlocked();
}
