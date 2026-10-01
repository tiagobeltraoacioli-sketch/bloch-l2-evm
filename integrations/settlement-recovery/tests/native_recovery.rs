// SPDX-License-Identifier: AGPL-3.0-or-later
//! Actual native header/body, real Groth16, disposable hybrid-PQ quorum and Reth.
//! The WS signer arrangement is synthetic; this does not establish live FFG.
#![cfg(unix)]
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::{
    l1::TransactionInclusionEvidenceV1,
    native_settlement::{
        store::{SettlementStoreMarkV1, SettlementStoreV1},
        SettlementExpectationV1, SettlementPolicyV1, SettlementProofVerifierV1, SettlementTransactionV1,
        SettlementWireFormat,
    },
    proof_statement::{configuration_commitment, SettlementStatementV2},
    settlement_admission::SettlementAdmissionExpectationV1,
    ChainSpec,
};
use bloch_native_escrow_pq::{
    checkpoint::{CheckpointPolicy, Phase},
    checkpoint_store::{CheckpointMark, CheckpointStore},
    settlement_authority::bind_settlement_checkpoint_authority,
};
use bloch_pos_committee::{
    header::{BlockHeaderV4, BlockId},
    ws::{self, CheckpointEnvelope, Signer, SignerSet, WeakSubjectivityCheckpoint},
};
use bloch_reth_execution::{
    prepare_genesis, BlochChainSpec, BlochNextBlockEnvCtx, BlochProviderFactory, BlochTables, CanonicalCoordinator,
    ReplayFloor, ReplayLimits,
};
use bloch_settlement_recovery::{
    cursor::{recover_and_stage_finality_candidate, recover_and_stage_native_finality_candidate},
    proof::NativeGroth16Verifier,
    recover_canonical_native_settlements, recover_canonical_settlements, SettlementRecoveryRequestV1,
};
use reth_chainspec::EthChainSpec;
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_db_api::{
    tables::{ChainState, ChainStateKey},
    transaction::DbTx,
};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

const TX: &[u8] = include_bytes!("../../../tests/fixtures/native-settlement/transaction.bin");
const HEADER: &[u8] = include_bytes!("../../../tests/fixtures/native-settlement/header.bin");
const STATE: &[u8] = include_bytes!("../../../tests/fixtures/native-settlement/state-root.bin");
fn hash(value: &str) -> B256 {
    value.parse().unwrap()
}
fn statement() -> SettlementStatementV2 {
    *SettlementTransactionV1::decode_wire(TX).unwrap().0.statement()
}
fn spec() -> Arc<BlochChainSpec> {
    Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0xd3), 0).unwrap())
}
fn policy() -> SettlementPolicyV1 {
    let spec = spec();
    SettlementPolicyV1 {
        network: B256::repeat_byte(0x91),
        genesis: hash("4bebee4e83c206d9e40692165639a5c1cf0546d13a39c233666b56ad0aeaaa3a"),
        domain: spec.domain(),
        configuration: configuration_commitment(spec.execution()).unwrap(),
        program_elf_keccak: hash("ba7207dad5dafe22f2f8c2dd0705f3acbb5b20886d5c05c528372bc88b4d4828"),
        program_vkey_koalabear: hash("7a3fec8175a17a171d82f74027d9bdba59fa8e17397e4b01716bc07926c3a41a"),
        program_vkey_bn254: hash("00f47fd903d685e85cec17ba027d9bdbab3f51c2ee5f92c078b5e03ca6c3a41a"),
        proof_policy: B256::from(bloch_l2_proof::policy_commitment()),
        chain_id: 700771,
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
    CheckpointPolicy::new(
        0x91,
        policy().genesis.0,
        SignerSet {
            id: 1,
            adopted_epoch: 0,
            threshold: 2,
            min_external: 1,
            signers: keys()
                .iter()
                .enumerate()
                .map(|(i, key)| Signer {
                    pubkey: key.0[4..].try_into().unwrap(),
                    external: i == 2,
                })
                .collect(),
        },
        Phase::A,
    )
    .unwrap()
}
fn envelope(indices: &[u8]) -> CheckpointEnvelope {
    envelope_for(HEADER, indices)
}
fn envelope_for(bytes: &[u8], indices: &[u8]) -> CheckpointEnvelope {
    let header = BlockHeaderV4::canonical_deserialize(bytes).unwrap();
    assert_eq!(header.state_root.as_slice(), STATE);
    let checkpoint = WeakSubjectivityCheckpoint {
        version: ws::WS_FORMAT_VERSION,
        network_id: 0x91,
        genesis_root: policy().genesis.0,
        epoch: 0,
        block_root: *BlockId::of(&header).as_bytes(),
        state_root: header.state_root,
        // The WS validator-set field is a fixture identity, not live membership evidence.
        validator_set_root: [12; 32],
        issued_at: 1,
        signer_set_id: 1,
    };
    let root = checkpoint.ws_digest();
    CheckpointEnvelope {
        checkpoint,
        signatures: indices
            .iter()
            .map(|i| {
                let sig = bloch_crypto::crypto::sign(&keys()[*i as usize].1, &root).unwrap();
                (*i, sig[4..].to_vec())
            })
            .collect(),
    }
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
struct Fixture {
    root: tempfile::TempDir,
    checkpoints: PathBuf,
    settlements: PathBuf,
    checkpoint_floor: CheckpointMark,
    settlement_floor: SettlementStoreMarkV1,
    l2_floor: ReplayFloor,
}
impl Fixture {
    fn create() -> Self {
        Self::create_with_wire(SettlementWireFormat::NativeV1)
    }
    fn create_with_wire(format: SettlementWireFormat) -> Self {
        let transaction = SettlementTransactionV1::decode_wire(TX).unwrap().0.encode_wire(format);
        let mut native_header = HEADER.to_vec();
        if format == SettlementWireFormat::ExperimentalV1 {
            // Attack fixture: a genuinely signed WS header containing the wrong
            // transport still must not qualify as native consensus settlement.
            native_header[68..100].copy_from_slice(&bloch_pos_committee::derive::body_root(std::slice::from_ref(
                &transaction,
            )));
        }
        let root = tempfile::tempdir().unwrap();
        let source = open(root.path());
        let genesis = prepare_genesis(&spec(), source.latest().unwrap().as_ref()).unwrap();
        let writer = source.database_provider_rw().unwrap();
        writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
        writer.commit().unwrap();
        let mut coordinator = CanonicalCoordinator::attach(source.clone()).unwrap();
        coordinator
            .extend(
                coordinator.head().hash(),
                BlochNextBlockEnvCtx {
                    timestamp: 1,
                    prevrandao: B256::repeat_byte(7),
                    anchor_root: statement().l1_block,
                    deposits: vec![],
                },
                vec![],
            )
            .unwrap();
        let block = source.block_by_number(1).unwrap().unwrap();
        assert_eq!(block.header.0.hash(), statement().l2_header_hash);
        assert_eq!(block.header.0.state_root, statement().l2_state_root);
        let checkpoints = root.path().join("checkpoints");
        let settlements = root.path().join("settlements");
        let mut cp = CheckpointStore::create(&checkpoints, checkpoint_policy()).unwrap();
        cp.accept(&envelope_for(&native_header, &[0, 1, 2]), &native_header, 1)
            .unwrap();
        let verified = cp.current(1).unwrap();
        let expected = SettlementAdmissionExpectationV1 {
            settlement: SettlementExpectationV1 {
                statement: statement(),
                source_predecessor: B256::ZERO,
            },
            block: verified.anchor().block,
            slot: verified.anchor().slot,
            checkpoint: verified.anchor(),
            transaction_index: 0,
        };
        let evidence = TransactionInclusionEvidenceV1::new(
            verified.anchor(),
            vec![Bytes::copy_from_slice(&native_header)],
            vec![Bytes::copy_from_slice(&transaction)],
        )
        .unwrap();
        let mut store = SettlementStoreV1::create(&settlements, policy()).unwrap();
        let mark = store.mark();
        bind_settlement_checkpoint_authority(verified, evidence, &expected)
            .unwrap()
            .verify_and_commit(
                &mut store,
                mark,
                &expected.settlement,
                &NativeGroth16Verifier::from_policy(&policy()).unwrap(),
            )
            .unwrap();
        assert_eq!(store.admission().unwrap().transaction(), transaction);
        assert_eq!(
            &fs::read(settlements.join("00000000000000000001.sst")).unwrap()[..8],
            if format == SettlementWireFormat::NativeV1 {
                b"BLSTRC05"
            } else {
                b"BLSTRC04"
            }
        );
        Self {
            root,
            checkpoints,
            settlements,
            checkpoint_floor: cp.mark().unwrap(),
            settlement_floor: store.mark(),
            l2_floor: ReplayFloor {
                number: 1,
                hash: source.sealed_header(1).unwrap().unwrap().hash(),
            },
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
            current_epoch: 1,
            maximum_proofs: 1,
            canonical_limits: ReplayLimits::default(),
        }
    }
    fn history(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut paths = [&self.checkpoints, &self.settlements]
            .into_iter()
            .flat_map(|p| fs::read_dir(p).unwrap().map(|e| e.unwrap().path()))
            .collect::<Vec<_>>();
        paths.sort();
        paths
            .into_iter()
            .map(|p| {
                let bytes = fs::read(&p).unwrap();
                (p, bytes)
            })
            .collect()
    }
}

#[test]
fn native_bytes_real_proof_and_hybrid_quorum_survive_recovery_and_candidate_restart() {
    let fixture = Fixture::create();
    let before = fixture.history();
    let mut floor = None;
    for _ in 0..2 {
        let source = open(fixture.root.path());
        let recovered = recover_canonical_native_settlements(&source, fixture.request()).unwrap();
        assert_eq!(recovered.report().audited_records, 1);
        assert_eq!(
            recovered.stores().settlement_store().admission().unwrap().transaction(),
            TX
        );
        drop(recovered);
        let candidate = recover_and_stage_native_finality_candidate(&source, fixture.request(), floor).unwrap();
        floor = Some(candidate.cursor().commitment());
        drop(candidate);
        let reader = source.database_provider_ro().unwrap();
        for key in [ChainStateKey::LastFinalizedBlock, ChainStateKey::LastSafeBlock] {
            assert_eq!(reader.tx_ref().get::<ChainState>(key).unwrap(), None);
        }
    }
    assert_eq!(fixture.history(), before);
}

#[test]
fn real_quorum_refuses_missing_external_duplicate_and_corrupted_hybrid_signatures() {
    let policy = checkpoint_policy();
    for indices in [&[0, 2][..], &[0, 1, 2][..]] {
        assert!(policy.verify(&envelope(indices), HEADER, 1, None).is_ok());
    }
    for indices in [&[0][..], &[0, 1][..], &[2, 2][..]] {
        assert!(policy.verify(&envelope(indices), HEADER, 1, None).is_err());
    }
    for index in [0, 1] {
        let mut bad = envelope(&[0, 2]);
        let n = bad.signatures[index].1.len();
        let position = if index == 0 { 0 } else { n - 1 };
        bad.signatures[index].1[position] ^= 1;
        assert!(policy.verify(&bad, HEADER, 1, None).is_err());
    }
    let mut foreign = envelope(&[0, 2]);
    foreign.checkpoint.network_id ^= 1;
    assert!(policy.verify(&foreign, HEADER, 1, None).is_err());
    assert!(policy
        .verify(&envelope(&[0, 2]), HEADER, ws::WS_PERIOD_EPOCHS, None)
        .is_err());
}

#[test]
fn wrong_proof_policy_program_and_late_checkpoint_expiry_preserve_candidate() {
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let before = fixture.history();
    let mut wrong = policy();
    wrong.proof_policy = B256::repeat_byte(9);
    assert!(NativeGroth16Verifier::from_policy(&wrong).is_err());
    let proof = NativeGroth16Verifier::from_policy(&policy()).unwrap();
    let initial = recover_and_stage_finality_candidate(&source, fixture.request(), &proof, None).unwrap();
    let floor = Some(initial.cursor().commitment());
    drop(initial);
    let mut wrong = policy();
    wrong.program_vkey_bn254 = B256::repeat_byte(9);
    let reject = NativeGroth16Verifier::from_policy(&wrong).unwrap();
    assert!(recover_and_stage_finality_candidate(&source, fixture.request(), &reject, floor).is_err());
    let mut stale = fixture.request();
    stale.current_epoch = ws::WS_PERIOD_EPOCHS;
    assert!(recover_and_stage_finality_candidate(&source, stale, &proof, floor).is_err());
    assert!(recover_and_stage_finality_candidate(&source, fixture.request(), &proof, floor).is_ok());
    assert_eq!(fixture.history(), before);
}

#[test]
fn envelope_conversion_cannot_replace_exact_native_inclusion() {
    let (tx, format) = SettlementTransactionV1::decode_wire(TX).unwrap();
    assert_eq!(format, SettlementWireFormat::NativeV1);
    assert!(SettlementTransactionV1::decode(TX).is_err());
    let verified = checkpoint_policy().verify(&envelope(&[0, 2]), HEADER, 1, None).unwrap();
    let evidence = TransactionInclusionEvidenceV1::new(
        verified.anchor(),
        vec![Bytes::copy_from_slice(HEADER)],
        vec![Bytes::copy_from_slice(TX)],
    )
    .unwrap();
    assert!(evidence.authenticate_exact(&tx.encode()).is_err());
    assert!(TransactionInclusionEvidenceV1::new(
        verified.anchor(),
        vec![Bytes::copy_from_slice(HEADER)],
        vec![Bytes::copy_from_slice(&tx.encode())]
    )
    .is_err());
    let proof = NativeGroth16Verifier::from_policy(&policy()).unwrap();
    let mut bad = TX.to_vec();
    *bad.last_mut().unwrap() ^= 1;
    let (bad, _) = SettlementTransactionV1::decode_wire(&bad).unwrap();
    assert!(!proof.verify(
        policy().proof_policy,
        &bad.statement().encode(),
        &bad.encode()[bad.encode().len() - 356..]
    ));
}

#[test]
fn v5_rejects_padding_downgrades_missing_authority_and_missing_history() {
    use bloch_l2_evm::native_settlement::store::SettlementStoreErrorV1;
    let fixture = Fixture::create();
    let path = fixture.settlements.join("00000000000000000001.sst");
    let original = fs::read(&path).unwrap();
    let offset = original.windows(TX.len()).position(|window| window == TX).unwrap();
    let mut padding = original.clone();
    padding[offset + TX.len()] = 1;
    let mut downgrade = original.clone();
    downgrade[..8].copy_from_slice(b"BLSTRC04");
    let mut legacy = original.clone();
    legacy[offset - 1] = 1;
    let tx = SettlementTransactionV1::decode_wire(TX).unwrap().0.encode();
    legacy[offset..offset + tx.len()].copy_from_slice(&tx);
    let mut truncated = original.clone();
    truncated.truncate(truncated.len() - 1);
    for changed in [padding, downgrade, legacy, truncated] {
        fs::write(&path, changed).unwrap();
        assert!(matches!(
            SettlementStoreV1::open(&fixture.settlements, policy(), fixture.settlement_floor),
            Err(SettlementStoreErrorV1::Format)
        ));
    }
    fs::write(&path, &original).unwrap();
    let proof = NativeGroth16Verifier::from_policy(&policy()).unwrap();
    let source = open(fixture.root.path());
    let saved = fixture.root.path().join("retained-settlement");
    fs::rename(&path, &saved).unwrap();
    assert!(recover_canonical_settlements(&source, fixture.request(), &proof).is_err());
    fs::rename(&saved, &path).unwrap();
    assert!(recover_canonical_settlements(&source, fixture.request(), &proof).is_ok());
}

#[test]
fn corrupted_retained_real_quorum_is_rejected_before_execution_proof_replay() {
    use std::cell::Cell;
    struct Count {
        calls: Cell<u64>,
        inner: NativeGroth16Verifier,
    }
    impl SettlementProofVerifierV1 for Count {
        fn verify(&self, p: B256, v: &[u8], proof: &[u8]) -> bool {
            self.calls.set(self.calls.get() + 1);
            self.inner.verify(p, v, proof)
        }
    }
    let fixture = Fixture::create();
    let source = open(fixture.root.path());
    let path = fixture.checkpoints.join("00000000000000000000.ckp");
    let original = fs::read(&path).unwrap();
    let mut bad = original.clone();
    *bad.last_mut().unwrap() ^= 1;
    fs::write(&path, bad).unwrap();
    let counted = Count {
        calls: Cell::new(0),
        inner: NativeGroth16Verifier::from_policy(&policy()).unwrap(),
    };
    assert!(recover_canonical_settlements(&source, fixture.request(), &counted).is_err());
    assert_eq!(counted.calls.get(), 0);
    fs::write(&path, original).unwrap();
    assert!(recover_canonical_settlements(&source, fixture.request(), &counted).is_ok());
    assert_eq!(counted.calls.get(), 1);
}

#[test]
fn native_only_entry_refuses_legacy_history_even_with_real_proof_and_real_quorum() {
    let fixture = Fixture::create_with_wire(SettlementWireFormat::ExperimentalV1);
    let source = open(fixture.root.path());
    let before = fixture.history();
    let verifier = NativeGroth16Verifier::from_policy(&policy()).unwrap();
    assert!(recover_canonical_settlements(&source, fixture.request(), &verifier).is_ok());
    assert!(recover_canonical_native_settlements(&source, fixture.request()).is_err());
    assert!(recover_and_stage_native_finality_candidate(&source, fixture.request(), None).is_err());
    let candidate = recover_and_stage_finality_candidate(&source, fixture.request(), &verifier, None).unwrap();
    let mark = Some(candidate.cursor().commitment());
    drop(candidate);
    assert!(recover_and_stage_native_finality_candidate(&source, fixture.request(), mark).is_err());
    assert!(recover_and_stage_finality_candidate(&source, fixture.request(), &verifier, mark).is_ok());
    assert_eq!(fixture.history(), before);
}
