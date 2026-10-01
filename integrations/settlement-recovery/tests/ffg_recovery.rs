// SPDX-License-Identifier: AGPL-3.0-or-later
//! Genuine native proposer/FFG signatures and execution proof, under fixture trust.
#![cfg(unix)]
#[path = "support/native_ffg.rs"]
mod fixture;
use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::{
    l1::TransactionInclusionEvidenceV1,
    native_settlement::{
        store::{SettlementStoreMarkV1, SettlementStoreV1},
        SettlementExpectationV1, SettlementTransactionV1,
    },
    settlement_admission::SettlementAdmissionExpectationV1,
    ChainSpec,
};
use bloch_native_escrow_pq::{
    checkpoint::{CheckpointPolicy, Phase},
    checkpoint_store::{CheckpointMark, CheckpointStore},
    settlement_authority::bind_settlement_checkpoint_authority,
};
use bloch_pos_committee::{
    interfaces::StateReader,
    transition::CommittedState,
    ws::{self, CheckpointEnvelope, Signer, SignerSet, WeakSubjectivityCheckpoint},
};
use bloch_reth_execution::{
    prepare_genesis, BlochChainSpec, BlochNextBlockEnvCtx, BlochProviderFactory, BlochTables, CanonicalCoordinator,
    ReplayFloor, ReplayLimits,
};
use bloch_settlement_recovery::{
    cursor::{recover_and_stage_ffg_finality_candidate, recover_and_stage_native_finality_candidate},
    native::{
        verify_native_finality, NativeFinalityErrorV1, NativeGenesisTrustV1, NativeReplayBlockV1, NativeReplayLimitsV1,
    },
    proof::NativeGroth16Verifier,
    recover_canonical_ffg_settlements, SettlementRecoveryRequestV1,
};
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_db_api::{
    tables::{ChainState, ChainStateKey},
    transaction::DbTx,
};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native-ffg")
}
fn genesis() -> CommittedState {
    let v: Value = serde_json::from_slice(&fs::read(root().join("bootstrap.json")).unwrap()).unwrap();
    fixture::genesis(
        &v["public_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
            .collect::<Vec<_>>(),
    )
}
fn trust() -> NativeGenesisTrustV1 {
    NativeGenesisTrustV1 {
        settlement_policy: fixture::policy(),
        // Fixed independently of the submitted chain; retained fixture provenance.
        state_root: fixture::hash("a18d390fd74edb85ccce6be661a21dfa3aa645759142ecc1292fe6631963078c"),
    }
}
fn blocks(mode: &str) -> Vec<NativeReplayBlockV1> {
    let v: Vec<Value> = serde_json::from_slice(&fs::read(root().join(format!("{mode}.json"))).unwrap()).unwrap();
    v.iter().map(fixture::decode_block).collect()
}

#[test]
fn genuine_native_quorums_require_both_ffg_rounds_and_finalize_the_exact_settlement() {
    let genesis = genesis();
    assert_eq!(genesis.state_root(), trust().state_root.0);
    for mode in ["full", "two"] {
        let blocks = blocks(mode);
        let native = verify_native_finality(&genesis, trust(), &blocks, NativeReplayLimitsV1::default()).unwrap();
        assert_eq!(native.report().finalized_epoch, 1);
        assert_eq!(
            native.report().finalized.block.0,
            *blocks[1].envelope.header.id().as_bytes()
        );
        assert_eq!(native.report().finalized.slot, 2);
        assert_eq!(native.report().replayed_slot, 96);
        assert!(matches!(
            verify_native_finality(&genesis, trust(), &blocks[..5], NativeReplayLimitsV1::default()),
            Err(NativeFinalityErrorV1::NotFinalized)
        ));
    }
}

#[test]
fn insufficient_duplicate_and_conflicting_real_votes_do_not_finalize() {
    for mode in ["insufficient", "duplicates", "conflict"] {
        assert!(
            matches!(
                verify_native_finality(&genesis(), trust(), &blocks(mode), NativeReplayLimitsV1::default()),
                Err(NativeFinalityErrorV1::NotFinalized)
            ),
            "{mode}"
        );
    }
}

#[test]
fn corrupt_proposer_attester_proof_body_and_foreign_branch_are_rejected() {
    let genesis = genesis();
    let original = blocks("full");
    for end in [false, true] {
        let mut b = original.clone();
        let sig = &mut b[0].envelope.proposer_sig;
        let at = if end { sig.len() - 1 } else { 0 };
        sig[at] ^= 1;
        assert!(matches!(
            verify_native_finality(&genesis, trust(), &b, NativeReplayLimitsV1::default()),
            Err(NativeFinalityErrorV1::Transition { block: 0, .. })
        ));
    }
    let mut b = original.clone();
    b[3].attestations[0].signature[0] ^= 1;
    assert!(verify_native_finality(&genesis, trust(), &b, NativeReplayLimitsV1::default()).is_err());
    let mut b = original.clone();
    *b[1].transactions[0].last_mut().unwrap() ^= 1;
    assert!(verify_native_finality(&genesis, trust(), &b, NativeReplayLimitsV1::default()).is_err());
    let mut b = original.clone();
    b[3].attestations[0].data.target_root = [9; 32];
    assert!(matches!(
        verify_native_finality(&genesis, trust(), &b, NativeReplayLimitsV1::default()),
        Err(NativeFinalityErrorV1::VoteBranch)
    ));
    let mut b = original;
    b.remove(0);
    assert!(matches!(
        verify_native_finality(&genesis, trust(), &b, NativeReplayLimitsV1::default()),
        Err(NativeFinalityErrorV1::Ancestry)
    ));
}

#[test]
fn independent_genesis_and_all_replay_budgets_fail_before_signature_work() {
    let genesis = genesis();
    let mut b = blocks("full");
    b[0].envelope.proposer_sig.fill(0);
    let mut wrong = trust();
    wrong.state_root = B256::repeat_byte(9);
    assert!(matches!(
        verify_native_finality(&genesis, wrong, &b, NativeReplayLimitsV1::default()),
        Err(NativeFinalityErrorV1::Trust)
    ));
    let normal = NativeReplayLimitsV1::default();
    for limit in [
        NativeReplayLimitsV1 { blocks: 1, ..normal },
        NativeReplayLimitsV1 { epochs: 2, ..normal },
        NativeReplayLimitsV1 {
            attestations: 1,
            ..normal
        },
        NativeReplayLimitsV1 {
            transactions: 0,
            ..normal
        },
        NativeReplayLimitsV1 { proofs: 0, ..normal },
        NativeReplayLimitsV1 { bytes: 304, ..normal },
        NativeReplayLimitsV1 {
            blocks: 10_001,
            ..normal
        },
    ] {
        assert!(matches!(
            verify_native_finality(&genesis, trust(), &b, limit),
            Err(NativeFinalityErrorV1::Limit)
        ));
    }
}

fn keys() -> &'static Vec<(Vec<u8>, Vec<u8>)> {
    static KEYS: OnceLock<Vec<(Vec<u8>, Vec<u8>)>> = OnceLock::new();
    KEYS.get_or_init(|| (0..3).map(|_| bloch_crypto::crypto::generate_keypair()).collect())
}
fn cp_policy() -> CheckpointPolicy {
    CheckpointPolicy::new(
        0x91,
        fixture::policy().genesis.0,
        SignerSet {
            id: 1,
            adopted_epoch: 0,
            threshold: 2,
            min_external: 1,
            signers: keys()
                .iter()
                .enumerate()
                .map(|(i, k)| Signer {
                    pubkey: k.0[4..].try_into().unwrap(),
                    external: i == 2,
                })
                .collect(),
        },
        Phase::A,
    )
    .unwrap()
}
fn spec() -> Arc<BlochChainSpec> {
    Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0xd3), 0).unwrap())
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
struct Disk {
    root: tempfile::TempDir,
    checkpoints: PathBuf,
    settlements: PathBuf,
    cp: CheckpointMark,
    settlement: SettlementStoreMarkV1,
    l2: ReplayFloor,
}
impl Disk {
    fn new(checkpoint_index: usize, epoch: u64) -> Self {
        let b = blocks("full");
        let transaction = &b[1].transactions[0];
        let tx = SettlementTransactionV1::decode_wire(transaction).unwrap().0;
        let root = tempfile::tempdir().unwrap();
        let source = open(root.path());
        let prepared = prepare_genesis(&spec(), source.latest().unwrap().as_ref()).unwrap();
        let writer = source.database_provider_rw().unwrap();
        writer.save_blocks(vec![prepared], SaveBlocksMode::Full).unwrap();
        writer.commit().unwrap();
        let mut coordinator = CanonicalCoordinator::attach(source.clone()).unwrap();
        coordinator
            .extend(
                coordinator.head().hash(),
                BlochNextBlockEnvCtx {
                    timestamp: 1,
                    prevrandao: B256::repeat_byte(7),
                    anchor_root: tx.statement().l1_block,
                    deposits: vec![],
                },
                vec![],
            )
            .unwrap();
        let block = source.block_by_number(1).unwrap().unwrap();
        assert_eq!(block.header.0.hash(), tx.statement().l2_header_hash);
        let header = b[checkpoint_index].envelope.header;
        let checkpoint = WeakSubjectivityCheckpoint {
            version: ws::WS_FORMAT_VERSION,
            network_id: 0x91,
            genesis_root: fixture::policy().genesis.0,
            epoch,
            block_root: *header.id().as_bytes(),
            state_root: header.state_root,
            validator_set_root: [12; 32],
            issued_at: 3,
            signer_set_id: 1,
        };
        let envelope = CheckpointEnvelope {
            checkpoint,
            signatures: keys()
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    let signature = bloch_crypto::crypto::sign(&k.1, &checkpoint.ws_digest()).unwrap();
                    (i as u8, signature[4..].to_vec())
                })
                .collect(),
        };
        let checkpoints = root.path().join("checkpoints");
        let settlements = root.path().join("settlements");
        let mut cp = CheckpointStore::create(&checkpoints, cp_policy()).unwrap();
        cp.accept(&envelope, &header.canonical_serialize(), 3).unwrap();
        let verified = cp.current(3).unwrap();
        let expected = SettlementAdmissionExpectationV1 {
            settlement: SettlementExpectationV1 {
                statement: *tx.statement(),
                source_predecessor: B256::ZERO,
            },
            block: B256::from(*b[1].envelope.header.id().as_bytes()),
            slot: 2,
            checkpoint: verified.anchor(),
            transaction_index: 0,
        };
        let evidence = TransactionInclusionEvidenceV1::new(
            verified.anchor(),
            b[1..=checkpoint_index]
                .iter()
                .map(|b| Bytes::copy_from_slice(&b.envelope.header.canonical_serialize()))
                .collect(),
            vec![Bytes::copy_from_slice(transaction)],
        )
        .unwrap();
        let mut store = SettlementStoreV1::create(&settlements, fixture::policy()).unwrap();
        let mark = store.mark();
        bind_settlement_checkpoint_authority(verified, evidence, &expected)
            .unwrap()
            .verify_and_commit(
                &mut store,
                mark,
                &expected.settlement,
                &NativeGroth16Verifier::from_policy(&fixture::policy()).unwrap(),
            )
            .unwrap();
        Self {
            root,
            checkpoints,
            settlements,
            cp: cp.mark().unwrap(),
            settlement: store.mark(),
            l2: ReplayFloor {
                number: 1,
                hash: source.sealed_header(1).unwrap().unwrap().hash(),
            },
        }
    }
    fn request(&self) -> SettlementRecoveryRequestV1<'_> {
        SettlementRecoveryRequestV1 {
            checkpoint_path: &self.checkpoints,
            checkpoint_policy: cp_policy(),
            checkpoint_floor: self.cp,
            settlement_path: &self.settlements,
            settlement_policy: fixture::policy(),
            settlement_floor: self.settlement,
            l2_floor: self.l2,
            current_epoch: 3,
            maximum_proofs: 1,
            canonical_limits: ReplayLimits::default(),
        }
    }
    fn history(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = [&self.checkpoints, &self.settlements]
            .into_iter()
            .flat_map(|p| fs::read_dir(p).unwrap().map(|e| e.unwrap().path()))
            .collect::<Vec<_>>();
        files.sort();
        files
            .into_iter()
            .map(|p| {
                let b = fs::read(&p).unwrap();
                (p, b)
            })
            .collect()
    }
}

#[test]
fn native_ffg_and_real_settlement_recover_and_stage_after_restart() {
    let disk = Disk::new(1, 1);
    let before = disk.history();
    let mut mark = None;
    for _ in 0..2 {
        let source = open(disk.root.path());
        let native =
            verify_native_finality(&genesis(), trust(), &blocks("full"), NativeReplayLimitsV1::default()).unwrap();
        let recovered = recover_canonical_ffg_settlements(&source, disk.request(), &native).unwrap();
        assert_eq!(recovered.native_finality(), Some(native.report()));
        drop(recovered);
        let staged = recover_and_stage_ffg_finality_candidate(&source, disk.request(), &native, mark).unwrap();
        assert_eq!(staged.recovery().native_finality(), Some(native.report()));
        mark = Some(staged.cursor().commitment());
        drop(staged);
        let reader = source.database_provider_ro().unwrap();
        for key in [ChainStateKey::LastSafeBlock, ChainStateKey::LastFinalizedBlock] {
            assert_eq!(reader.tx_ref().get::<ChainState>(key).unwrap(), None);
        }
    }
    assert_eq!(disk.history(), before);
}

#[test]
fn genuine_ws_signatures_cannot_override_native_finality_or_checkpoint_epoch() {
    let native = verify_native_finality(&genesis(), trust(), &blocks("full"), NativeReplayLimitsV1::default()).unwrap();
    // The second checkpoint is the correct epoch-2 root (slot 63), but only
    // epoch 1 is finalized. This isolates finality from checkpoint convention.
    for (position, epoch) in [(1, 0), (3, 2)] {
        let disk = Disk::new(position, epoch);
        let source = open(disk.root.path());
        let before = disk.history();
        // The compatibility path has real proof and WS authority. FFG adds an independent condition.
        let candidate = recover_and_stage_native_finality_candidate(&source, disk.request(), None).unwrap();
        let mark = Some(candidate.cursor().commitment());
        drop(candidate);
        assert!(recover_canonical_ffg_settlements(&source, disk.request(), &native).is_err());
        assert!(recover_and_stage_ffg_finality_candidate(&source, disk.request(), &native, mark).is_err());
        assert!(recover_and_stage_native_finality_candidate(&source, disk.request(), mark).is_ok());
        assert_eq!(disk.history(), before);
    }
}

#[test]
fn future_native_replay_cannot_stage_at_an_earlier_trusted_epoch() {
    let disk = Disk::new(1, 1);
    let source = open(disk.root.path());
    let before = disk.history();
    let native = verify_native_finality(&genesis(), trust(), &blocks("full"), NativeReplayLimitsV1::default()).unwrap();
    let mut request = disk.request();
    request.current_epoch = 2;
    assert!(recover_and_stage_ffg_finality_candidate(&source, request, &native, None).is_err());
    assert!(recover_and_stage_ffg_finality_candidate(&source, disk.request(), &native, None).is_ok());
    assert_eq!(disk.history(), before);
}
