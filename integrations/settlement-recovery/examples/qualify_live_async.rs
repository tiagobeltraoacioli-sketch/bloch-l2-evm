// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded qualification of a pinned development manifest and real live history.
//! This executable owns only a separate unfunded L2 database, never a live RPC DB.
#[path = "../tests/support/native_ffg.rs"]
mod fixture;
use alloy_primitives::B256;
use bloch_l2_evm::{native_settlement::SettlementPolicyV1, proof_statement::SettlementStatementV2, ChainSpec};
use bloch_pos_committee::interfaces::{ProposalEnvelope, StateReader};
use bloch_pos_node::{
    codec,
    genesis::{L2Config, Manifest, ManifestFormat},
};
use bloch_reth_execution::{
    prepare_genesis, BlochChainSpec, BlochNextBlockEnvCtx, BlochProviderFactory, BlochTables, CanonicalCoordinator,
    ReplayFloor, ReplayLimits,
};
use bloch_settlement_recovery::native::{
    audit_finalized_async_settlements, verify_native_finality, NativeGenesisTrustV1, NativeReplayBlockV1,
    NativeReplayLimitsV1,
};
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockReader, DBProvider, DatabaseProviderFactory, ProviderFactory,
};
use serde_json::json;
use std::{fs, io::Write, path::Path, sync::Arc};

fn public_file(path: &Path, limit: u64) -> Vec<u8> {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && metadata.len() <= limit);
    fs::read(path).unwrap()
}
fn save(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
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
fn config(p: SettlementPolicyV1) -> L2Config {
    L2Config {
        identities: [
            p.domain.0,
            p.configuration.0,
            p.program_elf_keccak.0,
            p.program_vkey_koalabear.0,
            p.program_vkey_bn254.0,
        ],
        proof_policy: p.proof_policy.0,
        chain_id: p.chain_id,
        initial_l2_parent: p.initial_l2_parent_hash.0,
        initial_l2_state: p.initial_l2_state_root.0,
    }
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() == 3 && args[1] == "config" {
        save(Path::new(&args[2]), &config(fixture::policy()).encode());
        return;
    }
    assert!(
        args.len() == 7,
        "usage: qualify_live_async init|recover MANIFEST PINNED_NETWORK_HEX HISTORY_DIR DATABASE REPORT"
    );
    let mode = &args[1];
    assert!(mode == "init" || mode == "recover");
    let manifest = Manifest::decode(&public_file(Path::new(&args[2]), 1_048_576)).unwrap();
    assert_eq!(manifest.format, ManifestFormat::V3L2Async(config(fixture::policy())));
    assert_eq!(manifest.validators.len(), 3);
    let genesis = manifest.genesis_state();
    let native_policy = genesis.l2_settlement().unwrap().policy();
    // This pin is retained at installation, before any submitted proof/history.
    assert_eq!(hex::encode(native_policy.identities[0]), args[3]);
    let policy = SettlementPolicyV1 {
        network: native_policy.identities[0].into(),
        genesis: native_policy.identities[1].into(),
        ..fixture::policy()
    };
    let history = Path::new(&args[4]);
    let index: Vec<String> = serde_json::from_slice(&public_file(&history.join("index.json"), 1_048_576)).unwrap();
    assert!(!index.is_empty() && index.len() <= 10_000);
    let mut total = 0usize;
    let blocks = index
        .iter()
        .map(|id| {
            assert!(id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
            let bytes = public_file(&history.join(format!("{id}.bin")), 1_048_576);
            total += bytes.len();
            assert!(total <= 64 * 1_048_576);
            let env = codec::decode_envelope(&bytes).unwrap();
            assert_eq!(codec::encode_envelope(&env), bytes);
            assert_eq!(codec::hex32(env.block_id().as_bytes()), *id);
            NativeReplayBlockV1 {
                envelope: ProposalEnvelope {
                    header: env.header,
                    proposer_sig: env.proposer_sig,
                },
                attestations: env.body.attestations,
                transactions: env.body.transactions,
            }
        })
        .collect::<Vec<_>>();
    let trust = NativeGenesisTrustV1 {
        state_root: genesis.state_root().into(),
        settlement_policy: policy,
    };
    let limits = NativeReplayLimitsV1 {
        blocks: 10_000,
        epochs: 4096,
        attestations: 100_000,
        transactions: 100_000,
        proofs: 1024,
        bytes: 64 * 1_048_576,
    };
    let verified = verify_native_finality(&genesis, trust, &blocks, limits).unwrap();
    let statements = blocks
        .iter()
        .flat_map(|b| &b.transactions)
        .filter_map(|bytes| bloch_pos_committee::l2_settlement::Transaction::decode_async(bytes))
        .map(|tx| SettlementStatementV2::decode(&tx.statement).unwrap())
        .collect::<Vec<_>>();
    // The pinned worker currently proves the first empty-inbox block. No loop,
    // deposits, bridge operations or fabricated successor proof is implied.
    assert_eq!(statements.len(), 1);
    let statement = statements[0];
    let database = Path::new(&args[5]);
    if mode == "init" {
        fs::create_dir(database).unwrap();
    } else {
        assert!(database.join("db").is_dir());
    }
    let source = open(database);
    if mode == "init" {
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
                    anchor_root: statement.l1_block,
                    deposits: vec![],
                },
                vec![],
            )
            .unwrap();
        drop(coordinator);
    }
    let block = source.block_by_number(1).unwrap().unwrap();
    assert_eq!(block.header.0.hash(), statement.l2_header_hash);
    assert_eq!(block.header.0.state_root, statement.l2_state_root);
    let audit = audit_finalized_async_settlements(
        &verified,
        &source,
        policy,
        ReplayFloor {
            number: 1,
            hash: statement.l2_header_hash,
        },
        ReplayLimits {
            blocks: 1,
            bytes: 1_048_576,
        },
    )
    .unwrap();
    // Negative qualifications use real signatures/proofs from this exact history.
    let mut corrupted = blocks.clone();
    let candidate = corrupted.iter_mut().find(|b| !b.transactions.is_empty()).unwrap();
    candidate.transactions[0][100] ^= 1;
    assert!(verify_native_finality(&genesis, trust, &corrupted, limits).is_err());
    let mut corrupted = blocks.clone();
    corrupted.last_mut().unwrap().envelope.proposer_sig[20] ^= 1;
    assert!(verify_native_finality(&genesis, trust, &corrupted, limits).is_err());
    let inclusion = blocks.iter().position(|b| !b.transactions.is_empty()).unwrap();
    let premature = verify_native_finality(&genesis, trust, &blocks[..=inclusion], limits);
    if let Ok(premature) = premature {
        assert!(audit_finalized_async_settlements(
            &premature,
            &source,
            policy,
            ReplayFloor {
                number: 1,
                hash: statement.l2_header_hash
            },
            ReplayLimits {
                blocks: 1,
                bytes: 1_048_576
            }
        )
        .is_err());
    }
    let report = verified.report();
    save(
        Path::new(&args[6]),
        &serde_json::to_vec_pretty(&json!({
            "ok":true, "mode":mode, "classification":"live-unfunded-native-async-l2-development",
            "genesis_state_root":hex::encode(trust.state_root), "network":hex::encode(policy.network),
            "native_genesis":hex::encode(policy.genesis), "replayed_blocks":report.replayed_blocks,
            "replayed_slot":report.replayed_slot, "native_finalized_epoch":report.finalized_epoch,
            "native_finalized_block":hex::encode(report.finalized.block),
            "l2_number":statement.l2_number, "l2_block":hex::encode(statement.l2_header_hash),
            "l2_state_root":hex::encode(statement.l2_state_root), "source_block":hex::encode(statement.l1_block),
            "source_slot":statement.l1_slot, "source_height":statement.l1_height,
            "audited_records":audit.audited_records, "negative_checks_passed":true,
            "production_finality":false, "rpc_finality_published":false,
            "same_host_failure_domain":true, "empty_inbox":true
        }))
        .unwrap(),
    );
    println!("Real native signatures, Groth16, FFG and persisted canonical L2 correspondence verified ({mode}).");
}
