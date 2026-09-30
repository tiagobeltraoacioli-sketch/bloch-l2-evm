// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real MDBX/static/RocksDB recovery under independent rollback floors and limits.
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use alloy_rlp::Encodable;
use bloch_l2_evm::{ChainSpec, DepositMint, DepositProvenance};
use bloch_reth_execution::{
    inspect_canonical_prefix, prepare_genesis, replay_canonical_prefix_with_limits, BlochChainSpec,
    BlochNextBlockEnvCtx, BlochProviderFactory, BlochRethTransaction, BlochTables, CanonicalCoordinator, ReplayFloor,
    ReplayLimits,
};
use k256::ecdsa::SigningKey;
use reth_chainspec::EthChainSpec;
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_db_api::transaction::DbTxMut;
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockNumReader, BlockReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory, ReceiptProvider,
    StateProvider,
};
use std::{path::Path, process::Command, sync::Arc};

fn spec() -> Arc<BlochChainSpec> {
    // Same explicit synthetic identity used by the developer executable.
    Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0xd3), 0).unwrap())
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
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}
fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn signed(nonce: u64, to: TxKind, input: Bytes) -> BlochRethTransaction {
    let tx = TxEip1559 {
        chain_id: ChainSpec::testnet().chain_id,
        nonce,
        to,
        input,
        gas_limit: 200_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        ..Default::default()
    };
    let signature: Signature = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    tx.into_signed(signature).into()
}
fn attributes(number: u64) -> BlochNextBlockEnvCtx {
    BlochNextBlockEnvCtx {
        timestamp: number,
        prevrandao: B256::ZERO,
        anchor_root: B256::repeat_byte(0xd3),
        deposits: vec![],
    }
}
fn seed(factory: &BlochProviderFactory, count: u64) {
    let spec = spec();
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut coordinator = CanonicalCoordinator::attach(factory.clone()).unwrap();
    for number in 1..=count {
        let mut attrs = attributes(number);
        let transactions = match number {
            1 => {
                attrs.deposits.push(DepositMint {
                    recipient: sender(),
                    provenance: DepositProvenance::BridgedBlch {
                        l1_height: 1,
                        l1_tx_index: 0,
                        l1_txid: [0xd3; 32],
                        l1_vout: 0,
                        l1_sats: 100_000_000,
                    },
                });
                vec![]
            }
            2 => {
                // Deploy real bytecode that stores the calldata word in slot zero.
                let runtime = alloy_primitives::hex!("60003560005500");
                let mut init = vec![
                    0x60,
                    runtime.len() as u8,
                    0x60,
                    12,
                    0x60,
                    0,
                    0x39,
                    0x60,
                    runtime.len() as u8,
                    0x60,
                    0,
                    0xf3,
                ];
                init.extend(runtime);
                vec![signed(0, TxKind::Create, init.into())]
            }
            3 => vec![signed(
                1,
                TxKind::Call(sender().create(0)),
                U256::from(42).to_be_bytes::<32>().into(),
            )],
            _ => vec![],
        };
        coordinator
            .extend(coordinator.head().hash(), attrs, transactions)
            .unwrap();
    }
}
fn floor(source: &BlochProviderFactory, number: u64) -> ReplayFloor {
    ReplayFloor {
        number,
        hash: source.sealed_header(number).unwrap().unwrap().hash(),
    }
}
fn bytes(source: &BlochProviderFactory, height: u64) -> u64 {
    (1..=height)
        .map(|number| source.block_by_number(number).unwrap().unwrap().length() as u64)
        .sum()
}
fn assert_empty(target: &BlochProviderFactory) {
    assert!(target.sealed_header(0).unwrap().is_none());
    assert_eq!(target.best_block_number().unwrap(), 0);
    assert_eq!(target.last_block_number().unwrap(), 0);
}

#[test]
fn exact_budgets_reexecute_contract_receipts_state_and_continue_after_reopen() {
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let source = open(source_dir.path(), spec());
    seed(&source, 3);
    // This local test retains an earlier acknowledged head separately before replay;
    // it is not an independent production authority or finality checkpoint.
    let retained = floor(&source, 2);
    let limits = ReplayLimits {
        blocks: 3,
        bytes: bytes(&source, 3),
    };
    let inspected = inspect_canonical_prefix(&source, &spec(), Some(retained), limits).unwrap();
    assert_eq!(inspected.blocks, 3);
    assert_eq!(inspected.bytes, limits.bytes);
    let source_tip = source.sealed_header(3).unwrap().unwrap();
    let receipts = source.receipts_by_block(3.into()).unwrap();
    let target = open(target_dir.path(), spec());
    let outcome = replay_canonical_prefix_with_limits(&source, &target, Some(retained), limits).unwrap();
    assert_eq!(outcome.head, source_tip);
    assert_eq!(outcome.blocks, 3);
    assert_eq!(outcome.bytes, limits.bytes);
    assert_eq!(outcome.floor, Some(retained));
    assert_eq!(target.receipts_by_block(3.into()).unwrap(), receipts);
    assert_eq!(
        target
            .latest()
            .unwrap()
            .storage(sender().create(0), B256::ZERO)
            .unwrap(),
        Some(U256::from(42))
    );
    assert_eq!(
        target
            .latest()
            .unwrap()
            .basic_account(&sender())
            .unwrap()
            .unwrap()
            .nonce,
        2
    );
    drop(target);
    let target = open(target_dir.path(), spec());
    let mut resumed = CanonicalCoordinator::attach(target.clone()).unwrap();
    assert_eq!(resumed.head(), &source_tip);
    let next = signed(
        2,
        TxKind::Call(sender().create(0)),
        U256::from(43).to_be_bytes::<32>().into(),
    );
    resumed.extend(source_tip.hash(), attributes(4), vec![next]).unwrap();
    assert_eq!(
        target
            .latest()
            .unwrap()
            .storage(sender().create(0), B256::ZERO)
            .unwrap(),
        Some(U256::from(43))
    );
    assert_eq!(source.sealed_header(3).unwrap().unwrap(), source_tip);
    assert_eq!(
        source
            .latest()
            .unwrap()
            .storage(sender().create(0), B256::ZERO)
            .unwrap(),
        Some(U256::from(42))
    );
}

#[test]
fn insufficient_block_or_cumulative_byte_budget_preserves_empty_target() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(&directory.path().join("source"), spec());
    seed(&source, 3);
    let encoded = bytes(&source, 3);
    for (index, limits) in [
        ReplayLimits {
            blocks: 2,
            bytes: encoded,
        },
        ReplayLimits {
            blocks: 3,
            bytes: encoded - 1,
        },
        ReplayLimits {
            blocks: 3,
            bytes: bytes(&source, 1),
        },
        ReplayLimits { blocks: 0, bytes: 0 },
    ]
    .into_iter()
    .enumerate()
    {
        let target = open(&directory.path().join(format!("target-{index}")), spec());
        let error = replay_canonical_prefix_with_limits(&source, &target, None, limits).unwrap_err();
        assert!(error.to_string().contains("budget exceeded"), "{error}");
        assert_empty(&target);
    }
    assert_eq!(source.best_block_number().unwrap(), 3);
}

#[test]
fn exact_minimum_floor_accepts_complete_suffix_but_old_backup_and_fork_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let full = open(&directory.path().join("full"), spec());
    let old = open(&directory.path().join("old-backup"), spec());
    seed(&full, 3);
    seed(&old, 2);
    let retained = floor(&full, 3);
    let target = open(&directory.path().join("target"), spec());
    let error =
        replay_canonical_prefix_with_limits(&old, &target, Some(retained), ReplayLimits::default()).unwrap_err();
    assert!(error.to_string().contains("below the retained floor"), "{error}");
    assert_empty(&target);
    // Build a valid alternative block at the retained height, with different
    // executed contract state, rather than merely supplying a malformed hash.
    let mut forked = CanonicalCoordinator::attach(old.clone()).unwrap();
    let alternate = signed(
        1,
        TxKind::Call(sender().create(0)),
        U256::from(43).to_be_bytes::<32>().into(),
    );
    forked
        .extend(forked.head().hash(), attributes(3), vec![alternate])
        .unwrap();
    let error =
        replay_canonical_prefix_with_limits(&old, &target, Some(retained), ReplayLimits::default()).unwrap_err();
    assert!(error.to_string().contains("conflicts with retained floor"), "{error}");
    assert_empty(&target);
    let conflicting = ReplayFloor {
        number: 2,
        hash: retained.hash,
    };
    let error =
        replay_canonical_prefix_with_limits(&full, &target, Some(conflicting), ReplayLimits::default()).unwrap_err();
    assert!(error.to_string().contains("conflicts with retained floor"), "{error}");
    assert_empty(&target);
    let outcome =
        replay_canonical_prefix_with_limits(&full, &target, Some(floor(&full, 2)), ReplayLimits::default()).unwrap();
    assert_eq!(outcome.head.hash(), retained.hash);
}

#[test]
fn genesis_only_source_accepts_zero_limits_and_explicit_genesis_floor() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(&directory.path().join("source"), spec());
    seed(&source, 0);
    let target = open(&directory.path().join("target"), spec());
    let outcome = replay_canonical_prefix_with_limits(
        &source,
        &target,
        Some(floor(&source, 0)),
        ReplayLimits { blocks: 0, bytes: 0 },
    )
    .unwrap();
    assert_eq!(outcome.blocks, 0);
    assert_eq!(outcome.bytes, 0);
    assert_eq!(outcome.head.hash(), spec().genesis_hash());
    assert_eq!(CanonicalCoordinator::attach(target).unwrap().head(), &outcome.head);
}

#[test]
fn missing_body_is_rejected_before_target_genesis_is_written() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(&directory.path().join("source"), spec());
    seed(&source, 3);
    let writer = source.database_provider_rw().unwrap();
    writer
        .tx_ref()
        .delete::<bloch_reth_execution::BlochV2Deposits>(3, None)
        .unwrap();
    writer.commit().unwrap();
    let target = open(&directory.path().join("target"), spec());
    assert!(replay_canonical_prefix_with_limits(&source, &target, None, ReplayLimits::default()).is_err());
    assert_empty(&target);
}

#[test]
fn initialized_target_and_wrong_domain_are_never_replayed_over() {
    let directory = tempfile::tempdir().unwrap();
    let source = open(&directory.path().join("source"), spec());
    seed(&source, 3);
    let target = open(&directory.path().join("target"), spec());
    seed(&target, 1);
    let before = target.sealed_header(1).unwrap();
    assert!(replay_canonical_prefix_with_limits(&source, &target, None, ReplayLimits::default()).is_err());
    assert_eq!(target.sealed_header(1).unwrap(), before);
    let wrong_spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0xd4), 0).unwrap());
    let wrong = open(&directory.path().join("wrong-domain"), wrong_spec);
    assert!(replay_canonical_prefix_with_limits(&source, &wrong, None, ReplayLimits::default()).is_err());
    assert_empty(&wrong);
}

#[test]
fn cli_refuses_floor_and_budget_before_creating_target_or_serving_rpc() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source");
    let source = open(&source_path, spec());
    seed(&source, 3);
    let retained = floor(&source, 3);
    drop(source);
    let cases = [
        vec![
            "--replay-min-block".to_owned(),
            "4".to_owned(),
            "--replay-min-hash".to_owned(),
            retained.hash.to_string(),
        ],
        vec![
            "--replay-min-block".to_owned(),
            "2".to_owned(),
            "--replay-min-hash".to_owned(),
            retained.hash.to_string(),
        ],
        vec!["--replay-max-blocks".to_owned(), "2".to_owned()],
        vec!["--replay-max-bytes".to_owned(), "0".to_owned()],
    ];
    for (index, args) in cases.into_iter().enumerate() {
        let target = directory.path().join(format!("target-{index}"));
        let output = Command::new(env!("CARGO_BIN_EXE_bloch-evm-dev"))
            .args(["--synthetic-dev", "--init", "--data-dir"])
            .arg(&target)
            .arg("--replay-from")
            .arg(&source_path)
            .args(args)
            .args(["--port", "0"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!target.exists(), "preflight failure must not create target");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("RPC listening"));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("recovery"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_never_silently_drops_an_incomplete_or_out_of_context_floor() {
    let directory = tempfile::tempdir().unwrap();
    let hash = B256::repeat_byte(1).to_string();
    let cases = [
        vec!["--replay-from", "missing-source", "--replay-min-block", "3"],
        vec!["--replay-from", "missing-source", "--replay-min-hash", &hash],
        vec!["--replay-min-block", "3", "--replay-min-hash", &hash],
        vec!["--replay-max-blocks", "3"],
        vec!["--replay-max-bytes", "18446744073709551616"],
        vec![
            "--replay-from",
            "missing-source",
            "--replay-min-block",
            "3",
            "--replay-min-hash",
            "0x0",
        ],
    ];
    for (index, arguments) in cases.into_iter().enumerate() {
        let target = directory.path().join(format!("rejected-{index}"));
        let output = Command::new(env!("CARGO_BIN_EXE_bloch-evm-dev"))
            .args(["--synthetic-dev", "--init", "--data-dir"])
            .arg(&target)
            .args(arguments)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!target.exists());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("RPC listening"));
    }
}
