// SPDX-License-Identifier: MIT OR Apache-2.0
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_execution_artifact::ExecutionArtifact;
use bloch_l2_evm::{ChainSpec, DepositMint, DepositProvenance};
use bloch_reth_execution::{
    prepare_genesis,
    proof_export::{export_canonical_witness, MAX_REPLAY_BLOCKS},
    BlochChainSpec, BlochNextBlockEnvCtx, BlochProviderFactory, BlochRethTransaction, BlochTables,
    CanonicalCoordinator,
};
use k256::ecdsa::SigningKey;
use reth_chainspec::EthChainSpec;
use reth_db::mdbx::{init_db_for, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, SaveBlocksMode, StaticFileProvider},
    BlockNumReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory, StateProvider,
};
use std::{io::Write, process::Command, sync::Arc};

#[test]
fn persisted_signed_contract_exports_actual_witness_and_cli_preserves_source() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("node");
    std::fs::create_dir(&source).unwrap();
    let spec = Arc::new(BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0xd3), 0).unwrap());
    let factory: BlochProviderFactory = ProviderFactory::new(
        Arc::new(init_db_for::<_, BlochTables>(source.join("db"), DatabaseArguments::test()).unwrap()),
        spec.clone(),
        StaticFileProvider::read_write(source.join("static")).unwrap(),
        RocksDBBuilder::new(source.join("rocks"))
            .with_default_tables()
            .build()
            .unwrap(),
        reth_tasks::Runtime::test(),
    )
    .unwrap();
    let genesis = prepare_genesis(&spec, factory.latest().unwrap().as_ref()).unwrap();
    let writer = factory.database_provider_rw().unwrap();
    writer.save_blocks(vec![genesis], SaveBlocksMode::Full).unwrap();
    writer.commit().unwrap();
    let mut coordinator = CanonicalCoordinator::attach(factory.clone()).unwrap();
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let sender = Address::from_public_key(key.verifying_key());
    let contract = sender.create(0);
    let attributes = |timestamp, deposits| BlochNextBlockEnvCtx {
        timestamp,
        prevrandao: B256::ZERO,
        anchor_root: B256::repeat_byte(0xd3),
        deposits,
    };
    coordinator
        .extend(
            spec.genesis_hash(),
            attributes(
                1,
                vec![DepositMint {
                    recipient: sender,
                    provenance: DepositProvenance::BridgedBlch {
                        l1_height: 1,
                        l1_tx_index: 0,
                        l1_txid: [0xd3; 32],
                        l1_vout: 0,
                        l1_sats: 100_000_000,
                    },
                }],
            ),
            vec![],
        )
        .unwrap();
    let sign = |nonce, to, input: Bytes| {
        let transaction = TxEip1559 {
            chain_id: ChainSpec::testnet().chain_id,
            nonce,
            to,
            input,
            gas_limit: 200_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            ..Default::default()
        };
        let signature: Signature = key
            .sign_prehash_recoverable(transaction.signature_hash().as_slice())
            .unwrap()
            .into();
        BlochRethTransaction::from(transaction.into_signed(signature))
    };
    let initcode = vec![
        0x60, 0x07, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x07, 0x60, 0x00, 0xf3, 0x60, 0x00, 0x35, 0x60, 0x00, 0x55,
        0x00,
    ];
    coordinator
        .extend(
            coordinator.head().hash(),
            attributes(2, vec![]),
            vec![sign(0, TxKind::Create, initcode.into())],
        )
        .unwrap();
    let tip = coordinator
        .extend(
            coordinator.head().hash(),
            attributes(3, vec![]),
            vec![sign(
                1,
                TxKind::Call(contract),
                U256::from(42).to_be_bytes::<32>().to_vec().into(),
            )],
        )
        .unwrap();
    let artifact = export_canonical_witness(&factory, 3).unwrap();
    assert_eq!(
        factory.latest().unwrap().storage(contract, B256::ZERO).unwrap(),
        Some(U256::from(42))
    );
    assert_eq!(artifact.header(), &tip.0);
    assert_eq!(artifact.body().transactions.len(), 1);
    assert_eq!(artifact.expected().header_hash, tip.hash());
    assert_eq!(
        artifact.witness().prev_state_root,
        factory.sealed_header(2).unwrap().unwrap().0.state_root
    );
    assert_eq!(artifact.witness().new_state_root, tip.0.state_root);
    let encoded = artifact.encode().unwrap();
    assert_eq!(
        ExecutionArtifact::decode(&encoded, spec.execution(), spec.domain())
            .unwrap()
            .expected(),
        artifact.expected()
    );
    for invalid in [0, 4, MAX_REPLAY_BLOCKS + 1] {
        assert!(export_canonical_witness(&factory, invalid).is_err());
        assert_eq!(factory.best_block_number().unwrap(), 3);
        assert_eq!(factory.sealed_header(3).unwrap().unwrap(), tip);
    }
    let expected_prefix: Vec<_> = (1..=2)
        .map(|height| export_canonical_witness(&factory, height).unwrap().expected())
        .collect();
    drop(coordinator);
    drop(factory);
    let output = directory.path().join("block-3.json");
    let run = |height: &str, output: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_bloch-evm-export"))
            .arg("--synthetic-dev")
            .arg(&source)
            .arg(height)
            .arg(output)
            .output()
            .unwrap()
    };
    let exported = run("3", &output);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(
        ExecutionArtifact::decode(&bytes, spec.execution(), spec.domain())
            .unwrap()
            .expected(),
        artifact.expected()
    );
    assert!(!run("3", &output).status.success());
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
    let forbidden = source.join("must-not-create.json");
    assert!(!run("3", &forbidden).status.success());
    assert!(!forbidden.exists());
    let missing = directory.path().join("missing.json");
    assert!(!run("4", &missing).status.success());
    assert!(!missing.exists());
    let second = directory.path().join("block-3-again.json");
    assert!(run("3", &second).status.success());
    assert_eq!(std::fs::read(second).unwrap(), bytes);
    let mut chain_bytes = Vec::new();
    for (index, expected) in expected_prefix.iter().enumerate() {
        let height = (index + 1).to_string();
        let output = directory.path().join(format!("block-{height}.json"));
        let exported = run(&height, &output);
        assert!(
            exported.status.success(),
            "{}",
            String::from_utf8_lossy(&exported.stderr)
        );
        let encoded = std::fs::read(output).unwrap();
        let restored = ExecutionArtifact::decode(&encoded, spec.execution(), spec.domain()).unwrap();
        assert_eq!(&restored.expected(), expected);
        chain_bytes.push(encoded);
    }
    chain_bytes.push(bytes.clone());
    for pair in chain_bytes.windows(2) {
        let previous = ExecutionArtifact::decode(&pair[0], spec.execution(), spec.domain()).unwrap();
        let next = ExecutionArtifact::decode(&pair[1], spec.execution(), spec.domain()).unwrap();
        assert_eq!(next.parent(), previous.header());
    }
    // Explicit opt-in for the separate SP1 qualification process. Never replace
    // an existing artifact or retain the database/test fixture implicitly.
    if let Some(path) = std::env::var_os("BLOCH_QUALIFICATION_ARTIFACT") {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
    }
    if let Some(path) = std::env::var_os("BLOCH_QUALIFICATION_CHAIN_DIRECTORY") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir(&path).unwrap();
        for (index, encoded) in chain_bytes.iter().enumerate() {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path.join(format!("block-{}.json", index + 1)))
                .unwrap();
            file.write_all(encoded).unwrap();
            file.sync_all().unwrap();
        }
        std::fs::File::open(path).unwrap().sync_all().unwrap();
    }
}
