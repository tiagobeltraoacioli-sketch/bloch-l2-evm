//! Genuine existing proof artifacts are required; no mock or skipped acceptance.
#![cfg(feature = "source-settlement")]
#[path = "../src/fixture.rs"]
#[allow(dead_code)]
mod fixture;
#[path = "../src/source_fixture.rs"]
mod source_fixture;
use alloy_primitives::B256;
use bloch_evm_sp1_host::{
    source_settlement::SourceSettlement,
    verification::{ProgramIdentity, TrustedProgram},
};
use bloch_l2_evm::{ChainSpec, DepositProvenance};
use sp1_sdk::Elf;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
fn artifact(variable: &str, default: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(default))
}
async fn program() -> TrustedProgram {
    let elf = artifact(
        "BLOCH_SP1_ELF",
        "../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bloch-evm-synthetic-guest",
    );
    TrustedProgram::from_trusted_elf(Elf::from(fs::read(elf).unwrap()))
        .await
        .unwrap()
}
fn coordinator(f: &source_fixture::SourceFixture, p: ProgramIdentity) -> SourceSettlement {
    SourceSettlement::from_trusted_genesis(
        ChainSpec::testnet(),
        f.registry.network(),
        f.registry.genesis(),
        f.registry.domain(),
        p,
        f.execution.parent.clone(),
        f.registry.clone(),
    )
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_policy_and_failed_updates_preserve_both_cursors() {
    let f = source_fixture::source_contract().unwrap();
    let program = program().await;
    let mut c = coordinator(&f, program.identity());
    let initial = c.execution().mark();
    let mut bad = f.batch.clone();
    bad.locations[0].transaction = B256::repeat_byte(0x77);
    assert!(c
        .apply_source(f.expected_source, f.position, &f.headers, &bad, &f.proofs)
        .is_err());
    assert_eq!(c.source(), &f.registry);
    assert_eq!(c.execution().mark(), initial);
    assert_eq!(c.next_sequence(), 0);
    c.apply_source(f.expected_source, f.position, &f.headers, &f.batch, &f.proofs)
        .unwrap();
    let applied = c.source().clone();
    assert!(c
        .apply_source(f.expected_source, f.position, &f.headers, &f.batch, &f.proofs)
        .is_err());
    assert_eq!(c.source(), &applied);
    assert_eq!(c.execution().mark(), initial);
    assert_eq!(c.next_sequence(), 0);
    let legacy = fixture::fixture().unwrap();
    let legacy_proof = program
        .verify_file(
            artifact("BLOCH_SP1_CONTRACT_PROOF", "target/qualification-contract.proof"),
            &legacy.expected,
        )
        .unwrap();
    assert!(c.advance(&legacy_proof, &legacy.header, &legacy.body).is_err());
    assert!(c
        .advance(&legacy_proof, &f.execution.header, &f.execution.body)
        .is_err());
    assert_eq!(c.execution().mark(), initial);
    assert_eq!(c.next_sequence(), 0);
    assert_eq!(c.source(), &applied);
    for field in 0..3 {
        let mut header = f.execution.parent.clone();
        match field {
            0 => header.state_root[0] ^= 1,
            1 => header.gas_used = 1,
            _ => header.number = 1,
        }
        assert!(SourceSettlement::from_trusted_genesis(
            ChainSpec::testnet(),
            f.registry.network(),
            f.registry.genesis(),
            f.registry.domain(),
            program.identity(),
            header,
            f.registry.clone()
        )
        .is_err());
    }
    assert!(SourceSettlement::from_trusted_genesis(
        ChainSpec::testnet(),
        B256::repeat_byte(0xff),
        f.registry.genesis(),
        f.registry.domain(),
        program.identity(),
        f.execution.parent.clone(),
        f.registry.clone()
    )
    .is_err());
    assert!(SourceSettlement::from_trusted_genesis(
        ChainSpec::testnet(),
        f.registry.network(),
        f.registry.genesis(),
        f.registry.domain(),
        program.identity(),
        f.execution.parent.clone(),
        applied
    )
    .is_err());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_source_contract_proof_advances_execution_and_consumption_once() {
    let f = source_fixture::source_contract().unwrap();
    let program = program().await;
    let path = artifact("BLOCH_SP1_SOURCE_PROOF", "target/qualification-source-contract.proof");
    let token = program
        .verify_file(&path, &f.execution.expected)
        .expect("generate documented source-contract proof first");
    let mut c = coordinator(&f, program.identity());
    let initial = c.execution().mark();
    // Even this valid proof does not authorize a source absent from owned registry.
    assert!(c.advance(&token, &f.execution.header, &f.execution.body).is_err());
    c.apply_source(f.expected_source, f.position, &f.headers, &f.batch, &f.proofs)
        .unwrap();
    for kind in 0..4 {
        let mut body = f.execution.body.clone();
        match kind {
            0 => body.deposits.clear(),
            1 => body.deposits[0].recipient[0] ^= 1,
            2 => {
                let DepositProvenance::BridgedBlch { ref mut l1_sats, .. } = body.deposits[0].provenance;
                *l1_sats += 1;
            }
            _ => {
                body.transactions.pop();
            }
        }
        assert!(c.advance(&token, &f.execution.header, &body).is_err());
        assert_eq!(c.execution().mark(), initial);
        assert_eq!(c.next_sequence(), 0);
    }
    let mark = c.advance(&token, &f.execution.header, &f.execution.body).unwrap();
    assert_eq!(mark.execution.header_hash, f.execution.header.hash());
    assert_eq!(mark.next_sequence, 1);
    assert_eq!(mark.source_commitment, f.expected_source);
    assert!(c.advance(&token, &f.execution.header, &f.execution.body).is_err());
    assert_eq!(c.execution().mark(), mark.execution);
    assert_eq!(c.next_sequence(), 1);
    let elf = artifact(
        "BLOCH_SP1_ELF",
        "../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bloch-evm-synthetic-guest",
    );
    let result = Command::new(env!("CARGO_BIN_EXE_bloch-evm-sp1-host"))
        .args(["verify-source", "source-contract"])
        .arg(elf)
        .arg(path)
        .env("RAYON_NUM_THREADS", "2")
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert!(String::from_utf8_lossy(&result.stdout).contains("Source replay rejected"));
}
