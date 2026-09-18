//! File admission and real saved-proof verification for independently chosen exports.
#![cfg(feature = "node-artifact")]
#[path = "../src/fixture.rs"]
#[allow(dead_code)]
mod fixture;
use alloy_primitives::B256;
use bloch_evm_sp1_host::artifact::load_selected_artifact;
use bloch_execution_artifact::{ExecutionArtifact, MAX_ARTIFACT_BYTES};
use bloch_l2_evm::ChainSpec;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bloch-sp1-artifact-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn selected(f: &fixture::Fixture) -> Vec<u8> {
    ExecutionArtifact::new(
        &ChainSpec::testnet(),
        B256::repeat_byte(0xd3),
        &f.parent,
        &f.header,
        &f.body,
        f.witness.clone(),
    )
    .unwrap()
    .encode()
    .unwrap()
}
fn artifact(variable: &str, default: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(default))
}
#[test]
fn artifact_admission_rejects_oversize_special_files_and_changed_envelopes() {
    let temp = Temp::new();
    let f = fixture::fixture_empty().unwrap();
    let bytes = selected(&f);
    let good = temp.path("good");
    fs::write(&good, &bytes).unwrap();
    assert_eq!(load_selected_artifact(&good).unwrap().expected(), f.expected);
    let oversized = temp.path("oversized");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(MAX_ARTIFACT_BYTES as u64 + 1)
        .unwrap();
    assert!(load_selected_artifact(&oversized).is_err());
    assert!(load_selected_artifact(&temp.0).is_err());
    for (name, bytes) in [
        ("empty", vec![]),
        ("truncated", bytes[..bytes.len() - 1].to_vec()),
        ("trailing", [bytes.as_slice(), b"x"].concat()),
    ] {
        let path = temp.path(name);
        fs::write(&path, bytes).unwrap();
        assert!(load_selected_artifact(&path).is_err());
    }
    #[cfg(unix)]
    {
        let link = temp.path("symlink");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert!(load_selected_artifact(&link).is_err());
        let fifo = temp.path("fifo");
        assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        assert!(load_selected_artifact(&fifo).is_err());
    }
}
#[test]
fn standalone_artifact_verification_requires_the_selected_header() {
    let temp = Temp::new();
    let contract = temp.path("contract.json");
    let empty = temp.path("empty.json");
    fs::write(&contract, selected(&fixture::fixture().unwrap())).unwrap();
    fs::write(&empty, selected(&fixture::fixture_empty().unwrap())).unwrap();
    let elf = artifact(
        "BLOCH_SP1_ELF",
        "../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bloch-evm-synthetic-guest",
    );
    let proof = artifact("BLOCH_SP1_CONTRACT_PROOF", "target/qualification-contract.proof");
    let verify = |path: &Path| {
        Command::new(env!("CARGO_BIN_EXE_bloch-evm-sp1-artifact"))
            .arg("verify")
            .arg(path)
            .arg(&elf)
            .arg(&proof)
            .env("RAYON_NUM_THREADS", "2")
            .output()
            .unwrap()
    };
    let accepted = verify(&contract);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let rejected = verify(&empty);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("Mismatch"));
}
