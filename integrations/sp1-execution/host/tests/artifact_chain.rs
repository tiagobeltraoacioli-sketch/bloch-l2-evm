//! Actual persisted Reth artifacts and real SP1 proofs; missing inputs fail.
#![cfg(feature = "node-artifact")]
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bloch-sp1-artifact-chain-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn execute(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bloch-evm-sp1-chain"))
        .args(args)
        .env("RAYON_NUM_THREADS", "2")
        .output()
        .unwrap()
}
fn invoke(mode: &str, elf: &Path, journal: &Path, directory: &Path, pairs: &[(u8, u8)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-evm-sp1-chain"));
    command.arg(mode).arg(elf).arg(journal).env("RAYON_NUM_THREADS", "2");
    for (artifact, proof) in pairs {
        command
            .arg(directory.join(format!("block-{artifact}.json")))
            .arg(directory.join(format!("block-{proof}.proof")));
    }
    command.output().unwrap()
}
fn success(output: Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("number=3"));
}

#[test]
fn arguments_and_chain_size_fail_before_opening_inputs_or_creating_output() {
    let temp = Temp::new();
    let journal = temp.0.join("must-not-exist");
    assert!(execute(&["--help".as_ref()]).status.success());
    for args in [
        vec![],
        vec!["settle"],
        vec!["unknown", "elf", "journal", "artifact", "proof"],
    ] {
        let args: Vec<_> = args.iter().map(std::ffi::OsStr::new).collect();
        assert!(!execute(&args).status.success());
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-evm-sp1-chain"));
    command.arg("settle").arg("absent-elf").arg(&journal);
    for _ in 0..17 {
        command.arg("absent-artifact").arg("absent-proof");
    }
    let rejected = command.output().unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("at most 16"));
    assert!(!journal.exists());
}

#[test]
fn real_three_block_chain_settles_and_reopens_without_trusting_serialized_cursor() {
    let host = Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = std::env::var_os("BLOCH_SP1_CHAIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| host.join("target/qualification-source-chain"));
    let elf = std::env::var_os("BLOCH_SP1_ELF").map(PathBuf::from).unwrap_or_else(|| {
        host.join("../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bloch-evm-synthetic-guest")
    });
    for number in 1..=3 {
        for extension in ["json", "proof"] {
            assert!(
                directory.join(format!("block-{number}.{extension}")).is_file(),
                "generate actual Reth artifacts and real SP1 proofs first"
            );
        }
    }
    let temp = Temp::new();
    let journal = temp.0.join("chain");
    let full = [(1, 1), (2, 2), (3, 3)];
    success(invoke("settle", &elf, &journal, &directory, &full));
    let original = fs::read(&journal).unwrap();
    success(invoke("verify", &elf, &journal, &directory, &full));
    assert_eq!(fs::read(&journal).unwrap(), original);
    assert!(!invoke("settle", &elf, &journal, &directory, &full).status.success());
    assert_eq!(fs::read(&journal).unwrap(), original);
    // The complete-chain selector refuses a valid suffix outside its chosen tip.
    assert!(!invoke("verify", &elf, &journal, &directory, &full[..2])
        .status
        .success());
    assert_eq!(fs::read(&journal).unwrap(), original);
    for (name, pairs) in [
        ("late-wrong-proof", vec![(1, 1), (2, 2), (3, 2)]),
        ("missing-genesis-prefix", vec![(2, 2), (3, 3)]),
        ("omitted-parent", vec![(1, 1), (3, 3)]),
        ("repeated-block", vec![(1, 1), (1, 1)]),
    ] {
        let rejected = temp.0.join(name);
        assert!(
            !invoke("settle", &elf, &rejected, &directory, &pairs).status.success(),
            "{name}"
        );
        assert!(
            !rejected.exists(),
            "invalid selected chain must fail before creating journal: {name}"
        );
    }
    fs::write(&journal, &original[..original.len() - 1]).unwrap();
    let truncated = fs::read(&journal).unwrap();
    assert!(!invoke("verify", &elf, &journal, &directory, &full).status.success());
    assert_eq!(fs::read(&journal).unwrap(), truncated, "no tail repair");
    fs::write(&journal, &original).unwrap();
    success(invoke("verify", &elf, &journal, &directory, &full));
}
