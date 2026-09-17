//! Real saved SP1 proofs are required: run the documented proof qualification first.
//! Override paths with BLOCH_SP1_ELF, BLOCH_SP1_EMPTY_PROOF and BLOCH_SP1_CONTRACT_PROOF.
#[path = "../src/fixture.rs"]
#[allow(dead_code)]
mod fixture;

use alloy_primitives::keccak256;
use bloch_evm_sp1_host::{
    settlement::{SettlementCursor, SettlementJournal, MAX_JOURNAL_BYTES},
    verification::{decode_proof, load_proof, TrustedProgram, MAX_PROOF_BYTES},
};
use bloch_l2_evm::{node_primitives::NodeHeaderV2, ChainSpec};
use sp1_sdk::{Elf, SP1Proof, SP1PublicValues};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bloch-sp1-settlement-{}-{}",
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
impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn artifact(variable: &str, default: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(default))
}
fn paths() -> (PathBuf, PathBuf, PathBuf) {
    (
        artifact(
            "BLOCH_SP1_ELF",
            "../guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bloch-evm-synthetic-guest",
        ),
        artifact("BLOCH_SP1_EMPTY_PROOF", "target/qualification-empty.proof"),
        artifact("BLOCH_SP1_CONTRACT_PROOF", "target/qualification-contract.proof"),
    )
}
fn cursor(program: &TrustedProgram, fixture: &fixture::Fixture) -> SettlementCursor {
    SettlementCursor::from_trusted_anchor(
        ChainSpec::testnet(),
        fixture.expected.domain,
        program.identity(),
        fixture.parent.clone(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_proofs_bind_program_header_cursor_and_durable_recovery() {
    let (elf_path, empty_path, contract_path) = paths();
    let elf = fs::read(&elf_path).expect("build the pinned guest first");
    let trusted = TrustedProgram::from_trusted_elf(Elf::from(elf.clone())).await.unwrap();
    let empty = fixture::fixture_empty().unwrap();
    let contract = fixture::fixture().unwrap();
    let verified_empty = trusted
        .verify_file(&empty_path, &empty.expected)
        .expect("generate empty proof first");
    let verified_contract = trusted
        .verify_file(&contract_path, &contract.expected)
        .expect("generate contract proof first");
    assert_eq!(verified_empty.statement(), empty.expected);
    let initial = cursor(&trusted, &empty);
    assert_eq!(
        initial.expected_for_selected_header(&empty.header).unwrap(),
        empty.expected
    );
    let mut current = initial.clone();
    let accepted = current.advance(&verified_empty, &empty.header).unwrap();
    assert_eq!(accepted.header_hash, empty.header.hash());
    assert_eq!(accepted.state_root, empty.header.state_root);
    assert!(current.advance(&verified_empty, &empty.header).is_err());
    assert!(current.advance(&verified_contract, &contract.header).is_err());
    assert_eq!(current.mark(), accepted);

    let mutations: [fn(&mut NodeHeaderV2); 8] = [
        |h| h.parent_hash[0] ^= 1,
        |h| h.parent_state_root[0] ^= 1,
        |h| h.state_root[0] ^= 1,
        |h| h.domain[0] ^= 1,
        |h| h.number += 1,
        |h| h.chain_id += 1,
        |h| h.base_fee_per_gas += 1,
        |h| h.receipts_root[0] ^= 1,
    ];
    for mutate in mutations {
        let mut header = empty.header.clone();
        mutate(&mut header);
        let mut unchanged = initial.clone();
        assert!(unchanged.advance(&verified_empty, &header).is_err());
        assert_eq!(unchanged.mark(), initial.mark());
    }
    let mut other_spec = ChainSpec::testnet();
    other_spec.max_l1_sats -= 1;
    let mut other_config = SettlementCursor::from_trusted_anchor(
        other_spec,
        empty.expected.domain,
        trusted.identity(),
        empty.parent.clone(),
    )
    .unwrap();
    assert!(other_config.advance(&verified_empty, &empty.header).is_err());
    assert_eq!(other_config.mark(), initial.mark());

    // A changed ELF artifact can describe the same VM program/key. Its token
    // must still not cross the cursor's exact trusted-artifact identity.
    let mut alternate_elf = elf;
    alternate_elf.push(0);
    let alternate = TrustedProgram::from_trusted_elf(Elf::from(alternate_elf))
        .await
        .unwrap();
    assert_ne!(alternate.identity(), trusted.identity());
    assert_eq!(
        alternate.identity().verifying_key_hash(),
        trusted.identity().verifying_key_hash()
    );
    let alternate_token = alternate.verify_file(&empty_path, &empty.expected).unwrap();
    let mut unchanged = initial.clone();
    assert!(unchanged.advance(&alternate_token, &empty.header).is_err());
    assert_eq!(unchanged.mark(), initial.mark());

    let mut bad_public = load_proof(&empty_path).unwrap();
    let mut public = bad_public.public_values.as_slice().to_vec();
    public[0] ^= 1;
    bad_public.public_values = SP1PublicValues::from(public.as_slice());
    assert!(trusted.verify(bad_public, &empty.expected).is_err());
    let mut truncated = load_proof(&empty_path).unwrap();
    if let SP1Proof::Core(shards) = &mut truncated.proof {
        shards.pop().unwrap();
    }
    assert!(trusted.verify(truncated, &empty.expected).is_err());
    assert!(trusted.verify_file(&empty_path, &contract.expected).is_err());

    let temp = TestDirectory::new();
    let path = temp.path("empty.journal");
    let mut journal = SettlementJournal::create(&path, initial.clone()).unwrap();
    let prefix_len = fs::metadata(&path).unwrap().len() as usize;
    assert!(SettlementJournal::create(&path, initial.clone()).is_err());
    assert!(
        SettlementJournal::open(&path, &trusted, initial.clone(), initial.mark()).is_err(),
        "writer lock must exclude a second opener"
    );
    assert_eq!(journal.append(&verified_empty, &empty.header).unwrap(), accepted);
    let complete = fs::read(&path).unwrap();
    assert!(journal.append(&verified_empty, &empty.header).is_err());
    assert!(journal.append(&verified_contract, &contract.header).is_err());
    assert!(!journal.is_poisoned());
    assert_eq!(journal.cursor().mark(), accepted);
    assert_eq!(fs::read(&path).unwrap(), complete);
    drop(journal);
    let recovered = SettlementJournal::open(&path, &trusted, initial.clone(), accepted).unwrap();
    assert_eq!(recovered.cursor().mark(), accepted);
    drop(recovered);
    assert!(SettlementJournal::open(&path, &alternate, initial.clone(), accepted).is_err());
    let mut wrong_floor = accepted;
    wrong_floor.header_hash[0] ^= 1;
    assert!(SettlementJournal::open(&path, &trusted, initial.clone(), wrong_floor).is_err());

    let rollback = temp.path("rollback.journal");
    fs::write(&rollback, &complete[..prefix_len]).unwrap();
    assert!(SettlementJournal::open(&rollback, &trusted, initial.clone(), accepted).is_err());
    assert_eq!(fs::read(&rollback).unwrap(), complete[..prefix_len]);
    let partial = temp.path("partial.journal");
    fs::write(&partial, &complete[..complete.len() - 1]).unwrap();
    assert!(SettlementJournal::open(&partial, &trusted, initial.clone(), accepted).is_err());

    // Recompute the checksum after corrupting authenticated public values. A
    // checksum-only journal would accept this; real proof re-verification must not.
    let forged = temp.path("forged.journal");
    let mut forged_bytes = complete.clone();
    let frame_len = u32::from_be_bytes(forged_bytes[prefix_len..prefix_len + 4].try_into().unwrap()) as usize;
    let start = prefix_len + 4;
    let end = start + frame_len;
    let header_len = u32::from_be_bytes(forged_bytes[start..start + 4].try_into().unwrap()) as usize;
    let mut proof = load_proof(&empty_path).unwrap();
    let mut public = proof.public_values.as_slice().to_vec();
    *public.last_mut().unwrap() ^= 1;
    proof.public_values = SP1PublicValues::from(public.as_slice());
    forged_bytes[start + 4 + header_len..end].copy_from_slice(&bincode::serialize(&proof).unwrap());
    let checksum = keccak256(&forged_bytes[start..end]);
    forged_bytes[end..end + 32].copy_from_slice(checksum.as_slice());
    fs::write(&forged, &forged_bytes).unwrap();
    assert!(SettlementJournal::open(&forged, &trusted, initial.clone(), accepted).is_err());
    assert_eq!(fs::read(&forged).unwrap(), forged_bytes);

    let fork = temp.path("fork.journal");
    let mut competing = SettlementJournal::create(&fork, initial.clone()).unwrap();
    let contract_mark = competing.append(&verified_contract, &contract.header).unwrap();
    drop(competing);
    assert!(SettlementJournal::open(&fork, &trusted, initial.clone(), accepted).is_err());
    assert_eq!(
        SettlementJournal::open(&fork, &trusted, initial.clone(), contract_mark)
            .unwrap()
            .cursor()
            .mark(),
        contract_mark
    );

    let oversized = temp.path("oversized.journal");
    fs::write(&oversized, &complete[..prefix_len]).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&oversized)
        .unwrap()
        .set_len(MAX_JOURNAL_BYTES + 1)
        .unwrap();
    assert!(SettlementJournal::open(&oversized, &trusted, initial.clone(), accepted).is_err());

    let changed = temp.path("changed.journal");
    let mut sole_writer = SettlementJournal::create(&changed, initial.clone()).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&changed)
        .unwrap()
        .write_all(&[0])
        .unwrap();
    assert!(sole_writer.append(&verified_empty, &empty.header).is_err());
    assert!(sole_writer.is_poisoned());
    assert_eq!(sole_writer.cursor().mark(), initial.mark());
    assert!(sole_writer.append(&verified_empty, &empty.header).is_err());
    drop(sole_writer);
    assert!(SettlementJournal::open(&changed, &trusted, initial.clone(), initial.mark()).is_err());
}

#[test]
fn bounded_strict_proof_admission_and_file_types() {
    let (_, proof_path, _) = paths();
    let valid = fs::read(&proof_path).expect("generate empty proof first");
    decode_proof(&valid).unwrap();
    let mut bytes = valid.clone();
    bytes.push(0);
    assert!(decode_proof(&bytes).is_err());
    assert!(decode_proof(&valid[..valid.len() - 1]).is_err());
    assert!(decode_proof(&[]).is_err());
    let mut declared = [0; 12];
    declared[4..].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(decode_proof(&declared).is_err());
    declared[..4].copy_from_slice(&1u32.to_le_bytes());
    assert!(decode_proof(&declared).is_err());
    let temp = TestDirectory::new();
    let oversized = temp.path("oversized.proof");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(MAX_PROOF_BYTES as u64 + 1)
        .unwrap();
    assert!(load_proof(&oversized).is_err());
    assert!(load_proof(&temp.0).is_err());
    #[cfg(unix)]
    {
        let link = temp.path("symlink.proof");
        std::os::unix::fs::symlink(&proof_path, &link).unwrap();
        assert!(load_proof(&link).is_err());
        let fifo = temp.path("fifo.proof");
        assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        assert!(load_proof(&fifo).is_err(), "must not block opening a FIFO");
    }
}

#[test]
fn cli_settlement_uses_independent_processes_and_fixture_floor() {
    let (elf, empty, contract) = paths();
    let temp = TestDirectory::new();
    for (name, proof) in [("empty", &empty), ("contract", &contract)] {
        let journal = temp.path(&format!("{name}.journal"));
        let run = |mode: &str, fixture: &str, file: &Path, extra: Option<&Path>| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_bloch-evm-sp1-host"));
            command
                .env("RAYON_NUM_THREADS", "2")
                .args([mode, fixture])
                .arg(&elf)
                .arg(file);
            if let Some(extra) = extra {
                command.arg(extra);
            }
            command.output().unwrap()
        };
        let settled = run("settle", name, proof, Some(&journal));
        assert!(settled.status.success(), "{}", String::from_utf8_lossy(&settled.stderr));
        let verified = run("verify-settlement", name, &journal, None);
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        let alternate = if name == "empty" { "contract" } else { "empty" };
        assert!(!run("verify-settlement", alternate, &journal, None).status.success());
        let original = fs::read(&journal).unwrap();
        assert!(!run("settle", name, proof, Some(&journal)).status.success());
        assert_eq!(fs::read(&journal).unwrap(), original);
        let broken = temp.path(&format!("{name}-truncated.journal"));
        fs::write(&broken, &original[..original.len() - 1]).unwrap();
        assert!(!run("verify-settlement", name, &broken, None).status.success());
        let corrupt = temp.path(&format!("{name}-corrupt.journal"));
        let mut bytes = original;
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&corrupt, &bytes).unwrap();
        assert!(!run("verify-settlement", name, &corrupt, None).status.success());
        assert_eq!(fs::read(&corrupt).unwrap(), bytes);
    }
}
