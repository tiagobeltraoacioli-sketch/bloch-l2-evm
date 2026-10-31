#![cfg(unix)]
use alloy_primitives::{Address, B256};
use bloch_escrow_journal::{Journal, JournalError, JournalHead};
use bloch_l2_evm::{
    domain::{input_commitment, TrustedL1Batch},
    escrow::{Coin, EscrowLedger, LockIntent, Outpoint},
    escrow_execution::{EscrowEvmDomain, TrustedEscrowBatch, TrustedLockLocation},
    escrow_inbox::InboxProof,
    execute_signed_block, generate_signed_batch_witness, BatchWitness, BlockContext, ChainSpec, DepositMint,
    DepositPosition, DepositProvenance, L2State, SignedBlockInput,
};
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

/// `File::try_lock` is an flock on the open file description. A child spawned by a
/// parallel test holds a copy of every open descriptor until its exec, so it can
/// make a lock taken in this window look contended (`Locked`). Tests that own a
/// temp directory therefore run one at a time.
static TEMP_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
thread_local!(static HOLDS_GATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) });
struct Gate(Option<std::sync::MutexGuard<'static, ()>>);
impl Gate {
    fn take() -> Self {
        if HOLDS_GATE.with(|held| held.replace(true)) {
            return Self(None);
        }
        Self(Some(TEMP_GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())))
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        if self.0.is_some() {
            HOLDS_GATE.with(|held| held.set(false));
        }
    }
}
struct Temp(PathBuf, #[allow(dead_code)] Gate);
impl Temp {
    fn new() -> Self {
        let gate = Gate::take();
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bloch-journal-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Self(path, gate)
    }
    fn record(&self, number: u64) -> PathBuf {
        self.0.join(format!("{number:020}.blj"))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    domain: EscrowEvmDomain,
    trusted: TrustedEscrowBatch,
    proofs: Vec<InboxProof>,
    input: SignedBlockInput,
    witness: BatchWitness,
    second: (TrustedEscrowBatch, SignedBlockInput, BatchWitness),
}
fn fixture() -> Fixture {
    let spec = ChainSpec::default();
    let mut state = L2State::genesis(&spec);
    let network = B256::repeat_byte(1);
    let domain = EscrowEvmDomain::new(
        network,
        B256::repeat_byte(2),
        B256::repeat_byte(3),
        spec.clone(),
        state.commit_root(),
        16 * 1024 * 1024,
    )
    .unwrap();
    let owner = B256::repeat_byte(6);
    let source = Outpoint {
        txid: B256::repeat_byte(8),
        vout: 0,
    };
    let mut escrow = EscrowLedger::new(network, domain.id(), vec![(source, Coin { value: 1000, owner })], 10).unwrap();
    let record = escrow
        .apply_authorized_lock(&LockIntent {
            network,
            domain: domain.id(),
            owner,
            inputs: vec![source],
            recipient: Address::repeat_byte(7),
            amount: 600,
            fee: 10,
            change_owner: owner,
            nonce: 0,
        })
        .unwrap();
    let snapshot = escrow.inbox();
    let proofs = vec![snapshot.proof(0).unwrap()];
    let mut context = BlockContext::next(&spec, &state);
    context.timestamp = 100;
    context.anchor_root = B256::repeat_byte(4);
    let input = SignedBlockInput {
        context,
        deposits: vec![DepositMint {
            recipient: record.recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 50,
                l1_tx_index: 3,
                l1_vout: 0,
                l1_txid: [9; 32],
                l1_sats: 600,
            },
        }],
        ..Default::default()
    };
    let (witness, _) = generate_signed_batch_witness(&state, &spec, &input).unwrap();
    let trusted = TrustedEscrowBatch {
        execution: TrustedL1Batch {
            height: 100,
            block: input.context.anchor_root,
            domain: domain.id(),
            input: input_commitment(&input),
        },
        inbox_root: snapshot.root(),
        count: 1,
        locations: vec![TrustedLockLocation {
            sequence: 0,
            intent: record.id,
            position: DepositPosition {
                l1_height: 50,
                l1_tx_index: 3,
                l1_vout: 0,
            },
            transaction: B256::repeat_byte(9),
        }],
    };
    execute_signed_block(&spec, &mut state, &input).unwrap();
    let mut context = BlockContext::next(&spec, &state);
    context.anchor_root = input.context.anchor_root;
    context.timestamp += 1;
    let second_input = SignedBlockInput {
        context,
        ..Default::default()
    };
    let (second_witness, _) = generate_signed_batch_witness(&state, &spec, &second_input).unwrap();
    let mut second_trusted = trusted.clone();
    second_trusted.locations.clear();
    second_trusted.execution.input = input_commitment(&second_input);
    Fixture {
        domain,
        trusted,
        proofs,
        input,
        witness,
        second: (second_trusted, second_input, second_witness),
    }
}
fn commit(journal: &mut Journal, f: &Fixture) {
    journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness).unwrap();
}

#[test]
fn restart_reexecutes_deposit_and_refuses_duplicate_credit() {
    let f = fixture();
    let temp = Temp::new();
    let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    commit(&mut journal, &f);
    let head = journal.head();
    let root = journal.state_root();
    drop(journal);
    let mut calls = 0;
    let mut journal = Journal::open(&temp.0, f.domain.clone(), head, |number| {
        assert_eq!(number, 1);
        calls += 1;
        Ok(f.trusted.clone())
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(journal.head(), head);
    assert_eq!(journal.state_root(), root);
    assert_eq!(journal.next_deposit(), 1);
    assert_eq!(journal.next_block(), 2);
    assert!(matches!(
        journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness),
        Err(JournalError::Verification(_))
    ));
    assert_eq!(journal.head(), head);
    journal.commit(&f.second.0, &[], &f.second.1, &f.second.2).unwrap();
    assert_eq!(journal.next_deposit(), 1);
    assert_eq!(journal.next_block(), 3);
}

#[test]
fn exclusive_writer_lock_is_released_on_drop() {
    let f = fixture();
    let temp = Temp::new();
    let journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    let head = journal.head();
    assert!(matches!(
        Journal::open(&temp.0, f.domain.clone(), head, |_| unreachable!()),
        Err(JournalError::Locked)
    ));
    assert!(Journal::create(&temp.0, f.domain.clone()).is_err());
    drop(journal);
    Journal::open(&temp.0, f.domain, head, |_| unreachable!()).unwrap();
}

#[test]
fn interrupted_temporary_write_is_ignored_and_lost_ack_commit_is_recovered() {
    let f = fixture();
    let temp = Temp::new();
    let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    let minimum = journal.head();
    commit(&mut journal, &f);
    let committed = journal.head();
    drop(journal);
    fs::write(temp.0.join(".pending-interrupted"), b"incomplete payload").unwrap();
    let journal = Journal::open(&temp.0, f.domain, minimum, |_| Ok(f.trusted.clone())).unwrap();
    assert_eq!(journal.head(), committed);
    assert_eq!(journal.next_deposit(), 1);
}

#[test]
fn publication_error_poisoning_prevents_unsafe_retry() {
    let f = fixture();
    let temp = Temp::new();
    let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    let head = journal.head();
    let root = journal.state_root();
    fs::create_dir(temp.record(1)).unwrap(); // Simulate a destination I/O conflict.
    assert!(matches!(
        journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness),
        Err(JournalError::CommitUncertain(_))
    ));
    assert_eq!(journal.head(), head);
    assert_eq!(journal.state_root(), root);
    assert_eq!(journal.next_deposit(), 0);
    fs::remove_dir(temp.record(1)).unwrap();
    assert!(matches!(
        journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness),
        Err(JournalError::Poisoned)
    ));
    drop(journal);
    let mut journal = Journal::open(&temp.0, f.domain.clone(), head, |_| unreachable!()).unwrap();
    commit(&mut journal, &f);
}

#[test]
fn invalid_execution_writes_nothing_and_does_not_poison() {
    let f = fixture();
    let temp = Temp::new();
    let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    let mut bad = f.witness.clone();
    bad.new_state_root = B256::ZERO;
    assert!(matches!(
        journal.commit(&f.trusted, &f.proofs, &f.input, &bad),
        Err(JournalError::Verification(_))
    ));
    assert!(!temp.record(1).exists());
    commit(&mut journal, &f);
}

#[test]
fn committed_corruption_and_truncation_are_not_silently_discarded() {
    for truncate in [false, true] {
        let f = fixture();
        let temp = Temp::new();
        let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
        commit(&mut journal, &f);
        let head = journal.head();
        drop(journal);
        let mut bytes = fs::read(temp.record(1)).unwrap();
        if truncate {
            bytes.truncate(bytes.len() - 1);
        } else {
            bytes[20] ^= 1;
        }
        fs::write(temp.record(1), bytes).unwrap();
        assert!(matches!(
            Journal::open(&temp.0, f.domain, head, |_| panic!("must reject before derivation")),
            Err(JournalError::Format)
        ));
    }
}

#[test]
fn independent_watermark_detects_suffix_deletion_and_wrong_digest() {
    let f = fixture();
    let temp = Temp::new();
    let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    commit(&mut journal, &f);
    let head = journal.head();
    drop(journal);
    let wrong = JournalHead {
        blocks: 1,
        digest: B256::ZERO,
    };
    assert!(matches!(
        Journal::open(&temp.0, f.domain.clone(), wrong, |_| Ok(f.trusted.clone())),
        Err(JournalError::Rollback)
    ));
    fs::remove_file(temp.record(1)).unwrap();
    assert!(matches!(
        Journal::open(&temp.0, f.domain, head, |_| unreachable!()),
        Err(JournalError::Rollback)
    ));
}

#[test]
fn missing_middle_record_is_rejected() {
    let f = fixture();
    let temp = Temp::new();
    let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    commit(&mut journal, &f);
    journal.commit(&f.second.0, &[], &f.second.1, &f.second.2).unwrap();
    let head = journal.head();
    drop(journal);
    fs::remove_file(temp.record(1)).unwrap();
    assert!(matches!(
        Journal::open(&temp.0, f.domain, head, |_| unreachable!()),
        Err(JournalError::Format)
    ));
}

#[test]
fn recovery_requires_fresh_external_derivation_and_correct_domain() {
    let f = fixture();
    let temp = Temp::new();
    let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    commit(&mut journal, &f);
    let head = journal.head();
    drop(journal);
    assert!(matches!(
        Journal::open(&temp.0, f.domain.clone(), head, |_| Err(io::Error::other(
            "L1 unavailable"
        ))),
        Err(JournalError::Derivation(_))
    ));
    let mut wrong = f.trusted.clone();
    wrong.execution.input = B256::ZERO;
    assert!(matches!(
        Journal::open(&temp.0, f.domain.clone(), head, |_| Ok(wrong.clone())),
        Err(JournalError::Verification(_))
    ));
    let other = EscrowEvmDomain::new(
        B256::repeat_byte(99),
        B256::repeat_byte(2),
        B256::repeat_byte(3),
        ChainSpec::default(),
        f.domain.state_root(),
        16 * 1024 * 1024,
    )
    .unwrap();
    assert!(matches!(
        Journal::open(&temp.0, other, head, |_| unreachable!()),
        Err(JournalError::WrongDomain)
    ));
}

#[test]
fn malformed_unicode_filename_and_symlink_fail_without_panicking() {
    let f = fixture();
    let temp = Temp::new();
    let journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    let head = journal.head();
    drop(journal);
    let malformed = temp.0.join(format!("{}é.blj", "x".repeat(18)));
    fs::write(&malformed, []).unwrap();
    assert!(matches!(
        Journal::open(&temp.0, f.domain.clone(), head, |_| unreachable!()),
        Err(JournalError::Format)
    ));
    fs::remove_file(malformed).unwrap();
    std::os::unix::fs::symlink(temp.0.join("MANIFEST"), temp.record(1)).unwrap();
    assert!(matches!(
        Journal::open(&temp.0, f.domain, head, |_| unreachable!()),
        Err(JournalError::Format)
    ));
}

#[test]
fn recomputed_file_checksum_does_not_bypass_execution_or_receipt_checks() {
    for change_receipt in [false, true] {
        let f = fixture();
        let temp = Temp::new();
        let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
        let minimum = journal.head();
        commit(&mut journal, &f);
        drop(journal);
        let bytes = fs::read(temp.record(1)).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes[16..bytes.len() - 32]).unwrap();
        let zero = serde_json::to_value(B256::ZERO).unwrap();
        if change_receipt {
            value["receipt"] = zero;
        } else {
            value["witness"]["new_state_root"] = zero;
        }
        let payload = serde_json::to_vec(&value).unwrap();
        let mut changed = bytes[..8].to_vec();
        changed.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        changed.extend_from_slice(&payload);
        changed.extend_from_slice(alloy_primitives::keccak256(payload).as_slice());
        fs::write(temp.record(1), changed).unwrap();
        let recovered = Journal::open(&temp.0, f.domain, minimum, |_| Ok(f.trusted.clone()));
        if change_receipt {
            assert!(matches!(recovered, Err(JournalError::Format)));
        } else {
            assert!(matches!(recovered, Err(JournalError::Verification(_))));
        }
    }
}

#[test]
fn oversized_disk_record_is_rejected_before_reading_payload() {
    let f = fixture();
    let temp = Temp::new();
    let journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    let minimum = journal.head();
    drop(journal);
    let file = fs::File::create(temp.record(1)).unwrap();
    file.set_len(bloch_escrow_journal::MAX_RECORD_BYTES as u64 + 49)
        .unwrap();
    assert!(matches!(
        Journal::open(&temp.0, f.domain, minimum, |_| unreachable!()),
        Err(JournalError::Limit)
    ));
}

#[test]
fn crash_child_writer() {
    let Some(path) = std::env::var_os("BLOCH_JOURNAL_CRASH_TEST_PATH") else {
        return;
    };
    let f = fixture();
    let mut journal = Journal::create(path, f.domain.clone()).unwrap();
    commit(&mut journal, &f);
    // Exit without dropping Journal or releasing its lock in application code.
    std::process::exit(73);
}

#[test]
fn committed_state_survives_process_exit_without_destructors() {
    let temp = Temp::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child_writer", "--nocapture"])
        .env("BLOCH_JOURNAL_CRASH_TEST_PATH", &temp.0)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    let f = fixture();
    let minimum = JournalHead::genesis(f.domain.id());
    let journal = Journal::open(&temp.0, f.domain, minimum, |_| Ok(f.trusted.clone())).unwrap();
    assert_eq!(journal.next_block(), 2);
    assert_eq!(journal.next_deposit(), 1);
    assert_eq!(journal.state_root(), f.witness.new_state_root);
}

fn cli_setup(temp: &Temp, f: &Fixture) {
    fs::create_dir(&temp.0).unwrap();
    fs::create_dir(temp.0.join("trust")).unwrap();
    let config = serde_json::json!({ "version": 1, "profile": "bloch-evm-cancun-local-v1",
        "network": B256::repeat_byte(1), "module": B256::repeat_byte(2), "runtime": B256::repeat_byte(3),
        "expected_domain": f.domain.id(), "witness_limit": 16777216 });
    write_json(temp.0.join("config.json"), &config);
    let head = JournalHead::genesis(f.domain.id());
    write_json(
        temp.0.join("head.json"),
        &serde_json::json!({"blocks": head.blocks, "digest": head.digest}),
    );
    write_json(
        temp.0.join("proposal.json"),
        &serde_json::json!({"version": 1,
        "proofs": f.proofs, "input": f.input, "witness": f.witness}),
    );
    let t = &f.trusted;
    let locations: Vec<_> = t
        .locations
        .iter()
        .map(|l| {
            serde_json::json!({
                "sequence": l.sequence, "intent": l.intent, "height": l.position.l1_height,
                "transaction_index": l.position.l1_tx_index, "output_index": l.position.l1_vout,
                "transaction": l.transaction,
            })
        })
        .collect();
    write_json(
        temp.0.join("trust/00000000000000000001.json"),
        &serde_json::json!({
            "version": 1, "height": t.execution.height, "block": t.execution.block,
            "domain": t.execution.domain, "input": t.execution.input, "inbox_root": t.inbox_root,
            "count": t.count, "locations": locations,
        }),
    );
}
fn write_json(path: PathBuf, value: &serde_json::Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn cli(temp: &Temp, command: &str) -> std::process::Output {
    let mut process = std::process::Command::new(env!("CARGO_BIN_EXE_bloch-domain"));
    process
        .arg(command)
        .arg(temp.0.join("config.json"))
        .arg(temp.0.join("journal"));
    if command != "init" {
        process.arg(temp.0.join("head.json")).arg(temp.0.join("trust"));
    }
    if command == "apply" {
        process.arg(temp.0.join("proposal.json"));
    }
    process.output().unwrap()
}

#[test]
fn cli_initializes_applies_recovers_and_refuses_duplicate_credit() {
    let f = fixture();
    let temp = Temp::new();
    cli_setup(&temp, &f);
    assert!(cli(&temp, "init").status.success());
    let output = cli(&temp, "apply");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let applied: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(applied["next_deposit"], 1);
    assert_eq!(applied["history_usage"]["records"], 1);
    assert_eq!(
        applied["history_usage"]["bytes"],
        fs::metadata(temp.0.join("journal/00000000000000000001.blj"))
            .unwrap()
            .len()
            .to_string()
    );
    assert_eq!(
        applied["state_root"],
        serde_json::to_value(f.witness.new_state_root).unwrap()
    );
    write_json(temp.0.join("head.json"), &applied["head"]);
    let recovered = cli(&temp, "status");
    assert!(recovered.status.success());
    let recovered: serde_json::Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(recovered["head"], applied["head"]);
    assert_eq!(recovered["next_deposit"], 1);
    assert_eq!(cli(&temp, "apply").status.code(), Some(1));
    assert!(!temp.0.join("journal/00000000000000000002.blj").exists());
    fs::remove_file(temp.0.join("trust/00000000000000000001.json")).unwrap();
    assert_eq!(cli(&temp, "status").status.code(), Some(1));
}

#[test]
fn cli_never_takes_trusted_context_from_the_proposal() {
    let f = fixture();
    let temp = Temp::new();
    cli_setup(&temp, &f);
    assert!(cli(&temp, "init").status.success());
    let path = temp.0.join("proposal.json");
    let mut proposal: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    proposal["trusted"] = serde_json::json!({"finalized": true});
    write_json(path.clone(), &proposal);
    assert_eq!(cli(&temp, "apply").status.code(), Some(1));
    proposal.as_object_mut().unwrap().remove("trusted");
    write_json(path, &proposal);
    let trust_path = temp.0.join("trust/00000000000000000001.json");
    let mut trust: serde_json::Value = serde_json::from_slice(&fs::read(&trust_path).unwrap()).unwrap();
    trust["input"] = serde_json::to_value(B256::ZERO).unwrap();
    write_json(trust_path.clone(), &trust);
    assert_eq!(cli(&temp, "apply").status.code(), Some(1));
    fs::remove_file(trust_path).unwrap();
    assert_eq!(cli(&temp, "apply").status.code(), Some(1));
    assert!(!temp.0.join("journal/00000000000000000001.blj").exists());
}

#[test]
fn cli_rejects_wrong_identity_symlinks_and_oversized_inputs() {
    let f = fixture();
    let temp = Temp::new();
    cli_setup(&temp, &f);
    let config_path = temp.0.join("config.json");
    let mut config: serde_json::Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    config["expected_domain"] = serde_json::to_value(B256::ZERO).unwrap();
    write_json(config_path.clone(), &config);
    assert_eq!(cli(&temp, "init").status.code(), Some(1));
    assert!(!temp.0.join("journal").exists());
    config["expected_domain"] = serde_json::to_value(f.domain.id()).unwrap();
    write_json(config_path, &config);
    assert!(cli(&temp, "init").status.success());
    let proposal = temp.0.join("proposal.json");
    fs::rename(&proposal, temp.0.join("real-proposal.json")).unwrap();
    std::os::unix::fs::symlink(temp.0.join("real-proposal.json"), &proposal).unwrap();
    assert_eq!(cli(&temp, "apply").status.code(), Some(1));
    fs::remove_file(&proposal).unwrap();
    fs::File::create(proposal)
        .unwrap()
        .set_len(bloch_escrow_journal::MAX_RECORD_BYTES as u64 + 1)
        .unwrap();
    assert_eq!(cli(&temp, "apply").status.code(), Some(1));
    assert!(!temp.0.join("journal/00000000000000000001.blj").exists());
}

#[test]
fn recovery_budget_rejects_before_derivation_and_accepts_exact_boundary() {
    use bloch_escrow_journal::RecoveryLimits;
    let temp = Temp::new();
    let f = fixture();
    let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness).unwrap();
    let head = journal.head();
    drop(journal);
    let bytes = fs::metadata(temp.record(1)).unwrap().len();
    let original = fs::read(temp.record(1)).unwrap();
    for limits in [
        RecoveryLimits { records: 0, bytes },
        RecoveryLimits {
            records: 1,
            bytes: bytes - 1,
        },
    ] {
        assert!(matches!(
            Journal::open_with_limits(&temp.0, f.domain.clone(), head, limits, |_| panic!(
                "over-budget history must not request derivation"
            )),
            Err(JournalError::Limit)
        ));
        assert_eq!(fs::read(temp.record(1)).unwrap(), original);
    }
    let mut calls = 0;
    let recovered = Journal::open_with_limits(
        &temp.0,
        f.domain,
        head,
        RecoveryLimits { records: 1, bytes },
        |number| {
            calls += 1;
            assert_eq!(number, 1);
            Ok(f.trusted.clone())
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(recovered.head(), head);
}

#[test]
fn empty_journal_recovers_with_zero_record_budget() {
    use bloch_escrow_journal::RecoveryLimits;
    let temp = Temp::new();
    let f = fixture();
    let journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    let head = journal.head();
    drop(journal);
    let recovered = Journal::open_with_limits(&temp.0, f.domain, head, RecoveryLimits { records: 0, bytes: 0 }, |_| {
        panic!("empty journal needs no derivation")
    })
    .unwrap();
    assert_eq!(recovered.head(), head);
}

#[test]
fn recovery_byte_budget_is_cumulative_across_records() {
    use bloch_escrow_journal::RecoveryLimits;
    let temp = Temp::new();
    let f = fixture();
    let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
    journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness).unwrap();
    journal.commit(&f.second.0, &[], &f.second.1, &f.second.2).unwrap();
    let head = journal.head();
    drop(journal);
    let first = fs::metadata(temp.record(1)).unwrap().len();
    let second = fs::metadata(temp.record(2)).unwrap().len();
    assert!(matches!(
        Journal::open_with_limits(
            &temp.0,
            f.domain.clone(),
            head,
            RecoveryLimits {
                records: 2,
                bytes: first.max(second)
            },
            |_| panic!("total budget must be checked before replay")
        ),
        Err(JournalError::Limit)
    ));
    let recovered = Journal::open_with_limits(
        &temp.0,
        f.domain,
        head,
        RecoveryLimits {
            records: 2,
            bytes: first + second,
        },
        |number| {
            Ok(if number == 1 {
                f.trusted.clone()
            } else {
                f.second.0.clone()
            })
        },
    )
    .unwrap();
    assert_eq!(recovered.head(), head);
}

#[test]
fn cli_recovery_budgets_apply_to_status_and_apply_without_mutating_history() {
    let f = fixture();
    let temp = Temp::new();
    cli_setup(&temp, &f);
    assert!(cli(&temp, "init").status.success());
    let applied = cli(&temp, "apply");
    assert!(applied.status.success());
    let applied: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    write_json(temp.0.join("head.json"), &applied["head"]);
    let record = temp.0.join("journal/00000000000000000001.blj");
    let original = fs::read(&record).unwrap();
    let size = original.len() as u64;
    let path = temp.0.join("config.json");
    let mut config: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for limits in [
        serde_json::json!({"max_records": 0, "max_bytes": size}),
        serde_json::json!({"max_records": 1, "max_bytes": size - 1}),
    ] {
        config["recovery"] = limits;
        write_json(path.clone(), &config);
        for command in ["status", "apply"] {
            let output = cli(&temp, command);
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("Limit"));
        }
        assert_eq!(fs::read(&record).unwrap(), original);
        assert!(!temp.0.join("journal/00000000000000000002.blj").exists());
    }
    config["recovery"] = serde_json::json!({"max_records": 1, "max_bytes": size});
    write_json(path.clone(), &config);
    let status = cli(&temp, "status");
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["head"], applied["head"]);
    // Misspelled or incomplete budget objects must not silently use defaults.
    for limits in [
        serde_json::json!({"max_record": 1, "max_bytes": size}),
        serde_json::json!({"max_records": 1}),
        serde_json::json!({"max_records": -1, "max_bytes": size}),
    ] {
        config["recovery"] = limits;
        write_json(path.clone(), &config);
        assert_eq!(cli(&temp, "status").status.code(), Some(1));
    }
}

#[test]
fn retained_recovery_budget_prevents_unrecoverable_new_commits() {
    use bloch_escrow_journal::RecoveryLimits;
    let f = fixture();
    let reference = Temp::new();
    let mut measured = Journal::create(&reference.0, f.domain.clone()).unwrap();
    measured.commit(&f.trusted, &f.proofs, &f.input, &f.witness).unwrap();
    measured.commit(&f.second.0, &[], &f.second.1, &f.second.2).unwrap();
    let total = fs::metadata(reference.record(1)).unwrap().len() + fs::metadata(reference.record(2)).unwrap().len();
    let temp = Temp::new();
    let created = Journal::create(&temp.0, f.domain.clone()).unwrap();
    let genesis = created.head();
    drop(created);
    for limits in [
        RecoveryLimits {
            records: 0,
            bytes: total,
        },
        RecoveryLimits { records: 2, bytes: 0 },
    ] {
        let mut journal =
            Journal::open_with_limits(&temp.0, f.domain.clone(), genesis, limits, |_| panic!("empty history")).unwrap();
        assert!(matches!(
            journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness),
            Err(JournalError::Limit)
        ));
        assert_eq!(journal.head(), genesis);
        assert!(!temp.record(1).exists());
    }
    let limits = RecoveryLimits {
        records: 2,
        bytes: total - 1,
    };
    let mut journal =
        Journal::open_with_limits(&temp.0, f.domain.clone(), genesis, limits, |_| panic!("empty history")).unwrap();
    journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness).unwrap();
    let first = journal.head();
    assert!(matches!(
        journal.commit(&f.second.0, &[], &f.second.1, &f.second.2),
        Err(JournalError::Limit)
    ));
    assert_eq!(journal.head(), first);
    assert_eq!(journal.next_block(), 2);
    assert!(!temp.record(2).exists());
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 3); // no pending publication
    drop(journal);
    let mut journal = Journal::open_with_limits(
        &temp.0,
        f.domain.clone(),
        first,
        RecoveryLimits {
            records: 2,
            bytes: total,
        },
        |_| Ok(f.trusted.clone()),
    )
    .unwrap();
    journal.commit(&f.second.0, &[], &f.second.1, &f.second.2).unwrap();
    let head = journal.head();
    drop(journal);
    let recovered = Journal::open_with_limits(
        &temp.0,
        f.domain,
        head,
        RecoveryLimits {
            records: 2,
            bytes: total,
        },
        |n| Ok(if n == 1 { f.trusted.clone() } else { f.second.0.clone() }),
    )
    .unwrap();
    assert_eq!(recovered.head(), head);
    let usage = recovered.history_usage().unwrap();
    assert_eq!(usage.records, 2);
    assert_eq!(usage.bytes, total);
    assert_eq!(usage.remaining_records, 0);
    assert_eq!(usage.remaining_bytes, 0);
}

#[test]
fn cli_apply_does_not_write_beyond_configured_recovery_budget() {
    let f = fixture();
    let temp = Temp::new();
    cli_setup(&temp, &f);
    assert!(cli(&temp, "init").status.success());
    let path = temp.0.join("config.json");
    let mut config: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for limits in [
        serde_json::json!({"max_records": 0, "max_bytes": 10000000}),
        serde_json::json!({"max_records": 10, "max_bytes": 0}),
    ] {
        config["recovery"] = limits;
        write_json(path.clone(), &config);
        assert!(cli(&temp, "status").status.success());
        let output = cli(&temp, "apply");
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("Limit"));
        assert!(!temp.0.join("journal/00000000000000000001.blj").exists());
        assert_eq!(fs::read_dir(temp.0.join("journal")).unwrap().count(), 2);
    }
    config.as_object_mut().unwrap().remove("recovery");
    write_json(path, &config);
    assert!(cli(&temp, "apply").status.success());
}
