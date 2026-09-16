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

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
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
        Self(path)
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
