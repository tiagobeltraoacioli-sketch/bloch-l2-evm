use super::*;
use alloy_primitives::Address;
use bloch_l2_evm::{
    domain::{input_commitment, TrustedL1Batch},
    escrow::{Coin, EscrowLedger, LockIntent, Outpoint},
    escrow_execution::TrustedLockLocation,
    execute_signed_block, generate_signed_batch_witness, BlockContext, ChainSpec, DepositMint, DepositPosition,
    DepositProvenance, L2State,
};

const STAGES: [PublicationStage; 5] = [
    PublicationStage::Created,
    PublicationStage::Written,
    PublicationStage::FileSynced,
    PublicationStage::Renamed,
    PublicationStage::DirectorySynced,
];
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
    let inbox = escrow.inbox();
    let proofs = vec![inbox.proof(0).unwrap()];
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
                l1_txid: [9; 32],
                l1_vout: 0,
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
        inbox_root: inbox.root(),
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
    context.timestamp += 1;
    context.anchor_root = input.context.anchor_root;
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
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "bloch-publication-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        Self(std::env::temp_dir().join(name))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn check_recovery(path: &Path, f: &Fixture, committed: bool) {
    let minimum = JournalHead::genesis(f.domain.id());
    let mut derivations = 0;
    let mut journal = Journal::open(path, f.domain.clone(), minimum, |number| {
        assert_eq!(number, 1);
        derivations += 1;
        Ok(f.trusted.clone())
    })
    .unwrap();
    assert_eq!(derivations, usize::from(committed));
    assert_eq!(journal.head().blocks, u64::from(committed));
    assert_eq!(journal.next_deposit(), u64::from(committed));
    assert_eq!(journal.next_block(), 1 + u64::from(committed));
    if committed {
        assert_eq!(journal.state_root(), f.witness.new_state_root);
        assert!(matches!(
            journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness),
            Err(JournalError::Verification(_))
        ));
    } else {
        assert_eq!(journal.state_root(), f.domain.state_root());
        journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness).unwrap();
    }
    assert_eq!(journal.head().blocks, 1);
    assert_eq!(journal.next_deposit(), 1);
}

#[test]
fn io_error_at_each_publication_boundary_preserves_memory_and_requires_recovery() {
    for (index, stop) in STAGES.into_iter().enumerate() {
        let f = fixture();
        let temp = Temp::new();
        let mut journal = Journal::create(&temp.0, f.domain.clone()).unwrap();
        let before = journal.head();
        let result =
            journal.commit_with_publisher(&f.trusted, &f.proofs, &f.input, &f.witness, |directory, name, bytes| {
                publish_staged(directory, name, bytes, |stage| {
                    if stage == stop {
                        Err(io::Error::other("injected publication failure"))
                    } else {
                        Ok(())
                    }
                })
            });
        assert!(matches!(result, Err(JournalError::CommitUncertain(_))), "{stop:?}");
        assert_eq!(journal.head(), before);
        assert_eq!(journal.state_root(), f.domain.state_root());
        assert_eq!(journal.next_deposit(), 0);
        assert_eq!(journal.next_block(), 1);
        assert!(matches!(
            journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness),
            Err(JournalError::Poisoned)
        ));
        drop(journal);
        check_recovery(&temp.0, &f, index >= 3);
    }
}

// Child-only environment handling is compiled exclusively into the test binary.
#[test]
fn publication_child() {
    let Some(path) = std::env::var_os("BLOCH_PUBLICATION_TEST_PATH") else {
        return;
    };
    let path = PathBuf::from(path);
    let mode = std::env::var("BLOCH_PUBLICATION_TEST_MODE").unwrap();
    let f = fixture();
    if mode == "cwd" {
        let parent = path.parent().unwrap();
        let relative = path.file_name().unwrap();
        std::env::set_current_dir(parent).unwrap();
        let mut journal = Journal::create(relative, f.domain.clone()).unwrap();
        std::env::set_current_dir("/").unwrap();
        journal.commit(&f.trusted, &f.proofs, &f.input, &f.witness).unwrap();
        let head = journal.head();
        drop(journal);
        std::env::set_current_dir(parent).unwrap();
        let mut journal = Journal::open(relative, f.domain.clone(), head, |_| Ok(f.trusted.clone())).unwrap();
        std::env::set_current_dir("/").unwrap();
        journal.commit(&f.second.0, &[], &f.second.1, &f.second.2).unwrap();
        return;
    }
    let stop = STAGES[mode.parse::<usize>().unwrap()];
    let mut journal = Journal::create(&path, f.domain.clone()).unwrap();
    journal
        .commit_with_publisher(&f.trusted, &f.proofs, &f.input, &f.witness, |directory, name, bytes| {
            publish_staged(directory, name, bytes, |stage| {
                if stage == stop {
                    std::process::exit(86);
                }
                Ok(())
            })
        })
        .unwrap();
    panic!("requested exit boundary was not reached");
}

fn child(path: &Path, mode: &str) -> std::process::ExitStatus {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "fault_tests::publication_child", "--nocapture"])
        .env("BLOCH_PUBLICATION_TEST_PATH", path)
        .env("BLOCH_PUBLICATION_TEST_MODE", mode)
        .status()
        .unwrap()
}

#[test]
fn process_exit_at_each_publication_boundary_recovers_only_complete_records() {
    for index in 0..STAGES.len() {
        let temp = Temp::new();
        assert_eq!(child(&temp.0, &index.to_string()).code(), Some(86));
        check_recovery(&temp.0, &fixture(), index >= 3);
    }
}

#[test]
fn relative_create_and_open_remain_bound_after_process_directory_changes() {
    let temp = Temp::new();
    assert!(child(&temp.0, "cwd").success());
    let f = fixture();
    let journal = Journal::open(
        &temp.0,
        f.domain.clone(),
        JournalHead::genesis(f.domain.id()),
        |number| {
            Ok(if number == 1 {
                f.trusted.clone()
            } else {
                f.second.0.clone()
            })
        },
    )
    .unwrap();
    assert_eq!(journal.head().blocks, 2);
    assert_eq!(journal.next_deposit(), 1);
    assert_eq!(journal.state_root(), f.second.2.new_state_root);
}
