// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use alloy_primitives::Address;
use bloch_l2_evm::escrow::{Coin, EscrowError, Outpoint};
use std::{process::Command, sync::OnceLock};

const STAGES: [PublicationStage; 5] = [
    PublicationStage::Created,
    PublicationStage::Written,
    PublicationStage::FileSynced,
    PublicationStage::Renamed,
    PublicationStage::DirectorySynced,
];
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
        let name = format!(
            "bloch-lock-fault-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path, gate)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> Vec<OwnedLock> {
    static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    let (public, secret) = KEYS.get_or_init(bloch_crypto::crypto::generate_keypair);
    let owner = B256::from_slice(&Sha3_256::digest(public));
    let first = LockIntent {
        network: B256::repeat_byte(1),
        domain: B256::repeat_byte(2),
        owner,
        inputs: vec![Outpoint {
            txid: B256::repeat_byte(3),
            vout: 0,
        }],
        recipient: Address::repeat_byte(4),
        amount: 600,
        fee: 10,
        change_owner: owner,
        nonce: 0,
    };
    let mut second = first.clone();
    second.inputs = vec![Outpoint {
        txid: first.signing_root(),
        vout: 0,
    }];
    second.amount = 300;
    second.nonce = 1;
    [first, second]
        .into_iter()
        .map(|intent| {
            let signature = bloch_crypto::crypto::sign(secret, intent.signing_root().as_slice()).unwrap();
            OwnedLock {
                intent,
                public_key: public.clone(),
                signature,
            }
        })
        .collect()
}
fn baseline(locks: &[OwnedLock]) -> PqEscrow {
    let first = &locks[0].intent;
    PqEscrow::new(
        first.network,
        first.domain,
        vec![(
            first.inputs[0],
            Coin {
                value: 1000,
                owner: first.owner,
            },
        )],
        100,
    )
    .unwrap()
}
fn requests(locks: &[OwnedLock]) -> Vec<SignedLock<'_>> {
    locks
        .iter()
        .map(|r| SignedLock {
            intent: &r.intent,
            public_key: &r.public_key,
            signature: &r.signature,
        })
        .collect()
}
fn floor(locks: &[OwnedLock]) -> LockMark {
    LockMark {
        batches: 0,
        digest: baseline(locks).commitment(),
    }
}
fn check_recovery(path: &Path, locks: &[OwnedLock], stage: PublicationStage) {
    let committed = matches!(stage, PublicationStage::Renamed | PublicationStage::DirectorySynced);
    let mut store = LockStore::open(path, baseline(locks), floor(locks)).unwrap();
    assert_eq!(store.mark().unwrap().batches, u64::from(committed));
    let requests = requests(locks);
    let mut expected = baseline(locks);
    if committed {
        expected.submit_batch(&requests).unwrap();
    }
    assert_eq!(store.escrow().unwrap().commitment(), expected.commitment());
    assert!(store.escrow().unwrap().conserved());
    if committed {
        let mark = store.mark().unwrap();
        assert!(matches!(
            store.submit_batch(&requests),
            Err(StoreError::Authorization(AuthorizationError::Transition(
                EscrowError::Replay
            )))
        ));
        assert_eq!(store.mark().unwrap(), mark);
    } else {
        assert_eq!(store.submit_batch(&requests).unwrap().len(), 2);
    }
    assert_eq!(store.escrow().unwrap().locked_sat(), 900);
    let mark = store.mark().unwrap();
    let root = store.escrow().unwrap().commitment();
    drop(store);
    let store = LockStore::open(path, baseline(locks), mark).unwrap();
    assert_eq!(store.escrow().unwrap().commitment(), root);
    assert_eq!(store.mark().unwrap(), mark);
}
#[test]
fn io_failure_at_each_publication_boundary_poison_and_recover() {
    let locks = fixture();
    for stage in STAGES {
        let temp = Temp::new();
        let path = temp.0.join("journal");
        let mut store = LockStore::create(&path, baseline(&locks)).unwrap();
        let old_root = store.escrow.commitment();
        let result = store.submit_staged(&requests(&locks), |at| {
            if at == stage {
                Err(io::Error::other("injected publication failure"))
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(StoreError::CommitUncertain(_))), "{stage:?}");
        assert_eq!(store.escrow.commitment(), old_root);
        assert!(matches!(store.mark(), Err(StoreError::Poisoned)));
        assert!(matches!(store.history_usage(), Err(StoreError::Poisoned)));
        assert!(matches!(store.escrow(), Err(StoreError::Poisoned)));
        assert!(matches!(
            store.submit_batch(&requests(&locks)),
            Err(StoreError::Poisoned)
        ));
        drop(store);
        check_recovery(&path, &locks, stage);
    }
}
// Only this test executable reads the child environment; library users cannot
// trigger fault injection. The parent supplies public authorizations, never keys.
#[test]
fn process_exit_child() {
    let Some(path) = std::env::var_os("BLOCH_LOCK_FAULT_FIXTURE") else {
        return;
    };
    let path = PathBuf::from(path);
    let stage: usize = std::env::var("BLOCH_LOCK_FAULT_STAGE").unwrap().parse().unwrap();
    let locks: Vec<OwnedLock> = serde_json::from_slice(&fs::read(path.join("fixture.json")).unwrap()).unwrap();
    let mut store = LockStore::create(path.join("journal"), baseline(&locks)).unwrap();
    store
        .submit_staged(&requests(&locks), |at| {
            if at == STAGES[stage] {
                std::process::exit(77);
            }
            Ok(())
        })
        .unwrap();
    panic!("child did not reach requested publication boundary");
}
#[test]
fn process_exit_without_destructors_recovers_complete_batches() {
    let locks = fixture();
    for (index, stage) in STAGES.into_iter().enumerate() {
        let temp = Temp::new();
        fs::write(temp.0.join("fixture.json"), serde_json::to_vec(&locks).unwrap()).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "lock_store::fault_tests::process_exit_child", "--nocapture"])
            .env("BLOCH_LOCK_FAULT_FIXTURE", &temp.0)
            .env("BLOCH_LOCK_FAULT_STAGE", index.to_string())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(77),
            "{stage:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        check_recovery(&temp.0.join("journal"), &locks, stage);
    }
}

#[test]
fn recovery_sync_failure_returns_no_handle_and_releases_writer_lock() {
    let locks = fixture();
    let temp = Temp::new();
    let path = temp.0.join("journal");
    let mut store = LockStore::create(&path, baseline(&locks)).unwrap();
    // Reproduce the unresolved publication case: rename completed, directory
    // sync has not run and the caller never received a success acknowledgment.
    assert!(matches!(
        store.submit_staged(&requests(&locks), |at| {
            if at == PublicationStage::Renamed {
                Err(io::Error::other("interrupted before directory sync"))
            } else {
                Ok(())
            }
        }),
        Err(StoreError::CommitUncertain(_))
    ));
    drop(store);
    let mut called = false;
    let recovered = LockStore::open_with_sync(&path, baseline(&locks), floor(&locks), |directory| {
        called = true;
        assert_eq!(directory, fs::canonicalize(&path).unwrap());
        // Recovery must retain the exclusive lock until synchronization finishes.
        assert!(matches!(
            LockStore::open(&path, baseline(&locks), floor(&locks)),
            Err(StoreError::Locked)
        ));
        Err(io::Error::other("injected recovery sync failure"))
    });
    assert!(called);
    assert!(matches!(recovered, Err(StoreError::Io(_))));
    check_recovery(&path, &locks, PublicationStage::Renamed);
}

#[test]
fn recovery_syncs_both_empty_and_committed_histories_before_returning() {
    let locks = fixture();
    let temp = Temp::new();
    let path = temp.0.join("journal");
    drop(LockStore::create(&path, baseline(&locks)).unwrap());
    for batches in 0..=1 {
        let mut called = false;
        let mut store = LockStore::open_with_sync(&path, baseline(&locks), floor(&locks), |directory| {
            called = true;
            File::open(directory)?.sync_all()
        })
        .unwrap();
        assert!(called);
        assert_eq!(store.mark().unwrap().batches, batches);
        if batches == 0 {
            store.submit_batch(&requests(&locks)).unwrap();
        }
    }
}

#[test]
fn recovery_rejects_bad_history_and_missing_floor_before_sync() {
    let locks = fixture();
    let temp = Temp::new();
    let path = temp.0.join("journal");
    drop(LockStore::create(&path, baseline(&locks)).unwrap());
    let missing = LockMark {
        batches: 1,
        digest: B256::repeat_byte(99),
    };
    assert!(matches!(
        LockStore::open_with_sync(&path, baseline(&locks), missing, |_| {
            panic!("must reject absent acknowledged history before syncing")
        }),
        Err(StoreError::Rollback)
    ));
    fs::write(path.join(name(1)), b"broken record").unwrap();
    assert!(matches!(
        LockStore::open_with_sync(&path, baseline(&locks), floor(&locks), |_| {
            panic!("must authenticate history before syncing")
        }),
        Err(StoreError::Format)
    ));
}

#[test]
fn recovery_budget_covers_cumulative_bytes_and_rejects_before_decoding() {
    let locks = fixture();
    let temp = Temp::new();
    let path = temp.0.join("journal");
    let mut store = LockStore::create(&path, baseline(&locks)).unwrap();
    store.submit_batch(&requests(&locks[..1])).unwrap();
    store.submit_batch(&requests(&locks[1..])).unwrap();
    let mark = store.mark().unwrap();
    let root = store.escrow().unwrap().commitment();
    drop(store);
    let a = fs::read(path.join(name(1))).unwrap();
    let b = fs::read(path.join(name(2))).unwrap();
    let total = (a.len() + b.len()) as u64;
    for limits in [
        RecoveryLimits {
            batches: 1,
            bytes: total,
        },
        RecoveryLimits {
            batches: 2,
            bytes: total - 1,
        },
    ] {
        assert!(matches!(
            LockStore::open_with_limits(&path, baseline(&locks), mark, limits),
            Err(StoreError::Limit)
        ));
        assert_eq!(fs::read(path.join(name(1))).unwrap(), a);
        assert_eq!(fs::read(path.join(name(2))).unwrap(), b);
    }
    let store = LockStore::open_with_limits(
        &path,
        baseline(&locks),
        mark,
        RecoveryLimits {
            batches: 2,
            bytes: total,
        },
    )
    .unwrap();
    assert_eq!(store.escrow().unwrap().commitment(), root);
    drop(store);
    // Invalid JSON below a too-small total budget must never reach decoding/PQ.
    fs::write(path.join(name(1)), b"not-json").unwrap();
    assert!(matches!(
        LockStore::open_with_limits(&path, baseline(&locks), mark, RecoveryLimits { batches: 2, bytes: 0 }),
        Err(StoreError::Limit)
    ));
}

#[test]
fn zero_recovery_budget_accepts_empty_escrow() {
    let locks = fixture();
    let temp = Temp::new();
    let path = temp.0.join("journal");
    drop(LockStore::create(&path, baseline(&locks)).unwrap());
    let store = LockStore::open_with_limits(
        &path,
        baseline(&locks),
        floor(&locks),
        RecoveryLimits { batches: 0, bytes: 0 },
    )
    .unwrap();
    assert_eq!(store.mark().unwrap(), floor(&locks));
}

#[test]
fn new_locks_respect_retained_budget_without_poisoning_or_partial_publication() {
    let locks = fixture();
    let temp = Temp::new();
    let reference = temp.0.join("reference");
    let mut measured = LockStore::create(&reference, baseline(&locks)).unwrap();
    measured.submit_batch(&requests(&locks[..1])).unwrap();
    measured.submit_batch(&requests(&locks[1..])).unwrap();
    let total =
        fs::metadata(reference.join(name(1))).unwrap().len() + fs::metadata(reference.join(name(2))).unwrap().len();
    drop(measured);
    let path = temp.0.join("journal");
    drop(LockStore::create(&path, baseline(&locks)).unwrap());
    for limits in [
        RecoveryLimits {
            batches: 0,
            bytes: total,
        },
        RecoveryLimits { batches: 2, bytes: 0 },
    ] {
        let mut store = LockStore::open_with_limits(&path, baseline(&locks), floor(&locks), limits).unwrap();
        assert!(matches!(
            store.submit_batch(&requests(&locks[..1])),
            Err(StoreError::Limit)
        ));
        assert_eq!(store.mark().unwrap(), floor(&locks));
        assert_eq!(store.escrow().unwrap().commitment(), baseline(&locks).commitment());
        assert_eq!(fs::read_dir(&path).unwrap().count(), 2);
    }
    let mut store = LockStore::open_with_limits(
        &path,
        baseline(&locks),
        floor(&locks),
        RecoveryLimits {
            batches: 2,
            bytes: total - 1,
        },
    )
    .unwrap();
    store.submit_batch(&requests(&locks[..1])).unwrap();
    let mark = store.mark().unwrap();
    let root = store.escrow().unwrap().commitment();
    for _ in 0..2 {
        assert!(matches!(
            store.submit_batch(&requests(&locks[1..])),
            Err(StoreError::Limit)
        ));
        assert_eq!(store.mark().unwrap(), mark);
        assert_eq!(store.escrow().unwrap().commitment(), root);
        assert_eq!(fs::read_dir(&path).unwrap().count(), 3);
    }
    drop(store);
    let mut store = LockStore::open_with_limits(
        &path,
        baseline(&locks),
        mark,
        RecoveryLimits {
            batches: 2,
            bytes: total,
        },
    )
    .unwrap();
    store.submit_batch(&requests(&locks[1..])).unwrap();
    let final_mark = store.mark().unwrap();
    assert_eq!(store.escrow().unwrap().locked_sat(), 900);
    assert!(store.escrow().unwrap().conserved());
    drop(store);
    let recovered = LockStore::open_with_limits(
        &path,
        baseline(&locks),
        final_mark,
        RecoveryLimits {
            batches: 2,
            bytes: total,
        },
    )
    .unwrap();
    assert_eq!(recovered.mark().unwrap(), final_mark);
    assert_eq!(recovered.escrow().unwrap().locked_sat(), 900);
    let usage = recovered.history_usage().unwrap();
    assert_eq!(usage.batches, 2);
    assert_eq!(usage.bytes, total);
    assert_eq!(usage.remaining_batches, 0);
    assert_eq!(usage.remaining_bytes, 0);
}
