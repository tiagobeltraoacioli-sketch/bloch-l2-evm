// SPDX-License-Identifier: AGPL-3.0-or-later
use bloch_native_escrow_pq::checkpoint::{CheckpointError as Error, CheckpointPolicy, Phase};
use bloch_pos_committee::{
    derive::body_root,
    header::{BlockHeaderV4, BlockId},
    ws::{self, CheckpointEnvelope, Signer, SignerSet, WeakSubjectivityCheckpoint},
};
use std::sync::OnceLock;

fn keys() -> &'static Vec<(Vec<u8>, Vec<u8>)> {
    static KEYS: OnceLock<Vec<(Vec<u8>, Vec<u8>)>> = OnceLock::new();
    KEYS.get_or_init(|| (0..5).map(|_| bloch_crypto::crypto::generate_keypair()).collect())
}
fn set(phase_b: bool) -> SignerSet {
    let n = if phase_b { 5 } else { 3 };
    SignerSet {
        id: 1,
        signers: keys()[..n]
            .iter()
            .enumerate()
            .map(|(i, k)| Signer {
                pubkey: k.0[4..].try_into().unwrap(),
                external: i >= if phase_b { 3 } else { 2 },
            })
            .collect(),
        threshold: if phase_b { 3 } else { 2 },
        min_external: if phase_b { 2 } else { 1 },
        adopted_epoch: 50,
    }
}
fn signed(cp: WeakSubjectivityCheckpoint, indices: &[u8]) -> CheckpointEnvelope {
    let digest = cp.ws_digest();
    CheckpointEnvelope {
        checkpoint: cp,
        signatures: indices
            .iter()
            .map(|i| {
                let signature = bloch_crypto::crypto::sign(&keys()[*i as usize].1, &digest).unwrap();
                (*i, signature[4..].to_vec())
            })
            .collect(),
    }
}
fn fixture(epoch: u64) -> (CheckpointEnvelope, Vec<u8>) {
    let mut header = vec![0; 304];
    header[..4].copy_from_slice(&0xb10c_0005u32.to_le_bytes());
    header[36..68].fill(11);
    header[68..100].copy_from_slice(&body_root(&[]));
    header[100..108].copy_from_slice(&(epoch * 120).to_le_bytes());
    let native = BlockHeaderV4::canonical_deserialize(&header).unwrap();
    let cp = WeakSubjectivityCheckpoint {
        version: ws::WS_FORMAT_VERSION,
        network_id: 7,
        genesis_root: [9; 32],
        epoch,
        block_root: *BlockId::of(&native).as_bytes(),
        state_root: native.state_root,
        validator_set_root: [12; 32],
        issued_at: 12345,
        signer_set_id: 1,
    };
    (signed(cp, &[0, 2]), header)
}
fn policy() -> CheckpointPolicy {
    CheckpointPolicy::new(7, [9; 32], set(false), Phase::A).unwrap()
}

#[test]
fn real_phase_a_and_b_quorums_feed_header_authentication() {
    let (env, header) = fixture(100);
    for phase_b in [false, true] {
        let p = CheckpointPolicy::new(7, [9; 32], set(phase_b), if phase_b { Phase::B } else { Phase::A }).unwrap();
        let env = if phase_b {
            signed(env.checkpoint, &[0, 3, 4])
        } else {
            env.clone()
        };
        let verified = p.verify(&env, &header, 101, None).unwrap();
        assert_eq!(verified.epoch(), 100);
        assert!(!verified.arrangement_review_due());
        let body = bloch_l2_evm::l1::authenticate_body(verified.anchor(), &[header.clone().into()], &[]).unwrap();
        assert_eq!(body.state_root(), verified.state_root());
        assert_eq!(body.slot(), 12000);
    }
}
#[test]
fn both_signature_halves_are_required() {
    let (env, header) = fixture(100);
    let p = policy();
    for offset in [0, 3309] {
        let mut broken = env.clone();
        broken.signatures[0].1[offset] ^= 1;
        assert!(matches!(p.verify(&broken, &header, 101, None), Err(Error::Envelope(_))));
    }
    let mut broken = env.clone();
    broken.signatures[0].1.truncate(3309);
    assert!(p.verify(&broken, &header, 101, None).is_err());
    let mut changed = env;
    changed.checkpoint.validator_set_root[0] ^= 1;
    assert!(p.verify(&changed, &header, 101, None).is_err());
}
#[test]
fn weak_duplicate_and_nonexternal_arrangements_or_envelopes_fail() {
    let mut duplicate = set(false);
    duplicate.signers[2].pubkey = duplicate.signers[0].pubkey;
    assert!(matches!(
        CheckpointPolicy::new(7, [9; 32], duplicate, Phase::A),
        Err(Error::Arrangement)
    ));
    let mut weak = set(false);
    weak.threshold = 1;
    weak.min_external = 0;
    assert!(CheckpointPolicy::new(7, [9; 32], weak, Phase::A).is_err());
    let mut overflow = set(false);
    overflow.adopted_epoch = u64::MAX;
    assert!(CheckpointPolicy::new(7, [9; 32], overflow, Phase::A).is_err());
    let (env, header) = fixture(100);
    let p = policy();
    for indices in [&[0, 1][..], &[0][..], &[0, 0, 2][..]] {
        assert!(p.verify(&signed(env.checkpoint, indices), &header, 101, None).is_err());
    }
}
#[test]
fn freshness_and_arrangement_windows_are_enforced() {
    let p = policy();
    let (env, header) = fixture(100);
    assert_eq!(p.verify(&env, &header, 99, None).unwrap_err(), Error::Future);
    assert_eq!(
        p.verify(&env, &header, 100 + ws::WS_PERIOD_EPOCHS, None).unwrap_err(),
        Error::Stale
    );
    assert!(p.verify(&env, &header, 99 + ws::WS_PERIOD_EPOCHS, None).is_ok());
    let (early, header) = fixture(49);
    assert_eq!(p.verify(&early, &header, 100, None).unwrap_err(), Error::AdoptionWindow);
    let epoch = set(false).review_deadline() + 1;
    let (review, header) = fixture(epoch);
    assert!(p
        .verify(&review, &header, epoch, None)
        .unwrap()
        .arrangement_review_due());
    let epoch = set(false).hard_stop() + 1;
    let (expired, header) = fixture(epoch);
    assert!(p.verify(&expired, &header, epoch, None).is_err());
}
#[test]
fn chain_identity_header_state_and_version_are_bound() {
    let p = policy();
    let (env, header) = fixture(100);
    for field in 0..3 {
        let mut cp = env.checkpoint;
        match field {
            0 => cp.network_id += 1,
            1 => cp.genesis_root[0] ^= 1,
            _ => cp.state_root[0] ^= 1,
        }
        assert!(p.verify(&signed(cp, &[0, 2]), &header, 101, None).is_err());
    }
    let mut altered = header.clone();
    altered[200] ^= 1;
    assert_eq!(p.verify(&env, &altered, 101, None).unwrap_err(), Error::Header);
    altered = header;
    altered[..4].fill(0);
    let mut cp = env.checkpoint;
    cp.block_root = *BlockId::of(&BlockHeaderV4::canonical_deserialize(&altered).unwrap()).as_bytes();
    assert_eq!(
        p.verify(&signed(cp, &[0, 2]), &altered, 101, None).unwrap_err(),
        Error::Header
    );
}
#[test]
fn rollback_and_same_epoch_conflicts_are_refused_but_identical_retry_is_valid() {
    let p = policy();
    let (env, header) = fixture(100);
    let old = p.verify(&env, &header, 101, None).unwrap();
    assert_eq!(p.verify(&env, &header, 101, Some(&old)).unwrap().digest(), old.digest());
    let mut changed = env.checkpoint;
    changed.issued_at += 1;
    assert_eq!(
        p.verify(&signed(changed, &[0, 2]), &header, 101, Some(&old))
            .unwrap_err(),
        Error::Conflict
    );
    let (new, new_header) = fixture(101);
    let latest = p.verify(&new, &new_header, 101, Some(&old)).unwrap();
    assert_eq!(
        p.verify(&env, &header, 101, Some(&latest)).unwrap_err(),
        Error::Rollback
    );
}
#[test]
fn envelope_and_header_work_are_bounded() {
    let (mut env, header) = fixture(100);
    let p = policy();
    assert_eq!(p.verify(&env, &header[..303], 101, None).unwrap_err(), Error::Limit);
    env.signatures[0].1 = vec![0; 8193];
    assert_eq!(p.verify(&env, &header, 101, None).unwrap_err(), Error::Limit);
}

#[cfg(unix)]
mod persistence {
    use super::*;
    use bloch_native_escrow_pq::checkpoint_store::{CheckpointStore, StoreError};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let name = format!(
                "bloch-checkpoint-store-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            Self(std::env::temp_dir().join(name))
        }
        fn record(&self, epoch: u64) -> PathBuf {
            self.0.join(format!("{epoch:020}.ckp"))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn recovery_preserves_floor_and_identical_acceptance_is_idempotent() {
        let temp = Temp::new();
        let (env, header) = fixture(100);
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        assert!(matches!(store.current(100), Err(StoreError::Empty)));
        let mark = store.accept(&env, &header, 100).unwrap();
        assert!(matches!(
            CheckpointStore::open(&temp.0, policy(), Some(mark)),
            Err(StoreError::Locked)
        ));
        drop(store);
        let mut store = CheckpointStore::open(&temp.0, policy(), Some(mark)).unwrap();
        assert_eq!(store.current(101).unwrap().digest(), mark.digest);
        assert_eq!(store.accept(&env, &header, 101).unwrap(), mark);
        let (old, old_header) = fixture(99);
        assert!(matches!(
            store.accept(&old, &old_header, 101),
            Err(StoreError::Verify(Error::Rollback))
        ));
        assert!(!temp.record(99).exists());
    }
    #[test]
    fn stale_history_can_recover_but_cannot_become_a_current_anchor() {
        let temp = Temp::new();
        let (env, header) = fixture(100);
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        let mark = store.accept(&env, &header, 100).unwrap();
        drop(store);
        let mut store = CheckpointStore::open(&temp.0, policy(), Some(mark)).unwrap();
        let now = 100 + ws::WS_PERIOD_EPOCHS;
        assert!(matches!(store.current(now), Err(StoreError::Verify(Error::Stale))));
        assert_eq!(store.mark(), Some(mark));
        let (new, new_header) = fixture(now);
        let latest = store.accept(&new, &new_header, now).unwrap();
        assert_eq!(store.current(now).unwrap().digest(), latest.digest);
        drop(store);
        assert_eq!(
            CheckpointStore::open(&temp.0, policy(), Some(mark)).unwrap().mark(),
            Some(latest)
        );
    }
    #[test]
    fn historical_audit_rechecks_exact_record_without_exporting_a_current_anchor() {
        let temp = Temp::new();
        let (old, old_header) = fixture(100);
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        let old_mark = store.accept(&old, &old_header, 101).unwrap();
        let (new, new_header) = fixture(102);
        store.accept(&new, &new_header, 103).unwrap();

        let observed_now = 100 + ws::WS_PERIOD_EPOCHS;
        let audit = store.historical_audit(100, 101, observed_now).unwrap();
        assert_eq!(audit.checkpoint_epoch(), 100);
        assert_eq!(audit.checked_at_epoch(), 101);
        assert_eq!(audit.checkpoint_digest(), old_mark.digest);
        assert_eq!(audit.anchor().slot, 12_000);
        assert!(matches!(
            store.historical_audit(100, observed_now + 1, observed_now),
            Err(StoreError::Verify(Error::Future))
        ));
        assert!(matches!(
            store.historical_audit(101, 101, observed_now),
            Err(StoreError::Missing)
        ));

        let canonical = fs::read(temp.record(100)).unwrap();
        let mut changed = canonical.clone();
        *changed.last_mut().unwrap() ^= 1;
        fs::write(temp.record(100), changed).unwrap();
        assert!(store.historical_audit(100, 101, observed_now).is_err());

        let mut relinked = canonical;
        relinked[8] ^= 1;
        fs::write(temp.record(100), relinked).unwrap();
        assert!(matches!(
            store.historical_audit(100, 101, observed_now),
            Err(StoreError::Format)
        ));
    }
    #[test]
    fn conflicting_checkpoint_never_replaces_committed_file() {
        let temp = Temp::new();
        let (env, header) = fixture(100);
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        let mark = store.accept(&env, &header, 100).unwrap();
        let bytes = fs::read(temp.record(100)).unwrap();
        let mut cp = env.checkpoint;
        cp.issued_at += 1;
        assert!(matches!(
            store.accept(&signed(cp, &[0, 2]), &header, 100),
            Err(StoreError::Verify(Error::Conflict))
        ));
        assert_eq!(store.mark(), Some(mark));
        assert_eq!(fs::read(temp.record(100)).unwrap(), bytes);
    }
    #[test]
    fn tampering_truncation_and_tail_deletion_fail_closed() {
        for mode in 0..3 {
            let temp = Temp::new();
            let (env, header) = fixture(100);
            let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
            let mark = store.accept(&env, &header, 100).unwrap();
            drop(store);
            if mode == 2 {
                fs::remove_file(temp.record(100)).unwrap();
            } else {
                let mut bytes = fs::read(temp.record(100)).unwrap();
                if mode == 0 {
                    let last = bytes.len() - 1;
                    bytes[last] ^= 1;
                } else {
                    bytes.truncate(bytes.len() - 1);
                }
                fs::write(temp.record(100), bytes).unwrap();
            }
            assert!(CheckpointStore::open(&temp.0, policy(), Some(mark)).is_err());
        }
    }
    #[test]
    fn immutable_policy_and_oversized_records_are_enforced() {
        let temp = Temp::new();
        let store = CheckpointStore::create(&temp.0, policy()).unwrap();
        drop(store);
        let changed = CheckpointPolicy::new(8, [9; 32], set(false), Phase::A).unwrap();
        assert!(matches!(
            CheckpointStore::open(&temp.0, changed, None),
            Err(StoreError::Policy)
        ));
        fs::File::create(temp.record(100)).unwrap().set_len(65537).unwrap();
        assert!(matches!(
            CheckpointStore::open(&temp.0, policy(), None),
            Err(StoreError::Limit)
        ));
    }
    #[test]
    fn publication_failure_poisoning_requires_recovery() {
        let temp = Temp::new();
        let (env, header) = fixture(100);
        let mut store = CheckpointStore::create(&temp.0, policy()).unwrap();
        fs::create_dir(temp.record(100)).unwrap();
        assert!(matches!(
            store.accept(&env, &header, 100),
            Err(StoreError::CommitUncertain(_))
        ));
        assert_eq!(store.mark(), None);
        assert!(matches!(store.current(100), Err(StoreError::Poisoned)));
        assert!(matches!(store.accept(&env, &header, 100), Err(StoreError::Poisoned)));
        fs::remove_dir(temp.record(100)).unwrap();
        drop(store);
        let mut store = CheckpointStore::open(&temp.0, policy(), None).unwrap();
        store.accept(&env, &header, 100).unwrap();
    }
    #[test]
    fn incomplete_temporary_files_are_not_accepted_as_checkpoints() {
        let temp = Temp::new();
        let store = CheckpointStore::create(&temp.0, policy()).unwrap();
        drop(store);
        fs::write(temp.0.join(".pending-interrupted"), b"partial checkpoint").unwrap();
        let store = CheckpointStore::open(&temp.0, policy(), None).unwrap();
        assert_eq!(store.mark(), None);
        assert!(matches!(store.current(100), Err(StoreError::Empty)));
    }
}
