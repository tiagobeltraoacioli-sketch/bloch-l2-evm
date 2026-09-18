// SPDX-License-Identifier: AGPL-3.0-or-later
//! Real PQ signatures from disposable test keys; no production wallet or network.
use alloy_primitives::{Address, B256};
use bloch_l2_evm::escrow::{Coin, EscrowError, LockIntent, Outpoint};
use bloch_native_escrow_pq::{AuthorizationError as Error, PqEscrow};
use sha3::{Digest, Sha3_256};
use std::sync::OnceLock;
fn keys() -> &'static (Vec<u8>, Vec<u8>) {
    static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEYS.get_or_init(bloch_crypto::crypto::generate_keypair)
}
fn setup() -> (PqEscrow, LockIntent) {
    let owner = B256::from_slice(&Sha3_256::digest(&keys().0));
    let source = Outpoint {
        txid: B256::repeat_byte(4),
        vout: 0,
    };
    let intent = LockIntent {
        network: B256::repeat_byte(1),
        domain: B256::repeat_byte(2),
        owner,
        inputs: vec![source],
        recipient: Address::repeat_byte(7),
        amount: 600,
        fee: 10,
        change_owner: owner,
        nonce: 0,
    };
    let ledger = PqEscrow::new(
        intent.network,
        intent.domain,
        vec![(source, Coin { value: 1000, owner })],
        100,
    )
    .unwrap();
    (ledger, intent)
}
fn sign(intent: &LockIntent) -> Vec<u8> {
    bloch_crypto::crypto::sign(&keys().1, intent.signing_root().as_slice()).unwrap()
}
#[test]
fn real_hybrid_authorization_locks_exact_value() {
    let (mut ledger, intent) = setup();
    let signature = sign(&intent);
    let record = ledger.submit(&intent, &keys().0, &signature).unwrap();
    assert_eq!(record.amount, 600);
    let inbox = ledger.inbox();
    let proof = inbox.proof(record.sequence).unwrap();
    assert_eq!(proof.deposit, record);
    assert!(proof.verify(intent.network, intent.domain, inbox.root()));
    assert_eq!(ledger.locked_sat(), 600);
    assert!(ledger.conserved());
    assert!(ledger.coin(intent.inputs[0]).is_none());
    assert_eq!(
        ledger
            .coin(Outpoint {
                txid: record.id,
                vout: 0
            })
            .unwrap()
            .value,
        390
    );
}
#[test]
fn each_hybrid_component_is_required() {
    let (mut ledger, intent) = setup();
    let signature = sign(&intent);
    let root = ledger.commitment();
    for offset in [4, 4 + 3309, signature.len() - 1] {
        let mut broken = signature.clone();
        broken[offset] ^= 1;
        assert_eq!(ledger.submit(&intent, &keys().0, &broken), Err(Error::Signature));
        assert_eq!(ledger.commitment(), root);
    }
    let only_mldsa = &signature[..4 + 3309];
    assert_eq!(ledger.submit(&intent, &keys().0, only_mldsa), Err(Error::Signature));
}
#[test]
fn all_intent_mutations_fail_before_state_changes() {
    let (mut ledger, intent) = setup();
    let signature = sign(&intent);
    let root = ledger.commitment();
    for n in 0..10 {
        let mut changed = intent.clone();
        match n {
            0 => changed.network = B256::repeat_byte(9),
            1 => changed.domain = B256::repeat_byte(9),
            2 => changed.owner = B256::repeat_byte(9),
            3 => changed.change_owner = B256::repeat_byte(9),
            4 => changed.recipient = Address::repeat_byte(9),
            5 => changed.amount += 1,
            6 => changed.fee += 1,
            7 => changed.nonce += 1,
            8 => changed.inputs[0].vout += 1,
            _ => changed.inputs[0].txid = B256::repeat_byte(9),
        }
        assert!(ledger.submit(&changed, &keys().0, &signature).is_err());
        assert_eq!(ledger.commitment(), root);
    }
}
#[test]
fn legacy_and_downgraded_suites_are_rejected() {
    let (mut ledger, intent) = setup();
    let signature = sign(&intent);
    let root = ledger.commitment();
    assert_eq!(
        ledger.submit(&intent, &keys().0[4..], &signature[4..]),
        Err(Error::Suite)
    );
    let mut downgraded = signature.clone();
    downgraded[2] = 2;
    assert_eq!(ledger.submit(&intent, &keys().0, &downgraded), Err(Error::Suite));
    let mut public = keys().0.clone();
    public[2] = 2;
    assert_eq!(ledger.submit(&intent, &public, &signature), Err(Error::Suite));
    assert_eq!(ledger.commitment(), root);
}
#[test]
fn malformed_or_oversized_requests_fail_without_panics() {
    let (mut ledger, intent) = setup();
    let signature = sign(&intent);
    let root = ledger.commitment();
    for length in [0, 1, 3, 4, 1952, 3745, 3748] {
        assert!(ledger.submit(&intent, &keys().0[..length], &signature).is_err());
    }
    for length in [0, 1, 3, 4, 3309, 3313, signature.len() - 1] {
        assert!(ledger.submit(&intent, &keys().0, &signature[..length]).is_err());
    }
    assert_eq!(ledger.submit(&intent, &keys().0, &vec![0; 8193]), Err(Error::Limit));
    let mut large = intent.clone();
    large.inputs = vec![intent.inputs[0]; 4097];
    assert_eq!(ledger.submit(&large, &keys().0, &signature), Err(Error::Limit));
    assert_eq!(ledger.commitment(), root);
}
#[test]
fn replay_and_resigned_double_spend_are_still_rejected() {
    let (mut ledger, mut intent) = setup();
    let signature = sign(&intent);
    ledger.submit(&intent, &keys().0, &signature).unwrap();
    let root = ledger.commitment();
    assert_eq!(
        ledger.submit(&intent, &keys().0, &signature),
        Err(Error::Transition(EscrowError::Replay))
    );
    intent.nonce += 1;
    assert_eq!(
        ledger.submit(&intent, &keys().0, &sign(&intent)),
        Err(Error::Transition(EscrowError::Funding))
    );
    assert_eq!(ledger.commitment(), root);
}
#[test]
fn authenticated_overspend_and_wrong_network_are_rejected() {
    let (mut ledger, mut intent) = setup();
    let root = ledger.commitment();
    intent.amount = 1001;
    assert_eq!(
        ledger.submit(&intent, &keys().0, &sign(&intent)),
        Err(Error::Transition(EscrowError::Amount))
    );
    intent.amount = 600;
    intent.network = B256::repeat_byte(9);
    assert_eq!(
        ledger.submit(&intent, &keys().0, &sign(&intent)),
        Err(Error::Transition(EscrowError::Configuration))
    );
    assert_eq!(ledger.commitment(), root);
}
#[test]
fn authenticated_funding_does_not_enable_unverified_withdrawals() {
    let (mut ledger, intent) = setup();
    ledger.submit(&intent, &keys().0, &sign(&intent)).unwrap();
    let root = ledger.commitment();
    assert_eq!(ledger.release(), Err(EscrowError::ReleaseUnavailable));
    assert_eq!(ledger.commitment(), root);
}

fn chained(intent: &LockIntent) -> LockIntent {
    let mut next = intent.clone();
    next.inputs = vec![Outpoint {
        txid: intent.signing_root(),
        vout: 0,
    }];
    next.amount = 300;
    next.nonce += 1;
    next
}
fn request<'a>(intent: &'a LockIntent, signature: &'a [u8]) -> bloch_native_escrow_pq::SignedLock<'a> {
    bloch_native_escrow_pq::SignedLock {
        intent,
        public_key: &keys().0,
        signature,
    }
}
#[test]
fn atomic_batch_matches_sequential_locks_and_spends_change() {
    let (mut batch, first) = setup();
    let (mut sequential, _) = setup();
    let second = chained(&first);
    let a = sign(&first);
    let b = sign(&second);
    let expected = vec![
        sequential.submit(&first, &keys().0, &a).unwrap(),
        sequential.submit(&second, &keys().0, &b).unwrap(),
    ];
    assert_eq!(
        batch
            .submit_batch(&[request(&first, &a), request(&second, &b)])
            .unwrap(),
        expected
    );
    assert_eq!(batch.commitment(), sequential.commitment());
    assert_eq!(batch.locked_sat(), 900);
    assert!(batch.conserved());
    let root = batch.commitment();
    assert!(batch
        .submit_batch(&[request(&first, &a), request(&second, &b)])
        .is_err());
    assert_eq!(batch.commitment(), root);
}
#[test]
fn batch_rolls_back_invalid_signature_double_spend_and_capacity_failure() {
    let (mut ledger, first) = setup();
    let a = sign(&first);
    let root = ledger.commitment();
    let second = chained(&first);
    let mut bad_signature = sign(&second);
    bad_signature[4] ^= 1;
    assert_eq!(
        ledger.submit_batch(&[request(&first, &a), request(&second, &bad_signature)]),
        Err(Error::Signature)
    );
    assert_eq!(ledger.commitment(), root);
    let mut conflict = first.clone();
    conflict.nonce += 1;
    assert_eq!(
        ledger.submit_batch(&[request(&first, &a), request(&conflict, &sign(&conflict))]),
        Err(Error::Transition(EscrowError::Funding))
    );
    assert_eq!(ledger.commitment(), root);
    assert_eq!(
        ledger.submit_batch(&[request(&first, &a), request(&first, &a)]),
        Err(Error::Transition(EscrowError::Replay))
    );
    assert_eq!(ledger.commitment(), root);
    let mut limited = PqEscrow::new(
        first.network,
        first.domain,
        vec![(
            first.inputs[0],
            Coin {
                value: 1000,
                owner: first.owner,
            },
        )],
        1,
    )
    .unwrap();
    let root = limited.commitment();
    assert_eq!(
        limited.submit_batch(&[request(&first, &a), request(&second, &sign(&second))]),
        Err(Error::Transition(EscrowError::Capacity))
    );
    assert_eq!(limited.commitment(), root);
}
#[test]
fn batch_preflights_total_work_before_any_authentication() {
    let (mut ledger, first) = setup();
    let root = ledger.commitment();
    assert_eq!(ledger.submit_batch(&[]), Err(Error::Limit));
    let requests: Vec<_> = (0..=bloch_native_escrow_pq::MAX_LOCK_BATCH)
        .map(|_| request(&first, &[]))
        .collect();
    assert_eq!(ledger.submit_batch(&requests), Err(Error::Limit));
    let mut oversized = first.clone();
    oversized.inputs = vec![first.inputs[0]; 4096];
    assert_eq!(
        ledger.submit_batch(&[request(&first, &[]), request(&oversized, &[])]),
        Err(Error::Limit)
    );
    assert_eq!(
        ledger.submit_batch(&[request(&first, &[]), request(&first, &vec![0; 8193])]),
        Err(Error::Limit)
    );
    assert_eq!(ledger.commitment(), root);
}

#[cfg(unix)]
mod persistence {
    use super::*;
    use bloch_native_escrow_pq::lock_store::{LockStore, StoreError};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            Self(std::env::temp_dir().join(format!(
                    "bloch-lock-store-{}-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn replay_restores_change_inbox_and_double_spend_protection() {
        let temp = Temp::new();
        let (baseline, first) = setup();
        let mut store = LockStore::create(&temp.0, baseline).unwrap();
        let floor = store.mark().unwrap();
        assert!(matches!(
            LockStore::open(&temp.0, setup().0, floor),
            Err(StoreError::Locked)
        ));
        let second = chained(&first);
        store.submit_batch(&[request(&first, &sign(&first))]).unwrap();
        let older = store.mark().unwrap();
        store.submit_batch(&[request(&second, &sign(&second))]).unwrap();
        let latest = store.mark().unwrap();
        let root = store.escrow().unwrap().commitment();
        drop(store);
        fs::write(temp.0.join(".pending-incomplete"), b"incomplete").unwrap();
        let mut reopened = LockStore::open(&temp.0, setup().0, older).unwrap();
        assert_eq!(reopened.mark().unwrap(), latest);
        assert_eq!(reopened.escrow().unwrap().commitment(), root);
        assert!(reopened.escrow().unwrap().conserved());
        assert!(reopened.escrow().unwrap().inbox().proof(1).is_some());
        assert!(matches!(
            reopened.submit_batch(&[request(&first, &sign(&first))]),
            Err(StoreError::Authorization(Error::Transition(EscrowError::Replay)))
        ));
        assert_eq!(reopened.mark().unwrap(), latest);
        drop(reopened);
        fs::remove_file(temp.0.join("00000000000000000002.locks")).unwrap();
        assert!(matches!(
            LockStore::open(&temp.0, setup().0, latest),
            Err(StoreError::Rollback)
        ));
    }
    #[test]
    fn corrupted_signature_is_reverified_and_wrong_baseline_is_rejected() {
        let temp = Temp::new();
        let (baseline, first) = setup();
        let mut store = LockStore::create(&temp.0, baseline).unwrap();
        let floor = store.mark().unwrap();
        store.submit_batch(&[request(&first, &sign(&first))]).unwrap();
        drop(store);
        let mut wrong = setup().0;
        wrong.submit(&first, &keys().0, &sign(&first)).unwrap();
        assert!(matches!(
            LockStore::open(&temp.0, wrong, floor),
            Err(StoreError::Baseline)
        ));
        let path = temp.0.join("00000000000000000001.locks");
        let mut json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let byte = json["locks"][0]["signature"][4].as_u64().unwrap();
        json["locks"][0]["signature"][4] = (byte ^ 1).into();
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(matches!(
            LockStore::open(&temp.0, setup().0, floor),
            Err(StoreError::Authorization(Error::Signature))
        ));
    }
    #[test]
    fn publication_failure_poisons_writer_and_never_overwrites_existing_record() {
        let temp = Temp::new();
        let (baseline, first) = setup();
        let mut store = LockStore::create(&temp.0, baseline).unwrap();
        let floor = store.mark().unwrap();
        let path = temp.0.join("00000000000000000001.locks");
        fs::write(&path, b"collision").unwrap();
        assert!(matches!(
            store.submit_batch(&[request(&first, &sign(&first))]),
            Err(StoreError::CommitUncertain(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"collision");
        assert!(matches!(store.mark(), Err(StoreError::Poisoned)));
        assert!(matches!(store.escrow(), Err(StoreError::Poisoned)));
        assert!(matches!(store.submit_batch(&[]), Err(StoreError::Poisoned)));
        drop(store);
        fs::remove_file(path).unwrap();
        let reopened = LockStore::open(&temp.0, setup().0, floor).unwrap();
        assert_eq!(reopened.mark().unwrap(), floor);
    }
    #[test]
    fn invalid_later_lock_leaves_disk_and_memory_unchanged() {
        let temp = Temp::new();
        let (baseline, first) = setup();
        let mut store = LockStore::create(&temp.0, baseline).unwrap();
        let floor = store.mark().unwrap();
        assert!(store
            .submit_batch(&[request(&first, &sign(&first)), request(&first, &sign(&first))])
            .is_err());
        assert_eq!(store.mark().unwrap(), floor);
        assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 2);
        drop(store);
        assert_eq!(
            LockStore::open(&temp.0, setup().0, floor).unwrap().mark().unwrap(),
            floor
        );
    }
}
