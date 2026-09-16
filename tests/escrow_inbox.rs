#![cfg(feature = "experimental-escrow")]
use alloy_primitives::{Address, B256};
use bloch_l2_evm::escrow::{Coin, EscrowLedger, LockIntent, Outpoint};

fn ledger(count: u64) -> EscrowLedger {
    let owner = B256::repeat_byte(3);
    let mut ledger = EscrowLedger::new(
        B256::repeat_byte(1),
        B256::repeat_byte(2),
        (0..count)
            .map(|i| {
                (
                    Outpoint {
                        txid: B256::repeat_byte(4),
                        vout: i as u32,
                    },
                    Coin { value: 100, owner },
                )
            })
            .collect(),
        1000,
    )
    .unwrap();
    for i in 0..count {
        ledger
            .apply_authorized_lock(&LockIntent {
                network: B256::repeat_byte(1),
                domain: B256::repeat_byte(2),
                owner,
                inputs: vec![Outpoint {
                    txid: B256::repeat_byte(4),
                    vout: i as u32,
                }],
                recipient: Address::repeat_byte(7),
                amount: i + 1,
                fee: 0,
                change_owner: owner,
                nonce: i,
            })
            .unwrap();
    }
    ledger
}

#[test]
fn every_position_verifies_in_even_and_odd_trees() {
    for count in [0, 1, 2, 3, 5, 17, 32, 65] {
        let snapshot = ledger(count).inbox();
        assert_eq!(snapshot.len(), count as usize);
        assert_eq!(snapshot.is_empty(), count == 0);
        assert!(snapshot.proof(count).is_none());
        for i in 0..count {
            let proof = snapshot.proof(i).unwrap();
            assert_eq!(proof.deposit.amount, i + 1);
            assert!(proof.verify(B256::repeat_byte(1), B256::repeat_byte(2), snapshot.root()));
        }
    }
}

#[test]
fn every_deposit_field_and_snapshot_count_are_bound() {
    let snapshot = ledger(5).inbox();
    let original = snapshot.proof(2).unwrap();
    for field in 0..7 {
        let mut proof = original.clone();
        match field {
            0 => proof.deposit.id = B256::ZERO,
            1 => proof.deposit.domain = B256::repeat_byte(9),
            2 => proof.deposit.recipient = Address::repeat_byte(9),
            3 => proof.deposit.amount += 1,
            4 => proof.deposit.sequence += 1,
            5 => proof.count += 1,
            _ => proof.siblings[0] = B256::ZERO,
        }
        assert!(!proof.verify(B256::repeat_byte(1), B256::repeat_byte(2), snapshot.root()));
    }
    assert!(!original.verify(B256::repeat_byte(9), B256::repeat_byte(2), snapshot.root()));
    assert!(!original.verify(B256::repeat_byte(1), B256::repeat_byte(9), snapshot.root()));
    assert!(!original.verify(B256::repeat_byte(1), B256::repeat_byte(2), B256::ZERO));
}

#[test]
fn noncanonical_paths_and_extreme_counts_fail_closed() {
    let snapshot = ledger(5).inbox();
    let original = snapshot.proof(4).unwrap();
    for mode in 0..6 {
        let mut proof = original.clone();
        match mode {
            0 => proof.siblings.clear(),
            1 => proof.siblings.push(B256::ZERO),
            2 => proof.siblings = vec![B256::ZERO; 65],
            3 => proof.count = 0,
            4 => proof.deposit.sequence = proof.count,
            _ => {
                proof.count = u64::MAX;
                proof.deposit.sequence = u64::MAX - 1;
            }
        }
        assert!(!proof.verify(B256::repeat_byte(1), B256::repeat_byte(2), snapshot.root()));
    }
}

#[test]
fn snapshots_are_immutable_and_membership_is_not_replay_consumption() {
    let mut ledger = ledger(3);
    let old = ledger.inbox();
    let old_root = old.root();
    let previous = old.proof(0).unwrap().deposit;
    ledger
        .apply_authorized_lock(&LockIntent {
            network: B256::repeat_byte(1),
            domain: B256::repeat_byte(2),
            owner: B256::repeat_byte(3),
            inputs: vec![Outpoint {
                txid: previous.id,
                vout: 0,
            }],
            recipient: Address::repeat_byte(8),
            amount: 10,
            fee: 0,
            change_owner: B256::repeat_byte(3),
            nonce: 100,
        })
        .unwrap();
    let newer = ledger.inbox();
    assert_eq!(old.root(), old_root);
    assert_eq!(old.len(), 3);
    assert_eq!(newer.len(), 4);
    let proof = old.proof(1).unwrap();
    assert_ne!(old.root(), newer.root());
    assert!(!proof.verify(B256::repeat_byte(1), B256::repeat_byte(2), newer.root()));
    for _ in 0..2 {
        assert!(proof.verify(B256::repeat_byte(1), B256::repeat_byte(2), old.root()));
    }
}

// Pinned from the pre-cache implementation; consensus hashes must not change.
#[test]
fn cached_snapshots_preserve_existing_commitments_and_odd_paths() {
    let vectors = [
        (
            0,
            "a019da2e3889d746224a252f73b075de328c5cd7868cbc07e0198dc8a39e37a7",
            None,
        ),
        (
            1,
            "20bd6ca52d9becdaec1d7d5f9da4cb2bae5dc0750399564f207ddd611a6c0c3f",
            None,
        ),
        (
            3,
            "01e133115118405d2e8cb0bea269cf2b15cea5bb29a06952526f96ff9fd6aaeb",
            Some("a6f3e71423fe00efcc2a4641e133e5890459c0d168d52d3427f12e9e0b055ebc"),
        ),
        (
            5,
            "ca7340c21097ba8bf83d82dd5ac5ccfe8e3d17cd165df266ef57b8f1c513bac5",
            Some("0ddf698384f1e2c457aa94ed47a125e1b3a442ea132605249e52b4f3bf1d05c9"),
        ),
        (
            17,
            "7a674e5de162ae1acf22d572b136e8d52862f0748808a6d3fe588189754dac7d",
            Some("6dd97075550f411b34d80b613d28de15c5b5ad5f2f4ebe7da6d5aec339263131"),
        ),
    ];
    for (count, root, sibling) in vectors {
        let snapshot = ledger(count).inbox();
        assert_eq!(snapshot.root(), root.parse::<B256>().unwrap());
        let cloned = snapshot.clone();
        assert_eq!(cloned.root(), snapshot.root());
        if count > 0 {
            let expected: Vec<B256> = sibling.into_iter().map(|s| s.parse().unwrap()).collect();
            assert_eq!(snapshot.proof(count - 1).unwrap().siblings, expected);
            assert_eq!(cloned.proof(count - 1), snapshot.proof(count - 1));
        }
    }
}

#[test]
fn contiguous_proof_batches_are_exact_and_bounded() {
    let snapshot = ledger(17).inbox();
    let proofs = snapshot.proofs(3..17).unwrap();
    assert_eq!(proofs.len(), 14);
    for (index, proof) in proofs.iter().enumerate() {
        assert_eq!(*proof, snapshot.proof(index as u64 + 3).unwrap());
        assert!(proof.verify(B256::repeat_byte(1), B256::repeat_byte(2), snapshot.root()));
    }
    assert!(snapshot.proofs(17..17).unwrap().is_empty());
    assert!(snapshot.proofs(18..18).is_none());
    assert!(snapshot.proofs(core::ops::Range { start: 5, end: 4 }).is_none());
    assert!(snapshot.proofs(0..u64::MAX).is_none());
    assert!(ledger(0).inbox().proofs(0..0).unwrap().is_empty());
}

#[test]
fn proof_range_verification_binds_external_expectations_and_exact_sequence() {
    use bloch_l2_evm::escrow_inbox::verify_proof_range;
    let snapshot = ledger(5).inbox();
    let proofs = snapshot.proofs(1..4).unwrap();
    let network = B256::repeat_byte(1);
    let domain = B256::repeat_byte(2);
    let verify = |proofs: &[_]| verify_proof_range(network, domain, snapshot.root(), 5, 1..4, proofs);
    let observed = verify(&proofs).unwrap();
    assert_eq!(observed.total_sat(), 2 + 3 + 4);
    assert_eq!(observed.root(), snapshot.root());
    assert_eq!(observed.count(), 5);
    assert_eq!(observed.range(), 1..4);
    assert!(verify(&proofs[..2]).is_none());
    for mode in 0..5 {
        let mut changed = proofs.clone();
        match mode {
            0 => changed.reverse(),
            1 => changed[1] = changed[0].clone(),
            2 => changed[2].deposit.amount += 1,
            3 => changed[2].count += 1,
            _ => changed[2].siblings.push(B256::ZERO),
        }
        assert!(verify(&changed).is_none());
    }
    assert!(verify_proof_range(network, domain, B256::ZERO, 5, 1..4, &proofs).is_none());
    assert!(verify_proof_range(network, domain, snapshot.root(), 6, 1..4, &proofs).is_none());
    assert!(verify_proof_range(B256::ZERO, domain, snapshot.root(), 5, 1..4, &proofs).is_none());
    assert!(verify_proof_range(network, B256::ZERO, snapshot.root(), 5, 1..4, &proofs).is_none());
    assert!(verify_proof_range(network, domain, snapshot.root(), 5, 5..5, &[]).is_none());
    assert!(verify_proof_range(network, domain, snapshot.root(), u64::MAX, 0..u64::MAX, &[]).is_none());
    assert_eq!(verify(&proofs).unwrap(), observed); // membership never consumes
}
