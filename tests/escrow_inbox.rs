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
