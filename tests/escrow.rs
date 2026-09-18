#![cfg(feature = "experimental-escrow")]
use alloy_primitives::{Address, B256};
use bloch_l2_evm::escrow::{Coin, EscrowError as Error, EscrowLedger, LockIntent, Outpoint};
fn setup() -> (EscrowLedger, LockIntent) {
    let source = Outpoint {
        txid: B256::repeat_byte(4),
        vout: 0,
    };
    let intent = LockIntent {
        network: B256::repeat_byte(1),
        domain: B256::repeat_byte(2),
        owner: B256::repeat_byte(3),
        inputs: vec![source],
        recipient: Address::repeat_byte(7),
        amount: 600,
        fee: 10,
        change_owner: B256::repeat_byte(3),
        nonce: 0,
    };
    let ledger = EscrowLedger::new(
        intent.network,
        intent.domain,
        vec![(
            source,
            Coin {
                value: 1000,
                owner: intent.owner,
            },
        )],
        100,
    )
    .unwrap();
    (ledger, intent)
}
#[test]
fn authorized_lock_consumes_inputs_and_conserves_principal_change_and_fee() {
    let (mut ledger, intent) = setup();
    let deposit = ledger.apply_authorized_lock(&intent).unwrap();
    assert!(ledger.coin(intent.inputs[0]).is_none());
    assert_eq!(ledger.locked_sat(), 600);
    assert_eq!(ledger.fee_sat(), 10);
    assert_eq!(
        ledger
            .coin(Outpoint {
                txid: deposit.id,
                vout: 0
            })
            .unwrap()
            .value,
        390
    );
    assert_eq!(deposit.recipient, intent.recipient);
    assert_eq!(deposit.sequence, 0);
    assert!(ledger.conserved());
}
#[test]
fn replay_and_nonce_changed_double_spend_preserve_state() {
    let (mut ledger, mut intent) = setup();
    ledger.apply_authorized_lock(&intent).unwrap();
    let root = ledger.commitment();
    assert_eq!(ledger.apply_authorized_lock(&intent), Err(Error::Replay));
    intent.nonce += 1;
    assert_eq!(ledger.apply_authorized_lock(&intent), Err(Error::Funding));
    assert_eq!(ledger.commitment(), root);
}
#[test]
fn wrong_network_domain_owner_or_overspend_do_not_mutate() {
    let (ledger, intent) = setup();
    for n in 0..4 {
        let mut ledger = ledger.clone();
        let root = ledger.commitment();
        let mut invalid = intent.clone();
        match n {
            0 => invalid.network = B256::repeat_byte(99),
            1 => invalid.domain = B256::repeat_byte(99),
            2 => invalid.owner = B256::repeat_byte(99),
            _ => invalid.amount = 1001,
        }
        assert!(ledger.apply_authorized_lock(&invalid).is_err());
        assert_eq!(ledger.commitment(), root);
    }
}
#[test]
fn duplicated_inputs_and_change_overflow_are_rejected() {
    let (mut ledger, mut intent) = setup();
    intent.inputs.push(intent.inputs[0]);
    let root = ledger.commitment();
    assert_eq!(ledger.apply_authorized_lock(&intent), Err(Error::Funding));
    assert_eq!(ledger.commitment(), root);
    intent.inputs[1].vout = 1;
    intent.amount = 1;
    intent.fee = 0;
    let coins = intent
        .inputs
        .iter()
        .map(|id| {
            (
                *id,
                Coin {
                    value: u64::MAX,
                    owner: intent.owner,
                },
            )
        })
        .collect();
    let mut ledger = EscrowLedger::new(intent.network, intent.domain, coins, 100).unwrap();
    let root = ledger.commitment();
    assert_eq!(ledger.apply_authorized_lock(&intent), Err(Error::Amount));
    assert_eq!(ledger.commitment(), root);
}
#[test]
fn every_authorization_field_changes_the_signing_root() {
    let (_, intent) = setup();
    let root = intent.signing_root();
    for n in 0..10 {
        let mut changed = intent.clone();
        match n {
            0 => changed.network = B256::repeat_byte(8),
            1 => changed.domain = B256::repeat_byte(8),
            2 => changed.owner = B256::repeat_byte(8),
            3 => changed.change_owner = B256::repeat_byte(8),
            4 => changed.recipient = Address::repeat_byte(8),
            5 => changed.amount += 1,
            6 => changed.fee += 1,
            7 => changed.nonce += 1,
            8 => changed.inputs[0].vout += 1,
            _ => changed.inputs[0].txid = B256::repeat_byte(8),
        }
        assert_ne!(changed.signing_root(), root);
    }
}
#[test]
fn chained_locks_conserve_value_and_create_monotonic_inbox_positions() {
    let (mut ledger, mut intent) = setup();
    intent.amount = 1;
    intent.fee = 1;
    for n in 0..64 {
        intent.nonce = n;
        let record = ledger.apply_authorized_lock(&intent).unwrap();
        assert_eq!(record.sequence, n);
        assert!(ledger.conserved());
        intent.inputs = vec![Outpoint {
            txid: record.id,
            vout: 0,
        }];
    }
    assert_eq!(ledger.locked_sat(), 64);
    assert_eq!(ledger.fee_sat(), 64);
    assert_eq!(ledger.lock_count(), 64);
}
#[test]
fn capacity_never_discards_replay_protection() {
    let (_, mut intent) = setup();
    let source = intent.inputs[0];
    let mut ledger = EscrowLedger::new(
        intent.network,
        intent.domain,
        vec![(
            source,
            Coin {
                value: 1000,
                owner: intent.owner,
            },
        )],
        1,
    )
    .unwrap();
    intent.amount = 1;
    let first = ledger.apply_authorized_lock(&intent).unwrap();
    let root = ledger.commitment();
    intent.inputs = vec![Outpoint {
        txid: first.id,
        vout: 0,
    }];
    assert_eq!(ledger.apply_authorized_lock(&intent), Err(Error::Capacity));
    assert_eq!(ledger.commitment(), root);
}
#[test]
fn release_without_verifier_is_unconditionally_unavailable() {
    let (mut ledger, intent) = setup();
    ledger.apply_authorized_lock(&intent).unwrap();
    let root = ledger.commitment();
    assert_eq!(ledger.release(), Err(Error::ReleaseUnavailable));
    assert_eq!(ledger.commitment(), root);
    assert!(ledger.conserved());
}
#[test]
fn duplicate_genesis_outpoints_are_rejected() {
    let (_, intent) = setup();
    let entry = (
        intent.inputs[0],
        Coin {
            value: 1000,
            owner: intent.owner,
        },
    );
    assert!(matches!(
        EscrowLedger::new(intent.network, intent.domain, vec![entry, entry], 100),
        Err(Error::Configuration)
    ));
}
