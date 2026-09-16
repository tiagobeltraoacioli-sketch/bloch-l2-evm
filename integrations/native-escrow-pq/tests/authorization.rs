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
