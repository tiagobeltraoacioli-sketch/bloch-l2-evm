//! Simulation only: caller authorization and initial coins are trusted test inputs.
use alloy_primitives::{Address, B256};
use bloch_l2_evm::escrow::{Coin, EscrowError, EscrowLedger, LockIntent, Outpoint};
fn main() {
    let input = Outpoint {
        txid: B256::repeat_byte(4),
        vout: 0,
    };
    let owner = B256::repeat_byte(3);
    let intent = LockIntent {
        network: B256::repeat_byte(1),
        domain: B256::repeat_byte(2),
        owner,
        inputs: vec![input],
        recipient: Address::repeat_byte(7),
        amount: 60_000,
        fee: 10,
        change_owner: owner,
        nonce: 0,
    };
    let mut ledger = EscrowLedger::new(
        intent.network,
        intent.domain,
        vec![(input, Coin { value: 100_000, owner })],
        100,
    )
    .unwrap();
    let record = ledger.apply_authorized_lock(&intent).unwrap();
    assert!(ledger.conserved());
    assert!(ledger.coin(input).is_none());
    let change = ledger
        .coin(Outpoint {
            txid: record.id,
            vout: 0,
        })
        .unwrap();
    assert_eq!(ledger.apply_authorized_lock(&intent), Err(EscrowError::Replay));
    assert_eq!(ledger.release(), Err(EscrowError::ReleaseUnavailable));
    println!("SIMULATION ONLY: authorization assumed; no keys, mainnet funds, EVM mint or release.");
    println!(
        "Locked: {} sat; change: {} sat; accounted fee: {} sat",
        ledger.locked_sat(),
        change.value,
        ledger.fee_sat()
    );
    println!("Experimental state commitment: {}", ledger.commitment());
    println!("Conservation verified; replay and unavailable release rejected.");
}
