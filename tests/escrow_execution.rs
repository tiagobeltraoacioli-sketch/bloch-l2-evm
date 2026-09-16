#![cfg(feature = "experimental-escrow")]
use alloy_primitives::{Address, B256};
use bloch_l2_evm::{
    domain::{input_commitment, TrustedL1Batch},
    escrow::{Coin, EscrowLedger, LockIntent, Outpoint},
    escrow_execution::{EscrowEvmDomain, EscrowExecutionError as Error, TrustedEscrowBatch, TrustedLockLocation},
    escrow_inbox::{InboxProof, InboxSnapshot},
    execute_signed_block, generate_signed_batch_witness,
    scale::sats_to_wei,
    BatchWitness, BlockContext, ChainSpec, DepositMint, DepositPosition, DepositProvenance, L2State, SignedBlockInput,
};

struct Fixture {
    spec: ChainSpec,
    state: L2State,
    domain: EscrowEvmDomain,
    inbox: InboxSnapshot,
}
fn fixture(count: u64) -> Fixture {
    let mut spec = ChainSpec::default();
    spec.deposit_gas = spec.gas_limit / 2; // Mandatory chunks of two.
    let mut state = L2State::genesis(&spec);
    let domain = EscrowEvmDomain::new(
        B256::repeat_byte(1),
        B256::repeat_byte(2),
        B256::repeat_byte(3),
        spec.clone(),
        state.commit_root(),
        16 * 1024 * 1024,
    )
    .unwrap();
    let owner = B256::repeat_byte(8);
    let mut escrow = EscrowLedger::new(
        B256::repeat_byte(1),
        domain.id(),
        (0..count)
            .map(|i| {
                (
                    Outpoint {
                        txid: B256::repeat_byte(9),
                        vout: i as u32,
                    },
                    Coin { value: 1000, owner },
                )
            })
            .collect(),
        100,
    )
    .unwrap();
    for i in 0..count {
        escrow
            .apply_authorized_lock(&LockIntent {
                network: B256::repeat_byte(1),
                domain: domain.id(),
                owner,
                inputs: vec![Outpoint {
                    txid: B256::repeat_byte(9),
                    vout: i as u32,
                }],
                recipient: Address::repeat_byte(7),
                amount: 100,
                fee: 0,
                change_owner: owner,
                nonce: i,
            })
            .unwrap();
    }
    Fixture {
        spec,
        state,
        domain,
        inbox: escrow.inbox(),
    }
}
fn batch(f: &Fixture) -> (TrustedEscrowBatch, Vec<InboxProof>, SignedBlockInput, BatchWitness) {
    let start = f.domain.next_deposit();
    let end = (start + 2).min(f.inbox.len() as u64);
    let proofs: Vec<_> = (start..end).map(|i| f.inbox.proof(i).unwrap()).collect();
    // Synthetic, explicitly host-trusted L1 positions: not inbox positions/slots.
    let locations: Vec<_> = proofs
        .iter()
        .map(|p| TrustedLockLocation {
            sequence: p.deposit.sequence,
            intent: p.deposit.id,
            position: DepositPosition {
                l1_height: 50,
                l1_tx_index: p.deposit.sequence as u32,
                l1_vout: 0,
            },
            transaction: B256::repeat_byte(10 + p.deposit.sequence as u8),
        })
        .collect();
    let deposits = proofs
        .iter()
        .zip(&locations)
        .map(|(p, l)| DepositMint {
            recipient: p.deposit.recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: l.position.l1_height,
                l1_tx_index: l.position.l1_tx_index,
                l1_vout: l.position.l1_vout,
                l1_txid: l.transaction.into(),
                l1_sats: p.deposit.amount,
            },
        })
        .collect();
    let mut context = BlockContext::next(&f.spec, &f.state);
    context.timestamp = 100 + f.domain.next_block();
    context.anchor_root = B256::repeat_byte(4);
    let input = SignedBlockInput {
        context,
        deposits,
        ..Default::default()
    };
    let (witness, _) = generate_signed_batch_witness(&f.state, &f.spec, &input).unwrap();
    let trusted = TrustedEscrowBatch {
        execution: TrustedL1Batch {
            height: 100,
            block: input.context.anchor_root,
            domain: f.domain.id(),
            input: input_commitment(&input),
        },
        inbox_root: f.inbox.root(),
        count: f.inbox.len() as u64,
        locations,
    };
    (trusted, proofs, input, witness)
}
fn cursor(f: &Fixture) -> (B256, u64, u64) {
    (f.domain.state_root(), f.domain.next_block(), f.domain.next_deposit())
}

#[test]
fn ordered_chunks_credit_exact_value_once_and_empty_blocks_remain_valid() {
    let mut f = fixture(5);
    for expected in [2, 4, 5, 5] {
        let (trusted, proofs, input, witness) = batch(&f);
        let receipt = f
            .domain
            .verify_and_advance(&trusted, &proofs, &input, &witness)
            .unwrap();
        let outcome = execute_signed_block(&f.spec, &mut f.state, &input).unwrap();
        assert_eq!(outcome.state_root, receipt.execution.new_root);
        assert_eq!(f.domain.next_deposit(), expected);
        assert_eq!(
            f.state.balance_of(&Address::repeat_byte(7)),
            sats_to_wei(expected * 100)
        );
        assert_eq!(f.state.total_minted_wei(), sats_to_wei(expected * 100));
        let before = cursor(&f);
        assert!(f
            .domain
            .verify_and_advance(&trusted, &proofs, &input, &witness)
            .is_err());
        assert_eq!(cursor(&f), before);
    }
}

#[test]
fn omitted_extra_reordered_and_replayed_proofs_do_not_advance() {
    let mut f = fixture(5);
    let (trusted, proofs, input, witness) = batch(&f);
    let before = cursor(&f);
    for mode in 0..4 {
        let mut altered = proofs.clone();
        match mode {
            0 => {
                altered.pop();
            }
            1 => altered.push(proofs[0].clone()),
            2 => altered.reverse(),
            _ => altered[1] = altered[0].clone(),
        }
        assert_eq!(
            f.domain.verify_and_advance(&trusted, &altered, &input, &witness),
            Err(Error::Sequence)
        );
        assert_eq!(cursor(&f), before);
    }
    let mut omitted = input.clone();
    omitted.deposits.clear();
    assert_eq!(
        f.domain.verify_and_advance(&trusted, &proofs, &omitted, &witness),
        Err(Error::Sequence)
    );
}

#[test]
fn forged_inclusion_location_or_mint_cannot_credit() {
    let mut f = fixture(2);
    let (trusted, proofs, input, witness) = batch(&f);
    let before = cursor(&f);
    for mode in 0..9 {
        let mut t = trusted.clone();
        let mut p = proofs.clone();
        let mut i = input.clone();
        match mode {
            0 => p[0].deposit.amount += 1,
            1 => t.inbox_root = B256::repeat_byte(88),
            2 => t.locations[0].intent = B256::ZERO,
            3 => t.locations[0].position.l1_height = 101,
            4 => t.locations[0].transaction = B256::ZERO,
            5 => i.deposits[0].recipient = Address::repeat_byte(88),
            6 => p[0].count += 1,
            7 => t.locations[0].position.l1_tx_index += 1,
            _ => t.locations[0].transaction = B256::repeat_byte(88),
        }
        assert_eq!(f.domain.verify_and_advance(&t, &p, &i, &witness), Err(Error::Inclusion));
        assert_eq!(cursor(&f), before);
    }
}

#[test]
fn failed_execution_preserves_both_cursors_and_allows_corrected_retry() {
    let mut f = fixture(2);
    let (trusted, proofs, input, mut witness) = batch(&f);
    let correct = witness.new_state_root;
    witness.new_state_root = B256::repeat_byte(77);
    let before = cursor(&f);
    assert!(matches!(
        f.domain.verify_and_advance(&trusted, &proofs, &input, &witness),
        Err(Error::Execution(_))
    ));
    assert_eq!(cursor(&f), before);
    witness.new_state_root = correct;
    f.domain
        .verify_and_advance(&trusted, &proofs, &input, &witness)
        .unwrap();
    assert_eq!(f.domain.next_deposit(), 2);
}

#[test]
fn snapshot_conflicts_and_shrinking_counts_are_rejected() {
    let mut f = fixture(5);
    let (t, p, i, w) = batch(&f);
    f.domain.verify_and_advance(&t, &p, &i, &w).unwrap();
    execute_signed_block(&f.spec, &mut f.state, &i).unwrap();
    let (trusted, proofs, input, witness) = batch(&f);
    let before = cursor(&f);
    for mode in 0..5 {
        let mut t = trusted.clone();
        match mode {
            0 => t.inbox_root = B256::repeat_byte(99),
            1 => t.count += 1,
            2 => t.execution.block = B256::repeat_byte(99),
            3 => {
                t.execution.height += 1;
                t.count -= 1;
            }
            _ => {
                t.execution.height += 1;
                t.inbox_root = B256::repeat_byte(99);
            }
        }
        assert_eq!(
            f.domain.verify_and_advance(&t, &proofs, &input, &witness),
            Err(Error::Snapshot)
        );
        assert_eq!(cursor(&f), before);
    }
}

#[test]
fn receipt_binds_consumption_and_empty_inbox_executes() {
    let mut f = fixture(0);
    let (t, p, i, w) = batch(&f);
    let receipt = f.domain.verify_and_advance(&t, &p, &i, &w).unwrap();
    assert_eq!((receipt.start, receipt.end), (0, 0));
    for mode in 0..4 {
        let mut changed = receipt.clone();
        match mode {
            0 => changed.start += 1,
            1 => changed.end += 1,
            2 => changed.inbox_count += 1,
            _ => changed.inbox_root = B256::ZERO,
        }
        assert_ne!(receipt.commitment(), changed.commitment());
    }
}

#[test]
fn larger_snapshot_at_new_anchor_resumes_from_consumed_prefix() {
    let mut f = fixture(2);
    let (t, p, i, w) = batch(&f);
    f.domain.verify_and_advance(&t, &p, &i, &w).unwrap();
    execute_signed_block(&f.spec, &mut f.state, &i).unwrap();
    f.inbox = fixture(5).inbox;
    let (mut trusted, proofs, mut input, _) = batch(&f);
    input.context.anchor_root = B256::repeat_byte(5);
    trusted.execution.block = input.context.anchor_root;
    trusted.execution.height = 101;
    trusted.execution.input = input_commitment(&input);
    let (witness, _) = generate_signed_batch_witness(&f.state, &f.spec, &input).unwrap();
    let receipt = f
        .domain
        .verify_and_advance(&trusted, &proofs, &input, &witness)
        .unwrap();
    assert_eq!((receipt.start, receipt.end), (2, 4));
    execute_signed_block(&f.spec, &mut f.state, &input).unwrap();
    assert_eq!(f.state.total_minted_wei(), sats_to_wei(400));
    let before = cursor(&f);
    trusted.execution.height = 99;
    assert!(f
        .domain
        .verify_and_advance(&trusted, &proofs, &input, &witness)
        .is_err());
    assert_eq!(cursor(&f), before);
}
