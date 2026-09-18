// SPDX-License-Identifier: MIT OR Apache-2.0
//! Compose the experimental mapping with the existing real EVM verifier.
//! The source commitment remains explicitly trusted synthetic input.
mod support;

use alloy_primitives::{Address, B256};
use bloch_l2_evm::{
    domain::{input_commitment, TrustedL1Batch},
    escrow::{Coin, EscrowLedger, LockIntent, Outpoint},
    escrow_execution::{EscrowEvmDomain, TrustedLockLocation},
    execute_signed_block, generate_signed_batch_witness,
    scale::sats_to_wei,
    BlockContext, ChainSpec, DepositMint, DepositPosition, DepositProvenance, L2State, SignedBlockInput,
};
use bloch_native_domain_devnet::{SourceAnchor, SourceBatch, SourceRegistry, MAX_LOCKS};

#[test]
fn accepted_source_drives_mandatory_chunks_without_duplicate_credit_after_failed_execution() {
    let network = B256::repeat_byte(1);
    let recipient = Address::repeat_byte(7);
    let owner = B256::repeat_byte(8);
    let mut spec = ChainSpec::default();
    spec.deposit_gas = spec.gas_limit / 2;
    let mut state = L2State::genesis(&spec);
    let mut domain = EscrowEvmDomain::new(
        network,
        B256::repeat_byte(2),
        B256::repeat_byte(3),
        spec.clone(),
        state.commit_root(),
        16 * 1024 * 1024,
    )
    .unwrap();
    let genesis = support::position(0);
    let position = support::position(2);
    let mut source = SourceRegistry::new(network, domain.id(), support::cursor()).unwrap();
    let mut ledger = EscrowLedger::new(
        network,
        domain.id(),
        (0..3)
            .map(|vout| {
                (
                    Outpoint {
                        txid: B256::repeat_byte(9),
                        vout,
                    },
                    Coin { value: 101, owner },
                )
            })
            .collect(),
        MAX_LOCKS,
    )
    .unwrap();
    let mut locations = Vec::new();
    for sequence in 0..3 {
        let deposit = ledger
            .apply_authorized_lock(&LockIntent {
                network,
                domain: domain.id(),
                owner,
                inputs: vec![Outpoint {
                    txid: B256::repeat_byte(9),
                    vout: sequence as u32,
                }],
                recipient,
                amount: 100,
                fee: 1,
                change_owner: owner,
                nonce: sequence,
            })
            .unwrap();
        locations.push(TrustedLockLocation {
            sequence,
            intent: deposit.id,
            transaction: B256::repeat_byte(20 + sequence as u8),
            position: DepositPosition {
                l1_height: 2,
                l1_tx_index: sequence as u32,
                l1_vout: 0,
            },
        });
    }
    assert!(ledger.conserved());
    let inbox = ledger.inbox();
    let snapshot = SourceBatch {
        network,
        genesis: genesis.genesis(),
        domain: domain.id(),
        previous: source.commitment(),
        anchor: SourceAnchor {
            block: position.block(),
            slot: position.slot(),
            height: position.height(),
        },
        inbox_root: inbox.root(),
        count: 3,
        locations,
    };
    // This test authority is synthetic and independent of EVM witness verification.
    let trusted_source = snapshot.commitment().unwrap();
    source
        .apply(
            trusted_source,
            position,
            &support::headers(2),
            &snapshot,
            &inbox.proofs(0..3).unwrap(),
        )
        .unwrap();
    #[cfg(unix)]
    {
        use bloch_native_domain_devnet::journal::{JournalLimits, SourceJournal};
        // Recover through actual files with an independently retained mark,
        // then use that recovered source for every EVM block below.
        let directory = std::env::temp_dir().join(format!(
            "bloch-source-execution-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut journal = SourceJournal::create(
            &directory,
            network,
            domain.id(),
            support::cursor(),
            JournalLimits::default(),
        )
        .unwrap();
        let retained = journal
            .append(
                trusted_source,
                position,
                &support::headers(2),
                &snapshot,
                &inbox.proofs(0..3).unwrap(),
            )
            .unwrap();
        drop(journal);
        let recovered = SourceJournal::open(
            &directory,
            network,
            domain.id(),
            support::cursor(),
            retained,
            JournalLimits::default(),
        )
        .unwrap();
        assert_eq!(recovered.registry().unwrap(), &source);
        source = recovered.registry().unwrap().clone();
        drop(recovered);
        std::fs::remove_dir_all(directory).unwrap();
    }
    let accepted_source = source.clone();
    for expected_consumed in [2, 3, 3] {
        let range = domain.required_deposit_range(source.count()).unwrap();
        let proofs = inbox.proofs(range.clone()).unwrap();
        let deposits = proofs
            .iter()
            .zip(&source.locations()[range.start as usize..range.end as usize])
            .map(|(proof, location)| DepositMint {
                recipient: proof.deposit.recipient,
                provenance: DepositProvenance::BridgedBlch {
                    l1_height: location.position.l1_height,
                    l1_tx_index: location.position.l1_tx_index,
                    l1_txid: location.transaction.into(),
                    l1_vout: location.position.l1_vout,
                    l1_sats: proof.deposit.amount,
                },
            })
            .collect();
        let mut context = BlockContext::next(&spec, &state);
        context.timestamp = 100 + domain.next_block();
        context.anchor_root = source.anchor().block;
        let input = SignedBlockInput {
            context,
            deposits,
            ..Default::default()
        };
        let (witness, _) = generate_signed_batch_witness(&state, &spec, &input).unwrap();
        let trusted = source
            .execution_batch(
                TrustedL1Batch {
                    height: source.anchor().height,
                    block: source.anchor().block,
                    domain: domain.id(),
                    input: input_commitment(&input),
                },
                range.clone(),
            )
            .unwrap();
        let before = (domain.state_root(), domain.next_block(), domain.next_deposit());
        let mut invalid = witness.clone();
        invalid.new_state_root = B256::ZERO;
        assert!(domain.verify_and_advance(&trusted, &proofs, &input, &invalid).is_err());
        assert_eq!(
            (domain.state_root(), domain.next_block(), domain.next_deposit()),
            before
        );
        assert_eq!(source, accepted_source);
        let receipt = domain.verify_and_advance(&trusted, &proofs, &input, &witness).unwrap();
        assert_eq!(receipt.start..receipt.end, range);
        assert_eq!(domain.next_deposit(), expected_consumed);
        let outcome = execute_signed_block(&spec, &mut state, &input).unwrap();
        assert_eq!(outcome.state_root, receipt.execution.new_root);
        assert_eq!(state.balance_of(&recipient), sats_to_wei(100 * expected_consumed));
        assert_eq!(state.total_minted_wei(), sats_to_wei(100 * expected_consumed));
        let after = (domain.state_root(), domain.next_block(), domain.next_deposit());
        assert!(domain.verify_and_advance(&trusted, &proofs, &input, &witness).is_err());
        assert_eq!((domain.state_root(), domain.next_block(), domain.next_deposit()), after);
        assert_eq!(source, accepted_source);
        assert!(ledger.conserved());
    }
}
