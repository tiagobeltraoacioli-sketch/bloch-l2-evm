// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use alloy_primitives::Address;
use bloch_l2_evm::escrow::{Coin, LockIntent, Outpoint};

fn hash(n: u8) -> B256 {
    B256::repeat_byte(n)
}
#[path = "../tests/support/mod.rs"]
mod support;
use support::{cursor, headers, position};
fn path(state: &SourceRegistry, height: u64) -> Vec<Bytes> {
    headers(height)[state.anchor().height as usize..].to_vec()
}
fn anchor(height: u64) -> SourceAnchor {
    let p = position(height);
    SourceAnchor {
        block: p.block(),
        slot: p.slot(),
        height: p.height(),
    }
}
fn registry() -> SourceRegistry {
    SourceRegistry::new(hash(1), hash(2), cursor()).unwrap()
}
fn fixture(count: usize) -> (SourceBatch, Vec<InboxProof>) {
    fixture_recipient(count, Address::repeat_byte(9))
}
fn fixture_recipient(count: usize, recipient: Address) -> (SourceBatch, Vec<InboxProof>) {
    let coins = (0..count)
        .map(|index| {
            (
                Outpoint {
                    txid: hash(index as u8 + 10),
                    vout: 0,
                },
                Coin {
                    value: 100,
                    owner: hash(4),
                },
            )
        })
        .collect();
    let mut escrow = EscrowLedger::new(hash(1), hash(2), coins, MAX_LOCKS).unwrap();
    let mut locations = vec![];
    for index in 0..count {
        let deposit = escrow
            .apply_authorized_lock(&LockIntent {
                network: hash(1),
                domain: hash(2),
                owner: hash(4),
                inputs: vec![Outpoint {
                    txid: hash(index as u8 + 10),
                    vout: 0,
                }],
                recipient,
                amount: 99,
                fee: 1,
                change_owner: hash(4),
                nonce: index as u64,
            })
            .unwrap();
        locations.push(TrustedLockLocation {
            sequence: index as u64,
            intent: deposit.id,
            transaction: hash(index as u8 + 20),
            position: DepositPosition {
                l1_height: 1,
                l1_tx_index: index as u32,
                l1_vout: 0,
            },
        });
    }
    assert!(escrow.conserved());
    let inbox = escrow.inbox();
    let proofs = inbox.proofs(0..count as u64).unwrap();
    (
        SourceBatch {
            network: hash(1),
            domain: hash(2),
            genesis: position(0).genesis(),
            previous: registry().commitment(),
            anchor: anchor(1),
            inbox_root: inbox.root(),
            count: count as u64,
            locations,
        },
        proofs,
    )
}
fn rejected(state: &mut SourceRegistry, batch: &SourceBatch, proofs: &[InboxProof], error: Error) {
    let before = state.clone();
    assert_eq!(
        state.apply(
            batch.commitment().unwrap(),
            position(batch.anchor.height),
            &path(state, batch.anchor.height),
            batch,
            proofs
        ),
        Err(error)
    );
    assert_eq!(*state, before);
}

#[test]
fn complete_mapping_preserves_height_not_slot_and_exports_existing_boundary() {
    let (batch, proofs) = fixture(2);
    let mut state = registry();
    state
        .apply(
            batch.commitment().unwrap(),
            position(batch.anchor.height),
            &path(&state, batch.anchor.height),
            &batch,
            &proofs,
        )
        .unwrap();
    assert_eq!(state.anchor().slot, 150);
    assert_eq!(state.anchor().height, 1);
    assert_eq!(state.locations()[1].position.l1_height, 1);
    assert_eq!(state.locations(), batch.locations);
    assert_eq!(state.count(), 2);
    rejected(&mut state, &batch, &proofs, Error::Replay);
    let mut next = batch.clone();
    next.previous = state.commitment();
    next.anchor = anchor(2);
    state
        .apply(
            next.commitment().unwrap(),
            position(next.anchor.height),
            &path(&state, next.anchor.height),
            &next,
            &proofs,
        )
        .unwrap();
    assert_eq!(state.count(), 2);
}

#[test]
fn codec_is_exact_bounded_and_versioned() {
    let (batch, _) = fixture(2);
    let bytes = batch.encode().unwrap();
    assert_eq!(bytes.len(), FIXED_BYTES + 2 * RECORD_BYTES);
    assert_eq!(SourceBatch::decode(&bytes).unwrap(), batch);
    for end in 0..bytes.len() {
        assert!(SourceBatch::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert_eq!(SourceBatch::decode(&bad), Err(Error::Codec));
    let mut bad = bytes.clone();
    bad[TAG.len() - 1] = b'2';
    assert_eq!(SourceBatch::decode(&bad), Err(Error::Codec));
    let mut bad = bytes.clone();
    bad[FIXED_BYTES - 4..FIXED_BYTES].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(SourceBatch::decode(&bad), Err(Error::Limit));
    assert_eq!(SourceBatch::decode(&vec![0; MAX_SOURCE_BYTES + 1]), Err(Error::Limit));
    let mut oversized = batch;
    oversized.count = MAX_LOCKS as u64 + 1;
    assert_eq!(oversized.encode(), Err(Error::Limit));
}

#[test]
fn authority_identity_ancestry_incomplete_and_slot_substitution_are_atomic() {
    let (batch, proofs) = fixture(2);
    let mut state = registry();
    let before = state.clone();
    assert_eq!(
        state.apply(hash(99), position(1), &headers(1), &batch, &proofs),
        Err(Error::Authority)
    );
    assert_eq!(state, before);
    let mut bad = batch.clone();
    bad.domain = hash(90);
    rejected(&mut state, &bad, &proofs, Error::Identity);
    let mut bad = batch.clone();
    bad.previous = B256::ZERO;
    rejected(&mut state, &bad, &proofs, Error::Ancestry);
    let mut bad = batch.clone();
    bad.anchor.slot = state.anchor.slot;
    rejected(&mut state, &bad, &proofs, Error::Identity);
    rejected(&mut state, &batch, &proofs[..1], Error::Incomplete);
    let mut bad = batch.clone();
    bad.locations.pop();
    rejected(&mut state, &bad, &proofs, Error::Incomplete);
    let mut bad = batch.clone();
    bad.locations[0].position.l1_height = bad.anchor.slot;
    rejected(&mut state, &bad, &proofs, Error::Mapping);
    let mut bad_proofs = proofs.clone();
    bad_proofs[1].deposit.amount += 1;
    rejected(&mut state, &batch, &bad_proofs, Error::Inclusion);
    let mut bad = batch;
    bad.locations[1].intent = hash(91);
    rejected(&mut state, &bad, &proofs, Error::Mapping);
}

#[test]
fn append_requires_full_unchanged_historical_mapping_and_leaves() {
    let (first, first_proofs) = fixture(1);
    let mut state = registry();
    state
        .apply(
            first.commitment().unwrap(),
            position(first.anchor.height),
            &path(&state, first.anchor.height),
            &first,
            &first_proofs,
        )
        .unwrap();
    let (mut next, proofs) = fixture(2);
    next.previous = state.commitment();
    next.anchor = anchor(2);
    next.locations[1].position.l1_height = 2;
    let mut bad = next.clone();
    bad.locations[0].transaction = hash(77);
    rejected(&mut state, &bad, &proofs, Error::Conflict);
    rejected(&mut state, &next, &proofs[1..], Error::Incomplete);
    let mut bad = next.clone();
    bad.locations[1].transaction = bad.locations[0].transaction;
    rejected(&mut state, &bad, &proofs, Error::Conflict);
    state
        .apply(
            next.commitment().unwrap(),
            position(next.anchor.height),
            &path(&state, next.anchor.height),
            &next,
            &proofs,
        )
        .unwrap();
    assert_eq!(state.count(), 2);
    // Membership proofs are valid, but the new tree rewrites prior locks.
    let (mut replacement, replacement_proofs) = fixture_recipient(3, Address::repeat_byte(55));
    replacement.previous = state.commitment();
    replacement.anchor = anchor(3);
    replacement.locations[1].position.l1_height = 2;
    replacement.locations[2].position.l1_height = 3;
    assert!(verify_proof_range(hash(1), hash(2), replacement.inbox_root, 3, 0..3, &replacement_proofs).is_some());
    rejected(&mut state, &replacement, &replacement_proofs, Error::Conflict);
}

#[test]
fn empty_snapshot_has_one_canonical_domain_bound_root() {
    let (batch, proofs) = fixture(0);
    let mut state = registry();
    let mut bad = batch.clone();
    bad.inbox_root = hash(33);
    rejected(&mut state, &bad, &proofs, Error::Inclusion);
    state
        .apply(
            batch.commitment().unwrap(),
            position(batch.anchor.height),
            &path(&state, batch.anchor.height),
            &batch,
            &proofs,
        )
        .unwrap();
    assert_eq!(state.count(), 0);
    assert_ne!(state.commitment(), registry().commitment());
    let other = SourceRegistry::new(hash(1), hash(9), cursor()).unwrap();
    assert_ne!(other.inbox_root(), registry().inbox_root());
}

#[test]
fn execution_adapter_binds_accepted_anchor_and_does_not_choose_consumption() {
    let (batch, proofs) = fixture(2);
    let mut state = registry();
    state
        .apply(
            batch.commitment().unwrap(),
            position(batch.anchor.height),
            &path(&state, batch.anchor.height),
            &batch,
            &proofs,
        )
        .unwrap();
    let execution = TrustedL1Batch {
        height: 1,
        block: position(1).block(),
        domain: hash(2),
        input: hash(99),
    };
    let joined = state.execution_batch(execution.clone(), 1..2).unwrap();
    assert_eq!(joined.locations, batch.locations[1..2]);
    assert_eq!(joined.count, 2);
    assert_eq!(joined.inbox_root, batch.inbox_root);
    assert_eq!(joined.execution, execution);
    assert!(state
        .execution_batch(execution.clone(), 2..2)
        .unwrap()
        .locations
        .is_empty());
    assert!(matches!(
        state.execution_batch(execution.clone(), 0..3),
        Err(Error::Incomplete)
    ));
    let mut wrong = execution.clone();
    wrong.height = 150;
    assert!(matches!(state.execution_batch(wrong, 0..1), Err(Error::Identity)));
    let mut wrong = execution.clone();
    wrong.block = hash(6);
    assert!(matches!(state.execution_batch(wrong, 0..1), Err(Error::Identity)));
    let mut wrong = execution;
    wrong.domain = hash(8);
    assert!(matches!(state.execution_batch(wrong, 0..1), Err(Error::Identity)));
    assert_eq!(state.count(), 2);
}

#[test]
fn derived_position_is_required_and_must_match_genesis_and_anchor() {
    assert_eq!(
        SourceRegistry::new(hash(1), hash(2), {
            let mut c = cursor();
            c.advance(
                bloch_l2_evm::l1::FinalizedCheckpoint {
                    block: position(1).block(),
                    slot: 150,
                },
                &headers(1),
            )
            .unwrap();
            c
        }),
        Err(Error::Configuration)
    );
    let (batch, proofs) = fixture(1);
    let mut state = registry();
    let before = state.clone();
    assert_eq!(
        state.apply(batch.commitment().unwrap(), position(2), &headers(2), &batch, &proofs),
        Err(Error::Identity)
    );
    assert_eq!(state, before);
    let mut wrong = batch.clone();
    wrong.genesis = hash(98);
    rejected(&mut state, &wrong, &proofs, Error::Identity);
    let mut wrong = batch;
    wrong.anchor.height = wrong.anchor.slot;
    // A caller-supplied height cannot replace the ancestry-derived position.
    assert_eq!(
        state.apply(wrong.commitment().unwrap(), position(1), &headers(1), &wrong, &proofs),
        Err(Error::Identity)
    );
    assert_eq!(state, before);
}

#[test]
fn valid_position_on_divergent_branch_cannot_extend_accepted_source() {
    use bloch_l2_evm::l1::FinalizedCheckpoint;
    let (first, proofs) = fixture(0);
    let mut state = registry();
    state
        .apply(first.commitment().unwrap(), position(1), &headers(1), &first, &proofs)
        .unwrap();
    let before = state.clone();
    let mut branch = headers(2);
    let mut branch_one = branch[1].to_vec();
    branch_one[36] = 77; // A different valid header at height one.
    branch[1] = branch_one.into();
    let mut branch_two = branch[2].to_vec();
    branch_two[4..36].copy_from_slice(support::id(&branch[1]).as_slice());
    branch[2] = branch_two.into();
    let checkpoint = FinalizedCheckpoint {
        block: support::id(&branch[2]),
        slot: 200,
    };
    let mut other_cursor = cursor();
    let other = other_cursor.advance(checkpoint, &branch).unwrap();
    assert_eq!(other.genesis(), position(2).genesis());
    assert_eq!(other.height(), 2);
    let mut fork = first.clone();
    fork.previous = state.commitment();
    fork.anchor = SourceAnchor {
        block: other.block(),
        slot: other.slot(),
        height: other.height(),
    };
    assert_eq!(
        state.apply(fork.commitment().unwrap(), other, &branch[1..], &fork, &[]),
        Err(Error::Ancestry)
    );
    assert_eq!(state, before);
    let spliced = [headers(1)[1].clone(), branch[2].clone()];
    assert_eq!(
        state.apply(fork.commitment().unwrap(), other, &spliced, &fork, &[]),
        Err(Error::Ancestry)
    );
    assert_eq!(state, before);
    let mut correct = first;
    correct.previous = state.commitment();
    correct.anchor = anchor(2);
    state
        .apply(
            correct.commitment().unwrap(),
            position(2),
            &headers(2)[1..],
            &correct,
            &[],
        )
        .unwrap();
    assert_eq!(state.anchor().height, 2);
}

fn v2_fixture() -> (
    SourceRegistry,
    bloch_l2_evm::ChainSpec,
    bloch_l2_evm::node_primitives::NodeHeaderV2,
    bloch_l2_evm::node_primitives::NodeBodyV2,
) {
    use bloch_l2_evm::{
        node_primitives::{NodeBodyV2, NodeHeaderV2},
        ChainSpec, DepositMint, DepositProvenance,
    };
    let (batch, proofs) = fixture(2);
    let mut state = registry();
    state
        .apply(batch.commitment().unwrap(), position(1), &headers(1), &batch, &proofs)
        .unwrap();
    let spec = ChainSpec::default();
    let body = NodeBodyV2 {
        deposits: batch
            .locations
            .iter()
            .zip(&proofs)
            .map(|(location, proof)| DepositMint {
                recipient: proof.deposit.recipient,
                provenance: DepositProvenance::BridgedBlch {
                    l1_height: location.position.l1_height,
                    l1_tx_index: location.position.l1_tx_index,
                    l1_txid: location.transaction.into(),
                    l1_vout: location.position.l1_vout,
                    l1_sats: proof.deposit.amount,
                },
            })
            .collect(),
        transactions: vec![],
    };
    // Deliberately only structural data: this unit fixture is NOT executed or
    // claimed to be a proof. Separate integration tests use actual V2 execution.
    let header = NodeHeaderV2 {
        domain: batch.domain,
        chain_id: spec.chain_id,
        number: 1,
        gas_limit: spec.gas_limit,
        gas_used: spec.deposit_gas * 2,
        beneficiary: spec.coinbase(),
        anchor_root: batch.anchor.block,
        transactions_root: body.transactions_root(),
        deposits_hash: body.deposits_hash(),
        parent_state_root: hash(81),
        state_root: hash(82),
        ..Default::default()
    };
    (state, spec, header, body)
}

#[test]
fn v2_selection_binds_complete_header_body_source_and_configuration_without_consuming() {
    use bloch_l2_evm::proof_statement::configuration_commitment;
    let (state, spec, header, body) = v2_fixture();
    let before = state.clone();
    let token = state.validate_v2_prefix(&spec, 0, &header, &body).unwrap();
    assert_eq!(token.range(), 0..2);
    assert_eq!(token.network(), hash(1));
    assert_eq!(token.genesis(), position(0).genesis());
    assert_eq!(token.domain(), header.domain);
    assert_eq!(token.source_commitment(), state.commitment());
    assert_eq!(token.inbox_root(), state.inbox_root());
    assert_eq!(token.inbox_count(), 2);
    assert_eq!(token.anchor(), state.anchor());
    assert_eq!(token.body_commitment(), keccak256(alloy_rlp::encode(&body)));
    assert_eq!(
        token.statement().configuration,
        configuration_commitment(&spec).unwrap()
    );
    assert_eq!(token.statement().previous_state_root, header.parent_state_root);
    assert_eq!(token.statement().header_hash, header.hash());
    // Selection may be repeated. Only the future atomic settlement cursor will
    // prevent consuming this range twice; this method makes no replay claim.
    assert_eq!(state.validate_v2_prefix(&spec, 0, &header, &body).unwrap(), token);
    assert_eq!(state, before);
    let mut different = header;
    different.state_root = hash(88);
    let other = state.validate_v2_prefix(&spec, 0, &different, &body).unwrap();
    assert_ne!(other.statement(), token.statement());
    assert!(token.statement().check_expected(&other.statement().encode()).is_err());
}

#[test]
fn v2_selection_rejects_forged_mints_even_with_matching_body_hash() {
    let (state, spec, header, body) = v2_fixture();
    let before = state.clone();
    let mut wrong = body.clone();
    wrong.deposits[1].recipient = Address::repeat_byte(44);
    let mut matching = header.clone();
    matching.deposits_hash = wrong.deposits_hash();
    assert_eq!(
        state.validate_v2_prefix(&spec, 0, &matching, &wrong),
        Err(Error::Mapping)
    );
    let mut wrong = body.clone();
    let bloch_l2_evm::DepositProvenance::BridgedBlch { l1_sats, .. } = &mut wrong.deposits[1].provenance;
    *l1_sats += 1;
    let mut matching = header.clone();
    matching.deposits_hash = wrong.deposits_hash();
    assert_eq!(
        state.validate_v2_prefix(&spec, 0, &matching, &wrong),
        Err(Error::Mapping)
    );
    let mut wrong = body.clone();
    wrong.deposits.pop();
    assert_eq!(
        state.validate_v2_prefix(&spec, 0, &header, &wrong),
        Err(Error::Incomplete)
    );
    assert_eq!(
        state.validate_v2_prefix(&spec, 3, &header, &body),
        Err(Error::Incomplete)
    );
    let mut wrong = body.clone();
    wrong.transactions.push(Bytes::from_static(&[2]));
    let mut matching = header.clone();
    matching.transactions_root = wrong.transactions_root();
    assert_eq!(state.validate_v2_prefix(&spec, 0, &matching, &wrong), Err(Error::Body));
    let mut wrong = header.clone();
    wrong.deposits_hash = hash(45);
    assert_eq!(state.validate_v2_prefix(&spec, 0, &wrong, &body), Err(Error::Body));
    let mut wrong = header.clone();
    wrong.anchor_root = hash(46);
    assert_eq!(state.validate_v2_prefix(&spec, 0, &wrong, &body), Err(Error::Identity));
    let mut wrong = header.clone();
    wrong.domain = hash(47);
    assert_eq!(
        state.validate_v2_prefix(&spec, 0, &wrong, &body),
        Err(Error::Configuration)
    );
    let mut wrong = header;
    wrong.gas_used += 1;
    assert_eq!(state.validate_v2_prefix(&spec, 0, &wrong, &body), Err(Error::Body));
    assert_eq!(state, before);
}
