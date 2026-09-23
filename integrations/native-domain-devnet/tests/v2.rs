// SPDX-License-Identifier: MIT OR Apache-2.0
//! Execution validity and source authorization are independent requirements.
mod support;

use alloy_primitives::{Address, B256};
use bloch_l2_evm::{
    escrow::{Coin, EscrowLedger, LockIntent, Outpoint},
    escrow_execution::TrustedLockLocation,
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    native_settlement::{
        SettlementPolicyV1, SettlementProofVerifierV1, SettlementRegistryV1,
        SETTLEMENT_PROOF_V1_BYTES,
    },
    proof_statement::execute_statement,
    scale::sats_to_wei,
    BlockContext, ChainSpec, DepositMint, DepositPosition, DepositProvenance,
};
use bloch_native_domain_devnet::{SettlementPayload, SourceAnchor, SourceBatch, SourceRegistry, MAX_LOCKS};

struct ExactSettlementVerifier {
    policy: B256,
}

impl SettlementProofVerifierV1 for ExactSettlementVerifier {
    fn verify(&self, proof_policy: B256, _: &[u8], proof: &[u8]) -> bool {
        proof_policy == self.policy && proof == [0x5a; SETTLEMENT_PROOF_V1_BYTES]
    }
}

#[test]
fn valid_v2_execution_still_requires_exact_source_selected_deposits() {
    let network = B256::repeat_byte(1);
    let domain = B256::repeat_byte(0xd3);
    let owner = B256::repeat_byte(8);
    let recipient = Address::repeat_byte(7);
    let mut spec = ChainSpec::testnet();
    spec.deposit_gas = spec.gas_limit / 2;
    let mut source = SourceRegistry::new(network, domain, support::cursor()).unwrap();
    let mut ledger = EscrowLedger::new(
        network,
        domain,
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
    let position = support::position(1);
    let mut locations = vec![];
    let mut mints = vec![];
    for sequence in 0..3 {
        let lock = ledger
            .apply_authorized_lock(&LockIntent {
                network,
                domain,
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
        let transaction = B256::repeat_byte(20 + sequence as u8);
        locations.push(TrustedLockLocation {
            sequence,
            intent: lock.id,
            transaction,
            position: DepositPosition {
                l1_height: 1,
                l1_tx_index: sequence as u32,
                l1_vout: 0,
            },
        });
        mints.push(DepositMint {
            recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: sequence as u32,
                l1_txid: transaction.into(),
                l1_vout: 0,
                l1_sats: 100,
            },
        });
    }
    let inbox = ledger.inbox();
    let batch = SourceBatch {
        network,
        domain,
        genesis: position.genesis(),
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
    source
        .apply(
            batch.commitment().unwrap(),
            position,
            &support::headers(1),
            &batch,
            &inbox.proofs(0..3).unwrap(),
        )
        .unwrap();
    let accepted = source.clone();
    let mut state = genesis_v2(&spec, 0).unwrap();
    let initial_head = node_head(&spec, domain, &state).unwrap();
    let settlement_policy = SettlementPolicyV1 {
        network,
        genesis: position.genesis(),
        domain,
        configuration: bloch_l2_evm::proof_statement::configuration_commitment(&spec).unwrap(),
        program_elf_keccak: B256::repeat_byte(0xa1),
        program_vkey_koalabear: B256::repeat_byte(0xa2),
        program_vkey_bn254: B256::repeat_byte(0xa3),
        proof_policy: B256::repeat_byte(0xa4),
        chain_id: spec.chain_id,
        first_l2_number: 1,
        initial_l2_parent_hash: initial_head.hash(),
        initial_l2_state_root: initial_head.state_root,
    };
    let mut settlement_registry = SettlementRegistryV1::new(settlement_policy).unwrap();
    let settlement_verifier = ExactSettlementVerifier {
        policy: settlement_policy.proof_policy,
    };
    let mut consumed = 0;
    for end in [2, 3, 3] {
        let parent = node_head(&spec, domain, &state).unwrap();
        let context = BlockContext {
            number: parent.number + 1,
            timestamp: parent.timestamp + 1,
            base_fee_per_gas: spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
            prevrandao: B256::repeat_byte(6),
            anchor_root: position.block(),
        };
        let body = NodeBodyV2 {
            deposits: mints[consumed as usize..end as usize].to_vec(),
            transactions: vec![],
        };
        if consumed == 0 {
            for mode in 0..3 {
                let mut forged = body.clone();
                match mode {
                    0 => forged.deposits[0].recipient = Address::repeat_byte(99),
                    1 => {
                        let DepositProvenance::BridgedBlch { ref mut l1_sats, .. } = forged.deposits[0].provenance;
                        *l1_sats += 1;
                    }
                    _ => {
                        forged.deposits.pop();
                    }
                }
                let (witness, outcome) = generate_node_batch_witness(&state, &spec, domain, &context, &forged).unwrap();
                // A genuine successful stateless execution is insufficient to
                // authorize a wrong recipient/amount or omit the mandatory prefix.
                let statement = execute_statement(&spec, domain, &witness, &context, &forged).unwrap();
                assert_eq!(statement.header_hash, outcome.header.hash());
                assert!(source
                    .validate_v2_prefix(&spec, consumed, &outcome.header, &forged)
                    .is_err());
                assert_eq!(source, accepted);
                assert_eq!(state.total_minted_wei(), sats_to_wei(0));
            }
        }
        let (witness, recorded) = generate_node_batch_witness(&state, &spec, domain, &context, &body).unwrap();
        let selected = source
            .validate_v2_prefix(&spec, consumed, &recorded.header, &body)
            .unwrap();
        let statement = execute_statement(&spec, domain, &witness, &context, &body).unwrap();
        assert_eq!(statement, selected.statement());
        assert_eq!(selected.range(), consumed..end);
        assert_eq!(selected.source_commitment(), source.commitment());
        assert_eq!(selected.inbox_count(), 3);
        assert_eq!(selected.anchor().block, position.block());
        assert_eq!(statement.header_hash, recorded.header.hash());
        if consumed == 0 {
            let mut wrong_policy = settlement_policy;
            wrong_policy.domain = B256::repeat_byte(0xee);
            assert_eq!(
                selected.select_settlement_v1(&recorded.header, wrong_policy, &settlement_registry),
                Err(bloch_native_domain_devnet::Error::Identity)
            );
        } else {
            let stale_registry = SettlementRegistryV1::new(settlement_policy).unwrap();
            assert_eq!(
                selected.select_settlement_v1(&recorded.header, settlement_policy, &stale_registry),
                Err(bloch_native_domain_devnet::Error::Replay)
            );
        }
        let selection = selected
            .select_settlement_v1(&recorded.header, settlement_policy, &settlement_registry)
            .unwrap();
        let expectation = selection.expectation();
        assert_eq!(expectation.statement.l2_header_hash, recorded.header.hash());
        assert_eq!(expectation.statement.consumed_start..expectation.statement.consumed_end, consumed..end);
        assert_eq!(expectation.statement.source_commitment, source.commitment());
        assert!(selection.transaction([0; SETTLEMENT_PROOF_V1_BYTES]).is_err());
        let transaction = selection.transaction([0x5a; SETTLEMENT_PROOF_V1_BYTES]).unwrap();
        let accepted_settlement = settlement_registry
            .verify_and_apply(&transaction.encode(), &expectation, &settlement_verifier)
            .unwrap();
        assert_eq!(accepted_settlement.l2_number, recorded.header.number);
        assert_eq!(accepted_settlement.consumed_end, end);
        let settlement = SettlementPayload::from_validated_prefix(
            &selected,
            &recorded.header,
            B256::repeat_byte(0xa1),
            B256::repeat_byte(0xa2),
            B256::repeat_byte(0xa3),
            B256::repeat_byte(0xa4),
            B256::repeat_byte(0xa5),
        )
        .unwrap();
        assert_eq!(settlement.l2_header_hash, statement.header_hash);
        assert_eq!(settlement.l2_state_root, recorded.header.state_root);
        assert_eq!(settlement.chain_id, spec.chain_id);
        assert_eq!(settlement.l1_block, selected.anchor().block);
        assert_eq!(settlement.consumed_start..settlement.consumed_end, consumed..end);
        assert_eq!(
            SettlementPayload::decode(&settlement.encode().unwrap()).unwrap(),
            settlement
        );
        let mut mismatched = recorded.header.clone();
        mismatched.state_root[0] ^= 1;
        assert!(SettlementPayload::from_validated_prefix(
            &selected,
            &mismatched,
            B256::repeat_byte(0xa1),
            B256::repeat_byte(0xa2),
            B256::repeat_byte(0xa3),
            B256::repeat_byte(0xa4),
            B256::repeat_byte(0xa5),
        )
        .is_err());
        let outcome = execute_node_block(&spec, domain, &mut state, &context, &body).unwrap();
        assert_eq!(outcome.header, recorded.header);
        assert_eq!(state.balance_of(&recipient), sats_to_wei(end * 100));
        assert_eq!(state.total_minted_wei(), sats_to_wei(end * 100));
        assert_eq!(source, accepted);
        assert!(ledger.conserved());
        // The consuming coordinator owns advancement; validation never consumes.
        consumed = end;
    }
}
