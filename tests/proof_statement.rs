use alloy_primitives::{Address, B256, U256};
use bloch_l2_evm::{
    node_execution::{generate_node_batch_witness, genesis_v2},
    node_primitives::NodeBodyV2,
    proof_statement::{configuration_commitment, execute_statement, ExecutionStatement, StatementError, STATEMENT_TAG},
    BlockContext, ChainSpec,
};

#[test]
fn every_configuration_knob_is_bound_or_rejected() {
    let spec = ChainSpec::testnet();
    let expected = configuration_commitment(&spec).unwrap();
    let mutations: [fn(&mut ChainSpec); 14] = [
        |s| s.chain_id += 1,
        |s| s.gas_limit += 1,
        |s| s.block_time_secs += 1,
        |s| s.base_fee_elasticity += 1,
        |s| s.base_fee_denominator += 1,
        |s| s.initial_base_fee += 1,
        |s| s.block_reward = U256::from(1),
        |s| s.base_fee_vault = Address::repeat_byte(0x31),
        |s| s.sequencer_fee_vault = Address::repeat_byte(0x31),
        |s| s.supply_ledger = Address::repeat_byte(0x31),
        |s| s.block_info = Address::repeat_byte(0x31),
        |s| s.max_l1_sats -= 1,
        |s| s.deposit_gas += 1,
        |s| s.spec_id = revm::primitives::hardfork::SpecId::SHANGHAI,
    ];
    for mutate in mutations {
        let mut changed = spec.clone();
        mutate(&mut changed);
        assert_ne!(configuration_commitment(&changed), Ok(expected));
    }
    let mut invalid = spec;
    invalid.chain_id = 0;
    assert!(configuration_commitment(&invalid).is_err());
}

#[test]
fn strict_encoding_and_trusted_expectation_reject_all_byte_mutations() {
    let expected = ExecutionStatement {
        configuration: B256::repeat_byte(1),
        domain: B256::repeat_byte(2),
        previous_state_root: B256::repeat_byte(3),
        header_hash: B256::repeat_byte(4),
    };
    let bytes = expected.encode();
    assert_eq!(&bytes[..STATEMENT_TAG.len()], STATEMENT_TAG);
    assert_eq!(&bytes[STATEMENT_TAG.len()..STATEMENT_TAG.len() + 32], &[1; 32]);
    assert_eq!(ExecutionStatement::decode(&bytes), Ok(expected));
    assert_eq!(expected.check_expected(&bytes), Ok(()));
    for index in 0..bytes.len() {
        let mut changed = bytes;
        changed[index] ^= 1;
        assert!(expected.check_expected(&changed).is_err());
    }
    for length in 0..bytes.len() {
        assert_eq!(
            ExecutionStatement::decode(&bytes[..length]),
            Err(StatementError::Encoding)
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_eq!(ExecutionStatement::decode(&trailing), Err(StatementError::Encoding));
}

#[test]
fn actual_witness_reexecution_binds_configuration_and_complete_header() {
    let spec = ChainSpec::testnet();
    let mut state = genesis_v2(&spec, 10).unwrap();
    state.commit_root();
    let domain = B256::repeat_byte(19);
    let context = BlockContext {
        number: 1,
        timestamp: 11,
        base_fee_per_gas: spec.next_base_fee(spec.initial_base_fee, 0),
        prevrandao: B256::repeat_byte(7),
        anchor_root: B256::repeat_byte(8),
    };
    let body = NodeBodyV2::default();
    let (witness, outcome) = generate_node_batch_witness(&state, &spec, domain, &context, &body).unwrap();
    let statement = execute_statement(&spec, domain, &witness, &context, &body).unwrap();
    assert_eq!(
        statement,
        ExecutionStatement {
            configuration: configuration_commitment(&spec).unwrap(),
            domain,
            previous_state_root: state.state_root(),
            header_hash: outcome.header.hash()
        }
    );
    let mut wrong_spec = spec.clone();
    // This informational knob does not alter execution, but must alter the statement.
    wrong_spec.block_time_secs += 1;
    let changed = execute_statement(&wrong_spec, domain, &witness, &context, &body).unwrap();
    assert_eq!(changed.header_hash, statement.header_hash);
    assert_eq!(
        statement.check_expected(&changed.encode()),
        Err(StatementError::Mismatch)
    );
    let mut bad_witness = witness.clone();
    bad_witness.new_state_root = B256::ZERO;
    assert!(execute_statement(&spec, domain, &bad_witness, &context, &body).is_err());
    bad_witness = witness.clone();
    bad_witness.prev_state_root = B256::ZERO;
    assert!(execute_statement(&spec, domain, &bad_witness, &context, &body).is_err());
    let mut bad_context = context;
    bad_context.anchor_root = B256::ZERO;
    assert!(execute_statement(&spec, domain, &witness, &bad_context, &body).is_err());
}
