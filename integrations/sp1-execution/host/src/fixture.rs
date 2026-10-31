// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic, synthetic-only inputs with independently executed host expectations.
//! The signing key is a published fixture. No network or real funds are involved.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, node_head},
    node_primitives::{NodeBodyV2, NodeHeaderV2},
    proof_statement::{configuration_commitment, ExecutionStatement},
    proving::BatchWitness,
    BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State,
};
use k256::ecdsa::SigningKey;
use std::{error::Error, io};

/// Three private input frames and an independently computed expected public statement.
pub struct Fixture {
    pub witness: BatchWitness,
    pub context: BlockContext,
    pub body: NodeBodyV2,
    pub expected: ExecutionStatement,
    pub parent: NodeHeaderV2,
    pub header: NodeHeaderV2,
}

/// Synthetic deposit funds nonce-0 deployment and nonce-1 call storing 42 in slot 0.
pub fn fixture() -> Result<Fixture, Box<dyn Error>> {
    fixture_with(&ChainSpec::testnet())
}

/// [`fixture`] under the given execution rules (settlement V3: `testnet_v3`).
pub fn fixture_with(spec: &ChainSpec) -> Result<Fixture, Box<dyn Error>> {
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).map_err(|error| io::Error::other(error.to_string()))?;
    let sender = Address::from_public_key(key.verifying_key());
    let contract = sender.create(0);
    // Runtime: PUSH1 0; CALLDATALOAD; PUSH1 0; SSTORE; STOP.
    let runtime = [0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00];
    // Copy and return the seven runtime bytes immediately following this prefix.
    let mut initcode = vec![0x60, 0x07, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x07, 0x60, 0x00, 0xf3];
    initcode.extend_from_slice(&runtime);
    let body = NodeBodyV2 {
        deposits: vec![DepositMint {
            recipient: sender,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: 0,
                l1_txid: [0xd3; 32],
                l1_vout: 0,
                l1_sats: 100_000_000,
            },
        }],
        transactions: vec![
            sign(spec, &key, 0, TxKind::Create, initcode.into())?,
            sign(
                spec,
                &key,
                1,
                TxKind::Call(contract),
                Bytes::copy_from_slice(&U256::from(42).to_be_bytes::<32>()),
            )?,
        ],
    };
    let (fixture, state, outcome) = execute_fixture_with(spec, body, B256::repeat_byte(8))?;
    ensure(state.nonce_of(&sender) == 2, "fixture sender nonce is not 2")?;
    ensure(outcome.transactions.len() == 2, "fixture transaction count differs")?;
    ensure(outcome.receipts.len() == 2, "fixture receipt count differs")?;
    ensure(
        outcome
            .transactions
            .iter()
            .all(|tx| tx.success && tx.gas_used > 0 && tx.burned_wei == U256::ZERO),
        "fixture deployment or call failed",
    )?;
    ensure(
        outcome.transactions[0].created_address == Some(contract) && outcome.transactions[1].created_address.is_none(),
        "fixture creation address differs",
    )?;
    let account = state
        .account(&contract)
        .ok_or_else(|| io::Error::other("fixture contract missing"))?;
    ensure(
        account.nonce == 1 && account.code_hash == keccak256(runtime),
        "fixture runtime differs",
    )?;
    let slot = state
        .db()
        .cache
        .accounts
        .get(&contract)
        .and_then(|account| account.storage.get(&U256::ZERO))
        .copied();
    ensure(slot == Some(U256::from(42)), "fixture contract slot 0 is not 42")?;
    Ok(fixture)
}

/// Benchmark block: one deposit funds a single sender that makes `n` plain
/// value transfers (21,000 gas each) to `n` distinct, previously empty
/// accounts. `n = 0` is the deposit-only block the devnets settle today.
pub fn fixture_transfers(spec: &ChainSpec, n: u64) -> Result<Fixture, Box<dyn Error>> {
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).map_err(|error| io::Error::other(error.to_string()))?;
    let sender = Address::from_public_key(key.verifying_key());
    let mut transactions = Vec::new();
    for nonce in 0..n {
        let mut recipient = [0x5a; 20];
        recipient[12..].copy_from_slice(&nonce.to_be_bytes());
        transactions.push(sign_with(
            spec,
            &key,
            nonce,
            TxKind::Call(Address::from(recipient)),
            U256::from(1_000_000_000_000u64),
            Bytes::new(),
            21_000,
        )?);
    }
    let body = NodeBodyV2 {
        deposits: vec![bench_deposit(sender)],
        transactions,
    };
    let (fixture, state, outcome) = execute_fixture_with(spec, body, B256::repeat_byte(8))?;
    ensure(state.nonce_of(&sender) == n, "transfer fixture sender nonce differs")?;
    ensure(
        outcome
            .transactions
            .iter()
            .all(|tx| tx.success && tx.gas_used == 21_000),
        "a benchmark transfer failed",
    )?;
    Ok(fixture)
}

/// Benchmark block: one deposit, a deployment of a contract whose runtime
/// stores calldata word `v` at storage slot `v`, then `n` calls writing `n`
/// distinct fresh slots. User transactions: `n + 1`.
pub fn fixture_calls(spec: &ChainSpec, n: u64) -> Result<Fixture, Box<dyn Error>> {
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).map_err(|error| io::Error::other(error.to_string()))?;
    let sender = Address::from_public_key(key.verifying_key());
    let contract = sender.create(0);
    // Runtime: PUSH1 0; CALLDATALOAD; DUP1; SSTORE; STOP  (sstore(v, v)).
    let runtime = [0x60, 0x00, 0x35, 0x80, 0x55, 0x00];
    // Copy and return the six runtime bytes immediately following this prefix.
    let mut initcode = vec![0x60, 0x06, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x06, 0x60, 0x00, 0xf3];
    initcode.extend_from_slice(&runtime);
    let mut transactions = vec![sign_with(
        spec,
        &key,
        0,
        TxKind::Create,
        U256::ZERO,
        initcode.into(),
        200_000,
    )?];
    for i in 0..n {
        transactions.push(sign_with(
            spec,
            &key,
            i + 1,
            TxKind::Call(contract),
            U256::ZERO,
            Bytes::copy_from_slice(&U256::from(i + 1).to_be_bytes::<32>()),
            100_000,
        )?);
    }
    let body = NodeBodyV2 {
        deposits: vec![bench_deposit(sender)],
        transactions,
    };
    let (fixture, state, outcome) = execute_fixture_with(spec, body, B256::repeat_byte(8))?;
    ensure(state.nonce_of(&sender) == n + 1, "call fixture sender nonce differs")?;
    ensure(
        outcome.transactions.iter().all(|tx| tx.success),
        "a benchmark contract call failed",
    )?;
    let account = state
        .account(&contract)
        .ok_or_else(|| io::Error::other("benchmark contract missing"))?;
    ensure(account.code_hash == keccak256(runtime), "benchmark runtime differs")?;
    Ok(fixture)
}

/// Benchmark block: one deposit, then `n` withdrawals through the outbox
/// predeploy (`initiateWithdrawal`, 0.01 BLCH each, distinct L1 recipients).
/// Requires a chain with the withdrawal outbox (`ChainSpec::testnet_v3`).
pub fn fixture_withdrawals(spec: &ChainSpec, n: u64) -> Result<Fixture, Box<dyn Error>> {
    use bloch_l2_evm::withdrawal::{INITIATE_WITHDRAWAL_SELECTOR, MIN_WITHDRAWAL_SATS};
    let outbox = spec
        .withdrawal_outbox
        .ok_or_else(|| io::Error::other("withdrawal fixture requires the outbox"))?;
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).map_err(|error| io::Error::other(error.to_string()))?;
    let sender = Address::from_public_key(key.verifying_key());
    let mut transactions = Vec::new();
    for nonce in 0..n {
        let mut input = INITIATE_WITHDRAWAL_SELECTOR.to_vec();
        input.extend_from_slice(&[0x5a; 24]);
        input.extend_from_slice(&nonce.to_be_bytes());
        transactions.push(sign_with(
            spec,
            &key,
            nonce,
            TxKind::Call(outbox),
            bloch_l2_evm::sats_to_wei(MIN_WITHDRAWAL_SATS),
            input.into(),
            100_000,
        )?);
    }
    // 100 BLCH: n withdrawals of 0.01 BLCH plus fees, for any benchmarked n.
    let mut deposit = bench_deposit(sender);
    let DepositProvenance::BridgedBlch { l1_sats, .. } = &mut deposit.provenance;
    *l1_sats = 100 * 100_000_000;
    let body = NodeBodyV2 {
        deposits: vec![deposit],
        transactions,
    };
    let (fixture, state, outcome) = execute_fixture_with(spec, body, B256::repeat_byte(8))?;
    ensure(state.nonce_of(&sender) == n, "withdrawal fixture sender nonce differs")?;
    ensure(
        outcome.transactions.iter().all(|tx| tx.success)
            && outcome.withdrawals.as_ref().map(|w| w.commitment.count) == Some(n),
        "a benchmark withdrawal failed",
    )?;
    Ok(fixture)
}

fn bench_deposit(recipient: Address) -> DepositMint {
    DepositMint {
        recipient,
        provenance: DepositProvenance::BridgedBlch {
            l1_height: 1,
            l1_tx_index: 0,
            l1_txid: [0xd3; 32],
            l1_vout: 0,
            l1_sats: 100_000_000,
        },
    }
}

/// Minimal transition for initial zkVM/proof qualification before the contract fixture.
pub fn fixture_empty() -> Result<Fixture, Box<dyn Error>> {
    fixture_empty_with(&ChainSpec::testnet())
}

/// [`fixture_empty`] under the given execution rules.
pub fn fixture_empty_with(spec: &ChainSpec) -> Result<Fixture, Box<dyn Error>> {
    fixture_empty_in(spec, B256::repeat_byte(0xd3))
}

/// [`fixture_empty_with`] under the given V2 domain (the mainnet guest
/// compiles `MAINNET_DOMAIN`).
pub fn fixture_empty_in(spec: &ChainSpec, domain: B256) -> Result<Fixture, Box<dyn Error>> {
    let (fixture, _, outcome) = execute_fixture_in(spec, domain, NodeBodyV2::default(), B256::repeat_byte(8))?;
    ensure(
        outcome.transactions.is_empty() && outcome.receipts.is_empty(),
        "empty fixture has transactions",
    )?;
    Ok(fixture)
}

pub(crate) fn execute_fixture_at(
    body: NodeBodyV2,
    anchor_root: B256,
) -> Result<(Fixture, L2State, bloch_l2_evm::node_execution::NodeExecutionOutcome), Box<dyn Error>> {
    execute_fixture_with(&ChainSpec::testnet(), body, anchor_root)
}

pub(crate) fn execute_fixture_with(
    spec: &ChainSpec,
    body: NodeBodyV2,
    anchor_root: B256,
) -> Result<(Fixture, L2State, bloch_l2_evm::node_execution::NodeExecutionOutcome), Box<dyn Error>> {
    // A mainnet rule set runs under the domain its guest compiles.
    let domain = if spec.chain_id == bloch_l2_evm::chainspec::MAINNET_CHAIN_ID {
        bloch_l2_evm::chainspec::MAINNET_DOMAIN
    } else {
        B256::repeat_byte(0xd3)
    };
    execute_fixture_in(spec, domain, body, anchor_root)
}

pub(crate) fn execute_fixture_in(
    spec: &ChainSpec,
    domain: B256,
    body: NodeBodyV2,
    anchor_root: B256,
) -> Result<(Fixture, L2State, bloch_l2_evm::node_execution::NodeExecutionOutcome), Box<dyn Error>> {
    let mut pre_state = genesis_v2(spec, 0)?;
    let previous_state_root = pre_state.commit_root();
    let parent = node_head(spec, domain, &pre_state)?;
    // Fixtures anchor to native slot 1 (`l1_slot` of the synthetic contexts).
    let context = BlockContext {
        number: 1,
        timestamp: match spec.block_derivation {
            Some(rule) => rule.timestamp(parent.timestamp, 1).ok_or("timestamp overflow")?,
            None => 1,
        },
        base_fee_per_gas: spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
        prevrandao: B256::repeat_byte(7),
        anchor_root,
    };
    let (witness, recorded) = generate_node_batch_witness(&pre_state, spec, domain, &context, &body)?;
    ensure(
        pre_state.state_root() == previous_state_root,
        "witness generation mutated pre-state",
    )?;
    let mut state = pre_state.clone();
    let outcome = execute_node_block(spec, domain, &mut state, &context, &body)?;
    outcome.header.validate_parent(spec, &parent)?;
    outcome
        .header
        .validate_commitments(spec, domain, &body, &outcome.receipts)?;
    ensure(outcome.header == recorded.header, "host and witness headers differ")?;
    ensure(
        outcome.withdrawals == recorded.withdrawals,
        "host and witness withdrawals differ",
    )?;
    ensure(
        outcome.receipts == recorded.receipts,
        "host and witness receipts differ",
    )?;
    ensure(
        outcome.transactions.len() == recorded.transactions.len()
            && outcome
                .transactions
                .iter()
                .zip(&recorded.transactions)
                .all(|(actual, expected)| {
                    actual.success == expected.success
                        && actual.gas_used == expected.gas_used
                        && actual.created_address == expected.created_address
                        && actual.burned_wei == expected.burned_wei
                        && actual.result == expected.result
                }),
        "host and witness transaction outcomes differ",
    )?;
    ensure(
        state.commit_root() == outcome.header.state_root
            && witness.new_state_root == outcome.header.state_root
            && witness.prev_state_root == previous_state_root
            && outcome.header.parent_state_root == previous_state_root,
        "host and witness state roots differ",
    )?;
    // Derive expected values from the configured host execution, not guest output
    // or a deserialized statement supplied alongside a proof.
    let expected = ExecutionStatement {
        configuration: configuration_commitment(spec)?,
        domain,
        previous_state_root,
        header_hash: outcome.header.hash(),
    };
    Ok((
        Fixture {
            witness,
            context,
            body,
            expected,
            parent,
            header: outcome.header.clone(),
        },
        state,
        outcome,
    ))
}

fn sign(spec: &ChainSpec, key: &SigningKey, nonce: u64, to: TxKind, input: Bytes) -> Result<Bytes, Box<dyn Error>> {
    sign_with(spec, key, nonce, to, U256::ZERO, input, 200_000)
}

fn sign_with(
    spec: &ChainSpec,
    key: &SigningKey,
    nonce: u64,
    to: TxKind,
    value: U256,
    input: Bytes,
    gas_limit: u64,
) -> Result<Bytes, Box<dyn Error>> {
    let transaction = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to,
        value,
        input,
        gas_limit,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        ..Default::default()
    };
    let signature: Signature = key
        .sign_prehash_recoverable(transaction.signature_hash().as_slice())
        .map_err(|error| io::Error::other(error.to_string()))?
        .into();
    Ok(TxEnvelope::from(transaction.into_signed(signature))
        .encoded_2718()
        .into())
}

fn ensure(condition: bool, message: &'static str) -> Result<(), Box<dyn Error>> {
    if !condition {
        return Err(io::Error::other(message).into());
    }
    Ok(())
}
