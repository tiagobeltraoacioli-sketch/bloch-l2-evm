// SPDX-License-Identifier: MIT OR Apache-2.0
//! Review tool, execute-only, synthetic keys, no network (agent 137): what forced
//! inclusion costs the sparse guest at its bounds. The forced envelopes bypass the
//! sequencer's SP1-gas budget, so L1 caps them at 300k declared gas per settlement.
//!
//! usage: bloch-evm-sp1-forced-cost MODE --sparse ELF
//!   MODE transfers   14 forced transfers of 21k declared gas each (294k), plus one skipped
//!   MODE modexp      one forced call to the MODEXP precompile (512-byte base and modulus,
//!                    16-byte all-ones exponent) declared at 300k, plus one skipped
//!   MODE skipped     16 forced records that are all skipped (nonce gaps of funded senders)
//!
//! Builds the block under the next rules with forced inclusion, generates the sparse
//! witness, checks the native statement, executes the ELF and requires the same public
//! values. Prints one JSON line.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    chainspec::MAINNET_DOMAIN,
    forced_inclusion::{ForcedRecord, ForcedTransaction},
    node_execution::{execute_node_block, genesis_v2, node_head, select::{select_node_transactions_after_forced, SelectionLimits}},
    node_primitives::NodeBodyV2,
    proof_statement::SettlementContextV2,
    sparse_witness::{execute_settlement_statement_v3_sparse, generate_sparse_node_witness_forced, BlockHashes},
    BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State,
};
use k256::ecdsa::SigningKey;
use sp1_sdk::{Elf, LightProver, Prover, SP1Stdin};
use std::{error::Error, fs, io};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn key(seed: u8) -> Result<SigningKey> {
    SigningKey::from_bytes((&[seed; 32]).into()).map_err(|e| io::Error::other(e.to_string()).into())
}

fn sign(spec: &ChainSpec, key: &SigningKey, nonce: u64, to: Address, input: Bytes, gas_limit: u64) -> Result<Bytes> {
    let transaction = TxEip1559 {
        chain_id: spec.chain_id,
        nonce,
        to: TxKind::Call(to),
        value: U256::from(1u64),
        input,
        gas_limit,
        max_fee_per_gas: 2_000_000_000_000,
        max_priority_fee_per_gas: 0,
        ..Default::default()
    };
    let signature: Signature = key
        .sign_prehash_recoverable(transaction.signature_hash().as_slice())
        .map_err(|e| io::Error::other(e.to_string()))?
        .into();
    Ok(TxEnvelope::from(transaction.into_signed(signature)).encoded_2718().into())
}

fn record(index: u64, envelope: Bytes, declared: u64) -> ForcedTransaction {
    ForcedTransaction {
        record: ForcedRecord { l1_height: 100 + index, l1_txid: [index as u8; 32], envelope_hash: keccak256(&envelope), gas_limit: declared },
        envelope,
    }
}

fn context(spec: &ChainSpec, state: &L2State) -> Result<BlockContext> {
    let parent = node_head(spec, MAINNET_DOMAIN, state)?;
    let rule = spec.block_derivation.ok_or("next rules expected")?;
    Ok(BlockContext {
        number: parent.number + 1,
        timestamp: rule.timestamp(parent.timestamp, 1).ok_or("timestamp overflow")?,
        base_fee_per_gas: spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
        prevrandao: rule.prevrandao,
        anchor_root: B256::repeat_byte(8),
    })
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: bloch-evm-sp1-forced-cost transfers|modexp|skipped --sparse ELF";
    let mode = args.first().ok_or(usage)?.clone();
    let elf = args.iter().position(|a| a == "--sparse").and_then(|i| args.get(i + 1)).ok_or(usage)?.clone();
    let spec = ChainSpec::mainnet_next_or_rehearsal();
    if !spec.forced_inclusion {
        return Err("this build has no forced inclusion".into());
    }
    let mut state = genesis_v2(&spec, 0)?;
    state.commit_root();
    // Fund 16 senders with one deposit each, in one block.
    let keys: Vec<SigningKey> = (1..=16u8).map(key).collect::<Result<_>>()?;
    let deposits: Vec<DepositMint> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| DepositMint {
            recipient: Address::from_public_key(k.verifying_key()),
            provenance: DepositProvenance::BridgedBlch {
                l1_height: 1,
                l1_tx_index: i as u32,
                l1_txid: [0xd3; 32],
                l1_vout: 0,
                l1_sats: 100_000_000_000,
            },
        })
        .collect();
    let funding = NodeBodyV2 { deposits, transactions: vec![] };
    let ctx = context(&spec, &state)?;
    execute_node_block(&spec, MAINNET_DOMAIN, &mut state, &ctx, &funding)?;
    state.commit_root();

    let to = Address::repeat_byte(0x55);
    let mut forced = Vec::new();
    match mode.as_str() {
        "transfers" => {
            for (i, k) in keys.iter().take(14).enumerate() {
                forced.push(record(i as u64, sign(&spec, k, 0, to, Bytes::new(), 21_000)?, 21_000));
            }
            forced.push(record(14, sign(&spec, &keys[14], 9, to, Bytes::new(), 21_000)?, 21_000).clone());
            forced.truncate(14);
            // 14 x 21k is 294k; no room for a skipped one under the 300k cap.
        }
        "modexp" => {
            let (len_b, len_e, len_m) = (512usize, 16usize, 512usize);
            let mut input = Vec::new();
            for len in [len_b, len_e, len_m] {
                input.extend_from_slice(&U256::from(len).to_be_bytes::<32>());
            }
            input.extend(std::iter::repeat_n(0xab, len_b));
            input.extend(std::iter::repeat_n(0xff, len_e));
            let mut modulus = vec![0xcd; len_m];
            modulus[len_m - 1] = 0xcf;
            input.extend(modulus);
            forced.push(record(0, sign(&spec, &keys[0], 0, Address::with_last_byte(5), input.into(), 278_000)?, 279_000));
            forced.push(record(1, sign(&spec, &keys[1], 9, to, Bytes::new(), 21_000)?, 21_000));
        }
        "skipped" => {
            for (i, k) in keys.iter().enumerate() {
                forced.push(record(i as u64, sign(&spec, k, 7, to, Bytes::new(), 21_000)?, 21_000).clone());
            }
            forced.truncate(14);
        }
        _ => return Err(usage.into()),
    }
    let ctx = context(&spec, &state)?;
    let deposits: Vec<DepositMint> = vec![];
    let (selection, _) = select_node_transactions_after_forced(
        &spec, MAINNET_DOMAIN, state.db(), state.state_root(), &ctx, &deposits, &forced, &[], SelectionLimits::protocol(&spec),
    )?;
    let body = NodeBodyV2 { deposits, transactions: selection.included.clone() };
    let (witness, canonical) =
        generate_sparse_node_witness_forced(&state, &spec, MAINNET_DOMAIN, &ctx, &body, BlockHashes::Lazy, &forced)?;
    let settlement = SettlementContextV2 {
        network: B256::repeat_byte(0x41),
        genesis: B256::repeat_byte(0x42),
        program_elf_keccak: B256::repeat_byte(0x43),
        program_vkey_koalabear: B256::repeat_byte(0x44),
        program_vkey_bn254: B256::repeat_byte(0x45),
        previous_settlement: B256::repeat_byte(0x48),
        l1_slot: 1,
        l1_height: 1,
        source_commitment: B256::repeat_byte(0x46),
        inbox_root: B256::repeat_byte(0x47),
        inbox_count: 0,
        consumed_start: 0,
        consumed_end: 0,
    };
    let expected = execute_settlement_statement_v3_sparse(&spec, MAINNET_DOMAIN, &witness, &ctx, &body, settlement, BlockHashes::Lazy)?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);
    stdin.write(&ctx);
    stdin.write_vec(alloy_rlp::encode(&body));
    stdin.write(&settlement);
    let executor = LightProver::new().await;
    let (public, report) = executor.execute(Elf::from(fs::read(&elf)?), stdin).await?;
    if report.exit_code != 0 {
        return Err(format!("the honest block exited with code {}", report.exit_code).into());
    }
    expected.check_expected(public.as_slice())?;
    // Attacks on the ELF: the guest must refuse what the native path refuses.
    let run_attack = |w: &bloch_l2_evm::sparse_witness::SparseBatchWitness| {
        let mut stdin = SP1Stdin::new();
        stdin.write(w);
        stdin.write(&ctx);
        stdin.write_vec(alloy_rlp::encode(&body));
        stdin.write(&settlement);
        stdin
    };
    let mut attacks = Vec::new();
    // 1. Leave out the account of every forced sender, one at a time (skipped ones included).
    for f in &forced {
        let Ok(tx) = bloch_l2_evm::decode_signed_transaction(&spec, &f.envelope) else { continue };
        let sender = tx.sender();
        let mut changed = witness.clone();
        let before = changed.pre_accounts.len() + changed.absent_accounts.len();
        changed.pre_accounts.retain(|a| a.address != sender);
        changed.absent_accounts.retain(|a| *a != sender);
        if changed.pre_accounts.len() + changed.absent_accounts.len() == before {
            continue;
        }
        let native = execute_settlement_statement_v3_sparse(&spec, MAINNET_DOMAIN, &changed, &ctx, &body, settlement, BlockHashes::Lazy).is_err();
        let elf_refused = match executor.execute(Elf::from(fs::read(&elf)?), run_attack(&changed)).await {
            Err(_) => true,
            Ok((_, report)) => report.exit_code != 0,
        };
        attacks.push(format!("{{\"attack\":\"sender-omitted\",\"native_refused\":{native},\"elf_refused\":{elf_refused}}}"));
        if !native || !elf_refused {
            return Err(format!("a witness without forced sender {sender} was accepted: native refused {native}, ELF refused {elf_refused}").into());
        }
    }
    // 2. Drop the forced list: whatever executes, the statement must differ from the honest one.
    let mut dropped = witness.clone();
    dropped.forced.clear();
    let differs = match executor.execute(Elf::from(fs::read(&elf)?), run_attack(&dropped)).await {
        Err(_) => true,
        Ok((public, report)) => report.exit_code != 0 || expected.check_expected(public.as_slice()).is_err(),
    };
    attacks.push(format!("{{\"attack\":\"list-dropped\",\"statement_differs_or_refused\":{differs}}}"));
    if !differs {
        return Err("dropping the forced list kept the statement".into());
    }
    let declared: u64 = forced.iter().map(|f| f.record.gas_limit).sum();
    println!(
        "{{\"mode\":\"{mode}\",\"forced\":{},\"included\":{},\"skipped\":{},\"declared_gas\":{declared},\"l2_gas_used\":{},\"witness_bytes\":{},\"instructions\":{},\"sp1_gas\":{},\"user_tx_count\":{},\"public_values_match\":true,\"attacks\":[{}]}}",
        forced.len(),
        selection.included.len(),
        selection.skipped.len(),
        canonical.header.gas_used,
        bincode::serialized_size(&witness)?,
        report.total_instruction_count(),
        report.gas().map_or("null".to_string(), |g| g.to_string()),
        expected.user_tx_count,
        attacks.join(","),
    );
    Ok(())
}
