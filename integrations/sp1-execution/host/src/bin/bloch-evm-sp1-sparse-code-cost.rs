// SPDX-License-Identifier: MIT OR Apache-2.0
//! Review tool, execute-only, synthetic keys, no network: what a forced deposit still
//! costs the sparse guest. The witness carries the whole code of every touched account,
//! and hydration analyses and hashes it, whether or not the code runs.
//!
//! usage: bloch-evm-sp1-sparse-code-cost RULES CONTRACTS CODE_BYTES DEPOSITS --sparse ELF [--complete ELF]
//!
//! Deploys CONTRACTS contracts of CODE_BYTES zero bytes at 15M gas per block (the
//! settler's cap), then builds one deposit-only block with DEPOSITS deposits, one per
//! contract while they last, then to fresh addresses. Prints one JSON line per ELF.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    chainspec::MAINNET_DOMAIN,
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2},
    sparse_witness::{generate_sparse_node_witness, BlockHashes},
    BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State,
};
use k256::ecdsa::SigningKey;
use sp1_sdk::{Elf, LightProver, Prover, SP1Stdin};
use std::{error::Error, fs, io};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct Chain {
    spec: ChainSpec,
    state: L2State,
    key: SigningKey,
    sender: Address,
    nonce: u64,
    deposits: u64,
}

impl Chain {
    fn deposit(&mut self, recipient: Address, sats: u64) -> DepositMint {
        self.deposits += 1;
        DepositMint {
            recipient,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: self.deposits,
                l1_tx_index: 0,
                l1_txid: [0xd3; 32],
                l1_vout: 0,
                l1_sats: sats,
            },
        }
    }
    fn create(&mut self, initcode: Bytes, gas_limit: u64) -> Result<Bytes> {
        let transaction = TxEip1559 {
            chain_id: self.spec.chain_id,
            nonce: self.nonce,
            to: TxKind::Create,
            input: initcode,
            gas_limit,
            max_fee_per_gas: 2_000_000_000_000,
            max_priority_fee_per_gas: 0,
            ..Default::default()
        };
        self.nonce += 1;
        let signature: Signature = self
            .key
            .sign_prehash_recoverable(transaction.signature_hash().as_slice())
            .map_err(|e| io::Error::other(e.to_string()))?
            .into();
        Ok(TxEnvelope::from(transaction.into_signed(signature)).encoded_2718().into())
    }
    fn context(&self) -> Result<BlockContext> {
        let parent = node_head(&self.spec, MAINNET_DOMAIN, &self.state)?;
        let (timestamp, prevrandao) = match self.spec.block_derivation {
            Some(rule) => (rule.timestamp(parent.timestamp, 1).ok_or("timestamp overflow")?, rule.prevrandao),
            None => (parent.timestamp + 1, B256::repeat_byte(7)),
        };
        Ok(BlockContext {
            number: parent.number + 1,
            timestamp,
            base_fee_per_gas: self.spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
            prevrandao,
            anchor_root: B256::repeat_byte(8),
        })
    }
    fn commit(&mut self, body: &NodeBodyV2) -> Result<u64> {
        let context = self.context()?;
        let outcome = execute_node_block(&self.spec, MAINNET_DOMAIN, &mut self.state, &context, body)?;
        self.state.commit_root();
        if !outcome.transactions.iter().all(|tx| tx.success) {
            return Err("a deployment failed".into());
        }
        Ok(outcome.header.gas_used)
    }
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: bloch-evm-sp1-sparse-code-cost RULES CONTRACTS CODE_BYTES DEPOSITS --sparse ELF [--complete ELF]";
    if args.len() < 6 {
        return Err(usage.into());
    }
    let spec = match args[0].as_str() {
        "mainnet" => ChainSpec::mainnet(),
        "mainnet-v1" => ChainSpec::mainnet_v1(),
        _ => return Err(usage.into()),
    };
    let contracts: u64 = args[1].parse()?;
    let code_bytes: usize = args[2].parse()?;
    let deposits: u64 = args[3].parse()?;
    let elf_of = |name: &str| args.iter().position(|arg| arg == name).and_then(|i| args.get(i + 1)).cloned();

    let mut state = genesis_v2(&spec, 0)?;
    state.commit_root();
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).map_err(|e| io::Error::other(e.to_string()))?;
    let sender = Address::from_public_key(key.verifying_key());
    let mut chain = Chain { spec: spec.clone(), state, key, sender, nonce: 0, deposits: 0 };

    // PUSH2 size PUSH1 0 RETURN: a runtime of zero bytes.
    let initcode: Bytes = vec![0x61, (code_bytes >> 8) as u8, code_bytes as u8, 0x60, 0x00, 0xf3].into();
    let gas_each = 60_000 + 200 * code_bytes as u64 + 40_000;
    let per_block = (15_000_000 / gas_each).max(1);
    let mut addresses = Vec::new();
    let mut funded = 0u64;
    let mut blocks = 0u64;
    let mut gas_total = 0u64;
    let mut deployed = 0u64;
    while deployed < contracts {
        let mut transactions = Vec::new();
        for _ in 0..per_block.min(contracts - deployed) {
            addresses.push(sender.create(chain.nonce));
            transactions.push(chain.create(initcode.clone(), gas_each)?);
            deployed += 1;
        }
        let deposit = chain.deposit(sender, 100_000_000_000);
        funded += 100_000_000_000;
        let body = NodeBodyV2 { deposits: vec![deposit], transactions };
        gas_total += chain.commit(&body)?;
        blocks += 1;
    }
    let balance = chain.state.balance_of(&sender);
    let funded_wei = U256::from(funded) * U256::from(10_000_000_000u64);
    let fee_wei = funded_wei.saturating_sub(balance);

    let mut list = Vec::new();
    for index in 0..deposits {
        let recipient = match addresses.get(index as usize) {
            Some(address) => *address,
            None => {
                let mut raw = [0x5a; 20];
                raw[12..].copy_from_slice(&index.to_be_bytes());
                Address::from(raw)
            }
        };
        list.push(chain.deposit(recipient, 1_000_000));
    }
    let body = NodeBodyV2 { deposits: list, transactions: vec![] };
    let context = chain.context()?;
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
        inbox_count: deposits,
        consumed_start: 0,
        consumed_end: deposits,
    };
    let domain = MAINNET_DOMAIN;
    let (complete, _) = generate_node_batch_witness(&chain.state, &spec, domain, &context, &body)?;
    let expected = execute_settlement_statement_v3(&spec, domain, &complete, &context, &body, settlement)?;
    let (witness, _) = generate_sparse_node_witness(&chain.state, &spec, domain, &context, &body, BlockHashes::Lazy)?;
    let encoded_body = alloy_rlp::encode(&body);
    let executor = LightProver::new().await;
    let mut run = |name: &'static str, elf: String, stdin: SP1Stdin, bytes: u64| {
        let executor = &executor;
        let expected = &expected;
        let (contracts, code_bytes, deposits, fee_wei) = (contracts, code_bytes, deposits, fee_wei);
        async move {
            let (public, report) = executor.execute(Elf::from(fs::read(elf)?), stdin).await?;
            expected.check_expected(public.as_slice())?;
            println!(
                "{{\"guest\":\"{name}\",\"contracts\":{contracts},\"code_bytes\":{code_bytes},\"deposits\":{deposits},\"witness_bytes\":{bytes},\"instructions\":{},\"sp1_gas\":{},\"setup_blocks\":{blocks},\"setup_gas\":{gas_total},\"setup_fee_wei\":\"{fee_wei}\"}}",
                report.total_instruction_count(),
                report.gas().map_or("null".to_string(), |g| g.to_string()),
            );
            Result::Ok(())
        }
    };
    if let Some(elf) = elf_of("--complete") {
        let mut stdin = SP1Stdin::new();
        stdin.write(&complete);
        stdin.write(&context);
        stdin.write_vec(encoded_body.clone());
        stdin.write(&settlement);
        run("complete", elf, stdin, bincode::serialized_size(&complete)?).await?;
    }
    if let Some(elf) = elf_of("--sparse") {
        let mut stdin = SP1Stdin::new();
        stdin.write(&witness);
        stdin.write(&context);
        stdin.write_vec(encoded_body.clone());
        stdin.write(&settlement);
        run("sparse", elf, stdin, bincode::serialized_size(&witness)?).await?;
    }
    Ok(())
}
