// SPDX-License-Identifier: MIT OR Apache-2.0
//! Execution-only cycle benchmark of the CANDIDATE sparse settlement guest, against
//! the complete-witness guest on the same block. No proof, no network, synthetic keys.
//!
//! usage: bloch-evm-sp1-sparse-bench RULES HEIGHT SLOTS READS UPDATES INSERTS
//!            [--complete ELF] [--sparse ELF] [--eager ELF] [--tamper omit-read|omit-exclusion|forge-leaf]
//!
//! RULES is `mainnet` or `mainnet-v1`. HEIGHT is the number of empty blocks before
//! the measured block (the EIP-4788 ring grows 2 slots per block to 16,380). SLOTS is
//! the storage of a contract filled by real transactions. READS, UPDATES and INSERTS
//! are distinct slots the measured block reads, rewrites and creates. Slot numbers are
//! consecutive, and the trie key is keccak256(slot), so they spread over the trie. All
//! zero with SLOTS 0 is an empty block.
//!
//! Each ELF runs in the SP1 executor. The committed statement is checked byte for
//! byte against the host's complete-witness execution. Prints one JSON line per ELF.
//! With --tamper the sparse witness is altered and the guest must fail: the line
//! says whether it did.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use bloch_l2_evm::{
    chainspec::MAINNET_DOMAIN,
    node_execution::{execute_node_block, generate_node_batch_witness, genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2, SettlementStatementV3},
    sparse_witness::{
        deploy_code, execute_settlement_statement_v3_sparse, forged_storage_leaf, generate_sparse_node_witness, slot_trie_key,
        storage_ops_runtime, BlockHashes, SparseBatchWitness,
    },
    BlockContext, ChainSpec, DepositMint, DepositProvenance, L2State,
};
use k256::ecdsa::SigningKey;
use sp1_sdk::{Elf, LightProver, Prover, SP1Stdin};
use std::{error::Error, fs, io, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct Chain {
    spec: ChainSpec,
    state: L2State,
    key: SigningKey,
    sender: Address,
    nonce: u64,
    deposits: u64,
}

fn ops(op: u64, start: u64, count: u64) -> Bytes {
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(&U256::from(op).to_be_bytes::<32>());
    data.extend_from_slice(&U256::from(start).to_be_bytes::<32>());
    data.extend_from_slice(&U256::from(count).to_be_bytes::<32>());
    data.into()
}

impl Chain {
    fn new(spec: ChainSpec) -> Result<Self> {
        let mut state = genesis_v2(&spec, 0)?;
        state.commit_root();
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).map_err(|e| io::Error::other(e.to_string()))?;
        let sender = Address::from_public_key(key.verifying_key());
        Ok(Self {
            spec,
            state,
            key,
            sender,
            nonce: 0,
            deposits: 0,
        })
    }

    fn deposit(&mut self) -> DepositMint {
        self.deposits += 1;
        DepositMint {
            recipient: self.sender,
            provenance: DepositProvenance::BridgedBlch {
                l1_height: self.deposits,
                l1_tx_index: 0,
                l1_txid: [0xd3; 32],
                l1_vout: 0,
                l1_sats: 100_000_000_000,
            },
        }
    }

    fn tx(&mut self, to: TxKind, input: Bytes, gas_limit: u64) -> Result<Bytes> {
        let transaction = TxEip1559 {
            chain_id: self.spec.chain_id,
            nonce: self.nonce,
            to,
            input,
            gas_limit,
            max_fee_per_gas: 2_000_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
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

    fn commit(&mut self, body: &NodeBodyV2) -> Result<bool> {
        let context = self.context()?;
        let outcome = execute_node_block(&self.spec, MAINNET_DOMAIN, &mut self.state, &context, body)?;
        self.state.commit_root();
        Ok(outcome.transactions.iter().all(|tx| tx.success))
    }
}

fn peak_rss_bytes() -> u64 {
    // SAFETY: getrusage writes only into the provided, zero-initialised struct.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let max = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        max
    } else {
        max * 1024
    }
}

fn settlement(body: &NodeBodyV2) -> SettlementContextV2 {
    SettlementContextV2 {
        network: B256::repeat_byte(0x41),
        genesis: B256::repeat_byte(0x42),
        program_elf_keccak: B256::repeat_byte(0x43),
        program_vkey_koalabear: B256::repeat_byte(0x44),
        program_vkey_bn254: B256::repeat_byte(0x45),
        previous_settlement: B256::ZERO,
        l1_slot: 1,
        l1_height: 1,
        source_commitment: B256::repeat_byte(0x46),
        inbox_root: B256::repeat_byte(0x47),
        inbox_count: body.deposits.len() as u64,
        consumed_start: 0,
        consumed_end: body.deposits.len() as u64,
    }
}

struct Run {
    cycles: u64,
    syscalls: u64,
    gas: String,
    seconds: f64,
    failed: Option<String>,
}

async fn execute(
    executor: &LightProver,
    elf: &str,
    stdin: SP1Stdin,
    expected: &SettlementStatementV3,
) -> Result<Run> {
    let elf = Elf::from(fs::read(elf)?);
    let started = Instant::now();
    let executed = executor.execute(elf, stdin).await;
    let seconds = started.elapsed().as_secs_f64();
    let (public, report) = match executed {
        Ok(result) => result,
        Err(error) => {
            return Ok(Run {
                cycles: 0,
                syscalls: 0,
                gas: "null".into(),
                seconds,
                failed: Some(error.to_string()),
            })
        }
    };
    if report.exit_code != 0 {
        return Ok(Run {
            cycles: report.total_instruction_count(),
            syscalls: report.total_syscall_count(),
            gas: "null".into(),
            seconds,
            failed: Some(format!("exit code {}", report.exit_code)),
        });
    }
    expected.check_expected(public.as_slice())?;
    Ok(Run {
        cycles: report.total_instruction_count(),
        syscalls: report.total_syscall_count(),
        gas: report.gas().map_or("null".to_string(), |g| g.to_string()),
        seconds,
        failed: None,
    })
}

/// The deepest node on the path of `slot` in the contract's proof: its removal must
/// make the read an error.
fn omit_slot(witness: &mut SparseBatchWitness, contract: Address, slot: u64) -> Result<()> {
    let key = slot_trie_key(slot);
    let account = witness
        .pre_accounts
        .iter_mut()
        .find(|account| account.address == contract)
        .ok_or("contract is not in the witness")?;
    let deepest = account
        .storage_proof
        .keys()
        .filter(|path| key.starts_with(path))
        .max_by_key(|path| path.len())
        .copied()
        .ok_or("slot is not covered")?;
    account.storage_proof.remove(&deepest);
    Ok(())
}

fn forge_leaf(witness: &mut SparseBatchWitness, contract: Address, slot: u64) -> Result<()> {
    let key = slot_trie_key(slot);
    let account = witness
        .pre_accounts
        .iter_mut()
        .find(|account| account.address == contract)
        .ok_or("contract is not in the witness")?;
    let deepest = account
        .storage_proof
        .keys()
        .filter(|path| key.starts_with(path))
        .max_by_key(|path| path.len())
        .copied()
        .ok_or("slot is not covered")?;
    let rest = key.slice(deepest.len()..);
    account
        .storage_proof
        .insert(deepest, forged_storage_leaf(rest, U256::from(777_777u64)));
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: bloch-evm-sp1-sparse-bench RULES HEIGHT SLOTS READS UPDATES INSERTS [--complete ELF] [--sparse ELF] [--eager ELF] [--tamper omit-read|omit-exclusion|forge-leaf]";
    if args.len() < 6 {
        return Err(usage.into());
    }
    let spec = match args[0].as_str() {
        "mainnet" => ChainSpec::mainnet(),
        "mainnet-v1" => ChainSpec::mainnet_v1(),
        _ => return Err(usage.into()),
    };
    let height: u64 = args[1].parse().map_err(|_| usage)?;
    let slots: u64 = args[2].parse().map_err(|_| usage)?;
    let reads: u64 = args[3].parse().map_err(|_| usage)?;
    let updates: u64 = args[4].parse().map_err(|_| usage)?;
    let inserts: u64 = args[5].parse().map_err(|_| usage)?;
    let mut complete_elf = None;
    let mut sparse_elf = None;
    let mut eager_elf = None;
    let mut tamper = None;
    let mut rest = args[6..].iter();
    while let Some(flag) = rest.next() {
        let value = rest.next().ok_or(usage)?.clone();
        match flag.as_str() {
            "--complete" => complete_elf = Some(value),
            "--sparse" => sparse_elf = Some(value),
            "--eager" => eager_elf = Some(value),
            "--tamper" => tamper = Some(value),
            _ => return Err(usage.into()),
        }
    }

    let mut chain = Chain::new(spec.clone())?;
    let domain = MAINNET_DOMAIN;
    let setup_started = Instant::now();

    // Empty blocks first, so the ring has the height's size.
    for _ in 0..height {
        chain.commit(&NodeBodyV2::default())?;
    }

    // Fill the contract with real transactions, at the gas target so the base fee
    // does not climb. Fresh-slot SSTORE costs 22,100 gas.
    let mut contract = Address::ZERO;
    if slots > 0 || reads + updates + inserts > 0 {
        contract = chain.sender.create(0);
        let runtime = storage_ops_runtime();
        let deposit = chain.deposit();
        let deploy = chain.tx(TxKind::Create, deploy_code(&runtime).into(), 2_000_000)?;
        let body = NodeBodyV2 {
            deposits: vec![deposit],
            transactions: vec![deploy],
        };
        if !chain.commit(&body)? {
            return Err("deployment failed".into());
        }
        let per_block = spec.gas_limit / spec.base_fee_elasticity / 22_400;
        let mut start = 0;
        while start < slots {
            let count = per_block.min(slots - start);
            let deposit = chain.deposit();
            let fill = chain.tx(TxKind::Call(contract), ops(0, start, count), spec.gas_limit / 2)?;
            let body = NodeBodyV2 {
                deposits: vec![deposit],
                transactions: vec![fill],
            };
            if !chain.commit(&body)? {
                return Err("fill failed".into());
            }
            start += count;
        }
    }
    let setup_seconds = setup_started.elapsed().as_secs_f64();

    // The measured block.
    let mut transactions = Vec::new();
    if reads > 0 {
        transactions.push(chain.tx(TxKind::Call(contract), ops(1, 0, reads), spec.gas_limit / 2)?);
    }
    if updates > 0 {
        let start = slots.saturating_sub(updates);
        transactions.push(chain.tx(TxKind::Call(contract), ops(2, start, updates), spec.gas_limit / 2)?);
    }
    if inserts > 0 {
        transactions.push(chain.tx(TxKind::Call(contract), ops(0, slots + 1_000_000, inserts), spec.gas_limit / 2)?);
    }
    let body = if transactions.is_empty() {
        NodeBodyV2::default()
    } else {
        NodeBodyV2 {
            deposits: vec![chain.deposit()],
            transactions,
        }
    };
    let context = chain.context()?;
    let settlement = settlement(&body);

    let generate_started = Instant::now();
    let (complete, canonical) = generate_node_batch_witness(&chain.state, &spec, domain, &context, &body)?;
    let complete_seconds = generate_started.elapsed().as_secs_f64();
    if !canonical.transactions.iter().all(|tx| tx.success) {
        return Err("a measured transaction failed".into());
    }
    let expected = execute_settlement_statement_v3(&spec, domain, &complete, &context, &body, settlement)?;
    let encoded_body = alloy_rlp::encode(&body);
    let executor = LightProver::new().await;

    let emit = |name: &str, witness_bytes: u64, generate_seconds: f64, run: &Run, extra: String| {
        println!(
            "{{\"guest\":\"{name}\",\"rules\":\"{}\",\"height\":{height},\"slots\":{slots},\"reads\":{reads},\"updates\":{updates},\"inserts\":{inserts},\"block_gas\":{},\"witness_bytes\":{witness_bytes},\"cycles\":{},\"syscalls\":{},\"sp1_gas\":{},\"execute_seconds\":{:.2},\"generate_seconds\":{generate_seconds:.3},\"setup_seconds\":{setup_seconds:.1},\"peak_rss_bytes\":{},\"failed\":{}{extra}}}",
            args[0],
            canonical.header.gas_used,
            run.cycles,
            run.syscalls,
            run.gas,
            run.seconds,
            peak_rss_bytes(),
            run.failed.as_ref().map_or("null".to_string(), |text| format!("{:?}", text.chars().take(300).collect::<String>())),
        );
    };

    if let Some(elf) = &complete_elf {
        let mut stdin = SP1Stdin::new();
        stdin.write(&complete);
        stdin.write(&context);
        stdin.write_vec(encoded_body.clone());
        stdin.write(&settlement);
        let run = execute(&executor, elf, stdin, &expected).await?;
        emit("complete", bincode::serialized_size(&complete)?, complete_seconds, &run, String::new());
    }

    for (name, elf, mode) in [
        ("sparse-lazy", &sparse_elf, BlockHashes::Lazy),
        ("sparse-eager", &eager_elf, BlockHashes::Eager),
    ] {
        let Some(elf) = elf else { continue };
        let started = Instant::now();
        let (mut witness, _) = generate_sparse_node_witness(&chain.state, &spec, domain, &context, &body, mode)?;
        let generate_seconds = started.elapsed().as_secs_f64();
        let size = witness.size();
        let native = execute_settlement_statement_v3_sparse(&spec, domain, &witness, &context, &body, settlement, mode)?;
        if native.encode() != expected.encode() {
            return Err("the sparse statement differs from the complete statement natively".into());
        }
        let mut tampered = "null".to_string();
        if let Some(kind) = &tamper {
            match kind.as_str() {
                "omit-read" => omit_slot(&mut witness, contract, 0)?,
                "omit-exclusion" => omit_slot(&mut witness, contract, slots + 1_000_000)?,
                "forge-leaf" => forge_leaf(&mut witness, contract, 0)?,
                _ => return Err(usage.into()),
            }
            let native = execute_settlement_statement_v3_sparse(&spec, domain, &witness, &context, &body, settlement, mode);
            tampered = format!("{:?}", format!("{kind}: native rejected: {}", native.is_err()));
        }
        let mut stdin = SP1Stdin::new();
        stdin.write(&witness);
        stdin.write(&context);
        stdin.write_vec(encoded_body.clone());
        stdin.write(&settlement);
        let run = execute(&executor, elf, stdin, &expected).await?;
        emit(
            name,
            bincode::serialized_size(&witness)?,
            generate_seconds,
            &run,
            format!(
                ",\"accounts\":{},\"account_nodes\":{},\"storage_nodes\":{},\"node_bytes\":{},\"tampered\":{tampered}",
                size.accounts, size.account_nodes, size.storage_nodes, size.node_bytes
            ),
        );
    }
    Ok(())
}
