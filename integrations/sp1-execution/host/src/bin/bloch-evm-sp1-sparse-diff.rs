// SPDX-License-Identifier: MIT OR Apache-2.0
//! Review tool, no proof, no network: replay the settler's stored block artifacts of a
//! real private chain from genesis, and compare for each block the pinned complete-witness
//! path with the candidate sparse path: native statements, the guests' public values
//! in the SP1 executor, and, when the settler kept one, the public values of the
//! real proof.
//!
//! usage: bloch-evm-sp1-sparse-diff WORK_DIR ELF_DIR [--no-elf] [--from N] [--to N]
//!
//! WORK_DIR holds `<height>-<hash>/block.artifact`, as the settler leaves them.
//! ELF_DIR holds `complete_v1`, `complete_next`, `settlement_v3_mainnet_v1_sparse` and
//! `settlement_v3_mainnet_sparse`. Prints one JSON line per block and a summary. Any
//! difference is printed with `"differ"` and counted; the exit code is then 1.

use alloy_primitives::{B256, U256};
use bloch_execution_artifact::ExecutionArtifact;
use bloch_l2_evm::{
    chainspec::MAINNET_DOMAIN,
    node_execution::{execute_node_block, genesis_v2, node_head},
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2, SettlementStatementV3},
    sparse_witness::{
        execute_settlement_statement_v3_sparse, generate_sparse_node_witness, verify_node_batch_sparse, BlockHashes,
        SparseBatchWitness,
    },
    ChainSpec, L2State,
};
use sp1_sdk::{Elf, LightProver, Prover, SP1ProofWithPublicValues, SP1Stdin};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct Stored {
    dir: PathBuf,
    artifact: ExecutionArtifact,
    spec: ChainSpec,
    domain: B256,
}

fn load(dir: &Path) -> Result<Stored> {
    let bytes = fs::read(dir.join("block.artifact"))?;
    let mut last = None;
    for (spec, domain) in [
        (ChainSpec::mainnet_v1(), MAINNET_DOMAIN),
        (ChainSpec::mainnet(), MAINNET_DOMAIN),
        (ChainSpec::testnet_v3(), B256::repeat_byte(0xd3)),
    ] {
        match ExecutionArtifact::decode(&bytes, &spec, domain) {
            Ok(artifact) => {
                return Ok(Stored {
                    dir: dir.to_path_buf(),
                    artifact,
                    spec,
                    domain,
                })
            }
            Err(error) => last = Some(error),
        }
    }
    Err(format!("{}: {}", dir.display(), last.unwrap()).into())
}

/// The settlement context of the real block: from the settler's native request, and
/// the program identity from the real proof when one is kept.
fn settlement(stored: &Stored, real: Option<&SettlementStatementV3>) -> Result<(SettlementContextV2, bool)> {
    let body = stored.artifact.body();
    let mut context = SettlementContextV2 {
        network: B256::repeat_byte(0x41),
        genesis: B256::repeat_byte(0x42),
        program_elf_keccak: B256::repeat_byte(0x43),
        program_vkey_koalabear: B256::repeat_byte(0x44),
        program_vkey_bn254: B256::repeat_byte(0x45),
        previous_settlement: if stored.artifact.header().number == 1 { B256::ZERO } else { B256::repeat_byte(0x48) },
        l1_slot: 1,
        l1_height: 1,
        source_commitment: B256::repeat_byte(0x46),
        inbox_root: B256::repeat_byte(0x47),
        inbox_count: body.deposits.len() as u64,
        consumed_start: 0,
        consumed_end: body.deposits.len() as u64,
    };
    let mut from_request = false;
    if let Ok(text) = fs::read_to_string(stored.dir.join("native-request.txt")) {
        let fields: Vec<&str> = text.lines().collect();
        if fields.len() == 8 || fields.len() == 11 {
            context.network = fields[0].parse()?;
            context.genesis = fields[1].parse()?;
            context.l1_slot = fields[3].parse()?;
            context.l1_height = fields[4].parse()?;
            context.source_commitment = fields[5].parse()?;
            context.inbox_root = fields[6].parse()?;
            context.previous_settlement = fields[7].parse()?;
            if fields.len() == 11 {
                context.inbox_count = fields[8].parse()?;
                context.consumed_start = fields[9].parse()?;
                context.consumed_end = fields[10].parse()?;
            } else {
                context.inbox_count = 0;
                context.consumed_start = 0;
                context.consumed_end = 0;
            }
            from_request = true;
        }
    }
    if let Some(real) = real {
        context.program_elf_keccak = real.base.program_elf_keccak;
        context.program_vkey_koalabear = real.base.program_vkey_koalabear;
        context.program_vkey_bn254 = real.base.program_vkey_bn254;
    }
    Ok((context, from_request))
}

fn real_statement(dir: &Path) -> Option<(Vec<u8>, SettlementStatementV3)> {
    let proof = SP1ProofWithPublicValues::load(dir.join("settlement.proof")).ok()?;
    let bytes = proof.public_values.as_slice().to_vec();
    let statement = SettlementStatementV3::decode(&bytes).ok()?;
    Some((bytes, statement))
}

async fn run_elf(executor: &LightProver, elf: &Path, stdin: SP1Stdin) -> Result<(Vec<u8>, u64, u64)> {
    let (public, report) = executor.execute(Elf::from(fs::read(elf)?), stdin).await?;
    if report.exit_code != 0 {
        return Err(format!("guest exit code {}", report.exit_code).into());
    }
    Ok((public.as_slice().to_vec(), report.total_instruction_count(), report.gas().unwrap_or(0)))
}

fn sparse_stdin(witness: &SparseBatchWitness, stored: &Stored, settlement: &SettlementContextV2) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(witness);
    stdin.write(stored.artifact.context());
    stdin.write_vec(alloy_rlp::encode(stored.artifact.body()));
    stdin.write(settlement);
    stdin
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        return Err("usage: bloch-evm-sp1-sparse-diff WORK_DIR ELF_DIR [--no-elf] [--from N] [--to N]".into());
    }
    let (work, elf_dir) = (PathBuf::from(&args[0]), PathBuf::from(&args[1]));
    let use_elf = !args.iter().any(|arg| arg == "--no-elf");
    let flag = |name: &str| -> Option<u64> {
        args.iter()
            .position(|arg| arg == name)
            .and_then(|index| args.get(index + 1))
            .and_then(|value| value.parse().ok())
    };
    let (from, to) = (flag("--from").unwrap_or(0), flag("--to").unwrap_or(u64::MAX));

    let mut by_height: BTreeMap<u64, Vec<PathBuf>> = BTreeMap::new();
    for entry in fs::read_dir(&work)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else { continue };
        let Some(height) = name.split('-').next().and_then(|height| height.parse::<u64>().ok()) else { continue };
        if path.join("block.artifact").is_file() {
            by_height.entry(height).or_default().push(path);
        }
    }
    let first = *by_height.keys().next().ok_or("no artifacts")?;
    if first != 1 {
        return Err(format!("the chain must start at block 1, the first artifact is {first}").into());
    }

    let executor = LightProver::new().await;
    let mut state: Option<L2State> = None;
    let mut parent_hash: Option<B256> = None;
    let (mut blocks, mut differ, mut user_txs, mut with_real, mut matched_real, mut with_request) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut withdrawals, mut deposits, mut failed_txs, mut elf_runs, mut tampered, mut tamper_survived) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut height = 1u64;
    let mut seed = alloy_primitives::keccak256(b"sparse-diff");
    loop {
        if height > to {
            break;
        }
        let Some(candidates) = by_height.get(&height) else { break };
        let mut chosen = None;
        for dir in candidates {
            let stored = load(dir)?;
            if parent_hash.is_none() || parent_hash == Some(stored.artifact.header().parent_hash) {
                chosen = Some(stored);
                break;
            }
        }
        let Some(stored) = chosen else {
            println!("{{\"stop\":\"no artifact at height {height} continues the chain\"}}");
            break;
        };
        let (spec, domain) = (stored.spec.clone(), stored.domain);
        let parent = stored.artifact.parent().clone();
        let mut current = match state.take() {
            Some(current) => current,
            None => {
                let mut genesis = genesis_v2(&spec, parent.timestamp)?;
                genesis.commit_root();
                genesis
            }
        };
        if node_head(&spec, domain, &current)? != parent {
            return Err(format!("block {height}: the replayed head is not the artifact's parent").into());
        }
        let context = stored.artifact.context().clone();
        let body = stored.artifact.body().clone();
        let header = stored.artifact.header().clone();
        let complete = stored.artifact.witness().clone();
        let mut problems: Vec<String> = Vec::new();

        if height >= from {
            let real = real_statement(&stored.dir);
            let (settlement_context, from_request) = settlement(&stored, real.as_ref().map(|(_, statement)| statement))?;
            with_request += u64::from(from_request);
            let expected = match execute_settlement_statement_v3(&spec, domain, &complete, &context, &body, settlement_context) {
                Ok(statement) => Some(statement),
                Err(error) => {
                    problems.push(format!("complete statement: {error:?}"));
                    None
                }
            };
            let mut size_lazy = None;
            let mut cycles = (0u64, 0u64, 0u64, 0u64);
            for mode in [BlockHashes::Lazy, BlockHashes::Eager] {
                match generate_sparse_node_witness(&current, &spec, domain, &context, &body, mode) {
                    Err(error) => problems.push(format!("sparse generation {mode:?}: {error}")),
                    Ok((witness, canonical)) => {
                        if canonical.header != header {
                            problems.push(format!("canonical header differs from the artifact, {mode:?}"));
                        }
                        match execute_settlement_statement_v3_sparse(&spec, domain, &witness, &context, &body, settlement_context, mode) {
                            Err(error) => problems.push(format!("sparse statement {mode:?}: {error}")),
                            Ok(statement) => {
                                if let Some(expected) = &expected {
                                    if statement.encode() != expected.encode() {
                                        problems.push(format!("sparse statement differs from complete, {mode:?}"));
                                    }
                                }
                                if let Some((bytes, _)) = &real {
                                    if statement.encode().as_slice() != bytes.as_slice() {
                                        problems.push(format!("sparse statement differs from the real proof, {mode:?}"));
                                    }
                                }
                            }
                        }
                        if mode == BlockHashes::Lazy {
                            size_lazy = Some(bincode::serialized_size(&witness)?);
                            // One real attack per block: remove one storage or account node.
                            seed = alloy_primitives::keccak256(seed);
                            let pick = u64::from_be_bytes(seed[..8].try_into()?);
                            let mut changed = witness.clone();
                            let accounts = changed.pre_accounts.len() as u64;
                            let account = &mut changed.pre_accounts[(pick % accounts.max(1)) as usize];
                            let keys: Vec<_> = account.storage_proof.keys().copied().collect();
                            if !keys.is_empty() {
                                let key = keys[((pick >> 16) % keys.len() as u64) as usize];
                                account.storage_proof.remove(&key);
                                tampered += 1;
                                if let Ok(outcome) = verify_node_batch_sparse(&spec, domain, &changed, &context, &body, mode) {
                                    tamper_survived += 1;
                                    if outcome.header != header {
                                        problems.push("a tampered witness gave another header".into());
                                    }
                                }
                            }
                            if use_elf {
                                let (complete_elf, sparse_elf) = if spec == ChainSpec::mainnet_v1() {
                                    ("complete_v1", "settlement_v3_mainnet_v1_sparse")
                                } else if spec == ChainSpec::mainnet() {
                                    ("complete_next", "settlement_v3_mainnet_sparse")
                                } else {
                                    ("", "")
                                };
                                if !complete_elf.is_empty() {
                                    let mut stdin = SP1Stdin::new();
                                    stdin.write(&complete);
                                    stdin.write(&context);
                                    stdin.write_vec(alloy_rlp::encode(&body));
                                    stdin.write(&settlement_context);
                                    match (
                                        run_elf(&executor, &elf_dir.join(complete_elf), stdin).await,
                                        run_elf(&executor, &elf_dir.join(sparse_elf), sparse_stdin(&witness, &stored, &settlement_context)).await,
                                    ) {
                                        (Ok(a), Ok(b)) => {
                                            elf_runs += 1;
                                            cycles = (a.1, b.1, a.2, b.2);
                                            if a.0 != b.0 {
                                                problems.push("the guests committed different public values".into());
                                            }
                                            if let Some((bytes, _)) = &real {
                                                if a.0 != *bytes {
                                                    problems.push("the complete guest differs from the real proof".into());
                                                }
                                            }
                                        }
                                        (a, b) => problems.push(format!(
                                            "guest failure: complete {:?} sparse {:?}",
                                            a.err().map(|error| error.to_string()),
                                            b.err().map(|error| error.to_string())
                                        )),
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if real.is_some() {
                with_real += 1;
                if !problems.iter().any(|text| text.contains("real proof")) {
                    matched_real += 1;
                }
            }
            println!(
                "{{\"height\":{height},\"dir\":{:?},\"rules\":\"{}\",\"txs\":{},\"deposits\":{},\"gas\":{},\"complete_bytes\":{},\"sparse_bytes\":{},\"instr_complete\":{},\"instr_sparse\":{},\"sp1gas_complete\":{},\"sp1gas_sparse\":{},\"real_proof\":{},\"request\":{},\"differ\":{:?}}}",
                stored.dir.file_name().unwrap(),
                if spec == ChainSpec::mainnet_v1() { "v1" } else if spec == ChainSpec::mainnet() { "next" } else { "testnet_v3" },
                body.transactions.len(),
                body.deposits.len(),
                header.gas_used,
                bincode::serialized_size(&complete)?,
                size_lazy.unwrap_or(0),
                cycles.0,
                cycles.1,
                cycles.2,
                cycles.3,
                real.is_some(),
                from_request,
                problems,
            );
            blocks += 1;
            differ += problems.len() as u64;
        }

        let outcome = execute_node_block(&spec, domain, &mut current, &context, &body)?;
        if outcome.header != header {
            return Err(format!("block {height}: replay differs from the artifact's header").into());
        }
        current.commit_root();
        user_txs += body.transactions.len() as u64;
        deposits += body.deposits.len() as u64;
        withdrawals += outcome.withdrawals.as_ref().map_or(0, |summary| summary.withdrawals.len() as u64);
        failed_txs += outcome.transactions.iter().filter(|tx| !tx.success).count() as u64;
        parent_hash = Some(header.hash());
        state = Some(current);
        height += 1;
    }
    let _ = U256::ZERO;
    println!(
        "{{\"summary\":true,\"work\":{work:?},\"last_height\":{},\"artifacts_top\":{},\"blocks\":{blocks},\"user_txs\":{user_txs},\"failed_txs\":{failed_txs},\"deposits\":{deposits},\"withdrawals\":{withdrawals},\"with_request\":{with_request},\"with_real_proof\":{with_real},\"statement_equals_real_proof\":{matched_real},\"elf_pairs\":{elf_runs},\"tampered\":{tampered},\"tamper_harmless\":{tamper_survived},\"differences\":{differ}}}",
        height - 1,
        by_height.keys().next_back().copied().unwrap_or(0),
    );
    Ok(if differ == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) })
}
