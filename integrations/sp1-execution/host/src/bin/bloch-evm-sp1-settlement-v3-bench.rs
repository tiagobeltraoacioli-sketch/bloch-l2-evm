// SPDX-License-Identifier: MIT OR Apache-2.0
//! Execution-only cycle benchmark for the settlement V3 guest (no proof).
//!
//! usage: bloch-evm-sp1-settlement-v3-bench <transfers|calls> N SETTLEMENT_V3_ELF
//!
//! Builds a deterministic block (one deposit plus N transfers, or one deposit,
//! a deployment and N contract calls), re-executes it on the host to derive
//! the expected V3 statement, runs the guest in the SP1 executor, checks the
//! committed statement byte-for-byte and prints one JSON line: SP1 instruction
//! count (cycles), syscalls, SP1 gas, execution wall time and this process's
//! peak RSS. Run one configuration per process so peak RSS is per block.
//! Program identities in the context are synthetic: execution does not depend
//! on them, and no verifying key is derived (that would dominate RSS).
#[allow(dead_code)]
#[path = "../fixture.rs"]
mod fixture;

use alloy_primitives::B256;
use bloch_l2_evm::{
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2},
    ChainSpec,
};
use sp1_sdk::{Elf, LightProver, Prover, SP1Stdin};
use std::{error::Error, fs, io, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn peak_rss_bytes() -> u64 {
    // SAFETY: getrusage writes only into the provided, zero-initialised struct.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let max = usage.ru_maxrss as u64;
    // macOS reports bytes, Linux kibibytes.
    if cfg!(target_os = "macos") {
        max
    } else {
        max * 1024
    }
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: bloch-evm-sp1-settlement-v3-bench <transfers|calls> N SETTLEMENT_V3_ELF";
    if args.len() != 3 {
        return Err(usage.into());
    }
    let n: u64 = args[1].parse().map_err(|_| usage)?;
    let fixture = match args[0].as_str() {
        "transfers" => fixture::fixture_transfers(n)?,
        "calls" => fixture::fixture_calls(n)?,
        _ => return Err(usage.into()),
    };
    let context = SettlementContextV2 {
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
        inbox_count: 1,
        consumed_start: 0,
        consumed_end: 1,
    };
    let expected = execute_settlement_statement_v3(
        &ChainSpec::testnet(),
        B256::repeat_byte(0xd3),
        &fixture.witness,
        &fixture.context,
        &fixture.body,
        context,
    )?;
    let body = alloy_rlp::encode(&fixture.body);
    let mut stdin = SP1Stdin::new();
    stdin.write(&fixture.witness);
    stdin.write(&fixture.context);
    stdin.write_vec(body.clone());
    stdin.write(&context);
    let witness_bytes = bincode::serialized_size(&fixture.witness)?;

    let elf = Elf::from(fs::read(&args[2])?);
    let executor = LightProver::new().await;
    let started = Instant::now();
    let (public, report) = executor.execute(elf, stdin).await?;
    let seconds = started.elapsed().as_secs_f64();
    if report.exit_code != 0 {
        return Err(io::Error::other("settlement V3 guest execution failed").into());
    }
    expected.check_expected(public.as_slice())?;
    println!(
        "{{\"kind\":\"{}\",\"n\":{},\"user_txs\":{},\"block_gas_used\":{},\"body_bytes\":{},\"witness_bytes\":{},\"cycles\":{},\"syscalls\":{},\"sp1_gas\":{},\"execute_seconds\":{:.2},\"peak_rss_bytes\":{}}}",
        args[0],
        n,
        expected.user_tx_count,
        fixture.header.gas_used,
        body.len(),
        witness_bytes,
        report.total_instruction_count(),
        report.total_syscall_count(),
        report.gas().map_or("null".to_string(), |g| g.to_string()),
        seconds,
        peak_rss_bytes()
    );
    Ok(())
}
