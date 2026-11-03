// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline qualification harness for the settlement V3 guest.
//!
//! Differs from `bloch-evm-sp1-settlement-v2` in exactly two ways: the guest
//! commits the 766-byte V3 statement, and `native-artifact` does NOT refuse L2
//! blocks with user transactions. Deposits must still equal the consumed
//! native inbox range; the native chain checks them via `deposits_hash`.
//!
//! A leading `--mainnet` selects the mainnet program (`settlement_v3_mainnet`:
//! `ChainSpec::mainnet`, chain id 700770, `MAINNET_DOMAIN`) for every mode;
//! without it the harness checks the devnet `settlement_v3` program
//! (`ChainSpec::testnet_v3`, domain `0xd3…d3`), unchanged.
#[allow(dead_code)]
#[path = "../fixture.rs"]
mod fixture;

use alloy_primitives::B256;
use bloch_evm_sp1_host::verification::{ProgramIdentity, TrustedProgram};
use bloch_l2_evm::{
    proof_statement::{execute_settlement_statement_v3, SettlementContextV2, SettlementStatementV3},
    ChainSpec,
};
use sp1_sdk::{Elf, LightProver, ProveRequest, Prover, ProverClient, SP1PublicValues, SP1Stdin};
use std::{error::Error, ffi::OsStr, fs, io, process::Command, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The program the harness qualifies, selected once from the command line.
static MAINNET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn mainnet() -> bool {
    *MAINNET.get().unwrap_or(&false)
}

/// The execution rules the selected guest compiles.
fn spec() -> ChainSpec {
    if mainnet() {
        ChainSpec::mainnet()
    } else {
        ChainSpec::testnet_v3()
    }
}

/// The V2 domain the selected guest compiles.
fn domain() -> B256 {
    if mainnet() {
        bloch_l2_evm::chainspec::MAINNET_DOMAIN
    } else {
        B256::repeat_byte(0xd3)
    }
}

fn program_name() -> &'static str {
    if mainnet() {
        "settlement_v3_mainnet"
    } else {
        "settlement_v3"
    }
}
const QUALIFICATION_GNARK_IMAGE: &str =
    "ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d";

struct Qualification {
    execution: fixture::Fixture,
    context: SettlementContextV2,
    expected: SettlementStatementV3,
}

fn stdin(fixture: &fixture::Fixture, context: SettlementContextV2) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&fixture.witness);
    stdin.write(&fixture.context);
    stdin.write_vec(alloy_rlp::encode(&fixture.body));
    stdin.write(&context);
    stdin
}

fn expect(execution: fixture::Fixture, context: SettlementContextV2) -> Result<Qualification> {
    expect_in(&spec(), domain(), execution, context)
}

fn expect_in(spec: &ChainSpec, domain: B256, execution: fixture::Fixture, context: SettlementContextV2) -> Result<Qualification> {
    let expected = execute_settlement_statement_v3(
        spec,
        domain,
        &execution.witness,
        &execution.context,
        &execution.body,
        context,
    )?;
    Ok(Qualification {
        execution,
        context,
        expected,
    })
}

fn synthetic_context(identity: ProgramIdentity, deposits: u64) -> SettlementContextV2 {
    synthetic_context_for(
        [
            identity.elf_keccak(),
            identity.verifying_key_hash(),
            identity.verifying_key_bn254(),
        ],
        deposits,
    )
}

fn synthetic_context_for(program: [B256; 3], deposits: u64) -> SettlementContextV2 {
    SettlementContextV2 {
        network: B256::repeat_byte(0x41),
        genesis: B256::repeat_byte(0x42),
        program_elf_keccak: program[0],
        program_vkey_koalabear: program[1],
        program_vkey_bn254: program[2],
        previous_settlement: B256::ZERO,
        l1_slot: 1,
        l1_height: 1,
        source_commitment: B256::repeat_byte(0x43),
        inbox_root: B256::repeat_byte(0x44),
        inbox_count: deposits,
        consumed_start: 0,
        consumed_end: deposits,
    }
}

/// Chained successor from the canonical L2 database export, as in V2, but a
/// block with user transactions is accepted.
#[cfg(feature = "node-artifact")]
fn native_artifact_qualification(
    identity: ProgramIdentity,
    text: &str,
    artifact: &std::path::Path,
) -> Result<Qualification> {
    let fields: Vec<_> = text.lines().collect();
    if text.len() > 700 || (fields.len() != 8 && fields.len() != 11) {
        return Err(io::Error::other("native artifact request requires 8 or 11 fields").into());
    }
    let hash = |index: usize, zero_ok: bool| -> Result<B256> {
        if fields[index].len() != 64
            || !fields[index]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(io::Error::other("native request requires lowercase 32-byte hexadecimal identities").into());
        }
        let value: B256 = fields[index].parse()?;
        if value == B256::ZERO && !zero_ok {
            return Err(io::Error::other("zero native request identity").into());
        }
        Ok(value)
    };
    let slot: u64 = fields[3].parse()?;
    let height: u64 = fields[4].parse()?;
    if height == 0 || slot < height {
        return Err(io::Error::other("invalid native request position").into());
    }
    let previous_settlement = hash(7, true)?;
    let artifact = bloch_evm_sp1_host::artifact::load_selected_artifact_in(artifact, &spec(), domain())?;
    if (artifact.header().number == 1) != (previous_settlement == B256::ZERO) {
        return Err(io::Error::other("only L2 block 1 may have no previous settlement").into());
    }
    if artifact.context().anchor_root != hash(2, false)? {
        return Err(io::Error::other("artifact anchor is not the native-selected source block").into());
    }
    let (inbox_count, consumed_start, consumed_end) = if fields.len() == 11 {
        (
            fields[8].parse::<u64>()?,
            fields[9].parse::<u64>()?,
            fields[10].parse::<u64>()?,
        )
    } else {
        (0, 0, 0)
    };
    // V3: user transactions are allowed. Deposits must still be exactly the
    // consumed inbox range.
    if consumed_end.checked_sub(consumed_start) != Some(artifact.body().deposits.len() as u64)
        || consumed_end > inbox_count
    {
        return Err(io::Error::other("artifact deposits do not match the consumed inbox range").into());
    }
    let execution = fixture::Fixture {
        witness: artifact.witness().clone(),
        context: artifact.context().clone(),
        body: artifact.body().clone(),
        expected: artifact.expected(),
        parent: artifact.parent().clone(),
        header: artifact.header().clone(),
    };
    let context = SettlementContextV2 {
        network: hash(0, false)?,
        genesis: hash(1, false)?,
        program_elf_keccak: identity.elf_keccak(),
        program_vkey_koalabear: identity.verifying_key_hash(),
        program_vkey_bn254: identity.verifying_key_bn254(),
        previous_settlement,
        l1_slot: slot,
        l1_height: height,
        source_commitment: hash(5, false)?,
        inbox_root: hash(6, false)?,
        inbox_count,
        consumed_start,
        consumed_end,
    };
    expect(execution, context)
}

fn qualification(name: &str, identity: ProgramIdentity) -> Result<Qualification> {
    match name {
        "empty" => expect(fixture::fixture_empty_in(&spec(), domain())?, synthetic_context(identity, 0)),
        // Deposit plus a signed deploy and call: two user transactions.
        "contract" if mainnet() => Err(io::Error::other("the contract fixture is devnet-only (development domain)").into()),
        "contract" => expect(fixture::fixture_with(&ChainSpec::testnet_v3())?, synthetic_context(identity, 1)),
        #[cfg(feature = "node-artifact")]
        "native-artifact" => {
            let request = std::env::var_os("BLOCH_NATIVE_L2_REQUEST")
                .ok_or("BLOCH_NATIVE_L2_REQUEST must name the native request with the previous settlement")?;
            let artifact = std::env::var_os("BLOCH_NATIVE_L2_ARTIFACT")
                .ok_or("BLOCH_NATIVE_L2_ARTIFACT must name the exported execution artifact")?;
            let metadata = fs::symlink_metadata(&request)?;
            if !metadata.is_file() || metadata.len() > 700 {
                return Err("invalid native request file".into());
            }
            native_artifact_qualification(identity, &fs::read_to_string(request)?, std::path::Path::new(&artifact))
        }
        #[cfg(not(feature = "node-artifact"))]
        "native-artifact" => Err(io::Error::other("native-artifact requires --features node-artifact").into()),
        _ => Err(io::Error::other("fixture must be empty, contract or native-artifact").into()),
    }
}

/// The settler's preflight ran into `BLOCH_PREFLIGHT_CYCLE_LIMIT`: a measured verdict, not a failure of the host.
#[derive(Debug)]
struct OverCycleLimit(u64);

impl std::fmt::Display for OverCycleLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "guest execution exceeded the preflight cycle limit of {} instructions", self.0)
    }
}

impl Error for OverCycleLimit {}

/// Exit status of an `execute` run that hit `BLOCH_PREFLIGHT_CYCLE_LIMIT` (sequencer policy v2).
const EXIT_OVER_CYCLE_LIMIT: i32 = 3;

/// `BLOCH_PREFLIGHT_CYCLE_LIMIT`: an instruction limit for `execute` only (the settler's preflight, sequencer policy
/// v2, at least twice the block instruction budget). Unset: no limit, as before. Proving never reads it.
fn preflight_cycle_limit(value: Option<&OsStr>) -> Result<Option<u64>> {
    let Some(value) = value else { return Ok(None) };
    let text = value.to_str().ok_or("BLOCH_PREFLIGHT_CYCLE_LIMIT must be decimal")?;
    match text.parse::<u64>() {
        Ok(limit) if limit > 0 && text.bytes().all(|b| b.is_ascii_digit()) => Ok(Some(limit)),
        _ => Err("BLOCH_PREFLIGHT_CYCLE_LIMIT must be a positive decimal integer".into()),
    }
}

/// What stage 1 of the preflight decides from the gas-off instruction count (agent 224, recommendation 2).
#[derive(Debug, PartialEq, Eq)]
enum StageOne {
    /// At or over the cycle limit: the verdict, with no gas run.
    OverLimit(u64),
    /// Under the limit: stage 2 (the gas run) measures the SP1 gas.
    UnderLimit(u64),
}

/// Stage 1's verdict. SP1 stops a gas run once `instructions >= limit` (sp1-prover worker/prover/execute.rs), so the
/// same comparison here gives the verdict the gas run would have given, without waiting for its next gas chunk. Only a
/// guest that ran to a clean exit gives a verdict.
fn stage_one_verdict(limit: u64, instructions: u64, exit_code: u32) -> Result<StageOne> {
    let _ = (limit, instructions, exit_code);
    unimplemented!("stage one verdict")
}

/// Stage 2 must count exactly the instructions stage 1 counted: the two executors run the same program on the same
/// input. A difference means the measurement cannot be trusted, so the run gives no cost (a host failure for the
/// policy, never a verdict on a transaction).
fn check_stage_counts(stage_one: u64, stage_two: u64) -> Result<()> {
    let _ = (stage_one, stage_two);
    unimplemented!("stage counts")
}

/// The longest the runtime may take to shut down before the process exits (agent 224 measured 0-6.6 s).
const RUNTIME_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// Run `future` on a two-worker runtime, then shut the runtime down (bounded by `grace`) before returning, so an SP1
/// executor task can drop its native runner child and its /dev/shm segments before the process exits (7c73a6e).
fn run_then_shut_down<T>(future: impl std::future::Future<Output = Result<T>>, grace: std::time::Duration) -> Result<T> {
    let _ = grace;
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let result = runtime.block_on(future);
    std::mem::forget(runtime);
    result
}

fn main() -> Result<()> {
    // The runtime is shut down before the exit, so the executor's tasks end first and release what they hold.
    match run_then_shut_down(run(), RUNTIME_SHUTDOWN_GRACE) {
        Err(error) => match error.downcast_ref::<OverCycleLimit>() {
            Some(OverCycleLimit(limit)) => {
                use std::io::Write;
                println!("Settlement V3 over cycle limit: limit={limit}");
                let _ = io::stdout().flush();
                std::process::exit(EXIT_OVER_CYCLE_LIMIT);
            }
            None => Err(error),
        },
        done => done,
    }
}

async fn run() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: bloch-evm-sp1-settlement-v3 [--mainnet] <execute|prove-groth16|verify-groth16> <empty|contract|native-artifact> TRUSTED_SETTLEMENT_V3_ELF [PROOF_FILE]";
    let selected = args.first().map(String::as_str) == Some("--mainnet");
    if selected {
        args.remove(0);
    }
    MAINNET.set(selected).expect("program selected once");
    if args.first().map(String::as_str) == Some("identity") {
        return print_identity(args.get(1).filter(|_| args.len() == 2).ok_or(
            "usage: bloch-evm-sp1-settlement-v3 [--mainnet] identity TRUSTED_SETTLEMENT_V3_ELF",
        )?)
        .await;
    }
    let mode = args.first().map(String::as_str).ok_or(usage)?;
    let expected_len = if mode == "execute" { 3 } else { 4 };
    if !matches!(mode, "execute" | "prove-groth16" | "verify-groth16") || args.len() != expected_len {
        return Err(usage.into());
    }
    let (fixture_name, elf_path) = (args[1].as_str(), &args[2]);
    if mode == "prove-groth16" {
        require_release_gnark_environment(
            std::env::var_os("SP1_CIRCUIT_MODE").as_deref(),
            std::env::var_os("SP1_GNARK_IMAGE").as_deref(),
        )?;
        let docker = Command::new("docker").arg("info").output()?;
        if !docker.status.success() {
            return Err(io::Error::other("Docker is not ready for the pinned SP1 Gnark backend").into());
        }
    }

    let elf = Elf::from(fs::read(elf_path)?);
    let trusted = TrustedProgram::from_trusted_elf(elf.clone()).await?;
    let qualification = qualification(fixture_name, trusted.identity())?;
    let (fixture, context, expected) = (&qualification.execution, qualification.context, qualification.expected);
    println!("OFFLINE QUALIFICATION ONLY: no native source authority, consensus activation, finality or payouts");
    println!(
        "Expected settlement V3 statement: user_tx_count={} deposits_hash={:?} transactions_root={:?} withdrawal_root={:?} withdrawal_count={}",
        expected.user_tx_count,
        expected.deposits_hash,
        expected.transactions_root,
        expected.withdrawal_root,
        expected.withdrawal_count
    );

    if mode == "execute" {
        let limit = preflight_cycle_limit(std::env::var_os("BLOCH_PREFLIGHT_CYCLE_LIMIT").as_deref())?;
        let executor = LightProver::new().await;
        let started = Instant::now();
        let mut request = executor.execute(elf, stdin(fixture, context)).calculate_gas(true);
        if let Some(limit) = limit {
            request = request.cycle_limit(limit);
        }
        let (public, report) = match request.await {
            Ok(done) => done,
            // SP1 6.8 (sp1-prover worker/prover/execute.rs) returns ExecutionError::ExceededCycleLimit, which the SDK
            // passes on as text: "exceeded cycle limit of N".
            Err(error) if limit.is_some() && error.to_string().contains("exceeded cycle limit") => {
                eprintln!("{error}");
                return Err(Box::new(OverCycleLimit(limit.unwrap_or_default())));
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(limit) = limit.filter(|limit| report.total_instruction_count() >= *limit) {
            return Err(Box::new(OverCycleLimit(limit)));
        }
        if report.exit_code != 0 {
            return Err(io::Error::other("settlement V3 guest execution failed").into());
        }
        expected.check_expected(public.as_slice())?;
        // Proving-cost indicators: precompile work does not show in the instruction count.
        let syscalls: Vec<String> = report
            .syscall_counts
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(code, count)| format!("{code:?}={count}"))
            .collect();
        println!(
            "Settlement V3 cost: gas={} touched_memory={} record_bytes={} syscalls={}",
            report.gas().map_or("none".to_string(), |g| g.to_string()),
            report.touched_memory_addresses,
            report.total_record_size(),
            syscalls.join(",")
        );
        println!(
            "Settlement V3 guest matched the independent host statement: {} instructions in {:?}",
            report.total_instruction_count(),
            started.elapsed()
        );
        return Ok(());
    }

    let proof_path = &args[3];
    if mode == "verify-groth16" {
        let qualified = trusted.verify_groth16_settlement_v3_file(proof_path, &expected)?;
        println!(
            "Real settlement V3 Groth16 proof verified offline: canonical={} bytes; no activation implied",
            qualified.canonical_proof_bytes()?.len()
        );
        return Ok(());
    }

    if fs::exists(proof_path)? {
        return Err(io::Error::other("proof output already exists").into());
    }
    let prover = ProverClient::builder().cpu().build().await;
    let key = prover.setup(elf).await?;
    let started = Instant::now();
    let proof = prover.prove(&key, stdin(fixture, context)).groth16().await?;
    let qualified = trusted.verify_groth16_settlement_v3(proof.clone(), &expected)?;
    if qualified.canonical_proof_bytes()?.len() != 356 {
        return Err(io::Error::other("unexpected canonical Groth16 proof length").into());
    }
    let mut tampered = proof.clone();
    let mut public = tampered.public_values.as_slice().to_vec();
    *public.last_mut().ok_or("proof has no public bytes")? ^= 1;
    tampered.public_values = SP1PublicValues::from(public.as_slice());
    if trusted.verify_groth16_settlement_v3(tampered, &expected).is_ok() {
        return Err(io::Error::other("proof accepted altered public values").into());
    }
    let file = fs::OpenOptions::new().write(true).create_new(true).open(proof_path)?;
    bincode::serialize_into(&file, &proof)?;
    file.sync_all()?;
    let reopened = trusted.verify_groth16_settlement_v3_file(proof_path, &expected)?;
    println!(
        "Settlement V3 Groth16 proof generated, persisted and reverified in {:?}: canonical={} bytes; no activation implied",
        started.elapsed(),
        reopened.canonical_proof_bytes()?.len()
    );
    Ok(())
}

/// Print every L2-side pin a V3 genesis needs, as JSON: the compiled domain
/// and configuration commitment, the ELF Keccak, both SP1 key
/// identities and (with `source-settlement`) the V3 proof-policy commitment.
/// No proof is generated; deriving the keys runs the SP1 setup only.
async fn print_identity(elf_path: &str) -> Result<()> {
    let bytes = fs::read(elf_path)?;
    let trusted = TrustedProgram::from_trusted_elf(Elf::from(bytes)).await?;
    let identity = trusted.identity();
    let spec = spec();
    #[cfg(feature = "source-settlement")]
    let policy = {
        use sha2::Digest;
        let full_vk: [u8; 32] = sha2::Sha256::digest(*sp1_verifier::GROTH16_VK_BYTES).into();
        format!(
            "\"{:x}\"",
            bloch_native_domain_devnet::settlement_v3_groth16_proof_policy_commitment(
                sp1_sdk::SP1_CIRCUIT_VERSION,
                B256::from(full_vk),
            )?
        )
    };
    #[cfg(not(feature = "source-settlement"))]
    let policy = "null".to_string();
    println!(
        "{{\"program\":\"{}\",\"chain_id\":{},\"domain\":\"{:x}\",\"configuration\":\"{:x}\",\"elf_keccak\":\"{:x}\",\"vkey_koalabear\":\"{:x}\",\"vkey_bn254\":\"{:x}\",\"sp1_circuit_version\":\"{}\",\"proof_policy_v3\":{}}}",
        program_name(),
        spec.chain_id,
        domain(),
        bloch_l2_evm::proof_statement::configuration_commitment(&spec)?,
        identity.elf_keccak(),
        identity.verifying_key_hash(),
        identity.verifying_key_bn254(),
        sp1_sdk::SP1_CIRCUIT_VERSION,
        policy
    );
    Ok(())
}

fn require_release_gnark_environment(circuit_mode: Option<&OsStr>, image: Option<&OsStr>) -> Result<()> {
    if circuit_mode.is_some_and(|mode| mode != "release") {
        return Err(io::Error::other("settlement V3 Groth16 qualification requires release circuits").into());
    }
    let image = image
        .and_then(OsStr::to_str)
        .ok_or_else(|| io::Error::other("SP1_GNARK_IMAGE must pin the qualification image by sha256 digest"))?;
    if image != QUALIFICATION_GNARK_IMAGE {
        return Err(io::Error::other("SP1_GNARK_IMAGE does not match the reviewed qualification image digest").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_cycle_limit_is_a_positive_decimal_or_unset() {
        assert_eq!(preflight_cycle_limit(None).unwrap(), None);
        assert_eq!(preflight_cycle_limit(Some(OsStr::new("180000000"))).unwrap(), Some(180_000_000));
        for bad in ["0", "", "-1", "+5", "1e9", "0x10", " 5", "18446744073709551616"] {
            assert!(preflight_cycle_limit(Some(OsStr::new(bad))).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn stage_one_gives_the_verdict_at_or_over_the_limit() {
        let limit = 180_000_000;
        assert_eq!(stage_one_verdict(limit, 2_279_398_170, 0).unwrap(), StageOne::OverLimit(2_279_398_170));
        assert_eq!(stage_one_verdict(limit, limit, 0).unwrap(), StageOne::OverLimit(limit));
        assert_eq!(stage_one_verdict(limit, limit - 1, 0).unwrap(), StageOne::UnderLimit(limit - 1));
        assert_eq!(stage_one_verdict(limit, 1_490_000, 0).unwrap(), StageOne::UnderLimit(1_490_000));
    }

    #[test]
    fn stage_one_gives_no_verdict_for_a_failed_guest() {
        assert!(stage_one_verdict(180_000_000, 2_279_398_170, 1).is_err());
        assert!(stage_one_verdict(180_000_000, 1_000, 1).is_err());
    }

    #[test]
    fn stage_two_must_count_what_stage_one_counted() {
        assert!(check_stage_counts(1_321_465_654, 1_321_465_654).is_ok());
        assert!(check_stage_counts(1_321_465_654, 1_321_465_655).is_err());
        assert!(check_stage_counts(0, 1).is_err());
    }

    #[test]
    fn the_runtime_shuts_down_before_the_result_is_returned() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let released = Arc::new(AtomicBool::new(false));
        let flag = released.clone();
        let result: Result<()> = run_then_shut_down(
            async move {
                // An executor task still holding its runner when the run stops on the cycle limit.
                tokio::task::spawn_blocking(move || {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    flag.store(true, Ordering::SeqCst);
                });
                Err(Box::new(OverCycleLimit(7)) as Box<dyn Error>)
            },
            std::time::Duration::from_secs(10),
        );
        assert!(matches!(result.unwrap_err().downcast_ref::<OverCycleLimit>(), Some(OverCycleLimit(7))));
        assert!(released.load(Ordering::SeqCst), "returned before the blocking task released its resources");
    }

    #[test]
    fn the_runtime_shutdown_is_bounded() {
        let started = Instant::now();
        let result: Result<()> = run_then_shut_down(
            async {
                tokio::task::spawn_blocking(|| std::thread::sleep(std::time::Duration::from_secs(20)));
                Ok(())
            },
            std::time::Duration::from_millis(200),
        );
        assert!(result.is_ok());
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "shutdown waited {:?}", started.elapsed());
    }

    #[test]
    fn proving_environment_is_release_only_and_digest_pinned() {
        let pinned = OsStr::new(QUALIFICATION_GNARK_IMAGE);
        assert!(require_release_gnark_environment(None, Some(pinned)).is_ok());
        assert!(require_release_gnark_environment(Some(OsStr::new("dev")), Some(pinned)).is_err());
        assert!(require_release_gnark_environment(None, None).is_err());
    }

    /// The mainnet program's statement: configuration of chain id 700770 and
    /// the mainnet domain, never the devnet ones.
    #[test]
    fn mainnet_statement_binds_the_mainnet_rules_and_domain() {
        use bloch_l2_evm::chainspec::MAINNET_DOMAIN;
        let program = [B256::repeat_byte(9), B256::repeat_byte(10), B256::repeat_byte(11)];
        let main = expect_in(
            &ChainSpec::mainnet(),
            MAINNET_DOMAIN,
            fixture::fixture_empty_in(&ChainSpec::mainnet(), MAINNET_DOMAIN).unwrap(),
            synthetic_context_for(program, 0),
        )
        .unwrap();
        let dev = expect_in(
            &ChainSpec::testnet_v3(),
            B256::repeat_byte(0xd3),
            fixture::fixture_empty_in(&ChainSpec::testnet_v3(), B256::repeat_byte(0xd3)).unwrap(),
            synthetic_context_for(program, 0),
        )
        .unwrap();
        let (m, d) = (main.expected.encode(), dev.expected.encode());
        assert_eq!(m.len(), d.len());
        assert_ne!(m, d);
        let configuration = bloch_l2_evm::proof_statement::configuration_commitment(&ChainSpec::mainnet()).unwrap();
        assert!(m.windows(32).any(|w| w == configuration.as_slice()));
        assert!(m.windows(32).any(|w| w == MAINNET_DOMAIN.as_slice()));
        assert!(!m.windows(32).any(|w| w == B256::repeat_byte(0xd3).as_slice()));
        // The devnet harness keeps the devnet program parameters.
        assert!(!mainnet());
        assert_eq!((spec(), domain(), program_name()), (ChainSpec::testnet_v3(), B256::repeat_byte(0xd3), "settlement_v3"));
    }

    /// The V3 harness accepts the user-transaction fixture that V2's
    /// `native-artifact` path refuses, and derives a matching statement.
    #[test]
    fn contract_fixture_settles_user_transactions_under_v3() {
        let program = [B256::repeat_byte(9), B256::repeat_byte(10), B256::repeat_byte(11)];
        let q = expect(fixture::fixture_with(&ChainSpec::testnet_v3()).unwrap(), synthetic_context_for(program, 1)).unwrap();
        assert_eq!(q.expected.user_tx_count, 2);
        assert_eq!(q.expected.base.consumed_end, 1);
        assert_eq!(q.expected.deposits_hash, q.execution.body.deposits_hash());
        assert_eq!(SettlementStatementV3::decode(&q.expected.encode()).unwrap(), q.expected);
    }
}
