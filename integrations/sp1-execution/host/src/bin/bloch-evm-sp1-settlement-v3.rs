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
//! (`ChainSpec::testnet_v3`, domain `0xd3…d3`), unchanged. A leading
//! `--mainnet-v1` selects the same mainnet path under `ChainSpec::mainnet_v1`,
//! the rules of the program the activation pinned: the settler uses it for blocks
//! settled before the native gate replaces that program.
//!
//! CANDIDATE: `--sparse` after either mainnet flag selects the sparse-witness guest
//! and its artifact (`produce export --witness sparse`). The statement is the same.
//!
//! CANDIDATE (forced inclusion, `sparse-witness` or `node-artifact` builds): `--mainnet` without
//! `--sparse` is the rollback fallback guest (`guest-fallback`), the next rules
//! with forced inclusion on the complete witness. It takes a fifth input, the
//! forced records the block consumed, which the complete artifact carries.
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
static MAINNET: std::sync::OnceLock<Option<ChainSpec>> = std::sync::OnceLock::new();

/// CANDIDATE: `--sparse` after the rules flag selects the sparse-witness guest
/// (`settlement_v3_mainnet_sparse`) and its artifact. Mainnet path only.
static SPARSE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn sparse() -> bool {
    SPARSE.get().copied().unwrap_or(false)
}

fn mainnet() -> bool {
    matches!(MAINNET.get(), Some(Some(_)))
}

/// The execution rules the selected guest compiles.
fn spec() -> ChainSpec {
    match MAINNET.get() {
        Some(Some(rules)) => rules.clone(),
        _ => ChainSpec::testnet_v3(),
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
    program_name_for(MAINNET.get().and_then(Option::as_ref), sparse())
}

/// The guest program a rules flag and a witness flag select (agent 163, B-3):
/// `--mainnet-v1 --sparse` is `settlement_v3_mainnet_v1_sparse`, not the
/// next-rules sparse guest. `--mainnet-v1` alone names the activated complete
/// program, which was built as `settlement_v3_mainnet`.
fn program_name_for(rules: Option<&ChainSpec>, sparse: bool) -> &'static str {
    let next = rules.is_some_and(|rules| rules.fee_vault_sweep.is_some());
    match (rules.is_some(), next, sparse) {
        (true, true, true) => "settlement_v3_mainnet_sparse",
        (true, false, true) => "settlement_v3_mainnet_v1_sparse",
        (true, _, false) => "settlement_v3_mainnet",
        (false, _, _) => "settlement_v3",
    }
}

/// The empty-block qualification under the selected rules and witness: what an
/// ELF built for them must commit.
fn empty_qualification(identity: ProgramIdentity) -> Result<Qualification> {
    let execution = fixture::fixture_empty_in(&spec(), domain())?;
    let context = synthetic_context(identity, 0);
    if !sparse() {
        return expect(execution, context);
    }
    use bloch_l2_evm::sparse_witness::{generate_sparse_node_witness, BlockHashes};
    let mut pre = bloch_l2_evm::node_execution::genesis_v2(&spec(), 0)?;
    pre.commit_root();
    let (witness, _) =
        generate_sparse_node_witness(&pre, &spec(), domain(), &execution.context, &execution.body, BlockHashes::Lazy)
            .map_err(|error| io::Error::other(format!("sparse witness of the empty block: {error:?}")))?;
    expect_sparse(execution, witness, context)
}

/// B-3: refuse an ELF that does not compute the rules the flags name. The ELF
/// is executed (SP1 execute, no proof) on an empty block under those rules, and
/// its committed statement must equal the host's, configuration commitment
/// included. A next-rules ELF under `--mainnet-v1`, a v1 ELF under `--mainnet`,
/// a sparse ELF without `--sparse` or the reverse all fail here.
async fn check_elf_computes_the_selected_rules(elf: Elf, identity: ProgramIdentity) -> Result<()> {
    let refuse = |why: String| -> Box<dyn Error> {
        io::Error::other(format!("the ELF is not {} under the selected rules: {why}", program_name())).into()
    };
    let qualification = empty_qualification(identity)?;
    let executor = LightProver::new().await;
    let (public, report) =
        executor.execute(elf, stdin(&qualification)).await.map_err(|error| refuse(format!("execution failed: {error}")))?;
    if report.exit_code != 0 {
        return Err(refuse(format!("guest exit code {}", report.exit_code)));
    }
    qualification.expected.check_expected(public.as_slice()).map_err(|error| refuse(format!("{error:?}")))?;
    Ok(())
}
const QUALIFICATION_GNARK_IMAGE: &str =
    "ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d";

struct Qualification {
    execution: fixture::Fixture,
    context: SettlementContextV2,
    expected: SettlementStatementV3,
    /// CANDIDATE: the sparse witness, written to the guest instead of
    /// `execution.witness` (`--sparse`).
    sparse: Option<bloch_l2_evm::sparse_witness::SparseBatchWitness>,
    /// CANDIDATE: the forced records, written as the fallback guest's fifth
    /// input (`Some` exactly for that guest; empty when none is due).
    forced: Option<Vec<bloch_l2_evm::forced_inclusion::ForcedTransaction>>,
}

/// CANDIDATE: whether `spec` on the complete witness is the forced fallback
/// guest, which reads the forced list after the settlement context.
fn forced_fallback(spec: &ChainSpec) -> bool {
    #[cfg(any(feature = "sparse-witness", feature = "node-artifact"))]
    {
        spec.forced_inclusion && !sparse()
    }
    #[cfg(not(any(feature = "sparse-witness", feature = "node-artifact")))]
    {
        let _ = spec;
        false
    }
}

fn stdin(qualification: &Qualification) -> SP1Stdin {
    let (fixture, context) = (&qualification.execution, qualification.context);
    let mut stdin = SP1Stdin::new();
    match &qualification.sparse {
        Some(witness) => stdin.write(witness),
        None => stdin.write(&fixture.witness),
    }
    stdin.write(&fixture.context);
    stdin.write_vec(alloy_rlp::encode(&fixture.body));
    stdin.write(&context);
    if let Some(forced) = &qualification.forced {
        stdin.write(forced);
    }
    stdin
}

fn expect(execution: fixture::Fixture, context: SettlementContextV2) -> Result<Qualification> {
    expect_in(&spec(), domain(), execution, context)
}

fn expect_in(spec: &ChainSpec, domain: B256, execution: fixture::Fixture, context: SettlementContextV2) -> Result<Qualification> {
    expect_forced_in(spec, domain, execution, context, Vec::new())
}

/// [`expect_in`] with the forced records the block consumed. Only the forced
/// fallback guest takes them; a non-empty list for any other program is refused.
fn expect_forced_in(
    spec: &ChainSpec,
    domain: B256,
    execution: fixture::Fixture,
    context: SettlementContextV2,
    forced: Vec<bloch_l2_evm::forced_inclusion::ForcedTransaction>,
) -> Result<Qualification> {
    #[cfg(any(feature = "sparse-witness", feature = "node-artifact"))]
    if forced_fallback(spec) {
        let expected = bloch_l2_evm::forced_complete::execute_settlement_statement_v3_forced(
            spec,
            domain,
            &execution.witness,
            &execution.context,
            &execution.body,
            context,
            &forced,
        )?;
        return Ok(Qualification {
            execution,
            context,
            expected,
            sparse: None,
            forced: Some(forced),
        });
    }
    if !forced.is_empty() {
        return Err(io::Error::other("forced records apply to the forced fallback guest only").into());
    }
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
        sparse: None,
        forced: None,
    })
}

/// [`expect_in`] for the sparse-witness guest: the statement comes from the
/// stateless sparse verifier with lazy `BLOCKHASH`, the guest's own procedure.
fn expect_sparse(
    execution: fixture::Fixture,
    witness: bloch_l2_evm::sparse_witness::SparseBatchWitness,
    context: SettlementContextV2,
) -> Result<Qualification> {
    use bloch_l2_evm::sparse_witness::{execute_settlement_statement_v3_sparse, BlockHashes};
    let expected = execute_settlement_statement_v3_sparse(
        &spec(),
        domain(),
        &witness,
        &execution.context,
        &execution.body,
        context,
        BlockHashes::Lazy,
    )?;
    Ok(Qualification {
        execution,
        context,
        expected,
        sparse: Some(witness),
        forced: None,
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
    let mut forced = Vec::new();
    let (artifact, sparse_witness) = if sparse() {
        let loaded = bloch_evm_sp1_host::artifact::load_selected_sparse_artifact_in(artifact, &spec(), domain())?;
        let witness = loaded.witness();
        // The complete witness is not used on this path: `stdin` and `expect_in`
        // take the sparse one. An empty placeholder keeps one fixture type.
        let placeholder = bloch_l2_evm::proving::BatchWitness {
            prev_state_root: witness.prev_state_root,
            new_state_root: witness.new_state_root,
            proof: Default::default(),
            pre_accounts: Vec::new(),
            absent_accounts: Vec::new(),
        };
        let execution = fixture::Fixture {
            witness: placeholder,
            context: loaded.context().clone(),
            body: loaded.body().clone(),
            expected: loaded.expected(),
            parent: loaded.parent().clone(),
            header: loaded.header().clone(),
        };
        (execution, Some(witness.clone()))
    } else {
        let loaded = bloch_evm_sp1_host::artifact::load_selected_artifact_in(artifact, &spec(), domain())?;
        forced = loaded.forced().to_vec();
        let execution = fixture::Fixture {
            witness: loaded.witness().clone(),
            context: loaded.context().clone(),
            body: loaded.body().clone(),
            expected: loaded.expected(),
            parent: loaded.parent().clone(),
            header: loaded.header().clone(),
        };
        (execution, None)
    };
    if (artifact.header.number == 1) != (previous_settlement == B256::ZERO) {
        return Err(io::Error::other("only L2 block 1 may have no previous settlement").into());
    }
    if artifact.context.anchor_root != hash(2, false)? {
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
    if consumed_end.checked_sub(consumed_start) != Some(artifact.body.deposits.len() as u64)
        || consumed_end > inbox_count
    {
        return Err(io::Error::other("artifact deposits do not match the consumed inbox range").into());
    }
    let execution = artifact;
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
    match sparse_witness {
        Some(witness) => expect_sparse(execution, witness, context),
        None => expect_forced_in(&spec(), domain(), execution, context, forced),
    }
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
/// Fields: the limit, and stage 1's exact instruction count (at or over the limit).
#[derive(Debug)]
struct OverCycleLimit(u64, u64);

impl std::fmt::Display for OverCycleLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "guest execution of {} instructions is at or over the preflight cycle limit of {}", self.1, self.0)
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
    if exit_code != 0 {
        return Err(io::Error::other(format!("settlement V3 guest execution failed in preflight stage 1 (exit code {exit_code})")).into());
    }
    Ok(if instructions >= limit { StageOne::OverLimit(instructions) } else { StageOne::UnderLimit(instructions) })
}

/// Stage 2 must count exactly the instructions stage 1 counted: the two executors run the same program on the same
/// input. A difference means the measurement cannot be trusted, so the run gives no cost (a host failure for the
/// policy, never a verdict on a transaction).
fn check_stage_counts(stage_one: u64, stage_two: u64) -> Result<()> {
    if stage_one != stage_two {
        return Err(io::Error::other(format!(
            "preflight stage 1 counted {stage_one} instructions and stage 2 counted {stage_two}: no cost"
        ))
        .into());
    }
    Ok(())
}

/// Stage 1: the guest's exact instruction count with SP1 gas off, from the plain (minimal) executor that SP1's own
/// execute uses (sp1-prover worker/prover/execute.rs), run to the end without tracing: no trace ring, no /dev/shm
/// trace segments, about 1B instructions per second (agent 224). In SDK 6.8 a gas-off `execute` reports 0
/// instructions, so the runner is called directly. Returns (instructions, guest exit code).
async fn count_instructions(elf: &Elf, stdin: SP1Stdin) -> Result<(u64, u32)> {
    let program = sp1_core_executor::Program::from(elf)
        .map_err(|error| io::Error::other(format!("preflight stage 1 could not load the ELF: {error}")))?;
    let memory_limit = sp1_core_executor::SP1CoreOpts::default().memory_limit;
    let SP1Stdin { buffer, proofs, .. } = stdin;
    if !proofs.is_empty() {
        return Err(io::Error::other("preflight stage 1 takes no deferred proofs").into());
    }
    let counted = tokio::task::spawn_blocking(move || -> std::result::Result<(u64, u32), String> {
        // No trace (None) and no trace slots (0), as SP1 runs it with gas off. Dropping the runner kills its child.
        let mut runner =
            sp1_core_executor_runner::MinimalExecutorRunner::new(std::sync::Arc::new(program), false, None, memory_limit, 0);
        for input in &buffer {
            runner.with_input(input);
        }
        while runner.try_execute_chunk().map_err(|error| error.to_string())?.is_some() {}
        Ok((runner.global_clk(), runner.exit_code()))
    })
    .await?;
    counted.map_err(|error| io::Error::other(format!("preflight stage 1 execution failed: {error}")).into())
}

/// The longest the runtime may take to shut down before the process exits (agent 224 measured 0-6.6 s).
const RUNTIME_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// Run `future` on a two-worker runtime, then shut the runtime down (bounded by `grace`) before returning, so an SP1
/// executor task can drop its native runner child and its /dev/shm segments before the process exits (7c73a6e).
fn run_then_shut_down<T>(future: impl std::future::Future<Output = Result<T>>, grace: std::time::Duration) -> Result<T> {
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let result = runtime.block_on(future);
    runtime.shutdown_timeout(grace);
    result
}

fn main() -> Result<()> {
    // The runtime is shut down before the exit, so the executor's tasks end first and release what they hold.
    match run_then_shut_down(run(), RUNTIME_SHUTDOWN_GRACE) {
        Err(error) => match error.downcast_ref::<OverCycleLimit>() {
            Some(OverCycleLimit(limit, instructions)) => {
                use std::io::Write;
                println!("Settlement V3 over cycle limit: limit={limit} instructions={instructions} stage=1");
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
    let usage = "usage: bloch-evm-sp1-settlement-v3 [--mainnet|--mainnet-v1 [--sparse]] <execute|prove-groth16|verify-groth16> <empty|contract|native-artifact> TRUSTED_SETTLEMENT_V3_ELF [PROOF_FILE]";
    let selected = match args.first().map(String::as_str) {
        // The release gate (agent 163, B-1): no next rules without the owner's
        // fee-sweep recipient.
        Some("--mainnet") => Some(ChainSpec::mainnet_next().ok_or(
            "--mainnet: the next mainnet rules need the owner's fee-sweep recipient (MAINNET_FEE_SWEEP_RECIPIENT is unset)",
        )?),
        Some("--mainnet-v1") => Some(ChainSpec::mainnet_v1()),
        _ => None,
    };
    if selected.is_some() {
        args.remove(0);
    }
    let sparse_selected = args.first().map(String::as_str) == Some("--sparse");
    if sparse_selected {
        if selected.is_none() {
            return Err("--sparse applies to the mainnet program path only".into());
        }
        args.remove(0);
    }
    MAINNET.set(selected).expect("program selected once");
    SPARSE.set(sparse_selected).expect("witness selected once");
    if args.first().map(String::as_str) == Some("identity") {
        return print_identity(args.get(1).filter(|_| args.len() == 2).ok_or(
            "usage: bloch-evm-sp1-settlement-v3 [--mainnet|--mainnet-v1] identity TRUSTED_SETTLEMENT_V3_ELF",
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
    let expected = qualification.expected;
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
        let started = Instant::now();
        // Two-stage preflight (sequencer policy v2, section 3.4). SP1 checks a cycle limit only when a gas chunk of
        // 2^27 memory entries completes, so a gas run stops 20-30 s late on compute-heavy code (agent 224). Stage 1
        // counts without gas; at or over the limit that count is the verdict and no gas run starts.
        let stage_one = match limit {
            Some(limit) => {
                let (instructions, exit_code) = count_instructions(&elf, stdin(&qualification)).await?;
                println!(
                    "Settlement V3 preflight stage 1: instructions={instructions} elapsed_ms={}",
                    started.elapsed().as_millis()
                );
                match stage_one_verdict(limit, instructions, exit_code)? {
                    StageOne::OverLimit(instructions) => return Err(Box::new(OverCycleLimit(limit, instructions))),
                    StageOne::UnderLimit(instructions) => Some(instructions),
                }
            }
            None => None,
        };
        let executor = LightProver::new().await;
        let mut request = executor.execute(elf, stdin(&qualification)).calculate_gas(true);
        if let Some(limit) = limit {
            // Kept as a second guard: under the limit by stage 1, so it never fires unless the stages disagree.
            request = request.cycle_limit(limit);
        }
        let (public, report) = match request.await {
            Ok(done) => done,
            // SP1 6.8 (sp1-prover worker/prover/execute.rs) returns ExecutionError::ExceededCycleLimit, which the SDK
            // passes on as text: "exceeded cycle limit of N". Stage 1 counted fewer: the stages disagree, no cost.
            Err(error) if limit.is_some() && error.to_string().contains("exceeded cycle limit") => {
                return Err(io::Error::other(format!("preflight stage 2 stopped on the cycle limit after stage 1 counted {}: {error}", stage_one.unwrap_or_default())).into());
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(counted) = stage_one {
            check_stage_counts(counted, report.total_instruction_count())?;
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
    let proof = prover.prove(&key, stdin(&qualification)).groth16().await?;
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
    let trusted = TrustedProgram::from_trusted_elf(Elf::from(bytes.clone())).await?;
    let identity = trusted.identity();
    check_elf_computes_the_selected_rules(Elf::from(bytes), identity).await?;
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
                Err(Box::new(OverCycleLimit(7, 9)) as Box<dyn Error>)
            },
            std::time::Duration::from_secs(10),
        );
        assert!(matches!(result.unwrap_err().downcast_ref::<OverCycleLimit>(), Some(OverCycleLimit(7, 9))));
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
            &ChainSpec::mainnet_next_or_rehearsal(),
            MAINNET_DOMAIN,
            fixture::fixture_empty_in(&ChainSpec::mainnet_next_or_rehearsal(), MAINNET_DOMAIN).unwrap(),
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
        let configuration = bloch_l2_evm::proof_statement::configuration_commitment(&ChainSpec::mainnet_next_or_rehearsal()).unwrap();
        assert!(m.windows(32).any(|w| w == configuration.as_slice()));
        assert!(m.windows(32).any(|w| w == MAINNET_DOMAIN.as_slice()));
        assert!(!m.windows(32).any(|w| w == B256::repeat_byte(0xd3).as_slice()));
        // The devnet harness keeps the devnet program parameters.
        assert!(!mainnet());
        assert_eq!((spec(), domain(), program_name()), (ChainSpec::testnet_v3(), B256::repeat_byte(0xd3), "settlement_v3"));
    }

    /// CANDIDATE: the complete-witness next rules are the forced fallback
    /// guest (fifth input, the forced list); the activated rules are not, and
    /// refuse a forced list.
    #[cfg(any(feature = "sparse-witness", feature = "node-artifact"))]
    #[test]
    fn the_complete_next_rules_take_the_forced_list_and_the_activated_rules_do_not() {
        use bloch_l2_evm::chainspec::MAINNET_DOMAIN;
        let program = [B256::repeat_byte(9), B256::repeat_byte(10), B256::repeat_byte(11)];
        let next = ChainSpec::mainnet_next_or_rehearsal();
        assert!(next.forced_inclusion && forced_fallback(&next));
        let q = expect_in(&next, MAINNET_DOMAIN, fixture::fixture_empty_in(&next, MAINNET_DOMAIN).unwrap(), synthetic_context_for(program, 0))
            .unwrap();
        assert_eq!(q.forced, Some(Vec::new()));
        if !bloch_l2_evm::chainspec::MAINNET_NEXT_RULES_RELEASABLE {
            assert_eq!(q.expected.base.configuration, bloch_l2_evm::chainspec::REHEARSAL_CONFIGURATION_FORCED);
        }
        let v1 = ChainSpec::mainnet_v1();
        assert!(!forced_fallback(&v1));
        let q = expect_in(&v1, MAINNET_DOMAIN, fixture::fixture_empty_in(&v1, MAINNET_DOMAIN).unwrap(), synthetic_context_for(program, 0))
            .unwrap();
        assert_eq!(q.forced, None);
        let record = bloch_l2_evm::forced_inclusion::ForcedTransaction {
            record: bloch_l2_evm::forced_inclusion::ForcedRecord {
                l1_height: 1,
                l1_txid: [1; 32],
                envelope_hash: alloy_primitives::keccak256([0xde, 0xad]),
                gas_limit: 21_000,
            },
            envelope: vec![0xde, 0xad].into(),
        };
        assert!(expect_forced_in(&v1, MAINNET_DOMAIN, fixture::fixture_empty_in(&v1, MAINNET_DOMAIN).unwrap(), synthetic_context_for(program, 0), vec![record])
            .is_err());
    }

    /// B-3: the printed program follows both flags.
    #[test]
    fn the_program_name_follows_the_rules_and_the_witness() {
        let (v1, next) = (ChainSpec::mainnet_v1(), ChainSpec::mainnet_next_or_rehearsal());
        assert_eq!(program_name_for(Some(&next), true), "settlement_v3_mainnet_sparse");
        assert_eq!(program_name_for(Some(&v1), true), "settlement_v3_mainnet_v1_sparse");
        assert_eq!(program_name_for(Some(&next), false), "settlement_v3_mainnet");
        assert_eq!(program_name_for(Some(&v1), false), "settlement_v3_mainnet");
        assert_eq!(program_name_for(None, false), "settlement_v3");
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
