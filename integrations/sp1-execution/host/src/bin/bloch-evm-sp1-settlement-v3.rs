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

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
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
        let executor = LightProver::new().await;
        let started = Instant::now();
        let (public, report) = executor.execute(elf, stdin(&qualification)).calculate_gas(true).await?;
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
