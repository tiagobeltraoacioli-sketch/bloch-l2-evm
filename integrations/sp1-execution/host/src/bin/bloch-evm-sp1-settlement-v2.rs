// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline-only qualification harness for the four-frame settlement V2 guest.
#[allow(dead_code)]
#[path = "../fixture.rs"]
mod fixture;
#[cfg(feature = "source-settlement")]
#[path = "../source_fixture.rs"]
mod source_fixture;

use alloy_primitives::B256;
#[cfg(feature = "source-settlement")]
use bloch_evm_sp1_host::source_settlement::SourceSettlement;
use bloch_evm_sp1_host::verification::{ProgramIdentity, QualifiedGroth16SettlementV2, TrustedProgram};
use bloch_l2_evm::{
    proof_statement::{execute_settlement_statement_v2, SettlementContextV2, SettlementStatementV2},
    ChainSpec,
};
use sp1_sdk::{Elf, LightProver, ProveRequest, Prover, ProverClient, SP1PublicValues, SP1Stdin};
use std::{error::Error, ffi::OsStr, fs, io, process::Command, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const QUALIFICATION_GNARK_IMAGE: &str =
    "ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d";

struct Qualification {
    execution: fixture::Fixture,
    context: SettlementContextV2,
    expected: SettlementStatementV2,
    #[cfg(feature = "source-settlement")]
    source: Option<SourceSettlement>,
}

fn stdin(fixture: &fixture::Fixture, context: SettlementContextV2) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&fixture.witness);
    stdin.write(&fixture.context);
    stdin.write_vec(alloy_rlp::encode(&fixture.body));
    stdin.write(&context);
    stdin
}

fn empty_qualification(identity: ProgramIdentity) -> Result<Qualification> {
    let execution = fixture::fixture_empty()?;
    let context = SettlementContextV2 {
        network: B256::repeat_byte(0x41),
        genesis: B256::repeat_byte(0x42),
        program_elf_keccak: identity.elf_keccak(),
        program_vkey_koalabear: identity.verifying_key_hash(),
        program_vkey_bn254: identity.verifying_key_bn254(),
        previous_settlement: B256::ZERO,
        l1_slot: 1,
        l1_height: 1,
        source_commitment: B256::repeat_byte(0x43),
        inbox_root: B256::repeat_byte(0x44),
        inbox_count: 0,
        consumed_start: 0,
        consumed_end: 0,
    };
    let expected = execute_settlement_statement_v2(
        &ChainSpec::testnet(),
        B256::repeat_byte(0xd3),
        &execution.witness,
        &execution.context,
        &execution.body,
        context,
    )?;
    Ok(Qualification {
        execution,
        context,
        expected,
        #[cfg(feature = "source-settlement")]
        source: None,
    })
}

#[cfg(feature = "source-settlement")]
fn source_qualification(identity: ProgramIdentity) -> Result<Qualification> {
    let fixture = source_fixture::source_contract()?;
    let mut registry = fixture.registry.clone();
    registry.apply(
        fixture.expected_source,
        fixture.position,
        &fixture.headers,
        &fixture.batch,
        &fixture.proofs,
    )?;
    let selected = registry.validate_v2_prefix(
        &ChainSpec::testnet(),
        0,
        &fixture.execution.header,
        &fixture.execution.body,
    )?;
    let range = selected.range();
    let anchor = selected.anchor();
    let context = SettlementContextV2 {
        network: selected.network(),
        genesis: selected.genesis(),
        program_elf_keccak: identity.elf_keccak(),
        program_vkey_koalabear: identity.verifying_key_hash(),
        program_vkey_bn254: identity.verifying_key_bn254(),
        previous_settlement: B256::ZERO,
        l1_slot: anchor.slot,
        l1_height: anchor.height,
        source_commitment: selected.source_commitment(),
        inbox_root: selected.inbox_root(),
        inbox_count: selected.inbox_count(),
        consumed_start: range.start,
        consumed_end: range.end,
    };
    let mut source = SourceSettlement::from_trusted_genesis(
        ChainSpec::testnet(),
        fixture.registry.network(),
        fixture.registry.genesis(),
        fixture.registry.domain(),
        identity,
        fixture.execution.parent.clone(),
        fixture.registry,
    )?;
    source.apply_source(
        fixture.expected_source,
        fixture.position,
        &fixture.headers,
        &fixture.batch,
        &fixture.proofs,
    )?;
    let expected = source.expected_statement_v2(&fixture.execution.header, &fixture.execution.body)?;
    let independently_executed = execute_settlement_statement_v2(
        &ChainSpec::testnet(),
        B256::repeat_byte(0xd3),
        &fixture.execution.witness,
        &fixture.execution.context,
        &fixture.execution.body,
        context,
    )?;
    if expected != independently_executed {
        return Err(io::Error::other("source coordinator and independently executed V2 statement differ").into());
    }
    Ok(Qualification {
        execution: fixture.execution,
        context,
        expected,
        source: Some(source),
    })
}

/// Public deterministic context exported by the native transition rehearsal.
/// This input selects a test fixture; it is not a production trust anchor.
fn native_qualification(identity: ProgramIdentity, text: &str) -> Result<Qualification> {
    let fields: Vec<_> = text.lines().collect();
    if text.len() > 512 || fields.len() != 7 {
        return Err(io::Error::other("native fixture requires exactly seven bounded fields").into());
    }
    let hash = |index: usize| -> Result<B256> {
        if fields[index].len() != 64 || !fields[index].bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::other("native fixture requires 32-byte hexadecimal identities").into());
        }
        let value: B256 = fields[index].parse()?;
        if value == B256::ZERO { return Err(io::Error::other("zero native fixture identity").into()); }
        Ok(value)
    };
    let slot: u64 = fields[3].parse()?;
    let height: u64 = fields[4].parse()?;
    if height == 0 || slot < height { return Err(io::Error::other("invalid native fixture position").into()); }
    let (execution, _, _) = fixture::execute_fixture_at(Default::default(), hash(2)?)?;
    let context = SettlementContextV2 {
        network: hash(0)?, genesis: hash(1)?,
        program_elf_keccak: identity.elf_keccak(), program_vkey_koalabear: identity.verifying_key_hash(),
        program_vkey_bn254: identity.verifying_key_bn254(), previous_settlement: B256::ZERO,
        l1_slot: slot, l1_height: height, source_commitment: hash(5)?, inbox_root: hash(6)?,
        inbox_count: 0, consumed_start: 0, consumed_end: 0,
    };
    let expected = execute_settlement_statement_v2(&ChainSpec::testnet(), B256::repeat_byte(0xd3),
        &execution.witness, &execution.context, &execution.body, context)?;
    Ok(Qualification { execution, context, expected,
        #[cfg(feature = "source-settlement")]
        source: None,
    })
}

/// A chained successor: block `n` exported from the persisted canonical L2
/// database (`bloch-evm-export`) plus the native request and the commitment of
/// the previously accepted native settlement. The artifact's sparse witness is
/// re-executed on decode; its anchor must be the native-selected source block.
#[cfg(feature = "node-artifact")]
fn native_artifact_qualification(identity: ProgramIdentity, text: &str, artifact: &std::path::Path) -> Result<Qualification> {
    let fields: Vec<_> = text.lines().collect();
    if text.len() > 600 || fields.len() != 8 {
        return Err(io::Error::other("native artifact request requires seven native fields and the previous settlement").into());
    }
    let hash = |index: usize, zero_ok: bool| -> Result<B256> {
        if fields[index].len() != 64 || !fields[index].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(io::Error::other("native request requires lowercase 32-byte hexadecimal identities").into());
        }
        let value: B256 = fields[index].parse()?;
        if value == B256::ZERO && !zero_ok { return Err(io::Error::other("zero native request identity").into()); }
        Ok(value)
    };
    let slot: u64 = fields[3].parse()?;
    let height: u64 = fields[4].parse()?;
    if height == 0 || slot < height { return Err(io::Error::other("invalid native request position").into()); }
    let previous_settlement = hash(7, true)?;
    let artifact = bloch_evm_sp1_host::artifact::load_selected_artifact(artifact)?;
    let number = artifact.header().number;
    if (number == 1) != (previous_settlement == B256::ZERO) {
        return Err(io::Error::other("only L2 block 1 may have no previous settlement").into());
    }
    if artifact.context().anchor_root != hash(2, false)? {
        return Err(io::Error::other("artifact anchor is not the native-selected source block").into());
    }
    if !artifact.body().transactions.is_empty() || !artifact.body().deposits.is_empty() {
        return Err(io::Error::other("native settlement currently accepts empty L2 blocks only").into());
    }
    let execution = fixture::Fixture {
        witness: artifact.witness().clone(), context: artifact.context().clone(), body: artifact.body().clone(),
        expected: artifact.expected(), parent: artifact.parent().clone(), header: artifact.header().clone(),
    };
    let context = SettlementContextV2 {
        network: hash(0, false)?, genesis: hash(1, false)?,
        program_elf_keccak: identity.elf_keccak(), program_vkey_koalabear: identity.verifying_key_hash(),
        program_vkey_bn254: identity.verifying_key_bn254(), previous_settlement,
        l1_slot: slot, l1_height: height, source_commitment: hash(5, false)?, inbox_root: hash(6, false)?,
        inbox_count: 0, consumed_start: 0, consumed_end: 0,
    };
    let expected = execute_settlement_statement_v2(&ChainSpec::testnet(), B256::repeat_byte(0xd3),
        &execution.witness, &execution.context, &execution.body, context)?;
    Ok(Qualification { execution, context, expected,
        #[cfg(feature = "source-settlement")]
        source: None,
    })
}

fn qualification(name: &str, identity: ProgramIdentity) -> Result<Qualification> {
    match name {
        "empty" => empty_qualification(identity),
        "native-empty" => {
            let path = std::env::var_os("BLOCH_NATIVE_L2_REQUEST")
                .ok_or("BLOCH_NATIVE_L2_REQUEST must name the exported public native fixture")?;
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.len() > 512 { return Err("invalid native fixture file".into()); }
            native_qualification(identity, &fs::read_to_string(path)?)
        },
        #[cfg(feature = "node-artifact")]
        "native-artifact" => {
            let request = std::env::var_os("BLOCH_NATIVE_L2_REQUEST")
                .ok_or("BLOCH_NATIVE_L2_REQUEST must name the native request with the previous settlement")?;
            let artifact = std::env::var_os("BLOCH_NATIVE_L2_ARTIFACT")
                .ok_or("BLOCH_NATIVE_L2_ARTIFACT must name the exported execution artifact")?;
            let metadata = fs::symlink_metadata(&request)?;
            if !metadata.is_file() || metadata.len() > 600 { return Err("invalid native request file".into()); }
            native_artifact_qualification(identity, &fs::read_to_string(request)?, std::path::Path::new(&artifact))
        },
        #[cfg(not(feature = "node-artifact"))]
        "native-artifact" => Err(io::Error::other("native-artifact requires --features node-artifact").into()),
        #[cfg(feature = "source-settlement")]
        "source-contract" => source_qualification(identity),
        #[cfg(not(feature = "source-settlement"))]
        "source-contract" => Err(io::Error::other("source-contract requires --features source-settlement").into()),
        _ => Err(io::Error::other("fixture must be empty, native-empty, native-artifact or source-contract").into()),
    }
}

fn report_verified_source(qualification: &mut Qualification, proof: &QualifiedGroth16SettlementV2) -> Result<()> {
    #[cfg(feature = "source-settlement")]
    if let Some(source) = qualification.source.as_mut() {
        let mark = source.advance_groth16_settlement_v2(
            proof,
            &qualification.execution.header,
            &qualification.execution.body,
        )?;
        if mark.next_sequence() == 0 || mark.payload().payload.consumed_end == 0 {
            return Err(io::Error::other("source-bound qualification did not consume a nonempty prefix").into());
        }
        println!(
            "Source-bound inert payload derived: consumed={}..{} source={:?} settlement={:?}",
            mark.payload().payload.consumed_start,
            mark.payload().payload.consumed_end,
            mark.source_commitment(),
            mark.settlement_commitment()
        );
    }
    #[cfg(not(feature = "source-settlement"))]
    let _ = (qualification, proof);
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: bloch-evm-sp1-settlement-v2 <execute|prove-groth16|verify-groth16> <empty|source-contract|native-empty|native-artifact> TRUSTED_SETTLEMENT_V2_ELF [PROOF_FILE]";
    let mode = args.first().map(String::as_str).ok_or(usage)?;
    let legacy_args = if mode == "execute" { 2 } else { 3 };
    let selected_args = legacy_args + 1;
    if !matches!(mode, "execute" | "prove-groth16" | "verify-groth16")
        || !matches!(args.len(), len if len == legacy_args || len == selected_args)
    {
        return Err(usage.into());
    }
    // The original fixture-less form remains an alias for `empty`.
    let (fixture_name, elf_index, proof_index) = if args.len() == legacy_args {
        ("empty", 1, 2)
    } else {
        (args[1].as_str(), 2, 3)
    };
    if mode == "prove-groth16" {
        require_release_gnark_environment(
            std::env::var_os("SP1_CIRCUIT_MODE").as_deref(),
            std::env::var_os("SP1_GNARK_IMAGE").as_deref(),
        )?;
        let docker = Command::new("docker").arg("info").output().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Docker is required by the pinned SP1 Gnark backend: {error}"),
            )
        })?;
        if !docker.status.success() {
            return Err(io::Error::other(format!(
                "Docker is not ready for the pinned SP1 Gnark backend: {}",
                String::from_utf8_lossy(&docker.stderr).trim()
            ))
            .into());
        }
    }

    let elf = Elf::from(fs::read(&args[elf_index])?);
    let trusted = TrustedProgram::from_trusted_elf(elf.clone()).await?;
    let identity = trusted.identity();
    let mut qualification = qualification(fixture_name, identity)?;
    let fixture = &qualification.execution;
    let settlement_context = qualification.context;
    let expected = qualification.expected;

    println!(
        "SYNTHETIC OFFLINE QUALIFICATION ONLY: no native source authority, consensus activation, finality or payouts"
    );
    println!("Expected settlement V2 statement: {expected:?}");

    if mode == "execute" {
        let executor = LightProver::new().await;
        let (public, report) = executor.execute(elf, stdin(fixture, settlement_context)).await?;
        if report.exit_code != 0 {
            return Err(io::Error::other("settlement V2 guest execution failed").into());
        }
        expected.check_expected(public.as_slice())?;
        println!(
            "Settlement V2 guest matched the independent host statement: {} instructions",
            report.total_instruction_count()
        );
        return Ok(());
    }

    if mode == "verify-groth16" {
        let qualified = trusted.verify_groth16_settlement_v2_file(&args[proof_index], &expected)?;
        report_verified_source(&mut qualification, &qualified)?;
        println!(
            "Real settlement V2 Groth16 proof verified offline: canonical={} bytes; no activation implied",
            qualified.canonical_proof_bytes()?.len()
        );
        return Ok(());
    }

    if fs::exists(&args[proof_index])? {
        return Err(io::Error::other("proof output already exists").into());
    }
    let prover = ProverClient::builder().cpu().build().await;
    let key = prover.setup(elf).await?;
    println!("Generating settlement V2 Groth16 proof with the explicit local CPU prover");
    let started = Instant::now();
    let proof = prover
        .prove(&key, stdin(fixture, settlement_context))
        .groth16()
        .await?;
    let qualified = trusted.verify_groth16_settlement_v2(proof.clone(), &expected)?;
    report_verified_source(&mut qualification, &qualified)?;
    if qualified.canonical_proof_bytes()?.len() != 356 {
        return Err(io::Error::other("unexpected canonical Groth16 proof length").into());
    }

    let mut wrong_expected = expected;
    wrong_expected.network[0] ^= 1;
    if trusted
        .verify_groth16_settlement_v2(proof.clone(), &wrong_expected)
        .is_ok()
    {
        return Err(io::Error::other("proof accepted an altered trusted expectation").into());
    }
    let mut tampered = proof.clone();
    let mut public = tampered.public_values.as_slice().to_vec();
    *public.last_mut().ok_or("proof has no public bytes")? ^= 1;
    tampered.public_values = SP1PublicValues::from(public.as_slice());
    if trusted.verify_groth16_settlement_v2(tampered, &expected).is_ok() {
        return Err(io::Error::other("proof accepted altered public values").into());
    }

    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[proof_index])?;
    bincode::serialize_into(&file, &proof)?;
    file.sync_all()?;
    let reopened = trusted.verify_groth16_settlement_v2_file(&args[proof_index], &expected)?;
    println!(
        "Settlement V2 Groth16 proof generated, persisted and reverified in {:?}: artifact={} bytes canonical={} bytes; no activation implied",
        started.elapsed(),
        file.metadata()?.len(),
        reopened.canonical_proof_bytes()?.len()
    );
    Ok(())
}

fn require_release_gnark_environment(circuit_mode: Option<&OsStr>, image: Option<&OsStr>) -> Result<()> {
    if circuit_mode.is_some_and(|mode| mode != "release") {
        return Err(io::Error::other(
            "settlement V2 Groth16 qualification requires release circuits; unset SP1_CIRCUIT_MODE or set it to release",
        )
        .into());
    }
    let image = image
        .and_then(OsStr::to_str)
        .ok_or_else(|| io::Error::other("SP1_GNARK_IMAGE must pin the qualification image by sha256 digest"))?;
    if image != QUALIFICATION_GNARK_IMAGE {
        return Err(io::Error::other(
            "SP1_GNARK_IMAGE does not match the reviewed qualification image digest",
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PINNED: &str = QUALIFICATION_GNARK_IMAGE;

    #[test]
    fn proving_environment_is_release_only_and_digest_pinned() {
        assert!(require_release_gnark_environment(None, Some(OsStr::new(PINNED))).is_ok());
        assert!(require_release_gnark_environment(Some(OsStr::new("release")), Some(OsStr::new(PINNED))).is_ok());
        assert!(require_release_gnark_environment(Some(OsStr::new("dev")), Some(OsStr::new(PINNED))).is_err());
        assert!(require_release_gnark_environment(None, None).is_err());
        assert!(
            require_release_gnark_environment(None, Some(OsStr::new("ghcr.io/succinctlabs/sp1-gnark:v6.1.0"))).is_err()
        );
        assert!(require_release_gnark_environment(
            None,
            Some(OsStr::new(
                "ghcr.io/succinctlabs/sp1-gnark@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ))
        )
        .is_err());
        assert!(require_release_gnark_environment(
            None,
            Some(OsStr::new(
                "ghcr.io/succinctlabs/sp1-gnark@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ))
        )
        .is_err());
    }

    #[cfg(feature = "source-settlement")]
    #[test]
    fn source_contract_fixture_is_nonempty_and_source_authenticated() {
        let fixture = source_fixture::source_contract().unwrap();
        let mut registry = fixture.registry.clone();
        registry
            .apply(
                fixture.expected_source,
                fixture.position,
                &fixture.headers,
                &fixture.batch,
                &fixture.proofs,
            )
            .unwrap();
        let selected = registry
            .validate_v2_prefix(
                &ChainSpec::testnet(),
                0,
                &fixture.execution.header,
                &fixture.execution.body,
            )
            .unwrap();
        assert_eq!(selected.range(), 0..1);
        assert_eq!(selected.inbox_count(), 1);
        assert_eq!(selected.source_commitment(), fixture.expected_source);
        assert_eq!(selected.statement(), fixture.execution.expected);

        let mut altered_batch = fixture.batch.clone();
        altered_batch.locations[0].transaction[0] ^= 1;
        let mut rejected = fixture.registry.clone();
        assert!(rejected
            .apply(
                fixture.expected_source,
                fixture.position,
                &fixture.headers,
                &altered_batch,
                &fixture.proofs,
            )
            .is_err());

        let mut wrong_body = fixture.execution.body.clone();
        wrong_body.deposits[0].recipient[0] ^= 1;
        let mut wrong_header = fixture.execution.header.clone();
        wrong_header.deposits_hash = wrong_body.deposits_hash();
        assert!(registry
            .validate_v2_prefix(&ChainSpec::testnet(), 0, &wrong_header, &wrong_body)
            .is_err());
        assert!(registry
            .validate_v2_prefix(
                &ChainSpec::testnet(),
                1,
                &fixture.execution.header,
                &fixture.execution.body,
            )
            .is_err());
    }
}
