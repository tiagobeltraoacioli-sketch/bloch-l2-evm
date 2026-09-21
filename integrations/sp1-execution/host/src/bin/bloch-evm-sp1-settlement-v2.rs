// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline-only qualification harness for the four-frame settlement V2 guest.
#[allow(dead_code)]
#[path = "../fixture.rs"]
mod fixture;

use alloy_primitives::B256;
use bloch_evm_sp1_host::verification::TrustedProgram;
use bloch_l2_evm::{
    proof_statement::{execute_settlement_statement_v2, SettlementContextV2},
    ChainSpec,
};
use sp1_sdk::{Elf, LightProver, ProveRequest, Prover, ProverClient, SP1PublicValues, SP1Stdin};
use std::{error::Error, ffi::OsStr, fs, io, process::Command, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn stdin(fixture: &fixture::Fixture, context: SettlementContextV2) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&fixture.witness);
    stdin.write(&fixture.context);
    stdin.write_vec(alloy_rlp::encode(&fixture.body));
    stdin.write(&context);
    stdin
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: bloch-evm-sp1-settlement-v2 <execute|prove-groth16|verify-groth16> TRUSTED_SETTLEMENT_V2_ELF [PROOF_FILE]";
    let mode = args.first().map(String::as_str).ok_or(usage)?;
    let expected_args = if mode == "execute" { 2 } else { 3 };
    if !matches!(mode, "execute" | "prove-groth16" | "verify-groth16") || args.len() != expected_args {
        return Err(usage.into());
    }
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

    let elf = Elf::from(fs::read(&args[1])?);
    let trusted = TrustedProgram::from_trusted_elf(elf.clone()).await?;
    let identity = trusted.identity();
    let fixture = fixture::fixture_empty()?;
    let settlement_context = SettlementContextV2 {
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
        &fixture.witness,
        &fixture.context,
        &fixture.body,
        settlement_context,
    )?;

    println!(
        "SYNTHETIC OFFLINE QUALIFICATION ONLY: no native source authority, consensus activation, finality or payouts"
    );
    println!("Expected settlement V2 statement: {expected:?}");

    if mode == "execute" {
        let executor = LightProver::new().await;
        let (public, report) = executor.execute(elf, stdin(&fixture, settlement_context)).await?;
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
        let qualified = trusted.verify_groth16_settlement_v2_file(&args[2], &expected)?;
        println!(
            "Real settlement V2 Groth16 proof verified offline: canonical={} bytes; no activation implied",
            qualified.canonical_proof_bytes()?.len()
        );
        return Ok(());
    }

    if fs::exists(&args[2])? {
        return Err(io::Error::other("proof output already exists").into());
    }
    let prover = ProverClient::builder().cpu().build().await;
    let key = prover.setup(elf).await?;
    println!("Generating settlement V2 Groth16 proof with the explicit local CPU prover");
    let started = Instant::now();
    let proof = prover
        .prove(&key, stdin(&fixture, settlement_context))
        .groth16()
        .await?;
    let qualified = trusted.verify_groth16_settlement_v2(proof.clone(), &expected)?;
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

    let file = fs::OpenOptions::new().write(true).create_new(true).open(&args[2])?;
    bincode::serialize_into(&file, &proof)?;
    file.sync_all()?;
    let reopened = trusted.verify_groth16_settlement_v2_file(&args[2], &expected)?;
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
    let prefix = "ghcr.io/succinctlabs/sp1-gnark@sha256:";
    let digest = image
        .strip_prefix(prefix)
        .ok_or_else(|| io::Error::other("SP1_GNARK_IMAGE must pin ghcr.io/succinctlabs/sp1-gnark by digest"))?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(io::Error::other("SP1_GNARK_IMAGE contains a non-canonical sha256 digest").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PINNED: &str =
        "ghcr.io/succinctlabs/sp1-gnark@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn proving_environment_is_release_only_and_digest_pinned() {
        assert!(require_release_gnark_environment(None, Some(OsStr::new(PINNED))).is_ok());
        assert!(require_release_gnark_environment(Some(OsStr::new("release")), Some(OsStr::new(PINNED))).is_ok());
        assert!(require_release_gnark_environment(Some(OsStr::new("dev")), Some(OsStr::new(PINNED))).is_err());
        assert!(require_release_gnark_environment(None, None).is_err());
        assert!(require_release_gnark_environment(
            None,
            Some(OsStr::new("ghcr.io/succinctlabs/sp1-gnark:v6.1.0"))
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
}
