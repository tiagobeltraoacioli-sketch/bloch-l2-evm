// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline qualification harness for the settlement V3 guest.
//!
//! Differs from `bloch-evm-sp1-settlement-v2` in exactly two ways: the guest
//! commits the 766-byte V3 statement, and `native-artifact` does NOT refuse L2
//! blocks with user transactions. Deposits must still equal the consumed
//! native inbox range; the native chain checks them via `deposits_hash`.
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
    let expected = execute_settlement_statement_v3(
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
    let artifact = bloch_evm_sp1_host::artifact::load_selected_artifact(artifact)?;
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
        "empty" => expect(fixture::fixture_empty()?, synthetic_context(identity, 0)),
        // Deposit plus a signed deploy and call: two user transactions.
        "contract" => expect(fixture::fixture()?, synthetic_context(identity, 1)),
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: bloch-evm-sp1-settlement-v3 <execute|prove-groth16|verify-groth16> <empty|contract|native-artifact> TRUSTED_SETTLEMENT_V3_ELF [PROOF_FILE]";
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
        "Expected settlement V3 statement: user_tx_count={} deposits_hash={:?} transactions_root={:?}",
        expected.user_tx_count, expected.deposits_hash, expected.transactions_root
    );

    if mode == "execute" {
        let executor = LightProver::new().await;
        let started = Instant::now();
        let (public, report) = executor.execute(elf, stdin(fixture, context)).await?;
        if report.exit_code != 0 {
            return Err(io::Error::other("settlement V3 guest execution failed").into());
        }
        expected.check_expected(public.as_slice())?;
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

    /// The V3 harness accepts the user-transaction fixture that V2's
    /// `native-artifact` path refuses, and derives a matching statement.
    #[test]
    fn contract_fixture_settles_user_transactions_under_v3() {
        let program = [B256::repeat_byte(9), B256::repeat_byte(10), B256::repeat_byte(11)];
        let q = expect(fixture::fixture().unwrap(), synthetic_context_for(program, 1)).unwrap();
        assert_eq!(q.expected.user_tx_count, 2);
        assert_eq!(q.expected.base.consumed_end, 1);
        assert_eq!(q.expected.deposits_hash, q.execution.body.deposits_hash());
        assert_eq!(SettlementStatementV3::decode(&q.expected.encode()).unwrap(), q.expected);
    }
}
