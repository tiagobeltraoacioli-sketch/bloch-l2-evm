// SPDX-License-Identifier: MIT OR Apache-2.0
mod fixture;
#[cfg(feature = "source-settlement")]
mod source_fixture;

use bloch_evm_sp1_host::{
    settlement::{SettlementCursor, SettlementJournal, SettlementMark},
    verification::{load_proof, TrustedProgram},
};
use sp1_sdk::{Elf, LightProver, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof, SP1PublicValues, SP1Stdin};
use std::{error::Error, fs, io, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn inputs(fixture: &fixture::Fixture) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&fixture.witness);
    stdin.write(&fixture.context);
    stdin.write_vec(alloy_rlp::encode(&fixture.body));
    stdin
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "source-settlement feature also accepts fixture source-contract and verify-source source-contract TRUSTED_ELF PROOF_FILE; usage: bloch-evm-sp1-host fixture <empty|contract> | execute <empty|contract> TRUSTED_ELF | <prove|verify> <empty|contract> TRUSTED_ELF PROOF_FILE | settle <empty|contract> TRUSTED_ELF PROOF_FILE NEW_JOURNAL | verify-settlement <empty|contract> TRUSTED_ELF JOURNAL";
    let mode = args.first().map(String::as_str).ok_or(usage)?;
    let fixture = match args.get(1).map(String::as_str) {
        Some("empty") => fixture::fixture_empty()?,
        Some("contract") => fixture::fixture()?,
        #[cfg(feature = "source-settlement")]
        Some("source-contract") => source_fixture::source_contract()?.execution,
        _ => return Err(usage.into()),
    };
    let expected_args = match mode {
        "fixture" => 2,
        "execute" => 3,
        "prove" | "verify" | "verify-settlement" => 4,
        #[cfg(feature = "source-settlement")]
        "verify-source" => 4,
        "settle" => 5,
        _ => return Err(usage.into()),
    };
    if args.len() != expected_args {
        return Err(usage.into());
    }
    println!("SYNTHETIC DEV ONLY: local fixture/cursor; no native L1 provenance, settlement or payouts.");
    println!("Expected statement: {:?}", fixture.expected);
    if mode == "fixture" {
        return Ok(());
    }
    let elf = Elf::from(fs::read(&args[2])?);
    if mode == "execute" {
        println!("Initializing local SP1 executor");
        let client = LightProver::new().await;
        println!("Executing guest");
        let started = Instant::now();
        let (public, report) = client.execute(elf.clone(), inputs(&fixture)).await?;
        if report.exit_code != 0 {
            return Err(io::Error::other("guest execution failed").into());
        }
        fixture.expected.check_expected(public.as_slice())?;
        println!(
            "Guest matched host: {} instructions, {:?}",
            report.total_instruction_count(),
            started.elapsed()
        );

        // The real guest must abort for a false post-state and malformed body.
        let mut invalid = fixture.witness.clone();
        invalid.new_state_root = alloy_primitives::B256::ZERO;
        let mut bad_root = SP1Stdin::new();
        bad_root.write(&invalid);
        bad_root.write(&fixture.context);
        bad_root.write_vec(alloy_rlp::encode(&fixture.body));
        let mut malformed = SP1Stdin::new();
        malformed.write(&fixture.witness);
        malformed.write(&fixture.context);
        let mut body = alloy_rlp::encode(&fixture.body);
        body.push(0);
        malformed.write_vec(body);
        for (name, stdin) in [("false post-state", bad_root), ("trailing body bytes", malformed)] {
            let (_, report) = client.execute(elf.clone(), stdin).await?;
            if report.exit_code == 0 {
                return Err(io::Error::other(format!("guest accepted {name}")).into());
            }
            println!("Guest rejected {name}");
        }
        return Ok(());
    }

    let trusted = TrustedProgram::from_trusted_elf(elf.clone()).await?;
    if mode == "settle" || mode == "verify-settlement" {
        let anchor = SettlementCursor::from_trusted_anchor(
            bloch_l2_evm::ChainSpec::testnet(),
            fixture.expected.domain,
            trusted.identity(),
            fixture.parent.clone(),
        )?;
        if mode == "settle" {
            let verified = trusted.verify_file(&args[3], &fixture.expected)?;
            let mut journal = SettlementJournal::create(&args[4], anchor.clone())?;
            let floor = journal.append(&verified, &fixture.header)?;
            drop(journal);
            let recovered = SettlementJournal::open(&args[4], &trusted, anchor, floor)?;
            println!(
                "Local settlement persisted and reverified: {:?}",
                recovered.cursor().mark()
            );
        } else {
            // The floor comes from independently executed fixture selection, not
            // the untrusted journal's claimed cursor.
            let floor = SettlementMark {
                number: fixture.header.number,
                header_hash: fixture.header.hash(),
                state_root: fixture.header.state_root,
            };
            let recovered = SettlementJournal::open(&args[3], &trusted, anchor, floor)?;
            println!(
                "Local settlement reopened under independent fixture floor: {:?}",
                recovered.cursor().mark()
            );
        }
        return Ok(());
    }
    #[cfg(feature = "source-settlement")]
    if mode == "verify-source" {
        if args[1] != "source-contract" {
            return Err("verify-source requires source-contract".into());
        }
        let source = source_fixture::source_contract()?;
        let mut coordinated = bloch_evm_sp1_host::source_settlement::SourceSettlement::from_trusted_genesis(
            bloch_l2_evm::ChainSpec::testnet(),
            source.registry.network(),
            source.registry.genesis(),
            source.registry.domain(),
            trusted.identity(),
            fixture.parent.clone(),
            source.registry,
        )?;
        coordinated.apply_source(
            source.expected_source,
            source.position,
            &source.headers,
            &source.batch,
            &source.proofs,
        )?;
        let proof = trusted.verify_file(&args[3], &fixture.expected)?;
        let mark = coordinated.advance(&proof, &fixture.header, &fixture.body)?;
        println!("Synthetic source and core proof accepted atomically in memory: {mark:?}");
        if coordinated.advance(&proof, &fixture.header, &fixture.body).is_ok() {
            return Err("source coordinator accepted replay".into());
        }
        println!("Source replay rejected; no native authority or durable combined cursor claimed");
        return Ok(());
    }
    if mode == "verify" {
        trusted.verify_file(&args[3], &fixture.expected)?;
        println!("Core proof verified against trusted ELF and independently executed fixture");
        return Ok(());
    }

    // Refuse replacement before starting an expensive proving job.
    if fs::exists(&args[3])? {
        return Err(io::Error::other("proof output already exists").into());
    }
    // Explicit CPU builder: environment variables cannot select a mock or remote prover.
    println!("Initializing local SP1 CPU prover");
    let client = ProverClient::builder().cpu().build().await;
    println!("Setting up trusted guest key");
    let key = client.setup(elf).await?;
    println!("Generating core proof");
    let started = Instant::now();
    let proof = client.prove(&key, inputs(&fixture)).core().await?;
    let prove_time = started.elapsed();
    trusted.verify(proof.clone(), &fixture.expected)?;

    let mut wrong_expected = fixture.expected;
    wrong_expected.domain[0] ^= 1;
    if trusted.verify(proof.clone(), &wrong_expected).is_ok() {
        return Err(io::Error::other("accepted wrong trusted expectation").into());
    }
    let mut tampered = proof.clone();
    let mut public = tampered.public_values.as_slice().to_vec();
    *public.last_mut().ok_or("proof has no public bytes")? ^= 1;
    tampered.public_values = SP1PublicValues::from(public.as_slice());
    if client.verify(&tampered, key.verifying_key(), None).is_ok() {
        return Err(io::Error::other("accepted tampered proof public values").into());
    }
    drop(tampered);
    let mut truncated = proof.clone();
    if let SP1Proof::Core(shards) = &mut truncated.proof {
        shards.pop().ok_or("prover returned an empty core proof")?;
    }
    if client.verify(&truncated, key.verifying_key(), None).is_ok() {
        return Err(io::Error::other("accepted a core proof missing its final shard").into());
    }
    drop(truncated);
    let file = fs::OpenOptions::new().write(true).create_new(true).open(&args[3])?;
    bincode::serialize_into(&file, &proof)?;
    file.sync_all()?;
    let loaded = load_proof(&args[3])?;
    trusted.verify(loaded, &fixture.expected)?;
    println!(
        "Core proof accepted; altered expectation, public values and truncated core proof rejected; prove {:?}, {} bytes persisted",
        prove_time,
        file.metadata()?.len()
    );
    Ok(())
}
