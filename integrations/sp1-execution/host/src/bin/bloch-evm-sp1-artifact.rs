// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local artifact acceptance; selected canonical exports are not native authority.
use bloch_evm_sp1_host::{
    artifact::load_selected_artifact,
    settlement::{SettlementCursor, SettlementMark},
    verification::{load_proof, TrustedProgram},
    Result,
};
use bloch_execution_artifact::ExecutionArtifact;
use sp1_sdk::{
    Elf, LightProver, ProveRequest, Prover, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin,
};
use std::{fs, io, time::Instant};

fn inputs(artifact: &ExecutionArtifact) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(artifact.witness());
    stdin.write(artifact.context());
    stdin.write_vec(alloy_rlp::encode(artifact.body()));
    stdin
}
fn accept_successor(
    trusted: &TrustedProgram,
    artifact: &ExecutionArtifact,
    proof: SP1ProofWithPublicValues,
) -> Result<SettlementMark> {
    let token = trusted.verify(proof, &artifact.expected())?;
    let mut cursor = SettlementCursor::from_trusted_anchor(
        bloch_l2_evm::ChainSpec::testnet(),
        artifact.expected().domain,
        trusted.identity(),
        artifact.parent().clone(),
    )?;
    let initial = cursor.mark();
    let mut changed = artifact.header().clone();
    changed.state_root[0] ^= 1;
    if cursor.advance(&token, &changed).is_ok() || cursor.mark() != initial {
        return Err(io::Error::other("accepted changed selected header").into());
    }
    let mark = cursor.advance(&token, artifact.header())?;
    if cursor.advance(&token, artifact.header()).is_ok() || cursor.mark() != mark {
        return Err(io::Error::other("accepted successor replay").into());
    }
    Ok(mark)
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: bloch-evm-sp1-artifact execute TRUSTED_ARTIFACT TRUSTED_ELF | <prove|verify> TRUSTED_ARTIFACT TRUSTED_ELF PROOF_FILE";
    let mode = args.first().map(String::as_str).ok_or(usage)?;
    let count = match mode {
        "execute" => 3,
        "prove" | "verify" => 4,
        _ => return Err(usage.into()),
    };
    if args.len() != count {
        return Err(usage.into());
    }
    let artifact = load_selected_artifact(&args[1])?;
    let expected = artifact.expected();
    println!("LOCAL DEVELOPER ARTIFACT: testnet/domain D3; selected parent/source authority remains external.");
    println!("Expected statement from re-executed selected artifact: {expected:?}");
    let elf = Elf::from(fs::read(&args[2])?);
    if mode == "execute" {
        let client = LightProver::new().await;
        let started = Instant::now();
        let (public, report) = client.execute(elf.clone(), inputs(&artifact)).await?;
        if report.exit_code != 0 {
            return Err(io::Error::other("artifact guest failed").into());
        }
        expected.check_expected(public.as_slice())?;
        println!(
            "Guest matched selected artifact: {} instructions, {:?}",
            report.total_instruction_count(),
            started.elapsed()
        );
        let mut witness = artifact.witness().clone();
        witness.new_state_root[0] ^= 1;
        let mut bad_root = SP1Stdin::new();
        bad_root.write(&witness);
        bad_root.write(artifact.context());
        bad_root.write_vec(alloy_rlp::encode(artifact.body()));
        let mut bad_body = SP1Stdin::new();
        bad_body.write(artifact.witness());
        bad_body.write(artifact.context());
        let mut body = alloy_rlp::encode(artifact.body());
        body.push(0);
        bad_body.write_vec(body);
        for (name, input) in [("false post-state", bad_root), ("trailing body bytes", bad_body)] {
            let (_, report) = client.execute(elf.clone(), input).await?;
            if report.exit_code == 0 {
                return Err(io::Error::other(format!("guest accepted {name}")).into());
            }
            println!("Guest rejected {name}");
        }
        return Ok(());
    }
    let trusted = TrustedProgram::from_trusted_elf(elf.clone()).await?;
    if mode == "verify" {
        let mark = accept_successor(&trusted, &artifact, load_proof(&args[3])?)?;
        println!("Core proof verified against trusted ELF and selected re-executed block artifact; local trusted-parent successor {mark:?}; changed-header/replay rejected");
        return Ok(());
    }
    match fs::symlink_metadata(&args[3]) {
        Ok(_) => return Err(io::Error::other("proof output already exists").into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    println!("Initializing explicit local CPU core prover");
    let client = ProverClient::builder().cpu().build().await;
    let key = client.setup(elf).await?;
    println!("Generating artifact core proof");
    let started = Instant::now();
    let proof = client.prove(&key, inputs(&artifact)).core().await?;
    let prove_time = started.elapsed();
    accept_successor(&trusted, &artifact, proof.clone())?;
    let mut wrong = expected;
    wrong.header_hash[0] ^= 1;
    if trusted.verify(proof.clone(), &wrong).is_ok() {
        return Err(io::Error::other("accepted wrong expected header").into());
    }
    let mut tampered = proof.clone();
    let mut public = tampered.public_values.as_slice().to_vec();
    *public.last_mut().ok_or("empty proof public values")? ^= 1;
    tampered.public_values = SP1PublicValues::from(public.as_slice());
    if trusted.verify(tampered, &expected).is_ok() {
        return Err(io::Error::other("accepted tampered public values").into());
    }
    let mut truncated = proof.clone();
    if let SP1Proof::Core(shards) = &mut truncated.proof {
        shards.pop().ok_or("empty core proof")?;
    }
    if trusted.verify(truncated, &expected).is_ok() {
        return Err(io::Error::other("accepted missing final core shard").into());
    }
    let file = fs::OpenOptions::new().write(true).create_new(true).open(&args[3])?;
    bincode::serialize_into(&file, &proof)?;
    file.sync_all()?;
    accept_successor(&trusted, &artifact, load_proof(&args[3])?)?;
    println!("Artifact core proof accepted; changed header/public bytes/missing shard rejected; prove {:?}, {} bytes persisted", prove_time, file.metadata()?.len());
    Ok(())
}
