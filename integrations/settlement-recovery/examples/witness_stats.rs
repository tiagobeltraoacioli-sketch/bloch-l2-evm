// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test tool: what an execution artifact's witness holds, per account, to trace what a proof pays for. Not in any release.
//!
//!   witness_stats ARTIFACT DOMAIN_HEX GENESIS_TIME
use bloch_execution_artifact::ExecutionArtifact;
use bloch_reth_execution::L2Network;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path, domain, genesis_time] = args.as_slice() else { return Err("usage: ARTIFACT DOMAIN GENESIS_TIME".into()) };
    let network = L2Network::parse("mainnet", Some(domain), Some(genesis_time))?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let artifact = ExecutionArtifact::decode(&bytes, &network.rules, network.domain).map_err(|e| e.to_string())?;
    let witness = artifact.witness();
    let proof: usize = witness.proof.values().map(|node| node.len()).sum();
    println!("artifact {} bytes, proof nodes {} ({proof} bytes), absent {}", bytes.len(), witness.proof.len(), witness.absent_accounts.len());
    for account in &witness.pre_accounts {
        println!("{} storage_slots={} code={}", account.address, account.storage.len(), account.code.len());
    }
    Ok(())
}
