// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read a connector checkpoint and exercise source-bound native EVM execution.
//! Empty, zero-value batch only: no network transaction or deposit is created.
use alloy_primitives::B256;
use bloch_l2_evm::genesis4::{prepare_source_batch, verify_source_batch, ReportedSource};
use bloch_l2_evm::{execute_signed_block, generate_signed_batch_witness, ChainSpec, L2State};
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("Usage: genesis4_source CHECKPOINT_JSON")?;
    let bytes = fs::read(path)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("checkpoint exceeds 2 MiB".into());
    }
    let record: serde_json::Value = serde_json::from_slice(&bytes)?;
    if record["schema"] != "bloch.genesis4.source/1" || record["trust"] != "operator-rpc-corroborated" {
        return Err("not a Genesis-4 connector record".into());
    }
    let source = ReportedSource {
        network_id: u32::try_from(record["network_id"].as_u64().ok_or("network_id")?)?,
        genesis_root: record["genesis_root"].as_str().ok_or("genesis_root")?.parse()?,
        block_hash: record["block"]["block_id"].as_str().ok_or("block_id")?.parse()?,
        slot: record["block"]["slot"].as_u64().ok_or("slot")?,
    };
    let spec = ChainSpec::testnet();
    let mut state = L2State::genesis(&spec);
    let pre_root = state.state_root();
    let input = prepare_source_batch(&spec, &state, &source, vec![]).map_err(|error| format!("source: {error:?}"))?;
    let (witness, _) =
        generate_signed_batch_witness(&state, &spec, &input).map_err(|error| format!("witness: {error:?}"))?;
    let verified = verify_source_batch(&spec, &source, B256::ZERO, pre_root, &witness, &input)
        .map_err(|error| format!("verify: {error:?}"))?;
    let executed = execute_signed_block(&spec, &mut state, &input)?;
    if executed.state_root != verified.new_state_root {
        return Err("execution mismatch".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "mode": "source-bound-zero-value-replay", "bloch_source": source.block_hash.to_string(),
            "bloch_slot": source.slot, "l2_block_hash": verified.block_hash.to_string(),
            "state_root": verified.new_state_root.to_string(), "execution_replayed": true,
            "settled_on_bloch": false, "deposits_enabled": false
        })
    );
    Ok(())
}
