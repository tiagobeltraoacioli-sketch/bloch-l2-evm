// SPDX-License-Identifier: MIT OR Apache-2.0
//! Derive the exact V2 genesis identity from a canonical frozen input artifact.

use alloy_primitives::B256;
use bloch_l2_evm::{
    node_execution::{genesis_v2, node_head},
    ChainSpec,
};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::Path, process, str::FromStr};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FrozenGenesis {
    #[serde(rename = "chainId")]
    chain_id: u64,
    domain: String,
    #[serde(rename = "executionProfile")]
    execution_profile: String,
    schema: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct DerivedIdentity {
    #[serde(rename = "blockHash")]
    block_hash: String,
    #[serde(rename = "buildSourceRevision")]
    build_source_revision: String,
    #[serde(rename = "chainId")]
    chain_id: u64,
    domain: String,
    #[serde(rename = "executionProfile")]
    execution_profile: String,
    #[serde(rename = "stateRoot")]
    state_root: String,
    timestamp: u64,
}

fn derive(path: &Path) -> Result<DerivedIdentity, String> {
    let build_source_revision = option_env!("BLOCH_L2_SOURCE_REVISION")
        .filter(|value| {
            value.len() == 40
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or("identity verifier was built without a lowercase 40-hex BLOCH_L2_SOURCE_REVISION")?;
    let bytes = fs::read(path).map_err(|error| format!("cannot read frozen genesis: {error}"))?;
    if bytes.len() > 1024 * 1024 {
        return Err("frozen genesis exceeds the size limit".into());
    }
    let input: FrozenGenesis =
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid frozen genesis JSON: {error}"))?;
    let mut canonical = serde_json::to_vec(&input).map_err(|error| error.to_string())?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("frozen genesis must use canonical field order, compact JSON and one trailing newline".into());
    }
    if input.schema != "bloch.l2.frozen-genesis.v1" {
        return Err("unsupported frozen genesis schema".into());
    }
    if input.execution_profile != "bloch-l2-cancun-zero-issuance-v1" {
        return Err("unsupported execution profile".into());
    }
    if input.chain_id != 700_771 {
        return Err("frozen genesis chainId must be 700771".into());
    }
    if input.timestamp == 0 {
        return Err("production genesis timestamp must be nonzero".into());
    }
    let domain = B256::from_str(&input.domain).map_err(|_| "domain must be a lowercase 32-byte 0x hash")?;
    if domain == B256::ZERO || format!("{domain:#x}") != input.domain {
        return Err("domain must be a nonzero lowercase 32-byte 0x hash".into());
    }
    let spec = ChainSpec::testnet();
    spec.validate().map_err(|error| error.to_string())?;
    if spec.chain_id != input.chain_id {
        return Err("compiled execution profile has a different chain id".into());
    }
    let state = genesis_v2(&spec, input.timestamp).map_err(|error| error.to_string())?;
    let header = node_head(&spec, domain, &state).map_err(|error| error.to_string())?;
    if header.state_root != state.state_root() {
        return Err("internal genesis state/header root mismatch".into());
    }
    Ok(DerivedIdentity {
        block_hash: format!("{:#x}", header.hash()),
        build_source_revision: build_source_revision.into(),
        chain_id: spec.chain_id,
        domain: format!("{domain:#x}"),
        execution_profile: input.execution_profile,
        state_root: format!("{:#x}", state.state_root()),
        timestamp: input.timestamp,
    })
}

fn main() {
    let arguments: Vec<_> = env::args_os().collect();
    if arguments.len() != 2 {
        eprintln!("usage: bloch-genesis-identity <canonical-frozen-genesis.json>");
        process::exit(2);
    }
    match derive(Path::new(&arguments[1])) {
        Ok(identity) => println!("{}", serde_json::to_string(&identity).expect("identity serialization")),
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}
