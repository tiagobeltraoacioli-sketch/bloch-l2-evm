// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test tool: extend a PRIVATE L2 database with COUNT empty blocks in one process, printing one JSON
//! line per block. Long-history tests of the settled RPC need tens of thousands of real blocks, and
//! `bloch-l2-produce-dev extend` costs a process start per block. Not in any release.
//!
//!   fill_empty_l2 TARGET COUNT DOMAIN_HEX GENESIS_TIME   (mainnet rules, TARGET already initialized)
use bloch_reth_execution::{BlochNextBlockEnvCtx, BlochProviderFactory, CanonicalCoordinator, L2Network};
use alloy_primitives::{hex, B256};
use reth_db::mdbx::{open_db, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, StaticFileProvider},
    ProviderFactory,
};
use reth_tasks::{RuntimeBuilder, RuntimeConfig};
use std::{path::Path, sync::Arc};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [target, count, domain, genesis_time] = args.as_slice() else { return Err("usage: TARGET COUNT DOMAIN GENESIS_TIME".into()) };
    let count: u64 = count.parse().map_err(|_| "COUNT")?;
    let network = L2Network::parse("mainnet", Some(domain), Some(genesis_time))?;
    let runtime = RuntimeBuilder::new(RuntimeConfig::default()).build().map_err(|e| e.to_string())?;
    let path = Path::new(target);
    let db = open_db(path.join("db"), DatabaseArguments::default()).map_err(|e| e.to_string())?;
    let factory: BlochProviderFactory = ProviderFactory::new(
        Arc::new(db),
        Arc::new(network.chain_spec().map_err(|e| e.to_string())?),
        StaticFileProvider::read_write(path.join("static")).map_err(|e| e.to_string())?,
        RocksDBBuilder::new(path.join("rocks")).with_default_tables().build().map_err(|e| e.to_string())?,
        runtime.clone(),
    )
    .map_err(|e| e.to_string())?;
    let mut coordinator = CanonicalCoordinator::attach(factory).map_err(|e| e.to_string())?;
    for _ in 0..count {
        let head = coordinator.head().clone();
        let attributes = BlochNextBlockEnvCtx {
            timestamp: head.0.timestamp + 1,
            prevrandao: B256::repeat_byte(7),
            anchor_root: B256::repeat_byte(0xab),
            deposits: vec![],
        };
        let tip = coordinator.extend(head.hash(), attributes, vec![]).map_err(|e| e.to_string())?;
        println!(
            "{{\"number\":{},\"hash\":\"{}\",\"state_root\":\"{}\"}}",
            tip.0.number,
            hex::encode(tip.hash()),
            hex::encode(tip.0.state_root)
        );
    }
    Ok(())
}
