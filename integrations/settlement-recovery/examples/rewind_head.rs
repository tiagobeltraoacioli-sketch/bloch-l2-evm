// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test tool: remove the head block of a PRIVATE L2 database, named by hash, as a rewind or a foreign recovery
//! replaces it. For RPC tests across a replaced head. Not in any release.
//!
//!   rewind_head TARGET HEAD_HASH DOMAIN_HEX GENESIS_TIME
use alloy_primitives::B256;
use bloch_reth_execution::{BlochProviderFactory, L2Network};
use reth_db::mdbx::{open_db, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, StaticFileProvider},
    BlockExecutionWriter, BlockNumReader, DBProvider, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
};
use reth_tasks::{RuntimeBuilder, RuntimeConfig};
use std::{path::Path, sync::Arc};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [target, hash, domain, genesis_time] = args.as_slice() else { return Err("usage: TARGET HEAD_HASH DOMAIN GENESIS_TIME".into()) };
    let expected: B256 = hash.trim_start_matches("0x").parse().map_err(|_| "HEAD_HASH")?;
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
    let number = factory.best_block_number().map_err(|e| e.to_string())?;
    let head = factory.sealed_header(number).map_err(|e| e.to_string())?.ok_or("head missing")?;
    if number == 0 || head.hash() != expected {
        return Err("the head is not the named block".into());
    }
    let writer = factory.database_provider_rw().map_err(|e| e.to_string())?;
    writer.remove_block_and_execution_above(number - 1).map_err(|e| e.to_string())?;
    writer.commit().map_err(|e| e.to_string())?;
    let parent = factory.sealed_header(number - 1).map_err(|e| e.to_string())?.ok_or("parent missing")?;
    println!("{{\"number\":{},\"hash\":\"{}\"}}", parent.0.number, alloy_primitives::hex::encode(parent.hash()));
    Ok(())
}
