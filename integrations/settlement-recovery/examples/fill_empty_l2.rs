// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test tool: extend a PRIVATE L2 database with COUNT empty blocks in one process, printing one JSON
//! line per block. Long-history tests of the settled RPC need tens of thousands of real blocks, and
//! `bloch-l2-produce-dev extend` costs a process start per block. Not in any release.
//!
//!   fill_empty_l2 TARGET COUNT DOMAIN_HEX GENESIS_TIME [TXS_PER_BLOCK KEY_HEX NONCE]
//! (mainnet rules, TARGET already initialized). With transactions, KEY pays plain transfers to a new address each,
//! so the state grows.
use alloy_consensus::private::alloy_eips::eip2718::Encodable2718;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{hex, B256};
use bloch_l2_evm::node_execution::select::SelectionLimits;
use bloch_reth_execution::{BlochNextBlockEnvCtx, BlochProviderFactory, CanonicalCoordinator, L2Network};
use reth_db::mdbx::{open_db, DatabaseArguments};
use reth_provider::{
    providers::{RocksDBBuilder, StaticFileProvider},
    ProviderFactory,
};
use reth_tasks::{RuntimeBuilder, RuntimeConfig};
use std::{path::Path, sync::Arc};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (target, count, domain, genesis_time) = match args.as_slice() {
        [a, b, c, d] | [a, b, c, d, _, _, _] => (a, b, c, d),
        _ => return Err("usage: TARGET COUNT DOMAIN GENESIS_TIME [TXS_PER_BLOCK KEY_HEX NONCE]".into()),
    };
    let per_block: u64 = args.get(4).map_or(Ok(0), |v| v.parse()).map_err(|_| "TXS_PER_BLOCK")?;
    let key = args
        .get(5)
        .map(|k| {
            hex::decode(k)
                .ok()
                .and_then(|b| k256::ecdsa::SigningKey::from_slice(&b).ok())
                .ok_or("KEY_HEX")
        })
        .transpose()?;
    let mut nonce: u64 = args.get(6).map_or(Ok(0), |v| v.parse()).map_err(|_| "NONCE")?;
    let mut fresh = 0u64;
    let count: u64 = count.parse().map_err(|_| "COUNT")?;
    let network = L2Network::parse("mainnet", Some(domain), Some(genesis_time))?;
    let runtime = RuntimeBuilder::new(RuntimeConfig::default())
        .build()
        .map_err(|e| e.to_string())?;
    let path = Path::new(target);
    let db = open_db(path.join("db"), DatabaseArguments::default()).map_err(|e| e.to_string())?;
    let factory: BlochProviderFactory = ProviderFactory::new(
        Arc::new(db),
        Arc::new(network.chain_spec().map_err(|e| e.to_string())?),
        StaticFileProvider::read_write(path.join("static")).map_err(|e| e.to_string())?,
        RocksDBBuilder::new(path.join("rocks"))
            .with_default_tables()
            .build()
            .map_err(|e| e.to_string())?,
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
        let tip = match &key {
            None => coordinator
                .extend(head.hash(), attributes, vec![])
                .map_err(|e| e.to_string())?,
            Some(key) => {
                let mut pending = Vec::new();
                for _ in 0..per_block {
                    fresh += 1;
                    let mut to = [0x55u8; 20];
                    to[12..].copy_from_slice(&fresh.to_be_bytes());
                    let tx = TxEip1559 {
                        chain_id: network.rules.chain_id,
                        nonce,
                        to: alloy_primitives::TxKind::Call(to.into()),
                        value: alloy_primitives::U256::from(1u64),
                        gas_limit: 21_000,
                        max_fee_per_gas: 4_000_000_000,
                        max_priority_fee_per_gas: 100_000_000,
                        ..Default::default()
                    };
                    nonce += 1;
                    let signature: alloy_primitives::Signature = key
                        .sign_prehash_recoverable(tx.signature_hash().as_slice())
                        .map_err(|e| e.to_string())?
                        .into();
                    pending.push(TxEnvelope::from(tx.into_signed(signature)).encoded_2718().into());
                }
                let limits = SelectionLimits::protocol(&network.rules);
                let (tip, selection) = coordinator
                    .extend_with_pending(head.hash(), attributes, &pending, limits)
                    .map_err(|e| e.to_string())?;
                if selection.transactions.len() != pending.len() {
                    return Err(format!(
                        "block {}: {} of {} transactions",
                        tip.0.number,
                        selection.transactions.len(),
                        pending.len()
                    ));
                }
                tip
            }
        };
        println!(
            "{{\"number\":{},\"hash\":\"{}\",\"state_root\":\"{}\"}}",
            tip.0.number,
            hex::encode(tip.hash()),
            hex::encode(tip.0.state_root)
        );
    }
    Ok(())
}
