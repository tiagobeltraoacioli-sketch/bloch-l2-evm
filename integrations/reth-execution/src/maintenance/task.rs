// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bloch adaptation of Reth v2.4.1 `crates/transaction-pool/src/maintain.rs`.
//! Upstream revision: 8eb210175687c9f0c889a3b6795c16781d830e3a.
//! See `third-party/RETH-LICENSE-MIT` for upstream attribution.
//! Retains canonical account updates, reorg reinsertion, batched asynchronous
//! reloads and expiry. Blob maintenance is omitted: Bloch rejects blob transactions.
//! Unlike the pinned upstream loop, reload results are bound to their requested head.
use crate::{BlochChainSpec, BlochNodeBlock, BlochNodeHeader, BlochNodePrimitives};
use alloy_consensus::{transaction::TxHashRef, BlockHeader};
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{map::AddressSet, Address, B256};
use futures_util::{Stream, StreamExt};
use reth_chain_state::CanonStateNotification;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_execution_types::ChangedAccount;
use reth_primitives_traits::{transaction::signed::SignedTransaction, SealedHeader};
use reth_provider::{BlockReaderIdExt, StateProviderFactory};
use reth_tasks::Runtime;
use reth_transaction_pool::{
    maintain::MaintainPoolConfig, BlockInfo, CanonicalStateUpdate, EthPooledTransaction, PoolTransaction,
    PoolUpdateKind, TransactionPoolExt,
};
use std::time::Duration;
use tokio::sync::oneshot;

struct ReloadResult {
    at: B256,
    requested: Vec<Address>,
    accounts: Vec<ChangedAccount>,
    failed: Vec<Address>,
}

impl ReloadResult {
    fn accept(self, current: B256, dirty: &mut AddressSet) -> Option<Vec<ChangedAccount>> {
        if self.at != current {
            dirty.extend(self.requested);
            return None;
        }
        dirty.extend(self.failed);
        Some(self.accounts)
    }
}

fn load_accounts<C: StateProviderFactory>(client: &C, at: B256, requested: Vec<Address>) -> ReloadResult {
    let mut result = ReloadResult {
        at,
        requested,
        accounts: vec![],
        failed: vec![],
    };
    match client.history_by_block_hash(at) {
        Ok(state) => {
            for &address in &result.requested {
                match state.basic_account(&address) {
                    Ok(account) => result.accounts.push(account.map_or_else(
                        || ChangedAccount::empty(address),
                        |account| ChangedAccount {
                            address,
                            nonce: account.nonce,
                            balance: account.balance,
                        },
                    )),
                    Err(_) => result.failed.push(address),
                }
            }
        }
        Err(_) => result.failed.clone_from(&result.requested),
    }
    result
}

pub(super) async fn run<C, P, S>(client: C, pool: P, mut events: S, runtime: Runtime, config: MaintainPoolConfig)
where
    C: StateProviderFactory
        + BlockReaderIdExt<Header = BlochNodeHeader>
        + ChainSpecProvider<ChainSpec = BlochChainSpec>
        + Clone
        + 'static,
    P: TransactionPoolExt<Transaction = EthPooledTransaction, Block = BlochNodeBlock> + 'static,
    S: Stream<Item = CanonStateNotification<BlochNodePrimitives>> + Send + Unpin,
{
    if let Ok(Some(header)) = client.header_by_number_or_tag(BlockNumberOrTag::Latest) {
        let header = SealedHeader::seal_slow(header);
        pool.set_block_info(BlockInfo {
            block_gas_limit: header.gas_limit(),
            last_seen_block_hash: header.hash(),
            last_seen_block_number: header.number(),
            pending_basefee: client
                .chain_spec()
                .next_block_base_fee(header.header(), header.timestamp())
                .unwrap_or_default(),
            pending_blob_fee: None,
        });
    }
    let mut dirty = AddressSet::default();
    let mut drifted = false;
    let mut first_event = true;
    let mut reload: Option<oneshot::Receiver<ReloadResult>> = None;
    // Failed providers retry on ticks, not an unbounded ready-future loop.
    let mut retry = tokio::time::interval(Duration::from_millis(100));
    let mut may_reload = true;
    let mut expiry = tokio::time::interval(config.max_tx_lifetime);
    loop {
        if drifted {
            dirty.extend(pool.unique_senders());
            drifted = false;
        }
        if may_reload && reload.is_none() && !dirty.is_empty() {
            let requested: Vec<_> = dirty.iter().copied().take(config.max_reload_accounts).collect();
            for address in &requested {
                dirty.remove(address);
            }
            let at = pool.block_info().last_seen_block_hash;
            let client = client.clone();
            let (send, receive) = oneshot::channel();
            runtime.spawn_blocking_task(async move {
                let _ = send.send(load_accounts(&client, at, requested));
            });
            reload = Some(receive);
            may_reload = false;
        }
        tokio::select! {
            result = async { reload.as_mut().expect("guarded reload").await }, if reload.is_some() => {
                reload = None;
                match result {
                    Ok(result) => {
                        if let Some(accounts) = result.accept(pool.block_info().last_seen_block_hash, &mut dirty) {
                            pool.update_accounts(accounts);
                        }
                    }
                    Err(_) => drifted = true,
                }
            }
            _ = retry.tick() => { may_reload = true; }
            _ = expiry.tick() => {
                let now = std::time::Instant::now();
                let expired = pool.queued_transactions().into_iter().filter(|tx|
                    (tx.origin.is_external() || config.no_local_exemptions)
                        && now.duration_since(tx.timestamp) > config.max_tx_lifetime)
                    .map(|tx| *tx.hash()).collect();
                pool.remove_transactions(expired);
            }
            event = events.next() => {
                let Some(event) = event else { break };
                if first_event { drifted = true; first_event = false; }
                let (new, old) = match event {
                    CanonStateNotification::Commit { new } => (new, None),
                    CanonStateNotification::Reorg { new, old } => (new, Some(old)),
                };
                // Empty replacement notifications cannot identify a new tip. The
                // canonical coordinator must supply an actual replacement segment.
                if new.is_empty() { drifted = true; continue; }
                let (blocks, state) = new.inner();
                let tip = blocks.tip();
                let info = pool.block_info();
                let fee = client.chain_spec().next_block_base_fee(tip.header(), tip.timestamp()).unwrap_or_default();
                if old.is_none() && tip.number().abs_diff(info.last_seen_block_number) > config.max_update_depth {
                    pool.set_block_info(BlockInfo {
                        block_gas_limit: tip.gas_limit(), last_seen_block_hash: tip.hash(),
                        last_seen_block_number: tip.number(), pending_basefee: fee, pending_blob_fee: None,
                    });
                    drifted = true;
                    continue;
                }
                let mut changed: Vec<_> = state.changed_accounts().collect();
                let changed_addresses: AddressSet = changed.iter().map(|a| a.address).collect();
                for address in &changed_addresses { dirty.remove(address); }
                let mined = blocks.transaction_hashes_vec();
                let mut reinject = vec![];
                if let Some(old) = &old {
                    let (old_blocks, old_state) = old.inner();
                    if blocks.first().parent_hash() != info.last_seen_block_hash
                        && (old.is_empty() || old_blocks.first().parent_hash() != info.last_seen_block_hash) {
                        drifted = true;
                    }
                    let missing = old_state.accounts_iter().map(|(address, _)| address)
                        .filter(|address| !changed_addresses.contains(address)).collect();
                    let loaded = load_accounts(&client, tip.hash(), missing);
                    dirty.extend(loaded.failed);
                    changed.extend(loaded.accounts);
                    let mined_set: std::collections::HashSet<_> = mined.iter().copied().collect();
                    reinject = old_blocks.transactions_with_sender()
                        .filter(|(_, tx)| !mined_set.contains(tx.tx_hash()))
                        .filter_map(|(sender, tx)| EthPooledTransaction::try_from_consensus(tx.clone().with_signer(*sender)).ok())
                        .collect();
                } else if blocks.first().parent_hash() != info.last_seen_block_hash {
                    drifted = true;
                }
                pool.on_canonical_state_change(CanonicalStateUpdate {
                    new_tip: tip.sealed_block(), pending_block_base_fee: fee, pending_block_blob_fee: None,
                    changed_accounts: changed, mined_transactions: mined,
                    update_kind: if old.is_some() { PoolUpdateKind::Reorg } else { PoolUpdateKind::Commit },
                });
                if !reinject.is_empty() { let _ = pool.add_external_transactions(reinject).await; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_reload_requeues_every_address_without_applying_old_nonce() {
        let address = Address::repeat_byte(1);
        let mut dirty = AddressSet::default();
        let result = ReloadResult {
            at: B256::repeat_byte(1),
            requested: vec![address],
            accounts: vec![ChangedAccount {
                address,
                nonce: 99,
                balance: Default::default(),
            }],
            failed: vec![],
        };
        assert!(result.accept(B256::repeat_byte(2), &mut dirty).is_none());
        assert!(dirty.contains(&address));
    }
    #[test]
    fn matching_reload_applies_success_and_retries_only_failures() {
        let good = Address::repeat_byte(1);
        let bad = Address::repeat_byte(2);
        let mut dirty = AddressSet::default();
        let result = ReloadResult {
            at: B256::ZERO,
            requested: vec![good, bad],
            accounts: vec![ChangedAccount::empty(good)],
            failed: vec![bad],
        };
        assert_eq!(result.accept(B256::ZERO, &mut dirty).unwrap().len(), 1);
        assert_eq!(dirty.len(), 1);
        assert!(dirty.contains(&bad));
    }
}
