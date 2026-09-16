// SPDX-License-Identifier: MIT OR Apache-2.0
//! Automatic adapted Reth pool maintenance over the canonical provider notification stream.
use crate::{BlochChainSpec, BlochNodeBlock, BlochNodePrimitives};
use reth_chain_state::CanonStateSubscriptions;
use reth_provider::providers::{BlockchainProvider, ProviderNodeTypes};
use reth_tasks::Runtime;
use reth_transaction_pool::{maintain::MaintainPoolConfig, EthPooledTransaction, TransactionPoolExt};
use std::future::Future;
mod task;

/// Invalid pool-maintenance runtime policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceConfigError {
    ZeroReloadBatch,
    ZeroLifetime,
}
impl std::fmt::Display for MaintenanceConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ZeroReloadBatch => "reload batch must be positive",
            Self::ZeroLifetime => "transaction lifetime must be positive",
        })
    }
}
impl std::error::Error for MaintenanceConfigError {}
fn validate_config(config: &MaintainPoolConfig) -> Result<(), MaintenanceConfigError> {
    if config.max_reload_accounts == 0 {
        return Err(MaintenanceConfigError::ZeroReloadBatch);
    }
    if config.max_tx_lifetime.is_zero() {
        return Err(MaintenanceConfigError::ZeroLifetime);
    }
    Ok(())
}

/// Subscribe immediately and return the Bloch-adapted Reth pool-maintenance future.
///
/// Create this future before publishing canonical notifications, then spawn and
/// supervise it for the node lifetime. Subscription happens before the first
/// poll. Start promptly: the upstream broadcast stream has bounded capacity.
/// This does not persist blocks or establish fork choice/L1 finality.
///
/// The canonical coordinator must durably commit a transition and update the
/// provider's canonical/persisted markers before publishing its complete Reth
/// notification. Notifications must contain nonempty new segments: the pinned
/// upstream reorg path does not support an empty replacement chain. The pool
/// derives changed accounts, mined transactions and reorg reinsertion from the
/// execution outcomes; deposits are not turned into user transactions.
///
/// This uses Bloch's `EthChainSpec::next_block_base_fee` implementation, including
/// deposit gas and the kernel's integer arithmetic. Blob fees remain disabled.
/// Pool backup/restart policy and recovery from process crashes are separate.
/// Account reload results are discarded and requeued when their requested head
/// differs from the pool head; failed reloads retry at most every 100 ms.
/// Zero reload batch size or zero transaction lifetime returns a configuration
/// error before subscribing. Blob cleanup is omitted because Bloch rejects blobs.
/// This bounded adapter does not expose upstream maintenance metrics.
pub fn pool_maintenance<N, P>(
    provider: BlockchainProvider<N>,
    pool: P,
    runtime: Runtime,
    config: MaintainPoolConfig,
) -> Result<impl Future<Output = ()> + Send + 'static, MaintenanceConfigError>
where
    N: ProviderNodeTypes<Primitives = BlochNodePrimitives, ChainSpec = BlochChainSpec>,
    P: TransactionPoolExt<Transaction = EthPooledTransaction, Block = BlochNodeBlock> + 'static,
{
    validate_config(&config)?;
    let events = provider.canonical_state_stream();
    Ok(task::run(provider, pool, events, runtime, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_zero_reload_batch() {
        let config = MaintainPoolConfig {
            max_reload_accounts: 0,
            ..Default::default()
        };
        assert_eq!(validate_config(&config), Err(MaintenanceConfigError::ZeroReloadBatch));
    }
    #[test]
    fn rejects_zero_lifetime() {
        let config = MaintainPoolConfig {
            max_tx_lifetime: std::time::Duration::ZERO,
            ..Default::default()
        };
        assert_eq!(validate_config(&config), Err(MaintenanceConfigError::ZeroLifetime));
    }
}
