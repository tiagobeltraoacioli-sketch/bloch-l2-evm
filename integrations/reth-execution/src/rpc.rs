// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reth EthApi construction using Bloch's canonical provider, pool and V2 RPC types.
use crate::{
    rpc_types::{BlochHeaderConverter, BlochRpcTypes},
    BlochChainSpec, BlochEvmConfig, BlochNextBlockEnvCtx, BlochNodeHeader, BlochNodePrimitives,
};
use alloy_rpc_types_eth::BlockOverrides;
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::SealedHeader;
use reth_rpc::{eth::EthApiBuilder, EthApi};
use reth_rpc_convert::RpcConverter;
use reth_rpc_eth_api::{helpers::pending_block::PendingEnvBuilder, RpcNodeCore};
use reth_rpc_eth_types::{builder::config::PendingBlockKind, receipt::EthReceiptConverter, EthApiError};
use reth_tasks::Runtime;
use std::sync::Arc;

/// RPC conversions retain the V2 header and reuse Ethereum user-transaction receipts.
pub type BlochRpcConverter =
    RpcConverter<BlochRpcTypes, BlochEvmConfig, EthReceiptConverter<BlochChainSpec>, BlochHeaderConverter>;

pub fn rpc_converter(spec: Arc<BlochChainSpec>) -> BlochRpcConverter {
    RpcConverter::new(EthReceiptConverter::new(spec)).with_header_converter(BlochHeaderConverter)
}

/// Policy for a node without an authenticated pending derivation snapshot.
/// Canonical historical/latest state queries remain available. Callers supplying
/// pending data must instead implement a builder bound to the selected parent.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDerivedPending;

impl PendingEnvBuilder<BlochEvmConfig> for NoDerivedPending {
    fn pending_env_attributes(
        &self,
        _parent: &SealedHeader<BlochNodeHeader>,
        _block_overrides: Option<&BlockOverrides>,
    ) -> Result<BlochNextBlockEnvCtx, EthApiError> {
        Err(EthApiError::Unsupported(
            "pending Bloch derivation is unavailable: authenticated anchor and deposits are required",
        ))
    }
}

/// Unix time (2020-01-01) from which a parent timestamp is read as
/// wall-clock seconds. Development history stamped `parent + 1` stays far below.
pub const WALL_CLOCK_FLOOR_SECS: u64 = 1_577_836_800;

/// RPC-only `pending` environment, as Ethereum clients expect from a node
/// whose sequencer does not publish a pending block: the next block on the
/// latest canonical header, with no deposits and the parent's anchor and
/// randomness. Calls and gas estimates at `pending` therefore run on the
/// latest state with `number = latest + 1` (so `BLOCKHASH(latest)` is the real
/// hash, as it will be when the transaction is included) and a timestamp of
/// `max(parent + 1, now)` once the chain is on wall-clock time (`parent + 1`
/// for development history below [`WALL_CLOCK_FLOOR_SECS`]).
///
/// It never builds, stores or announces a block: it only shapes simulations.
/// Canonical execution, settlement and the attestors never see it. Explicit
/// `time`, `random` and `beaconRoot` block overrides are honoured.
#[derive(Clone, Copy, Debug, Default)]
pub struct LatestDerivedPending;

impl LatestDerivedPending {
    /// The attributes of the speculative next block at `now` (unix seconds).
    pub fn attributes(
        parent: &BlochNodeHeader,
        now: u64,
        block_overrides: Option<&BlockOverrides>,
    ) -> BlochNextBlockEnvCtx {
        let successor = parent.0.timestamp.saturating_add(1);
        let timestamp = if parent.0.timestamp >= WALL_CLOCK_FLOOR_SECS {
            successor.max(now)
        } else {
            successor
        };
        let overrides = block_overrides.cloned().unwrap_or_default();
        BlochNextBlockEnvCtx {
            timestamp: overrides.time.unwrap_or(timestamp),
            prevrandao: overrides.random.unwrap_or(parent.0.prevrandao),
            anchor_root: overrides.beacon_root.unwrap_or(parent.0.anchor_root),
            deposits: vec![],
        }
    }
}

impl PendingEnvBuilder<BlochEvmConfig> for LatestDerivedPending {
    fn pending_env_attributes(
        &self,
        parent: &SealedHeader<BlochNodeHeader>,
        block_overrides: Option<&BlockOverrides>,
    ) -> Result<BlochNextBlockEnvCtx, EthApiError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        Ok(Self::attributes(parent.header(), now, block_overrides))
    }
}

/// How an RPC node answers the `pending` tag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PendingPolicy {
    /// Refuse pending environments ([`NoDerivedPending`]); the default of
    /// [`build_eth_api`], kept for the development node and its tests.
    #[default]
    Unavailable,
    /// Ethereum-client semantics without a published pending block
    /// ([`LatestDerivedPending`]): pending state is the latest state, pending
    /// calls and estimates run in the derived next-block environment, and no
    /// pending block is built from a pool (`PendingBlockKind::None`). Pair it
    /// with [`serve_pending_blocks_as_latest`] so block-shaped queries return
    /// the latest block instead of `null`.
    LatestDerived,
}

/// Block-shaped methods whose first parameter is a block number or tag.
pub const PENDING_AS_LATEST_METHODS: [&str; 6] = [
    "eth_getBlockByNumber",
    "eth_getHeaderByNumber",
    "eth_getBlockReceipts",
    "eth_getBlockTransactionCountByNumber",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getRawTransactionByBlockNumberAndIndex",
];

/// Replace `"pending"` by `"latest"` in the first parameter.
pub fn pending_param_as_latest(mut params: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    if let Some(first) = params.first_mut() {
        if first.as_str() == Some("pending") {
            *first = serde_json::Value::String("latest".into());
        }
    }
    params
}

/// Answer block-shaped `pending` queries ([`PENDING_AS_LATEST_METHODS`]) with
/// the latest canonical block, as rollup RPCs without a published pending
/// block do. Each method present in `module` is replaced by a wrapper that
/// rewrites the tag and calls the original handler in process; other tags and
/// methods are untouched. Call it after every module has been merged.
pub fn serve_pending_blocks_as_latest(
    module: &mut jsonrpsee::RpcModule<()>,
) -> Result<(), jsonrpsee::core::RegisterMethodError> {
    let original: jsonrpsee::Methods = module.clone().into();
    for method in PENDING_AS_LATEST_METHODS {
        if module.remove_method(method).is_none() {
            continue;
        }
        let original = original.clone();
        module.register_async_method(method, move |params, _, _| {
            let original = original.clone();
            async move {
                let values: Vec<serde_json::Value> = if params.as_str().is_none() {
                    vec![]
                } else {
                    params.parse()?
                };
                original
                    .call::<_, serde_json::Value>(method, pending_param_as_latest(values))
                    .await
                    .map_err(|error| match error {
                        jsonrpsee::core::server::MethodsError::JsonRpc(object) => object,
                        other => jsonrpsee::types::ErrorObjectOwned::owned(-32603, other.to_string(), None::<()>),
                    })
            }
        })?;
    }
    Ok(())
}

/// Components forwarded to Reth with an RPC-specific clone of the EVM config.
/// The caller's original configuration and canonical executor remain unchanged.
#[derive(Clone, Debug)]
pub struct BlochRpcComponents<N> {
    inner: N,
    evm: BlochEvmConfig,
}

impl<N> RpcNodeCore for BlochRpcComponents<N>
where
    N: RpcNodeCore<Primitives = BlochNodePrimitives, Evm = BlochEvmConfig>,
{
    type Primitives = BlochNodePrimitives;
    type Provider = N::Provider;
    type Pool = N::Pool;
    type Network = N::Network;
    type Evm = BlochEvmConfig;

    fn provider(&self) -> &Self::Provider {
        self.inner.provider()
    }
    fn pool(&self) -> &Self::Pool {
        self.inner.pool()
    }
    fn network(&self) -> &Self::Network {
        self.inner.network()
    }
    fn evm_config(&self) -> &Self::Evm {
        &self.evm
    }
}

/// Construct upstream Reth handlers over initialized Bloch components.
///
/// Must run inside a Tokio runtime. The caller owns canonical maintenance and
/// transport lifecycle; this does not launch networking, fork choice or Engine API.
/// Pending environments are unavailable until authenticated derivation is wired.
/// Call/estimate BLOCKHASH uses provider ancestry and explicit RPC overrides;
/// canonical execution retains its shared-kernel frozen history. Broader
/// simulation/tracing and wallet workflows require separate qualification.
pub fn build_eth_api<N>(components: N, runtime: Runtime) -> EthApi<BlochRpcComponents<N>, BlochRpcConverter>
where
    N: RpcNodeCore<
        Primitives = BlochNodePrimitives,
        Evm = BlochEvmConfig,
        Provider: ChainSpecProvider<ChainSpec = BlochChainSpec>,
    >,
{
    build_eth_api_with(components, runtime, PendingPolicy::Unavailable)
}

/// [`build_eth_api`] with an explicit [`PendingPolicy`].
pub fn build_eth_api_with<N>(
    components: N,
    runtime: Runtime,
    pending: PendingPolicy,
) -> EthApi<BlochRpcComponents<N>, BlochRpcConverter>
where
    N: RpcNodeCore<
        Primitives = BlochNodePrimitives,
        Evm = BlochEvmConfig,
        Provider: ChainSpecProvider<ChainSpec = BlochChainSpec>,
    >,
{
    // eth_call may not burn more gas than one block can hold (reth's default cap is 50M).
    let gas_cap = components.provider().chain_spec().execution().gas_limit;
    build_eth_api_capped(components, runtime, pending, gas_cap)
}

/// [`build_eth_api_with`] with an explicit simulation gas cap: `eth_call`, `eth_estimateGas` and
/// `eth_createAccessList` never run with more gas than `gas_cap`, whatever the request, the
/// caller's allowance or a block override says (the snapshot patch applies the cap to every
/// path, see RETH-SNAPSHOT.md). Must be nonzero.
pub fn build_eth_api_capped<N>(
    components: N,
    runtime: Runtime,
    pending: PendingPolicy,
    gas_cap: u64,
) -> EthApi<BlochRpcComponents<N>, BlochRpcConverter>
where
    N: RpcNodeCore<
        Primitives = BlochNodePrimitives,
        Evm = BlochEvmConfig,
        Provider: ChainSpecProvider<ChainSpec = BlochChainSpec>,
    >,
{
    assert!(gas_cap > 0, "a zero gas cap means no cap");
    let converter = rpc_converter(components.provider().chain_spec());
    let gas_cap = reth_rpc_eth_types::gas_oracle::GasCap(gas_cap);
    let components = BlochRpcComponents {
        evm: components.evm_config().clone().for_rpc(),
        inner: components,
    };
    let builder = EthApiBuilder::new_with_components(components)
        .with_rpc_converter(converter)
        .task_spawner(runtime)
        .gas_cap(gas_cap);
    match pending {
        PendingPolicy::Unavailable => builder.with_pending_env_builder(NoDerivedPending).build(),
        PendingPolicy::LatestDerived => builder
            .with_pending_env_builder(LatestDerivedPending)
            .pending_block_kind(PendingBlockKind::None)
            .build(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bloom, B256};
    use bloch_l2_evm::node_primitives::NodeHeaderV2;

    fn parent(timestamp: u64) -> BlochNodeHeader {
        BlochNodeHeader(NodeHeaderV2 {
            domain: B256::repeat_byte(1),
            chain_id: 700_770,
            number: 41,
            timestamp,
            base_fee_per_gas: 7,
            gas_limit: 30_000_000,
            gas_used: 0,
            user_gas_used: 0,
            beneficiary: Address::repeat_byte(2),
            prevrandao: B256::repeat_byte(3),
            anchor_root: B256::repeat_byte(4),
            parent_hash: B256::repeat_byte(5),
            parent_state_root: B256::repeat_byte(6),
            transactions_root: B256::repeat_byte(7),
            receipts_root: B256::repeat_byte(8),
            deposits_hash: B256::repeat_byte(9),
            logs_bloom: Bloom::ZERO,
            state_root: B256::repeat_byte(11),
        })
    }

    #[test]
    fn pending_env_is_the_next_block_on_latest_without_deposits() {
        let now = 1_800_000_000;
        // Wall-clock chain: the pending block is stamped now, never before parent + 1.
        let wall = LatestDerivedPending::attributes(&parent(1_799_999_990), now, None);
        assert_eq!(wall.timestamp, now);
        assert_eq!(wall.prevrandao, B256::repeat_byte(3));
        assert_eq!(wall.anchor_root, B256::repeat_byte(4));
        assert!(wall.deposits.is_empty());
        let ahead = LatestDerivedPending::attributes(&parent(now + 5), now, None);
        assert_eq!(ahead.timestamp, now + 6);
        // Development history (parent + 1 stamps) keeps parent + 1.
        assert_eq!(LatestDerivedPending::attributes(&parent(216), now, None).timestamp, 217);
        // Explicit overrides win.
        let overrides = BlockOverrides {
            time: Some(5),
            random: Some(B256::repeat_byte(0xaa)),
            beacon_root: Some(B256::repeat_byte(0xbb)),
            ..Default::default()
        };
        let forced = LatestDerivedPending::attributes(&parent(216), now, Some(&overrides));
        assert_eq!(forced.timestamp, 5);
        assert_eq!(forced.prevrandao, B256::repeat_byte(0xaa));
        assert_eq!(forced.anchor_root, B256::repeat_byte(0xbb));
    }

    #[test]
    fn only_a_pending_first_parameter_is_rewritten() {
        use serde_json::json;
        let rewrite =
            |v: serde_json::Value| serde_json::Value::Array(pending_param_as_latest(v.as_array().unwrap().clone()));
        assert_eq!(rewrite(json!(["pending", true])), json!(["latest", true]));
        assert_eq!(rewrite(json!(["latest", false])), json!(["latest", false]));
        assert_eq!(rewrite(json!(["0x10", false])), json!(["0x10", false]));
        assert_eq!(rewrite(json!(["finalized"])), json!(["finalized"]));
        assert_eq!(rewrite(json!([])), json!([]));
        assert_eq!(rewrite(json!(["0x1", "pending"])), json!(["0x1", "pending"]));
    }

    #[tokio::test]
    async fn block_methods_answer_pending_with_the_latest_handler() {
        use serde_json::{json, Value};
        let mut module = jsonrpsee::RpcModule::new(());
        // Stand-in for the upstream handler: echoes the tag it receives.
        module
            .register_method("eth_getBlockByNumber", |params, _, _| {
                let values: Vec<Value> = params.parse()?;
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>(json!({"tag": values[0], "full": values[1]}))
            })
            .unwrap();
        module
            .register_method("eth_getBalance", |params, _, _| {
                let values: Vec<Value> = params.parse()?;
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>(values[1].clone())
            })
            .unwrap();
        module
            .register_method("eth_getBlockReceipts", |_, _, _| {
                Err::<Value, _>(jsonrpsee::types::ErrorObjectOwned::owned(-32001, "boom", None::<()>))
            })
            .unwrap();
        serve_pending_blocks_as_latest(&mut module).unwrap();
        let block: Value = module
            .call("eth_getBlockByNumber", vec![json!("pending"), json!(true)])
            .await
            .unwrap();
        assert_eq!(block, json!({"tag": "latest", "full": true}));
        let block: Value = module
            .call("eth_getBlockByNumber", vec![json!("0x5"), json!(false)])
            .await
            .unwrap();
        assert_eq!(block, json!({"tag": "0x5", "full": false}));
        // Methods outside the block-shaped list keep their own pending handling.
        let balance: Value = module
            .call(
                "eth_getBalance",
                vec![json!("0x0000000000000000000000000000000000000000"), json!("pending")],
            )
            .await
            .unwrap();
        assert_eq!(balance, json!("pending"));
        // Upstream errors pass through with their code.
        let error = module
            .call::<_, Value>("eth_getBlockReceipts", vec![json!("pending")])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("boom"), "{error}");
    }
}
