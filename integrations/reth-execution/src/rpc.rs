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
use reth_rpc_eth_types::{receipt::EthReceiptConverter, EthApiError};
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
    let converter = rpc_converter(components.provider().chain_spec());
    let components = BlochRpcComponents {
        evm: components.evm_config().clone().for_rpc(),
        inner: components,
    };
    EthApiBuilder::new_with_components(components)
        .with_rpc_converter(converter)
        .with_pending_env_builder(NoDerivedPending)
        .task_spawner(runtime)
        .build()
}
