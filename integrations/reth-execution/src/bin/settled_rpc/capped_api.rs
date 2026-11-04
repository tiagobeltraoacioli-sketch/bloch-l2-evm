// SPDX-License-Identifier: MIT OR Apache-2.0
//! The settled RPC's EthApi with its own simulation gas cap.
//!
//! Kept in the binary on purpose: any change to the `bloch-reth-execution` library, even an
//! unused new item, changed the bytes of `bloch-l2-produce-dev` (agent 195, rebuild of f2f12ad),
//! and the follower and the block producer must stay byte-identical to their pinned release.
use bloch_reth_execution::{
    build_eth_api_with, rpc_converter, BlochChainSpec, BlochEvmConfig, BlochNodePrimitives, BlochRpcConverter,
    LatestDerivedPending, NoDerivedPending, PendingPolicy,
};
use reth_chainspec::ChainSpecProvider;
use reth_rpc::{eth::EthApiBuilder, EthApi};
use reth_rpc_eth_api::RpcNodeCore;
use reth_rpc_eth_types::builder::config::PendingBlockKind;
use reth_tasks::Runtime;

/// The caller's components with the library's RPC copy of the EVM configuration, as the
/// library's `BlochRpcComponents`.
#[derive(Clone, Debug)]
pub struct CappedRpcComponents<N> {
    inner: N,
    evm: BlochEvmConfig,
}

impl<N> RpcNodeCore for CappedRpcComponents<N>
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

/// `build_eth_api_with` with an explicit simulation gas cap: `eth_call`, `eth_estimateGas` and
/// `eth_createAccessList` never run with more gas than `gas_cap`, whatever the request, the
/// caller's allowance or a block override says (the snapshot patch applies the cap to every path,
/// integrations/reth-execution/RETH-SNAPSHOT.md). Must be nonzero.
pub fn build_eth_api_capped<N>(
    components: N,
    runtime: Runtime,
    pending: PendingPolicy,
    gas_cap: u64,
) -> EthApi<CappedRpcComponents<N>, BlochRpcConverter>
where
    N: RpcNodeCore<
            Primitives = BlochNodePrimitives,
            Evm = BlochEvmConfig,
            Provider: ChainSpecProvider<ChainSpec = BlochChainSpec>,
        > + Clone,
{
    assert!(gas_cap > 0, "a zero gas cap means no cap");
    // The RPC copy of the EVM configuration (provider ancestry for BLOCKHASH, explicit block
    // overrides) is only made inside the library; take it from a throwaway library EthApi.
    let evm = build_eth_api_with(components.clone(), runtime.clone(), PendingPolicy::Unavailable)
        .evm_config()
        .clone();
    let converter = rpc_converter(components.provider().chain_spec());
    let builder = EthApiBuilder::new_with_components(CappedRpcComponents { inner: components, evm })
        .with_rpc_converter(converter)
        .task_spawner(runtime)
        .gas_cap(reth_rpc_eth_types::gas_oracle::GasCap(gas_cap));
    match pending {
        PendingPolicy::Unavailable => builder.with_pending_env_builder(NoDerivedPending).build(),
        PendingPolicy::LatestDerived => builder
            .with_pending_env_builder(LatestDerivedPending)
            .pending_block_kind(PendingBlockKind::None)
            .build(),
    }
}
