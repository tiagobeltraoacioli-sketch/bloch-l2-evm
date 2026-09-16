// SPDX-License-Identifier: MIT OR Apache-2.0
//! HTTP transport for the actual Reth RPC module; no alternate JSON handlers.
use jsonrpsee::{server::ServerConfig, RpcModule};
use reth_rpc_builder::{error::RpcError, RpcServerConfig, RpcServerHandle, TransportRpcModules};
use std::net::{Ipv4Addr, SocketAddr};

/// Start the supplied upstream EthApi module on IPv4 loopback.
///
/// Port zero asks the OS for an available port. Retain the returned handle for
/// the server lifetime; `http_local_addr()` / `http_url()` report the endpoint.
/// Calling `stop()` requests actual upstream shutdown (it does not await it).
/// Dropping the last handle also stops the server. The caller owns provider,
/// pool maintenance and canonical-coordinator lifecycle. This launches neither
/// P2P networking nor an Engine API, and does not fabricate pending derivation.
pub async fn start_http_rpc(module: RpcModule<()>, port: u16) -> Result<RpcServerHandle, RpcError> {
    let modules = TransportRpcModules::default().with_http(module);
    RpcServerConfig::http(ServerConfig::builder())
        .with_http_address(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .start(&modules)
        .await
}
