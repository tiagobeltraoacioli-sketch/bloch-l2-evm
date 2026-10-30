// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loopback transports for actual Reth RPC modules; no alternate JSON handlers.
use jsonrpsee::{
    server::{BatchRequestConfig, ServerConfig},
    RpcModule,
};
use reth_rpc_builder::{error::RpcError, RpcServerConfig, RpcServerHandle, TransportRpcModules};
use std::net::{Ipv4Addr, SocketAddr};

/// Enough for one maximum-size hex transaction plus JSON-RPC framing, while
/// refusing multi-megabyte bodies before JSON deserialization.
pub const RPC_MAX_REQUEST_BYTES: u32 = 512 * 1024;
/// A full block may contain 16 MiB of raw transactions, which expands beyond
/// 32 MiB when represented as JSON hex alongside transaction metadata.
pub const RPC_MAX_RESPONSE_BYTES: u32 = 64 * 1024 * 1024;
/// Calls per JSON-RPC batch. An unlimited batch turns one HTTP request (one
/// unit for a per-request gateway rate limit) into thousands of calls, e.g.
/// 2,000 `eth_estimateGas` in a 320 KB body kept one connection busy for 41 s
/// in the 2026-10-30 spool rehearsal.
pub const RPC_MAX_BATCH_CALLS: u32 = 100;

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
    RpcServerConfig::http(
        ServerConfig::builder()
            .max_request_body_size(RPC_MAX_REQUEST_BYTES)
            .max_response_body_size(RPC_MAX_RESPONSE_BYTES)
            .set_batch_request_config(BatchRequestConfig::Limit(RPC_MAX_BATCH_CALLS)),
    )
    .with_http_address(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    .start(&modules)
    .await
}

/// Start a separate loopback WebSocket listener for an upstream RPC module.
/// Independent listeners allow HTTP and WS to have different method sets and
/// independently selected ephemeral ports. The caller owns both server handles.
pub async fn start_ws_rpc(module: RpcModule<()>, port: u16) -> Result<RpcServerHandle, RpcError> {
    let modules = TransportRpcModules::default().with_ws(module);
    RpcServerConfig::ws(
        ServerConfig::builder()
            .max_request_body_size(RPC_MAX_REQUEST_BYTES)
            .max_response_body_size(RPC_MAX_RESPONSE_BYTES)
            .set_batch_request_config(BatchRequestConfig::Limit(RPC_MAX_BATCH_CALLS))
            .max_subscriptions_per_connection(64),
    )
    .with_ws_address(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    .start(&modules)
    .await
}
