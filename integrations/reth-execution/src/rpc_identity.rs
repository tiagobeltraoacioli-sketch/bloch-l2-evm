// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only deployment identity for clients with an independently trusted manifest.
use crate::{BlochBlockchainProvider, BlochChainSpec};
use alloy_primitives::B256;
use jsonrpsee::{types::ErrorObjectOwned, RpcModule};
use reth_chainspec::EthChainSpec;
use reth_provider::{BlockNumReader, HeaderProvider};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Schema identifier pinned by deployment manifests and clients.
pub const CHAIN_IDENTITY_FORMAT: &str = "bloch-chain-identity-v1";
/// Canonical block-header encoding whose hash identifies this chain.
pub const HEADER_FORMAT: &str = "bloch-node-header-v2-fixed-width";
/// Schema identifier for a challenge-bound canonical head snapshot.
pub const CHAIN_STATUS_FORMAT: &str = "bloch-chain-status-v1";

/// Immutable identity values derived only from the configured chain specification.
///
/// This response is not a trust root: a client must compare every field with an
/// independently reviewed deployment manifest before enabling privileged actions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlochChainIdentity {
    pub format: String,
    pub chain_id: String,
    pub domain: B256,
    pub genesis_hash: B256,
    pub header_format: String,
}

/// A challenge-bound view of the currently persisted canonical head.
///
/// Echoing a fresh client challenge prevents an intermediary from satisfying a
/// request with a response cached for another request. This is not a signature
/// or a finality proof: clients still need a trusted deployment manifest and an
/// authenticated transport, and must treat the reported head as unfinalized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlochChainStatus {
    pub format: String,
    pub challenge: B256,
    pub identity: BlochChainIdentity,
    pub head_number: String,
    pub head_hash: B256,
    pub state_root: B256,
}

impl BlochChainIdentity {
    pub fn from_spec(spec: &BlochChainSpec) -> Self {
        Self {
            format: CHAIN_IDENTITY_FORMAT.to_owned(),
            chain_id: format!("0x{:x}", spec.execution().chain_id),
            domain: spec.domain(),
            genesis_hash: spec.genesis_hash(),
            header_format: HEADER_FORMAT.to_owned(),
        }
    }
}

/// Build the isolated `bloch_chainIdentity` module for explicit transport merging.
pub fn chain_identity_rpc(spec: Arc<BlochChainSpec>) -> RpcModule<()> {
    let identity = BlochChainIdentity::from_spec(&spec);
    let mut module = RpcModule::new(());
    module
        .register_method("bloch_chainIdentity", move |params, _, _| {
            if !matches!(params.as_str(), None | Some("[]")) {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    "chain identity accepts no parameters",
                    None::<()>,
                ));
            }
            Ok::<_, ErrorObjectOwned>(identity.clone())
        })
        .expect("the static identity method name is unique in a new module");
    module
}

/// Build an isolated `bloch_chainStatus` module over the canonical provider.
///
/// The provider is sampled before and after reading the selected header. A
/// concurrent canonical change fails the request instead of publishing a torn
/// `(number, hash, stateRoot)` tuple. The method accepts exactly one nonzero
/// 32-byte challenge and performs no writes.
pub fn chain_status_rpc(spec: Arc<BlochChainSpec>, provider: BlochBlockchainProvider) -> RpcModule<()> {
    let identity = BlochChainIdentity::from_spec(&spec);
    let mut module = RpcModule::new(());
    module
        .register_method("bloch_chainStatus", move |params, _, _| {
            let (challenge,): (B256,) = params.parse()?;
            if challenge == B256::ZERO {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    "chain status challenge must be nonzero",
                    None::<()>,
                ));
            }
            let number = provider.best_block_number().map_err(internal_error)?;
            let head = provider
                .sealed_header(number)
                .map_err(internal_error)?
                .ok_or_else(|| internal_error("canonical head is missing"))?;
            let stable_number = provider.best_block_number().map_err(internal_error)?;
            let stable_head = provider.sealed_header(number).map_err(internal_error)?;
            if stable_number != number || stable_head.as_ref() != Some(&head) {
                return Err(internal_error("canonical head changed while reading status"));
            }
            Ok::<_, ErrorObjectOwned>(BlochChainStatus {
                format: CHAIN_STATUS_FORMAT.to_owned(),
                challenge,
                identity: identity.clone(),
                head_number: format!("0x{number:x}"),
                head_hash: head.hash(),
                state_root: head.0.state_root,
            })
        })
        .expect("the chain status method name is unique in a new module");
    module
}

fn internal_error(_error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32603, "canonical chain status is unavailable", None::<()>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use bloch_l2_evm::ChainSpec;

    #[test]
    fn identity_binds_chain_domain_and_genesis() {
        let kernel = ChainSpec::testnet();
        let spec = BlochChainSpec::new(kernel.clone(), B256::repeat_byte(7), 11).unwrap();
        let identity = BlochChainIdentity::from_spec(&spec);
        assert_eq!(identity.format, CHAIN_IDENTITY_FORMAT);
        assert_eq!(identity.chain_id, format!("0x{:x}", kernel.chain_id));
        assert_eq!(identity.domain, B256::repeat_byte(7));
        assert_eq!(identity.genesis_hash, spec.genesis_hash());
        assert_eq!(identity.header_format, HEADER_FORMAT);

        let other_domain = BlochChainSpec::new(kernel.clone(), B256::repeat_byte(8), 11).unwrap();
        assert_ne!(identity, BlochChainIdentity::from_spec(&other_domain));
        let other_time = BlochChainSpec::new(kernel, B256::repeat_byte(7), 12).unwrap();
        assert_ne!(identity, BlochChainIdentity::from_spec(&other_time));
    }
}
