// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only deployment identity for clients with an independently trusted manifest.
use crate::BlochChainSpec;
use alloy_primitives::B256;
use jsonrpsee::{types::ErrorObjectOwned, RpcModule};
use reth_chainspec::EthChainSpec;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Schema identifier pinned by deployment manifests and clients.
pub const CHAIN_IDENTITY_FORMAT: &str = "bloch-chain-identity-v1";
/// Canonical block-header encoding whose hash identifies this chain.
pub const HEADER_FORMAT: &str = "bloch-node-header-v2-fixed-width";

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
            let _: () = params.parse()?;
            Ok::<_, ErrorObjectOwned>(identity.clone())
        })
        .expect("the static identity method name is unique in a new module");
    module
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
