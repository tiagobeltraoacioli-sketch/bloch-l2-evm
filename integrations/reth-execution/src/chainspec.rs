// SPDX-License-Identifier: MIT OR Apache-2.0
//! Immutable provider configuration for the explicit Bloch V2 genesis.
use crate::BlochNodeHeader;
use alloy_eips::{eip1559::BaseFeeParams, eip7840::BlobParams};
use alloy_genesis::{ChainConfig, Genesis, GenesisAccount};
use alloy_primitives::{B256, U256};
use bloch_l2_evm::{
    node_execution::{genesis_v2, node_head},
    BlockExecutionError, ChainSpec,
};
use reth_chainspec::{Chain, DepositContract, EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition};
use reth_network_peers::NodeRecord;
use std::fmt::Display;

/// A trusted domain and validated execution configuration bound to a V2 genesis.
///
/// The allocation is derived from the zero-issuance kernel genesis, including
/// system bytecode and committed head slots. This does not authenticate the
/// domain against L1 or initialize a database. Cancun describes EVM semantics;
/// Ethereum withdrawals, blobs and Ethereum header hashing are not enabled.
#[derive(Clone, Debug)]
pub struct BlochChainSpec {
    execution: ChainSpec,
    domain: B256,
    genesis: Genesis,
    header: BlochNodeHeader,
}

impl BlochChainSpec {
    /// Construct canonical genesis data; arbitrary prefunded allocations are not accepted.
    pub fn new(execution: ChainSpec, domain: B256, timestamp: u64) -> Result<Self, BlockExecutionError> {
        let state = genesis_v2(&execution, timestamp)?;
        let header = BlochNodeHeader(node_head(&execution, domain, &state)?);
        let alloc = state
            .db()
            .cache
            .accounts
            .iter()
            .filter_map(|(address, account)| {
                state.account(address)?;
                let code = account
                    .info
                    .code
                    .as_ref()
                    .or_else(|| state.db().cache.contracts.get(&account.info.code_hash))
                    .map(|code| code.original_bytes());
                Some((
                    *address,
                    GenesisAccount {
                        nonce: Some(account.info.nonce),
                        balance: account.info.balance,
                        code,
                        storage: Some(
                            account
                                .storage
                                .iter()
                                .filter(|(_, value)| !value.is_zero())
                                .map(|(key, value)| (B256::from(*key), B256::from(*value)))
                                .collect(),
                        ),
                        private_key: None,
                    },
                ))
            })
            .collect();
        let genesis = Genesis {
            config: ChainConfig {
                chain_id: execution.chain_id,
                homestead_block: Some(0),
                eip150_block: Some(0),
                eip155_block: Some(0),
                eip158_block: Some(0),
                byzantium_block: Some(0),
                constantinople_block: Some(0),
                petersburg_block: Some(0),
                istanbul_block: Some(0),
                berlin_block: Some(0),
                london_block: Some(0),
                terminal_total_difficulty: Some(U256::ZERO),
                shanghai_time: Some(0),
                cancun_time: Some(0),
                ..Default::default()
            },
            timestamp,
            gas_limit: execution.gas_limit,
            coinbase: execution.coinbase(),
            base_fee_per_gas: Some(execution.initial_base_fee.into()),
            alloc,
            ..Default::default()
        };
        Ok(Self {
            execution,
            domain,
            genesis,
            header,
        })
    }

    /// Kernel rules used to construct this configuration.
    pub fn execution(&self) -> &ChainSpec {
        &self.execution
    }
    /// Caller-authenticated V2 domain identity.
    pub fn domain(&self) -> B256 {
        self.domain
    }
}

impl EthChainSpec for BlochChainSpec {
    type Header = BlochNodeHeader;
    fn chain(&self) -> Chain {
        Chain::from_id(self.execution.chain_id)
    }
    fn base_fee_params_at_timestamp(&self, _: u64) -> BaseFeeParams {
        BaseFeeParams::new(
            self.execution.base_fee_denominator.into(),
            self.execution.base_fee_elasticity.into(),
        )
    }
    fn blob_params_at_timestamp(&self, _: u64) -> Option<BlobParams> {
        None
    }
    fn deposit_contract(&self) -> Option<&DepositContract> {
        None
    }
    fn genesis_hash(&self) -> B256 {
        self.header.0.hash()
    }
    fn prune_delete_limit(&self) -> usize {
        20_000
    }
    fn display_hardforks(&self) -> Box<dyn Display> {
        Box::new("Bloch V2: Cancun EVM at genesis; no scheduled upgrades")
    }
    fn genesis_header(&self) -> &Self::Header {
        &self.header
    }
    fn genesis(&self) -> &Genesis {
        &self.genesis
    }
    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        None
    }
    fn is_optimism(&self) -> bool {
        false
    }
    fn is_ethereum(&self) -> bool {
        false
    }
    fn final_paris_total_difficulty(&self) -> Option<U256> {
        Some(U256::ZERO)
    }
    fn next_block_base_fee(&self, parent: &Self::Header, _: u64) -> Option<u64> {
        Some(
            self.execution
                .next_base_fee(parent.0.base_fee_per_gas, parent.0.gas_used),
        )
    }
}

impl EthereumHardforks for BlochChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        use EthereumHardfork::*;
        match fork {
            Frontier | Homestead | Tangerine | SpuriousDragon | Byzantium | Constantinople | Petersburg | Istanbul
            | Berlin | London => ForkCondition::Block(0),
            Paris => ForkCondition::TTD {
                activation_block_number: 0,
                fork_block: Some(0),
                total_difficulty: U256::ZERO,
            },
            Shanghai | Cancun => ForkCondition::Timestamp(0),
            _ => ForkCondition::Never,
        }
    }
}
