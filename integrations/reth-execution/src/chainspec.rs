// SPDX-License-Identifier: MIT OR Apache-2.0
//! Immutable provider configuration for the explicit Bloch V2 genesis.
use crate::{BlochNodeHeader, RuleSchedule};
use alloy_eips::{eip1559::BaseFeeParams, eip7840::BlobParams};
use alloy_genesis::{ChainConfig, Genesis, GenesisAccount};
use alloy_primitives::{B256, U256};
use bloch_l2_evm::{
    node_execution::{genesis_v2, node_head},
    BlockExecutionError, ChainSpec,
};
use reth_chainspec::{
    Chain, ChainHardforks, DepositContract, EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition,
    ForkFilter, ForkFilterKey, ForkId, Hardfork, Hardforks, Head,
};
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
    rules: RuleSchedule,
    domain: B256,
    genesis: Genesis,
    header: BlochNodeHeader,
    hardforks: ChainHardforks,
}

impl BlochChainSpec {
    /// Construct canonical genesis data; arbitrary prefunded allocations are not accepted.
    pub fn new(execution: ChainSpec, domain: B256, timestamp: u64) -> Result<Self, BlockExecutionError> {
        Self::scheduled(RuleSchedule::single(execution), domain, timestamp)
    }

    /// The same for a chain whose rules may change at a block ([`RuleSchedule`]).
    pub fn scheduled(rules: RuleSchedule, domain: B256, timestamp: u64) -> Result<Self, BlockExecutionError> {
        let execution = rules.base().clone();
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
            rules,
            domain,
            genesis,
            header,
            hardforks: evm_hardforks(),
        })
    }

    /// The base kernel rules. Everything a next rule set may not change reads
    /// these; block execution reads [`Self::execution_at`].
    pub fn execution(&self) -> &ChainSpec {
        &self.execution
    }
    /// The kernel rules block `number` runs.
    pub fn execution_at(&self, number: u64) -> &ChainSpec {
        self.rules.at(number)
    }
    /// Which rules each block runs.
    pub fn rules(&self) -> &RuleSchedule {
        &self.rules
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
        // The rules of the block after `parent` (F387-1: the next rules floor it).
        let number = parent.0.number.checked_add(1)?;
        Some(
            self.execution_at(number)
                .next_base_fee(parent.0.base_fee_per_gas, parent.0.gas_used),
        )
    }
}

// One immutable schedule backs both the Ethereum EVM helpers and generic Reth
// fork introspection. This does not enable Ethereum consensus body/header rules.
fn evm_hardforks() -> ChainHardforks {
    use EthereumHardfork::*;
    let forks = [
        Frontier,
        Homestead,
        Tangerine,
        SpuriousDragon,
        Byzantium,
        Constantinople,
        Petersburg,
        Istanbul,
        Berlin,
        London,
        Paris,
        Shanghai,
        Cancun,
    ];
    ChainHardforks::new(
        forks
            .into_iter()
            .map(|fork| {
                let condition = match fork {
                    Paris => ForkCondition::TTD {
                        activation_block_number: 0,
                        fork_block: Some(0),
                        total_difficulty: U256::ZERO,
                    },
                    Shanghai | Cancun => ForkCondition::Timestamp(0),
                    _ => ForkCondition::Block(0),
                };
                (Box::new(fork) as Box<dyn Hardfork>, condition)
            })
            .collect(),
    )
}

impl EthereumHardforks for BlochChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.hardforks.fork(fork)
    }
}

impl Hardforks for BlochChainSpec {
    fn fork<H: Hardfork>(&self, fork: H) -> ForkCondition {
        self.hardforks.fork(fork)
    }
    fn forks_iter(&self) -> impl Iterator<Item = (&dyn Hardfork, ForkCondition)> {
        self.hardforks.forks_iter()
    }
    fn fork_id(&self, head: &Head) -> ForkId {
        self.fork_filter(*head).current()
    }
    fn latest_fork_id(&self) -> ForkId {
        // Every configured transition is active at genesis; there is no future ID.
        self.fork_id(&Head {
            timestamp: self.genesis.timestamp,
            ..Default::default()
        })
    }
    fn fork_filter(&self, head: Head) -> ForkFilter {
        let forks = self
            .hardforks
            .forks_iter()
            .filter_map(|(_, condition)| match condition {
                ForkCondition::Block(block)
                | ForkCondition::TTD {
                    fork_block: Some(block),
                    ..
                } => Some(ForkFilterKey::Block(block)),
                ForkCondition::Timestamp(timestamp) => Some(ForkFilterKey::Time(timestamp)),
                _ => None,
            });
        ForkFilter::new(head, self.genesis_hash(), self.genesis.timestamp, forks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generic_schedule_matches_evm_and_has_no_future_upgrade() {
        let spec = BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(1), 100).unwrap();
        assert_eq!(spec.forks_iter().count(), 13);
        for fork in [
            EthereumHardfork::Frontier,
            EthereumHardfork::Homestead,
            EthereumHardfork::Tangerine,
            EthereumHardfork::SpuriousDragon,
            EthereumHardfork::Byzantium,
            EthereumHardfork::Constantinople,
            EthereumHardfork::Petersburg,
            EthereumHardfork::Istanbul,
            EthereumHardfork::Berlin,
            EthereumHardfork::London,
            EthereumHardfork::Paris,
            EthereumHardfork::Shanghai,
            EthereumHardfork::Cancun,
            EthereumHardfork::Dao,
            EthereumHardfork::Prague,
            EthereumHardfork::Osaka,
        ] {
            assert_eq!(spec.fork(fork), spec.ethereum_fork_activation(fork));
        }
        assert_eq!(spec.fork(EthereumHardfork::Cancun), ForkCondition::Timestamp(0));
        assert_eq!(spec.fork(EthereumHardfork::Prague), ForkCondition::Never);
        assert_eq!(spec.fork(EthereumHardfork::Dao), ForkCondition::Never);
        assert_eq!(spec.latest_fork_id().next, 0);
        assert_eq!(
            spec.fork_id(&Head {
                number: u64::MAX,
                timestamp: u64::MAX,
                ..Default::default()
            }),
            spec.latest_fork_id()
        );
    }
    #[test]
    fn fork_identity_uses_actual_v2_genesis_and_filter_agrees() {
        let spec = BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(1), 100).unwrap();
        let other = BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(2), 100).unwrap();
        let head = Head {
            timestamp: 100,
            ..Default::default()
        };
        let expected = ForkId {
            hash: reth_chainspec::ForkHash::from(spec.genesis_header().0.hash()),
            next: 0,
        };
        assert_eq!(spec.fork_id(&head), expected);
        assert_eq!(spec.fork_filter(head).current(), expected);
        assert!(spec.fork_filter(head).validate(expected).is_ok());
        assert_ne!(other.latest_fork_id(), expected);
        assert!(spec.fork_filter(head).validate(other.latest_fork_id()).is_err());
    }
}
