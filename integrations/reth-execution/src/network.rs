// SPDX-License-Identifier: MIT OR Apache-2.0
//! Which L2 network a node binary serves: execution rules, V2 domain and
//! genesis timestamp, selected once on the command line.
//!
//! The development networks keep their historical identity (rules
//! `testnet_v3`/`testnet`, chain id 700771, domain `0xd3…d3`, genesis
//! timestamp 0), so their databases and settled history open unchanged. The
//! mainnet (chain id 700770, [`ChainSpec::mainnet`]) has no default identity:
//! its domain and genesis timestamp come from the pinned genesis ceremony and
//! must be given explicitly, and its genesis timestamp must be wall-clock
//! seconds so L2 time is wall-clock from block 0.
use crate::{rpc::WALL_CLOCK_FLOOR_SECS, BlochChainSpec, RuleSchedule};
use alloy_primitives::B256;
use bloch_l2_evm::{BlockExecutionError, ChainSpec};

/// V2 domain of the development networks (devnet2..devnet4).
pub const DEVNET_DOMAIN: B256 = B256::repeat_byte(0xd3);

/// Execution rules, domain and genesis of one L2 network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Network {
    /// Kernel execution rules of the chain's first blocks (chain id included).
    pub rules: ChainSpec,
    /// The rule set later blocks switch to, on a network that has one.
    pub next_rules: Option<ChainSpec>,
    /// V2 header domain.
    pub domain: B256,
    /// Genesis block timestamp (unix seconds on mainnet).
    pub genesis_timestamp: u64,
    /// True only for the mainnet profile.
    pub mainnet: bool,
}

impl L2Network {
    /// devnet4: settlement V3 rules, development identity.
    pub fn devnet_v3() -> Self {
        Self {
            rules: ChainSpec::testnet_v3(),
            next_rules: None,
            domain: DEVNET_DOMAIN,
            genesis_timestamp: 0,
            mainnet: false,
        }
    }

    /// devnet2/devnet3: settlement V2 rules, development identity.
    pub fn devnet_v2() -> Self {
        Self {
            rules: ChainSpec::testnet(),
            ..Self::devnet_v3()
        }
    }

    /// The mainnet profile: [`ChainSpec::mainnet_v1`] switching to
    /// [`ChainSpec::mainnet`] (chain id 700770, see [`RuleSchedule`]) with the
    /// ceremony's domain and a wall-clock genesis timestamp.
    pub fn mainnet(domain: B256, genesis_timestamp: u64) -> Result<Self, String> {
        if domain.is_zero() || domain == DEVNET_DOMAIN {
            return Err("the mainnet domain must be the ceremony's, not zero or the devnet domain".into());
        }
        if genesis_timestamp < WALL_CLOCK_FLOOR_SECS {
            return Err(format!(
                "the mainnet genesis timestamp must be wall-clock unix seconds (>= {WALL_CLOCK_FLOOR_SECS})"
            ));
        }
        Ok(Self {
            rules: ChainSpec::mainnet_v1(),
            next_rules: Some(ChainSpec::mainnet()),
            domain,
            genesis_timestamp,
            mainnet: true,
        })
    }

    /// Parse `--rules v3|v2|mainnet` with the optional `--domain HEX` and
    /// `--genesis-time SECS`. Both are required for mainnet and refused for
    /// the development rules, whose identity is fixed.
    pub fn parse(rules: &str, domain: Option<&str>, genesis_time: Option<&str>) -> Result<Self, String> {
        match rules {
            "v3" | "v2" => {
                if domain.is_some() || genesis_time.is_some() {
                    return Err("--domain/--genesis-time apply only to --rules mainnet".into());
                }
                Ok(if rules == "v3" {
                    Self::devnet_v3()
                } else {
                    Self::devnet_v2()
                })
            }
            "mainnet" => {
                let domain = domain.ok_or("--rules mainnet requires --domain HEX")?;
                let domain = domain.strip_prefix("0x").unwrap_or(domain);
                if domain.len() != 64 || !domain.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("--domain must be 64 hex characters".into());
                }
                let domain: B256 = domain.parse().map_err(|_| "--domain is not a hash")?;
                let genesis_time = genesis_time
                    .ok_or("--rules mainnet requires --genesis-time SECS")?
                    .parse::<u64>()
                    .map_err(|_| "--genesis-time must be decimal unix seconds")?;
                Self::mainnet(domain, genesis_time)
            }
            other => Err(format!("--rules must be v3, v2 or mainnet, not {other}")),
        }
    }

    /// The provider configuration bound to this network's genesis.
    pub fn chain_spec(&self) -> Result<BlochChainSpec, BlockExecutionError> {
        let rules = match &self.next_rules {
            Some(next) => RuleSchedule::new(self.rules.clone(), next.clone())
                .map_err(|_| BlockExecutionError::InvalidChainSpec(bloch_l2_evm::ChainSpecError::PartialNextRules))?,
            None => RuleSchedule::single(self.rules.clone()),
        };
        BlochChainSpec::scheduled(rules, self.domain, self.genesis_timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_l2_evm::{MAINNET_CHAIN_ID, TESTNET_CHAIN_ID};
    use reth_chainspec::EthChainSpec;

    const DOMAIN: &str = "7070707070707070707070707070707070707070707070707070707070707070";

    #[test]
    fn development_rules_keep_their_identity_and_refuse_mainnet_knobs() {
        let v3 = L2Network::parse("v3", None, None).unwrap();
        assert_eq!(v3, L2Network::devnet_v3());
        assert_eq!(v3.rules, ChainSpec::testnet_v3());
        assert_eq!(v3.rules.chain_id, TESTNET_CHAIN_ID);
        assert_eq!((v3.domain, v3.genesis_timestamp), (DEVNET_DOMAIN, 0));
        assert_eq!(L2Network::parse("v2", None, None).unwrap().rules, ChainSpec::testnet());
        assert!(L2Network::parse("v3", Some(DOMAIN), None).is_err());
        assert!(L2Network::parse("v2", None, Some("1800000000")).is_err());
        assert!(L2Network::parse("v4", None, None).is_err());
        // The devnet genesis is the one devnet4 was initialized with.
        let old = BlochChainSpec::new(ChainSpec::testnet_v3(), B256::repeat_byte(0xd3), 0).unwrap();
        assert_eq!(v3.chain_spec().unwrap().genesis_hash(), old.genesis_hash());
    }

    /// The pinned mainnet L2 genesis (2026-10-14): `MAINNET_DOMAIN`, the
    /// Genesis-4 slot-0 time, no premine. These two hashes are the native
    /// activation's `initial_l2_parent` / `initial_l2_state`.
    #[test]
    fn pinned_mainnet_genesis_has_no_premine() {
        use bloch_l2_evm::chainspec::{BEACON_ROOTS_ADDRESS, BLOCK_INFO, MAINNET_DOMAIN, MAINNET_GENESIS_TIMESTAMP};
        let spec = L2Network::mainnet(MAINNET_DOMAIN, MAINNET_GENESIS_TIMESTAMP)
            .unwrap()
            .chain_spec()
            .unwrap();
        assert_eq!(
            format!("{:x}", spec.genesis_hash()),
            "632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468"
        );
        assert_eq!(
            format!("{:x}", spec.genesis_header().0.state_root),
            "2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d"
        );
        assert_eq!(spec.genesis_header().0.timestamp, 1_786_656_679);
        assert_eq!(spec.genesis().gas_limit, 30_000_000);
        assert_eq!(spec.genesis().base_fee_per_gas, Some(1_000_000_000));
        // The whole allocation: the EIP-4788 beacon-roots predeploy (code) and
        // the BLOCK_INFO head record (storage), both with zero balance. The
        // withdrawal outbox is installed by block 1; the vaults and the supply
        // ledger are created lazily. No account holds value.
        let alloc = &spec.genesis().alloc;
        let mut addresses: Vec<_> = alloc.keys().copied().collect();
        addresses.sort();
        let mut expected = vec![BEACON_ROOTS_ADDRESS, BLOCK_INFO];
        expected.sort();
        assert_eq!(addresses, expected);
        let shape: Vec<_> = expected
            .iter()
            .map(|a| (alloc[a].balance, alloc[a].nonce, alloc[a].storage.as_ref().map_or(0, |s| s.len())))
            .collect();
        assert!(alloc.values().all(|a| a.balance.is_zero()), "no premine: {shape:?}");
        // System accounts carry nonce 1 (EIP-161 non-empty), never value.
        assert!(alloc.values().all(|a| a.nonce == Some(1)), "{shape:?}");
        assert!(alloc[&BEACON_ROOTS_ADDRESS].code.as_ref().is_some_and(|c| !c.is_empty()));
        assert!(alloc[&BLOCK_INFO].code.as_ref().is_none_or(|c| c.is_empty()));
    }

    #[test]
    fn mainnet_needs_the_ceremony_domain_and_a_wall_clock_genesis() {
        let mainnet = L2Network::parse("mainnet", Some(DOMAIN), Some("1800000000")).unwrap();
        assert!(mainnet.mainnet);
        assert_eq!(mainnet.rules, ChainSpec::mainnet_v1());
        assert_eq!(mainnet.next_rules, Some(ChainSpec::mainnet()));
        assert_eq!(mainnet.rules.chain_id, MAINNET_CHAIN_ID);
        let spec = mainnet.chain_spec().unwrap();
        assert_eq!(spec.chain().id(), 700_770);
        assert_eq!(spec.genesis_header().0.timestamp, 1_800_000_000);
        assert_eq!(spec.genesis_header().0.chain_id, 700_770);
        assert_ne!(
            spec.genesis_hash(),
            L2Network::devnet_v3().chain_spec().unwrap().genesis_hash()
        );
        assert_eq!(
            L2Network::parse("mainnet", Some(&format!("0x{DOMAIN}")), Some("1800000000")).unwrap(),
            mainnet
        );
        for (domain, time) in [
            (None, Some("1800000000")),
            (Some(DOMAIN), None),
            (Some(DOMAIN), Some("0")),
            (Some(DOMAIN), Some("228")),
            (Some(DOMAIN), Some("x")),
            (
                Some("d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3"),
                Some("1800000000"),
            ),
            (
                Some("0000000000000000000000000000000000000000000000000000000000000000"),
                Some("1800000000"),
            ),
            (Some("70"), Some("1800000000")),
        ] {
            assert!(
                L2Network::parse("mainnet", domain, time).is_err(),
                "{domain:?} {time:?}"
            );
        }
    }
}
