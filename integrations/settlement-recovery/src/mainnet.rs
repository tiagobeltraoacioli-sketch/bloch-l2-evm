// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pinned Bloch L2 mainnet identity (chain id 700770) for the native follower.
//!
//! The Genesis-4 native mainnet carries no L2 registry at genesis; native
//! release `78b7343a` installs it at the epoch-5850 flag day (slot 187200)
//! with `l2_settlement::mainnet::PROGRAM` and the 3-of-5 attestor set. These
//! values repeat that activation so a follower can check, while replaying from
//! the pinned Genesis-4 manifest, that the transition installed exactly this
//! policy (docs/MAINNET-PROGRAM.md).
use alloy_primitives::{b256, B256};
use bloch_l2_evm::{
    chainspec::{GENESIS4_NETWORK_DOMAIN, MAINNET_CHAIN_ID, MAINNET_DOMAIN},
    native_settlement::SettlementPolicyV1,
};

/// SHA3-256 of `genesis/mainnet.manifest` (Genesis-4): the admission domain.
pub const MAINNET_NETWORK: B256 = GENESIS4_NETWORK_DOMAIN;
/// SHA-256 of the manifest file (`7eef82a7…b2dd`), for operators' `sha256sum`.
pub const MAINNET_MANIFEST_SHA256: B256 = b256!("7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd");
/// Genesis-4 native genesis block id.
pub const MAINNET_NATIVE_GENESIS: B256 = b256!("9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415");
/// Hash of the 3-of-5 withdrawal attestor set installed with the policy.
pub const MAINNET_ATTESTOR_SET: B256 = b256!("1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b");
/// L2 genesis header hash (`initial_l2_parent`).
pub const MAINNET_L2_GENESIS: B256 = b256!("632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468");
/// L2 genesis state root (`initial_l2_state`).
pub const MAINNET_L2_GENESIS_STATE: B256 = b256!("2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d");

/// The settlement policy the epoch-5850 activation installs.
pub fn mainnet_settlement_policy() -> SettlementPolicyV1 {
    SettlementPolicyV1 {
        network: MAINNET_NETWORK,
        genesis: MAINNET_NATIVE_GENESIS,
        domain: MAINNET_DOMAIN,
        configuration: b256!("8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b"),
        program_elf_keccak: b256!("6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073"),
        program_vkey_koalabear: b256!("389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e"),
        program_vkey_bn254: b256!("007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e"),
        proof_policy: b256!("154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d"),
        chain_id: MAINNET_CHAIN_ID,
        first_l2_number: 1,
        initial_l2_parent_hash: MAINNET_L2_GENESIS,
        initial_l2_state_root: MAINNET_L2_GENESIS_STATE,
    }
}

/// The V1 settlement policy of a native activation (attestor set excluded).
pub fn policy_from_activation(policy: &bloch_pos_committee::l2_settlement::Policy) -> SettlementPolicyV1 {
    let id = |i: usize| B256::from(policy.identities[i]);
    SettlementPolicyV1 {
        network: id(0),
        genesis: id(1),
        domain: id(2),
        configuration: id(3),
        program_elf_keccak: id(4),
        program_vkey_koalabear: id(5),
        program_vkey_bn254: id(6),
        proof_policy: policy.proof_policy.into(),
        chain_id: policy.chain_id,
        first_l2_number: 1,
        initial_l2_parent_hash: policy.initial_l2_parent.into(),
        initial_l2_state_root: policy.initial_l2_state.into(),
    }
}

/// The policy and withdrawal attestor-set hash a flag-day network bound to
/// `network` must install: the pinned mainnet values for Genesis-4; for any
/// other network only what the linked native consensus itself installs there
/// (`activation_for`), which is `None` unless the native crates are built with
/// the qualification feature `l2-activation-rehearsal-mainnet-policy` (private
/// mainnet-path rehearsal; never a funded network).
pub fn flag_day_policy(network: B256) -> Option<(SettlementPolicyV1, B256)> {
    if network == MAINNET_NETWORK {
        return Some((mainnet_settlement_policy(), MAINNET_ATTESTOR_SET));
    }
    let activation = bloch_pos_committee::l2_settlement::activation_for(Some(network.0))?;
    let policy = policy_from_activation(&activation.policy);
    (policy.network == network).then_some((policy, activation.policy.attestor_set.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_l2_evm::chainspec::MAINNET_GENESIS_TIMESTAMP;
    use bloch_reth_execution::L2Network;
    use reth_chainspec::EthChainSpec;

    /// The candidate program the native gate would install runs these rules.
    #[test]
    fn native_next_program_pins_the_next_configuration() {
        let next = bloch_pos_committee::l2_settlement::mainnet::PROGRAM_NEXT;
        let configuration =
            bloch_l2_evm::proof_statement::configuration_commitment(&bloch_l2_evm::ChainSpec::mainnet()).unwrap();
        assert_eq!(next.identities[0], configuration.0);
        assert_eq!(bloch_pos_committee::params::L2_NEXT_PROGRAM_EPOCH, u64::MAX);
    }

    #[test]
    fn pinned_policy_matches_the_mainnet_execution_profile() {
        let policy = mainnet_settlement_policy();
        assert!(policy.commitment().is_ok());
        assert_eq!(policy.proof_policy.0, bloch_l2_proof::policy_commitment_v3());
        let spec = L2Network::mainnet(MAINNET_DOMAIN, MAINNET_GENESIS_TIMESTAMP)
            .unwrap()
            .chain_spec()
            .unwrap();
        assert_eq!(spec.genesis_hash(), policy.initial_l2_parent_hash);
        assert_eq!(spec.genesis_header().0.state_root, policy.initial_l2_state_root);
        assert_eq!(spec.genesis_header().0.chain_id, 700_770);
        assert_eq!(
            policy.configuration,
            bloch_l2_evm::proof_statement::configuration_commitment(&bloch_l2_evm::ChainSpec::mainnet_v1()).unwrap(),
        );
        assert_eq!(
            MAINNET_NETWORK,
            b256!("f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966")
        );
    }

    #[test]
    fn flag_day_policy_is_the_pin_and_matches_the_native_mainnet_activation() {
        let (policy, attestors) = flag_day_policy(MAINNET_NETWORK).unwrap();
        assert_eq!(policy, mainnet_settlement_policy());
        assert_eq!(attestors, MAINNET_ATTESTOR_SET);
        // The linked native release installs exactly these values at the flag day.
        let native = bloch_pos_committee::l2_settlement::activation_for(Some(MAINNET_NETWORK.0))
            .expect("the native release pins the mainnet activation");
        assert_eq!(policy_from_activation(&native.policy), policy);
        assert_eq!(B256::from(native.policy.attestor_set), MAINNET_ATTESTOR_SET);
        // Release builds (no qualification feature) give no other network a policy.
        assert!(flag_day_policy(B256::repeat_byte(0x42)).is_none());
    }
}
