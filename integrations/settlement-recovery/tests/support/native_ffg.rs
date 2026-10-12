#![allow(dead_code)]
use alloy_primitives::B256;
use bloch_l2_evm::{native_settlement::SettlementPolicyV1, proof_statement::configuration_commitment, ChainSpec};
use bloch_pos_committee::{
    attestation::{Attestation, AttestationData},
    beacon::RandaoChain,
    header::{BlockHeaderV4, BlockId},
    interfaces::ProposalEnvelope,
    l2_settlement::Policy,
    state_root::EvmCommitment,
    transition::{CommittedState, GenesisValidator},
};
use bloch_reth_execution::BlochChainSpec;
use bloch_settlement_recovery::native::NativeReplayBlockV1;
use reth_chainspec::EthChainSpec;
use serde_json::{json, Value};

pub fn hash(s: &str) -> B256 {
    s.parse().unwrap()
}
pub fn policy() -> SettlementPolicyV1 {
    let spec = BlochChainSpec::new(ChainSpec::testnet(), B256::repeat_byte(0xd3), 0).unwrap();
    SettlementPolicyV1 {
        network: B256::repeat_byte(0x91),
        genesis: hash("4bebee4e83c206d9e40692165639a5c1cf0546d13a39c233666b56ad0aeaaa3a"),
        domain: spec.domain(),
        configuration: configuration_commitment(spec.execution()).unwrap(),
        program_elf_keccak: hash("ba7207dad5dafe22f2f8c2dd0705f3acbb5b20886d5c05c528372bc88b4d4828"),
        program_vkey_koalabear: hash("7a3fec8175a17a171d82f74027d9bdba59fa8e17397e4b01716bc07926c3a41a"),
        program_vkey_bn254: hash("00f47fd903d685e85cec17ba027d9bdbab3f51c2ee5f92c078b5e03ca6c3a41a"),
        proof_policy: B256::from(bloch_l2_proof::policy_commitment()),
        chain_id: 700771,
        first_l2_number: 1,
        initial_l2_parent_hash: spec.genesis_hash(),
        initial_l2_state_root: spec.genesis_header().0.state_root,
    }
}
pub fn chains() -> Vec<RandaoChain> {
    (0..3)
        .map(|i| {
            let mut seed = [0; 32];
            seed[0] = i;
            seed[1] = 0x5a;
            RandaoChain::generate(seed)
        })
        .collect()
}
pub fn genesis(keys: &[Vec<u8>]) -> CommittedState {
    let header = BlockHeaderV4 {
        version: 0xb10c_0005,
        parent: [0; 32],
        state_root: [0; 32],
        body_root: [0; 32],
        slot: 0,
        proposer_index: 0,
        randao_reveal: [0; 32],
        randao_mix: [7; 32],
        justified_root: [0; 32],
        finalized_root: [0; 32],
        attestation_root: [0; 32],
        coherence_root: [0x33; 32],
    };
    let p = policy();
    assert_eq!(*header.id().as_bytes(), p.genesis.0);
    let vals = keys
        .iter()
        .zip(chains())
        .enumerate()
        .map(|(i, (key, chain))| GenesisValidator {
            index: i as u32,
            pubkey: key.clone(),
            staked_sat: 200_000 * 100_000_000u128,
            randao_commitment: chain.commitment(),
            withdrawal_credentials: vec![i as u8; 4],
            commission_bps: 500,
        })
        .collect::<Vec<_>>();
    CommittedState::genesis_with_network_domain(
        p.network.0,
        BlockId::of(&header),
        [7; 32],
        &vals,
        &[],
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        EvmCommitment {
            account_root: [0x44; 32],
            receipts_root: [0x55; 32],
            gas_used: 0,
            base_fee_per_gas: 1,
        },
        &[],
    )
    .configure_l2_genesis(Policy {
        identities: [
            p.network.0,
            p.genesis.0,
            p.domain.0,
            p.configuration.0,
            p.program_elf_keccak.0,
            p.program_vkey_koalabear.0,
            p.program_vkey_bn254.0,
        ],
        proof_policy: p.proof_policy.0,
        chain_id: p.chain_id,
        initial_l2_parent: p.initial_l2_parent_hash.0,
        initial_l2_state: p.initial_l2_state_root.0,
        attestor_set: [0; 32],
    })
    .unwrap()
}
pub fn encode_block(b: &NativeReplayBlockV1) -> Value {
    json!({"header":hex::encode(b.envelope.header.canonical_serialize()),
        "proposer_signature":hex::encode(&b.envelope.proposer_sig),
        "transactions":b.transactions.iter().map(hex::encode).collect::<Vec<_>>(),
        "attestations":b.attestations.iter().map(|a| json!({
            "validator":a.validator,"signature":hex::encode(&a.signature),"slot":a.data.slot,
            "head":hex::encode(a.data.head),"source_epoch":a.data.source_epoch,
            "source_root":hex::encode(a.data.source_root),"target_epoch":a.data.target_epoch,
            "target_root":hex::encode(a.data.target_root),
        })).collect::<Vec<_>>()})
}
pub fn decode_block(v: &Value) -> NativeReplayBlockV1 {
    fn bytes(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }
    fn h(v: &Value) -> [u8; 32] {
        bytes(v).try_into().unwrap()
    }
    NativeReplayBlockV1 {
        envelope: ProposalEnvelope {
            header: BlockHeaderV4::canonical_deserialize(&bytes(&v["header"])).unwrap(),
            proposer_sig: bytes(&v["proposer_signature"]),
        },
        transactions: v["transactions"].as_array().unwrap().iter().map(bytes).collect(),
        attestations: v["attestations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| Attestation {
                validator: a["validator"].as_u64().unwrap().try_into().unwrap(),
                signature: bytes(&a["signature"]),
                data: AttestationData {
                    slot: a["slot"].as_u64().unwrap(),
                    head: h(&a["head"]),
                    source_epoch: a["source_epoch"].as_u64().unwrap(),
                    source_root: h(&a["source_root"]),
                    target_epoch: a["target_epoch"].as_u64().unwrap(),
                    target_root: h(&a["target_root"]),
                },
            })
            .collect(),
    }
}
