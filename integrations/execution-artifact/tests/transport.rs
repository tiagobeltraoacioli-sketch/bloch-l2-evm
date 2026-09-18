// SPDX-License-Identifier: MIT OR Apache-2.0
use alloy_primitives::B256;
use bloch_execution_artifact::ExecutionArtifact;
use bloch_l2_evm::{
    node_execution::{generate_node_batch_witness, genesis_v2, node_head},
    node_primitives::NodeBodyV2,
    BlockContext, ChainSpec,
};

fn artifact() -> ExecutionArtifact {
    let spec = ChainSpec::testnet();
    let domain = B256::repeat_byte(0xd3);
    let state = genesis_v2(&spec, 0).unwrap();
    let parent = node_head(&spec, domain, &state).unwrap();
    let body = NodeBodyV2::default();
    let context = BlockContext {
        number: 1,
        timestamp: 1,
        base_fee_per_gas: spec.next_base_fee(parent.base_fee_per_gas, parent.gas_used),
        prevrandao: B256::ZERO,
        anchor_root: B256::repeat_byte(8),
    };
    let (witness, outcome) = generate_node_batch_witness(&state, &spec, domain, &context, &body).unwrap();
    ExecutionArtifact::new(&spec, domain, &parent, &outcome.header, &body, witness).unwrap()
}

#[test]
fn transports_exact_reexecuted_block_without_accepting_transport_as_authority() {
    let artifact = artifact();
    let bytes = artifact.encode().unwrap();
    let restored = ExecutionArtifact::decode(&bytes, &ChainSpec::testnet(), B256::repeat_byte(0xd3)).unwrap();
    assert_eq!(restored.encode().unwrap(), bytes);
    assert_eq!(restored.expected(), artifact.expected());
    assert_eq!(restored.body(), artifact.body());
    assert_eq!(restored.witness(), artifact.witness());
    assert_eq!(restored.parent(), artifact.parent());
    assert_eq!(restored.header(), artifact.header());
    assert!(ExecutionArtifact::decode(&bytes, &ChainSpec::testnet(), B256::repeat_byte(9)).is_err());
    let mut wrong_spec = ChainSpec::testnet();
    wrong_spec.max_l1_sats -= 1;
    assert!(ExecutionArtifact::decode(&bytes, &wrong_spec, B256::repeat_byte(0xd3)).is_err());
}

#[test]
fn corrupt_witness_parent_header_and_envelope_fail_closed() {
    let bytes = artifact().encode().unwrap();
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let decode = |value: &serde_json::Value| {
        ExecutionArtifact::decode(
            &serde_json::to_vec(value).unwrap(),
            &ChainSpec::testnet(),
            B256::repeat_byte(0xd3),
        )
    };
    let mut wrong = original.clone();
    wrong["format"] = "BLOCH:EVM:EXECUTION-ARTIFACT:2".into();
    assert!(decode(&wrong).is_err());
    let mut wrong = original.clone();
    wrong["extra"] = true.into();
    assert!(decode(&wrong).is_err());
    let mut wrong = original.clone();
    wrong["witness"]["new_state_root"] = B256::ZERO.to_string().into();
    assert!(decode(&wrong).is_err());
    let mut wrong = original.clone();
    wrong["witness"]["proof"] = serde_json::json!({});
    assert!(decode(&wrong).is_err());
    for name in ["parent_rlp", "header_rlp", "body_rlp"] {
        let mut wrong = original.clone();
        let encoded = wrong[name].as_str().unwrap().to_owned() + "00";
        wrong[name] = encoded.into();
        assert!(decode(&wrong).is_err(), "{name}");
    }
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(b"{}");
    assert!(ExecutionArtifact::decode(&trailing, &ChainSpec::testnet(), B256::repeat_byte(0xd3)).is_err());
    for end in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        assert!(ExecutionArtifact::decode(&bytes[..end], &ChainSpec::testnet(), B256::repeat_byte(0xd3)).is_err());
    }
}

#[test]
fn unchanged_state_roots_do_not_authorize_a_different_full_header() {
    let original = artifact();
    let mut header = original.header().clone();
    header.receipts_root[0] ^= 1;
    assert!(ExecutionArtifact::new(
        &ChainSpec::testnet(),
        B256::repeat_byte(0xd3),
        original.parent(),
        &header,
        original.body(),
        original.witness().clone(),
    )
    .is_err());
}
