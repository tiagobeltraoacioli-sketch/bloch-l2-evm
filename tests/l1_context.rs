use alloy_primitives::{Bytes, B256};
use bloch_l2_evm::{
    l1::{authenticate_ancestry, FinalizedCheckpoint},
    l1_context::{authenticate_l1_context, L1ContextError},
    node_primitives::NodeHeaderV2,
};
use serde_json::Value;
use std::str::FromStr;

fn decode(value: &str) -> Bytes {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .into()
}

fn ancestry() -> bloch_l2_evm::l1::AuthenticatedAncestry {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!("fixtures/genesis4-bodies.json")).unwrap();
    let fixture = &fixtures[4];
    let headers: Vec<Bytes> = fixture["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| decode(value.as_str().unwrap()))
        .collect();
    authenticate_ancestry(
        FinalizedCheckpoint {
            block: B256::from_str(fixture["checkpoint"].as_str().unwrap()).unwrap(),
            slot: fixture["checkpoint_slot"].as_u64().unwrap(),
        },
        &headers,
    )
    .unwrap()
}

fn make_header(anchor: B256) -> NodeHeaderV2 {
    NodeHeaderV2 {
        domain: B256::repeat_byte(0x11),
        chain_id: 700_771,
        number: 7,
        state_root: B256::repeat_byte(0x22),
        anchor_root: anchor,
        ..Default::default()
    }
}

#[test]
fn binds_exact_l2_header_to_authenticated_native_context() {
    let ancestry = ancestry();
    let header = make_header(ancestry.block());
    let context = authenticate_l1_context(header.chain_id, header.domain, &header, &ancestry).unwrap();
    assert_eq!(context.chain_id(), 700_771);
    assert_eq!(context.domain(), header.domain);
    assert_eq!(context.l2_number(), header.number);
    assert_eq!(context.l2_block(), header.hash());
    assert_eq!(context.l2_state_root(), header.state_root);
    assert_eq!(context.l1_anchor(), ancestry.block());
    assert_eq!(context.l1_anchor_slot(), ancestry.slot());
    assert_eq!(context.l1_checkpoint(), ancestry.checkpoint().block);
    assert_eq!(context.l1_checkpoint_slot(), ancestry.checkpoint().slot);
}

#[test]
fn rejects_identity_anchor_and_genesis_substitution() {
    let ancestry = ancestry();
    let header = make_header(ancestry.block());
    assert_eq!(
        authenticate_l1_context(84001, header.domain, &header, &ancestry),
        Err(L1ContextError::Identity)
    );
    assert_eq!(
        authenticate_l1_context(header.chain_id, B256::repeat_byte(9), &header, &ancestry),
        Err(L1ContextError::Identity)
    );
    let wrong_anchor = make_header(B256::repeat_byte(3));
    assert_eq!(
        authenticate_l1_context(wrong_anchor.chain_id, wrong_anchor.domain, &wrong_anchor, &ancestry),
        Err(L1ContextError::Anchor)
    );
    for changed in [
        NodeHeaderV2 {
            number: 0,
            ..header.clone()
        },
        NodeHeaderV2 {
            state_root: B256::ZERO,
            ..header
        },
    ] {
        assert_eq!(
            authenticate_l1_context(changed.chain_id, changed.domain, &changed, &ancestry),
            Err(L1ContextError::Genesis)
        );
    }
}
