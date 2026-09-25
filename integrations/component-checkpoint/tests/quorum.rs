// SPDX-License-Identifier: AGPL-3.0-or-later
use bloch_component_checkpoint::*;
use std::sync::OnceLock;
fn keys() -> &'static Vec<(Vec<u8>, Vec<u8>)> {
    static KEYS: OnceLock<Vec<(Vec<u8>, Vec<u8>)>> = OnceLock::new();
    KEYS.get_or_init(|| (0..3).map(|_| bloch_crypto::crypto::generate_keypair()).collect())
}
fn fixture(component: Component, threshold: u8) -> (Registry, Envelope, Trust) {
    let registry = Registry {
        version: 1,
        id: "review-1".into(),
        threshold,
        min_external: 1,
        valid_from: 100,
        valid_until: 100_000,
        signers: keys()
            .iter()
            .enumerate()
            .map(|(i, (pk, _))| Signer {
                id: format!("holder-{i}"),
                external: i == 2,
                public_key: hex::encode(pk),
            })
            .collect(),
    };
    let cp = Checkpoint {
        version: 1,
        component,
        chain_id: "eip155:8453".into(),
        genesis: hash(b"genesis"),
        sequence: 1,
        previous: "00".repeat(32),
        issued_at: 1_000,
        expires_at: 10_000,
        finalized_height: 100,
        finalized_hash: hash(b"block"),
        state_root: hash(b"state"),
        configuration_sha3: hash(b"config"),
        artifacts_sha3: hash(b"artifacts"),
        registry_sha3: registry.commitment().unwrap(),
    };
    let trust = Trust {
        version: 1,
        component,
        chain_id: cp.chain_id.clone(),
        genesis: cp.genesis.clone(),
        registry_sha3: cp.registry_sha3.clone(),
        configuration_sha3: cp.configuration_sha3.clone(),
        artifacts_sha3: cp.artifacts_sha3.clone(),
        next_sequence: 1,
        previous: cp.previous.clone(),
        minimum_finalized_height: 100,
        maximum_age_seconds: 1_000,
    };
    let signatures = [0, 2]
        .iter()
        .map(|i| sign(&registry, &cp, &format!("holder-{i}"), &keys()[*i].1).unwrap())
        .collect();
    (
        registry,
        Envelope {
            checkpoint: cp,
            signatures,
        },
        trust,
    )
}
#[test]
fn real_hybrid_quorums_for_each_component_and_three_of_three() {
    for component in [Component::L2, Component::Dex, Component::Bridge] {
        let (r, env, trust) = fixture(component, 2);
        let v = verify(&r, &env, &trust, 1_500).unwrap();
        assert_eq!(v.component, component);
        assert_eq!(v.signer_ids.len(), 2);
        assert!(!v.activation_authorized && !v.consensus_finality_verified);
        let (r, mut env, trust) = fixture(component, 3);
        assert!(verify(&r, &env, &trust, 1_500).is_err());
        env.signatures
            .push(sign(&r, &env.checkpoint, "holder-1", &keys()[1].1).unwrap());
        assert_eq!(verify(&r, &env, &trust, 1_500).unwrap().signer_ids.len(), 3);
    }
}
#[test]
fn rejects_duplicates_nonexternal_only_unknown_signers_and_invalid_extras() {
    let (r, env, trust) = fixture(Component::Dex, 2);
    let mut changed = env.clone();
    changed.signatures[1] = changed.signatures[0].clone();
    assert!(verify(&r, &changed, &trust, 1_500).is_err());
    changed.signatures[1] = sign(&r, &changed.checkpoint, "holder-1", &keys()[1].1).unwrap();
    assert!(verify(&r, &changed, &trust, 1_500).is_err());
    changed = env.clone();
    changed.signatures[0].signer = "unknown".into();
    assert!(verify(&r, &changed, &trust, 1_500).is_err());
    changed = env.clone();
    let mut extra = sign(&r, &changed.checkpoint, "holder-1", &keys()[1].1).unwrap();
    extra.signature.replace_range(100..102, "00");
    // Guarantee a malformed signature independent of random signature bytes.
    extra.signature.truncate(100);
    changed.signatures.push(extra);
    assert!(verify(&r, &changed, &trust, 1_500).is_err());
    let mut duplicate = r.clone();
    duplicate.signers[2].public_key = duplicate.signers[0].public_key.clone();
    assert!(duplicate.validate().is_err());
    let mut weak = r.clone();
    weak.threshold = 1;
    assert!(weak.validate().is_err());
    weak = r.clone();
    weak.min_external = 0;
    assert!(weak.validate().is_err());
}
#[test]
fn both_halves_and_exact_suite_are_required() {
    let (r, env, trust) = fixture(Component::L2, 2);
    for byte in [4, 4 + 3309] {
        let mut changed = env.clone();
        let mut sig = hex::decode(&changed.signatures[0].signature).unwrap();
        sig[byte] ^= 1;
        changed.signatures[0].signature = hex::encode(sig);
        assert!(verify(&r, &changed, &trust, 1_500).is_err());
    }
    let mut changed = env.clone();
    changed.signatures[0].signature.replace_range(4..6, "02");
    assert!(verify(&r, &changed, &trust, 1_500).is_err());
    let mut downgraded = r.clone();
    downgraded.signers[0].public_key.replace_range(4..6, "02");
    assert!(downgraded.validate().is_err());
}
#[test]
fn changed_payload_and_cross_component_replay_fail_even_with_changed_trust() {
    let (r, env, trust) = fixture(Component::L2, 2);
    for field in [
        "component",
        "chain_id",
        "genesis",
        "sequence",
        "previous",
        "issued_at",
        "expires_at",
        "finalized_height",
        "finalized_hash",
        "state_root",
        "configuration_sha3",
        "artifacts_sha3",
        "registry_sha3",
    ] {
        let mut json = serde_json::to_value(&env).unwrap();
        let value = &mut json["checkpoint"][field];
        *value = match field {
            "component" => serde_json::json!("dex"),
            "chain_id" => serde_json::json!("eip155:1"),
            "sequence" | "issued_at" | "expires_at" | "finalized_height" => {
                serde_json::json!(value.as_u64().unwrap() + 1)
            }
            _ => serde_json::json!(hash(b"changed")),
        };
        let changed: Envelope = serde_json::from_value(json).unwrap();
        assert!(verify(&r, &changed, &trust, 1_500).is_err(), "{field}");
    }
    let mut changed = env.clone();
    changed.checkpoint.component = Component::Bridge;
    let mut changed_trust = trust;
    changed_trust.component = Component::Bridge;
    assert!(verify(&r, &changed, &changed_trust, 1_500).is_err());
}
#[test]
fn expiry_replay_and_clock_limits() {
    let (r, env, trust) = fixture(Component::Bridge, 2);
    for now in [999, 2_001, 10_000, u64::MAX] {
        assert!(verify(&r, &env, &trust, now).is_err());
    }
    assert!(verify(&r, &env, &trust, 2_000).is_ok());
    for kind in 0..4 {
        let mut t = trust.clone();
        match kind {
            0 => t.next_sequence = 2,
            1 => t.previous = hash(b"previous"),
            2 => t.minimum_finalized_height = 101,
            _ => t.maximum_age_seconds = 0,
        }
        assert!(verify(&r, &env, &t, 1_500).is_err());
    }
}
#[test]
fn signing_refuses_wrong_holder_key_and_json_rejects_unknown_or_duplicate_fields() {
    let (r, env, _) = fixture(Component::Dex, 2);
    assert!(sign(&r, &env.checkpoint, "holder-0", &keys()[1].1).is_err());
    let json = serde_json::to_string(&env.checkpoint).unwrap();
    let duplicate = json.replacen("{", "{\"version\":1,", 1);
    assert!(serde_json::from_str::<Checkpoint>(&duplicate).is_err());
    let unknown = json.replacen("{", "{\"activation_authorized\":true,", 1);
    assert!(serde_json::from_str::<Checkpoint>(&unknown).is_err());
}
