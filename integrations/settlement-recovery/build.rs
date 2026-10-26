// SPDX-License-Identifier: AGPL-3.0-or-later
//! Detects, in the sibling native checkout this crate is built against, the
//! L1 consensus features the replay verifier must follow, so ONE source tree
//! builds against the running native release AND against a hard-fork release.
//!
//! `bloch_native_sig_policy`: the native `SignatureVerifier` trait carries
//! `verify_with_key_under` (L1 hard fork SIG_CANONICAL_ACTIVATION_EPOCH,
//! audit e9b52781). The transition then judges every signature through a
//! policy wrapper, and a verifier that keeps the trait's default silently
//! applies the PRE-fork rule after the fork: from the activation epoch every
//! proposer signature fails and the follower halts. With the cfg set,
//! `native::NativeConsensusVerifierV1` overrides it with
//! `bloch_crypto::crypto::verify_with_policy`, exactly as the node does.
//!
//! `bloch_native_mldsa_pin`: the native `SignaturePolicy` has the
//! `CompatiblePinned` variant (L1 MLDSA_PIN_ACTIVATION_EPOCH: the ML-DSA half
//! judged by the pinned FIPS 204 verifier). The override maps it to
//! `bloch_crypto::crypto::SignaturePolicy::CompatiblePinned`, as the node's
//! `crypto_policy` does.
//!
//! `bloch_native_spend_at_epoch`: the trait carries `verify_spend_at_epoch`
//! (L1 hard fork HF3_SLH_SUITE_EPOCH, suite 0x0003 for eUTXO spends). Its
//! default is fail-closed (the pre-fork verdict), so a replay verifier that
//! keeps it refuses the first block with a suite-0x0003 spend after the fork
//! and the follower halts. With the cfg set the override maps it to
//! `bloch_crypto::crypto::verify_spend(.., params::hf3_slh_suite_active(epoch))`,
//! as the node's `HybridVerifier` does.
//!
//! `bloch_native_kes_leaf`: the trait carries `verify_kes_leaf` (KES leaves
//! are signed in the canonical, suite-bound v2 form from the first KES
//! signature). Its default is the v1 `verify_with_key`, which refuses every
//! v2 leaf: the follower would halt at the first KES-signed proposal or vote.
//! With the cfg set the override maps it to `bloch_crypto::crypto::verify_bound`,
//! as the node's `HybridVerifier` does.
//!
//! Guard: every method of the native `SignatureVerifier` trait must be one
//! this crate has reviewed. A new trait method has a default, so a verifier
//! that does not know about it compiles and silently applies that default;
//! that is exactly how the `verify_kes_leaf` gap went unnoticed. An unknown
//! method fails the build here instead, until it is mirrored from the node's
//! `HybridVerifier` (crates/bloch-pos-node/src/keys.rs) and added below.
use std::path::Path;

/// Native `SignatureVerifier` methods reviewed against the node's
/// `HybridVerifier`, and how `NativeConsensusVerifierV1` handles each.
const REVIEWED_TRAIT_METHODS: &[&str] = &[
    "verify_with_key",       // required; bloch_crypto::crypto::verify
    "verify_with_key_under", // bloch_native_sig_policy
    "verify_spend_at_epoch", // bloch_native_spend_at_epoch
    "verify_kes",            // default in the node too (kes::verify -> verify_kes_leaf)
    "verify_kes_leaf",       // bloch_native_kes_leaf
    "verify_l2_settlement",  // required in practice; bloch_l2_proof::verify
];

fn trait_methods(source: &str) -> Vec<String> {
    let start = source
        .find("pub trait SignatureVerifier {")
        .unwrap_or_else(|| panic!("native checkout: no `pub trait SignatureVerifier` in attestation.rs"));
    let body = &source[start..];
    let end = body
        .find("\n}\n")
        .unwrap_or_else(|| panic!("native checkout: unterminated `SignatureVerifier` trait"));
    body[..end]
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("fn ")?;
            Some(rest.split(|c: char| c == '(' || c == '<').next()?.trim().to_owned())
        })
        .collect()
}

fn main() {
    println!("cargo::rustc-check-cfg=cfg(bloch_native_sig_policy)");
    println!("cargo::rustc-check-cfg=cfg(bloch_native_mldsa_pin)");
    println!("cargo::rustc-check-cfg=cfg(bloch_native_spend_at_epoch)");
    println!("cargo::rustc-check-cfg=cfg(bloch_native_kes_leaf)");
    let attestation = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bloch-validator-payout/crates/bloch-pos-committee/src/attestation.rs");
    println!("cargo::rerun-if-changed={}", attestation.display());
    let source = std::fs::read_to_string(&attestation)
        .unwrap_or_else(|e| panic!("native checkout: cannot read {}: {e}", attestation.display()));
    let methods = trait_methods(&source);
    for m in &methods {
        if !REVIEWED_TRAIT_METHODS.contains(&m.as_str()) {
            panic!(
                "native SignatureVerifier has an unreviewed method `{m}`: mirror the node's \
                 HybridVerifier in src/native.rs and add it to REVIEWED_TRAIT_METHODS in build.rs"
            );
        }
    }
    let has = |m: &str| methods.iter().any(|x| x == m);
    if has("verify_with_key_under") {
        println!("cargo::rustc-cfg=bloch_native_sig_policy");
    }
    if source.contains("    CompatiblePinned,") {
        println!("cargo::rustc-cfg=bloch_native_mldsa_pin");
    }
    if has("verify_spend_at_epoch") {
        println!("cargo::rustc-cfg=bloch_native_spend_at_epoch");
    }
    if has("verify_kes_leaf") {
        println!("cargo::rustc-cfg=bloch_native_kes_leaf");
    }
}
