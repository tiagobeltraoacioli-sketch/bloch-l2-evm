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
//! `bloch_native_spend_at_epoch`: the trait carries `verify_spend_at_epoch`
//! (L1 hard fork HF3_SLH_SUITE_EPOCH, suite 0x0003 for eUTXO spends). Its
//! default is fail-closed (the pre-fork verdict), so a replay verifier that
//! keeps it refuses the first block with a suite-0x0003 spend after the fork
//! and the follower halts. With the cfg set the override maps it to
//! `bloch_crypto::crypto::verify_at_epoch`, as the node's HybridVerifier does.
use std::path::Path;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(bloch_native_sig_policy)");
    println!("cargo::rustc-check-cfg=cfg(bloch_native_spend_at_epoch)");
    let attestation = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bloch-validator-payout/crates/bloch-pos-committee/src/attestation.rs");
    println!("cargo::rerun-if-changed={}", attestation.display());
    let source = std::fs::read_to_string(&attestation)
        .unwrap_or_else(|e| panic!("native checkout: cannot read {}: {e}", attestation.display()));
    if source.contains("fn verify_with_key_under(") {
        println!("cargo::rustc-cfg=bloch_native_sig_policy");
    }
    if source.contains("fn verify_spend_at_epoch(") {
        println!("cargo::rustc-cfg=bloch_native_spend_at_epoch");
    }
}
