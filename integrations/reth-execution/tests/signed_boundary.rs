// SPDX-License-Identifier: MIT OR Apache-2.0
//! Re-run the portable signed boundary against the host's unified dependency graph.
//!
//! Reth storage enables Alloy's secp256k1 recovery backend alongside k256.
//! Reuse the exact canonical-byte, domain, scalar and atomicity regressions so
//! feature unification cannot silently bypass the portable authentication gate.
//! The core-only `serde` wire test is covered by the portable all-features job.

#[allow(unexpected_cfgs)]
#[path = "../../../tests/signed_transactions.rs"]
mod signed_transactions;
