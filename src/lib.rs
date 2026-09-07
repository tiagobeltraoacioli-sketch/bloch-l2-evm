// SPDX-License-Identifier: MIT OR Apache-2.0
//! # bloch-l2-evm — **SCAFFOLD, UNAUDITED, not a working L2.**
//!
//! Execution-layer state-transition scaffold for the Bloch EVM L2 described in
//! `docs/specs/BLOCH-L2-EVM-DESIGN.md` §1. It is a first-iteration,
//! compiling skeleton — real, tested code where feasible, honest labelled stubs
//! where a multi-month integration (Reth node, SP1 guest) belongs. **Nothing
//! here is a working Layer-2.** No claim of ethereum/tests or EEST conformance
//! is made anywhere in this crate. An internal deep audit exists
//! (`AUDITORIA-L2.md`); the P0 findings are addressed, the rest are tracked
//! there and in `tests/audit_regressions.rs`.
//!
//! > **The reorg gate (from the design, read first).** An L2 inherits its
//! > L1's finality. Bloch today is k=4 forgeable, 51%-attackable, unaudited —
//! > a Bloch reorg can unwind L2 state anchored to reorged blocks. Real value
//! > is gated on Bloch mainnet security (k=8 ramp, WAN hashrate, checkpoint
//! > finality) + a third-party audit + legal review. Everything below is
//! > **testnet / zero-value** until then.
//!
//! ## What is REAL and tested here
//! * [`chainspec::ChainSpec`] — the design's genesis knobs (chain_id 700771,
//!   30M gas limit, EIP-1559 elasticity 2 / denominator 250, block reward 0,
//!   COINBASE = fee-vault address, L1 supply cap) plus a tested EIP-1559
//!   next-base-fee calculation with those knobs.
//! * [`scale`] — the exact u64-sats (8 decimals, L1 BLCH) ⇄ U256-wei
//!   (18 decimals, L2) helpers with `ATOM_SCALE = 10^10`.
//! * [`state::L2State`] — an account/state layer over revm's
//!   `CacheDB`/`InMemoryDB` with deposit-mint (credits **exactly** the
//!   escrow-derived wei; provenance is bridged BLCH **only**; deposits must
//!   strictly advance a cursor of canonical L1 positions, so each escrow
//!   output mints at most once; the L1 cap bounds every deposit and the
//!   cumulative supply) and a two-slot supply ledger **committed in the state
//!   root** as the storage of a system account.
//! * [`executor::execute_block`] — runs **UNMODIFIED** revm at
//!   `SpecId::CANCUN`, **atomically** (the caller's state is untouched on any
//!   error), accepts only transaction types 0/1/2, applies deposit mints at
//!   block start, routes the basefee part of what revm charged to the
//!   `BaseFeeVault` and the priority fee to the `SequencerFeeVault` — the
//!   protocol never burns bridged BLCH.
//! * [`stateroot::compute_keccak_mpt_state_root`] — the **real** keccak-256
//!   hexary Merkle-Patricia state root (account trie + per-account storage
//!   tries, empty accounts excluded per EIP-161) via `alloy-trie`, wired into
//!   [`executor::ExecutionOutcome::state_root`], plus
//!   [`stateroot::SparseTrieView`] / [`stateroot::stateless_new_root`]: the
//!   **authenticated** sparse-trie update a stateless guest uses (proof
//!   hash-linked to `prev_state_root`, incomplete witnesses rejected).
//! * [`proving`] — host-side [`proving::generate_batch_witness`] (records the
//!   batch's full read set, self-verifies with the guest procedure) and the
//!   guest procedure [`proving::verify_batch`] (hydrate + verify pre-state,
//!   re-execute with reads outside the witness failing, derive the change set,
//!   compute the post-state root statelessly).
//!
//! ## What is honestly STUBBED (`todo!()` / `unimplemented!()`, `// SCAFFOLD:`)
//! * the `eth_*` JSON-RPC surface, the txpool, and the Reth-SDK node
//!   embedding ([`stubs`]).
//! * the SP1 guest (riscv32im) build target ([`stubs::sp1_guest`]) — the
//!   procedure it must run is [`proving::verify_batch`].
//!
//! The L2 is an **owned Postern product** that anchors to the ownerless Bloch
//! base as ordinary transactions; the base gains no operator and needs no
//! consensus change. BLCH is never sold and the L2 never issues new BLCH.

// Design determinism rule (§1): integer-only arithmetic in the execution path.
#![deny(clippy::float_arithmetic)]
#![warn(missing_docs)]
// `no_std` + `alloc` capable (the shape an SP1 guest requires) — the default
// `std` feature keeps the host build unchanged; `--no-default-features` proves
// the crate's own source carries no std dependency. (revm/alloy still need
// their own no_std features flipped for a real riscv32im guest build — the SP1
// toolchain stage; this establishes OUR code is no_std-clean.)
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
// The test harness itself links std; make it available to test code in the
// no_std configuration too, so `cargo test --no-default-features` compiles.
#[cfg(test)]
#[macro_use]
extern crate std;

pub mod chainspec;
pub mod executor;
pub mod proving;
pub mod scale;
pub mod state;
pub mod stateroot;
pub mod stubs;

pub use chainspec::ChainSpec;
pub use executor::{
    deposits_hash, execute_block, validate_block_input, BlockContext, BlockExecutionError, BlockInput,
    ExecutionOutcome, TxOutcome, SUPPORTED_TX_TYPES,
};
pub use proving::{
    generate_batch_witness, hydrate_and_verify, verify_batch, BatchWitness, GenerateError, GuestState,
    HydratedPreState, VerifiedBatch, VerifyError, WitnessAccessError, WitnessAccount, WitnessBacking,
};
pub use scale::{sats_to_wei, wei_to_sats, ATOM_SCALE};
pub use state::{DepositError, DepositMint, DepositPosition, DepositProvenance, L2Account, L2State};
pub use stateroot::{compute_keccak_mpt_state_root, stateless_new_root, SparseTrieView, WitnessError};

/// The exact revm version this scaffold is pinned to (also pinned as `=41.0.0`
/// in `Cargo.toml` and recorded in `README.md`). Any bump is a documented
/// program upgrade per the design's determinism contract.
pub const REVM_PIN: &str = "41.0.0";
