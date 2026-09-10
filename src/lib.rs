// SPDX-License-Identifier: MIT OR Apache-2.0
//! # bloch-l2-evm — **SCAFFOLD, UNAUDITED, not a working L2.**
//!
//! Execution-layer state-transition scaffold for the Bloch EVM L2 described in
//! `docs/specs/BLOCH-L2-EVM-DESIGN.md` §1. It is a first-iteration,
//! compiling skeleton — real, tested code where feasible, honest labelled stubs
//! where a multi-month integration (Reth node, SP1 guest) belongs. **Nothing
//! here is a working Layer-2.** No claim of ethereum/tests or EEST conformance
//! is made anywhere in this crate. An internal deep audit exists
//! (`AUDITORIA-L2.md`); its P0, P1 and P2 findings are addressed and its
//! regression tests live in `tests/audit_regressions.rs`.
//! A second-pass review (`SECURITY-AUDIT-2026-09-07.md`) adds adversarial
//! regressions in `tests/deep_security.rs` and documents the remaining
//! L1 derivation and proving-system boundaries. [`transactions`] adds the
//! authenticated L2 ECDSA ingress; native Bloch L1 remains PQ-only.
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
//!   COINBASE = fee-vault address, the L1 supply cap of 100 billion BLCH,
//!   the per-deposit gas) plus a tested EIP-1559 next-base-fee calculation
//!   with those knobs. [`ChainSpec::validate`] rejects every degenerate knob
//!   and the executor refuses to run under an invalid spec.
//! * [`scale`] — the exact u64-sats (8 decimals, L1 BLCH) ⇄ U256-wei
//!   (18 decimals, L2) helpers with `ATOM_SCALE = 10^10`.
//! * [`state::L2State`] — a **sealed** account/state layer over revm's
//!   `CacheDB`/`InMemoryDB` with deposit-mint (credits **exactly** the
//!   escrow-derived wei; provenance is bridged BLCH **only**; deposits must
//!   strictly advance a cursor of canonical L1 positions, so each escrow
//!   output mints at most once; the L1 cap bounds every deposit and the
//!   cumulative supply), a three-slot supply ledger (minted, cursor, burned)
//!   and the head-block record **committed in the state root** as the storage
//!   of system accounts. One EIP-161 existence predicate is shared by the
//!   views, the root and the pruning (no ghost accounts, no zero slots), and
//!   the keccak-MPT commitment is cached and maintained **incrementally**.
//! * [`executor::execute_block`] — runs **UNMODIFIED** revm at
//!   `SpecId::CANCUN`, **atomically** and in **O(what the block touched)**:
//!   the block runs on an overlay of the state (nothing is cloned) and only
//!   the touched accounts are re-hashed. It validates the header against the committed head record
//!   (number, timestamp, EIP-1559 base fee), serves `BLOCKHASH` from a
//!   committed 256-entry ring of real L2 block hashes, runs the EIP-4788
//!   system call (storing the Bloch anchor root), accepts only
//!   EIP-155-protected transactions of types 0/1/2, applies deposit mints at
//!   block start (each metered at `ChainSpec::deposit_gas` of the block
//!   budget), routes the basefee part of what revm charged to the
//!   `BaseFeeVault` and the priority fee to the `SequencerFeeVault` — the
//!   protocol never burns bridged BLCH — and records what the EVM itself
//!   destroyed (EIP-6780) in the ledger, so
//!   `total_native == total_minted - total_burned` always holds.
//! * [`stateroot::compute_keccak_mpt_state_root`] — the **real** keccak-256
//!   hexary Merkle-Patricia state root (account trie + per-account storage
//!   tries, empty accounts excluded per EIP-161) via `alloy-trie`, the
//!   from-scratch reference; [`mpt::Mpt`] is the owned, **incremental** trie
//!   (byte-identical roots and proofs, asserted against `HashBuilder`) that
//!   backs [`executor::ExecutionOutcome::state_root`] per block; plus
//!   [`stateroot::SparseTrieView`] / [`stateroot::stateless_new_root`]: the
//!   **authenticated** sparse-trie update a stateless guest uses (proof
//!   hash-linked to `prev_state_root`, incomplete witnesses rejected).
//! * [`proving`] — host-side [`proving::generate_batch_witness`] (one
//!   recording run on an overlay, proof from the cached trie, no clone of the
//!   pre-state, self-verifies with the guest procedure) and the
//!   guest procedure [`proving::verify_batch`] (hydrate + verify pre-state,
//!   re-execute with reads outside the witness failing, derive the change set,
//!   compute the post-state root statelessly).
//!
//! * [`transactions`] — canonical EIP-155/2930/1559 decoding, low-S ECDSA
//!   recovery, signed host execution and signed guest verification. Always use
//!   these entry points for network input; raw `TxEnv` callers remain trusted.
//!
//! ## What is honestly STUBBED (`todo!()` / `unimplemented!()`, `// SCAFFOLD:`)
//! * the `eth_*` JSON-RPC surface, the txpool, and the Reth-SDK node
//!   embedding ([`stubs`]).
//! * the SP1 guest (riscv32im) build target ([`stubs::sp1_guest`]) — the
//!   procedure it must run is [`transactions::verify_signed_batch`].
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
pub mod genesis4;
pub mod mpt;
pub mod proving;
pub mod scale;
pub mod state;
pub mod stateroot;
pub mod stubs;
pub mod transactions;

pub use chainspec::{ChainSpec, ChainSpecError};
pub use executor::{
    deposits_hash, execute_block, validate_block_input, BlockContext, BlockExecutionError, BlockInput,
    ExecutionOutcome, L2Header, TxOutcome, SUPPORTED_TX_TYPES,
};
pub use mpt::Mpt;
pub use proving::{
    generate_batch_witness, hydrate_and_verify, verify_batch, BatchWitness, GenerateError, GuestState,
    HydratedPreState, VerifiedBatch, VerifyError, WitnessAccessError, WitnessAccount, WitnessBacking,
};
pub use scale::{sats_to_wei, wei_to_sats, ATOM_SCALE};
pub use state::{DepositError, DepositMint, DepositPosition, DepositProvenance, HeadRecord, L2Account, L2State};
pub use stateroot::{compute_keccak_mpt_state_root, stateless_new_root, SparseTrieView, WitnessError};
pub use transactions::{
    decode_signed_transaction, execute_signed_block, generate_signed_batch_witness, verify_signed_batch,
    AuthenticatedTransaction, SignedBlockInput, SignedInputError, TransactionAuthError,
};

/// The exact revm version this scaffold is pinned to (also pinned as `=41.0.0`
/// in `Cargo.toml` and recorded in `README.md`). Any bump is a documented
/// program upgrade per the design's determinism contract.
pub const REVM_PIN: &str = "41.0.0";
