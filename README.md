<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# bloch-l2-evm

> **SCAFFOLD, not a working L2.** This crate is a first-iteration,
> compiling skeleton of the execution layer described in
> `docs/specs/BLOCH-L2-EVM-DESIGN.md` §1 (design documents live in the
> upstream monorepo, not in this repository). Nothing here is deployed or
> value-bearing, and **no claim of ethereum/tests or EEST conformance is made
> anywhere**. It is not a node, not a sequencer, not a prover, and not a Reth
> embedding — it is the state-transition core those would call, plus honest
> labelled stubs. An internal deep audit and its status live in
> [`AUDITORIA-L2.md`](AUDITORIA-L2.md) (Portuguese) and
> [`tests/audit_regressions.rs`](tests/audit_regressions.rs).

> **The reorg gate (from the design, read first).** An L2 inherits its L1's
> finality. Bloch today is k=4 forgeable, 51%-attackable, unaudited — a Bloch
> reorg can unwind L2 state anchored to reorged blocks. Real value is gated on
> Bloch mainnet security (k=8 ramp, WAN hashrate, checkpoint finality) + a
> third-party audit + legal review. Everything below is **testnet /
> zero-value** until then.

The L2 is an **owned Postern product** (it has a sequencer/operator) that
anchors to the ownerless Bloch-SIS-PoW base as ordinary transactions — the
base gains no operator and needs no consensus change. The native gas token is
an L2 representation of **bridged BLCH**: zero issuance, never sold, and never
burned by the protocol (the EVM's EIP-6780 `SELFDESTRUCT`-to-self can still
destroy value; see audit finding C11).

## Version pins (normative for this scaffold)

| dependency | pin | why |
|---|---|---|
| `revm` | **`=41.0.0`** (exact) | The design requires ONE pinned revm so the native node and the future SP1 guest re-execute byte-identical code; any bump is a documented program upgrade. |
| `alloy-primitives` | `1.6.0` (resolves to 1.6.1 via `Cargo.lock`) | `Address`/`U256`/`B256` are one type family across the crate. Exact pinning of the alloy crates is tracked as audit finding C31. |
| hardfork | `SpecId::CANCUN` | Cancun at genesis per the design; Prague only via a coordinated, height-gated upgrade. |

`Cargo.lock` is committed (determinism contract, design §1).

## What is REAL and tested (`cargo test`)

* **`ChainSpec`** (`src/chainspec.rs`) — the design's genesis knobs:
  `chain_id = 700771` (testnet placeholder pending ethereum-lists/chains
  registration), `gas_limit = 30_000_000`, EIP-1559 `elasticity = 2` /
  `denominator = 250`, initial base fee 1 gwei, **block reward = 0**,
  COINBASE = fee-vault address, the supply-ledger system account and the L1
  supply cap (`max_l1_sats`, a **placeholder** of 21M BLCH pending the design
  document). Includes a tested integer-only EIP-1559 next-base-fee computation.
* **Exact sats⇄wei scaling** (`src/scale.rs`) — `ATOM_SCALE = 10^10`: u64 L1
  sats (8 decimals) scale exactly to U256 L2 wei (18 decimals); the reverse
  direction fails (never rounds) on non-aligned amounts. 1 BLCH = 10^18 wei.
* **`L2State`** (`src/state.rs`) — an account/state layer over revm's
  `CacheDB`/`InMemoryDB` with **deposit-mint**: credits *exactly*
  `sats_to_wei(l1_sats)`; provenance is a single-variant enum (**bridged BLCH
  only** — no admin mint, no reward, no other asset); deposits must
  **strictly advance a cursor of canonical L1 positions**
  `(l1_height, l1_tx_index, l1_vout)` — the OP-Stack/Arbitrum inbox model —
  so each escrow output mints at most once and replays, duplicates and
  out-of-order derivation are rejected; every deposit and the cumulative
  supply are bounded by the L1 cap. The ledger (total minted wei + cursor)
  is two storage slots of the `SUPPLY_LEDGER` system account, so it is
  **committed in the state root** and carried by batch witnesses at O(1)
  size whatever the chain's history.
* **`execute_block`** (`src/executor.rs`) — runs **UNMODIFIED revm** at
  `SpecId::CANCUN`, **atomically**: the block is validated, applied to a
  working copy, and the caller's state is replaced only on success (on any
  error it is byte-identical to the pre-block state). Accepts only
  transaction types 0/1/2 (type 3 and every other type byte are rejected at
  the boundary), applies deposit mints at block start, routes the basefee
  part of what revm actually charged to the `BaseFeeVault` (`0x4200…0019`)
  and the priority fee to the `SequencerFeeVault` (`0x4200…0011`, the block
  beneficiary), and commits the deposit list via `deposits_hash`. Tests cover
  transfers, deploy+call, reverts, fee routing, every error path (state
  unchanged), replay, caps and unsupported types.
* **keccak-256 MPT state root** (`src/stateroot.rs`) — a real, standard
  Ethereum keccak-256 hexary Merkle-Patricia trie root over the
  post-execution account trie + per-account storage tries, built with
  `alloy-trie`'s `HashBuilder`, accounts/storage RLP-encoded exactly as
  Ethereum does; empty accounts (EIP-161) and zero slots excluded. Plus
  **`SparseTrieView` / `stateless_new_root`**: the authenticated sparse-trie
  update a stateless guest uses — the multiproof is hash-linked to
  `prev_state_root` node by node, embedded (< 32-byte) children are decoded
  in place, and every malformed or incomplete witness is a `WitnessError`
  (never a panic or a silently wrong root).
* **Stateless proving path** (`src/proving.rs`) — host-side
  `generate_batch_witness` records the batch's full read set with a
  recording overlay, emits existing accounts (with complete non-zero
  storage) and absent addresses, builds the multiproof, and self-verifies by
  running the guest procedure; guest-side `verify_batch` hydrates and
  verifies the pre-state (inclusion for every account, provable absence for
  every absent address), re-executes with reads outside the witness
  **failing**, derives the change set itself and computes the post-state
  root statelessly. Tests cover honest batches (transfers, contract calls
  that read other accounts, deposits through the ledger) and tampering
  (omitted / injected / stripped / forged inputs are rejected).

## What is honestly STUBBED (`todo!()` / `unimplemented!()`, `// SCAFFOLD:`)

* `eth_*` JSON-RPC, txpool, and the Reth-SDK node embedding (`src/stubs.rs`)
  — the design mandates Reth's stack precisely so this surface is *not*
  hand-rolled.
* the SP1 guest (riscv32im) build target (`src/stubs.rs::sp1_guest`) — the
  procedure it must run is `proving::verify_batch`; the dependency-level
  no_std wiring is the SP1 toolchain stage.
* genesis alloc / predeploy bytecode (the vault addresses exist as plain
  balance-holding accounts here, not deployed Solidity vaults), block hashes
  for `BLOCKHASH`, the EIP-4788 system call, and header validation against
  the parent (audit findings C13, C16, C17).

## Layout / build

Standalone cargo crate with its own empty `[workspace]` table (the
`crates/bloch-tokens` pattern) so it stays outside the product root workspace
and carries the heavy revm tree independently.

```sh
cargo build
cargo test                                          # unit tests + live audit regressions
cargo test --test audit_regressions -- --ignored    # still-open audit findings (expected: failures)
cargo test --no-default-features                    # the crate's own source is no_std-clean
```

License: MIT OR Apache-2.0. `publish = false`, version `0.0.0-scaffold`.
