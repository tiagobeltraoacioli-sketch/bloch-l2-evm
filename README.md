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
> [`tests/audit_regressions.rs`](tests/audit_regressions.rs); its P0, P1 and
> P2 findings are fixed and every finding has a live regression test.

The [second-pass security audit](SECURITY-AUDIT-2026-09-07.md) documents
additional fixes for sparse-proof completeness, canonical decoding, the Cancun
hardfork boundary, transaction-field consistency, and configured head access.
It also records the remaining L1 authentication and proof-system integration
requirements. The [L2 wallet boundary](WALLET-COMPATIBILITY.md) now authenticates
original signed Ethereum bytes in host execution and guest verification; native
Bloch L1 authorization remains PQ-only. The included EIP-1193 client adapter is
ready to integrate with an application; the RPC/Reth node itself remains stubbed. Regressions live in `tests/deep_security.rs`.

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
burned by the protocol. The EVM's EIP-6780 `SELFDESTRUCT`-to-self can still
destroy value; the executor measures that per transaction and commits the
running total, so `total_native == total_minted - total_burned` always holds
(audit finding C11).

## Version pins (normative for this scaffold)

| dependency | pin | why |
|---|---|---|
| `revm` | **`=41.0.0`** (exact), `default-features = false`, features `c-kzg`, `portable` | The design requires ONE pinned revm so the native node and the future SP1 guest re-execute byte-identical code; any bump is a documented program upgrade. `c-kzg` provides the Cancun point-evaluation precompile; `secp256k1` (C) is not enabled (ecrecover uses the pure-Rust `k256`), nor `blst`/`tracer`. The guest's one feature delta is `c-kzg` → `kzg-rs`. |
| `alloy-consensus` / `alloy-eips` | **`=2.2.0`** / **`=2.2.0`** (exact) | Signed Ethereum envelopes and k256 sender recovery, exclusively at the L2 authorization boundary. |
| `alloy-primitives` | **`=1.6.1`** (exact) | `Address`/`U256`/`B256` are one type family across the crate. |
| `alloy-trie` / `alloy-rlp` | **`=0.9.5`** / **`=0.3.16`** (exact) | Trie node encoders, `HashBuilder`, proofs and RLP: consensus-relevant, pinned like revm. |
| `ruint` | **`=1.20.0`** (exact) | The U256 implementation. A documented program upgrade over the audited 1.19.0 (RUSTSEC-2026-0220, shift overflow flags); revm bounds every EVM shift to < 256, so no executed semantics changed. |
| toolchain | **`1.94.1`** (`rust-toolchain.toml`), `rust-version = 1.94.1` | The SP1 vkey depends on the exact compiler; a moving channel is not acceptable. |
| hardfork | `SpecId::CANCUN` | Cancun at genesis per the design; Prague only via a coordinated, height-gated upgrade. |

`Cargo.lock` is committed and CI builds `--locked` (determinism contract,
design §1). Every dependency is `default-features = false` with the feature
set chosen explicitly in `Cargo.toml`; `cargo deny` (`deny.toml`) bans native
backends and unknown sources.

## What is REAL and tested (`cargo test`)

* **Signed wallet ingress** (`src/transactions.rs`) — bounded canonical decoding
  of protected legacy/EIP-2930/EIP-1559 transactions, chain-ID enforcement and
  low-S ECDSA recovery using pinned Alloy/k256. `execute_signed_block` and
  `verify_signed_batch` recover callers from the original bytes. A portable
  [EIP-1193 wallet adapter](wallets/bloch-l2.mjs) provides network selection and
  wallet signing requests; `node --test wallets/bloch-l2.test.mjs` tests it.

* **`ChainSpec`** (`src/chainspec.rs`) — the design's genesis knobs:
  `chain_id = 700771` (testnet placeholder pending ethereum-lists/chains
  registration), `gas_limit = 30_000_000`, EIP-1559 `elasticity = 2` /
  `denominator = 250`, initial base fee 1 gwei, **block reward = 0**,
  COINBASE = fee-vault address, the supply-ledger and block-info system
  accounts, the EIP-4788 predeploy (canonical bytecode), the L1 supply cap
  (`max_l1_sats` = 100 billion BLCH = 10^19 sats, the most the L2 supply can
  ever reach: 10^29 wei) and the per-deposit gas (`deposit_gas` = 21 000).
  `ChainSpec::validate` rejects every degenerate knob and the executor refuses
  an invalid spec. Includes a tested, total, integer-only EIP-1559
  next-base-fee computation.
* **Exact sats⇄wei scaling** (`src/scale.rs`) — `ATOM_SCALE = 10^10`: u64 L1
  sats (8 decimals) scale exactly to U256 L2 wei (18 decimals); the reverse
  direction fails (never rounds) on non-aligned amounts. 1 BLCH = 10^18 wei.
* **`L2State`** (`src/state.rs`) — a **sealed** account/state layer over
  revm's `CacheDB`/`InMemoryDB` (`db()` to read, `db_mut()` invalidates the
  cached commitment) with **deposit-mint**: credits *exactly*
  `sats_to_wei(l1_sats)`; provenance is a single-variant enum (**bridged BLCH
  only** — no admin mint, no reward, no other asset); deposits must
  **strictly advance a cursor of canonical L1 positions**
  `(l1_height, l1_tx_index, l1_vout)` — the OP-Stack/Arbitrum inbox model —
  so each escrow output mints at most once and replays, duplicates and
  out-of-order derivation are rejected; every deposit and the cumulative
  supply are bounded by the L1 cap. The ledger (total minted wei, cursor,
  total burned wei) is three storage slots of the `SUPPLY_LEDGER` system
  account, and the head-block record plus a 256-entry ring of L2 block
  hashes are storage of the `BLOCK_INFO` system account, so all of it is
  **committed in the state root** and carried by batch witnesses at O(1)
  size whatever the chain's history. One EIP-161 existence predicate is
  shared by the views, the root, the witness and the pruning: touched-empty
  accounts never persist and zero-valued slots are dropped when a block is
  applied, so the live state and the committed root agree account for account.
* **`execute_block`** (`src/executor.rs`) — runs **UNMODIFIED revm** at
  `SpecId::CANCUN`, **atomically and in O(what the block touched)**: the
  block is validated, run on an overlay of the state that holds only the
  accounts it reads or writes, and merged only on success (on any error the
  state is byte-identical to the pre-block state; nothing is cloned). It
  validates the header
  against the committed head record (`number == head + 1`, non-decreasing
  timestamp, `base_fee == next_base_fee(head)`; `BlockContext::next` derives
  a conforming one), defines the L2 block hash (`L2Header::hash`), serves
  `BLOCKHASH` from the committed 256-entry ring of real block hashes, runs
  the EIP-4788 system call at block start (storing the Bloch anchor root),
  accepts only EIP-155-protected transactions of types 0/1/2 (type 3, every
  other type byte, unprotected and foreign-chain transactions are rejected at
  the boundary), applies deposit mints at block start (each metered at
  `deposit_gas` of the block budget, fee-less, so at most
  `gas_limit / deposit_gas` deposits fit and deposit load moves the base fee
  like user load), routes the basefee
  part of what revm actually charged to the `BaseFeeVault` (`0x4200…0019`)
  and the priority fee to the `SequencerFeeVault` (`0x4200…0011`, the block
  beneficiary), reconciles every transaction's balance deltas to measure the
  EIP-6780 burn, and commits the deposit list via `deposits_hash`. Tests
  cover transfers, deploy+call, reverts, fee routing, header rules, block
  hashes, the system call, burns, every error path (state unchanged), replay,
  caps and unsupported types.
* **keccak-256 MPT state root** (`src/stateroot.rs`, `src/mpt.rs`) — a
  real, standard Ethereum keccak-256 hexary Merkle-Patricia trie root over
  the post-execution account trie + per-account storage tries, accounts and
  storage RLP-encoded exactly as Ethereum does; empty accounts (EIP-161) and
  zero slots excluded. The from-scratch reference uses `alloy-trie`'s
  `HashBuilder`; the state keeps an **incremental** owned trie (`Mpt`: cached
  node hashes, only changed paths re-hashed, byte-identical roots *and*
  proofs asserted against `HashBuilder`/`ProofRetainer`), so sealing an
  empty block costs the same against 1k or 1M accounts. Plus
  **`SparseTrieView` / `stateless_new_root`**: the authenticated sparse-trie
  update a stateless guest uses — the multiproof is hash-linked to
  `prev_state_root` node by node, embedded (< 32-byte) children are decoded
  in place, and every malformed or incomplete witness is a `WitnessError`
  (never a panic or a silently wrong root).
* **Stateless proving path** (`src/proving.rs`) — host-side
  `generate_batch_witness` runs the batch **once** on a recording overlay
  (read set and post-state at the same time, the pre-state is never cloned),
  emits existing accounts (with complete non-zero storage) and absent
  addresses, takes the multiproof from the cached trie (a from-scratch pass
  only when the cache is cold), derives the post-state root through the
  guest's own sparse-trie update, and self-verifies by running the guest
  procedure; with the `serde` feature the witness is the round-trip-tested
  host→guest wire format. Guest-side `verify_batch` hydrates and
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
  procedure it must run is `transactions::verify_signed_batch`; the dependency-level
  no_std wiring is the SP1 toolchain stage.
* genesis alloc / vault predeploy bytecode (the vault addresses exist as
  plain balance-holding accounts here, not deployed Solidity vaults), the
  anchor reader (the Bloch anchor root and `prevrandao` are inputs the node
  must derive; the STF commits them), RPC/pool wiring of the signed transaction
  boundary and receipts (transactions are not yet committed in the block header).

## Layout / build

Standalone cargo crate with its own empty `[workspace]` table (the
`crates/bloch-tokens` pattern) so it stays outside the product root workspace
and carries the heavy revm tree independently.

```sh
cargo build --locked
cargo test --locked                                             # unit tests + every audit regression
cargo test --locked --features serde                            # + the witness / snapshot wire-format round trip
cargo test --locked --no-default-features                       # the whole tree (revm, alloy) in no_std + alloc
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo deny check bans sources advisories licenses               # native backends, duplicates, sources, advisories
cargo test --release --test audit_regressions -- --ignored c27  # C27 benchmark at the audit's sizes (160k)
```

CI (`.github/workflows/ci.yml`) runs all of the above with the committed
lockfile and the pinned toolchain.

License: MIT OR Apache-2.0. `publish = false`, version `0.0.0-scaffold`.
