# Audit scope: the sparse settlement witness guest

Status: **candidate, inert.** No release builds or selects this code, no L1
configuration names its programs, and the pinned programs (`settlement_v3_mainnet`
`203114bf…`, candidate `44d4c9d7…`) do not change by a byte with the
`sparse-witness` feature off.

Branch `codex/sparse-audit-r7-20261102`. The commit under audit is the one named
in "Programs" below; later commits on the branch that touch only `docs/` do not
change the programs.

## What the guest does

The settlement guest proves that one L2 block, executed on top of
`prev_state_root`, gives the header, receipts, withdrawals and post-state root its
statement names. The complete witness (`crate::proving::BatchWitness`) carries
every non-zero storage slot of every touched account, so its cost grows with
storage, not with work: an empty block at L2 height 8191 costs 227.7M
instructions through the EIP-4788 ring, and one cheap call to a 100k-slot contract
costs 1,319M.

The sparse witness (`SparseBatchWitness`) carries, for each touched account, its
nonce, balance, code hash, storage root and a multiproof of only the slots the
block touches, plus the code the block loads. The state transition, the roots and
the 766-byte statement are the same as with the complete witness; only the
program identity differs. Measured: 2.45M instructions for the empty block at
8191, 3.56M for the 100k-slot contract (agent 81, execute-only), and real
Groth16 proofs at about 34 GiB.

## In scope

| File | Lines | What to review |
|---|---:|---|
| `src/sparse_witness.rs` | 1,028 | All of it: witness types and their bounded decoding, `SparseBacking` (the guest's database), `hydrate_sparse`, `post_storage_root`, `derive_post_root`, `prepare_parent_lazy`, `run_sparse_block`, `verify_node_batch_sparse`, `execute_settlement_statement_v3_sparse`. The generator (`RecordingDb`, `generate_sparse_node_witness`) is host code: a bug there can only make a block fail to prove, see "Trust assumptions" |
| `src/sparse_view.rs` | 169 | `IndexedTrieView`: the frontier index, `lookup`, `apply` (included into `stateroot.rs` under the feature) |
| `src/stateroot.rs` | lines 395-740 | `SparseTrieView::from_proof`, `walk`, `contains_key`, `apply`. Pre-existing and already used by the pinned guest for the account trie; the sparse guest uses it for every storage trie as well |
| `src/state.rs` | `ensure_system_account`, `credit_balance`, `account_exists`, `info_exists` | The only places besides revm's commit that set `StorageCleared` |
| `integrations/sp1-execution/guest-sparse/src/bin/*.rs` | 3 x 35 | Program entry points: compiled chain spec, input order, statement commit |
| `integrations/sp1-execution/guest-sparse/Cargo.toml`, `Cargo.lock` | | Features (`default-features = false`, `sparse-witness`), SP1 patches (tiny-keccak, k256) pinned by tag and commit |
| `integrations/sp1-execution/guest-sparse/container/Dockerfile`, `build-container.sh` | 38 + 71 | The pinned build. The ELF is pinned only as built here |

Out of scope, but listed so that nothing is assumed: the host export path
(`integrations/execution-artifact`, `integrations/reth-execution/src/proof_export.rs`,
`bloch-l2-produce-dev export --witness sparse`), the settler
(`deployment/mainnet/settler`), the L1 side (`PROGRAM_NEXT` on
`codex/guest-activation-r5-20261102`), and the test and review tools in
`integrations/sp1-execution/host/src/bin/bloch-evm-sp1-sparse-*.rs`. A bug in any
of them can stop settlement; none of them can make the guest accept a wrong
transition.

## Trust assumptions

1. **revm 41** (`revm-context`, `revm-handler`, `revm-database` 41.0.0) executes
   the EVM correctly, and a database error raised inside any call frame is
   returned as the fatal `EVMError::Database`, never as a revert a contract can
   observe or catch. `BlockSession::try_transaction` turns it into a failed
   block.
2. **revm loads code only through `code_by_hash`** when `AccountInfo.code` is
   `None` (`load_account_with_code`, `load_code`). The guest hydrates every
   account with `code: None`.
3. **alloy-trie and keccak-256.** Node decoding and hashing are correct; inside
   the zkVM keccak is SP1's `keccak-permute` precompile through the patched
   `tiny-keccak` (`patch-2.0.2-sp1-6.2.0`).
4. **SP1** v6.8.0 (zkVM, executor), circuit v6.1.0, and the Groth16 wrapper are
   sound. The L1 verifier checks the BN254 program key against a compiled
   constant.
5. **`prev_state_root` is authentic.** It is bound by the settlement statement
   chain, exactly as for the complete witness. The guest proves a transition from
   it; it does not prove the root itself.
6. **The witness and its generator are untrusted.** Every value the guest uses is
   either hash-linked to `prev_state_root` or computed by the guest. The
   generator only affects liveness: it refuses any witness whose stateless
   verification differs from the independent complete-witness path in header,
   receipts, withdrawals or transaction results.
7. **The build toolchain binaries are trusted, not source-reproduced.** The
   container pins Succinct's release tarballs by SHA-256 (`cargo-prove` v6.8.0,
   `succinct-1.96.0-64bit-v2`, whose `rustc -vV` reports an unknown commit) and
   the Rust base image by digest. Reproducibility means "the same inputs give the
   same ELF on any Linux x86_64 host", not "the compiler was rebuilt from source".

## Invariants

Each is tested; the test names are in `src/sparse_witness/tests.rs` (T) and
`src/sparse_witness/review.rs` (R).

1. **No unwitnessed zero.** A storage read returns the value of a leaf hash-linked
   to the account's storage root, zero only for a position the proof exposes as
   empty, and otherwise an error that fails the block. `StorageCleared`, the
   marker that makes a missing slot read as zero, is never set by hydration.
   (T: omit-read, omit-exclusion, forged leaf, forged trie; R: the trie property
   over 160,000 random tries, inline nodes.)
2. **Account binding.** Each hydrated account's nonce, balance, code hash and
   storage root are compared byte for byte with the leaf under
   `prev_state_root`. Each address listed absent is proved excluded. Duplicates,
   EIP-161 empty accounts and the zero code hash are refused. A touched account
   in neither list is a database error.
3. **Code binding (new, I1).** The guest hashes every entry of `codes` and keys
   it by the hash it computed, so an entry is only ever served for its own hash.
   A code load of any hash not in the list fails the block. An entry nobody
   loads is unused. Empty, undecodable and duplicate entries are refused.
4. **Errors are fatal.** No witness omission can become a failed inner call:
   every state opcode (BALANCE, EXTCODESIZE, EXTCODEHASH, EXTCODECOPY, CALL,
   STATICCALL, DELEGATECALL, CALLCODE, SELFDESTRUCT, SLOAD, SSTORE) under a
   catching frame fails the block when its account, slot or code is left out.
   Below the cold-access gas, revm performs no load on either path.
5. **Post-state root.** Every cached slot of an account not wiped in the block
   needs an authenticated pre-state, including a write without a read and a zero
   write. A deletion that collapses a branch onto an opaque child is refused. An
   account created or wiped in the block (`StorageCleared`) is rebuilt from its
   cached storage only. The derived root must equal the witness's claim and is
   the one the statement carries.
6. **Lazy BLOCKHASH.** The parent's hash is written to its ring slot before any
   transaction; any other `BLOCKHASH` in `[N-256, N)` is an authenticated slot
   read, and a number outside the window is an error. The value equals the eager
   path's.
7. **Statement equivalence.** For the same block, the sparse statement equals the
   complete witness's statement byte for byte. Measured on 538 real blocks by
   agent 88, and on the programs below over 505 stored real blocks of 17 private
   chains: 0 differences, and the statement equals the real proof's public
   values on 491 of 491 blocks that kept their proof. In the same run, the ELF
   refused every witness the native path refused after removing one trie node
   (290), and every witness with one code entry removed (505).
8. **Malleability is harmless.** Reordered lists, extra trie nodes, extra
   accounts, extra absent addresses and extra code entries change only the
   program input, never the statement.
9. **Allocation guards are not rules.** Trie nodes at most 1,024 bytes, code
   entries at most 24,576 bytes (EIP-170), at most 65,536 entries and 1 GiB of
   code in all: far above what a block's gas can load.

## Changes made for the audit (agent 115)

| Finding | Change |
|---|---|
| I1: a deposit carried and hashed the recipient's whole code | `SparseWitnessAccount.code` is replaced by `code_hash`; code travels once in `SparseBatchWitness::codes`, only when loaded. The generator strips code from the accounts it reads, records every `code_by_hash`, and includes only those hashes |
| I3: unreachable `NotExisting` arm in `derive_post_root`, misleading comment | The arm now refuses (`UnknownAccount`) instead of deriving a leaf; the comment names `ensure_system_account` and `credit_balance` |
| I2: the ELF depended on the build host | `container/Dockerfile` and `build-container.sh`: one pinned image, sources at `/bloch-l2-evm`, registry at `/cargo` |
| Artifact | The sparse artifact format moves to `BLOCH:EVM:EXECUTION-ARTIFACT:SPARSE:2`; version 1 files no longer decode |
| Pins | The settler's `MAINNET_NEXT_SPARSE` and the sparse crossing harness name the programs below. The native `PROGRAM_NEXT` (L1 side, out of scope) must move with them |
| Review tool | `bloch-evm-sp1-sparse-diff` also removes one code entry per block and requires the native path and the guest to refuse |

## Known limits

- **A full block is not provable.** Cost scales with work paid in gas, not with
  storage, but a 27.7M-gas read-only block is about 800M SP1 gas, far above what
  any host has proved. A per-block proving-cost limit is still needed before user
  transactions.
- **Read-heavy blocks cost more than on the complete guest**: +14% to +42% when a
  block reads most of an account's storage (agent 81's bench).
- **Executed code is still hashed per block.** A contract the block calls costs
  the hash and analysis of its code (up to 24,576 bytes), as on the complete
  guest; each cold account load costs the caller 2,600 gas.
- **Removable nodes.** Proof nodes exposing the neighbours of a deleted key are
  not always needed; removing them gives the canonical outcome. Not a soundness
  issue, but the witness is not minimal-and-unique.
- **Coverage of the next rules on real data** is thin: 4 real blocks, one private
  crossing (agent 81, 36/36 checks on the previous ELF). The rest rests on the
  synthetic fuzz (200 chains of 250 blocks at `REVIEW_SCALE=40`).
- **Export stops at L2 block 4096** (`MAX_REPLAY_BLOCKS`), for both witnesses.
- **The sweep recipient is a placeholder**, so the next-rules ELF and its keys move
  once it is set.
- **Pinned only on Linux x86_64.** `guest-sparse/build.sh` on macOS gives other
  hashes and is not a pin.

## Programs

Commit `b772f2d`, built by `build-container.sh` on two hosts (136.244.93.186 and
45.77.142.123, Linux 6.8.0 x86_64, separately built images) with identical
output:

| Program | SHA-256 | ELF Keccak | KoalaBear key | BN254 key |
|---|---|---|---|---|
| `settlement_v3_mainnet_sparse` | `78c533fab3669e491d409f1c0d92e736ee0389e8e6fd7b64da3a7e3f69d37bea` | `1f755262230baf9f1fded98a698cd3e31aa7f23a146116d4bd7e21e2bee2a5e0` | `7e5b3c3345608ab36aced4db40f7692147a3fca80ace7a285bc335f342ee5910` | `00fcb6786715822acf5676a6dc0f769218f47f9502b39e8a2de19af9c2ee5910` |
| `settlement_v3_mainnet_v1_sparse` | `b1b09c1f5b98b744493f4fb9ee4b15e05792e28cfe6cddf4a8a4eddfdf0d246c` | `195e6f361989cb4334d24d3646ba05b8e36955691e33cb4f5495548f35991fea` | `13f4866d5bd744237d732bd85f6a0fd62980231c69ff67690d84c57e14a73510` | `0027e90cdb6f5d108feb995ec5f6a0fd653004639a7fd9da46c262bf14a73510` |
| `settlement_v3_mainnet_sparse_eager` (measurement only) | `f3c68511ea70b1bd6044266fb1088eb4a2ceb39c280ddc2a4fb85322468dfc64` | | | |

One real block proved with `settlement_v3_mainnet_sparse`: block 6 of a private
crossing run (next rules, 2 user transactions, 2 withdrawals), through the
settler's `--mainnet --sparse prove-groth16 native-artifact`: 371 s, 29.2 GiB
peak, Groth16 proof reverified offline.

Configuration commitment (next rules) `975ec2585246abeaea86421dd5726918b632dd91a246f635fe74990b68bcd878`,
proof policy V3 `154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d`.

## How to reproduce

Build the programs (Linux x86_64, Docker):

```
integrations/sp1-execution/guest-sparse/build-container.sh /tmp/sparse-elf b772f2d
```

```
cat /tmp/sparse-elf/SHA256SUMS
```

Program keys, with the V3 host built from the same commit:

```
cargo build --release --locked --manifest-path integrations/sp1-execution/host/Cargo.toml --features source-settlement,node-artifact,sparse-witness --bin bloch-evm-sp1-settlement-v3 --bin bloch-evm-sp1-sparse-diff
```

```
integrations/sp1-execution/host/target/release/bloch-evm-sp1-settlement-v3 --mainnet identity /tmp/sparse-elf/settlement_v3_mainnet_sparse
```

Unit, adversarial and property tests (the second run is the large fuzz, about 15
minutes on 6 cores):

```
cargo test --release --locked --lib --features sparse-witness
```

```
REVIEW_SCALE=40 cargo test --release --locked --lib --features sparse-witness review::
```

```
cargo test --release --locked --lib
```

Differential on stored settler artifacts (`WORK_DIR` is a settler `work`
directory; `ELF_DIR` holds `complete_v1`, `complete_next` and the two sparse
programs):

```
bloch-evm-sp1-sparse-diff WORK_DIR ELF_DIR
```
