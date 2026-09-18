# Local durable source-bound SP1 settlement

This optional `source-settlement` host component combines **real SP1 Core proof
verification**, existing V2 execution rules and an independently authenticated
experimental source journal. It does not activate native consensus, attest
transaction DA, authenticate native finality, create backing funds, or implement
withdrawals. The guest and ELF are unchanged.

## Policy and trust inputs

`SourceSettlementPolicy::new` pins the complete chain specification, native
network/genesis, execution domain, exact program identity and canonical V2
genesis header. It recomputes `genesis_v2`/`node_head` and rejects precredited or
otherwise altered block-zero headers. Consumption starts at zero; no arbitrary
serialized consumed cursor can bootstrap the journal.

The independently opened `SourceJournal` must already have passed **exact**
externally retained `SourceMark` validation. Never use a source mark found in the
SP1 journal to open that source journal or promote an unacknowledged source
suffix. Its verified current source can have pending locks; a new combined
journal still starts with canonical zero-funded EVM genesis and consumption zero.
This differs from the more restricted in-memory coordinator bootstrap, which
starts with the source registry itself at native genesis.

`SourceSettlementJournal::create(path, policy, &mut source)` refuses an existing
file. Its manifest binds program ELF/key, configuration, execution domain,
native network/genesis, canonical EVM genesis, and the initially selected source
mark. Source network/genesis/domain are checked independently because native
network/genesis are not fields of the guest's execution statement.

## Append and recovery

`append(source, verified_proof, header, body)`:

1. Checks journal integrity/size and source policy identity.
2. Authenticates both the last selected and current source marks through
   `SourceJournal::snapshot_at`. A replacement source handle cannot switch to
   another branch merely by presenting the same genesis or a larger record count.
3. Uses the shared `prepare_source_advance` helper to enforce the mandatory exact
   deposit prefix, complete V2 statement, trusted program and canonical parent.
4. Writes one bounded checksummed frame with the source mark, canonical header,
   canonical body and the already verified real proof. It calls `sync_all`
   before publishing either execution or consumption in memory.

`open(path, policy, trusted_program, source, retained_floor)` replays the whole
file privately. Every historical source mark must occur in the independently
trusted current source history, and selected source record numbers may not move
backward. Every proof is decoded with existing limits and cryptographically
reverified by `TrustedProgram`; every consumed range is derived from the exact
body/source selection. Stored cursor values do not authorize restoration.

The independently retained floor contains **all** of execution number/header
hash/state root, next consumed sequence, and the complete last selected source
mark. Recovery must encounter this exact tuple. Valid subsequent execution
frames can be recovered as durable local selection only after proof, source,
parent and prefix checks. This is deliberately different from source recovery:
source authority requires an exact external tip, while complete proof-backed
execution suffixes can survive a crash before their acknowledgment was retained.
Recovered consumption prevents replaying the same deposit block again.

A source journal can advance while execution remains behind. Historical lookup
revalidates the full source tip before exposing a selected earlier snapshot;
the combined journal does not rewind or mutate source history.

## Files, codecs and failures

Frames contain the fixed canonical `SourceMark`, big-endian u32 header/body
lengths, their strict tagged V2 RLP encodings, and the strict existing SP1 proof
encoding. A big-endian u32 frame length and Keccak checksum enclose the payload.
Header/body/proof and cumulative record/byte limits are checked before allocation.
The prototype uses the existing execution-journal limits of 256 frames and
256 MiB total. Source replay has its own 4096-lock, 10,000-frame and 64 MiB caps.
Historical source lookup is repeated per execution frame: worst-case work is
O(source history × execution history), not a production indexing solution.

The retained combined mark has a tagged fixed-width codec. Its execution fields
use big-endian integers; its nested `SourceMark` retains that format's documented
little-endian codec. Decoding either is transport, not authentication.

Exclusive advisory locking prevents cooperating concurrent writers. Safe opening
rejects symlinks/non-regular files using the host's existing platform-specific
helper. Ancestor paths and storage ownership remain trusted. Append detects
unexpected length changes, and any uncertain write/fsync poisons mark/cursor
access and future writes. Truncated or corrupt tails fail closed; no repair or
silent truncation is performed. Source and execution are separate files, not a
cross-file atomic transaction: a source-only commit leaves pending locks, while
one durable execution frame advances execution and consumption together.

Tests use actual saved SP1 proof artifacts and temporary files. Truncation and
unacknowledged-complete-frame tests exercise recovery semantics; they are not a
claim of physical power-loss testing. The proof decoder's byte/shard bounds are
not a complete hostile-proof CPU/memory sandbox.

## Qualification

Build the unchanged pinned guest and generate `source-contract` as documented
in [SETTLEMENT.md](SETTLEMENT.md). Use the host README's protobuf compiler setup
(`protoc` on `PATH` or `PROTOC` set to its absolute executable path). The default proof is `target/qualification-source-contract.proof`;
`BLOCH_SP1_SOURCE_PROOF` and `BLOCH_SP1_ELF` can select already qualified artifacts.
Then run:

```sh
RAYON_NUM_THREADS=2 CARGO_BUILD_JOBS=2 cargo +1.98.1 test --release --offline --locked \
  --manifest-path integrations/sp1-execution/host/Cargo.toml \
  --features source-settlement --test source_journal_proofs -- --test-threads=1
```

Missing proofs fail the test; no ignored test or mock verifier substitutes for
real qualification. The tests cover accepted deployment/call proof settlement,
independent source progress, exact historical source selection, full floors,
replay/forged mint rejection, native identity mismatch despite the same execution
domain, a different valid inbox/history with the same native genesis and domain,
restart, truncated frames and poisoned state after external writes.

Observed qualification on 2026-09-17: the release integration command above
passed all **3 tests**, with **0 ignored**, in **29.65 seconds**. It used the
actual source-contract SP1 proof after verification and save/reload, not an
execution-only substitute. The first optimized test build took 5 minutes.
The separate bounded framing unit test passed **1/1**; release Clippy for the
library and `source_journal_proofs` passed with warnings denied.
