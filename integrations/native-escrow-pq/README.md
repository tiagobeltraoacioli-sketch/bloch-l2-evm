# Native escrow: hybrid PQ authorization adapter

Experimental local integration, not a deployed Genesis-4 transaction or bridge.
This separate AGPL-3.0-or-later crate uses the official `bloch-crypto` verifier;
it does not add its dependencies to the portable EVM crate's default build.

The separate [checkpoint module](CHECKPOINTS.md) now authenticates native
weak-subjectivity envelopes with real hybrid signatures, fixed Phase-A/Phase-B
quorum policies, freshness checks and exact header binding. It does not replace
trusted signer distribution or prove FFG history independently.

The Unix [lock store](LOCK-STORE.md) persists signed batches with exclusive writer
locking, replay verification and independently retained rollback floors. It wraps
the in-memory facade below without introducing native consensus activation.

## Authorization and state transition

`PqEscrow::submit` accepts an escrow intent, public key and signature. It requires
the enveloped suite `b1 0c 01 00`: ML-DSA-65 **and** Falcon-1024. Both components
must verify. Raw legacy keys and ML-DSA-only suite downgrade are refused even
though the general-purpose native crypto API supports other encodings.

The SHA3-256 hash of the complete enveloped public key must match the intent's
native owner. The signature authenticates `LockIntent::signing_root`, including
network, domain, funding owner, ordered input outpoints, recipient, amount, fee,
change owner and nonce. Authentication precedes the atomic escrow transition.
The kernel then checks ownership, available value, replay and conservation.
Errors preserve the ledger. No mutable kernel accessor or configurable verifier
allows callers to bypass authorization through this facade.

Requests are bounded to 4,096 inputs, 8,192 signature bytes and the exact
3,749-byte hybrid public key. These are adapter limits, not newly established
mainnet consensus parameters. A future network decoder must enforce size limits
before allocation and budget concurrent cryptographic work.

### Atomic ordered lock batches

`PqEscrow::submit_batch` takes 1–64 borrowed `SignedLock` requests, with at most
4,096 inputs across the entire batch. All size budgets are checked before
cloning state or verifying signatures. Every intent still requires its own
complete hybrid authorization; this is not cryptographic signature aggregation.

Requests execute in order on a private candidate ledger. A later request may
spend change created by an earlier request, but cannot reuse an already consumed
input. Only after every authorization and transition succeeds is the candidate
published. Signature failure, double spend, replay or capacity exhaustion discards
the entire candidate, including its fees, change, deposits and inbox sequence.
Results match sequential submission for a successful batch.

The implementation clones the existing ledger once per batch, so memory/time
also depend on existing local state size. These per-call limits are not a global
memory or concurrency budget. Atomicity is in-memory only; no durability, native
checkpoint import or consensus activation is introduced. Ordinary verified UTXOs
must not be imported as escrow allocations without a consensus-enforced lock.

## Reproduce

Use Rust 1.94.1 and a sibling `bloch-validator-payout` checkout at:

```
5af78a04a27dcb2c2253c32134fca888a8a965f9
```

The Cargo path dependency does not enforce the Git revision: check it explicitly
before reproducing results. The committed lockfile pins registry dependencies.
The `pqcrypto-internals` patch uses the native repository's implementation.
The resolved Falcon dependency is version 0.4.1 with only its `std` feature;
optimized/default features are not enabled.

From the modular execution repository root:

```sh
git -C ../bloch-validator-payout rev-parse HEAD
cargo +1.94.1 test --offline --locked --manifest-path integrations/native-escrow-pq/Cargo.toml
```

Offline execution requires dependencies already cached. Eleven authorization tests
passed using real, disposable hybrid keypairs and signatures. They cover valid
funding, corruption/removal of each signature component, changes to every intent
field, suite downgrade, malformed and oversized requests, replay, a re-signed
double spend, overspending, wrong network and unavailable withdrawals. Tests do
not open wallets, persist private keys or contact the network.
Batch tests additionally cover sequential equivalence, chained change spending,
whole-batch rollback on signature/replay/double-spend/capacity failures and
aggregate input/signature/count limits before authentication.

## Durable escrow-to-EVM integration test

`tests/durable_execution.rs` connects the real hybrid authorization adapter,
`LockStore`, cached inbox proofs, the mandatory deposit-range API, real EVM
execution and the independent durable execution `Journal`. The journal crate is
a development-only dependency; this does not add a new runtime service.

Run the scenario with:

```sh
cargo +1.94.1 test --offline --locked --manifest-path integrations/native-escrow-pq/Cargo.toml --test durable_execution
```

Two signed local locks spend 1,000 satoshis of test allocation into 900 locked,
20 in fees and 80 in change. The test closes and reopens the escrow before any
EVM credit, generates inclusion proofs, rejects a modified deposit, verifies
execution and checks exactly 900 satoshis scaled to wei in both recipient balance
and total minted supply. It then reopens both journals and rejects repeated
funding and repeated EVM credit. Missing host derivation or a changed inbox root
also prevents execution-journal recovery.

This is a local integration test with disposable keys. Its L1 locations, anchor
and finality context are explicitly synthetic, host-trusted inputs. The test
does not derive them from native blocks, activate an escrow transaction on L1,
prove mainnet backing or create a distributed atomic transaction across journals.
It tests recovery after a durable escrow commit preceding EVM credit. Native
consensus integration remains necessary before this flow can represent production
deposits; neither journal may supply its own trusted L1 derivation.

## Remaining boundaries

Initial coins are trusted local genesis allocations. This adapter does not
authenticate a live UTXO snapshot, define a consensus wire format,
calculate live transaction fees or activate new rules on validators. Funding
authorization alone does not establish finalized deposit inclusion or authorize
an EVM mint. Withdrawals remain unconditionally disabled until verified execution,
settlement, nullifiers and atomic native payouts are implemented together.

See [the transition kernel](../../EXPERIMENTAL-NATIVE-ESCROW.md) and
[Genesis-4 derivation requirements](../../GENESIS4-BRIDGE-DERIVATION.md).
