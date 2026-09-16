# Native escrow: hybrid PQ authorization adapter

Experimental local integration, not a deployed Genesis-4 transaction or bridge.
This separate AGPL-3.0-or-later crate uses the official `bloch-crypto` verifier;
it does not add its dependencies to the portable EVM crate's default build.

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

Offline execution requires dependencies already cached. Eight integration tests
passed using real, disposable hybrid keypairs and signatures. They cover valid
funding, corruption/removal of each signature component, changes to every intent
field, suite downgrade, malformed and oversized requests, replay, a re-signed
double spend, overspending, wrong network and unavailable withdrawals. Tests do
not open wallets, persist private keys or contact the network.

## Remaining boundaries

Initial coins are trusted local genesis allocations. This adapter does not
authenticate a live UTXO snapshot, persist state, define a consensus wire format,
calculate live transaction fees or activate new rules on validators. Funding
authorization alone does not establish finalized deposit inclusion or authorize
an EVM mint. Withdrawals remain unconditionally disabled until verified execution,
settlement, nullifiers and atomic native payouts are implemented together.

See [the transition kernel](../../EXPERIMENTAL-NATIVE-ESCROW.md) and
[Genesis-4 derivation requirements](../../GENESIS4-BRIDGE-DERIVATION.md).
