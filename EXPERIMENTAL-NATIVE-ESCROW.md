# Experimental native escrow transition kernel

Status: executable local model, feature-disabled by default. It is not a
Genesis-4 transaction, consensus change, production vault or working bridge.

## Implemented

The `experimental-escrow` Cargo feature exposes a deterministic ledger of native
spendable outputs and locked liabilities. `LockIntent::signing_root` binds the
network, execution domain, funding authority, canonical input list, EVM recipient,
amount, explicit fee, change owner and nonce under an experimental SHA3 domain.
The nonce participates in intent identity; it is not an account-level nonce
allocator. Spent outpoints and retained intent identities prevent replay.

`apply_authorized_lock` validates all input ownership and value constraints
before mutation. It consumes funding coins, records one append-only inbox entry,
creates deterministic change and accounts for the fee. Locked principal is no
longer in the spendable set. The invariant is:

```
spendable native value + locked liabilities + accounted fees = initial allocation
```

Per-output amounts are u64; aggregates use u128. Inputs must be strictly ordered
and unique. No arithmetic saturation can turn an invalid amount into an accepted
lock. Empty/oversized input lists, zero recipients, wrong domains, missing or
foreign-owned inputs, insufficient funds, change overflow and identifier
collisions fail without state mutation. A full journal refuses new locks instead
of discarding replay protection. State commitments cover configuration, initial
allocation, coins, liabilities, fees and the inbox position in canonical order.

## Authentication boundary

This kernel assumes its embedding consensus host has ALREADY authenticated the
funder's post-quantum signature over the exact signing root. An owner hash is not
a proof of possession. There is deliberately no production RPC handler exposing
this method, no generic proof-success flag and no built-in accept-all signature
verifier. The example/test harness supplies synthetic authorized intents.
Anyone embedding this without real funding authentication could steal its model
coins; passing the model tests does not authenticate any real funds.

The separate [hybrid PQ adapter](integrations/native-escrow-pq/README.md) now
provides an authenticated local facade using the actual native ML-DSA-65 AND
Falcon-1024 verifier. Its eight integration tests exercise real signatures.
The raw kernel API still requires authenticated callers; native consensus
integration and finalized deposit derivation remain outstanding.

The genesis allocation is likewise trusted input for simulations. The kernel
does not import an existing live eUTXO set or mutate the existing consensus state.
Fees are accounted, not routed to a live validator. The experimental commitment
is not Genesis-4's SMT root. There is no transaction wire tag or activation epoch.

`LockedDeposit` is a liability record, NOT a `DepositMint`, finality certificate or
proof. It does not bypass the EVM derivation boundary. Its inbox sequence is not
silently substituted for L1 block height. The existing height-based EVM deposit
cursor still needs an explicit authenticated mapping or versioned migration.

`release` is unconditionally unavailable. No administrative flag can release
coins. Real withdrawal execution/proofs, finalized settlement, nullifiers and
output generation must be implemented together before enabling releases.

## Run and validate

```sh
cargo +1.94.1 run --locked --features experimental-escrow --example native_escrow
cargo +1.94.1 test --locked --features experimental-escrow
cargo +1.94.1 check --locked --no-default-features --features experimental-escrow
```

The example consumes a synthetic 100,000-sat input, locks 60,000 sat, creates
39,990 sat change and accounts for 10 sat fees. It then demonstrates refusal of
replay and release. No signing, networking or production state is involved.

Nine new tests cover conservation, atomic failure, replay/changed-nonce double
spend, wrong domain/owner, duplicate inputs, u64 change overflow, intent-field
binding, 64 sequential locks, journal capacity, duplicate genesis allocations
and unconditional release refusal. These are local transition tests, not PQ
signature, bridge-proof or mainnet settlement qualification.

## Integration still required

The [ordered inbox inclusion primitive](EXPERIMENTAL-ESCROW-INBOX.md) provides
local Merkle paths for accepted locks. Its separate root still needs consensus
authentication; membership alone does not authorize a deposit mint.

Port the reviewed transition into the native consensus state with the existing
PQ verifier, state-root commitments and transaction gas/fee calculation. Specify
canonical codec and inbox identity, activation and durable recovery. Authenticate
finalized escrow records before producing EVM deposit mints. Prove withdrawals
against verified execution and nullify them atomically with native payouts.
The feature flag is an engineering guard, not a substitute for these components.

Validation of this increment: 158 tests passed with the experimental feature,
one pre-existing test ignored. No-default-features compilation passed with the
kernel enabled. The executable simulation produced the expected conserved
60,000/39,990/10-satoshi split and refused replay and release.
