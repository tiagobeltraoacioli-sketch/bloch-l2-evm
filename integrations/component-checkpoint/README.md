# Component checkpoints: L2, DEX and bridge

This offline release/checkpoint gate uses the same **ML-DSA-65 AND Falcon-1024**
primitive as the L1 Phase A ceremony. Three separately controlled public keys
are required. The default arrangement is **2 of 3, including at least one external
holder**; `threshold: 3` requires all three signatures. A registry cannot lower
this to one signature or omit external participation.

This is a new **component review domain**, not the L1 checkpoint wire format.
It attests an exact component, chain/genesis, finalized block/state root, release
configuration and artifact set. It does not prove finality independently, turn on
an L2 genesis, deploy the DEX, change fees, or authorize bridge mint/release. The
existing consensus, deployment and custody gates remain necessary. There are no
production signer keys or production signatures in this repository.

## Reproducible native verifier

Check out `bloch-sis-pow` at
`5af78a04a27dcb2c2253c32134fca888a8a965f9` in the sibling directory
`bloch-validator-payout`. Use a clean checkout of that revision, not an operator's
working tree. The relative paths match the existing native PQ integrations.

```sh
cargo +1.94.1 test --locked --manifest-path integrations/component-checkpoint/Cargo.toml
cargo +1.94.1 build --locked --release --manifest-path integrations/component-checkpoint/Cargo.toml
```

The binary is `integrations/component-checkpoint/target/release/bloch-component-checkpoint`.
Record its **SHA3-256 of raw file bytes**, compiler/dependency revision and the
reviewed source artifact manifest. A checksum authenticates a previously trusted
build, not an arbitrary binary received with the checkpoint. DEX/bridge adapters
require this independently selected verifier hash and execute a private snapshot.

## Registry and trust

Start from `../../checkpoints/registry.pending.json` (relative to this directory).
Fill the three holder IDs, `external` statuses, validity timestamps and public
keys through the ceremony. Each holder generates/retains their own offline key;
never send secret keys to the coordinator. Use the exact 3,749-byte **enveloped**
public key in lowercase hex, without `0x`. L1 raw 3,745-byte public keys must be
explicitly exported as suite `b10c0100` plus the raw key; never reinterpret an L1
signature as a component signature. The holder signing command uses the matching
enveloped secret-key hex file, readable only by its owner.

Key uniqueness is enforced; independence of the three people/organizations must
be established by the external registry-adoption ceremony. A replacement registry
requires a new independently pinned trust file. The checkpoint cannot adopt its
own replacement keys. A registry/checkpoint lifetime may not exceed 456 days.

All commitments are **lowercase 32-byte hex without `0x`**:

- configuration/artifact/trust/verifier file pins: SHA3-256 of exact bytes;
- registry: SHA3-256 of `BLOCH-COMPONENT-SIGNERS-v1\0` followed by compact JSON
  serialized by the Rust `Registry` struct in declaration order;
- checkpoint: SHA3-256 of `BLOCH-COMPONENT-CHECKPOINT-v1\0` followed by compact
  JSON serialized by the Rust `Checkpoint` struct in declaration order.

Use `registry-id` and `prepare`, not another language's guessed canonicalization.
Integer fields are JSON unsigned integers. Unknown/duplicate fields, floats,
wrong suites, malformed hex and oversized documents are refused. Both hybrid
signature halves must verify; every supplied signature must be valid, even beyond
quorum. Maximum document size is 1 MiB.

## Ceremony

From the L2 repository (`scripts/component-checkpoint.py` in DEX/bridge):

```sh
python3 tools/component-checkpoint.py manifest \
  --file Cargo.toml --file Cargo.lock --file src/lib.rs > artifacts.json

python3 tools/component-checkpoint.py prepare \
  --verifier "$CHECKPOINT_VERIFIER" --verifier-sha3 "$VERIFIER_SHA3" \
  --registry registry.json --configuration deployment-reviewed.json \
  --artifacts artifacts.json --chain-id "$REVIEWED_CHAIN_ID" \
  --genesis "$REVIEWED_GENESIS_HEX" --finalized-header finalized-header.json \
  --sequence 1 --previous 0000000000000000000000000000000000000000000000000000000000000000 \
  --output ceremony
```

The header document has exactly `height`, `hash` and `state_root`. Obtain these
from independently checked finalized views of the selected component/chain. An
RPC assertion alone is not a consensus proof. Include all relevant deployment
code/runtime pins, fee/rebate policy, route caps and evidence in the artifact set;
the tiny manifest command above illustrates syntax, not a complete release.

`prepare` creates a new directory and never overwrites a previous ceremony. It
emits zero signatures and a **pending** trust file. Each holder independently
reviews the payload, actual files, registry and finalized header, then compares
the trust-file SHA3 through an authenticated channel. Publishing a hash beside an
untrusted file does not adopt that hash as a trust root.

On **each holder's own offline machine**, after inspection:

```sh
"$CHECKPOINT_VERIFIER" sign registry.json ceremony/payload.json \
  /private/offline/holder.sk holder-id > holder-signature.json
```

Collect public signature files only:

```sh
"$CHECKPOINT_VERIFIER" assemble registry.json ceremony/payload.json \
  holder-one-signature.json external-holder-signature.json > envelope.json

python3 tools/component-checkpoint.py verify \
  --verifier "$CHECKPOINT_VERIFIER" --verifier-sha3 "$VERIFIER_SHA3" \
  --registry registry.json --configuration deployment-reviewed.json \
  --artifacts artifacts.json --envelope envelope.json \
  --trust reviewed-trust.json --trust-sha3 "$INDEPENDENT_TRUST_SHA3"
```

Supply all three signature files to `assemble` for a 3-of-3 registry. Assembly is
not acceptance: the `verify` exit status and fresh verification of artifact bytes
are mandatory. A saved JSON success report is not a signed approval certificate.

For the next checkpoint, independently pin `next_sequence` to the previous
sequence + 1, `previous` to its checkpoint digest and
`minimum_finalized_height` to at least the last accepted height. Store these
watermarks durably outside the downloadable package. The verifier is deliberately
stateless: restoring an old trust file/watermark can permit rollback, so operators
must retain their latest independently protected trust pin. Repeated verification
of the same checkpoint with the same trust file is idempotent, not a state update.

## Component integration

- L2: `tools/component-checkpoint.py` pins `component=l2`; include frozen-genesis,
  execution/settlement configuration and relevant L1 anchor evidence. This adds
  release review; existing genesis admission/native checkpoint validation still
  controls execution.
- DEX: `scripts/component-checkpoint.py` pins `component=dex`; include reviewed
  deployment runtime pins and `bloch.dex.fee-policy.v1`, plus generated fee
  transaction drafts. Existing pool addresses cannot acquire new immutable code.
- Bridge: `scripts/component-checkpoint.py` pins `component=bridge`; include
  route/custody/cap configuration and source/native evidence. Three checkpoint
  reviewers are separate from the existing 3-of-5 custody participants.

The adapter rehashes the supplied configuration, manifest and every listed local
artifact before acceptance. It rejects cross-component envelopes and requires a
pinned native verifier and pinned trust file. No network/signing side effect is
part of verification. The detached hybrid signature command is a separate local
holder operation. The EVM fee authority/custody contracts do not verify this PQ
review certificate on-chain.

## Verification coverage

Real hybrid signatures exercise all three components, 2-of-3 and 3-of-3,
external participation, duplicate holders, invalid extra signatures, wrong keys,
both signature halves, suite downgrade, every payload field, cross-component
replay, sequence/height/predecessor rollback, stale/future/expired checkpoints and
strict JSON. CLI integration tests create disposable test-only keys, then run
prepare, holder sign, assemble and the Python admission adapter for each component;
they reject changed files, changed trust pins and ceremony overwrite.
