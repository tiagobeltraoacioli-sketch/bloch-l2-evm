# Genesis-4 bridge derivation boundary

Status: read-only native transfer authentication implemented; native bridge
settlement and mint authorization are not implemented or consensus-active.

## Why the old bridge envelope cannot be reused

The historical `bloch-l2-bridge` L2D0 envelope is 34 bytes containing a magic,
version, operation, EVM chain ID and EVM recipient. Its watcher reads arbitrary
script bytes in zero-value outputs. Genesis-4 Transfer/TransferV2 instead encode
each output as exactly `value_sat: u64` and `script_hash: [u8;32]`. That hash
commits the spender's key; it is not a data payload or a script interpreter.

A zero-value output or a hash that happens to resemble a message must never be
interpreted as this envelope. Likewise, receiving funds at an operator's key is
custody, not a consensus-enforced escrow. No RPC or inferred EVM address can
supply the missing authorization. Observations and `DepositMint` therefore remain
separate types with no automatic conversion.

## Implemented observation

`l1_transfer::observe_transfer` accepts only an `AuthenticatedBody` from the
Genesis-4 ancestry/body verifier. It strictly decodes Transfer (0x01) and
TransferV2 (0x06), preserves output positions, and derives the consensus txid
with DS_SPEND and DS_TXID. Witness bytes are excluded from this identity exactly
as in consensus; SHA3-256 of signed transport bytes is not a transaction ID.

The result provides block, slot, body index, txid and exact output amounts/scripts.
Payment sums use u128, including when multiple u64 outputs exceed u64::MAX.
Local limits are 1 MiB per transfer and 4,096 inputs, outputs or witness entries.
Truncation, trailing bytes, invalid references and unsupported tags are rejected.
This is a bounded reader, not a second signature/UTXO/fee consensus validator.
The externally authenticated checkpoint remains the source of transaction validity.

Run the offline observer with a separately trusted checkpoint:

```sh
cargo +1.94.1 run --locked --example verify_l1_body -- \
  body.json TRUSTED_FINALIZED_BLOCK_ID TRUSTED_FINALIZED_SLOT NATIVE_SCRIPT_HASH
```

The optional final argument emits read-only JSON observations with decimal-string
amounts. It counts unsupported non-transfer transactions instead of claiming to
cover every possible output-producing transaction. Historical payment does not
prove an output is still unspent. No keys, wallet unlock or broadcast are involved.

## Required native escrow design before credits

The [native state inclusion adapter](integrations/native-state-proof/README.md)
now verifies historical eUTXO membership and the existing native EVM commitment
under an authenticated header using the official consensus SMT verifier. These
observations do not prove an experimental escrow lock or authorize minting.

For the noncustodial execution-module design, a future consensus-enforced lock
must authenticate all of these together:

- Genesis/network and execution-domain identities, plus protocol version;
- funding authority and consumed native outpoints;
- exact locked native amount and independently specified fee/change amounts;
- recipient encoding and recipient within the destination runtime;
- unique deposit identity and replay-protected inbox position;
- release rules tied to a verified domain withdrawal commitment.

The L1 state transition must remove the funding inputs and record a locked
liability atomically. Funds cannot remain spendable by an ordinary operator key
while being presented as cryptographically locked. The EVM derivation must credit
only the exact locked amount once, using 10^10 wei per native satoshi. Its trusted
ordered deposit stream must agree with authenticated L1 escrow records.

A withdrawal must debit/burn the corresponding L2 representation, commit the
recipient and exact native amount in the verified execution, and consume a
single-use release identity on L1. Proof replay, cross-domain replay, wrong
recipient, over-release and release before finality must fail. An administrator
must not be able to bypass proof verification or create backing assets.

The current deposit cursor uses L1 block height. A header's slot is not its block
height. The future derivation needs an authenticated height mapping or a
coordinated cursor-format upgrade; substituting slot values is forbidden.

No native lock transaction tag or activation epoch is assigned by this document.
Those require an explicit consensus specification, implementation, testnet
qualification and coordinated deployment. Until then, observed transfers must
never be automatically promoted into mint authorizations.

## Validation

149 tests passed; one pre-existing test remains ignored. The crate still compiles
without its default std feature. Six new tests compare both wire formats with
consensus-generated vectors, verify exact u128 sums, reject every truncated
prefix and trailing data, reject count/reference errors and legacy envelopes,
and distinguish consensus txid from witness-dependent block commitments. The CLI
was also exercised with two u64::MAX outputs and preserved their amounts as
strings and original indices 0 and 2. No production wallet or network was used.
