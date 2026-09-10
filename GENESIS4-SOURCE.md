# Genesis-4 source-bound execution

`genesis4::prepare_source_batch` connects a host-accepted Bloch source block
to the native EVM engine. It derives timestamp from the Genesis-4 manifest
clock, PREVRANDAO from the committed parent L2 hash and source hash, and sets
the EIP-4788 anchor root to the Bloch block identity. Regressing source slots
and conflicting same-slot sources are rejected before execution.

`verify_source_batch` replays signed transactions and checks the source,
expected parent hash and expected pre-state root supplied independently by
the verifier. Deposits are rejected: a source block reference is not an escrow
proof. The host must validate source headers/finality and persist its cursor;
`ReportedSource` deliberately makes no finality claim by itself.

The DevKit's `bloch_network.py` companion validates header identities and
persists an RPC-corroborated source cursor. It trusts the operator RPC for
canonicality and finality, not a cryptographic light-client proof.

```sh
cargo test --locked --test genesis4_source
cargo run --locked --example genesis4_source -- /path/to/bloch-source.json
```

The example runs an empty, zero-value batch and prints the source hash and
derived execution commitment. It does not broadcast, settle on Bloch or expose
an Ethereum RPC server. It demonstrates the real native engine/source wiring,
not an activated rollup. Existing account/supply/fee rules are unchanged.
