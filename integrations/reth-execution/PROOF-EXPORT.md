# Export a persisted developer block for proving

The `bloch-evm-export` executable opens a **stopped** synthetic developer node's
MDBX, static files and RocksDB read-only. It reconstructs canonical genesis and
re-executes every selected block up to the requested height, comparing each full
V2 header with storage. For the selected block it generates a real sparse witness
and validates the complete transport artifact with stateless re-execution.

This exports input for a prover. It does not generate a cryptographic proof,
authenticate native deposits/finality, or turn an arbitrary received artifact
into trusted canonical selection.

Build after verifying the prepared Reth source:

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 build --locked --offline \
  --manifest-path integrations/reth-execution/Cargo.toml --bin bloch-evm-export

integrations/reth-execution/target/debug/bloch-evm-export \
  --synthetic-dev /absolute/path/to/stopped-devnode 3 /absolute/path/outside-node/block-3.json
```

The CLI fixes the developer configuration: testnet chain parameters, V2 domain
`0xd3…d3` and timestamp-zero genesis. The source must already contain `db`,
`static` and `rocks`; it never initializes or repairs them. Output must be a new
file outside the source tree and is synchronized before success is reported.
An existing output is never replaced. A failed write may leave a partial new
artifact; it is not silently retried or presented as successful.

## Selection and resource boundary

Stop all source writers before exporting. Read-only handles do not freeze a
writer in another process. The exporter compares the chosen header and tip
before/after reconstruction and validates the complete parent-linked prefix;
these checks are not a claim of an atomic live-provider snapshot or native
canonicality. The operator remains responsible for choosing the source.

This prototype exports non-genesis heights 1 through 4096 by reconstructing the
whole prefix. It needs all those bodies. Pruned or missing data fails closed.
Work and accumulated state depend on every transaction in that prefix, so this
is not a public proof-request endpoint or complete memory/CPU budget. Incremental
provider witness capture and a production admission policy remain separate work.

The [artifact envelope](../execution-artifact/README.md) keeps the transport
independent of Reth and SP1 SDK versions. Its expected statement is an execution
expectation, not a proof or a native funding permission.

## Reproduce the persisted contract fixture

The integration test persists a synthetic funding block, a signed contract
deployment and a signed storage update to `42`. It checks the library export,
then closes the writer and exports through the separate CLI process. It also
checks rejected heights, output overwrite protection and repeated export bytes.

```sh
python3 integrations/reth-execution/prepare-reth.py --check -- \
  cargo +1.98.1 test --locked --offline \
  --manifest-path integrations/reth-execution/Cargo.toml --test proof_export
```

For subsequent SP1 qualification, explicitly set `BLOCH_QUALIFICATION_ARTIFACT`
to a new file path when running that test. Only after all assertions pass, the
test writes and synchronizes the same CLI-exported bytes there. Existing files
are refused. Without this variable the temporary database and export disappear
when the test finishes. The fixture uses a public test signing key and synthetic
deposits; its transport does not authenticate native funding.

Local qualification on 2026-09-17 passed with Rust 1.98.1 and the prepared Reth
snapshot correction: the persisted contract/CLI test passed in 4.73 seconds,
including an explicit storage-slot value of `42`; scoped Clippy with
`-D warnings` and package formatting passed. The exported JSON is 7221 bytes,
SHA-256 `2b2e192921bf2e4471bc29d40ffaaca3a251fdf22bd4f37512dcb6229889e987`.
These results establish host reconstruction/export; SP1 qualification is separate.
