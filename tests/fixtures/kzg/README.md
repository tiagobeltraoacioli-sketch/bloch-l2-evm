# Ethereum point-evaluation vectors

`verify_kzg_proof.json` contains all 122 `tests/verify_kzg_proof/kzg-mainnet`
cases from [ethereum/c-kzg-4844 at e125905e5e01186e6ccb7a0ced4845bf7eddbcfe](https://github.com/ethereum/c-kzg-4844/tree/e125905e5e01186e6ccb7a0ced4845bf7eddbcfe/tests/verify_kzg_proof/kzg-mainnet).
This is the source revision recorded by the pinned c-kzg 2.1.8 crate.
The upstream Apache-2.0 license is included as `LICENSE`.

The JSON preserves every input hex string and the expected YAML output:
54 `true`, 48 `false`, and 20 `null`. Each record contains the original
directory name and SHA-256 of its unmodified `data.yaml`. Conversion only
changes serialization from YAML to JSON and adds those provenance fields.
The downloaded GitHub source tarball SHA-256 was
`0cf1e5a4c0c34e1956740cdaa71f65fa25656ab4c8373217e48e187ec0d087c6`.

Tests construct the versioned hash from each supplied commitment and invoke
the registered Cancun precompile. Invalid total input lengths fail before
cryptographic verification. For correctly sized inputs, both invalid
encodings (`null`) and false proofs map to `BlobVerifyKzgProofFailed`.
Successful cases additionally check exact gas and return bytes. The corpus
runs offline with either host c-kzg or pure-Rust arkworks; it does not itself
measure execution or proving inside the zkVM.
