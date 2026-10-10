# Settlement V3 guest with SP1 precompiles — execution-only cycle benchmark (2026-10-10, M3)

Same harness, blocks and machine as
[the M2 baseline](settlement-v3-cycles-20261010.md); only the guest changed.
Execution in the SP1 6.8.0 executor only; **no proof was generated**.

## What changed in the guest (M3.0b)

* `alloy-primitives` built with `tiny-keccak`, and `tiny-keccak` patched to
  `sp1-patches/tiny-keccak` tag `patch-2.0.2-sp1-6.2.0` (Keccak-f precompile);
* `k256` patched to `sp1-patches/elliptic-curves` tag
  `patch-k256-13.4-sp1-6.2.0` (secp256k1 precompiles; pulls
  `sp1-patches/signatures` tag `sp1-skip-verify-on-recovery` for `ecdsa`);
* M3.2: the statement now carries `da_commitment` (Keccak over the
  user-transaction batch), computed in the guest;
* built with `scripts/build-reproducible.sh` (path remapping).

The bench checks each committed 766-byte statement byte-for-byte against host
execution with the unpatched crates, so the patches did not change results for
these blocks. The two fixed host checks (`execute empty`, `execute contract`)
also matched (445,986 and 906,295 instructions).

## Command

```sh
cd integrations/sp1-execution
(cd guest && ./scripts/build-reproducible.sh)
(cd host && PROTOC=/path/to/protoc cargo +1.98.1 build --locked --release \
   --features node-artifact,source-settlement \
   --bin bloch-evm-sp1-settlement-v3-bench --bin bloch-evm-sp1-settlement-v3)
python3 host/scripts/bench_settlement_v3.py \
  host/target/release/bloch-evm-sp1-settlement-v3-bench \
  guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/settlement_v3 \
  transfers:0 transfers:1 transfers:10 transfers:50 transfers:100 calls:10 calls:50
```

## Results

Machine: MacBook Pro, x86_64, macOS (Darwin 25.6.0), 16 GB RAM.
ELF: `settlement_v3` SHA-256 `eff3efca9f174a44472282badbec3092d8803cc6463be4edb2421b12452fd12c`.

| Block | User txs | Block gas | Body bytes | Witness bytes | SP1 cycles | Syscalls | SP1 gas | Execute (s) | Peak RSS (MiB) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| transfers N=0 | 0 | 21,000 | 86 | 1,274 | 520,378 | 95 | 675228 | 0.11 | 120 |
| transfers N=1 | 1 | 42,000 | 206 | 1,358 | 741,223 | 897 | 930401 | 0.14 | 128 |
| transfers N=10 | 10 | 231,000 | 1,279 | 1,610 | 2,184,437 | 7,927 | 2554187 | 0.33 | 138 |
| transfers N=50 | 50 | 1,071,000 | 6,039 | 2,730 | 8,748,049 | 39,195 | 9867158 | 1.27 | 189 |
| transfers N=100 | 100 | 2,121,000 | 11,989 | 4,130 | 16,882,348 | 78,132 | 18907228 | 2.60 | 247 |
| calls N=10 | 11 | 507,956 | 1,672 | 1,358 | 2,290,011 | 8,762 | 2710994 | 0.39 | 146 |
| calls N=50 | 51 | 2,237,916 | 7,552 | 1,358 | 8,386,485 | 40,072 | 9738061 | 1.35 | 190 |

Execute time and RSS are of the executor, not of proving.

## Comparison with M2 (no precompiles)

| Block | M2 cycles | M3 cycles | Ratio |
|---|---:|---:|---:|
| transfers N=0 | 1,180,199 | 520,378 | 2.3× |
| transfers N=1 | 4,239,301 | 741,223 | 5.7× |
| transfers N=10 | 30,804,933 | 2,184,437 | 14.1× |
| transfers N=50 | 148,848,880 | 8,748,049 | 17.0× |
| transfers N=100 | 296,377,446 | 16,882,348 | 17.6× |
| calls N=10 | 33,862,140 | 2,290,011 | 14.8× |
| calls N=50 | 152,080,805 | 8,386,485 | 18.1× |

## Reading

* Marginal cost ≈ **0.16 M cycles per signed transaction** (was ≈ 2.95 M):
  (16,882,348 − 741,223) / 99 ≈ 163 k. Signature recovery and Keccak now run
  as syscalls (≈ 780 syscalls per transfer).
* The deposit-only block halves (1.18 M → 0.52 M cycles).
* SP1 gas is the executor's cost estimate including precompile rows; it tracks
  cycles here (18.9 M for 100 transfers).
* Proof cost is still unmeasured; precompile tables add rows that the cycle
  count does not show. A real Groth16 proof of a user-transaction block on the
  L2 host is still required before sizing `max_block_txs` (M7).
* New program identity (vkeys below); a devnet that pinned the M2 ELF cannot
  accept proofs of this ELF.

## Program identity of this ELF (`bloch-evm-sp1-settlement-v3 identity`)

```json
{"program":"settlement_v3","chain_id":700771,"domain":"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3","configuration":"d8bda58311d30b1e2c08097b8ad4f08b767dbad1ed70403aaf6f601944921616","elf_keccak":"865acc2891bd0b4d9f18e813c21f4483b8f8f950f0a982172be1ac14c861b5be","vkey_koalabear":"56c29fa41bc5c42471b3e769490a69f72d52d0221caaa74d4c0ab7df260067ba","vkey_bn254":"00ad853f486f1710938d9f3b4c90a69f75aa5a04472aa9d366055befa60067ba","sp1_circuit_version":"v6.1.0","proof_policy_v3":"154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d"}
```

`proof_policy_v3` is unchanged (it does not depend on the ELF) and equals the
native `policy_commitment_v3()`. Identity derivation took 8.7 s and 0.8 GB RSS.
