# Settlement V3 guest — execution-only cycle benchmark (2026-10-10)

Execution in the SP1 6.8.0 executor only (`LightProver::execute`); **no proof
was generated**. Purpose: size the prover for V3 blocks with user transactions.
Reference: a deposit-only block today takes ~18 min to prove (Groth16) with
~60 GB peak RSS at 8 threads on the L2 host.

## Command

```sh
cd integrations/sp1-execution
# guest (SP1 6.8.0 CLI, succinct toolchain)
(cd guest && CARGO_BUILD_JOBS=2 cargo prove build --locked)
# host (release; sp1-prover-types needs protoc)
(cd host && PROTOC=/path/to/protoc cargo +1.98.1 build --locked --release \
   --features node-artifact,source-settlement \
   --bin bloch-evm-sp1-settlement-v3-bench --bin bloch-evm-sp1-settlement-v3)
python3 host/scripts/bench_settlement_v3.py \
  host/target/release/bloch-evm-sp1-settlement-v3-bench \
  guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/settlement_v3 \
  transfers:0 transfers:1 transfers:10 transfers:50 transfers:100 calls:10 calls:50
```

Each configuration runs in its own process (peak RSS via `getrusage`, per
block). The bench re-executes the block on the host, runs the guest, and checks
the committed 766-byte V3 statement byte-for-byte before reporting.

## Blocks

* `transfers N`: one native deposit funds one sender, which sends N plain value
  transfers (21,000 gas each) to N distinct new accounts. `N = 0` is the
  deposit-only block the devnets settle today.
* `calls N`: one deposit, one contract deployment, then N calls each writing a
  fresh storage slot (`sstore(v, v)`); user transactions = N + 1.

## Results

Machine: MacBook Pro, x86_64, macOS (Darwin 25.6.0), 16 GB RAM.
ELF: `settlement_v3` built from `codex/l2-v3-m2-20261010` at
`~/worktrees/l2-v3-m2-20261010` (SHA-256 `a80aa3a54848cd03fff30dd1acb79d9ce357d75a0e2902fbd748da124936861a`).

| Block | User txs | Block gas | Body bytes | Witness bytes | SP1 cycles | Syscalls | SP1 gas | Execute (s) | Peak RSS (MiB) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| transfers N=0 | 0 | 21,000 | 86 | 1,274 | 1,180,199 | 0 | 1,188,811 | 0.12 | 103 |
| transfers N=1 | 1 | 42,000 | 206 | 1,358 | 4,239,301 | 0 | 4,053,376 | 0.24 | 131 |
| transfers N=10 | 10 | 231,000 | 1,279 | 1,610 | 30,804,933 | 0 | 28,834,632 | 1.39 | 215 |
| transfers N=50 | 50 | 1,071,000 | 6,039 | 2,730 | 148,848,880 | 0 | 138,935,808 | 6.54 | 575 |
| transfers N=100 | 100 | 2,121,000 | 11,989 | 4,130 | 296,377,446 | 0 | 276,498,625 | 13.02 | 1,064 |
| calls N=10 | 11 | 507,956 | 1,672 | 1,358 | 33,862,140 | 0 | 31,686,149 | 1.53 | 227 |
| calls N=50 | 51 | 2,237,916 | 7,552 | 1,358 | 152,080,805 | 0 | 141,991,836 | 6.73 | 604 |

Execute time and RSS are of the executor, not of proving.

## Reading

* Marginal cost ≈ **2.95 M cycles per signed transaction**, almost all of it
  independent of what the transaction does (transfer vs. storage-writing call
  cost the same within ~10%). The deposit-only block is 1.18 M cycles.
* **Syscalls = 0**: the guest uses no SP1 precompiles. secp256k1 sender
  recovery (k256) and Keccak run as plain RISC-V. Switching the guest to SP1's
  patched `k256`/`tiny-keccak`/`sha3` crates (precompile syscalls) is the
  obvious first optimisation before sizing GPU/aggregation (M7); it changes the
  program identity (new ELF, new vkeys, new genesis policy).
* Proof cost was not measured. SP1 proving scales roughly with cycles (shards)
  plus a fixed Groth16 wrap; a 100-transfer block is ~250× the deposit-only
  block in cycles, so on the current CPU host it is far beyond 18 minutes.
  Until precompiles are in place, keep `max_block_txs` very small on devnet4
  (single digits) and measure a real proof before raising it.
* State is near-empty (fresh genesis). Witness size and MPT work grow with real
  state depth; these numbers are a lower bound.

## Program identity of this ELF (from `bloch-evm-sp1-settlement-v3 identity`)

```json
{"program":"settlement_v3","chain_id":700771,
 "domain":"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3",
 "configuration":"d8bda58311d30b1e2c08097b8ad4f08b767dbad1ed70403aaf6f601944921616",
 "elf_keccak":"b343363ded81606f1b7e61fdebb2a266a60c3d0f302fa2e98546b8b4dac87157",
 "vkey_koalabear":"77788bcf2733dd8673c0e21a31665a7026e9810573f9e98b2684c59534e9468d",
 "vkey_bn254":"00eef1179e9ccf761b9e0710d31665a704dd3020bcfe7a62d34262cab4e9468d",
 "sp1_circuit_version":"v6.1.0",
 "proof_policy_v3":"154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d"}
```

`proof_policy_v3` equals the native `policy_commitment_v3()` of
`codex/native-l2-v3-m2-20261010` (cross-checked). The ELF embeds absolute
source paths: the same sources built under another directory produce another
ELF (the M1 ELF built at `~/worktrees/l2-v3-m1-20261010` has SHA-256
`6dd5f5a3…a454`). Devnet4 pins must come from the ELF actually deployed.
