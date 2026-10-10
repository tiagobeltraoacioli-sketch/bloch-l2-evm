# Settlement V3 guest with the withdrawal outbox — execution-only cycle benchmark (2026-10-10, M4)

Same harness and machine as [the M3 run](settlement-v3-cycles-precompiles-20261010.md).
Execution in the SP1 6.8.0 executor only; **no proof was generated**.

## What changed (M4)

* Every block runs under `ChainSpec::testnet_v3()`: the outbox predeploy is
  installed at block start and, at block end, the outbox counter and root are
  read (and, with withdrawals, the frontier updated and the root recomputed:
  ≤ 32 + 32 Keccak per block, one frontier slot write per leaf).
* The statement carries the post-block `withdrawal_root` / `withdrawal_count`.
* New bench kind `withdrawals N`: one deposit (100 BLCH), then N calls to
  `initiateWithdrawal` (0.01 BLCH each, distinct L1 recipients).
* ELF `settlement_v3` SHA-256 `6fa44f9cd5c3b5461db115725692b4b6277cf441edf72e89343c5dc71ab3c259`
  (reproducible: `verify-reproducible.sh` gave the same three ELFs from two
  clean checkouts).

Each committed 766-byte statement was checked byte-for-byte against host
execution. `execute empty` / `execute contract`: 522,275 and 986,024
instructions (M3: 445,986 / 906,295).

## Command

```sh
cd integrations/sp1-execution
(cd guest && ./scripts/build-reproducible.sh --out "$PWD/pinned")
(cd host && cargo +1.98.1 build --locked --release --features node-artifact,source-settlement \
   --bin bloch-evm-sp1-settlement-v3-bench --bin bloch-evm-sp1-settlement-v3)
python3 host/scripts/bench_settlement_v3.py host/target/release/bloch-evm-sp1-settlement-v3-bench \
  guest/pinned/settlement_v3 transfers:0 transfers:1 transfers:10 transfers:100 calls:10 \
  withdrawals:1 withdrawals:10 withdrawals:50 withdrawals:100
```

## Results

Machine: MacBook Pro, x86_64, macOS (Darwin 25.6.0), 16 GB RAM. A single-threaded
native test was running concurrently, so wall times are slightly pessimistic;
cycle and syscall counts are deterministic.

| Block | User txs | Withdrawals | Block gas | Body bytes | Witness bytes | SP1 cycles | Syscalls | SP1 gas | Execute (s) | Peak RSS (MiB) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| transfers N=0 | 0 | 0 | 21,000 | 86 | 1,302 | 595,779 | 132 | 789279 | 0.22 | 119 |
| transfers N=1 | 1 | 0 | 42,000 | 206 | 1,386 | 815,565 | 933 | 1040148 | 0.27 | 129 |
| transfers N=10 | 10 | 0 | 231,000 | 1,279 | 1,638 | 2,282,170 | 7,963 | 2692263 | 0.64 | 140 |
| transfers N=100 | 100 | 0 | 2,121,000 | 11,989 | 4,158 | 17,652,984 | 78,169 | 19600010 | 4.73 | 250 |
| calls N=10 | 11 | 0 | 507,956 | 1,672 | 1,386 | 2,393,337 | 8,798 | 2850288 | 0.77 | 147 |
| withdrawals N=1 | 1 | 1 | 66,794 | 246 | 1,358 | 927,645 | 997 | 1215522 | 0.29 | 130 |
| withdrawals N=10 | 10 | 10 | 325,148 | 1,670 | 1,358 | 2,547,786 | 8,188 | 3148076 | 0.70 | 147 |
| withdrawals N=50 | 50 | 50 | 1,473,388 | 7,990 | 1,358 | 9,552,757 | 39,957 | 11433371 | 2.39 | 196 |
| withdrawals N=100 | 100 | 100 | 2,908,688 | 15,890 | 1,358 | 18,292,056 | 79,634 | 21781639 | 4.85 | 254 |

## Reading

* Fixed cost of the outbox per block: ≈ +75 k cycles (transfers N=0:
  520,378 → 595,779; the outbox account and two slots join every witness,
  +28 bytes).
* Marginal cost of a withdrawal ≈ **175 k cycles** ((18,292,056 − 927,645) / 99),
  close to a plain transfer (≈ 171 k now, 163 k in M3): signature recovery
  dominates; the leaf, the frontier update and the EVM call add little because
  Keccak runs as a precompile.
* L2 gas per withdrawal ≈ 28.8 k (cold nonce slot write + LOG3), so a 30 M gas
  block could carry ~1,000 withdrawals; the prover, not gas, is the limit.
* Proof cost is still unmeasured (M7).
