# Local escrow audit CLI

`bloch-escrow-audit` reconstructs the experimental escrow from its trusted baseline
and signed journal, rechecking hybrid authorization and all transitions. It does
not sign, submit locks, unlock wallets, contact a network or activate native rules.
Recovery takes an exclusive writer lock and synchronizes the directory before
reporting success; it does not append records or alter accounting state.

```sh
cargo +1.94.1 build --offline --locked --manifest-path integrations/native-escrow-pq/Cargo.toml --bin bloch-escrow-audit
integrations/native-escrow-pq/target/debug/bloch-escrow-audit BASELINE_JSON JOURNAL MINIMUM_JSON
```

Unix and the pinned sibling native checkout documented in README are required.
Run `--help` for syntax. The tool only opens an existing journal.

BASELINE_JSON is a strict object with these fields:

| Field | Value |
| --- | --- |
| `version` | 1 |
| `profile` | `bloch-local-escrow-v1` |
| `network`, `domain` | Independently trusted nonzero B256 identities |
| `capacity` | Original ledger capacity, 1–10,000 |
| `expected_commitment` | Independently pinned initial `PqEscrow::commitment()` |
| `allocations` | At most 4,096 `{outpoint: {txid, vout}, value, owner}` objects |

B256 values use 32-byte hex encoding; allocation values are exact native satoshis
(u64). Duplicate outpoints, zero amounts and zero owners are rejected by the
ledger constructor. This CLI profile supports a fresh allocation baseline, not
an already-mutated ledger. It is deliberately narrower than the library API.
The baseline file is capped at 1 MiB before decoding. Configuration limits are
checked before constructing the ledger; they are local tooling limits, not
mainnet parameters. Distribute and pin this file through a trusted channel;
placing a matching commitment inside an untrusted file does not authenticate it.

MINIMUM_JSON is `{ "batches": u64, "digest": B256 }`, capped at 4 KiB. Keep this
mark independently of the journal. It must identify a retained prefix; using an
old mark cannot detect loss of newer records. The command never overwrites the
operator's retained mark. Input files must be regular files, not symlinks. Protect
all input paths against concurrent replacement by other processes.

Output includes the recovered mark, state commitment, inbox root/count, conserved
accounting status and `locked_sat` as a decimal string (avoiding loss of u128
precision in consumers). `native_finality_verified` is always false: a successful
local audit does not prove L1 finality, native backing, mainnet supply or mint
permission. No addresses or funding keys are enumerated in the report.

Exit status is 0 for successful output, 1 for rejected input or recovery, and 3
for output failure. A failed output may follow successful recovery synchronization;
rerun the audit to obtain the report. Recovery errors produce no success JSON.
The integrated durable-execution test invokes this executable on real disposable
PQ signatures, checks exact reported commitments and rejects a concurrent writer,
modified baseline and missing minimum history.
