# Stuck L2 block: operator runbook

Applies to `settler_v3.py` on chain 700770. Tool: `deployment/mainnet/l2_stuck_block.py`. Rehearsal: `deployment/mainnet/heavy/stuck_drill.py`.

## What a stuck block is

The settler commits a block to its database, then proves it. Proof failures (out of memory, the 3600 s limit on a proof
attempt) are retried on the same block, and after `max_consecutive_failures` the worker exits and systemd restarts it.
Settlement, deposits and withdrawals wait. Nothing else breaks: L1 keeps its frozen source, and that source does not
expire while the block is unproved.

Symptoms in the settler log:

- `prover-failed` for the same directory, more than once;
- `retry` with `prover prove failed`, or `remote-proof` with a non-zero `exit_code`;
- `l2-block-reused` with the same number after each restart.

Do not act on one failure. A killed or rebooted prover also produces one.

## Why recovery is safe

- Proof comes first. DA publication and settlement both need a proof, so a stuck block has nothing on L1.
- Transactions waiting in the spool are evicted after 3 hours and must be sent again: a long stop costs users that, not funds.
- `safe` and `finalized` on the RPC, the bridge signers, attestors and replicas read settled L1 data only. They never
  saw the block. Only `latest` on the RPC that reads the settler database shows it.
- Deposits are minted again in the replacement: the native request names them and does not move.
- Withdrawals in a replaced block never reached L1, so nothing can be claimed from them.
- `discard` refuses any block that has a proof, a prepared DA transaction, a DA record on L1 or a submitted settlement.

What an operator can do wrong: replace a block that users saw on `latest`. A transaction in it can be quarantined or land
in another block. That is a change of unsettled history only. Announce it.

## Step 0: stop and read

Stop the settler and the settled RPC on this host.

```
sudo systemctl stop bloch-l2-mainnet-settler
```

```
sudo systemctl stop bloch-l2-mainnet-rpc
```

Check that no prover survived, on the settler host and on the prover host.

```
pgrep -af 'settlement-v3.*prove-groth16|sp1-native-runner'
```

A prover that was killed can leave `sp1-native-runner-bin` children and a Gnark container behind (about 4 GB each in the
rehearsal). Stop those too.

Read the block. This changes nothing.

```
python3 l2_stuck_block.py status --config /etc/bloch-l2-mainnet-settler/settler.json
```

Decide from these fields:

| Field | Meaning |
|---|---|
| `proved: true` | There is a verified proof. Start the settler. It publishes and settles. |
| `da_recorded_on_l1` not empty, `da_prepared` not empty, `settlement_submitted: true` | Past the proof step. Not a stuck block. Start the settler and read its log. |
| `transactions` 0 or null | Deposits only. Exit A is the only exit. |
| `instructions` | The guest's count for this block. Compare it with the budget. |

## Exit A: prove it on a bigger machine

Use this when the block is over the limits of this prover and you want to keep it exactly as it is. Nobody loses a
transaction and the block hash does not change. A proof is valid wherever it is made, and the inputs are not secret.

Settings that use less memory, at about twice the time, let this prover finish blocks above its default limit (193M
instructions at 90 GiB, in 1 h 43 min, rehearsal host, about 20 cores). Set them on the proving command:
`SP1_WORKER_NUM_CORE_WORKERS=2 SP1_WORKER_CORE_BUFFER_SIZE=1 SP1_WORKER_NUM_SPLICING_WORKERS=1 SP1_WORKER_SPLICING_BUFFER_SIZE=1 SP1_WORKER_GLOBAL_MEMORY_BUFFER_SIZE=2`.

Use exit B when the block would need more than about half a day of proving. Extrapolated at those settings, the worst
15M-gas block needs about 35 hours. That run was not measured.

```
python3 l2_stuck_block.py export-job --config /etc/bloch-l2-mainnet-settler/settler.json --out /var/tmp/job-N
```

Copy the directory to the big machine, with the same host binary and the pinned guest `203114bf…c473`. There:

```
HOME=$PWD/home RAYON_NUM_THREADS=24 SP1_CIRCUIT_MODE=release BLOCH_NATIVE_L2_REQUEST=job-N/native-request.txt BLOCH_NATIVE_L2_ARTIFACT=job-N/block.artifact bloch-evm-sp1-settlement-v3 --mainnet prove-groth16 native-artifact settlement_v3_mainnet job-N/external.proof
```

Copy `external.proof` back and import it. The tool verifies it against this block's request and artifact, and refuses
anything else.

```
python3 l2_stuck_block.py import-proof --config /etc/bloch-l2-mainnet-settler/settler.json --proof /var/tmp/job-N/external.proof
```

Start the units. The settler finds `proved.json` and continues with DA and settlement.

```
sudo systemctl start bloch-l2-mainnet-rpc
```

```
sudo systemctl start bloch-l2-mainnet-settler
```

## Exit B: replace the block

Use this when a transaction in the block cannot be proved at an acceptable cost.

### 1. Find the transactions

`triage` runs the guest in execute mode for each transaction, in block order. It needs no proof and no lock. It takes
seconds per transaction, plus up to 1-2 minutes for a transaction of several billion instructions. It waits with exit 75 until the follower has finalized the accepted settlement. Run it again later.

```
python3 l2_stuck_block.py triage --config /etc/bloch-l2-mainnet-settler/settler.json --budget 100000000 --budget-gas 240000000 --follower-state /var/lib/bloch-l2-mainnet-follower/state --follower-status /var/lib/bloch-l2-mainnet-follower/status.json --out /var/tmp/triage-N.json
```

Read `exclude`, `kept` and `instructions_after` in the output. A 15M-gas transaction of a kind that cannot be proved shows up as a
single step with a delta in the billions.

### 2. Plan, then apply

Without `--apply`, the tool rebuilds the database in a new directory, checks that its head equals the accepted settlement,
prints the plan, and removes the new directory.

```
python3 l2_stuck_block.py discard --config /etc/bloch-l2-mainnet-settler/settler.json --follower-state /var/lib/bloch-l2-mainnet-follower/state --follower-status /var/lib/bloch-l2-mainnet-follower/status.json --exclude-file /var/tmp/triage-N.json
```

```
python3 l2_stuck_block.py discard --config /etc/bloch-l2-mainnet-settler/settler.json --follower-state /var/lib/bloch-l2-mainnet-follower/state --follower-status /var/lib/bloch-l2-mainnet-follower/status.json --exclude-file /var/tmp/triage-N.json --apply
```

What `--apply` does:

- returns the block's other transactions to the spool;
- moves the named ones to `<txpool>-quarantine/`, which nothing reads;
- moves the work directory and the old database aside, for review;
- installs the rebuilt database.

### 3. Resume

```
sudo systemctl start bloch-l2-mainnet-rpc
```

```
sudo systemctl start bloch-l2-mainnet-settler
```

The RPC unit removes its view directory at start. The settler builds a new block with the same number, same anchor and same
deposits.

### 4. Check

- The settler log shows `l2-block-produced` and then `accepted` for that number.
- `eth_getBlockByNumber latest` shows the new block.
- A replica rebuilt from L1 reports the same head.
- Withdrawals in the discarded block are back in the block, or quarantined. A quarantined transaction never executed, so
  the sender has not paid and holds the same balance.

Keep the quarantined file and the old database until the block is finalized.

## After any stuck block

The offender can be sent again. If the budget of `settler_v3.py` (`max_block_instructions`, `max_block_sp1_gas`) is not active, enable it before
reopening the spool. With it, a block over the budget is never committed, so this runbook covers only hardware failure.
