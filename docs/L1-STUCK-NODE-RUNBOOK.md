# L1 node stuck on its own branch: detection and recovery

For operators of `bloch-pos` nodes. Detection is read-only. Recovery deletes chain data, so read section 3 in full first.

## 1. What it is

A node that is restarted while it can reach only part of the network can build a short branch of its own. After it reconnects, the other side's blocks have unknown parents. They are parked, the parking limit per source (32) fills, and the node does not walk back to the common ancestor. It stays on its branch, keeps signing there, and its stake stops counting on the main chain.

Neither cure is certain. On private rehearsal nets (one host, devnet transport, 1 s slots, doppelganger protection off):

| Action | Result |
|---|---|
| Restart of one stuck node | Healed it in 1 of 3 runs |
| Restart of the whole stuck group of 5 | 0 of 2 runs healed the tracked node; in 3 later runs, 5, 3 and 3 of 5 nodes healed |
| Delete chain data and resync | 5 of 5 nodes in one run, 4 of 5 in another. The fifth signed during its resync, built a new branch at an old epoch and stuck again |

How this behaves on libp2p across real hosts has not been tested.

Those nets had a young genesis. On mainnet the genesis is older than the weak-subjectivity window, so a wiped node refuses to start unless it gets a checkpoint or a healthy node's chain files: see "Wipe and resync" below.

## 2. Detect

All three signs must hold together, while the reference gains at least 3 finalized epochs:

| Sign | Source |
|---|---|
| Parked blocks steady at 32 or more | `bloch_pos_blocks_parked` on the node's metrics port |
| Finalized epoch not moving while the reference's advances | `getchaininfo` on both |
| Reference head unknown to the node | `getblockbyid` on the node answers "no block" for the reference's `block_id` |

One sign is not enough. A healthy node has shown 27 and 32 parked, and a node catching up lacks the reference head for a while.

Tools:

- `deployment/mainnet/l1_stuck_check.py`: standalone, no dependencies.
- `deployment/mainnet/l2_monitor.py --l1-stuck-node NAME=RPC_URL[,METRICS_URL] --l1-stuck-state PATH`: the same decision, compared against the `--l1-rpc` nodes. Without these options the monitor makes no extra call.

| Result | Meaning | Do |
|---|---|---|
| OK | The signs do not hold together, or not for long enough | Nothing |
| OK "does not answer" | Probably a restart | Nothing yet |
| UNKNOWN | No reference answers, or the node has been silent for 3+ finalized epochs | Check the node or the references |
| WARN "not following the reference" | Finalized frozen and head unknown, but parked is low or unreadable | Check connectivity and peers. A node cut off from the network looks like this and recovers once reconnected |
| WARN "finalizing, but" | Finality close to the reference, yet the head stays unknown | Compare finalized roots by hand, and escalate if they differ |
| CRIT "STUCK" | All three signs held | Section 3 |

Metrics are off by default (`--metrics-port`). Without them the tool can reach WARN but never CRIT.

Alarm time: CRIT comes when the reference has gained 3 finalized epochs since parked reached 32, plus up to one poll. Measured at 1 s slots: 89-98 s from parked reaching 32 (3 epochs are 96 s). On mainnet that scales to about 48 minutes plus the poll, which is an inference, since no run used 30 s slots. After a restart the wait starts again, so a node that is still stuck returns to CRIT one window later.

Finality that has stalled everywhere never raises this alarm, since the reference gains no epochs. `l2_monitor.py`'s `l1_finality_lag` covers that case.

## 3. Recover

Do this for one node at a time, and only on a CRIT that you have confirmed.

### Never delete

- `validator.key`
- `validator.kes`
- `slashing_protection.bin`

Deleting `slashing_protection.bin` removes the node's record of what it has signed, including on the stuck branch. Signing again without that record can get the validator slashed. Back up these three files only by your normal secure procedure, and never into a shared location.

Also leave `mesh_identity.bin` and any other file not listed under "Delete only".

### Before you touch anything

1. Confirm which side is the main chain. Compare the node with at least two references on different hosts, and with a public explorer if there is one. The stuck node is the one that gained no finalized epochs. **If the references disagree with each other, or several of your nodes show CRIT, stop and escalate.** Wiping the wrong side loses the wrong data and takes more stake offline.
2. Do not wipe a node that is only cut off. Restore its network and wait 3 finalized epochs. In the 12-epoch partition rehearsal, the cut-off side recovered without any wipe.
3. Check that the host reaches its peers and has the disk space for a full chain.

### First: one restart

A restart costs far less than a full resync and sometimes heals. Restart the stuck node once, with doppelganger protection on, and let `l1_stuck_check.py` run for 3 finalized epochs after duties resume. If it is back at CRIT, or it has not rejoined, go on to the wipe.

### Wipe and resync

**A wiped mainnet node does not start without a weak-subjectivity checkpoint.** With the mainnet binary (fa980367, `01c98b68…`) and an empty data directory, `bloch-pos run` exits at once with `ERR_WS_REQUIRE_CHECKPOINT`: its only anchor, the genesis, is older than the 2016-epoch window. Keeping `ws_latest.bin` does not help; the node refuses the same way. So before you delete anything, have one of these ready:

- **A published checkpoint** (preferred): the envelope, the signer-set file and the signer-set SHA3-256 fingerprint from an independent channel, as in `CHECKPOINT-RUNBOOK.md` §4. Add `--ws-checkpoint ENVELOPE --ws-signer-set SET --ws-signer-set-sha3 FINGERPRINT` to the unit's `ExecStart` for the first start. If no checkpoint younger than 2016 epochs is published, this path does not exist: do not wipe.
- **The chain files of a healthy node you operate** (`blocks.*`, `meta.*`, `ws_latest*`, copied while that node is stopped; never its `validator.key`, `validator.kes` or `slashing_protection.bin`). The node then boots from that node's finalized history, needs no checkpoint, and replays every block before it serves; see "How long it takes" below.

Without one of the two, a wipe turns a stuck validator into a stopped one.

Replace `UNIT` and `DATA_DIR` with your values. Check each one before running. These commands are for the node being recovered only.

Stop the node:

```
sudo systemctl stop UNIT
```

Confirm it has stopped. It must not be running when files are removed:

```
systemctl is-active UNIT
```

Look at what the delete pattern matches, before deleting:

```
sudo find DATA_DIR -maxdepth 1 -type f \( -name 'blocks.*' -o -name 'state.cache*' -o -name 'meta.*' -o -name 'ws_latest*' \) -print
```

**Delete only** files shown by that command. It must not list `validator.key`, `validator.kes` or `slashing_protection.bin`:

```
sudo find DATA_DIR -maxdepth 1 -type f \( -name 'blocks.*' -o -name 'state.cache*' -o -name 'meta.*' -o -name 'ws_latest*' \) -delete
```

Confirm the protected files are still there:

```
sudo ls -l DATA_DIR/validator.key DATA_DIR/slashing_protection.bin
```

On a node with a KES tree, also confirm that one:

```
sudo ls -l DATA_DIR/validator.kes
```

Start it, with doppelganger protection on (do not add `--no-doppelganger-check`):

```
sudo systemctl start UNIT
```

### Afterwards

- Watch `l1_stuck_check.py` until it reports OK, with the reference head known and the finalized epoch following the reference.
- During the resync it reports OK or "does not answer". A long resync is expected. See "How long it takes" below.
- **Keep watching after the resync starts.** A wiped node can stick again, as one did in rehearsal with doppelganger protection off: it shows CRIT at a finalized epoch below where it stood. Repeat the wipe once, with protection on and the peers confirmed reachable. If it sticks again, stop the node and escalate.
- The log may show `slashing protection: refusing` lines. That is the protection doing its job on what the node signed on the stuck branch. Do not remove the file to silence them.

### Refill from a healthy node you operate (no checkpoint needed)

Use a node of your own fleet that `l1_stuck_check.py` reports OK and that follows the reference head; prefer one that does not validate (an RPC or archival node). Stop it briefly (it misses its duties meanwhile, so pick one with no proposal due), copy its chain files, start it again. Copy by name, never with a glob over the whole directory:

```
sudo systemctl stop HEALTHY_UNIT
sudo tar -C HEALTHY_DATA_DIR -cf /tmp/chain.tar blocks.log blocks.idx meta.bin ws_latest.bin state.cache
sudo systemctl start HEALTHY_UNIT
```

Move `/tmp/chain.tar` to the stuck node's host, then, with the stuck node stopped and after the delete above:

```
sudo tar -C DATA_DIR -xf /tmp/chain.tar
sudo chown -R NODE_USER: DATA_DIR
sudo ls -l DATA_DIR/validator.key DATA_DIR/slashing_protection.bin
sudo systemctl start UNIT
```

The tar must hold no `validator.key`, `validator.kes`, `slashing_protection.bin` or `mesh_identity.bin`: list it with `tar -tf /tmp/chain.tar` before moving it. The node keeps its own key and its own slashing protection, and catches up from the copied head over the network.

### How long it takes

Measured 2026-11-02 (agents/106-recovery.md) with the mainnet binary fa980367 (`01c98b68…`) on a copy of mainnet history to slot 211072 (e6596, 174,032 blocks, 2.9 GB), on a shared 32-core host under load, nodes linked by the devnet transport on loopback inside a private network namespace (not libp2p, not across hosts). Mainnet is about 660 epochs longer today, so scale times by about a third.

| Path | Time to serve the copied head | Needs |
|---|---|---|
| Wipe, then start | Never: exit `ERR_WS_REQUIRE_CHECKPOINT` | Not usable on mainnet |
| Wipe, start with a weak-subjectivity checkpoint | Accepted, then fetches every block from slot 1 over the peer link at a steady 4.2 blocks/s (14,336 blocks in 3,394 s, 128 per 30 s): about 11.5 h for 174,032 blocks, about 15 h for today's chain, extrapolated | A published checkpoint, signer set and fingerprint |
| Refill with a healthy node's files including `state.cache` | 97 s from start (cache restore 21 s); 5 s to copy 2.9 GB on one disk | A healthy node stopped for the copy |
| Refill without `state.cache` (or `state.cache` lost) | Full replay: 51 to 54 min | A healthy node stopped for the copy |

After it serves the copied head, the node still catches up over the network for the time since the copy was taken.

## 4. Avoiding it

- Keep doppelganger protection on. It delays duties by 64 slots, which is 32 minutes at 30 s slots. On rehearsal nets a restarted group split only when it stayed isolated for longer than that window. The scaling to 30 s slots is an inference, since no run used 30 s slots.
- Restart in waves, confirming each host reaches its peers.
- Do not start validators on hosts cut off from the rest. After an outage over 32 minutes, restore the network first.
