# Bloch L2 mainnet read-only replica

A standalone replica of L2 mainnet (chain id 700770) for any host that is not the settler: guardians, monitors,
reserve watchers, signers' mint pre-checks. It runs a native follower and a settled RPC, and rebuilds the L2
database from L1 data only. It has no txpool, no key and no signing path, and it trusts nothing from the settler.

`deployment/mainnet/follower-rpc` remains the package for the settler host: it needs the settler's database and
spool. This package needs neither.

## What runs

| Unit | Runs as | Does | Limits |
|---|---|---|---|
| `bloch-l2-replica-follower.service` | `bloch-l2-replica` | FFG replay of L1 from the pinned Genesis-4 manifest, one L1 RPC, read-only methods | 6 GB, 200% CPU, network: only that L1 host |
| `bloch-l2-replica-refresh.service` + `.timer` | `bloch-l2-replica` | every 5 min, if the follower's tip moved: `produce reconstruct` into a new generation, check it, swap `current` atomically | 3 GB, 100% CPU, no network |
| `bloch-l2-replica-rpc.service` | `bloch-l2-replica` | `bloch-l2-settled-rpc` on `127.0.0.1:18965`, no `--txpool` | 4 GB, 200% CPU, loopback only |
| `bloch-l2-replica-rpc-reload.path` + `.service` | root | restarts the RPC when a new generation is published (the only privileged step) | no network |

The refresh keeps the current generation and one older generation. It halts (exit 3, current database untouched) if a
rebuild has another L2 genesis, contradicts a finalized settlement, or no longer holds a block it published before.
A rebuild that changes nothing is discarded, so the RPC does not restart once per epoch.

Paths: binaries in `/opt/bloch/l2-replica/releases/<id>` behind `current` and `previous` symlinks, public inputs and
the L1 URL in `/etc/bloch-l2-replica`, data in `/var/lib/bloch-l2-replica/{follower,generations,rpc,refresh}`.

Host: 4 vCPU, 8 GB, 100 GB. Choose an L1 RPC close to the host: the follower fetches one block per request, so the
first sync takes about an hour at 2 ms per request and about two days at 0.9 s per request.

## What the levels mean here

- `finalized`: the L2 block whose settlement lies inside the prefix this replica verified by its own FFG replay. It
  never comes from the settler or from the L1 RPC. Use this level for decisions.
- `latest`: the newest settled block in the follower's verified blocks. It can be ahead of `finalized` by about
  3 epochs, because the follower's own FFG proof trails the L1 node's finalized root. It is not the sequencer's head:
  a block that is produced but not settled is not visible here.
- `safe`: the settlement the L1 RPC reports at its head, if it matches the local chain. It rests on that RPC's word.
- `eth_sendRawTransaction` is refused. Send transactions to the public gateway or the sequencer.
- An L1 RPC can stall a replica or feed it no new blocks. It cannot make it accept a false chain: stale data shows
  as lag, which `replica_check.py verify` reports.

## Install

Everything below is for the operator of the replica host, as root. Installing starts nothing.

`DIR` holds `bloch-l2-native-follower`, `bloch-l2-settled-rpc`, `bloch-l2-produce-dev`, `mainnet.manifest` and
`carryover.tsv.gz`. `PINS.sha256` pins all five, and an install stops on any difference. `--settler-l1-rpc-url` names
the settler's L1 source so the replica refuses to read from the same host. Credentials in a URL are refused, and so is
an artifacts directory with a secret-looking file. The installer also refuses a host with a settler state directory.

```
sudo ./install-replica.sh install --artifacts DIR --l1-rpc-url http://HOST:8080 --settler-l1-rpc-url http://OTHER:8080 --dry-run
```

```
sudo ./install-replica.sh install --artifacts DIR --l1-rpc-url http://HOST:8080 --settler-l1-rpc-url http://OTHER:8080
```

```
sudo systemctl enable --now bloch-l2-replica-follower bloch-l2-replica-refresh.timer bloch-l2-replica-rpc-reload.path
```

```
sudo systemctl enable bloch-l2-replica-rpc
```

The first replay takes about an hour. When the follower reports the L2 genesis final, the next refresh publishes the
first generation and the path unit starts the RPC. Check it with:

```
./install-replica.sh status
```

```
sudo -u bloch-l2-replica python3 -I /opt/bloch/l2-replica/current/replica_check.py verify --rpc http://127.0.0.1:18965 --status /var/lib/bloch-l2-replica/follower/status.json --l1 http://HOST:8080 --l1 http://OTHER:8080
```

The sandbox settings have not been run under systemd in a rehearsal. On the first real start, check that all three
services stay up with `systemctl --failed` and `journalctl -u 'bloch-l2-replica-*'`. A `status=31/SYS` or `203/EXEC`
exit points at the sandbox.

## Upgrade and rollback

New binaries are a reviewed change of `PINS.sha256` in this directory. Stage and flip with:

```
sudo ./install-replica.sh upgrade --artifacts NEWDIR --dry-run
```

```
sudo ./install-replica.sh upgrade --artifacts NEWDIR
```

Both releases stay on disk with their rendered units. The upgrade restarts nothing and prints the services whose binary
changed. An RPC restart takes seconds. A follower restart re-verifies the whole chain from Genesis-4, about an hour,
and `finalized` stays frozen meanwhile: never restart a follower across an L1 gate you need.

```
sudo ./install-replica.sh rollback
```

A rollback flips `current` and `previous` back, restores that release's units and prints the same restart list. Its
hashes are checked first. Data is not touched. To remove the replica, use `remove`, which keeps the verified blocks,
or `remove --purge-data`.

## Pointing the bridge and L2 services at a replica

Run the replica on the operator's own host, and read it on loopback. The binary only binds `127.0.0.1`. For a second
host use an SSH tunnel or a private network. Do not publish the port: the public gateway in
`deployment/mainnet/public-rpc` does that job.

| Service | Setting | Value | Notes |
|---|---|---|---|
| `tools/guardiao/guardiao.py` | `l2_rpc` | `http://127.0.0.1:18965` | **Reads only: see the limit below.** Also set `l2_genesis_hash`. |
| `tools/reservas/reservas.py` | each bridge's `l2_rpc` | `http://127.0.0.1:18965` | Read-only. Reads at `finalized`, so this is an exact fit. |
| `tools/signatario-*` mint pre-checks | `l2_rpc` | `http://127.0.0.1:18965` | Mints are checked against the settled chain. See the relayer limit. |
| `tools/signatario-*` release | `follower` | the signer's own follower | The signer rebuilds the L2 itself and serves it on a private settled RPC. It never reads `l2_rpc` for finality, so this path needs no replica. |
| `deployment/mainnet/attestor` | none | | The agent has no L2 RPC: it uses its own follower and rebuild, plus an L1 RPC quorum. Do not point it at a replica. |
| `deployment/mainnet/l2_monitor.py` | `--l2-rpc` | `http://127.0.0.1:18965` | Gives a second view next to the settler's RPC. |

Use a different `--l1-rpc-url` per operator, so that a stalled L1 RPC stops only one of them.

### Limit: a replica cannot carry transactions

`guardiao.py` sends `pause()` through the same `l2_rpc` it reads (`cast send --rpc-url` or `send_raw_l2`), and
`vigia.py` sends relayed L2 transactions through `l2_rpc` too. A replica refuses `eth_sendRawTransaction`, so with only
`l2_rpc` set to a replica **a guardian detects a violation and then fails to pause**, with the failure only in its log.
Before guardians depend on a replica, these tools need a separate setting for sending, for example `l2_tx_rpc`,
pointing at the public gateway or the sequencer, with the receipt read from the same endpoint. Nonces must also be
read there, because the replica's `latest` trails the sequencer.

### Limit: a replica sees settled blocks only

A mint that the sequencer has included but not settled does not appear on the replica. `guardiao.py` compares reserves
at `latest`, so its view trails by the settlement delay. Its grace periods (`reserves_grace_s`, `provenance_grace_s`)
must exceed that delay. That delay is a property of the settler's cadence and is not set here.

## Tests

`REPLICA_ARTIFACTS=DIR python3 -I tests/test_replica.py` runs the installer, refresh and check tests with fake binaries
and fake RPCs on loopback. `DIR` holds the real `mainnet.manifest` and `carryover.tsv.gz`.

`--prefix DIR` installs everything under `DIR`, without users, ownership or systemctl, and
`rehearsal/run-prefix.py DIR exec UNIT` runs the rendered unit's exact command. That exercises the command lines
and the data flow, not the sandbox.
