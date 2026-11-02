# Bloch L2 mainnet attestor agent

Chain 700770. Attestor set `1c06adbb…cc4b`, 3-of-5 hybrid ML-DSA-65 + Falcon-1024 keys, pinned
in consensus (`l2_settlement::mainnet::ATTESTOR_SET`). Changing the set needs a hard fork.

Attestations are needed only for L2→L1 withdrawal **claims of 100 BLCH or more**. Such a claim
proves against `withdrawals.matured_large`: the newest retained root at least 2,880 blocks old.
The claim carries three signatures over
`SHA3("BLOCH:L2:WITHDRAW-ATTEST:1" ‖ network f47d3e49… ‖ chain 700770 ‖ root)`.

Each of the five operators runs one agent with one key, on their own host. The agent does the
signing by itself. Operators act only on alerts.

## Contents

| File | Role |
| --- | --- |
| `attestor_agent.py` | The agent: `run`, `once [--dry-run]`, `check [--no-key]`. Python standard library only. |
| `attestor_lib.py` | Pins, withdrawal tree, set hash, attestation digest. All mirror the native code. |
| `aggregate_attestation.py` | Claimant tool. Collects any 3 partials, verifies them natively and prints the `prepare` arguments. |
| `sigfeed.py` | The read-only feed server and the bounded fetch client. The same file ships in the bridge signer (`sigfeed.sha256` pins it). |
| `install-attestor.sh` | `install`, `upgrade`, `upgrade-rollback`, `rollback [--purge-key]` (uninstall) and `status` on an operator host. |
| `systemd/bloch-l2-attestor.service` | The hardened agent unit: no listener, `IPAddressDeny=any` plus an allow-list, `LoadCredential`. |
| `systemd/bloch-l2-attestor-feed.service` | The read-only feed (`--feed-port`): the agent's outbox only, no credential. |
| `systemd/bloch-l2-attestor-follower.service` | The agent's own native follower (FFG replay from Genesis-4). |
| `keykit/` | Key custody for the key holder: seal, verify, package, backup-check, shred, release (`make-operator-bundles.sh`, `KEY-HANDOFF-CHECKLIST.md`); operator side: `check-operator-bundle.sh`, `OPERATOR-ONBOARDING.md`, `OPERATOR-INSTALL.template.md`, pins `operator-pins-v2.sha256`. |
| `public/` | The pinned `attestors.set` and the five public keys. |
| `tests/` | `python3 -m unittest -v test_attestor` (needs `BLOCH_POS` and `MAINNET_MANIFEST`) and `python3 -m unittest -v test_upgrade` (no native binary; follower pin and `upgrade`/`upgrade-rollback`). |
| `tests/rehearse_upgrade.sh` | Rehearsal of `upgrade`/`upgrade-rollback` on old-kit `--prefix` installs against live L1 (`rehearsal_services.sh` stands in for systemctl, `rehearsal_check.py` runs `check` with a throwaway set). |
| `tests/test_package_guards.py` | `python3 -m unittest -v test_package_guards` on Linux: refusals for stale pins, unpublished binaries, and the retry after a failed key step. No native binary. |
| `tests/rehearse_owner_flow.sh` | End-to-end owner rehearsal with throwaway keys (`tty_driver.py` types the passphrases). |
| `tests/rehearse_custody_flow.sh` | Custody rehearsal with throwaway keys: `owner` part (macOS or Linux) and `operator` part (Linux, v2 artifacts). |

The agent needs a `bloch-pos` built from bloch-sis-pow `codex/l2-attestor-keystore-20261019`
(dd287b6c + one CLI-only commit). That commit adds:

- `l2-claim seal-key`, `key-check` and `key-info`;
- `l2-claim attest --sealed`;
- `l2-claim verify-attestation`.

Consensus code is unchanged. The other binaries come from the RC pinned build (`build-release.sh`):
`bloch-l2-native-follower` and `bloch-l2-produce-dev`.

## What the agent does each cycle (default 60 s)

1. **Pause file.** If `/etc/bloch-l2-attestor/PAUSE` exists, the agent does nothing.
2. **Own follower.** `status.json` must be under 15 minutes old, on network `f47d3e49…` and chain
   700770, with the L2 genesis `632e45ae…` finalized.
3. **Discovery via RPC quorum.** The agent calls `getl2settlement` on three read-only RPCs. It uses
   an answer only if 2 of the 3 match on network, genesis, chain, attestor set, large-claim
   threshold, retained `withdrawals.roots` and the `claimed` bitmap.
   - A pin mismatch halts the agent (exit 3).
   - A retained root becomes a candidate only if it is also a settlement in the agent's **own
     FFG-finalized replay**, with the same root and count. Otherwise the agent logs
     `awaiting-own-finality`, or `refused-root-not-on-own-chain` with an alert.
   - The RPCs can make the agent skip a root. They can never make it sign.
4. **Rebuild.** The agent rebuilds the whole L2 from the L1 blocks alone
   (`produce reconstruct --l1-follower --rules mainnet`).
   - The rebuilt block hash, state root and withdrawal root/count must equal the finalized
     settlement. If not, the agent logs `refused-rebuild-differs` with an alert.
   - It derives every leaf under the root with `withdrawal-proof` and re-checks each one in Python.
5. **Policy.**
   - If the root covers no unclaimed withdrawal of 100 BLCH or more, the agent logs `root-skipped`.
   - Otherwise the root is **held**, with an alert, when either:
     - a withdrawal is above `max_single_sat` (default 1,000 BLCH), or
     - the large withdrawals this root would newly cover push the UTC day past `daily_cap_sat`
       (default 1,000 BLCH).
   - To release a held root, add the `INDEX LEAF` line from the alert to
     `/etc/bloch-l2-attestor/approvals.txt`. The leaf must match.
6. **Sign and publish.**
   - The agent signs with `bloch-pos l2-claim attest --sealed`. The key is opened inside bloch-pos
     only.
   - It checks the partial: signer index, and the digest over the pinned network, chain and root.
   - It checks the signature length. A claim admits attestor signatures of at most 4,593 bytes,
     but a valid Falcon-1024 part can make the hybrid signature longer. The agent then signs
     again (fresh randomness, `resign-oversized` event), at most 64 times, and halts if none fits.
     The aggregator also skips a partial whose signature is longer than 4,593 bytes.
   - It writes the partial to `/var/lib/bloch-l2-attestor/outbox/700770/<root>/attestor-<I>.partial`
     (plus a `.json` file).
   - The operator's feed serves the outbox. It also pushes to any optional push target, retrying failures every cycle.
   - It raises a `signed` alert.

At startup and once a day, `rebuild-check` rebuilds the L2 and compares every finalized settlement.
This makes a broken rebuild (sandbox, disk, binary) show up before a claim needs it.

Every root that covers an unclaimed large withdrawal is signed as soon as it is finalized. That is
about 2,880 blocks before the root can serve a large claim. So partials are already waiting when
the claimant needs them.

## Oversized signatures, and the `bloch-pos` pin

The pinned `bloch-pos` (`093909a2…`, `keykit/operator-pins-v2.sha256`) has no `sign_fitting`, so `l2-claim attest` can write a
signature above the claim's 4593-byte bound. The agent is the gate, and the pin does not need to move:

- `sign` writes `attest` output to a scratch directory, and only a partial that `attestor_lib.parse_partial` accepts reaches
  the outbox. Above the bound it signs again with fresh randomness, at most 64 times, then halts.
- The feed serves only the outbox, and push targets publish only from it, so an oversized partial is never published.
- The fix reaches a host through the kit: `attestor_agent.py` and `attestor_lib.py`, copied by `install-attestor.sh` and covered
  by `CONTENTS.sha256` in each operator package. Packages built before this commit do not have it, so build them from this commit.
- **Do not run `l2-claim attest` by hand and publish the result.** `aggregate_attestation.py` and the monitor both ignore an
  oversized partial, but a hand-made one costs that signer the round.

## Where partials go (the operator's read-only feed)

Each operator serves its own outbox: `bloch-l2-attestor-feed` runs `sigfeed.py serve` on one TCP port.

    GET <base>/700770/<root>/attestor-<I>.partial

- There is no shared drop, no token and no upload path. The aggregator and the monitor poll the five
  feeds. Attestors never read each other, so one operator down costs exactly that operator's partial.
- The feed is a separate unit from the agent. It holds no credential, sees only the outbox (a read-only
  bind mount), accepts GET and HEAD, serves only the path shape above and caps connections per address.
- Partials are public: one signature over a public root. The content authenticates itself, so a feed
  can withhold but cannot forge. The aggregator treats each source as hostile (byte and time limits,
  no redirects) and lets the native verifier choose among candidates, so a forged partial from one
  source cannot displace a real one from another.
- Plain HTTP is enough, because TLS adds no integrity here. An operator who wants HTTPS can put an
  auto-renewing proxy in front; `sigfeed.py serve --tls-cert --tls-key` also works, but an expired
  certificate takes the operator's feed down.
- Monitor: pass `--attest-drop URL` once per feed.

### Hosts with no inbound port

The push options remain for these hosts: `--publish-command '["rsync","-a","{file}","me@my-host:/srv/{relpath}"]'`,
or `--publish-url` with `--publish-token-file` for a PUT endpoint the operator controls. Either target
must then serve the same paths over GET. This target belongs to that operator alone; it is not a shared drop.

## Operator install (each of the five hosts)

The host must not be a mainnet validator host or the settler. It needs 2 cores, 8 GB RAM and an
80 GB disk (`keykit/OPERATOR-ONBOARDING.md`). All commands run as root. Nothing below sends a transaction.
An operator follows the package's `INSTALL.md`; this is the short form.

```
sudo ./install-attestor.sh install --artifacts DIR --index I --bundle attestor-I.sealed \
     --l1-rpc-url http://80.240.16.185:8080 --feed-port 8787
sudo systemctl enable --now bloch-l2-attestor-follower
sudo systemd-run --pipe --wait -p User=bloch-l2-attestor \
     -p LoadCredential=passphrase:/etc/bloch-l2-attestor/keystore.passphrase \
     /usr/bin/python3 -I /opt/bloch/l2-attestor/attestor_agent.py check --config /etc/bloch-l2-attestor/config.json
sudo systemctl enable --now bloch-l2-attestor-feed
sudo systemctl enable --now bloch-l2-attestor
```

Notes:

- `install` asks once for the **transport passphrase** of the operator's bundle. It then re-seals
  the key under a fresh random host passphrase, stored in `keystore.passphrase` (root, 0400).
- A wrong passphrase leaves nothing installed: run the command again.
- `install` refuses a follower, producer or `bloch-pos` that is not the published build, whatever `SHA256SUMS` says.
- After the first command, wait for the follower's first replay (about 60–90 min).
- `check` prints `check-ok`. It covers the pins, opening the key, the follower, the RPC quorum and
  the rebuild check.
- When everything works, delete the bundle copy from the host. The operator keeps the offline backup.

Rehearsal without root or systemd: `install … --prefix /scratch/host-I` installs every file under
that directory as the invoking user, writes the units to `/scratch/host-I/systemd` without loading
them, and prints a `key-check` command instead of the systemd steps. `--rehearsal-set FILE` (only
with `--prefix`) accepts a throwaway attestor set. `tests/rehearse_owner_flow.sh` runs the whole
owner flow this way with throwaway keys (seal, verify, install for 3 operators, check, sign a
synthetic root, aggregate 3-of-5, native verify, shred). Rehearsed on 2026-10-19 on 209.250.236.240.

To uninstall, run `sudo ./install-attestor.sh rollback`. This removes the units and keeps the state
and the key. `--purge-key` also shreds the host key and passphrase, after you type `PURGE`. It is not a binary rollback: for
that, see `upgrade-rollback` below.

## Claimants: retry `l2-claim sign` on a shape error

With the pinned `bloch-pos`, about 1 in 1,000 runs of `l2-claim sign` draws a Falcon signature over the size bound.
It exits with `signed claim has an invalid shape: Shape` and writes no file. Run the same command again: each run
signs anew. No funds or nonces are affected.

## Binary pins

`config.json` pins three binaries by SHA-256: `bloch_pos_sha256`, `produce_sha256` and (since the
2026-10-30 kit) `follower_sha256`, the follower named by `follower`. The agent checks all three at
`check` and at the start of `run`/`once`. A mismatch halts it with exit 3, and the unit does not
restart. The follower pin matters because the follower's `status.json` is what the agent treats as
L1 finality: a replaced follower could report any settlement as finalized.

**Configs written by an older kit have no `follower_sha256`.** With this kit's agent they halt with
`config lacks follower and follower_sha256: the follower binary is not pinned …` (exit 3). This is
deliberate. The alternatives were worse:

- Warning and continuing would leave the gap open, and a warning in the journal is easy to miss.
- Pinning whatever follower is installed at first start would also pin a swapped binary.

The kit's agent scripts reach a host only through `install` or `upgrade`. Both write the pin
together with the scripts, from the published hashes. So the halt fires only if someone copies the
new scripts by hand. The fix is `install-attestor.sh upgrade`. Older agents ignore the extra keys,
so an old agent with a new `config.json` keeps working (this is the state after a partial rollback).

The pin covers the file on disk. The agent checks it only at start, so restart the agent after any
binary swap (`upgrade` does this). The running follower process is not inspected; the agent's
sandbox cannot see other users' processes. `upgrade` starts the follower only after the new file
is pinned.

## Upgrade (HF1–HF3: follower and producer v2)

The L1 hard forks start at epoch 7180 (HF1, 2026-11-01 16:11 UTC). Each attestor host must run the
v2 follower and producer **before epoch 7178 (15:39 UTC)**:

- `bloch-l2-native-follower` `cdf5da5cb38b12a483fc8822fa22c2b3e90e9e4c7918ec73814f682bc37550b2`
- `bloch-l2-produce-dev` `e3f1a290bf60b65702034fb0bc973ab15d1b05b236145c48880cfd2d0f477f69`

These are the hashes of the next build (build commit 17383fe), which replace v2.1's follower
and producer. They are built into `install-attestor.sh` as the defaults. Use `--follower-sha256` and
`--produce-sha256` only for a later corrected build whose hashes the coordinator published.

Upgrade **one host at a time**, so that at least 3 of 5 stay up. Each host is down for about
75 min (measured in report 02: 62 min re-verify, 13 min finality). Run the upgrade inside `tmux` or `screen`:

```
sudo ./install-attestor.sh upgrade --artifacts /root/hf123
```

`/root/hf123` holds the two files (a `SHA256SUMS` there is optional; if present it must agree). The
script does the manual procedure and stops at the first failure:

1. It checks both files against the published SHA-256 before it touches anything.
2. It creates `/etc/bloch-l2-attestor/PAUSE`, then stops `bloch-l2-attestor` and
   `bloch-l2-attestor-follower`.
3. It backs up `/opt/bloch/l2-attestor` to `/opt/bloch/l2-attestor.pre-hf123`, and `config.json` to
   `config.json.pre-hf123`. It moves the follower's `status.json` to `status.json.pre-hf123`, so
   that the agent cannot accept the old follower's last status as fresh.
4. It installs the two binaries and this kit's agent scripts (`attestor_agent.py`,
   `attestor_lib.py`, `aggregate_attestation.py`, `sigfeed.py`). It prepares
   `bloch-l2-attestor-feed.service` without enabling it, and keeps an existing `feed.env` unless
   `--feed-port` or `--feed-bind` is given (default `0.0.0.0:8787`; `--no-feed` skips the unit). A feed
   that is already running is restarted. The key, the passphrase, `bloch-pos`, the other units and
   the state do not change. **The host now needs inbound TCP 8787**: open it, then run the
   `systemctl enable --now bloch-l2-attestor-feed` line the script prints. `upgrade-rollback` removes a
   feed unit that the upgrade added.
5. It re-hashes the installed files.
6. It writes `produce_sha256`, `follower` and `follower_sha256` into `config.json` (atomically,
   keeping its owner and mode) and checks every pin against the disk.
7. It starts the follower and waits until a new `status.json` appears (the re-verify of the retained
   L1 history: about 50–60 min; `--wait-timeout`, default 2 h).
8. It runs `attestor_agent.py check` as at install. The run must print `check-ok`. A
   `check-not-ready` result is retried 10 times.
9. It waits until `native_finalized_epoch` advances (`--advance-timeout`, default 40 min).
10. It removes `PAUSE` and starts the agent (`--no-unpause` stops before this step).

At the end it prints `REPORT: attestor I: upgrade check-ok, epoch X->Y, follower cdf5da5c, produce
e3f1a290`. Post that line in the operators' channel; the next operator then starts.

If a step fails, `PAUSE` stays in place, the agent stays stopped and the follower keeps running.
Fix the cause, then continue from the follower start with
`sudo ./install-attestor.sh upgrade --resume`. A second `upgrade` on an upgraded host changes
nothing. Keep the `.pre-hf123` backups until after epoch 7360.

**Rollback, before HF1 only:** `sudo ./install-attestor.sh upgrade-rollback`. It restores the
backed-up binaries, agent scripts and `config.json`, moves `status.json` aside, and then repeats
steps 7–10 with the old follower. It also works after a failed upgrade. It is refused from 70
minutes before epoch 7180 on, because the old follower's re-verify could not finish before the
fork, and an old follower cannot follow the chain past it. After that, keep `PAUSE` and fix forward
with the published build. Partials already signed stay valid either way.

Rehearsal without root or systemd: `upgrade`/`upgrade-rollback --prefix DIR --service-cmd CMD
--check-cmd CMD` run against a `--prefix` install. `CMD start|stop|is-active follower|agent` stands
in for `systemctl`. `--now-unix` (prefix only) moves the clock for the HF1 gate.

## Claimant (≥ 100 BLCH)

1. Generate the withdrawal proof against `withdrawals.matured_large`.
2. Run:

   ```
   aggregate_attestation.py --proof proof.json \
       --source http://OPERATOR-0:8787 --source http://OPERATOR-1:8787 --source http://OPERATOR-2:8787 \
       --source http://OPERATOR-3:8787 --source http://OPERATOR-4:8787 --out att/ \
       --bloch-pos ATTESTOR-BUILD/bloch-pos --genesis mainnet.manifest --attestors attestors.set \
       --rpc http://80.240.16.185:8080 --rpc http://199.247.22.8:8080 --rpc http://45.77.67.251:8080
   ```

   **`--bloch-pos` must be the attestor build `093909a2…`, not the node build.** The node build (fa980367
   and the release it carries) has no `l2-claim verify-attestation`: it answers `l2-claim: expected prepare,
   inspect, sign, attestor-set, set-attestors, attest or --help`, and the aggregator then reports every set
   as refused, which reads like bad signatures. A claimant who sees that message has the wrong binary, not
   bad partials. The tool now says so.

3. Use the printed `--attestors … --attestation …` arguments in `bloch-pos l2-claim prepare`, then
   `sign`.
4. Broadcast separately.

## Alerts and actions

| Event | Action |
| --- | --- |
| `signed` | None. Expected for every large withdrawal. Check it against the L2 explorer if unsure. |
| `held` | Check the withdrawal. If it is legitimate, add the printed `INDEX LEAF` line to `approvals.txt`. |
| `refused-root-not-on-own-chain` / `refused-rebuild-differs` | Do not override. Compare with the other operators. Possible RPC or settler fault, or an attack. |
| `halt` (exit 3) | A pin, identity or rebuild failure. Read the reason. The unit does not restart by itself. |
| `waiting` | The follower is stale or there is no RPC quorum. Transient. |
| `publish-failed` | An optional push target is unreachable. The agent retries every cycle. The outbox still holds the partial, and the feed serves it. |

The pause file stops all signing at once: `sudo touch /etc/bloch-l2-attestor/PAUSE`.

## Measured and known limits

- **Live dry run, 2026-10-19, 45.77.142.123, read-only.** The run used the RC `bloch-l2-produce-dev`
  (`192eda33…`) and a live mainnet follower.
  - Every pin matched: manifest, set file, the RPC quorum 3/3 (attestor set `1c06adbb…`, large-claim
    threshold 100 BLCH) and the rebuilt L2 genesis `632e45ae…`.
  - The rebuild of 155,365 L1 blocks took 9.8 s, with about 110 MB peak.
  - There were no settlements yet, so nothing was signed.
- **Rebuild ceiling.** `produce reconstruct` refuses more than 1,000,000 L1 blocks
  (`MAX_L1_BLOCKS`), and `withdrawal-proof` scans at most 1,000,000 L2 blocks.
  - At 2,880 blocks a day, the L1 limit is reached around August 2027.
  - The daily `rebuild-check` halts with a clear reason before then. Raise the limit, or add a
    checkpointed rebuild, well before that date.
- **Settled-block cost.** `withdrawal-proof` re-reads every settled L2 block for each new withdrawal
  index. Leaves are cached in `state.json`, so each index is derived only once.
