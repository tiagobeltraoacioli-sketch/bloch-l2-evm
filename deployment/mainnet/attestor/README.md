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
| `install-attestor.sh` | `install`, `rollback [--purge-key]` and `status` on an operator host. |
| `systemd/bloch-l2-attestor.service` | The hardened agent unit: no listener, `IPAddressDeny=any` plus an allow-list, `LoadCredential`. |
| `systemd/bloch-l2-attestor-feed.service` | The read-only feed (`--feed-port`): the agent's outbox only, no credential. |
| `systemd/bloch-l2-attestor-follower.service` | The agent's own native follower (FFG replay from Genesis-4). |
| `keykit/` | Key custody for the key holder: seal, verify, package, backup-check, shred, release (`make-operator-bundles.sh`, `KEY-HANDOFF-CHECKLIST.md`); operator side: `check-operator-bundle.sh`, `OPERATOR-ONBOARDING.md`, `OPERATOR-INSTALL.template.md`, pins `operator-pins-v2.sha256`. |
| `public/` | The pinned `attestors.set` and the five public keys. |
| `tests/` | `python3 -m unittest -v test_attestor` (needs `BLOCH_POS` and `MAINNET_MANIFEST`). |
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

The host must not be a mainnet validator host or the settler. It needs 2 cores, 8 GB RAM and
40 GB disk. The follower's copy of L1 was 2.8 GB at 155k blocks and keeps growing. All commands run as root. Nothing below sends a transaction.

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
- After the first command, wait for the follower's first replay (about 30–60 min).
- `check` prints `check-ok`. It covers the pins, opening the key, the follower, the RPC quorum and
  the rebuild check.
- When everything works, delete the bundle copy from the host. The operator keeps the offline backup.

Rehearsal without root or systemd: `install … --prefix /scratch/host-I` installs every file under
that directory as the invoking user, writes the units to `/scratch/host-I/systemd` without loading
them, and prints a `key-check` command instead of the systemd steps. `--rehearsal-set FILE` (only
with `--prefix`) accepts a throwaway attestor set. `tests/rehearse_owner_flow.sh` runs the whole
owner flow this way with throwaway keys (seal, verify, install for 3 operators, check, sign a
synthetic root, aggregate 3-of-5, native verify, shred). Rehearsed on 2026-10-19 on 209.250.236.240.

To roll back, run `sudo ./install-attestor.sh rollback`. This removes the units and keeps the state
and the key. `--purge-key` also shreds the host key and passphrase.

## Claimant (≥ 100 BLCH)

1. Generate the withdrawal proof against `withdrawals.matured_large`.
2. Run:

   ```
   aggregate_attestation.py --proof proof.json --source https://drop.example/attest --out att/ \
       --bloch-pos bloch-pos --genesis mainnet.manifest --attestors attestors.set \
       --rpc http://80.240.16.185:8080 --rpc http://199.247.22.8:8080 --rpc http://45.77.67.251:8080
   ```

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
| `publish-failed` | The drop is unreachable. The agent retries every cycle. The outbox still holds the partial. |

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
