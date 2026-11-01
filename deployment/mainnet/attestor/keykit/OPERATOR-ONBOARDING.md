# Bloch L2 mainnet attestor: operator onboarding

You are one of five attestors for Bloch L2 mainnet (chain id 700770). The attestor set is
`1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b`, a 3-of-5 set of hybrid
ML-DSA-65 + Falcon-1024 keys pinned in L1 consensus.

An L2→L1 withdrawal claim of 100 BLCH or more needs signatures from three of the five attestors.
Your host runs an agent that rebuilds the L2 from L1 data by itself. It signs a withdrawal root only
when that root is final on its own L1 replay and its own rebuild gives the same root. The agent has
no network listener and sends no transactions.

Your bundle (`operator-I.tar`) holds your sealed key, the public set, the pins, the kit and
`INSTALL.md` with your index filled in. Follow `INSTALL.md`. This file lists what you must prepare
and what you must reply.

## 1. Host requirements

Use a host that is **only** your attestor. It must not be a Bloch validator, the L2 settler, another
operator's attestor, or a machine you share with anyone else.

| Item | Minimum | Recommended |
| --- | --- | --- |
| CPU | 2 dedicated x86_64 cores | 4 dedicated cores |
| RAM | 8 GB | 16 GB |
| Disk | 80 GB SSD | 160 GB NVMe SSD |
| OS | Ubuntu 24.04 LTS, x86_64 | same, fully patched, unattended security upgrades |
| Python | `/usr/bin/python3` (3.12 on 24.04), standard library only | – |
| Network | outbound IPv4 to the L1 RPCs, one inbound port for the read-only feed | a static public IPv4 |

Why these numbers:

- **OS.** The follower and producer binaries need glibc 2.38 or newer. Ubuntu 22.04 and Debian 12 are
  too old. Use Ubuntu 24.04 LTS on x86_64; ARM is not supported.
- **RAM and CPU.** The follower unit is capped at 6 GB of memory and 2 CPUs (`MemoryMax=6G`,
  `CPUQuota=200%`). The agent's rebuild of the L2 peaked at about 110 MB.
- **Disk.** The follower's copy of L1 was 3.3 GB at about 181,000 L1 blocks. It grows by about 50 MB
  a day (2,880 blocks a day), so about 20 GB a year.
- **Restart time.** After any restart the follower re-verifies all retained L1 history. This took
  about 60 minutes at 181,000 blocks (report 02: 62 minutes, then up to 16 for the next finalized epoch),
  and it grows with the chain. Plan maintenance around it. While it runs the agent logs `waiting`.

## 2. Ports and firewall

The attestor needs **one inbound port**: TCP 8787, open to everyone, for the read-only feed
(`bloch-l2-attestor-feed`). It serves only your public signatures, accepts GET and HEAD only, holds no
credential and runs apart from the agent, which still has no listener. Also allow inbound SSH (TCP 22),
only from your own admin addresses. Deny everything else inbound.

Outbound:

| Destination | Port | Used by |
| --- | --- | --- |
| `80.240.16.185`, `199.247.22.8`, `45.77.67.251` | TCP 8080 (HTTP) | the agent (2-of-3 RPC quorum) |
| the `--l1-rpc-url` host (default `80.240.16.185`) | TCP 8080 | the follower |
| Ubuntu mirrors, NTP | 80/443, UDP 123 | the OS |

The systemd units already deny all other addresses (`IPAddressDeny=any` with an allow-list that the
installer writes). Keep the host clock in sync (`timedatectl` must show `System clock synchronized: yes`).

Example with `ufw`:

```
sudo ufw default deny incoming
```
```
sudo ufw default allow outgoing
```
```
sudo ufw allow from YOUR_ADMIN_IP to any port 22 proto tcp
```
```
sudo ufw allow 8787/tcp
```
```
sudo ufw enable
```

`YOUR_ADMIN_IP` is the public address you connect from. If it changes, you lose SSH until you use your
provider's console, so check that console works first. Then, from another machine, confirm that SSH still
connects. Many providers also have a firewall panel of their own: open 8787 there too.

## 3. Key handling rules

- You receive three things over **three different channels**: the bundle file `operator-I.tar`, the
  transport passphrase, and the line of `PACKAGES.sha256` for your bundle. Never accept two of them
  over the same channel.
- The installer re-seals your key under a random host passphrase that only root can read. The
  transport passphrase is not stored on the host.
- The key holder chose the transport passphrase. After `check-ok`, re-seal your offline backup under
  a passphrase only you know (`INSTALL.md` step 8), keep it on two offline media, and delete every
  bundle copy from the host. Your re-sealed backup and your own passphrase, kept apart, are your
  recovery path if the host is lost.
- Never put the bundle and its passphrase in the same place, cloud drive, password manager entry or
  message. Never send either to another attestor.
- If you think your bundle **and** its passphrase are both exposed, run
  `sudo touch /etc/bloch-l2-attestor/PAUSE` and tell the coordinator at once.

## 4. Monitoring

The agent logs one JSON line per event to the journal. Check these every day, or wire them into your
own monitoring:

```
journalctl -u bloch-l2-attestor -o cat --since -24h | grep -E '"(halt|held|refused-[a-z-]+|publish-failed|alert-failed)"'
```
```
systemctl is-active bloch-l2-attestor bloch-l2-attestor-follower bloch-l2-attestor-feed
```
```
curl -fsS http://127.0.0.1:8787/healthz
```
```
python3 -c 'import json; s=json.load(open("/var/lib/bloch-l2-attestor-follower/status.json")); import time; print(s["native_finalized_epoch"], s["verified_blocks"], int(time.time() - s["written_at_unix"]), "s old")'
```

What healthy looks like:

- All three units are `active`, and the feed prints `ok`.
- `native_finalized_epoch` increases by one about every 16 minutes (one L1 epoch is 960 s).
- The agent is mostly silent. It logs `waiting`, `awaiting-own-finality`, `root-skipped` or `signed`
  when they apply. A `rebuild-check-ok` line appears at start and once a day: no such line for more than
  a day means the agent is not working.

Act on these:

| Event | What to do |
| --- | --- |
| `halt` (the agent stops, exit 3) | Read the `reason`. Fix the pin or binary it names. Do not edit pins to make it pass. Ask the coordinator. |
| `held` | A large or over-cap withdrawal. Check it. If it is legitimate, add the printed `INDEX LEAF` line to `/etc/bloch-l2-attestor/approvals.txt`. |
| `refused-root-not-on-own-chain`, `refused-rebuild-differs` | Do **not** override. Compare with the other operators and tell the coordinator. |
| `systemctl is-active` says `failed` after a `halt` | The unit does not restart by itself, on purpose. After the coordinator has answered: `sudo systemctl restart bloch-l2-attestor`. |
| `publish-failed` | Only with an optional push target (see `kit/README.md`): it is unreachable. The agent retries; the partial stays in `/var/lib/bloch-l2-attestor/outbox`, which the feed serves. |
| `native_finalized_epoch` stuck for more than 1 hour | Check the follower journal: `journalctl -u bloch-l2-attestor-follower -n 50`. |

`alert_command` in `config.json` runs inside the agent's sandbox, which can only reach the allow-listed
addresses. Use it to write to a local file or the local mail spool, and ship alerts from outside the
unit (for example a cron job of your own that reads the journal).

## 5. L1 hard forks: what to do at each one

L1 epoch E starts at Unix time `1786656679 + E × 960`.

| Gate | Epoch | Start (UTC) | What you do |
| --- | --- | --- | --- |
| Binaries | 7178 | Sun 2026-11-01 15:39 | Your host must run the follower `c18752fd…` and producer `fb0d5313…` (pinned in `ARTIFACTS.sha256`). A new install from this bundle has them. If you install after a date below, skip that row: the first replay crosses it for you. |
| HF1 | 7180 / 7186 | Sun 2026-11-01 16:11 / 17:47 | Watch `native_finalized_epoch` pass 7186 and keep increasing. No action if it does. |
| HF2 | 7270 | Mon 2026-11-02 16:11 | Same check: the epoch passes 7270. |
| HF3 | 7360 | Tue 2026-11-03 16:11 | Same check: the epoch passes 7360. |
| KES enforcement | 8620 | Tue 2026-11-17 16:11 | Same check: the epoch passes 8620. |

At each gate:

1. Do not restart or upgrade anything in the two hours before the gate. A restart costs at least an
   hour of re-verification.
2. About one hour after the gate, run the `status.json` command above twice, 16+ minutes apart. The
   epoch must be past the gate and increasing.
3. If the follower stops advancing, or the agent logs `halt`, run
   `sudo touch /etc/bloch-l2-attestor/PAUSE`, keep the logs and contact the coordinator. Do not roll
   back to older binaries after epoch 7180: they cannot follow the forked chain.
4. Post "attestor I: past epoch N, finalized X" in the operators' channel.

Any later binary change arrives the same way: new hashes from the coordinator over one channel,
confirmed over a second channel, installed one host at a time so that at least three attestors stay
up.

## 6. Your reply to the coordinator

When `check-ok` passes and the agent is running, reply with this filled in. It contains **no secret**.

```
attestor index: I
operator name and on-call contact (Signal/phone):
host public IPv4 (egress address used for the RPCs):
host provider and region:
publication endpoint: the base URL of your feed, normally http://<public IPv4>:8787. The check is
  curl -fsS http://<public IPv4>:8787/healthz (from another host: it must print ok)
bundle hash I checked (sha256 of operator-I.tar):
check-ok line (signer_index, set_hash):
installed binaries (sha256sum /opt/bloch/l2-attestor/*):
native_finalized_epoch, two readings 16+ minutes apart:
offline backup re-sealed under my own passphrase (INSTALL.md step 8): yes/no
where my two offline backups are kept (places only, no details):
```

The list of the five endpoints is public, so that claimants and monitors can collect partials. The
endpoint must not require a login to read; partials are public signatures over public roots.
