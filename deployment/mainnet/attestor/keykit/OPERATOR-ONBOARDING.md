# Bloch L2 mainnet attestor: operator onboarding

Read this whole file before you touch the host. Then follow `INSTALL.md`, which is in the same
directory and has your attestor index filled in.

## 0. What this is, in five lines

- **Bloch L1** is the base proof-of-stake chain. **Bloch L2** (chain id 700770) is a rollup that
  settles on it. Money moves from L2 back to L1 by a **withdrawal claim** on L1.
- A claim of **100 BLCH or more** needs signatures from **three of five attestors**. You are one of
  the five. Your signature says "this withdrawal root is final on L1 and my own rebuild of the L2
  gives exactly this root".
- The five public keys are fixed in L1 consensus (attestor set
  `1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b`, 3-of-5, hybrid ML-DSA-65 +
  Falcon-1024 keys). Replacing a key needs an L1 hard fork, so **a lost or leaked key is expensive
  for everyone**.
- Your host runs an **agent** that follows L1 by itself, rebuilds the L2 from L1 data, and signs on
  its own. It sends no transactions and moves no funds. You keep it running, watch its alerts and
  install upgrades when told.
- Your signatures are public. A small read-only web server on your host (the **feed**, TCP 8787)
  serves them to whoever assembles a claim.

Words used below:

| Word | Meaning |
| --- | --- |
| coordinator | The person who sent you this bundle. Their contact and the operators' group are in the message that came with it. |
| key holder | The person who created and sealed the five keys. Today this is the coordinator. |
| bundle | `operator-I.tar`. It holds your key, **sealed** (encrypted) under a transport passphrase. |
| transport passphrase | The passphrase the key holder chose for your bundle. It reaches you on a separate channel. |
| your own passphrase | A new passphrase that only you know, for your offline backup (`INSTALL.md` step 9). |
| follower | The program that downloads L1 blocks and verifies them itself. Its output is `status.json`. |
| epoch | The L1 finality unit: 960 seconds (16 minutes). |

## 1. Host requirements

Use a host that is **only** your attestor. It must not be a Bloch validator, the L2 settler, another
operator's attestor, or a machine you share with anyone else. Do not run other services on it.

| Item | Minimum | Recommended |
| --- | --- | --- |
| CPU | 2 dedicated x86_64 cores | 4 dedicated cores |
| RAM | 8 GB | 16 GB |
| Disk | 80 GB SSD | 160 GB NVMe SSD |
| OS | Ubuntu 24.04 LTS, x86_64 | same, fully patched, unattended security upgrades |
| Python | `/usr/bin/python3` (3.12 on 24.04), standard library only | – |
| Network | outbound IPv4 to the three L1 RPCs below, one inbound port for the feed | a static public IPv4 |
| Access | a normal user with `sudo`, over SSH with a key | your provider's web console also works (you need it if the firewall locks you out) |

Why these numbers:

- **OS.** The follower and producer binaries need glibc 2.38 or newer. Ubuntu 22.04 and Debian 12 are
  too old. Use Ubuntu 24.04 LTS on x86_64; ARM is not supported.
- **RAM and CPU.** The follower is capped at 6 GB of memory and 2 CPUs. The agent's rebuild of the L2
  peaked at about 110 MB.
- **Disk.** The follower's copy of L1 was 3.3 GB at about 181,000 L1 blocks. It grows by about 50 MB a
  day (2,880 blocks a day), so about 20 GB a year.
- **Restart time.** After any restart of the follower, it re-verifies all of L1 history. That took
  about one hour at 181,000 blocks and grows with the chain. While it runs, the agent logs `waiting`
  and cannot sign. Plan reboots and maintenance around it, and never restart two attestors at once.

You also need, on your own computer: two USB drives for your offline backup, a way to copy files to
and from the host (`scp`), and paper.

## 2. Ports and firewall

Inbound:

- **TCP 8787, open to everyone**, for the feed (`bloch-l2-attestor-feed`). It serves only your public
  signatures, accepts GET and HEAD only, and holds no key or passphrase. The signing agent itself has
  no network listener.
- **TCP 22 (SSH), only from your own admin addresses.**
- Nothing else.

Outbound:

| Destination | Port | Used by |
| --- | --- | --- |
| `80.240.16.185`, `199.247.22.8`, `45.77.67.251` | TCP 8080 (HTTP) | the agent (it needs 2 of these 3 to agree) |
| the `--l1-rpc-url` host (`80.240.16.185` in `INSTALL.md`) | TCP 8080 | the follower |
| Ubuntu mirrors, NTP | 80/443, UDP 123 | the OS |

The installer also restricts the services themselves to these addresses. Keep the host clock in sync:
`timedatectl` must show `System clock synchronized: yes`.

Example with `ufw`. Run the SSH rule **before** `ufw enable`, or you lock yourself out:

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

`YOUR_ADMIN_IP` is the public address you connect from (search "what is my IP" on your own
computer). If it changes later, you lose SSH until you use your provider's web console, so check that
the console works first. After `ufw enable`, open a **second** SSH session from your computer to
confirm SSH still works before you close the first one. Many providers also have a firewall panel of
their own: open 8787 there too.

## 3. Key handling rules

These rules exist because one leaked key brings an attacker one third of the way to signing any
large withdrawal, and one lost key cannot be replaced without a hard fork.

- You receive three things over **three different channels**: the bundle `operator-I.tar`, the
  transport passphrase, and one hash line from `PACKAGES.sha256`. If two of them arrive together,
  stop and tell the coordinator.
- **Never** put the bundle and a passphrase in the same place: not the same message, cloud drive,
  password-manager entry, notes file or photo.
- **Never** type a passphrase into a command line, a file on the host, a chat, or an email. Type it
  only at a prompt that asks for it (`Sealed attestor key passphrase:`, `New sealed-key passphrase:`,
  `Repeat passphrase:`). It is not echoed; that is normal.
- **Never** upload the bundle to a cloud drive or file-sharing link. Copy it with `scp` from your
  computer straight to the host.
- **Never** send a passphrase or a `.sealed` file to anyone, including the coordinator and the other
  attestors. Nobody will ever ask you for them. Treat any such request as an attack.
- The installer re-seals your key under a random host passphrase that only root can read. The
  transport passphrase is not stored on the host.
- The key holder knows the transport passphrase. So, after `check-ok`, you re-seal your **offline
  backup** under your own passphrase (`INSTALL.md` step 9). From then on your backup is
  `attestor-I.operator.sealed` on two USB drives, plus your own passphrase on paper, kept in a third
  place. **The transport bundle is not your backup**: after step 9, delete every copy of
  `operator-I.tar` and `attestor-I.sealed` you made (host, laptop, Downloads folder, USB drives)
  (`INSTALL.md` step 10).
- If you forget your own passphrase and lose the host, your key is gone for good. Test that you can
  read your paper before you delete anything.
- If you think your key may be exposed (host broken into, backup **and** passphrase lost together),
  stop signing at once and tell the coordinator:

```
sudo touch /etc/bloch-l2-attestor/PAUSE
```

## 4. Monitoring

The agent logs one JSON line per event to the system journal. Check these every day, or wire them
into your own monitoring. They need `sudo` because the journal and the status file belong to system
users.

```
sudo journalctl -u bloch-l2-attestor -o cat --since -24h | grep -E '"(halt|held|refused-[a-z-]+|publish-failed|alert-failed)"'
```
```
systemctl is-active bloch-l2-attestor bloch-l2-attestor-follower bloch-l2-attestor-feed
```
```
curl -fsS http://127.0.0.1:8787/healthz
```
```
sudo python3 -c 'import json, time; s=json.load(open("/var/lib/bloch-l2-attestor-follower/status.json")); print(s["native_finalized_epoch"], s["verified_blocks"], int(time.time() - s["written_at_unix"]), "s old")'
```

What healthy looks like:

- `systemctl is-active` prints `active` three times, and the feed prints `ok`.
- The first number of the last command (`native_finalized_epoch`) increases by one about every 16
  minutes, and the status is less than a few minutes old.
- The agent is mostly silent. It logs `waiting`, `awaiting-own-finality`, `root-skipped` or `signed`
  when they apply. A `rebuild-check-ok` line appears at start and once a day: no such line for more than
  a day means the agent is not working.

Act on these:

| Event | What to do |
| --- | --- |
| `halt` (the agent stops, exit 3) | Read the `reason`. Do not edit pins or hashes to make it pass. Send the line to the coordinator. |
| `held` | A withdrawal above the per-withdrawal or daily limit. Do not approve it on your own. Send the alert line to the coordinator and wait for their written answer. To approve, add the printed `INDEX LEAF` line, unchanged, to `/etc/bloch-l2-attestor/approvals.txt` (with `sudo`); the agent reads it on its next cycle. |
| `refused-root-not-on-own-chain`, `refused-rebuild-differs` | Do **not** override. Tell the coordinator and the operators' group. It can be an RPC or settler fault, or an attack. |
| `systemctl is-active` says `failed` after a `halt` | The unit does not restart by itself, on purpose. Only after the coordinator has answered: `sudo systemctl restart bloch-l2-attestor`. |
| `publish-failed` | Only with an optional push target (see `kit/README.md`). The agent retries; your feed still serves the signature. |
| `native_finalized_epoch` stuck for more than 1 hour | Look at the follower: `sudo journalctl -u bloch-l2-attestor-follower -n 50`, and send it to the coordinator. |

**Alerts to your phone or email.** The agent can run a command on each event (`alert_command` in
`/etc/bloch-l2-attestor/config.json`). That command runs inside the agent's sandbox, which can reach
only the L1 RPCs, so it cannot send mail or call a web hook itself. Use it to write to a local file,
and ship alerts from outside (for example a cron job of your own that runs the `journalctl` line
above and mails you). Do not change any other field of `config.json`: the agent halts if a pin
differs.

## 5. L1 upgrades and hard forks

L1 epoch E starts at Unix time `1786656679 + E × 960`.

These L1 hard forks are **already past**. A new install from this bundle crosses them during its
first replay, and you have nothing to do for them:

| Gate | Epoch | Time (UTC) |
| --- | --- | --- |
| HF1 | 7180 / 7186 | 2026-11-01 16:11 / 17:47 |
| HF2 | 7270 | 2026-11-02 16:11 |

These are still ahead (check the date you install):

| Gate | Epoch | Time (UTC) | What you do |
| --- | --- | --- | --- |
| HF3 | 7360 | Tue 2026-11-03 16:11 | Nothing to install. If you are installed by then, check the epoch passes 7360. If you install later, skip this row. |
| KES enforcement | 8620 | Tue 2026-11-17 16:11 | Nothing to install. Check the epoch passes 8620. |
| Next L2 program upgrade | announced by the coordinator | about December 2026 | You will need a new follower and producer before a deadline. The coordinator sends the new hashes and an upgrade command. A host that does not upgrade stops signing at that point. |

At each gate:

1. Do not restart or upgrade anything in the two hours before the gate. A follower restart costs at
   least an hour of re-verification.
2. About one hour after the gate, run the `status.json` command of section 4 twice, 16 or more minutes
   apart. The epoch must be past the gate and increasing.
3. If the follower stops advancing, or the agent logs `halt`, pause signing, keep the logs and contact
   the coordinator. Do not roll back to older binaries.

```
sudo touch /etc/bloch-l2-attestor/PAUSE
```

4. Post "attestor I: past epoch N" in the operators' group.

**Binary upgrades.** New binary hashes always come from the coordinator over one channel and are
confirmed over a second one. Upgrade **one host at a time**, waiting until the previous operator
reports success, so that at least three attestors stay up. Each upgrade takes the host off for
about 75 minutes (the follower's replay plus one finalized epoch). The coordinator sends the exact
command; the installer refuses binaries whose hashes it does not expect.

## 6. Your reply to the coordinator

When `INSTALL.md` is done up to step 10, reply with this filled in. It contains **no secret**.

```
attestor index: I
operator name and on-call contact (Signal/phone):
host public IPv4:
host provider and region:
feed URL: http://<public IPv4>:8787
curl -fsS http://<public IPv4>:8787/healthz from another machine printed: ok / other
bundle line I checked (sha256 of operator-I.tar):
check-ok line (signer_index, set_hash):
installed binaries (output of: sha256sum /opt/bloch/l2-attestor/bloch-*):
native_finalized_epoch, two readings 16+ minutes apart:
offline backup re-sealed under my own passphrase (INSTALL.md step 9): yes/no
both USB copies checked against the host's sha256: yes/no
every copy of operator-I.tar and attestor-I.sealed deleted (INSTALL.md step 10): yes/no
where my two offline backups are kept (kind of place only, no address):
```

The list of the five feed URLs is public, so that claimants and monitors can collect signatures. The
feed must not require a login; signatures are public data over public roots.
