# Install attestor @INDEX@ (Bloch L2 mainnet, chain 700770)

- Attestor index: **@INDEX@**
- Attestor set: `@SET_HASH@` (3-of-5)
- Sealed key: `attestor-@INDEX@.sealed`, SHA-256 `@SEALED_SHA256@`
- Kit commit: `@KIT_COMMIT@`

Read `ONBOARDING.md` first: host requirements, firewall, monitoring, the fork schedule and the reply
you send at the end. Every command below runs on the attestor host, from a normal user that can use
`sudo`. Run one command at a time, and stop at the first output that differs from what is described.
Plan about two hours: most of it is waiting at step 6. If anything refuses, send the coordinator the
output. Never send a passphrase or the sealed key.

## 1. Check the bundle you received

You received `operator-@INDEX@.tar` over one channel and its `PACKAGES.sha256` line over another.
In the directory that holds the tar, put that single line in a file named `PACKAGES.sha256`, then run:

```
sha256sum -c PACKAGES.sha256
```

It must print `operator-@INDEX@.tar: OK`. If it does not, stop and tell the coordinator.

```
tar -xf operator-@INDEX@.tar
```
```
cd operator-@INDEX@
```

## 2. Get the Linux artifacts

If the bundle has an `artifacts/` directory, there is nothing to do here. Otherwise copy the five files named in
`ARTIFACTS.sha256`, plus `carryover.tsv.gz.sha256`, into `operator-@INDEX@/artifacts/` from the place
the coordinator gives you. Their hashes are pinned in `ARTIFACTS.sha256`, so the source does not need
to be trusted.

## 3. Check the bundle and the artifacts

```
./check-operator-bundle.sh --open
```

It checks every bundle file, the pinned set, your public key, every artifact (including the
follower `cdf5da5c…` and producer `e3f1a290…`), that the host can run them, and the sealed key
header. With `--open` it asks for the **transport passphrase** (it arrived on its own channel, not
with the bundle) and proves the key opens and signs for index @INDEX@. It must end with
`BUNDLE OK for attestor @INDEX@`. Fix any `WARNING` line before you go on. A wrong passphrase prints
`authentication failed`: nothing has changed, run the command again.

## 4. Open the firewall

ONBOARDING.md section 2 has the commands. Allow SSH from your own address **before** you enable the
firewall, or you lock yourself out. Inbound TCP 8787 must be open to everyone. If your provider has
its own firewall panel, open 8787 there too. If your host cannot take an inbound port, see "Hosts with
no inbound port" in `kit/README.md`.

## 5. Install (nothing starts yet)

This prepares a read-only endpoint on TCP 8787 that serves only your signatures. No drop and no
token are involved.

```
sudo kit/install-attestor.sh install --artifacts artifacts --index @INDEX@ --bundle attestor-@INDEX@.sealed --l1-rpc-url http://80.240.16.185:8080 --feed-port 8787
```

Type the transport passphrase once at `Sealed attestor key passphrase:`. It must print
`ok: sealed key opens and signs for attestor @INDEX@ of 3-of-5 set 1c06adbb…` and
`Installed attestor @INDEX@, NOT started.` If the passphrase was wrong, nothing was installed: run the
same command again. Do not edit `config.json`: the agent halts if a pin differs.

The installer refuses binaries other than the published ones and pins all three in `config.json`.

## 6. Start the follower and wait for its first replay

```
sudo systemctl enable --now bloch-l2-attestor-follower
```

The first replay takes 60–90 minutes on two cores, and more as the chain grows. Until it finishes
`status.json` does not exist, and the next command prints `No such file`. That is normal. Run it again
every 15 minutes until it shows `'finalized': True`:

```
sudo python3 -c 'import json; s=json.load(open("/var/lib/bloch-l2-attestor-follower/status.json")); print(s["native_finalized_epoch"], s["l2_genesis"])'
```

## 7. Check

```
sudo systemd-run --pipe --wait -p User=bloch-l2-attestor -p LoadCredential=passphrase:/etc/bloch-l2-attestor/keystore.passphrase /usr/bin/python3 -I /opt/bloch/l2-attestor/attestor_agent.py check --config /etc/bloch-l2-attestor/config.json
```

Before the replay finishes this prints `check-not-ready`; wait and run it again. It must print
`check-ok` with `signer_index @INDEX@` and `set_hash 1c06adbb…`.

## 8. Start the feed and the agent

```
sudo systemctl enable --now bloch-l2-attestor-feed
```
```
sudo systemctl enable --now bloch-l2-attestor
```
```
journalctl -u bloch-l2-attestor -o cat -n 20
```

Expect `started`, then `rebuild-check-ok`, then nothing or `waiting`, `awaiting-own-finality` or
`root-skipped`. Silence between events is normal: the agent logs only when something happens.

From **another machine**, not this host, check that the world reaches your feed:

```
curl -fsS http://YOUR_PUBLIC_IPV4:8787/healthz
```

It must print `ok`. If it times out, your firewall or your provider's firewall blocks 8787. Without the
feed your signatures reach nobody, and the agent itself cannot tell you. Fix this before you reply.

## 9. Re-seal your offline backup under a passphrase only you know

The key holder chose the transport passphrase, so they can still open `attestor-@INDEX@.sealed`.
Re-seal your backup copy under your own passphrase so that, after the handoff, nobody but you can
open your key. Do this on the host (or any Linux machine with the same `bloch-pos`):

```
artifacts/bloch-pos l2-claim seal-key --sealed attestor-@INDEX@.sealed --attestors attestors.set --signer-index @INDEX@ --out attestor-@INDEX@.operator.sealed
```

It asks for the transport passphrase at `Sealed attestor key passphrase:`, then for your new
passphrase twice (`New sealed-key passphrase:`, `Repeat passphrase:`). Prove the new file opens:

```
artifacts/bloch-pos l2-claim key-check --sealed attestor-@INDEX@.operator.sealed --attestors attestors.set --signer-index @INDEX@
```

Copy `attestor-@INDEX@.operator.sealed` to your offline media (two USB drives in different places).
A rented server has no USB port: fetch the file to your own computer with `scp` first, write it to
both drives, delete it from that computer, and compare `sha256sum` of both drives with the file on the
host. Write your passphrase on paper and keep it apart from the drives. Forgetting it loses your backup,
and nobody can recover it. Only then delete the file from the host:

```
shred -u attestor-@INDEX@.operator.sealed
```

Tell the coordinator you re-sealed (no passphrase, no file). The key holder can then destroy their
own copies of bundle @INDEX@.

## 10. Remove the bundle from the host

The host now holds only the re-sealed key (`/etc/bloch-l2-attestor/attestor.sealed`) and its random
host passphrase (root, 0400). Delete what you brought:

```
cd ..
```
```
shred -u operator-@INDEX@/attestor-@INDEX@.sealed operator-@INDEX@.tar
```

Your offline backup is now `attestor-@INDEX@.operator.sealed` (step 9) plus the passphrase only you
know. Keep them in different places.

## 11. Reply

Send the coordinator the reply in `ONBOARDING.md` section 6 (no secret in it).
