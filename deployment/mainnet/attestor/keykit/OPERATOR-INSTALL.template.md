# Install attestor @INDEX@ (Bloch L2 mainnet, chain 700770)

- Attestor index: **@INDEX@**
- Attestor set: `@SET_HASH@` (3-of-5)
- Sealed key: `attestor-@INDEX@.sealed`, SHA-256 `@SEALED_SHA256@`
- Kit commit: `@KIT_COMMIT@`

Read `ONBOARDING.md` first: what an attestor is, host requirements, firewall, key rules, monitoring
and the reply you send at the end.

How to use this file:

- Commands run on the attestor host, as a normal user that can use `sudo`, unless a step says "on
  your computer". Run one command at a time, and stop at the first output that differs from what is
  described. Then send the coordinator the command and its full output.
- Never send anyone a passphrase or a `.sealed` file, and never type a passphrase anywhere except at a
  prompt that asks for it.
- Plan about two hours, mostly waiting at step 6. The transport bundle stays on the host until
  step 10, so finish steps 1 to 10 the same day.
- Paths like `kit/install-attestor.sh` and `artifacts` are relative: steps 3 to 9 run from inside the
  `operator-@INDEX@` directory.

## 1. Check the bundle and copy it to the host

You received `operator-@INDEX@.tar` over one channel, a passphrase over a second, and one line of
`PACKAGES.sha256` over a third. Keep the passphrase on paper for now.

On your computer, copy the tar to the host's home directory (replace `USER` and `HOST`):

```
scp operator-@INDEX@.tar USER@HOST:
```

On the host, in your home directory, create a file named `PACKAGES.sha256` that holds only the line
you received: it reads `<64 hex characters>  operator-@INDEX@.tar`, with two spaces. For example with
`nano PACKAGES.sha256`. Then:

```
sha256sum -c PACKAGES.sha256
```

It must print `operator-@INDEX@.tar: OK`. If it prints `FAILED`, or the line names another index,
stop and tell the coordinator: the file was changed or swapped.

```
tar -xf operator-@INDEX@.tar
```
```
cd operator-@INDEX@
```

## 2. Get the Linux artifacts

If the bundle has an `artifacts/` directory (`ls artifacts` lists `bloch-pos`,
`bloch-l2-native-follower`, `bloch-l2-produce-dev`, `mainnet.manifest`, `carryover.tsv.gz`,
`carryover.tsv.gz.sha256` and `SHA256SUMS`), there is nothing to do here. Otherwise copy those files
into `operator-@INDEX@/artifacts/` from the place the coordinator gives you. Their hashes are pinned
in `ARTIFACTS.sha256`, so the download source does not need to be trusted.

## 3. Check the bundle and the artifacts

```
./check-operator-bundle.sh --open
```

It checks every bundle file, the pinned set, your public key, every artifact (including the
follower `cdf5da5c…` and producer `e3f1a290…`), that this host can run them, and the sealed key
header. With `--open` it asks for the **transport passphrase** at `Sealed attestor key passphrase:`
and proves that the key opens and signs for index @INDEX@. Nothing is written.

It must end with `BUNDLE OK for attestor @INDEX@`. Fix any `WARNING` line (memory, disk, clock)
before you go on. A wrong passphrase prints `authentication failed`: nothing has changed, run the
command again. Any `FAIL` line: stop and send it to the coordinator.

## 4. Open the firewall

`ONBOARDING.md` section 2 has the commands. Allow SSH from your own address **before** you enable the
firewall, or you lock yourself out. Inbound TCP 8787 must be open to everyone, including in your
provider's own firewall panel if it has one. If your host cannot take an inbound port, stop and ask
the coordinator (`kit/README.md`, "Hosts with no inbound port", describes the alternative).

## 5. Install (nothing starts yet)

```
sudo kit/install-attestor.sh install --artifacts artifacts --index @INDEX@ --bundle attestor-@INDEX@.sealed --l1-rpc-url http://80.240.16.185:8080 --feed-port 8787
```

Type the transport passphrase once at `Sealed attestor key passphrase:`. It must print
`ok: sealed key opens and signs for attestor @INDEX@ of 3-of-5 set 1c06adbb…` and
`Installed attestor @INDEX@, NOT started.` The list of commands it prints after that is the same as
steps 6 to 8 below; follow this file.

If the passphrase was wrong, nothing was installed: run the same command again. If it says
`this host already has an attestor`, stop and ask the coordinator; do not purge anything.

The installer refuses binaries other than the published ones and pins all three in
`/etc/bloch-l2-attestor/config.json`. Do not edit that file's pins: the agent halts if a pin differs.

## 6. Start the follower and wait for its first replay

```
sudo systemctl enable --now bloch-l2-attestor-follower
```

The first replay downloads and verifies all of L1. It takes 60–90 minutes or more on two cores, and
longer as the chain grows. Until it finishes, `status.json` does not exist and the next command prints
`No such file or directory`. That is normal. Run it again every 15 minutes:

```
sudo python3 -c 'import json; s=json.load(open("/var/lib/bloch-l2-attestor-follower/status.json")); print(s["native_finalized_epoch"], s["l2_genesis"])'
```

It is ready when it prints an epoch number followed by a dictionary that contains `'finalized': True`.
To see that the follower is working while you wait:

```
sudo journalctl -u bloch-l2-attestor-follower -n 5 -o cat
```

## 7. Check

```
sudo systemd-run --pipe --wait -p User=bloch-l2-attestor -p LoadCredential=passphrase:/etc/bloch-l2-attestor/keystore.passphrase /usr/bin/python3 -I /opt/bloch/l2-attestor/attestor_agent.py check --config /etc/bloch-l2-attestor/config.json
```

This command uses the random host passphrase that the installer stored; it asks you for nothing.
Before the replay finishes it prints `check-not-ready`; wait and run it again. It must print
`check-ok` with `signer_index @INDEX@` and `set_hash 1c06adbb…`. Keep that line for your reply.

## 8. Start the feed and the agent

```
sudo systemctl enable --now bloch-l2-attestor-feed
```
```
sudo systemctl enable --now bloch-l2-attestor
```
```
sudo journalctl -u bloch-l2-attestor -o cat -n 20
```

Expect `started`, then `rebuild-check-ok`, then nothing or `waiting`, `awaiting-own-finality` or
`root-skipped`. Silence between events is normal: the agent logs only when something happens.

On **your computer** (not the host), check that the world reaches your feed:

```
curl -fsS http://YOUR_HOST_PUBLIC_IPV4:8787/healthz
```

It must print `ok`. If it times out, your firewall or your provider's firewall blocks 8787. Without the
feed your signatures reach nobody, and the agent itself cannot tell you. Fix this before you reply.

## 9. Re-seal your offline backup under a passphrase only you know

The key holder chose the transport passphrase, so they can still open `attestor-@INDEX@.sealed`.
Make your own backup copy that only you can open. First write a new passphrase of six or more random
words on paper. Do not reuse the transport passphrase or any passphrase you use elsewhere. Then, on
the host, inside `operator-@INDEX@`:

```
artifacts/bloch-pos l2-claim seal-key --sealed attestor-@INDEX@.sealed --attestors attestors.set --signer-index @INDEX@ --out attestor-@INDEX@.operator.sealed
```

It asks for the **transport** passphrase at `Sealed attestor key passphrase:`, then for **your new**
passphrase twice (`New sealed-key passphrase:`, `Repeat passphrase:`). Prove the new file opens with
your new passphrase:

```
artifacts/bloch-pos l2-claim key-check --sealed attestor-@INDEX@.operator.sealed --attestors attestors.set --signer-index @INDEX@
```

It must print `ok: sealed key opens and signs for attestor @INDEX@ …`. Note its hash:

```
sha256sum attestor-@INDEX@.operator.sealed
```

On **your computer**, fetch it and write it to both USB drives (replace `USER`, `HOST`, and the drive
paths; on Linux use `sha256sum` instead of `shasum -a 256`):

```
scp USER@HOST:operator-@INDEX@/attestor-@INDEX@.operator.sealed .
```
```
cp attestor-@INDEX@.operator.sealed /Volumes/USB1/
```
```
cp attestor-@INDEX@.operator.sealed /Volumes/USB2/
```
```
shasum -a 256 /Volumes/USB1/attestor-@INDEX@.operator.sealed /Volumes/USB2/attestor-@INDEX@.operator.sealed
```

Both hashes must equal the host's. Then delete the copy on your computer, and empty the trash:

```
rm attestor-@INDEX@.operator.sealed
```

Do not put this file in a cloud-synced folder (iCloud Desktop/Documents, Dropbox, OneDrive, Google
Drive) even for a moment. Keep the two drives in two different places, and the paper with your
passphrase in a third. Forgetting the passphrase loses your backup, and nobody can recover it.

Only then, on the host, delete the re-sealed file there:

```
shred -u attestor-@INDEX@.operator.sealed
```

## 10. Delete every copy of the transport bundle

From now on the host holds only its own re-sealed key (`/etc/bloch-l2-attestor/attestor.sealed`) and
the random host passphrase (root only). Your backup is the file from step 9. The transport bundle can
still be opened by the key holder, so remove it everywhere. On the host:

```
cd ..
```
```
shred -u operator-@INDEX@/attestor-@INDEX@.sealed operator-@INDEX@.tar
```

Keep the rest of the `operator-@INDEX@` directory on the host: it holds no secret, and you need its
`kit/` and `artifacts/` to reinstall (step 12).

On your computer, delete `operator-@INDEX@.tar` and anything you extracted from it, also in Downloads,
email attachments, chat downloads and USB drives, then empty the trash. Destroy the paper with the
**transport** passphrase. Keep only the paper with **your own** passphrase.

## 11. Reply

Send the coordinator the reply in `ONBOARDING.md` section 6. It holds no secret. The key holder then
destroys their own copies of bundle @INDEX@.

## 12. If the host is lost or must be replaced

You need: a new host prepared as in `ONBOARDING.md` (sections 1 and 2), one USB drive with
`attestor-@INDEX@.operator.sealed`, your own passphrase, and the `kit/` and `artifacts/` directories
(from the old host if you still have it; otherwise ask the coordinator for the current bundle without
key, and check it with them). Tell the coordinator first, and pause the old host if it still runs:

```
sudo touch /etc/bloch-l2-attestor/PAUSE
```

On the new host, put the re-sealed file next to `kit/` and `artifacts/`, run step 4, then step 5 with
`--bundle attestor-@INDEX@.operator.sealed`. At `Sealed attestor key passphrase:` type **your own**
passphrase. Then steps 6 to 8, delete the copy of the file you brought to the new host with
`shred -u`, and send the reply. Then retire the old host: `sudo kit/install-attestor.sh rollback --purge-key` on it
(only once the new host shows `check-ok`). Never keep the key on two hosts: each copy is one more place to steal it from.
