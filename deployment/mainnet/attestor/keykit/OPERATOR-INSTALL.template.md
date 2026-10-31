# Install attestor @INDEX@ (Bloch L2 mainnet, chain 700770)

- Attestor index: **@INDEX@**
- Attestor set: `@SET_HASH@` (3-of-5)
- Sealed key: `attestor-@INDEX@.sealed`, SHA-256 `@SEALED_SHA256@`
- Kit commit: `@KIT_COMMIT@`

Read `ONBOARDING.md` first: host requirements, firewall, monitoring, the fork schedule and the reply
you send at the end. Every command below runs on the attestor host. Run one command at a time.

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

If the bundle has an `artifacts/` directory, use it. Otherwise copy the five files named in
`ARTIFACTS.sha256`, plus `carryover.tsv.gz.sha256`, into `operator-@INDEX@/artifacts/` from the place
the coordinator gives you. Their hashes are pinned in `ARTIFACTS.sha256`, so the source does not need
to be trusted.

## 3. Check the bundle and the artifacts

```
./check-operator-bundle.sh --open
```

It checks every bundle file, the pinned set, your public key, every artifact (including the v2
follower `c18752fd…` and producer `fb0d5313…`) and the sealed key header. With `--open` it asks for
the **transport passphrase** (received over the third channel) and proves the key opens and signs
for index @INDEX@. It must end with `BUNDLE OK for attestor @INDEX@`.

## 4. Install (nothing starts yet)

This prepares a read-only endpoint on TCP 8787 that serves only your signatures. No drop and no
token are involved. If your host cannot take an inbound port, see "Hosts with no inbound port" in
`kit/README.md`.

```
sudo kit/install-attestor.sh install --artifacts artifacts --index @INDEX@ --bundle attestor-@INDEX@.sealed --l1-rpc-url http://80.240.16.185:8080 --feed-port 8787
```

Type the transport passphrase once at `Sealed attestor key passphrase:`. It must print
`ok: sealed key opens and signs for attestor @INDEX@ of 3-of-5 set 1c06adbb…` and
`Installed attestor @INDEX@, NOT started.`

The installer pins `bloch-pos` and the producer in `config.json`, but not the follower. Check the
installed follower yourself:

```
sha256sum /opt/bloch/l2-attestor/bloch-l2-native-follower /opt/bloch/l2-attestor/bloch-l2-produce-dev /opt/bloch/l2-attestor/bloch-pos
```

The three hashes must equal the lines in `ARTIFACTS.sha256`.

## 5. Start the follower and wait for its first replay

```
sudo systemctl enable --now bloch-l2-attestor-follower
```

The first replay takes 30–60 minutes or more. Wait until `status.json` shows the L2 genesis as
finalized:

```
sudo python3 -c 'import json; s=json.load(open("/var/lib/bloch-l2-attestor-follower/status.json")); print(s["native_finalized_epoch"], s["l2_genesis"])'
```

## 6. Check

```
sudo systemd-run --pipe --wait -p User=bloch-l2-attestor -p LoadCredential=passphrase:/etc/bloch-l2-attestor/keystore.passphrase /usr/bin/python3 -I /opt/bloch/l2-attestor/attestor_agent.py check --config /etc/bloch-l2-attestor/config.json
```

Before the replay finishes this prints `check-not-ready`; wait and run it again. It must print
`check-ok` with `signer_index @INDEX@` and `set_hash 1c06adbb…`.

## 7. Start the agent

```
sudo systemctl enable --now bloch-l2-attestor
```
```
journalctl -u bloch-l2-attestor -o cat -n 20
```

Expect `started`, then `rebuild-check-ok`, then `waiting`, `awaiting-own-finality` or `root-skipped`.

## 8. Re-seal your offline backup under a passphrase only you know

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

Copy `attestor-@INDEX@.operator.sealed` to your offline media (two USB drives in different places),
check the copies with `sha256sum`, and only then delete it from the host:

```
shred -u attestor-@INDEX@.operator.sealed
```

Tell the coordinator you re-sealed (no passphrase, no file). The key holder can then destroy their
own copies of bundle @INDEX@.

## 9. Remove the bundle from the host

The host now holds only the re-sealed key (`/etc/bloch-l2-attestor/attestor.sealed`) and its random
host passphrase (root, 0400). Delete what you brought:

```
cd ..
```
```
shred -u operator-@INDEX@/attestor-@INDEX@.sealed operator-@INDEX@.tar
```

Your offline backup is now `attestor-@INDEX@.operator.sealed` (step 8) plus the passphrase only you
know. Keep them in different places.

## 10. Reply

Send the coordinator the reply in `ONBOARDING.md` section 6 (no secret in it).
