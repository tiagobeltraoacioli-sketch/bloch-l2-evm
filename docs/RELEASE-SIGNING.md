# Bloch L2 release signing ceremony

Release `bloch-l2-2026-11-03-next-native-78d4921c`, build commit `926d2cf50af11f389ad1ffa91c0b7720178b3472`,
native `78d4921c3ec6ba41829f3878eed47f8d3bb96230`. Signing target: the release `SHA256SUMS`,
SHA-256 `6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19`.

Only the owner holds the release key and runs sections 2 to 5. Every command is one block; run them in order.
Sign only after G0 has passed (plan D7) and the kit tip is frozen.

## 1. The key

| | |
|---|---|
| Key | Bloch release key, the one that signed the `bloch-pos` node releases of 2026-09-22, 2026-10-14 and 2026-10-29 |
| Key ID | `1A5D96A5C4955EF7` |
| Public key | `RWT3XpXEpZZdGtghC5SmyRj2VRTAGUfO5KxBucYVTRfriNE13wsXhfj6` |
| Public key file | `bloch-release-20260922.pub`, SHA-256 `77a18b65d75508752100bdef83ed09bcf5ec0a203a1b3de1831548b4521ae243` |
| Pinned in | `deployment/mainnet/verify_release_signature.py` (`RELEASE_PUBKEY`, `RELEASE_KEY_ID`) |
| Tool | `rsign` 0.6.7 (rsign2) on the owner's Mac; output is minisign format (`minisign -Vm` verifies it) |

The secret key is wherever the owner kept it for the 2026-10-29 signature (`rsign`'s default is
`~/.rsign/rsign.key`). No agent has opened, copied or listed it. The sign command below passes
the pinned public key with `-p`: `rsign` then refuses a secret key that does not belong to key
`1A5D96A5C4955EF7` ("Could not verify signature with the provided public key ID"), so the signing
step itself proves the right key was used, without printing anything secret.

A new key is generated only for a rotation (section 7), never for an ordinary release: operators
already trust `1A5D96A5C4955EF7`. If one is needed, generate it offline onto an encrypted volume,
always with a password (never `-W`), and follow section 7 before using it.

## 2. Fetch the release from two hosts and compare byte for byte (online)

The release was assembled independently on 45.77 and 136. Fetch both copies whole and compare them
on the Mac before signing. Each copy is about 93 MB.

```
mkdir -p ~/bloch-l2-signing
```

```
scp -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@45.77.142.123:l2dexbridge-20261030/rpc-limits-r10/release/bloch-l2-2026-11-03-next-native-78d4921c ~/bloch-l2-signing/from-4577
```

```
scp -r -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ubuntu@136.244.93.186:l2dexbridge-20261030/rpc-limits-r10/release/bloch-l2-2026-11-03-next-native-78d4921c ~/bloch-l2-signing/from-136
```

The next command must print nothing (identical trees, every byte):

```
diff -r ~/bloch-l2-signing/from-4577 ~/bloch-l2-signing/from-136
```

```
cd ~/bloch-l2-signing/from-4577
```

Every line must say `OK` (8 files):

```
shasum -a 256 -c SHA256SUMS
```

Must print `6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19  SHA256SUMS`:

```
shasum -a 256 SHA256SUMS
```

The frozen kit must pin the same value (line `artifacts/SHA256SUMS`):

```
grep 'artifacts/SHA256SUMS$' ~/worktrees/l2-launch-kit-20261103/deployment/mainnet/GO-LIVE-PINS.sha256
```

No `SHA256SUMS.minisig` may exist yet (`rsign` overwrites one silently). This must say "No such file":

```
ls -l SHA256SUMS.minisig
```

Take the public key from the published node release, and check its hash is `77a18b65…e243`:

```
cp ~/worktrees/publish-node-78d4921c-20261029/releases/bloch-pos-2026-10-29-hf123/bloch-release-20260922.pub ~/bloch-l2-signing/
```

```
shasum -a 256 ~/bloch-l2-signing/bloch-release-20260922.pub
```

The trusted comment is derived from `release.json` and the SHA-256 of `SHA256SUMS`. It must print
exactly the line in section 3:

```
python3 -I ~/worktrees/l2-launch-kit-20261103/deployment/mainnet/verify_release_signature.py --print-trusted-comment ~/bloch-l2-signing/from-4577
```

## 3. Sign (offline)

Turn Wi-Fi off and unplug any network cable, then mount the volume holding the secret key if it
is not in `~/.rsign`. If your key file is not `~/.rsign/rsign.key`, change only the `-s` path.
`rsign` asks for the key's password.

The trusted comment (signed together with the file; one line, no line breaks):

```text
bloch-l2 release=bloch-l2-2026-11-03-next-native-78d4921c sha256sums=6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19 l2_commit=926d2cf50af11f389ad1ffa91c0b7720178b3472 native_commit=78d4921c3ec6ba41829f3878eed47f8d3bb96230 chain_id=700770 platform=linux-x86_64
```

```
cd ~/bloch-l2-signing/from-4577
```

```
rsign sign -s ~/.rsign/rsign.key -p ~/bloch-l2-signing/bloch-release-20260922.pub -x SHA256SUMS.minisig -c "signature from Bloch release key 1A5D96A5C4955EF7" -t "bloch-l2 release=bloch-l2-2026-11-03-next-native-78d4921c sha256sums=6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19 l2_commit=926d2cf50af11f389ad1ffa91c0b7720178b3472 native_commit=78d4921c3ec6ba41829f3878eed47f8d3bb96230 chain_id=700770 platform=linux-x86_64" SHA256SUMS
```

If it fails (wrong password, or "Could not verify signature with the provided public key ID"),
`rsign` leaves an empty `SHA256SUMS.minisig`. Remove it before trying again:

```
rm SHA256SUMS.minisig
```

Unmount the key volume. Do not edit `release.json` or `BUILD-INFO` (`signed=false` stays): they
are inside `SHA256SUMS`, and any edit moves the signing target.

## 4. Verify (still offline)

Must print `Signature and comment signature verified` and the trusted comment above:

```
rsign verify -p ~/bloch-l2-signing/bloch-release-20260922.pub -x SHA256SUMS.minisig SHA256SUMS
```

The kit verifier, with the pinned key, the canonical trusted comment and every file. Must end with `signature OK`:

```
python3 -I ~/worktrees/l2-launch-kit-20261103/deployment/mainnet/verify_release_signature.py --release-dir ~/bloch-l2-signing/from-4577 --expect-sha256 6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19
```

The same signature must verify on the copy from the other host:

```
cp SHA256SUMS.minisig ~/bloch-l2-signing/from-136/
```

```
python3 -I ~/worktrees/l2-launch-kit-20261103/deployment/mainnet/verify_release_signature.py --release-dir ~/bloch-l2-signing/from-136 --expect-sha256 6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19
```

```
shasum -a 256 SHA256SUMS.minisig
```

Record that hash next to D7 in the owner documents.

## 5. Where the signature and public key go (online again)

- `SHA256SUMS.minisig` stays next to `SHA256SUMS` in `~/bloch-l2-signing/from-4577`: plan P2 stages A
  and B from that signed copy on the Mac (`scp ~/bloch-l2-signing/from-4577/* …`), so it carries the
  signature. Put it in the release directory on both build hosts as well (below), so that those
  copies are complete. `release.json` already names it (`checksum_signature`).
- `bloch-release-20260922.pub` travels with every published copy of the release, as with the node
  releases. Operators must not trust the copy inside a download alone: they compare it with the
  key ID and public key string published earlier (node release READMEs) or rely on the pinned key
  in the kit's verifier.
- Keep `~/bloch-l2-signing/from-4577` (with the signature) as the owner's archive copy of the release.

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/bloch-l2-signing/from-4577/SHA256SUMS.minisig ubuntu@45.77.142.123:l2dexbridge-20261030/rpc-limits-r10/release/bloch-l2-2026-11-03-next-native-78d4921c/
```

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/bloch-l2-signing/from-4577/SHA256SUMS.minisig ubuntu@136.244.93.186:l2dexbridge-20261030/rpc-limits-r10/release/bloch-l2-2026-11-03-next-native-78d4921c/
```

If A or B was staged before signing, copy it into their `artifacts` too:

```
scp -i ~/Desktop/ssh-chaves/edgevana/edgevana_fleet_g4 ~/bloch-l2-signing/from-4577/SHA256SUMS.minisig ubuntu@136.244.93.186:l2-golive-next/artifacts/
```

## 6. How operators and installers verify

- **Plan P2, on A and on B** (replaces `minisign -Vm … -P <owner public key>`; no minisign needed,
  Python 3 standard library only):

```
python3 -I /home/ubuntu/l2-golive-next/kit/verify_release_signature.py --release-dir /home/ubuntu/l2-golive-next/artifacts --expect-sha256 6d3bd62885ca269e50e85b53c8c378a7d86467680563292e784c6f0459258c19
```

- **`follower-rpc/install.sh`** runs the same check, with the pinned key, before it installs
  anything (also with `--dry-run`), and stops when `SHA256SUMS.minisig` is missing, made by another
  key, over other bytes, carries another trusted comment, or any listed file differs.
  `--allow-unsigned` exists for private rehearsals only and prints a warning.
- **Anyone with minisign** (Ubuntu package `minisign`), in the release directory:

```
minisign -Vm SHA256SUMS -P RWT3XpXEpZZdGtghC5SmyRj2VRTAGUfO5KxBucYVTRfriNE13wsXhfj6
```

  then `sha256sum -c --strict SHA256SUMS`, and compare the printed trusted comment with section 3.
- **Not covered by the signature check:** `install-shadow.sh`, `install-settler-mainnet.py`,
  `prover/install-prover-mainnet.py`, `replica/install-replica.sh` and the attestor bundle. They
  check their own pins (`GO-LIVE-PINS*.sha256`, `replica/PINS.sha256`, `ARTIFACTS.sha256`) and run
  on hosts where P2 has verified the signature. The kit itself is not signed: its integrity is the
  owner's frozen git tip and `GO-LIVE-PINS.sha256`.

What the verifier checks (`verify_release_signature.py`): the minisign signature format with the
prehashed algorithm (`ED`, BLAKE2b-512; legacy `Ed` refused), the key ID equals the pinned key,
both Ed25519 signatures (file and trusted comment) with canonical `S` and point encodings, the
trusted comment equals the canonical line built from `release.json` and the SHA-256 of
`SHA256SUMS`, every line of `SHA256SUMS` matches a file in the directory (no paths, no duplicates,
`release.json` covered), and that neither the key nor the `SHA256SUMS` hash is on the revocation
lists.

## 7. Revocation

minisign has no revocation mechanism of its own. Revocation is a reviewed kit change plus a
public notice:

- **A signature was issued in error, key safe** (wrong file, release withdrawn): add the SHA-256
  of that `SHA256SUMS` to `REVOKED_SHA256SUMS` in `verify_release_signature.py`, update the pin of
  the verifier in `GO-LIVE-PINS.sha256`, and announce the withdrawal on the same channels as the
  release. A signature over any other `SHA256SUMS` is never accepted by P2 anyway: P2 requires
  `--expect-sha256` and the kit pins the target.
- **The key is lost or compromised:**
  1. Stop: no install, upgrade or bridge/DEX pin that depends on a release signature until step 4.
  2. Generate a new key offline (section 1), add `1A5D96A5C4955EF7` to `REVOKED_KEY_IDS`, set
     `RELEASE_PUBKEY` and `RELEASE_KEY_ID` to the new key, and update the verifier's pin.
  3. Re-sign every release still in use (this L2 release and the current `bloch-pos` node release,
     which share this key) with the new key, following sections 2 to 5.
  4. Publish the new public key and the revocation through channels that do not depend on the old
     key (the repository, the website and the release pages), and tell operators the new key ID.
  A compromised key can sign anything, including a "revocation"; operators should only accept a
  key change that arrives with a new kit pin through the owner's usual channels.

Note: this key also signs `bloch-pos` node releases. Losing it affects L1 node releases too.
