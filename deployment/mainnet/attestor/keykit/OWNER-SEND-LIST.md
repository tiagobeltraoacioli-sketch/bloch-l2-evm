# What the key holder sends each attestor operator

Package from the current kit, never from `~/worktrees/attestor-custody-20261030` (commit 922fec4): that tree pins the old
producer `7c1cc62b…`, which halts on the first settled deposit. `package` here refuses those pins, and also v2.1's follower `c18752fd…` and
producer `fb0d5313…`: packages for this build pin follower `cdf5da5c…` and producer `e3f1a290…` (build 17383fe).

Build each package with the binaries inside (`package --artifacts DIR`, about 70 MB compressed or 90 MB as a tar). A non-expert
then has nothing to fetch. `DIR` holds the five pinned files plus `carryover.tsv.gz.sha256`.

## Before you send anything to operator I

Tell the operator, in any channel, what they need ready. None of this is secret:

- A dedicated Ubuntu 24.04 x86_64 host: 2 cores, 8 GB, 80 GB SSD at least. Not a validator, not the settler, not another operator's host.
- A static public IPv4 with inbound TCP 8787 open to everyone, and SSH open only to them.
- `sudo` on that host, and two USB drives on their own computer.
- About two hours of mostly waiting, and a contact method for alerts.

## Three things, three channels

| # | What | How | Never |
|---|---|---|---|
| 1 | `operator-I.tar` | File transfer or in person. It holds the sealed key, so treat it as sensitive, though it cannot be opened alone | In the same channel as 2 |
| 2 | Transport passphrase I | Voice, or in person, or a disappearing message | In writing next to the file; to anyone but operator I; reused for another index |
| 3 | The one `operator-I.tar` line of `PACKAGES.sha256` | A third channel, or read it aloud | Inside the tar's message |

Item 3 is public, and the operator uses it to detect a swapped file. Send only that one line.

## Message to send with item 1

    Attestor index I for Bloch L2. Extract nothing yet. You will get a passphrase and one hash line separately. Put the line in a
    file named PACKAGES.sha256 beside the tar, run: sha256sum -c PACKAGES.sha256, and it must print operator-I.tar: OK. Then run
    tar -xf operator-I.tar and follow operator-I/INSTALL.md from step 1. Read operator-I/ONBOARDING.md first. Send me the reply at
    the end of ONBOARDING.md. Never send me a passphrase or the sealed file. Questions: CONTACT

## What comes back

The reply template in `ONBOARDING.md` section 6: no secret in it. Check these before you run `release-owner-copy --index I`:

1. `check-ok` names `signer_index I` and set `1c06adbb…`.
2. `curl -fsS http://THEIR_IPV4:8787/healthz` from your machine prints `ok`.
3. Installed hashes: `bloch-pos 093909a2…`, follower `cdf5da5c…`, producer `e3f1a290…`.
4. Two epoch readings 16+ minutes apart, increasing.
5. Offline backup re-sealed: yes.

Publish the five feed URLs to claimants and monitors once all five answer.
