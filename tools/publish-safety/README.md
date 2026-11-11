# Publication safety tools

Two tools keep private operator material out of anything published from this repository.
Nothing here pushes, publishes or rewrites history.

## `publish_check.py`: pre-push and pre-publication checker

It blocks a push when the content or the commits being pushed contain:

| Category | What |
| --- | --- |
| `rule6` | confidential operational topics (patterns in the private denylist only) |
| `deployer`, `retired-address` | the forbidden deployer and the retired address set (private denylist) |
| `private-key` | PEM private keys, 32-byte hex keys next to a key word, mnemonics, keystore JSON |
| `token` | GitHub, Slack, AWS, Telegram and API-key shaped tokens |
| `secret-file` | tracked files named like keys, keystores, passphrases or `.env` |
| `internal-ip` | operator host addresses (private denylist) |
| `key-path` | paths into local key folders (private denylist) |
| `identity` | private author or committer identities, in commit metadata or in content |

It warns (never blocks) on RFC 1918 and other unlisted IPv4 addresses, `/home/<user>`-style host
paths and internal workspace references. Reported values are cut to their first 6 characters.

The **denylist is private**. Writing the forbidden values into a repository would publish them, so
the checker reads them from `~/.config/bloch-publish-safety/denylist.conf` (or `--denylist`, or
`$BLOCH_PUBLISH_DENYLIST`) and refuses to run without it. `denylist.example.conf` shows the format.
`publish-allowlist.txt` holds public values only: the public L1 RPC endpoints, loopback and
documentation ranges, the well-known Anvil test keys and files whose PEM header is a string literal.

```
python3 tools/publish-safety/publish_check.py tree HEAD
python3 tools/publish-safety/publish_check.py commits origin/main..HEAD
python3 tools/publish-safety/publish_check.py files docs/public/L2-MAINNET-GO-LIVE.md
```

As a hook, `pre-push` checks the full tree of every pushed ref and every pushed commit (metadata,
message and added lines) that the remote does not have yet. Remotes named in
`git config --get-all bloch.privateRemote` are skipped; every other remote is checked.

## `redact_runbook.py`: public variants of the go-live runbooks

The private runbooks (`docs/L2-MAINNET-GO-LIVE.md`, `docs/L2-MAINNET-GO-LIVE-V21.md`) stay the only
source. `public-variants.txt` lists each private source and its generated public copy under
`docs/public/`. The generator replaces operator hosts (by role, from a private host map at
`~/.config/bloch-publish-safety/host-roles.conf`), process IDs, home directories, local workspace
paths and key paths with placeholders, keeps the public RPC endpoints, numbers any host the map does
not name as `<HOST_n>`, and refuses to write a copy that still has a blocking hit or a host path.

```
python3 tools/publish-safety/redact_runbook.py
python3 tools/publish-safety/redact_runbook.py --check
```

Edit only the private source, then regenerate. A public tree must carry the `docs/public/` copies
and must not carry the private sources.

## Tests

```
python3 -m unittest discover -s tools/publish-safety -p 'test_*.py'
```

All fixtures are synthetic: RFC 5737 addresses and values derived from fixed seeds at run time.
