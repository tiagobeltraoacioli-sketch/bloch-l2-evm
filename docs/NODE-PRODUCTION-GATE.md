# Production node bind gate

`network/node-production.json` is the offline, fail-closed gate for a Bloch L2
node that may expose RPC or P2P listeners. The checked-in manifest is pending:
all eight requirements are false, all evidence references are null, and both
listen endpoints are null.

The gate covers the selected chain identity, frozen production genesis,
execution domain, P2P policy, authenticated checkpoint policy, source
derivation policy, settlement policy, and finality policy. Marking a requirement
satisfied requires a repository-relative artifact and its exact SHA-256 digest.
This hash binding records the reviewed input; it does not replace review of the
artifact or operational qualification.

`productionReady` and `bind.enabled` are derived values. Both must equal the
conjunction of every requirement. A disabled bind must not publish endpoints;
an enabled bind must name explicit RPC and P2P `host:port` values. Consequently,
editing only `bind.enabled`, adding an endpoint, omitting a policy, or using
placeholder evidence fails validation.

Validate the pending manifest offline with:

```sh
python3 tools/check-node-production.py
```

An activation workflow must use the stricter form before starting a process or
opening a firewall:

```sh
python3 tools/check-node-production.py --require-bind-permitted
```

The strict command intentionally fails for the checked-in manifest. No service
manager, container runtime, node binary, or firewall rule should treat the
non-strict structural check as authorization to bind.

## Portable qualification package

`tools/node-qualification-package.py` creates a deterministic ZIP containing
the network identity, registration proposal, finality gate, node gate, and the
exact transitive set of evidence files referenced by the two gates. Every file
is inventoried by path, byte length and SHA-256. Verification re-runs all three
semantic validators from the packaged copies; trusting only the inventory or a
reported boolean is insufficient.

The builder requires the exact 40-character source revision instead of guessing
it from a mutable working tree. It refuses to overwrite an existing package,
rejects paths outside the package, symlinks, extra files and common private-key
or credential material. This is a handoff and audit format, not a secret store.

```sh
python3 tools/node-qualification-package.py build \
  --revision <reviewed-40-character-git-sha> \
  --output /secure/review/node-qualification.zip
python3 tools/node-qualification-package.py verify \
  /secure/review/node-qualification.zip
```

For an activation workflow, use the strict verifier immediately before any
process or firewall change:

```sh
python3 tools/node-qualification-package.py verify \
  /secure/review/node-qualification.zip \
  --require-activation-permitted
```

The checked-in pending manifests produce a valid audit package whose
`activationPermitted` value is false. The strict command therefore fails, as it
must. Packaging pending evidence does not satisfy a requirement, qualify an
endpoint, start a node, or authorize a listener.
