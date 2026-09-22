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
is inventoried by path, byte length and SHA-256. Verification uses the trusted,
externally pinned validator suite to re-check the packaged sources; trusting
only the inventory or a reported boolean is insufficient.

The builder requires the exact 40-character source revision. It proves that
every packaged source/evidence byte and every validator byte is the version
tracked at that commit; an arbitrary SHA-shaped string, untracked evidence or a
dirty validator therefore cannot acquire provenance. It refuses to overwrite
an existing package, rejects paths outside the package, symlinks, extra files
and common private-key or credential material. This is a handoff and audit
format, not a secret store.

Package fields are not trust roots. In particular, `sourceRevision` and the
verifier identity inside the ZIP are self-declarations. Before handoff, record
the reviewed commit and the verifier-suite SHA-256 through an independent,
authenticated channel. The suite identity covers this packager and all three
semantic validators. Obtain it from the exact reviewed checkout with:

```sh
python3 tools/node-qualification-package.py verifier-id
```

```sh
python3 tools/node-qualification-package.py build \
  --revision <reviewed-40-character-git-sha> \
  --output /secure/review/node-qualification.zip
python3 tools/node-qualification-package.py verify \
  /secure/review/node-qualification.zip \
  --expected-source-revision <reviewed-40-character-git-sha> \
  --trusted-verifier-sha256 <independently-recorded-64-hex-sha256>
```

Do not copy either expected value from the package being checked. Verification
fails if the package revision differs, if the local verifier suite differs from
the trusted suite hash, or if the package names a different verifier. Semantic
validator modules are loaded only after these provenance checks pass.

For an activation workflow, use the strict verifier immediately before any
process or firewall change:

```sh
python3 tools/node-qualification-package.py verify \
  /secure/review/node-qualification.zip \
  --expected-source-revision <reviewed-40-character-git-sha> \
  --trusted-verifier-sha256 <independently-recorded-64-hex-sha256> \
  --require-activation-permitted
```

The checked-in pending manifests produce a valid audit package whose
`activationPermitted` value is false. The strict command therefore fails, as it
must. Packaging pending evidence does not satisfy a requirement, qualify an
endpoint, start a node, or authorize a listener.
