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

## Reproducible provisioning preflight

`deployment/l2-node.json` is the side-effect-free handoff before any Compose or
systemd unit is generated. It fixes chain ID 700771 and the Docker runtime, but
intentionally leaves the production image, genesis, storage and listeners null.
Those values are not present in the reviewed repository and must not be invented.

The preflight requires a content-addressed image reference ending in
`@sha256:<digest>`, a repository-contained genesis with its exact SHA-256, a
narrow absolute data directory, and listeners that exactly match the qualified
node readiness manifest. The image reference and genesis digest must also arrive
through independent trusted inputs; values copied only from the deployment
manifest are self-declarations. The readiness manifest itself is hash-bound and
must permit binding before `startPermitted` can become true.

Inspect the pending plan without side effects:

```sh
python3 tools/check-node-provisioning.py
```

An eventual reviewed start workflow must supply the independently recorded pins
and use the strict form immediately before generating or starting a service:

```sh
python3 tools/check-node-provisioning.py \
  --trusted-image '<registry>/<repository>@sha256:<64-hex-digest>' \
  --trusted-genesis-sha256 '<64-hex-digest>' \
  --require-start-permitted
```

The checked-in plan makes that command fail. The preflight never calls Docker,
systemd, a node binary or a firewall tool. Do not create a service definition
until a real image, frozen production genesis and all eight node requirements
have passed independent review.

### Production build request

`deployment/production-node-build-request.json` records the result of inspecting
the available build sources. The only runnable node entrypoint is
`bloch-evm-dev`; its source makes `--synthetic-dev` mandatory and explicitly has
no P2P, native/L1 derivation or finality. It is not a production image candidate.
The Reth integration does pin an upstream base revision, patch, Rust toolchain and
Cargo lockfile, and the request hash-binds those selected inputs. This is enough
to reproduce the tested synthetic candidate with the prepared sibling checkout,
not enough to define a production node or its container.

The machine-readable request lists nine unresolved inputs: a production
entrypoint, frozen genesis, authenticated native derivation, production
consensus/finality, builder and runtime image digests, container build definition,
complete source SBOM and build-provenance policy. It deliberately contains no
image, SBOM or provenance output and cannot authorize a build.

```sh
python3 tools/check-production-node-build-request.py
python3 tools/check-production-node-build-request.py --require-build-permitted
```

The first command verifies the seven hash-bound inputs and reports all nine missing
decisions. The second always fails for this constraints-only schema. Do not turn
the synthetic executable into a production container by merely renaming it or
supplying a Dockerfile; the missing protocol inputs must first be implemented and
reviewed in a new production-build manifest.

### Production entrypoint capability contract

`deployment/production-entrypoint-contract.json` defines the minimum protocol
surface before any production binary can be named: authenticated P2P, native/L1
derivation, production consensus, settlement-bound finalized head, frozen genesis,
readiness-gated JSON-RPC, durable state/head/receipt/cursor persistence, graceful
shutdown and qualified crash recovery. Each capability carries an exact ordered
acceptance contract so dropping a safety property is a detectable schema change.

The current contract has no binary, image, arguments, service user, data directory
or genesis. All nine capabilities are `missing`; build, start, RPC/P2P bind and
finalized-publication permissions are false. The build request hash-binds this
contract as an audited input but deliberately leaves `production-node-entrypoint`
unresolved. Linking a constraint is not evidence that an implementation exists.

```sh
python3 tools/check-production-entrypoint-contract.py
python3 tools/check-production-entrypoint-contract.py --require-production-ready
```

The strict command fails. The checker rejects substituting `bloch-evm-dev`, adding
`--synthetic-dev`, weakening/reordering a capability, self-approving evidence or
opening any permission.

## Portable qualification package

`tools/node-qualification-package.py` creates a deterministic ZIP containing
the network identity, registration proposal, finality gate, node gate,
provisioning preflight, blocked production-build request, production entrypoint
contract, and the exact transitive set of evidence files referenced by the two
readiness gates plus all seven audited build inputs. Every file
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
authenticated channel. The suite identity covers this packager, all three
semantic readiness validators, provisioning preflight, build-request checker and
entrypoint-contract checker. Obtain it from the exact reviewed checkout with:

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

## Authenticated observation intake

`tools/intake-operational-evidence.py` provides a narrow handoff boundary for
real operational observations. It normalizes an exact, bounded JSON schema and
authenticates the canonical bytes with an SSH signature. Signatures use the
`bloch-l2-operational-evidence-v1` namespace; the signer principal must match
the observation's `observer` field.

The `allowed_signers` file and its SHA-256 are external trust inputs. The tool
refuses a policy inside this repository and refuses one that differs from the
independently pinned digest. Obtain the policy and digest through an
authenticated operator/reviewer channel; never copy either from the submitted
evidence. No private key is accepted or stored by the intake tool.

Prepare and sign an observation:

```sh
python3 tools/intake-operational-evidence.py normalize \
  --input /secure/intake/raw-observation.json \
  --output /secure/intake/canonical-observation.json
ssh-keygen -Y sign -f /secure/operator/key \
  -n bloch-l2-operational-evidence-v1 \
  /secure/intake/canonical-observation.json
```

Authenticate it using the independently provisioned public-key policy:

```sh
python3 tools/intake-operational-evidence.py authenticate \
  --observation /secure/intake/canonical-observation.json \
  --details /secure/intake/finality-probe.json \
  --signature /secure/intake/canonical-observation.json.sig \
  --allowed-signers /secure/trust/bloch-l2-allowed-signers \
  --trusted-allowed-signers-sha256 <independently-recorded-64-hex-sha256> \
  --output /secure/review/authenticated-observation.json
```

The intake refuses missing or changed detail bytes: their SHA-256 must equal the
signed observation's `detailsSha256`. The immutable output binds the observation,
detail bytes, signature and trust-root hashes. A reviewer can reproduce the
verification without writing another artifact:

```sh
python3 tools/intake-operational-evidence.py verify \
  --artifact /secure/review/authenticated-observation.json \
  --observation /secure/intake/canonical-observation.json \
  --details /secure/intake/finality-probe.json \
  --signature /secure/intake/canonical-observation.json.sig \
  --allowed-signers /secure/trust/bloch-l2-allowed-signers \
  --trusted-allowed-signers-sha256 <independently-recorded-64-hex-sha256>
```

The artifact is deliberately marked `effect: observation-only` and
`qualified: false`.
A `pass` result is a signed observation, not a qualified requirement. Reviewers
must separately validate the referenced detail bytes, freshness, independence,
scope and the requirement-specific acceptance policy before changing either
readiness manifest. This tool never edits those manifests, never opens a
permission and never starts or binds a node.
