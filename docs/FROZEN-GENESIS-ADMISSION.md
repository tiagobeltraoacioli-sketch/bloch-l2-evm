# Frozen genesis admission

`tools/check-frozen-genesis-admission.mjs` is an offline, side-effect-free gate
for the production genesis of Bloch L2 chain `700771`. It does not generate a
genesis, appoint authorities, start a node, open RPC/P2P, or update the checked-in
contract. The repository contract remains pending and grants no permissions.

Admission requires all of the following external inputs at once:

1. A canonical trust-root registry containing exactly three distinct Ed25519
   public keys and three distinct organization identifiers, with threshold 2.
2. The path and SHA-256 of that registry fixed in a separately reviewed commit
   of `deployment/frozen-genesis-admission.json` before any genesis package is
   presented. A digest supplied by the same admission request is not accepted.
3. A compiled `bloch-genesis-identity` binary whose SHA-256 and 40-hex source
   revision are fixed by that same prior reviewed commit. The gate executes a
   private copy of the verified bytes, not `cargo run` from the mutable checkout.
4. A canonical package binding the exact frozen input bytes, reviewed state
   root and block hash, network and chain ID `700771`. The input selects only
   the compiled `bloch-l2-cancun-zero-issuance-v1` profile, domain and timestamp;
   it cannot add allocations or change execution parameters.
5. A canonical approval envelope with at least two valid signatures from the
   registered independent roots over the domain-separated package digest.

Before checking signatures, the gate runs the SHA-pinned Rust
`bloch-genesis-identity` binary. It reconstructs `ChainSpec::testnet()`, the
V2 genesis state and header, and requires the derived state root and block hash
to equal the reviewed package. Signatures therefore cannot authenticate an
inconsistent declared identity. The gate also checks exact schemas, canonical
JSON bytes, regular non-symlink files, path containment, artifact hashes, chain
identity, key type, signer uniqueness and signatures. Files are opened with
`O_NOFOLLOW`; inode/metadata stability is checked before, during and after the
read, and hard-linked or group/world-writable inputs are rejected. Organizational
independence is a real-world fact:
distinct strings and keys are necessary but do not prove it. The ceremony must
establish and document that independence outside this repository.

Build the verifier only from a clean reviewed revision, then distribute its
digest independently before changing the admission contract:

```sh
BLOCH_L2_SOURCE_REVISION="$(git rev-parse HEAD)" \
  cargo build --locked --release --features serde \
  --example bloch-genesis-identity
sha256sum target/release/examples/bloch-genesis-identity
```

Pending check (expected success with `genesisAdmitted: false`):

```sh
node tools/check-frozen-genesis-admission.mjs
```

Production admission check (paths are examples only):

```sh
node tools/check-frozen-genesis-admission.mjs \
  --package /secure/input/frozen-genesis-package.json \
  --approvals /secure/input/frozen-genesis-approvals.json \
  --require-admitted
```

Even a successful result reports `nodeStartPermitted: false`. It is evidence for
the separate production-entrypoint gate, not permission to deploy or bind a
network service.

## Executable ceremony workflow

The ceremony tool never creates or reads a private key. Every output is opened
with create-once semantics and mode `0600`; an existing path is an error. Start
in a new owner-only directory only after the reviewed contract pins the roots
registry and identity-verifier binary:

```sh
install -d -m 0700 /secure/ceremony-700771

node tools/frozen-genesis-ceremony.mjs template \
  --out /secure/ceremony-700771/genesis.template.json

node tools/frozen-genesis-ceremony.mjs freeze \
  --template /secure/ceremony-700771/genesis.template.json \
  --domain "$REVIEWED_EXECUTION_DOMAIN" \
  --timestamp "$REVIEWED_GENESIS_TIMESTAMP" \
  --out /secure/ceremony-700771/genesis.json

node tools/frozen-genesis-ceremony.mjs derive \
  --contract deployment/frozen-genesis-admission.json \
  --genesis /secure/ceremony-700771/genesis.json \
  --ceremony-id ceremony-700771-001 \
  --decision-id decision-700771-genesis-001 \
  --out /secure/ceremony-700771/package.json

node tools/frozen-genesis-ceremony.mjs requests \
  --contract deployment/frozen-genesis-admission.json \
  --package /secure/ceremony-700771/package.json \
  --out-dir /secure/ceremony-700771/requests
```

The `requests` command emits three JSON requests and three exact binary payloads.
Transfer one request and its matching payload to each independent root through
that organization's authenticated channel. On each organization's offline
signing machine, after independently reviewing the package digest:

```sh
openssl pkeyutl -sign -rawin \
  -inkey /offline/private/root-ed25519.pem \
  -in trust-root-1.payload.bin \
  -out trust-root-1.signature.bin
```

The private-key path above belongs only to that independent authority and must
never be copied to the coordinator. Return only the 64-byte detached signature.
The coordinator verifies and wraps each response create-once:

```sh
node tools/frozen-genesis-ceremony.mjs respond \
  --contract deployment/frozen-genesis-admission.json \
  --request /secure/ceremony-700771/requests/trust-root-1.request.json \
  --signature /secure/inbox/trust-root-1.signature.bin \
  --out /secure/ceremony-700771/trust-root-1.response.json
```

After at least two independently returned responses exist, assemble the final
approval envelope and re-run the admission gate:

```sh
node tools/frozen-genesis-ceremony.mjs assemble \
  --contract deployment/frozen-genesis-admission.json \
  --package /secure/ceremony-700771/package.json \
  --response /secure/ceremony-700771/trust-root-1.response.json \
  --response /secure/ceremony-700771/trust-root-2.response.json \
  --out /secure/ceremony-700771/approvals.json

node tools/check-frozen-genesis-admission.mjs \
  --contract deployment/frozen-genesis-admission.json \
  --package /secure/ceremony-700771/package.json \
  --approvals /secure/ceremony-700771/approvals.json \
  --require-admitted
```

The assembled result still reports `nodeStartPermitted: false`. A successful
genesis ceremony does not satisfy finality, derivation, persistence, recovery,
RPC, P2P or production-entrypoint gates.
