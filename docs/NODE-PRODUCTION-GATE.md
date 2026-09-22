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
