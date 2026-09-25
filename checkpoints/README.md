# Pending component checkpoint ceremony

`registry.pending.json` is an intentionally incomplete adoption template. It is
not a valid registry and cannot authorize a checkpoint. Do not substitute test
keys, placeholder hashes or signatures produced by a coordinator for three
independent holders.

The default follows L1 Phase A: 2 of 3, at least one external signature. Set the
reviewed registry threshold to 3 to require all three. Holder identities, public
keys, timestamps, network/finality evidence and reviewed artifact/configuration
pins must be supplied before preparing a signable package.

See [the native ceremony runbook](../integrations/component-checkpoint/README.md).

`candidate-artifacts.json` hashes the public source/configuration files of this
development change. It is an unsigned review inventory, not a complete deployed
release. Production ceremonies must add actual deployment/runtime, finalized-state
and configuration evidence before the three holders review and sign.
