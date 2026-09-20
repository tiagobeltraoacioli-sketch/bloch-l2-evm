# Bloch L2 network identity decision

The selected Bloch L2 testnet chain ID is **700771** (`eip155:700771`). This
decision minimizes consensus migration risk: the execution specification,
signed-transaction domain, block headers, proof statements and bridge deposit
envelopes already bind that value. Chain IDs 8400 and 84001 are not launch
identities. The former is a retired public scaffold; the latter is an inactive
DEX/wallet compatibility environment that must be migrated after the production
genesis is frozen.

Selection is not registration and is not activation. The machine-readable
decision in [`network/identity.json`](../network/identity.json) deliberately
keeps every activation gate false. In particular:

1. `eip155:700771` must be registered to the exact Bloch metadata in the public
   `ethereum-lists/chains` registry. Availability alone does not reserve it.
2. A production genesis must be generated, reviewed and frozen. The synthetic
   developer genesis is not reusable.
3. The production RPC must expose an authenticated, non-regressing `finalized`
   block backed by the selected native consensus mechanism. A synthetic height,
   elapsed time or operator label is not finality.
4. Bridge, DEX and wallet manifests must migrate together and be verified
   against the frozen genesis before any service or liquidity is enabled.

The exact finality boundary and the evidence still required are specified in
[L2-FINALITY.md](L2-FINALITY.md). An authenticated native anchor alone does not
close the `finalizedRpcVerified` gate.

[`network/eip155-700771.json`](../network/eip155-700771.json) is the proposed
registry record. Its empty RPC list is intentional while there is no qualified
public endpoint. Do not publish an unqualified IP address merely to satisfy a
directory field.

## Collision check

Download the current registry independently and run:

```sh
python3 tools/check-network-identity.py /path/to/chains_mini.json
```

An absent record reports `available-unregistered` and leaves production closed.
Once the upstream registration is merged, require the exact record with:

```sh
python3 tools/check-network-identity.py \
  --require-registered /path/to/chains_mini.json
```

Any occupant with different metadata is treated as a chain-ID collision, never
as evidence that Bloch was registered.
