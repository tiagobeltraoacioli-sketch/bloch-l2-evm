#!/usr/bin/env python3
"""Build the 264-byte native L2 settlement config (l2-config.bin) for devnet4.

Layout (bloch-pos-node genesis_l2::L2Config, decoded with an exact length):
  domain || configuration || elf_keccak || vkey_koalabear || vkey_bn254   5 x 32
  proof_policy                                                            32
  chain_id                                                                u64 little-endian
  initial_l2_parent || initial_l2_state                                   2 x 32

Inputs (no network, no keys):
  --identity FILE   JSON printed by `bloch-evm-sp1-settlement-v3 identity ELF`
                    (host built with --features node-artifact,source-settlement)
  --genesis FILE    JSON printed by `bloch-l2-produce-dev head --target DB`
                    right after `init` (number 0: hash + state_root)
  --native-policy HEX  policy_commitment_v3() printed by the native build
                    (must equal the identity's proof_policy_v3)
  --out FILE        refuses to overwrite

The settler checks values[T+64:T+224] == config[:160] and puts config[160:192]
(the proof policy) in every settlement transaction, so this file is the single
source of the V3 program pins on both sides. Dependency-free Python 3.9+.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

CONFIG_BYTES = 264
CHAIN_ID = 700771
DOMAIN = 'd3' * 32


def h32(value, name):
    value = value.lower().removeprefix('0x')
    if len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise SystemExit(f'{name} must be 32 bytes of hex')
    raw = bytes.fromhex(value)
    if raw == bytes(32):
        raise SystemExit(f'{name} must not be zero')
    return raw


def build(identity, genesis, native_policy):
    if identity.get('program') != 'settlement_v3':
        raise SystemExit('identity is not the settlement_v3 program')
    if identity.get('chain_id') != CHAIN_ID or identity.get('domain') != DOMAIN:
        raise SystemExit('identity chain id or domain differs from the devnet L2')
    if identity.get('proof_policy_v3') is None:
        raise SystemExit('identity lacks proof_policy_v3: build the host with --features source-settlement')
    policy = h32(identity['proof_policy_v3'], 'proof_policy_v3')
    if policy != h32(native_policy, '--native-policy'):
        raise SystemExit('L2 host and native build disagree on the V3 proof policy')
    if genesis.get('number') != 0:
        raise SystemExit('genesis JSON must be the head of a freshly initialised L2 database (number 0)')
    out = b''.join(h32(identity[k], k) for k in ('domain', 'configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254'))
    out += policy + CHAIN_ID.to_bytes(8, 'little') + h32(genesis['hash'], 'genesis hash') + h32(genesis['state_root'], 'genesis state_root')
    assert len(out) == CONFIG_BYTES
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--identity', required=True)
    p.add_argument('--genesis', required=True)
    p.add_argument('--native-policy', required=True)
    p.add_argument('--out', required=True)
    a = p.parse_args(argv)
    config = build(json.loads(Path(a.identity).read_text()), json.loads(Path(a.genesis).read_text()), a.native_policy)
    with open(a.out, 'xb') as f:
        f.write(config)
    print(json.dumps({'out': a.out, 'bytes': len(config), 'sha256': hashlib.sha256(config).hexdigest(),
                      'proof_policy': config[160:192].hex(), 'identities_prefix_160': config[:160].hex()}))


if __name__ == '__main__':
    sys.exit(main())
