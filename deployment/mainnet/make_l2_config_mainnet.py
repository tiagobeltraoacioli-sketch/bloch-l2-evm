#!/usr/bin/env python3
"""Build the 264-byte Bloch L2 MAINNET settlement config (l2-config.bin, chain 700770).

Same layout as deployment/devnet/devnet4/make_l2_config.py (bloch-pos-node
genesis_l2::L2Config, exact length):
  domain || configuration || elf_keccak || vkey_koalabear || vkey_bn254   5 x 32
  proof_policy (V3)                                                       32
  chain_id                                                                u64 little-endian
  initial_l2_parent || initial_l2_state                                   2 x 32

Every field must equal the mainnet pin (native release 78b7343a
l2_settlement::mainnet::PROGRAM, docs/MAINNET-PROGRAM.md); the inputs only
prove that the binaries you run agree with it:
  --identity FILE   JSON of `bloch-evm-sp1-settlement-v3 --mainnet identity settlement_v3_mainnet`
  --genesis FILE    JSON of `bloch-l2-produce-dev head --target DB --rules mainnet --domain ... --genesis-time ...`
                    right after `init` (number 0)
  --native-policy HEX  optional: policy_commitment_v3() of the native build
  --pins-only       build from the pins alone (no binaries checked)
  --out FILE        refuses to overwrite
The result's SHA-256 is 292f4fa8...4f6b (the file the 2026-10-18 rehearsal ran with).
Dependency-free Python 3.9+; no network, no keys.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

CONFIG_BYTES = 264
PINS = {
    'program': 'settlement_v3_mainnet',
    'chain_id': 700770,
    'domain': '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',
    'configuration': '8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b',
    'elf_keccak': '6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073',
    'vkey_koalabear': '389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e',
    'vkey_bn254': '007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e',
    'proof_policy_v3': '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d',
    'l2_genesis': '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468',
    'l2_genesis_state': '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d',
}
CONFIG_SHA256 = '292f4fa8d5a949a26c20317cfc9360d53afda4779b298f1841107985ca5c4f6b'
IDENTITY_FIELDS = ('domain', 'configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254')


def h32(value, name):
    if not isinstance(value, str):
        raise SystemExit(f'{name} must be 32 bytes of hex')
    value = value.lower().removeprefix('0x')
    if len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise SystemExit(f'{name} must be 32 bytes of hex')
    return bytes.fromhex(value)


def from_pins():
    out = b''.join(bytes.fromhex(PINS[k]) for k in IDENTITY_FIELDS) + bytes.fromhex(PINS['proof_policy_v3'])
    out += PINS['chain_id'].to_bytes(8, 'little') + bytes.fromhex(PINS['l2_genesis']) + bytes.fromhex(PINS['l2_genesis_state'])
    assert len(out) == CONFIG_BYTES and hashlib.sha256(out).hexdigest() == CONFIG_SHA256
    return out


def build(identity, genesis, native_policy=None):
    """The config from the binaries' own answers, refused unless every field equals the pin."""
    if identity.get('program') != PINS['program']:
        raise SystemExit('identity is not the settlement_v3_mainnet program (run the host with --mainnet)')
    if identity.get('chain_id') != PINS['chain_id']:
        raise SystemExit(f'identity chain id {identity.get("chain_id")} is not 700770')
    if identity.get('proof_policy_v3') is None:
        raise SystemExit('identity lacks proof_policy_v3: build the host with --features source-settlement')
    for key in IDENTITY_FIELDS + ('proof_policy_v3',):
        if h32(identity.get(key), key).hex() != PINS[key]:
            raise SystemExit(f'identity {key} differs from the mainnet pin')
    if native_policy is not None and h32(native_policy, '--native-policy').hex() != PINS['proof_policy_v3']:
        raise SystemExit('the native build disagrees on the V3 proof policy')
    if genesis.get('number') != 0:
        raise SystemExit('genesis JSON must be the head of a freshly initialised L2 database (number 0)')
    if h32(genesis.get('hash'), 'genesis hash').hex() != PINS['l2_genesis']:
        raise SystemExit('L2 genesis hash differs from the mainnet pin (wrong --rules/--domain/--genesis-time?)')
    if h32(genesis.get('state_root'), 'genesis state_root').hex() != PINS['l2_genesis_state']:
        raise SystemExit('L2 genesis state root differs from the mainnet pin')
    out = b''.join(h32(identity[k], k) for k in IDENTITY_FIELDS) + h32(identity['proof_policy_v3'], 'proof_policy_v3')
    out += identity['chain_id'].to_bytes(8, 'little') + h32(genesis['hash'], 'hash') + h32(genesis['state_root'], 'state_root')
    if out != from_pins():
        raise SystemExit('built config differs from the pinned mainnet config')
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--identity')
    p.add_argument('--genesis')
    p.add_argument('--native-policy')
    p.add_argument('--pins-only', action='store_true')
    p.add_argument('--out', required=True)
    a = p.parse_args(argv)
    if a.pins_only:
        if a.identity or a.genesis or a.native_policy:
            p.error('--pins-only takes no --identity/--genesis/--native-policy')
        config = from_pins()
    else:
        if not (a.identity and a.genesis):
            p.error('--identity and --genesis are required (or --pins-only)')
        config = build(json.loads(Path(a.identity).read_text()), json.loads(Path(a.genesis).read_text()),
                       a.native_policy)
    with open(a.out, 'xb') as f:
        f.write(config)
    print(json.dumps({'out': a.out, 'bytes': len(config), 'sha256': hashlib.sha256(config).hexdigest(),
                      'chain_id': PINS['chain_id'], 'proof_policy': config[160:192].hex()}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
