#!/usr/bin/env python3
"""Assemble the native `l2_settlement::mainnet::PROGRAM` pins for chain 700770.

The native activation (bloch-sis-pow `crates/bloch-pos-committee/src/l2_settlement.rs`,
module `mainnet`) pins seven V2 identities, the proof policy and the L2 genesis:

  identities[0]  Genesis-4 admission network domain (SHA3-256 of the manifest encoding)
  identities[1]  Genesis-4 native genesis block id
  identities[2]  L2 V2 domain (MAINNET_DOMAIN)
  identities[3]  execution configuration commitment (ChainSpec::mainnet)
  identities[4]  settlement_v3_mainnet ELF Keccak-256
  identities[5]  SP1 KoalaBear verifying-key hash
  identities[6]  SP1 BN254 verifying-key hash
  proof_policy   policy_commitment_v3() (native) == identity proof_policy_v3 (L2 host)
  initial_l2_parent / initial_l2_state  L2 genesis header hash / state root

Inputs (no network, no keys):
  --identity FILE   `bloch-evm-sp1-settlement-v3 --mainnet-v1 identity settlement_v3_mainnet` (this kit's host
                    takes --mainnet for the next rules), or, for the program swap (CANDIDATE),
                    `--mainnet --sparse identity settlement_v3_mainnet_sparse`, which prints `PROGRAM_NEXT`
  --const NAME      the Rust constant (default from the program: PROGRAM, PROGRAM_NEXT); PROGRAM_FALLBACK
                    takes the complete-witness guest's `--mainnet identity` under the next rules
  --genesis FILE    `bloch-l2-produce-dev --rules mainnet --domain D --genesis-time T head`
                    right after `init` (number 0)
  --native-policy HEX   native `policy_commitment_v3()` (print_policy_commitment_v3)
  --network HEX     Genesis-4 admission domain
  --native-genesis HEX  Genesis-4 genesis block id
  --elf FILE        optional: the ELF; its SHA-256 is reported (the Keccak-256
                    identity comes from the host, the stdlib has no Keccak)
Prints JSON with the values and the Rust `Program` literal. Refuses any mismatch.
Dependency-free Python 3.9+.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

CHAIN_ID = 700770
PROGRAM = 'settlement_v3_mainnet'
# The host's program name, and the native constant it fills by default.
PROGRAMS = {'settlement_v3_mainnet': 'PROGRAM', 'settlement_v3_mainnet_sparse': 'PROGRAM_NEXT'}
CONSTS = ('PROGRAM', 'PROGRAM_NEXT', 'PROGRAM_FALLBACK')
DEVNET_DOMAIN = 'd3' * 32


def h32(value, name):
    value = value.lower().removeprefix('0x')
    if len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise SystemExit(f'{name} must be 32 bytes of hex')
    if value == '0' * 64:
        raise SystemExit(f'{name} must not be zero')
    return value


def rust(name, value):
    pairs = ', '.join(f'0x{value[i:i + 2]}' for i in range(0, 64, 2))
    return f'{name}[{pairs}]'


def build(identity, genesis, native_policy, network, native_genesis, const=None):
    program = identity.get('program')
    if program not in PROGRAMS or identity.get('chain_id') != CHAIN_ID:
        raise SystemExit(f'identity is not a {"/".join(PROGRAMS)} program of chain {CHAIN_ID}')
    const = const or PROGRAMS[program]
    if const not in CONSTS:
        raise SystemExit(f'--const must be one of {", ".join(CONSTS)}')
    if program == 'settlement_v3_mainnet_sparse' and const != 'PROGRAM_NEXT':
        raise SystemExit('the sparse-witness guest is the next program only')
    if identity.get('domain') == DEVNET_DOMAIN:
        raise SystemExit('identity carries the development domain')
    if identity.get('proof_policy_v3') is None:
        raise SystemExit('identity lacks proof_policy_v3: build the host with --features source-settlement')
    policy = h32(identity['proof_policy_v3'], 'proof_policy_v3')
    if policy != h32(native_policy, '--native-policy'):
        raise SystemExit('L2 host and native build disagree on the V3 proof policy')
    if genesis.get('number') != 0:
        raise SystemExit('genesis JSON must be the head of a freshly initialised L2 database (number 0)')
    identities = [h32(network, '--network'), h32(native_genesis, '--native-genesis')] + [
        h32(identity[k], k) for k in ('domain', 'configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254')]
    if len(set(identities)) != 7:
        raise SystemExit('identities must be distinct')
    parent, state = h32(genesis['hash'], 'genesis hash'), h32(genesis['state_root'], 'genesis state_root')
    names = ['genesis4_network', 'genesis4_genesis', 'l2_domain', 'configuration', 'elf_keccak',
             'vkey_koalabear', 'vkey_bn254']
    if const != 'PROGRAM':
        # `NextProgram`: identities 3 to 6 and the policy; 0 to 2, the genesis and the attestor set stay.
        literal = f'pub const {const}: NextProgram = NextProgram {{\n    identities: [\n'
        for n, v in list(zip(names, identities))[3:]:
            literal += f'        // {n}\n        h32("{v}"),\n'
        literal += f'    ],\n    proof_policy: h32("{policy}"),\n}};\n'
    else:
        literal = f'pub const {const}: Option<Program> = Some(Program {{\n    identities: [\n'
        for n, v in zip(names, identities):
            literal += f'        // {n}\n        {rust("", v)},\n'
        literal += f'    ],\n    proof_policy: {rust("", policy)},\n'
        literal += f'    initial_l2_parent: {rust("", parent)},\n    initial_l2_state: {rust("", state)},\n}});\n'
    return {'chain_id': CHAIN_ID, 'program': program, 'const': const, 'identities': dict(zip(names, identities)),
            'proof_policy': policy, 'initial_l2_parent': parent, 'initial_l2_state': state,
            'sp1_circuit_version': identity.get('sp1_circuit_version'), 'rust': literal}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for flag in ('--identity', '--genesis', '--native-policy', '--network', '--native-genesis'):
        p.add_argument(flag, required=True)
    p.add_argument('--elf')
    p.add_argument('--const', choices=CONSTS)
    a = p.parse_args(argv)
    out = build(json.loads(Path(a.identity).read_text()), json.loads(Path(a.genesis).read_text()),
                a.native_policy, a.network, a.native_genesis, a.const)
    if a.elf:
        out['elf_sha256'] = hashlib.sha256(Path(a.elf).read_bytes()).hexdigest()
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    sys.exit(main())
