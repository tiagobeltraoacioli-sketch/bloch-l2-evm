#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Assemble the 3-of-5 attestation of a Bloch L2 MAINNET withdrawal claim (>= 100 BLCH) from the
attestor agents' partials, and verify it with the native code before any transaction is built.

  aggregate_attestation.py --proof PROOF.json --source DIR_OR_URL [--source ...] --out DIR
        [--bloch-pos BIN] [--genesis mainnet.manifest] [--attestors attestors.set]
        [--rpc URL --rpc URL --rpc URL]

--proof   the claim's withdrawal proof (bloch-l2-produce-dev withdrawal-proof) against the root the
          claim will prove against: for >= 100 BLCH, getl2settlement withdrawals.matured_large.
--source  a drop holding `<chain>/<root>/attestor-<i>.partial` (an agent outbox directory, a
          shared directory, or an HTTP(S) base URL). Several sources are merged; for each signer
          the first well-formed partial over the expected digest is kept.
--rpc     optional: require a 2-of-3 quorum to report the proof's root as matured_large now.

Output: DIR/attestor-<i>.partial for the first `threshold` valid signers, DIR/aggregate.json, and
the `bloch-pos l2-claim prepare` arguments. The native `l2-claim verify-attestation` (the same
`Attestation::verify` the claim transition runs) must accept the set before anything is written.
Read-only: no key, no transaction.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import attestor_lib as lib  # noqa: E402


def fetch(source, relpath):
    if source.startswith(('http://', 'https://')):
        try:
            with urllib.request.urlopen(source.rstrip('/') + '/' + relpath, timeout=20) as response:
                return response.read(100_000).decode()
        except Exception:  # noqa: BLE001 - a missing partial is normal
            return None
    path = Path(source) / relpath
    return path.read_text() if path.is_file() else None


def rpc_matured_large(urls):
    answers = {}
    for url in urls:
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'getl2settlement', 'params': []}).encode()
        try:
            request = urllib.request.Request(url, data=body, headers={'content-type': 'application/json'})
            with urllib.request.urlopen(request, timeout=15) as response:
                matured = json.loads(response.read())['result']['withdrawals']['matured_large']
        except Exception:  # noqa: BLE001
            continue
        key = lib.canonical(matured)
        answers[key] = answers.get(key, 0) + 1
    best = max(answers.items(), key=lambda kv: kv[1], default=(None, 0))
    return json.loads(best[0]) if best[1] >= 2 else 'no-quorum'


def aggregate(proof_path, sources, out, bloch_pos, genesis, attestors, pins=lib.MAINNET, rpc=()):
    doc = json.loads(Path(proof_path).read_text())
    proof = lib.check_proof(doc, pins.chain_id)
    root = proof['root']
    threshold, keys = lib.read_set(attestors)
    if lib.set_hash(threshold, keys) != pins.set_hash:
        raise SystemExit('the attestor set file is not the pinned set')
    if lib.sha256_file(genesis) != pins.manifest_sha256:
        raise SystemExit('the genesis manifest is not the pinned one')
    if rpc:
        matured = rpc_matured_large(rpc)
        if matured == 'no-quorum' or not matured or matured.get('root') != root:
            raise SystemExit(f'the proof root {root} is not the quorum matured_large root ({matured}); '
                             'regenerate the proof against withdrawals.matured_large')
    if proof['sats'] < pins.large_claim_sat:
        print(f'note: {proof["sats"]} sat is below large_claim_sat; the claim needs no attestation', file=sys.stderr)
    digest = lib.attestation_digest(pins.network, pins.chain_id, root)
    chosen, problems = {}, []
    for index in range(len(keys)):
        for source in sources:
            text = fetch(source, lib.partial_relpath(pins.chain_id, root, index))
            if text is None:
                continue
            try:
                signer, signed, _ = lib.parse_partial(text)
            except ValueError as e:
                problems.append(f'{source} attestor {index}: {e}')
                continue
            if signer != index or signed != digest:
                problems.append(f'{source} attestor {index}: signs another index or digest')
                continue
            chosen[index] = text
            break
    if len(chosen) < threshold:
        raise SystemExit(f'only {len(chosen)} of the {threshold} required partials for root {root} '
                         f'(signers {sorted(chosen)}); problems: {problems}')
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    files = []
    for index in sorted(chosen)[:threshold]:
        path = out / f'attestor-{index}.partial'
        path.write_text(chosen[index])
        files.append(str(path))
    args = [bloch_pos, 'l2-claim', 'verify-attestation', '--genesis', genesis, '--proof', str(proof_path),
            '--attestors', attestors, '--expect-set-hash', pins.set_hash]
    for path in files:
        args += ['--attestation', path]
    done = subprocess.run(args, capture_output=True, text=True)
    if done.returncode:
        for path in files:
            Path(path).unlink()
        raise SystemExit(f'native verification refused the attestation: {done.stderr.strip()}')
    summary = {'chain_id': pins.chain_id, 'root': root, 'digest': digest, 'set_hash': pins.set_hash,
               'signers': sorted(chosen)[:threshold], 'available': sorted(chosen), 'withdrawal': proof,
               'native_verify': done.stdout.strip(), 'problems': problems,
               'prepare_args': ['--attestors', attestors] + [x for f in files for x in ('--attestation', f)]}
    (out / 'aggregate.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    return summary


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('--proof', required=True)
    p.add_argument('--source', action='append', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--bloch-pos', default='bloch-pos')
    p.add_argument('--genesis', default='mainnet.manifest')
    p.add_argument('--attestors', default='attestors.set')
    p.add_argument('--rpc', action='append', default=[])
    a = p.parse_args(argv)
    summary = aggregate(a.proof, a.source, a.out, a.bloch_pos, a.genesis, a.attestors, rpc=a.rpc)
    print(summary['native_verify'])
    print('prepare the claim with (offline; sign and broadcast are separate steps):')
    print(' '.join([a.bloch_pos, 'l2-claim', 'prepare', '--genesis', a.genesis, '--funding-pubkey', 'FUNDING.pk',
                    '--input', 'TXID:VOUT:SAT', '--proof', a.proof, '--base-fee', 'N', '--tip', 'N',
                    *summary['prepare_args'], '--out', 'claim.unsigned']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
