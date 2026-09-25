#!/usr/bin/env python3
"""Prepare or verify a component release checkpoint using the pinned native PQ tool.

No network, wallet unlock, deployment, custody transfer or activation. The same
adapter is distributed with L2, DEX and bridge; COMPONENT is fixed per repository.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time

COMPONENT = 'l2'
ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1_048_576


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(path, maximum=LIMIT):
    with Path(path).open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, 'input size limit')
    return raw


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def parse(raw):
    def reject(_):
        raise ValueError('floating point/nonfinite value forbidden')
    return json.loads(raw, object_pairs_hook=unique, parse_float=reject, parse_constant=reject)


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode()


def sha3(raw):
    return hashlib.sha3_256(raw).hexdigest()


def artifact_path(root, value):
    require(type(value) is str and 0 < len(value) <= 512, 'invalid artifact path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == value,
            'artifact path must be normalized and relative')
    target = (root / value).resolve(strict=True)
    require(target.is_relative_to(root.resolve()) and target.is_file(), 'artifact outside reviewed root')
    return target


def checked_artifacts(root, raw):
    doc = parse(raw)
    require(type(doc) is dict and set(doc) == {'schema', 'component', 'files'}
            and doc['schema'] == 'bloch.component-artifacts.v1' and doc['component'] == COMPONENT,
            'wrong component artifact manifest')
    require(type(doc['files']) is list and 1 <= len(doc['files']) <= 256, 'bounded artifacts required')
    seen = set()
    for item in doc['files']:
        require(type(item) is dict and set(item) == {'path', 'sha3'}, 'invalid artifact entry')
        require(type(item['path']) is str and item['path'] not in seen, 'duplicate artifact path')
        seen.add(item['path'])
        target = artifact_path(root, item['path'])
        require(sha3(read(target, 64 * LIMIT)) == item['sha3'], 'reviewed artifact content changed')
    return doc


def native(args, command, documents):
    # Execute an immutable private snapshot of the exact hash-pinned binary and
    # inputs. Downloaded metadata cannot select another verifier implementation.
    binary = read(args.verifier, 256 * LIMIT)
    require(re.fullmatch('[0-9a-f]{64}', args.verifier_sha3) is not None
            and sha3(binary) == args.verifier_sha3, 'verifier SHA3 pin mismatch')
    with tempfile.TemporaryDirectory(prefix='bloch-checkpoint-') as tmp:
        directory = Path(tmp)
        executable = directory / 'verifier'
        executable.write_bytes(binary)
        executable.chmod(0o500)
        for name, raw in documents.items():
            (directory / name).write_bytes(raw)
            (directory / name).chmod(0o400)
        result = subprocess.run([str(executable), *command], cwd=directory, capture_output=True,
                                timeout=60, check=False)
        require(result.returncode == 0, 'native checkpoint verification refused: ' + result.stderr.decode('utf-8', errors='replace')[:400])
        require(len(result.stdout) <= LIMIT, 'native output limit')
        return parse(result.stdout)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    manifest = sub.add_parser('manifest', help='Hash explicit public source/build artifacts')
    manifest.add_argument('--root', type=Path, default=ROOT)
    manifest.add_argument('--file', action='append', required=True)
    for command in ['prepare', 'verify']:
        p = sub.add_parser(command)
        p.add_argument('--root', type=Path, default=ROOT)
        p.add_argument('--verifier', type=Path, required=True)
        p.add_argument('--verifier-sha3', required=True)
        p.add_argument('--registry', type=Path, required=True)
        p.add_argument('--configuration', type=Path, required=True)
        p.add_argument('--artifacts', type=Path, required=True)
        if command == 'prepare':
            p.add_argument('--chain-id', required=True)
            p.add_argument('--genesis', required=True)
            p.add_argument('--finalized-header', type=Path, required=True,
                           help='Independently reviewed JSON: height, hash, state_root')
            p.add_argument('--sequence', type=int, required=True)
            p.add_argument('--previous', required=True)
            p.add_argument('--lifetime-seconds', type=int, default=30 * 86400)
            p.add_argument('--output', type=Path, required=True, help='New private ceremony directory')
        else:
            p.add_argument('--envelope', type=Path, required=True)
            p.add_argument('--trust', type=Path, required=True)
            p.add_argument('--trust-sha3', required=True, help='Pin obtained independently from reviewers')
    args = parser.parse_args(argv)
    if args.command == 'manifest':
        require(len(args.file) == len(set(args.file)) and len(args.file) <= 256, 'duplicate/oversized artifact set')
        return {'schema': 'bloch.component-artifacts.v1', 'component': COMPONENT,
                'files': [{'path': p, 'sha3': sha3(read(artifact_path(args.root, p), 64 * LIMIT))}
                          for p in sorted(args.file)]}
    artifacts, configuration, registry = read(args.artifacts), read(args.configuration), read(args.registry)
    checked_artifacts(args.root, artifacts)
    docs = {'registry.json': registry}
    if args.command == 'prepare':
        registry_hash = native(args, ['registry-id', 'registry.json'], docs)['registry_sha3']
        header = parse(read(args.finalized_header))
        require(type(header) is dict and set(header) == {'height', 'hash', 'state_root'}, 'invalid finalized header')
        now = int(time.time())
        require(0 < args.lifetime_seconds <= 456 * 86400, 'invalid lifetime')
        cp = dict(version=1, component=COMPONENT, chain_id=args.chain_id, genesis=args.genesis,
                  sequence=args.sequence, previous=args.previous, issued_at=now, expires_at=now + args.lifetime_seconds,
                  finalized_height=header['height'], finalized_hash=header['hash'], state_root=header['state_root'],
                  configuration_sha3=sha3(configuration), artifacts_sha3=sha3(artifacts), registry_sha3=registry_hash)
        docs['payload.json'] = encoded(cp)
        envelope = native(args, ['prepare', 'registry.json', 'payload.json'], docs)
        trust = dict(version=1, component=COMPONENT, chain_id=cp['chain_id'], genesis=cp['genesis'],
                     registry_sha3=registry_hash, configuration_sha3=cp['configuration_sha3'],
                     artifacts_sha3=cp['artifacts_sha3'], next_sequence=cp['sequence'], previous=cp['previous'],
                     minimum_finalized_height=cp['finalized_height'], maximum_age_seconds=args.lifetime_seconds)
        trust_raw = encoded(trust)
        docs.update({'unsigned-envelope.json': encoded(envelope), 'trust.pending.json': trust_raw,
                     'configuration.json': configuration, 'artifacts.json': artifacts})
        # Validate everything before creating output; never replace another ceremony.
        args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name, raw in docs.items():
            with (args.output / name).open('xb') as stream:
                stream.write(raw)
            (args.output / name).chmod(0o600)
        return {'component': COMPONENT, 'signatures': 0, 'checkpoint_verified': False,
                'activation_authorized': False, 'trust_pending_sha3': sha3(trust_raw),
                'notice': 'Review and pin the trust file independently before accepting signatures.'}
    trust_raw = read(args.trust)
    require(sha3(trust_raw) == args.trust_sha3, 'independent trust SHA3 pin mismatch')
    trust = parse(trust_raw)
    require(trust.get('component') == COMPONENT, 'cross-component checkpoint refused')
    require(trust.get('configuration_sha3') == sha3(configuration)
            and trust.get('artifacts_sha3') == sha3(artifacts), 'reviewed input pin mismatch')
    docs.update({'envelope.json': read(args.envelope), 'trust.json': trust_raw})
    result = native(args, ['verify', 'registry.json', 'envelope.json', 'trust.json', args.trust_sha3], docs)
    require(result.get('component') == COMPONENT and result.get('activation_authorized') is False,
            'unexpected native verifier result')
    result['checkpoint_verified'] = True
    result['reviewed_artifact_count'] = len(parse(artifacts)['files'])
    return result


if __name__ == '__main__':
    try:
        print(json.dumps(main(), indent=2, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        print(json.dumps({'checkpoint_verified': False, 'activation_authorized': False,
                          'error': str(error)[:500]}), file=sys.stderr)
        sys.exit(1)
