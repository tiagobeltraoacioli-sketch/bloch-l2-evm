#!/usr/bin/env python3
"""Remote settlement V3 Groth16 prover: an SSH forced command (development networks).

Installed on a second CPU host and bound to one dedicated key in
`authorized_keys`:

    command="/usr/bin/python3 /opt/bloch/l2-devnet4-prover/remote_prover.py",restrict ssh-ed25519 AAAA...

The settler (`settler_v3.py`, `remote_prover`) sends one framed job on stdin:

    b'BLOCH:L2:PROVE:1\\n' || u32 BE len || native-request.txt || u64 BE len || block.artifact

and receives the bincode Groth16 proof file on stdout (nothing else). The
pinned `bloch-evm-sp1-settlement-v3 prove-groth16 native-artifact` recomputes
the expected statement from the same request and artifact and reverifies the
proof before writing it; the settler verifies it again locally before any
submission, so this host is trusted for liveness only, never for validity.

One proof at a time (an exclusive lock; a second job exits 75 = busy). With
`max_memory_bytes` in the config the job refuses to start unless one of its
own cgroups (cgroup v2) caps memory at or below that value, so a prover sharing
a host with other services can only exhaust its own slice.
Holds no keys and reaches no network besides Docker for the pinned Gnark image.

Mainnet (chain 700770): the same script serves the `settlement_v3_mainnet`
program when its config has `"mainnet": true` (the pinned host then runs with
`--mainnet`, i.e. ChainSpec::mainnet and MAINNET_DOMAIN). A forced command may
name its config explicitly (`remote_prover.py --config PATH`), so a devnet and a
mainnet prover can share one release of this file without sharing a config.
Exit codes: 0 proof written, 64 bad request, 70 prover failed, 75 busy.
Dependency-free Python 3.9+.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

CONFIG = Path(os.environ.get('BLOCH_REMOTE_PROVER_CONFIG', '/etc/bloch-l2-devnet4-prover/config.json'))
MAGIC = b'BLOCH:L2:PROVE:1\n'
MAX_REQUEST_BYTES = 700  # the V3 host refuses longer native requests
MAX_ARTIFACT_BYTES = 64 << 20
MAX_PROOF_BYTES = 1 << 20


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError('truncated job')
    return data


def parse_job(stream):
    """Return (request, artifact) from one framed job; refuse anything else."""
    if read_exact(stream, len(MAGIC)) != MAGIC:
        raise ValueError('bad magic')
    (request_len,) = struct.unpack('>I', read_exact(stream, 4))
    if not 0 < request_len <= MAX_REQUEST_BYTES:
        raise ValueError('request length out of bounds')
    request = read_exact(stream, request_len)
    (artifact_len,) = struct.unpack('>Q', read_exact(stream, 8))
    if not 0 < artifact_len <= MAX_ARTIFACT_BYTES:
        raise ValueError('artifact length out of bounds')
    artifact = read_exact(stream, artifact_len)
    if stream.read(1):
        raise ValueError('trailing bytes after the job')
    request.decode('ascii')
    return request, artifact


def cgroup_memory_cap(proc_cgroup='/proc/self/cgroup', root='/sys/fs/cgroup'):
    """Smallest memory.max over this process's cgroup v2 path and its ancestors (None if unlimited)."""
    try:
        text = Path(proc_cgroup).read_text()
    except OSError:  # no cgroup v2 information: treat as unlimited
        return None
    line = next((l for l in text.splitlines() if l.startswith('0::')), None)
    if line is None:
        return None
    path, caps = Path(root + line[3:].strip()), []
    while True:
        limit = path / 'memory.max'
        if limit.is_file():
            value = limit.read_text().strip()
            if value != 'max':
                caps.append(int(value))
        if path == Path(root) or path.parent == path:
            break
        path = path.parent
    return min(caps) if caps else None


def config_path(argv, environ):
    """The config file: `--config PATH` on the forced command line, else the environment/default."""
    if not argv:
        return Path(environ.get('BLOCH_REMOTE_PROVER_CONFIG', str(CONFIG)))
    if len(argv) == 2 and argv[0] == '--config' and argv[1].startswith('/'):
        return Path(argv[1])
    raise ValueError('usage: remote_prover.py [--config /ABSOLUTE/PATH]')


def fail(code, message):
    sys.stderr.write(f'remote_prover: {message}\n')
    sys.exit(code)


def main():
    if os.environ.get('SSH_ORIGINAL_COMMAND', 'prove') != 'prove':
        fail(64, 'only the "prove" command is served')
    try:
        c = json.loads(config_path(sys.argv[1:], os.environ).read_text())
    except (ValueError, OSError) as error:
        fail(64 if isinstance(error, ValueError) and 'usage' in str(error) else 70, f'config: {error}')
    if not isinstance(c.get('mainnet', False), bool):
        fail(70, 'config: mainnet must be a boolean')
    for key in ('prover', 'guest'):
        if digest(c[key]) != c[key + '_sha256']:
            fail(70, f'{key} differs from its pin')
    if c.get('max_memory_bytes'):
        cap = cgroup_memory_cap()
        if cap is None or cap > c['max_memory_bytes']:
            fail(70, f'refusing to prove without a memory cap <= {c["max_memory_bytes"]} (cgroup cap {cap})')
    work = Path(c['workdir'])
    lock = (work / '.lock').open('w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fail(75, 'another proof is running')
    try:
        request, artifact = parse_job(sys.stdin.buffer)
    except (ValueError, UnicodeDecodeError) as error:
        fail(64, str(error))
    job = Path(tempfile.mkdtemp(prefix='job-', dir=work))
    try:
        (job / 'native-request.txt').write_bytes(request)
        (job / 'block.artifact').write_bytes(artifact)
        proof = job / 'settlement.proof'
        # Docker mounts host paths: temporary files must live in a host-visible directory.
        env = {'PATH': '/usr/bin:/bin', 'HOME': c['home'], 'TMPDIR': str(job),
               'RAYON_NUM_THREADS': str(c['prover_threads']), 'SP1_CIRCUIT_MODE': 'release',
               'SP1_GNARK_IMAGE': c['gnark_image'],
               'BLOCH_NATIVE_L2_REQUEST': str(job / 'native-request.txt'),
               'BLOCH_NATIVE_L2_ARTIFACT': str(job / 'block.artifact')}
        # `"mainnet": true` proves the mainnet program (settlement_v3_mainnet); the settler
        # verifies the result locally with the same flag, so a wrong program is never submitted.
        argv = [c['prover'], *(['--mainnet'] if c.get('mainnet') else []), 'prove-groth16', 'native-artifact',
                c['guest'], str(proof)]
        with (work / 'last-prove.log').open('w') as log:
            try:
                result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=log,
                                        stderr=subprocess.STDOUT, timeout=c.get('timeout_seconds', 3500))
            except subprocess.TimeoutExpired:
                fail(70, 'prover timed out')
        if result.returncode or not proof.is_file() or not 0 < proof.stat().st_size <= MAX_PROOF_BYTES:
            tail = (work / 'last-prove.log').read_text(errors='replace')[-2000:]
            fail(70, f'prover exited {result.returncode}:\n{tail}')
        sys.stdout.buffer.write(proof.read_bytes())
        sys.stdout.buffer.flush()
    finally:
        shutil.rmtree(job, ignore_errors=True)


if __name__ == '__main__':
    main()
