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
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

CONFIG = Path(os.environ.get('BLOCH_REMOTE_PROVER_CONFIG', '/etc/bloch-l2-devnet4-prover/config.json'))
MAGIC = b'BLOCH:L2:PROVE:1\n'
MAX_REQUEST_BYTES = 700  # the V3 host refuses longer native requests
MAX_ARTIFACT_BYTES = 64 << 20
MAX_PROOF_BYTES = 1 << 20
# Scheduling and shard-size settings of the SP1 6.8 prover. They change memory and time, never the
# program or the verifier: the arity settings and WITHOUT_VK_VERIFICATION are absent on purpose.
PROVER_ENV_ALLOWED = frozenset((
    'SP1_WORKER_NUM_CORE_WORKERS', 'SP1_WORKER_CORE_BUFFER_SIZE',
    'SP1_WORKER_NUM_SPLICING_WORKERS', 'SP1_WORKER_SPLICING_BUFFER_SIZE',
    'SP1_WORKER_GLOBAL_MEMORY_BUFFER_SIZE',
    'SP1_WORKER_NUM_SETUP_WORKERS', 'SP1_WORKER_SETUP_BUFFER_SIZE',
    'SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS', 'SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE',
    'SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS', 'SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE',
    'SP1_WORKER_NUM_RECURSION_PROVER_WORKERS', 'SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE',
    'ELEMENT_THRESHOLD',
))


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


def prover_env(config):
    """The optional low-memory settings of the config. Anything outside the list refuses the job."""
    settings = config.get('prover_env', {})
    if not isinstance(settings, dict):
        raise ValueError('prover_env must be an object')
    for name, value in settings.items():
        if name not in PROVER_ENV_ALLOWED:
            raise ValueError(f'prover_env {name} is not allowed')
        if not isinstance(value, str) or not value.isascii() or not value.isdigit() or int(value) < 1:
            raise ValueError(f'prover_env {name} must be a positive decimal string')
    return dict(settings)


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


def client_gone(fd=1):
    """True once the reader of the job's stdout (the SSH channel) has closed it."""
    poller = select.poll()
    poller.register(fd, select.POLLOUT)  # with POLLOUT, macOS also reports the hangup of a pipe
    return any(events & (select.POLLERR | select.POLLHUP | select.POLLNVAL) for _, events in poller.poll(0))


def stop_group(process):
    """Stop the prover and everything it started, so the job lock and the memory are really released."""
    for number, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 10)):
        try:
            os.killpg(process.pid, number)
        except ProcessLookupError:
            return
        try:
            process.wait(grace)
            break
        except subprocess.TimeoutExpired:
            pass
    try:  # the leader is gone; whatever else of the group is left (the native runner) goes too
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    time.sleep(0.2)  # let the kernel tear down the killed processes' mappings


def group_segments(pgid, directory):
    """The SP1 shared-memory files (`sp1_*`, `sem.sp1_*` under `directory`) that processes of group `pgid` map or hold."""
    found, prefix = set(), str(directory).rstrip('/') + '/'
    for proc in Path('/proc').iterdir() if Path('/proc').is_dir() else ():
        if not proc.name.isdigit():
            continue
        try:
            stat = (proc / 'stat').read_text()
            if int(stat.rsplit(')', 1)[1].split()[2]) != pgid:
                continue
            paths = [line.split(None, 5)[5] for line in (proc / 'maps').read_text().splitlines() if len(line.split(None, 5)) == 6]
            paths += [os.readlink(fd) for fd in (proc / 'fd').iterdir()]
        except (OSError, ValueError, IndexError):
            continue
        for path in paths:
            path = path.replace(' (deleted)', '')
            name = path[len(prefix):] if path.startswith(prefix) else ''
            if name.startswith(('sp1_', 'sem.sp1_')) and '/' not in name:
                found.add(path)
    return found


def segment_mapped(path):
    """Whether any process we can see maps or holds `path`. Processes of other users cannot be read; they cannot have
    opened this user's segment either (mode 0600), unless they run as root."""
    target = str(path)
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if target in (proc / 'maps').read_text():
                return True
            if any(os.readlink(fd) == target for fd in (proc / 'fd').iterdir()):
                return True
        except OSError:
            continue
    return False


def remove_leaked_segments(paths, mapped=segment_mapped):
    """Remove the given segments, which this run's prover processes mapped, once no process maps them. A killed SP1 native
    runner never unlinks its segments (4.7 GB each in /dev/shm), and a full /dev/shm makes every later SP1 run on the
    host crash. Only segments seen mapped by this run's own process group are candidates: nothing another job created."""
    removed, paths = [], set(paths)
    for path in list(paths):  # the semaphores of a segment this group used carry its name: sem.sp1_<id>_t_empty, _filled
        head, name = os.path.split(path)
        if name.startswith('sp1_'):
            paths |= {os.path.join(head, f'sem.{name}_{end}') for end in ('empty', 'filled')}
    for path in sorted(paths):
        try:
            if not os.path.exists(path) or mapped(path):
                continue
            os.unlink(path)
            removed.append(os.path.basename(path))
        except OSError:
            continue
    if removed:
        print(json.dumps({'event': 'prover-shm-removed', 'segments': removed}), file=sys.stderr, flush=True)
    return removed


def run_while_client_connected(argv, env, log, timeout, gone=client_gone, poll_seconds=1, shm='/dev/shm'):
    """Run the prover in its own process group. A proof nobody can receive holds the lock and tens of GB
    for its whole duration and makes every retry of the restarted settler exit 75, so a dead client or
    the timeout stops the whole group at once. The SP1 shared-memory segments the group mapped are unlinked
    afterwards: a killed native runner never does it, and they outlive this process in /dev/shm."""
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    deadline = time.monotonic() + timeout
    ours = set()

    def finish(reason=None):
        ours.update(group_segments(process.pid, shm))
        stop_group(process)
        remove_leaked_segments(ours)
        if reason:
            fail(70, reason)
    while True:
        ours.update(group_segments(process.pid, shm))
        try:
            code = process.wait(poll_seconds)
        except subprocess.TimeoutExpired:
            code = None
        if code is not None:
            finish()
            return code
        if gone():
            finish('client disconnected: proof abandoned')
        if time.monotonic() >= deadline:
            finish('prover timed out')


def main():
    if os.environ.get('SSH_ORIGINAL_COMMAND', 'prove') != 'prove':
        fail(64, 'only the "prove" command is served')
    try:
        c = json.loads(config_path(sys.argv[1:], os.environ).read_text())
    except (ValueError, OSError) as error:
        fail(64 if isinstance(error, ValueError) and 'usage' in str(error) else 70, f'config: {error}')
    if not isinstance(c.get('mainnet', False), bool):
        fail(70, 'config: mainnet must be a boolean')
    try:
        tuning = prover_env(c)
    except ValueError as error:
        fail(70, f'config: {error}')
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
               'BLOCH_NATIVE_L2_ARTIFACT': str(job / 'block.artifact'), **tuning}
        # `"mainnet": true` proves the mainnet program (settlement_v3_mainnet); the settler
        # verifies the result locally with the same flag, so a wrong program is never submitted.
        argv = [c['prover'], *(['--mainnet'] if c.get('mainnet') else []), 'prove-groth16', 'native-artifact',
                c['guest'], str(proof)]
        with (work / 'last-prove.log').open('w') as log:
            returncode = run_while_client_connected(argv, env, log, c.get('timeout_seconds', 3500))
        if returncode or not proof.is_file() or not 0 < proof.stat().st_size <= MAX_PROOF_BYTES:
            tail = (work / 'last-prove.log').read_text(errors='replace')[-2000:]
            fail(70, f'prover exited {returncode}:\n{tail}')
        sys.stdout.buffer.write(proof.read_bytes())
        sys.stdout.buffer.flush()
    finally:
        shutil.rmtree(job, ignore_errors=True)


if __name__ == '__main__':
    main()
