#!/usr/bin/env python3
"""Install (or roll back) the Bloch L2 MAINNET settlement prover (chain 700770) on a CPU host.

Same wiring as the devnet4 prover (deployment/devnet/remote_prover.py on 140.82.35.231):
the settler host (settler_v3.py, `remote_prover` config) sends one framed job
(native request + execution artifact) over SSH to a forced command bound to one
dedicated key, and gets the Groth16 proof file back. The settler re-runs
`execute` before and `verify-groth16` after with its own pinned host and guest, so
this host is trusted for liveness only, never for validity. It holds no keys and
needs no inbound port besides sshd; outbound only Docker's pinned Gnark image
(pulled before install) - the SP1 Groth16 circuit files are seeded from --circuits.

Run as root from a directory holding:
  bloch-evm-sp1-settlement-v3   host built by build-program.sh (features source-settlement,node-artifact)
  settlement_v3_mainnet         guest ELF, SHA-256 203114bf...c473 (build-reproducible.sh)
  remote_prover.py              deployment/devnet/remote_prover.py (with --config / "mainnet"), SHA-256 3c11d9be...c8e5
  SHA256SUMS                    sha256sum of the three files above (reviewed by the operator)

  sudo python3 install-prover-mainnet.py install --settler-pubkey FILE --settler-host IP \\
      --circuits DIR [--memory-gib 100] [--threads 32] [--prover-env NAME=VALUE ...]
      [--timeout-seconds 5400] [--dry-run]

The defaults are the measured settings below: --threads 32, ELEMENT_THRESHOLD=268435456, 5,400 s.

Measured 2026-11-02 on 32 vCPU / 125 GiB hosts (agents/93-prover-tuning.md), empty block 8191:
SP1 defaults OOM at 100 GiB; --threads 32 --prover-env ELEMENT_THRESHOLD=268435456 proves in
2,731-2,809 s at 84-85 GiB, so it also needs --timeout-seconds 5400 and a settler remote
timeout above it.
  sudo python3 install-prover-mainnet.py rollback [--dry-run]

install refuses unless: the guest and remote_prover.py have their pinned SHA-256 (a SHA256SUMS
beside them is the operator's review aid and proves nothing about which version this is); the host's `--mainnet identity`
prints exactly the program the native mainnet activation pins (ELF Keccak, KoalaBear and
BN254 vkeys, proof policy, domain, configuration); the Gnark image is present; nothing is
installed yet; MemAvailable covers the cap + 20 GiB (Gnark container, outside the slice). It creates the system user
bloch-l2-prover-mainnet (docker group, no password, no login besides the forced command),
/opt/bloch/l2-mainnet-prover, /etc/bloch-l2-mainnet-prover/config.json,
/var/lib/bloch-l2-mainnet-prover and a user-slice drop-in (MemoryMax, CPUQuota, no swap);
remote_prover.py refuses to prove outside that cap. No service is started: the prover
runs only when the settler connects. rollback removes exactly what install recorded in
/etc/bloch-l2-mainnet-prover/installed.json (refusing while a proof is running).
"""
import argparse
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys

USER = 'bloch-l2-prover-mainnet'
RELEASE = Path('/opt/bloch/l2-mainnet-prover')
ETC = Path('/etc/bloch-l2-mainnet-prover')
STATE = Path('/var/lib/bloch-l2-mainnet-prover')
FILES = ('bloch-evm-sp1-settlement-v3', 'settlement_v3_mainnet', 'remote_prover.py')
GNARK_IMAGE = 'ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d'
GUEST_SHA256 = '203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473'
# Stops the prover group on client disconnect. The older 99bbc1bc... does not, and sits in staging with a passing SHA256SUMS.
# Agent 93's measured low-memory setting, used unless --prover-env is given.
DEFAULT_PROVER_ENV = ['ELEMENT_THRESHOLD=268435456']
REMOTE_PROVER_SHA256 = 'ba309912cbb7faeb961eab80ade93e9cb2f4ebbaeb4df0a6904b3df53534ad0a'
# bloch-sis-pow l2_settlement::mainnet::PROGRAM (set at 78b7343a, active since epoch 5850; unchanged
# in the armed release 78d4921c and in fa980367).
PINNED = {
    'chain_id': 700770,
    'domain': '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',
    'configuration': '8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b',
    'elf_keccak': '6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073',
    'vkey_koalabear': '389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e',
    'vkey_bn254': '007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e',
    'sp1_circuit_version': 'v6.1.0',
    'proof_policy_v3': '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d',
}
# Measured on 136.244.93.186 (Cascade Lake, 32 vCPU, 2026-10-30) at 8 threads: prover peak RSS 20.4 GiB
# (empty block), 25.5 GiB (5 txs), 45.2 GiB (50 transfers), 96.5 GiB (200 transfers). The default 100 GiB
# (MemoryHigh 96) is sized for the settler's max_block_txs 128 as transfers, about 72 GiB by extrapolation.
# Gas-heavy blocks are unmeasured. Below 32 GiB even a small block can OOM.
MIN_MEMORY_GIB = 32
# The Gnark Groth16 container runs under dockerd, outside the slice, and peaks at ~18.5 GB.
HEADROOM_GIB = 20


def die(message):
    raise SystemExit(f'install-prover-mainnet: {message}')


def run(argv, **kw):
    return subprocess.run([str(a) for a in argv], check=True, capture_output=True, text=True, **kw).stdout


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_sizes(memory_gib, threads):
    if memory_gib < MIN_MEMORY_GIB:
        die(f'--memory-gib must be >= {MIN_MEMORY_GIB} (even a small mainnet proof peaks above 25 GiB)')
    if not 1 <= threads <= 63:
        die('--threads must be within 1..63')


def check_identity(text):
    """The host's `--mainnet identity` output must be exactly the natively pinned program."""
    try:
        identity = json.loads(text)
    except ValueError:
        die('host identity is not JSON')
    if identity.get('program') != 'settlement_v3_mainnet':
        die(f'host identity is for {identity.get("program")!r}, not settlement_v3_mainnet')
    for key, value in PINNED.items():
        if identity.get(key) != value:
            die(f'identity {key} = {identity.get(key)!r}, mainnet pins {value!r}')
    return identity


def slice_dropin(memory_gib, threads):
    return ('# Bloch L2 mainnet prover: a proof may only use its own slice (install-prover-mainnet.py)\n'
            '[Slice]\n'
            f'MemoryHigh={memory_gib - 4}G\nMemoryMax={memory_gib}G\nMemorySwapMax=0\n'
            f'CPUQuota={threads * 100}%\nTasksMax=512\n')


def authorized_line(key, settler_host, release, config):
    key = key.strip()
    if not key.startswith('ssh-ed25519 ') or '\n' in key or '"' in key:
        die('expected one ssh-ed25519 public key line')
    if not settler_host or any(c in settler_host for c in '",\n '):
        die('bad --settler-host')
    return (f'restrict,from="{settler_host}",command="/usr/bin/python3 {release}/remote_prover.py '
            f'--config {config}" {key}\n')


def allowed_prover_env():
    """The list of the remote_prover.py this kit ships (next to this file in a release, in devnet/ in the repo)."""
    here = Path(__file__).resolve().parent
    for path in (here / FILES[2], here.parent.parent / 'devnet' / FILES[2]):
        if path.is_file():
            for node in ast.parse(path.read_text()).body:
                if isinstance(node, ast.Assign) and node.targets[0].id == 'PROVER_ENV_ALLOWED':
                    return frozenset(ast.literal_eval(node.value.args[0]))
    die('remote_prover.py with PROVER_ENV_ALLOWED not found')


def parse_prover_env(items):
    """NAME=VALUE options of --prover-env, refused here with the same rule remote_prover.py applies per job."""
    settings, allowed = {}, allowed_prover_env()
    for item in items or ():
        name, separator, value = item.partition('=')
        if not separator or name not in allowed or not value.isascii() \
                or not value.isdigit() or int(value) < 1:
            die(f'bad --prover-env {item!r}')
        settings[name] = value
    return settings


def prover_config(release, state, prover_sha256, threads, memory_gib, prover_env=None, timeout_seconds=3500):
    return {'mainnet': True,
            'prover': str(release / FILES[0]), 'prover_sha256': prover_sha256,
            'guest': str(release / FILES[1]), 'guest_sha256': GUEST_SHA256,
            'workdir': str(state / 'work'), 'home': str(state / 'work'),
            'prover_threads': threads, 'gnark_image': GNARK_IMAGE,
            'timeout_seconds': timeout_seconds, 'max_memory_bytes': memory_gib << 30,
            **({'prover_env': prover_env} if prover_env else {})}


def mem_available_gib():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) >> 20
    die('no MemAvailable')


def install(args, here):
    check_sizes(args.memory_gib, args.threads)
    sums = {}
    for line in (here / 'SHA256SUMS').read_text().splitlines():
        if line.strip():
            value, name = line.split()
            sums[Path(name.lstrip('*')).name] = value
    for name in FILES:
        if digest(here / name) != sums.get(name):
            die(f'{name} differs from SHA256SUMS')
    if sums[FILES[1]] != GUEST_SHA256:
        die('settlement_v3_mainnet is not the pinned guest')
    if sums[FILES[2]] != REMOTE_PROVER_SHA256:
        die(f'remote_prover.py is {sums[FILES[2]]}, not the pinned {REMOTE_PROVER_SHA256}')
    identity = check_identity(run([here / FILES[0], '--mainnet', 'identity', here / FILES[1]]))
    circuits = Path(args.circuits)
    if not (circuits / 'groth16').is_dir():
        die(f'{circuits}/groth16 missing (SP1 v6.1.0 Groth16 circuit artifacts, e.g. from a prover HOME/.sp1/circuits)')
    run(['docker', 'image', 'inspect', GNARK_IMAGE])
    for path in (RELEASE, ETC, STATE):
        if path.exists():
            die(f'{path} exists: already installed (rollback first)')
    try:
        pwd.getpwnam(USER)
        die(f'user {USER} exists')
    except KeyError:
        pass
    sshd = run(['sshd', '-T']) if os.geteuid() == 0 else ''  # sshd -T needs root (dry runs skip it)
    for directive in ('allowusers', 'allowgroups'):
        if any(l.startswith(directive + ' ') for l in sshd.splitlines()):
            die(f'sshd {directive} would refuse {USER}')
    available = mem_available_gib()
    memory_ok = available >= args.memory_gib + HEADROOM_GIB
    if not memory_ok and not args.dry_run:
        die(f'MemAvailable {available} GiB < cap {args.memory_gib} + {HEADROOM_GIB} GiB headroom')
    line = authorized_line(Path(args.settler_pubkey).read_text(), args.settler_host, RELEASE, ETC / 'config.json')
    plan = {'user': USER, 'release': str(RELEASE), 'etc': str(ETC), 'state': str(STATE),
            'memory_gib': args.memory_gib, 'threads': args.threads, 'identity': identity,
            'sha256': {n: sums[n] for n in FILES},
            'prover_env': parse_prover_env(args.prover_env or DEFAULT_PROVER_ENV), 'timeout_seconds': args.timeout_seconds}
    if args.dry_run:
        print(json.dumps({'dry_run': True, **plan, 'mem_available_gib': available, 'memory_ok': memory_ok,
                          'authorized_keys': line.strip(),
                          'slice': slice_dropin(args.memory_gib, args.threads)}, indent=2))
        return
    run(['useradd', '--system', '--user-group', '--home-dir', STATE, '--no-create-home', '--shell', '/bin/sh',
         '--groups', 'docker', USER])
    # '*' = no password, but not '!'-locked: sshd refuses keys for locked accounts when UsePAM is off.
    run(['usermod', '-p', '*', USER])
    owner = pwd.getpwnam(USER)
    slice_file = Path(f'/etc/systemd/system/user-{owner.pw_uid}.slice.d/zz-l2-mainnet-prover.conf')
    plan.update(uid=owner.pw_uid, slice=str(slice_file))
    ETC.mkdir(mode=0o755)
    (ETC / 'installed.json').write_text(json.dumps(plan, indent=2) + '\n')  # rollback reads this first
    # Home and authorized_keys belong to root: the prover user cannot change what its key may run.
    STATE.mkdir(mode=0o755)
    (STATE / '.ssh').mkdir(mode=0o755)
    work = STATE / 'work'
    work.mkdir(mode=0o700)
    (work / '.sp1').mkdir(mode=0o700)
    shutil.copytree(circuits, work / '.sp1' / 'circuits', symlinks=False)
    for path in [work, *work.rglob('*')]:
        os.chown(path, owner.pw_uid, owner.pw_gid)
    RELEASE.mkdir(parents=True, mode=0o755)
    for name in FILES:
        shutil.copyfile(here / name, RELEASE / name)
        (RELEASE / name).chmod(0o755 if name.startswith('bloch-') else 0o644)
    config = prover_config(RELEASE, STATE, sums[FILES[0]], args.threads, args.memory_gib,
                           parse_prover_env(args.prover_env or DEFAULT_PROVER_ENV), args.timeout_seconds)
    (ETC / 'config.json').write_text(json.dumps(config, indent=2) + '\n')
    (ETC / 'config.json').chmod(0o644)
    slice_file.parent.mkdir(parents=True, exist_ok=True)
    slice_file.write_text(slice_dropin(args.memory_gib, args.threads))
    slice_file.chmod(0o644)
    run(['systemctl', 'daemon-reload'])
    (STATE / '.ssh' / 'authorized_keys').write_text(line)
    (STATE / '.ssh' / 'authorized_keys').chmod(0o644)
    host_key = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
    print(json.dumps({'installed': True, **plan, 'host_key': ' '.join(host_key[:2])}, indent=2))


def rollback(args):
    record = ETC / 'installed.json'
    if not record.is_file():
        die(f'{record} missing: nothing recorded to roll back')
    plan = json.loads(record.read_text())
    if plan.get('user') != USER or plan.get('etc') != str(ETC):
        die('installed.json does not describe this prover')
    steps = [f'remove {STATE}/.ssh/authorized_keys (no new jobs)', f'userdel {USER}',
             f'remove {plan.get("slice")}', 'systemctl daemon-reload', f'remove {RELEASE}', f'remove {STATE}',
             f'remove {ETC}']
    if args.dry_run:
        print(json.dumps({'dry_run': True, 'steps': steps}, indent=2))
        return
    (STATE / '.ssh' / 'authorized_keys').unlink(missing_ok=True)
    lock_path = STATE / 'work' / '.lock'
    if lock_path.exists():
        with lock_path.open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                die('a proof is running; retry when it ends (new jobs are already refused)')
    try:
        pwd.getpwnam(USER)
        run(['userdel', USER])
    except KeyError:
        pass
    if plan.get('slice'):
        Path(plan['slice']).unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    for path in (RELEASE, STATE, ETC):
        shutil.rmtree(path, ignore_errors=True)
    print(json.dumps({'rolled_back': True, 'steps': steps}, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    i = sub.add_parser('install')
    i.add_argument('--settler-pubkey', required=True)
    i.add_argument('--settler-host', required=True)
    i.add_argument('--circuits', required=True)
    i.add_argument('--memory-gib', type=int, default=100)
    i.add_argument('--threads', type=int, default=32)
    i.add_argument('--prover-env', action='append', metavar='NAME=VALUE',
                   help='default ELEMENT_THRESHOLD=268435456 (agent 93); give it explicitly to replace the default')
    i.add_argument('--timeout-seconds', type=int, default=5400)
    i.add_argument('--dry-run', action='store_true')
    r = sub.add_parser('rollback')
    r.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    if os.geteuid() != 0 and not args.dry_run:
        die('run as root (or --dry-run)')
    if args.command == 'install':
        install(args, Path(__file__).resolve().parent)
    else:
        rollback(args)


if __name__ == '__main__':
    main()
