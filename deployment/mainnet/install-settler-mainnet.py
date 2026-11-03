#!/usr/bin/env python3
"""Install the Bloch L2 MAINNET settlement worker (chain 700770) on the operator host.

Run as root, step by step; every step is idempotent-refusing (it never overwrites state it
did not create in the same step) and prints what it did. Nothing here sends a transaction:
only `start` lets the worker submit settlements to Bloch L1 mainnet.

  sudo python3 install-settler-mainnet.py prepare --release DIR
      DIR holds: settler_v3.py, bloch-evm-sp1-settlement-v3, bloch-l2-produce-dev,
      settlement_v3_mainnet (SHA-256 203114bf...), bloch-pos (the armed mainnet release
      78d4921c, SHA-256 700631b0...), mainnet.manifest (SHA-256 7eef82a7...) and
      l2_reorg_recover.py (SHA-256 2a648b31...); every file is pinned in PINS below and is
      hashed after it is copied into /opt (the copies run, not the source).
      Creates the system user, /opt + /var/lib + /etc directories, the pinned
      l2-config.bin, and a NEW sealed DA fee keystore (hybrid ML-DSA-65 + Falcon-1024)
      whose passphrase is generated here and never printed. Prints the funding
      script hash to send the DA fee budget to.
  sudo python3 install-settler-mainnet.py configure [--user-transactions]
        [--prover-threads N] [--remote-prover USER@HOST --prover-host-key FILE]
        [--follower-state DIR --follower-status FILE | --no-foreign-recovery] [--reorg-recovery]
      Foreign settlement recovery is ON by default (owner decision D17, 2026-11-02): it reads the
      local native follower at FOLLOWER_STATE / FOLLOWER_STATUS, which must exist and be readable
      by the settler user. --no-foreign-recovery leaves it off (any foreign settlement then halts).
      --reorg-recovery turns on the automatic recovery after an L1 reorg of an own settlement
      (SETTLER-RUNBOOK.md "Automatic reorg recovery"); OFF unless given, never with --no-foreign-recovery.
      Runs, as the settler user, `--check-rpc` and the read-only `--dry-run` (SP1
      execute of the next L2 block against the live request) on a pending config, and
      only then writes config.json (user transactions OFF unless asked). A failed check
      leaves no config.json, so `start` stays refused and configure can simply be re-run.
      Never broadcasts.
  sudo python3 install-settler-mainnet.py dry-run [--prove]
      Re-runs the dry run; --prove also generates and verifies the Groth16 proof and
      writes the 1155-byte settlement it WOULD submit (~20 GB RAM at 6 threads, Docker).
  sudo python3 install-settler-mainnet.py start --confirm-mainnet
      Writes and starts the systemd unit. From here the worker submits 0x13 (and,
      with user transactions, 0x15) transactions to Bloch L1 mainnet.
  sudo python3 install-settler-mainnet.py rollback
      Stops and disables the unit and removes the unit file. Keeps the L2 database,
      the work directory, the DA keystore and its passphrase (never deleted here).

Dependency-free Python 3.9+.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import sys

USER = 'bloch-l2-mainnet-settler'
STATE = Path('/var/lib/bloch-l2-mainnet-settler')
DA_DIR = Path('/var/lib/bloch-l2-mainnet-da')
ETC = Path('/etc/bloch-l2-mainnet-settler')
PUBLIC = ETC / 'public'
CONFIG = ETC / 'config.json'
PENDING = ETC / 'config.json.pending'
OPT = Path('/opt/bloch/l2-mainnet-settler')
UNIT_NAME = 'bloch-l2-mainnet-settler.service'
UNIT = Path('/etc/systemd/system') / UNIT_NAME
# Absolute: as_settler runs with PATH=/usr/bin:/bin, and on Ubuntu 24.04 runuser is only in /usr/sbin.
RUNUSER = '/usr/sbin/runuser'
RPC_URLS = ['http://80.240.16.185:8080', 'http://199.247.22.8:8080', 'http://45.77.67.251:8080']
GNARK_IMAGE = 'ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d'
PINS = {
    'settlement_v3_mainnet': '203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473',
    # Armed release 78d4921c (HF1 7180/7186, HF2 7270, HF3 7360, KES 8620), canonical container,
    # source-digest 35c2b943... Used only as the DA keygen and DA signer.
    'bloch-pos': '700631b040a3a4b2299017162dd4a2c5f521bb49d5fa3c9ed677ba285673794e',
    'mainnet.manifest': '7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd',
    # The operator's repair after a reorg of an accepted settlement. It finds settler_v3.py beside itself.
    'l2_reorg_recover.py': '2a648b315edf1d884aab287bf7f8eaf85b753ef7205dc0784c542298f0609a53',
    # The worker itself, its SP1 host and its producer (GO-LIVE-PINS.sha256 release-settler-v2/). Every file
    # this installer copies is pinned here: the worker runs with the DA key, so none is trusted on first use.
    'settler_v3.py': 'd98718425e48d45283b382c6a1d2893e2c7721e6fc0ce94ea2fbc0052a7c7adc',
    'bloch-evm-sp1-settlement-v3': '3a24c36d9e761b02f6da05b43647c2513768e80c055941c5c0df2420a504973a',
    'bloch-l2-produce-dev': 'e3f1a290bf60b65702034fb0bc973ab15d1b05b236145c48880cfd2d0f477f69',
}
FILES = ('settler_v3.py', 'bloch-evm-sp1-settlement-v3', 'bloch-l2-produce-dev', 'settlement_v3_mainnet',
         'bloch-pos', 'mainnet.manifest', 'l2_reorg_recover.py')
# Foreign settlement recovery (D17: on at launch) reads follower A on this host (go-live plan P3).
FOLLOWER_STATE = '/var/lib/bloch-l2-mainnet-follower/native'
FOLLOWER_STATUS = '/var/lib/bloch-l2-mainnet-follower/status.json'
# DA fee budget: one max-size batch (114,688 B) costs 20,489 sat at the 10 msat/gas floor.
LOW_BALANCE_SAT = 100_000_000  # 1 BLCH: alert (log da-funding-low) below this
# The local fallback runs in this unit (MemoryMax=32G). Measured proof RSS at 8 threads (2026-10-30):
# 25.5 GiB at 1.57M instructions, 45.2 GiB at 8.86M, so 32 GiB is about 4M. Larger blocks need the prover.
LOCAL_PROVE_MAX_INSTRUCTIONS = 3_000_000


def run(argv, **kw):
    return subprocess.run([str(a) for a in argv], check=True, capture_output=True, text=True, **kw).stdout


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def option(args, name, default=None):
    return args[args.index(name) + 1] if name in args else default


def release():
    """The installed release directory (one per settler_v3.py digest)."""
    found = sorted(OPT.glob('*/settler_v3.py'))
    assert len(found) == 1, f'expected one release under {OPT}, found {len(found)}'
    return found[0].parent


def settler_module(directory):
    sys.dont_write_bytecode = True  # no __pycache__ written as root into the release directory
    sys.path.insert(0, str(directory))
    import settler_v3  # noqa: E402
    return settler_v3


def as_settler(argv, env=None, config=CONFIG):
    clean = {'PATH': '/usr/bin:/bin', 'HOME': str(STATE), 'BLOCH_SETTLER_CONFIG': str(config)}
    return subprocess.run([RUNUSER, '-u', USER, '--', *map(str, argv)], env={**clean, **(env or {})},
                          capture_output=True, text=True)


def prepare(args):
    source = Path(option(args, '--release', ''))
    assert source.is_dir(), 'prepare --release DIR'
    assert not any(p.exists() for p in (STATE, DA_DIR, ETC, OPT, UNIT)), 'already prepared (see rollback)'
    assert set(PINS) == set(FILES), 'every installed file has a pin'
    for name in FILES:
        assert (source / name).is_file(), f'{source / name} is missing'
    # Copy first, then hash the root-owned copies: the source (often under /home/ubuntu) may change after any
    # check of it, and only the bytes that were hashed may run. Nothing here executes or imports from source.
    target = OPT / PINS['settler_v3.py'][:16]
    try:
        target.mkdir(parents=True, mode=0o755)
        for name in FILES:
            shutil.copyfile(source / name, target / name)
            (target / name).chmod(0o644 if name.endswith(('.py', '.manifest')) or name == 'settlement_v3_mainnet'
                                  else 0o755)
        for name, pin in PINS.items():
            assert digest(target / name) == pin, f'{name} differs from its pin {pin}'
        settler = settler_module(target)
        assert settler.MAINNET['guest_sha256'] == PINS['settlement_v3_mainnet']
        build = run([target / 'bloch-pos', '--version']) + run([target / 'bloch-pos', 'buildinfo'])
        assert '78d4921c' in build and '+devnet' not in build and 'rehearsal' not in build, 'not the mainnet release'
    except BaseException:
        # Nothing but these copies exists yet (no user, no state, no key): remove them so prepare can simply re-run.
        shutil.rmtree(OPT, ignore_errors=True)
        raise
    run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', STATE,
         '--shell', '/usr/sbin/nologin', '--groups', 'docker', USER])
    owner = pwd.getpwnam(USER)
    for path in (ETC, PUBLIC):
        path.mkdir(mode=0o755)
    (PUBLIC / 'l2-config.bin').write_bytes(settler.mainnet_l2_config())
    assert digest(PUBLIC / 'l2-config.bin') == settler.MAINNET_L2_CONFIG_SHA256
    STATE.mkdir(mode=0o700)
    for sub in ('work', 'tmp', 'txpool', 'ssh'):
        (STATE / sub).mkdir(mode=0o700)
    DA_DIR.mkdir(mode=0o700)
    # The DA fee key: a sealed hybrid keystore that holds only DA fee money. Its passphrase is
    # generated here, readable by the settler alone, and never printed.
    passphrase = STATE / 'da.passphrase'
    # Created 0400 in one step (O_EXCL: never over an existing file), not created then narrowed.
    with os.fdopen(os.open(passphrase, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400), 'w') as out:
        out.write(secrets.token_hex(48) + '\n')
    env = {'PATH': '/usr/bin:/bin', 'BLOCH_KEYSTORE_PASSPHRASE_FILE': str(passphrase)}
    run([target / 'bloch-pos', 'keygen', '--dir', DA_DIR, '--index', '0'], env=env)
    pubkey = run([target / 'bloch-pos', 'keygen-public', '--dir', DA_DIR], env=env).split('\t')[1].strip()
    assert len(bytes.fromhex(pubkey)) == 3749
    assert 'sealed' in run([target / 'bloch-pos', 'keys', 'inspect', '--dir', DA_DIR])
    (PUBLIC / 'da.pubkey.hex').write_text(pubkey + '\n')
    for path in [STATE, DA_DIR, *STATE.iterdir(), *DA_DIR.iterdir()]:
        os.chown(path, owner.pw_uid, owner.pw_gid)
    script = hashlib.sha3_256(bytes.fromhex(pubkey)).hexdigest()
    print(json.dumps({'prepared': str(target), 'user': USER, 'l2_config_sha256': digest(PUBLIC / 'l2-config.bin'),
                      'da_keystore': str(DA_DIR), 'da_funding_script_hash': script,
                      'next': 'fund the DA key only if user transactions will be enabled; then run configure'},
                     indent=2))


def configure(args):
    assert STATE.is_dir() and not CONFIG.exists(), 'run prepare first, configure once'
    rel = release()
    settler = settler_module(rel)
    threads = int(option(args, '--prover-threads', '6'))
    config = {
        'network_kind': 'mainnet', 'network': settler.MAINNET['network'], 'l2_genesis': settler.MAINNET['l2_genesis'],
        'rpc_urls': RPC_URLS, 'rpc_quorum': 2,
        'produce': str(rel / 'bloch-l2-produce-dev'), 'l2_db': str(STATE / 'canonical'),
        'workdir': str(STATE / 'work'), 'home': str(STATE),
        'prover': str(rel / 'bloch-evm-sp1-settlement-v3'), 'prover_sha256': digest(rel / 'bloch-evm-sp1-settlement-v3'),
        'guest': str(rel / 'settlement_v3_mainnet'), 'guest_sha256': digest(rel / 'settlement_v3_mainnet'),
        'l2_config': str(PUBLIC / 'l2-config.bin'), 'l2_config_sha256': digest(PUBLIC / 'l2-config.bin'),
        'gnark_image': GNARK_IMAGE, 'prover_threads': threads, 'timestamp_rule': settler.MAINNET_TIMESTAMP_RULE,
        'acceptance_timeout_seconds': 1800, 'poll_seconds': 15, 'resubmit_seconds': 300,
        'idle_seconds': 30, 'max_consecutive_failures': 8,
        'user_transactions': '--user-transactions' in args, 'txpool_dir': str(STATE / 'txpool'),
        'max_block_gas': 15_000_000, 'max_block_bytes': 114_688, 'max_block_txs': 128, 'min_tip_wei': 100_000_000,
        **({'skip_idle_blocks': True, 'max_idle_seconds': int(option(args, '--max-idle-seconds', '86400')),
            'min_block_interval_seconds': int(option(args, '--min-block-interval', '0'))}
           if '--skip-idle-blocks' in args else {}),
        'local_prove_max_instructions': LOCAL_PROVE_MAX_INSTRUCTIONS,
        'da': {'signer': str(rel / 'bloch-pos'), 'signer_sha256': digest(rel / 'bloch-pos'),
               'genesis': str(rel / 'mainnet.manifest'), 'funding_pubkey': str(PUBLIC / 'da.pubkey.hex'),
               'keystore_dir': str(DA_DIR), 'passphrase_file': str(STATE / 'da.passphrase'),
               'tip_millisat_per_gas': 0, 'inclusion_timeout_seconds': 1800, 'low_balance_sat': LOW_BALANCE_SAT},
    }
    state, status = option(args, '--follower-state'), option(args, '--follower-status')
    assert bool(state) == bool(status), 'foreign settlement recovery takes both --follower-state and --follower-status'
    if '--no-foreign-recovery' in args:
        assert not state, '--no-foreign-recovery takes no follower paths'
    else:
        # D17: on by default. Outside /home (ProtectHome=true) and readable by the settler user, checked here
        # rather than at the first foreign settlement. See SETTLER-RUNBOOK.md, "Foreign settlements".
        state, status = state or FOLLOWER_STATE, status or FOLLOWER_STATUS
        assert state.startswith('/') and status.startswith('/') and not state.startswith('/home') \
            and not status.startswith('/home'), 'the follower paths must be absolute and outside /home'
        readable = as_settler(['/usr/bin/test', '-d', state, '-a', '-r', state, '-a', '-x', state, '-a',
                               '-r', status])
        assert readable.returncode == 0, (f'the settler user cannot read the follower state {state} and status '
                                          f'{status}: start follower A first (P3), or pass --no-foreign-recovery')
        config['foreign_recovery'] = {'follower_state': state, 'follower_status': status}
    if '--reorg-recovery' in args:
        # Off unless asked for. It reads the same follower store, and a restore or a second divergence ends on the
        # foreign path, so it needs foreign_recovery.
        assert '--no-foreign-recovery' not in args, '--reorg-recovery needs foreign recovery (drop --no-foreign-recovery)'
        config['reorg_recovery'] = {'follower_state': state, 'follower_status': status}
    target = option(args, '--remote-prover')
    if target:
        host_key = Path(option(args, '--prover-host-key', '')).read_text().strip()
        assert host_key.split()[0] in ('ssh-ed25519', 'ecdsa-sha2-nistp256') and '\n' not in host_key
        owner = pwd.getpwnam(USER)
        if not (STATE / 'ssh/id_ed25519').exists():
            run([RUNUSER, '-u', USER, '--', 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', USER,
                 '-f', STATE / 'ssh/id_ed25519'])
        known = STATE / 'ssh/known_hosts'
        known.write_text(f"{target.split('@')[-1]} {' '.join(host_key.split()[:2])}\n")
        os.chown(known, owner.pw_uid, owner.pw_gid)
        known.chmod(0o600)
        config['remote_prover'] = {'target': target, 'key': str(STATE / 'ssh/id_ed25519'), 'known_hosts': str(known),
                                   'order': ['remote', 'local'], 'timeout_seconds': 5700}
        # Above the prover's own 5,400 s limit (install-prover-mainnet.py), so the prover stops first and says why.
        print('remote prover key (authorize it on the prover host with the forced command):')
        print((STATE / 'ssh/id_ed25519.pub').read_text().strip())
    settler.Settler(config)  # every pin, offline (no RPC call before cycle())
    # config.json appears only after every check passed: a failed check can be retried, and start stays refused.
    PENDING.write_text(json.dumps(config, indent=2) + '\n')
    PENDING.chmod(0o644)
    check = as_settler(['/usr/bin/python3', '-u', rel / 'settler_v3.py', '--check-rpc'], config=PENDING)
    print(check.stdout + check.stderr)
    assert check.returncode == 0, 'the mainnet RPC quorum check failed'
    dry_run([], config=PENDING)
    os.replace(PENDING, CONFIG)
    print(json.dumps({'configured': str(CONFIG)}))


def dry_run(args, config=CONFIG):
    assert Path(config).exists(), 'run configure first'
    rel = release()
    argv = ['/usr/bin/python3', '-u', rel / 'settler_v3.py', '--dry-run'] + (['--prove'] if '--prove' in args else [])
    done = as_settler(argv, {'TMPDIR': str(STATE / 'tmp')}, config=config)
    print(done.stdout[-6000:] + done.stderr[-2000:])
    assert done.returncode == 0, 'dry run failed: see the output above (a run that stopped early writes no dry-run-report.json)'


def start(args):
    assert '--confirm-mainnet' in args, 'start submits to Bloch L1 mainnet: pass --confirm-mainnet'
    assert CONFIG.exists() and not UNIT.exists(), 'configure first; start once'
    rel = release()
    UNIT.write_text(f'''[Unit]
Description=Bloch L2 MAINNET settlement worker (chain 700770; 0x13 settlements, 0x15 DA)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service
# Retryable failures (RPC, prover, producer refusals) exit 1 after max_consecutive_failures
# with backoff; never let the start rate limit turn that into a permanent stop.
StartLimitIntervalSec=0

[Service]
Type=simple
User={USER}
Group={USER}
SupplementaryGroups=docker
Environment=BLOCH_SETTLER_CONFIG={ETC}/config.json
Environment=HOME={STATE}
Environment=TMPDIR={STATE}/tmp
ExecStart=/usr/bin/python3 -u {rel}/settler_v3.py
Restart=on-failure
RestartSec=60
# Stop: SIGTERM to the worker only; it kills its prover group, removes the SP1 segments the group mapped and
# kills a Gnark container the group left (review r10 M1), then systemd SIGKILLs anything left. The cleanup
# needs at most about 80 s (30 s group wait, three 15 s docker calls).
KillMode=mixed
TimeoutStopSec=120
# Backstop: POSIX shared memory and semaphores of the settler user (SP1 segments) go when the unit stops.
RemoveIPC=yes
# exit 3 = halt for operator review (divergence, off-rule foreign settlement, refused proof): never auto-restart.
RestartPreventExitStatus=3
UMask=0077
NoNewPrivileges=true
# No PrivateTmp: the Docker daemon must see the prover's temporary files.
PrivateTmp=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={STATE} {DA_DIR}
# Kernel, cgroup and privilege surfaces the worker never uses (it runs Docker through the socket, not here).
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
LimitCORE=0
Nice=5
CPUQuota=1200%
# Local fallback SP1 Groth16, only up to LOCAL_PROVE_MAX_INSTRUCTIONS (see above). Gnark runs outside this unit.
MemoryMax=32G
MemorySwapMax=0

[Install]
WantedBy=multi-user.target
''')
    UNIT.chmod(0o644)
    run(['systemd-analyze', 'verify', UNIT])
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', UNIT_NAME])
    print(json.dumps({'started': UNIT_NAME, 'logs': f'journalctl -u {UNIT_NAME} -f -o cat'}, indent=2))


def rollback(_args):
    if UNIT.exists():
        subprocess.run(['systemctl', 'disable', '--now', UNIT_NAME], check=False)
        UNIT.unlink()
        run(['systemctl', 'daemon-reload'])
    print(json.dumps({'stopped': UNIT_NAME, 'kept': [str(STATE), str(DA_DIR), str(ETC), str(OPT)],
                      'note': 'an L1 settlement already accepted stays accepted; restart with start --confirm-mainnet'},
                     indent=2))


if __name__ == '__main__':
    assert os.geteuid() == 0, 'run as root'
    commands = {'prepare': prepare, 'configure': configure, 'dry-run': dry_run, 'start': start, 'rollback': rollback}
    command = sys.argv[1] if len(sys.argv) > 1 else ''
    if command not in commands:
        raise SystemExit(__doc__)
    commands[command](sys.argv[2:])
