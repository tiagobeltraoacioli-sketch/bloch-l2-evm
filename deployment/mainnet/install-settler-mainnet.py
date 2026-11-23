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
      Creates the system user, the read group bloch-l2-mainnet-l2read (the RPC and shadow users join it to
      read the canonical database and the work directory, nothing else), /opt + /var/lib + /etc directories,
      the pinned l2-config.bin, and a NEW sealed DA fee keystore (hybrid ML-DSA-65 + Falcon-1024) whose
      passphrase is generated here, kept root-only in /etc/bloch-l2-mainnet-settler/da.passphrase and never
      printed: the worker reads only the copy its unit puts in its private runtime directory (review r10 M-4).
      Prints the funding script hash to send the DA fee budget to.
  sudo python3 install-settler-mainnet.py configure --rpc-urls URL,URL,URL [--user-transactions]
        [--prover-threads N] [--remote-prover USER@HOST --prover-host-key FILE]
        [--follower-state DIR --follower-status FILE | --no-foreign-recovery]
      The L1 RPCs are configuration, not code: --rpc-urls (or L1_RPC_URLS in the environment of the
      python3 process, e.g. `sudo L1_RPC_URLS=... python3 ...`) names at least three http(s)://host:port
      URLs on distinct hosts. Nothing is built in, and a placeholder (TBD-owner) is refused. The quorum
      is a strict majority (2 of 3). config.json keeps them as rpc_urls, which install-shadow.sh reads.
      Foreign settlement recovery is ON by default (owner decision D17, 2026-11-02): it reads the
      local native follower at FOLLOWER_STATE / FOLLOWER_STATUS, which must exist and be readable
      by the settler user. --no-foreign-recovery leaves it off (any foreign settlement then halts).
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
  sudo python3 install-settler-mainnet.py upgrade --release DIR --confirm-mainnet
      Installs a newer worker release (the PINS of this installer) beside the running one: stages and hashes
      it like prepare, rewrites the release fields of a pending config (old config kept as
      config.json.<old release>), stops the unit, runs --check-rpc and the dry run on the pending config with
      the new release, and only then switches config.json and the unit's ExecStart and starts it again.
      A failed check leaves the old release, config and unit running as before (review r10 M-3).
  sudo python3 install-settler-mainnet.py upgrade --rollback --confirm-mainnet
      Switches back to the release the last upgrade replaced (its kept config and directory).
  sudo python3 install-settler-mainnet.py settler-key prepare
      Audit L2N-01 (L1 settler gate, inert until the owner arms it). Needs a release whose bloch-pos has
      `l2-settler`. Creates a NEW sealed settler keystore in /var/lib/bloch-l2-mainnet-settler-key (0700, the
      settler user's) with a passphrase generated here (root-only settler.passphrase, never printed), and
      writes its public key to public/settler.pubkey.hex: the only thing that leaves the host, for the set
      file the L1 release pins. Standby keys are generated the same way on their own offline hosts.
  sudo python3 install-settler-mainnet.py settler-key enable --set FILE [--activation-epoch l1|N]
        [--da-settler-key] --confirm-mainnet
      FILE is the settler set (`bloch-pos l2-settler set`), this host's key in it. Checks the key with the
      pinned signer (`l2-settler check`), installs the set as the worker's own file (it rewrites it at a
      rotation), adds settler_authorization to the configuration (old config kept as
      config.json.pre-settler-key) and rewrites the unit so the passphrase reaches the worker like the DA
      one. Before the gate's epoch (default: read from the L1) the worker settles exactly as before.
      --da-settler-key also funds and signs DA with the settler key (L1 DA settler-slot rule).
      The unit must be stopped; start it afterwards.
  sudo python3 install-settler-mainnet.py rollback
      Stops and disables the unit and removes the unit file. Keeps the L2 database,
      the work directory, the DA keystore and its passphrase (never deleted here).

Dependency-free Python 3.9+.
"""
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse

USER = 'bloch-l2-mainnet-settler'
# The RPC and shadow users join this group: it reads the canonical database and the work directory only (the
# state directory is 2710, so group members cannot list it). The settler joins it to read the RPC's txpool spool.
READ_GROUP = 'bloch-l2-mainnet-l2read'
STATE = Path('/var/lib/bloch-l2-mainnet-settler')
DA_DIR = Path('/var/lib/bloch-l2-mainnet-da')
ETC = Path('/etc/bloch-l2-mainnet-settler')
PUBLIC = ETC / 'public'
CONFIG = ETC / 'config.json'
PENDING = ETC / 'config.json.pending'
OPT = Path('/opt/bloch/l2-mainnet-settler')
UNIT_NAME = 'bloch-l2-mainnet-settler.service'
UNIT = Path('/etc/systemd/system') / UNIT_NAME
UPGRADE = ETC / 'upgrade.json'
# Review r10 M-4: root:root 0400 in /etc, outside the worker's writable state. The unit copies it at every start
# into its private RuntimeDirectory as a 0400 file of the settler user (gone when the unit stops). Not
# LoadCredential: systemd 255 hands a credential to a User= service as mode 0440 (root:root plus a user ACL), and
# bloch-pos refuses any passphrase file with a group or other bit (keys::read_passphrase_file), measured under a
# real systemd in agents/204-installers-systemd.md.
DA_PASSPHRASE = ETC / 'da.passphrase'
RUNTIME = Path('/run/bloch-l2-mainnet-settler')
DA_RUNTIME_PASSPHRASE = RUNTIME / 'da.passphrase'
# The settler key (audit L2N-01): the same custody as the DA key, in a directory of its own.
SETTLER_DIR = Path('/var/lib/bloch-l2-mainnet-settler-key')
SETTLER_PASSPHRASE = ETC / 'settler.passphrase'
SETTLER_RUNTIME_PASSPHRASE = RUNTIME / 'settler.passphrase'
SETTLER_PUBKEY = PUBLIC / 'settler.pubkey.hex'
SETTLER_SET = STATE / 'settler.set'  # public data; the worker replaces it when a rotation it signed is accepted
# Absolute: as_settler runs with PATH=/usr/bin:/bin, and on Ubuntu 24.04 runuser is only in /usr/sbin.
RUNUSER = '/usr/sbin/runuser'
# The L1 RPCs come from configure --rpc-urls or $L1_RPC_URLS, never from this file (reviews r11 235/240: no
# operator or validator host is compiled into the kit, and choosing the third RPC is not a kit commit).
RPC_URLS_ENV = 'L1_RPC_URLS'
MIN_RPC_URLS = 3
# Placeholders the plan and the templates use for a value only the owner can fill in.
RPC_PLACEHOLDER = re.compile(r'tbd|[<>]|THIRD_L1|L1_RPC_3|IP_OF', re.IGNORECASE)
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
    'settler_v3.py': '9b8f5245c925e90f8802eca358bbed07e022e96bb20d04250974aba8edf95e48',
    'bloch-evm-sp1-settlement-v3': '3a24c36d9e761b02f6da05b43647c2513768e80c055941c5c0df2420a504973a',
    'bloch-l2-produce-dev': '598873aef6770002297a710387969218dd7d684ea8e9d8bdcf067d43123b37db',
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


def l1_rpc_urls(args, environ=None):
    """The L1 RPC URLs of this host's settler: --rpc-urls, else $L1_RPC_URLS (separated by commas or spaces)."""
    environ = os.environ if environ is None else environ
    raw, source = option(args, '--rpc-urls'), '--rpc-urls'
    if raw is None:
        raw, source = environ.get(RPC_URLS_ENV, ''), RPC_URLS_ENV
    urls = [u for u in re.split(r'[\s,]+', raw.strip()) if u]
    assert urls, (f'configure needs the L1 RPCs: --rpc-urls URL,URL,URL (or {RPC_URLS_ENV}); '
                  'none is built into the installer')
    for url in urls:
        assert not RPC_PLACEHOLDER.search(url), f'{source}: {url!r} is a placeholder: put the real L1 RPC URL in'
        parts = urllib.parse.urlsplit(url)
        try:
            port = parts.port
        except ValueError:
            port = None
        assert parts.scheme in ('http', 'https') and parts.hostname and port and '@' not in parts.netloc \
            and parts.path in ('', '/') and not parts.query and not parts.fragment, \
            f'{source}: {url!r} is not an http(s)://HOST:PORT URL'
    hosts = [urllib.parse.urlsplit(u).hostname for u in urls]
    assert len(set(hosts)) == len(hosts), f'{source}: the L1 RPCs must be on distinct hosts (one failure domain each)'
    assert len(urls) >= MIN_RPC_URLS, f'{source}: at least {MIN_RPC_URLS} L1 RPCs on distinct hosts (quorum 2 of 3)'
    return urls


def release(config=None):
    """The release directory a config runs (its prover's directory); before configure, the only one installed."""
    config = Path(config or CONFIG)
    if config.exists():
        rel = Path(json.loads(config.read_text())['prover']).parent
        assert rel.parent == OPT and (rel / 'settler_v3.py').is_file(), f'{config} names no release under {OPT}'
        return rel
    found = sorted(OPT.glob('*/settler_v3.py'))
    assert len(found) == 1, f'expected one release under {OPT}, found {len(found)}'
    return found[0].parent


def install_release(source, target):
    """Copy the release files into `target` (root-owned) and check the COPIES: the source (often under /home/ubuntu)
    may change after any check of it, and only the bytes that were hashed may run. Nothing here executes or imports
    from source. A `target` that already exists (an upgrade back to a kept release) is re-checked, not copied."""
    assert set(PINS) == set(FILES), 'every installed file has a pin'
    if not target.exists():
        for name in FILES:
            assert (source / name).is_file(), f'{source / name} is missing'
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
    return settler


def settler_module(directory):
    sys.dont_write_bytecode = True  # no __pycache__ written as root into the release directory
    sys.path.insert(0, str(directory))
    sys.modules.pop('settler_v3', None)  # an upgrade imports the new release, not a cached old one
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
    target = OPT / PINS['settler_v3.py'][:16]
    try:
        settler = install_release(source, target)
    except BaseException:
        # Nothing but these copies exists yet (no user, no state, no key): remove them so prepare can simply re-run.
        shutil.rmtree(OPT, ignore_errors=True)
        raise
    run(['groupadd', '--system', '-f', READ_GROUP])
    run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', STATE,
         '--shell', '/usr/sbin/nologin', '--groups', f'docker,{READ_GROUP}', USER])
    owner, readers = pwd.getpwnam(USER), grp.getgrnam(READ_GROUP).gr_gid
    for path in (ETC, PUBLIC):
        path.mkdir(mode=0o755)
    (PUBLIC / 'l2-config.bin').write_bytes(settler.mainnet_l2_config())
    assert digest(PUBLIC / 'l2-config.bin') == settler.MAINNET_L2_CONFIG_SHA256
    DA_DIR.mkdir(mode=0o700)
    # The DA fee key: a sealed hybrid keystore that holds only DA fee money. Its passphrase is generated here,
    # root-only, and never printed; the worker reads only the unit's runtime copy DA_RUNTIME_PASSPHRASE (M-4).
    # Created 0400 in one step (O_EXCL: never over an existing file), not created then narrowed.
    with os.fdopen(os.open(DA_PASSPHRASE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400), 'w') as out:
        out.write(secrets.token_hex(48) + '\n')
    env = {'PATH': '/usr/bin:/bin', 'BLOCH_KEYSTORE_PASSPHRASE_FILE': str(DA_PASSPHRASE)}
    run([target / 'bloch-pos', 'keygen', '--dir', DA_DIR, '--index', '0'], env=env)
    pubkey = run([target / 'bloch-pos', 'keygen-public', '--dir', DA_DIR], env=env).split('\t')[1].strip()
    assert len(bytes.fromhex(pubkey)) == 3749
    assert 'sealed' in run([target / 'bloch-pos', 'keys', 'inspect', '--dir', DA_DIR])
    (PUBLIC / 'da.pubkey.hex').write_text(pubkey + '\n')
    for path in [DA_DIR, *DA_DIR.iterdir()]:
        os.chown(path, owner.pw_uid, owner.pw_gid)
    # State: group READ_GROUP with setgid, so every file and database the worker creates later (UMask=0027) is
    # readable by the RPC and shadow users, while the state directory itself only lets them through (2710).
    # ssh/ and the DA keystore stay the settler's alone.
    layout = {STATE: 0o2710, STATE / 'work': 0o2750, STATE / 'txpool': 0o2770, STATE / 'tmp': 0o2700,
              STATE / 'ssh': 0o700}
    for path, mode in layout.items():
        path.mkdir(mode=0o700)
        os.chown(path, owner.pw_uid, owner.pw_gid if path.name == 'ssh' else readers)
        path.chmod(mode)  # after chown, which may clear the setgid bit
    script = hashlib.sha3_256(bytes.fromhex(pubkey)).hexdigest()
    print(json.dumps({'prepared': str(target), 'user': USER, 'l2_config_sha256': digest(PUBLIC / 'l2-config.bin'),
                      'da_keystore': str(DA_DIR), 'da_funding_script_hash': script,
                      'next': 'fund the DA key only if user transactions will be enabled; then run configure'},
                     indent=2))


def configure(args):
    assert STATE.is_dir() and not CONFIG.exists(), 'run prepare first, configure once'
    rpc_urls = l1_rpc_urls(args)  # before anything else: a missing or placeholder RPC is a usage error
    rel = release()
    settler = settler_module(rel)
    threads = int(option(args, '--prover-threads', '6'))
    config = {
        'network_kind': 'mainnet', 'network': settler.MAINNET['network'], 'l2_genesis': settler.MAINNET['l2_genesis'],
        'rpc_urls': rpc_urls, 'rpc_quorum': len(rpc_urls) // 2 + 1,
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
               'keystore_dir': str(DA_DIR), 'passphrase_file': str(DA_RUNTIME_PASSPHRASE),
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
    rel = release(config)
    argv = ['/usr/bin/python3', '-u', rel / 'settler_v3.py', '--dry-run'] + (['--prove'] if '--prove' in args else [])
    done = as_settler(argv, {'TMPDIR': str(STATE / 'tmp')}, config=config)
    print(done.stdout[-6000:] + done.stderr[-2000:])
    assert done.returncode == 0, 'dry run failed: see the output above (a run that stopped early writes no dry-run-report.json)'


def unit_text(rel):
    return f'''[Unit]
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
SupplementaryGroups=docker {READ_GROUP}
Environment=BLOCH_SETTLER_CONFIG={ETC}/config.json
# The DA passphrase (root:root 0400 in {ETC}) reaches the worker only as this copy in its private runtime
# directory (0700, removed at stop): a 0400 file of {USER}, as bloch-pos requires (review r10 M-4).
RuntimeDirectory={RUNTIME.name}
RuntimeDirectoryMode=0700
ExecStartPre=+/usr/bin/install -m 0400 -o {USER} -g {USER} {DA_PASSPHRASE} {DA_RUNTIME_PASSPHRASE}
{settler_key_lines()}Environment=HOME={STATE}
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
# 0027: what the worker writes under the setgid state directory is readable by {READ_GROUP} (the RPC reads the
# canonical database, the shadow the work directory); ssh/ and the DA keystore are 0700 and stay private.
UMask=0027
NoNewPrivileges=true
# No PrivateTmp: the Docker daemon must see the prover's temporary files.
PrivateTmp=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={STATE} {DA_DIR}{f' {SETTLER_DIR}' if SETTLER_PASSPHRASE.is_file() else ''}
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
'''


def settler_key_lines():
    """The unit lines of the settler key, once `settler-key prepare` made it: without one the unit is byte for
    byte what it was."""
    if not SETTLER_PASSPHRASE.is_file():
        return ''
    return (f'# The settler passphrase (audit L2N-01): the same path as the DA one, a 0400 copy of {USER}.\n'
            f'ExecStartPre=+/usr/bin/install -m 0400 -o {USER} -g {USER} {SETTLER_PASSPHRASE} '
            f'{SETTLER_RUNTIME_PASSPHRASE}\n')


def write_unit(rel):
    # The unit's ExecStartPre copies this file at every start: refuse a unit that could never start.
    assert DA_PASSPHRASE.is_file(), f'{DA_PASSPHRASE} is missing (a prepare by an older installer): see SETTLER-RUNBOOK.md'
    UNIT.write_text(unit_text(rel))
    UNIT.chmod(0o644)
    run(['systemd-analyze', 'verify', UNIT])
    run(['systemctl', 'daemon-reload'])


def start(args):
    assert '--confirm-mainnet' in args, 'start submits to Bloch L1 mainnet: pass --confirm-mainnet'
    assert CONFIG.exists() and not UNIT.exists(), 'configure first; start once'
    write_unit(release())
    run(['systemctl', 'enable', '--now', UNIT_NAME])
    print(json.dumps({'started': UNIT_NAME, 'logs': f'journalctl -u {UNIT_NAME} -f -o cat'}, indent=2))


def unit_active():
    return subprocess.run(['systemctl', 'is-active', '--quiet', UNIT_NAME]).returncode == 0


def release_config(config, rel):
    """`config` with every field that names a release file pointed at `rel` (and its pins recomputed)."""
    new = {**config, 'produce': str(rel / 'bloch-l2-produce-dev'),
           'prover': str(rel / 'bloch-evm-sp1-settlement-v3'), 'prover_sha256': digest(rel / 'bloch-evm-sp1-settlement-v3'),
           'guest': str(rel / 'settlement_v3_mainnet'), 'guest_sha256': digest(rel / 'settlement_v3_mainnet')}
    signer = {'signer': str(rel / 'bloch-pos'), 'signer_sha256': digest(rel / 'bloch-pos'),
              'genesis': str(rel / 'mainnet.manifest')}
    new['da'] = {**config['da'], **({} if config['da'].get('settler_key') else signer)}
    if 'settler_authorization' in config:
        new['settler_authorization'] = {**config['settler_authorization'], **signer}
    return new


def switch(rel, config, record):
    """Make `config` (already checked) the live one for release `rel`: the old config.json is kept beside it as
    config.json.<old release>, the unit runs `rel`. The caller has stopped the unit."""
    old = release()
    shutil.copy2(CONFIG, ETC / f'config.json.{old.name}')
    PENDING.write_text(json.dumps(config, indent=2) + '\n')
    PENDING.chmod(0o644)
    os.replace(PENDING, CONFIG)
    write_unit(rel)
    UPGRADE.write_text(json.dumps({**record, 'previous': old.name, 'current': rel.name,
                                   'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}, indent=2) + '\n')


def upgrade(args):
    """Review r10 M-3: a pinned worker upgrade beside the running release, checked before the switch."""
    assert '--confirm-mainnet' in args, 'upgrade restarts the mainnet worker: pass --confirm-mainnet'
    assert CONFIG.exists() and UNIT.exists(), 'upgrade a started settler (prepare, configure, start first)'
    if '--rollback' in args:
        return upgrade_rollback()
    source = Path(option(args, '--release', ''))
    current = release()
    target = OPT / PINS['settler_v3.py'][:16]
    assert target != current, f'{target.name} is already the running release'
    assert source.is_dir() or target.exists(), 'upgrade --release DIR --confirm-mainnet'
    created = not target.exists()
    try:
        settler = install_release(source, target)
        config = release_config(json.loads(CONFIG.read_text()), target)
        settler.Settler(config)  # every pin of the new release, offline
    except BaseException:
        if created:
            shutil.rmtree(target, ignore_errors=True)
        raise
    PENDING.write_text(json.dumps(config, indent=2) + '\n')
    PENDING.chmod(0o644)
    was_active = unit_active()
    # The dry run copies the live database once a settlement is accepted: the worker must not write it meanwhile.
    run(['systemctl', 'stop', UNIT_NAME])
    try:
        check = as_settler(['/usr/bin/python3', '-u', target / 'settler_v3.py', '--check-rpc'], config=PENDING)
        print(check.stdout + check.stderr)
        assert check.returncode == 0, 'the mainnet RPC quorum check failed with the new release'
        dry_run([], config=PENDING)
    except BaseException:
        PENDING.unlink(missing_ok=True)
        if created:
            shutil.rmtree(target, ignore_errors=True)
        if was_active:
            run(['systemctl', 'start', UNIT_NAME])
        print(json.dumps({'upgrade': 'refused', 'running': current.name, 'unit_restarted': was_active}))
        raise
    switch(target, config, {'upgraded': True})
    if was_active:
        run(['systemctl', 'start', UNIT_NAME])
    print(json.dumps({'upgraded': target.name, 'previous': current.name, 'started': was_active,
                      'rollback': 'install-settler-mainnet.py upgrade --rollback --confirm-mainnet'}, indent=2))


def upgrade_rollback():
    assert UPGRADE.exists(), f'{UPGRADE} missing: no upgrade to roll back'
    record = json.loads(UPGRADE.read_text())
    current, previous = release(), OPT / record['previous']
    assert current.name == record['current'], f'running {current.name}, but the last upgrade installed {record["current"]}'
    kept = ETC / f'config.json.{previous.name}'
    assert kept.exists() and (previous / 'settler_v3.py').is_file(), f'{kept} or {previous} is missing'
    config = json.loads(kept.read_text())
    assert Path(config['prover']).parent == previous, f'{kept} does not run {previous}'
    # The kept release must still be the bytes it ran: its directory is named by its worker's digest, and the
    # kept config pins its prover, guest and DA signer.
    assert digest(previous / 'settler_v3.py').startswith(previous.name), 'kept settler_v3.py changed'
    for key, name in (('prover_sha256', 'bloch-evm-sp1-settlement-v3'), ('guest_sha256', 'settlement_v3_mainnet')):
        assert digest(previous / name) == config[key], f'kept {name} changed'
    assert digest(previous / 'bloch-pos') == config['da']['signer_sha256'], 'kept bloch-pos changed'
    was_active = unit_active()
    run(['systemctl', 'stop', UNIT_NAME])
    switch(previous, config, {'rolled_back': True})
    if was_active:
        run(['systemctl', 'start', UNIT_NAME])
    print(json.dumps({'rolled_back_to': previous.name, 'from': current.name, 'started': was_active}, indent=2))


def settler_key(args):
    """Audit L2N-01: the settler's signing key and its entry in the configuration (see the module docstring)."""
    command = args[0] if args else ''
    assert command in ('prepare', 'enable'), 'settler-key prepare | settler-key enable --set FILE'
    assert STATE.is_dir(), 'run prepare first'
    rel = release()
    signer = rel / 'bloch-pos'
    run([signer, 'l2-settler', '--help'])  # a release without the settler tool stops here
    if command == 'prepare':
        assert not SETTLER_DIR.exists() and not SETTLER_PASSPHRASE.exists() and not SETTLER_PUBKEY.exists(), \
            'a settler key exists: it is never overwritten (see SETTLER-RUNBOOK.md, settler key)'
        owner = pwd.getpwnam(USER)
        SETTLER_DIR.mkdir(mode=0o700)
        with os.fdopen(os.open(SETTLER_PASSPHRASE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400), 'w') as out:
            out.write(secrets.token_hex(48) + '\n')
        env = {'PATH': '/usr/bin:/bin', 'BLOCH_KEYSTORE_PASSPHRASE_FILE': str(SETTLER_PASSPHRASE)}
        run([signer, 'keygen', '--dir', SETTLER_DIR, '--index', '0'], env=env)
        assert 'sealed' in run([signer, 'keys', 'inspect', '--dir', SETTLER_DIR])
        run([signer, 'l2-settler', 'pubkey', '--dir', SETTLER_DIR, '--out', SETTLER_PUBKEY], env=env)
        pubkey = bytes.fromhex(SETTLER_PUBKEY.read_text().strip())
        assert len(pubkey) == 3749
        SETTLER_PUBKEY.chmod(0o644)
        for path in [SETTLER_DIR, *SETTLER_DIR.iterdir()]:
            os.chown(path, owner.pw_uid, owner.pw_gid)
        print(json.dumps({'settler_keystore': str(SETTLER_DIR), 'settler_pubkey_file': str(SETTLER_PUBKEY),
                          'settler_pubkey_sha3': hashlib.sha3_256(pubkey).hexdigest(),
                          'next': 'back up the keystore and the passphrase separately (key backup policy); give '
                                  'the public key file to the owner for the settler set; then settler-key enable'},
                         indent=2))
        return
    assert '--confirm-mainnet' in args, 'enable changes how the mainnet worker settles: pass --confirm-mainnet'
    assert CONFIG.exists() and SETTLER_PASSPHRASE.is_file() and SETTLER_PUBKEY.is_file(), \
        'configure and settler-key prepare first'
    assert not unit_active(), f'stop {UNIT_NAME} first'
    config = json.loads(CONFIG.read_text())
    assert 'settler_authorization' not in config, 'already enabled'
    settler = settler_module(rel)
    text = Path(option(args, '--set', '')).read_text()
    keys = settler.parse_settler_set(text)
    assert keys is not None, '--set is not a settler set (1 to 3 distinct keys, hex, one per line)'
    assert bytes.fromhex(SETTLER_PUBKEY.read_text().strip()) in keys, "this host's settler key is not in --set"
    activation = option(args, '--activation-epoch', 'l1')
    activation = activation if activation == 'l1' else int(activation)
    assert not SETTLER_SET.exists(), f'{SETTLER_SET} exists'
    owner = pwd.getpwnam(USER)
    SETTLER_SET.write_text(''.join(k.hex() + '\n' for k in keys))
    os.chown(SETTLER_SET, owner.pw_uid, owner.pw_gid)
    SETTLER_SET.chmod(0o640)
    try:
        run([signer, 'l2-settler', 'check', '--set', SETTLER_SET, '--dir', SETTLER_DIR],
            env={'PATH': '/usr/bin:/bin', 'BLOCH_KEYSTORE_PASSPHRASE_FILE': str(SETTLER_PASSPHRASE)})
        config['settler_authorization'] = {
            'signer': str(signer), 'signer_sha256': digest(signer), 'genesis': str(rel / 'mainnet.manifest'),
            'keystore_dir': str(SETTLER_DIR), 'passphrase_file': str(SETTLER_RUNTIME_PASSPHRASE),
            'pubkey': str(SETTLER_PUBKEY), 'set': str(SETTLER_SET), 'activation_epoch': activation}
        if '--da-settler-key' in args:
            policy = {k: v for k, v in config['da'].items()
                      if k not in ('signer', 'signer_sha256', 'genesis', 'funding_pubkey', 'keystore_dir', 'passphrase_file')}
            config['da'] = {**policy, 'settler_key': True, 'settler_slot_activation_epoch': 'l1'}
        settler.Settler(config)  # every pin and the set, offline
    except BaseException:
        SETTLER_SET.unlink()
        raise
    shutil.copy2(CONFIG, ETC / 'config.json.pre-settler-key')
    PENDING.write_text(json.dumps(config, indent=2) + '\n')
    PENDING.chmod(0o644)
    os.replace(PENDING, CONFIG)
    write_unit(rel)
    print(json.dumps({'settler_authorization': 'configured', 'activation_epoch': activation,
                      'set_hash': settler.settler_set_hash(keys).hex(), 'keys': len(keys),
                      'da_settler_key': '--da-settler-key' in args,
                      'next': f'systemctl start {UNIT_NAME}; the log shows settler-key-checked'}, indent=2))


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
    commands = {'prepare': prepare, 'configure': configure, 'dry-run': dry_run, 'start': start, 'upgrade': upgrade,
                'settler-key': settler_key, 'rollback': rollback}
    command = sys.argv[1] if len(sys.argv) > 1 else ''
    if command not in commands:
        raise SystemExit(__doc__)
    commands[command](sys.argv[2:])
