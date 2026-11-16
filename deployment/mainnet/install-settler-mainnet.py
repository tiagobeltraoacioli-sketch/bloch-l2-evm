#!/usr/bin/env python3
"""Install the Bloch L2 MAINNET settlement worker (chain 700770) on the operator host.

Run as root, step by step; every step is idempotent-refusing (it never overwrites state it
did not create in the same step) and prints what it did. Nothing here sends a transaction:
only `start` lets the worker submit settlements to Bloch L1 mainnet.

  sudo python3 install-settler-mainnet.py prepare --release DIR
      DIR holds: settler_v3.py, bloch-evm-sp1-settlement-v3, bloch-l2-produce-dev,
      settlement_v3_mainnet (SHA-256 203114bf...), bloch-pos (the armed mainnet release
      78d4921c, SHA-256 700631b0...), mainnet.manifest (SHA-256 7eef82a7...) and
      l2_reorg_recover.py (SHA-256 2a648b31...) and, for the program swap (CANDIDATE, native
      L2_NEXT_PROGRAM_EPOCH inert), settlement_v3_mainnet_sparse (SHA-256 81813124...) and, for the
      inert rollback (L2_PROGRAM_ROLLBACK_EPOCH), settlement_v3_mainnet_fallback (SHA-256 7528e26d...),
      plus sequencer_policy_v2.py; every file is pinned in PINS below and is hashed after it is copied
      into /opt (the copies run, not the source).
      The host of this kit serves both programs: the activated one with --mainnet-v1, the
      next one with --mainnet --sparse (see "Program swap" in SETTLER-RUNBOOK.md).
      Creates the system user, the read group bloch-l2-mainnet-l2read (the RPC and shadow users join it to
      read the canonical database and the work directory, nothing else), /opt + /var/lib + /etc directories,
      the pinned l2-config.bin, and a NEW sealed DA fee keystore (hybrid ML-DSA-65 + Falcon-1024) whose
      passphrase is generated here, kept root-only in /etc/bloch-l2-mainnet-settler/da.passphrase and never
      printed: the worker reads only the copy its unit puts in its private runtime directory (review r10 M-4).
      Prints the funding script hash to send the DA fee budget to.
  sudo python3 install-settler-mainnet.py configure --rpc-urls URL,URL,URL [--user-transactions [--sequencer-policy-v2]]
        [--prover-threads N] [--remote-prover USER@HOST --prover-host-key FILE]
        [--max-block-sp1-gas N --max-block-instructions N]
        [--follower-state DIR --follower-status FILE | --no-foreign-recovery]
      The L1 RPCs are configuration, not code: --rpc-urls (or L1_RPC_URLS in the environment of the
      python3 process, e.g. `sudo L1_RPC_URLS=... python3 ...`) names at least three http(s)://host:port
      URLs on distinct hosts. Nothing is built in, and a placeholder (TBD-owner) is refused. The quorum
      is a strict majority (2 of 3). config.json keeps them as rpc_urls, which install-shadow.sh reads.
      Foreign settlement recovery is ON by default (owner decision D17, 2026-11-02): it reads the
      local native follower at FOLLOWER_STATE / FOLLOWER_STATUS, which must exist and be readable
      by the settler user. --no-foreign-recovery leaves it off (any foreign settlement then halts).
      --reorg-recovery turns on the automatic recovery after an L1 reorg of an own settlement
      (SETTLER-RUNBOOK.md "Automatic reorg recovery"); OFF unless given, never with --no-foreign-recovery.
      Runs, as the settler user, `--check-rpc` and the read-only `--dry-run` (SP1
      execute of the next L2 block against the live request) on a pending config, and
      only then writes config.json (user transactions OFF unless asked). --sequencer-policy-v2
      adds the block budget and limits of docs/SEQUENCER-POLICY-V2.md (POLICY_V2 below). A failed check
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
# Absolute: as_settler runs with PATH=/usr/bin:/bin, and on Ubuntu 24.04 runuser is only in /usr/sbin.
RUNUSER = '/usr/sbin/runuser'
# Not a SHA-256: no file matches it, so `prepare` refuses until the December host is pinned.
CANDIDATE_HOST_PIN = 'unpinned-december-sp1-host'
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
    # The worker itself, its sequencer policy, its SP1 host and its producer. Every file this installer copies
    # is pinned here: the worker runs with the DA key, so none is trusted on first use.
    'settler_v3.py': 'ee08bc7d082e5cf23d30e38577477aada72b2565ab5816ec31749932d6f67b7a',
    'sequencer_policy_v2.py': '31511e5580c7fa7e7a6c7877979f73f638b5b04efe12c5d27befda4ac716c552',
    # CANDIDATE: the SP1 host of the December release (features source-settlement,node-artifact,sparse-witness)
    # has no release build yet. Until it is pinned here prepare refuses every host (fail closed).
    'bloch-evm-sp1-settlement-v3': CANDIDATE_HOST_PIN,
    # CANDIDATE: fork candidate v2 out/ (agent 143, reproduced on two hosts) against the unreleased native f12b4113.
    'bloch-l2-produce-dev': '425d4fe84cde5833070dcd05f7b18edcf912fdd214a478aa5bf9c5241144cc78',
    # CANDIDATE, not scheduled: the sparse-witness guest that native PROGRAM_NEXT names. It moves with the
    # fee-sweep recipient (0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544, fixed) and with the audit's fixes.
    'settlement_v3_mainnet_sparse': '81813124c19b1a9bfe5755fc742fa36a48420134b71e18ef355e26e1c5f1b6d9',
    # CANDIDATE, not scheduled: the complete-witness guest that native PROGRAM_FALLBACK names (the next rules
    # WITH forced inclusion, configuration 27d6ce9f; installed by the inert rollback gate). Pinned container
    # build of guest-fallback, bloch-l2-evm codex/fallback-forced-r11-20261103 (agent 216).
    'settlement_v3_mainnet_fallback': '7528e26da4076499e0fabcc621836aae396d0ddcb1cbf567436273c820c7c3e1',
}
# This kit's host takes --mainnet for the NEXT rules; the activated program is --mainnet-v1.
ACTIVATED_PROVER_ARGS = ['--mainnet-v1']
FILES = ('settler_v3.py', 'sequencer_policy_v2.py', 'bloch-evm-sp1-settlement-v3', 'bloch-l2-produce-dev', 'settlement_v3_mainnet',
         'bloch-pos', 'mainnet.manifest', 'l2_reorg_recover.py', 'settlement_v3_mainnet_sparse',
         'settlement_v3_mainnet_fallback')
# Foreign settlement recovery (D17: on at launch) reads follower A on this host (go-live plan P3).
FOLLOWER_STATE = '/var/lib/bloch-l2-mainnet-follower/native'
FOLLOWER_STATUS = '/var/lib/bloch-l2-mainnet-follower/status.json'
# Sequencer policy v2 (docs/SEQUENCER-POLICY-V2.md; owner decisions agents/OWNER-DECISIONS-R10.md, 2026-11-02): only with
# user transactions. Needs a prover with the cost line and BLOCH_PREFLIGHT_CYCLE_LIMIT, and a producer with `select`.
POLICY_V2 = {
    'max_block_sp1_gas': 90_000_000, 'max_block_instructions': 90_000_000, 'max_block_txs': 64,
    'max_tx_gas': 5_000_000, 'exempt_max_tx_gas': 15_000_000,
    'fresh_slot_price_wei': 200 * 10**12, 'fresh_slots_per_block': 128, 'fresh_slots_per_sender': 256,
    'producer_write_price': True,  # round 15: the candidate's produce-dev applies the write price itself
    'fresh_sender_window_seconds': 48 * 3600,
    'preflight_cycle_limit_factor': 2, 'preflight_execute_seconds': 90, 'preflight_max_runs': 24,
    'preflight_max_seconds': 180, 'sender_ban_seconds': 86400, 'standing_seconds': 7 * 86400,
    'band_max_wait_seconds': 7200,
    # Try order and gate (agents/243): small/large split floor and weekly recovery, wait for dependent gate refusals.
    'large_gas_floor': 120_000, 'large_gas_recovery_seconds': 7 * 86400, 'gate_dependent_wait_seconds': 3600,
    # Agents 264/304: 8 of the 64 places go by tip alone; preflight runs share one database copy per block plan.
    'tip_reserved_txs': 8, 'preflight_database': 'rewind',
    # Congestion tip ON, capped at 3 gwei (owner, middle ground). Tips go where the L2 fee recipient sends them.
    'congestion_max_tip_wei': 3 * 10**9,
    # Operator and signer addresses only: TBD-owner (40 lowercase hex characters each, no 0x).
    'write_limit_exempt_senders': [],
}
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
            (target / name).chmod(0o644 if name.endswith(('.py', '.manifest')) or name.startswith('settlement_v3_mainnet')
                                  else 0o755)
    for name, pin in PINS.items():
        assert digest(target / name) == pin, f'{name} differs from its pin {pin}'
    settler = settler_module(target)
    assert settler.MAINNET['guest_sha256'] == PINS['settlement_v3_mainnet']
    assert settler.MAINNET_NEXT_SPARSE['guest_sha256'] == PINS['settlement_v3_mainnet_sparse']
    assert settler.MAINNET_FALLBACK['guest_sha256'] == PINS['settlement_v3_mainnet_fallback']
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
    (PUBLIC / 'l2-config.next.bin').write_bytes(settler.mainnet_l2_config(settler.MAINNET_NEXT_SPARSE))
    (PUBLIC / 'l2-config.fallback.bin').write_bytes(settler.mainnet_l2_config(settler.MAINNET_FALLBACK))
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
    assert '--sequencer-policy-v2' not in args or '--user-transactions' in args, \
        '--sequencer-policy-v2 needs --user-transactions'
    custom_budget = [option(args, key) for key in ('--max-block-sp1-gas', '--max-block-instructions')]
    assert all(custom_budget) or not any(custom_budget), 'custom SP1 gas and instruction budgets must be supplied together'
    if any(custom_budget):
        assert all(int(value) > 0 for value in custom_budget), 'custom proving budgets must be positive'
    config = {
        'network_kind': 'mainnet', 'network': settler.MAINNET['network'], 'l2_genesis': settler.MAINNET['l2_genesis'],
        'rpc_urls': rpc_urls, 'rpc_quorum': len(rpc_urls) // 2 + 1,
        'produce': str(rel / 'bloch-l2-produce-dev'), 'l2_db': str(STATE / 'canonical'),
        'workdir': str(STATE / 'work'), 'home': str(STATE),
        'prover': str(rel / 'bloch-evm-sp1-settlement-v3'), 'prover_sha256': digest(rel / 'bloch-evm-sp1-settlement-v3'),
        'prover_args': ACTIVATED_PROVER_ARGS,
        'guest': str(rel / 'settlement_v3_mainnet'), 'guest_sha256': digest(rel / 'settlement_v3_mainnet'),
        'l2_config': str(PUBLIC / 'l2-config.bin'), 'l2_config_sha256': digest(PUBLIC / 'l2-config.bin'),
        # The program L1 installs at the (inert) gate. The worker follows getl2settlement.program; until the
        # gate it only passes --rule-set base to the producer.
        'next_program': {
            'witness': 'sparse', 'prover_args': ['--mainnet', '--sparse'],
            'prover': str(rel / 'bloch-evm-sp1-settlement-v3'), 'prover_sha256': digest(rel / 'bloch-evm-sp1-settlement-v3'),
            'guest': str(rel / 'settlement_v3_mainnet_sparse'), 'guest_sha256': digest(rel / 'settlement_v3_mainnet_sparse'),
            'l2_config': str(PUBLIC / 'l2-config.next.bin'), 'l2_config_sha256': digest(PUBLIC / 'l2-config.next.bin')},
        # The program L1 installs at the (inert) rollback gate in place of the sparse guest: the same rules, the
        # complete witness. Nothing is rewound at a rollback; the block in flight is proved again with this guest.
        'fallback_program': {
            'witness': 'complete', 'prover_args': ['--mainnet'],
            'prover': str(rel / 'bloch-evm-sp1-settlement-v3'), 'prover_sha256': digest(rel / 'bloch-evm-sp1-settlement-v3'),
            'guest': str(rel / 'settlement_v3_mainnet_fallback'), 'guest_sha256': digest(rel / 'settlement_v3_mainnet_fallback'),
            'l2_config': str(PUBLIC / 'l2-config.fallback.bin'),
            'l2_config_sha256': digest(PUBLIC / 'l2-config.fallback.bin')},
        'gnark_image': GNARK_IMAGE, 'prover_threads': threads, 'timestamp_rule': settler.MAINNET_TIMESTAMP_RULE,
        'acceptance_timeout_seconds': 1800, 'poll_seconds': 15, 'resubmit_seconds': 300,
        'idle_seconds': 30, 'max_consecutive_failures': 8,
        'user_transactions': '--user-transactions' in args, 'txpool_dir': str(STATE / 'txpool'),
        'max_block_gas': 15_000_000, 'max_block_bytes': 114_688, 'max_block_txs': 128, 'min_tip_wei': 100_000_000,
        **(POLICY_V2 if '--sequencer-policy-v2' in args else {}),
        **({'skip_idle_blocks': True, 'max_idle_seconds': int(option(args, '--max-idle-seconds', '86400')),
            'min_block_interval_seconds': int(option(args, '--min-block-interval', '0'))}
           if '--skip-idle-blocks' in args else {}),
        'local_prove_max_instructions': LOCAL_PROVE_MAX_INSTRUCTIONS,
        # V2 keeps SP1 gas and instruction budgets distinct; never infer one unit from the other.
        **({'max_block_sp1_gas': int(custom_budget[0]), 'max_block_instructions': int(custom_budget[1])}
           if all(custom_budget) else {}),
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
        # The next program's forced command on the same prover host takes its own key
        # (install-prover-mainnet.py install --program next).
        if not (STATE / 'ssh/id_ed25519_next').exists():
            run([RUNUSER, '-u', USER, '--', 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', USER + '-next',
                 '-f', STATE / 'ssh/id_ed25519_next'])
        config['next_program']['remote_prover'] = {**config['remote_prover'], 'key': str(STATE / 'ssh/id_ed25519_next')}
        # And the fallback program's (install-prover-mainnet.py install --program fallback).
        if not (STATE / 'ssh/id_ed25519_fallback').exists():
            run([RUNUSER, '-u', USER, '--', 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', USER + '-fallback',
                 '-f', STATE / 'ssh/id_ed25519_fallback'])
        config['fallback_program']['remote_prover'] = {**config['remote_prover'],
                                                       'key': str(STATE / 'ssh/id_ed25519_fallback')}
        # Above the prover's own 5,400 s limit (install-prover-mainnet.py), so the prover stops first and says why.
        print('remote prover key (authorize it on the prover host with the forced command):')
        print((STATE / 'ssh/id_ed25519.pub').read_text().strip())
        print('next-program key (authorize it with install-prover-mainnet.py install --program next):')
        print((STATE / 'ssh/id_ed25519_next.pub').read_text().strip())
        print('fallback-program key (authorize it with install-prover-mainnet.py install --program fallback):')
        print((STATE / 'ssh/id_ed25519_fallback.pub').read_text().strip())
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
# 0027: what the worker writes under the setgid state directory is readable by {READ_GROUP} (the RPC reads the
# canonical database, the shadow the work directory); ssh/ and the DA keystore are 0700 and stay private.
UMask=0027
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
'''


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
    for key, guest in (('next_program', 'settlement_v3_mainnet_sparse'),
                       ('fallback_program', 'settlement_v3_mainnet_fallback')):
        if key in config:
            new[key] = {**config[key], 'prover': new['prover'], 'prover_sha256': new['prover_sha256'],
                        'guest': str(rel / guest), 'guest_sha256': digest(rel / guest)}
    new['da'] = {**config['da'], 'signer': str(rel / 'bloch-pos'), 'signer_sha256': digest(rel / 'bloch-pos'),
                 'genesis': str(rel / 'mainnet.manifest')}
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
    for key, guest in (('next_program', 'settlement_v3_mainnet_sparse'),
                       ('fallback_program', 'settlement_v3_mainnet_fallback')):
        if key in config:
            for field, name in (('prover', 'bloch-evm-sp1-settlement-v3'), ('guest', guest)):
                assert Path(config[key][field]) == previous / name, f'kept {key} names another release'
                assert digest(previous / name) == config[key][field + '_sha256'], f'kept {key} {name} changed'
    was_active = unit_active()
    run(['systemctl', 'stop', UNIT_NAME])
    switch(previous, config, {'rolled_back': True})
    if was_active:
        run(['systemctl', 'start', UNIT_NAME])
    print(json.dumps({'rolled_back_to': previous.name, 'from': current.name, 'started': was_active}, indent=2))


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
                'rollback': rollback}
    command = sys.argv[1] if len(sys.argv) > 1 else ''
    if command not in commands:
        raise SystemExit(__doc__)
    commands[command](sys.argv[2:])
