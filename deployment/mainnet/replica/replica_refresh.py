#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rebuild the replica's L2 database from the follower's verified L1 blocks and publish it.

`reconstruct` refuses an existing target, so every rebuild is a new generation under
STATE/generations. `current` is a symlink swapped atomically; the RPC is restarted by the
path unit that watches STATE/refresh/generation. A rebuild that does not change the settled
chain is discarded, so the RPC is not restarted once per epoch.

Exit 0: published, unchanged or still waiting for the follower. Exit 3: the rebuild contradicts
the pins, the finalized settlements or an earlier generation; the current database stays in place.
Uses only the follower's state and the local disk. It holds no secret and opens no socket.
"""
import argparse
import fcntl
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

NETWORK = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'
CHAIN_ID = 700770
L2_GENESIS = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
NETWORK_ARGS = ['--rules', 'mainnet', '--domain', '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733',
                '--genesis-time', '1786656679']
TIMESTAMP_RULE = '1:1786656679:30000'
SCHEMA = 'bloch.l2.native-follower-status.v2'
SCHEMA_V3 = 'bloch.l2.native-follower-status.v3'
KEEP_GENERATIONS = 2


class Halt(Exception):
    pass


def log(event, **fields):
    print(json.dumps({'event': event, 'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), **fields}), flush=True)


def write_atomic(path, text):
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(text)
    os.replace(tmp, path)



def settlements_of(status, path):
    """Every finalized settlement of a follower status, oldest first: the list in schema v2, or the log beside the file
    in schema v3, which must hold exactly what the status names. Every entry is compared with the rebuilt chain later."""
    if status.get('schema') != SCHEMA_V3:
        return status.get('finalized_settlements', [])
    log = status.get('settlement_log') or {}
    name, entries, size = log.get('file'), log.get('entries'), log.get('bytes')
    if not isinstance(name, str) or not name or '/' in name or name in ('.', '..'):
        raise ValueError('the follower status names a bad settlement log')
    data = b''
    if entries:
        with open(Path(path).with_name(name), 'rb') as f:
            data = f.read(size)
    lines = data.splitlines()
    if len(data) != size or len(lines) != entries:
        raise ValueError('the follower settlement log does not match its status')
    settlements = [json.loads(line) for line in lines]
    if [s.get('l2_number') for s in settlements] != list(range(1, len(settlements) + 1)):
        raise ValueError('the follower settlement log is not contiguous from block 1')
    recent = status.get('finalized_settlements_recent') or []
    if entries and (not recent or settlements[-len(recent):] != recent):
        raise ValueError('the follower settlement log differs from its status')
    return settlements


def read_status(path, max_age, now):
    """The follower's status, or None while it is still replaying. A status for anything else is a halt."""
    try:
        status = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    if status.get('schema') not in (SCHEMA, SCHEMA_V3) or status.get('network') != NETWORK or status.get('chain_id') != CHAIN_ID \
            or status.get('production_finality') is not False:
        raise Halt('the follower status is for another network or schema')
    genesis = status.get('l2_genesis') or {}
    if genesis.get('hash') != L2_GENESIS:
        raise Halt(f'the follower reports L2 genesis {genesis.get("hash")}, not the pin')
    if genesis.get('finalized') is not True or now - status.get('written_at_unix', 0) > max_age:
        return None
    try:
        status['finalized_settlements'] = settlements_of(status, path)
    except (OSError, ValueError) as e:
        raise Halt(f'follower settlement log: {e}') from None
    return status


def rebuild(produce, native, target, timeout, attempts=3):
    done = None
    for _ in range(attempts):  # the follower may be appending to its index
        done = subprocess.run([produce, 'reconstruct', '--target', str(target), '--l1-follower', str(native),
                               '--timestamp-rule', TIMESTAMP_RULE, *NETWORK_ARGS],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout)
        if done.returncode == 0:
            return json.loads(done.stdout)
        shutil.rmtree(target, ignore_errors=True)
        time.sleep(2)
    raise Halt(f'reconstruct failed: {done.stderr.strip()[-800:]}')


def check_report(report, status, previous):
    """The rebuilt chain must hold the pin, every finalized settlement and every block published before."""
    if report.get('genesis') != L2_GENESIS:
        raise Halt(f'the rebuilt L2 genesis {report.get("genesis")} differs from the pin')
    blocks = {b['number']: b for b in report.get('blocks', [])}
    # read_status puts the whole log of a schema v3 status in this list; a status without it still has its newest.
    for s in status.get('finalized_settlements') or status.get('finalized_settlements_recent', []):
        b = blocks.get(s['l2_number'])
        if b is None or (b['hash'], b['state_root']) != (s['l2_hash'], s['l2_state_root']) or \
                (s.get('withdrawals') and s['withdrawals'] != {'root': b['withdrawal_root'], 'count': b['withdrawal_count']}):
            raise Halt(f'L2 block {s["l2_number"]} rebuilt from L1 differs from the finalized settlement')
    for number, block_hash in (previous or {}).get('chain', {}).items():
        b = blocks.get(int(number))
        if b is None or b['hash'] != block_hash:
            raise Halt(f'L2 block {number} was published before and the rebuild no longer holds it')


def prune(generations, keep):
    """Remove every generation except the newest `keep` and the one `current` points to."""
    current = (generations / 'current').resolve() if (generations / 'current').exists() else None
    found = sorted(p for p in generations.iterdir() if p.name.startswith('g-') and p.is_dir() and not p.is_symlink())
    for path in found[:-keep] if keep else found:
        if path.resolve() != current:
            shutil.rmtree(path, ignore_errors=True)


def refresh(a):
    state = Path(a.state)
    generations, work = state / 'generations', state / 'refresh'
    now = time.time()
    status = read_status(state / 'follower/status.json', a.max_status_age, now)
    if status is None:
        log('waiting-for-follower')
        return
    meta_path, seen_path = work / 'generation', work / 'seen-tip'
    previous = json.loads(meta_path.read_text()) if meta_path.exists() else None
    current_ok = (generations / 'current/db').is_dir()
    tip = status.get('verified_tip')
    if current_ok and seen_path.exists() and seen_path.read_text() == tip:
        log('unchanged', verified_tip=tip)
        return
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now))
    target = generations / f'g-{stamp}'
    if target.exists():
        raise Halt(f'{target} already exists')
    started = time.time()
    report = rebuild(a.produce, state / 'follower/native', target, a.timeout)
    try:
        check_report(report, status, previous)
    except Halt:
        shutil.rmtree(target, ignore_errors=True)
        raise
    chain = {str(b['number']): b['hash'] for b in report['blocks']}
    if current_ok and previous is not None and chain == previous.get('chain'):
        shutil.rmtree(target, ignore_errors=True)
        write_atomic(seen_path, tip)
        log('unchanged-after-rebuild', verified_tip=tip, native_blocks=report.get('native_blocks'),
            seconds=round(time.time() - started, 1))
        prune(generations, KEEP_GENERATIONS)
        return
    link = generations / 'current.tmp'
    if link.is_symlink():
        link.unlink()
    link.symlink_to(target.name)
    os.replace(link, generations / 'current')
    write_atomic(seen_path, tip)
    write_atomic(meta_path, json.dumps({'generation': target.name, 'genesis': report['genesis'],
                                        'settled': report.get('settled'), 'head': report.get('head'),
                                        'native_blocks': report.get('native_blocks'), 'verified_tip': tip,
                                        'chain': chain}))
    log('published', generation=target.name, settled=report.get('settled'), head=report.get('head'),
        native_blocks=report.get('native_blocks'), seconds=round(time.time() - started, 1))
    prune(generations, KEEP_GENERATIONS)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--produce', required=True)
    p.add_argument('--state', required=True)
    p.add_argument('--max-status-age', type=int, default=3600)
    p.add_argument('--timeout', type=int, default=1800)
    a = p.parse_args(argv)
    with open(Path(a.state) / 'refresh/lock', 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log('already-running')
            return 0
        try:
            refresh(a)
        except Halt as e:
            log('halt', reason=str(e))
            return 3
    return 0


if __name__ == '__main__':
    sys.exit(main())
