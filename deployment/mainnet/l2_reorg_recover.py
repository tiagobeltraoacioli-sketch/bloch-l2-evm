#!/usr/bin/env python3
"""Recover the settler's L2 database after an L1 reorg removed an accepted, unfinalized settlement.

settler_v3 halts (exit 3) when the database does not extend what L1 accepted: "L2 head N cannot extend accepted
settlement M" (a database ahead of L1 after a reorg, or behind it after an old backup was restored), or an unsettled
block with another anchor. This tool is the operator's repair. It never signs, broadcasts or edits a database in
place:

1. reads the accepted settlement from a quorum of native RPCs;
2. refuses (exit 75, run again later) until the follower has finalized that settlement;
3. rebuilds a NEW database from verified L1 blocks with `produce reconstruct` and requires its head to be exactly the
   accepted L2 hash;
4. returns the user transactions of unsettled blocks to the spool: from each orphaned work directory's DA batch, from
   the work directories named with --respool-from (the pre-restore `work/` of a restored backup), and from every DA
   batch above the accepted number that the settler's own DA key published on L1 (read from the follower's verified
   blocks and checked against the recorded commitment). A database behind the accepted head has no work directory
   for those blocks: their paid batches on L1 are the only copy the restore left;
5. moves orphaned work directories aside, and swaps the databases, keeping the old one for review.

Stop the settler and every settled RPC on this database first: the swap is not visible to a running process.

  l2_reorg_recover.py --config settler.json --follower-state DIR [--respool-from WORK_DIR ...] [--apply]

Without --apply it reports the plan and changes nothing. Exit: 0 done or planned, 75 not finalized yet, 3 refused.
"""
import argparse
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SETTLER = Path(os.environ.get('BLOCH_SETTLER_V3', str(HERE.parent / 'devnet/settler_v3.py')))
if not SETTLER.exists():
    SETTLER = HERE / 'settler_v3.py'
spec = importlib.util.spec_from_file_location('settler_v3', SETTLER)
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


class Refuse(Exception):
    pass


class NotYet(Exception):
    pass


def batch_transactions(payload):
    """The raw transactions of a canonical DA batch (u32 BE count, then u32 BE length + bytes each)."""
    if S.da_batch_count(payload) is None:
        raise Refuse('malformed DA batch in an orphaned block')
    out, at = [], 4
    for _ in range(int.from_bytes(payload[:4], 'big')):
        size = int.from_bytes(payload[at:at + 4], 'big')
        out.append(payload[at + 4:at + 4 + size])
        at += 4 + size
    return out


def orphaned_dirs(work, accepted):
    """Work directories of L2 blocks above the accepted number (NNNNNNNN-anchor)."""
    found = []
    for path in sorted(Path(work).iterdir()):
        head = path.name.split('-')[0]
        if path.is_dir() and len(head) == 8 and head.isdigit() and int(head) > accepted:
            found.append(path)
    return found


def respool(directories, pool):
    """Write each orphaned user transaction as a spool entry, whole or not at all. Returns the new file names."""
    written = []
    for directory in directories:
        payload = directory / 'da-payload.hex'
        if not payload.exists():
            continue
        for raw in batch_transactions(bytes.fromhex(payload.read_text().strip())):
            name = S.keccak256(raw).hex() + '.tx'
            target = Path(pool) / name
            if not target.exists():
                S.atomic_write(target, raw.hex() + '\n')
                target.chmod(0o600)
                written.append(name)
    return written


def respool_payloads(payloads, pool):
    """Write the transactions of DA batches (bytes) as spool entries, whole or not at all. Returns the new names."""
    written = []
    for payload in payloads:
        for raw in batch_transactions(payload):
            name = S.keccak256(raw).hex() + '.tx'
            target = Path(pool) / name
            if not target.exists():
                S.atomic_write(target, raw.hex() + '\n')
                target.chmod(0o600)
                written.append(name)
    return written


def own_l1_batches(config, settler, view, number, follower_state):
    """{(l2 number, commitment): payload} of the DA batches above `number` that the settler's own DA key published,
    read from the follower's verified L1 blocks. Batches of other keys are never respooled."""
    records = [r for r in view.get('data_availability', []) if int(r['l2_number']) > number]
    da = config.get('da') or {}
    if not records or not da.get('funding_pubkey'):
        return {}
    own = bytes.fromhex(Path(da['funding_pubkey']).read_text().strip())
    found = S.recorded_da_batches(follower_state, settler.chain_id, records)
    return {key: payload for key, (key_bytes, payload) in found.items() if key_bytes == own}


def finalized_hash(state, status_path, number):
    """The L2 hash the follower finalized at `number`, or None. Status v2 lists every settlement; v3 lists the
    newest and names a log with one line per settlement, in number order."""
    entries = state.get('finalized_settlements') or state.get('finalized_settlements_recent') or []
    for entry in entries:
        if entry['l2_number'] == number:
            return entry['l2_hash']
    log = state.get('settlement_log')
    if not log or not status_path or not 1 <= number <= log['entries'] or '/' in log['file']:
        return None
    with open(Path(status_path).with_name(log['file']), 'rb') as f:
        for index, line in enumerate(f, 1):
            if index == number:
                entry = json.loads(line)
                return entry['l2_hash'] if entry['l2_number'] == number else None
    return None


def plan(config, follower_state, apply, run=subprocess.run, status=None, respool_from=(), settler=None):
    settler = settler or S.Settler(config)
    if not settler.check_identity():
        raise NotYet('no RPC quorum on the network identity')
    view = settler.native_view()
    if view is None:
        raise NotYet('no RPC quorum on the settlement view')
    accepted = view.get('accepted')
    if not accepted:
        raise Refuse('no accepted settlement: rebuild is the initial database, do it by hand')
    fields = S.statement_fields(accepted['statement'])
    number, l2_hash = fields['l2_number'], fields['l2_hash']
    db = Path(config['l2_db'])
    head = settler.produce('head', '--target', str(db))
    report = {'accepted_number': number, 'accepted_hash': l2_hash, 'database_head': head['number'], 'apply': apply}
    if head['number'] == number and settler.local_hash(number) == l2_hash:
        raise Refuse(f'database head {number} is the accepted head: nothing to recover')
    # Behind: an old backup restored, or a database rebuilt before the latest settlement. Its unsettled blocks
    # have no work directory any more; their user transactions come back from the paid batches on L1.
    report['database'] = "behind" if head['number'] < number else "ahead" if head['number'] > number else "forked"
    state = status if status is not None else json.loads(Path(config['follower_status']).read_text()) if config.get('follower_status') else None
    if state is not None:
        if finalized_hash(state, config.get('follower_status'), number) != l2_hash:
            raise NotYet(f'settlement {number} is not finalized by the follower yet')
    rebuilt = db.with_name(db.name + f'.rebuilt-{int(time.time())}')
    args = ['reconstruct', '--target', str(rebuilt), '--l1-follower', str(follower_state)]
    if config.get('timestamp_rule'):
        args += ['--timestamp-rule', config['timestamp_rule']]
    try:
        document = settler.produce(*args)
    except S.ProducerError as error:
        shutil.rmtree(rebuilt, ignore_errors=True)
        raise Refuse(f'rebuild from L1 refused: {error}') from None
    if document.get('head') != l2_hash:
        # A later settlement may already be final; never truncate L1 truth, and never accept another head.
        shutil.rmtree(rebuilt, ignore_errors=True)
        raise NotYet(f'rebuilt head {document.get("head")} is not the accepted {l2_hash}')
    work = Path(config['workdir'])
    orphans = orphaned_dirs(work, number)
    extra = [p for d in respool_from for p in orphaned_dirs(d, number)]
    l1 = own_l1_batches(config, settler, view, number, follower_state) if config.get('user_transactions') else {}
    report['rebuilt_settled'] = document.get('settled')
    report['orphaned_blocks'] = [p.name for p in orphans]
    report['respool_from'] = [str(p) for p in extra]
    report['l1_batches'] = sorted(f'{n}:{c[:16]}' for n, c in l1)
    if not apply:
        shutil.rmtree(rebuilt, ignore_errors=True)
        return report
    stamp = int(time.time())
    if config.get('txpool_dir'):
        written = respool(orphans + extra, config['txpool_dir'])
        written += respool_payloads([l1[k] for k in sorted(l1)], config['txpool_dir'])
        report['respooled'] = len(written)
    else:
        report['respooled'] = 0
    aside = work.parent / f'{work.name}-orphaned-{stamp}'
    aside.mkdir()
    for path in orphans:
        path.rename(aside / path.name)
    kept = db.with_name(f'{db.name}.orphaned-{stamp}')
    db.rename(kept)
    rebuilt.rename(db)
    report['old_database'] = str(kept)
    report['orphaned_work'] = str(aside)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', required=True)
    parser.add_argument('--follower-state', required=True)
    parser.add_argument('--follower-status', help='follower status file; required unless named in the config')
    parser.add_argument('--respool-from', action='append', default=[], metavar='WORK_DIR',
                        help='also respool the DA batches of blocks above the accepted number in this work directory '
                             '(the pre-restore work/ of a restored backup); repeatable')
    parser.add_argument('--apply', action='store_true')
    options = parser.parse_args()
    config = json.loads(Path(options.config).read_text())
    if options.follower_status:
        config['follower_status'] = options.follower_status
    if not config.get('follower_status'):
        parser.error('--follower-status is required')
    try:
        # The worker's progress lines go to stderr: stdout is exactly one JSON document.
        with contextlib.redirect_stdout(sys.stderr):
            report = plan(config, options.follower_state, options.apply, respool_from=options.respool_from)
        print(json.dumps(report, indent=1))
    except NotYet as why:
        print(json.dumps({'not_yet': str(why)}))
        sys.exit(75)
    except (Refuse, S.Halt) as why:
        print(json.dumps({'refused': str(why)}))
        sys.exit(3)


if __name__ == '__main__':
    main()
