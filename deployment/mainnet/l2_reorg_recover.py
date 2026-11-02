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
4. returns the user transactions of unsettled blocks to the spool: from each orphaned work directory's DA batch and
   from the work directories named with --respool-from (the pre-restore `work/` of a restored backup). DA batches
   found on L1 are never re-spooled: L1 does not show who paid for a batch, so a batch posted by anyone could be
   taken for this settler's (agents/145 F1). A database behind the accepted head has no work directory for its
   unsettled blocks: keep the pre-restore `work/` and pass it with --respool-from;
5. moves orphaned work directories aside, and swaps the databases, keeping the old one for review.

Orphaned blocks are those off the accepted chain: every local block above the highest local block whose hash equals
the canonical one (the common ancestor), and every work directory above the accepted number. The canonical hashes
come from the rebuild's `blocks` and from the follower's finalized settlements (review r10 L2: a database "forked" at
the accepted number, or "ahead" after a deeper reorg, also orphans its blocks at or below that number).

The rebuild gets `--rebuild-timeout` (default: the config's `foreign_recovery.rebuild_timeout_seconds`, else 3600 s),
not the 300 s of the other producer commands (review r10 L3). The swap is journalled in `<l2_db>.recovery.json`, the
format the worker's own foreign recovery uses: a run interrupted between its renames is finished by the next
`--apply`, or by the worker's `finish_swap` when it starts (review r10 L4).

Stop the settler and every settled RPC on this database first: the swap is not visible to a running process.

  l2_reorg_recover.py --config settler.json --follower-state DIR [--respool-from WORK_DIR ...] [--rebuild-timeout S] [--apply]

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


def orphaned_dirs(work, accepted, off_chain=()):
    """Work directories of L2 blocks above the accepted number, or numbered in `off_chain` (NNNNNNNN-anchor)."""
    found = []
    for path in sorted(Path(work).iterdir()):
        head = path.name.split('-')[0]
        if path.is_dir() and len(head) == 8 and head.isdigit() and (int(head) > accepted or int(head) in off_chain):
            found.append(path)
    return found


def common_ancestor(settler, local_head, number, canonical):
    """(highest local block number whose hash is canonical, whether that was assumed). `canonical(k)` is the
    accepted chain's hash at k or None when unknown; an unknown hash ends the walk there (assumed common), which is
    the behaviour before review r10 L2."""
    for k in range(min(local_head, number), 0, -1):
        expected = canonical(k)
        if expected is None:
            return k, True
        if settler.local_hash(k) == expected:
            return k, False
    return 0, False


def finish_swap(journal_path, l2_db, work):
    """Complete a journalled swap. Every step is skipped once done, so a crash at any point resumes here. The journal
    has the worker's format (settler_v3 Settler.finish_swap), so a restarted worker finishes it too."""
    state = json.loads(Path(journal_path).read_text())
    db, rebuilt, kept = Path(l2_db), Path(state['rebuilt']), Path(state['kept'])
    if rebuilt.exists():
        if db.exists():
            db.rename(kept)
        rebuilt.rename(db)
    aside = Path(state['work_aside'])
    aside.mkdir(exist_ok=True)
    for name in state['stale']:
        if (Path(work) / name).exists():
            (Path(work) / name).rename(aside / name)
    S.atomic_write(Path(work).parent / 'l2-db-generation.json', json.dumps(
        {'database': str(db), 'number': state['number'], 'l2_hash': state['l2_hash'], 'time': int(time.time())}) + '\n')
    Path(journal_path).unlink()
    return state


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


def rebuild_timeout(config):
    return int((config.get('foreign_recovery') or {}).get('rebuild_timeout_seconds', 3600))


def plan(config, follower_state, apply, run=subprocess.run, status=None, respool_from=(), settler=None,
         timeout=None):
    db = Path(config['l2_db'])
    journal = db.with_name(db.name + '.recovery.json')
    if journal.exists():
        # Review r10 L4: an interrupted swap (this tool's or the worker's) is finished before anything else.
        if not apply:
            raise Refuse(f'{journal} records an unfinished database swap: run again with --apply to finish it')
        state = finish_swap(journal, db, config['workdir'])
        return {'finished_interrupted_swap': True, 'number': state['number'], 'l2_hash': state['l2_hash'],
                'old_database': state['kept'], 'orphaned_work': state['work_aside'], 'apply': apply}
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
    head = settler.produce('head', '--target', str(db))
    report = {'accepted_number': number, 'accepted_hash': l2_hash, 'database_head': head['number'], 'apply': apply}
    if head['number'] == number and settler.local_hash(number) == l2_hash:
        raise Refuse(f'database head {number} is the accepted head: nothing to recover')
    # Behind: an old backup restored, or a database rebuilt before the latest settlement. Its unsettled blocks
    # have no work directory any more: their user transactions come back only from --respool-from (the pre-restore work/).
    report['database'] = "behind" if head['number'] < number else "ahead" if head['number'] > number else "forked"
    state = status if status is not None else json.loads(Path(config['follower_status']).read_text()) if config.get('follower_status') else None
    if state is not None:
        if finalized_hash(state, config.get('follower_status'), number) != l2_hash:
            raise NotYet(f'settlement {number} is not finalized by the follower yet')
    stamp = time.time_ns()
    rebuilt = db.with_name(db.name + f'.rebuilt-{stamp}')
    args = ['reconstruct', '--target', str(rebuilt), '--l1-follower', str(follower_state)]
    if config.get('timestamp_rule'):
        args += ['--timestamp-rule', config['timestamp_rule']]
    seconds = timeout if timeout is not None else rebuild_timeout(config)
    try:
        # Review r10 L3: a rebuild replays the whole L2 chain; it gets the rebuild timeout, not the producer's 300 s.
        document = settler.produce(*args, timeout=seconds)
    except S.ProducerError as error:
        shutil.rmtree(rebuilt, ignore_errors=True)
        raise Refuse(f'rebuild from L1 refused: {error}') from None
    except subprocess.TimeoutExpired:
        shutil.rmtree(rebuilt, ignore_errors=True)
        raise Refuse(f'rebuild from L1 did not finish in {seconds} s: run again with a larger --rebuild-timeout') from None
    if document.get('head') != l2_hash:
        # A later settlement may already be final; never truncate L1 truth, and never accept another head.
        shutil.rmtree(rebuilt, ignore_errors=True)
        raise NotYet(f'rebuilt head {document.get("head")} is not the accepted {l2_hash}')
    rebuilt_hashes = {b['number']: b['hash'] for b in document.get('blocks', []) if 'number' in b and 'hash' in b}

    def canonical(k):
        if k == number:
            return l2_hash
        if k in rebuilt_hashes:
            return rebuilt_hashes[k]
        return finalized_hash(state, config.get('follower_status'), k) if state is not None else None
    common, assumed = common_ancestor(settler, head['number'], number, canonical)
    off_chain = set(range(common + 1, min(head['number'], number) + 1))
    work = Path(config['workdir'])
    orphans = orphaned_dirs(work, number, off_chain)
    extra = [p for d in respool_from for p in orphaned_dirs(d, number)]
    report['common_ancestor'] = common
    if assumed:
        report['common_ancestor_assumed'] = True
    report['rebuilt_settled'] = document.get('settled')
    report['orphaned_blocks'] = [p.name for p in orphans]
    report['respool_from'] = [str(p) for p in extra]
    if not apply:
        shutil.rmtree(rebuilt, ignore_errors=True)
        return report
    if config.get('txpool_dir'):
        report['respooled'] = len(respool(orphans + extra, config['txpool_dir']))
    else:
        report['respooled'] = 0
    aside = work.parent / f'{work.name}-orphaned-{stamp}'
    kept = db.with_name(f'{db.name}.orphaned-{stamp}')
    # Review r10 L4: journal first, then rename; a failure between the renames is finished by the next run.
    S.atomic_write(journal, json.dumps({'rebuilt': str(rebuilt), 'kept': str(kept), 'work_aside': str(aside),
                                        'stale': [p.name for p in orphans], 'number': number, 'l2_hash': l2_hash},
                                       indent=2) + '\n')
    finish_swap(journal, db, work)
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
    parser.add_argument('--rebuild-timeout', type=int, metavar='SECONDS',
                        help='time allowed for `produce reconstruct` (default: foreign_recovery.rebuild_timeout_seconds '
                             'from the config, else 3600)')
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
            report = plan(config, options.follower_state, options.apply, respool_from=options.respool_from,
                          timeout=options.rebuild_timeout)
        print(json.dumps(report, indent=1))
    except NotYet as why:
        print(json.dumps({'not_yet': str(why)}))
        sys.exit(75)
    except (Refuse, S.Halt) as why:
        print(json.dumps({'refused': str(why)}))
        sys.exit(3)


if __name__ == '__main__':
    main()
