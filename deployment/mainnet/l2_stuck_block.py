#!/usr/bin/env python3
"""Get the L2 past a block the prover cannot finish (see deployment/mainnet/STUCK-BLOCK-RUNBOOK.md).

settler_v3 commits a block to its database before proving it and retries the same block forever. A block that cannot
be proved within the prover's memory or time stops settlement, deposits and withdrawals until an operator acts. L1
has seen nothing of that block: a proof is what opens its DA publication and its settlement. So there are two exits:

  export-job  writes the request and block artifact of the stuck block, to prove on a bigger machine;
  import-proof checks a proof from that machine against this block and hands it to the settler (same block, same hash);
  triage      measures the block transaction by transaction with the guest (execute mode, no proof) and names the
              transactions that do not fit a budget;
  discard     replaces the unsettled block: rebuilds the database at the accepted settlement from verified L1 blocks,
              returns the block's transactions to the spool, and moves the named ones to a quarantine directory.

`status` reads everything and changes nothing. This tool never signs or broadcasts. Stop the settler and every settled
RPC on this database first: `discard` swaps the database, and `import-proof` writes into the settler's work directory.

  l2_stuck_block.py status       --config settler.json
  l2_stuck_block.py export-job   --config settler.json --out NEW_DIR
  l2_stuck_block.py import-proof --config settler.json --proof FILE
  l2_stuck_block.py triage       --config settler.json --budget-gas SP1_GAS [--budget INSTRUCTIONS] --follower-state DIR --follower-status FILE [--out FILE]
  l2_stuck_block.py discard      --config settler.json --follower-state DIR --follower-status FILE
                                 (--exclude HASH ... | --exclude-file FILE | --exclude-all) [--apply]

A block with deposits only cannot be replaced. L1 names exactly the deposits of the next settlement, in order, up to 64
(`MAX_INBOX_PER_SETTLEMENT`), so a replacement would be the same block. `status` and a refused `triage` say what it costs
and that the only exit is a proof from elsewhere: `export-job`, then `import-proof`. Removing the user transactions of a
block whose deposits alone are too heavy does not help either: `triage` says so with `deposits_alone_fit: false`.

Exit codes: 0 done or planned, 75 not possible yet (run again later), 3 refused.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
SETTLER = Path(os.environ.get('BLOCH_SETTLER_V3', str(HERE.parent / 'devnet/settler_v3.py')))
if not SETTLER.exists():
    SETTLER = HERE / 'settler_v3.py'
spec = importlib.util.spec_from_file_location('settler_v3', SETTLER)
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
S.log = lambda event, **fields: print(json.dumps({'event': event, **fields}), file=sys.stderr, flush=True)  # stdout carries only the report


class Refuse(Exception):
    def __init__(self, text, **fields):
        super().__init__(text)
        self.fields = fields


class NotYet(Exception):
    pass


def atomic_write(path, text, mode=0o600):
    tmp = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), 'w') as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    tmp.replace(path)


def batch_transactions(payload):
    """The raw transactions of a canonical DA batch (u32 BE count, then u32 BE length + bytes each)."""
    if S.da_batch_count(payload) is None:
        raise Refuse('malformed DA batch in the stuck block')
    out, at = [], 4
    for _ in range(int.from_bytes(payload[:4], 'big')):
        size = int.from_bytes(payload[at:at + 4], 'big')
        out.append(payload[at + 4:at + 4 + size])
        at += 4 + size
    return out


class Stuck:
    """The unsettled block at the database head, with every fact the decisions below rest on."""

    def __init__(self, config):
        self.config = config
        self.settler = S.Settler(config)
        if not self.settler.check_identity():
            raise NotYet('no RPC quorum on the network identity')
        self.view = self.settler.native_view()
        if self.view is None or self.view.get('source') is None:
            raise NotYet('no RPC quorum on the settlement view, or no source yet')
        accepted = self.view.get('accepted')
        fields = S.statement_fields(accepted['statement']) if accepted else None
        self.accepted_number = fields['l2_number'] if fields else 0
        self.accepted_hash = fields['l2_hash'] if fields else config['l2_genesis']
        self.number = self.accepted_number + 1
        self.db = Path(config['l2_db'])
        self.head = self.settler.produce('head', '--target', str(self.db))
        if self.head['number'] != self.number:
            raise Refuse(f'database head {self.head["number"]} is not one block above accepted {self.accepted_number}: '
                         'no stuck block (or use l2_reorg_recover.py)')
        anchor = self.view['source']['block']
        self.directory = Path(config['workdir']) / f'{self.number:08d}-{anchor[:16]}'
        if not (self.directory / 'block.artifact').exists() or not (self.directory / 'native-request.txt').exists():
            raise Refuse(f'{self.directory} has no block artifact and request: the settler has not prepared this block')
        self.block = {}
        if (self.directory / 'block.json').exists():
            self.block = json.loads((self.directory / 'block.json').read_text())
        if self.block.get('hash') not in (None, self.head['hash']):
            raise Refuse('block.json describes another block than the database head')
        self.temporary = tempfile.TemporaryDirectory(prefix='.stuck-', dir=self.db.parent)

    def facts(self):
        d = self.directory
        records = [r for r in self.view.get('data_availability', []) if r.get('number', r.get('l2_number')) == self.number]
        log_text = (d / 'execute.log').read_text(errors='replace') if (d / 'execute.log').exists() else ''
        found = re.findall(r'(\d+) instructions', log_text)
        sp1_gas = re.findall(r'Settlement V3 cost: gas=(\d+)', log_text)
        return {
            'number': self.number, 'hash': self.head['hash'], 'directory': str(d), 'accepted_number': self.accepted_number,
            'accepted_hash': self.accepted_hash, 'transactions': self.block.get('transactions'),
            'deposits': self.block.get('deposits'), 'declared_gas': self.block.get('declared_gas'),
            'instructions': int(found[-1]) if found else None, 'sp1_gas': int(sp1_gas[-1]) if sp1_gas else None,
            'proved': (d / 'proved.json').exists(),
            'da_prepared': sorted(p.name for p in d.glob('da-unsigned-*.hex')),
            'da_recorded_on_l1': records,
            'settlement_submitted': (d / 'submitted.json').exists(),
            'source_anchor': self.view['source']['block'],
            'deposit_only': self.block.get('transactions') == 0,
            'exit': 'prove elsewhere: export-job, then import-proof' if self.block.get('transactions') == 0
                    else 'prove elsewhere, or triage and discard',
        }

    def raws(self):
        """The block's raw user transactions, from the canonical DA batch of the current database."""
        if not self.block.get('transactions') and self.block:
            return []
        out = Path(self.temporary.name) / 'da.hex'
        out.unlink(missing_ok=True)
        try:
            self.settler.produce('da', '--target', str(self.db), '--number', str(self.number), '--out', str(out))
        except S.ProducerError as error:
            if 'no user transactions' in str(error):
                return []
            raise
        return batch_transactions(bytes.fromhex(out.read_text().strip()))

    def rebuild(self, follower_state, follower_status):
        """A NEW database at the accepted settlement, from verified L1 blocks (or genesis before any settlement)."""
        target = self.db.with_name(self.db.name + f'.rebuilt-{int(time.time())}')
        if self.accepted_number == 0:
            self.settler.produce('init', '--target', str(target))
            head = self.settler.produce('head', '--target', str(target))
            if head['hash'] != self.config['l2_genesis']:
                shutil.rmtree(target, ignore_errors=True)
                raise Refuse('fresh database does not have the pinned L2 genesis')
            return target
        finals = {x['l2_number']: x['l2_hash'] for x in json.loads(Path(follower_status).read_text()).get('finalized_settlements', [])}
        if finals.get(self.accepted_number) != self.accepted_hash:
            raise NotYet(f'settlement {self.accepted_number} is not finalized by the follower yet')
        args = ['reconstruct', '--target', str(target), '--l1-follower', str(follower_state)]
        if self.config.get('timestamp_rule'):
            args += ['--timestamp-rule', self.config['timestamp_rule']]
        try:
            document = self.settler.produce(*args)
        except S.ProducerError as error:
            shutil.rmtree(target, ignore_errors=True)
            raise Refuse(f'rebuild from L1 refused: {error}') from None
        if document.get('head') != self.accepted_hash:
            shutil.rmtree(target, ignore_errors=True)
            raise NotYet(f'rebuilt head {document.get("head")} is not the accepted {self.accepted_hash}')
        return target


def check_replaceable(facts):
    """Only a block L1 has seen nothing of may be replaced."""
    if facts['da_recorded_on_l1']:
        raise Refuse(f'L1 holds a DA record for block {facts["number"]}: it has a proof, so settle it, do not replace it')
    if facts['settlement_submitted']:
        raise Refuse('a settlement of this block was submitted: wait for the outcome, do not replace it')
    if facts['proved']:
        raise Refuse('this block already has a verified proof: start the settler, it will publish and settle it')
    if facts['da_prepared']:
        raise Refuse('a DA transaction was prepared for this block: it may be on L1; check it, do not replace the block')


def export_job(stuck, out):
    out = Path(out)
    out.mkdir(parents=True)
    names = ('native-request.txt', 'block.artifact')
    for name in names:
        shutil.copy2(stuck.directory / name, out / name)
    manifest = {'number': stuck.number, 'hash': stuck.head['hash'], 'guest_sha256': stuck.config.get('guest_sha256'),
                'sha256': {name: S.digest(out / name) for name in names}}
    (out / 'job.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return {'job': str(out), **manifest}


def import_proof(stuck, proof):
    """Local verify against this block's own request and artifact, then the record the settler looks for."""
    facts = stuck.facts()
    if facts['proved']:
        raise Refuse('this block already has a proof')
    target = stuck.directory / 'settlement.proof'
    shutil.copy2(proof, target)
    c = stuck.settler.c
    env = {'PATH': c.get('prover_path', '/usr/bin:/bin'), 'HOME': c['home'], 'TMPDIR': c['home'] + '/tmp',
           'SP1_CIRCUIT_MODE': 'release', 'BLOCH_NATIVE_L2_REQUEST': str(stuck.directory / 'native-request.txt'),
           'BLOCH_NATIVE_L2_ARTIFACT': str(stuck.directory / 'block.artifact')}
    with (stuck.directory / 'verify.log').open('w') as out:
        result = stuck.settler.run([c['prover'], *stuck.settler.prover_args, 'verify-groth16', 'native-artifact', c['guest'], str(target)],
                                   env=env, stdout=out, stderr=-2, timeout=3600)
    if result.returncode:
        target.unlink(missing_ok=True)
        raise Refuse(f'proof does not verify against this block: see {stuck.directory}/verify.log')
    atomic_write(stuck.directory / 'proved.json',
                 json.dumps({'steps': [{'name': 'import', 'where': 'external', 'exit_code': 0, 'seconds': 0}],
                             'proof_sha256': S.digest(target)}, indent=2) + '\n', mode=0o644)
    return {'imported': str(target), 'proof_sha256': S.digest(target), 'number': stuck.number, 'hash': stuck.head['hash']}


def measure(stuck, base, kept, workspace, tag):
    """Instructions of the block built on `base` from exactly these transactions (no proof, no lock)."""
    db = workspace / f'db-{tag}'
    shutil.rmtree(db, ignore_errors=True)
    S.copy_database(base, db)  # no mode bits: the read-group database is setgid (F312-7, R308-5P-7)
    block_dir = workspace / f'block-{tag}'
    shutil.rmtree(block_dir, ignore_errors=True)
    block_dir.mkdir()
    pool = block_dir / 'pool.json'
    pool.write_text(json.dumps([raw.hex() for raw in kept]))
    source = stuck.view['source']
    args = ['extend', '--target', str(db), '--parent', stuck.accepted_hash, '--anchor', source['block'],
            '--deposits', str(stuck.directory / 'deposits.json')]
    if stuck.config.get('timestamp_rule'):
        args += ['--timestamp-rule', stuck.config['timestamp_rule'], '--anchor-slot', source['request'].splitlines()[3]]
    args += ['--txs', str(pool), '--max-gas', str(stuck.config['max_block_gas']), '--max-bytes', str(stuck.config['max_block_bytes']),
             '--max-txs', str(stuck.config['max_block_txs'])]
    block = stuck.settler.produce(*args)
    stuck.settler.produce('export', '--target', str(db), '--number', str(stuck.number), '--out', str(block_dir / 'block.artifact'))
    shutil.copy2(stuck.directory / 'native-request.txt', block_dir / 'native-request.txt')
    stuck.settler.prove(block_dir, stages=('execute',))
    log_text = (block_dir / 'execute.log').read_text(errors='replace')
    found = re.findall(r'(\d+) instructions', log_text)
    gas = re.findall(r'Settlement V3 cost: gas=(\d+)', log_text)
    shutil.rmtree(db, ignore_errors=True)
    shutil.rmtree(block_dir, ignore_errors=True)
    if not found:
        raise Refuse('the guest did not report an instruction count')
    return int(found[-1]), int(gas[-1]) if gas else None, block


def fits_budget(instructions, gas, budget, budget_gas):
    """Against SP1 gas first: a guest that reports none cannot pass that budget. Instructions only when a budget names them."""
    if budget_gas is not None and (gas is None or gas > budget_gas):
        return False
    return budget is None or instructions <= budget


def triage(stuck, budget, budget_gas, follower_state, follower_status, out=None):
    """Greedy, in block order: keep a transaction when the block with it still fits the budget."""
    raws = stuck.raws()
    if not raws:
        facts = stuck.facts()
        raise Refuse('this block has no user transactions: replacing it cannot make it smaller; prove it elsewhere',
                     sp1_gas=facts['sp1_gas'], instructions=facts['instructions'], deposits=facts['deposits'],
                     next_step='export-job, prove on a bigger machine, import-proof')
    workspace = Path(tempfile.mkdtemp(prefix='.triage-', dir=stuck.db.parent))
    base = stuck.rebuild(follower_state, follower_status)
    try:
        kept, quarantine, steps = [], [], []
        current, gas, _ = measure(stuck, base, [], workspace, 'base')
        steps.append({'hash': None, 'instructions': current, 'sp1_gas': gas})
        deposits_fit = fits_budget(current, gas, budget, budget_gas)
        for raw in raws:
            name = S.keccak256(raw).hex()
            instructions, gas, block = measure(stuck, base, kept + [raw], workspace, 'step')
            taken = name in block.get('included', [])
            fits = fits_budget(instructions, gas, budget, budget_gas)
            steps.append({'hash': name, 'instructions': instructions, 'sp1_gas': gas, 'delta': instructions - current, 'included': taken, 'fits': fits})
            if fits:
                kept.append(raw)
                current = instructions
            else:
                quarantine.append(name)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
        shutil.rmtree(base, ignore_errors=True)
    report = {'number': stuck.number, 'budget': budget, 'budget_gas': budget_gas, 'deposits_alone_fit': deposits_fit, 'kept': len(kept), 'exclude': quarantine, 'instructions_after': current, 'steps': steps}
    if out:
        atomic_write(Path(out), json.dumps(report, indent=1) + '\n', mode=0o644)
    return report


def discard(stuck, exclude, exclude_all, follower_state, follower_status, apply):
    facts = stuck.facts()
    check_replaceable(facts)
    raws = stuck.raws()
    if not raws:
        raise Refuse('this block has no user transactions: its replacement would be the same block; prove it elsewhere')
    hashes = {S.keccak256(raw).hex(): raw for raw in raws}
    unknown = sorted(set(exclude) - set(hashes))
    if unknown:
        raise Refuse(f'not in this block: {unknown}')
    excluded = set(hashes) if exclude_all else set(exclude)
    if not excluded:
        raise Refuse('name the transactions to quarantine: the same transactions would rebuild the same stuck block')
    rebuilt = stuck.rebuild(follower_state, follower_status)
    report = {'number': stuck.number, 'old_hash': stuck.head['hash'], 'accepted_hash': stuck.accepted_hash, 'apply': apply,
              'respool': sorted(set(hashes) - excluded), 'quarantine': sorted(excluded)}
    if not apply:
        shutil.rmtree(rebuilt, ignore_errors=True)
        return report
    stamp = int(time.time())
    pool = Path(stuck.config['txpool_dir'])
    quarantine = pool.parent / f'{pool.name}-quarantine'
    quarantine.mkdir(exist_ok=True, mode=0o700)
    for name, raw in hashes.items():
        atomic_write((quarantine if name in excluded else pool) / f'{name}.tx', raw.hex() + '\n')
    work = Path(stuck.config['workdir'])
    aside = work.parent / f'{work.name}-discarded-{stamp}'
    aside.mkdir()
    (aside / 'discard.json').write_text(json.dumps(report, indent=2) + '\n')
    stuck.directory.rename(aside / stuck.directory.name)
    kept = stuck.db.with_name(f'{stuck.db.name}.discarded-{stamp}')
    stuck.db.rename(kept)
    rebuilt.rename(stuck.db)
    report.update(old_database=str(kept), old_work=str(aside), quarantine_dir=str(quarantine))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['status', 'export-job', 'import-proof', 'triage', 'discard'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--out')
    parser.add_argument('--proof')
    parser.add_argument('--budget', type=int)
    parser.add_argument('--budget-gas', type=int)
    parser.add_argument('--follower-state')
    parser.add_argument('--follower-status')
    parser.add_argument('--exclude', action='append', default=[])
    parser.add_argument('--exclude-file')
    parser.add_argument('--exclude-all', action='store_true')
    parser.add_argument('--apply', action='store_true')
    o = parser.parse_args()
    config = json.loads(Path(o.config).read_text())
    try:
        stuck = Stuck(config)
        if o.command == 'status':
            result = stuck.facts()
        elif o.command == 'export-job':
            result = export_job(stuck, o.out)
        elif o.command == 'import-proof':
            result = import_proof(stuck, o.proof)
        else:
            if not o.follower_state or not o.follower_status:
                parser.error('--follower-state and --follower-status are required')
            if o.command == 'triage':
                if o.budget is None and o.budget_gas is None:
                    parser.error('triage needs --budget-gas (or --budget)')
                check_replaceable(stuck.facts())
                result = triage(stuck, o.budget, o.budget_gas, o.follower_state, o.follower_status, o.out)
            else:
                exclude = list(o.exclude)
                if o.exclude_file:
                    exclude += json.loads(Path(o.exclude_file).read_text())['exclude']
                result = discard(stuck, [x.removeprefix('0x') for x in exclude], o.exclude_all, o.follower_state, o.follower_status, o.apply)
        print(json.dumps(result, indent=1))
    except NotYet as why:
        print(json.dumps({'not_yet': str(why)}))
        sys.exit(75)
    except (Refuse, S.Halt, S.ProducerError) as why:
        print(json.dumps({'refused': str(why), **getattr(why, 'fields', {})}))
        sys.exit(3)


if __name__ == '__main__':
    main()
