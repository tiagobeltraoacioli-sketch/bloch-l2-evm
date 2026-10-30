#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bloch L2 MAINNET withdrawal attestor agent (chain 700770, attestor set 1c06adbb…, 3-of-5).

One agent runs on each attestor operator's host with that operator's sealed key. It signs, with
`bloch-pos l2-claim attest`, every withdrawal root a large claim (>= 100 BLCH) could prove
against, and only roots it rebuilt itself from L1 data. No recurring manual work: an operator
acts on alerts only.

  attestor_agent.py run    --config FILE              loop (the systemd unit)
  attestor_agent.py once   --config FILE [--dry-run]  one cycle; --dry-run never signs
  attestor_agent.py check  --config FILE [--no-key]   read-only self-check (pins, key, follower, RPC)

How requests are discovered (no queue, no claimant input). The native L1 retains a record per
settlement that added withdrawals (`getl2settlement withdrawals.roots`); a claim of >= 100 BLCH
must prove against the newest record at least 2880 blocks old (`matured_large`). So each cycle:

 1. Follower: this host's own `bloch-l2-native-follower` status (FFG replay of L1 from the pinned
    Genesis-4 manifest) must be fresh, on network f47d3e49…, with the L2 genesis finalized.
 2. RPC quorum: `getl2settlement` from the configured read-only RPCs; only a 2-of-3 identical
    answer is used (network, genesis, chain, attestor set, large-claim threshold, retained roots,
    claimed bitmap). It is never trusted to authorize: a root is a candidate only if it is ALSO a
    settlement in this host's own finalized replay with the same root and count. The RPC can at
    most make the agent skip work (liveness), never sign.
 3. Rebuild: for any unsigned candidate it rebuilds the whole L2 from the L1 blocks alone
    (`bloch-l2-produce-dev reconstruct --l1-follower --rules mainnet`), requires the rebuilt block
    hash, state root and withdrawal root/count to equal the finalized settlement, and derives every
    withdrawal leaf under the root (`withdrawal-proof`, each re-checked here in Python).
 4. Policy: the root is signed only if it covers at least one unclaimed withdrawal >= 100 BLCH.
    Guards: pause file, per-withdrawal maximum and a per-UTC-day cap on newly covered large
    withdrawals (above them the root is HELD until the operator lists the withdrawal in the
    approvals file), refusal and alert on any mismatch.
 5. Sign and publish: `l2-claim attest --sealed` (the key is opened inside bloch-pos only; the
    passphrase is a systemd credential), the partial is checked (signer index, digest over the
    pinned network/chain/root), written to the outbox `<state>/outbox/700770/<root>/attestor-I.partial`
    and pushed to every configured drop (HTTP PUT and/or a command such as rsync). The claimant's
    aggregate_attestation.py collects any 3 and verifies them natively.

Every event is one JSON line on stdout (journald). Exit 3 = pin/identity halt (no restart).
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import attestor_lib as lib  # noqa: E402

VERSION = 'bloch-l2-attestor-agent/1'
PINS = lib.MAINNET  # the command line always enforces the mainnet pins (tests construct Agent directly)
DEFAULTS = {
    'rpc_quorum': 2,
    'rpc_timeout_seconds': 15,
    'poll_seconds': 60,
    'max_status_age_seconds': 900,
    'daily_cap_sat': 1_000 * 100_000_000,       # newly covered large withdrawals per UTC day
    'max_single_sat': 1_000 * 100_000_000,      # one withdrawal above this needs an approval line
    'pause_file': '/etc/bloch-l2-attestor/PAUSE',
    'approvals_file': '/etc/bloch-l2-attestor/approvals.txt',
    'publish': [],
    'alert_command': None,
    'command_timeout_seconds': 3600,
}
# The follower binary pin (kit 2026-10-30). Not in REQUIRED: a config written by an older kit still loads,
# and check_identity halts (exit 3) with the migration instructions instead of a bare traceback.
FOLLOWER_PIN = ('follower', 'follower_sha256')
REQUIRED = ('signer_index', 'bloch_pos', 'bloch_pos_sha256', 'produce', 'produce_sha256', 'manifest',
            'attestors', 'sealed_key', 'follower_status', 'follower_native', 'state_dir', 'rpc_urls')


class Halt(Exception):
    """A pin or identity mismatch: the operator must look. Exit 3, no restart."""


class Skip(Exception):
    """Nothing can be decided this cycle (stale follower, no quorum): retry later."""


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def log(event, **fields):
    print(json.dumps({'time': now_utc().strftime('%Y-%m-%dT%H:%M:%SZ'), 'event': event, **fields},
                     sort_keys=True), flush=True)


class Agent:
    def __init__(self, config, pins=lib.MAINNET, dry_run=False):
        self.c = {**DEFAULTS, **config}
        missing = [k for k in REQUIRED if k not in self.c]
        if missing:
            raise Halt(f'config lacks {", ".join(missing)}')
        self.pins = pins
        self.dry_run = dry_run
        self.index = int(self.c['signer_index'])
        self.state_dir = Path(self.c['state_dir'])
        self.state_path = self.state_dir / 'state.json'
        self.outbox = self.state_dir / 'outbox'

    # ---------------------------------------------------------------- identity
    def check_identity(self, key='open'):
        """Pins of the binaries (bloch-pos, produce, and the follower that writes `follower_status`), the manifest
        and the set; the sealed key's header (`key` 'header') and that it opens and signs for this index ('open');
        'none' skips the key (dry run). Halts on any mismatch, and on a config without the follower pin."""
        missing = [k for k in FOLLOWER_PIN if not self.c.get(k)]
        if missing:
            raise Halt(f'config lacks {" and ".join(missing)}: the follower binary is not pinned. This agent refuses to '
                       'start until it is (an unpinned follower decides what the agent treats as finalized). Run '
                       '`install-attestor.sh upgrade --artifacts DIR`, which installs the published follower, checks '
                       'its SHA-256 and writes both keys. Never pin a hash taken from the installed file alone.')
        for name in ('bloch_pos', 'produce', 'follower'):
            try:
                digest = lib.sha256_file(self.c[name])
            except OSError as e:
                raise Halt(f'{name} cannot be read for its SHA-256 pin: {e}') from None
            if digest != self.c[f'{name}_sha256']:
                raise Halt(f'{name} differs from its pinned SHA-256')
        if lib.sha256_file(self.c['manifest']) != self.pins.manifest_sha256:
            raise Halt('the manifest is not the pinned Genesis-4 mainnet.manifest')
        threshold, keys = lib.read_set(self.c['attestors'])
        if lib.set_hash(threshold, keys) != self.pins.set_hash:
            raise Halt('the attestor set file is not the consensus-pinned set')
        if not 0 <= self.index < len(keys):
            raise Halt('signer_index is outside the set')
        self.threshold, self.keys = threshold, keys
        if key == 'none':
            return {'signer_index': self.index, 'set_hash': self.pins.set_hash, 'threshold': threshold, 'n': len(keys)}
        info = self.native('key-info', '--sealed', self.c['sealed_key'])
        fields = dict(line.split(' ', 1) for line in info.splitlines() if ' ' in line)
        if int(fields.get('signer_index', -1)) != self.index or fields.get('set_hash') != self.pins.set_hash:
            raise Halt('the sealed key is not this signer index of the pinned set')
        if key == 'open':
            self.native('key-check', '--sealed', self.c['sealed_key'], '--attestors', self.c['attestors'],
                        '--signer-index', str(self.index), '--passphrase-file', self.passphrase_file())
        return {'signer_index': self.index, 'set_hash': self.pins.set_hash, 'threshold': threshold, 'n': len(keys)}

    def passphrase_file(self):
        if self.c.get('passphrase_file'):
            return self.c['passphrase_file']
        directory = os.environ.get('CREDENTIALS_DIRECTORY')
        if not directory:
            raise Halt('no passphrase: run under systemd with LoadCredential=passphrase:… (or set passphrase_file)')
        return str(Path(directory) / self.c.get('passphrase_credential', 'passphrase'))

    def native(self, *args):
        done = subprocess.run([self.c['bloch_pos'], 'l2-claim', *args], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=600)
        if done.returncode:
            raise Halt(f'bloch-pos l2-claim {args[0]} refused: {done.stderr.strip()[-600:]}')
        return done.stdout

    # ---------------------------------------------------------------- state
    def load_state(self):
        if self.state_path.exists():
            return json.loads(self.state_path.read_text())
        return {'signed': {}, 'skipped': {}, 'held': {}, 'leaves': {}, 'approved': {}, 'published': {}, 'refused': {}}

    def save_state(self, state):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(state, sort_keys=True, indent=1) + '\n')
        os.replace(tmp, self.state_path)

    # ---------------------------------------------------------------- inputs
    def follower(self):
        try:
            status = json.loads(Path(self.c['follower_status']).read_text())
        except (OSError, ValueError) as e:
            raise Skip(f'follower status unreadable: {e}') from None
        if status.get('network') != self.pins.network or status.get('chain_id') != self.pins.chain_id:
            raise Halt('the follower verifies another network or chain')
        age = time.time() - float(status.get('written_at_unix', 0))
        if age > self.c['max_status_age_seconds']:
            raise Skip(f'follower status is {int(age)} s old (stalled follower)')
        genesis = status.get('l2_genesis') or {}
        if genesis.get('hash') != self.pins.l2_genesis_hash or genesis.get('finalized') is not True:
            raise Skip('the L2 genesis is not finalized on the own replay yet')
        return status

    def rpc(self, url, method, params=()):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
        request = urllib.request.Request(url, data=body, headers={'content-type': 'application/json'})
        with urllib.request.urlopen(request, timeout=self.c['rpc_timeout_seconds']) as response:
            reply = json.loads(response.read(8_000_000))
        if 'result' not in reply:
            raise ValueError(f'{method}: {reply.get("error")}')
        return reply['result']

    def view(self):
        """The 2-of-3 (rpc_quorum) identical projection of getl2settlement, or Skip."""
        answers, errors = {}, []
        for url in self.c['rpc_urls']:
            try:
                r = self.rpc(url, 'getl2settlement')
                w = r['withdrawals']
                projection = {
                    'network': r['network'], 'genesis': r['genesis'], 'chain_id': r['chain_id'],
                    'attestor_set': w.get('attestor_set'), 'large_claim_sat': int(w['large_claim_sat']),
                    'roots': [{k: e[k] for k in ('l2_number', 'root', 'count', 'height')} for e in w['roots']],
                    'claimed': w['claimed'],
                }
            except Exception as e:  # noqa: BLE001 - any endpoint failure is just a missing vote
                errors.append(f'{url}: {e}')
                continue
            answers.setdefault(lib.canonical(projection), []).append(url)
        best = max(answers.items(), key=lambda kv: len(kv[1]), default=(None, []))
        if len(best[1]) < self.c['rpc_quorum']:
            raise Skip(f'no RPC quorum ({len(best[1])}/{len(self.c["rpc_urls"])}); errors: {errors[:3]}')
        if len(answers) > 1:
            log('rpc-endpoint-diverged', minority=[u for k, us in answers.items() if k != best[0] for u in us])
        view = json.loads(best[0])
        if (view['network'], view['genesis'], view['chain_id']) != (self.pins.network, self.pins.genesis, self.pins.chain_id):
            raise Halt('the RPC quorum follows another network')
        if view['attestor_set'] != self.pins.set_hash:
            raise Halt('the live L2 policy names another attestor set')
        if view['large_claim_sat'] != self.pins.large_claim_sat:
            raise Halt('the live large-claim threshold differs from the pin')
        return view

    def approvals(self):
        """`INDEX LEAF_HEX` lines the operator added to sign past the caps (leaf must match)."""
        path = Path(self.c['approvals_file'])
        found = {}
        if path.exists():
            for line in path.read_text().splitlines():
                parts = line.split('#', 1)[0].split()
                if len(parts) == 2:
                    found[int(parts[0])] = parts[1].lower()
        return found

    # ---------------------------------------------------------------- rebuild
    def produce(self, *args, timeout=None):
        done = subprocess.run([self.c['produce'], *args, *self.pins.network_args], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=timeout or self.c['command_timeout_seconds'])
        return done

    def rebuild(self, work):
        """Rebuild the L2 from the follower's L1 blocks into `work/l2`; the reconstruct report."""
        target = work / 'l2'
        for _ in range(3):  # the follower may be appending to its index
            done = self.produce('reconstruct', '--target', str(target), '--l1-follower', self.c['follower_native'],
                                '--timestamp-rule', self.pins.timestamp_rule)
            if done.returncode == 0:
                report = json.loads(done.stdout)
                if report.get('genesis') != self.pins.l2_genesis_hash:
                    raise Halt('the rebuilt L2 genesis differs from the pin')
                return target, report
            shutil.rmtree(target, ignore_errors=True)
            time.sleep(2)
        raise Halt(f'reconstruct from L1 data failed: {done.stderr.strip()[-800:]}')

    def own_proof(self, target, index, number, root, count):
        done = self.produce('withdrawal-proof', '--target', str(target), '--index', str(index), '--number', str(number),
                            '--root', root, '--count', str(count))
        if done.returncode:
            raise Halt(f'withdrawal-proof {index} against block {number} refused: {done.stderr.strip()[-600:]}')
        doc = json.loads(done.stdout)
        fields = lib.check_proof(doc, self.pins.chain_id)
        if (fields['root'], fields['count'], fields['index']) != (root, count, index):
            raise Halt(f'withdrawal-proof {index} answered for another root/count/index')
        return doc, fields

    def rebuild_check(self):
        """Rebuild the L2 from L1 now and require every finalized settlement of the own replay to match.
        Run at start and once a day, so a broken rebuild (sandbox, disk, binary) shows before a claim needs it."""
        status = self.follower()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix='rebuild-check-', dir=self.state_dir))
        try:
            _, report = self.rebuild(work)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        rebuilt = {b['number']: b for b in report['blocks']}
        for s in status.get('finalized_settlements', []):
            b = rebuilt.get(s['l2_number'])
            if b is None or (b['hash'], b['state_root']) != (s['l2_hash'], s['l2_state_root']) or \
                    (s.get('withdrawals') and s['withdrawals'] != {'root': b['withdrawal_root'], 'count': b['withdrawal_count']}):
                raise Halt(f'rebuild check: L2 block {s["l2_number"]} rebuilt from L1 differs from the finalized settlement')
        self.last_rebuild_check = time.time()
        log('rebuild-check-ok', native_blocks=report.get('native_blocks'), l2_blocks=report.get('settled'),
            finalized_settlements=len(status.get('finalized_settlements', [])))
        return report

    # ---------------------------------------------------------------- cycle
    def cycle(self):
        if Path(self.c['pause_file']).exists():
            log('paused', pause_file=self.c['pause_file'])
            return 'paused'
        status = self.follower()
        view = self.view()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        state = self.load_state()
        finals = {s['l2_number']: s for s in status.get('finalized_settlements', []) if s.get('withdrawals')}
        todo = []
        for record in view['roots']:
            root, number, count = record['root'], record['l2_number'], record['count']
            if root in state['signed'] or root in state['skipped']:
                continue
            own = finals.get(number)
            if own is None:
                log('awaiting-own-finality', l2_number=number, root=root)
                continue
            if own['withdrawals'] != {'root': root, 'count': count}:
                self.alert_once(state, root, 'refused-root-not-on-own-chain', l2_number=number, root=root,
                                rpc_count=count, own=own['withdrawals'])
                continue
            todo.append((number, root, count, own))
        if todo:
            work = Path(tempfile.mkdtemp(prefix='rebuild-', dir=self.state_dir))
            try:
                target, report = self.rebuild(work)
                rebuilt = {b['number']: b for b in report['blocks']}
                for number, root, count, own in sorted(todo):
                    self.decide(state, view, target, rebuilt.get(number), number, root, count, own)
                    self.save_state(state)
                log('rebuilt', native_blocks=report.get('native_blocks'), l2_blocks=report.get('settled'))
            finally:
                shutil.rmtree(work, ignore_errors=True)
        self.publish_pending(state)
        self.save_state(state)
        return 'ok'

    def decide(self, state, view, target, block, number, root, count, own):
        if block is None or (block['hash'], block['state_root'], block['withdrawal_root'], block['withdrawal_count']) != \
                (own['l2_hash'], own['l2_state_root'], root, count):
            self.alert_once(state, root, 'refused-rebuild-differs', l2_number=number, root=root,
                            rebuilt=block and {k: block.get(k) for k in ('hash', 'state_root', 'withdrawal_root',
                                                                         'withdrawal_count')},
                            finalized={'hash': own['l2_hash'], 'state_root': own['l2_state_root']})
            return
        leaves, docs = state['leaves'], {}
        for i in range(count):
            if str(i) not in leaves:
                doc, fields = self.own_proof(target, i, number, root, count)
                docs[i] = doc
                leaves[str(i)] = {k: fields[k] for k in ('sats', 'l1_recipient', 'leaf', 'l2_block')}
        large = [i for i in range(count) if leaves[str(i)]['sats'] >= self.pins.large_claim_sat]
        unclaimed = [i for i in large if not lib.claimed(view['claimed'], i)]
        if not unclaimed:
            state['skipped'][root] = {'l2_number': number, 'reason': 'no unclaimed withdrawal >= large_claim_sat'}
            log('root-skipped', l2_number=number, root=root, large=len(large))
            return
        approvals, today = self.approvals(), now_utc().strftime('%Y-%m-%d')
        new = [i for i in unclaimed if str(i) not in state['approved']]
        approved_by_operator = [i for i in new if approvals.get(i) == leaves[str(i)]['leaf']]
        capped = [i for i in new if i not in approved_by_operator]
        too_big = [i for i in capped if leaves[str(i)]['sats'] > self.c['max_single_sat']]
        spent = sum(a['sats'] for a in state['approved'].values() if a['day'] == today and not a['operator'])
        amount = sum(leaves[str(i)]['sats'] for i in capped)
        if too_big or spent + amount > self.c['daily_cap_sat']:
            if root not in state['held']:
                state['held'][root] = now_utc().isoformat()
                self.alert('held', l2_number=number, root=root, over_single=too_big, day_spent_sat=spent,
                           new_sat=amount, cap_sat=self.c['daily_cap_sat'],
                           approve_with=[f'{i} {leaves[str(i)]["leaf"]}' for i in capped])
            return
        if self.dry_run:
            log('would-sign', l2_number=number, root=root, unclaimed_large=unclaimed)
            return
        index = unclaimed[0]
        doc = docs.get(index) or self.own_proof(target, index, number, root, count)[0]
        partial = self.sign(doc, root)
        for i in new:
            state['approved'][str(i)] = {'day': today, 'sats': leaves[str(i)]['sats'], 'root': root,
                                         'operator': i in approved_by_operator}
        state['held'].pop(root, None)
        state['signed'][root] = {'l2_number': number, 'count': count, 'signed_at': now_utc().isoformat(),
                                 'covers_large': unclaimed, 'partial': str(partial)}
        self.alert('signed', l2_number=number, root=root, count=count, covers_large=unclaimed,
                   sats=[leaves[str(i)]['sats'] for i in unclaimed], partial=str(partial))

    def sign(self, doc, root):
        """`l2-claim attest --sealed` over this agent's own proof; the checked partial in the outbox."""
        relpath = lib.partial_relpath(self.pins.chain_id, root, self.index)
        final = self.outbox / relpath
        final.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self.state_dir) as scratch:
            proof = Path(scratch) / 'proof.json'
            proof.write_text(json.dumps(doc) + '\n')
            out = Path(scratch) / 'partial'
            self.native('attest', '--genesis', self.c['manifest'], '--proof', str(proof),
                        '--attestors', self.c['attestors'], '--signer-index', str(self.index),
                        '--sealed', self.c['sealed_key'], '--passphrase-file', self.passphrase_file(), '--out', str(out))
            text = out.read_text()
            index, digest, _ = lib.parse_partial(text)
            if index != self.index or digest != lib.attestation_digest(self.pins.network, self.pins.chain_id, root):
                raise Halt('the partial signs another index, network, chain or root')
            tmp = final.with_suffix('.tmp')
            tmp.write_text(text)
            os.replace(tmp, final)
        meta = {'agent': VERSION, 'chain_id': self.pins.chain_id, 'root': root, 'signer_index': self.index,
                'set_hash': self.pins.set_hash, 'digest': digest, 'signed_at': now_utc().isoformat()}
        final.with_suffix('.json').write_text(json.dumps(meta, sort_keys=True) + '\n')
        return final

    # ---------------------------------------------------------------- publish / alert
    def publish_pending(self, state):
        targets = self.c['publish']
        for root, entry in state['signed'].items():
            done = state['published'].setdefault(root, [])
            for n, target in enumerate(targets):
                tid = f'{n}:{target.get("kind")}'
                if tid in done:
                    continue
                try:
                    self.publish(target, Path(entry['partial']), root)
                except Exception as e:  # noqa: BLE001 - retried next cycle
                    log('publish-failed', root=root, target=tid, error=str(e)[:300])
                    continue
                done.append(tid)
                log('published', root=root, target=tid)

    def publish(self, target, partial, root):
        relpath = lib.partial_relpath(self.pins.chain_id, root, self.index)
        meta = partial.with_suffix('.json')
        if target['kind'] == 'http_put':
            headers = {'content-type': 'text/plain'}
            token = target.get('token_credential')
            if token:
                directory = os.environ.get('CREDENTIALS_DIRECTORY', '')
                headers['authorization'] = 'Bearer ' + (Path(directory) / token).read_text().strip()
            for path, name in ((partial, relpath), (meta, relpath[:-len('.partial')] + '.json')):
                url = target['url'].rstrip('/') + '/' + name
                request = urllib.request.Request(url, data=path.read_bytes(), method='PUT', headers=headers)
                with urllib.request.urlopen(request, timeout=30) as response:
                    if response.status >= 300:
                        raise OSError(f'HTTP {response.status}')
        elif target['kind'] == 'command':
            fill = {'file': str(partial), 'json': str(meta), 'relpath': relpath, 'root': root,
                    'chain': str(self.pins.chain_id), 'index': str(self.index), 'outbox': str(self.outbox)}
            argv = [part.format(**fill) for part in target['argv']]
            done = subprocess.run(argv, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
            if done.returncode:
                raise OSError(f'exit {done.returncode}: {done.stderr.strip()[-300:]}')
        else:
            raise ValueError(f'unknown publish kind {target.get("kind")}')

    def alert_once(self, state, key, event, **fields):
        """A refusal is re-evaluated every cycle but alerted once per root (`key`) and reason."""
        refused = state.setdefault('refused', {})
        if refused.get(key) != event:
            refused[key] = event
            self.alert(event, **fields)
        else:
            log(event, l2_number=fields.get('l2_number'), root=key, repeated=True)

    def alert(self, event, **fields):
        log(event, alert=True, signer_index=self.index, **fields)
        argv = self.c.get('alert_command')
        if argv:
            text = json.dumps({'event': event, **fields}, sort_keys=True, default=str)
            try:
                subprocess.run([a.format(event=event) for a in argv], input=text, text=True, timeout=60,
                               capture_output=True)
            except Exception as e:  # noqa: BLE001 - an alert failure never stops the agent
                log('alert-failed', error=str(e)[:200])


def load_config(path):
    return json.loads(Path(path).read_text())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('command', choices=('run', 'once', 'check'))
    parser.add_argument('--config', required=True)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--no-key', action='store_true', help='check: skip opening the sealed key')
    a = parser.parse_args(argv)
    try:
        agent = Agent(load_config(a.config), pins=PINS, dry_run=a.dry_run)
    except Halt as e:
        log('halt', alert=True, reason=str(e))
        return 3
    try:
        if a.command == 'check':
            identity = agent.check_identity(key='header' if a.no_key else 'open')
            status = agent.follower()
            view = agent.view()
            report = agent.rebuild_check()
            log('check-ok', **identity, follower_verified_slot=status.get('verified_slot'),
                finalized_settlements=len(status.get('finalized_settlements', [])), retained_roots=len(view['roots']),
                rebuilt_l2_blocks=report.get('settled'))
            return 0
        agent.check_identity(key='none' if a.dry_run else 'open')
        log('started', agent=VERSION, signer_index=agent.index, dry_run=a.dry_run, set_hash=agent.pins.set_hash)
        agent.last_rebuild_check = 0
        while True:
            try:
                if time.time() - agent.last_rebuild_check > 86_400:
                    agent.rebuild_check()
                agent.cycle()
            except Skip as e:
                log('waiting', reason=str(e))
            if a.command == 'once':
                return 0
            time.sleep(agent.c['poll_seconds'])
    except Skip as e:
        log('check-not-ready', reason=str(e))
        return 1
    except Halt as e:
        agent.alert('halt', reason=str(e))
        return 3


if __name__ == '__main__':
    sys.exit(main())
