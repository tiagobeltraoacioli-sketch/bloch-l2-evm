#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Unit tests of bloch-l2-withdraw.py against scripted L1 and L2 RPC servers on loopback. A lying RPC is the point."""
import contextlib
import copy
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

HERE = Path(__file__).resolve()
SPEC = importlib.util.spec_from_file_location('withdraw', HERE.parent.parent / 'bloch-l2-withdraw.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
VECTORS = HERE.parents[4] / 'tests/fixtures/l2-withdrawal-v1/vectors.json'

CHAIN = tool.MAINNET_CHAIN_ID
ME = bytes([0x11] * 32)
ZERO = [bytes(32)]
for _ in range(32):
    ZERO.append(tool.node(ZERO[-1], ZERO[-1]))


def tree_root(leaves):
    level = list(leaves)
    for h in range(32):
        level = [tool.node(level[i], level[i + 1] if i + 1 < len(level) else ZERO[h]) for i in range(0, len(level), 2)] or [ZERO[h + 1]]
    return level[0]


def tree_proof(leaves, index):
    level, siblings = list(leaves), []
    for h in range(32):
        sibling = index ^ 1
        siblings.append(level[sibling] if sibling < len(level) else ZERO[h])
        level = [tool.node(level[i], level[i + 1] if i + 1 < len(level) else ZERO[h]) for i in range(0, len(level), 2)]
        index >>= 1
    return siblings


def field(i):
    return (ME if i % 2 == 0 else bytes([0x22] * 32)), 1_000_000 + i


def leaves(count):
    return [tool.leaf_hash(CHAIN, i, field(i)[0], field(i)[1]) for i in range(count)]


def proof_doc(index, count, number):
    recipient, sats = field(index)
    all_leaves = leaves(count)
    return {'chain_id': CHAIN, 'number': number, 'withdrawal_root': tree_root(all_leaves).hex(), 'withdrawal_count': count,
            'index': index,
            'withdrawal': {'nonce': index, 'l1_recipient': recipient.hex(), 'sats': sats, 'sender': 'aa' * 20,
                           'l2_block': number, 'leaf': all_leaves[index].hex()},
            'siblings': [s.hex() for s in tree_proof(all_leaves, index)], 'finalized': True, 'native_slot': 9, 'native_block': 'bb'}


def record(count, number, finalized=True):
    return {'l2_number': number, 'root': tree_root(leaves(count)).hex(), 'count': count, 'height': 100 + number, 'finalized': finalized}


def l1_answer(roots, claimable, large=None):
    return {'network': tool.MAINNET_NETWORK, 'genesis': tool.MAINNET_GENESIS, 'chain_id': CHAIN, 'withdrawals': {
        'roots': roots, 'claimable': claimable, 'claimable_large': large, 'large_claim_sat': '10000000000',
        'attested_claim_sat': '10000000000', 'attestor_set': 'ab' * 32,
        'finalized_checkpoint': {'epoch': 1, 'root': 'cd' * 32, 'own_root': None, 'own_chain_rule_active': False},
        'claimed': {'count': 0, 'floor': 0, 'words': []},
        'release_window': {'remaining_sat': '1000000000'}}}


class Scripted(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['content-length'])))
        out = self.server.script(request['method'], request['params'])
        self.server.calls.append((request['method'], request['params']))
        if isinstance(out, bytes):
            body = out
        elif isinstance(out, Fail):
            body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'error': {'code': out.code, 'message': 'scripted'}}).encode()
        else:
            body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': out}).encode()
        self.send_response(200)
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Fail:
    def __init__(self, code):
        self.code = code


def serve(script):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Scripted)
    server.script, server.calls = script, []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f'http://127.0.0.1:{server.server_port}'


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.out = os.path.join(self.dir.name, 'proof.json')
        self.servers = []
        self.addCleanup(lambda: [s.shutdown() for s in self.servers])
        self.doc = proof_doc(0, 3, 2)
        self.l1 = l1_answer([record(3, 2)], record(3, 2))

    def url(self, script):
        server, url = serve(script)
        self.servers.append(server)
        return url

    def l2(self, doc=None):
        return self.url(lambda method, params: doc if doc is not None else self.doc)

    def l1url(self, answer=None):
        return self.url(lambda method, params: answer if answer is not None else self.l1)

    def fetch(self, l2=None, l1=None, index=0, extra=()):
        l1s = l1 if isinstance(l1, list) else [l1 or self.l1url()]
        argv = ['fetch', '--l2-rpc', l2 or self.l2(), '--index', str(index), '--recipient', ME.hex(), '--out', self.out, *extra]
        for url in l1s:
            argv += ['--l1-rpc', url]
        return tool.main(argv)

    def refused(self, doc, **kw):
        self.assertEqual(self.fetch(self.l2(doc), **kw), tool.REFUSED)
        self.assertFalse(os.path.exists(self.out), 'no file is written from a refused proof')


class Hashing(unittest.TestCase):
    def test_keccak_known_answers(self):
        self.assertEqual(tool.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(tool.keccak256(b'WithdrawalInitiated(uint256,bytes32,address,uint256)').hex(), tool.WITHDRAWAL_TOPIC)
        self.assertEqual(tool.keccak256(b'initiateWithdrawal(bytes32)')[:4].hex(), tool.INITIATE_SELECTOR)

    def test_the_shared_native_vectors(self):
        vectors = json.loads(VECTORS.read_text())
        self.assertEqual(ZERO[32].hex(), vectors['empty_root'][2:])
        for v in vectors['leaves']:
            own = tool.leaf_hash(v['chain_id'], v['nonce'], bytes.fromhex(v['l1_recipient'][2:]), v['sats'])
            self.assertEqual(own.hex(), v['leaf'][2:])
        checked = 0
        for tree in vectors['trees']:
            for p in tree.get('proofs', []):
                siblings = [bytes.fromhex(s[2:]) for s in p['siblings']]
                i = p['index']
                leaf = tool.leaf_hash(vectors['chain_id'], i, bytes([i % 255 + 1] * 32), 1_000_000 + i)
                self.assertEqual(tool.root_from_proof(leaf, p['index'], siblings).hex(), tree['root'][2:])
                checked += 1
        self.assertGreater(checked, 0)


class Accepts(Base):
    def test_a_good_proof_is_written_clean(self):
        self.assertEqual(self.fetch(), tool.OK)
        written = json.loads(Path(self.out).read_text())
        self.assertEqual(written['withdrawal_root'], self.doc['withdrawal_root'])
        self.assertNotIn('finalized', written)
        self.assertNotIn('native_slot', written)
        self.assertEqual(tool.main(['verify', '--proof', self.out]), tool.OK)
        self.assertEqual(tool.main(['verify', '--proof', self.out, '--l1-rpc', self.l1url()]), tool.OK)

    def test_it_asks_for_the_matured_root_not_the_newest(self):
        newest, matured = proof_doc(0, 5, 3), proof_doc(0, 3, 2)
        answers = {None: newest, matured['withdrawal_root']: matured}
        l2 = self.url(lambda m, p: answers[p[1] if len(p) > 1 else None])
        self.l1 = l1_answer([record(3, 2), record(5, 3)], record(3, 2))
        self.assertEqual(self.fetch(l2), tool.OK)
        self.assertEqual(json.loads(Path(self.out).read_text())['withdrawal_count'], 3)

    def test_a_large_withdrawal_uses_the_large_delay_root(self):
        self.l1['withdrawals']['large_claim_sat'] = '1000000'
        self.l1['withdrawals']['claimable_large'] = None
        self.assertEqual(self.fetch(), tool.NOT_READY)
        self.l1['withdrawals']['claimable_large'] = record(3, 2)
        self.assertEqual(self.fetch(), tool.OK)

    def test_any_recipient_is_for_relayers_only(self):
        l2, l1 = self.l2(proof_doc(1, 3, 2)), self.l1url()
        common = ['fetch', '--l2-rpc', l2, '--l1-rpc', l1, '--index', '1', '--out', self.out]
        self.assertEqual(tool.main(common), tool.REFUSED)
        self.assertEqual(tool.main(common + ['--any-recipient']), tool.OK)

    def test_an_existing_file_is_kept(self):
        Path(self.out).write_text('mine')
        self.assertEqual(self.fetch(), tool.REFUSED)
        self.assertEqual(Path(self.out).read_text(), 'mine')


class TamperedProof(Base):
    def tampered(self, change):
        doc = copy.deepcopy(self.doc)
        change(doc)
        return doc

    def test_each_tampered_field_is_refused(self):
        def flip(text):
            return ('0' if text[0] != '0' else '1') + text[1:]

        cases = {
            'sibling': lambda d: d['siblings'].__setitem__(0, flip(d['siblings'][0])),
            'deep sibling': lambda d: d['siblings'].__setitem__(31, flip(d['siblings'][31])),
            'swapped siblings': lambda d: d['siblings'].__setitem__(0, d['siblings'][1]),
            'missing sibling': lambda d: d['siblings'].pop(),
            'extra sibling': lambda d: d['siblings'].append('00' * 32),
            'short sibling': lambda d: d['siblings'].__setitem__(0, 'ab'),
            'root': lambda d: d.__setitem__('withdrawal_root', flip(d['withdrawal_root'])),
            'leaf': lambda d: d['withdrawal'].__setitem__('leaf', flip(d['withdrawal']['leaf'])),
            'sats': lambda d: d['withdrawal'].__setitem__('sats', d['withdrawal']['sats'] + 1),
            'sats as a string': lambda d: d['withdrawal'].__setitem__('sats', str(d['withdrawal']['sats'])),
            'sats as a bool': lambda d: d['withdrawal'].__setitem__('sats', True),
            'recipient': lambda d: d['withdrawal'].__setitem__('l1_recipient', '33' * 32),
            'nonce': lambda d: d['withdrawal'].__setitem__('nonce', 1),
            'index': lambda d: d.__setitem__('index', 1),
            'chain': lambda d: d.__setitem__('chain_id', 700771),
            'count below index': lambda d: d.__setitem__('withdrawal_count', 0),
            'no withdrawal': lambda d: d.pop('withdrawal'),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.refused(self.tampered(change))

    def test_a_consistent_forgery_needs_an_l1_root(self):
        """Fully self-consistent fake tree paying the attacker: only the L1 anchor catches it."""
        fake_leaf = tool.leaf_hash(CHAIN, 0, ME, 9_000_000_000)
        doc = {'chain_id': CHAIN, 'number': 2, 'withdrawal_root': tree_root([fake_leaf]).hex(), 'withdrawal_count': 1, 'index': 0,
               'withdrawal': {'nonce': 0, 'l1_recipient': ME.hex(), 'sats': 9_000_000_000, 'sender': 'aa' * 20, 'l2_block': 2, 'leaf': fake_leaf.hex()},
               'siblings': [s.hex() for s in tree_proof([fake_leaf], 0)]}
        self.assertEqual(self.fetch(self.url(lambda m, p: doc)), tool.REFUSED)
        self.assertFalse(os.path.exists(self.out))
        path = os.path.join(self.dir.name, 'forged.json')
        Path(path).write_text(json.dumps(doc))
        self.assertEqual(tool.main(['verify', '--proof', path]), tool.OK, 'internally consistent')
        self.assertEqual(tool.main(['verify', '--proof', path, '--l1-rpc', self.l1url()]), tool.REFUSED)

    def test_another_withdrawal_at_another_index_is_refused(self):
        self.refused(proof_doc(2, 3, 2))

    def test_someone_elses_withdrawal_is_refused(self):
        self.assertEqual(self.fetch(self.l2(proof_doc(1, 3, 2)), index=1), tool.REFUSED)

    def test_an_expected_amount_is_enforced(self):
        self.assertEqual(self.fetch(extra=['--sats', '5']), tool.REFUSED)
        self.assertEqual(self.fetch(extra=['--sats', str(field(0)[1])]), tool.OK)

    def test_a_wrong_root_answer_is_refused(self):
        newest = proof_doc(0, 5, 3)
        self.l1 = l1_answer([record(3, 2), record(5, 3)], record(3, 2))
        self.assertEqual(self.fetch(self.url(lambda m, p: newest)), tool.REFUSED)

    def test_an_amount_that_changes_between_answers_is_refused(self):
        """A fake small first answer must not select the short delay for a large withdrawal."""
        fake_leaf = tool.leaf_hash(CHAIN, 0, ME, 1_000_000)
        fake = {'chain_id': CHAIN, 'number': 9, 'withdrawal_root': tree_root([fake_leaf]).hex(), 'withdrawal_count': 1, 'index': 0,
                'withdrawal': {'nonce': 0, 'l1_recipient': ME.hex(), 'sats': 1_000_000, 'sender': 'aa' * 20, 'l2_block': 9, 'leaf': fake_leaf.hex()},
                'siblings': [s.hex() for s in tree_proof([fake_leaf], 0)]}
        real = copy.deepcopy(self.doc)
        real_leaf = tool.leaf_hash(CHAIN, 0, ME, 20_000_000_000)
        real.update(withdrawal_root=tree_root([real_leaf]).hex(), withdrawal_count=1, siblings=[s.hex() for s in tree_proof([real_leaf], 0)])
        real['withdrawal'].update(sats=20_000_000_000, leaf=real_leaf.hex())
        rec = {'l2_number': 2, 'root': real['withdrawal_root'], 'count': 1, 'height': 5, 'finalized': True}
        self.l1 = l1_answer([rec], rec)
        l2 = self.url(lambda m, p: real if len(p) > 1 else fake)
        self.assertEqual(self.fetch(l2), tool.REFUSED)
        self.assertFalse(os.path.exists(self.out))

    def test_garbage_answers_are_refused(self):
        self.assertEqual(self.fetch(self.url(lambda m, p: b'not json' if m.startswith('bloch') else self.l1)), tool.NOT_READY)
        for answer in (b'[1]', b'{"result":{"a":1,"a":2}}', b'{"result":null}'):
            with self.subTest(answer):
                self.assertEqual(self.fetch(self.url(lambda m, p: answer if m.startswith('bloch') else self.l1)), tool.REFUSED)


class Anchor(Base):
    def test_a_root_not_on_l1_is_refused(self):
        self.l1 = l1_answer([record(9, 7)], record(3, 2))
        self.assertEqual(self.fetch(), tool.REFUSED)

    def test_a_wrong_count_or_l2_block_on_l1_is_refused(self):
        for change in ({'count': 2}, {'l2_number': 3}):
            with self.subTest(change):
                bad = {**record(3, 2), **change}
                self.l1 = l1_answer([bad], record(3, 2))
                self.assertEqual(self.fetch(), tool.REFUSED)

    def test_unfinalized_on_l1_is_not_ready(self):
        self.l1 = l1_answer([record(3, 2, finalized=False)], record(3, 2))
        self.assertEqual(self.fetch(), tool.NOT_READY)
        self.assertFalse(os.path.exists(self.out))

    def test_no_claimable_root_or_one_older_than_the_withdrawal_is_not_ready(self):
        self.l1 = l1_answer([], None)
        self.assertEqual(self.fetch(), tool.NOT_READY)
        self.l1 = l1_answer([record(1, 1), record(3, 2)], record(1, 1))
        self.assertEqual(self.fetch(self.l2(proof_doc(2, 3, 2)), index=2, extra=[]), tool.NOT_READY)

    def test_every_l1_must_agree(self):
        good, other = self.l1url(), self.l1url(l1_answer([record(9, 7)], record(9, 7)))
        self.assertEqual(self.fetch(l1=[good, other]), tool.REFUSED)
        self.assertEqual(self.fetch(l1=[good, good]), tool.OK)

    def test_another_network_is_refused(self):
        for key in ('network', 'genesis', 'chain_id'):
            with self.subTest(key):
                answer = copy.deepcopy(self.l1)
                answer[key] = 'other'
                self.assertEqual(self.fetch(l1=self.l1url(answer)), tool.REFUSED)

    def test_a_finality_that_is_not_the_chains_own_is_not_ready(self):
        self.l1['withdrawals']['finalized_checkpoint']['own_root'] = 'ee' * 32
        self.assertEqual(self.fetch(), tool.NOT_READY)

    def test_already_claimed(self):
        self.l1['withdrawals']['claimed'] = {'count': 1, 'floor': 0, 'words': [{'word': 0, 'bits': '01' + '00' * 31}]}
        self.assertEqual(self.fetch(), tool.CLAIMED)
        self.l1['withdrawals']['claimed'] = {'count': 256, 'floor': 1, 'words': []}
        self.assertEqual(self.fetch(), tool.CLAIMED)
        self.l1['withdrawals']['claimed'] = {'count': 1, 'floor': 0, 'words': [{'word': 0, 'bits': '02' + '00' * 31}]}
        self.assertEqual(self.fetch(), tool.OK)


class Status(Base):
    def setUp(self):
        super().setUp()
        self.doc = proof_doc(0, 2, 5)
        self.path = os.path.join(tempfile.mkdtemp(), 'proof.json')
        with open(self.path, 'w') as file:
            json.dump({k: v for k, v in self.doc.items() if k not in ('finalized', 'native_slot', 'native_block')}, file)

    def ask(self, claimed, states=(), sent=None, height=1000):
        rec = record(2, 5)
        answer = l1_answer([rec], rec)
        if claimed:
            answer['withdrawals']['claimed'] = {'count': 1, 'floor': 0, 'words': [{'word': 0, 'bits': '01' + '00' * 31}]}
        utxos = [{'txid': f'{i:064x}', 'vout': 0, 'value_sat': str(self.doc['withdrawal']['sats'])} for i in range(len(states))]

        def script(method, params):
            if method == 'getl2settlement':
                return answer
            if method == 'getutxos':
                return {'utxos': utxos, 'truncated': False}
            if method == 'getchaininfo':
                return {'height': height}
            return {'status': states[int(params[0], 16)]}
        args = ['status', '--proof', self.path, '--l1-rpc', self.url(script)]
        return tool.main(args + (['--sent-height', str(sent)] if sent is not None else []))

    def test_only_a_finalized_output_is_final(self):
        self.assertEqual(self.ask(True, ['finalized']), tool.OK)
        for state in ('included', 'justified'):
            self.assertEqual(self.ask(True, [state]), tool.NOT_READY)

    def test_an_equal_output_not_final_holds_the_answer(self):
        self.assertEqual(self.ask(True, ['finalized', 'included']), tool.NOT_READY)

    def test_accepted_then_dropped_is_not_success(self):
        self.assertEqual(self.ask(False), tool.NOT_READY)
        self.assertEqual(self.ask(False, sent=990), tool.NOT_READY)
        self.assertEqual(self.ask(False, sent=900), tool.DROPPED)

    def ask_tx(self, claimed, state):
        rec = record(2, 5)
        answer = l1_answer([rec], rec)
        if claimed:
            answer['withdrawals']['claimed'] = {'count': 1, 'floor': 0, 'words': [{'word': 0, 'bits': '01' + '00' * 31}]}

        def script(method, params):
            return answer if method == 'getl2settlement' else {'status': state} if method == 'gettxstatus' else {'utxos': []}
        return tool.main(['status', '--proof', self.path, '--l1-rpc', self.url(script), '--tx', 'ab' * 32])

    def test_following_a_txid(self):
        self.assertEqual(self.ask_tx(True, 'finalized'), tool.OK)
        self.assertEqual(self.ask_tx(True, 'justified'), tool.NOT_READY)
        self.assertEqual(self.ask_tx(False, 'pending'), tool.NOT_READY)
        self.assertEqual(self.ask_tx(False, 'unknown'), tool.DROPPED)
        self.assertEqual(self.ask_tx(False, 'finalized'), tool.REFUSED)
        self.assertEqual(self.ask_tx(True, 'unknown'), tool.CLAIMED)
        self.assertEqual(self.ask_tx(True, 'paid'), tool.REFUSED)

    def test_claimed_with_no_followable_output(self):
        self.assertEqual(self.ask(True), tool.CLAIMED)
        self.assertEqual(self.ask(True, ['unknown']), tool.CLAIMED)

    def test_verify_says_claimed_after_the_root_left_the_list(self):
        answer = l1_answer([], None)
        answer['withdrawals']['claimed'] = {'count': 1, 'floor': 0, 'words': [{'word': 0, 'bits': '01' + '00' * 31}]}
        url = self.url(lambda m, p: answer)
        self.assertEqual(tool.main(['verify', '--proof', self.path, '--l1-rpc', url]), tool.CLAIMED)


class RpcErrors(Base):
    def test_retryable_errors_are_not_ready_and_others_refused(self):
        for code in (-32001, -32041, -32042, -32043, -32045, -32046):
            with self.subTest(code):
                self.assertEqual(self.fetch(self.url(lambda m, p: Fail(code))), tool.NOT_READY)
        for code in (-32044, -32601, -32602):
            with self.subTest(code):
                self.assertEqual(self.fetch(self.url(lambda m, p: Fail(code))), tool.REFUSED)

    def test_a_v21_rpc_without_the_method_refuses_at_once_and_says_why(self):
        calls = []

        def l2(method, params):
            calls.append(method)
            return Fail(-32601)

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.fetch(self.url(l2), extra=['--wait', '600']), tool.REFUSED)
        self.assertEqual(calls, ['bloch_getWithdrawalProof'])
        self.assertIn('v2.1', err.getvalue())

    def test_an_unreachable_rpc_is_not_ready(self):
        self.assertEqual(self.fetch('http://127.0.0.1:9'), tool.NOT_READY)

    def test_wait_ends_when_the_withdrawal_finalizes(self):
        calls = []

        def l2(method, params):
            calls.append(1)
            return Fail(-32041) if len(calls) < 2 else self.doc

        tool.POLL_SECONDS = 0.05
        self.assertEqual(self.fetch(self.url(l2), extra=['--wait', '20']), tool.OK)
        self.assertGreaterEqual(len(calls), 2)


class Burn(Base):
    def test_the_call_it_prints(self):
        self.assertEqual(tool.main(['burn', '--recipient', ME.hex(), '--sats', '1000000']), tool.OK)
        self.assertEqual(tool.main(['burn', '--recipient', ME.hex(), '--sats', '999999']), tool.REFUSED)
        self.assertEqual(tool.main(['burn', '--recipient', '00' * 32, '--sats', '1000000']), tool.REFUSED)

    def test_a_pubkey_file_is_hashed_with_sha3(self):
        path = os.path.join(self.dir.name, 'pub.hex')
        Path(path).write_text('abcd\n')

        class Args:
            recipient = None
            recipient_pubkey = path
        self.assertEqual(tool.recipient_of(Args).hex(), __import__('hashlib').sha3_256(bytes.fromhex('abcd')).hexdigest())

    def test_find_reads_the_outbox_log_only(self):
        log = {'address': tool.OUTBOX, 'topics': ['0x' + tool.WITHDRAWAL_TOPIC, '0x' + '00' * 31 + '07', '0x' + ME.hex()],
               'data': '0x' + '00' * 12 + 'aa' * 20 + (2_000_000 * tool.ATOM_SCALE).to_bytes(32, 'big').hex()}
        other = {**log, 'address': '0x' + '11' * 20}
        found = tool.withdrawals_in_receipt({'logs': [other, log], 'blockNumber': '0x5'})
        self.assertEqual(found, [{'index': 7, 'l1_recipient': ME.hex(), 'sats': 2_000_000, 'sender': '0x' + 'aa' * 20, 'l2_block': 5}])
        reverted = self.url(lambda m, p: {'status': '0x0', 'logs': []})
        self.assertEqual(tool.main(['find', '--l2-rpc', reverted, '--tx', '0xab']), tool.REFUSED)
        pending = self.url(lambda m, p: None)
        self.assertEqual(tool.main(['find', '--l2-rpc', pending, '--tx', '0xab']), tool.NOT_READY)


if __name__ == '__main__':
    unittest.main()
