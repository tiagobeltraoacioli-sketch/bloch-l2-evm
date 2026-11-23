#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit AUDIT-L1L2-20261123, L2N-01 (the settler side of both protections) and L1X-04 (DA with the settler key).

1. Settler authorization: behind the L1 gate L2_SETTLER_AUTHORIZATION_ACTIVATION_EPOCH (native commit 5312e209) a
   settlement is accepted only with a trailer signed by a registered settler key. The worker's own codec is
   checked against the cross-repository vector (`deployment/mainnet/testdata/settler-authorization-vector.json`,
   the same file the native test `the_cross_repository_vector_is_what_consensus_accepts` verifies with the
   committee's decoder and the real hybrid verifier); the worker's behaviour is run against an L1 double that
   applies the native rule: no set installed, a trailer is refused; a set installed, a settlement needs one.
2. Program switch: the deployed program before the L1 switch epoch, `settlement_v3_mainnet_bound` from it on.
3. DA funded by the settler key once the L1 DA settler-slot rule (native commit 1ada9df7) is armed.

No network, no prover, no key: the signer here is a double of `bloch-pos l2-settler` with a toy signature."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess
import sys
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_v3 as t  # noqa: E402

VECTOR = HERE.parent / 'mainnet/testdata/settler-authorization-vector.json'
BOUND_CONFIG = bytes(range(95, 255)) + b'\x77' * 32  # the bound program: other identities, the same proof policy
KEY = lambda tag: bytes([tag]) * s.PQ_KEY_BYTES  # noqa: E731


def toy_sign(key, digest):
    return hashlib.sha3_256(key + digest).digest() * 4


def refusal(why):
    return s.RpcError(f"sendrawtransaction: {{'code': {s.TX_REFUSED}, 'message': 'L2 settlement refused: {why}'}}")


class GatedL1(t.Fake):
    """The native rules of the two L1 gates over the shared fake world.

    `settler_gate` / `switch` / `da_gate`: activation epochs (None = inert). `epoch` is the head epoch the RPCs
    report; `judge_epoch` (default: the same) is the epoch of the block that would include a transaction, so a
    test can put the reporting endpoints one epoch behind the proposers. `registered` is the installed set."""

    def __init__(self, root, values, keys=None, settler_gate=None, switch=None, da_gate=None, **kwargs):
        super().__init__(root, values, **kwargs)
        self.settler_gate, self.switch, self.da_gate = settler_gate, switch, da_gate
        self.registered = list(keys or [])
        self.judge_epoch = None
        self.report_gates = True
        self.refusals, self.after_refusal = [], None
        self.own, self.included = KEY(1), None

    def judged(self):
        return self.epoch if self.judge_epoch is None else self.judge_epoch

    def rpc(self, port, method, params=()):
        if method == 'getchaininfo':
            info = super().rpc(port, method, params)
            if self.report_gates:
                gate = lambda epoch: {'activation_epoch': epoch, 'active': epoch is not None and self.epoch >= epoch}  # noqa: E731
                info['hard_forks'] = {s.SETTLER_GATE: gate(self.settler_gate), s.DA_SETTLER_SLOT_GATE: gate(self.da_gate),
                                      s.PROGRAM_SWITCH_GATE: gate(self.switch), 'hf2_sig_canonical': gate(None)}
            return info
        if method == 'sendrawtransaction' and params[0].startswith('13'):
            return self.settle(bytes.fromhex(params[0]))
        return super().rpc(port, method, params)

    def refuse(self, why):
        self.refusals.append(why)
        if self.after_refusal:
            self.after_refusal()
        raise refusal(why)

    def settle(self, tx):
        """native State::check_authorization and the program rule, then the acceptance of the base double."""
        self.sent.append(tx)
        if tx == self.included:
            return {'status': 'duplicate', 'tx_hash': '00' * 32}  # the other endpoints of the one world
        base, trailer = tx[:s.TRANSACTION_BYTES], tx[s.TRANSACTION_BYTES:]
        installed = self.settler_gate is not None and self.judged() >= self.settler_gate and bool(self.registered)
        if installed != bool(trailer):
            self.refuse('settler')
        next_set = None
        if trailer:
            decoded = s.decode_authorization(trailer)
            if decoded is None:
                self.refuse('undecodable')
            signer, signature, next_set = decoded
            if signer >= len(self.registered):
                self.refuse('settler')
            digest = s.settler_digest(bytes.fromhex(t.NETWORK), s.CHAIN_ID, s.settlement_commitment(base), next_set)
            if signature != toy_sign(self.registered[signer], digest):
                self.refuse('settler')
        values = base[33:33 + s.VALUES_BYTES]
        program = BOUND_CONFIG if self.switch is not None and self.judged() >= self.switch else t.CONFIG_BYTES
        if values[s.T + 64:s.T + 224] != program[:160]:
            self.refuse('policy')
        if next_set:
            self.registered = next_set
        self.included = tx
        self.accepted = {'statement': values.hex(), 'commitment': s.settlement_commitment(base).hex()}
        return {'status': 'accepted', 'tx_hash': '00' * 32}

    def run(self, argv, **kwargs):
        name = Path(argv[0]).name
        if name == 'bloch-pos' and argv[1] == 'l2-settler':
            self.calls.append([str(a) for a in argv])
            assert kwargs['env']['BLOCH_KEYSTORE_PASSPHRASE_FILE'], 'the keystore is opened with its passphrase file'
            return self.signer(argv)
        if name == 'produce' and argv[1] == 'head' and self.head:
            # After block 1 the local head is the block the double settled (hash 0x51…51).
            self.calls.append([str(a) for a in argv])
            return types.SimpleNamespace(returncode=0, stderr='', stdout=json.dumps({'number': self.head, 'hash': '51' * 32}))
        if 'settlement-v3' in name and '--bound' in argv:
            self.calls.append([str(a) for a in argv])
            if 'prove-groth16' in argv:
                Path(argv[-1]).write_bytes(t.artifact(bound(self.values)))
            return types.SimpleNamespace(returncode=0, stdout='', stderr='')
        return super().run(argv, **kwargs)

    def signer(self, argv):
        """`bloch-pos l2-settler check|authorize` with the toy signature."""
        out = types.SimpleNamespace(returncode=0, stdout='', stderr='')
        option = lambda flag: argv[argv.index(flag) + 1]  # noqa: E731
        keys = s.parse_settler_set(Path(option('--set')).read_text())
        if keys is None or self.own not in keys:
            out.returncode, out.stderr = 2, "this keystore's key is not in the settler set"
            return out
        if argv[2] == 'check':
            return out
        assert argv[2] == 'authorize'
        tx = bytes.fromhex(Path(option('--tx')).read_text().strip())
        next_set = s.parse_settler_set(Path(option('--next-set')).read_text()) if '--next-set' in argv else None
        digest = s.settler_digest(bytes.fromhex(t.NETWORK), int(option('--chain-id')), s.settlement_commitment(tx),
                                  next_set)
        wire = tx + s.encode_authorization(keys.index(self.own), toy_sign(self.own, digest), next_set)
        Path(option('--out')).write_text(self.tamper(wire).hex() + '\n')
        return out

    tamper = staticmethod(lambda wire: wire)


def bound(values):
    v = bytearray(values)
    v[s.T + 64:s.T + 224] = BOUND_CONFIG[:160]
    return bytes(v)


def events(logged, name):
    return [c.kwargs for c in logged.call_args_list if c.args[0] == name]


def signer_calls(fake, command):
    return [c for c in fake.calls if Path(c[0]).name == 'bloch-pos' and c[1] == 'l2-settler' and c[2] == command]


class Base(unittest.TestCase):
    setUp_, tearDown = t.SettlerV3Test.setUp, t.SettlerV3Test.tearDown
    config, da_config = t.SettlerV3Test.config, t.SettlerV3Test.da_config

    def setUp(self):
        self.setUp_()
        (self.root / 'settler.pub').write_text(KEY(1).hex() + '\n')
        self.write_set([KEY(1), KEY(2)])
        (self.root / 'settlement_v3_bound').write_bytes(b'bound guest')
        (self.root / 'l2-config-bound.bin').write_bytes(BOUND_CONFIG)

    def write_set(self, keys, name='settler.set'):
        (self.root / name).write_text(''.join(k.hex() + '\n' for k in keys))

    def authorization(self, **extra):
        return {'signer': str(self.root / 'bloch-pos'), 'signer_sha256': s.digest(self.root / 'bloch-pos'),
                'genesis': str(self.root / 'genesis'), 'keystore_dir': str(self.root / 'settler-keys'),
                'passphrase_file': str(self.root / 'settler-pass'), 'pubkey': str(self.root / 'settler.pub'),
                'set': str(self.root / 'settler.set'), 'activation_epoch': 'l1', **extra}

    def switch(self, **extra):
        return {'activation_epoch': 'l1', 'guest': str(self.root / 'settlement_v3_bound'),
                'guest_sha256': s.digest(self.root / 'settlement_v3_bound'),
                'l2_config': str(self.root / 'l2-config-bound.bin'),
                'l2_config_sha256': s.digest(self.root / 'l2-config-bound.bin'), 'prover_args': ['--bound'], **extra}

    def settler(self, fake, **extra):
        clock = iter(range(0, 10_000_000, 3))
        return s.Settler(self.config(**extra), rpc=fake.rpc, run=fake.run, sleep=lambda _: None,
                         clock=lambda: next(clock))

    def next_block(self, fake):
        """Let the double offer block 2 on top of what it accepted (a new directory, a fresh statement)."""
        previous = fake.accepted['statement']
        fake.values = (bytes(fake.values[:s.T + 224]) + bytes.fromhex(fake.accepted['commitment'])  # the previous head
                       + bytes(fake.values[s.T + 256:s.T + 264]) + (2).to_bytes(8, 'big') + bytes(fake.values[s.T + 272:]))
        fake.head = 1
        return previous


class CodecAgainstTheNativeVector(unittest.TestCase):
    """The worker's digest, commitment and trailer codec, byte for byte against what the L1 verifier accepts."""

    @classmethod
    def setUpClass(cls):
        cls.v = json.loads(VECTOR.read_text())
        cls.keys = [bytes.fromhex(k) for k in cls.v['set'].split(',')]
        cls.next = [bytes.fromhex(k) for k in cls.v['next_set'].split(',')]
        cls.tx = bytes.fromhex(cls.v['unsigned_tx'])

    def test_the_vector_is_the_file_the_native_test_verifies(self):
        # Both repositories commit the same bytes; the native side checks the hybrid signatures in it.
        self.assertEqual(hashlib.sha256(VECTOR.read_bytes()).hexdigest(),
                         '1096758c25ac240caec2b7403960f39bec0179c9ebd7f3f73b005d34990a3167')
        self.assertEqual(len(self.tx), s.TRANSACTION_BYTES)
        self.assertEqual((self.tx[0], self.tx[33:33 + s.T]), (s.ASYNC_SETTLEMENT_TAG, s.TAG))

    def test_commitment_set_hash_and_digest_match(self):
        v, network, chain = self.v, bytes.fromhex(self.v['network_domain']), int(self.v['chain_id'])
        self.assertEqual((v['network_domain'], chain), (s.MAINNET['network'], s.MAINNET['chain_id']))
        self.assertEqual(s.settlement_commitment(self.tx).hex(), v['commitment'])
        self.assertEqual(s.parse_settler_set(v['set'].replace(',', '\n')), self.keys)
        self.assertEqual(s.settler_set_hash(self.keys).hex(), v['set_hash'])
        self.assertEqual(s.settler_set_hash(self.next).hex(), v['rotation_next_set_hash'])
        self.assertEqual(v['plain_next_set_hash'], '00' * 32)
        commitment = s.settlement_commitment(self.tx)
        self.assertEqual(s.settler_digest(network, chain, commitment).hex(), v['plain_digest'])
        self.assertEqual(s.settler_digest(network, chain, commitment, self.next).hex(), v['rotation_digest'])
        # The trailer is not part of the commitment: the accepted head chains exactly as before.
        self.assertEqual(s.settlement_commitment(bytes.fromhex(v['plain_authorized_tx'])), commitment)

    def test_the_trailer_decodes_and_encodes_to_the_same_bytes(self):
        for case, next_set in (('plain', None), ('rotation', self.next)):
            wire = bytes.fromhex(self.v[f'{case}_authorized_tx'])
            self.assertEqual(wire[:s.TRANSACTION_BYTES], self.tx, 'the deployed bytes, then the trailer')
            signer, signature, decoded_next = s.decode_authorization(wire[s.TRANSACTION_BYTES:])
            self.assertEqual((str(signer), decoded_next), (self.v[f'{case}_signer'], next_set))
            self.assertLessEqual(len(signature), s.PQ_SIGNATURE_MAX)
            self.assertEqual(s.encode_authorization(signer, signature, decoded_next), wire[s.TRANSACTION_BYTES:])
            self.assertLessEqual(len(wire), s.TRANSACTION_BYTES + s.SETTLER_MAX_AUTHORIZATION_BYTES)

    def test_decoding_is_exact(self):
        signature = b'\x05' * 100
        good = s.encode_authorization(1, signature, [KEY(3), KEY(4)])
        self.assertEqual(s.decode_authorization(good), (1, signature, [KEY(3), KEY(4)]))
        self.assertEqual(s.decode_authorization(s.encode_authorization(0, signature)), (0, signature, None))
        for bad in (good + b'\0', good[:-1], s.encode_authorization(0, b''), s.encode_authorization(3, signature),
                    s.encode_authorization(0, signature, [KEY(3), KEY(3)]),
                    s.encode_authorization(0, signature, [KEY(i) for i in range(4)]),
                    s.encode_authorization(0, b'\x05' * (s.PQ_SIGNATURE_MAX + 1)), b'', b'\0' * 5):
            self.assertIsNone(s.decode_authorization(bad))
        self.assertEqual(s.SETTLER_MAX_AUTHORIZATION_BYTES, 1 + 4 + 4593 + 1 + 3 * 3749)

    def test_a_set_text_is_one_to_three_distinct_keys(self):
        line = lambda tag: KEY(tag).hex()  # noqa: E731
        self.assertEqual(s.parse_settler_set(f'{line(1)}\n\n {line(2)} \n'), [KEY(1), KEY(2)])
        for bad in ('', f'{line(1)}\n{line(1)}\n', '\n'.join(line(i) for i in range(4)), line(1)[:-2], 'zz'):
            self.assertIsNone(s.parse_settler_set(bad))
        # Order is part of the set (the signer index).
        self.assertNotEqual(s.settler_set_hash([KEY(1), KEY(2)]), s.settler_set_hash([KEY(2), KEY(1)]))


class BeforeTheGate(Base):
    def test_without_the_configuration_nothing_is_read_signed_or_changed(self):
        fake = GatedL1(self.root, t.statement(), settler_gate=5, keys=[KEY(1)])
        fake.epoch = 100  # the L1 gate is in force, but this worker was not configured for it
        fake.report_gates = False
        worker = self.settler(fake)
        with mock.patch.object(fake, 'settle', wraps=lambda tx: t.Fake.rpc(fake, 1, 'sendrawtransaction', [tx.hex()])):
            self.assertTrue(worker.cycle())
        [tx] = t.broadcasts(fake.sent)
        self.assertEqual(len(tx), 1155)
        self.assertEqual(signer_calls(fake, 'check') + signer_calls(fake, 'authorize'), [])
        self.assertEqual(sorted(p.name for p in (self.root / 'work').glob('*/*')),
                         ['accepted.json', 'block.artifact', 'block.json', 'deposits.json', 'execute.log',
                          'native-request.txt', 'prove.log', 'proved.json', 'settlement.proof', 'submitted.json',
                          'transaction.bin', 'verify.log'], 'the directory of a block is what it was')
        record = json.loads(next((self.root / 'work').glob('*/submitted.json')).read_text())
        self.assertEqual(sorted(record), ['attempts', 'first_unix', 'last_status', 'tx_sha256'])
        self.assertEqual(json.loads(next((self.root / 'work').glob('*/proved.json')).read_text()).keys(),
                         {'steps', 'proof_sha256'})

    def test_configured_and_inert_the_bytes_are_the_deployed_bytes(self):
        plain = GatedL1(self.root, t.statement())
        plain.report_gates = False
        self.assertTrue(self.settler(plain, workdir=str(self.root / 'plain')).cycle())
        for gate, epoch in ((None, 100), (200, 100), (200, 198)):
            fake = GatedL1(self.root, t.statement(), settler_gate=gate, keys=[KEY(1), KEY(2)])
            fake.epoch = epoch
            work = self.root / f'work-{gate}-{epoch}'
            with mock.patch.object(s, 'log') as logged:
                self.assertTrue(self.settler(fake, workdir=str(work), settler_authorization=self.authorization()).cycle())
            self.assertEqual(t.broadcasts(fake.sent), t.broadcasts(plain.sent), 'byte for byte what is deployed')
            self.assertEqual(fake.refusals, [])
            self.assertEqual(signer_calls(fake, 'authorize'), [], 'nothing is signed before the gate')
            self.assertEqual(len(signer_calls(fake, 'check')), 1, 'the key is checked on the day the unit starts')
            self.assertEqual(len(events(logged, 'settler-key-checked')), 1)
            self.assertFalse(list(work.glob('*/transaction-authorized.bin')))
            self.assertFalse(json.loads(next(work.glob('*/submitted.json')).read_text())['authorized'])

    def test_an_l1_that_does_not_report_the_gate_is_an_inert_gate(self):
        fake = GatedL1(self.root, t.statement(), keys=[KEY(1)])
        fake.report_gates = False
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.settler(fake, settler_authorization=self.authorization()).cycle())
        self.assertEqual(len(t.broadcasts(fake.sent)[0]), 1155)
        self.assertEqual(events(logged, 'l1-gate-not-reported'), [{'gate': s.SETTLER_GATE, 'configured': 'l1'}])

    def test_a_key_that_cannot_sign_stops_the_worker_before_the_gate(self):
        fake = GatedL1(self.root, t.statement(), settler_gate=None)
        fake.own = KEY(9)  # the keystore holds another key than the public key file says
        with self.assertRaisesRegex(s.Halt, 'settler key check failed'):
            self.settler(fake, settler_authorization=self.authorization()).cycle()
        self.assertEqual(fake.sent, [])

    def test_the_configuration_is_checked(self):
        fake = GatedL1(self.root, t.statement())
        cases = [({'signer_sha256': '00' * 32}, 'settler signer differs from its pin'),
                 ({'activation_epoch': -1}, 'activation_epoch must be'), ({'activation_epoch': True}, 'activation_epoch'),
                 ({'set': ''}, 'settler_authorization.set is required'),
                 ({'pubkey': str(self.root / 'l2-config.bin')}, 'settler_authorization.pubkey')]
        for change, message in cases:
            with self.assertRaisesRegex(s.Halt, message):
                self.settler(fake, settler_authorization=self.authorization(**change))
        self.write_set([KEY(2), KEY(3)])
        with self.assertRaisesRegex(s.Halt, 'the settler key is not in the settler set file'):
            self.settler(fake, settler_authorization=self.authorization())
        self.write_set([KEY(1), KEY(1)])
        with self.assertRaisesRegex(s.Halt, 'is not a settler set'):
            self.settler(fake, settler_authorization=self.authorization())
        with self.assertRaisesRegex(s.Halt, 'must be an object'):
            self.settler(fake, settler_authorization=[])

    def test_a_configured_epoch_must_agree_with_the_l1(self):
        for reported, configured, message in ((300, 200, 'the L1 reports 300'), (None, 200, 'the L1 reports inert')):
            fake = GatedL1(self.root, t.statement(), settler_gate=reported, keys=[KEY(1)])
            worker = self.settler(fake, workdir=str(self.root / f'w{reported}'),
                                  settler_authorization=self.authorization(activation_epoch=configured))
            with self.assertRaisesRegex(s.Halt, message):
                worker.cycle()
            self.assertEqual(fake.sent, [])
        # An L1 that predates the gate's RPC row: the configured epoch decides.
        fake = GatedL1(self.root, t.statement(), settler_gate=50, keys=[KEY(1), KEY(2)])
        fake.report_gates = False
        self.assertTrue(self.settler(fake, settler_authorization=self.authorization(activation_epoch=50)).cycle())
        self.assertGreater(len(t.broadcasts(fake.sent)[0]), 1155)

    def test_no_quorum_on_the_gate_is_never_a_guess(self):
        fake = GatedL1(self.root, t.statement(), settler_gate=50, keys=[KEY(1)])
        ports = t.Ports(fake)
        gates = iter([50, 60, 70] * 20)
        real = fake.rpc

        def split(port, method, params=()):
            answer = real(port, method, params)
            if method == 'getchaininfo':
                answer['hard_forks'][s.SETTLER_GATE]['activation_epoch'] = next(gates)
            return answer
        ports.fake = types.SimpleNamespace(rpc=split, view=fake.view)
        worker = s.Settler(self.config(settler_authorization=self.authorization()), rpc=ports.rpc, run=fake.run,
                           sleep=lambda _: None, clock=iter(range(0, 10 ** 6, 3)).__next__)
        with self.assertRaisesRegex(RuntimeError, 'no RPC quorum on the L1 gate'):
            worker.cycle()
        self.assertEqual(fake.sent, [])


class BehindTheGate(Base):
    def armed(self, epoch=100, gate=50, keys=None, **kwargs):
        fake = GatedL1(self.root, t.statement(), settler_gate=gate, keys=keys or [KEY(1), KEY(2)], **kwargs)
        fake.epoch = epoch
        return fake

    def test_the_settlement_carries_the_trailer_the_l1_requires(self):
        fake = self.armed()
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.settler(fake, settler_authorization=self.authorization()).cycle())
        [wire] = t.broadcasts(fake.sent)
        directory = next((self.root / 'work').glob('*/transaction.bin')).parent
        base = (directory / 'transaction.bin').read_bytes()
        self.assertEqual((len(base), wire[:1155]), (1155, base), 'the deployed settlement, then the trailer')
        signer, signature, next_set = s.decode_authorization(wire[1155:])
        self.assertEqual((signer, next_set), (0, None))
        digest = s.settler_digest(bytes.fromhex(t.NETWORK), s.CHAIN_ID, s.settlement_commitment(base))
        self.assertEqual(signature, toy_sign(KEY(1), digest), 'signed over this exact settlement')
        self.assertEqual(fake.refusals, [])
        self.assertEqual(fake.accepted['commitment'], s.settlement_commitment(base).hex())
        # The signer alone opens the keystore, with the passphrase file, on the trusted genesis and the chain.
        [call] = signer_calls(fake, 'authorize')
        option = lambda flag: call[call.index(flag) + 1]  # noqa: E731
        self.assertEqual((option('--genesis'), option('--chain-id'), option('--dir'), option('--set')),
                         (str(self.root / 'genesis'), str(s.CHAIN_ID), str(self.root / 'settler-keys'),
                          str(self.root / 'settler.set')))
        self.assertNotIn('--next-set', call)
        self.assertNotIn('--allow-plaintext-keystore', call)
        meta = json.loads((directory / 'authorization.json').read_text())
        self.assertEqual((meta['signer'], meta['set_hash'], meta['next_set_hash'], meta['digest']),
                         (0, s.settler_set_hash([KEY(1), KEY(2)]).hex(), None, digest.hex()))
        record = json.loads((directory / 'submitted.json').read_text())
        self.assertEqual((record['authorized'], record['tx_sha256'], record['wire_sha256']),
                         (True, hashlib.sha256(base).hexdigest(), hashlib.sha256(wire).hexdigest()))
        self.assertEqual(len(events(logged, 'settlement-authorized')), 1)

    def test_an_authorized_settlement_is_signed_once(self):
        fake = self.armed()
        worker = self.settler(fake, settler_authorization=self.authorization())
        directory = self.root / 'd'
        directory.mkdir()
        tx = bytes([0x13]) + bytes(32) + t.statement() + bytes(356)
        first = worker.authorize(1, directory, tx)
        self.assertEqual(worker.authorize(1, directory, tx), first)
        self.assertEqual(len(signer_calls(fake, 'authorize')), 1)
        # Another settlement in the same directory (a new proof) is signed again, never reused.
        other = tx[:-1] + b'\x01'
        self.assertNotEqual(worker.authorize(1, directory, other), first)
        self.assertEqual(len(signer_calls(fake, 'authorize')), 2)

    def test_what_the_signer_returns_is_checked(self):
        tx_of = lambda wire: wire[:1155]  # noqa: E731
        cases = [(lambda w: b'\x14' + w[1:], 'not this settlement'), (lambda w: w + b'\0', 'not this settlement'),
                 (lambda w: tx_of(w) + bytes([1]) + w[1156:], 'another signer'),
                 (lambda w: tx_of(w), 'not this settlement'),
                 (lambda w: w[:-1] + b'\x01' + KEY(7), 'another next set')]
        for i, (tamper, message) in enumerate(cases):
            fake = self.armed()
            fake.tamper = tamper
            worker = self.settler(fake, workdir=str(self.root / f'w{i}'), settler_authorization=self.authorization())
            with self.assertRaisesRegex(s.Halt, message):
                worker.cycle()
            self.assertEqual(fake.sent, [], 'nothing unverified is broadcast')

    def test_a_signer_refusal_stops_the_worker(self):
        fake = self.armed()
        worker = self.settler(fake, settler_authorization=self.authorization())
        worker.settler_key_checked = True
        fake.own = KEY(9)
        with self.assertRaisesRegex(s.Halt, 'settler signer refused'):
            worker.cycle()
        self.assertEqual(fake.sent, [])

    def test_an_outsider_is_what_the_l1_double_refuses(self):
        # The finding's settlement: a valid proof and no registered key. The pinned worker (no configuration)
        # is that outsider once the set is installed; its refusal is terminal, as before.
        fake = self.armed()
        fake.report_gates = False
        with self.assertRaisesRegex(s.Halt, 'native nodes refuse the settlement'):
            self.settler(fake).cycle()
        self.assertEqual(set(fake.refusals), {'settler'})
        self.assertIsNone(fake.accepted)

    def test_a_refusal_far_from_the_gate_still_halts_and_names_the_set(self):
        fake = self.armed(keys=[KEY(5), KEY(6)])  # the L1 holds another set than the set file
        with self.assertRaisesRegex(s.Halt, 'is this key in the registered set'):
            self.settler(fake, settler_authorization=self.authorization()).cycle()
        self.assertIsNone(fake.accepted)

    def test_proved_before_the_boundary_and_included_after_it(self):
        # The endpoints report the last epoch before the gate; the block that would include the settlement is
        # already behind it. The unsigned form is refused, the worker does not halt, and sends the signed form
        # as soon as the head it reads is behind the gate.
        fake = self.armed(epoch=49, gate=50)
        fake.judge_epoch = 50
        fake.after_refusal = lambda: setattr(fake, 'epoch', 50)
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.settler(fake, settler_authorization=self.authorization()).cycle())
        sent = t.broadcasts(fake.sent)
        self.assertEqual([len(tx) > 1155 for tx in sent], [False, True])
        self.assertEqual(sent[1][:1155], sent[0], 'the same proof: only the trailer is added')
        self.assertEqual(fake.refusals, ['settler'] * 3, 'one refusal per endpoint, for the unsigned form only')
        self.assertEqual(len(events(logged, 'settlement-refused-at-gate-boundary')), 1)
        self.assertEqual(events(logged, 'settlement-form-changed'), [{'number': 1, 'authorized': True}])
        self.assertEqual(len(signer_calls(fake, 'prove-groth16')), 0)
        self.assertEqual(sum('prove-groth16' in c for c in fake.calls), 1, 'no second proof')

    def test_signed_just_before_the_nodes_install_the_set(self):
        # The other direction: the worker reads the gate's epoch while the including block is still before it.
        fake = self.armed(epoch=50, gate=50)
        fake.judge_epoch = 49
        fake.after_refusal = lambda: setattr(fake, 'judge_epoch', 50)
        self.assertTrue(self.settler(fake, settler_authorization=self.authorization()).cycle())
        self.assertTrue(all(len(tx) > 1155 for tx in fake.sent), 'the signed form only')
        self.assertEqual(fake.refusals, ['settler'], 'refused by the node still before the boundary, then taken')
        self.assertIsNotNone(fake.accepted)


class Rotation(Base):
    def armed(self):
        fake = GatedL1(self.root, t.statement(), settler_gate=50, keys=[KEY(1), KEY(2)])
        fake.epoch = 100
        return fake

    def test_a_rotation_request_rides_on_the_next_settlement_and_replaces_the_set(self):
        fake = self.armed()
        self.write_set([KEY(2), KEY(1), KEY(3)], 'settler.set.next')
        worker = self.settler(fake, settler_authorization=self.authorization())
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(worker.cycle())
        [wire] = t.broadcasts(fake.sent)
        signer, _, next_set = s.decode_authorization(wire[1155:])
        self.assertEqual((signer, next_set), (0, [KEY(2), KEY(1), KEY(3)]))
        self.assertIn('--next-set', signer_calls(fake, 'authorize')[0])
        self.assertEqual(fake.registered, [KEY(2), KEY(1), KEY(3)], 'the L1 installed the next set')
        # The worker follows: set file replaced, the old one kept, the request retired, no journal left.
        self.assertEqual(s.parse_settler_set((self.root / 'settler.set').read_text()), [KEY(2), KEY(1), KEY(3)])
        self.assertEqual(s.parse_settler_set((self.root / 'settler.set.previous').read_text()), [KEY(1), KEY(2)])
        self.assertFalse((self.root / 'settler.set.next').exists())
        self.assertTrue((self.root / 'settler.set.next.applied').exists())
        self.assertFalse((self.root / 'settler.set.rotation.json').exists())
        [rotated] = events(logged, 'settler-set-rotated')
        self.assertEqual((rotated['previous_set_hash'], rotated['set_hash'], rotated['this_key_registered']),
                         (s.settler_set_hash([KEY(1), KEY(2)]).hex(), s.settler_set_hash([KEY(2), KEY(1), KEY(3)]).hex(),
                          True))
        self.assertEqual(len(events(logged, 'settler-rotation-signed')), 1)
        # The next block is signed under the new set, with this key's new index and no further rotation.
        self.next_block(fake)
        self.assertTrue(worker.cycle())
        signer, _, next_set = s.decode_authorization(t.broadcasts(fake.sent)[1][1155:])
        self.assertEqual((signer, next_set), (1, None))
        self.assertEqual(fake.refusals, [])

    def test_a_key_rotated_out_stops_settling_and_says_why(self):
        fake = self.armed()
        self.write_set([KEY(2), KEY(3)], 'settler.set.next')
        worker = self.settler(fake, settler_authorization=self.authorization())
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(worker.cycle())
        self.assertFalse(events(logged, 'settler-set-rotated')[0]['this_key_registered'])
        self.next_block(fake)
        with self.assertRaisesRegex(s.Halt, 'a registered key must settle'):
            worker.cycle()
        self.assertEqual(len(t.broadcasts(fake.sent)), 1)
        # A restart says the same before anything else.
        with self.assertRaisesRegex(s.Halt, 'the settler key is not in the settler set file'):
            self.settler(fake, settler_authorization=self.authorization())

    def test_a_crash_between_acceptance_and_the_set_file_is_repaired_at_the_next_cycle(self):
        fake = self.armed()
        self.write_set([KEY(1), KEY(3)], 'settler.set.next')
        worker = self.settler(fake, settler_authorization=self.authorization())
        with mock.patch.object(worker, 'reconcile_rotation'):
            self.assertTrue(worker.cycle())  # accepted, and the process dies before the set file is written
        self.assertEqual(s.parse_settler_set((self.root / 'settler.set').read_text()), [KEY(1), KEY(2)])
        self.assertTrue((self.root / 'settler.set.rotation.json').exists())
        self.next_block(fake)
        restarted = self.settler(fake, settler_authorization=self.authorization())
        self.assertTrue(restarted.cycle())
        self.assertEqual(s.parse_settler_set((self.root / 'settler.set').read_text()), [KEY(1), KEY(3)])
        self.assertEqual(fake.refusals, [], 'block 2 was signed under the installed set')

    def test_a_rotation_whose_block_went_to_another_statement_did_not_happen(self):
        fake = self.armed()
        self.write_set([KEY(1), KEY(3)], 'settler.set.next')
        worker = self.settler(fake, settler_authorization=self.authorization())
        directory = self.root / 'd'
        directory.mkdir()
        tx = bytes([0x13]) + bytes(32) + t.statement() + bytes(356)
        worker.authorize(1, directory, tx)
        self.assertTrue((self.root / 'settler.set.rotation.json').exists())
        other = t.statement(**{'336': b'\x52' * 32})
        with mock.patch.object(s, 'log') as logged:
            worker.reconcile_rotation({'statement': other.hex(), 'commitment': '00' * 32})
        self.assertEqual(len(events(logged, 'settler-rotation-not-applied')), 1)
        self.assertEqual(s.parse_settler_set((self.root / 'settler.set').read_text()), [KEY(1), KEY(2)])
        self.assertTrue((self.root / 'settler.set.next').exists(), 'the request stays for the next settlement')
        self.assertFalse((self.root / 'settler.set.rotation.json').exists())

    def test_an_invalid_or_empty_request_never_stops_settlement(self):
        fake = self.armed()
        (self.root / 'settler.set.next').write_text('not a set\n')
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.settler(fake, settler_authorization=self.authorization()).cycle())
        self.assertEqual(len(events(logged, 'settler-rotation-invalid')), 1)
        self.assertEqual(s.decode_authorization(t.broadcasts(fake.sent)[0][1155:])[2], None)
        self.assertEqual(fake.registered, [KEY(1), KEY(2)])

    def test_before_the_gate_a_request_waits(self):
        fake = GatedL1(self.root, t.statement(), settler_gate=None, keys=[KEY(1), KEY(2)])
        self.write_set([KEY(1), KEY(3)], 'settler.set.next')
        self.assertTrue(self.settler(fake, settler_authorization=self.authorization()).cycle())
        self.assertEqual(len(t.broadcasts(fake.sent)[0]), 1155)
        self.assertTrue((self.root / 'settler.set.next').exists())
        self.assertEqual(s.parse_settler_set((self.root / 'settler.set').read_text()), [KEY(1), KEY(2)])


class ProgramSwitch(Base):
    def world(self, epoch, switch=200, **kwargs):
        fake = GatedL1(self.root, t.statement(), switch=switch, **kwargs)
        fake.epoch = epoch
        return fake

    def prover_calls(self, fake):
        return [c for c in fake.calls if 'settlement-v3' in Path(c[0]).name]

    def test_before_the_switch_the_deployed_program_proves_as_today(self):
        plain = GatedL1(self.root, t.statement())
        plain.report_gates = False
        self.assertTrue(self.settler(plain, workdir=str(self.root / 'plain')).cycle())
        for switch in (None, 200):
            fake = self.world(100, switch=switch)
            work = self.root / f'w{switch}'
            self.assertTrue(self.settler(fake, workdir=str(work), program_switch=self.switch()).cycle())
            self.assertEqual(t.broadcasts(fake.sent), t.broadcasts(plain.sent))
            strip = lambda calls, root: [[a.replace(str(root), 'W') for a in c] for c in calls]  # noqa: E731
            self.assertEqual(strip(self.prover_calls(fake), work), strip(self.prover_calls(plain), self.root / 'plain'),
                             'the prover is invoked exactly as it is today')
            self.assertEqual(json.loads(next(work.glob('*/program.json')).read_text())['program'], 'deployed')

    def test_from_the_switch_on_the_bound_program_proves_and_its_identities_are_settled(self):
        fake = self.world(200)
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.settler(fake, program_switch=self.switch()).cycle())
        calls = self.prover_calls(fake)
        self.assertEqual([c[1] for c in calls], ['--bound'] * 3, 'execute, prove and verify under the bound program')
        self.assertEqual({c[c.index('native-artifact') + 1] for c in calls}, {str(self.root / 'settlement_v3_bound')})
        [tx] = t.broadcasts(fake.sent)
        self.assertEqual(tx[33 + s.T + 64:33 + s.T + 224], BOUND_CONFIG[:160], 'the bound program identities')
        self.assertEqual(tx[1:33], t.CONFIG_BYTES[160:192], 'the proof policy is the same')
        self.assertEqual(fake.refusals, [])
        directory = next((self.root / 'work').glob('*/proved.json')).parent
        self.assertEqual(json.loads((directory / 'proved.json').read_text())['program'], 'bound')
        self.assertEqual(events(logged, 'program-selected')[0]['program'], 'bound')

    def test_the_deployed_program_after_the_switch_is_what_the_l1_refuses(self):
        # Control: the worker without the switch configuration keeps proving the old program and is refused.
        fake = self.world(200)
        fake.report_gates = False
        with self.assertRaisesRegex(s.Halt, 'native nodes refuse the settlement'):
            self.settler(fake).cycle()
        self.assertEqual(set(fake.refusals), {'policy'})

    def test_a_proof_started_one_epoch_before_the_switch_is_bound_and_waits_for_it(self):
        fake = self.world(199)
        worker = self.settler(fake, program_switch=self.switch())
        with mock.patch.object(s, 'log') as logged:
            self.assertFalse(worker.cycle())
            self.assertFalse(worker.cycle())
        self.assertEqual(fake.sent, [], 'a bound settlement is never sent before the switch')
        self.assertEqual(sum('prove-groth16' in c for c in fake.calls), 1, 'proved once, held')
        self.assertEqual([e['activation_epoch'] for e in events(logged, 'settlement-waiting-program-switch')], [200, 200])
        fake.epoch = 200
        self.assertTrue(worker.cycle())
        self.assertEqual(fake.refusals, [])
        self.assertEqual(sum('prove-groth16' in c for c in fake.calls), 1)
        # With lead_epochs 0 the same epoch still proves the deployed program.
        early = self.world(199)
        self.assertTrue(self.settler(early, workdir=str(self.root / 'lead0'),
                                     program_switch=self.switch(lead_epochs=0)).cycle())
        self.assertEqual(t.broadcasts(early.sent)[0][33 + s.T + 64:33 + s.T + 224], t.CONFIG_BYTES[:160])

    def test_a_deployed_proof_not_included_by_the_switch_is_proved_again(self):
        fake = self.world(198)
        worker = self.settler(fake, program_switch=self.switch())
        with mock.patch.object(worker, 'submit_and_wait', return_value=False):
            self.assertFalse(worker.cycle())  # proved under the deployed program, never included
        directory = next((self.root / 'work').glob('*/proved.json')).parent
        self.assertEqual(json.loads((directory / 'program.json').read_text())['program'], 'deployed')
        # Still before the switch: the finished proof is submitted, not thrown away.
        fake.epoch = 199
        with mock.patch.object(worker, 'submit_and_wait', return_value=False) as submit:
            self.assertFalse(worker.cycle())
        self.assertEqual(submit.call_count, 1)
        self.assertEqual(sum('prove-groth16' in c for c in fake.calls), 1)
        # The switch passed: the old proof can no longer settle.
        fake.epoch = 200
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(worker.cycle())
        self.assertEqual(sum('prove-groth16' in c for c in fake.calls), 2)
        self.assertEqual(events(logged, 'program-switch-reprove')[0]['previous'], 'deployed')
        self.assertTrue((directory / 'proved.json.deployed').exists() and (directory / 'transaction.bin.deployed').exists())
        self.assertEqual(json.loads((directory / 'proved.json').read_text())['program'], 'bound')
        self.assertEqual(fake.refusals, [])
        self.assertEqual(t.broadcasts(fake.sent)[0][33 + s.T + 64:33 + s.T + 224], BOUND_CONFIG[:160])

    def test_a_deployed_settlement_overtaken_by_the_switch_while_it_waits_is_abandoned(self):
        fake = self.world(199, switch=200)
        fake.judge_epoch = 200  # proposers are already behind the switch
        fake.after_refusal = lambda: setattr(fake, 'epoch', 200)
        worker = self.settler(fake, program_switch=self.switch(lead_epochs=0))
        with mock.patch.object(s, 'log') as logged:
            self.assertFalse(worker.cycle())
            self.assertEqual(len(events(logged, 'settlement-missed-program-switch')), 1)
            self.assertTrue(worker.cycle())
        self.assertEqual(sum('prove-groth16' in c for c in fake.calls), 2)
        self.assertIsNotNone(fake.accepted)

    def test_the_choice_never_goes_back(self):
        fake = self.world(199)
        worker = self.settler(fake, program_switch=self.switch())
        self.assertFalse(worker.cycle())
        fake.epoch = 190  # an endpoint set that reports an older head
        self.assertFalse(worker.cycle())
        directory = next((self.root / 'work').glob('*/program.json')).parent
        self.assertEqual(json.loads((directory / 'program.json').read_text())['program'], 'bound')
        self.assertEqual(sum('prove-groth16' in c for c in fake.calls), 1)
        fake.switch = None  # the gate disappears from the L1: an operator must look
        worker.gate_cache.clear()
        with self.assertRaisesRegex(s.Halt, 'no longer scheduled'):
            worker.cycle()

    def test_both_gates_together(self):
        fake = GatedL1(self.root, t.statement(), settler_gate=50, switch=200, keys=[KEY(1), KEY(2)])
        fake.epoch = 200
        self.assertTrue(self.settler(fake, settler_authorization=self.authorization(),
                                     program_switch=self.switch()).cycle())
        [wire] = t.broadcasts(fake.sent)
        self.assertGreater(len(wire), 1155)
        self.assertEqual(wire[33 + s.T + 64:33 + s.T + 224], BOUND_CONFIG[:160])
        self.assertEqual(fake.refusals, [])

    def test_the_remote_prover_is_asked_for_the_bound_program(self):
        (self.root / 'known_hosts').write_text('host key\n')
        remote = {'target': 'prover@host', 'key': str(self.root / 'key'), 'known_hosts': str(self.root / 'known_hosts'),
                  'order': ['remote']}
        for epoch, command in ((100, 'prove'), (200, 'prove-bound')):
            fake = self.world(epoch)
            fake.values = bound(fake.values) if epoch >= 200 else fake.values
            self.assertTrue(self.settler(fake, workdir=str(self.root / f'r{epoch}'), remote_prover=remote,
                                         program_switch=self.switch()).cycle())
            [ssh] = [c for c in fake.calls if Path(c[0]).name == 'ssh']
            self.assertEqual(ssh[-2:], ['prover@host', command])

    def test_the_remote_prover_serves_the_bound_program_only_when_it_pins_it(self):
        prover = self.root / 'fake-settlement-v3'
        # Writes the flag and the guest it was given, so the test sees which program ran.
        prover.write_text('#!/bin/sh\nprintf "%s %s" "$1" "$4" > "$5"\n')
        prover.chmod(0o755)
        (self.root / 'pwork').mkdir()
        bound_guest = self.root / 'settlement_v3_bound'
        config = {'prover': str(prover), 'prover_sha256': s.digest(prover), 'guest': str(self.root / 'settlement_v3'),
                  'guest_sha256': s.digest(self.root / 'settlement_v3'), 'workdir': str(self.root / 'pwork'),
                  'home': str(self.root / 'home'), 'prover_threads': 4, 'gnark_image': 'image', 'mainnet': True}
        job = t.rp.MAGIC + struct.pack('>I', 4) + b'req\n' + struct.pack('>Q', 3) + b'art'

        def run(command, **extra):
            (self.root / 'prover.json').write_text(json.dumps({**config, **extra}))
            env = {'PATH': '/usr/bin:/bin', 'BLOCH_REMOTE_PROVER_CONFIG': str(self.root / 'prover.json'),
                   'SSH_ORIGINAL_COMMAND': command}
            return subprocess.run([sys.executable, str(HERE / 'remote_prover.py')], input=job, capture_output=True, env=env)
        bound_config = {'bound': {'guest': str(bound_guest), 'guest_sha256': s.digest(bound_guest)}}
        done = run('prove', **bound_config)
        self.assertEqual((done.returncode, done.stdout.decode()), (0, f'--mainnet {self.root / "settlement_v3"}'))
        done = run('prove-bound', **bound_config)
        self.assertEqual((done.returncode, done.stdout.decode()), (0, f'--mainnet-bound {bound_guest}'))
        # A prover that was not given the bound guest refuses, and so does one whose bound guest changed.
        self.assertEqual(run('prove-bound').returncode, 64)
        self.assertEqual(run('prove-bound', bound={'guest': str(bound_guest), 'guest_sha256': '00' * 32}).returncode, 70)
        self.assertEqual(run('prove-bound', mainnet=False, **bound_config).returncode, 64)
        self.assertEqual(run('prove-other', **bound_config).returncode, 64)

    def test_the_configuration_is_checked(self):
        fake = self.world(100)
        for change, message in (({'guest_sha256': '00' * 32}, 'program_switch.guest differs from its pin'),
                                ({'l2_config': ''}, 'program_switch.l2_config is required'),
                                ({'lead_epochs': -1}, 'lead_epochs'), ({'activation_epoch': 'soon'}, 'activation_epoch'),
                                ({'prover_args': '--bound'}, 'prover_args as a list')):
            with self.assertRaisesRegex(s.Halt, message):
                self.settler(fake, program_switch=self.switch(**change))

    def test_on_the_mainnet_path_the_bound_program_is_the_pinned_one(self):
        guest = self.root / 'settlement_v3_mainnet_bound'
        guest.write_bytes(b'bound mainnet guest')
        config = self.root / 'l2-config-mainnet-bound.bin'
        config.write_bytes(s.mainnet_l2_config(s.MAINNET_BOUND))
        switch = {'activation_epoch': 'l1', 'guest': str(guest), 'guest_sha256': s.digest(guest),
                  'l2_config': str(config), 'l2_config_sha256': s.digest(config)}

        def programs(**change):
            stub = types.SimpleNamespace(mainnet_path=True, prover_args=['--mainnet'],
                                         c={'guest': 'g', 'l2_config': 'c', 'program_switch': {**switch, **change}})
            s.Settler.init_programs(stub)
            return stub.programs
        with self.assertRaisesRegex(s.Halt, 'pinned settlement_v3_mainnet_bound ELF'):
            programs()  # the file is not the pinned ELF
        with mock.patch.dict(s.MAINNET_BOUND, {'guest_sha256': s.digest(guest)}):
            bound_program = programs()['bound']
            self.assertEqual((bound_program['prover_args'], bound_program['remote_command']),
                             (['--mainnet-bound'], 'prove-bound'))
            self.assertEqual(programs()['deployed']['prover_args'], ['--mainnet'])
            with self.assertRaisesRegex(s.Halt, 'fixed on the mainnet path'):
                programs(prover_args=['--mainnet'])
            config.write_bytes(s.mainnet_l2_config())  # the deployed identities under the bound name
            with self.assertRaisesRegex(s.Halt, 'differs from the pinned bound program'):
                programs(l2_config_sha256=s.digest(config))

    def test_the_bound_pins_are_the_documented_candidate_values(self):
        doc = (HERE.parent.parent / 'docs/MAINNET-PROGRAM.md').read_text()
        row = lambda label: re.search(rf'\| {re.escape(label)} \| `([0-9a-f]{{64}})` \| `([0-9a-f]{{64}})`', doc).groups()  # noqa: E731
        for label, key in (('ELF SHA-256', 'guest_sha256'), ('`identities[3]` configuration', 'configuration'),
                           ('`identities[4]` ELF Keccak-256', 'elf_keccak'), ('`identities[5]` KoalaBear key', 'vkey_koalabear'),
                           ('`identities[6]` BN254 key', 'vkey_bn254')):
            self.assertEqual(row(label), (s.MAINNET[key], s.MAINNET_BOUND[key]), label)
        same = set(s.MAINNET) - {'guest_sha256', 'configuration', 'elf_keccak', 'vkey_koalabear', 'vkey_bn254'}
        self.assertTrue(all(s.MAINNET[k] == s.MAINNET_BOUND[k] for k in same), 'policy, domain, genesis: unchanged')
        self.assertEqual(s.MAINNET_BOUND_STATUS, 'candidate', 'a release sets its own values and says so')
        deployed, candidate = s.mainnet_l2_config(), s.mainnet_l2_config(s.MAINNET_BOUND)
        self.assertEqual(hashlib.sha256(deployed).hexdigest(), s.MAINNET_L2_CONFIG_SHA256)
        self.assertEqual((deployed[:32], deployed[160:]), (candidate[:32], candidate[160:]))
        self.assertNotEqual(deployed[32:160], candidate[32:160])


class DaWithTheSettlerKey(Base):
    def user(self, fake, da=None, **extra):
        return self.settler(fake, user_transactions=True, txpool_dir=str(self.root / 'txpool'),
                            da=self.da_config() if da is None else da, **extra)

    def da_calls(self, fake, command):
        return [c for c in fake.calls if Path(c[0]).name == 'bloch-pos' and c[1] == 'l2-da' and c[2] == command]

    def test_the_da_transaction_is_funded_and_signed_by_the_settler_keystore(self):
        fake = GatedL1(self.root, t.statement(user_txs=2), produced_txs=2, settler_gate=50, da_gate=60,
                       keys=[KEY(1), KEY(2)])
        fake.epoch = 100
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.user(fake, da={'settler_key': True, 'settler_slot_activation_epoch': 'l1'},
                                      settler_authorization=self.authorization()).cycle())
        [prepare], [sign] = self.da_calls(fake, 'prepare'), self.da_calls(fake, 'sign')
        self.assertEqual(prepare[prepare.index('--funding-pubkey') + 1], str(self.root / 'settler.pub'))
        self.assertEqual(sign[sign.index('--dir') + 1], str(self.root / 'settler-keys'))
        self.assertEqual(events(logged, 'da-funding-key-not-registered'), [])
        self.assertEqual(len(fake.da_records), 1)
        self.assertGreater(len(t.broadcasts(fake.sent)[-1]), 1155)

    def test_settler_key_needs_the_authorization_block_and_no_other_key(self):
        fake = GatedL1(self.root, t.statement(user_txs=2), produced_txs=2)
        with self.assertRaisesRegex(s.Halt, 'da.settler_key requires settler_authorization'):
            self.user(fake, da={'settler_key': True})
        with self.assertRaisesRegex(s.Halt, "da.funding_pubkey must be the settler key's or absent"):
            self.user(fake, da={**self.da_config(), 'settler_key': True}, settler_authorization=self.authorization())
        with self.assertRaisesRegex(s.Halt, 'da.settler_slot_activation_epoch'):
            self.user(fake, da={**self.da_config(), 'settler_slot_activation_epoch': 'yes'})

    def test_a_funding_key_outside_the_set_is_reported_once_the_rule_is_armed(self):
        for epoch, expected in ((59, 0), (60, 1)):
            fake = GatedL1(self.root, t.statement(user_txs=2), produced_txs=2, settler_gate=50, da_gate=60,
                           keys=[KEY(1), KEY(2)])
            fake.epoch = epoch
            with mock.patch.object(s, 'log') as logged:
                self.assertTrue(self.user(fake, workdir=str(self.root / f'w{epoch}'),
                                          da={**self.da_config(), 'settler_slot_activation_epoch': 'l1'},
                                          settler_authorization=self.authorization()).cycle())
            reported = events(logged, 'da-funding-key-not-registered')
            self.assertEqual(len(reported), expected, 'once per block, and the batch is still published')
            self.assertEqual(len(fake.da_records), 1)
            if reported:
                self.assertEqual((reported[0]['registered_keys'], reported[0]['activation_epoch']), (2, 60))

    def test_without_the_setting_the_da_path_reads_no_gate(self):
        fake = GatedL1(self.root, t.statement(user_txs=2), produced_txs=2, da_gate=60)
        fake.epoch = 100
        fake.report_gates = False
        with mock.patch.object(s, 'log') as logged:
            self.assertTrue(self.user(fake).cycle())
        self.assertEqual(events(logged, 'da-funding-key-not-registered') + events(logged, 'l1-gate-not-reported'), [])


@unittest.skipUnless(os.environ.get('BLOCH_POS_BIN') and os.environ.get('BLOCH_GENESIS_MANIFEST'),
                     'set BLOCH_POS_BIN (a bloch-pos with `l2-settler`) and BLOCH_GENESIS_MANIFEST (genesis/mainnet.manifest)')
class RealSigner(Base):
    """The worker against the real `bloch-pos l2-settler` and throwaway sealed keystores made here: generation,
    the key check, an authorization and a rotation, each accepted by the tool's own `verify` (the committee's
    decoder and digest and the hybrid verifier). The manifest gives the network domain; nothing is broadcast."""

    def setUp(self):
        super().setUp()
        self.bin, self.manifest = os.environ['BLOCH_POS_BIN'], os.environ['BLOCH_GENESIS_MANIFEST']
        self.passphrase = self.root / 'settler-pass'
        self.passphrase.write_text(secrets.token_urlsafe(36) + '\n')
        self.passphrase.chmod(0o600)
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root / 'home'),
                    'BLOCH_KEYSTORE_PASSPHRASE_FILE': str(self.passphrase)}
        for name in ('settler-keys', 'standby-keys', 'new-keys'):
            self.tool('keygen', '--dir', self.root / name, '--index', '0')
            (self.root / f'{name}.pub').unlink(missing_ok=True)
            self.tool('l2-settler', 'pubkey', '--dir', self.root / name, '--out', self.root / f'{name}.pub')
        (self.root / 'settler.pub').write_text((self.root / 'settler-keys.pub').read_text())
        (self.root / 'settler.set').unlink()
        self.tool('l2-settler', 'set', '--pubkey', self.root / 'settler-keys.pub', '--pubkey',
                  self.root / 'standby-keys.pub', '--out', self.root / 'settler.set')

    def tool(self, *argv, ok=True):
        result = subprocess.run([self.bin, *map(str, argv)], env=self.env, capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode == 0, ok, result.stderr)
        return result

    def worker(self):
        authorization = self.authorization(signer=self.bin, signer_sha256=s.digest(self.bin), genesis=self.manifest)
        fake = GatedL1(self.root, t.statement())
        return s.Settler(self.config(network=s.MAINNET['network'], settler_authorization=authorization),
                         rpc=fake.rpc, run=subprocess.run, sleep=lambda _: None, clock=iter(range(0, 10 ** 6, 3)).__next__)

    def verify(self, wire, set_file='settler.set', ok=True):
        path = self.root / 'wire.hex'
        path.write_text(wire.hex() + '\n')
        return self.tool('l2-settler', 'verify', '--genesis', self.manifest, '--chain-id', s.CHAIN_ID, '--tx', path,
                         '--set', self.root / set_file, ok=ok)

    def test_the_keystore_is_sealed_and_only_public_material_leaves_it(self):
        report = self.tool('keys', 'inspect', '--dir', self.root / 'settler-keys').stdout
        self.assertIn('Argon2id', report)
        key_file = self.root / 'settler-keys/validator.key'
        self.assertEqual(key_file.stat().st_mode & 0o777, 0o600)
        public = bytes.fromhex((self.root / 'settler.pub').read_text().strip())
        self.assertEqual(len(public), s.PQ_KEY_BYTES)
        self.assertEqual(s.parse_settler_set((self.root / 'settler.set').read_text())[0], public)
        # Without the passphrase the tool does not open the keystore, and plaintext is not an option here.
        no_pass = {k: v for k, v in self.env.items() if k != 'BLOCH_KEYSTORE_PASSPHRASE_FILE'}
        refused = subprocess.run([self.bin, 'l2-settler', 'check', '--set', str(self.root / 'settler.set'), '--dir',
                                  str(self.root / 'settler-keys')], env=no_pass, capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)
        self.tool('l2-settler', 'check', '--set', self.root / 'settler.set', '--dir', self.root / 'settler-keys',
                  '--allow-plaintext-keystore', ok=False)

    def test_the_worker_signs_what_the_native_tool_verifies(self):
        worker = self.worker()
        worker.check_settler_key()
        directory = self.root / 'block'
        directory.mkdir()
        tx = bytes([0x13]) + bytes(32) + t.statement() + bytes(356)
        wire = worker.authorize(1, directory, tx)
        self.assertEqual(wire[:1155], tx)
        signer, signature, next_set = s.decode_authorization(wire[1155:])
        self.assertEqual((signer, next_set), (0, None))
        self.assertIn('authorized by signer 0 of 2', self.verify(wire).stdout)
        # Not valid for another settlement, proof or set, nor with the trailer altered.
        self.verify(tx[:-1] + b'\x01' + wire[1155:], ok=False)
        self.verify(tx[:40] + b'\x01' + tx[41:] + wire[1155:], ok=False)
        self.verify(wire[:1155] + bytes([1]) + wire[1156:], ok=False)
        self.tool('l2-settler', 'set', '--pubkey', self.root / 'new-keys.pub', '--out', self.root / 'other.set')
        self.verify(wire, 'other.set', ok=False)
        meta = json.loads((directory / 'authorization.json').read_text())
        self.assertEqual(meta['signature_bytes'], len(signature))
        # The unsigned settlement is still what `inspect` calls the form accepted before the gate.
        (self.root / 'unsigned.hex').write_text(tx.hex() + '\n')
        self.assertIn('authorization  : none', self.tool('l2-settler', 'inspect', '--tx', self.root / 'unsigned.hex').stdout)

    def test_a_rotation_signed_by_the_worker_verifies_with_its_next_set(self):
        self.tool('l2-settler', 'set', '--pubkey', self.root / 'new-keys.pub', '--pubkey', self.root / 'standby-keys.pub',
                  '--out', self.root / 'settler.set.next')
        worker = self.worker()
        directory = self.root / 'block'
        directory.mkdir()
        tx = bytes([0x13]) + bytes(32) + t.statement() + bytes(356)
        wire = worker.authorize(1, directory, tx)
        _, _, next_set = s.decode_authorization(wire[1155:])
        self.assertEqual(next_set, s.parse_settler_set((self.root / 'settler.set.next').read_text()))
        report = self.verify(wire).stdout
        self.assertIn(f'next set: 2 key(s), set hash {s.settler_set_hash(next_set).hex()}', report)
        # The standby key authorizes the same settlement by hand (the lost-key procedure).
        (self.root / 'unsigned.hex').write_text(tx.hex() + '\n')
        self.tool('l2-settler', 'authorize', '--genesis', self.manifest, '--chain-id', s.CHAIN_ID, '--tx',
                  self.root / 'unsigned.hex', '--set', self.root / 'settler.set', '--dir', self.root / 'standby-keys',
                  '--next-set', self.root / 'settler.set.next', '--out', self.root / 'standby.hex')
        standby = bytes.fromhex((self.root / 'standby.hex').read_text().strip())
        self.assertEqual(s.decode_authorization(standby[1155:])[0], 1)
        self.assertIn('authorized by signer 1 of 2', self.verify(standby).stdout)
        # A key outside the set is refused by the tool.
        self.tool('l2-settler', 'authorize', '--genesis', self.manifest, '--chain-id', s.CHAIN_ID, '--tx',
                  self.root / 'unsigned.hex', '--set', self.root / 'settler.set', '--dir', self.root / 'new-keys',
                  '--out', self.root / 'outsider.hex', ok=False)
        self.assertFalse((self.root / 'outsider.hex').exists())


if __name__ == '__main__':
    unittest.main()
