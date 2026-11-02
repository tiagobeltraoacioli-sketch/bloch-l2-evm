#!/usr/bin/env python3
"""Review r7 F5 (agent 121): with `skip_idle_blocks` and user transactions on, a spool entry no block includes (a nonce
gap) made every cycle due, so a block was built every pacing interval. A spooled file is now demand only when its nonce
is its sender's next nonce at the head.

Fake native RPC and producer (test_settler_foreign.IdleTest); transactions are really signed here.
Run: python3 -m unittest -v deployment/devnet/test_settler_f5.py
"""
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import settler_v3 as s  # noqa: E402
import test_settler_foreign as foreign  # noqa: E402

KEY = 0x2b1c0ffee  # throwaway test key
CHAIN = 700770


def address(key):
    point = s.secp_mul(key, s.SECP_G)
    return s.keccak256(point[0].to_bytes(32, 'big') + point[1].to_bytes(32, 'big'))[12:]


def sign(key, digest):
    e = int.from_bytes(digest, 'big')
    k = int.from_bytes(s.keccak256(key.to_bytes(32, 'big') + digest), 'big') % s.SECP_N or 1
    point = s.secp_mul(k, s.SECP_G)
    r = point[0] % s.SECP_N
    sig = pow(k, -1, s.SECP_N) * (e + r * key) % s.SECP_N
    parity = point[1] % 2
    if sig > s.SECP_N // 2:
        sig, parity = s.SECP_N - sig, parity ^ 1
    return parity, r, sig


def rlp_bytes(data):
    if len(data) == 1 and data[0] < 0x80:
        return data
    if len(data) < 56:
        return bytes([0x80 + len(data)]) + data
    size = len(data).to_bytes((len(data).bit_length() + 7) // 8, 'big')
    return bytes([0xb7 + len(size)]) + size + data


def eip1559(key, nonce, chain=CHAIN, to=b'\x35' * 20, value=1, gas=21_000, max_fee=2_000_000_000, tip=200_000_000):
    fields = [s.rlp_uint(chain), s.rlp_uint(nonce), s.rlp_uint(tip), s.rlp_uint(max_fee), s.rlp_uint(gas), rlp_bytes(to),
              s.rlp_uint(value), rlp_bytes(b''), s.rlp_list([])]
    parity, r, sig = sign(key, s.keccak256(b'\x02' + s.rlp_list(fields)))
    return b'\x02' + s.rlp_list(fields + [s.rlp_uint(parity), s.rlp_uint(r), s.rlp_uint(sig)])


def legacy(key, nonce, chain=CHAIN, gas_price=2_000_000_000):
    fields = [s.rlp_uint(nonce), s.rlp_uint(gas_price), s.rlp_uint(21_000), rlp_bytes(b'\x35' * 20), s.rlp_uint(1),
              rlp_bytes(b'')]
    parity, r, sig = sign(key, s.keccak256(s.rlp_list(fields + [s.rlp_uint(chain), b'\x80', b'\x80'])))
    return s.rlp_list(fields + [s.rlp_uint(chain * 2 + 35 + parity), s.rlp_uint(r), s.rlp_uint(sig)])


class Recovery(unittest.TestCase):
    def test_the_eip155_example_transaction(self):
        raw = bytes.fromhex(
            'f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195'
            'fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83')
        sender, nonce = s.spooled_sender_nonce(raw)
        self.assertEqual(sender.hex(), '9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f')
        self.assertEqual(nonce, 9)

    def test_signed_types_read_back(self):
        for raw in (eip1559(KEY, 7), legacy(KEY, 7), eip1559(KEY, 300, value=10**30)):
            self.assertEqual(s.spooled_sender_nonce(raw)[0], address(KEY))
        self.assertEqual(s.spooled_sender_nonce(eip1559(KEY, 300))[1], 300)

    def test_what_does_not_read_is_none(self):
        raw = eip1559(KEY, 1)
        for bad in (b'', b'\x00', b'\x03' + raw[1:], raw[:-1], raw + b'\x00', b'\xc0', legacy(KEY, 1)[:-2]):
            self.assertIsNone(s.spooled_sender_nonce(bad), bad.hex())


class IdleDemand(unittest.TestCase):
    """The settler's idle check, as in test_settler_foreign.IdleTest, with a producer that answers `account`."""

    def setUp(self):
        self.idle = foreign.IdleTest('setUp')
        self.idle.setUp()
        self.addCleanup(self.idle.base.tmp.cleanup)
        self.addCleanup(mock.patch.stopall)
        self.nonce, self.accounts, self.refuse = 0, [], False
        world, original = self.idle.world, self.idle.world.run

        def run(argv, **kwargs):
            if Path(argv[0]).name == 'produce' and argv[1] == 'account':
                world.calls.append([str(a) for a in argv])
                self.accounts.append(argv[argv.index('--address') + 1])
                if self.refuse:
                    return types.SimpleNamespace(returncode=2, stdout='', stderr='database busy')
                return types.SimpleNamespace(returncode=0, stderr='', stdout=json.dumps({'nonce': self.nonce}))
            return original(argv, **kwargs)
        world.run = run

    def spool(self, name, raw):
        (self.idle.root / 'txpool' / f'{name}.tx').write_text(raw.hex() + '\n')

    def due_cycles(self, settler, cycles=5):
        due = 0
        for age_slots in range(1, cycles + 1):  # consecutive fresh sources, no deposit, far below max_idle (100 slots)
            self.idle.world.head_slot = 1000 + age_slots
            due += not self.idle.held(settler)
        return due

    def test_a_nonce_gap_entry_does_not_make_blocks_due(self):
        # Agent 121's test (review r7, R5), with the gapped entry really signed: the sender's next nonce is 0.
        settler = self.idle.settler(users=True)
        self.spool('gap', eip1559(KEY, 5))
        due = self.due_cycles(settler)
        self.assertEqual(due, 0, f'{due} of 5 cycles built a block for an entry no block includes')
        self.assertEqual(self.accounts, [address(KEY).hex()], 'one account read per sender and head')

    def test_sixteen_gapped_entries_and_pacing_build_nothing(self):
        settler = self.idle.settler(users=True, min_block_interval_seconds=60)
        for n in range(1, 17):
            self.spool(f'g{n}', eip1559(KEY, n))
        self.assertEqual(self.due_cycles(settler), 0)

    def test_the_next_nonce_is_demand(self):
        settler = self.idle.settler(users=True)
        self.spool('gap', eip1559(KEY, 5))
        self.assertTrue(self.idle.held(settler))
        self.spool('next', legacy(KEY, 0))
        self.assertFalse(self.idle.held(settler))

    def test_the_gap_filled_on_chain_is_demand(self):
        settler = self.idle.settler(users=True)
        self.spool('gap', eip1559(KEY, 5))
        self.assertTrue(self.idle.held(settler))
        self.nonce = 5
        self.idle.world.write(self.idle.root / 'db', [foreign.GENESIS_HASH, 'aa' * 32])
        self.idle.world.accepted = {'statement': foreign.values_for(1, ('aa' * 32, 'ae' * 32)).hex(),
                                    'commitment': foreign.PARENT_COMMITMENT}
        self.assertFalse(self.idle.held(settler), 'a new head must re-read the sender nonce')

    def test_a_used_nonce_is_not_demand(self):
        self.nonce = 9
        settler = self.idle.settler(users=True)
        self.spool('old', eip1559(KEY, 3))
        self.assertTrue(self.idle.held(settler))

    def test_unreadable_bytes_and_an_unknown_nonce_are_demand(self):
        settler = self.idle.settler(users=True)
        self.spool('junk', b'\x00')
        self.assertFalse(self.idle.held(settler))
        (self.idle.root / 'txpool' / 'junk.tx').unlink()
        self.spool('gap', eip1559(KEY, 5))
        self.refuse = True
        self.assertFalse(self.idle.held(settler))
        self.assertTrue(self.idle.base.events('spool-demand-unknown'))

    def test_without_user_transactions_nothing_is_read(self):
        settler = self.idle.settler()
        self.spool('next', eip1559(KEY, 0))
        self.assertTrue(self.idle.held(settler))
        self.assertEqual(self.accounts, [])


if __name__ == '__main__':
    unittest.main()
