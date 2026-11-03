# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for make_reset_target.py (the reset.json producer, finding G-6).

Pure: no network, no follower binary. A synthetic V3 statement and proof stand in
for a real settlement; the native commitment is cross-checked against a real
rehearsal settlement in test_commitment_matches_real_rehearsal (skipped unless the
fixture file is present). Run: python3 -m pytest deployment/mainnet/test_make_reset_target.py
or python3 deployment/mainnet/test_make_reset_target.py
"""
import importlib.util
import json
from pathlib import Path

try:
    import pytest
except ImportError:  # standard-library fallback so the suite runs without pytest
    import contextlib

    class _Pytest:
        class Skipped(Exception):
            pass

        @staticmethod
        @contextlib.contextmanager
        def raises(exc):
            try:
                yield
            except exc:
                return
            raise AssertionError(f'did not raise {exc.__name__}')

        @staticmethod
        def skip(reason):
            raise _Pytest.Skipped(reason)

        @staticmethod
        def main(argv):
            import inspect
            mod = inspect.getmodule(inspect.currentframe())
            failed = 0
            for name, fn in sorted(vars(mod).items()):
                if name.startswith('test_') and callable(fn):
                    try:
                        fn()
                        print(f'PASS {name}')
                    except _Pytest.Skipped as s:
                        print(f'SKIP {name}: {s}')
                    except Exception as e:  # noqa: BLE001
                        failed += 1
                        print(f'FAIL {name}: {type(e).__name__}: {e}')
            print(f'{"FAIL" if failed else "OK"}: {failed} failed')
            return 1 if failed else 0

    pytest = _Pytest()

_spec = importlib.util.spec_from_file_location('mrt', Path(__file__).with_name('make_reset_target.py'))
mrt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mrt)


def make_statement(number, config=b'\x11' * 32, elf=b'\x22' * 32):
    s = bytearray(mrt.STATEMENT_V3_BYTES)
    s[:len(mrt.STATEMENT_V3_TAG)] = mrt.STATEMENT_V3_TAG
    # identities 0..2 (admission domain, native genesis, L2 domain): arbitrary fixed bytes
    for i, b in enumerate((b'\xa0' * 32, b'\xa1' * 32, b'\xa2' * 32)):
        s[mrt.S + i * 32:mrt.S + i * 32 + 32] = b
    s[mrt.S + mrt.OFF_CONFIG:mrt.S + mrt.OFF_CONFIG + 32] = config
    s[mrt.S + mrt.OFF_ELF:mrt.S + mrt.OFF_ELF + 32] = elf
    s[mrt.S + mrt.OFF_L2_NUMBER:mrt.S + mrt.OFF_L2_NUMBER + 8] = number.to_bytes(8, 'big')
    return bytes(s)


def make_tx(number, proof_policy=b'\x33' * 32, proof=b'\x44' * mrt.PROOF_BYTES, **kw):
    statement = make_statement(number, **kw)
    raw = bytes([mrt.ASYNC_WIRE_TAG]) + proof_policy + statement + proof
    assert len(raw) == mrt.TRANSACTION_V3_BYTES
    return raw, proof_policy, statement, proof


def follower_entry(number, commitment, **over):
    e = {'l2_number': number, 'l2_hash': 'aa' * 32, 'l2_state_root': 'bb' * 32,
         'commitment': commitment, 'configuration': '11' * 32,
         'native_block': 'cc' * 32, 'native_slot': 4096}
    e.update(over)
    return e


def test_decode_round_trips():
    raw, policy, statement, proof = make_tx(7)
    assert mrt.decode_settlement_tx(raw) == (policy, statement, proof)
    assert mrt.statement_l2_number(statement) == 7


def test_decode_rejects_wrong_tag_and_length():
    raw, *_ = make_tx(7)
    assert mrt.decode_settlement_tx(raw[:-1]) is None            # short
    assert mrt.decode_settlement_tx(bytes([0x12]) + raw[1:]) is None  # wrong wire tag


def test_find_settlement_picks_the_named_block():
    raw5, *_ = make_tx(5)
    raw6, p6, s6, pr6 = make_tx(6)
    txs = ['00' * 10, raw5.hex(), raw6.hex()]
    assert mrt.find_settlement(txs, 6) == (p6, s6, pr6)
    assert mrt.find_settlement(txs, 9) is None


def test_build_ok():
    raw, policy, statement, proof = make_tx(42)
    commitment = mrt.settlement_commitment(policy, statement, proof).hex()
    followers = [follower_entry(42, commitment), follower_entry(42, commitment)]
    reset = mrt.build(42, followers, [raw.hex()], expect_config='11' * 32, expect_elf='22' * 32)
    assert reset == {'number': 42, 'commitment': commitment, 'statement': statement.hex()}
    # round-trips through JSON exactly as arm.py reads it
    assert json.loads(json.dumps(reset))['statement'] == statement.hex()


def test_build_genesis_needs_no_lookup():
    assert mrt.build(0, []) == {'number': 0, 'commitment': '0' * 64, 'statement': None}


def test_build_rejects_follower_disagreement():
    raw, policy, statement, proof = make_tx(42)
    commitment = mrt.settlement_commitment(policy, statement, proof).hex()
    followers = [follower_entry(42, commitment), follower_entry(42, commitment, l2_hash='ff' * 32)]
    with pytest.raises(SystemExit):
        mrt.build(42, followers, [raw.hex()])


def test_build_rejects_commitment_mismatch():
    """The L1 block carries a different settlement than the followers logged."""
    raw, policy, statement, proof = make_tx(42)
    wrong_commitment = 'de' * 32
    followers = [follower_entry(42, wrong_commitment), follower_entry(42, wrong_commitment)]
    with pytest.raises(SystemExit):
        mrt.build(42, followers, [raw.hex()])


def test_build_rejects_missing_settlement_in_block():
    raw, policy, statement, proof = make_tx(41)   # block 41, not 42
    commitment = mrt.settlement_commitment(policy, statement, proof).hex()
    followers = [follower_entry(42, commitment), follower_entry(42, commitment)]
    with pytest.raises(SystemExit):
        mrt.build(42, followers, [raw.hex()])


def test_build_rejects_wrong_program_pins():
    raw, policy, statement, proof = make_tx(42, config=b'\x99' * 32)
    commitment = mrt.settlement_commitment(policy, statement, proof).hex()
    followers = [follower_entry(42, commitment), follower_entry(42, commitment)]
    with pytest.raises(SystemExit):
        mrt.build(42, followers, [raw.hex()], expect_config='11' * 32)


def test_commitment_matches_real_rehearsal():
    """Cross-check the native commitment against a real settled block if the fixture
    (one JSON {proof_policy, statement, proof, commitment} from a follower log + L1 block)
    is present. Written by the host step; skipped otherwise."""
    fixture = Path(__file__).with_name('reset-target-fixture.json')
    if not fixture.exists():
        pytest.skip('no real-rehearsal fixture present')
    data = json.loads(fixture.read_text())
    got = mrt.settlement_commitment(bytes.fromhex(data['proof_policy']),
                                    bytes.fromhex(data['statement']),
                                    bytes.fromhex(data['proof'])).hex()
    assert got == data['commitment']


if __name__ == '__main__':
    import sys
    sys.exit(pytest.main([__file__, '-q']))
