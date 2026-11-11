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


IDS = ('a0' * 32, 'a1' * 32, 'a2' * 32)   # the synthetic network of make_statement
PINS = dict(expect_config='11' * 32, expect_elf='22' * 32, forfeit=True, identities=IDS)


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
    reset = mrt.build(42, followers, [raw.hex()], **PINS)
    assert reset == {'number': 42, 'commitment': commitment, 'statement': statement.hex(), 'forfeit': True}
    assert mrt.build(42, followers, [raw.hex()], **dict(PINS, forfeit=False))['forfeit'] is False
    # round-trips through JSON exactly as arm.py reads it
    assert json.loads(json.dumps(reset))['statement'] == statement.hex()


def test_build_genesis_needs_no_lookup():
    assert mrt.build(0, [], forfeit=False) == {'number': 0, 'commitment': '0' * 64, 'statement': None, 'forfeit': False}
    with pytest.raises(SystemExit):
        mrt.build(0, [])


def test_build_rejects_follower_disagreement():
    raw, policy, statement, proof = make_tx(42)
    commitment = mrt.settlement_commitment(policy, statement, proof).hex()
    followers = [follower_entry(42, commitment), follower_entry(42, commitment, l2_hash='ff' * 32)]
    with pytest.raises(SystemExit):
        mrt.build(42, followers, [raw.hex()], **PINS)
    assert mrt.build(42, followers[:1] * 2, [raw.hex()], **PINS)['number'] == 42


def test_build_rejects_commitment_mismatch():
    """The L1 block carries a different settlement than the followers logged."""
    raw, policy, statement, proof = make_tx(42)
    wrong_commitment = 'de' * 32
    followers = [follower_entry(42, wrong_commitment), follower_entry(42, wrong_commitment)]
    with pytest.raises(SystemExit):
        mrt.build(42, followers, [raw.hex()], **PINS)


def test_build_rejects_missing_settlement_in_block():
    raw, policy, statement, proof = make_tx(41)   # block 41, not 42
    commitment = mrt.settlement_commitment(policy, statement, proof).hex()
    followers = [follower_entry(42, commitment), follower_entry(42, commitment)]
    with pytest.raises(SystemExit):
        mrt.build(42, followers, [raw.hex()], **PINS)


def test_build_rejects_wrong_program_pins():
    raw, policy, statement, proof = make_tx(42, config=b'\x99' * 32)
    commitment = mrt.settlement_commitment(policy, statement, proof).hex()
    followers = [follower_entry(42, commitment), follower_entry(42, commitment)]
    with pytest.raises(SystemExit):
        mrt.build(42, followers, [raw.hex()], **PINS)
    assert mrt.build(42, [dict(f, configuration='99' * 32) for f in followers], [raw.hex()],
                     **dict(PINS, expect_config='99' * 32))['number'] == 42


def refusal(*args, **kw):
    try:
        mrt.build(*args, **kw)
    except SystemExit as stop:
        return str(stop.code)
    return None


def test_every_pin_and_the_reset_form_are_required():
    """R308-9: no pin is optional and the reset form is never defaulted."""
    raw, policy, statement, proof = make_tx(42)
    commitment = mrt.settlement_commitment(policy, statement, proof).hex()
    followers = [follower_entry(42, commitment), follower_entry(42, commitment)]
    assert refusal(42, followers, [raw.hex()], **PINS) is None
    for drop, word in (('expect_config', 'expect-program-config'), ('expect_elf', 'expect-program-elf'),
                       ('forfeit', 'reset form')):
        kw = {k: v for k, v in PINS.items() if k != drop}
        assert word in (refusal(42, followers, [raw.hex()], **kw) or ''), drop
    for bad in (dict(expect_config='11' * 31), dict(expect_elf='zz' * 32), dict(forfeit='true'), dict(forfeit=1),
                dict(identities=IDS[:2]), dict(identities=('', '', ''))):
        assert refusal(42, followers, [raw.hex()], **dict(PINS, **bad)), bad
    assert 'expected active program' in refusal(42, followers, [raw.hex()], **dict(PINS, expect_elf='23' * 32))


def test_the_network_identities_default_to_mainnet_and_are_compared():
    raw, policy, statement, proof = make_tx(42)
    commitment = mrt.settlement_commitment(policy, statement, proof).hex()
    followers = [follower_entry(42, commitment), follower_entry(42, commitment)]
    no_ids = {k: v for k, v in PINS.items() if k != 'identities'}
    assert 'another network' in refusal(42, followers, [raw.hex()], **no_ids)
    for i, name in enumerate(mrt.IDENTITY_NAMES):
        other = list(IDS)
        other[i] = 'ee' * 32
        assert name in refusal(42, followers, [raw.hex()], **dict(PINS, identities=tuple(other)))
    # the built-in identities are the settler's mainnet pins
    settler = (Path(__file__).resolve().parents[1] / 'devnet' / 'settler_v3.py').read_text()
    block = settler.split('MAINNET = {', 1)[1].split('}', 1)[0]
    for key, value in zip(('network', 'genesis', 'l2_domain'), mrt.MAINNET_IDENTITIES):
        assert f"'{key}': '{value}'" in block, key


def test_the_follower_configuration_must_be_the_statement_s():
    raw, policy, statement, proof = make_tx(42)
    commitment = mrt.settlement_commitment(policy, statement, proof).hex()
    followers = [follower_entry(42, commitment, configuration='12' * 32)] * 2
    assert 'logged configuration' in refusal(42, followers, [raw.hex()], **PINS)


def _files(tmp, name, entries, log=True, recent=None):
    status = {'host': name}
    if log:
        (tmp / f'{name}.settlements.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in entries))
        status['settlement_log'] = {'file': f'{name}.settlements.jsonl'}
    else:
        status['finalized_settlements'] = entries
    if recent is not None:
        status['finalized_settlements_recent'] = recent
    (tmp / f'{name}.json').write_text(json.dumps(status))
    return str(tmp / f'{name}.json')


def _run_main(*argv):
    import contextlib as ctx
    import io
    import sys
    old, out, err = sys.argv, io.StringIO(), io.StringIO()
    sys.argv = ['make_reset_target.py', *map(str, argv)]
    try:
        with ctx.redirect_stdout(out), ctx.redirect_stderr(err):
            try:
                mrt.main()
                code = 0
            except SystemExit as stop:
                code = stop.code
    finally:
        sys.argv = old
    return code, out.getvalue(), err.getvalue()


def test_main_end_to_end_and_its_refusals():
    """The command line: required flags, two distinct followers, the forfeit key, the truthful notes."""
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        raw, policy, statement, proof = make_tx(42)
        e = follower_entry(42, mrt.settlement_commitment(policy, statement, proof).hex())
        a, b = _files(tmp, 'a', [e]), _files(tmp, 'b', [e])
        (tmp / 'block.hex').write_text(raw.hex() + '\n')
        base = ['--number', 42, '--l1-block-hex', tmp / 'block.hex', '--rehearsal-identities', *IDS]
        pins = ['--expect-program-config', '11' * 32, '--expect-program-elf', '22' * 32]
        two = ['--follower-status', a, '--follower-status', b]
        code, out, err = _run_main(*base, *pins, *two, '--reset-form', 'forfeit', '--out', tmp / 'reset.json')
        assert code == 0, err
        assert json.loads(out) == json.loads((tmp / 'reset.json').read_text())
        assert json.loads(out) == {'number': 42, 'commitment': e['commitment'], 'statement': statement.hex(), 'forfeit': True}
        assert 'FORFEIT' in err and 'not refused by the depth' in err and 'NOT for mainnet' in err and 'NOT checked here' in err
        code, out, err = _run_main(*base, *pins, *two, '--reset-form', 'plain')
        assert code == 0 and json.loads(out)['forfeit'] is False and 'PLAIN' in err
        # refusals: no form, no pins, mainnet identities (the default) on a synthetic statement
        assert _run_main(*base, *pins, *two)[0] not in (0, None)
        assert 'expect-program-config' in str(_run_main(*base, *two, '--reset-form', 'forfeit')[0])
        assert 'expect-program-elf' in str(_run_main(*base, *pins[:2], *two, '--reset-form', 'forfeit')[0])
        assert 'another network' in str(_run_main(*base[:4], *pins, *two, '--reset-form', 'forfeit')[0])
        assert 'drop the flag' in str(_run_main(*base[:4], '--rehearsal-identities', *mrt.MAINNET_IDENTITIES, *pins, *two,
                                                '--reset-form', 'forfeit')[0])
        # one follower presented as two: same path, a symbolic link, a hard link, a byte copy, one log behind two files
        os.symlink(a, tmp / 'link.json')
        os.link(a, tmp / 'hard.json')
        (tmp / 'copy.json').write_bytes(Path(a).read_bytes())
        (tmp / 'c.json').write_text(json.dumps({'host': 'c', 'settlement_log': {'file': 'a.settlements.jsonl'}}))
        for second, word in ((a, 'same file'), (tmp / 'link.json', 'same file'), (tmp / 'hard.json', 'same file'),
                             (tmp / 'copy.json', 'same bytes'), (tmp / 'c.json', 'same settlement log')):
            code, _, _ = _run_main(*base, *pins, '--follower-status', a, '--follower-status', second, '--reset-form', 'forfeit')
            assert word in str(code), (second, code)
        assert not (tmp / 'reset.json.tmp').exists()


def test_several_log_lines_for_one_block():
    """R308-9: the newest line wins, only if it is the newest by L1 slot; identical repeats are one line."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        old = follower_entry(50, '01' * 32, l2_hash='01' * 32, native_slot=100)
        new = follower_entry(50, '02' * 32, l2_hash='02' * 32, native_slot=200)
        notes = []
        assert mrt.load_follower(_files(tmp, 'a', [old, follower_entry(51, '03' * 32), new]), 50, notes.append) == new
        assert len(notes) == 1 and '2 times' in notes[0] and 'L1 slot 200' in notes[0]
        notes.clear()
        assert mrt.load_follower(_files(tmp, 'b', [new, new]), 50, notes.append) == new and notes == []
        assert mrt.load_follower(_files(tmp, 'c', [old, new], recent=[new]), 50, notes.append) == new
        assert mrt.load_follower(_files(tmp, 'd', [], recent=[new]), 50, notes.append) == new
        assert mrt.load_follower(_files(tmp, 'e', [old], log=False), 50, notes.append) == old
        for name, entries, recent in (('f', [new, old], None),                       # last line is not the newest
                                      ('g', [old, dict(new, native_slot=100)], None),  # same slot twice
                                      ('h', [old, dict(new, native_slot=None)], None),
                                      ('i', [old, new], [old]),                       # recent disagrees with the newest
                                      ('j', [follower_entry(51, '03' * 32)], None)):  # no line at all
            with pytest.raises(SystemExit):
                mrt.load_follower(_files(tmp, name, entries, recent=recent), 50, notes.append)


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


def load_tests(loader, tests, pattern):
    """`python3 -m unittest discover` runs these plain test functions too."""
    import unittest
    suite = unittest.TestSuite()
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            suite.addTest(unittest.FunctionTestCase(fn, description=name))
    return suite


if __name__ == '__main__':
    import sys
    sys.exit(pytest.main([__file__, '-q']))
