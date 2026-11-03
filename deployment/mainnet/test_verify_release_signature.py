#!/usr/bin/env python3
"""Tests for verify_release_signature.py: real signatures by the pinned release key, an rsign
rehearsal signature, and signatures made here with throwaway keys (a minimal Ed25519 signer)."""
import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import verify_release_signature as v  # noqa: E402

DATA = HERE / 'testdata' / 'release-signature'
SCRIPT = HERE / 'verify_release_signature.py'


# ---- throwaway Ed25519 signer, test only ----
def _compress(pt):
    x, y, z, _ = pt
    zi = pow(z, v._P - 2, v._P)
    x, y = x * zi % v._P, y * zi % v._P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


class Key:
    def __init__(self, seed, key_id=None):
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], 'little')
        a &= (1 << 254) - 8
        a |= 1 << 254
        self.a, self.prefix = a, h[32:]
        self.pk = _compress(v._mul(a, v._G))
        self.key_id = key_id or hashlib.sha256(seed).digest()[:8]

    def sign(self, msg):
        r = int.from_bytes(hashlib.sha512(self.prefix + msg).digest(), 'little') % v._L
        R = _compress(v._mul(r, v._G))
        k = int.from_bytes(hashlib.sha512(R + self.pk + msg).digest(), 'little') % v._L
        return R + ((r + k * self.a) % v._L).to_bytes(32, 'little')

    def pubkey(self):
        return 'untrusted comment: throwaway test key\n' + base64.b64encode(b'Ed' + self.key_id + self.pk).decode() + '\n'

    def minisig(self, content, trusted, legacy=False, sig_override=None, key_id=None, global_override=None):
        msg = content if legacy else hashlib.blake2b(content, digest_size=64).digest()
        sig = sig_override or self.sign(msg)
        glob = global_override or self.sign(sig + trusted.encode())
        alg = b'Ed' if legacy else b'ED'
        return ('untrusted comment: test\n' + base64.b64encode(alg + (key_id or self.key_id) + sig).decode() + '\n'
                + 'trusted comment: ' + trusted + '\n' + base64.b64encode(glob).decode() + '\n').encode()


def run_main(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = v.main([str(a) for a in args])
    return rc, out.getvalue(), err.getvalue()


class Ed25519(unittest.TestCase):
    def test_rfc8032_test1_derived_key(self):
        # RFC 8032 7.1 TEST 1 secret key; public key must match the RFC value.
        k = Key(bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))
        self.assertEqual(k.pk.hex(), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        sig = k.sign(b'')
        self.assertEqual(sig.hex(), 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065'
                                    '224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        self.assertTrue(v.ed25519_verify(k.pk, b'', sig))
        self.assertFalse(v.ed25519_verify(k.pk, b'x', sig))

    def test_malleated_s_refused(self):
        k = Key(b'malleate')
        sig = k.sign(b'm')
        s = int.from_bytes(sig[32:], 'little') + v._L
        self.assertLess(s, 1 << 256)
        self.assertFalse(v.ed25519_verify(k.pk, b'm', sig[:32] + s.to_bytes(32, 'little')))

    def test_bad_point_refused(self):
        k = Key(b'point')
        sig = k.sign(b'm')
        self.assertFalse(v.ed25519_verify(b'\xff' * 32, b'm', sig))
        self.assertFalse(v.ed25519_verify(k.pk, b'm', b'\xff' * 32 + sig[32:]))
        self.assertFalse(v.ed25519_verify(k.pk[:31], b'm', sig))


class RealSignatures(unittest.TestCase):
    def test_pinned_key_file_matches_constant(self):
        text = (DATA / 'bloch-release-20260922.pub').read_text()
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),
                         '77a18b65d75508752100bdef83ed09bcf5ec0a203a1b3de1831548b4521ae243')
        self.assertEqual(text.splitlines()[1], v.RELEASE_PUBKEY)
        key_id, _ = v.parse_pubkey(v.RELEASE_PUBKEY)
        self.assertEqual(v.key_id_hex(key_id), v.RELEASE_KEY_ID)

    def test_node_release_hf123_verifies_with_pinned_key(self):
        rc, out, err = run_main(DATA / 'node-hf123' / 'SHA256SUMS', '--expect-sha256',
                                '58c797ba7366ad851e73a9c1013cc4dbc46ecb340cfd83d04733882a3fa011ae')
        self.assertEqual(rc, 0, err)
        self.assertIn('trusted comment: bloch-pos hf123 armed 78d4921c E1 7180 E2 7270 E3 7360 KES 8620', out)
        self.assertIn('signature OK', out)

    def test_node_release_tampered_byte_refused(self):
        with tempfile.TemporaryDirectory() as t:
            content = bytearray((DATA / 'node-hf123' / 'SHA256SUMS').read_bytes())
            content[0] ^= 1
            (Path(t) / 'SHA256SUMS').write_bytes(bytes(content))
            shutil.copy(DATA / 'node-hf123' / 'SHA256SUMS.minisig', t)
            rc, _, err = run_main(Path(t) / 'SHA256SUMS')
            self.assertEqual(rc, 1)
            self.assertIn('signature does not match the file', err)

    def test_node_release_is_not_an_l2_release(self):
        # A genuine node-release signature must not pass --release-dir: wrong trusted comment.
        with tempfile.TemporaryDirectory() as t:
            shutil.copy(DATA / 'node-hf123' / 'SHA256SUMS', t)
            shutil.copy(DATA / 'node-hf123' / 'SHA256SUMS.minisig', t)
            (Path(t) / 'release.json').write_text(json.dumps({
                'release': 'x', 'l2_commit': 'a', 'native_commit': 'b', 'chain_id': 700770, 'platform': 'linux-x86_64'}))
            rc, _, err = run_main('--release-dir', t)
            self.assertEqual(rc, 1)
            self.assertIn('not the canonical line', err)

    def test_rsign_rehearsal_release_dir(self):
        d = DATA / 'rsign-rehearsal'
        rc, out, err = run_main('--release-dir', d, '--pubkey-file', d / 'throwaway.pub')
        self.assertEqual(rc, 0, err)
        self.assertIn('REHEARSAL', err)
        self.assertIn('dummy-bin: OK', out)
        rc, _, err = run_main('--release-dir', d)
        self.assertEqual(rc, 1)
        self.assertIn('is not the pinned key 1A5D96A5C4955EF7', err)


class Crafted(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.key = Key(b'throwaway release key')
        self.pub = self.d / 'k.pub'
        self.pub.write_text(self.key.pubkey())
        (self.d / 'bin-a').write_bytes(b'binary a\n')
        self.release = {'release': 'bloch-l2-test', 'chain_id': 700770, 'l2_commit': 'c' * 40,
                        'native_commit': 'd' * 40, 'platform': 'linux-x86_64'}
        (self.d / 'release.json').write_text(json.dumps(self.release))
        self.write_sums()

    def tearDown(self):
        self.tmp.cleanup()

    def write_sums(self, text=None):
        if text is None:
            text = ''.join(f'{hashlib.sha256((self.d / n).read_bytes()).hexdigest()}  {n}\n' for n in ('bin-a', 'release.json'))
        (self.d / 'SHA256SUMS').write_text(text)
        self.sums = (self.d / 'SHA256SUMS').read_bytes()

    def canonical(self):
        return v.canonical_trusted_comment(self.release, hashlib.sha256(self.sums).hexdigest())

    def sign(self, trusted=None, **kw):
        (self.d / 'SHA256SUMS.minisig').write_bytes(self.key.minisig(self.sums, trusted or self.canonical(), **kw))

    def verify(self, *extra):
        return run_main('--release-dir', self.d, '--pubkey-file', self.pub, *extra)

    def test_valid(self):
        self.sign()
        rc, out, err = self.verify('--expect-sha256', hashlib.sha256(self.sums).hexdigest())
        self.assertEqual(rc, 0, err)
        self.assertIn('bin-a: OK', out)

    def test_print_trusted_comment_matches(self):
        rc, out, _ = run_main('--print-trusted-comment', self.d)
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), self.canonical())

    def test_expect_sha256_mismatch(self):
        self.sign()
        rc, _, err = self.verify('--expect-sha256', '0' * 64)
        self.assertEqual(rc, 1)
        self.assertIn('expected', err)

    def test_wrong_trusted_comment_validly_signed(self):
        self.sign(trusted=self.canonical().replace('release=bloch-l2-test', 'release=bloch-l2-other'))
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('not the canonical line', err)

    def test_trusted_comment_edited_after_signing(self):
        self.sign()
        p = self.d / 'SHA256SUMS.minisig'
        p.write_bytes(p.read_bytes().replace(b'chain_id=700770', b'chain_id=700771'))
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('trusted comment signature is invalid', err)

    def test_global_signature_corrupt(self):
        self.sign(global_override=b'\x01' * 64)
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)

    def test_file_signature_by_other_key_same_key_id(self):
        other = Key(b'attacker', key_id=self.key.key_id)
        (self.d / 'SHA256SUMS.minisig').write_bytes(other.minisig(self.sums, self.canonical()))
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('signature does not match the file', err)

    def test_key_id_mismatch(self):
        self.sign(key_id=b'\x00' * 8)
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('is not the pinned key', err)

    def test_legacy_refused_then_allowed(self):
        self.sign(legacy=True)
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('legacy', err)
        rc, _, err = self.verify('--allow-legacy')
        self.assertEqual(rc, 0, err)

    def test_binary_swapped_after_signing(self):
        self.sign()
        (self.d / 'bin-a').write_bytes(b'binary b\n')
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('bin-a: SHA-256 does not match', err)

    def test_listed_file_missing(self):
        self.sign()
        (self.d / 'bin-a').unlink()
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('missing', err)

    def test_release_json_not_covered(self):
        self.write_sums(f'{hashlib.sha256(b"binary a" + bytes([10])).hexdigest()}  bin-a\n')
        self.sign()
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('does not cover release.json', err)

    def test_path_escape_refused(self):
        self.write_sums('0' * 64 + '  ../etc/passwd\n')
        self.sign()
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('malformed', err)

    def test_duplicate_line_refused(self):
        h = hashlib.sha256((self.d / 'bin-a').read_bytes()).hexdigest()
        self.write_sums(f'{h}  bin-a\n{h}  bin-a\n')
        self.sign()
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('twice', err)

    def test_truncated_signature_file(self):
        self.sign()
        p = self.d / 'SHA256SUMS.minisig'
        p.write_bytes(b'\n'.join(p.read_bytes().split(b'\n')[:3]) + b'\n')
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('expected 4', err)

    def test_missing_signature_file(self):
        rc, _, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn('SHA256SUMS.minisig', err)

    def test_revoked_key_refused(self):
        self.sign()
        revoked = v.key_id_hex(self.key.key_id)
        old = v.REVOKED_KEY_IDS
        v.REVOKED_KEY_IDS = frozenset({revoked})
        try:
            rc, _, err = self.verify()
        finally:
            v.REVOKED_KEY_IDS = old
        self.assertEqual(rc, 1)
        self.assertIn('revoked', err)

    def test_withdrawn_release_refused(self):
        self.sign()
        old = v.REVOKED_SHA256SUMS
        v.REVOKED_SHA256SUMS = frozenset({hashlib.sha256(self.sums).hexdigest()})
        try:
            rc, _, err = self.verify()
        finally:
            v.REVOKED_SHA256SUMS = old
        self.assertEqual(rc, 1)
        self.assertIn('withdrawn', err)

    @unittest.skipUnless(shutil.which('rsign'), 'rsign not installed')
    def test_rsign_accepts_python_made_signature(self):
        self.sign()
        done = subprocess.run(['rsign', 'verify', '-p', str(self.pub), '-x', str(self.d / 'SHA256SUMS.minisig'),
                               str(self.d / 'SHA256SUMS')], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(self.canonical(), done.stdout + done.stderr)

    def test_cli_isolated_mode(self):
        self.sign()
        done = subprocess.run([sys.executable, '-I', str(SCRIPT), '--release-dir', str(self.d), '--pubkey-file', str(self.pub)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(done.stdout.rstrip().endswith('signature OK'))


if __name__ == '__main__':
    unittest.main()
