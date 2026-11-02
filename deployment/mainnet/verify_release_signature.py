#!/usr/bin/env python3
"""Verify a minisign/rsign signature over a Bloch L2 release SHA256SUMS, with no third-party code.

    verify_release_signature.py --release-dir DIR [--expect-sha256 HEX]
    verify_release_signature.py FILE [--sig FILE.minisig] [--expect-sha256 HEX] [--expect-trusted-comment TEXT]
    verify_release_signature.py --print-trusted-comment DIR

The release key is pinned below (RELEASE_PUBKEY, key ID RELEASE_KEY_ID). --pubkey / --pubkey-file
replace it for rehearsals only and print a REHEARSAL line. The file `SHA256SUMS.minisig` is the
minisign format written by `rsign sign` and `minisign -S`:

    untrusted comment: <free text, not covered by any signature>
    base64( "ED" | key_id[8] | ed25519( BLAKE2b-512(FILE) )[64] )
    trusted comment: <one line>
    base64( ed25519( signature[64] | trusted comment bytes )[64] )

Both Ed25519 signatures must verify against the pinned key. Legacy "Ed" signatures (over the
raw file instead of its BLAKE2b-512 digest) are refused unless --allow-legacy.

--release-dir DIR additionally requires the trusted comment to be the canonical line for that
release (see canonical_trusted_comment), built from DIR/release.json and the SHA-256 of
DIR/SHA256SUMS, and then checks every line of SHA256SUMS against the files in DIR
(`sha256sum -c --strict` semantics: every listed file must exist and match, no extra syntax).

Exit 0 and a final "signature OK" line on success; exit 1 with a reason on any failure.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys

# Bloch release key (the key that signed the bloch-pos node releases 2026-09-22 to 2026-10-29).
# Public key file `bloch-release-20260922.pub`, SHA-256 77a18b65d75508752100bdef83ed09bcf5ec0a203a1b3de1831548b4521ae243.
RELEASE_PUBKEY = 'RWT3XpXEpZZdGtghC5SmyRj2VRTAGUfO5KxBucYVTRfriNE13wsXhfj6'
RELEASE_KEY_ID = '1A5D96A5C4955EF7'
# Revoked or retired keys, by key ID (16 hex digits as printed by minisign). A signature by one of
# these is refused even when it is passed with --pubkey. See docs/RELEASE-SIGNING.md, "Revocation".
REVOKED_KEY_IDS = frozenset()
# Withdrawn signatures, by the SHA-256 of the signed SHA256SUMS: a release the owner signed and then
# withdrew while the key itself stays valid. Refused with any key.
REVOKED_SHA256SUMS = frozenset()

TRUSTED_PREFIX = 'trusted comment: '
UNTRUSTED_PREFIX = 'untrusted comment: '
MAX_SIG_FILE = 4096

# ---- Ed25519 verification (RFC 8032 section 5.1.7, cofactorless, canonical S and point encodings) ----
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    D = 2 * z1 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _equal(a, b):
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 % _P == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def ed25519_verify(public, msg, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    R = _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], 'little')
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + msg).digest(), 'little') % _L
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


# ---- minisign format ----
class VerifyError(Exception):
    pass


def _b64(text, size, what):
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except Exception:
        raise VerifyError(f'{what} is not valid base64')
    if len(raw) != size:
        raise VerifyError(f'{what} has {len(raw)} bytes, expected {size}')
    return raw


def key_id_hex(key_id):
    return key_id[::-1].hex().upper()  # minisign prints the little-endian key number


def parse_pubkey(text):
    lines = [l for l in text.splitlines() if l.strip()]
    if lines and lines[0].startswith(UNTRUSTED_PREFIX):
        lines = lines[1:]
    if len(lines) != 1:
        raise VerifyError('public key must be one base64 line, optionally after an untrusted comment')
    raw = _b64(lines[0], 42, 'public key')
    if raw[:2] != b'Ed':
        raise VerifyError('public key algorithm is not Ed25519')
    return raw[2:10], raw[10:]


def parse_signature(data):
    if len(data) > MAX_SIG_FILE:
        raise VerifyError('signature file too large')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise VerifyError('signature file is not UTF-8')
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines = lines[:-1]
    lines = [l[:-1] if l.endswith('\r') else l for l in lines]
    if len(lines) != 4:
        raise VerifyError(f'signature file has {len(lines)} lines, expected 4')
    if not lines[0].startswith(UNTRUSTED_PREFIX):
        raise VerifyError('line 1 is not an untrusted comment')
    raw = _b64(lines[1], 74, 'signature')
    if not lines[2].startswith(TRUSTED_PREFIX):
        raise VerifyError('line 3 is not a trusted comment')
    trusted = lines[2][len(TRUSTED_PREFIX):]
    global_sig = _b64(lines[3], 64, 'global signature')
    return {'alg': raw[:2], 'key_id': raw[2:10], 'sig': raw[10:], 'trusted': trusted, 'global_sig': global_sig}


def verify_bytes(content, sig_data, pubkey_text, allow_legacy=False):
    """Return the trusted comment if `sig_data` is a valid signature of `content`, else raise."""
    key_id, pk = parse_pubkey(pubkey_text)
    s = parse_signature(sig_data)
    if key_id_hex(s['key_id']) in REVOKED_KEY_IDS or key_id_hex(key_id) in REVOKED_KEY_IDS:
        raise VerifyError(f'key {key_id_hex(s["key_id"])} is revoked')
    if s['key_id'] != key_id:
        raise VerifyError(f'signature key ID {key_id_hex(s["key_id"])} is not the pinned key {key_id_hex(key_id)}')
    if s['alg'] == b'ED':
        msg = hashlib.blake2b(content, digest_size=64).digest()
    elif s['alg'] == b'Ed':
        if not allow_legacy:
            raise VerifyError('legacy (non-prehashed) signature refused; sign with rsign or minisign >= 0.8')
        msg = content
    else:
        raise VerifyError('unknown signature algorithm')
    if not ed25519_verify(pk, msg, s['sig']):
        raise VerifyError('signature does not match the file')
    if not ed25519_verify(pk, s['sig'] + s['trusted'].encode('utf-8'), s['global_sig']):
        raise VerifyError('trusted comment signature is invalid')
    return s['trusted']


def canonical_trusted_comment(release, sums_sha256):
    """The one trusted comment accepted by --release-dir. Everything in it comes from release.json."""
    return ('bloch-l2 release={release} sha256sums={sums} l2_commit={l2} native_commit={native} '
            'chain_id={chain} platform={platform}').format(
        release=release['release'], sums=sums_sha256, l2=release['l2_commit'],
        native=release['native_commit'], chain=release['chain_id'], platform=release['platform'])


_SUM_LINE = re.compile(r'^([0-9a-f]{64}) [ *]([^/\\\x00]+)$')


def check_sums(directory, sums_bytes):
    entries = []
    for n, line in enumerate(sums_bytes.decode('utf-8').splitlines(), 1):
        m = _SUM_LINE.match(line)
        if not m or m.group(2) in ('.', '..'):
            raise VerifyError(f'SHA256SUMS line {n} is malformed')
        entries.append((m.group(1), m.group(2)))
    if not entries:
        raise VerifyError('SHA256SUMS is empty')
    names = [e[1] for e in entries]
    if len(set(names)) != len(names):
        raise VerifyError('SHA256SUMS lists a file twice')
    for want, name in entries:
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            raise VerifyError(f'{name}: listed in SHA256SUMS but missing')
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        if h.hexdigest() != want:
            raise VerifyError(f'{name}: SHA-256 does not match SHA256SUMS')
        print(f'{name}: OK')
    return names


def _read(path, limit=None):
    with open(path, 'rb') as f:
        data = f.read() if limit is None else f.read(limit + 1)
    return data


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('file', nargs='?', help='signed file (default with --release-dir: DIR/SHA256SUMS)')
    ap.add_argument('--release-dir', help='release directory with SHA256SUMS, SHA256SUMS.minisig, release.json')
    ap.add_argument('--sig', help='signature file (default: FILE.minisig)')
    ap.add_argument('--pubkey', help='REHEARSAL ONLY: public key string instead of the pinned release key')
    ap.add_argument('--pubkey-file', help='REHEARSAL ONLY: public key file instead of the pinned release key')
    ap.add_argument('--expect-sha256', help='also require this SHA-256 of the signed file')
    ap.add_argument('--expect-trusted-comment', help='also require exactly this trusted comment')
    ap.add_argument('--allow-legacy', action='store_true', help='accept legacy non-prehashed signatures')
    ap.add_argument('--print-trusted-comment', metavar='DIR',
                    help='print the canonical trusted comment for release DIR (no signature needed) and exit')
    a = ap.parse_args(argv)
    try:
        if a.print_trusted_comment:
            d = a.print_trusted_comment
            sha = hashlib.sha256(_read(os.path.join(d, 'SHA256SUMS'))).hexdigest()
            try:
                release = json.loads(_read(os.path.join(d, 'release.json')).decode('utf-8'))
                print(canonical_trusted_comment(release, sha))
            except (ValueError, KeyError, TypeError) as e:
                raise VerifyError(f'release.json unusable: {e}')
            return 0
        if a.release_dir:
            if a.file:
                raise VerifyError('give either FILE or --release-dir, not both')
            target = os.path.join(a.release_dir, 'SHA256SUMS')
        elif a.file:
            target = a.file
        else:
            raise VerifyError('nothing to verify: give FILE or --release-dir')
        if a.pubkey and a.pubkey_file:
            raise VerifyError('give --pubkey or --pubkey-file, not both')
        if a.pubkey or a.pubkey_file:
            pubkey_text = a.pubkey or _read(a.pubkey_file, 4096).decode('utf-8', 'replace')
            print('REHEARSAL: public key from the command line, not the pinned release key', file=sys.stderr)
        else:
            pubkey_text = RELEASE_PUBKEY
        key_id, _ = parse_pubkey(pubkey_text)
        content = _read(target)
        sig_data = _read(a.sig or target + '.minisig', MAX_SIG_FILE)
        sha = hashlib.sha256(content).hexdigest()
        if sha in REVOKED_SHA256SUMS:
            raise VerifyError(f'release SHA256SUMS {sha} was withdrawn by the owner')
        trusted = verify_bytes(content, sig_data, pubkey_text, a.allow_legacy)
        print(f'key {key_id_hex(key_id)}: signature and trusted comment valid')
        print(f'trusted comment: {trusted}')
        print(f'sha256 {sha}  {os.path.basename(target)}')
        if a.expect_sha256 and sha != a.expect_sha256.strip().lower():
            raise VerifyError(f'{target} has SHA-256 {sha}, expected {a.expect_sha256}')
        if a.expect_trusted_comment is not None and trusted != a.expect_trusted_comment:
            raise VerifyError('trusted comment differs from --expect-trusted-comment')
        if a.release_dir:
            try:
                release = json.loads(_read(os.path.join(a.release_dir, 'release.json')).decode('utf-8'))
                want = canonical_trusted_comment(release, sha)
            except (OSError, ValueError, KeyError, TypeError) as e:
                raise VerifyError(f'release.json unusable: {e}')
            if trusted != want:
                raise VerifyError(f'trusted comment is not the canonical line for this release:\n  want: {want}\n  got:  {trusted}')
            names = check_sums(a.release_dir, content)
            if 'release.json' not in names:
                raise VerifyError('SHA256SUMS does not cover release.json')
        print('signature OK')
        return 0
    except (VerifyError, OSError) as e:
        print(f'verify_release_signature: FAILED: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
