#!/usr/bin/env python3
"""Set the fee-sweep recipient of the next L2 rules (chain 700770) in one pass, and list what must be rebuilt.

The recipient (`MAINNET_FEE_SWEEP_RECIPIENT`, src/chainspec.rs) is compiled into the next rule set: it is
part of the configuration commitment (`BLOCH:EVM:CONFIG:3:CANCUN`, identity 3), so the next guest ELFs, their
verifying keys, the native `PROGRAM_NEXT` / `PROGRAM_FALLBACK` pins and every kit pin derived from them move
with it. This script edits the two source trees; it never builds, proves, signs or touches a network
(except `onchain`, which only reads one RPC the operator names).

Release gate (agent 163 B-1, agent 217): the L2 tree ships with `MAINNET_FEE_SWEEP_RECIPIENT = None`. Until it
holds a release address, no next-rules guest compiles, `ChainSpec::mainnet()` is invalid, and build-release.sh and
both guest build-container.sh scripts refuse the fork build (they call `gate`).

The owner's one command (phase 1; validates, optionally reads the Safe on L2, edits both trees, re-checks the gate
and commits both trees so the container builds can take the commit):

  set      ADDRESS --l2 T --native N (--rpc URL | --confirm ADDRESS) [--allow-codeless] [--no-commit] [--dry-run]

ADDRESS is always the EIP-55 mixed-case checksum form with its 0x prefix (R308-4): an all-lowercase, all-uppercase or
prefix-less value carries no checksum and is refused, as is every burn or patterned (keyless) address. `set` also
wants proof that the address is the intended one: `--rpc URL` (the address already holds code on the L2 at
`finalized`), or the address typed a second time (`--confirm ADDRESS`, or at the prompt on a terminal). A
counterfactual address (`--rpc URL --allow-codeless`) needs the second typing too.

Steps (each refuses to run on a tree it does not recognise, and is idempotent):

  gate     --l2 T | --chainspec FILE    exit 0 only if the tree carries a release recipient, with its EIP-55
                                        form in the doc line `apply` writes (used by the build scripts)
  check    ADDRESS                      validate the address, print the new configuration commitment
  apply    ADDRESS --l2 T --native N    phase 1: the recipient constant, the rehearsal constants and the
                                        configuration commitment in both trees
  pins     --l2 T --native N --sparse-identity F --sparse-elf F --complete-identity F --complete-elf F
                                        phase 2, after the pinned-container builds: the ELF SHA-256, ELF
                                        Keccak and both verifying-key hashes of the sparse (PROGRAM_NEXT) and
                                        complete (PROGRAM_FALLBACK) guests in both trees
  native-commit --l2 T --native N       phase 3, after committing the native tree: build-release.sh's
                                        CANDIDATE_NATIVE_COMMIT, refusing if the native lock inputs changed
  audit    --l2 T --native N            list every leftover old value, and the rebuild list
  onchain  ADDRESS --rpc URL            read-only: code, and for a Safe its owners and threshold, at `finalized`

Dependency-free Python 3.9+ (Keccak-256 is implemented here and checked against the known commitments). The
next configuration includes the base-fee floor (`MAINNET_MIN_BASE_FEE`, agent 197), read from src/chainspec.rs.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------------------------- Keccak-256
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _M if n else v


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    p = bytearray(data) + b'\x01'
    while len(p) % rate:
        p += b'\x00'
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(p[off + 8 * i: off + 8 * i + 8], 'little')
        a = _keccak_f(a)
    return b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


# ------------------------------------------------------------------------------- configuration commitment
# ChainSpec::mainnet_v1() (= testnet_v3 under chain 700770) and the next-rule fields of ChainSpec::mainnet().
# `apply` refuses to edit unless these reproduce the commitments pinned in the tree (activated 8ec1c804... and
# the candidate's next configuration for the recipient currently in chainspec.rs), so a drift of any knob here
# stops the script instead of producing a wrong pin.
CHAIN_ID = 700770
U64_KNOBS = (CHAIN_ID, 30_000_000, 2, 2, 250, 1_000_000_000)  # chain id, gas limit, block time, elasticity, denominator, initial base fee
VAULTS_ETC = ('4200000000000000000000000000000000000019', '4200000000000000000000000000000000000011',
              '4200000000000000000000000000000000000100', '4200000000000000000000000000000000000101')
MAX_L1_SATS, DEPOSIT_GAS = 100_000_000_000 * 100_000_000, 21_000
OUTBOX, MIN_WITHDRAWAL_SATS = '4200000000000000000000000000000000000102', 1_000_000
GENESIS_TIME, SLOT_MS, PREVRANDAO = 1_786_656_679, 30_000, bytes([7]) * 32
ACTIVATED_CONFIGURATION = '8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b'
PROOF_POLICY = '154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d'
L2_DOMAIN = '1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733'
# Addresses the recipient must never be: the system accounts ChainSpec::validate refuses to collide with,
# and the EIP-4788 contract.
SYSTEM = {a: n for a, n in (
    ('4200000000000000000000000000000000000019', 'base-fee vault'),
    ('4200000000000000000000000000000000000011', 'sequencer fee vault (COINBASE)'),
    ('4200000000000000000000000000000000000100', 'supply ledger'),
    ('4200000000000000000000000000000000000101', 'block info'),
    ('4200000000000000000000000000000000000102', 'withdrawal outbox'),
    ('000f3df6d732807ef1319fb7b8bb8522d0beac02', 'EIP-4788 beacon roots'),
)}
BURN = {'0000000000000000000000000000000000000000', '000000000000000000000000000000000000dead',
        'dead000000000000000000000000000000000000', 'deaddeaddeaddeaddeaddeaddeaddeaddeaddead'}


# The candidate pins of d462647 / f12b4113 were built before the floor (agent 197) and with the placeholder.
LEGACY_PLACEHOLDER_CONFIGURATION = '975ec2585246abeaea86421dd5726918b632dd91a246f635fe74990b68bcd878'
PLACEHOLDER = '00000000000000000000000000000000000fee01'
# configuration_commitment(ChainSpec::mainnet_rehearsal()) with the 0.1 gwei floor; pinned on the Rust side by
# chainspec::tests::rehearsal_configuration_matches_the_sweep_script.
REHEARSAL_CONFIGURATION = '9d06fe0c95e743c08d482e6460831071f7be6288ce0fd8c05a769a0fa8518764'
# With L1 forced inclusion in the next rules (agents 122/137/215/216; `forced_inclusion: true` in
# ChainSpec::mainnet, core feature `forced-inclusion`) the commitment is `BLOCH:EVM:CONFIG:4:CANCUN`: the version 3
# fields, the floor, then the forced bounds of src/forced_inclusion.rs. The guests of the next rules (sparse and the
# 216 fallback) are built with that feature, so their configuration is the version 4 value.
FORCED_BOUND_NAMES = ('MAX_PER_SETTLEMENT', 'MIN_GAS', 'MAX_GAS', 'MAX_GAS_PER_SETTLEMENT', 'MAX_ENVELOPE_BYTES')
FORCED_BOUNDS = (16, 21_000, 300_000, 300_000, 8 * 1024)
FORCED_FILE = 'src/forced_inclusion.rs'
# The forced candidate pins of agent 137 (placeholder, no floor) and the forced rehearsal value (floor 0.1 gwei).
LEGACY_PLACEHOLDER_CONFIGURATION_FORCED = 'b4663ab88607a1ebf7d1801920365fdde276889e211e097011bf48fcd0f7a29d'
REHEARSAL_CONFIGURATION_FORCED = '50ccc8c9f20a7396ac9c9c5e44e9f80ffece8a26dc0c2dc0127fcf88d5fe27b4'


def configuration_commitment(recipient=None, min_base_fee=0, forced=False):
    """`proof_statement::configuration_commitment` of mainnet_v1 (recipient None) or of mainnet() with that
    recipient and floor. A floor of 0 gives the layout before agent 197's floor (the legacy candidate pins)."""
    be = lambda v, n=8: v.to_bytes(n, 'big')  # noqa: E731
    if forced and not recipient:
        raise ValueError('forced inclusion exists only under the next rules')
    out = (b'BLOCH:EVM:CONFIG:4:CANCUN' if forced else b'BLOCH:EVM:CONFIG:3:CANCUN' if recipient
           else b'BLOCH:EVM:CONFIG:2:CANCUN')
    out += b''.join(be(v) for v in U64_KNOBS) + be(0, 32)
    out += b''.join(bytes.fromhex(a) for a in VAULTS_ETC) + be(MAX_L1_SATS) + be(DEPOSIT_GAS)
    out += bytes.fromhex(OUTBOX) + be(MIN_WITHDRAWAL_SATS)
    if recipient:
        out += be(GENESIS_TIME) + be(SLOT_MS) + PREVRANDAO + bytes.fromhex(recipient)
        if min_base_fee:
            out += be(min_base_fee)
    elif min_base_fee:
        raise ValueError('a base-fee floor exists only under the next rules')
    if forced:
        out += b''.join(be(v) for v in FORCED_BOUNDS)
    return keccak256(out).hex()


def eip55(addr):
    h = keccak256(addr.encode()).hex()
    return '0x' + ''.join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(addr))


def patterned(low):
    """Why a 40-hex value looks hand-made (nobody holds a key for it), or None. A key-derived or CREATE2 address
    has a run of 16 equal nibbles, or a period of 8 or fewer, with a probability far below 2^-50."""
    run = best = 1
    for i in range(1, 40):
        run = run + 1 if low[i] == low[i - 1] else 1
        best = max(best, run)
    if best >= 16:
        return f'a run of {best} equal hex digits'
    for period in range(1, 9):
        if all(low[i] == low[i % period] for i in range(40)):
            return f'the {period}-digit pattern {low[:period]} repeated'
    return None


def refusal_of(low):
    """Why this 40-lowercase-hex recipient may never be compiled into a release, or None."""
    if low in SYSTEM:
        return f'{eip55(low)} is the {SYSTEM[low]}: refused by ChainSpec::validate or a sweep loop'
    if low.startswith('42000000000000000000000000000000000'):
        return f'{eip55(low)} is in the OP-style predeploy range 0x4200...: refused'
    if low == PLACEHOLDER:
        return 'that is the rehearsal placeholder (REHEARSAL_FEE_SWEEP_RECIPIENT), not a decision'
    if low in BURN:
        return (f'{eip55(low)} is a burn address: fees sent there are locked forever and stay in the L1 escrow. '
                'Owner decision in force: never a burn address (there is no override)')
    if int(low, 16) <= 0xff:
        return (f'{eip55(low)} is in the precompile range: a precompile may revert on the empty call '
                '(0x09 blake2f does), and then no sweep ever succeeds')
    pattern = patterned(low)
    if pattern:
        return (f'{eip55(low)} is {pattern}: a hand-made value nobody holds a key or code for, so every fee swept '
                'there is lost (never a burn address)')
    return None


def parse_address(text):
    """Lowercase 40-hex recipient, or SystemExit with the reason. The text must be the EIP-55 mixed-case form with
    its 0x prefix (R308-4): a single-case or prefix-less value has no checksum, so one wrong digit cannot be seen."""
    raw = text.strip()
    if not re.fullmatch(r'0x[0-9a-fA-F]{40}', raw):
        raise SystemExit(f'not a 0x-prefixed 20-byte hex address: {text!r}')
    low = raw[2:].lower()
    if eip55(low) != raw:
        if raw[2:] in (low, low.upper()):
            raise SystemExit(f'{text} carries no checksum (single case): give the EIP-55 mixed-case form exactly as '
                             'the Safe shows it. The tool does not print it for you: a wrong digit would get a valid '
                             'checksum that way')
        raise SystemExit(f'EIP-55 checksum mismatch: {text}: one or more characters are wrong; copy the address again')
    refusal = refusal_of(low)
    if refusal:
        raise SystemExit(refusal)
    return low


# ---------------------------------------------------------------------------------------------- the trees
CHAINSPEC = 'src/chainspec.rs'
SETTLER = 'deployment/devnet/settler_v3.py'
BUILD_RELEASE = 'deployment/mainnet/build-release.sh'
CROSSINGS = ('deployment/mainnet/rehearsal/next-consensus/crossing.py',
             'deployment/mainnet/rehearsal/next-consensus/sparse/crossing.py',
             # agent 137's forced-inclusion crossing (fork candidate v3)
             'deployment/mainnet/rehearsal/forced-inclusion/crossing.py')
NATIVE_PINS = 'crates/bloch-pos-committee/src/l2_settlement.rs'
SELF_FILES = {'set-sweep-recipient.py', 'test_set_sweep_recipient.py', 'SWEEP-RECIPIENT-PROCEDURE.md',
              # agent 221's real rehearsal data (a statement of a past private run), never a pin
              'reset-target-fixture.json',
              # the audited sparse build f6eb456 (78c533fa, before forced inclusion and the floor): a record, never a pin
              'AUDIT-SCOPE-SPARSE.md'}
# The constant at the start of a line (never inside a `//` comment), with any white space after `=`: `apply` writes
# the two-line form rustfmt keeps (max_width 120; the one-line form is 126 columns), and the one-line form is still
# read (R308-6).
RECIPIENT_RE = re.compile(r'^pub const MAINNET_FEE_SWEEP_RECIPIENT: Option<Address> =\s*'
                          r'(?:None|Some\(Address::new\(hex!\("([0-9a-f]{40})"\)\)\));', re.M)
OWNER_LINE_RE = re.compile(r'^/// rules, fixed by the owner: `(0x[0-9a-fA-F]{40})`\.$', re.M)
FLOOR_RE = re.compile(r'pub const MAINNET_MIN_BASE_FEE: u64 = ([0-9_]+);')
PLACEHOLDER_DOC = ('/// UNSET, `TBD-owner`: the immutable recipient of the fee-vault sweep under the\n'
                   "/// next mainnet rules, the Bloch Inc Safe's L2 address once the owner fixes it\n"
                   '/// (`deployment/mainnet/set-sweep-recipient.py apply`). It enters the\n'
                   '/// configuration commitment, so the configuration, ELF and verifying keys of\n'
                   '/// the next rules exist only once it is set.\n')
GUEST_GATE = 'bloch_l2_evm::chainspec::MAINNET_NEXT_RULES_RELEASABLE'
GUESTS = ('integrations/sp1-execution/guest-sparse/src/bin/settlement_v3_mainnet_sparse.rs',
          'integrations/sp1-execution/guest-sparse/src/bin/settlement_v3_mainnet_sparse_eager.rs',
          'integrations/sp1-execution/guest/src/bin/settlement_v3_mainnet.rs')
NATIVE_PLACEHOLDER_DOC = ('    /// The configuration carries a PLACEHOLDER fee-sweep recipient, `TBD-owner`,\n'
                          '    /// and the guest is a candidate, so these values are examples until\n')

# Placeholder sentences in kit comments and docs, rewritten by `apply` ({a} = the EIP-55 recipient).
COMMENT_EDITS = (
    ('deployment/devnet/settler_v3.py',
     '# carries a placeholder fee-sweep recipient (TBD-owner), so all of these move when the recipient is fixed.',
     "# carries the owner's fee-sweep recipient {a} (src/chainspec.rs); these values are built with it."),
    ('deployment/mainnet/install-settler-mainnet.py',
     "    # fee-sweep recipient (TBD-owner) and with the audit's fixes.",
     "    # fee-sweep recipient ({a}, fixed) and with the audit's fixes."),
    ('deployment/mainnet/prover/install-prover-mainnet.py',
     '# recipient is a placeholder (TBD-owner), so the configuration and every value below move with it.',
     '# recipient is {a} (fixed by the owner); the configuration and every value below are built with it.'),
    ('deployment/mainnet/prover/install-prover-mainnet.py',
     '# name). It moves with the fee-sweep recipient (TBD-owner) like PINNED_NEXT.',
     '# name). It is built with the fee-sweep recipient {a} like PINNED_NEXT.'),
    ('docs/AUDIT-SCOPE-SPARSE.md',
     '- **The sweep recipient is a placeholder**, so the next-rules ELF and its keys move\n  once it is set.',
     '- **The sweep recipient is `{a}`** (set by the owner); the next-rules ELF and\n  its keys are built with it.'),
)


def recipient_constant(recipient):
    """The constant as `apply` writes it: the form rustfmt keeps."""
    return ('pub const MAINNET_FEE_SWEEP_RECIPIENT: Option<Address> =\n'
            f'    Some(Address::new(hex!("{recipient}")));')


def set_constant(text, recipient):
    """A chainspec.rs text with the recipient constant and its doc (which carries the EIP-55 form the gate checks)."""
    out = RECIPIENT_RE.sub(lambda _: recipient_constant(recipient), text).replace(PLACEHOLDER_DOC, owner_doc(recipient))
    return OWNER_LINE_RE.sub(lambda _: owner_doc(recipient).split('\n')[1], out)


def owner_doc(recipient):
    return ('/// The immutable recipient of the fee-vault sweep under the next mainnet\n'
            f'/// rules, fixed by the owner: `{eip55(recipient)}`.\n'
            '/// It enters the configuration commitment, so the configuration, ELF and\n'
            '/// verifying keys of the next rules are built with it.\n')


def native_owner_doc(recipient):
    return ('    /// The configuration carries the owner\'s fee-sweep recipient\n'
            f'    /// `{eip55(recipient)}` (bloch-l2-evm\n'
            '    /// `MAINNET_FEE_SWEEP_RECIPIENT`); these values are candidates until\n')


def git_files(tree):
    out = subprocess.run(['git', '-C', str(tree), 'ls-files', '-z'], check=True, capture_output=True).stdout
    return [tree / p for p in out.decode().split('\0') if p]


def text_files(tree):
    for path in git_files(tree):
        if not path.is_file() or path.stat().st_size > 4_000_000:
            continue
        data = path.read_bytes()
        if b'\0' in data[:8192]:
            continue
        try:
            yield path, data.decode()
        except UnicodeDecodeError:
            continue


def recipient_in(text, where):
    """The recipient a chainspec.rs text carries: 40 lowercase hex, or None while unset."""
    found = list(RECIPIENT_RE.finditer(text))
    if not found:
        raise SystemExit(f'{where}: `MAINNET_FEE_SWEEP_RECIPIENT: Option<Address>` not found; not a gated fork-candidate '
                         'L2 tree (agent 217 gate)')
    if len(found) > 1:
        raise SystemExit(f'{where}: MAINNET_FEE_SWEEP_RECIPIENT is defined {len(found)} times (one may sit in a block '
                         'comment); refusing to guess')
    return found[0].group(1)


def floor_in(text, where):
    m = FLOOR_RE.search(text)
    if not m:
        raise SystemExit(f'{where}: MAINNET_MIN_BASE_FEE not found; the tree lacks the base-fee floor (agent 197)')
    return int(m.group(1).replace('_', ''))


def current_recipient(l2):
    return recipient_in((l2 / CHAINSPEC).read_text(), l2 / CHAINSPEC)


def current_floor(l2):
    return floor_in((l2 / CHAINSPEC).read_text(), l2 / CHAINSPEC)


FORCED_NEXT_RE = re.compile(r'#\[cfg\(feature = "forced-inclusion"\)\]\s*forced_inclusion: true,')


def forced_in(text):
    """Whether the next mainnet rules of this chainspec.rs carry L1 forced inclusion."""
    return len(FORCED_NEXT_RE.findall(text)) == 1


def current_forced(l2):
    """Whether the tree's next rules carry forced inclusion; then the forced bounds must be the ones this script
    hashes."""
    if not forced_in((l2 / CHAINSPEC).read_text()):
        return False
    text = (l2 / FORCED_FILE).read_text()
    for name, want in zip(FORCED_BOUND_NAMES, FORCED_BOUNDS):
        m = re.search(rf'pub const {name}: (?:u64|usize) = ([0-9_* ]+);', text)
        if not m or eval(m.group(1).replace('_', ''), {'__builtins__': {}}) != want:  # noqa: S307 (digits, _ and * only)
            raise SystemExit(f'{l2 / FORCED_FILE}: {name} is not {want}; update FORCED_BOUNDS with the Rust value')
    return True


def tree_configuration(l2, recipient):
    return configuration_commitment(recipient, current_floor(l2), current_forced(l2))


def gate_refusal(recipient):
    """Why this recipient may not be compiled into a release, or None. Stricter than the Rust
    `is_release_fee_sweep_recipient`: burn addresses and the whole 0x00..00ff range are refused too."""
    if recipient is None:
        return 'MAINNET_FEE_SWEEP_RECIPIENT is unset (TBD-owner): run set-sweep-recipient.py set ADDRESS'
    return refusal_of(recipient)


def text_refusal(text, where):
    """(recipient, why the chainspec.rs text may not be released or None). Beyond `gate_refusal`, the doc line `apply`
    writes must carry the EIP-55 form of the constant (R308-4): a constant edited by hand, or one wrong digit in it,
    does not match the checksum next to it."""
    r = recipient_in(text, where)
    refusal = gate_refusal(r)
    if refusal:
        return r, refusal
    forms = OWNER_LINE_RE.findall(text)
    if forms != [eip55(r)]:
        return r, (f'the constant is {r} but the doc line "/// rules, fixed by the owner: `{eip55(r)}`." is '
                   f'{"missing" if not forms else "not that: " + ", ".join(forms)}; the recipient must be written by '
                   'set-sweep-recipient.py set/apply from the EIP-55 form, never by hand')
    return r, None


def settler_pin(l2, name):
    """The dict literal `NAME = {...}` of settler_v3.py as {key: hex}."""
    text = (l2 / SETTLER).read_text()
    m = re.search(rf'^{name} = \{{(.*?)^\}}', text, re.S | re.M)
    if not m:
        raise SystemExit(f'{SETTLER}: {name} not found')
    return dict(re.findall(r"'(\w+)': '([0-9a-f]{64})'", m.group(1)))


def native_program(native, const):
    text = (native / NATIVE_PINS).read_text()
    m = re.search(rf'pub const {const}: NextProgram = NextProgram \{{(.*?)\n    \}};', text, re.S)
    if not m:
        raise SystemExit(f'{NATIVE_PINS}: {const} not found; not a fork-candidate native tree')
    return re.findall(r'h32\("([0-9a-f]{64})"\)', m.group(1))


def self_check(l2, native):
    """Refuse unless this script's commitment reproduces the activated configuration and the next configuration the
    trees pin: the one of their own recipient and floor, or (an unset tree) the rehearsal or legacy candidate pins.
    Returns (old recipient for the rehearsal constants, old configuration)."""
    if configuration_commitment() != ACTIVATED_CONFIGURATION:
        raise SystemExit('internal: the activated configuration does not reproduce')
    if configuration_commitment(PLACEHOLDER) != LEGACY_PLACEHOLDER_CONFIGURATION:
        raise SystemExit('internal: the legacy candidate configuration does not reproduce')
    floor, forced = current_floor(l2), current_forced(l2)
    if configuration_commitment(PLACEHOLDER, floor) != REHEARSAL_CONFIGURATION:
        raise SystemExit('internal: the rehearsal configuration does not reproduce (floor or layout drift)')
    if configuration_commitment(PLACEHOLDER, 0, True) != LEGACY_PLACEHOLDER_CONFIGURATION_FORCED:
        raise SystemExit('internal: the forced candidate configuration does not reproduce')
    if configuration_commitment(PLACEHOLDER, floor, True) != REHEARSAL_CONFIGURATION_FORCED:
        raise SystemExit('internal: the forced rehearsal configuration does not reproduce (floor, bounds or layout drift)')
    old = current_recipient(l2)
    if old is None:
        old = PLACEHOLDER
        allowed = ({REHEARSAL_CONFIGURATION_FORCED, LEGACY_PLACEHOLDER_CONFIGURATION_FORCED} if forced
                   else {REHEARSAL_CONFIGURATION, LEGACY_PLACEHOLDER_CONFIGURATION})
    else:
        allowed = {configuration_commitment(old, floor, forced)}
    pinned_values = {
        settler_pin(l2, 'MAINNET_NEXT')['configuration'], settler_pin(l2, 'MAINNET_NEXT_SPARSE')['configuration'],
        native_program(native, 'PROGRAM_NEXT')[0], native_program(native, 'PROGRAM_FALLBACK')[0]}
    want = next(iter(pinned_values)) if len(pinned_values) == 1 and pinned_values <= allowed else sorted(allowed)[0]
    pinned = {
        f'{SETTLER} MAINNET_NEXT': settler_pin(l2, 'MAINNET_NEXT')['configuration'],
        f'{SETTLER} MAINNET_NEXT_SPARSE': settler_pin(l2, 'MAINNET_NEXT_SPARSE')['configuration'],
        f'{NATIVE_PINS} PROGRAM_NEXT': native_program(native, 'PROGRAM_NEXT')[0],
        f'{NATIVE_PINS} PROGRAM_FALLBACK': native_program(native, 'PROGRAM_FALLBACK')[0],
    }
    if settler_pin(l2, 'MAINNET')['configuration'] != ACTIVATED_CONFIGURATION:
        raise SystemExit(f'{SETTLER} MAINNET: activated configuration is not {ACTIVATED_CONFIGURATION}')
    bad = {k: v for k, v in pinned.items() if v != want}
    if bad:
        raise SystemExit('the trees do not pin the configuration of their own recipient '
                         f'({eip55(old)} -> {want}); refusing:\n  ' + '\n  '.join(f'{k}: {v}' for k, v in bad.items()))
    return old, want


class Editor:
    """Collects every edit in memory; `report` writes them all to temporary files and renames those at the end
    (R308-6), src/chainspec.rs last: an interruption before the renames leaves the trees untouched, and one between
    them leaves the gate closed. Later edits of one run read the earlier ones through `read` / `files`."""

    def __init__(self, dry_run):
        self.dry_run, self.changed, self.pending = dry_run, {}, {}

    def read(self, path):
        return self.pending[path] if path in self.pending else path.read_text()

    def files(self, tree):
        for path, text in text_files(tree):
            yield path, self.pending.get(path, text)

    def write(self, path, before, after, why):
        if before == after:
            return
        self.changed.setdefault(str(path), []).append(why)
        self.pending[path] = after

    def replace_everywhere(self, trees, old, new, why, bounded=True, skip=()):
        pattern = re.compile(rf'(?<![0-9a-fA-F]){re.escape(old)}(?![0-9a-fA-F])' if bounded else re.escape(old))
        for tree in trees:
            for path, text in list(self.files(tree)):
                if old in text and path.name not in SELF_FILES and path not in skip:
                    self.write(path, text, pattern.sub(new, text), why)

    def flush(self):
        if self.dry_run or not self.pending:
            return
        order = sorted(self.pending, key=lambda p: (str(p).endswith(CHAINSPEC), str(p)))
        temps = []
        try:
            for path in order:
                tmp = path.with_name(f'.{path.name}.sweep-tmp')
                tmp.write_text(self.pending[path])
                shutil.copymode(path, tmp)
                temps.append((tmp, path))
            for tmp, path in temps:
                os.replace(tmp, path)
        finally:
            for tmp, _ in temps:
                if tmp.exists():
                    tmp.unlink()
        self.pending = {}

    def report(self):
        self.flush()
        verb = 'would change' if self.dry_run else 'changed'
        for path, whys in sorted(self.changed.items()):
            print(f'{verb} {path}: {", ".join(sorted(set(whys)))}')
        if not self.changed:
            print('nothing to change')


# Files the settler installer pins by SHA-256 (install-settler-mainnet.py PINS) that apply/pins edit. Their pins must
# follow, or the installer refuses the kit (fork candidate v3: apply rewrites settler_v3.py's MAINNET_NEXT pins).
INSTALLER = 'deployment/mainnet/install-settler-mainnet.py'
INSTALLER_PINNED = (('settler_v3.py', SETTLER),)


def refresh_installer_pins(l2, ed):
    p = l2 / INSTALLER
    if not p.is_file():
        return
    t = ed.read(p)
    t2 = t
    for name, rel in INSTALLER_PINNED:
        digest = hashlib.sha256(ed.read(l2 / rel).encode()).hexdigest()
        t2 = re.sub(rf"('{re.escape(name)}': ')[0-9a-f]{{64}}(')", lambda m: m.group(1) + digest + m.group(2), t2)
    ed.write(p, t, t2, 'installer pin of an edited file')


# -------------------------------------------------------------------------------------------------- steps
def cmd_check(args):
    r = parse_address(args.address)
    print(json.dumps({'recipient': eip55(r), 'configuration (no floor, no forced inclusion)': configuration_commitment(r),
                      'configuration (0.1 gwei floor, forced inclusion)':
                          configuration_commitment(r, 100_000_000, True)}, indent=2))


def short_forms(old, new):
    """(old, new, bounded) for the short spellings of a 64-hex value in comments: `78c533fa…7bea`, `78c533fa...7bea`
    and the bare `78c533fa`."""
    return [(f'{old[:8]}{sep}{old[-4:]}', f'{new[:8]}{sep}{new[-4:]}', False) for sep in ('…', '...')] + [
        (old[:8], new[:8], True)]


def cmd_apply(args):
    r = parse_address(args.address)
    l2, native = Path(args.l2).resolve(), Path(args.native).resolve()
    old, old_cfg = self_check(l2, native)
    new_cfg = tree_configuration(l2, r)
    ed = Editor(args.dry_run)
    p = l2 / CHAINSPEC
    t = p.read_text()
    # Also on an unchanged recipient: an older tree carries the one-line constant, or lacks the EIP-55 doc line.
    ed.write(p, t, set_constant(t, r), 'MAINNET_FEE_SWEEP_RECIPIENT')
    if current_recipient(l2) != r:
        for rel in CROSSINGS:
            p = l2 / rel
            t = p.read_text()
            ed.write(p, t, t.replace(f"SWEEP_RECIPIENT = '{old}'", f"SWEEP_RECIPIENT = '{r}'"), 'rehearsal SWEEP_RECIPIENT')
        ed.replace_everywhere([l2, native], old_cfg, new_cfg, 'next configuration commitment')
        # The short forms of the configuration in comments (R308-5); `pins` does the same for the guest hashes.
        for before, after, bounded in short_forms(old_cfg, new_cfg):
            ed.replace_everywhere([l2, native], before, after, 'next configuration commitment (short)', bounded=bounded)
        p = native / NATIVE_PINS
        t = ed.read(p)
        ed.write(p, t, t.replace(NATIVE_PLACEHOLDER_DOC, native_owner_doc(r)), 'PROGRAM_NEXT doc')
        for rel, before, after in COMMENT_EDITS:
            p = l2 / rel
            if p.is_file():
                t = ed.read(p)
                ed.write(p, t, t.replace(before, after.format(a=eip55(r))), 'placeholder comment')
        if old != PLACEHOLDER:
            # A second `set` (R308-5): every text that names the previous recipient, in either spelling, follows.
            # src/chainspec.rs is written above only (its Rust tests pin a throwaway address of their own).
            for before, after in ((eip55(old)[2:], eip55(r)[2:]), (old, r)):
                ed.replace_everywhere([l2, native], before, after, 'previous recipient', skip=(l2 / CHAINSPEC,))
                for rel in sorted({rel for rel, _, _ in COMMENT_EDITS}):  # one of them is a record `SELF_FILES` skips
                    p = l2 / rel
                    if p.is_file():
                        t = ed.read(p)
                        ed.write(p, t, t.replace(before, after), 'previous recipient')
    refresh_installer_pins(l2, ed)
    ed.report()
    print(json.dumps({'old_recipient': eip55(old), 'recipient': eip55(r), 'old_configuration': old_cfg,
                      'min_base_fee': current_floor(l2),
                      'configuration': new_cfg, 'next': 'build both guests in the pinned container on two hosts, '
                      'then run `pins` (see `audit` for the full rebuild list)'}, indent=2))


def load_identity(path, program, configuration):
    ident = json.loads(Path(path).read_text())
    want = {'program': program, 'chain_id': CHAIN_ID, 'domain': L2_DOMAIN, 'configuration': configuration,
            'proof_policy_v3': PROOF_POLICY}
    bad = {k: (ident.get(k), v) for k, v in want.items() if ident.get(k) != v}
    if bad:
        raise SystemExit(f'{path}: identity does not match ' + json.dumps(bad))
    for k in ('elf_keccak', 'vkey_koalabear', 'vkey_bn254'):
        if not re.fullmatch(r'[0-9a-f]{64}', str(ident.get(k, ''))):
            raise SystemExit(f'{path}: {k} missing')
    return ident


def elf_digest(arg):
    p = Path(arg)
    if p.is_file():
        data = p.read_bytes()
        return hashlib.sha256(data).hexdigest(), len(data)
    if re.fullmatch(r'[0-9a-f]{64}', arg):
        return arg, None
    raise SystemExit(f'{arg}: neither an ELF file nor a SHA-256')


def cmd_pins(args):
    l2, native = Path(args.l2).resolve(), Path(args.native).resolve()
    r, refusal = text_refusal((l2 / CHAINSPEC).read_text(), l2 / CHAINSPEC)
    if refusal:
        raise SystemExit(f'pins: {refusal}')
    cfg = tree_configuration(l2, r)
    for name in ('MAINNET_NEXT', 'MAINNET_NEXT_SPARSE'):
        if settler_pin(l2, name)['configuration'] != cfg:
            raise SystemExit(f'{SETTLER} {name}: run `apply` first (configuration is not {cfg})')
    ed = Editor(args.dry_run)
    out = {}
    for kind, pin, const, program, ident_path, elf in (
            ('sparse', 'MAINNET_NEXT_SPARSE', 'PROGRAM_NEXT', 'settlement_v3_mainnet_sparse', args.sparse_identity, args.sparse_elf),
            ('complete', 'MAINNET_NEXT', 'PROGRAM_FALLBACK', 'settlement_v3_mainnet', args.complete_identity, args.complete_elf)):
        ident = load_identity(ident_path, program, cfg)
        sha, size = elf_digest(elf)
        old = settler_pin(l2, pin)
        if native_program(native, const)[1:4] != [old['elf_keccak'], old['vkey_koalabear'], old['vkey_bn254']]:
            raise SystemExit(f'{NATIVE_PINS} {const} and {SETTLER} {pin} disagree; refusing')
        new = {'elf_keccak': ident['elf_keccak'], 'vkey_koalabear': ident['vkey_koalabear'],
               'vkey_bn254': ident['vkey_bn254'], 'guest_sha256': sha}
        for key, value in new.items():
            if old[key] != value:
                ed.replace_everywhere([l2, native], old[key], value, f'{kind} {key}')
        if old['guest_sha256'] != sha:
            o, n = old['guest_sha256'], sha
            for before, after, bounded in short_forms(o, n):
                ed.replace_everywhere([l2, native], before, after, f'{kind} guest_sha256 (short)', bounded=bounded)
            if size is not None:
                p = native / NATIVE_PINS
                t = ed.read(p)
                size_text = f'{size:,}'.replace(',', ' ')
                t2 = re.sub(rf'(`{n[:8]}…{n[-4:]}`\s*(?:///\s*)?\()[\d ]+( bytes\))', lambda m: m.group(1) + size_text + m.group(2), t)
                ed.write(p, t, t2, f'{kind} ELF size')
        out[const] = {'configuration': cfg, **new, 'elf_bytes': size}
    refresh_installer_pins(l2, ed)
    ed.report()
    print(json.dumps(out, indent=2))
    print('PROGRAM_NEXT_FINAL stays false: flip it (and hard_forks.rs test `assert!(!PROGRAM_NEXT_FINAL)`) only when '
          'the owner signs off the final reproducible guests.')


def cmd_native_commit(args):
    l2, native = Path(args.l2).resolve(), Path(args.native).resolve()
    p = l2 / BUILD_RELEASE
    t = p.read_text()
    m = re.search(r'^CANDIDATE_NATIVE_COMMIT=([0-9a-f]{40})$', t, re.M)
    if not m:
        raise SystemExit(f'{BUILD_RELEASE}: CANDIDATE_NATIVE_COMMIT not found')
    old = m.group(1)
    run = lambda *a: subprocess.run(['git', '-C', str(native), *a], capture_output=True, text=True)  # noqa: E731
    head = run('rev-parse', 'HEAD').stdout.strip()
    if run('status', '--porcelain', '--untracked-files=no').stdout.strip():
        raise SystemExit(f'{native}: commit the native changes first')
    if run('merge-base', '--is-ancestor', old, head).returncode != 0:
        raise SystemExit(f'{native} HEAD {head} does not descend from {old}')
    diff = run('diff', '--name-only', old, head).stdout.split()
    lock_inputs = [f for f in diff if f.endswith(('Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml'))]
    if lock_inputs:
        raise SystemExit(f'native lock inputs changed ({", ".join(lock_inputs)}): resolve and pin a new lock first')
    ed = Editor(args.dry_run)
    ed.write(p, t, t.replace(f'CANDIDATE_NATIVE_COMMIT={old}', f'CANDIDATE_NATIVE_COMMIT={head}'), 'CANDIDATE_NATIVE_COMMIT')
    # The shadow sequencer's installer pins the same native commit (agent 218, install-shadow.sh).
    shadow = l2 / 'deployment/mainnet/install-shadow.sh'
    if shadow.is_file():
        st = shadow.read_text()
        ed.write(shadow, st, re.sub(r'(?m)^NATIVE_COMMIT=[0-9a-f]{40}$', f'NATIVE_COMMIT={head}', st), 'install-shadow NATIVE_COMMIT')
    ed.report()
    print(json.dumps({'old_native': old, 'native': head, 'changed_native_files': diff,
                      'lock': 'unchanged (CANDIDATE_LOCK_SHA256 stays)'}, indent=2))


def rebuild_list():
    return [
        'Guests (pinned container, two Linux x86_64 hosts, SHA256SUMS identical): settlement_v3_mainnet_sparse '
        '(PROGRAM_NEXT), settlement_v3_mainnet (PROGRAM_FALLBACK); settlement_v3_mainnet_sparse_eager (measurement '
        'only) also moves; settlement_v3_mainnet_v1_sparse (mainnet_v1, no recipient) must stay b1b09c1f, stop if not',
        'Identities: `bloch-evm-sp1-settlement-v3 --mainnet --sparse identity settlement_v3_mainnet_sparse` and '
        '`--mainnet identity settlement_v3_mainnet` from the host built from this tree; feed them to `pins`',
        'Native (bloch-sis-pow): commit l2_settlement.rs; bloch-pos release build on two hosts, qualify (forced '
        'build with a fresh context), sign; l2_tests and hard_forks suites',
        'L2 kit: build-release.sh after `native-commit` (follower, produce-dev, settled-rpc all link the chainspec '
        'and detect the switch by the sweep code); prover host; settlement-recovery tools; attestor package; '
        'GO-LIVE pins files; settler/prover installers carry the new guest pins',
        'Fixtures and rehearsals: a real Groth16 proof under the new keys (native fixture test), the crossing '
        '(sparse/crossing.py, 36 checks, with a real sweep to the new recipient), the rollback crossing, run B',
        'Operator config: sequencer `next_elf_keccak` = the new sparse ELF Keccak; settler `next_program` / '
        '`fallback_program` via install-settler-mainnet.py',
        'Docs: AUDIT-SCOPE-SPARSE.md table, SETTLER-RUNBOOK.md, fork notice (recipient is public), exchange docs '
        '(vault balances become sweepable to the recipient after the gate)',
    ]


def cmd_audit(args):
    l2, native = Path(args.l2).resolve(), Path(args.native).resolve()
    r, refusal = text_refusal((l2 / CHAINSPEC).read_text(), l2 / CHAINSPEC)
    cfg = tree_configuration(l2, r) if r else None
    stale = {'placeholder recipient': PLACEHOLDER,
             'placeholder configuration': LEGACY_PLACEHOLDER_CONFIGURATION,
             'rehearsal configuration': REHEARSAL_CONFIGURATION,
             'forced placeholder configuration': LEGACY_PLACEHOLDER_CONFIGURATION_FORCED,
             'forced rehearsal configuration': REHEARSAL_CONFIGURATION_FORCED}
    for v in args.old or []:
        stale[f'old value {v[:8]}'] = v.lower()
        stale[f'old short {v[:8]}'] = v.lower()[:8]
    hits, notes = [], []
    for tree in (l2, native):
        for path, text in text_files(tree):
            lines = text.splitlines()
            for n, line in enumerate(lines, 1):
                # A constant rustfmt wrapped over two lines (`const NAME: B256 =` / `B256::new(hex!(..));`) is one item.
                item = (lines[n - 2] + ' ' + line) if n > 1 and lines[n - 2].rstrip().endswith('=') else line
                for name, v in stale.items():
                    # The rehearsal constant itself and the Rust tests that pin it stay by design.
                    if path.match('*/src/chainspec.rs') and (
                            'REHEARSAL_FEE_SWEEP_RECIPIENT' in item or 'REHEARSAL_CONFIGURATION' in item
                            or 'CONFIGURATION_FORCED' in item):
                        continue
                    # The monitor's own constant: it must know the placeholder to alarm on it (R308-5).
                    if path.name == 'revenue_monitor.py' and line.startswith('PLACEHOLDER_SWEEP_RECIPIENT = '):
                        continue
                    if v in line and path.name not in SELF_FILES:
                        hits.append(f'{path}:{n}: {name}')
                if 'TBD-owner' in line and re.search(r'sweep|recipient', line, re.I) and path.name not in SELF_FILES:
                    notes.append(f'{path}:{n}: {line.strip()[:140]}')
    native_cfg = native_program(native, 'PROGRAM_NEXT')[0]
    gate_problems = [f'{l2 / g}: no compile-time release gate' for g in GUESTS
                     if (l2 / g).is_file() and GUEST_GATE not in (l2 / g).read_text()]
    result = {'recipient': eip55(r) if r else None, 'gate': refusal or 'release recipient',
              'placeholder': refusal is not None, 'configuration': cfg,
              'native_PROGRAM_NEXT_configuration_matches': native_cfg == cfg,
              'native_PROGRAM_NEXT_FINAL': 'pub const PROGRAM_NEXT_FINAL: bool = true;' in (native / NATIVE_PINS).read_text(),
              'stale_values': hits, 'tbd_owner_sweep_mentions': notes, 'gate_problems': gate_problems,
              'rebuild': rebuild_list()}
    print(json.dumps(result, indent=2))
    if hits or result['placeholder'] or not result['native_PROGRAM_NEXT_configuration_matches'] or result['gate_problems']:
        sys.exit(1)


def cmd_gate(args):
    """The release gate the build scripts call. Exit 0 only for a release recipient; print why not otherwise."""
    if args.chainspec:
        text = sys.stdin.read() if args.chainspec == '-' else Path(args.chainspec).read_text()
        where = args.chainspec
    else:
        where = Path(args.l2).resolve() / CHAINSPEC
        text = where.read_text()
    r, refusal = text_refusal(text, where)
    if refusal:
        print(f'sweep-recipient gate: REFUSED: {refusal}', file=sys.stderr)
        sys.exit(3)
    print(json.dumps({'gate': 'release recipient', 'recipient': eip55(r),
                      'configuration': configuration_commitment(r, floor_in(text, where), forced_in(text))}))


def cmd_set(args):
    """The owner's one command: check, optional on-chain read, apply to both trees, gate, commit."""
    r = parse_address(args.address)
    if args.allow_codeless and not args.rpc:
        raise SystemExit('--allow-codeless only makes sense with --rpc')
    if args.rpc:
        cmd_onchain(argparse.Namespace(address=args.address, rpc=args.rpc, allow_codeless=args.allow_codeless))
    if not args.rpc or args.allow_codeless:
        # No code on the L2 vouches for the address (R308-4): it must be typed a second time, checksum included.
        again = args.confirm
        if again is None and sys.stdin.isatty():
            again = input('Type the recipient address again, from the Safe itself (EIP-55 form, do not paste the '
                          'line above): ')
        if again is None:
            raise SystemExit('set needs proof that this is the intended address: --rpc URL (the address must hold '
                             'code on the L2 at finalized), or the address a second time as --confirm ADDRESS')
        if parse_address(again) != r:
            raise SystemExit(f'the two addresses differ: {args.address} and {again.strip()}; nothing written')
    l2, native = Path(args.l2).resolve(), Path(args.native).resolve()
    run = lambda tree, *a: subprocess.run(['git', '-C', str(tree), *a], capture_output=True, text=True)  # noqa: E731
    if not args.dry_run and not args.no_commit:
        for tree in (l2, native):
            if run(tree, 'status', '--porcelain', '--untracked-files=no').stdout.strip():
                raise SystemExit(f'{tree}: commit or stash local changes first (set commits its own edits)')
    cmd_apply(argparse.Namespace(address=args.address, l2=args.l2, native=args.native, dry_run=args.dry_run))
    if args.dry_run:
        print('dry run: nothing written, nothing committed')
        return
    refusal = text_refusal((l2 / CHAINSPEC).read_text(), l2 / CHAINSPEC)[1]
    if refusal:
        raise SystemExit(f'internal: the gate still refuses after apply: {refusal}')
    if not args.no_commit:
        message = (f'Next mainnet rules: the owner\'s fee-sweep recipient {eip55(r)}\n\n'
                   'Written by deployment/mainnet/set-sweep-recipient.py set. The next configuration commitment is '
                   f'{tree_configuration(l2, r)}; the guest ELF and key pins move after the '
                   'pinned-container builds (set-sweep-recipient.py pins).\n')
        for tree in (l2, native):
            if run(tree, 'status', '--porcelain', '--untracked-files=no').stdout.strip():
                done = run(tree, 'commit', '-q', '-a', '-m', message)
                if done.returncode:
                    raise SystemExit(f'{tree}: git commit failed: {done.stderr.strip()}')
                print(f'committed {tree} {run(tree, "rev-parse", "--short", "HEAD").stdout.strip()}')
    print('next: build both guests in the pinned container on two hosts from the L2 commit above, run the host '
          '`identity` for each (it now executes the ELF under the selected rules), then `pins`, commit native, '
          '`native-commit`, `audit`')


def rpc(url, method, params):
    req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = json.loads(resp.read())
    if 'error' in body:
        raise SystemExit(f'{method}: {body["error"]}')
    return body['result']


def cmd_onchain(args):
    r = parse_address(args.address)
    a = '0x' + r
    if int(rpc(args.rpc, 'eth_chainId', []), 16) != CHAIN_ID:
        raise SystemExit(f'{args.rpc} is not chain {CHAIN_ID}')
    code = rpc(args.rpc, 'eth_getCode', [a, 'finalized'])
    out = {'recipient': eip55(r), 'code_bytes': (len(code) - 2) // 2,
           'balance_wei': int(rpc(args.rpc, 'eth_getBalance', [a, 'finalized']), 16)}
    if code != '0x':
        call = lambda sel: rpc(args.rpc, 'eth_call', [{'to': a, 'data': sel}, 'finalized'])  # noqa: E731
        try:
            out['threshold'] = int(call('0xe75235b8'), 16)
            words = call('0xa0e67e2b')[2:]
            n = int(words[64:128], 16)
            out['owners'] = [eip55(words[128 + 64 * i + 24: 128 + 64 * (i + 1)]) for i in range(n)]
            version = call('0xffa1ad74')[2:]
            out['safe_version'] = bytes.fromhex(version[128:128 + 2 * int(version[64:128], 16)]).decode()
        except (SystemExit, ValueError) as error:
            out['safe'] = f'not a Safe ({error})'
    print(json.dumps(out, indent=2))
    if code == '0x' and not args.allow_codeless:
        raise SystemExit('no code at finalized: deploy the Safe on L2 first (or pass --allow-codeless for a '
                         'counterfactual address whose deployment is guaranteed)')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('check')
    c.add_argument('address')
    c.set_defaults(fn=cmd_check)
    g = sub.add_parser('gate')
    where = g.add_mutually_exclusive_group(required=True)
    where.add_argument('--l2', help='bloch-l2-evm checkout')
    where.add_argument('--chainspec', help='a src/chainspec.rs file, or - for stdin (e.g. `git show REV:src/chainspec.rs`)')
    g.set_defaults(fn=cmd_gate)
    st = sub.add_parser('set')
    st.add_argument('address')
    st.add_argument('--l2', required=True, help='bloch-l2-evm checkout (fork candidate)')
    st.add_argument('--native', required=True, help='bloch-sis-pow checkout (fork candidate)')
    st.add_argument('--rpc', help='L2 RPC: the address must hold code at `finalized` (`onchain`)')
    st.add_argument('--allow-codeless', action='store_true',
                    help='with --rpc: accept a counterfactual Safe address (then --confirm is needed too)')
    st.add_argument('--confirm', metavar='ADDRESS', help='the address typed a second time (EIP-55 form); needed '
                    'without --rpc and with --allow-codeless; asked at the prompt on a terminal')
    st.add_argument('--no-commit', action='store_true')
    st.add_argument('--dry-run', action='store_true')
    st.set_defaults(fn=cmd_set)
    for name, fn in (('apply', cmd_apply), ('pins', cmd_pins), ('native-commit', cmd_native_commit), ('audit', cmd_audit)):
        p = sub.add_parser(name)
        if name == 'apply':
            p.add_argument('address')
        p.add_argument('--l2', required=True, help='bloch-l2-evm checkout (fork candidate)')
        p.add_argument('--native', required=True, help='bloch-sis-pow checkout (fork candidate)')
        if name != 'audit':
            p.add_argument('--dry-run', action='store_true')
        if name == 'pins':
            for k in ('sparse', 'complete'):
                p.add_argument(f'--{k}-identity', required=True)
                p.add_argument(f'--{k}-elf', required=True, help='the ELF file, or its SHA-256')
        if name == 'audit':
            p.add_argument('--old', action='append', help='another superseded 64-hex value to look for')
        p.set_defaults(fn=fn)
    o = sub.add_parser('onchain')
    o.add_argument('address')
    o.add_argument('--rpc', required=True)
    o.add_argument('--allow-codeless', action='store_true')
    o.set_defaults(fn=cmd_onchain)
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == '__main__':
    main()
