#!/usr/bin/env python3
"""Keep the launch kit's pin lists and the go-live plan's hash table equal to the tree.

  refresh_kit_pins.py            check only: exit 1 and list every difference (what the tests run)
  refresh_kit_pins.py --write    rewrite the source-derived lines and the plan's hashes

What it covers (review R308-14, R308-17, agent 312 F312-1):
  1. GO-LIVE-PINS.sha256 and GO-LIVE-PINS-PROVER.sha256: every line whose payload is a source file of this
     repository (SOURCES below) equals that file.
  2. GO-LIVE-PINS.sha256 has one `kit/<path>` line for EVERY file of deployment/mainnet that the staged kit
     (`scp -r deployment/mainnet .../kit`) carries and a host may run, install or read as configuration:
     everything except tests, test data, review demonstrations, Markdown and the two pin lists themselves.
  3. docs/L2-MAINNET-GO-LIVE.md section 3.2: every row's hash equals the file, and the P2 "GO when" line
     names the hash of GO-LIVE-PINS.sha256.

It never touches a binary pin (artifacts/, release-*/ binaries): those are release evidence from the build
hosts and move only with a new release. Standard library only.
"""
import hashlib
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PINS, PROVER_PINS = HERE / 'GO-LIVE-PINS.sha256', HERE / 'GO-LIVE-PINS-PROVER.sha256'
PLAN = ROOT / 'docs' / 'L2-MAINNET-GO-LIVE.md'
# Pin-list payloads that are copies of repository sources (not under kit/).
SOURCES = {
    'artifacts/sequencer_mainnet.py': HERE / 'sequencer_mainnet.py',
    'release-settler-v2/settler_v3.py': HERE.parent / 'devnet' / 'settler_v3.py',
    'release-settler-v2/l2_reorg_recover.py': HERE / 'l2_reorg_recover.py',
    'release-settler-v2/install-settler-mainnet.py': HERE / 'install-settler-mainnet.py',
    'release-settler-v2/sequencer_policy_v2.py': HERE.parent / 'devnet' / 'sequencer_policy_v2.py',
}
PROVER_SOURCES = {
    'release-prover-v2/remote_prover.py': HERE.parent / 'devnet' / 'remote_prover.py',
    'release-prover-v2/install-prover-mainnet.py': HERE / 'prover' / 'install-prover-mainnet.py',
}
# Sources whose pinned copy is the RELEASE's (built at the release commit), not the tree's: never refreshed.
RELEASE_BOUND = {'artifacts/sequencer_mainnet.py'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def kit_files():
    """Relative paths (posix) of every kit file that must be pinned."""
    out = []
    for path in sorted(HERE.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(HERE).as_posix()
        parts = rel.split('/')
        if ('tests' in parts or 'testdata' in parts or '__pycache__' in parts or 'node_modules' in parts
                or parts[0].startswith('review-r15-308') or parts[-1].startswith('test_') or parts[-1].endswith(('.md', '.pyc'))
                or parts[-1] in ('.gitignore', '.DS_Store') or path in (PINS, PROVER_PINS)):
            continue
        out.append(rel)
    return out


def read_pins(path):
    entries = []
    for line in path.read_text().splitlines():
        digest, name = line.split()
        entries.append((name, digest))
    return entries


def wanted_pins():
    """(GO-LIVE-PINS lines, GO-LIVE-PINS-PROVER lines) as they must be for this tree."""
    main = []
    for name, digest in read_pins(PINS):
        if name.startswith('kit/'):
            continue
        if name in SOURCES and name not in RELEASE_BOUND:
            digest = sha(SOURCES[name])
        main.append((name, digest))
    main += [(f'kit/{rel}', sha(HERE / rel)) for rel in kit_files()]
    prover = [(name, sha(PROVER_SOURCES[name]) if name in PROVER_SOURCES else digest) for name, digest in read_pins(PROVER_PINS)]
    return main, prover


def render(entries):
    return ''.join(f'{digest}  {name}\n' for name, digest in entries)


ROW = re.compile(r'^(\| `)([^`]+)(` \| `)([0-9a-f]{64})(`.*)$', re.M)
P2 = re.compile(r'(`kit/GO-LIVE-PINS\.sha256` hashes to `)([0-9a-f]{64})(`)')


def plan_with_tree_hashes(text, pins_digest):
    start, end = text.index('### 3.2'), text.index('### 3.3')

    def row(m):
        path = ROOT / m.group(2)
        if m.group(2) == 'deployment/mainnet/GO-LIVE-PINS.sha256':
            return m.group(1) + m.group(2) + m.group(3) + pins_digest + m.group(5)
        return m.group(1) + m.group(2) + m.group(3) + (sha(path) if path.is_file() else m.group(4)) + m.group(5)
    table = ROW.sub(row, text[start:end])
    text = text[:start] + table + text[end:]
    return P2.sub(lambda m: m.group(1) + pins_digest + m.group(3), text)


def differences():
    """Human-readable lines; empty when the pin lists and the plan equal the tree."""
    main, prover = wanted_pins()
    out = []
    for path, want in ((PINS, main), (PROVER_PINS, prover)):
        have = dict(read_pins(path))
        names = [n for n, _ in read_pins(path)]
        out += [f'{path.name}: duplicate line for {n}' for n in sorted(set(names)) if names.count(n) > 1]
        for name, digest in want:
            if name not in have:
                out.append(f'{path.name}: no line for {name}')
            elif have[name] != digest:
                out.append(f'{path.name}: {name} is pinned {have[name][:12]}…, the tree has {digest[:12]}…')
        out += [f'{path.name}: line for {n}, which the kit does not carry' for n in have if n not in dict(want)]
    text = PLAN.read_text()
    pins_digest = hashlib.sha256(render(main).encode()).hexdigest()
    start, end = text.index('### 3.2'), text.index('### 3.3')
    for m in ROW.finditer(text[start:end]):
        path = ROOT / m.group(2)
        want = pins_digest if m.group(2) == 'deployment/mainnet/GO-LIVE-PINS.sha256' else (sha(path) if path.is_file() else None)
        if want is None:
            out.append(f'plan 3.2: {m.group(2)} is not a file of this tree')
        elif want != m.group(4):
            out.append(f'plan 3.2: {m.group(2)} says {m.group(4)[:12]}…, the tree has {want[:12]}…')
    p2 = P2.search(text)
    if not p2:
        out.append('plan P2: no "`kit/GO-LIVE-PINS.sha256` hashes to" line')
    elif p2.group(2) != pins_digest:
        out.append(f'plan P2 GO line says {p2.group(2)[:12]}…, GO-LIVE-PINS.sha256 must hash to {pins_digest[:12]}…')
    return out


def write():
    main, prover = wanted_pins()
    PROVER_PINS.write_text(render(prover))
    PINS.write_text(render(main))   # last of the kit files: nothing in it depends on itself
    PLAN.write_text(plan_with_tree_hashes(PLAN.read_text(), sha(PINS)))


def main(argv):
    if argv == ['--write']:
        write()
    elif argv:
        sys.exit(__doc__)
    found = differences()
    for line in found:
        print(line)
    print(f'GO-LIVE-PINS.sha256 {sha(PINS)}  ({len(read_pins(PINS))} lines, {len(kit_files())} kit files)')
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
