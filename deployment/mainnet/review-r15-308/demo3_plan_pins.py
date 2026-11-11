#!/usr/bin/env python3
"""D3: docs/L2-MAINNET-GO-LIVE.md section 3.2 (the hashes the owner compares in P2, "NO-GO: any mismatch") against the
files of the same checkout, and against GO-LIVE-PINS.sha256's own lines."""
import hashlib, re, sys
from pathlib import Path
R = Path(__file__).resolve().parents[3]
text = (R / 'docs/L2-MAINNET-GO-LIVE.md').read_text()
table = text.split('### 3.2')[1].split('### 3.3')[0]
bad = 0
for path, want in re.findall(r'^\| `([^`]+)` \| `([0-9a-f]{64})`', table, re.M):
    got = hashlib.sha256((R / path).read_bytes()).hexdigest()
    if got != want:
        bad += 1
        print(f'MISMATCH {path}\n   plan {want}\n   tree {got}')
p2 = re.search(r'`kit/GO-LIVE-PINS.sha256` hashes to `([0-9a-f]{64})`', text).group(1)
got = hashlib.sha256((R / 'deployment/mainnet/GO-LIVE-PINS.sha256').read_bytes()).hexdigest()
print('P2 GO criterion for kit/GO-LIVE-PINS.sha256:', p2, '\n                       tree:', got)
bad += p2 != got
sys.exit(f'{bad} plan hashes differ from the kit at this commit' if bad else 0)
