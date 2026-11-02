#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Print, as JSON, every L1 activation epoch a native params.rs compiles in.

  l1_gates.py NATIVE/crates/bloch-pos-committee/src/params.rs

Reads `pub const <NAME>_ACTIVATION_EPOCH: u64 = <value>;` (plain literals and u64::MAX) and the
`*_RECOVERY_EPOCHS` slices. u64::MAX is reported as "inert"; an expression this reader does not
evaluate (cfg/env-dependent) is reported verbatim with a "?" prefix, never guessed. The L2 binaries
built against that tree follow exactly these epochs; build-release.sh writes them into build.json and
the operator compares them with the L1 release notice (docs/L2-HARD-FORK-OPERATOR-STEPS.md).
"""
import json
import re
import sys

# L2_*_EPOCH: the program swap and its rollback (L2_NEXT_PROGRAM_EPOCH, L2_PROGRAM_ROLLBACK_EPOCH), which the
# follower and the producer also run.
CONST = re.compile(r'^pub const (HF[0-9]+_[A-Z0-9_]+_EPOCH|L2_[A-Z0-9_]+_EPOCH|[A-Z0-9_]+_ACTIVATION_EPOCH): u64 =\s*(.+?);\s*$', re.M)
SLICE = re.compile(r'^pub const ([A-Z0-9_]+_RECOVERY_EPOCHS): &\[u64\] = &\[(.*?)\];', re.M)


def value(text):
    text = ' '.join(text.split())
    if text == 'u64::MAX':
        return 'inert'
    if text.replace('_', '').isdigit():
        return int(text.replace('_', ''))
    return '?' + text


def gates(source):
    out = {}
    for name, raw in CONST.findall(source):
        v = value(raw)
        # The same name under two cfgs (mainnet / devnet): keep every distinct value.
        if name in out and out[name] != v:
            out[name] = sorted({json.dumps(out[name]), json.dumps(v)})
        else:
            out[name] = v
    for name, raw in SLICE.findall(source):
        out[name] = [int(x.replace('_', '')) for x in raw.split(',') if x.strip()]
    return dict(sorted(out.items()))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: l1_gates.py params.rs')
    print(json.dumps(gates(open(sys.argv[1]).read()), sort_keys=True))
