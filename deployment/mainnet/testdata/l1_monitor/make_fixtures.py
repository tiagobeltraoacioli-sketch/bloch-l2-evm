#!/usr/bin/env python3
"""Turns recorded private-net probes into replay fixtures for test_l1_monitor.py.

Sources (read only): the `probes.jsonl` and `verdict.json` files that agents 69 and 79 recorded on private 1 s-slot
nets of real bloch-pos rehearsal binaries (see each fixture's `source`). A probe holds, for one "online" node and one
"returned" node, the fields of `getchaininfo` it kept (slot, height, finalized, justified, block_id), and the answer of
`getblockbyid` for the other node's head on each of them (true, or the error text, cut at 120 characters by the
recorder). The verdict's `phases` give every node's finalized epoch and head prefix at the same epoch, and the metrics
lines of both nodes. The online node is node 0 and the returned node the lowest-numbered node of `args.offline`.
A probe with no phase at its epoch (the first, "back") takes membership from `args.offline` (`membership: args`).

What this script adds, and labels: a node whose head prefix matches neither recorded node is `derived` (only its
finalized epoch and head prefix are recorded); its view is built from those, and its `getblockbyid` answers are
assumed to be "no block" both ways. A pair inside one group (same head) answers true.

  python3 make_fixtures.py EVIDENCE_DIR OUT_DIR
"""
import json
import sys
from pathlib import Path

CASES = {
    # name: (probes, verdict, description)
    'p1noq': ('69-orphan-recovery-evidence/verdicts/p1noq/probes.jsonl', '69-orphan-recovery-evidence/verdicts/p1noq/verdict.json',
              '14 validators; nodes 9-13 cut off and returned (partition), verdict SPLIT: 9-13 stuck at finalized e14'),
    'th2': ('69-orphan-recovery-evidence/verdicts/th2/probes.jsonl', '69-orphan-recovery-evidence/verdicts/th2/verdict.json',
            '14 validators; nodes 9-13 restarted under a held cut, verdict SPLIT: 9-13 stuck at finalized e14'),
    'ju': ('79-orphan-review-evidence/verdicts/ju-probes.jsonl', '79-orphan-review-evidence/verdicts/ju.json',
           '5 validators, each isolated e14-e76; after the heal every node on its own head, finality stalled at e12'),
    'k2': ('79-orphan-review-evidence/verdicts/k2-probes.jsonl', '79-orphan-review-evidence/verdicts/k2.json',
           '5 validators, groups {0,1} {2,4} {3,5} isolated e14-e40; afterwards 2-4 finalize, 0 stays at e12 and 1 at e13'),
    'w1fix': ('69-orphan-recovery-evidence/verdicts/w1fix/probes.jsonl', '69-orphan-recovery-evidence/verdicts/w1fix/verdict.json',
              '14 validators; nodes 9-13 out e16-e22, then wiped and resynced, verdict REJOINED'),
    'h2fix': ('69-orphan-recovery-evidence/verdicts/h2fix/probes.jsonl', '69-orphan-recovery-evidence/verdicts/h2fix/verdict.json',
              '14 validators; nodes 9-13 restarted after an outage, catch up, verdict REJOINED'),
}
KEEP = ('slot', 'height', 'finalized', 'justified', 'block_id')


def build(evidence: Path, name: str):
    probes_path, verdict_path, about = CASES[name]
    probes = [json.loads(line) for line in (evidence / probes_path).read_text().splitlines() if line.strip()]
    verdict = json.loads((evidence / verdict_path).read_text())
    phases = {ph['epoch']: ph for ph in verdict['phases']}
    rounds = []
    for pr in probes:
        on, back = pr['online'], pr['returned']
        ph = phases.get(pr['epoch'])
        groups = {'online': on, 'returned': back}
        nodes, derived, membership = {}, [], 'phase'
        metrics = {}
        if ph:
            # Group membership comes from the phase: a node is in a recorded node's group when its (finalized, head)
            # equals that representative's in the same phase. The phase heads were read a moment apart from the probe,
            # so the probe's own views are used for the members.
            reps = {'online': '0', 'returned': str(min(int(x) for x in verdict['args']['offline'].split(',')))}
            rep_key = {g: (ph['nodes'][n]['fin'], ph['nodes'][n]['head']) for g, n in reps.items()}
            for n, v in sorted(ph['nodes'].items(), key=lambda kv: int(kv[0])):
                match = [g for g in ('returned', 'online') if (v['fin'], v['head']) == rep_key[g]]
                if match:
                    nodes[f'n{n}'] = {'group': match[0], 'view': {k: groups[match[0]][k] for k in KEEP}}
                    metrics[f'n{n}'] = '\n'.join(ph.get(f'metrics_{match[0]}') or []) or None
                else:
                    view = {'slot': on['slot'], 'height': None, 'finalized': {'epoch': v['fin'], 'root': None},
                            'justified': None, 'block_id': v['head'] + '0' * (64 - len(v['head']))}
                    nodes[f'n{n}'] = {'group': f'derived-{v["head"]}', 'view': view}
                    metrics[f'n{n}'] = None
                    derived.append(f'n{n}')
        else:  # no phase at this epoch: membership from the run's arguments (offline nodes = the returned group)
            offline = {int(x) for x in verdict['args']['offline'].split(',')}
            for n in range(int(verdict['args']['validators'])):
                g = 'returned' if n in offline else 'online'
                nodes[f'n{n}'] = {'group': g, 'view': {k: groups[g][k] for k in KEEP}}
                metrics[f'n{n}'] = None
            membership = 'args'
        answers = {}
        for a, na in nodes.items():
            answers[a] = {}
            for b, nb in nodes.items():
                if na['group'] == nb['group']:
                    ans = True
                elif {na['group'], nb['group']} == {'online', 'returned'}:
                    ans = pr['online_has_returned_head'] if na['group'] == 'online' else pr['returned_has_online_head']
                else:
                    ans = f'getblockbyid: rpc error -32000: no block {nb["view"]["block_id"]} (derived: assumed)'
                answers[a][nb['view']['block_id']] = ans
        rounds.append({'tag': pr['tag'], 'epoch': pr['epoch'], 'now': on['slot'],
                       'getchaininfo': {n: v['view'] for n, v in nodes.items()},
                       'getblockbyid': answers, 'metrics': metrics, 'derived': derived,
                       'membership': membership})
    return {'case': name, 'about': about, 'source': [f'agents/{probes_path}', f'agents/{verdict_path}'],
            'verdict': verdict.get('verdict'), 'slot_seconds': 1, 'slots_per_epoch': 32, 'genesis_time': 0,
            'note': 'getchaininfo views are the recorded fields only; `derived` nodes are reconstructed (see make_fixtures.py)',
            'rounds': rounds}


def main():
    evidence, out = Path(sys.argv[1]), Path(sys.argv[2])
    for name in CASES:
        (out / f'{name}.json').write_text(json.dumps(build(evidence, name), indent=1, sort_keys=True) + '\n')
        print(name)


if __name__ == '__main__':
    main()
