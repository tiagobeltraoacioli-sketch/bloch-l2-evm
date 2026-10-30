#!/usr/bin/env python3
"""Test double of `bloch-l2-produce-dev reconstruct`, driven by the JSON file in REPLICA_FAKE_PRODUCE."""
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
fixture = json.loads(Path(os.environ['REPLICA_FAKE_PRODUCE']).read_text())
if args[0] != 'reconstruct' or '--l1-follower' not in args or '--rules' not in args:
    sys.exit('unexpected command')
if fixture.get('fail'):
    sys.exit('fixture: reconstruct fails')
target = Path(args[args.index('--target') + 1])
target.mkdir()
for d in ('db', 'static', 'rocks'):
    (target / d).mkdir()
print(json.dumps(fixture['report']))
