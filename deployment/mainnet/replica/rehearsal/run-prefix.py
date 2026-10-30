#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the units rendered by `install-replica.sh --prefix` without systemd: what ExecStart says, nothing else.

  run-prefix.py PREFIX exec UNIT     run the unit's ExecStartPre lines, then exec its ExecStart
  run-prefix.py PREFIX print UNIT    print the argv

Reading the argv from the rendered unit means a rehearsal exercises the exact command line a real
install would run. It does not exercise the unit's sandbox or its resource limits.
"""
import os
import shlex
import subprocess
import sys
from pathlib import Path


def lines(unit, key):
    return [l.split('=', 1)[1] for l in unit.read_text().splitlines() if l.startswith(key + '=')]


def expand(text, env):
    for k, v in env.items():
        text = text.replace('${' + k + '}', v)
    return text


def main():
    prefix, action, name = sys.argv[1:4]
    unit = Path(prefix, 'systemd', name)
    env = {}
    for path in lines(unit, 'EnvironmentFile'):
        for line in Path(path).read_text().splitlines():
            k, _, v = line.partition('=')
            env[k] = v
    argv = shlex.split(expand(lines(unit, 'ExecStart')[0], env))
    if action == 'print':
        print(shlex.join(argv))
        return
    for pre in lines(unit, 'ExecStartPre'):
        subprocess.run(shlex.split(expand(pre, env)), check=True)
    os.execv(argv[0], argv)


if __name__ == '__main__':
    main()
