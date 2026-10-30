#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Drive an interactive command through a real pty, answering passphrase / DESTROY / RELEASE prompts the way
the owner would type them. Rehearsal only (throwaway passphrases from PASSDIR/pass-I).

  tty_driver.py PASSDIR DEFAULT_INDEX -- CMD ARGS...
"""
import os
import pty
import re
import sys

passdir, default_index = sys.argv[1], sys.argv[2]
cmd = sys.argv[sys.argv.index('--') + 1:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)

current = default_index
buf = b''
answered = 0
while True:
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    sys.stdout.buffer.write(data)
    sys.stdout.flush()
    buf += data
    text = buf.decode(errors='replace')
    for m in re.finditer(r'attestor (\d)', text):
        current = m.group(1)
    tail = text.rstrip()
    last = text.splitlines()[-1] if text.splitlines() else ''
    if not text.endswith(': '):
        continue
    if re.search(r'Type DESTROY (\d) to overwrite', last):
        i = re.findall(r'Type DESTROY (\d)', tail)[-1]
        os.write(fd, f'DESTROY {i}\n'.encode())
        buf = b''
        answered += 1
    elif re.search(r'Type RELEASE (\d)', last):
        i = re.findall(r'Type RELEASE (\d)', tail)[-1]
        os.write(fd, f'RELEASE {i}\n'.encode())
        buf = b''
        answered += 1
    elif re.search(r'passphrase', last, re.I):
        secret = open(os.path.join(passdir, f'pass-{current}')).read().strip()
        os.write(fd, secret.encode() + b'\n')
        buf = b''
        answered += 1
_, status = os.waitpid(pid, 0)
print(f'\n[tty_driver] answered {answered} prompt(s); exit {os.waitstatus_to_exitcode(status)}', file=sys.stderr)
sys.exit(os.waitstatus_to_exitcode(status))
