#!/usr/bin/env python3
"""The settler's block budget with real binaries and no proof: real producer, real guest in execute mode, on a copy of a
private database. Spool: honest transfers around one 14M-gas modexp transaction. Run with FS set to the drill root."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

R = Path(os.environ['FS'])
RUN = R / 'run'
sys.path.insert(0, str(R / 'src/settler'))
import settler_v3 as S  # noqa: E402

T = R / 'budget-check'
shutil.rmtree(T, ignore_errors=True)
T.mkdir()
shutil.copytree(RUN / 'canonical', T / 'canonical', symlinks=True)
(T / 'txpool').mkdir()
(T / 'work' / 'b').mkdir(parents=True)
cfg = json.loads((RUN / 'settler.json').read_text())
cfg.update(l2_db=str(T / 'canonical'), workdir=str(T / 'work'), txpool_dir=str(T / 'txpool'),
           max_block_instructions=int(os.environ.get('BUDGET', '30000000')), max_block_txs=128, preflight_execute_seconds=int(os.environ.get('EXEC_LIMIT', '30')))
st = S.Settler(cfg)
head = st.produce('head', '--target', cfg['l2_db'])
state = json.loads((RUN / 'state.json').read_text())
user = st.produce('account', '--target', cfg['l2_db'], '--address', state['l2_address_user'])
att = st.produce('account', '--target', cfg['l2_db'], '--address', state['l2_address_attacker'])
for i in range(3):
    st.produce('sign-tx', '--key', str(RUN / 'user.l2.key'), '--nonce', str(user['nonce'] + i), '--to', '00' * 19 + f'{0x80 + i:02x}',
               '--value-wei', '1000000000000', '--out', str(T / 'txpool' / f'{0xa0 + i:02x}.tx'))
gen = T / 'gen'
subprocess.run(['python3', '-I', str(R.parent / 'tools/heavy_gen.py'), 'pc-modexp-512b', '--key', str(RUN / 'attacker.l2.key'), '--out', str(gen),
                '--block-gas', '14000000', '--nonce', str(att['nonce'])], check=True)
shutil.copy2(next(gen.iterdir()), T / 'txpool' / 'a1-evil.tx')
deposits = T / 'work/b/deposits.json'
deposits.write_text('[]')
src = (R / 'budget-source.txt').read_text() if (R / 'budget-source.txt').exists() else None
view = st.rpc(st.native.ports[0], 'getl2settlement')
source = view['source']
slot = int(source['request'].splitlines()[3])
st.preflight_source = source['request'] + 'cd' * 32 + '\n' + f"{source['inbox_count']}\n{source['inbox_count']}\n{source['inbox_count']}\n"
number = head['number'] + 1
for attempt in range(2):
    t = time.time()
    block = st.extend_within_budget(head['hash'], source['block'], deposits, slot, number)
    print(json.dumps({'attempt': attempt, 'seconds': round(time.time() - t, 1), 'number': block['number'], 'transactions': block.get('transactions'),
                      'included': block.get('included'), 'spool_left': sorted(p.name for p in (T / 'txpool').iterdir()),
                      'quarantine': sorted(p.name for p in (T / 'txpool-quarantine').iterdir()) if (T / 'txpool-quarantine').exists() else []}), flush=True)
    head = st.produce('head', '--target', cfg['l2_db'])
    number = head['number'] + 1
    if not list((T / 'txpool').iterdir()):
        break
print(json.dumps({'db_du': subprocess.run(['du', '-sh', str(T / 'canonical')], capture_output=True, text=True).stdout.strip(),
                  'apparent': subprocess.run(['du', '-sh', '--apparent-size', str(T / 'canonical')], capture_output=True, text=True).stdout.strip()}))
shutil.rmtree(T)
