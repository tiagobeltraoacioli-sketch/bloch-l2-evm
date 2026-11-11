#!/usr/bin/env python3
"""D4: the settler installer accepts 4 (or 5) L1 RPCs on distinct hosts ("at least 3"); install-shadow.sh then writes
the shadow config with the literal "rpc_quorum": 2, which the SHIPPED sequencer_mainnet.py refuses (Halt, exit 3) for
any list longer than 3. Imports the kit files by path; no root, no network."""
import hashlib, importlib.util, os, re, sys, tempfile, unittest
sys.dont_write_bytecode = True
W = str(__import__('pathlib').Path(__file__).resolve().parents[1])
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m); return m
settler = load('settler_installer', W + '/install-settler-mainnet.py')
seq = load('sequencer_mainnet_kit', W + '/sequencer_mainnet.py')

class D4(unittest.TestCase):
    def test_four_rpcs_accepted_by_the_settler_work_in_the_shadow(self):
        urls = settler.l1_rpc_urls(['--rpc-urls', ','.join(f'http://192.0.2.{i}:8080' for i in (1, 2, 3, 4))], environ={})
        self.assertEqual(len(urls), 4)                                   # settler configure: accepted, quorum 3
        text = open(W + '/install-shadow.sh').read()
        quorum = int(re.search(r'^  "rpc_quorum": (\d+),$', text, re.M).group(1))   # what install-shadow.sh writes
        print('install-shadow.sh writes rpc_quorum =', quorum, 'for', len(urls), 'rpc_urls')
        d = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        produce = os.path.join(d, 'produce'); open(produce, 'wb').write(b'x')
        config = {'produce': produce, 'produce_sha256': hashlib.sha256(b'x').hexdigest(), 'l2_db': d + '/canonical',
                  'workdir': d + '/work', 'rpc_urls': urls, 'rpc_quorum': quorum, 'poll_seconds': 15,
                  'settler_workdir': d + '/settler-work'}
        try:
            seq.Sequencer(config)
        except seq.Halt as e:
            self.fail(f'shadow halts on the config install-shadow.sh generates: {e}')

if __name__ == '__main__':
    unittest.main(verbosity=2)
