"""F8: a prover run's process group is killed on a timeout and after exit, and only the SP1 segments that group
mapped are removed. Linux only (reads /proc)."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import settler_v3 as s  # noqa: E402

CHILD = textwrap.dedent('''
    import mmap, os, subprocess, sys, time
    shm, mode = sys.argv[1], sys.argv[2]
    path = os.path.join(shm, 'sp1_test_' + str(os.getpid()))
    with open(path, 'wb') as f:
        f.write(b'\\0' * 4096)
    for end in ('empty', 'filled'):
        open(os.path.join(shm, 'sem.sp1_test_' + str(os.getpid()) + '_' + end), 'w').close()
    f = open(path, 'r+b'); m = mmap.mmap(f.fileno(), 4096)
    grandchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])
    open(os.path.join(shm, 'grandchild.pid'), 'w').write(str(grandchild.pid))
    if mode == 'exit':
        time.sleep(1.5)
        sys.exit(0)
    time.sleep(600)
''')


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        return Path(f'/proc/{pid}/stat').read_text().split()[2] != 'Z'
    except OSError:
        return False


@unittest.skipUnless(Path('/proc/self/maps').exists(), 'needs /proc')
class F8(unittest.TestCase):
    def run_case(self, mode, timeout):
        with tempfile.TemporaryDirectory() as shm:
            foreign = Path(shm) / 'sp1_other_job'
            foreign.write_bytes(b'x')
            settler = s.Settler.__new__(s.Settler)
            settler.run, settler.c = subprocess.run, {'prover_shm_dir': shm}
            raised = False
            try:
                result = settler.run_bounded([sys.executable, '-c', CHILD, shm, mode], timeout=timeout,
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                raised, result = True, None
            grandchild = int((Path(shm) / 'grandchild.pid').read_text())
            time.sleep(0.5)
            left = sorted(p.name for p in Path(shm).iterdir() if p.name.startswith(('sp1_', 'sem.sp1_')))
            return raised, result, alive(grandchild), left

    def test_timeout_kills_the_group_and_removes_its_segments_only(self):
        raised, _, grandchild_alive, left = self.run_case('hang', 4)
        self.assertTrue(raised)
        self.assertFalse(grandchild_alive)
        self.assertEqual(left, ['sp1_other_job'])

    def test_exit_kills_what_the_run_left_and_removes_its_segments_only(self):
        raised, result, grandchild_alive, left = self.run_case('exit', 60)
        self.assertFalse(raised)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(grandchild_alive)
        self.assertEqual(left, ['sp1_other_job'])

    def test_an_injected_runner_is_used_as_given(self):
        calls = []
        settler = s.Settler.__new__(s.Settler)
        settler.run, settler.c = (lambda argv, **kw: calls.append((argv, kw)) or subprocess.CompletedProcess(argv, 0)), {}
        settler.run_bounded(['x'], timeout=5)
        self.assertEqual(calls, [(['x'], {'timeout': 5})])


if __name__ == '__main__':
    unittest.main()
