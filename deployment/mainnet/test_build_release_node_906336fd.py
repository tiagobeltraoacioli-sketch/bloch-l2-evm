"""The release recipe can build against node release 906336fd, with one pinned lock.

Node release 906336fd arms two consensus rules at epoch 8620 that native 78d4921c does not have. The follower and
the producer replay L1 consensus with the native code they link, so the next L2 release must link 906336fd
(docs/L2-FOLLOWER-NODE-906336FD.md). These checks read the recipe; they build nothing.
"""
import hashlib
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECIPE = (HERE / 'build-release.sh').read_text()
COMMIT = '906336fd35f157dac380523b59dee8a5a325175a'
LOCK = HERE / 'follower-rpc' / 'settlement-recovery.native-906336fd.Cargo.lock'


class Node906336fdRecipe(unittest.TestCase):
    def test_the_recipe_names_the_commit_and_pins_the_lock_that_is_in_the_kit(self):
        self.assertIn(f'NODE_906336FD_COMMIT={COMMIT}', RECIPE)
        pinned = re.search(r'^NODE_906336FD_LOCK_SHA256=([0-9a-f]{64})$', RECIPE, re.M).group(1)
        self.assertEqual(pinned, hashlib.sha256(LOCK.read_bytes()).hexdigest())
        self.assertIn('follower-rpc/settlement-recovery.native-906336fd.Cargo.lock', RECIPE)

    def test_another_lock_for_that_commit_is_refused(self):
        self.assertRegex(RECIPE, r'is not the pinned lock \$NODE_906336FD_LOCK_SHA256 of native \$NODE_906336FD_COMMIT')

    def test_the_signed_release_stays_the_default(self):
        self.assertIn('NATIVE_COMMIT=${NATIVE_COMMIT:-78d4921c3ec6ba41829f3878eed47f8d3bb96230}', RECIPE)

    def test_the_lock_resolves_the_node_crates_the_l2_links(self):
        text = LOCK.read_text()
        for name in ('bloch-pos-committee', 'bloch-pos-node', 'bloch-crypto', 'bloch-l2-proof', 'pqcrypto-mlkem'):
            self.assertIn(f'name = "{name}"', text)


if __name__ == '__main__':
    unittest.main()
