#!/usr/bin/env python3
"""Refuse source changes not represented by a pinned release build.

The native checkout may carry exactly the documented inert feature shim. A
native revision that already defines both features needs no shim. Reth has a
separate exact-patch verifier in integrations/reth-execution/prepare-reth.py.
"""
import argparse
import importlib.util
from pathlib import Path
import subprocess


HERE = Path(__file__).resolve().parent
SHIM_PATH = HERE / 'follower-rpc' / 'native-feature-shim.py'
module_spec = importlib.util.spec_from_file_location('native_build_shim', SHIM_PATH)
shim = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(shim)
MANIFESTS = tuple(f'crates/{crate}/Cargo.toml' for crate in ('bloch-pos-committee', 'bloch-pos-node'))


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def require(ok, message):
    if not ok:
        raise ValueError(message)


def worktree(root):
    root = Path(root)
    require(not root.is_symlink(), f'{root}: source root must not be a symlink')
    actual = Path(git(root, 'rev-parse', '--show-toplevel').decode().strip())
    require(actual.resolve() == root.resolve(), f'{root}: expected a worktree root')
    flags = git(root, 'ls-files', '-v', '-z').split(b'\0')
    require(all(not entry or (not entry[:1].islower() and entry[:1] != b'S') for entry in flags),
            f'{root}: index flags can hide source edits')


def verify_l2(root):
    worktree(root)
    require(not git(root, 'status', '--porcelain', '--untracked-files=all'),
            'L2 release source must be committed and clean, including untracked files')


def verify_native(root, expected_revision, applied=False):
    root = Path(root)
    worktree(root)
    require(git(root, 'rev-parse', 'HEAD').decode().strip() == expected_revision,
            'Native revision differs from the selected release')
    require(not git(root, 'diff', '--cached', '--name-only'), 'Native source has staged changes')
    require(not git(root, 'ls-files', '--others', '--exclude-standard'), 'Native source has untracked files')
    changed = set(filter(None, git(root, 'diff', '--no-ext-diff', '--name-only', '-z').decode().split('\0')))
    require(changed <= set(MANIFESTS), 'Native source has changes outside the two feature-shim manifests')
    for name in MANIFESTS:
        original = git(root, 'show', f'HEAD:{name}')
        text = original.decode()
        # Use the same transformation as the build shim, but on the committed
        # bytes, never on a possibly edited worktree manifest.
        expected = shim.shimmed_text(text, name).encode()
        path = root / name
        require(not path.is_symlink() and path.is_file(), f'{name}: manifest must be a regular file')
        allowed = (expected,) if applied else (original, expected)
        require(path.read_bytes() in allowed, f'{name}: edits differ from the exact inert feature shim')
        # Content equality alone would overlook an executable-bit edit.
        require(not git(root, 'diff', '--no-ext-diff', '--summary', '--', name),
                f'{name}: manifest mode or identity changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--l2', required=True, type=Path)
    parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--native-revision', required=True)
    parser.add_argument('--shim-applied', action='store_true')
    args = parser.parse_args()
    try:
        verify_l2(args.l2)
        verify_native(args.native, args.native_revision, args.shim_applied)
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.exit(2, f'build source verification failed: {error}\n')
    print('Verified clean L2 source and exact native feature shim')


if __name__ == '__main__':
    main()
