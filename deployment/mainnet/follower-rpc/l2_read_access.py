#!/usr/bin/env python3
"""Give the settled RPC's own user its reader slot in the canonical database (review r10 decision 4).

Run by bloch-l2-mainnet-rpc.service as root (ExecStartPre=+) before every start, so also after the settlement
worker swapped in a rebuilt database:

  l2_read_access.py CANONICAL OWNER GROUP

The RPC opens the MDBX database read-only, but a reader registers in the lock file `db/mdbx.lck`. A reader that
cannot write the lock file is opened without the lock table by libmdbx (measured under systemd: the RPC then maps
only mdbx.dat), and such a reader is not protected from the writer reusing the pages it reads. So the lock file
must be writable by GROUP. This makes `CANONICAL/db/mdbx.lck` group GROUP and group read-write, and nothing else.

It only touches a regular file owned by OWNER (the database writer), reached without following any symlink, and
refuses (exit 1, the RPC does not start) when there is no such lock file. Dependency-free Python 3.9+.
"""
import grp
import os
import pwd
import stat
import sys


def grant(canonical, owner, group):
    uid, gid = pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid
    parts = [part for part in canonical.split('/') if part]
    if not canonical.startswith('/') or not parts or '..' in parts:
        raise SystemExit(f'l2_read_access: {canonical!r} is not an absolute path')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in parts + ['db']:
            try:
                following = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            except OSError as error:  # ELOOP/ENOTDIR on a symlink: never followed
                raise SystemExit(f'l2_read_access: {canonical}: {name}: {error.strerror} (symlinks are not followed)')
            os.close(directory)
            directory = following
        try:
            lock = os.open('mdbx.lck', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except OSError as error:
            raise SystemExit(f'l2_read_access: {canonical}/db/mdbx.lck: {error.strerror} (not an initialized database)')
        try:
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
                raise SystemExit(f'l2_read_access: {canonical}/db/mdbx.lck is not a regular file of {owner}')
            os.fchown(lock, -1, gid)
            os.fchmod(lock, stat.S_IMODE(info.st_mode) | stat.S_IRGRP | stat.S_IWGRP)
        finally:
            os.close(lock)
    finally:
        os.close(directory)
    print(f'l2_read_access: {canonical}/db/mdbx.lck group {group} read-write')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: l2_read_access.py CANONICAL OWNER GROUP')
    grant(*sys.argv[1:])
