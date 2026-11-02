#!/usr/bin/env python3
"""Read-only: did L1 finality ever lag since an epoch? Answers from block headers, so it needs no earlier sampling.

Each block header carries `finalized_root`. For every epoch in the range this takes the last block of the epoch,
finds the block that root names, and reports epoch minus that block's epoch. A checkpoint whose first slot was empty
names an earlier block, so a single epoch can read one too high: the exit status allows for it with --max-lag.

  l1_finality_history.py --rpc URL --from-epoch 7180 [--to-epoch N] [--max-lag 4] [--slots-per-epoch 32]

Prints one JSON document. Exit: 0 no epoch over the limit, 2 at least one over the limit, 3 could not read.
Calls getchaininfo, getblockbyslot and getblockbyid only. Dependency-free Python 3.9+.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request


class Empty(Exception):
    pass


def call(url, method, *params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    request = urllib.request.Request(url, body, {'content-type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        reply = json.load(response)
    if reply.get('error'):
        raise Empty(str(reply['error']))
    return reply['result']


def last_block(url, epoch, slots):
    """The last canonical block of an epoch, or None if the whole epoch is empty."""
    for slot in range((epoch + 1) * slots - 1, epoch * slots - 1, -1):
        try:
            return call(url, 'getblockbyslot', slot)
        except Empty:
            continue
    return None


def history(url, first, last, slots, get_block=last_block, get_root=None):
    get_root = get_root or (lambda root: call(url, 'getblockbyid', root))
    known, lags, empty = {}, {}, []
    for epoch in range(first, last + 1):
        block = get_block(url, epoch, slots)
        if block is None:
            empty.append(epoch)
            continue
        root = block['finalized_root']
        if root not in known:
            known[root] = get_root(root)['epoch']
        lags[epoch] = epoch - known[root]
    return lags, empty


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--rpc', required=True)
    parser.add_argument('--from-epoch', type=int, required=True)
    parser.add_argument('--to-epoch', type=int)
    parser.add_argument('--max-lag', type=int, default=4)
    parser.add_argument('--slots-per-epoch', type=int, default=32)
    options = parser.parse_args()
    try:
        info = call(options.rpc, 'getchaininfo')
        # The newest finished epoch: the current one has no last block yet.
        last = options.to_epoch if options.to_epoch is not None else info['epoch'] - 1
        lags, empty = history(options.rpc, options.from_epoch, last, options.slots_per_epoch)
    except (OSError, ValueError, KeyError, TypeError, Empty, urllib.error.URLError) as why:
        print(json.dumps({'ok': False, 'error': str(why)}))
        sys.exit(3)
    over = {epoch: lag for epoch, lag in lags.items() if lag > options.max_lag}
    ok = bool(lags) and not over and not empty
    print(json.dumps({'ok': ok, 'from_epoch': options.from_epoch, 'to_epoch': last, 'epochs_read': len(lags),
                      'max_lag_seen': max(lags.values(), default=None), 'limit': options.max_lag,
                      'over_limit': over, 'empty_epochs': empty}, indent=1))
    sys.exit(0 if ok else 2)


if __name__ == '__main__':
    main()
