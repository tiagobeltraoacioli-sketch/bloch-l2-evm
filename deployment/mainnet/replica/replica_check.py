#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only checks of a Bloch L2 mainnet replica. Sends no transaction and needs no key.

  replica_check.py preflight --l1 URL [--l1 URL ...]
      Each L1 RPC must answer for the pinned network, genesis, chain id and L2 activation.
  replica_check.py verify --rpc URL --status FILE --l1 URL [--l1 URL ...] [--max-lag-epochs 8]
      The replica RPC, its follower status and the L1 RPCs must agree. Prints one JSON document.

Exit 0: every check passed. Exit 1: a check failed. Exit 2: usage.
"""
import argparse
import json
import sys
import urllib.request
from pathlib import Path

NETWORK = 'f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966'
L1_GENESIS = '9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415'
CHAIN_ID = 700770
ACTIVATION_BLOCK = '618c9b80cebda5b5bda0b0c7d79e19dae8dc24e773aa94a2c135eb805ff0dc9f'
L2_GENESIS = '632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468'
L2_STATE_ROOT = '2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d'
SCHEMA = 'bloch.l2.native-follower-status.v2'


def rpc(url, method, params=(), timeout=20):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    req = urllib.request.Request(url, body, {'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        doc = json.load(r)
    if doc.get('error'):
        raise RuntimeError(f'{method}: {doc["error"]}')
    return doc['result']


class Report:
    def __init__(self):
        self.checks = []

    def check(self, name, ok, **detail):
        self.checks.append({'check': name, 'ok': bool(ok), **detail})

    def finish(self, **extra):
        ok = all(c['ok'] for c in self.checks)
        print(json.dumps({'ok': ok, **extra, 'checks': self.checks}, indent=1))
        return 0 if ok else 1


def strip0x(text):
    return (text or '').lower().removeprefix('0x')


def check_l1(report, url):
    """Identity of one L1 RPC; returns its (finalized epoch, finalized root, settlement view)."""
    try:
        view = rpc(url, 'getl2settlement')
        info = rpc(url, 'getchaininfo')
    except Exception as e:
        report.check('l1-answers', False, url=url, error=str(e)[:300])
        return None
    report.check('l1-identity', (view.get('network'), view.get('genesis'), view.get('chain_id')) == (NETWORK, L1_GENESIS, CHAIN_ID),
                 url=url, network=view.get('network'), genesis=view.get('genesis'), chain_id=view.get('chain_id'))
    report.check('l1-activation', (view.get('source') or {}).get('block') == ACTIVATION_BLOCK, url=url,
                 block=(view.get('source') or {}).get('block'))
    return info['finalized']['epoch'], info['finalized']['root'], view


def preflight(a):
    report = Report()
    for url in a.l1:
        check_l1(report, url)
    return report.finish(mode='preflight')


def verify(a):
    report = Report()
    status = json.loads(Path(a.status).read_text())
    genesis = status.get('l2_genesis') or {}
    report.check('status-identity', status.get('schema') == SCHEMA and status.get('network') == NETWORK
                 and status.get('chain_id') == CHAIN_ID and status.get('production_finality') is False)
    report.check('status-l2-genesis', genesis.get('hash') == L2_GENESIS and genesis.get('state_root') == L2_STATE_ROOT
                 and genesis.get('activation_block') == ACTIVATION_BLOCK and genesis.get('finalized') is True, l2_genesis=genesis)
    chain = rpc(a.rpc, 'eth_chainId')
    report.check('rpc-chain-id', int(chain, 16) == CHAIN_ID, chain_id=chain)
    block0 = rpc(a.rpc, 'eth_getBlockByNumber', ['0x0', False])
    report.check('rpc-genesis', strip0x(block0['hash']) == L2_GENESIS and strip0x(block0['stateRoot']) == L2_STATE_ROOT,
                 hash=block0['hash'], state_root=block0['stateRoot'])
    finalized = rpc(a.rpc, 'eth_getBlockByNumber', ['finalized', False])
    latest = rpc(a.rpc, 'eth_getBlockByNumber', ['latest', False])
    settlements = status.get('finalized_settlements', [])
    want = settlements[-1]['l2_hash'] if settlements else L2_GENESIS
    report.check('rpc-finalized-matches-status', finalized is not None and strip0x(finalized['hash']) == strip0x(want),
                 finalized=finalized and finalized['hash'], want=want)
    report.check('rpc-latest-not-below-finalized', finalized is not None and int(latest['number'], 16) >= int(finalized['number'], 16),
                 latest=latest['number'])
    view = rpc(a.rpc, 'bloch_finality')
    report.check('rpc-finality-view', view.get('l2_genesis', {}).get('hash') == L2_GENESIS, finalized_height=view.get('finalized_height'),
                 l1_finalized=view.get('l1', {}).get('finalized'))
    logs = rpc(a.rpc, 'eth_getLogs', [{'fromBlock': '0x0', 'toBlock': 'finalized'}])
    report.check('rpc-logs-answer', isinstance(logs, list), count=len(logs))
    for url in a.l1:
        l1 = check_l1(report, url)
        if l1 is None:
            continue
        epoch, _, settlement = l1
        lag = epoch - status.get('native_finalized_epoch', 0)
        report.check('follower-lag-within-bound', -1 <= lag <= a.max_lag_epochs, url=url, l1_finalized_epoch=epoch,
                     follower_finalized_epoch=status.get('native_finalized_epoch'), lag_epochs=lag)
        if settlement.get('accepted') is None:
            report.check('no-settlement-on-l1-nor-replica', not settlements, url=url)
    return report.finish(mode='verify', rpc=a.rpc, verified_tip=status.get('verified_tip'),
                         verified_blocks=status.get('verified_blocks'), native_finalized_epoch=status.get('native_finalized_epoch'),
                         native_finalized_block=status.get('native_finalized_block'))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = p.add_subparsers(dest='cmd', required=True)
    f = sub.add_parser('preflight')
    f.add_argument('--l1', action='append', required=True)
    v = sub.add_parser('verify')
    v.add_argument('--rpc', required=True)
    v.add_argument('--status', required=True)
    v.add_argument('--l1', action='append', required=True)
    v.add_argument('--max-lag-epochs', type=int, default=8)
    a = p.parse_args(argv)
    return preflight(a) if a.cmd == 'preflight' else verify(a)


if __name__ == '__main__':
    sys.exit(main())
