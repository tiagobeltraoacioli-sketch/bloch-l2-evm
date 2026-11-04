#!/usr/bin/env python3
"""Exercise quote -> explicit re-sign -> spool on the disposable Rust RPC fixture.

Start the ignored serve_disposable_admission_rehearsal test first. This driver
accepts only its loopback/devnet schema and public test key. It never mines a
block and reports admission separately from inclusion. No automatic retry.
"""
import argparse
import json
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request


def rehearse(fixture, cast):
    url = urllib.parse.urlsplit(fixture['rpc'])
    if (fixture['schema'] != 'bloch-admission-rehearsal-v1' or url.scheme != 'http'
            or url.hostname != '127.0.0.1' or fixture['chain_id'] != 700771
            or fixture['test_private_key'] != '0x' + '07' * 32 or fixture['nonce'] != 1):
        raise ValueError('only the disposable loopback fixture and its public test key are permitted')

    def rpc(method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        request = urllib.request.Request(fixture['rpc'], data=body, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=20) as response:
            value = json.load(response)
        if value.get('jsonrpc') != '2.0' or value.get('id') != 1:
            raise ValueError('unexpected RPC envelope')
        return value

    def run_cast(*args):
        result = subprocess.run([cast, *args], text=True, capture_output=True, timeout=30)
        if result.returncode:
            # Do not include argv: it contains the fixture's signing key.
            raise RuntimeError('cast failed: ' + result.stderr[:1000])
        return result.stdout.strip()

    pool = Path(fixture['spool'])
    if int(rpc('eth_chainId', [])['result'], 16) != 700771:
        raise ValueError('the listener is not the disposable devnet chain')
    if list(pool.glob('*.tx')):
        raise ValueError('rehearsal needs an unused fixture spool')
    head = rpc('eth_blockNumber', [])['result']
    refused = rpc('eth_sendRawTransaction', [fixture['underpriced_approve_raw']])
    error = refused.get('error', {})
    quote = error.get('data', {})
    assert error.get('code') == -32000 and quote.get('kind') == 'sequencer-fee-underpriced'
    assert quote['transactionHash'] == fixture['underpriced_approve_hash']
    assert quote['scope'] == 'latest-state-next-block'
    required = int(quote['requiredPriorityFeePerGas'], 16)
    cap = int(quote['requiredMaxFeePerGas'], 16)
    assert cap == required + int(quote['baseFeePerGas'], 16)
    assert not list(pool.iterdir()), 'a fee refusal changed the spool'
    # This explicit rehearsal step signs exactly the quoted price. Production
    # clients must obtain user approval and must never silently raise budgets.
    raw = run_cast('mktx', fixture['token'], 'approve(address,uint256)', '0x' + '22' * 20, '1',
                   '--chain', '700771', '--nonce', '1', '--gas-limit', '200000',
                   '--gas-price', str(cap), '--priority-gas-price', str(required),
                   '--private-key', fixture['test_private_key'], '--rpc-url', fixture['rpc'])
    expected = run_cast('keccak', raw)
    admitted = rpc('eth_sendRawTransaction', [raw])
    assert admitted.get('result') == expected, admitted
    entry = pool / (expected[2:] + '.tx')
    assert entry.read_text().strip() == raw.removeprefix('0x')
    assert rpc('eth_sendRawTransaction', [raw]).get('result') == expected, 'duplicate admission is not idempotent'
    pending = rpc('eth_getTransactionCount', [fixture['sender'], 'pending'])['result']
    latest = rpc('eth_getTransactionCount', [fixture['sender'], 'latest'])['result']
    assert int(pending, 16) == 2 and int(latest, 16) == 1
    assert rpc('eth_blockNumber', [])['result'] == head
    assert rpc('eth_getTransactionReceipt', [expected])['result'] is None
    return {'schema': 'bloch-admission-rehearsal-result-v1', 'refusal': refused,
            'admitted_hash': expected, 'spooled': True, 'included': False,
            'pending_nonce': pending, 'canonical_nonce': latest, 'head': head,
            'required_priority_fee_wei': str(required), 'required_max_fee_wei': str(cap)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    parser.add_argument('--cast', default='cast')
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = rehearse(json.loads(args.fixture.read_text()), args.cast)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('admitted_hash', 'spooled', 'included', 'pending_nonce')}))


if __name__ == '__main__':
    main()
