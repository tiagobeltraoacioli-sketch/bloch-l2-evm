// SPDX-License-Identifier: MIT OR Apache-2.0
// Audit AUDIT-L1L2-20261123, L2N-10: the settled RPC reads block tags without regard to case, so the gateway
// must too. A call at "Finalized" or "SAFE" is a finality read: it goes to the backend whose levels are open,
// not, as a plain read, to the local backend whose levels are closed.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(process.env.GW ?? new URL('../l2rpc-gateway.js', import.meta.url), 'utf8')
  .replace("import cfg from 'l2rpc-config.js';", 'const cfg = injectedConfig;')
  .replace('export default {', 'globalThis.gateway = {');

class Dictionary extends Map {
  keys() { return [...super.keys()]; }
  incr(key, amount, initial) { const next = (this.get(key) ?? initial) + amount; this.set(key, next); return next; }
}

function harness() {
  const shared = { l2rate: new Dictionary(), l2slots: new Dictionary(), l2state: new Dictionary() };
  const now = 1_800_000_000_000;
  class FakeDate extends Date { static now() { return now; } }
  const context = vm.createContext({
    injectedConfig: { role: 'sequencer', peerProbeUrl: 'http://peer/probe', chainId: 700770, chainIdHex: '0xab162',
      stateMaxAgeMs: 15000, maxStatusAgeS: 900, maxBatch: 100, callsPerMinute: 1200, txPerMinute: 30,
      simPerIp: 2, simTotal: 8, maxLagBlocks: 0, maxLogBlockRange: 2000, maxLogAddresses: 16 },
    ngx: { shared }, Date: FakeDate,
  });
  vm.runInContext(source, context);
  // local: head 100, but its levels are CLOSED (follower status invalid). peer: levels open, finalized 90.
  shared.l2state.set('local', JSON.stringify({ ok: true, head: 100, finalized: null, statusState: 'invalid', statusAge: null, ts: now, error: null }));
  shared.l2state.set('peer', JSON.stringify({ ok: true, head: 100, finalized: 90, statusState: 'ok', statusAge: 5, ts: now, error: null }));
  const request = (body) => ({
    requestText: JSON.stringify(body), variables: { remote_addr: '192.0.2.1' }, headersOut: {}, subrequests: [], bodies: [],
    return(status, payload) { this.response = { status, body: payload ? JSON.parse(payload) : null }; },
    internalRedirect(where) { this.redirect = where; },
    async subrequest(where, options) {
      this.subrequests.push(where);
      this.bodies.push(JSON.parse(options.body));
      return { status: 200, responseText: JSON.stringify(JSON.parse(options.body).map((x) => ({ jsonrpc: '2.0', id: x.id, result: '0x1' }))) };
    },
  });
  return { handle: context.gateway.handle, request };
}

const account = '0x' + '11'.repeat(20);
const balance = (tag) => ({ jsonrpc: '2.0', id: 1, method: 'eth_getBalance', params: [account, tag] });
const where = async (body) => {
  const h = harness();
  const r = h.request(body);
  await h.handle(r);
  return { redirect: r.redirect, subrequests: r.subrequests, response: r.response };
};
const toOpenBackend = { redirect: undefined, subrequests: ['/_l2s/peer'], response: undefined };

test('a finality tag in any case is a finality read and goes to the backend whose levels are open', async () => {
  for (const tag of ['finalized', 'Finalized', 'FINALIZED', 'safe', 'Safe', 'SAFE', 'sAfE']) {
    const got = await where(balance(tag));
    assert.deepEqual({ redirect: got.redirect, subrequests: got.subrequests }, { redirect: undefined, subrequests: ['/_l2s/peer'] },
      `the call at "${tag}" was proxied unchanged to ${got.redirect} (the backend with closed levels)`);
  }
});

test('the EIP-1898 object form and a log filter are read the same way', async () => {
  for (const tag of ['Finalized', 'SAFE']) {
    assert.deepEqual((await where({ jsonrpc: '2.0', id: 1, method: 'eth_getBalance', params: [account, { blockNumber: tag }] })).subrequests,
      toOpenBackend.subrequests, tag);
    const logs = await where({ jsonrpc: '2.0', id: 1, method: 'eth_getLogs', params: [{ address: account, fromBlock: '0x5a', toBlock: tag }] });
    assert.deepEqual(logs.subrequests, toOpenBackend.subrequests, `eth_getLogs toBlock ${tag}: ${JSON.stringify(logs.response)}`);
  }
});

test('other tags keep their route, and what is not a tag is still not a level', async () => {
  for (const tag of ['latest', 'Latest', '0x10', 'finalised', 'safe ']) {
    const got = await where(balance(tag));
    assert.notDeepEqual(got.subrequests, toOpenBackend.subrequests, tag);
  }
});

test('"Pending" is the pending tag for the nonce route, as "pending" is', async () => {
  const count = (tag) => ({ jsonrpc: '2.0', id: 1, method: 'eth_getTransactionCount', params: [account, tag] });
  const lower = await where(count('pending'));
  for (const tag of ['Pending', 'PENDING']) {
    assert.deepEqual(await where(count(tag)), lower, tag);
  }
  assert.notDeepEqual(await where(count('latest')), await where(count('Finalized')));
});
