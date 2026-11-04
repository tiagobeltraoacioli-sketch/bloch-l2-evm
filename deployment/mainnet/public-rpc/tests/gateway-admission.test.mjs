// SPDX-License-Identifier: MIT OR Apache-2.0
// Exercise the actual njs handler with an in-memory shared dictionary and
// controlled transport. nginx rendering and live transport have separate tests.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../l2rpc-gateway.js', import.meta.url), 'utf8')
  .replace("import cfg from 'l2rpc-config.js';", 'const cfg = injectedConfig;')
  .replace('export default {', 'globalThis.gateway = {');
const hash = '0x' + 'ab'.repeat(32);
const call = (method = 'eth_sendRawTransaction', id = 'client-id') =>
  ({ jsonrpc: '2.0', id, method, params: method === 'eth_sendRawTransaction' ? ['0x01'] : [{}, 'latest'] });

class Dictionary extends Map {
  incr(key, amount, initial) {
    const next = (this.get(key) ?? initial) + amount;
    this.set(key, next);
    return next;
  }
}

function harness(overrides = {}) {
  const shared = { l2rate: new Dictionary(), l2state: new Dictionary() };
  const context = vm.createContext({
    injectedConfig: {
      role: 'sequencer', peerProbeUrl: 'http://peer/probe',
      chainId: 31337, chainIdHex: '0x7a69', stateMaxAgeMs: 60000,
      maxStatusAgeS: 60, maxBatch: 20, callsPerMinute: 1000,
      txPerMinute: 100, simPerIp: 1, simTotal: 2, ...overrides,
    },
    ngx: { shared },
  });
  vm.runInContext(source, context);
  const requests = [];
  const request = (body = call(), ip = '192.0.2.1', transport) => {
    const r = {
      requestText: JSON.stringify(body), variables: { remote_addr: ip }, headersOut: {},
      subrequests: [],
      return(status, payload) { this.response = { status, body: payload ? JSON.parse(payload) : null }; },
      internalRedirect(where) { this.redirect = where; },
      async subrequest(where, options) {
        this.subrequests.push({ where, body: JSON.parse(options.body) });
        if (transport) return transport(where, options);
        return { status: 200, responseText: JSON.stringify(JSON.parse(options.body)
          .filter((x) => x.id !== undefined).map((x) => ({ jsonrpc: '2.0', id: x.id, result: hash }))) };
      },
    };
    requests.push(r);
    return r;
  };
  const slots = () => [...shared.l2rate].filter(([key]) => key.startsWith('s ') || key.startsWith('S '));
  return { handle: context.gateway.handle, request, slots, shared, requests };
}

function deferredReply() {
  let release;
  const promise = new Promise((resolve) => { release = resolve; });
  return { transport: () => promise, release: () => release({ status: 200,
    responseText: JSON.stringify([{ jsonrpc: '2.0', id: 0, result: hash }]) }) };
}

test('raw admission uses one sequencer subrequest and releases its EVM slots', async () => {
  const h = harness();
  const r = h.request();
  await h.handle(r);
  assert.equal(r.redirect, undefined);
  assert.equal(r.subrequests.length, 1);
  assert.equal(r.subrequests[0].where, '/_l2s/seq');
  assert.equal(r.response.body.id, 'client-id');
  assert.equal(r.response.body.result, hash);
  assert.ok(h.slots().length > 0);
  assert.ok(h.slots().every(([, value]) => value === 0));
});

test('underpriced admission data survives unchanged, with no retry', async () => {
  const h = harness();
  const error = { code: -32000, message: 'storage tip too low', data: {
    kind: 'sequencer-fee-underpriced', transactionHash: hash,
    requiredPriorityFeePerGas: '0x123', requiredMaxFeePerGas: '0x124',
  } };
  const r = h.request(call(), undefined, async () => ({ status: 200,
    responseText: JSON.stringify([{ jsonrpc: '2.0', id: 0, error }]) }));
  await h.handle(r);
  assert.deepEqual(r.response.body.error, error);
  assert.equal(r.subrequests.length, 1);
});

for (const [name, transport] of [
  ['HTTP failure', async () => ({ status: 502, responseText: '' })],
  ['malformed reply', async () => ({ status: 200, responseText: '{' })],
  ['subrequest exception', async () => { throw new Error('connection lost'); }],
]) {
  test(`${name} remains an unknown submission, never a retry`, async () => {
    const h = harness();
    const r = h.request(call(), undefined, transport);
    await h.handle(r);
    assert.equal(r.response.status, 503);
    assert.equal(r.response.body.error.code, -32052);
    assert.equal(r.subrequests.length, 1);
    assert.ok(h.slots().every(([, value]) => value === 0));
  });
}

test('raw admission shares per-client and global EVM capacity with simulations', async () => {
  const h = harness();
  const first = deferredReply();
  const second = deferredReply();
  const r1 = h.request(call(), '192.0.2.1', first.transport);
  const p1 = h.handle(r1);
  assert.equal(r1.subrequests.length, 1);
  const sameIp = h.request(call('eth_call'));
  await h.handle(sameIp);
  assert.equal(sameIp.response.status, 429);
  assert.equal(sameIp.subrequests.length, 0);
  const r2 = h.request(call('eth_estimateGas'), '192.0.2.2', second.transport);
  const p2 = h.handle(r2);
  const third = h.request(call(), '192.0.2.3');
  await h.handle(third);
  assert.equal(third.response.status, 429);
  assert.equal(third.subrequests.length, 0);
  first.release();
  second.release();
  await Promise.all([p1, p2]);
  const retry = h.request(call(), '192.0.2.3');
  await h.handle(retry);
  assert.equal(retry.response.status, 200);
  assert.ok(h.slots().every(([, value]) => value === 0));
});

test('mixed raw/simulation batch counts each EVM call before forwarding', async () => {
  const h = harness();
  const r = h.request([call(), call('eth_call', 2)]);
  await h.handle(r);
  assert.equal(r.response.status, 429);
  assert.equal(r.subrequests.length, 0);
  assert.equal(r.response.body.length, 2);
  assert.ok(h.slots().every(([, value]) => value === 0));
});

test('raw admission retains the independent per-minute transaction budget', async () => {
  const h = harness({ txPerMinute: 1 });
  await h.handle(h.request());
  const r = h.request();
  await h.handle(r);
  assert.equal(r.response.status, 429);
  assert.match(r.response.body.error.message, /eth_sendRawTransaction per minute/);
  assert.equal(r.subrequests.length, 0);
});

test('a known unavailable sequencer refuses before reserving or submitting', async () => {
  const h = harness();
  h.shared.l2state.set('local', JSON.stringify({ ok: false, ts: Date.now() }));
  const r = h.request();
  await h.handle(r);
  assert.equal(r.response.body.error.code, -32053);
  assert.equal(r.response.body.error.data.submitted, false);
  assert.equal(r.subrequests.length, 0);
  assert.equal(h.slots().length, 0);
});
