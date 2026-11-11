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
  keys() { return [...super.keys()]; }
  incr(key, amount, initial) {
    const next = (this.get(key) ?? initial) + amount;
    this.set(key, next);
    return next;
  }
}

// `timers: true` gives the handler njs's setTimeout/clearTimeout, driven by the fake clock (advance). Without
// it the handler sees no timers and a slot lives its whole lifetime, as before review R308-2P-7.
function harness(overrides = {}, { timers = false } = {}) {
  const shared = { l2rate: new Dictionary(), l2slots: new Dictionary(), l2state: new Dictionary() };
  const clock = { now: 1_800_000_000_000 };
  class FakeDate extends Date { static now() { return clock.now; } }
  let pending = [];
  let nextTimer = 1;
  const fakeTimers = !timers ? {} : {
    setTimeout(fn, ms) { const id = nextTimer++; pending.push({ id, at: clock.now + ms, fn }); return id; },
    clearTimeout(id) { pending = pending.filter((t) => t.id !== id); },
  };
  // Moves the clock, running the timers that fall due on the way, in order.
  const advance = (ms) => {
    const end = clock.now + ms;
    for (;;) {
      const due = pending.filter((t) => t.at <= end).sort((a, b) => a.at - b.at)[0];
      if (!due) break;
      pending = pending.filter((t) => t !== due);
      clock.now = Math.max(clock.now, due.at);
      due.fn();
    }
    clock.now = end;
  };
  // A worker that is killed takes its requests and their njs timers with it.
  const destroyRequests = () => { pending = []; };
  const context = vm.createContext({
    Date: FakeDate, ...fakeTimers,
    injectedConfig: {
      role: 'sequencer', peerProbeUrl: 'http://peer/probe',
      chainId: 31337, chainIdHex: '0x7a69', stateMaxAgeMs: 60000,
      maxStatusAgeS: 60, maxBatch: 20, callsPerMinute: 1000,
      txPerMinute: 100, simPerIp: 1, simTotal: 2, maxLagBlocks: 0, ...overrides,
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
  // EVM slots in flight: one key per call, gone when its request returns.
  const slots = () => shared.l2slots.keys();
  const setState = (name, more = {}) => shared.l2state.set(name, JSON.stringify({ ok: true, head: 100, finalized: 90,
    statusState: 'ok', statusAge: 5, ts: clock.now, error: null, ...more }));
  return { handle: context.gateway.handle, client: context.gateway.client, request, slots, shared, requests, clock, setState,
    advance, destroyRequests, timers: () => pending.length };
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
  assert.deepEqual(h.slots(), []);
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
    assert.deepEqual(h.slots(), []);
  });
}

test('raw admission has its own per-client count and shares the gateway-wide total', async () => {
  const h = harness({ txReserve: 0 }); // simPerIp 1 (so 1 admission per client), 2 slots in all
  const first = deferredReply();
  const second = deferredReply();
  const r1 = h.request(call(), '192.0.2.1', first.transport);
  const p1 = h.handle(r1);
  assert.equal(r1.subrequests.length, 1);
  const sameIpTx = h.request(call());
  await h.handle(sameIpTx);
  assert.equal(sameIpTx.response.status, 429, 'a second admission in flight from the same client');
  assert.match(sameIpTx.response.body.error.message, /per client/);
  assert.equal(sameIpTx.subrequests.length, 0);
  // The client's own admission does not use up its simulation count.
  const r2 = h.request(call('eth_estimateGas'), '192.0.2.1', second.transport);
  const p2 = h.handle(r2);
  assert.equal(r2.subrequests.length, 1);
  const third = h.request(call(), '192.0.2.3');
  await h.handle(third);
  assert.equal(third.response.status, 429, 'the gateway-wide total is reached');
  assert.match(third.response.body.error.message, /^Busy/);
  assert.equal(third.response.headersOut, undefined);
  assert.equal(third.headersOut['Retry-After'], '1');
  assert.equal(third.subrequests.length, 0);
  first.release();
  second.release();
  await Promise.all([p1, p2]);
  const retry = h.request(call(), '192.0.2.3');
  await h.handle(retry);
  assert.equal(retry.response.status, 200);
  assert.deepEqual(h.slots(), []);
});

test('mixed raw/simulation batch: one admission and one simulation run together', async () => {
  const h = harness();
  const r = h.request([call(), call('eth_call', 2)]);
  await h.handle(r);
  assert.equal(r.response.status, 200);
  assert.deepEqual(r.subrequests.map((s) => s.where).sort(), ['/_l2s/local', '/_l2s/seq']);
  assert.equal(r.response.body.length, 2);
  assert.deepEqual(h.slots(), []);
});

// ------------------------------------------------------------ review R308-27 (round 15)

const pendingTransport = () => {
  const waiting = [];
  const transport = (where, options) => new Promise((resolve) => waiting.push(() => resolve({ status: 200,
    responseText: JSON.stringify(JSON.parse(options.body).map((x) => ({ jsonrpc: '2.0', id: x.id, result: hash }))) })));
  return { transport, waiting, release: () => waiting.splice(0).forEach((f) => f()) };
};
const tick = () => new Promise((resolve) => setImmediate(resolve));
const DEFAULTS = { simPerIp: 2, simTotal: 8, txPerIp: 1, txReserve: 3, simFloor: 2, slotTtlMs: 60000, slotGraceMs: 20000 }; // render.py

test('R308-27: simulations never take the slots reserved for transactions', async () => {
  const h = harness(DEFAULTS);
  const slow = pendingTransport();
  const running = [];
  const statuses = [];
  for (let n = 0; n < 4; n++) {
    for (let k = 0; k < 2; k++) {
      const r = h.request(call('eth_call'), `192.0.2.${n + 1}`, slow.transport);
      running.push(h.handle(r).then(() => statuses.push(r.response.status)));
    }
  }
  await tick();
  assert.equal(slow.waiting.length, 5, 'simulations in flight: simTotal 8 minus the reserve of 3');
  const sim = h.request(call('eth_estimateGas'), '198.51.100.7');
  await h.handle(sim);
  assert.equal(sim.response.status, 429);
  assert.match(sim.response.body.error.message, /^Busy/);
  // Three transactions of three other clients still reach the sequencer; a fourth finds the total used.
  const txs = [7, 8, 9].map((n) => h.request(call(), `198.51.100.${n}`, slow.transport));
  txs.forEach((r) => running.push(h.handle(r)));
  await tick();
  assert.deepEqual(txs.map((r) => r.subrequests.length), [1, 1, 1]);
  assert.equal(txs[0].subrequests[0].where, '/_l2s/seq');
  const tx4 = h.request(call(), '198.51.100.10');
  await h.handle(tx4);
  assert.equal(tx4.response.status, 429);
  assert.equal(tx4.subrequests.length, 0);
  slow.release();
  await Promise.all(running);
  assert.deepEqual(statuses.sort(), [200, 200, 200, 200, 200, 429, 429, 429]);
  assert.deepEqual(h.slots(), []);
});

test('R308-2P-7: transactions use every slot but the simulations\' floor, and a simulation is still served', async () => {
  const h = harness(DEFAULTS);
  const slow = pendingTransport();
  const running = [];
  for (let n = 0; n < 8; n++) running.push(h.handle(h.request(call(), `192.0.2.${n + 1}`, slow.transport)));
  await tick();
  assert.equal(slow.waiting.length, 6, 'admissions in flight: simTotal 8 minus the simulation floor of 2');
  const sims = [7, 8].map((n) => h.request(call('eth_call'), `198.51.100.${n}`, slow.transport));
  sims.forEach((r) => running.push(h.handle(r)));
  await tick();
  assert.deepEqual(sims.map((r) => r.subrequests.length), [1, 1]);
  const third = h.request(call('eth_call'), '198.51.100.9');
  await h.handle(third);
  assert.equal(third.response.status, 429, 'the total of 8 is used');
  slow.release();
  await Promise.all(running);
  assert.deepEqual(h.slots(), []);
});

// Review R308-2P-6 (demonstration K1 of agent 308, second pass): the reserve was 2 and one client could have 2
// admissions in flight, so three keys at the simulation cap and a fourth with two admissions refused everyone's
// transactions. Now one client holds one admission, never more than half of the reserve.
for (const [name, config] of [['render.py defaults', DEFAULTS],
  ['the configuration of the finding (2 per client, reserve 2)', { simPerIp: 2, simTotal: 8, txPerIp: 2, txReserve: 2 }]]) {
  test(`R308-2P-6: one client cannot hold the transaction reserve (${name})`, async () => {
    const h = harness(config);
    const slow = pendingTransport();
    const running = [];
    for (let n = 0; n < 3; n++) for (let k = 0; k < 2; k++) running.push(h.handle(h.request(call('eth_call'), `203.0.113.${n + 1}`, slow.transport)));
    const greedy = [0, 1].map(() => h.request(call(), '203.0.113.9', slow.transport));
    greedy.forEach((r) => running.push(h.handle(r)));
    await tick();
    assert.deepEqual(greedy.map((r) => r.subrequests.length), [1, 0], 'the second admission in flight of one client');
    assert.match(greedy[1].response.body.error.message, /per client/);
    const victim = h.request(call(), '198.51.100.7');
    await h.handle(victim);
    assert.equal(victim.subrequests.length, 1, 'victim transaction refused: ' + JSON.stringify(victim.response));
    slow.release();
    await Promise.all(running);
    assert.deepEqual(h.slots(), []);
  });
}

test('R308-2P-7: a per-client simulation count above the simulations\' share still runs on an idle gateway', async () => {
  const h = harness({ simPerIp: 8, simTotal: 8, txReserve: 2 }); // render.py now refuses this; the handler clamps it
  const r = h.request([1, 2, 3, 4, 5, 6, 7].map((id) => call('eth_call', id)), '192.0.2.9');
  await h.handle(r);
  assert.equal(r.response.status, 200, JSON.stringify(r.response.body[0]));
  assert.deepEqual(r.subrequests.map((s) => s.body.length), [6, 1]);
});

// Review R308-2P-7 (K3): a handler that never came back held its slots for the whole lifetime (60 s). With
// timers a slot counts for the grace only (20 s) and a request in flight renews it. On nginx 1.24 / njs 0.8.2
// a client that closes its connection does NOT lose the handler (it resumes when the backend answers; see the
// README); the lost handler of this test is a killed worker, whose timers die with it.
test('R308-2P-7: the slots of handlers that never come back stop counting after the grace, not the lifetime', async () => {
  const h = harness(DEFAULTS, { timers: true });
  const aborted = () => new Promise(() => {});
  for (let n = 0; n < 3; n++) for (let k = 0; k < 2; k++) h.handle(h.request(call('eth_call'), `203.0.113.${n + 1}`, aborted));
  for (let n = 0; n < 3; n++) h.handle(h.request(call(), `203.0.113.${n + 10}`, aborted));
  await tick();
  assert.equal(h.slots().length, 8);
  h.destroyRequests();
  h.advance(19000);
  for (const method of ['eth_sendRawTransaction', 'eth_call']) {
    const r = h.request(call(method), '198.51.100.7');
    await h.handle(r);
    assert.equal(r.response.status, 429, method + ' inside the grace');
  }
  h.advance(1001);
  for (const method of ['eth_sendRawTransaction', 'eth_call']) {
    const r = h.request(call(method), '198.51.100.7');
    await h.handle(r);
    assert.equal(r.response.status, 200, method + ' after the grace: ' + JSON.stringify(r.response));
  }
  assert.deepEqual(h.slots(), []);
  assert.equal(h.timers(), 0, 'a finished request leaves no timer behind');
});

test('R308-2P-7: a request in flight keeps its slots past the grace, up to the slot lifetime', async () => {
  const h = harness(DEFAULTS, { timers: true });
  const slow = pendingTransport();
  const running = [];
  for (let n = 0; n < 3; n++) for (let k = 0; k < 2; k++) running.push(h.handle(h.request(call('eth_call'), `203.0.113.${n + 1}`, slow.transport)));
  await tick();
  assert.equal(h.slots().length, 5);
  h.advance(45000);
  const during = h.request(call('eth_call'), '198.51.100.7');
  await h.handle(during);
  assert.equal(during.response.status, 429, 'five simulations still in flight after 45 s');
  h.advance(14000);
  const late = h.request(call('eth_call'), '198.51.100.7');
  await h.handle(late);
  assert.equal(late.response.status, 429, 'still in flight after 59 s');
  h.advance(1001);   // the lifetime of 60 s: renewals never carry a slot past it
  const after = h.request(call('eth_call'), '198.51.100.7');
  await h.handle(after);
  assert.equal(after.response.status, 200);
  slow.release();
  await Promise.all(running);
  assert.equal(h.timers(), 0);
});

test('R308-27: the slots of requests that never return stop counting after the slot lifetime', async () => {
  const h = harness({ ...DEFAULTS, slotTtlMs: 60000 });
  const aborted = () => new Promise(() => {}); // njs never resumes a handler whose client connection failed
  for (let n = 0; n < 3; n++) for (let k = 0; k < 2; k++) h.handle(h.request(call('eth_call'), `203.0.113.${n + 1}`, aborted));
  for (let n = 0; n < 3; n++) h.handle(h.request(call(), `203.0.113.${n + 10}`, aborted));
  await tick();
  assert.equal(h.slots().length, 8, 'five simulations (the sixth is refused) and three admissions');
  h.clock.now += 59000;
  for (const method of ['eth_sendRawTransaction', 'eth_call']) {
    const r = h.request(call(method), '198.51.100.7');
    await h.handle(r);
    assert.equal(r.response.status, 429, method + ' inside the slot lifetime');
  }
  h.clock.now += 1001;
  for (const method of ['eth_sendRawTransaction', 'eth_call']) {
    const r = h.request(call(method), '198.51.100.7');
    await h.handle(r);
    assert.equal(r.response.status, 200, method + ' after the slot lifetime: ' + JSON.stringify(r.response));
  }
  assert.deepEqual(h.slots(), [], 'the expired keys are removed by the next count');
});

test('R308-27: the EVM slots of one IPv6 /56 are one client; the rate budgets stay per /64', async () => {
  const h = harness(DEFAULTS);
  const slow = pendingTransport();
  const running = [];
  const admitted = [];
  for (let n = 0; n < 4; n++) {
    const r = h.request(call('eth_call'), `2001:db8:0:${n}::1`, slow.transport);
    running.push(h.handle(r));
    admitted.push(r);
  }
  await tick();
  assert.deepEqual(admitted.map((r) => r.subrequests.length), [1, 1, 0, 0]);
  assert.match(admitted[2].response.body.error.message, /per client/);
  const other = h.request(call('eth_call'), '2001:db8:0:100::1', slow.transport); // the next /56
  running.push(h.handle(other));
  await tick();
  assert.equal(other.subrequests.length, 1);
  slow.release();
  await Promise.all(running);
  assert.ok(h.slots().length === 0);
  const key = (a) => h.client({ variables: { remote_addr: a } });
  assert.equal(key('2001:db8:0:1::1'), '2001:db8:0:1::/64');
  assert.notEqual(key('2001:db8:0:1::1'), key('2001:db8:0:2::1'));
});

// ------------------------------------------------------------ review R308-28 (round 15)

const finalized = (id = 7) => ({ jsonrpc: '2.0', id, method: 'eth_call', params: [{ to: '0x' + '11'.repeat(20) }, 'finalized'] });
const closed = (options) => ({ status: 200, responseText: JSON.stringify(JSON.parse(options.body)
  .map((x) => ({ jsonrpc: '2.0', id: x.id, error: { code: -32001, message: 'finality levels closed' } }))) });
const good = (options) => ({ status: 200, responseText: JSON.stringify(JSON.parse(options.body)
  .map((x) => ({ jsonrpc: '2.0', id: x.id, result: hash }))) });

for (const [name, first] of [
  ['504 (read timeout)', async () => ({ status: 504, responseText: '' })],
  ['failed subrequest', async () => { throw new Error('connection lost'); }],
  ['200 that does not parse', async () => ({ status: 200, responseText: '{' })],
  ['500', async () => ({ status: 500, responseText: '' })],
]) {
  test(`R308-28: a finality call answered with ${name} is not sent to the other backend`, async () => {
    const h = harness();
    h.setState('local');
    h.setState('peer');
    const r = h.request(finalized(), '192.0.2.1', first);
    await h.handle(r);
    assert.deepEqual(r.subrequests.map((s) => s.where), ['/_l2s/local']);
    assert.equal(r.response.status, 503);
    assert.equal(r.response.body.error.code, -32053);
    assert.deepEqual(h.slots(), []);
  });
}

for (const status of [429, 502, 503]) {
  test(`R308-28: a finality call refused with ${status} goes once to the other backend`, async () => {
    const h = harness();
    h.setState('local');
    h.setState('peer');
    const r = h.request(finalized(), '192.0.2.1', async (where, options) => (where === '/_l2s/local' ? { status, responseText: '' } : good(options)));
    await h.handle(r);
    assert.deepEqual(r.subrequests.map((s) => s.where), ['/_l2s/local', '/_l2s/peer']);
    assert.equal(r.response.status, 200);
    assert.equal(r.response.body.result, hash);
    assert.equal(r.response.body.id, 7);
  });
}

test('R308-28: a parsed "closed" answer goes once to the other backend, which holds its slot meanwhile', async () => {
  const h = harness({ slotTtlMs: 60000 });
  h.setState('local');
  h.setState('peer');
  let slotsDuringRetry;
  const r = h.request(finalized(), '192.0.2.1', async (where, options) => {
    if (where === '/_l2s/local') { h.clock.now += 50000; return closed(options); }
    h.clock.now += 20000; // 70 s after the start: the slot was renewed before the second round trip
    const again = h.request(call('eth_call'), '192.0.2.1');
    await h.handle(again);
    slotsDuringRetry = again.response.status;
    return good(options);
  });
  await h.handle(r);
  assert.deepEqual(r.subrequests.map((s) => s.where), ['/_l2s/local', '/_l2s/peer']);
  assert.equal(r.response.body.result, hash);
  assert.equal(slotsDuringRetry, 429, 'the retried call still holds its slot');
  assert.deepEqual(h.slots(), []);
});

test('R308-28: in a batch only the entries with a closed answer are retried', async () => {
  const h = harness({ simPerIp: 2, simTotal: 8 });
  h.setState('local');
  h.setState('peer');
  const r = h.request([finalized(1), finalized(2)], '192.0.2.1', async (where, options) => {
    const sent = JSON.parse(options.body);
    if (where === '/_l2s/peer') return good(options);
    return { status: 200, responseText: JSON.stringify([
      { jsonrpc: '2.0', id: sent[0].id, result: '0x01' },
      { jsonrpc: '2.0', id: sent[1].id, error: { code: -32001, message: 'closed' } }]) };
  });
  await h.handle(r);
  assert.deepEqual(r.subrequests.map((s) => s.body.length), [2, 1]);
  assert.deepEqual(r.response.body.map((x) => x.result), ['0x01', hash]);
});

// ------------------------------------------------------------ review R308-33b (round 15)

test('R308-33b: a batch with more EVM calls than one client may have in flight runs them in waves', async () => {
  const h = harness(DEFAULTS);
  let inFlight = 0;
  let most = 0;
  const transport = async (where, options) => {
    const n = JSON.parse(options.body).filter((x) => x.method === 'eth_call').length;
    inFlight += n;
    most = Math.max(most, inFlight);
    await tick();
    inFlight -= n;
    return good(options);
  };
  const batch = [call('eth_call', 'a'), call('eth_blockNumber', 'b'), call('eth_call', 'c'), call('eth_call', 'd'),
    call('eth_call', 'e'), call('eth_call', 'f')];
  const r = h.request(batch, '192.0.2.9', transport);
  await h.handle(r);
  assert.equal(r.response.status, 200);
  assert.deepEqual(r.response.body.map((x) => x.id), ['a', 'b', 'c', 'd', 'e', 'f']);
  assert.ok(r.response.body.every((x) => x.result === hash));
  assert.equal(most, 2);
  assert.deepEqual(r.subrequests.map((s) => s.body.length), [3, 2, 1], 'the call without EVM work goes with the first wave');
  assert.deepEqual(h.slots(), []);
});

test('R308-33b: a later wave that finds the gateway busy is answered per entry; what ran keeps its answers', async () => {
  const h = harness(DEFAULTS);
  const slow = pendingTransport();
  const others = [];
  const r = h.request([call('eth_call', 1), call('eth_call', 2), call('eth_call', 3), call('eth_sendRawTransaction', 4)], '192.0.2.9',
    async (where, options) => {
      // While the first wave runs, six other clients take every slot admissions may use (8 minus the floor of 2).
      for (let n = 0; n < 6; n++) others.push(h.handle(h.request(call(), `203.0.113.${n + 10}`, slow.transport)));
      await tick();
      return good(options);
    });
  await h.handle(r);
  assert.equal(r.response.status, 200);
  assert.deepEqual(r.response.body.slice(0, 2).map((x) => x.result), [hash, hash]);
  for (const entry of r.response.body.slice(2)) {
    assert.equal(entry.error.code, -32005);
    assert.match(entry.error.message, /^Busy.*not run/);
    assert.deepEqual(entry.error.data, { run: false, submitted: false });
  }
  assert.deepEqual(r.response.body.map((x) => x.id), [1, 2, 3, 4]);
  assert.equal(r.subrequests.length, 1, 'the transaction of the refused wave was not submitted');
  slow.release();
  await Promise.all(others);
  assert.deepEqual(h.slots(), []);
});

test('R308-33b: a batch of transactions is admitted a client share at a time, each submitted once', async () => {
  const h = harness(DEFAULTS);
  const r = h.request([call('eth_sendRawTransaction', 1), call('eth_sendRawTransaction', 2), call('eth_sendRawTransaction', 3)]);
  await h.handle(r);
  assert.equal(r.response.status, 200);
  assert.deepEqual(r.subrequests.map((s) => [s.where, s.body.length]), [['/_l2s/seq', 1], ['/_l2s/seq', 1], ['/_l2s/seq', 1]]);
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
  h.shared.l2state.set('local', JSON.stringify({ ok: false, ts: h.clock.now }));
  const r = h.request();
  await h.handle(r);
  assert.equal(r.response.body.error.code, -32053);
  assert.equal(r.response.body.error.data.submitted, false);
  assert.equal(r.subrequests.length, 0);
  assert.equal(h.slots().length, 0);
});

// nginx 1.24 with njs 0.8.2 refuses the module at load ("await in arguments not supported"); node accepts it.
test('njs: no await inside call arguments', () => {
  const hits = source.split('\n').map((line, i) => [i + 1, line]).filter(([, line]) => !/^\s*\/\//.test(line) && /[(,[]\s*await\b/.test(line));
  assert.deepEqual(hits, []);
});

test('round 15: bloch_admissionQuote goes to the sequencer first and holds one simulation slot', async () => {
  const h = harness({ simPerIp: 1, simTotal: 2 });
  const held = deferredReply();
  const first = h.request({ jsonrpc: '2.0', id: 1, method: 'bloch_admissionQuote', params: [{ from: '0x' + '11'.repeat(20) }] }, '192.0.2.1', held.transport);
  const running = h.handle(first);
  await Promise.resolve();
  assert.equal(h.slots().length, 1, 'the quote is EVM work');
  // The same client's second quote is over its simulation limit while the first runs.
  const second = h.request({ jsonrpc: '2.0', id: 2, method: 'bloch_admissionQuote', params: [{ from: '0x' + '11'.repeat(20) }] });
  await h.handle(second);
  assert.equal(second.response.body.error.code, -32005);
  held.release();
  await running;
  assert.equal(first.subrequests.length, 1);
  assert.match(first.subrequests[0].where, /seqread/);
  assert.deepEqual(h.slots(), []);
});
