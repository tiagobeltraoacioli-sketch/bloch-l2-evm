// Second-pass review of the gateway fixes 3b7ee9a/4806b8d (tip 2bb155a). Loads the real handler from the worktree.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const GW = new URL('../public-rpc/l2rpc-gateway.js', import.meta.url).pathname;
const source = readFileSync(GW, 'utf8')
  .replace("import cfg from 'l2rpc-config.js';", 'const cfg = injectedConfig;')
  .replace('export default {', 'globalThis.gateway = {');
const hash = '0x' + 'ab'.repeat(32);
class Dictionary extends Map {
  keys() { return [...super.keys()]; }
  incr(key, amount, initial) { const next = (this.get(key) ?? initial) + amount; this.set(key, next); return next; }
}
function harness(extra) {
  const shared = { l2rate: new Dictionary(), l2slots: new Dictionary(), l2state: new Dictionary() };
  const clock = { now: 1_800_000_000_000 };
  class FakeDate extends Date { static now() { return clock.now; } }
  const context = vm.createContext({
    injectedConfig: Object.assign({
      role: 'sequencer', peerProbeUrl: 'http://peer/probe', chainId: 700770, chainIdHex: '0xab162',
      stateMaxAgeMs: 15000, maxStatusAgeS: 900, maxBatch: 100, callsPerMinute: 1200, txPerMinute: 30,
      simPerIp: 2, simTotal: 8, txPerIp: 2, txReserve: 2, slotTtlMs: 60000, maxLagBlocks: 0,   // render.py defaults
    }, extra || {}),
    ngx: { shared }, Date: FakeDate,
  });
  vm.runInContext(source, context);
  const answer = (options) => ({ status: 200, responseText: JSON.stringify(JSON.parse(options.body)
    .filter((x) => x.id !== undefined).map((x) => ({ jsonrpc: '2.0', id: x.id, result: hash }))) });
  const request = (body, ip, transport) => ({
    requestText: JSON.stringify(body), variables: { remote_addr: ip, request_id: Math.random().toString(16).slice(2) },
    headersOut: {}, subrequests: [],
    return(status, payload) { this.response = { status, body: payload ? JSON.parse(payload) : null }; },
    internalRedirect(where) { this.redirect = where; },
    async subrequest(where, options) {
      this.subrequests.push({ where, body: JSON.parse(options.body) });
      return transport ? transport(where, options, answer) : answer(options);
    },
  });
  const setState = (name) => shared.l2state.set(name, JSON.stringify({ ok: true, head: 100, finalized: 90,
    statusState: 'ok', statusAge: 5, ts: clock.now, error: null }));
  return { handle: context.gateway.handle, request, shared, clock, setState };
}
const ethCall = (id) => ({ jsonrpc: '2.0', id, method: 'eth_call', params: [{ to: '0x' + '11'.repeat(20) }, 'latest'] });
const rawTx = (id) => ({ jsonrpc: '2.0', id, method: 'eth_sendRawTransaction', params: ['0x01'] });
const tick = () => new Promise((resolve) => setImmediate(resolve));
function slowTransport() {
  const pending = [];
  const slow = (where, options, answer) => new Promise((resolve) => pending.push(() => resolve(answer(options))));
  return { slow, release: () => pending.forEach((f) => f()) };
}

// K1. The reserve (2) equals the per-client admission cap (2): ONE client's two slow admissions take the whole
// reserve. With the simulations at their cap (three client keys), that is the same four client keys as R308-27.
test('K1: with simulations at their cap, one client holding two admissions does not refuse everyone else\'s transaction', async () => {
  const h = harness(); h.setState('local');
  const t = slowTransport(); const running = [];
  for (let n = 0; n < 3; n++) for (let k = 0; k < 2; k++) running.push(h.handle(h.request(ethCall(1), `203.0.113.${n + 1}`, t.slow)));
  for (let k = 0; k < 2; k++) running.push(h.handle(h.request(rawTx(1), '203.0.113.9', t.slow)));
  await tick();
  const victim = h.request(rawTx('pay'), '198.51.100.7');
  await h.handle(victim);
  t.release(); await Promise.all(running);
  assert.equal(victim.subrequests.length, 1, 'victim transaction refused: ' + JSON.stringify(victim.response));
});

// K2. The reverse starvation: admissions in flight count against the simulation cap (n.e + n.t - txs > 6).
test('K2: three clients with two admissions in flight each do not refuse every simulation', async () => {
  const h = harness(); h.setState('local');
  const t = slowTransport(); const running = [];
  for (let n = 0; n < 3; n++) for (let k = 0; k < 2; k++) running.push(h.handle(h.request(rawTx(1), `203.0.113.${n + 1}`, t.slow)));
  await tick();
  const victim = h.request(ethCall('sim'), '198.51.100.7');
  await h.handle(victim);
  t.release(); await Promise.all(running);
  assert.equal(victim.subrequests.length, 1, 'victim simulation refused: ' + JSON.stringify(victim.response));
});

// K3. An aborted request keeps its slot for the full TTL whatever the call cost: 6 requests a minute from 3
// addresses (2 each, connection closed at once) keep every simulation of every client refused.
test('K3: 59 s after six aborted eth_call (three addresses) another client\'s eth_call is served', async () => {
  const h = harness(); h.setState('local');
  const aborted = () => new Promise(() => {});
  for (let n = 0; n < 3; n++) for (let k = 0; k < 2; k++) h.handle(h.request(ethCall(1), `203.0.113.${n + 1}`, aborted));
  await tick();
  h.clock.now += 59000; h.setState('local');
  const victim = h.request(ethCall('sim'), '198.51.100.7');
  await h.handle(victim);
  assert.equal(victim.response.status, 200, '59 s later: ' + JSON.stringify(victim.response));
});

// K4. render.py accepts --sim-per-ip above --sim-total minus --tx-reserve (only >= 1 is checked). A wave is then
// larger than the simulation pool and is refused on an idle gateway, for ever ("Retry-After: 1").
test('K4: simPerIp 8, simTotal 8, txReserve 2 (accepted by render.py): a batch of 7 eth_call on an idle gateway is served', async () => {
  const h = harness({ simPerIp: 8 }); h.setState('local');
  const r = h.request([1, 2, 3, 4, 5, 6, 7].map(ethCall), '192.0.2.9');
  await h.handle(r);
  assert.equal(r.response.status, 200, 'idle gateway: ' + JSON.stringify(r.response.body[0]));
});

// Controls (pass): things checked and found correct.
test('control: refused later wave reports submitted:false only for transactions that were never forwarded; order kept', async () => {
  const h = harness(); h.setState('local');
  const t = slowTransport();
  let blockers = [];
  const r = h.request([rawTx('a'), rawTx('b'), rawTx('c'), ethCall('d')], '192.0.2.9', async (where, options, answer) => {
    // while wave 0 (a, b) is in flight, other clients fill the gateway
    if (!blockers.length) for (let n = 0; n < 4; n++) for (let k = 0; k < 2; k++) blockers.push(h.handle(h.request(rawTx(1), `203.0.113.${n + 1}`, t.slow)));
    await tick();
    return answer(options);
  });
  await h.handle(r);
  t.release(); await Promise.all(blockers);
  const sent = r.subrequests.flatMap((s) => s.body.map((c) => c.method + ':' + c.id));
  assert.equal(r.response.status, 200);
  assert.deepEqual(r.response.body.map((x) => x.id), ['a', 'b', 'c', 'd']);
  assert.deepEqual(sent, ['eth_sendRawTransaction:0', 'eth_sendRawTransaction:1']);
  assert.equal(r.response.body[0].result, hash); assert.equal(r.response.body[1].result, hash);
  assert.deepEqual(r.response.body[2].error.data, { run: false, submitted: false });
  assert.deepEqual(r.response.body[3].error.data, { run: false, submitted: false });
});
