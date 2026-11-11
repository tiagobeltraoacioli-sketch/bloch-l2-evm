// Review a308 (second pass): demonstrations against the real njs handler l2rpc-gateway.js of the review worktree.
// Loading technique of deployment/mainnet/public-rpc/tests/gateway-admission.test.mjs (vm + fake njs `r`).
// Every test states the expected behaviour and FAILS on the current code.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const GW = new URL('../public-rpc/l2rpc-gateway.js', import.meta.url).pathname;
const source = readFileSync(GW, 'utf8')
  .replace("import cfg from 'l2rpc-config.js';", 'const cfg = injectedConfig;')
  .replace('export default {', 'globalThis.gateway = {');
const hash = '0x' + 'ab'.repeat(32);

// keys() and the l2slots dictionary: added by the fix line (the EVM slots moved to their own zone, R308-27).
class Dictionary extends Map {
  keys() { return [...super.keys()]; }
  incr(key, amount, initial) {
    const next = (this.get(key) ?? initial) + amount;
    this.set(key, next);
    return next;
  }
}

// render.py defaults: simPerIp 2, simTotal 8, 1200 calls/min, 30 tx/min, batch 100.
function harness() {
  const shared = { l2rate: new Dictionary(), l2slots: new Dictionary(), l2state: new Dictionary() };
  const clock = { now: 1_800_000_000_000 - (1_800_000_000_000 % 150000) + 1000 }; // 1 s into a 150 s slot window
  class FakeDate extends Date { static now() { return clock.now; } }
  const context = vm.createContext({
    injectedConfig: {
      role: 'sequencer', peerProbeUrl: 'http://peer/probe', chainId: 700770, chainIdHex: '0xab162',
      stateMaxAgeMs: 15000, maxStatusAgeS: 900, maxBatch: 100, callsPerMinute: 1200, txPerMinute: 30,
      simPerIp: 2, simTotal: 8, maxLagBlocks: 0,
    },
    ngx: { shared },
    Date: FakeDate,
  });
  vm.runInContext(source, context);
  const answer = (options) => ({ status: 200, responseText: JSON.stringify(JSON.parse(options.body)
    .filter((x) => x.id !== undefined).map((x) => ({ jsonrpc: '2.0', id: x.id, result: hash }))) });
  const request = (body, ip, transport) => ({
    requestText: JSON.stringify(body), variables: { remote_addr: ip }, headersOut: {}, subrequests: [],
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

const ethCall = (id, tag = 'latest') => ({ jsonrpc: '2.0', id, method: 'eth_call', params: [{ to: '0x' + '11'.repeat(20) }, tag] });
const rawTx = (id) => ({ jsonrpc: '2.0', id, method: 'eth_sendRawTransaction', params: ['0x01'] });
const tick = () => new Promise((resolve) => setImmediate(resolve));

// G1. Decision G4: a read timeout is never retried on the other backend. The guard hop answers 504 after its
// 30 s proxy_read_timeout (timeout is not in proxy_next_upstream); retryFinality() then replays the call.
test('G1: an eth_call at "finalized" that times out (504) on the first backend is not replayed on the other', async () => {
  const h = harness();
  h.setState('local');
  h.setState('peer');
  const r = h.request(ethCall(7, 'finalized'), '192.0.2.1', async () => ({ status: 504, responseText: '' }));
  await h.handle(r);
  assert.deepEqual(r.subrequests.map((s) => s.where), ['/_l2s/local'],
    'the timed-out eth_call went to: ' + JSON.stringify(r.subrequests.map((s) => s.where)));
});

// G2. The 8 gateway-wide EVM slots are shared by simulations and transaction admission (2616ddd). Four client
// keys (4 IPv4 addresses, or 4 /64 of one IPv6 /56 line) with 2 slow eth_call each hold all of them.
test('G2: simulations of four other client keys do not refuse a fifth client\'s eth_sendRawTransaction', async () => {
  const h = harness();
  h.setState('local');
  const pending = [];
  const slow = (where, options, answer) => new Promise((resolve) => pending.push(() => resolve(answer(options))));
  const running = [];
  for (let n = 0; n < 4; n++) {
    for (let k = 0; k < 2; k++) running.push(h.handle(h.request(ethCall(1), `2001:db8:0:${n}::1`, slow)));
  }
  await tick();
  const victim = h.request(rawTx('pay'), '198.51.100.7');
  await h.handle(victim);
  pending.forEach((release) => release());
  await Promise.all(running);
  assert.equal(victim.subrequests.length, 1, 'the transaction never reached the sequencer: ' + JSON.stringify(victim.response));
});

// G3. Slots of requests whose client connection failed are never released (the code's own comment: njs does not
// resume the handler). 100 s later, in the same window and inside the dictionary's 120 s timeout, nothing is in
// flight and the gateway still refuses every EVM call and every transaction.
test('G3: 8 aborted eth_call do not make the gateway refuse transactions 100 s later', async () => {
  const h = harness();
  h.setState('local');
  const aborted = () => new Promise(() => {}); // the handler is never resumed, so `finally` never runs
  for (let n = 0; n < 4; n++) for (let k = 0; k < 2; k++) h.handle(h.request(ethCall(1), `203.0.113.${n + 1}`, aborted));
  await tick();
  h.clock.now += 100000;
  h.setState('local');
  const victim = h.request(rawTx('pay'), '198.51.100.7');
  await h.handle(victim);
  assert.equal(victim.response.status, 200, '100 s after 8 aborted requests: ' + JSON.stringify(victim.response));
});

// G4. --max-batch 100 ("ethers v6 batches up to 100") against simPerIp 2 counted per batch entry: a batch with
// three EVM calls is refused whole, always, also on an idle gateway; Retry-After 1 never helps.
test('G4: an idle client sending one batch of three eth_call is served', async () => {
  const h = harness();
  h.setState('local');
  const r = h.request([ethCall(1), ethCall(2), ethCall(3)], '192.0.2.9');
  await h.handle(r);
  assert.equal(r.response.status, 200, 'refused: ' + JSON.stringify(r.response.body[0]));
});
