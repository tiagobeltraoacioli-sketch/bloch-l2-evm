// SPDX-License-Identifier: MIT OR Apache-2.0
// Independent review, round 10: l2rpc-gateway.js under node, against a model of the njs 0.8.2 API.
//
//   node --test tests/review_r10_gateway.mjs
//
// Real here: l2rpc-gateway.js and the l2rpc-config.js that render.py writes with the production flags of
// setup-gateway.sh (--cors-any --backend-conns 400). Modelled: ngx.shared (get/set/incr as in
// ngx_js_shared_dict.c), r.subrequest, r.internalRedirect, r.return, and the settled RPC backends.
// nginx itself (limit_req, realip, proxy timeouts) is not modelled; tests/review_r10_rig.py covers it.
//
// Every test states what the public endpoint needs. A failing test is a finding of report 154.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
// Permits of bloch-l2-settled-rpc (MAX_CONCURRENT_SIMULATIONS, integrations/reth-execution/src/bin/bloch-l2-settled-rpc.rs).
const BACKEND_PERMITS = 4;
const BACKENDS = 2;

// ------------------------------------------------------------------ the gateway, rendered for production
const out = mkdtempSync(join(tmpdir(), 'gw-r10-'));
execFileSync('python3', [join(HERE, '..', 'render.py'), '--role', 'sequencer', '--name', 'review-r10', '--out', out,
  '--peer', '127.0.0.1:1', '--peer-allow', '127.0.0.1', '--cors-any', '--backend-conns', '400'], { stdio: 'pipe' });
const src = readFileSync(join(out, 'l2rpc-gateway.js'), 'utf8');
assert.ok(src.includes("import cfg from 'l2rpc-config.js';"));
writeFileSync(join(out, 'gateway.mjs'), src.replace("import cfg from 'l2rpc-config.js';", "import cfg from './config.mjs';"));
writeFileSync(join(out, 'config.mjs'), readFileSync(join(out, 'l2rpc-config.js'), 'utf8'));

// Wall clock the gateway reads (Date.now); tests move it forward.
let offsetMs = 0;
const realNow = Date.now.bind(Date);
Date.now = () => realNow() + offsetMs;

// ngx.shared as in ngx_js_shared_dict.c (njs 0.8.2): with a zone timeout, add, set and incr (re)arm the
// expiry at now + timeout; an expired key reads as absent; incr on an absent key stores init + delta.
class Dict {
  constructor(timeoutMs) { this.m = new Map(); this.timeoutMs = timeoutMs || 0; }
  live(k) {
    const e = this.m.get(k);
    if (e && this.timeoutMs && e.expire <= Date.now()) { this.m.delete(k); return undefined; }
    return e;
  }
  get(k) { const e = this.live(k); return e ? e.v : undefined; }
  set(k, v) { this.m.set(k, { v, expire: Date.now() + this.timeoutMs }); return this; }
  incr(k, delta, init) {
    const e = this.live(k);
    const v = (e ? e.v : (init || 0)) + delta;
    this.set(k, v);
    return v;
  }
}

globalThis.ngx = { shared: { l2rate: new Dict(120000), l2state: new Dict() }, fetch: async () => { throw new Error('no fetch in tests'); } };
const gw = (await import(pathToFileURL(join(out, 'gateway.mjs')).href)).default;
const cfg = (await import(pathToFileURL(join(out, 'config.mjs')).href)).default;

function healthy() {
  const s = { ok: true, head: 5000, finalized: 4000, statusState: 'ok', statusAge: 5, ts: Date.now(), error: null };
  ngx.shared.l2state.set('local', JSON.stringify(s));
  ngx.shared.l2state.set('peer', JSON.stringify(s));
}

function reset() {
  offsetMs = 0;
  ngx.shared.l2rate = new Dict(120000); // js_shared_dict_zone zone=l2rate:16m timeout=120s
  healthy();
}

// A backend: answers every call of a batch; `hold` keeps EVM simulations in flight until released.
function backend() {
  const b = { inFlight: 0, maxInFlight: 0, waiting: [], seen: [] };
  b.release = () => { const w = b.waiting.splice(0); w.forEach((f) => f()); };
  b.answer = (c) => {
    b.seen.push(c.method);
    if (c.method === 'eth_call') return { jsonrpc: '2.0', id: c.id, result: '0x' + 'ca11'.padEnd(64, '0') };
    if (c.method === 'eth_getBalance') return { jsonrpc: '2.0', id: c.id, result: '0x64' };
    return { jsonrpc: '2.0', id: c.id, result: '0x1' };
  };
  b.subrequest = async (where, opts, request) => {
    const calls = JSON.parse(opts.body);
    const sims = calls.filter((c) => c.method === 'eth_call').length;
    b.inFlight += sims;
    b.maxInFlight = Math.max(b.maxInFlight, b.inFlight);
    if (sims && b.hold) await new Promise((f) => b.waiting.push(f));
    b.inFlight -= sims;
    // ngx_http_js_subrequest_done (njs 0.8.2, nginx/ngx_http_js_module.c:3462) returns without resolving the
    // promise when the client connection has failed: the handler never resumes.
    if (request.aborted) return new Promise(() => {});
    return { status: 200, responseText: JSON.stringify(calls.map(b.answer)) };
  };
  return b;
}

function request(body, ip, be) {
  const r = {
    requestText: typeof body === 'string' ? body : JSON.stringify(body),
    variables: { remote_addr: ip },
    headersOut: {},
    status: null,
    body: null,
    redirect: null,
    aborted: false,
    return(status, text) { r.status = status; r.body = text === undefined ? null : JSON.parse(text); },
    internalRedirect(where) { r.redirect = where; r.status = 'proxied'; },
    subrequest(where, opts) { return be.subrequest(where, opts, r); },
  };
  return r;
}

const call = (id, method, params) => ({ jsonrpc: '2.0', id, method, params: params || [] });
const ethCall = (id) => call(id, 'eth_call', [{ to: '0x' + '00'.repeat(19) + 'be', data: '0x' }, 'latest']);
const tick = () => new Promise((f) => setImmediate(f));

// ------------------------------------------------------------------ faithfulness of the model (expected to pass)

test('model: the call budget holds for one IPv4 address (61st batch of 20 is 429)', async () => {
  reset();
  const be = backend();
  const batch = Array.from({ length: 20 }, (_, i) => call(i, 'eth_blockNumber'));
  const statuses = [];
  for (let i = 0; i < 61; i++) { const r = request(batch, '192.0.2.10', be); await gw.handle(r); statuses.push(r.status); }
  assert.deepEqual(statuses.slice(0, 60), Array(60).fill('proxied'));
  assert.equal(statuses[60], 429);
});

test('model: 17 eth_call from one client exceed the rendered simPerIp of 16', async () => {
  reset();
  const be = backend();
  assert.equal(cfg.simPerIp, 16);
  const r = request(Array.from({ length: 17 }, (_, i) => ethCall(i)), '192.0.2.11', be);
  await gw.handle(r);
  assert.equal(r.status, 429);
});

// ------------------------------------------------------------------ findings (each fails at f1c8033)

test('G1: an IPv6 client cannot multiply its call budget by rotating addresses inside its /64', async () => {
  reset();
  const be = backend();
  const batch = Array.from({ length: 20 }, (_, i) => call(i, 'eth_blockNumber'));
  const statuses = [];
  for (let i = 0; i < 61; i++) {
    const r = request(batch, `2001:db8:1:2::${(i + 1).toString(16)}`, be);
    await gw.handle(r);
    statuses.push(r.status);
  }
  assert.ok(statuses.includes(429), `61 batches of 20 (1,220 calls, budget ${cfg.callsPerMinute}/min) from one /64: no 429`);
});

test('G1: an IPv6 client cannot multiply its transaction budget inside its /64', async () => {
  reset();
  const be = backend();
  const tx = (i) => call(i, 'eth_sendRawTransaction', ['0x02' + 'ab'.repeat(60)]);
  const statuses = [];
  for (let i = 0; i < cfg.txPerMinute + 1; i++) {
    const r = request(tx(i), `2001:db8:1:2:${i.toString(16)}::1`, be);
    await gw.handle(r);
    statuses.push(r.status);
  }
  assert.equal(statuses[cfg.txPerMinute], 429, `${cfg.txPerMinute + 1} transactions from one /64: ${JSON.stringify(statuses.slice(-3))}`);
});

test('G2: one client cannot hold more EVM simulations in flight than one backend has permits', async () => {
  reset();
  const be = backend();
  be.hold = true;
  const r = request(Array.from({ length: BACKEND_PERMITS + 1 }, (_, i) => ethCall(i)), '192.0.2.20', be);
  const done = gw.handle(r);
  await tick();
  const admitted = be.inFlight;
  be.release();
  await done;
  assert.ok(admitted <= BACKEND_PERMITS,
    `one IPv4 client has ${admitted} eth_call in flight at the backend, which serves ${BACKEND_PERMITS} at a time for every client`);
});

test('G2: simulations in flight across all clients stay within the permits of both backends', async () => {
  reset();
  const be = backend();
  be.hold = true;
  const pending = [];
  for (let c = 0; c < 4; c++) {
    const r = request(Array.from({ length: 4 }, (_, i) => ethCall(i)), `198.51.100.${c + 1}`, be);
    pending.push({ r, done: gw.handle(r) });
  }
  await tick();
  const admitted = be.inFlight;
  be.release();
  await Promise.all(pending.map((p) => p.done));
  assert.ok(admitted <= BACKEND_PERMITS * BACKENDS,
    `4 IPv4 clients have ${admitted} eth_call in flight, ${BACKEND_PERMITS * BACKENDS} permits exist; the rest wait up to 10 s and fail -32005`);
});

test('G3: a client that closes its connection mid-simulation does not lose its simulation slots for good', async () => {
  reset();
  const be = backend();
  be.hold = true;
  const ip = '203.0.113.30';
  const first = request(Array.from({ length: 16 }, (_, i) => ethCall(i)), ip, be);
  gw.handle(first);
  await tick();
  first.aborted = true; // the client (or Cloudflare) closes the connection
  be.release();
  await tick();
  be.hold = false;
  // The client keeps using the endpoint: one eth_call a minute for ten minutes.
  const statuses = [];
  for (let minute = 1; minute <= 10; minute++) {
    offsetMs = minute * 60000;
    const later = request(ethCall(minute), ip, be);
    await gw.handle(later);
    statuses.push(later.status);
  }
  healthy();
  assert.notEqual(statuses[statuses.length - 1], 429,
    `ten minutes later still 429 (${JSON.stringify(statuses)}); l2rate "s ${ip}" = ${ngx.shared.l2rate.get('s ' + ip)}`);
});

test('G7 (Info): duplicate ids inside a split batch get their own answers', async () => {
  reset();
  const be = backend();
  const r = request([ethCall(1), call(1, 'eth_getBalance', ['0x' + '11'.repeat(20), 'latest'])], '192.0.2.70', be);
  await gw.handle(r);
  assert.equal(r.status, 200);
  assert.notDeepEqual(r.body[0], r.body[1], `both calls got ${JSON.stringify(r.body[1])}`);
});
