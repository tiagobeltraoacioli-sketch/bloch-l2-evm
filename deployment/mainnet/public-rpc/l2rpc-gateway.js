// SPDX-License-Identifier: MIT OR Apache-2.0
// Bloch L2 mainnet public JSON-RPC gateway (nginx njs >= 0.8.1).
//
// nginx terminates TLS, applies CORS, per-IP request rate and connection
// limits and the body cap; this module validates every JSON-RPC call against
// the method allowlist, charges per-IP call and transaction budgets, answers
// the chain identity locally and routes the request:
//
//   read     to the fresher of the local settled RPC and the peer host's
//            (nginx upstream with the other one as backup)
//   seqread  the sequencer first (it counts the spool and knows the required tip), then the other:
//            eth_getTransactionCount at pending, eth_gasPrice, eth_maxPriorityFeePerGas, eth_feeHistory
//   finality a call at `safe` or `finalized`, bloch_finality, bloch_settlement or
//            bloch_getWithdrawalProof: to a backend whose follower status is valid
//            and younger than cfg.maxStatusAgeS and, among those, the one with the
//            higher finalized level; once more to the other backend when the first
//            has closed those levels, answers null, lacks the proof, or refused the
//            round trip (429/502/503); never after a read timeout (504). A stale
//            status alone never refuses a read: old finality is still true, and
//            /health reports the age. A backend with no status view is not current.
//   tx       eth_sendRawTransaction, the sequencer only, never retried
//
// Backend freshness comes from a js_periodic probe (chain id, head, finalized,
// follower status) kept in a shared dictionary; /health reports it.
import cfg from 'l2rpc-config.js';

const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Fee suggestions: answered by the sequencer first (route seqread).
const FEE_METHODS = { eth_gasPrice: true, eth_maxPriorityFeePerGas: true, eth_feeHistory: true };

// route per method; block: index of the block parameter (for "pending").
const METHODS = {
  web3_clientVersion: 'read',
  web3_sha3: 'read',
  net_version: 'local',
  net_listening: 'read',
  net_peerCount: 'read',
  eth_chainId: 'local',
  eth_syncing: 'read',
  eth_accounts: 'read',
  eth_blockNumber: 'read',
  eth_gasPrice: 'read',
  eth_maxPriorityFeePerGas: 'read',
  eth_blobBaseFee: 'read',
  eth_feeHistory: 'read',
  eth_getBalance: 'read',
  eth_getCode: 'read',
  eth_getStorageAt: 'read',
  eth_getTransactionCount: 'read',
  eth_getProof: 'read',
  eth_call: 'read',
  eth_estimateGas: 'read',
  eth_createAccessList: 'read',
  eth_getBlockByNumber: 'read',
  eth_getBlockByHash: 'read',
  eth_getBlockReceipts: 'read',
  eth_getBlockTransactionCountByNumber: 'read',
  eth_getBlockTransactionCountByHash: 'read',
  eth_getUncleCountByBlockNumber: 'read',
  eth_getUncleCountByBlockHash: 'read',
  eth_getUncleByBlockNumberAndIndex: 'read',
  eth_getUncleByBlockHashAndIndex: 'read',
  eth_getTransactionByHash: 'read',
  eth_getRawTransactionByHash: 'read',
  eth_getTransactionByBlockNumberAndIndex: 'read',
  eth_getTransactionByBlockHashAndIndex: 'read',
  eth_getTransactionReceipt: 'read',
  eth_getLogs: 'read',
  eth_sendRawTransaction: 'tx',
  bloch_finality: 'read',
  bloch_settlement: 'read',
  bloch_chainIdentity: 'read',
  bloch_chainStatus: 'read',
  bloch_getWithdrawalProof: 'read',
};

const EXPLAINED = {
  eth_newFilter: 'Filters are not supported behind a multi-backend gateway; poll eth_getLogs with a block range.',
  eth_newBlockFilter: 'Filters are not supported behind a multi-backend gateway; poll eth_blockNumber.',
  eth_newPendingTransactionFilter: 'Filters are not supported behind a multi-backend gateway.',
  eth_getFilterChanges: 'Filters are not supported behind a multi-backend gateway; poll eth_getLogs with a block range.',
  eth_getFilterLogs: 'Filters are not supported behind a multi-backend gateway; use eth_getLogs.',
  eth_uninstallFilter: 'Filters are not supported behind a multi-backend gateway.',
  eth_subscribe: 'Subscriptions need WebSocket; this endpoint is HTTPS JSON-RPC only.',
  eth_unsubscribe: 'Subscriptions need WebSocket; this endpoint is HTTPS JSON-RPC only.',
  eth_sendTransaction: 'The node holds no keys. Sign locally and use eth_sendRawTransaction.',
  eth_sign: 'The node holds no keys. Sign locally.',
  eth_signTransaction: 'The node holds no keys. Sign locally.',
  eth_signTypedData_v4: 'The node holds no keys. Sign locally.',
};

// EVM simulations and raw transaction admission: the expensive calls. They go through njs subrequests and
// hold a slot each while in flight (see "EVM slots" below): simulations 'e', transaction admission 't'.
const SIMULATION = { eth_call: true, eth_estimateGas: true, eth_createAccessList: true };
function evmKind(method) {
  if (method === 'eth_sendRawTransaction') return 't';
  return SIMULATION[method] === true ? 'e' : null;
}
// A slot lives this long unless its request ends first: longer than one round trip can last (the subrequest
// hop reads for 40 s at most). It is renewed before the finality retry.
const SLOT_TTL_MS = cfg.slotTtlMs || 60000;
// Slots of cfg.simTotal that simulations never take, so transaction admission is not starved by them.
const TX_RESERVE = cfg.txReserve === undefined ? Math.floor(cfg.simTotal / 4) : cfg.txReserve;
// Transaction admissions in flight per client, counted apart from its simulations.
const TX_PER_IP = cfg.txPerIp === undefined ? cfg.simPerIp : cfg.txPerIp;

// Position of the block parameter of each method that takes a tag.
const TAG_POSITION = {
  eth_getBlockByNumber: 0, eth_getBlockReceipts: 0, eth_getBlockTransactionCountByNumber: 0,
  eth_getUncleCountByBlockNumber: 0, eth_getUncleByBlockNumberAndIndex: 0, eth_getTransactionByBlockNumberAndIndex: 0,
  eth_feeHistory: 1, eth_getBalance: 1, eth_getCode: 1, eth_getTransactionCount: 1, eth_call: 1, eth_estimateGas: 1,
  eth_createAccessList: 1, eth_getStorageAt: 2, eth_getProof: 2,
};
// Answered from the follower status, so the same choice of backend applies.
const FINALITY_METHODS = { bloch_finality: true, bloch_settlement: true, bloch_getWithdrawalProof: true };
// Answers the other backend may do better on: levels closed (-32001), and for a withdrawal proof: not finalized
// here yet, unknown index, unknown root, index catching up, frozen.
const RETRY_CODES = { '-32001': true, '-32041': true, '-32042': true, '-32043': true, '-32045': true, '-32046': true };

// Largest backend answer for one split part (a request that goes through njs subrequests: any eth_call,
// eth_estimateGas, eth_createAccessList or eth_sendRawTransaction, finality calls, mixed routes). The subrequest is held in memory,
// so the answer is bounded: the size guard (guardHeader/guardBody, on the hop in front of each backend)
// replaces a larger answer with a short marker, and every call of that part gets -32005 "response too large".
const SUB_ANSWER_MAX = cfg.subAnswerMaxBytes || 2097152;

const HEX_QTY = /^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$/;
const HASH32 = /^0x[0-9a-fA-F]{64}$/;

function qty(v) {
  if (typeof v !== 'string' || !HEX_QTY.test(v) || v.length > 18) return null;
  return parseInt(v, 16);
}

function err(id, code, message, data) {
  const e = { code: code, message: message };
  if (data !== undefined) e.data = data;
  return { jsonrpc: '2.0', id: id === undefined ? null : id, error: e };
}

function ok(id, result) {
  return { jsonrpc: '2.0', id: id, result: result };
}

// ---------------------------------------------------------------- backend state

function readState(name) {
  const raw = ngx.shared.l2state.get(name);
  if (!raw) return null;
  try {
    const s = JSON.parse(raw);
    s.age = Date.now() - s.ts;
    return s;
  } catch (e) {
    return null;
  }
}

function fresh(s) {
  return s !== null && s.age <= cfg.stateMaxAgeMs;
}

// Head of the best healthy backend, for eth_getLogs range checks.
function bestHead() {
  let best = null;
  ['local', 'peer'].forEach((n) => {
    const s = readState(n);
    if (fresh(s) && s.ok && (best === null || s.head > best)) best = s.head;
  });
  return best;
}

// 'local' or 'peer': the backend a read goes to first (nginx falls back to
// the other on transport errors and 502/503/504).
function readTarget() {
  const l = readState('local');
  const p = readState('peer');
  const lOk = fresh(l) && l.ok;
  const pOk = fresh(p) && p.ok;
  if (lOk && pOk) return l.head + cfg.maxLagBlocks >= p.head ? 'local' : 'peer';
  if (lOk) return 'local';
  if (pOk) return 'peer';
  return 'local';
}

function isLevel(v) {
  return v === 'finalized' || v === 'safe';
}

function namesFinalityLevel(method, params) {
  if (!Array.isArray(params)) return false;
  if (method === 'eth_getLogs') {
    const f = params[0];
    return !!f && typeof f === 'object' && (isLevel(f.fromBlock) || isLevel(f.toBlock));
  }
  if (!has(TAG_POSITION, method)) return false;
  const v = params[TAG_POSITION[method]];
  return isLevel(v) || (!!v && typeof v === 'object' && isLevel(v.blockNumber));
}

// A backend answering, with a valid follower status younger than the threshold. No status view (a backend
// starting, or without a follower) is not current, and neither is one whose database lags its follower.
function finalityCurrent(s) {
  return fresh(s) && s.ok && s.statusState === 'ok' && s.statusAge !== null && s.statusAge <= cfg.maxStatusAgeS;
}

// A backend whose levels are open, even on an old status or behind its follower.
function finalityOpen(s) {
  return fresh(s) && s.ok && (s.statusState === 'ok' || s.statusState === 'lagging');
}

// 'local' or 'peer': the first backend for a finality read. Among open backends the higher finalized level,
// so that routing does not move a client backwards; then current; then the read target.
function finalityTarget() {
  const l = readState('local');
  const p = cfg.peerProbeUrl ? readState('peer') : null;
  if (finalityOpen(l) && finalityOpen(p)) {
    const lf = l.finalized === null ? -1 : l.finalized;
    const pf = p.finalized === null ? -1 : p.finalized;
    if (lf !== pf) return lf > pf ? 'local' : 'peer';
    if (finalityCurrent(l) !== finalityCurrent(p)) return finalityCurrent(l) ? 'local' : 'peer';
    return readTarget();
  }
  if (finalityOpen(l)) return 'local';
  return finalityOpen(p) ? 'peer' : readTarget();
}

function closedAnswer(reply) {
  if (!reply || typeof reply !== 'object') return false;
  if (reply.error) return RETRY_CODES[String(reply.error.code)] === true;
  // Null is "nothing here": a backend starting, or one behind the other. The peer may hold it.
  if (reply.result === null) return true;
  // bloch_finality names a state; only an answer with the member can say the levels are closed.
  const status = typeof reply.result === 'object' ? reply.result.status : null;
  return !!status && typeof status === 'object' && status.state !== undefined && status.state !== 'ok' && status.state !== 'lagging';
}

function sequencerDown() {
  const s = readState(cfg.role === 'sequencer' ? 'local' : 'peer');
  return fresh(s) && !s.ok;
}

// ------------------------------------------------------------------ validation

function logsScopeError(params) {
  const f = Array.isArray(params) ? params[0] : undefined;
  if (!f || typeof f !== 'object' || Array.isArray(f)) return 'eth_getLogs expects one filter object.';
  if (f.blockHash !== undefined) {
    if (f.fromBlock !== undefined || f.toBlock !== undefined) return 'blockHash excludes fromBlock/toBlock.';
    return typeof f.blockHash === 'string' && HASH32.test(f.blockHash) ? null : 'blockHash must be a 32-byte hex string.';
  }
  if (Array.isArray(f.address) && f.address.length > cfg.maxLogAddresses) {
    return 'At most ' + cfg.maxLogAddresses + ' addresses per eth_getLogs call.';
  }
  const tagged = (v) => v === undefined || v === null || typeof v !== 'string' || !HEX_QTY.test(v);
  let head = null;
  if (tagged(f.fromBlock) || tagged(f.toBlock)) {
    head = bestHead();
    if (head === null) return 'Chain head unknown; retry shortly or use numeric fromBlock/toBlock.';
  }
  const resolve = (v) => {
    if (v === undefined || v === null || v === 'latest' || v === 'pending' || v === 'safe' || v === 'finalized') return head;
    if (v === 'earliest') return 0;
    return qty(v);
  };
  const from = resolve(f.fromBlock);
  const to = resolve(f.toBlock);
  if (from === null || to === null) return 'fromBlock/toBlock must be a hex quantity or a block tag.';
  if (to < from) return 'toBlock is below fromBlock.';
  if (to - from + 1 > cfg.maxLogBlockRange) {
    return 'Block range too large: at most ' + cfg.maxLogBlockRange + ' blocks per eth_getLogs call.';
  }
  return null;
}

// Returns {route} for a forwardable call, {reply} for one answered here.
function classify(call) {
  if (call === null || typeof call !== 'object' || Array.isArray(call)) {
    return { reply: err(null, -32600, 'Invalid request') };
  }
  const id = call.id;
  if (call.jsonrpc !== '2.0' || typeof call.method !== 'string') return { reply: err(id, -32600, 'Invalid request') };
  if (id !== undefined && id !== null && typeof id !== 'string' && typeof id !== 'number') {
    return { reply: err(null, -32600, 'Invalid request id') };
  }
  if (call.params !== undefined && (call.params === null || typeof call.params !== 'object')) {
    return { reply: err(id, -32602, 'params must be an array or an object') };
  }
  const m = call.method;
  if (has(EXPLAINED, m)) return { reply: err(id, -32601, 'Method not available: ' + m + '. ' + EXPLAINED[m]) };
  if (!has(METHODS, m)) return { reply: err(id, -32601, 'Method not available: ' + m) };
  const route = METHODS[m];
  if (route === 'local') {
    if (m === 'eth_chainId') return { reply: ok(id, cfg.chainIdHex) };
    return { reply: ok(id, String(cfg.chainId)) };
  }
  if (m === 'eth_getLogs') {
    const e = logsScopeError(call.params);
    if (e) return { reply: err(id, -32602, e) };
  }
  if (m === 'eth_getTransactionCount' && Array.isArray(call.params) && call.params[1] === 'pending') {
    return { route: 'seqread' };
  }
  // Only the sequencer's RPC knows the sequencer's required tip (--required-tip-file); a replica suggests the floor.
  if (FEE_METHODS[m] === true && !namesFinalityLevel(m, call.params)) return { route: 'seqread' };
  if (route === 'read' && (FINALITY_METHODS[m] === true || namesFinalityLevel(m, call.params))) return { route: 'finality' };
  return { route: route };
}

// --------------------------------------------------------------------- budgets

// The budget key of a client: its IPv4 address, or the /64 of its IPv6 address (one subscriber line holds a
// whole /64, so a per-address key would let it multiply every budget). IPv4-mapped IPv6 counts as IPv4.
// bits 56: the key of the EVM slots, since a subscriber line usually holds a /56 (review R308-27).
function clientKey(addr, bits) {
  if (typeof addr !== 'string' || addr.indexOf(':') < 0) return addr;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  if (mapped) return mapped[1];
  const halves = addr.toLowerCase().split('::');
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const groups = halves.length > 1 ? head.concat(Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), tail) : head;
  const four = groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, ''));
  if (bits === 56) {
    if (four.length === 4) four[3] = (('0000' + four[3]).slice(-4).slice(0, 2) + '00').replace(/^0+(?=.)/, '');
    return four.join(':') + '::/56';
  }
  return four.join(':') + '::/64';
}

// js_set $l2_client: the key of nginx's limit_req and limit_conn zones.
function client(r) {
  return clientKey(r.variables.remote_addr);
}

function charge(r, calls, txs) {
  const ip = clientKey(r.variables.remote_addr);
  const minute = Math.floor(Date.now() / 60000);
  const d = ngx.shared.l2rate;
  const c = d.incr('c ' + ip + ' ' + minute, calls, 0);
  if (c > cfg.callsPerMinute) return 'call';
  if (txs > 0 && d.incr('t ' + ip + ' ' + minute, txs, 0) > cfg.txPerMinute) return 'tx';
  return null;
}

// ------------------------------------------------------------------- EVM slots
//
// One key per call in flight in the shared dictionary l2slots: "<kind> <client> <request> <n>", its value the
// time (ms) it stops counting. A request deletes its keys when its subrequests return; a request whose client
// connection failed is never resumed by njs, and its keys then stop counting by themselves after SLOT_TTL_MS
// (review R308-27: no counter that needs a release). Limits, each counted over the live keys:
//   simulations per client          cfg.simPerIp
//   transaction admissions per client   TX_PER_IP
//   simulations, all clients        cfg.simTotal - TX_RESERVE (the reserve is for transactions only)
//   simulations and admissions, all clients   cfg.simTotal
// The client of a slot is its IPv4 address or its IPv6 /56.

function slotCounts(d, now, who) {
  const n = { e: 0, t: 0, myE: 0, myT: 0 };
  const mine = ' ' + who + ' ';
  const keys = d.keys(4096);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const until = d.get(key);
    if (until === undefined) continue;
    if (until <= now) {
      d.delete(key);
      continue;
    }
    const kind = key.charAt(0) === 't' ? 't' : 'e';
    n[kind]++;
    if (key.indexOf(mine) === 1) n[kind === 't' ? 'myT' : 'myE']++;
  }
  return n;
}

function releaseSlots(hold) {
  hold.keys.forEach((key) => { hold.d.delete(key); });
}

function renewSlots(hold) {
  const until = Date.now() + SLOT_TTL_MS;
  hold.keys.forEach((key) => { hold.d.set(key, until); });
}

// Takes `sims` simulation slots and `txs` admission slots for one wave of a request. Returns the hold, with
// hold.refused set ('client' or 'busy', and nothing held) when a limit is reached. The keys are written
// first and counted after, so two workers racing for the last slot can both be refused, never both admitted.
function takeSlots(r, tag, sims, txs) {
  const d = ngx.shared.l2slots;
  const who = clientKey(r.variables.remote_addr, 56);
  const hold = { d: d, keys: [], refused: null };
  const now = Date.now();
  for (let i = 0; i < sims + txs; i++) {
    const key = (i < sims ? 'e' : 't') + ' ' + who + ' ' + tag + '.' + i;
    d.set(key, now + SLOT_TTL_MS);
    hold.keys.push(key);
  }
  const n = slotCounts(d, now, who);
  if ((sims > 0 && n.myE > cfg.simPerIp) || (txs > 0 && n.myT > TX_PER_IP)) hold.refused = 'client';
  else if (n.e + n.t > cfg.simTotal || (sims > 0 && n.e + n.t - txs > cfg.simTotal - TX_RESERVE)) hold.refused = 'busy';
  if (hold.refused) {
    releaseSlots(hold);
    hold.keys = [];
  }
  return hold;
}

function slotMessage(refused) {
  return refused === 'client'
    ? 'Rate limited: at most ' + cfg.simPerIp + ' EVM simulations and ' + TX_PER_IP + ' transaction admissions in flight per client.'
    : 'Busy: too many EVM simulations or transaction admissions in flight; retry shortly.';
}

// ---------------------------------------------------------------------- output

function send(r, status, body) {
  r.headersOut['Content-Type'] = 'application/json';
  r.headersOut['Cache-Control'] = 'no-store';
  r.return(status, JSON.stringify(body));
}

function tooLarge(id) {
  return err(id, -32005, 'Response too large: the answer to this request is above ' + SUB_ANSWER_MAX +
    ' bytes. Send this call alone, without eth_call/eth_estimateGas/eth_createAccessList in the same batch, or narrow it.',
    { limitBytes: SUB_ANSWER_MAX });
}

function unavailable(id, route) {
  if (route === 'tx') {
    return err(id, -32052, 'Submission outcome unknown: the sequencer did not answer. Check the transaction hash or the nonce before resending.');
  }
  return err(id, -32053, 'No healthy L2 backend; retry shortly.');
}

const BACKEND = { local: '/_l2/local', peer: '/_l2/peer' };

function location(route) {
  if (route === 'tx') return '/_l2/seq';
  if (route === 'seqread') return '/_l2/seqread';
  if (route === 'finality') return BACKEND[finalityTarget()];
  return readTarget() === 'local' ? '/_l2/local' : '/_l2/peer';
}

// One upstream round trip for `calls`; the answers by id, empty on any failure.
// Calls go out with their batch index as id (client ids may repeat, or lose precision as numbers), and their
// answers are keyed by that index.
function outgoing(x) {
  if (x.call.id === undefined) return x.call;
  const copy = {};
  Object.keys(x.call).forEach((k) => { copy[k] = x.call[k]; });
  copy.id = x.index;
  return copy;
}

// Subrequests go through the size-guarded twin of each backend location (/_l2s/...).
// The answers by batch index; byId.status is the HTTP status of the hop, 0 when the subrequest itself failed.
async function roundTrip(r, where, calls) {
  const byId = {};
  Object.defineProperty(byId, 'status', { value: 0, writable: true, enumerable: false });
  let reply;
  try {
    reply = await r.subrequest(where.replace('/_l2/', '/_l2s/'), { method: 'POST', body: JSON.stringify(calls.map(outgoing)) });
  } catch (e) {
    // A rejected subrequest may already have reached the sequencer. Preserve
    // the unknown-submission response and never retry the transaction route.
    return byId;
  }
  byId.status = Number(reply.status) || 0;
  if (reply.status === 200) {
    try {
      const parsed = JSON.parse(reply.responseText);
      if (parsed && !Array.isArray(parsed) && typeof parsed === 'object' && parsed.l2_too_large !== undefined) {
        byId.tooLarge = true;
      } else if (Array.isArray(parsed)) {
        parsed.forEach((item) => {
          if (item && typeof item === 'object' && typeof item.id === 'number') byId[item.id] = item;
        });
      }
    } catch (e) {
      // no answers
    }
  }
  return byId;
}

// The hop refused or could not reach its backends: nothing ran there, so the other backend may be asked.
// 504 (the 30 s read timeout), a failed subrequest and an answer that does not parse are not in this list:
// the call may still be running on the first backend (decision G4: a read timeout is never retried on the
// other backend; review R308-28).
const RETRY_STATUS = { 429: true, 502: true, 503: true };

// Finality calls go once to the other backend when the first one answered them with a parsed "closed"
// answer, or refused the whole round trip with 429/502/503. The second answer replaces the first only if it
// is not closed too. `before` runs ahead of the second round trip (the caller renews its EVM slots).
async function retryFinality(r, first, calls, byId, before) {
  if (byId.tooLarge) return; // the other backend's answer is as large
  if (!cfg.peerProbeUrl) return;
  const refused = RETRY_STATUS[byId.status] === true;
  const again = calls.filter((c) => c.call.id !== undefined && (byId[c.index] ? closedAnswer(byId[c.index]) : refused));
  if (!again.length) return;
  if (before) before();
  const other = first === BACKEND.local ? BACKEND.peer : BACKEND.local;
  const second = await roundTrip(r, other, again);
  again.forEach((c) => {
    const key = c.index;
    if (second[key] && !closedAnswer(second[key])) byId[key] = second[key];
    else if (!byId[key] && second[key]) byId[key] = second[key];
  });
}

async function forwardPart(r, p, before) {
  const where = location(p.route);
  const byId = await roundTrip(r, where, p.calls);
  if (p.route === 'finality') await retryFinality(r, where, p.calls, byId, before);
  return { p: p, byId: byId };
}

async function forwardParts(r, parts, before) {
  // parts: [{route, calls: [{index, call}]}]; one upstream round trip per route, plus a retry for finality.
  const results = await Promise.all(parts.map((p) => forwardPart(r, p, before)));
  const out = [];
  results.forEach((x) => {
    x.p.calls.forEach((c) => {
      if (c.call.id === undefined) return;
      if (x.byId.tooLarge) {
        out.push({ index: c.index, reply: tooLarge(c.call.id), unanswered: false });
        return;
      }
      const hit = x.byId[c.index];
      if (hit) hit.id = c.call.id;
      out.push({ index: c.index, reply: hit || unavailable(c.call.id, x.p.route), unanswered: !hit });
    });
  });
  return out;
}

// --------------------------------------------------------------------- handler

async function handle(r) {
  let body;
  try {
    body = JSON.parse(r.requestText || '');
  } catch (e) {
    return send(r, 200, err(null, -32700, 'Parse error'));
  }
  const batch = Array.isArray(body);
  const calls = batch ? body : [body];
  if (batch && calls.length === 0) return send(r, 200, err(null, -32600, 'Empty batch'));
  if (calls.length > cfg.maxBatch) {
    return send(r, 200, err(null, -32600, 'Batch too large: at most ' + cfg.maxBatch + ' calls per request.'));
  }

  const replies = [];
  const forward = [];
  let txs = 0;
  for (let i = 0; i < calls.length; i++) {
    const c = classify(calls[i]);
    if (c.reply) {
      if (calls[i] && typeof calls[i] === 'object' && calls[i].id === undefined && !c.reply.error) continue;
      replies.push({ index: i, reply: c.reply });
    } else {
      if (c.route === 'tx') txs++;
      forward.push({ index: i, call: calls[i], route: c.route });
    }
  }
  r.variables.l2_methods = calls
    .slice(0, 4)
    .map((c) => (c && typeof c.method === 'string' ? c.method.slice(0, 48) : '?'))
    .join(',') + (calls.length > 4 ? ',+' + (calls.length - 4) : '');

  const over = charge(r, calls.length, txs);
  if (over) {
    r.headersOut['Retry-After'] = '60';
    const msg = over === 'tx'
      ? 'Rate limited: at most ' + cfg.txPerMinute + ' eth_sendRawTransaction per minute per client.'
      : 'Rate limited: at most ' + cfg.callsPerMinute + ' calls per minute per client (a batch counts each call).';
    const ids = calls.map((c) => (c && typeof c === 'object' ? c.id : null));
    return send(r, 429, batch ? ids.map((id) => err(id, -32005, msg)) : err(ids[0], -32005, msg));
  }

  if (forward.length && forward.some((f) => f.route === 'tx') && sequencerDown()) {
    forward.filter((f) => f.route === 'tx').forEach((f) => {
      replies.push({ index: f.index, reply: err(f.call.id, -32053, 'The sequencer is unavailable; the transaction was not submitted.', { submitted: false }) });
    });
    for (let i = forward.length - 1; i >= 0; i--) if (forward[i].route === 'tx') forward.splice(i, 1);
  }

  if (forward.length === 0) {
    if (!batch) return replies.length ? send(r, 200, replies[0].reply) : r.return(204);
    return send(r, 200, replies.sort((a, b) => a.index - b.index).map((x) => x.reply));
  }

  const routes = {};
  forward.forEach((f) => { routes[f.route] = true; });
  const routeList = Object.keys(routes);
  const evm = forward.filter((f) => evmKind(f.call.method) !== null);

  // Fast path: no EVM work, everything forwardable shares one route and
  // nothing was answered here, so nginx proxies the original body unchanged.
  if (evm.length === 0 && replies.length === 0 && routeList.length === 1 && routeList[0] !== 'finality') {
    const route = routeList[0];
    const failures = forward.filter((f) => f.call.id !== undefined).map((f) => unavailable(f.call.id, route));
    r.variables.l2_failure = JSON.stringify(batch ? failures : failures[0] || err(null, -32053, 'No healthy L2 backend; retry shortly.'));
    r.internalRedirect(location(route));
    return;
  }

  // Waves: the calls without EVM work go with the first one; the EVM calls follow in request order, as many
  // per wave as one client may have in flight (cfg.simPerIp simulations, TX_PER_IP admissions). A batch
  // with more of them is therefore served, a wave at a time, and never holds more slots than its client may
  // (review R308-33b).
  const waves = [];
  let wave = { calls: forward.filter((f) => evmKind(f.call.method) === null), e: 0, t: 0 };
  evm.forEach((f) => {
    const kind = evmKind(f.call.method);
    if ((kind === 'e' && wave.e >= cfg.simPerIp) || (kind === 't' && wave.t >= TX_PER_IP)) {
      waves.push(wave);
      wave = { calls: [], e: 0, t: 0 };
    }
    wave.calls.push(f);
    wave[kind]++;
  });
  waves.push(wave);

  const tag = (r.variables.request_id || String(Math.random()).slice(2)) + '.';
  let forwarded = [];
  for (let k = 0; k < waves.length; k++) {
    const w = waves[k];
    let hold = null;
    if (w.e + w.t > 0) {
      hold = takeSlots(r, tag + k, w.e, w.t);
      if (hold.refused && k === 0) {
        // Nothing of this request ran: the whole request is refused.
        r.headersOut['Retry-After'] = '1';
        const msg = slotMessage(hold.refused);
        const ids = calls.map((c) => (c && typeof c === 'object' ? c.id : null));
        return send(r, 429, batch ? ids.map((id) => err(id, -32005, msg)) : err(ids[0], -32005, msg));
      }
      if (hold.refused) {
        // Earlier waves ran: the calls of this wave and the later ones are answered one by one.
        const msg = slotMessage(hold.refused) + ' This call of the batch was not run; send it again.';
        for (let j = k; j < waves.length; j++) {
          waves[j].calls.forEach((c) => {
            if (c.call.id === undefined) return;
            forwarded.push({ index: c.index, reply: err(c.call.id, -32005, msg, { run: false, submitted: false }), unanswered: false });
          });
        }
        break;
      }
    }
    // Split per route, merge in request order.
    const waveRoutes = {};
    w.calls.forEach((f) => { waveRoutes[f.route] = true; });
    const parts = Object.keys(waveRoutes).map((route) => ({ route: route, calls: w.calls.filter((f) => f.route === route) }));
    try {
      forwarded = forwarded.concat(await forwardParts(r, parts, hold ? () => renewSlots(hold) : null));
    } finally {
      if (hold) releaseSlots(hold);
    }
  }
  const merged = replies.concat(forwarded).sort((a, b) => a.index - b.index).map((x) => x.reply);
  // No backend answered any part: 503, as the single-route path answers (a batch mixing read and seqread calls).
  const status = replies.length === 0 && forwarded.length > 0 && forwarded.every((x) => x.unanswered) ? 503 : 200;
  if (!batch) return merged.length ? send(r, status, merged[0]) : r.return(204);
  return send(r, status, merged);
}

function failure(r) {
  return r.variables.l2_failure || JSON.stringify(err(null, -32053, 'No healthy L2 backend; retry shortly.'));
}

// ----------------------------------------------------------------- probe/health

const PROBE_BODY = JSON.stringify([
  { jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] },
  { jsonrpc: '2.0', id: 2, method: 'eth_blockNumber', params: [] },
  { jsonrpc: '2.0', id: 3, method: 'eth_getBlockByNumber', params: ['finalized', false] },
  { jsonrpc: '2.0', id: 4, method: 'bloch_finality', params: [] },
]);

async function probeOne(name, url) {
  const s = { ok: false, head: null, finalized: null, statusState: null, statusAge: null, ts: Date.now(), error: null };
  try {
    const reply = await ngx.fetch(url, {
      method: 'POST',
      body: PROBE_BODY,
      headers: { 'Content-Type': 'application/json' },
    });
    if (reply.status !== 200) throw new Error('HTTP ' + reply.status);
    const items = await reply.json();
    const by = {};
    items.forEach((it) => { by[it.id] = it; });
    const chain = by[1] && by[1].result;
    if (chain !== cfg.chainIdHex) throw new Error('chain id ' + chain);
    s.head = qty(by[2] && by[2].result);
    if (s.head === null) throw new Error('no head');
    const fin = by[3] && by[3].result;
    s.finalized = fin && typeof fin === 'object' ? qty(fin.number) : null;
    const signal = by[4] && by[4].result && by[4].result.status;
    if (signal && typeof signal === 'object') {
      s.statusState = typeof signal.state === 'string' ? signal.state : 'unknown';
      s.statusAge = typeof signal.age_s === 'number' ? signal.age_s : null;
    }
    s.ok = true;
  } catch (e) {
    s.error = String(e.message || e).slice(0, 120);
  }
  s.ts = Date.now();
  ngx.shared.l2state.set(name, JSON.stringify(s));
}

async function probe() {
  await Promise.all([probeOne('local', cfg.localProbeUrl), cfg.peerProbeUrl ? probeOne('peer', cfg.peerProbeUrl) : Promise.resolve()]);
}

function view(s) {
  if (s === null) return { ok: false, error: 'not probed yet' };
  return {
    ok: fresh(s) && s.ok,
    head: s.head,
    finalized: s.finalized,
    ageMs: s.age,
    followerStatus: s.statusState === null ? undefined : { state: s.statusState, ageS: s.statusAge },
    finalityCurrent: finalityCurrent(s),
    error: s.error || undefined,
  };
}

// ------------------------------------------------------------- size guard
// On the hop between a subrequest and its backend (the unix-socket guard server). A Content-Length above
// SUB_ANSWER_MAX is replaced by a short marker at once; a body without a length is passed until it crosses the
// limit and then cut (the subrequest then fails to parse and answers -32053). The subrequest buffer holds
// SUB_ANSWER_MAX plus a margin, so nginx never waits on, or aborts for, a body it cannot hold.
function guardHeader(r) {
  const n = Number(r.headersOut['Content-Length']);
  r.variables.l2_guard = n > SUB_ANSWER_MAX ? 'over' : 'pass';
  r.variables.l2_guard_n = '0';
  if (n > SUB_ANSWER_MAX) {
    delete r.headersOut['Content-Length'];
    r.headersOut['Content-Type'] = 'application/json';
  }
}

function guardBody(r, data, flags) {
  const state = r.variables.l2_guard;
  if (state === 'done') return;
  if (state === 'over') {
    r.variables.l2_guard = 'done';
    r.sendBuffer(JSON.stringify({ l2_too_large: SUB_ANSWER_MAX }), { last: true });
    return;
  }
  const n = Number(r.variables.l2_guard_n || 0) + data.length;
  r.variables.l2_guard_n = String(n);
  if (n > SUB_ANSWER_MAX) {
    r.variables.l2_guard = 'done';
    r.sendBuffer('', { last: true });
    return;
  }
  r.sendBuffer(data, flags);
}

function health(r) {
  const l = readState('local');
  const p = cfg.peerProbeUrl ? readState('peer') : null;
  const out = {
    chainId: cfg.chainIdHex,
    gateway: cfg.name,
    role: cfg.role,
    local: view(l),
    peer: cfg.peerProbeUrl ? view(p) : undefined,
  };
  out.sequencer = cfg.role === 'sequencer' ? out.local.ok : !!(out.peer && out.peer.ok);
  out.ok = out.local.ok || !!(out.peer && out.peer.ok);
  // Reads still work when this is false; alert on it.
  out.finalityCurrent = out.local.finalityCurrent === true || !!(out.peer && out.peer.finalityCurrent === true);
  out.maxStatusAgeS = cfg.maxStatusAgeS;
  r.headersOut['Content-Type'] = 'application/json';
  r.headersOut['Cache-Control'] = 'no-store';
  r.return(out.ok ? 200 : 503, JSON.stringify(out));
}

export default { handle, failure, probe, health, client, guardHeader, guardBody };
