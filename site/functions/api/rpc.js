const UPSTREAM = 'https://l2rpc.posternlabs.com';
const hash = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{64}$/.test(v);
const address = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
const block = (v) => v === 'latest' || (typeof v === 'string' && /^0x[0-9a-fA-F]{1,16}$/.test(v));
const validators = {
  web3_clientVersion: (p) => p.length === 0,
  eth_chainId: (p) => p.length === 0,
  eth_blockNumber: (p) => p.length === 0,
  eth_getBlockByNumber: (p) => p.length === 2 && block(p[0]) && p[1] === false,
  eth_getBlockByHash: (p) => p.length === 2 && hash(p[0]) && p[1] === false,
  eth_getTransactionByHash: (p) => p.length === 1 && hash(p[0]),
  eth_getTransactionReceipt: (p) => p.length === 1 && hash(p[0]),
  eth_getBalance: (p) => p.length === 2 && address(p[0]) && p[1] === 'latest',
  eth_getTransactionCount: (p) => p.length === 2 && address(p[0]) && p[1] === 'latest',
};
const response = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
});
export async function onRequest({ request }) {
  if (request.method !== 'POST') return response({ error: 'POST required' }, 405);
  if (Number(request.headers.get('content-length') || 0) > 2048) return response({ error: 'Request too large' }, 413);
  let stage = 'request';
  let timeout;
  try {
    if (!request.body) return response({ error: 'Request body required' }, 400);
    const input = request.body.getReader();
    const decoder = new TextDecoder(); let text = ''; let inputBytes = 0;
    while (true) {
      const { value, done } = await input.read();
      if (done) break;
      inputBytes += value.length;
      if (inputBytes > 2048) { await input.cancel(); return response({ error: 'Request too large' }, 413); }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    const { method, params } = JSON.parse(text);
    if (!Object.hasOwn(validators, method) || !Array.isArray(params) || !validators[method](params)) {
      return response({ error: 'Unsupported read-only request' }, 400);
    }
    stage = 'upstream';
    const controller = new AbortController();
    timeout = setTimeout(() => controller.abort(), 10000);
    const upstream = await fetch(UPSTREAM, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: controller.signal,
    });
    if (!upstream.ok || !upstream.body) return response({ error: 'Upstream unavailable' }, 502);
    stage = 'response';
    const reader = upstream.body.getReader();
    const chunks = []; let length = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > 1048576) { await reader.cancel(); return response({ error: 'Upstream response too large' }, 502); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const c of chunks) { bytes.set(c, offset); offset += c.length; }
    const data = JSON.parse(new TextDecoder().decode(bytes));
    if (data.error) return response({ error: 'This query is unavailable on the connected RPC.' }, 502);
    if (!Object.hasOwn(data, 'result')) return response({ error: 'Invalid upstream response' }, 502);
    return response({ result: data.result });
  } catch (error) { console.error('rpc failure', stage, error.name, error.message); return response({ error: `RPC unavailable (${stage}). Try again shortly.` }, 502); } finally { if (timeout !== undefined) clearTimeout(timeout); }
}
