const $ = (id) => document.getElementById(id);
let generation = 0;
async function rpc(method, params = []) {
  const res = await fetch('/api/rpc', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ method, params }), signal: AbortSignal.timeout(15000) });
  const data = await res.json();
  if (!res.ok || data.error) throw new Error(data.error || 'RPC unavailable');
  return data.result;
}
function quantity(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value)) throw new Error('Invalid RPC quantity');
  return BigInt(value).toString();
}
async function identity() {
  try {
    const [chain, client] = await Promise.all([rpc('eth_chainId'), rpc('web3_clientVersion')]);
    const id = quantity(chain);
    if (typeof client !== 'string') throw new Error('Invalid client identity');
    $('network-status').textContent = `Connected RPC · Chain ID ${id} · ${client} · ${id === '8400' ? 'Legacy devnet — not the new L2 release' : 'Unexpected identity — verify the network before interpreting results'}`;
  } catch { $('network-status').textContent = 'RPC identity unavailable. Results cannot currently be verified against a connected network.'; $('network-status').classList.add('error'); }
}
function card(title, value) {
  const article = document.createElement('article'); article.className = 'result-card';
  const heading = document.createElement('h3'); heading.textContent = title;
  const pre = document.createElement('pre'); pre.textContent = value === null ? 'No record returned by this RPC.' : JSON.stringify(value, null, 2);
  article.append(heading, pre); $('result-content').append(article);
}
async function search(value) {
  const current = ++generation;
  $('result-content').replaceChildren(); $('result-status').classList.remove('error'); $('result-status').textContent = 'Querying the connected RPC…';
  try {
    let title, records;
    if (/^0x[0-9a-fA-F]{40}$/.test(value)) {
      title = 'Address';
      const data = await Promise.allSettled([rpc('eth_getBalance', [value, 'latest']), rpc('eth_getTransactionCount', [value, 'latest'])]);
      records = data.map((r, i) => [i ? 'Transaction count' : 'Balance · base units (wei)', r.status === 'fulfilled' ? { address: value, value: quantity(r.value), block: 'latest' } : { unavailable: r.reason.message }]);
    } else if (/^0x[0-9a-fA-F]{64}$/.test(value)) {
      title = 'Hash lookup';
      const data = await Promise.allSettled([rpc('eth_getTransactionByHash', [value]), rpc('eth_getTransactionReceipt', [value]), rpc('eth_getBlockByHash', [value, false])]);
      records = data.map((r, i) => [['Transaction', 'Receipt', 'Block'][i], r.status === 'fulfilled' ? r.value : { unavailable: r.reason.message }]);
    } else if (value === 'latest' || /^\d{1,20}$/.test(value)) {
      title = value === 'latest' ? 'Latest block' : `Block ${value}`;
      if (value !== 'latest' && BigInt(value) > 0xffffffffffffffffn) throw new Error('Block number is too large.');
      records = [['Block', await rpc('eth_getBlockByNumber', [value === 'latest' ? value : `0x${BigInt(value).toString(16)}`, false])]];
    } else throw new Error('Enter a decimal block number, full EVM address, full hash, or latest.');
    if (current !== generation) return;
    $('result-title').textContent = title;
    for (const [label, result] of records) card(label, result);
    $('result-status').textContent = `Query completed at ${new Date().toLocaleTimeString('en-US')}. See individual results for missing or unsupported records.`;
  } catch (error) {
    if (current !== generation) return;
    $('result-status').classList.add('error'); $('result-status').textContent = error.message;
  }
}
$('search-form').addEventListener('submit', (event) => { event.preventDefault(); void search($('query').value.trim()); });
$('refresh').addEventListener('click', () => { void identity(); void search('latest'); });
void identity(); void search('latest');
