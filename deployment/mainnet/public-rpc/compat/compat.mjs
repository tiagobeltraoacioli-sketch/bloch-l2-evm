// SPDX-License-Identifier: MIT OR Apache-2.0
// Wallet/library compatibility checks against the public gateway (chain 700770).
//
//   node compat.mjs URL RAW_TX SENDER
//
// URL: the gateway; RAW_TX: a signed transfer from a throwaway (unfunded) key,
// so the submission must come back as "insufficient funds" from the
// sequencer, mapped by each library to its own error type.
// Covers ethers v6 (JsonRpcProvider with its default batching), viem
// (public client, with and without JSON-RPC batching) and the call sequence
// MetaMask issues when a network is added and a transfer is prepared.
import { JsonRpcProvider, Transaction } from 'ethers';
import { createPublicClient, defineChain, http } from 'viem';

const [url, raw, sender] = process.argv.slice(2);
const GENESIS = '0x632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468';
const DEAD = '0x000000000000000000000000000000000000dEaD';
const BEEF = '0x000000000000000000000000000000000000bEEF';
let passed = 0;
let failed = 0;

async function check(name, fn) {
  try {
    const detail = await fn();
    passed++;
    console.log(`PASS ${name}${detail === undefined ? '' : ' ' + JSON.stringify(detail, (k, v) => (typeof v === 'bigint' ? v.toString() : v))}`);
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}: ${(e && (e.shortMessage || e.message)) || e}`.slice(0, 400));
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// ------------------------------------------------------------------ ethers v6
const provider = new JsonRpcProvider(url, undefined, { batchMaxCount: 100 });
await check('ethers getNetwork', async () => {
  const n = await provider.getNetwork();
  assert(n.chainId === 700770n, `chain ${n.chainId}`);
  return n.chainId;
});
await check('ethers getBlockNumber', async () => provider.getBlockNumber());
// No L2 block is settled yet, so safe/finalized are the genesis.
const head = await provider.getBlockNumber();
for (const tag of ['latest', 'pending', 'safe', 'finalized', 'earliest', 0]) {
  await check(`ethers getBlock(${tag})`, async () => {
    const b = await provider.getBlock(tag);
    if (tag === 'latest' || tag === 'pending') assert(b && b.number >= head, `number ${b && b.number}`);
    else assert(b && b.hash === GENESIS, `hash ${b && b.hash}`);
    return b.number;
  });
}
await check('ethers getFeeData (EIP-1559)', async () => {
  const f = await provider.getFeeData();
  assert(f.maxFeePerGas !== null && f.maxPriorityFeePerGas !== null, 'no 1559 fee data');
  return { maxFeePerGas: f.maxFeePerGas, maxPriorityFeePerGas: f.maxPriorityFeePerGas };
});
await check('ethers getBalance', async () => provider.getBalance(DEAD));
await check('ethers getTransactionCount(pending)', async () => provider.getTransactionCount(sender, 'pending'));
await check('ethers estimateGas', async () => {
  const g = await provider.estimateGas({ from: DEAD, to: BEEF, value: 0n });
  assert(g === 21000n, `gas ${g}`);
  return g;
});
await check('ethers call', async () => provider.call({ to: BEEF, data: '0x' }));
await check('ethers getLogs', async () => (await provider.getLogs({ fromBlock: 0, toBlock: 'latest' })).length);
await check('ethers getCode', async () => provider.getCode(BEEF));
await check('ethers 60 concurrent calls (auto-batched)', async () => {
  const all = await Promise.all(Array.from({ length: 60 }, (_, i) => provider.getBalance('0x' + (i + 1).toString(16).padStart(40, '0'))));
  return all.length;
});
await check('ethers broadcastTransaction -> INSUFFICIENT_FUNDS from the sequencer', async () => {
  try {
    await provider.broadcastTransaction(raw);
  } catch (e) {
    assert(e.code === 'INSUFFICIENT_FUNDS', `code ${e.code}: ${e.shortMessage}`);
    return e.code;
  }
  throw new Error('accepted an unfunded transaction');
});
await check('ethers parses the raw tx as chain 700770', async () => {
  const t = Transaction.from(raw);
  assert(t.chainId === 700770n && t.from.toLowerCase() === sender.toLowerCase(), 'decode');
  return t.type;
});
await check('ethers getTransactionReceipt(unknown) -> null', async () => {
  const r = await provider.getTransactionReceipt('0x' + '00'.repeat(32));
  assert(r === null, 'not null');
});

// ----------------------------------------------------------------------- viem
const chain = defineChain({
  id: 700770,
  name: 'Bloch L2',
  nativeCurrency: { name: 'Bloch', symbol: 'BLOCH', decimals: 18 },
  rpcUrls: { default: { http: [url] } },
});
for (const batch of [false, true]) {
  const c = createPublicClient({ chain, transport: http(url, { batch }) });
  const p = batch ? 'viem(batch)' : 'viem';
  await check(`${p} getChainId`, async () => {
    const id = await c.getChainId();
    assert(id === 700770, `chain ${id}`);
    return id;
  });
  for (const blockTag of ['latest', 'pending', 'safe', 'finalized']) {
    await check(`${p} getBlock(${blockTag})`, async () => {
      const b = await c.getBlock({ blockTag });
      if (blockTag === 'latest' || blockTag === 'pending') assert(b.number >= BigInt(head), `number ${b.number}`);
      else assert(b.hash === GENESIS, `hash ${b.hash}`);
      return b.number;
    });
  }
  await check(`${p} estimateFeesPerGas`, async () => c.estimateFeesPerGas());
  await check(`${p} getBalance+getTransactionCount+getCode in parallel`, async () =>
    Promise.all([c.getBalance({ address: DEAD }), c.getTransactionCount({ address: sender, blockTag: 'pending' }), c.getCode({ address: BEEF })]));
  await check(`${p} estimateGas`, async () => c.estimateGas({ account: DEAD, to: BEEF, value: 0n }));
  await check(`${p} call`, async () => c.call({ to: BEEF, data: '0x' }));
  await check(`${p} getLogs`, async () => (await c.getLogs({ fromBlock: 0n, toBlock: 'latest' })).length);
  await check(`${p} sendRawTransaction -> insufficient funds`, async () => {
    try {
      await c.sendRawTransaction({ serializedTransaction: raw });
    } catch (e) {
      assert(/insufficient funds/i.test(e.details || e.message), e.shortMessage);
      return e.name;
    }
    throw new Error('accepted an unfunded transaction');
  });
  await check(`${p} getTransactionReceipt(unknown) -> TransactionReceiptNotFoundError`, async () => {
    try {
      await c.getTransactionReceipt({ hash: '0x' + '00'.repeat(32) });
    } catch (e) {
      assert(e.name === 'TransactionReceiptNotFoundError', e.name);
      return e.name;
    }
    throw new Error('found');
  });
}

// ------------------------------------------------------ MetaMask call sequence
// What the extension sends on wallet_addEthereumChain and while preparing a
// transfer (background requests carry the extension origin; extensions with
// host permissions are not subject to CORS).
const mm = [
  ['eth_chainId', []],
  ['net_version', []],
  ['eth_blockNumber', []],
  ['eth_getBlockByNumber', ['latest', false]],
  ['eth_getBalance', [sender, 'latest']],
  ['eth_getTransactionCount', [sender, 'pending']],
  ['eth_gasPrice', []],
  ['eth_maxPriorityFeePerGas', []],
  ['eth_feeHistory', ['0x5', 'latest', [10, 20, 30]]],
  ['eth_getCode', [BEEF, 'latest']],
  ['eth_estimateGas', [{ from: DEAD, to: BEEF, value: '0x0' }]],
  ['eth_call', [{ to: BEEF, data: '0x70a08231' + '0'.repeat(24) + DEAD.slice(2).toLowerCase() }, 'latest']],
  ['eth_getTransactionReceipt', ['0x' + '00'.repeat(32)]],
  ['eth_getTransactionByHash', ['0x' + '00'.repeat(32)]],
  ['web3_clientVersion', []],
];
for (const [method, params] of mm) {
  await check(`metamask ${method}`, async () => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    const j = await res.json();
    assert(res.status === 200 && !j.error, JSON.stringify(j.error));
    return typeof j.result === 'string' ? j.result.slice(0, 20) : j.result === null ? null : typeof j.result;
  });
}
await check('metamask EIP-1559 detection: latest block has baseFeePerGas', async () => {
  const b = await provider.send('eth_getBlockByNumber', ['latest', false]);
  assert(typeof b.baseFeePerGas === 'string', 'no baseFeePerGas');
  return b.baseFeePerGas;
});
await check('browser dapp on an official origin: preflight + POST carry CORS', async () => {
  const pre = await fetch(url, { method: 'OPTIONS', headers: { origin: 'https://blochdex.com', 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type' } });
  const post = await fetch(url, { method: 'POST', headers: { origin: 'https://blochdex.com', 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' });
  assert(pre.status === 204 && pre.headers.get('access-control-allow-origin') === 'https://blochdex.com', 'preflight');
  assert(post.headers.get('access-control-allow-origin') === 'https://blochdex.com', 'post');
});

console.log(`\n${passed}/${passed + failed} passed`);
process.exit(failed ? 1 : 0);
