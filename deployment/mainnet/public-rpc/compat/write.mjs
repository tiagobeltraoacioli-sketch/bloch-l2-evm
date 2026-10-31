// SPDX-License-Identifier: MIT OR Apache-2.0
// Write-path checks (ethers v6, viem) against a gateway in front of a PRIVATE
// L2 copy whose blocks are produced from the sequencer spool.
//
//   KEY=<throwaway funded key> node write.mjs URL
import { JsonRpcProvider, Wallet, ContractFactory } from 'ethers';
import { createPublicClient, createWalletClient, defineChain, http, parseAbi } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const url = process.argv[2];
const key = process.env.KEY;
const BEEF = '0x000000000000000000000000000000000000bEEF';
// Counter: number() / increment(); solc 0.8.28 runtime via a minimal initcode.
const COUNTER_ABI = ['function number() view returns (uint256)', 'function increment()'];
const COUNTER_BIN = process.env.COUNTER_BIN;
let passed = 0;
let failed = 0;
async function check(name, fn) {
  try {
    const d = await fn();
    passed++;
    console.log(`PASS ${name}${d === undefined ? '' : ' ' + JSON.stringify(d, (k, v) => (typeof v === 'bigint' ? v.toString() : v))}`);
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}: ${(e && (e.shortMessage || e.message)) || e}`.slice(0, 400));
  }
}
const assert = (c, m) => { if (!c) throw new Error(m); };

// cacheTimeout -1: ethers v6 otherwise reuses an identical eth_getTransactionCount
// answer for 250 ms, so two sends in a row get the same nonce (on any chain).
const provider = new JsonRpcProvider(url, undefined, { polling: true, pollingInterval: 1000, cacheTimeout: -1 });
const wallet = new Wallet(key, provider);
await check('ethers balance of the funded throwaway (fresh read through the gateway)', async () => {
  const b = await provider.getBalance(wallet.address);
  assert(b > 0n, 'unfunded');
  return b;
});
await check('ethers sendTransaction (EIP-1559) + wait for receipt', async () => {
  const tx = await wallet.sendTransaction({ to: BEEF, value: 12345n });
  const r = await tx.wait(1, 60000);
  assert(r.status === 1, 'status');
  return { block: r.blockNumber, gasUsed: r.gasUsed };
});
await check('ethers second tx right after (pending nonce from the sequencer spool)', async () => {
  const t1 = await wallet.sendTransaction({ to: BEEF, value: 1n });
  const t2 = await wallet.sendTransaction({ to: BEEF, value: 2n });
  assert(t2.nonce === t1.nonce + 1, `nonces ${t1.nonce} ${t2.nonce}`);
  const [r1, r2] = await Promise.all([t1.wait(1, 60000), t2.wait(1, 60000)]);
  return [r1.status, r2.status];
});
if (COUNTER_BIN) {
  await check('ethers ContractFactory.deploy + call + send', async () => {
    const c = await new ContractFactory(COUNTER_ABI, COUNTER_BIN, wallet).deploy();
    await c.waitForDeployment();
    const tx = await c.increment();
    await tx.wait(1, 60000);
    const n = await c.number();
    assert(n === 1n, `number ${n}`);
    return { address: await c.getAddress(), number: n };
  });
}
await check('ethers getLogs/getBlockReceipts on the new blocks', async () => {
  const head = await provider.getBlockNumber();
  const receipts = await provider.send('eth_getBlockReceipts', ['0x' + head.toString(16)]);
  return { head, receipts: receipts.length };
});

const chain = defineChain({ id: 700770, name: 'Bloch L2', nativeCurrency: { name: 'Bloch', symbol: 'BLOCH', decimals: 18 }, rpcUrls: { default: { http: [url] } } });
const account = privateKeyToAccount(key);
const pub = createPublicClient({ chain, transport: http(url), pollingInterval: 1000 });
const wal = createWalletClient({ chain, transport: http(url), account });
await check('viem sendTransaction + waitForTransactionReceipt', async () => {
  const hash = await wal.sendTransaction({ to: BEEF, value: 7n });
  const r = await pub.waitForTransactionReceipt({ hash, timeout: 60000 });
  assert(r.status === 'success', r.status);
  return { block: r.blockNumber };
});
await check('viem legacy (type 0, EIP-155) transaction', async () => {
  const hash = await wal.sendTransaction({ to: BEEF, value: 8n, type: 'legacy' });
  const r = await pub.waitForTransactionReceipt({ hash, timeout: 60000 });
  assert(r.status === 'success', r.status);
  return r.type;
});
await check('viem getTransaction/getTransactionReceipt/getBlock(includeTransactions)', async () => {
  const b = await pub.getBlock({ blockTag: 'latest', includeTransactions: true });
  assert(b.transactions.length >= 1, 'no txs');
  const t = await pub.getTransaction({ hash: b.transactions[0].hash });
  return { block: b.number, txType: t.type };
});
console.log(`\n${passed}/${passed + failed} passed`);
process.exit(failed ? 1 : 0);
