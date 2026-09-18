// SPDX-License-Identifier: MIT OR Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {HDNodeWallet,JsonRpcProvider,Transaction,toBeHex,zeroPadValue} from 'ethers';
import {startNode,serveDapp} from './services.mjs';
import {PHRASE,onboard,approve} from './metamask.mjs';

test('real MetaMask EIP-1193 UI connects, rejects, signs deploy/call on isolated Bloch', {timeout:240000},async()=>{
 const root=await mkdtemp(join(tmpdir(),'bloch-metamask-'));
 let context,node,web,provider;
 try {
  await promisify(execFile)('python3',[fileURLToPath(new URL('./prepare-metamask.py',import.meta.url)),'--offline']);
  if(!process.env.CHROME)await promisify(execFile)('python3',[fileURLToPath(new URL('./prepare-chrome.py',import.meta.url)),'--offline']);
  const archive=await readFile(new URL('./.cache/metamask-chrome-13.48.0.zip',import.meta.url));
  assert.equal(createHash('sha256').update(archive).digest('hex'),'d95e4c23001ed7485ccdc86c879b4e944806ababdf52e0fc578e277131e48cea');
  const account=HDNodeWallet.fromPhrase(PHRASE).address;
  node=await startNode(join(root,'node'),account);provider=new JsonRpcProvider(node.url);
  const genesis=(await provider.getBlock(0)).hash;
  web=await serveDapp(node.url,genesis);
  context=await chromium.launchPersistentContext(join(root,'profile'),{
   executablePath:process.env.CHROME??fileURLToPath(new URL('./.cache/chrome-153.0.8010.47/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',import.meta.url)),
   headless:true,locale:'en-US',ignoreDefaultArgs:['--disable-extensions'],
   args:['--enable-unsafe-extension-debugging','--disable-sync','--disable-background-networking'],
  });
  console.log('Chrome',context.browser().version());
  if(process.env.BROWSER_TRACE==='1')context.on('page',p=>{console.log('New browser page:',p.url());p.on('framenavigated',f=>{if(f===p.mainFrame())console.log('Browser page:',f.url());});});
  const cdp=await context.browser().newBrowserCDPSession();
  if(process.env.BROWSER_TRACE==='1'){
  await cdp.send('Target.setDiscoverTargets',{discover:true});
  cdp.on('Target.targetCreated',({targetInfo})=>console.log('Chrome target created:',targetInfo.type,targetInfo.url));
  cdp.on('Target.targetInfoChanged',({targetInfo})=>console.log('Chrome target changed:',targetInfo.type,targetInfo.url));
  }
  const {id}=await cdp.send('Extensions.loadUnpacked',{path:fileURLToPath(new URL('./.cache/metamask-13.48.0',import.meta.url))});
  await onboard(context,id);
  const page=await context.newPage();await page.goto(web.url);
  await page.getByRole('button',{name:'Connect MetaMask',exact:true}).click();
  const session=await approve(context,page,'connect',id);assert.equal(session.ok,true,JSON.stringify(session));
  assert.equal(session.value.accounts[0].toLowerCase(),account.toLowerCase());
  assert.equal(session.value.chainId,'0xab163');
  await page.evaluate(to=>{void window.send({to,value:'0x1'});},account);
  const rejected=await approve(context,page,'reject',id);
  if(rejected.ok){const tx=await provider.getTransaction(rejected.value);console.log('Unexpected submitted transaction',tx&&{hash:tx.hash,from:Transaction.from(tx).from,nonce:tx.nonce,chainId:tx.chainId.toString()});}
  assert.equal(rejected.ok,false);assert.equal(rejected.code,4001);
  assert.equal(await provider.getTransactionCount(account),0);
  const runtime='3615601257600035600055602a60006000a15b60005460005260206000f3';
  const len=(runtime.length/2).toString(16).padStart(2,'0');
  await page.evaluate(data=>{void window.send({data});},`0x60${len}600c60003960${len}6000f3${runtime}`);
  const deployment=await approve(context,page,'deploy',id);assert.equal(deployment.ok,true,JSON.stringify(deployment));
  const receipt=await provider.waitForTransaction(deployment.value,1,30000);assert.equal(receipt.status,1);
  assert.equal(Transaction.from(await provider.getTransaction(deployment.value)).from.toLowerCase(),account.toLowerCase());
  const contract=receipt.contractAddress;assert.equal(await provider.getCode(contract),`0x${runtime}`);
  await page.evaluate(({to,data})=>{void window.send({to,data});},{to:contract,data:zeroPadValue(toBeHex(42),32)});
  const call=await approve(context,page,'confirm',id);assert.equal(call.ok,true,JSON.stringify(call));
  const called=await provider.waitForTransaction(call.value,1,30000);assert.equal(called.status,1);
  assert.equal(Transaction.from(await provider.getTransaction(call.value)).from.toLowerCase(),account.toLowerCase());
  assert.equal(called.logs[0].topics[0],zeroPadValue(toBeHex(42),32));
  assert.equal(await provider.getStorage(contract,0),zeroPadValue(toBeHex(42),32));
  assert.equal(await provider.call({to:contract}),zeroPadValue(toBeHex(42),32));
  assert.equal(await provider.getTransactionCount(account),2);
  const rpcUrl=node.url;
  await node.close(); node=undefined; provider.destroy();
  node=await startNode(join(root,'node'),undefined,Number(new URL(rpcUrl).port));
  assert.equal(node.url,rpcUrl); provider=new JsonRpcProvider(node.url);
  assert.equal(await provider.getTransactionCount(account),2);
  assert.equal(await provider.getCode(contract),`0x${runtime}`);
  assert.equal(await provider.getStorage(contract,0),zeroPadValue(toBeHex(42),32));
  assert.equal((await provider.getTransactionReceipt(call.value)).blockHash,called.blockHash);
  const walletRead=await page.evaluate(async to=>window.realProvider.request({method:'eth_call',params:[{to},'latest']}),contract);
  assert.equal(walletRead,zeroPadValue(toBeHex(42),32));
 }finally{
  provider?.destroy();
  try{await context?.close();}finally{try{await web?.close();}finally{try{await node?.close();}finally{await rm(root,{recursive:true,force:true});}}}
 }
});
