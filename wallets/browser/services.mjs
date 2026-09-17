// SPDX-License-Identifier: MIT OR Apache-2.0
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';

export async function startNode(directory, account, port = 0) {
  const binary=process.env.BLOCH_DEVNODE_BIN??fileURLToPath(new URL('../../integrations/reth-execution/target/debug/bloch-evm-dev',import.meta.url));
  const args=['--synthetic-dev','--data-dir',directory,'--port',String(port),'--block-interval-ms','200'];
  if(account !== undefined) args.push('--init','--fund',account);
  const child=spawn(binary,args,{stdio:['ignore','pipe','pipe']});
  let stderr='';child.stderr.on('data',x=>stderr=(stderr+x).slice(-16000));
  const exited=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>resolve({code,signal}));});exited.catch(()=>{});
  const lines=createInterface({input:child.stdout});let timeout;
  try {
    const url=await new Promise((resolve,reject)=>{
      timeout=setTimeout(()=>reject(Error(`node startup timeout ${stderr}`)),30000);
      lines.on('line',line=>{if(line.startsWith('RPC listening at '))resolve(line.slice(17));});
      exited.then(x=>reject(Error(`node startup exit ${JSON.stringify(x)} ${stderr}`)),reject);
    });
    return {url,async close(){
      if(child.exitCode===null&&child.signalCode===null)child.kill('SIGINT');
      const deadline=setTimeout(()=>child.kill('SIGKILL'),20000);
      try {const result=await exited;assert.equal(result.code,0,`node shutdown ${JSON.stringify(result)} ${stderr}`);}
      finally{clearTimeout(deadline);lines.close();}
    }};
  }catch(e){child.kill('SIGKILL');await exited.catch(()=>{});throw e;}finally{clearTimeout(timeout);}
}

export async function serveDapp(rpcUrl){
  const html=await readFile(new URL('./dapp.html',import.meta.url),'utf8');
  const adapter=await readFile(new URL('../bloch-l2.mjs',import.meta.url));
  const server=createServer((req,res)=>{
    if(req.url==='/bloch-l2.mjs'){res.setHeader('Content-Type','text/javascript');res.end(adapter);}
    else if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end(html.replace('RPC_ENDPOINT_JSON',JSON.stringify(rpcUrl)));}
    else{res.writeHead(404);res.end();}
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  return {url:`http://127.0.0.1:${server.address().port}`,close:()=>new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()))};
}
