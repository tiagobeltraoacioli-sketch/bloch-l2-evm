// SPDX-License-Identifier: MIT OR Apache-2.0
import {attachPanel} from './sidepanel.mjs';
export const PHRASE = 'air antenna begin firm concert unusual speak height knife plastic cigar essay';
export async function onboard(context, extensionId) {
 const page=await context.newPage();page.setDefaultTimeout(30000);
 await page.goto(`chrome-extension://${extensionId}/home.html`);
 await page.waitForSelector('button',{timeout:60000});
 await page.locator('select').selectOption({label:'English'}).catch(async error=>{throw Error(`${error.message}; initial UI=${await page.locator('body').innerText()}`);});
 const imp=page.getByRole('button',{name:"I have an existing wallet",exact:true}); await imp.click(); await imp.waitFor({state:'hidden'});
 await page.getByRole('button',{name:'Import using Secret Recovery Phrase',exact:true}).click();
 await page.getByRole('button',{name:'Import using Secret Recovery Phrase',exact:true}).waitFor({state:'hidden'});
 await page.getByTestId('srp-input-import__srp-note').focus();
 await page.keyboard.type(PHRASE);
 await page.keyboard.press('Tab');
 await page.getByTestId('import-srp-confirm').click();
 await page.getByTestId('import-srp-confirm').waitFor({state:'hidden'});
 await page.getByTestId('create-password-new-input').fill('Synthetic-public-fixture-only!');
 await page.getByTestId('create-password-confirm-input').fill('Synthetic-public-fixture-only!');
 await page.getByRole('checkbox').check();
 await page.getByRole('button',{name:'Create password',exact:true}).click();
 await page.getByRole('button',{name:'Create password',exact:true}).waitFor({state:'hidden',timeout:60000});
 await page.getByRole('button',{name:'Maybe later',exact:true}).click({timeout:60000});
 await page.getByRole('button',{name:'Maybe later',exact:true}).waitFor({state:'hidden'});
 await page.getByRole('button',{name:'Continue',exact:true}).waitFor({timeout:30000});
 for (const toggle of await page.getByRole('switch').all()) if (await toggle.getAttribute('aria-checked')==='true') await toggle.click();
 for (const checkbox of await page.getByRole('checkbox').all()) await checkbox.uncheck();
 await page.getByRole('button',{name:'Continue',exact:true}).click();
 await page.getByRole('button',{name:'Continue',exact:true}).waitFor({state:'hidden'});

 await page.getByRole('button',{name:'Open wallet',exact:true}).click();
 const deadline=Date.now()+30000;
 while(!context.pages().some(p=>p.url()===`chrome-extension://${extensionId}/home.html#/`)){
  if(Date.now()>deadline)throw Error('MetaMask wallet home did not open after onboarding');
  await new Promise(resolve=>setTimeout(resolve,100));
 }
 for(const existing of context.pages())if(existing.url().startsWith(`chrome-extension://${extensionId}/`))await existing.close();
 const settings=await context.newPage();
 await settings.goto(`chrome-extension://${extensionId}/sidepanel.html`);
 await settings.waitForSelector('button');

 await settings.getByTestId('account-options-menu-button').click().catch(async error=>{throw Error(`${error.message}; display UI=${await settings.locator('body').innerText()}`);});
 if(process.env.BROWSER_TRACE==='1')console.log('MetaMask display menu:',await settings.locator('body').innerText());
 await Promise.all([settings.waitForEvent('close',{timeout:10000}),settings.getByText('Switch to popup',{exact:true}).click()]);
 for(const existing of context.pages())if(existing.url().startsWith(`chrome-extension://${extensionId}/`))await existing.close();
 return page;
}

const completedApprovals=new WeakMap();
export async function approve(context,dapp,mode,extensionId){
 const completed=completedApprovals.get(context)??new Set();completedApprovals.set(context,completed);
 const observedUrls=new Set();
 const expectedSequence=await dapp.evaluate(()=>window.requestSequence);
 const cdp=await context.browser().newBrowserCDPSession();const panels=new Map();const urls=new Set();
 const deadline=Date.now()+60000; let previous=''; const clicked=new Set();
 try {
  while(Date.now()<deadline){
   const result=await dapp.evaluate(()=>window.result);
   if(result!==null&&result.sequence===expectedSequence){console.log(`MetaMask ${mode} result`,result);if(clicked.size===0)throw Error(`MetaMask ${mode} completed without an observed UI action`);for(const url of observedUrls)completed.add(url);return result;}
   const pages=context.pages().filter(page=>page.url().startsWith(`chrome-extension://${extensionId}/notification.html`)&&!completed.has(page.url()));
   for(const page of pages){
    if(page.isClosed())continue;
    const text=await page.locator('body').innerText();
    if(text!==previous){if(process.env.BROWSER_TRACE==='1')console.log(`MetaMask ${mode} ${page.url()}: ${text.slice(0,1800)}`);previous=text;}
    const names=mode==='connect'?['Add network','Approve','Switch network','Connect','Next','Confirm']:
      mode==='reject'?['Reject','Cancel']:['Confirm'];
    if(mode!=='deploy'||/deploy/i.test(text))for(const name of names){
     const key=page.url()+' '+name;
     const button=page.getByRole('button',{name,exact:true});
     if(!clicked.has(key)&&await button.count()===1&&await button.isVisible()&&await button.isEnabled()){
      await button.click();clicked.add(key);observedUrls.add(page.url());console.log('UI click:',mode,key);await dapp.bringToFront();break;
     }
    }
   }
   const {targetInfos}=await cdp.send('Target.getTargets');
   for(const target of targetInfos.filter(t=>t.url.startsWith(`chrome-extension://${extensionId}/`)&&!completed.has(t.url)&&/\/(notification|popup|sidepanel)\.html#\/(connect|confirm)/.test(t.url))){
    if(pages.some(page=>page.url()===target.url))continue;
    if(!urls.has(target.url)){console.log('Untracked approval UI:',target.type,target.url);urls.add(target.url);}
    if(!panels.has(target.targetId))panels.set(target.targetId,await attachPanel(cdp,target.targetId));
    const panel=panels.get(target.targetId);const text=await panel.text();
    if(text!==previous){if(process.env.BROWSER_TRACE==='1')console.log(`MetaMask ${mode} ${target.url}: ${text.slice(0,1800)}`);previous=text;}
    const names=mode==='connect'?['Add network','Approve','Switch network','Connect','Next','Confirm']:mode==='reject'?['Reject','Cancel']:['Confirm'];
    if(mode!=='deploy'||/deploy/i.test(text))for(const name of names){
     const key=target.url+' '+name;
     if(!clicked.has(key)&&await panel.click(name)){clicked.add(key);observedUrls.add(target.url);console.log('UI click:',mode,key);await dapp.bringToFront();break;}
    }
   }
   await new Promise(resolve=>setTimeout(resolve,100));
  }
  throw Error(`MetaMask ${mode} approval did not complete; last visible UI: ${previous}`);
 }catch(error){console.log('EIP-1193 trace',await dapp.evaluate(()=>window.rpcTrace).catch(()=>null));throw error;}finally{for(const panel of panels.values())await panel.close();await cdp.detach();}
}
