import {chromium} from 'playwright';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
const p=await mkdtemp(join(tmpdir(),'bloch-mm-'));
const c=await chromium.launchPersistentContext(p,{executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,locale:"en-US",ignoreDefaultArgs:['--disable-extensions'],args:['--enable-unsafe-extension-debugging','--disable-sync','--disable-background-networking']});
try {
 const d=await c.browser().newBrowserCDPSession();
 const {id}=await d.send('Extensions.loadUnpacked',{path:resolve('wallets/browser/.cache/metamask-13.48.0')});
 console.log('EXT',id);
 const page=await c.newPage(); page.setDefaultTimeout(15000);await page.goto(`chrome-extension://${id}/home.html`);
 await page.waitForSelector('button',{timeout:60000});
 await page.locator('select').selectOption({label:'English'});
 const imp=page.getByRole('button',{name:"I have an existing wallet",exact:true}); await imp.click(); await imp.waitFor({state:'hidden'});
 await page.getByRole('button',{name:'Import using Secret Recovery Phrase',exact:true}).click();
 await page.getByRole('button',{name:'Import using Secret Recovery Phrase',exact:true}).waitFor({state:'hidden'});
 console.log('AFTER SRP',await page.locator('body').innerText());
 for(const input of await page.locator('input').all()) console.log('INPUT',await input.getAttribute('type'),await input.getAttribute('data-testid'),await input.getAttribute('placeholder'));

} finally {await c.close();await rm(p,{recursive:true,force:true});}
