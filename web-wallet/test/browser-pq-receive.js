import { randomBytes } from 'node:crypto';
// Parent browser gate. Requires web + extension production builds. Runs real
// shipped WASM, restore/save/unlock, all 13 receive variants and decoded QR.
// No outside traffic: HTTP proxy denies external origins before worker start.
// Public fixture phrase only. Temporary browser profiles are removed; screenshots
// can be supplied via PQ_RECEIVE_SCREENSHOT_DIR. Missing artifacts fail, no skips.
// Needs dist/ and dist-extension/unpacked, Chromium at CHROMIUM_PATH (default
// /usr/bin/chromium), jsqr; the host listens on 127.0.0.1 port 0. Env:
// PQ_RECEIVE_BROWSER_MODE (web or extension) runs one surface only;
// PQ_RECEIVE_DIAGNOSTIC (any value) waits longer for a restore failure to show.
// Leaves: screenshots in PQ_RECEIVE_SCREENSHOT_DIR when set, including
// <mode>-pq-failure.png after a failure (which is rethrown); nothing else.
// Falsely passes: the outside-traffic check asserts only that no refused URL
// contains the recovery phrase, not that none was attempted; a mode left out by
// PQ_RECEIVE_BROWSER_MODE is not run; a stale build is tested as built.
// UI pack 2026-11-03: the "receive address derived locally" status line is gone (the
// line is empty and not visible; the network is checked on the environment summary);
// the extension's Settings is reached through the bottom bar. Falsely passes if the
// address never appeared (the check follows the wait for the shown address).
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { chromium } from 'playwright';
import { pastePhrase } from './browser-phrase.js';
import { assertNetworkGroups } from './browser-network-groups.js';
import { walletPageSupported, walletPqNetwork } from '../src/pq/wallet-capabilities.js';
import { extensionPageSupported, extensionNetworkConfig } from '../extension/src/constants/capabilities.js';
import { PQ_NETWORKS } from '../src/pq/networks.js';
const jsQR=createRequire(import.meta.url)('jsqr');
const app=fileURLToPath(new URL('..',import.meta.url)),web=join(app,'dist'),extension=join(app,'dist-extension/unpacked');
const fixture=JSON.parse(await readFile(new URL('./fixtures/pq-receive.json',import.meta.url),'utf8')).vectors[0];
const password='Aa9!'+randomBytes(24).toString('hex'),outside=[],errors=[];
const manifest=JSON.parse(await readFile(join(extension,'manifest.json'),'utf8'));
assert.deepEqual(await readFile(join(extension,'wasm/receive-keygen.wasm')),await readFile(join(app,'src/pq/receive-keygen.wasm')));
const server=createServer(async(req,res)=>{
  if(/^https?:\/\//.test(req.url)){outside.push(req.url);res.writeHead(403);res.end();return;}
  const path=resolve(web,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname));
  if(path!==web&&!path.startsWith(web+'/')){res.writeHead(403);res.end();return;}
  try {
    const file=path===web?join(web,'index.html'):path;
    const mime={'.html':'text/html','.js':'application/javascript','.css':'text/css','.wasm':'application/wasm','.svg':'image/svg+xml','.json':'application/json','.png':'image/png'}[extname(file)]||'application/octet-stream';
    res.writeHead(200,{'Content-Type':mime});res.end(await readFile(file));
  }catch{res.writeHead(404);res.end();}
});
server.on('connect',(req,socket)=>{socket.on('error',()=>{});outside.push(req.url);socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');});
await new Promise(done=>server.listen(0,'127.0.0.1',done));
const origin=`http://127.0.0.1:${server.address().port}`;
const temporary=await mkdtemp(join(tmpdir(),'pq-receive-browser-'));
let context, activePage, activeMode;
async function qr(page){
  const pixels=await page.evaluate(async()=>{
    const svg=document.querySelector('#receive-qr svg');if(!svg)return null;
    const size=Number(svg.getAttribute('width'))*4,img=new Image();
    await new Promise((ok,fail)=>{img.onload=ok;img.onerror=fail;img.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(new XMLSerializer().serializeToString(svg));});
    const canvas=document.createElement('canvas');canvas.width=canvas.height=size;
    const c=canvas.getContext('2d');c.imageSmoothingEnabled=false;c.fillStyle='#fff';c.fillRect(0,0,size,size);c.drawImage(img,0,0,size,size);
    return {size,data:Array.from(c.getImageData(0,0,size,size).data)};
  });
  assert.ok(pixels,'QR exists');return jsQR(Uint8ClampedArray.from(pixels.data),pixels.size,pixels.size)?.data;
}
// #chain and #pq-network-environment are hidden; the shipped page chooses both in
// the network disclosure (src/app.js:2307, :970). Send expectations come from the
// surface's capability table (handoff enables some mainnet/testnet sends).
const sendSupported=(chain,network)=>activeMode==='extension'?extensionPageSupported(chain,'send',network):walletPageSupported(chain,'send',network);
async function openDisclosure(page){if(!await page.locator('#wallet-network').evaluate(n=>n.open))await page.locator('#wallet-network > summary').click();}
async function selectChain(page,chain){await openDisclosure(page);const badge=page.locator(`#portfolio-networks .network-health[data-chain="${chain}"]`);const toggle=badge.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " network-group ")]').locator('.network-group-toggle');if(await toggle.count()&&await toggle.getAttribute('aria-expanded')!=='true')await toggle.click();await badge.click();}
async function selectEnvironment(page,network){if(await page.locator('#pq-network-environment').inputValue()===network)return;await openDisclosure(page);if(!await page.locator('#wallet-environment').evaluate(n=>n.open))await page.locator('#wallet-environment > summary').click();await page.locator(`#wallet-environment button[data-environment="${network}"]`).click();}
async function openReceive(page){if(!(await page.locator('#page-receive').isVisible()))await page.locator('.wallet-navigation a[href="#receive"]').click();}
async function address(page,chain,network,expected,{decode=true}={}){
  await openReceive(page);
  await selectChain(page,chain);
  await selectEnvironment(page,network);
  try { await page.waitForFunction(expected=>document.querySelector('#receive-address')?.textContent===expected,expected); } catch(error) { console.error('ADDRESS DIAGNOSTIC',{chain,network,expected},await page.evaluate(()=>({chain:document.querySelector('#chain')?.value,address:document.querySelector('#receive-address')?.textContent,network:document.querySelector('#pq-network-environment')?.value,status:document.querySelector('#pq-address-status')?.textContent,wallet:document.querySelector('#wallet-status')?.textContent})));throw error; }
  assert.equal(await page.locator('#pq-network-environment').inputValue(),network);
  assert.equal(await page.locator('#copy-address').isDisabled(),false);
  // Positive side: where the table enables sending, the rail offers Send.
  assert.equal(await page.locator('.wallet-navigation a[href="#send"]').isVisible(),sendSupported(chain,network),`${activeMode} ${chain} ${network}: Send link follows the capability table`);
  if(!sendSupported(chain,network)){
    assert.equal(await page.locator('#quick-send').isDisabled(),true);
    assert.equal(await page.locator('#send-fields').isVisible(),false);
    // The note is the surface's configured sendNote for this network (web/Connect
    // walletPqNetwork, extension extensionNetworkConfig over src/pq/networks.js).
    const config=PQ_NETWORKS[chain]&&(activeMode==='extension'?extensionNetworkConfig(chain,PQ_NETWORKS[chain],network):walletPqNetwork(chain,PQ_NETWORKS[chain],network));
    assert.ok(config?.sendNote,`${chain} ${network}: a receive-only network has a send note`);
    assert.equal(await page.locator('#send-disabled-note').textContent(),config.sendNote);
  }
  // UI pack 2026-11-03 (operator "2"): the status line "<Network> receive address derived locally." is gone once the address
  // is shown, the empty line takes no space; the network is read from the environment summary ("Environment · <label>").
  assert.equal(await page.locator('#pq-address-status').textContent(),'');
  assert.equal(await page.locator('#pq-address-status').isVisible(),false);
  // The recovery note stays (UI pack 2026-11-03 section 5b), its text as on 14dc02b9f (src/app.js:966, extension wallet-screen.js:148).
  assert.equal(await page.locator('#pq-recovery-note').textContent(),'Recover this address with your Nodus recovery phrase. Native chain wallets may derive different addresses.');
  // It sits in the network environment disclosure (src/app.js:977, extension wallet-screen.js:158), shown with it, not hidden.
  assert.equal(await page.locator('#pq-recovery-note').evaluate(node=>node.hidden),false);
  assert.match(await page.locator('#wallet-environment summary').textContent(),new RegExp(network==='testnet'?'Testnet':'Mainnet'));
  if(decode)assert.equal(await qr(page),expected);
  await page.locator('#send-form').evaluate(form=>form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
  assert.equal(await page.locator('#review-dialog').evaluate(d=>d.open),false);
}
async function settings(page){await home(page);await page.locator(activeMode==='extension'?'#extension-bottom-bar button[aria-label="Settings"]':'.wallet-navigation a[href="#settings"]').click();await page.locator('#page-settings').waitFor({state:'visible'});}
async function lockPage(page){if(!(await page.locator('#lock').isVisible()))await home(page);await page.locator('#lock').click();}
async function home(page){await page.locator('.wallet-navigation a[href="#"]').click();}
try {
  for(const mode of process.env.PQ_RECEIVE_BROWSER_MODE ? [process.env.PQ_RECEIVE_BROWSER_MODE] : ['web','extension']){
    activeMode=mode;console.log(`Start ${mode} actual receive flow`);
    context=await chromium.launchPersistentContext(join(temporary,mode),{
      executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',channel:'chromium',headless:true,
      chromiumSandbox:true,viewport:{width:1360,height:1000},ignoreDefaultArgs:mode==='extension'?['--disable-extensions']:[],
      args:[`--proxy-server=${origin}`,'--proxy-bypass-list=127.0.0.1','--disable-background-networking',...(mode==='extension'?[`--load-extension=${extension}`,`--disable-extensions-except=${extension}`]:[])],
    });
    context.setDefaultTimeout(15000);
    await context.route('**/*',route=>{
      const url=new URL(route.request().url());
      if(url.origin===origin||url.protocol==='chrome-extension:')return route.continue();
      outside.push(url.href);return route.abort('blockedbyclient');
    });
    const page=activePage=await context.newPage();page.on('pageerror',e=>errors.push(`${mode}: ${e.message}`));
    await page.routeWebSocket(()=>true,ws=>ws.close());
    let url=origin;
    if(mode==='extension'){
      const worker=context.serviceWorkers().find(w=>w.url().startsWith('chrome-extension:'))||await context.waitForEvent('serviceworker');
      url=`chrome-extension://${new URL(worker.url()).hostname}/home.html`;
    }
    await page.goto(url);await page.locator('#restore:visible').click();await pastePhrase(page,fixture.phrase);
    await page.locator('#backup-confirm').check();
    if(mode==='extension'){await page.locator('#new-password').fill(password);await page.locator('#confirm-password').fill(password);}
    await page.locator('#phrase-submit').click();
    try { await page.locator('#wallet-open').waitFor({state:'visible'}); }
    catch(error) { if(process.env.PQ_RECEIVE_DIAGNOSTIC) await page.waitForFunction(()=>document.querySelector('#wallet-status')?.textContent,{},{timeout:25000}).catch(()=>{}); console.error('RESTORE DIAGNOSTIC',await page.evaluate(()=>({status:document.querySelector('#wallet-status')?.textContent,phraseError:document.querySelector('#phrase-error')?.textContent,invalid:[...document.querySelectorAll(':invalid')].map(n=>({id:n.id,message:n.validationMessage}))})),errors); throw error; }
    await page.waitForFunction(()=>!document.querySelector('.network-heading-select')?.closest('[inert]'));
    await assertNetworkGroups(page,{addressBookIxios:mode==='extension'});
    // A balance redraw keeps keyboard focus on the same grouped badge and
    // does not scroll or change the selected transfer network.
    assert.equal(await page.locator('#wallet-home').isVisible(),true);
    // 0.1.151: unavailable balances are hidden by default; list every network to reach Tidecoin's heading.
    await page.locator('#show-zero-balances').uncheck();
    await page.evaluate(()=>scrollTo(0,0));
    await page.waitForFunction(()=>!document.querySelector('#portfolio-refresh').disabled);
    const focusRedraw=await page.evaluate(()=>{
      document.querySelector('.network-assets[data-chain="tidecoin"] .network-heading-select').focus({preventScroll:true});
      const initialFocus=document.activeElement?.closest('[data-chain]')?.dataset.chain;
      const before={x:scrollX,y:scrollY,chain:document.querySelector('#chain').value};
      document.querySelector('#portfolio-hide').click();document.querySelector('#portfolio-hide').click();
      return {initialFocus,before,after:{x:scrollX,y:scrollY,chain:document.querySelector('#chain').value},focused:document.activeElement?.closest('[data-chain]')?.dataset.chain};
    });
    assert.equal(focusRedraw.initialFocus,'tidecoin');assert.deepEqual(focusRedraw.after,focusRedraw.before);assert.equal(focusRedraw.focused,'tidecoin');
    // Crossing group boundaries retains the legacy receive address and returns
    // to the exact PQ fixture; selecting a heading cannot become a chain value.
    await openReceive(page);await selectChain(page,'ethereum');
    const legacyAddress=await page.locator('#receive-address').textContent();
    assert.match(legacyAddress,/^0x[0-9a-fA-F]{40}$/);
    for(const [chain,networks] of Object.entries(fixture.addresses))for(const [network,expected]of Object.entries(networks))await address(page,chain,network,expected);
    await selectChain(page,'ethereum');assert.equal(await page.locator('#receive-address').textContent(),legacyAddress);
    await settings(page);
    if(mode==='web'){
      await page.locator('#vault-storage-title').click();
      await page.locator('#vault-password').fill(password);await page.locator('#vault-confirm-password').fill(password);
      await page.locator('#vault-risk-confirm').check();await page.locator('#vault-save').click();
      await page.waitForFunction(()=>document.querySelector('#vault-save-status').textContent.includes('Encrypted wallet saved'));
    }
    await home(page);await address(page,'ckb','testnet',fixture.addresses.ckb.testnet);
    if(process.env.PQ_RECEIVE_SCREENSHOT_DIR){await mkdir(process.env.PQ_RECEIVE_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:join(process.env.PQ_RECEIVE_SCREENSHOT_DIR,`${mode}-ckb-receive.png`),fullPage:true});}
    await lockPage(page);
    if(mode==='web'){
      assert.equal(await page.locator('#receive-address').textContent(),'');
      assert.equal(await page.locator('#receive-qr').evaluate(n=>n.childElementCount),0);
    }
    await page.locator('#unlock-password:visible').fill(password);await page.locator('#unlock-wallet').click();
    await page.locator('#wallet-open').waitFor({state:'visible'});
    // Operator 2026-11-03 ("hersey varsa yeniden acista mainnet"): after reopening, a network
    // that has a mainnet opens on mainnet, whatever was chosen before.
    await openReceive(page);await selectChain(page,'ckb');assert.equal(await page.locator('#pq-network-environment').inputValue(),'mainnet');
    await address(page,'ckb','testnet',fixture.addresses.ckb.testnet);
    await address(page,'qtc','mainnet',fixture.addresses.qtc.mainnet);
    await address(page,'qtc','testnet',fixture.addresses.qtc.testnet);
    await lockPage(page);await page.reload();await page.locator('#unlock-password:visible').fill(password);await page.locator('#unlock-wallet').click();
    await page.locator('#wallet-open').waitFor({state:'visible'});
    await address(page,'asentum','testnet',fixture.addresses.asentum.testnet);
    // #chain is hidden (keyboard users choose in the network disclosure); cross the
    // PQ/legacy group boundary through its chips instead.
    await selectChain(page,'ethereum');
    assert.equal(await page.locator('#chain').inputValue(),'ethereum');
    assert.equal(await page.locator('#receive-address').textContent(),legacyAddress);
    await selectChain(page,'asentum');
    assert.equal(await page.locator('#chain').inputValue(),'asentum');
    await page.waitForFunction(expected=>document.querySelector('#receive-address')?.textContent===expected,fixture.addresses.asentum.testnet);
    await page.waitForFunction(()=>!document.querySelector('.network-heading-select')?.closest('[inert]'));
    // The helper expects the network disclosure closed, as the page leaves it after a choice is made elsewhere.
    if(await page.locator('#wallet-network').evaluate(n=>n.open))await page.locator('#wallet-network > summary').click();
    await assertNetworkGroups(page,{addressBookIxios:mode==='extension'});
    assert.equal(await page.locator('#pq-network-environment option').count(),1);
    assert.deepEqual(errors,[]);
    await lockPage(page);await context.close();context=null;
    console.log(`PASS ${mode}: 13 receive variants, decoded QR, send refusal, encrypted recovery, network persistence, reload`);
  }
  assert.ok(outside.every(url=>!url.includes(fixture.phrase)),'no recovery phrase in request URL');
  console.log('PASS offline browser gates; external transport blocked; no on-chain transaction claim');
}catch(error){
  console.error('SAFE FAILURE DIAGNOSTIC',activeMode,await activePage?.evaluate(()=>({vault:document.querySelector('#vault-status')?.textContent,wallet:document.querySelector('#wallet-status')?.textContent,boot:document.querySelector('#wallet-boot-status')?.textContent})).catch(()=>null));
  if(process.env.PQ_RECEIVE_SCREENSHOT_DIR&&activePage)await activePage.screenshot({path:join(process.env.PQ_RECEIVE_SCREENSHOT_DIR,`${activeMode}-pq-failure.png`),fullPage:true}).catch(()=>{});
  throw error;
}finally{
  await context?.close();await new Promise(done=>server.close(done));await rm(temporary,{recursive:true,force:true});
}
