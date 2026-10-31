// Parent browser gate. Requires web + extension production builds. Runs real
// shipped WASM, restore/save/unlock, all 13 receive variants and decoded QR.
// No outside traffic: HTTP proxy denies external origins before worker start.
// Public fixture phrase only. Temporary browser profiles are removed; screenshots
// can be supplied via PQ_RECEIVE_SCREENSHOT_DIR. Missing artifacts fail, no skips.
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { chromium } from 'playwright';
import { pastePhrase } from './browser-phrase.js';
const jsQR=createRequire(import.meta.url)('jsqr');
const app=fileURLToPath(new URL('..',import.meta.url)),web=join(app,'dist'),extension=join(app,'dist-extension/unpacked');
const fixture=JSON.parse(await readFile(new URL('./fixtures/pq-receive.json',import.meta.url),'utf8')).vectors[0];
const password='Pq9!Velvet-Cedar-Moon$47',outside=[],errors=[];
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
server.on('connect',(req,socket)=>{outside.push(req.url);socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');});
await new Promise(done=>server.listen(0,'127.0.0.1',done));
const origin=`http://127.0.0.1:${server.address().port}`;
const temporary=await mkdtemp(join(tmpdir(),'pq-receive-browser-'));
let context;
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
async function openReceive(page){if(!(await page.locator('#chain').isVisible()))await page.locator('#quick-receive').click();}
async function address(page,chain,network,expected,{decode=true}={}){
  await openReceive(page);
  await page.selectOption('#chain',chain);
  await page.selectOption('#pq-network-environment',network);
  try { await page.waitForFunction(expected=>document.querySelector('#receive-address')?.textContent===expected,expected); } catch(error) { console.error('ADDRESS DIAGNOSTIC',{chain,network,expected},await page.evaluate(()=>({chain:document.querySelector('#chain')?.value,address:document.querySelector('#receive-address')?.textContent,network:document.querySelector('#pq-network-environment')?.value,status:document.querySelector('#pq-address-status')?.textContent,wallet:document.querySelector('#wallet-status')?.textContent})));throw error; }
  assert.equal(await page.locator('#pq-network-environment').inputValue(),network);
  assert.equal(await page.locator('#quick-send').isDisabled(),true);
  assert.equal(await page.locator('#send-fields').isVisible(),false);
  assert.equal(await page.locator('#copy-address').isDisabled(),false);
  assert.match(await page.locator('#send-disabled-note').textContent(),/Sending and balances are not available/);
  assert.match(await page.locator('#pq-address-status').textContent(),new RegExp(network==='testnet'?'Testnet':'Mainnet'));
  if(decode)assert.equal(await qr(page),expected);
  await page.locator('#send-form').evaluate(form=>form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
  assert.equal(await page.locator('#review-dialog').evaluate(d=>d.open),false);
}
async function settings(page){await home(page);await page.locator('.wallet-navigation a[href="#settings"]').click();await page.locator('#page-settings').waitFor({state:'visible'});}
async function lockPage(page){if(!(await page.locator('#lock').isVisible()))await home(page);await page.locator('#lock').click();}
async function home(page){const back=page.locator('.wallet-page:not([hidden]) .page-back');if(await back.count())await back.click();}
try {
  for(const mode of process.env.PQ_RECEIVE_BROWSER_MODE ? [process.env.PQ_RECEIVE_BROWSER_MODE] : ['web','extension']){
    console.log(`Start ${mode} actual receive flow`);
    context=await chromium.launchPersistentContext(join(temporary,mode),{
      executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',channel:'chromium',headless:true,
      viewport:{width:1360,height:1000},ignoreDefaultArgs:mode==='extension'?['--disable-extensions']:[],
      args:[`--proxy-server=${origin}`,'--proxy-bypass-list=127.0.0.1','--disable-background-networking',...(mode==='extension'?[`--load-extension=${extension}`,`--disable-extensions-except=${extension}`]:[])],
    });
    context.setDefaultTimeout(15000);
    await context.route('**/*',route=>{
      const url=new URL(route.request().url());
      if(url.origin===origin||url.protocol==='chrome-extension:')return route.continue();
      outside.push(url.href);return route.abort('blockedbyclient');
    });
    const page=await context.newPage();page.on('pageerror',e=>errors.push(`${mode}: ${e.message}`));
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
    catch(error) { if(process.env.PQ_RECEIVE_DIAGNOSTIC) await page.waitForFunction(()=>document.querySelector('#wallet-status')?.textContent,{},{timeout:25000}).catch(()=>{}); console.error('RESTORE DIAGNOSTIC',await page.evaluate(()=>({status:document.querySelector('#wallet-status')?.textContent,phraseError:document.querySelector('#phrase-error')?.textContent,invalid:[...document.querySelectorAll(':invalid')].map(n=>({id:n.id,message:n.validationMessage})),body:document.body.innerText})),errors); throw error; }
    for(const [chain,networks] of Object.entries(fixture.addresses))for(const [network,expected]of Object.entries(networks))await address(page,chain,network,expected);
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
    await openReceive(page);await page.selectOption('#chain','ckb');assert.equal(await page.locator('#pq-network-environment').inputValue(),'testnet');
    await address(page,'ckb','testnet',fixture.addresses.ckb.testnet);
    await address(page,'qtc','mainnet',fixture.addresses.qtc.mainnet);
    await address(page,'qtc','testnet',fixture.addresses.qtc.testnet);
    await lockPage(page);await page.reload();await page.locator('#unlock-password:visible').fill(password);await page.locator('#unlock-wallet').click();
    await page.locator('#wallet-open').waitFor({state:'visible'});
    await address(page,'asentum','testnet',fixture.addresses.asentum.testnet);
    assert.equal(await page.locator('#pq-network-environment option').count(),1);
    assert.deepEqual(errors,[]);
    await lockPage(page);await context.close();context=null;
    console.log(`PASS ${mode}: 13 receive variants, decoded QR, send refusal, encrypted recovery, network persistence, reload`);
  }
  assert.ok(outside.every(url=>!url.includes(fixture.phrase)),'no recovery phrase in request URL');
  console.log('PASS offline browser gates; external transport blocked; no on-chain transaction claim');
}finally{
  await context?.close();await new Promise(done=>server.close(done));await rm(temporary,{recursive:true,force:true});
}
