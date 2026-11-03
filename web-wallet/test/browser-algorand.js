import { randomBytes } from 'node:crypto';
// Built shared web UI with real public recovery fixture, isolated profile,
// loopback static host and mocked providers. No external traffic is allowed.
// Proves: Algorand balance/history reads, failure states, same-address
// environment switches cancelling stale reads, send refusal for an unsaved
// wallet, and lock clearing. Needs dist/ built and a Chromium (CHROMIUM_PATH,
// default /usr/bin/google-chrome). The static host listens on 127.0.0.1 port 0.
// ALGORAND_SCREENSHOT_DIR (default algorand-ui-evidence under the system temp
// directory) receives algorand-receive.png and is left in place; the temporary
// browser profile and the host are removed in finally.
// It tests the built dist/, not src/: a stale build is tested as built.
// Hide zero balances hides a row whose balance is unavailable (src/portfolio.js
// groupNetworks), and every return to the home page re-checks the box
// (src/app.js resetAssetView), so the script unchecks it on each home opening
// before it reads an "unavailable" row. It could falsely pass if a row's text
// matched by coincidence; the failure texts are asserted together with the
// absence of the previous (12.345678 / 7.654321) amounts.
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { pastePhrase } from './browser-phrase.js';
import { algorandNetwork } from '../src/pq/algorand.js';
const web=fileURLToPath(new URL('../dist',import.meta.url));
const fixture=JSON.parse(await readFile(new URL('./fixtures/pq-receive.json',import.meta.url),'utf8')).vectors[0];
const evidence=process.env.ALGORAND_SCREENSHOT_DIR||join(tmpdir(),'algorand-ui-evidence');await mkdir(evidence,{recursive:true});
const account=fixture.addresses.algorand.mainnet, errors=[], requests=[], blocked=[];
const server=createServer(async(req,res)=>{
  const path=resolve(web,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname));
  if(path!==web&&!path.startsWith(web+'/')){res.writeHead(403);res.end();return;}
  try {const file=path===web?join(web,'index.html'):path, data=await readFile(file);res.writeHead(200,{'Content-Type':({'.html':'text/html','.js':'application/javascript','.css':'text/css','.wasm':'application/wasm','.json':'application/json','.svg':'image/svg+xml','.png':'image/png'})[extname(file)]||'application/octet-stream'});res.end(data);}catch{res.writeHead(404);res.end();}
});
server.on('connect',(req,socket)=>{socket.on('error',()=>{});blocked.push(req.url);socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');});
await new Promise(done=>server.listen(0,'127.0.0.1',done));
const origin=`http://127.0.0.1:${server.address().port}`, temporary=await mkdtemp(join(tmpdir(),'algorand-ui-'));
let context, mode='success', pending=[], delay=false;
const tx={id:'A'.repeat(52),'tx-type':'pay',sender:'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ','confirmed-round':5,'round-time':1700000000,'payment-transaction':{receiver:account,amount:2500000}};
const home=async page=>{await page.locator('.wallet-navigation a[href="#"]').click();};
// Home, then show every holding (the box is re-checked on each home opening), then the Receive page.
const receivePage=async page=>{await home(page);await page.locator('#show-zero-balances').uncheck();await page.locator('.wallet-navigation a[href="#receive"]').click();};
const balances=page=>page.locator('.chain-holding[data-chain="algorand"]');
try {
 context=await chromium.launchPersistentContext(temporary,{executablePath:process.env.CHROMIUM_PATH||'/usr/bin/google-chrome',headless:true,chromiumSandbox:true,viewport:{width:1360,height:1000},args:[`--proxy-server=${origin}`,'--proxy-bypass-list=127.0.0.1','--disable-background-networking']});
 context.setDefaultTimeout(30000);
 await context.route('**/*',async route=>{
  const url=new URL(route.request().url());if(url.origin===origin)return route.continue();
  if(!/^(mainnet|testnet)-(api|idx)\.algonode\.cloud$/.test(url.hostname)){blocked.push(url.href);return route.abort('blockedbyclient');}
  requests.push({url:url.href,method:route.request().method()});
  const networkId=url.hostname.startsWith('mainnet')?'mainnet':'testnet', genesis=algorandNetwork(networkId).genesisHash;
  const respond=async()=>{
   if(mode==='http')return route.fulfill({status:503,body:'unavailable'});
   let data=url.pathname.endsWith('/params')||url.pathname.endsWith('/0')?{'genesis-hash':genesis,round:0}:url.pathname.endsWith('/transactions')?{'current-round':mode==='malformed'?'bad':10,transactions:[{...tx,'payment-transaction':{...tx['payment-transaction'],amount:networkId==='mainnet'?2500000:3500000}}]}:{address:account,amount:mode==='malformed'?'bad':networkId==='mainnet'?12345678:7654321};
   await route.fulfill({json:data}).catch(()=>{});
  };
  if(delay&&networkId==='mainnet'&&!url.pathname.endsWith('/params')&&!url.pathname.endsWith('/0'))pending.push(respond);else await respond();
 });
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.routeWebSocket(()=>true,ws=>ws.close());
 await page.goto(origin);await page.locator('#restore:visible').click();await pastePhrase(page,fixture.phrase);await page.locator('#backup-confirm').check();await page.locator('#phrase-submit').click();await page.locator('#wallet-open').waitFor({state:'visible'});
 await page.locator('.wallet-navigation a[href="#receive"]').click();await page.selectOption('#chain','algorand',{force:true});
 await page.waitForFunction(a=>document.querySelector('#receive-address').textContent===a,account);
 await page.waitForFunction(()=>document.querySelector('.chain-holding[data-chain="algorand"]')?.textContent.includes('12.345678'));
 // Algorand mainnet send is open since 0.1.157 (src/pq/wallet-capabilities.js); this wallet is not saved, so the submit below is refused before any review.
 assert.equal(await page.locator('#quick-send').isDisabled(),false);
 await page.locator('#send-form').evaluate(form=>form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));assert.equal(await page.locator('#review-dialog').evaluate(d=>d.open),false);
 await home(page);await page.locator('.wallet-navigation a[href="#wallet-activity"]').click();await page.waitForFunction(()=>document.querySelector('#history').textContent.includes('2.5 ALGO'));assert.match(await page.locator('#history-status').textContent(),/Algorand Indexer/);await page.locator('#activity-panel').screenshot({path:join(evidence,'algorand-history.png')});
 await receivePage(page);
 // Same address, new environment must clear ready and retained values.
 mode='malformed';await page.selectOption('#pq-network-environment','testnet',{force:true});await page.waitForFunction(()=>document.querySelector('.chain-holding[data-chain="algorand"]')?.textContent.includes('Balance unavailable'));
 assert.doesNotMatch(await balances(page).textContent(),/12\.345678|Last read|0 ALGO/);
 await page.waitForFunction(()=>document.querySelector('#history-status').textContent.includes('could not be read'));assert.equal(await page.locator('#history').textContent(),'');
 // A provider HTTP failure shows its status (src/portfolio.js balanceErrorDetail; test/browser-capabilities.js:66-67); a malformed body shows "Balance unavailable".
 mode='http';await page.selectOption('#pq-network-environment','mainnet',{force:true});await page.waitForFunction(()=>document.querySelector('.chain-holding[data-chain="algorand"]')?.textContent.includes('HTTP 503'));
 mode='success';await page.selectOption('#pq-network-environment','testnet',{force:true});await page.waitForFunction(()=>document.querySelector('.chain-holding[data-chain="algorand"]')?.textContent.includes('7.654321'));
 // Mainnet balance/history remain pending, then switch identical address.
 delay=true;await page.selectOption('#pq-network-environment','mainnet',{force:true});await page.waitForFunction(()=>document.querySelector('#history-status').textContent.includes('Reading'));
 await new Promise(done=>setTimeout(done,100));assert.ok(pending.length>=2,'both old reads are held');
 await page.selectOption('#pq-network-environment','testnet',{force:true});for(const release of pending.splice(0))await release();
 await page.waitForFunction(()=>document.querySelector('.chain-holding[data-chain="algorand"]')?.textContent.includes('7.654321'));assert.doesNotMatch(await balances(page).textContent(),/12\.345678/);
 assert.equal(await page.locator('#receive-address').textContent(),account);
 await page.waitForFunction(()=>document.querySelector('#history').textContent.includes('3.5 ALGO'));assert.doesNotMatch(await page.locator('#history').textContent(),/2\.5 ALGO/);
 await page.locator('#receive-panel').screenshot({path:join(evidence,'algorand-receive.png')});await home(page);await page.locator('details.network-assets[data-chain="algorand"]').evaluate(n=>n.open=true);await page.locator('details.network-assets[data-chain="algorand"]').screenshot({path:join(evidence,'algorand-balance.png')});await page.screenshot({path:join(evidence,'algorand-read-only.png'),fullPage:true});
 await home(page);await page.locator('.wallet-navigation a[href="#settings"]').click();await page.locator('#vault-storage-title').click();
 const password='Aa9!'+randomBytes(24).toString('hex');await page.locator('#vault-password').fill(password);await page.locator('#vault-confirm-password').fill(password);await page.locator('#vault-risk-confirm').check();await page.locator('#vault-save').click();await page.waitForFunction(()=>document.querySelector('#vault-save-status').textContent.includes('Encrypted wallet saved'));
 await home(page);await page.locator('.wallet-navigation a[href="#receive"]').click();await page.selectOption('#pq-network-environment','mainnet',{force:true});await new Promise(done=>setTimeout(done,100));await home(page);await page.locator('#lock').click();for(const release of pending.splice(0))await release();assert.equal(await page.locator('#receive-address').textContent(),'');assert.equal(await page.locator('#history').textContent(),'');
 delay=false;mode='http';await page.reload();await page.locator('#unlock-password:visible').fill(password);await page.locator('#unlock-wallet').click();await page.locator('#wallet-open').waitFor({state:'visible'});await page.locator('#show-zero-balances').uncheck();await page.locator('.wallet-navigation a[href="#receive"]').click();await page.selectOption('#chain','algorand',{force:true});await page.waitForFunction(()=>document.querySelector('.chain-holding[data-chain="algorand"]')?.textContent.includes('HTTP 503'));assert.doesNotMatch(await balances(page).textContent(),/12\.345678|7\.654321|Last read/);assert.equal(await page.locator('#history').textContent(),'');
 assert.ok(requests.every(r=>r.method==='GET'));assert.deepEqual(errors,[]);console.log(JSON.stringify({passed:'balance/history, errors, same-address environment cancellation, send refusal, lock',requests,consoleErrors:errors,blockedExternalRequests:blocked.length,screenshot:join(evidence,'algorand-read-only.png')},null,2));
} finally {await context?.close();await new Promise(done=>server.close(done));await rm(temporary,{recursive:true,force:true});}
