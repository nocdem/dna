import { randomBytes } from 'node:crypto';
// Production DOM, real recovery WASM, synthetic accounts, intercepted providers.
// Proves, per surface, which network pages (Send, Activity, Earn, Vaults,
// contracts) are offered, zero-balance hiding, stale-state clearing on network
// and environment switches, keyboard use, no overflow at 1360/390/360 px, and
// that the CKB reads are POST to the public RPC only. No broadcast occurs.
// Needs: built dist/ (web), dist-connect/ (connect) and dist-extension/unpacked
// (extension), and Chromium at CHROMIUM_PATH (default /usr/bin/google-chrome);
// browser-capability-fixture.js hosts the build on 127.0.0.1 port 0.
// Env: CAPABILITY_BROWSER_MODE (default web,connect,extension; comma list) picks
// the surfaces; CAPABILITY_SCREENSHOT_DIR (default ../evidence/navigation-stage2
// relative to the working directory).
// Leaves: screenshots plus <mode>-browser.json on a pass, or <mode>-failure.json
// / -failure-transports.json / -failure.png on a failure (which is rethrown), in
// that directory; the temporary profile and host are removed.
// Falsely passes: a mode left out of CAPABILITY_BROWSER_MODE is simply not run.
// Expected Send/Activity come from the same capability tables the pages use, so
// a wrong table entry agrees with itself. It tests the built files, not src/.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { isolatedWallet, publicFixture } from './browser-capability-fixture.js';
import { pastePhrase } from './browser-phrase.js';
import { assertNetworkGroups } from './browser-network-groups.js';
// Expected Send/Activity per surface come from the shipped capability tables:
// web and Connect src/pq/wallet-capabilities.js, extension constants/capabilities.js.
import { walletPageSupported } from '../src/pq/wallet-capabilities.js';
import { extensionPageSupported } from '../extension/src/constants/capabilities.js';
const evidence=resolve(process.env.CAPABILITY_SCREENSHOT_DIR||'../evidence/navigation-stage2');await mkdir(evidence,{recursive:true});
const password='Aa9!'+randomBytes(24).toString('hex');
for(const mode of (process.env.CAPABILITY_BROWSER_MODE||'web,connect,extension').split(',')){
 let run;
 try{
  run=await isolatedWallet(mode);const {page}=run;
  await page.goto(run.url);await page.locator('#restore:visible').click();await pastePhrase(page,publicFixture.phrase);await page.locator('#backup-confirm').check();
  if(mode==='extension'){await page.locator('#new-password').fill(password);await page.locator('#confirm-password').fill(password);}
  await page.locator('#phrase-submit').click();await page.locator('#wallet-open').waitFor({state:'visible'});await page.waitForFunction(()=>!document.querySelector('#chain')?.closest('[inert]'));if(mode==='connect')await page.locator('#nav-wallet').click();
  await page.waitForFunction(()=>!document.querySelector('#portfolio-refresh').disabled);
  await assertNetworkGroups(page, { addressBookIxios: mode === 'extension' });
  const group=chain=>page.locator(`.network-assets[data-chain="${chain}"]`);
  const nav=href=>page.locator(`.wallet-navigation a[href="#${href}"]`);
  // UI pack 2026-11-03: Send is offered only where the network can send now. NODUS is receive-only while its
  // connection is not ready (never here: no node is reachable), so the capability table alone is not enough for it.
  const supports=(chain,pageName,networkId)=>chain==='nodus'&&pageName==='send'?false:mode==='extension'?extensionPageSupported(chain,pageName,networkId):walletPageSupported(chain,pageName,networkId);
  const assertPages=async(chain,networkId,label='')=>{assert.equal(await nav('send').isVisible(),supports(chain,'send',networkId),`${mode} ${chain} ${networkId} Send ${label}`);assert.equal(await nav('wallet-activity').isVisible(),supports(chain,'wallet-activity',networkId),`${mode} ${chain} ${networkId} Activity ${label}`);};
  // #chain is hidden; networks and environments are chosen in the network
  // disclosure (src/app.js:2307, :970), as on the shipped page; pages without the
  // disclosure return home first.
  const select=async chain=>{if(!await page.locator('#wallet-network').isVisible()){await nav('').click();await page.locator('#wallet-home').waitFor({state:'visible'});}if(!await page.locator('#wallet-network').evaluate(n=>n.open))await page.locator('#wallet-network > summary').click();const badge=page.locator(`#portfolio-networks .network-health[data-chain="${chain}"]`);const toggle=badge.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " network-group ")]').locator('.network-group-toggle');if(await toggle.count()&&await toggle.getAttribute('aria-expanded')!=='true')await toggle.click();await badge.click();};
  const environment=async id=>{if(!await page.locator('#wallet-network').evaluate(n=>n.open))await page.locator('#wallet-network > summary').click();if(!await page.locator('#wallet-environment').evaluate(n=>n.open))await page.locator('#wallet-environment > summary').click();await page.locator(`#wallet-environment button[data-environment="${id}"]`).click();};
  assert.equal(await page.locator('.wallet-navigation').count(),1);
  assert.equal(await page.locator('#balances .holding-actions, #balances .asset-action').count(),0,'holdings only; actions live on dedicated pages');
  assert.equal(await page.locator('#show-zero-balances').isChecked(),true);
  assert.match(await page.locator('label[for="show-zero-balances"]').textContent(),/Hide zero balances/);
  await page.waitForFunction(()=>!document.querySelector('.network-assets[data-chain="tron"]'));
  assert.equal(await group('ethereum').count(),1,'zero native / funded token retained');
  assert.equal(await group('bsc').count(),1,'one raw native unit retained');
  // 0.1.151 (399147dd2, src/portfolio.js groupNetworks): with Hide zero
  // balances checked, zero, failed and unknown balances all leave the list.
  assert.equal(await group('solana').count(),0,'failed balance hidden');
  assert.equal(await group('tidecoin').count(),0,'unknown balance hidden');
  await page.locator('#show-zero-balances').uncheck();
  for(const chain of ['tron','solana','tidecoin'])assert.equal(await group(chain).count(),1,`${chain} listed with zero balances shown`);
  await page.locator('#show-zero-balances').check();assert.equal(await group('tron').count(),0);
  await select('ckb');await nav('receive').click();
  await page.waitForFunction(a=>document.querySelector('#receive-address').textContent===a,publicFixture.addresses.ckb.mainnet);
  await assertPages('ckb','mainnet');
  // The proxy denies the CKB read, so the row has no balance and is hidden while Hide zero balances is checked (0.1.151).
  assert.equal(await group('ckb').count(),0,'CKB without a balance read leaves the list');
  await environment('testnet');
  await page.waitForFunction(a=>document.querySelector('#receive-address').textContent===a,publicFixture.addresses.ckb.testnet);
  await assertPages('ckb','testnet');
  // 0.1.152 (729389e77): CKB reads balances from its public JSON-RPC (src/pq/ckb.js:6-7);
  // Send follows the surface table above. Reads use only that RPC, by POST.
  for(const {url,method} of run.requests.filter(({url})=>/ckb\.dev/.test(url)))assert.ok(/^https:\/\/(?:mainnet\.ckb\.dev\/rpc|testnet\.ckb\.dev\/?)$/.test(url)&&method==='POST',`CKB request ${method} ${url}`);
  await select('algorand');await nav('receive').click();
  await page.waitForFunction(a=>document.querySelector('#receive-address').textContent===a,publicFixture.addresses.algorand.mainnet);
  // Algorand mainnet send is enabled by the handoff on every surface; testnet stays receive-only.
  await assertPages('algorand','mainnet');
  // The Hide zero balances box is on the home asset panel; it resets on each home opening (src/app.js:2338-2343).
  run.state.failAlgorand=true;await nav('').click();await page.locator('#assets-panel').waitFor({state:'visible'});await page.locator('#show-zero-balances').uncheck();await environment('testnet');
  // A failed read shows its error on the row (the fixture's HTTP 503), never an inferred zero.
  await page.waitForFunction(()=>(document.querySelector('.network-assets[data-chain="algorand"]')?.textContent??'').includes('HTTP 503'));
  assert.equal(await group('algorand').count(),1,'failed Algorand balance listed with zero balances shown');
  await assertPages('algorand','testnet','after an RPC failure');
  run.state.failAlgorand=false;
  await select('nodus');
  for(const [target,panel] of [['earn','stake-panel'],['contracts','evm-panel'],['vaults','vault-panel']]){
   assert.equal(await nav(target).isVisible(),true);await nav(target).click();await page.locator('#'+panel).waitFor({state:'visible'});
   assert.match(await page.locator('#'+panel).textContent(),/Connect to the Nodus node/);
   assert.equal(await page.locator('#'+panel+' button:visible:not(:disabled)').filter({hasText:/^(Delegate|Withdraw|Approve|Create|Deploy|Send|Confirm)/}).count(),0);
   // These pages show no network chooser; switch through the hidden #chain selector the chips drive.
   await page.selectOption('#chain','bsc',{force:true});await page.locator('#page-'+target).waitFor({state:'hidden'});await page.selectOption('#chain','nodus',{force:true});
  }
  await nav('').click();await page.locator('#assets-panel').waitFor({state:'visible'});
  await group('bsc').getByRole('button',{name:'Select BNB Smart Chain network',exact:true}).click();assert.equal(await page.locator('#chain').inputValue(),'bsc');assert.equal(await nav('wallet-activity').isVisible(),false);
  for(const id of ['nav-earn','nav-vaults','nav-evm'])assert.equal(await page.locator('#'+id).isVisible(),false);
  // The extension's Settings is a bottom-bar button (UI pack 2026-11-03); web and Connect keep the rail gear.
  await (mode==='extension'?page.locator('#extension-bottom-bar button[aria-label="Settings"]'):nav('settings')).click();assert.equal(await page.locator('#page-settings').isVisible(),true);
  run.state.historyEthereum=address=>[{hash:'0x'+'c'.repeat(64),from:'0x0000000000000000000000000000000000000001',to:address,timeStamp:'1700000000',value:'314159000000000000',isError:'0',txreceipt_status:'1'}];
  await select('ethereum');await nav('wallet-activity').click();await page.locator('#history-refresh').click();
  await page.waitForFunction(()=>document.querySelector('#history').textContent.includes('0.314159'));
  await nav('send').click();assert.equal(await page.locator('#page-send').isVisible(),true);assert.equal(await page.locator('#receive-panel').isVisible(),false);
  run.state.prepareEthereum=true;
  await page.locator('#recipient').fill('0x0000000000000000000000000000000000000001');await page.locator('#amount').fill('0.01');
  await page.locator('#review-button').click();await page.locator('#review-dialog').waitFor({state:'visible'});
  // Native modal intentionally prevents pointer access to the network control;
  // exercise the same change handler to simulate an interrupting context switch.
  await page.locator('#chain').evaluate(n=>{n.value='bsc';n.dispatchEvent(new Event('change',{bubbles:true}));});
  await page.locator('#review-dialog').waitFor({state:'hidden'});assert.equal(run.state.broadcasts,0);
  run.state.prepareEthereum=false;await select('ethereum');
  await page.locator('#recipient').fill('0x1111111111111111111111111111111111111111');await page.locator('#amount').fill('1');
  await nav('receive').click();assert.equal(await page.locator('#receive-panel').isVisible(),true);assert.equal(await page.locator('#send-fields').isVisible(),false);
  await select('algorand');await page.waitForFunction(a=>document.querySelector('#receive-address').textContent===a,publicFixture.addresses.algorand.mainnet);
  assert.equal(await page.locator('#recipient').inputValue(),'');assert.equal(await page.locator('#amount').inputValue(),'');assert.equal(await page.locator('#review-dialog').evaluate(n=>n.open),false);
  await assertPages('algorand','mainnet');
  // The extension saves the environment in the background before it redraws (extension/src/ui/wallet-screen.js
  // pqEnvironment.onchange); selectChain writes the page links before the receive address, so the testnet address
  // marks the redraw. Checking the links right after the click read the mainnet links when the save was slow.
  await environment('testnet');await page.waitForFunction(a=>document.querySelector('#receive-address').textContent===a,publicFixture.addresses.algorand.testnet);await assertPages('algorand','testnet');
  await select('tidecoin');assert.equal(await nav('wallet-activity').isVisible(),false);assert.equal(await page.locator('#history').textContent(),'');
  await select('ethereum');await nav('').click();run.state.holdEthereum=true;
  await page.locator('#portfolio-refresh').evaluate(n=>n.click());
  for(let i=0;i<100&&!run.state.pending.length;i++)await page.waitForTimeout(20);
  assert.ok(run.state.pending.length,'real balance read held');
  assert.equal(await group('ethereum').count(),1,'loading network retained');
  run.state.holdEthereum=false;run.state.pending.splice(0).forEach(ok=>ok());
  await page.waitForFunction(()=>!document.querySelector('#portfolio-refresh').disabled);
  run.state.failures=['ethereum:ETH','ethereum:USDT','ethereum:USDC','ethereum:DAI'];
  await nav('').click();await page.locator('#portfolio-refresh').evaluate(n=>n.click());await page.waitForFunction(()=>!document.querySelector('#portfolio-refresh').disabled);
  assert.equal(await nav('send').isVisible(),true,'RPC failure retains implemented send capability');
  for(const width of [1360,390,360]){
   await page.setViewportSize({width,height:1000});await nav('').click();await page.locator('#assets-panel').waitFor({state:'visible'});
   const layout=await page.evaluate(()=>{const nav=document.querySelector('.wallet-navigation').getBoundingClientRect(),panel=document.querySelector('#assets-panel').getBoundingClientRect();return{overflow:document.documentElement.scrollWidth>innerWidth,nav:{x:nav.x,right:nav.right,width:nav.width},panel:{x:panel.x,right:panel.right}};});
   assert.equal(layout.overflow,false,JSON.stringify(layout));assert.ok(layout.nav.right<=layout.panel.x+1,JSON.stringify(layout));
   await page.screenshot({path:join(evidence,`${mode}-portfolio-${width}.png`),fullPage:true});await page.screenshot({path:join(evidence,`${mode}-portfolio-${width}-viewport.png`)});
   await nav('receive').focus();await page.keyboard.press('Enter');assert.equal(await page.locator('#page-receive').isVisible(),true);
   await page.screenshot({path:join(evidence,`${mode}-receive-${width}.png`),fullPage:true});
  }
  // 0.1.152 CKB balance reader: at least one read occurred, and every request to a CKB host
  // (any *.ckb.dev) used only its public JSON-RPC, by POST, throughout all flows.
  const ckbRequests=run.requests.filter(({url})=>/^https:\/\/[^/]*ckb\.dev(?:[/:?]|$)/.test(url));
  assert.ok(ckbRequests.length>0,'the CKB balance reader made at least one request');
  for(const {url,method} of ckbRequests)assert.ok(/^https:\/\/(?:mainnet\.ckb\.dev\/rpc|testnet\.ckb\.dev\/?)$/.test(url)&&method==='POST',`CKB request ${method} ${url}`);
  assert.equal(run.state.broadcasts,0);assert.deepEqual(run.errors,[]);await writeFile(join(evidence,`${mode}-browser.json`),JSON.stringify({passed:true,broadcasts:run.state.broadcasts,requests:run.requests,blocked:run.blocked,pageErrors:run.errors,consoleErrors:run.consoleErrors},null,2));
  console.log(`PASS ${mode}: network holdings/zero precision, contextual capabilities, dedicated pages, stale state, keyboard and 1360/390/360 layouts`);
 }catch(error){await writeFile(join(evidence,`${mode}-failure.json`),JSON.stringify({error:String(error),pageErrors:run?.errors,consoleErrors:run?.consoleErrors},null,2));if(run)await writeFile(join(evidence,`${mode}-failure-transports.json`),JSON.stringify({requests:run.requests,blocked:run.blocked},null,2));if(run)await run.page.screenshot({path:join(evidence,`${mode}-failure.png`),fullPage:true}).catch(()=>{});throw error;}
 finally{await run?.close();}
}
