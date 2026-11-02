import { randomBytes } from 'node:crypto';
// Production DOM, real recovery WASM, synthetic accounts, intercepted providers.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { isolatedWallet, publicFixture } from './browser-capability-fixture.js';
import { pastePhrase } from './browser-phrase.js';
import { assertNetworkGroups } from './browser-network-groups.js';
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
  const select=async chain=>{await page.selectOption('#chain',chain);};
  assert.equal(await page.locator('.wallet-navigation').count(),1);
  assert.equal(await page.locator('#balances .holding-actions, #balances .asset-action').count(),0,'holdings only; actions live on dedicated pages');
  assert.equal(await page.locator('#show-zero-balances').isChecked(),true);
  assert.match(await page.locator('label[for="show-zero-balances"]').textContent(),/Hide zero balances/);
  await page.waitForFunction(()=>!document.querySelector('.network-assets[data-chain="tron"]'));
  assert.equal(await group('ethereum').count(),1,'zero native / funded token retained');
  assert.equal(await group('bsc').count(),1,'one raw native unit retained');
  assert.equal(await group('solana').count(),1,'failed balance retained');
  assert.equal(await group('tidecoin').count(),1,'unknown balance retained');
  await page.locator('#show-zero-balances').uncheck();assert.equal(await group('tron').count(),1);
  await page.locator('#show-zero-balances').check();assert.equal(await group('tron').count(),0);
  await select('ckb');await nav('receive').click();
  await page.waitForFunction(a=>document.querySelector('#receive-address').textContent===a,publicFixture.addresses.ckb.mainnet);
  assert.equal(await nav('send').isVisible(),false);assert.equal(await nav('wallet-activity').isVisible(),false);
  assert.doesNotMatch(await group('ckb').textContent(),/total live-cell capacity/i);
  await page.selectOption('#pq-network-environment','testnet');
  await page.waitForFunction(a=>document.querySelector('#receive-address').textContent===a,publicFixture.addresses.ckb.testnet);
  assert.equal(await nav('send').isVisible(),false);assert.equal(await nav('wallet-activity').isVisible(),false);
  assert.equal(run.requests.some(({url})=>/https:\/\/(?:mainnet|testnet)\.ckb\.dev(?:\/|$)/.test(url)),false,'CKB remains receive-only without provider reads');
  await select('algorand');await nav('receive').click();
  await page.waitForFunction(a=>document.querySelector('#receive-address').textContent===a,publicFixture.addresses.algorand.mainnet);
  assert.equal(await nav('send').isVisible(),false);assert.equal(await nav('wallet-activity').isVisible(),true);
  run.state.failAlgorand=true;await page.selectOption('#pq-network-environment','testnet');
  await page.waitForFunction(()=>document.querySelector('.network-assets[data-chain="algorand"]')?.textContent.includes('Balance unavailable'));
  assert.equal(await group('algorand').count(),1,'failed Algorand balance retained');
  assert.equal(await nav('send').isVisible(),false);assert.equal(await nav('wallet-activity').isVisible(),true,'RPC failure retains implemented history capability');
  run.state.failAlgorand=false;
  await select('nodus');
  for(const [target,panel] of [['earn','stake-panel'],['contracts','evm-panel'],['vaults','vault-panel']]){
   assert.equal(await nav(target).isVisible(),true);await nav(target).click();await page.locator('#'+panel).waitFor({state:'visible'});
   assert.match(await page.locator('#'+panel).textContent(),/Connect to the Nodus node/);
   assert.equal(await page.locator('#'+panel+' button:visible:not(:disabled)').filter({hasText:/^(Delegate|Withdraw|Approve|Create|Deploy|Send|Confirm)/}).count(),0);
   await select('bsc');await page.locator('#page-'+target).waitFor({state:'hidden'});await select('nodus');
  }
  await nav('').click();await page.locator('#assets-panel').waitFor({state:'visible'});
  await group('bsc').getByRole('button',{name:'Select BNB Smart Chain network',exact:true}).click();assert.equal(await page.locator('#chain').inputValue(),'bsc');assert.equal(await nav('wallet-activity').isVisible(),false);
  for(const id of ['nav-earn','nav-vaults','nav-evm'])assert.equal(await page.locator('#'+id).isVisible(),false);
  await nav('settings').click();assert.equal(await page.locator('#page-settings').isVisible(),true);
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
  assert.equal(await nav('send').isVisible(),false);assert.equal(await nav('wallet-activity').isVisible(),true);
  await page.selectOption('#pq-network-environment','testnet');await page.waitForFunction(a=>document.querySelector('#receive-address').textContent===a,publicFixture.addresses.algorand.testnet);
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
  assert.equal(run.requests.some(({url})=>/https:\/\/(?:mainnet|testnet)\.ckb\.dev(?:\/|$)/.test(url)),false,'no CKB API reads throughout all flows');
  assert.equal(run.state.broadcasts,0);assert.deepEqual(run.errors,[]);await writeFile(join(evidence,`${mode}-browser.json`),JSON.stringify({passed:true,broadcasts:run.state.broadcasts,requests:run.requests,blocked:run.blocked,pageErrors:run.errors,consoleErrors:run.consoleErrors},null,2));
  console.log(`PASS ${mode}: network holdings/zero precision, contextual capabilities, dedicated pages, stale state, keyboard and 1360/390/360 layouts`);
 }catch(error){await writeFile(join(evidence,`${mode}-failure.json`),JSON.stringify({error:String(error),pageErrors:run?.errors,consoleErrors:run?.consoleErrors},null,2));if(run)await writeFile(join(evidence,`${mode}-failure-transports.json`),JSON.stringify({requests:run.requests,blocked:run.blocked},null,2));if(run)await run.page.screenshot({path:join(evidence,`${mode}-failure.png`),fullPage:true}).catch(()=>{});throw error;}
 finally{await run?.close();}
}
