// Synthetic public recovery fixture. Never forward an external transport.
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve, extname } from 'node:path';
import { chromium } from 'playwright';
import { portfolioRead, cellframeRead, historyRead, ixiosRead } from './portfolio-routes.js';
import { algorandNetwork } from '../src/pq/algorand.js';
export const publicFixture=JSON.parse(await readFile(new URL('./fixtures/pq-receive.json',import.meta.url),'utf8')).vectors[0];
export async function isolatedWallet(mode='web') {
 const root=resolve(new URL('..',import.meta.url).pathname,mode==='connect'?'dist-connect':'dist');
 const extension=resolve(new URL('../dist-extension/unpacked',import.meta.url).pathname);
 const blocked=[],requests=[],errors=[],consoleErrors=[];
 const state={holdings:{'ethereum:USDT':'1000000','bsc:BNB':'1'},failures:['solana:SOL'],holdEthereum:false,pending:[],prepareEthereum:false,broadcasts:0};
 state.historyEthereum=address=>[{hash:'0x'+'c'.repeat(64),from:'0x0000000000000000000000000000000000000001',to:address,timeStamp:'1700000000',value:'314159000000000000',isError:'0',txreceipt_status:'1'}];
 const server=createServer(async(req,res)=>{
  if(/^https?:\/\//.test(req.url)){blocked.push(req.url);res.writeHead(403);return res.end();}
  const path=resolve(root,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname));
  if(path!==root&&!path.startsWith(root+'/')){res.writeHead(403);return res.end();}
  try{const file=path===root?join(root,'index.html'):path;const data=await readFile(file);res.writeHead(200,{'Content-Type':({'.html':'text/html','.js':'application/javascript','.css':'text/css','.wasm':'application/wasm','.svg':'image/svg+xml','.json':'application/json','.png':'image/png'})[extname(file)]||'application/octet-stream'});res.end(data);}catch{res.writeHead(404);res.end();}
 });
 server.on('connect',(req,socket)=>{socket.on('error',()=>{});blocked.push(req.url);socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');});
 await new Promise((ok,fail)=>{server.once('error',fail);server.listen(0,'127.0.0.1',ok);});
 const origin=`http://127.0.0.1:${server.address().port}`, temporary=await mkdtemp(join(tmpdir(),'capabilities-ui-'));
 let context;
 try{
  context=await chromium.launchPersistentContext(temporary,{executablePath:process.env.CHROMIUM_PATH||'/usr/bin/google-chrome',headless:true,chromiumSandbox:true,viewport:{width:1360,height:1000},ignoreDefaultArgs:mode==='extension'?['--disable-extensions']:[],args:[`--proxy-server=${origin}`,'--proxy-bypass-list=127.0.0.1','--disable-background-networking',...(mode==='extension'?[`--load-extension=${extension}`,`--disable-extensions-except=${extension}`]:[])]});
  context.setDefaultTimeout(20000);
  await context.routeWebSocket(()=>true,ws=>{blocked.push(ws.url());ws.close();});
  await context.route('**/*',async route=>{
   const req=route.request(),url=new URL(req.url());if(url.origin===origin||url.protocol==='chrome-extension:')return route.continue();
   requests.push({url:url.href,method:req.method()});
   if(state.prepareEthereum&&url.hostname==='ethereum-rpc.publicnode.com'){
    const call=req.postDataJSON();
    if((Array.isArray(call)?call:[call]).some(c=>c.method==='eth_sendRawTransaction')){state.broadcasts++;return route.abort('blockedbyclient');}
    const results={eth_chainId:'0x1',eth_getBalance:'0x8ac7230489e80000',eth_call:'0x'+'0'.repeat(64),eth_estimateGas:'0x5208',eth_gasPrice:'0x3b9aca00',eth_maxPriorityFeePerGas:'0x3b9aca00',eth_getTransactionCount:'0x0',eth_getBlockByNumber:{hash:'0x'+'a'.repeat(64),parentHash:'0x'+'b'.repeat(64),number:'0x1',timestamp:'0x65000000',nonce:'0x0000000000000000',difficulty:'0x0',gasLimit:'0x1c9c380',gasUsed:'0x5208',miner:'0x0000000000000000000000000000000000000001',extraData:'0x',transactions:[]}};
    const calls=Array.isArray(call)?call:[call];
    if(calls.every(c=>Object.hasOwn(results,c.method))){const replies=calls.map(c=>({jsonrpc:'2.0',id:c.id,result:results[c.method]}));return route.fulfill({json:Array.isArray(call)?replies:replies[0]});}
   }
   if(state.holdEthereum&&url.hostname==='ethereum-rpc.publicnode.com')await new Promise(ok=>state.pending.push(ok));
   if(/^(mainnet|testnet)-(api|idx)\.algonode\.cloud$/.test(url.hostname)){
    if(state.failAlgorand)return route.fulfill({status:503,body:'Synthetic unavailable'});
    const network=url.hostname.startsWith('mainnet')?'mainnet':'testnet';
    return route.fulfill({json:url.pathname.endsWith('/params')||url.pathname.endsWith('/0')?{'genesis-hash':algorandNetwork(network).genesisHash,round:0}:url.pathname.endsWith('/transactions')?{'current-round':10,transactions:[]}:{address:publicFixture.addresses.algorand[network],amount:0}});
   }
   if(await historyRead(route,{ethereum:state.historyEthereum||[]})||await cellframeRead(route,{balance:'0'})||await ixiosRead(route,{balance:0n})||await portfolioRead(route,state))return;
   blocked.push(url.href);return route.abort('blockedbyclient');
  });
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')consoleErrors.push(m.text());});
  let url=origin;
  if(mode==='extension'){
   const worker=context.serviceWorkers().find(w=>w.url().startsWith('chrome-extension:'))||await context.waitForEvent('serviceworker',{timeout:15000});
   url=`chrome-extension://${new URL(worker.url()).hostname}/home.html`;
   // The consumers of this fixture restore a wallet straight away; the data notice (2026-11-03 Chrome Web Store
   // decision, plan section 2.7) is agreed to here by storing its text version (background/privacy-consent.js).
   await worker.evaluate(()=>chrome.storage.local.set({'nodus.privacyConsent.v1':'1'}));
  }
  return {page,context,url,state,blocked,requests,errors,consoleErrors,async close(){state.pending.splice(0).forEach(ok=>ok());await context.close();await new Promise(ok=>server.close(ok));await rm(temporary,{recursive:true,force:true});}};
 }catch(error){await context?.close();await new Promise(ok=>server.close(ok));await rm(temporary,{recursive:true,force:true});throw error;}
}
