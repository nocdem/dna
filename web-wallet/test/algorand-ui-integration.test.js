import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { walletCapabilities, walletPageSupported, walletPqNetwork } from '../src/pq/wallet-capabilities.js';
import { capabilitiesFor } from '../src/capabilities.js';
import { activityKeyFor, serializeActivity, parseActivity } from '../src/activity-storage.js';
import { checkActivity } from '../src/activity.js';
import { prepareTransfer } from '../src/wallet.js';
import { ALGORAND_FALCON_PROTOCOL } from '../src/pq/algorand-prepare.js';
import { algorandNetwork } from '../src/pq/algorand.js';
const fixture=JSON.parse(await readFile(new URL('./fixtures/pq-receive.json',import.meta.url),'utf8')).vectors[0];
const address=fixture.addresses.algorand.mainnet;
const row={chain:'algorand',address,to:address,symbol:'ALGO',amount:'0.000001',hash:'A'.repeat(52),lastValidBlockHeight:200,createdAt:'2026-11-02T00:00:00Z',status:'unknown'};
test('Web Wallet mainnet native candidates are independently gated; QTC history visible',()=>{
 assert.equal(walletCapabilities('algorand','mainnet').send,true);
 assert.equal(walletCapabilities('algorand','testnet').send,false);
 assert.equal(walletCapabilities('soqucoin','mainnet').send,true);
 assert.equal(walletCapabilities('soqucoin','testnet').send,false);
 assert.equal(capabilitiesFor('soqucoin').send,false);
 assert.equal(walletCapabilities('algorand').send,false);
 assert.equal(capabilitiesFor('algorand').send,false);
 assert.equal(walletPageSupported('algorand','send','testnet'),false);
 assert.equal(walletPqNetwork('algorand',{receiveOnly:true},'mainnet').receiveOnly,false);
 assert.equal(walletPqNetwork('algorand',{receiveOnly:true},'testnet').receiveOnly,true);
 assert.equal(walletCapabilities('qtc','mainnet').history,true);
 assert.equal(walletCapabilities('asentum','testnet').send,true);for(const id of ['mainnet','devnet',undefined])assert.equal(walletCapabilities('asentum',id).send,false);
 assert.equal(walletPqNetwork('asentum',{receiveOnly:true},'testnet').receiveOnly,false);assert.equal(walletPqNetwork('asentum',{receiveOnly:true},'mainnet').receiveOnly,true);
});
test('dispatcher rejects testnet and wrong asset before provider access',async()=>{
 await assert.rejects(prepareTransfer({chain:'algorand',symbol:'ALGO',networkId:'testnet'}),/verified Algorand/);
 await assert.rejects(prepareTransfer({chain:'algorand',symbol:'USDC',networkId:'mainnet'}),/verified Algorand/);
});
test('authenticated pending ALGO record survives reload before and after address derivation',async()=>{
 const id=Buffer.alloc(16,9).toString('base64'),key=await activityKeyFor(fixture.phrase,id);
 const serialized=await serializeActivity(id,[row],key);
 for(const addresses of [{},{algorand:address}]){
  const rows=await parseActivity(serialized,id,addresses,key);
  assert.equal(rows.length,1);assert.equal(rows[0].hash,row.hash);assert.equal(rows[0].status,'pending');
  assert.equal(rows[0].lastValidBlockHeight,200);assert.equal(rows[0].endpoint,'https://mainnet-api.algonode.cloud');
 }
 await assert.rejects(parseActivity(serialized,id,{algorand:'wrong'},key));
});
test('tracker validates network and sender; 404 after expiry is not evidence of failure',async()=>{
 let mode='confirmed';
 const fetcher=async url=>{
  if(url.endsWith('/params'))return new Response(JSON.stringify({'consensus-version':mode==='wrong-network'?'wrong':ALGORAND_FALCON_PROTOCOL,'genesis-hash':algorandNetwork('mainnet').genesisHash,'genesis-id':'mainnet-v1.0','last-round':300}));
  if(mode==='missing'){
   if(url.includes('/blocks/0'))return new Response(JSON.stringify({'genesis-hash':algorandNetwork('mainnet').genesisHash,round:0}));
   if(url.includes('?txid='))return new Response(JSON.stringify({'current-round':199,transactions:[]}));
   return new Response('{}',{status:404});
  }
  return new Response(JSON.stringify({'confirmed-round':101,txn:{txn:{snd:mode==='wrong-sender'?'bad':address}}}));
 };
 assert.equal((await checkActivity(row,{fetcher})).status,'confirmed');
 mode='missing';assert.equal((await checkActivity(row,{fetcher})).status,'pending');
 mode='wrong-network';await assert.rejects(checkActivity(row,{fetcher}),/network changed/);
 mode='wrong-sender';await assert.rejects(checkActivity(row,{fetcher}),/different sender/);
});
test('UI routes selected network, persists before submission and prevents abandonment/duplicate pending sends',async()=>{
 const app=await readFile(new URL('../src/app.js',import.meta.url),'utf8');
 assert.match(app,/networkId: isPqChain\(chain\) \? pqSelections\[chain\]/);
 assert.match(app,/\['ethereum', 'bsc', 'algorand', 'soqucoin', 'splendor', 'asentum', 'ckb'\]\.includes/);
 assert.match(app,/row.chain !== NODUS_ASSET.chain && !\['algorand', 'soqucoin', 'splendor', 'asentum', 'ckb'\]\.includes/);
 assert.match(app,/await persistActivity\(\{ required: true,/);
 assert.match(app,/\['algorand', 'soqucoin', 'splendor', 'asentum', 'ckb'\]\.includes\(\$\('chain'\)\.value\) && !activitySession/);
});

test('old confirmations and known pre-submit cancellation recover without duplicate send',async()=>{
 const id=Buffer.alloc(16,8).toString('base64'),key=await activityKeyFor(fixture.phrase,id);
 let old=await parseActivity(await serializeActivity(id,[{...row,status:'confirmed'}],key),id,{algorand:address},key);
 const fetcher=async url=>{
  if(url.includes('/pending/'))return new Response('{}',{status:404});
  if(url.endsWith('/params'))return new Response(JSON.stringify({'consensus-version':ALGORAND_FALCON_PROTOCOL,'genesis-hash':algorandNetwork('mainnet').genesisHash,'genesis-id':'mainnet-v1.0','last-round':400}));
  if(url.includes('/blocks/0'))return new Response(JSON.stringify({'genesis-hash':algorandNetwork('mainnet').genesisHash,round:0}));
  return new Response(JSON.stringify({'current-round':399,transactions:[{id:row.hash,sender:address,'tx-type':'pay','confirmed-round':101}]}));
 };
 assert.equal((await checkActivity(old[0],{fetcher})).status,'confirmed');
 const cancelled={...row,status:'failed',notSubmitted:true};
 const saved=await parseActivity(await serializeActivity(id,[cancelled],key),id,{algorand:address},key);
 assert.equal((await checkActivity(saved[0],{fetcher:()=>{throw Error('must not request')}})).status,'failed');
});

test('only complete indexed-through expiry evidence releases unresolved records',async()=>{
 let mode='complete';
 const fetcher=async url=>{
  if(url.includes('/pending/'))return new Response(JSON.stringify({txn:{txn:{snd:address}}}));
  if(url.endsWith('/params'))return new Response(JSON.stringify({'consensus-version':ALGORAND_FALCON_PROTOCOL,'genesis-hash':algorandNetwork('mainnet').genesisHash,'genesis-id':'mainnet-v1.0','last-round':400}));
  if(url.includes('/blocks/0'))return new Response(JSON.stringify({'genesis-hash':algorandNetwork('mainnet').genesisHash,round:0}));
  return new Response(JSON.stringify({'current-round':mode==='lagging'?199:399,transactions:[],...(mode==='paginated'?{'next-token':'continuation'}:{})}));
 };
 assert.equal((await checkActivity(row,{fetcher})).status,'expired');
 mode='lagging';assert.equal((await checkActivity(row,{fetcher})).status,'pending');
 mode='paginated';assert.equal((await checkActivity(row,{fetcher})).status,'pending');
});

test('origin-wide durable callback rejects another tab pending ALGO reservation',async()=>{
 const {runInNewContext}=await import('node:vm');
 const app=await readFile(new URL('../src/app.js',import.meta.url),'utf8');
 const source=app.slice(app.indexOf('function persistActivity('),app.indexOf('// The last balances,'));
 let writes=0;
 const session={id:'test',key:{},vault:'vault'},wallet={addresses:{algorand:address},locked:false};
 const candidate={...row,hash:'B'.repeat(52),status:'pending'};
 const context={activitySession:session,wallet,history:[candidate],historyWrites:Promise.resolve(),activityBlocked:false,VAULT_KEY:'vaultkey',ACTIVITY_KEY:'activitykey',quarantinedRows:[],
  localStorage:{getItem:key=>key==='vaultkey'?'vault':'encrypted',setItem:()=>{writes++;}},
  terminal:status=>['confirmed','failed','expired','replaced','abandoned'].includes(status),
  withActivityLock:work=>work(),submissionProofStorage:{},recoverSubmissionProofs:async({rows})=>rows,clearSubmissionProofs:async()=>{},parseActivity:async()=>[{...row,status:'pending',savedStatus:'unknown'}],
  serializeActivity:async()=> 'sealed',quarantineLocks:()=>[],Map,Promise,Date,Object};
 runInNewContext(source+'; globalThis.persist = persistActivity;',context);
 await assert.rejects(context.persist({required:true}),/Another algorand submission/i);
 assert.equal(writes,0);
 context.history.push({...row,status:'confirmed'});
 await context.persist({required:true});assert.equal(writes,1);
});
