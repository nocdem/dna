import test from 'node:test';import assert from 'node:assert/strict';
import {readFileSync}from'node:fs';import {sha256}from'@noble/hashes/sha2';import {bytesToHex,hexToBytes}from'@noble/hashes/utils';import{base64}from'@scure/base';
import{prepareXionReview,observeXionSubmission}from'../src/pq/xion-transfer.js';
const f=JSON.parse(readFileSync(new URL('./fixtures/pq-receive.json',import.meta.url))).vectors[0];
const wasmBytes=readFileSync(new URL('../src/pq/mldsa65-sign.wasm',import.meta.url));
function setup(){
 const wallet={addresses:{xion:f.addresses.xion.mainnet},recoveryPhrase:f.phrase};let posts=0,hash,mode='ok',accountReads=0,gas=1000,height=1000;
 const fetcher=async(url,options={})=>{
  let data;
  if(url.endsWith('/node_info'))data={default_node_info:{network:'xion-mainnet-1'}};
  else if(url.endsWith('/syncing'))data={syncing:false,latest_block_height:String(height)};
  else if(url.endsWith('/blocks/latest')){const h={chain_id:'xion-mainnet-1',height:String(height),time:new Date().toISOString()};data={block_id:{hash:base64.encode(new Uint8Array(32).fill(1))},block:{header:h},sdk_block:{header:h}};}
  else if(url.includes('/accounts/')){accountReads++;data={account:{'@type':'/cosmos.auth.v1beta1.BaseAccount',address:wallet.addresses.xion,account_number:'5',sequence:((mode==='changed'&&accountReads>1)||(mode==='changed-final'&&accountReads>2))?'3':'2',pub_key:null}};if(mode==='head-advances-final'&&accountReads===3)height+=6;}
  else if(url.includes('/spendable_balances/'))data={balance:{denom:'uxion',amount:'100000000'}};
  else if(url.endsWith('/simulate'))data={gas_info:{gas_used:String(gas)}};
  else if(options.method==='POST'){
   posts++;assert.ok(hash,'durable callback precedes POST');const payload=JSON.parse(options.body);assert.equal(payload.mode,'BROADCAST_MODE_SYNC');assert.equal(bytesToHex(sha256(base64.decode(payload.tx_bytes))),hash);
   if(mode==='ambiguous')throw Error('connection lost');data={tx_response:{txhash:hash.toUpperCase(),code:0}};
  }else if(mode==='missing')return new Response('{}',{status:404});
  else data={tx:{body:{messages:[{'@type':'/cosmos.bank.v1beta1.MsgSend',from_address:wallet.addresses.xion}]}},tx_response:{txhash:hash,height:'123',code:0}};
  const q=options.headers?.['x-cosmos-block-height'];return new Response(JSON.stringify(data),q?{headers:{'x-cosmos-block-height':q}}:undefined);
 };
 const args={wallet,publicKey:hexToBytes(f.keys.xion.pk),to:wallet.addresses.xion,amountAtoms:'1',gasLimit:'10000',feeAtoms:'100',networkId:'mainnet',fetcher,wasmBytes};
 return {args,wallet,fetcher,posts:()=>posts,setMode:m=>mode=m,setGas:n=>gas=n,setHeight:n=>height=n,onBroadcast:d=>{hash=d.hash;assert.equal(d.signedPayload.encoding,'base64');return {submissionId:'0123456789abcdef0123456789abcdef'};},getHash:()=>hash};
}
test('XION explicit-fee native controller signs only after confirm and persists before one mocked SYNC admission',async()=>{
 const x=setup(),r=await prepareXionReview(x.args);assert.equal(x.posts(),0);assert.equal(r.gasUsed,'1000');
 const hash=await r.confirm(x.onBroadcast);assert.match(hash,/^[0-9a-f]{64}$/);assert.equal(x.posts(),1);
 await assert.rejects(r.confirm(x.onBroadcast),/closed/);await assert.rejects(prepareXionReview(x.args),/unresolved/);
 assert.equal((await observeXionSubmission({networkId:'mainnet',from:x.wallet.addresses.xion,hash,fetcher:x.fetcher})).state,'confirmed');
});
test('XION refuses missing fee, changed sequence and insufficient simulated gas without submission',async()=>{
 const x=setup();await assert.rejects(prepareXionReview({...x.args,feeAtoms:undefined}),/Explicit/);
 const r=await prepareXionReview(x.args);x.setMode('changed');await assert.rejects(r.confirm(x.onBroadcast),e=>/account changed/.test(e.message)&&e.xionNotSubmitted===true);assert.equal(x.posts(),0);
 const y=setup();y.setGas(10001);await assert.rejects(prepareXionReview(y.args),/below/);
});
test('XION ambiguous admission is never retried or released by a missing lookup',async()=>{
 const x=setup(),r=await prepareXionReview(x.args);x.setMode('ambiguous');await assert.rejects(r.confirm(x.onBroadcast));assert.equal(x.posts(),1);
 x.setMode('missing');assert.equal((await observeXionSubmission({networkId:'mainnet',from:x.wallet.addresses.xion,hash:x.getHash(),fetcher:x.fetcher})).state,'pending');
 await assert.rejects(prepareXionReview(x.args),/unresolved/);x.setMode('ok');await observeXionSubmission({networkId:'mainnet',from:x.wallet.addresses.xion,hash:x.getHash(),fetcher:x.fetcher});
});
test('XION lock in durable callback prevents POST and marks known non-submission',async()=>{
 const x=setup(),r=await prepareXionReview(x.args);
 await assert.rejects(r.confirm(d=>{const attempt=x.onBroadcast(d);x.wallet.locked=true;return attempt;}),e=>e.xionNotSubmitted===true);assert.equal(x.posts(),0);
});
test('XION optional timeout survives preflight, review, signing and durable callback',async()=>{
 const x=setup();let pending;const r=await prepareXionReview(x.args);assert.equal(r.timeoutHeight,'1100');const hash=await r.confirm(d=>{pending=d;return x.onBroadcast(d);});assert.equal(pending.timeoutHeight,'1100');assert.equal(pending.accountNumber,'5');const {validateXionSignedPayload,verifyXionSignedPayload}=await import('../src/pq/xion-recovery.js');const row={networkId:pending.networkId,address:pending.from,to:pending.to,amountAtoms:pending.amountAtoms,feeAtoms:pending.feeAtoms,gasLimit:pending.gasLimit,sequence:pending.sequence,accountNumber:pending.accountNumber,timeoutHeight:pending.timeoutHeight,hash,submissionId:'ab'.repeat(16),status:'pending',signedPayload:pending.signedPayload};validateXionSignedPayload(row);await verifyXionSignedPayload(row,{wasmBytes});assert.throws(()=>validateXionSignedPayload({...row,timeoutHeight:'1101'}));await observeXionSubmission({networkId:'mainnet',from:x.wallet.addresses.xion,hash,fetcher:x.fetcher});
});

test('XION refuses before POST if timeout becomes too close after durable callback',async()=>{const x=setup(),r=await prepareXionReview(x.args);await assert.rejects(r.confirm(d=>{const attempt=x.onBroadcast(d);x.setHeight(1096);return attempt;}),e=>e.xionNotSubmitted===true&&/timeout/.test(e.message));assert.equal(x.posts(),0);});

test('XION rechecks height-pinned account after durable callback before POST',async()=>{const x=setup(),r=await prepareXionReview(x.args);x.setMode('changed-final');let recorded=false;await assert.rejects(r.confirm(d=>{recorded=true;return x.onBroadcast(d);}),e=>e.xionNotSubmitted===true&&/account changed/.test(e.message));assert.equal(recorded,true);assert.equal(x.posts(),0);});
test('XION fails closed if head advances too far during last pinned state reads',async()=>{const x=setup(),r=await prepareXionReview(x.args);x.setMode('head-advances-final');let recorded=false;await assert.rejects(r.confirm(d=>{recorded=true;return x.onBroadcast(d);}),e=>e.xionNotSubmitted===true&&/ledger advanced/.test(e.message));assert.equal(recorded,true);assert.equal(x.posts(),0);});
