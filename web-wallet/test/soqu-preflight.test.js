import test from 'node:test';import assert from 'node:assert/strict';import{readFileSync}from'node:fs';
import{serveReceiveWasmForFile}from'./fixtures/receive-wasm-fetch.js';serveReceiveWasmForFile(); // Soqucoin signing seed comes from the receive module (native rule)
import{prepareVerifiedSoquPayment,SOQU_MAINNET,soquCoinAtoms}from'../src/pq/soqu-preflight.js';
import{soquScript}from'../src/pq/soqu-transaction.js';import{parseExactJson}from'../src/pq/integer-json.js';
import{prepareSoquTransfer,soquPendingSubmission,reconcileSoquSubmission}from'../src/pq/soqu-transfer.js';
const fixture=JSON.parse(readFileSync(new URL('./fixtures/pq-receive.json',import.meta.url))).vectors[0];
const address=fixture.addresses.soqucoin.mainnet,wasmBytes=readFileSync(new URL('../src/pq/mldsa44-sign.wasm',import.meta.url));
import {createSoquRpcFixture as setup} from './fixtures/soqu-rpc-fixture.js';
test('exact decimal/node and integer/indexer values never round through Number',()=>{
 assert.equal(soquCoinAtoms('12345678901.12345678'),1234567890112345678n);
 for(const value of [1,'1e2','-1','1.000000001'])assert.throws(()=>soquCoinAtoms(value));
 assert.equal(parseExactJson('{"value":12345678901.12345678}').value,'12345678901.12345678');
 assert.throws(()=>parseExactJson('{"result":{"value":1,"v\\u0061lue":2}}'),/ambiguous/);
});
test('SOQ prepare proves mainnet, full page, exact ownership and mature node input without signing',async()=>{
 const x=setup(),r=await prepareVerifiedSoquPayment(x.args);assert.equal(r.prepared.transaction.inputs.length,1);assert.equal(r.prepared.amount,1000000n);assert.equal(r.feeRate,1000n);assert.equal(x.posts(),0);assert.deepEqual(x.calls,['getblockhash','getblockchaininfo','utxos','gettxout']);
});
test('wrong chain, unsynced/stale node and indexer ownership/duplicate/truncation fail closed',async()=>{
 for(const mutation of [x=>x.mode('genesis'),x=>x.info.chain='test',x=>x.info.initialblockdownload=true,x=>x.info.mediantime=1,x=>x.data.address='another',x=>x.data.utxo_count=2,x=>{x.data.utxos.push({...x.row});x.data.utxo_count=2;},x=>x.row.value=0]){
  const x=setup();mutation(x);await assert.rejects(prepareVerifiedSoquPayment(x.args));assert.equal(x.posts(),0);
 }
});
test('spent, immature, unconfirmed, wrong asset and altered node amounts cannot enter signing set',async()=>{
 for(const mutation of [x=>x.mode('spent'),x=>{x.proof.coinbase=true;x.proof.confirmations=287;},x=>x.proof.confirmations=0,x=>x.row.assetType=1,x=>x.row.visibility=1,x=>x.proof.assettype=1,x=>x.proof.scriptPubKey.hex='5120'+'11'.repeat(32),x=>x.proof.value=9,x=>x.proof.bestblock='aa'.repeat(32)]){
  const x=setup();mutation(x);await assert.rejects(prepareVerifiedSoquPayment(x.args));assert.equal(x.posts(),0);
 }
 const x=setup();x.proof.coinbase=true;x.proof.confirmations=288;assert.ok(await prepareVerifiedSoquPayment(x.args));
});
test('real SOQ MLDSA44 send rechecks inputs and records outpoints before sole mocked broadcast',async()=>{
 const x=setup(),r=await prepareSoquTransfer(x.transfer);assert.equal(x.posts(),0);
 const hash=await r.confirm(details=>{assert.equal(x.posts(),0);assert.deepEqual(details.inputs,[{txid:x.row.txid,vout:0}]);x.record(details);});
 assert.equal(x.posts(),1);assert.equal(soquPendingSubmission(address),hash);assert.equal(x.calls.filter(m=>m==='gettxout').length,3);
 await assert.rejects(r.confirm(x.record),/already closed/);await assert.rejects(prepareSoquTransfer(x.transfer),/pending/);
 assert.equal((await reconcileSoquSubmission({from:address,hash,fetcher:x.fetcher})).state,'confirmed');assert.equal(soquPendingSubmission(address),null);
});
test('cancel, lock, persistence failure and input spent after review prevent broadcast',async()=>{
 const a=setup(),cancelled=await prepareSoquTransfer(a.transfer);cancelled.cancel();await assert.rejects(cancelled.confirm(a.record),/closed/);
 const b=setup(),locked=await prepareSoquTransfer(b.transfer);b.wallet.locked=true;await assert.rejects(locked.confirm(b.record),/locked/);
 const c=setup(),failed=await prepareSoquTransfer(c.transfer);await assert.rejects(failed.confirm(()=>{throw Error('durable save failed');}),e=>e.soquNotSubmitted===true);assert.equal(c.posts(),0);
 const d=setup(),stale=await prepareSoquTransfer(d.transfer);d.mode('spent');await assert.rejects(stale.confirm(d.record),e=>e.soquNotSubmitted===true);assert.equal(d.posts(),0);
});
test('lost broadcast response preserves hold and never retries or rebuilds',async()=>{
 const x=setup(),r=await prepareSoquTransfer(x.transfer);x.mode('ambiguous');await assert.rejects(r.confirm(x.record),e=>e.soquNotSubmitted!==true);
 const hash=soquPendingSubmission(address);assert.ok(hash);assert.equal(x.posts(),1);await assert.rejects(prepareSoquTransfer(x.transfer),/pending/);assert.equal(x.posts(),1);
 x.mode('');await reconcileSoquSubmission({from:address,hash,fetcher:x.fetcher});
});

test('txindex-missing SOQ historical recovery requires canonical block inclusion, never indexer claims alone',async()=>{
 const hash='ab'.repeat(32),blockhash='cd'.repeat(32);let mode='confirmed';
 const fetcher=async(url,options)=>{
  if(url.includes('/api/v2/history/'))return new Response(JSON.stringify({address,transactions:mode==='missing'?[]:[{txid:hash,height:900,confirmed:true}]}));
  const req=JSON.parse(options.body);let result;
  if(req.method==='getblockhash')result=req.params[0]===0?SOQU_MAINNET.genesis:blockhash;
  else if(req.method==='getblockchaininfo')result={chain:'main',blocks:1000,headers:1000,bestblockhash:blockhash,initialblockdownload:false,mediantime:Math.floor(Date.now()/1000)-600};
  else if(req.method==='getrawtransaction')return new Response(JSON.stringify({id:req.id,result:null,error:{code:-5,message:'No such transaction'}}),{status:500});
  else if(req.method==='getblock')result={hash:blockhash,height:900,confirmations:mode==='orphan'?-1:101,tx:mode==='noinclusion'?[]:[hash]};
  else throw Error('Unexpected method');
  return new Response(JSON.stringify({id:req.id,result,error:null}));
 };
 assert.equal((await reconcileSoquSubmission({from:address,hash,fetcher})).state,'confirmed');
 for(mode of ['missing','orphan','noinclusion'])assert.equal((await reconcileSoquSubmission({from:address,hash,fetcher})).state,'pending');
});
