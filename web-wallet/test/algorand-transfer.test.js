import test from 'node:test';import assert from 'node:assert/strict';import{readFile}from'node:fs/promises';
import{prepareAlgorandTransfer,algorandPendingSubmission,reconcileAlgorandSubmission}from'../src/pq/algorand-transfer.js';
import{algorandNetwork}from'../src/pq/algorand.js';import{ALGORAND_FALCON_PROTOCOL}from'../src/pq/algorand-prepare.js';
const fixture=JSON.parse(await readFile(new URL('./fixtures/pq-receive.json',import.meta.url),'utf8')).vectors[0];
const wasmBytes=await readFile(new URL('../src/pq/algorand-sign.wasm',import.meta.url));
function setup(){
 const wallet={addresses:{algorand:fixture.addresses.algorand.mainnet},recoveryPhrase:fixture.phrase};let posts=0,pendingHash,mode='ok';
 const fetcher=async(url,options)=>{
  if(options.method==='POST'){posts++;if(mode==='ambiguous')throw Error('transport failed');return new Response(JSON.stringify({txId:pendingHash}));}
  const data=url.endsWith('/params')?{'consensus-version':ALGORAND_FALCON_PROTOCOL,'genesis-hash':algorandNetwork('mainnet').genesisHash,'genesis-id':'mainnet-v1.0','last-round':100,'min-fee':1000,fee:0}:url.includes('/pending/')?{'confirmed-round':102,txn:{txn:{snd:wallet.addresses.algorand}}}:{address:wallet.addresses.algorand,round:100,amount:10000000,'min-balance':100000};
  return new Response(JSON.stringify(data));
 };
 return {wallet,fetcher,posts:()=>posts,mode:m=>mode=m,onBroadcast:({hash})=>{pendingHash=hash;},args:{wallet,to:wallet.addresses.algorand,amountAtoms:'1',maxFeeAtoms:'10000',wasmBytes,fetcher}};
}
test('review then confirm signs with existing recovery derivation, records hash before one mocked POST, reconciles',async()=>{
 const x=setup(),review=await prepareAlgorandTransfer(x.args);assert.equal(x.posts(),0);assert.equal(review.feeAtoms,'3000');
 const hash=await review.confirm(x.onBroadcast);assert.match(hash,/^[A-Z2-7]{52}$/);assert.equal(x.posts(),1);assert.equal(algorandPendingSubmission(x.wallet),hash);
 await assert.rejects(review.confirm(x.onBroadcast),/already closed/);await assert.rejects(prepareAlgorandTransfer(x.args),/already pending/);
 assert.equal((await reconcileAlgorandSubmission(x.wallet,{fetcher:x.fetcher})).state,'confirmed');assert.equal(algorandPendingSubmission(x.wallet),null);
});
test('cancel and wallet lock prevent signing/submission; ambiguous request is never retried',async()=>{
 const a=setup(),cancelled=await prepareAlgorandTransfer(a.args);cancelled.cancel();await assert.rejects(cancelled.confirm(),/already closed/);assert.equal(a.posts(),0);
 const b=setup(),locked=await prepareAlgorandTransfer(b.args);b.wallet.locked=true;await assert.rejects(locked.confirm(),/locked/);assert.equal(b.posts(),0);
 const c=setup(),review=await prepareAlgorandTransfer(c.args);c.mode('ambiguous');await assert.rejects(review.confirm(c.onBroadcast));assert.equal(c.posts(),1);assert.ok(algorandPendingSubmission(c.wallet));
 await assert.rejects(review.confirm(c.onBroadcast),/already closed/);assert.equal(c.posts(),1);
 await reconcileAlgorandSubmission(c.wallet,{fetcher:c.fetcher});
});
test('a lock in pending callback prevents the POST and concurrent reviews cannot race a send',async()=>{
 const x=setup(),a=await prepareAlgorandTransfer(x.args),b=await prepareAlgorandTransfer(x.args);
 const first=a.confirm(({hash})=>{x.onBroadcast({hash});x.wallet.locked=true;});
 await assert.rejects(b.confirm(x.onBroadcast),/already pending/);await assert.rejects(first,error=>/locked/.test(error.message)&&error.algorandNotSubmitted===true);assert.equal(x.posts(),0);assert.equal(algorandPendingSubmission(x.wallet),null);
});
