import test from'node:test';import assert from'node:assert/strict';import{readFileSync}from'node:fs';import{bech32m}from'@scure/base';
import{validateSoquSignedPayload}from'../src/pq/soqu-signed-payload.js';
const v=JSON.parse(readFileSync(new URL('./fixtures/soqu-node-sighash.json',import.meta.url)));
const to=bech32m.encode('sq',[1,...bech32m.toWords(Buffer.from(v.outputs[0].script_pubkey.slice(4),'hex'))]);
const row={address:v.key.address_sq,to,hash:v.txid,amount:'40',inputs:v.inputs.map(({txid,vout})=>({txid,vout})),signedPayload:{encoding:'hex',data:v.signed_tx}};
test('independent official-node SOQ signed vector validates exact replay hash/outputs/outpoints/key',()=>{assert.equal(validateSoquSignedPayload(row).raw,v.signed_tx);});
test('SOQ replay decoder rejects changed review, payload, trailing data and unsupported encodings',()=>{
 for(const patch of [{hash:'00'.repeat(32)},{amount:'41'},{to:row.address},{inputs:[]},{signedPayload:{encoding:'json',data:v.signed_tx}},{signedPayload:{encoding:'hex',data:v.signed_tx+'00'}},{signedPayload:{encoding:'hex',data:'03'+v.signed_tx.slice(2)}}])assert.throws(()=>validateSoquSignedPayload({...row,...patch}));
 const wrongkey=v.signed_tx.slice(0,-10)+'ff'+v.signed_tx.slice(-8);assert.throws(()=>validateSoquSignedPayload({...row,signedPayload:{encoding:'hex',data:wrongkey}}));
});

test('explicit SOQ replay uses exact authenticated bytes, reconciles twice and never accesses signing keys',async()=>{
 const {prepareSoquResubmission}=await import('../src/pq/soqu-transfer.js');const {SOQU_MAINNET}=await import('../src/pq/soqu-preflight.js');
 let posts=0,reads=0,recorded=false,mode='pending';
 const wallet={addresses:{soqucoin:row.address},locked:false,get recoveryPhrase(){throw Error('replay must not derive keys');}};
 const fetcher=async(url,options)=>{
  if(url.includes('/api/v2/history/'))return new Response(JSON.stringify({address:row.address,transactions:[]}));
  const req=JSON.parse(options.body);let result;
  if(req.method==='getblockhash')result=SOQU_MAINNET.genesis;
  else if(req.method==='getblockchaininfo')result={chain:'main',blocks:1000,headers:1000,bestblockhash:'cd'.repeat(32),initialblockdownload:false,mediantime:Math.floor(Date.now()/1000)-600};
  else if(req.method==='getrawtransaction'){reads++;result={txid:row.hash,confirmations:mode==='confirmed'?1:0,blockhash:'cd'.repeat(32)};}
  else if(req.method==='sendrawtransaction'){posts++;assert.ok(recorded);assert.equal(req.params[0],v.signed_tx);if(mode==='duplicate'){mode='confirmed';return new Response(JSON.stringify({id:req.id,result:null,error:{code:-27,message:'transaction already in block chain'}}),{status:500});}result=row.hash;}
  else throw Error('Unexpected method');
  return new Response(JSON.stringify({id:req.id,result,error:null}));
 };
 const pending={...row,status:'unknown',feeAtoms:'1000000'};
 const review=await prepareSoquResubmission({wallet,row:pending,fetcher});assert.equal(posts,0);assert.equal(review.isResubmission,true);
 assert.equal(await review.confirm(details=>{assert.equal(details.signedPayload.data,v.signed_tx);recorded=true;}),row.hash);assert.equal(posts,1);assert.equal(reads,2);
 await assert.rejects(review.confirm(()=>{}),/closed/);assert.equal(posts,1);
 const locked=await prepareSoquResubmission({wallet,row:pending,fetcher});await assert.rejects(locked.confirm(()=>{wallet.locked=true;}),error=>/locked/.test(error.message)&&error.soquNotSubmitted!==true);assert.equal(posts,1);
 wallet.locked=false;mode='duplicate';const duplicate=await prepareSoquResubmission({wallet,row:pending,fetcher});assert.equal(await duplicate.confirm(()=>{recorded=true;}),row.hash);assert.equal(posts,2);
 mode='confirmed';await assert.rejects(prepareSoquResubmission({wallet,row:pending,fetcher}),/already confirmed/);assert.equal(posts,2);
});
