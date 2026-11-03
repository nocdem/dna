import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {SOQU_MAINNET} from '../../src/pq/soqu-preflight.js';
import {soquScript} from '../../src/pq/soqu-transaction.js';
const fixture=JSON.parse(readFileSync(new URL('./pq-receive.json',import.meta.url))).vectors[0];
const address=fixture.addresses.soqucoin.mainnet,wasmBytes=readFileSync(new URL('../../src/pq/mldsa44-sign.wasm',import.meta.url));
export function createSoquRpcFixture(){
 let mode='',record,posts=0;const calls=[];
 const row={txid:'ab'.repeat(32),vout:0,value:1000000000,height:10,assetType:0,visibility:0};
 const info={chain:'main',blocks:1000,headers:1000,bestblockhash:'cd'.repeat(32),initialblockdownload:false,mediantime:Math.floor(Date.now()/1000)-600};
 const proof={bestblock:info.bestblockhash,confirmations:500,value:10,scriptPubKey:{hex:soquScript(address)},coinbase:false,assettype:0};
 const data={address,utxo_count:1,utxos:[row]};
 const fetcher=async(url,options)=>{
  let result;if(url===SOQU_MAINNET.rpc+'/'){
   const body=JSON.parse(options.body);calls.push(body.method);
   switch(body.method){
    case'getblockhash':result=mode==='genesis'?'aa'.repeat(32):SOQU_MAINNET.genesis;break;
    case'getblockchaininfo':result=info;break;
    case'gettxout':result=mode==='spent'?null:proof;break;
    case'sendrawtransaction':posts++;assert.ok(record);assert.match(body.params[0],/^[0-9a-f]+$/);if(mode==='ambiguous')throw Error('lost response');result=mode==='wrongtxid'?'00'.repeat(32):record.hash;break;
    case'getrawtransaction':result={txid:record.hash,confirmations:mode==='unconfirmed'?0:1,blockhash:info.bestblockhash};break;
    default:throw Error('unexpected RPC '+body.method);
   }
   return new Response(JSON.stringify({result,error:null,id:body.id}));
  }
  if(url===`${SOQU_MAINNET.api}/api/v2/history/${address}`)return new Response(JSON.stringify({address,transactions:[]}));
  assert.equal(url,`${SOQU_MAINNET.api}/api/v2/utxos/${address}`);calls.push('utxos');return new Response(JSON.stringify(data));
 };
 const wallet={addresses:{soqucoin:address},recoveryPhrase:fixture.phrase,locked:false};
 return {address,phrase:fixture.phrase,wasmBytes,data,row,info,proof,calls,wallet,fetcher,mode(v){mode=v;},record(v){record=v;},posts:()=>posts,args:{from:address,to:address,amountAtoms:'1000000',fetcher},transfer:{wallet,to:address,amountAtoms:'1000000',fetcher,wasmBytes}};
}
