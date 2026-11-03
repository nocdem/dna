// Official browser transports, not guessed node-wallet APIs:
// soqucoin/soqushield@cb3e842af29e4c087a5eb9974f6f76c415862b7a
// lib/services/{balance_service,rpc_service}.dart + lib/models/wallet_keys.dart.
// Node fields/genesis/maturity: soqucoin@28222c3810701c05eb27e8feb09f032bb75fc097
// src/rpc/blockchain.cpp gettxout, src/chainparams.cpp (mainnet maturity 288).
import {rpcFetch} from '../rpc-transport.js';
import {integerJson,parseExactJson,atoms} from './integer-json.js';
import {soquScript} from './soqu-transaction.js';
import {prepareSoquPayment} from './soqu-payment.js';
export const SOQU_MAINNET=Object.freeze({rpc:'https://mainnet-rpc.soqu.org',api:'https://mainnet-api.soqu.org',genesis:'0d828600816cbd7c23789660b53f90cb6ec7ff85540698e13845eb2d2f0486a8'});
const hash=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const uint=value=>{const n=atoms(value);if(n>BigInt(Number.MAX_SAFE_INTEGER))throw Error('Unsafe SOQ integer.');return Number(n);};
const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
export function soquCoinAtoms(value){
 if(typeof value!=='string'||!/^(0|[1-9]\d{0,10})(\.\d{1,8})?$/.test(value))throw Error('Invalid exact SOQ coin amount.');
 const [whole,fraction='']=value.split('.');const n=BigInt(whole)*100000000n+BigInt(fraction.padEnd(8,'0'));
 if(n>2000000000000000000n)throw Error('SOQ amount exceeds monetary range.');return n;
}
// Explicit allowlist. No keys/credentials, wallet RPCs, retries or redirects.
export async function soquRpc(method,params=[],{signal,fetcher}={}){
 if(!['getblockhash','getblock','getblockchaininfo','gettxout','getrawtransaction','sendrawtransaction'].includes(method))throw Error('Unsupported SOQ RPC method.');
 const id=`nodus-soq-${method}`;
 const response=await rpcFetch(SOQU_MAINNET.rpc,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'1.0',id,method,params}),signal},{fetcher});
 signal?.throwIfAborted();const data=parseExactJson(await response.text());
 if(!object(data)||data.id!==id||!Object.hasOwn(data,'result'))throw Error('SOQ RPC returned an invalid envelope.');
 if(!response.ok||data.error!==null){const failure=Error('SOQ RPC rejected request.');if(object(data.error)&&typeof data.error.code==='string'&&/^-[1-9]\d{0,5}$/.test(data.error.code))failure.rpcCode=data.error.code;throw failure;}
 return data.result;
}
export async function checkSoquMainnet(options={}){
 const genesis=await soquRpc('getblockhash',[0],options);if(genesis!==SOQU_MAINNET.genesis)throw Error('SOQ node is on the wrong genesis.');
 const info=await soquRpc('getblockchaininfo',[],options);
 if(!object(info)||info.chain!=='main'||info.initialblockdownload!==false||!hash(info.bestblockhash))throw Error('SOQ mainnet node is not synchronized.');
 const height=uint(info.blocks),headers=uint(info.headers),median=uint(info.mediantime),now=Math.floor(Date.now()/1000);
 if(height<1||headers<height||headers-height>2||median<now-7200||median>now+600)throw Error('SOQ mainnet node is stale or behind headers.');
 return {height,hash:info.bestblockhash};
}
export async function checkSoquInput(input,from,tip,options={}){
 const value=await soquRpc('gettxout',[input.txid,input.vout,true],options);
 if(value===null)return null;
 if(!object(value)||value.bestblock!==tip.hash||!object(value.scriptPubKey)||typeof value.coinbase!=='boolean')throw Error('SOQ UTXO proof is invalid or tip changed.');
 const confirmations=uint(value.confirmations),amount=soquCoinAtoms(value.value);
 if(value.assettype!=='0'||value.scriptPubKey.hex!==soquScript(from)||amount!==input.value)throw Error('SOQ indexer/node UTXO ownership, asset or amount mismatch.');
 if(confirmations<1||(value.coinbase&&confirmations<288))return null;
 return {...input,script_pubkey:soquScript(from)};
}
export async function prepareVerifiedSoquPayment({from,to,amountAtoms,feeRate=1000n,networkId='mainnet',signal,fetcher}={}){
 if(networkId!=='mainnet')throw Error('SOQ send requires mainnet.');
 soquScript(from);soquScript(to);const amount=atoms(amountAtoms);
 if(amount<279500n||typeof feeRate!=='bigint'||feeRate<1000n||feeRate>100000n)throw Error('Invalid SOQ amount or fee rate.');
 const options={signal,fetcher},tip=await checkSoquMainnet(options);
 const data=await integerJson(`${SOQU_MAINNET.api}/api/v2/utxos/${encodeURIComponent(from)}`,options);
 if(data.address!==from||!Array.isArray(data.utxos)||data.utxos.length>5000||uint(data.utxo_count)!==data.utxos.length)throw Error('Invalid or incomplete SOQ UTXO page.');
 const seen=new Set(),candidates=[];
 for(const row of data.utxos){
  if(!object(row)||!hash(row.txid))throw Error('Invalid SOQ UTXO.');
  const vout=uint(row.vout),height=uint(row.height),value=atoms(row.value),key=`${row.txid}:${vout}`;
  if(vout>0xffffffff||height>tip.height||seen.has(key)||value<=0n)throw Error('Invalid/duplicate SOQ outpoint.');seen.add(key);
  if(row.assetType==='0'&&row.visibility==='0'&&height>0)candidates.push({txid:row.txid,vout,value,height});
 }
 candidates.sort((a,b)=>a.value===b.value?a.height-b.height:a.value>b.value?-1:1);
 const selected=[];let total=0n;
 for(const candidate of candidates){
  const verified=await checkSoquInput(candidate,from,tip,options);if(!verified)continue;
  selected.push(verified);total+=verified.value;
  // Conservative two-output quote, bounded at the SDK's 80-input operational
  // cap. This wallet selects at most 15 so signed recovery bytes fit the
  // unchanged 150k encrypted Activity bound. The builder enforces 2 SOQ.
  if(total>amount){
   try{return {prepared:prepareSoquPayment({inputs:selected,from,to,amount,feeRate,networkId}),tip,feeRate};}
   catch(error){if(!/insufficient funds/.test(error.message))throw error;}
  }
  if(selected.length===15)break;
 }
 throw Error('Insufficient verified mature SOQ inputs (maximum 15 for encrypted recovery storage).');
}
