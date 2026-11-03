// Source-only contract: soqushield@cb3e842 lib/services/balance_service.dart
// transactions[{txid,height,confirmed}]; soqucoin@28222c3
// src/rpc/rawtransaction.cpp TxToJSON (native output metadata omitted by default).
// Partial confirmed native SOQ net flows, NOT a complete account scan. Outgoing
// net debits include fees; mixed-asset/confidential transactions are omitted.
import {integerJson,atoms,decimalAtoms} from './integer-json.js';
import {SOQU_MAINNET,soquRpc,checkSoquMainnet,soquCoinAtoms} from './soqu-preflight.js';
import {soquScript} from './soqu-transaction.js';
const hash=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x),hex=x=>typeof x==='string'&&/^(?:[0-9a-f]{2})*$/.test(x);
export const SOQU_HISTORY_LIMIT=20,SOQU_HISTORY_READS=100;
function outputs(tx,id){
 if(!tx||tx.txid!==id||!Array.isArray(tx.vout)||!tx.vout.length||tx.vout.length>2000)throw Error('Invalid SOQ transaction outputs.');let total=0n;
 return tx.vout.map((o,i)=>{if(atoms(o?.n)!==BigInt(i)||!hex(o?.scriptPubKey?.hex))throw Error('Invalid SOQ output index or script.');
  if((o.assetType!==undefined&&o.assetType!=='0')||(o.visibility!==undefined&&o.visibility!=='0')||o.assetName!==undefined||o.visibilityName!==undefined||/^(54|57)/.test(o.scriptPubKey.hex))throw Error('Non-native or confidential SOQ history transaction.');
  const value=soquCoinAtoms(o.value);total+=value;if(total>2000000000000000000n)throw Error('SOQ output total exceeds monetary range.');return {value,script:o.scriptPubKey.hex};});
}
export async function readSoquHistoryPage(account,{networkId='mainnet',signal,fetcher}={}){
 if(networkId!=='mainnet')throw Error('SOQ account history requires verified mainnet.');const own=soquScript(account),options={signal,fetcher},tip=await checkSoquMainnet(options);
 const data=await integerJson(`${SOQU_MAINNET.api}/api/v2/history/${encodeURIComponent(account)}`,options);
 if(!data||!Array.isArray(data.transactions)||data.transactions.length>5000||(data.address!==undefined&&data.address!==account))throw Error('Invalid or oversized SOQ history index.');
 const seen=new Set(),eligible=[];let omitted=0;
 for(const entry of data.transactions){if(!entry||!hash(entry.txid)||seen.has(entry.txid))throw Error('Invalid or duplicate SOQ history identifier.');seen.add(entry.txid);
  if(entry.confirmed!==true){omitted++;continue;}let height;try{height=atoms(entry.height);}catch{omitted++;continue;}if(height<1n||height>BigInt(tip.height)){omitted++;continue;}eligible.push({...entry,height:Number(height)});
 }
 eligible.sort((a,b)=>b.height-a.height||a.txid.localeCompare(b.txid));const chosen=eligible.slice(0,SOQU_HISTORY_LIMIT),txs=new Map(),blocks=new Map(),rows=[];let reads=0;
 const rpc=async(method,params)=>{signal?.throwIfAborted();if(++reads>SOQU_HISTORY_READS)throw Error('SOQ history read budget exhausted.');return soquRpc(method,params,options);};
 const transaction=async id=>{if(!txs.has(id))txs.set(id,rpc('getrawtransaction',[id,true]));return txs.get(id);};
 const block=async height=>{if(!blocks.has(height))blocks.set(height,(async()=>{const id=await rpc('getblockhash',[height]);if(!hash(id))throw Error('Invalid SOQ block identifier.');const b=await rpc('getblock',[id,1]);if(b?.hash!==id||atoms(b.height)!==BigInt(height)||atoms(b.confirmations)<1n||!Array.isArray(b.tx)||b.tx.length>10000||!b.tx.every(hash))throw Error('Invalid SOQ canonical block.');const seconds=atoms(b.time);if(seconds===0n||seconds>BigInt(Math.floor(Date.now()/1000)+600))throw Error('Invalid SOQ block time.');return {...b,seconds};})());return blocks.get(height);};
 for(const entry of chosen){try{
   const tx=await transaction(entry.txid),outs=outputs(tx,entry.txid),b=await block(entry.height);
   if(tx.blockhash!==b.hash||atoms(tx.confirmations)<1n||!b.tx.includes(entry.txid)||!Array.isArray(tx.vin)||!tx.vin.length||tx.vin.length>32)throw Error('Unconfirmed or unsupported SOQ history transaction.');
   let incoming=outs.filter(o=>o.script===own).reduce((n,o)=>n+o.value,0n),outgoing=0n,totalInput=0n;const inputs=new Set(),coinbase=tx.vin.length===1&&typeof tx.vin[0].coinbase==='string';
   if(coinbase){if(!hex(tx.vin[0].coinbase)||!tx.vin[0].coinbase||tx.vin[0].txid!==undefined||tx.vin[0].vout!==undefined)throw Error('Invalid SOQ coinbase.');}
   else for(const input of tx.vin){if(input.coinbase!==undefined||!hash(input.txid))throw Error('Invalid SOQ previous transaction.');const vout=atoms(input.vout);if(vout>0xffffffffn)throw Error('Invalid SOQ previous output.');const key=`${input.txid}:${vout}`;if(inputs.has(key))throw Error('Duplicate SOQ history input.');inputs.add(key);const prev=outputs(await transaction(input.txid),input.txid),out=prev[Number(vout)];if(!out)throw Error('Missing SOQ previous output.');totalInput+=out.value;if(totalInput>2000000000000000000n)throw Error('SOQ input total exceeds monetary range.');if(out.script===own)outgoing+=out.value;}
   if(!coinbase&&totalInput<outs.reduce((n,o)=>n+o.value,0n))throw Error('SOQ history violates value conservation.');if(incoming===outgoing){omitted++;continue;}
   const outgoingFlow=outgoing>incoming;rows.push({chain:'soqucoin',hash:entry.txid,time:Number(b.seconds)*1000,dir:outgoingFlow?'out':'in',symbol:'SOQ',amount:decimalAtoms(outgoingFlow?outgoing-incoming:incoming-outgoing),peer:'',status:'confirmed'});
  }catch(e){signal?.throwIfAborted();omitted++;}
 }
 const end=await checkSoquMainnet(options);if(end.hash!==tip.hash||end.height!==tip.height)throw Error('SOQ chain tip changed during history read.');
 rows.sort((a,b)=>b.time-a.time||a.hash.localeCompare(b.hash));
 return {rows,totalListed:data.transactions.length,examined:chosen.length,omitted:omitted+Math.max(0,eligible.length-chosen.length),partial:true,status:`Partial native SOQ net flows: up to ${SOQU_HISTORY_LIMIT} confirmed indexed transactions; outgoing amounts include fees. Unconfirmed, mixed-asset, confidential, missing-prevout and over-budget entries are omitted.`};
}
export async function readSoquHistory(account,options){return (await readSoquHistoryPage(account,options)).rows;}
