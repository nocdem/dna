// Cosmos SDK GetTxsEvent (pinned 64fd208a11fb54f7ffdca1a1290c2cfbbc254e49).
// These are untrusted indexer/node observations, not inclusion proofs. This
// deliberately reports only single-message native MsgSend transactions;
// contract/internal/multi-message transfers are outside this partial view.
import {bech32} from '@scure/base';
import {integerJson} from './integer-json.js';
const nets=Object.freeze({mainnet:{url:'https://api.xion-mainnet-1.burnt.com',chain:'xion-mainnet-1'},testnet:{url:'https://api.xion-testnet-2.burnt.com',chain:'xion-testnet-2'}});
function valid(s){try{if(typeof s!=='string'||s!==s.toLowerCase())return false;const d=bech32.decode(s),b=bech32.fromWords(d.words);return d.prefix==='xion'&&b.length===20&&bech32.encode('xion',bech32.toWords(b))===s;}catch{return false;}}
function parsePage(data,self) {
 if(!data||!Array.isArray(data.txs)||!Array.isArray(data.tx_responses)||data.txs.length!==data.tx_responses.length||data.txs.length>50)throw new Error('Invalid XION history response.');
 const rows=[];
 for(let i=0;i<data.txs.length;i++) {
  const tx=data.txs[i],r=data.tx_responses[i],msgs=tx?.body?.messages;
  if(!Array.isArray(msgs)||msgs.length!==1)continue;
  // When the response duplicates decoded Tx data, do not pair inconsistent
  // indexed metadata with another transaction's message.
  if(r?.tx?.body?.messages!==undefined && JSON.stringify(r.tx.body.messages)!==JSON.stringify(msgs)) throw new Error('Conflicting XION transaction data.');
  const m=msgs[0],from=m?.from_address,to=m?.to_address;
  if(m?.['@type']!=='/cosmos.bank.v1beta1.MsgSend'||!valid(from)||!valid(to)||(from!==self&&to!==self)||!Array.isArray(m.amount)||m.amount.length!==1)continue;
  const coin=m.amount[0];if(coin?.denom!=='uxion'||typeof coin.amount!=='string'||!/^[1-9]\d{0,77}$/.test(coin.amount)||BigInt(coin.amount)>=2n**256n)continue;
  if(typeof r?.txhash!=='string'||!/^[0-9a-fA-F]{64}$/.test(r.txhash)||typeof r.code!=='string'||!/^(0|[1-9]\d{0,9})$/.test(r.code)||BigInt(r.code)>4294967295n)continue;
  if(typeof r.timestamp!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(r.timestamp))continue;
  const time=Date.parse(r.timestamp);if(!Number.isSafeInteger(time)||time<=0)continue;
  const n=BigInt(coin.amount),fraction=String(n%1000000n).padStart(6,'0').replace(/0+$/,'');
  rows.push({chain:'xion',hash:r.txhash.toLowerCase(),time,dir:from===self&&to===self?'self':from===self?'out':'in',symbol:'XION',amount:String(n/1000000n)+(fraction?'.'+fraction:''),peer:from===self?to:from,status:r.code==='0'?'confirmed':'failed'});
 }
 return rows;
}
export function parseXionHistory(pages,account) {
 if(!valid(account)||!Array.isArray(pages)||pages.length!==2)throw new Error('Invalid XION history input.');
 const rows=[],seen=new Map();
 for(const page of pages)for(const row of parsePage(page,account)){
  const old=seen.get(row.hash);if(old){if(JSON.stringify(old)!==JSON.stringify(row))throw new Error('Conflicting XION history rows.');continue;}seen.set(row.hash,row);rows.push(row);
 }
 return rows.sort((a,b)=>b.time-a.time||a.hash.localeCompare(b.hash)).slice(0,50);
}
export async function readXionHistory(account,{networkId='mainnet',signal,fetcher}={}){
 if(!valid(account))throw new Error('Invalid XION address.');if(!Object.hasOwn(nets,networkId))throw new Error('Unsupported XION network.');
 const net=nets[networkId],opts={signal,fetcher};signal?.throwIfAborted();
 const info=await integerJson(net.url+'/cosmos/base/tendermint/v1beta1/node_info',opts);signal?.throwIfAborted();
 if(info.default_node_info?.network!==net.chain)throw new Error('XION provider is connected to the wrong network.');
 const pages=[];for(const key of ['sender','recipient']){const query=encodeURIComponent(`transfer.${key}='${account}'`);pages.push(await integerJson(`${net.url}/cosmos/tx/v1beta1/txs?query=${query}&order_by=ORDER_BY_DESC&page=1&limit=50`,opts));signal?.throwIfAborted();}
 return parseXionHistory(pages,account);
}
