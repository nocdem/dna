// /idx/v1/address endpoint documented in Splendor Quantum Chain README;
// field shapes/status corroborated by public testnet indexer and /tx receipt
// on 2026-11-02. Indexer data are untrusted, incomplete, not inclusion proofs.
import {integerJson} from './integer-json.js';
const nets=Object.freeze({mainnet:{url:'https://quantum-rpc.splendor.org',chain:'splendor-quantum-1',genesis:'d865193d3bd88fb4446626940e63b5658275342a0153638079cf9e962332a257'},testnet:{url:'https://quantum-rpc-testnet.splendor.org',chain:'splendor-quantum-testnet-1',genesis:'324d7f561493ae6d08062288cb99adfbb3f83297d352b783f611171251a1289f'}});
const valid=s=>typeof s==='string'&&/^SQ:[0-9a-f]{64}$/.test(s);
export function parseSplendorHistory(data,account){
 if(!valid(account)||!data||data.address!==account||!(data.transactions===null||Array.isArray(data.transactions))||data.transactions?.length>50)throw new Error('Invalid Splendor history response.');
 const seen=new Map(),rows=[];
 for(const t of data.transactions||[]){
  if(t?.kind!=='transfer'||!valid(t.from)||!valid(t.to)||(t.from!==account&&t.to!==account)||typeof t.hash!=='string'||!/^[0-9a-f]{64}$/.test(t.hash)||typeof t.amount!=='string'||!/^[1-9]\d{0,77}$/.test(t.amount)||BigInt(t.amount)>=2n**256n||!['0','1'].includes(t.status)||typeof t.timestamp!=='string'||!/^(0|[1-9]\d{0,11})$/.test(t.timestamp))continue;
  const time=Number(t.timestamp)*1000;if(!Number.isSafeInteger(time)||time<=0)continue;
  const n=BigInt(t.amount),fraction=String(n%10n**18n).padStart(18,'0').replace(/0+$/,'');
  const row={chain:'splendor',hash:t.hash,time,dir:t.from===account&&t.to===account?'self':t.from===account?'out':'in',symbol:'SPLD',amount:String(n/10n**18n)+(fraction?'.'+fraction:''),peer:t.from===account?t.to:t.from,status:t.status==='1'?'confirmed':'failed'};
  const old=seen.get(row.hash);if(old){if(JSON.stringify(old)!==JSON.stringify(row))throw new Error('Conflicting Splendor history rows.');continue;}seen.set(row.hash,row);rows.push(row);
 }
 return rows.sort((a,b)=>b.time-a.time||a.hash.localeCompare(b.hash));
}
export async function readSplendorHistory(account,{networkId='mainnet',signal,fetcher}={}){
 if(!valid(account))throw new Error('Invalid Splendor address.');if(!Object.hasOwn(nets,networkId))throw new Error('Unsupported Splendor network.');
 const net=nets[networkId],opts={signal,fetcher};signal?.throwIfAborted();
 const status=await integerJson(net.url+'/status',opts);signal?.throwIfAborted();
 if(status.chain_id!==net.chain||status.genesis_hash!==net.genesis)throw new Error('Splendor provider is connected to the wrong network.');
 const page=await integerJson(`${net.url}/idx/v1/address/${encodeURIComponent(account)}?limit=50`,opts);signal?.throwIfAborted();
 return parseSplendorHistory(page,account);
}
