// Official explorer gateway: final submit ONLY, never a harmless simulation.
// Source qtcchain/qtc-explorer@73a6076 internal/gateway/broadcast.go.
import {integerJson,atoms,parseExactJson} from './integer-json.js';
import {rpcFetch,boundedBytes} from '../rpc-transport.js';
import {decodeQtcPrevoutTransaction} from './qtc-prevout.js';
const nets={mainnet:{url:'https://qtc.events',chain:'main',genesis:'d5f04a8a320b4e7bb454c7c564ca9cf191f70d7521d2486b62274df776f4eb24'},testnet:{url:'https://testnet.qtc.events',chain:'test',genesis:'efcba50d2de7cb16fd92423df899eba29e750b2271ef0ea64efe8cfeb4382ddf'}};
const hash=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
function network(id){if(!Object.hasOwn(nets,id))throw Error('Unsupported QTC network.');return nets[id];}
export function qtcGatewayBody(raw){if(typeof raw!=='string'||!/^([0-9a-f]{2})+$/.test(raw))throw Error('Invalid QTC gateway transaction.');const body=JSON.stringify({hex:raw});if(new TextEncoder().encode(body).length>65536)throw Error('QTC gateway JSON exceeds 64 KiB.');return body;}
export async function readQtcPrevious(txid,{networkId='mainnet',signal,fetcher=fetch}={}){
 if(!hash(txid))throw Error('Invalid QTC previous transaction ID.');const n=network(networkId),combined=signal?AbortSignal.any([signal,AbortSignal.timeout(15000)]):AbortSignal.timeout(15000);combined.throwIfAborted();
 const r=await fetcher(`${n.url}/api/v1/tx/${txid}/hex`,{method:'GET',signal:combined,redirect:'error',credentials:'omit',referrerPolicy:'no-referrer'});if(!r.ok){void r.body?.cancel().catch(()=>{});throw Error(`QTC previous transaction unavailable (HTTP ${r.status}).`);}const bytes=await boundedBytes(r,262144,combined);combined.throwIfAborted();const tx=decodeQtcPrevoutTransaction(new TextDecoder('utf-8',{fatal:true}).decode(bytes).trim());if(tx.txid!==txid)throw Error('QTC previous transaction ID mismatch.');return tx;
}
export async function verifyQtcPrevious(inputs,options){for(const i of inputs){const tx=await readQtcPrevious(i.txid,options),out=tx.outputs[i.vout];if(!out||out.value!==i.value||out.script!==i.script_pubkey||tx.coinbase!==i.coinbase)throw Error('QTC canonical previous output mismatch.');}}
export async function submitQtcGateway({raw,txid,networkId='mainnet',signal,fetcher}={}){
 const n=network(networkId);if(!hash(txid)||decodeQtcPrevoutTransaction(raw).txid!==txid)throw Error('QTC gateway transaction hash mismatch.');const body=qtcGatewayBody(raw);signal?.throwIfAborted();
 // Once called, every error is ambiguous: no error status releases the hold.
 const response=await rpcFetch(`${n.url}/api/v1/tx/broadcast`,{method:'POST',headers:{'Content-Type':'application/json'},body,signal},{fetcher});if(!response.ok){const error=Error(`QTC gateway submission is unresolved (HTTP ${response.status}).`);error.status=response.status;throw error;}
 const data=parseExactJson(new TextDecoder('utf-8',{fatal:true}).decode(await boundedBytes(response,16384,signal)));if(data?.txid!==txid||data.error)throw Error('QTC gateway returned a mismatched transaction ID.');return txid;
}
export async function observeQtcGateway({hash:txid,networkId='mainnet',signal,fetcher}={}){
 if(!hash(txid))throw Error('Invalid QTC transaction ID.');const n=network(networkId),o={signal,fetcher},pending={hash:txid,status:'pending'};
 const chain=await integerJson(`${n.url}/api/v1/chain`,o),gen=await integerJson(`${n.url}/api/v1/block/0`,o),now=BigInt(Math.floor(Date.now()/1000));
 if(chain.chain!==n.chain||!hash(chain.hash)||atoms(chain.height)!==atoms(chain.node_height)||atoms(chain.indexer_lag)!==0n||atoms(chain.time)>now+600n||atoms(chain.time)+7200n<now||gen.block?.hash!==n.genesis||atoms(gen.block?.height)!==0n)throw Error('QTC confirmation source is stale or wrong network.');
 let status;try{status=await integerJson(`${n.url}/api/v1/tx/${txid}/status`,o);}catch(e){if(e.status===404)return pending;throw e;}
 if(status.confirmed!==true)return pending;if(!hash(status.block_hash)||atoms(status.block_height)===0n||atoms(status.confirmations)<1n)return pending;
 const b=await integerJson(`${n.url}/api/v1/block/${status.block_height}`,o),block=b.block;
 if(block?.hash!==status.block_hash||block.orphaned!==false||atoms(block.height)!==atoms(status.block_height)||!Array.isArray(block.txids)||!block.txids.includes(txid)||atoms(b.confirmations)!==atoms(chain.height)-atoms(block.height)+1n||atoms(status.confirmations)!==atoms(b.confirmations))return pending;
 const end=await integerJson(`${n.url}/api/v1/chain`,o);if(end.hash!==chain.hash||end.chain!==n.chain)return pending;
 return {hash:txid,status:'confirmed'};
}
// Fixed official-host adapter. No custom URLs, credentials, retries or fallback.
export function createQtcGatewayTransport(networkId,{fetcher}={}){network(networkId);const bound=args=>{if(args.networkId!==networkId)throw Error('QTC gateway network changed.');return {...args,networkId,fetcher};};return Object.freeze({broadcast:args=>submitQtcGateway(bound(args)),observe:args=>observeQtcGateway(bound(args))});}
